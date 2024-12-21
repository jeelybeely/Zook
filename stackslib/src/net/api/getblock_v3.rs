// Adapted `getblock_v3.rs` for the Zook Network
// Replacing references to STX/Bitcoin with zBTCZ and BTCZ, aligning with Zook goals

use std::io::{Read, Seek, SeekFrom, Write};
use std::{fs, io};

use regex::{Captures, Regex};
use rusqlite::Connection;
use serde::de::Error as de_Error;
use btcz_common::codec::{BitcoinZMessageCodec, MAX_MESSAGE_LEN};
use btcz_common::types::chainstate::{ConsensusHash, BitcoinZBlockId};
use btcz_common::types::net::PeerHost;
use btcz_common::util::hash::to_hex;
use {serde, serde_json};

use crate::chainstate::btcz::{BitcoinZBlock, BitcoinZChainState, BitcoinZStagingBlocksConn};
use crate::chainstate::btcz::Error as ChainError;
use crate::net::http::{
    parse_bytes, Error, HttpBadRequest, HttpChunkGenerator, HttpContentType, HttpNotFound,
    HttpRequest, HttpRequestContents, HttpRequestPreamble, HttpResponse, HttpResponseContents,
    HttpResponsePayload, HttpResponsePreamble, HttpServerError, HttpVersion,
};
use crate::net::httpcore::{
    HttpRequestContentsExtensions, RPCRequestHandler, BitcoinZHttp, BitcoinZHttpRequest,
    BitcoinZHttpResponse,
};
use crate::net::{Error as NetError, BitcoinZNodeState, TipRequest, MAX_HEADERS};
use crate::util_lib::db::{DBConn, Error as DBError};

#[derive(Clone)]
pub struct RPCBitcoinZBlockRequestHandler {
    pub block_id: Option<BitcoinZBlockId>,
}

impl RPCBitcoinZBlockRequestHandler {
    pub fn new() -> Self {
        Self { block_id: None }
    }
}

pub struct BitcoinZBlockStream {
    /// index block hash of the block to download
    pub index_block_hash: BitcoinZBlockId,
    /// consensus hash of this block (identifies its tenure; used by the tenure stream)
    pub consensus_hash: ConsensusHash,
    /// parent index block hash of the block to download (used by the tenure stream)
    pub parent_block_id: BitcoinZBlockId,
    /// offset into the blob
    pub offset: u64,
    /// total number of bytes read.
    pub total_bytes: u64,
    /// Connection to the staging DB
    pub staging_db_conn: BitcoinZStagingBlocksConn,
    /// rowid of the block
    pub rowid: i64,
}

impl BitcoinZBlockStream {
    pub fn new(
        chainstate: &BitcoinZChainState,
        block_id: BitcoinZBlockId,
        consensus_hash: ConsensusHash,
        parent_block_id: BitcoinZBlockId,
    ) -> Result<Self, ChainError> {
        let staging_db_path = chainstate.get_bitcoinz_staging_blocks_path()?;
        let db_conn = BitcoinZChainState::open_bitcoinz_staging_blocks(&staging_db_path, false)?;
        let rowid = db_conn
            .conn()
            .get_bitcoinz_block_rowid(&block_id)?
            .ok_or(ChainError::NoSuchBlockError)?;

        Ok(BitcoinZBlockStream {
            index_block_hash: block_id,
            consensus_hash,
            parent_block_id,
            offset: 0,
            total_bytes: 0,
            staging_db_conn: db_conn,
            rowid,
        })
    }
    /// Reset the stream to send another block.
    /// Does not change the DB connection or consensus hash.
    pub fn reset(
        &mut self,
        block_id: BitcoinZBlockId,
        parent_block_id: BitcoinZBlockId,
    ) -> Result<(), ChainError> {
        let rowid = self
            .staging_db_conn
            .conn()
            .get_bitcoinz_block_rowid(&block_id)?
            .ok_or(ChainError::NoSuchBlockError)?;

        self.index_block_hash = block_id;
        self.parent_block_id = parent_block_id;
        self.offset = 0;
        self.total_bytes = 0;
        self.rowid = rowid;
        Ok(())
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCBitcoinZBlockRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/blocks/(?P<block_id>[0-9a-f]{64})$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/blocks/:block_id"
    }

    /// Try to decode this request.
    /// Ensure the request is well-formed and validate the structure.
    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        captures: &Captures,
        query: Option<&str>,
        _body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        if preamble.get_content_length() != 0 {
            return Err(Error::DecodeError(
                "Invalid Http request: expected 0-length body".to_string(),
            ));
        }

        let block_id_str = captures
            .name("block_id")
            .ok_or_else(|| {
                Error::DecodeError("Failed to match path to block ID group".to_string())
            })?
            .as_str();

        let block_id = BitcoinZBlockId::from_hex(block_id_str).map_err(|_| {
            Error::DecodeError("Invalid path: unparseable block ID".to_string())
        })?;
        self.block_id = Some(block_id);

        Ok(HttpRequestContents::new().query_string(query))
    }
}
impl RPCRequestHandler for RPCBitcoinZBlockRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.block_id = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut BitcoinZNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let block_id = self
            .block_id
            .take()
            .ok_or(NetError::SendError("Missing `block_id`".into()))?;

        let stream_res =
            node.with_node_state(|_network, _sortdb, chainstate, _mempool, _rpc_args| {
                let Some((tenure_id, parent_block_id)) = chainstate
                    .bitcoinz_blocks_db()
                    .get_tenure_and_parent_block_id(&block_id)?
                else {
                    return Err(ChainError::NoSuchBlockError);
                };
                BitcoinZBlockStream::new(chainstate, block_id.clone(), tenure_id, parent_block_id)
            });

        // Start loading up the block
        let stream = match stream_res {
            Ok(stream) => stream,
            Err(ChainError::NoSuchBlockError) => {
                return BitcoinZHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new(format!("No such block {:?}\n", &block_id)),
                )
                .try_into_contents()
                .map_err(NetError::from)
            }
            Err(e) => {
                let msg = format!("Failed to load block {}: {:?}\n", &block_id, &e);
                warn!("{}", &msg);
                return BitcoinZHttpResponse::new_error(&preamble, &HttpServerError::new(msg))
                    .try_into_contents()
                    .map_err(NetError::from);
            }
        };

        let resp_preamble = HttpResponsePreamble::from_http_request_preamble(
            &preamble,
            200,
            "OK",
            None,
            HttpContentType::Bytes,
        );

        Ok((
            resp_preamble,
            HttpResponseContents::from_stream(Box::new(stream)),
        ))
    }
}
impl HttpResponse for RPCBitcoinZBlockRequestHandler {
    /// Decode this response from a byte stream.  This is called by the client to decode this
    /// message.
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let bytes = parse_bytes(preamble, body, MAX_MESSAGE_LEN.into())?;
        Ok(HttpResponsePayload::Bytes(bytes))
    }
}

/// Stream implementation for a BitcoinZ block
impl HttpChunkGenerator for BitcoinZBlockStream {
    #[cfg(test)]
    fn hint_chunk_size(&self) -> usize {
        32
    }

    #[cfg(not(test))]
    fn hint_chunk_size(&self) -> usize {
        4096
    }

    fn generate_next_chunk(&mut self) -> Result<Vec<u8>, String> {
        let mut blob_fd = self
            .staging_db_conn
            .open_bitcoinz_block(self.rowid, false)
            .map_err(|e| {
                let msg = format!(
                    "Failed to open BitcoinZ block {}: {:?}",
                    &self.index_block_hash, &e
                );
                warn!("{}", &msg);
                msg
            })?;

        blob_fd.seek(SeekFrom::Start(self.offset)).map_err(|e| {
            let msg = format!(
                "Failed to read BitcoinZ block {}: {:?}",
                &self.index_block_hash, &e
            );
            warn!("{}", &msg);
            msg
        })?;

        let mut buf = vec![0u8; self.hint_chunk_size()];
        let num_read = blob_fd.read(&mut buf).map_err(|e| {
            let msg = format!(
                "Failed to read BitcoinZ block {}: {:?}",
                &self.index_block_hash, &e
            );
            warn!("{}", &msg);
            msg
        })?;

        buf.truncate(num_read);

        self.offset += num_read as u64;
        self.total_bytes += num_read as u64;

        Ok(buf)
    }
}
impl StacksHttpRequest {
    pub fn new_get_bitcoinz_block(host: PeerHost, block_id: BitcoinZBlockId) -> BitcoinZHttpRequest {
        BitcoinZHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v3/blocks/{}", &block_id),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    /// Decode an HTTP response into a block.
    /// If it fails, return Self::Error(..)
    pub fn decode_bitcoinz_block(self) -> Result<BitcoinZBlock, NetError> {
        let contents = self.get_http_payload_ok()?;

        // contents will be raw bytes
        let block_bytes: Vec<u8> = contents.try_into()?;
        let block = BitcoinZBlock::consensus_deserialize(&mut &block_bytes[..])?;

        Ok(block)
    }
}
