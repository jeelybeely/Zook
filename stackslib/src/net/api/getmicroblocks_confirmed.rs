// Adapted `getmicroblocks_confirmed.rs` for the Zook Network
// Replacing STX/Stacks-specific logic with zBTCZ and BitcoinZ structures

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::{fs, io};

use regex::{Captures, Regex};
use serde::de::Error as de_Error;
use btcz_common::codec::{read_next, BitcoinZMessageCodec, MAX_MESSAGE_LEN};
use btcz_common::types::chainstate::{BlockHeaderHash, BitcoinZBlockId};
use btcz_common::types::net::PeerHost;
use btcz_common::util::hash::to_hex;
use {serde, serde_json};

use crate::chainstate::btcz::db::BitcoinZChainState;
use crate::chainstate::btcz::{Error as ChainError, BitcoinZBlockHeader, BitcoinZMicroblock};
use crate::net::api::getmicroblocks_indexed::BitcoinZIndexedMicroblockStream;
use crate::net::http::{
    parse_bytes, Error, HttpBadRequest, HttpChunkGenerator, HttpContentType, HttpNotFound,
    HttpRequest, HttpRequestContents, HttpRequestPreamble, HttpResponse, HttpResponseContents,
    HttpResponsePayload, HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{
    request, HttpRequestContentsExtensions, RPCRequestHandler, BitcoinZHttp, BitcoinZHttpRequest,
    BitcoinZHttpResponse,
};
use crate::net::{Error as NetError, BitcoinZNodeState, TipRequest, MAX_HEADERS};
use crate::util_lib::db::{DBConn, Error as DBError};

#[derive(Clone)]
pub struct RPCMicroblocksConfirmedRequestHandler {
    pub block_id: Option<BitcoinZBlockId>,
}

impl RPCMicroblocksConfirmedRequestHandler {
    pub fn new() -> Self {
        Self { block_id: None }
    }
}
impl BitcoinZIndexedMicroblockStream {
    /// Make a new indexed microblock streamer using the descendent BitcoinZ anchored block
    pub fn new_confirmed(
        chainstate: &BitcoinZChainState,
        child_block_id: &BitcoinZBlockId,
    ) -> Result<Self, ChainError> {
        let tail_microblock_index_hash =
            if let Some(bhh) = chainstate.get_confirmed_microblock_index_hash(child_block_id)? {
                bhh
            } else {
                return Err(ChainError::NoSuchBlockError);
            };

        BitcoinZIndexedMicroblockStream::new(chainstate, &tail_microblock_index_hash)
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCMicroblocksConfirmedRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v2/microblocks/confirmed/(?P<block_id>[0-9a-f]{64})$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/microblocks/confirmed/:block_id"
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

        let block_id = request::get_block_hash(captures, "block_id")?;

        self.block_id = Some(block_id);
        Ok(HttpRequestContents::new().query_string(query))
    }
}
impl RPCRequestHandler for RPCMicroblocksConfirmedRequestHandler {
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
            .ok_or(NetError::SendError("`block_id` not set".into()))?;

        let stream_res =
            node.with_node_state(|_network, _sortdb, chainstate, _mempool, _rpc_args| {
                BitcoinZIndexedMicroblockStream::new_confirmed(chainstate, &block_id)
            });

        let stream = match stream_res {
            Ok(stream) => stream,
            Err(ChainError::NoSuchBlockError) => {
                return BitcoinZHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new(format!("No such block {:?}\n", &block_id)),
                )
                .try_into_contents()
                .map_err(NetError::from);
            }
            Err(e) => {
                let msg = format!("Failed to load block: {:?}\n", &e);
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
impl HttpResponse for RPCMicroblocksConfirmedRequestHandler {
    /// Decode this response from a byte stream. This is called by the client to decode this message.
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let bytes = parse_bytes(preamble, body, MAX_MESSAGE_LEN.into())?;
        Ok(HttpResponsePayload::Bytes(bytes))
    }
}

impl BitcoinZHttpRequest {
    pub fn new_getmicroblocks_confirmed(
        host: PeerHost,
        child_block_id: BitcoinZBlockId,
    ) -> BitcoinZHttpRequest {
        BitcoinZHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v2/microblocks/confirmed/{}", &child_block_id),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}
