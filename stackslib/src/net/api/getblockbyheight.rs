// Adapted `getblockbyheight.rs` for the Zook Network
// Aligning with zBTCZ and BitcoinZ structures

use std::io::{Read, Seek, SeekFrom, Write};
use std::{fs, io};

use regex::{Captures, Regex};
use serde::de::Error as de_Error;
use btcz_common::codec::{BitcoinZMessageCodec, MAX_MESSAGE_LEN};
use btcz_common::types::chainstate::{ConsensusHash, BitcoinZBlockId};
use btcz_common::types::net::PeerHost;
use {serde, serde_json};

use crate::chainstate::nakamoto::{
    BitcoinZBlock, BitcoinZChainState, BitcoinZStagingBlocksConn, BitcoinZDBIndexed,
};
use crate::chainstate::btcz::db::BitcoinZChainState;
use crate::chainstate::btcz::Error as ChainError;
use crate::net::api::getblock_v3::{BitcoinZBlockStream, RPCBitcoinZBlockRequestHandler};
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
pub struct RPCBitcoinZBlockByHeightRequestHandler {
    pub block_height: Option<u64>,
}

impl RPCBitcoinZBlockByHeightRequestHandler {
    pub fn new() -> Self {
        Self { block_height: None }
    }
}
/// Decode the HTTP request
impl HttpRequest for RPCBitcoinZBlockByHeightRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/blocks/height/(?P<block_height>[0-9]{1,20})$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/blocks/height/:block_height"
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

        let block_height_str = captures
            .name("block_height")
            .ok_or_else(|| {
                Error::DecodeError("Failed to match path to block height group".to_string())
            })?
            .as_str();

        let block_height = block_height_str.parse::<u64>().map_err(|_| {
            Error::DecodeError("Invalid path: unparseable block height".to_string())
        })?;
        self.block_height = Some(block_height);

        Ok(HttpRequestContents::new().query_string(query))
    }
}
impl RPCRequestHandler for RPCBitcoinZBlockByHeightRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.block_height = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        contents: HttpRequestContents,
        node: &mut BitcoinZNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let block_height = self
            .block_height
            .take()
            .ok_or(NetError::SendError("Missing `block_height`".into()))?;

        let tip = match node.load_btcz_chain_tip(&preamble, &contents) {
            Ok(tip) => tip,
            Err(error_resp) => {
                return error_resp.try_into_contents().map_err(NetError::from);
            }
        };

        let index_block_hash_res =
            node.with_node_state(|_network, _sortdb, chainstate, _mempool, _rpc_args| {
                chainstate
                    .index_conn()
                    .get_ancestor_block_hash(block_height, &tip)
            });

        let block_id = match index_block_hash_res {
            Ok(index_block_hash_opt) => match index_block_hash_opt {
                Some(index_block_hash) => index_block_hash,
                None => {
                    let msg = format!("No such block #{:?}\n", block_height);
                    warn!("{}", &msg);
                    return BitcoinZHttpResponse::new_error(&preamble, &HttpNotFound::new(msg))
                        .try_into_contents()
                        .map_err(NetError::from);
                }
            },
            Err(e) => {
                let msg = format!("Failed to load block #{}: {:?}\n", block_height, &e);
                warn!("{}", &msg);
                return BitcoinZHttpResponse::new_error(&preamble, &HttpServerError::new(msg))
                    .try_into_contents()
                    .map_err(NetError::from);
            }
        };

        let stream_res =
            node.with_node_state(|_network, _sortdb, chainstate, _mempool, _rpc_args| {
                let Some((tenure_id, parent_block_id)) = chainstate
                    .bitcoinz_blocks_db()
                    .get_tenure_and_parent_block_id(&block_id)?
                else {
                    return Err(ChainError::NoSuchBlockError);
                };
                BitcoinZBlockStream::new(chainstate, block_id, tenure_id, parent_block_id)
            });

        let stream = match stream_res {
            Ok(stream) => stream,
            Err(ChainError::NoSuchBlockError) => {
                return BitcoinZHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new(format!("No such block #{:?}\n", &block_height)),
                )
                .try_into_contents()
                .map_err(NetError::from)
            }
            Err(e) => {
                let msg = format!("Failed to load block #{}: {:?}\n", block_height, &e);
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
impl RPCRequestHandler for RPCBitcoinZBlockByHeightRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.block_height = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        contents: HttpRequestContents,
        node: &mut BitcoinZNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let block_height = self
            .block_height
            .take()
            .ok_or(NetError::SendError("Missing `block_height`".into()))?;

        let tip = match node.load_btcz_chain_tip(&preamble, &contents) {
            Ok(tip) => tip,
            Err(error_resp) => {
                return error_resp.try_into_contents().map_err(NetError::from);
            }
        };

        let index_block_hash_res =
            node.with_node_state(|_network, _sortdb, chainstate, _mempool, _rpc_args| {
                chainstate
                    .index_conn()
                    .get_ancestor_block_hash(block_height, &tip)
            });

        let block_id = match index_block_hash_res {
            Ok(index_block_hash_opt) => match index_block_hash_opt {
                Some(index_block_hash) => index_block_hash,
                None => {
                    let msg = format!("No such block #{:?}\n", block_height);
                    warn!("{}", &msg);
                    return BitcoinZHttpResponse::new_error(&preamble, &HttpNotFound::new(msg))
                        .try_into_contents()
                        .map_err(NetError::from);
                }
            },
            Err(e) => {
                let msg = format!("Failed to load block #{}: {:?}\n", block_height, &e);
                warn!("{}", &msg);
                return BitcoinZHttpResponse::new_error(&preamble, &HttpServerError::new(msg))
                    .try_into_contents()
                    .map_err(NetError::from);
            }
        };

        let stream_res =
            node.with_node_state(|_network, _sortdb, chainstate, _mempool, _rpc_args| {
                let Some((tenure_id, parent_block_id)) = chainstate
                    .bitcoinz_blocks_db()
                    .get_tenure_and_parent_block_id(&block_id)?
                else {
                    return Err(ChainError::NoSuchBlockError);
                };
                BitcoinZBlockStream::new(chainstate, block_id, tenure_id, parent_block_id)
            });

        let stream = match stream_res {
            Ok(stream) => stream,
            Err(ChainError::NoSuchBlockError) => {
                return BitcoinZHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new(format!("No such block #{:?}\n", &block_height)),
                )
                .try_into_contents()
                .map_err(NetError::from)
            }
            Err(e) => {
                let msg = format!("Failed to load block #{}: {:?}\n", block_height, &e);
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

/// Decode the HTTP response
impl HttpResponse for RPCBitcoinZBlockByHeightRequestHandler {
    /// Decode this response from a byte stream.  This is called by the client to decode this
    /// message
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
    pub fn new_get_bitcoinz_block_by_height(
        host: PeerHost,
        block_height: u64,
        tip: TipRequest,
    ) -> BitcoinZHttpRequest {
        BitcoinZHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v3/blocks/height/{}", block_height),
            HttpRequestContents::new().for_tip(tip),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}
