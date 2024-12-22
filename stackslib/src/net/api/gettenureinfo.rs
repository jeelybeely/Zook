// Adapted `gettenureinfo.rs` for the Zook Network
// Replacing STX/Stacks-specific logic with zBTCZ and BitcoinZ structures

use std::io::{Read, Seek, SeekFrom, Write};
use std::{fs, io};

use regex::{Captures, Regex};
use serde::de::Error as de_Error;
use btcz_common::codec::{BitcoinZMessageCodec, MAX_MESSAGE_LEN};
use btcz_common::types::chainstate::{ConsensusHash, BitcoinZBlockId};
use btcz_common::types::net::PeerHost;
use btcz_common::util::hash::{to_hex, Sha512Trunc256Sum};
use {serde, serde_json};

use crate::chainstate::nakamoto::{
    NakamotoBlock, NakamotoChainState, NakamotoStagingBlocksConn,
};
use crate::chainstate::btcz::db::BitcoinZChainState;
use crate::chainstate::btcz::Error as ChainError;
use crate::net::api::getblock_v3::NakamotoBlockStream;
use crate::net::http::{
    parse_bytes, parse_json, Error, HttpBadRequest, HttpChunkGenerator, HttpContentType,
    HttpNotFound, HttpRequest, HttpRequestContents, HttpRequestPreamble, HttpResponse,
    HttpResponseContents, HttpResponsePayload, HttpResponsePreamble, HttpServerError, HttpVersion,
};
use crate::net::httpcore::{
    HttpRequestContentsExtensions, RPCRequestHandler, BitcoinZHttp, BitcoinZHttpRequest,
    BitcoinZHttpResponse,
};
use crate::net::{Error as NetError, BitcoinZNodeState, TipRequest, MAX_HEADERS};
use crate::util_lib::db::{DBConn, Error as DBError};

#[derive(Clone)]
pub struct RPCNakamotoTenureInfoRequestHandler {}

impl RPCNakamotoTenureInfoRequestHandler {
    pub fn new() -> Self {
        Self {}
    }
}

/// The view of this node's current tenure.
/// All of this information can be found from the PeerNetwork struct, so loading this up should
/// incur zero disk I/O.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct RPCGetTenureInfo {
    /// The highest known consensus hash (identifies the current tenure)
    pub consensus_hash: ConsensusHash,
    /// The tenure-start block ID of the current tenure
    pub tenure_start_block_id: BitcoinZBlockId,
    /// The consensus hash of the parent tenure
    pub parent_consensus_hash: ConsensusHash,
    /// The block hash of the parent tenure's start block
    pub parent_tenure_start_block_id: BitcoinZBlockId,
    /// The highest BitcoinZ block ID in the current tenure
    pub tip_block_id: BitcoinZBlockId,
    /// The height of this tip
    pub tip_height: u64,
    /// Which reward cycle we're in
    pub reward_cycle: u64,
}
/// Decode the HTTP request
impl HttpRequest for RPCNakamotoTenureInfoRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/tenures/info"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/tenures/info"
    }

    /// Try to decode this request.
    /// Ensure the request is well-formed and validate the structure.
    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        _captures: &Captures,
        query: Option<&str>,
        _body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        if preamble.get_content_length() != 0 {
            return Err(Error::DecodeError(
                "Invalid Http request: expected 0-length body".to_string(),
            ));
        }
        Ok(HttpRequestContents::new().query_string(query))
    }
}
impl RPCRequestHandler for RPCNakamotoTenureInfoRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {}

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut BitcoinZNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let info = node.with_node_state(|network, _sortdb, _chainstate, _mempool, _rpc_args| {
            RPCGetTenureInfo {
                consensus_hash: network.btcz_tip.consensus_hash.clone(),
                tenure_start_block_id: network.tenure_start_block_id.clone(),
                parent_consensus_hash: network.parent_btcz_tip.consensus_hash.clone(),
                parent_tenure_start_block_id: BitcoinZBlockId::new(
                    &network.parent_btcz_tip.consensus_hash,
                    &network.parent_btcz_tip.block_hash,
                ),
                tip_block_id: BitcoinZBlockId::new(
                    &network.btcz_tip.consensus_hash,
                    &network.btcz_tip.block_hash,
                ),
                tip_height: network.btcz_tip.height,
                reward_cycle: network
                    .burnchain
                    .block_height_to_reward_cycle(network.burnchain_tip.block_height)
                    .expect("FATAL: burnchain tip before system start"),
            }
        });

        let preamble = HttpResponsePreamble::ok_json(&preamble);
        let body = HttpResponseContents::try_from_json(&info)?;
        Ok((preamble, body))
    }
}
impl HttpResponse for RPCNakamotoTenureInfoRequestHandler {
    /// Decode this response from a byte stream. This is called by the client to decode this
    /// message
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let peer_info: RPCGetTenureInfo = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(peer_info)?)
    }
}

impl BitcoinZHttpRequest {
    /// Make a new getinfo request to this endpoint
    pub fn new_get_nakamoto_tenure_info(host: PeerHost) -> BitcoinZHttpRequest {
        BitcoinZHttpRequest::new_for_peer(
            host,
            "GET".into(),
            "/v3/tenures/info".into(),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl BitcoinZHttpResponse {
    pub fn decode_nakamoto_tenure_info(self) -> Result<RPCGetTenureInfo, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let tenure_info: RPCGetTenureInfo = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(tenure_info)
    }
}
