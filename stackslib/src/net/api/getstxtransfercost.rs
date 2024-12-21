// Adapted `getstxtransfercost.rs` for the Zook Network
// Replaces STX-specific logic with zBTCZ and aligns with Zook Network goals

use std::io::{Read, Write};

use clarity::vm::costs::ExecutionCost;
use regex::{Captures, Regex};
use btcz_common::types::chainstate::{
    BlockHeaderHash, ConsensusHash, BitcoinZBlockId, BitcoinZPublicKey,
};
use btcz_common::types::net::PeerHost;
use btcz_common::types::BitcoinZPublicKeyBuffer;
use btcz_common::util::hash::{Hash160, Sha256Sum};
use url::form_urlencoded;

use crate::burnchains::affirmation::AffirmationMap;
use crate::burnchains::Txid;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::btcz::db::blocks::MINIMUM_TX_FEE_RATE_PER_BYTE;
use crate::chainstate::btcz::db::BitcoinZChainState;
use crate::core::mempool::MemPoolDB;
use crate::net::api::postfeerate::RPCPostFeeRateRequestHandler;
use crate::net::http::{
    parse_json, Error, HttpBadRequest, HttpRequest, HttpRequestContents, HttpRequestPreamble,
    HttpResponse, HttpResponseContents, HttpResponsePayload, HttpResponsePreamble,
};
use crate::net::httpcore::{
    HttpPreambleExtensions, RPCRequestHandler, BitcoinZHttpRequest, BitcoinZHttpResponse,
};
use crate::net::p2p::PeerNetwork;
use crate::net::{Error as NetError, HttpServerError, BitcoinZNodeState};
use crate::version_string;

pub(crate) const SINGLESIG_TX_TRANSFER_LEN: u64 = 180;

#[derive(Clone)]
pub struct RPCGetZBTCZTransferCostRequestHandler {}

impl RPCGetZBTCZTransferCostRequestHandler {
    pub fn new() -> Self {
        Self {}
    }
}
impl HttpRequest for RPCGetZBTCZTransferCostRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v2/fees/transfer$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/fees/transfer"
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
impl RPCRequestHandler for RPCGetZBTCZTransferCostRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {}

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut BitcoinZNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        // Estimated transaction length for zBTCZ transfer
        let estimated_len = SINGLESIG_TX_TRANSFER_LEN;

        let fee_resp = node.with_node_state(|_network, sortdb, _chainstate, _mempool, rpc_args| {
            let tip = self.get_canonical_burn_chain_tip(&preamble, sortdb)?;
            let btcz_epoch = self.get_btcz_epoch(&preamble, sortdb, tip.block_height)?;

            if let Some((_, fee_estimator, metric)) = rpc_args.get_estimators_ref() {
                // zBTCZ transfer transactions have minimal runtime cost
                let estimated_cost = ExecutionCost::ZERO;
                let estimations =
                    RPCPostFeeRateRequestHandler::estimate_tx_fee_from_cost_and_length(
                        &preamble,
                        fee_estimator,
                        metric,
                        estimated_cost,
                        estimated_len,
                        btcz_epoch,
                    )?
                    .estimations;
                if estimations.len() != 3 {
                    return Err(BitcoinZHttpResponse::new_error(
                        &preamble,
                        &HttpServerError::new(
                            "Logic error in fee estimation: did not get three estimates".into(),
                        ),
                    ));
                }

                // Safety -- checked estimations.len() == 3 above
                let median_estimation = &estimations[1];

                // NOTE: this returns the fee _rate_
                Ok(median_estimation.fee / estimated_len)
            } else {
                debug!("Fee and cost estimation not configured on this BitcoinZ node");
                Ok(MINIMUM_TX_FEE_RATE_PER_BYTE)
            }
        });

        let fee = match fee_resp {
            Ok(fee) => fee,
            Err(response) => {
                return response.try_into_contents().map_err(NetError::from);
            }
        };

        let mut preamble = HttpResponsePreamble::ok_json(&preamble);
        preamble.set_canonical_btcz_tip_height(Some(node.canonical_btcz_tip_height()));
        let body = HttpResponseContents::try_from_json(&fee)?;
        Ok((preamble, body))
    }
}
impl BitcoinZHttpRequest {
    pub fn new_get_zbtcz_transfer_cost(host: PeerHost) -> BitcoinZHttpRequest {
        let contents = HttpRequestContents::new();
        BitcoinZHttpRequest::new_for_peer(host, "GET".into(), "/v2/fees/transfer".into(), contents)
            .expect("FATAL: failed to construct request from infallible data")
    }
}

impl BitcoinZHttpResponse {
    pub fn decode_zbtcz_transfer_fee(self) -> Result<u64, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let fee: u64 = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(fee)
    }
}
