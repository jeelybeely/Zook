// Adapted `getstackers.rs` for the Zook Network
// Replaces STX-specific logic with zBTCZ and aligns with Zook Network goals

use regex::{Captures, Regex};
use serde_json::json;
use btcz_common::types::chainstate::BitcoinZBlockId;
use btcz_common::types::net::PeerHost;
use btcz_common::util::hash::Sha256Sum;

use crate::burnchains::Burnchain;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::coordinator::OnChainRewardSetProvider;
use crate::chainstate::btcz::boot::{
    PoxVersions, RewardSet, POX_1_NAME, POX_2_NAME, POX_3_NAME, POX_4_NAME,
};
use crate::chainstate::btcz::db::BitcoinZChainState;
use crate::chainstate::btcz::Error as ChainError;
use crate::core::mempool::MemPoolDB;
use crate::net::http::{
    parse_json, Error, HttpBadRequest, HttpNotFound, HttpRequest, HttpRequestContents,
    HttpRequestPreamble, HttpResponse, HttpResponseContents, HttpResponsePayload,
    HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{
    HttpPreambleExtensions, HttpRequestContentsExtensions, RPCRequestHandler, BitcoinZHttp,
    BitcoinZHttpRequest, BitcoinZHttpResponse,
};
use crate::net::p2p::PeerNetwork;
use crate::net::{Error as NetError, BitcoinZNodeState, TipRequest};
use crate::util_lib::boot::boot_code_id;
use crate::util_lib::db::Error as DBError;

#[derive(Clone, Default)]
pub struct GetStackersRequestHandler {
    cycle_number: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetStackersResponse {
    pub stacker_set: RewardSet,
}

pub enum GetStackersErrors {
    NotAvailableYet(crate::chainstate::coordinator::Error),
    Other(String),
}

impl GetStackersErrors {
    pub const NOT_AVAILABLE_ERR_TYPE: &'static str = "not_available_try_again";
    pub const OTHER_ERR_TYPE: &'static str = "other";

    pub fn error_type_string(&self) -> &'static str {
        match self {
            Self::NotAvailableYet(_) => Self::NOT_AVAILABLE_ERR_TYPE,
            Self::Other(_) => Self::OTHER_ERR_TYPE,
        }
    }
}
impl HttpRequest for GetStackersRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/stacker_set/(?P<cycle_num>[0-9]{1,10})$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/stacker_set/:cycle_num"
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
                "Invalid Http request: expected 0-length body".into(),
            ));
        }

        let Some(cycle_num_str) = captures.name("cycle_num") else {
            return Err(Error::DecodeError(
                "Missing in request path: `cycle_num`".into(),
            ));
        };
        let cycle_num = u64::from_str_radix(cycle_num_str.into(), 10)
            .map_err(|e| Error::DecodeError(format!("Failed to parse cycle number: {e}")))?;

        self.cycle_number = Some(cycle_num);

        Ok(HttpRequestContents::new().query_string(query))
    }
}
impl RPCRequestHandler for GetStackersRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.cycle_number = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        contents: HttpRequestContents,
        node: &mut BitcoinZNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let tip = match node.load_btcz_chain_tip(&preamble, &contents) {
            Ok(tip) => tip,
            Err(error_resp) => {
                return error_resp.try_into_contents().map_err(NetError::from);
            }
        };
        let Some(cycle_number) = self.cycle_number.clone() else {
            return BitcoinZHttpResponse::new_error(
                &preamble,
                &HttpBadRequest::new_json(json!({"response": "error", "err_msg": "Failed to read cycle number in request"}))
            )
                .try_into_contents()
                .map_err(NetError::from);
        };

        let stacker_response =
            node.with_node_state(|network, sortdb, chainstate, _mempool, _rpc_args| {
                GetStackersResponse::load(
                    sortdb,
                    chainstate,
                    &tip,
                    network.get_burnchain(),
                    cycle_number,
                )
            });

        let response = match stacker_response {
            Ok(response) => response,
            Err(error) => {
                return BitcoinZHttpResponse::new_error(
                    &preamble,
                    &HttpBadRequest::new_json(json!({
                        "response": "error",
                        "err_type": error.error_type_string(),
                        "err_msg": error.to_string()})),
                )
                .try_into_contents()
                .map_err(NetError::from)
            }
        };

        let mut preamble = HttpResponsePreamble::ok_json(&preamble);
        preamble.set_canonical_btcz_tip_height(Some(node.canonical_btcz_tip_height()));
        let body = HttpResponseContents::try_from_json(&response)?;
        Ok((preamble, body))
    }
}
impl HttpResponse for GetStackersRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let response: GetStackersResponse = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(response)?)
    }
}

impl BitcoinZHttpRequest {
    /// Make a new getstackers request to this endpoint
    pub fn new_getstackers(
        host: PeerHost,
        cycle_num: u64,
        tip_req: TipRequest,
    ) -> BitcoinZHttpRequest {
        BitcoinZHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v3/stacker_set/{cycle_num}"),
            HttpRequestContents::new().for_tip(tip_req),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl BitcoinZHttpResponse {
    pub fn decode_stacker_set(self) -> Result<GetStackersResponse, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let response: GetStackersResponse = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(response)
    }
}
impl HttpResponse for GetStackersRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let response: GetStackersResponse = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(response)?)
    }
}

impl BitcoinZHttpRequest {
    /// Make a new getstackers request to this endpoint
    pub fn new_getstackers(
        host: PeerHost,
        cycle_num: u64,
        tip_req: TipRequest,
    ) -> BitcoinZHttpRequest {
        BitcoinZHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v3/stacker_set/{cycle_num}"),
            HttpRequestContents::new().for_tip(tip_req),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl BitcoinZHttpResponse {
    pub fn decode_stacker_set(self) -> Result<GetStackersResponse, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let response: GetStackersResponse = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(response)
    }
}

#[cfg(test)]
mod test {
    use super::GetStackersErrors;

    #[test]
    // Test the formatting and error type strings of GetStackersErrors
    fn get_stackers_errors() {
        let not_available_err = GetStackersErrors::NotAvailableYet(
            crate::chainstate::coordinator::Error::PoXNotProcessedYet,
        );
        let other_err = GetStackersErrors::Other("foo".into());

        assert_eq!(
            not_available_err.error_type_string(),
            GetStackersErrors::NOT_AVAILABLE_ERR_TYPE
        );
        assert_eq!(
            other_err.error_type_string(),
            GetStackersErrors::OTHER_ERR_TYPE
        );

        assert!(not_available_err
            .to_string()
            .starts_with("Could not read reward set"));
        assert_eq!(other_err.to_string(), "foo".to_string());
    }

    #[test]
    fn test_decode_stacker_set() {
        use serde_json::json;

        let payload = json!({
            "stacker_set": "MockRewardSetData"
        });
        let serialized_payload = serde_json::to_vec(&payload).unwrap();

        let response = BitcoinZHttpResponse::decode_stacker_set(
            BitcoinZHttpResponse::mock_ok(serialized_payload),
        );

        assert!(response.is_ok());
        assert_eq!(response.unwrap().stacker_set, "MockRewardSetData");
    }
}
