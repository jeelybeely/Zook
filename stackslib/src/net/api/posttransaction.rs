// Adapted `posttransaction.rs` for the Zook Network
// Replacing STX/Stacks-specific logic with zBTCZ and BitcoinZ structures

use std::io::{Read, Write};

use clarity::vm::costs::ExecutionCost;
use regex::{Captures, Regex};
use btcz_common::codec::{Error as CodecError, BitcoinZMessageCodec, MAX_PAYLOAD_LEN};
use btcz_common::types::chainstate::{
    BlockHeaderHash, ConsensusHash, BitcoinZBlockId, BitcoinZPublicKey,
};
use btcz_common::types::net::PeerHost;
use btcz_common::types::BitcoinZPublicKeyBuffer;
use btcz_common::util::hash::{hex_bytes, to_hex, Hash160, Sha256Sum};
use btcz_common::util::retry::BoundReader;

use crate::burnchains::affirmation::AffirmationMap;
use crate::burnchains::Txid;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::btcz::db::BitcoinZChainState;
use crate::chainstate::btcz::{BitcoinZTransaction, TransactionPayload};
use crate::core::mempool::MemPoolDB;
use crate::cost_estimates::FeeRateEstimate;
use crate::net::http::{
    parse_json, Error, HttpBadRequest, HttpContentType, HttpNotFound, HttpRequest,
    HttpRequestContents, HttpRequestPreamble, HttpResponse, HttpResponseContents,
    HttpResponsePayload, HttpResponsePreamble, HttpServerError, HttpVersion,
};
use crate::net::httpcore::{
    HttpPreambleExtensions, RPCRequestHandler, BitcoinZHttpRequest, BitcoinZHttpResponse,
};
use crate::net::p2p::PeerNetwork;
use crate::net::relay::Relayer;
use crate::net::{Attachment, Error as NetError, BitcoinZMessageType, BitcoinZNodeState};

#[derive(Serialize, Deserialize)]
pub struct PostTransactionRequestBody {
    pub tx: String,
    pub attachment: Option<String>,
}

#[derive(Clone)]
pub struct RPCPostTransactionRequestHandler {
    pub tx: Option<BitcoinZTransaction>,
    pub attachment: Option<Attachment>,
}

impl RPCPostTransactionRequestHandler {
    pub fn new() -> Self {
        Self {
            tx: None,
            attachment: None,
        }
    }
    impl RPCPostTransactionRequestHandler {
        pub fn new() -> Self {
            Self {
                tx: None,
                attachment: None,
            }
        }
    
        /// Decode a bare transaction from the body
        fn parse_posttransaction_octets(mut body: &[u8]) -> Result<BitcoinZTransaction, Error> {
            let tx = BitcoinZTransaction::consensus_deserialize(&mut body).map_err(|e| {
                if let CodecError::DeserializeError(msg) = e {
                    Error::DecodeError(format!("Failed to deserialize posted transaction: {}", msg))
                } else {
                    e.into()
                }
            })?;
            Ok(tx)
        }
    
        /// Decode a JSON-encoded transaction and Atlas attachment pair
        fn parse_posttransaction_json(
            body: &[u8],
        ) -> Result<(BitcoinZTransaction, Option<Attachment>), Error> {
            let body: PostTransactionRequestBody = serde_json::from_slice(body)
                .map_err(|_e| Error::DecodeError("Failed to parse body".into()))?;
    
            let tx = {
                let tx_bytes = hex_bytes(&body.tx)
                    .map_err(|_e| Error::DecodeError("Failed to parse tx".into()))?;
                BitcoinZTransaction::consensus_deserialize(&mut &tx_bytes[..]).map_err(|e| {
                    if let CodecError::DeserializeError(msg) = e {
                        Error::DecodeError(format!("Failed to deserialize posted transaction: {}", msg))
                    } else {
                        e.into()
                    }
                })
            }?;
    
            let attachment = match body.attachment {
                None => None,
                Some(ref attachment_content) => {
                    let content = hex_bytes(attachment_content)
                        .map_err(|_e| Error::DecodeError("Failed to parse attachment".into()))?;
                    Some(Attachment::new(content))
                }
            };
    
            Ok((tx, attachment))
        }
    }
    impl HttpRequest for RPCPostTransactionRequestHandler {
        fn verb(&self) -> &'static str {
            "POST"
        }
    
        fn path_regex(&self) -> Regex {
            Regex::new(r#"^/v2/transactions$"#).unwrap()
        }
    
        fn metrics_identifier(&self) -> &str {
            "/v2/transactions"
        }
    
        /// Try to decode this request.
        /// Ensure the request is well-formed and validate the structure.
        fn try_parse_request(
            &mut self,
            preamble: &HttpRequestPreamble,
            _captures: &Captures,
            query: Option<&str>,
            body: &[u8],
        ) -> Result<HttpRequestContents, Error> {
            if preamble.get_content_length() == 0 {
                return Err(Error::DecodeError(
                    "Invalid Http request: expected non-zero-length body for PostTransaction"
                        .to_string(),
                ));
            }
    
            if preamble.get_content_length() > MAX_PAYLOAD_LEN {
                return Err(Error::DecodeError(
                    "Invalid Http request: PostTransaction body is too big".to_string(),
                ));
            }
    
            match preamble.content_type {
                None => {
                    return Err(Error::DecodeError(
                        "Missing Content-Type for transaction".to_string(),
                    ));
                }
                Some(HttpContentType::Bytes) => {
                    // expect a bare transaction
                    let tx = Self::parse_posttransaction_octets(body)?;
                    self.tx = Some(tx);
                    self.attachment = None;
                }
                Some(HttpContentType::JSON) => {
                    // expect a transaction and an attachment
                    let (tx, attachment_opt) = Self::parse_posttransaction_json(body)?;
                    self.tx = Some(tx);
                    self.attachment = attachment_opt;
                }
                _ => {
                    return Err(Error::DecodeError(
                        "Wrong Content-Type for transaction; expected application/json or application/octet-stream".to_string(),
                    ));
                }
            }
    
            Ok(HttpRequestContents::new().query_string(query))
        }
    }
    impl RPCRequestHandler for RPCPostTransactionRequestHandler {
        /// Reset internal state
        fn restart(&mut self) {
            self.tx = None;
            self.attachment = None;
        }
    
        /// Make the response
        fn try_handle_request(
            &mut self,
            preamble: HttpRequestPreamble,
            _contents: HttpRequestContents,
            node: &mut BitcoinZNodeState,
        ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
            let tx = self
                .tx
                .take()
                .ok_or(NetError::SendError("`tx` not set".into()))?;
            let attachment_opt = self.attachment.take();
    
            let txid = tx.txid();
    
            let data_resp = node.with_node_state(|network, sortdb, chainstate, mempool, rpc_args| {
                if mempool.has_tx(&txid) {
                    debug!("Mempool already has POSTed transaction {}", &txid);
                    return Ok(false);
                }
    
                let event_observer = rpc_args.event_observer.as_deref();
                let burn_tip = self.get_canonical_burn_chain_tip(&preamble, sortdb)?;
                let btcz_epoch = self.get_btcz_epoch(&preamble, sortdb, burn_tip.block_height)?;
    
                // Check for defects determinable statically
                if Relayer::do_static_problematic_checks()
                    && !Relayer::static_check_problematic_relayed_tx(
                        chainstate.mainnet,
                        btcz_epoch.epoch_id,
                        &tx,
                        network.ast_rules,
                    )
                    .is_ok()
                {
                    debug!(
                        "Transaction {} is problematic in rules {:?}; will not store or relay",
                        &tx.txid(),
                        network.ast_rules
                    );
                    return Ok(false);
                }
    
                let zook_tip = self.get_zook_chain_tip(&preamble, sortdb, chainstate)?;
    
                // Accept to mempool
                if let Err(e) = mempool.submit(
                    chainstate,
                    sortdb,
                    &zook_tip.consensus_hash,
                    &zook_tip.anchored_header.block_hash(),
                    &tx,
                    event_observer,
                    &btcz_epoch.block_limit,
                    &btcz_epoch.epoch_id,
                ) {
                    return Err(BitcoinZHttpResponse::new_error(
                        &preamble,
                        &HttpBadRequest::new_json(e.into_json(&txid)),
                    ));
                };
    
                // Store attachment if it's part of a contract call
                if let Some(ref attachment) = attachment_opt {
                    if let TransactionPayload::ContractCall(ref contract_call) = tx.payload {
                        if network
                            .get_atlasdb()
                            .should_keep_attachment(&contract_call.to_clarity_contract_id(), attachment)
                        {
                            network
                                .get_atlasdb_mut()
                                .insert_uninstantiated_attachment(attachment)
                                .map_err(|e| {
                                    BitcoinZHttpResponse::new_error(
                                        &preamble,
                                        &HttpServerError::new(format!(
                                            "Failed to store contract-call attachment: {:?}",
                                            &e
                                        )),
                                    )
                                })?;
                        }
                    }
                }
    
                Ok(true)
            });
    
            let (accepted, txid) = match data_resp {
                Ok(accepted) => (accepted, txid),
                Err(response) => {
                    return response.try_into_contents().map_err(NetError::from);
                }
            };
    
            // Forward to the P2P network
            if accepted {
                node.set_relay_message(BitcoinZMessageType::Transaction(tx));
            }
    
            let mut preamble = HttpResponsePreamble::ok_json(&preamble);
            preamble.set_canonical_btcz_tip_height(Some(node.canonical_btcz_tip_height()));
            let body = HttpResponseContents::try_from_json(&txid)?;
            Ok((preamble, body))
        }
    }
    /// Decode the HTTP response
impl HttpResponse for RPCPostTransactionRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let txid: Txid = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(txid)?)
    }
}

impl BitcoinZHttpRequest {
    /// Make a new post-transaction request
    pub fn new_post_transaction(host: PeerHost, tx: BitcoinZTransaction) -> BitcoinZHttpRequest {
        BitcoinZHttpRequest::new_for_peer(
            host,
            "POST".into(),
            "/v2/transactions".to_string(),
            HttpRequestContents::new().payload_btcz(&tx),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }

    /// Make a new post-transaction request with an attachment
    pub fn new_post_transaction_with_attachment(
        host: PeerHost,
        tx: BitcoinZTransaction,
        attachment: Option<Vec<u8>>,
    ) -> BitcoinZHttpRequest {
        BitcoinZHttpRequest::new_for_peer(
            host,
            "POST".into(),
            "/v2/transactions".to_string(),
            HttpRequestContents::new().payload_json(
                serde_json::to_value(PostTransactionRequestBody {
                    tx: to_hex(&tx.serialize_to_vec()),
                    attachment: attachment.map(|bytes| to_hex(&bytes)),
                })
                .expect("FATAL: failed to construct request from infallible data"),
            ),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl BitcoinZHttpResponse {
    #[cfg(test)]
    pub fn new_posttransaction(txid: Txid, with_content_length: bool) -> BitcoinZHttpResponse {
        let value = serde_json::to_value(txid).expect("FATAL: failed to serialize infallible data");
        let length = serde_json::to_string(&value)
            .expect("FATAL: failed to serialize infallible data")
            .len();
        let preamble = HttpResponsePreamble::new(
            HttpVersion::Http11,
            200,
            "OK".to_string(),
            if with_content_length {
                Some(length as u32)
            } else {
                None
            },
            HttpContentType::JSON,
            true,
        );
        let body = HttpResponsePayload::JSON(value);
        BitcoinZHttpResponse::new(preamble, body)
    }

    pub fn decode_txid(self) -> Result<Txid, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let txid: Txid = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(txid)
    }
}
