// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::io::{Read, Write};

use clarity::vm::clarity::ClarityConnection;
use clarity::vm::costs::{ExecutionCost, LimitedCostTracker};
use clarity::vm::types::{PrincipalData, StandardPrincipalData};
use clarity::vm::ClarityVersion;
use regex::{Captures, Regex};
use bitcoinz_common::types::chainstate::BitcoinzBlockId;
use bitcoinz_common::types::net::PeerHost;
use bitcoinz_common::types::BitcoinzEpochId;
use bitcoinz_common::util::hash::Sha256Sum;

use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::bitcoinz::boot::{
    ZPOX_1_NAME, ZPOX_2_NAME, ZPOX_3_NAME, ZPOX_4_NAME,
};
use crate::chainstate::bitcoinz::db::BitcoinzChainState;
use crate::chainstate::bitcoinz::Error as ChainError;
use crate::core::mempool::MemPoolDB;
use crate::core::BitcoinzEpoch;
use crate::net::http::{
    parse_json, Error, HttpNotFound, HttpRequest, HttpRequestContents, HttpRequestPreamble,
    HttpResponse, HttpResponseContents, HttpResponsePayload, HttpResponsePreamble,
    HttpServerError,
};
use crate::net::httpcore::{
    HttpPreambleExtensions, HttpRequestContentsExtensions, RPCRequestHandler, BitcoinzHttp,
    BitcoinzHttpRequest, BitcoinzHttpResponse,
};
use crate::net::p2p::PeerNetwork;
use crate::net::{Error as NetError, BitcoinzNodeState, TipRequest};
use crate::util_lib::boot::boot_code_id;
use crate::util_lib::db::Error as DBError;

#[derive(Clone)]
pub struct RPCZPoxInfoRequestHandler {}
impl RPCZPoxInfoRequestHandler {
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RPCZPoxCurrentCycleInfo {
    pub id: u64,
    pub min_threshold_zbtcz: u64,
    pub stacked_zbtcz: u64,
    pub is_pox_active: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RPCZPoxNextCycleInfo {
    pub id: u64,
    pub min_threshold_zbtcz: u64,
    pub min_increment_zbtcz: u64,
    pub stacked_zbtcz: u64,
    pub prepare_phase_start_block_height: u64,
    pub blocks_until_prepare_phase: i64,
    pub reward_phase_start_block_height: u64,
    pub blocks_until_reward_phase: u64,
    pub zbtcz_until_pox_rejection: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RPCZPoxContractVersion {
    pub contract_id: String,
    pub activation_bitcoinz_block_height: u64,
    pub first_reward_cycle_id: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RPCZPoxEpoch {
    pub epoch_id: BitcoinzEpochId,
    pub start_height: u64,
    pub end_height: u64,
    pub block_limit: ExecutionCost,
    pub network_epoch: u8,
}

impl From<BitcoinzEpoch> for RPCZPoxEpoch {
    fn from(epoch: BitcoinzEpoch) -> Self {
        Self {
            epoch_id: epoch.epoch_id,
            start_height: epoch.start_height,
            end_height: epoch.end_height,
            block_limit: epoch.block_limit,
            network_epoch: epoch.network_epoch,
        }
    }
}
/// The data we return on GET /v2/zpox
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RPCZPoxInfoData {
    pub contract_id: String,
    pub zpox_activation_threshold_zbtcz: u64,
    pub first_bitcoinz_block_height: u64,
    pub current_bitcoinz_block_height: u64,
    pub prepare_phase_block_length: u64,
    pub reward_phase_block_length: u64,
    pub reward_slots: u64,
    pub rejection_fraction: Option<u64>,
    pub total_liquid_supply_zbtcz: u64,
    pub current_cycle: RPCZPoxCurrentCycleInfo,
    pub next_cycle: RPCZPoxNextCycleInfo,
    pub epochs: Vec<RPCZPoxEpoch>,

    // below are included for backwards-compatibility
    pub min_amount_zbtcz: u64,
    pub prepare_cycle_length: u64,
    pub reward_cycle_id: u64,
    pub reward_cycle_length: u64,
    pub rejection_votes_left_required: Option<u64>,
    pub next_reward_cycle_in: u64,

    // Information specific to each PoX contract version
    pub contract_versions: Vec<RPCZPoxContractVersion>,
}

impl RPCZPoxInfoData {
    pub fn from_db(
        sortdb: &SortitionDB,
        chainstate: &mut BitcoinzChainState,
        tip: &BitcoinzBlockId,
        burnchain: &Burnchain,
    ) -> Result<RPCZPoxInfoData, NetError> {
        let mainnet = chainstate.mainnet;
        let chain_id = chainstate.chain_id;
        let current_burn_height =
            SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())?.block_height;

        let zpox_contract_name = burnchain
            .zpox_constants
            .active_zpox_contract(current_burn_height);

        let contract_identifier = boot_code_id(zpox_contract_name, mainnet);
        let function = "get-zpox-info";
        let cost_track = LimitedCostTracker::new_free();
        let sender = PrincipalData::Standard(StandardPrincipalData::transient());

        debug!(
            "Active zPoX contract is '{}' (current_burn_height = {}, v1_unlock_height = {}",
            &contract_identifier, current_burn_height, burnchain.zpox_constants.v1_unlock_height
        );

        // Note: should always be 0 unless somehow configured to start later
        let zpox_1_first_cycle = burnchain
            .block_height_to_reward_cycle(u64::from(burnchain.first_block_height))
            .ok_or(NetError::ChainstateError(
                "zPoX-1 first reward cycle begins before first burn block height".to_string(),
            ))?;

        let zpox_2_first_cycle = burnchain
            .block_height_to_reward_cycle(u64::from(burnchain.zpox_constants.v1_unlock_height))
            .ok_or(NetError::ChainstateError(
                "zPoX-2 first reward cycle begins before first burn block height".to_string(),
            ))?
            + 1;

        let zpox_3_first_cycle = burnchain
            .block_height_to_reward_cycle(u64::from(
                burnchain.zpox_constants.zpox_3_activation_height,
            ))
            .ok_or(NetError::ChainstateError(
                "zPoX-3 first reward cycle begins before first burn block height".to_string(),
            ))?
            + 1;

        let zpox_4_first_cycle = burnchain
            .block_height_to_reward_cycle(u64::from(
                burnchain.zpox_constants.zpox_4_activation_height,
            ))
            .ok_or(NetError::ChainstateError(
                "zPoX-4 first reward cycle begins before first burn block height".to_string(),
            ))?
            + 1;

        let data = chainstate
            .maybe_read_only_clarity_tx(
                &sortdb.index_handle_at_block(chainstate, tip)?,
                tip,
                |clarity_tx| {
                    clarity_tx.with_readonly_clarity_env(
                        mainnet,
                        chain_id,
                        ClarityVersion::Clarity2,
                        sender,
                        None,
                        cost_track,
                        |env| env.execute_contract(&contract_identifier, function, &[], true),
                    )
                },
            )
            .map_err(|_| NetError::NotFoundError)?;

        let res = match data {
            Some(Ok(res)) => res.expect_result_ok()?.expect_tuple()?,
            _ => return Err(NetError::DBError(DBError::NotFoundError)),
        };

        let first_bitcoinz_block_height = res
            .get("first-bitcoinz-block-height")
            .unwrap_or_else(|_| panic!("FATAL: no 'first-bitcoinz-block-height'"))
            .to_owned()
            .expect_u128()? as u64;

        let min_stacking_increment_zbtcz = res
            .get("min-amount-zbtcz")
            .unwrap_or_else(|_| panic!("FATAL: no 'min-amount-zbtcz'"))
            .to_owned()
            .expect_u128()? as u64;

        let prepare_cycle_length = res
            .get("prepare-cycle-length")
            .unwrap_or_else(|_| panic!("FATAL: no 'prepare-cycle-length'"))
            .to_owned()
            .expect_u128()? as u64;

        let reward_cycle_length = res
            .get("reward-cycle-length")
            .unwrap_or_else(|_| panic!("FATAL: no 'reward-cycle-length'"))
            .to_owned()
            .expect_u128()? as u64;

        let total_liquid_supply_zbtcz = res
            .get("total-liquid-supply-zbtcz")
            .unwrap_or_else(|_| panic!("FATAL: no 'total-liquid-supply-zbtcz'"))
            .to_owned()
            .expect_u128()? as u64;
        let has_rejection_data = zpox_contract_name == ZPOX_1_NAME
            || zpox_contract_name == ZPOX_2_NAME
            || zpox_contract_name == ZPOX_3_NAME;

        let (rejection_fraction, rejection_votes_left_required) = if has_rejection_data {
            let rejection_fraction = res
                .get("rejection-fraction")
                .unwrap_or_else(|_| panic!("FATAL: no 'rejection-fraction'"))
                .to_owned()
                .expect_u128()? as u64;

            let current_rejection_votes = res
                .get("current-rejection-votes")
                .unwrap_or_else(|_| panic!("FATAL: no 'current-rejection-votes'"))
                .to_owned()
                .expect_u128()? as u64;

            let total_required = (total_liquid_supply_zbtcz as u128 / 100)
                .checked_mul(rejection_fraction as u128)
                .ok_or_else(|| NetError::DBError(DBError::Overflow))?
                as u64;

            let votes_left = total_required.saturating_sub(current_rejection_votes);
            (Some(rejection_fraction), Some(votes_left))
        } else {
            (None, None)
        };

        let burnchain_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())?;

        let zpox_consts = &burnchain.zpox_constants;

        if prepare_cycle_length != zpox_consts.prepare_length as u64 {
            error!(
                "zPoX Constants in config mismatched with zPoX contract constants: {} != {}",
                prepare_cycle_length, zpox_consts.prepare_length
            );
            return Err(NetError::DBError(DBError::Corruption));
        }

        if reward_cycle_length != zpox_consts.reward_cycle_length as u64 {
            error!(
                "zPoX Constants in config mismatched with zPoX contract constants: {} != {}",
                reward_cycle_length, zpox_consts.reward_cycle_length
            );
            return Err(NetError::DBError(DBError::Corruption));
        }

        // Calculate `reward_cycle_id` accurately for clients
        let reward_cycle_id = burnchain
            .block_height_to_reward_cycle(burnchain_tip.block_height)
            .ok_or_else(|| {
                NetError::ChainstateError("Current burn block height is before BitcoinZ start".into())
            })?;
        let effective_height = burnchain_tip.block_height - first_bitcoinz_block_height;

        let next_reward_cycle_in = reward_cycle_length - (effective_height % reward_cycle_length);

        let next_rewards_start = burnchain_tip.block_height + next_reward_cycle_in;
        let next_prepare_phase_start = next_rewards_start - prepare_cycle_length;

        let next_prepare_phase_in = i64::try_from(next_prepare_phase_start)
            .map_err(|_| NetError::ChainstateError("Burn block height overflowed i64".into()))?
            - i64::try_from(burnchain_tip.block_height).map_err(|_| {
                NetError::ChainstateError("Burn block height overflowed i64".into())
            })?;

        let cur_block_zpox_contract = zpox_consts.active_zpox_contract(burnchain_tip.block_height);
        let cur_cycle_zpox_contract =
            zpox_consts.active_zpox_contract(burnchain.reward_cycle_to_block_height(reward_cycle_id));
        let next_cycle_zpox_contract = zpox_consts
            .active_zpox_contract(burnchain.reward_cycle_to_block_height(reward_cycle_id + 1));

        let cur_cycle_stacked_zbtcz = chainstate.get_total_zbtcz_stacked(
            &sortdb,
            tip,
            reward_cycle_id as u128,
            cur_cycle_zpox_contract,
        )?;
        let next_cycle_stacked_zbtcz =
            match chainstate.get_total_zbtcz_stacked(
                &sortdb,
                tip,
                reward_cycle_id as u128 + 1,
                next_cycle_zpox_contract,
            ) {
                Ok(zbtcz) => zbtcz,
                Err(ChainError::ClarityError(_)) => {
                    // contract not instantiated yet
                    0
                }
                Err(e) => {
                    return Err(e.into());
                }
            };

        let reward_slots = zpox_consts.reward_slots() as u64;

        let cur_cycle_threshold = BitcoinzChainState::get_threshold_from_participation(
            total_liquid_supply_zbtcz as u128,
            cur_cycle_stacked_zbtcz,
            reward_slots as u128,
        ) as u64;

        let next_threshold = BitcoinzChainState::get_threshold_from_participation(
            total_liquid_supply_zbtcz as u128,
            next_cycle_stacked_zbtcz,
            reward_slots as u128,
        ) as u64;

        let zpox_activation_threshold_zbtcz = (total_liquid_supply_zbtcz as u128)
            .checked_mul(zpox_consts.zpox_participation_threshold_pct as u128)
            .map(|x| x / 100)
            .ok_or_else(|| NetError::DBError(DBError::Overflow))?
            as u64;

        let cur_cycle_zpox_active = sortdb.is_zpox_active(burnchain, &burnchain_tip)?;
        let epochs: Vec<_> = SortitionDB::get_bitcoinz_epochs(sortdb.conn())?
            .into_iter()
            .map(|epoch| RPCZPoxEpoch::from(epoch))
            .collect();

        Ok(RPCZPoxInfoData {
            contract_id: boot_code_id(cur_block_zpox_contract, chainstate.mainnet).to_string(),
            zpox_activation_threshold_zbtcz,
            first_bitcoinz_block_height,
            current_bitcoinz_block_height: burnchain_tip.block_height,
            prepare_phase_block_length: prepare_cycle_length,
            reward_phase_block_length: reward_cycle_length - prepare_cycle_length,
            reward_slots,
            rejection_fraction,
            total_liquid_supply_zbtcz,
            current_cycle: RPCZPoxCurrentCycleInfo {
                id: reward_cycle_id,
                min_threshold_zbtcz: cur_cycle_threshold,
                stacked_zbtcz: cur_cycle_stacked_zbtcz as u64,
                is_pox_active: cur_cycle_zpox_active,
            },
            next_cycle: RPCZPoxNextCycleInfo {
                id: reward_cycle_id + 1,
                min_threshold_zbtcz: next_threshold,
                min_increment_zbtcz: min_stacking_increment_zbtcz,
                stacked_zbtcz: next_cycle_stacked_zbtcz as u64,
                prepare_phase_start_block_height: next_prepare_phase_start,
                blocks_until_prepare_phase: next_prepare_phase_in,
                reward_phase_start_block_height: next_rewards_start,
                blocks_until_reward_phase: next_reward_cycle_in,
                zbtcz_until_pox_rejection: rejection_votes_left_required,
            },
            epochs,
            min_amount_zbtcz: next_threshold,
            prepare_cycle_length,
            reward_cycle_id,
            reward_cycle_length,
            rejection_votes_left_required,
            next_reward_cycle_in,
            contract_versions: vec![
                RPCZPoxContractVersion {
                    contract_id: boot_code_id(ZPOX_1_NAME, chainstate.mainnet).to_string(),
                    activation_bitcoinz_block_height: burnchain.first_block_height,
                    first_reward_cycle_id: zpox_1_first_cycle,
                },
                RPCZPoxContractVersion {
                    contract_id: boot_code_id(ZPOX_2_NAME, chainstate.mainnet).to_string(),
                    activation_bitcoinz_block_height: burnchain.zpox_constants.v1_unlock_height
                        as u64,
                    first_reward_cycle_id: zpox_2_first_cycle,
                },
                RPCZPoxContractVersion {
                    contract_id: boot_code_id(ZPOX_3_NAME, chainstate.mainnet).to_string(),
                    activation_bitcoinz_block_height: burnchain
                        .zpox_constants
                        .zpox_3_activation_height
                        as u64,
                    first_reward_cycle_id: zpox_3_first_cycle,
                },
                RPCZPoxContractVersion {
                    contract_id: boot_code_id(ZPOX_4_NAME, chainstate.mainnet).to_string(),
                    activation_bitcoinz_block_height: burnchain
                        .zpox_constants
                        .zpox_4_activation_height
                        as u64,
                    first_reward_cycle_id: zpox_4_first_cycle,
                },
            ],
        })
    }
}
/// Decode the HTTP request
impl HttpRequest for RPCZPoxInfoRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v2/zpox$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/zpox"
    }

    /// Try to decode this request.
    /// There's nothing to load here, so just make sure the request is well-formed.
    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        _captures: &Captures,
        query: Option<&str>,
        _body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        if preamble.get_content_length() != 0 {
            return Err(Error::DecodeError(
                "Invalid Http request: expected 0-length body for GetZPoxInfo".to_string(),
            ));
        }

        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCZPoxInfoRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {}

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        contents: HttpRequestContents,
        node: &mut BitcoinzNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let tip = match node.load_bitcoinz_chain_tip(&preamble, &contents) {
            Ok(tip) => tip,
            Err(error_resp) => {
                return error_resp.try_into_contents().map_err(NetError::from);
            }
        };

        let zpox_info_res =
            node.with_node_state(|network, sortdb, chainstate, _mempool, _rpc_args| {
                RPCZPoxInfoData::from_db(sortdb, chainstate, &tip, network.get_burnchain())
            });

        let zpox_info = match zpox_info_res {
            Ok(zpox_info) => zpox_info,
            Err(NetError::NotFoundError) | Err(NetError::DBError(DBError::NotFoundError)) => {
                return BitcoinzHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new("No such chain tip".into()),
                )
                .try_into_contents()
                .map_err(NetError::from);
            }
            Err(e) => {
                return BitcoinzHttpResponse::new_error(
                    &preamble,
                    &HttpServerError::new(format!("Failed to load zPoX info: {:?}", &e)),
                )
                .try_into_contents()
                .map_err(NetError::from);
            }
        };

        let mut preamble = HttpResponsePreamble::ok_json(&preamble);
        preamble.set_canonical_bitcoinz_tip_height(Some(node.canonical_bitcoinz_tip_height()));
        let body = HttpResponseContents::try_from_json(&zpox_info)?;
        Ok((preamble, body))
    }
}

impl HttpResponse for RPCZPoxInfoRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let zpox_info: RPCZPoxInfoData = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(zpox_info)?)
    }
}
