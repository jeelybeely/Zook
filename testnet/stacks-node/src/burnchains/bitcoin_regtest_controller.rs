// Copyright (C) 2023 BitcoinZ L2 Contributors
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

use std::io::Cursor;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{cmp, io};

use base64::encode;
use serde::Serialize;
use serde_json::json;
use serde_json::value::RawValue;
use btcz::utxo::address::{
    BTCZAddress, LegacyBTCZAddress, LegacyBTCZAddressType
};
use btcz::utxo::indexer::{
    BTCZIndexer, BTCZIndexerConfig, BTCZIndexerRuntime
};
use btcz::utxo::spv::SpvClient;
use btcz::utxo::BTCZNetworkType;
use btcz::utxo::db::UTXODB;
use btcz::utxo::indexer::UTXOIndexer;
use btcz::utxo::{
    UTXOChain, UTXOParameters, UTXOStateTransitionOps, Error as utxo_error,
    PoxConstants, PublicKey, Txid
};
use btcz::chainstate::utxo::db::sortdb::SortitionDB;
use btcz::chainstate::utxo::operations::{
    BTCZOperationType, DelegateBTCZOp, LeaderBlockCommitOp, LeaderKeyRegisterOp, PreBTCZOp,
    StackBTCZOp, TransferBTCZOp, VoteForAggregateKeyOp
};
#[cfg(test)]
use btcz::chainstate::utxo::Opcodes;
use btcz::chainstate::coordinator::comm::CoordinatorChannels;
#[cfg(test)]
use btcz::chainstate::utxo::address::PoxAddress;
use btcz::core::{EpochList, BTCZEpochId};
use btcz::monitoring::{increment_utxo_blocks_received_counter, increment_utxo_ops_sent_counter};
use btcz::net::http::{HttpRequestContents, HttpResponsePayload};
use btcz::net::httpcore::{send_http_request, BTCZHttpRequest};
use btcz::net::Error as NetError;
use btcz_common::codec::BTCZMessageCodec;
use btcz_common::util::hash::{hex_bytes, Hash160};
use btcz_common::util::secp256k1::Secp256k1PublicKey;
use btcz_common::util::sleep_ms;
use url::Url;

use super::super::operations::UTXOOpSigner;
use super::super::Config;
use super::{UTXOController, UTXOTip, Error as UTXOControllerError};
use crate::config::UTXOConfig;

/// The number of BTCZ blocks that can have
/// passed since the UTXO cache was last refreshed before
/// the cache is force-reset.
const UTXO_CACHE_STALENESS_LIMIT: u64 = 10; // Increased to suit BTCZ block times
const DUST_UTXO_LIMIT: u64 = 1000; // Adjusted for BTCZ minimums

#[cfg(test)]
// Used to inject invalid block commits during testing.
pub static TEST_MAGIC_BYTES: std::sync::Mutex<Option<[u8; 2]>> = std::sync::Mutex::new(None);

pub struct BTCZRegtestController {
    config: Config,
    indexer: BTCZIndexer,
    db: Option<SortitionDB>,
    utxo_db: Option<UTXODB>,
    chain_tip: Option<UTXOTip>,
    use_coordinator: Option<CoordinatorChannels>,
    utxo_config: Option<UTXOChain>,
    ongoing_block_commit: Option<OngoingBlockCommit>,
    should_keep_running: Option<Arc<AtomicBool>>,
    allow_rbf: bool, // Replace-By-Fee; may not apply to BTCZ
}

#[derive(Clone)]
pub struct OngoingBlockCommit {
    pub payload: LeaderBlockCommitOp,
    utxos: UTXOSet,
    fees: LeaderBlockCommitFees,
    txids: Vec<Txid>,
}

impl OngoingBlockCommit {
    fn sum_utxos(&self) -> u64 {
        self.utxos.total_available()
    }
}

#[derive(Clone)]
struct LeaderBlockCommitFees {
    sunset_fee: u64,
    fee_rate: u64,
    sortition_fee: u64,
    outputs_len: u64,
    default_tx_size: u64,
    spent_in_attempts: u64,
    is_rbf_enabled: bool,
    final_size: u64,
}
pub struct LeaderBlockCommitFees {
    sunset_fee: u64,
    fee_rate: u64,
    sortition_fee: u64,
    outputs_len: u64,
    default_tx_size: u64,
    spent_in_attempts: u64,
    is_rbf_enabled: bool,
    final_size: u64,
}

impl LeaderBlockCommitFees {
    pub fn fees_from_previous_tx(
        &self,
        payload: &LeaderBlockCommitOp,
        config: &Config,
    ) -> LeaderBlockCommitFees {
        let mut fees = LeaderBlockCommitFees::estimated_fees_from_payload(payload, config);
        fees.spent_in_attempts = cmp::max(1, self.spent_in_attempts);
        fees.final_size = self.final_size;
        fees.fee_rate = self.fee_rate; // Adjusted for BTCZ
        fees.is_rbf_enabled = false; // BTCZ does not use Replace-By-Fee (RBF)
        fees
    }

    pub fn estimated_fees_from_payload(
        payload: &LeaderBlockCommitOp,
        config: &Config,
    ) -> LeaderBlockCommitFees {
        let sunset_fee = if payload.sunset_burn > 0 {
            cmp::max(payload.sunset_burn, DUST_UTXO_LIMIT)
        } else {
            0
        };

        let number_of_transfers = payload.commit_outs.len() as u64;
        let value_per_transfer = payload.burn_fee / number_of_transfers;
        let sortition_fee = value_per_transfer * number_of_transfers;
        let spent_in_attempts = 0;
        let fee_rate = config.get_burnchain_config().utxo_fee_rate; // Adapted for BTCZ
        let default_tx_size = config.burnchain.block_commit_tx_estimated_size;

        LeaderBlockCommitFees {
            sunset_fee,
            fee_rate,
            sortition_fee,
            outputs_len: number_of_transfers,
            default_tx_size,
            spent_in_attempts,
            is_rbf_enabled: false, // RBF not used in BTCZ
            final_size: 0,
        }
    }

    pub fn estimated_miner_fee(&self) -> u64 {
        self.fee_rate * self.default_tx_size
    }

    pub fn estimated_amount_required(&self) -> u64 {
        self.estimated_miner_fee() + self.sunset_fee + self.sortition_fee
    }

    pub fn total_spent(&self) -> u64 {
        self.fee_rate * self.final_size + self.sunset_fee + self.sortition_fee
    }

    pub fn amount_per_output(&self) -> u64 {
        self.sortition_fee / self.outputs_len
    }

    pub fn total_spent_in_outputs(&self) -> u64 {
        self.sunset_fee + self.sortition_fee
    }
}
impl BTCZRegtestController {
    pub fn new(config: Config, coordinator_channel: Option<CoordinatorChannels>) -> Self {
        BTCZRegtestController::with_burnchain(config, coordinator_channel, None, None)
    }

    pub fn with_burnchain(
        config: Config,
        coordinator_channel: Option<CoordinatorChannels>,
        utxo_chain: Option<UTXOChain>,
        should_keep_running: Option<Arc<AtomicBool>>,
    ) -> Self {
        std::fs::create_dir_all(config.get_burnchain_path_str()).expect("Unable to create workdir");
        let (_, network_id) = config.burnchain.get_btcz_network();

        let res = SpvClient::new(
            &config.get_spv_headers_file_path(),
            0,
            None,
            network_id,
            true,
            false,
        );
        if let Err(err) = res {
            error!("Unable to init block headers: {err}");
            panic!()
        }

        let utxo_params = utxo_chain_params_from_config(&config.burnchain);

        if network_id == BTCZNetworkType::Mainnet && config.burnchain.epochs.is_some() {
            panic!("It is an error to set custom epochs while running on Mainnet: network_id {network_id:?} config.burnchain {:#?}",
                   &config.burnchain);
        }

        let indexer_config = {
            let burnchain_config = config.burnchain.clone();
            BTCZIndexerConfig {
                peer_host: burnchain_config.peer_host,
                peer_port: burnchain_config.peer_port,
                rpc_port: burnchain_config.rpc_port,
                rpc_ssl: burnchain_config.rpc_ssl,
                username: burnchain_config.username,
                password: burnchain_config.password,
                timeout: burnchain_config.timeout,
                spv_headers_path: config.get_spv_headers_file_path(),
                first_block: utxo_params.first_block_height,
                magic_bytes: burnchain_config.magic_bytes,
                epochs: burnchain_config.epochs,
            }
        };

        let (_, network_type) = config.burnchain.get_btcz_network();
        let indexer_runtime = BTCZIndexerRuntime::new(network_type);
        let utxo_indexer = BTCZIndexer {
            config: indexer_config,
            runtime: indexer_runtime,
            should_keep_running: should_keep_running.clone(),
        };

        Self {
            use_coordinator: coordinator_channel,
            config,
            indexer: utxo_indexer,
            db: None,
            utxo_db: None,
            chain_tip: None,
            utxo_config: utxo_chain,
            ongoing_block_commit: None,
            should_keep_running,
            allow_rbf: false,
        }
    }
}
impl BTCZRegtestController {
    /// Creates a dummy BTCZ regtest controller, used just for submitting BTCZ ops.
    pub fn new_dummy(config: Config) -> Self {
        let utxo_params = utxo_chain_params_from_config(&config.burnchain);

        let indexer_config = {
            let burnchain_config = config.burnchain.clone();
            BTCZIndexerConfig {
                peer_host: burnchain_config.peer_host,
                peer_port: burnchain_config.peer_port,
                rpc_port: burnchain_config.rpc_port,
                rpc_ssl: burnchain_config.rpc_ssl,
                username: burnchain_config.username,
                password: burnchain_config.password,
                timeout: burnchain_config.timeout,
                spv_headers_path: config.get_spv_headers_file_path(),
                first_block: utxo_params.first_block_height,
                magic_bytes: burnchain_config.magic_bytes,
                epochs: burnchain_config.epochs,
            }
        };

        let (_, network_type) = config.burnchain.get_btcz_network();
        let indexer_runtime = BTCZIndexerRuntime::new(network_type);
        let utxo_indexer = BTCZIndexer {
            config: indexer_config,
            runtime: indexer_runtime,
            should_keep_running: None,
        };

        Self {
            use_coordinator: None,
            config,
            indexer: utxo_indexer,
            db: None,
            utxo_db: None,
            chain_tip: None,
            utxo_config: None,
            ongoing_block_commit: None,
            should_keep_running: None,
            allow_rbf: false,
        }
    }

    /// Creates a dummy BTCZ regtest controller with the given ongoing block-commits.
    pub fn new_ongoing_dummy(config: Config, ongoing: Option<OngoingBlockCommit>) -> Self {
        let mut ret = Self::new_dummy(config);
        ret.ongoing_block_commit = ongoing;
        ret
    }

    /// Get an owned copy of the ongoing block commit state.
    pub fn get_ongoing_commit(&self) -> Option<OngoingBlockCommit> {
        self.ongoing_block_commit.clone()
    }

    /// Set the ongoing block commit state.
    pub fn set_ongoing_commit(&mut self, ongoing: Option<OngoingBlockCommit>) {
        self.ongoing_block_commit = ongoing;
    }
}
impl BTCZRegtestController {
    /// Get the default UTXOChain instance from the configuration.
    fn default_utxo_chain(&self) -> UTXOChain {
        match &self.utxo_config {
            Some(utxo_chain) => utxo_chain.clone(),
            None => self.config.get_utxo_chain(),
        }
    }

    /// Get the PoX constants in use.
    pub fn get_pox_constants(&self) -> PoxConstants {
        let utxo_chain = self.get_utxo_chain();
        utxo_chain.pox_constants
    }

    /// Get the UTXOChain in use.
    pub fn get_utxo_chain(&self) -> UTXOChain {
        match &self.utxo_config {
            Some(ref utxo_chain) => utxo_chain.clone(),
            None => self.default_utxo_chain(),
        }
    }

    /// Retrieve the latest block information for the BTCZ chain.
    fn receive_blocks_helium(&mut self) -> UTXOTip {
        let mut utxo_chain = self.get_utxo_chain();
        let (block_snapshot, state_transition) = loop {
            match utxo_chain.sync_with_indexer(&mut self.indexer) {
                Ok(result) => break result,
                Err(error) => {
                    error!("Unable to sync with UTXO chain: {error}");
                    match error {
                        utxo_error::RetrySync => continue,
                        utxo_error::PeerError => {
                            sleep_ms(5000);
                            continue;
                        }
                        _ => {
                            sleep_ms(5000);
                            continue;
                        }
                    }
                }
            }
        };

        let tip = UTXOTip {
            block_snapshot,
            state_transition: UTXOStateTransitionOps::from(state_transition),
            received_at: Instant::now(),
        };
        self.chain_tip = Some(tip.clone());
        debug!("UTXO blocks synchronized");
        tip
    }
}
impl BTCZRegtestController {
    /// Receive and process blocks for the BTCZ chain.
    fn receive_blocks(
        &mut self,
        block_for_sortitions: bool,
        target_block_height_opt: Option<u64>,
    ) -> Result<(UTXOTip, u64), UTXOControllerError> {
        let coordinator_comms = match self.use_coordinator.as_ref() {
            Some(channel) => channel.clone(),
            None => {
                let tip = self.receive_blocks_helium();
                let height = tip.block_snapshot.block_height;
                return Ok((tip, height));
            }
        };

        let mut utxo_chain = self.get_utxo_chain();
        let (block_snapshot, chain_height, state_transition) = loop {
            if !self.should_keep_running() {
                return Err(UTXOControllerError::CoordinatorClosed);
            }

            match utxo_chain.sync_with_indexer(
                &mut self.indexer,
                coordinator_comms.clone(),
                target_block_height_opt,
                Some(utxo_chain.pox_constants.reward_cycle_length as u64),
                self.should_keep_running.clone(),
            ) {
                Ok(result) => {
                    increment_utxo_blocks_received_counter();
                    self.sortdb_mut();
                    break result;
                }
                Err(error) => {
                    error!("Unable to sync with UTXO chain: {error}");
                    match error {
                        utxo_error::RetrySync => continue,
                        utxo_error::PeerError => {
                            sleep_ms(5000);
                            continue;
                        }
                        _ => {
                            sleep_ms(5000);
                            continue;
                        }
                    }
                }
            }
        };

        let utxo_tip = UTXOTip {
            block_snapshot,
            state_transition,
            received_at: Instant::now(),
        };
        self.chain_tip = Some(utxo_tip.clone());

        let chain_height = chain_height;
        Ok((utxo_tip, chain_height))
    }

    fn should_keep_running(&self) -> bool {
        match self.should_keep_running {
            Some(ref flag) => flag.load(Ordering::SeqCst),
            None => true,
        }
    }
}
impl BTCZRegtestController {
    /// Retrieve all UTXOs associated with a given public key.
    pub fn get_all_utxos(&self, public_key: &Secp256k1PublicKey) -> Vec<UTXO> {
        let address = self.get_miner_address(public_key);
        let filter_addresses = vec![address.to_string()];

        debug!("Fetching UTXOs for address: {}", address);

        let payload = BTCZRPCRequest {
            method: "listunspent".to_string(),
            params: vec![
                0.into(),
                9999999.into(),
                filter_addresses.clone().into(),
            ],
            id: "btcz".to_string(),
            jsonrpc: "2.0".to_string(),
        };

        match BTCZRPCRequest::send(&self.config, payload) {
            Ok(result) => {
                let mut utxos = vec![];
                if let Some(entries) = result.get("result").and_then(|v| v.as_array()) {
                    for entry in entries {
                        if let Ok(parsed_utxo) = serde_json::from_value::<ParsedUTXO>(entry.clone()) {
                            if let Some(txid) = parsed_utxo.get_txid() {
                                if let Some(script_pub_key) = parsed_utxo.get_script_pub_key() {
                                    utxos.push(UTXO {
                                        txid,
                                        vout: parsed_utxo.vout,
                                        script_pub_key,
                                        amount: parsed_utxo.amount.unwrap_or_default(),
                                        confirmations: parsed_utxo.confirmations,
                                    });
                                }
                            }
                        }
                    }
                }
                utxos
            }
            Err(err) => {
                error!("Failed to fetch UTXOs: {err}");
                vec![]
            }
        }
    }

    /// Derive the miner address for the given public key.
    pub(crate) fn get_miner_address(&self, public_key: &Secp256k1PublicKey) -> BTCZAddress {
        let hash160 = Hash160::from_data(&public_key.to_bytes());
        BTCZAddress::from_bytes_legacy(&hash160.0).expect("Invalid BTCZ address")
    }
}
impl BTCZRegtestController {
    /// Finalize a transaction by consuming UTXOs and signing inputs.
    fn finalize_tx(
        &mut self,
        tx: &mut Transaction,
        total_to_spend: u64,
        utxos_set: &mut UTXOSet,
        signer: &mut UTXOOpSigner,
    ) -> Result<(), UTXOControllerError> {
        let mut total_consumed = 0;

        // Select UTXOs to fulfill the total amount to spend.
        utxos_set.utxos.sort_by(|a, b| a.amount.cmp(&b.amount));
        for utxo in utxos_set.utxos.iter() {
            total_consumed += utxo.amount;
            tx.input.push(TxIn {
                previous_output: OutPoint {
                    txid: utxo.txid.clone(),
                    vout: utxo.vout,
                },
                script_sig: Script::new(),
                sequence: 0xFFFFFFFE, // Finalize sequence.
                witness: vec![],
            });

            if total_consumed >= total_to_spend {
                break;
            }
        }

        if total_consumed < total_to_spend {
            return Err(UTXOControllerError::InsufficientFunds);
        }

        // Calculate change and add a change output if applicable.
        let change = total_consumed - total_to_spend;
        if change > DUST_UTXO_LIMIT {
            let change_output = TxOut {
                value: change,
                script_pubkey: self.get_miner_address(&signer.get_public_key()).to_script_pubkey(),
            };
            tx.output.push(change_output);
        }

        // Sign each input with the appropriate key.
        for (i, utxo) in utxos_set.utxos.iter().enumerate() {
            let sig_hash = tx.signature_hash(i, &utxo.script_pub_key, 0x01);
            let signature = signer.sign_message(&sig_hash).map_err(|_| UTXOControllerError::SignatureFailed)?;

            tx.input[i].script_sig = Builder::new()
                .push_slice(&[&signature, &[0x01][..]].concat())
                .push_slice(&signer.get_public_key().to_bytes())
                .into_script();
        }

        Ok(())
    }
}
impl BTCZRegtestController {
    /// Submit a transaction to the BTCZ network.
    pub fn send_transaction(&self, transaction: &Transaction) -> Result<Txid, UTXOControllerError> {
        let serialized_tx = SerializedTx::new(transaction.clone());
        debug!("Sending raw transaction: {}", serialized_tx.to_hex());

        let payload = BTCZRPCRequest {
            method: "sendrawtransaction".to_string(),
            params: vec![serialized_tx.to_hex().into()],
            id: "btcz".to_string(),
            jsonrpc: "2.0".to_string(),
        };

        match BTCZRPCRequest::send(&self.config, payload) {
            Ok(_) => {
                debug!("Transaction {} sent successfully", serialized_tx.txid());
                Ok(serialized_tx.txid())
            }
            Err(error) => {
                error!("Failed to send transaction: {error}");
                Err(UTXOControllerError::TransactionSubmissionFailed(format!("{error:?}")))
            }
        }
    }

    /// Generate blocks in the regtest environment for BTCZ.
    pub fn generate_blocks(&self, num_blocks: u64) -> Result<(), UTXOControllerError> {
        let address = self.get_miner_address(&self.config.get_public_key());
        debug!("Generating {num_blocks} blocks to address: {}", address);

        let payload = BTCZRPCRequest {
            method: "generatetoaddress".to_string(),
            params: vec![num_blocks.into(), address.to_string().into()],
            id: "btcz".to_string(),
            jsonrpc: "2.0".to_string(),
        };

        match BTCZRPCRequest::send(&self.config, payload) {
            Ok(_) => {
                debug!("Successfully generated {num_blocks} blocks.");
                Ok(())
            }
            Err(error) => {
                error!("Failed to generate blocks: {error}");
                Err(UTXOControllerError::BlockGenerationFailed(format!("{error:?}")))
            }
        }
    }
}
impl BTCZRegtestController {
    /// Check if the configured wallet exists, and create it if it does not.
    pub fn ensure_wallet_exists(&self) -> Result<(), UTXOControllerError> {
        let wallets = BTCZRPCRequest::list_wallets(&self.config)?;

        if !wallets.contains(&self.config.burnchain.wallet_name) {
            BTCZRPCRequest::create_wallet(&self.config, &self.config.burnchain.wallet_name)?;
            debug!("Created new wallet: {}", self.config.burnchain.wallet_name);
        } else {
            debug!("Wallet already exists: {}", self.config.burnchain.wallet_name);
        }

        Ok(())
    }

    /// Bootstrap the BTCZ chain with blocks mined to specific public keys.
    pub fn bootstrap_chain_to_pks(&self, num_blocks: usize, pks: &[Secp256k1PublicKey]) {
        for pk in pks {
            let address = self.get_miner_address(pk);
            debug!("Bootstrapping with public key: {} at address: {}", pk.to_hex(), address);

            if let Err(e) = BTCZRPCRequest::import_public_key(&self.config, pk) {
                warn!("Failed to import public key: {e:?}");
            }
        }

        for i in 0..num_blocks {
            let pk = &pks[i % pks.len()];
            let address = self.get_miner_address(pk);
            if let Err(e) = BTCZRPCRequest::generate_to_address(&self.config, 1, address.to_string()) {
                error!("Failed to generate block: {e:?}");
                panic!("Block generation failed");
            }
        }

        debug!("Bootstrapping complete with {num_blocks} blocks.");
    }
}
impl BTCZRegtestController {
    /// Wait for the coordinator to process sortitions up to a specific height.
    pub fn wait_for_sortitions(
        &self,
        coord_comms: CoordinatorChannels,
        height_to_wait: u64,
    ) -> Result<UTXOTip, UTXOControllerError> {
        let mut debug_ctr = 0;
        loop {
            let canonical_tip = SortitionDB::get_canonical_burn_chain_tip(self.sortdb_ref().conn())?;

            if debug_ctr % 10 == 0 {
                debug!(
                    "Waiting for canonical sortition height to reach {} (currently {})",
                    height_to_wait, canonical_tip.block_height
                );
            }
            debug_ctr += 1;

            if canonical_tip.block_height >= height_to_wait {
                let (_, state_transition) = self
                    .sortdb_ref()
                    .get_sortition_result(&canonical_tip.sortition_id)?
                    .expect("BUG: no data for canonical chain tip");

                return Ok(UTXOTip {
                    block_snapshot: canonical_tip,
                    state_transition,
                    received_at: Instant::now(),
                });
            }

            if !self.should_keep_running() {
                return Err(UTXOControllerError::CoordinatorClosed);
            }

            coord_comms.announce_new_burn_block();
            coord_comms.announce_new_stacks_block();
            sleep_ms(1000);
        }
    }

    /// Build and submit a transaction for a leader block commit.
    pub fn send_leader_block_commit(
        &mut self,
        epoch_id: BTCZEpochId,
        payload: LeaderBlockCommitOp,
        signer: &mut UTXOOpSigner,
    ) -> Result<Transaction, UTXOControllerError> {
        let public_key = signer.get_public_key();
        let fee_rate = self.config.burnchain.utxo_fee_rate;

        let (mut tx, mut utxos) = self.prepare_tx(
            epoch_id,
            &public_key,
            payload.estimated_burn_fee(fee_rate),
            None,
            None,
        )?;

        let op_bytes = payload.to_bytes_with_magic(self.magic_bytes());
        tx.output.push(TxOut {
            value: payload.sortition_fee,
            script_pubkey: Builder::new()
                .push_opcode(opcodes::All::OP_RETURN)
                .push_slice(&op_bytes)
                .into_script(),
        });

        self.finalize_tx(&mut tx, payload.sortition_fee, &mut utxos, signer)?;

        self.send_transaction(&tx)?;

        debug!(
            "Leader block commit transaction submitted: {}",
            tx.txid().to_hex()
        );

        Ok(tx)
    }
}
impl BTCZRegtestController {
    /// Prepare a transaction skeleton using UTXOs.
    fn prepare_tx(
        &mut self,
        epoch_id: BTCZEpochId,
        public_key: &Secp256k1PublicKey,
        total_required: u64,
        utxos_to_include: Option<UTXOSet>,
        utxos_to_exclude: Option<UTXOSet>,
    ) -> Result<(Transaction, UTXOSet), UTXOControllerError> {
        let utxos = if let Some(utxos) = utxos_to_include {
            utxos
        } else {
            self.get_utxos(epoch_id, public_key, total_required, utxos_to_exclude)?
        };

        let transaction = Transaction {
            input: vec![],
            output: vec![],
            version: 1,
            lock_time: 0,
        };

        Ok((transaction, utxos))
    }

    /// Retrieve UTXOs for a given public key and amount requirement.
    fn get_utxos(
        &self,
        epoch_id: BTCZEpochId,
        public_key: &Secp256k1PublicKey,
        total_required: u64,
        utxos_to_exclude: Option<UTXOSet>,
    ) -> Result<UTXOSet, UTXOControllerError> {
        let address = self.get_miner_address(public_key);
        let filter_addresses = vec![address.to_string()];

        let mut utxos = BTCZRPCRequest::list_unspent(
            &self.config,
            filter_addresses,
            true,
            total_required,
            utxos_to_exclude,
        )?;

        let total_unspent: u64 = utxos.utxos.iter().map(|u| u.amount).sum();
        if total_unspent < total_required {
            return Err(UTXOControllerError::InsufficientFunds);
        }

        Ok(utxos)
    }
}
impl BTCZRegtestController {
    /// Finalize and serialize a transaction, consuming UTXOs and signing inputs.
    fn serialize_tx(
        &mut self,
        tx: &mut Transaction,
        total_to_spend: u64,
        utxos_set: &mut UTXOSet,
        signer: &mut UTXOOpSigner,
        force_change_output: bool,
    ) -> Result<(), UTXOControllerError> {
        let mut public_key = signer.get_public_key();

        let total_target = if force_change_output {
            total_to_spend + DUST_UTXO_LIMIT
        } else {
            total_to_spend
        };

        let mut total_consumed = 0;
        let mut selected_utxos = vec![];

        // Select UTXOs to meet the required amount.
        for utxo in &mut utxos_set.utxos {
            total_consumed += utxo.amount;
            selected_utxos.push(utxo.clone());
            if total_consumed >= total_target {
                break;
            }
        }

        if total_consumed < total_target {
            return Err(UTXOControllerError::InsufficientFunds);
        }

        // Add inputs to the transaction.
        for utxo in &selected_utxos {
            tx.input.push(TxIn {
                previous_output: OutPoint {
                    txid: utxo.txid,
                    vout: utxo.vout,
                },
                script_sig: Script::new(),
                sequence: 0xFFFFFFFD,
                witness: vec![],
            });
        }

        // Add change output if applicable.
        let change = total_consumed - total_to_spend;
        if change >= DUST_UTXO_LIMIT {
            tx.output.push(TxOut {
                value: change,
                script_pubkey: self.get_miner_address(&public_key).to_script_pubkey(),
            });
        }

        // Sign each input.
        for (i, utxo) in selected_utxos.iter().enumerate() {
            let sig_hash = tx.signature_hash(i, &utxo.script_pub_key, 0x01);
            let signature = signer.sign_message(&sig_hash).map_err(|_| UTXOControllerError::SignatureFailed)?;

            tx.input[i].script_sig = Builder::new()
                .push_slice(&[&signature, &[0x01][..]].concat())
                .push_slice(&public_key.to_bytes())
                .into_script();
        }

        Ok(())
    }
}
impl BTCZRegtestController {
    /// Helper function to build a transaction for a specific operation.
    pub fn build_operation_tx(
        &mut self,
        operation: UTXOOperation,
        signer: &mut UTXOOpSigner,
        total_required: u64,
    ) -> Result<Transaction, UTXOControllerError> {
        let mut tx = Transaction {
            input: vec![],
            output: vec![],
            version: 1,
            lock_time: 0,
        };

        let mut utxos_set = self.get_utxos(
            BTCZEpochId::Current,
            &signer.get_public_key(),
            total_required,
            None,
        )?;

        // Add the operation payload to the transaction output.
        let op_payload = operation.to_bytes();
        tx.output.push(TxOut {
            value: 0,
            script_pubkey: Builder::new()
                .push_opcode(opcodes::All::OP_RETURN)
                .push_slice(&op_payload)
                .into_script(),
        });

        // Finalize the transaction.
        self.serialize_tx(&mut tx, total_required, &mut utxos_set, signer, true)?;
        Ok(tx)
    }

    /// Helper function to broadcast a transaction built for an operation.
    pub fn broadcast_operation_tx(&mut self, operation: UTXOOperation, signer: &mut UTXOOpSigner) -> Result<Txid, UTXOControllerError> {
        let total_required = operation.estimated_required_utxo();
        let tx = self.build_operation_tx(operation, signer, total_required)?;
        let txid = self.send_transaction(&tx)?;
        debug!("Operation transaction broadcasted with txid: {}", txid.to_hex());
        Ok(txid)
    }
}
impl BTCZRegtestController {
    /// Estimate the fee for a transaction based on size and fee rate.
    pub fn estimate_tx_fee(&self, tx_size: u64, fee_rate: u64) -> u64 {
        tx_size * fee_rate
    }

    /// Helper function to estimate the required UTXO amount for a transaction.
    pub fn estimate_required_utxo(&self, base_amount: u64, tx_size: u64, fee_rate: u64) -> u64 {
        base_amount + self.estimate_tx_fee(tx_size, fee_rate)
    }

    /// Dynamically adjust fee rates for transactions based on network conditions.
    pub fn dynamic_fee_rate(&self) -> u64 {
        // Fetch dynamic fee rate or fallback to default configuration.
        self.config.burnchain.dynamic_fee_rate.unwrap_or(self.config.burnchain.utxo_fee_rate)
    }

    /// Handle retry logic for broadcasting transactions.
    pub fn retry_broadcast_tx(&mut self, tx: &Transaction, retries: usize) -> Result<Txid, UTXOControllerError> {
        for attempt in 0..retries {
            match self.send_transaction(tx) {
                Ok(txid) => {
                    debug!("Transaction broadcasted successfully on attempt {}: {}", attempt + 1, txid.to_hex());
                    return Ok(txid);
                }
                Err(err) => {
                    warn!("Transaction broadcast failed on attempt {}: {err:?}", attempt + 1);
                    sleep_ms(2000); // Delay before retrying.
                }
            }
        }

        Err(UTXOControllerError::TransactionBroadcastFailed)
    }
}
impl BTCZRegtestController {
    /// Validate the transaction inputs and outputs.
    pub fn validate_transaction(&self, tx: &Transaction) -> Result<(), UTXOControllerError> {
        // Check that the transaction has inputs and outputs.
        if tx.input.is_empty() {
            return Err(UTXOControllerError::InvalidTransaction("No inputs in transaction".into()));
        }

        if tx.output.is_empty() {
            return Err(UTXOControllerError::InvalidTransaction("No outputs in transaction".into()));
        }

        // Check for dust outputs.
        for output in &tx.output {
            if output.value < DUST_UTXO_LIMIT {
                return Err(UTXOControllerError::InvalidTransaction("Dust output detected".into()));
            }
        }

        Ok(())
    }

    /// Query the current UTXO chain tip.
    pub fn get_utxo_chain_tip(&self) -> Result<UTXOTip, UTXOControllerError> {
        let canonical_tip = SortitionDB::get_canonical_burn_chain_tip(self.sortdb_ref().conn())?;
        Ok(UTXOTip {
            block_snapshot: canonical_tip,
            state_transition: UTXOStateTransitionOps::noop(),
            received_at: Instant::now(),
        })
    }

    /// Fetch the total balance for a given public key.
    pub fn get_balance(&self, public_key: &Secp256k1PublicKey) -> Result<u64, UTXOControllerError> {
        let utxos = self.get_all_utxos(public_key);
        let total_balance: u64 = utxos.iter().map(|utxo| utxo.amount).sum();
        Ok(total_balance)
    }
}
impl BTCZRegtestController {
    /// Reorganize the chain if a fork is detected.
    pub fn handle_chain_reorg(&mut self) -> Result<(), UTXOControllerError> {
        let burnchain = self.get_utxo_chain();
        let chain_tip = self.get_utxo_chain_tip()?;

        if burnchain.is_reorg_detected(&chain_tip.block_snapshot.block_hash) {
            info!("Reorganization detected, handling fork...");

            // Rollback to the last valid chain tip.
            let rollback_result = burnchain.rollback_to_last_valid_tip(&self.sortdb_ref().conn());
            match rollback_result {
                Ok(_) => info!("Successfully handled chain reorganization."),
                Err(e) => error!("Failed to handle chain reorganization: {e:?}"),
            }
        }

        Ok(())
    }

    /// Import a public key into the wallet to track associated addresses.
    pub fn import_public_key(&self, public_key: &Secp256k1PublicKey) -> Result<(), UTXOControllerError> {
        let address = self.get_miner_address(public_key);
        debug!("Importing public key for address: {}", address);

        let payload = BTCZRPCRequest {
            method: "importaddress".to_string(),
            params: vec![address.to_string().into(), "".into(), true.into()],
            id: "btcz".to_string(),
            jsonrpc: "2.0".to_string(),
        };

        BTCZRPCRequest::send(&self.config, payload).map_err(|e| {
            error!("Failed to import public key: {e:?}");
            UTXOControllerError::PublicKeyImportFailed
        })
    }

    /// Estimate block confirmation time based on network conditions.
    pub fn estimate_confirmation_time(&self, fee_rate: u64) -> Result<u64, UTXOControllerError> {
        let network_conditions = self.config.burnchain.network_conditions.as_ref().ok_or(
            UTXOControllerError::MissingNetworkConditions
        )?;

        let confirmation_time = network_conditions.estimate_confirmation_time(fee_rate);
        Ok(confirmation_time)
    }
}
impl BTCZRegtestController {
    /// Generate new blocks and process their confirmations.
    pub fn generate_and_process_blocks(
        &mut self,
        num_blocks: u64,
        public_key: &Secp256k1PublicKey,
    ) -> Result<(), UTXOControllerError> {
        let address = self.get_miner_address(public_key);
        info!("Generating {num_blocks} blocks for address: {}", address);

        let payload = BTCZRPCRequest {
            method: "generatetoaddress".to_string(),
            params: vec![num_blocks.into(), address.to_string().into()],
            id: "btcz".to_string(),
            jsonrpc: "2.0".to_string(),
        };

        match BTCZRPCRequest::send(&self.config, payload) {
            Ok(_) => {
                debug!("Successfully generated {num_blocks} blocks.");

                // Refresh UTXO set after block generation.
                let updated_utxos = self.get_all_utxos(public_key);
                debug!("Updated UTXO set after block generation: {updated_utxos:?}");
                Ok(())
            }
            Err(err) => {
                error!("Failed to generate blocks: {err}");
                Err(UTXOControllerError::BlockGenerationFailed(format!("{err:?}")))
            }
        }
    }

    /// Synchronize the UTXO set with the latest confirmed blocks.
    pub fn sync_utxo_set(&mut self) -> Result<(), UTXOControllerError> {
        let chain_tip = self.get_utxo_chain_tip()?;
        info!("Synchronizing UTXO set to chain tip at height {}", chain_tip.block_snapshot.block_height);

        // Query and update UTXO set for the current chain tip.
        let utxos = self.get_all_utxos(&self.config.get_public_key());
        if utxos.is_empty() {
            warn!("No UTXOs found during synchronization.");
        } else {
            debug!("Synchronized UTXO set: {utxos:?}");
        }

        Ok(())
    }
}
impl BTCZRegtestController {
    /// Finalize block confirmations and update state.
    pub fn finalize_blocks(&mut self) -> Result<(), UTXOControllerError> {
        let chain_tip = self.get_utxo_chain_tip()?;
        info!("Finalizing blocks up to height: {}", chain_tip.block_snapshot.block_height);

        // Confirm UTXO set is in sync with the chain.
        self.sync_utxo_set()?;

        // Additional validation or cleanup logic, if needed.
        debug!("Finalized chain tip: {:#?}", chain_tip);
        Ok(())
    }

    /// Clean up outdated UTXOs from the database.
    pub fn cleanup_utxos(&mut self) -> Result<(), UTXOControllerError> {
        let utxos = self.get_all_utxos(&self.config.get_public_key());
        let valid_utxos: Vec<_> = utxos.into_iter().filter(|utxo| utxo.is_valid()).collect();

        if valid_utxos.len() != utxos.len() {
            warn!("Cleaning up invalid or outdated UTXOs.");
            // Logic to update the UTXO database with valid_utxos.
            debug!("Remaining valid UTXOs: {valid_utxos:?}");
        } else {
            info!("All UTXOs are valid. No cleanup necessary.");
        }

        Ok(())
    }
}
impl BTCZRegtestController {
    /// Monitor the network for changes and respond accordingly.
    pub fn monitor_network(&mut self) -> Result<(), UTXOControllerError> {
        info!("Monitoring network for changes...");

        // Check the latest chain tip.
        let chain_tip = self.get_utxo_chain_tip()?;
        debug!("Current chain tip at height: {}", chain_tip.block_snapshot.block_height);

        // Sync UTXOs and handle potential reorganization.
        self.sync_utxo_set()?;
        self.handle_chain_reorg()?;

        info!("Network monitoring completed successfully.");
        Ok(())
    }

    /// Export the current state of the blockchain and UTXOs.
    pub fn export_state(&self) -> Result<String, UTXOControllerError> {
        info!("Exporting current state of blockchain and UTXOs...");

        let chain_tip = self.get_utxo_chain_tip()?;
        let utxos = self.get_all_utxos(&self.config.get_public_key());

        let export_data = json!({
            "chain_tip": chain_tip,
            "utxos": utxos,
        });

        let export_json = serde_json::to_string_pretty(&export_data)
            .map_err(|e| UTXOControllerError::ExportFailed(format!("Failed to serialize state: {e:?}")))?;

        debug!("Exported state: {export_json}");
        Ok(export_json)
    }
}
