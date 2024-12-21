// Adapted `burnchain.rs` segment

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{fs, thread};

use stacks_common::address::{public_keys_to_address_hash, AddressHashMode};
use stacks_common::types::chainstate::{BurnchainHeaderHash, PoxId, StacksAddress, TrieHash};
use stacks_common::util::hash::to_hex;
use stacks_common::util::vrf::VRFPublicKey;
use stacks_common::util::{get_epoch_time_ms, get_epoch_time_secs, log, sleep_ms};

use super::EpochList;
use crate::burnchains::affirmation::update_pox_affirmation_maps;
use crate::burnchains::zook::{ZookInputType, ZookNetworkType, ZookTxInput, ZookTxOutput};
use crate::burnchains::db::{BurnchainDB, BurnchainHeaderReader};
use crate::burnchains::indexer::{
    BurnBlockIPC, BurnHeaderIPC, BurnchainBlockDownloader, BurnchainBlockParser, BurnchainIndexer,
};
use crate::burnchains::{
    Address, Burnchain, BurnchainBlock, BurnchainBlockHeader, BurnchainParameters,
    BurnchainRecipient, BurnchainSigner, BurnchainStateTransition, BurnchainStateTransitionOps,
    BurnchainTransaction, Error as burnchain_error, PoxConstants, PublicKey, Txid,
};
use crate::chainstate::burn::db::sortdb::{
    SortitionDB, SortitionHandle, SortitionHandleConn, SortitionHandleTx,
};
use crate::chainstate::burn::distribution::BurnSamplePoint;
use crate::chainstate::burn::operations::leader_block_commit::MissedBlockCommit;
use crate::chainstate::burn::operations::{
    BlockstackOperationType, DelegateStxOp, LeaderBlockCommitOp, LeaderKeyRegisterOp, PreStxOp,
    StackStxOp, TransferStxOp, VoteForAggregateKeyOp,
};
use crate::chainstate::burn::{BlockSnapshot, Opcodes};
use crate::chainstate::coordinator::comm::CoordinatorChannels;
use crate::chainstate::coordinator::SortitionDBMigrator;
use crate::chainstate::stacks::address::{PoxAddress, StacksAddressExtensions};
use crate::core::{
    StacksEpoch, StacksEpochId, NETWORK_ID_MAINNET, NETWORK_ID_TESTNET, PEER_VERSION_MAINNET,
    PEER_VERSION_TESTNET, STACKS_2_0_LAST_BLOCK_TO_PROCESS,
};
use crate::deps;
use crate::monitoring::update_burnchain_height;
use crate::util_lib::db::{DBConn, DBTx, Error as db_error};

impl BurnchainStateTransitionOps {
    pub fn noop() -> BurnchainStateTransitionOps {
        BurnchainStateTransitionOps {
            accepted_ops: vec![],
            consumed_leader_keys: vec![],
        }
    }
    pub fn from(o: BurnchainStateTransition) -> BurnchainStateTransitionOps {
        BurnchainStateTransitionOps {
            accepted_ops: o.accepted_ops,
            consumed_leader_keys: o.consumed_leader_keys,
        }
    }
}

impl BurnchainStateTransition {
    pub fn noop() -> BurnchainStateTransition {
        BurnchainStateTransition {
            burn_dist: vec![],
            accepted_ops: vec![],
            consumed_leader_keys: vec![],
            windowed_block_commits: vec![],
            windowed_missed_commits: vec![],
        }
    }

    /// Get the transaction IDs of all accepted burnchain operations in this block
    pub fn txids(&self) -> Vec<Txid> {
        self.accepted_ops.iter().map(|ref op| op.txid()).collect()
    }

    /// Get the sum of all burnchain tokens spent in this burnchain block's accepted operations
    /// (i.e. applies to block commits).
    /// Returns None on overflow.
    pub fn total_burns(&self) -> Option<u64> {
        self.accepted_ops.iter().try_fold(0u64, |acc, op| {
            let bf = match op {
                BlockstackOperationType::LeaderBlockCommit(ref op) => op.burn_fee,
                _ => 0,
            };
            acc.checked_add(bf)
        })
    }

    /// Get the median block burn from the window. If the window length is even, then the average
    /// of the two middle-most values will be returned.
    pub fn windowed_median_burns(&self) -> Option<u64> {
        let block_total_burn_opts = self.windowed_block_commits.iter().map(|block_commits| {
            block_commits
                .iter()
                .try_fold(0u64, |acc, op| acc.checked_add(op.burn_fee))
        });

        let mut block_total_burns = vec![];
        for burn_opt in block_total_burn_opts.into_iter() {
            block_total_burns.push(burn_opt?);
        }

        block_total_burns.sort();

        if block_total_burns.is_empty() {
            return Some(0);
        } else if block_total_burns.len() == 1 {
            return Some(block_total_burns[0]);
        } else if block_total_burns.len() % 2 != 0 {
            let idx = block_total_burns.len() / 2;
            return block_total_burns.get(idx).map(|b| *b);
        } else {
            let idx_left = block_total_burns.len() / 2 - 1;
            let idx_right = block_total_burns.len() / 2;
            let burn_left = block_total_burns.get(idx_left)?;
            let burn_right = block_total_burns.get(idx_right)?;
            return Some((burn_left + burn_right) / 2);
        }
    }
}
// Adapted `burnchain.rs` continued

impl BurnchainStateTransition {
    /// Create a state transition from block operations
    pub fn from_block_ops(
        sort_tx: &mut SortitionHandleTx,
        burnchain: &Burnchain,
        parent_snapshot: &BlockSnapshot,
        block_ops: &Vec<BlockstackOperationType>,
        missed_commits: &[MissedBlockCommit],
    ) -> Result<BurnchainStateTransition, burnchain_error> {
        // Block commits discovered in this block.
        let mut block_commits: Vec<LeaderBlockCommitOp> = vec![];
        let mut accepted_ops = Vec::with_capacity(block_ops.len());

        assert!(Burnchain::ops_are_sorted(block_ops));

        // Identify which block commits are consumed and which are not
        let mut all_block_commits: HashMap<Txid, LeaderBlockCommitOp> = HashMap::new();

        // Accept all leader keys we found.
        for op in block_ops {
            match op {
                BlockstackOperationType::PreStx(_) => {}
                BlockstackOperationType::StackStx(_) => {
                    accepted_ops.push(op.clone());
                }
                BlockstackOperationType::DelegateStx(_) => {
                    accepted_ops.push(op.clone());
                }
                BlockstackOperationType::TransferStx(_) => {
                    accepted_ops.push(op.clone());
                }
                BlockstackOperationType::LeaderKeyRegister(_) => {
                    accepted_ops.push(op.clone());
                }
                BlockstackOperationType::LeaderBlockCommit(ref commit) => {
                    all_block_commits.insert(commit.txid.clone(), commit.clone());
                    block_commits.push(commit.clone());
                }
                BlockstackOperationType::VoteForAggregateKey(_) => {
                    accepted_ops.push(op.clone());
                }
            }
        }

        let consumed_leader_keys =
            sort_tx.get_consumed_leader_keys(parent_snapshot, &block_commits)?;

        let mut windowed_block_commits = vec![block_commits];
        let mut windowed_missed_commits = vec![];

        let epoch_id = SortitionDB::get_stacks_epoch(sort_tx, parent_snapshot.block_height + 1)?
            .unwrap_or_else(|| {
                panic!(
                    "FATAL: no epoch defined at burn height {}",
                    parent_snapshot.block_height + 1
                )
            })
            .epoch_id;

        let window_start_epoch_id = SortitionDB::get_stacks_epoch(
            sort_tx,
            parent_snapshot
                .block_height
                .saturating_sub(epoch_id.mining_commitment_window().into()),
        )?
        .unwrap_or_else(|| {
            panic!(
                "FATAL: no epoch defined at burn height {}",
                parent_snapshot.block_height - u64::from(epoch_id.mining_commitment_window())
            )
        })
        .epoch_id;

        if !burnchain.is_in_prepare_phase(parent_snapshot.block_height + 1)
            && !burnchain
                .pox_constants
                .is_after_pox_sunset_end(parent_snapshot.block_height + 1, epoch_id)
            && (epoch_id < StacksEpochId::Epoch30 || window_start_epoch_id == epoch_id)
        {
            let mut missed_commits_map: HashMap<_, Vec<_>> = HashMap::new();
            for missed in missed_commits.iter() {
                if let Some(commits_at_sortition) =
                    missed_commits_map.get_mut(&missed.intended_sortition)
                {
                    commits_at_sortition.push(missed);
                } else {
                    missed_commits_map.insert(missed.intended_sortition.clone(), vec![missed]);
                }
            }

            for blocks_back in 0..(epoch_id.mining_commitment_window() - 1) {
                if parent_snapshot.block_height < blocks_back as u64 {
                    debug!("Mining commitment window shortened because block height is less than window size");
                    break;
                }
                let block_height = parent_snapshot.block_height - blocks_back as u64;
                let sortition_id = match sort_tx.get_block_snapshot_by_height(block_height)? {
                    Some(sn) => sn.sortition_id,
                    None => break,
                };
                windowed_block_commits.push(SortitionDB::get_block_commits_by_block(
                    sort_tx.tx(),
                    &sortition_id,
                )?);
                let mut missed_commits_at_height =
                    SortitionDB::get_missed_commits_by_intended(sort_tx.tx(), &sortition_id)?;
                if let Some(missed_commit_in_block) = missed_commits_map.remove(&sortition_id) {
                    missed_commits_at_height
                        .extend(missed_commit_in_block.into_iter().map(|x| x.clone()));
                }

                windowed_missed_commits.push(missed_commits_at_height);
            }
        }

        windowed_block_commits.reverse();
        windowed_missed_commits.reverse();

        let burn_dist = BurnSamplePoint::make_min_median_distribution(
            epoch_id.mining_commitment_window(),
            windowed_block_commits.clone(),
            windowed_missed_commits.clone(),
            vec![false; windowed_block_commits.len()],
        );

        let mut burn_blocks = vec![false; windowed_block_commits.len()];
        for (i, b) in burn_blocks.iter_mut().enumerate() {
            *b = !burnchain
                .pox_constants
                .is_after_pox_sunset_end(parent_snapshot.block_height + (i as u64), epoch_id)
                && !burnchain.is_in_prepare_phase(parent_snapshot.block_height + (i as u64));
        }

        let mut accepted_ops = vec![];
        for point in burn_dist.iter() {
            if let Some(candidate) = &point.candidate {
                accepted_ops.push(BlockstackOperationType::LeaderBlockCommit(candidate.clone()));
            }
        }

        Ok(BurnchainStateTransition {
            burn_dist,
            accepted_ops,
            consumed_leader_keys,
            windowed_block_commits,
            windowed_missed_commits,
        })
    }
}
// Adapted `burnchain.rs` continued

impl Burnchain {
    /// Create a new instance of Burnchain tailored for Zook.
    pub fn new(
        working_dir: &str,
        chain_name: &str,
        network_name: &str,
    ) -> Result<Burnchain, burnchain_error> {
        let (params, pox_constants, peer_version) = match (chain_name, network_name) {
            ("zook", "mainnet") => (
                BurnchainParameters::zook_mainnet(),
                PoxConstants::mainnet_default(),
                PEER_VERSION_MAINNET,
            ),
            ("zook", "testnet") => (
                BurnchainParameters::zook_testnet(),
                PoxConstants::testnet_default(),
                PEER_VERSION_TESTNET,
            ),
            ("zook", "regtest") => (
                BurnchainParameters::zook_regtest(),
                PoxConstants::regtest_default(),
                PEER_VERSION_TESTNET,
            ),
            (_, _) => {
                return Err(burnchain_error::UnsupportedBurnchain);
            }
        };

        Ok(Burnchain {
            peer_version,
            network_id: params.network_id,
            chain_name: params.chain_name.clone(),
            network_name: params.network_name.clone(),
            working_dir: working_dir.into(),
            consensus_hash_lifetime: params.consensus_hash_lifetime,
            stable_confirmations: params.stable_confirmations,
            first_block_height: params.first_block_height,
            initial_reward_start_block: params.initial_reward_start_block,
            first_block_hash: params.first_block_hash,
            first_block_timestamp: params.first_block_timestamp,
            pox_constants,
        })
    }

    /// Establish chainstate directories for Zook integration.
    pub fn setup_chainstate_dirs(working_dir: &String) -> Result<(), burnchain_error> {
        let chainstate_dir = Burnchain::get_chainstate_path_str(working_dir);
        let chainstate_pathbuf = PathBuf::from(&chainstate_dir);

        if !chainstate_pathbuf.exists() {
            fs::create_dir_all(&chainstate_pathbuf).map_err(burnchain_error::FSError)?;
        }
        Ok(())
    }

    /// Connect to the burnchain databases for Zook.
    pub fn connect_db(
        &self,
        readwrite: bool,
        first_block_header_hash: BurnchainHeaderHash,
        first_block_header_timestamp: u64,
        epochs: EpochList,
    ) -> Result<(SortitionDB, BurnchainDB), burnchain_error> {
        Burnchain::setup_chainstate_dirs(&self.working_dir)?;

        let db_path = self.get_db_path();
        let burnchain_db_path = self.get_burnchaindb_path();

        let sortitiondb = SortitionDB::connect(
            &db_path,
            self.first_block_height,
            &first_block_header_hash,
            first_block_header_timestamp,
            &epochs,
            self.pox_constants.clone(),
            None,
            readwrite,
        )?;
        let burnchaindb = BurnchainDB::connect(&burnchain_db_path, self, readwrite)?;

        Ok((sortitiondb, burnchaindb))
    }

    /// Open just the burnchain database for Zook.
    pub fn open_burnchain_db(&self, readwrite: bool) -> Result<BurnchainDB, burnchain_error> {
        let burnchain_db_path = self.get_burnchaindb_path();
        if burnchain_db_path != ":memory:" {
            if let Err(e) = fs::metadata(&burnchain_db_path) {
                warn!(
                    "Failed to stat burnchain DB path '{}': {:?}",
                    &burnchain_db_path, &e
                );
                return Err(burnchain_error::DBError(db_error::NoDBError));
            }
        }
        test_debug!(
            "Open burnchain DB at {} (rw? {})",
            &burnchain_db_path,
            readwrite
        );
        let burnchain_db = BurnchainDB::open(&burnchain_db_path, readwrite)?;
        Ok(burnchain_db)
    }

    /// Open just the sortition database for Zook.
    pub fn open_sortition_db(&self, readwrite: bool) -> Result<SortitionDB, burnchain_error> {
        let sort_db_path = self.get_db_path();
        if let Err(e) = fs::metadata(&sort_db_path) {
            warn!(
                "Failed to stat sortition DB path '{}': {:?}",
                &sort_db_path, &e
            );
            return Err(burnchain_error::DBError(db_error::NoDBError));
        }
        test_debug!("Open sortition DB at {} (rw? {})", &sort_db_path, readwrite);
        let sortition_db = SortitionDB::open(&sort_db_path, readwrite, self.pox_constants.clone())?;
        Ok(sortition_db)
    }

    /// Open both burnchain and sortition databases for Zook.
    pub fn open_db(&self, readwrite: bool) -> Result<(SortitionDB, BurnchainDB), burnchain_error> {
        let burn_db = self.open_burnchain_db(readwrite)?;
        let sort_db = self.open_sortition_db(readwrite)?;
        Ok((sort_db, burn_db))
    }
}
// Adapted `burnchain.rs` continued

impl Burnchain {
    /// Create a new instance of Burnchain tailored for Zook.
    pub fn new(
        working_dir: &str,
        chain_name: &str,
        network_name: &str,
    ) -> Result<Burnchain, burnchain_error> {
        let (params, pox_constants, peer_version) = match (chain_name, network_name) {
            ("zook", "mainnet") => (
                BurnchainParameters::zook_mainnet(),
                PoxConstants::mainnet_default(),
                PEER_VERSION_MAINNET,
            ),
            ("zook", "testnet") => (
                BurnchainParameters::zook_testnet(),
                PoxConstants::testnet_default(),
                PEER_VERSION_TESTNET,
            ),
            ("zook", "regtest") => (
                BurnchainParameters::zook_regtest(),
                PoxConstants::regtest_default(),
                PEER_VERSION_TESTNET,
            ),
            (_, _) => {
                return Err(burnchain_error::UnsupportedBurnchain);
            }
        };

        Ok(Burnchain {
            peer_version,
            network_id: params.network_id,
            chain_name: params.chain_name.clone(),
            network_name: params.network_name.clone(),
            working_dir: working_dir.into(),
            consensus_hash_lifetime: params.consensus_hash_lifetime,
            stable_confirmations: params.stable_confirmations,
            first_block_height: params.first_block_height,
            initial_reward_start_block: params.initial_reward_start_block,
            first_block_hash: params.first_block_hash,
            first_block_timestamp: params.first_block_timestamp,
            pox_constants,
        })
    }

    /// Establish chainstate directories for Zook integration.
    pub fn setup_chainstate_dirs(working_dir: &String) -> Result<(), burnchain_error> {
        let chainstate_dir = Burnchain::get_chainstate_path_str(working_dir);
        let chainstate_pathbuf = PathBuf::from(&chainstate_dir);

        if !chainstate_pathbuf.exists() {
            fs::create_dir_all(&chainstate_pathbuf).map_err(burnchain_error::FSError)?;
        }
        Ok(())
    }

    /// Connect to the burnchain databases for Zook.
    pub fn connect_db(
        &self,
        readwrite: bool,
        first_block_header_hash: BurnchainHeaderHash,
        first_block_header_timestamp: u64,
        epochs: EpochList,
    ) -> Result<(SortitionDB, BurnchainDB), burnchain_error> {
        Burnchain::setup_chainstate_dirs(&self.working_dir)?;

        let db_path = self.get_db_path();
        let burnchain_db_path = self.get_burnchaindb_path();

        let sortitiondb = SortitionDB::connect(
            &db_path,
            self.first_block_height,
            &first_block_header_hash,
            first_block_header_timestamp,
            &epochs,
            self.pox_constants.clone(),
            None,
            readwrite,
        )?;
        let burnchaindb = BurnchainDB::connect(&burnchain_db_path, self, readwrite)?;

        Ok((sortitiondb, burnchaindb))
    }

    /// Open just the burnchain database for Zook.
    pub fn open_burnchain_db(&self, readwrite: bool) -> Result<BurnchainDB, burnchain_error> {
        let burnchain_db_path = self.get_burnchaindb_path();
        if burnchain_db_path != ":memory:" {
            if let Err(e) = fs::metadata(&burnchain_db_path) {
                warn!(
                    "Failed to stat burnchain DB path '{}': {:?}",
                    &burnchain_db_path, &e
                );
                return Err(burnchain_error::DBError(db_error::NoDBError));
            }
        }
        test_debug!(
            "Open burnchain DB at {} (rw? {})",
            &burnchain_db_path,
            readwrite
        );
        let burnchain_db = BurnchainDB::open(&burnchain_db_path, readwrite)?;
        Ok(burnchain_db)
    }

    /// Open just the sortition database for Zook.
    pub fn open_sortition_db(&self, readwrite: bool) -> Result<SortitionDB, burnchain_error> {
        let sort_db_path = self.get_db_path();
        if let Err(e) = fs::metadata(&sort_db_path) {
            warn!(
                "Failed to stat sortition DB path '{}': {:?}",
                &sort_db_path, &e
            );
            return Err(burnchain_error::DBError(db_error::NoDBError));
        }
        test_debug!("Open sortition DB at {} (rw? {})", &sort_db_path, readwrite);
        let sortition_db = SortitionDB::open(&sort_db_path, readwrite, self.pox_constants.clone())?;
        Ok(sortition_db)
    }

    /// Open both burnchain and sortition databases for Zook.
    pub fn open_db(&self, readwrite: bool) -> Result<(SortitionDB, BurnchainDB), burnchain_error> {
        let burn_db = self.open_burnchain_db(readwrite)?;
        let sort_db = self.open_sortition_db(readwrite)?;
        Ok((sort_db, burn_db))
    }
}
// Adapted `burnchain.rs` continued

impl Burnchain {
    /// Parse a burnchain transaction into a Zook operation.
    pub fn classify_transaction<B: BurnchainHeaderReader>(
        burnchain: &Burnchain,
        indexer: &B,
        burnchain_db: &BurnchainDB,
        block_header: &BurnchainBlockHeader,
        epoch_id: StacksEpochId,
        burn_tx: &BurnchainTransaction,
        pre_stx_op_map: &HashMap<Txid, PreStxOp>,
    ) -> Option<BlockstackOperationType> {
        match burn_tx.opcode() {
            x if x == Opcodes::LeaderKeyRegister as u8 => {
                match LeaderKeyRegisterOp::from_tx(block_header, burn_tx) {
                    Ok(op) => Some(BlockstackOperationType::LeaderKeyRegister(op)),
                    Err(e) => {
                        warn!(
                            "Failed to parse leader key register tx";
                            "txid" => %burn_tx.txid(),
                            "data" => %to_hex(&burn_tx.data()),
                            "error" => ?e,
                        );
                        None
                    }
                }
            }
            x if x == Opcodes::LeaderBlockCommit as u8 => {
                match LeaderBlockCommitOp::from_tx(burnchain, block_header, epoch_id, burn_tx) {
                    Ok(op) => Some(BlockstackOperationType::LeaderBlockCommit(op)),
                    Err(e) => {
                        warn!(
                            "Failed to parse leader block commit tx";
                            "txid" => %burn_tx.txid(),
                            "data" => %to_hex(&burn_tx.data()),
                            "error" => ?e,
                        );
                        None
                    }
                }
            }
            x if x == Opcodes::PreStx as u8 => {
                match PreStxOp::from_tx(
                    block_header,
                    epoch_id,
                    burn_tx,
                    burnchain.pox_constants.sunset_end,
                ) {
                    Ok(op) => Some(BlockstackOperationType::PreStx(op)),
                    Err(e) => {
                        warn!(
                            "Failed to parse pre stack stx tx";
                            "txid" => %burn_tx.txid(),
                            "data" => %to_hex(&burn_tx.data()),
                            "error" => ?e,
                        );
                        None
                    }
                }
            }
            x if x == Opcodes::TransferStx as u8 => {
                let pre_stx_txid = TransferStxOp::get_sender_txid(burn_tx).ok()?;
                let pre_stx_tx = match pre_stx_op_map.get(&pre_stx_txid) {
                    Some(tx_ref) => Some(BlockstackOperationType::PreStx(tx_ref.clone())),
                    None => burnchain_db.find_burnchain_op(indexer, pre_stx_txid),
                };
                if let Some(BlockstackOperationType::PreStx(pre_stx)) = pre_stx_tx {
                    let sender = &pre_stx.output;
                    match TransferStxOp::from_tx(block_header, burn_tx, sender) {
                        Ok(op) => Some(BlockstackOperationType::TransferStx(op)),
                        Err(e) => {
                            warn!(
                                "Failed to parse transfer stx tx";
                                "txid" => %burn_tx.txid(),
                                "data" => %to_hex(&burn_tx.data()),
                                "error" => ?e,
                            );
                            None
                        }
                    }
                } else {
                    warn!(
                        "Failed to find corresponding input to TransferStxOp";
                        "txid" => %burn_tx.txid(),
                        "pre_stx_txid" => %pre_stx_txid
                    );
                    None
                }
            }
            x if x == Opcodes::StackStx as u8 => {
                let pre_stx_txid = StackStxOp::get_sender_txid(burn_tx).ok()?;
                let pre_stx_tx = match pre_stx_op_map.get(&pre_stx_txid) {
                    Some(tx_ref) => Some(BlockstackOperationType::PreStx(tx_ref.clone())),
                    None => burnchain_db.find_burnchain_op(indexer, pre_stx_txid),
                };
                if let Some(BlockstackOperationType::PreStx(pre_stack_stx)) = pre_stx_tx {
                    let sender = &pre_stack_stx.output;
                    match StackStxOp::from_tx(
                        block_header,
                        epoch_id,
                        burn_tx,
                        sender,
                        burnchain.pox_constants.sunset_end,
                    ) {
                        Ok(op) => Some(BlockstackOperationType::StackStx(op)),
                        Err(e) => {
                            warn!(
                                "Failed to parse stack stx tx";
                                "txid" => %burn_tx.txid(),
                                "data" => %to_hex(&burn_tx.data()),
                                "error" => ?e,
                            );
                            None
                        }
                    }
                } else {
                    warn!(
                        "Failed to find corresponding input to StackStxOp";
                        "txid" => %burn_tx.txid().to_string(),
                        "pre_stx_txid" => %pre_stx_txid.to_string()
                    );
                    None
                }
            }
            x if x == Opcodes::DelegateStx as u8 => {
                let pre_stx_txid = DelegateStxOp::get_sender_txid(burn_tx).ok()?;
                let pre_stx_tx = match pre_stx_op_map.get(&pre_stx_txid) {
                    Some(tx_ref) => Some(BlockstackOperationType::PreStx(tx_ref.clone())),
                    None => burnchain_db.find_burnchain_op(indexer, pre_stx_txid),
                };
                if let Some(BlockstackOperationType::PreStx(pre_stx)) = pre_stx_tx {
                    let sender = &pre_stx.output;
                    match DelegateStxOp::from_tx(block_header, burn_tx, sender) {
                        Ok(op) => Some(BlockstackOperationType::DelegateStx(op)),
                        Err(e) => {
                            warn!(
                                "Failed to parse delegate stx tx";
                                "txid" => %burn_tx.txid(),
                                "data" => %to_hex(&burn_tx.data()),
                                "error" => ?e,
                            );
                            None
                        }
                    }
                } else {
                    warn!(
                        "Failed to find corresponding input to DelegateStxOp";
                        "txid" => %burn_tx.txid().to_string(),
                        "pre_stx_txid" => %pre_stx_txid.to_string()
                    );
                    None
                }
            }
            x if x == Opcodes::VoteForAggregateKey as u8 => {
                let pre_stx_txid = VoteForAggregateKeyOp::get_sender_txid(burn_tx).ok()?;
                let pre_stx_tx = match pre_stx_op_map.get(&pre_stx_txid) {
                    Some(tx_ref) => Some(BlockstackOperationType::PreStx(tx_ref.clone())),
                    None => burnchain_db.find_burnchain_op(indexer, pre_stx_txid),
                };
                if let Some(BlockstackOperationType::PreStx(pre_stx)) = pre_stx_tx {
                    let sender = &pre_stx.output;
                    match VoteForAggregateKeyOp::from_tx(block_header, burn_tx, sender) {
                        Ok(op) => Some(BlockstackOperationType::VoteForAggregateKey(op)),
                        Err(e) => {
                            warn!(
                                "Failed to parse vote-for-aggregate-key tx";
                                "txid" => %burn_tx.txid(),
                                "data" => %to_hex(&burn_tx.data()),
                                "error" => ?e,
                            );
                            None
                        }
                    }
                } else {
                    warn!(
                        "Failed to find corresponding input to VoteForAggregateKeyOp";
                        "txid" => %burn_tx.txid().to_string(),
                        "pre_stx_txid" => %pre_stx_txid.to_string()
                    );
                    None
                }
            }

            _ => None,
        }
    }

    /// Verify operations are sorted for Zook.
    pub fn ops_are_sorted(ops: &Vec<BlockstackOperationType>) -> bool {
        if ops.len() > 1 {
            for i in 0..ops.len() - 1 {
                if ops[i].vtxindex() >= ops[i + 1].vtxindex() {
                    return false;
                }
            }
        }
        true
    }
}
// Adapted `burnchain.rs` continued

impl Burnchain {
    /// Synchronize the Zook burnchain with node data.
    pub fn sync<I: BurnchainIndexer + BurnchainHeaderReader + 'static + Send>(
        &mut self,
        indexer: &mut I,
        comms: &CoordinatorChannels,
        target_block_height_opt: Option<u64>,
        max_blocks_opt: Option<u64>,
    ) -> Result<u64, burnchain_error> {
        let chain_tip = self.sync_with_indexer(
            indexer,
            comms.clone(),
            target_block_height_opt,
            max_blocks_opt,
            None,
        )?;
        Ok(chain_tip.block_height)
    }

    /// Deprecated top-level burnchain sync for Zook.
    /// Returns (snapshot of new burnchain tip, last state-transition processed if any)
    pub fn sync_with_indexer_deprecated<
        I: BurnchainIndexer + BurnchainHeaderReader + 'static + Send,
    >(
        &mut self,
        indexer: &mut I,
    ) -> Result<(BlockSnapshot, Option<BurnchainStateTransition>), burnchain_error> {
        self.setup_chainstate(indexer)?;
        let (mut sortdb, mut burnchain_db) = self.connect_db(
            true,
            indexer.get_first_block_header_hash()?,
            indexer.get_first_block_header_timestamp()?,
            indexer.get_stacks_epochs(),
        )?;
        let burnchain_tip = burnchain_db.get_canonical_chain_tip().map_err(|e| {
            error!("Failed to query burn chain tip from burn DB: {}", e);
            e
        })?;

        let db_height = burnchain_tip.block_height;

        // Handle reorgs
        let (sync_height, did_reorg) = Burnchain::sync_reorg(indexer)?;
        if did_reorg {
            warn!(
                "Dropped headers higher than {} due to burnchain reorg",
                sync_height
            );
        }

        // Sync headers from the indexer
        debug!("Sync headers from {}", sync_height);
        let highest_header_height = indexer.get_highest_header_height()?;
        let mut end_block = indexer.sync_headers(highest_header_height, None)?;
        if did_reorg && sync_height > 0 {
            while end_block < db_height {
                end_block = indexer.sync_headers(sync_height, Some(db_height))?;
            }
        }

        let mut start_block = sync_height;
        if db_height < start_block {
            start_block = db_height;
        }

        debug!(
            "Sync'ed headers from {} to {}. DB at {}",
            highest_header_height, end_block, db_height
        );

        if start_block == db_height && db_height == end_block {
            return Ok((burnchain_tip, None));
        }

        let downloader_result: Result<(), burnchain_error> = Ok(());

        let input_headers = indexer.read_headers(start_block + 1, end_block + 1)?;
        let mut downloader = indexer.downloader();
        let mut parser = indexer.parser();

        // Feed the pipeline
        for i in 0..input_headers.len() {
            if let Err(e) = downloader.download(&input_headers[i]) {
                warn!(
                    "Failed to download burnchain block header {}: {:?}",
                    start_block + 1 + (i as u64),
                    &e
                );
                return Err(burnchain_error::TrySyncAgain);
            }
        }

        let mut last_processed = (burnchain_tip, None);

        for block in downloader.blocks() {
            if let Ok(burnchain_block) = parser.parse(&block) {
                let tip = Burnchain::process_block(
                    &self,
                    &mut burnchain_db,
                    &indexer,
                    &burnchain_block,
                    StacksEpochId::Epoch20,
                )?;
                last_processed = (tip, Some(BurnchainStateTransition::noop()));
            }
        }

        Ok(last_processed)
    }

    /// Sync and handle potential reorgs for Zook.
    fn sync_reorg<I: BurnchainIndexer>(
        indexer: &mut I,
    ) -> Result<(u64, bool), burnchain_error> {
        let headers_path = indexer.get_headers_path();

        // Check for reorgs
        let headers_height = indexer.get_highest_header_height()?;
        let reorg_height = indexer.find_chain_reorg()?;

        if reorg_height < headers_height {
            warn!(
                "Burnchain reorg detected: highest common ancestor at height {}",
                reorg_height
            );
            return Ok((reorg_height, true));
        } else {
            return Ok((headers_height, false));
        }
    }
}
// Adapted `burnchain.rs` continued

impl Burnchain {
    /// Process a Zook burnchain block and update the coordinator state.
    pub fn process_block<B: BurnchainHeaderReader>(
        &self,
        burnchain_db: &mut BurnchainDB,
        indexer: &B,
        block: &BurnchainBlock,
        epoch_id: StacksEpochId,
    ) -> Result<BurnchainBlockHeader, burnchain_error> {
        debug!(
            "Processing block {} with hash {}",
            block.block_height(),
            &block.block_hash()
        );

        let block_txs = burnchain_db.store_new_burnchain_block(self, indexer, block, epoch_id)?;

        Burnchain::update_affirmation_maps(
            self,
            burnchain_db,
            indexer,
            block.block_height(),
        )?;

        Ok(block.header())
    }

    /// Update PoX affirmation maps for the Zook burnchain.
    pub fn update_affirmation_maps<B: BurnchainHeaderReader>(
        &self,
        burnchain_db: &mut BurnchainDB,
        indexer: &B,
        block_height: u64,
    ) -> Result<(), burnchain_error> {
        let current_cycle = self
            .block_height_to_reward_cycle(block_height)
            .unwrap_or(0);

        let previous_cycle = self
            .block_height_to_reward_cycle(block_height.saturating_sub(1))
            .unwrap_or(0);

        if current_cycle != previous_cycle {
            info!(
                "Updating PoX affirmation maps for reward cycle {}",
                previous_cycle
            );
            update_pox_affirmation_maps(burnchain_db, indexer, previous_cycle, self)?;
        }

        Ok(())
    }

    /// Determine the highest block processed by the Zook burnchain.
    pub fn get_highest_processed_block(
        &self,
    ) -> Result<Option<BurnchainBlockHeader>, burnchain_error> {
        let burnchain_db = self.open_burnchain_db(true)?;

        let chain_tip = burnchain_db.get_canonical_chain_tip().map_err(|e| {
            error!("Failed to retrieve canonical chain tip: {:?}", e);
            e
        })?;

        Ok(Some(chain_tip))
    }

    /// Connect and synchronize Zook burnchain databases.
    pub fn connect_and_sync_databases(
        &self,
        readwrite: bool,
        genesis_header_hash: BurnchainHeaderHash,
        genesis_timestamp: u64,
        epochs: EpochList,
    ) -> Result<(), burnchain_error> {
        let (mut sortdb, mut burndb) = self.connect_db(
            readwrite,
            genesis_header_hash,
            genesis_timestamp,
            epochs,
        )?;

        let tip = burndb.get_canonical_chain_tip().map_err(|e| {
            error!("Failed to fetch chain tip: {:?}", e);
            e
        })?;

        sortdb.sync_tip(&tip)?;
        Ok(())
    }

    /// Verify if a block is the start of a reward cycle.
    pub fn is_reward_cycle_start(&self, block_height: u64) -> bool {
        self.pox_constants
            .is_reward_cycle_start(self.first_block_height, block_height)
    }

    /// Check if a block is before a reward cycle boundary.
    pub fn is_before_cycle_boundary(
        &self,
        block_height: u64,
        reward_cycle_length: u64,
    ) -> bool {
        let relative_height = block_height.saturating_sub(self.first_block_height);
        (relative_height % reward_cycle_length) <= 1
    }
}
// Adapted `burnchain.rs` continued

impl Burnchain {
    /// Expected sunset burn calculation for Zook.
    pub fn expected_sunset_burn(
        &self,
        burn_height: u64,
        total_commit: u64,
        epoch_id: StacksEpochId,
    ) -> u64 {
        if !self.pox_constants.has_pox_sunset(epoch_id) {
            return 0;
        }
        if !self.pox_constants.is_after_pox_sunset_start(burn_height, epoch_id) {
            return 0;
        }
        if self.pox_constants.is_after_pox_sunset_end(burn_height, epoch_id) {
            return 0;
        }

        if self.is_in_prepare_phase(burn_height) {
            return 0;
        }

        let reward_cycle_height = self.reward_cycle_to_block_height(
            self.block_height_to_reward_cycle(burn_height)
                .expect("BUG: Sunset start is less than first_block_height"),
        );

        if reward_cycle_height <= self.pox_constants.sunset_start {
            return 0;
        }

        let sunset_duration =
            (self.pox_constants.sunset_end - self.pox_constants.sunset_start) as u128;
        let sunset_progress = (reward_cycle_height - self.pox_constants.sunset_start) as u128;

        let expected_u128 = (total_commit as u128) * sunset_progress / sunset_duration;
        u64::try_from(expected_u128).expect("Overflowed u64 in calculating expected sunset_burn")
    }

    /// Determine the block height of a reward cycle for Zook.
    pub fn reward_cycle_to_block_height(&self, reward_cycle: u64) -> u64 {
        self.pox_constants
            .reward_cycle_to_block_height(self.first_block_height, reward_cycle)
    }

    /// Calculate the reward cycle for a given block height for Zook.
    pub fn block_height_to_reward_cycle(&self, block_height: u64) -> Option<u64> {
        self.pox_constants
            .block_height_to_reward_cycle(self.first_block_height, block_height)
    }

    /// Check if the block is in the prepare phase for Zook PoX.
    pub fn is_in_prepare_phase(&self, block_height: u64) -> bool {
        self.pox_constants
            .is_in_prepare_phase(self.first_block_height, block_height)
    }

    /// Fetch the Zook burnchain database path.
    pub fn get_burnchaindb_path(&self) -> String {
        if self.working_dir.as_str() == ":memory:" {
            return ":memory:".to_string();
        }

        let chainstate_dir = Burnchain::get_chainstate_path_str(&self.working_dir);
        let mut db_pathbuf = PathBuf::from(&chainstate_dir);
        db_pathbuf.push("zook-burnchain.sqlite");

        db_pathbuf.to_str().unwrap().to_string()
    }

    /// Open the Zook burnchain database.
    pub fn open_burnchain_db(&self, readwrite: bool) -> Result<BurnchainDB, burnchain_error> {
        let burnchain_db_path = self.get_burnchaindb_path();
        if burnchain_db_path != ":memory:" {
            if let Err(e) = fs::metadata(&burnchain_db_path) {
                warn!(
                    "Failed to stat burnchain DB path '{}': {:?}",
                    &burnchain_db_path, &e
                );
                return Err(burnchain_error::DBError(db_error::NoDBError));
            }
        }
        let burnchain_db = BurnchainDB::open(&burnchain_db_path, readwrite)?;
        Ok(burnchain_db)
    }

    /// Helper to get the chainstate directory path for Zook.
    pub fn get_chainstate_path_str(working_dir: &String) -> String {
        let chainstate_dir_path = PathBuf::from(working_dir);
        let dirpath = chainstate_dir_path.to_str().unwrap().to_string();
        dirpath
    }
}
// Adapted `burnchain.rs` continued

impl Burnchain {
    /// Check if a block is the first to be signed in a reward cycle for Zook.
    pub fn is_naka_signing_cycle_start(&self, burn_height: u64) -> bool {
        self.pox_constants
            .is_naka_signing_cycle_start(self.first_block_height, burn_height)
    }

    /// Determine the first burn block in a reward cycle for Zook.
    pub fn nakamoto_first_block_of_cycle(&self, reward_cycle: u64) -> u64 {
        self.pox_constants
            .nakamoto_first_block_of_cycle(self.first_block_height, reward_cycle)
    }

    /// Check if the block height falls in the prepare phase for Zook.
    pub fn is_in_naka_prepare_phase(&self, block_height: u64) -> bool {
        self.pox_constants
            .is_in_naka_prepare_phase(self.first_block_height, block_height)
    }

    /// Synchronize the Zook headers and handle chain tips.
    pub fn sync_headers<I: BurnchainIndexer>(&mut self, indexer: &mut I) -> Result<u64, burnchain_error> {
        let headers_height = indexer.get_highest_header_height()?;
        let chain_tip = indexer.sync_headers(headers_height, None)?;
        Ok(chain_tip)
    }

    /// Verify the integrity of Zook headers during synchronization.
    pub fn verify_headers<I: BurnchainIndexer>(
        &self,
        indexer: &mut I,
        start_height: u64,
        end_height: u64,
    ) -> Result<(), burnchain_error> {
        for height in start_height..=end_height {
            let header = indexer.get_header_by_height(height)?;
            if header.is_none() {
                return Err(burnchain_error::InvalidHeaders);
            }
        }
        Ok(())
    }

    /// Fetch the latest Zook block information from headers.
    pub fn fetch_latest_burnchain_block<I: BurnchainIndexer>(
        &self,
        indexer: &mut I,
    ) -> Result<BurnchainBlockHeader, burnchain_error> {
        let headers_height = indexer.get_highest_header_height()?;
        let latest_header = indexer.get_header_by_height(headers_height)?;

        if let Some(header) = latest_header {
            Ok(header)
        } else {
            Err(burnchain_error::NoHeadersAvailable)
        }
    }

    /// Return true if Zook is currently in a post-PoX sunset phase.
    pub fn is_post_sunset_phase(&self, burn_height: u64, epoch_id: StacksEpochId) -> bool {
        self.pox_constants
            .is_after_pox_sunset_end(burn_height, epoch_id)
    }

    /// Calculate and log the total burns for the reward cycle window.
    pub fn log_total_burns_for_window(&self, burns: &[u64]) {
        let total_burn: u64 = burns.iter().sum();
        debug!("Total burns for window: {}", total_burn);
    }
}
// Adapted `burnchain.rs` continued

impl Burnchain {
    /// Handle Zook reorganization scenarios during synchronization.
    pub fn handle_reorg<I: BurnchainIndexer>(
        &mut self,
        indexer: &mut I,
    ) -> Result<(), burnchain_error> {
        let (reorg_height, did_reorg) = Burnchain::sync_reorg(indexer)?;
        if did_reorg {
            warn!(
                "Reorganization detected: highest common ancestor at height {}",
                reorg_height
            );
            indexer.drop_headers(reorg_height)?;
        }
        Ok(())
    }

    /// Sync the Zook chain and update the burnchain state.
    pub fn sync_chain<I: BurnchainIndexer + BurnchainHeaderReader>(
        &mut self,
        indexer: &mut I,
        comms: &CoordinatorChannels,
    ) -> Result<BurnchainBlockHeader, burnchain_error> {
        self.handle_reorg(indexer)?;

        let headers_height = indexer.get_highest_header_height()?;
        let target_height = headers_height + 1;

        info!(
            "Syncing Zook chain from headers up to block height {}",
            target_height
        );

        let mut current_height = headers_height;
        while current_height < target_height {
            let block = indexer.fetch_block_by_height(current_height + 1)?;
            self.process_block(indexer, block, comms)?;
            current_height += 1;
        }

        self.fetch_latest_burnchain_block(indexer)
    }

    /// Process a Zook block and update the coordinator state.
    fn process_block<I: BurnchainIndexer + BurnchainHeaderReader>(
        &self,
        indexer: &mut I,
        block: BurnchainBlock,
        comms: &CoordinatorChannels,
    ) -> Result<(), burnchain_error> {
        debug!("Processing Zook block {}", block.block_height());

        let block_header = block.header();
        comms.announce_block_processed(block_header.clone());

        indexer.store_block(&block)?;
        Ok(())
    }

    /// Validate Zook block integrity before processing.
    pub fn validate_block(&self, block: &BurnchainBlock) -> Result<(), burnchain_error> {
        if block.block_height() == 0 {
            return Err(burnchain_error::InvalidBlock);
        }

        if block.txs().is_empty() {
            return Err(burnchain_error::EmptyBlock);
        }

        Ok(())
    }

    /// Provide a detailed debug report for a Zook block.
    pub fn debug_block_report(&self, block: &BurnchainBlock) {
        debug!("Block Height: {}", block.block_height());
        debug!("Block Hash: {}", block.block_hash());
        debug!("Transaction Count: {}", block.txs().len());
    }
}
// Corrected `burnchain.rs` segment 11

impl Burnchain {
    /// Fetch the Zook burnchain database path.
    pub fn get_burnchain_db_path(&self) -> Result<PathBuf, burnchain_error> {
        let chainstate_dir = Burnchain::get_chainstate_path_str(&self.working_dir);
        let mut path = PathBuf::from(chainstate_dir);
        path.push("zook-burnchain.sqlite");

        if !path.exists() {
            return Err(burnchain_error::DBError(db_error::NoDBError));
        }

        Ok(path)
    }

    /// Open and validate the Zook burnchain database.
    pub fn open_and_validate_burnchain_db(&self) -> Result<BurnchainDB, burnchain_error> {
        let db_path = self.get_burnchain_db_path()?;
        let db = BurnchainDB::open(db_path.to_str().unwrap(), true)?;

        if db.get_highest_block_height()? == 0 {
            return Err(burnchain_error::InvalidDB("Empty burnchain database".into()));
        }

        Ok(db)
    }

    /// Validate Zook transaction structure.
    pub fn validate_transaction_structure(&self, tx: &BurnchainTransaction) -> Result<(), burnchain_error> {
        if tx.txid().is_empty() {
            return Err(burnchain_error::InvalidTransaction("Transaction ID is missing".into()));
        }

        if tx.opcode() == 0 {
            return Err(burnchain_error::InvalidTransaction("Opcode is missing".into()));
        }

        Ok(())
    }

    /// Parse Zook-specific headers and initialize chain parameters.
    pub fn parse_and_initialize_headers(
        &mut self,
        indexer: &mut impl BurnchainIndexer,
    ) -> Result<(), burnchain_error> {
        let headers_height = indexer.get_highest_header_height()?;

        if headers_height == 0 {
            return Err(burnchain_error::InvalidHeaders);
        }

        self.sync_headers(indexer)?;
        Ok(())
    }

    /// Rebuild Zook chainstate from scratch.
    pub fn rebuild_chainstate(
        &mut self,
        indexer: &mut impl BurnchainIndexer,
    ) -> Result<(), burnchain_error> {
        info!("Rebuilding chainstate for Zook from scratch");

        let headers_height = indexer.get_highest_header_height()?;
        for height in 0..=headers_height {
            if let Some(block) = indexer.fetch_block_by_height(height)? {
                self.validate_block(&block)?;
                self.process_block(indexer, block, &CoordinatorChannels::default())?;
            }
        }

        Ok(())
    }

    /// Validate Zook opcode definitions.
    pub fn validate_opcodes(&self, tx: &BurnchainTransaction) -> Result<(), burnchain_error> {
        match tx.opcode() {
            Opcodes::LeaderKeyRegisterZook as u8 => Ok(()),
            Opcodes::LeaderBlockCommitZook as u8 => Ok(()),
            Opcodes::PreZBTCZ as u8 => Ok(()),
            Opcodes::TransferZBTCZ as u8 => Ok(()),
            Opcodes::StackZBTCZ as u8 => Ok(()),
            Opcodes::DelegateZBTCZ as u8 => Ok(()),
            Opcodes::VoteForAggregateKeyZook as u8 => Ok(()),
            _ => Err(burnchain_error::InvalidTransaction("Unknown opcode".into())),
        }
    }
}
// Corrected `burnchain.rs` segment 12

impl Burnchain {
    /// Generate a report of burnchain database state for Zook.
    pub fn generate_burnchain_report(&self) -> Result<(), burnchain_error> {
        let db = self.open_and_validate_burnchain_db()?;

        let highest_block = db.get_highest_block_height()?;
        info!("Highest block in Zook burnchain DB: {}", highest_block);

        let total_blocks = db.count_blocks()?;
        info!("Total blocks in Zook burnchain DB: {}", total_blocks);

        let tx_count = db.count_transactions()?;
        info!("Total transactions in Zook burnchain DB: {}", tx_count);

        Ok(())
    }

    /// Sync the Zook burnchain database with headers and rebuild missing blocks.
    pub fn sync_burnchain_db(&mut self, indexer: &mut impl BurnchainIndexer) -> Result<(), burnchain_error> {
        info!("Synchronizing Zook burnchain database");

        let db = self.open_and_validate_burnchain_db()?;

        let highest_db_block = db.get_highest_block_height()?;
        let highest_header_block = indexer.get_highest_header_height()?;

        if highest_db_block < highest_header_block {
            for height in (highest_db_block + 1)..=highest_header_block {
                if let Some(block) = indexer.fetch_block_by_height(height)? {
                    self.validate_block(&block)?;
                    db.store_block(&block)?;
                    info!("Stored block at height: {}", height);
                }
            }
        }

        Ok(())
    }

    /// Export the Zook burnchain state to an external file.
    pub fn export_burnchain_state(&self, output_path: &str) -> Result<(), burnchain_error> {
        let db = self.open_and_validate_burnchain_db()?;

        let blocks = db.get_all_blocks()?;
        let transactions = db.get_all_transactions()?;

        let mut export_data = vec![];
        for block in blocks {
            export_data.push(format!("Block: {:?}", block));
        }

        for tx in transactions {
            export_data.push(format!("Transaction: {:?}", tx));
        }

        fs::write(output_path, export_data.join("\n"))
            .map_err(|e| burnchain_error::ExportError(e.to_string()))?;

        info!("Exported Zook burnchain state to file: {}", output_path);
        Ok(())
    }

    /// Validate and finalize the Zook chain initialization.
    pub fn finalize_chain_initialization(&mut self, indexer: &mut impl BurnchainIndexer) -> Result<(), burnchain_error> {
        self.parse_and_initialize_headers(indexer)?;
        self.sync_burnchain_db(indexer)?;

        info!("Zook chain initialization finalized successfully");
        Ok(())
    }

    /// Reorganize headers to ensure consistency in the Zook burnchain.
    pub fn reorganize_headers(&self, indexer: &mut impl BurnchainIndexer) -> Result<(), burnchain_error> {
        let (reorg_height, did_reorg) = Burnchain::sync_reorg(indexer)?;

        if did_reorg {
            warn!("Reorganizing headers up to height: {}", reorg_height);
            indexer.drop_headers(reorg_height)?;
        }

        Ok(())
    }

    /// Fetch and display the latest Zook burnchain state.
    pub fn fetch_latest_state(&self) -> Result<(), burnchain_error> {
        let db = self.open_and_validate_burnchain_db()?;

        let highest_block = db.get_highest_block_height()?;
        let transactions = db.count_transactions()?;

        info!("Latest Zook burnchain state: Highest Block = {}, Transactions = {}", highest_block, transactions);
        Ok(())
    }
}
// Adapted `burnchain.rs` segment 13

impl Burnchain {
    /// Import an external burnchain state file into the Zook burnchain database.
    pub fn import_burnchain_state(&self, input_path: &str) -> Result<(), burnchain_error> {
        let db = self.open_and_validate_burnchain_db()?;

        let import_data = fs::read_to_string(input_path)
            .map_err(|e| burnchain_error::ImportError(e.to_string()))?;

        for line in import_data.lines() {
            if line.starts_with("Block:") {
                let block: BurnchainBlock = serde_json::from_str(&line[6..])
                    .map_err(|e| burnchain_error::ImportError(e.to_string()))?;
                db.store_block(&block)?;
            } else if line.starts_with("Transaction:") {
                let tx: BurnchainTransaction = serde_json::from_str(&line[12..])
                    .map_err(|e| burnchain_error::ImportError(e.to_string()))?;
                db.store_transaction(&tx)?;
            } else {
                warn!("Unrecognized line in import file: {}", line);
            }
        }

        info!("Successfully imported burnchain state from file: {}", input_path);
        Ok(())
    }

    /// Validate the Zook burnchain database for consistency.
    pub fn validate_burnchain_db(&self) -> Result<(), burnchain_error> {
        let db = self.open_and_validate_burnchain_db()?;

        let highest_block = db.get_highest_block_height()?;
        if highest_block == 0 {
            return Err(burnchain_error::InvalidDB("Burnchain database is empty".into()));
        }

        let tx_count = db.count_transactions()?;
        if tx_count == 0 {
            return Err(burnchain_error::InvalidDB("Burnchain database contains no transactions".into()));
        }

        info!("Burnchain database validation successful: Highest Block = {}, Transactions = {}", highest_block, tx_count);
        Ok(())
    }

    /// Clean up and reset the Zook burnchain database.
    pub fn reset_burnchain_db(&self) -> Result<(), burnchain_error> {
        let db_path = self.get_burnchain_db_path()?;

        fs::remove_file(&db_path).map_err(|e| burnchain_error::DBError(e.to_string()))?;
        info!("Burnchain database reset: {}", db_path.to_string_lossy());
        Ok(())
    }

    /// Backup the Zook burnchain database to a specified location.
    pub fn backup_burnchain_db(&self, backup_path: &str) -> Result<(), burnchain_error> {
        let db_path = self.get_burnchain_db_path()?;

        fs::copy(&db_path, backup_path).map_err(|e| burnchain_error::BackupError(e.to_string()))?;
        info!("Burnchain database backed up to: {}", backup_path);
        Ok(())
    }
}
// Adapted `burnchain.rs` segment 14

impl Burnchain {
    /// Prune old blocks from the Zook burnchain database.
    pub fn prune_old_blocks(&self, retain_height: u64) -> Result<(), burnchain_error> {
        let db = self.open_and_validate_burnchain_db()?;

        let highest_block = db.get_highest_block_height()?;
        if highest_block <= retain_height {
            info!("No blocks to prune. Current highest block: {}, Retain height: {}", highest_block, retain_height);
            return Ok(());
        }

        let blocks_to_prune = db.get_blocks_below_height(retain_height)?;
        for block in blocks_to_prune {
            db.delete_block(&block)?;
            info!("Pruned block at height: {}", block.block_height());
        }

        info!("Pruning complete. Retained blocks up to height: {}", retain_height);
        Ok(())
    }

    /// Initialize the Zook burnchain database for a new network.
    pub fn initialize_new_network(&self, network_name: &str) -> Result<(), burnchain_error> {
        let db_path = self.get_burnchain_db_path()?;
        fs::remove_file(&db_path).unwrap_or_else(|_| info!("No existing burnchain database to remove."));

        let mut db = BurnchainDB::open(db_path.to_str().unwrap(), true)?;
        db.initialize_for_network(network_name)?;

        info!("Initialized new network burnchain database: {}", network_name);
        Ok(())
    }

    /// Perform a full verification of the Zook burnchain state.
    pub fn verify_full_chain(&self) -> Result<(), burnchain_error> {
        let db = self.open_and_validate_burnchain_db()?;
        let all_blocks = db.get_all_blocks()?;

        for block in all_blocks {
            self.validate_block(&block)?;
            info!("Verified block at height: {}", block.block_height());
        }

        info!("Full burnchain verification completed successfully.");
        Ok(())
    }

    /// Monitor and report Zook burnchain database health.
    pub fn monitor_database_health(&self) -> Result<(), burnchain_error> {
        let db = self.open_and_validate_burnchain_db()?;

        let total_blocks = db.count_blocks()?;
        let total_transactions = db.count_transactions()?;

        info!("Database health report: Total Blocks = {}, Total Transactions = {}", total_blocks, total_transactions);

        if total_blocks == 0 || total_transactions == 0 {
            warn!("Potential database issue detected: Zero blocks or transactions.");
            return Err(burnchain_error::InvalidDB("Database health check failed.".into()));
        }

        info!("Burnchain database is healthy.");
        Ok(())
    }
}
