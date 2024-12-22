// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2021 Stacks Open Internet Foundation
// Adapted for the Zook Network
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

use std::cmp;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;
use std::fmt::Write;
use serde::de::Error as de_Error;
use serde::ser::Error as ser_Error;
use serde::{Deserialize, Serialize};
zook_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ZBTCZAddress, ZBTCZBlockId, SortitionId,
};

use crate::burnchains::db::{
    BurnchainBlockData, BurnchainDB, BurnchainDBTransaction, BurnchainHeaderReader,
};
use crate::burnchains::{Burnchain, BurnchainBlockHeader, Error};
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::operations::leader_block_commit::{
    RewardSetInfo, BURN_BLOCK_MINED_AT_MODULUS,
};
use crate::chainstate::burn::operations::{BlockstackOperationType, LeaderBlockCommitOp};
use crate::chainstate::burn::{BlockSnapshot, ConsensusHash};

/// Affirmation map entries. Used to track the presence, absence, or irrelevance of anchor blocks.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum AffirmationMapEntry {
    AnchorBlockPresent,
    AnchorBlockAbsent,
    Nothing,
}

impl AffirmationMapEntry {
    pub fn from_char(c: char) -> Option<AffirmationMapEntry> {
        match c {
            'p' => Some(AffirmationMapEntry::AnchorBlockPresent),
            'a' => Some(AffirmationMapEntry::AnchorBlockAbsent),
            'n' => Some(AffirmationMapEntry::Nothing),
            _ => None,
        }
    }
}

/// A collection of affirmation map entries, representing the state of anchor block confirmations.
#[derive(Clone, PartialEq)]
pub struct AffirmationMap {
    pub affirmations: Vec<AffirmationMapEntry>,
}

impl fmt::Display for AffirmationMapEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AffirmationMapEntry::AnchorBlockPresent => write!(f, "p"),
            AffirmationMapEntry::AnchorBlockAbsent => write!(f, "a"),
            AffirmationMapEntry::Nothing => write!(f, "n"),
        }
    }
}

impl fmt::Debug for AffirmationMapEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("{}", self))
    }
}

impl fmt::Display for AffirmationMap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for entry in &self.affirmations {
            write!(f, "{}", entry)?;
        }
        Ok(())
    }
}

impl fmt::Debug for AffirmationMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl Serialize for AffirmationMap {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let encoded = self.encode();
        s.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for AffirmationMap {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(d)?;
        AffirmationMap::decode(&encoded).ok_or(de_Error::custom("Failed to decode affirmation map"))
    }
}
// Segment 2: Adapting AffirmationMap for Zook Network

use std::cmp;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use serde::{Deserialize, Serialize};

/// Affirmation map entries for Zook Network.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum AffirmationMapEntry {
    ZBTCZAnchorBlockPresent,
    ZBTCZAnchorBlockAbsent,
    None,
}

impl AffirmationMapEntry {
    /// Parse a character into an AffirmationMapEntry.
    pub fn from_chr(c: char) -> Option<Self> {
        match c {
            'p' => Some(Self::ZBTCZAnchorBlockPresent),
            'a' => Some(Self::ZBTCZAnchorBlockAbsent),
            'n' => Some(Self::None),
            _ => None,
        }
    }
}

/// AffirmationMap tracks confirmations of anchor blocks.
#[derive(Clone, PartialEq)]
pub struct AffirmationMap {
    affirmations: Vec<AffirmationMapEntry>,
}

impl AffirmationMap {
    /// Create a new AffirmationMap with specified entries.
    pub fn new(entries: Vec<AffirmationMapEntry>) -> Self {
        Self { affirmations: entries }
    }

    /// Create an empty AffirmationMap.
    pub fn empty() -> Self {
        Self { affirmations: Vec::new() }
    }

    /// Get the entry at a specific reward cycle.
    pub fn at(&self, cycle: u64) -> Option<&AffirmationMapEntry> {
        self.affirmations.get(cycle as usize)
    }

    /// Add an entry to the map.
    pub fn push(&mut self, entry: AffirmationMapEntry) {
        self.affirmations.push(entry);
    }

    /// Get the length of the map.
    pub fn len(&self) -> usize {
        self.affirmations.len()
    }

    /// Encode the map as a string for storage.
    pub fn encode(&self) -> String {
        self.affirmations
            .iter()
            .map(|entry| match entry {
                AffirmationMapEntry::ZBTCZAnchorBlockPresent => 'p',
                AffirmationMapEntry::ZBTCZAnchorBlockAbsent => 'a',
                AffirmationMapEntry::None => 'n',
            })
            .collect()
    }

    /// Decode a string into an AffirmationMap.
    pub fn decode(encoded: &str) -> Option<Self> {
        let affirmations = encoded
            .chars()
            .map(AffirmationMapEntry::from_chr)
            .collect::<Option<Vec<_>>>()?;
        Some(Self { affirmations })
    }
}
/// Affirmation map entries represent the presence, absence, or irrelevance of anchor blocks.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum AffirmationMapEntry {
    AnchorBlockPresent,
    AnchorBlockAbsent,
    Nothing,
}

impl AffirmationMapEntry {
    pub fn from_chr(c: char) -> Option<AffirmationMapEntry> {
        match c {
            'p' => Some(AffirmationMapEntry::AnchorBlockPresent),
            'a' => Some(AffirmationMapEntry::AnchorBlockAbsent),
            'n' => Some(AffirmationMapEntry::Nothing),
            _ => None,
        }
    }
}

/// AffirmationMap encapsulates the state of anchor block confirmations over time.
#[derive(Clone, PartialEq)]
pub struct AffirmationMap {
    affirmations: Vec<AffirmationMapEntry>,
}

impl AffirmationMap {
    /// Create a new affirmation map with given entries.
    pub fn new(entries: Vec<AffirmationMapEntry>) -> Self {
        Self { affirmations: entries }
    }

    /// Create an empty affirmation map.
    pub fn empty() -> Self {
        Self { affirmations: vec![] }
    }

    /// Get the affirmation map entry for a specific reward cycle.
    pub fn at(&self, reward_cycle: u64) -> Option<&AffirmationMapEntry> {
        self.affirmations.get(reward_cycle as usize)
    }

    /// Add a new entry to the affirmation map.
    pub fn push(&mut self, entry: AffirmationMapEntry) {
        self.affirmations.push(entry);
    }

    /// Remove the last entry from the affirmation map.
    pub fn pop(&mut self) -> Option<AffirmationMapEntry> {
        self.affirmations.pop()
    }

    /// Get the length of the affirmation map.
    pub fn len(&self) -> usize {
        self.affirmations.len()
    }

    /// Encode the affirmation map as a string for storage.
    pub fn encode(&self) -> String {
        self.affirmations
            .iter()
            .map(|entry| match entry {
                AffirmationMapEntry::AnchorBlockPresent => "p",
                AffirmationMapEntry::AnchorBlockAbsent => "a",
                AffirmationMapEntry::Nothing => "n",
            })
            .collect()
    }

    /// Decode a string into an affirmation map.
    pub fn decode(encoded: &str) -> Option<Self> {
        let entries = encoded
            .chars()
            .map(AffirmationMapEntry::from_chr)
            .collect::<Option<Vec<_>>>()?;
        Some(Self { affirmations: entries })
    }

    /// Find the divergence point between two affirmation maps.
    pub fn find_divergence(&self, other: &Self) -> Option<u64> {
        for i in 0..std::cmp::min(self.len(), other.len()) {
            if self.affirmations[i] != other.affirmations[i] {
                return Some(i as u64);
            }
        }
        if other.len() > self.len() {
            Some(self.len() as u64)
        } else {
            None
        }
    }

    /// Calculate the weight of this affirmation map.
    pub fn weight(&self) -> u64 {
        self.affirmations
            .iter()
            .filter(|&&entry| entry == AffirmationMapEntry::AnchorBlockPresent)
            .count() as u64
    }
}
/// An affirmation map is simply a list of affirmation map entries. This struct provides methods
/// for manipulating and accessing affirmation data related to sortition histories.
#[derive(Clone, PartialEq)]
pub struct AffirmationMap {
    pub affirmations: Vec<AffirmationMapEntry>,
}

impl fmt::Display for AffirmationMapEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AffirmationMapEntry::AnchorBlockPresent => write!(f, "p"),
            AffirmationMapEntry::AnchorBlockAbsent => write!(f, "a"),
            AffirmationMapEntry::Nothing => write!(f, "n"),
        }
    }
}

impl fmt::Debug for AffirmationMapEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("{}", &self))
    }
}

impl fmt::Display for AffirmationMap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for entry in self.affirmations.iter() {
            write!(f, "{}", &entry)?;
        }
        Ok(())
    }
}

impl fmt::Debug for AffirmationMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl Serialize for AffirmationMap {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let am_str = self.encode();
        s.serialize_str(am_str.as_str())
    }
}

impl<'de> Deserialize<'de> for AffirmationMap {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<AffirmationMap, D::Error> {
        let am_str = String::deserialize(d)?;
        let am = AffirmationMap::decode(&am_str).ok_or(de_Error::custom(
            "Failed to decode affirmation map".to_string(),
        ))?;
        Ok(am)
    }
}

impl AffirmationMap {
    /// Create a new affirmation map with specified entries.
    pub fn new(entries: Vec<AffirmationMapEntry>) -> AffirmationMap {
        AffirmationMap {
            affirmations: entries,
        }
    }

    /// Create an empty affirmation map.
    pub fn empty() -> AffirmationMap {
        AffirmationMap {
            affirmations: vec![],
        }
    }

    /// Retrieve the affirmation entry for the specified reward cycle.
    pub fn at(&self, reward_cycle: u64) -> Option<&AffirmationMapEntry> {
        self.affirmations.get(reward_cycle as usize)
    }

    /// Add an entry to the affirmation map.
    pub fn push(&mut self, entry: AffirmationMapEntry) {
        self.affirmations.push(entry);
    }

    /// Remove the last entry from the affirmation map.
    pub fn pop(&mut self) -> Option<AffirmationMapEntry> {
        self.affirmations.pop()
    }

    /// Get the length of the affirmation map.
    pub fn len(&self) -> usize {
        self.affirmations.len()
    }

    /// Access the affirmation map as a slice.
    pub fn as_slice(&self) -> &[AffirmationMapEntry] {
        &self.affirmations
    }

    /// Encode the affirmation map as a string for storage.
    pub fn encode(&self) -> String {
        let mut ret = String::with_capacity(self.affirmations.len());
        write!(&mut ret, "{}", self).expect("BUG: failed to serialize affirmations -- likely OOM");
        ret
    }

    /// Decode a string into an affirmation map.
    pub fn decode(s: &str) -> Option<AffirmationMap> {
        if !s.is_ascii() {
            return None;
        }

        let mut affirmations = Vec::with_capacity(s.len());
        for chr in s.chars() {
            if let Some(next) = AffirmationMapEntry::from_char(chr) {
                affirmations.push(next);
            } else {
                return None;
            }
        }
        Some(AffirmationMap { affirmations })
    }

    /// Determine divergence between two affirmation maps.
    /// Returns the index where the maps diverge or None if they do not.
    pub fn find_divergence(&self, other: &AffirmationMap) -> Option<u64> {
        for i in 0..cmp::min(self.len(), other.len()) {
            if self.affirmations[i] != other.affirmations[i] {
                return Some(i as u64);
            }
        }

        if other.len() > self.len() {
            return Some(self.len() as u64);
        }

        None
    }

    /// Determine the starting reward cycle for inventory search based on the heaviest map.
    pub fn find_inv_search(&self, heaviest: &AffirmationMap) -> u64 {
        let mut highest_p = None;
        for i in 0..cmp::min(self.len(), heaviest.len()) {
            if self.affirmations[i] == heaviest.affirmations[i]
                && self.affirmations[i] == AffirmationMapEntry::AnchorBlockPresent
            {
                highest_p = Some(i);
            }
        }

        if let Some(highest_p) = highest_p {
            for i in highest_p..cmp::min(self.len(), heaviest.len()) {
                if self.affirmations[i] == heaviest.affirmations[i]
                    && self.affirmations[i] == AffirmationMapEntry::AnchorBlockAbsent
                {
                    return i as u64;
                }
                if self.affirmations[i] != heaviest.affirmations[i] {
                    return i as u64;
                }
            }
            return highest_p as u64;
        } else {
            // No agreement on any anchor block
            0
        }
    }

    /// Check if another affirmation map is a prefix of this map.
    pub fn has_prefix(&self, prefix: &AffirmationMap) -> bool {
        if self.len() < prefix.len() {
            return false;
        }

        for i in 0..prefix.len() {
            if self.affirmations[i] != prefix.affirmations[i] {
                return false;
            }
        }

        true
    }

    /// Calculate the weight of the affirmation map.
    /// Weight is the count of anchor blocks affirmed as present.
    pub fn weight(&self) -> u64 {
        self.affirmations
            .iter()
            .filter(|entry| **entry != AffirmationMapEntry::AnchorBlockAbsent)
            .count() as u64
    }
}
/// Update a completed reward cycle's affirmation maps.
pub fn update_pox_affirmation_maps<B: BurnchainHeaderReader>(
    burnchain_db: &mut BurnchainDB,
    indexer: &B,
    reward_cycle: u64,
    burnchain: &Burnchain,
) -> Result<(), Error> {
    debug!(
        "Processing PoX affirmations for reward cycle {}",
        reward_cycle
    );

    let tx = burnchain_db.tx_begin()?;

    let (prepare_ops, pox_anchor_block_info_opt) =
        find_pox_anchor_block(&tx, reward_cycle, indexer, burnchain)?;

    if let Some((anchor_block, descendancy)) = pox_anchor_block_info_opt.clone() {
        debug!(
            "PoX anchor block elected in reward cycle {} for reward cycle {} is {}",
            reward_cycle,
            reward_cycle + 1,
            &anchor_block.block_header_hash
        );

        // Anchor block found for this upcoming reward cycle.
        tx.set_anchor_block(&anchor_block, reward_cycle + 1)?;
        assert_eq!(descendancy.len(), prepare_ops.len());

        // Mark the prepare-phase commits that elected this next reward cycle's anchor block as
        // having descended or not descended from this anchor block.
        for (block_idx, block_ops) in prepare_ops.iter().enumerate() {
            assert_eq!(block_ops.len(), descendancy[block_idx].len());

            for (tx_idx, tx_op) in block_ops.iter().enumerate() {
                debug!(
                    "Creating affirmation map for block-commit at {},{}",
                    tx_op.block_height,
                    tx_op.vtxindex
                );
                tx.make_prepare_phase_affirmation_map(
                    indexer,
                    burnchain,
                    reward_cycle + 1,
                    tx_op,
                    Some(&anchor_block),
                    descendancy[block_idx][tx_idx],
                )?;
            }
        }
    } else {
        debug!(
            "No PoX anchor block selected in reward cycle {} for reward cycle {}",
            reward_cycle,
            reward_cycle + 1
        );

        // No anchor block found for this upcoming reward cycle.
        tx.clear_anchor_block(reward_cycle + 1)?;

        // Mark all prepare-phase commits as NOT having descended from the next reward cycle's anchor
        // block since one was not chosen.
        for block_ops in prepare_ops.iter() {
            for tx_op in block_ops.iter() {
                debug!(
                    "Creating affirmation map for block-commit at {},{} with no anchor block",
                    tx_op.block_height,
                    tx_op.vtxindex
                );
                tx.make_prepare_phase_affirmation_map(
                    indexer,
                    burnchain,
                    reward_cycle + 1,
                    tx_op,
                    None,
                    false,
                )?;
            }
        }
    }

    // Commit transaction.
    tx.commit()?;

    debug!(
        "Successfully processed PoX affirmations for reward cycle {}",
        reward_cycle
    );
    Ok(())
}
/// Filter the block commits that are valid for processing within the prepare phase
/// based on their respective burn fees and parent block relationships.
pub fn filter_valid_block_commits(
    burnchain_tx: &BurnchainDBTransaction,
    prepare_phase_ops: Vec<Vec<LeaderBlockCommitOp>>,
    parent_commits: &[LeaderBlockCommitOp],
) -> Vec<Vec<LeaderBlockCommitOp>> {
    let mut valid_commits = vec![];

    for block_ops in prepare_phase_ops {
        let filtered_ops: Vec<LeaderBlockCommitOp> = block_ops
            .into_iter()
            .filter(|opdata| {
                let parent_exists = parent_commits.iter().any(|parent| {
                    parent.block_height == opdata.parent_block_ptr as u64
                        && parent.vtxindex == opdata.parent_vtxindex as u32
                });

                let valid_burn_modulus = opdata.burn_block_mined_at() % BURN_BLOCK_MINED_AT_MODULUS
                    == (opdata.block_height + 1) % BURN_BLOCK_MINED_AT_MODULUS;

                if !parent_exists {
                    debug!(
                        "Discarding block commit {} due to missing parent block {}.",
                        opdata.txid, opdata.parent_block_ptr
                    );
                    return false;
                }

                if !valid_burn_modulus {
                    debug!(
                        "Discarding block commit {} due to invalid burn modulus.",
                        opdata.txid
                    );
                    return false;
                }

                true
            })
            .collect();

        if !filtered_ops.is_empty() {
            valid_commits.push(filtered_ops);
        }
    }

    valid_commits
}

/// Select the heaviest block commit within the prepare phase for a specific reward cycle.
/// The selection is based on the cumulative burn fees and confirmations.
pub fn select_heaviest_block_commit(
    valid_commits: &[Vec<LeaderBlockCommitOp>],
    anchor_threshold: u32,
) -> Option<(LeaderBlockCommitOp, u64, u64)> {
    let mut heaviest_commit: Option<(LeaderBlockCommitOp, u64, u64)> = None;
    let mut max_burn = 0;
    let mut max_confs = 0;

    for block_ops in valid_commits {
        for opdata in block_ops {
            let conf_count = block_ops.iter().filter(|o| o.txid == opdata.txid).count() as u64;
            let total_burn = opdata.burn_fee;

            if conf_count >= anchor_threshold as u64 {
                if total_burn > max_burn || (total_burn == max_burn && conf_count > max_confs) {
                    max_burn = total_burn;
                    max_confs = conf_count;
                    heaviest_commit = Some((opdata.clone(), max_burn, max_confs));
                }
            }
        }
    }

    heaviest_commit
}

/// Update the reward cycle's affirmation map based on the heaviest block commit selection.
pub fn update_reward_cycle_affirmations(
    burnchain_tx: &mut BurnchainDBTransaction,
    reward_cycle: u64,
    heaviest_commit: Option<(LeaderBlockCommitOp, u64, u64)>,
) -> Result<(), Error> {
    match heaviest_commit {
        Some((block_commit, burn, confs)) => {
            debug!(
                "Heaviest block commit selected for reward cycle {}: {} with {} burn fees and {} confirmations.",
                reward_cycle, block_commit.txid, burn, confs
            );
            burnchain_tx.set_anchor_block(&block_commit, reward_cycle)?;
        }
        None => {
            debug!(
                "No heaviest block commit found for reward cycle {}. Clearing anchor block.",
                reward_cycle
            );
            burnchain_tx.clear_anchor_block(reward_cycle)?;
        }
    }

    Ok(())
}
/// This function processes PoX affirmation updates for the given burnchain block.
/// Ensures that affirmation maps are correctly updated for the block-commit in context.
pub fn process_affirmation_updates<B: BurnchainHeaderReader>(
    burnchain_db: &mut BurnchainDB,
    indexer: &B,
    block_height: u64,
    burnchain: &Burnchain,
) -> Result<(), Error> {
    let reward_cycle = burnchain
        .pox_constants
        .block_height_to_reward_cycle(burnchain.first_block_height, block_height)?;

    debug!(
        "Processing affirmation updates for block height {} in reward cycle {}",
        block_height, reward_cycle
    );

    update_affirmation_map(burnchain_db, indexer, reward_cycle, burnchain)?;
    Ok(())
}

/// Generate a report of affirmation statuses for monitoring and debugging purposes.
/// Provides a human-readable representation of affirmation maps for a reward cycle.
pub fn generate_affirmation_report(
    burnchain_db: &BurnchainDB,
    reward_cycle: u64,
) -> Result<String, Error> {
    let tx = burnchain_db.tx_begin()?;
    let affirmation_map = tx.load_affirmation_map(reward_cycle)?;

    let report = format!(
        "Affirmation Report for Reward Cycle {}:\n{:#?}",
        reward_cycle, affirmation_map
    );

    Ok(report)
}

/// Synchronize affirmation maps for a given block-commit.
/// Ensures that all block-commits in the reward cycle are consistent
/// with the PoX anchor block status.
pub fn synchronize_affirmation_maps<B: BurnchainHeaderReader>(
    burnchain_db: &mut BurnchainDB,
    indexer: &B,
    reward_cycle: u64,
    burnchain: &Burnchain,
) -> Result<(), Error> {
    debug!("Synchronizing affirmation maps for reward cycle {}", reward_cycle);

    let tx = burnchain_db.tx_begin()?;

    let (prepare_ops, pox_anchor_block_info_opt) =
        find_pox_anchor_block(&tx, reward_cycle, indexer, burnchain)?;

    if let Some((anchor_block, descendancy)) = pox_anchor_block_info_opt.clone() {
        debug!(
            "Updating affirmation maps with elected PoX anchor block {} for reward cycle {}",
            &anchor_block.block_header_hash,
            reward_cycle + 1
        );

        for (block_idx, block_ops) in prepare_ops.iter().enumerate() {
            assert_eq!(block_ops.len(), descendancy[block_idx].len());

            for (tx_idx, tx_op) in block_ops.iter().enumerate() {
                test_debug!(
                    "Synchronizing affirmation map for block-commit at {},{}",
                    tx_op.block_height,
                    tx_op.vtxindex
                );
                tx.make_prepare_phase_affirmation_map(
                    indexer,
                    burnchain,
                    reward_cycle + 1,
                    tx_op,
                    Some(&anchor_block),
                    descendancy[block_idx][tx_idx],
                )?;
            }
        }
    } else {
        debug!(
            "No PoX anchor block elected for reward cycle {}. Clearing affirmation maps.",
            reward_cycle + 1
        );

        tx.clear_anchor_block(reward_cycle + 1)?;

        for block_ops in prepare_ops.iter() {
            for tx_op in block_ops.iter() {
                test_debug!(
                    "Clearing affirmation map for block-commit at {},{}",
                    tx_op.block_height,
                    tx_op.vtxindex
                );
                tx.make_prepare_phase_affirmation_map(
                    indexer,
                    burnchain,
                    reward_cycle + 1,
                    tx_op,
                    None,
                    false,
                )?;
            }
        }
    }

    tx.commit()?;
    debug!("Synchronized affirmation maps for reward cycle {}", reward_cycle);

    Ok(())
}

/// Compute the heaviest affirmation map for the network.
/// This considers all known affirmation maps and selects the one with the highest weight.
pub fn compute_heaviest_affirmation_map(
    burnchain_db: &BurnchainDB,
    reward_cycle: u64,
) -> Result<AffirmationMap, Error> {
    debug!("Computing heaviest affirmation map for reward cycle {}", reward_cycle);

    let tx = burnchain_db.tx_begin()?;

    let affirmation_maps = tx.get_affirmation_maps(reward_cycle)?;
    let mut heaviest_map = AffirmationMap::empty();
    let mut max_weight = 0;

    for (block_commit, affirmation_map) in affirmation_maps.into_iter() {
        let weight = affirmation_map.weight();
        if weight > max_weight {
            heaviest_map = affirmation_map;
            max_weight = weight;
            debug!(
                "New heaviest affirmation map found with weight {} for block-commit {}",
                weight, block_commit
            );
        } else if weight == max_weight {
            debug!(
                "Tie in affirmation map weights: {}, keeping current heaviest map.",
                weight
            );
        }
    }

    debug!("Heaviest affirmation map computed with weight {}", max_weight);
    Ok(heaviest_map)
}

/// Update the burnchain database with the heaviest affirmation map.
pub fn update_heaviest_affirmation_map(
    burnchain_db: &mut BurnchainDB,
    reward_cycle: u64,
    heaviest_map: &AffirmationMap,
) -> Result<(), Error> {
    debug!(
        "Updating burnchain database with heaviest affirmation map for reward cycle {}",
        reward_cycle
    );

    let tx = burnchain_db.tx_begin()?;
    tx.set_heaviest_affirmation_map(reward_cycle, heaviest_map)?;
    tx.commit()?;

    debug!("Heaviest affirmation map updated for reward cycle {}", reward_cycle);
    Ok(())
}
/// Handles updates to PoX affirmation maps.
/// Ensures that the affirmation maps are updated consistently based on the reward cycle and anchor block status.
pub fn handle_pox_affirmation_map_updates<B: BurnchainHeaderReader>(
    burnchain_db: &mut BurnchainDB,
    indexer: &B,
    reward_cycle: u64,
    burnchain: &Burnchain,
) -> Result<(), Error> {
    debug!(
        "Handling updates to PoX affirmation maps for reward cycle {}",
        reward_cycle
    );

    let tx = burnchain_db.tx_begin()?;

    // Fetch prepare phase commits and possible PoX anchor block
    let (prepare_ops, pox_anchor_block_info_opt) =
        find_pox_anchor_block(&tx, reward_cycle, indexer, burnchain)?;

    if let Some((anchor_block, descendancy)) = pox_anchor_block_info_opt {
        debug!(
            "Selected PoX anchor block in reward cycle {} for reward cycle {} is {}",
            reward_cycle,
            reward_cycle + 1,
            &anchor_block.block_header_hash
        );

        // Update database with the new anchor block
        tx.set_anchor_block(&anchor_block, reward_cycle + 1)?;
        assert_eq!(descendancy.len(), prepare_ops.len());

        // Process prepare-phase commits and update affirmation maps
        for (block_idx, block_ops) in prepare_ops.iter().enumerate() {
            assert_eq!(block_ops.len(), descendancy[block_idx].len());

            for (tx_idx, tx_op) in block_ops.iter().enumerate() {
                debug!(
                    "Creating affirmation map for block-commit at {},{}",
                    tx_op.block_height, tx_op.vtxindex
                );
                tx.make_prepare_phase_affirmation_map(
                    indexer,
                    burnchain,
                    reward_cycle + 1,
                    tx_op,
                    Some(&anchor_block),
                    descendancy[block_idx][tx_idx],
                )?;
            }
        }
    } else {
        debug!(
            "No PoX anchor block selected in reward cycle {} for reward cycle {}",
            reward_cycle, reward_cycle + 1
        );

        // Clear any existing anchor block for the upcoming reward cycle
        tx.clear_anchor_block(reward_cycle + 1)?;

        // Update prepare-phase commits for missing anchor block
        for block_ops in prepare_ops.iter() {
            for tx_op in block_ops.iter() {
                debug!(
                    "Creating affirmation map for block-commit at {},{} with no anchor block",
                    tx_op.block_height, tx_op.vtxindex
                );
                tx.make_prepare_phase_affirmation_map(
                    indexer,
                    burnchain,
                    reward_cycle + 1,
                    tx_op,
                    None,
                    false,
                )?;
            }
        }
    }

    // Commit transaction
    tx.commit()?;

    debug!(
        "Successfully handled updates to PoX affirmation maps for reward cycle {}",
        reward_cycle
    );
    Ok(())
}

/// Validates and applies PoX anchor block selection criteria.
/// This ensures the proper election of anchor blocks and updates the relevant database entries.
pub fn validate_and_apply_pox_criteria<B: BurnchainHeaderReader>(
    burnchain_db: &mut BurnchainDB,
    indexer: &B,
    reward_cycle: u64,
    burnchain: &Burnchain,
) -> Result<(), Error> {
    debug!(
        "Validating and applying PoX criteria for reward cycle {}",
        reward_cycle
    );

    // Fetch prepare phase block commits and validate them
    let prepare_phase_commits =
        inner_find_valid_prepare_phase_commits(burnchain_db, reward_cycle, indexer, burnchain)?;
    debug!("Validated {} prepare-phase commits", prepare_phase_commits.len());

    // Identify and apply the heaviest block commit
    if let Some((anchor_block_commit, descendancy, confirmations, burnt)) =
        find_heaviest_block_commit(
            burnchain_db,
            indexer,
            &prepare_phase_commits,
            burnchain.pox_constants.anchor_threshold,
        )?
    {
        debug!(
            "Applying PoX anchor block with confirmations: {} and burnt: {}",
            confirmations, burnt
        );

        apply_anchor_block(
            burnchain_db,
            reward_cycle,
            &anchor_block_commit,
            descendancy,
        )?;
    } else {
        debug!(
            "No PoX anchor block found for reward cycle {}",
            reward_cycle
        );
    }

    Ok(())
}

/// Helper function to apply an anchor block.
/// Updates the burnchain database with the selected anchor block.
fn apply_anchor_block(
    burnchain_db: &mut BurnchainDB,
    reward_cycle: u64,
    anchor_block_commit: &LeaderBlockCommitOp,
    descendancy: Vec<Vec<bool>>,
) -> Result<(), Error> {
    debug!(
        "Applying anchor block {} for reward cycle {}",
        anchor_block_commit.block_header_hash, reward_cycle
    );

    let tx = burnchain_db.tx_begin()?;

    // Update anchor block information in the database
    tx.set_anchor_block(anchor_block_commit, reward_cycle + 1)?;

    // Log and commit the transaction
    tx.commit()?;

    debug!("Successfully applied anchor block for reward cycle {}", reward_cycle);
    Ok(())
}
/// Filters prepare-phase commits to include only those valid for a given reward cycle.
pub fn filter_valid_prepare_phase_commits<B: BurnchainHeaderReader>(
    burnchain_tx: &BurnchainDBTransaction,
    indexer: &B,
    reward_cycle: u64,
    burnchain: &Burnchain,
) -> Result<Vec<Vec<LeaderBlockCommitOp>>, Error> {
    debug!("Filtering valid prepare-phase commits for reward cycle {}", reward_cycle);

    let prepare_phase_commits = read_prepare_phase_commits(
        burnchain_tx,
        indexer,
        &burnchain.zbtcz_constants,
        burnchain.first_block_height,
        reward_cycle,
    )?;

    let parent_commits = read_parent_block_commits(burnchain_tx, indexer, &prepare_phase_commits)?;

    let filtered_commits = filter_orphan_block_commits(&parent_commits, prepare_phase_commits);
    let valid_commits = filter_missed_block_commits(filtered_commits);

    debug!(
        "Filtered valid prepare-phase commits: {}",
        valid_commits.iter().flatten().count()
    );

    Ok(valid_commits)
}

/// Determines the heaviest block commit pointer in a given reward cycle's prepare phase.
pub fn determine_heaviest_block_commit<B: BurnchainHeaderReader>(
    burnchain_tx: &BurnchainDBTransaction,
    reward_cycle: u64,
    indexer: &B,
    burnchain: &Burnchain,
) -> Result<Option<ZBTCZAnchorPtr>, Error> {
    debug!(
        "Determining heaviest block commit for reward cycle {}",
        reward_cycle
    );

    let valid_commits = filter_valid_prepare_phase_commits(burnchain_tx, indexer, reward_cycle, burnchain)?;

    Ok(inner_find_heaviest_block_commit_ptr(
        &valid_commits,
        burnchain.zbtcz_constants.anchor_threshold,
    )
    .map(|(ptr, _)| ptr))
}

/// Given a reward cycle, find the associated affirmation map for a block commit.
/// This function ensures accurate affirmations of ZBTCZ anchor blocks.
pub fn get_affirmation_map<B: BurnchainHeaderReader>(
    burnchain_tx: &BurnchainDBTransaction,
    indexer: &B,
    reward_cycle: u64,
    burnchain: &Burnchain,
) -> Result<AffirmationMap, Error> {
    let prepare_phase_ops = read_prepare_phase_commits(
        burnchain_tx,
        indexer,
        &burnchain.zbtcz_constants,
        burnchain.first_block_height,
        reward_cycle,
    )?;

    let parent_commits = read_parent_block_commits(burnchain_tx, indexer, &prepare_phase_ops)?;
    let filtered_ops = filter_orphan_block_commits(&parent_commits, prepare_phase_ops);
    let valid_ops = filter_missed_block_commits(filtered_ops);

    let (zbtcz_anchor_ptr, ancestors) = match inner_find_heaviest_block_commit_ptr(
        &valid_ops,
        burnchain.zbtcz_constants.anchor_threshold,
    ) {
        Some(data) => data,
        None => {
            debug!("No anchor block found for reward cycle {}", reward_cycle);
            return Ok(AffirmationMap::empty());
        }
    };

    let mut affirmations = AffirmationMap::empty();
    for (block_idx, block_ops) in valid_ops.iter().enumerate() {
        for (tx_idx, opdata) in block_ops.iter().enumerate() {
            if let Some(&(ancestor_height, ancestor_vtxindex)) =
                ancestors.get(&(opdata.block_height, opdata.vtxindex))
            {
                if ancestor_height == zbtcz_anchor_ptr.block_height
                    && ancestor_vtxindex == zbtcz_anchor_ptr.vtxindex
                {
                    affirmations.push(AffirmationMapEntry::AnchorBlockPresent);
                } else {
                    affirmations.push(AffirmationMapEntry::AnchorBlockAbsent);
                }
            } else {
                affirmations.push(AffirmationMapEntry::Nothing);
            }
        }
    }

    Ok(affirmations)
}

/// Validate a ZBTCZ anchor block against its affirmation map.
pub fn validate_anchor_block<B: BurnchainHeaderReader>(
    burnchain_tx: &BurnchainDBTransaction,
    indexer: &B,
    reward_cycle: u64,
    anchor_block: &LeaderBlockCommitOp,
    burnchain: &Burnchain,
) -> Result<bool, Error> {
    let affirmation_map = get_affirmation_map(burnchain_tx, indexer, reward_cycle, burnchain)?;
    if affirmation_map.at(reward_cycle as u64) == Some(&AffirmationMapEntry::AnchorBlockPresent) {
        Ok(true)
    } else {
        debug!("Anchor block {} is not affirmed in reward cycle {}", anchor_block.txid, reward_cycle);
        Ok(false)
    }
}
/// Synchronize affirmation maps for a given reward cycle, ensuring all related
/// block-commits in the prepare phase align with the latest anchor block.
pub fn synchronize_affirmation_maps<B: BurnchainHeaderReader>(
    burnchain_db: &mut BurnchainDB,
    indexer: &B,
    reward_cycle: u64,
    burnchain: &Burnchain,
) -> Result<(), Error> {
    debug!("Synchronizing affirmation maps for reward cycle {}", reward_cycle);

    let tx = burnchain_db.tx_begin()?;

    // Process and validate prepare-phase commits for the reward cycle
    let (prepare_ops, anchor_block_info_opt) =
        find_anchor_block_in_prepare_phase(&tx, reward_cycle, indexer, burnchain)?;

    if let Some((anchor_block, descendancy)) = anchor_block_info_opt {
        debug!(
            "Updating affirmation maps for reward cycle {} with anchor block {}",
            reward_cycle,
            anchor_block.block_header_hash
        );

        // Align prepare-phase block-commits with the elected anchor block
        for (block_idx, block_ops) in prepare_ops.iter().enumerate() {
            for (op_idx, block_op) in block_ops.iter().enumerate() {
                tx.create_affirmation_map(
                    indexer,
                    burnchain,
                    reward_cycle + 1,
                    block_op,
                    Some(&anchor_block),
                    descendancy[block_idx][op_idx],
                )?;
            }
        }

        tx.set_anchor_block(anchor_block, reward_cycle + 1)?;
    } else {
        debug!("No anchor block found for reward cycle {}. Clearing affirmation maps.", reward_cycle);

        tx.clear_anchor_block(reward_cycle + 1)?;

        for block_ops in &prepare_ops {
            for block_op in block_ops {
                tx.create_affirmation_map(
                    indexer,
                    burnchain,
                    reward_cycle + 1,
                    block_op,
                    None,
                    false,
                )?;
            }
        }
    }

    tx.commit()?;
    debug!("Completed synchronization of affirmation maps for reward cycle {}", reward_cycle);

    Ok(())
}

/// Find the heaviest affirmation map from the database, using weight as the determining factor.
pub fn compute_heaviest_affirmation_map(
    burnchain_db: &BurnchainDB,
    reward_cycle: u64,
) -> Result<AffirmationMap, Error> {
    debug!("Computing heaviest affirmation map for reward cycle {}", reward_cycle);

    let tx = burnchain_db.tx_begin()?;

    let all_maps = tx.load_all_affirmation_maps(reward_cycle)?;
    let mut heaviest_map = AffirmationMap::empty();
    let mut max_weight = 0;

    for affirmation_map in all_maps {
        let weight = affirmation_map.weight();
        if weight > max_weight {
            heaviest_map = affirmation_map;
            max_weight = weight;
        }
    }

    debug!("Heaviest affirmation map has weight {}", max_weight);
    Ok(heaviest_map)
}

/// Update the database with the newly computed heaviest affirmation map.
pub fn update_heaviest_affirmation_map(
    burnchain_db: &mut BurnchainDB,
    reward_cycle: u64,
    heaviest_map: &AffirmationMap,
) -> Result<(), Error> {
    debug!("Updating database with heaviest affirmation map for reward cycle {}", reward_cycle);

    let tx = burnchain_db.tx_begin()?;
    tx.store_heaviest_affirmation_map(reward_cycle, heaviest_map)?;
    tx.commit()?;

    debug!("Database updated with heaviest affirmation map for reward cycle {}", reward_cycle);
    Ok(())
}
/// Validate a ZBTCZ anchor block against its affirmation map.
/// Ensures the block is correctly affirmed for the given reward cycle.
pub fn validate_anchor_block<B: BurnchainHeaderReader>(
    burnchain_tx: &BurnchainDBTransaction,
    indexer: &B,
    reward_cycle: u64,
    anchor_block: &LeaderBlockCommitOp,
    burnchain: &Burnchain,
) -> Result<bool, Error> {
    debug!(
        "Validating anchor block {} for reward cycle {}",
        anchor_block.txid, reward_cycle
    );

    let affirmation_map = get_affirmation_map(burnchain_tx, indexer, reward_cycle, burnchain)?;

    if affirmation_map
        .at(reward_cycle)
        .map_or(false, |entry| matches!(entry, AffirmationMapEntry::AnchorBlockPresent))
    {
        debug!("Anchor block {} is valid and affirmed.", anchor_block.txid);
        Ok(true)
    } else {
        debug!(
            "Anchor block {} is not affirmed in reward cycle {}.",
            anchor_block.txid, reward_cycle
        );
        Ok(false)
    }
}

/// Reconcile and align the affirmation maps for a given reward cycle.
/// Ensures that all block-commits are correctly synchronized with the
/// heaviest affirmation map for consistency.
pub fn reconcile_affirmation_maps<B: BurnchainHeaderReader>(
    burnchain_db: &mut BurnchainDB,
    indexer: &B,
    reward_cycle: u64,
    burnchain: &Burnchain,
) -> Result<(), Error> {
    debug!("Reconciling affirmation maps for reward cycle {}", reward_cycle);

    let tx = burnchain_db.tx_begin()?;
    let heaviest_map = compute_heaviest_affirmation_map(burnchain_db, reward_cycle)?;

    let all_maps = tx.load_all_affirmation_maps(reward_cycle)?;
    for affirmation_map in all_maps {
        if !affirmation_map.has_prefix(&heaviest_map) {
            debug!(
                "Affirmation map does not align with the heaviest map for reward cycle {}",
                reward_cycle
            );
            tx.store_affirmation_map(reward_cycle, &heaviest_map)?;
        }
    }

    tx.commit()?;
    debug!("Completed reconciliation of affirmation maps for reward cycle {}", reward_cycle);
    Ok(())
}
