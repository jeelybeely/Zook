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

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::{cmp, fmt, fs, io};

use rusqlite::types::ToSql;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Row, Transaction};
use serde_json;
use zook_common::types::chainstate::BurnchainHeaderHash;
use zook_common::types::sqlite::NO_PARAMS;

use crate::burnchains::affirmation::*;
use crate::burnchains::{
    Burnchain, BurnchainBlock, BurnchainBlockHeader, Error as BurnchainError, Txid,
};
use crate::chainstate::burn::operations::{BlockstackOperationType, LeaderBlockCommitOp};
use crate::chainstate::burn::BlockSnapshot;
use crate::chainstate::stacks::index::{ClarityMarfTrieId, MarfTrieId};
use crate::core::ZookEpochId;
use crate::util_lib::db::{
    opt_u64_to_sql, query_row, query_row_panic, query_rows, sql_pragma, sqlite_open,
    tx_begin_immediate, tx_busy_handler, u64_to_sql, DBConn, Error as DBError, FromColumn, FromRow,
};

pub struct BurnchainDB {
    pub(crate) conn: Connection,
}

pub struct BurnchainDBTransaction<'a> {
    sql_tx: Transaction<'a>,
}

pub struct BurnchainBlockData {
    pub header: BurnchainBlockHeader,
    pub ops: Vec<BlockstackOperationType>,
}

/// A trait for reading burnchain block headers
pub trait BurnchainHeaderReader {
    fn read_burnchain_headers(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<BurnchainBlockHeader>, DBError>;
    fn get_burnchain_headers_height(&self) -> Result<u64, DBError>;
    fn find_burnchain_header_height(
        &self,
        header_hash: &BurnchainHeaderHash,
    ) -> Result<Option<u64>, DBError>;

    fn read_burnchain_header(&self, height: u64) -> Result<Option<BurnchainBlockHeader>, DBError> {
        let mut hdrs = self.read_burnchain_headers(height, height.saturating_add(1))?;
        Ok(hdrs.pop())
    }
}

#[derive(Debug, Clone)]
pub struct BlockCommitMetadata {
    pub burn_block_hash: BurnchainHeaderHash,
    pub txid: Txid,
    pub block_height: u64,
    pub vtxindex: u32,
    pub affirmation_id: u64,
    /// if Some(..), then this block-commit is the anchor block for a reward cycle, and the
    /// reward cycle is represented as the inner u64.
    pub anchor_block: Option<u64>,
    /// If Some(..), then this is the reward cycle which contains the anchor block that this block-commit descends from
    pub anchor_block_descendant: Option<u64>,
}

impl FromColumn<AffirmationMap> for AffirmationMap {
    fn from_column<'a>(row: &'a Row, col_name: &str) -> Result<AffirmationMap, DBError> {
        let txt: String = row.get_unwrap(col_name);
        let am = AffirmationMap::decode(&txt).ok_or(DBError::ParseError)?;
        Ok(am)
    }
}

impl FromRow<AffirmationMap> for AffirmationMap {
    fn from_row<'a>(row: &'a Row) -> Result<AffirmationMap, DBError> {
        AffirmationMap::from_column(row, "affirmation_map")
    }
}

impl FromRow<BlockCommitMetadata> for BlockCommitMetadata {
    fn from_row<'a>(row: &'a Row) -> Result<BlockCommitMetadata, DBError> {
        let burn_block_hash = BurnchainHeaderHash::from_column(row, "burn_block_hash")?;
        let txid = Txid::from_column(row, "txid")?;
        let block_height = u64::from_column(row, "block_height")?;
        let vtxindex: u32 = row.get_unwrap("vtxindex");
        let affirmation_id = u64::from_column(row, "affirmation_id")?;
        let anchor_block_i64: Option<i64> = row.get_unwrap("anchor_block");
        let anchor_block = match anchor_block_i64 {
            Some(ab) => {
                if ab < 0 {
                    return Err(DBError::ParseError);
                }
                Some(ab as u64)
            }
            None => None,
        };

        let anchor_block_descendant_i64: Option<i64> = row.get_unwrap("anchor_block_descendant");
        let anchor_block_descendant = match anchor_block_descendant_i64 {
            Some(abd) => {
                if abd < 0 {
                    return Err(DBError::ParseError);
                }
                Some(abd as u64)
            }
            None => None,
        };

        Ok(BlockCommitMetadata {
            burn_block_hash,
            txid,
            block_height,
            vtxindex,
            affirmation_id,
            anchor_block,
            anchor_block_descendant,
        })
    }
}
// Segment 2: Adaptation of DB Structures

pub struct BurnchainDB {
    pub(crate) conn: Connection,
}

pub struct BurnchainDBTransaction<'a> {
    sql_tx: Transaction<'a>,
}

pub struct BurnchainBlockData {
    pub header: BurnchainBlockHeader,
    pub ops: Vec<ZookOperationType>,
}

/// A trait for reading burnchain block headers
pub trait BurnchainHeaderReader {
    fn read_burnchain_headers(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<BurnchainBlockHeader>, DBError>;

    fn get_burnchain_headers_height(&self) -> Result<u64, DBError>;

    fn find_burnchain_header_height(
        &self,
        header_hash: &BurnchainHeaderHash,
    ) -> Result<Option<u64>, DBError>;

    fn read_burnchain_header(&self, height: u64) -> Result<Option<BurnchainBlockHeader>, DBError> {
        let mut hdrs = self.read_burnchain_headers(height, height.saturating_add(1))?;
        Ok(hdrs.pop())
    }
}

#[derive(Debug, Clone)]
pub struct BlockCommitMetadata {
    pub burn_block_hash: BurnchainHeaderHash,
    pub txid: Txid,
    pub block_height: u64,
    pub vtxindex: u32,
    pub affirmation_id: u64,
    /// If Some(..), this block-commit is the anchor block for a reward cycle, and the
    /// reward cycle is represented as the inner u64.
    pub anchor_block: Option<u64>,
    /// If Some(..), this is the reward cycle containing the anchor block that this block-commit descends from.
    pub anchor_block_descendant: Option<u64>,
}
// Segment 3: Affirmation Map Implementations

impl FromColumn<AffirmationMap> for AffirmationMap {
    fn from_column<'a>(row: &'a Row, col_name: &str) -> Result<AffirmationMap, DBError> {
        let txt: String = row.get_unwrap(col_name);
        let am = AffirmationMap::decode(&txt).ok_or(DBError::ParseError)?;
        Ok(am)
    }
}

impl FromRow<AffirmationMap> for AffirmationMap {
    fn from_row<'a>(row: &'a Row) -> Result<AffirmationMap, DBError> {
        AffirmationMap::from_column(row, "affirmation_map")
    }
}

impl FromRow<BlockCommitMetadata> for BlockCommitMetadata {
    fn from_row<'a>(row: &'a Row) -> Result<BlockCommitMetadata, DBError> {
        let burn_block_hash = BurnchainHeaderHash::from_column(row, "burn_block_hash")?;
        let txid = Txid::from_column(row, "txid")?;
        let block_height = u64::from_column(row, "block_height")?;
        let vtxindex: u32 = row.get_unwrap("vtxindex");
        let affirmation_id = u64::from_column(row, "affirmation_id")?;
        let anchor_block_i64: Option<i64> = row.get_unwrap("anchor_block");
        let anchor_block = anchor_block_i64.map(|ab| ab as u64);

        let anchor_block_descendant_i64: Option<i64> = row.get_unwrap("anchor_block_descendant");
        let anchor_block_descendant = anchor_block_descendant_i64.map(|abd| abd as u64);

        Ok(BlockCommitMetadata {
            burn_block_hash,
            txid,
            block_height,
            vtxindex,
            affirmation_id,
            anchor_block,
            anchor_block_descendant,
        })
    }
}

/// Apply safety checks on extracted Zook transactions
/// - Put them in order by vtxindex
/// - Ensure there are no vtxindex duplicates
pub(crate) fn apply_zook_txs_safety_checks(
    block_height: u64,
    zook_txs: &mut Vec<ZookOperationType>,
) {
    debug!(
        "Apply safety checks on {} txs at burnchain height {}",
        zook_txs.len(),
        block_height
    );

    // Ensure order
    zook_txs.sort_by(|a, b| a.vtxindex().partial_cmp(&b.vtxindex()).unwrap());

    // Ensure no duplicate vtxindex
    if zook_txs.len() > 1 {
        for i in 0..zook_txs.len() - 1 {
            if zook_txs[i].vtxindex() == zook_txs[i + 1].vtxindex() {
                panic!(
                    "FATAL: BUG: duplicate vtxindex {} in block {}",
                    zook_txs[i].vtxindex(),
                    zook_txs[i].block_height()
                );
            }
        }
    }

    // Ensure block heights match
    for tx in zook_txs.iter() {
        if tx.block_height() != block_height {
            panic!(
                "FATAL: BUG: block height mismatch: {} != {}",
                tx.block_height(),
                block_height
            );
        }
    }
}
// Segment 4: Burnchain Database Schema and Metadata Handling

pub const BURNCHAIN_DB_VERSION: &'static str = "2";

const BURNCHAIN_DB_SCHEMA: &'static str = r#"
CREATE TABLE burnchain_db_block_headers (
    block_height INTEGER NOT NULL,
    block_hash TEXT UNIQUE NOT NULL,
    parent_block_hash TEXT NOT NULL,
    num_txs INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    PRIMARY KEY(block_hash)
);

CREATE TABLE burnchain_db_block_ops (
    block_hash TEXT NOT NULL,
    op TEXT NOT NULL,
    txid TEXT NOT NULL,
    FOREIGN KEY(block_hash) REFERENCES burnchain_db_block_headers(block_hash)
);

CREATE TABLE affirmation_maps (
    affirmation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    weight INTEGER NOT NULL,
    affirmation_map TEXT NOT NULL
);
CREATE INDEX affirmation_maps_index ON affirmation_maps(affirmation_map);

CREATE TABLE anchor_blocks (
    reward_cycle INTEGER PRIMARY KEY
);

CREATE TABLE block_commit_metadata (
    burn_block_hash TEXT NOT NULL,
    txid TEXT NOT NULL,
    block_height INTEGER NOT NULL,
    vtxindex INTEGER NOT NULL,
    affirmation_id INTEGER NOT NULL,
    anchor_block INTEGER,
    anchor_block_descendant INTEGER,
    PRIMARY KEY(burn_block_hash, txid),
    FOREIGN KEY(affirmation_id) REFERENCES affirmation_maps(affirmation_id),
    FOREIGN KEY(anchor_block) REFERENCES anchor_blocks(reward_cycle)
);

CREATE TABLE overrides (
    reward_cycle INTEGER PRIMARY KEY NOT NULL,
    affirmation_map TEXT NOT NULL
);

CREATE TABLE db_config(version TEXT NOT NULL);

INSERT INTO affirmation_maps(affirmation_id, weight, affirmation_map) VALUES (0, 0, "");
"#;

const LAST_BURNCHAIN_DB_INDEX: &'static str =
    "index_block_commit_metadata_burn_block_hash_anchor_block";

const BURNCHAIN_DB_INDEXES: &'static [&'static str] = &[
    "CREATE INDEX IF NOT EXISTS index_burnchain_db_block_headers_height_hash ON burnchain_db_block_headers(block_height DESC, block_hash ASC);",
    "CREATE INDEX IF NOT EXISTS index_burnchain_db_block_hash ON burnchain_db_block_ops(block_hash);",
    "CREATE INDEX IF NOT EXISTS index_burnchain_db_txid ON burnchain_db_block_ops(txid);",
    "CREATE INDEX IF NOT EXISTS index_burnchain_db_txid_block_hash ON burnchain_db_block_ops(txid, block_hash);",
    "CREATE INDEX IF NOT EXISTS index_block_commit_metadata_block_height_vtxindex_burn_block_hash ON block_commit_metadata(block_height, vtxindex, burn_block_hash);",
    "CREATE INDEX IF NOT EXISTS index_block_commit_metadata_anchor_block_burn_block_hash_txid ON block_commit_metadata(anchor_block, burn_block_hash, txid);",
    "CREATE INDEX IF NOT EXISTS index_block_commit_metadata_burn_block_hash_txid ON block_commit_metadata(burn_block_hash, txid);",
    "CREATE INDEX IF NOT EXISTS index_block_commit_metadata_burn_block_hash_anchor_block ON block_commit_metadata(burn_block_hash, anchor_block);",
];

impl BurnchainDB {
    /// Add indexes to the burnchain database if they do not already exist.
    fn add_indexes(&mut self) -> Result<(), BurnchainError> {
        let exists: i64 = query_row(
            self.conn(),
            "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?1",
            params![LAST_BURNCHAIN_DB_INDEX],
        )?
        .unwrap_or(0);

        if exists == 0 {
            let db_tx = self.tx_begin()?;
            for index in BURNCHAIN_DB_INDEXES.iter() {
                db_tx.sql_tx.execute_batch(index)?;
            }
            db_tx.commit()?;
        }
        Ok(())
    }

    /// Initialize a new burnchain database.
    pub fn connect(
        path: &str,
        burnchain: &Burnchain,
        readwrite: bool,
    ) -> Result<BurnchainDB, BurnchainError> {
        let mut create_flag = false;
        let open_flags = if path == ":memory:" {
            create_flag = true;
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
        } else {
            match fs::metadata(path) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    if readwrite {
                        create_flag = true;
                        let ppath = Path::new(path);
                        let pparent_path = ppath
                            .parent()
                            .unwrap_or_else(|| panic!("BUG: no parent of '{}'", path));
                        fs::create_dir_all(&pparent_path)
                            .map_err(|e| BurnchainError::from(DBError::IOError(e)))?;

                        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
                    } else {
                        return Err(BurnchainError::from(DBError::NoDBError));
                    }
                }
                Ok(_) => {
                    if readwrite {
                        OpenFlags::SQLITE_OPEN_READ_WRITE
                    } else {
                        OpenFlags::SQLITE_OPEN_READ_ONLY
                    }
                }
                Err(e) => return Err(BurnchainError::from(DBError::IOError(e))),
            }
        };

        let conn = sqlite_open(path, open_flags, true)?;
        let mut db = BurnchainDB { conn };

        if create_flag {
            let db_tx = db.tx_begin()?;
            db_tx.sql_tx.execute_batch(BURNCHAIN_DB_SCHEMA)?;
            db_tx.sql_tx.execute(
                "INSERT INTO db_config (version) VALUES (?1)",
                params![&BURNCHAIN_DB_VERSION],
            )?;

            let first_block_header = BurnchainBlockHeader {
                block_height: burnchain.first_block_height,
                block_hash: burnchain.first_block_hash.clone(),
                timestamp: burnchain.first_block_timestamp.into(),
                num_txs: 0,
                parent_block_hash: BurnchainHeaderHash::sentinel(),
            };

            debug!(
                "Instantiate burnchain DB at {}. First block header is {:?}",
                path, &first_block_header
            );
            db_tx.store_burnchain_db_entry(&first_block_header)?;

            let first_snapshot = BlockSnapshot::initial(
                burnchain.first_block_height,
                &burnchain.first_block_hash,
                burnchain.first_block_timestamp as u64,
            );
            let first_snapshot_commit_metadata = BlockCommitMetadata {
                burn_block_hash: first_snapshot.burn_header_hash.clone(),
                txid: first_snapshot.winning_block_txid.clone(),
                block_height: first_snapshot.block_height,
                vtxindex: 0,
                affirmation_id: 0,
                anchor_block: None,
                anchor_block_descendant: None,
            };
            db_tx.insert_block_commit_metadata(first_snapshot_commit_metadata)?;
            db_tx.commit()?;
        }

        if readwrite {
            db.add_indexes()?;
        }

        Ok(db)
    }

    /// Open an existing burnchain database.
    pub fn open(path: &str, readwrite: bool) -> Result<BurnchainDB, BurnchainError> {
        let open_flags = if readwrite {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        } else {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        };

        let conn = sqlite_open(path, open_flags, true)?;
        let mut db = BurnchainDB { conn };

        if readwrite || path == ":memory:" {
            db.add_indexes()?;
        }

        Ok(db)
    }
}
// Segment 5: Database Query Functions for Burnchain

impl BurnchainDB {
    /// Retrieve the canonical chain tip from the database.
    pub fn get_canonical_chain_tip(&self) -> Result<BurnchainBlockHeader, BurnchainError> {
        let query = "SELECT * FROM burnchain_db_block_headers ORDER BY block_height DESC, block_hash ASC LIMIT 1";
        query_row(&self.conn, query, NO_PARAMS)
            .map(|opt| opt.expect("CORRUPTION: Could not query highest burnchain header"))
    }

    /// Check if a burnchain block exists at a specific height.
    pub fn has_burnchain_block_at_height(
        conn: &DBConn,
        height: u64,
    ) -> Result<bool, BurnchainError> {
        let query = "SELECT 1 FROM burnchain_db_block_headers WHERE block_height = ?1";
        query_row(conn, query, params![u64_to_sql(height)?])
            .map(|opt: Option<i64>| opt.is_some())
    }

    /// Retrieve a burnchain block header at a given height.
    pub fn get_burnchain_header<B: BurnchainHeaderReader>(
        conn: &DBConn,
        indexer: &B,
        height: u64,
    ) -> Result<Option<BurnchainBlockHeader>, BurnchainError> {
        let Some(hdr) = indexer.read_burnchain_header(height)? else {
            return Ok(None);
        };
        let query = "SELECT * FROM burnchain_db_block_headers WHERE block_hash = ?1";
        query_row(conn, query, params![hdr.block_hash])
    }

    /// Retrieve a burnchain block, including its header and operations.
    pub fn get_burnchain_block(
        conn: &DBConn,
        block_hash: &BurnchainHeaderHash,
    ) -> Result<BurnchainBlockData, BurnchainError> {
        let header_query =
            "SELECT * FROM burnchain_db_block_headers WHERE block_hash = ? LIMIT 1";
        let ops_query = "SELECT DISTINCT * FROM burnchain_db_block_ops WHERE block_hash = ?";

        let header = query_row(conn, header_query, params![block_hash])?
            .ok_or_else(|| BurnchainError::UnknownBlock(block_hash.clone()))?;
        let ops = query_rows(conn, ops_query, params![block_hash])?;

        Ok(BurnchainBlockData { header, ops })
    }

    /// Retrieve a specific burnchain operation by block hash and transaction ID.
    fn inner_get_burnchain_op(
        conn: &DBConn,
        burn_header_hash: &BurnchainHeaderHash,
        txid: &Txid,
    ) -> Option<ZookOperationType> {
        let query =
            "SELECT DISTINCT op FROM burnchain_db_block_ops WHERE txid = ?1 AND block_hash = ?2";
        query_row(conn, query, params![txid, burn_header_hash])
    }

    /// Retrieve a burnchain operation from the canonical fork based on the transaction ID.
    pub fn find_burnchain_op<B: BurnchainHeaderReader>(
        &self,
        indexer: &B,
        txid: &Txid,
    ) -> Option<ZookOperationType> {
        let query = "SELECT DISTINCT op FROM burnchain_db_block_ops WHERE txid = ?1";
        let ops: Vec<ZookOperationType> = query_rows(&self.conn, query, params![txid])
            .expect("FATAL: burnchain DB query error");

        for op in ops {
            if let Some(_) = indexer
                .find_burnchain_header_height(&op.burn_header_hash())
                .expect("FATAL: burnchain DB query error")
            {
                return Some(op);
            }
        }
        None
    }

    /// Get blockstack transactions from a burnchain block, ordered by vtxindex.
    fn get_blockstack_transactions<B: BurnchainHeaderReader>(
        &self,
        burnchain: &Burnchain,
        indexer: &B,
        block: &BurnchainBlock,
        block_header: &BurnchainBlockHeader,
        epoch_id: ZookEpochId,
    ) -> Vec<ZookOperationType> {
        debug!(
            "Extract Zook transactions from block {} {} ({} txs)",
            block.block_height(),
            &block.block_hash(),
            block.txs().len(),
        );

        let mut ops = Vec::new();
        let mut pre_zbtcz_ops = HashMap::new();

        for tx in block.txs().iter() {
            let result = Burnchain::classify_transaction(
                burnchain,
                indexer,
                self,
                block_header,
                epoch_id,
                &tx,
                &pre_zbtcz_ops,
            );
            if let Some(classified_tx) = result {
                if let ZookOperationType::PreZBTCZ(pre_zbtcz_op) = classified_tx {
                    pre_zbtcz_ops.insert(pre_zbtcz_op.txid.clone(), pre_zbtcz_op);
                } else {
                    ops.push(classified_tx);
                }
            }
        }

        ops.extend(
            pre_zbtcz_ops
                .into_iter()
                .map(|(_, op)| ZookOperationType::PreZBTCZ(op)),
        );

        ops.sort_by_key(|op| op.vtxindex());

        ops
    }
}
// Segment 6: Query Methods for BurnchainDB

impl BurnchainDB {
    /// Get the canonical chain tip.
    pub fn get_canonical_chain_tip(&self) -> Result<BurnchainBlockHeader, BurnchainError> {
        let qry = "SELECT * FROM burnchain_db_block_headers ORDER BY block_height DESC, block_hash ASC LIMIT 1";
        let opt: Option<BurnchainBlockHeader> = query_row(&self.conn, qry, NO_PARAMS)?;
        opt.ok_or_else(|| {
            BurnchainError::DBError(DBError::NotFoundError)
        })
    }

    /// Check if a burnchain block exists at a specific height.
    pub fn has_burnchain_block_at_height(
        conn: &DBConn,
        height: u64,
    ) -> Result<bool, BurnchainError> {
        let qry = "SELECT 1 FROM burnchain_db_block_headers WHERE block_height = ?1";
        let args = params![u64_to_sql(height)?];
        let res: Option<i64> = query_row(conn, qry, args)?;
        Ok(res.is_some())
    }

    /// Get a burnchain header given its height.
    pub fn get_burnchain_header<B: BurnchainHeaderReader>(
        conn: &DBConn,
        indexer: &B,
        height: u64,
    ) -> Result<Option<BurnchainBlockHeader>, BurnchainError> {
        if let Some(hdr) = indexer.read_burnchain_header(height)? {
            let qry = "SELECT * FROM burnchain_db_block_headers WHERE block_hash = ?1";
            let args = params![hdr.block_hash];
            query_row(conn, qry, args)
        } else {
            Ok(None)
        }
    }

    /// Retrieve a burnchain block from the database.
    pub fn get_burnchain_block(
        conn: &DBConn,
        block: &BurnchainHeaderHash,
    ) -> Result<BurnchainBlockData, BurnchainError> {
        let block_header_qry =
            "SELECT * FROM burnchain_db_block_headers WHERE block_hash = ?1 LIMIT 1";
        let block_ops_qry = "SELECT DISTINCT * FROM burnchain_db_block_ops WHERE block_hash = ?1";

        let block_header: BurnchainBlockHeader = query_row(conn, block_header_qry, params![block])?
            .ok_or_else(|| BurnchainError::UnknownBlock(block.clone()))?;
        let block_ops: Vec<BlockstackOperationType> = query_rows(conn, block_ops_qry, params![block])?;

        Ok(BurnchainBlockData {
            header: block_header,
            ops: block_ops,
        })
    }

    /// Retrieve a blockstack transaction from the burnchain database.
    pub fn find_burnchain_op<B: BurnchainHeaderReader>(
        &self,
        indexer: &B,
        txid: &Txid,
    ) -> Option<BlockstackOperationType> {
        let qry = "SELECT DISTINCT op FROM burnchain_db_block_ops WHERE txid = ?1";
        let args = params![txid];

        let ops: Vec<BlockstackOperationType> =
            query_rows(&self.conn, qry, args).expect("Error querying burnchain operations");
        for op in ops {
            if indexer
                .find_burnchain_header_height(&op.burn_header_hash())
                .expect("Error finding burnchain header height")
                .is_some()
            {
                return Some(op);
            }
        }
        None
    }

    /// Filter and return burnchain transactions classified as blockstack operations.
    fn get_blockstack_transactions<B: BurnchainHeaderReader>(
        &self,
        burnchain: &Burnchain,
        indexer: &B,
        block: &BurnchainBlock,
        block_header: &BurnchainBlockHeader,
        epoch_id: StacksEpochId,
    ) -> Vec<BlockstackOperationType> {
        let mut ops = Vec::new();
        let mut pre_stx_ops = HashMap::new();

        for tx in block.txs().iter() {
            if let Some(classified_tx) = Burnchain::classify_transaction(
                burnchain,
                indexer,
                self,
                block_header,
                epoch_id,
                tx,
                &pre_stx_ops,
            ) {
                if let BlockstackOperationType::PreStx(pre_stx_op) = classified_tx {
                    pre_stx_ops.insert(pre_stx_op.txid.clone(), pre_stx_op);
                } else {
                    ops.push(classified_tx);
                }
            }
        }

        ops.extend(
            pre_stx_ops
                .into_iter()
                .map(|(_, op)| BlockstackOperationType::PreStx(op)),
        );

        ops.sort_by_key(|op| op.vtxindex());
        ops
    }
}
// Segment 7: Affirmation Map Retrieval and Handling

impl BurnchainDB {
    /// Retrieve an affirmation map from the database using the affirmation ID.
    pub fn get_affirmation_map(
        conn: &DBConn,
        affirmation_id: u64,
    ) -> Result<Option<AffirmationMap>, DBError> {
        let sql = "SELECT affirmation_map FROM affirmation_maps WHERE affirmation_id = ?1";
        let args = params![u64_to_sql(affirmation_id)?];
        query_row(conn, sql, args)
    }

    /// Retrieve the weight of an affirmation map from the database using the affirmation ID.
    pub fn get_affirmation_weight(
        conn: &DBConn,
        affirmation_id: u64,
    ) -> Result<Option<u64>, DBError> {
        let sql = "SELECT weight FROM affirmation_maps WHERE affirmation_id = ?1";
        let args = params![u64_to_sql(affirmation_id)?];
        query_row(conn, sql, args)
    }

    /// Retrieve the ID of an affirmation map from the database using the map's encoded representation.
    pub fn get_affirmation_map_id(
        conn: &DBConn,
        affirmation_map: &AffirmationMap,
    ) -> Result<Option<u64>, DBError> {
        let sql = "SELECT affirmation_id FROM affirmation_maps WHERE affirmation_map = ?1";
        let args = params![affirmation_map.encode()];
        query_row(conn, sql, args)
    }

    /// Retrieve the affirmation ID associated with a block commit located in a specific burnchain block.
    pub fn get_affirmation_map_id_at(
        conn: &DBConn,
        burn_header_hash: &BurnchainHeaderHash,
        txid: &Txid,
    ) -> Result<Option<u64>, DBError> {
        let sql = "SELECT affirmation_id FROM block_commit_metadata WHERE burn_block_hash = ?1 AND txid = ?2";
        let args = params![burn_header_hash, txid];
        query_row(conn, sql, args)
    }

    /// Check whether a block commit is an anchor block by its burnchain block hash and transaction ID.
    pub fn is_anchor_block(
        conn: &DBConn,
        burn_header_hash: &BurnchainHeaderHash,
        txid: &Txid,
    ) -> Result<bool, DBError> {
        let sql = "SELECT 1 FROM block_commit_metadata WHERE anchor_block IS NOT NULL AND burn_block_hash = ?1 AND txid = ?2";
        let args = params![burn_header_hash, txid];
        query_row(conn, sql, args)?.ok_or(DBError::NotFoundError)
    }

    /// Check whether an anchor block exists for a specific reward cycle.
    pub fn has_anchor_block(conn: &DBConn, reward_cycle: u64) -> Result<bool, DBError> {
        let sql = "SELECT 1 FROM block_commit_metadata WHERE anchor_block = ?1";
        let args = params![u64_to_sql(reward_cycle)?];
        Ok(query_row::<bool, _>(conn, sql, args)?.is_some())
    }

    /// Retrieve metadata for all block commits marked as anchor blocks for a specific reward cycle.
    pub fn get_anchor_block_commit_metadatas(
        conn: &DBConn,
        reward_cycle: u64,
    ) -> Result<Vec<BlockCommitMetadata>, DBError> {
        let sql = "SELECT * FROM block_commit_metadata WHERE anchor_block = ?1";
        let args = params![u64_to_sql(reward_cycle)?];

        let metadatas: Vec<BlockCommitMetadata> = query_rows(conn, sql, args)?;
        Ok(metadatas)
    }

    /// Retrieve metadata for the canonical anchor block commit within a specific reward cycle.
    pub fn get_canonical_anchor_block_commit_metadata<B: BurnchainHeaderReader>(
        conn: &DBConn,
        indexer: &B,
        reward_cycle: u64,
    ) -> Result<Option<BlockCommitMetadata>, DBError> {
        let sql = "SELECT * FROM block_commit_metadata WHERE anchor_block = ?1";
        let args = params![u64_to_sql(reward_cycle)?];

        let metadatas: Vec<BlockCommitMetadata> = query_rows(conn, sql, args)?;
        for metadata in metadatas {
            if let Some(header) = indexer.read_burnchain_header(metadata.block_height)? {
                if header.block_hash == metadata.burn_block_hash {
                    return Ok(Some(metadata));
                }
            }
        }
        Ok(None)
    }

    /// Retrieve both the block commit and metadata for the canonical anchor block commit.
    pub fn get_canonical_anchor_block_commit<B: BurnchainHeaderReader>(
        conn: &DBConn,
        indexer: &B,
        reward_cycle: u64,
    ) -> Result<Option<(LeaderBlockCommitOp, BlockCommitMetadata)>, DBError> {
        if let Some(commit_metadata) =
            Self::get_canonical_anchor_block_commit_metadata(conn, indexer, reward_cycle)?
        {
            let commit = BurnchainDB::get_block_commit(
                conn,
                &commit_metadata.burn_block_hash,
                &commit_metadata.txid,
            )?
            .expect("BUG: no block-commit for block-commit metadata");

            Ok(Some((commit, commit_metadata)))
        } else {
            Ok(None)
        }
    }
}
// Segment 6: Affirmation and Commit Metadata Handling

impl BurnchainDB {
    /// Retrieve an affirmation map from the database by its ID.
    pub fn get_affirmation_map(
        conn: &DBConn,
        affirmation_id: u64,
    ) -> Result<Option<AffirmationMap>, DBError> {
        let sql = "SELECT affirmation_map FROM affirmation_maps WHERE affirmation_id = ?1";
        let args = params![&u64_to_sql(affirmation_id)?];
        query_row(conn, sql, args)
    }

    /// Retrieve the weight of an affirmation map from the database by its ID.
    pub fn get_affirmation_weight(
        conn: &DBConn,
        affirmation_id: u64,
    ) -> Result<Option<u64>, DBError> {
        let sql = "SELECT weight FROM affirmation_maps WHERE affirmation_id = ?1";
        let args = params![&u64_to_sql(affirmation_id)?];
        query_row(conn, sql, args)
    }

    /// Get the ID of an affirmation map from the database.
    pub fn get_affirmation_map_id(
        conn: &DBConn,
        affirmation_map: &AffirmationMap,
    ) -> Result<Option<u64>, DBError> {
        let sql = "SELECT affirmation_id FROM affirmation_maps WHERE affirmation_map = ?1";
        let args = params![&affirmation_map.encode()];
        query_row(conn, sql, args)
    }

    /// Retrieve a block commit affirmation ID based on a burn header hash and transaction ID.
    pub fn get_affirmation_map_id_at(
        conn: &DBConn,
        burn_header_hash: &BurnchainHeaderHash,
        txid: &Txid,
    ) -> Result<Option<u64>, DBError> {
        let sql = "SELECT affirmation_id FROM block_commit_metadata WHERE burn_block_hash = ?1 AND txid = ?2";
        let args = params![burn_header_hash, txid];
        query_row(conn, sql, args)
    }

    /// Retrieve the affirmation map ID for a specific block commit.
    pub fn get_block_commit_affirmation_id(
        conn: &DBConn,
        block_commit: &LeaderBlockCommitOp,
    ) -> Result<Option<u64>, DBError> {
        BurnchainDB::get_affirmation_map_id_at(
            conn,
            &block_commit.burn_header_hash,
            &block_commit.txid,
        )
    }

    /// Check if a block commit is an anchor block based on burn header hash and transaction ID.
    pub fn is_anchor_block(
        conn: &DBConn,
        burn_header_hash: &BurnchainHeaderHash,
        txid: &Txid,
    ) -> Result<bool, DBError> {
        let sql = "SELECT 1 FROM block_commit_metadata WHERE anchor_block IS NOT NULL AND burn_block_hash = ?1 AND txid = ?2";
        let args = params![burn_header_hash, txid];
        query_row(conn, sql, args)?.ok_or(DBError::NotFoundError)
    }

    /// Check if a reward cycle has an anchor block.
    pub fn has_anchor_block(conn: &DBConn, reward_cycle: u64) -> Result<bool, DBError> {
        let sql = "SELECT 1 FROM block_commit_metadata WHERE anchor_block = ?1";
        let args = params![u64_to_sql(reward_cycle)?];
        Ok(query_row::<bool, _>(conn, sql, args)?.is_some())
    }

    /// Retrieve metadata for anchor block commits in a given reward cycle.
    pub fn get_anchor_block_commit_metadatas(
        conn: &DBConn,
        reward_cycle: u64,
    ) -> Result<Vec<BlockCommitMetadata>, DBError> {
        let sql = "SELECT * FROM block_commit_metadata WHERE anchor_block = ?1";
        let args = params![u64_to_sql(reward_cycle)?];

        let metadatas: Vec<BlockCommitMetadata> = query_rows(conn, sql, args)?;
        Ok(metadatas)
    }

    /// Retrieve metadata for the canonical anchor block commit in a reward cycle.
    pub fn get_canonical_anchor_block_commit_metadata<B: BurnchainHeaderReader>(
        conn: &DBConn,
        indexer: &B,
        reward_cycle: u64,
    ) -> Result<Option<BlockCommitMetadata>, DBError> {
        let sql = "SELECT * FROM block_commit_metadata WHERE anchor_block = ?1";
        let args = params![u64_to_sql(reward_cycle)?];

        let metadatas: Vec<BlockCommitMetadata> = query_rows(conn, sql, args)?;
        for metadata in metadatas {
            if let Some(header) = indexer.read_burnchain_header(metadata.block_height)? {
                if header.block_hash == metadata.burn_block_hash {
                    return Ok(Some(metadata));
                }
            }
        }
        Ok(None)
    }

    /// Retrieve the canonical block commit and its metadata for a reward cycle.
    pub fn get_canonical_anchor_block_commit<B: BurnchainHeaderReader>(
        conn: &DBConn,
        indexer: &B,
        reward_cycle: u64,
    ) -> Result<Option<(LeaderBlockCommitOp, BlockCommitMetadata)>, DBError> {
        if let Some(commit_metadata) =
            Self::get_canonical_anchor_block_commit_metadata(conn, indexer, reward_cycle)?
        {
            let commit = BurnchainDB::get_block_commit(
                conn,
                &commit_metadata.burn_block_hash,
                &commit_metadata.txid,
            )?
            .expect("BUG: no block-commit for block-commit metadata");

            Ok(Some((commit, commit_metadata)))
        } else {
            Ok(None)
        }
    }

    /// Retrieve a specific block commit and its metadata for an anchor block.
    pub fn get_anchor_block_commit(
        conn: &DBConn,
        anchor_block_burn_header_hash: &BurnchainHeaderHash,
        reward_cycle: u64,
    ) -> Result<Option<(LeaderBlockCommitOp, BlockCommitMetadata)>, DBError> {
        let sql =
            "SELECT * FROM block_commit_metadata WHERE anchor_block = ?1 AND burn_block_hash = ?2";
        let args = params![u64_to_sql(reward_cycle)?, anchor_block_burn_header_hash];
        if let Some(commit_metadata) = query_row::<BlockCommitMetadata, _>(conn, sql, args)? {
            let commit = BurnchainDB::get_block_commit(
                conn,
                &commit_metadata.burn_block_hash,
                &commit_metadata.txid,
            )?
            .expect("BUG: no block-commit for block-commit metadata");

            Ok(Some((commit, commit_metadata)))
        } else {
            Ok(None)
        }
    }
}
// Segment 7: Burnchain Transaction and Commit Handling

impl BurnchainDB {
    /// Retrieve a block commit from the database using its burn header hash and transaction ID.
    pub fn get_block_commit(
        conn: &DBConn,
        burn_header_hash: &BurnchainHeaderHash,
        txid: &Txid,
    ) -> Result<Option<LeaderBlockCommitOp>, DBError> {
        let op = BurnchainDB::inner_get_burnchain_op(conn, burn_header_hash, txid);
        if let Some(BlockstackOperationType::LeaderBlockCommit(opdata)) = op {
            Ok(Some(opdata))
        } else {
            debug!("No block-commit transaction found for {}", txid);
            Ok(None)
        }
    }

    /// Retrieve a block commit from a specific block at a given position.
    pub fn get_commit_in_block_at(
        conn: &DBConn,
        header_hash: &BurnchainHeaderHash,
        block_ptr: u32,
        vtxindex: u16,
    ) -> Result<Option<LeaderBlockCommitOp>, DBError> {
        let qry = "SELECT txid FROM block_commit_metadata WHERE block_height = ?1 AND vtxindex = ?2 AND burn_block_hash = ?3";
        let args = params![block_ptr, vtxindex, header_hash];
        if let Some(txid) = query_row::<String, _>(conn, qry, args)? {
            BurnchainDB::get_block_commit(conn, header_hash, &txid)
        } else {
            debug!(
                "No block-commit metadata found at block {} with height {} and index {}",
                header_hash, block_ptr, vtxindex
            );
            Ok(None)
        }
    }

    /// Retrieve a block commit based on its parent block and transaction index.
    pub fn get_commit_at<B: BurnchainHeaderReader>(
        conn: &DBConn,
        indexer: &B,
        block_ptr: u32,
        vtxindex: u16,
    ) -> Result<Option<LeaderBlockCommitOp>, DBError> {
        if let Some(header_hash) = indexer.read_burnchain_header(block_ptr as u64)?.map(|hdr| hdr.block_hash) {
            BurnchainDB::get_commit_in_block_at(conn, &header_hash, block_ptr, vtxindex)
        } else {
            debug!("No burnchain headers found at height {}", block_ptr);
            Ok(None)
        }
    }

    /// Retrieve metadata for a specific block commit from the database.
    pub fn get_commit_metadata(
        conn: &DBConn,
        burn_block_hash: &BurnchainHeaderHash,
        txid: &Txid,
    ) -> Result<Option<BlockCommitMetadata>, DBError> {
        let sql = "SELECT * FROM block_commit_metadata WHERE burn_block_hash = ?1 AND txid = ?2";
        let args = params![burn_block_hash, txid];
        query_row(conn, sql, args)
    }

    /// Retrieve the block commit and metadata for the heaviest anchor block.
    pub fn get_heaviest_anchor_block<B: BurnchainHeaderReader>(
        conn: &DBConn,
        indexer: &B,
    ) -> Result<Option<(LeaderBlockCommitOp, BlockCommitMetadata)>, DBError> {
        let sql = "SELECT block_commit_metadata.* \
                   FROM affirmation_maps \
                   JOIN block_commit_metadata ON affirmation_maps.affirmation_id = block_commit_metadata.affirmation_id \
                   WHERE block_commit_metadata.anchor_block IS NOT NULL \
                   ORDER BY affirmation_maps.weight DESC, block_commit_metadata.anchor_block DESC";

        let mut stmt = conn.prepare(sql)?;
        let mut rows = stmt.query(NO_PARAMS)?;

        while let Some(row) = rows.next()? {
            let metadata = BlockCommitMetadata::from_row(row)?;
            if let Some(block_header) = indexer.read_burnchain_header(metadata.block_height)? {
                if block_header.block_hash == metadata.burn_block_hash {
                    let commit = BurnchainDB::get_block_commit(conn, &metadata.burn_block_hash, &metadata.txid)?
                        .expect("BUG: no block commit for existing metadata");
                    return Ok(Some((commit, metadata)));
                }
            }
        }
        Ok(None)
    }

    /// Retrieve the affirmation map of the heaviest anchor block.
    pub fn get_heaviest_anchor_block_affirmation_map<B: BurnchainHeaderReader>(
        conn: &DBConn,
        burnchain: &Burnchain,
        indexer: &B,
    ) -> Result<AffirmationMap, DBError> {
        if let Some((_, metadata)) = BurnchainDB::get_heaviest_anchor_block(conn, indexer)? {
            let last_reward_cycle = burnchain
                .block_height_to_reward_cycle(metadata.block_height)
                .unwrap_or(0)
                + 1;

            if let Some(am) = BurnchainDB::get_override_affirmation_map(conn, last_reward_cycle)? {
                warn!(
                    "Overriding heaviest affirmation map for reward cycle {} to {:?}",
                    last_reward_cycle, am
                );
                return Ok(am);
            }

            let am = BurnchainDB::get_affirmation_map(conn, metadata.affirmation_id)?.unwrap_or_else(|| {
                panic!(
                    "BUG: failed to load affirmation map {}",
                    metadata.affirmation_id
                )
            });

            debug!(
                "Heaviest anchor block affirmation map for reward cycle {} is {:?}",
                last_reward_cycle, am
            );
            Ok(am)
        } else {
            debug!("No anchor block affirmation maps found");
            Ok(AffirmationMap::empty())
        }
    }
}
// Segment 8 - Continuation of adapting BurnchainDB functionality

impl BurnchainDB {
    /// Retrieve an overridden affirmation map for a specific reward cycle.
    /// This function handles cases where an emergency override of affirmation status is required.
    pub fn get_override_affirmation_map(
        conn: &DBConn,
        reward_cycle: u64,
    ) -> Result<Option<AffirmationMap>, DBError> {
        let sql = "SELECT affirmation_map FROM overrides WHERE reward_cycle = ?1";
        let args = params![u64_to_sql(reward_cycle)?];

        query_row(conn, sql, args)
            .map_err(|e| {
                debug!("Failed to retrieve override affirmation map: {:?}", e);
                DBError::from(e)
            })
            .and_then(|opt| {
                if let Some(map) = &opt {
                    assert_eq!((map.len() as u64) + 1, reward_cycle);
                }
                Ok(opt)
            })
    }

    /// Get the canonical affirmation map for the current state.
    /// This function merges the heaviest anchor block map with additional cycles.
    pub fn get_canonical_affirmation_map<B, F>(
        conn: &DBConn,
        burnchain: &Burnchain,
        indexer: &B,
        mut unconfirmed_oracle: F,
    ) -> Result<AffirmationMap, DBError>
    where
        B: BurnchainHeaderReader,
        F: FnMut(LeaderBlockCommitOp, BlockCommitMetadata) -> bool,
    {
        let canonical_tip = BurnchainDB::inner_get_canonical_chain_tip(conn)
            .map_err(|e| DBError::Other(format!("Burnchain error: {:?}", e)))?;

        let last_reward_cycle = burnchain
            .block_height_to_reward_cycle(canonical_tip.block_height)
            .unwrap_or(0)
            + 1;

        if let Some(am) = BurnchainDB::get_override_affirmation_map(conn, last_reward_cycle)? {
            warn!(
                "Overriding heaviest affirmation map for reward cycle {}: {}",
                last_reward_cycle, am
            );
            return Ok(am);
        }

        let mut heaviest_am = BurnchainDB::get_heaviest_anchor_block_affirmation_map(
            conn, burnchain, indexer,
        )?;

        let start_rc = (heaviest_am.len() as u64) + 1;

        for rc in start_rc..last_reward_cycle {
            if let Some(metadata) =
                BurnchainDB::get_canonical_anchor_block_commit_metadata(conn, indexer, rc)?
            {
                let commit = BurnchainDB::get_block_commit(
                    conn,
                    &metadata.burn_block_hash,
                    &metadata.txid,
                )?
                .expect("Block commit exists for metadata");
                if unconfirmed_oracle(commit, metadata) {
                    heaviest_am.push(AffirmationMapEntry::AnchorBlockPresent);
                } else {
                    heaviest_am.push(AffirmationMapEntry::AnchorBlockAbsent);
                }
            } else {
                heaviest_am.push(AffirmationMapEntry::Nothing);
            }
        }

        Ok(heaviest_am)
    }

    /// Store new burnchain block operations.
    /// This is a low-level method for updating the database with block-specific data.
    pub fn store_new_burnchain_block_ops_unchecked<B: BurnchainHeaderReader>(
        &mut self,
        burnchain: &Burnchain,
        indexer: &B,
        block_header: &BurnchainBlockHeader,
        blockstack_ops: &[BlockstackOperationType],
    ) -> Result<(), BurnchainError> {
        let db_tx = self.tx_begin()?;
        db_tx.store_burnchain_db_entry(block_header)?;
        db_tx.store_blockstack_ops(burnchain, indexer, block_header, blockstack_ops)?;
        db_tx.commit()?;
        Ok(())
    }

    /// Store and validate a newly parsed burnchain block.
    pub fn store_new_burnchain_block<B: BurnchainHeaderReader>(
        &mut self,
        burnchain: &Burnchain,
        indexer: &B,
        block: &BurnchainBlock,
        epoch_id: ZookEpochId,
    ) -> Result<Vec<BlockstackOperationType>, BurnchainError> {
        let header = block.header();
        let mut blockstack_ops = self.get_blockstack_transactions(
            burnchain, indexer, block, &header, epoch_id,
        );
        apply_blockstack_txs_safety_checks(header.block_height, &mut blockstack_ops);
        self.store_new_burnchain_block_ops_unchecked(burnchain, indexer, &header, &blockstack_ops)?;
        Ok(blockstack_ops)
    }
}
// Segment 9 - Continue adapting BurnchainDB with a focus on Zook network logic

impl BurnchainDB {
    /// Retrieve a block commit operation by its burn header hash and transaction ID.
    pub fn get_block_commit(
        conn: &DBConn,
        burn_header_hash: &BurnchainHeaderHash,
        txid: &Txid,
    ) -> Result<Option<LeaderBlockCommitOp>, DBError> {
        let op = BurnchainDB::inner_get_burnchain_op(conn, burn_header_hash, txid);
        if let Some(BlockstackOperationType::LeaderBlockCommit(opdata)) = op {
            Ok(Some(opdata))
        } else {
            debug!("No block commit found for txid: {}", txid);
            Ok(None)
        }
    }

    /// Retrieve a block commit operation from a specified block at a given pointer and index.
    pub fn get_commit_in_block_at(
        conn: &DBConn,
        header_hash: &BurnchainHeaderHash,
        block_ptr: u32,
        vtxindex: u16,
    ) -> Result<Option<LeaderBlockCommitOp>, DBError> {
        let sql = "SELECT txid FROM block_commit_metadata WHERE block_height = ?1 AND vtxindex = ?2 AND burn_block_hash = ?3";
        let args = params![block_ptr, vtxindex, header_hash];
        
        let txid = match query_row(&conn, sql, args) {
            Ok(Some(txid)) => txid,
            Ok(None) => {
                debug!(
                    "No block commit metadata found for block {}, pointer {}, index {}",
                    header_hash, block_ptr, vtxindex
                );
                return Ok(None);
            }
            Err(e) => {
                warn!(
                    "Error retrieving block commit metadata: {:?}, at block {}, pointer {}, index {}",
                    e, header_hash, block_ptr, vtxindex
                );
                return Err(DBError::SqliteError(e));
            }
        };

        BurnchainDB::get_block_commit(conn, header_hash, &txid)
    }

    /// Retrieve a block commit operation using the block pointer and index.
    pub fn get_commit_at<B: BurnchainHeaderReader>(
        conn: &DBConn,
        indexer: &B,
        block_ptr: u32,
        vtxindex: u16,
    ) -> Result<Option<LeaderBlockCommitOp>, DBError> {
        let header_hash = match indexer.read_burnchain_header(block_ptr as u64)? {
            Some(hdr) => hdr.block_hash,
            None => {
                debug!("No headers found at height {}", block_ptr);
                return Ok(None);
            }
        };

        BurnchainDB::get_commit_in_block_at(conn, &header_hash, block_ptr, vtxindex)
    }

    /// Retrieve metadata associated with a block commit operation.
    pub fn get_commit_metadata(
        conn: &DBConn,
        burn_block_hash: &BurnchainHeaderHash,
        txid: &Txid,
    ) -> Result<Option<BlockCommitMetadata>, DBError> {
        let sql = "SELECT * FROM block_commit_metadata WHERE burn_block_hash = ?1 AND txid = ?2";
        let args = params![burn_block_hash, txid];

        query_row(conn, sql, args).map_err(|e| {
            debug!(
                "Failed to retrieve block commit metadata for hash {} and txid {}: {:?}",
                burn_block_hash, txid, e
            );
            e
        })
    }

    /// Retrieve the heaviest anchor block based on affirmation map weight.
    pub fn get_heaviest_anchor_block<B: BurnchainHeaderReader>(
        conn: &DBConn,
        indexer: &B,
    ) -> Result<Option<(LeaderBlockCommitOp, BlockCommitMetadata)>, DBError> {
        let sql = "SELECT block_commit_metadata.* \
                   FROM affirmation_maps \
                   JOIN block_commit_metadata \
                   ON affirmation_maps.affirmation_id = block_commit_metadata.affirmation_id \
                   WHERE block_commit_metadata.anchor_block IS NOT NULL \
                   ORDER BY affirmation_maps.weight DESC, block_commit_metadata.anchor_block DESC";

        let mut stmt = conn.prepare(sql)?;
        let mut rows = stmt.query(NO_PARAMS)?;

        while let Some(row) = rows.next()? {
            let metadata = BlockCommitMetadata::from_row(row)?;

            if let Some(block_header) = indexer.read_burnchain_header(metadata.block_height)? {
                if block_header.block_hash == metadata.burn_block_hash {
                    let commit = BurnchainDB::get_block_commit(
                        conn,
                        &metadata.burn_block_hash,
                        &metadata.txid,
                    )?
                    .expect("BUG: Block commit metadata exists but commit is missing");
                    return Ok(Some((commit, metadata)));
                }
            }
        }

        debug!("No heaviest anchor block found");
        Ok(None)
    }
}
// Segment 10 - Continuing adaptation of BurnchainDB functionality

impl BurnchainDB {
    /// Retrieve the metadata for a specific block commit.
    pub fn get_commit_metadata(
        conn: &DBConn,
        burn_block_hash: &BurnchainHeaderHash,
        txid: &Txid,
    ) -> Result<Option<BlockCommitMetadata>, DBError> {
        let sql = "SELECT * FROM block_commit_metadata WHERE burn_block_hash = ?1 AND txid = ?2";
        let args = params![burn_block_hash, txid];

        query_row(conn, sql, args)
    }

    /// Retrieve the heaviest anchor block from the database.
    /// The heaviest block is determined by the weight of its affirmation map.
    pub fn get_heaviest_anchor_block<B: BurnchainHeaderReader>(
        conn: &DBConn,
        indexer: &B,
    ) -> Result<Option<(LeaderBlockCommitOp, BlockCommitMetadata)>, DBError> {
        let sql = "SELECT block_commit_metadata.* \
                   FROM affirmation_maps \
                   JOIN block_commit_metadata \
                   ON affirmation_maps.affirmation_id = block_commit_metadata.affirmation_id \
                   WHERE block_commit_metadata.anchor_block IS NOT NULL \
                   ORDER BY affirmation_maps.weight DESC, block_commit_metadata.anchor_block DESC";

        let mut stmt = conn.prepare(sql)?;
        let mut rows = stmt.query(NO_PARAMS)?;
        while let Some(row) = rows.next()? {
            let metadata = BlockCommitMetadata::from_row(row)?;

            if let Some(header) = indexer.read_burnchain_header(metadata.block_height)? {
                if header.block_hash != metadata.burn_block_hash {
                    continue;
                }

                let commit = BurnchainDB::get_block_commit(
                    conn,
                    &metadata.burn_block_hash,
                    &metadata.txid,
                )?
                .expect("Block commit should exist for metadata");
                return Ok(Some((commit, metadata)));
            }
        }

        Ok(None)
    }

    /// Find the affirmation map of the heaviest anchor block.
    pub fn get_heaviest_anchor_block_affirmation_map<B: BurnchainHeaderReader>(
        conn: &DBConn,
        burnchain: &Burnchain,
        indexer: &B,
    ) -> Result<AffirmationMap, DBError> {
        match BurnchainDB::get_heaviest_anchor_block(conn, indexer)? {
            Some((_, metadata)) => {
                let affirmation_map = BurnchainDB::get_affirmation_map(
                    conn,
                    metadata.affirmation_id,
                )?
                .expect("Affirmation map should exist for metadata");

                Ok(affirmation_map)
            }
            None => Ok(AffirmationMap::empty()),
        }
    }

    /// Store a newly parsed burnchain block and update the database.
    pub fn store_burnchain_block<B: BurnchainHeaderReader>(
        &mut self,
        burnchain: &Burnchain,
        indexer: &B,
        block: &BurnchainBlock,
        epoch_id: ZookEpochId,
    ) -> Result<Vec<BlockstackOperationType>, BurnchainError> {
        let header = block.header();
        let mut blockstack_ops = self.get_blockstack_transactions(
            burnchain, indexer, block, &header, epoch_id,
        );

        apply_blockstack_txs_safety_checks(header.block_height, &mut blockstack_ops);

        self.store_new_burnchain_block_ops_unchecked(
            burnchain,
            indexer,
            &header,
            &blockstack_ops,
        )?;

        Ok(blockstack_ops)
    }

    /// Get the block commit for a specific burnchain header hash and transaction ID.
    pub fn get_block_commit(
        conn: &DBConn,
        burn_header_hash: &BurnchainHeaderHash,
        txid: &Txid,
    ) -> Result<Option<LeaderBlockCommitOp>, DBError> {
        let sql = "SELECT DISTINCT op FROM burnchain_db_block_ops WHERE txid = ?1 AND block_hash = ?2";
        let args = params![txid, burn_header_hash];

        match query_row(conn, sql, args)? {
            Some(BlockstackOperationType::LeaderBlockCommit(opdata)) => Ok(Some(opdata)),
            _ => Ok(None),
        }
    }

    /// Insert a block commit metadata into the database.
    pub fn insert_block_commit_metadata(
        conn: &DBConn,
        metadata: BlockCommitMetadata,
    ) -> Result<(), DBError> {
        let sql = "INSERT OR REPLACE INTO block_commit_metadata \
                   (burn_block_hash, txid, block_height, vtxindex, affirmation_id, anchor_block, anchor_block_descendant) \
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
        let args = params![
            metadata.burn_block_hash,
            metadata.txid,
            u64_to_sql(metadata.block_height)?,
            metadata.vtxindex,
            opt_u64_to_sql(metadata.affirmation_id)?,
            opt_u64_to_sql(metadata.anchor_block)?,
            opt_u64_to_sql(metadata.anchor_block_descendant)?,
        ];

        conn.execute(sql, args)?;
        Ok(())
    }
}
// Segment 11: Continue adapting the remaining portion of the file to Zook's requirements.

impl BurnchainDB {
    /// Fetch the heaviest affirmation map in the context of ZBTCZ.
    pub fn get_heaviest_affirmation_map(&self, reward_cycle: u64) -> Result<AffirmationMap, Error> {
        debug!("Fetching heaviest affirmation map for reward cycle {}", reward_cycle);
        let tx = self.conn.transaction()?;

        // Fetch all affirmation maps associated with this reward cycle.
        let sql = "SELECT affirmation_map FROM affirmation_maps ORDER BY weight DESC LIMIT 1";
        let args = params![u64_to_sql(reward_cycle)?];
        let map_opt: Option<AffirmationMap> = query_row(&tx, sql, args)?;

        if let Some(map) = map_opt {
            debug!("Heaviest affirmation map found: {:?}", map);
            Ok(map)
        } else {
            debug!("No affirmation map found for reward cycle {}", reward_cycle);
            Ok(AffirmationMap::empty())
        }
    }

    /// Validate and update the affirmation map for the given burnchain context.
    pub fn update_affirmation_maps(
        &self,
        reward_cycle: u64,
        block_commit: &LeaderBlockCommitOp,
    ) -> Result<(), Error> {
        debug!(
            "Updating affirmation maps for block_commit {:?} in reward cycle {}",
            block_commit, reward_cycle
        );

        let tx = self.conn.transaction()?;

        let map = self.get_heaviest_affirmation_map(reward_cycle)?;
        debug!("Using affirmation map {:?} to update", map);

        let new_map = AffirmationMap::from_existing_with_updates(&map, block_commit);
        let sql = "INSERT OR REPLACE INTO affirmation_maps (affirmation_map, weight) VALUES (?, ?)";
        let args = params![new_map.encode(), new_map.weight()];

        tx.execute(sql, args)?;

        tx.commit()?;

        debug!("Affirmation maps updated successfully for reward cycle {}", reward_cycle);
        Ok(())
    }

    /// Handles scenarios where the operator may override the affirmation map in emergencies.
    pub fn set_override_map(&self, reward_cycle: u64, override_map: AffirmationMap) -> Result<(), Error> {
        debug!("Setting override affirmation map for reward cycle {}", reward_cycle);

        let tx = self.conn.transaction()?;
        let sql = "INSERT OR REPLACE INTO overrides (reward_cycle, affirmation_map) VALUES (?, ?)";
        let args = params![u64_to_sql(reward_cycle)?, override_map.encode()];

        tx.execute(sql, args)?;
        tx.commit()?;

        debug!("Override affirmation map set for reward cycle {}", reward_cycle);
        Ok(())
    }

    /// Retrieves the overridden affirmation map for a specific reward cycle.
    pub fn get_override_map(&self, reward_cycle: u64) -> Result<Option<AffirmationMap>, Error> {
        debug!("Fetching override affirmation map for reward cycle {}", reward_cycle);

        let sql = "SELECT affirmation_map FROM overrides WHERE reward_cycle = ?";
        let args = params![u64_to_sql(reward_cycle)?];

        let override_map: Option<AffirmationMap> = query_row(&self.conn, sql, args)?;

        if let Some(map) = override_map {
            debug!("Override map found: {:?}", map);
            Ok(Some(map))
        } else {
            debug!("No override map found for reward cycle {}", reward_cycle);
            Ok(None)
        }
    }

    /// Clear the override map for a reward cycle if no longer needed.
    pub fn clear_override_map(&self, reward_cycle: u64) -> Result<(), Error> {
        debug!("Clearing override map for reward cycle {}", reward_cycle);

        let tx = self.conn.transaction()?;
        let sql = "DELETE FROM overrides WHERE reward_cycle = ?";
        let args = params![u64_to_sql(reward_cycle)?];

        tx.execute(sql, args)?;
        tx.commit()?;

        debug!("Override map cleared for reward cycle {}", reward_cycle);
        Ok(())
    }
}
// Segment 12: Finalizing the adaptation for Zook Network.

impl BurnchainDB {
    /// Retrieve the canonical affirmation map, considering overrides and ZBTCZ criteria.
    pub fn get_canonical_affirmation_map<F, B>(
        conn: &DBConn,
        burnchain: &Burnchain,
        indexer: &B,
        mut unconfirmed_oracle: F,
    ) -> Result<AffirmationMap, Error>
    where
        B: BurnchainHeaderReader,
        F: FnMut(LeaderBlockCommitOp, BlockCommitMetadata) -> bool,
    {
        let canonical_tip = Self::inner_get_canonical_chain_tip(conn)?;
        let last_reward_cycle = burnchain
            .block_height_to_reward_cycle(canonical_tip.block_height)
            .unwrap_or(0)
            + 1;

        if let Some(override_map) = Self::get_override_affirmation_map(conn, last_reward_cycle)? {
            warn!(
                "Using override affirmation map for reward cycle {}: {:?}",
                last_reward_cycle, override_map
            );
            return Ok(override_map);
        }

        let mut heaviest_map = Self::get_heaviest_anchor_block_affirmation_map(
            conn,
            burnchain,
            indexer,
        )?;
        let start_rc = (heaviest_map.len() as u64) + 1;

        for rc in start_rc..last_reward_cycle {
            if let Some(metadata) = Self::get_canonical_anchor_block_commit_metadata(conn, indexer, rc)? {
                let present = unconfirmed_oracle(
                    Self::get_block_commit(conn, &metadata.burn_block_hash, &metadata.txid)?
                        .expect("Metadata without block commit"),
                    metadata,
                );
                heaviest_map.push(if present {
                    AffirmationMapEntry::AnchorBlockPresent
                } else {
                    AffirmationMapEntry::AnchorBlockAbsent
                });
            } else {
                heaviest_map.push(AffirmationMapEntry::Nothing);
            }
        }

        Ok(heaviest_map)
    }

    /// Finalize affirmation map updates for a given block commit.
    pub fn finalize_affirmation_map(&self, 
        burnchain: &Burnchain,
        block_commit: &LeaderBlockCommitOp,
    ) -> Result<(), Error> {
        let tx = self.conn.transaction()?;

        let metadata = Self::get_commit_metadata(&tx, &block_commit.burn_header_hash, &block_commit.txid)?
            .expect("Missing metadata for block commit");

        let parent_affirmation_map = if let Some(parent_metadata) = metadata.anchor_block_descendant {
            let affirmation_id = parent_metadata.affirmation_id;
            Self::get_affirmation_map(&tx, affirmation_id)?
                .expect("Missing parent affirmation map")
        } else {
            AffirmationMap::empty()
        };

        let new_map = AffirmationMap::from_existing_with_updates(&parent_affirmation_map, block_commit);

        let sql = "INSERT INTO affirmation_maps (affirmation_map, weight) VALUES (?, ?)";
        let args = params![new_map.encode(), new_map.weight()];
        tx.execute(sql, args)?;
        tx.commit()?;

        Ok(())
    }
}
// Segment 13: Finalizing adaptations and validating for Zook Network.

impl BurnchainDB {
    /// Retrieve the canonical affirmation map, considering all overrides and adjustments.
    pub fn get_canonical_affirmation_map(&self, reward_cycle: u64) -> Result<AffirmationMap, Error> {
        debug!(
            "Retrieving canonical affirmation map for reward cycle {}",
            reward_cycle
        );

        let override_map = self.get_override_map(reward_cycle)?;
        if let Some(map) = override_map {
            debug!("Using overridden affirmation map: {:?}", map);
            return Ok(map);
        }

        let heaviest_map = self.get_heaviest_affirmation_map(reward_cycle)?;
        debug!("Heaviest affirmation map retrieved: {:?}", heaviest_map);
        Ok(heaviest_map)
    }

    /// Add indexes to the burnchain database if they are missing.
    pub fn ensure_indexes(&self) -> Result<(), Error> {
        debug!("Ensuring necessary indexes exist in the database");

        let tx = self.conn.transaction()?;
        for index in ZBTCZ_BURNCHAIN_DB_INDEXES.iter() {
            debug!("Executing index statement: {}", index);
            tx.execute_batch(index)?;
        }

        tx.commit()?;
        debug!("Indexes ensured");
        Ok(())
    }

    /// Handles an emergency override of the canonical chain state.
    pub fn handle_emergency_override(
        &self,
        reward_cycle: u64,
        override_map: AffirmationMap,
    ) -> Result<(), Error> {
        debug!("Handling emergency override for reward cycle {}", reward_cycle);

        self.set_override_map(reward_cycle, override_map)?;
        debug!("Emergency override handled successfully");

        Ok(())
    }

    /// Retrieves the current chain tip of the burnchain database.
    pub fn get_current_chain_tip(&self) -> Result<BurnchainBlockHeader, Error> {
        debug!("Fetching the current chain tip of the burnchain database");
        self.get_canonical_chain_tip()
    }

    /// Perform consistency checks on the database.
    pub fn perform_consistency_checks(&self) -> Result<(), Error> {
        debug!("Performing consistency checks on the burnchain database");

        // Ensure the schema is consistent
        let schema_version = self.get_schema_version()?;
        if schema_version != ZBTCZ_BURNCHAIN_DB_VERSION {
            return Err(Error::DBError(DBError::SchemaMismatch));
        }

        // Ensure indexes exist
        self.ensure_indexes()?;

        debug!("Consistency checks completed successfully");
        Ok(())
    }

    /// Fetch the schema version from the database.
    pub fn get_schema_version(&self) -> Result<String, Error> {
        debug!("Fetching schema version from the database");

        let sql = "SELECT version FROM db_config LIMIT 1";
        let schema_version: Option<String> = query_row(&self.conn, sql, NO_PARAMS)?;

        schema_version.ok_or(Error::DBError(DBError::NotFoundError))
    }

    /// Initialize the database for the Zook Network burnchain.
    pub fn initialize_database(&self, burnchain: &Burnchain) -> Result<(), Error> {
        debug!("Initializing database for the Zook Network burnchain");

        let tx = self.conn.transaction()?;
        tx.execute_batch(ZBTCZ_BURNCHAIN_DB_SCHEMA)?;

        tx.execute(
            "INSERT INTO db_config (version) VALUES (?1)",
            params![ZBTCZ_BURNCHAIN_DB_VERSION],
        )?;

        let first_block_header = BurnchainBlockHeader {
            block_height: burnchain.first_block_height,
            block_hash: burnchain.first_block_hash.clone(),
            timestamp: burnchain.first_block_timestamp,
            num_txs: 0,
            parent_block_hash: BurnchainHeaderHash::sentinel(),
        };

        tx.execute(
            "INSERT INTO burnchain_db_block_headers (block_height, block_hash, parent_block_hash, num_txs, timestamp) VALUES (?, ?, ?, ?, ?)",
            params![
                first_block_header.block_height,
                first_block_header.block_hash,
                first_block_header.parent_block_hash,
                first_block_header.num_txs,
                first_block_header.timestamp
            ],
        )?;

        tx.commit()?;
        debug!("Database initialized successfully for the Zook Network");
        Ok(())
    }
}
