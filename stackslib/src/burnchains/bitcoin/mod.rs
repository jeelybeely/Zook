// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

// This module is concerned with the implementation of the BitcoinZIndexer
// structure and its methods and traits.

use std::sync::Arc;
use std::{error, fmt, io};

use zook_common::deps_common::bitcoinz::network::serialize::Error as bitcoinz_serialize_error;
use zook_common::types::chainstate::BurnchainHeaderHash;
use zook_common::util::HexError as bitcoinz_hex_error;

use crate::burnchains::bitcoinz::address::BitcoinZAddress;
use crate::burnchains::bitcoinz::keys::BitcoinZPublicKey;
use crate::burnchains::Txid;
use crate::chainstate::burn::operations::ZookOperationType;
use crate::deps;
use crate::util_lib::db::Error as db_error;

pub mod address;
pub mod bits;
pub mod blocks;
pub mod indexer;
pub mod keys;
pub mod messages;
pub mod network;
pub mod spv;

pub type PeerMessage = zook_common::deps_common::bitcoinz::network::message::NetworkMessage;

// Borrowed from Andrew Poelstra's rust-bitcoin

/// Network error
#[derive(Debug)]
pub enum Error {
    /// I/O error
    Io(io::Error),
    /// Not connected to peer
    SocketNotConnectedToPeer,
    /// Serialization error
    SerializationError(bitcoinz_serialize_error),
    /// Invalid Message to peer
    InvalidMessage(PeerMessage),
    /// Invalid Reply from peer
    InvalidReply,
    /// Invalid magic
    InvalidMagic,
    /// Unhandled message
    UnhandledMessage(PeerMessage),
    /// Connection is broken and ought to be re-established
    ConnectionBroken,
    /// Connection could not be (re-)established
    ConnectionError,
    /// general filesystem error
    FilesystemError(io::Error),
    /// Database error
    DBError(db_error),
    /// Hashing error
    HashError(bitcoinz_hex_error),
    /// Non-contiguous header
    NoncontiguousHeader,
    /// Missing header
    MissingHeader,
    /// Invalid header proof-of-work (i.e. due to a bad timestamp or a bad `bits` field)
    InvalidPoW,
    /// Chainwork would decrease by including a given header
    InvalidChainWork,
    /// Wrong number of bytes for constructing an address
    InvalidByteSequence,
    /// Configuration error
    ConfigError(String),
    /// Tried to synchronize to a point above the chain tip
    BlockchainHeight,
    /// Request timed out
    TimedOut,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref e) => fmt::Display::fmt(e, f),
            Error::SocketNotConnectedToPeer => write!(f, "not connected to peer"),
            Error::SerializationError(ref e) => fmt::Display::fmt(e, f),
            Error::InvalidMessage(ref _msg) => write!(f, "Invalid message to send"),
            Error::InvalidReply => write!(f, "invalid reply for given message"),
            Error::InvalidMagic => write!(f, "invalid network magic"),
            Error::UnhandledMessage(ref _msg) => write!(f, "Unhandled message"),
            Error::ConnectionBroken => write!(f, "connection to peer node is broken"),
            Error::ConnectionError => write!(f, "connection to peer could not be (re-)established"),
            Error::FilesystemError(ref e) => fmt::Display::fmt(e, f),
            Error::DBError(ref e) => fmt::Display::fmt(e, f),
            Error::HashError(ref e) => fmt::Display::fmt(e, f),
            Error::NoncontiguousHeader => write!(f, "Non-contiguous header"),
            Error::MissingHeader => write!(f, "Missing header"),
            Error::InvalidPoW => write!(f, "Invalid proof of work"),
            Error::InvalidChainWork => write!(f, "Chain difficulty cannot decrease"),
            Error::InvalidByteSequence => write!(f, "Invalid sequence of bytes"),
            Error::ConfigError(ref e_str) => fmt::Display::fmt(e_str, f),
            Error::BlockchainHeight => write!(f, "Value is beyond the end of the blockchain"),
            Error::TimedOut => write!(f, "Request timed out"),
        }
    }
}
impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::Io(ref e) => Some(e),
            Error::SocketNotConnectedToPeer => None,
            Error::SerializationError(ref e) => Some(e),
            Error::InvalidMessage(ref _msg) => None,
            Error::InvalidReply => None,
            Error::InvalidMagic => None,
            Error::UnhandledMessage(ref _msg) => None,
            Error::ConnectionBroken => None,
            Error::ConnectionError => None,
            Error::FilesystemError(ref e) => Some(e),
            Error::DBError(ref e) => Some(e),
            Error::HashError(ref e) => Some(e),
            Error::NoncontiguousHeader => None,
            Error::MissingHeader => None,
            Error::InvalidPoW => None,
            Error::InvalidChainWork => None,
            Error::InvalidByteSequence => None,
            Error::ConfigError(ref _e_str) => None,
            Error::BlockchainHeight => None,
            Error::TimedOut => None,
        }
    }
}

impl From<db_error> for Error {
    fn from(e: db_error) -> Error {
        Error::DBError(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BitcoinZNetworkType {
    Mainnet,
    Testnet,
    Regtest,
}

#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub struct BitcoinZTxOutput {
    pub address: BitcoinZAddress,
    pub units: u64,
}

/// Legacy BitcoinZ address input type, based on scriptSig.
#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub enum BitcoinZInputType {
    Standard,
    SegwitP2SH,
}

/// BitcoinZ tx input we can parse in older versions.
/// In older versions, we cared about being able to parse a scriptSig and witness.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct BitcoinZTxInputStructured {
    pub keys: Vec<BitcoinZPublicKey>,
    pub num_required: usize,
    pub in_type: BitcoinZInputType,
    pub tx_ref: (Txid, u32),
}

/// BitcoinZ tx input we can parse in later versions.
/// In later versions, we don't care about being able to parse a scriptSig or witness.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct BitcoinZTxInputRaw {
    pub scriptSig: Vec<u8>,
    pub witness: Vec<Vec<u8>>,
    pub tx_ref: (Txid, u32),
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum BitcoinZTxInput {
    Structured(BitcoinZTxInputStructured),
    Raw(BitcoinZTxInputRaw),
}

impl From<BitcoinZTxInputStructured> for BitcoinZTxInput {
    fn from(inp: BitcoinZTxInputStructured) -> BitcoinZTxInput {
        BitcoinZTxInput::Structured(inp)
    }
}

impl From<BitcoinZTxInputRaw> for BitcoinZTxInput {
    fn from(inp: BitcoinZTxInputRaw) -> BitcoinZTxInput {
        BitcoinZTxInput::Raw(inp)
    }
}
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct BitcoinZTransaction {
    pub txid: Txid,
    pub vtxindex: u32,
    pub opcode: u8,
    pub data: Vec<u8>,
    /// how much BitcoinZ was sent to the data output
    pub data_amt: u64,
    pub inputs: Vec<BitcoinZTxInput>,
    pub outputs: Vec<BitcoinZTxOutput>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct BitcoinZBlock {
    pub block_height: u64,
    pub block_hash: BurnchainHeaderHash,
    pub parent_block_hash: BurnchainHeaderHash,
    pub txs: Vec<BitcoinZTransaction>,
    pub timestamp: u64,
}

impl BitcoinZBlock {
    pub fn new(
        height: u64,
        hash: &BurnchainHeaderHash,
        parent: &BurnchainHeaderHash,
        txs: Vec<BitcoinZTransaction>,
        timestamp: u64,
    ) -> BitcoinZBlock {
        BitcoinZBlock {
            block_height: height,
            block_hash: hash.clone(),
            parent_block_hash: parent.clone(),
            txs: txs,
            timestamp: timestamp,
        }
    }
}
