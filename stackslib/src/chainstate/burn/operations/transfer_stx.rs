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

use std::io::{Read, Write};

use zbtcz_common::address::AddressHashMode;
use zbtcz_common::codec::{write_next, Error as codec_error, ZbtczMessageCodec};
use zbtcz_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ZbtczAddress, TrieHash, VRFSeed,
};
use zbtcz_common::util::hash::to_hex;
use zbtcz_common::util::log;
use zbtcz_common::util::vrf::{VRFPrivateKey, VRFPublicKey, VRF};

use crate::burnchains::{
    Address, Burnchain, BurnchainBlockHeader, BurnchainRecipient, BurnchainTransaction, PublicKey,
    Txid,
};
use crate::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandleTx};
use crate::chainstate::burn::operations::{
    parse_u128_from_be, ZbtczOperationType, Error as op_error, TransferZbtczOp,
};
use crate::chainstate::burn::{ConsensusHash, Opcodes};
use crate::chainstate::zbtcz::index::storage::TrieFileStorage;
use crate::chainstate::zbtcz::{ZbtczPrivateKey, ZbtczPublicKey};
use crate::core::POX_MAX_NUM_CYCLES;
use crate::net::Error as net_error;

// return type from parse_data below
struct ParsedData {
    transfered_uzbtcz: u128,
    memo: Vec<u8>,
}

impl TransferZbtczOp {
    #[cfg(test)]
    pub fn new(
        sender: &ZbtczAddress,
        recipient: &ZbtczAddress,
        transfered_uzbtcz: u128,
    ) -> TransferZbtczOp {
        TransferZbtczOp {
            sender: sender.clone(),
            recipient: recipient.clone(),
            transfered_uzbtcz,
            memo: vec![],
            // to be filled in
            txid: Txid([0u8; 32]),
            vtxindex: 0,
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
        }
    }

    fn parse_data(data: &Vec<u8>) -> Option<ParsedData> {
        /*
            Wire format:
            0      2  3                             19        80
            |------|--|-----------------------------|---------|
             magic  op     uZBTCZ to transfer (u128)     memo (up to 61 bytes)

             Note that `data` is missing the first 3 bytes -- the magic and op have been stripped

             The values uzbtcz to transfer are in big-endian order.
        */

        if data.len() < 16 {
            // too short
            warn!(
                "TransferZbtczOp payload is malformed ({} bytes, expected >= {})",
                data.len(),
                16
            );
            return None;
        }

        if data.len() > (61 + 16) {
            // too long
            warn!(
                "TransferZbtczOp payload is malformed ({} bytes, expected <= {})",
                data.len(),
                16 + 61
            );
            return None;
        }

        let transfered_uzbtcz = parse_u128_from_be(&data[0..16]).unwrap();
        let memo = Vec::from(&data[16..]);

        Some(ParsedData {
            transfered_uzbtcz,
            memo,
        })
    }

    pub fn get_sender_txid(tx: &BurnchainTransaction) -> Result<&Txid, op_error> {
        match tx.get_input_tx_ref(0) {
            Some((ref txid, vout)) => {
                if *vout != 1 {
                    warn!(
                        "Invalid tx: TransferZbtczOp must spend the second output of the PreZbtczOp"
                    );
                    Err(op_error::InvalidInput)
                } else {
                    Ok(txid)
                }
            }
            None => {
                warn!("Invalid tx: TransferZbtczOp must have at least one input");
                Err(op_error::InvalidInput)
            }
        }
    }

    pub fn from_tx(
        block_header: &BurnchainBlockHeader,
        tx: &BurnchainTransaction,
        sender: &ZbtczAddress,
    ) -> Result<TransferZbtczOp, op_error> {
        TransferZbtczOp::parse_from_tx(
            block_header.block_height,
            &block_header.block_hash,
            tx,
            sender,
        )
    }

    /// parse a TransferZbtczOp
    pub fn parse_from_tx(
        block_height: u64,
        block_hash: &BurnchainHeaderHash,
        tx: &BurnchainTransaction,
        sender: &ZbtczAddress,
    ) -> Result<TransferZbtczOp, op_error> {
        // can't be too careful...
        let num_outputs = tx.num_recipients();
        if tx.num_signers() == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                tx.num_signers(),
                num_outputs,
            );
            return Err(op_error::InvalidInput);
        }

        if num_outputs == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                tx.num_signers(),
                num_outputs,
            );
            return Err(op_error::InvalidInput);
        }

        if tx.opcode() != Opcodes::TransferZbtcz as u8 {
            warn!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(op_error::InvalidInput);
        };

        let data = TransferZbtczOp::parse_data(&tx.data()).ok_or_else(|| {
            warn!("Invalid tx data");
            op_error::ParseError
        })?;

        let outputs = tx.get_recipients();
        assert!(outputs.len() > 0);

        let output = outputs[0]
            .as_ref()
            .ok_or_else(|| {
                warn!("Invalid tx: could not decode the first output");
                op_error::InvalidInput
            })?
            .address
            .clone()
            .try_into_zbtcz_address()
            .ok_or_else(|| {
                warn!("Invalid tx: output must be representable as a ZbtczAddress");
                op_error::InvalidInput
            })?;

        Ok(TransferZbtczOp {
            sender: sender.clone(),
            recipient: output,
            transfered_uzbtcz: data.transfered_uzbtcz,
            memo: data.memo,
            txid: tx.txid(),
            vtxindex: tx.vtxindex(),
            block_height,
            burn_header_hash: block_hash.clone(),
        })
    }
}

impl ZbtczMessageCodec for TransferZbtczOp {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        if self.memo.len() > 61 {
            return Err(codec_error::ArrayTooLong);
        }
        write_next(fd, &(Opcodes::TransferZbtcz as u8))?;
        fd.write_all(&self.transfered_uzbtcz.to_be_bytes())
            .map_err(|e| codec_error::WriteError(e))?;
        fd.write_all(&self.memo)
            .map_err(|e| codec_error::WriteError(e))?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(_fd: &mut R) -> Result<TransferZbtczOp, codec_error> {
        // Op deserialized through burnchain indexer
        unimplemented!();
    }
}

impl TransferZbtczOp {
    pub fn check(&self) -> Result<(), op_error> {
        if self.transfered_uzbtcz == 0 {
            warn!("Invalid TransferZbtczOp, must have positive uzbtcz");
            return Err(op_error::TransferZbtczMustBePositive);
        }
        if self.sender == self.recipient {
            warn!("Invalid TransferZbtczOp, sender is recipient");
            return Err(op_error::TransferZbtczSelfSend);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use zbtcz_common::address::AddressHashMode;
    use zbtcz_common::deps_common::bitcoin::blockdata::transaction::Transaction;
    use zbtcz_common::deps_common::bitcoin::network::serialize::{deserialize, serialize_hex};
    use zbtcz_common::types::chainstate::{BlockHeaderHash, ZbtczAddress, VRFSeed};
    use zbtcz_common::util::get_epoch_time_secs;
    use zbtcz_common::util::hash::*;
    use zbtcz_common::util::vrf::VRFPublicKey;

    use super::*;
    use crate::burnchains::bitcoin::address::*;
    use crate::burnchains::bitcoin::blocks::BitcoinBlockParser;
    use crate::burnchains::bitcoin::keys::BitcoinPublicKey;
    use crate::burnchains::bitcoin::*;
    use crate::burnchains::*;
    use crate::chainstate::burn::db::sortdb::*;
    use crate::chainstate::burn::db::*;
    use crate::chainstate::burn::operations::*;
    use crate::chainstate::burn::{ConsensusHash, *};
    use crate::chainstate::zbtcz::address::ZbtczAddressExtensions;
    use crate::chainstate::zbtcz::ZbtczPublicKey;

    #[test]
    fn test_parse_transfer_zbtcz() {
        let tx = BitcoinTransaction {
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::TransferZbtcz as u8,
            data: vec![1; 77],
            data_amt: 0,
            inputs: vec![BitcoinTxInputStructured {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }
            .into()],
            outputs: vec![
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([1; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 30,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([0; 20]),
                    }),
                },
            ],
        };

        let sender = ZbtczAddress {
            version: 0,
            bytes: Hash160([0; 20]),
        };
        let op = TransferZbtczOp::parse_from_tx(
            16843022,
            &BurnchainHeaderHash([0; 32]),
            &BurnchainTransaction::Bitcoin(tx.clone()),
            &sender,
        )
        .unwrap();

        assert_eq!(&op.sender, &sender);
        assert_eq!(
            &op.recipient,
            &ZbtczAddress::from_legacy_bitcoin_address(
                &tx.outputs[0].address.clone().expect_legacy()
            )
        );
        assert_eq!(op.transfered_uzbtcz, u128::from_be_bytes([1; 16]));
        assert_eq!(op.memo, vec![1; 61]);
    }
}
