// Adapted `stack_stx.rs` for the Zook Network
// Ensures seamless PoX functionality with zBTCZ and BTCZ

use std::io::{Read, Write};

use btcz_common::address::AddressHashMode;
use btcz_common::codec::{write_next, Error as codec_error, BitcoinZMessageCodec};
use btcz_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, BitcoinZAddress, TrieHash, VRFSeed,
};
use btcz_common::types::BitcoinZPublicKeyBuffer;
use btcz_common::util::hash::to_hex;
use btcz_common::util::log;
use btcz_common::util::secp256k1::Secp256k1PublicKey;
use btcz_common::util::vrf::{VRFPrivateKey, VRFPublicKey, VRF};

use crate::burnchains::btcz::{
    BitcoinZTxInput, BitcoinZTxInputStructured, BitcoinZTransaction, PublicKey, Txid,
};
use crate::burnchains::{Address, Burnchain, BurnchainBlockHeader};
use crate::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandleTx};
use crate::chainstate::burn::operations::{
    parse_u128_from_be, parse_u32_from_be, parse_u64_from_be, BlockstackOperationType,
    Error as op_error, PreZBTCZOp, StackZBTCZOp,
};
use crate::chainstate::burn::{ConsensusHash, Opcodes};
use crate::chainstate::stacks::address::PoxAddress;
use crate::chainstate::stacks::index::storage::TrieFileStorage;
use crate::chainstate::stacks::{BitcoinZPrivateKey, BitcoinZPublicKey};
use crate::core::{ZookEpochId, POX_MAX_NUM_CYCLES};
use crate::net::Error as net_error;

// Return type from parse_data below
struct ParsedData {
    stacked_zbtcz: u128,
    num_cycles: u8,
    signer_key: Option<BitcoinZPublicKeyBuffer>,
    max_amount: Option<u128>,
    auth_id: Option<u32>,
}

pub static OUTPUTS_PER_COMMIT: usize = 2;

impl PreZBTCZOp {
    #[cfg(test)]
    pub fn new(sender: &BitcoinZAddress) -> PreZBTCZOp {
        PreZBTCZOp {
            output: sender.clone(),
            // To be filled in
            txid: Txid([0u8; 32]),
            vtxindex: 0,
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
        }
    }

    pub fn from_tx(
        block_header: &BurnchainBlockHeader,
        epoch_id: ZookEpochId,
        tx: &BurnchainTransaction,
        pox_sunset_ht: u64,
    ) -> Result<PreZBTCZOp, op_error> {
        PreZBTCZOp::parse_from_tx(
            block_header.block_height,
            &block_header.block_hash,
            epoch_id,
            tx,
            pox_sunset_ht,
        )
    }

    /// Parse a PreZBTCZOp
    /// `pox_sunset_ht` is the height at which PoX *disables*
    pub fn parse_from_tx(
        block_height: u64,
        block_hash: &BurnchainHeaderHash,
        epoch_id: ZookEpochId,
        tx: &BurnchainTransaction,
        pox_sunset_ht: u64,
    ) -> Result<PreZBTCZOp, op_error> {
        // Can't be too careful...
        let num_inputs = tx.num_signers();
        let num_outputs = tx.num_recipients();

        if num_inputs == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                num_inputs, num_outputs,
            );
            return Err(op_error::InvalidInput);
        }

        if num_outputs == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                num_inputs, num_outputs,
            );
            return Err(op_error::InvalidInput);
        }

        if tx.opcode() != Opcodes::PreZBTCZ as u8 {
            warn!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(op_error::InvalidInput);
        };

        let outputs = tx.get_recipients();
        assert!(outputs.len() > 0);

        let output = outputs[0]
            .as_ref()
            .ok_or_else(|| {
                warn!("Invalid tx: first output cannot be decoded");
                op_error::InvalidInput
            })?
            .address
            .clone()
            .try_into_btcz_address()
            .ok_or_else(|| {
                warn!("Invalid tx: first output must be representable as a BitcoinZAddress");
                op_error::InvalidInput
            })?;

        // Check if we've reached PoX disable
        if PoxConstants::has_pox_sunset(epoch_id) && block_height >= pox_sunset_ht {
            debug!(
                "PreZBTCZOp broadcasted after sunset. Ignoring. txid={}",
                tx.txid()
            );
            return Err(op_error::InvalidInput);
        }

        Ok(PreZBTCZOp {
            output: output,
            txid: tx.txid(),
            vtxindex: tx.vtxindex(),
            block_height,
            burn_header_hash: block_hash.clone(),
        })
    }
}
impl StackZBTCZOp {
    #[cfg(test)]
    pub fn new(
        sender: &BitcoinZAddress,
        reward_addr: &PoxAddress,
        stacked_zbtcz: u128,
        num_cycles: u8,
        signer_key: Option<BitcoinZPublicKeyBuffer>,
        max_amount: Option<u128>,
        auth_id: Option<u32>,
    ) -> StackZBTCZOp {
        StackZBTCZOp {
            sender: sender.clone(),
            reward_addr: reward_addr.clone(),
            stacked_zbtcz,
            num_cycles,
            signer_key,
            max_amount,
            auth_id,
            // To be filled in
            txid: Txid([0u8; 32]),
            vtxindex: 0,
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
        }
    }

    /// Parse a StackZBTCZOp
    /// `pox_sunset_ht` is the height at which PoX *disables*
    pub fn parse_from_tx(
        block_height: u64,
        block_hash: &BurnchainHeaderHash,
        epoch_id: ZookEpochId,
        tx: &BurnchainTransaction,
        sender: &BitcoinZAddress,
        pox_sunset_ht: u64,
    ) -> Result<StackZBTCZOp, op_error> {
        // Can't be too careful...
        let num_outputs = tx.num_recipients();

        if tx.num_signers() == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                tx.num_signers(),
                num_outputs
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

        if tx.opcode() != Opcodes::StackZBTCZ as u8 {
            warn!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(op_error::InvalidInput);
        };

        let data = StackZBTCZOp::parse_data(&tx.data()).ok_or_else(|| {
            warn!("Invalid tx data");
            op_error::ParseError
        })?;

        let outputs = tx.get_recipients();
        assert!(outputs.len() > 0);

        let first_output = outputs[0].as_ref().ok_or_else(|| {
            warn!("Invalid tx: failed to decode first output");
            op_error::InvalidInput
        })?;

        // Coerce a hash mode for this address if need be, since we'll need it when we feed this
        // address into the .pox contract
        let reward_addr = first_output.address.clone().coerce_hash_mode();

        // Check if we've reached PoX disable
        if PoxConstants::has_pox_sunset(epoch_id) && block_height >= pox_sunset_ht {
            debug!(
                "StackZBTCZOp broadcasted after sunset. Ignoring. txid={}",
                tx.txid()
            );
            return Err(op_error::InvalidInput);
        }

        Ok(StackZBTCZOp {
            sender: sender.clone(),
            reward_addr,
            stacked_zbtcz: data.stacked_zbtcz,
            num_cycles: data.num_cycles,
            signer_key: data.signer_key,
            max_amount: data.max_amount,
            auth_id: data.auth_id,
            txid: tx.txid(),
            vtxindex: tx.vtxindex(),
            block_height,
            burn_header_hash: block_hash.clone(),
        })
    }

    /// Validate the StackZBTCZOp
    pub fn check(&self) -> Result<(), op_error> {
        if self.stacked_zbtcz == 0 {
            warn!("Invalid StackZBTCZOp, must have positive zBTCZ");
            return Err(op_error::StackZBTCZMustBePositive);
        }

        if self.num_cycles == 0 || self.num_cycles > POX_MAX_NUM_CYCLES {
            warn!(
                "Invalid StackZBTCZOp, num_cycles = {}, but must be in (0, {}]",
                self.num_cycles, POX_MAX_NUM_CYCLES
            );
            return Err(op_error::InvalidNumCycles);
        }

        // Check to see if the signer key is valid if available
        if let Some(signer_key) = self.signer_key {
            Secp256k1PublicKey::from_slice(signer_key.as_bytes())
                .map_err(|_| op_error::StackZBTCZInvalidKey)?;
        }

        Ok(())
    }
}
impl BitcoinZMessageCodec for StackZBTCZOp {
    /*
             Wire format:

            0      2  3                             19           20                  53                 69                        73
            |------|--|-----------------------------|------------|-------------------|-------------------|-------------------------|
            magic  op         zBTCZ to lock (u128)     cycles (u8)     signer key (optional)   max_amount (optional u128)  auth_id (optional u32)

    */
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(Opcodes::StackZBTCZ as u8))?;
        fd.write_all(&self.stacked_zbtcz.to_be_bytes())
            .map_err(|e| codec_error::WriteError(e))?;
        write_next(fd, &self.num_cycles)?;

        if let Some(signer_key) = &self.signer_key {
            fd.write_all(&signer_key.as_bytes()[..])
                .map_err(codec_error::WriteError)?;
        }
        if let Some(max_amount) = &self.max_amount {
            fd.write_all(&max_amount.to_be_bytes())
                .map_err(|e| codec_error::WriteError(e))?;
        }
        if let Some(auth_id) = &self.auth_id {
            fd.write_all(&auth_id.to_be_bytes())
                .map_err(|e| codec_error::WriteError(e))?;
        }
        Ok(())
    }

    fn consensus_deserialize<R: Read>(_fd: &mut R) -> Result<StackZBTCZOp, codec_error> {
        // Op deserialized through burnchain indexer
        unimplemented!();
    }
}

impl StackZBTCZOp {
    pub fn finalize(&self) -> Result<(), op_error> {
        if self.stacked_zbtcz == 0 {
            warn!("Cannot finalize: zero zBTCZ locked");
            return Err(op_error::StackZBTCZMustBePositive);
        }

        debug!(
            "Finalizing StackZBTCZOp for txid={} with {} cycles",
            to_hex(&self.txid), self.num_cycles
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use btcz_common::address::{AddressHashMode, C32_ADDRESS_VERSION_MAINNET_SINGLESIG};
    use btcz_common::util::hash::*;

    use super::*;

    #[test]
    fn test_consensus_serialize_deserialize() {
        let sender = BitcoinZAddress {
            version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
            bytes: Hash160([0x01; 20]),
        };
        let reward_addr = PoxAddress::Standard(
            BitcoinZAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160([0x02; 20]),
            },
            None,
        );

        let op = StackZBTCZOp {
            sender,
            reward_addr,
            stacked_zbtcz: 1000,
            num_cycles: 10,
            signer_key: Some(BitcoinZPublicKeyBuffer([0x01; 33])),
            max_amount: Some(2000),
            auth_id: Some(42),
            txid: Txid([0x10; 32]),
            vtxindex: 1,
            block_height: 100,
            burn_header_hash: BurnchainHeaderHash([0x20; 32]),
        };

        let mut serialized = Vec::new();
        op.consensus_serialize(&mut serialized).expect("Serialization failed");
        assert!(!serialized.is_empty());

        // Deserialize logic would go here, currently unimplemented
    }
}
impl BitcoinZMessageCodec for PreZBTCZOp {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(Opcodes::PreZBTCZ as u8))?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(_fd: &mut R) -> Result<PreZBTCZOp, codec_error> {
        // Op deserialized through burnchain indexer
        unimplemented!();
    }
}

#[cfg(test)]
mod more_tests {
    use super::*;
    use btcz_common::address::{BitcoinZAddress, AddressHashMode};

    #[test]
    fn test_pre_zbtcz_op_serialization() {
        let sender = BitcoinZAddress {
            version: AddressHashMode::SerializeP2PKH as u8,
            bytes: Hash160([0x01; 20]),
        };

        let op = PreZBTCZOp {
            output: sender,
            txid: Txid([0x10; 32]),
            vtxindex: 1,
            block_height: 100,
            burn_header_hash: BurnchainHeaderHash([0x20; 32]),
        };

        let mut serialized = Vec::new();
        op.consensus_serialize(&mut serialized).expect("Serialization failed");
        assert!(!serialized.is_empty());

        // Deserialize logic would go here, currently unimplemented
    }

    #[test]
    fn test_stack_zbtcz_op_validation() {
        let sender = BitcoinZAddress {
            version: AddressHashMode::SerializeP2PKH as u8,
            bytes: Hash160([0x01; 20]),
        };
        let reward_addr = PoxAddress::Standard(
            BitcoinZAddress {
                version: AddressHashMode::SerializeP2PKH as u8,
                bytes: Hash160([0x02; 20]),
            },
            None,
        );

        let op = StackZBTCZOp {
            sender,
            reward_addr,
            stacked_zbtcz: 0,
            num_cycles: 10,
            signer_key: None,
            max_amount: None,
            auth_id: None,
            txid: Txid([0x10; 32]),
            vtxindex: 1,
            block_height: 100,
            burn_header_hash: BurnchainHeaderHash([0x20; 32]),
        };

        let result = op.check();
        assert!(matches!(result, Err(op_error::StackZBTCZMustBePositive)));

        let valid_op = StackZBTCZOp {
            stacked_zbtcz: 1000,
            ..op
        };

        let result = valid_op.check();
        assert!(result.is_ok());
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use btcz_common::address::{BitcoinZAddress, AddressHashMode};
    use btcz_common::util::hash::{Hash160, to_hex};

    #[test]
    fn test_parse_stack_zbtcz() {
        let tx = BitcoinZTransaction {
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::StackZBTCZ as u8,
            data: vec![1; 80],
            data_amt: 0,
            inputs: vec![BitcoinZTxInputStructured {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinZInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }
            .into()],
            outputs: vec![
                BitcoinZTxOutput {
                    units: 10,
                    address: BitcoinZAddress {
                        version: AddressHashMode::SerializeP2PKH as u8,
                        bytes: Hash160([0x01; 20]),
                    },
                },
                BitcoinZTxOutput {
                    units: 20,
                    address: BitcoinZAddress {
                        version: AddressHashMode::SerializeP2PKH as u8,
                        bytes: Hash160([0x02; 20]),
                    },
                },
            ],
        };

        let sender = BitcoinZAddress {
            version: AddressHashMode::SerializeP2PKH as u8,
            bytes: Hash160([0x03; 20]),
        };

        let op = StackZBTCZOp::parse_from_tx(
            100,
            &BurnchainHeaderHash([0; 32]),
            ZookEpochId::Epoch2_05,
            &tx,
            &sender,
            101,
        )
        .unwrap();

        assert_eq!(op.sender, sender);
        assert_eq!(op.reward_addr.bytes, Hash160([0x01; 20]));
        assert_eq!(op.stacked_zbtcz, u128::from_be_bytes([1; 16]));
        assert_eq!(op.num_cycles, 10);
    }

    #[test]
    fn test_parse_invalid_stack_zbtcz() {
        let tx = BitcoinZTransaction {
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::StackZBTCZ as u8,
            data: vec![1; 80],
            data_amt: 0,
            inputs: vec![BitcoinZTxInputStructured {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinZInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }
            .into()],
            outputs: vec![
                BitcoinZTxOutput {
                    units: 10,
                    address: BitcoinZAddress {
                        version: AddressHashMode::SerializeP2PKH as u8,
                        bytes: Hash160([0x01; 20]),
                    },
                },
            ],
        };

        let sender = BitcoinZAddress {
            version: AddressHashMode::SerializeP2PKH as u8,
            bytes: Hash160([0x03; 20]),
        };

        let op_err = StackZBTCZOp::parse_from_tx(
            100,
            &BurnchainHeaderHash([0; 32]),
            ZookEpochId::Epoch2_05,
            &tx,
            &sender,
            100,
        )
        .unwrap_err();

        assert!(matches!(op_err, op_error::InvalidInput));
    }

    #[test]
    fn test_stack_zbtcz_op_script_len() {
        let sender_addr = BitcoinZAddress {
            version: AddressHashMode::SerializeP2PKH as u8,
            bytes: Hash160([0x03; 20]),
        };
        let reward_addr = PoxAddress::Standard(
            BitcoinZAddress {
                version: AddressHashMode::SerializeP2PKH as u8,
                bytes: Hash160([0x02; 20]),
            },
            None,
        );
        let op = StackZBTCZOp {
            sender: sender_addr,
            reward_addr,
            stacked_zbtcz: 100,
            txid: Txid([10u8; 32]),
            vtxindex: 10,
            block_height: 10,
            burn_header_hash: BurnchainHeaderHash([0x10; 32]),
            num_cycles: 10,
            signer_key: Some(BitcoinZPublicKeyBuffer([0x01; 33])),
            max_amount: Some(200),
            auth_id: Some(0u32),
        };

        let mut serialized = Vec::new();
        op.consensus_serialize(&mut serialized)
            .expect("Expected serialization to succeed");

        assert!(serialized.len() > 0);
    }
}
