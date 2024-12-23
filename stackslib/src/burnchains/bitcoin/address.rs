// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
// Adapted for the Zook Network and BitcoinZ
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

use bitcoinz_common::address::b58 as base58;
use bitcoinz_common::util::hash::{hex_bytes, to_hex, Hash160};
use bitcoinz_common::util::log;

use crate::burnchains::bitcoinz::{BitcoinZNetworkType, Error as btc_error};
use crate::burnchains::Address;
use crate::chainstate::zook::{
    ZBTCZ_ADDRESS_VERSION_MAINNET_MULTISIG, ZBTCZ_ADDRESS_VERSION_MAINNET_SINGLESIG,
    ZBTCZ_ADDRESS_VERSION_TESTNET_MULTISIG, ZBTCZ_ADDRESS_VERSION_TESTNET_SINGLESIG,
};

#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub enum LegacyBitcoinZAddressType {
    PublicKeyHash,
    ScriptHash,
}

/// Legacy BitcoinZ address
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct LegacyBitcoinZAddress {
    pub addrtype: LegacyBitcoinZAddressType,
    pub network_id: BitcoinZNetworkType,
    pub bytes: Hash160,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum BitcoinZAddress {
    Legacy(LegacyBitcoinZAddress),
}

impl From<LegacyBitcoinZAddress> for BitcoinZAddress {
    fn from(addr: LegacyBitcoinZAddress) -> BitcoinZAddress {
        BitcoinZAddress::Legacy(addr)
    }
}

// legacy address versions
pub const ADDRESS_VERSION_MAINNET_SINGLESIG: u8 = 0x1C; // BitcoinZ mainnet P2PKH prefix
pub const ADDRESS_VERSION_MAINNET_MULTISIG: u8 = 0x1D; // BitcoinZ mainnet P2SH prefix
pub const ADDRESS_VERSION_TESTNET_SINGLESIG: u8 = 0x1E; // BitcoinZ testnet P2PKH prefix
pub const ADDRESS_VERSION_TESTNET_MULTISIG: u8 = 0x1F; // BitcoinZ testnet P2SH prefix

pub fn legacy_address_type_to_version_byte(
    addrtype: LegacyBitcoinZAddressType,
    network_id: BitcoinZNetworkType,
) -> u8 {
    match (addrtype, network_id) {
        (LegacyBitcoinZAddressType::PublicKeyHash, BitcoinZNetworkType::Mainnet) => {
            ADDRESS_VERSION_MAINNET_SINGLESIG
        }
        (LegacyBitcoinZAddressType::ScriptHash, BitcoinZNetworkType::Mainnet) => {
            ADDRESS_VERSION_MAINNET_MULTISIG
        }
        (LegacyBitcoinZAddressType::PublicKeyHash, BitcoinZNetworkType::Testnet) => {
            ADDRESS_VERSION_TESTNET_SINGLESIG
        }
        (LegacyBitcoinZAddressType::ScriptHash, BitcoinZNetworkType::Testnet) => {
            ADDRESS_VERSION_TESTNET_MULTISIG
        }
    }
}

pub fn legacy_version_byte_to_address_type(
    version: u8,
) -> Option<(LegacyBitcoinZAddressType, BitcoinZNetworkType)> {
    match version {
        ADDRESS_VERSION_MAINNET_SINGLESIG => Some((
            LegacyBitcoinZAddressType::PublicKeyHash,
            BitcoinZNetworkType::Mainnet,
        )),
        ADDRESS_VERSION_MAINNET_MULTISIG => Some((
            LegacyBitcoinZAddressType::ScriptHash,
            BitcoinZNetworkType::Mainnet,
        )),
        ADDRESS_VERSION_TESTNET_SINGLESIG => Some((
            LegacyBitcoinZAddressType::PublicKeyHash,
            BitcoinZNetworkType::Testnet,
        )),
        ADDRESS_VERSION_TESTNET_MULTISIG => Some((
            LegacyBitcoinZAddressType::ScriptHash,
            BitcoinZNetworkType::Testnet,
        )),
        _ => None,
    }
}
// Segment 2: Continue adapting BitcoinZ address types and methods

#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub enum LegacyBitcoinZAddressType {
    PublicKeyHash,
    ScriptHash,
}

/// Legacy BitcoinZ address
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct LegacyBitcoinZAddress {
    pub addrtype: LegacyBitcoinZAddressType,
    pub network_id: BitcoinZNetworkType,
    pub bytes: Hash160,
}

impl LegacyBitcoinZAddress {
    fn to_versioned_bytes(&self) -> [u8; 21] {
        let mut ret = [0; 21];
        let version_byte = legacy_address_type_to_version_byte(self.addrtype, self.network_id);
        ret[0] = version_byte;
        ret[1..].copy_from_slice(&self.bytes.0);
        ret
    }

    pub fn to_b58(&self) -> String {
        let versioned_bytes = self.to_versioned_bytes();
        base58::check_encode_slice(&versioned_bytes)
    }

    /// Create a P2PKH transaction output
    pub fn to_p2pkh_tx_out(bytes: &Hash160, value: u64) -> TxOut {
        let script_pubkey = BtcScriptBuilder::new()
            .push_opcode(BtcOp::OP_DUP)
            .push_opcode(BtcOp::OP_HASH160)
            .push_slice(&bytes.0)
            .push_opcode(BtcOp::OP_EQUALVERIFY)
            .push_opcode(BtcOp::OP_CHECKSIG)
            .into_script();
        TxOut {
            value,
            script_pubkey,
        }
    }

    /// Create a P2SH transaction output
    pub fn to_p2sh_tx_out(bytes: &Hash160, value: u64) -> TxOut {
        let script_pubkey = BtcScriptBuilder::new()
            .push_opcode(BtcOp::OP_HASH160)
            .push_slice(&bytes.0)
            .push_opcode(BtcOp::OP_EQUAL)
            .into_script();
        TxOut {
            value,
            script_pubkey,
        }
    }

    /// Instantiate a legacy address from a base58check string
    pub fn from_b58(addrb58: &str) -> Result<LegacyBitcoinZAddress, btc_error> {
        let bytes = base58::from_check(addrb58).map_err(|_e| btc_error::InvalidByteSequence)?;

        if bytes.len() != 21 {
            return Err(btc_error::InvalidByteSequence);
        }

        let version = bytes[0];

        let (addrtype, network_id) = match legacy_version_byte_to_address_type(version) {
            Some(x) => x,
            None => return Err(btc_error::InvalidByteSequence),
        };

        let mut payload_bytes = [0; 20];
        payload_bytes.copy_from_slice(&bytes[1..21]);

        Ok(LegacyBitcoinZAddress {
            addrtype,
            network_id,
            bytes: Hash160(payload_bytes),
        })
    }
}
// Segment 3: Adapting Segwit BitcoinZ Address for BitcoinZ

/// BitcoinZ Segwit Address
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum SegwitBitcoinZAddress {
    P2WPKH(bool, [u8; 20]), // Pay to Witness Public Key Hash
    P2WSH(bool, [u8; 32]),  // Pay to Witness Script Hash
}

impl SegwitBitcoinZAddress {
    pub fn witness_version(&self) -> u8 {
        match *self {
            SegwitBitcoinZAddress::P2WPKH(..) => SEGWIT_V0,
            SegwitBitcoinZAddress::P2WSH(..) => SEGWIT_V0,
        }
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.bytes_ref().to_vec()
    }

    pub fn bytes_ref(&self) -> &[u8] {
        match *self {
            SegwitBitcoinZAddress::P2WPKH(_, ref bytes) => bytes,
            SegwitBitcoinZAddress::P2WSH(_, ref bytes) => bytes,
        }
    }

    pub fn to_versioned_bytes(&self) -> Vec<u8> {
        let mut bytes = self.bytes();
        let version = self.witness_version();
        let mut versioned_bytes = Vec::with_capacity(1 + bytes.len());
        versioned_bytes.push(version);
        versioned_bytes.append(&mut bytes);
        versioned_bytes
    }

    pub fn is_mainnet(&self) -> bool {
        match *self {
            SegwitBitcoinZAddress::P2WPKH(ref mainnet, _) => *mainnet,
            SegwitBitcoinZAddress::P2WSH(ref mainnet, _) => *mainnet,
        }
    }

    pub fn to_bech32(&self, hrp: &str) -> Result<String, btc_error> {
        let bytes = self.bytes();
        let mut quintets: Vec<u5> = vec![u5::try_from_u8(self.witness_version())
            .map_err(|_| btc_error::InvalidByteSequence)?];
        quintets.extend_from_slice(&bytes.to_base32());
        bech32::encode(hrp, quintets, bech32::Variant::Bech32)
            .map_err(|_| btc_error::InvalidByteSequence)
    }

    pub fn to_tx_out(&self, value: u64) -> TxOut {
        let script_pubkey = match self {
            SegwitBitcoinZAddress::P2WPKH(_, bytes) => BtcScriptBuilder::new()
                .push_opcode(BtcOp::OP_PUSHBYTES_0)
                .push_slice(bytes)
                .into_script(),
            SegwitBitcoinZAddress::P2WSH(_, bytes) => BtcScriptBuilder::new()
                .push_opcode(BtcOp::OP_PUSHBYTES_0)
                .push_slice(bytes)
                .into_script(),
        };

        TxOut {
            value,
            script_pubkey,
        }
    }
}
// Segment 4: Continuing adaptation for BitcoinZ

impl BitcoinZAddress {
    /// Instantiate an address from a scriptpubkey specific to BitcoinZ.
    /// If the address format is unrecognized, return None.
    /// WARNING: Cannot differentiate between P2SH and other address formats here.
    pub fn from_scriptpubkey(
        network_id: BitcoinZNetworkType,
        scriptpubkey: &[u8],
    ) -> Option<BitcoinZAddress> {
        if scriptpubkey.len() == 25
            && scriptpubkey[0..3] == [0x76, 0xa9, 0x14] // P2PKH prefix
            && scriptpubkey[23..25] == [0x88, 0xac] // P2PKH suffix
        {
            let mut my_bytes = [0; 20];
            my_bytes.copy_from_slice(&scriptpubkey[3..23]);

            Some(BitcoinZAddress::Legacy(BitcoinZLegacyAddress {
                network_id,
                addrtype: BitcoinZAddressType::PublicKeyHash,
                bytes: Hash160(my_bytes),
            }))
        } else if scriptpubkey.len() == 23
            && scriptpubkey[0..2] == [0xa9, 0x14] // P2SH prefix
            && scriptpubkey[22] == 0x87 // P2SH suffix
        {
            let mut my_bytes = [0; 20];
            my_bytes.copy_from_slice(&scriptpubkey[2..22]);

            Some(BitcoinZAddress::Legacy(BitcoinZLegacyAddress {
                network_id,
                addrtype: BitcoinZAddressType::ScriptHash,
                bytes: Hash160(my_bytes),
            }))
        } else {
            None
        }
    }

    /// Determine if the address is a burn address specific to BitcoinZ.
    /// A burn address in BitcoinZ is represented by a specific byte pattern.
    pub fn is_burn(&self) -> bool {
        match self {
            BitcoinZAddress::Legacy(ref legacy_addr) => legacy_addr.bytes == Hash160([0u8; 20]),
        }
    }
}

impl std::fmt::Display for BitcoinZLegacyAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_b58().fmt(f)
    }
}

impl std::fmt::Display for BitcoinZAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BitcoinZAddress::Legacy(ref legacy_addr) => legacy_addr.fmt(f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BitcoinZAddress, BitcoinZLegacyAddress, BitcoinZAddressType};
    use bitcoinz_common::util::hash::Hash160;

    #[test]
    fn test_from_scriptpubkey() {
        let p2pkh_script = hex::decode("76a9146ea17fc39169cdd9f2414a893aa5ce0c4b4c893488ac").unwrap();
        let p2sh_script = hex::decode("a9142c2edf39b098e05cf770e6b5a2fcedb54ee4fe0587").unwrap();

        let p2pkh_address = BitcoinZAddress::from_scriptpubkey(
            BitcoinZNetworkType::Mainnet,
            &p2pkh_script,
        );

        assert_eq!(
            p2pkh_address,
            Some(BitcoinZAddress::Legacy(BitcoinZLegacyAddress {
                network_id: BitcoinZNetworkType::Mainnet,
                addrtype: BitcoinZAddressType::PublicKeyHash,
                bytes: Hash160::from_hex("6ea17fc39169cdd9f2414a893aa5ce0c4b4c8934").unwrap(),
            }))
        );

        let p2sh_address = BitcoinZAddress::from_scriptpubkey(
            BitcoinZNetworkType::Mainnet,
            &p2sh_script,
        );

        assert_eq!(
            p2sh_address,
            Some(BitcoinZAddress::Legacy(BitcoinZLegacyAddress {
                network_id: BitcoinZNetworkType::Mainnet,
                addrtype: BitcoinZAddressType::ScriptHash,
                bytes: Hash160::from_hex("2c2edf39b098e05cf770e6b5a2fcedb54ee4fe05").unwrap(),
            }))
        );
    }
}
// Segment 5: Enhancing BitcoinZ-specific functionality

impl BitcoinZLegacyAddress {
    /// Convert the address to Base58Check encoding.
    pub fn to_b58(&self) -> String {
        let mut versioned_bytes = vec![self.addrtype.to_version_byte(self.network_id)];
        versioned_bytes.extend_from_slice(&self.bytes.0);
        base58::check_encode_slice(&versioned_bytes)
    }

    /// Create a P2PKH TxOut for BitcoinZ.
    pub fn to_p2pkh_tx_out(bytes: &Hash160, value: u64) -> TxOut {
        let script_pubkey = ZBTCZScriptBuilder::new()
            .push_opcode(ZBTCZOp::OP_DUP)
            .push_opcode(ZBTCZOp::OP_HASH160)
            .push_slice(&bytes.0)
            .push_opcode(ZBTCZOp::OP_EQUALVERIFY)
            .push_opcode(ZBTCZOp::OP_CHECKSIG)
            .into_script();
        TxOut {
            value,
            script_pubkey,
        }
    }

    /// Create a P2SH TxOut for BitcoinZ.
    pub fn to_p2sh_tx_out(bytes: &Hash160, value: u64) -> TxOut {
        let script_pubkey = ZBTCZScriptBuilder::new()
            .push_opcode(ZBTCZOp::OP_HASH160)
            .push_slice(&bytes.0)
            .push_opcode(ZBTCZOp::OP_EQUAL)
            .into_script();
        TxOut {
            value,
            script_pubkey,
        }
    }

    /// Instantiate a legacy address from a Base58Check string specific to BitcoinZ.
    pub fn from_b58(addr_b58: &str) -> Result<BitcoinZLegacyAddress, btc_error> {
        let bytes = base58::from_check(addr_b58).map_err(|_e| btc_error::InvalidByteSequence)?;

        if bytes.len() != 21 {
            return Err(btc_error::InvalidByteSequence);
        }

        let version_byte = bytes[0];
        let addrtype = BitcoinZAddressType::from_version_byte(version_byte)
            .ok_or(btc_error::InvalidAddressType)?;

        let mut payload_bytes = [0; 20];
        payload_bytes.copy_from_slice(&bytes[1..]);

        Ok(BitcoinZLegacyAddress {
            network_id: BitcoinZNetworkType::from_version_byte(version_byte)?,
            addrtype,
            bytes: Hash160(payload_bytes),
        })
    }
}
// Segment 6: Extending adaptations for BitcoinZ

impl BitcoinZAddress {
    /// Construct a BitcoinZ address from raw bytes.
    /// This function validates the byte length to ensure compatibility with BitcoinZ.
    pub fn from_bytes(network_id: BitcoinZNetworkType, addrtype: BitcoinZAddressType, bytes: &[u8]) -> Option<BitcoinZAddress> {
        if bytes.len() != 20 {
            return None;
        }

        let mut my_bytes = [0; 20];
        my_bytes.copy_from_slice(bytes);

        Some(BitcoinZAddress::Legacy(BitcoinZLegacyAddress {
            network_id,
            addrtype,
            bytes: Hash160(my_bytes),
        }))
    }

    /// Determine the type of BitcoinZ address from a scriptPubKey.
    pub fn detect_type_from_script(scriptpubkey: &[u8]) -> Option<BitcoinZAddressType> {
        if scriptpubkey.len() == 25
            && scriptpubkey[0..3] == [0x76, 0xa9, 0x14] // P2PKH prefix
            && scriptpubkey[23..25] == [0x88, 0xac] // P2PKH suffix
        {
            Some(BitcoinZAddressType::PublicKeyHash)
        } else if scriptpubkey.len() == 23
            && scriptpubkey[0..2] == [0xa9, 0x14] // P2SH prefix
            && scriptpubkey[22] == 0x87 // P2SH suffix
        {
            Some(BitcoinZAddressType::ScriptHash)
        } else {
            None
        }
    }
}

impl Address for BitcoinZAddress {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            BitcoinZAddress::Legacy(ref legacy_addr) => legacy_addr.bytes.as_bytes().to_vec(),
        }
    }

    fn from_string(s: &str) -> Option<BitcoinZAddress> {
        match BitcoinZLegacyAddress::from_b58(s) {
            Ok(addr) => Some(BitcoinZAddress::Legacy(addr)),
            Err(_) => None,
        }
    }

    fn is_burn(&self) -> bool {
        match self {
            BitcoinZAddress::Legacy(ref legacy_addr) => legacy_addr.bytes == Hash160([0u8; 20]),
        }
    }
}

#[cfg(test)]
mod more_tests {
    use super::{BitcoinZAddress, BitcoinZAddressType, BitcoinZLegacyAddress};
    use bitcoinz_common::util::hash::Hash160;

    #[test]
    fn test_from_bytes() {
        let bytes = [0x6e, 0xa1, 0x7f, 0xc3, 0x91, 0x69, 0xcd, 0xd9, 0xf2, 0x41, 0x4a, 0x89, 0x3a, 0xa5, 0xce, 0x0c, 0x4b, 0x4c, 0x89, 0x34];

        let address = BitcoinZAddress::from_bytes(
            BitcoinZNetworkType::Mainnet,
            BitcoinZAddressType::PublicKeyHash,
            &bytes,
        );

        assert_eq!(
            address,
            Some(BitcoinZAddress::Legacy(BitcoinZLegacyAddress {
                network_id: BitcoinZNetworkType::Mainnet,
                addrtype: BitcoinZAddressType::PublicKeyHash,
                bytes: Hash160(bytes),
            }))
        );
    }

    #[test]
    fn test_detect_type_from_script() {
        let p2pkh_script = hex::decode("76a9146ea17fc39169cdd9f2414a893aa5ce0c4b4c893488ac").unwrap();
        let p2sh_script = hex::decode("a9142c2edf39b098e05cf770e6b5a2fcedb54ee4fe0587").unwrap();

        assert_eq!(
            BitcoinZAddress::detect_type_from_script(&p2pkh_script),
            Some(BitcoinZAddressType::PublicKeyHash)
        );
        assert_eq!(
            BitcoinZAddress::detect_type_from_script(&p2sh_script),
            Some(BitcoinZAddressType::ScriptHash)
        );
    }
}
// Segment 7: Finalizing adaptations for BitcoinZ

impl BitcoinZLegacyAddress {
    /// Serialize the BitcoinZ address to base58 format.
    pub fn to_b58(&self) -> String {
        let mut versioned_bytes = vec![0; 21];
        let version_byte = match self.addrtype {
            BitcoinZAddressType::PublicKeyHash => match self.network_id {
                BitcoinZNetworkType::Mainnet => BTCZ_ADDRESS_VERSION_MAINNET_SINGLESIG,
                BitcoinZNetworkType::Testnet => BTCZ_ADDRESS_VERSION_TESTNET_SINGLESIG,
            },
            BitcoinZAddressType::ScriptHash => match self.network_id {
                BitcoinZNetworkType::Mainnet => BTCZ_ADDRESS_VERSION_MAINNET_MULTISIG,
                BitcoinZNetworkType::Testnet => BTCZ_ADDRESS_VERSION_TESTNET_MULTISIG,
            },
        };

        versioned_bytes[0] = version_byte;
        versioned_bytes[1..21].copy_from_slice(self.bytes.as_bytes());

        base58::check_encode_slice(&versioned_bytes)
    }

    /// Deserialize a BitcoinZ address from a base58 string.
    pub fn from_b58(addr_b58: &str) -> Result<BitcoinZLegacyAddress, btc_error> {
        let decoded = base58::from_check(addr_b58).map_err(|_| btc_error::InvalidByteSequence)?;

        if decoded.len() != 21 {
            return Err(btc_error::InvalidByteSequence);
        }

        let version_byte = decoded[0];
        let addrtype = match version_byte {
            BTCZ_ADDRESS_VERSION_MAINNET_SINGLESIG | BTCZ_ADDRESS_VERSION_TESTNET_SINGLESIG => BitcoinZAddressType::PublicKeyHash,
            BTCZ_ADDRESS_VERSION_MAINNET_MULTISIG | BTCZ_ADDRESS_VERSION_TESTNET_MULTISIG => BitcoinZAddressType::ScriptHash,
            _ => return Err(btc_error::InvalidByteSequence),
        };

        let network_id = match version_byte {
            BTCZ_ADDRESS_VERSION_MAINNET_SINGLESIG | BTCZ_ADDRESS_VERSION_MAINNET_MULTISIG => BitcoinZNetworkType::Mainnet,
            BTCZ_ADDRESS_VERSION_TESTNET_SINGLESIG | BTCZ_ADDRESS_VERSION_TESTNET_MULTISIG => BitcoinZNetworkType::Testnet,
            _ => return Err(btc_error::InvalidByteSequence),
        };

        let mut hash_bytes = [0u8; 20];
        hash_bytes.copy_from_slice(&decoded[1..21]);

        Ok(BitcoinZLegacyAddress {
            addrtype,
            network_id,
            bytes: Hash160(hash_bytes),
        })
    }
}

#[cfg(test)]
mod final_tests {
    use super::{BitcoinZLegacyAddress, BitcoinZNetworkType, BitcoinZAddressType};
    use bitcoinz_common::util::hash::Hash160;

    #[test]
    fn test_to_b58_and_back() {
        let original = BitcoinZLegacyAddress {
            addrtype: BitcoinZAddressType::PublicKeyHash,
            network_id: BitcoinZNetworkType::Mainnet,
            bytes: Hash160::from_hex("6ea17fc39169cdd9f2414a893aa5ce0c4b4c8934").unwrap(),
        };

        let b58 = original.to_b58();
        let parsed = BitcoinZLegacyAddress::from_b58(&b58).unwrap();

        assert_eq!(original, parsed);
    }

    #[test]
    fn test_invalid_b58() {
        let invalid_b58 = "1InvalidB58String12345";
        assert!(BitcoinZLegacyAddress::from_b58(invalid_b58).is_err());
    }
}
// Segment 8: Concluding and extending final touches for BitcoinZ integration

impl BitcoinZAddress {
    /// Converts BitcoinZ address to its hexadecimal representation.
    pub fn to_hex(&self) -> String {
        match self {
            BitcoinZAddress::Legacy(addr) => hex::encode(addr.bytes.as_bytes()),
        }
    }

    /// Attempt to create a BitcoinZ address from a hexadecimal string.
    pub fn from_hex(hex_str: &str, addrtype: BitcoinZAddressType, network_id: BitcoinZNetworkType) -> Option<Self> {
        if let Ok(bytes) = hex::decode(hex_str) {
            if bytes.len() == 20 {
                let mut hash_bytes = [0u8; 20];
                hash_bytes.copy_from_slice(&bytes);
                return Some(BitcoinZAddress::Legacy(BitcoinZLegacyAddress {
                    addrtype,
                    network_id,
                    bytes: Hash160(hash_bytes),
                }));
            }
        }
        None
    }
}

#[cfg(test)]
mod additional_tests {
    use super::*;

    #[test]
    fn test_to_hex_and_from_hex() {
        let addr = BitcoinZLegacyAddress {
            addrtype: BitcoinZAddressType::PublicKeyHash,
            network_id: BitcoinZNetworkType::Mainnet,
            bytes: Hash160::from_hex("6ea17fc39169cdd9f2414a893aa5ce0c4b4c8934").unwrap(),
        };

        let hex_repr = BitcoinZAddress::Legacy(addr.clone()).to_hex();
        assert_eq!(hex_repr, "6ea17fc39169cdd9f2414a893aa5ce0c4b4c8934");

        let reconstructed = BitcoinZAddress::from_hex(&hex_repr, addr.addrtype, addr.network_id);
        assert_eq!(reconstructed, Some(BitcoinZAddress::Legacy(addr)));
    }

    #[test]
    fn test_invalid_hex() {
        let invalid_hex = "invalidhex";
        let addr = BitcoinZAddress::from_hex(invalid_hex, BitcoinZAddressType::PublicKeyHash, BitcoinZNetworkType::Mainnet);
        assert!(addr.is_none());
    }
}
