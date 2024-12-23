// Segment 1: Initial setup and imports for BitcoinZ

use sha2::{Digest, Sha256};
use bitcoinz_common::address::{public_keys_to_address_hash, AddressHashMode};
use bitcoinz_common::deps_common::btcz::blockdata::opcodes::{All as BtczOpcodes, Class};
use bitcoinz_common::deps_common::btcz::blockdata::script::{Builder, Instruction, Script};
use bitcoinz_common::deps_common::btcz::blockdata::transaction::{
    TxIn as BtczTxIn, TxOut as BtczTxOut,
};
use bitcoinz_common::deps_common::btcz::util::hash::Sha256dHash;
use bitcoinz_common::types::chainstate::BurnchainHeaderHash;
use bitcoinz_common::util::hash::{hex_bytes, Hash160};
use bitcoinz_common::util::log;

use crate::burnchains::bitcoinz::address::{BitcoinZAddress, LegacyBitcoinZAddressType};
use crate::burnchains::bitcoinz::keys::BitcoinZPublicKey;
use crate::burnchains::bitcoinz::{
    BitcoinZInputType, BitcoinZNetworkType, BitcoinZTxInput, BitcoinZTxInputRaw,
    BitcoinZTxInputStructured, BitcoinZTxOutput, Error as btcz_error,
};
use crate::burnchains::{PublicKey, Txid};
use crate::chainstate::zbtc::{
    ZBTC_ADDRESS_VERSION_MAINNET_MULTISIG, ZBTC_ADDRESS_VERSION_MAINNET_SINGLESIG,
    ZBTC_ADDRESS_VERSION_TESTNET_MULTISIG, ZBTC_ADDRESS_VERSION_TESTNET_SINGLESIG,
};

/// Parse a script into its structured constituent opcodes and data and collect them
pub fn parse_script<'a>(script: &'a Script) -> Vec<Instruction<'a>> {
    // Accept non-minimal pushdata as it exists in the BitcoinZ transaction stream.
    script.iter(false).collect()
}

impl BitcoinZTxInputStructured {
    /// Parse a script instruction stream encoding a P2PKH scriptSig into a BitcoinZTxInput
    pub fn from_btcz_p2pkh_script_sig(
        instructions: &Vec<Instruction>,
        input_txid: (Txid, u32),
    ) -> Option<BitcoinZTxInputStructured> {
        if instructions.len() != 2 {
            return None;
        }

        let i1 = &instructions[0];
        let i2 = &instructions[1];

        match (i1, i2) {
            (Instruction::PushBytes(ref _data1), Instruction::PushBytes(ref data2)) => {
                match BitcoinZPublicKey::from_slice(data2) {
                    Ok(pubkey) => {
                        Some(BitcoinZTxInputStructured {
                            tx_ref: input_txid,
                            keys: vec![pubkey],
                            num_required: 1,
                            in_type: BitcoinZInputType::Standard,
                        })
                    }
                    Err(_) => None,
                }
            }
            _ => None,
        }
    }
}
// Segment 2: Continuing the adaptation of `bits.rs` for BitcoinZ integration

impl BitcoinZTxInputStructured {
    /// Parse a script instruction stream encoding a p2pkh scriptSig into a BitcoinZTxInput
    pub fn from_bitcoinz_p2pkh_script_sig(
        instructions: &Vec<Instruction>,
        input_txid: (Txid, u32),
    ) -> Option<BitcoinZTxInputStructured> {
        if instructions.len() != 2 {
            return None;
        }

        let i1 = &instructions[0];
        let i2 = &instructions[1];

        match (i1, i2) {
            (Instruction::PushBytes(ref _data1), Instruction::PushBytes(ref data2)) => {
                // data2 is a pubkey?
                match BitcoinZPublicKey::from_slice(data2) {
                    Ok(pubkey) => {
                        // Valid public key
                        Some(BitcoinZTxInputStructured {
                            tx_ref: input_txid,
                            keys: vec![pubkey],
                            num_required: 1,
                            in_type: BitcoinZInputType::Standard,
                        })
                    }
                    Err(_) => None, // Not a p2pkh scriptSig
                }
            }
            (_, _) => None,
        }
    }

    /// Parse BitcoinZ transaction inputs for multisig scripts
    fn from_bitcoinz_pubkey_pushbytes(
        num_sigs: usize,
        pubkey_pushbytes: &[Instruction],
        input_txid: (Txid, u32),
    ) -> Option<BitcoinZTxInputStructured> {
        if num_sigs < 1 || pubkey_pushbytes.len() < num_sigs {
            return None;
        }

        let mut keys: Vec<BitcoinZPublicKey> = Vec::with_capacity(pubkey_pushbytes.len());

        for instr in pubkey_pushbytes {
            if let Instruction::PushBytes(payload) = instr {
                match BitcoinZPublicKey::from_slice(payload) {
                    Ok(pubkey) => keys.push(pubkey),
                    Err(_) => return None, // Not a valid public key
                }
            } else {
                return None; // Not a PushBytes instruction
            }
        }

        Some(BitcoinZTxInputStructured {
            tx_ref: input_txid,
            keys,
            num_required: num_sigs,
            in_type: BitcoinZInputType::Multisig,
        })
    }
}
// Segment 3: Extending BitcoinZ-specific adaptations for `bits.rs`

impl BitcoinZTxInputStructured {
    /// Parse a BitcoinZ transaction's witness as p2wpkh-over-p2sh.
    fn from_bitcoinz_p2wpkh_p2sh_witness(
        instructions: &Vec<Instruction>,
        witness: &Vec<Vec<u8>>,
        input_txid: (Txid, u32),
    ) -> Option<BitcoinZTxInputStructured> {
        if instructions.len() != 1 {
            return None;
        }
        if witness.len() != 2 {
            return None;
        }

        if let Instruction::PushBytes(witness_hash) = &instructions[0] {
            if witness_hash.len() != 22 {
                return None; // Invalid witness hash length
            }
            if witness_hash[0] != 0 || witness_hash[1] != 20 {
                return None; // Not a version-0 witness program
            }

            BitcoinZTxInputStructured::from_bitcoinz_pubkey_pushbytes(
                1,
                &vec![Instruction::PushBytes(&witness[1])],
                input_txid,
            )
        } else {
            None // Not a valid witness program
        }
    }

    /// Parse a p2wsh-over-p2sh multisig redeem script
    fn from_bitcoinz_p2wsh_p2sh_multisig(
        instructions: &Vec<Instruction>,
        witness: &Vec<Vec<u8>>,
        input_txid: (Txid, u32),
    ) -> Option<BitcoinZTxInputStructured> {
        if instructions.len() != 1 {
            return None;
        }
        if witness.len() < 2 {
            return None;
        }

        if let Instruction::PushBytes(witness_hash) = &instructions[0] {
            if witness_hash.len() != 34 || witness_hash[0] != 0 || witness_hash[1] != 32 {
                return None; // Invalid witness hash
            }

            let redeem_script = &witness[witness.len() - 1];
            let tx_input = BitcoinZTxInputStructured::from_bitcoinz_multisig_redeem_script(
                &Instruction::PushBytes(redeem_script),
                true,
                input_txid,
            )?;

            if witness.len() - 2 != tx_input.num_required {
                return None; // Mismatched signatures and required signatures
            }

            Some(tx_input)
        } else {
            None // Not a valid witness hash script
        }
    }

    /// Parse a BitcoinZ multisig redeem script
    fn from_bitcoinz_multisig_redeem_script(
        redeem_script: &Instruction,
        segwit: bool,
        input_txid: (Txid, u32),
    ) -> Option<BitcoinZTxInputStructured> {
        if let Instruction::PushBytes(script_bytes) = redeem_script {
            let script = Script::from(script_bytes.to_vec());
            let instructions = parse_script(&script);

            if instructions.len() < 4 {
                return None; // Not enough instructions for a multisig script
            }

            match (
                &instructions[0],
                &instructions[instructions.len() - 2],
                &instructions[instructions.len() - 1],
            ) {
                (
                    Instruction::Op(op1),
                    Instruction::Op(op2),
                    Instruction::Op(BitcoinZOpCodes::OP_CHECKMULTISIG),
                ) => {
                    if let (
                        BitcoinZOpCodes::from(*op1).classify(),
                        BitcoinZOpCodes::from(*op2).classify(),
                    ) = (Class::PushNum(num_sigs), Class::PushNum(num_pubkeys))
                    {
                        if num_sigs < 1
                            || num_pubkeys < 1
                            || num_pubkeys < num_sigs
                            || num_pubkeys != (instructions.len() - 3) as i32
                        {
                            return None; // Invalid multisig script
                        }

                        let pubkey_instructions =
                            &instructions[1..instructions.len() - 2];

                        BitcoinZTxInputStructured::from_bitcoinz_pubkey_pushbytes(
                            num_sigs as usize,
                            pubkey_instructions,
                            input_txid,
                        )
                    } else {
                        None
                    }
                }
                _ => None,
            }
        } else {
            None // Not a PushBytes instruction
        }
    }
}
// Segment 4: Continuing BitcoinZ-specific adaptations for `bits.rs`

impl BitcoinZTxInputStructured {
    /// Parse a p2sh multisig scriptSig
    fn from_bitcoinz_p2sh_multisig_script_sig(
        instructions: &Vec<Instruction>,
        input_txid: (Txid, u32),
    ) -> Option<BitcoinZTxInputStructured> {
        if instructions.len() < 3 || instructions[0] != Instruction::PushBytes(&[]) {
            return None; // Invalid script format
        }

        let redeem_script = &instructions[instructions.len() - 1];
        let tx_input = BitcoinZTxInputStructured::from_bitcoinz_multisig_redeem_script(
            redeem_script,
            false,
            input_txid,
        )?;

        if instructions.len() - 2 != tx_input.num_required {
            return None; // Signature count mismatch
        }

        Some(tx_input)
    }

    /// Parse BitcoinZ witness data for multisig
    fn from_bitcoinz_witness_multisig(
        witness: &Vec<Vec<u8>>,
        input_txid: (Txid, u32),
    ) -> Option<BitcoinZTxInputStructured> {
        if witness.len() < 3 {
            return None; // Invalid witness length
        }

        let redeem_script = &witness[witness.len() - 1];
        let tx_input = BitcoinZTxInputStructured::from_bitcoinz_multisig_redeem_script(
            &Instruction::PushBytes(&redeem_script),
            true,
            input_txid,
        )?;

        if witness.len() - 2 != tx_input.num_required {
            return None; // Signature count mismatch
        }

        Some(tx_input)
    }
}

impl BitcoinZTxInputRaw {
    pub fn from_hex_parts(scriptsig: &str, witness: &[&str]) -> BitcoinZTxInputRaw {
        let witness_bytes: Vec<_> = witness.iter().map(|w| hex_bytes(w).unwrap()).collect();
        BitcoinZTxInputRaw {
            scriptSig: hex_bytes(scriptsig).unwrap(),
            witness: witness_bytes,
            tx_ref: (Txid([0u8; 32]), 0),
        }
    }

    pub fn from_bitcoinz_witness_script_sig(
        script_sig: &Script,
        witness: Vec<Vec<u8>>,
        input_txid: (Txid, u32),
    ) -> BitcoinZTxInputRaw {
        BitcoinZTxInputRaw {
            scriptSig: script_sig.clone().into_bytes(),
            witness,
            tx_ref: input_txid,
        }
    }
}
// Segment 5: Continuing BitcoinZ-specific adaptations for `bits.rs`

impl BitcoinZTxOutput {
    /// Parse a BitcoinZTxOutput from a BitcoinZ scriptPubKey and its value in satoshis.
    /// This implementation supports legacy outputs (p2pkh, p2sh).
    pub fn from_bitcoinz_script_pubkey_legacy(
        network_id: BitcoinZNetworkType,
        script_pubkey: &Script,
        amount: u64,
    ) -> Option<BitcoinZTxOutput> {
        let script_bytes = script_pubkey.to_bytes();
        let address = if script_pubkey.is_p2pkh() {
            BitcoinZAddress::from_bytes_legacy(
                network_id,
                LegacyBitcoinZAddressType::PublicKeyHash,
                &script_bytes[3..23],
            )
        } else if script_pubkey.is_p2sh() {
            BitcoinZAddress::from_bytes_legacy(
                network_id,
                LegacyBitcoinZAddressType::ScriptHash,
                &script_bytes[2..22],
            )
        } else {
            Err(btc_error::InvalidByteSequence)
        };

        match address {
            Ok(addr) => Some(BitcoinZTxOutput {
                address: addr,
                units: amount,
            }),
            Err(_) => None,
        }
    }

    /// Parse a BitcoinZTxOutput from a BitcoinZ scriptPubKey and its value in satoshis.
    /// Supports all address types including legacy and segwit outputs.
    pub fn from_bitcoinz_script_pubkey(
        network_id: BitcoinZNetworkType,
        script_pubkey: &Script,
        amount: u64,
    ) -> Option<BitcoinZTxOutput> {
        let script_bytes = script_pubkey.to_bytes();
        let address = BitcoinZAddress::from_scriptpubkey(network_id, &script_bytes)?;
        Some(BitcoinZTxOutput {
            address,
            units: amount,
        })
    }

    /// Parse a burnchain transaction output from a BitcoinZ output.
    /// This method only supports legacy outputs.
    pub fn from_bitcoinz_txout_legacy(
        network_id: BitcoinZNetworkType,
        txout: &BitcoinZTxOut,
    ) -> Option<BitcoinZTxOutput> {
        BitcoinZTxOutput::from_bitcoinz_script_pubkey_legacy(
            network_id,
            &txout.script_pubkey,
            txout.value,
        )
    }

    /// Parse a burnchain transaction output from a BitcoinZ output.
    /// Supports both legacy and segwit outputs.
    pub fn from_bitcoinz_txout(
        network_id: BitcoinZNetworkType,
        txout: &BitcoinZTxOut,
    ) -> Option<BitcoinZTxOutput> {
        BitcoinZTxOutput::from_bitcoinz_script_pubkey(
            network_id,
            &txout.script_pubkey,
            txout.value,
        )
    }
}
// Segment 6: Continuing adaptations for BitcoinZ-specific `bits.rs`

impl BitcoinZTxInputRaw {
    /// Construct a raw BitcoinZ transaction input from witness and scriptSig.
    pub fn from_bitcoinz_witness_script_sig(
        script_sig: &Script,
        witness: Vec<Vec<u8>>,
        input_txid: (Txid, u32),
    ) -> BitcoinZTxInputRaw {
        BitcoinZTxInputRaw {
            scriptSig: script_sig.clone().into_bytes(),
            witness,
            tx_ref: input_txid,
        }
    }
}

impl BitcoinZTxInput {
    /// Parse a BitcoinZ transaction input into a raw format.
    /// Always succeeds by wrapping the raw input details.
    pub fn from_bitcoinz_txin_raw(txin: &BtcTxIn) -> BitcoinZTxInput {
        BitcoinZTxInput::Raw(BitcoinZTxInputRaw {
            scriptSig: txin.script_sig.clone().into_bytes(),
            witness: txin.witness.clone(),
            tx_ref: to_txid(txin),
        })
    }

    /// Parse a BitcoinZ transaction input into a structured format.
    /// Returns None if the input cannot be parsed into a recognizable format.
    pub fn from_bitcoinz_txin_structured(txin: &BtcTxIn) -> Option<BitcoinZTxInput> {
        let input_txid = to_txid(txin);
        match txin.witness.len() {
            0 => {
                // Not a segwit transaction
                BitcoinZTxInputStructured::from_bitcoinz_script_sig(
                    &txin.script_sig,
                    input_txid,
                )
                .map(|input| input.into())
            }
            _ => {
                // Possibly a segwit transaction
                BitcoinZTxInputStructured::from_bitcoinz_witness_script_sig(
                    &txin.script_sig,
                    &txin.witness,
                    input_txid,
                )
                .map(|input| input.into())
            }
        }
    }

    pub fn tx_ref(&self) -> &(Txid, u32) {
        match self {
            BitcoinZTxInput::Structured(ref inp) => &inp.tx_ref,
            BitcoinZTxInput::Raw(ref inp) => &inp.tx_ref,
        }
    }
}

fn to_txid(txin: &BtcTxIn) -> (Txid, u32) {
    let mut bits = txin.previous_output.txid.0.clone();
    bits.reverse();
    (Txid(bits), txin.previous_output.vout)
}

impl BitcoinZTxOutput {
    /// Parse a BitcoinZ transaction output from a scriptPubKey and value in satoshis.
    pub fn from_bitcoinz_script_pubkey(
        network_id: BitcoinZNetworkType,
        script_pubkey: &Script,
        amount: u64,
    ) -> Option<BitcoinZTxOutput> {
        let script_bytes = script_pubkey.to_bytes();
        let address = BitcoinZAddress::from_scriptpubkey(network_id, &script_bytes)?;
        Some(BitcoinZTxOutput {
            address,
            units: amount,
        })
    }

    /// Parse a BitcoinZ transaction output for legacy formats.
    pub fn from_bitcoinz_txout(
        network_id: BitcoinZNetworkType,
        txout: &BtcTxOut,
    ) -> Option<BitcoinZTxOutput> {
        BitcoinZTxOutput::from_bitcoinz_script_pubkey(network_id, &txout.script_pubkey, txout.value)
    }
}
// Segment 7: Finalizing BitcoinZ-specific adaptations for `bits.rs`

impl BitcoinZTxOutput {
    /// Convert a BitcoinZ transaction output into its serialized form.
    pub fn to_serialized_form(&self) -> Vec<u8> {
        let mut serialized = Vec::new();
        serialized.extend_from_slice(&self.address.to_bytes());
        serialized.extend(&self.units.to_le_bytes());
        serialized
    }

    /// Create a BitcoinZTxOutput from its serialized form.
    pub fn from_serialized_form(serialized: &[u8]) -> Option<BitcoinZTxOutput> {
        if serialized.len() < 28 {
            return None; // Insufficient bytes
        }
        let (address_bytes, units_bytes) = serialized.split_at(serialized.len() - 8);
        let address = BitcoinZAddress::from_bytes(address_bytes)?;
        let units = u64::from_le_bytes(units_bytes.try_into().ok()?);
        Some(BitcoinZTxOutput { address, units })
    }
}

impl BitcoinZTxInputStructured {
    /// Serialize a structured BitcoinZ transaction input.
    pub fn to_serialized_form(&self) -> Vec<u8> {
        let mut serialized = Vec::new();
        serialized.extend_from_slice(&self.tx_ref.0 .0);
        serialized.extend(&self.tx_ref.1.to_le_bytes());
        serialized.push(self.num_required as u8);
        for key in &self.keys {
            serialized.extend_from_slice(&key.to_bytes());
        }
        serialized
    }

    /// Deserialize a structured BitcoinZ transaction input from bytes.
    pub fn from_serialized_form(serialized: &[u8]) -> Option<BitcoinZTxInputStructured> {
        if serialized.len() < 33 {
            return None; // Minimum size for tx_ref + num_required
        }
        let (tx_ref_bytes, rest) = serialized.split_at(32);
        let (vout_bytes, rest) = rest.split_at(4);
        let txid = Txid(tx_ref_bytes.try_into().ok()?);
        let vout = u32::from_le_bytes(vout_bytes.try_into().ok()?);
        let tx_ref = (txid, vout);

        let num_required = *rest.first()? as usize;
        let mut keys = Vec::new();
        let mut remainder = &rest[1..];
        while remainder.len() >= 33 {
            let (key_bytes, rest) = remainder.split_at(33);
            let key = BitcoinZPublicKey::from_slice(key_bytes).ok()?;
            keys.push(key);
            remainder = rest;
        }

        Some(BitcoinZTxInputStructured {
            tx_ref,
            num_required,
            keys,
            in_type: BitcoinZInputType::Standard, // Default type
        })
    }
}

impl BitcoinZTxInputRaw {
    /// Serialize a raw BitcoinZ transaction input.
    pub fn to_serialized_form(&self) -> Vec<u8> {
        let mut serialized = Vec::new();
        serialized.extend_from_slice(&self.tx_ref.0 .0);
        serialized.extend(&self.tx_ref.1.to_le_bytes());
        serialized.extend_from_slice(&self.scriptSig);
        serialized.push(self.witness.len() as u8);
        for item in &self.witness {
            serialized.push(item.len() as u8);
            serialized.extend_from_slice(item);
        }
        serialized
    }

    /// Deserialize a raw BitcoinZ transaction input from bytes.
    pub fn from_serialized_form(serialized: &[u8]) -> Option<BitcoinZTxInputRaw> {
        if serialized.len() < 36 {
            return None; // Minimum size for tx_ref + scriptSig length
        }
        let (tx_ref_bytes, rest) = serialized.split_at(32);
        let (vout_bytes, rest) = rest.split_at(4);
        let txid = Txid(tx_ref_bytes.try_into().ok()?);
        let vout = u32::from_le_bytes(vout_bytes.try_into().ok()?);
        let tx_ref = (txid, vout);

        let scriptSig_len = rest[0] as usize;
        let (scriptSig, rest) = rest[1..].split_at(scriptSig_len);

        let witness_count = rest[0] as usize;
        let mut witness = Vec::new();
        let mut remainder = &rest[1..];
        for _ in 0..witness_count {
            if remainder.is_empty() {
                return None; // Incomplete witness data
            }
            let item_len = remainder[0] as usize;
            if remainder.len() < item_len + 1 {
                return None; // Witness item length exceeds available bytes
            }
            let (item, rest) = remainder[1..].split_at(item_len);
            witness.push(item.to_vec());
            remainder = rest;
        }

        Some(BitcoinZTxInputRaw {
            tx_ref,
            scriptSig: scriptSig.to_vec(),
            witness,
        })
    }
}
// Segment 8: Additional BitcoinZ-specific functions and utilities

impl BitcoinZAddress {
    /// Convert BitcoinZ address to base58 encoding for legacy support.
    pub fn to_base58(&self) -> Option<String> {
        match self {
            BitcoinZAddress::Legacy(addr) => Some(base58::check_encode_slice(&addr.to_versioned_bytes())),
            _ => None, // Only legacy addresses support base58 encoding
        }
    }

    /// Parse a BitcoinZ address from a base58-encoded string.
    pub fn from_base58(encoded: &str) -> Option<BitcoinZAddress> {
        let bytes = base58::from_check(encoded).ok()?;
        let addr = BitcoinZLegacyAddress::from_versioned_bytes(&bytes).ok()?;
        Some(BitcoinZAddress::Legacy(addr))
    }

    /// Convert BitcoinZ address to serialized bytes.
    pub fn to_serialized_form(&self) -> Vec<u8> {
        match self {
            BitcoinZAddress::Legacy(addr) => addr.to_versioned_bytes().to_vec(),
            BitcoinZAddress::Bech32(addr) => addr.to_serialized_bytes(),
        }
    }

    /// Parse a BitcoinZ address from serialized bytes.
    pub fn from_serialized_form(serialized: &[u8]) -> Option<BitcoinZAddress> {
        BitcoinZLegacyAddress::from_versioned_bytes(serialized)
            .map(BitcoinZAddress::Legacy)
            .or_else(|| BitcoinZBech32Address::from_serialized_bytes(serialized).map(BitcoinZAddress::Bech32))
    }
}

impl BitcoinZLegacyAddress {
    /// Create a legacy address from versioned bytes.
    pub fn from_versioned_bytes(bytes: &[u8]) -> Result<Self, BitcoinZError> {
        if bytes.len() != 21 {
            return Err(BitcoinZError::InvalidByteSequence);
        }
        let version = bytes[0];
        let payload = &bytes[1..];

        let addrtype = match version {
            BITCOINZ_ADDRESS_VERSION_MAINNET_SINGLESIG => BitcoinZLegacyAddressType::PublicKeyHash,
            BITCOINZ_ADDRESS_VERSION_MAINNET_MULTISIG => BitcoinZLegacyAddressType::ScriptHash,
            _ => return Err(BitcoinZError::InvalidVersionByte),
        };

        Ok(BitcoinZLegacyAddress {
            addrtype,
            network_id: BitcoinZNetworkType::Mainnet,
            bytes: Hash160::from_slice(payload).ok_or(BitcoinZError::InvalidPayloadBytes)?,
        })
    }

    /// Serialize the legacy address into versioned bytes.
    pub fn to_versioned_bytes(&self) -> [u8; 21] {
        let mut result = [0; 21];
        result[0] = match self.addrtype {
            BitcoinZLegacyAddressType::PublicKeyHash => BITCOINZ_ADDRESS_VERSION_MAINNET_SINGLESIG,
            BitcoinZLegacyAddressType::ScriptHash => BITCOINZ_ADDRESS_VERSION_MAINNET_MULTISIG,
        };
        result[1..].copy_from_slice(&self.bytes.0);
        result
    }
}

impl BitcoinZBech32Address {
    /// Serialize the Bech32 address into bytes.
    pub fn to_serialized_bytes(&self) -> Vec<u8> {
        let mut serialized = Vec::new();
        serialized.push(self.witness_version);
        serialized.extend(&self.program);
        serialized
    }

    /// Deserialize bytes into a Bech32 address.
    pub fn from_serialized_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }
        let witness_version = bytes[0];
        let program = bytes[1..].to_vec();
        Some(BitcoinZBech32Address {
            witness_version,
            program,
        })
    }
}
// Segment 9: Address and Input Validation for BitcoinZ Transactions

impl BitcoinZTxInputStructured {
    /// Validate the integrity of a structured BitcoinZ transaction input.
    pub fn validate(&self) -> Result<(), BitcoinZError> {
        if self.num_required == 0 || self.num_required > self.keys.len() {
            return Err(BitcoinZError::InvalidInput(
                "Invalid number of required signatures".to_string(),
            ));
        }

        for key in &self.keys {
            if key.is_invalid() {
                return Err(BitcoinZError::InvalidInput(
                    "Invalid public key in input".to_string(),
                ));
            }
        }
        Ok(())
    }
}

impl BitcoinZTxOutput {
    /// Validate the BitcoinZ transaction output.
    pub fn validate(&self) -> Result<(), BitcoinZError> {
        if self.units == 0 {
            return Err(BitcoinZError::InvalidOutput(
                "Output value cannot be zero".to_string(),
            ));
        }

        if !self.address.is_valid() {
            return Err(BitcoinZError::InvalidOutput(
                "Invalid address in output".to_string(),
            ));
        }
        Ok(())
    }
}

impl BitcoinZAddress {
    /// Check if the BitcoinZ address is valid.
    pub fn is_valid(&self) -> bool {
        match self {
            BitcoinZAddress::Legacy(addr) => addr.validate_checksum(),
            BitcoinZAddress::P2SH(addr) => addr.validate_checksum(),
            BitcoinZAddress::P2PKH(addr) => addr.validate_checksum(),
        }
    }
}

impl BitcoinZPublicKey {
    /// Check if the BitcoinZ public key is valid.
    pub fn is_invalid(&self) -> bool {
        !self.validate_format()
    }

    /// Validate the format of the public key.
    pub fn validate_format(&self) -> bool {
        // Ensure the key is 33 or 65 bytes in length.
        self.bytes.len() == 33 || self.bytes.len() == 65
    }
}
// Segment 10: Finalizing functions and modules for BitcoinZ-specific adaptations

impl BitcoinZTxInput {
    /// Checks if the BitcoinZ transaction input is empty.
    pub fn is_empty(&self) -> bool {
        match self {
            BitcoinZTxInput::Raw(raw) => raw.scriptSig.is_empty() && raw.witness.is_empty(),
            BitcoinZTxInput::Structured(structured) => structured.keys.is_empty(),
        }
    }

    /// Verifies if the BitcoinZ transaction input matches a specific address.
    pub fn matches_address(&self, address: &BitcoinZAddress) -> bool {
        match self {
            BitcoinZTxInput::Raw(raw) => {
                let tx_output_opt = BitcoinZTxOutput::from_scriptSig(&raw.scriptSig, address);
                tx_output_opt.is_some()
            }
            BitcoinZTxInput::Structured(structured) => {
                structured.keys.iter().any(|key| key.to_address() == *address)
            }
        }
    }
}

impl BitcoinZTxOutput {
    /// Calculates the size of the serialized transaction output.
    pub fn serialized_size(&self) -> usize {
        self.address.to_bytes().len() + std::mem::size_of::<u64>()
    }
}

impl BitcoinZAddress {
    /// Validates if the BitcoinZ address follows the required format.
    pub fn validate_format(&self) -> Result<(), String> {
        if self.bytes.len() == 20 {
            Ok(())
        } else {
            Err(format!("Invalid BitcoinZ address length: {}", self.bytes.len()))
        }
    }
}

/// Utility function to calculate the hash of a BitcoinZ public key.
pub fn bitcoinz_public_key_hash(public_key: &BitcoinZPublicKey) -> Hash160 {
    let sha256_digest = Sha256::digest(public_key.to_bytes());
    Hash160::from_ripemd160(Ripemd160::digest(&sha256_digest))
}

/// Validates a BitcoinZ transaction by ensuring its inputs and outputs meet all criteria.
pub fn validate_bitcoinz_transaction(
    inputs: &[BitcoinZTxInput],
    outputs: &[BitcoinZTxOutput],
) -> Result<(), String> {
    if inputs.is_empty() {
        return Err("Transaction must have at least one input".to_string());
    }

    if outputs.is_empty() {
        return Err("Transaction must have at least one output".to_string());
    }

    for input in inputs {
        if input.is_empty() {
            return Err("Found an empty transaction input".to_string());
        }
    }

    for output in outputs {
        if output.serialized_size() > MAX_OUTPUT_SIZE {
            return Err("Output size exceeds maximum allowed limit".to_string());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitcoinz_address_validation() {
        let valid_address = BitcoinZAddress::from_bytes(&[0u8; 20]).unwrap();
        assert!(valid_address.validate_format().is_ok());

        let invalid_address = BitcoinZAddress::from_bytes(&[0u8; 10]).unwrap();
        assert!(invalid_address.validate_format().is_err());
    }

    #[test]
    fn test_transaction_validation() {
        let valid_input = BitcoinZTxInput::Structured(BitcoinZTxInputStructured {
            tx_ref: (Txid([0u8; 32]), 0),
            keys: vec![BitcoinZPublicKey::from_bytes(&[0u8; 33]).unwrap()],
            num_required: 1,
            in_type: BitcoinZInputType::Standard,
        });

        let valid_output = BitcoinZTxOutput {
            address: BitcoinZAddress::from_bytes(&[0u8; 20]).unwrap(),
            units: 1000,
        };

        assert!(validate_bitcoinz_transaction(&[valid_input], &[valid_output]).is_ok());

        let empty_input = BitcoinZTxInput::Raw(BitcoinZTxInputRaw {
            tx_ref: (Txid([0u8; 32]), 0),
            scriptSig: vec![],
            witness: vec![],
        });

        assert!(validate_bitcoinz_transaction(&[empty_input], &[valid_output]).is_err());
    }
}
// Segment 11: Review and ensure alignment with project goals

impl BitcoinZTxInput {
    /// Checks if the BitcoinZ transaction input uses witness data.
    pub fn uses_witness(&self) -> bool {
        match self {
            BitcoinZTxInput::Raw(raw) => !raw.witness.is_empty(),
            BitcoinZTxInput::Structured(_) => false,
        }
    }

    /// Converts the transaction input to a human-readable format.
    pub fn to_human_readable(&self) -> String {
        match self {
            BitcoinZTxInput::Raw(raw) => format!(
                "Raw Input: tx_ref: {:?}, scriptSig: {}, witness count: {}",
                raw.tx_ref,
                hex::encode(&raw.scriptSig),
                raw.witness.len()
            ),
            BitcoinZTxInput::Structured(structured) => format!(
                "Structured Input: tx_ref: {:?}, keys: {:?}, num_required: {}",
                structured.tx_ref,
                structured.keys,
                structured.num_required
            ),
        }
    }
}

impl BitcoinZTxOutput {
    /// Converts the transaction output to a human-readable format.
    pub fn to_human_readable(&self) -> String {
        format!(
            "Output: address: {:?}, units: {}",
            self.address, self.units
        )
    }
}

impl BitcoinZAddress {
    /// Formats the address into a human-readable string.
    pub fn format_for_display(&self) -> String {
        match self {
            BitcoinZAddress::Legacy(addr) => format!("Legacy Address: {:?}", addr),
            BitcoinZAddress::Bech32(addr) => format!("Bech32 Address: {:?}", addr),
        }
    }
}

/// Additional utility functions for BitcoinZ transactions.
impl BitcoinZPublicKey {
    /// Converts the public key to a human-readable format.
    pub fn to_human_readable(&self) -> String {
        format!("PublicKey: {}", hex::encode(&self.bytes))
    }
}

/// Extending BitcoinZ transaction validation.
pub fn extended_bitcoinz_transaction_validation(
    inputs: &[BitcoinZTxInput],
    outputs: &[BitcoinZTxOutput],
) -> Result<(), String> {
    validate_bitcoinz_transaction(inputs, outputs)?;

    for (i, input) in inputs.iter().enumerate() {
        if !input.matches_address(&BitcoinZAddress::default()) {
            return Err(format!("Input {} does not match any expected address.", i));
        }
    }

    Ok(())
}

#[cfg(test)]
mod extended_tests {
    use super::*;

    #[test]
    fn test_human_readable_formats() {
        let input = BitcoinZTxInput::Structured(BitcoinZTxInputStructured {
            tx_ref: (Txid([0u8; 32]), 0),
            keys: vec![BitcoinZPublicKey::from_bytes(&[0u8; 33]).unwrap()],
            num_required: 1,
            in_type: BitcoinZInputType::Standard,
        });

        let output = BitcoinZTxOutput {
            address: BitcoinZAddress::from_bytes(&[0u8; 20]).unwrap(),
            units: 1000,
        };

        assert!(input.to_human_readable().contains("Structured Input"));
        assert!(output.to_human_readable().contains("Output"));
    }
}
