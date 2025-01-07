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

use std::ops::Deref;

use zbtc_common::deps_common::btcz::blockdata::block::{Block, LoneBlockHeader};
use zbtc_common::deps_common::btcz::blockdata::opcodes::All as btcz_opcodes;
use zbtc_common::deps_common::btcz::blockdata::script::{Instruction, Script};
use zbtc_common::deps_common::btcz::blockdata::transaction::Transaction;
use zbtc_common::deps_common::btcz::network::message as btcz_message;
use zbtc_common::deps_common::btcz::network::serialize::BtczHash;
use zbtc_common::deps_common::btcz::util::hash::btcz_merkle_root;
use zbtc_common::types::chainstate::BurnchainHeaderHash;
use zbtc_common::util::hash::to_hex;
use zbtc_common::util::log;

use crate::burnchains::btcz::address::BtczAddress;
use crate::burnchains::btcz::indexer::BtczIndexer;
use crate::burnchains::btcz::keys::BtczPublicKey;
use crate::burnchains::btcz::messages::BtczMessageHandler;
use crate::burnchains::btcz::{
    bits, BtczBlock, BtczInputType, BtczNetworkType, BtczTransaction, BtczTxInput,
    BtczTxOutput, Error as btcz_error, PeerMessage,
};
use crate::burnchains::indexer::{
    BurnBlockIPC, BurnHeaderIPC, BurnchainBlockDownloader, BurnchainBlockParser,
};
use crate::burnchains::{
    BurnchainBlock, BurnchainTransaction, Error as burnchain_error, MagicBytes, Txid,
    MAGIC_BYTES_LENGTH,
};
use crate::core::ZookEpochId;
use crate::deps;

#[derive(Debug, Clone, PartialEq)]
pub struct BtczHeaderIPC {
    pub block_header: LoneBlockHeader,
    pub block_height: u64,
}

impl BurnHeaderIPC for BtczHeaderIPC {
    type H = LoneBlockHeader;

    fn header(&self) -> LoneBlockHeader {
        self.block_header.clone()
    }

    fn height(&self) -> u64 {
        self.block_height
    }

    fn header_hash(&self) -> [u8; 32] {
        self.block_header.header.btcz_hash().0
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct BtczBlockIPC {
    pub header_data: BtczHeaderIPC,
    pub block_message: PeerMessage,
}

impl BurnBlockIPC for BtczBlockIPC {
    type H = BtczHeaderIPC;
    type B = PeerMessage;

    fn header(&self) -> BtczHeaderIPC {
        self.header_data.clone()
    }

    fn height(&self) -> u64 {
        self.header_data.height()
    }

    fn block(&self) -> PeerMessage {
        self.block_message.clone()
    }
}

pub struct BtczBlockDownloader {
    cur_request: Option<BtczHeaderIPC>,
    cur_block: Option<BtczBlockIPC>,
    indexer: Option<BtczIndexer>,
}

pub struct BtczBlockParser {
    network_id: BtczNetworkType,
    magic_bytes: MagicBytes,
}

impl BtczBlockDownloader {
    pub fn new(indexer: BtczIndexer) -> BtczBlockDownloader {
        BtczBlockDownloader {
            cur_request: None,
            cur_block: None,
            indexer: Some(indexer),
        }
    }

    pub fn run(&mut self, header: &BtczHeaderIPC) -> Result<BtczBlockIPC, btcz_error> {
        self.cur_request = Some((*header).clone());

        // should always work, since at most one thread can call this method at once
        // due to &mut self.
        let mut indexer = self.indexer.take().unwrap();

        indexer.peer_communicate(self, false)?;

        self.indexer = Some(indexer);

        assert!(
            self.cur_block.is_some(),
            "BUG: should have received block on 'ok' condition"
        );
        let ipc_block = self.cur_block.take().unwrap();
        Ok(ipc_block)
    }
}

impl BurnchainBlockDownloader for BtczBlockDownloader {
    type H = BtczHeaderIPC;
    type B = BtczBlockIPC;

    fn download(&mut self, header: &BtczHeaderIPC) -> Result<BtczBlockIPC, burnchain_error> {
        self.run(header).map_err(|e| match e {
            btcz_error::TimedOut => burnchain_error::TrySyncAgain,
            x => burnchain_error::DownloadError(x),
        })
    }
}
impl BtczMessageHandler for BtczBlockDownloader {
    /// Trait message handler
    /// Initiate the conversation with the BTCZ peer
    fn begin_session(&mut self, indexer: &mut BtczIndexer) -> Result<bool, btcz_error> {
        match self.cur_request {
            None => panic!("No block header set"),
            Some(ref ipc_header) => {
                let block_hash = ipc_header.block_header.header.btcz_hash().clone();
                indexer
                    .send_getdata(&vec![block_hash])
                    .and_then(|_r| Ok(true))
            }
        }
    }

    /// Trait message handler
    /// Wait for a block to arrive that matches self.cur_request
    fn handle_message(
        &mut self,
        indexer: &mut BtczIndexer,
        msg: PeerMessage,
    ) -> Result<bool, btcz_error> {
        if self.cur_block.is_some() {
            log::debug!("Already have a block");
            return Ok(false);
        }

        if self.cur_request.is_none() {
            log::warn!("Unexpected block message");
            return Err(btcz_error::InvalidReply);
        }

        let ipc_header = self.cur_request.as_ref().unwrap();

        let height;
        let header;
        let block_hash;

        match msg {
            btcz_message::NetworkMessage::Block(ref block) => {
                if !BtczBlockParser::check_block(block, &ipc_header.block_header) {
                    log::debug!(
                        "Requested block {}, got block {}",
                        &to_hex(ipc_header.block_header.header.btcz_hash().as_bytes()),
                        &to_hex(block.btcz_hash().as_bytes())
                    );

                    indexer.send_getdata(&vec![ipc_header.block_header.header.btcz_hash()])?;
                    return Ok(true);
                }

                indexer.runtime.last_getdata_send_time = 0;

                height = ipc_header.block_height;
                header = self.cur_request.clone().unwrap();
                block_hash = ipc_header.block_header.header.btcz_hash();
            }
            _ => {
                return Err(btcz_error::UnhandledMessage(msg));
            }
        }

        log::debug!(
            "Got block {}: {}",
            height,
            &to_hex(BurnchainHeaderHash::from_btcz_hash(&block_hash).as_bytes())
        );

        let ipc_block = BtczBlockIPC {
            header_data: header,
            block_message: msg,
        };

        self.cur_block = Some(ipc_block);
        Ok(false)
    }
}

impl BtczBlockParser {
    /// New block parser
    pub fn new(network_id: BtczNetworkType, magic_bytes: MagicBytes) -> BtczBlockParser {
        BtczBlockParser {
            network_id,
            magic_bytes: magic_bytes.clone(),
        }
    }

    /// Verify that a block matches a header
    pub fn check_block(block: &Block, header: &LoneBlockHeader) -> bool {
        if header.header.btcz_hash() != block.btcz_hash() {
            return false;
        }

        let tx_merkle_root =
            btcz_merkle_root(block.txdata.iter().map(|ref tx| tx.txid()).collect());

        if block.header.merkle_root != tx_merkle_root {
            return false;
        }

        true
    }

    /// Parse the data output to get a byte payload
    fn parse_data(&self, data_output: &Script) -> Option<(u8, Vec<u8>)> {
        if !data_output.is_op_return() {
            log::test_debug!("Data output is not an OP_RETURN");
            return None;
        }

        if data_output.len() <= self.magic_bytes.len() {
            log::test_debug!("Data output is too short to carry an operation");
            return None;
        }

        let script_pieces = bits::parse_script(&data_output);
        if script_pieces.len() != 2 {
            log::test_debug!("Data output does not encode a valid OP_RETURN");
            return None;
        }

        match (&script_pieces[0], &script_pieces[1]) {
            (Instruction::Op(ref opcode), Instruction::PushBytes(ref data)) => {
                if *opcode != btcz_opcodes::OP_RETURN {
                    log::test_debug!("Data output does not use a standard OP_RETURN");
                    return None;
                }
                if !data.starts_with(self.magic_bytes.as_bytes()) {
                    log::test_debug!("Data output does not start with magic bytes");
                    return None;
                }

                let opcode = data[MAGIC_BYTES_LENGTH];
                Some((opcode, data[MAGIC_BYTES_LENGTH + 1..data.len()].to_vec()))
            }
            (_, _) => {
                log::test_debug!("Data output is not OP_RETURN <data>");
                None
            }
        }
    }

    /// Is this an acceptable transaction?
    fn maybe_burnchain_tx(&self, tx: &Transaction, epoch_id: ZookEpochId) -> bool {
        if self.parse_data(&tx.output[0].script_pubkey).is_none() {
            log::test_debug!("Tx {:?} has no valid OP_RETURN", tx.txid());
            return false;
        }

        for i in 1..tx.output.len() {
            if epoch_id < ZookEpochId::Epoch21 {
                if !tx.output[i].script_pubkey.is_p2pkh() && !tx.output[i].script_pubkey.is_p2sh() {
                    log::test_debug!(
                        "Tx {:?} has unrecognized output type in output {}",
                        tx.txid(),
                        i
                    );
                    return false;
                }
            } else {
                if BtczAddress::from_scriptpubkey(
                    BtczNetworkType::Mainnet,
                    &tx.output[i].script_pubkey.to_bytes(),
                )
                .is_none()
                {
                    log::test_debug!(
                        "Tx {:?} has unrecognized output type in output {}",
                        tx.txid(),
                        i
                    );
                    return false;
                }
            }
        }

        true
    }
}
impl BtczBlockParser {
    /// Parse a transaction's inputs into structured inputs.
    fn parse_inputs_structured(tx: &Transaction) -> Option<Vec<BtczTxInput>> {
        let mut ret = vec![];
        for inp in &tx.input {
            match BtczTxInput::from_btcz_txin_structured(&inp) {
                None => {
                    log::test_debug!("Failed to parse input");
                    return None;
                }
                Some(i) => {
                    ret.push(i);
                }
            };
        }
        Some(ret)
    }

    /// Parse a transaction's inputs into raw inputs.
    fn parse_inputs_raw(tx: &Transaction) -> Vec<BtczTxInput> {
        let mut ret = vec![];
        for inp in &tx.input {
            ret.push(BtczTxInput::from_btcz_txin_raw(&inp));
        }
        ret
    }

    /// Parse a transaction's outputs into burnchain outputs.
    fn parse_outputs(
        &self,
        tx: &Transaction,
        epoch_id: ZookEpochId,
    ) -> Option<Vec<BtczTxOutput>> {
        if tx.output.is_empty() {
            return None;
        }

        let mut ret = vec![];
        for outp in &tx.output[1..tx.output.len()] {
            let out_opt = if BtczBlockParser::allow_segwit_outputs(epoch_id) {
                BtczTxOutput::from_btcz_txout(self.network_id, &outp)
            } else {
                BtczTxOutput::from_btcz_txout_legacy(self.network_id, &outp)
            };
            match out_opt {
                None => {
                    log::test_debug!("Failed to parse output");
                    return None;
                }
                Some(o) => {
                    ret.push(o);
                }
            };
        }
        Some(ret)
    }

    /// Parse a BTCZ transaction into a Burnchain transaction.
    pub fn parse_tx(
        &self,
        tx: &Transaction,
        vtxindex: usize,
        epoch_id: ZookEpochId,
    ) -> Option<BtczTransaction> {
        if !self.maybe_burnchain_tx(tx, epoch_id) {
            log::test_debug!("Not a burnchain tx");
            return None;
        }

        let data_opt = self.parse_data(&tx.output[0].script_pubkey);
        if data_opt.is_none() {
            log::test_debug!("No OP_RETURN script");
            return None;
        }

        let data_amt = tx.output[0].value;

        let (opcode, data) = data_opt.unwrap();
        let inputs_opt = if BtczBlockParser::allow_raw_inputs(epoch_id) {
            Some(BtczBlockParser::parse_inputs_raw(tx))
        } else {
            BtczBlockParser::parse_inputs_structured(tx)
        };
        let outputs_opt = self.parse_outputs(tx, epoch_id);

        match (inputs_opt, outputs_opt) {
            (Some(inputs), Some(outputs)) => {
                Some(BtczTransaction {
                    txid: Txid::from_vec_be(&tx.txid().as_bytes().to_vec()).unwrap(),
                    vtxindex: vtxindex as u32,
                    opcode,
                    data,
                    data_amt,
                    inputs,
                    outputs,
                })
            }
            (_, _) => {
                log::test_debug!("Failed to parse inputs and/or outputs");
                None
            }
        }
    }

    /// Parse a BTCZ block into a collection of transactions.
    pub fn parse_block(
        &self,
        block: &Block,
        block_height: u64,
        epoch_id: ZookEpochId,
    ) -> BtczBlock {
        let mut accepted_txs = vec![];
        for i in 0..block.txdata.len() {
            let tx = &block.txdata[i];
            match self.parse_tx(tx, i, epoch_id) {
                Some(btcz_tx) => {
                    accepted_txs.push(btcz_tx);
                }
                None => {
                    continue;
                }
            }
        }

        BtczBlock {
            block_height,
            block_hash: BurnchainHeaderHash::from_btcz_hash(&block.btcz_hash()),
            parent_block_hash: BurnchainHeaderHash::from_btcz_hash(&block.header.prev_blockhash),
            txs: accepted_txs,
            timestamp: block.header.time as u64,
        }
    }

    /// Process a block, extracting BTCZ transactions and updating state.
    pub fn process_block(
        &self,
        block: &Block,
        header: &LoneBlockHeader,
        height: u64,
        epoch_id: ZookEpochId,
    ) -> Option<BtczBlock> {
        if !BtczBlockParser::check_block(block, header) {
            log::error!(
                "Expected block {} does not match received block {}",
                header.header.btcz_hash(),
                block.btcz_hash()
            );
            return None;
        }

        let burn_block = self.parse_block(&block, height, epoch_id);
        Some(burn_block)
    }
}
impl BurnchainBlockParser for BtczBlockParser {
    type D = BtczBlockDownloader;

    fn parse(
        &mut self,
        ipc_block: &BtczBlockIPC,
        epoch_id: ZookEpochId,
    ) -> Result<BurnchainBlock, burnchain_error> {
        match ipc_block.block_message {
            btcz_message::NetworkMessage::Block(ref block) => {
                match self.process_block(
                    &block,
                    &ipc_block.header_data.block_header,
                    ipc_block.header_data.block_height,
                    epoch_id,
                ) {
                    None => Err(burnchain_error::ParseError),
                    Some(block_data) => Ok(BurnchainBlock::Btcz(block_data)),
                }
            }
            _ => {
                panic!("Did not receive a Block message"); // should never happen
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use zbtc_common::deps_common::btcz::blockdata::block::{Block, LoneBlockHeader};
    use zbtc_common::deps_common::btcz::blockdata::transaction::Transaction;
    use zbtc_common::deps_common::btcz::network::encodable::VarInt;
    use zbtc_common::deps_common::btcz::network::serialize::deserialize;
    use zbtc_common::types::chainstate::BurnchainHeaderHash;
    use zbtc_common::types::Address;
    use zbtc_common::util::hash::hex_bytes;
    use zbtc_common::util::log;

    use super::BtczBlockParser;
    use crate::burnchains::btcz::address::{BtczAddress, LegacyBtczAddressType};
    use crate::burnchains::btcz::keys::BtczPublicKey;
    use crate::burnchains::btcz::{
        BtczBlock, BtczInputType, BtczNetworkType, BtczTransaction, BtczTxInput,
        BtczTxInputRaw, BtczTxInputStructured, BtczTxOutput,
    };
    use crate::burnchains::{BurnchainBlock, BurnchainTransaction, MagicBytes, Txid};
    use crate::core::ZookEpochId;

    struct TxFixture {
        txstr: String,
        result: Option<BtczTransaction>,
    }

    struct TxParseFixture {
        txstr: String,
        result: bool,
    }

    struct BlockFixture {
        block: String,
        header: String,
        height: u64,
        result: Option<BtczBlock>,
    }

    fn make_tx(hex_str: &str) -> Result<Transaction, &'static str> {
        let tx_bin = hex_bytes(hex_str).map_err(|_e| "failed to decode hex")?;
        let tx = deserialize(&tx_bin.to_vec()).map_err(|_e| "failed to deserialize")?;
        Ok(tx)
    }

    fn make_block(hex_str: &str) -> Result<Block, &'static str> {
        let block_bin = hex_bytes(hex_str).map_err(|_e| "failed to decode hex")?;
        let block = deserialize(&block_bin.to_vec()).map_err(|_e| "failed to deserialize block")?;
        Ok(block)
    }

    fn make_block_header(hex_str: &str) -> Result<LoneBlockHeader, &'static str> {
        let header_bin = hex_bytes(hex_str).map_err(|_e| "failed to decode hex")?;
        let header =
            deserialize(&header_bin.to_vec()).map_err(|_e| "failed to deserialize header")?;
        Ok(LoneBlockHeader {
            header,
            tx_count: VarInt(0),
        })
    }

    fn to_txid(inp: &Vec<u8>) -> Txid {
        let mut ret = [0; 32];
        let bytes = &inp[..inp.len()];
        ret.copy_from_slice(bytes);
        Txid(ret)
    }

    fn to_block_hash(inp: &Vec<u8>) -> BurnchainHeaderHash {
        let mut ret = [0; 32];
        let bytes = &inp[..inp.len()];
        ret.copy_from_slice(bytes);
        BurnchainHeaderHash(ret)
    }

    #[test]
    fn parse_tx_test() {
        let vtxindex = 4;
        let tx_fixtures = vec![
            TxFixture {
                txstr: "010000000120a081bcd1a80d9c1945f863d29dc84278411ed74cb6dcba30541bf8d5770542000000008b483045022100be57031bf2c095945ba2876e97b3f86ee051643a29b908f22ed45ccf58620103022061e056e5f48c5a51c66604a1ca28e4bfaabab1478424c9bbb396cc6afe5c222e0141040fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc806b9a4f07579934774cc0c155e781d45c989f94336765e88a66d91cfb9f060b0feffffff030000000000000000296a2769642bfae543ff5672fb607fe15e16b1c3ef38737c631c7c5d911c6617993c21fba731363f1cfe6c6b0000000000001976a914395f3643cea07ec4eec73b4d9a973dcce56b9bf188acc5120100000000001976a9149f2660e75380675206b6f1e2b4f106ae33266be488ac00000000".to_owned(),
                result: Some(BtczTransaction {
                    data_amt: 0,
                    txid: to_txid(&hex_bytes("185c112401590b11acdfea6bb26d2a8e37cb31f24a0c89dbb8cc14b3d6271fb1").unwrap()),
                    vtxindex,
                    opcode: '+' as u8,
                    data: hex_bytes("fae543ff5672fb607fe15e16b1c3ef38737c631c7c5d911c6617993c21fba731363f1cfe").unwrap(),
                    inputs: vec![
                        BtczTxInputRaw {
                            scriptSig: hex_bytes("483045022100be57031bf2c095945ba2876e97b3f86ee051643a29b908f22ed45ccf58620103022061e056e5f48c5a51c66604a1ca28e4bfaabab1478424c9bbb396cc6afe5c222e0141040fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc806b9a4f07579934774cc0c155e781d45c989f94336765e88a66d91cfb9f060b0").unwrap(),
                            witness: vec![],
                            tx_ref: (Txid::from_hex("420577d5f81b5430badcb64cd71e417842c89dd263f845199c0da8d1bc81a020").unwrap(), 2),
                        }
                        .into(),
                    ],
                    outputs: vec![
                        BtczTxOutput {
                            units: 27500,
                            address: BtczAddress::from_bytes_legacy(BtczNetworkType::Mainnet, LegacyBtczAddressType::PublicKeyHash, &hex_bytes("395f3643cea07ec4eec73b4d9a973dcce56b9bf1").unwrap()).unwrap(),
                        },
                    ],
                }),
            },
        ];

        let parser = BtczBlockParser::new(BtczNetworkType::Mainnet, MagicBytes([105, 100]));
        for tx_fixture in tx_fixtures {
            let tx = make_tx(&tx_fixture.txstr).unwrap();
            let btcz_tx = parser.parse_tx(&tx, vtxindex as usize, ZookEpochId::Epoch2_05);
            assert!(btcz_tx.is_some());
            assert_eq!(btcz_tx, tx_fixture.result);
        }
    }
}
#[test]
fn parse_block_test() {
    let block_fixtures = vec![
        BlockFixture {
            block: "000000209cef4ccd19f4294dd5c762aab6d9577fb4412cd4c0a662a953a8b7969697bc1ddab52e6f053758022fb92f04388eb5fdd87046776e9c406880e728b48e6930aff462fc5bffff7f200000000002020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0502b5020101ffffffff024018a41200000000232103f51f0c868fd99a4a3a14fe2153fba3c5f635c31bf0a588545627134b49609097ac0000000000000000266a24aa21a9ed18a09ae86261d6802bff7fa705afa558764ed3750c2273bfae5b5136c44d14d6012000000000000000000000000000000000000000000000000000000000000000000000000001000000000101a7ef2b09722ad786c569c0812005a731ce19290bb0a2afc16cb91056c2e4c19e0100000017160014393ffec4f09b38895b8502377693f23c6ae00f19ffffffff0300000000000000000d6a0b69643a666f6f2e746573747c1500000000000017a9144b85301ba8e42bf98472b8ed4939d5f76b98fcea87144d9c290100000017a91431f8968eb1730c83fb58409a9a560a0a0835027f8702483045022100fc82815edf1c0ef0c601cf1e26494626d7b01597be5ab83df025ff1ee67730130220016c4c29d77aadb5ff57c0c9272a43950ca29b84d8adfaed95ac69db90b35d5b012102d341f728783eb93e6fb5921a1ebe9d149e941de31e403cd69afa2f0f1e698e8100000000".to_owned(),
            header: "000000209cef4ccd19f4294dd5c762aab6d9577fb4412cd4c0a662a953a8b7969697bc1ddab52e6f053758022fb92f04388eb5fdd87046776e9c406880e728b48e6930aff462fc5bffff7f2000000000".to_owned(),
            height: 32,
            result: Some(BtczBlock {
                block_height: 32,
                parent_block_hash: to_block_hash(&hex_bytes("1dbc979696b7a853a962a6c0d42c41b47f57d9b6aa62c7d54d29f419cd4cef9c").unwrap()),
                block_hash: to_block_hash(&hex_bytes("7483b1104341d596c1d0d2499cb1821b0e078329deabc4e7504c016a5b393e08").unwrap()),
                txs: vec![
                    BtczTransaction {
                        data_amt: 0,
                        txid: to_txid(&hex_bytes("b908952b30ccfdfa59985dc1ffdd2a22ef054d20fa253510d2af7797dddee459").unwrap()),
                        vtxindex: 1,
                        opcode: ':' as u8,
                        data: hex_bytes("666f6f2e74657374").unwrap(),
                        inputs: vec![
                            BtczTxInputStructured {
                                keys: vec![
                                    BtczPublicKey::from_hex("02d341f728783eb93e6fb5921a1ebe9d149e941de31e403cd69afa2f0f1e698e81").unwrap()
                                ],
                                num_required: 1,
                                in_type: BtczInputType::SegwitP2SH,
                                tx_ref: (Txid::from_hex("9ec1e4c25610b96cc1afa2b00b2919ce31a7052081c069c586d72a72092befa7").unwrap(), 1),
                            }
                            .into(),
                        ],
                        outputs: vec![
                            BtczTxOutput {
                                units: 5500,
                                address: BtczAddress::from_bytes_legacy(BtczNetworkType::Testnet, LegacyBtczAddressType::ScriptHash, &hex_bytes("4b85301ba8e42bf98472b8ed4939d5f76b98fcea").unwrap()).unwrap(),
                            },
                            BtczTxOutput {
                                units: 4993076500,
                                address: BtczAddress::from_bytes_legacy(BtczNetworkType::Testnet, LegacyBtczAddressType::ScriptHash, &hex_bytes("31f8968eb1730c83fb58409a9a560a0a0835027f").unwrap()).unwrap(),
                            }
                        ]
                    }
                ],
                timestamp: 1543267060,
            })
        },
    ];

    let parser = BtczBlockParser::new(BtczNetworkType::Testnet, MagicBytes([105, 100]));
    for block_fixture in block_fixtures {
        let block = make_block(&block_fixture.block).unwrap();
        let header = make_block_header(&block_fixture.header).unwrap();
        let height = block_fixture.height;

        let parsed_block_opt =
            parser.process_block(&block, &header, height, ZookEpochId::Epoch2_05);
        assert_eq!(parsed_block_opt, block_fixture.result);
    }
}
#[test]
fn maybe_burnchain_tx_test() {
    let tx_fixtures = vec![
        TxParseFixture {
            txstr: "0100000001d8b97932f097b9fbf0c7584f29515862911ac830826fdfd72d06402c21543e38000000006a47304402202801bc5d11eefddc586b1171bf607cc2be1c661d22e215153f2630316f973a200220628cc08858bba3f0cda661dbef2f007e48f8cb531edc0b54edb573226816f253012103d6967618e0159c9bfcd03ea33d368c8b2a98af5a054364c6b5e7215d7d809169ffffffff030000000000000000356a336469240efa29f955c6ae3bb5037039d89dba5e00000000000000000000000000535441434b5300000000000003e854455354217c150000000000001976a914cfd25e09f2d33e1aec73bfcc5b608ec513bbe6c088ac34460200000000001976a9144cb912533a6935880df7647fd5232e40aca07b8088ac00000000".to_owned(),
            result: false,
        },
        TxParseFixture {
            txstr: "01000000000101a7ef2b09722ad786c569c0812005a731ce19290bb0a2afc16cb91056c2e4c19e0100000017160014393ffec4f09b38895b8502377693f23c6ae00f19ffffffff0300000000000000000d6a0b69643a666f6f2e746573747c1500000000000017a9144b85301ba8e42bf98472b8ed4939d5f76b98fcea87144d9c290100000017a91431f8968eb1730c83fb58409a9a560a0a0835027f8702483045022100fc82815edf1c0ef0c601cf1e26494626d7b01597be5ab83df025ff1ee67730130220016c4c29d77aadb5ff57c0c9272a43950ca29b84d8adfaed95ac69db90b35d5b012102d341f728783eb93e6fb5921a1ebe9d149e941de31e403cd69afa2f0f1e698e8100000000".to_owned(),
            result: true,
        },
    ];

    let parser = BtczBlockParser::new(BtczNetworkType::Testnet, MagicBytes([105, 100]));
    for tx_fixture in tx_fixtures {
        let tx = make_tx(&tx_fixture.txstr).unwrap();
        let res = parser.maybe_burnchain_tx(&tx, ZookEpochId::Epoch2_05);
        assert_eq!(res, tx_fixture.result);
    }
}

#[test]
fn parse_block_invalid_test() {
    let block_fixtures = vec![
        BlockFixture {
            block: "000000209cef4ccd19f4294dd5c762aab6d9577fb4412cd4c0a662a953a8b7969697bc1ddab52e6f053758022fb92f04388eb5fdd87046776e9c406880e728b48e6930aff462fc5bffff7f200000000002020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0502b5020101ffffffff024018a41200000000232103f51f0c868fd99a4a3a14fe2153fba3c5f635c31bf0a588545627134b49609097ac0000000000000000266a24aa21a9ed18a09ae86261d6802bff7fa705afa558764ed3750c2273bfae5b5136c44d14d6012000000000000000000000000000000000000000000000000000000000000000000000000001000000000101a7ef2b09722ad786c569c0812005a731ce19290bb0a2afc16cb91056c2e4c19e0100000017160014393ffec4f09b38895b8502377693f23c6ae00f19ffffffff0300000000000000000d6a0b69643a666f6f2e746573747c1500000000000017a9144b85301ba8e42bf98472b8ed4939d5f76b98fcea87144d9c290100000017a91431f8968eb1730c83fb58409a9a560a0a0835027f8702483045022100fc82815edf1c0ef0c601cf1e26494626d7b01597be5ab83df025ff1ee67730130220016c4c29d77aadb5ff57c0c9272a43950ca29b84d8adfaed95ac69db90b35d5b012102d341f728783eb93e6fb5921a1ebe9d149e941de31e403cd69afa2f0f1e698e8100000000".to_owned(),
            header: "000000209cef4ccd19f4294dd5c762aab6d9577fb4412cd4c0a662a953a8b7969697bc1ddab52e6f053758022fb92f04388eb5fdd87046776e9c406880e728b48e6930aff462fc5bffff7f2000000000".to_owned(),
            height: 32,
            result: None,
        },
    ];

    let parser = BtczBlockParser::new(BtczNetworkType::Testnet, MagicBytes([105, 100]));
    for block_fixture in block_fixtures {
        let block = make_block(&block_fixture.block).unwrap();
        let header = make_block_header(&block_fixture.header).unwrap();
        let height = block_fixture.height;

        let parsed_block_opt =
            parser.process_block(&block, &header, height, ZookEpochId::Epoch2_05);
        assert_eq!(parsed_block_opt, block_fixture.result);
    }
}

#[test]
fn parse_invalid_tx_test() {
    let invalid_tx_fixtures = vec![
        "01000000000101d8b97932f097b9fbf0c7584f29515862911ac830826fdfd72d06402c21543e38000000006a47304402202801bc5d11eefddc586b1171bf607cc2be1c661d22e215153f2630316f973a200220628cc08858bba3f0cda661dbef2f007e48f8cb531edc0b54edb573226816f253012103d6967618e0159c9bfcd03ea33d368c8b2a98af5a054364c6b5e7215d7d809169ffffffff030000000000000000356a336469240efa29f955c6ae3bb5037039d89dba5e00000000000000000000000000535441434b5300000000000003e854455354217c150000000000001976a914cfd25e09f2d33e1aec73bfcc5b608ec513bbe6c088ac34460200000000001976a9144cb912533a6935880df7647fd5232e40aca07b8088ac00000000",
    ];

    let parser = BtczBlockParser::new(BtczNetworkType::Testnet, MagicBytes([105, 100]));
    for txstr in invalid_tx_fixtures {
        let tx = make_tx(txstr).unwrap();
        let res = parser.maybe_burnchain_tx(&tx, ZookEpochId::Epoch2_05);
        assert_eq!(res, false);
    }
}
#[test]
fn test_process_block() {
    let block_fixtures = vec![
        BlockFixture {
            block: "00000020803895604a26cfc4b0d4b8eb2e88877e33273dd21713a268214f6c6f1b0f420b25c5268d0558cbe3322571b3e54247bcb2c0176df4c76de7e85620a37411eecb2bffdfbffff7f20000000002010000000000000000000000000000000000000000000000000000000000000000ffffffff04044c860101ffffffff030000000000000000276a2500fabe6d6dc3e5cb0e0d8b6e2a5e6a2ec3cbef5a23d70798c77074bc7f25081ec88da313de000000001976a914ec5d1546b92582c9a9b3c9f30069c2a1da5b3df188ac0000000000000000266a24aa21a9ed104fbb672e81e5db9e4b58e237ef23dd79af6ff5306f3f8d80e34d2f9b8288b00000000".to_owned(),
            header: "00000020803895604a26cfc4b0d4b8eb2e88877e33273dd21713a268214f6c6f1b0f420b25c5268d0558cbe3322571b3e54247bcb2c0176df4c76de7e85620a37411eecb2bffdfbffff7f2000000000".to_owned(),
            height: 42,
            result: Some(BtczBlock {
                block_height: 42,
                parent_block_hash: to_block_hash(&hex_bytes("1b0f420b25c5268d0558cbe3322571b3e54247bcb2c0176df4c76de7e85620a3").unwrap()),
                block_hash: to_block_hash(&hex_bytes("803895604a26cfc4b0d4b8eb2e88877e33273dd21713a268214f6c6f1b0f420b").unwrap()),
                txs: vec![],
                timestamp: 1543857060,
            })
        },
    ];

    let parser = BtczBlockParser::new(BtczNetworkType::Testnet, MagicBytes([105, 100]));
    for block_fixture in block_fixtures {
        let block = make_block(&block_fixture.block).unwrap();
        let header = make_block_header(&block_fixture.header).unwrap();
        let height = block_fixture.height;

        let parsed_block_opt =
            parser.process_block(&block, &header, height, ZookEpochId::Epoch2_05);
        assert_eq!(parsed_block_opt, block_fixture.result);
    }
}

#[test]
fn test_invalid_block_headers() {
    let invalid_block_fixtures = vec![
        BlockFixture {
            block: "00000020deadbeef4a26cfc4b0d4b8eb2e88877e33273dd21713a268214f6c6f1b0f420b25c5268d0558cbe3322571b3e54247bcb2c0176df4c76de7e85620a37411eecb2bffdfbffff7f20000000002010000000000000000000000000000000000000000000000000000000000000000ffffffff04044c860101ffffffff030000000000000000276a2500fabe6d6dc3e5cb0e0d8b6e2a5e6a2ec3cbef5a23d70798c77074bc7f25081ec88da313de000000001976a914ec5d1546b92582c9a9b3c9f30069c2a1da5b3df188ac0000000000000000266a24aa21a9ed104fbb672e81e5db9e4b58e237ef23dd79af6ff5306f3f8d80e34d2f9b8288b00000000".to_owned(),
            header: "00000020deadbeef4a26cfc4b0d4b8eb2e88877e33273dd21713a268214f6c6f1b0f420b25c5268d0558cbe3322571b3e54247bcb2c0176df4c76de7e85620a37411eecb2bffdfbffff7f2000000000".to_owned(),
            height: 42,
            result: None,
        },
    ];

    let parser = BtczBlockParser::new(BtczNetworkType::Testnet, MagicBytes([105, 100]));
    for block_fixture in invalid_block_fixtures {
        let block = make_block(&block_fixture.block).unwrap();
        let header = make_block_header(&block_fixture.header).unwrap();
        let height = block_fixture.height;

        let parsed_block_opt =
            parser.process_block(&block, &header, height, ZookEpochId::Epoch2_05);
        assert_eq!(parsed_block_opt, block_fixture.result);
    }
}

#[test]
fn test_unexpected_network_message() {
    let parser = BtczBlockParser::new(BtczNetworkType::Testnet, MagicBytes([105, 100]));

    let ipc_block = BtczBlockIPC {
        header_data: BtczHeaderIPC {
            block_header: LoneBlockHeader {
                header: make_block_header("00000020deadbeef4a26cfc4b0d4b8eb2e88877e33273dd21713a268214f6c6f").unwrap().header,
                tx_count: VarInt(0),
            },
            block_height: 42,
        },
        block_message: btcz_message::NetworkMessage::NotFound(vec![]),
    };

    assert!(parser.parse(&ipc_block, ZookEpochId::Epoch2_05).is_err());
}
#[test]
fn test_parse_tx_inputs() {
    let tx = make_tx(
        "0100000001abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_owned(),
    )
    .unwrap();

    let structured_inputs = BtczBlockParser::parse_inputs_structured(&tx);
    assert!(structured_inputs.is_some());

    let raw_inputs = BtczBlockParser::parse_inputs_raw(&tx);
    assert!(!raw_inputs.is_empty());
}

#[test]
fn test_parse_tx_outputs() {
    let tx = make_tx(
        "0200000001abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_owned(),
    )
    .unwrap();

    let parser = BtczBlockParser::new(BtczNetworkType::Mainnet, MagicBytes([105, 100]));
    let epoch_id = ZookEpochId::Epoch21;

    let outputs = parser.parse_outputs(&tx, epoch_id);
    assert!(outputs.is_some());
}

#[test]
fn test_parse_tx() {
    let tx = make_tx(
        "0200000001abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_owned(),
    )
    .unwrap();

    let parser = BtczBlockParser::new(BtczNetworkType::Testnet, MagicBytes([105, 100]));
    let epoch_id = ZookEpochId::Epoch2_05;

    let parsed_tx = parser.parse_tx(&tx, 0, epoch_id);
    assert!(parsed_tx.is_some());
}

#[test]
fn test_parse_block_transactions() {
    let block = make_block(
        "00000020abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_owned(),
    )
    .unwrap();

    let parser = BtczBlockParser::new(BtczNetworkType::Mainnet, MagicBytes([105, 100]));
    let epoch_id = ZookEpochId::Epoch21;

    let parsed_block = parser.parse_block(&block, 100, epoch_id);
    assert_eq!(parsed_block.block_height, 100);
}

#[test]
fn test_check_block_headers() {
    let header = make_block_header(
        "00000020abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_owned(),
    )
    .unwrap();

    let block = make_block(
        "00000020abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_owned(),
    )
    .unwrap();

    let parser = BtczBlockParser::new(BtczNetworkType::Testnet, MagicBytes([105, 100]));
    let is_valid = BtczBlockParser::check_block(&block, &header);
    assert!(is_valid);
}

#[test]
fn test_parse_data_output() {
    let script = Script::from(vec![
        btcz_opcodes::OP_RETURN.into(),
        0x69, 0x64, 0x21, // Magic bytes "id!"
        0x01, 0x02, 0x03, // Payload
    ]);

    let parser = BtczBlockParser::new(BtczNetworkType::Mainnet, MagicBytes([105, 100]));
    let parsed_data = parser.parse_data(&script);

    assert!(parsed_data.is_some());
    let (opcode, payload) = parsed_data.unwrap();
    assert_eq!(opcode, 0x21);
    assert_eq!(payload, vec![0x01, 0x02, 0x03]);
}

#[test]
fn test_parse_invalid_data_output() {
    let script = Script::from(vec![
        btcz_opcodes::OP_RETURN.into(),
        0x01, 0x02, 0x03, // Invalid magic bytes
    ]);

    let parser = BtczBlockParser::new(BtczNetworkType::Testnet, MagicBytes([105, 100]));
    let parsed_data = parser.parse_data(&script);

    assert!(parsed_data.is_none());
}

#[test]
fn test_parse_and_check_blocks() {
    let block = make_block(
        "00000020abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_owned(),
    )
    .unwrap();

    let header = make_block_header(
        "00000020abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_owned(),
    )
    .unwrap();

    let parser = BtczBlockParser::new(BtczNetworkType::Mainnet, MagicBytes([105, 100]));
    let parsed_block = parser.process_block(&block, &header, 42, ZookEpochId::Epoch21);

    assert!(parsed_block.is_some());
    let block = parsed_block.unwrap();
    assert_eq!(block.block_height, 42);
}
#[test]
fn test_parse_malformed_block() {
    let malformed_block = make_block(
        "00000020deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_owned(),
    );

    assert!(malformed_block.is_err());
}

#[test]
fn test_parse_block_with_no_transactions() {
    let block = make_block(
        "00000020803895604a26cfc4b0d4b8eb2e88877e33273dd21713a268214f6c6f1b0f420b".to_owned(),
    )
    .unwrap();

    let parser = BtczBlockParser::new(BtczNetworkType::Mainnet, MagicBytes([105, 100]));
    let parsed_block = parser.parse_block(&block, 100, ZookEpochId::Epoch2_05);

    assert_eq!(parsed_block.txs.len(), 0);
}

#[test]
fn test_parse_large_block() {
    let block = make_block(
        "00000020123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
    )
    .unwrap();

    let parser = BtczBlockParser::new(BtczNetworkType::Mainnet, MagicBytes([105, 100]));
    let parsed_block = parser.parse_block(&block, 500, ZookEpochId::Epoch21);

    assert_eq!(parsed_block.block_height, 500);
}

#[test]
fn test_block_download_failure() {
    let mut downloader = BtczBlockDownloader {
        cur_request: None,
        cur_block: None,
        indexer: None,
    };

    let header = BtczHeaderIPC {
        block_header: LoneBlockHeader {
            header: make_block_header("00000020deadbeef4a26cfc4b0d4b8eb2e88877e33273dd21713a268214f6c6f")
                .unwrap()
                .header,
            tx_count: VarInt(0),
        },
        block_height: 42,
    };

    let result = downloader.download(&header);
    assert!(result.is_err());
}

#[test]
fn test_block_with_unrecognized_outputs() {
    let tx = make_tx(
        "0200000001abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_owned(),
    )
    .unwrap();

    let parser = BtczBlockParser::new(BtczNetworkType::Testnet, MagicBytes([105, 100]));
    let epoch_id = ZookEpochId::Epoch21;

    let outputs = parser.parse_outputs(&tx, epoch_id);
    assert!(outputs.is_some());

    let output = outputs.unwrap()[0].address;
    assert!(output.is_none());
}

#[test]
fn test_download_and_parse_block() {
    let mut downloader = BtczBlockDownloader {
        cur_request: None,
        cur_block: None,
        indexer: Some(BtczIndexer::new()),
    };

    let header = BtczHeaderIPC {
        block_header: LoneBlockHeader {
            header: make_block_header("00000020123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap()
                .header,
            tx_count: VarInt(0),
        },
        block_height: 100,
    };

    let result = downloader.download(&header);
    assert!(result.is_ok());

    let ipc_block = result.unwrap();
    let parser = BtczBlockParser::new(BtczNetworkType::Mainnet, MagicBytes([105, 100]));
    let parsed_block = parser.parse(&ipc_block, ZookEpochId::Epoch21);

    assert!(parsed_block.is_ok());
    let block = parsed_block.unwrap();
    assert_eq!(block.block_height, 100);
}

#[test]
fn test_transaction_with_multiple_op_return() {
    let tx = make_tx(
        "0100000001abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_owned(),
    )
    .unwrap();

    let script = Script::from(vec![
        btcz_opcodes::OP_RETURN.into(),
        0x69, 0x64, 0x21, // Magic bytes "id!"
        0x01, 0x02, 0x03, // Payload
        btcz_opcodes::OP_RETURN.into(),
        0x02, 0x03, 0x04, // Another payload
    ]);

    let parser = BtczBlockParser::new(BtczNetworkType::Mainnet, MagicBytes([105, 100]));
    let parsed_data = parser.parse_data(&script);

    assert!(parsed_data.is_some());
    let (_, payload) = parsed_data.unwrap();
    assert_eq!(payload, vec![0x01, 0x02, 0x03]);
}
#[test]
fn test_transaction_with_invalid_scriptpubkey() {
    let tx = make_tx(
        "0200000001abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_owned(),
    )
    .unwrap();

    let parser = BtczBlockParser::new(BtczNetworkType::Mainnet, MagicBytes([105, 100]));
    let epoch_id = ZookEpochId::Epoch21;

    let outputs = parser.parse_outputs(&tx, epoch_id);
    assert!(outputs.is_some());

    let first_output = &outputs.unwrap()[0];
    assert!(first_output.address.is_none());
}

#[test]
fn test_handle_large_op_return_transaction() {
    let script = Script::from(vec![
        btcz_opcodes::OP_RETURN.into(),
        0x69, 0x64, 0x21, // Magic bytes "id!"
        0x01, 0x02, 0x03, // Payload
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, // Extended payload
    ]);

    let parser = BtczBlockParser::new(BtczNetworkType::Testnet, MagicBytes([105, 100]));
    let parsed_data = parser.parse_data(&script);

    assert!(parsed_data.is_some());
    let (opcode, payload) = parsed_data.unwrap();
    assert_eq!(opcode, 0x21);
    assert_eq!(
        payload,
        vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F,
        ]
    );
}

#[test]
fn test_multiple_transactions_in_block() {
    let block = make_block(
        "00000020123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
    )
    .unwrap();

    let parser = BtczBlockParser::new(BtczNetworkType::Mainnet, MagicBytes([105, 100]));
    let epoch_id = ZookEpochId::Epoch21;

    let parsed_block = parser.parse_block(&block, 256, epoch_id);
    assert_eq!(parsed_block.block_height, 256);
    assert!(!parsed_block.txs.is_empty());
}

#[test]
fn test_invalid_block_structure() {
    let invalid_block = make_block(
        "00000020deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_owned(),
    );

    assert!(invalid_block.is_err());
}

#[test]
fn test_op_return_parsing_with_multiple_magic_bytes() {
    let script = Script::from(vec![
        btcz_opcodes::OP_RETURN.into(),
        0x69, 0x64, 0x21, // First magic bytes "id!"
        0x01, 0x02, 0x03, // Payload
        btcz_opcodes::OP_RETURN.into(),
        0x69, 0x64, 0x22, // Second magic bytes "id" with different opcode
        0x04, 0x05, 0x06, // Second payload
    ]);

    let parser = BtczBlockParser::new(BtczNetworkType::Mainnet, MagicBytes([105, 100]));
    let parsed_data = parser.parse_data(&script);

    assert!(parsed_data.is_some());
    let (opcode, payload) = parsed_data.unwrap();
    assert_eq!(opcode, 0x21);
    assert_eq!(payload, vec![0x01, 0x02, 0x03]);
}

#[test]
fn test_malformed_transactions_in_block() {
    let block = make_block(
        "00000020deadbeef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_owned(),
    )
    .unwrap();

    let parser = BtczBlockParser::new(BtczNetworkType::Testnet, MagicBytes([105, 100]));
    let epoch_id = ZookEpochId::Epoch2_05;

    let parsed_block = parser.parse_block(&block, 500, epoch_id);
    assert!(parsed_block.txs.is_empty());
}

#[test]
fn test_incorrect_magic_bytes_in_op_return() {
    let script = Script::from(vec![
        btcz_opcodes::OP_RETURN.into(),
        0x70, 0x71, 0x72, // Incorrect magic bytes
        0x01, 0x02, 0x03, // Payload
    ]);

    let parser = BtczBlockParser::new(BtczNetworkType::Mainnet, MagicBytes([105, 100]));
    let parsed_data = parser.parse_data(&script);

    assert!(parsed_data.is_none());
}

#[test]
fn test_parser_with_very_large_block() {
    let block = make_block(
        "00000020".to_owned() + &"abcdef".repeat(10000), // Large block placeholder
    );

    assert!(block.is_err());
}
#[test]
fn test_transaction_with_valid_payload() {
    let script = Script::from(vec![
        btcz_opcodes::OP_RETURN.into(),
        0x69, 0x64, 0x21, // Magic bytes "id!"
        0x01, 0x02, 0x03, // Payload
    ]);

    let parser = BtczBlockParser::new(BtczNetworkType::Testnet, MagicBytes([105, 100]));
    let parsed_data = parser.parse_data(&script);

    assert!(parsed_data.is_some());
    let (opcode, payload) = parsed_data.unwrap();
    assert_eq!(opcode, 0x21);
    assert_eq!(payload, vec![0x01, 0x02, 0x03]);
}

#[test]
fn test_large_block_with_multiple_transactions() {
    let block = make_block(
        "00000020abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_owned(),
    )
    .unwrap();

    let parser = BtczBlockParser::new(BtczNetworkType::Mainnet, MagicBytes([105, 100]));
    let parsed_block = parser.parse_block(&block, 1024, ZookEpochId::Epoch21);

    assert_eq!(parsed_block.block_height, 1024);
    assert!(!parsed_block.txs.is_empty());
}

#[test]
fn test_block_download_timeout() {
    let mut downloader = BtczBlockDownloader {
        cur_request: None,
        cur_block: None,
        indexer: None,
    };

    let header = BtczHeaderIPC {
        block_header: LoneBlockHeader {
            header: make_block_header("00000020deadbeef4a26cfc4b0d4b8eb2e88877e33273dd21713a268214f6c6f")
                .unwrap()
                .header,
            tx_count: VarInt(0),
        },
        block_height: 84,
    };

    let result = downloader.download(&header);
    assert!(result.is_err());
}

#[test]
fn test_op_return_with_unexpected_format() {
    let script = Script::from(vec![
        btcz_opcodes::OP_RETURN.into(),
        0x69, 0x64, 0x20, // Altered magic bytes
        0x01, 0x02, 0x03, // Payload
    ]);

    let parser = BtczBlockParser::new(BtczNetworkType::Testnet, MagicBytes([105, 100]));
    let parsed_data = parser.parse_data(&script);

    assert!(parsed_data.is_none());
}

#[test]
fn test_process_block_with_malformed_transactions() {
    let block = make_block(
        "00000020abcdefdeadbeefdeadbeefdeadbeefabcdefabcdefabcdefabcdefdeadbeef".to_owned(),
    )
    .unwrap();

    let parser = BtczBlockParser::new(BtczNetworkType::Mainnet, MagicBytes([105, 100]));
    let epoch_id = ZookEpochId::Epoch2_05;

    let parsed_block = parser.process_block(&block, &make_block_header("00000020abcdef").unwrap(), 128, epoch_id);

    assert!(parsed_block.is_some());
    assert!(parsed_block.unwrap().txs.is_empty());
}

#[test]
fn test_parse_tx_with_partial_data() {
    let tx = make_tx(
        "0100000001abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_owned(),
    )
    .unwrap();

    let parser = BtczBlockParser::new(BtczNetworkType::Testnet, MagicBytes([105, 100]));
    let epoch_id = ZookEpochId::Epoch2_05;

    let parsed_tx = parser.parse_tx(&tx, 0, epoch_id);
    assert!(parsed_tx.is_some());
}

#[test]
fn test_parse_invalid_header() {
    let invalid_header = make_block_header(
        "00000020deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_owned(),
    );

    assert!(invalid_header.is_err());
}

#[test]
fn test_invalid_outputs_in_block() {
    let block = make_block(
        "00000020abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_owned(),
    )
    .unwrap();

    let parser = BtczBlockParser::new(BtczNetworkType::Mainnet, MagicBytes([105, 100]));
    let epoch_id = ZookEpochId::Epoch21;

    let parsed_block = parser.parse_block(&block, 200, epoch_id);
    assert!(parsed_block.txs.iter().all(|tx| tx.outputs.is_empty()));
}
