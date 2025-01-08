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

use std::io::Write;
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{io, thread, time};

use rand::{thread_rng, Rng};
use bitcoinz_common::deps_common::bitcoinz::network::encodable::{
    ConsensusDecodable, ConsensusEncodable,
};
use bitcoinz_common::deps_common::bitcoinz::network::serialize::{RawDecoder, RawEncoder};
use bitcoinz_common::deps_common::bitcoinz::network::{
    address as bitcoinz_network_address, constants as bitcoinz_constants, message as bitcoinz_message,
    message_blockdata as bitcoinz_message_blockdata, message_network as bitcoinz_message_network,
    serialize as bitcoinz_serialize,
};
use bitcoinz_common::deps_common::bitcoinz::util::hash::Sha256dHash;
use bitcoinz_common::util::{get_epoch_time_secs, log};

use crate::burnchains::bitcoinz::indexer::{network_id_to_bytes, BitcoinZIndexer};
use crate::burnchains::bitcoinz::messages::BitcoinZMessageHandler;
use crate::burnchains::bitcoinz::{Error as bitcoinz_error, PeerMessage};
use crate::burnchains::indexer::BurnchainIndexer;

// Based on Andrew Poelstra's rust-bitcoin library.
impl BitcoinZIndexer {
    /// Send a BitcoinZ protocol message on the wire
    pub fn send_message(&mut self, payload: bitcoinz_message::NetworkMessage) -> Result<(), bitcoinz_error> {
        let message = bitcoinz_message::RawNetworkMessage {
            magic: network_id_to_bytes(self.runtime.network_id),
            payload: payload,
        };

        self.with_socket(|ref mut sock| {
            message
                .consensus_encode(&mut RawEncoder::new(&mut *sock))
                .map_err(bitcoinz_error::SerializationError)?;

            sock.flush().map_err(bitcoinz_error::Io)
        })
    }

    /// Receive a BitcoinZ protocol message on the wire
    /// If this method returns Err(ConnectionBroken), then the caller should attempt to re-connect.
    pub fn recv_message(&mut self) -> Result<PeerMessage, bitcoinz_error> {
        let magic = network_id_to_bytes(self.runtime.network_id);

        self.with_socket(|ref mut sock| {
            // read the message off the wire
            let mut decoder = RawDecoder::new(sock);

            let decoded: bitcoinz_message::RawNetworkMessage =
                ConsensusDecodable::consensus_decode(&mut decoder).map_err(|e| {
                    // if we can't finish a recv(), then report that the connection is broken
                    match e {
                        bitcoinz_serialize::Error::Io(ref io_error) => {
                            if io_error.kind() == io::ErrorKind::UnexpectedEof {
                                bitcoinz_error::ConnectionBroken
                            } else {
                                bitcoinz_error::Io(io::Error::new(
                                    io_error.kind(),
                                    "I/O error when processing message",
                                ))
                            }
                        }
                        _ => bitcoinz_error::SerializationError(e),
                    }
                })?;

            // sanity check -- must match our network
            if decoded.magic != magic {
                return Err(bitcoinz_error::InvalidMagic);
            }

            Ok(decoded.payload)
        })
    }

    /// Get sender address from our socket
    pub fn get_local_sockaddr(&mut self) -> Result<SocketAddr, bitcoinz_error> {
        self.with_socket(|ref mut sock| sock.local_addr().map_err(bitcoinz_error::Io))
    }

    /// Get receiver address from our socket
    pub fn get_remote_sockaddr(&mut self) -> Result<SocketAddr, bitcoinz_error> {
        self.with_socket(|ref mut sock| sock.peer_addr().map_err(bitcoinz_error::Io))
    }

    /// Handle and consume message we received, if we can.
    /// Returns UnhandledMessage if we can't handle the given message.
    pub fn handle_message<T: BitcoinZMessageHandler>(
        &mut self,
        message: PeerMessage,
        handler: Option<&mut T>,
    ) -> Result<bool, bitcoinz_error> {
        if self.runtime.last_getdata_send_time > 0
            && self.runtime.last_getdata_send_time + self.runtime.timeout < get_epoch_time_secs()
        {
            warn!("Timed out waiting for block data.  Killing connection.");
            return Err(bitcoinz_error::TimedOut);
        }

        if self.runtime.last_getheaders_send_time > 0
            && self.runtime.last_getheaders_send_time + self.runtime.timeout < get_epoch_time_secs()
        {
            warn!("Timed out waiting for headers data.  Killing connection.");
            return Err(bitcoinz_error::TimedOut);
        }

        // classify the message here, so we can pass it along to the handler explicitly
        match message {
            bitcoinz_message::NetworkMessage::Version(..) => {
                return self.handle_version(message).and_then(|_r| Ok(true));
            }
            bitcoinz_message::NetworkMessage::Verack => {
                return self.handle_verack(message).and_then(|_r| Ok(true));
            }
            bitcoinz_message::NetworkMessage::Ping(..) => {
                return self.handle_ping(message).and_then(|_r| Ok(true));
            }
            bitcoinz_message::NetworkMessage::Pong(..) => {
                return self.handle_pong(message).and_then(|_r| Ok(true));
            }
            _ => match handler {
                Some(custom_handler) => custom_handler.handle_message(self, message),
                None => Err(bitcoinz_error::UnhandledMessage(message)),
            },
        }
    }
}

/// Do the initial handshake to the remote peer.
/// Returns the remote peer's block height
pub fn peer_handshake(&mut self) -> Result<u64, bitcoinz_error> {
    debug!(
        "Begin peer handshake to {}:{}",
        self.config.peer_host, self.config.peer_port
    );
    self.send_version()?;
    let version_reply = self.recv_message()?;
    self.handle_version(version_reply)?;

    let verack_reply = self.recv_message()?;
    self.handle_verack(verack_reply)?;

    debug!(
        "Established connection to {}:{}, who has {} blocks",
        self.config.peer_host, self.config.peer_port, self.runtime.block_height
    );
    Ok(self.runtime.block_height)
}

/// Connect to a remote peer, do a handshake with the remote peer, and use exponential backoff until we
/// succeed in establishing a connection.
/// This method masks ConnectionBroken errors, but does not mask other network errors.
/// Returns the remote peer's block height on success
pub fn connect_handshake_backoff(&mut self) -> Result<u64, bitcoinz_error> {
    let mut backoff: f64 = 1.0;
    let mut rng = thread_rng();

    loop {
        let connection_result = self.connect();
        match connection_result {
            Ok(()) => {
                // connected!  now do the handshake
                let handshake_result = self.peer_handshake();
                match handshake_result {
                    Ok(block_height) => {
                        // connected!
                        return Ok(block_height);
                    }
                    Err(bitcoinz_error::ConnectionBroken) => {
                        // need to try again
                        backoff = 2.0 * backoff + (backoff * rng.gen_range(0.0..1.0));
                    }
                    Err(e) => {
                        // propagate other network error
                        warn!(
                            "Failed to handshake with {}:{}: {:?}",
                            &self.config.peer_host, self.config.peer_port, &e
                        );
                        return Err(e);
                    }
                }
            }
            Err(err_msg) => {
                error!(
                    "Failed to connect to peer {}:{}: {}",
                    &self.config.peer_host, self.config.peer_port, err_msg
                );
                backoff = 2.0 * backoff + (backoff * rng.gen_range(0.0..1.0));
            }
        }

        // don't sleep more than 60 seconds
        if backoff > 60.0 {
            backoff = 60.0;
        }

        if backoff > 10.0 {
            warn!("Connection broken; retrying in {} sec...", backoff);
        }

        if let Some(ref should_keep_running) = self.should_keep_running {
            if !should_keep_running.load(Ordering::SeqCst) {
                return Err(bitcoinz_error::TimedOut);
            }
        }

        let duration = time::Duration::from_millis((backoff * 1_000.0) as u64);
        thread::sleep(duration);
    }
}

/// Send a Version message
pub fn send_version(&mut self) -> Result<(), bitcoinz_error> {
    let timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(dur) => dur,
        Err(err) => err.duration(),
    }
    .as_secs() as i64;

    let local_addr = self.get_local_sockaddr()?;
    let remote_addr = self.get_remote_sockaddr()?;

    let sender_address = bitcoinz_network_address::Address::new(&local_addr, 0);
    let remote_address = bitcoinz_network_address::Address::new(&remote_addr, 0);

    let payload = bitcoinz_message_network::VersionMessage {
        version: bitcoinz_constants::PROTOCOL_VERSION,
        services: 0,
        timestamp: timestamp,
        receiver: remote_address,
        sender: sender_address,
        nonce: self.runtime.version_nonce,
        user_agent: self.runtime.user_agent.to_owned(),
        start_height: 0,
        relay: false,
    };

    debug!(
        "Send version (nonce={}) to {}:{}",
        self.runtime.version_nonce, self.config.peer_host, self.config.peer_port
    );
    self.send_message(bitcoinz_message::NetworkMessage::Version(payload))
}

/// Receive a Version message and reply with a Verack
pub fn handle_version(&mut self, version_message: PeerMessage) -> Result<(), bitcoinz_error> {
    match version_message {
        bitcoinz_message::NetworkMessage::Version(msg_body) => {
            debug!(
                "Handle version -- remote peer blockchain height is {}",
                msg_body.start_height
            );
            self.runtime.block_height = msg_body.start_height as u64;
            return self.send_verack();
        }
        _ => {
            error!("Did not receive version, but got {:?}", version_message);
        }
    };
    return Err(bitcoinz_error::InvalidMessage(version_message));
}

/// Send a verack
pub fn send_verack(&mut self) -> Result<(), bitcoinz_error> {
    let payload = bitcoinz_message::NetworkMessage::Verack;

    debug!("Send verack");
    self.send_message(payload)
}
    /// Handle a verack we received.
    /// Does nothing.
    pub fn handle_verack(&mut self, verack_message: PeerMessage) -> Result<(), bitcoinz_error> {
        match verack_message {
            bitcoinz_message::NetworkMessage::Verack => {
                debug!("Handle verack");
                return Ok(());
            }
            _ => {
                error!("Did not receive verack, but got {:?}", verack_message);
            }
        };
        Err(bitcoinz_error::InvalidMessage(verack_message))
    }

    /// Respond to a Ping message by sending a Pong message
    pub fn handle_ping(&mut self, ping_message: PeerMessage) -> Result<(), bitcoinz_error> {
        match ping_message {
            bitcoinz_message::NetworkMessage::Ping(ref n) => {
                debug!("Handle ping {}", n);
                let payload = bitcoinz_message::NetworkMessage::Pong(*n);

                debug!("Send pong {}", n);
                return self.send_message(payload);
            }
            _ => {
                error!("Did not receive ping, but got {:?}", ping_message);
            }
        };
        Err(bitcoinz_error::InvalidMessage(ping_message))
    }

    /// Respond to a Pong message.
    /// Does nothing.
    pub fn handle_pong(&mut self, pong_message: PeerMessage) -> Result<(), bitcoinz_error> {
        match pong_message {
            bitcoinz_message::NetworkMessage::Pong(n) => {
                debug!("Handle pong {}", n);
                return Ok(());
            }
            _ => {
                error!("Did not receive pong, but got {:?}", pong_message);
            }
        };
        Err(bitcoinz_error::InvalidReply)
    }

    /// Send a GetHeaders message
    /// Note that this isn't a generic GetHeaders message -- you should use this only to ask
    /// for a batch of 2,000 block hashes after this given hash.
    pub fn send_getheaders(&mut self, prev_block_hash: Sha256dHash) -> Result<(), bitcoinz_error> {
        let getheaders =
            bitcoinz_message_blockdata::GetHeadersMessage::new(vec![prev_block_hash], prev_block_hash);
        let payload = bitcoinz_message::NetworkMessage::GetHeaders(getheaders);

        debug!(
            "Send GetHeaders {} for 2000 headers to {}:{}",
            prev_block_hash.be_hex_string(),
            self.config.peer_host,
            self.config.peer_port
        );

        self.runtime.last_getheaders_send_time = get_epoch_time_secs();
        self.send_message(payload)
    }

    /// Send a GetData message
    pub fn send_getdata(&mut self, block_hashes: &Vec<Sha256dHash>) -> Result<(), bitcoinz_error> {
        assert!(block_hashes.len() > 0);
        let getdata_invs = block_hashes
            .iter()
            .map(|h| bitcoinz_message_blockdata::Inventory {
                inv_type: bitcoinz_message_blockdata::InvType::Block,
                hash: h.clone(),
            })
            .collect();

        let getdata = bitcoinz_message::NetworkMessage::GetData(getdata_invs);

        self.runtime.last_getdata_send_time = get_epoch_time_secs();
        debug!(
            "Send GetData {}-{} to {}:{}",
            block_hashes[0].be_hex_string(),
            block_hashes[block_hashes.len() - 1].be_hex_string(),
            self.config.peer_host,
            self.config.peer_port
        );
        self.send_message(getdata)
    }
