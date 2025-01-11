// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use crate::{
    crypto::{
        chachapoly::{ChaCha, ChaChaPoly},
        hmac::Hmac,
        sha256::Sha256,
        EphemeralPrivateKey, EphemeralPublicKey, StaticPrivateKey,
    },
    runtime::{Runtime, UdpSocket},
    transports::ssu2::message::{AeadState, Block, HeaderBuilder, MessageBuilder, MessageType},
};

use bytes::{Buf, Bytes, BytesMut};
use hashbrown::HashMap;
use rand_core::RngCore;
use thingbuf::mpsc::{Receiver, Sender};

use alloc::collections::VecDeque;
use core::{
    future::Future,
    mem,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::socket";

/// Read buffer length.
const READ_BUFFER_LEN: usize = 2048usize;

/// Protocol name.
const PROTOCOL_NAME: &str = "Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256";

/// Events emitted by [`Ssu2Socket`].
#[derive(Debug, Default, Clone)]
pub enum Ssu2SessionEvent {
    #[default]
    Dummy,
}

/// Write state.
enum WriteState {
    /// Get next packet.
    GetPacket,

    /// Send packet.
    SendPacket {
        /// Packet.
        pkt: BytesMut,

        /// Target.
        target: SocketAddr,
    },

    /// Poisoned.
    Poisoned,
}

/// SSU2 socket.
pub struct Ssu2Socket<R: Runtime> {
    /// Receive buffer.
    buffer: Vec<u8>,

    /// Chaining key.
    chaining_key: Bytes,

    /// Inbound state.
    inbound_state: Bytes,

    /// Intro key.
    intro_key: StaticPrivateKey,

    /// Raw intro key bytes.
    intro_key_raw: [u8; 32],

    /// Outbound state.
    outbound_state: Bytes,

    /// Pending outbound packets.
    pending_pkts: VecDeque<(BytesMut, SocketAddr)>,

    /// TX channel for sending session events to [`Ssu2`].
    session_tx: Sender<Ssu2SessionEvent>,

    /// SSU2 sessions.
    sessions: HashMap<u64, ()>,

    /// UDP socket.
    socket: R::UdpSocket,

    /// Static key.
    static_key: StaticPrivateKey,

    /// Write state.
    write_state: WriteState,
}

impl<R: Runtime> Ssu2Socket<R> {
    /// Create new [`Ssu2Socket`].
    pub fn new(
        socket: R::UdpSocket,
        static_key: StaticPrivateKey,
        intro_key: StaticPrivateKey,
        session_tx: Sender<Ssu2SessionEvent>,
    ) -> Self {
        let state = Sha256::new().update(PROTOCOL_NAME.as_bytes()).finalize();
        let chaining_key = state.clone();
        let outbound_state = Sha256::new().update(&state).finalize();
        let inbound_state = Sha256::new()
            .update(&outbound_state)
            .update(static_key.public().to_vec())
            .finalize();

        let intro_key_raw =
            TryInto::<[u8; 32]>::try_into(intro_key.public().to_vec()).expect("to succeed");

        Self {
            buffer: vec![0u8; READ_BUFFER_LEN],
            chaining_key: Bytes::from(chaining_key),
            inbound_state: Bytes::from(inbound_state),
            intro_key,
            intro_key_raw,
            outbound_state: Bytes::from(outbound_state),
            pending_pkts: VecDeque::new(),
            sessions: HashMap::new(),
            session_tx,
            socket,
            static_key: StaticPrivateKey::from(static_key),
            write_state: WriteState::GetPacket,
        }
    }

    /// Handle packet.
    //
    // TODO: needs as lot of refactoring
    fn handle_packet(&mut self, nread: usize, address: SocketAddr) {
        tracing::trace!(
            target: LOG_TARGET,
            ?nread,
            "handle packet",
        );

        let iv1 = TryInto::<[u8; 12]>::try_into(&self.buffer[nread - 24..nread - 12])
            .expect("to succeed");
        let iv2 =
            TryInto::<[u8; 12]>::try_into(&self.buffer[nread - 12..nread]).expect("to succeed");
        let mut mask = [0u8; 8];
        ChaCha::with_iv(self.intro_key_raw, iv1).decrypt_ref(&mut mask);

        let connection_id = u64::from_be(mask.into_iter().zip(&mut self.buffer).fold(
            0u64,
            |connection_id, (a, b)| {
                *b ^= a;

                (connection_id << 8) | (*b as u64)
            },
        ));

        tracing::info!(
            target: LOG_TARGET,
            ?connection_id,
            "received message"
        );

        if self.sessions.contains_key(&connection_id) {
            tracing::info!("handle message for active session");
            todo!();
        }

        ChaCha::with_iv(self.intro_key_raw, iv2)
            .decrypt([0u8; 8])
            .into_iter()
            .zip(&mut self.buffer[8..])
            .for_each(|(a, b)| {
                *b ^= a;
            });

        match MessageType::try_from(self.buffer[12]) {
            Ok(MessageType::TokenRequest) => {
                let pkt_num = u32::from_le_bytes(
                    TryInto::<[u8; 4]>::try_into(&self.buffer[8..12]).expect("to succeed"),
                );

                tracing::info!(
                    target: LOG_TARGET,
                    ?pkt_num,
                    version = ?self.buffer[13],
                    net_id = ?self.buffer[14],
                    "handle token request",
                );

                ChaCha::with_iv(self.intro_key_raw, [0u8; 12])
                    .decrypt_ref(&mut self.buffer[16..32]);

                let src_connection_id = u64::from_le_bytes(
                    TryInto::<[u8; 8]>::try_into(&self.buffer[16..24]).expect("to succeed"),
                );
                let token = u64::from_le_bytes(
                    TryInto::<[u8; 8]>::try_into(&self.buffer[24..32]).expect("to succeed"),
                );

                let mut payload = self.buffer[32..nread].to_vec();
                ChaChaPoly::with_nonce(&self.intro_key_raw, pkt_num.to_be() as u64)
                    .decrypt_with_ad(&self.buffer[..32], &mut payload)
                    .unwrap();

                match Block::parse(&payload) {
                    Some(blocks) => blocks.into_iter().for_each(|block| {
                        tracing::trace!(target: LOG_TARGET, "block = {block:?}");
                    }),
                    None => tracing::error!(
                        target: LOG_TARGET,
                        "failed to parse blocks",
                    ),
                }

                let token = R::rng().next_u64();
                let pkt = MessageBuilder::new(
                    HeaderBuilder::long()
                        .with_dst_id(connection_id)
                        .with_src_id(src_connection_id)
                        .with_token(token)
                        .with_message_type(MessageType::Retry)
                        .build::<R>(),
                )
                .with_key(self.intro_key_raw)
                .with_block(Block::DateTime {
                    timestamp: R::time_since_epoch().as_secs() as u32,
                })
                .with_block(Block::Address { address })
                .build();

                self.pending_pkts.push_back((pkt, address));
            }
            Ok(MessageType::SessionRequest) => {
                let pkt_num = u32::from_le_bytes(
                    TryInto::<[u8; 4]>::try_into(&self.buffer[8..12]).expect("to succeed"),
                );

                tracing::info!(
                    target: LOG_TARGET,
                    ?pkt_num,
                    version = ?self.buffer[13],
                    net_id = ?self.buffer[14],
                    "handle session request",
                );

                ChaCha::with_iv(self.intro_key_raw, [0u8; 12])
                    .decrypt_ref(&mut self.buffer[16..64]);

                let src_connection_id = u64::from_le_bytes(
                    TryInto::<[u8; 8]>::try_into(&self.buffer[16..24]).expect("to succeed"),
                );

                // TODO: extract token and verify it's valid

                let state =
                    Sha256::new().update(&self.inbound_state).update(&self.buffer[..32]).finalize();
                let state = Sha256::new().update(state).update(&self.buffer[32..64]).finalize();

                let public_key =
                    EphemeralPublicKey::from_bytes(&self.buffer[32..64]).expect("to succeed");
                let shared = self.static_key.diffie_hellman(&public_key);

                let mut temp_key = Hmac::new(&self.chaining_key).update(&shared).finalize();
                let chaining_key = Hmac::new(&temp_key).update([0x01]).finalize();
                let mut cipher_key =
                    Hmac::new(&temp_key).update(&chaining_key).update([0x02]).finalize();

                // TODO: derive sessioncreated header keyfrom `cipher_key` (??)
                // HKDF(chainKey, ZEROLEN, "SessCreateHeader", 32)
                let temp_key = Hmac::new(&chaining_key).update([]).finalize();
                let k_header_2 =
                    Hmac::new(&temp_key).update(b"SessCreateHeader").update([0x01]).finalize();
                let k_header_2 = TryInto::<[u8; 32]>::try_into(k_header_2).unwrap();

                // state for `SessionCreated`
                let new_state =
                    Sha256::new().update(&state).update(&self.buffer[64..nread]).finalize();

                let mut payload = self.buffer[64..nread].to_vec();
                ChaChaPoly::with_nonce(&cipher_key, 0u64)
                    .decrypt_with_ad(&state, &mut payload)
                    .unwrap();

                match Block::parse(&payload) {
                    Some(blocks) => blocks.into_iter().for_each(|block| {
                        tracing::trace!(target: LOG_TARGET, "block = {block:?}");
                    }),
                    None => tracing::error!(
                        target: LOG_TARGET,
                        "failed to parse blocks",
                    ),
                }

                let sk = EphemeralPrivateKey::random(R::rng());
                let pk = sk.public();

                let shared = sk.diffie_hellman(&public_key);

                let mut temp_key = Hmac::new(&chaining_key).update(&shared).finalize();
                let chaining_key = Hmac::new(&temp_key).update([0x01]).finalize();
                let mut cipher_key =
                    Hmac::new(&temp_key).update(&chaining_key).update([0x02]).finalize();

                let token = R::rng().next_u64();
                // TODO: probably unnecessary memory copies here and below
                let pkt = MessageBuilder::new(
                    HeaderBuilder::long()
                        .with_dst_id(connection_id)
                        .with_src_id(src_connection_id)
                        .with_token(0u64)
                        .with_message_type(MessageType::SessionCreated)
                        .build::<R>(),
                )
                .with_keypair(self.intro_key_raw, k_header_2)
                .with_ephemeral_key(pk)
                .with_aead_state(AeadState {
                    state: new_state,
                    cipher_key,
                    nonce: 0u64,
                })
                .with_block(Block::DateTime {
                    timestamp: R::time_since_epoch().as_secs() as u32,
                })
                .with_block(Block::Address { address })
                .build();

                self.pending_pkts.push_back((BytesMut::from(&pkt[..]), address));

                // TODO: create new session

                tracing::error!("-------------------------------------------------------------");
            }
            Ok(message_type) => {
                tracing::error!(
                    target: LOG_TARGET,
                    ?message_type,
                    "not supported",
                );
            }
            Err(()) => tracing::warn!(
                target: LOG_TARGET,
                message_type = ?self.buffer[12],
                "unrecognized message type",
            ),
        }
    }
}

impl<R: Runtime> Future for Ssu2Socket<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        loop {
            match Pin::new(&mut this.socket).poll_recv_from(cx, &mut this.buffer.as_mut()) {
                Poll::Pending => break,
                Poll::Ready(None) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "socket closed",
                    );
                    return Poll::Ready(());
                }
                Poll::Ready(Some((nread, from))) => {
                    this.handle_packet(nread, from);
                }
            }
        }

        loop {
            match mem::replace(&mut this.write_state, WriteState::Poisoned) {
                WriteState::GetPacket => match this.pending_pkts.pop_front() {
                    None => {
                        this.write_state = WriteState::GetPacket;
                        break;
                    }
                    Some((pkt, target)) => {
                        this.write_state = WriteState::SendPacket { pkt, target };
                    }
                },
                WriteState::SendPacket { pkt, target } =>
                    match Pin::new(&mut this.socket).poll_send_to(cx, &pkt, target) {
                        Poll::Ready(Some(_)) => {
                            this.write_state = WriteState::GetPacket;
                        }
                        Poll::Ready(None) => return Poll::Ready(()),
                        Poll::Pending => {
                            this.write_state = WriteState::SendPacket { pkt, target };
                            break;
                        }
                    },
                WriteState::Poisoned => unreachable!(),
            }
        }

        Poll::Pending
    }
}
