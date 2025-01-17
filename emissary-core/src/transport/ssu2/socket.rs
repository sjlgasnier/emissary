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
        base64_decode,
        chachapoly::{ChaCha, ChaChaPoly},
        hmac::Hmac,
        sha256::Sha256,
        EphemeralPrivateKey, EphemeralPublicKey, StaticPrivateKey,
    },
    primitives::{RouterId, RouterInfo, Str, TransportKind},
    runtime::{JoinSet, Runtime, UdpSocket},
    subsystem::SubsystemHandle,
    transport::{
        ssu2::{
            message::{AeadState, Block, HeaderBuilder, MessageBuilder, MessageType},
            session::{
                active::{Ssu2Session, Ssu2SessionContext},
                pending::{
                    PendingSsu2Session, PendingSsu2SessionContext, PendingSsu2SessionStatus,
                },
            },
            Packet,
        },
        TransportEvent,
    },
};

use bytes::{Buf, Bytes, BytesMut};
use futures::{Stream, StreamExt};
use hashbrown::HashMap;
use rand_core::RngCore;
use thingbuf::mpsc::{channel, Receiver, Sender};

use alloc::collections::VecDeque;
use core::{
    future::Future,
    mem,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll, Waker},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::socket";

/// Protocol name.
const PROTOCOL_NAME: &str = "Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256";

/// Read buffer length.
const READ_BUFFER_LEN: usize = 2048usize;

/// SSU2 session channel size.
///
/// This is the channel from [`Ssu2Socket`] to a pending/active SSU2 session.
const CHANNEL_SIZE: usize = 256usize;

/// SSU2 packet channel size.
///
/// Used to receive datagrams from active sessions.
const PKT_CHANNEL_SIZE: usize = 8192usize;

/// Events emitted by [`Ssu2Socket`].
#[derive(Debug, Default, Clone)]
pub enum Ssu2SessionCommand {
    /// Accept connection.
    Accept {
        /// Router ID.
        router_id: RouterId,
    },

    /// Reject connection.
    Reject {
        /// Router ID.
        router_id: RouterId,
    },

    /// Connect to router.
    Connect {
        /// Router info.
        router_info: RouterInfo,
    },

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
    /// Active sessions.
    ///
    /// The session returns a `(RouterId, destination connection ID)` tuple when it exits.
    active_sessions: R::JoinSet<(RouterId, u64)>,

    /// Receive buffer.
    buffer: Vec<u8>,

    /// Chaining key.
    chaining_key: Bytes,

    /// Inbound state.
    inbound_state: Bytes,

    /// Introduction key.
    intro_key: [u8; 32],

    /// Outbound state.
    outbound_state: Bytes,

    /// Pending outbound sessions.
    ///
    /// Remote routers' intro keys indexed by their socket addresses.
    pending_outbound: HashMap<SocketAddr, [u8; 32]>,

    /// Pending outbound packets.
    pending_pkts: VecDeque<(BytesMut, SocketAddr)>,

    /// Pending SSU2 sessions.
    pending_sessions: R::JoinSet<PendingSsu2SessionStatus>,

    /// RX channel for receiving packets from active sessions.
    pkt_rx: Receiver<Packet>,

    /// TX channel given to active sessions.
    pkt_tx: Sender<Packet>,

    /// SSU2 sessions.
    sessions: HashMap<u64, Sender<Packet>>,

    /// UDP socket.
    socket: R::UdpSocket,

    /// Static key.
    static_key: StaticPrivateKey,

    /// Subsystem handle.
    subsystem_handle: SubsystemHandle,

    /// Local router info.
    //
    // TODO: bytes
    router_info: Vec<u8>,

    /// Unvalidated sessions.
    unvalidated_sessions: HashMap<RouterId, Ssu2SessionContext>,

    /// Waker.
    waker: Option<Waker>,

    /// Write state.
    write_state: WriteState,
}

impl<R: Runtime> Ssu2Socket<R> {
    /// Create new [`Ssu2Socket`].
    pub fn new(
        socket: R::UdpSocket,
        static_key: StaticPrivateKey,
        intro_key: [u8; 32],
        subsystem_handle: SubsystemHandle,
        router_info: Vec<u8>,
    ) -> Self {
        let state = Sha256::new().update(PROTOCOL_NAME.as_bytes()).finalize();
        let chaining_key = state.clone();
        let outbound_state = Sha256::new().update(&state).finalize();
        let inbound_state = Sha256::new()
            .update(&outbound_state)
            .update(static_key.public().to_vec())
            .finalize();

        // create channel pair which is used to exchange outbound packets
        // with active sessions and `Ssu2Socket`
        //
        // TODO: implement `Clone` for `R::UdpSocket`
        let (pkt_tx, pkt_rx) = channel(PKT_CHANNEL_SIZE);

        Self {
            active_sessions: R::join_set(),
            buffer: vec![0u8; READ_BUFFER_LEN],
            chaining_key: Bytes::from(chaining_key),
            inbound_state: Bytes::from(inbound_state),
            intro_key,
            outbound_state: Bytes::from(outbound_state),
            pending_outbound: HashMap::new(),
            pending_pkts: VecDeque::new(),
            pending_sessions: R::join_set(),
            pkt_rx,
            pkt_tx,
            sessions: HashMap::new(),
            socket,
            static_key: StaticPrivateKey::from(static_key),
            subsystem_handle,
            unvalidated_sessions: HashMap::new(),
            waker: None,
            router_info,
            write_state: WriteState::GetPacket,
        }
    }

    /// Handle packet.
    //
    // TODO: needs as lot of refactoring
    fn handle_packet(&mut self, nread: usize, address: SocketAddr) {
        // TODO: ensure size
        let iv1 = TryInto::<[u8; 12]>::try_into(&self.buffer[nread - 24..nread - 12])
            .expect("to succeed");
        let iv2 =
            TryInto::<[u8; 12]>::try_into(&self.buffer[nread - 12..nread]).expect("to succeed");
        ChaCha::with_iv(self.intro_key, iv1)
            .decrypt([0u8; 8])
            .into_iter()
            .zip(&mut self.buffer[..8])
            .for_each(|(a, b)| {
                *b ^= a;
            });
        let connection_id = u64::from_le_bytes(
            TryInto::<[u8; 8]>::try_into(&self.buffer[..8]).expect("to succeed"),
        );

        if let Some(tx) = self.sessions.get_mut(&connection_id) {
            if let Err(error) = tx.try_send(Packet {
                pkt: self.buffer[..nread].to_vec(),
                address,
            }) {
                // tracing::debug!(
                //     target: LOG_TARGET,
                //     ?connection_id,
                //     ?error,
                //     "failed to send datagram to ssu2 session",
                // );
            }
            return;
        }

        tracing::info!(
            target: LOG_TARGET,
            ?connection_id,
            "received message"
        );

        ChaCha::with_iv(self.intro_key, iv2)
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

                ChaCha::with_iv(self.intro_key, [0u8; 12]).decrypt_ref(&mut self.buffer[16..32]);

                let src_connection_id = u64::from_le_bytes(
                    TryInto::<[u8; 8]>::try_into(&self.buffer[16..24]).expect("to succeed"),
                );
                let token = u64::from_le_bytes(
                    TryInto::<[u8; 8]>::try_into(&self.buffer[24..32]).expect("to succeed"),
                );

                let mut payload = self.buffer[32..nread].to_vec();
                ChaChaPoly::with_nonce(&self.intro_key, pkt_num.to_be() as u64)
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
                .with_key(self.intro_key)
                .with_block(Block::DateTime {
                    timestamp: R::time_since_epoch().as_secs() as u32,
                })
                .with_block(Block::Address { address })
                .build::<R>();

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

                ChaCha::with_iv(self.intro_key, [0u8; 12]).decrypt_ref(&mut self.buffer[16..64]);

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

                let mut aead_state = AeadState {
                    cipher_key: cipher_key.clone(),
                    nonce: 0u64,
                    state: new_state,
                };

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
                .with_keypair(self.intro_key, k_header_2)
                .with_ephemeral_key(pk)
                .with_aead_state(&mut aead_state)
                .with_block(Block::DateTime {
                    timestamp: R::time_since_epoch().as_secs() as u32,
                })
                .with_block(Block::Address { address })
                .build::<R>();

                self.pending_pkts.push_back((BytesMut::from(&pkt[..]), address));

                // create new session
                let temp_key = Hmac::new(&chaining_key).update([]).finalize();
                let k_header_2 =
                    Hmac::new(&temp_key).update(b"SessionConfirmed").update([0x01]).finalize();
                let k_header_2 = TryInto::<[u8; 32]>::try_into(k_header_2).unwrap();
                let k_session_created = TryInto::<[u8; 32]>::try_into(cipher_key).unwrap();

                let (tx, rx) = channel(CHANNEL_SIZE);
                self.sessions.insert(connection_id, tx);
                self.pending_sessions.push(PendingSsu2Session::<R>::new(
                    PendingSsu2SessionContext::Inbound {
                        address,
                        dst_id: connection_id,
                        src_id: src_connection_id,
                        k_header_1: self.intro_key.clone(),
                        k_header_2,
                        k_session_created,
                        chaining_key,
                        ephemeral_key: sk,
                        rx,
                        state: aead_state.state,
                    },
                ));
            }
            Ok(message_type) => {
                tracing::error!(
                    target: LOG_TARGET,
                    ?message_type,
                    "not supported",
                );
            }
            Err(()) => match self.pending_outbound.get(&address) {
                Some(intro_key) => {
                    // undo header decryption done with incorrect key
                    ChaCha::with_iv(self.intro_key, iv1)
                        .decrypt([0u8; 8])
                        .into_iter()
                        .zip(&mut self.buffer[..8])
                        .for_each(|(a, b)| {
                            *b ^= a;
                        });
                    ChaCha::with_iv(self.intro_key, iv2)
                        .decrypt([0u8; 8])
                        .into_iter()
                        .zip(&mut self.buffer[8..])
                        .for_each(|(a, b)| {
                            *b ^= a;
                        });

                    // re-decrypt
                    ChaCha::with_iv(*intro_key, iv1)
                        .decrypt([0u8; 8])
                        .into_iter()
                        .zip(&mut self.buffer[..8])
                        .for_each(|(a, b)| {
                            *b ^= a;
                        });

                    let connection_id = u64::from_le_bytes(
                        TryInto::<[u8; 8]>::try_into(&self.buffer[..8]).expect("to succeed"),
                    );

                    if let Some(tx) = self.sessions.get_mut(&connection_id) {
                        if let Err(error) = tx.try_send(Packet {
                            pkt: self.buffer[..nread].to_vec(),
                            address,
                        }) {
                            // tracing::debug!(
                            //     target: LOG_TARGET,
                            //     ?connection_id,
                            //     ?error,
                            //     "failed to send datagram to ssu2 session",
                            // );
                        }
                        return;
                    } else {
                        tracing::error!("not found after check");
                    }
                }
                None => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        message_type = ?self.buffer[12],
                        "unrecognized message type",
                    );
                }
            },
        }
    }

    pub fn connect(&mut self, router_info: RouterInfo) {
        tracing::debug!(
            target: LOG_TARGET,
            router_id = %router_info.identity.id(),
            "establish outbound session",
        );

        // must succeed since `TransportManager` has ensured `router_info` contains
        // a valid and reachable ssu2 router address
        //
        // TODO: add helper code for all of this in `RouterAddress`
        let address = router_info.addresses.get(&TransportKind::Ssu2).expect("to exist");
        let intro_key = {
            let intro_key = address.options.get(&Str::from("i")).expect("to exist");
            let intro_key = base64_decode(&intro_key.as_bytes()).expect("to succeed");

            TryInto::<[u8; 32]>::try_into(intro_key).expect("to succeed")
        };
        let static_key = {
            let static_key = address.options.get(&Str::from("s")).expect("to exist");
            let static_key = base64_decode(&static_key.as_bytes()).expect("to succeed");

            TryInto::<[u8; 32]>::try_into(static_key).expect("to succeed")
        };
        let address = address.socket_address.expect("to exist");

        let state = Sha256::new().update(&self.outbound_state).update(static_key).finalize();
        let src_id = R::rng().next_u64();
        let dst_id = R::rng().next_u64();

        let (tx, rx) = channel(CHANNEL_SIZE);
        self.sessions.insert(src_id, tx);

        self.pending_outbound.insert(address, intro_key);
        self.pending_sessions.push(PendingSsu2Session::<R>::new(
            PendingSsu2SessionContext::Outbound {
                address,
                chaining_key: self.chaining_key.clone(),
                local_static_key: self.static_key.clone(),
                router_id: router_info.identity.id(),
                dst_id,
                intro_key,
                pkt_tx: self.pkt_tx.clone(),
                rx,
                src_id,
                state,
                static_key,
                router_info: self.router_info.clone(),
            },
        ));

        if let Some(waker) = self.waker.take() {
            waker.wake_by_ref();
        }
    }

    pub fn accept(&mut self, router_id: &RouterId) {
        match self.unvalidated_sessions.remove(router_id) {
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    %router_id,
                    "non-existent unvalidated session accepted",
                );
                debug_assert!(false);
            }
            Some(context) => {
                tracing::trace!(
                    target: LOG_TARGET,
                    %router_id,
                    "session accepted",
                );

                self.active_sessions.push(
                    Ssu2Session::<R>::new(
                        context,
                        self.pkt_tx.clone(),
                        self.subsystem_handle.clone(),
                    )
                    .run(),
                );

                if let Some(waker) = self.waker.take() {
                    waker.wake_by_ref();
                }
            }
        }
    }

    pub fn reject(&mut self, router_id: &RouterId) {
        match self.unvalidated_sessions.remove(router_id) {
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    %router_id,
                    "non-existent unvalidated session rejected",
                );
                debug_assert!(false);
            }
            Some(context) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    "session rejected",
                );
                // TODO: send termination
            }
        }
    }
}

impl<R: Runtime> Stream for Ssu2Socket<R> {
    type Item = TransportEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;

        loop {
            match Pin::new(&mut this.socket).poll_recv_from(cx, &mut this.buffer.as_mut()) {
                Poll::Pending => break,
                Poll::Ready(None) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "socket closed",
                    );
                    return Poll::Ready(None);
                }
                Poll::Ready(Some((nread, from))) => {
                    this.handle_packet(nread, from);
                }
            }
        }

        loop {
            match this.active_sessions.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some((router_id, dst_id))) =>
                    return Poll::Ready(Some(TransportEvent::ConnectionClosed { router_id })),
            }
        }

        loop {
            match this.pending_sessions.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(PendingSsu2SessionStatus::NewInboundSession {
                    context,
                    pkt,
                    target,
                })) => {
                    let router_id = context.router_id.clone();

                    tracing::trace!(
                        target: LOG_TARGET,
                        %router_id,
                        "inbound session negotiated",
                    );

                    this.pending_pkts.push_back((pkt, target));
                    this.unvalidated_sessions.insert(router_id.clone(), context);

                    return Poll::Ready(Some(TransportEvent::ConnectionEstablished { router_id }));
                }
                Poll::Ready(Some(PendingSsu2SessionStatus::NewOutboundSession { context })) => {
                    let router_id = context.router_id.clone();

                    tracing::trace!(
                        target: LOG_TARGET,
                        %router_id,
                        "outbound session negotiated",
                    );

                    this.unvalidated_sessions.insert(router_id.clone(), context);

                    return Poll::Ready(Some(TransportEvent::ConnectionEstablished { router_id }));
                }
                Poll::Ready(Some(PendingSsu2SessionStatus::SocketClosed)) =>
                    return Poll::Ready(None),
            }
        }

        loop {
            match this.pkt_rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                // TODO: useless conversion from vec to bytesmut
                Poll::Ready(Some(Packet { pkt, address })) =>
                    this.pending_pkts.push_back((BytesMut::from(&pkt[..]), address)),
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
                        Poll::Ready(None) => return Poll::Ready(None),
                        Poll::Pending => {
                            this.write_state = WriteState::SendPacket { pkt, target };
                            break;
                        }
                    },
                WriteState::Poisoned => unreachable!(),
            }
        }

        self.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}
