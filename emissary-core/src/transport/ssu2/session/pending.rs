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
        EphemeralPrivateKey, EphemeralPublicKey, StaticPrivateKey, StaticPublicKey,
    },
    primitives::{RouterId, Str, TransportKind},
    runtime::Runtime,
    transport::ssu2::{
        message::{
            AeadState, Block, HeaderBuilder, MessageBuilder, MessageType, NoiseContext,
            SessionConfirmedBuilder, SessionRequestBuilder, ShortHeaderFlag, TokenRequestBuilder,
        },
        session::active::{KeyContext, Ssu2SessionContext},
        Packet,
    },
};

use bytes::{Bytes, BytesMut};
use thingbuf::mpsc::{Receiver, Sender};

use core::{
    future::Future,
    marker::PhantomData,
    mem,
    net::SocketAddr,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};

// TODO: no unwraps
// TODO: refactor
// TODO: separate inbound/outbound handling to separate files

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::session::pending";

/// Pending session context.
pub enum PendingSsu2SessionContext {
    /// Pending inbound session.
    Inbound {
        /// Socket address of the remote router.
        address: SocketAddr,

        /// Chaining key.
        chaining_key: Vec<u8>,

        /// Destination connection ID.
        dst_id: u64,

        /// Our ephemeral private key.
        ephemeral_key: EphemeralPrivateKey,

        /// Key for decrypting first part of the header.
        k_header_1: [u8; 32],

        /// Key for decrypting second part of the header.
        k_header_2: [u8; 32],

        /// Key for decrypting the `SessionCreated` message.
        k_session_created: [u8; 32],

        /// RX channel for receiving datagrams from `Ssu2Socket`.
        rx: Receiver<Packet>,

        /// Source connection ID.
        src_id: u64,

        /// AEAD state.
        state: Vec<u8>,
    },

    /// Pending outbound session.
    Outbound {
        /// Socket address of the remote router.
        address: SocketAddr,

        /// Chaining key.
        chaining_key: Bytes,

        /// ID of the remote router.
        router_id: RouterId,

        /// Destination connection ID.
        dst_id: u64,

        /// Remote router's intro key.
        intro_key: [u8; 32],

        /// TX channel for sending packets to [`Ssu2Socket`].
        pkt_tx: Sender<Packet>,

        /// RX channel for receiving datagrams from `Ssu2Socket`.
        rx: Receiver<Packet>,

        /// Source connection ID.
        src_id: u64,

        /// AEAD state.
        state: Vec<u8>,

        /// Remote router's static key.
        static_key: [u8; 32],

        /// Local static key.
        local_static_key: StaticPrivateKey,
        router_info: Vec<u8>,
    },
}

/// Status returned by [`PendingSession`] to [`Ssu2Socket`].
pub enum PendingSsu2SessionStatus {
    /// New session has been opened.
    ///
    /// Session info is forwaded to [`Ssu2Socket`] and to [`TransportManager`] for validation and
    /// if the session is accepted, a new future is started for the session.
    NewInboundSession {
        /// Context for the active session.
        context: Ssu2SessionContext,

        /// ACK for `SessionConfirmed`.
        pkt: BytesMut,

        /// Socket address of the remote router.
        target: SocketAddr,
    },

    /// New outbound session.
    NewOutboundSession {
        /// Context for the active session.
        context: Ssu2SessionContext,
    },

    /// [`SSu2Socket`] has been closed.
    SocketClosed,
}

/// Pending session state.
enum PendingSsu2SessionState {
    /// Awaiting `SessionConfirmed` message from remote router.
    AwaitingSessionConfirmed {
        /// Chaining key.
        chaining_key: Vec<u8>,

        /// Our ephemeral private key.
        ephemeral_key: EphemeralPrivateKey,

        /// Cipher key for decrypting the second part of the header
        k_header_2: [u8; 32],

        /// Key for decrypting the `SessionCreated` message.
        k_session_created: [u8; 32],

        /// Source connection ID.
        src_id: u64,

        /// AEAD state from `SessionCreated` message.
        state: Vec<u8>,
    },

    /// Send `TokenRequest` to remote router.
    SendTokenRequest {
        /// Chaining key.
        chaining_key: Bytes,

        /// Local static key.
        local_static_key: StaticPrivateKey,

        /// TX channel for sending packets to [`Ssu2Socket`].
        pkt_tx: Sender<Packet>,

        /// Router ID.
        router_id: RouterId,

        router_info: Vec<u8>,

        /// Source connection ID.
        src_id: u64,

        /// AEAD state.
        state: Vec<u8>,
        /// Remote router's static key.
        static_key: [u8; 32],
    },

    /// Awaiting `SessionCreated` message from remote router.
    AwaitingSessionCreated {
        router_info: Vec<u8>,
        noise_ctx: NoiseContext,
        intro_key: [u8; 32],
        pkt_tx: Sender<Packet>,
        src_id: u64,
        router_id: RouterId,
    },

    /// Awaiting first ACK to be received.
    AwaitingFirstAck {
        /// Noise context.
        noise_ctx: NoiseContext,
        router_id: RouterId,
        intro_key: [u8; 32],
    },

    /// State has been poisoned.
    Poisoned,
}

/// Pending SSU2 session.
pub struct PendingSsu2Session<R: Runtime> {
    /// Socket address of the remote router.
    address: SocketAddr,

    /// Destination connection ID.
    dst_id: u64,

    /// Intro key.
    intro_key: [u8; 32],

    /// RX channel for receiving datagrams from `Ssu2Socket`.
    rx: Option<Receiver<Packet>>,

    /// Pending session state.
    state: PendingSsu2SessionState,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> PendingSsu2Session<R> {
    /// Create new [`PendingSsu2Session`].
    pub fn new(context: PendingSsu2SessionContext) -> Self {
        match context {
            PendingSsu2SessionContext::Inbound {
                address,
                chaining_key,
                dst_id,
                ephemeral_key,
                k_header_1,
                k_header_2,
                k_session_created,
                rx,
                src_id,
                state,
            } => Self {
                address,
                intro_key: k_header_1,
                dst_id,
                rx: Some(rx),
                state: PendingSsu2SessionState::AwaitingSessionConfirmed {
                    chaining_key,
                    ephemeral_key,
                    k_header_2,
                    k_session_created,
                    src_id,
                    state,
                },
                _runtime: Default::default(),
            },
            PendingSsu2SessionContext::Outbound {
                address,
                chaining_key,
                dst_id,
                intro_key,
                pkt_tx,
                router_info,
                rx,
                src_id,
                state,
                static_key,
                router_id,
                local_static_key,
            } => {
                tracing::info!(target: LOG_TARGET, "send token request");

                let pkt = TokenRequestBuilder::default()
                    .with_dst_id(dst_id)
                    .with_src_id(src_id)
                    .with_intro_key(intro_key)
                    .build::<R>()
                    .to_vec();

                // TODO: retransmissions
                if let Err(error) = pkt_tx.try_send(Packet { pkt, address }) {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?error,
                        ?address,
                        "failed to send `TokenRequest`",
                    );
                }

                Self {
                    address,
                    dst_id,
                    intro_key,
                    rx: Some(rx),
                    state: PendingSsu2SessionState::SendTokenRequest {
                        chaining_key,
                        router_id,
                        local_static_key,
                        pkt_tx,
                        src_id,
                        state,
                        static_key,
                        router_info,
                    },
                    _runtime: Default::default(),
                }
            }
        }
    }

    /// Handle received packet to a pending session.
    ///
    /// `pkt` contains the full header but the first part of the header has been decrypted by the
    /// `Ssu2Socket`, meaning only the second part of the header must be decrypted by us.
    //
    // TODO: ensure packet has enough bytes
    fn on_packet(&mut self, mut pkt: Vec<u8>) -> Option<PendingSsu2SessionStatus> {
        match mem::replace(&mut self.state, PendingSsu2SessionState::Poisoned) {
            PendingSsu2SessionState::AwaitingSessionConfirmed {
                chaining_key,
                ephemeral_key,
                k_header_2,
                k_session_created,
                state,
                src_id,
            } => {
                let iv2 = TryInto::<[u8; 12]>::try_into(&pkt[pkt.len() - 12..pkt.len()])
                    .expect("to succeed");

                ChaCha::with_iv(k_header_2, iv2)
                    .decrypt([0u8; 8])
                    .into_iter()
                    .zip(&mut pkt[8..])
                    .for_each(|(a, b)| {
                        *b ^= a;
                    });

                match MessageType::try_from(pkt[12]) {
                    Ok(MessageType::SessionConfirmed) => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            "received session created message",
                        );

                        // TODO: validate header
                        // TODO: check if the router info is fragmented
                        // TODO: ensure packet number is 0

                        let state = Sha256::new().update(&state).update(&pkt[..16]).finalize();
                        let new_state =
                            Sha256::new().update(&state).update(&pkt[16..64]).finalize();

                        let mut static_key = pkt[16..64].to_vec();
                        ChaChaPoly::with_nonce(&k_session_created, 1u64)
                            .decrypt_with_ad(&state, &mut static_key)
                            .unwrap();
                        let static_key = StaticPublicKey::from_bytes(&static_key).unwrap();
                        let shared = ephemeral_key.diffie_hellman(&static_key);

                        let mut temp_key = Hmac::new(&chaining_key).update(&shared).finalize();
                        let chaining_key = Hmac::new(&temp_key).update([0x01]).finalize();
                        let mut cipher_key =
                            Hmac::new(&temp_key).update(&chaining_key).update([0x02]).finalize();

                        let mut payload = pkt[64..].to_vec();
                        ChaChaPoly::with_nonce(&cipher_key, 0u64)
                            .decrypt_with_ad(&new_state, &mut payload)
                            .unwrap();

                        let Some(blocks) = Block::parse(&payload) else {
                            tracing::warn!(
                                target: LOG_TARGET,
                                "failed to parse message blocks of `SessionConfirmed`",
                            );
                            debug_assert!(false);
                            return None;
                        };

                        let Some(Block::RouterInfo { router_info }) = blocks
                            .iter()
                            .find(|block| core::matches!(block, Block::RouterInfo { .. }))
                        else {
                            tracing::warn!(
                                target: LOG_TARGET,
                                "`SessionConfirmed` doesn't include router info block",
                            );
                            debug_assert!(false);
                            return None;
                        };
                        let intro_key = router_info
                            .addresses
                            .get(&TransportKind::Ssu2)
                            .unwrap()
                            .options
                            .get(&Str::from("i"))
                            .unwrap();
                        let intro_key = base64_decode(intro_key.as_bytes()).unwrap();
                        let intro_key = TryInto::<[u8; 32]>::try_into(intro_key).unwrap();

                        let temp_key = Hmac::new(&chaining_key).update([]).finalize();
                        let k_ab = Hmac::new(&temp_key).update([0x01]).finalize();
                        let k_ba = Hmac::new(&temp_key).update(&k_ab).update([0x02]).finalize();

                        let mut temp_key = Hmac::new(&k_ab).update([]).finalize();
                        let k_data_ab = TryInto::<[u8; 32]>::try_into(
                            Hmac::new(&temp_key)
                                .update(b"HKDFSSU2DataKeys")
                                .update([0x01])
                                .finalize(),
                        )
                        .unwrap();
                        let k_header_2_ab = TryInto::<[u8; 32]>::try_into(
                            Hmac::new(&temp_key)
                                .update(&k_data_ab)
                                .update(b"HKDFSSU2DataKeys")
                                .update([0x02])
                                .finalize(),
                        )
                        .unwrap();

                        let mut temp_key = Hmac::new(&k_ba).update([]).finalize();
                        let k_data_ba = TryInto::<[u8; 32]>::try_into(
                            Hmac::new(&temp_key)
                                .update(b"HKDFSSU2DataKeys")
                                .update([0x01])
                                .finalize(),
                        )
                        .unwrap();
                        let k_header_2_ba = TryInto::<[u8; 32]>::try_into(
                            Hmac::new(&temp_key)
                                .update(&k_data_ba)
                                .update(b"HKDFSSU2DataKeys")
                                .update([0x02])
                                .finalize(),
                        )
                        .unwrap();

                        let mut state = AeadState {
                            cipher_key: k_data_ba.to_vec(),
                            nonce: 0u64,
                            state: Vec::new(),
                        };

                        let pkt = MessageBuilder::new_with_min_padding(
                            HeaderBuilder::short()
                                .with_pkt_num(0u32)
                                .with_short_header_flag(ShortHeaderFlag::Data {
                                    immediate_ack: false,
                                })
                                .with_dst_id(src_id)
                                .build::<R>(),
                            NonZeroUsize::new(8usize).expect("non-zero value"),
                        )
                        .with_keypair(intro_key, k_header_2_ba)
                        .with_aead_state(&mut state)
                        .with_block(Block::Ack {
                            ack_through: 0,
                            num_acks: 0,
                            ranges: Vec::new(),
                        })
                        .build::<R>();

                        let mut test = pkt.to_vec();
                        let mut mask = [0u8; 8];
                        let iv1 = TryInto::<[u8; 12]>::try_into(
                            pkt[pkt.len() - 24..pkt.len() - 12].to_vec(),
                        )
                        .unwrap();
                        ChaCha::with_iv(intro_key, iv1).decrypt_ref(&mut mask);
                        let connection_id = u64::from_be(mask.into_iter().zip(&mut test).fold(
                            0u64,
                            |connection_id, (a, b)| {
                                *b ^= a;

                                (connection_id << 8) | (*b as u64)
                            },
                        ));

                        return Some(PendingSsu2SessionStatus::NewInboundSession {
                            context: Ssu2SessionContext {
                                address: self.address,
                                dst_id: src_id,
                                intro_key,
                                recv_key_ctx: KeyContext::new(k_data_ab, k_header_2_ab),
                                send_key_ctx: KeyContext::new(k_data_ba, k_header_2_ba),
                                router_id: router_info.identity.id(),
                                pkt_rx: self.rx.take().expect("to exist"),
                            },
                            pkt,
                            target: self.address,
                        });
                    }
                    Ok(message_type) => tracing::warn!(
                        target: LOG_TARGET,
                        ?message_type,
                        "received an unexpected message",
                    ),
                    Err(()) => tracing::warn!(
                        target: LOG_TARGET,
                        message_type = ?pkt[12],
                        "received an unknown message",
                    ),
                }
            }
            PendingSsu2SessionState::SendTokenRequest {
                chaining_key,
                pkt_tx,
                src_id,
                state,
                static_key,
                router_info,
                router_id,
                local_static_key,
            } => {
                let iv = TryInto::<[u8; 12]>::try_into(&pkt[pkt.len() - 12..pkt.len()])
                    .expect("to succeed");
                ChaCha::with_iv(self.intro_key, iv)
                    .decrypt([0u8; 8])
                    .into_iter()
                    .zip(&mut pkt[8..])
                    .for_each(|(a, b)| {
                        *b ^= a;
                    });

                // encrypt last 16 bytes of the header
                ChaCha::with_iv(self.intro_key, [0u8; 12usize]).encrypt_ref(&mut pkt[16..32]);
                let token: [u8; 8] = TryInto::try_into(pkt[24..32].to_vec()).unwrap();
                let token = u64::from_le_bytes(token);
                let pkt_num = u32::from_le_bytes(
                    TryInto::<[u8; 4]>::try_into(&pkt[8..12]).expect("to succeed"),
                );

                let mut payload = pkt[32..].to_vec();
                ChaChaPoly::with_nonce(&self.intro_key, pkt_num.to_be() as u64)
                    .decrypt_with_ad(&pkt[..32], &mut payload)
                    .unwrap();

                let mut noise_ctx = NoiseContext {
                    local_static_key,
                    chaining_key: chaining_key.clone(),
                    static_key: StaticPublicKey::from(static_key),
                    state: state.clone(),
                    eph: EphemeralPrivateKey::random(R::rng()),
                    cipher_key: Vec::new(),
                    remote_eph: None,
                };

                let pkt = SessionRequestBuilder::default()
                    .with_dst_id(self.dst_id)
                    .with_src_id(src_id)
                    .with_intro_key(self.intro_key)
                    .with_token(token)
                    .with_noise_ctx(&mut noise_ctx)
                    .build::<R>()
                    .to_vec();

                // TODO: retransmissions
                if let Err(error) = pkt_tx.try_send(Packet {
                    pkt,
                    address: self.address,
                }) {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?error,
                        address = ?self.address,
                        "failed to send `SessionRequest`",
                    );
                }

                self.state = PendingSsu2SessionState::AwaitingSessionCreated {
                    noise_ctx,
                    router_info,
                    intro_key: self.intro_key,
                    router_id,
                    pkt_tx,
                    src_id,
                }
            }
            PendingSsu2SessionState::AwaitingSessionCreated {
                mut noise_ctx,
                pkt_tx,
                src_id,
                router_info,
                router_id,
                intro_key,
            } => {
                let iv = TryInto::<[u8; 12]>::try_into(&pkt[pkt.len() - 12..pkt.len()])
                    .expect("to succeed");
                let temp_key = Hmac::new(&noise_ctx.chaining_key).update([]).finalize();
                let k_header_2 =
                    Hmac::new(&temp_key).update(b"SessCreateHeader").update([0x01]).finalize();
                let k_header_2: [u8; 32] = TryInto::try_into(k_header_2).unwrap();

                ChaCha::with_iv(k_header_2, iv)
                    .decrypt([0u8; 8])
                    .into_iter()
                    .zip(&mut pkt[8..])
                    .for_each(|(a, b)| {
                        *b ^= a;
                    });

                // decrypt last 16 bytes of the header + ephemeral public key
                ChaCha::with_iv(k_header_2, [0u8; 12usize]).encrypt_ref(&mut pkt[16..64]);

                // TODO: validate header

                noise_ctx.mix_hash(&pkt[..32]).mix_hash(&pkt[32..64]);
                let eph = EphemeralPublicKey::from_bytes(&pkt[32..64]).unwrap();

                let shared = noise_ctx.eph.diffie_hellman(&eph);
                let mut temp_key = Hmac::new(&noise_ctx.chaining_key).update(&shared).finalize();
                let chaining_key = Hmac::new(&temp_key).update([0x01]).finalize();
                let mut cipher_key =
                    Hmac::new(&temp_key).update(&chaining_key).update([0x02]).finalize();

                let state = noise_ctx.state.clone();
                noise_ctx.mix_hash(&pkt[64..]);
                noise_ctx.remote_eph = Some(eph);
                noise_ctx.cipher_key = cipher_key.clone();
                noise_ctx.chaining_key = chaining_key.clone().into();

                let mut payload = pkt[64..].to_vec();
                ChaChaPoly::with_nonce(&cipher_key, 0u64)
                    .decrypt_with_ad(&state, &mut payload)
                    .expect("to succeed");

                // TODO: validate datetime
                // TODO: get our address
                // TODO: get token

                let temp_key = Hmac::new(&chaining_key).update([]).finalize();
                let k_header_2 =
                    Hmac::new(&temp_key).update(b"SessionConfirmed").update([0x01]).finalize();
                let k_header_2 = TryInto::<[u8; 32]>::try_into(k_header_2).unwrap();

                let pkt = SessionConfirmedBuilder::default()
                    .with_dst_id(self.dst_id)
                    .with_src_id(src_id)
                    .with_intro_key(self.intro_key)
                    .with_noise_ctx(&mut noise_ctx)
                    .with_k_header_2(k_header_2)
                    .with_router_info(router_info)
                    .build::<R>()
                    .to_vec();

                // TODO: retransmissions
                if let Err(error) = pkt_tx.try_send(Packet {
                    pkt,
                    address: self.address,
                }) {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?error,
                        address = ?self.address,
                        "failed to send `SessionConfirmed`",
                    );
                }

                self.state = PendingSsu2SessionState::AwaitingFirstAck {
                    noise_ctx,
                    router_id,
                    intro_key,
                };
            }
            PendingSsu2SessionState::AwaitingFirstAck {
                noise_ctx,
                intro_key,
                router_id,
            } => {
                let temp_key = Hmac::new(&noise_ctx.chaining_key).update([]).finalize();
                let k_ab = Hmac::new(&temp_key).update([0x01]).finalize();
                let k_ba = Hmac::new(&temp_key).update(&k_ab).update([0x02]).finalize();

                let mut temp_key = Hmac::new(&k_ab).update([]).finalize();
                let k_data_ab = TryInto::<[u8; 32]>::try_into(
                    Hmac::new(&temp_key).update(b"HKDFSSU2DataKeys").update([0x01]).finalize(),
                )
                .unwrap();
                let k_header_2_ab = TryInto::<[u8; 32]>::try_into(
                    Hmac::new(&temp_key)
                        .update(&k_data_ab)
                        .update(b"HKDFSSU2DataKeys")
                        .update([0x02])
                        .finalize(),
                )
                .unwrap();

                let mut temp_key = Hmac::new(&k_ba).update([]).finalize();
                let k_data_ba = TryInto::<[u8; 32]>::try_into(
                    Hmac::new(&temp_key).update(b"HKDFSSU2DataKeys").update([0x01]).finalize(),
                )
                .unwrap();
                let k_header_2_ba = TryInto::<[u8; 32]>::try_into(
                    Hmac::new(&temp_key)
                        .update(&k_data_ba)
                        .update(b"HKDFSSU2DataKeys")
                        .update([0x02])
                        .finalize(),
                )
                .unwrap();

                let iv = TryInto::<[u8; 12]>::try_into(&pkt[pkt.len() - 12..pkt.len()])
                    .expect("to succeed");

                ChaCha::with_iv(k_header_2_ba, iv)
                    .decrypt([0u8; 8])
                    .into_iter()
                    .zip(&mut pkt[8..])
                    .for_each(|(a, b)| {
                        *b ^= a;
                    });

                let pkt_num: [u8; 4] = TryInto::try_into(pkt[8..12].to_vec()).unwrap();
                let pkt_num = u32::from_be_bytes(pkt_num);

                return Some(PendingSsu2SessionStatus::NewOutboundSession {
                    context: Ssu2SessionContext {
                        address: self.address,
                        dst_id: self.dst_id,
                        intro_key,
                        recv_key_ctx: KeyContext::new(k_data_ba, k_header_2_ba),
                        send_key_ctx: KeyContext::new(k_data_ab, k_header_2_ab),
                        router_id,
                        pkt_rx: self.rx.take().expect("to exist"),
                    },
                });
            }
            // TODO: handle correctly
            PendingSsu2SessionState::Poisoned => unreachable!(),
        }

        None
    }
}

impl<R: Runtime> Future for PendingSsu2Session<R> {
    type Output = PendingSsu2SessionStatus;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            let pkt = match &mut self.rx {
                None => return Poll::Ready(PendingSsu2SessionStatus::SocketClosed),
                Some(rx) => match rx.poll_recv(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(None) =>
                        return Poll::Ready(PendingSsu2SessionStatus::SocketClosed),
                    Poll::Ready(Some(Packet { pkt, .. })) => pkt,
                },
            };

            if let Some(status) = self.on_packet(pkt) {
                return Poll::Ready(status);
            }
        }
    }
}
