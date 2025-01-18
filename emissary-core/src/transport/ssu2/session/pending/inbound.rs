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
    primitives::{Str, TransportKind},
    runtime::Runtime,
    transport::ssu2::{
        message::{AeadState, Block, HeaderBuilder, MessageBuilder, MessageType, ShortHeaderFlag},
        session::{
            active::{KeyContext, Ssu2SessionContext},
            pending::PendingSsu2SessionStatus,
        },
        Packet,
    },
};

use bytes::Bytes;
use rand_core::RngCore;
use thingbuf::mpsc::{Receiver, Sender};
use zeroize::Zeroize;

use core::{
    future::Future,
    marker::PhantomData,
    mem,
    net::SocketAddr,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::session::inbound";

/// Inbound SSU2 session context.
pub struct InboundSsu2Context {
    /// Socket address of the remote router.
    pub address: SocketAddr,

    /// Chaining key.
    pub chaining_key: Bytes,

    /// Destination connection ID.
    pub dst_id: u64,

    /// Local intro key.
    pub intro_key: [u8; 32],

    /// `TokenRequest` packet.
    pub pkt: Vec<u8>,

    /// TX channel for sending packets to [`Ssu2Socket`].
    //
    // TODO: make `R::UdpSocket` clonable
    pub pkt_tx: Sender<Packet>,

    /// RX channel for receiving datagrams from `Ssu2Socket`.
    pub rx: Receiver<Packet>,

    /// AEAD state.
    pub state: Bytes,

    /// Local static key.
    pub static_key: StaticPrivateKey,
}

/// Pending session state.
enum PendingSessionState {
    /// Awaiting `SessionRequest` message from remote router.
    AwaitingSessionRequest,

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

        /// AEAD state from `SessionCreated` message.
        state: Vec<u8>,
    },

    /// State has been poisoned.
    Poisoned,
}

/// Pending inbound SSU2 session.
pub struct InboundSsu2Session<R: Runtime> {
    /// Socket address of the remote router.
    address: SocketAddr,

    /// AEAD state.
    aead: Bytes,

    /// Chaining key.
    chaining_key: Bytes,

    /// Destination connection ID.
    dst_id: u64,

    /// Intro key.
    intro_key: [u8; 32],

    /// TX channel for sending packets to [`Ssu2Socket`].
    //
    // TODO: make `R::UdpSocket` clonable
    pkt_tx: Sender<Packet>,

    /// RX channel for receiving datagrams from `Ssu2Socket`.
    rx: Option<Receiver<Packet>>,

    /// Source connection ID.
    src_id: u64,

    /// Pending session state.
    state: PendingSessionState,

    /// Static key.
    static_key: StaticPrivateKey,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> InboundSsu2Session<R> {
    /// Create new [`PendingSsu2Session`].
    //
    // TODO: explain what happens here
    pub fn new(context: InboundSsu2Context) -> Self {
        let InboundSsu2Context {
            address,
            chaining_key,
            dst_id,
            pkt_tx,
            intro_key,
            static_key,
            mut pkt,
            rx,
            state,
        } = context;

        ChaCha::with_iv(intro_key, [0u8; 12]).decrypt_ref(&mut pkt[16..32]);

        let pkt_num =
            u32::from_le_bytes(TryInto::<[u8; 4]>::try_into(&pkt[8..12]).expect("to succeed"));
        let src_id =
            u64::from_le_bytes(TryInto::<[u8; 8]>::try_into(&pkt[16..24]).expect("to succeed"));

        let mut payload = pkt[32..pkt.len()].to_vec();
        ChaChaPoly::with_nonce(&intro_key, pkt_num.to_be() as u64)
            .decrypt_with_ad(&pkt[..32], &mut payload)
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
                .with_src_id(dst_id)
                .with_dst_id(src_id)
                .with_token(token)
                .with_message_type(MessageType::Retry)
                .build::<R>(),
        )
        .with_key(intro_key)
        .with_block(Block::DateTime {
            timestamp: R::time_since_epoch().as_secs() as u32,
        })
        .with_block(Block::Address { address })
        .build::<R>()
        .to_vec();

        // TODO: retries
        if let Err(error) = pkt_tx.try_send(Packet { pkt, address }) {
            tracing::warn!(
                target: LOG_TARGET,
                ?dst_id,
                ?src_id,
                ?address,
                ?error,
                "failed to send `Retry`",
            );
        }

        Self {
            address,
            aead: state,
            chaining_key,
            dst_id,
            intro_key,
            pkt_tx,
            rx: Some(rx),
            src_id,
            state: PendingSessionState::AwaitingSessionRequest,
            static_key,
            _runtime: Default::default(),
        }
    }

    /// Handle `SessionRequest` message.
    fn on_session_request(&mut self, mut pkt: Vec<u8>) -> Option<PendingSsu2SessionStatus> {
        let iv2 =
            TryInto::<[u8; 12]>::try_into(&pkt[pkt.len() - 12..pkt.len()]).expect("to succeed");
        ChaCha::with_iv(self.intro_key, iv2)
            .decrypt([0u8; 8])
            .into_iter()
            .zip(&mut pkt[8..])
            .for_each(|(a, b)| {
                *b ^= a;
            });

        let pkt_num =
            u32::from_le_bytes(TryInto::<[u8; 4]>::try_into(&pkt[8..12]).expect("to succeed"));

        tracing::info!(
            target: LOG_TARGET,
            ?pkt_num,
            version = ?pkt[13],
            net_id = ?pkt[14],
            "handle session request",
        );

        ChaCha::with_iv(self.intro_key, [0u8; 12]).decrypt_ref(&mut pkt[16..64]);

        // TODO: extract token and verify it's valid

        let state = Sha256::new().update(&self.aead).update(&pkt[..32]).finalize();
        let state = Sha256::new().update(state).update(&pkt[32..64]).finalize();

        let public_key = EphemeralPublicKey::from_bytes(&pkt[32..64]).expect("to succeed");
        let mut shared = self.static_key.diffie_hellman(&public_key);

        let mut temp_key = Hmac::new(&self.chaining_key).update(&shared).finalize();
        let chaining_key = Hmac::new(&temp_key).update([0x01]).finalize();
        let mut cipher_key = Hmac::new(&temp_key).update(&chaining_key).update([0x02]).finalize();

        shared.zeroize();
        temp_key.zeroize();

        // TODO: derive sessioncreated header keyfrom `cipher_key` (??)
        // HKDF(chainKey, ZEROLEN, "SessCreateHeader", 32)
        let temp_key = Hmac::new(&chaining_key).update([]).finalize();
        let k_header_2 = Hmac::new(&temp_key).update(b"SessCreateHeader").update([0x01]).finalize();
        let k_header_2 = TryInto::<[u8; 32]>::try_into(k_header_2).unwrap();

        // state for `SessionCreated`
        let new_state = Sha256::new().update(&state).update(&pkt[64..pkt.len()]).finalize();

        let mut payload = pkt[64..pkt.len()].to_vec();
        ChaChaPoly::with_nonce(&cipher_key, 0u64)
            .decrypt_with_ad(&state, &mut payload)
            .unwrap();

        cipher_key.zeroize();

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

        let mut shared = sk.diffie_hellman(&public_key);

        let mut temp_key = Hmac::new(&chaining_key).update(&shared).finalize();
        let chaining_key = Hmac::new(&temp_key).update([0x01]).finalize();
        let cipher_key = Hmac::new(&temp_key).update(&chaining_key).update([0x02]).finalize();

        temp_key.zeroize();
        shared.zeroize();

        let mut aead_state = AeadState {
            cipher_key: cipher_key.clone(),
            nonce: 0u64,
            state: new_state,
        };

        // TODO: probably unnecessary memory copies here and below
        let pkt = MessageBuilder::new(
            HeaderBuilder::long()
                .with_src_id(self.dst_id)
                .with_dst_id(self.src_id)
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
        .with_block(Block::Address {
            address: self.address,
        })
        .build::<R>()
        .to_vec();

        // TODO: retries
        if let Err(error) = self.pkt_tx.try_send(Packet {
            pkt,
            address: self.address,
        }) {
            tracing::warn!(
                target: LOG_TARGET,
                dst_id = ?self.dst_id,
                src_id = ?self.src_id,
                address = ?self.address,
                ?error,
                "failed to send `SessionCreated`",
            );
        }

        // create new session
        let temp_key = Hmac::new(&chaining_key).update([]).finalize();
        let k_header_2 = Hmac::new(&temp_key).update(b"SessionConfirmed").update([0x01]).finalize();
        let k_header_2 = TryInto::<[u8; 32]>::try_into(k_header_2).unwrap();
        let k_session_created = TryInto::<[u8; 32]>::try_into(cipher_key).unwrap();

        self.state = PendingSessionState::AwaitingSessionConfirmed {
            chaining_key,
            ephemeral_key: sk,
            k_header_2,
            k_session_created,
            state: aead_state.state,
        };

        None
    }

    /// Handle received packet to a pending session.
    ///
    /// `pkt` contains the full header but the first part of the header has been decrypted by the
    /// `Ssu2Socket`, meaning only the second part of the header must be decrypted by us.
    //
    // TODO: ensure packet has enough bytes
    fn on_packet(&mut self, mut pkt: Vec<u8>) -> Option<PendingSsu2SessionStatus> {
        match mem::replace(&mut self.state, PendingSessionState::Poisoned) {
            PendingSessionState::AwaitingSessionRequest {} => {
                let _ = self.on_session_request(pkt);
            }
            PendingSessionState::AwaitingSessionConfirmed {
                chaining_key,
                ephemeral_key,
                k_header_2,
                k_session_created,
                state,
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
                        let mut shared = ephemeral_key.diffie_hellman(&static_key);

                        let mut temp_key = Hmac::new(&chaining_key).update(&shared).finalize();
                        let chaining_key = Hmac::new(&temp_key).update([0x01]).finalize();
                        let mut cipher_key =
                            Hmac::new(&temp_key).update(&chaining_key).update([0x02]).finalize();

                        let mut payload = pkt[64..].to_vec();
                        ChaChaPoly::with_nonce(&cipher_key, 0u64)
                            .decrypt_with_ad(&new_state, &mut payload)
                            .unwrap();

                        shared.zeroize();
                        temp_key.zeroize();
                        cipher_key.zeroize();

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

                        let temp_key = Hmac::new(&k_ab).update([]).finalize();
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

                        let temp_key = Hmac::new(&k_ba).update([]).finalize();
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
                                .with_dst_id(self.src_id)
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
                        let _connection_id = u64::from_be(mask.into_iter().zip(&mut test).fold(
                            0u64,
                            |connection_id, (a, b)| {
                                *b ^= a;

                                (connection_id << 8) | (*b as u64)
                            },
                        ));

                        return Some(PendingSsu2SessionStatus::NewInboundSession {
                            context: Ssu2SessionContext {
                                address: self.address,
                                dst_id: self.src_id,
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
            PendingSessionState::Poisoned => unreachable!(),
        }

        None
    }
}

impl<R: Runtime> Future for InboundSsu2Session<R> {
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
