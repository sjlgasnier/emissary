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
        chachapoly::ChaChaPoly, hmac::Hmac, EphemeralPrivateKey, StaticPrivateKey, StaticPublicKey,
    },
    error::Ssu2Error,
    primitives::RouterId,
    runtime::Runtime,
    transport::ssu2::{
        message::{
            HeaderKind, HeaderReader, NoiseContext, SessionConfirmedBuilder, SessionRequestBuilder,
            TokenRequestBuilder,
        },
        session::{
            active::{KeyContext, Ssu2SessionContext},
            pending::PendingSsu2SessionStatus,
        },
        Packet,
    },
};

use bytes::Bytes;
use thingbuf::mpsc::{Receiver, Sender};
use zeroize::Zeroize;

use core::{
    future::Future,
    marker::PhantomData,
    mem,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::session::outbound";

/// Outbound SSU2 session context.
pub struct OutboundSsu2Context {
    /// Socket address of the remote router.
    pub address: SocketAddr,

    /// Chaining key.
    pub chaining_key: Bytes,

    /// Destination connection ID.
    pub dst_id: u64,

    /// Remote router's intro key.
    pub intro_key: [u8; 32],

    /// Local static key.
    pub local_static_key: StaticPrivateKey,

    /// TX channel for sending packets to [`Ssu2Socket`].
    pub pkt_tx: Sender<Packet>,

    /// ID of the remote router.
    pub router_id: RouterId,

    /// Serialized local router info.
    pub router_info: Vec<u8>,

    /// RX channel for receiving datagrams from `Ssu2Socket`.
    pub rx: Receiver<Packet>,

    /// Source connection ID.
    pub src_id: u64,

    /// AEAD state.
    pub state: Vec<u8>,

    /// Remote router's static key.
    pub static_key: [u8; 32],
}

/// State for a pending outbound SSU2 session.
enum PendingSessionState {
    /// Awaiting `Retry` from remote router.
    AwaitingRetry {
        /// Chaining key.
        chaining_key: Bytes,

        /// Local static key.
        local_static_key: StaticPrivateKey,

        /// Serialized local router info.
        router_info: Vec<u8>,

        /// AEAD state.
        state: Vec<u8>,

        /// Remote router's static key.
        static_key: [u8; 32],
    },

    /// Awaiting `SessionCreated` message from remote router.
    AwaitingSessionCreated {
        /// Noise context.
        noise_ctx: NoiseContext,

        /// Serialized local router info.
        router_info: Vec<u8>,
    },

    /// Awaiting first ACK to be received.
    AwaitingFirstAck {
        /// Noise context.
        noise_ctx: NoiseContext,
    },

    Poisoned,
}

/// Pending outbound SSU2 session.
pub struct OutboundSsu2Session<R: Runtime> {
    /// Socket address of the remote router.
    address: SocketAddr,

    /// Destination connection ID.
    dst_id: u64,

    /// Intro key.
    intro_key: [u8; 32],

    /// TX channel for sending packets to [`Ssu2Socket`].
    pkt_tx: Sender<Packet>,

    /// ID of the remote router.
    router_id: RouterId,

    /// RX channel for receiving datagrams from `Ssu2Socket`.
    rx: Option<Receiver<Packet>>,

    /// Source connection ID.
    src_id: u64,

    /// Pending session state.
    state: PendingSessionState,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> OutboundSsu2Session<R> {
    /// Create new [`OutboundSsu2Session`].
    pub fn new(context: OutboundSsu2Context) -> Self {
        let OutboundSsu2Context {
            address,
            chaining_key,
            router_id,
            dst_id,
            intro_key,
            pkt_tx,
            rx,
            src_id,
            state,
            static_key,
            local_static_key,
            router_info,
        } = context;

        tracing::trace!(
            target: LOG_TARGET,
            %router_id,
            ?dst_id,
            ?src_id,
            "send `TokenRequest`",
        );

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
            pkt_tx,
            router_id,
            rx: Some(rx),
            src_id,
            state: PendingSessionState::AwaitingRetry {
                chaining_key,
                local_static_key,
                state,
                static_key,
                router_info,
            },
            _runtime: Default::default(),
        }
    }

    /// Handle `Retry`.
    ///
    /// Attempt to parse the header into `Retry` and if it succeeds, send a `SessionRequest` to
    /// remote using the token that was received in the `Retry` message. The state of the outbound
    /// connection proceeds to `AwaitingSessionCreated` which is handled by
    /// [`OutboundSsu2Session::on_session_created()`].
    ///
    /// <https://geti2p.net/spec/ssu2#kdf-for-retry>
    /// <https://geti2p.net/spec/ssu2#retry-type-9>
    fn on_retry(
        &mut self,
        mut pkt: Vec<u8>,
        chaining_key: Bytes,
        local_static_key: StaticPrivateKey,
        router_info: Vec<u8>,
        state: Vec<u8>,
        static_key: [u8; 32],
    ) -> Result<Option<PendingSsu2SessionStatus>, Ssu2Error> {
        let (pkt_num, token) = match HeaderReader::new(self.intro_key, &mut pkt)?
            .parse(self.intro_key)
            .ok_or(Ssu2Error::InvalidVersion)? // TODO: could be too short mesasge
        {
            HeaderKind::Retry {
                net_id: _,
                pkt_num,
                token,
            } => {
                // TODO: verify net id

                (pkt_num, token)
            }
            kind => {
                tracing::debug!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    dst_id = ?self.dst_id,
                    src_id = ?self.src_id,
                    ?kind,
                    "invalid message, expected `Retry`",
                );
                return Err(Ssu2Error::UnexpectedMessage);
            }
        };

        tracing::trace!(
            target: LOG_TARGET,
            router_id = %self.router_id,
            dst_id = ?self.dst_id,
            src_id = ?self.src_id,
            "handle `Retry`",
        );

        let mut payload = pkt[32..].to_vec();
        ChaChaPoly::with_nonce(&self.intro_key, pkt_num as u64)
            .decrypt_with_ad(&pkt[..32], &mut payload)?;

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
            .with_src_id(self.src_id)
            .with_intro_key(self.intro_key)
            .with_token(token)
            .with_noise_ctx(&mut noise_ctx)
            .build::<R>()
            .to_vec();

        // TODO: retransmissions
        if let Err(error) = self.pkt_tx.try_send(Packet {
            pkt,
            address: self.address,
        }) {
            tracing::warn!(
                target: LOG_TARGET,
                ?error,
                router_id = %self.router_id,
                dst_id = ?self.dst_id,
                src_id = ?self.src_id,
                "failed to send `SessionRequest`",
            );
        }

        self.state = PendingSessionState::AwaitingSessionCreated {
            noise_ctx,
            router_info,
        };

        Ok(None)
    }

    /// Handle `SessionCreated`.
    ///
    /// Attempt to parse the header into `SessionCrated` and if it succeeds, send a
    /// `SessionConfirmed` to remote. The state of the outbound connection proceeds to
    /// `AwaitingFirstAck` which is handled by [`OutboundSsu2Session::on_data()`]. Once an ACK for
    /// the `SessionConfirmed` message has been received, data phase keys are derived and the
    /// session is considered established
    ///
    /// <https://geti2p.net/spec/ssu2#kdf-for-session-created-and-session-confirmed-part-1>
    /// <https://geti2p.net/spec/ssu2#sessioncreated-type-1>
    ///
    /// Conversion to `[u8; N]` in this function use `expect()` as they are guaranteed to succeed.
    fn on_session_created(
        &mut self,
        mut pkt: Vec<u8>,
        router_info: Vec<u8>,
        mut noise_ctx: NoiseContext,
    ) -> Result<Option<PendingSsu2SessionStatus>, Ssu2Error> {
        let temp_key = Hmac::new(&noise_ctx.chaining_key).update([]).finalize();
        let k_header_2 = Hmac::new(&temp_key).update(b"SessCreateHeader").update([0x01]).finalize();
        let k_header_2: [u8; 32] = TryInto::try_into(k_header_2).expect("to succeed");

        let ephemeral_key = match HeaderReader::new(self.intro_key, &mut pkt)?
            .parse(k_header_2)
            .ok_or(Ssu2Error::InvalidVersion)? // TODO: could be other error
        {
            HeaderKind::SessionCreated {
                ephemeral_key,
                net_id: _,
                ..
            } => {
                // TODO: verify net id

                ephemeral_key
            }
            kind => {
                tracing::debug!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    dst_id = ?self.dst_id,
                    src_id = ?self.src_id,
                    ?kind,
                    "invalid message, expected `Retry`",
                );
                return Err(Ssu2Error::UnexpectedMessage);
            }
        };

        tracing::trace!(
            target: LOG_TARGET,
            router_id = %self.router_id,
            dst_id = ?self.dst_id,
            src_id = ?self.src_id,
            "handle `SessionCreated`",
        );

        noise_ctx.mix_hash(&pkt[..32]).mix_hash(&pkt[32..64]);

        let mut shared = noise_ctx.eph.diffie_hellman(&ephemeral_key);
        let mut temp_key = Hmac::new(&noise_ctx.chaining_key).update(&shared).finalize();
        let chaining_key = Hmac::new(&temp_key).update([0x01]).finalize();
        let cipher_key = Hmac::new(&temp_key).update(&chaining_key).update([0x02]).finalize();

        let state = noise_ctx.state.clone();
        noise_ctx.mix_hash(&pkt[64..]);
        noise_ctx.remote_eph = Some(ephemeral_key);
        noise_ctx.cipher_key = cipher_key.clone();
        noise_ctx.chaining_key = chaining_key.clone().into();

        let mut payload = pkt[64..].to_vec();
        ChaChaPoly::with_nonce(&cipher_key, 0u64).decrypt_with_ad(&state, &mut payload)?;

        shared.zeroize();
        temp_key.zeroize();

        // TODO: validate datetime
        // TODO: get our address

        let temp_key = Hmac::new(&chaining_key).update([]).finalize();
        let k_header_2 = Hmac::new(&temp_key).update(b"SessionConfirmed").update([0x01]).finalize();
        let k_header_2 = TryInto::<[u8; 32]>::try_into(k_header_2).expect("to succeed");

        let pkt = SessionConfirmedBuilder::default()
            .with_dst_id(self.dst_id)
            .with_src_id(self.src_id)
            .with_intro_key(self.intro_key)
            .with_noise_ctx(&mut noise_ctx)
            .with_k_header_2(k_header_2)
            .with_router_info(router_info)
            .build::<R>()
            .to_vec();

        // TODO: retransmissions
        if let Err(error) = self.pkt_tx.try_send(Packet {
            pkt,
            address: self.address,
        }) {
            tracing::warn!(
                target: LOG_TARGET,
                router_id = %self.router_id,
                dst_id = ?self.dst_id,
                src_id = ?self.src_id,
                ?error,
                "failed to send `SessionConfirmed`",
            );
        }

        self.state = PendingSessionState::AwaitingFirstAck { noise_ctx };
        Ok(None)
    }

    /// Handle `Data`, in other words an ACK for the `SessionConfirmed` message.
    ///
    /// Verify that a valid message was received, derive data phase keys and return session context
    /// for [`Ssu2Socket`] which starts an active session.
    ///
    /// <https://geti2p.net/spec/ssu2#kdf-for-session-confirmed-part-1-using-session-created-kdf>
    /// <https://geti2p.net/spec/ssu2#kdf-for-session-confirmed-part-2>
    /// <https://geti2p.net/spec/ssu2#sessionconfirmed-type-2>
    /// <https://geti2p.net/spec/ssu2#kdf-for-data-phase>
    ///
    /// Conversion to `[u8; N]` in this function use `expect()` as they are guaranteed to succeed.
    fn on_data(
        &mut self,
        _pkt: Vec<u8>,
        noise_ctx: NoiseContext,
    ) -> Result<Option<PendingSsu2SessionStatus>, Ssu2Error> {
        // TODO: implement data packet parse
        // TODO: verify ack was received

        tracing::trace!(
            target: LOG_TARGET,
            router_id = %self.router_id,
            dst_id = ?self.dst_id,
            src_id = ?self.src_id,
            "handle `Data` (first ack)",
        );

        let temp_key = Hmac::new(&noise_ctx.chaining_key).update([]).finalize();
        let k_ab = Hmac::new(&temp_key).update([0x01]).finalize();
        let k_ba = Hmac::new(&temp_key).update(&k_ab).update([0x02]).finalize();

        let temp_key = Hmac::new(&k_ab).update([]).finalize();
        let k_data_ab = TryInto::<[u8; 32]>::try_into(
            Hmac::new(&temp_key).update(b"HKDFSSU2DataKeys").update([0x01]).finalize(),
        )
        .expect("to succeed");
        let k_header_2_ab = TryInto::<[u8; 32]>::try_into(
            Hmac::new(&temp_key)
                .update(&k_data_ab)
                .update(b"HKDFSSU2DataKeys")
                .update([0x02])
                .finalize(),
        )
        .expect("to succeed");

        let temp_key = Hmac::new(&k_ba).update([]).finalize();
        let k_data_ba = TryInto::<[u8; 32]>::try_into(
            Hmac::new(&temp_key).update(b"HKDFSSU2DataKeys").update([0x01]).finalize(),
        )
        .expect("to succeed");
        let k_header_2_ba = TryInto::<[u8; 32]>::try_into(
            Hmac::new(&temp_key)
                .update(&k_data_ba)
                .update(b"HKDFSSU2DataKeys")
                .update([0x02])
                .finalize(),
        )
        .expect("to succeed");

        Ok(Some(PendingSsu2SessionStatus::NewOutboundSession {
            context: Ssu2SessionContext {
                address: self.address,
                dst_id: self.dst_id,
                intro_key: self.intro_key,
                recv_key_ctx: KeyContext::new(k_data_ba, k_header_2_ba),
                send_key_ctx: KeyContext::new(k_data_ab, k_header_2_ab),
                router_id: self.router_id.clone(),
                pkt_rx: self.rx.take().expect("to exist"),
            },
        }))
    }

    /// Handle `pkt`.
    ///
    /// If the packet is the next in expected sequnce, the outbound session advances to the next
    /// state and if an ACK for `SessionConfirmed` has been received,
    /// [`PendingSsu2SessionStatus::NewOutboundSession`] is returned to the caller, shutting down
    /// this future and allowing [`Ssu2Socket`] to start a new future for the active session.
    ///
    /// If a fatal error occurs during handling of the packet,
    /// [`PendingSsu2SessionStatus::SessionTerminated`] is returned.
    fn on_packet(&mut self, pkt: Vec<u8>) -> Result<Option<PendingSsu2SessionStatus>, Ssu2Error> {
        match mem::replace(&mut self.state, PendingSessionState::Poisoned) {
            PendingSessionState::AwaitingRetry {
                chaining_key,
                state,
                static_key,
                router_info,
                local_static_key,
            } => self.on_retry(
                pkt,
                chaining_key,
                local_static_key,
                router_info,
                state,
                static_key,
            ),
            PendingSessionState::AwaitingSessionCreated {
                noise_ctx,
                router_info,
            } => self.on_session_created(pkt, router_info, noise_ctx),
            PendingSessionState::AwaitingFirstAck { noise_ctx } => self.on_data(pkt, noise_ctx),
            PendingSessionState::Poisoned => {
                tracing::warn!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    dst_id = ?self.dst_id,
                    src_id = ?self.src_id,
                    "outbound session state is poisoned",
                );
                debug_assert!(false);
                return Ok(Some(PendingSsu2SessionStatus::SessionTermianted {}));
            }
        }
    }
}

impl<R: Runtime> Future for OutboundSsu2Session<R> {
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

            match self.on_packet(pkt) {
                Ok(None) => {}
                Ok(Some(status)) => return Poll::Ready(status),
                Err(error) => tracing::debug!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    dst_id = ?self.dst_id,
                    src_id = ?self.src_id,
                    ?error,
                    "failed to handle packet",
                ),
            }
        }
    }
}
