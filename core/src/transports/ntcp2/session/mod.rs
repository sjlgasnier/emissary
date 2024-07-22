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

//! NTCP2 Noise handshake implementation.
//!
//! https://geti2p.net/spec/ntcp2#overview
//!
//! Implementation refers to `ck` as `chaining_key` and to `h` as `state`.
//1 This implementation also refers to Alice as initiator and to Bob as responder.
//!
//! [`SessionManager::create_session()`] and [`SessionManager::create_session()`]
//! return futures which negotiate connection for initiators and responders, respectively.
//!
//! These two functions do not themselves implement code from the specification in order
//! to prevent mixing that code with I/O code. Handshake implementations for initiator
//! and responder can be found from `initiator.rs` and `responder.rs`.

use crate::{
    crypto::{
        base64_decode, sha256::Sha256, siphash::SipHash, SigningPrivateKey, StaticPrivateKey,
        StaticPublicKey,
    },
    primitives::{RouterInfo, Str, TransportKind},
    runtime::{AsyncRead, AsyncWrite, Runtime, TcpStream},
    transports::{
        ntcp2::session::{initiator::Initiator, responder::Responder},
        SubsystemHandle,
    },
    util::{AsyncReadExt, AsyncWriteExt},
    Error,
};

use zerocopy::{AsBytes, FromBytes, FromZeroes};

use alloc::{vec, vec::Vec};
use core::{future::Future, net::SocketAddr, str::FromStr};

mod active;
mod initiator;
mod responder;

pub use active::Ntcp2Session;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ntcp2::session";

/// Noise protocol name;.
const PROTOCOL_NAME: &str = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256";

/// Role of the session.
#[derive(Debug, Clone, Copy)]
pub enum Role {
    /// Initiator (Alice).
    Initiator,

    /// Responder (Bob).
    Responder,
}

/// Key context.
pub(super) struct KeyContext {
    /// Key used to encrypt outbound messages.
    pub send_key: Vec<u8>,

    /// Key used to decrypt inbound messages.
    pub recv_key: Vec<u8>,

    /// SipHash context for (de)obfuscating message lengths.
    pub sip: SipHash,
}

impl KeyContext {
    /// Create new [`KeyContext`].
    pub fn new(send_key: Vec<u8>, recv_key: Vec<u8>, sip: SipHash) -> Self {
        Self {
            send_key,
            recv_key,
            sip,
        }
    }
}

/// Initiator options.
#[derive(Debug, AsBytes, FromBytes, FromZeroes)]
#[repr(packed)]
pub(super) struct InitiatorOptions {
    id: u8,
    version: u8,
    padding_length: [u8; 2],
    m3_p2_len: [u8; 2],
    reserved1: [u8; 2],
    timestamp: [u8; 4],
    reserved2: [u8; 4],
}

/// Responder options.
#[derive(Debug, AsBytes, FromBytes, FromZeroes)]
#[repr(packed)]
pub(super) struct ResponderOptions {
    reserved1: [u8; 2],
    padding_length: [u8; 2],
    reserved2: [u8; 4],
    timestamp: [u8; 4],
    reserved3: [u8; 4],
}

/// Session manager.
///
/// Responsible for creating context for inbound and outboudn NTCP2 sessions.
pub struct SessionManager<R: Runtime> {
    /// Runtime.
    runtime: R,

    /// State that is common for all outbound connections.
    outbound_initial_state: Vec<u8>,

    /// State that is common for all inbound connections.
    // TODO: `bytes::Bytes`?
    inbound_initial_state: Vec<u8>,

    /// Chaining key.
    // TODO: `bytes::Bytes`?
    chaining_key: Vec<u8>,

    /// Local NTCP2 static key.
    local_key: StaticPrivateKey,

    /// Local NTCP2 IV.
    local_iv: Vec<u8>,

    /// Local signing key.
    local_signing_key: SigningPrivateKey,

    /// Local router info.
    local_router_info: RouterInfo,

    /// Subsystem handle.
    subsystem_handle: SubsystemHandle,
}

impl<R: Runtime> SessionManager<R> {
    /// Create new [`SessionManager`].
    ///
    /// This function initializes the common state for both inbound and outbound connections.
    ///
    /// See the beginning of [1] for steps on generating start state.
    ///
    /// [1]: https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-handshake-message-1
    pub fn new(
        runtime: R,
        local_key: Vec<u8>,
        local_iv: Vec<u8>,
        local_signing_key: SigningPrivateKey,
        local_router_info: RouterInfo,
        subsystem_handle: SubsystemHandle,
    ) -> crate::Result<Self> {
        let local_key = StaticPrivateKey::from(local_key);

        // initial state
        let state = Sha256::new().update(&PROTOCOL_NAME.as_bytes().to_vec()).finalize();

        // chaining key
        let chaining_key = state.clone();

        // MixHash (null prologue)
        let outbound_initial_state = Sha256::new().update(&state).finalize();

        // MixHash(rs)
        let inbound_initial_state = Sha256::new()
            .update(&outbound_initial_state)
            .update(&local_key.public().to_vec())
            .finalize();

        Ok(Self {
            runtime,
            local_key,
            local_iv,
            local_signing_key,
            local_router_info,
            chaining_key,
            inbound_initial_state,
            outbound_initial_state,
            subsystem_handle,
        })
    }

    /// Create new [`Handshaker`] for initiator (Alice).
    ///
    /// Implements the key generation from [1], creates a `SessionRequest` message and returns
    /// that message together with an [`Initiator`] object which allows the call to drive progress
    /// on the opening connection.
    ///
    /// [1]: https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-handshake-message-1
    pub fn create_session(
        &self,
        router: RouterInfo,
    ) -> impl Future<Output = crate::Result<Ntcp2Session<R>>> {
        let local_info = self.local_router_info.serialize(&self.local_signing_key);
        let local_router_hash = self.local_router_info.identity().hash().to_vec();
        let local_key = self.local_key.clone();
        let outbound_initial_state = self.outbound_initial_state.clone();
        let chaining_key = self.chaining_key.clone();
        let runtime = self.runtime.clone();
        let subsystem_handle = self.subsystem_handle.clone();

        async move {
            let (remote_key, iv, socket_address) = {
                let ntcp2 =
                    router.addresses().get(&TransportKind::Ntcp2).ok_or(Error::NotSupported)?;

                let static_key = ntcp2
                    .options()
                    .get(&Str::from_str("s").expect("to succeed"))
                    .ok_or_else(|| {
                        tracing::warn!(target: LOG_TARGET, "static key missing from ntcp2 info");
                        Error::InvalidData
                    })?;

                let iv = ntcp2.options().get(&Str::from_str("i").expect("to succeed")).ok_or_else(
                    || {
                        tracing::warn!(target: LOG_TARGET, "iv missing from ntcp2 info");
                        Error::InvalidData
                    },
                )?;

                // `format!()` is not available in `no_std`
                // so socket address has to be constructed manually
                //
                // TODO: the `primitives` apis need a lot of work lol
                // TODO: maybe add common getters for `RouterAddress`
                let host = ntcp2
                    .options()
                    .get(&Str::from_str("host").expect("to succeed"))
                    .ok_or_else(|| {
                        tracing::warn!(target: LOG_TARGET, "host missing from ntcp2 info");
                        Error::InvalidData
                    })?;

                // let host = core::str::from_utf8(host.string())
                //     .unwrap()
                //     .parse::<core::net::IpAddr>()
                //     .unwrap();
                let host = "127.0.0.1".parse::<core::net::IpAddr>().unwrap();

                let port = ntcp2
                    .options()
                    .get(&Str::from_str("port").expect("to succeed"))
                    .ok_or_else(|| {
                        tracing::warn!(target: LOG_TARGET, "port missing from ntcp2 info");
                        Error::InvalidData
                    })?;

                let port = core::str::from_utf8(port.string()).unwrap().parse::<u16>().unwrap();

                (
                    StaticPublicKey::from_bytes(base64_decode(static_key.string())).unwrap(),
                    base64_decode(iv.string()),
                    core::net::SocketAddr::new(host, port),
                )
            };

            tracing::trace!(
                target: LOG_TARGET,
                ?socket_address,
                "start dialing remote peer",
            );

            let mut stream = R::TcpStream::connect(socket_address).await.unwrap();
            let router_hash = router.identity().hash().to_vec();

            // create `SessionRequest` message and send it remote peer
            let (mut initiator, message) = Initiator::new::<R>(
                outbound_initial_state,
                chaining_key,
                local_info,
                local_key,
                &remote_key,
                router_hash,
                iv,
            )?;
            stream.write_all(&message).await?;

            // read `SessionCreated` and decrypt & parse it to find padding length
            let mut reply = alloc::vec![0u8; 64];
            stream.read_exact(&mut reply).await?;

            let padding_len = initiator.register_session_confirmed(&reply)?;

            // read padding and finalize session by sending `SessionConfirmed`
            let mut reply = alloc::vec![0u8; padding_len];
            stream.read_exact(&mut reply).await?;

            let (mut key_context, message) = initiator.finalize(&reply)?;
            stream.write_all(&message).await?;

            Ok(Ntcp2Session::<R>::new(
                Role::Initiator,
                router,
                runtime.clone(),
                stream,
                key_context,
                subsystem_handle,
            ))
        }
    }

    /// Accept inbound TCP connection and negotiate NTCP2 session parameters for it.
    pub fn accept_session(
        &self,
        mut stream: R::TcpStream,
    ) -> impl Future<Output = crate::Result<(Ntcp2Session<R>)>> {
        let local_info = self.local_router_info.serialize(&self.local_signing_key);
        let local_router_hash = self.local_router_info.identity().hash().to_vec();
        let inbound_initial_state = self.inbound_initial_state.clone();
        let chaining_key = self.chaining_key.clone();
        let runtime = self.runtime.clone();
        let subsystem_handle = self.subsystem_handle.clone();
        let local_key = self.local_key.clone();
        let iv = self.local_iv.clone();

        async move {
            tracing::trace!(
                target: LOG_TARGET,
                "read `SessionRequest` from socket",
            );

            /// read first part of `SessionRequest` which has fixed length
            let mut message = vec![0u8; 64];
            stream.read_exact(&mut message).await?;

            let (mut responder, padding_len) = Responder::new::<R>(
                inbound_initial_state.clone(),
                chaining_key.clone(),
                local_router_hash,
                local_key.clone(),
                iv,
                message,
            )?;

            // read padding and create session if the peer is accepted
            let mut padding = alloc::vec![0u8; padding_len];
            stream.read_exact(&mut padding).await?;

            let (message, message_len) = responder.create_session::<R>(padding)?;
            stream.write_all(&message).await?;

            // read `SessionConfirmed` message and finalize session
            let mut message = alloc::vec![0u8; message_len];
            stream.read_exact(&mut message).await?;

            match responder.finalize(message) {
                Ok((key_context, router)) => {
                    tracing::info!(%router);

                    Ok(Ntcp2Session::new(
                        Role::Responder,
                        router,
                        runtime.clone(),
                        stream,
                        key_context,
                        subsystem_handle,
                    ))
                }
                Err(error) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to accept session",
                    );
                    let _ = stream.close().await;

                    Err(error)
                }
            }
        }
    }
}
