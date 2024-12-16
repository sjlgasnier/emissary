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
    profile::ProfileStorage,
    runtime::{Runtime, TcpStream},
    transports::{
        ntcp2::session::{initiator::Initiator, responder::Responder},
        SubsystemHandle,
    },
    util::{AsyncReadExt, AsyncWriteExt},
    Error,
};

use bytes::Bytes;

use alloc::{vec, vec::Vec};
use core::{future::Future, str::FromStr};

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

/// Session manager.
///
/// Responsible for creating context for inbound and outboudn NTCP2 sessions.
pub struct SessionManager<R: Runtime> {
    /// Chaining key.
    chaining_key: Bytes,

    /// State that is common for all inbound connections.
    inbound_initial_state: Bytes,

    /// Local NTCP2 IV.
    local_iv: [u8; 16],

    /// Local NTCP2 static key.
    local_key: StaticPrivateKey,

    /// Local router info.
    local_router_info: RouterInfo,

    /// Local signing key.
    local_signing_key: SigningPrivateKey,

    /// State that is common for all outbound connections.
    outbound_initial_state: Bytes,

    /// Router storage.
    profile_storage: ProfileStorage<R>,

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
        local_key: [u8; 32],
        local_iv: [u8; 16],
        local_signing_key: SigningPrivateKey,
        local_router_info: RouterInfo,
        subsystem_handle: SubsystemHandle,
        profile_storage: ProfileStorage<R>,
    ) -> crate::Result<Self> {
        let local_key = StaticPrivateKey::from(local_key);
        let state = Sha256::new().update(PROTOCOL_NAME.as_bytes()).finalize();
        let chaining_key = state.clone();
        let outbound_initial_state = Sha256::new().update(&state).finalize();
        let inbound_initial_state = Sha256::new()
            .update(&outbound_initial_state)
            .update(local_key.public().to_vec())
            .finalize();

        Ok(Self {
            chaining_key: Bytes::from(chaining_key),
            inbound_initial_state: Bytes::from(inbound_initial_state),
            local_iv,
            local_key,
            local_router_info,
            local_signing_key,
            outbound_initial_state: Bytes::from(outbound_initial_state),
            profile_storage,
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
        let net_id = self.local_router_info.net_id;
        let local_info = self.local_router_info.serialize(&self.local_signing_key);
        let router_id = router.identity.id();
        let local_key = self.local_key.clone();
        let outbound_initial_state = self.outbound_initial_state.clone();
        let chaining_key = self.chaining_key.clone();
        let mut subsystem_handle = self.subsystem_handle.clone();

        async move {
            let (remote_key, iv, socket_address) = {
                let ntcp2 =
                    router.addresses.get(&TransportKind::Ntcp2).ok_or(Error::NotSupported)?;

                let static_key = ntcp2
                    .options
                    .get(&Str::from_str("s").expect("to succeed"))
                    .ok_or_else(|| {
                        tracing::warn!(target: LOG_TARGET, "static key missing from ntcp2 info");
                        Error::InvalidData
                    })?;

                let iv = ntcp2.options.get(&Str::from_str("i").expect("to succeed")).ok_or_else(
                    || {
                        tracing::warn!(target: LOG_TARGET, "iv missing from ntcp2 info");
                        Error::InvalidData
                    },
                )?;

                let socket_address = ntcp2.socket_address.ok_or_else(|| {
                    tracing::debug!(target: LOG_TARGET, "router doesn't have socket address");
                    Error::InvalidData
                })?;

                (
                    StaticPublicKey::from_bytes(&base64_decode(static_key.as_bytes()).ok_or_else(
                        || {
                            tracing::warn!(
                                target: LOG_TARGET,
                                "failed to base64-decode ntcp2 static key"
                            );

                            Error::InvalidData
                        },
                    )?)
                    .ok_or_else(|| {
                        tracing::warn!(
                            target: LOG_TARGET,
                            "failed to create public key from ntcp2 record",
                        );
                        Error::InvalidData
                    })?,
                    base64_decode(iv.as_bytes()).ok_or_else(|| {
                        tracing::warn!(
                            target: LOG_TARGET,
                            "failed to base64-decode ntcp2 iv"
                        );

                        Error::InvalidData
                    })?,
                    socket_address,
                )
            };

            tracing::trace!(
                target: LOG_TARGET,
                ?socket_address,
                "start dialing remote peer",
            );

            let Some(mut stream) = R::TcpStream::connect(socket_address).await else {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    "failed to dial router",
                );
                subsystem_handle.report_connection_failure(router_id).await;
                return Err(Error::DialFailure);
            };
            let router_hash = router.identity.hash().to_vec();

            // create `SessionRequest` message and send it remote peer
            let (mut initiator, message) = Initiator::new::<R>(
                &outbound_initial_state,
                &chaining_key,
                local_info,
                local_key,
                &remote_key,
                router_hash,
                iv,
                net_id,
            )?;
            stream.write_all(&message).await?;

            // read `SessionCreated` and decrypt & parse it to find padding length
            let mut reply = alloc::vec![0u8; 64];
            stream.read_exact(&mut reply).await?;

            let padding_len = initiator.register_session_confirmed(&reply)?;

            // read padding and finalize session by sending `SessionConfirmed`
            let mut reply = alloc::vec![0u8; padding_len];
            stream.read_exact(&mut reply).await?;

            let (key_context, message) = initiator.finalize(&reply)?;
            stream.write_all(&message).await?;

            Ok(Ntcp2Session::<R>::new(
                Role::Initiator,
                router,
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
    ) -> impl Future<Output = crate::Result<Ntcp2Session<R>>> {
        let net_id = self.local_router_info.net_id();
        let local_router_hash = self.local_router_info.identity.hash().to_vec();
        let inbound_initial_state = self.inbound_initial_state.clone();
        let chaining_key = self.chaining_key.clone();
        let subsystem_handle = self.subsystem_handle.clone();
        let local_key = self.local_key.clone();
        let iv = self.local_iv;
        let profile_storage = self.profile_storage.clone();

        async move {
            tracing::trace!(
                target: LOG_TARGET,
                "read `SessionRequest` from socket",
            );

            // read first part of `SessionRequest` which has fixed length
            let mut message = vec![0u8; 64];
            stream.read_exact(&mut message).await?;

            let (mut responder, padding_len) = Responder::new(
                &inbound_initial_state,
                &chaining_key,
                local_router_hash,
                local_key.clone(),
                iv,
                message,
                net_id,
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
                    if router.net_id() != net_id {
                        tracing::warn!(
                            target: LOG_TARGET,
                            local_net_id = ?net_id,
                            remote_net_id = ?router.net_id(),
                            "remote router is part of a different network",
                        );

                        let _ = stream.close().await;
                        return Err(Error::NetworkMismatch);
                    }

                    profile_storage.add_router(router.clone());

                    Ok(Ntcp2Session::new(
                        Role::Responder,
                        router,
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

#[cfg(test)]
mod tests {
    use crate::{
        crypto::{SigningPrivateKey, StaticPrivateKey},
        primitives::{
            Capabilities, Date, RouterAddress, RouterIdentity, RouterInfo, Str, TransportKind,
        },
        profile::ProfileStorage,
        runtime::{
            mock::{MockRuntime, MockTcpStream},
            Runtime,
        },
        subsystem::SubsystemHandle,
        transports::ntcp2::session::SessionManager,
    };
    use hashbrown::HashMap;
    use rand::{thread_rng, RngCore};
    use std::time::Duration;
    use tokio::net::TcpListener;

    struct Ntcp2Builder {
        net_id: u8,
        router_address: Option<RouterAddress>,
        ntcp2_iv: [u8; 16],
        ntcp2_key: [u8; 32],
    }

    impl Ntcp2Builder {
        fn new() -> Self {
            let ntcp2_key = {
                let mut local_key = [0u8; 32];
                thread_rng().fill_bytes(&mut local_key);
                local_key
            };
            let ntcp2_iv = {
                let mut local_iv = [0u8; 16];
                thread_rng().fill_bytes(&mut local_iv);
                local_iv
            };

            Self {
                net_id: 2u8,
                router_address: None,
                ntcp2_iv,
                ntcp2_key,
            }
        }

        fn with_net_id(mut self, net_id: u8) -> Self {
            self.net_id = net_id;
            self
        }

        fn with_router_address(mut self, port: u16) -> Self {
            self.router_address = Some(RouterAddress::new_published(
                self.ntcp2_key.clone(),
                self.ntcp2_iv,
                port,
                "127.0.0.1".to_string(),
            ));
            self
        }

        fn build(mut self) -> Ntcp2 {
            let signing_key = SigningPrivateKey::random(thread_rng());
            let static_key = StaticPrivateKey::random(thread_rng());
            let identity = RouterIdentity::from_keys::<MockRuntime>(
                static_key.as_ref().to_vec(),
                signing_key.as_ref().to_vec(),
            )
            .unwrap();
            let router_info = RouterInfo {
                identity,
                published: Date::new(
                    (MockRuntime::time_since_epoch() - Duration::from_secs(2 * 60)).as_millis()
                        as u64,
                ),
                addresses: HashMap::from_iter([(
                    TransportKind::Ntcp2,
                    self.router_address
                        .take()
                        .unwrap_or(RouterAddress::new_unpublished(self.ntcp2_key.clone())),
                )]),
                options: HashMap::from_iter([
                    (Str::from("netId"), Str::from(self.net_id.to_string())),
                    (Str::from("caps"), Str::from("L")),
                ]),
                net_id: self.net_id,
                capabilities: Capabilities::parse(&Str::from("L")).unwrap(),
            };

            Ntcp2 {
                ntcp2_iv: self.ntcp2_iv,
                ntcp2_key: self.ntcp2_key,
                router_info,
                signing_key,
            }
        }
    }

    struct Ntcp2 {
        ntcp2_iv: [u8; 16],
        ntcp2_key: [u8; 32],
        router_info: RouterInfo,
        signing_key: SigningPrivateKey,
    }

    #[tokio::test]
    async fn connection_succeeds() {
        let local = Ntcp2Builder::new().build();
        let local_manager = SessionManager::new(
            local.ntcp2_key,
            local.ntcp2_iv,
            local.signing_key,
            local.router_info,
            SubsystemHandle::new(),
            ProfileStorage::<MockRuntime>::new(&[], &[]),
        )
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote = Ntcp2Builder::new()
            .with_router_address(listener.local_addr().unwrap().port())
            .build();
        let remote_manager = SessionManager::new(
            remote.ntcp2_key,
            remote.ntcp2_iv,
            remote.signing_key,
            remote.router_info.clone(),
            SubsystemHandle::new(),
            ProfileStorage::<MockRuntime>::new(&[], &[]),
        )
        .unwrap();

        let handle =
            tokio::spawn(
                async move { local_manager.create_session(remote.router_info.clone()).await },
            );

        let stream = MockTcpStream::new(
            tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap()
                .0,
        );
        let (res1, res2) = tokio::join!(remote_manager.accept_session(stream), handle);

        assert!(res1.is_ok());
        assert!(res2.unwrap().is_ok());
    }

    #[tokio::test]
    async fn invalid_network_id_initiator() {
        let local = Ntcp2Builder::new().with_net_id(128).build();
        let local_manager = SessionManager::new(
            local.ntcp2_key,
            local.ntcp2_iv,
            local.signing_key,
            local.router_info,
            SubsystemHandle::new(),
            ProfileStorage::<MockRuntime>::new(&[], &[]),
        )
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote = Ntcp2Builder::new()
            .with_router_address(listener.local_addr().unwrap().port())
            .build();
        let remote_manager = SessionManager::new(
            remote.ntcp2_key,
            remote.ntcp2_iv,
            remote.signing_key,
            remote.router_info.clone(),
            SubsystemHandle::new(),
            ProfileStorage::<MockRuntime>::new(&[], &[]),
        )
        .unwrap();

        let handle = tokio::spawn(async move {
            let stream = MockTcpStream::new(
                tokio::time::timeout(Duration::from_secs(5), listener.accept())
                    .await
                    .unwrap()
                    .unwrap()
                    .0,
            );
            remote_manager.accept_session(stream).await
        });

        assert!(local_manager.create_session(remote.router_info.clone()).await.is_err());
        assert!(handle.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn invalid_network_id_responder() {
        let local = Ntcp2Builder::new().build();
        let local_manager = SessionManager::new(
            local.ntcp2_key,
            local.ntcp2_iv,
            local.signing_key,
            local.router_info,
            SubsystemHandle::new(),
            ProfileStorage::<MockRuntime>::new(&[], &[]),
        )
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote = Ntcp2Builder::new()
            .with_net_id(128)
            .with_router_address(listener.local_addr().unwrap().port())
            .build();
        let remote_manager = SessionManager::new(
            remote.ntcp2_key,
            remote.ntcp2_iv,
            remote.signing_key,
            remote.router_info.clone(),
            SubsystemHandle::new(),
            ProfileStorage::<MockRuntime>::new(&[], &[]),
        )
        .unwrap();

        let handle = tokio::spawn(async move {
            let stream = MockTcpStream::new(
                tokio::time::timeout(Duration::from_secs(5), listener.accept())
                    .await
                    .unwrap()
                    .unwrap()
                    .0,
            );
            remote_manager.accept_session(stream).await
        });

        assert!(local_manager.create_session(remote.router_info.clone()).await.is_err());
        assert!(handle.await.unwrap().is_err());
    }
}
