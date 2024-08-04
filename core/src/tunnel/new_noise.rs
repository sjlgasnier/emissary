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
        EphemeralPrivateKey, EphemeralPublicKey, StaticPrivateKey, StaticPublicKey,
    },
    i2np::HopRole,
    runtime::Runtime,
    Error,
};

use bytes::Bytes;
use zeroize::Zeroize;

use alloc::{sync::Arc, vec, vec::Vec};
use core::{fmt, mem};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::noise";

/// Noise protocol name;.
const PROTOCOL_NAME: &str = "Noise_N_25519_ChaChaPoly_SHA256";

/// Tunnel key context.
pub struct TunnelKeyContext {
    iv_key: Vec<u8>,
    layer_key: Vec<u8>,
}

impl TunnelKeyContext {
    /// Get reference to IV key.
    pub fn iv_key(&self) -> &[u8] {
        &self.iv_key
    }

    /// Get reference to layer key.
    pub fn layer_key(&self) -> &[u8] {
        &self.layer_key
    }
}

/// Tunnel keys.
pub struct TunnelKeys {
    /// Garlic key.
    ///
    /// Only available for OBEP.
    garlic_key: Option<Vec<u8>>,

    /// Garlic tag.
    ///
    /// Only available for OBEP.
    garlic_tag: Option<Vec<u8>>,

    /// IV key.
    iv_key: Vec<u8>,

    /// Layer key.
    layer_key: Vec<u8>,

    /// Reply key.
    ///
    /// Only used during tunnel building.
    reply_key: Vec<u8>,
}

impl TunnelKeys {
    /// Get reference to Garlic key.
    pub fn garlic_key(&self) -> &[u8] {
        self.garlic_key.as_ref().expect("to exist").as_ref()
    }

    /// Get reference to Garlic tag.
    pub fn garlic_tag(&self) -> &[u8] {
        self.garlic_tag.as_ref().expect("to exist").as_ref()
    }

    /// Get reference to IV key.
    pub fn iv_key(&self) -> &[u8] {
        &self.iv_key
    }

    /// Get reference to layer key.
    pub fn layer_key(&self) -> &[u8] {
        &self.layer_key
    }

    /// Get reference to reply key.
    pub fn reply_key(&self) -> &[u8] {
        &self.reply_key
    }
}

impl TunnelKeys {
    /// Create new [`TunnelKeys`].
    fn new(mut chaining_key: Vec<u8>, hop_role: HopRole) -> TunnelKeys {
        let mut temp_key = Hmac::new(&chaining_key).update(&[]).finalize();
        let ck = Hmac::new(&temp_key).update(&b"SMTunnelReplyKey").update(&[0x01]).finalize();
        let reply_key = Hmac::new(&temp_key)
            .update(&ck)
            .update(&b"SMTunnelReplyKey")
            .update(&[0x02])
            .finalize();

        let mut temp_key = Hmac::new(&ck).update(&[]).finalize();
        let mut ck = Hmac::new(&temp_key).update(&b"SMTunnelLayerKey").update(&[0x01]).finalize();
        let layer_key = Hmac::new(&temp_key)
            .update(&ck)
            .update(&b"SMTunnelLayerKey")
            .update(&[0x02])
            .finalize();

        match hop_role {
            HopRole::InboundGateway | HopRole::Participant => {
                temp_key.zeroize();
                chaining_key.zeroize();

                TunnelKeys {
                    garlic_key: None,
                    garlic_tag: None,
                    iv_key: ck,
                    layer_key,
                    reply_key,
                }
            }
            HopRole::OutboundEndpoint => {
                let mut temp_key = Hmac::new(&ck).update(&[]).finalize();
                let ck =
                    Hmac::new(&temp_key).update(&b"TunnelLayerIVKey").update(&[0x01]).finalize();
                let iv_key = Hmac::new(&temp_key)
                    .update(&ck)
                    .update(&b"TunnelLayerIVKey")
                    .update(&[0x02])
                    .finalize();

                let mut temp_key = Hmac::new(&ck).update(&[]).finalize();
                let mut ck =
                    Hmac::new(&temp_key).update(&b"RGarlicKeyAndTag").update(&[0x01]).finalize();
                let garlic_key = Hmac::new(&temp_key)
                    .update(&ck)
                    .update(&b"RGarlicKeyAndTag")
                    .update(&[0x02])
                    .finalize();

                let garlic_tag = ck[..8].to_vec();

                temp_key.zeroize();
                chaining_key.zeroize();

                TunnelKeys {
                    garlic_key: Some(garlic_key),
                    garlic_tag: Some(garlic_tag),
                    iv_key,
                    layer_key,
                    reply_key,
                }
            }
        }
    }
}

/// Inbound session (transit tunnel) state with short records.
enum ShortInboundSessionState {
    /// Inbound state has been initialized.
    ///
    /// Next step is decrypting the received build record.
    Initialized {
        /// Chaining key.
        chaining_key: Vec<u8>,

        /// AEAD key, used to encrypt/decrypt build records.
        aead_key: Vec<u8>,

        /// Associaed data for encrypting/decrypting build records.
        state: Vec<u8>,
    },

    /// Build record decrypted.
    RecordDecrypted {
        /// Chaining key.
        chaining_key: Vec<u8>,

        /// AEAD key, used to encrypt/decrypt build records.
        aead_key: Vec<u8>,

        /// Associaed data for encrypting/decrypting build records.
        state: Vec<u8>,
    },

    /// Tunnel keys derived
    TunnelKeysDerived {
        /// Associated data from previous state.
        state: Vec<u8>,

        /// Tunnels keys.
        tunnel_keys: TunnelKeys,
    },

    /// Build records encrypted.
    ///
    /// This is the final state before finalizing the session creation.
    BuildRecordsEncrypted {
        /// Tunnels keys.
        tunnel_keys: TunnelKeys,
    },

    /// State has been poisoned.
    Poisoned,
}

impl fmt::Debug for ShortInboundSessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Initialized { .. } =>
                f.debug_struct("ShortInboundSessionState::Initialized").finish_non_exhaustive(),
            Self::RecordDecrypted { .. } => f
                .debug_struct("ShortInboundSessionState::RecordDecrypted")
                .finish_non_exhaustive(),
            Self::TunnelKeysDerived { .. } => f
                .debug_struct("ShortInboundSessionState::TunnelKeysDerived")
                .finish_non_exhaustive(),
            Self::BuildRecordsEncrypted { .. } => f
                .debug_struct("ShortInboundSessionState::BuildRecordsEncrypted")
                .finish_non_exhaustive(),
            Self::Poisoned => f.debug_struct("ShortInboundSessionState::Poisoned").finish(),
        }
    }
}

/// Noise context for inbound session (transit tunnels) with short records.
///
/// https://geti2p.net/spec/tunnel-creation-ecies#short-record-specification
pub struct ShortInboundSession {
    /// Inbound session state.
    state: ShortInboundSessionState,
}

impl ShortInboundSession {
    /// Create new [`ShortInboundSession`].
    pub fn new(chaining_key: Vec<u8>, aead_key: Vec<u8>, state: Vec<u8>) -> Self {
        Self {
            state: ShortInboundSessionState::Initialized {
                chaining_key,
                aead_key,
                state,
            },
        }
    }

    /// Decrypt build record and return the plaintext record.
    pub fn decrypt_build_record(&mut self, mut record: Vec<u8>) -> crate::Result<Vec<u8>> {
        match mem::replace(&mut self.state, ShortInboundSessionState::Poisoned) {
            ShortInboundSessionState::Initialized {
                chaining_key,
                aead_key,
                state,
            } => {
                let new_state = Sha256::new().update(&state).update(&record).finalize();

                ChaChaPoly::new(&aead_key).decrypt_with_ad(&state, &mut record)?;

                self.state = ShortInboundSessionState::RecordDecrypted {
                    state: new_state,
                    chaining_key,
                    aead_key,
                };

                Ok(record)
            }
            state => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?state,
                    "state is poisoned",
                );
                debug_assert!(false);
                Err(Error::InvalidState)
            }
        }
    }

    /// Create tunnel keys for the transit tunnel.
    pub fn create_tunnel_keys(&mut self, hop_role: HopRole) -> crate::Result<()> {
        match mem::replace(&mut self.state, ShortInboundSessionState::Poisoned) {
            ShortInboundSessionState::RecordDecrypted {
                chaining_key,
                mut aead_key,
                state,
            } => {
                self.state = ShortInboundSessionState::TunnelKeysDerived {
                    state,
                    tunnel_keys: TunnelKeys::new(chaining_key, hop_role),
                };
                aead_key.zeroize();

                Ok(())
            }
            state => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?state,
                    "state is poisoned",
                );
                debug_assert!(false);
                Err(Error::InvalidState)
            }
        }
    }

    /// Encrypt build records of the tunnel build request.
    ///
    /// `our_record` denotes the index of our record inside the build request. This record is
    /// encrypted with ChaCha20Poly1305 whereas the other records are encrypted with ChaCha20.
    ///
    /// [Specification](https://geti2p.net/spec/tunnel-creation-ecies#record-encryption)
    pub fn encrypt_build_records(
        &mut self,
        payload: &mut [u8],
        our_record: usize,
    ) -> crate::Result<()> {
        match mem::replace(&mut self.state, ShortInboundSessionState::Poisoned) {
            ShortInboundSessionState::TunnelKeysDerived { state, tunnel_keys } => {
                debug_assert!(payload.len() > 218 && (payload.len() - 1) % 218 == 0);

                // encrypt our record with chachapoly, using the associated data derived in
                // `Self::decrypt_build_record()` and encrypt the other records with
                payload[1..].chunks_mut(218).enumerate().for_each(|(idx, mut record)| {
                    if idx == our_record {
                        let tag = ChaChaPoly::with_nonce(&tunnel_keys.reply_key(), idx as u64)
                            .encrypt_with_ad(&state, &mut record[0..202])
                            .unwrap();
                        record[202..218].copy_from_slice(&tag);
                    } else {
                        ChaCha::with_nonce(&tunnel_keys.reply_key(), idx as u64)
                            .encrypt(&mut record);
                    }
                });
                self.state = ShortInboundSessionState::BuildRecordsEncrypted { tunnel_keys };

                Ok(())
            }
            state => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?state,
                    "state is poisoned",
                );
                debug_assert!(false);
                Err(Error::InvalidState)
            }
        }
    }

    /// Finalize inbound session creation and return tunnel keys.
    pub fn finalize(mut self) -> crate::Result<TunnelKeys> {
        match self.state {
            ShortInboundSessionState::BuildRecordsEncrypted { tunnel_keys } => Ok(tunnel_keys),
            state => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?state,
                    "state is poisoned",
                );
                debug_assert!(false);
                Err(Error::InvalidState)
            }
        }
    }
}

/// Inbound session (transit tunnel) state with long records.
///
/// https://geti2p.net/spec/tunnel-creation-ecies#long-record-specification
enum LongInboundSessionState {
    /// Inbound state has been initialized.
    ///
    /// Next step is decrypting the received build record.
    Initialized {
        /// Chaining key.
        chaining_key: Vec<u8>,

        /// AEAD key, used to encrypt/decrypt build records.
        aead_key: Vec<u8>,

        /// Associaed data for encrypting/decrypting build records.
        state: Vec<u8>,
    },

    /// Build record decrypted.
    RecordDecrypted {
        /// Chaining key.
        chaining_key: Vec<u8>,

        /// Associaed data for encrypting/decrypting build records.
        state: Vec<u8>,
    },

    /// Build records encrypted.
    ///
    /// This is the final state before finalizing the session creation.
    BuildRecordsEncrypted,

    /// State has been poisoned.
    Poisoned,
}

impl fmt::Debug for LongInboundSessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Initialized { .. } =>
                f.debug_struct("LongInboundSessionState::Initialized").finish_non_exhaustive(),
            Self::RecordDecrypted { .. } => f
                .debug_struct("LongInboundSessionState::RecordDecrypted")
                .finish_non_exhaustive(),
            Self::BuildRecordsEncrypted { .. } =>
                f.debug_struct("LongInboundSessionState::BuildRecordsEncrypted").finish(),
            Self::Poisoned => f.debug_struct("LongInboundSessionState::Poisoned").finish(),
        }
    }
}

/// Noise context for inbound session (transit tunnels).
pub struct LongInboundSession {
    /// Inbound session state.
    state: LongInboundSessionState,
}

impl LongInboundSession {
    /// Create new [`LongInboundSession`].
    pub fn new(chaining_key: Vec<u8>, aead_key: Vec<u8>, state: Vec<u8>) -> Self {
        Self {
            state: LongInboundSessionState::Initialized {
                chaining_key,
                aead_key,
                state,
            },
        }
    }

    /// Decrypt build record and return the plaintext record.
    pub fn decrypt_build_record(&mut self, mut record: Vec<u8>) -> crate::Result<Vec<u8>> {
        match mem::replace(&mut self.state, LongInboundSessionState::Poisoned) {
            LongInboundSessionState::Initialized {
                chaining_key,
                aead_key,
                state,
            } => {
                let new_state = Sha256::new().update(&state).update(&record).finalize();

                ChaChaPoly::new(&aead_key).decrypt_with_ad(&state, &mut record)?;

                self.state = LongInboundSessionState::RecordDecrypted {
                    state: new_state,
                    chaining_key,
                };

                Ok(record)
            }
            state => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?state,
                    "state is poisoned",
                );
                debug_assert!(false);
                Err(Error::InvalidState)
            }
        }
    }

    /// Encrypt build records of the tunnel build request.
    ///
    /// `our_record` denotes the index of our record inside the build request. This record is
    /// encrypted with ChaCha20Poly1305 whereas the other records are encrypted with ChaCha20.
    pub fn encrypt_build_record(&mut self, record: &mut [u8]) -> crate::Result<()> {
        match mem::replace(&mut self.state, LongInboundSessionState::Poisoned) {
            LongInboundSessionState::RecordDecrypted {
                mut chaining_key,
                state,
            } => {
                let tag = ChaChaPoly::new(&chaining_key)
                    .encrypt_with_ad(&state, &mut record[0..512])
                    .unwrap();
                record[512..528].copy_from_slice(&tag);

                self.state = LongInboundSessionState::BuildRecordsEncrypted;

                Ok(())
            }
            state => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?state,
                    "state is poisoned",
                );
                debug_assert!(false);
                Err(Error::InvalidState)
            }
        }
    }

    /// Finalize inbound session creation and return tunnel keys.
    pub fn finalize(mut self, layer_key: Vec<u8>, iv_key: Vec<u8>) -> crate::Result<TunnelKeys> {
        match self.state {
            LongInboundSessionState::BuildRecordsEncrypted => Ok(TunnelKeys {
                garlic_key: None,
                garlic_tag: None,
                iv_key,
                layer_key,
                reply_key: Vec::new(),
            }),
            state => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?state,
                    "state is poisoned",
                );
                debug_assert!(false);
                Err(Error::InvalidState)
            }
        }
    }
}

/// Noise context for outbound sessions (local tunnels).
pub struct OutboundSession {
    /// AEAD key for encrypting build records.
    aead_key: Vec<u8>,

    /// Serialized ephemeral public key.
    ephemeral_key: Vec<u8>,

    /// Associated data for encrypting build records.
    state: Vec<u8>,

    /// Tunnel keys.
    tunnel_keys: TunnelKeys,
}

impl OutboundSession {
    /// Get reference to AEAD key.
    pub fn aead_key(&self) -> &[u8] {
        &self.aead_key
    }

    /// Get reference to serialized ephemeral public key.
    pub fn ephemeral_key(&self) -> &[u8] {
        &self.ephemeral_key
    }

    /// Get reference to associated data.
    ///
    /// Used when encrypting/decrypting build records.
    pub fn state(&self) -> &[u8] {
        &self.state
    }

    /// Set value for associated data.
    pub fn set_state(&mut self, state: Vec<u8>) {
        self.state = state;
    }

    /// Get reference to Garlic key.
    pub fn garlic_key(&self) -> &[u8] {
        self.tunnel_keys.garlic_key()
    }

    /// Get reference to Garlic tag.
    pub fn garlic_tag(&self) -> &[u8] {
        &self.tunnel_keys.garlic_tag()
    }

    /// Get reference to IV key.
    pub fn iv_key(&self) -> &[u8] {
        &self.tunnel_keys.iv_key()
    }

    /// Get reference to layer key.
    pub fn layer_key(&self) -> &[u8] {
        &self.tunnel_keys.layer_key()
    }

    /// Get reference to reply key.
    pub fn reply_key(&self) -> &[u8] {
        &self.tunnel_keys.reply_key()
    }
}

impl fmt::Debug for OutboundSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboundSession").finish_non_exhaustive()
    }
}

/// Noise context for tunnels.
#[derive(Clone)]
pub struct NoiseContext {
    /// Chaining key.
    chaining_key: Bytes,

    /// Inbound state.
    inbound_state: Bytes,

    /// Outbound state.
    outbound_state: Bytes,

    /// Local static key.
    local_key: Arc<StaticPrivateKey>,

    /// Local router hash.
    local_router_hash: Bytes,
}

impl NoiseContext {
    /// Create new [`NoiseContext`].
    pub fn new(local_key: StaticPrivateKey, local_router_hash: Bytes) -> Self {
        let chaining_key = {
            let mut chaining_key = PROTOCOL_NAME.as_bytes().to_vec();
            chaining_key.append(&mut vec![0u8]);
            chaining_key
        };
        let outbound_state = Sha256::new().update(&chaining_key).finalize();
        let inbound_state = Sha256::new()
            .update(&outbound_state)
            .update(local_key.public().to_bytes())
            .finalize();

        Self {
            local_router_hash,
            chaining_key: Bytes::from(chaining_key),
            inbound_state: Bytes::from(inbound_state),
            outbound_state: Bytes::from(outbound_state),
            local_key: Arc::new(local_key),
        }
    }

    /// Get reference to local router hash.
    pub fn local_router_hash(&self) -> &Bytes {
        &self.local_router_hash
    }

    /// Create outbound Noise context for tunnels created by the local router.
    pub fn create_outbound_session<R: Runtime>(
        &self,
        remote_static: StaticPublicKey,
        hop_role: HopRole,
    ) -> OutboundSession {
        let local_ephemeral = EphemeralPrivateKey::new(R::rng());
        let local_ephemeral_public = local_ephemeral.public_key().to_vec();
        let state = {
            let state = Sha256::new()
                .update(&self.outbound_state)
                .update::<&[u8]>(remote_static.as_ref())
                .finalize();

            Sha256::new().update(&state).update(&local_ephemeral_public).finalize()
        };

        let mut shared_secret = local_ephemeral.diffie_hellman(&remote_static);
        let mut temp_key = Hmac::new(&self.chaining_key).update(&shared_secret).finalize();
        let chaining_key = Hmac::new(&temp_key).update(&[0x01]).finalize();
        let aead_key = Hmac::new(&temp_key).update(&chaining_key).update(&[0x02]).finalize();

        temp_key.zeroize();
        shared_secret.zeroize();
        local_ephemeral.zeroize();

        OutboundSession {
            tunnel_keys: TunnelKeys::new(chaining_key, hop_role),
            ephemeral_key: local_ephemeral_public,
            state,
            aead_key,
        }
    }

    /// Create inbound Noise session for a transit tunnel with short build records (218 bytes).
    pub fn create_short_inbound_session(
        &self,
        remote_key: EphemeralPublicKey,
    ) -> ShortInboundSession {
        let mut shared_secret = self.local_key.diffie_hellman(&remote_key);
        let mut temp_key = Hmac::new(&self.chaining_key).update(&shared_secret).finalize();
        let chaining_key = Hmac::new(&temp_key).update(&[0x01]).finalize();
        let aead_key = Hmac::new(&temp_key).update(&chaining_key).update(&[0x02]).finalize();
        let state = Sha256::new()
            .update(&self.inbound_state)
            .update(&remote_key.to_vec())
            .finalize();

        temp_key.zeroize();
        shared_secret.zeroize();

        ShortInboundSession::new(chaining_key, aead_key, state)
    }

    /// Create inbound Noise session for a transit tunnel with long build records (528 bytes).
    pub fn create_long_inbound_session(
        &self,
        remote_key: EphemeralPublicKey,
    ) -> LongInboundSession {
        let mut shared_secret = self.local_key.diffie_hellman(&remote_key);
        let mut temp_key = Hmac::new(&self.chaining_key).update(&shared_secret).finalize();
        let chaining_key = Hmac::new(&temp_key).update(&[0x01]).finalize();
        let aead_key = Hmac::new(&temp_key).update(&chaining_key).update(&[0x02]).finalize();
        let state = Sha256::new()
            .update(&self.inbound_state)
            .update(&remote_key.to_vec())
            .finalize();

        temp_key.zeroize();
        shared_secret.zeroize();

        LongInboundSession::new(chaining_key, aead_key, state)
    }
}
