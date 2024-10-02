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
        chachapoly::ChaChaPoly, hmac::Hmac, sha256::Sha256, StaticPrivateKey, StaticPublicKey,
    },
    destination::session::tagset::{PendingTagSet, TagSet, TagSetEntry},
    i2np::{
        garlic::{NextKeyBuilder, NextKeyKind},
        Message,
    },
    primitives::DestinationId,
    runtime::Runtime,
    Error,
};

use bytes::{BufMut, Bytes, BytesMut};
use curve25519_elligator2::{MapToPointVariant, MontgomeryPoint, Randomized};
use rand_core::RngCore;
use x25519_dalek::PublicKey;
use zeroize::Zeroize;

use alloc::vec::Vec;
use core::{fmt, marker::PhantomData, mem};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::session::context";

/// Noise protocol name.
const PROTOCOL_NAME: &str = "Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256";

/// Outbound session state.
enum OutboundSessionState {
    /// `NewSession` message has been sent to remote and the session is waiting for a reply.
    OutboundSessionPending {
        /// Destination ID.
        destination_id: DestinationId,

        /// State (`h` from the specification).
        state: Bytes,

        /// Static private key.
        static_private_key: StaticPrivateKey,

        /// Ephemeral private key.
        ephemeral_private_key: StaticPrivateKey,

        /// Chaining key.
        chaining_key: Vec<u8>,
    },

    /// Session has been negotiated.
    Active {
        /// Destination ID.
        destination_id: DestinationId,

        /// [`TagSet`] for outbound messages.
        send_tag_set: TagSet,

        /// [`TagSet`] for inbound messages.
        recv_tag_set: TagSet,

        /// Pending outbound [`TagSet`], if any.
        pending_outbound_tagset: Option<PendingTagSet>,
    },

    /// State has been poisoned.
    Poisoned,
}

impl fmt::Debug for OutboundSessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutboundSessionPending { destination_id, .. } => f
                .debug_struct("OutboundSessionState::OutboundSessionPending")
                .field("id", &destination_id)
                .finish_non_exhaustive(),
            Self::Active { destination_id, .. } => f
                .debug_struct("OutboundSessionState::Active")
                .field("id", &destination_id)
                .finish_non_exhaustive(),
            Self::Poisoned =>
                f.debug_struct("OutboundSessionState::Poisoned").finish_non_exhaustive(),
        }
    }
}

/// Outbound session.
pub struct OutboundSession<R: Runtime> {
    /// Outbound session state.
    state: OutboundSessionState,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> OutboundSession<R> {
    /// Garlic-encrypt `message`.
    pub fn encrypt_message(&mut self, mut message: Vec<u8>) -> crate::Result<Vec<u8>> {
        match &mut self.state {
            OutboundSessionState::Active { send_tag_set, .. } => {
                // TODO: next key
                let TagSetEntry { index, key, tag } = send_tag_set.next_entry().unwrap();

                // TODO: ugly
                let mut out = BytesMut::with_capacity(message.len() + 16 + 8);

                let mac = ChaChaPoly::with_nonce(&key, index as u64)
                    .encrypt_with_ad(&tag, &mut message)
                    .unwrap();

                out.put_slice(&tag);
                out.put_slice(&message);
                out.put_slice(&mac);

                Ok(out.freeze().to_vec())
            }
            state => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?state,
                    "invalid state for call to `encrypt_message()`",
                );
                debug_assert!(false);
                return Err(Error::InvalidState);
            }
        }
    }

    /// Garlic-decrypt `message`, potentially advancing the state of the [`OutboundSession`].
    ///
    /// Returns a byte vector to the decrypted payload section of `message`.
    pub fn decrypt_message(&mut self, message: Message) -> crate::Result<Vec<u8>> {
        match mem::replace(&mut self.state, OutboundSessionState::Poisoned) {
            // Handle `NewSessionReply` message.
            //
            // https://geti2p.net/spec/ecies#kdf-for-flags-static-key-section-encrypted-contents
            OutboundSessionState::OutboundSessionPending {
                state,
                ephemeral_private_key,
                static_private_key,
                chaining_key,
                destination_id,
            } => {
                if message.payload.len() < 60 {
                    tracing::warn!(
                        target: LOG_TARGET,
                        payload_len = ?message.payload.len(),
                        "`NewSessionReply` is too short",
                    );
                    debug_assert!(false);

                    return Err(Error::InvalidData);
                }

                // garlic tag, used as associated data for the decipher
                let garlic_tag = message.payload[4..12].to_vec();

                // extract and decode elligator2-encoded public key of the remote destination
                let public_key = {
                    // conversion must succeed since the provided range is correct and
                    // the payload has been confirmed to be large enough to hold the public key
                    let public_key = TryInto::<[u8; 32]>::try_into(&message.payload[12..44])
                        .expect("to succeed");
                    let new_pubkey = Randomized::from_representative(&public_key)
                        .unwrap()
                        .to_montgomery()
                        .to_bytes();

                    StaticPublicKey::from(new_pubkey)
                };

                // poly1305 mac for the key section (empty payload)
                let mut ciphertext = message.payload[44..60].to_vec();

                // payload section of the `NewSessionReply`
                let mut payload = message.payload[60..].to_vec();

                // calculate new state with garlic tag & remote's ephemeral public key
                let state = {
                    let state = Sha256::new().update(&state).update(&garlic_tag).finalize();

                    Sha256::new().update(&state).update::<&[u8]>(public_key.as_ref()).finalize()
                };

                // calculate keys from shared secrets derived from ee & es
                let (chaining_key, keydata) = {
                    // ephemeral-ephemeral
                    let mut shared = ephemeral_private_key.diffie_hellman(&public_key);
                    let mut temp_key = Hmac::new(&chaining_key).update(&shared).finalize();
                    let mut chaining_key =
                        Hmac::new(&temp_key).update(&b"").update(&[0x01]).finalize();

                    // static-ephemeral
                    shared = static_private_key.diffie_hellman(&public_key);
                    temp_key = Hmac::new(&chaining_key).update(&shared).finalize();
                    chaining_key = Hmac::new(&temp_key).update(&b"").update(&[0x01]).finalize();
                    let keydata = Hmac::new(&temp_key)
                        .update(&chaining_key)
                        .update(&b"")
                        .update(&[0x02])
                        .finalize();

                    shared.zeroize();
                    temp_key.zeroize();

                    (chaining_key, keydata)
                };

                // verify they poly1305 mac for the key section is correct and return updated state
                let state = {
                    let updated_state = Sha256::new().update(&state).update(&ciphertext).finalize();
                    ChaChaPoly::new(&keydata).decrypt_with_ad(&state, &mut ciphertext)?;

                    updated_state
                };

                // split key into send and receive keys
                let mut temp_key = Hmac::new(&chaining_key).update(&[]).finalize();
                let mut send_key = Hmac::new(&temp_key).update(&[0x01]).finalize();
                let mut recv_key =
                    Hmac::new(&temp_key).update(&send_key).update(&[0x02]).finalize();

                // initialize send and receive tag sets
                let send_tag_set = TagSet::new(0u16, &chaining_key, send_key);
                let recv_tag_set = TagSet::new(0u16, chaining_key, &recv_key);

                // decode payload of the `NewSessionReply` message
                let mut temp_key = Hmac::new(&recv_key).update(&[]).finalize();
                let mut payload_key =
                    Hmac::new(&temp_key).update(&b"AttachPayloadKDF").update(&[0x01]).finalize();

                ChaChaPoly::new(&payload_key).decrypt_with_ad(&state, &mut payload)?;

                temp_key.zeroize();
                payload_key.zeroize();

                self.state = OutboundSessionState::Active {
                    destination_id,
                    send_tag_set,
                    recv_tag_set,
                    pending_outbound_tagset: None,
                };

                Ok(payload)
            }
            OutboundSessionState::Active {
                destination_id,
                send_tag_set,
                mut recv_tag_set,
                pending_outbound_tagset,
            } => {
                let TagSetEntry { index, key, tag } = recv_tag_set.next_entry().unwrap();

                let size = message.payload[..4].to_vec();
                let garlic_tag = message.payload[4..12].to_vec();
                let mut payload = message.payload[12..].to_vec();

                // TODO: lookup for garlic tag

                ChaChaPoly::with_nonce(&key, index as u64)
                    .decrypt_with_ad(&tag, &mut payload)
                    .unwrap();

                self.state = OutboundSessionState::Active {
                    destination_id,
                    send_tag_set,
                    recv_tag_set,
                    pending_outbound_tagset,
                };

                Ok(payload)
            }
            OutboundSessionState::Poisoned => {
                tracing::warn!(
                    target: LOG_TARGET,
                    "outbound session state has been poisoned"
                );
                debug_assert!(false);
                return Err(Error::InvalidState);
            }
        }
    }

    /// Generate new send key for the [`OutboundSession`].
    //
    // TODO: explain in more detail
    pub fn generate_next_key(&mut self) -> crate::Result<NextKeyKind> {
        match mem::replace(&mut self.state, OutboundSessionState::Poisoned) {
            OutboundSessionState::Active {
                destination_id,
                send_tag_set,
                recv_tag_set,
                pending_outbound_tagset,
            } => {
                let pending_tagset = send_tag_set.create_pending_tagset::<R>();
                let public_key = pending_tagset.public_key();
                let key_id = pending_tagset.key_id();

                self.state = OutboundSessionState::Active {
                    destination_id,
                    send_tag_set,
                    recv_tag_set,
                    pending_outbound_tagset: Some(pending_tagset),
                };

                Ok(NextKeyBuilder::forward(key_id)
                    .with_public_key(public_key)
                    .with_request_reverse_key(true)
                    .build())
            }
            OutboundSessionState::OutboundSessionPending { .. } => {
                tracing::warn!(
                    target: LOG_TARGET,
                    "cannot generate new key while session is pending"
                );
                debug_assert!(false);
                return Err(Error::InvalidState);
            }
            OutboundSessionState::Poisoned => {
                tracing::warn!(
                    target: LOG_TARGET,
                    "outbound session state has been poisoned"
                );
                debug_assert!(false);
                return Err(Error::InvalidState);
            }
        }
    }

    /// Handle `NextKey` block from remote.
    ///
    /// This is either a response to a `NextKey` block sent by the local router, either containing a
    /// reverse key or an ID of an existing key or it's a `NextKey` block for a new receive
    /// [`TagSet`], containing a new forward key, or an ID of an existing forward key.
    pub fn handle_next_key(&mut self, kind: NextKeyKind) {
        match kind {
            NextKeyKind::ForwardKey {
                key_id,
                public_key,
                reverse_key_requested,
            } => {
                todo!("forward keys not supported");
            }
            NextKeyKind::ReverseKey {
                key_id,
                mut public_key,
            } => {
                tracing::info!(?key_id, "handle reverse key");

                match mem::replace(&mut self.state, OutboundSessionState::Poisoned) {
                    OutboundSessionState::Active {
                        destination_id,
                        send_tag_set,
                        recv_tag_set,
                        mut pending_outbound_tagset,
                    } => {
                        tracing::info!(target: LOG_TARGET, "generate new outbound tagset");

                        let public_key = public_key.take().expect("key to exist");
                        let tagset = pending_outbound_tagset
                            .take()
                            .expect("to exist")
                            .into_tagset(public_key);

                        self.state = OutboundSessionState::Active {
                            destination_id,
                            send_tag_set: tagset,
                            recv_tag_set,
                            pending_outbound_tagset: None,
                        };
                    }
                    state => panic!("invalid state: {state:?}"),
                }
            }
        }
    }
}

/// Key context for an ECIES-X25519-AEAD-Ratchet session.
#[derive(Clone)]
pub struct KeyContext<R: Runtime> {
    /// Chaining key.
    chaining_key: Bytes,

    /// Inbound state.
    inbound_state: Bytes,

    /// Outbound state.
    outbound_state: Bytes,

    /// Static private key of the session.
    private_key: StaticPrivateKey,

    /// Static public key of the session.
    public_key: StaticPublicKey,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> KeyContext<R> {
    /// Create new [`NoiseContext`].
    ///
    /// https://geti2p.net/spec/ecies#f-kdfs-for-new-session-message
    pub fn new() -> Self {
        let chaining_key = Sha256::new().update(PROTOCOL_NAME.as_bytes()).finalize();

        // generate random static keypair for the session
        let private_key = StaticPrivateKey::new(&mut R::rng());
        let public_key = private_key.public();

        let outbound_state = Sha256::new().update(&chaining_key).finalize();
        let inbound_state =
            Sha256::new().update(&outbound_state).update(public_key.to_bytes()).finalize();

        Self {
            chaining_key: Bytes::from(chaining_key),
            inbound_state: Bytes::from(inbound_state),
            outbound_state: Bytes::from(outbound_state),
            private_key,
            public_key,
            _runtime: Default::default(),
        }
    }

    /// Generate private key which can be Elligator2-encoded.
    fn generate_ephemeral_keypair() -> ([u8; 32], u8) {
        let mut rng = R::rng();
        let tweak = rng.next_u32() as u8;

        loop {
            let mut private = [0u8; 32];
            rng.fill_bytes(&mut private);

            if Randomized::to_representative(&private, tweak).into_option().is_some() {
                return (private, tweak);
            }
        }
    }

    /// Create new outbound session.
    ///
    /// https://geti2p.net/spec/ecies#f-kdfs-for-new-session-message
    pub fn create_oubound_session(
        &mut self,
        destination_id: DestinationId,
        pubkey: StaticPublicKey,
        payload: &[u8],
    ) -> (OutboundSession<R>, Vec<u8>) {
        // generate new elligator2-encodable ephemeral keypair
        let (private_key, public_key, representative) = {
            let (private_key, tweak) = Self::generate_ephemeral_keypair();
            let sk = StaticPrivateKey::from(private_key.clone().to_vec());
            let public_key =
                StaticPublicKey::from(Randomized::mul_base_clamped(private_key).to_montgomery().0);

            // elligator2 conversion must succeed because `Self::generate_ephemeral_keypair()`
            // has ensured that the public key is encodable
            let representative =
                Randomized::to_representative(&private_key, tweak).expect("to succeed");

            (sk, public_key, representative)
        };

        let state = {
            let state = Sha256::new()
                .update(&self.outbound_state)
                .update::<&[u8]>(pubkey.as_ref())
                .finalize();

            Sha256::new().update(&state).update(&public_key).finalize()
        };

        // derive keys for encrypting initiator's static key
        let (chaining_key, static_key_ciphertext) = {
            let mut shared = private_key.diffie_hellman(&pubkey);
            let mut temp_key = Hmac::new(&self.chaining_key).update(&shared).finalize();
            let mut chaining_key = Hmac::new(&temp_key).update(&b"").update(&[0x01]).finalize();
            let mut cipher_key = Hmac::new(&temp_key)
                .update(&chaining_key)
                .update(&b"")
                .update(&[0x02])
                .finalize();

            // encrypt initiator's static public key
            //
            // `encrypt_with_ad()` must succeed as it's called with valid parameters
            let mut static_key = {
                let mut out = BytesMut::with_capacity(32 + 16);
                out.put_slice(&self.public_key.as_ref());

                out.freeze().to_vec()
            };

            ChaChaPoly::with_nonce(&cipher_key, 0u64)
                .encrypt_with_ad_new(&state, &mut static_key)
                .expect("to succeed");

            shared.zeroize();
            temp_key.zeroize();
            cipher_key.zeroize();

            (chaining_key, static_key)
        };

        // state for payload section
        let state = Sha256::new().update(&state).update(&static_key_ciphertext).finalize();

        // encrypt payload section
        let (chaining_key, payload_ciphertext) = {
            let shared = self.private_key.diffie_hellman(&pubkey);
            let mut temp_key = Hmac::new(&chaining_key).update(&shared).finalize();
            let mut chaining_key = Hmac::new(&temp_key).update(&b"").update(&[0x01]).finalize();
            let cipher_key = Hmac::new(&temp_key)
                .update(&chaining_key)
                .update(&b"")
                .update(&[0x02])
                .finalize();

            // create buffer with 16 extra bytes for poly1305 auth tag
            let mut payload = {
                let mut out = BytesMut::with_capacity(payload.len() + 16);
                out.put_slice(&payload);

                out.freeze().to_vec()
            };

            // `encrypt_with_ad()` must succeed as it's called with valid parameters
            ChaChaPoly::with_nonce(&cipher_key, 0u64)
                .encrypt_with_ad_new(&state, &mut payload)
                .expect("to succeed");

            (chaining_key, payload)
        };

        // state for new session reply kdf
        let state =
            Bytes::from(Sha256::new().update(&state).update(&payload_ciphertext).finalize());

        let payload = {
            let mut out = BytesMut::with_capacity(
                representative
                    .len()
                    .saturating_add(static_key_ciphertext.len())
                    .saturating_add(payload_ciphertext.len()),
            );
            out.put_slice(&representative);
            out.put_slice(&static_key_ciphertext);
            out.put_slice(&payload_ciphertext);

            out.freeze().to_vec()
        };

        (
            OutboundSession {
                state: OutboundSessionState::OutboundSessionPending {
                    state,
                    destination_id,
                    static_private_key: self.private_key.clone(),
                    ephemeral_private_key: private_key,
                    chaining_key,
                },
                _runtime: Default::default(),
            },
            payload,
        )
    }

    /// Create inbound session.
    ///
    /// https://geti2p.net/spec/ecies#f-kdfs-for-new-session-message
    pub fn create_inbound_session(&self, representative: [u8; 32]) {
        let new_pubkey = Randomized::from_representative(&representative).unwrap().to_montgomery();
        let public_key = StaticPublicKey::from(new_pubkey.0);

        let state = Sha256::new().update(&self.inbound_state).update(&public_key).finalize();
        let shared = self.private_key.diffie_hellman(&public_key);
    }

    /// Get static public key.
    pub fn public_key(&self) -> StaticPublicKey {
        self.public_key.clone()
    }
}
