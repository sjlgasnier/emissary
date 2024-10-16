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

//! Inbound ECIES-X25519-AEAD-Ratchet session implementation.

use crate::{
    crypto::{
        chachapoly::ChaChaPoly, hmac::Hmac, sha256::Sha256, StaticPrivateKey, StaticPublicKey,
    },
    destination::session::{
        session::PendingSessionEvent,
        tagset::{TagSet, TagSetEntry},
        KeyContext,
    },
    error::Error,
    runtime::Runtime,
};

use bytes::{BufMut, Bytes, BytesMut};
use curve25519_elligator2::{MapToPointVariant, MontgomeryPoint, Randomized};
use zeroize::Zeroize;

use core::{fmt, iter, marker::PhantomData, mem};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::destination::session::inbound";

/// Number of garlic tags to generate.
const NUM_TAGS_TO_GENERATE: usize = 128;

/// State of the inbound session.
enum InboundSessionState {
    /// Inbound session is awaiting `NewSesionReply` to be sent.
    ///
    /// `SessionManager` waits for a while for the upper protocol layer to process the payload
    /// received in `NewSession` message in case the upper layer reply generates a reply for the
    /// received message.
    ///
    /// If no reply is received within a certain time window, `NewSessionReply` is sent without
    /// payload.
    AwaitingNewSessionReplyTransmit {
        /// Chaining key.
        chaining_key: Vec<u8>,

        /// State for `NewSessionReply` KDF.
        state: Vec<u8>,

        /// Ephemeral public key of remote destination.
        remote_ephemeral_public_key: StaticPublicKey,

        /// Static public key of remote destination.
        remote_static_public_key: StaticPublicKey,
    },

    /// `NewSessionReply` has been sent.
    ///
    /// [`InboundSession`] is waiting for `ExistingSession` message to be received before the
    /// session is considered active.
    NewSessionReplySent {
        /// `TagSet` for encrypting outbound messages.
        send_tag_set: TagSet,

        /// `TagSet` for decrypting inbound messages.
        recv_tag_set: TagSet,
    },

    /// Inbound session state has been poisoned.
    Poisoned,
}

impl fmt::Debug for InboundSessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AwaitingNewSessionReplyTransmit { .. } => f
                .debug_struct("InboundSessionState::AwaitingNewSessionReplyTransmit ")
                .finish_non_exhaustive(),
            Self::NewSessionReplySent { .. } => f
                .debug_struct("InboundSessionState::NewSessionReplySent ")
                .finish_non_exhaustive(),
            Self::Poisoned =>
                f.debug_struct("InboundSessionState::Poisoned ").finish_non_exhaustive(),
        }
    }
}

/// Inbound session.
pub struct InboundSession<R: Runtime> {
    /// Static private key of the session.
    private_key: StaticPrivateKey,

    /// State of the inbound session.
    state: InboundSessionState,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> InboundSession<R> {
    /// Create new [`InboundSession`].
    pub fn new(
        private_key: StaticPrivateKey,
        remote_static_public_key: StaticPublicKey,
        remote_ephemeral_public_key: StaticPublicKey,
        chaining_key: Vec<u8>,
        state: Vec<u8>,
    ) -> Self {
        Self {
            private_key,
            state: InboundSessionState::AwaitingNewSessionReplyTransmit {
                chaining_key,
                remote_static_public_key,
                remote_ephemeral_public_key,
                state,
            },
            _runtime: Default::default(),
        }
    }

    /// Create `NewSessionReply`.
    ///
    /// TODO: documentation
    pub fn create_new_session_reply(
        &mut self,
        mut payload: Vec<u8>,
    ) -> crate::Result<(Vec<u8>, Vec<TagSetEntry>)> {
        match mem::replace(&mut self.state, InboundSessionState::Poisoned) {
            InboundSessionState::AwaitingNewSessionReplyTransmit {
                chaining_key,
                remote_ephemeral_public_key,
                remote_static_public_key,
                state,
            } => {
                // generate new elligator2-encodable ephemeral keypair
                let (ephemeral_private_key, ephemeral_public_key, representative) = {
                    let (ephemeral_private_key, tweak) =
                        KeyContext::<R>::generate_ephemeral_keypair();
                    let sk = StaticPrivateKey::from(ephemeral_private_key.clone().to_vec());
                    let ephemeral_public_key = StaticPublicKey::from(
                        Randomized::mul_base_clamped(ephemeral_private_key).to_montgomery().0,
                    );

                    // conversion must succeed as `KeyContext::generate_ephemeral_keypair()`
                    // has ensured that the public key is encodable
                    let representative =
                        Randomized::to_representative(&ephemeral_private_key, tweak)
                            .expect("to succeed");

                    (sk, ephemeral_public_key, representative)
                };

                // create garlic tag for the `NewSessionReply` message
                let garlic_tag = {
                    let mut temp_key = Hmac::new(&chaining_key).update(&[]).finalize();
                    let mut tagset_key = Hmac::new(&temp_key)
                        .update(&b"SessionReplyTags")
                        .update(&[0x01])
                        .finalize();
                    let mut nsr_tag_set = TagSet::new(0u16, &chaining_key, tagset_key);

                    // `next_entry()` must succeed as `nsr_tag_set` is a fresh `TagSet`
                    nsr_tag_set.next_entry().expect("to succeed").tag
                };

                // calculate keys from shared secrets derived from ee & es
                let (chaining_key, keydata) = {
                    // ephemeral-ephemeral
                    let mut shared =
                        ephemeral_private_key.diffie_hellman(&remote_ephemeral_public_key);
                    let mut temp_key = Hmac::new(&chaining_key).update(&shared).finalize();
                    let mut chaining_key =
                        Hmac::new(&temp_key).update(&b"").update(&[0x01]).finalize();

                    // static-ephemeral
                    shared = ephemeral_private_key.diffie_hellman(&remote_static_public_key);
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

                // calculate new state encrypting the empty key section
                let state = {
                    let state =
                        Sha256::new().update(&state).update(&garlic_tag.to_le_bytes()).finalize();

                    Sha256::new()
                        .update(&state)
                        .update::<&[u8]>(ephemeral_public_key.as_ref())
                        .finalize()
                };
                let mac = ChaChaPoly::new(&keydata).encrypt_with_ad(&state, &mut vec![])?;

                // include `mac` into state for payload section's encryption
                let state = Sha256::new().update(&state).update(&mac).finalize();

                // split key into send and receive keys
                let mut temp_key = Hmac::new(&chaining_key).update(&[]).finalize();
                let mut recv_key = Hmac::new(&temp_key).update(&[0x01]).finalize();
                let mut send_key =
                    Hmac::new(&temp_key).update(&recv_key).update(&[0x02]).finalize();

                // initialize send and receive tag sets
                let mut send_tag_set = TagSet::new(0u16, &chaining_key, &send_key);
                let mut recv_tag_set = TagSet::new(0u16, chaining_key, recv_key);

                // decode payload of the `NewSessionReply` message
                let mut temp_key = Hmac::new(&send_key).update(&[]).finalize();
                let mut payload_key =
                    Hmac::new(&temp_key).update(&b"AttachPayloadKDF").update(&[0x01]).finalize();

                ChaChaPoly::new(&payload_key).encrypt_with_ad_new(&state, &mut payload)?;

                let payload = {
                    let mut out = BytesMut::with_capacity(
                        representative
                            .len()
                            .saturating_add(8) // garlic tag
                            .saturating_add(mac.len())
                            .saturating_add(payload.len()),
                    );
                    out.put_slice(&garlic_tag.to_le_bytes());
                    out.put_slice(&representative);
                    out.put_slice(&mac);
                    out.put_slice(&payload);

                    out.freeze().to_vec()
                };

                // generate garlic tag/session key pairs for reception
                //
                // `next_entry()` must succeed as this is a fresh tagset and `NUM_TAGS_TO_GENERATE`
                // is smaller than the maximum tag count in a `Tagset`
                let tags = (0..NUM_TAGS_TO_GENERATE)
                    .map(|_| recv_tag_set.next_entry().expect("to succeed"))
                    .collect::<Vec<_>>();

                self.state = InboundSessionState::NewSessionReplySent {
                    send_tag_set,
                    recv_tag_set,
                };

                Ok((payload, tags))
            }
            state => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?state,
                    "invalid state for `NewSessionReply` message",
                );
                debug_assert!(false);
                Err(Error::InvalidState)
            }
        }
    }

    /// Handle `ExistingSession` message.
    ///
    /// Decrypt `message` using `session_key` and return the decrypted payload and the inner state
    /// of `InboundSession`, allowing the caller to create a new `Session` object which contains
    /// both send and receive `TagSet`s.
    pub fn handle_existing_session(
        &mut self,
        tag_set_entry: TagSetEntry,
        mut payload: Vec<u8>,
    ) -> crate::Result<(Vec<u8>, TagSet, TagSet)> {
        let InboundSessionState::NewSessionReplySent {
            send_tag_set,
            recv_tag_set,
        } = mem::replace(&mut self.state, InboundSessionState::Poisoned)
        else {
            tracing::warn!(
                target: LOG_TARGET,
                "invalid state for `ExistingSession` message",
            );
            debug_assert!(false);
            return Err(Error::InvalidState);
        };

        let mut payload = payload[12..].to_vec();

        ChaChaPoly::with_nonce(&tag_set_entry.key, tag_set_entry.index as u64)
            .decrypt_with_ad(&tag_set_entry.tag.to_le_bytes(), &mut payload)?;

        Ok((payload, send_tag_set, recv_tag_set))
    }
}
