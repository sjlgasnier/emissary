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

//! Outbound ECIES-X25519-AEAD-Ratchet session implementation.

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
use core::{
    fmt,
    marker::PhantomData,
    mem,
    ops::{Range, RangeFrom},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::destination::session::outbound";

/// Number of tags to generate for `NewSessionReply`.
const NSR_TAG_COUNT: usize = 16usize;

/// Minimum length for `NewSessionReply` message.
const NSR_MINIMUM_LEN: usize = 60usize;

/// Ephemeral public key offset in `NewSessionReply` message.
const NSR_EPHEMERAL_PUBKEY_OFFSET: Range<usize> = 12..44;

/// Poly1305 MAC offset in `NewSessionReply` message.
const NSR_POLY1305_MAC_OFFSET: Range<usize> = 44..60;

/// Payload offset in `NewSessionReply` message.
const NSR_PAYLOAD_OFFSET: RangeFrom<usize> = 60..;

/// Outbound session state.
pub enum OutboundSessionState {
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
    pub state: OutboundSessionState,

    /// Marker for `Runtime`.
    pub _runtime: PhantomData<R>,
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
                    .encrypt_with_ad(&tag.to_le_bytes(), &mut message)?;

                out.put_slice(&tag.to_le_bytes());
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
                    .decrypt_with_ad(&tag.to_le_bytes(), &mut payload)
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

    /// Generate garlic tags for the incoming `NewSessionReply`
    ///
    /// This function can only be called once, after the outbound session has been initialized and
    /// its state is `OutboundSessionPending`, for other states the call will panic.
    pub fn generate_new_session_reply_tags(&self) -> impl Iterator<Item = TagSetEntry> {
        let OutboundSessionState::OutboundSessionPending { chaining_key, .. } = &self.state else {
            unreachable!();
        };

        let mut temp_key = Hmac::new(&chaining_key).update(&[]).finalize();
        let mut tagset_key =
            Hmac::new(&temp_key).update(&b"SessionReplyTags").update(&[0x01]).finalize();

        let mut nsr_tag_set = TagSet::new(0u16, &chaining_key, tagset_key);

        (0..NSR_TAG_COUNT).map(move |_| nsr_tag_set.next_entry().expect("to succeed"))
    }

    /// Handle `NewSessionReply` from remote destination.
    ///
    /// Decrypt `message` using `tag_set_entry`, derive send and receive tag sets
    /// and return the parsed inner payload of `message`.
    ///
    /// Session is considered active after this function has returned successfully.
    ///
    /// https://geti2p.net/spec/ecies#kdf-for-flags-static-key-section-encrypted-contents
    pub fn handle_new_session_reply(
        &mut self,
        tag_set_entry: TagSetEntry,
        message: Vec<u8>,
    ) -> crate::Result<(Vec<u8>, TagSet, TagSet)> {
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
                if message.len() < NSR_MINIMUM_LEN {
                    tracing::warn!(
                        target: LOG_TARGET,
                        payload_len = ?message.len(),
                        "`NewSessionReply` is too short",
                    );
                    debug_assert!(false);

                    return Err(Error::InvalidData);
                }

                // extract and decode elligator2-encoded public key of the remote destination
                let public_key = {
                    // conversion must succeed since the provided range is correct and
                    // the payload has been confirmed to be large enough to hold the public key
                    let public_key =
                        TryInto::<[u8; 32]>::try_into(&message[NSR_EPHEMERAL_PUBKEY_OFFSET])
                            .expect("to succeed");
                    let new_pubkey = Randomized::from_representative(&public_key)
                        .unwrap()
                        .to_montgomery()
                        .to_bytes();

                    StaticPublicKey::from(new_pubkey)
                };

                // poly1305 mac for the key section (empty payload)
                let mut ciphertext = message[NSR_POLY1305_MAC_OFFSET].to_vec();

                // payload section of the `NewSessionReply`
                let mut payload = message[NSR_PAYLOAD_OFFSET].to_vec();

                // calculate new state with garlic tag & remote's ephemeral public key
                let state = {
                    let state = Sha256::new()
                        .update(&state)
                        .update(&tag_set_entry.tag.to_le_bytes())
                        .finalize();

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

                Ok((payload, send_tag_set, recv_tag_set))
            }
            state => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?state,
                    "invalid state for `NewSessionReply`"
                );
                debug_assert!(false);
                return Err(Error::InvalidState);
            }
        }
    }
}
