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
    i2np::Message,
    runtime::Runtime,
    Error,
};

use bytes::{BufMut, Bytes, BytesMut};
use curve25519_elligator2::{MapToPointVariant, MontgomeryPoint, Randomized};
use rand_core::RngCore;
use x25519_dalek::PublicKey;

use alloc::vec::Vec;
use core::marker::PhantomData;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::session::context";

/// Noise protocol name.
const PROTOCOL_NAME: &str = "Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256";

/// Session tag entry.
pub struct TagSetEntry {
    /// Index.
    index: usize,

    /// Session tag.
    tag: Bytes,

    /// Session key.
    key: StaticPrivateKey,
}

/// Tag set.
///
/// https://geti2p.net/spec/ecies#sample-implementation
pub struct TagSet {}

impl TagSet {
    /// Create new [`TagSet`].
    pub fn new(key: StaticPrivateKey, num_tags: usize) -> Self {
        Self {}
    }

    /// Extend [`TagSet`] with `num_tags` many tags.
    pub fn extend(&mut self, num_tags: usize) {}

    /// Remove tags and keys that are too old.
    pub fn expire(&mut self) {}

    /// Calculate next session tag based on the previous session tag.
    pub fn ratchet_tag(&mut self) {}

    /// Calculate next session key based on the previouis session key.
    pub fn ratchet_key(&mut self) {}

    /// Get next [`TagSetEntry`].
    ///
    /// Returns `None` if all tags have been used.
    pub fn next_entry(&mut self) -> Option<TagSetEntry> {
        None
    }

    /// Get session key for for a session `tag`.
    pub fn session_key(&mut self, tag: Bytes) -> Option<StaticPrivateKey> {
        None
    }
}

/// Outbound session.
// TODO: pending outbound session
pub struct OutboundSession {
    /// AEAD state.
    pub state: Bytes,
    pub private_key: StaticPrivateKey,
    pub chaining_key: Vec<u8>,
}

impl OutboundSession {
    /// Handle `NewSessionReply` message.
    pub fn handle_new_session_reply(&mut self, message: Message) -> crate::Result<Vec<u8>> {
        let garlic_tag = message.payload[4..12].to_vec();
        let public_key = TryInto::<[u8; 32]>::try_into(&message.payload[12..44])
            .map_err(|_| Error::InvalidData)?;
        let mut ciphertext =
            TryInto::<[u8; 16]>::try_into(&message.payload[44..60]).unwrap().to_vec();
        let mut payload = message.payload[60..].to_vec();
        let new_pubkey =
            Randomized::from_representative(&public_key).unwrap().to_montgomery().to_bytes();
        let pubkey = StaticPublicKey::from(new_pubkey);
        let sk = StaticPrivateKey::from([0u8; 32]);

        let state = self.state.to_vec();

        let state = Sha256::new().update(&state).update(&garlic_tag).finalize();
        let state = Sha256::new().update(&state).update(&new_pubkey).finalize();

        let shared_secret = self.private_key.diffie_hellman(&pubkey);

        let mut temp_key = Hmac::new(&self.chaining_key).update(&shared_secret).finalize();
        let mut chaining_key = Hmac::new(&temp_key).update(&b"").update(&[0x01]).finalize();

        let shared = sk.diffie_hellman(&pubkey);

        let mut temp_key = Hmac::new(&chaining_key).update(&shared).finalize();
        let mut chaining_key = Hmac::new(&temp_key).update(&b"").update(&[0x01]).finalize();
        let keydata = Hmac::new(&temp_key)
            .update(&chaining_key)
            .update(&b"")
            .update(&[0x02])
            .finalize();
        let new_state = Sha256::new().update(&state).update(&ciphertext).finalize();

        ChaChaPoly::new(&keydata).decrypt_with_ad(&state, &mut ciphertext)?;

        let state = new_state;

        // split
        let temp_key = Hmac::new(&chaining_key).update(&[]).finalize();
        let send_key = Hmac::new(&temp_key).update(&[0x01]).finalize();
        let recv_key = Hmac::new(&temp_key).update(&send_key).update(&[0x02]).finalize();

        // TODO: `DH_INITIALIZE` send keys
        // TODO: `DH_INITIALIZE` recv keys

        let mut temp_key = Hmac::new(&recv_key).update(&[]).finalize();
        let mut payload_key =
            Hmac::new(&temp_key).update(&b"AttachPayloadKDF").update(&[0x01]).finalize();

        ChaChaPoly::new(&payload_key).decrypt_with_ad(&state, &mut payload)?;

        Ok(payload)
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
        // TODO: generate actually random key
        let private_key = StaticPrivateKey::from([0u8; 32]);
        // let private_key = StaticPrivateKey::new(&mut R::rng());
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
        pubkey: StaticPublicKey,
        payload: &[u8],
    ) -> (OutboundSession, Vec<u8>) {
        let (private_key, tweak) = Self::generate_ephemeral_keypair();
        let sk = StaticPrivateKey::from(private_key.clone().to_vec());
        let public_key =
            StaticPublicKey::from(Randomized::mul_base_clamped(private_key).to_montgomery().0);

        let state = Sha256::new()
            .update(&self.outbound_state)
            .update::<&[u8]>(pubkey.as_ref())
            .finalize();

        let state = Sha256::new().update(&state).update(&public_key).finalize();
        let shared = sk.diffie_hellman(&pubkey);

        let representative = Randomized::to_representative(&private_key, tweak).unwrap();

        // derive keys for encrypting initiator's static key
        let (chaining_key, static_key_ciphertext) = {
            let mut temp_key = Hmac::new(&self.chaining_key).update(&shared).finalize();
            let mut chaining_key = Hmac::new(&temp_key).update(&b"").update(&[0x01]).finalize();
            let cipher_key = Hmac::new(&temp_key)
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

            ChaChaPoly::with_nonce(&cipher_key, 0)
                .encrypt_with_ad_new(&state, &mut static_key)
                .expect("to succeed");

            (chaining_key, static_key)
        };

        // state for payload section
        let state = Sha256::new().update(&state).update(&static_key_ciphertext).finalize();

        tracing::error!("first chaining key = {chaining_key:?}");

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
            //
            // TODO: optimize?
            let mut payload = {
                let mut out = BytesMut::with_capacity(payload.len() + 16);
                out.put_slice(&payload);

                out.freeze().to_vec()
            };

            // `encrypt_with_ad()` must succeed as it's called with valid parameters
            ChaChaPoly::with_nonce(&cipher_key, 0)
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

        // tagset key
        let mut temp_key = Hmac::new(&chaining_key).update(&[]).finalize();
        let tagset_key =
            Hmac::new(&temp_key).update(&b"SessionReplyTags").update(&[0x01]).finalize();

        // DH_INITIALIZE (chaining key, tagset key)
        let mut temp_key = Hmac::new(&chaining_key).update(&tagset_key).finalize();
        let next_root_key =
            Hmac::new(&temp_key).update(&b"KDFDHRatchetStep").update(&[0x01]).finalize();
        let ratchet_key = Hmac::new(&temp_key)
            .update(&next_root_key)
            .update(&b"KDFDHRatchetStep")
            .update(&[0x02])
            .finalize();

        let mut temp_key = Hmac::new(&ratchet_key).update(&[]).finalize();
        let session_tag_ck =
            Hmac::new(&temp_key).update(&b"TagAndKeyGenKeys").update(&[0x01]).finalize();
        let symmetric_key_ck = Hmac::new(&temp_key)
            .update(&session_tag_ck)
            .update(&b"TagAndKeyGenKeys")
            .update(&[0x02])
            .finalize();

        let mut temp_key = Hmac::new(&session_tag_ck).update(&[]).finalize();
        let session_key_data =
            Hmac::new(&temp_key).update(&b"STInitialization").update(&[0x01]).finalize();
        let session_tag_constant = Hmac::new(&temp_key)
            .update(&session_key_data)
            .update(&b"STInitialization")
            .update(&[0x02])
            .finalize();

        tracing::error!("chaining key = {chaining_key:?}");

        (
            OutboundSession {
                state,
                private_key: sk,
                chaining_key,
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
}

#[cfg(test)]
mod tests {}
