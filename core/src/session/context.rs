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
    runtime::Runtime,
};

use bytes::{BufMut, Bytes, BytesMut};
use curve25519_elligator2::{MapToPointVariant, MontgomeryPoint, Randomized};
use rand_core::RngCore;
use x25519_dalek::PublicKey;

use core::marker::PhantomData;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::session::context";

/// Noise protocol name.
const PROTOCOL_NAME: &str = "Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256";

/// Outbound session.
pub struct OutboundSession {
    /// AEAD state.
    state: Bytes,
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

        println!("inbound state: {inbound_state:?}");

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

        // encrypt payload section
        let payload_ciphertext = {
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

            payload
        };

        // state for new session reply kdf
        let state =
            Bytes::from(Sha256::new().update(&state).update(&payload_ciphertext).finalize());

        let payload = {
            let mut out = BytesMut::with_capacity(32 + 32 + 16 + 128 + 16);
            out.put_slice(&representative);
            out.put_slice(&static_key_ciphertext);
            out.put_slice(&payload_ciphertext);

            out.freeze().to_vec()
        };

        (OutboundSession { state }, payload)
    }

    /// Create inbound session.
    ///
    /// https://geti2p.net/spec/ecies#f-kdfs-for-new-session-message
    pub fn create_inbound_session(&self, representative: [u8; 32]) {
        let new_pubkey = Randomized::from_representative(&representative).unwrap().to_montgomery();
        let public_key = StaticPublicKey::from(new_pubkey.0);

        let state = Sha256::new().update(&self.inbound_state).update(&public_key).finalize();
        let shared = self.private_key.diffie_hellman(&public_key);

        println!("create_inbound_session(): state  {state:?}");
        println!("create_inbound_session(): shared {shared:?}");
    }
}

#[cfg(test)]
mod tests {}
