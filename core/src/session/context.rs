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
    crypto::{sha256::Sha256, StaticPrivateKey, StaticPublicKey},
    runtime::Runtime,
};

use bytes::Bytes;

use core::marker::PhantomData;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::session::context";

/// Noise protocol name.
const PROTOCOL_NAME: &str = "Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256";

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

    /// Create new outbound session.
    ///
    /// https://geti2p.net/spec/ecies#f-kdfs-for-new-session-message
    pub fn create_oubound_session(&self) {}

    /// Create inbound session.
    ///
    /// https://geti2p.net/spec/ecies#f-kdfs-for-new-session-message
    pub fn create_inbound_session(&self) {}
}
