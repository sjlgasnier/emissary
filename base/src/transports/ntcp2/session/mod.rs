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

use crate::{
    crypto::{sha256::Sha256, siphash::SipHash, StaticPrivateKey, StaticPublicKey},
    runtime::Runtime,
    transports::ntcp2::session::initiator::Initiator,
};

use zerocopy::{AsBytes, FromBytes, FromZeroes};

use alloc::vec::Vec;

pub use active::Session;

mod active;
mod initiator;
mod responder;

/// Noise protocol name;.
const PROTOCOL_NAME: &str = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256";

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
pub struct SessionManager {
    /// State that is common for all outbound connections.
    outbound_initial_state: Vec<u8>,

    /// State that is common for all inbound connections.
    // TODO: `bytes::Bytes`?
    inbound_initial_state: Vec<u8>,

    /// Chaining key.
    // TODO: `bytes::Bytes`?
    chaining_key: Vec<u8>,
}

impl SessionManager {
    /// Create new [`SessionManager`].
    ///
    /// This function initializes the common state for both inbound and outbound connections.
    ///
    /// See the beginning of [1] for steps on generating start state.
    ///
    /// [1]: https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-handshake-message-1
    pub fn new(local_static_key: StaticPublicKey) -> Self {
        // initial state
        let state = Sha256::new()
            .update(&PROTOCOL_NAME.as_bytes().to_vec())
            .finalize();

        // chaining key
        let chaining_key = state.clone();

        // MixHash (null prologue)
        let outbound_initial_state = Sha256::new().update(&state).finalize();

        // MixHash(rs)
        let inbound_initial_state = Sha256::new()
            .update(&outbound_initial_state)
            .update(local_static_key.to_vec())
            .finalize();

        Self {
            chaining_key,
            inbound_initial_state,
            outbound_initial_state,
        }
    }

    /// Create new [`Handshaker`] for initiator (Alice).
    ///
    /// Implements the key generation from [1], creates a `SessionRequest` message and returns
    /// that message together with an [`Initiator`] object which allows the call to drive progress
    /// on the opening connection.
    ///
    /// [1]: https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-handshake-message-1
    pub fn create_session<R: Runtime>(
        &self,
        local_info: Vec<u8>,
        local_static_key: StaticPrivateKey,
        remote_static_key: &StaticPublicKey,
        router_hash: Vec<u8>,
        iv: Vec<u8>,
    ) -> crate::Result<(Initiator, Vec<u8>)> {
        Initiator::new::<R>(
            self.outbound_initial_state.clone(),
            self.chaining_key.clone(),
            local_info,
            local_static_key,
            remote_static_key,
            router_hash,
            iv,
        )
    }

    /// Create new [`Handshaker`] for responder (Bob).
    pub fn new_responder(&self) -> Self {
        todo!()
    }
}
