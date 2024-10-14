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

use crate::{crypto::StaticPrivateKey, runtime::Runtime};

use core::marker::PhantomData;

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
    },
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
    pub fn new(private_key: StaticPrivateKey, chaining_key: Vec<u8>, state: Vec<u8>) -> Self {
        Self {
            private_key,
            state: InboundSessionState::AwaitingNewSessionReplyTransmit {
                chaining_key,
                state,
            },
            _runtime: Default::default(),
        }
    }
}
