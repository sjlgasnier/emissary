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

//! ECIES-X25519-AEAD-Ratchet implementation.
//!
//! https://geti2p.net/spec/ecies

use crate::{
    crypto::StaticPrivateKey,
    i2np::{Message, MessageType},
    primitives::DestinationId,
    runtime::Runtime,
};

use core::marker::PhantomData;

mod context;
mod message;
mod outbound;
mod tagset;

// TODO: remove re-exports
pub use context::KeyContext;
pub use outbound::OutboundSession;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::destination::session";

/// Session manager for a `Destination`.
///
/// Handles both inbound and outbound sessions.
pub struct SessionManager<R: Runtime> {
    /// Destination ID.
    destination_id: DestinationId,

    /// Key context.
    key_context: KeyContext<R>,
}

impl<R: Runtime> SessionManager<R> {
    /// Create new [`SessionManager`].
    pub fn new(destination_id: DestinationId, private_key: StaticPrivateKey) -> Self {
        Self {
            destination_id,
            key_context: KeyContext::from_private_key(private_key),
        }
    }

    /// Decrypt `message`.
    ///
    /// `message` could be one of three types of messages:
    ///  * `NewSession` - session request from a remote destination
    ///  * `NewSessionReply` - reply for a session request initiated by us
    ///  * `ExistingSession` - message belonging to an existing session
    ///
    /// All messages kinds can be received from any remote destination, the only common factor
    /// between them is that the recipient is `Destination` this `SessionManager` is bound to.
    pub fn decrypt(&mut self, message: Message) -> crate::Result<()> {
        tracing::trace!(
            target: LOG_TARGET,
            id = %self.destination_id,
            message_id = ?message.message_id,
            "garlic message",
        );
        debug_assert_eq!(message.message_type, MessageType::Garlic);

        Ok(())
    }
}
