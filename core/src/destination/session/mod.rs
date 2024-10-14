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
    i2np::{garlic::GarlicMessage, Message, MessageType},
    primitives::DestinationId,
    runtime::Runtime,
};

use bytes::Bytes;
use hashbrown::HashMap;

use core::marker::PhantomData;

mod context;
mod inbound;
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

    /// Mapping from garlic tags to session keys.
    garlic_tags: HashMap<u64, Bytes>,

    /// Key context.
    key_context: KeyContext<R>,
}

impl<R: Runtime> SessionManager<R> {
    /// Create new [`SessionManager`].
    pub fn new(destination_id: DestinationId, private_key: StaticPrivateKey) -> Self {
        Self {
            destination_id,
            garlic_tags: HashMap::new(),
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
    ///
    /// [`SessionManager::decrypt()`] assumes that the caller has validated `message` to be a garlic
    /// message of appropriate length, containing at least the message length and a garlic tag.
    pub fn decrypt(&mut self, message: Message) -> crate::Result<Vec<u8>> {
        // extract garlic tag and attempt to find session key for the tag
        //
        // if no key is found, `message` is assumed to be `NewSession`
        let garlic_tag = GarlicMessage::garlic_tag(&message);

        tracing::trace!(
            target: LOG_TARGET,
            id = %self.destination_id,
            message_id = ?message.message_id,
            ?garlic_tag,
            "garlic message",
        );

        match self.garlic_tags.remove(&garlic_tag) {
            None => {
                tracing::trace!(
                    target: LOG_TARGET,
                    ?garlic_tag,
                    "session key not found, asssume new session",
                );

                let (_session, payload) =
                    self.key_context.create_inbound_session(message.payload)?;

                Ok(payload)
            }
            Some(_) => {
                tracing::trace!(
                    target: LOG_TARGET,
                    ?garlic_tag,
                    "garlic tag found"
                );

                todo!();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;
    use bytes::{BufMut, BytesMut};
    use core::time::Duration;
    use rand::{thread_rng, RngCore};

    #[test]
    fn new_inbound_session() {
        let private_key = StaticPrivateKey::new(thread_rng());
        let public_key = private_key.public();
        let destination_id = DestinationId::from(vec![1, 2, 3, 4]);
        let mut session = SessionManager::<MockRuntime>::new(destination_id.clone(), private_key);

        let remote_private_key = StaticPrivateKey::new(thread_rng());
        let mut key_context = KeyContext::<MockRuntime>::from_private_key(remote_private_key);

        let (outbound_session, message) = {
            let (outbound, message) =
                key_context.create_oubound_session(destination_id, public_key, &[1, 2, 3, 4]);
            let mut payload = BytesMut::with_capacity(message.len() + 4);
            payload.put_u32(message.len() as u32);
            payload.put_slice(&message);

            (
                outbound,
                Message {
                    message_type: MessageType::Garlic,
                    message_id: thread_rng().next_u32(),
                    expiration: Duration::from_secs(1337),
                    payload: payload.freeze().to_vec(),
                },
            )
        };

        assert_eq!(session.decrypt(message).unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn new_inbound_session_empty_payload() {
        let private_key = StaticPrivateKey::new(thread_rng());
        let public_key = private_key.public();
        let destination_id = DestinationId::from(vec![1, 2, 3, 4]);
        let mut session = SessionManager::<MockRuntime>::new(destination_id.clone(), private_key);

        let remote_private_key = StaticPrivateKey::new(thread_rng());
        let mut key_context = KeyContext::<MockRuntime>::from_private_key(remote_private_key);

        let (outbound_session, message) = {
            let (outbound, message) =
                key_context.create_oubound_session(destination_id, public_key, &[]);
            let mut payload = BytesMut::with_capacity(message.len() + 4);
            payload.put_u32(message.len() as u32);
            payload.put_slice(&message);

            (
                outbound,
                Message {
                    message_type: MessageType::Garlic,
                    message_id: thread_rng().next_u32(),
                    expiration: Duration::from_secs(1337),
                    payload: payload.freeze().to_vec(),
                },
            )
        };

        assert_eq!(session.decrypt(message).unwrap(), vec![]);
    }
}
