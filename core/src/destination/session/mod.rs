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
    destination::session::session::{PendingSession, PendingSessionEvent, Session},
    error::Error,
    i2np::{
        database::store::{DatabaseStore, DatabaseStorePayload},
        garlic::{GarlicMessage, GarlicMessageBlock},
        Message, MessageType,
    },
    primitives::DestinationId,
    runtime::Runtime,
};

use bytes::Bytes;
use hashbrown::HashMap;
use inbound::InboundSession;

use core::marker::PhantomData;

mod context;
mod inbound;
mod message;
mod outbound;
mod session;
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
    /// Active sessions.
    active: HashMap<DestinationId, Session<R>>,

    /// Destination ID.
    destination_id: DestinationId,

    /// Mapping from garlic tags to session keys.
    garlic_tags: HashMap<u64, Bytes>,

    /// Key context.
    key_context: KeyContext<R>,

    /// Pending sessions.
    pending: HashMap<DestinationId, PendingSession<R>>,
}

impl<R: Runtime> SessionManager<R> {
    /// Create new [`SessionManager`].
    pub fn new(destination_id: DestinationId, private_key: StaticPrivateKey) -> Self {
        Self {
            active: HashMap::new(),
            destination_id,
            garlic_tags: HashMap::new(),
            key_context: KeyContext::from_private_key(private_key),
            pending: HashMap::new(),
        }
    }

    /// Encrypt `message` destined to `destination_id`.
    ///
    /// TODO: more documentation
    pub fn encrypt(
        &mut self,
        destination_id: &DestinationId,
        message: Vec<u8>,
    ) -> crate::Result<Vec<u8>> {
        match self.active.get_mut(destination_id) {
            Some(session) => todo!("handle active session"),
            None => match self.pending.get_mut(destination_id) {
                Some(session) => session
                    .advance_outbound(message)?
                    .filter_map(|event| match event {
                        PendingSessionEvent::StoreTags { tags } => {
                            self.garlic_tags.extend(tags.into_iter());
                            None
                        }
                        PendingSessionEvent::SendMessage { message } => Some(message),
                    })
                    .take(1)
                    .next()
                    .ok_or(Error::InvalidState),
                None => todo!("outbound sessions not supported"),
            },
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
    ///
    /// On success, returns a serialized garlic clove set.
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
                    id = %self.destination_id,
                    ?garlic_tag,
                    "session key not found, asssume new session",
                );

                // parse `NewSession` and attempt to create an inbound session
                //
                // the returned session is either a bound or an unbound inbound session
                //
                // if it's a bound session, the parsed garlic clove set must include a `LeaseSet2`
                // so a reply can be sent to the remote destination and if `LeaseSet2` is not
                // bundled, the inbound session is rejected
                let (session, payload) =
                    self.key_context.create_inbound_session(message.payload)?;

                // attempt to parse `payload` into clove set
                let clove_set = GarlicMessage::parse(&payload).ok_or_else(|| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        id = %self.destination_id,
                        "failed to parse `NewSession` payload into a clove set",
                    );

                    Error::InvalidData
                })?;

                // locate `DatabaseStore` i2np message from the clove set
                let Some(GarlicMessageBlock::GarlicClove { message_body, .. }) =
                    clove_set.blocks.iter().find(|clove| match clove {
                        GarlicMessageBlock::GarlicClove { message_type, .. }
                            if message_type == &MessageType::DatabaseStore =>
                            true,
                        _ => false,
                    })
                else {
                    tracing::warn!(
                        target: LOG_TARGET,
                        id = %self.destination_id,
                        "clove set doesn't contain `DatabaseStore`, cannot reply",
                    );

                    return Err(Error::InvalidData);
                };

                // attempt to parse the `DatabaseStore` as `LeaseSet2`
                let Some(DatabaseStore {
                    payload: DatabaseStorePayload::LeaseSet2 { leaseset },
                    ..
                }) = DatabaseStore::<R>::parse(&message_body)
                else {
                    tracing::warn!(
                        target: LOG_TARGET,
                        id = %self.destination_id,
                        "`DatabaseStore` is not a valid `LeaseSet2` store, cannot reply",
                    );

                    return Err(Error::InvalidData);
                };

                tracing::debug!(
                    target: LOG_TARGET,
                    id = %self.destination_id,
                    remote_id = %leaseset.header.destination.id(),
                    "inbound session created",
                );

                self.pending.insert(
                    leaseset.header.destination.id(),
                    PendingSession::new_inbound(
                        self.destination_id.clone(),
                        leaseset.header.destination.id(),
                        session,
                    ),
                );

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
    use crate::{
        i2np::{
            database::store::{DatabaseStoreBuilder, DatabaseStoreKind},
            garlic::{DeliveryInstructions as GarlicDeliveryInstructions, GarlicMessageBuilder},
        },
        primitives::{LeaseSet2, MessageId},
        runtime::mock::MockRuntime,
    };
    use bytes::{BufMut, BytesMut};
    use core::time::Duration;
    use rand::{thread_rng, RngCore};

    #[test]
    fn new_inbound_session() {
        crate::util::init_logger();

        let private_key = StaticPrivateKey::new(thread_rng());
        let public_key = private_key.public();
        let destination_id = DestinationId::from(vec![1, 2, 3, 4]);
        let mut session = SessionManager::<MockRuntime>::new(destination_id.clone(), private_key);

        let remote_private_key = StaticPrivateKey::new(thread_rng());
        let mut key_context = KeyContext::<MockRuntime>::from_private_key(remote_private_key);

        let (remote_leaseset, remote_signing_key) = LeaseSet2::random();
        let remote_destination_id = remote_leaseset.header.destination.id();

        let database_store = DatabaseStoreBuilder::new(
            Bytes::from(remote_leaseset.header.destination.id().to_vec()),
            DatabaseStoreKind::LeaseSet2 {
                leaseset: Bytes::from(remote_leaseset.serialize(&remote_signing_key)),
            },
        )
        .build();

        let mut payload = GarlicMessageBuilder::new()
            .with_date_time(MockRuntime::time_since_epoch().as_secs() as u32)
            .with_garlic_clove(
                MessageType::DatabaseStore,
                MessageId::from(MockRuntime::rng().next_u32()),
                (MockRuntime::time_since_epoch() + Duration::from_secs(10)).as_secs(),
                GarlicDeliveryInstructions::Local,
                &database_store,
            )
            .with_garlic_clove(
                MessageType::Data,
                MessageId::from(MockRuntime::rng().next_u32()),
                (MockRuntime::time_since_epoch() + Duration::from_secs(10)).as_secs(),
                GarlicDeliveryInstructions::Local,
                &{
                    let payload = vec![1, 2, 3, 4];
                    let mut out = BytesMut::with_capacity(payload.len() + 4);

                    out.put_u32(payload.len() as u32);
                    out.put_slice(&payload);

                    out.freeze().to_vec()
                },
            )
            .build();

        let (mut outbound_session, message) = {
            let (outbound, message) =
                key_context.create_oubound_session(destination_id, public_key, &payload);
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

        let payload = session.decrypt(message).unwrap();
        let clove_set = GarlicMessage::parse(&payload).unwrap();

        // verify message is valid
        {
            let Some(GarlicMessageBlock::GarlicClove { message_body, .. }) =
                clove_set.blocks.iter().find(|clove| match clove {
                    GarlicMessageBlock::GarlicClove { message_type, .. }
                        if message_type == &MessageType::Data =>
                        true,
                    _ => false,
                })
            else {
                panic!("message not found");
            };

            assert_eq!(&message_body[4..], &vec![1, 2, 3, 4]);
        }

        // verify pending inbound session exists for the destination
        assert!(session.pending.contains_key(&remote_destination_id));
        let message = {
            let payload = session.encrypt(&remote_destination_id, vec![1, 2, 3, 4]).unwrap();
            let mut out = BytesMut::with_capacity(payload.len() + 4);
            out.put_u32(payload.len() as u32);
            out.put_slice(&payload);

            Message {
                payload: out.freeze().to_vec(),
                ..Default::default()
            }
        };

        assert_eq!(
            outbound_session.decrypt_message(message).unwrap(),
            [1, 2, 3, 4]
        );

        let message = {
            let message = outbound_session.encrypt_message(vec![5, 6, 7, 8]).unwrap();

            let mut out = BytesMut::with_capacity(message.len() + 4);
            out.put_u32(message.len() as u32);
            out.put_slice(&message);

            Message {
                payload: out.freeze().to_vec(),
                ..Default::default()
            }
        };

        let _ = session.decrypt(message).unwrap();
    }

    #[test]
    fn messages_out_of_order() {
        todo!();
    }

    // TODO: remove or enable when anonymous datagrams work
    #[test]
    #[ignore]
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
