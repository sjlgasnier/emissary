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
    crypto::{StaticPrivateKey, StaticPublicKey},
    destination::session::session::{PendingSession, PendingSessionEvent, Session},
    error::Error,
    i2np::{
        database::store::{
            DatabaseStore, DatabaseStoreBuilder, DatabaseStoreKind, DatabaseStorePayload,
        },
        garlic::{
            DeliveryInstructions as GarlicDeliveryInstructions, GarlicMessage, GarlicMessageBlock,
            GarlicMessageBuilder,
        },
        Message, MessageType,
    },
    primitives::{DestinationId, LeaseSet2, MessageId},
    runtime::Runtime,
};

use bytes::{BufMut, Bytes, BytesMut};
use hashbrown::HashMap;
use inbound::InboundSession;
use rand_core::RngCore;

#[cfg(feature = "std")]
use parking_lot::RwLock;
#[cfg(feature = "no_std")]
use spin::rwlock::RwLock;

use alloc::sync::Arc;
use core::{marker::PhantomData, time::Duration};

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

/// Number of garlic tags to generate.
const NUM_TAGS_TO_GENERATE: usize = 128;

/// Session manager for a `Destination`.
///
/// Handles both inbound and outbound sessions.
pub struct SessionManager<R: Runtime> {
    /// Active sessions.
    active: HashMap<DestinationId, Session<R>>,

    /// Destination ID.
    destination_id: DestinationId,

    /// Mapping from garlic tags to session keys.
    garlic_tags: Arc<RwLock<HashMap<u64, DestinationId>>>,

    /// Key context.
    key_context: KeyContext<R>,

    /// Currently active, serialized `LeaseSet2` of the local destination.
    leaseset: Bytes,

    /// Known remote destinations and their public keys.
    remote_destinations: HashMap<DestinationId, StaticPublicKey>,

    /// Pending sessions.
    pending: HashMap<DestinationId, PendingSession<R>>,
}

impl<R: Runtime> SessionManager<R> {
    /// Create new [`SessionManager`].
    pub fn new(
        destination_id: DestinationId,
        private_key: StaticPrivateKey,
        leaseset: Bytes,
    ) -> Self {
        Self {
            leaseset,
            active: HashMap::new(),
            destination_id,
            garlic_tags: Default::default(),
            key_context: KeyContext::from_private_key(private_key),
            remote_destinations: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// Set new `LeaseSet2` for the local destination.
    pub fn set_local_leaseset(&mut self, leaseset: Bytes) {
        self.leaseset = leaseset;
    }

    /// Add remote destination to [`SessionManager`].
    ///
    /// Public key of the remote destination is fetched from its `LeaseSet2`.
    ///
    /// Calling `SessionManager::encrypt()` presupposes that the public key of remote destination
    /// has been added to [`SessionManager`], otherwise the call will fail.
    pub fn add_remote_destination(
        &mut self,
        destination_id: DestinationId,
        public_key: StaticPublicKey,
    ) {
        self.remote_destinations.insert(destination_id, public_key);
    }

    /// Remove remote destination from [`SessionKeyManager`].
    pub fn remote_remote_destination(&mut self, destination_id: &DestinationId) {
        self.remote_destinations.remove(destination_id);
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
            Some(session) => session.encrypt(message),
            None => match self.pending.get_mut(destination_id) {
                Some(session) => match session.advance_outbound(message)? {
                    PendingSessionEvent::SendMessage { message } => Ok(message),
                    PendingSessionEvent::CreateSession { message, context } => todo!(),
                },
                None => {
                    // public key of the destination should exist since the caller (`Destination`)
                    // should've queried the lease set of the remote destination when sending the
                    // first message to them
                    let public_key =
                        self.remote_destinations.get(destination_id).ok_or_else(|| {
                            tracing::warn!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                remote = %destination_id,
                                "public key for remote destination doesn't exist",
                            );

                            debug_assert!(false);
                            Error::InvalidState
                        })?;

                    // create garlic message for establishing a new session
                    //
                    // the message consists of three parts
                    //  * date time block
                    //  * bundled leaseset
                    //  * garlic clove for upper-level protocol data
                    //
                    // this garlic message is wrapped inside a `NewSession` message
                    // and sent to remote
                    let database_store = DatabaseStoreBuilder::new(
                        Bytes::from(self.destination_id.to_vec()),
                        DatabaseStoreKind::LeaseSet2 {
                            leaseset: Bytes::from(self.leaseset.clone()),
                        },
                    )
                    .build();

                    let mut payload = GarlicMessageBuilder::new()
                        .with_date_time(R::time_since_epoch().as_secs() as u32)
                        .with_garlic_clove(
                            MessageType::DatabaseStore,
                            MessageId::from(R::rng().next_u32()),
                            (R::time_since_epoch() + Duration::from_secs(10)).as_secs(),
                            GarlicDeliveryInstructions::Local,
                            &database_store,
                        )
                        .with_garlic_clove(
                            MessageType::Data,
                            MessageId::from(R::rng().next_u32()),
                            (R::time_since_epoch() + Duration::from_secs(10)).as_secs(),
                            GarlicDeliveryInstructions::Local,
                            &{
                                let mut out = BytesMut::with_capacity(message.len() + 4);

                                out.put_u32(message.len() as u32);
                                out.put_slice(&message);

                                out.freeze().to_vec()
                            },
                        )
                        .build();

                    // wrap the garlic message inside a `NewSession` message
                    // and create a pending outbound session
                    let (session, payload) = self.key_context.create_outbound_session(
                        destination_id.clone(),
                        &public_key,
                        &payload,
                    );

                    self.pending.insert(
                        destination_id.clone(),
                        PendingSession::new_outbound(
                            self.destination_id.clone(),
                            destination_id.clone(),
                            session,
                            Arc::clone(&self.garlic_tags),
                        ),
                    );

                    Ok(payload)
                }
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
        let session = { self.garlic_tags.write().remove(&garlic_tag) };

        tracing::trace!(
            target: LOG_TARGET,
            local = %self.destination_id,
            message_id = ?message.message_id,
            ?garlic_tag,
            "garlic message",
        );

        match session {
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
                    local = %self.destination_id,
                    remote = %leaseset.header.destination.id(),
                    "inbound session created",
                );

                self.pending.insert(
                    leaseset.header.destination.id(),
                    PendingSession::new_inbound(
                        self.destination_id.clone(),
                        leaseset.header.destination.id(),
                        session,
                        Arc::clone(&self.garlic_tags),
                    ),
                );

                Ok(payload)
            }
            Some(destination_id) => match self.active.get_mut(&destination_id) {
                Some(session) => session.decrypt(garlic_tag, message.payload),
                None => match self.pending.get_mut(&destination_id) {
                    Some(session) => match session.advance_inbound(garlic_tag, message.payload)? {
                        PendingSessionEvent::SendMessage { message } => todo!(),
                        PendingSessionEvent::CreateSession { message, context } => {
                            tracing::info!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                remote = %destination_id,
                                "new session started",
                            );

                            self.pending.remove(&destination_id);
                            self.active.insert(destination_id, Session::new(context));

                            Ok(message)
                        }
                    },
                    None => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            remote = %destination_id,
                            ?garlic_tag,
                            "destination for garlic tag doesn't exist",
                        );
                        debug_assert!(false);
                        Err(Error::InvalidState)
                    }
                },
            },
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
        let private_key = StaticPrivateKey::new(thread_rng());
        let public_key = private_key.public();
        let destination_id = DestinationId::from(vec![1, 2, 3, 4]);
        let (leaseset, signing_key) = LeaseSet2::random();
        let leaseset = Bytes::from(leaseset.serialize(&signing_key));
        let mut session =
            SessionManager::<MockRuntime>::new(destination_id.clone(), private_key, leaseset);

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
                key_context.create_outbound_session(destination_id, &public_key, &payload);
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

        let message = session.decrypt(message).unwrap();
        assert_eq!(message, [5, 6, 7, 8]);
    }

    #[test]
    fn messages_out_of_order() {
        let private_key = StaticPrivateKey::new(thread_rng());
        let public_key = private_key.public();
        let destination_id = DestinationId::from(vec![1, 2, 3, 4]);
        let (leaseset, signing_key) = LeaseSet2::random();
        let leaseset = Bytes::from(leaseset.serialize(&signing_key));
        let mut session =
            SessionManager::<MockRuntime>::new(destination_id.clone(), private_key, leaseset);

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
                key_context.create_outbound_session(destination_id, &public_key, &payload);
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

        // verify pending inbound session still exists for the destination
        assert!(session.pending.contains_key(&remote_destination_id));

        let message = session.decrypt(message).unwrap();
        assert_eq!(message, [5, 6, 7, 8]);

        // verify that the inbound session is now considered active
        assert!(session.active.contains_key(&remote_destination_id));
        assert!(session.pending.is_empty());

        // generate three messages and send them in reverse order
        let messages = (0..3)
            .map(|i| {
                let message = outbound_session.encrypt_message(vec![i as u8; 4]).unwrap();

                let mut out = BytesMut::with_capacity(message.len() + 4);
                out.put_u32(message.len() as u32);
                out.put_slice(&message);

                Message {
                    payload: out.freeze().to_vec(),
                    ..Default::default()
                }
            })
            .collect::<Vec<_>>();

        messages.into_iter().enumerate().rev().for_each(|(i, message)| {
            let message = session.decrypt(message).unwrap();
            assert_eq!(message, [i as u8; 4]);
        });

        // send message from the inbound session
        let message = session.encrypt(&remote_destination_id, vec![1, 3, 3, 7]).unwrap();

        let mut out = BytesMut::with_capacity(message.len() + 4);
        out.put_u32(message.len() as u32);
        out.put_slice(&message);

        let message = Message {
            payload: out.freeze().to_vec(),
            ..Default::default()
        };

        assert_eq!(
            outbound_session.decrypt_message(message).unwrap(),
            vec![1, 3, 3, 7]
        );
    }

    #[test]
    fn new_outbound_session() {
        // create inbound `SessionManager`
        let inbound_private_key = StaticPrivateKey::new(thread_rng());
        let inbound_public_key = inbound_private_key.public();
        let (inbound_leaseset, inbound_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let inbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                inbound_destination_id,
            )
        };
        let mut inbound_session = SessionManager::<MockRuntime>::new(
            inbound_destination_id.clone(),
            inbound_private_key,
            inbound_leaseset,
        );

        // create outbound `SessionManager`
        let outbound_private_key = StaticPrivateKey::new(thread_rng());
        let outbound_public_key = outbound_private_key.public();
        let (outbound_leaseset, outbound_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let outbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                outbound_destination_id,
            )
        };
        let mut outbound_session = SessionManager::<MockRuntime>::new(
            outbound_destination_id.clone(),
            outbound_private_key,
            outbound_leaseset,
        );
        outbound_session.add_remote_destination(inbound_destination_id.clone(), inbound_public_key);

        // initialize outbound session and create `NewSession` message
        let message = {
            let message =
                outbound_session.encrypt(&inbound_destination_id, vec![1, 2, 3, 4]).unwrap();

            let mut out = BytesMut::with_capacity(message.len() + 4);
            out.put_u32(message.len() as u32);
            out.put_slice(&message);

            out.freeze().to_vec()
        };

        // handle `NewSession` message, initialize inbound session
        // and create `NewSessionReply` message
        let message = {
            let message = inbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let clove_set = GarlicMessage::parse(&message).unwrap();
            let Some(GarlicMessageBlock::GarlicClove { message_body, .. }) =
                clove_set.blocks.iter().find(|clove| match clove {
                    GarlicMessageBlock::GarlicClove { message_type, .. }
                        if message_type == &MessageType::Data =>
                        true,
                    _ => false,
                })
            else {
                panic!("data message not found");
            };

            assert_eq!(message_body, &[0, 0, 0, 4, 1, 2, 3, 4]);

            // create response to `NewSession`
            let message =
                inbound_session.encrypt(&outbound_destination_id, vec![5, 6, 7, 8]).unwrap();

            let mut out = BytesMut::with_capacity(message.len() + 4);

            out.put_u32(message.len() as u32);
            out.put_slice(&message);
            out.freeze().to_vec()
        };

        // handle `NewSessionReply` and finalize outbound session
        let message = {
            let message = outbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            assert_eq!(message, &[5, 6, 7, 8]);
        };

        // finalize inbound session by sending an `ExistingSession` message
        let message = {
            let message =
                outbound_session.encrypt(&inbound_destination_id, vec![1, 3, 3, 7]).unwrap();

            let mut out = BytesMut::with_capacity(message.len() + 4);

            out.put_u32(message.len() as u32);
            out.put_slice(&message);
            out.freeze().to_vec()
        };

        // handle `ExistingSession` message
        let message = inbound_session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(message, [1, 3, 3, 7]);

        // send `ExistingSession` from inbound session
        // finalize inbound session by sending an `ExistingSession` message
        let message = {
            let message =
                inbound_session.encrypt(&outbound_destination_id, vec![1, 3, 3, 8]).unwrap();

            let mut out = BytesMut::with_capacity(message.len() + 4);

            out.put_u32(message.len() as u32);
            out.put_slice(&message);
            out.freeze().to_vec()
        };

        // handle `ExistingSession` message
        let message = outbound_session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(message, [1, 3, 3, 8]);
    }
}
