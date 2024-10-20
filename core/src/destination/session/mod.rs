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
    destination::session::{
        context::KeyContext,
        session::{PendingSession, PendingSessionEvent, Session},
    },
    error::Error,
    i2np::{
        database::store::{
            DatabaseStore, DatabaseStoreBuilder, DatabaseStoreKind, DatabaseStorePayload,
        },
        garlic::{
            DeliveryInstructions as GarlicDeliveryInstructions, GarlicClove, GarlicMessage,
            GarlicMessageBlock, GarlicMessageBuilder, OwnedDeliveryInstructions,
        },
        Message, MessageType, I2NP_MESSAGE_EXPIRATION,
    },
    primitives::{DestinationId, MessageId},
    runtime::Runtime,
};

use bytes::{BufMut, Bytes, BytesMut};
use hashbrown::HashMap;
use rand_core::RngCore;

#[cfg(feature = "std")]
use parking_lot::RwLock;
#[cfg(feature = "no_std")]
use spin::rwlock::RwLock;

use alloc::sync::Arc;
use core::time::Duration;

mod context;
mod inbound;
mod outbound;
mod session;
mod tagset;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::destination::session";

/// Number of garlic tags to generate.
const NUM_TAGS_TO_GENERATE: usize = 128;

/// Number of tag set entries consumed per key before a DH ratchet is performed.
const SESSION_DH_RATCHET_THRESHOLD: usize = 150;

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
    pub fn remove_remote_destination(&mut self, destination_id: &DestinationId) {
        self.remote_destinations.remove(destination_id);
    }

    /// Encrypt `message` destined to `destination_id`.
    ///
    /// Caller must ensure that `message` is a serialized I2CP payload ([`GzipPayload`]).
    ///
    /// [`SessionManager::encrypt()`] wraps `message` in I2NP Data [1] payload and wraps that in a
    /// garlic clove which then gets encrypted into a `NewSession`, `NewSessionReply` or
    /// `ExistingSession` message, based on the session's state.
    ///
    /// [1]: https://geti2p.net/spec/i2np#data
    pub fn encrypt(
        &mut self,
        destination_id: &DestinationId,
        message: Vec<u8>,
    ) -> crate::Result<Vec<u8>> {
        match self.active.get_mut(destination_id) {
            Some(session) => {
                // TODO: ugly
                let message = {
                    let mut out = BytesMut::with_capacity(message.len() + 4);

                    out.put_u32(message.len() as u32);
                    out.put_slice(&message);
                    out
                };
                let message = GarlicMessageBuilder::new().with_garlic_clove(
                    MessageType::Data,
                    MessageId::from(R::rng().next_u32()),
                    R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                    GarlicDeliveryInstructions::Local,
                    &message,
                );

                session.encrypt(message).map(|message| {
                    let mut out = BytesMut::with_capacity(message.len() + 4);

                    out.put_u32(message.len() as u32);
                    out.put_slice(&message);
                    out.freeze().to_vec()
                })
            }
            None => match self.pending.get_mut(destination_id) {
                Some(session) => {
                    let message = GarlicMessageBuilder::new()
                        .with_garlic_clove(
                            MessageType::Data,
                            MessageId::from(R::rng().next_u32()),
                            R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                            GarlicDeliveryInstructions::Local,
                            &{
                                let mut out = BytesMut::with_capacity(message.len() + 4);

                                out.put_u32(message.len() as u32);
                                out.put_slice(&message);

                                out.freeze().to_vec()
                            },
                        )
                        .build();

                    match session.advance_outbound(message)? {
                        PendingSessionEvent::SendMessage { message } => Ok({
                            let mut out = BytesMut::with_capacity(message.len() + 4);

                            out.put_u32(message.len() as u32);
                            out.put_slice(&message);
                            out.freeze().to_vec()
                        }),
                        PendingSessionEvent::CreateSession { message, context } => todo!(),
                    }
                }
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
                            R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                            GarlicDeliveryInstructions::Local,
                            &database_store,
                        )
                        .with_garlic_clove(
                            MessageType::Data,
                            MessageId::from(R::rng().next_u32()),
                            R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
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

                    Ok({
                        let mut out = BytesMut::with_capacity(payload.len() + 4);

                        out.put_u32(payload.len() as u32);
                        out.put_slice(&payload);
                        out.freeze().to_vec()
                    })
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
    pub fn decrypt(
        &mut self,
        message: Message,
    ) -> crate::Result<impl Iterator<Item = GarlicClove>> {
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

        let payload = match session {
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

                // TODO: verify `DateTime`

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

                payload
            }
            Some(destination_id) => match self.active.get_mut(&destination_id) {
                Some(session) => session.decrypt(garlic_tag, message.payload)?,
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

                            message
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
                        return Err(Error::InvalidState);
                    }
                },
            },
        };

        // parse garlic cloves from the decrypted messages and return them to the caller
        //
        // TODO: optimize, ideally this should return references
        let cloves = GarlicMessage::parse(&payload)
            .ok_or_else(|| {
                tracing::warn!(
                    target: LOG_TARGET,
                    id = %self.destination_id,
                    "failed to parse `NewSession` payload into a clove set",
                );

                Error::InvalidData
            })?
            .blocks
            .into_iter()
            .filter_map(|block| match block {
                GarlicMessageBlock::GarlicClove {
                    message_type,
                    message_id,
                    expiration,
                    delivery_instructions,
                    message_body,
                } => Some(GarlicClove {
                    message_type,
                    message_id,
                    expiration,
                    delivery_instructions: OwnedDeliveryInstructions::from(&delivery_instructions),
                    message_body: message_body.to_vec(),
                }),
                _ => None,
            })
            .collect::<Vec<_>>();

        Ok(cloves.into_iter())
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
        outbound_session.add_remote_destination(destination_id.clone(), public_key);
        let message = outbound_session.encrypt(&destination_id, vec![1, 2, 3, 4]).unwrap();

        let mut cloves = session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        // verify message is valid
        {
            let Some(GarlicClove { message_body, .. }) =
                cloves.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };

            assert_eq!(&message_body[4..], &vec![1, 2, 3, 4]);
        }

        // verify pending inbound session exists for the destination
        assert!(session.pending.contains_key(&outbound_destination_id));
        let message = Message {
            payload: session.encrypt(&outbound_destination_id, vec![1, 2, 3, 4]).unwrap(),
            ..Default::default()
        };

        {
            let mut message = outbound_session.decrypt(message).unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(&message_body[4..], &vec![1, 2, 3, 4]);
        }

        let message = {
            let message = outbound_session.encrypt(&destination_id, vec![5, 6, 7, 8]).unwrap();

            Message {
                payload: message,
                ..Default::default()
            }
        };

        assert_eq!(
            session
                .decrypt(message)
                .unwrap()
                .find(|clove| std::matches!(clove.message_type, MessageType::Data))
                .unwrap()
                .message_body,
            [0, 0, 0, 4, 5, 6, 7, 8]
        );

        assert!(session.active.contains_key(&outbound_destination_id));
        assert!(outbound_session.active.contains_key(&destination_id));
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
        outbound_session.add_remote_destination(destination_id.clone(), public_key);
        let message = outbound_session.encrypt(&destination_id, vec![1, 2, 3, 4]).unwrap();

        let mut payload = session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        // verify message is valid
        {
            let Some(GarlicClove { message_body, .. }) =
                payload.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };

            assert_eq!(&message_body[4..], &vec![1, 2, 3, 4]);
        }

        // verify pending inbound session exists for the destination
        assert!(session.pending.contains_key(&outbound_destination_id));

        let message = Message {
            payload: session.encrypt(&outbound_destination_id, vec![1, 2, 3, 4]).unwrap(),
            ..Default::default()
        };

        let mut message = outbound_session.decrypt(message).unwrap();
        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(&message_body[4..], &vec![1, 2, 3, 4]);

        let message = {
            let message = outbound_session.encrypt(&destination_id, vec![5, 6, 7, 8]).unwrap();

            Message {
                payload: message,
                ..Default::default()
            }
        };

        // verify pending inbound session still exists for the destination
        assert!(session.pending.contains_key(&outbound_destination_id));

        // verify message is valid
        {
            let mut message = session.decrypt(message).unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };

            assert_eq!(&message_body[4..], &vec![5, 6, 7, 8]);
        }

        // verify that the inbound session is now considered active
        assert!(session.active.contains_key(&outbound_destination_id));
        assert!(session.pending.is_empty());

        // generate three messages and send them in reverse order
        let messages = (0..3)
            .map(|i| {
                let message = outbound_session.encrypt(&destination_id, vec![i as u8; 4]).unwrap();

                Message {
                    payload: message,
                    ..Default::default()
                }
            })
            .collect::<Vec<_>>();

        messages.into_iter().enumerate().rev().for_each(|(i, message)| {
            let mut message = session.decrypt(message).unwrap();
            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };

            assert_eq!(&message_body[4..], &vec![i as u8; 4]);
        });

        // send message from the inbound session
        let message = Message {
            payload: session.encrypt(&outbound_destination_id, vec![1, 3, 3, 7]).unwrap(),
            ..Default::default()
        };

        let mut message = outbound_session.decrypt(message).unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(&message_body[4..], &vec![1, 3, 3, 7]);
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
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1, 2, 3, 4]).unwrap();

        // handle `NewSession` message, initialize inbound session
        // and create `NewSessionReply` message
        let message = {
            let mut message = inbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(&message_body[4..], &vec![1, 2, 3, 4]);

            // create response to `NewSession`
            inbound_session.encrypt(&outbound_destination_id, vec![5, 6, 7, 8]).unwrap()
        };

        // handle `NewSessionReply` and finalize outbound session
        let message = {
            let mut message = outbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(&message_body[4..], &vec![5, 6, 7, 8]);
        };

        // finalize inbound session by sending an `ExistingSession` message
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1, 3, 3, 7]).unwrap();

        // handle `ExistingSession` message
        let mut message = inbound_session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(&message_body[4..], &vec![1, 3, 3, 7]);

        // finalize inbound session by sending an `ExistingSession` message
        let message = inbound_session.encrypt(&outbound_destination_id, vec![1, 3, 3, 8]).unwrap();

        // handle `ExistingSession` message
        let mut message = outbound_session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(&message_body[4..], &vec![1, 3, 3, 8]);
    }

    #[test]
    fn two_simultaneous_inbound_sessions() {
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

        // create first outbound `SessionManager`
        let outbound1_private_key = StaticPrivateKey::new(thread_rng());
        let outbound1_public_key = outbound1_private_key.public();
        let (outbound1_leaseset, outbound1_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let outbound1_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                outbound1_destination_id,
            )
        };
        let mut outbound1_session = SessionManager::<MockRuntime>::new(
            outbound1_destination_id.clone(),
            outbound1_private_key,
            outbound1_leaseset,
        );
        outbound1_session
            .add_remote_destination(inbound_destination_id.clone(), inbound_public_key.clone());

        // create second outbound `SessionManager`
        let outbound2_private_key = StaticPrivateKey::new(thread_rng());
        let outbound2_public_key = outbound2_private_key.public();
        let (outbound2_leaseset, outbound2_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let outbound2_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                outbound2_destination_id,
            )
        };
        let mut outbound2_session = SessionManager::<MockRuntime>::new(
            outbound2_destination_id.clone(),
            outbound2_private_key,
            outbound2_leaseset,
        );
        outbound2_session
            .add_remote_destination(inbound_destination_id.clone(), inbound_public_key);

        // initialize first outbound session and create `NewSession` message
        let message = outbound1_session.encrypt(&inbound_destination_id, vec![1, 2, 3, 4]).unwrap();

        // handle `NewSession` message, initialize inbound session
        // and create `NewSessionReply` message
        let outbound1_nsr = {
            let mut message = inbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(&message_body[4..], &vec![1, 2, 3, 4]);

            // create response to `NewSession`
            inbound_session.encrypt(&outbound1_destination_id, vec![5, 6, 7, 8]).unwrap()
        };

        // initialize second outbound session and create `NewSession` message
        let message = outbound2_session.encrypt(&inbound_destination_id, vec![1, 2, 3, 4]).unwrap();

        // handle `NewSession` message, initialize inbound session
        // and create `NewSessionReply` message
        let outbound2_nsr = {
            let mut message = inbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(&message_body[4..], &vec![1, 2, 3, 4]);

            // create response to `NewSession`
            inbound_session.encrypt(&outbound2_destination_id, vec![5, 6, 7, 8]).unwrap()
        };

        // handle `NewSessionReply` and finalize outbound for the first session
        {
            let mut message = outbound1_session
                .decrypt(Message {
                    payload: outbound1_nsr,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(&message_body[4..], &vec![5, 6, 7, 8]);
        }

        // handle `NewSessionReply` and finalize outbound for the first session
        {
            let mut message = outbound2_session
                .decrypt(Message {
                    payload: outbound2_nsr,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(&message_body[4..], &vec![5, 6, 7, 8]);
        }

        // finalize inbound session by sending an `ExistingSession` message
        let message = outbound1_session.encrypt(&inbound_destination_id, vec![1, 3, 3, 7]).unwrap();

        // handle `ExistingSession` message
        let mut message = inbound_session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(message_body[4..], [1, 3, 3, 7]);

        // // send `ExistingSession` from inbound session
        // finalize inbound session by sending an `ExistingSession` message
        let message = inbound_session.encrypt(&outbound1_destination_id, vec![1, 3, 3, 8]).unwrap();

        // handle `ExistingSession` message
        let mut message = outbound1_session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(message_body[4..], [1, 3, 3, 8]);

        // verify there's one pending inbound session
        assert_eq!(inbound_session.active.len(), 1);
        assert_eq!(inbound_session.pending.len(), 1);
        assert_eq!(outbound1_session.active.len(), 1);
        assert_eq!(outbound1_session.pending.len(), 0);
        assert_eq!(outbound2_session.active.len(), 1);
        assert_eq!(outbound2_session.pending.len(), 0);

        // finalize inbound session by sending an `ExistingSession` message
        let message = outbound2_session.encrypt(&inbound_destination_id, vec![1, 3, 3, 7]).unwrap();

        // handle `ExistingSession` message
        let mut message = inbound_session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(message_body[4..], [1, 3, 3, 7]);

        // send `ExistingSession` from inbound session
        // finalize inbound session by sending an `ExistingSession` message
        let message = inbound_session.encrypt(&outbound2_destination_id, vec![1, 3, 3, 9]).unwrap();

        // handle `ExistingSession` message
        let mut message = outbound2_session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(message_body[4..], [1, 3, 3, 9]);

        // verify there's one pending inbound session
        assert_eq!(inbound_session.active.len(), 2);
        assert_eq!(inbound_session.pending.len(), 0);
        assert_eq!(outbound1_session.active.len(), 1);
        assert_eq!(outbound1_session.pending.len(), 0);
        assert_eq!(outbound2_session.active.len(), 1);
        assert_eq!(outbound2_session.pending.len(), 0);
    }

    #[test]
    fn two_simultaneous_outbound_sessions() {
        // create first inbound `SessionManager`
        let inbound1_private_key = StaticPrivateKey::new(thread_rng());
        let inbound1_public_key = inbound1_private_key.public();
        let (inbound1_leaseset, inbound1_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let inbound1_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                inbound1_destination_id,
            )
        };
        let mut inbound1_session = SessionManager::<MockRuntime>::new(
            inbound1_destination_id.clone(),
            inbound1_private_key,
            inbound1_leaseset,
        );

        // create second inbound `SessionManager`
        let inbound2_private_key = StaticPrivateKey::new(thread_rng());
        let inbound2_public_key = inbound2_private_key.public();
        let (inbound2_leaseset, inbound2_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let inbound2_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                inbound2_destination_id,
            )
        };
        let mut inbound2_session = SessionManager::<MockRuntime>::new(
            inbound2_destination_id.clone(),
            inbound2_private_key,
            inbound2_leaseset,
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
        outbound_session
            .add_remote_destination(inbound1_destination_id.clone(), inbound1_public_key);
        outbound_session
            .add_remote_destination(inbound2_destination_id.clone(), inbound2_public_key);

        // initialize first outbound session and create `NewSession` message
        let ns1 = outbound_session.encrypt(&inbound1_destination_id, vec![1, 1, 1, 1]).unwrap();

        // initialize second outbound session and create `NewSession` message
        let ns2 = outbound_session.encrypt(&inbound2_destination_id, vec![2, 2, 2, 2]).unwrap();

        // handle `NewSession` message, initialize the first inbound session
        // and create `NewSessionReply` message
        let nsr1 = {
            let mut message = inbound1_session
                .decrypt(Message {
                    payload: ns1,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [1, 1, 1, 1]);

            // create response to `NewSession`
            inbound1_session.encrypt(&outbound_destination_id, vec![3, 3, 3, 3]).unwrap()
        };

        // handle `NewSession` message, initialize the first inbound session
        // and create `NewSessionReply` message
        let nsr2 = {
            let mut message = inbound2_session
                .decrypt(Message {
                    payload: ns2,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [2, 2, 2, 2]);

            // create response to `NewSession`
            inbound2_session.encrypt(&outbound_destination_id, vec![4, 4, 4, 4]).unwrap()
        };

        // handle `NewSessionReply` from first inbound session and finalize outbound session
        {
            let mut message = outbound_session
                .decrypt(Message {
                    payload: nsr1,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [3, 3, 3, 3]);
        }

        // handle `NewSessionReply` from second session and finalize outbound session
        {
            let mut message = outbound_session
                .decrypt(Message {
                    payload: nsr2,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [4, 4, 4, 4]);
        }

        assert_eq!(inbound1_session.active.len(), 0);
        assert_eq!(inbound1_session.pending.len(), 1);
        assert_eq!(inbound2_session.active.len(), 0);
        assert_eq!(inbound2_session.pending.len(), 1);
        assert_eq!(outbound_session.active.len(), 2);
        assert_eq!(outbound_session.pending.len(), 0);

        // finalize first inbound session by sending an `ExistingSession` message
        let es1 = outbound_session.encrypt(&inbound1_destination_id, vec![1, 3, 3, 7]).unwrap();

        // handle `ExistingSession` message
        let mut message = inbound1_session
            .decrypt(Message {
                payload: es1,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(message_body[4..], [1, 3, 3, 7]);

        assert_eq!(inbound1_session.active.len(), 1);
        assert_eq!(inbound1_session.pending.len(), 0);
        assert_eq!(inbound2_session.active.len(), 0);
        assert_eq!(inbound2_session.pending.len(), 1);
        assert_eq!(outbound_session.active.len(), 2);
        assert_eq!(outbound_session.pending.len(), 0);

        // finalize second inbound session by sending an `ExistingSession` message
        let es2 = outbound_session.encrypt(&inbound2_destination_id, vec![1, 3, 3, 8]).unwrap();

        // handle `ExistingSession` message
        let mut message = inbound2_session
            .decrypt(Message {
                payload: es2,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(message_body[4..], [1, 3, 3, 8]);

        assert_eq!(inbound1_session.active.len(), 1);
        assert_eq!(inbound1_session.pending.len(), 0);
        assert_eq!(inbound2_session.active.len(), 1);
        assert_eq!(inbound2_session.pending.len(), 0);
        assert_eq!(outbound_session.active.len(), 2);
        assert_eq!(outbound_session.pending.len(), 0);
    }

    #[test]
    fn tags_are_autogenerated() {
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
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1, 2, 3, 4]).unwrap();

        // handle `NewSession` message, initialize inbound session
        // and create `NewSessionReply` message
        let message = {
            let mut message = inbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [1, 2, 3, 4]);

            // create response to `NewSession`
            inbound_session.encrypt(&outbound_destination_id, vec![5, 6, 7, 8]).unwrap()
        };

        // handle `NewSessionReply` and finalize outbound session
        let message = {
            let mut message = outbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [5, 6, 7, 8]);
        };

        // finalize inbound session by sending an `ExistingSession` message
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1, 3, 3, 7]).unwrap();

        // handle `ExistingSession` message
        let mut message = inbound_session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(message_body[4..], [1, 3, 3, 7]);

        // send twice as many messages as there were initial tags
        // and verify that all messages are decrypted correctly
        for i in 0..NUM_TAGS_TO_GENERATE * 2 {
            // send `ExistingSession` from inbound session
            // finalize inbound session by sending an `ExistingSession` message
            let message =
                inbound_session.encrypt(&outbound_destination_id, vec![i as u8; 4]).unwrap();

            // handle `ExistingSession` message
            let mut message = outbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [i as u8; 4]);
        }
    }

    #[test]
    fn dh_ratchet() {
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
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1, 2, 3, 4]).unwrap();

        // handle `NewSession` message, initialize inbound session
        // and create `NewSessionReply` message
        let message = {
            let mut message = inbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [1, 2, 3, 4]);

            // create response to `NewSession`
            inbound_session.encrypt(&outbound_destination_id, vec![5, 6, 7, 8]).unwrap()
        };

        // handle `NewSessionReply` and finalize outbound session
        let message = {
            let mut message = outbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [5, 6, 7, 8]);
        };

        // finalize inbound session by sending an `ExistingSession` message
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1, 3, 3, 7]).unwrap();

        // handle `ExistingSession` message
        let mut message = inbound_session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(message_body[4..], [1, 3, 3, 7]);

        // run the dh ratchet five times to exercise all state transitions
        for _ in 0..5 {
            // send twice as many messages as there were initial tags
            // and verify that all messages are decrypted correctly
            let mut responded_to_nextkey = false;

            for i in 0..SESSION_DH_RATCHET_THRESHOLD + 5 {
                // send `ExistingSession` from inbound session
                // finalize inbound session by sending an `ExistingSession` message
                let message =
                    inbound_session.encrypt(&outbound_destination_id, vec![i as u8; 4]).unwrap();

                // handle `ExistingSession` message
                let mut message = outbound_session
                    .decrypt(Message {
                        payload: message,
                        ..Default::default()
                    })
                    .unwrap();

                let Some(GarlicClove { message_body, .. }) =
                    message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
                else {
                    panic!("message not found");
                };
                assert_eq!(message_body[4..], [i as u8; 4]);

                if i > SESSION_DH_RATCHET_THRESHOLD && !responded_to_nextkey {
                    let message =
                        outbound_session.encrypt(&inbound_destination_id, vec![4]).unwrap();

                    let mut message = inbound_session
                        .decrypt(Message {
                            payload: message,
                            ..Default::default()
                        })
                        .unwrap();

                    responded_to_nextkey = true;
                }
            }
        }
    }

    #[test]
    fn ack_request_and_ack() {
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
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1, 2, 3, 4]).unwrap();

        // handle `NewSession` message, initialize inbound session
        // and create `NewSessionReply` message
        let message = {
            let mut message = inbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [1, 2, 3, 4]);

            // create response to `NewSession`
            inbound_session.encrypt(&outbound_destination_id, vec![5, 6, 7, 8]).unwrap()
        };

        // handle `NewSessionReply` and finalize outbound session
        let message = {
            let mut message = outbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [5, 6, 7, 8]);
        };

        // finalize inbound session by sending an `ExistingSession` message
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1, 3, 3, 7]).unwrap();

        // handle `ExistingSession` message
        let mut message = inbound_session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(message_body[4..], [1, 3, 3, 7]);

        // send twice as many messages as there were initial tags
        // and verify that all messages are decrypted correctly
        for i in 0..NUM_TAGS_TO_GENERATE * 2 {
            // send `ExistingSession` from inbound session
            // finalize inbound session by sending an `ExistingSession` message
            let message =
                inbound_session.encrypt(&outbound_destination_id, vec![i as u8; 4]).unwrap();

            // handle `ExistingSession` message
            let mut message = outbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [i as u8; 4]);
        }
    }
}
