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
    crypto::{chachapoly::ChaChaPoly, StaticPrivateKey, StaticPublicKey},
    destination::session::{
        context::KeyContext,
        inbound::InboundSession,
        outbound::OutboundSession,
        tagset::{TagSet, TagSetEntry},
        LOG_TARGET,
    },
    error::Error,
    primitives::DestinationId,
    runtime::Runtime,
};

use bytes::Bytes;
use curve25519_elligator2::{MapToPointVariant, MontgomeryPoint, Randomized};
use hashbrown::HashMap;

#[cfg(feature = "std")]
use parking_lot::RwLock;
#[cfg(feature = "no_std")]
use spin::rwlock::RwLock;

use alloc::sync::Arc;
use core::{marker::PhantomData, mem};

/// Event emitted by [`PendingSession`].
pub enum PendingSessionEvent {
    /// Send message to remote destination.
    SendMessage {
        /// Serialized message.
        message: Vec<u8>,
    },

    /// Create new active `Session` and send `message` to remote destination.
    CreateSession {
        /// Serialized message.
        message: Vec<u8>,

        /// Session context.
        context: SessionContext,
    },
}

/// State of the pending session.
enum PendingSessionState<R: Runtime> {
    /// Inbound session received from remote destination.
    InboundActive {
        /// Inbound session.
        inbound: InboundSession<R>,

        /// Garlic tags, global mapping for all active and pending sessions.
        garlic_tags: Arc<RwLock<HashMap<u64, DestinationId>>>,

        /// Garlic tag -> session key mapping for inbound messages.
        tag_set_entries: HashMap<u64, TagSetEntry>,
    },

    /// Outbound session established to remote destination.
    OutboundActive {
        /// Outbound session.
        outbound: OutboundSession<R>,

        /// Garlic tags, global mapping for all active and pending sessions.
        garlic_tags: Arc<RwLock<HashMap<u64, DestinationId>>>,
    },

    /// State has been poisoned.
    Poisoned,
}

/// Pending ECIES-X25519-AEAD-Ratchet session.
pub struct PendingSession<R: Runtime> {
    /// ID of the local destination.
    local: DestinationId,

    /// ID of the remote destination.
    remote: DestinationId,

    /// State of the session.
    state: PendingSessionState<R>,
}

impl<R: Runtime> PendingSession<R> {
    /// Create new [`Session`] from an [`InboundSession`].
    pub fn new_inbound(
        local: DestinationId,
        remote: DestinationId,
        inbound: InboundSession<R>,
        garlic_tags: Arc<RwLock<HashMap<u64, DestinationId>>>,
    ) -> Self {
        Self {
            local,
            remote,
            state: PendingSessionState::InboundActive {
                inbound,
                tag_set_entries: HashMap::new(),
                garlic_tags,
            },
        }
    }

    /// Create new [`Session`] from an [`OutboundSession`].
    pub fn new_outbound(
        local: DestinationId,
        remote: DestinationId,
        outbound: OutboundSession<R>,
        garlic_tags: Arc<RwLock<HashMap<u64, DestinationId>>>,
    ) -> Self {
        Self {
            local,
            remote,
            state: PendingSessionState::OutboundActive {
                outbound,
                garlic_tags,
            },
        }
    }

    /// Advance the state of [`PendingSession`] with an outbound `message`.
    ///
    /// TODO: more documentation
    pub fn advance_outbound(&mut self, message: Vec<u8>) -> crate::Result<PendingSessionEvent> {
        match mem::replace(&mut self.state, PendingSessionState::Poisoned) {
            PendingSessionState::InboundActive {
                mut inbound,
                mut tag_set_entries,
                mut garlic_tags,
            } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    "send `NewSessionReply`",
                );

                // create `NewSessionReply` and garlic receive tags
                let (message, entries) = inbound.create_new_session_reply(message)?;

                // store receive garlic tags both in the global storage common for all destinations
                // so `SessionManager` can dispatch received messages to the correct `Session` and
                // also in the session's own `TagSetEntry` storage so the session has access to the
                // session key and associated context to decrypt the message
                {
                    let mut inner = garlic_tags.write();

                    entries.into_iter().for_each(|entry| {
                        inner.insert(entry.tag, self.remote.clone());
                        tag_set_entries.insert(entry.tag, entry);
                    })
                }

                self.state = PendingSessionState::InboundActive {
                    inbound,
                    tag_set_entries,
                    garlic_tags,
                };

                Ok(PendingSessionEvent::SendMessage { message })
            }
            PendingSessionState::OutboundActive {
                outbound,
                garlic_tags,
            } => {
                todo!();
            }
            PendingSessionState::Poisoned => {
                tracing::warn!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    "session state has been poisoned",
                );
                debug_assert!(false);
                return Err(Error::InvalidState);
            }
        }
    }

    /// Advance the state of [`PendingSession`] with an inbound `message`.
    ///
    /// This is either a `NewSessionReply` for outbound sessions or a `ExistingSession`
    /// for inbound session.
    pub fn advance_inbound(
        &mut self,
        garlic_tag: u64,
        message: Vec<u8>,
    ) -> crate::Result<PendingSessionEvent> {
        match mem::replace(&mut self.state, PendingSessionState::Poisoned) {
            PendingSessionState::InboundActive {
                mut inbound,
                mut tag_set_entries,
                garlic_tags,
            } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    "send `NewSessionReply`",
                );

                let session_key = tag_set_entries.remove(&garlic_tag).ok_or_else(|| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        local = %self.local,
                        remote = %self.remote,
                        ?garlic_tag,
                        "`TagSetEntry` doesn't exist",
                    );

                    debug_assert!(false);
                    Error::InvalidState
                })?;

                let (message, send_tag_set, recv_tag_set) =
                    inbound.handle_existing_session(session_key, message)?;

                Ok(PendingSessionEvent::CreateSession {
                    message,
                    context: SessionContext {
                        recv_tag_set,
                        send_tag_set,
                        tag_set_entries,
                        garlic_tags,
                        local: self.local.clone(),
                        remote: self.remote.clone(),
                    },
                })
            }
            PendingSessionState::OutboundActive {
                outbound,
                garlic_tags,
            } => {
                todo!();
            }
            PendingSessionState::Poisoned => {
                tracing::warn!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    "session state has been poisoned",
                );
                debug_assert!(false);
                return Err(Error::InvalidState);
            }
        }
    }
}

/// Session context, passed into [`Session::new()`].
pub struct SessionContext {
    /// Garlic tags, global mapping for all active and pending sessions.
    garlic_tags: Arc<RwLock<HashMap<u64, DestinationId>>>,

    /// ID of the local destination.
    local: DestinationId,

    /// `TagSet` for inbound messages.
    recv_tag_set: TagSet,

    /// ID of the remote destination.
    remote: DestinationId,

    /// `TagSet` for outbound messages.
    send_tag_set: TagSet,

    /// `TagSet` entries for inbound messages.
    tag_set_entries: HashMap<u64, TagSetEntry>,
}

/// Active ECIES-X25519-AEAD-Ratchet session.
pub struct Session<R: Runtime> {
    /// Garlic tags, global mapping for all active and pending sessions.
    garlic_tags: Arc<RwLock<HashMap<u64, DestinationId>>>,

    /// ID of the local destination.
    local: DestinationId,

    /// `TagSet` for inbound messages.
    recv_tag_set: TagSet,

    /// ID of the remote destination.
    remote: DestinationId,

    /// `TagSet` for outbound messages.
    send_tag_set: TagSet,

    /// `TagSet` entries for inbound messages.
    tag_set_entries: HashMap<u64, TagSetEntry>,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> Session<R> {
    /// Create new [`Session`].
    pub fn new(context: SessionContext) -> Self {
        let SessionContext {
            garlic_tags,
            local,
            recv_tag_set,
            remote,
            send_tag_set,
            tag_set_entries,
        } = context;

        Self {
            garlic_tags,
            local,
            recv_tag_set,
            remote,
            send_tag_set,
            tag_set_entries,
            _runtime: Default::default(),
        }
    }

    /// Decrypt `message` using `garlic_tag` which identifies a `TagSetEntry`.
    pub fn decrypt(&mut self, garlic_tag: u64, message: Vec<u8>) -> crate::Result<Vec<u8>> {
        let tag_set_entry = self.tag_set_entries.remove(&garlic_tag).ok_or_else(|| {
            tracing::warn!(
                target: LOG_TARGET,
                local = %self.local,
                remote = %self.remote,
                ?garlic_tag,
                "`TagSetEntry` doesn't exist",
            );

            debug_assert!(false);
            Error::InvalidState
        })?;

        let mut payload = message[12..].to_vec();

        ChaChaPoly::with_nonce(&tag_set_entry.key, tag_set_entry.index as u64)
            .decrypt_with_ad(&tag_set_entry.tag.to_le_bytes(), &mut payload)
            .map(|_| payload)
    }
}
