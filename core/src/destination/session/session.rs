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
    crypto::{StaticPrivateKey, StaticPublicKey},
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

use core::{marker::PhantomData, mem};

/// Event emitted by [`PendingSession`].
pub enum PendingSessionEvent<R: Runtime> {
    /// Send message to remote destination and store garlic tags into `SessionManager`
    StoreTags {
        /// Serialized message.
        message: Vec<u8>,

        /// Garlic tags to store.
        tags: Vec<u64>,
    },

    /// Create new active `Session` and send `message` to remote destination.
    CreateSession {
        /// Serialized message.
        message: Vec<u8>,

        /// Active [`Session`].
        session: Session<R>,
    },
}

/// State of the pending session.
enum PendingSessionState<R: Runtime> {
    /// Inbound session received from remote destination.
    InboundActive {
        /// Inbound session.
        inbound: InboundSession<R>,

        /// Garlic tag -> session key mapping for inbound messages.
        tag_set_entries: HashMap<u64, TagSetEntry>,
    },

    /// Outbound session established to remote destination.
    OutboundActive {
        /// Outbound session.
        outbound: OutboundSession<R>,
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
    ) -> Self {
        Self {
            local,
            remote,
            state: PendingSessionState::InboundActive {
                inbound,
                tag_set_entries: HashMap::new(),
            },
        }
    }

    /// Create new [`Session`] from an [`OutboundSession`].
    pub fn new_outbound(
        local: DestinationId,
        remote: DestinationId,
        outbound: OutboundSession<R>,
    ) -> Self {
        Self {
            local,
            remote,
            state: PendingSessionState::OutboundActive { outbound },
        }
    }

    /// Advance the state of [`PendingSession`] with an outbound `message`.
    ///
    /// TODO: more documentation
    pub fn advance_outbound(&mut self, message: Vec<u8>) -> crate::Result<PendingSessionEvent<R>> {
        match mem::replace(&mut self.state, PendingSessionState::Poisoned) {
            PendingSessionState::InboundActive {
                mut inbound,
                mut tag_set_entries,
            } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    "send `NewSessionReply`",
                );

                // TODO: explain this code
                // TODO: refactor
                let (message, entries) = inbound.create_new_session_reply(message)?;
                let tags = entries.iter().map(|entry| entry.tag).collect::<Vec<_>>();

                tag_set_entries.extend(entries.into_iter().map(|entry| (entry.tag, entry)));
                self.state = PendingSessionState::InboundActive {
                    inbound,
                    tag_set_entries,
                };

                Ok(PendingSessionEvent::StoreTags { message, tags })
            }
            PendingSessionState::OutboundActive { outbound } => {
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
    ) -> crate::Result<PendingSessionEvent<R>> {
        match mem::replace(&mut self.state, PendingSessionState::Poisoned) {
            PendingSessionState::InboundActive {
                mut inbound,
                mut tag_set_entries,
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
                        "session key doesn't exist",
                    );

                    debug_assert!(false);
                    Error::InvalidState
                })?;

                let (message, send_tag_set, recv_tag_set) =
                    inbound.handle_existing_session(session_key, message)?;

                Ok(PendingSessionEvent::CreateSession {
                    message,
                    session: Session::new(send_tag_set, recv_tag_set, tag_set_entries),
                })
            }
            PendingSessionState::OutboundActive { outbound } => {
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

/// Active ECIES-X25519-AEAD-Ratchet session.
pub struct Session<R: Runtime> {
    /// `TagSet` for inbound messages.
    recv_tag_set: TagSet,

    /// `TagSet` for outbound messages.
    send_tag_set: TagSet,

    /// `TagSet` entries for inbound messages.
    tag_set_entries: HashMap<u64, TagSetEntry>,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> Session<R> {
    /// Create new [`Session`].
    pub fn new(
        send_tag_set: TagSet,
        recv_tag_set: TagSet,
        tag_set_entries: HashMap<u64, TagSetEntry>,
    ) -> Self {
        Self {
            send_tag_set,
            recv_tag_set,
            tag_set_entries,
            _runtime: Default::default(),
        }
    }
}
