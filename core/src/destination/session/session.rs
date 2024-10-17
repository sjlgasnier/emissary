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
        LOG_TARGET, NUM_TAGS_TO_GENERATE,
    },
    error::Error,
    primitives::DestinationId,
    runtime::Runtime,
};

use bytes::{BufMut, Bytes, BytesMut};
use curve25519_elligator2::{MapToPointVariant, MontgomeryPoint, Randomized};
use hashbrown::HashMap;

#[cfg(feature = "std")]
use parking_lot::RwLock;
#[cfg(feature = "no_std")]
use spin::rwlock::RwLock;

use alloc::sync::Arc;
use core::{fmt, marker::PhantomData, mem};

/// Garlic message overheard.
///
/// 8 bytes for garlic tag and 16 bytes Poly1305 MAC.
const GARLIC_MESSAGE_OVERHEAD: usize = 24usize;

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

        /// Garlic tag -> session key mapping for `NewSessionReply` message(s).
        tag_set_entries: HashMap<u64, TagSetEntry>,
    },

    /// State has been poisoned.
    Poisoned,
}

impl<R: Runtime> fmt::Debug for PendingSessionState<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InboundActive {
                inbound,
                garlic_tags,
                tag_set_entries,
            } => f.debug_struct("PendingSessionState::InboundActive").finish_non_exhaustive(),
            Self::OutboundActive {
                outbound,
                garlic_tags,
                tag_set_entries,
            } => f.debug_struct("PendingSessionState::OutboundActive").finish_non_exhaustive(),
            Self::Poisoned =>
                f.debug_struct("PendingSessionState::Poisoned").finish_non_exhaustive(),
        }
    }
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
        // generate and store tag set entries for `NewSessionReply`
        let tag_set_entries = {
            let mut inner = garlic_tags.write();

            outbound
                .generate_new_session_reply_tags()
                .map(|tag_set| {
                    inner.insert(tag_set.tag, remote.clone());
                    (tag_set.tag, tag_set)
                })
                .collect()
        };

        Self {
            local,
            remote,
            state: PendingSessionState::OutboundActive {
                outbound,
                garlic_tags,
                tag_set_entries,
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
            state => {
                tracing::warn!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    ?state,
                    "invalid session state",
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

                let tag_set_entry = tag_set_entries.remove(&garlic_tag).ok_or_else(|| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        local = %self.local,
                        remote = %self.remote,
                        ?garlic_tag,
                        "`TagSetEntry` doesn't exist for `ExistingSession`",
                    );

                    debug_assert!(false);
                    Error::InvalidState
                })?;

                let (message, send_tag_set, recv_tag_set) =
                    inbound.handle_existing_session(tag_set_entry, message)?;

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
                mut outbound,
                mut tag_set_entries,
                garlic_tags,
            } => {
                let tag_set_entry = tag_set_entries.remove(&garlic_tag).ok_or_else(|| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        local = %self.local,
                        remote = %self.remote,
                        ?garlic_tag,
                        "`TagSetEntry` doesn't exist for `NewSessionReply`",
                    );

                    debug_assert!(false);
                    Error::InvalidState
                })?;

                let (message, send_tag_set, mut recv_tag_set) =
                    outbound.handle_new_session_reply(tag_set_entry, message)?;

                // generate tag set entries for inbound messages and store remote's id in the global
                // storage under the generated garlic tags and store the tag set entries themselves
                // inside the `Session`'s storage
                {
                    let mut inner = garlic_tags.write();

                    // `next_entry()` must succeed as `recv_tag_set` is a fresh `TagSet`
                    (0..NUM_TAGS_TO_GENERATE).for_each(|_| {
                        let entry = recv_tag_set.next_entry().expect("to succeed");

                        inner.insert(entry.tag, self.remote.clone());
                        tag_set_entries.insert(entry.tag, entry);
                    });
                }

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
        tracing::trace!(
            target: LOG_TARGET,
            local = %self.local,
            remote = %self.remote,
            ?garlic_tag,
            "inbound garlic message",
        );

        let TagSetEntry { index, key, tag } =
            self.tag_set_entries.remove(&garlic_tag).ok_or_else(|| {
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

        // generate new tag for the used tag if there are tags left
        {
            match self.recv_tag_set.next_entry() {
                None => tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    "receive tag set ran out of tags",
                ),
                Some(entry) => {
                    self.garlic_tags.write().insert(entry.tag, self.remote.clone());
                    self.tag_set_entries.insert(entry.tag, entry);
                }
            }
        }

        let mut payload = message[12..].to_vec();

        ChaChaPoly::with_nonce(&key, index as u64)
            .decrypt_with_ad(&tag.to_le_bytes(), &mut payload)
            .map(|_| payload)
    }

    /// Encrypt `message`.
    pub fn encrypt(&mut self, mut message: Vec<u8>) -> crate::Result<Vec<u8>> {
        let TagSetEntry { index, key, tag } = self.send_tag_set.next_entry().ok_or_else(|| {
            tracing::warn!(
                target: LOG_TARGET,
                local = %self.local,
                remote = %self.remote,
                "`TagSet` ran out of tags",
            );
            debug_assert!(false);
            Error::InvalidState
        })?;

        tracing::trace!(
            target: LOG_TARGET,
            local = %self.local,
            remote = %self.remote,
            garlic_tag = ?tag,
            "outbound garlic message",
        );

        let mut out = BytesMut::with_capacity(message.len() + GARLIC_MESSAGE_OVERHEAD);

        ChaChaPoly::with_nonce(&key, index as u64)
            .encrypt_with_ad_new(&tag.to_le_bytes(), &mut message)?;

        out.put_u64_le(tag);
        out.put_slice(&message);

        Ok(out.freeze().to_vec())
    }
}
