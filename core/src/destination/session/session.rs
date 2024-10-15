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
        context::KeyContext, inbound::InboundSession, outbound::OutboundSession, LOG_TARGET,
    },
    error::Error,
    primitives::DestinationId,
    runtime::Runtime,
};

use bytes::Bytes;
use curve25519_elligator2::{MapToPointVariant, MontgomeryPoint, Randomized};

use core::{marker::PhantomData, mem};

/// Event emitted by [`PendingSession`].
pub enum PendingSessionEvent {
    /// Send message to remote destination.
    SendMessage {
        /// Serialized message.
        message: Vec<u8>,
    },

    /// Store garlic tags into `SessionManager`.
    StoreTags {
        /// (Garlic tags, session key) tuples to store.
        tags: Vec<(u64, Bytes)>,
    },
}

/// State of the pending session.
enum PendingSessionState<R: Runtime> {
    /// Inbound session received from remote destination.
    InboundActive {
        /// Inbound session.
        inbound: InboundSession<R>,
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
            state: PendingSessionState::InboundActive { inbound },
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
    pub fn advance_outbound(
        &mut self,
        message: Vec<u8>,
    ) -> crate::Result<impl Iterator<Item = PendingSessionEvent>> {
        match mem::replace(&mut self.state, PendingSessionState::Poisoned) {
            PendingSessionState::InboundActive { mut inbound } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    "send `NewSessionReply`",
                );

                inbound.create_new_session_reply(message)
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
    pub fn advance_inbound(&mut self, message: Vec<u8>) -> crate::Result<Vec<u8>> {
        match mem::replace(&mut self.state, PendingSessionState::Poisoned) {
            PendingSessionState::InboundActive { mut inbound } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    "send `NewSessionReply`",
                );

                let _ = inbound.handle_existing_session(message);

                todo!();
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
    _marker: PhantomData<R>,
}
