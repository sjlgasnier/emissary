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
    error::StreamingError, primitives::DestinationId, runtime::Runtime, sam::socket::SamSocket,
};

use alloc::collections::VecDeque;
use core::fmt;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::sam::streaming::listener";

/// Virtual stream listener kind.
pub enum ListenerKind<R: Runtime> {
    /// Listener used to accept one inbound virtual stream (`STREAM ACCEPT`).
    Ephemeral {
        /// SAMv3 socket used to communicate with the client.
        socket: SamSocket<R>,

        /// Has the stream configured to be silent.
        silent: bool,
    },

    /// Listener used to accept all inbound virtual stream (`STREAM FORWARD`).
    Persistent {
        /// SAMv3 socket used the client used to send the `STREAM FORWARD` command.
        socket: SamSocket<R>,

        /// Port which the persistent TCP listener is listening on.
        port: u16,

        /// Has the stream configured to be silent.
        silent: bool,
    },
}

impl<R: Runtime> fmt::Debug for ListenerKind<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ephemeral { .. } =>
                f.debug_struct("ListenerKind::Ephemeral").finish_non_exhaustive(),
            Self::Persistent {
                socket,
                port,
                silent,
            } => f
                .debug_struct("ListenerKind::Persistent")
                .field("port", &port)
                .finish_non_exhaustive(),
        }
    }
}

/// Listener state.
///
/// [`StreamListener`] can alter between uninitialized, ephemeral and persisten states, depending on
/// which kind(s) of socket(s) are/is active. If all ephemeral sockets are consumed by incomming
/// connections, the state switches to uninitialized. Client can then register a new ephemeral or a
/// persisten listener. if a persistent listener is active, ephemeral listener is not allowed to be
/// registered until the socket that keeps the persistent listener open is closed. Then state
/// switches back to uninitialized and client can register another persistent or ephemeral socket.
enum ListenerState<R: Runtime> {
    /// Listener state is uninitialized.
    Uninitialized {
        /// Pending connections.
        pending: VecDeque<()>,
    },

    /// Listener is configured to be ephemeral.
    Ephemeral {
        /// Ephemeral sockest and their silence configuration.
        ///
        /// Each ephemeral socket is able to accept one stream.
        sockets: VecDeque<(SamSocket<R>, bool)>,
    },

    /// Listener is configured to be persistent.
    Persistent {
        /// Socket that was used to send the `STREAM FORWARD` command.
        socket: SamSocket<R>,

        /// Port of the active TCP listener.
        port: u16,

        /// Have the inbound streams been configured to be silent.
        silent: bool,
    },
}

/// I2P virtual stream listener.
pub struct StreamListener<R: Runtime> {
    /// ID of the local destination.
    destination_id: DestinationId,

    /// Listener state.
    state: ListenerState<R>,
}

impl<R: Runtime> StreamListener<R> {
    /// Create new [`StreamListener`].
    pub fn new(destination_id: DestinationId) -> Self {
        Self {
            destination_id,
            state: ListenerState::Uninitialized {
                pending: VecDeque::new(),
            },
        }
    }

    /// Register inbound `stream`.
    pub fn register_stream(&mut self, stream: ()) -> Result<(), StreamingError> {
        Ok(())
    }

    /// Register new listener `kind`.
    ///
    /// If `kind` is [`ListenerKind::Ephemeral`], push the listener into a set of pending listeners
    /// from which it will be taken when an inbound stream is received.
    ///
    /// If `kind` is [`ListenerKind::Persistent`], the store the port of the active TCP listener (on
    /// client side) into [`StreamManager`]'s context and when an inbond stream is received,
    /// establish new connection to the TCP listener.
    ///
    /// Active `STREAM ACCEPT` and `STREAM FORWARD` are mutually exclusive as per the specification.
    /// If user sent `STREAM ACCEPT` while there was an active `STREAM FORWARD` or vice versa, the
    /// follow-up listener kind is rejected.
    ///
    /// If there was a pending listener while a `STREAM ACCEPT` was received, the pending stream is
    /// associated with the new listener and any remaining listeners will remain in the pending
    /// state. If there were one or more pending streams while a `STREAM FORWARD` was received, the
    /// pending streams are associated with the active TCP listener and dispatched into background.
    pub fn register_listener(&mut self, kind: ListenerKind<R>) -> Result<(), StreamingError> {
        tracing::trace!(
            target: LOG_TARGET,
            local = %self.destination_id,
            ?kind,
            "register listener",
        );

        Ok(())
    }
}
