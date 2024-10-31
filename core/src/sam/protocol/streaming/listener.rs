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
    crypto::base64_encode,
    error::StreamingError,
    primitives::DestinationId,
    runtime::{JoinSet, Runtime},
    sam::{
        protocol::streaming::stream::{Stream, StreamContext},
        socket::SamSocket,
    },
};

use futures::StreamExt;
use nom::AsBytes;

use alloc::collections::VecDeque;
use core::{
    fmt, mem,
    pin::Pin,
    task::{Context, Poll, Waker},
};

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
            Self::Persistent { port, .. } => f
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

    /// Listener state has been poisoned.
    Poisoned,
}

impl<R: Runtime> fmt::Debug for ListenerState<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uninitialized { pending } => f
                .debug_struct("ListenerState::Uninitialized")
                .field("num_pending", &pending.len())
                .finish(),
            Self::Ephemeral { sockets } => f
                .debug_struct("ListenerState::Ephemeral")
                .field("num_listeners", &sockets.len())
                .finish(),
            Self::Persistent { port, .. } => f
                .debug_struct("ListenerState::Ephemeral")
                .field("port", &port)
                .finish_non_exhaustive(),
            Self::Poisoned => f.debug_struct("ListenerState::Poisoned").finish(),
        }
    }
}

/// I2P virtual stream listener.
pub struct StreamListener<R: Runtime> {
    /// ID of the local destination.
    destination_id: DestinationId,

    /// Pending sockets.
    pending_sockets: R::JoinSet<crate::Result<SamSocket<R>>>,

    /// Listener state.
    state: ListenerState<R>,

    /// Active streams.
    streams: R::JoinSet<u32>,

    /// Waker, if any.
    waker: Option<Waker>,
}

impl<R: Runtime> StreamListener<R> {
    /// Create new [`StreamListener`].
    pub fn new(destination_id: DestinationId) -> Self {
        Self {
            destination_id,
            pending_sockets: R::join_set(),
            state: ListenerState::Uninitialized {
                pending: VecDeque::new(),
            },
            streams: R::join_set(),
            waker: None,
        }
    }

    /// Register inbound `stream`.
    pub fn register_stream(&mut self, context: StreamContext) -> Result<(), StreamingError> {
        tracing::debug!(
            target: LOG_TARGET,
            local = %self.destination_id,
            remote = %context.remote,
            "register stream",
        );

        match mem::replace(&mut self.state, ListenerState::Poisoned) {
            ListenerState::Ephemeral { mut sockets } => {
                // socket must exist since the ephemeral state was active
                let (socket, silent) = sockets.pop_front().expect("to exist");

                // if the socket wasn't configured to be silent, send the remote's destination
                // to client before the socket is convered into a regural tcp stream
                let initial_message = (!silent)
                    .then(|| format!("{}\n", base64_encode(context.remote.to_vec())).into_bytes());

                // start new future for the stream in the background
                //
                // if `SILENT` was set to false, the first message `Stream` sends to the connected
                // client is the destination id of the remote peer after which it transfers to send
                // anything that was received from the remote peer via `StreamManager`
                self.streams.push(Stream::<R>::new(
                    socket.into_inner(),
                    initial_message,
                    context,
                ));

                assert!(sockets.is_empty());
                self.state = ListenerState::Uninitialized {
                    pending: VecDeque::new(),
                };
            }
            state => panic!("support not implemented for {state:?}"),
        }

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
        tracing::debug!(
            target: LOG_TARGET,
            local = %self.destination_id,
            ?kind,
            "register listener",
        );

        // ensure `kind` is valid with listener's current state
        match (&self.state, &kind) {
            (ListenerState::Ephemeral { .. }, ListenerKind::Persistent { .. }) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    "cannot register persistent listener when ephemeral is active",
                );
                return Err(StreamingError::ListenerMismatch);
            }
            (ListenerState::Persistent { .. }, ListenerKind::Ephemeral { .. }) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    "cannot register ephemeral listener when persistent is active",
                );
                return Err(StreamingError::ListenerMismatch);
            }
            (ListenerState::Persistent { .. }, ListenerKind::Persistent { .. }) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    "cannot register duplicate persistent listener",
                );
                return Err(StreamingError::ListenerMismatch);
            }
            _ => {}
        }

        // TODO: if listener is accepted, client must be notified
        // TODO: this needs a lot of documentation
        match (&self.state, kind) {
            (
                ListenerState::Uninitialized { pending },
                ListenerKind::Ephemeral { mut socket, silent },
            ) if pending.is_empty() => match silent {
                true =>
                    self.state = ListenerState::Ephemeral {
                        sockets: VecDeque::from_iter([(socket, silent)]),
                    },
                false => {
                    self.pending_sockets.push(async move {
                        socket
                            .send_message_blocking("STREAM STATUS RESULT=OK\n".as_bytes().to_vec())
                            .await
                            .map(|()| socket)
                    });
                    self.waker.take().map(|waker| waker.wake_by_ref());
                    self.state = ListenerState::Uninitialized {
                        pending: VecDeque::new(),
                    };
                }
            },
            state => todo!("not implemented: {state:?}"),
        }

        Ok(())
    }
}

impl<R: Runtime> futures::Stream for StreamListener<R> {
    type Item = u32;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.pending_sockets.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(Err(error))) => tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    ?error,
                    "failed to send status message",
                ),
                Poll::Ready(Some(Ok(socket))) =>
                    match mem::replace(&mut self.state, ListenerState::Poisoned) {
                        ListenerState::Uninitialized { pending } => {
                            // connection wasn't configured to be silent because
                            // a status message was sent to the client
                            self.state = ListenerState::Ephemeral {
                                sockets: VecDeque::from_iter([(socket, false)]),
                            };
                        }
                        ListenerState::Ephemeral { mut sockets } => {
                            sockets.push_back((socket, false));
                            self.state = ListenerState::Ephemeral { sockets };
                        }
                        ListenerState::Persistent {
                            socket,
                            port,
                            silent,
                        } => todo!("fix race condition"),
                        ListenerState::Poisoned => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                "listener state is poisoned",
                            );
                            debug_assert!(false);
                            return Poll::Ready(None);
                        }
                    },
            }
        }

        loop {
            match self.streams.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(stream_id)) => return Poll::Ready(Some(stream_id)),
            }
        }

        self.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::noop::{NoopRuntime, NoopTcpStream};

    // #[test]
    fn register_persistent_when_ephemeral_is_active() {
        let mut listener = StreamListener::<NoopRuntime>::new(DestinationId::random());
        match &listener.state {
            ListenerState::Uninitialized { pending } if pending.is_empty() => {}
            _ => panic!("invalid state"),
        }

        assert!(listener
            .register_listener(ListenerKind::Ephemeral {
                socket: SamSocket::new(NoopTcpStream::new()),
                silent: false,
            })
            .is_ok());

        assert_eq!(
            listener.register_listener(ListenerKind::Persistent {
                socket: SamSocket::new(NoopTcpStream::new()),
                port: 1337,
                silent: false
            }),
            Err(StreamingError::ListenerMismatch)
        );
    }

    // #[test]
    fn register_ephemeral_when_persistent_is_active() {
        let mut listener = StreamListener::<NoopRuntime>::new(DestinationId::random());
        match &listener.state {
            ListenerState::Uninitialized { pending } if pending.is_empty() => {}
            _ => panic!("invalid state"),
        }

        assert!(listener
            .register_listener(ListenerKind::Persistent {
                socket: SamSocket::new(NoopTcpStream::new()),
                port: 1337,
                silent: false
            })
            .is_ok());

        assert_eq!(
            listener.register_listener(ListenerKind::Ephemeral {
                socket: SamSocket::new(NoopTcpStream::new()),
                silent: false
            }),
            Err(StreamingError::ListenerMismatch)
        );
    }

    // #[test]
    fn register_multiple_ephemeral_listeners() {}

    // #[test]
    fn register_multiple_persistent_listeners() {}
}
