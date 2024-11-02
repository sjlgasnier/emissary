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
    error::{ConnectionError, Error, StreamingError},
    primitives::DestinationId,
    runtime::{JoinSet, Runtime, TcpStream},
    sam::{
        protocol::streaming::{
            config::StreamConfig,
            stream::{Stream, StreamContext},
        },
        socket::SamSocket,
    },
    util::AsyncWriteExt,
};

use futures::{future::BoxFuture, StreamExt};
use nom::AsBytes;

use alloc::collections::VecDeque;
use core::{
    fmt,
    future::Future,
    mem,
    net::{IpAddr, Ipv4Addr, SocketAddr},
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

/// Listener kind while it's being initialized.
enum PendingListenerKind {
    /// Ephemeral listener (`STREAM ACCEPT`).
    Ephemeral,

    /// Persistent listener (`STREAM FORWARD`).
    Persistent {
        /// Port where the TCP listener is listening on.
        port: u16,

        /// Have the streams been configured to be silent.
        silent: bool,
    },
}

impl fmt::Debug for PendingListenerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ephemeral => f.debug_struct("PendingListenerKind::Ephemeral").finish(),
            Self::Persistent { port, silent } => f
                .debug_struct("PendingListenerKind::Persistent")
                .field("port", &port)
                .field("silent", &silent)
                .finish(),
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

    /// Listener state is being initialized.
    ///
    /// Essentially this means that the connected client is being notified that the accept/forward
    /// request has been accepted and the socket is busy writing the message to client. Once the
    /// write has finished, [`StreamListener`] initializes itself to either
    /// [`ListenerState::Ephemeral`] (`STREAM ACCEPT`) or [`ListenerState::Persistent`] (`STREAM
    /// FORWARD`).
    Initializing {
        /// Listener kind.
        ///
        /// Which state shall [`StreamListener`] take after it has been initialized.
        kind: PendingListenerKind,
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
            Self::Initializing { kind } =>
                f.debug_struct("ListenerState::Initialzing").field("kind", &kind).finish(),
            Self::Ephemeral { sockets } => f
                .debug_struct("ListenerState::Ephemeral")
                .field("num_listeners", &sockets.len())
                .finish(),
            Self::Persistent { port, .. } => f
                .debug_struct("ListenerState::Persistent")
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
                    StreamConfig::default(),
                ));

                match sockets.is_empty() {
                    true => {
                        self.state = ListenerState::Uninitialized {
                            pending: VecDeque::new(),
                        };
                    }
                    false => {
                        self.state = ListenerState::Ephemeral { sockets };
                    }
                }
            }
            ListenerState::Persistent {
                socket,
                port,
                silent,
            } => {
                // if the socket wasn't configured to be silent, send the remote's destination
                // to client before the socket is convered into a regural tcp stream
                let initial_message = (!silent)
                    .then(|| format!("{}\n", base64_encode(context.remote.to_vec())).into_bytes());

                // start new future for the stream in the background
                //
                // if `SILENT` was set to false, the first message `Stream` sends to the connected
                // client is the destination id of the remote peer after which it transfers to send
                // anything that was received from the remote peer via `StreamManager`
                self.streams.push(async move {
                    let Some(mut stream) = R::TcpStream::connect(SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::LOCALHOST),
                        port,
                    ))
                    .await
                    else {
                        tracing::warn!(
                            target: LOG_TARGET,
                            "failed to open tcp stream to forwarded listener",
                        );
                        return context.recv_stream_id;
                    };

                    Stream::<R>::new(stream, initial_message, context, StreamConfig::default())
                        .await
                });

                self.state = ListenerState::Persistent {
                    socket,
                    port,
                    silent,
                };
            }
            state => {
                tracing::error!(target: LOG_TARGET, ?state, "state not supported");
                panic!("support not implemented for {state:?}");
            }
        }

        Ok(())
    }

    /// Validate that `kind` is an approriate listener kind with the current state.
    ///
    /// `STREAM ACCEPT` and `STREAM FORWARD` are mutually exclusive and the second socket for the
    /// incompatible kind is rejected. Multiple `STREAM FORWARD`s are also not supported.
    ///
    /// On success the function returns `kind` so the caller can process it normally and on error
    /// the function returns `None` and sends a rejection message to the client.
    fn validate_listener(&mut self, kind: ListenerKind<R>) -> Option<ListenerKind<R>> {
        match (&self.state, kind) {
            // state can be either uninitialized or initializing/initialized to be ephemeral
            (
                ListenerState::Ephemeral { .. }
                | ListenerState::Uninitialized { .. }
                | ListenerState::Initializing {
                    kind: PendingListenerKind::Ephemeral,
                },
                kind @ ListenerKind::Ephemeral { .. },
            ) => return Some(kind),

            // only an unitialized listener can accept `STREAM FORWARD`
            (ListenerState::Uninitialized { .. }, kind @ ListenerKind::Persistent { .. }) =>
                return Some(kind),

            // all other states are invalid and the accept requested is rejected
            (state, kind @ (ListenerKind::Ephemeral { .. } | ListenerKind::Persistent { .. })) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    state = ?self.state,
                    ?kind,
                    "invalid (state, kind) combination for listener",
                );

                match kind {
                    ListenerKind::Ephemeral { mut socket, .. }
                    | ListenerKind::Persistent { mut socket, .. } => {
                        R::spawn(async move {
                            let _ = socket
                                .send_message_blocking(
                                    "STREAM STATUS RESULT=I2P_ERROR\n".as_bytes().to_vec(),
                                )
                                .await;
                            let _ = socket.into_inner().close().await;
                        });
                    }
                }

                None
            }
        }
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
        let kind = self.validate_listener(kind).ok_or(StreamingError::ListenerMismatch)?;

        // initialize socket if it needs to be and update listener state
        //
        // if `SILENT` was set to false (default), send acceptance notification in a new future
        // and update listener state
        //
        // if the state is uninitialize and a message must be sent to user, the listener is put into
        // `Initializing` state which indicates that at least one socket is being initialized for
        // accepting a new connection
        match (&mut self.state, kind) {
            (
                ListenerState::Uninitialized { pending },
                ListenerKind::Ephemeral { mut socket, silent },
            ) if pending.is_empty() => match silent {
                true =>
                    self.state = ListenerState::Ephemeral {
                        sockets: VecDeque::from_iter([(socket, silent)]),
                    },
                false => {
                    self.state = ListenerState::Initializing {
                        kind: PendingListenerKind::Ephemeral,
                    };

                    self.pending_sockets.push(async move {
                        socket
                            .send_message_blocking("STREAM STATUS RESULT=OK\n".as_bytes().to_vec())
                            .await
                            .map(|()| socket)
                    });
                    self.waker.take().map(|waker| waker.wake_by_ref());
                }
            },
            (
                ListenerState::Initializing {
                    kind: PendingListenerKind::Ephemeral,
                },
                ListenerKind::Ephemeral { mut socket, silent },
            ) => match silent {
                true =>
                    self.state = ListenerState::Ephemeral {
                        sockets: VecDeque::from_iter([(socket, silent)]),
                    },
                false => {
                    self.state = ListenerState::Initializing {
                        kind: PendingListenerKind::Ephemeral,
                    };

                    self.pending_sockets.push(async move {
                        socket
                            .send_message_blocking("STREAM STATUS RESULT=OK\n".as_bytes().to_vec())
                            .await
                            .map(|()| socket)
                    });
                    self.waker.take().map(|waker| waker.wake_by_ref());
                }
            },
            (
                ListenerState::Ephemeral { ref mut sockets },
                ListenerKind::Ephemeral { mut socket, silent },
            ) => match silent {
                true => {
                    sockets.push_back((socket, silent));
                }
                false => {
                    self.pending_sockets.push(async move {
                        socket
                            .send_message_blocking("STREAM STATUS RESULT=OK\n".as_bytes().to_vec())
                            .await
                            .map(|()| socket)
                    });
                    self.waker.take().map(|waker| waker.wake_by_ref());
                }
            },
            (
                ListenerState::Uninitialized { pending },
                ListenerKind::Persistent {
                    mut socket,
                    port,
                    silent,
                },
            ) if pending.is_empty() => {
                self.state = ListenerState::Initializing {
                    kind: PendingListenerKind::Persistent { port, silent },
                };

                // from specification:
                //
                // "Whether SILENT is true or false, the SAM bridge always answers with a STREAM
                // STATUS message. Note that this is a different behavior from STREAM ACCEPT and
                // STREAM CONNECT when SILENT=true"
                //
                // https://geti2p.net/en/docs/api/samv3
                self.pending_sockets.push(async move {
                    socket
                        .send_message_blocking("STREAM STATUS RESULT=OK\n".as_bytes().to_vec())
                        .await
                        .map(|()| socket)
                });
                self.waker.take().map(|waker| waker.wake_by_ref());
            }
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
                        ListenerState::Initializing { kind } => match kind {
                            PendingListenerKind::Ephemeral => {
                                self.state = ListenerState::Ephemeral {
                                    sockets: VecDeque::from_iter([(socket, false)]),
                                };
                            }
                            PendingListenerKind::Persistent { port, silent } => {
                                self.state = ListenerState::Persistent {
                                    socket,
                                    port,
                                    silent,
                                };
                            }
                        },
                        state => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                ?state,
                                "invalid listener state for ready socket",
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
    use crate::runtime::{
        mock::{MockRuntime, MockTcpStream},
        noop::{NoopRuntime, NoopTcpStream},
    };
    use std::time::Duration;
    use thingbuf::mpsc::channel;
    use tokio::{io::AsyncReadExt, net::TcpListener};

    #[test]
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

    #[test]
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

    #[test]
    fn register_multiple_ephemeral_listeners() {
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

        match &listener.state {
            ListenerState::Initializing {
                kind: PendingListenerKind::Ephemeral,
            } => {}
            _ => panic!("invalid state"),
        }

        assert!(listener
            .register_listener(ListenerKind::Ephemeral {
                socket: SamSocket::new(NoopTcpStream::new()),
                silent: false
            })
            .is_ok());

        match &listener.state {
            ListenerState::Initializing {
                kind: PendingListenerKind::Ephemeral,
            } => {}
            _ => panic!("invalid state"),
        }
    }

    #[test]
    fn register_multiple_silent_ephemeral_listeners() {
        let mut listener = StreamListener::<NoopRuntime>::new(DestinationId::random());
        match &listener.state {
            ListenerState::Uninitialized { pending } if pending.is_empty() => {}
            _ => panic!("invalid state"),
        }

        assert!(listener
            .register_listener(ListenerKind::Ephemeral {
                socket: SamSocket::new(NoopTcpStream::new()),
                silent: true,
            })
            .is_ok());

        match &listener.state {
            ListenerState::Ephemeral { sockets } if sockets.len() == 1 => {}
            _ => panic!("invalid state"),
        }

        assert!(listener
            .register_listener(ListenerKind::Ephemeral {
                socket: SamSocket::new(NoopTcpStream::new()),
                silent: true
            })
            .is_ok());

        match &listener.state {
            ListenerState::Ephemeral { sockets } if sockets.len() == 2 => {}
            _ => panic!("invalid state"),
        }
    }

    #[test]
    fn register_multiple_persistent_listeners() {
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
            listener.register_listener(ListenerKind::Persistent {
                socket: SamSocket::new(NoopTcpStream::new()),
                port: 1338,
                silent: false
            }),
            Err(StreamingError::ListenerMismatch)
        );
    }

    #[tokio::test]
    async fn pending_socket_initialized() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let mut listener = StreamListener::<MockRuntime>::new(DestinationId::random());
        match &listener.state {
            ListenerState::Uninitialized { pending } if pending.is_empty() => {}
            _ => panic!("invalid state"),
        }

        assert!(listener
            .register_listener(ListenerKind::Persistent {
                socket: SamSocket::new(stream2.unwrap()),
                port: 1337,
                silent: false
            })
            .is_ok());

        match &listener.state {
            ListenerState::Initializing {
                kind:
                    PendingListenerKind::Persistent {
                        port: 1337,
                        silent: false,
                    },
            } => {}
            _ => panic!("invalid state"),
        }

        while !listener.pending_sockets.is_empty() {
            futures::future::poll_fn(|cx| match listener.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Ready(()),
                Poll::Ready(_) => panic!("invalid event"),
            })
            .await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        match &listener.state {
            ListenerState::Persistent {
                port: 1337,
                silent: false,
                ..
            } => {}
            _ => panic!("invalid state"),
        }
    }

    #[tokio::test]
    async fn register_silent_and_non_silent_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, eph1) = tokio::join!(listener.accept(), MockTcpStream::connect(address));
        let (stream2, eph2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let mut listener = StreamListener::<MockRuntime>::new(DestinationId::random());
        match &listener.state {
            ListenerState::Uninitialized { pending } if pending.is_empty() => {}
            _ => panic!("invalid state"),
        }

        assert!(listener
            .register_listener(ListenerKind::Ephemeral {
                socket: SamSocket::new(eph1.unwrap()),
                silent: false
            })
            .is_ok());

        match &listener.state {
            ListenerState::Initializing {
                kind: PendingListenerKind::Ephemeral,
            } => {}
            _ => panic!("invalid state"),
        }

        // register another ephemeral listener but this time it's silent
        assert!(listener
            .register_listener(ListenerKind::Ephemeral {
                socket: SamSocket::new(eph2.unwrap()),
                silent: true,
            })
            .is_ok());

        match &listener.state {
            ListenerState::Ephemeral { sockets } if sockets.len() == 1 => {}
            _ => panic!("invalid state"),
        }

        // poll the other pending socket until it's ready
        while !listener.pending_sockets.is_empty() {
            futures::future::poll_fn(|cx| match listener.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Ready(()),
                Poll::Ready(_) => panic!("invalid event"),
            })
            .await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // verify there are two listeners
        match &listener.state {
            ListenerState::Ephemeral { sockets } if sockets.len() == 2 => {}
            _ => panic!("invalid state"),
        }
    }

    #[tokio::test]
    async fn register_stream_while_listener_is_pending() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, eph1) = tokio::join!(listener.accept(), MockTcpStream::connect(address));
        let (stream2, eph2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let mut listener = StreamListener::<MockRuntime>::new(DestinationId::random());
        match &listener.state {
            ListenerState::Uninitialized { pending } if pending.is_empty() => {}
            _ => panic!("invalid state"),
        }

        assert!(listener
            .register_listener(ListenerKind::Ephemeral {
                socket: SamSocket::new(eph1.unwrap()),
                silent: false
            })
            .is_ok());

        match &listener.state {
            ListenerState::Initializing {
                kind: PendingListenerKind::Ephemeral,
            } => {}
            _ => panic!("invalid state"),
        }

        // register another ephemeral listener but this time it's silent
        assert!(listener
            .register_listener(ListenerKind::Ephemeral {
                socket: SamSocket::new(eph2.unwrap()),
                silent: true,
            })
            .is_ok());

        match &listener.state {
            ListenerState::Ephemeral { sockets } if sockets.len() == 1 => {}
            _ => panic!("invalid state"),
        }

        let (cmd_tx, cmd_rx) = channel(1);
        let (event_tx, event_rx) = channel(1);
        let _ = listener.register_stream(StreamContext {
            cmd_rx,
            event_tx,
            local: DestinationId::random(),
            recv_stream_id: 1337u32,
            remote: DestinationId::random(),
        });

        match &listener.state {
            ListenerState::Uninitialized { .. } => {}
            _ => panic!("invalid state"),
        }

        // poll the other pending socket until it's ready
        while !listener.pending_sockets.is_empty() {
            futures::future::poll_fn(|cx| match listener.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Ready(()),
                Poll::Ready(_) => panic!("invalid event"),
            })
            .await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // verify there are two listeners
        match &listener.state {
            ListenerState::Ephemeral { sockets } if sockets.len() == 1 => {}
            _ => panic!("invalid state"),
        }
    }

    #[tokio::test]
    async fn two_active_listeners() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, eph1) = tokio::join!(listener.accept(), MockTcpStream::connect(address));
        let (stream2, eph2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let mut listener = StreamListener::<MockRuntime>::new(DestinationId::random());
        match &listener.state {
            ListenerState::Uninitialized { pending } if pending.is_empty() => {}
            _ => panic!("invalid state"),
        }

        assert!(listener
            .register_listener(ListenerKind::Ephemeral {
                socket: SamSocket::new(eph1.unwrap()),
                silent: true
            })
            .is_ok());

        match &listener.state {
            ListenerState::Ephemeral { sockets } if sockets.len() == 1 => {}
            _ => panic!("invalid state"),
        }

        assert!(listener
            .register_listener(ListenerKind::Ephemeral {
                socket: SamSocket::new(eph2.unwrap()),
                silent: true,
            })
            .is_ok());

        match &listener.state {
            ListenerState::Ephemeral { sockets } if sockets.len() == 2 => {}
            _ => panic!("invalid state"),
        }

        let (cmd_tx, cmd_rx) = channel(1);
        let (event_tx, event_rx) = channel(1);
        let _ = listener.register_stream(StreamContext {
            cmd_rx,
            event_tx,
            local: DestinationId::random(),
            recv_stream_id: 1337u32,
            remote: DestinationId::random(),
        });

        match &listener.state {
            ListenerState::Ephemeral { sockets } if sockets.len() == 1 => {}
            _ => panic!("invalid state"),
        }

        let (cmd_tx, cmd_rx) = channel(1);
        let (event_tx, event_rx) = channel(1);
        let _ = listener.register_stream(StreamContext {
            cmd_rx,
            event_tx,
            local: DestinationId::random(),
            recv_stream_id: 1337u32,
            remote: DestinationId::random(),
        });

        match &listener.state {
            ListenerState::Uninitialized { .. } => {}
            _ => panic!("invalid state"),
        }
    }

    #[tokio::test]
    async fn persistent_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let mut listener = StreamListener::<MockRuntime>::new(DestinationId::random());
        match &listener.state {
            ListenerState::Uninitialized { pending } if pending.is_empty() => {}
            _ => panic!("invalid state"),
        }

        assert!(listener
            .register_listener(ListenerKind::Persistent {
                socket: SamSocket::new(stream2.unwrap()),
                port: 1337,
                silent: false
            })
            .is_ok());

        match &listener.state {
            ListenerState::Initializing {
                kind:
                    PendingListenerKind::Persistent {
                        port: 1337,
                        silent: false,
                    },
            } => {}
            _ => panic!("invalid state"),
        }

        while !listener.pending_sockets.is_empty() {
            futures::future::poll_fn(|cx| match listener.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Ready(()),
                Poll::Ready(_) => panic!("invalid event"),
            })
            .await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        match &listener.state {
            ListenerState::Persistent {
                port: 1337,
                silent: false,
                ..
            } => {}
            _ => panic!("invalid state"),
        }

        // multiple streams can be registered
        for _ in 0..5 {
            let (cmd_tx, cmd_rx) = channel(1);
            let (event_tx, event_rx) = channel(1);
            let _ = listener.register_stream(StreamContext {
                cmd_rx,
                event_tx,
                local: DestinationId::random(),
                recv_stream_id: 1337u32,
                remote: DestinationId::random(),
            });

            match &listener.state {
                ListenerState::Persistent {
                    port: 1337,
                    silent: false,
                    ..
                } => {}
                _ => panic!("invalid state"),
            }
        }
    }
}
