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
    error::Error,
    netdb::NetDbHandle,
    primitives::{Lease, TunnelId},
    runtime::{AddressBook, Runtime},
    sam::{
        parser::{DestinationContext, SamVersion, SessionKind},
        session::{SamSessionCommand, SamSessionCommandRecycle},
        socket::SamSocket,
    },
    tunnel::{TunnelPoolEvent, TunnelPoolHandle},
};

use futures::{future::BoxFuture, FutureExt, StreamExt};
use hashbrown::{HashMap, HashSet};
use thingbuf::mpsc::{Receiver, Sender};

use alloc::{string::String, sync::Arc, vec::Vec};
use core::{
    future::Future,
    mem,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::sam::pending::session";

/// SAMv3 client session context.
pub struct SamSessionContext<R: Runtime> {
    /// Address book, if specified.
    pub address_book: Option<Arc<dyn AddressBook>>,

    /// Active inbound tunnels and their leases.
    pub inbound: HashMap<TunnelId, Lease>,

    /// Session options.
    pub options: HashMap<String, String>,

    /// Destination context.
    pub destination: DestinationContext,

    /// Active outbound tunnels.
    pub outbound: HashSet<TunnelId>,

    /// Session ID.
    pub session_id: Arc<str>,

    /// Session kind.
    pub session_kind: SessionKind,

    /// SAMv3 socket.
    pub socket: SamSocket<R>,

    /// Tunnel pool handle.
    pub tunnel_pool_handle: TunnelPoolHandle,

    /// Handle to `NetDb`.
    pub netdb_handle: NetDbHandle,

    /// RX channel for receiving commands to an active session.
    pub receiver: Receiver<SamSessionCommand<R>, SamSessionCommandRecycle>,

    /// TX channel which can be used to send datagrams to clients.
    pub datagram_tx: Sender<(u16, Vec<u8>)>,
}

/// State of the pending I2CP client session.
enum PendingSessionState<R: Runtime> {
    /// Building tunnel pool.
    BuildingTunnelPool {
        /// Address book.
        address_book: Option<Arc<dyn AddressBook>>,

        /// SAMv3 socket associated with the session.
        socket: SamSocket<R>,

        /// ID of the client session.
        session_id: Arc<str>,

        /// Session kind.
        session_kind: SessionKind,

        /// Session options.
        options: HashMap<String, String>,

        /// Destination context.
        destination: DestinationContext,

        /// Negotiated version.
        version: SamVersion,

        /// Handle to `NetDb`.
        netdb_handle: NetDbHandle,

        /// Tunnel pool build future.
        ///
        /// Resolves to a `TunnelPoolHandle` once the pool has been built.
        tunnel_pool_future: BoxFuture<'static, TunnelPoolHandle>,

        /// RX channel for receiving commands to an active session.
        receiver: Receiver<SamSessionCommand<R>, SamSessionCommandRecycle>,

        /// TX channel which can be used to send datagrams to clients.
        datagram_tx: Sender<(u16, Vec<u8>)>,
    },

    /// Building tunnels.
    BuildingTunnels {
        /// Address book.
        address_book: Option<Arc<dyn AddressBook>>,

        /// SAMv3 socket associated with the session.
        socket: SamSocket<R>,

        /// Session ID.
        session_id: Arc<str>,

        /// Session kind.
        session_kind: SessionKind,

        /// Session options.
        options: HashMap<String, String>,

        /// Destination context.
        destination: DestinationContext,

        /// Negotiated version.
        version: SamVersion,

        /// Handle to `NetDb`.
        netdb_handle: NetDbHandle,

        /// Handle to the built tunnel pool.
        handle: TunnelPoolHandle,

        /// RX channel for receiving commands to an active session.
        receiver: Receiver<SamSessionCommand<R>, SamSessionCommandRecycle>,

        /// TX channel which can be used to send datagrams to clients.
        datagram_tx: Sender<(u16, Vec<u8>)>,

        /// Active inbound tunnels and their leases.
        inbound: HashMap<TunnelId, Lease>,

        /// Active outbound tunnels.
        outbound: HashSet<TunnelId>,
    },

    /// Pending connection state has been poisoned.
    Poisoned,
}

/// Pending SAMv3 sessions.
///
/// Builds a tunnel pool and waits for one inbound and one outbound tunnel to be built before
/// returning to [`SamSessionContext`] to `SamServer`, allowing it to start a `Destination`
/// for the connected client.
pub struct PendingSamSession<R: Runtime> {
    /// Session state.
    state: PendingSessionState<R>,
}

impl<R: Runtime> PendingSamSession<R> {
    /// Create new [`PendingSamSession`].
    pub fn new(
        socket: SamSocket<R>,
        destination: DestinationContext,
        session_id: Arc<str>,
        session_kind: SessionKind,
        options: HashMap<String, String>,
        version: SamVersion,
        receiver: Receiver<SamSessionCommand<R>, SamSessionCommandRecycle>,
        datagram_tx: Sender<(u16, Vec<u8>)>,
        tunnel_pool_future: BoxFuture<'static, TunnelPoolHandle>,
        netdb_handle: NetDbHandle,
        address_book: Option<Arc<dyn AddressBook>>,
    ) -> Self {
        Self {
            state: PendingSessionState::BuildingTunnelPool {
                address_book,
                datagram_tx,
                socket,
                session_id,
                session_kind,
                options,
                version,
                receiver,
                destination,
                tunnel_pool_future,
                netdb_handle,
            },
        }
    }
}

impl<R: Runtime> Future for PendingSamSession<R> {
    type Output = crate::Result<SamSessionContext<R>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match mem::replace(&mut self.state, PendingSessionState::Poisoned) {
                PendingSessionState::BuildingTunnelPool {
                    address_book,
                    socket,
                    session_id,
                    session_kind,
                    options,
                    destination,
                    version,
                    receiver,
                    datagram_tx,
                    netdb_handle,
                    mut tunnel_pool_future,
                } => match tunnel_pool_future.poll_unpin(cx) {
                    Poll::Ready(handle) => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            %session_id,
                            "tunnel pool for the session has been built",
                        );

                        self.state = PendingSessionState::BuildingTunnels {
                            address_book,
                            socket,
                            session_id,
                            session_kind,
                            options,
                            destination,
                            version,
                            handle,
                            receiver,
                            datagram_tx,
                            netdb_handle,
                            inbound: HashMap::new(),
                            outbound: HashSet::new(),
                        };
                    }
                    Poll::Pending => {
                        self.state = PendingSessionState::BuildingTunnelPool {
                            address_book,
                            socket,
                            session_id,
                            session_kind,
                            options,
                            destination,
                            version,
                            receiver,
                            datagram_tx,
                            netdb_handle,
                            tunnel_pool_future,
                        };
                        break;
                    }
                },
                PendingSessionState::BuildingTunnels {
                    address_book,
                    socket,
                    session_id,
                    session_kind,
                    options,
                    destination,
                    version,
                    receiver,
                    datagram_tx,
                    netdb_handle,
                    mut handle,
                    mut inbound,
                    mut outbound,
                } => match handle.poll_next_unpin(cx) {
                    Poll::Pending => {
                        self.state = PendingSessionState::BuildingTunnels {
                            address_book,
                            socket,
                            session_id,
                            session_kind,
                            options,
                            destination,
                            version,
                            netdb_handle,
                            receiver,
                            datagram_tx,
                            handle,
                            inbound,
                            outbound,
                        };
                        break;
                    }
                    Poll::Ready(None) => return Poll::Ready(Err(Error::EssentialTaskClosed)),
                    Poll::Ready(Some(TunnelPoolEvent::InboundTunnelBuilt { tunnel_id, lease })) => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            %session_id,
                            %tunnel_id,
                            "inbound tunnel built for pending session",
                        );
                        inbound.insert(tunnel_id, lease);

                        // `SESSION STATUS` shall not be sent until there is
                        // at least one inbound and outbound tunnel built
                        if inbound.len() == 0 || outbound.len() == 0 {
                            self.state = PendingSessionState::BuildingTunnels {
                                address_book,
                                socket,
                                session_id,
                                session_kind,
                                options,
                                destination,
                                version,
                                netdb_handle,
                                handle,
                                receiver,
                                datagram_tx,
                                inbound,
                                outbound,
                            };
                            continue;
                        }

                        tracing::debug!(
                            target: LOG_TARGET,
                            %session_id,
                            num_inbound = ?inbound.len(),
                            num_outbound = ?outbound.len(),
                            "publish destination's lease set",
                        );

                        return Poll::Ready(Ok(SamSessionContext {
                            address_book,
                            inbound,
                            options,
                            destination,
                            outbound,
                            session_id,
                            session_kind,
                            socket,
                            receiver,
                            datagram_tx,
                            netdb_handle,
                            tunnel_pool_handle: handle,
                        }));
                    }
                    Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelBuilt { tunnel_id })) => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            %session_id,
                            %tunnel_id,
                            "outbound tunnel built for pending session",
                        );
                        outbound.insert(tunnel_id);

                        // `SESSION STATUS` shall not be sent until there is
                        // at least one inbound and outbound tunnel built
                        if inbound.len() == 0 || outbound.len() == 0 {
                            self.state = PendingSessionState::BuildingTunnels {
                                address_book,
                                socket,
                                session_id,
                                session_kind,
                                options,
                                destination,
                                version,
                                netdb_handle,
                                handle,
                                receiver,
                                datagram_tx,
                                inbound,
                                outbound,
                            };
                            continue;
                        }

                        tracing::debug!(
                            target: LOG_TARGET,
                            %session_id,
                            num_inbound = ?inbound.len(),
                            num_outbound = ?outbound.len(),
                            "publish destination's lease set",
                        );

                        return Poll::Ready(Ok(SamSessionContext {
                            address_book,
                            inbound,
                            options,
                            destination,
                            outbound,
                            session_id,
                            session_kind,
                            socket,
                            receiver,
                            datagram_tx,
                            netdb_handle,
                            tunnel_pool_handle: handle,
                        }));
                    }
                    Poll::Ready(Some(TunnelPoolEvent::InboundTunnelExpired { tunnel_id })) => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            %session_id,
                            %tunnel_id,
                            "inbound tunnel expired for pending session",
                        );
                        inbound.remove(&tunnel_id);

                        self.state = PendingSessionState::BuildingTunnels {
                            address_book,
                            socket,
                            session_id,
                            session_kind,
                            options,
                            destination,
                            version,
                            netdb_handle,
                            handle,
                            receiver,
                            datagram_tx,
                            inbound,
                            outbound,
                        };
                    }
                    Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelExpired { tunnel_id })) => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            %session_id,
                            %tunnel_id,
                            "outbound tunnel expired for pending session",
                        );
                        outbound.remove(&tunnel_id);

                        self.state = PendingSessionState::BuildingTunnels {
                            address_book,
                            socket,
                            session_id,
                            session_kind,
                            options,
                            destination,
                            version,
                            netdb_handle,
                            handle,
                            receiver,
                            datagram_tx,
                            inbound,
                            outbound,
                        };
                    }
                    Poll::Ready(Some(event)) => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            %session_id,
                            ?event,
                            "unexpected event",
                        );

                        self.state = PendingSessionState::BuildingTunnels {
                            address_book,
                            socket,
                            session_id,
                            session_kind,
                            options,
                            destination,
                            version,
                            netdb_handle,
                            handle,
                            receiver,
                            datagram_tx,
                            inbound,
                            outbound,
                        };
                    }
                },
                PendingSessionState::Poisoned => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "pending session state has been poisoned",
                    );
                    debug_assert!(false);
                    return Poll::Ready(Err(Error::InvalidState));
                }
            }
        }

        Poll::Pending
    }
}
