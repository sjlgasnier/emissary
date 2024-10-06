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

//! Pending I2CP client session.
//!
//! IC2P client session is considered pending until the client has sent a `CreateSession` message
//! and a tunnel pool with at least one inbound tunnel has been built for the session.
//!
//! After these two conditions have been met, the pending session is destroyed and a new active
//! session is created from the pending context.

use crate::{
    i2cp::{
        message::{BandwidthLimits, Message, SessionId, SessionStatus, SessionStatusKind, SetDate},
        socket::I2cpSocket,
    },
    primitives::{Date, Lease2, Str, TunnelId},
    runtime::Runtime,
    tunnel::{TunnelManagerHandle, TunnelPoolEvent, TunnelPoolHandle},
};

use futures::{future::BoxFuture, FutureExt, StreamExt};
use hashbrown::{HashMap, HashSet};

use core::{
    future::Future,
    mem,
    pin::Pin,
    str::FromStr,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::i2cp::pending-session";

/// I2CP client session context.
pub struct I2cpSessionContext<R: Runtime> {
    /// Active inbound tunnels and their leases.
    pub inbound: HashMap<TunnelId, Lease2>,

    /// Active outbound tunnels.
    pub outbound: HashSet<TunnelId>,

    /// Session ID.
    pub session_id: u16,

    /// I2CP socket.
    pub socket: I2cpSocket<R>,

    /// Tunnel pool handle.
    pub tunnel_pool_handle: TunnelPoolHandle,
}

/// State of the pending I2CP client session.
enum PendingSessionState<R: Runtime> {
    /// I2CP session doesn't have an active tunnel pool.
    Inactive {
        /// Session ID.
        session_id: u16,

        /// I2CP socket.
        socket: I2cpSocket<R>,
    },

    /// The tunnel pool itself is being built.
    BuildingPool {
        /// Session ID.
        session_id: u16,

        /// I2CP socket.
        socket: I2cpSocket<R>,

        /// Tunnel pool build future.
        ///
        /// Resolves to a `TunnelPoolHandle` once the pool has been built.
        tunnel_pool_future: BoxFuture<'static, TunnelPoolHandle>,
    },

    /// Building tunnels of the tunnel pool.
    ///
    /// As soon as the the first inbound tunnel is built,
    /// the state is switched to [`TunnnelPoolState::Active`].
    BuildingTunnels {
        /// Session ID.
        session_id: u16,

        /// I2CP socket.
        socket: I2cpSocket<R>,

        /// Handle to the built tunnel pool.
        handle: TunnelPoolHandle,

        /// Active inbound tunnels and their leases.
        inbound: HashMap<TunnelId, Lease2>,

        /// Active outbound tunnels.
        outbound: HashSet<TunnelId>,
    },

    /// Tunnel pool state is poisoned.
    Poisoned,
}

impl<R: Runtime> PendingSessionState<R> {
    /// Get mutable reference to session's `I2cpSocket`.
    ///
    /// Panics if called after the session has been poisoned.
    fn socket(&mut self) -> &mut I2cpSocket<R> {
        match self {
            Self::Inactive { socket, .. } => socket,
            Self::BuildingPool { socket, .. } => socket,
            Self::BuildingTunnels { socket, .. } => socket,
            Self::Poisoned => unreachable!(),
        }
    }

    /// Get session ID of the pending session.
    ///
    /// Panics if called after the session has been poisoned.
    fn session_id(&self) -> u16 {
        match self {
            Self::Inactive { session_id, .. } => *session_id,
            Self::BuildingPool { session_id, .. } => *session_id,
            Self::BuildingTunnels { session_id, .. } => *session_id,
            Self::Poisoned => unreachable!(),
        }
    }
}

/// Pending I2CP client session.
pub struct PendingI2cpSession<R: Runtime> {
    /// Handle to `TunnelManager`.
    tunnel_manager_handle: TunnelManagerHandle,

    /// State of the pending session.
    state: PendingSessionState<R>,
}

impl<R: Runtime> PendingI2cpSession<R> {
    /// Create new [`I2cpSession`] from `stream`.
    pub fn new(
        session_id: u16,
        socket: I2cpSocket<R>,
        tunnel_manager_handle: TunnelManagerHandle,
    ) -> Self {
        Self {
            tunnel_manager_handle,
            state: PendingSessionState::Inactive { session_id, socket },
        }
    }

    /// Handle I2CP message received from the client.
    fn on_message(&mut self, message: Message) {
        match message {
            Message::GetDate { version, options } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    %version,
                    ?options,
                    "get date, send set date",
                );

                self.state.socket().send_message(SetDate::new(
                    Date::new(R::time_since_epoch().as_millis() as u64),
                    Str::from_str("0.9.63").expect("to succeed"),
                ));
            }
            Message::GetBandwidthLimits => {
                tracing::trace!(
                    target: LOG_TARGET,
                    "handle bandwidth limit request",
                );

                self.state.socket().send_message(BandwidthLimits::new());
            }
            Message::DestroySession { session_id } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    ?session_id,
                    "destroy session",
                );

                self.state
                    .socket()
                    .send_message(SessionStatus::new(session_id, SessionStatusKind::Destroyed));
            }
            Message::CreateSession {
                destination,
                date,
                options,
            } => {
                let session_id = self.state.session_id();

                tracing::info!(
                    target: LOG_TARGET,
                    ?session_id,
                    destination = %destination.id(),
                    ?date,
                    num_options = ?options.len(),
                    "create session",
                );

                self.state.socket().send_message(SessionStatus::new(
                    SessionId::Session(session_id),
                    SessionStatusKind::Created,
                ));

                // TODO: introduce `TunnelManager`
                // TODO:  - allow creating new `TunnelManagerHandle`
                // TODO: parse tunnel pool config from options
                // TODO: create tunnel pool
                // TODO: return new kind of handle from `TunnelManager`
            }
            _ => {}
        }
    }
}

impl<R: Runtime> Future for PendingI2cpSession<R> {
    type Output = Option<I2cpSessionContext<R>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.state.socket().poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(message)) => self.on_message(message),
            }
        }

        loop {
            match mem::replace(&mut self.state, PendingSessionState::Poisoned) {
                state @ PendingSessionState::Inactive { .. } => {
                    self.state = state;
                    break;
                }
                PendingSessionState::BuildingPool {
                    session_id,
                    socket,
                    mut tunnel_pool_future,
                } => match tunnel_pool_future.poll_unpin(cx) {
                    Poll::Ready(handle) => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            ?session_id,
                            "tunnel pool for the session has been built",
                        );

                        self.state = PendingSessionState::BuildingTunnels {
                            session_id,
                            socket,
                            handle,
                            inbound: HashMap::new(),
                            outbound: HashSet::new(),
                        };
                    }
                    Poll::Pending => {
                        self.state = PendingSessionState::BuildingPool {
                            session_id,
                            socket,
                            tunnel_pool_future,
                        };
                        break;
                    }
                },
                PendingSessionState::BuildingTunnels {
                    session_id,
                    socket,
                    mut handle,
                    mut inbound,
                    mut outbound,
                } => match handle.poll_next_unpin(cx) {
                    Poll::Pending => {
                        self.state = PendingSessionState::BuildingTunnels {
                            session_id,
                            socket,
                            handle,
                            inbound,
                            outbound,
                        };
                        break;
                    }
                    Poll::Ready(None) => return Poll::Ready(None),
                    Poll::Ready(Some(TunnelPoolEvent::InboundTunnelBuilt { tunnel_id, lease })) => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            ?session_id,
                            "first inbound tunnel built for pending session",
                        );
                        inbound.insert(tunnel_id, lease);

                        return Poll::Ready(Some(I2cpSessionContext {
                            inbound,
                            outbound,
                            tunnel_pool_handle: handle,
                            session_id,
                            socket,
                        }));
                    }
                    Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelBuilt { tunnel_id })) => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            ?session_id,
                            "outbound tunnel built for pending session",
                        );
                        outbound.insert(tunnel_id);

                        self.state = PendingSessionState::BuildingTunnels {
                            session_id,
                            socket,
                            handle,
                            inbound,
                            outbound,
                        };
                    }
                    Poll::Ready(Some(TunnelPoolEvent::InboundTunnelExpired { tunnel_id })) => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?session_id,
                            "inbound tunnel expired for pending session",
                        );
                        inbound.remove(&tunnel_id);

                        self.state = PendingSessionState::BuildingTunnels {
                            session_id,
                            socket,
                            handle,
                            inbound,
                            outbound,
                        };
                    }
                    Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelExpired { tunnel_id })) => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?session_id,
                            "outbound tunnel expired for pending session",
                        );
                        outbound.remove(&tunnel_id);

                        self.state = PendingSessionState::BuildingTunnels {
                            session_id,
                            socket,
                            handle,
                            inbound,
                            outbound,
                        };
                    }
                    Poll::Ready(Some(event)) => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?session_id,
                            ?event,
                            "unexpected event",
                        );

                        self.state = PendingSessionState::BuildingTunnels {
                            session_id,
                            socket,
                            handle,
                            inbound,
                            outbound,
                        };
                    }
                },
                PendingSessionState::Poisoned => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "pending i2cp session tunnel pool state is poisoned",
                    );

                    return Poll::Ready(None);
                }
            }
        }

        Poll::Pending
    }
}
