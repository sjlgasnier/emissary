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
    primitives::{Date, Lease, Str, TunnelId},
    runtime::Runtime,
    tunnel::{TunnelManagerHandle, TunnelPoolConfig, TunnelPoolEvent, TunnelPoolHandle},
};

use futures::{future::BoxFuture, FutureExt, StreamExt};
use hashbrown::{HashMap, HashSet};

use alloc::{boxed::Box, string::ToString};
use core::{
    fmt,
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
    pub inbound: HashMap<TunnelId, Lease>,

    /// Session options.
    pub options: HashMap<Str, Str>,

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
    /// I2CP session doesn't have an active tunnel pool
    /// and is waiting for the client to send `CreateSession` message.
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

        /// Session options.
        options: HashMap<Str, Str>,

        /// Tunnel pool build future.
        ///
        /// Resolves to a `TunnelPoolHandle` once the pool has been built.
        tunnel_pool_future: BoxFuture<'static, TunnelPoolHandle>,
    },

    /// Tunnels of the tunnel pool are being built.
    ///
    /// As soon as the the first inbound tunnel is built, the pending I2CP session
    /// future returns [`I2cpSessionContext`] to `I2cpServer` which starts
    /// the actual I2CP client session event loop
    BuildingTunnels {
        /// Session ID.
        session_id: u16,

        /// I2CP socket.
        socket: I2cpSocket<R>,

        /// Session options.
        options: HashMap<Str, Str>,

        /// Handle to the built tunnel pool.
        handle: TunnelPoolHandle,

        /// Active inbound tunnels and their leases.
        inbound: HashMap<TunnelId, Lease>,

        /// Active outbound tunnels.
        outbound: HashSet<TunnelId>,
    },

    /// Tunnel pool state is poisoned.
    Poisoned,
}

impl<R: Runtime> fmt::Debug for PendingSessionState<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inactive { session_id, .. } => f
                .debug_struct("PendingSessionState::Inactive")
                .field("session_id", &session_id)
                .finish_non_exhaustive(),
            Self::BuildingPool { session_id, .. } => f
                .debug_struct("PendingSessionState::BuildingPool")
                .field("session_id", &session_id)
                .finish_non_exhaustive(),
            Self::BuildingTunnels { session_id, .. } => f
                .debug_struct("PendingSessionState::BuildingTunnels")
                .field("session_id", &session_id)
                .finish_non_exhaustive(),
            Self::Poisoned =>
                f.debug_struct("PendingSessionState::Poisoned").finish_non_exhaustive(),
        }
    }
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
                    session_id = ?self.state.session_id(),
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
                    session_id = ?self.state.session_id(),
                    "handle bandwidth limit request",
                );

                self.state.socket().send_message(BandwidthLimits::new());
            }
            Message::DestroySession { session_id } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    session_id = ?self.state.session_id(),
                    destroyed_session_id = ?session_id,
                    "destroy session",
                );

                self.state
                    .socket()
                    .send_message(SessionStatus::new(session_id, SessionStatusKind::Destroyed));
            }
            Message::CreateSession {
                destination,
                date,
                mut options,
            } => match mem::replace(&mut self.state, PendingSessionState::Poisoned) {
                PendingSessionState::Inactive {
                    session_id,
                    mut socket,
                } => {
                    tracing::info!(
                        target: LOG_TARGET,
                        ?session_id,
                        destination = %destination.id(),
                        ?date,
                        num_options = ?options.len(),
                        "create session",
                    );

                    // create tunnel pool config
                    //
                    // emissary uses `inbound.nick` to name the tunnel pool config and in case it's
                    // not set check if `outbound.nick` is set and if so, use that for the tunnel
                    // pool's name
                    //
                    // if neither is set, use the destination short hash as the tunnel pool's name
                    let tunnel_pool_config = {
                        match options.get(&Str::from("inbound.nickname")) {
                            Some(_) => TunnelPoolConfig::from(&options),
                            None => {
                                let name =
                                    options.get(&Str::from("outbound.nickname")).map_or_else(
                                        || Str::from(destination.id().to_string()),
                                        |name| name.clone(),
                                    );
                                options.insert(Str::from("inbound.nickname"), Str::from(name));

                                TunnelPoolConfig::from(&options)
                            }
                        }
                    };

                    // attempt to create tunnel pool for the session
                    //
                    // if channel towards `TunnelManager` is clogged, don't respond to the client,
                    // allowing them to retry `CreateSession` later when the channel has available
                    // capacity
                    //
                    // response from `TunnelManagerHandle::create_tunnel_pool()` is a future which
                    // the session must poll until a `TunnelPoolHandle` is received. Reception of
                    // the handle doesn't mean the tunnel is ready for use and the handle must be
                    // polled further until an inbound tunnel is built
                    match self.tunnel_manager_handle.create_tunnel_pool(tunnel_pool_config) {
                        Ok(future) => {
                            tracing::trace!(
                                target: LOG_TARGET,
                                ?session_id,
                                "tunnel pool build started",
                            );

                            socket.send_message(SessionStatus::new(
                                SessionId::Session(session_id),
                                SessionStatusKind::Created,
                            ));
                            self.state = PendingSessionState::BuildingPool {
                                session_id,
                                socket,
                                options,
                                tunnel_pool_future: Box::pin(future),
                            };
                        }
                        Err(error) => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                ?session_id,
                                ?error,
                                "failed to build tunnel pool",
                            );

                            self.state = PendingSessionState::Inactive { session_id, socket };
                        }
                    }
                }
                state => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?state,
                        "`CreateSession` received but tunnel pool is already pending",
                    );

                    self.state = state;
                }
            },
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
                    options,
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
                            options,
                            handle,
                            inbound: HashMap::new(),
                            outbound: HashSet::new(),
                        };
                    }
                    Poll::Pending => {
                        self.state = PendingSessionState::BuildingPool {
                            session_id,
                            socket,
                            options,
                            tunnel_pool_future,
                        };
                        break;
                    }
                },
                PendingSessionState::BuildingTunnels {
                    session_id,
                    socket,
                    options,
                    mut handle,
                    mut inbound,
                    mut outbound,
                } => match handle.poll_next_unpin(cx) {
                    Poll::Pending => {
                        self.state = PendingSessionState::BuildingTunnels {
                            session_id,
                            socket,
                            options,
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
                            %tunnel_id,
                            "inbound tunnel built for pending session",
                        );
                        inbound.insert(tunnel_id, lease);

                        // create active i2cp session if there's at least one outbound
                        // and one inbound tunnel
                        if !inbound.is_empty() && !outbound.is_empty() {
                            return Poll::Ready(Some(I2cpSessionContext {
                                inbound,
                                options,
                                outbound,
                                session_id,
                                socket,
                                tunnel_pool_handle: handle,
                            }));
                        }

                        self.state = PendingSessionState::BuildingTunnels {
                            session_id,
                            socket,
                            options,
                            handle,
                            inbound,
                            outbound,
                        };
                    }
                    Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelBuilt { tunnel_id })) => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            ?session_id,
                            %tunnel_id,
                            "outbound tunnel built for pending session",
                        );
                        outbound.insert(tunnel_id);

                        // create active i2cp session if there's at least one outbound
                        // and one inbound tunnel
                        if !inbound.is_empty() && !outbound.is_empty() {
                            return Poll::Ready(Some(I2cpSessionContext {
                                inbound,
                                options,
                                outbound,
                                session_id,
                                socket,
                                tunnel_pool_handle: handle,
                            }));
                        }

                        self.state = PendingSessionState::BuildingTunnels {
                            session_id,
                            socket,
                            options,
                            handle,
                            inbound,
                            outbound,
                        };
                    }
                    Poll::Ready(Some(TunnelPoolEvent::InboundTunnelExpired { tunnel_id })) => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?session_id,
                            %tunnel_id,
                            "inbound tunnel expired for pending session",
                        );
                        inbound.remove(&tunnel_id);

                        self.state = PendingSessionState::BuildingTunnels {
                            session_id,
                            socket,
                            options,
                            handle,
                            inbound,
                            outbound,
                        };
                    }
                    Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelExpired { tunnel_id })) => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?session_id,
                            %tunnel_id,
                            "outbound tunnel expired for pending session",
                        );
                        outbound.remove(&tunnel_id);

                        self.state = PendingSessionState::BuildingTunnels {
                            session_id,
                            socket,
                            options,
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
                            options,
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
                    debug_assert!(false);

                    return Poll::Ready(None);
                }
            }
        }

        Poll::Pending
    }
}
