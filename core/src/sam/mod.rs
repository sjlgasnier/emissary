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

//! SAMV3 server implementation.
//!
//! https://geti2p.net/en/docs/api/samv3

use crate::{
    error::{ConnectionError, Error},
    netdb::NetDbHandle,
    primitives::Str,
    runtime::{JoinSet, MetricsHandle, Runtime, TcpListener},
    sam::{
        parser::SamCommand,
        pending::{
            connection::{ConnectionKind, PendingSamConnection},
            session::{PendingSamSession, SamSessionContext},
        },
    },
    tunnel::{TunnelManagerHandle, TunnelPoolConfig},
};

use futures::StreamExt;
use hashbrown::{HashMap, HashSet};
use thingbuf::mpsc::{channel, Sender};

use alloc::{string::String, sync::Arc};
use core::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

mod parser;
mod pending;
mod socket;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::sam";

/// SAMv3 server.
pub struct SamServer<R: Runtime> {
    /// Active SAMv3 sessions.
    active_sessions: HashMap<Arc<str>, Sender<SamCommand>>,

    /// TCP listener.
    listener: R::TcpListener,

    /// Metrics handle.
    metrics: R::MetricsHandle,

    /// Handle to `NetDb`.
    netdb_handle: NetDbHandle,

    /// Pending inbound SAMv3 connections.
    ///
    /// Inbound connections which are in the state of being handshaked and reading a command from
    /// the client. After the command has been read, `SamServer` validates it against the current
    /// state, ensuring, e.g., that the it's not a duplicate `SESSION CREATE` request.
    pending_inbound_connections: R::JoinSet<crate::Result<ConnectionKind<R>>>,

    /// Session IDs of pending SAMv3 sessions.
    pending_session_ids: HashSet<Arc<str>>,

    /// Pending SAMv3 sessions that are in the process of building a tunnel pool.
    pending_sessions: R::JoinSet<crate::Result<SamSessionContext<R>>>,

    /// Handle to `TunnelManager`.
    tunnel_manager_handle: TunnelManagerHandle,
}

impl<R: Runtime> SamServer<R> {
    /// Create new [`SamServer`]
    pub async fn new(
        tcp_port: u16,
        _udp_port: u16,
        netdb_handle: NetDbHandle,
        tunnel_manager_handle: TunnelManagerHandle,
        metrics: R::MetricsHandle,
    ) -> crate::Result<Self> {
        tracing::info!(
            target: LOG_TARGET,
            ?tcp_port,
            "starting sam server",
        );

        let address = SocketAddr::new(
            "127.0.0.1".parse::<IpAddr>().expect("valid address"),
            tcp_port,
        );
        let listener = R::TcpListener::bind(address)
            .await
            .ok_or(Error::Connection(ConnectionError::BindFailure))?;

        Ok(Self {
            active_sessions: HashMap::new(),
            listener,
            metrics,
            netdb_handle,
            pending_inbound_connections: R::join_set(),
            pending_session_ids: HashSet::new(),
            pending_sessions: R::join_set(),
            tunnel_manager_handle,
        })
    }
}

impl<R: Runtime> Future for SamServer<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.listener.poll_accept(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(stream)) => {
                    self.pending_inbound_connections.push(PendingSamConnection::new(stream));
                }
            }
        }

        loop {
            match self.pending_inbound_connections.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(Ok(kind))) => match kind {
                    ConnectionKind::Session {
                        socket,
                        version,
                        session_id,
                        session_kind,
                        options,
                    } => {
                        // client send a `SESSION CREATE` message with an id that is already
                        // in use by either an active or a pending session
                        //
                        // reject connection by closing the socket
                        if self.active_sessions.contains_key(&session_id)
                            || self.pending_session_ids.contains(&session_id)
                        {
                            tracing::warn!(
                                target: LOG_TARGET,
                                ?session_id,
                                "duplicate session id",
                            );
                            continue;
                        }

                        tracing::info!(
                            target: LOG_TARGET,
                            ?session_id,
                            ?version,
                            "start constructing new session",
                        );

                        // send request to `TunnelManager` to start creating a tunnel pool and get
                        // back a future which returns a `TunnelPoolHandle` when the tunnel pool has
                        // been constructed
                        //
                        // the constructed pool is not ready for immediate use and must be polled
                        // until the desired amount of inbound/outbound tunnels have been built at
                        // which point an active samv3 session can be constructed
                        let tunnel_pool_future =
                            match self.tunnel_manager_handle.create_tunnel_pool(TunnelPoolConfig {
                                name: Str::from(Arc::clone(&session_id)),
                                ..Default::default()
                            }) {
                                Ok(tunnel_pool_future) => tunnel_pool_future,
                                Err(error) => {
                                    tracing::warn!(
                                        target: LOG_TARGET,
                                        ?session_id,
                                        ?error,
                                        "failed to create tunnel pool for session",
                                    );
                                    continue;
                                }
                            };

                        self.pending_session_ids.insert(Arc::clone(&session_id));
                        self.pending_sessions.push(PendingSamSession::new(
                            socket,
                            Arc::clone(&session_id),
                            options,
                            version,
                            Box::pin(tunnel_pool_future),
                        ));
                    }
                    kind => tracing::warn!(
                        target: LOG_TARGET,
                        ?kind,
                        "currently unuspported connection",
                    ),
                },
                Poll::Ready(Some(Err(error))) => tracing::trace!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to accept samv3 client connection",
                ),
            }
        }

        loop {
            match self.pending_sessions.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(Ok(context))) => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        session_id = ?context.session_id,
                        "start active session",
                    );
                }
                Poll::Ready(Some(Err(error))) => tracing::warn!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to create tunnel pool for session",
                ),
            }
        }

        Poll::Pending
    }
}
