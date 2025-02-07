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
    error::{ChannelError, QueryError},
    netdb::NetDbHandle,
    primitives::{Date, RouterId, RouterInfo},
    router::context::RouterContext,
    runtime::{Counter, Gauge, JoinSet, MetricType, MetricsHandle, Runtime},
    subsystem::{
        InnerSubsystemEvent, SubsystemCommand, SubsystemEvent, SubsystemHandle, SubsystemKind,
    },
    transport::{metrics::*, ntcp2::Ntcp2Context, ssu2::Ssu2Context},
};

use bytes::Bytes;
use futures::{future::BoxFuture, FutureExt, Stream, StreamExt};
use hashbrown::{HashMap, HashSet};
use thingbuf::mpsc::{channel, errors::TrySendError, Receiver, Sender};

use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
use core::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

mod metrics;
mod ntcp2;
mod ssu2;

pub use ntcp2::Ntcp2Transport;
pub use ssu2::Ssu2Transport;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::transport-manager";

/// Local [`RouterInfo`] republish interval.
///
/// Local router info gets republished to `NetDb` every 15 minutes.
const ROUTER_INFO_REPUBLISH_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// Termination reason.
#[derive(Debug, Default, PartialEq, Eq)]
pub enum TerminationReason {
    /// Unspecified or normal termination.
    #[default]
    Unspecified,

    /// Termination block was received.
    TerminationReceived,

    /// Idle timeout.
    IdleTimeout,

    /// Socket was closed (NTCP2 only).
    IoError,

    /// Router is shutting down.
    RouterShutdown,

    /// AEAD failure.
    AeadFailure,

    /// Incompatible options,
    IncompatibleOptions,

    /// Unsupported signature kind.
    IncompatibleSignatureKind,

    /// Clock skew.
    ClockSkew,

    /// Padding violation.
    PaddinViolation,

    /// Payload format error.
    PayloadFormatError,

    /// AEAD framing error.
    AeadFramingError,

    /// NTCP2 handshake error.
    Ntcp2HandshakeError(u8),

    /// SSU2 handshake error.
    Ssu2HandshakeError(u8),

    /// Intra frame timeout.
    IntraFrameReadTimeout,

    /// Invalid router info.
    InvalidRouterInfo,

    /// Router has been banned.
    Banned,

    /// Timeout (SSU2 only)
    Timeout,

    /// Bad token (SSU2 only).
    BadToken,

    /// Connection limit reached (SSU2 only)
    ConnectionLimits,

    /// Incompatible version (SSU2 only)
    IncompatibleVersion,

    /// Wrong network ID (SSU2 only)
    WrongNetId,

    /// Replaced by new session (SSU2 only)
    ReplacedByNewSession,
}

impl TerminationReason {
    /// Get [`TerminationReason`] from an NTCP2 termination reason.
    pub fn ntcp2(value: u8) -> Self {
        match value {
            0 => TerminationReason::Unspecified,
            1 => TerminationReason::TerminationReceived,
            2 => TerminationReason::IdleTimeout,
            3 => TerminationReason::RouterShutdown,
            4 => TerminationReason::AeadFailure,
            5 => TerminationReason::IncompatibleOptions,
            6 => TerminationReason::IncompatibleSignatureKind,
            7 => TerminationReason::ClockSkew,
            8 => TerminationReason::PaddinViolation,
            9 => TerminationReason::AeadFramingError,
            10 => TerminationReason::PayloadFormatError,
            11 => TerminationReason::Ntcp2HandshakeError(1),
            12 => TerminationReason::Ntcp2HandshakeError(2),
            13 => TerminationReason::Ntcp2HandshakeError(3),
            14 => TerminationReason::IntraFrameReadTimeout,
            15 => TerminationReason::InvalidRouterInfo,
            16 => TerminationReason::InvalidRouterInfo,
            17 => TerminationReason::Banned,
            _ => TerminationReason::Unspecified,
        }
    }

    /// Get [`TerminationReason`] from an SSU2 termination reason.
    pub fn ssu2(value: u8) -> Self {
        match value {
            0 => TerminationReason::Unspecified,
            1 => TerminationReason::TerminationReceived,
            2 => TerminationReason::IdleTimeout,
            3 => TerminationReason::RouterShutdown,
            4 => TerminationReason::AeadFailure,
            5 => TerminationReason::IncompatibleOptions,
            6 => TerminationReason::IncompatibleSignatureKind,
            7 => TerminationReason::ClockSkew,
            8 => TerminationReason::PaddinViolation,
            9 => TerminationReason::AeadFramingError,
            10 => TerminationReason::PayloadFormatError,
            11 => TerminationReason::Ssu2HandshakeError(1),
            12 => TerminationReason::Ssu2HandshakeError(2),
            13 => TerminationReason::Ssu2HandshakeError(3),
            14 => TerminationReason::IntraFrameReadTimeout,
            15 => TerminationReason::InvalidRouterInfo,
            16 => TerminationReason::InvalidRouterInfo,
            17 => TerminationReason::Banned,
            18 => TerminationReason::BadToken,
            19 => TerminationReason::ConnectionLimits,
            20 => TerminationReason::IncompatibleVersion,
            21 => TerminationReason::WrongNetId,
            22 => TerminationReason::ReplacedByNewSession,
            _ => TerminationReason::Unspecified,
        }
    }
}

/// Transport event.
#[derive(Debug)]
pub enum TransportEvent {
    /// Connection successfully established to router.
    ConnectionEstablished {
        /// ID of the connected router.
        router_id: RouterId,
    },

    /// Connection closed to router.
    ConnectionClosed {
        /// ID of the disconnected router.
        router_id: RouterId,

        /// Reason for the termination.
        reason: TerminationReason,
    },

    /// Failed to dial peer.
    ///
    /// The connection is considered failed if we failed to reach the router
    /// or if there was an error during handshaking.
    ConnectionFailure {
        /// ID of the remote router.
        router_id: RouterId,
    },
}

/// Transport interface.
pub trait Transport: Stream + Unpin + Send {
    /// Connect to `router`.
    fn connect(&mut self, router: RouterInfo);

    /// Accept connection and start its event loop.
    fn accept(&mut self, router: &RouterId);

    /// Reject connection.
    fn reject(&mut self, router: &RouterId);
}

#[derive(Debug, Clone)]
pub enum ProtocolCommand {
    /// Attempt to connect to remote peer.
    Connect {
        /// ID of the remote router.
        router_id: RouterId,
    },

    /// Dummy event.
    Dummy,
}

impl Default for ProtocolCommand {
    fn default() -> Self {
        Self::Dummy
    }
}

/// Transport service.
///
/// Implements a handle that is given to subsystems of `emissary` are themselves not transports
/// but interact with them, namely `NetDb` and `TunnelManager`. [`TransportService`] allows
/// the subsystem to establish new connections, close existing connections, send and receive
/// messages to and from the network.
pub struct TransportService<R: Runtime> {
    /// TX channel for sending commands to [`TransportManager`].
    cmd_tx: Sender<ProtocolCommand>,

    /// RX channel for receiving events from enabled transports.
    event_rx: Receiver<InnerSubsystemEvent>,

    /// Pending events.
    pending_events: VecDeque<InnerSubsystemEvent>,

    /// Connected routers.
    routers: HashMap<RouterId, Sender<SubsystemCommand>>,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> TransportService<R> {
    /// Attempt to establish connection to `router`.
    ///
    /// The connection is established in the background and the result
    /// can be received by polling [`TransportService`].
    ///
    /// [`TransportService::connect()`] returns an error if the channel is clogged
    /// and the caller should try again later.
    ///
    /// If `router` is not reachable or the handshake fails, the error is reported
    /// via [`TransportService::poll_next()`].
    pub fn connect(&mut self, router_id: &RouterId) -> Result<(), ()> {
        if self.routers.contains_key(router_id) {
            tracing::debug!(
                target: LOG_TARGET,
                %router_id,
                "tried to dial an already-connected router",
            );

            self.pending_events.push_back(InnerSubsystemEvent::ConnectionFailure {
                router: router_id.clone(),
            });
            return Ok(());
        }

        self.cmd_tx
            .try_send(ProtocolCommand::Connect {
                router_id: router_id.clone(),
            })
            .map_err(|_| ())
    }

    /// Send I2NP `message` to `router`.
    ///
    /// If the router doesn't exist, `ChannelError::DoesntExist` is returned.
    /// If the channel is closed, `ChannelError::Closed` is returned.
    /// If the channel is full, `ChannelError::Full` is returned.
    ///
    /// In all error cases, `message` is returned together with error
    pub fn send(
        &mut self,
        router: &RouterId,
        message: Vec<u8>,
    ) -> Result<(), (ChannelError, Vec<u8>)> {
        let Some(channel) = self.routers.get(router) else {
            return Err((ChannelError::DoesntExist, message));
        };

        channel.try_send(SubsystemCommand::SendMessage { message }).map_err(|error| {
            let (error, message) = match error {
                TrySendError::Full(message) => (ChannelError::Full, message),
                TrySendError::Closed(message) => (ChannelError::Closed, message),
                _ => unimplemented!(),
            };

            let inner = match message {
                SubsystemCommand::SendMessage { message } => message,
                _ => unreachable!(),
            };

            (error, inner)
        })
    }

    /// Create new [`TransportService`] for testing.
    #[cfg(test)]
    pub fn new() -> (
        Self,
        Receiver<ProtocolCommand>,
        Sender<InnerSubsystemEvent>,
        crate::profile::ProfileStorage<R>,
    ) {
        let (event_tx, event_rx) = channel(64);
        let (cmd_tx, cmd_rx) = channel(64);
        let profile_storage = crate::profile::ProfileStorage::new(&Vec::new(), &Vec::new());

        (
            TransportService {
                cmd_tx,
                event_rx,
                pending_events: VecDeque::new(),
                routers: HashMap::new(),
                _runtime: Default::default(),
            },
            cmd_rx,
            event_tx,
            profile_storage,
        )
    }
}

impl<R: Runtime> Stream for TransportService<R> {
    type Item = SubsystemEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match futures::ready!(self.event_rx.poll_recv(cx)) {
            None => Poll::Ready(None),
            Some(InnerSubsystemEvent::ConnectionEstablished { router, tx }) => {
                self.routers.insert(router.clone(), tx);
                Poll::Ready(Some(SubsystemEvent::ConnectionEstablished { router }))
            }
            Some(InnerSubsystemEvent::ConnectionClosed { router }) => {
                self.routers.remove(&router);
                Poll::Ready(Some(SubsystemEvent::ConnectionClosed { router }))
            }
            Some(InnerSubsystemEvent::ConnectionFailure { router }) =>
                Poll::Ready(Some(SubsystemEvent::ConnectionFailure { router })),
            Some(InnerSubsystemEvent::I2Np { messages }) =>
                Poll::Ready(Some(SubsystemEvent::I2Np { messages })),
            Some(InnerSubsystemEvent::Dummy) => unreachable!(),
        }
    }
}

/// Builder for [`TransportManager`].
pub struct TransportManagerBuilder<R: Runtime> {
    /// Allow local addresses.
    allow_local: bool,

    /// RX channel for receiving commands from other subsystems.
    cmd_rx: Receiver<ProtocolCommand>,

    /// TX channel passed onto other subsystems.
    cmd_tx: Sender<ProtocolCommand>,

    /// Local router info.
    local_router_info: RouterInfo,

    /// Handle to [`NetDb`].
    netdb_handle: Option<NetDbHandle>,

    /// Router context.
    router_ctx: RouterContext<R>,

    /// Subsystem handle passed onto enabled transports.
    subsystem_handle: SubsystemHandle,

    /// Enabled transports.
    transports: Vec<Box<dyn Transport<Item = TransportEvent>>>,
}

impl<R: Runtime> TransportManagerBuilder<R> {
    /// Create new [`TransportManagerBuilder`].
    pub fn new(
        router_ctx: RouterContext<R>,
        local_router_info: RouterInfo,
        allow_local: bool,
    ) -> Self {
        let (cmd_tx, cmd_rx) = channel(256);

        Self {
            allow_local,
            cmd_rx,
            cmd_tx,
            local_router_info,
            netdb_handle: None,
            router_ctx,
            subsystem_handle: SubsystemHandle::new(),
            transports: Vec::with_capacity(2),
        }
    }

    //// Register subsystem.
    pub fn register_subsystem(&mut self, kind: SubsystemKind) -> TransportService<R> {
        let (event_tx, event_rx) = channel(64);

        tracing::debug!(
            target: LOG_TARGET,
            subsystem = ?kind,
            "register subsystem",
        );

        self.subsystem_handle.register_subsystem(event_tx);

        TransportService {
            cmd_tx: self.cmd_tx.clone(),
            event_rx,
            pending_events: VecDeque::new(),
            routers: HashMap::new(),
            _runtime: Default::default(),
        }
    }

    /// Register NTCP2 as an active transport.
    pub fn register_ntcp2(&mut self, context: Ntcp2Context<R>) {
        self.transports.push(Box::new(Ntcp2Transport::new(
            context,
            self.allow_local,
            self.router_ctx.clone(),
            self.subsystem_handle.clone(),
        )))
    }

    /// Register SSU2 as an active transport.
    pub fn register_ssu2(&mut self, context: Ssu2Context<R>) {
        self.transports.push(Box::new(Ssu2Transport::new(
            context,
            self.allow_local,
            self.router_ctx.clone(),
            self.subsystem_handle.clone(),
        )))
    }

    /// Register [`NetDbHandle`].
    pub fn register_netdb_handle(&mut self, netdb_handle: NetDbHandle) {
        self.netdb_handle = Some(netdb_handle);
    }

    /// Build into [`TransportManager`].
    pub fn build(self) -> TransportManager<R> {
        TransportManager {
            cmd_rx: self.cmd_rx,
            local_router_info: self.local_router_info,
            netdb_handle: self.netdb_handle.expect("to exist"),
            pending_queries: R::join_set(),
            poll_index: 0usize,
            router_ctx: self.router_ctx,
            // publish the router info 10 seconds after booting, otherwise republish it periodically
            // in intervals of [`ROUTER_INFO_REPUBLISH_INTERVAL`]
            router_info_republish_timer: Box::pin(R::delay(Duration::from_secs(10))),
            routers: HashSet::new(),
            subsystem_handle: self.subsystem_handle,
            transports: self.transports,
        }
    }
}

/// Transport manager.
///
/// Transport manager is responsible for connecting the higher-level subsystems
/// together with enabled, lower-level transports and polling for polling those
/// transports so that they can make progress.
pub struct TransportManager<R: Runtime> {
    /// RX channel for receiving commands from other subsystems.
    cmd_rx: Receiver<ProtocolCommand>,

    /// Local router info.
    local_router_info: RouterInfo,

    /// Handle to [`NetDb`].
    netdb_handle: NetDbHandle,

    /// Pending router info queries.
    pending_queries: R::JoinSet<(RouterId, Result<(), QueryError>)>,

    /// Poll index for transports.
    poll_index: usize,

    /// Router context.
    router_ctx: RouterContext<R>,

    /// Router info republish timer.
    router_info_republish_timer: BoxFuture<'static, ()>,

    /// Connected routers.
    routers: HashSet<RouterId>,

    /// Subsystem handle.
    subsystem_handle: SubsystemHandle,

    /// Enabled transports.
    transports: Vec<Box<dyn Transport<Item = TransportEvent>>>,
}

impl<R: Runtime> TransportManager<R> {
    /// Collect `TransportManager`-related metric counters, gauges and histograms.
    pub fn metrics(metrics: Vec<MetricType>) -> Vec<MetricType> {
        let metrics = register_metrics(metrics);
        let metrics = Ntcp2Transport::<R>::metrics(metrics);

        Ssu2Transport::<R>::metrics(metrics)
    }

    /// Attempt to dial `router_id`.
    ///
    /// If `router_id` is not found in local storage, send [`RouterInfo`] query for `router_id` to
    /// [`NetDb`] and if the [`RouterInfo`] is found, attempt to dial it.
    fn on_dial_router(&mut self, router_id: RouterId) {
        match self.router_ctx.profile_storage().get(&router_id) {
            Some(router_info) => {
                // TODO: compare transport costs
                self.transports[0].connect(router_info);
            }
            None => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    "router info not found, send router info query to netdb",
                );

                match self.netdb_handle.query_router_info(router_id.clone()) {
                    Err(error) => tracing::warn!(
                        target: LOG_TARGET,
                        %router_id,
                        ?error,
                        "failed to send router info query",
                    ),
                    Ok(rx) => {
                        self.pending_queries.push(async move {
                            match rx.await {
                                Err(_) => return (router_id, Err(QueryError::Timeout)),
                                Ok(Err(error)) => return (router_id, Err(error)),
                                Ok(Ok(lease_set)) => return (router_id, Ok(lease_set)),
                            }
                        });
                    }
                }
            }
        }
    }
}

impl<R: Runtime> Future for TransportManager<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let len = self.transports.len();
        let start_index = self.poll_index;

        loop {
            let index = self.poll_index % len;
            self.poll_index += 1;

            match self.transports[index].poll_next_unpin(cx) {
                Poll::Pending => {}
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(TransportEvent::ConnectionEstablished { router_id })) => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        %router_id,
                        "connection established",
                    );

                    match self.routers.insert(router_id.clone()) {
                        true => {
                            self.transports[index].accept(&router_id);
                            self.router_ctx.metrics_handle().gauge(NUM_CONNECTIONS).increment(1);
                        }
                        false => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                %router_id,
                                "router already connected, rejecting",
                            );
                            self.transports[index].reject(&router_id);
                        }
                    }
                    self.router_ctx.profile_storage().dial_succeeded(&router_id);
                }
                Poll::Ready(Some(TransportEvent::ConnectionClosed { router_id, reason })) => {
                    match reason {
                        TerminationReason::Banned => tracing::warn!(
                            target: LOG_TARGET,
                            %router_id,
                            ?reason,
                            "remote router banned us",
                        ),
                        TerminationReason::IdleTimeout => tracing::trace!(
                            target: LOG_TARGET,
                            %router_id,
                            ?reason,
                            "connection closed",
                        ),
                        reason => tracing::debug!(
                            target: LOG_TARGET,
                            %router_id,
                            ?reason,
                            "connection closed",
                        ),
                    }

                    self.routers.remove(&router_id);
                    self.router_ctx.metrics_handle().gauge(NUM_CONNECTIONS).decrement(1);
                }
                Poll::Ready(Some(TransportEvent::ConnectionFailure { router_id })) => {
                    self.router_ctx.metrics_handle().counter(NUM_DIAL_FAILURES).increment(1);
                    self.router_ctx.profile_storage().dial_failed(&router_id);
                }
            }

            if self.poll_index == start_index + len {
                break;
            }
        }

        loop {
            match self.pending_queries.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some((router_id, Ok(())))) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        "router info query succeeded, dial pending router",
                    );

                    self.on_dial_router(router_id);
                }
                Poll::Ready(Some((router_id, Err(error)))) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        ?error,
                        "router info query failed",
                    );

                    // report connection failure to subsystems
                    let mut handle = self.subsystem_handle.clone();
                    R::spawn(async move {
                        handle.report_connection_failure(router_id).await;
                    });
                }
            }
        }

        loop {
            match self.cmd_rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(ProtocolCommand::Connect { router_id })) =>
                    self.on_dial_router(router_id),
                Poll::Ready(Some(event)) => tracing::warn!(
                    target: LOG_TARGET,
                    ?event,
                    "unhandled event",
                ),
            }
        }

        if self.router_info_republish_timer.poll_unpin(cx).is_ready() {
            // reset publish time and serialize our new router info
            self.local_router_info.published = Date::new(R::time_since_epoch().as_millis() as u64);
            let serialized =
                Bytes::from(self.local_router_info.serialize(self.router_ctx.signing_key()));

            // reset router info in router context so all subsystems are using the latest version of
            // it and publish it to netdb
            self.router_ctx.set_router_info(serialized.clone());
            self.netdb_handle
                .publish_router_info(self.router_ctx.router_id().clone(), serialized);

            // reset timer and register it into the executor
            self.router_info_republish_timer = Box::pin(R::delay(ROUTER_INFO_REPUBLISH_INTERVAL));
            let _ = self.router_info_republish_timer.poll_unpin(cx);
        }

        Poll::Pending
    }
}
