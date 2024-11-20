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
    crypto::{SigningPrivateKey, StaticPrivateKey},
    error::ChannelError,
    i2np::Message,
    primitives::{RouterAddress, RouterId, RouterInfo, TransportKind},
    router_storage::RouterStorage,
    runtime::{MetricType, Runtime},
    subsystem::{
        InnerSubsystemEvent, SubsystemCommand, SubsystemEvent, SubsystemHandle, SubsystemKind,
    },
    transports::ntcp2::Ntcp2Transport,
    Error, Ntcp2Config,
};

use futures::{Stream, StreamExt};
use hashbrown::{HashMap, HashSet};
use thingbuf::mpsc::{channel, errors::TrySendError, Receiver, Sender};

use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

mod ntcp2;
mod ssu2;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::transport-manager";

// TODO: introduce `Endpoint`?

#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// Connection successfully established to remote peer.
    ConnectionEstablished {
        /// `RouterInfo` for the connected peer.
        router: RouterInfo,
    },
    ConnectionClosed {},
    ConnectionFailure {},
    Message {},
}

/// Transport event.
#[derive(Debug)]
pub enum TransportEvent {
    /// Connection successfully established to router.
    ConnectionEstablished {
        /// `RouterInfo` for the connected peer.
        router_info: RouterInfo,
    },

    /// Connection closed to router.
    ConnectionClosed {
        /// Router ID.
        router: RouterId,
    },

    /// Failed to dial peer.
    ///
    /// The connection is considered failed if we failed to reach the router
    /// or if there was an error during handshaking.
    ConnectionFailure {},
}

// TODO: `poll_progress()` - only poll pending streams
// TODO: `poll()` - poll pending streams and listener
pub trait Transport: Stream + Unpin {
    /// Connect to `router`.
    //
    // TODO: how to signal preference for transport?
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
        /// Remote's router info.
        router: RouterInfo,
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
pub struct TransportService {
    /// TX channel for sending commands to [`TransportManager`].
    cmd_tx: Sender<ProtocolCommand>,

    /// RX channel for receiving events from enabled transports.
    event_rx: Receiver<InnerSubsystemEvent>,

    /// Pending events.
    pending_events: VecDeque<InnerSubsystemEvent>,

    /// Router storage.
    router_storage: RouterStorage,

    /// Connected routers.
    routers: HashMap<RouterId, Sender<SubsystemCommand>>,
}

impl TransportService {
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
    pub fn connect(&mut self, router: &RouterId) -> Result<(), ()> {
        if self.routers.contains_key(router) {
            tracing::warn!(
                target: LOG_TARGET,
                ?router,
                "tried to dial an already-connected router",
            );
            debug_assert!(false);

            self.pending_events.push_back(InnerSubsystemEvent::ConnectionFailure {
                router: router.clone(),
            });
            return Ok(());
        }

        match self.router_storage.get(router) {
            Some(router_info) => self
                .cmd_tx
                .try_send(ProtocolCommand::Connect {
                    router: router_info,
                })
                .map_err(|_| ()),
            None => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?router,
                    "failed to dial router, router doesn't exist",
                );
                self.pending_events.push_back(InnerSubsystemEvent::ConnectionFailure {
                    router: router.clone(),
                });
                Ok(())
            }
        }
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
}

impl Stream for TransportService {
    type Item = SubsystemEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match futures::ready!(self.event_rx.poll_recv(cx)) {
                None => return Poll::Ready(None),
                Some(InnerSubsystemEvent::ConnectionEstablished { router, tx }) => {
                    self.routers.insert(router.clone(), tx);
                    return Poll::Ready(Some(SubsystemEvent::ConnectionEstablished { router }));
                }
                Some(InnerSubsystemEvent::ConnectionClosed { router }) => {
                    self.routers.remove(&router);
                    return Poll::Ready(Some(SubsystemEvent::ConnectionClosed { router }));
                }
                Some(InnerSubsystemEvent::ConnectionFailure { router }) => {
                    return Poll::Ready(Some(SubsystemEvent::ConnectionFailure { router }));
                }
                Some(InnerSubsystemEvent::I2Np { messages }) => {
                    return Poll::Ready(Some(SubsystemEvent::I2Np { messages }));
                }
                Some(InnerSubsystemEvent::Dummy) => unreachable!(),
            }
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

    /// TX channel passed onto other subsystems.
    cmd_tx: Sender<ProtocolCommand>,

    /// Local key.
    local_key: StaticPrivateKey,

    /// Local `RouterInfo`.
    local_router_info: RouterInfo,

    /// Local signing key.
    local_signing_key: SigningPrivateKey,

    /// Metrics handle.
    metrics_handle: R::MetricsHandle,

    /// Poll index for transports.
    poll_index: usize,

    /// Router storage.
    router_storage: RouterStorage,

    /// Connected routers.
    routers: HashSet<RouterId>,

    // Runtime.
    runtime: R,

    /// Subsystem handle passed onto enabled transports.
    subsystem_handle: SubsystemHandle,

    /// Enabled transports.
    transports: Vec<Box<dyn Transport<Item = TransportEvent>>>,
}

impl<R: Runtime> TransportManager<R> {
    /// Create new [`TransportManager`].
    pub fn new(
        runtime: R,
        local_key: StaticPrivateKey,
        local_signing_key: SigningPrivateKey,
        local_router_info: RouterInfo,
        router_storage: RouterStorage,
        metrics_handle: R::MetricsHandle,
    ) -> Self {
        let (cmd_tx, cmd_rx) = channel(256);

        Self {
            cmd_rx,
            cmd_tx,
            local_key,
            local_router_info,
            local_signing_key,
            metrics_handle,
            poll_index: 0usize,
            routers: HashSet::new(),
            router_storage,
            runtime,
            subsystem_handle: SubsystemHandle::new(),
            transports: Vec::with_capacity(2),
        }
    }

    /// Collect `TransportManager`-related metric counters, gauges and histograms.
    pub fn metrics(metrics: Vec<MetricType>) -> Vec<MetricType> {
        let metrics = Ntcp2Transport::<R>::metrics(metrics);

        metrics
    }

    /// Register new subsystem to [`TransportManager`].
    ///
    /// The number of subsystems is fixed and the initialization order is important.
    pub fn register_subsystem(&mut self, kind: SubsystemKind) -> TransportService {
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
            router_storage: self.router_storage.clone(),
        }
    }

    /// Register enabled transport
    ///
    /// The number of transports is fixed and the initialization order is important.
    //
    // TODO: this is not correct, fix when ssu2 is implemented
    pub async fn register_transport(
        &mut self,
        kind: TransportKind,
        config: Ntcp2Config,
    ) -> crate::Result<()> {
        let TransportKind::Ntcp2 = kind else {
            panic!("only ntcp2 is supported");
        };

        self.transports.push(Box::new(
            Ntcp2Transport::new(
                config,
                self.runtime.clone(),
                self.local_signing_key.clone(),
                self.local_router_info.clone(),
                self.subsystem_handle.clone(),
                self.router_storage.clone(),
            )
            .await?,
        ));

        Ok(())
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
                Poll::Ready(Some(TransportEvent::ConnectionEstablished { router_info })) => {
                    let router = router_info.identity().id();

                    tracing::debug!(
                        target: LOG_TARGET,
                        ?router,
                        "connection established",
                    );

                    match self.routers.insert(router.clone()) {
                        true => self.transports[index].accept(&router),
                        false => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                ?router,
                                "router already connected, rejecting",
                            );
                            self.transports[index].reject(&router);
                        }
                    }
                }
                Poll::Ready(Some(TransportEvent::ConnectionClosed { router })) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?router,
                        "connection closed",
                    );

                    self.routers.remove(&router);
                }
                Poll::Ready(Some(event)) => {
                    tracing::warn!("unhandled event: {event:?}");
                }
            }

            if self.poll_index == start_index + len {
                break;
            }
        }

        loop {
            match futures::ready!(self.cmd_rx.poll_recv(cx)) {
                None => return Poll::Ready(()),
                Some(ProtocolCommand::Connect { router }) => {
                    self.transports[0].connect(router);
                }
                Some(event) => {
                    todo!("event: {event:?}");
                }
            }
        }
    }
}
