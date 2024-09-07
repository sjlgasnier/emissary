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
    crypto::StaticPrivateKey,
    i2np::{Message, MessageType},
    primitives::{MessageId, RouterId, RouterInfo, TunnelId},
    router_storage::RouterStorage,
    runtime::{Counter, MetricType, MetricsHandle, Runtime},
    subsystem::SubsystemEvent,
    transports::TransportService,
    tunnel::{
        garlic::{DeliveryInstructions, GarlicHandler},
        metrics::*,
        noise::NoiseContext,
        pool::{ExploratorySelector, TunnelPool, TunnelPoolConfig, TunnelPoolContext},
        routing_table::RoutingTable,
        transit::TransitTunnelManager,
    },
};

use futures::StreamExt;
use hashbrown::{HashMap, HashSet};
use thingbuf::mpsc::{channel, Receiver};

use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

mod fragment;
mod garlic;
mod hop;
mod metrics;
mod noise;
mod pool;
mod routing_table;
mod transit;

#[cfg(test)]
mod tests;

pub use pool::TunnelPoolHandle;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel";

/// Default channel size.
const DEFAULT_CHANNEL_SIZE: usize = 512;

/// Tunnel expiration, 10 minutes.
const TUNNEL_EXPIRATION: Duration = Duration::from_secs(10 * 60);

/// Router state.
#[derive(Debug)]
pub enum RouterState {
    /// Router is connected.
    Connected,

    /// Router is being dialed.
    Dialing {
        /// Pending messages.
        pending_messages: Vec<Vec<u8>>,
    },
}

/// Tunnel manager.
pub struct TunnelManager<R: Runtime> {
    /// Garlic message handler.
    garlic: GarlicHandler<R>,

    /// RX channel for receiving messages from other tunnel-related subsystems.
    message_rx: Receiver<(RouterId, Vec<u8>)>,

    /// Metrics handle.
    metrics_handle: R::MetricsHandle,

    /// Pending inbound tunnels.
    pending_inbound: HashSet<MessageId>,

    /// Pending outbound tunnels.
    pending_outbound: HashSet<TunnelId>,

    /// Local router info.
    router_info: RouterInfo,

    /// Connected routers.
    routers: HashMap<RouterId, RouterState>,

    /// Routing table.
    routing_table: RoutingTable,

    /// Transport service.
    service: TransportService,
}

impl<R: Runtime> TunnelManager<R> {
    /// Create new [`TunnelManager`].
    ///
    /// Returns a [`TunnelManager`] object and a handle for the exploratory tunnel pool.
    pub fn new(
        service: TransportService,
        router_info: RouterInfo,
        local_key: StaticPrivateKey,
        metrics_handle: R::MetricsHandle,
        router_storage: RouterStorage,
    ) -> (Self, TunnelPoolHandle) {
        tracing::trace!(
            target: LOG_TARGET,
            "starting tunnel manager",
        );

        let noise = NoiseContext::new(local_key, router_info.identity().hash());
        let (routing_table, message_rx, transit_rx) = {
            let (message_tx, message_rx) = channel(DEFAULT_CHANNEL_SIZE);
            let (transit_tx, transit_rx) = channel(DEFAULT_CHANNEL_SIZE);
            let routing_table =
                RoutingTable::new(router_info.identity().id(), message_tx, transit_tx);

            (routing_table, message_rx, transit_rx)
        };

        // create `TransitTunnelManager` and run it in a separate task
        //
        // `TransitTunnelManager` communicates with `TunnelManager` via `RoutingTable`
        R::spawn(TransitTunnelManager::<R>::new(
            noise.clone(),
            routing_table.clone(),
            transit_rx,
            metrics_handle.clone(),
        ));

        // start exploratory tunnel pool
        //
        // `TunnelPool` communicates with `TunnelManager` via `RoutingTable`
        let pool_handle = {
            let (pool_context, pool_handle) = TunnelPoolContext::new();
            let selector = ExploratorySelector::new(router_storage.clone(), pool_handle.clone());

            R::spawn(TunnelPool::<R, _>::new(
                TunnelPoolConfig::default(),
                selector,
                pool_context,
                routing_table.clone(),
                noise.clone(),
                metrics_handle.clone(),
            ));

            pool_handle
        };

        (
            Self {
                garlic: GarlicHandler::new(noise.clone(), metrics_handle.clone()),
                message_rx,
                metrics_handle: metrics_handle.clone(),
                pending_inbound: HashSet::new(),
                pending_outbound: HashSet::new(),
                router_info,
                routers: HashMap::new(),
                routing_table,
                service,
            },
            pool_handle,
        )
    }

    /// Collect tunnel-related metric counters, gauges and histograms.
    pub fn metrics(metrics: Vec<MetricType>) -> Vec<MetricType> {
        metrics::register_metrics(metrics)
    }

    /// Send `message` to `router`.
    ///
    /// If the router is not connected, its information is looked up from `RouterStorage` and if it
    /// exists, it will be dialed and if the connection is established successfully, any pending
    /// messages will be sent to the router once the connection has been registered to
    /// [`TunnelManager`].
    ///
    /// If the connection fails to establish, [`TunnelManager`] is notified of it
    /// and any pending messages will be dropped.
    ///
    /// [`TransportService::send()`] returns an error if the channel is closed, meaning the
    /// the connection has been closed or if the channel is full at which point the message
    /// will just be dropped.
    fn send_message(&mut self, router: &RouterId, message: Vec<u8>) {
        match self.routers.get_mut(router) {
            Some(RouterState::Connected) => {
                if let Err(error) = self.service.send(&router, message) {
                    tracing::error!(
                        target: LOG_TARGET,
                        ?router,
                        ?error,
                        "failed to send message to router",
                    );
                }
            }
            Some(RouterState::Dialing {
                ref mut pending_messages,
            }) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?router,
                    "router is being dialed, buffer message",
                );
                pending_messages.push(message);
            }
            None => match router == &self.router_info.identity().id() {
                true => {
                    todo!("message to self, shouldn't happen");
                    // tracing::debug!(
                    //     target: LOG_TARGET,
                    //     message_type = ?MessageType::from_u8(message[2]),
                    //     message_len = ?message.len(),
                    //     "router message to self",
                    // );
                    // match Message::parse_short(&message) {
                    //     Some(message) => self.on_message(message),
                    //     None => {
                    //         tracing::error!(
                    //             target: LOG_TARGET,
                    //             "failed to parse message created by emissary",
                    //         );
                    //         debug_assert!(false);
                    //     }
                    // }
                }
                false => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?router,
                        "start dialing router",
                    );

                    self.service.connect(&router);
                    self.routers.insert(
                        router.clone(),
                        RouterState::Dialing {
                            pending_messages: vec![message],
                        },
                    );
                }
            },
        }
    }

    /// Handle established connection to `router`.
    ///
    /// Store `router` into `routers` and send any pending messages to `router`.
    fn on_connection_established(&mut self, router: RouterId) {
        tracing::trace!(
            target: LOG_TARGET,
            %router,
            "connection established",
        );

        match self.routers.remove(&router) {
            Some(RouterState::Dialing { pending_messages }) if !pending_messages.is_empty() => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?router,
                    "router with pending messages connected",
                );

                for message in pending_messages {
                    self.service.send(&router, message);
                }
            }
            Some(RouterState::Dialing { .. }) | None => {}
            state => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?router,
                    ?state,
                    "invalid state for connected router",
                );
                debug_assert!(false);
            }
        }

        self.routers.insert(router.clone(), RouterState::Connected);
    }

    /// Handle closed connection to `router`.
    fn on_connection_closed(&mut self, router: &RouterId) {
        tracing::debug!(
            target: LOG_TARGET,
            %router,
            "connection closed",
        );
        self.routers.remove(router);
    }

    /// Handle connection failure to `router`
    ///
    /// Remove `router` from `routers` and drop any pending messages to them.
    fn on_connection_failure(&mut self, router: &RouterId) {
        tracing::debug!(
            target: LOG_TARGET,
            %router,
            "failed to open connection to router",
        );

        if self.routers.remove(router).is_none() {
            tracing::warn!(
                target: LOG_TARGET,
                "connection failure for unknown router",
            );
            debug_assert!(false);
        }
    }

    /// Handle garlic message.
    ///
    /// Decrypt the payload, return I2NP messages inside the garlic cloves
    /// and process them individually.
    fn on_garlic(&mut self, message: Message) {
        self.garlic.handle_message(message).map(|messages| {
            messages.for_each(|delivery_instructions| match delivery_instructions {
                DeliveryInstructions::Local { message } => self.on_message(message),
                DeliveryInstructions::Router { router, message } =>
                    self.send_message(&router, message),
                DeliveryInstructions::Tunnel {
                    router,
                    tunnel,
                    message,
                } => self.send_message(&router, message),
                DeliveryInstructions::Destination => unreachable!(),
            })
        });
    }

    /// Handle received message from one of the open connections.
    fn on_message(&mut self, message: Message) {
        self.metrics_handle.counter(NUM_TUNNEL_MESSAGES).increment(1);

        match message.message_type {
            MessageType::DeliveryStatus
            | MessageType::TunnelData
            | MessageType::TunnelGateway
            | MessageType::VariableTunnelBuild
            | MessageType::ShortTunnelBuild
            | MessageType::OutboundTunnelBuildReply
            | MessageType::TunnelBuild =>
                if let Err(error) = self.routing_table.route_message(message) {
                    tracing::error!(target: LOG_TARGET, ?error, "failed to route message");
                },
            MessageType::Garlic => self.on_garlic(message),
            MessageType::TunnelBuildReply
            | MessageType::Data
            | MessageType::VariableTunnelBuildReply => unimplemented!(),
            MessageType::DatabaseStore
            | MessageType::DatabaseLookup
            | MessageType::DatabaseSearchReply => todo!("route to netdb"),
        }
    }
}

impl<R: Runtime> Future for TunnelManager<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        while let Poll::Ready(event) = self.message_rx.poll_recv(cx) {
            match event {
                None => return Poll::Ready(()),
                Some((router, message)) => self.send_message(&router, message),
            }
        }

        loop {
            match futures::ready!(self.service.poll_next_unpin(cx)) {
                Some(SubsystemEvent::ConnectionEstablished { router }) =>
                    self.on_connection_established(router),
                Some(SubsystemEvent::ConnectionClosed { router }) =>
                    self.on_connection_closed(&router),
                Some(SubsystemEvent::I2Np { messages }) =>
                    messages.into_iter().for_each(|message| self.on_message(message)),
                Some(SubsystemEvent::ConnectionFailure { router }) =>
                    self.on_connection_failure(&router),
                Some(SubsystemEvent::Dummy) => unreachable!(),
                None => return Poll::Ready(()),
            }
        }
    }
}
