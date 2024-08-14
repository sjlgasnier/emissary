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
    error::TunnelError,
    i2np::{
        garlic::GarlicMessage,
        tunnel::{data::EncryptedTunnelData, gateway::TunnelGateway},
        Message, MessageType,
    },
    primitives::{MessageId, RouterId, RouterInfo, TunnelId},
    router_storage::RouterStorage,
    runtime::{Counter, MetricType, MetricsHandle, Runtime},
    subsystem::SubsystemEvent,
    transports::TransportService,
    tunnel::{
        garlic::{DeliveryInstructions, GarlicHandler},
        metrics::*,
        new_noise::NoiseContext,
        pool::{TunnelBuildDirection, TunnelPoolConfig, TunnelPoolEvent, TunnelPoolManager},
        transit::TransitTunnelManager,
    },
    Error,
};

use futures::StreamExt;
use hashbrown::{HashMap, HashSet};

use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

mod garlic;
mod hop;
mod metrics;
mod new_noise;
mod pool;
mod transit;

#[cfg(test)]
mod tests;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel";

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

    /// Metrics handle.
    metrics_handle: R::MetricsHandle,

    /// Pending inbound tunnels.
    pending_inbound: HashSet<MessageId>,

    /// Pending outbound tunnels.
    pending_outbound: HashSet<TunnelId>,

    /// Tunnel pool manager.
    pools: TunnelPoolManager<R>,

    /// Local router info.
    router_info: RouterInfo,

    /// Connected routers.
    routers: HashMap<RouterId, RouterState>,

    /// Transport service.
    service: TransportService,

    /// Transit tunnel manager.
    transit: TransitTunnelManager<R>,
}

impl<R: Runtime> TunnelManager<R> {
    /// Create new [`TunnelManager`].
    pub fn new(
        service: TransportService,
        router_info: RouterInfo,
        local_key: StaticPrivateKey,
        metrics_handle: R::MetricsHandle,
        routers: RouterStorage,
    ) -> Self {
        tracing::trace!(
            target: LOG_TARGET,
            "starting tunnel manager",
        );

        let noise = NoiseContext::new(local_key, router_info.identity().hash());
        let pools = TunnelPoolManager::new(
            noise.clone(),
            metrics_handle.clone(),
            routers,
            TunnelPoolConfig::default(),
        );
        let transit = TransitTunnelManager::new(noise.clone(), metrics_handle.clone());
        let garlic = GarlicHandler::new(noise, metrics_handle.clone());

        Self {
            garlic,
            metrics_handle: metrics_handle.clone(),
            pending_inbound: HashSet::new(),
            pending_outbound: HashSet::new(),
            pools,
            router_info,
            routers: HashMap::new(),
            service,
            transit,
        }
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
                    tracing::debug!(
                        target: LOG_TARGET,
                        message_type = ?MessageType::from_u8(message[2]),
                        message_len = ?message.len(),
                        "router message to self",
                    );

                    match Message::parse_short(&message) {
                        Some(message) => self.on_message(message),
                        None => {
                            tracing::error!(
                                target: LOG_TARGET,
                                "failed to parse message created by emissary",
                            );
                            debug_assert!(false);
                        }
                    }
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

    /// Handle variable tunnel build reply.
    ///
    /// Currently these messages are not supported and are dropped without rejection.
    fn on_variable_tunnel_build(&mut self, message: Message) {
        // TODO: fix
        let _ = self.transit.handle_variable_tunnel_build(message);
    }

    /// Handle short tunnel build request.
    ///
    /// This message is either a response to a short build request sent by us
    /// or a transit tunnel build request.
    fn on_short_tunnel_build(&mut self, message: Message) {
        match self.pending_inbound.remove(&MessageId::from(message.message_id)) {
            true => {
                self.pools.handle_inbound_tunnel_build_response(message);
            }
            false => match self.transit.handle_short_tunnel_build(message) {
                Ok((router, message)) => self.send_message(&router, message),
                Err(error) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to handle short tunnel build request",
                    );
                }
            },
        }
    }

    /// Handle tunnel gateway message.
    fn on_tunnel_gateway(&mut self, message: Message) {
        let Some(message) = TunnelGateway::parse(&message.payload) else {
            tracing::warn!(
                target: LOG_TARGET,
                message_id = ?message.message_id,
                "malformed tunnel gateway message",
            );

            return;
        };

        // TODO: should be smarter at dispatching message to correct tunnel
        match self.transit.handle_tunnel_gateway(&message) {
            Ok((router, message)) => self.send_message(&router, message),
            Err(Error::Tunnel(TunnelError::TunnelDoesntExist(tunnel_id))) =>
                if let Err(error) = self.pools.handle_outbound_tunnel_build_reply(message) {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?tunnel_id,
                        ?error,
                        "failed to handle tunnel gateway message for tunnel pool",
                    );
                },
            Err(error) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to handle tunnel gateway message",
                );
            }
        }
    }

    /// Handle tunnel data.
    fn on_tunnel_data(&mut self, message: Message) {
        let Some(message) = EncryptedTunnelData::parse(&message.payload) else {
            tracing::warn!(
                target: LOG_TARGET,
                message_id = ?message.message_id,
                "malformed tunnel data message",
            );

            return;
        };

        // TODO: should be smarter at dispatching message to correct tunnel
        match self.transit.handle_tunnel_data(&message) {
            Ok((router, message)) => self.send_message(&router, message),
            Err(Error::Tunnel(TunnelError::TunnelDoesntExist(tunnel_id))) =>
                if let Err(error) = self.pools.handle_tunnel_data(&message) {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?tunnel_id,
                        ?error,
                        "failed to handle tunnel data message for tunnel pool",
                    );
                },
            Err(error) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to handle tunnel data message",
                );
            }
        }
    }

    /// Handle garlic message.
    ///
    /// Decrypt the payload, return I2NP messages inside the garlic cloves
    /// and process them individually.
    fn on_garlic(&mut self, mut message: Message) {
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

    fn on_delivery_status(&mut self, message: Message) {
        todo!();
    }

    fn on_outbound_tunnel_build_reply(&mut self, message: Message) {
        todo!();
    }

    /// Handle tunnel build request from `TunnelPoolManager`.
    fn on_build_tunnel(
        &mut self,
        router: RouterId,
        direction: TunnelBuildDirection,
        message: Vec<u8>,
    ) {
        tracing::trace!(
            target: LOG_TARGET,
            %router,
            ?direction,
            "build tunnel",
        );

        match direction {
            TunnelBuildDirection::Outbound { tunnel_id } => {
                self.pending_outbound.insert(tunnel_id);
            }
            TunnelBuildDirection::Inbound { message_id } => {
                self.pending_inbound.insert(message_id);
            }
        }

        self.send_message(&router, message);
    }

    fn on_send_message(&mut self, router: RouterId, messsage_id: MessageId, message: Vec<u8>) {
        self.send_message(&router, message);
    }

    /// Handle received message from one of the open connections.
    fn on_message(&mut self, message: Message) {
        self.metrics_handle.counter(NUM_TUNNEL_MESSAGES).increment(1);

        match message.message_type {
            MessageType::DeliveryStatus => self.on_delivery_status(message),
            MessageType::Garlic => self.on_garlic(message),
            MessageType::TunnelData => self.on_tunnel_data(message),
            MessageType::TunnelGateway => self.on_tunnel_gateway(message),
            MessageType::VariableTunnelBuild => self.on_variable_tunnel_build(message),
            MessageType::ShortTunnelBuild => self.on_short_tunnel_build(message),
            MessageType::OutboundTunnelBuildReply => self.on_outbound_tunnel_build_reply(message),
            MessageType::TunnelBuild
            | MessageType::TunnelBuildReply
            | MessageType::Data
            | MessageType::VariableTunnelBuildReply => unimplemented!(),
            MessageType::DatabaseStore
            | MessageType::DatabaseLookup
            | MessageType::DatabaseSearchReply => unreachable!(),
        }
    }
}

impl<R: Runtime> Future for TunnelManager<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.pools.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(event)) => match event {
                    TunnelPoolEvent::BuildTunnel {
                        router,
                        direction,
                        message,
                    } => self.on_build_tunnel(router, direction, message),
                    TunnelPoolEvent::SendI2NpMessage {
                        router,
                        message_id,
                        message,
                    } => self.on_send_message(router, message_id, message),
                },
            }
        }

        loop {
            match self.service.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(SubsystemEvent::ConnectionEstablished { router })) =>
                    self.on_connection_established(router),
                Poll::Ready(Some(SubsystemEvent::ConnectionClosed { router })) =>
                    self.on_connection_closed(&router),
                Poll::Ready(Some(SubsystemEvent::I2Np { messages })) =>
                    messages.into_iter().for_each(|message| self.on_message(message)),
                Poll::Ready(Some(SubsystemEvent::ConnectionFailure { router })) =>
                    self.on_connection_failure(&router),
                Poll::Ready(Some(SubsystemEvent::Dummy)) => unreachable!(),
                Poll::Ready(None) => return Poll::Ready(()),
            }
        }
    }
}
