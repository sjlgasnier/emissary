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
    i2np::{MessageType, RawI2npMessage},
    primitives::{MessageId, RouterId, RouterInfo},
    router_storage::RouterStorage,
    runtime::{Counter, MetricType, MetricsHandle, Runtime},
    subsystem::SubsystemEvent,
    transports::TransportService,
    tunnel::{
        metrics::*,
        new_noise::NoiseContext,
        pool::{TunnelPoolConfig, TunnelPoolEvent, TunnelPoolManager},
        transit::TransitTunnelManager,
    },
};

use futures::StreamExt;
use hashbrown::{HashMap, HashSet};

use alloc::vec::Vec;
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

mod garlic;
mod hop;
mod metrics;
mod new_noise;
mod noise;
mod pool;
mod transit;

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
    /// Metrics handle.
    metrics_handle: R::MetricsHandle,

    /// Pending local tunnels.
    pending_tunnels: HashSet<MessageId>,

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
        let transit = TransitTunnelManager::new(noise, metrics_handle.clone());

        Self {
            metrics_handle: metrics_handle.clone(),
            pending_tunnels: HashSet::new(),
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

    fn on_connection_established(&mut self, router: RouterId) {
        tracing::debug!(
            target: LOG_TARGET,
            %router,
            "connection established",
        );
    }

    fn on_connection_closed(&mut self, router: &RouterId) {
        tracing::debug!(
            target: LOG_TARGET,
            %router,
            "connection closed",
        );
    }

    fn on_connection_failure(&mut self, router: &RouterId) {
        tracing::debug!(
            target: LOG_TARGET,
            %router,
            "failed to open connection to router",
        );
    }

    fn on_tunnel_gateway(&mut self, messsage_id: u32, expiration: u64, payload: Vec<u8>) {}
    fn on_tunnel_data(&mut self, messsage_id: u32, expiration: u64, payload: Vec<u8>) {}
    fn on_garlic(&mut self, messsage_id: u32, expiration: u64, payload: Vec<u8>) {}
    fn on_delivery_status(&mut self, messsage_id: u32, expiration: u64, payload: Vec<u8>) {}
    fn on_variable_tunnel_build(&mut self, messsage_id: u32, expiration: u64, payload: Vec<u8>) {}
    fn on_short_tunnel_build(&mut self, messsage_id: u32, expiration: u64, payload: Vec<u8>) {}
    fn on_outbound_tunnel_build_reply(
        &mut self,
        messsage_id: u32,
        expiration: u64,
        payload: Vec<u8>,
    ) {
    }
    fn on_build_tunnel(&mut self, router: RouterId, messsage_id: MessageId, message: Vec<u8>) {}
    fn on_send_message(&mut self, router: RouterId, messsage_id: MessageId, message: Vec<u8>) {}

    /// Handle received message from one of the open connections.
    fn on_message(&mut self, message: RawI2npMessage) {
        self.metrics_handle.counter(NUM_TUNNEL_MESSAGES).increment(1);

        let RawI2npMessage {
            message_type,
            message_id,
            expiration,
            payload,
        } = message;

        match message_type {
            MessageType::DeliveryStatus => self.on_delivery_status(message_id, expiration, payload),
            MessageType::Garlic => self.on_garlic(message_id, expiration, payload),
            MessageType::TunnelData => self.on_tunnel_data(message_id, expiration, payload),
            MessageType::TunnelGateway => self.on_tunnel_gateway(message_id, expiration, payload),
            MessageType::VariableTunnelBuild =>
                self.on_variable_tunnel_build(message_id, expiration, payload),
            MessageType::ShortTunnelBuild =>
                self.on_short_tunnel_build(message_id, expiration, payload),
            MessageType::OutboundTunnelBuildReply =>
                self.on_outbound_tunnel_build_reply(message_id, expiration, payload),
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
                        message_id,
                        message,
                    } => self.on_build_tunnel(router, message_id, message),
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
