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
    i2np::{MessageType, RawI2npMessage},
    primitives::{RouterId, RouterInfo},
    router_storage::RouterStorage,
    runtime::{Counter, MetricType, MetricsHandle, Runtime},
    subsystem::SubsystemEvent,
    transports::TransportService,
    tunnel::metrics::*,
};

use futures::StreamExt;
use hashbrown::HashMap;

use alloc::vec::Vec;
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

mod garlic;
mod hop;
mod metrics;
mod noise;
mod pool;

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

    /// Local router info.
    router_info: RouterInfo,

    /// Connected routers.
    routers: HashMap<RouterId, RouterState>,

    /// Transport service.
    service: TransportService,
}

impl<R: Runtime> TunnelManager<R> {
    /// Create new [`TunnelManager`].
    pub fn new(
        service: TransportService,
        router_info: RouterInfo,
        metrics_handle: R::MetricsHandle,
        routers: RouterStorage,
    ) -> Self {
        tracing::trace!(
            target: LOG_TARGET,
            "starting tunnel manager",
        );

        Self {
            metrics_handle,
            router_info,
            routers: HashMap::new(),
            service,
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

    fn on_message(&mut self, message: RawI2npMessage) {
        self.metrics_handle.counter(NUM_TUNNEL_MESSAGES).increment(1);

        let RawI2npMessage {
            message_type,
            message_id,
            expiration,
            payload,
        } = message;

        match message_type {
            MessageType::Garlic => {
                todo!();
            }
            _ => todo!(),
        }

        // TODO: message can be:
        // TODO:  - garlic-wrapped netdb message
        // TODO:  - garlic-wrapped tunnel message to us
        // TODO:
        // TODO:

        todo!();
    }
}

impl<R: Runtime> Future for TunnelManager<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
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
