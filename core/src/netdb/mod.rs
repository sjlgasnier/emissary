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
    i2np::{Message, MessageType},
    netdb::{dht::Dht, metrics::*},
    primitives::{RouterId, RouterInfo},
    router_storage::RouterStorage,
    runtime::{Counter, Gauge, MetricType, MetricsHandle, Runtime},
    subsystem::SubsystemEvent,
    transports::TransportService,
    tunnel::TunnelPoolHandle,
};

use futures::{FutureExt, StreamExt};
use hashbrown::{HashMap, HashSet};

use alloc::vec::Vec;
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

mod bucket;
mod dht;
mod metrics;
mod routing_table;
mod types;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::netdb";

/// Floodfill state.
#[derive(Debug)]
pub enum RouterState {
    /// FloodFill is connected.
    Connected,

    /// FloodFill is being dialed.
    Dialing {
        /// Pending messages.
        pending_messages: Vec<Vec<u8>>,
    },
}

/// Network database (NetDB).
pub struct NetDb<R: Runtime> {
    /// Kademlia DHT implementation.
    dht: Dht<R>,

    /// Metrics handle.
    metrics: R::MetricsHandle,

    /// Router storage.
    router_storage: RouterStorage,

    /// Connected floodfills.
    routers: HashMap<RouterId, RouterState>,

    /// Transport service.
    service: TransportService,

    /// Exploratory tunnel pool handle.
    exploratory_pool_handle: TunnelPoolHandle,
}

impl<R: Runtime> NetDb<R> {
    /// Create new [`NetDb`].
    pub fn new(
        local_router_id: RouterId,
        service: TransportService,
        router_storage: RouterStorage,
        metrics: R::MetricsHandle,
        exploratory_pool_handle: TunnelPoolHandle,
    ) -> Self {
        let floodfills = router_storage
            .routers()
            .iter()
            .filter_map(|(id, router)| router.is_floodfill().then_some(id.clone()))
            .collect::<HashSet<_>>();

        metrics.counter(NUM_FLOODFILLS).increment(floodfills.len());

        tracing::trace!(
            target: LOG_TARGET,
            num_floodfills = ?floodfills.len(),
            "starting netdb",
        );

        Self {
            exploratory_pool_handle,
            dht: Dht::new(local_router_id, floodfills, metrics.clone()),
            metrics,
            routers: HashMap::new(),
            router_storage,
            service,
        }
    }

    /// Collect `NetDb`-related metric counters, gauges and histograms.
    pub fn metrics(metrics: Vec<MetricType>) -> Vec<MetricType> {
        metrics::register_metrics(metrics)
    }

    /// Handle established connection to `router`.
    fn on_connection_established(&mut self, router_id: RouterId) {
        match self.routers.remove(&router_id) {
            None =>
                match self.router_storage.get(&router_id).expect("router to exist").is_floodfill() {
                    true => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            %router_id,
                            "new floodfill connected",
                        );

                        // insert new floodfills into `Dht` as well
                        self.dht.add_floodfill(router_id.clone());

                        self.routers.insert(router_id, RouterState::Connected);
                        self.metrics.gauge(NUM_CONNECTED_FLOODFILLS).increment(1);
                        self.metrics.counter(NUM_FLOODFILLS).increment(1);
                    }
                    false => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            %router_id,
                            "connection established",
                        );
                    }
                },
            Some(state) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    "known floodfill connected",
                );

                // "insert" floodfill into `Dht` so their "last active" status gets updated
                self.dht.add_floodfill(router_id.clone());

                self.routers.insert(router_id, RouterState::Connected);
                self.metrics.gauge(NUM_CONNECTED_FLOODFILLS).increment(1);
            }
        }
    }

    /// Handle closed connection to `router`.
    fn on_connection_closed(&mut self, router_id: RouterId) {
        match self.routers.remove(&router_id) {
            None => {
                tracing::trace!(
                    target: LOG_TARGET,
                    %router_id,
                    "connection closed",
                );
            }
            Some(_) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    "floodfill disconnected",
                );

                self.routers.remove(&router_id);
                self.metrics.gauge(NUM_CONNECTED_FLOODFILLS).decrement(1);
            }
        }
    }

    /// Handle I2NP message.
    fn on_message(&mut self, message: Message) {
        match message.message_type {
            MessageType::DatabaseStore => {
                tracing::trace!("database store");
            }
            MessageType::DatabaseLookup => {
                tracing::trace!("database lookup");
            }
            MessageType::DatabaseSearchReply => {
                tracing::trace!("database search reply");
            }
            message_type => tracing::warn!(
                target: LOG_TARGET,
                ?message_type,
                "unsupported message",
            ),
        }
    }
}

impl<R: Runtime> Future for NetDb<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.service.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(SubsystemEvent::I2Np { messages })) =>
                    messages.into_iter().for_each(|message| self.on_message(message)),
                Poll::Ready(Some(SubsystemEvent::ConnectionEstablished { router })) =>
                    self.on_connection_established(router),
                Poll::Ready(Some(SubsystemEvent::ConnectionClosed { router })) =>
                    self.on_connection_closed(router),
                _ => {}
            }
        }
    }
}
