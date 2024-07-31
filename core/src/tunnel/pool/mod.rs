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
    i2np::RawI2npMessage,
    primitives::{MessageId, RouterId, RouterInfo, TunnelId},
    router_storage::RouterStorage,
    runtime::Runtime,
    tunnel::{
        hop::{InboundTunnel, OutboundTunnel, PendingTunnel, TunnelBuildParameters},
        noise::NoiseContext,
        pool::selector::{ClientSelector, ExploratorySelector, HopSelector, TunnelSelector},
    },
};

use bytes::Bytes;
use futures::{future::BoxFuture, FutureExt, Stream};
use hashbrown::HashMap;
use rand_core::RngCore;

use alloc::{boxed::Box, collections::VecDeque, vec, vec::Vec};
use core::{
    fmt,
    future::ready,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

mod selector;

/// Tunnel maintenance interval.
const TUNNEL_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(10);

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::pool";

/// Events emitted by the tunnel pools.
pub enum TunnelPoolEvent {
    /// Send I2NP message to router.
    SendI2NpMessage {
        /// Router ID.
        router: RouterId,

        /// Message ID.
        message_id: MessageId,

        /// Serialized I2NP message.
        message: Vec<u8>,
    },
}

impl fmt::Debug for TunnelPoolEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SendI2NpMessage {
                router,
                message_id,
                message,
            } => f
                .debug_struct("TunnelPoolEvent::SendI2NpMessage")
                .field("router", &router)
                .field("message_id", &message_id)
                .finish_non_exhaustive(),
        }
    }
}

/// Tunnel pool configuration.
pub struct TunnelPoolConfig {
    /// How many inbound tunnels the pool should have.
    num_inbound: usize,

    /// How many hops should each inbound tunnel have.
    num_inbound_hops: usize,

    /// How many outbound tunnels the pool should have.
    num_outbound: usize,

    /// How many hops should each outbound tunnel have.
    num_outbound_hops: usize,

    /// Destination of the tunnel (currently unused).
    destination: (),
}

pub struct TunnelPool<R> {
    /// Tunnel pool configuration.
    config: TunnelPoolConfig,

    /// Inbound tunnels.
    inbound: HashMap<TunnelId, InboundTunnel>,

    /// Noise context.
    noise: NoiseContext,

    /// Local router hash.
    our_hash: Bytes,

    /// Outbound tunnels.
    outbound: HashMap<TunnelId, OutboundTunnel>,

    /// Pending tunnels.
    pending: HashMap<MessageId, ()>,

    /// Marker
    _marker: PhantomData<R>,
}

impl<R: Runtime> TunnelPool<R> {
    /// Create empty [`TunnelPool`] from [`TunnelPoolConfig`].
    pub fn new(noise: NoiseContext, our_hash: Bytes, config: TunnelPoolConfig) -> Self {
        Self {
            config,
            inbound: HashMap::new(),
            _marker: Default::default(),
            noise,
            our_hash,
            outbound: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// Get next free `TunnelId` for an inbound/outbound tunnel.
    fn next_tunnel_id<const INBOUND: bool>(&self) -> TunnelId {
        loop {
            let tunnel_id = TunnelId::from(R::rng().next_u32());

            match INBOUND {
                true if !self.inbound.contains_key(&tunnel_id) => return tunnel_id,
                false if !self.outbound.contains_key(&tunnel_id) => return tunnel_id,
                _ => {}
            }
        }
    }

    /// Get net free `MessageId`.
    fn next_message_id(&self) -> MessageId {
        loop {
            let message_id = MessageId::from(R::rng().next_u32());

            if !self.pending.contains_key(&message_id) {
                return message_id;
            }
        }
    }

    /// Get reference to inbound tunnels of the pool.
    pub fn inbound(&self) -> &HashMap<TunnelId, InboundTunnel> {
        &self.inbound
    }

    /// Get reference to outbound tunnels of the pool.
    pub fn outbound(&self) -> &HashMap<TunnelId, OutboundTunnel> {
        &self.outbound
    }

    /// Maintain tunnels of the tunnel pool.
    pub fn maintain_tunnels(
        &mut self,
        selector: impl TunnelSelector + HopSelector,
    ) -> impl Iterator<Item = TunnelPoolEvent> {
        // TODO: pending tunnels!
        let num_inbound_to_build = self.config.num_inbound.saturating_sub(self.inbound.len());
        let num_outbound_to_build = self.config.num_outbound.saturating_sub(self.outbound.len());
        let mut events = Vec::<TunnelPoolEvent>::new();

        // build one or more outbound tunnels
        //
        // select an inbound tunnel for reply delivery from one of the pool's inbound tunnels
        // and if none exist, create a fake 0-hop inbound tunnel
        for _ in 0..num_outbound_to_build {
            match selector.select_inbound_tunnel(self.inbound.iter()) {
                Some((tunnel_id, tunnel)) => todo!(),
                None => {
                    let message_id = self.next_message_id();
                    let tunnel_id = self.next_tunnel_id::<true>();
                    let Some(hops) = selector.select_hops(self.config.num_outbound_hops) else {
                        tracing::warn!(
                            target: LOG_TARGET,
                            hops_required = ?self.config.num_outbound_hops,
                            "not enough routers for outbound tunnel build",
                        );
                        continue;
                    };

                    match PendingTunnel::create_outbound_tunnel::<R>(TunnelBuildParameters {
                        hops,
                        tunnel_id,
                        message_id,
                        noise: self.noise.clone(),
                        our_hash: self.our_hash.clone(),
                    }) {
                        Ok((tunnel, router, message)) => {
                            // TODO: what to do with tunnel?
                            events.push(TunnelPoolEvent::SendI2NpMessage {
                                router,
                                message_id,
                                message,
                            });
                        }
                        Err(error) => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                ?tunnel_id,
                                ?message_id,
                                ?error,
                                "failed to create outbound tunnel",
                            );
                            continue;
                        }
                    }
                }
            }
        }

        events.into_iter()
    }
}

/// Tunnel pool manager.
pub struct TunnelPoolManager<R: Runtime> {
    /// Exploratory tunnel pool.
    exploratory_pool: TunnelPool<R>,

    /// Maintenance timer.
    maintenance_timer: BoxFuture<'static, ()>,

    /// Metrics handle.
    metrics_handle: R::MetricsHandle,

    /// Noise context.
    noise: NoiseContext,

    /// Pending events.
    pending_events: VecDeque<TunnelPoolEvent>,

    /// Router storage.
    router_storage: RouterStorage,

    /// Client tunnels.
    tunnels: Vec<TunnelPool<R>>,
}

impl<R: Runtime> TunnelPoolManager<R> {
    /// Create new [`TunnelPoolManager`].
    pub fn new(
        noise: NoiseContext,
        our_hash: Bytes,
        metrics_handle: R::MetricsHandle,
        router_storage: RouterStorage,
        exploratory_pool_config: TunnelPoolConfig,
    ) -> Self {
        Self {
            exploratory_pool: TunnelPool::new(noise.clone(), our_hash, exploratory_pool_config),
            maintenance_timer: Box::pin(ready(())),
            metrics_handle,
            noise,
            pending_events: VecDeque::new(),
            router_storage,
            tunnels: Vec::new(),
        }
    }

    /// Maintain tunnel pools.
    ///
    /// Call into the exploratory tunnel pool to maintain exploratory tunnels and for each client
    /// tunnel pool, call [`TunnelPool::maintain_tunnels()`] to maintain client tunnels.
    ///
    /// Each call to [`TunnelPool::maintain_tunnels()`] yields events which must be forwarded to
    /// `TunnelManager` for further processing.
    fn maintain_tunnel_pools(&mut self) {
        tracing::trace!(target: LOG_TARGET, "maintain tunnel pools");

        // maintain the exploratory tunnel pool
        self.pending_events.extend(
            self.exploratory_pool
                .maintain_tunnels(ExploratorySelector::new(&self.router_storage)),
        );

        // maintain client tunnel pools
        self.tunnels.iter_mut().for_each(|tunnel| {
            self.pending_events.extend(tunnel.maintain_tunnels(ClientSelector::new(
                &self.exploratory_pool,
                &self.router_storage,
            )))
        })
    }
}

impl<R: Runtime> Stream for TunnelPoolManager<R> {
    type Item = TunnelPoolEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(Some(event));
        }

        futures::ready!(self.maintenance_timer.poll_unpin(cx));

        // create new timer and register it into the executor
        {
            self.maintenance_timer = Box::pin(R::delay(TUNNEL_MAINTENANCE_INTERVAL));
            let _ = self.maintenance_timer.poll_unpin(cx);
        }

        self.maintain_tunnel_pools();
        self.pending_events
            .pop_front()
            .map_or(Poll::Pending, |event| Poll::Ready(Some(event)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{base64_encode, StaticPrivateKey},
        primitives::RouterInfo,
        runtime::mock::MockRuntime,
    };

    use futures::StreamExt;
    use tracing_subscriber::prelude::*;

    #[tokio::test]
    async fn tunnel_test() {
        tracing_subscriber::registry().with(tracing_subscriber::fmt::layer()).try_init();

        let handle = MockRuntime::register_metrics(Vec::new());
        let router_storage = RouterStorage::from_random(
            (0..25).map(|_| RouterInfo::random::<MockRuntime>()).collect(),
        );
        let pool_config = TunnelPoolConfig {
            num_inbound: 1usize,
            num_inbound_hops: 2usize,
            num_outbound: 1usize,
            num_outbound_hops: 3usize,
            destination: (),
        };
        let noise = {
            let mut key_bytes = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut key_bytes);

            NoiseContext::new(StaticPrivateKey::from(key_bytes))
        };
        let our_hash = {
            let mut our_hash = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut our_hash);

            Bytes::from(our_hash)
        };

        tracing::info!("our router hash = {}", base64_encode(&our_hash));

        let mut pool_manager = TunnelPoolManager::<MockRuntime>::new(
            noise,
            our_hash,
            handle,
            router_storage,
            pool_config,
        );

        let event = pool_manager.next().await;

        tracing::error!("{event:?}");
    }
}
