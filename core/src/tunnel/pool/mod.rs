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
    crypto::StaticPublicKey,
    error::{ChannelError, RoutingError},
    i2np::{tunnel::gateway::TunnelGateway, Message, MessageBuilder},
    primitives::{MessageId, RouterId, TunnelId},
    router_storage::RouterStorage,
    runtime::{Counter, Gauge, JoinSet, MetricsHandle, Runtime},
    tunnel::{
        hop::{
            inbound::InboundTunnel, outbound::OutboundTunnel, pending::PendingTunnel, ReceiverKind,
            Tunnel, TunnelBuildParameters, TunnelInfo,
        },
        metrics::*,
        noise::NoiseContext,
        pool::{
            context::TunnelMessage,
            listener::TunnelBuildListener,
            selector::{ClientSelector, HopSelector, TunnelSelector},
            timer::{TunnelKind, TunnelTimer, TunnelTimerEvent},
            zero_hop::ZeroHopInboundTunnel,
        },
        routing_table::RoutingTable,
    },
    Error,
};

use bytes::Bytes;
use futures::{
    future::{select, BoxFuture, Either},
    FutureExt, Stream, StreamExt,
};
use futures_channel::oneshot;
use hashbrown::{HashMap, HashSet};
use listener::ReceiveKind;
use rand_core::RngCore;
use thingbuf::mpsc;

#[cfg(feature = "std")]
use parking_lot::RwLock;
#[cfg(feature = "no_std")]
use spin::rwlock::RwLock;

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

pub use context::{TunnelPoolContext, TunnelPoolHandle};
pub use selector::ExploratorySelector;

mod context;
mod listener;
mod selector;
mod timer;
mod zero_hop;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::pool";

/// Tunnel maintenance interval.
const TUNNEL_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(10);

/// Tunnel build request expiration.
///
/// How long is a pending tunnel kept active before the request is considered failed.
const TUNNEL_BUILD_EXPIRATION: Duration = Duration::from_secs(8);

/// Tunnel channel size.
const TUNNEL_CHANNEL_SIZE: usize = 64usize;

/// Tunnel rebuild timeout.
///
/// Tunnel of a pool needs to be rebuilt before it expires as otherwise the pool may be not have any
/// tunnels of that type. Start building a new tunnel to replace to old one 2 minutes before the old
/// tunnel expires.
const TUNNEL_REBUILD_TIMEOUT: Duration = Duration::from_secs(8 * 10);

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

impl Default for TunnelPoolConfig {
    fn default() -> Self {
        Self {
            num_inbound: 1usize,
            num_inbound_hops: 2usize,
            num_outbound: 1usize,
            num_outbound_hops: 2usize,
            destination: (),
        }
    }
}

// enum DeliveryInstructions {
//     Local,
//     Router {
//         /// Router ID.
//         router_id: RouterId,
//     },
//     Tunnel {
//         /// Tunnel ID.
//         tunnel_id: TunnelId,

//         /// Router ID.
//         router_id: RouterId,
//     },
// }

// pub struct TunnelSender {
//     delivery_instructions: Option<DeliveryInstructions>,
// }

// impl TunnelSender {
//     /// Create new
//     fn new(gateway: TunnelId, message: Vec<u8>) -> Self {
//         Self {
//             delivery_instructions: None,
//         }
//     }

//     /// Send message through the tunnel to its endpoint.
//     pub fn with_local_delivery(mut self) -> Self {
//         assert!(self.delivery_instructions.is_none());

//         self.delivery_instructions = Some(DeliveryInstructions::Local);
//         self
//     }

//     /// Send message through the tunnel to `router_id`.
//     pub fn with_router_delivery(mut self, router_id: RouterId) -> Self {
//         assert!(self.delivery_instructions.is_none());

//         self.delivery_instructions = Some(DeliveryInstructions::Router { router_id });
//         self
//     }

//     /// Send message through the tunnel to (`destination`, `router_id`).
//     pub fn with_tunnel_delivery(mut self, router_id: RouterId, destination: TunnelId) -> Self {
//         assert!(self.delivery_instructions.is_none());

//         self.delivery_instructions = Some(DeliveryInstructions::Tunnel {
//             router_id,
//             tunnel_id: destination,
//         });
//         self
//     }

//     pub fn with_listener(self, _listener: oneshot::Receiver<Message>) -> Self {
//         self
//     }

//     pub fn send(self) -> Result<(), ()> {
//         assert!(self.delivery_instructions.is_some());

//         Ok(())
//     }
// }

/// Tunnel pool implementation.
///
/// Tunnel pool manages a set of inbound and outbound tunnels for a particular destination.
pub struct TunnelPool<R: Runtime, S: TunnelSelector + HopSelector> {
    /// Tunnel pool configuration.
    config: TunnelPoolConfig,

    /// Tunne pool context.
    context: TunnelPoolContext,

    /// Expiring inbound tunnels.
    expiring_inbound: HashSet<TunnelId>,

    /// Expiring outbound tunnels.
    expiring_outbound: HashSet<TunnelId>,

    /// Active inbound tunnels.
    inbound: R::JoinSet<TunnelId>,

    /// Tunnel maintenance timer.
    maintenance_timer: BoxFuture<'static, ()>,

    /// Metrics handle.
    metrics: R::MetricsHandle,

    /// Noise context.
    noise: NoiseContext,

    /// Active outbound tunnels.
    outbound: HashMap<TunnelId, OutboundTunnel<R>>,

    /// Pending inbound tunnels.
    pending_inbound: TunnelBuildListener<R, InboundTunnel>,

    /// Pending outbound tunnels.
    pending_outbound: TunnelBuildListener<R, OutboundTunnel<R>>,

    /// Routing table.
    routing_table: RoutingTable,

    /// Tunnel/hop selector for the tunnel pool.
    selector: S,

    /// Expiration timers for inbound/outbound tunnels.
    tunnel_timers: TunnelTimer<R>,
}

impl<R: Runtime, S: TunnelSelector + HopSelector> TunnelPool<R, S> {
    /// Create new [`TunnelPool`].
    pub fn new(
        config: TunnelPoolConfig,
        selector: S,
        context: TunnelPoolContext,
        routing_table: RoutingTable,
        noise: NoiseContext,
        metrics: R::MetricsHandle,
    ) -> Self {
        Self {
            config,
            context,
            expiring_inbound: HashSet::new(),
            expiring_outbound: HashSet::new(),
            inbound: R::join_set(),
            maintenance_timer: Box::pin(R::delay(Duration::from_secs(0))),
            metrics,
            noise,
            outbound: HashMap::new(),
            pending_inbound: TunnelBuildListener::new(routing_table.clone()),
            pending_outbound: TunnelBuildListener::new(routing_table.clone()),
            routing_table,
            selector,
            tunnel_timers: TunnelTimer::new(),
        }
    }

    /// Maintain the tunnel pool.
    ///
    /// If the number of inbound/outbound is less than desired, build new tunnels.
    ///
    /// Each active tunnel gets tested once every 10 seconds by selecting a pair of random tunnels
    /// and sending a test message to the outbound tunnel and receiving the message back via the
    /// paired inbound tunnels.
    fn maintain_pool(&mut self) {
        // build one or more outbound tunnels
        //
        // select an inbound tunnel for reply delivery from one of the available inbound tunnels
        // and if none exist, create a fake 0-hop inbound tunnel
        let num_outbound_to_build = self
            .config
            .num_outbound
            .saturating_sub(self.outbound.len())
            .saturating_sub(self.pending_outbound.len())
            .saturating_add(self.expiring_outbound.len());

        for _ in 0..num_outbound_to_build {
            // attempt to select hops for the outbound tunnel
            //
            // if there aren't enough available hops, the tunnel build is skipped
            let Some(hops) = self.selector.select_hops(self.config.num_outbound_hops) else {
                tracing::warn!(
                    target: LOG_TARGET,
                    hops_required = ?self.config.num_outbound_hops,
                    "not enough routers for outbound tunnel build",
                );
                continue;
            };

            // allocate random tunnel id for the pending outbound tunnel
            //
            // this can just be a random id (with no regard for collisions)
            // as outbound tunnel messages are not routed through `RoutingTable`
            let tunnel_id = TunnelId::from(R::rng().next_u32());

            // build outbound tunnel
            //
            // the tunnel build reply is received either through an existing inbound tunnel
            // or through a fake 0-hop inbound tunnel if there are no available inbound tunnels
            match self.selector.select_inbound_tunnel() {
                // no inbound tunnels available
                //
                // create a fake 0-hop inbound tunnel and add listener for the tunnel build reply
                // in the routing table
                //
                // if the reply is received, it'll be routed via the routing table to the fake
                // inbound tunnel which routes it to inbound tunnel `TunnelListener` from which
                // it'll be received by the `TunnelPool`
                None => {
                    // the fake 0-hop tunnel routes the build response via `RoutingTable`
                    let (gateway, zero_hop_tunnel) =
                        ZeroHopInboundTunnel::new::<R>(self.routing_table.clone());

                    // generate message id for the build request and optimistically insert
                    // a listener tx channel for it in the routing table
                    //
                    // if the building the build request fails, the listener must be removed
                    // from the routing table
                    let (message_id, message_rx) =
                        self.routing_table.insert_listener(&mut R::rng());

                    tracing::trace!(
                        target: LOG_TARGET,
                        %tunnel_id,
                        %gateway,
                        %message_id,
                        num_hops = ?hops.len(),
                        "build outbound tunnel via 0-hop tunnel",
                    );

                    match PendingTunnel::<OutboundTunnel<R>>::create_tunnel::<R>(
                        TunnelBuildParameters {
                            hops,
                            tunnel_info: TunnelInfo::Outbound {
                                gateway,
                                tunnel_id,
                                router_id: self.noise.local_router_hash().clone(),
                            },
                            receiver: ReceiverKind::Outbound,
                            message_id,
                            noise: self.noise.clone(),
                        },
                    ) {
                        Ok((tunnel, router_id, message)) => {
                            // spawn the fake 0-hop inbound tunnel in the background if it exists
                            //
                            // it will exit after receiving its first message because
                            // the tunnel is only used for this particular build request
                            R::spawn(zero_hop_tunnel);

                            // add pending tunnel into outbound tunnel build listener
                            // and send tunnel build request to the first hop
                            self.pending_outbound.add_pending_tunnel(
                                tunnel,
                                ReceiveKind::RoutingTable { message_id },
                                message_rx,
                            );
                            self.metrics.gauge(NUM_PENDING_OUTBOUND_TUNNELS).increment(1);

                            self.routing_table.send_message(router_id, message.serialize_short());
                        }
                        Err(error) => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                %tunnel_id,
                                %message_id,
                                ?error,
                                "failed to create outbound tunnel",
                            );

                            self.routing_table.remove_tunnel(&gateway);
                            self.routing_table.remove_listener(&message_id);
                        }
                    }
                }
                // inbound tunnel available
                //
                // add message listener for selected tunnel's tunnel pool and send the build request
                //
                // once the tunnel build reply is received into the selected inbound tunnel (which
                // could be a different pool), it'll be received by the selected tunnel's
                // `TunnelPool` which routes the message to the listener
                Some((gateway, router_id, handle)) => {
                    // if an inbound tunnel exists, the reply is routed through it and received
                    // by its `TunnelPool` which routes the message to the listener
                    let (message_id, message_rx) = handle.add_listener(&mut R::rng());

                    tracing::trace!(
                        target: LOG_TARGET,
                        %tunnel_id,
                        %gateway,
                        %router_id,
                        %message_id,
                        num_hops = ?hops.len(),
                        "build outbound tunnel via existing inbound tunnel",
                    );

                    match PendingTunnel::<OutboundTunnel<R>>::create_tunnel::<R>(
                        TunnelBuildParameters {
                            hops,
                            tunnel_info: TunnelInfo::Outbound {
                                gateway,
                                router_id: Bytes::from(Into::<Vec<u8>>::into(router_id)),
                                tunnel_id,
                            },
                            receiver: ReceiverKind::Outbound,
                            message_id,
                            noise: self.noise.clone(),
                        },
                    ) {
                        Ok((tunnel, router_id, message)) => {
                            // add pending tunnel into outbound tunnel build listener
                            // and send tunnel build request to the first hop
                            self.pending_outbound.add_pending_tunnel(
                                tunnel,
                                ReceiveKind::Tunnel {
                                    handle: handle.clone(),
                                    message_id,
                                },
                                message_rx,
                            );
                            self.metrics.gauge(NUM_PENDING_OUTBOUND_TUNNELS).increment(1);

                            self.routing_table.send_message(router_id, message.serialize_short());
                        }
                        Err(error) => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                %tunnel_id,
                                %message_id,
                                ?error,
                                "failed to create outbound tunnel",
                            );

                            handle.remove_listener(&message_id);
                        }
                    }
                }
            }
        }

        // build one or more inbound tunnels
        //
        // select an outbound for request delivery from one of the available outbound tunnels
        //
        // select an inbound tunnel for reply delivery from one of the pool's inbound tunnels
        // and if none exist, use a fake 0-hop outbound tunnel
        let num_inbound_to_build = self
            .config
            .num_inbound
            .saturating_sub(self.inbound.len())
            .saturating_sub(self.pending_inbound.len())
            .saturating_add(self.expiring_inbound.len());

        for _ in 0..num_inbound_to_build {
            // tunnel that's used to deliver the tunnel build request message
            //
            // if it's `None`, a fake 0-hop outbound tunnel is used
            let send_tunnel_id = self.selector.select_outbound_tunnel();

            // select hops for the tunnel
            let Some(hops) = self.selector.select_hops(self.config.num_inbound_hops) else {
                tracing::warn!(
                    target: LOG_TARGET,
                    hops_required = ?self.config.num_inbound_hops,
                    "not enough routers for inbound tunnel build",
                );
                continue;
            };

            // generate message id for the build request and optimistically insert
            // a listener tx channel for it in the routing table
            //
            // if the building the build request fails, the listener must be removed
            // from the routing table
            let (message_id, message_rx) = self.routing_table.insert_listener(&mut R::rng());

            // generate tunnel id for the inbound tunnel that's about to be built
            let (tunnel_id, tunnel_rx) =
                self.routing_table.insert_tunnel::<TUNNEL_CHANNEL_SIZE>(&mut R::rng());

            match PendingTunnel::<InboundTunnel>::create_tunnel::<R>(TunnelBuildParameters {
                hops,
                tunnel_info: TunnelInfo::Inbound {
                    tunnel_id,
                    router_id: self.noise.local_router_hash().clone(),
                },
                receiver: ReceiverKind::Inbound {
                    message_rx: tunnel_rx,
                    handle: self.context.handle(),
                },
                message_id,
                noise: self.noise.clone(),
            }) {
                Ok((tunnel, router, message)) => {
                    // add pending tunnel into outbound tunnel build listener and send
                    // tunnel build request to the first hop
                    self.pending_inbound.add_pending_tunnel(
                        tunnel,
                        ReceiveKind::RoutingTable { message_id },
                        message_rx,
                    );
                    self.metrics.gauge(NUM_PENDING_INBOUND_TUNNELS).increment(1);

                    match send_tunnel_id {
                        None => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                %tunnel_id,
                                "no outbound tunnel available, send build request directly",
                            );
                            self.routing_table.send_message(router, message.serialize_short());
                        }
                        Some((send_tunnel_id, handle)) => {
                            tracing::trace!(
                                target: LOG_TARGET,
                                %tunnel_id,
                                %send_tunnel_id,
                                "send tunnel build request to local outbound tunnel",
                            );

                            if let Err(error) = handle.send_message(
                                send_tunnel_id,
                                router,
                                message.serialize_standard(),
                            ) {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    %tunnel_id,
                                    %send_tunnel_id,
                                    ?error,
                                    "failed to send message to outbound tunnel"
                                );
                            }
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?tunnel_id,
                        ?message_id,
                        ?error,
                        "failed to create outbound tunnel",
                    );

                    self.routing_table.remove_tunnel(&tunnel_id);
                    self.routing_table.remove_listener(&message_id);
                    continue;
                }
            }
        }
    }
}

impl<R: Runtime, S: TunnelSelector + HopSelector> Future for TunnelPool<R, S> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        while let Poll::Ready(Some((tunnel_id, event))) = self.pending_outbound.poll_next_unpin(cx)
        {
            match event {
                Err(error) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to build outbound tunnel",
                    );

                    // TODO: remove message listener

                    self.metrics.counter(NUM_BUILD_FAILURES).increment(1);
                    self.metrics.gauge(NUM_PENDING_OUTBOUND_TUNNELS).decrement(1);
                }
                Ok(tunnel) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        outbound_tunnel_id = %tunnel.tunnel_id(),
                        "outbound tunnel built",
                    );

                    self.selector.add_outbound_tunnel(tunnel_id);
                    self.outbound.insert(tunnel_id, tunnel);
                    self.metrics.gauge(NUM_PENDING_OUTBOUND_TUNNELS).decrement(1);
                    self.metrics.gauge(NUM_OUTBOUND_TUNNELS).increment(1);
                }
            }
        }

        while let Poll::Ready(Some((tunnel_id, event))) = self.pending_inbound.poll_next_unpin(cx) {
            match event {
                Err(error) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        %tunnel_id,
                        ?error,
                        "failed to build inbound channel",
                    );

                    self.routing_table.remove_tunnel(&tunnel_id);
                    self.metrics.counter(NUM_BUILD_FAILURES).increment(1);
                    self.metrics.gauge(NUM_PENDING_INBOUND_TUNNELS).decrement(1);
                }
                Ok(tunnel) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        tunnel_id = %tunnel.tunnel_id(),
                        "inbound tunnel built",
                    );

                    // TODO: explain
                    let (router_id, tunnel_id) = tunnel.gateway();
                    self.selector.add_inbound_tunnel(tunnel_id, router_id);

                    self.inbound.push(tunnel);
                    self.metrics.gauge(NUM_INBOUND_TUNNELS).increment(1);
                    self.metrics.gauge(NUM_PENDING_INBOUND_TUNNELS).decrement(1);
                }
            }
        }

        while let Poll::Ready(event) = self.inbound.poll_next_unpin(cx) {
            match event {
                None => return Poll::Ready(()),
                Some(tunnel_id) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %tunnel_id,
                        "inbound tunnel exited",
                    );
                    self.expiring_inbound.remove(&tunnel_id);
                    self.routing_table.remove_tunnel(&tunnel_id);
                }
            }
        }

        while let Poll::Ready(event) = self.context.poll_next_unpin(cx) {
            match event {
                None => return Poll::Ready(()),
                Some(event) => match event {
                    TunnelMessage::Dummy => unreachable!(),
                    TunnelMessage::Outbound {
                        gateway,
                        router_id,
                        message,
                    } => {
                        // TODO: no unwraps
                        let tunnel = self.outbound.get(&gateway).unwrap();
                        let (router_id, message) = tunnel.send_to_router(router_id, message);
                        self.routing_table.send_message(router_id, message).unwrap();
                    }
                    TunnelMessage::Inbound { message } => tracing::warn!(
                        target: LOG_TARGET,
                        message_type = ?message.message_type,
                        "unhandled message"
                    ),
                },
            }
        }

        // poll tunnel timers
        //
        // both inbound and outbound tunnels emit `Rebuild` events which indicate that the tunnel is
        // about to expire and tunnel pool should build a replacement for the expiring tunnel
        //
        // as outbound tunnels do not have an asynchronous event loop but are instead stored in
        // tunnel pool, `TunnelTimer` also emits a `Destroy` event for them so tunnel pool knows
        // when to remove them from `outbound`
        //
        // inbound tunnels have their own event loops which track when the tunnel should be
        // destroyed and thus tunnel pool doesn't need an explicit signal from `TunnelTimer` for
        // inbound tunnel destruction
        while let Poll::Ready(event) = self.tunnel_timers.poll_next_unpin(cx) {
            match event {
                None => return Poll::Ready(()),
                Some(TunnelTimerEvent::Destroy { tunnel_id }) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %tunnel_id,
                        "outbound tunnel expired",
                    );
                    self.outbound.remove(&tunnel_id);
                    self.expiring_outbound.remove(&tunnel_id);
                }
                Some(TunnelTimerEvent::Rebuild {
                    kind: TunnelKind::Outbound { tunnel_id },
                }) => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        %tunnel_id,
                        "outbound tunnel about to expire",
                    );
                    self.expiring_outbound.insert(tunnel_id);
                }
                Some(TunnelTimerEvent::Rebuild {
                    kind: TunnelKind::Inbound { tunnel_id },
                }) => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        %tunnel_id,
                        "inbound tunnel about to expire",
                    );
                    self.expiring_inbound.insert(tunnel_id);
                }
            }
        }

        futures::ready!(self.maintenance_timer.poll_unpin(cx));

        // create new timer and register it into the executor
        {
            self.maintenance_timer = Box::pin(R::delay(TUNNEL_MAINTENANCE_INTERVAL));
            let _ = self.maintenance_timer.poll_unpin(cx);
        }

        self.maintain_pool();

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{base64_encode, StaticPrivateKey},
        primitives::{RouterId, RouterInfo},
        runtime::mock::MockRuntime,
        tunnel::tests::TestTransitTunnelManager,
    };
    use futures::StreamExt;

    #[tokio::test]
    async fn build_outbound_exploratory_tunnel() {
        // create 10 routers and add them to local `RouterStorage`
        let mut routers = (0..10)
            .map(|_| {
                let transit = TestTransitTunnelManager::new();
                let router_id = transit.router();

                (transit.router(), transit)
            })
            .collect::<HashMap<_, _>>();
        let router_storage = RouterStorage::from_random(
            routers.iter().map(|(_, transit)| transit.router_info()).collect(),
        );

        let pool_config = TunnelPoolConfig {
            num_inbound: 0usize,
            num_inbound_hops: 0usize,
            num_outbound: 1usize,
            num_outbound_hops: 3usize,
            destination: (),
        };
        let our_hash = {
            let mut our_hash = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut our_hash);

            Bytes::from(our_hash)
        };
        let noise = {
            let mut key_bytes = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut key_bytes);

            NoiseContext::new(StaticPrivateKey::from(key_bytes), our_hash.clone())
        };
        let handle = MockRuntime::register_metrics(Vec::new());
        let (manager_tx, manager_rx) = mpsc::channel(64);
        let (transit_tx, transit_rx) = mpsc::channel(64);
        let routing_table = RoutingTable::new(RouterId::from(our_hash), manager_tx, transit_tx);
        let (context, pool_handle) = TunnelPoolContext::new();

        let mut tunnel_pool = TunnelPool::<MockRuntime, _>::new(
            pool_config,
            ExploratorySelector::new(router_storage.clone(), pool_handle),
            context,
            routing_table.clone(),
            noise,
            handle.clone(),
        );

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.pending_outbound.len(), 1);

        // 1st outbound hop (participant)
        let (router, message) = manager_rx.try_recv().unwrap();
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 2nd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 3rd outbound hop (obep)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // route tunnel build response to the fake 0-hop inbound tunnel
        let message = Message::parse_short(&message).unwrap();
        routing_table.route_message(message);

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.outbound.len(), 1);
        assert_eq!(tunnel_pool.pending_outbound.len(), 0);
        assert_eq!(MockRuntime::get_gauge_value(NUM_OUTBOUND_TUNNELS), Some(1));
    }

    #[tokio::test]
    async fn outbound_exploratory_build_request_expires() {
        // create 10 routers and add them to local `RouterStorage`
        let mut routers = (0..10)
            .map(|_| {
                let transit = TestTransitTunnelManager::new();
                let router_id = transit.router();

                (transit.router(), transit)
            })
            .collect::<HashMap<_, _>>();
        let router_storage = RouterStorage::from_random(
            routers.iter().map(|(_, transit)| transit.router_info()).collect(),
        );

        let pool_config = TunnelPoolConfig {
            num_inbound: 0usize,
            num_inbound_hops: 0usize,
            num_outbound: 1usize,
            num_outbound_hops: 3usize,
            destination: (),
        };
        let our_hash = {
            let mut our_hash = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut our_hash);

            Bytes::from(our_hash)
        };
        let noise = {
            let mut key_bytes = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut key_bytes);

            NoiseContext::new(StaticPrivateKey::from(key_bytes), our_hash.clone())
        };
        let handle = MockRuntime::register_metrics(Vec::new());
        let (manager_tx, manager_rx) = mpsc::channel(64);
        let (transit_tx, transit_rx) = mpsc::channel(64);
        let routing_table = RoutingTable::new(RouterId::from(our_hash), manager_tx, transit_tx);
        let (context, pool_handle) = TunnelPoolContext::new();

        let mut tunnel_pool = TunnelPool::<MockRuntime, _>::new(
            pool_config,
            ExploratorySelector::new(router_storage.clone(), pool_handle),
            context,
            routing_table.clone(),
            noise,
            handle.clone(),
        );

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.pending_outbound.len(), 1);

        // 1st outbound hop (participant)
        let (router, message) = manager_rx.try_recv().unwrap();
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 2nd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 3rd outbound hop (obep)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // don't route the response which causes the build request to expire
        assert!(tokio::time::timeout(TUNNEL_BUILD_EXPIRATION, &mut tunnel_pool).await.is_err());
        assert_eq!(MockRuntime::get_counter_value(NUM_BUILD_FAILURES), Some(1));
    }

    #[tokio::test]
    async fn build_inbound_exploratory_tunnel() {
        // create 10 routers and add them to local `RouterStorage`
        let mut routers = (0..10)
            .map(|_| {
                let transit = TestTransitTunnelManager::new();
                let router_id = transit.router();

                (transit.router(), transit)
            })
            .collect::<HashMap<_, _>>();
        let router_storage = RouterStorage::from_random(
            routers.iter().map(|(_, transit)| transit.router_info()).collect(),
        );

        let pool_config = TunnelPoolConfig {
            num_inbound: 1usize,
            num_inbound_hops: 3usize,
            num_outbound: 0usize,
            num_outbound_hops: 0usize,
            destination: (),
        };
        let our_hash = {
            let mut our_hash = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut our_hash);

            Bytes::from(our_hash)
        };
        let noise = {
            let mut key_bytes = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut key_bytes);

            NoiseContext::new(StaticPrivateKey::from(key_bytes), our_hash.clone())
        };
        let handle = MockRuntime::register_metrics(Vec::new());
        let (manager_tx, manager_rx) = mpsc::channel(64);
        let (transit_tx, transit_rx) = mpsc::channel(64);
        let routing_table = RoutingTable::new(RouterId::from(our_hash), manager_tx, transit_tx);
        let (context, pool_handle) = TunnelPoolContext::new();

        let mut tunnel_pool = TunnelPool::<MockRuntime, _>::new(
            pool_config,
            ExploratorySelector::new(router_storage.clone(), pool_handle),
            context,
            routing_table.clone(),
            noise,
            handle.clone(),
        );

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.pending_inbound.len(), 1);

        // 1st outbound hop (ibgw)
        let (router, message) = manager_rx.try_recv().unwrap();
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 2nd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 3rd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // route tunnel build response to the tunnel build response listener
        let message = Message::parse_short(&message).unwrap();
        routing_table.route_message(message);

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.inbound.len(), 1);
        assert_eq!(tunnel_pool.pending_inbound.len(), 0);
        assert_eq!(MockRuntime::get_gauge_value(NUM_INBOUND_TUNNELS), Some(1));
    }

    #[tokio::test]
    async fn inbound_exploratory_build_request_expires() {
        // create 10 routers and add them to local `RouterStorage`
        let mut routers = (0..10)
            .map(|_| {
                let transit = TestTransitTunnelManager::new();
                let router_id = transit.router();

                (transit.router(), transit)
            })
            .collect::<HashMap<_, _>>();
        let router_storage = RouterStorage::from_random(
            routers.iter().map(|(_, transit)| transit.router_info()).collect(),
        );

        let pool_config = TunnelPoolConfig {
            num_inbound: 1usize,
            num_inbound_hops: 3usize,
            num_outbound: 0usize,
            num_outbound_hops: 0usize,
            destination: (),
        };
        let our_hash = {
            let mut our_hash = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut our_hash);

            Bytes::from(our_hash)
        };
        let noise = {
            let mut key_bytes = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut key_bytes);

            NoiseContext::new(StaticPrivateKey::from(key_bytes), our_hash.clone())
        };
        let handle = MockRuntime::register_metrics(Vec::new());
        let (manager_tx, manager_rx) = mpsc::channel(64);
        let (transit_tx, transit_rx) = mpsc::channel(64);
        let routing_table = RoutingTable::new(RouterId::from(our_hash), manager_tx, transit_tx);
        let (context, pool_handle) = TunnelPoolContext::new();

        let mut tunnel_pool = TunnelPool::<MockRuntime, _>::new(
            pool_config,
            ExploratorySelector::new(router_storage.clone(), pool_handle),
            context,
            routing_table.clone(),
            noise,
            handle.clone(),
        );

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.pending_inbound.len(), 1);

        // 1st outbound hop (ibgw)
        let (router, message) = manager_rx.try_recv().unwrap();
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 2nd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 3rd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // don't route the response which causes the build request to expire
        assert!(tokio::time::timeout(TUNNEL_BUILD_EXPIRATION, &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.inbound.len(), 0);
        assert_eq!(MockRuntime::get_counter_value(NUM_BUILD_FAILURES), Some(1))
    }

    #[tokio::test]
    async fn build_inbound_client_tunnel() {
        // create 10 routers and add them to local `RouterStorage`
        let mut routers = (0..10)
            .map(|_| {
                let transit = TestTransitTunnelManager::new();
                let router_id = transit.router();

                (transit.router(), transit)
            })
            .collect::<HashMap<_, _>>();
        let router_storage = RouterStorage::from_random(
            routers.iter().map(|(_, transit)| transit.router_info()).collect(),
        );

        let pool_config = TunnelPoolConfig {
            num_inbound: 0usize,
            num_inbound_hops: 0usize,
            num_outbound: 1usize,
            num_outbound_hops: 3usize,
            destination: (),
        };
        let our_hash = {
            let mut our_hash = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut our_hash);

            Bytes::from(our_hash)
        };
        let noise = {
            let mut key_bytes = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut key_bytes);

            NoiseContext::new(StaticPrivateKey::from(key_bytes), our_hash.clone())
        };
        let handle = MockRuntime::register_metrics(Vec::new());
        let (manager_tx, manager_rx) = mpsc::channel(64);
        let (transit_tx, transit_rx) = mpsc::channel(64);
        let routing_table =
            RoutingTable::new(RouterId::from(our_hash.clone()), manager_tx, transit_tx);
        let (context, pool_handle) = TunnelPoolContext::new();
        let (client_context, client_pool_handle) = TunnelPoolContext::new();
        let exploratory_selector = ExploratorySelector::new(router_storage.clone(), pool_handle);
        let client_selector = ClientSelector::new(exploratory_selector.clone(), client_pool_handle);

        let mut exploratory_pool = TunnelPool::<MockRuntime, _>::new(
            pool_config,
            exploratory_selector.clone(),
            context,
            routing_table.clone(),
            noise.clone(),
            handle.clone(),
        );

        assert!(
            tokio::time::timeout(Duration::from_secs(2), &mut exploratory_pool)
                .await
                .is_err()
        );
        assert_eq!(exploratory_pool.pending_outbound.len(), 1);

        // 1st outbound hop (participant)
        let (router, message) = manager_rx.try_recv().unwrap();
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 2nd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 3rd outbound hop (obep)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // route tunnel build response to the fake 0-hop inbound tunnel
        let message = Message::parse_short(&message).unwrap();
        routing_table.route_message(message);

        assert!(
            tokio::time::timeout(Duration::from_secs(2), &mut exploratory_pool)
                .await
                .is_err()
        );
        assert_eq!(exploratory_pool.outbound.len(), 1);
        assert_eq!(exploratory_pool.pending_outbound.len(), 0);
        assert_eq!(MockRuntime::get_gauge_value(NUM_OUTBOUND_TUNNELS), Some(1));

        {
            let pool_config = TunnelPoolConfig {
                num_inbound: 1usize,
                num_inbound_hops: 3usize,
                num_outbound: 0usize,
                num_outbound_hops: 0usize,
                destination: (),
            };
            let mut client_pool = TunnelPool::<MockRuntime, _>::new(
                pool_config,
                exploratory_selector,
                client_context,
                routing_table.clone(),
                noise,
                handle.clone(),
            );

            let future = async {
                tokio::select! {
                    _ = &mut client_pool => {}
                    _ = &mut exploratory_pool => {}
                }
            };

            assert!(tokio::time::timeout(Duration::from_secs(1), future).await.is_err());

            let (router_id, message) = manager_rx.try_recv().unwrap();

            // 1st hop (participant)
            let (router_id, message) = {
                let message = Message::parse_short(&message).unwrap();
                let mut router = routers.get_mut(&router_id).unwrap();

                router.routing_table().route_message(message).unwrap();
                assert!(tokio::time::timeout(Duration::from_secs(1), &mut router).await.is_err());
                router.message_rx().try_recv().unwrap()
            };

            // 2nd hop (participant)
            let (router_id, message) = {
                let message = Message::parse_short(&message).unwrap();
                let mut router = routers.get_mut(&router_id).unwrap();

                router.routing_table().route_message(message).unwrap();
                assert!(tokio::time::timeout(Duration::from_secs(1), &mut router).await.is_err());
                router.message_rx().try_recv().unwrap()
            };

            // 3rd hop (obep)
            let (router_id, message) = {
                let message = Message::parse_short(&message).unwrap();
                let mut router = routers.get_mut(&router_id).unwrap();

                router.routing_table().route_message(message).unwrap();
                assert!(tokio::time::timeout(Duration::from_secs(1), &mut router).await.is_err());
                router.message_rx().try_recv().unwrap()
            };

            // inbound build 1st hop (ibgw)
            let (router_id, message) = {
                let message = Message::parse_short(&message).unwrap();
                let mut router = routers.get_mut(&router_id).unwrap();

                router.routing_table().route_message(message).unwrap();
                assert!(tokio::time::timeout(Duration::from_secs(1), &mut router).await.is_err());
                router.message_rx().try_recv().unwrap()
            };

            // inbound build 2nd hop (participant)
            let (router_id, message) = {
                let message = Message::parse_short(&message).unwrap();
                let mut router = routers.get_mut(&router_id).unwrap();

                router.routing_table().route_message(message).unwrap();
                assert!(tokio::time::timeout(Duration::from_secs(1), &mut router).await.is_err());
                router.message_rx().try_recv().unwrap()
            };

            // inbound build 3rd hop (participant)
            let (router_id, message) = {
                let message = Message::parse_short(&message).unwrap();
                let mut router = routers.get_mut(&router_id).unwrap();

                router.routing_table().route_message(message).unwrap();
                assert!(tokio::time::timeout(Duration::from_secs(1), &mut router).await.is_err());
                router.message_rx().try_recv().unwrap()
            };

            assert_eq!(router_id, RouterId::from(our_hash));

            let message = Message::parse_short(&message).unwrap();
            routing_table.route_message(message);

            let future = async {
                tokio::select! {
                    _ = &mut client_pool => {}
                    _ = &mut exploratory_pool => {}
                }
            };

            assert!(tokio::time::timeout(Duration::from_secs(1), future).await.is_err());
        }

        assert_eq!(MockRuntime::get_gauge_value(NUM_OUTBOUND_TUNNELS), Some(1));
        assert_eq!(MockRuntime::get_gauge_value(NUM_INBOUND_TUNNELS), Some(1));
    }

    #[tokio::test]
    async fn build_outbound_client_tunnel() {
        // create 10 routers and add them to local `RouterStorage`
        let mut routers = (0..10)
            .map(|_| {
                let transit = TestTransitTunnelManager::new();
                let router_id = transit.router();

                (transit.router(), transit)
            })
            .collect::<HashMap<_, _>>();
        let router_storage = RouterStorage::from_random(
            routers.iter().map(|(_, transit)| transit.router_info()).collect(),
        );

        let pool_config = TunnelPoolConfig {
            num_inbound: 1usize,
            num_inbound_hops: 3usize,
            num_outbound: 0usize,
            num_outbound_hops: 0usize,
            destination: (),
        };
        let our_hash = {
            let mut our_hash = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut our_hash);

            Bytes::from(our_hash)
        };
        let noise = {
            let mut key_bytes = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut key_bytes);

            NoiseContext::new(StaticPrivateKey::from(key_bytes), our_hash.clone())
        };
        let handle = MockRuntime::register_metrics(Vec::new());
        let (manager_tx, manager_rx) = mpsc::channel(64);
        let (transit_tx, transit_rx) = mpsc::channel(64);
        let routing_table =
            RoutingTable::new(RouterId::from(our_hash.clone()), manager_tx, transit_tx);
        let (context, pool_handle) = TunnelPoolContext::new();
        let (client_context, client_pool_handle) = TunnelPoolContext::new();
        let exploratory_selector = ExploratorySelector::new(router_storage.clone(), pool_handle);
        let client_selector = ClientSelector::new(exploratory_selector.clone(), client_pool_handle);

        let mut exploratory_pool = TunnelPool::<MockRuntime, _>::new(
            pool_config,
            exploratory_selector.clone(),
            context,
            routing_table.clone(),
            noise.clone(),
            handle.clone(),
        );

        assert!(
            tokio::time::timeout(Duration::from_secs(2), &mut exploratory_pool)
                .await
                .is_err()
        );
        assert_eq!(exploratory_pool.pending_inbound.len(), 1);

        // 1st outbound hop (ibgw)
        let (router, message) = manager_rx.try_recv().unwrap();
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 2nd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 3rd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // route tunnel build response to the tunnel build response listener
        let message = Message::parse_short(&message).unwrap();
        routing_table.route_message(message);

        assert!(
            tokio::time::timeout(Duration::from_secs(2), &mut exploratory_pool)
                .await
                .is_err()
        );
        assert_eq!(exploratory_pool.inbound.len(), 1);
        assert_eq!(exploratory_pool.pending_inbound.len(), 0);
        assert_eq!(MockRuntime::get_gauge_value(NUM_INBOUND_TUNNELS), Some(1));

        {
            let pool_config = TunnelPoolConfig {
                num_inbound: 0usize,
                num_inbound_hops: 0usize,
                num_outbound: 1usize,
                num_outbound_hops: 3usize,
                destination: (),
            };
            let mut client_pool = TunnelPool::<MockRuntime, _>::new(
                pool_config,
                exploratory_selector,
                client_context,
                routing_table.clone(),
                noise,
                handle.clone(),
            );

            let future = async {
                tokio::select! {
                    _ = &mut client_pool => {}
                    _ = &mut exploratory_pool => {}
                }
            };

            assert!(tokio::time::timeout(Duration::from_secs(1), future).await.is_err());

            let (router_id, message) = manager_rx.try_recv().unwrap();

            // outbound build 1st hop (participant)
            let (router_id, message) = {
                let message = Message::parse_short(&message).unwrap();
                let mut router = routers.get_mut(&router_id).unwrap();

                router.routing_table().route_message(message).unwrap();
                assert!(tokio::time::timeout(Duration::from_secs(1), &mut router).await.is_err());
                router.message_rx().try_recv().unwrap()
            };

            // outbound build 2nd hop (participant)
            let (router_id, message) = {
                let message = Message::parse_short(&message).unwrap();
                let mut router = routers.get_mut(&router_id).unwrap();

                router.routing_table().route_message(message).unwrap();
                assert!(tokio::time::timeout(Duration::from_secs(1), &mut router).await.is_err());
                router.message_rx().try_recv().unwrap()
            };

            // outbound build 3rd hop (obep)
            let (router_id, message) = {
                let message = Message::parse_short(&message).unwrap();
                let mut router = routers.get_mut(&router_id).unwrap();

                router.routing_table().route_message(message).unwrap();
                assert!(tokio::time::timeout(Duration::from_secs(1), &mut router).await.is_err());
                router.message_rx().try_recv().unwrap()
            };

            // build reply 1st hop (ibgw)
            let (router_id, message) = {
                let message = Message::parse_short(&message).unwrap();
                let mut router = routers.get_mut(&router_id).unwrap();

                router.routing_table().route_message(message).unwrap();
                assert!(tokio::time::timeout(Duration::from_secs(1), &mut router).await.is_err());
                router.message_rx().try_recv().unwrap()
            };

            // build reply 2nd hop (participant)
            let (router_id, message) = {
                let message = Message::parse_short(&message).unwrap();
                let mut router = routers.get_mut(&router_id).unwrap();

                router.routing_table().route_message(message).unwrap();
                assert!(tokio::time::timeout(Duration::from_secs(1), &mut router).await.is_err());
                router.message_rx().try_recv().unwrap()
            };

            // build reply 3rd hop (participant)
            let (router_id, message) = {
                let message = Message::parse_short(&message).unwrap();
                let mut router = routers.get_mut(&router_id).unwrap();

                router.routing_table().route_message(message).unwrap();
                assert!(tokio::time::timeout(Duration::from_secs(1), &mut router).await.is_err());
                router.message_rx().try_recv().unwrap()
            };
            assert_eq!(router_id, RouterId::from(our_hash));

            let message = Message::parse_short(&message).unwrap();
            routing_table.route_message(message);

            let future = async {
                tokio::select! {
                    _ = &mut client_pool => {}
                    _ = &mut exploratory_pool => {}
                }
            };

            assert!(tokio::time::timeout(Duration::from_secs(1), future).await.is_err());
        }

        assert_eq!(MockRuntime::get_gauge_value(NUM_OUTBOUND_TUNNELS), Some(1));
        assert_eq!(MockRuntime::get_gauge_value(NUM_INBOUND_TUNNELS), Some(1));
    }

    #[tokio::test]
    async fn exploratory_outbound_build_reply_received_late() {
        // create 10 routers and add them to local `RouterStorage`
        let mut routers = (0..10)
            .map(|_| {
                let transit = TestTransitTunnelManager::new();
                let router_id = transit.router();

                (transit.router(), transit)
            })
            .collect::<HashMap<_, _>>();
        let router_storage = RouterStorage::from_random(
            routers.iter().map(|(_, transit)| transit.router_info()).collect(),
        );

        let pool_config = TunnelPoolConfig {
            num_inbound: 0usize,
            num_inbound_hops: 0usize,
            num_outbound: 1usize,
            num_outbound_hops: 3usize,
            destination: (),
        };
        let our_hash = {
            let mut our_hash = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut our_hash);

            Bytes::from(our_hash)
        };
        let noise = {
            let mut key_bytes = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut key_bytes);

            NoiseContext::new(StaticPrivateKey::from(key_bytes), our_hash.clone())
        };
        let handle = MockRuntime::register_metrics(Vec::new());
        let (manager_tx, manager_rx) = mpsc::channel(64);
        let (transit_tx, transit_rx) = mpsc::channel(64);
        let routing_table = RoutingTable::new(RouterId::from(our_hash), manager_tx, transit_tx);
        let (context, pool_handle) = TunnelPoolContext::new();

        let mut tunnel_pool = TunnelPool::<MockRuntime, _>::new(
            pool_config,
            ExploratorySelector::new(router_storage.clone(), pool_handle),
            context,
            routing_table.clone(),
            noise,
            handle.clone(),
        );

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.pending_outbound.len(), 1);

        // 1st outbound hop (participant)
        let (router, message) = manager_rx.try_recv().unwrap();
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 2nd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 3rd outbound hop (obep)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // don't route the response which causes the build request to expire
        assert!(tokio::time::timeout(Duration::from_secs(8), &mut tunnel_pool).await.is_err());
        assert_eq!(MockRuntime::get_counter_value(NUM_BUILD_FAILURES), Some(1));

        // route message to listener after timeout
        let message = Message::parse_short(&message).unwrap();
        match routing_table.route_message(message).unwrap_err() {
            RoutingError::RouteNotFound(_, _) => {}
            error => panic!("invalid error: {error:?}"),
        }

        assert!(tokio::time::timeout(TUNNEL_BUILD_EXPIRATION, &mut tunnel_pool).await.is_err());
        assert_eq!(MockRuntime::get_counter_value(NUM_BUILD_FAILURES), Some(1));
    }

    #[tokio::test]
    async fn exploratory_inbound_build_reply_received_late() {
        use tracing_subscriber::prelude::*;
        tracing_subscriber::registry().with(tracing_subscriber::fmt::layer()).try_init();

        // create 10 routers and add them to local `RouterStorage`
        let mut routers = (0..10)
            .map(|_| {
                let transit = TestTransitTunnelManager::new();
                let router_id = transit.router();

                (transit.router(), transit)
            })
            .collect::<HashMap<_, _>>();
        let router_storage = RouterStorage::from_random(
            routers.iter().map(|(_, transit)| transit.router_info()).collect(),
        );

        let pool_config = TunnelPoolConfig {
            num_inbound: 1usize,
            num_inbound_hops: 3usize,
            num_outbound: 0usize,
            num_outbound_hops: 0usize,
            destination: (),
        };
        let our_hash = {
            let mut our_hash = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut our_hash);

            Bytes::from(our_hash)
        };
        let noise = {
            let mut key_bytes = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut key_bytes);

            NoiseContext::new(StaticPrivateKey::from(key_bytes), our_hash.clone())
        };
        let handle = MockRuntime::register_metrics(Vec::new());
        let (manager_tx, manager_rx) = mpsc::channel(64);
        let (transit_tx, transit_rx) = mpsc::channel(64);
        let routing_table = RoutingTable::new(RouterId::from(our_hash), manager_tx, transit_tx);
        let (context, pool_handle) = TunnelPoolContext::new();

        let mut tunnel_pool = TunnelPool::<MockRuntime, _>::new(
            pool_config,
            ExploratorySelector::new(router_storage.clone(), pool_handle),
            context,
            routing_table.clone(),
            noise,
            handle.clone(),
        );

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.pending_inbound.len(), 1);

        // 1st outbound hop (ibgw)
        let (router, message) = manager_rx.try_recv().unwrap();
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 2nd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 3rd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // don't route the response which causes the build request to expire
        assert!(tokio::time::timeout(Duration::from_secs(8), &mut tunnel_pool).await.is_err());
        assert_eq!(MockRuntime::get_counter_value(NUM_BUILD_FAILURES), Some(1));

        // route message to listener after timeout
        let message = Message::parse_short(&message).unwrap();
        let _ = routing_table.route_message(message);

        // verify it's routed to transit manager which'll reject it
        assert!(transit_rx.try_recv().is_ok());
    }
}
