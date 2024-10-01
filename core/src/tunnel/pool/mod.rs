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
    error::{ChannelError, Error},
    i2np::{Message, MessageBuilder, MessageType},
    primitives::{Lease2, MessageId, RouterId, TunnelId},
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
            selector::{HopSelector, TunnelSelector},
            timer::{TunnelKind, TunnelTimer, TunnelTimerEvent},
            zero_hop::ZeroHopInboundTunnel,
        },
        routing_table::RoutingTable,
        TUNNEL_EXPIRATION,
    },
};

use bytes::Bytes;
use futures::{
    future::{select, BoxFuture, Either},
    FutureExt, StreamExt,
};
use hashbrown::{HashMap, HashSet};
use listener::ReceiveKind;
use rand_core::RngCore;
use thingbuf::mpsc;

use alloc::{boxed::Box, vec::Vec};
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

/// Tunnel test expiration.
///
/// How long is the tunnel considered under testing until the test is considered a failure.
const TUNNEL_TEST_EXPIRATION: Duration = Duration::from_secs(8);

/// Tunnel channel size.
const TUNNEL_CHANNEL_SIZE: usize = 64usize;

/// Tunnel rebuild timeout.
///
/// Tunnel of a pool needs to be rebuilt before it expires as otherwise the pool may be not have any
/// tunnels of that type. Start building a new tunnel to replace to old one 2 minutes before the old
/// tunnel expires.
const TUNNEL_REBUILD_TIMEOUT: Duration = Duration::from_secs(8 * 60);

/// Tunnel pool kind.
///
/// There are two different kinds of tunnel pools:
///  * exploratory tunnel pool
///  * client tunnel pools
///
/// The distinction is made as client tunnel pools are crated for destinations and inbound tunnels
/// of those pools must be able to route garlic cloves to the installed destination.
#[derive(Clone)]
pub enum TunnelPoolKind {
    /// Exploratory tunnel pool.
    Exploratory,

    /// Client tunnel pool.
    Client(mpsc::Sender<Message>),
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
    ///
    /// After the inbound tunnel expires, it returns a `(TunnelId, TunnelId)` tuple where the first
    /// `TunnelId` is the ID of the inbound tunnel and second ID if the id of the gateway.
    inbound: R::JoinSet<(TunnelId, TunnelId)>,

    /// Inbound tunnels.
    inbound_tunnels: HashMap<TunnelId, RouterId>,

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

    /// Pending tunnel tests.
    pending_tests: R::JoinSet<(TunnelId, TunnelId, crate::Result<()>)>,

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
            inbound_tunnels: HashMap::new(),
            maintenance_timer: Box::pin(R::delay(Duration::from_secs(0))),
            metrics,
            noise,
            outbound: HashMap::new(),
            pending_inbound: TunnelBuildListener::new(routing_table.clone()),
            pending_outbound: TunnelBuildListener::new(routing_table.clone()),
            pending_tests: R::join_set(),
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
                    //
                    // `ZeroHopInboundTunnel::new()` also returns a `oneshot::Receiver<Message>`
                    // which is used to receive the build response, if it's received in time
                    let (gateway, zero_hop_tunnel, message_rx) =
                        ZeroHopInboundTunnel::new::<R>(self.routing_table.clone());

                    // allocate random message id for the build request
                    //
                    // since the reply is not routed through routing table,
                    // message id collisions are not a concern and this can just be a random number
                    let message_id = MessageId::from(R::rng().next_u32());

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
                                ReceiveKind::ZeroHop,
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
                // could be in a different pool), it'll be received by the selected tunnel's
                // `TunnelPool` which routes the message to the listener
                Some((gateway, router_id, handle)) => {
                    // TODO: rewrite this comment
                    //
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
                            // listening for outbound tunnel build responses through an existing
                            // inbound tunnel is more complex than listening through a fake 0-hop
                            // inbound tunnel since the inbound tunnel is not expecting to receive
                            // just one message and because the selected OBEP has freedom to choose
                            // whether to garlic encrypt the tunnel build response or not
                            //
                            // if the response is not garlic encrypted, it'll be identified by the
                            // generated message id and if it is garlic encrypted, it'll be
                            // identified by the garlic tag which means that the inbound tunnel must
                            // have two listener types, one for the unecrypted response and one for
                            // the encrypted response
                            handle.add_garlic_listener(message_id, tunnel.garlic_tag());

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
                                "no outbound tunnel available, send build request to router",
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

                            if let Err(error) = handle.send_to_router(
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

        // test active tunnels
        //
        // for pairs of active inbound and outbound tunnels, send a test message through and
        // outbound tunnel and request the obep of that tunnel to route the message to the selected
        // inbound tunnel
        //
        // for each message, start a timer which expires after 8 seconds and if the response is
        // received into the selected inbound tunnel within the time limit, the tunnel is considered
        // operational
        self.outbound
            .keys()
            .filter(|tunnel_id| !self.expiring_outbound.contains(*tunnel_id))
            .copied()
            .zip(
                self.inbound_tunnels.iter().filter_map(|(tunnel_id, router)| {
                    (!self.expiring_inbound.contains(tunnel_id)).then_some((*tunnel_id, router))
                }),
            )
            .for_each(|(outbound, (inbound, router))| {
                // allocate new message id and an RX channel for receiving the tunnel test message
                let (message_id, message_rx) = self.context.add_listener(&mut R::rng());

                tracing::trace!(
                    target: LOG_TARGET,
                    %outbound,
                    %inbound,
                    %router,
                    %message_id,
                    "test tunnel",
                );

                // create dummy test message and send it through the outbound tunnel
                // to the selected inbound tunnel's gateway
                let message = MessageBuilder::standard()
                    .with_expiration((R::time_since_epoch() + Duration::from_secs(8)).as_secs())
                    .with_message_type(MessageType::Data)
                    .with_message_id(message_id)
                    .with_payload(b"tunnel test")
                    .build();

                // outbound tunnel must exist since it was jus iterated over
                let (router, mut messages) = self
                    .outbound
                    .get(&outbound)
                    .expect("outbound tunnel to exist")
                    .send_to_tunnel(router.clone(), inbound, message);

                // message must exist since it's a valid i2np message
                match self
                    .routing_table
                    .send_message(router, messages.next().expect("message to exist"))
                {
                    Ok(_) => self.pending_tests.push(async move {
                        match select(message_rx, Box::pin(R::delay(TUNNEL_TEST_EXPIRATION))).await {
                            Either::Right((_, _)) => (outbound, inbound, Err(Error::Timeout)),
                            Either::Left((Err(_), _)) =>
                                (outbound, inbound, Err(Error::Channel(ChannelError::Closed))),
                            Either::Left((Ok(_), _)) => (outbound, inbound, Ok(())),
                        }
                    }),
                    Err(error) => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            %outbound,
                            %inbound,
                            ?error,
                            "failed to send tunnel test message",
                        );

                        self.context.remove_listener(&message_id);
                    }
                }

                debug_assert!(messages.next().is_none());
            });
    }
}

impl<R: Runtime, S: TunnelSelector + HopSelector> Future for TunnelPool<R, S> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // poll pending outbound tunnels
        while let Poll::Ready(Some((tunnel_id, event))) = self.pending_outbound.poll_next_unpin(cx)
        {
            match event {
                Err(error) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to build outbound tunnel",
                    );

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

        // poll pending inbound tunnels
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

                    // fetch the newly created inbound tunnel's gateway information
                    //
                    // in order for the inbound tunnel to be usable, it's gateway information must
                    // be stored in selector/routing table, as opposed to the endpoint information,
                    // because the gateway is used to receive messages
                    let (router_id, tunnel_id) = tunnel.gateway();
                    self.selector.add_inbound_tunnel(tunnel_id, router_id.clone());
                    self.inbound_tunnels.insert(tunnel_id, router_id.clone());

                    // store lease of the new inbound tunnel into `TunnelPoolHandle` so client code
                    // can query available leases when it's creating new sessions
                    self.context.add_lease(
                        *tunnel.tunnel_id(),
                        Lease2 {
                            router_id,
                            tunnel_id,
                            expires: (R::time_since_epoch() + TUNNEL_EXPIRATION).as_secs() as u32,
                        },
                    );

                    self.inbound.push(tunnel);
                    self.metrics.gauge(NUM_INBOUND_TUNNELS).increment(1);
                    self.metrics.gauge(NUM_PENDING_INBOUND_TUNNELS).decrement(1);
                }
            }
        }

        // poll event loops of inbound tunnels
        while let Poll::Ready(event) = self.inbound.poll_next_unpin(cx) {
            match event {
                None => return Poll::Ready(()),
                Some((tunnel_id, gateway_tunnel_id)) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %tunnel_id,
                        %gateway_tunnel_id,
                        "inbound tunnel exited",
                    );

                    self.expiring_inbound.remove(&tunnel_id);
                    self.routing_table.remove_tunnel(&tunnel_id);
                    self.context.remove_lease(&tunnel_id);
                    self.selector.remove_inbound_tunnel(&gateway_tunnel_id);
                }
            }
        }

        // poll tunnel message context
        //
        // tunnel message context receives two types of events:
        //  1) inbound tunnel events
        //  2) outbound tunnel events
        //
        // inbound tunnel events are received from the network and a route for them couldn't be
        // found from the `TunnelHandle`'s routing table which causes them to be routed to
        // `TunnelPool` for further processing
        //
        // outbound tunnel events are received from destinations/other tunnel pools that wish to
        // send message over one of this tunnel pool's outbound tunnels, e.g., when sending a tunnel
        // build request to remote
        while let Poll::Ready(event) = self.context.poll_next_unpin(cx) {
            match event {
                None => return Poll::Ready(()),
                Some(event) => match event {
                    TunnelMessage::Dummy => unreachable!(),
                    TunnelMessage::RouterDelivery {
                        gateway,
                        router_id,
                        message,
                    } => match self.outbound.get(&gateway) {
                        None => tracing::warn!(
                            target: LOG_TARGET,
                            %gateway,
                            "cannot send message, outbound tunnel doesn't exist",
                        ),
                        Some(tunnel) => {
                            let (router_id, messages) = tunnel.send_to_router(router_id, message);

                            messages.into_iter().for_each(|message| {
                                if let Err(error) =
                                    self.routing_table.send_message(router_id.clone(), message)
                                {
                                    tracing::warn!(
                                        target: LOG_TARGET,
                                        %gateway,
                                        ?error,
                                        "failed to send tunnel message to router",
                                    );
                                }
                            });
                        }
                    },
                    TunnelMessage::TunnelDelivery {
                        gateway,
                        tunnel_id,
                        message,
                    } => {
                        // TODO: needs to be fairer
                        let Some((outbound_gateway, tunnel)) = self.outbound.iter().next() else {
                            tracing::warn!(
                                target: LOG_TARGET,
                                "failed to send tunnel message, no outbound tunnel available",
                            );
                            continue;
                        };

                        tracing::trace!(
                            target: LOG_TARGET,
                            %outbound_gateway,
                            "send tunnel message to remote destination",
                        );

                        let (router_id, messages) =
                            tunnel.send_to_tunnel(gateway.clone(), tunnel_id, message);

                        messages.into_iter().for_each(|message| {
                            if let Err(error) =
                                self.routing_table.send_message(router_id.clone(), message)
                            {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    %gateway,
                                    ?error,
                                    "failed to send tunnel message to router",
                                );
                            }
                        });
                    }
                    TunnelMessage::Inbound { message } => tracing::warn!(
                        target: LOG_TARGET,
                        message_type = ?message.message_type,
                        "unhandled message"
                    ),
                },
            }
        }

        // poll tunnel tests
        while let Poll::Ready(event) = self.pending_tests.poll_next_unpin(cx) {
            match event {
                None => return Poll::Ready(()),
                Some((outbound, inbound, result)) => match result {
                    Err(error) => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            %outbound,
                            %inbound,
                            ?error,
                            "tunnel test failed",
                        );

                        self.metrics.counter(NUM_TEST_FAILURES).increment(1);
                    }
                    Ok(()) => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            %outbound,
                            %inbound,
                            "tunnel test succeeded",
                        );

                        self.metrics.counter(NUM_TEST_SUCCESSES).increment(1);
                    }
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
                    self.selector.remove_outbound_tunnel(&tunnel_id);
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
        error::RoutingError,
        i2np::Message,
        primitives::{RouterId, RouterInfo},
        router_storage::RouterStorage,
        runtime::mock::MockRuntime,
        tunnel::{pool::selector::ClientSelector, tests::TestTransitTunnelManager},
    };
    use futures::StreamExt;
    use thingbuf::mpsc;

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
        let (context, pool_handle) = TunnelPoolContext::new(TunnelPoolKind::Exploratory);

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
        let (context, pool_handle) = TunnelPoolContext::new(TunnelPoolKind::Exploratory);

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
        let (context, pool_handle) = TunnelPoolContext::new(TunnelPoolKind::Exploratory);

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
        let (context, pool_handle) = TunnelPoolContext::new(TunnelPoolKind::Exploratory);

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
        let (context, pool_handle) = TunnelPoolContext::new(TunnelPoolKind::Exploratory);
        let (client_context, client_pool_handle) =
            TunnelPoolContext::new(TunnelPoolKind::Exploratory);
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
        let (context, pool_handle) = TunnelPoolContext::new(TunnelPoolKind::Exploratory);
        let (client_context, client_pool_handle) =
            TunnelPoolContext::new(TunnelPoolKind::Exploratory);
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
        let (context, pool_handle) = TunnelPoolContext::new(TunnelPoolKind::Exploratory);

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

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(MockRuntime::get_counter_value(NUM_BUILD_FAILURES), Some(1));
    }

    #[tokio::test]
    async fn exploratory_inbound_build_reply_received_late() {
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
        let (context, pool_handle) = TunnelPoolContext::new(TunnelPoolKind::Exploratory);

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

    #[tokio::test]
    async fn exploratory_tunnel_test() {
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
            num_inbound_hops: 2usize,
            num_outbound: 1usize,
            num_outbound_hops: 2usize,
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
        let (context, pool_handle) = TunnelPoolContext::new(TunnelPoolKind::Exploratory);

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

        // build one inbound and one outbound tunnel
        for _ in 0..2 {
            let (router, message) = manager_rx.try_recv().unwrap();

            // 1st outbound hop
            let message = Message::parse_short(&message).unwrap();
            let (router, message) =
                routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

            // 2nd outbound hop
            let message = Message::parse_short(&message).unwrap();
            let (router, message) =
                routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

            let message = Message::parse_short(&message).unwrap();
            routing_table.route_message(message);

            assert!(
                tokio::time::timeout(Duration::from_millis(250), &mut tunnel_pool)
                    .await
                    .is_err()
            );
        }

        assert_eq!(tunnel_pool.outbound.len(), 1);
        assert_eq!(tunnel_pool.inbound.len(), 1);
        assert_eq!(tunnel_pool.pending_outbound.len(), 0);
        assert_eq!(tunnel_pool.pending_inbound.len(), 0);
        assert_eq!(MockRuntime::get_gauge_value(NUM_OUTBOUND_TUNNELS), Some(1));
        assert_eq!(MockRuntime::get_gauge_value(NUM_INBOUND_TUNNELS), Some(1));

        assert!(tokio::time::timeout(Duration::from_secs(8), &mut tunnel_pool).await.is_err());
        let (router, message) = manager_rx.try_recv().unwrap();

        // 1st outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        routers
            .get_mut(&router)
            .unwrap()
            .routing_table()
            .route_message(message)
            .unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(250),
            &mut routers.get_mut(&router).unwrap()
        )
        .await
        .is_err());

        let (router, message) = routers.get_mut(&router).unwrap().message_rx().try_recv().unwrap();
        assert!(routers.get_mut(&router).unwrap().message_rx().try_recv().is_err());

        // 2nd outbound hop (obep)
        let message = Message::parse_short(&message).unwrap();
        routers
            .get_mut(&router)
            .unwrap()
            .routing_table()
            .route_message(message)
            .unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(250),
            &mut routers.get_mut(&router).unwrap()
        )
        .await
        .is_err());
        let (router, message) = routers.get_mut(&router).unwrap().message_rx().try_recv().unwrap();

        // 1st inbound hop (ibgw)
        let message = Message::parse_short(&message).unwrap();
        routers
            .get_mut(&router)
            .unwrap()
            .routing_table()
            .route_message(message)
            .unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(250),
            &mut routers.get_mut(&router).unwrap()
        )
        .await
        .is_err());
        let (router, message) = routers.get_mut(&router).unwrap().message_rx().try_recv().unwrap();

        // 2nd inbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        routers
            .get_mut(&router)
            .unwrap()
            .routing_table()
            .route_message(message)
            .unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(250),
            &mut routers.get_mut(&router).unwrap()
        )
        .await
        .is_err());
        let (router, message) = routers.get_mut(&router).unwrap().message_rx().try_recv().unwrap();

        // route response to local router and verify that tunnel test is considered succeeded
        assert_eq!(router, RouterId::from(our_hash));

        let message = Message::parse_short(&message).unwrap();
        routing_table.route_message(message);

        assert!(
            tokio::time::timeout(Duration::from_millis(250), &mut tunnel_pool)
                .await
                .is_err()
        );

        assert_eq!(MockRuntime::get_counter_value(NUM_TEST_SUCCESSES), Some(1));
    }

    #[tokio::test]
    async fn exploratory_tunnel_test_expires() {
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
            num_inbound_hops: 2usize,
            num_outbound: 1usize,
            num_outbound_hops: 2usize,
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
        let (context, pool_handle) = TunnelPoolContext::new(TunnelPoolKind::Exploratory);

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

        // build one inbound and one outbound tunnel
        for _ in 0..2 {
            let (router, message) = manager_rx.try_recv().unwrap();

            // 1st outbound hop
            let message = Message::parse_short(&message).unwrap();
            let (router, message) =
                routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

            // 2nd outbound hop
            let message = Message::parse_short(&message).unwrap();
            let (router, message) =
                routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

            let message = Message::parse_short(&message).unwrap();
            routing_table.route_message(message);

            assert!(
                tokio::time::timeout(Duration::from_millis(250), &mut tunnel_pool)
                    .await
                    .is_err()
            );
        }

        assert_eq!(tunnel_pool.outbound.len(), 1);
        assert_eq!(tunnel_pool.inbound.len(), 1);
        assert_eq!(tunnel_pool.pending_outbound.len(), 0);
        assert_eq!(tunnel_pool.pending_inbound.len(), 0);
        assert_eq!(MockRuntime::get_gauge_value(NUM_OUTBOUND_TUNNELS), Some(1));
        assert_eq!(MockRuntime::get_gauge_value(NUM_INBOUND_TUNNELS), Some(1));

        assert!(tokio::time::timeout(Duration::from_secs(8), &mut tunnel_pool).await.is_err());
        let (router, message) = manager_rx.try_recv().unwrap();

        // 1st outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        routers
            .get_mut(&router)
            .unwrap()
            .routing_table()
            .route_message(message)
            .unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(250),
            &mut routers.get_mut(&router).unwrap()
        )
        .await
        .is_err());

        let (router, message) = routers.get_mut(&router).unwrap().message_rx().try_recv().unwrap();
        assert!(routers.get_mut(&router).unwrap().message_rx().try_recv().is_err());

        // 2nd outbound hop (obep)
        let message = Message::parse_short(&message).unwrap();
        routers
            .get_mut(&router)
            .unwrap()
            .routing_table()
            .route_message(message)
            .unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(250),
            &mut routers.get_mut(&router).unwrap()
        )
        .await
        .is_err());

        // don't route the test message any further and verify the test timeouts
        assert!(tokio::time::timeout(Duration::from_secs(9), &mut tunnel_pool).await.is_err());
        assert_eq!(MockRuntime::get_counter_value(NUM_TEST_FAILURES), Some(1));
    }
}
