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
    error::TunnelError,
    i2np::{
        EncryptedTunnelData, MessageType, RawI2NpMessageBuilder, RawI2npMessage,
        TunnelGatewayMessage, I2NP_STANDARD,
    },
    primitives::{MessageId, RouterId, RouterInfo, TunnelId},
    router_storage::RouterStorage,
    runtime::Runtime,
    tunnel::{
        hop::{
            inbound::InboundTunnel, outbound::OutboundTunnel, pending::PendingTunnel, Tunnel,
            TunnelBuildParameters,
        },
        new_noise::NoiseContext,
        pool::selector::{ClientSelector, ExploratorySelector, HopSelector, TunnelSelector},
    },
    Error,
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

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::pool";

/// Tunnel maintenance interval.
const TUNNEL_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(10);

/// Tunnel build direction.
#[derive(Debug)]
pub enum TunnelBuildDirection {
    /// Outbound tunnel.
    Outbound {
        /// Tunnel ID of the inbound gateway.
        tunnel_id: TunnelId,
    },

    /// Inbound tunnel.
    Inbound {
        /// Message ID of the build request
        message_id: MessageId,
    },
}

/// Events emitted by the tunnel pools.
pub enum TunnelPoolEvent {
    /// Build tunnel.
    BuildTunnel {
        /// Router ID.
        router: RouterId,

        /// Tunnel build direction.
        direction: TunnelBuildDirection,

        /// Serialized I2NP message.
        message: Vec<u8>,
    },

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
            Self::BuildTunnel {
                router,
                direction,
                message,
            } => f
                .debug_struct("TunnelPoolEvent::BuildTunnel")
                .field("router", &router)
                .field("direction", &direction)
                .finish_non_exhaustive(),
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

/// Tunnel pool.
pub struct TunnelPool<R> {
    /// Tunnel pool configuration.
    config: TunnelPoolConfig,

    /// Inbound tunnels.
    inbound: HashMap<TunnelId, InboundTunnel>,

    /// Noise context.
    noise: NoiseContext,

    /// Outbound tunnels.
    outbound: HashMap<TunnelId, OutboundTunnel>,

    /// Pending inbound tunnels.
    pending_inbound: HashMap<MessageId, PendingTunnel<InboundTunnel>>,

    /// Pending outbound tunnels.
    pending_outbound: HashMap<TunnelId, PendingTunnel<OutboundTunnel>>,

    /// Marker for `Runtime`.
    _marker: PhantomData<R>,
}

impl<R: Runtime> TunnelPool<R> {
    /// Create empty [`TunnelPool`] from [`TunnelPoolConfig`].
    pub fn new(noise: NoiseContext, config: TunnelPoolConfig) -> Self {
        Self {
            config,
            inbound: HashMap::new(),
            noise,
            outbound: HashMap::new(),
            pending_inbound: HashMap::new(),
            pending_outbound: HashMap::new(),
            _marker: Default::default(),
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

            if !self.pending_inbound.contains_key(&message_id) {
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

                    match PendingTunnel::<OutboundTunnel>::create_tunnel::<R>(
                        TunnelBuildParameters {
                            hops,
                            tunnel_id,
                            message_id,
                            noise: self.noise.clone(),
                            our_hash: self.noise.local_router_hash().clone(),
                        },
                    ) {
                        Ok((tunnel, router, message)) => {
                            self.pending_outbound.insert(tunnel_id, tunnel);

                            events.push(TunnelPoolEvent::BuildTunnel {
                                router,
                                message,
                                direction: TunnelBuildDirection::Outbound { tunnel_id },
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

        // build one or more inbound tunnels
        //
        // select an outbound tunnel for reply delivery from one of the pool's outbound tunnels
        // and if none exist, create a fake 0-hop outbound tunnel
        for _ in 0..num_inbound_to_build {
            match selector.select_outbound_tunnel(self.outbound.iter()) {
                Some((tunnel_id, tunnel)) => todo!(),
                None => {
                    let message_id = self.next_message_id();
                    let tunnel_id = self.next_tunnel_id::<true>();
                    let Some(hops) = selector.select_hops(self.config.num_inbound_hops) else {
                        tracing::warn!(
                            target: LOG_TARGET,
                            hops_required = ?self.config.num_inbound_hops,
                            "not enough routers for inbound tunnel build",
                        );
                        continue;
                    };

                    match PendingTunnel::<InboundTunnel>::create_tunnel::<R>(
                        TunnelBuildParameters {
                            hops,
                            tunnel_id,
                            message_id,
                            noise: self.noise.clone(),
                            our_hash: self.noise.local_router_hash().clone(),
                        },
                    ) {
                        Ok((tunnel, router, message)) => {
                            self.pending_inbound.insert(message_id, tunnel);

                            events.push(TunnelPoolEvent::BuildTunnel {
                                router,
                                message,
                                direction: TunnelBuildDirection::Inbound { message_id },
                            });
                        }
                        Err(error) => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                ?tunnel_id,
                                ?message_id,
                                ?error,
                                "failed to create inbound tunnel",
                            );
                            continue;
                        }
                    }
                }
            }
        }

        if self.outbound.len() == 1 && self.inbound.len() == 1 {
            let message_id = R::rng().next_u32();
            let msg = RawI2NpMessageBuilder::standard()
                .with_message_type(MessageType::DeliveryStatus)
                .with_message_id(message_id)
                .with_expiration((R::time_since_epoch() + Duration::from_secs(10 * 60)).as_secs()) // TODO: fix time
                .with_payload(vec![1, 2, 3, 4]) // TODO: create proper test message
                .serialize();

            tracing::error!(
                target: LOG_TARGET,
                ?message_id,
                "test tunnels",
            );

            let (_, inbound_tunnel) = self.inbound.iter().next().unwrap();
            let (_, outbound_tunnel) = self.outbound.iter().next().unwrap();

            let (router, gateway) = inbound_tunnel.gateway();
            let (router, message) = outbound_tunnel.send_to_tunnel::<R>(router, gateway, msg);

            events.push(TunnelPoolEvent::SendI2NpMessage {
                router,
                message_id: MessageId::from(message_id),
                message,
            });
        }

        events.into_iter()
    }

    /// Handle outbound tunnel build reply.
    ///
    /// If the message is valid and all hops agreed to participate in the tunnel,
    /// a new outbound tunnel is created for the pool.
    pub fn handle_outbound_tunnel_build_reply(
        &mut self,
        message: TunnelGatewayMessage,
    ) -> crate::Result<()> {
        let tunnel = self.pending_outbound.remove(message.tunnel_id()).ok_or(Error::Tunnel(
            TunnelError::TunnelDoesntExist(*message.tunnel_id()),
        ))?;

        let parsed_message = RawI2npMessage::parse::<I2NP_STANDARD>(message.payload())
            .ok_or(Error::Tunnel(TunnelError::InvalidMessage))?;

        match tunnel.try_build_tunnel(parsed_message) {
            Ok(tunnel) => {
                tracing::info!(
                    target: LOG_TARGET,
                    tunnel_id = %tunnel.tunnel_id(),
                    "outbound tunnel created",
                );
                self.outbound.insert(*tunnel.tunnel_id(), tunnel);

                Ok(())
            }
            Err(error) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    tunnel_id = %message.tunnel_id(),
                    ?error,
                    "failed to create outbound tunnel",
                );

                Err(error)
            }
        }
    }

    /// Handle inbound tunnel build reply.
    ///
    /// If the message is valid and all hops agreed to participate in the tunnel,
    /// a new inbound tunnel is created for the pool.
    pub fn handle_inbound_tunnel_build_reply(
        &mut self,
        message: RawI2npMessage,
    ) -> crate::Result<TunnelId> {
        let message_id = MessageId::from(message.message_id);

        let tunnel = self
            .pending_inbound
            .remove(&message_id)
            .ok_or(Error::Tunnel(TunnelError::MessageDoesntExist(message_id)))?;

        match tunnel.try_build_tunnel(message) {
            Ok(tunnel) => {
                tracing::info!(
                    target: LOG_TARGET,
                    tunnel_id = %tunnel.tunnel_id(),
                    "inbound tunnel created",
                );
                let tunnel_id = *tunnel.tunnel_id();

                self.inbound.insert(tunnel_id, tunnel);

                Ok(tunnel_id)
            }
            Err(error) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    %message_id,
                    ?error,
                    "failed to create inbound tunnel",
                );

                Err(error)
            }
        }
    }

    /// Handle tunnel data message.
    pub fn handle_tunnel_data(&mut self, message: &EncryptedTunnelData) -> crate::Result<()> {
        tracing::warn!(
            target: LOG_TARGET,
            "handle tunnel data",
        );

        let tunnel = self.inbound.get_mut(&message.tunnel_id()).ok_or(Error::Tunnel(
            TunnelError::TunnelDoesntExist(message.tunnel_id()),
        ))?;

        match tunnel.handle_tunnel_data(message) {
            Ok(message) => {
                let message = RawI2npMessage::parse::<false>(&message).ok_or(Error::InvalidData)?;

                tracing::info!(
                    "tunnel tested successfully, payload = {:?}",
                    message.payload
                );

                Ok(())
            }
            Ok(message) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?message,
                    "message doesn't contain the correct payload",
                );
                Err(Error::InvalidData)
            }
            Err(error) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    "failed to handle tunnel data message",
                );
                Err(Error::InvalidData)
            }
        }
    }
}

/// Tunnel pool manager.
pub struct TunnelPoolManager<R: Runtime> {
    /// Exploratory tunnel pool.
    exploratory_pool: TunnelPool<R>,

    /// `TunnelId` -> `TunnelPool` mappings.
    inbound: HashMap<TunnelId, Option<usize>>,

    /// Maintenance timer.
    maintenance_timer: BoxFuture<'static, ()>,

    /// Metrics handle.
    metrics_handle: R::MetricsHandle,

    /// Noise context.
    noise: NoiseContext,

    /// Pending events.
    pending_events: VecDeque<TunnelPoolEvent>,

    /// Pending inbound tunnels.
    ///
    /// Value of the entry is an index into `pools`.
    ///
    /// `None` denotes the exploratory tunnel pool.
    pending_inbound: HashMap<MessageId, Option<usize>>,

    /// Pending outbound tunnels.
    ///
    /// Value of the entry is an index into `pools`.
    ///
    /// `None` denotes the exploratory tunnel pool.
    pending_outbound: HashMap<TunnelId, Option<usize>>,

    /// Client tunnels pools.
    pools: Vec<TunnelPool<R>>,

    /// Router storage.
    router_storage: RouterStorage,
}

impl<R: Runtime> TunnelPoolManager<R> {
    /// Create new [`TunnelPoolManager`].
    pub fn new(
        noise: NoiseContext,
        metrics_handle: R::MetricsHandle,
        router_storage: RouterStorage,
        exploratory_pool_config: TunnelPoolConfig,
    ) -> Self {
        Self {
            exploratory_pool: TunnelPool::new(noise.clone(), exploratory_pool_config),
            inbound: HashMap::new(),
            maintenance_timer: Box::pin(ready(())),
            metrics_handle,
            noise,
            pending_events: VecDeque::new(),
            pending_inbound: HashMap::new(),
            pending_outbound: HashMap::new(),
            pools: Vec::new(),
            router_storage,
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
        tracing::trace!(
            target: LOG_TARGET,
            num_pools = ?(self.pools.len() + 1),
            "maintain tunnel pools",
        );

        // maintain the exploratory tunnel pool
        self.pending_events.extend(
            self.exploratory_pool
                .maintain_tunnels(ExploratorySelector::new(&self.router_storage))
                .map(|event| {
                    match event {
                        TunnelPoolEvent::BuildTunnel { ref direction, .. } => match direction {
                            TunnelBuildDirection::Outbound { tunnel_id } => {
                                self.pending_outbound.insert(*tunnel_id, None);
                            }
                            TunnelBuildDirection::Inbound { message_id } => {
                                self.pending_inbound.insert(*message_id, None);
                            }
                        },
                        _ => {}
                    }

                    event
                }),
        );

        // maintain client tunnel pools
        self.pools.iter_mut().enumerate().for_each(|(idx, tunnel)| {
            self.pending_events.extend(
                tunnel
                    .maintain_tunnels(ClientSelector::new(
                        &self.exploratory_pool,
                        &self.router_storage,
                    ))
                    .map(|event| {
                        match event {
                            TunnelPoolEvent::BuildTunnel { ref direction, .. } => match direction {
                                TunnelBuildDirection::Outbound { tunnel_id } => {
                                    self.pending_outbound.insert(*tunnel_id, Some(idx));
                                }
                                TunnelBuildDirection::Inbound { message_id } => {
                                    self.pending_inbound.insert(*message_id, Some(idx));
                                }
                            },
                            _ => {}
                        }

                        event
                    }),
            )
        })
    }

    /// Handle outbound tunnel build reply.
    pub fn handle_outbound_tunnel_build_reply(
        &mut self,
        message: TunnelGatewayMessage,
    ) -> crate::Result<()> {
        // TODO: this may have to more complicated if an actual inbound tunnel is used
        self.pending_outbound
            .remove(message.tunnel_id())
            .map(|pool| pool.map_or(&mut self.exploratory_pool, |idx| &mut self.pools[idx]))
            .ok_or(Error::Tunnel(TunnelError::TunnelDoesntExist(
                *message.tunnel_id(),
            )))?
            .handle_outbound_tunnel_build_reply(message)
    }

    /// Handle inbound tunnel build reply.
    pub fn handle_inbound_tunnel_build_response(
        &mut self,
        message: RawI2npMessage,
    ) -> crate::Result<()> {
        let (idx, mut pool) = self
            .pending_inbound
            .remove(&MessageId::from(message.message_id))
            .map(|pool| {
                pool.map_or((None, &mut self.exploratory_pool), |idx| {
                    (Some(idx), &mut self.pools[idx])
                })
            })
            .ok_or(Error::Tunnel(TunnelError::MessageDoesntExist(
                MessageId::from(message.message_id),
            )))?;

        pool.handle_inbound_tunnel_build_reply(message).map(|tunnel| {
            self.inbound.insert(tunnel, idx);
        })
    }

    /// Handle tunnel data.
    pub fn handle_tunnel_data(&mut self, message: &EncryptedTunnelData) -> crate::Result<()> {
        self.inbound
            .get_mut(&message.tunnel_id())
            .map(|pool| pool.map_or(&mut self.exploratory_pool, |idx| &mut self.pools[idx]))
            .ok_or(Error::Tunnel(TunnelError::TunnelDoesntExist(
                message.tunnel_id(),
            )))?
            .handle_tunnel_data(message)
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

    #[tokio::test]
    async fn tunnel_test() {
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

        let mut pool_manager =
            TunnelPoolManager::<MockRuntime>::new(noise, handle, router_storage, pool_config);

        let _ = pool_manager.next().await;
    }
}
