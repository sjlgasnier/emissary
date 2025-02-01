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
    crypto::{chachapoly::ChaChaPoly, EphemeralPublicKey},
    error::TunnelError,
    i2np::{
        garlic::{DeliveryInstructions, GarlicMessage, GarlicMessageBuilder},
        tunnel::{
            build::{short, variable},
            gateway::TunnelGateway,
        },
        HopRole, Message, MessageBuilder, MessageType, I2NP_MESSAGE_EXPIRATION,
    },
    primitives::{RouterId, TunnelId},
    runtime::{Counter, Gauge, JoinSet, MetricsHandle, Runtime},
    shutdown::ShutdownHandle,
    tunnel::{
        metrics::*,
        noise::{NoiseContext, TunnelKeys},
        routing_table::RoutingTable,
        transit::{inbound::InboundGateway, outbound::OutboundEndpoint, participant::Participant},
    },
    Error,
};

use bytes::{BufMut, BytesMut};
use futures::{FutureExt, StreamExt};
use thingbuf::mpsc::Receiver;

use alloc::vec::Vec;
use core::{
    future::Future,
    ops::{Range, RangeFrom},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

mod inbound;
mod outbound;
mod participant;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::transit";

/// Short tunnel build request record size.
const SHORT_RECORD_LEN: usize = 218;

/// Variable tunnel build request record size.
const VARIABLE_RECORD_LEN: usize = 528;

/// Public key offset in the build request record.
const PUBLIC_KEY_OFFSET: Range<usize> = 16..48;

/// Start offset for the build request record payload.
const RECORD_START_OFFSET: RangeFrom<usize> = 48..;

/// Transit tunnel channel size.
const TUNNEL_CHANNEL_SIZE: usize = 64usize;

/// Transit tunnel expiration.
///
/// Tunnels expire in 10 minutes but the expiration timer for transit tunnels are started as soon as
/// the tunnel build requets is accepted. Tunnel creator might not start the timer quite as soon
/// which could result in tunnel messages getting dropped towards the end of the tunnel's life time.
///
/// In order to prevent this from happening, increase the transit tunnel expiration by an additional
/// 20 seconds to allow remaining traffic pass through the tunnel before it is destroyed.
const TRANSIT_TUNNEL_EXPIRATION: Duration = Duration::from_secs(10 * 60 + 20);

/// Common interface for transit tunnels.
pub trait TransitTunnel<R: Runtime>: Future<Output = TunnelId> + Send {
    /// Create new [`TransitTunnel`].
    fn new(
        tunnel_id: TunnelId,
        next_tunnel_id: TunnelId,
        next_router: RouterId,
        tunnel_keys: TunnelKeys,
        routing_table: RoutingTable,
        metrics_handle: R::MetricsHandle,
        message_rx: Receiver<Message>,
    ) -> Self;
}

/// Transit tunnel manager.
pub struct TransitTunnelManager<R: Runtime> {
    /// RX channel for receiving messages from `TunnelManager`.
    message_rx: Receiver<Message>,

    /// Metrics handle.
    metrics_handle: R::MetricsHandle,

    /// Noise context.
    noise: NoiseContext,

    /// Routing table.
    routing_table: RoutingTable,

    /// Shutdown handle.
    shutdown_handle: ShutdownHandle,

    /// Active transit tunnels.
    tunnels: R::JoinSet<TunnelId>,
}

impl<R: Runtime> TransitTunnelManager<R> {
    /// Create new [`TransitTunnelManager`].
    pub fn new(
        noise: NoiseContext,
        routing_table: RoutingTable,
        message_rx: Receiver<Message>,
        metrics_handle: R::MetricsHandle,
        shutdown_handle: ShutdownHandle,
    ) -> Self {
        Self {
            message_rx,
            metrics_handle,
            noise,
            routing_table,
            shutdown_handle,
            tunnels: R::join_set(),
        }
    }

    /// Return mutable reference to local build record and its index in the build request message.
    fn find_local_record<'a, const RECORD_SIZE: usize>(
        &self,
        payload: &'a mut [u8],
    ) -> Option<(usize, &'a mut [u8])> {
        (payload.len() > RECORD_SIZE && (payload.len() - 1) % RECORD_SIZE == 0)
            .then(|| {
                payload[1..]
                    .chunks_mut(RECORD_SIZE)
                    .enumerate()
                    .find(|(_, chunk)| chunk[..16] == self.noise.local_router_hash()[..16])
            })
            .flatten()
    }

    /// Handle variable tunnel build request.
    pub fn handle_variable_tunnel_build(
        &mut self,
        message: Message,
    ) -> crate::Result<(RouterId, Vec<u8>)> {
        let Message {
            message_id,
            expiration,
            mut payload,
            ..
        } = message;

        let (_, record) = self
            .find_local_record::<VARIABLE_RECORD_LEN>(&mut payload)
            .ok_or(Error::Tunnel(TunnelError::RecordNotFound))?;

        let mut session = self.noise.create_long_inbound_session(
            EphemeralPublicKey::from_bytes(&record[PUBLIC_KEY_OFFSET]).ok_or(Error::InvalidData)?,
        );
        let decrypted_record =
            session.decrypt_build_record(record[RECORD_START_OFFSET].to_vec())?;

        let build_record =
            variable::TunnelBuildRecord::parse(&decrypted_record).ok_or_else(|| {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?message_id,
                    "malformed variable tunnel build request",
                );

                Error::InvalidData
            })?;

        let role = build_record.role();
        let tunnel_id = build_record.tunnel_id();
        let next_tunnel_id = build_record.next_tunnel_id();
        let next_message_id = build_record.next_message_id();
        let next_router = build_record.next_router();

        tracing::trace!(
            target: LOG_TARGET,
            ?role,
            %tunnel_id,
            %next_tunnel_id,
            %next_message_id,
            %next_router,
            "variable tunnel build request",
        );

        // check if the tunnel can be accepted
        //
        // all transit tunnel build requests are rejected if the tunnel is shutting
        //
        // if the router is active, check if a new receiver can be added to routing table and if so,
        // create new receiver for the transit tunnel and add it to routing table
        let maybe_receiver = match self.shutdown_handle.is_shutting_down() {
            true => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?role,
                    %tunnel_id,
                    "router shutting down, rejecting transit tunnel",
                );

                None
            }
            false => match self.routing_table.try_add_tunnel::<TUNNEL_CHANNEL_SIZE>(tunnel_id) {
                Ok(receiver) => Some(receiver),
                Err(error) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        %tunnel_id,
                        ?error,
                        "tunnel already exists in routing table, rejecting",
                    );
                    None
                }
            },
        };

        match maybe_receiver {
            None => {
                self.metrics_handle.counter(NUM_TRANSIT_TUNNELS_REJECTED).increment(1);

                record[48] = 0x00; // no options
                record[49] = 0x00;
                record[511] = 0x30; // reject

                session.encrypt_build_record(record)?;
            }
            Some(receiver) => {
                self.metrics_handle.counter(NUM_TRANSIT_TUNNELS_ACCEPTED).increment(1);
                self.metrics_handle.gauge(NUM_TRANSIT_TUNNELS).increment(1);

                record[48] = 0x00; // no options
                record[49] = 0x00;
                record[511] = 0x00; // accept

                session.encrypt_build_record(record)?;

                // start tunnel event loop
                //
                // an accepted tunnel must be maintained for 10 minutes as we won't know
                // if another participant of the tunnel rejected it
                match role {
                    HopRole::InboundGateway => self.tunnels.push(InboundGateway::<R>::new(
                        tunnel_id,
                        next_tunnel_id,
                        next_router.clone(),
                        session.finalize(
                            build_record.tunnel_layer_key().to_vec(),
                            build_record.tunnel_iv_key().to_vec(),
                        )?,
                        self.routing_table.clone(),
                        self.metrics_handle.clone(),
                        receiver,
                    )),
                    HopRole::Participant => self.tunnels.push(Participant::<R>::new(
                        tunnel_id,
                        next_tunnel_id,
                        next_router.clone(),
                        session.finalize(
                            build_record.tunnel_layer_key().to_vec(),
                            build_record.tunnel_iv_key().to_vec(),
                        )?,
                        self.routing_table.clone(),
                        self.metrics_handle.clone(),
                        receiver,
                    )),
                    HopRole::OutboundEndpoint => self.tunnels.push(OutboundEndpoint::<R>::new(
                        tunnel_id,
                        next_tunnel_id,
                        next_router.clone(),
                        session.finalize(
                            build_record.tunnel_layer_key().to_vec(),
                            build_record.tunnel_iv_key().to_vec(),
                        )?,
                        self.routing_table.clone(),
                        self.metrics_handle.clone(),
                        receiver,
                    )),
                }
            }
        }

        let message = MessageBuilder::short()
            .with_message_type(match role {
                HopRole::OutboundEndpoint => MessageType::VariableTunnelBuildReply,
                HopRole::InboundGateway | HopRole::Participant => MessageType::VariableTunnelBuild,
            })
            .with_message_id(next_message_id)
            .with_expiration(expiration)
            .with_payload(&payload)
            .build();

        Ok((next_router, message))
    }

    /// Handle short tunnel build request.
    pub fn handle_short_tunnel_build(
        &mut self,
        message: Message,
    ) -> crate::Result<(RouterId, Vec<u8>)> {
        let Message {
            message_id,
            expiration,
            mut payload,
            ..
        } = message;

        let (record_idx, record) = self
            .find_local_record::<SHORT_RECORD_LEN>(&mut payload)
            .ok_or(Error::Tunnel(TunnelError::RecordNotFound))?;

        let mut session = self.noise.create_short_inbound_session(
            EphemeralPublicKey::from_bytes(&record[PUBLIC_KEY_OFFSET]).ok_or(Error::InvalidData)?,
        );
        let decrypted_record =
            session.decrypt_build_record(record[RECORD_START_OFFSET].to_vec())?;

        let build_record = short::TunnelBuildRecord::parse(&decrypted_record).ok_or_else(|| {
            tracing::debug!(
                target: LOG_TARGET,
                ?message_id,
                "malformed short tunnel build request",
            );

            Error::InvalidData
        })?;

        let role = build_record.role();
        let tunnel_id = build_record.tunnel_id();
        let next_tunnel_id = build_record.next_tunnel_id();
        let next_message_id = build_record.next_message_id();
        let next_router = build_record.next_router();

        tracing::trace!(
            target: LOG_TARGET,
            ?role,
            %tunnel_id,
            %next_tunnel_id,
            %next_message_id,
            %next_router,
            "short tunnel build request",
        );

        // check if the tunnel can be accepted
        //
        // all transit tunnel build requests are rejected if the tunnel is shutting
        //
        // if the router is active, check if a new receiver can be added to routing table and if so,
        // create new receiver for the transit tunnel and add it to routing table
        let maybe_receiver = match self.shutdown_handle.is_shutting_down() {
            true => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?role,
                    %tunnel_id,
                    "router shutting down, rejecting transit tunnel",
                );

                None
            }
            false => match self.routing_table.try_add_tunnel::<TUNNEL_CHANNEL_SIZE>(tunnel_id) {
                Ok(receiver) => Some(receiver),
                Err(error) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        %tunnel_id,
                        ?error,
                        "tunnel already exists in routing table, rejecting",
                    );
                    None
                }
            },
        };

        // create tunnel build reply, either accept or reject, depending on whether the tunnel could
        // be accepted or not
        //
        // if assigned role is OBEP, generate keys for garlic-encrypting the TBRM
        //
        // if the tunnel is accepted, an event loop for the tunnel is started right away since we
        // won't know if another participant of the tunnel rejected the tunnel or not
        let (garlic_key, garlic_tag) = match maybe_receiver {
            None => {
                self.metrics_handle.counter(NUM_TRANSIT_TUNNELS_REJECTED).increment(1);

                record[48] = 0x00; // no options
                record[49] = 0x00;
                record[201] = 30; // reject

                session.create_tunnel_keys(role)?;
                session.encrypt_build_records(&mut payload, record_idx)?;

                match role {
                    HopRole::OutboundEndpoint => {
                        let tunnel_keys = session.finalize()?;

                        (
                            Some(tunnel_keys.garlic_key()),
                            Some(tunnel_keys.garlic_tag()),
                        )
                    }
                    _ => (None, None),
                }
            }
            Some(receiver) => {
                self.metrics_handle.counter(NUM_TRANSIT_TUNNELS_ACCEPTED).increment(1);
                self.metrics_handle.gauge(NUM_TRANSIT_TUNNELS).increment(1);

                record[48] = 0x00; // no options
                record[49] = 0x00;
                record[201] = 0x00; // accept

                session.create_tunnel_keys(role)?;
                session.encrypt_build_records(&mut payload, record_idx)?;

                // start tunnel event loop
                //
                // an accepted tunnel must be maintained for 10 minutes as we won't know
                // if another participant of the tunnel rejected it
                match role {
                    HopRole::InboundGateway => {
                        self.tunnels.push(InboundGateway::<R>::new(
                            tunnel_id,
                            next_tunnel_id,
                            next_router.clone(),
                            session.finalize()?,
                            self.routing_table.clone(),
                            self.metrics_handle.clone(),
                            receiver,
                        ));

                        (None, None)
                    }
                    HopRole::Participant => {
                        self.tunnels.push(Participant::<R>::new(
                            tunnel_id,
                            next_tunnel_id,
                            next_router.clone(),
                            session.finalize()?,
                            self.routing_table.clone(),
                            self.metrics_handle.clone(),
                            receiver,
                        ));

                        (None, None)
                    }
                    HopRole::OutboundEndpoint => {
                        let tunnel_keys = session.finalize()?;
                        let garlic_key = tunnel_keys.garlic_key();
                        let garlic_tag = tunnel_keys.garlic_tag();

                        self.tunnels.push(OutboundEndpoint::<R>::new(
                            tunnel_id,
                            next_tunnel_id,
                            next_router.clone(),
                            tunnel_keys,
                            self.routing_table.clone(),
                            self.metrics_handle.clone(),
                            receiver,
                        ));

                        (Some(garlic_key), Some(garlic_tag))
                    }
                }
            }
        };

        match role {
            // IBGWs and participants just forward the build request as-is to the next hop
            HopRole::InboundGateway | HopRole::Participant => {
                let msg = MessageBuilder::short()
                    .with_message_type(MessageType::ShortTunnelBuild)
                    .with_message_id(next_message_id)
                    .with_expiration(expiration)
                    .with_payload(&payload)
                    .build();

                Ok((next_router, msg))
            }
            // OBEP wraps the `OutboundBuildTunnelReply` in a `TunnelGateway` in order for
            // the recipient IBGW to be able to forward the tunnel build reply correctly
            HopRole::OutboundEndpoint => {
                // garlic tag and key must exist since this is a response for an OBEP
                let garlic_key = garlic_key.expect("to exist");
                let garlic_tag = garlic_tag.expect("to exist");

                let mut message = GarlicMessageBuilder::default()
                    .with_garlic_clove(
                        MessageType::OutboundTunnelBuildReply,
                        next_message_id,
                        R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                        DeliveryInstructions::Local,
                        &payload,
                    )
                    .with_date_time(R::time_since_epoch().as_secs() as u32)
                    .build();

                // message length + poly13055 tag + garlic tag + garlic message length
                let mut out = BytesMut::with_capacity(message.len() + 16 + 8 + 4);

                // encryption must succeed since the parameters are managed by us
                ChaChaPoly::new(&garlic_key)
                    .encrypt_with_ad_new(&garlic_tag, &mut message)
                    .expect("to succeed");

                out.put_u32(message.len() as u32 + 8);
                out.put_slice(&garlic_tag);
                out.put_slice(&message);

                let message = MessageBuilder::standard()
                    .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
                    .with_message_type(MessageType::Garlic)
                    .with_message_id(next_message_id)
                    .with_payload(&out)
                    .build();

                let msg = TunnelGateway {
                    tunnel_id: next_tunnel_id,
                    payload: &message,
                }
                .serialize();

                let message = MessageBuilder::short()
                    .with_message_type(MessageType::TunnelGateway)
                    .with_message_id(next_message_id)
                    .with_expiration(expiration)
                    .with_payload(&msg)
                    .build();

                Ok((next_router, message))
            }
        }
    }
}

impl<R: Runtime> Future for TransitTunnelManager<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        while let Poll::Ready(event) = self.message_rx.poll_recv(cx) {
            let result = match event {
                None => return Poll::Ready(()),
                Some(message) => match message.message_type {
                    MessageType::ShortTunnelBuild => self.handle_short_tunnel_build(message),
                    MessageType::VariableTunnelBuild => self.handle_variable_tunnel_build(message),
                    MessageType::Garlic => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            parsed = ?GarlicMessage::parse(&message.payload[..12]),
                            "garlic message received to obep",
                        );
                        continue;
                    }
                    message_type => {
                        tracing::warn!(?message_type, "unsupported message type");
                        continue;
                    }
                },
            };

            match result {
                Ok((router, message)) =>
                    if let Err(error) = self.routing_table.send_message(router, message) {
                        tracing::error!(target: LOG_TARGET, ?error, "failed to send message");
                    },
                Err(error) => tracing::debug!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to handle message",
                ),
            }
        }

        if self.shutdown_handle.poll_unpin(cx).is_ready() {
            tracing::info!(
                target: LOG_TARGET,
                "graceful shutdown requested",
            );

            if self.tunnels.is_empty() {
                self.shutdown_handle.shutdown();
                return Poll::Ready(());
            } else {
                tracing::info!(
                    target: LOG_TARGET,
                    num_tunnels = ?self.tunnels.len(),
                    "waiting for transit tunnels to expire",
                );
            }
        }

        while let Poll::Ready(event) = self.tunnels.poll_next_unpin(cx) {
            match event {
                None => return Poll::Ready(()),
                Some(tunnel_id) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        %tunnel_id,
                        "transit tunnel expired",
                    );
                    self.routing_table.remove_tunnel(&tunnel_id);
                    self.metrics_handle.gauge(NUM_TRANSIT_TUNNELS).decrement(1);

                    if self.tunnels.is_empty() && self.shutdown_handle.is_shutting_down() {
                        tracing::info!(
                            target: LOG_TARGET,
                            "shutting down",
                        );
                        self.shutdown_handle.shutdown();
                        return Poll::Ready(());
                    }
                }
            }
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{StaticPrivateKey, StaticPublicKey},
        primitives::{MessageId, Str},
        runtime::mock::MockRuntime,
        shutdown::ShutdownContext,
        tunnel::{
            garlic::{DeliveryInstructions as GarlicDeliveryInstructions, GarlicHandler},
            hop::{
                inbound::InboundTunnel, outbound::OutboundTunnel, pending::PendingTunnel,
                ReceiverKind, TunnelBuildParameters, TunnelInfo,
            },
            pool::TunnelPoolBuildParameters,
            tests::make_router,
        },
    };
    use bytes::Bytes;
    use rand_core::RngCore;
    use thingbuf::mpsc::channel;

    #[tokio::test]
    async fn accept_tunnel_build_request_participant() {
        let handle = MockRuntime::register_metrics(vec![], None);
        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey, ShutdownContext<MockRuntime>)>,
            Vec<TransitTunnelManager<MockRuntime>>,
        ) = (0..3)
            .map(|_| make_router(true))
            .into_iter()
            .map(|(router_hash, pk, noise_context, _)| {
                let (transit_tx, transit_rx) = channel(16);
                let (manager_tx, _manager_rx) = channel(16);
                let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
                let shutdown_handle = shutdown_ctx.handle();
                let routing_table =
                    RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

                (
                    (router_hash, pk, shutdown_ctx),
                    TransitTunnelManager::new(
                        noise_context,
                        routing_table,
                        transit_rx,
                        handle.clone(),
                        shutdown_handle,
                    ),
                )
            })
            .unzip();

        let (local_hash, _local_pk, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());
        let (hops, _handles): (Vec<_>, Vec<_>) = hops
            .into_iter()
            .map(|(router_id, public_key, context)| ((router_id, public_key), context))
            .unzip();

        let (_pending_tunnel, _next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise,
                    message_id,
                    tunnel_info: TunnelInfo::Outbound {
                        gateway,
                        tunnel_id,
                        router_id: local_hash,
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        assert!(transit_managers[0].handle_short_tunnel_build(message).is_ok());
    }

    #[tokio::test]
    async fn accept_tunnel_build_request_ibgw() {
        let handle = MockRuntime::register_metrics(vec![], None);
        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey, ShutdownContext<MockRuntime>)>,
            Vec<(
                GarlicHandler<MockRuntime>,
                TransitTunnelManager<MockRuntime>,
            )>,
        ) = (0..3)
            .map(|_| make_router(true))
            .into_iter()
            .map(|(router_hash, pk, noise_context, _)| {
                let (transit_tx, transit_rx) = channel(16);
                let (manager_tx, _manager_rx) = channel(16);
                let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
                let shutdown_handle = shutdown_ctx.handle();
                let routing_table =
                    RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

                (
                    (router_hash, pk, shutdown_ctx),
                    (
                        GarlicHandler::new(noise_context.clone(), handle.clone()),
                        TransitTunnelManager::new(
                            noise_context,
                            routing_table,
                            transit_rx,
                            handle.clone(),
                            shutdown_handle,
                        ),
                    ),
                )
            })
            .unzip();

        let (local_hash, _local_pk, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let TunnelPoolBuildParameters {
            context_handle: handle,
            ..
        } = TunnelPoolBuildParameters::new(Default::default());
        let (_tx, rx) = channel(64);
        let (hops, _handles): (Vec<_>, Vec<_>) = hops
            .into_iter()
            .map(|(router_id, public_key, context)| ((router_id, public_key), context))
            .unzip();

        let (_pending_tunnel, _next_router, message) =
            PendingTunnel::<InboundTunnel>::create_tunnel::<MockRuntime>(TunnelBuildParameters {
                hops: hops.clone(),
                name: Str::from("tunnel-pool"),
                noise: local_noise,
                message_id,
                tunnel_info: TunnelInfo::Inbound {
                    tunnel_id,
                    router_id: local_hash,
                },
                receiver: ReceiverKind::Inbound {
                    message_rx: rx,
                    handle,
                },
            })
            .unwrap();

        let message = match transit_managers[0].0.handle_message(message).unwrap().next() {
            Some(GarlicDeliveryInstructions::Local { message }) => message,
            _ => panic!("invalid delivery instructions"),
        };

        assert!(transit_managers[0].1.handle_short_tunnel_build(message).is_ok());
    }

    #[tokio::test]
    async fn accept_tunnel_build_request_obep() {
        let handle = MockRuntime::register_metrics(vec![], None);
        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey, ShutdownContext<MockRuntime>)>,
            Vec<TransitTunnelManager<MockRuntime>>,
        ) = (0..3)
            .map(|_| make_router(true))
            .into_iter()
            .map(|(router_hash, pk, noise_context, _)| {
                let (transit_tx, transit_rx) = channel(16);
                let (manager_tx, _manager_rx) = channel(16);
                let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
                let shutdown_handle = shutdown_ctx.handle();
                let routing_table =
                    RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

                (
                    (router_hash, pk, shutdown_ctx),
                    TransitTunnelManager::new(
                        noise_context,
                        routing_table,
                        transit_rx,
                        handle.clone(),
                        shutdown_handle,
                    ),
                )
            })
            .unzip();

        let (local_hash, _local_pk, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());
        let (hops, _handles): (Vec<_>, Vec<_>) = hops
            .into_iter()
            .map(|(router_id, public_key, context)| ((router_id, public_key), context))
            .unzip();

        let (pending_tunnel, _next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise.clone(),
                    message_id,
                    tunnel_info: TunnelInfo::Outbound {
                        gateway,
                        tunnel_id,
                        router_id: local_hash,
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        let message = (0..transit_managers.len() - 1).fold(message, |message, i| {
            let (_, msg) = transit_managers[i].handle_short_tunnel_build(message).unwrap();

            Message::parse_short(&msg).unwrap()
        });

        let (_, msg) = transit_managers[2].handle_short_tunnel_build(message).unwrap();

        let Message {
            message_type,
            payload,
            ..
        } = Message::parse_short(&msg).unwrap();

        assert_eq!(message_type, MessageType::TunnelGateway);

        let TunnelGateway {
            tunnel_id: recv_tunnel_id,
            payload,
        } = TunnelGateway::parse(&payload).unwrap();

        assert_eq!(TunnelId::from(recv_tunnel_id), gateway);
        let message = Message::parse_standard(&payload).unwrap();
        assert_eq!(message.message_type, MessageType::Garlic);

        pending_tunnel.try_build_tunnel::<MockRuntime>(message).unwrap();
    }

    #[test]
    fn local_record_not_found() {
        let handle = MockRuntime::register_metrics(vec![], None);
        let (hops, _transit_managers): (
            Vec<(Bytes, StaticPublicKey, ShutdownContext<MockRuntime>)>,
            Vec<TransitTunnelManager<MockRuntime>>,
        ) = (0..3)
            .map(|_| make_router(true))
            .into_iter()
            .map(|(router_hash, pk, noise_context, _)| {
                let (transit_tx, transit_rx) = channel(16);
                let (manager_tx, _manager_rx) = channel(16);
                let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
                let shutdown_handle = shutdown_ctx.handle();
                let routing_table =
                    RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

                (
                    (router_hash, pk, shutdown_ctx),
                    TransitTunnelManager::new(
                        noise_context,
                        routing_table,
                        transit_rx,
                        handle.clone(),
                        shutdown_handle,
                    ),
                )
            })
            .unzip();

        let (local_hash, _local_pk, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());
        let (hops, _handles): (Vec<_>, Vec<_>) = hops
            .into_iter()
            .map(|(router_id, public_key, context)| ((router_id, public_key), context))
            .unzip();

        let (_pending_tunnel, _next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise,
                    message_id,
                    tunnel_info: TunnelInfo::Outbound {
                        gateway,
                        tunnel_id,
                        router_id: local_hash.clone(),
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        // make new router which is not part of the tunnel build request
        let (_, _, noise, _) = make_router(true);
        let (transit_tx, transit_rx) = channel(16);
        let (manager_tx, _manager_rx) = channel(16);
        let routing_table = RoutingTable::new(RouterId::from(&local_hash), manager_tx, transit_tx);
        let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
        let shutdown_handle = shutdown_ctx.handle();
        let mut transit_manager = TransitTunnelManager::<MockRuntime>::new(
            noise,
            routing_table,
            transit_rx,
            handle.clone(),
            shutdown_handle,
        );

        match transit_manager.handle_short_tunnel_build(message).unwrap_err() {
            Error::Tunnel(TunnelError::RecordNotFound) => {}
            error => panic!("invalid error: {error:?}"),
        }
    }

    #[test]
    fn invalid_public_key_used() {
        let handle = MockRuntime::register_metrics(vec![], None);
        let (mut hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey, ShutdownContext<MockRuntime>)>,
            Vec<TransitTunnelManager<MockRuntime>>,
        ) = (0..3)
            .map(|_| make_router(true))
            .into_iter()
            .map(|(router_hash, pk, noise_context, _)| {
                let (transit_tx, transit_rx) = channel(16);
                let (manager_tx, _manager_rx) = channel(16);
                let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
                let shutdown_handle = shutdown_ctx.handle();
                let routing_table =
                    RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

                (
                    (router_hash, pk, shutdown_ctx),
                    TransitTunnelManager::new(
                        noise_context,
                        routing_table,
                        transit_rx,
                        handle.clone(),
                        shutdown_handle,
                    ),
                )
            })
            .unzip();

        let (local_hash, _local_pk, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        // replace the first hop's public key with a random public key
        let new_pubkey = {
            let mut key_bytes = [0u8; 32];
            MockRuntime::rng().fill_bytes(&mut key_bytes);
            let key = StaticPrivateKey::from_bytes(&key_bytes).unwrap();

            key.public()
        };
        hops[0].1 = new_pubkey;
        let (hops, _handles): (Vec<_>, Vec<_>) = hops
            .into_iter()
            .map(|(router_id, public_key, context)| ((router_id, public_key), context))
            .unzip();

        let (_pending_tunnel, _next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise,
                    message_id,
                    tunnel_info: TunnelInfo::Outbound {
                        gateway,
                        tunnel_id,
                        router_id: local_hash,
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        match transit_managers[0].handle_short_tunnel_build(message).unwrap_err() {
            Error::Chacha20Poly1305(_) => {}
            error => panic!("invalid error: {error:?}"),
        }
    }

    #[tokio::test]
    async fn router_shutting_down_tunnel_rejected() {
        let handle = MockRuntime::register_metrics(vec![], None);
        let mut hops = Vec::<(Bytes, StaticPublicKey)>::new();
        let mut ctxs = Vec::<ShutdownContext<MockRuntime>>::new();
        let mut transit_managers = Vec::<TransitTunnelManager<MockRuntime>>::new();

        for i in 0..3 {
            let (router_hash, pk, noise_context, _) = make_router(true);

            let (transit_tx, transit_rx) = channel(16);
            let (manager_tx, _manager_rx) = channel(16);
            let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
            let mut shutdown_handle = shutdown_ctx.handle();

            if i % 2 == 0 {
                shutdown_ctx.shutdown();
                tokio::time::timeout(Duration::from_secs(2), &mut shutdown_handle)
                    .await
                    .expect("no timeout");
            }

            let routing_table =
                RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

            hops.push((router_hash, pk));
            ctxs.push(shutdown_ctx);
            transit_managers.push(TransitTunnelManager::new(
                noise_context,
                routing_table,
                transit_rx,
                handle.clone(),
                shutdown_handle,
            ));
        }

        let (local_hash, _local_pk, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, _next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise.clone(),
                    message_id,
                    tunnel_info: TunnelInfo::Outbound {
                        gateway,
                        tunnel_id,
                        router_id: local_hash,
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        let message = (0..transit_managers.len() - 1).fold(message, |message, i| {
            let (_, msg) = transit_managers[i].handle_short_tunnel_build(message).unwrap();

            Message::parse_short(&msg).unwrap()
        });

        let (_, msg) = transit_managers[2].handle_short_tunnel_build(message).unwrap();

        let Message {
            message_type,
            payload,
            ..
        } = Message::parse_short(&msg).unwrap();

        assert_eq!(message_type, MessageType::TunnelGateway);

        let TunnelGateway {
            tunnel_id: recv_tunnel_id,
            payload,
        } = TunnelGateway::parse(&payload).unwrap();

        assert_eq!(TunnelId::from(recv_tunnel_id), gateway);
        let message = Message::parse_standard(&payload).unwrap();
        assert_eq!(message.message_type, MessageType::Garlic);

        match pending_tunnel.try_build_tunnel::<MockRuntime>(message) {
            Err(error) => {
                assert_eq!(error[0].1, Some(Err(TunnelError::TunnelRejected(30))));
                assert_eq!(error[1].1, Some(Ok(())));
                assert_eq!(error[2].1, Some(Err(TunnelError::TunnelRejected(30))));
            }
            _ => panic!("invalid error"),
        }
    }

    #[tokio::test]
    async fn transit_manager_exits_after_all_tunnels_have_expired() {
        crate::util::init_logger();

        let handle = MockRuntime::register_metrics(vec![], None);
        let (router_hash, _pk, noise_context, _) = make_router(true);
        let (transit_tx, transit_rx) = channel(16);
        let (manager_tx, _manager_rx) = channel(16);
        let routing_table = RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);
        let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
        let shutdown_handle = shutdown_ctx.handle();

        let mut transit_manager = TransitTunnelManager::<MockRuntime>::new(
            noise_context,
            routing_table,
            transit_rx,
            handle.clone(),
            shutdown_handle,
        );

        let handle = tokio::spawn(async move {
            transit_manager.tunnels.push(async move {
                tokio::time::sleep(Duration::from_secs(10)).await;
                TunnelId::random()
            });

            let _ = (&mut transit_manager).await;
        });

        shutdown_ctx.shutdown();

        // wait for 5 seconds and verify the operation times out because the transit tunnel expires
        // in 10 seconds
        assert!(tokio::time::timeout(Duration::from_secs(5), &mut shutdown_ctx).await.is_err());

        // wait until the transit tunnel expires and transit tunnel manager exits
        assert!(tokio::time::timeout(Duration::from_secs(10), &mut shutdown_ctx).await.is_ok());
        assert!(handle.await.is_ok());
    }
}
