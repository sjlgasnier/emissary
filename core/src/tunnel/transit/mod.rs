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
    crypto::{
        base64_encode,
        chachapoly::{ChaCha, ChaChaPoly},
        sha256::Sha256,
        EphemeralPublicKey, StaticPublicKey,
    },
    error::{RejectionReason, RoutingError, TunnelError},
    i2np::{
        tunnel::{
            build::{short, variable},
            data::EncryptedTunnelData,
            gateway::TunnelGateway,
        },
        HopRole, Message, MessageBuilder, MessageType,
    },
    primitives::{RouterId, TunnelId},
    runtime::{JoinSet, Runtime},
    tunnel::{
        noise::{NoiseContext, TunnelKeys},
        routing_table::RoutingTable,
        transit::{inbound::InboundGateway, outbound::OutboundEndpoint, participant::Participant},
    },
    Error,
};

use bytes::Bytes;
use futures::StreamExt;
use hashbrown::HashMap;
use rand_core::RngCore;
use thingbuf::mpsc::{channel, Receiver};

use alloc::{boxed::Box, vec::Vec};
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

    /// Get role of the transit tunnel hop.
    fn role(&self) -> HopRole;
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
    ) -> Self {
        Self {
            message_rx,
            metrics_handle,
            noise,
            routing_table,
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
                    .find(|(i, chunk)| &chunk[..16] == &self.noise.local_router_hash()[..16])
            })
            .flatten()
    }

    /// Handle variable tunnel build request.
    ///
    /// Only OBEP is supported, for any other hop the message is dropped.
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

        let (record_idx, mut record) = self
            .find_local_record::<VARIABLE_RECORD_LEN>(&mut payload)
            .ok_or(Error::Tunnel(TunnelError::RecordNotFound))?;

        let mut session = self
            .noise
            .create_long_inbound_session(EphemeralPublicKey::try_from(&record[PUBLIC_KEY_OFFSET])?);
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

        if role != HopRole::OutboundEndpoint {
            tracing::warn!(
                target: LOG_TARGET,
                ?role,
                %tunnel_id,
                %next_tunnel_id,
                %next_message_id,
                %next_router,
                "variable tunnel build only supported for outbound endpoint",
            );

            return Err(Error::Tunnel(TunnelError::MessageRejected(
                RejectionReason::NotSupported,
            )));
        }

        tracing::trace!(
            target: LOG_TARGET,
            ?role,
            %tunnel_id,
            %next_tunnel_id,
            %next_message_id,
            %next_router,
            "variable tunnel build request",
        );

        // try to insert transit tunnel into routing table, allocating it a channel
        //
        // if the tunnel already exists in the routing table, the build request is rejected
        match self.routing_table.try_add_tunnel::<TUNNEL_CHANNEL_SIZE>(tunnel_id) {
            Err(error) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    %tunnel_id,
                    ?error,
                    "tunnel already exists in routing table, rejecting",
                );

                // TODO: metrics
                record[48] = 0x00; // no options
                record[49] = 0x00;
                record[511] = 0x30; // reject

                session.encrypt_build_record(&mut record)?;
            }
            Ok(receiver) => {
                // TODO: metrics
                record[48] = 0x00; // no options
                record[49] = 0x00;
                record[511] = 0x00; // accept

                session.encrypt_build_record(&mut record)?;

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
            .with_message_type(MessageType::VariableTunnelBuildReply)
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
            message_type,
            message_id,
            expiration,
            mut payload,
        } = message;

        let (record_idx, record) = self
            .find_local_record::<SHORT_RECORD_LEN>(&mut payload)
            .ok_or(Error::Tunnel(TunnelError::RecordNotFound))?;

        let mut session = self.noise.create_short_inbound_session(EphemeralPublicKey::try_from(
            &record[PUBLIC_KEY_OFFSET],
        )?);
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
            ?next_router,
            "short tunnel build request",
        );

        // try to insert transit tunnel into routing table, allocating it a channel
        //
        // if the tunnel already exists in the routing table, the build request is rejected
        match self.routing_table.try_add_tunnel::<TUNNEL_CHANNEL_SIZE>(tunnel_id) {
            Err(error) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    %tunnel_id,
                    ?error,
                    "tunnel already exists in routing table, rejecting",
                );

                // TODO: metrics
                record[48] = 0x00; // no options
                record[49] = 0x00;
                record[201] = 0x30; // reject

                session.create_tunnel_keys(role)?;
                session.encrypt_build_records(&mut payload, record_idx)?;
            }
            Ok(receiver) => {
                // TODO: metrics
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
                    HopRole::InboundGateway => self.tunnels.push(InboundGateway::<R>::new(
                        tunnel_id,
                        next_tunnel_id,
                        next_router.clone(),
                        session.finalize()?,
                        self.routing_table.clone(),
                        self.metrics_handle.clone(),
                        receiver,
                    )),
                    HopRole::Participant => self.tunnels.push(Participant::<R>::new(
                        tunnel_id,
                        next_tunnel_id,
                        next_router.clone(),
                        session.finalize()?,
                        self.routing_table.clone(),
                        self.metrics_handle.clone(),
                        receiver,
                    )),
                    HopRole::OutboundEndpoint => self.tunnels.push(OutboundEndpoint::<R>::new(
                        tunnel_id,
                        next_tunnel_id,
                        next_router.clone(),
                        session.finalize()?,
                        self.routing_table.clone(),
                        self.metrics_handle.clone(),
                        receiver,
                    )),
                }
            }
        }

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
                // TODO: garlic encrypt
                let msg = MessageBuilder::standard()
                    .with_message_type(MessageType::OutboundTunnelBuildReply)
                    .with_message_id(next_message_id)
                    .with_expiration(expiration)
                    .with_payload(&payload)
                    .build();

                let msg = TunnelGateway {
                    tunnel_id: next_tunnel_id.into(),
                    payload: &msg,
                }
                .serialize();

                let message = MessageBuilder::short()
                    .with_message_type(MessageType::TunnelGateway)
                    .with_message_id(R::rng().next_u32())
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
        crypto::StaticPrivateKey,
        primitives::MessageId,
        runtime::mock::MockRuntime,
        tunnel::{
            hop::{
                inbound::InboundTunnel, outbound::OutboundTunnel, pending::PendingTunnel,
                ReceiverKind, TunnelBuildParameters, TunnelInfo,
            },
            pool::{
                TunnelPool, TunnelPoolBuildParameters, TunnelPoolContext, TunnelPoolContextHandle,
            },
            tests::make_router,
        },
    };
    use thingbuf::mpsc::{channel, Sender};

    #[tokio::test]
    async fn accept_tunnel_build_request_participant() {
        let handle = MockRuntime::register_metrics(vec![]);
        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey)>,
            Vec<TransitTunnelManager<MockRuntime>>,
        ) = (0..3)
            .map(|_| make_router())
            .into_iter()
            .map(|(router_hash, pk, noise_context, _)| {
                let (transit_tx, transit_rx) = channel(16);
                let (manager_tx, manager_rx) = channel(16);
                let routing_table =
                    RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

                (
                    (router_hash, pk),
                    TransitTunnelManager::new(
                        noise_context,
                        routing_table,
                        transit_rx,
                        handle.clone(),
                    ),
                )
            })
            .unzip();

        let (local_hash, local_pk, local_noise, _) = make_router();
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
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
        let handle = MockRuntime::register_metrics(vec![]);
        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey)>,
            Vec<TransitTunnelManager<MockRuntime>>,
        ) = (0..3)
            .map(|_| make_router())
            .into_iter()
            .map(|(router_hash, pk, noise_context, _)| {
                let (transit_tx, transit_rx) = channel(16);
                let (manager_tx, manager_rx) = channel(16);
                let routing_table =
                    RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

                (
                    (router_hash, pk),
                    TransitTunnelManager::new(
                        noise_context,
                        routing_table,
                        transit_rx,
                        handle.clone(),
                    ),
                )
            })
            .unzip();

        let (local_hash, local_pk, local_noise, _) = make_router();
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let TunnelPoolBuildParameters {
            context,
            context_handle: handle,
            ..
        } = TunnelPoolBuildParameters::new(Default::default());
        let (tx, rx) = channel(64);

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<InboundTunnel>::create_tunnel::<MockRuntime>(TunnelBuildParameters {
                hops: hops.clone(),
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

        assert!(transit_managers[0].handle_short_tunnel_build(message).is_ok());
    }

    #[tokio::test]
    async fn accept_tunnel_build_request_obep() {
        let handle = MockRuntime::register_metrics(vec![]);
        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey)>,
            Vec<TransitTunnelManager<MockRuntime>>,
        ) = (0..3)
            .map(|_| make_router())
            .into_iter()
            .map(|(router_hash, pk, noise_context, _)| {
                let (transit_tx, transit_rx) = channel(16);
                let (manager_tx, manager_rx) = channel(16);
                let routing_table =
                    RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

                (
                    (router_hash, pk),
                    TransitTunnelManager::new(
                        noise_context,
                        routing_table,
                        transit_rx,
                        handle.clone(),
                    ),
                )
            })
            .unzip();

        let (local_hash, local_pk, local_noise, _) = make_router();
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
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

        let message = (0..transit_managers.len() - 1).fold(message, |message, i| {
            let (_, msg) = transit_managers[i].handle_short_tunnel_build(message).unwrap();

            Message::parse_short(&msg).unwrap()
        });

        let (_, msg) = transit_managers[2].handle_short_tunnel_build(message).unwrap();

        let Message {
            message_type,
            message_id,
            expiration,
            payload,
        } = Message::parse_short(&msg).unwrap();

        assert_eq!(message_type, MessageType::TunnelGateway);

        let TunnelGateway {
            tunnel_id: recv_tunnel_id,
            payload,
        } = TunnelGateway::parse(&payload).unwrap();

        assert_eq!(TunnelId::from(recv_tunnel_id), gateway);

        let Some(Message {
            message_type: MessageType::OutboundTunnelBuildReply,
            message_id,
            expiration,
            payload,
        }) = Message::parse_standard(&payload)
        else {
            panic!("invalid message");
        };
    }

    #[test]
    fn local_record_not_found() {
        let handle = MockRuntime::register_metrics(vec![]);
        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey)>,
            Vec<TransitTunnelManager<MockRuntime>>,
        ) = (0..3)
            .map(|_| make_router())
            .into_iter()
            .map(|(router_hash, pk, noise_context, _)| {
                let (transit_tx, transit_rx) = channel(16);
                let (manager_tx, manager_rx) = channel(16);
                let routing_table =
                    RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

                (
                    (router_hash, pk),
                    TransitTunnelManager::new(
                        noise_context,
                        routing_table,
                        transit_rx,
                        handle.clone(),
                    ),
                )
            })
            .unzip();

        let (local_hash, local_pk, local_noise, _) = make_router();
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
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
        let (_, _, noise, _) = make_router();
        let (transit_tx, transit_rx) = channel(16);
        let (manager_tx, manager_rx) = channel(16);
        let routing_table = RoutingTable::new(RouterId::from(&local_hash), manager_tx, transit_tx);
        let mut transit_manager = TransitTunnelManager::<MockRuntime>::new(
            noise,
            routing_table,
            transit_rx,
            handle.clone(),
        );

        match transit_manager.handle_short_tunnel_build(message).unwrap_err() {
            Error::Tunnel(TunnelError::RecordNotFound) => {}
            error => panic!("invalid error: {error:?}"),
        }
    }

    #[test]
    fn invalid_public_key_used() {
        let handle = MockRuntime::register_metrics(vec![]);
        let (mut hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey)>,
            Vec<TransitTunnelManager<MockRuntime>>,
        ) = (0..3)
            .map(|_| make_router())
            .into_iter()
            .map(|(router_hash, pk, noise_context, _)| {
                let (transit_tx, transit_rx) = channel(16);
                let (manager_tx, manager_rx) = channel(16);
                let routing_table =
                    RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

                (
                    (router_hash, pk),
                    TransitTunnelManager::new(
                        noise_context,
                        routing_table,
                        transit_rx,
                        handle.clone(),
                    ),
                )
            })
            .unzip();

        let (local_hash, local_pk, local_noise, _) = make_router();
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        // replace the first hop's public key with a random public key
        let new_pubkey = {
            let mut key_bytes = [0u8; 32];
            MockRuntime::rng().fill_bytes(&mut key_bytes);
            let key = StaticPrivateKey::from(key_bytes.to_vec());

            key.public()
        };
        hops[0].1 = new_pubkey;

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
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
}
