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
        chachapoly::{ChaCha, ChaChaPoly},
        sha256::Sha256,
    },
    error::TunnelError,
    i2np::{
        garlic::{GarlicMessage, GarlicMessageBlock},
        tunnel::build::short,
        HopRole, Message, MessageBuilder, MessageType,
    },
    primitives::{RouterId, TunnelId},
    runtime::Runtime,
    tunnel::hop::{
        inbound::InboundTunnel, outbound::OutboundTunnel, ReceiverKind, Tunnel,
        TunnelBuildParameters, TunnelBuilder, TunnelDirection, TunnelHop, TunnelInfo,
    },
    Error,
};

use aes::cipher::Key;
use rand_core::RngCore;

use alloc::{collections::VecDeque, vec::Vec};
use core::{iter, marker::PhantomData, num::NonZeroUsize, time::Duration};
use thingbuf::mpsc::Receiver;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::pending";

/// How many build records should a `ShortTunnelBuildRequest` contain.
///
/// This includes the actual build request records and any fake records.
const NUM_BUILD_RECORDS: usize = 4;

/// How long is reply waited for a build request until it's considered expired.
const TUNNEL_BUILD_EXPIRATION: Duration = Duration::from_secs(10);

/// Outbound tunnel.
pub struct PendingTunnel<T: Tunnel> {
    /// Pending tunnel hops.
    hops: VecDeque<TunnelHop>,

    /// Message receiver for the tunnel.
    receiver: ReceiverKind,

    /// Tunnel ID.
    tunnel_id: TunnelId,

    /// Marker for `Tunnel`.
    _tunnel: PhantomData<T>,
}

impl<T: Tunnel> PendingTunnel<T> {
    /// Get reference to [`PendingTunnel`]'s `TunnelId`.
    pub fn tunnel_id(&self) -> &TunnelId {
        &self.tunnel_id
    }

    /// Create new [`PendingTunnel`].
    pub fn create_tunnel<R: Runtime>(
        parameters: TunnelBuildParameters,
    ) -> Result<(Self, RouterId, Message), TunnelError> {
        let TunnelBuildParameters {
            hops,
            noise,
            message_id,
            tunnel_info,
            receiver,
        } = parameters;

        if hops.len() > NUM_BUILD_RECORDS {
            return Err(TunnelError::TooManyHops(hops.len()));
        }

        // extract pending tunnel's id and id of the tunnel that's used for reception of the reply
        //
        // inbound tunnel build responses don't come through a tunnel so those build requests can
        // use the same tunnel id that's used for the actual tunnel
        //
        // outbound tunnel build responses are received through a channel which is different from
        // the actual tunnel that is being created and will thus have a different tunnel id
        let (gateway, tunnel_id, router_id) = match (tunnel_info, T::direction()) {
            (info @ TunnelInfo::Outbound { .. }, TunnelDirection::Outbound) => info.destruct(),
            (info @ TunnelInfo::Inbound { .. }, TunnelDirection::Inbound) => info.destruct(),
            (_, _) => unreachable!(),
        };

        tracing::trace!(
            target: LOG_TARGET,
            %message_id,
            %tunnel_id,
            direction = ?T::direction(),
            num_hops = ?hops.len(),
            "create tunnel",
        );

        // set build record to expire 10 seconds from now
        let time_now = R::time_since_epoch();
        let build_expiration = (time_now + TUNNEL_BUILD_EXPIRATION).as_secs() as u32;
        let num_hops =
            NonZeroUsize::new(hops.len()).ok_or(TunnelError::NotEnoughHops(hops.len()))?;

        // prepare router info for build records
        //
        // each hop is generated a random tunnel id and local info is chained at the end
        let (tunnel_ids, router_hashes): (Vec<_>, Vec<_>) = hops
            .iter()
            .map(|(router_hash, _)| (TunnelId::from(R::rng().next_u32()), router_hash.clone()))
            .chain(iter::once((gateway, router_id)))
            .unzip();

        // create build records and generate key contexts for each hop
        let (mut tunnel_hops, mut build_records): (VecDeque<TunnelHop>, Vec<Vec<u8>>) = tunnel_ids
            .iter()
            .zip(router_hashes.iter())
            .zip(tunnel_ids.iter().skip(1))
            .zip(router_hashes.iter().skip(1))
            .zip(T::hop_roles(num_hops))
            .zip(hops.into_iter().map(|(_, key)| key))
            .map(
                |(
                    ((((tunnel_id, router_hash), next_tunnel_id), next_router_hash), hop_role),
                    key,
                )| {
                    (
                        TunnelHop {
                            role: hop_role,
                            tunnel_id: *tunnel_id,
                            router: RouterId::from(router_hash),
                            key_context: noise.create_outbound_session::<R>(key, hop_role),
                        },
                        short::TunnelBuildRecordBuilder::default()
                            .with_tunnel_id(*tunnel_id)
                            .with_next_tunnel_id(*next_tunnel_id)
                            .with_next_router_hash(next_router_hash.as_ref())
                            .with_hop_role(hop_role)
                            .with_request_time(time_now.as_secs() as u32)
                            .with_request_expiration(build_expiration)
                            .with_next_message_id(message_id)
                            .serialize(&mut R::rng()),
                    )
                },
            )
            .unzip();

        // encrypt build records with each hop's aead key and extend the build record into full
        // `ShortTunnelBuildRecord` by prepending hop's truncated router hash and ephemeral public
        // key of the local router
        //
        // additionally, append fake records at the end so that the length of the tunnel build
        // request message is `NUM_BUILD_RECORDS` records long
        let mut encrypted_records = router_hashes
            .iter()
            .zip(build_records.iter_mut())
            .zip(tunnel_hops.iter_mut())
            .filter_map(|(((router_hash), mut record), mut tunnel_hop)| {
                ChaChaPoly::new(&tunnel_hop.key_context.aead_key())
                    .encrypt_with_ad_new(&tunnel_hop.key_context.state(), &mut record)
                    .ok()
                    .map(|_| {
                        // update associated data to include the encrypted record
                        // which is used when decrypting the build reply
                        tunnel_hop.key_context.set_state(
                            Sha256::new()
                                .update(&tunnel_hop.key_context.state())
                                .update(&record)
                                .finalize(),
                        );

                        let mut full_record = router_hash[..16].to_vec();
                        full_record.extend_from_slice(&tunnel_hop.key_context.ephemeral_key());
                        full_record.extend_from_slice(&record);

                        full_record
                    })
            })
            .chain(
                (0..NUM_BUILD_RECORDS - num_hops.get())
                    .map(|_| short::TunnelBuildRecordBuilder::random(&mut R::rng())),
            )
            .collect::<Vec<_>>();

        // double encrypt records
        //
        // TODO: randomize order
        tunnel_hops.iter().enumerate().for_each(|(hop_idx, hop)| {
            encrypted_records.iter_mut().skip(hop_idx + 1).enumerate().for_each(
                |(record_idx, mut record)| {
                    ChaCha::with_nonce(
                        &hop.key_context.reply_key(),
                        (hop_idx + record_idx + 1) as u64,
                    )
                    .decrypt(&mut record);
                },
            )
        });

        // TODO: garlic encrypt for inbound builds

        Ok((
            Self {
                hops: tunnel_hops,
                receiver,
                tunnel_id,
                _tunnel: Default::default(),
            },
            RouterId::from(router_hashes[0].clone().to_vec()),
            Message {
                message_id: *message_id,
                expiration: build_expiration as u64,
                message_type: MessageType::ShortTunnelBuild,
                payload: short::TunnelBuildReplyBuilder::from_records(encrypted_records),
            },
        ))
    }

    /// Try to build tunnel from the tunnel build response contained in `payload`.
    ///
    /// This function consumes `self` and returns either a `Tunnel` which can then be used
    /// for tunnel messaging, or a `TunnelError` if the received message was malformed or one of the
    /// tunnel participants rejected the build request.
    pub fn try_build_tunnel(self, mut message: Message) -> crate::Result<T> {
        tracing::trace!(
            target: LOG_TARGET,
            tunnel = %self.tunnel_id,
            direction = ?T::direction(),
            "handle tunnel build reply",
        );

        let mut payload = match (T::direction(), message.message_type) {
            // for inbound build the message type doesn't change from `ShortTunnelBuild`
            (TunnelDirection::Inbound, MessageType::ShortTunnelBuild) => message.payload.to_vec(),

            // for outbound builds the reply can be received in `OutboundTunnelBuildReply`
            (TunnelDirection::Outbound, MessageType::OutboundTunnelBuildReply) =>
                message.payload.to_vec(),

            // outbound reply can also be wrapped in a `GarlicMessage`
            (TunnelDirection::Outbound, MessageType::Garlic) => {
                // tunnel must exist since it was created by us
                let outbound_endpoint = self.hops.back().expect("tunnel to exist");

                // garlic decrypt the payload with OBEP's garlic key and tag
                // and try to parse the plaintext into a `GarlicMessage`
                let mut record = message.payload[12..].to_vec();
                ChaChaPoly::new(outbound_endpoint.key_context.garlic_key())
                    .decrypt_with_ad(outbound_endpoint.key_context.garlic_tag(), &mut record)?;

                let message = GarlicMessage::parse(&record).ok_or_else(|| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        tunnel_id = %self.tunnel_id,
                        "malformed garlic message as tunnel build reply",
                    );

                    Error::Tunnel(TunnelError::InvalidMessage)
                })?;

                // try to locate a garlic glove containing `OutboundTunnelBuildReply`
                // and discard any other cloves as they're no interesting at this time
                match message.blocks.into_iter().find(|message| match message {
                    GarlicMessageBlock::GarlicClove {
                        message_type: MessageType::OutboundTunnelBuildReply,
                        ..
                    } => true,
                    _ => false,
                }) {
                    Some(GarlicMessageBlock::GarlicClove { message_body, .. }) =>
                        message_body.to_vec(),
                    _ => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            tunnel_id = %self.tunnel_id,
                            "garlic messge didn't contain valid tunnel reply",
                        );

                        return Err(Error::Tunnel(TunnelError::InvalidMessage));
                    }
                }
            }
            (direction, message_type) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    tunnel_id = %self.tunnel_id,
                    ?direction,
                    ?message_type,
                    "invalid build message reply",
                );

                return Err(Error::Tunnel(TunnelError::InvalidMessage));
            }
        };

        self.hops
            .into_iter()
            .enumerate()
            .rev()
            .try_fold(
                TunnelBuilder::new(self.tunnel_id, self.receiver),
                |builder, (hop_idx, hop)| {
                    // TODO: ensure `payload` is long enough
                    let mut record =
                        payload[1 + (hop_idx * 218)..1 + ((1 + hop_idx) * 218)].to_vec();

                    ChaChaPoly::with_nonce(&hop.key_context.reply_key(), hop_idx as u64)
                        .decrypt_with_ad(&hop.key_context.state(), &mut record)
                        .map_err(|error| {
                            tracing::debug!(
                                target: LOG_TARGET,
                                tunnel_id = ?self.tunnel_id,
                                hop_tunnel_id = ?hop.tunnel_id,
                                ?error,
                                "failed to decrypt build record"
                            );

                            Error::Tunnel(TunnelError::InvalidMessage)
                        })?;

                    match record[201] {
                        0x00 => {
                            tracing::trace!(
                                target: LOG_TARGET,
                                tunnel_id = ?self.tunnel_id,
                                hop_tunnel_id = ?hop.tunnel_id,
                                direction = ?T::direction(),
                                "tunnel accepted",
                            );
                        }
                        reason => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                tunnel_id = ?self.tunnel_id,
                                hop_tunnel_id = ?hop.tunnel_id,
                                direction = ?T::direction(),
                                ?reason,
                                "tunnel rejected",
                            );

                            return Err(Error::Tunnel(TunnelError::TunnelRejected(reason)));
                        }
                    }

                    payload[1..]
                        .chunks_mut(218)
                        .enumerate()
                        .filter(|(index, _)| index != &hop_idx)
                        .for_each(|(index, mut record)| {
                            ChaCha::with_nonce(&hop.key_context.reply_key(), index as u64)
                                .encrypt(&mut record);
                        });

                    Ok(builder.with_hop(hop))
                },
            )
            .map(|builder| builder.build())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        crypto::{base64_encode, EphemeralPublicKey, StaticPrivateKey, StaticPublicKey},
        i2np::tunnel::{build::short::TunnelBuildRecord, gateway::TunnelGateway},
        primitives::MessageId,
        runtime::mock::MockRuntime,
        tunnel::{
            noise::NoiseContext,
            pool::{TunnelPoolContext, TunnelPoolHandle},
            routing_table::RoutingTable,
            tests::{make_router, TestTransitTunnelManager},
            transit::TransitTunnelManager,
        },
    };
    use bytes::Bytes;
    use thingbuf::mpsc::channel;

    #[tokio::test]
    async fn create_outbound_tunnel() {
        let handle = MockRuntime::register_metrics(vec![]);

        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey)>,
            Vec<TestTransitTunnelManager>,
        ) = (0..3)
            .map(|manager| {
                let manager = TestTransitTunnelManager::new();

                ((manager.router_hash(), manager.public_key()), manager)
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

        assert_eq!(message.message_id, message_id.into());
        assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));
        assert_eq!(message.payload[0], 4u8);
        assert_eq!(message.payload[1..].len() % 218, 0);

        let message = hops.iter().zip(transit_managers.iter_mut()).fold(
            message,
            |acc, ((router_hash, _), transit_manager)| {
                let (_, message) = transit_manager.handle_short_tunnel_build(acc).unwrap();
                Message::parse_short(&message).unwrap()
            },
        );
        assert_eq!(message.message_type, MessageType::TunnelGateway);

        let TunnelGateway {
            tunnel_id: recv_tunnel_id,
            payload,
        } = TunnelGateway::parse(&message.payload).unwrap();

        assert_eq!(TunnelId::from(recv_tunnel_id), gateway);

        let message = Message::parse_standard(&payload).unwrap();
        assert!(pending_tunnel.try_build_tunnel(message).is_ok());
    }

    #[tokio::test]
    async fn create_inbound_tunnel() {
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
        let (context, handle) = TunnelPoolContext::new();
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

        assert_eq!(message.message_id, message_id.into());
        assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));
        assert_eq!(message.payload[0], 4u8);
        assert_eq!(message.payload[1..].len() % 218, 0);

        let message = hops.iter().zip(transit_managers.iter_mut()).fold(
            message,
            |acc, ((router_hash, _), transit_manager)| {
                let (_, message) = transit_manager.handle_short_tunnel_build(acc).unwrap();
                Message::parse_short(&message).unwrap()
            },
        );

        assert_eq!(message.message_type, MessageType::ShortTunnelBuild);
        assert!(pending_tunnel.try_build_tunnel(message).is_ok());
    }

    #[test]
    fn tunnel_rejected() {
        let (hops, noise_contexts): (Vec<(Bytes, StaticPublicKey)>, Vec<NoiseContext>) = (0..3)
            .map(|_| make_router())
            .into_iter()
            .map(|(router_hash, pk, noise_context, _)| ((router_hash, pk), noise_context))
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

        let Message {
            message_type: MessageType::ShortTunnelBuild,
            message_id: parsed_message_id,
            expiration,
            mut payload,
        } = message
        else {
            panic!("invalid message");
        };

        assert_eq!(parsed_message_id, message_id.into());
        assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));
        assert_eq!(payload[0], 4u8);
        assert_eq!(payload[1..].len() % 218, 0);

        fn find_own_record<'a>(
            hash: &Bytes,
            payload: &'a mut [u8],
        ) -> Option<(usize, &'a mut [u8])> {
            payload
                .chunks_mut(218)
                .enumerate()
                .find(|(_, chunk)| &chunk[..16] == &hash[..16])
        }

        for ((router_hash, _), noise) in hops.iter().zip(noise_contexts.iter()) {
            let (record_idx, record) = find_own_record(&router_hash, &mut payload[1..]).unwrap();

            let mut new_record = record[..].to_vec();

            let pk = EphemeralPublicKey::try_from(&new_record[16..48]).unwrap();

            let mut session = noise.create_short_inbound_session(pk);
            let decrypted_record = session.decrypt_build_record(record[48..].to_vec()).unwrap();

            let (tunnel_id, role) = {
                let record = short::TunnelBuildRecord::parse(&decrypted_record).unwrap();
                (record.tunnel_id(), record.role())
            };

            if record_idx % 2 == 0 {
                record[201] = 0x30;
            } else {
                record[201] = 0x00;
            }

            session.create_tunnel_keys(role).unwrap();
            session.encrypt_build_records(&mut payload, record_idx).unwrap();
        }

        let message = Message {
            message_type: MessageType::OutboundTunnelBuildReply,
            message_id: message_id.into(),
            expiration,
            payload,
        };

        match pending_tunnel.try_build_tunnel(message).unwrap_err() {
            Error::Tunnel(TunnelError::TunnelRejected(0x30)) => {}
            _ => panic!("invalid error"),
        }
    }

    #[test]
    fn invalid_ciphertext() {
        let (hops, noise_contexts): (Vec<(Bytes, StaticPublicKey)>, Vec<NoiseContext>) = (0..3)
            .map(|_| make_router())
            .into_iter()
            .map(|(router_hash, pk, noise_context, _)| ((router_hash, pk), noise_context))
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

        assert_eq!(message.message_id, message_id.into());
        assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));
        assert_eq!(message.payload[0], 4u8);
        assert_eq!(message.payload[1..].len() % 218, 0);

        // try to parse the tunnel build request as a reply, ciphertexsts won't decrypt correctly
        match pending_tunnel.try_build_tunnel(message).unwrap_err() {
            Error::Tunnel(TunnelError::InvalidMessage) => {}
            _ => panic!("invalid error"),
        }
    }
}
