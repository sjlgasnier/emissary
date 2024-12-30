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
        EphemeralPrivateKey,
    },
    error::{Error, TunnelError},
    i2np::{
        garlic::{DeliveryInstructions, GarlicMessage, GarlicMessageBlock, GarlicMessageBuilder},
        tunnel::build::short,
        Message, MessageType, I2NP_MESSAGE_EXPIRATION,
    },
    primitives::{RouterId, TunnelId},
    runtime::Runtime,
    tunnel::hop::{
        outbound::OutboundTunnel, ReceiverKind, Tunnel, TunnelBuildParameters, TunnelBuilder,
        TunnelDirection, TunnelHop, TunnelInfo,
    },
};

use bytes::{BufMut, Bytes, BytesMut};
use rand_core::RngCore;

use alloc::{collections::VecDeque, vec::Vec};
use core::{iter, marker::PhantomData, num::NonZeroUsize, time::Duration};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::pending";

/// How many records fit into a single [`TunnelData`] without having to fragment the tunnel build
/// request.
///
/// Used to clamp down the amount of fake records for inbound tunnel builds.
const UNFRAGMENTED_MAX_RECORDS: usize = 4usize;

/// Maximum build records.
const MAX_BUILD_RECORDS: usize = 8usize;

/// How long is reply waited for a build request until it's considered expired.
const TUNNEL_BUILD_EXPIRATION: Duration = Duration::from_secs(10);

/// Short tunnel build request record size.
const SHORT_RECORD_LEN: usize = 218;

/// Outbound tunnel.
pub struct PendingTunnel<T: Tunnel> {
    /// Pending tunnel hops.
    hops: VecDeque<TunnelHop>,

    /// Number of build records (real and fake).
    num_records: usize,

    /// Message receiver for the tunnel.
    receiver: ReceiverKind,

    /// Tunnel ID.
    tunnel_id: TunnelId,

    /// Marker for `Tunnel`.
    _tunnel: PhantomData<T>,
}

impl<R: Runtime> PendingTunnel<OutboundTunnel<R>> {
    /// Get garlic tag of the outbound endpoint.
    pub fn garlic_tag(&self) -> Bytes {
        // obep must exist since it was created by us
        self.hops.back().expect("tunnel to exist").key_context.garlic_tag_owned()
    }
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

        if hops.len() > MAX_BUILD_RECORDS {
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
            direction = ?T::direction(),
            %message_id,
            %tunnel_id,
            num_hops = ?hops.len(),
            "create tunnel",
        );

        // set build record to expire 10 seconds from now
        let time_now = R::time_since_epoch();
        let build_expiration = time_now + TUNNEL_BUILD_EXPIRATION;
        let num_hops =
            NonZeroUsize::new(hops.len()).ok_or(TunnelError::NotEnoughHops(hops.len()))?;

        // calculate record count for the tunnel build message
        //
        // if the build request doesn't consume all available record slots, a random number of fake
        // records are added to each tunnel build message
        //
        // for inbound builds (sent though an outbound tunnel), if the caller requested fewer than
        // [`UNFRAGMENTED_MAX_RECORDS`] many hops, the fake record count is clamped down to
        // [`UNFRAGMENTED_MAX_RECORDS`] to prevent the build message from getting fragmented
        let num_records = match T::direction() {
            TunnelDirection::Inbound if hops.len() < UNFRAGMENTED_MAX_RECORDS =>
                (hops.len() + (R::rng().next_u32() % 3) as usize).clamp(0, UNFRAGMENTED_MAX_RECORDS),
            _ => (hops.len() + (R::rng().next_u32() % 3) as usize).clamp(0, MAX_BUILD_RECORDS),
        };

        // save the first hop's static key in case this is an inbound tunnel build so that the
        // tunnel build message can be garlic-encrypted, preventing OBEP from reading the message
        let first_hop_static_key = hops[0].1.clone();

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
                            tunnel_id: *tunnel_id,
                            router: RouterId::from(router_hash),
                            key_context: noise.create_outbound_session::<R>(key, hop_role),
                        },
                        short::TunnelBuildRecordBuilder::default()
                            .with_tunnel_id(*tunnel_id)
                            .with_next_tunnel_id(*next_tunnel_id)
                            .with_next_router_hash(next_router_hash.as_ref())
                            .with_hop_role(hop_role)
                            .with_request_time((time_now.as_secs() / 60) as u32)
                            .with_request_expiration(build_expiration.as_secs() as u32)
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
            .filter_map(|((router_hash, record), tunnel_hop)| {
                ChaChaPoly::new(tunnel_hop.key_context.aead_key())
                    .encrypt_with_ad_new(tunnel_hop.key_context.state(), record)
                    .ok()
                    .map(|_| {
                        // update associated data to include the encrypted record
                        // which is used when decrypting the build reply
                        tunnel_hop.key_context.set_state(
                            Sha256::new()
                                .update(tunnel_hop.key_context.state())
                                .update(&record)
                                .finalize(),
                        );

                        let mut full_record = router_hash[..16].to_vec();
                        full_record.extend_from_slice(tunnel_hop.key_context.ephemeral_key());
                        full_record.extend_from_slice(record);

                        full_record
                    })
            })
            .chain(
                (0..num_records - num_hops.get())
                    .map(|_| short::TunnelBuildRecordBuilder::random(&mut R::rng())),
            )
            .collect::<Vec<_>>();

        // double encrypt records
        tunnel_hops.iter().enumerate().for_each(|(hop_idx, hop)| {
            encrypted_records.iter_mut().skip(hop_idx + 1).enumerate().for_each(
                |(record_idx, record)| {
                    ChaCha::with_nonce(
                        hop.key_context.reply_key(),
                        (hop_idx + record_idx + 1) as u64,
                    )
                    .decrypt(record);
                },
            )
        });

        Ok((
            Self {
                hops: tunnel_hops,
                num_records,
                receiver,
                _tunnel: Default::default(),
                tunnel_id,
            },
            RouterId::from(router_hashes[0].clone().to_vec()),
            match T::direction() {
                TunnelDirection::Outbound => Message {
                    message_id: *message_id,
                    expiration: build_expiration,
                    message_type: MessageType::ShortTunnelBuild,
                    payload: short::TunnelBuildReplyBuilder::from_records(encrypted_records),
                },
                TunnelDirection::Inbound => {
                    let mut message = GarlicMessageBuilder::default()
                        .with_date_time(R::time_since_epoch().as_secs() as u32)
                        .with_garlic_clove(
                            MessageType::ShortTunnelBuild,
                            message_id,
                            R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                            DeliveryInstructions::Local,
                            &short::TunnelBuildReplyBuilder::from_records(encrypted_records),
                        )
                        .build();

                    let ephemeral_secret = EphemeralPrivateKey::random(R::rng());
                    let ephemeral_public = ephemeral_secret.public_key();
                    let (key, tag) =
                        noise.derive_outbound_garlic_key(first_hop_static_key, ephemeral_secret);

                    // message length + poly13055 tg + ephemeral key + garlic message length
                    let mut out = BytesMut::with_capacity(message.len() + 16 + 32 + 4);

                    // encryption must succeed since the parameters are managed by us
                    ChaChaPoly::new(&key)
                        .encrypt_with_ad_new(&tag, &mut message)
                        .expect("to succeed");

                    out.put_u32(message.len() as u32 + 32);
                    out.put_slice(&ephemeral_public.to_vec());
                    out.put_slice(&message);

                    Message {
                        message_type: MessageType::Garlic,
                        message_id: *message_id,
                        expiration: R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                        payload: out.to_vec(),
                    }
                }
            },
        ))
    }

    /// Try to build tunnel from the tunnel build response contained in `payload`.
    ///
    /// This function consumes `self` and returns either a `Tunnel` which can then be used
    /// for tunnel messaging, or a `TunnelError` if the received message was malformed or one of the
    /// tunnel participants rejected the build request.
    pub fn try_build_tunnel<R: Runtime>(self, message: Message) -> crate::Result<T> {
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
                ChaChaPoly::new(&outbound_endpoint.key_context.garlic_key())
                    .decrypt_with_ad(&outbound_endpoint.key_context.garlic_tag(), &mut record)?;

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
                match message.blocks.into_iter().find(|message| {
                    core::matches!(
                        message,
                        GarlicMessageBlock::GarlicClove {
                            message_type: MessageType::OutboundTunnelBuildReply,
                            ..
                        }
                    )
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

        if payload.len() != (self.num_records * SHORT_RECORD_LEN + 1) {
            tracing::warn!(
                target: LOG_TARGET,
                tunnel = %self.tunnel_id,
                direction = ?T::direction(),
                expected_size = ?(self.hops.len() * SHORT_RECORD_LEN + 1),
                actual_size = ?payload.len(),
                "malformed tunnel build reply"
            );
            return Err(Error::Tunnel(TunnelError::InvalidMessage));
        }

        self.hops
            .into_iter()
            .enumerate()
            .rev()
            .try_fold(
                TunnelBuilder::new(self.tunnel_id, self.receiver),
                |builder, (hop_idx, hop)| {
                    let mut record = payload
                        [1 + (hop_idx * SHORT_RECORD_LEN)..1 + ((1 + hop_idx) * SHORT_RECORD_LEN)]
                        .to_vec();

                    ChaChaPoly::with_nonce(hop.key_context.reply_key(), hop_idx as u64)
                        .decrypt_with_ad(hop.key_context.state(), &mut record)
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
                        .for_each(|(index, record)| {
                            ChaCha::with_nonce(hop.key_context.reply_key(), index as u64)
                                .encrypt(record);
                        });

                    Ok(builder.with_hop(hop))
                },
            )
            .map(|builder| builder.build::<R>())
    }

    #[cfg(test)]
    pub fn hops(&self) -> &VecDeque<TunnelHop> {
        &self.hops
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        crypto::{EphemeralPublicKey, StaticPublicKey},
        i2np::tunnel::gateway::TunnelGateway,
        primitives::MessageId,
        runtime::mock::MockRuntime,
        shutdown::ShutdownContext,
        tunnel::{
            garlic::{DeliveryInstructions as GarlicDeliveryInstructions, GarlicHandler},
            hop::inbound::InboundTunnel,
            noise::NoiseContext,
            pool::TunnelPoolBuildParameters,
            routing_table::RoutingTable,
            tests::{make_router, TestTransitTunnelManager},
            transit::TransitTunnelManager,
        },
    };
    use bytes::Bytes;
    use thingbuf::mpsc::channel;

    #[tokio::test]
    async fn create_outbound_tunnel() {
        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey)>,
            Vec<TestTransitTunnelManager>,
        ) = (0..3)
            .map(|i| {
                let manager = TestTransitTunnelManager::new(if i % 2 == 0 { true } else { false });

                ((manager.router_hash(), manager.public_key()), manager)
            })
            .unzip();

        let (local_hash, _, local_noise, _) = make_router(true);
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
        assert_eq!(message.payload[1..].len() % 218, 0);

        let message = hops.iter().zip(transit_managers.iter_mut()).fold(
            message,
            |acc, ((_, _), transit_manager)| {
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
        assert!(pending_tunnel.try_build_tunnel::<MockRuntime>(message).is_ok());
    }

    #[tokio::test]
    async fn create_inbound_tunnel() {
        let handle = MockRuntime::register_metrics(vec![], None);

        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey, ShutdownContext<MockRuntime>)>,
            Vec<(
                GarlicHandler<MockRuntime>,
                TransitTunnelManager<MockRuntime>,
            )>,
        ) = (0..3)
            .map(|i| make_router(if i % 2 == 0 { true } else { false }))
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
        let _gateway = TunnelId::from(MockRuntime::rng().next_u32());
        let (hops, _handles): (Vec<_>, Vec<_>) = hops
            .into_iter()
            .map(|(router_id, public_key, context)| ((router_id, public_key), context))
            .unzip();
        let TunnelPoolBuildParameters {
            context_handle: handle,
            ..
        } = TunnelPoolBuildParameters::new(Default::default());
        let (_tx, rx) = channel(64);

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

        let message = match transit_managers[0].0.handle_message(message).unwrap().next() {
            Some(GarlicDeliveryInstructions::Local { message }) => message,
            _ => panic!("invalid delivery instructions"),
        };

        assert_eq!(message.message_id, message_id.into());
        assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));
        assert_eq!(message.payload[1..].len() % 218, 0);

        let message = hops.iter().zip(transit_managers.iter_mut()).fold(
            message,
            |acc, ((_, _), (_, transit_manager))| {
                let (_, message) = transit_manager.handle_short_tunnel_build(acc).unwrap();
                Message::parse_short(&message).unwrap()
            },
        );

        assert_eq!(message.message_type, MessageType::ShortTunnelBuild);
        assert!(pending_tunnel.try_build_tunnel::<MockRuntime>(message).is_ok());
    }

    #[test]
    fn tunnel_rejected() {
        let (hops, noise_contexts): (Vec<(Bytes, StaticPublicKey)>, Vec<NoiseContext>) = (0..3)
            .map(|i| make_router(if i % 2 == 0 { true } else { false }))
            .into_iter()
            .map(|(router_hash, pk, noise_context, _)| ((router_hash, pk), noise_context))
            .unzip();

        let (local_hash, _local_pk, local_noise, _) = make_router(true);
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

            let new_record = record[..].to_vec();

            let pk = EphemeralPublicKey::from_bytes(&new_record[16..48]).unwrap();

            let mut session = noise.create_short_inbound_session(pk);
            let decrypted_record = session.decrypt_build_record(record[48..].to_vec()).unwrap();

            let (_tunnel_id, role) = {
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

        match pending_tunnel.try_build_tunnel::<MockRuntime>(message).unwrap_err() {
            Error::Tunnel(TunnelError::TunnelRejected(0x30)) => {}
            _ => panic!("invalid error"),
        }
    }

    #[test]
    fn invalid_ciphertext() {
        let (hops, _noise_contexts): (Vec<(Bytes, StaticPublicKey)>, Vec<NoiseContext>) = (0..3)
            .map(|i| make_router(if i % 2 == 0 { true } else { false }))
            .into_iter()
            .map(|(router_hash, pk, noise_context, _)| ((router_hash, pk), noise_context))
            .unzip();

        let (local_hash, _local_pk, local_noise, _) = make_router(true);
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
        match pending_tunnel.try_build_tunnel::<MockRuntime>(message).unwrap_err() {
            Error::Tunnel(TunnelError::InvalidMessage) => {}
            _ => panic!("invalid error"),
        }
    }

    #[test]
    fn malformed_tunnel_build_reply() {
        let (hops, _noise_contexts): (Vec<(Bytes, StaticPublicKey)>, Vec<NoiseContext>) = (0..3)
            .map(|i| make_router(if i % 2 == 0 { true } else { false }))
            .into_iter()
            .map(|(router_hash, pk, noise_context, _)| ((router_hash, pk), noise_context))
            .unzip();

        let (local_hash, _local_pk, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, next_router, mut message) =
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

        // set random data as payload which causes the length check to fail
        message.message_type = MessageType::OutboundTunnelBuildReply;
        message.payload = vec![0u8; 123];

        // try to parse the tunnel build request as a reply, ciphertexsts won't decrypt correctly
        match pending_tunnel.try_build_tunnel::<MockRuntime>(message).unwrap_err() {
            Error::Tunnel(TunnelError::InvalidMessage) => {}
            _ => panic!("invalid error"),
        }
    }

    #[tokio::test]
    async fn create_long_outobound_tunnel() {
        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey)>,
            Vec<TestTransitTunnelManager>,
        ) = (0..8)
            .map(|i| {
                let manager = TestTransitTunnelManager::new(if i % 2 == 0 { true } else { false });

                ((manager.router_hash(), manager.public_key()), manager)
            })
            .unzip();

        let (local_hash, _, local_noise, _) = make_router(true);
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
        assert_eq!(message.payload[0], 8u8);
        assert_eq!(message.payload[1..].len() % 218, 0);

        let message = hops.iter().zip(transit_managers.iter_mut()).fold(
            message,
            |acc, ((_, _), transit_manager)| {
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
        assert!(pending_tunnel.try_build_tunnel::<MockRuntime>(message).is_ok());
    }
}
