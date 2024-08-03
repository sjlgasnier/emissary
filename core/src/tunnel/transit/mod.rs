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
        StaticPublicKey,
    },
    error::TunnelError,
    i2np::{
        HopRole, MessageType, RawI2NpMessageBuilder, RawI2npMessage, ShortTunnelBuildRecord,
        TunnelGatewayMessage,
    },
    primitives::{RouterId, TunnelId},
    runtime::Runtime,
    tunnel::noise::{NoiseContext, PendingTunnelKeyContext},
    Error,
};

use bytes::Bytes;
use hashbrown::HashMap;

use alloc::{boxed::Box, vec::Vec};
use core::time::Duration;
use rand_core::RngCore;

pub trait TransitTunnel: Send {
    fn role(&self) -> HopRole;
}

/// Tunnel participant.
struct Participant {
    /// Tunnel ID.
    tunnel_id: TunnelId,
    /// Next tunnel ID.
    next_tunnel_id: TunnelId,

    /// Next router ID.
    next_router: RouterId,

    /// Tunnel key context.
    key_context: PendingTunnelKeyContext,
}

impl TransitTunnel for Participant {
    fn role(&self) -> HopRole {
        HopRole::Participant
    }
}

/// Inbound gateway.
struct InboundGateway {
    /// Tunnel ID.
    tunnel_id: TunnelId,
    /// Next tunnel ID.
    next_tunnel_id: TunnelId,

    /// Next router ID.
    next_router: RouterId,

    /// Tunnel key context.
    key_context: PendingTunnelKeyContext,
}

impl TransitTunnel for InboundGateway {
    fn role(&self) -> HopRole {
        HopRole::InboundGateway
    }
}

/// Outbound endpoint.
struct OutboundEndpoint {
    /// Tunnel ID.
    tunnel_id: TunnelId,
    /// Next tunnel ID.
    next_tunnel_id: TunnelId,

    /// Next router ID.
    next_router: RouterId,

    /// Tunnel key context.
    key_context: PendingTunnelKeyContext,
}

impl TransitTunnel for OutboundEndpoint {
    fn role(&self) -> HopRole {
        HopRole::OutboundEndpoint
    }
}

impl Participant {
    fn new(
        tunnel_id: TunnelId,
        next_tunnel_id: TunnelId,
        next_router: RouterId,
        key_context: PendingTunnelKeyContext,
    ) -> Self
    where
        Self: Sized,
    {
        Participant {
            tunnel_id,
            next_tunnel_id,
            next_router,
            key_context,
        }
    }
}

impl InboundGateway {
    fn new(
        tunnel_id: TunnelId,
        next_tunnel_id: TunnelId,
        next_router: RouterId,
        key_context: PendingTunnelKeyContext,
    ) -> Self
    where
        Self: Sized,
    {
        InboundGateway {
            tunnel_id,
            next_tunnel_id,
            next_router,
            key_context,
        }
    }
}

impl OutboundEndpoint {
    fn new(
        tunnel_id: TunnelId,
        next_tunnel_id: TunnelId,
        next_router: RouterId,
        key_context: PendingTunnelKeyContext,
    ) -> Self
    where
        Self: Sized,
    {
        OutboundEndpoint {
            tunnel_id,
            next_tunnel_id,
            next_router,
            key_context,
        }
    }
}

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::transit";

/// Short tunnel build request record size.
const SHORT_BUILD_REQUEST_RECORD: usize = 218;

/// Transit tunnel manager.
pub struct TransitTunnelManager<R: Runtime> {
    /// Metrics handle.
    metrics_handle: R::MetricsHandle,

    /// Noise context.
    noise: NoiseContext,

    /// Transit tunnels.
    tunnels: HashMap<TunnelId, Box<dyn TransitTunnel>>,
}

impl<R: Runtime> TransitTunnelManager<R> {
    /// Create new [`TransitTunnelManager`].
    pub fn new(noise: NoiseContext, metrics_handle: R::MetricsHandle) -> Self {
        Self {
            noise,
            metrics_handle,
            tunnels: HashMap::new(),
        }
    }

    /// Return mutable reference to local build record and its index the build request messages.
    fn find_local_record<'a>(&self, payload: &'a mut [u8]) -> Option<(usize, &'a mut [u8])> {
        (payload.len() > SHORT_BUILD_REQUEST_RECORD
            && (payload.len() - 1) % SHORT_BUILD_REQUEST_RECORD == 0)
            .then(|| {
                payload[1..]
                    .chunks_mut(SHORT_BUILD_REQUEST_RECORD)
                    .enumerate()
                    .find(|(i, chunk)| &chunk[..16] == &self.noise.local_router_hash()[..16])
            })
            .flatten()
    }

    /// Handle short tunnel build request.
    pub fn handle_short_tunnel_build(
        &mut self,
        message: RawI2npMessage,
    ) -> crate::Result<(RouterId, Vec<u8>)> {
        let RawI2npMessage {
            message_type,
            message_id,
            expiration,
            mut payload,
        } = message;

        // try to locate our record
        let (record_idx, record) = self
            .find_local_record(&mut payload)
            .ok_or(Error::Tunnel(TunnelError::RecordNotFound))?;

        // create pending tunnel session by deriving keys for decrypting the record
        let mut session = self.noise.create_pending_tunnel_session(
            StaticPublicKey::from_bytes(record[16..48].to_vec()).expect("to succeed"),
        );
        let (decrypted_record, aead_state) = session.decrypt_build_record(record[48..].to_vec())?;

        let build_record = ShortTunnelBuildRecord::parse(&decrypted_record).ok_or_else(|| {
            tracing::debug!(
                target: LOG_TARGET,
                ?message_id,
                "malformed short tunnel build request",
            );

            Error::InvalidData
        })?;

        let role = build_record.role();
        let tunnel_id = TunnelId::from(build_record.tunnel_id());
        let next_tunnel_id = TunnelId::from(build_record.next_tunnel_id());
        let next_message_id = build_record.next_message_id();
        let next_router = RouterId::from(build_record.next_router_hash());
        let tunnel_session = session.derive_tunnel_keys(role);

        tracing::trace!(
            target: LOG_TARGET,
            ?role,
            ?tunnel_id,
            ?next_tunnel_id,
            ?next_message_id,
            ?next_router,
            "short tunnel build request",
        );

        record[48] = 0x00; // no options
        record[49] = 0x00;
        record[201] = 0x00; // accept

        // encrypt our record with chachapoly
        // TODO: so ugly
        let tag = ChaChaPoly::with_nonce(&tunnel_session.reply_key, record_idx as u64)
            .encrypt_with_ad(&aead_state, &mut record[0..202])
            .unwrap();
        record[202..218].copy_from_slice(&tag);

        // encrypt other records with chacha
        payload[1..]
            .chunks_mut(SHORT_BUILD_REQUEST_RECORD)
            .enumerate()
            .filter(|(idx, _)| idx != &record_idx)
            .for_each(|(idx, mut record)| {
                ChaCha::with_nonce(&tunnel_session.reply_key, idx as u64).encrypt(&mut record);
            });

        self.tunnels.insert(
            tunnel_id,
            match role {
                HopRole::InboundGateway => Box::new(InboundGateway::new(
                    tunnel_id,
                    next_tunnel_id,
                    next_router.clone(),
                    tunnel_session,
                )),
                HopRole::Participant => Box::new(Participant::new(
                    tunnel_id,
                    next_tunnel_id,
                    next_router.clone(),
                    tunnel_session,
                )),
                HopRole::OutboundEndpoint => Box::new(OutboundEndpoint::new(
                    tunnel_id,
                    next_tunnel_id,
                    next_router.clone(),
                    tunnel_session,
                )),
            },
        );

        match role {
            // IBGWs and participants just forward the build request as-is to the next hop
            HopRole::InboundGateway | HopRole::Participant => {
                let msg = RawI2NpMessageBuilder::short()
                    .with_message_type(MessageType::ShortTunnelBuild)
                    .with_message_id(next_message_id)
                    .with_expiration(expiration)
                    .with_payload(payload)
                    .serialize();

                Ok((next_router, msg))
            }
            // OBEP wraps the `OutboundBuildTunnelReply` in a `TunnelGateway` in order for
            // the recipient IBGW to be able to forward the tunnel build reply correctly
            HopRole::OutboundEndpoint => {
                // TODO: garlic encrypt
                let msg = RawI2NpMessageBuilder::standard()
                    .with_message_type(MessageType::OutboundTunnelBuildReply)
                    .with_message_id(next_message_id)
                    .with_expiration(expiration)
                    .with_payload(payload)
                    .serialize();

                let msg = TunnelGatewayMessage {
                    tunnel_id: next_tunnel_id.into(),
                    payload: &msg,
                }
                .serialize();

                let message = RawI2NpMessageBuilder::short()
                    .with_message_type(MessageType::TunnelGateway)
                    .with_message_id(R::rng().next_u32())
                    .with_expiration(expiration)
                    .with_payload(msg)
                    .serialize();

                Ok((next_router, message))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::StaticPrivateKey,
        primitives::MessageId,
        runtime::mock::MockRuntime,
        tunnel::hop::{
            inbound::InboundTunnel, outbound::OutboundTunnel, pending::PendingTunnel,
            TunnelBuildParameters,
        },
    };

    fn make_router() -> (Bytes, StaticPublicKey, NoiseContext) {
        let mut key_bytes = vec![0u8; 32];
        let mut router_hash = vec![0u8; 32];

        MockRuntime::rng().fill_bytes(&mut key_bytes);
        MockRuntime::rng().fill_bytes(&mut router_hash);

        let sk = StaticPrivateKey::from(key_bytes);
        let pk = sk.public();
        let router_hash = Bytes::from(router_hash);

        (router_hash.clone(), pk, NoiseContext::new(sk, router_hash))
    }

    #[test]
    fn accept_tunnel_build_request_participant() {
        let handle = MockRuntime::register_metrics(vec![]);
        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey)>,
            Vec<TransitTunnelManager<MockRuntime>>,
        ) = (0..3)
            .map(|_| make_router())
            .into_iter()
            .map(|(router_hash, pk, noise_context)| {
                (
                    (router_hash, pk),
                    TransitTunnelManager::new(noise_context, handle.clone()),
                )
            })
            .unzip();

        let (local_hash, local_pk, local_noise) = make_router();
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<OutboundTunnel>::create_tunnel::<MockRuntime>(TunnelBuildParameters {
                hops: hops.clone(),
                noise: local_noise,
                message_id,
                tunnel_id,
                our_hash: local_hash,
            })
            .unwrap();

        let mut message = RawI2npMessage::parse::<true>(&message).unwrap();

        assert!(transit_managers[0].handle_short_tunnel_build(message).is_ok());
        assert_eq!(transit_managers[0].tunnels.len(), 1);
        assert_eq!(
            transit_managers[0].tunnels.iter().next().map(|(_, tunnel)| tunnel.role()),
            Some(HopRole::Participant)
        );
    }

    #[test]
    fn accept_tunnel_build_request_ibgw() {
        let handle = MockRuntime::register_metrics(vec![]);
        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey)>,
            Vec<TransitTunnelManager<MockRuntime>>,
        ) = (0..3)
            .map(|_| make_router())
            .into_iter()
            .map(|(router_hash, pk, noise_context)| {
                (
                    (router_hash, pk),
                    TransitTunnelManager::new(noise_context, handle.clone()),
                )
            })
            .unzip();

        let (local_hash, local_pk, local_noise) = make_router();
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<InboundTunnel>::create_tunnel::<MockRuntime>(TunnelBuildParameters {
                hops: hops.clone(),
                noise: local_noise,
                message_id,
                tunnel_id,
                our_hash: local_hash,
            })
            .unwrap();

        let mut message = RawI2npMessage::parse::<true>(&message).unwrap();

        assert!(transit_managers[0].handle_short_tunnel_build(message).is_ok());
        assert_eq!(transit_managers[0].tunnels.len(), 1);
        assert_eq!(
            transit_managers[0].tunnels.iter().next().map(|(_, tunnel)| tunnel.role()),
            Some(HopRole::InboundGateway)
        );
    }

    #[test]
    fn accept_tunnel_build_request_obep() {
        let handle = MockRuntime::register_metrics(vec![]);
        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey)>,
            Vec<TransitTunnelManager<MockRuntime>>,
        ) = (0..3)
            .map(|_| make_router())
            .into_iter()
            .map(|(router_hash, pk, noise_context)| {
                (
                    (router_hash, pk),
                    TransitTunnelManager::new(noise_context, handle.clone()),
                )
            })
            .unzip();

        let (local_hash, local_pk, local_noise) = make_router();
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<OutboundTunnel>::create_tunnel::<MockRuntime>(TunnelBuildParameters {
                hops: hops.clone(),
                noise: local_noise,
                message_id,
                tunnel_id,
                our_hash: local_hash,
            })
            .unwrap();

        let message = (0..transit_managers.len() - 1).fold(
            RawI2npMessage::parse::<true>(&message).unwrap(),
            |message, i| {
                let (_, msg) = transit_managers[i].handle_short_tunnel_build(message).unwrap();

                assert_eq!(transit_managers[i].tunnels.len(), 1);
                assert_eq!(
                    transit_managers[i].tunnels.iter().next().map(|(_, tunnel)| tunnel.role()),
                    Some(HopRole::Participant)
                );

                RawI2npMessage::parse::<true>(&msg).unwrap()
            },
        );

        let (_, msg) = transit_managers[2].handle_short_tunnel_build(message).unwrap();
        assert_eq!(transit_managers[2].tunnels.len(), 1);
        assert_eq!(
            transit_managers[2].tunnels.iter().next().map(|(_, tunnel)| tunnel.role()),
            Some(HopRole::OutboundEndpoint)
        );

        let RawI2npMessage {
            message_type,
            message_id,
            expiration,
            payload,
        } = RawI2npMessage::parse::<true>(&msg).unwrap();

        assert_eq!(message_type, MessageType::TunnelGateway);

        let TunnelGatewayMessage {
            tunnel_id: recv_tunnel_id,
            payload,
        } = TunnelGatewayMessage::parse(&payload).unwrap();

        assert_eq!(TunnelId::from(recv_tunnel_id), tunnel_id);

        let Some(RawI2npMessage {
            message_type: MessageType::OutboundTunnelBuildReply,
            message_id,
            expiration,
            payload,
        }) = RawI2npMessage::parse::<false>(&payload)
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
            .map(|(router_hash, pk, noise_context)| {
                (
                    (router_hash, pk),
                    TransitTunnelManager::new(noise_context, handle.clone()),
                )
            })
            .unzip();

        let (local_hash, local_pk, local_noise) = make_router();
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<OutboundTunnel>::create_tunnel::<MockRuntime>(TunnelBuildParameters {
                hops: hops.clone(),
                noise: local_noise,
                message_id,
                tunnel_id,
                our_hash: local_hash,
            })
            .unwrap();

        let mut message = RawI2npMessage::parse::<true>(&message).unwrap();

        // make new router which is not part of the tunnel build request
        let (_, _, noise) = make_router();
        let mut transit_manager = TransitTunnelManager::<MockRuntime>::new(noise, handle.clone());

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
            .map(|(router_hash, pk, noise_context)| {
                (
                    (router_hash, pk),
                    TransitTunnelManager::new(noise_context, handle.clone()),
                )
            })
            .unzip();

        let (local_hash, local_pk, local_noise) = make_router();
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());

        // replace the first hop's public key with a random public key
        let new_pubkey = {
            let mut key_bytes = [0u8; 32];
            MockRuntime::rng().fill_bytes(&mut key_bytes);
            let key = StaticPrivateKey::from(key_bytes.to_vec());

            key.public()
        };
        hops[0].1 = new_pubkey;

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<OutboundTunnel>::create_tunnel::<MockRuntime>(TunnelBuildParameters {
                hops: hops.clone(),
                noise: local_noise,
                message_id,
                tunnel_id,
                our_hash: local_hash,
            })
            .unwrap();

        let mut message = RawI2npMessage::parse::<true>(&message).unwrap();

        match transit_managers[0].handle_short_tunnel_build(message).unwrap_err() {
            Error::Chacha20Poly1305(_) => {}
            error => panic!("invalid error: {error:?}"),
        }
    }
}
