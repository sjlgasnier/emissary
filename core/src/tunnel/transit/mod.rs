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
    error::{RejectionReason, TunnelError},
    i2np::{
        EncryptedTunnelData, HopRole, MessageType, RawI2NpMessageBuilder, RawI2npMessage,
        ShortTunnelBuildRecord, TunnelBuildRecord, TunnelGatewayMessage,
    },
    primitives::{RouterId, TunnelId},
    runtime::Runtime,
    tunnel::{
        new_noise::{NoiseContext, TunnelKeys},
        transit::{inbound::InboundGateway, outbound::OutboundEndpoint, participant::Participant},
    },
    Error,
};

use bytes::Bytes;
use hashbrown::HashMap;
use rand_core::RngCore;

use alloc::{boxed::Box, vec::Vec};
use core::{
    ops::{Range, RangeFrom},
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

/// Common interface for transit tunnels.
pub trait TransitTunnel: Send {
    /// Get role of the transit tunnel hop.
    fn role(&self) -> HopRole;

    /// Handle tunnel data.
    ///
    /// Return `RouterId` of the next hop and the message that
    /// needs to be forwarded to them on success.
    ///
    /// `EncryptedTunnelData` will only be accepted by OBEPs and participants.
    fn handle_tunnel_data<'a>(
        &mut self,
        tunnel_data: EncryptedTunnelData<'a>,
    ) -> crate::Result<(RouterId, Vec<u8>)>;

    /// Handle tunnel gateway message.
    ///
    /// `TunnelGatewayMessage` will only be accepted by IBGWs.
    fn handle_tunnel_gateway<'a>(
        &mut self,
        tunnel_gateway: &'a TunnelGatewayMessage<'a>,
    ) -> crate::Result<(RouterId, Vec<u8>)>;
}

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
        message: RawI2npMessage,
    ) -> crate::Result<(RouterId, Vec<u8>)> {
        let RawI2npMessage {
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

        let build_record = TunnelBuildRecord::parse(&decrypted_record).ok_or_else(|| {
            tracing::warn!(
                target: LOG_TARGET,
                ?message_id,
                "malformed variable tunnel build request",
            );

            Error::InvalidData
        })?;

        let role = build_record.role();
        let tunnel_id = TunnelId::from(build_record.tunnel_id());
        let next_tunnel_id = TunnelId::from(build_record.next_tunnel_id());
        let next_message_id = build_record.next_message_id();
        let next_router = RouterId::from(build_record.next_router_hash());

        if role != HopRole::OutboundEndpoint {
            tracing::warn!(
                target: LOG_TARGET,
                ?role,
                %tunnel_id,
                %next_tunnel_id,
                %next_message_id,
                ?next_router,
                "variable tunnel build only supported for outbound enpoint",
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
            ?next_router,
            "variable tunnel build request",
        );

        record[48] = 0x00; // no options
        record[49] = 0x00;
        record[511] = 0x00; // accept

        session.encrypt_build_record(&mut record);
        session.finalize(
            build_record.tunnel_layer_key().to_vec(),
            build_record.tunnel_iv_key().to_vec(),
        );

        let message = RawI2NpMessageBuilder::short()
            .with_message_type(MessageType::VariableTunnelBuildReply)
            .with_message_id(message_id)
            .with_expiration(expiration)
            .with_payload(payload)
            .serialize();

        Ok((next_router, message))
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

        let (record_idx, record) = self
            .find_local_record::<SHORT_RECORD_LEN>(&mut payload)
            .ok_or(Error::Tunnel(TunnelError::RecordNotFound))?;

        let mut session = self.noise.create_short_inbound_session(EphemeralPublicKey::try_from(
            &record[PUBLIC_KEY_OFFSET],
        )?);
        let decrypted_record =
            session.decrypt_build_record(record[RECORD_START_OFFSET].to_vec())?;

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

        tracing::trace!(
            target: LOG_TARGET,
            ?role,
            %tunnel_id,
            %next_tunnel_id,
            %next_message_id,
            ?next_router,
            "short tunnel build request",
        );

        record[48] = 0x00; // no options
        record[49] = 0x00;
        record[201] = 0x00; // accept

        session.create_tunnel_keys(role)?;
        session.encrypt_build_records(&mut payload, record_idx)?;

        self.tunnels.insert(
            tunnel_id,
            match role {
                HopRole::InboundGateway => Box::new(InboundGateway::<R>::new(
                    tunnel_id,
                    next_tunnel_id,
                    next_router.clone(),
                    session.finalize()?,
                )),
                HopRole::Participant => Box::new(Participant::<R>::new(
                    tunnel_id,
                    next_tunnel_id,
                    next_router.clone(),
                    session.finalize()?,
                )),
                HopRole::OutboundEndpoint => Box::new(OutboundEndpoint::<R>::new(
                    tunnel_id,
                    next_tunnel_id,
                    next_router.clone(),
                    session.finalize()?,
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

    /// Handle tunnel data.
    pub fn handle_tunnel_data(
        &mut self,
        message: RawI2npMessage,
    ) -> crate::Result<(RouterId, Vec<u8>)> {
        let RawI2npMessage {
            message_type,
            message_id,
            expiration,
            payload,
        } = message;

        let tunnel_data = EncryptedTunnelData::parse(&payload)
            .ok_or(Error::Tunnel(TunnelError::InvalidMessage))?;

        self.tunnels
            .get_mut(&tunnel_data.tunnel_id())
            .ok_or(Error::Tunnel(TunnelError::TunnelDoesntExist(
                tunnel_data.tunnel_id(),
            )))?
            .handle_tunnel_data(tunnel_data)
    }

    /// Handle tunnel gateway message.
    pub fn handle_tunnel_gateway(
        &mut self,
        message: &TunnelGatewayMessage,
    ) -> crate::Result<(RouterId, Vec<u8>)> {
        self.tunnels
            .get_mut(message.tunnel_id())
            .ok_or(Error::Tunnel(TunnelError::TunnelDoesntExist(
                *message.tunnel_id(),
            )))?
            .handle_tunnel_gateway(&message)
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
                TunnelBuildParameters,
            },
            tests::make_router,
        },
    };

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
