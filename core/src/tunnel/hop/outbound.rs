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
    crypto::aes::{cbc, ecb},
    i2np::{HopRole, MessageType, RawI2NpMessageBuilder, RawI2npMessage, TunnelDataBuilder},
    primitives::{RouterId, TunnelId},
    runtime::Runtime,
    tunnel::hop::{Tunnel, TunnelDirection, TunnelHop},
};

use rand_core::RngCore;

use alloc::{vec, vec::Vec};
use core::{iter, num::NonZeroUsize, time::Duration};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::obgw";

/// Outbound tunnel.
#[derive(Debug)]
pub struct OutboundTunnel {
    /// Tunnel ID.
    tunnel_id: TunnelId,

    /// Tunnel hops.
    hops: Vec<TunnelHop>,
}

impl OutboundTunnel {
    /// Create new [`OutboundTunnel`].
    pub fn new(tunnel_id: TunnelId, hops: Vec<TunnelHop>) -> Self {
        Self { tunnel_id, hops }
    }

    /// Send `message` to `router`
    pub fn send_to_router(&self, router: RouterId, message: Vec<u8>) -> (RouterId, Vec<u8>) {
        assert!(message.len() < 500, "fragmentation not supported");

        tracing::trace!(
            target: LOG_TARGET,
            tunnel = %self.tunnel_id,
            ?router,
            message_len = ?message.len(),
            "router delivery",
        );

        todo!();
    }

    /// Send `message` to tunnel identified by the (`router`, `gateway`) tuple.
    pub fn send_to_tunnel<R: Runtime>(
        &self,
        router: RouterId,
        gateway: TunnelId,
        message: Vec<u8>,
    ) -> (RouterId, Vec<u8>) {
        assert!(message.len() < 500, "fragmentation not supported");

        tracing::trace!(
            target: LOG_TARGET,
            tunnel = %self.tunnel_id,
            ?router,
            ?gateway,
            message_len = ?message.len(),
            "tunnel delivery",
        );

        // hop must exist since the tunnel is created by us
        let next_hop = self.hops.iter().next().expect("tunnel to exist");

        tracing::error!("next hop tunnel id = {}", next_hop.tunnel_id);

        let mut message = TunnelDataBuilder::new(next_hop.tunnel_id)
            .with_tunnel_delivery(router.into(), gateway, &message)
            .build::<R>();

        // iterative decrypt the tunnel data message and aes iv
        let (iv, ciphertext) = self.hops.iter().rev().fold(
            (message[4..20].to_vec(), message[20..].to_vec()),
            |(iv, message), hop| {
                let mut aes = ecb::Aes::new_decryptor(&hop.key_context.iv_key());
                let iv = aes.decrypt(&iv);

                let mut aes = cbc::Aes::new_decryptor(&hop.key_context.layer_key(), &iv);
                let ciphertext = aes.decrypt(message);

                let mut aes = ecb::Aes::new_decryptor(&hop.key_context.iv_key());
                let iv = aes.decrypt(iv);

                (iv, ciphertext)
            },
        );

        message[4..20].copy_from_slice(&iv);
        message[20..].copy_from_slice(&ciphertext);

        let message_id = R::rng().next_u32();
        tracing::error!("outer message id = {message_id}");

        let message = RawI2NpMessageBuilder::short()
            .with_message_type(MessageType::TunnelData)
            .with_message_id(message_id)
            .with_expiration((R::time_since_epoch() + Duration::from_secs(8)).as_secs())
            .with_payload(message)
            .serialize();

        (next_hop.router.clone(), message)
    }

    /// Send `message` to `router`
    pub fn send(&self, router: RouterId, message: Vec<u8>) -> (RouterId, Vec<u8>) {
        assert!(message.len() < 500, "fragmentation not supported");

        tracing::trace!(
            target: LOG_TARGET,
            tunnel = %self.tunnel_id,
            ?router,
            message_len = ?message.len(),
            "local delivery",
        );

        todo!();
    }
}

impl Tunnel for OutboundTunnel {
    fn new(tunnel_id: TunnelId, hops: Vec<TunnelHop>) -> Self {
        OutboundTunnel::new(tunnel_id, hops)
    }

    fn tunnel_id(&self) -> &TunnelId {
        &self.tunnel_id
    }

    fn hop_roles(num_hops: NonZeroUsize) -> impl Iterator<Item = HopRole> {
        match num_hops.get() == 1 {
            true => vec![HopRole::OutboundEndpoint].into_iter(),
            false => (0..num_hops.get() - 1)
                .map(|_| HopRole::Participant)
                .chain(iter::once(HopRole::OutboundEndpoint))
                .collect::<Vec<_>>()
                .into_iter(),
        }
    }

    fn direction() -> TunnelDirection {
        TunnelDirection::Outbound
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        i2np::{EncryptedTunnelData, TunnelGatewayMessage},
        runtime::mock::MockRuntime,
        tunnel::tests::{build_inbound_tunnel, build_outbound_tunnel},
    };
    use tracing_subscriber::prelude::*;

    #[test]
    fn send_tunnel_message() {
        let _ = tracing_subscriber::registry().with(tracing_subscriber::fmt::layer()).try_init();

        let (local_outbound_hash, mut outbound, mut outbound_transit) =
            build_outbound_tunnel(2usize);
        let (local_inbound_hash, mut inbound, mut inbound_transit) = build_inbound_tunnel(2usize);

        let (gateway_router, gateway_tunnel) = inbound.gateway();

        let (next_router, message) = outbound.send_to_tunnel::<MockRuntime>(
            gateway_router,
            gateway_tunnel,
            b"hello, world".to_vec(),
        );
        assert_eq!(outbound_transit[0].router(), next_router);

        // first outbound hop (participant)
        let message = RawI2npMessage::parse::<true>(&message).unwrap();
        let message = EncryptedTunnelData::parse(&message.payload).unwrap();
        let (next_router, message) = outbound_transit[0].handle_tunnel_data(&message).unwrap();
        assert_eq!(outbound_transit[1].router(), next_router);

        // second outbound hop (obep)
        let message = RawI2npMessage::parse::<true>(&message).unwrap();
        let message = EncryptedTunnelData::parse(&message.payload).unwrap();
        let (next_router, message) = outbound_transit[1].handle_tunnel_data(&message).unwrap();
        assert_eq!(inbound_transit[0].router(), next_router);

        // first inbound hop (ibgw)
        let Some(RawI2npMessage {
            message_type: MessageType::TunnelGateway,
            message_id,
            expiration,
            payload,
        }) = RawI2npMessage::parse::<true>(&message)
        else {
            panic!("invalid message");
        };

        let message = TunnelGatewayMessage::parse(&payload).unwrap();
        let (next_router, message) = inbound_transit[0].handle_tunnel_gateway(&message).unwrap();
        assert_eq!(inbound_transit[1].router(), next_router);

        // second inbound hop (participant)
        let message = RawI2npMessage::parse::<true>(&message).unwrap();
        let message = EncryptedTunnelData::parse(&message.payload).unwrap();
        let (next_router, message) = inbound_transit[1].handle_tunnel_data(&message).unwrap();
        assert_eq!(RouterId::from(local_inbound_hash), next_router);

        // inbound endpoint
        let Some(RawI2npMessage {
            message_type: MessageType::TunnelData,
            message_id,
            expiration,
            payload,
        }) = RawI2npMessage::parse::<true>(&message)
        else {
            panic!("invalid message");
        };

        let message = EncryptedTunnelData::parse(&payload).unwrap();
        let message = inbound.handle_tunnel_data(message).unwrap();
        assert_eq!(message, b"hello, world".to_vec());
    }
}
