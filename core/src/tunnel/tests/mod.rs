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
    crypto::{base64_encode, EphemeralPublicKey, StaticPrivateKey, StaticPublicKey},
    i2np::{tunnel::build::short, EncryptedTunnelData, RawI2npMessage, TunnelGatewayMessage},
    primitives::{MessageId, RouterId, TunnelId},
    runtime::{mock::MockRuntime, Runtime},
    tunnel::{
        hop::{
            inbound::InboundTunnel, outbound::OutboundTunnel, pending::PendingTunnel,
            TunnelBuildParameters,
        },
        new_noise::NoiseContext,
        transit::TransitTunnelManager,
    },
};

use bytes::Bytes;
use rand_core::RngCore;

/// Make new router.
pub fn make_router() -> (Bytes, StaticPublicKey, NoiseContext) {
    let mut key_bytes = vec![0u8; 32];
    let mut router_hash = vec![0u8; 32];

    MockRuntime::rng().fill_bytes(&mut key_bytes);
    MockRuntime::rng().fill_bytes(&mut router_hash);

    let sk = StaticPrivateKey::from(key_bytes);
    let pk = sk.public();
    let router_hash = Bytes::from(router_hash);

    (router_hash.clone(), pk, NoiseContext::new(sk, router_hash))
}

pub struct TestTransitTunnelManager {
    /// Transit tunnel manager.
    manager: TransitTunnelManager<MockRuntime>,

    /// Router hash.
    router_hash: Bytes,

    /// Static public key.
    public_key: StaticPublicKey,

    /// Router ID.
    router: RouterId,
}

impl TestTransitTunnelManager {
    pub fn new() -> Self {
        let (router_hash, public_key, noise) = make_router();

        Self {
            router_hash: router_hash.clone(),
            router: RouterId::from(router_hash),
            public_key,
            manager: TransitTunnelManager::<MockRuntime>::new(
                noise,
                MockRuntime::register_metrics(vec![]),
            ),
        }
    }

    /// Get hash of the router.
    pub fn router_hash(&self) -> Bytes {
        self.router_hash.clone()
    }

    /// Get public key of the router.
    pub fn public_key(&self) -> StaticPublicKey {
        self.public_key.clone()
    }

    /// Get ID of the router.
    pub fn router(&self) -> RouterId {
        self.router.clone()
    }

    /// Handle short tunnel build.
    pub fn handle_short_tunnel_build(
        &mut self,
        message: RawI2npMessage,
    ) -> crate::Result<(RouterId, Vec<u8>)> {
        self.manager.handle_short_tunnel_build(message)
    }

    /// Handle tunnel data.
    pub fn handle_tunnel_data(
        &mut self,
        message: &EncryptedTunnelData,
    ) -> crate::Result<(RouterId, Vec<u8>)> {
        self.manager.handle_tunnel_data(message)
    }

    pub fn handle_tunnel_gateway(
        &mut self,
        message: &TunnelGatewayMessage,
    ) -> crate::Result<(RouterId, Vec<u8>)> {
        self.manager.handle_tunnel_gateway(message)
    }
}

/// Build outbound tunnel.
pub fn build_outbound_tunnel(
    num_hops: usize,
) -> (Bytes, OutboundTunnel, Vec<TestTransitTunnelManager>) {
    let (hops, mut transit_managers): (
        Vec<(Bytes, StaticPublicKey)>,
        Vec<TestTransitTunnelManager>,
    ) = (0..num_hops)
        .map(|manager| {
            let manager = TestTransitTunnelManager::new();

            (
                (manager.router_hash.clone(), manager.public_key.clone()),
                manager,
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
            our_hash: local_hash.clone(),
        })
        .unwrap();

    let mut message = RawI2npMessage::parse::<true>(&message).unwrap();
    let message = hops.iter().zip(transit_managers.iter_mut()).fold(
        message,
        |acc, ((router_hash, _), transit_manager)| {
            let (_, message) = transit_manager.handle_short_tunnel_build(acc).unwrap();
            RawI2npMessage::parse::<true>(&message).unwrap()
        },
    );
    let TunnelGatewayMessage {
        tunnel_id: recv_tunnel_id,
        payload,
    } = TunnelGatewayMessage::parse(&message.payload).unwrap();

    let message = RawI2npMessage::parse::<false>(&payload).unwrap();
    let tunnel = pending_tunnel.try_build_tunnel(message).unwrap();

    (local_hash, tunnel, transit_managers)
}

/// Build inbound tunnel.
pub fn build_inbound_tunnel(
    num_hops: usize,
) -> (Bytes, InboundTunnel, Vec<TestTransitTunnelManager>) {
    let (hops, mut transit_managers): (
        Vec<(Bytes, StaticPublicKey)>,
        Vec<TestTransitTunnelManager>,
    ) = (0..num_hops)
        .map(|manager| {
            let manager = TestTransitTunnelManager::new();

            (
                (manager.router_hash.clone(), manager.public_key.clone()),
                manager,
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
            our_hash: local_hash.clone(),
        })
        .unwrap();

    let mut message = RawI2npMessage::parse::<true>(&message).unwrap();

    assert_eq!(message.message_id, message_id.into());
    assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));
    assert_eq!(message.payload[0], 4u8);
    assert_eq!(message.payload[1..].len() % 218, 0);

    let message = hops.iter().zip(transit_managers.iter_mut()).fold(
        message,
        |acc, ((router_hash, _), transit_manager)| {
            let (_, message) = transit_manager.handle_short_tunnel_build(acc).unwrap();
            RawI2npMessage::parse::<true>(&message).unwrap()
        },
    );

    let tunnel = pending_tunnel.try_build_tunnel(message).unwrap();

    (local_hash, tunnel, transit_managers)
}
