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
    crypto::{StaticPrivateKey, StaticPublicKey},
    i2np::{tunnel::gateway, Message, MessageType},
    primitives::{Capabilities, MessageId, RouterId, RouterInfo, Str, TunnelId},
    runtime::{mock::MockRuntime, Runtime},
    shutdown::ShutdownContext,
    tunnel::{
        garlic::DeliveryInstructions,
        hop::{
            inbound::InboundTunnel, outbound::OutboundTunnel, pending::PendingTunnel, ReceiverKind,
            TunnelBuildParameters, TunnelInfo,
        },
        noise::NoiseContext,
        pool::TunnelPoolBuildParameters,
        routing_table::{RoutingKind, RoutingTable},
        transit::TransitTunnelManager,
    },
};

use bytes::Bytes;
use futures::FutureExt;
use rand_core::RngCore;
use thingbuf::mpsc::{channel, Receiver};

use core::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use super::garlic::GarlicHandler;

/// Make new router.
pub fn make_router(fast: bool) -> (Bytes, StaticPublicKey, NoiseContext, RouterInfo) {
    let mut static_key_bytes = vec![0u8; 32];
    let mut signing_key_bytes = vec![0u8; 32];

    MockRuntime::rng().fill_bytes(&mut static_key_bytes);
    MockRuntime::rng().fill_bytes(&mut signing_key_bytes);

    let sk = StaticPrivateKey::from_bytes(&static_key_bytes).unwrap();
    let pk = sk.public();

    let mut router_info = RouterInfo::from_keys::<MockRuntime>(static_key_bytes, signing_key_bytes);
    if fast {
        router_info.capabilities = Capabilities::parse(&Str::from("XR")).expect("to succeed");
    }

    let router_hash: Vec<u8> = router_info.identity.id().into();
    let router_hash = Bytes::from(router_hash);

    (
        router_hash.clone(),
        pk,
        NoiseContext::new(sk.clone(), router_hash),
        router_info,
    )
}

/// [`TransitTunnelManager`] for testing.
pub struct TestTransitTunnelManager {
    /// Garlic handler.
    garlic: GarlicHandler<MockRuntime>,

    /// Transit tunnel manager.
    manager: TransitTunnelManager<MockRuntime>,

    /// RX channel for receiving messages from local tunnels.
    message_rx: Receiver<RoutingKind>,

    /// Static public key.
    public_key: StaticPublicKey,

    /// Router ID.
    router: RouterId,

    /// Router hash.
    router_hash: Bytes,

    /// Router info.
    router_info: RouterInfo,

    /// Routing table.
    routing_table: RoutingTable,

    /// Shutdown context.
    _shutdown_ctx: ShutdownContext<MockRuntime>,
}

impl fmt::Debug for TestTransitTunnelManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestTransitTunnelManager")
            .field("router", &self.router)
            .finish_non_exhaustive()
    }
}

impl TestTransitTunnelManager {
    pub fn new(fast: bool) -> Self {
        let (router_hash, public_key, noise, router_info) = make_router(fast);
        let (transit_tx, transit_rx) = channel(64);
        let (message_tx, message_rx) = channel(64);
        let routing_table =
            RoutingTable::new(RouterId::from(&router_hash), message_tx, transit_tx.clone());
        let mut _shutdown_ctx = ShutdownContext::<MockRuntime>::new();

        Self {
            garlic: GarlicHandler::new(noise.clone(), MockRuntime::register_metrics(vec![], None)),
            manager: TransitTunnelManager::<MockRuntime>::new(
                noise,
                routing_table.clone(),
                transit_rx,
                MockRuntime::register_metrics(vec![], None),
                _shutdown_ctx.handle(),
            ),
            message_rx,
            public_key,
            router_hash: router_hash.clone(),
            router_info,
            router: RouterId::from(router_hash),
            routing_table,
            _shutdown_ctx,
        }
    }

    /// Get copy of [`RouterInfo`].
    pub fn router_info(&self) -> RouterInfo {
        self.router_info.clone()
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

    /// Get mutable reference to [`GarlicHandler`].
    pub fn garlic(&mut self) -> &mut GarlicHandler<MockRuntime> {
        &mut self.garlic
    }

    /// Handle short tunnel build.
    pub fn handle_short_tunnel_build(
        &mut self,
        message: Message,
    ) -> crate::Result<(RouterId, Vec<u8>)> {
        self.manager.handle_short_tunnel_build(message)
    }

    /// Get mutable reference to the message RX channel.
    pub fn message_rx(&mut self) -> &mut Receiver<RoutingKind> {
        &mut self.message_rx
    }

    /// Get reference to [`RoutingTable`].
    pub fn routing_table(&self) -> &RoutingTable {
        &self.routing_table
    }
}

impl Future for TestTransitTunnelManager {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.manager.poll_unpin(cx)
    }
}

/// Build outbound tunnel.
pub fn build_outbound_tunnel(
    fast: bool,
    num_hops: usize,
) -> (
    Bytes,
    OutboundTunnel<MockRuntime>,
    Vec<TestTransitTunnelManager>,
) {
    let (hops, mut transit_managers): (
        Vec<(Bytes, StaticPublicKey)>,
        Vec<TestTransitTunnelManager>,
    ) = (0..num_hops)
        .map(|i| {
            let manager = TestTransitTunnelManager::new(if i % 2 == 0 { true } else { false });

            (
                (manager.router_hash.clone(), manager.public_key.clone()),
                manager,
            )
        })
        .unzip();

    let (local_hash, _local_pk, local_noise, _router_info) = make_router(fast);
    let message_id = MessageId::from(MockRuntime::rng().next_u32());
    let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
    let gateway = TunnelId::from(MockRuntime::rng().next_u32());

    let (pending_tunnel, _next_router, message) =
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

    let message = hops.iter().zip(transit_managers.iter_mut()).fold(
        message,
        |acc, ((_, _), transit_manager)| {
            let (_, message) = transit_manager.handle_short_tunnel_build(acc).unwrap();
            Message::parse_short(&message).unwrap()
        },
    );
    let gateway::TunnelGateway { payload, .. } =
        gateway::TunnelGateway::parse(&message.payload).unwrap();

    let message = Message::parse_standard(&payload).unwrap();
    assert_eq!(message.message_type, MessageType::Garlic);
    let tunnel = pending_tunnel.try_build_tunnel::<MockRuntime>(message).unwrap();

    (local_hash, tunnel, transit_managers)
}

/// Build inbound tunnel.
pub fn build_inbound_tunnel(
    fast: bool,
    num_hops: usize,
) -> (Bytes, InboundTunnel, Vec<TestTransitTunnelManager>) {
    let (hops, mut transit_managers): (
        Vec<(Bytes, StaticPublicKey)>,
        Vec<TestTransitTunnelManager>,
    ) = (0..num_hops)
        .map(|i| {
            let manager = TestTransitTunnelManager::new(if i % 2 == 0 { true } else { false });

            (
                (manager.router_hash.clone(), manager.public_key.clone()),
                manager,
            )
        })
        .unzip();

    let (local_hash, _local_pk, local_noise, _router_info) = make_router(fast);
    let message_id = MessageId::from(MockRuntime::rng().next_u32());
    let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
    let (_tx, rx) = channel(64);
    let TunnelPoolBuildParameters {
        context_handle: handle,
        ..
    } = TunnelPoolBuildParameters::new(Default::default());

    let (pending_tunnel, next_router, message) =
        PendingTunnel::<InboundTunnel>::create_tunnel::<MockRuntime>(TunnelBuildParameters {
            hops: hops.clone(),
            noise: local_noise,
            message_id,
            tunnel_info: TunnelInfo::Inbound {
                tunnel_id,
                router_id: local_hash.clone(),
            },
            receiver: ReceiverKind::Inbound {
                message_rx: rx,
                handle,
            },
        })
        .unwrap();

    let message = match transit_managers[0].garlic().handle_message(message).unwrap().next() {
        Some(DeliveryInstructions::Local { message }) => message,
        _ => panic!("invalid delivery instructions"),
    };

    assert_eq!(message.message_id, message_id.into());
    assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));
    assert_eq!(message.message_type, MessageType::ShortTunnelBuild);
    assert_eq!(message.payload[1..].len() % 218, 0);

    let message = hops.iter().zip(transit_managers.iter_mut()).fold(
        message,
        |acc, ((_, _), transit_manager)| {
            let (_, message) = transit_manager.handle_short_tunnel_build(acc).unwrap();
            Message::parse_short(&message).unwrap()
        },
    );

    let tunnel = pending_tunnel.try_build_tunnel::<MockRuntime>(message).unwrap();

    (local_hash, tunnel, transit_managers)
}
