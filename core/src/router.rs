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
    crypto::{base64_encode, SigningPrivateKey, StaticPrivateKey},
    netdb::NetDb,
    primitives::{RouterInfo, TransportKind},
    router_storage::RouterStorage,
    runtime::{MetricType, Runtime},
    subsystem::SubsystemKind,
    transports::TransportManager,
    tunnel::TunnelManager,
    Config,
};

use futures::{FutureExt, Stream, StreamExt};
use hashbrown::HashMap;
use thingbuf::mpsc;

use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::router";

#[derive(Debug)]
pub enum RouterEvent {}

/// Router.
pub struct Router<R: Runtime> {
    /// Runtime used by the router.
    runtime: R,

    /// Transport manager
    ///
    /// Polls both NTCP2 and SSU2 transports.
    transport_manager: TransportManager<R>,

    /// Local router info.
    local_router_info: RouterInfo,
}

impl<R: Runtime> Router<R> {
    /// Create new [`Router`].
    pub async fn new(runtime: R, config: Config) -> crate::Result<(Self, Vec<u8>)> {
        let now = R::time_since_epoch().as_millis() as u64;
        let local_key = StaticPrivateKey::from(config.static_key.clone());
        let test = config.signing_key.clone();
        let local_signing_key = SigningPrivateKey::new(&test).unwrap();
        let ntcp2_config = config.ntcp2_config.clone();
        let router_storage = RouterStorage::new(&config.routers);
        let local_router_info = RouterInfo::new(now, config);
        let serialized_router_info = local_router_info.serialize(&local_signing_key);
        let local_router_id = local_router_info.identity().id();

        let local_test = local_key.public().to_vec();
        let ntcp_test = StaticPrivateKey::from(ntcp2_config.as_ref().unwrap().key.clone())
            .public()
            .to_vec();

        tracing::info!(
            target: LOG_TARGET,
            local_router_hash = ?base64_encode(local_router_info.identity().hash()),
            "start emissary",
        );

        // collect metrics from all subsystems, register them and acquire metrics handle
        let metrics_handle = {
            let metrics = TransportManager::<R>::metrics(Vec::new());
            let metrics = TunnelManager::<R>::metrics(metrics);
            let metrics = NetDb::<R>::metrics(metrics);

            R::register_metrics(metrics)
        };

        // create transport manager and initialize & start enabled transports
        //
        // note: order of initialization is important
        let mut transport_manager = TransportManager::new(
            runtime.clone(),
            local_key.clone(),
            local_signing_key,
            local_router_info.clone(), // TODO: zzz
            router_storage,
            metrics_handle.clone(),
        );

        // initialize and start netdb
        {
            let transport_service = transport_manager.register_subsystem(SubsystemKind::NetDb);
            let netdb = NetDb::<R>::new(transport_service, metrics_handle.clone());

            R::spawn(netdb);
        }

        // initialize and start tunnel manager
        {
            let transport_service = transport_manager.register_subsystem(SubsystemKind::Tunnel);
            let tunnel_manager = TunnelManager::<R>::new(
                transport_service,
                local_key,
                local_router_info.identity().hash()[..16].to_vec(),
                local_router_id,
                metrics_handle,
            );

            R::spawn(tunnel_manager);
        }

        // initialize and start ntcp2
        transport_manager
            .register_transport(TransportKind::Ntcp2, ntcp2_config.expect("to exist"))
            .await?;

        Ok((
            Self {
                runtime,
                local_router_info,
                transport_manager,
            },
            serialized_router_info,
        ))
    }
}

impl<R: Runtime> Future for Router<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.transport_manager.poll_unpin(cx)
    }
}
