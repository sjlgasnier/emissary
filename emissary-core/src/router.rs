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
    error::Error,
    i2cp::I2cpServer,
    netdb::NetDb,
    primitives::{RouterInfo, TransportKind},
    profile::ProfileStorage,
    runtime::{MetricType, Runtime},
    sam::SamServer,
    subsystem::SubsystemKind,
    transports::TransportManager,
    tunnel::{TunnelManager, TunnelManagerHandle},
    Config, I2cpConfig, SamConfig,
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

/// Default network ID.
const NET_ID: u8 = 2u8;

#[derive(Debug)]
pub enum RouterEvent {}

/// Router.
pub struct Router<R: Runtime> {
    /// Transport manager
    ///
    /// Polls both NTCP2 and SSU2 transports.
    transport_manager: TransportManager<R>,

    /// Local router info.
    local_router_info: RouterInfo,

    /// Handle to [`TunnelManager`].
    _tunnel_manager_handle: TunnelManagerHandle,
}

impl<R: Runtime> Router<R> {
    /// Create new [`Router`].
    pub async fn new(runtime: R, config: Config) -> crate::Result<(Self, Vec<u8>)> {
        let now = R::time_since_epoch().as_millis() as u64;
        let local_key = StaticPrivateKey::from(config.static_key.clone());
        let test = config.signing_key.clone();
        let local_signing_key = SigningPrivateKey::new(&test).unwrap();
        let ntcp2_config = match &config.ntcp2_config {
            None => {
                tracing::error!(
                    target: LOG_TARGET,
                    "no transport enabled, cannot start router",
                );
                return Err(Error::InvalidData);
            }
            Some(config) => config.clone(),
        };
        let i2cp_config = config.i2cp_config.clone();
        let sam_config = config.samv3_config.clone();
        let exploratory_config = config.exploratory.clone();
        let floodfill = config.floodfill;
        let net_id = config.net_id.unwrap_or(NET_ID);
        let profile_storage = ProfileStorage::<R>::new(&config.routers, &config.profiles);
        let local_router_info = RouterInfo::new(now, config);
        let serialized_router_info = local_router_info.serialize(&local_signing_key);
        let local_router_id = local_router_info.identity.id();

        let local_test = local_key.public().to_vec();
        let ntcp_test = StaticPrivateKey::from(ntcp2_config.key.clone()).public().to_vec();

        tracing::info!(
            target: LOG_TARGET,
            local_router_hash = ?base64_encode(local_router_info.identity.hash()),
            ?net_id,
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
            profile_storage.clone(),
            metrics_handle.clone(),
        );

        // initialize and start tunnel manager
        //
        // acquire handle to exploratory tunnel pool which is given to `NetDb`
        let (tunnel_manager_handle, exploratory_pool_handle, netdb_msg_rx) = {
            let transport_service = transport_manager.register_subsystem(SubsystemKind::Tunnel);
            let (tunnel_manager, tunnel_manager_handle, tunnel_pool_handle, netdb_msg_rx) =
                TunnelManager::<R>::new(
                    transport_service,
                    local_router_info.clone(),
                    local_key,
                    metrics_handle.clone(),
                    profile_storage.clone(),
                    exploratory_config.into(),
                );

            R::spawn(tunnel_manager);

            (tunnel_manager_handle, tunnel_pool_handle, netdb_msg_rx)
        };

        // initialize and start netdb
        let netdb_handle = {
            let transport_service = transport_manager.register_subsystem(SubsystemKind::NetDb);
            let (netdb, netdb_handle) = NetDb::<R>::new(
                local_router_id,
                floodfill,
                transport_service,
                profile_storage.clone(),
                metrics_handle.clone(),
                exploratory_pool_handle,
                net_id,
                netdb_msg_rx,
            );

            R::spawn(netdb);

            netdb_handle
        };

        // initialize i2cp server if it was enabled
        if let Some(I2cpConfig { port }) = i2cp_config {
            let i2cp_server =
                I2cpServer::<R>::new(port, netdb_handle.clone(), tunnel_manager_handle.clone())
                    .await?;

            R::spawn(i2cp_server);
        }

        if let Some(SamConfig {
            tcp_port,
            udp_port,
            host,
        }) = sam_config
        {
            let sam_server = SamServer::<R>::new(
                tcp_port,
                udp_port,
                host,
                netdb_handle.clone(),
                tunnel_manager_handle.clone(),
                metrics_handle,
            )
            .await?;

            R::spawn(sam_server)
        }

        // initialize and start ntcp2
        transport_manager.register_transport(TransportKind::Ntcp2, ntcp2_config).await?;

        Ok((
            Self {
                local_router_info,
                transport_manager,
                _tunnel_manager_handle: tunnel_manager_handle,
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
