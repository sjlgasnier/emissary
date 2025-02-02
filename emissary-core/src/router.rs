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
    config::{Config, I2cpConfig, MetricsConfig, SamConfig},
    crypto::{SigningPrivateKey, StaticPrivateKey},
    error::Error,
    i2cp::I2cpServer,
    netdb::NetDb,
    primitives::RouterInfo,
    profile::ProfileStorage,
    runtime::Runtime,
    sam::SamServer,
    shutdown::ShutdownContext,
    subsystem::SubsystemKind,
    transport::{Ntcp2Transport, Ssu2Transport, TransportManager, TransportManagerBuilder},
    tunnel::{TunnelManager, TunnelManagerHandle},
};

use bytes::Bytes;
use futures::{FutureExt, Stream};
use rand_core::RngCore;

use alloc::{string::ToString, vec::Vec};
use core::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::router";

/// Default network ID.
const NET_ID: u8 = 2u8;

/// How many times [`Router::shutdown()`] needs to be called until the router is shutdown
/// immediately, cancelling graceful shutdown.
const IMMEDIATE_SHUTDOWN_COUNT: usize = 2usize;

/// Protocol address information.
#[derive(Debug, Default, Copy, Clone)]
pub struct ProtocolAddressInfo {
    /// Socket address of the SAMv3 TCP listener.
    pub sam_tcp: Option<SocketAddr>,

    /// Socket address of the SAMv3 UDP socket.
    pub sam_udp: Option<SocketAddr>,
}

/// Events emitted by [`Router`].
#[derive(Debug)]
pub enum RouterEvent {
    /// Router has been shut down.
    Shutdown,
}

/// Router.
pub struct Router<R: Runtime> {
    /// Shutdown context.
    shutdown_context: ShutdownContext<R>,

    /// Number of times shutdown has been requested.
    shutdown_count: usize,

    /// Transport manager
    ///
    /// Polls both NTCP2 and SSU2 transports.
    transport_manager: TransportManager<R>,

    /// Protocol address information.
    address_info: ProtocolAddressInfo,

    /// Handle to [`TunnelManager`].
    _tunnel_manager_handle: TunnelManagerHandle,
}

impl<R: Runtime> Router<R> {
    /// Create new [`Router`].
    pub async fn new(mut config: Config) -> crate::Result<(Self, Vec<u8>)> {
        // attempt to initialize the ntcp2 transport from provided config
        //
        // this is done prior to constructing local router info in case ntcp2 config contained an
        // unspecified port, meaning the actual socket address of the transport is available only
        // after the listener has been created
        let (ntcp2_context, ntcp2_address) =
            Ntcp2Transport::<R>::initialize(config.ntcp2.take()).await?;

        // attempt to initialize the ssu2 transport from provided config
        let (ssu2_context, ssu2_address) =
            Ssu2Transport::<R>::initialize(config.ssu2.take()).await?;

        if ntcp2_context.is_none() && ssu2_context.is_none() {
            tracing::warn!(
                target: LOG_TARGET,
                "cannot start router, no active transport protocol",
            );
            return Err(Error::Custom("no transport".to_string()));
        }

        // create static/signing keypairs for the router
        //
        // if caller didn't supply keys, generate transient keypair
        let local_static_key = StaticPrivateKey::from(config.static_key.unwrap_or_else(|| {
            let mut key = [0u8; 32];
            R::rng().fill_bytes(&mut key);
            key
        }));
        let local_signing_key = SigningPrivateKey::from(config.signing_key.unwrap_or_else(|| {
            let mut key = [0u8; 32];
            R::rng().fill_bytes(&mut key);
            key
        }));

        let local_router_info = RouterInfo::new::<R>(
            &config,
            ntcp2_address,
            ssu2_address,
            &local_static_key,
            &local_signing_key,
        );
        let Config {
            i2cp_config,
            samv3_config,
            floodfill,
            net_id,
            exploratory,
            insecure_tunnels,
            routers,
            profiles,
            allow_local,
            metrics:
                MetricsConfig {
                    disable_metrics,
                    metrics_server_port,
                },
            ..
        } = config;

        let profile_storage = ProfileStorage::<R>::new(&routers, &profiles);
        let serialized_router_info = local_router_info.serialize(&local_signing_key);
        let local_router_id = local_router_info.identity.id();
        let mut address_info = ProtocolAddressInfo::default();

        // create router shutdown context and allocate handle `TransitTunnelManager`
        //
        // `TransitTunnelManager` can take up to 10 minutes to shut down, depending on the age
        // of the newest transit tunnel
        let mut shutdown_context = ShutdownContext::<R>::new();
        let transit_shutdown_handle = shutdown_context.handle();

        tracing::info!(
            target: LOG_TARGET,
            ?local_router_id,
            net_id = ?net_id.unwrap_or(NET_ID),
            "starting emissary",
        );

        // collect metrics from all subsystems, register them and acquire metrics handle
        //
        // if metrics are disabled, call `R::register_metrics()` with an empty vector which makes
        // the runtime not start the metrics server and return a handle which doesn't update any
        // metirics
        let metrics_handle = match disable_metrics {
            true => R::register_metrics(Vec::new(), None),
            false => {
                let metrics = TransportManager::<R>::metrics(Vec::new());
                let metrics = TunnelManager::<R>::metrics(metrics);
                let metrics = NetDb::<R>::metrics(metrics);

                R::register_metrics(metrics, metrics_server_port)
            }
        };

        // create transport manager builder and initialize & start enabled transports
        //
        // note: order of initialization is important
        let mut transport_manager_builder = TransportManagerBuilder::new(
            local_signing_key,
            local_router_info.clone(),
            profile_storage.clone(),
            metrics_handle.clone(),
            allow_local,
        );

        // initialize and start tunnel manager
        //
        // acquire handle to exploratory tunnel pool which is given to `NetDb`
        let (tunnel_manager_handle, exploratory_pool_handle, netdb_msg_rx) = {
            let transport_service =
                transport_manager_builder.register_subsystem(SubsystemKind::Tunnel);
            let (tunnel_manager, tunnel_manager_handle, tunnel_pool_handle, netdb_msg_rx) =
                TunnelManager::<R>::new(
                    transport_service,
                    local_router_info.clone(),
                    local_static_key.clone(),
                    metrics_handle.clone(),
                    profile_storage.clone(),
                    exploratory.into(),
                    insecure_tunnels,
                    transit_shutdown_handle,
                );

            R::spawn(tunnel_manager);

            (tunnel_manager_handle, tunnel_pool_handle, netdb_msg_rx)
        };

        // initialize and start netdb
        let netdb_handle = {
            let transport_service =
                transport_manager_builder.register_subsystem(SubsystemKind::NetDb);
            let (netdb, netdb_handle) = NetDb::<R>::new(
                local_router_id,
                floodfill,
                transport_service,
                profile_storage.clone(),
                metrics_handle.clone(),
                exploratory_pool_handle,
                net_id.unwrap_or(NET_ID),
                netdb_msg_rx,
                Bytes::from(serialized_router_info.clone()),
                local_static_key,
            );

            R::spawn(netdb);

            netdb_handle
        };

        // pass netdb handle to transport manager builder
        //
        // transport manager uses netdb to query remote router infos and periodically publish local
        // router info when, e.g., it goes stale or a new external address is discovered
        transport_manager_builder.register_netdb_handle(netdb_handle.clone());

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
        }) = samv3_config
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

            address_info.sam_tcp = sam_server.tcp_local_address();
            address_info.sam_udp = sam_server.udp_local_address();

            R::spawn(sam_server)
        }

        if let Some(context) = ntcp2_context {
            transport_manager_builder.register_ntcp2(context);
        }

        if let Some(context) = ssu2_context {
            transport_manager_builder.register_ssu2(context);
        }

        Ok((
            Self {
                address_info,
                shutdown_context,
                shutdown_count: 0usize,
                transport_manager: transport_manager_builder.build(),
                _tunnel_manager_handle: tunnel_manager_handle,
            },
            serialized_router_info,
        ))
    }

    /// Shut down the router.
    ///
    /// The first request to shutdown the router starts a graceful shutdown and TOOD
    pub fn shutdown(&mut self) {
        self.shutdown_count += 1;

        if self.shutdown_count == 1 {
            tracing::info!(
                target: LOG_TARGET,
                "starting graceful shutdown",
            );
            self.shutdown_context.shutdown();
        } else {
            tracing::info!(
                target: LOG_TARGET,
                "shutting down router",
            );
        }
    }

    /// Get reference to [`ProtocolAddressInfo`].
    pub fn protocol_address_info(&self) -> &ProtocolAddressInfo {
        &self.address_info
    }
}

impl<R: Runtime> Stream for Router<R> {
    type Item = RouterEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.shutdown_count >= IMMEDIATE_SHUTDOWN_COUNT {
            return Poll::Ready(Some(RouterEvent::Shutdown));
        }

        if self.shutdown_context.poll_unpin(cx).is_ready() {
            return Poll::Ready(Some(RouterEvent::Shutdown));
        }

        match self.transport_manager.poll_unpin(cx) {
            Poll::Pending => {}
            Poll::Ready(()) => return Poll::Ready(None),
        }

        Poll::Pending
    }
}
