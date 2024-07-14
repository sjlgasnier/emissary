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
    runtime::Runtime,
    transports::{SubsystemKind, TransportManager},
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
}

impl<R: Runtime> Router<R> {
    /// Create new [`Router`].
    pub async fn new(runtime: R, config: Config, router: Vec<u8>) -> crate::Result<Self> {
        // TODO: ugly
        let router = RouterInfo::from_bytes(router).unwrap();
        let now = R::time_since_epoch().as_millis() as u64;
        let local_key = StaticPrivateKey::from(config.static_key.clone());
        let test = config.signing_key.clone();
        let local_signing_key = SigningPrivateKey::new(&test).unwrap();
        let local_router_info = RouterInfo::new(now, config);

        tracing::info!(
            target: LOG_TARGET,
            router_hash = ?base64_encode(local_router_info.identity().hash()),
            truncated_router_hash = ?base64_encode(&local_router_info.identity().hash()[..16]),
            "start emissary",
        );

        // create transport manager and initialize & start enabled transports
        //
        // note: order of initialization is important
        let mut transport_manager = TransportManager::new(
            runtime.clone(),
            local_key.clone(),
            local_signing_key,
            local_router_info,
        );

        // initialize and start netdb
        {
            let transport_service = transport_manager.register_subsystem(SubsystemKind::NetDb);
            let netdb = NetDb::new(transport_service);

            R::spawn(netdb);
        }

        // initialize and start tunnel manager
        {
            let transport_service = transport_manager.register_subsystem(SubsystemKind::Tunnel);
            let tunnel_manager = TunnelManager::new(transport_service, local_key);

            R::spawn(tunnel_manager);
        }

        // initialize and start ntcp2
        transport_manager.register_transport(TransportKind::Ntcp2).await?;

        Ok(Self {
            runtime,
            transport_manager,
        })
    }
}

impl<R: Runtime> Future for Router<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.transport_manager.poll_unpin(cx)
    }
}
