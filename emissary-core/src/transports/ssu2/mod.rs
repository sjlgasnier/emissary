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

#![allow(unused)]

use crate::{
    config::Ssu2Config,
    crypto::SigningPrivateKey,
    error::{ConnectionError, Error},
    primitives::{RouterAddress, RouterId, RouterInfo},
    profile::ProfileStorage,
    runtime::{MetricType, Runtime, UdpSocket},
    subsystem::SubsystemHandle,
    transports::{Transport, TransportEvent},
};

use futures::Stream;

use core::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

mod socket;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2";

/// SSU2 context.
pub struct Ssu2Context<R: Runtime> {
    /// SSU configuration.
    config: Ssu2Config,

    /// SSU listener.
    socket: R::UdpSocket,

    /// Socket address.
    socket_address: SocketAddr,
}

/// SSU2 transport.
pub struct Ssu2Transport<R: Runtime> {
    /// Metrics handle.
    metrics: R::MetricsHandle,
}

impl<R: Runtime> Ssu2Transport<R> {
    /// Create new [`Ssu2Transport`].
    pub fn new(
        context: Ssu2Context<R>,
        allow_local: bool,
        _local_signing_key: SigningPrivateKey,
        _local_router_info: RouterInfo,
        _subsystem_handle: SubsystemHandle,
        _profile_storage: ProfileStorage<R>,
        metrics: R::MetricsHandle,
    ) -> Self {
        let Ssu2Context { socket_address, .. } = context;

        tracing::info!(
            target: LOG_TARGET,
            listen_address = ?socket_address,
            ?allow_local,
            "starting ssu2",
        );

        Self { metrics }
    }

    /// Collect `Ssu2Transport`-related metric counters, gauges and histograms.
    pub fn metrics(metrics: Vec<MetricType>) -> Vec<MetricType> {
        metrics
    }

    /// Initialize [`SsU2Transport`].
    ///
    /// If SSU2 has been enabled, create a router address using the configuration that was provided
    /// and bind a TCP listener to the port that was specified.
    ///
    /// Returns a [`RouterAddress`] of the transport and an [`SsU2Context`] that needs to be passed
    /// to [`SsU2Transport::new()`] when constructing the transport.
    pub async fn initialize(
        _config: Option<Ssu2Config>,
    ) -> crate::Result<(Option<Ssu2Context<R>>, Option<RouterAddress>)> {
        Ok((None, None))
    }
}

impl<R: Runtime> Transport for Ssu2Transport<R> {
    fn connect(&mut self, _router: RouterInfo) {}
    fn accept(&mut self, _router_id: &RouterId) {}
    fn reject(&mut self, _router_id: &RouterId) {}
}

impl<R: Runtime> Stream for Ssu2Transport<R> {
    type Item = TransportEvent;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Pending
    }
}
