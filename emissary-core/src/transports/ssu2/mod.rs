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
    crypto::{SigningPrivateKey, StaticPrivateKey},
    error::{ConnectionError, Error},
    primitives::{RouterAddress, RouterId, RouterInfo},
    profile::ProfileStorage,
    runtime::{MetricType, Runtime, UdpSocket},
    subsystem::SubsystemHandle,
    transports::{
        ssu2::socket::{Ssu2SessionEvent, Ssu2Socket},
        Transport, TransportEvent,
    },
};

use futures::Stream;
use thingbuf::mpsc::{channel, Receiver, Sender};

use core::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

mod message;
mod socket;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2";

/// Size for the socket event channel.
const CHANNEL_SIZE: usize = 2048usize;

/// SSU2 context.
pub struct Ssu2Context<R: Runtime> {
    /// SSU configuration.
    config: Ssu2Config,

    /// UDP socket.
    socket: R::UdpSocket,

    /// Socket address.
    socket_address: SocketAddr,
}

/// SSU2 transport.
pub struct Ssu2Transport<R: Runtime> {
    /// Metrics handle.
    metrics: R::MetricsHandle,

    /// RX channel for receiving socket events.
    socket_rx: Receiver<Ssu2SessionEvent>,
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
        let Ssu2Context {
            socket_address,
            socket,
            config,
        } = context;

        tracing::info!(
            target: LOG_TARGET,
            listen_address = ?socket_address,
            ?allow_local,
            "starting ssu2",
        );

        let (socket_tx, socket_rx) = channel(CHANNEL_SIZE);

        // spawn ssu2 socket task in the background
        //
        // it's responsible for what?
        R::spawn(Ssu2Socket::<R>::new(
            socket,
            config.static_key,
            config.intro_key,
            socket_tx,
        ));

        Self { metrics, socket_rx }
    }

    /// Collect `Ssu2Transport`-related metric counters, gauges and histograms.
    pub fn metrics(metrics: Vec<MetricType>) -> Vec<MetricType> {
        metrics
    }

    /// Initialize [`SsU2Transport`].
    ///
    /// If SSU2 has been enabled, create a router address using the configuration that was provided
    /// and bind a UDP socket to the port that was specified.
    ///
    /// Returns a [`RouterAddress`] of the transport and an [`SsU2Context`] that needs to be passed
    /// to [`SsU2Transport::new()`] when constructing the transport.
    pub async fn initialize(
        config: Option<Ssu2Config>,
    ) -> crate::Result<(Option<Ssu2Context<R>>, Option<RouterAddress>)> {
        let Some(config) = config else {
            return Ok((None, None));
        };

        let socket =
            R::UdpSocket::bind(format!("0.0.0.0:{}", config.port).parse().expect("to succeed"))
                .await
                .ok_or(Error::Connection(ConnectionError::BindFailure))?;

        let socket_address = socket.local_address().ok_or_else(|| {
            tracing::warn!(
                target: LOG_TARGET,
                "failed to get local address of the ntcp2 listener",
            );

            Error::Connection(ConnectionError::BindFailure)
        })?;

        let address = match (config.publish, config.host) {
            (true, Some(host)) => RouterAddress::new_published_ssu2(
                config.static_key,
                config.intro_key,
                socket_address.port(),
                host,
            ),
            (true, None) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    "ntcp2 requested to be published but no host provided",
                );
                RouterAddress::new_unpublished_ssu2(
                    config.static_key,
                    config.intro_key,
                    socket_address.port(),
                )
            }
            (_, _) => RouterAddress::new_unpublished_ssu2(
                config.static_key,
                config.intro_key,
                socket_address.port(),
            ),
        };

        Ok((
            Some(Ssu2Context {
                config,
                socket,
                socket_address,
            }),
            Some(address),
        ))
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
