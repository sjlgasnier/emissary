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
    transport::{
        ssu2::socket::{Ssu2SessionCommand, Ssu2Socket},
        Transport, TransportEvent,
    },
};

use futures::{Stream, StreamExt};
use thingbuf::mpsc::{channel, Receiver, Sender};

use core::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

mod message;
mod session;
mod socket;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2";

/// Size for the socket event/command channel.
const CHANNEL_SIZE: usize = 1024usize;

#[derive(Debug, Clone)]
pub struct Packet {
    /// Packet.
    pub pkt: Vec<u8>,

    /// Socket address of the remote router.
    pub address: SocketAddr,
}

impl Default for Packet {
    fn default() -> Self {
        Self {
            pkt: Default::default(),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        }
    }
}

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

    /// SSU2 server socket.
    socket: Ssu2Socket<R>,
}

impl<R: Runtime> Ssu2Transport<R> {
    /// Create new [`Ssu2Transport`].
    pub fn new(
        context: Ssu2Context<R>,
        allow_local: bool,
        local_signing_key: SigningPrivateKey,
        local_router_info: RouterInfo,
        subsystem_handle: SubsystemHandle,
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

        Self {
            socket: Ssu2Socket::<R>::new(
                socket,
                StaticPrivateKey::from(config.static_key),
                config.intro_key,
                subsystem_handle,
                local_router_info.serialize(&local_signing_key),
            ),
            metrics,
        }
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
    fn connect(&mut self, router_info: RouterInfo) {
        self.socket.connect(router_info);
    }

    fn accept(&mut self, router_id: &RouterId) {
        self.socket.accept(router_id);
    }

    fn reject(&mut self, router_id: &RouterId) {
        self.socket.reject(router_id);
    }
}

impl<R: Runtime> Stream for Ssu2Transport<R> {
    type Item = TransportEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.socket.poll_next_unpin(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;

    #[tokio::test]
    async fn connect_ssu2() {
        crate::util::init_logger();

        let (ctx1, address1) = Ssu2Transport::<MockRuntime>::initialize(Some(Ssu2Config {
            port: 0u16,
            host: Some("127.0.0.1".parse().unwrap()),
            publish: true,
            static_key: [0xaa; 32],
            intro_key: [0xbb; 32],
        }))
        .await
        .unwrap();
        let (ctx2, address2) = Ssu2Transport::<MockRuntime>::initialize(Some(Ssu2Config {
            port: 0u16,
            host: Some("127.0.0.1".parse().unwrap()),
            publish: true,
            static_key: [0xcc; 32],
            intro_key: [0xdd; 32],
        }))
        .await
        .unwrap();

        let (static1, signing1) = (
            StaticPrivateKey::random(MockRuntime::rng()),
            SigningPrivateKey::random(MockRuntime::rng()),
        );
        let (static2, signing2) = (
            StaticPrivateKey::random(MockRuntime::rng()),
            SigningPrivateKey::random(MockRuntime::rng()),
        );
        let router_info1 = RouterInfo::new::<MockRuntime>(
            &Default::default(),
            None,
            address1,
            &static1,
            &signing1,
        );
        let router_info2 = RouterInfo::new::<MockRuntime>(
            &Default::default(),
            None,
            address2,
            &static2,
            &signing2,
        );
        let (handle1, event_rx1) = {
            let (tx, rx) = channel(64);
            let mut handle = SubsystemHandle::new();
            handle.register_subsystem(tx);

            (handle, rx)
        };
        let (handle2, event_rx2) = {
            let (tx, rx) = channel(64);
            let mut handle = SubsystemHandle::new();
            handle.register_subsystem(tx);

            (handle, rx)
        };

        let mut transport1 = Ssu2Transport::<MockRuntime>::new(
            ctx1.unwrap(),
            true,
            signing1,
            router_info1,
            handle1,
            ProfileStorage::<MockRuntime>::new(&[], &[]),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        let mut transport2 = Ssu2Transport::<MockRuntime>::new(
            ctx2.unwrap(),
            true,
            signing2,
            router_info2.clone(),
            handle2,
            ProfileStorage::<MockRuntime>::new(&[], &[]),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        tokio::spawn(async move {
            loop {
                match transport2.next().await.unwrap() {
                    TransportEvent::ConnectionEstablished { router_id } =>
                        transport2.accept(&router_id),
                    _ => {}
                }
            }
        });

        transport1.connect(router_info2);
        loop {
            match transport1.next().await.unwrap() {
                TransportEvent::ConnectionEstablished { router_id } => {
                    transport1.accept(&router_id);
                    break;
                }
                _ => {}
            }
        }
    }
}
