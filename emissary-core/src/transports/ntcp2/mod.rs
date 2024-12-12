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
    crypto::{
        base64_decode, chachapoly::ChaChaPoly, SigningPrivateKey, StaticPrivateKey, StaticPublicKey,
    },
    primitives::{RouterAddress, RouterId, RouterInfo, Str, TransportKind},
    profile::ProfileStorage,
    runtime::{Counter, JoinSet, MetricType, MetricsHandle, Runtime, TcpListener, TcpStream},
    subsystem::SubsystemHandle,
    transports::{
        metrics::*,
        ntcp2::{
            listener::Ntcp2Listener,
            message::MessageBlock,
            session::{Ntcp2Session, SessionManager},
        },
        Transport, TransportEvent,
    },
    Ntcp2Config,
};

use futures::{Stream, StreamExt};
use hashbrown::HashMap;
use thingbuf::mpsc::Sender;

use alloc::{boxed::Box, string::String, vec::Vec};
use core::{
    marker::PhantomData,
    pin::Pin,
    str::FromStr,
    task::{Context, Poll, Waker},
};

mod listener;
mod message;
mod session;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ntcp2";

/// NTCP2 transport.
pub struct Ntcp2Transport<R: Runtime> {
    /// NTCP2 connection listener.
    listener: Ntcp2Listener<R>,

    /// Metrics handle.
    metrics: R::MetricsHandle,

    /// Open connections.
    open_connections: R::JoinSet<RouterId>,

    /// Pending connections.
    ///
    /// Connections which have been established successfully
    /// but are waiting approval/rejection from the `TransportManager`.
    pending_connections: HashMap<RouterId, Ntcp2Session<R>>,

    /// Pending connections.
    pending_handshakes: R::JoinSet<crate::Result<Ntcp2Session<R>>>,

    /// Session manager.
    session_manager: SessionManager<R>,

    /// Waker.
    waker: Option<Waker>,
}

impl<R: Runtime> Ntcp2Transport<R> {
    /// Create new [`Ntcp2Transport`].
    pub async fn new(
        config: Ntcp2Config,
        local_signing_key: SigningPrivateKey,
        local_router_info: RouterInfo,
        subsystem_handle: SubsystemHandle,
        profile_storage: ProfileStorage<R>,
        metrics: R::MetricsHandle,
    ) -> crate::Result<Self> {
        // TODO: handle the case when user doesn't want to enable ntcp2 listener
        let socket_address = local_router_info
            .addresses
            .get(&TransportKind::Ntcp2)
            .expect("to exist")
            .socket_address()
            .expect("to exist");
        let listener = Ntcp2Listener::new(socket_address).await?;

        let session_manager = SessionManager::new(
            config.key,
            config.iv.to_vec(),
            local_signing_key,
            local_router_info,
            subsystem_handle,
            profile_storage,
        )?;

        tracing::trace!(
            target: LOG_TARGET,
            listen_address = ?socket_address,
            "starting ntcp2 transport",
        );

        Ok(Ntcp2Transport {
            listener,
            metrics,
            open_connections: R::join_set(),
            pending_connections: HashMap::new(),
            pending_handshakes: R::join_set(),
            session_manager,
            waker: None,
        })
    }

    /// Collect `Ntcp2Transport`-related metric counters, gauges and histograms.
    pub fn metrics(metrics: Vec<MetricType>) -> Vec<MetricType> {
        metrics
    }
}

impl<R: Runtime> Transport for Ntcp2Transport<R> {
    fn connect(&mut self, router: RouterInfo) {
        tracing::trace!(
            target: LOG_TARGET,
            router = ?router.identity.id(),
            "negotiate ntcp2 session with router",
        );

        let future = self.session_manager.create_session(router);
        self.pending_handshakes.push(future);
        self.waker.as_mut().map(|waker| waker.wake_by_ref());
        self.metrics.counter(NUM_OUTBOUND).increment(1);
    }

    fn accept(&mut self, router: &RouterId) {
        match self.pending_connections.remove(router) {
            Some(session) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router,
                    "ntcp2 session accepted, starting event loop",
                );

                self.open_connections.push(session.run());
                self.waker.as_mut().map(|waker| waker.wake_by_ref());
            }
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    %router,
                    "cannot accept non-existent ntcp2 session",
                );
                debug_assert!(false);
            }
        }
    }

    fn reject(&mut self, router: &RouterId) {
        match self.pending_connections.remove(router) {
            Some(connection) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router,
                    "ntcp2 session rejected, closing connection",
                );
                self.metrics.counter(NUM_REJECTED).increment(1);
                drop(connection);
            }
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    %router,
                    "cannot reject non-existent ntcp2 session",
                );
                debug_assert!(false);
            }
        }
    }
}

impl<R: Runtime> Stream for Ntcp2Transport<R> {
    type Item = TransportEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.waker = Some(cx.waker().clone());

        match self.open_connections.poll_next_unpin(cx) {
            Poll::Pending => {}
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Ready(Some(router)) =>
                return Poll::Ready(Some(TransportEvent::ConnectionClosed { router })),
        }

        match self.listener.poll_next_unpin(cx) {
            Poll::Pending => {}
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Ready(Some(stream)) => {
                tracing::trace!(
                    target: LOG_TARGET,
                    "inbound tcp connection, accept session",
                );

                let future = self.session_manager.accept_session(stream);
                self.pending_handshakes.push(future);
                self.metrics.counter(NUM_INBOUND).increment(1);
            }
        }

        if !self.pending_handshakes.is_empty() {
            match futures::ready!(self.pending_handshakes.poll_next_unpin(cx)) {
                Some(Ok(session)) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        role = ?session.role(),
                        router = %session.router().identity.id(),
                        "ntcp2 connection opened",
                    );

                    // get router info from the session, store the session itself into
                    // `pending_connections` and inform `TransportManager` that new ntcp2 connection
                    // with `router` has been opened
                    //
                    // `TransportManager` will either accept or reject the session
                    let router_info = session.router();
                    let router = router_info.identity.id();

                    self.pending_connections.insert(router, session);

                    return Poll::Ready(Some(TransportEvent::ConnectionEstablished {
                        router_info,
                    }));
                }
                Some(Err(error)) => return Poll::Ready(Some(TransportEvent::ConnectionFailure {})),
                None => return Poll::Ready(None),
            }
        }

        Poll::Pending
    }
}
