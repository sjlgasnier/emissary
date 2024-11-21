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
    crypto::base32_encode,
    error::QueryError,
    i2np::{
        database::{
            lookup::{DatabaseLookupBuilder, LookupType, ReplyType},
            store::{DatabaseStore, DatabaseStoreBuilder, DatabaseStoreKind, DatabaseStorePayload},
        },
        Message, MessageBuilder, MessageType, I2NP_MESSAGE_EXPIRATION,
    },
    netdb::{
        dht::Dht,
        handle::{NetDbAction, NetDbActionRecycle},
        metrics::*,
    },
    primitives::{Lease, LeaseSet2, RouterId, TunnelId},
    router_storage::RouterStorage,
    runtime::{Counter, Gauge, JoinSet, MetricType, MetricsHandle, Runtime},
    subsystem::SubsystemEvent,
    transports::TransportService,
    tunnel::{TunnelPoolEvent, TunnelPoolHandle},
};

use bytes::Bytes;
use futures::StreamExt;
use futures_channel::oneshot;
use hashbrown::{HashMap, HashSet};
use rand_core::RngCore;
use thingbuf::mpsc;

use alloc::vec::Vec;
use core::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

pub use handle::NetDbHandle;

mod bucket;
mod dht;
mod handle;
mod metrics;
mod routing_table;
mod types;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::netdb";

/// `NetDb` query timeout.
const QUERY_TIMEOUT: Duration = Duration::from_secs(15);

/// Tunnel selector.
///
/// Distributes tunnel usage fairly across all tunnels.
struct TunnelSelector<T: Clone> {
    /// Iterator index.
    iterator: usize,

    /// Tunnels.
    tunnels: Vec<T>,
}

impl<T: Clone> TunnelSelector<T> {
    /// Create new [`TunnelSelector`].
    pub fn new() -> Self {
        Self {
            iterator: 0usize,
            tunnels: Vec::new(),
        }
    }

    /// Add `tunnel` into [`TunnelSelector`].
    pub fn add_tunnel(&mut self, tunnel: T) {
        self.tunnels.push(tunnel);
    }

    /// Remove tunnel from [`TunnelSelector`] using predicate.
    pub fn remove_tunnel(&mut self, predicate: impl Fn(&T) -> bool) {
        self.tunnels.retain(|tunnel| predicate(tunnel))
    }

    /// Get next tunnel from [`TunnelSelector`], if any exists.
    pub fn next_tunnel(&mut self) -> Option<T> {
        if self.tunnels.is_empty() {
            return None;
        }

        let index = {
            let index = self.iterator;
            self.iterator = self.iterator.wrapping_add(1usize);

            index
        };

        Some(self.tunnels[index % self.tunnels.len()].clone())
    }
}

/// Floodfill state.
#[derive(Debug)]
enum RouterState {
    /// FloodFill is connected.
    Connected,

    /// FloodFill is being dialed.
    //
    // TODO: remove?
    Dialing {
        /// Pending messages.
        pending_messages: Vec<Vec<u8>>,
    },
}

/// Query kind.
enum QueryKind {
    /// Leaseset query.
    Leaseset {
        /// Oneshot sender for sending the result to caller.
        tx: oneshot::Sender<Result<LeaseSet2, QueryError>>,
    },
}

impl fmt::Debug for QueryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Leaseset { .. } => f.debug_struct("QueryKind::LeaseSet").finish_non_exhaustive(),
        }
    }
}

/// Network database (NetDB).
pub struct NetDb<R: Runtime> {
    /// Active queries.
    active: HashMap<Bytes, QueryKind>,

    /// Kademlia DHT implementation.
    dht: Dht<R>,

    /// Exploratory tunnel pool handle.
    exploratory_pool_handle: TunnelPoolHandle,

    /// Has the router been configured to act as a floodfill router.
    floodfill: bool,

    /// RX channel for receiving queries from other subsystems.
    handle_rx: mpsc::Receiver<NetDbAction, NetDbActionRecycle>,

    /// Active inbound tunnels.
    inbound_tunnels: TunnelSelector<Lease>,

    /// Local router ID.
    local_router_id: RouterId,

    /// Metrics handle.
    metrics: R::MetricsHandle,

    /// Active inbound tunhnels
    outbound_tunnels: TunnelSelector<TunnelId>,

    /// Query timers.
    query_timers: R::JoinSet<Bytes>,

    /// Router storage.
    router_storage: RouterStorage,

    /// Connected floodfills.
    routers: HashMap<RouterId, RouterState>,

    /// Transport service.
    service: TransportService,
}

impl<R: Runtime> NetDb<R> {
    /// Create new [`NetDb`].
    pub fn new(
        local_router_id: RouterId,
        floodfill: bool,
        service: TransportService,
        router_storage: RouterStorage,
        metrics: R::MetricsHandle,
        exploratory_pool_handle: TunnelPoolHandle,
    ) -> (Self, NetDbHandle) {
        let floodfills = router_storage
            .routers()
            .iter()
            .filter_map(|(id, router)| router.is_floodfill().then_some(id.clone()))
            .collect::<HashSet<_>>();

        metrics.counter(NUM_FLOODFILLS).increment(floodfills.len());

        tracing::info!(
            target: LOG_TARGET,
            num_floodfills = ?floodfills.len(),
            ?floodfill,
            "starting netdb",
        );

        let (handle_tx, handle_rx) = mpsc::with_recycle(64, NetDbActionRecycle::default());

        (
            Self {
                active: HashMap::new(),
                dht: Dht::new(local_router_id.clone(), floodfills, metrics.clone()),
                exploratory_pool_handle,
                floodfill,
                handle_rx,
                inbound_tunnels: TunnelSelector::new(),
                local_router_id,
                metrics,
                outbound_tunnels: TunnelSelector::new(),
                query_timers: R::join_set(),
                routers: HashMap::new(),
                router_storage,
                service,
            },
            NetDbHandle::new(handle_tx),
        )
    }

    /// Collect `NetDb`-related metric counters, gauges and histograms.
    pub fn metrics(metrics: Vec<MetricType>) -> Vec<MetricType> {
        metrics::register_metrics(metrics)
    }

    /// Handle established connection to `router`.
    fn on_connection_established(&mut self, router_id: RouterId) {
        match self.routers.remove(&router_id) {
            None =>
                match self.router_storage.get(&router_id).expect("router to exist").is_floodfill() {
                    true => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            %router_id,
                            "new floodfill connected",
                        );

                        // insert new floodfills into `Dht` as well
                        self.dht.add_floodfill(router_id.clone());

                        self.routers.insert(router_id, RouterState::Connected);
                        self.metrics.gauge(NUM_CONNECTED_FLOODFILLS).increment(1);
                        self.metrics.counter(NUM_FLOODFILLS).increment(1);
                    }
                    false => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            %router_id,
                            "connection established",
                        );
                    }
                },
            Some(_) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    "known floodfill connected",
                );

                // "insert" floodfill into `Dht` so their "last active" status gets updated
                self.dht.add_floodfill(router_id.clone());

                self.routers.insert(router_id, RouterState::Connected);
                self.metrics.gauge(NUM_CONNECTED_FLOODFILLS).increment(1);
            }
        }
    }

    /// Handle closed connection to `router`.
    fn on_connection_closed(&mut self, router_id: RouterId) {
        match self.routers.remove(&router_id) {
            None => tracing::trace!(
                target: LOG_TARGET,
                %router_id,
                "connection closed",
            ),
            Some(_) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    "floodfill disconnected",
                );

                self.routers.remove(&router_id);
                self.metrics.gauge(NUM_CONNECTED_FLOODFILLS).decrement(1);
            }
        }
    }

    /// Handle I2NP message.
    fn on_message(&mut self, message: Message) {
        match message.message_type {
            MessageType::DatabaseStore => {
                let Some(DatabaseStore { key, payload, .. }) =
                    DatabaseStore::<R>::parse(&message.payload)
                else {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "malformed database store received",
                    );

                    return;
                };

                match self.active.remove(&key) {
                    None => tracing::trace!(
                        target: LOG_TARGET,
                        %payload,
                        "database store"
                    ),
                    Some(kind) => match (payload, kind) {
                        (
                            DatabaseStorePayload::LeaseSet2 { leaseset },
                            QueryKind::Leaseset { tx },
                        ) => {
                            tracing::trace!(
                                target: LOG_TARGET,
                                id = ?leaseset.header.destination.id(),
                                "leaseset reply received",
                            );

                            let _ = tx.send(Ok(leaseset));
                        }
                        (payload, query) => tracing::warn!(
                            target: LOG_TARGET,
                            %payload,
                            ?query,
                            "unhandled database store kind",
                        ),
                    },
                }
            }
            MessageType::DatabaseLookup => {
                tracing::trace!("database lookup");
            }
            MessageType::DatabaseSearchReply => {
                tracing::trace!("database search reply");
            }
            message_type => tracing::warn!(
                target: LOG_TARGET,
                ?message_type,
                "unsupported message",
            ),
        }
    }

    /// Query `LeaseSet2` under `key` from `NetDb` and return result to caller via `tx`
    fn on_query_leaseset(
        &mut self,
        key: Bytes,
        tx: oneshot::Sender<Result<LeaseSet2, QueryError>>,
    ) {
        let floodfills = self.dht.closest(&key, 5usize).collect::<Vec<_>>();

        tracing::debug!(
            target: LOG_TARGET,
            key = ?base32_encode(&key),
            num_floodfills = ?floodfills.len(),
            "query leaseset",
        );

        let Some(Lease {
            router_id,
            tunnel_id,
            ..
        }) = self.inbound_tunnels.next_tunnel()
        else {
            tracing::warn!(
                target: LOG_TARGET,
                key = ?base32_encode(&key),
                "cannot send lease set query, no inbound tunnel available",
            );
            debug_assert!(false);

            tx.send(Err(QueryError::NoTunnel));
            return;
        };

        let Some(outbound_tunnel) = self.outbound_tunnels.next_tunnel() else {
            tracing::warn!(
                target: LOG_TARGET,
                key = ?base32_encode(&key),
                "cannot send lease set query, no outbound tunnel available",
            );
            debug_assert!(false);

            tx.send(Err(QueryError::NoTunnel));
            return;
        };

        let message = DatabaseLookupBuilder::new(key.clone(), LookupType::Leaseset)
            .with_reply_type(ReplyType::Tunnel {
                tunnel_id,
                router_id,
            })
            .build();

        let message_id = R::rng().next_u32();
        let message = MessageBuilder::standard()
            .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
            .with_message_type(MessageType::DatabaseLookup)
            .with_message_id(message_id)
            .with_payload(&message)
            .build();

        match floodfills.is_empty() {
            true => {
                tracing::warn!(
                    target: LOG_TARGET,
                    "cannot query leaseset, no floodfill",
                );

                let _ = tx.send(Err(QueryError::NoFloodfills));
            }
            false => {
                match self.exploratory_pool_handle.send_to_router(
                    outbound_tunnel,
                    floodfills[0].clone(),
                    message,
                ) {
                    Err(error) => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?error,
                            "failed to send query",
                        );

                        // TODO: correct error, retry later
                        let _ = tx.send(Err(QueryError::Timeout));
                    }
                    Ok(()) => {
                        // store leaseset query into active queries and start timer for the query
                        self.active.insert(key.clone(), QueryKind::Leaseset { tx });
                        self.query_timers.push(async move {
                            R::delay(QUERY_TIMEOUT).await;
                            key
                        });
                    }
                }
            }
        }
    }

    /// Store `leaseset` under `key` in `NetDb`.
    fn on_store_leaseset(&mut self, key: Bytes, leaseset: Bytes) {
        let floodfills = self.dht.closest(&key, 5usize).collect::<Vec<_>>();

        tracing::debug!(
            target: LOG_TARGET,
            key = ?base32_encode(&key),
            num_floodfills = ?floodfills.len(),
            "store leaseset in netdb",
        );

        let message =
            DatabaseStoreBuilder::new(key, DatabaseStoreKind::LeaseSet2 { leaseset }).build();

        let message_id = R::rng().next_u32();
        let message = MessageBuilder::short()
            .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
            .with_message_type(MessageType::DatabaseStore)
            .with_message_id(message_id)
            .with_payload(&message)
            .build();

        match floodfills.is_empty() {
            true => tracing::warn!(
                target: LOG_TARGET,
                "cannot store leaseset, no floodfills",
            ),
            false =>
                if let Err(error) = self.service.send(&floodfills[0], message) {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to store leaseset",
                    );
                },
        }
    }
}

impl<R: Runtime> Future for NetDb<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.service.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(Some(SubsystemEvent::I2Np { messages })) =>
                    messages.into_iter().for_each(|message| self.on_message(message)),
                Poll::Ready(Some(SubsystemEvent::ConnectionEstablished { router })) =>
                    self.on_connection_established(router),
                Poll::Ready(Some(SubsystemEvent::ConnectionClosed { router })) =>
                    self.on_connection_closed(router),
                _ => {}
            }
        }

        // events from the exploratory pool are not interesting to `NetDb`
        loop {
            match self.exploratory_pool_handle.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelBuilt { tunnel_id })) => {
                    self.outbound_tunnels.add_tunnel(tunnel_id);
                }
                Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelExpired { tunnel_id })) => {
                    self.outbound_tunnels.remove_tunnel(|tunnel| tunnel != &tunnel_id);
                }
                Poll::Ready(Some(TunnelPoolEvent::InboundTunnelBuilt { lease, .. })) => {
                    self.inbound_tunnels.add_tunnel(lease);
                }
                Poll::Ready(Some(TunnelPoolEvent::InboundTunnelExpired { tunnel_id })) => {
                    self.inbound_tunnels.remove_tunnel(|lease| lease.tunnel_id != tunnel_id);
                }
                Poll::Ready(Some(TunnelPoolEvent::Message { message })) => self.on_message(message),
                Poll::Ready(Some(TunnelPoolEvent::TunnelPoolShutDown)) => return Poll::Ready(()),
                Poll::Ready(Some(_)) => {}
            }
        }

        loop {
            match self.handle_rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(NetDbAction::QueryLeaseSet2 { key, tx })) =>
                    self.on_query_leaseset(key, tx),
                Poll::Ready(Some(NetDbAction::StoreLeaseSet2 { key, leaseset })) =>
                    self.on_store_leaseset(key, leaseset),
                Poll::Ready(Some(NetDbAction::Dummy)) => unreachable!(),
            }
        }

        loop {
            match self.query_timers.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(key)) => match self.active.remove(&key) {
                    Some(kind) => match kind {
                        QueryKind::Leaseset { tx } => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                ?key,
                                "leaseset query timed out",
                            );

                            let _ = tx.send(Err(QueryError::Timeout));
                        }
                    },
                    None => tracing::trace!(
                        target: LOG_TARGET,
                        ?key,
                        "active query doesnt exist",
                    ),
                },
            }
        }

        Poll::Pending
    }
}
