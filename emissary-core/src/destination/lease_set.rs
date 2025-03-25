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
    crypto::{chachapoly::ChaChaPoly, EphemeralPrivateKey, StaticPublicKey},
    error::QueryError,
    i2np::{
        database::{
            lookup::{DatabaseLookupBuilder, LookupType, ReplyType as LookupReplyType},
            store::{DatabaseStoreBuilder, DatabaseStoreKind, ReplyType},
        },
        garlic::{DeliveryInstructions, GarlicMessageBuilder, GARLIC_MESSAGE_OVERHEAD},
        MessageBuilder, MessageType, I2NP_MESSAGE_EXPIRATION,
    },
    netdb::{Dht, NetDbHandle},
    primitives::{DestinationId, Lease, MessageId, RouterId, TunnelId},
    profile::ProfileStorage,
    runtime::{Instant, JoinSet, Runtime},
    tunnel::{NoiseContext, TunnelMessageSender},
};

use bytes::{BufMut, Bytes, BytesMut};
use futures::{
    future::{select, BoxFuture, Either},
    FutureExt, StreamExt,
};
use hashbrown::{HashMap, HashSet};
use rand_core::RngCore;
use thingbuf::mpsc::{channel, Receiver, Sender};

use alloc::{boxed::Box, vec::Vec};
use core::{
    fmt,
    future::Future,
    marker::PhantomData,
    mem,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::destination::lease-set";

/// Lease set republish timeout.
const REPUBLISH_TIMEOUT: Duration = Duration::from_secs(10);

/// How long should [`LeaseSetPublisher`] wait before attempting to recontact [`NetDb`] after
/// the previous call was rejected.
const NETDB_BACKOFF_TIMEOUT: Duration = Duration::from_secs(2);

/// Time to wait before the lease set storage is verified.
///
/// `LeaseSet Storage Verification` in https://geti2p.net/en/docs/how/network-database
const STORAGE_VERIFICATION_START_TIMEOUT: Duration = Duration::from_secs(10);

/// How long is a `DatabaseStore` waited for before it's considered failed.
///
/// Once deemed failed, new `DatabaseStore` is sent if there is still time left.
const STORAGE_VERIFICATION_TIMEOUT: Duration = Duration::from_secs(2);

/// How long is lease set storage verification awaited in total before it's considered failed.
///
/// Once deemed as failed, local lease set is republished to `NetDb`.
const STORAGE_VERIFICATION_TOTAL_TIMEOUT: Duration = Duration::from_secs(15);

/// [`LeaseSet2`] publish state.
enum PublishState {
    /// Publish state is inactive because there are no pending changes to the [`Destination`]'s
    /// inbound tunnels.
    Inactive,

    /// [`LeaseSetManager`] is awaiting for a timer to expire to publish a new [`LeaseSet2`].
    WaitingForInboundTunnels {
        /// Republish timer.
        timer: BoxFuture<'static, ()>,
    },
}

/// Local lease set manager.
pub struct LeaseSetManager<R: Runtime> {
    /// ID of the local destination.
    destination_id: DestinationId,

    /// [`LeaseSet2`] publish state.
    state: PublishState,

    /// Active inbound tunnels.
    tunnels: HashMap<TunnelId, Lease>,

    /// TX channel for sending [`Event`]s to [`LeaseSetPublisher`].
    ///
    /// `None` if [`Destination`] is unpublished.
    tx: Option<Sender<Event>>,

    /// Waker.
    waker: Option<Waker>,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> LeaseSetManager<R> {
    /// Create new [`LeaseSetManager`].
    ///
    /// `tunnels` contains the currently built tunnels and a lease set for these tunnels have
    /// already been created and published if the [`Destination`] is not unpublished.
    pub fn new(
        tunnels: Vec<Lease>,
        destination_id: DestinationId,
        tunnel_message_sender: TunnelMessageSender,
        netdb_handle: NetDbHandle,
        noise_ctx: NoiseContext,
        profile_storage: ProfileStorage<R>,
        unpublished: bool,
        lease_set: Bytes,
    ) -> Self {
        // lease set publisher is started only if the destination is published
        let tx = (!unpublished).then(|| {
            let (tx, rx) = channel(64);

            R::spawn(
                LeaseSetPublisher::<R>::new(
                    destination_id.clone(),
                    lease_set,
                    netdb_handle,
                    tunnel_message_sender,
                    noise_ctx,
                    profile_storage,
                    tunnels.clone(),
                    rx,
                    tx.clone(),
                )
                .run(),
            );

            tx
        });

        Self {
            destination_id,
            state: PublishState::Inactive,
            tunnels: HashMap::from_iter(tunnels.into_iter().map(|lease| (lease.tunnel_id, lease))),
            tx,
            waker: None,
            _runtime: Default::default(),
        }
    }

    /// Register new lease set for the [`Destination`].
    pub fn register_lease_set(&self, lease_set: Bytes) {
        if let Some(ref tx) = self.tx {
            if let Err(error) = tx.try_send(Event::LeaseSet { lease_set }) {
                tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    ?error,
                    "failed to send lease set for publication",
                );
            }
        }
    }

    /// Register [`DatabaseStore`] message and send it [`LeaseSetPublisher`] if it's active.
    pub fn register_database_store(&self, key: Bytes) {
        if let Some(ref tx) = self.tx {
            if let Err(error) = tx.try_send(Event::DatabaseStore { key }) {
                tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    ?error,
                    "failed to send database store to lease set publisher",
                );
            }
        }
    }

    /// Register [`DatabaseSearchReply`] message and send it [`LeaseSetPublisher`] if it's active.
    pub fn register_database_search_reply(&self, key: Bytes, floodfills: Vec<RouterId>) {
        if let Some(ref tx) = self.tx {
            if let Err(error) = tx.try_send(Event::DatabaseSearchReply { key, floodfills }) {
                tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    ?error,
                    "failed to send database search reply to lease set publisher",
                );
            }
        }
    }

    /// Register [`Lease`] for a newly built inbound tunnel.
    pub fn register_inbound_tunnel(&mut self, lease: Lease) {
        self.tunnels.insert(lease.tunnel_id, lease.clone());

        if let Some(ref tx) = self.tx {
            if let Err(error) = tx.try_send(Event::InboundTunnelBuilt {
                lease: lease.clone(),
            }) {
                tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    ?error,
                    "failed to register new inbound tunnel for lease set publisher",
                );
            }
        }

        if let PublishState::Inactive = self.state {
            self.state = PublishState::WaitingForInboundTunnels {
                timer: Box::pin(R::delay(REPUBLISH_TIMEOUT)),
            };

            if let Some(waker) = self.waker.take() {
                waker.wake_by_ref();
            }
        }
    }

    /// Register that an inbound tunnel has expired.
    pub fn register_expired_inbound_tunnel(&mut self, tunnel_id: TunnelId) {
        self.tunnels.remove(&tunnel_id);

        if let Some(ref tx) = self.tx {
            if let Err(error) = tx.try_send(Event::InboundTunnelExpired { tunnel_id }) {
                tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    ?error,
                    "failed to register expired inbound tunnel for lease set publisher",
                );
            }
        }

        if let PublishState::Inactive = self.state {
            self.state = PublishState::WaitingForInboundTunnels {
                timer: Box::pin(R::delay(REPUBLISH_TIMEOUT)),
            };

            if let Some(waker) = self.waker.take() {
                waker.wake_by_ref();
            }
        }
    }
}

impl<R: Runtime> Future for LeaseSetManager<R> {
    type Output = Vec<Lease>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut self.state {
            PublishState::Inactive => {}
            PublishState::WaitingForInboundTunnels { timer } => match timer.poll_unpin(cx) {
                Poll::Pending => {}
                Poll::Ready(_) => {
                    self.state = PublishState::Inactive;
                    return Poll::Ready(self.tunnels.values().cloned().collect());
                }
            },
        }

        self.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// Events sent by [`LeaseSetManager`] to [`LeaseSetPublisher`].
#[derive(Default, Clone, Debug)]
enum Event {
    /// New [`LeaseSet2`] has been created for the [`Destination`].
    LeaseSet {
        /// Serialized [`LeaseSet2`].
        lease_set: Bytes,
    },

    /// New inbound tunnel has been built.
    InboundTunnelBuilt {
        /// Lease of the tunnel.
        lease: Lease,
    },

    /// Inbound tunnel has expired.
    InboundTunnelExpired {
        /// ID of the expired tunnel.
        tunnel_id: TunnelId,
    },

    /// [`DatabaseStore`] message has been received to [`Destination`].
    DatabaseStore {
        /// Key of the message.
        key: Bytes,
    },

    /// [`DatabaseSearchReply`] message has been received to [`Destination`].
    DatabaseSearchReply {
        /// Key of the message.
        key: Bytes,

        /// Floodfills closest to key.
        floodfills: Vec<RouterId>,
    },

    /// Router info query results.
    RouterInfoQueryResult {
        /// Router Id.
        router_id: RouterId,

        /// Query result for a floodfill's router info.
        ///
        /// If the query succeeded, the floodfill's public key be found from [`ProfileStorage`].
        result: Result<(), QueryError>,
    },

    #[default]
    Dummy,
}

/// Lease set publisher state.
enum LeaseSetPublisherState<R: Runtime> {
    /// Publishing lease set.
    PublishLeaseSet {
        /// Router ID of the previous floodfill that was used for publication.
        ///
        /// `None` if this is the first time the lease set is being published or if the previous
        /// storage was verified successfully and the floodfill that was used is considered good.
        previous_floodfill: Option<RouterId>,
    },

    /// Awaiting flooding to complete so storage verificatin can start.
    AwaitingFlooding {
        /// Router ID of the floodfill that was used for lease set publication.
        floodfill: RouterId,

        /// Timer that expires after the flooding is assumed finished.
        timer: BoxFuture<'static, ()>,
    },

    /// Awaiting lease set storage confirmation.
    AwaitingVerification {
        /// Router ID of the floodfill that was used for lease set publication.
        floodfill: RouterId,

        /// Queried floodfills.
        queried: HashSet<RouterId>,

        /// When was storage verification started.
        started: R::Instant,

        /// Timer for `DatabaseStore` reception.
        ///
        /// If no message is received by the time the timer expires, a new `DatabaseLookup`
        /// is sen tfor a new floodfill
        timer: BoxFuture<'static, ()>,
    },

    /// Awaiting new lease set to be created.
    AwaitingNewLeaseSet,
}

impl<R: Runtime> fmt::Debug for LeaseSetPublisherState<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublishLeaseSet { previous_floodfill } => f
                .debug_struct("LeaseSetPublisherState::PublishLeaseSet")
                .field("floodfill", &previous_floodfill)
                .finish(),
            Self::AwaitingFlooding { floodfill, .. } => f
                .debug_struct("LeaseSetPublisherState::AwaitingFlooding")
                .field("floodfill", &floodfill)
                .finish_non_exhaustive(),
            Self::AwaitingVerification { queried, .. } => f
                .debug_struct("LeaseSetPublisherState::AwaitingVerification")
                .field("num_queried", &queried.len())
                .finish_non_exhaustive(),
            Self::AwaitingNewLeaseSet =>
                f.debug_struct("LeaseSetPublisherState::AwaitingNewLeaseSet").finish(),
        }
    }
}

/// Lease set published.
///
/// [`LeaseSetPublisher`] is an independent task responsible for publishing the local lease set
/// of the [`Destination`] it's bound to.
///
/// It periodically receives a new [`LeaseSet2`] created by SAM/I2CP, publishes it to `NetDb` and
/// verifies that the publish succeeded and if not, keeps publishing it until it does.
///
/// [`LeaseSetManager`] sends [`Event`]s to [`LeaseSetPublisher`] which allows it to operate
/// correctly. The [`DatabaseStore`]/[`DatabaseSearchReply`] messages received are routed to
/// [`LeaseSetPublisher`] which allows it to verify if the lease set was published successfully and
/// if not, allows it to adjust the set of floodfills it needs to query.
struct LeaseSetPublisher<R: Runtime> {
    /// ID of the local destination.
    destination_id: DestinationId,

    /// Floodfills closest to key.
    floodfills: HashMap<RouterId, StaticPublicKey>,

    /// Lease set key.
    key: Bytes,

    /// Lease set
    lease_set: Bytes,

    /// Handle to [`NetDb`].
    netdb_handle: NetDbHandle,

    /// Noise context.
    noise_ctx: NoiseContext,

    /// Pending floodfills.
    ///
    /// Flooofills which have been learned through `DatabaseSearchReply` messages but whose
    /// `RouterInfo`s are currently not available and cannot be used for storage or lookups.
    ///
    /// Floodfills are moved to `floodfills` once their `RouterInfo`s have been found.
    pending_floodfills: HashSet<RouterId>,

    /// Profile storage.
    profile_storage: ProfileStorage<R>,

    /// RX channel for receiving [`Event`]s from [`LeaseSetManager`].
    rx: Receiver<Event>,

    /// State of the publisher.
    state: LeaseSetPublisherState<R>,

    /// Tunnel message sender.
    tunnel_message_sender: TunnelMessageSender,

    /// Active inbound tunnels.
    tunnels: Vec<Lease>,

    /// TX channel used to receive router info lookup results.
    tx: Sender<Event>,
}

impl<R: Runtime> LeaseSetPublisher<R> {
    /// Create new [`LeaseSetPublisher`].
    fn new(
        destination_id: DestinationId,
        lease_set: Bytes,
        netdb_handle: NetDbHandle,
        tunnel_message_sender: TunnelMessageSender,
        noise_ctx: NoiseContext,
        profile_storage: ProfileStorage<R>,
        tunnels: Vec<Lease>,
        rx: Receiver<Event>,
        tx: Sender<Event>,
    ) -> Self {
        Self {
            destination_id: destination_id.clone(),
            floodfills: HashMap::new(),
            key: Bytes::from(destination_id.to_vec()),
            lease_set,
            netdb_handle,
            noise_ctx,
            pending_floodfills: HashSet::new(),
            profile_storage,
            rx,
            state: LeaseSetPublisherState::PublishLeaseSet {
                previous_floodfill: None,
            },
            tunnel_message_sender,
            tunnels,
            tx,
        }
    }

    /// Create [`DatabaseStore`] message for the leaset set and return the message and ID
    /// of the selected floodfill to whom the message should be sent.
    ///
    /// Returns `None` if there are no inbound tunnels.
    fn create_database_store(
        &self,
        previous_floofill: &Option<RouterId>,
    ) -> Option<(RouterId, Vec<u8>)> {
        if self.tunnels.is_empty() {
            tracing::warn!(
                target: LOG_TARGET,
                local = %self.destination_id,
                "cannot publish lease set, no inbound tunnels",
            );
            return None;
        }

        // create database store and send it to a floodfill router over
        // one of the destination's outbound tunnels
        let reply_token = R::rng().next_u32();

        // select floodfill closest to us
        //
        // if the previous database store failed, try to excluse that floodfill
        //
        // if there are no other floodfills available, retry to failing floodfill
        let floodfill = match Dht::<R>::get_closest(
            &self.key,
            &self
                .floodfills
                .keys()
                .filter(|router_id| match &previous_floofill {
                    None => true,
                    Some(previous) => router_id != &previous,
                })
                .cloned()
                .collect::<HashSet<_>>(),
        ) {
            None => {
                tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    "no floodfills for lease set publication, trying a failing floodfill",
                );

                Dht::<R>::get_closest(
                    &self.key,
                    &self.floodfills.keys().cloned().collect::<HashSet<_>>(),
                )?
            }
            Some(floodfill) => floodfill,
        };

        // key must exist since the floodfill was selected from `self.floodfills`
        let floodfill_public_key = self.floodfills.get(&floodfill).expect("to exist");

        // select random tunnel for `DeliveryStatus`
        let Lease {
            router_id: ref gateway_router_id,
            tunnel_id: ref gateway_tunnel_id,
            ..
        } = self.tunnels[R::rng().next_u32() as usize % self.tunnels.len()];

        let message = DatabaseStoreBuilder::new(
            self.key.clone(),
            DatabaseStoreKind::LeaseSet2 {
                lease_set: self.lease_set.clone(),
            },
        )
        .with_reply_type(ReplyType::Tunnel {
            reply_token,
            tunnel_id: *gateway_tunnel_id,
            router_id: gateway_router_id.clone(),
        })
        .build();

        let mut message = GarlicMessageBuilder::default()
            .with_date_time(R::time_since_epoch().as_secs() as u32)
            .with_garlic_clove(
                MessageType::DatabaseStore,
                MessageId::from(R::rng().next_u32()),
                R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                DeliveryInstructions::Local,
                &message,
            )
            .build();

        let ephemeral_secret = EphemeralPrivateKey::random(R::rng());
        let ephemeral_public = ephemeral_secret.public();
        let (garlic_key, garlic_tag) = self
            .noise_ctx
            .derive_outbound_garlic_key(floodfill_public_key.clone(), ephemeral_secret);

        let mut out = BytesMut::with_capacity(message.len() + GARLIC_MESSAGE_OVERHEAD);

        // encryption must succeed since the parameters are managed by us
        ChaChaPoly::new(&garlic_key)
            .encrypt_with_ad_new(&garlic_tag, &mut message)
            .expect("to succeed");

        out.put_u32(message.len() as u32 + 32);
        out.put_slice(&ephemeral_public.to_vec());
        out.put_slice(&message);

        Some((
            floodfill,
            MessageBuilder::standard()
                .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
                .with_message_type(MessageType::Garlic)
                .with_message_id(R::rng().next_u32())
                .with_payload(&out)
                .build(),
        ))
    }

    /// Create [`DatabaseLookup`] message for lease set storage verification.
    ///
    /// `floodfills` contains the router IDs of the floodfills that have already been queried or who
    /// were sent the initial [`DatabaseStore`] message and who should be ignored for this lookup.
    ///
    /// On success, [`DatabaseLookup`] message and router ID of the floofill to whom the message
    /// must be sent.
    ///
    /// Returns `None` if there aren't enough floodfills for lease set storage verification or if
    /// there are no inbound tunnels available for `DatabaseStore`.
    fn create_database_lookup(
        &self,
        floodfills: &HashSet<RouterId>,
    ) -> Option<(RouterId, Vec<u8>)> {
        if self.tunnels.is_empty() {
            tracing::warn!(
                target: LOG_TARGET,
                local = %self.destination_id,
                "cannot verify lease set storage, no inbound tunnels",
            );
            return None;
        }

        let Some(floodfill) = Dht::<R>::get_closest(
            &self.key,
            &self
                .floodfills
                .keys()
                .filter(|router_id| !floodfills.contains(*router_id))
                .cloned()
                .collect::<HashSet<_>>(),
        ) else {
            tracing::debug!(
                target: LOG_TARGET,
                local = %self.destination_id,
                "not enough floodfills for lease set storage verification",
            );
            return None;
        };

        // must succeed since `floodfill` was selected from `self.floodfills`
        let floodfill_public_key = self.floodfills.get(&floodfill).expect("to exist");

        // select random tunnel for DSM
        let Lease {
            router_id: ref gateway_router_id,
            tunnel_id: ref gateway_tunnel_id,
            ..
        } = self.tunnels[R::rng().next_u32() as usize % self.tunnels.len()];

        let message = DatabaseLookupBuilder::new(self.key.clone(), LookupType::LeaseSet)
            .with_reply_type(LookupReplyType::Tunnel {
                tunnel_id: *gateway_tunnel_id,
                router_id: gateway_router_id.clone(),
            })
            .build();

        let mut message = GarlicMessageBuilder::default()
            .with_date_time(R::time_since_epoch().as_secs() as u32)
            .with_garlic_clove(
                MessageType::DatabaseLookup,
                MessageId::from(R::rng().next_u32()),
                R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                DeliveryInstructions::Local,
                &message,
            )
            .build();

        let ephemeral_secret = EphemeralPrivateKey::random(R::rng());
        let ephemeral_public = ephemeral_secret.public();
        let (garlic_key, garlic_tag) = self
            .noise_ctx
            .derive_outbound_garlic_key(floodfill_public_key.clone(), ephemeral_secret);

        // message length + poly13055 tg + ephemeral key + garlic message length
        let mut out = BytesMut::with_capacity(message.len() + 16 + 32 + 4);

        // encryption must succeed since the parameters are managed by us
        ChaChaPoly::new(&garlic_key)
            .encrypt_with_ad_new(&garlic_tag, &mut message)
            .expect("to succeed");

        out.put_u32(message.len() as u32 + 32);
        out.put_slice(&ephemeral_public.to_vec());
        out.put_slice(&message);

        let message = MessageBuilder::standard()
            .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
            .with_message_type(MessageType::Garlic)
            .with_message_id(R::rng().next_u32())
            .with_payload(&out)
            .build();

        Some((floodfill, message))
    }

    /// Handle event.
    async fn handle_event(&mut self, event: Event) {
        match (&self.state, event) {
            (_, Event::InboundTunnelBuilt { lease }) => {
                tracing::trace!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    ?lease,
                    "inbound tunnel built",
                );
                self.tunnels.push(lease);
            }
            (_, Event::InboundTunnelExpired { tunnel_id }) => {
                tracing::trace!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    %tunnel_id,
                    "inbound tunnel expired",
                );
                self.tunnels.retain(|tunnel| tunnel.tunnel_id != tunnel_id);
            }
            // DSM received as the lease set storage verification is in progress
            //
            // the lease set publisher can start waiting on a new lease set
            (LeaseSetPublisherState::AwaitingVerification { .. }, Event::DatabaseStore { key })
                if key == self.key =>
            {
                tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    "lease set storage verified",
                );
                self.state = LeaseSetPublisherState::AwaitingNewLeaseSet;
            }
            // lease set storage verification in progress and DSRM received
            //
            // this either means that the lease set publish failed or the floodfill it was sent to
            // flooded it to floodfills that are closer to the key and unknown to us
            //
            // filter out the routers from `floodfills` that are already known to us (their public
            // key is available) and store them in the set of available floodfills
            //
            // if there are unknown floodfills, start router info lookups in the background
            (
                LeaseSetPublisherState::AwaitingVerification { .. },
                Event::DatabaseSearchReply { key, floodfills },
            ) if key == self.key => {
                let floodfills_to_query = {
                    let reader = self.profile_storage.reader();

                    floodfills
                        .into_iter()
                        .filter_map(|router_id| match reader.router_info(&router_id) {
                            Some(info) => {
                                self.floodfills
                                    .insert(router_id, info.identity.static_key().clone());
                                None
                            }
                            None => (!self.pending_floodfills.contains(&router_id)).then_some(router_id),
                        })
                        .collect::<HashSet<_>>()
                };

                tracing::trace!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    new_floodfills = ?floodfills_to_query,
                    "received `DatabaseSearchReply` for lease set storage verification",
                );

                // start router info lookups in the background
                //
                // send DLM for the router info of each unknown floodfill and poll the
                // results until all queries have completed, either successfully or not
                //
                // `LeaseSetPublisher` decides whether to restart lookups if they failed
                if !floodfills_to_query.is_empty() {
                    let tx = self.tx.clone();
                    let netdb_handle = self.netdb_handle.clone();

                    // mark the floodfills as pending so lease set republish is postponed until
                    // their router info lookups have concluded
                    self.pending_floodfills.extend(floodfills_to_query.clone());

                    R::spawn(async move {
                        let mut futures = R::join_set::<(RouterId, Result<(), QueryError>)>();

                        for router_id in floodfills_to_query {
                            let rx = netdb_handle.query_router_info(router_id.clone()).await;

                            futures.push(async move {
                                (router_id, rx.await.unwrap_or(Err(QueryError::RetryFailure)))
                            });
                        }

                        while !futures.is_empty() {
                            match futures.next().await {
                                None => return,
                                Some((router_id, result)) => {
                                    let _ = tx
                                        .send(Event::RouterInfoQueryResult { router_id, result })
                                        .await;
                                }
                            }
                        }
                    });
                }
            }
            // new lease set has been created
            //
            // irrespective of what the previous state was, start publishing the new lease set as
            // this is the latest lease set and publish/confirmation of old lease set doesn't matter
            // anymore
            (_, Event::LeaseSet { lease_set }) => {
                self.lease_set = lease_set;
                self.state = LeaseSetPublisherState::PublishLeaseSet {
                    previous_floodfill: None,
                };
            }
            // router info lookup has resolved
            //
            // if the query failed, the query is not restarted as if we good floodfills, we don't
            // need to this "failed floodfill" and if we don't have enough floodfill and the failed
            // floodfill is actually closer to `key` and any of the floodfills we currently have,
            // the "failed floodfill" will be readvertised in a future DSRM and we can reinitiate a
            // query for its router info
            (_, Event::RouterInfoQueryResult { router_id, result }) => {
                if !self.pending_floodfills.remove(&router_id) {
                    tracing::warn!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        %router_id,
                        ?result,
                        "router info query concluded for unknown router",
                    );
                    debug_assert!(false);
                }

                match result {
                    Err(error) => tracing::trace!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        %router_id,
                        ?error,
                        "failed to find router info for requested floodfill",
                    ),
                    Ok(()) => match self.profile_storage.reader().router_info(&router_id) {
                        Some(router_info) => {
                            tracing::trace!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                %router_id,
                                "router info lookup succeeded for requested floodfill",
                            );

                            self.floodfills
                                .insert(router_id, router_info.identity.static_key().clone());
                        }
                        None => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                %router_id,
                                "router info lookup succeeded but router if not found in storage",
                            );
                            debug_assert!(false);
                        }
                    },
                }
            }
            (state, event) => tracing::trace!(
                target: LOG_TARGET,
                local = %self.destination_id,
                ?state,
                ?event,
                "ignoring uninteresting event/state combination",
            ),
        }
    }

    /// Run the event loop of [`LeaseSetPublisher`].
    async fn run(mut self) {
        // get the floofills closest to key right now
        //
        // these may change as more floodfills closer to key are discovered either through
        // kademlia random walks or via DSRM messages
        self.floodfills = loop {
            match self.netdb_handle.get_closest_floodfills(self.key.clone()) {
                Ok(query_rx) => match query_rx.await {
                    Ok(queried) => break queried.into_iter().collect(),
                    Err(_) => R::delay(NETDB_BACKOFF_TIMEOUT).await,
                },
                Err(_) => R::delay(NETDB_BACKOFF_TIMEOUT).await,
            }
        };

        loop {
            match self.state {
                LeaseSetPublisherState::PublishLeaseSet {
                    ref previous_floodfill,
                } => {
                    let Some((floodfill, message)) = self.create_database_store(previous_floodfill)
                    else {
                        self.state = LeaseSetPublisherState::AwaitingNewLeaseSet;
                        continue;
                    };

                    tracing::debug!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        %floodfill,
                        "publish local lease set",
                    );

                    // this is a blocking call so the only way it'd fail is if the tunnel pool had
                    // shut down
                    let _ = self
                        .tunnel_message_sender
                        .send_message(message)
                        .router_delivery(floodfill.clone())
                        .send()
                        .await;

                    // verify there's at least one other floodfill before proceeding to storage
                    // verification
                    if self.floodfills.len() == 1 {
                        tracing::warn!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            "not enough floodfills to verify lease set storage",
                        );
                        self.state = LeaseSetPublisherState::AwaitingNewLeaseSet;
                        continue;
                    }

                    self.state = LeaseSetPublisherState::AwaitingFlooding {
                        floodfill,
                        timer: Box::pin(R::delay(STORAGE_VERIFICATION_START_TIMEOUT)),
                    };
                }
                LeaseSetPublisherState::AwaitingFlooding {
                    ref floodfill,
                    ref mut timer,
                } => match select(self.rx.recv(), timer).await {
                    Either::Left((None, _)) => return,
                    Either::Left((Some(event), _)) => self.handle_event(event).await,
                    Either::Right(_) => {
                        let storage_floodfill = floodfill.clone();

                        let Some((lookup_floodfill, message)) =
                            self.create_database_lookup(&HashSet::from_iter([
                                storage_floodfill.clone()
                            ]))
                        else {
                            self.state = LeaseSetPublisherState::AwaitingNewLeaseSet;
                            continue;
                        };

                        tracing::trace!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            floodfill = %lookup_floodfill,
                            "sending lease set storage verification",
                        );

                        // this is a blocking call so the only way it'd fail is if the tunnel pool
                        // had shut down
                        let _ = self
                            .tunnel_message_sender
                            .send_message(message)
                            .router_delivery(lookup_floodfill.clone())
                            .send()
                            .await;

                        self.state = LeaseSetPublisherState::AwaitingVerification {
                            floodfill: storage_floodfill.clone(),
                            queried: HashSet::from_iter([
                                storage_floodfill.clone(),
                                lookup_floodfill,
                            ]),
                            started: R::now(),
                            timer: Box::pin(R::delay(STORAGE_VERIFICATION_TIMEOUT)),
                        };
                    }
                },
                LeaseSetPublisherState::AwaitingVerification {
                    ref mut queried,
                    ref mut timer,
                    ref started,
                    ref floodfill,
                } => match select(self.rx.recv(), timer).await {
                    Either::Left((None, _)) => return,
                    Either::Left((Some(event), _)) => self.handle_event(event).await,
                    Either::Right(_) => {
                        if started.elapsed() >= STORAGE_VERIFICATION_TOTAL_TIMEOUT {
                            tracing::debug!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                previous_floodfill = %floodfill,
                                "failed to verify storage after multiple retries, republishing",
                            );
                            self.state = LeaseSetPublisherState::PublishLeaseSet {
                                previous_floodfill: Some(floodfill.clone()),
                            };
                            continue;
                        }
                        let mut queried = mem::take(queried);

                        // if there aren't enough floodfills and there are no pending RI lookups for
                        // unknown floodfills, try to republish the lease set using the old
                        // floodfills
                        //
                        // if there are pending RI lookups for unknown floodfills, wait for them to
                        // conclude before attempting to republish the lease set
                        //
                        // if there aren't inbound tunnels, the state machine moves to
                        // `AwaitingNewLeaseSet` as there's nothing it can do right now
                        let (lookup_floodfill, message) =
                            match self.create_database_lookup(&queried) {
                                Some((lookup_floodfill, message)) => (lookup_floodfill, message),
                                None if !self.pending_floodfills.is_empty() => {
                                    tracing::debug!(
                                        target: LOG_TARGET,
                                        local = %self.destination_id,
                                        num_pending = ?self.pending_floodfills.len(),
                                        "waiting pending router info lookups to conclude",
                                    );

                                    self.state = LeaseSetPublisherState::AwaitingVerification {
                                        floodfill: floodfill.clone(),
                                        queried,
                                        started: *started,
                                        timer: Box::pin(R::delay(STORAGE_VERIFICATION_TIMEOUT)),
                                    };
                                    continue;
                                }
                                None => {
                                    tracing::debug!(
                                        target: LOG_TARGET,
                                        local = %self.destination_id,
                                        "lookup failed for all floodfills, republishing",
                                    );
                                    self.state = LeaseSetPublisherState::PublishLeaseSet {
                                        previous_floodfill: Some(floodfill.clone()),
                                    };
                                    continue;
                                }
                            };

                        tracing::trace!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            floodfill = %lookup_floodfill,
                            pending_floodfills = ?self.pending_floodfills.len(),
                            "resending lease set storage verification",
                        );

                        // this is a blocking call so the only way it'd fail is if the tunnel pool
                        // had shut down
                        let _ = self
                            .tunnel_message_sender
                            .send_message(message)
                            .router_delivery(lookup_floodfill.clone())
                            .send()
                            .await;

                        self.state = LeaseSetPublisherState::AwaitingVerification {
                            floodfill: floodfill.clone(),
                            queried: {
                                queried.insert(lookup_floodfill);
                                queried
                            },
                            started: *started,
                            timer: Box::pin(R::delay(STORAGE_VERIFICATION_TIMEOUT)),
                        };
                    }
                },
                LeaseSetPublisherState::AwaitingNewLeaseSet => match self.rx.recv().await {
                    None => return,
                    Some(event) => self.handle_event(event).await,
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::StaticPrivateKey,
        i2np::{
            database::{lookup::DatabaseLookup, store::DatabaseStore},
            Message,
        },
        netdb::NetDbAction,
        primitives::{LeaseSet2, RouterInfo, RouterInfoBuilder},
        runtime::mock::MockRuntime,
        tunnel::{
            DeliveryInstructions as GarlicDeliveryInstructions, GarlicHandler, TunnelMessage,
            TunnelPoolHandle,
        },
    };
    use std::collections::VecDeque;

    #[tokio::test]
    async fn lease_set_published_and_storage_verified() {
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let sender = tp_handle.sender();
        let (netdb_handle, netdb_rx) = NetDbHandle::create();
        let noise_ctx = NoiseContext::new(
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::from(RouterId::random().to_vec()),
        );
        let (lease_set, signing_key) = LeaseSet2::random();
        let tunnels = lease_set.leases.clone();
        let destination_id = lease_set.header.destination.id();
        let key = Bytes::from(destination_id.to_vec());
        let serialized = lease_set.serialize(&signing_key);
        let manager = LeaseSetManager::<MockRuntime>::new(
            tunnels,
            destination_id,
            sender,
            netdb_handle,
            noise_ctx,
            ProfileStorage::new(&[], &[]),
            false,
            Bytes::from(serialized),
        );

        let mut floodfills = (0..3)
            .map(|_| {
                (
                    RouterId::random(),
                    StaticPrivateKey::random(MockRuntime::rng()),
                )
            })
            .collect::<HashMap<_, _>>();

        match tokio::time::timeout(Duration::from_secs(5), netdb_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            NetDbAction::GetClosestFloodfills { tx, .. } => {
                tx.send(
                    floodfills
                        .iter()
                        .map(|(router_id, key)| (router_id.clone(), key.public()))
                        .collect(),
                )
                .unwrap();
            }
            _ => panic!("invalid action received"),
        }

        // handle lease set store
        match tokio::time::timeout(Duration::from_secs(5), tm_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            TunnelMessage::RouterDeliveryViaRoute {
                outbound_tunnel: None,
                router_id,
                message,
            } => {
                let message = Message::parse_standard(&message).unwrap();
                assert_eq!(message.message_type, MessageType::Garlic);

                // remove the floodfill from the set of floodfills since is shouldn't be for
                // verification
                let key = floodfills.remove(&router_id).unwrap();

                let mut garlic = GarlicHandler::<MockRuntime>::new(
                    NoiseContext::new(key, Bytes::from(router_id.to_vec())),
                    MockRuntime::register_metrics(vec![], None),
                );
                let GarlicDeliveryInstructions::Local { message } = garlic
                    .handle_message(message)
                    .unwrap()
                    .filter(|message| {
                        std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                    })
                    .collect::<VecDeque<_>>()
                    .pop_front()
                    .expect("to exist")
                else {
                    panic!("invalid type");
                };

                match message.message_type {
                    MessageType::DatabaseStore => {
                        let DatabaseStore { .. } =
                            DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();
                    }
                    _ => panic!("invalid message type"),
                }
            }
            _ => panic!("unexpected tunnel message"),
        }

        // handle lease set storage verification
        match tokio::time::timeout(Duration::from_secs(12), tm_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            TunnelMessage::RouterDeliveryViaRoute {
                outbound_tunnel: None,
                router_id,
                message,
            } => {
                let message = Message::parse_standard(&message).unwrap();
                assert_eq!(message.message_type, MessageType::Garlic);

                let static_key = floodfills.remove(&router_id).unwrap();

                let mut garlic = GarlicHandler::<MockRuntime>::new(
                    NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                    MockRuntime::register_metrics(vec![], None),
                );
                let GarlicDeliveryInstructions::Local { message } = garlic
                    .handle_message(message)
                    .unwrap()
                    .filter(|message| {
                        std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                    })
                    .collect::<VecDeque<_>>()
                    .pop_front()
                    .expect("to exist")
                else {
                    panic!("invalid type");
                };

                match message.message_type {
                    MessageType::DatabaseLookup => {
                        let DatabaseLookup {
                            key: lookup_key, ..
                        } = DatabaseLookup::parse(&message.payload).unwrap();

                        assert_eq!(key.as_ref(), &lookup_key);

                        // send database store to lease set publisher
                        manager.register_database_store(lookup_key);
                    }
                    _ => panic!("invalid message type"),
                }
            }
            _ => panic!("unexpected tunnel message"),
        }

        // verify there's no more activity coming from lease set publisher
        loop {
            tokio::select! {
                _ = tm_rx.recv() => panic!("unexpected event"),
                _ = netdb_rx.recv() => panic!("unexpected event"),
                _ = tokio::time::sleep(Duration::from_secs(15)) => break,
            }
        }
    }

    #[tokio::test]
    async fn lease_set_storage_reverified() {
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let sender = tp_handle.sender();
        let (netdb_handle, netdb_rx) = NetDbHandle::create();
        let noise_ctx = NoiseContext::new(
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::from(RouterId::random().to_vec()),
        );
        let (lease_set, signing_key) = LeaseSet2::random();
        let tunnels = lease_set.leases.clone();
        let destination_id = lease_set.header.destination.id();
        let key = Bytes::from(destination_id.to_vec());
        let serialized = lease_set.serialize(&signing_key);
        let manager = LeaseSetManager::<MockRuntime>::new(
            tunnels,
            destination_id,
            sender,
            netdb_handle,
            noise_ctx,
            ProfileStorage::new(&[], &[]),
            false,
            Bytes::from(serialized),
        );

        let mut floodfills = (0..3)
            .map(|_| {
                (
                    RouterId::random(),
                    StaticPrivateKey::random(MockRuntime::rng()),
                )
            })
            .collect::<HashMap<_, _>>();

        match tokio::time::timeout(Duration::from_secs(5), netdb_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            NetDbAction::GetClosestFloodfills { tx, .. } => {
                tx.send(
                    floodfills
                        .iter()
                        .map(|(router_id, key)| (router_id.clone(), key.public()))
                        .collect(),
                )
                .unwrap();
            }
            _ => panic!("invalid action received"),
        }

        // handle lease set store
        match tokio::time::timeout(Duration::from_secs(5), tm_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            TunnelMessage::RouterDeliveryViaRoute {
                outbound_tunnel: None,
                router_id,
                message,
            } => {
                let message = Message::parse_standard(&message).unwrap();
                assert_eq!(message.message_type, MessageType::Garlic);

                // remove the floodfill from the set of floodfills since is shouldn't be for
                // verification
                let key = floodfills.remove(&router_id).unwrap();

                let mut garlic = GarlicHandler::<MockRuntime>::new(
                    NoiseContext::new(key, Bytes::from(router_id.to_vec())),
                    MockRuntime::register_metrics(vec![], None),
                );
                let GarlicDeliveryInstructions::Local { message } = garlic
                    .handle_message(message)
                    .unwrap()
                    .filter(|message| {
                        std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                    })
                    .collect::<VecDeque<_>>()
                    .pop_front()
                    .expect("to exist")
                else {
                    panic!("invalid type");
                };

                match message.message_type {
                    MessageType::DatabaseStore => {
                        let DatabaseStore { .. } =
                            DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();
                    }
                    _ => panic!("invalid message type"),
                }
            }
            _ => panic!("unexpected tunnel message"),
        }

        // handle lease set storage verification but don't respond to it
        match tokio::time::timeout(Duration::from_secs(12), tm_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            TunnelMessage::RouterDeliveryViaRoute {
                outbound_tunnel: None,
                router_id,
                message,
            } => {
                let message = Message::parse_standard(&message).unwrap();
                assert_eq!(message.message_type, MessageType::Garlic);

                let static_key = floodfills.remove(&router_id).unwrap();

                let mut garlic = GarlicHandler::<MockRuntime>::new(
                    NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                    MockRuntime::register_metrics(vec![], None),
                );
                let GarlicDeliveryInstructions::Local { message } = garlic
                    .handle_message(message)
                    .unwrap()
                    .filter(|message| {
                        std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                    })
                    .collect::<VecDeque<_>>()
                    .pop_front()
                    .expect("to exist")
                else {
                    panic!("invalid type");
                };

                // ensure that database lookup was receveid but don't respond to it
                match message.message_type {
                    MessageType::DatabaseLookup => {
                        let DatabaseLookup {
                            key: lookup_key, ..
                        } = DatabaseLookup::parse(&message.payload).unwrap();

                        assert_eq!(key.as_ref(), &lookup_key);
                    }
                    _ => panic!("invalid message type"),
                }
            }
            _ => panic!("unexpected tunnel message"),
        }

        // handle lease set storage verification and send response
        match tokio::time::timeout(Duration::from_secs(12), tm_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            TunnelMessage::RouterDeliveryViaRoute {
                outbound_tunnel: None,
                router_id,
                message,
            } => {
                let message = Message::parse_standard(&message).unwrap();
                assert_eq!(message.message_type, MessageType::Garlic);

                let static_key = floodfills.remove(&router_id).unwrap();

                let mut garlic = GarlicHandler::<MockRuntime>::new(
                    NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                    MockRuntime::register_metrics(vec![], None),
                );
                let GarlicDeliveryInstructions::Local { message } = garlic
                    .handle_message(message)
                    .unwrap()
                    .filter(|message| {
                        std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                    })
                    .collect::<VecDeque<_>>()
                    .pop_front()
                    .expect("to exist")
                else {
                    panic!("invalid type");
                };

                // ensure that database lookup was receveid but don't respond to it
                match message.message_type {
                    MessageType::DatabaseLookup => {
                        let DatabaseLookup {
                            key: lookup_key, ..
                        } = DatabaseLookup::parse(&message.payload).unwrap();

                        assert_eq!(key.as_ref(), &lookup_key);

                        // send database store to lease set publisher
                        manager.register_database_store(lookup_key);
                    }
                    _ => panic!("invalid message type"),
                }
            }
            _ => panic!("unexpected tunnel message"),
        }

        // verify there's no more activity coming from lease set publisher
        loop {
            tokio::select! {
                _ = tm_rx.recv() => panic!("unexpected event"),
                _ = netdb_rx.recv() => panic!("unexpected event"),
                _ = tokio::time::sleep(Duration::from_secs(15)) => break,
            }
        }
    }

    #[tokio::test]
    async fn lease_set_republished_after_timeout() {
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let sender = tp_handle.sender();
        let (netdb_handle, netdb_rx) = NetDbHandle::create();
        let noise_ctx = NoiseContext::new(
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::from(RouterId::random().to_vec()),
        );
        let (lease_set, signing_key) = LeaseSet2::random();
        let tunnels = lease_set.leases.clone();
        let destination_id = lease_set.header.destination.id();
        let key = Bytes::from(destination_id.to_vec());
        let serialized = lease_set.serialize(&signing_key);
        let _manager = LeaseSetManager::<MockRuntime>::new(
            tunnels,
            destination_id,
            sender,
            netdb_handle,
            noise_ctx,
            ProfileStorage::new(&[], &[]),
            false,
            Bytes::from(serialized),
        );

        let floodfills = (0..30)
            .map(|_| {
                (
                    RouterId::random(),
                    StaticPrivateKey::random(MockRuntime::rng()),
                )
            })
            .collect::<HashMap<_, _>>();

        match tokio::time::timeout(Duration::from_secs(5), netdb_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            NetDbAction::GetClosestFloodfills { tx, .. } => {
                tx.send(
                    floodfills
                        .iter()
                        .map(|(router_id, key)| (router_id.clone(), key.public()))
                        .collect(),
                )
                .unwrap();
            }
            _ => panic!("invalid action received"),
        }

        // handle lease set store
        let original_floodfill = match tokio::time::timeout(Duration::from_secs(5), tm_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            TunnelMessage::RouterDeliveryViaRoute {
                outbound_tunnel: None,
                router_id,
                message,
            } => {
                let message = Message::parse_standard(&message).unwrap();
                assert_eq!(message.message_type, MessageType::Garlic);

                // remove the floodfill from the set of floodfills since is shouldn't be for
                // verification
                let key = floodfills.get(&router_id).unwrap();

                let mut garlic = GarlicHandler::<MockRuntime>::new(
                    NoiseContext::new(key.clone(), Bytes::from(router_id.to_vec())),
                    MockRuntime::register_metrics(vec![], None),
                );
                let GarlicDeliveryInstructions::Local { message } = garlic
                    .handle_message(message)
                    .unwrap()
                    .filter(|message| {
                        std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                    })
                    .collect::<VecDeque<_>>()
                    .pop_front()
                    .expect("to exist")
                else {
                    panic!("invalid type");
                };

                match message.message_type {
                    MessageType::DatabaseStore => {
                        let DatabaseStore { .. } =
                            DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();
                    }
                    _ => panic!("invalid message type"),
                }

                router_id
            }
            _ => panic!("unexpected tunnel message"),
        };

        // keep reading database lookups and ignore them until the lease set is republished
        loop {
            match tokio::time::timeout(Duration::from_secs(12), tm_rx.recv())
                .await
                .expect("no timeout")
                .expect("to succeed")
            {
                TunnelMessage::RouterDeliveryViaRoute {
                    outbound_tunnel: None,
                    router_id,
                    message,
                } => {
                    let message = Message::parse_standard(&message).unwrap();
                    assert_eq!(message.message_type, MessageType::Garlic);

                    let static_key = floodfills.get(&router_id).unwrap();

                    let mut garlic = GarlicHandler::<MockRuntime>::new(
                        NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                        MockRuntime::register_metrics(vec![], None),
                    );
                    let GarlicDeliveryInstructions::Local { message } = garlic
                        .handle_message(message)
                        .unwrap()
                        .filter(|message| {
                            std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                        })
                        .collect::<VecDeque<_>>()
                        .pop_front()
                        .expect("to exist")
                    else {
                        panic!("invalid type");
                    };

                    // ensure that database lookup was receveid but don't respond to it
                    match message.message_type {
                        MessageType::DatabaseLookup => {
                            let DatabaseLookup {
                                key: lookup_key, ..
                            } = DatabaseLookup::parse(&message.payload).unwrap();

                            assert_eq!(key.as_ref(), &lookup_key);
                        }
                        MessageType::DatabaseStore => {
                            // ensure the new publish is for some other floodfill
                            assert_ne!(original_floodfill, router_id);
                            break;
                        }
                        _ => panic!("invalid message type"),
                    }
                }
                _ => panic!("unexpected tunnel message"),
            }
        }
    }

    #[tokio::test]
    async fn lease_set_republished_after_running_out_of_floodfills() {
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let sender = tp_handle.sender();
        let (netdb_handle, netdb_rx) = NetDbHandle::create();
        let noise_ctx = NoiseContext::new(
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::from(RouterId::random().to_vec()),
        );
        let (lease_set, signing_key) = LeaseSet2::random();
        let tunnels = lease_set.leases.clone();
        let destination_id = lease_set.header.destination.id();
        let key = Bytes::from(destination_id.to_vec());
        let serialized = lease_set.serialize(&signing_key);
        let _manager = LeaseSetManager::<MockRuntime>::new(
            tunnels,
            destination_id,
            sender,
            netdb_handle,
            noise_ctx,
            ProfileStorage::new(&[], &[]),
            false,
            Bytes::from(serialized),
        );

        let floodfills = (0..5)
            .map(|_| {
                (
                    RouterId::random(),
                    StaticPrivateKey::random(MockRuntime::rng()),
                )
            })
            .collect::<HashMap<_, _>>();

        match tokio::time::timeout(Duration::from_secs(5), netdb_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            NetDbAction::GetClosestFloodfills { tx, .. } => {
                tx.send(
                    floodfills
                        .iter()
                        .map(|(router_id, key)| (router_id.clone(), key.public()))
                        .collect(),
                )
                .unwrap();
            }
            _ => panic!("invalid action received"),
        }

        // handle lease set store
        let original_floodfill = match tokio::time::timeout(Duration::from_secs(5), tm_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            TunnelMessage::RouterDeliveryViaRoute {
                outbound_tunnel: None,
                router_id,
                message,
            } => {
                let message = Message::parse_standard(&message).unwrap();
                assert_eq!(message.message_type, MessageType::Garlic);

                // remove the floodfill from the set of floodfills since is shouldn't be for
                // verification
                let key = floodfills.get(&router_id).unwrap();

                let mut garlic = GarlicHandler::<MockRuntime>::new(
                    NoiseContext::new(key.clone(), Bytes::from(router_id.to_vec())),
                    MockRuntime::register_metrics(vec![], None),
                );
                let GarlicDeliveryInstructions::Local { message } = garlic
                    .handle_message(message)
                    .unwrap()
                    .filter(|message| {
                        std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                    })
                    .collect::<VecDeque<_>>()
                    .pop_front()
                    .expect("to exist")
                else {
                    panic!("invalid type");
                };

                match message.message_type {
                    MessageType::DatabaseStore => {
                        let DatabaseStore { .. } =
                            DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();

                        router_id
                    }
                    _ => panic!("invalid message type"),
                }
            }
            _ => panic!("unexpected tunnel message"),
        };

        // keep reading database lookups and ignore them until the lease set is republished
        loop {
            match tokio::time::timeout(Duration::from_secs(12), tm_rx.recv())
                .await
                .expect("no timeout")
                .expect("to succeed")
            {
                TunnelMessage::RouterDeliveryViaRoute {
                    outbound_tunnel: None,
                    router_id,
                    message,
                } => {
                    let message = Message::parse_standard(&message).unwrap();
                    assert_eq!(message.message_type, MessageType::Garlic);

                    let static_key = floodfills.get(&router_id).unwrap();

                    let mut garlic = GarlicHandler::<MockRuntime>::new(
                        NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                        MockRuntime::register_metrics(vec![], None),
                    );
                    let GarlicDeliveryInstructions::Local { message } = garlic
                        .handle_message(message)
                        .unwrap()
                        .filter(|message| {
                            std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                        })
                        .collect::<VecDeque<_>>()
                        .pop_front()
                        .expect("to exist")
                    else {
                        panic!("invalid type");
                    };

                    // ensure that database lookup was receveid but don't respond to it
                    match message.message_type {
                        MessageType::DatabaseLookup => {
                            let DatabaseLookup {
                                key: lookup_key, ..
                            } = DatabaseLookup::parse(&message.payload).unwrap();

                            assert_eq!(key.as_ref(), &lookup_key);
                        }
                        MessageType::DatabaseStore => {
                            // ensure the new publish is for some other floodfill
                            assert_ne!(original_floodfill, router_id);
                            break;
                        }
                        _ => panic!("invalid message type"),
                    }
                }
                _ => panic!("unexpected tunnel message"),
            }
        }
    }

    #[tokio::test]
    async fn database_search_reply_with_locally_available_routers() {
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let sender = tp_handle.sender();
        let (netdb_handle, netdb_rx) = NetDbHandle::create();
        let noise_ctx = NoiseContext::new(
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::from(RouterId::random().to_vec()),
        );
        let (lease_set, signing_key) = LeaseSet2::random();
        let tunnels = lease_set.leases.clone();
        let destination_id = lease_set.header.destination.id();
        let key = Bytes::from(destination_id.to_vec());
        let serialized = lease_set.serialize(&signing_key);
        let profile_storage = ProfileStorage::new(&[], &[]);
        let manager = LeaseSetManager::<MockRuntime>::new(
            tunnels,
            destination_id,
            sender,
            netdb_handle,
            noise_ctx,
            profile_storage.clone(),
            false,
            Bytes::from(serialized),
        );

        let mut floodfills = (0..3)
            .map(|_| {
                (
                    RouterId::random(),
                    StaticPrivateKey::random(MockRuntime::rng()),
                )
            })
            .collect::<HashMap<_, _>>();
        let mut lookup_floodfills = floodfills.clone();

        match tokio::time::timeout(Duration::from_secs(5), netdb_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            NetDbAction::GetClosestFloodfills { tx, .. } => {
                tx.send(
                    floodfills
                        .iter()
                        .map(|(router_id, key)| (router_id.clone(), key.public()))
                        .collect(),
                )
                .unwrap();
            }
            _ => panic!("invalid action received"),
        }

        // handle lease set store
        match tokio::time::timeout(Duration::from_secs(5), tm_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            TunnelMessage::RouterDeliveryViaRoute {
                outbound_tunnel: None,
                router_id,
                message,
            } => {
                let message = Message::parse_standard(&message).unwrap();
                assert_eq!(message.message_type, MessageType::Garlic);

                // remove the floodfill from the set of floodfills since is shouldn't be for
                // verification
                let key = floodfills.get(&router_id).unwrap();
                assert!(lookup_floodfills.remove(&router_id).is_some());

                let mut garlic = GarlicHandler::<MockRuntime>::new(
                    NoiseContext::new(key.clone(), Bytes::from(router_id.to_vec())),
                    MockRuntime::register_metrics(vec![], None),
                );
                let GarlicDeliveryInstructions::Local { message } = garlic
                    .handle_message(message)
                    .unwrap()
                    .filter(|message| {
                        std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                    })
                    .collect::<VecDeque<_>>()
                    .pop_front()
                    .expect("to exist")
                else {
                    panic!("invalid type");
                };

                match message.message_type {
                    MessageType::DatabaseStore => {
                        let DatabaseStore { .. } =
                            DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();
                    }
                    _ => panic!("invalid message type"),
                }
            }
            _ => panic!("unexpected tunnel message"),
        }

        // read first database lookup and send database search reply
        match tokio::time::timeout(Duration::from_secs(12), tm_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            TunnelMessage::RouterDeliveryViaRoute {
                outbound_tunnel: None,
                router_id,
                message,
            } => {
                let message = Message::parse_standard(&message).unwrap();
                assert_eq!(message.message_type, MessageType::Garlic);

                let static_key = floodfills.get(&router_id).unwrap();
                assert!(lookup_floodfills.remove(&router_id).is_some());

                let mut garlic = GarlicHandler::<MockRuntime>::new(
                    NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                    MockRuntime::register_metrics(vec![], None),
                );
                let GarlicDeliveryInstructions::Local { message } = garlic
                    .handle_message(message)
                    .unwrap()
                    .filter(|message| {
                        std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                    })
                    .collect::<VecDeque<_>>()
                    .pop_front()
                    .expect("to exist")
                else {
                    panic!("invalid type");
                };

                // ensure that database lookup was receveid but don't respond to it
                match message.message_type {
                    MessageType::DatabaseLookup => {
                        let DatabaseLookup {
                            key: lookup_key, ..
                        } = DatabaseLookup::parse(&message.payload).unwrap();

                        assert_eq!(key.as_ref(), &lookup_key);

                        // send database search reply with random routers
                        let floodfills = (0..2)
                            .map(|_| {
                                let (floodfill, static_key, _) =
                                    RouterInfoBuilder::default().as_floodfill().build();
                                let router_id = floodfill.identity.id();

                                floodfills.insert(router_id.clone(), static_key.clone());
                                lookup_floodfills.insert(router_id.clone(), static_key);
                                profile_storage.add_router(floodfill);

                                router_id
                            })
                            .collect();

                        manager.register_database_search_reply(lookup_key, floodfills);
                    }
                    _ => panic!("invalid message type"),
                }
            }
            _ => panic!("unexpected tunnel message"),
        }

        // keep reading database lookups and ignore them until the lease set is republished
        loop {
            match tokio::time::timeout(Duration::from_secs(12), tm_rx.recv())
                .await
                .expect("no timeout")
                .expect("to succeed")
            {
                TunnelMessage::RouterDeliveryViaRoute {
                    outbound_tunnel: None,
                    router_id,
                    message,
                } => {
                    let message = Message::parse_standard(&message).unwrap();
                    assert_eq!(message.message_type, MessageType::Garlic);

                    let static_key = floodfills.get(&router_id).unwrap();
                    let _ = lookup_floodfills.remove(&router_id);

                    let mut garlic = GarlicHandler::<MockRuntime>::new(
                        NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                        MockRuntime::register_metrics(vec![], None),
                    );
                    let GarlicDeliveryInstructions::Local { message } = garlic
                        .handle_message(message)
                        .unwrap()
                        .filter(|message| {
                            std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                        })
                        .collect::<VecDeque<_>>()
                        .pop_front()
                        .expect("to exist")
                    else {
                        panic!("invalid type");
                    };

                    // ensure that database lookup was receveid but don't respond to it
                    match message.message_type {
                        MessageType::DatabaseLookup => {
                            let DatabaseLookup {
                                key: lookup_key, ..
                            } = DatabaseLookup::parse(&message.payload).unwrap();

                            assert_eq!(key.as_ref(), &lookup_key);
                        }
                        MessageType::DatabaseStore => {
                            assert!(lookup_floodfills.is_empty());
                            break;
                        }
                        _ => panic!("invalid message type"),
                    }
                }
                _ => panic!("unexpected tunnel message"),
            }
        }
    }

    #[tokio::test]
    async fn router_info_lookup_started_for_new_floodfills_all_queries_succeed() {
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let sender = tp_handle.sender();
        let (netdb_handle, netdb_rx) = NetDbHandle::create();
        let noise_ctx = NoiseContext::new(
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::from(RouterId::random().to_vec()),
        );
        let (lease_set, signing_key) = LeaseSet2::random();
        let tunnels = lease_set.leases.clone();
        let destination_id = lease_set.header.destination.id();
        let key = Bytes::from(destination_id.to_vec());
        let serialized = lease_set.serialize(&signing_key);
        let profile_storage = ProfileStorage::new(&[], &[]);
        let manager = LeaseSetManager::<MockRuntime>::new(
            tunnels,
            destination_id,
            sender,
            netdb_handle,
            noise_ctx,
            profile_storage.clone(),
            false,
            Bytes::from(serialized),
        );

        let mut floodfills = (0..3)
            .map(|_| {
                (
                    RouterId::random(),
                    StaticPrivateKey::random(MockRuntime::rng()),
                )
            })
            .collect::<HashMap<_, _>>();
        let mut lookup_floodfills = floodfills.clone();
        let mut new_floodfills = HashMap::<RouterId, (RouterInfo, StaticPrivateKey)>::new();

        match tokio::time::timeout(Duration::from_secs(5), netdb_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            NetDbAction::GetClosestFloodfills { tx, .. } => {
                tx.send(
                    floodfills
                        .iter()
                        .map(|(router_id, key)| (router_id.clone(), key.public()))
                        .collect(),
                )
                .unwrap();
            }
            _ => panic!("invalid action received"),
        }

        // handle lease set store
        match tokio::time::timeout(Duration::from_secs(5), tm_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            TunnelMessage::RouterDeliveryViaRoute {
                outbound_tunnel: None,
                router_id,
                message,
            } => {
                let message = Message::parse_standard(&message).unwrap();
                assert_eq!(message.message_type, MessageType::Garlic);

                // remove the floodfill from the set of floodfills since is shouldn't be for
                // verification
                let key = floodfills.get(&router_id).unwrap();
                assert!(lookup_floodfills.remove(&router_id).is_some());

                let mut garlic = GarlicHandler::<MockRuntime>::new(
                    NoiseContext::new(key.clone(), Bytes::from(router_id.to_vec())),
                    MockRuntime::register_metrics(vec![], None),
                );
                let GarlicDeliveryInstructions::Local { message } = garlic
                    .handle_message(message)
                    .unwrap()
                    .filter(|message| {
                        std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                    })
                    .collect::<VecDeque<_>>()
                    .pop_front()
                    .expect("to exist")
                else {
                    panic!("invalid type");
                };

                match message.message_type {
                    MessageType::DatabaseStore => {
                        let DatabaseStore { .. } =
                            DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();
                    }
                    _ => panic!("invalid message type"),
                }
            }
            _ => panic!("unexpected tunnel message"),
        }

        // read first database lookup and send database search reply
        match tokio::time::timeout(Duration::from_secs(12), tm_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            TunnelMessage::RouterDeliveryViaRoute {
                outbound_tunnel: None,
                router_id,
                message,
            } => {
                let message = Message::parse_standard(&message).unwrap();
                assert_eq!(message.message_type, MessageType::Garlic);

                let static_key = floodfills.get(&router_id).unwrap();
                assert!(lookup_floodfills.remove(&router_id).is_some());

                let mut garlic = GarlicHandler::<MockRuntime>::new(
                    NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                    MockRuntime::register_metrics(vec![], None),
                );
                let GarlicDeliveryInstructions::Local { message } = garlic
                    .handle_message(message)
                    .unwrap()
                    .filter(|message| {
                        std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                    })
                    .collect::<VecDeque<_>>()
                    .pop_front()
                    .expect("to exist")
                else {
                    panic!("invalid type");
                };

                // ensure that database lookup was receveid but don't respond to it
                match message.message_type {
                    MessageType::DatabaseLookup => {
                        let DatabaseLookup {
                            key: lookup_key, ..
                        } = DatabaseLookup::parse(&message.payload).unwrap();

                        assert_eq!(key.as_ref(), &lookup_key);

                        // send database search reply with random routers but don't add them to
                        // profile storage meaning `LeaseSetPublishe` must issue RI lookups for
                        // these floodfills
                        let floodfills = (0..2)
                            .map(|_| {
                                let (floodfill, static_key, _) =
                                    RouterInfoBuilder::default().as_floodfill().build();
                                let router_id = floodfill.identity.id();
                                new_floodfills.insert(router_id.clone(), (floodfill, static_key));

                                router_id
                            })
                            .collect();

                        manager.register_database_search_reply(lookup_key, floodfills);
                    }
                    _ => panic!("invalid message type"),
                }
            }
            _ => panic!("unexpected tunnel message"),
        }

        // keep reading DBLs and respond to router queries with the router info
        loop {
            tokio::select! {
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                        let static_key = floodfills.get(&router_id).unwrap();

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        // ensure that database lookup was receveid but don't respond to it
                        match message.message_type {
                            MessageType::DatabaseLookup => {
                                let DatabaseLookup {
                                    key: lookup_key,
                                    lookup,
                                    ..
                                } = DatabaseLookup::parse(&message.payload).unwrap();

                                assert_eq!(lookup, LookupType::LeaseSet);
                                assert_eq!(key.as_ref(), &lookup_key);
                                assert!(lookup_floodfills.remove(&router_id).is_some());
                            }
                            MessageType::DatabaseStore => {
                                assert!(lookup_floodfills.is_empty());
                                break;
                            }
                            _ => panic!("invalid message type"),
                        }
                    }
                    _ => panic!("unexpected tunnel message"),
                },
                event = netdb_rx.recv() => match event.unwrap() {
                    NetDbAction::QueryRouterInfo { router_id, tx } => {
                        let (router_info, static_key) = new_floodfills.remove(&router_id).unwrap();

                        floodfills.insert(router_id.clone(), static_key.clone());
                        lookup_floodfills.insert(router_id.clone(), static_key.clone());
                        profile_storage.add_router(router_info);

                        tx.send(Ok(())).unwrap();
                    }
                    _ => panic!("unexpected netdb action"),
                },
                _ = tokio::time::sleep(Duration::from_secs(12)) => {
                    panic!("unexpected timeout");
                }
            }
        }
    }

    #[tokio::test]
    async fn router_info_lookup_started_for_new_floodfills_one_query_succeeds() {
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let sender = tp_handle.sender();
        let (netdb_handle, netdb_rx) = NetDbHandle::create();
        let noise_ctx = NoiseContext::new(
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::from(RouterId::random().to_vec()),
        );
        let (lease_set, signing_key) = LeaseSet2::random();
        let tunnels = lease_set.leases.clone();
        let destination_id = lease_set.header.destination.id();
        let key = Bytes::from(destination_id.to_vec());
        let serialized = lease_set.serialize(&signing_key);
        let profile_storage = ProfileStorage::new(&[], &[]);
        let manager = LeaseSetManager::<MockRuntime>::new(
            tunnels,
            destination_id,
            sender,
            netdb_handle,
            noise_ctx,
            profile_storage.clone(),
            false,
            Bytes::from(serialized),
        );

        let mut floodfills = (0..3)
            .map(|_| {
                (
                    RouterId::random(),
                    StaticPrivateKey::random(MockRuntime::rng()),
                )
            })
            .collect::<HashMap<_, _>>();
        let mut lookup_floodfills = floodfills.clone();
        let mut new_floodfills = HashMap::<RouterId, (RouterInfo, StaticPrivateKey)>::new();

        match tokio::time::timeout(Duration::from_secs(5), netdb_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            NetDbAction::GetClosestFloodfills { tx, .. } => {
                tx.send(
                    floodfills
                        .iter()
                        .map(|(router_id, key)| (router_id.clone(), key.public()))
                        .collect(),
                )
                .unwrap();
            }
            _ => panic!("invalid action received"),
        }

        // handle lease set store
        match tokio::time::timeout(Duration::from_secs(5), tm_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            TunnelMessage::RouterDeliveryViaRoute {
                outbound_tunnel: None,
                router_id,
                message,
            } => {
                let message = Message::parse_standard(&message).unwrap();
                assert_eq!(message.message_type, MessageType::Garlic);

                // remove the floodfill from the set of floodfills since is shouldn't be for
                // verification
                let key = floodfills.get(&router_id).unwrap();
                assert!(lookup_floodfills.remove(&router_id).is_some());

                let mut garlic = GarlicHandler::<MockRuntime>::new(
                    NoiseContext::new(key.clone(), Bytes::from(router_id.to_vec())),
                    MockRuntime::register_metrics(vec![], None),
                );
                let GarlicDeliveryInstructions::Local { message } = garlic
                    .handle_message(message)
                    .unwrap()
                    .filter(|message| {
                        std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                    })
                    .collect::<VecDeque<_>>()
                    .pop_front()
                    .expect("to exist")
                else {
                    panic!("invalid type");
                };

                match message.message_type {
                    MessageType::DatabaseStore => {
                        let DatabaseStore { .. } =
                            DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();
                    }
                    _ => panic!("invalid message type"),
                }
            }
            _ => panic!("unexpected tunnel message"),
        }

        // read first database lookup and send database search reply
        match tokio::time::timeout(Duration::from_secs(12), tm_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            TunnelMessage::RouterDeliveryViaRoute {
                outbound_tunnel: None,
                router_id,
                message,
            } => {
                let message = Message::parse_standard(&message).unwrap();
                assert_eq!(message.message_type, MessageType::Garlic);

                let static_key = floodfills.get(&router_id).unwrap();
                assert!(lookup_floodfills.remove(&router_id).is_some());

                let mut garlic = GarlicHandler::<MockRuntime>::new(
                    NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                    MockRuntime::register_metrics(vec![], None),
                );
                let GarlicDeliveryInstructions::Local { message } = garlic
                    .handle_message(message)
                    .unwrap()
                    .filter(|message| {
                        std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                    })
                    .collect::<VecDeque<_>>()
                    .pop_front()
                    .expect("to exist")
                else {
                    panic!("invalid type");
                };

                // ensure that database lookup was receveid but don't respond to it
                match message.message_type {
                    MessageType::DatabaseLookup => {
                        let DatabaseLookup {
                            key: lookup_key, ..
                        } = DatabaseLookup::parse(&message.payload).unwrap();

                        assert_eq!(key.as_ref(), &lookup_key);

                        // send database search reply with random routers but don't add them to
                        // profile storage meaning `LeaseSetPublishe` must issue RI lookups for
                        // these floodfills
                        let floodfills = (0..3)
                            .map(|_| {
                                let (floodfill, static_key, _) =
                                    RouterInfoBuilder::default().as_floodfill().build();
                                let router_id = floodfill.identity.id();
                                new_floodfills.insert(router_id.clone(), (floodfill, static_key));

                                router_id
                            })
                            .collect();

                        manager.register_database_search_reply(lookup_key, floodfills);
                    }
                    _ => panic!("invalid message type"),
                }
            }
            _ => panic!("unexpected tunnel message"),
        }

        // keep reading DBLs and respond to router queries with the router info
        loop {
            tokio::select! {
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                        let static_key = floodfills.get(&router_id).unwrap();

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        // ensure that database lookup was receveid but don't respond to it
                        match message.message_type {
                            MessageType::DatabaseLookup => {
                                let DatabaseLookup {
                                    key: lookup_key,
                                    lookup,
                                    ..
                                } = DatabaseLookup::parse(&message.payload).unwrap();

                                assert_eq!(lookup, LookupType::LeaseSet);
                                assert_eq!(key.as_ref(), &lookup_key);
                                assert!(lookup_floodfills.remove(&router_id).is_some());
                            }
                            MessageType::DatabaseStore => {
                                assert!(lookup_floodfills.is_empty());
                                break;
                            }
                            _ => panic!("invalid message type"),
                        }
                    }
                    _ => panic!("unexpected tunnel message"),
                },
                event = netdb_rx.recv() => match event.unwrap() {
                    NetDbAction::QueryRouterInfo { router_id, tx } => {
                        // only respond to the first query and let the two others timeout
                        if new_floodfills.len() == 3 {
                            let (router_info, static_key) = new_floodfills.remove(&router_id).unwrap();

                            floodfills.insert(router_id.clone(), static_key.clone());
                            lookup_floodfills.insert(router_id.clone(), static_key.clone());
                            profile_storage.add_router(router_info);

                            tx.send(Ok(())).unwrap();
                        } else {
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_secs(15)).await;
                                tx.send(Err(QueryError::Timeout)).unwrap();
                            });
                        }

                    }
                    _ => panic!("unexpected netdb action"),
                },
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    panic!("unexpected timeout");
                }
            }
        }
    }

    #[tokio::test]
    async fn router_info_lookups_fail_lease_set_republished() {
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let sender = tp_handle.sender();
        let (netdb_handle, netdb_rx) = NetDbHandle::create();
        let noise_ctx = NoiseContext::new(
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::from(RouterId::random().to_vec()),
        );
        let (lease_set, signing_key) = LeaseSet2::random();
        let tunnels = lease_set.leases.clone();
        let destination_id = lease_set.header.destination.id();
        let key = Bytes::from(destination_id.to_vec());
        let serialized = lease_set.serialize(&signing_key);
        let profile_storage = ProfileStorage::new(&[], &[]);
        let manager = LeaseSetManager::<MockRuntime>::new(
            tunnels,
            destination_id,
            sender,
            netdb_handle,
            noise_ctx,
            profile_storage.clone(),
            false,
            Bytes::from(serialized),
        );

        let floodfills = (0..3)
            .map(|_| {
                (
                    RouterId::random(),
                    StaticPrivateKey::random(MockRuntime::rng()),
                )
            })
            .collect::<HashMap<_, _>>();
        let mut lookup_floodfills = floodfills.clone();
        let mut new_floodfills = HashMap::<RouterId, (RouterInfo, StaticPrivateKey)>::new();

        match tokio::time::timeout(Duration::from_secs(5), netdb_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            NetDbAction::GetClosestFloodfills { tx, .. } => {
                tx.send(
                    floodfills
                        .iter()
                        .map(|(router_id, key)| (router_id.clone(), key.public()))
                        .collect(),
                )
                .unwrap();
            }
            _ => panic!("invalid action received"),
        }

        // handle lease set store
        match tokio::time::timeout(Duration::from_secs(5), tm_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            TunnelMessage::RouterDeliveryViaRoute {
                outbound_tunnel: None,
                router_id,
                message,
            } => {
                let message = Message::parse_standard(&message).unwrap();
                assert_eq!(message.message_type, MessageType::Garlic);

                // remove the floodfill from the set of floodfills since is shouldn't be for
                // verification
                let key = floodfills.get(&router_id).unwrap();
                assert!(lookup_floodfills.remove(&router_id).is_some());

                let mut garlic = GarlicHandler::<MockRuntime>::new(
                    NoiseContext::new(key.clone(), Bytes::from(router_id.to_vec())),
                    MockRuntime::register_metrics(vec![], None),
                );
                let GarlicDeliveryInstructions::Local { message } = garlic
                    .handle_message(message)
                    .unwrap()
                    .filter(|message| {
                        std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                    })
                    .collect::<VecDeque<_>>()
                    .pop_front()
                    .expect("to exist")
                else {
                    panic!("invalid type");
                };

                match message.message_type {
                    MessageType::DatabaseStore => {
                        let DatabaseStore { .. } =
                            DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();
                    }
                    _ => panic!("invalid message type"),
                }
            }
            _ => panic!("unexpected tunnel message"),
        }

        // read first database lookup and send database search reply
        match tokio::time::timeout(Duration::from_secs(12), tm_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            TunnelMessage::RouterDeliveryViaRoute {
                outbound_tunnel: None,
                router_id,
                message,
            } => {
                let message = Message::parse_standard(&message).unwrap();
                assert_eq!(message.message_type, MessageType::Garlic);

                let static_key = floodfills.get(&router_id).unwrap();
                assert!(lookup_floodfills.remove(&router_id).is_some());

                let mut garlic = GarlicHandler::<MockRuntime>::new(
                    NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                    MockRuntime::register_metrics(vec![], None),
                );
                let GarlicDeliveryInstructions::Local { message } = garlic
                    .handle_message(message)
                    .unwrap()
                    .filter(|message| {
                        std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                    })
                    .collect::<VecDeque<_>>()
                    .pop_front()
                    .expect("to exist")
                else {
                    panic!("invalid type");
                };

                // ensure that database lookup was receveid but don't respond to it
                match message.message_type {
                    MessageType::DatabaseLookup => {
                        let DatabaseLookup {
                            key: lookup_key, ..
                        } = DatabaseLookup::parse(&message.payload).unwrap();

                        assert_eq!(key.as_ref(), &lookup_key);

                        // send database search reply with random routers but don't add them to
                        // profile storage meaning `LeaseSetPublishe` must issue RI lookups for
                        // these floodfills
                        let floodfills = (0..3)
                            .map(|_| {
                                let (floodfill, static_key, _) =
                                    RouterInfoBuilder::default().as_floodfill().build();
                                let router_id = floodfill.identity.id();
                                new_floodfills.insert(router_id.clone(), (floodfill, static_key));

                                router_id
                            })
                            .collect();

                        manager.register_database_search_reply(lookup_key, floodfills);
                    }
                    _ => panic!("invalid message type"),
                }
            }
            _ => panic!("unexpected tunnel message"),
        }

        // keep reading DBLs and respond to router queries with the router info
        loop {
            tokio::select! {
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                        let static_key = floodfills.get(&router_id).unwrap();

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        // ensure that database lookup was receveid but don't respond to it
                        match message.message_type {
                            MessageType::DatabaseLookup => {
                                let DatabaseLookup {
                                    key: lookup_key,
                                    lookup,
                                    ..
                                } = DatabaseLookup::parse(&message.payload).unwrap();

                                assert_eq!(lookup, LookupType::LeaseSet);
                                assert_eq!(key.as_ref(), &lookup_key);
                                assert!(lookup_floodfills.remove(&router_id).is_some());
                            }
                            MessageType::DatabaseStore => {
                                assert!(lookup_floodfills.is_empty());
                                break;
                            }
                            _ => panic!("invalid message type"),
                        }
                    }
                    _ => panic!("unexpected tunnel message"),
                },
                event = netdb_rx.recv() => match event.unwrap() {
                    NetDbAction::QueryRouterInfo { router_id, tx } => {
                        let _ = new_floodfills.remove(&router_id);
                        let sleep = Duration::from_secs((new_floodfills.len() + 1) as u64 * 2);

                        tokio::spawn(async move {
                            tokio::time::sleep(sleep).await;
                            tx.send(Err(QueryError::Timeout)).unwrap();
                        });
                    }
                    _ => panic!("unexpected netdb action"),
                },
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    panic!("unexpected timeout");
                }
            }
        }
    }

    #[tokio::test]
    async fn inbound_tunnel_registered() {
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let sender = tp_handle.sender();
        let (netdb_handle, _netdb_rx) = NetDbHandle::create();
        let noise_ctx = NoiseContext::new(
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::from(RouterId::random().to_vec()),
        );
        let mut manager = LeaseSetManager::<MockRuntime>::new(
            vec![Lease::random()],
            DestinationId::random(),
            sender,
            netdb_handle,
            noise_ctx,
            ProfileStorage::new(&[], &[]),
            true,
            Bytes::from(vec![1, 2, 3, 4]),
        );

        assert!(core::matches!(manager.state, PublishState::Inactive));
        assert_eq!(manager.tunnels.len(), 1);

        manager.register_inbound_tunnel(Lease::random());
        assert!(core::matches!(
            manager.state,
            PublishState::WaitingForInboundTunnels { .. }
        ));
        assert_eq!(manager.tunnels.len(), 2);

        manager.register_inbound_tunnel(Lease::random());
        assert!(core::matches!(
            manager.state,
            PublishState::WaitingForInboundTunnels { .. }
        ));
        assert_eq!(manager.tunnels.len(), 3);

        let leases = tokio::time::timeout(REPUBLISH_TIMEOUT + Duration::from_secs(2), &mut manager)
            .await
            .expect("no timeout");
        assert_eq!(leases.len(), 3);
    }

    #[tokio::test]
    async fn inbound_tunnel_expires() {
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let sender = tp_handle.sender();
        let (netdb_handle, _netdb_rx) = NetDbHandle::create();
        let noise_ctx = NoiseContext::new(
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::from(RouterId::random().to_vec()),
        );
        let mut manager = LeaseSetManager::<MockRuntime>::new(
            vec![Lease::random()],
            DestinationId::random(),
            sender,
            netdb_handle,
            noise_ctx,
            ProfileStorage::new(&[], &[]),
            true,
            Bytes::from(vec![1, 2, 3, 4]),
        );

        assert!(core::matches!(manager.state, PublishState::Inactive));
        assert_eq!(manager.tunnels.len(), 1);

        manager.register_inbound_tunnel(Lease::random());
        assert!(core::matches!(
            manager.state,
            PublishState::WaitingForInboundTunnels { .. }
        ));
        assert_eq!(manager.tunnels.len(), 2);

        manager.register_inbound_tunnel(Lease::random());
        assert!(core::matches!(
            manager.state,
            PublishState::WaitingForInboundTunnels { .. }
        ));
        assert_eq!(manager.tunnels.len(), 3);

        let leases = tokio::time::timeout(REPUBLISH_TIMEOUT + Duration::from_secs(2), &mut manager)
            .await
            .expect("no timeout")
            .into_iter()
            .map(|lease| lease.tunnel_id)
            .collect::<HashSet<_>>();
        assert_eq!(leases.len(), 3);

        // two new inbound tunnels are built
        manager.register_inbound_tunnel(Lease::random());
        manager.register_inbound_tunnel(Lease::random());

        // all original inbound tunnels expire
        for tunnel_id in &leases {
            manager.register_expired_inbound_tunnel(*tunnel_id);
        }

        // wait until the new lease set is published and verify that the expired tunnels no longer
        // exist
        let new_leases =
            tokio::time::timeout(REPUBLISH_TIMEOUT + Duration::from_secs(2), &mut manager)
                .await
                .expect("no timeout");
        assert_eq!(new_leases.len(), 2);
        assert!(new_leases.iter().all(|lease| !leases.contains(&lease.tunnel_id)));
    }
}
