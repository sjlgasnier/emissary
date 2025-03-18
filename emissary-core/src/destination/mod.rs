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
    crypto::{base32_encode, chachapoly::ChaChaPoly, EphemeralPrivateKey, StaticPrivateKey},
    destination::{
        lease_set::LeaseSetManager,
        routing_path::{
            PendingRoutingPathHandle, RoutingPath, RoutingPathHandle, RoutingPathManager,
        },
        session::{SessionManager, SessionManagerEvent},
    },
    error::{Error, QueryError},
    i2np::{
        database::{
            lookup::{DatabaseLookupBuilder, LookupType, ReplyType as LookupReplyType},
            search_reply::DatabaseSearchReply,
            store::{
                DatabaseStore, DatabaseStoreBuilder, DatabaseStoreKind, DatabaseStorePayload,
                ReplyType,
            },
        },
        delivery_status::DeliveryStatus,
        garlic::{DeliveryInstructions, GarlicMessageBuilder},
        Message, MessageBuilder, MessageType, I2NP_MESSAGE_EXPIRATION,
    },
    netdb::NetDbHandle,
    primitives::{DestinationId, Lease, LeaseSet2, MessageId, RouterId, TunnelId},
    runtime::{JoinSet, Runtime},
    tunnel::{NoiseContext, TunnelPoolEvent, TunnelPoolHandle},
};

use bytes::{BufMut, Bytes, BytesMut};
use futures::{future::BoxFuture, FutureExt, Stream, StreamExt};
use hashbrown::{HashMap, HashSet};
use rand_core::RngCore;

use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
use core::{
    mem,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};

mod lease_set;

pub mod routing_path;
pub mod session;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::destination";

/// How long should [`Destination`] wait before attempting to recontact [`NetDb`]
/// after the previous call was rejected.
const NETDB_BACKOFF_TIMEOUT: Duration = Duration::from_secs(5);

/// Number of retries before lease set query is aborted.
///
/// This is the number retries made when trying to contact [`NetDb`] for a lease set query
/// in case the channel used by [`NetDbHandle`] is clogged.
const NUM_QUERY_RETRIES: usize = 3usize;

/// Stale lease set prune interval.
const LEASE_SET_PRUNE_INTERVAL: Duration = Duration::from_secs(2 * 60);

/// How the message should be delivered to remote destination.
#[derive(Default, Clone)]
pub enum DeliveryStyle {
    /// Deliver the message to remote using the explicitly specified routing path.
    ViaRoute {
        /// Routing path.
        routing_path: RoutingPath,
    },

    /// Deliver the message to remote via any available route.
    Unspecified {
        /// ID of the remote destination.
        destination_id: DestinationId,
    },

    #[default]
    Dummy,
}

impl DeliveryStyle {
    /// Get reference to [`DestinationId`].
    pub fn destination_id(&self) -> &DestinationId {
        match self {
            Self::ViaRoute { routing_path } => &routing_path.destination_id,
            Self::Unspecified { destination_id } => destination_id,
            Self::Dummy => unreachable!(),
        }
    }
}

/// Events emitted by [`Destination`].
#[derive(Debug)]
pub enum DestinationEvent {
    /// One or more messages received.
    Messages {
        /// One or more I2NP Data messages.
        messages: Vec<Vec<u8>>,
    },

    /// Lease set of the remote found in NetDb.
    LeaseSetFound {
        /// ID of the remote destination.
        destination_id: DestinationId,
    },

    /// Lease set of the remote not found in NetDb.
    LeaseSetNotFound {
        /// ID of the remote destination.
        destination_id: DestinationId,

        /// Query error.
        error: QueryError,
    },

    /// Tunnel pool shut down.
    TunnelPoolShutDown,

    /// Create new lease set from leases.
    CreateLeaseSet {
        /// Leases.
        leases: Vec<Lease>,
    },

    /// Session with remote destination has been termianted.
    SessionTerminated {
        /// ID of the remote destination.
        destination_id: DestinationId,
    },
}

/// Lease set status of remote destination.
///
/// Remote's lease set must exist in [`Destination`] in order to send message to them.
#[derive(Debug, PartialEq, Eq)]
pub enum LeaseSetStatus {
    /// [`LeaseSet2`] for destination found in [`Destination`].
    ///
    /// Caller doesn't need to buffer messages and wait for the query to finish.
    Found,

    /// [`LeaseSet2`] for destination not found in [`Destination`].
    ///
    /// Query will be started in the backgroun and the caller is notified
    /// of the query result via [`Destination::poll_next()`].
    NotFound,

    /// Query for destination's [`LeaseSet2`] is pending.
    Pending,
}

/// Context associated with a remote destination.
pub struct DestinationContext {
    /// Lease set.
    lease_set: LeaseSet2,

    /// Pending messages, if any.
    ///
    /// Outbound messages are put on hold if remote lease set has expired
    /// and a new lease set is being queried.
    pending_messages: VecDeque<Vec<u8>>,

    /// Expiring lease sets.
    ///
    /// Some routing paths may still use these lease sets if they haven't expired and since the
    /// `RoutingPath` doesn't hold the `RouterId` of the lease set, these lease sets are stored
    /// separately.
    ///
    /// The stale lease sets are periodically pruned at an interval of `LEASE_SET_PRUNE_INTERVAL`.
    expiring_leases: HashMap<TunnelId, Lease>,
}

/// Client destination.
pub struct Destination<R: Runtime> {
    /// Destination ID of the client.
    destination_id: DestinationId,

    /// Active inbound tunnels.
    inbound_tunnels: Vec<Lease>,

    /// Serialized [`LeaseSet2`] for client's inbound tunnels.
    #[allow(unused)]
    lease_set: Bytes,

    /// Local lease set manager.
    lease_set_manager: LeaseSetManager<R>,

    /// Timer for periodic pruning of stale lease sets.
    lease_set_prune_timer: BoxFuture<'static, ()>,

    /// Handle to [`NetDb`].
    netdb_handle: NetDbHandle,

    /// Noise context.
    noise: NoiseContext,

    /// Active outbound tunnels.
    outbound_tunnels: Vec<TunnelId>,

    // /// Inbound tunnels waiting to be published to `NetDb`.
    // pending_inbound: Vec<(Lease, R::Instant)>,
    /// Pending lease set queries:
    pending_queries: HashSet<DestinationId>,

    /// Pending lease set storage verification(s).
    ///
    /// Realistically this has only one entry, unless the network is lagging.
    pending_storage_verifications: HashMap<Bytes, R::Instant>,

    /// Pending `LeaseSet2` query futures.
    query_futures: R::JoinSet<(DestinationId, Result<LeaseSet2, QueryError>)>,

    /// Known remote destinations.
    remote_destinations: HashMap<DestinationId, DestinationContext>,

    /// Routing path manager.
    routing_path_manager: RoutingPathManager<R>,

    /// Session manager.
    session_manager: SessionManager<R>,

    /// Handle to destination's [`TunnelPool`].
    tunnel_pool_handle: TunnelPoolHandle,

    /// Is the destination unpublished, i.e., does the lease set get published to `NetDb`.
    unpublished: bool,

    /// Waker.
    waker: Option<Waker>,
}

impl<R: Runtime> Destination<R> {
    /// Create new [`Destination`].
    ///
    /// `private_key` is the private key of the client destination and `lease`
    /// is a serialized [`LeaseSet2`] for the client's inbound tunnel(s).
    pub fn new(
        destination_id: DestinationId,
        private_key: StaticPrivateKey,
        lease_set: Bytes,
        netdb_handle: NetDbHandle,
        tunnel_pool_handle: TunnelPoolHandle,
        outbound_tunnels: Vec<TunnelId>,
        inbound_tunnels: Vec<Lease>,
        unpublished: bool,
    ) -> Self {
        Self {
            destination_id: destination_id.clone(),
            inbound_tunnels: inbound_tunnels.clone(),
            lease_set: lease_set.clone(),
            lease_set_manager: LeaseSetManager::new(inbound_tunnels),
            lease_set_prune_timer: Box::pin(R::delay(LEASE_SET_PRUNE_INTERVAL)),
            netdb_handle,
            noise: NoiseContext::new(private_key.clone(), Bytes::from(destination_id.to_vec())),
            outbound_tunnels: outbound_tunnels.clone(),
            pending_queries: HashSet::new(),
            pending_storage_verifications: HashMap::new(),
            query_futures: R::join_set(),
            remote_destinations: HashMap::new(),
            routing_path_manager: RoutingPathManager::new(destination_id.clone(), outbound_tunnels),
            session_manager: SessionManager::new(destination_id, private_key, lease_set),
            tunnel_pool_handle,
            unpublished,
            waker: None,
        }
    }

    /// Look up lease set status of remote destination.
    ///
    /// Before sending a message to remote, the caller must ensure [`Destination`] holds a valid
    /// lease for the remote destination. This needs to be done only once, when sending the first
    /// message to remote destination. If this function is called when there is no active lease set
    /// for `destination`, a lease set query is started in the background and its result can be
    /// polled via [`Destinatin::poll_next()`].
    ///
    /// If this function returns [`LeaseSetStatus::Found`], [`Destination::send_message()`] can be
    /// called as the remote is reachable. If it returns [`LeaseStatus::NotFound`] or
    /// [`LeaseStatus::Pending`], the caller must wait until [`Destination`] emits
    /// [`DestinationEvent::LeaseSetFound`], indicating that a lease set is foun and the remote
    /// destination is reachable.
    pub fn query_lease_set(&mut self, destination_id: &DestinationId) -> LeaseSetStatus {
        if self.pending_queries.contains(destination_id) {
            return LeaseSetStatus::Pending;
        }

        if let Some(context) = self.remote_destinations.get(destination_id) {
            if !context.lease_set.is_expired::<R>() {
                return LeaseSetStatus::Found;
            }

            tracing::debug!(
                target: LOG_TARGET,
                %destination_id,
                "lease set found but it's expired",
            );
        }

        tracing::trace!(
            target: LOG_TARGET,
            %destination_id,
            "lookup destination",
        );

        let handle = self.netdb_handle.clone();
        let destination_id = destination_id.clone();

        self.pending_queries.insert(destination_id.clone());
        self.query_futures.push(async move {
            for _ in 0..NUM_QUERY_RETRIES {
                let Ok(rx) = handle.query_lease_set(Bytes::from(destination_id.to_vec())) else {
                    R::delay(NETDB_BACKOFF_TIMEOUT).await;
                    continue;
                };

                tracing::trace!(
                    target: LOG_TARGET,
                    %destination_id,
                    "lease set query started",
                );

                match rx.await {
                    Err(_) => return (destination_id, Err(QueryError::Timeout)),
                    Ok(Err(error)) => return (destination_id, Err(error)),
                    Ok(Ok(lease_set)) => return (destination_id, Ok(lease_set)),
                }
            }

            tracing::warn!(
                target: LOG_TARGET,
                %destination_id,
                "failed to start lease set query after {NUM_QUERY_RETRIES} retries",
            );

            (destination_id, Err(QueryError::RetryFailure))
        });

        LeaseSetStatus::NotFound
    }

    /// Get reference to a [`LeaseSet2`] of the destination identified by `destination_id`.
    ///
    /// Caller must calle [`Destination::query_lease_set()`] and get a return value of
    /// [`LeaseSetStatus::Found`] before calling this function.
    pub fn lease_set(&self, destination_id: &DestinationId) -> &LeaseSet2 {
        &self.remote_destinations.get(destination_id).expect("to exist").lease_set
    }

    /// Send encrypted `message` to remote `destination`.
    ///
    /// Lease set for the remote destination must exist in [`Destination`], otherwise the call is
    /// rejected. Lease set can be queried with [`Destination::query_lease_set()`] which returns a
    /// result indicating whether the remote is "reachable" right now.
    ///
    /// After the message has been encrypted, it's sent to remote destination via one of the
    /// outbound tunnels of [`Destination`].
    fn send_message_inner(
        &mut self,
        delivery_style: DeliveryStyle,
        message: Vec<u8>,
    ) -> crate::Result<()> {
        let Some(context) = self.remote_destinations.get_mut(delivery_style.destination_id())
        else {
            tracing::warn!(
                target: LOG_TARGET,
                local = %self.destination_id,
                remote = %delivery_style.destination_id(),
                "`Destination::encrypt()` called but lease set is missing",
            );
            debug_assert!(false);
            return Err(Error::InvalidState);
        };

        // if remote lease set is expired, mark `message` as pending and start lease set query
        if context.lease_set.is_expired::<R>() {
            tracing::debug!(
                target: LOG_TARGET,
                local = %self.destination_id,
                remote = %delivery_style.destination_id(),
                "postpone outbound message, remote lease set is expired"
            );

            context.pending_messages.push_back(message);
            self.query_lease_set(delivery_style.destination_id());

            return Ok(());
        }

        // wrap the garlic message inside a standard i2np message and send it over
        // the one of the pool's outbound tunnels to remote destination
        let message = MessageBuilder::standard()
            .with_message_type(MessageType::Garlic)
            .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
            .with_message_id(R::rng().next_u32())
            .with_payload(&message)
            .build();

        match delivery_style {
            DeliveryStyle::ViaRoute {
                routing_path:
                    RoutingPath {
                        destination_id,
                        inbound,
                        outbound,
                    },
            } => match context.lease_set.leases.iter().find(|lease| lease.tunnel_id == inbound) {
                Some(Lease { router_id, .. }) => {
                    if let Err(error) = self
                        .tunnel_pool_handle
                        .send_message(message)
                        .tunnel_delivery(router_id.clone(), inbound)
                        .via_outbound_tunnel(outbound)
                        .try_send()
                    {
                        tracing::debug!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            remote = %destination_id,
                            %inbound,
                            %router_id,
                            %outbound,
                            ?error,
                            "failed to send message to tunnel via routing path",
                        );
                    }
                }
                None => match context.expiring_leases.get(&inbound) {
                    Some(Lease { router_id, .. }) => {
                        if let Err(error) = self
                            .tunnel_pool_handle
                            .send_message(message)
                            .tunnel_delivery(router_id.clone(), inbound)
                            .via_outbound_tunnel(outbound)
                            .try_send()
                        {
                            tracing::debug!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                remote = %destination_id,
                                %inbound,
                                %router_id,
                                %outbound,
                                ?error,
                                "failed to send message to tunnel via routing path",
                            );
                        }
                    }
                    None => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            %destination_id,
                            %inbound,
                            %outbound,
                            "lease set for selected ibgw doesn't exist",
                        );
                        debug_assert!(false);
                    }
                },
            },
            DeliveryStyle::Unspecified { destination_id } => {
                // select random tunnel for delivery
                let random_lease = R::rng().next_u32() as usize % context.lease_set.leases.len();

                if let Err(error) = self
                    .tunnel_pool_handle
                    .send_message(message)
                    .tunnel_delivery(
                        context.lease_set.leases[random_lease].router_id.clone(),
                        context.lease_set.leases[random_lease].tunnel_id,
                    )
                    .try_send()
                {
                    tracing::debug!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        remote = %destination_id,
                        ?error,
                        "failed to send message to tunnel",
                    );
                }
            }
            DeliveryStyle::Dummy => unreachable!(),
        }

        Ok(())
    }

    /// Encrypt and send `message` to remote destination.
    ///
    /// Session manager is expected to have public key of the remote destination.
    pub fn send_message(
        &mut self,
        delivery_style: DeliveryStyle,
        message: Vec<u8>,
    ) -> crate::Result<()> {
        match self.session_manager.encrypt(delivery_style.destination_id(), message) {
            Ok(message) => self.send_message_inner(delivery_style, message),
            Err(error) => Err(Error::Session(error)),
        }
    }

    /// Handle garlic messages received into one of the [`Destination`]'s inbound tunnels.
    ///
    /// The decrypted garlic message may contain a database store for an up-to-date [`LeaseSet2`] of
    /// the remote destination and if so, the currently stored lease set is overriden with the new
    /// lease set.
    ///
    /// Any garlic clove containing an I2NP Data message is returned to user.
    fn decrypt_message(&mut self, message: Message) -> crate::Result<Vec<Vec<u8>>> {
        tracing::trace!(
            target: LOG_TARGET,
            local = %self.destination_id,
            message_id = ?message.message_id,
            message_type = ?message.message_type,
            "inbound message to destination",
        );

        match message.message_type {
            MessageType::DatabaseStore => {
                let DatabaseStore { key, payload, .. } =
                    DatabaseStore::<R>::parse(&message.payload).ok_or_else(|| {
                        tracing::warn!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            "received malformed database store",
                        );
                        Error::InvalidData
                    })?;

                if core::matches!(payload, DatabaseStorePayload::RouterInfo { .. }) {
                    tracing::warn!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        "unexpected router info database store",
                    );
                    return Err(Error::InvalidData);
                }

                match self.pending_storage_verifications.remove(&key) {
                    None => tracing::warn!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        key = ?base32_encode(key),
                        "unexpected lease set database store",
                    ),
                    Some(_) => tracing::info!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        "lease set storage verified",
                    ),
                }

                return Ok(Vec::new());
            }
            MessageType::DatabaseSearchReply => {
                let DatabaseSearchReply { from, key, .. } =
                    DatabaseSearchReply::parse(&message.payload).ok_or_else(|| {
                        tracing::warn!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            "received malformed database search reply",
                        );
                        Error::InvalidData
                    })?;

                match self.pending_storage_verifications.remove(&key) {
                    None => tracing::debug!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        key = ?base32_encode(key),
                        floodfill = %RouterId::from(from),
                        "unexpected database search reply",
                    ),
                    Some(_) => tracing::debug!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        "lease set storage failed",
                    ),
                }

                return Ok(Vec::new());
            }
            MessageType::DeliveryStatus => {
                let DeliveryStatus { message_id, .. } = DeliveryStatus::parse(&message.payload)
                    .ok_or_else(|| {
                        tracing::warn!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            "received malformed delivery status",
                        );
                        Error::InvalidData
                    })?;

                tracing::trace!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    token = %message_id,
                    "delivery status",
                );

                return Ok(Vec::new());
            }
            MessageType::Garlic => {}
            _ => {
                tracing::warn!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    message_type = ?message.message_type,
                    message_id = ?message.message_id,
                    "unsupported message type for destination",
                );
                return Err(Error::NotSupported);
            }
        }

        if message.payload.len() <= 12 {
            tracing::warn!(
                target: LOG_TARGET,
                local = %self.destination_id,
                payload_len = ?message.payload.len(),
                "garlic message is too short",
            );
            return Err(Error::InvalidData);
        }

        Ok(self
            .session_manager
            .decrypt(message)
            .map_err(Error::Session)?
            .filter_map(|clove| match clove.message_type {
                MessageType::DatabaseStore => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        "remote lease set received",
                    );

                    match DatabaseStore::<R>::parse(&clove.message_body) {
                        Some(DatabaseStore {
                            payload: DatabaseStorePayload::LeaseSet2 { lease_set },
                            ..
                        }) => {
                            let destination_id = lease_set.header.destination.id();

                            if lease_set.leases.is_empty() {
                                tracing::error!(
                                    target: LOG_TARGET,
                                    local = %self.destination_id,
                                    remote = %destination_id,
                                    "remote didn't send any leases",
                                );
                                return None;
                            }

                            tracing::trace!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                remote = %destination_id,
                                "store lease set for remote destination",
                            );

                            self.routing_path_manager
                                .register_inbound_tunnel(&destination_id, lease_set.leases.clone());

                            match self.remote_destinations.get_mut(&destination_id) {
                                Some(context) => {
                                    mem::replace(&mut context.lease_set, lease_set)
                                        .leases
                                        .into_iter()
                                        .for_each(|lease| {
                                            context.expiring_leases.insert(lease.tunnel_id, lease);
                                        });
                                }
                                None => {
                                    self.remote_destinations.insert(
                                        destination_id,
                                        DestinationContext {
                                            lease_set,
                                            pending_messages: VecDeque::new(),
                                            expiring_leases: HashMap::new(),
                                        },
                                    );
                                }
                            }
                        }
                        database_store => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                ?database_store,
                                "ignoring `DatabaseStore`",
                            )
                        }
                    }

                    None
                }
                MessageType::Data => {
                    if clove.message_body.len() <= 4 {
                        tracing::warn!(
                            target: LOG_TARGET,
                            "empty i2np data message",
                        );
                        debug_assert!(false);
                        return None;
                    }

                    Some(clove.message_body[4..].to_vec())
                }
                _ => None,
            })
            .collect::<Vec<_>>())
    }

    /// Attempt to publish new lease set to `NetDb`.
    pub fn publish_lease_set(&mut self, key: Bytes, lease_set: Bytes) {
        // store our new lease set proactively to `SessionManager` so it can be given to all active
        // session right away while publishing the new lease set to NetDb in the background
        self.session_manager.register_lease_set(lease_set.clone());

        if self.unpublished {
            tracing::debug!(
                target: LOG_TARGET,
                local = %self.destination_id,
                "destination is unpublished, skipping lease set store to netdb",
            );
            return;
        }

        let netdb_handle = self.netdb_handle.clone();
        let tunnel_sender = self.tunnel_pool_handle.sender().clone();
        let local = self.destination_id.clone();
        let noise = self.noise.clone();

        // attempt to get an outbound tunnel for sending the database store message
        //
        // while technically the destination should always have at least one outbound tunnel, it's
        // possible that an outbound tunnel built has failed so many times that the previous
        // outbound tunnels expired, leaving the destination with no outbound tunnel
        //
        // TODO: make tunnel selection more random
        let gateway = match self.outbound_tunnels.first() {
            Some(gateway) => *gateway,
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    "no outbound tunnel available for lease set publication",
                );
                debug_assert!(false);
                return;
            }
        };

        // attempt to get an IBGW for lease set storage verification
        //
        // see comment above why this check must be made
        let Some(Lease {
            router_id: gateway_router_id,
            tunnel_id: gateway_tunnel_id,
            ..
        }) = self.inbound_tunnels.first().cloned()
        else {
            tracing::warn!(
                target: LOG_TARGET,
                local = %self.destination_id,
                "no inbound tunnel available for lease set storage verification",
            );
            debug_assert!(false);
            return;
        };

        // mark the key as "pending", waiting for lease set storage verification to end
        self.pending_storage_verifications.insert(key.clone(), R::now());

        R::spawn(async move {
            let floodfills = {
                let mut floodfills = None;

                for _ in 0..3 {
                    match netdb_handle.get_closest_floodfills(key.clone()) {
                        Ok(query_rx) => match query_rx.await {
                            Ok(queried) => {
                                floodfills = Some(queried);
                                break;
                            }
                            Err(_) => R::delay(NETDB_BACKOFF_TIMEOUT).await,
                        },
                        Err(_) => R::delay(NETDB_BACKOFF_TIMEOUT).await,
                    }
                }

                match floodfills {
                    Some(floodfills) => floodfills,
                    None => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            %local,
                            "failed to contact netdb after three retries, aborting lease set publish",
                        );
                        debug_assert!(false);
                        return;
                    }
                }
            };

            // create database store and send it to a floodfill router over
            // one of the destination's outbound tunnels
            let reply_token = R::rng().next_u32();

            tracing::trace!(
                target: LOG_TARGET,
                %local,
                %reply_token,
                "publish local lease set",
            );

            let message =
                DatabaseStoreBuilder::new(key.clone(), DatabaseStoreKind::LeaseSet2 { lease_set })
                    .with_reply_type(ReplyType::Tunnel {
                        reply_token,
                        tunnel_id: gateway_tunnel_id,
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
            let (garlic_key, garlic_tag) =
                noise.derive_outbound_garlic_key(floodfills[0].1.clone(), ephemeral_secret);

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

            // this is a blocking call so the only way it'd fail is if the tunnel pool had shut down
            let _ = tunnel_sender
                .send_message(message)
                .router_delivery(floodfills[0].0.clone())
                .via_outbound_tunnel(gateway)
                .send()
                .await;

            // verify there's at least one other floodfill before proceeding to storage verification
            if floodfills.len() == 1 {
                tracing::warn!(
                    target: LOG_TARGET,
                    %local,
                    "not enough floodfills to verify lease set storage",
                );
                return;
            }

            // wait 10 seconds and verify the lease set has been flooded to other floodfill routers
            //
            // `LeaseSet Storage Verification` in https://geti2p.net/en/docs/how/network-database
            R::delay(Duration::from_secs(10)).await;

            let message = DatabaseLookupBuilder::new(key, LookupType::Leaseset)
                .with_reply_type(LookupReplyType::Tunnel {
                    tunnel_id: gateway_tunnel_id,
                    router_id: gateway_router_id,
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
            let (garlic_key, garlic_tag) =
                noise.derive_outbound_garlic_key(floodfills[1].1.clone(), ephemeral_secret);

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

            // this is a blocking call so the only way it'd fail is if the tunnel pool had shut down
            let _ = tunnel_sender
                .send_message(message)
                .router_delivery(floodfills[1].0.clone())
                .via_outbound_tunnel(gateway)
                .send()
                .await;
        })
    }

    /// Shutdown session by shutting down the tunnel pool.
    pub fn shutdown(&mut self) {
        self.tunnel_pool_handle.shutdown();
    }

    /// Get [`RoutingPathHandle`].
    pub fn routing_path_handle(&mut self, destination_id: DestinationId) -> RoutingPathHandle<R> {
        self.routing_path_manager.handle(destination_id)
    }

    /// Get [`PendingRoutingPathHandle`].
    pub fn pending_routing_path_handle(&self) -> PendingRoutingPathHandle {
        self.routing_path_manager.pending_handle()
    }
}

impl<R: Runtime> Stream for Destination<R> {
    type Item = DestinationEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.tunnel_pool_handle.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => {
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(TunnelPoolEvent::TunnelPoolShutDown)) => {
                    return Poll::Ready(Some(DestinationEvent::TunnelPoolShutDown));
                }
                Poll::Ready(Some(TunnelPoolEvent::InboundTunnelBuilt { tunnel_id, lease })) => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        ?tunnel_id,
                        "inbound tunnel built",
                    );

                    self.inbound_tunnels.push(lease.clone());
                    self.lease_set_manager.register_inbound_tunnel(lease.clone());
                }
                Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelBuilt { tunnel_id })) => {
                    self.outbound_tunnels.push(tunnel_id);
                    self.routing_path_manager.register_outbound_tunnel_built(tunnel_id);
                }
                Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelExpired { tunnel_id })) => {
                    self.outbound_tunnels.retain(|tunnel| tunnel != &tunnel_id);
                    self.routing_path_manager.register_outbound_tunnel_expired(tunnel_id);
                }
                Poll::Ready(Some(TunnelPoolEvent::InboundTunnelExpired { tunnel_id })) => {
                    self.inbound_tunnels.retain(|lease| lease.tunnel_id != tunnel_id);
                    self.lease_set_manager.register_expired_inbound_tunnel(tunnel_id);
                }
                Poll::Ready(Some(TunnelPoolEvent::InboundTunnelExpiring { .. })) => {}
                Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelExpiring { tunnel_id })) => {
                    self.routing_path_manager.register_outbound_tunnel_expiring(tunnel_id);
                }
                Poll::Ready(Some(TunnelPoolEvent::Message { message })) =>
                    match self.decrypt_message(message) {
                        Err(error) => tracing::warn!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            ?error,
                            "failed to handle inbound message",
                        ),
                        Ok(messages) if !messages.is_empty() =>
                            return Poll::Ready(Some(DestinationEvent::Messages { messages })),
                        Ok(_) => {}
                    },
                Poll::Ready(Some(TunnelPoolEvent::Dummy)) => unreachable!(),
            }
        }

        loop {
            match self.session_manager.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(SessionManagerEvent::SessionTerminated { destination_id })) =>
                    return Poll::Ready(Some(DestinationEvent::SessionTerminated {
                        destination_id,
                    })),
                Poll::Ready(Some(SessionManagerEvent::SendMessage {
                    destination_id,
                    message,
                })) =>
                    if let Err(error) = self
                        .send_message_inner(DeliveryStyle::Unspecified { destination_id }, message)
                    {
                        tracing::warn!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            ?error,
                            "failed to send message",
                        );
                    },
            }
        }

        match self.query_futures.poll_next_unpin(cx) {
            Poll::Pending => {}
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Ready(Some((destination_id, result))) => match result {
                Err(error) => {
                    self.pending_queries.remove(&destination_id);
                    return Poll::Ready(Some(DestinationEvent::LeaseSetNotFound {
                        destination_id,
                        error,
                    }));
                }
                Ok(lease_set) => {
                    self.pending_queries.remove(&destination_id);
                    self.session_manager.add_remote_destination(
                        destination_id.clone(),
                        lease_set.public_keys[0].clone(),
                    );
                    self.routing_path_manager
                        .register_inbound_tunnel(&destination_id, lease_set.leases.clone());

                    // add new lease set for destination or create new destination of it didn't
                    // exist
                    //
                    // if the destination has pending messages, sending those before returning the
                    // lease set caller
                    match self.remote_destinations.get_mut(&destination_id) {
                        Some(context) => {
                            context.lease_set = lease_set;

                            mem::take(&mut context.pending_messages).into_iter().for_each(
                                |message| {
                                    if let Err(error) = self.send_message_inner(
                                        DeliveryStyle::Unspecified {
                                            destination_id: destination_id.clone(),
                                        },
                                        message,
                                    ) {
                                        tracing::debug!(
                                            target: LOG_TARGET,
                                            local = %self.destination_id,
                                            remote = %destination_id,
                                            ?error,
                                            "failed to send pending message",
                                        );
                                    }
                                },
                            );
                        }
                        None => {
                            self.remote_destinations.insert(
                                destination_id.clone(),
                                DestinationContext {
                                    lease_set,
                                    pending_messages: VecDeque::new(),
                                    expiring_leases: HashMap::new(),
                                },
                            );
                        }
                    }

                    return Poll::Ready(Some(DestinationEvent::LeaseSetFound { destination_id }));
                }
            },
        }

        if self.routing_path_manager.poll_unpin(cx).is_ready() {
            tracing::debug!(
                target: LOG_TARGET,
                "routing path manager exited",
            );
        }

        match self.lease_set_manager.poll_unpin(cx) {
            Poll::Pending => {}
            Poll::Ready(leases) =>
                return Poll::Ready(Some(DestinationEvent::CreateLeaseSet { leases })),
        }

        if self.lease_set_prune_timer.poll_unpin(cx).is_ready() {
            tracing::debug!(
                target: LOG_TARGET,
                local = %self.destination_id,
                "pruning stale lease sets",
            );

            let now = R::time_since_epoch();
            self.remote_destinations.iter_mut().for_each(|(_, context)| {
                context.expiring_leases.retain(|_, lease| lease.expires > now);
            });

            self.lease_set_prune_timer = Box::pin(R::delay(LEASE_SET_PRUNE_INTERVAL));
            let _ = self.lease_set_prune_timer.poll_unpin(cx);
        }

        self.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::SigningPrivateKey,
        i2np::{database::lookup::DatabaseLookup, garlic::GarlicClove},
        netdb::NetDbAction,
        primitives::{Destination as Dest, LeaseSet2Header, RouterId, TunnelId},
        runtime::{mock::MockRuntime, Runtime},
        tunnel::{
            DeliveryInstructions as GarlicDeliveryInstructions, GarlicHandler, TunnelMessage,
            TunnelPoolConfig,
        },
    };
    use std::collections::VecDeque;

    #[tokio::test]
    async fn query_lease_set_found() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::new(),
            netdb_handle,
            tp_handle,
            Vec::new(),
            Vec::new(),
            false,
        );

        // insert dummy lease set for `remote` into `Destination`
        let remote = DestinationId::random();
        let (lease_set, _) = LeaseSet2::random();
        destination.remote_destinations.insert(
            remote.clone(),
            DestinationContext {
                lease_set,
                pending_messages: VecDeque::new(),
                expiring_leases: HashMap::new(),
            },
        );

        // query lease set and verify it exists
        assert_eq!(destination.query_lease_set(&remote), LeaseSetStatus::Found);
    }

    #[tokio::test]
    async fn query_lease_set_expired() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::new(),
            netdb_handle,
            tp_handle,
            Vec::new(),
            Vec::new(),
            false,
        );

        // insert lease set which expired 10 seconds ago
        let remote = DestinationId::random();
        let (mut lease_set, _) = LeaseSet2::random();
        lease_set.header.expires =
            (MockRuntime::time_since_epoch() - Duration::from_secs(10)).as_secs() as u32;
        destination.remote_destinations.insert(
            remote.clone(),
            DestinationContext {
                lease_set,
                pending_messages: VecDeque::new(),
                expiring_leases: HashMap::new(),
            },
        );

        assert_eq!(
            destination.query_lease_set(&remote),
            LeaseSetStatus::NotFound
        );

        assert!(destination.pending_queries.contains(&remote));
        assert_eq!(destination.query_futures.len(), 1);
    }

    #[tokio::test]
    async fn query_lease_set_not_found() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::new(),
            netdb_handle,
            tp_handle,
            Vec::new(),
            Vec::new(),
            false,
        );

        // query lease set and verify it's not found and that a query has been started
        let remote = DestinationId::random();

        assert_eq!(
            destination.query_lease_set(&remote),
            LeaseSetStatus::NotFound
        );

        assert!(destination.pending_queries.contains(&remote));
        assert_eq!(destination.query_futures.len(), 1);
    }

    #[tokio::test]
    async fn query_lease_set_pending() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::new(),
            netdb_handle,
            tp_handle,
            Vec::new(),
            Vec::new(),
            false,
        );

        // query lease set and verify it's not found and that a query has been started
        let remote = DestinationId::random();

        assert_eq!(
            destination.query_lease_set(&remote),
            LeaseSetStatus::NotFound
        );

        assert!(destination.pending_queries.contains(&remote));
        assert_eq!(destination.query_futures.len(), 1);

        // verify that the status is pending on subsequent queries
        assert_eq!(
            destination.query_lease_set(&remote),
            LeaseSetStatus::Pending
        );
    }

    #[tokio::test]
    async fn query_lease_set_channel_clogged() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::new(),
            netdb_handle.clone(),
            tp_handle,
            Vec::new(),
            Vec::new(),
            false,
        );

        // spam the netdb handle full of queries
        loop {
            if netdb_handle.query_lease_set(Bytes::new()).is_err() {
                break;
            }
        }

        // query lease set and verify it's not found and that a query has been started
        let remote = DestinationId::random();
        assert_eq!(
            destination.query_lease_set(&remote),
            LeaseSetStatus::NotFound
        );

        assert!(destination.pending_queries.contains(&remote));
        assert_eq!(destination.query_futures.len(), 1);

        match destination.next().await {
            Some(DestinationEvent::LeaseSetNotFound {
                destination_id,
                error,
            }) => {
                assert_eq!(destination_id, remote);
                assert_eq!(error, QueryError::RetryFailure)
            }
            _ => panic!("invalid event"),
        }
    }

    #[test]
    #[should_panic]
    fn encrypt_message_lease_set_not_found() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::new(),
            netdb_handle,
            tp_handle,
            Vec::new(),
            Vec::new(),
            false,
        );

        destination
            .send_message(
                DeliveryStyle::Unspecified {
                    destination_id: DestinationId::random(),
                },
                vec![1, 2, 3, 4],
            )
            .unwrap();
    }

    #[tokio::test]
    async fn create_lease_set_immediately() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, tp_tx, _srx) = TunnelPoolHandle::from_config(TunnelPoolConfig {
            num_inbound: 1usize,
            ..Default::default()
        });
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::new(),
            netdb_handle.clone(),
            tp_handle,
            Vec::new(),
            Vec::new(),
            false,
        );

        // new inbound tunnel built
        tp_tx
            .send(TunnelPoolEvent::InboundTunnelBuilt {
                tunnel_id: TunnelId::random(),
                lease: Lease {
                    router_id: RouterId::random(),
                    tunnel_id: TunnelId::random(),
                    expires: MockRuntime::time_since_epoch() + Duration::from_secs(10 * 60),
                },
            })
            .await
            .unwrap();

        // verify event is emitted even though the timer is still active
        futures::future::poll_fn(|cx| match destination.lease_set_manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            _ => panic!("timer is ready"),
        })
        .await;

        match tokio::time::timeout(Duration::from_secs(15), destination.next())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            DestinationEvent::CreateLeaseSet { .. } => {}
            _ => panic!("invalid event"),
        }
    }

    #[tokio::test]
    async fn create_lease_set_after_timeout() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, tp_tx, _srx) = TunnelPoolHandle::from_config(TunnelPoolConfig {
            num_inbound: 3usize,
            ..Default::default()
        });
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::new(),
            netdb_handle.clone(),
            tp_handle,
            Vec::new(),
            Vec::new(),
            false,
        );

        // issue events for two new inbound tunnels
        for _ in 0..2 {
            tp_tx
                .send(TunnelPoolEvent::InboundTunnelBuilt {
                    tunnel_id: TunnelId::random(),
                    lease: Lease {
                        router_id: RouterId::random(),
                        tunnel_id: TunnelId::random(),
                        expires: MockRuntime::time_since_epoch() + Duration::from_secs(10 * 60),
                    },
                })
                .await
                .unwrap();
        }

        // verify that inbound tunnel is not built because 3 inbound tunnels are needed
        assert!(destination.next().now_or_never().is_none());

        // verify that that an event is emitted after the timer expires
        match tokio::time::timeout(Duration::from_secs(20), destination.next())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            DestinationEvent::CreateLeaseSet { .. } => {}
            _ => panic!("invalid event"),
        }
    }

    #[tokio::test]
    async fn lease_set_storage_verified() {
        let (netdb_handle, rx) = NetDbHandle::create();
        let (tp_handle, tm_rx, tp_tx, _srx) = TunnelPoolHandle::from_config(TunnelPoolConfig {
            num_inbound: 3usize,
            ..Default::default()
        });
        let destination_id = DestinationId::random();
        let encryption_key = StaticPrivateKey::random(MockRuntime::rng());
        let signing_key = SigningPrivateKey::random(MockRuntime::rng());
        let dest = Dest::new::<MockRuntime>(signing_key.public());
        let mut destination = Destination::<MockRuntime>::new(
            destination_id.clone(),
            encryption_key.clone(),
            Bytes::new(),
            netdb_handle.clone(),
            tp_handle,
            Vec::new(),
            Vec::new(),
            false,
        );

        // add one outbound tunnel
        tp_tx
            .send(TunnelPoolEvent::OutboundTunnelBuilt {
                tunnel_id: TunnelId::random(),
            })
            .await
            .unwrap();

        // issue events for three new inbound tunnels
        for _ in 0..3 {
            tp_tx
                .send(TunnelPoolEvent::InboundTunnelBuilt {
                    tunnel_id: TunnelId::random(),
                    lease: Lease {
                        router_id: RouterId::random(),
                        tunnel_id: TunnelId::random(),
                        expires: MockRuntime::time_since_epoch() + Duration::from_secs(10 * 60),
                    },
                })
                .await
                .unwrap();
        }

        match tokio::time::timeout(Duration::from_secs(20), destination.next())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            DestinationEvent::CreateLeaseSet { leases } => {
                let lease_set = Bytes::from(
                    LeaseSet2 {
                        header: LeaseSet2Header {
                            destination: dest.clone(),
                            expires: Duration::from_secs(10 * 60).as_secs() as u32,
                            is_unpublished: false,
                            offline_signature: None,
                            published: MockRuntime::time_since_epoch().as_secs() as u32,
                        },
                        public_keys: vec![encryption_key.public()],
                        leases,
                    }
                    .serialize(&signing_key),
                );

                destination.publish_lease_set(Bytes::from(destination_id.to_vec()), lease_set);
            }
            _ => panic!("invalid event"),
        }

        tokio::spawn(async move {
            let (floodfills, mut garlics): (Vec<_>, HashMap<_, _>) = (0..3)
                .map(|_| {
                    let router_id = RouterId::random();
                    let key = StaticPrivateKey::random(MockRuntime::rng());
                    let garlic = GarlicHandler::<MockRuntime>::new(
                        NoiseContext::new(key.clone(), Bytes::from(router_id.to_vec())),
                        MockRuntime::register_metrics(vec![], None),
                    );

                    ((router_id.clone(), key.public()), (router_id, garlic))
                })
                .unzip();

            let mut lease_set = Option::<Bytes>::None;
            let mut key = Option::<Bytes>::None;

            loop {
                tokio::select! {
                    event = rx.recv() => match event.unwrap() {
                        NetDbAction::GetClosestFloodfills { tx, .. } => {
                            tx.send(floodfills.clone()).unwrap();
                        }
                        _ => panic!("invalid event"),
                    },
                    message = tm_rx.recv() => match message.unwrap() {
                        TunnelMessage::RouterDeliveryViaRoute { message, router_id, .. } => {
                            let message = Message::parse_standard(&message).unwrap();
                            assert_eq!(message.message_type, MessageType::Garlic);

                            let GarlicDeliveryInstructions::Local { message } = garlics
                                .get_mut(&router_id)
                                .unwrap()
                                .handle_message(message)
                                .unwrap()
                                .filter(|message| std::matches!(message, GarlicDeliveryInstructions::Local { .. }))
                                .collect::<VecDeque<_>>()
                                .pop_front()
                                .expect("to exist") else {
                                    panic!("invalid type");
                                };

                            match message.message_type {
                                MessageType::DatabaseStore => {
                                    let DatabaseStore {
                                        reply,
                                        key: store_key,
                                        ..
                                    } = DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();

                                    key = Some(store_key);
                                    lease_set = Some(DatabaseStore::<MockRuntime>::extract_raw_lease_set(&message.payload));

                                    match reply {
                                        ReplyType::Tunnel { reply_token, .. } => {
                                            tp_tx.send(TunnelPoolEvent::Message { message: Message {
                                                    message_type: MessageType::DeliveryStatus,
                                                    message_id: MockRuntime::rng().next_u32(),
                                                    expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                                                    payload: DeliveryStatus {
                                                        message_id: reply_token,
                                                        timestamp: MockRuntime::time_since_epoch(),
                                                    }.serialize().to_vec()
                                            }}).await.unwrap();
                                        }
                                        _ => panic!("invalid reply type"),
                                    }
                                }
                                MessageType::DatabaseLookup => {
                                    let DatabaseLookup {
                                        key: lookup_key,
                                        ..
                                    } = DatabaseLookup::parse(&message.payload).unwrap();

                                    assert_eq!(key.as_ref().unwrap(), &lookup_key);

                                    let message =
                                        DatabaseStoreBuilder::new(
                                            key.clone().unwrap(),
                                            DatabaseStoreKind::LeaseSet2 { lease_set: lease_set.clone().unwrap() })
                                        .build();

                                    tp_tx.send(TunnelPoolEvent::Message { message: Message {
                                            message_type: MessageType::DatabaseStore,
                                            message_id: MockRuntime::rng().next_u32(),
                                            expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                                            payload: message.to_vec(),
                                    }}).await.unwrap();
                                }
                                _ => panic!("invalid message type"),
                            }
                        }
                        _ => panic!("invalid message type"),
                    }
                }
            }
        });

        match tokio::time::timeout(Duration::from_secs(15), destination.next()).await {
            Err(_) => {}
            res => tracing::warn!("unexpected result = {res:?}"),
        }
        assert!(destination.pending_storage_verifications.is_empty());
    }

    #[tokio::test]
    async fn lease_set_storage_verification_failure() {
        let (netdb_handle, rx) = NetDbHandle::create();
        let (tp_handle, tm_rx, tp_tx, _srx) = TunnelPoolHandle::from_config(TunnelPoolConfig {
            num_inbound: 3usize,
            ..Default::default()
        });
        let destination_id = DestinationId::random();
        let encryption_key = StaticPrivateKey::random(MockRuntime::rng());
        let signing_key = SigningPrivateKey::random(MockRuntime::rng());
        let dest = Dest::new::<MockRuntime>(signing_key.public());
        let mut destination = Destination::<MockRuntime>::new(
            destination_id.clone(),
            encryption_key.clone(),
            Bytes::new(),
            netdb_handle.clone(),
            tp_handle,
            Vec::new(),
            Vec::new(),
            false,
        );

        // add one outbound tunnel
        tp_tx
            .send(TunnelPoolEvent::OutboundTunnelBuilt {
                tunnel_id: TunnelId::random(),
            })
            .await
            .unwrap();

        // issue events for three new inbound tunnels
        for _ in 0..3 {
            tp_tx
                .send(TunnelPoolEvent::InboundTunnelBuilt {
                    tunnel_id: TunnelId::random(),
                    lease: Lease {
                        router_id: RouterId::random(),
                        tunnel_id: TunnelId::random(),
                        expires: MockRuntime::time_since_epoch() + Duration::from_secs(10 * 60),
                    },
                })
                .await
                .unwrap();
        }

        match tokio::time::timeout(Duration::from_secs(20), destination.next())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            DestinationEvent::CreateLeaseSet { leases } => {
                let lease_set = Bytes::from(
                    LeaseSet2 {
                        header: LeaseSet2Header {
                            destination: dest.clone(),
                            expires: Duration::from_secs(10 * 60).as_secs() as u32,
                            is_unpublished: false,
                            offline_signature: None,
                            published: MockRuntime::time_since_epoch().as_secs() as u32,
                        },
                        public_keys: vec![encryption_key.public()],
                        leases,
                    }
                    .serialize(&signing_key),
                );

                destination.publish_lease_set(Bytes::from(destination_id.to_vec()), lease_set);
            }
            _ => panic!("invalid event"),
        }

        tokio::spawn(async move {
            let (floodfills, mut garlics): (Vec<_>, HashMap<_, _>) = (0..3)
                .map(|_| {
                    let router_id = RouterId::random();
                    let key = StaticPrivateKey::random(MockRuntime::rng());
                    let garlic = GarlicHandler::<MockRuntime>::new(
                        NoiseContext::new(key.clone(), Bytes::from(router_id.to_vec())),
                        MockRuntime::register_metrics(vec![], None),
                    );

                    ((router_id.clone(), key.public()), (router_id, garlic))
                })
                .unzip();
            let mut key = Option::<Bytes>::None;

            loop {
                tokio::select! {
                    event = rx.recv() => match event.unwrap() {
                        NetDbAction::GetClosestFloodfills { tx, .. } => {
                            tx.send(floodfills.clone()).unwrap();
                        }
                        _ => panic!("invalid event"),
                    },
                    message = tm_rx.recv() => match message.unwrap() {
                        TunnelMessage::RouterDeliveryViaRoute { message, router_id, .. } => {
                            let message = Message::parse_standard(&message).unwrap();
                            assert_eq!(message.message_type, MessageType::Garlic);

                            let GarlicDeliveryInstructions::Local { message } = garlics
                                .get_mut(&router_id)
                                .unwrap()
                                .handle_message(message)
                                .unwrap()
                                .filter(|message| std::matches!(message, GarlicDeliveryInstructions::Local { .. }))
                                .collect::<VecDeque<_>>()
                                .pop_front()
                                .expect("to exist") else {
                                    panic!("invalid type");
                                };


                            match message.message_type {
                                MessageType::DatabaseStore => {
                                    let DatabaseStore {
                                        reply,
                                        key: store_key,
                                        ..
                                    } = DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();

                                    key = Some(store_key);

                                    match reply {
                                        ReplyType::Tunnel { reply_token, .. } => {
                                            tp_tx.send(TunnelPoolEvent::Message { message: Message {
                                                    message_type: MessageType::DeliveryStatus,
                                                    message_id: MockRuntime::rng().next_u32(),
                                                    expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                                                    payload: DeliveryStatus {
                                                        message_id: reply_token,
                                                        timestamp: MockRuntime::time_since_epoch(),
                                                    }.serialize().to_vec()
                                            }}).await.unwrap();
                                        }
                                        _ => panic!("invalid reply type"),
                                    }
                                }
                                MessageType::DatabaseLookup => {
                                    let DatabaseLookup {
                                        key: lookup_key,
                                        ..
                                    } = DatabaseLookup::parse(&message.payload).unwrap();

                                    assert_eq!(key.as_ref().unwrap(), &lookup_key);

                                    let message = DatabaseSearchReply {
                                        from: router_id.to_vec(),
                                        key: lookup_key,
                                        routers: vec![RouterId::random(), RouterId::random(), RouterId::random()],
                                    }.serialize();

                                    tp_tx.send(TunnelPoolEvent::Message { message: Message {
                                            message_type: MessageType::DatabaseSearchReply,
                                            message_id: MockRuntime::rng().next_u32(),
                                            expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                                            payload: message.to_vec(),
                                    }}).await.unwrap();
                                }
                                _ => panic!("invalid message type"),
                            }
                        }
                        _ => panic!("invalid message type"),
                    }
                }
            }
        });

        match tokio::time::timeout(Duration::from_secs(15), destination.next()).await {
            Err(_) => {}
            res => tracing::warn!("unexpected result = {res:?}"),
        }
        assert!(destination.pending_storage_verifications.is_empty());
    }

    #[tokio::test]
    async fn unpublished_destination() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, tp_tx, _srx) = TunnelPoolHandle::from_config(TunnelPoolConfig {
            num_inbound: 3usize,
            ..Default::default()
        });
        let destination_id = DestinationId::random();
        let encryption_key = StaticPrivateKey::random(MockRuntime::rng());
        let signing_key = SigningPrivateKey::random(MockRuntime::rng());
        let dest = Dest::new::<MockRuntime>(signing_key.public());
        let mut destination = Destination::<MockRuntime>::new(
            destination_id.clone(),
            encryption_key.clone(),
            Bytes::new(),
            netdb_handle.clone(),
            tp_handle,
            Vec::new(),
            Vec::new(),
            true,
        );

        // add one outbound tunnel
        tp_tx
            .send(TunnelPoolEvent::OutboundTunnelBuilt {
                tunnel_id: TunnelId::random(),
            })
            .await
            .unwrap();

        // issue events for three new inbound tunnels
        for _ in 0..3 {
            tp_tx
                .send(TunnelPoolEvent::InboundTunnelBuilt {
                    tunnel_id: TunnelId::random(),
                    lease: Lease {
                        router_id: RouterId::random(),
                        tunnel_id: TunnelId::random(),
                        expires: MockRuntime::time_since_epoch() + Duration::from_secs(10 * 60),
                    },
                })
                .await
                .unwrap();
        }

        assert!(destination.pending_storage_verifications.is_empty());

        match tokio::time::timeout(Duration::from_secs(20), destination.next())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            DestinationEvent::CreateLeaseSet { leases } => {
                let lease_set = Bytes::from(
                    LeaseSet2 {
                        header: LeaseSet2Header {
                            destination: dest.clone(),
                            expires: Duration::from_secs(10 * 60).as_secs() as u32,
                            is_unpublished: false,
                            offline_signature: None,
                            published: MockRuntime::time_since_epoch().as_secs() as u32,
                        },
                        public_keys: vec![encryption_key.public()],
                        leases,
                    }
                    .serialize(&signing_key),
                );

                destination.publish_lease_set(Bytes::from(destination_id.to_vec()), lease_set);
            }
            _ => panic!("invalid event"),
        }
        assert!(destination.pending_storage_verifications.is_empty());
    }

    #[tokio::test]
    async fn send_message_expired_lease_set() {
        let (netdb_handle, rx) = NetDbHandle::create();
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::new(),
            netdb_handle,
            tp_handle,
            Vec::new(),
            Vec::new(),
            false,
        );

        // insert lease set which expired 10 seconds ago
        let remote = DestinationId::random();
        let (lease_set, _) = LeaseSet2::random();
        let expired_lease_set = {
            let mut expired = lease_set.clone();
            expired.header.expires =
                (MockRuntime::time_since_epoch() - Duration::from_secs(10)).as_secs() as u32;

            expired
        };
        destination.remote_destinations.insert(
            remote.clone(),
            DestinationContext {
                lease_set: expired_lease_set,
                pending_messages: VecDeque::new(),
                expiring_leases: HashMap::new(),
            },
        );

        destination
            .session_manager
            .add_remote_destination(remote.clone(), lease_set.public_keys[0].clone());

        // send three messages and verify they're all queried
        destination
            .send_message(
                DeliveryStyle::Unspecified {
                    destination_id: remote.clone(),
                },
                vec![1, 1, 1, 1],
            )
            .unwrap();
        destination
            .send_message(
                DeliveryStyle::Unspecified {
                    destination_id: remote.clone(),
                },
                vec![2, 2, 2, 2],
            )
            .unwrap();
        destination
            .send_message(
                DeliveryStyle::Unspecified {
                    destination_id: remote.clone(),
                },
                vec![3, 3, 3, 3],
            )
            .unwrap();

        assert!(destination.pending_queries.contains(&remote));
        assert_eq!(destination.query_futures.len(), 1);
        assert_eq!(
            destination.remote_destinations.get(&remote).unwrap().pending_messages.len(),
            3
        );

        // poll destination for a while so that the query future is polled
        assert!(tokio::time::timeout(Duration::from_secs(2), destination.next()).await.is_err());

        match rx.try_recv().unwrap() {
            NetDbAction::QueryLeaseSet2 { tx, .. } => {
                let _ = tx.send(Ok(lease_set));
            }
            _ => panic!("unexpected event"),
        }

        // poll destination until the leaset set is registered
        match tokio::time::timeout(Duration::from_secs(5), destination.next())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            DestinationEvent::LeaseSetFound { destination_id } => {
                assert_eq!(destination_id, remote);
            }
            _ => panic!("invalid event"),
        }

        // verify that the three pending messages are sent to tunnel pool
        for _ in 0..3 {
            match tokio::time::timeout(Duration::from_secs(5), tm_rx.recv())
                .await
                .expect("no timeout")
                .expect("to succeed")
            {
                TunnelMessage::TunnelDeliveryViaRoute { .. } => {}
                _ => panic!("invalid tunnel message type"),
            }
        }
    }

    #[tokio::test]
    async fn new_lease_set_received() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let private_key = StaticPrivateKey::random(MockRuntime::rng());
        let destination_id = DestinationId::random();
        let public_key = private_key.public();
        let mut destination = Destination::<MockRuntime>::new(
            destination_id.clone(),
            private_key,
            Bytes::new(),
            netdb_handle,
            tp_handle,
            Vec::new(),
            Vec::new(),
            false,
        );

        // create remote destination and two leases for it
        let signing_key = SigningPrivateKey::random(MockRuntime::rng());
        let encryption_key = StaticPrivateKey::random(MockRuntime::rng());
        let dest = Dest::new::<MockRuntime>(signing_key.public());
        let remote_dest_id = dest.id();
        let expiring_inbound1 = Lease {
            router_id: RouterId::random(),
            tunnel_id: TunnelId::random(),
            expires: MockRuntime::time_since_epoch() + Duration::from_secs(10),
        };
        let expiring_inbound2 = Lease {
            router_id: RouterId::random(),
            tunnel_id: TunnelId::random(),
            expires: MockRuntime::time_since_epoch() + Duration::from_secs(10),
        };
        let lease_set = Bytes::from(
            LeaseSet2 {
                header: LeaseSet2Header {
                    destination: dest.clone(),
                    expires: Duration::from_secs(10).as_secs() as u32,
                    is_unpublished: false,
                    offline_signature: None,
                    published: MockRuntime::time_since_epoch().as_secs() as u32,
                },
                public_keys: vec![encryption_key.public()],
                leases: vec![expiring_inbound1.clone(), expiring_inbound2.clone()],
            }
            .serialize(&signing_key),
        );

        // create session manager and an NS message
        let mut session_manager = SessionManager::<MockRuntime>::new(
            remote_dest_id.clone(),
            encryption_key.clone(),
            lease_set,
        );
        session_manager.add_remote_destination(destination_id.clone(), public_key);
        let payload = session_manager.encrypt(&destination_id, vec![1, 3, 3, 7]).unwrap();
        let message = Message {
            message_type: MessageType::Garlic,
            message_id: *MessageId::random(),
            expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
            payload,
        };

        // verify that the remote destination isn't known to `destination`
        assert!(destination.remote_destinations.get(&remote_dest_id).is_none());

        // decrypt NS
        let messages = destination.decrypt_message(message).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0], vec![1, 3, 3, 7]);

        match destination.remote_destinations.get(&remote_dest_id) {
            Some(context) => {
                assert!(context
                    .lease_set
                    .leases
                    .iter()
                    .find(|lease| lease.tunnel_id == expiring_inbound1.tunnel_id
                        && lease.router_id == expiring_inbound1.router_id)
                    .is_some());
                assert!(context
                    .lease_set
                    .leases
                    .iter()
                    .find(|lease| lease.tunnel_id == expiring_inbound2.tunnel_id
                        && lease.router_id == expiring_inbound2.router_id)
                    .is_some());
                assert!(context.expiring_leases.is_empty())
            }
            None => panic!("expected to find context"),
        }

        // send NSR
        let message = Message {
            message_type: MessageType::Garlic,
            message_id: *MessageId::random(),
            expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
            payload: destination
                .session_manager
                .encrypt(&remote_dest_id, vec![1, 3, 3, 8])
                .unwrap(),
        };

        let Some(GarlicClove { message_body, .. }) = session_manager
            .decrypt(message)
            .unwrap()
            .find(|message| message.message_type == MessageType::Data)
        else {
            panic!("data message not found");
        };
        assert_eq!(message_body, vec![0, 0, 0, 4, 1, 3, 3, 8]);

        // send ES which starts a new session
        let payload = session_manager.encrypt(&destination_id, vec![1, 3, 3, 9]).unwrap();
        let message = Message {
            message_type: MessageType::Garlic,
            message_id: *MessageId::random(),
            expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
            payload,
        };

        // decrypt NS
        let messages = destination.decrypt_message(message).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0], vec![1, 3, 3, 9]);

        // create new lease set for `session_manager`
        let new_inbound1 = Lease {
            router_id: RouterId::random(),
            tunnel_id: TunnelId::random(),
            expires: MockRuntime::time_since_epoch() + Duration::from_secs(10),
        };
        let new_inbound2 = Lease {
            router_id: RouterId::random(),
            tunnel_id: TunnelId::random(),
            expires: MockRuntime::time_since_epoch() + Duration::from_secs(10),
        };
        let new_lease_set = Bytes::from(
            LeaseSet2 {
                header: LeaseSet2Header {
                    destination: dest.clone(),
                    expires: Duration::from_secs(10).as_secs() as u32,
                    is_unpublished: false,
                    offline_signature: None,
                    published: MockRuntime::time_since_epoch().as_secs() as u32,
                },
                public_keys: vec![encryption_key.public()],
                leases: vec![new_inbound1.clone(), new_inbound2.clone()],
            }
            .serialize(&signing_key),
        );
        session_manager.register_lease_set(new_lease_set);

        // send ES with a bundled lease set
        let payload = session_manager.encrypt(&destination_id, vec![1, 3, 4, 0]).unwrap();
        let message = Message {
            message_type: MessageType::Garlic,
            message_id: *MessageId::random(),
            expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
            payload,
        };

        // decrypt NS
        let messages = destination.decrypt_message(message).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0], vec![1, 3, 4, 0]);

        // verify that the old lease set is now `expiring_leases`
        match destination.remote_destinations.get(&remote_dest_id) {
            Some(context) => {
                assert!(context
                    .lease_set
                    .leases
                    .iter()
                    .find(|lease| lease.tunnel_id == new_inbound1.tunnel_id
                        && lease.router_id == new_inbound1.router_id)
                    .is_some());
                assert!(context
                    .lease_set
                    .leases
                    .iter()
                    .find(|lease| lease.tunnel_id == new_inbound2.tunnel_id
                        && lease.router_id == new_inbound2.router_id)
                    .is_some());

                match context.expiring_leases.get(&expiring_inbound1.tunnel_id) {
                    Some(lease) => {
                        assert_eq!(lease.router_id, expiring_inbound1.router_id);
                        assert_eq!(lease.expires.as_secs(), expiring_inbound1.expires.as_secs());
                    }
                    None => panic!("expected lease set to be found"),
                }

                match context.expiring_leases.get(&expiring_inbound2.tunnel_id) {
                    Some(lease) => {
                        assert_eq!(lease.router_id, expiring_inbound2.router_id);
                        assert_eq!(lease.expires.as_secs(), expiring_inbound2.expires.as_secs());
                    }
                    None => panic!("expected lease set to be found"),
                }
            }
            None => panic!("expected to find context"),
        }

        // set the lease set prune interval to a shorter timeout and poll `destination` until the
        // timer expires
        destination.lease_set_prune_timer = Box::pin(MockRuntime::delay(Duration::from_secs(11)));

        assert!(tokio::time::timeout(Duration::from_secs(15), destination.next()).await.is_err());

        // verify the old lease set has been pruned
        match destination.remote_destinations.get(&remote_dest_id) {
            Some(context) => {
                assert!(context
                    .lease_set
                    .leases
                    .iter()
                    .find(|lease| lease.tunnel_id == new_inbound1.tunnel_id
                        && lease.router_id == new_inbound1.router_id)
                    .is_some());
                assert!(context
                    .lease_set
                    .leases
                    .iter()
                    .find(|lease| lease.tunnel_id == new_inbound2.tunnel_id
                        && lease.router_id == new_inbound2.router_id)
                    .is_some());
                assert!(context.expiring_leases.is_empty());
            }
            None => panic!("expected to find context"),
        }
    }
}
