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
    crypto::StaticPrivateKey,
    destination::session::SessionManager,
    error::{Error, QueryError},
    i2np::{
        database::store::{DatabaseStore, DatabaseStorePayload},
        Message, MessageBuilder, MessageType, I2NP_MESSAGE_EXPIRATION,
    },
    netdb::NetDbHandle,
    primitives::{DestinationId, LeaseSet2},
    runtime::{JoinSet, Runtime},
    tunnel::{TunnelPoolEvent, TunnelPoolHandle},
};

use bytes::Bytes;
use futures::{Stream, StreamExt};
use hashbrown::{HashMap, HashSet};
use rand_core::RngCore;

use alloc::vec::Vec;
use core::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

pub mod session;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::destination";

/// Retry timeout for lease set query.
const QUERY_RETRY_TIMEOUT: Duration = Duration::from_secs(5);

/// Number of retries before lease set query is aborted.
///
/// This is the number retries made when trying to contact [`NetDb`] for a lease set query
/// in case the channel used by [`NetDbHandle`] is clogged.
const NUM_QUERY_RETRIES: usize = 3usize;

/// Events emitted by [`Destination`].
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

/// Client destination.
pub struct Destination<R: Runtime> {
    /// Destination ID of the client.
    destination_id: DestinationId,

    /// Serialized [`LeaseSet2`] for client's inbound tunnels.
    lease_set: Bytes,

    /// Handle to [`NetDb`].
    netdb_handle: NetDbHandle,

    /// Pending lease set queries:
    pending_queries: HashSet<DestinationId>,

    /// Pending `LeaseSet2` query futures.
    query_futures: R::JoinSet<(DestinationId, Result<LeaseSet2, QueryError>)>,

    /// Known remote destinations.
    remote_destinations: HashMap<DestinationId, LeaseSet2>,

    /// Session manager.
    session_manager: SessionManager<R>,

    /// Handle to destination's [`TunnelPool`].
    tunnel_pool_handle: TunnelPoolHandle,
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
    ) -> Self {
        Self {
            destination_id: destination_id.clone(),
            lease_set: lease_set.clone(),
            netdb_handle,
            pending_queries: HashSet::new(),
            query_futures: R::join_set(),
            remote_destinations: HashMap::new(),
            session_manager: SessionManager::new(destination_id, private_key, lease_set),
            tunnel_pool_handle,
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
        if self.remote_destinations.contains_key(destination_id) {
            return LeaseSetStatus::Found;
        }

        if self.pending_queries.contains(destination_id) {
            return LeaseSetStatus::Pending;
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
                let Ok(rx) = handle.query_leaseset(Bytes::from(destination_id.to_vec())) else {
                    R::delay(QUERY_RETRY_TIMEOUT).await;
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

            return (destination_id, Err(QueryError::RetryFailure));
        });

        LeaseSetStatus::NotFound
    }

    /// Encrypt and send `message` to remote destination.
    ///
    /// Lease set for the remote destination must exist in [`Destination`], otherwise the call is
    /// rejected. Lease set can be queried with [`Destination::query_lease_set()`] which returns a
    /// result indicating whether the remote is "reachable" right now.
    ///
    /// After the message has been encrypted, it's sent to remote destination via one of the
    /// outbound tunnels of [`Destination`].
    pub fn send_message(
        &mut self,
        destination_id: &DestinationId,
        message: Vec<u8>,
    ) -> crate::Result<()> {
        let Some(LeaseSet2 { leases, .. }) = self.remote_destinations.get(destination_id) else {
            tracing::warn!(
                target: LOG_TARGET,
                %destination_id,
                "`Destination::encrypt()` called but lease set is missing",
            );
            debug_assert!(false);
            return Err(Error::InvalidState);
        };

        // encrypt message
        //
        // session manager is expected to have public key of the destination
        let message = self.session_manager.encrypt(destination_id, message)?;

        // wrap the garlic message inside a standard i2np message and send it over
        // the one of the pool's outbound tunnels to remote destination
        let message = MessageBuilder::standard()
            .with_message_type(MessageType::Garlic)
            .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
            .with_message_id(R::rng().next_u32())
            .with_payload(&message)
            .build();

        if let Err(error) = self.tunnel_pool_handle.send_to_tunnel(
            leases[0].router_id.clone(),
            leases[0].tunnel_id,
            message,
        ) {
            tracing::debug!(
                target: LOG_TARGET,
                local = %self.destination_id,
                reomte = %destination_id,
                ?error,
                "failed to send message to tunnel",
            );
        }

        Ok(())
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
            message_id = ?message.message_id,
            "garlic message",
        );
        debug_assert_eq!(message.message_type, MessageType::Garlic);

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
            .decrypt(message)?
            .filter_map(|clove| match clove.message_type {
                MessageType::DatabaseStore => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "ignoring database store",
                    );

                    match DatabaseStore::<R>::parse(&clove.message_body) {
                        Some(DatabaseStore {
                            payload: DatabaseStorePayload::LeaseSet2 { leaseset },
                            ..
                        }) => {
                            if leaseset.leases.is_empty() {
                                tracing::error!(
                                    target: LOG_TARGET,
                                    local = %self.destination_id,
                                    remote = %leaseset.header.destination.id(),
                                    "remote didn't send any leases",
                                );
                                return None;
                            }

                            tracing::trace!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                remote = %leaseset.header.destination.id(),
                                "store lease set for remote destination",
                            );

                            self.remote_destinations
                                .insert(leaseset.header.destination.id(), leaseset);
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
}

impl<R: Runtime> Stream for Destination<R> {
    type Item = DestinationEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.tunnel_pool_handle.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(TunnelPoolEvent::TunnelPoolShutDown)) =>
                    return Poll::Ready(Some(DestinationEvent::TunnelPoolShutDown)),
                Poll::Ready(Some(TunnelPoolEvent::InboundTunnelBuilt { .. })) => {}
                Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelBuilt { .. })) => {}
                Poll::Ready(Some(TunnelPoolEvent::InboundTunnelExpired { .. })) => {}
                Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelExpired { .. })) => {}
                Poll::Ready(Some(TunnelPoolEvent::Message { message })) =>
                    match self.decrypt_message(message) {
                        Err(error) => tracing::warn!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            ?error,
                            "failed to decrypt garlic message",
                        ),
                        Ok(messages) if !messages.is_empty() =>
                            return Poll::Ready(Some(DestinationEvent::Messages { messages })),
                        Ok(_) => {}
                    },
                Poll::Ready(Some(TunnelPoolEvent::Dummy)) => unreachable!(),
            }
        }

        loop {
            match self.query_futures.poll_next_unpin(cx) {
                Poll::Pending => break,
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
                        self.remote_destinations.insert(destination_id.clone(), lease_set);

                        return Poll::Ready(Some(DestinationEvent::LeaseSetFound {
                            destination_id,
                        }));
                    }
                },
            }
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{mock::MockRuntime, Runtime};

    #[tokio::test]
    async fn query_lease_set_found() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::new(MockRuntime::rng()),
            Bytes::new(),
            netdb_handle,
            tp_handle,
        );

        // insert dummy lease set for `remote` into `Destination`
        let remote = DestinationId::random();
        let (lease_set, _) = LeaseSet2::random();
        destination.remote_destinations.insert(remote.clone(), lease_set);

        // query lease set and verify it exists
        assert_eq!(destination.query_lease_set(&remote), LeaseSetStatus::Found);
    }

    #[tokio::test]
    async fn query_lease_set_not_found() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::new(MockRuntime::rng()),
            Bytes::new(),
            netdb_handle,
            tp_handle,
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
            StaticPrivateKey::new(MockRuntime::rng()),
            Bytes::new(),
            netdb_handle,
            tp_handle,
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
            StaticPrivateKey::new(MockRuntime::rng()),
            Bytes::new(),
            netdb_handle.clone(),
            tp_handle,
        );

        // spam the netdb handle full of queries
        loop {
            if netdb_handle.query_leaseset(Bytes::new()).is_err() {
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
            StaticPrivateKey::new(MockRuntime::rng()),
            Bytes::new(),
            netdb_handle,
            tp_handle,
        );

        destination.send_message(&DestinationId::random(), vec![1, 2, 3, 4]);
    }
}
