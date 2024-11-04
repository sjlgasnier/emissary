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
        Message, MessageType,
    },
    netdb::NetDbHandle,
    primitives::{Destination as Dest, DestinationId, LeaseSet2, RouterId, TunnelId},
    runtime::{JoinSet, Runtime},
};

use bytes::Bytes;
use futures::{Stream, StreamExt};
use hashbrown::{HashMap, HashSet};

use alloc::{collections::VecDeque, vec::Vec};
use core::{
    pin::Pin,
    task::{Context, Poll, Waker},
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
    /// Send message to remote `Destination`.
    SendMessage {
        /// Router ID of the destination gateway.
        router_id: RouterId,

        /// Tunnel ID of the destination gateway.
        tunnel_id: TunnelId,

        /// Message to send.
        message: Vec<u8>,
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

    /// Pending events.
    //
    // TODO: remove
    pending_events: VecDeque<DestinationEvent>,

    /// Pending lease set queries:
    pending_queries: HashSet<DestinationId>,

    /// Pending `LeaseSet2` query futures.
    query_futures: R::JoinSet<(DestinationId, Result<LeaseSet2, QueryError>)>,

    /// Known remote destinations.
    remote_destinations: HashMap<DestinationId, LeaseSet2>,

    /// Session manager.
    session_manager: SessionManager<R>,

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
    ) -> Self {
        Self {
            destination_id: destination_id.clone(),
            lease_set: lease_set.clone(),
            netdb_handle,
            pending_events: VecDeque::new(),
            pending_queries: HashSet::new(),
            query_futures: R::join_set(),
            remote_destinations: HashMap::new(),
            session_manager: SessionManager::new(destination_id, private_key, lease_set),
            waker: None,
        }
    }

    /// Look up the lease set associated with `destination_id`.
    ///
    /// MORE DOCUMENTATION
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
                let Ok(mut rx) = handle.query_leaseset(Bytes::from(destination_id.to_vec())) else {
                    R::delay(QUERY_RETRY_TIMEOUT).await;
                    continue;
                };

                tracing::trace!(
                    target: LOG_TARGET,
                    %destination_id,
                    "lease set query started",
                );

                match rx.await {
                    Err(error) => return (destination_id, Err(QueryError::Timeout)),
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

    /// Encrypt `message` destined to `destination_id`.
    ///
    /// TODO: rewrite this comment
    ///
    /// Caller must call [`Destination::poll_next()`] to drive progress forward.
    pub fn encrypt_message(
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

        let message = self.session_manager.encrypt(destination_id, message)?;

        self.pending_events.push_back(DestinationEvent::SendMessage {
            router_id: leases[0].router_id.clone(),
            tunnel_id: leases[0].tunnel_id,
            message,
        });

        if let Some(waker) = self.waker.take() {
            waker.wake_by_ref();
        }

        Ok(())
    }

    /// Handle garlic messages received into one of the [`Destination`]'s inbound tunnels.
    pub fn decrypt_message(
        &mut self,
        message: Message,
    ) -> crate::Result<impl Iterator<Item = Vec<u8>>> {
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

        let messages = self
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
            .collect::<Vec<_>>();

        Ok(messages.into_iter())
    }
}

impl<R: Runtime> Stream for Destination<R> {
    type Item = DestinationEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
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
                        self.remote_destinations.insert(destination_id.clone(), lease_set);

                        return Poll::Ready(Some(DestinationEvent::LeaseSetFound {
                            destination_id,
                        }));
                    }
                },
            }
        }

        self.pending_events.pop_front().map_or_else(
            || {
                self.waker = Some(cx.waker().clone());
                Poll::Pending
            },
            |event| Poll::Ready(Some(event)),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::runtime::{mock::MockRuntime, Runtime};

    use super::*;

    #[tokio::test]
    async fn query_lease_set_found() {
        let (handle, _rx) = NetDbHandle::create();
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::new(MockRuntime::rng()),
            Bytes::new(),
            handle,
        );

        // insert dummy lease set for `remote` into `Destination`
        let remote = DestinationId::random();
        let (lease_set, signing_key) = LeaseSet2::random();
        destination.remote_destinations.insert(remote.clone(), lease_set);

        // query lease set and verify it exists
        assert_eq!(destination.query_lease_set(&remote), LeaseSetStatus::Found);
    }

    #[tokio::test]
    async fn query_lease_set_not_found() {
        let (handle, mut rx) = NetDbHandle::create();
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::new(MockRuntime::rng()),
            Bytes::new(),
            handle,
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
        let (handle, mut rx) = NetDbHandle::create();
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::new(MockRuntime::rng()),
            Bytes::new(),
            handle,
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
        let (handle, mut rx) = NetDbHandle::create();
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::new(MockRuntime::rng()),
            Bytes::new(),
            handle.clone(),
        );

        // spam the netdb handle full of queries
        loop {
            if handle.query_leaseset(Bytes::new()).is_err() {
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
        let (handle, mut rx) = NetDbHandle::create();
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::new(MockRuntime::rng()),
            Bytes::new(),
            handle,
        );

        destination.encrypt_message(&DestinationId::random(), vec![1, 2, 3, 4]);
    }
}
