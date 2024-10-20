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
    error::Error,
    i2np::{
        database::store::{DatabaseStore, DatabaseStorePayload},
        Message, MessageType,
    },
    primitives::{Destination as Dest, DestinationId, LeaseSet2, RouterId, TunnelId},
    runtime::Runtime,
};

use bytes::Bytes;
use futures::Stream;

use alloc::{collections::VecDeque, vec::Vec};
use core::{
    pin::Pin,
    task::{Context, Poll, Waker},
};
use hashbrown::HashMap;

pub mod protocol;
pub mod session;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::destination";

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
}

/// Client destination.
pub struct Destination<R: Runtime> {
    /// Destination ID of the client.
    destination_id: DestinationId,

    /// Serialized [`LeaseSet2`] for client's inbound tunnels.
    leaseset: Bytes,

    /// Pending events.
    pending_events: VecDeque<DestinationEvent>,

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
        leaseset: Bytes,
    ) -> Self {
        Self {
            destination_id: destination_id.clone(),
            session_manager: SessionManager::new(destination_id, private_key, leaseset.clone()),
            leaseset,
            pending_events: VecDeque::new(),
            remote_destinations: HashMap::new(),
            waker: None,
        }
    }

    /// Encrypt `message` destined to `destination_id`.
    ///
    /// If `destination_id` is not known to `Destination`, a lease set query is initiated and if the
    /// lease set is fetched successfully, the message is sent to remote.
    ///
    /// Caller must call [`Destination::poll_next()`] to drive progress forward.
    pub fn encrypt_message(
        &mut self,
        destination_id: &DestinationId,
        message: Vec<u8>,
    ) -> crate::Result<()> {
        let Some(LeaseSet2 { leases, .. }) = self.remote_destinations.get(destination_id) else {
            tracing::error!(
                target: LOG_TARGET,
                %destination_id,
                "lease set lookup not implemented",
            );
            return Ok(());
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
        self.pending_events.pop_front().map_or_else(
            || {
                self.waker = Some(cx.waker().clone());
                Poll::Pending
            },
            |event| Poll::Ready(Some(event)),
        )
    }
}
