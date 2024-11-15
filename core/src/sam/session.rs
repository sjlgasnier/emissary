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
    crypto::{base64_encode, SigningPrivateKey, StaticPrivateKey},
    destination::{Destination, DestinationEvent, LeaseSetStatus},
    error::QueryError,
    i2cp::{I2cpPayload, I2cpPayloadBuilder},
    primitives::{Destination as Dest, DestinationId, LeaseSet2, LeaseSet2Header},
    protocol::Protocol,
    runtime::Runtime,
    sam::{
        parser::{DestinationKind, SamVersion},
        pending::session::SamSessionContext,
        protocol::streaming::{Direction, ListenerKind, StreamManager, StreamManagerEvent},
        socket::SamSocket,
    },
};

use bytes::{BufMut, Bytes, BytesMut};
use futures::StreamExt;
use hashbrown::HashMap;
use thingbuf::mpsc::Receiver;

use alloc::{format, string::String, sync::Arc, vec, vec::Vec};
use core::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::sam::session";

/// Recycling strategy for [`SamSessionCommand`].
#[derive(Default, Clone)]
pub(super) struct SamSessionCommandRecycle(());

impl<R: Runtime> thingbuf::Recycle<SamSessionCommand<R>> for SamSessionCommandRecycle {
    fn new_element(&self) -> SamSessionCommand<R> {
        SamSessionCommand::Dummy
    }

    fn recycle(&self, element: &mut SamSessionCommand<R>) {
        *element = SamSessionCommand::Dummy;
    }
}

/// SAMv3 session commands.
pub enum SamSessionCommand<R: Runtime> {
    /// Open virtual stream to `destination` over this connection.
    Connect {
        /// SAMv3 socket associated with the outbound stream.
        socket: SamSocket<R>,

        /// Destination.
        destination: Dest,

        /// Options.
        options: HashMap<String, String>,
    },

    /// Accept inbond virtual stream over this connection.
    Accept {
        /// SAMv3 socket associated with the inbound stream.
        socket: SamSocket<R>,

        /// Options.
        options: HashMap<String, String>,
    },

    /// Forward incoming virtual streams to a TCP listener listening to `port`.
    Forward {
        /// SAMv3 socket associated with forwarding.
        socket: SamSocket<R>,

        /// Port which the TCP listener is listening.
        port: u16,

        /// Options.
        options: HashMap<String, String>,
    },

    /// Dummy event, never constructed.
    Dummy,
}

impl<R: Runtime> Default for SamSessionCommand<R> {
    fn default() -> Self {
        Self::Dummy
    }
}

/// State of a pending outbound stream.
enum PendingStreamState<R: Runtime> {
    /// Awaiting lease set query result.
    AwaitingLeaseSet {
        /// SAMv3 client socket.
        socket: SamSocket<R>,

        /// Remote destination.
        destination: Dest,

        /// Stream options.
        options: HashMap<String, String>,
    },

    /// Awaiting session to be created
    AwaitingSession {
        /// Stream ID assigned by [`StreamManager`].
        stream_id: u32,
    },
}

impl<R: Runtime> fmt::Debug for PendingStreamState<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AwaitingLeaseSet {
                socket,
                destination,
                options,
            } => f
                .debug_struct("PendingStreamState::AwaitingLeaseSet")
                .field("destination", &format_args!("{}", destination.id()))
                .finish_non_exhaustive(),
            Self::AwaitingSession { stream_id } => f
                .debug_struct("PendingStreamState::AwaitingSession")
                .field("stream_id", &stream_id)
                .finish(),
        }
    }
}

/// Active SAMv3 session.
pub struct SamSession<R: Runtime> {
    /// [`Dest`] of the session.
    ///
    /// Used to create new lease sets.
    dest: Dest,

    /// [`Destination`] of the session.
    destination: Destination<R>,

    /// Encryption key.
    encryption_key: StaticPrivateKey,

    /// Session options.
    options: HashMap<String, String>,

    /// Pending outbound streams.
    ///
    /// `STREAM CONNECT` is marked pending if there is no active lease set for the remote
    /// destination. The stream is moved from pending to active/rejected, based on the lease set
    /// query result.
    pending_outbound: HashMap<DestinationId, PendingStreamState<R>>,

    /// Receiver for commands sent for this session.
    ///
    /// Commands are dispatched by `SamServer` which ensures that [`SamCommand::CreateSession`]
    /// is never received by an active session.
    receiver: Receiver<SamSessionCommand<R>, SamSessionCommandRecycle>,

    /// Session ID.
    session_id: Arc<str>,

    /// Signing key.
    signing_key: SigningPrivateKey,

    /// Socket for reading session-related commands from the client.
    socket: SamSocket<R>,

    /// I2P virtual stream manager.
    stream_manager: StreamManager<R>,

    /// Negotiated SAMv3 version.
    version: SamVersion,
}

impl<R: Runtime> SamSession<R> {
    /// Create new [`SamSession`].
    pub fn new(context: SamSessionContext<R>) -> Self {
        let SamSessionContext {
            destination,
            inbound,
            mut socket,
            netdb_handle,
            options,
            outbound,
            receiver,
            session_id,
            tunnel_pool_handle,
            version,
        } = context;

        let (session_destination, dest, privkey, encryption_key, signing_key) = {
            let (encryption_key, signing_key, destination_id, destination) = match destination {
                DestinationKind::Transient => {
                    let mut rng = R::rng();

                    let signing_key = SigningPrivateKey::random(&mut rng);
                    let encryption_key = StaticPrivateKey::new(rng);

                    let destination = Dest::new(signing_key.public());
                    let destination_id = destination.id();

                    (encryption_key, signing_key, destination_id, destination)
                }
                DestinationKind::Persistent {
                    destination,
                    private_key,
                    signing_key,
                } => (private_key, signing_key, destination.id(), destination),
            };

            // from specification:
            //
            // "The $privkey is the base 64 of the concatenation of the Destination followed by the
            // Private Key followed by the Signing Private Key, optionally followed by the Offline
            // Signature, which is 663 or more bytes in binary and 884 or more bytes in base 64,
            // depending on signature type. The binary format is specified in Private Key File."
            let privkey = {
                let mut out = BytesMut::with_capacity(destination.serialized_len() + 2 * 32);
                out.put_slice(&destination.serialize());
                out.put_slice(encryption_key.as_ref());
                out.put_slice(signing_key.as_ref());

                base64_encode(out)
            };

            // create leaseset for the destination and store it in `NetDb`
            let local_leaseset = Bytes::from(
                LeaseSet2 {
                    header: LeaseSet2Header {
                        destination: destination.clone(),
                        published: R::time_since_epoch().as_secs() as u32,
                        expires: (R::time_since_epoch() + Duration::from_secs(10 * 60)).as_secs()
                            as u32,
                    },
                    public_keys: vec![encryption_key.public()],
                    leases: inbound.values().cloned().collect(),
                }
                .serialize(&signing_key),
            );

            if let Err(error) = netdb_handle
                .store_leaseset(Bytes::from(destination_id.to_vec()), local_leaseset.clone())
            {
                tracing::warn!(
                    target: LOG_TARGET,
                    %destination_id,
                    ?error,
                    "failed to publish lease set"
                );
                todo!();
            }

            tracing::info!(
                target: LOG_TARGET,
                %session_id,
                %destination_id,
                "start active session",
            );

            (
                Destination::new(
                    destination_id.clone(),
                    encryption_key.clone(),
                    local_leaseset,
                    netdb_handle,
                    tunnel_pool_handle,
                ),
                destination,
                privkey,
                encryption_key,
                signing_key,
            )
        };

        socket.send_message(
            format!("SESSION STATUS RESULT=OK DESTINATION={privkey}\n").as_bytes().to_vec(),
        );

        Self {
            dest: dest.clone(),
            destination: session_destination,
            encryption_key,
            options,
            pending_outbound: HashMap::new(),
            receiver,
            session_id,
            signing_key: signing_key.clone(),
            socket,
            stream_manager: StreamManager::new(dest, signing_key),
            version,
        }
    }

    /// Handle `STREAM CONNECT`.
    ///
    /// TODO: more documentation
    fn on_stream_connect(
        &mut self,
        socket: SamSocket<R>,
        destination: Dest,
        options: HashMap<String, String>,
    ) {
        tracing::info!(
            target: LOG_TARGET,
            session_id = %self.session_id,
            destination_id = %destination.id(),
            "connect to destination",
        );
        let destination_id = destination.id();

        match self.destination.query_lease_set(&destination_id) {
            LeaseSetStatus::Found => {
                tracing::error!(
                    target: LOG_TARGET,
                    "not implemented",
                );
                todo!();
            }
            LeaseSetStatus::NotFound => {
                tracing::trace!(
                    target: LOG_TARGET,
                    session_id = %self.session_id,
                    %destination_id,
                    "lease set query started, mark outbound stream as pending",
                );

                self.pending_outbound.insert(
                    destination_id,
                    PendingStreamState::AwaitingLeaseSet {
                        socket,
                        destination,
                        options,
                    },
                );
            }
            LeaseSetStatus::Pending => {
                tracing::warn!(
                    target: LOG_TARGET,
                    session_id = %self.session_id,
                    %destination_id,
                    "received duplicate `STREAM CONNECT` for destination",
                );
            }
        }
    }

    /// Handle succeeded lease set query result.
    ///
    /// Lease set query is initiated only if the client wants to create a new session with remote
    /// destination so fetch the initial protocol message from the protocol handler and send it to
    /// remote destination.
    fn on_lease_set_found(&mut self, destination_id: DestinationId) {
        match self.pending_outbound.remove(&destination_id) {
            Some(PendingStreamState::AwaitingLeaseSet {
                socket,
                destination,
                options,
            }) => {
                let destination_id = destination.id();
                let (packet, stream_id) = self.stream_manager.create_stream(
                    destination_id.clone(),
                    socket,
                    options
                        .get("SILENT")
                        .map_or(false, |value| value.parse::<bool>().unwrap_or(false)),
                );

                tracing::trace!(
                    target: LOG_TARGET,
                    session_id = ?self.session_id,
                    %destination_id,
                    ?stream_id,
                    "lease set found, create outbound stream",
                );

                self.pending_outbound.insert(
                    destination_id.clone(),
                    PendingStreamState::AwaitingSession { stream_id },
                );

                let Some(message) = I2cpPayloadBuilder::<R>::new(&packet)
                    .with_protocol(Protocol::Streaming)
                    .build()
                else {
                    tracing::error!(
                        target: LOG_TARGET,
                        session_id = ?self.session_id,
                        "failed to create i2cp payload",
                    );
                    debug_assert!(false);
                    return;
                };

                if let Err(error) = self.destination.send_message(&destination_id, message) {
                    tracing::error!(
                        target: LOG_TARGET,
                        session_id = ?self.session_id,
                        ?error,
                        "failed to send message to remote peer",
                    );
                    debug_assert!(false);
                }
            }
            state => {
                tracing::warn!(
                    target: LOG_TARGET,
                    session_id = ?self.session_id,
                    %destination_id,
                    ?state,
                    "stream in invalid state for lease set query result",
                );
                debug_assert!(false);
            }
        }
    }

    /// Handle lease set query error for `destination_id`.
    ///
    /// Client is notified that the remote destination is not reachable and the socket is closed.
    fn on_lease_set_not_found(&mut self, destination_id: DestinationId, error: QueryError) {
        match self.pending_outbound.remove(&destination_id) {
            Some(PendingStreamState::AwaitingLeaseSet { mut socket, .. }) => {
                R::spawn(async move {
                    socket
                        .send_message_blocking(b"STREAM STATUS STATUS=CANT_REACH_PEER".to_vec())
                        .await;
                });
            }
            state => {
                tracing::warn!(
                    target: LOG_TARGET,
                    session_id = ?self.session_id,
                    %destination_id,
                    ?state,
                    "stream in invalid state for lease set query error",
                );
                debug_assert!(false);
            }
        }
    }

    /// Handle one or more inbound messages.
    fn on_inbound_message(&mut self, messages: Vec<Vec<u8>>) {
        messages
            .into_iter()
            .for_each(|message| match I2cpPayload::decompress::<R>(message) {
                Some(I2cpPayload {
                    dst_port,
                    payload,
                    protocol,
                    src_port,
                }) => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        session_id = ?self.session_id,
                        ?src_port,
                        ?dst_port,
                        ?protocol,
                        "handle protocol payload",
                    );

                    match protocol {
                        Protocol::Streaming => {
                            if let Err(error) =
                                self.stream_manager.on_packet(src_port, dst_port, payload)
                            {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    session_id = ?self.session_id,
                                    ?error,
                                    "failed to handle streaming protocol packet",
                                );
                            }
                        }
                        protocol => tracing::warn!(
                            target: LOG_TARGET,
                            ?protocol,
                            "unsupported protocol",
                        ),
                    }
                }
                None => tracing::warn!(
                    target: LOG_TARGET,
                    session_id = ?self.session_id,
                    "failed to decompress i2cp payload",
                ),
            })
    }
}

impl<R: Runtime> Future for SamSession<R> {
    type Output = Arc<str>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.socket.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(Arc::clone(&self.session_id)),
                Poll::Ready(Some(command)) => match command {
                    command => tracing::warn!(
                        target: LOG_TARGET,
                        session_id = %self.session_id,
                        ?command,
                        "ignoring command"
                    ),
                },
            }
        }

        loop {
            match self.receiver.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(Arc::clone(&self.session_id)),
                Poll::Ready(Some(SamSessionCommand::Connect {
                    socket,
                    destination,
                    options,
                })) => self.on_stream_connect(socket, destination, options),
                Poll::Ready(Some(SamSessionCommand::Accept { socket, options })) =>
                    if let Err(error) =
                        self.stream_manager.register_listener(ListenerKind::Ephemeral {
                            socket,
                            silent: options
                                .get("SILENT")
                                .map_or(false, |value| value.parse::<bool>().unwrap_or(false)),
                        })
                    {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?error,
                            session_id = %self.session_id,
                            "failed to register ephemeral listener",
                        );
                    },
                Poll::Ready(Some(SamSessionCommand::Forward {
                    socket,
                    port,
                    options,
                })) =>
                    if let Err(error) =
                        self.stream_manager.register_listener(ListenerKind::Persistent {
                            socket,
                            port,
                            silent: options
                                .get("SILENT")
                                .map_or(false, |value| value.parse::<bool>().unwrap_or(false)),
                        })
                    {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?error,
                            session_id = %self.session_id,
                            "failed to register persistent listener",
                        );
                    },
                Poll::Ready(Some(SamSessionCommand::Dummy)) => unreachable!(),
            }
        }

        loop {
            match self.stream_manager.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(Arc::clone(&self.session_id)),
                Poll::Ready(Some(StreamManagerEvent::SendPacket {
                    destination_id,
                    packet,
                })) => {
                    let Some(message) = I2cpPayloadBuilder::<R>::new(&packet)
                        .with_protocol(Protocol::Streaming)
                        .build()
                    else {
                        tracing::warn!(
                            target: LOG_TARGET,
                            session_id = ?self.session_id,
                            "failed to create i2cp payload",
                        );
                        continue;
                    };

                    if let Err(error) = self.destination.send_message(&destination_id, message) {
                        tracing::warn!(
                            target: LOG_TARGET,
                            session_id = ?self.session_id,
                            ?error,
                            "failed to encrypt message",
                        );
                    };
                }
                Poll::Ready(Some(StreamManagerEvent::StreamOpened {
                    destination_id,
                    direction,
                })) => match direction {
                    Direction::Inbound => {}
                    Direction::Outbound => {
                        self.pending_outbound.remove(&destination_id);
                    }
                },
                Poll::Ready(Some(StreamManagerEvent::StreamRejected { destination_id })) => {
                    self.pending_outbound.remove(&destination_id);
                }
                Poll::Ready(Some(StreamManagerEvent::StreamClosed { destination_id })) => {}
            }
        }

        loop {
            match self.destination.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(Arc::clone(&self.session_id)),
                Poll::Ready(Some(DestinationEvent::Messages { messages })) =>
                    self.on_inbound_message(messages),
                Poll::Ready(Some(DestinationEvent::LeaseSetFound { destination_id })) =>
                    self.on_lease_set_found(destination_id),
                Poll::Ready(Some(DestinationEvent::LeaseSetNotFound {
                    destination_id,
                    error,
                })) => self.on_lease_set_not_found(destination_id, error),
                Poll::Ready(Some(DestinationEvent::TunnelPoolShutDown)) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        session_id = ?self.session_id,
                        "tunnel pool shut down, shutting down session",
                    );

                    return Poll::Ready(Arc::clone(&self.session_id));
                }
                Poll::Ready(Some(DestinationEvent::CreateLeaseSet { leases })) => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        session_id = ?self.session_id,
                        num_leases = ?leases.len(),
                        "create new lease set",
                    );

                    let lease_set = Bytes::from(
                        LeaseSet2 {
                            header: LeaseSet2Header {
                                destination: self.dest.clone(),
                                published: R::time_since_epoch().as_secs() as u32,
                                expires: (R::time_since_epoch() + Duration::from_secs(10 * 60))
                                    .as_secs() as u32,
                            },
                            public_keys: vec![self.encryption_key.public()],
                            leases,
                        }
                        .serialize(&self.signing_key),
                    );
                    let destination_id = Bytes::from(self.dest.id().to_vec());

                    self.destination.publish_lease_set(destination_id, lease_set);
                }
            }
        }

        Poll::Pending
    }
}
