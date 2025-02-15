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
    crypto::{base32_decode, base64_encode, SigningPrivateKey, StaticPrivateKey},
    destination::{Destination, DestinationEvent, LeaseSetStatus},
    error::QueryError,
    i2cp::{I2cpPayload, I2cpPayloadBuilder},
    primitives::{Destination as Dest, DestinationId, LeaseSet2, LeaseSet2Header},
    protocol::Protocol,
    runtime::{AddressBook, JoinSet, Runtime},
    sam::{
        parser::{DestinationContext, SamCommand, SessionKind},
        pending::session::SamSessionContext,
        protocol::{
            datagram::DatagramManager,
            streaming::{Direction, ListenerKind, StreamManager, StreamManagerEvent},
        },
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
    task::{Context, Poll, Waker},
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

        /// Destination ID.
        destination_id: DestinationId,

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

    /// Send repliable datagram to remote destination.
    SendDatagram {
        /// Destination of the receiver.
        destination: Dest,

        /// Datagram.
        datagram: Vec<u8>,
    },

    /// Dummy event, never constructed.
    Dummy,
}

impl<R: Runtime> Default for SamSessionCommand<R> {
    fn default() -> Self {
        Self::Dummy
    }
}

/// What kind of protocol is awaiting session to open.
enum ProtocolKind<R: Runtime> {
    /// Streaming protocol.
    Stream {
        /// SAMv3 client socket.
        socket: SamSocket<R>,

        /// Stream options.
        options: HashMap<String, String>,
    },

    /// Datagram protocol.
    Datagram {
        /// Destination of the remote peer.
        destination: Dest,

        /// Datagrams that are waiting to be sent.
        datagrams: Vec<Vec<u8>>,
    },
}

impl<R: Runtime> fmt::Debug for ProtocolKind<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stream { .. } => f.debug_struct("ProtocolKind::Stream").finish_non_exhaustive(),
            Self::Datagram { .. } =>
                f.debug_struct("ProtocolKind::Datagram").finish_non_exhaustive(),
        }
    }
}

/// State of a pending outbound session.
enum PendingSessionState<R: Runtime> {
    /// Awaiting lease set query result.
    AwaitingLeaseSet { protocol: ProtocolKind<R> },

    /// Awaiting session to be created
    AwaitingSession {
        /// Stream ID assigned by [`StreamManager`].
        stream_id: u32,
    },
}

impl<R: Runtime> fmt::Debug for PendingSessionState<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AwaitingLeaseSet { protocol } => f
                .debug_struct("PendingSessionState::AwaitingLeaseSet")
                .field("protocol", &protocol)
                .finish_non_exhaustive(),
            Self::AwaitingSession { stream_id } => f
                .debug_struct("PendingSessionState::AwaitingSession")
                .field("stream_id", &stream_id)
                .finish(),
        }
    }
}

/// Active SAMv3 session.
pub struct SamSession<R: Runtime> {
    /// Address book.
    address_book: Option<Arc<dyn AddressBook>>,

    /// I2P datagram manager.
    datagram_manager: DatagramManager<R>,

    /// [`Dest`] of the session.
    ///
    /// Used to create new lease sets.
    dest: Dest,

    /// [`Destination`] of the session.
    destination: Destination<R>,

    /// Encryption key.
    encryption_key: StaticPrivateKey,

    /// Pending host lookups
    lookup_futures: R::JoinSet<(String, Option<String>)>,

    /// Session options.
    #[allow(unused)]
    options: HashMap<String, String>,

    /// Pending host lookups.
    ///
    /// Pending `NAMING LOOKUP` queries for `.b32.i2p` addresses are stored here
    /// while the corresponding lease set is being queried.
    pending_host_lookups: HashMap<DestinationId, String>,

    /// Pending outbound streams.
    ///
    /// `STREAM CONNECT` is marked pending if there is no active lease set for the remote
    /// destination. The stream is moved from pending to active/rejected, based on the lease set
    /// query result.
    pending_outbound: HashMap<DestinationId, PendingSessionState<R>>,

    /// Receiver for commands sent for this session.
    ///
    /// Commands are dispatched by `SamServer` which ensures that [`SamCommand::CreateSession`]
    /// is never received by an active session.
    receiver: Receiver<SamSessionCommand<R>, SamSessionCommandRecycle>,

    /// Session ID.
    session_id: Arc<str>,

    /// Session kind.
    session_kind: SessionKind,

    /// Signing key.
    signing_key: SigningPrivateKey,

    /// Socket for reading session-related commands from the client.
    ///
    /// Set to `None` after the socket has been closed and th session is being destroyed.
    socket: Option<SamSocket<R>>,

    /// I2P virtual stream manager.
    stream_manager: StreamManager<R>,

    /// Waker.
    waker: Option<Waker>,
}

impl<R: Runtime> SamSession<R> {
    /// Create new [`SamSession`].
    pub fn new(context: SamSessionContext<R>) -> Self {
        let SamSessionContext {
            address_book,
            destination,
            inbound,
            mut socket,
            netdb_handle,
            options,
            outbound,
            receiver,
            datagram_tx,
            session_id,
            session_kind,
            tunnel_pool_handle,
        } = context;

        let (session_destination, dest, privkey, encryption_key, signing_key) = {
            let DestinationContext {
                destination,
                private_key,
                signing_key,
            } = destination;
            let destination_id = destination.id();

            // from specification:
            //
            // "The $privkey is the base 64 of the concatenation of the Destination followed by the
            // Private Key followed by the Signing Private Key, optionally followed by the Offline
            // Signature, which is 663 or more bytes in binary and 884 or more bytes in base 64,
            // depending on signature type. The binary format is specified in Private Key File."
            let privkey = {
                let mut out = BytesMut::with_capacity(destination.serialized_len() + 2 * 32);
                out.put_slice(&destination.serialize());
                out.put_slice((*private_key).as_ref());
                out.put_slice((*signing_key).as_ref());

                base64_encode(out)
            };

            // create leaseset for the destination and store it in `NetDb`
            let public_key = private_key.public();
            let local_leaseset = Bytes::from(
                LeaseSet2 {
                    header: LeaseSet2Header {
                        destination: destination.clone(),
                        expires: Duration::from_secs(10 * 60).as_secs() as u32,
                        offline_signature: None,
                        published: R::time_since_epoch().as_secs() as u32,
                    },
                    public_keys: vec![public_key],
                    leases: inbound.values().cloned().collect(),
                }
                .serialize(&signing_key),
            );

            let mut session_destination = Destination::new(
                destination_id.clone(),
                *private_key.clone(),
                local_leaseset.clone(),
                netdb_handle,
                tunnel_pool_handle,
                outbound.into_iter().collect(),
                inbound.into_values().collect(),
                options
                    .get("i2cp.dontPublishLeaseSet")
                    .map(|value| value.parse::<bool>().unwrap_or(false))
                    .unwrap_or(false),
            );
            session_destination
                .publish_lease_set(Bytes::from(destination_id.to_vec()), local_leaseset.clone());

            tracing::info!(
                target: LOG_TARGET,
                %session_id,
                %destination_id,
                "start active session",
            );

            (
                session_destination,
                destination,
                privkey,
                private_key,
                signing_key,
            )
        };

        socket.send_message(
            format!("SESSION STATUS RESULT=OK DESTINATION={privkey}\n").as_bytes().to_vec(),
        );

        Self {
            address_book,
            datagram_manager: DatagramManager::new(
                dest.clone(),
                datagram_tx,
                options.clone(),
                *signing_key.clone(),
                session_kind,
            ),
            dest: dest.clone(),
            destination: session_destination,
            encryption_key: *encryption_key,
            lookup_futures: R::join_set(),
            options,
            pending_host_lookups: HashMap::new(),
            pending_outbound: HashMap::new(),
            receiver,
            session_id,
            session_kind,
            signing_key: *signing_key.clone(),
            socket: Some(socket),
            stream_manager: StreamManager::new(dest, *signing_key),
            waker: None,
        }
    }

    /// Create outbound stream for a remote destiantion who's lease set has been resolved.
    ///
    /// The stream is considered pending and it's acceptance contingent on the remote destination
    /// responding to us within a reasonable time frame.
    fn create_outbound_stream(
        &mut self,
        destination_id: DestinationId,
        socket: SamSocket<R>,
        options: HashMap<String, String>,
    ) {
        let (stream_id, packet, src_port, dst_port) =
            self.stream_manager.create_stream(destination_id.clone(), socket, options);

        tracing::trace!(
            target: LOG_TARGET,
            %destination_id,
            ?stream_id,
            ?src_port,
            ?dst_port,
            "create pending outbound stream",
        );

        // mark the stream as pending & waiting for session to be opened
        //
        // from now on `StreamManager` will drive forward the stream progress and will
        // emit an event when the stream opens/fails to open
        self.pending_outbound.insert(
            destination_id.clone(),
            PendingSessionState::AwaitingSession { stream_id },
        );

        let Some(message) = I2cpPayloadBuilder::<R>::new(&packet)
            .with_protocol(Protocol::Streaming)
            .with_source_port(src_port)
            .with_destination_port(dst_port)
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

    /// Handle `STREAM CONNECT`.
    ///
    /// TODO: more documentation
    fn on_stream_connect(
        &mut self,
        mut socket: SamSocket<R>,
        destination_id: DestinationId,
        options: HashMap<String, String>,
    ) {
        let SessionKind::Stream = &self.session_kind else {
            tracing::warn!(
                target: LOG_TARGET,
                session_id = %self.session_id,
                stream_kind = ?self.session_kind,
                "session style doesn't support streams",
            );

            return drop(socket);
        };

        if destination_id == self.dest.id() {
            tracing::warn!(
                target: LOG_TARGET,
                "tried to open connection to self",
            );

            R::spawn(async move {
                let _ = socket
                    .send_message_blocking(b"STREAM STATUS RESULT=CANT_REACH_PEER\n".to_vec())
                    .await;
            });
            return;
        }

        tracing::info!(
            target: LOG_TARGET,
            session_id = %self.session_id,
            destination_id = %destination_id,
            "connect to destination",
        );

        match self.destination.query_lease_set(&destination_id) {
            LeaseSetStatus::Found => {
                tracing::trace!(
                    target: LOG_TARGET,
                    session_id = ?self.session_id,
                    %destination_id,
                    "lease set found, create outbound stream",
                );

                self.create_outbound_stream(destination_id, socket, options);
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
                    PendingSessionState::AwaitingLeaseSet {
                        protocol: ProtocolKind::Stream { socket, options },
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

    /// Handle `STREAM ACCEPT` command.
    ///
    /// Register the socket as an active listener to [`StreamManager`].
    ///
    /// If the session wasn't configured to use streams, reject the accept request.
    fn on_stream_accept(&mut self, socket: SamSocket<R>, options: HashMap<String, String>) {
        let SessionKind::Stream = &self.session_kind else {
            tracing::warn!(
                target: LOG_TARGET,
                session_id = %self.session_id,
                stream_kind = ?self.session_kind,
                "session style doesn't support streams",
            );

            return drop(socket);
        };

        if let Err(error) = self.stream_manager.register_listener(ListenerKind::Ephemeral {
            socket,
            silent: options
                .get("SILENT")
                .map_or(false, |value| value.parse::<bool>().unwrap_or(false)),
        }) {
            tracing::warn!(
                target: LOG_TARGET,
                ?error,
                session_id = %self.session_id,
                "failed to register ephemeral listener",
            );
        }
    }

    /// Handle `STREAM FORWARD` command.
    ///
    /// Register the socket as an active listener to [`StreamManager`].
    ///
    /// If the session wasn't configured to use streams, reject the forward request.
    fn on_stream_forward(
        &mut self,
        socket: SamSocket<R>,
        port: u16,
        options: HashMap<String, String>,
    ) {
        let SessionKind::Stream = &self.session_kind else {
            tracing::warn!(
                target: LOG_TARGET,
                session_id = %self.session_id,
                stream_kind = ?self.session_kind,
                "session style doesn't support streams",
            );

            return drop(socket);
        };

        if let Err(error) = self.stream_manager.register_listener(ListenerKind::Persistent {
            socket,
            port,
            silent: options
                .get("SILENT")
                .map_or(false, |value| value.parse::<bool>().unwrap_or(false)),
        }) {
            tracing::warn!(
                target: LOG_TARGET,
                ?error,
                session_id = %self.session_id,
                "failed to register persistent listener",
            );
        }
    }

    /// Send datagram to destination.
    ///
    /// If the session wasn't configured to use streams, the datagram is dropped.
    fn on_send_datagram(&mut self, destination: Dest, datagram: Vec<u8>) {
        if let SessionKind::Stream = &self.session_kind {
            tracing::warn!(
                target: LOG_TARGET,
                session_id = %self.session_id,
                stream_kind = ?self.session_kind,
                "session style doesn't support datagrams",
            );
            return;
        }

        tracing::info!(
            target: LOG_TARGET,
            session_id = %self.session_id,
            destination_id = %destination.id(),
            style = ?self.session_kind,
            "send datagram",
        );
        let destination_id = destination.id();

        match self.destination.query_lease_set(&destination_id) {
            LeaseSetStatus::Found => {
                let datagram = self.datagram_manager.make_datagram(datagram);

                if let Some(message) = I2cpPayloadBuilder::<R>::new(&datagram)
                    .with_protocol(self.session_kind.into())
                    .build()
                {
                    if let Err(error) = self.destination.send_message(&destination_id, message) {
                        tracing::warn!(
                            target: LOG_TARGET,
                            session_id = %self.session_id,
                            destination_id = %destination.id(),
                            ?error,
                            "failed to send repliable datagram",
                        )
                    }
                };
            }
            LeaseSetStatus::NotFound => {
                tracing::trace!(
                    target: LOG_TARGET,
                    session_id = %self.session_id,
                    %destination_id,
                    "lease set query started, mark outbound datagram as pending",
                );

                self.pending_outbound.insert(
                    destination_id,
                    PendingSessionState::AwaitingLeaseSet {
                        protocol: ProtocolKind::Datagram {
                            destination,
                            datagrams: vec![datagram],
                        },
                    },
                );
            }
            LeaseSetStatus::Pending => {
                tracing::warn!(
                    target: LOG_TARGET,
                    session_id = %self.session_id,
                    %destination_id,
                    "received datagram while session was pending",
                );

                match self.pending_outbound.get_mut(&destination_id) {
                    Some(PendingSessionState::AwaitingLeaseSet {
                        protocol: ProtocolKind::Datagram { datagrams, .. },
                    }) => {
                        datagrams.push(datagram);
                    }
                    state => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            session_id = %self.session_id,
                            %destination_id,
                            ?state,
                            "invalid state for repliable datagram",
                        );
                        debug_assert!(false);
                    }
                }
            }
        }
    }

    /// Handle succeeded lease set query result.
    ///
    /// Lease set query is initiated only if the client wants to create a new session with remote
    /// destination so fetch the initial protocol message from the protocol handler and send it to
    /// remote destination.
    fn on_lease_set_found(&mut self, destination_id: DestinationId) {
        tracing::trace!(
            target: LOG_TARGET,
            session_id = %self.session_id,
            %destination_id,
            "lease set found",
        );

        match self.pending_outbound.remove(&destination_id) {
            Some(PendingSessionState::AwaitingLeaseSet { protocol }) => match protocol {
                ProtocolKind::Stream {
                    socket, options, ..
                } => self.create_outbound_stream(destination_id.clone(), socket, options),
                ProtocolKind::Datagram {
                    destination,
                    datagrams,
                } => datagrams.into_iter().for_each(|datagram| {
                    let datagram = self.datagram_manager.make_datagram(datagram);

                    if let Some(message) = I2cpPayloadBuilder::<R>::new(&datagram)
                        .with_protocol(self.session_kind.into())
                        .build()
                    {
                        if let Err(error) = self.destination.send_message(&destination_id, message)
                        {
                            tracing::warn!(
                                target: LOG_TARGET,
                                session_id = %self.session_id,
                                destination_id = %destination.id(),
                                ?error,
                                "failed to send repliable datagram",
                            )
                        }
                    };
                }),
            },
            Some(PendingSessionState::AwaitingSession { .. }) => {
                // new stream was opened but by the the time the initial `SYN` packet was sent,
                // remote's lease set had expired and they had not sent us, a new lease set a lease
                // set query was started and the lease set was found
                //
                // the new lease set can be ignored for `PendingSessionState::AwaitinSession` since
                // the `SYN` packet was queued in `Destination` and was sent to remote destination
                // when the lease set was received
            }
            None => tracing::debug!(
                target: LOG_TARGET,
                session_id = ?self.session_id,
                %destination_id,
                "lease set query succeeded but no stream is interested in the lease set",
            ),
        }

        if let Some(name) = self.pending_host_lookups.remove(&destination_id) {
            tracing::trace!(
                target: LOG_TARGET,
                session_id = ?self.session_id,
                %destination_id,
                ?name,
                "lease set query succeeded for pending host lookup",
            );

            if let Some(socket) = &mut self.socket {
                socket.send_message(
                    format!(
                        "NAMING REPLY RESULT=OK NAME={name} VALUE={}\n",
                        base64_encode(
                            self.destination
                                .lease_set(&destination_id)
                                .header
                                .destination
                                .serialized()
                        ),
                    )
                    .as_bytes()
                    .to_vec(),
                );

                if let Some(waker) = self.waker.take() {
                    waker.wake_by_ref();
                }
            }
        }
    }

    /// Handle lease set query error for `destination_id`.
    ///
    /// Client is notified that the remote destination is not reachable and the socket is closed.
    fn on_lease_set_not_found(&mut self, destination_id: DestinationId, error: QueryError) {
        tracing::trace!(
            target: LOG_TARGET,
            session_id = %self.session_id,
            %destination_id,
            ?error,
            "lease set not found",
        );

        match self.pending_outbound.remove(&destination_id) {
            Some(PendingSessionState::AwaitingLeaseSet { protocol }) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    session_id = ?self.session_id,
                    %destination_id,
                    ?protocol,
                    ?error,
                    "failed to find lease set",
                );

                if let ProtocolKind::Stream { mut socket, .. } = protocol {
                    R::spawn(async move {
                        let _ = socket
                            .send_message_blocking(b"STREAM STATUS RESULT=CANT_REACH_PEER".to_vec())
                            .await;
                    });
                }
            }
            Some(PendingSessionState::AwaitingSession { stream_id }) => {
                // new stream was opened but by the the time the initial `SYN` packet was sent,
                // remote's lease set had expired and they had not sent us, a new lease set a lease
                // set query was started but the lease set was not found in the netdb
                //
                // as the remote cannot be contacted, remove the pending stream from `StreamManager`
                tracing::warn!(
                    target: LOG_TARGET,
                    session_id = ?self.session_id,
                    %destination_id,
                    ?stream_id,
                    "stream awaiting session but remote lease set not found",
                );
                self.stream_manager.remove_session(&destination_id);
            }
            None => tracing::debug!(
                target: LOG_TARGET,
                session_id = ?self.session_id,
                %destination_id,
                ?error,
                "lease set query failure but no stream is interested in the lease set",
            ),
        }

        if let Some(name) = self.pending_host_lookups.remove(&destination_id) {
            tracing::debug!(
                target: LOG_TARGET,
                session_id = ?self.session_id,
                %destination_id,
                ?name,
                ?error,
                "lease set query failed for pending host lookup",
            );

            if let Some(socket) = &mut self.socket {
                socket.send_message(
                    format!("NAMING REPLY RESULT=KEY_NOT_FOUND NAME={name}\n").as_bytes().to_vec(),
                );

                if let Some(waker) = self.waker.take() {
                    waker.wake_by_ref();
                }
            }
        }
    }

    /// Handle one or more inbound messages.
    fn on_inbound_message(&mut self, messages: Vec<Vec<u8>>) {
        messages
            .into_iter()
            .for_each(|message| match I2cpPayload::decompress::<R>(message) {
                Some(payload) => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        session_id = %self.session_id,
                        src_port = ?payload.src_port,
                        dst_port = ?payload.dst_port,
                        protocol = ?payload.protocol,
                        "handle protocol payload",
                    );

                    match payload.protocol {
                        Protocol::Streaming => {
                            if let Err(error) = self.stream_manager.on_packet(payload) {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    session_id = ?self.session_id,
                                    ?error,
                                    "failed to handle streaming protocol packet",
                                );
                            }
                        }
                        protocol =>
                            if let Err(error) = self.datagram_manager.on_datagram(payload) {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    session_id = ?self.session_id,
                                    ?protocol,
                                    ?error,
                                    "failed to handle datagram",
                                );
                            },
                    }
                }
                None => tracing::warn!(
                    target: LOG_TARGET,
                    session_id = ?self.session_id,
                    "failed to decompress i2cp payload",
                ),
            })
    }

    /// Handle `NAMING LOOKUP` query from the client.
    ///
    /// The query can either be for `ME`, meaning the [`Destination`] of [`SamSession`] is returned,
    /// a `.b32.i2p` which starts a lease set query for the destination. or a `.i2p` host name which
    /// is looked up from an address book if it exists.
    ///
    /// For `.b32.i2p`/`.i2p`, naming reply is deferred until the query is finished.
    fn on_naming_lookup(&mut self, name: String) {
        if name.as_str() == "ME" {
            tracing::debug!(
                target: LOG_TARGET,
                session_id = %self.session_id,
                "naming lookup for self",
            );

            if let Some(socket) = &mut self.socket {
                socket.send_message(
                    format!(
                        "NAMING REPLY RESULT=OK NAME=ME VALUE={}\n",
                        base64_encode(self.dest.serialized())
                    )
                    .as_bytes()
                    .to_vec(),
                );
            }

            return;
        }

        // if the host name ends in `.b32.i2p`, validate the hostname and check if [`Destination`]
        // already holds the host's lease set and if not, start a query
        //
        // once the query finishes, the naming reply is sent to client
        if let Some(end) = name.find(".b32.i2p") {
            tracing::debug!(
                target: LOG_TARGET,
                session_id = %self.session_id,
                "naming lookup for .b32.i2p address",
            );

            let start = if name.starts_with("http://") {
                7usize
            } else if name.starts_with("https://") {
                8usize
            } else {
                0usize
            };

            let message = match base32_decode(&name[start..end]) {
                None => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        session_id = %self.session_id,
                        ?name,
                        "invalid .b32.i2p address",
                    );

                    Some(
                        format!("NAMING REPLY RESULT=INVALID_KEY NAME={name}\n")
                            .as_bytes()
                            .to_vec(),
                    )
                }
                Some(destination) => {
                    let destination_id = DestinationId::from(destination);

                    match self.destination.query_lease_set(&destination_id) {
                        LeaseSetStatus::Found => {
                            tracing::trace!(
                                target: LOG_TARGET,
                                session_id = %self.session_id,
                                %destination_id,
                                ?name,
                                "lease set found for host",
                            );

                            Some(
                                format!(
                                    "NAMING REPLY RESULT=OK NAME={name} VALUE={}\n",
                                    base64_encode(
                                        self.destination
                                            .lease_set(&destination_id)
                                            .header
                                            .destination
                                            .serialized()
                                    )
                                )
                                .as_bytes()
                                .to_vec(),
                            )
                        }
                        status => {
                            tracing::trace!(
                                target: LOG_TARGET,
                                session_id = %self.session_id,
                                %destination_id,
                                ?name,
                                ?status,
                                "lease set not found for host, query started",
                            );
                            self.pending_host_lookups.insert(destination_id, name);

                            None
                        }
                    }
                }
            };

            if let (Some(socket), Some(message)) = (&mut self.socket, message) {
                socket.send_message(message);
            }

            return;
        }

        let message = match name.find(".i2p") {
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    session_id = %self.session_id,
                    ?name,
                    "invalid host name",
                );

                Some(format!("NAMING REPLY RESULT=INVALID_KEY NAME={name}\n").as_bytes().to_vec())
            }
            Some(_) => match &self.address_book {
                None => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        session_id = %self.session_id,
                        ?name,
                        "address book doesn't exist",
                    );

                    Some(
                        format!("NAMING REPLY RESULT=KEY_NOT_FOUND NAME={name}\n")
                            .as_bytes()
                            .to_vec(),
                    )
                }
                Some(address_book) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?name,
                        "lookup name from address book",
                    );

                    let future = address_book.resolve(name.clone());
                    self.lookup_futures.push(async move { (name, future.await) });

                    None
                }
            },
        };

        if let (Some(socket), Some(message)) = (&mut self.socket, message) {
            socket.send_message(message);
        }
    }
}

impl<R: Runtime> Future for SamSession<R> {
    type Output = Arc<str>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            let command = match &mut self.socket {
                None => break,
                Some(socket) => match socket.poll_next_unpin(cx) {
                    Poll::Pending => break,
                    Poll::Ready(None) => {
                        tracing::info!(
                            target: LOG_TARGET,
                            session_id = %self.session_id,
                            "session socket closed, destroy session",
                        );

                        self.stream_manager.shutdown();
                        self.socket = None;
                        break;
                    }
                    Poll::Ready(Some(command)) => command,
                },
            };

            match command {
                SamCommand::NamingLookup { name } => self.on_naming_lookup(name),
                command => tracing::warn!(
                    target: LOG_TARGET,
                    %command,
                    "ignoring command for active session",
                ),
            }
        }

        loop {
            match self.receiver.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(Arc::clone(&self.session_id)),
                Poll::Ready(Some(SamSessionCommand::Connect {
                    socket,
                    destination_id,
                    options,
                })) => self.on_stream_connect(socket, destination_id, options),
                Poll::Ready(Some(SamSessionCommand::Accept { socket, options })) =>
                    self.on_stream_accept(socket, options),
                Poll::Ready(Some(SamSessionCommand::Forward {
                    socket,
                    port,
                    options,
                })) => self.on_stream_forward(socket, port, options),
                Poll::Ready(Some(SamSessionCommand::SendDatagram {
                    destination,
                    datagram,
                })) => self.on_send_datagram(destination, datagram),
                Poll::Ready(Some(SamSessionCommand::Dummy)) => unreachable!(),
            }
        }

        loop {
            match self.stream_manager.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(Arc::clone(&self.session_id)),
                Poll::Ready(Some(StreamManagerEvent::SendPacket {
                    dst_port,
                    destination_id,
                    packet,
                    src_port,
                })) => {
                    let Some(message) = I2cpPayloadBuilder::<R>::new(&packet)
                        .with_protocol(Protocol::Streaming)
                        .with_source_port(src_port)
                        .with_destination_port(dst_port)
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
                        debug_assert!(false);
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
                Poll::Ready(Some(StreamManagerEvent::StreamClosed { destination_id })) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        session_id = ?self.session_id,
                        ?destination_id,
                        "stream closed",
                    );
                }
                Poll::Ready(Some(StreamManagerEvent::ShutDown)) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        session_id = ?self.session_id,
                        "stream manager shut down, shutting down tunnel pool",
                    );
                    self.destination.shutdown();
                }
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
                                expires: Duration::from_secs(10 * 60).as_secs() as u32,
                                offline_signature: None,
                                published: R::time_since_epoch().as_secs() as u32,
                            },
                            public_keys: vec![self.encryption_key.public()],
                            leases,
                        }
                        .serialize(&self.signing_key),
                    );
                    let destination_id = Bytes::from(self.dest.id().to_vec());

                    self.destination.publish_lease_set(destination_id, lease_set);
                }
                Poll::Ready(Some(DestinationEvent::SessionTerminated { destination_id })) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        session_id = ?self.session_id,
                        destination_id = %destination_id,
                        "session termianted with remote",
                    );
                    self.stream_manager.remove_session(&destination_id);
                }
            }
        }

        loop {
            match self.lookup_futures.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(Arc::clone(&self.session_id)),
                Poll::Ready(Some((name, result))) => {
                    let message = match result {
                        Some(destination) => {
                            tracing::trace!(
                                target: LOG_TARGET,
                                session_id = ?self.session_id,
                                %name,
                                "naming lookup succeeded",
                            );

                            format!("NAMING REPLY RESULT=OK NAME={name} VALUE={destination}\n")
                                .as_bytes()
                                .to_vec()
                        }
                        None => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                session_id = ?self.session_id,
                                %name,
                                "naming lookup failed",
                            );

                            format!("NAMING REPLY RESULT=KEY_NOT_FOUND NAME={name}\n")
                                .as_bytes()
                                .to_vec()
                        }
                    };

                    if let Some(socket) = &mut self.socket {
                        socket.send_message(message);

                        if let Some(waker) = self.waker.take() {
                            waker.wake_by_ref();
                        }
                    }
                }
            }
        }

        self.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}
