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
    crypto::{base64_encode, SigningPrivateKey},
    error::StreamingError,
    primitives::{Destination, DestinationId},
    runtime::{Instant, JoinSet, Runtime},
    sam::{
        protocol::streaming::{
            config::StreamConfig,
            listener::{SocketKind, StreamListener, StreamListenerEvent},
            packet::{Packet, PacketBuilder},
            stream::{
                active::{Stream, StreamContext, StreamKind},
                pending::{PendingStream, PendingStreamResult},
            },
        },
        socket::SamSocket,
    },
};

use bytes::{BufMut, BytesMut};
use futures::{future::BoxFuture, FutureExt, StreamExt};
use hashbrown::{HashMap, HashSet};
use rand_core::RngCore;
use thingbuf::mpsc::{channel, Receiver, Sender};

use alloc::{boxed::Box, collections::VecDeque, format, vec::Vec};
use core::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

mod config;
mod listener;
mod packet;
mod stream;

pub use listener::ListenerKind;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::streaming";

/// [`StreamManager`]'s message channel size.
///
/// Size of the channel used by all virtual streams to send messages to the network.
const STREAM_MANAGER_CHANNEL_SIZE: usize = 4096;

/// [`Stream`]'s message channel size.
///
/// Size of the channel used to send messages received from the network to a virtual stream.
const STREAM_CHANNEL_SIZE: usize = 512;

/// How long are streams kept in the pending state before they are pruned and rejected.
const PENDING_STREAM_PRUNE_THRESHOLD: Duration = Duration::from_secs(30);

/// How long should a pending outbound stream wait before sending another `SYN`.
const SYN_RETRY_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum `SYN` retries before the remote destination is considered unreachable.
const MAX_SYN_RETRIES: usize = 3usize;

/// Signature length.
const SIGNATURE_LEN: usize = 64usize;

/// Direction of stream.
pub enum Direction {
    /// Inbound stream.
    Inbound,

    /// Outbound stream.
    Outbound,
}

/// Events emitted by [`StreamManager`].
pub enum StreamManagerEvent {
    /// Stream opened.
    StreamOpened {
        /// ID of remote destination.
        destination_id: DestinationId,

        /// Direction of the stream.
        direction: Direction,
    },

    /// Stream closed.
    StreamClosed {
        /// ID of remote destination.
        destination_id: DestinationId,
    },

    /// Outbound stream rejected.
    StreamRejected {
        /// ID of remote destination.
        destination_id: DestinationId,
    },

    /// Send packet.
    SendPacket {
        /// ID of remote destination.
        destination_id: DestinationId,

        /// Packet.
        packet: Vec<u8>,
    },
}

/// Pending outbound stream.
struct PendingOutboundStream<R: Runtime> {
    /// ID of the remote destination.
    destination_id: DestinationId,

    /// Has the stream configured to be silent.
    silent: bool,

    /// SAMv3 client socket that was used to send `STREAM CONNECT` command.
    socket: SamSocket<R>,

    /// Serialised `SYN` packet.
    packet: Vec<u8>,

    /// Number of `SYN`s sent thus far.
    num_sent: usize,
}

/// I2P virtual stream manager.
pub struct StreamManager<R: Runtime> {
    /// TX channels for sending [`Packet`]'s to active streams.
    ///
    /// Indexed with receive stream ID.
    active: HashMap<u32, (DestinationId, Sender<Vec<u8>>)>,

    /// Destination of the session the stream manager is bound to.
    destination: Destination,

    /// ID of the `Destination` the stream manager is bound to.
    destination_id: DestinationId,

    /// Destination ID -> stream ID mappings.
    destination_streams: HashMap<DestinationId, HashSet<u32>>,

    /// Stream listener.
    listener: StreamListener<R>,

    /// RX channel for receiving [`Packet`]s from active streams.
    outbound_rx: Receiver<(DestinationId, Vec<u8>)>,

    /// Timers for outbound streams.
    outbound_timers: R::JoinSet<u32>,

    /// TX channel given to active streams they use for sending messages to the network.
    outbound_tx: Sender<(DestinationId, Vec<u8>)>,

    /// Pending events.
    pending_events: VecDeque<StreamManagerEvent>,

    /// Pending inbound streams.
    ///
    /// Indexed by the remote-selected receive stream ID.
    pending_inbound: HashMap<u32, PendingStream<R>>,

    /// Pending outbound streams.
    pending_outbound: HashMap<u32, PendingOutboundStream<R>>,

    /// Timer for pruning stale pending streams.
    prune_timer: BoxFuture<'static, ()>,

    /// Signing key.
    signing_key: SigningPrivateKey,

    /// Active streams.
    streams: R::JoinSet<u32>,
}

impl<R: Runtime> StreamManager<R> {
    /// Create new [`StreamManager`].
    pub fn new(destination: Destination, signing_key: SigningPrivateKey) -> Self {
        let (outbound_tx, outbound_rx) = channel(STREAM_MANAGER_CHANNEL_SIZE);
        let destination_id = destination.id();

        Self {
            active: HashMap::new(),
            destination,
            destination_id: destination_id.clone(),
            destination_streams: HashMap::new(),
            listener: StreamListener::new(destination_id),
            outbound_rx,
            outbound_timers: R::join_set(),
            outbound_tx,
            pending_events: VecDeque::new(),
            pending_inbound: HashMap::new(),
            pending_outbound: HashMap::new(),
            prune_timer: Box::pin(R::delay(PENDING_STREAM_PRUNE_THRESHOLD)),
            signing_key,
            streams: R::join_set(),
        }
    }

    /// Handle message with `SYN`.
    ///
    /// If this a response to an outbound stream sent by us, convert the pending stream to an active
    /// stream by allocating it a new channel and spawning it in a background task.
    ///
    /// If this a new inbound stream ensure that signature and destination are in the message and
    /// verify their validity. Additionally ensure that the NACK field contains local destination's
    /// ID. If validity checks pass, send the message to a listener if it exists. If there are no
    /// active listeners, mark the stream as pending and start a timer for waiting for a new
    /// listener to be registered. If no listener is registered within the time window, the stream
    /// is closed.
    fn on_synchronize(&mut self, packet: Vec<u8>) -> Result<(), StreamingError> {
        let Packet {
            send_stream_id,
            recv_stream_id,
            seq_nro,
            ack_through,
            nacks,
            resend_delay,
            flags,
            payload,
        } = Packet::parse(&packet).ok_or(StreamingError::Malformed)?;

        // if this is a syn-ack for an outbound stream, initialize state
        // for a new stream future and spawn it in the background
        if let Some(PendingOutboundStream {
            destination_id,
            silent,
            socket,
            ..
        }) = self.pending_outbound.remove(&send_stream_id)
        {
            tracing::trace!(
                target: LOG_TARGET,
                local = %self.destination_id,
                ?recv_stream_id,
                ?send_stream_id,
                "outbound stream accepted",
            );

            self.spawn_stream(
                SocketKind::Accept {
                    socket: socket.into_inner(),
                    silent,
                },
                recv_stream_id,
                destination_id.clone(),
                StreamKind::Outbound { send_stream_id },
            );

            return Ok(());
        }

        let signature = flags.signature().ok_or(StreamingError::SignatureMissing)?;
        let destination =
            flags.from_included().as_ref().ok_or(StreamingError::DestinationMissing)?;

        // verify that the nacks field contains local destination id for replay protection
        if nacks.len() == 8 {
            let destination_id = nacks
                .into_iter()
                .fold(BytesMut::with_capacity(32), |mut acc, x| {
                    acc.put_slice(&x.to_be_bytes());
                    acc
                })
                .freeze()
                .to_vec();

            if destination_id != self.destination_id.to_vec() {
                return Err(StreamingError::ReplayProtectionCheckFailed);
            }
        }

        // verify signature
        {
            match destination.verifying_key() {
                None => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        "verifying key missing from destination",
                    );
                    return Err(StreamingError::VerifyingKeyMissing);
                }
                Some(verifying_key) => {
                    // signature field is the last field of options, meaning it starts at
                    // `original.len() - payload.len() - SIGNATURE_LEN`
                    //
                    // in order to verify the signature, the calculated signature must be filled
                    // with zeros
                    let mut original = packet.to_vec();
                    let signature_start = original.len() - payload.len() - SIGNATURE_LEN;
                    original[signature_start..signature_start + SIGNATURE_LEN]
                        .copy_from_slice(&[0u8; SIGNATURE_LEN]);

                    verifying_key.verify_new(&original, signature).map_err(|error| {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?error,
                            "failed to verify packet signature"
                        );

                        StreamingError::InvalidSignature
                    })?;
                }
            }
        }

        tracing::info!(
            target: LOG_TARGET,
            local = %self.destination_id,
            payload_len = ?payload.len(),
            "inbound stream accepted",
        );

        // attempt to acquire a socket from `StreamListener`
        //
        // if no listener exists, the stream is marked as pending
        match self.listener.pop_socket() {
            Some(socket) => self.spawn_stream(
                socket,
                recv_stream_id,
                destination.id(),
                StreamKind::Inbound {
                    payload: payload.to_vec(),
                },
            ),
            None => {
                tracing::info!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    ?recv_stream_id,
                    "inbound stream but no available listeners",
                );

                // create new pending stream and send syn-ack for it
                let destination_id = destination.id();

                let (pending, packet) =
                    PendingStream::new(destination_id.clone(), recv_stream_id, payload.to_vec());
                let _ = self.outbound_tx.try_send((destination_id.clone(), packet));

                self.pending_inbound.insert(recv_stream_id, pending);
                self.destination_streams
                    .entry(destination_id.clone())
                    .or_default()
                    .insert(recv_stream_id);
            }
        }

        Ok(())
    }

    /// Spawn new [`Stream`] in the background.
    ///
    /// This function can spawn streams of two different kinds:
    ///  - streams where no packet exchange has happened yet (fresh streams)
    ///  - streams where packet exchange has happened (pending streams)
    ///
    /// If the stream is fresh,
    fn spawn_stream(
        &mut self,
        socket: SocketKind<R>,
        recv_stream_id: u32,
        destination_id: DestinationId,
        stream_kind: StreamKind,
    ) {
        // create context for the stream
        //
        // since this is an inbound stream, the stream will be indexed in `active` by the
        // remote-chosen receive stream id and the local stream will generate itself a random id
        // when it starts and uses that for sending
        let (tx, rx) = channel(STREAM_CHANNEL_SIZE);
        let context = StreamContext {
            cmd_rx: rx,
            event_tx: self.outbound_tx.clone(),
            local: self.destination_id.clone(),
            recv_stream_id,
            remote: destination_id.clone(),
        };

        // if the socket wasn't configured to be silent, send the remote's destination
        // to client before the socket is convered into a regural tcp stream
        let initial_message = match &socket {
            SocketKind::Accept { silent, .. } | SocketKind::Forwarded { silent, .. } if !silent =>
                Some(format!("{}\n", base64_encode(context.remote.to_vec())).into_bytes()),
            SocketKind::Connect { silent, .. } if !silent =>
                Some(b"STREAM STATUS RESULT=OK".to_vec()),
            _ => None,
        };

        // store the tx channel of the stream in `StreamManager`'s context
        //
        // `StreamManager` sends all inbound messages with `recv_stream_id` to this stream and all
        // outbound messages from the stream to remote peer are send through `event_tx`
        self.active.insert(recv_stream_id, (destination_id.clone(), tx));
        self.destination_streams
            .entry(destination_id.clone())
            .or_default()
            .insert(recv_stream_id);

        // if socket kind is `Connect` this is an outbound stream
        //
        // accept/forward indicates an inbound stream
        match &socket {
            SocketKind::Connect { .. } =>
                self.pending_events.push_back(StreamManagerEvent::StreamOpened {
                    destination_id,
                    direction: Direction::Outbound,
                }),
            SocketKind::Accept { .. } | SocketKind::Forwarded { .. } =>
                self.pending_events.push_back(StreamManagerEvent::StreamOpened {
                    destination_id,
                    direction: Direction::Inbound,
                }),
        }

        // start new future for the stream in the background
        //
        // if `SILENT` was set to false, the first message `Stream` sends to the connected
        // client is the destination id of the remote peer after which it transfers to send
        // anything that was received from the remote peer via `StreamManager`
        //
        // if the listener was created with `STREAM FORWARD`, a new tcp connection must be opened to
        // the forwarded listener before the stream can be started and if the listener is not
        // active, the stream is closed immediately
        match socket {
            SocketKind::Accept { socket, .. } | SocketKind::Connect { socket, .. } =>
                self.streams.push(Stream::<R>::new(
                    socket,
                    initial_message,
                    context,
                    StreamConfig::default(),
                    stream_kind,
                )),
            SocketKind::Forwarded { future, .. } => self.streams.push(async move {
                let Some(stream) = future.await else {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "failed to open tcp stream to forwarded listener",
                    );
                    return context.recv_stream_id;
                };

                Stream::<R>::new(
                    stream,
                    initial_message,
                    context,
                    StreamConfig::default(),
                    stream_kind,
                )
                .await
            }),
        }
    }

    /// Handle ready listener.
    ///
    /// An inbound stream may be received while there are no listeners or the listeners are busy
    /// sending status messages to the connected client. In those cases the inbound streams are put
    /// in a pending state where they remain waiting for a listener to be registered for a period of
    /// time before they're destroyed as session owner is apparently not interested in accepting
    /// inbound streams.
    ///
    /// When a listener is registered and it is ready to serve an inbound stream, [`StreamListener`]
    /// emits an event informing the [`StreamManager`] of it and the stream manager must check if
    /// there are any pending streams and if so, start event loops for the streams. If there are no
    /// pending streams, the event is ignored.
    fn on_listener_ready(&mut self) {
        tracing::debug!(
            target: LOG_TARGET,
            local = %self.destination_id,
            num_pending = ?self.pending_inbound.len(),
            "listener ready",
        );

        // loop through all pending streams until either:
        //  a) there are no more pending streams
        //  b) there are no more available listeners
        loop {
            let Some(stream_id) = self.pending_inbound.keys().next().copied() else {
                return;
            };

            let Some(socket) = self.listener.pop_socket() else {
                return;
            };

            // stream must exist since it was checked earlier that it's in the map
            let PendingStream {
                destination_id,
                send_stream_id,
                packets,
                seq_nro,
                ..
            } = self.pending_inbound.remove(&stream_id).expect("to exist");

            // spawn new task for the stream in the background
            self.spawn_stream(
                socket,
                stream_id,
                destination_id,
                StreamKind::InboundPending {
                    send_stream_id,
                    seq_nro,
                    packets,
                },
            );
        }
    }

    /// Register listener into [`StreamManager`].
    ///
    /// This function calls [`StreamListener::register_listener()`] which either rejects `kind`
    /// because it's in conflict with an active listener kind, puts the listener on hold because
    /// there are no active streams or starts an active stream for a pending inbound stream.
    ///
    /// This function calls [`StreamListener::register_listener()`] which either rejects `kind`
    /// because it's in conflict with an active listener kind, accepts the listener and possibly
    /// notifies the client of if it the socket wasn't configured to be silent. Client notification
    /// happens in the background, making the listener temporarily inactive. Once the client has
    /// been notified of listener acceptance, [`StreamManager`] is notified via
    /// [`StreamListener::poll_next()`] that there is an active listener.
    ///
    /// If the listener was configured to be silent and it was of type [`ListenerKind::Ephemeral`],
    /// the listener is immediately available for use. In these cases,
    /// [`StreamListener::register_listener()`] returns `Ok(true)` to indicate that
    /// [`StreamManager`] can accept a pending inbound stream using the registered listener, if a
    /// pending stream exists.
    pub fn register_listener(&mut self, kind: ListenerKind<R>) -> Result<(), StreamingError> {
        if self.listener.register_listener(kind)? {
            self.on_listener_ready();
        }

        Ok(())
    }

    /// Handle `payload` received from `src_port` to `dst_port`.
    pub fn on_packet(
        &mut self,
        src_port: u16,
        dst_port: u16,
        payload: Vec<u8>,
    ) -> Result<(), StreamingError> {
        let packet = Packet::peek(&payload).ok_or(StreamingError::Malformed)?;

        tracing::trace!(
            target: LOG_TARGET,
            local = %self.destination_id,
            send_stream_id = ?packet.send_stream_id(),
            recv_stream_id = ?packet.recv_stream_id(),
            seq_nro = ?packet.seq_nro(),
            "inbound message",
        );

        // forward received packet to an active handler if it exists
        if let Some((_, tx)) = self.active.get(&packet.recv_stream_id()) {
            if let Err(error) = tx.try_send(payload) {
                tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    send_stream_id = ?packet.send_stream_id(),
                    recv_stream_id = ?packet.recv_stream_id(),
                    seq_nro = ?packet.seq_nro(),
                    ?error,
                    "failed to send packet to stream, dropping",
                );
            }

            return Ok(());
        }

        if let Some(stream) = self.pending_inbound.get_mut(&packet.recv_stream_id()) {
            match stream.on_packet(payload) {
                PendingStreamResult::DoNothing => {}
                PendingStreamResult::Send { packet } => {
                    let _ = self.outbound_tx.try_send((stream.destination_id.clone(), packet));
                }
                PendingStreamResult::SendAndDestroy { packet: pkt } => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        recv_stream_id = ?packet.recv_stream_id(),
                        "send packet and destroy pending stream",
                    );
                    let _ = self.outbound_tx.try_send((stream.destination_id.clone(), pkt));

                    if let Some(PendingStream { destination_id, .. }) =
                        self.pending_inbound.remove(&packet.recv_stream_id())
                    {
                        self.destination_streams.get_mut(&destination_id).map(|streams| {
                            streams.remove(&packet.recv_stream_id());
                        });
                    }
                }
                PendingStreamResult::Destroy => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        recv_stream_id = ?packet.recv_stream_id(),
                        "destroy pending stream",
                    );

                    if let Some(PendingStream { destination_id, .. }) =
                        self.pending_inbound.remove(&packet.recv_stream_id())
                    {
                        self.destination_streams.get_mut(&destination_id).map(|streams| {
                            streams.remove(&packet.recv_stream_id());
                        });
                    }
                }
            }

            return Ok(());
        }

        // handle new stream
        //
        // both deserialized packet and the original payload are returned
        // so the included signature can be verified
        if packet.synchronize() {
            return self.on_synchronize(payload);
        }

        Ok(())
    }

    /// Create outbound stream to remote peer identfied by `destination_id`.
    ///
    /// Construct initial `SYN` packet and create pending outbound stream.
    ///
    /// Returns the initial packet and the selected receive stream ID which the caller
    /// can use to remove the pending stream if the session is rejected at a lower layer.
    pub fn create_stream(
        &mut self,
        destination_id: DestinationId,
        socket: SamSocket<R>,
        silent: bool,
    ) -> (BytesMut, u32) {
        // generate free receive stream id
        let recv_stream_id = {
            let mut rng = R::rng();

            loop {
                let stream_id = rng.next_u32();

                if !self.active.contains_key(&stream_id)
                    && !self.pending_outbound.contains_key(&stream_id)
                {
                    break stream_id;
                }
            }
        };

        let packet = PacketBuilder::new(recv_stream_id)
            .with_send_stream_id(0u32)
            .with_replay_protection(&destination_id)
            .with_synchronize()
            .with_signature()
            .with_from_included(self.destination.clone())
            .build_and_sign(&self.signing_key);

        tracing::debug!(
            target: LOG_TARGET,
            local = %self.destination_id,
            remote = %destination_id,
            ?recv_stream_id,
            "open stream",
        );

        // create pending stream and start timer for retrying `SYN` if the remote doesn't respond to
        // the first packet
        //
        // `SYN` is retried 3 times before the remote destination is considered unreachable
        self.pending_outbound.insert(
            recv_stream_id,
            PendingOutboundStream {
                destination_id: destination_id.clone(),
                silent,
                socket,
                num_sent: 1usize,
                packet: packet.clone().to_vec(),
            },
        );
        self.destination_streams
            .entry(destination_id)
            .or_default()
            .insert(recv_stream_id);
        self.outbound_timers.push(async move {
            R::delay(SYN_RETRY_TIMEOUT).await;
            recv_stream_id
        });

        (packet, recv_stream_id)
    }

    /// Remove pending outbound stream associated with `recv_stream_id`.
    pub fn remove_pending_stream(&mut self, recv_stream_id: u32) {
        self.pending_outbound.remove(&recv_stream_id);
    }

    /// Remove all streaming context associated with `destination_id`.
    pub fn remove_session(&mut self, destination_id: &DestinationId) {
        let Some(streams) = self.destination_streams.remove(destination_id) else {
            return;
        };

        tracing::debug!(
            target: LOG_TARGET,
            local = %self.destination_id,
            remote = %destination_id,
            num_streams = ?streams.len(),
            "remove session"
        );

        streams.into_iter().for_each(|stream_id| {
            self.active.remove(&stream_id);
            self.pending_inbound.remove(&stream_id);
            self.pending_outbound.remove(&stream_id);
        });
    }
}

impl<R: Runtime> futures::Stream for StreamManager<R> {
    type Item = StreamManagerEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(Some(event));
        }

        loop {
            match self.outbound_rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some((destination_id, packet))) =>
                    return Poll::Ready(Some(StreamManagerEvent::SendPacket {
                        destination_id,
                        packet,
                    })),
            }
        }

        loop {
            match self.streams.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(stream_id)) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        ?stream_id,
                        "stream closed"
                    );

                    // active stream may not exist if it was removed by calling
                    // `StreamManager::remove_session()`
                    let Some((destination_id, _)) = self.active.remove(&stream_id) else {
                        tracing::debug!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            ?stream_id,
                            "active stream doesn't exist",
                        );
                        continue;
                    };

                    return Poll::Ready(Some(StreamManagerEvent::StreamClosed { destination_id }));
                }
            }
        }

        loop {
            match self.listener.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(StreamListenerEvent::ListenerReady)) => self.on_listener_ready(),
            }
        }

        loop {
            match self.outbound_timers.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(stream_id)) => {
                    let Some(PendingOutboundStream {
                        destination_id,
                        packet,
                        ref mut num_sent,
                        ..
                    }) = self.pending_outbound.get_mut(&stream_id)
                    else {
                        continue;
                    };

                    // pending stream still exists, check if the packet should be resent
                    // or if the stream should be destroyed
                    if *num_sent < MAX_SYN_RETRIES {
                        let destination_id = destination_id.clone();
                        let packet = packet.clone();
                        *num_sent += 1;

                        tracing::debug!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            ?stream_id,
                            "resend `SYN`",
                        );

                        // create new timer for the new syn packet
                        //
                        // the future is guaranteed to be polled as we return from this branch
                        self.outbound_timers.push(async move {
                            R::delay(SYN_RETRY_TIMEOUT).await;
                            stream_id
                        });

                        return Poll::Ready(Some(StreamManagerEvent::SendPacket {
                            destination_id,
                            packet,
                        }));
                    } else {
                        // stream must exist since it was just fetched from `pending_outbound`
                        let PendingOutboundStream {
                            destination_id,
                            silent,
                            mut socket,
                            packet,
                            num_sent,
                        } = self.pending_outbound.remove(&stream_id).expect("to exist");

                        tracing::debug!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            ?stream_id,
                            "remote didn't reply after 3 tries, closing stream",
                        );

                        // send rejection to client and return event to `SamSession`
                        // indicating that the connection failed
                        R::spawn(async move {
                            socket
                                .send_message_blocking(
                                    b"STREAM STATUS RESULT=CANT_REACH_PEER\n".to_vec(),
                                )
                                .await;
                        });

                        return Poll::Ready(Some(StreamManagerEvent::StreamRejected {
                            destination_id,
                        }));
                    }
                }
            }
        }

        if let Poll::Ready(()) = self.prune_timer.poll_unpin(cx) {
            self.pending_inbound
                .iter()
                .filter_map(|(stream_id, pending_stream)| {
                    (pending_stream.established.elapsed() > PENDING_STREAM_PRUNE_THRESHOLD)
                        .then_some(*stream_id)
                })
                .collect::<HashSet<_>>()
                .into_iter()
                .for_each(|stream_id| {
                    tracing::debug!(
                        local = %self.destination_id,
                        ?stream_id,
                        "pruning stale pending stream",
                    );
                    self.pending_inbound.remove(&stream_id);
                });

            // create new timer and register it into the executor
            {
                self.prune_timer = Box::pin(R::delay(PENDING_STREAM_PRUNE_THRESHOLD));
                let _ = self.prune_timer.poll_unpin(cx);
            }
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        primitives::Destination,
        runtime::{
            mock::{MockRuntime, MockTcpStream},
            TcpStream,
        },
        sam::{protocol::streaming::packet::PacketBuilder, socket::SamSocket},
    };
    use rand::RngCore;
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, BufReader},
        net::TcpListener,
    };

    struct SocketFactory {
        listener: TcpListener,
    }

    impl SocketFactory {
        pub async fn new() -> Self {
            Self {
                listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            }
        }

        pub async fn socket(&self) -> (SamSocket<MockRuntime>, tokio::net::TcpStream) {
            let address = self.listener.local_addr().unwrap();
            let (stream1, stream2) =
                tokio::join!(self.listener.accept(), MockTcpStream::connect(address));
            let (mut stream, _) = stream1.unwrap();

            (SamSocket::new(stream2.unwrap()), stream)
        }
    }

    #[tokio::test]
    async fn register_ephemeral_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let (mut stream, _) = stream1.unwrap();
        let mut socket = SamSocket::<MockRuntime>::new(stream2.unwrap());

        let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
        let destination = Destination::new(signing_key.public());
        let mut manager = StreamManager::<MockRuntime>::new(destination, signing_key);

        assert!(manager
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: false
            })
            .is_ok());
    }

    #[tokio::test]
    async fn stale_pending_streams_are_pruned() {
        let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
        let destination = Destination::new(signing_key.public());
        let destination_id = destination.id();
        let mut manager = StreamManager::<MockRuntime>::new(destination, signing_key);

        let mut packets = (0..3)
            .into_iter()
            .map(|stream_id| {
                let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
                let destination = Destination::new(signing_key.public());
                let packet = PacketBuilder::new(stream_id as u32)
                    .with_synchronize()
                    .with_send_stream_id(0u32)
                    .with_replay_protection(&destination_id)
                    .with_from_included(destination)
                    .with_signature()
                    .build_and_sign(&signing_key);

                packet.to_vec()
            })
            .collect::<VecDeque<_>>();

        // register syn packet and verify the stream is pending
        assert!(manager.on_packet(0u16, 0u16, packets.pop_front().unwrap()).is_ok());
        assert_eq!(manager.pending_inbound.len(), 1);

        // reset timer
        manager.prune_timer = Box::pin(tokio::time::sleep(PENDING_STREAM_PRUNE_THRESHOLD));

        // wait for a little while so all streams won't get pruned at the same time
        tokio::time::sleep(Duration::from_secs(20)).await;

        // register two other pending streams
        assert!(manager.on_packet(0u16, 0u16, packets.pop_front().unwrap()).is_ok());
        assert!(manager.on_packet(0u16, 0u16, packets.pop_front().unwrap()).is_ok());
        assert_eq!(manager.pending_inbound.len(), 3);

        // poll manager until the first stream is pruned
        //
        // verify that the other two are still left
        loop {
            futures::future::poll_fn(|cx| match manager.poll_next_unpin(cx) {
                Poll::Pending => Poll::Ready(()),
                Poll::Ready(_) => Poll::Ready(()),
            })
            .await;

            if manager.pending_inbound.len() != 3 {
                break;
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // verify that first pending stream is pruned and that the other two are still left
        assert!(!manager.pending_inbound.contains_key(&0));
        assert!(manager.pending_inbound.contains_key(&1));
        assert!(manager.pending_inbound.contains_key(&2));

        // reset timer
        manager.prune_timer = Box::pin(tokio::time::sleep(Duration::from_secs(20)));

        // poll until the last two streams are also pruned
        loop {
            futures::future::poll_fn(|cx| match manager.poll_next_unpin(cx) {
                Poll::Pending => Poll::Ready(()),
                Poll::Ready(_) => panic!("invalid event"),
            })
            .await;

            if manager.pending_inbound.is_empty() {
                break;
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    #[tokio::test]
    async fn pending_stream_initialized_with_silent_listener() {
        let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
        let destination = Destination::new(signing_key.public());
        let destination_id = destination.id();
        let mut manager = StreamManager::<MockRuntime>::new(destination, signing_key);

        // register new inbound stream and since there are no listener, the stream will be pending
        let signing_key = SigningPrivateKey::new(&[1u8; 32]).unwrap();
        let destination = Destination::new(signing_key.public());
        let remote_destination_id = destination.id();
        let packet = PacketBuilder::new(1337u32)
            .with_synchronize()
            .with_send_stream_id(0u32)
            .with_replay_protection(&destination_id)
            .with_from_included(destination)
            .with_signature()
            .build_and_sign(&signing_key)
            .to_vec();

        assert!(manager.on_packet(0u16, 0u16, packet).is_ok());
        assert_eq!(manager.pending_inbound.len(), 1);

        // register new silent listener which is ready immediately
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));
        let (mut stream, _) = stream1.unwrap();
        let mut socket = SamSocket::<MockRuntime>::new(stream2.unwrap());

        assert!(manager
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: true
            })
            .is_ok());
        assert!(manager.pending_inbound.is_empty());

        assert!(std::matches!(
            manager.next().await,
            Some(StreamManagerEvent::StreamOpened { .. })
        ));

        // poll manager until ack packet is received
        match tokio::time::timeout(Duration::from_secs(5), manager.next())
            .await
            .unwrap()
            .unwrap()
        {
            StreamManagerEvent::SendPacket {
                destination_id: remote,
                packet,
            } => {
                let Packet {
                    send_stream_id,
                    recv_stream_id,
                    flags,
                    ..
                } = Packet::parse(&packet).unwrap();

                assert_eq!(remote, remote_destination_id);
                assert_eq!(send_stream_id, 1337u32);
                assert_ne!(recv_stream_id, 0u32);
                assert!(flags.synchronize());
            }
            _ => panic!("invalid event"),
        }
    }

    #[tokio::test]
    async fn pending_stream_initialized_with_non_silent_listener() {
        let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
        let destination = Destination::new(signing_key.public());
        let destination_id = destination.id();
        let mut manager = StreamManager::<MockRuntime>::new(destination, signing_key);

        // register new inbound stream and since there are no listener, the stream will be pending
        let signing_key = SigningPrivateKey::new(&[1u8; 32]).unwrap();
        let destination = Destination::new(signing_key.public());
        let remote_destination_id = destination.id();
        let packet = PacketBuilder::new(1337u32)
            .with_synchronize()
            .with_send_stream_id(0u32)
            .with_replay_protection(&destination_id)
            .with_from_included(destination)
            .with_signature()
            .build_and_sign(&signing_key)
            .to_vec();

        assert!(manager.on_packet(0u16, 0u16, packet).is_ok());
        assert_eq!(manager.pending_inbound.len(), 1);

        // register new silent listener which is ready immediately
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));
        let (mut stream, _) = stream1.unwrap();
        let mut socket = SamSocket::<MockRuntime>::new(stream2.unwrap());

        assert!(manager
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: false
            })
            .is_ok());
        assert!(!manager.pending_inbound.is_empty());

        // poll manager until ack packet is received
        match tokio::time::timeout(Duration::from_secs(5), manager.next())
            .await
            .unwrap()
            .unwrap()
        {
            StreamManagerEvent::SendPacket {
                destination_id: remote,
                packet,
            } => {
                let Packet {
                    send_stream_id,
                    recv_stream_id,
                    flags,
                    ..
                } = Packet::parse(&packet).unwrap();

                assert_eq!(remote, remote_destination_id);
                assert_eq!(send_stream_id, 1337u32);
                assert_ne!(recv_stream_id, 0u32);
                assert!(flags.synchronize());
            }
            _ => panic!("invalid event"),
        }
    }

    #[tokio::test]
    async fn pending_stream_initialized_with_persistent_listener() {
        let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
        let destination = Destination::new(signing_key.public());
        let destination_id = destination.id();
        let mut manager = StreamManager::<MockRuntime>::new(destination, signing_key);

        // register new inbound stream and since there are no listener, the stream will be pending
        let signing_key = SigningPrivateKey::new(&[1u8; 32]).unwrap();
        let destination = Destination::new(signing_key.public());
        let remote_destination_id = destination.id();
        let packet = PacketBuilder::new(1337u32)
            .with_synchronize()
            .with_send_stream_id(0u32)
            .with_replay_protection(&destination_id)
            .with_from_included(destination)
            .with_signature()
            .build_and_sign(&signing_key)
            .to_vec();

        assert!(manager.on_packet(0u16, 0u16, packet).is_ok());
        assert_eq!(manager.pending_inbound.len(), 1);

        // register new silent listener which is ready immediately
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let port = address.port();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));
        let (mut stream, _) = stream1.unwrap();
        let mut socket = SamSocket::<MockRuntime>::new(stream2.unwrap());

        assert!(manager
            .register_listener(ListenerKind::Persistent {
                socket,
                port,
                silent: false
            })
            .is_ok());
        assert!(!manager.pending_inbound.is_empty());

        // poll manager until ack packet is received
        match tokio::time::timeout(Duration::from_secs(5), manager.next())
            .await
            .unwrap()
            .unwrap()
        {
            StreamManagerEvent::SendPacket {
                destination_id: remote,
                packet,
            } => {
                let Packet {
                    send_stream_id,
                    recv_stream_id,
                    flags,
                    ..
                } = Packet::parse(&packet).unwrap();

                assert_eq!(remote, remote_destination_id);
                assert_eq!(send_stream_id, 1337u32);
                assert_ne!(recv_stream_id, 0u32);
                assert!(flags.synchronize());
            }
            _ => panic!("invalid event"),
        }

        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response).await.unwrap();

        assert_eq!(response.as_str(), "STREAM STATUS RESULT=OK\n");
    }

    #[tokio::test]
    async fn pending_stream_with_buffered_data_initialized() {
        let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
        let destination = Destination::new(signing_key.public());
        let destination_id = destination.id();
        let mut manager = StreamManager::<MockRuntime>::new(destination, signing_key);

        // register new inbound stream and since there are no listener, the stream will be pending
        let signing_key = SigningPrivateKey::new(&[1u8; 32]).unwrap();
        let destination = Destination::new(signing_key.public());
        let remote_destination_id = destination.id();
        let packet = PacketBuilder::new(1337u32)
            .with_synchronize()
            .with_send_stream_id(0u32)
            .with_replay_protection(&destination_id)
            .with_from_included(destination)
            .with_signature()
            .build_and_sign(&signing_key)
            .to_vec();

        assert!(manager.on_packet(0u16, 0u16, packet).is_ok());
        assert_eq!(manager.pending_inbound.len(), 1);

        // poll manager until ack packet is received
        let recv_stream_id = match tokio::time::timeout(Duration::from_secs(5), manager.next())
            .await
            .unwrap()
            .unwrap()
        {
            StreamManagerEvent::SendPacket {
                destination_id: remote,
                packet,
            } => {
                let Packet {
                    send_stream_id,
                    recv_stream_id,
                    flags,
                    ..
                } = Packet::parse(&packet).unwrap();

                assert_eq!(remote, remote_destination_id);
                assert_eq!(send_stream_id, 1337u32);
                assert_ne!(recv_stream_id, 0u32);
                assert!(flags.synchronize());

                recv_stream_id
            }
            _ => panic!("invalid event"),
        };

        // send three data packets and verify that they're all ack'ed
        {
            let messages = vec![
                b"hello, world".to_vec(),
                b"testing 123".to_vec(),
                b"goodbye world".to_vec(),
            ];

            for (i, message) in messages.into_iter().enumerate() {
                let packet = PacketBuilder::new(1337u32)
                    .with_synchronize()
                    .with_send_stream_id(recv_stream_id)
                    .with_seq_nro(i as u32 + 1u32)
                    .with_payload(&message)
                    .build()
                    .to_vec();

                assert!(manager.on_packet(0u16, 0u16, packet).is_ok());

                // poll manager until ack packet is received
                match tokio::time::timeout(Duration::from_secs(5), manager.next())
                    .await
                    .unwrap()
                    .unwrap()
                {
                    StreamManagerEvent::SendPacket {
                        destination_id: remote,
                        packet,
                    } => {
                        let Packet {
                            send_stream_id,
                            recv_stream_id,
                            flags,
                            ack_through,
                            ..
                        } = Packet::parse(&packet).unwrap();

                        assert_eq!(remote, remote_destination_id);
                        assert_eq!(send_stream_id, 1337u32);
                        assert_ne!(recv_stream_id, 0u32);
                        assert_eq!(ack_through, i as u32 + 1u32);
                    }
                    _ => panic!("invalid event"),
                }
            }
        }

        // verify that the stream is still pending
        assert_eq!(manager.pending_inbound.len(), 1);

        // register new silent listener which is ready immediately
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));
        let (mut stream, _) = stream1.unwrap();
        let mut socket = SamSocket::<MockRuntime>::new(stream2.unwrap());

        assert!(manager
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: true
            })
            .is_ok());
        assert!(manager.pending_inbound.is_empty());

        // poll manager in the background in order to drive the stream future forward
        tokio::spawn(async move { while let Some(_) = manager.next().await {} });

        // verify that the buffered data is returned to client
        let mut buffer = vec![0u8; 36];
        stream.read_exact(&mut buffer).await.unwrap();

        assert_eq!(buffer, b"hello, worldtesting 123goodbye world");
    }

    #[tokio::test]
    async fn outbound_stream_accepted() {
        let socket_factory = SocketFactory::new().await;

        let mut manager1 = {
            let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
            let destination = Destination::new(signing_key.public());
            let destination_id = destination.id();
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        let mut manager2 = {
            let signing_key = SigningPrivateKey::new(&[1u8; 32]).unwrap();
            let destination = Destination::new(signing_key.public());
            let destination_id = destination.id();
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        // register listener for `manager1`
        let (socket, _) = socket_factory.socket().await;
        assert!(manager1
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: true
            })
            .is_ok());

        // create new oubound stream to `manager1`
        let (socket, mut client_stream) = socket_factory.socket().await;
        let (packet, stream_id) =
            manager2.create_stream(manager1.destination_id.clone(), socket, false);

        assert!(manager1.on_packet(0u16, 0u16, packet.to_vec()).is_ok());

        assert!(std::matches!(
            manager1.next().await,
            Some(StreamManagerEvent::StreamOpened { .. })
        ));

        let (destination_id, packet) =
            match tokio::time::timeout(Duration::from_secs(5), manager1.next())
                .await
                .unwrap()
                .unwrap()
            {
                StreamManagerEvent::SendPacket {
                    destination_id,
                    packet,
                } => (destination_id, packet),
                _ => panic!("invalid event"),
            };

        assert_eq!(destination_id, manager2.destination_id);
        assert!(manager2.on_packet(0u16, 0u16, packet).is_ok());
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = manager1.next() => {}
                    _ = manager2.next() => {}
                }
            }
        });

        let mut reader = tokio::io::BufReader::new(client_stream);
        let mut response = String::new();
        reader.read_line(&mut response).await.unwrap();

        assert_eq!(response.as_str(), "STREAM STATUS RESULT=OK\n");
    }

    #[tokio::test]
    async fn outbound_stream_rejected() {
        let socket_factory = SocketFactory::new().await;

        let remote = DestinationId::random();

        let mut manager2 = {
            let signing_key = SigningPrivateKey::new(&[1u8; 32]).unwrap();
            let destination = Destination::new(signing_key.public());
            let destination_id = destination.id();
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        // create new oubound stream to `manager1`
        let (socket, mut client_stream) = socket_factory.socket().await;
        let _ = manager2.create_stream(remote.clone(), socket, false);

        // verify the syn packet is sent twice more
        for _ in 0..2 {
            match tokio::time::timeout(Duration::from_secs(15), manager2.next())
                .await
                .expect("no timeout")
                .expect("to succeed")
            {
                StreamManagerEvent::SendPacket {
                    destination_id,
                    packet,
                } if destination_id == remote => {
                    assert!(Packet::parse(&packet).unwrap().flags.synchronize());
                }
                _ => panic!("invalid event"),
            }
        }

        // verify that stream rejection is emitted
        match tokio::time::timeout(Duration::from_secs(15), manager2.next())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            StreamManagerEvent::StreamRejected { destination_id } if destination_id == remote => {}
            _ => panic!("invalid event"),
        }

        let mut reader = BufReader::new(client_stream);
        let mut response = String::new();
        tokio::time::timeout(Duration::from_secs(15), reader.read_line(&mut response))
            .await
            .expect("no timeout")
            .expect("to succeed");

        assert_eq!(response, "STREAM STATUS RESULT=CANT_REACH_PEER\n");
    }

    #[tokio::test]
    async fn data_in_syn_packet_silent_ephemeral() {
        let socket_factory = SocketFactory::new().await;

        let mut manager = {
            let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
            let destination = Destination::new(signing_key.public());
            let destination_id = destination.id();
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        // register listener for `manager1`
        let (socket, mut client_socket) = socket_factory.socket().await;
        assert!(manager
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: true
            })
            .is_ok());

        let signing_key = SigningPrivateKey::new(&[1u8; 32]).unwrap();
        let destination = Destination::new(signing_key.public());
        let packet = PacketBuilder::new(1337u32)
            .with_synchronize()
            .with_send_stream_id(0u32)
            .with_replay_protection(&manager.destination.id())
            .with_from_included(destination)
            .with_signature()
            .with_payload(b"hello, world")
            .build_and_sign(&signing_key)
            .to_vec();

        // handle syn packet and spawn manager in the background
        assert!(manager.on_packet(0u16, 0u16, packet).is_ok());

        tokio::spawn(async move { while let Some(_) = manager.next().await {} });

        // read the payload that was contained within the syn packet
        let mut buffer = [0u8; 12];
        tokio::time::timeout(
            Duration::from_secs(5),
            client_socket.read_exact(&mut buffer),
        )
        .await
        .expect("no timeout")
        .expect("to succeed");
        assert_eq!(&buffer, b"hello, world");
    }

    #[tokio::test]
    async fn data_in_syn_packet_non_silent_ephemeral() {
        let socket_factory = SocketFactory::new().await;

        let mut manager = {
            let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
            let destination = Destination::new(signing_key.public());
            let destination_id = destination.id();
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        // register listener for `manager1`
        let (socket, mut client_socket) = socket_factory.socket().await;
        assert!(manager
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: false
            })
            .is_ok());

        let signing_key = SigningPrivateKey::new(&[1u8; 32]).unwrap();
        let destination = Destination::new(signing_key.public());
        let destination_id = base64_encode(destination.id().to_vec());
        let packet = PacketBuilder::new(1337u32)
            .with_synchronize()
            .with_send_stream_id(0u32)
            .with_replay_protection(&manager.destination.id())
            .with_from_included(destination)
            .with_signature()
            .with_payload(b"hello, world\n")
            .build_and_sign(&signing_key)
            .to_vec();

        // handle syn packet and spawn manager in the background
        assert!(manager.on_packet(0u16, 0u16, packet).is_ok());

        tokio::spawn(async move { while let Some(_) = manager.next().await {} });

        let mut reader = BufReader::new(client_socket);
        let mut response = String::new();

        // read stream status
        reader.read_line(&mut response).await.unwrap();
        assert_eq!(response, "STREAM STATUS RESULT=OK\n");

        // read remote's destination id
        response.clear();
        reader.read_line(&mut response).await.unwrap();
        assert_eq!(response, format!("{destination_id}\n"));

        // read payload from syn packet
        response.clear();
        reader.read_line(&mut response).await.unwrap();
        assert_eq!(response, "hello, world\n");
    }

    #[tokio::test]
    async fn data_in_syn_packet_non_silent_pending_ephemeral() {
        let socket_factory = SocketFactory::new().await;

        let mut manager = {
            let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
            let destination = Destination::new(signing_key.public());
            let destination_id = destination.id();
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        let signing_key = SigningPrivateKey::new(&[1u8; 32]).unwrap();
        let destination = Destination::new(signing_key.public());
        let destination_id = base64_encode(destination.id().to_vec());
        let packet = PacketBuilder::new(1337u32)
            .with_synchronize()
            .with_send_stream_id(0u32)
            .with_replay_protection(&manager.destination.id())
            .with_from_included(destination)
            .with_signature()
            .with_payload(b"hello, world\n")
            .build_and_sign(&signing_key)
            .to_vec();

        // handle syn packet and spawn manager in the background
        assert!(manager.on_packet(0u16, 0u16, packet).is_ok());
        assert!(!manager.pending_inbound.is_empty());

        // register listener for `manager1`
        let (socket, mut client_socket) = socket_factory.socket().await;
        assert!(manager
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: false
            })
            .is_ok());

        tokio::spawn(async move { while let Some(_) = manager.next().await {} });

        let mut reader = BufReader::new(client_socket);
        let mut response = String::new();

        // read stream status
        reader.read_line(&mut response).await.unwrap();
        assert_eq!(response, "STREAM STATUS RESULT=OK\n");

        // read remote's destination id
        response.clear();
        reader.read_line(&mut response).await.unwrap();
        assert_eq!(response, format!("{destination_id}\n"));

        // read payload from syn packet
        response.clear();
        reader.read_line(&mut response).await.unwrap();
        assert_eq!(response, "hello, world\n");
    }

    #[tokio::test]
    async fn data_in_syn_packet_silent_pending_ephemeral() {
        let socket_factory = SocketFactory::new().await;

        let mut manager = {
            let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
            let destination = Destination::new(signing_key.public());
            let destination_id = destination.id();
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        let signing_key = SigningPrivateKey::new(&[1u8; 32]).unwrap();
        let destination = Destination::new(signing_key.public());
        let destination_id = base64_encode(destination.id().to_vec());
        let packet = PacketBuilder::new(1337u32)
            .with_synchronize()
            .with_send_stream_id(0u32)
            .with_replay_protection(&manager.destination.id())
            .with_from_included(destination)
            .with_signature()
            .with_payload(b"hello, world\n")
            .build_and_sign(&signing_key)
            .to_vec();

        // handle syn packet and spawn manager in the background
        assert!(manager.on_packet(0u16, 0u16, packet).is_ok());
        assert!(!manager.pending_inbound.is_empty());

        // register listener for `manager1`
        let (socket, mut client_socket) = socket_factory.socket().await;
        assert!(manager
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: true
            })
            .is_ok());

        tokio::spawn(async move { while let Some(_) = manager.next().await {} });

        let mut reader = BufReader::new(client_socket);
        let mut response = String::new();

        // read payload from syn packet
        response.clear();
        reader.read_line(&mut response).await.unwrap();
        assert_eq!(response, "hello, world\n");
    }

    #[tokio::test]
    async fn active_session_destroyed() {
        crate::util::init_logger();

        let socket_factory = SocketFactory::new().await;

        let mut manager1 = {
            let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
            let destination = Destination::new(signing_key.public());
            let destination_id = destination.id();
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        let mut manager2 = {
            let signing_key = SigningPrivateKey::new(&[1u8; 32]).unwrap();
            let destination = Destination::new(signing_key.public());
            let destination_id = destination.id();
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        // register listener for `manager1`
        let (socket, mut listener_stream) = socket_factory.socket().await;
        assert!(manager1
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: true
            })
            .is_ok());

        // create new oubound stream to `manager1`
        let (socket, mut client_stream) = socket_factory.socket().await;
        let (packet, stream_id) =
            manager2.create_stream(manager1.destination_id.clone(), socket, false);

        assert!(manager1.on_packet(0u16, 0u16, packet.to_vec()).is_ok());

        assert!(std::matches!(
            manager1.next().await,
            Some(StreamManagerEvent::StreamOpened { .. })
        ));

        let (destination_id, packet) =
            match tokio::time::timeout(Duration::from_secs(5), manager1.next())
                .await
                .unwrap()
                .unwrap()
            {
                StreamManagerEvent::SendPacket {
                    destination_id,
                    packet,
                } => (destination_id, packet),
                _ => panic!("invalid event"),
            };

        assert_eq!(destination_id, manager2.destination_id);
        assert!(manager2.on_packet(0u16, 0u16, packet).is_ok());

        // remove session to manager2 due to error
        manager1.remove_session(&manager2.destination_id);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = manager1.next() => {}
                    _ = manager2.next() => {}
                }
            }
        });

        let mut reader = tokio::io::BufReader::new(client_stream);
        let mut response = String::new();
        reader.read_line(&mut response).await.unwrap();

        assert_eq!(response.as_str(), "STREAM STATUS RESULT=OK\n");

        // verify that the stream has been closed
        let mut buffer = vec![0u8; 12];
        assert_eq!(listener_stream.read(&mut buffer).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn inbound_stream() {
        let signing_key = SigningPrivateKey::new(&[
            116, 15, 103, 156, 205, 43, 224, 113, 103, 249, 182, 195, 149, 25, 171, 177, 151, 135,
            221, 125, 79, 161, 205, 146, 188, 100, 15, 177, 189, 91, 167, 60,
        ])
        .unwrap();
        let destination = Destination::new(signing_key.public());
        let mut manager = StreamManager::<MockRuntime>::new(destination, signing_key);

        let payload = vec![
            0, 0, 0, 0, 7, 170, 162, 225, 0, 0, 0, 0, 0, 0, 0, 0, 8, 92, 237, 166, 51, 230, 31, 2,
            219, 176, 105, 43, 109, 206, 122, 239, 241, 221, 135, 206, 60, 147, 145, 41, 155, 120,
            133, 180, 145, 4, 26, 107, 40, 9, 4, 169, 1, 201, 127, 213, 228, 57, 98, 56, 202, 186,
            4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107,
            167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46,
            112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93,
            127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224,
            232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56,
            202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97,
            227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192,
            50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101,
            93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46,
            224, 232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57,
            98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217,
            232, 97, 227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78,
            254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107, 167,
            187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112,
            10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93, 127,
            213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232,
            108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202,
            186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227,
            107, 167, 187, 30, 101, 93, 25, 140, 66, 230, 135, 216, 58, 4, 196, 109, 50, 64, 50,
            20, 213, 102, 99, 242, 187, 7, 216, 187, 137, 158, 228, 199, 195, 182, 38, 53, 40, 227,
            5, 0, 4, 0, 7, 0, 0, 7, 20, 182, 215, 224, 75, 178, 60, 111, 31, 179, 197, 227, 223,
            204, 20, 139, 51, 220, 96, 129, 16, 67, 235, 112, 185, 5, 108, 37, 55, 24, 251, 233,
            175, 88, 10, 18, 128, 227, 33, 34, 87, 15, 141, 210, 183, 58, 42, 184, 148, 221, 156,
            78, 128, 175, 18, 79, 142, 32, 0, 13, 28, 247, 4, 222, 7,
        ];

        assert!(manager.on_packet(13, 37, payload).is_ok());
    }

    #[tokio::test]
    async fn invalid_signature() {
        let signing_key = SigningPrivateKey::new(&[
            116, 15, 103, 156, 205, 43, 224, 113, 103, 249, 182, 195, 149, 25, 171, 177, 151, 135,
            221, 125, 79, 161, 205, 146, 188, 100, 15, 177, 189, 91, 167, 60,
        ])
        .unwrap();
        let destination = Destination::new(signing_key.public());
        let mut manager = StreamManager::<MockRuntime>::new(destination, signing_key);

        let payload = vec![
            0, 0, 0, 0, 7, 170, 162, 225, 0, 0, 0, 0, 0, 0, 0, 0, 8, 92, 237, 166, 51, 230, 31, 2,
            219, 176, 105, 43, 109, 206, 122, 239, 241, 221, 135, 206, 60, 147, 145, 41, 155, 120,
            133, 180, 145, 4, 26, 107, 40, 9, 4, 169, 1, 201, 127, 213, 228, 57, 98, 56, 202, 186,
            4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107,
            167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46,
            112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93,
            127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224,
            232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56,
            202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97,
            227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192,
            50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101,
            93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46,
            224, 232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57,
            98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217,
            232, 97, 227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78,
            254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107, 167,
            187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112,
            10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93, 127,
            213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232,
            108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202,
            186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227,
            107, 167, 187, 30, 101, 93, 25, 140, 66, 230, 135, 216, 58, 4, 196, 109, 50, 64, 50,
            20, 213, 102, 99, 242, 187, 7, 216, 187, 137, 158, 228, 199, 195, 182, 38, 53, 40, 227,
            5, 0, 4, 0, 7, 0, 0, 7, 20, 182, 215, 224, 75, 178, 60, 111, 31, 179, 197, 227, 223,
            204, 20, 139, 51, 220, 96, 129, 16, 67, 235, 112, 185, 5, 108, 37, 55, 24, 251, 233,
            175, 88, 10, 18, 128, 227, 33, 34, 87, 15, 141, 210, 183, 58, 42, 184, 148, 221, 156,
            78, 128, 175, 18, 79, 142, 32, 0, 13, 28, 247, 4, 223, 7,
        ];

        assert_eq!(
            manager.on_packet(13, 37, payload),
            Err(StreamingError::InvalidSignature)
        );
    }

    #[tokio::test]
    async fn invalid_destination_id() {
        let signing_key = SigningPrivateKey::new(&[
            116, 15, 103, 156, 205, 43, 224, 113, 103, 249, 182, 195, 149, 25, 171, 177, 151, 135,
            221, 125, 79, 161, 205, 146, 188, 100, 15, 177, 189, 91, 167, 60,
        ])
        .unwrap();
        let destination = Destination::new(signing_key.public());
        let mut manager = StreamManager::<MockRuntime>::new(destination, signing_key);

        let payload = vec![
            0, 0, 0, 0, 7, 170, 162, 225, 0, 0, 0, 0, 0, 0, 0, 0, 8, 92, 237, 165, 51, 230, 31, 2,
            219, 176, 105, 43, 109, 206, 122, 239, 241, 221, 135, 206, 60, 147, 145, 41, 155, 120,
            133, 180, 145, 4, 26, 107, 40, 9, 4, 169, 1, 201, 127, 213, 228, 57, 98, 56, 202, 186,
            4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107,
            167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46,
            112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93,
            127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224,
            232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56,
            202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97,
            227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192,
            50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101,
            93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46,
            224, 232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57,
            98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217,
            232, 97, 227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78,
            254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107, 167,
            187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112,
            10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93, 127,
            213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232,
            108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202,
            186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227,
            107, 167, 187, 30, 101, 93, 25, 140, 66, 230, 135, 216, 58, 4, 196, 109, 50, 64, 50,
            20, 213, 102, 99, 242, 187, 7, 216, 187, 137, 158, 228, 199, 195, 182, 38, 53, 40, 227,
            5, 0, 4, 0, 7, 0, 0, 7, 20, 182, 215, 224, 75, 178, 60, 111, 31, 179, 197, 227, 223,
            204, 20, 139, 51, 220, 96, 129, 16, 67, 235, 112, 185, 5, 108, 37, 55, 24, 251, 233,
            175, 88, 10, 18, 128, 227, 33, 34, 87, 15, 141, 210, 183, 58, 42, 184, 148, 221, 156,
            78, 128, 175, 18, 79, 142, 32, 0, 13, 28, 247, 4, 222, 7,
        ];

        assert_eq!(
            manager.on_packet(13, 37, payload),
            Err(StreamingError::ReplayProtectionCheckFailed)
        );
    }
}
