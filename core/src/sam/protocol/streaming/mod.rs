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
    primitives::DestinationId,
    runtime::{Instant, JoinSet, Runtime},
    sam::protocol::streaming::{
        config::StreamConfig,
        listener::{SocketKind, StreamListener, StreamListenerEvent},
        packet::Packet,
        stream::{
            active::{Stream, StreamContext, StreamState},
            pending::{PendingStream, PendingStreamResult},
        },
    },
};

use bytes::{BufMut, BytesMut};
use futures::{future::BoxFuture, FutureExt, StreamExt};
use hashbrown::{HashMap, HashSet};
use thingbuf::mpsc::{channel, Receiver, Sender};

use alloc::{collections::VecDeque, vec::Vec};
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
const LOG_TARGET: &str = "emissary::sam::streaming";

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

/// Signature length.
const SIGNATURE_LEN: usize = 64usize;

/// I2P virtual stream manager.
pub struct StreamManager<R: Runtime> {
    /// TX channels for sending [`Packet`]'s to active streams.
    ///
    /// Indexed with receive stream ID.
    active: HashMap<u32, Sender<Vec<u8>>>,

    /// ID of the `Destination` the stream manager is bound to.
    destination_id: DestinationId,

    /// Stream listener.
    listener: StreamListener<R>,

    /// RX channel for receiving [`Packet`]s from active streams.
    outbound_rx: Receiver<(DestinationId, Vec<u8>)>,

    /// TX channel given to active streams they use for sending messages to the network.
    outbound_tx: Sender<(DestinationId, Vec<u8>)>,

    /// Pending streams.
    ///
    /// Indexed by the remote-selected receive stream ID.
    pending: HashMap<u32, PendingStream<R>>,

    /// Timer for pruning stale pending streams.
    prune_timer: BoxFuture<'static, ()>,

    /// Signing key.
    signing_key: SigningPrivateKey,

    /// Active streams.
    streams: R::JoinSet<u32>,
}

impl<R: Runtime> StreamManager<R> {
    /// Create new [`StreamManager`].
    pub fn new(destination_id: DestinationId, signing_key: SigningPrivateKey) -> Self {
        let (outbound_tx, outbound_rx) = channel(STREAM_MANAGER_CHANNEL_SIZE);

        Self {
            active: HashMap::new(),
            destination_id: destination_id.clone(),
            listener: StreamListener::new(destination_id),
            outbound_rx,
            outbound_tx,
            pending: HashMap::new(),
            prune_timer: Box::pin(R::delay(PENDING_STREAM_PRUNE_THRESHOLD)),
            signing_key,
            streams: R::join_set(),
        }
    }

    /// Handle message with `SYN`.
    ///
    /// Ensure that signature and destination are in the message and verify their validity.
    /// Additionally ensure that the NACK field contains local destination's ID.
    ///
    /// If validity checks pass, send the message to a listener if it exists. If there are no active
    /// listeners, mark the stream as pending and start a timer for waiting for a new listener to be
    /// registered. If no listener is registered within the time window, the stream is closed.
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

        let signature = flags.signature().ok_or(StreamingError::SignatureMissing)?;
        let destination =
            flags.from_included().as_ref().ok_or(StreamingError::DestinationMissing)?;

        // verify that the nacks field contains local destination id for replay protection
        {
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
                StreamState::Uninitialized,
            ),
            None => {
                tracing::info!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    ?recv_stream_id,
                    "inbound stream but no available listeners",
                );

                // create new pending stream and send syn-ack for it
                let (pending, packet) = PendingStream::new(destination.id(), recv_stream_id);
                let _ = self.outbound_tx.try_send((destination.id(), packet));

                self.pending.insert(recv_stream_id, pending);
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
        state: StreamState,
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
            remote: destination_id,
        };

        // if the socket wasn't configured to be silent, send the remote's destination
        // to client before the socket is convered into a regural tcp stream
        let initial_message = match &socket {
            SocketKind::Direct { silent, .. } => !silent,
            SocketKind::Forwarded { silent, .. } => !silent,
        }
        .then(|| format!("{}\n", base64_encode(context.remote.to_vec())).into_bytes());

        // store the tx channel of the stream in `StreamManager`'s context
        //
        // `StreamManager` sends all inbound messages with `recv_stream_id` to this stream and all
        // outbound messages from the stream to remote peer are send through `event_tx`
        self.active.insert(recv_stream_id, tx);

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
            SocketKind::Direct { socket, .. } => self.streams.push(Stream::<R>::new(
                socket,
                initial_message,
                context,
                StreamConfig::default(),
                state,
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
                    state,
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
            num_pending = ?self.pending.len(),
            "listener ready",
        );

        // loop through all pending streams until either:
        //  a) there are no more pending streams
        //  b) there are no more available listeners
        loop {
            let Some(stream_id) = self.pending.keys().next().copied() else {
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
            } = self.pending.remove(&stream_id).expect("to exist");

            // spawn new task for the stream in the background
            self.spawn_stream(
                socket,
                stream_id,
                destination_id,
                StreamState::Initialized {
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
            ?src_port,
            ?dst_port,
            "inbound message",
        );

        // forward received packet to an active handler if it exists
        if let Some(tx) = self.active.get(&packet.recv_stream_id()) {
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

        if let Some(stream) = self.pending.get_mut(&packet.recv_stream_id()) {
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
                    let _ = self.pending.remove(&packet.recv_stream_id());
                }
                PendingStreamResult::Destroy => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        recv_stream_id = ?packet.recv_stream_id(),
                        "destroy pending stream",
                    );

                    let _ = self.pending.remove(&packet.recv_stream_id());
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
}

impl<R: Runtime> futures::Stream for StreamManager<R> {
    type Item = (DestinationId, Vec<u8>);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.outbound_rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some((destination_id, packet))) =>
                    return Poll::Ready(Some((destination_id, packet))),
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
                    self.active.remove(&stream_id);
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

        if let Poll::Ready(()) = self.prune_timer.poll_unpin(cx) {
            self.pending
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
                    self.pending.remove(&stream_id);
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

    #[tokio::test]
    async fn register_ephemeral_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let (mut stream, _) = stream1.unwrap();
        let mut socket = SamSocket::<MockRuntime>::new(stream2.unwrap());

        let destination_id = DestinationId::random();
        let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
        let mut manager = StreamManager::<MockRuntime>::new(destination_id, signing_key);

        assert!(manager
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: false
            })
            .is_ok());
    }

    #[tokio::test]
    async fn stale_pending_streams_are_pruned() {
        let destination_id = DestinationId::random();
        let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
        let mut manager = StreamManager::<MockRuntime>::new(destination_id.clone(), signing_key);

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
        assert_eq!(manager.pending.len(), 1);

        // reset timer
        manager.prune_timer = Box::pin(tokio::time::sleep(PENDING_STREAM_PRUNE_THRESHOLD));

        // wait for a little while so all streams won't get pruned at the same time
        tokio::time::sleep(Duration::from_secs(20)).await;

        // register two other pending streams
        assert!(manager.on_packet(0u16, 0u16, packets.pop_front().unwrap()).is_ok());
        assert!(manager.on_packet(0u16, 0u16, packets.pop_front().unwrap()).is_ok());
        assert_eq!(manager.pending.len(), 3);

        // poll manager until the first stream is pruned
        //
        // verify that the other two are still left
        loop {
            futures::future::poll_fn(|cx| match manager.poll_next_unpin(cx) {
                Poll::Pending => Poll::Ready(()),
                Poll::Ready(_) => Poll::Ready(()),
            })
            .await;

            if manager.pending.len() != 3 {
                break;
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // verify that first pending stream is pruned and that the other two are still left
        assert!(!manager.pending.contains_key(&0));
        assert!(manager.pending.contains_key(&1));
        assert!(manager.pending.contains_key(&2));

        // reset timer
        manager.prune_timer = Box::pin(tokio::time::sleep(Duration::from_secs(20)));

        // poll until the last two streams are also pruned
        loop {
            futures::future::poll_fn(|cx| match manager.poll_next_unpin(cx) {
                Poll::Pending => Poll::Ready(()),
                Poll::Ready(_) => panic!("invalid event"),
            })
            .await;

            if manager.pending.is_empty() {
                break;
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    #[tokio::test]
    async fn pending_stream_initialized_with_silent_listener() {
        let destination_id = DestinationId::random();
        let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
        let mut manager = StreamManager::<MockRuntime>::new(destination_id.clone(), signing_key);

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
        assert_eq!(manager.pending.len(), 1);

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
        assert!(manager.pending.is_empty());

        // poll manager until ack packet is received
        let (remote, message) = manager.next().await.unwrap();

        let Packet {
            send_stream_id,
            recv_stream_id,
            flags,
            ..
        } = Packet::parse(&message).unwrap();

        assert_eq!(remote, remote_destination_id);
        assert_eq!(send_stream_id, 1337u32);
        assert_ne!(recv_stream_id, 0u32);
        assert!(flags.synchronize());
    }

    #[tokio::test]
    async fn pending_stream_initialized_with_non_silent_listener() {
        let destination_id = DestinationId::random();
        let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
        let mut manager = StreamManager::<MockRuntime>::new(destination_id.clone(), signing_key);

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
        assert_eq!(manager.pending.len(), 1);

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
        assert!(!manager.pending.is_empty());

        // poll manager until ack packet is received
        let (remote, message) = manager.next().await.unwrap();

        let Packet {
            send_stream_id,
            recv_stream_id,
            flags,
            ..
        } = Packet::parse(&message).unwrap();

        assert_eq!(remote, remote_destination_id);
        assert_eq!(send_stream_id, 1337u32);
        assert_ne!(recv_stream_id, 0u32);
        assert!(flags.synchronize());
    }

    #[tokio::test]
    async fn pending_stream_initialized_with_persistent_listener() {
        let destination_id = DestinationId::random();
        let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
        let mut manager = StreamManager::<MockRuntime>::new(destination_id.clone(), signing_key);

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
        assert_eq!(manager.pending.len(), 1);

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
        assert!(!manager.pending.is_empty());

        // poll manager until ack packet is received
        let (remote, message) = manager.next().await.unwrap();

        let Packet {
            send_stream_id,
            recv_stream_id,
            flags,
            ..
        } = Packet::parse(&message).unwrap();

        assert_eq!(remote, remote_destination_id);
        assert_eq!(send_stream_id, 1337u32);
        assert_ne!(recv_stream_id, 0u32);
        assert!(flags.synchronize());

        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response).await.unwrap();

        assert_eq!(response.as_str(), "STREAM STATUS RESULT=OK\n");
    }

    #[tokio::test]
    async fn pending_stream_with_buffered_data_initialized() {
        let destination_id = DestinationId::random();
        let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
        let mut manager = StreamManager::<MockRuntime>::new(destination_id.clone(), signing_key);

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
        assert_eq!(manager.pending.len(), 1);

        // poll manager until ack packet is received
        let (remote, message) = manager.next().await.unwrap();

        let Packet {
            send_stream_id,
            recv_stream_id,
            flags,
            ..
        } = Packet::parse(&message).unwrap();

        assert_eq!(remote, remote_destination_id);
        assert_eq!(send_stream_id, 1337u32);
        assert_ne!(recv_stream_id, 0u32);
        assert!(flags.synchronize());

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
                let (remote, message) = manager.next().await.unwrap();

                let Packet {
                    send_stream_id,
                    recv_stream_id,
                    flags,
                    ack_through,
                    ..
                } = Packet::parse(&message).unwrap();

                assert_eq!(remote, remote_destination_id);
                assert_eq!(send_stream_id, 1337u32);
                assert_ne!(recv_stream_id, 0u32);
                assert_eq!(ack_through, i as u32 + 1u32);
            }
        }

        // verify that the stream is still pending
        assert_eq!(manager.pending.len(), 1);

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
        assert!(manager.pending.is_empty());

        // poll manager in the background in order to drive the stream future forward
        tokio::spawn(async move { while let Some(_) = manager.next().await {} });

        // verify that the buffered data is returned to client
        let mut buffer = vec![0u8; 36];
        stream.read_exact(&mut buffer).await.unwrap();

        assert_eq!(buffer, b"hello, worldtesting 123goodbye world");
    }

    #[tokio::test]
    async fn inbound_stream() {
        let destination_id = DestinationId::from([
            200, 35, 63, 139, 109, 209, 249, 106, 242, 177, 156, 87, 29, 241, 241, 117, 75, 81,
            133, 124, 14, 246, 56, 138, 8, 201, 219, 160, 118, 181, 191, 27,
        ]);
        let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
        let mut manager = StreamManager::<MockRuntime>::new(destination_id, signing_key);

        let payload = vec![
            0, 0, 0, 0, 148, 23, 180, 82, 0, 0, 0, 0, 0, 0, 0, 0, 8, 200, 35, 63, 139, 109, 209,
            249, 106, 242, 177, 156, 87, 29, 241, 241, 117, 75, 81, 133, 124, 14, 246, 56, 138, 8,
            201, 219, 160, 118, 181, 191, 27, 9, 4, 169, 1, 201, 38, 195, 17, 125, 194, 201, 147,
            121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183,
            252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209,
            227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138,
            76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54,
            140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125,
            194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60,
            244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4,
            113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44,
            250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89,
            81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195,
            17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54,
            252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147,
            121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183,
            252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209,
            227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138,
            76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54,
            140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125,
            194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60,
            244, 107, 183, 252, 44, 250, 248, 138, 76, 180, 60, 50, 18, 127, 20, 227, 77, 70, 183,
            45, 98, 87, 86, 53, 211, 46, 229, 46, 211, 83, 237, 74, 202, 66, 177, 167, 84, 212,
            142, 59, 123, 5, 0, 4, 0, 7, 0, 0, 7, 20, 34, 64, 253, 113, 136, 137, 7, 144, 142, 165,
            147, 51, 145, 79, 234, 74, 126, 166, 86, 159, 203, 103, 202, 205, 154, 245, 129, 74,
            180, 253, 6, 52, 63, 37, 90, 147, 60, 180, 195, 134, 209, 104, 48, 24, 178, 46, 155,
            216, 187, 51, 17, 73, 220, 156, 1, 23, 130, 84, 245, 197, 171, 40, 76, 5,
        ];

        assert!(manager.on_packet(13, 37, payload).is_ok());
    }

    #[tokio::test]
    async fn invalid_signature() {
        let destination_id = DestinationId::from([
            200, 35, 63, 139, 109, 209, 249, 106, 242, 177, 156, 87, 29, 241, 241, 117, 75, 81,
            133, 124, 14, 246, 56, 138, 8, 201, 219, 160, 118, 181, 191, 27,
        ]);
        let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
        let mut manager = StreamManager::<MockRuntime>::new(destination_id, signing_key);

        let payload = vec![
            0, 0, 0, 0, 148, 23, 180, 82, 0, 0, 0, 0, 0, 0, 0, 0, 8, 200, 35, 63, 139, 109, 209,
            249, 106, 242, 177, 156, 87, 29, 241, 241, 117, 75, 81, 133, 124, 14, 246, 56, 138, 8,
            201, 219, 160, 118, 181, 191, 27, 9, 4, 169, 1, 201, 38, 195, 17, 125, 194, 201, 147,
            121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183,
            252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209,
            227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138,
            76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54,
            140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125,
            194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60,
            244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4,
            113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44,
            250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89,
            81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195,
            17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54,
            252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147,
            121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183,
            252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209,
            227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138,
            76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54,
            140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125,
            194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60,
            244, 107, 183, 252, 44, 250, 248, 138, 76, 180, 60, 50, 18, 127, 20, 227, 77, 70, 183,
            45, 98, 87, 86, 53, 211, 46, 229, 46, 211, 83, 237, 74, 202, 66, 177, 167, 84, 212,
            142, 59, 123, 5, 0, 4, 0, 7, 0, 0, 7, 20, 34, 64, 253, 113, 136, 137, 7, 144, 142, 165,
            147, 51, 145, 79, 234, 74, 126, 166, 86, 159, 203, 103, 202, 205, 154, 245, 129, 74,
            180, 253, 6, 52, 63, 37, 90, 147, 60, 180, 195, 134, 209, 104, 48, 24, 178, 46, 155,
            216, 187, 51, 17, 73, 220, 156, 1, 23, 130, 84, 245, 197, 171, 40, 76, 6,
        ];

        assert_eq!(
            manager.on_packet(13, 37, payload),
            Err(StreamingError::InvalidSignature)
        );
    }

    #[tokio::test]
    async fn invalid_destination_id() {
        let destination_id = DestinationId::from([
            200, 200, 200, 139, 109, 209, 249, 106, 242, 177, 156, 87, 29, 241, 241, 117, 75, 81,
            133, 124, 14, 246, 56, 138, 8, 201, 219, 160, 118, 181, 191, 27,
        ]);
        let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
        let mut manager = StreamManager::<MockRuntime>::new(destination_id, signing_key);

        let payload = vec![
            0, 0, 0, 0, 148, 23, 180, 82, 0, 0, 0, 0, 0, 0, 0, 0, 8, 200, 35, 63, 139, 109, 209,
            249, 106, 242, 177, 156, 87, 29, 241, 241, 117, 75, 81, 133, 124, 14, 246, 56, 138, 8,
            201, 219, 160, 118, 181, 191, 27, 9, 4, 169, 1, 201, 38, 195, 17, 125, 194, 201, 147,
            121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183,
            252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209,
            227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138,
            76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54,
            140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125,
            194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60,
            244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4,
            113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44,
            250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89,
            81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195,
            17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54,
            252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147,
            121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183,
            252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209,
            227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138,
            76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54,
            140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125,
            194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60,
            244, 107, 183, 252, 44, 250, 248, 138, 76, 180, 60, 50, 18, 127, 20, 227, 77, 70, 183,
            45, 98, 87, 86, 53, 211, 46, 229, 46, 211, 83, 237, 74, 202, 66, 177, 167, 84, 212,
            142, 59, 123, 5, 0, 4, 0, 7, 0, 0, 7, 20, 34, 64, 253, 113, 136, 137, 7, 144, 142, 165,
            147, 51, 145, 79, 234, 74, 126, 166, 86, 159, 203, 103, 202, 205, 154, 245, 129, 74,
            180, 253, 6, 52, 63, 37, 90, 147, 60, 180, 195, 134, 209, 104, 48, 24, 178, 46, 155,
            216, 187, 51, 17, 73, 220, 156, 1, 23, 130, 84, 245, 197, 171, 40, 76, 5,
        ];

        assert_eq!(
            manager.on_packet(13, 37, payload),
            Err(StreamingError::ReplayProtectionCheckFailed)
        );
    }
}
