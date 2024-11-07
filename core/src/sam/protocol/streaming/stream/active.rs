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
    error::StreamingError,
    primitives::DestinationId,
    runtime::{AsyncRead, AsyncWrite, Runtime},
    sam::protocol::streaming::{
        config::StreamConfig,
        packet::{Packet, PacketBuilder},
    },
};

use futures::{future::BoxFuture, FutureExt};
use rand_core::RngCore;
use thingbuf::mpsc::{Receiver, Sender};

use alloc::collections::{BTreeMap, VecDeque};
use core::{
    future::Future,
    marker::PhantomData,
    mem,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::sam::streaming::stream";

/// Read buffer size.
const READ_BUFFER_SIZE: usize = 8192;

/// Initial ACK delay.
const INITIAL_ACK_DELAY: Duration = Duration::from_millis(200);

/// Sequence number for a plain ACK message.
const PLAIN_ACK: u32 = 0u32;

/// Stream kind.
pub enum StreamKind {
    /// Stream is uninitialized and there has been no activity on it before.
    Inbound {
        /// Payload of the `SYN` packet, may be empty.
        payload: Vec<u8>,
    },

    /// Stream was pending before a listener was ready to accept it and there may have been data
    /// exchange in stream before the listener was ready. [`Stream`] must initialize its state
    /// using with the provided data.
    InboundPending {
        /// Selected send stream ID.
        send_stream_id: u32,

        /// Remote peer's current sequence number.
        seq_nro: u32,

        /// Received packets, if any.
        packets: VecDeque<Vec<u8>>,
    },

    /// Outbound stream.
    Outbound {
        /// Selected send stream ID.
        send_stream_id: u32,
    },
}

/// Context needed to initialize [`Stream`].
pub struct StreamContext {
    /// RX channel for receiving [`Packet`]s from the network.
    pub cmd_rx: Receiver<Vec<u8>>,

    /// TX channel for sending [`Packet`]s to the network.
    pub event_tx: Sender<(DestinationId, Vec<u8>)>,

    /// ID of the local destination.
    pub local: DestinationId,

    /// Stream ID selected by the stream originator.
    pub recv_stream_id: u32,

    /// ID of the remote destination.
    pub remote: DestinationId,
}

/// Write state.
enum WriteState {
    /// Get next message from channel.
    GetMessage,

    /// Send message into the socket.
    WriteMessage {
        /// Offset into `message`.
        offset: usize,

        /// Message.
        message: Vec<u8>,
    },

    /// [`WriteState`] has been poisoned.
    Poisoned,
}

/// Read state.
enum SocketState {
    /// Read message from client.
    ReadMessage,

    /// Sending message
    SendMessage {
        /// Offset into read buffer.
        offset: usize,
    },

    /// Awaiting ACK to be received for the sent message.
    AwaitingAck {
        /// Sequence number of the message.
        seq_nro: u32,

        /// Serialized packet.
        packet: Vec<u8>,
    },

    /// [`SocketState`] has been poisoned.
    Poisoned,
}

/// Inbound context.
pub struct InboundContext<R: Runtime> {
    /// ACK timer.
    ack_timer: Option<BoxFuture<'static, ()>>,

    /// Sequence number of the highest, last ACKed packet.
    last_acked: u32,

    /// Pending packets.
    pending: VecDeque<Vec<u8>>,

    /// Measured RTT.
    rtt: Duration,

    /// Highest received sequence number from remote destination.
    seq_nro: u32,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> InboundContext<R> {
    /// Create new [`InboundContext`] with highest received `seq_nro`.
    fn new(seq_nro: u32) -> Self {
        Self {
            ack_timer: None,
            pending: VecDeque::new(),
            rtt: INITIAL_ACK_DELAY,
            seq_nro,
            last_acked: seq_nro,
            _runtime: Default::default(),
        }
    }

    fn handle_packet(&mut self, seq_nro: u32, payload: Vec<u8>) {
        if seq_nro == self.seq_nro + 1 {
            self.pending.push_back(payload);
            self.seq_nro = seq_nro;

            if self.ack_timer.is_none() {
                self.ack_timer = Some(Box::pin(R::delay(self.rtt)));
            }
        } else {
            panic!("out-of-order packets not supported");
        }
    }

    fn set_rtt(&mut self, rtt: usize) {
        todo!();
    }

    fn pop_message(&mut self) -> Option<Vec<u8>> {
        self.pending.pop_front()
    }
}

impl<R: Runtime> Future for InboundContext<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(timer) = &mut self.ack_timer {
            if timer.poll_unpin(cx).is_ready() {
                self.ack_timer = None;
                return Poll::Ready(());
            }
        }

        Poll::Pending
    }
}

/// I2P virtual stream.
///
/// Implements a `Future` which returns the send stream ID after the virtual stream has been shut
/// down, either by the client or by the remote participant.
pub struct Stream<R: Runtime> {
    /// RX channel for receiving [`Packet`]s from the network.
    cmd_rx: Receiver<Vec<u8>>,

    /// Stream configuration.
    config: StreamConfig,

    /// TX channel for sending [`Packet`]s to the network.
    event_tx: Sender<(DestinationId, Vec<u8>)>,

    /// Inbound context for packets received from the network.
    inbound_context: InboundContext<R>,

    /// ID of the local destination.
    local: DestinationId,

    /// Next sequence number.
    next_seq_nro: u32,

    /// Read buffer.
    read_buffer: Vec<u8>,

    /// Socket state.
    read_state: SocketState,

    /// Receive stream ID (selected by remote peer).
    recv_stream_id: u32,

    /// ID of the remote destination.
    remote: DestinationId,

    /// Send stream ID (selected by us).
    send_stream_id: u32,

    /// Underlying TCP stream used to communicate with the client.
    stream: R::TcpStream,

    /// Write state.
    write_state: WriteState,
}

impl<R: Runtime> Stream<R> {
    /// Create new [`Stream`]
    pub fn new(
        stream: R::TcpStream,
        initial_message: Option<Vec<u8>>,
        context: StreamContext,
        config: StreamConfig,
        state: StreamKind,
    ) -> Self {
        let StreamContext {
            local,
            remote,
            cmd_rx,
            event_tx,
            recv_stream_id,
        } = context;

        let (send_stream_id, initial_message, highest_ack) = match state {
            StreamKind::Inbound { payload } => {
                let send_stream_id = R::rng().next_u32();
                let packet = PacketBuilder::new(send_stream_id)
                    .with_send_stream_id(recv_stream_id)
                    .with_seq_nro(0)
                    .with_synchronize()
                    .build();

                event_tx.try_send((remote.clone(), packet.to_vec())).unwrap();

                (
                    send_stream_id,
                    match (initial_message, payload.is_empty()) {
                        (Some(mut initial), false) => {
                            initial.extend_from_slice(&payload);
                            Some(initial)
                        }
                        (Some(initial), true) => Some(initial),
                        (None, false) => Some(payload),
                        (None, true) => None,
                    },
                    0u32,
                )
            }
            StreamKind::InboundPending {
                send_stream_id,
                seq_nro,
                packets,
            } => {
                let combined = packets.into_iter().fold(Vec::new(), |mut message, packet| {
                    message.extend_from_slice(&packet);
                    message
                });

                tracing::trace!(
                    target: LOG_TARGET,
                    %local,
                    %remote,
                    ?send_stream_id,
                    ?recv_stream_id,
                    pending_payload_len = ?combined.len(),
                    "initialize state from pending connection",
                );

                (
                    send_stream_id,
                    match (initial_message, combined.is_empty()) {
                        (None, true) => None,
                        (None, false) => Some(combined),
                        (Some(message), true) => Some(message),
                        (Some(mut message), false) => {
                            message.extend_from_slice(&combined);
                            Some(message)
                        }
                    },
                    seq_nro,
                )
            }
            StreamKind::Outbound { send_stream_id } => (
                send_stream_id,
                initial_message.is_some().then(|| b"STREAM STATUS RESULT=OK\n".to_vec()),
                0u32,
            ),
        };

        Self {
            cmd_rx,
            config,
            event_tx,
            inbound_context: InboundContext::new(highest_ack),
            local,
            next_seq_nro: 1u32,
            read_buffer: vec![0u8; READ_BUFFER_SIZE],
            read_state: SocketState::ReadMessage,
            recv_stream_id,
            remote,
            send_stream_id,
            stream,
            write_state: match initial_message {
                None => WriteState::GetMessage,
                Some(message) => WriteState::WriteMessage {
                    offset: 0usize,
                    message,
                },
            },
        }
    }

    /// Handle acknowledgements.
    fn handle_acks(&mut self, ack_through: u32, nacks: &[u32]) {}

    /// Handle `packet` received from the network.
    fn on_packet(&mut self, packet: Vec<u8>) -> Result<(), StreamingError> {
        let Packet {
            seq_nro,
            ack_through,
            nacks,
            resend_delay,
            flags,
            payload,
            ..
        } = Packet::parse(&packet).ok_or(StreamingError::Malformed)?;

        if !flags.no_ack() {
            self.handle_acks(ack_through, &nacks);
        }

        if !payload.is_empty() {
            self.inbound_context.handle_packet(seq_nro, payload.to_vec());
        }

        Ok(())
    }
}

impl<R: Runtime> Future for Stream<R> {
    type Output = u32;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = Pin::into_inner(self);

        loop {
            match mem::replace(&mut this.write_state, WriteState::Poisoned) {
                WriteState::GetMessage => match this.cmd_rx.poll_recv(cx) {
                    Poll::Pending => {
                        this.write_state = WriteState::GetMessage;
                        break;
                    }
                    Poll::Ready(None) => return Poll::Ready(this.recv_stream_id),
                    Poll::Ready(Some(message)) => match this.on_packet(message) {
                        Err(error) => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                local = %this.local,
                                remote = %this.remote,
                                ?error,
                                "failed to handle packet"
                            );
                            this.write_state = WriteState::GetMessage;
                        }
                        Ok(()) => match this.inbound_context.pop_message() {
                            Some(message) =>
                                this.write_state = WriteState::WriteMessage {
                                    offset: 0usize,
                                    message,
                                },
                            None => this.write_state = WriteState::GetMessage,
                        },
                    },
                },
                WriteState::WriteMessage { offset, message } =>
                    match Pin::new(&mut this.stream).as_mut().poll_write(cx, &message[offset..]) {
                        Poll::Pending => {
                            this.write_state = WriteState::WriteMessage { offset, message };
                            break;
                        }
                        Poll::Ready(Err(_)) => return Poll::Ready(this.recv_stream_id),
                        Poll::Ready(Ok(nwritten)) if nwritten == 0 => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                "wrote zero bytes to socket",
                            );

                            return Poll::Ready(this.recv_stream_id);
                        }
                        Poll::Ready(Ok(nwritten)) => match nwritten + offset == message.len() {
                            true => {
                                this.write_state = WriteState::GetMessage;
                            }
                            false => {
                                this.write_state = WriteState::WriteMessage {
                                    offset: offset + nwritten,
                                    message,
                                };
                            }
                        },
                    },
                WriteState::Poisoned => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        local = %this.local,
                        remote = %this.remote,
                        "write state is poisoned",
                    );
                    debug_assert!(false);
                    return Poll::Ready(this.recv_stream_id);
                }
            }
        }

        loop {
            match mem::replace(&mut this.read_state, SocketState::Poisoned) {
                SocketState::ReadMessage =>
                    match Pin::new(&mut this.stream).as_mut().poll_read(cx, &mut this.read_buffer) {
                        Poll::Pending => {
                            this.read_state = SocketState::ReadMessage;
                            break;
                        }
                        Poll::Ready(Err(error)) => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                ?error,
                                local = %this.local,
                                remote = %this.remote,
                                "socket error",
                            );
                            return Poll::Ready(this.recv_stream_id);
                        }
                        Poll::Ready(Ok(nread)) => {
                            if nread == 0 {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    local = %this.local,
                                    remote = %this.remote,
                                    "read zero bytes from socket",
                                );
                                return Poll::Ready(this.recv_stream_id);
                            }

                            this.read_state = SocketState::SendMessage { offset: nread };
                        }
                    },
                SocketState::SendMessage { offset } => {
                    let seq_nro = {
                        let seq_nro = this.next_seq_nro;
                        this.next_seq_nro += 1;

                        seq_nro
                    };

                    tracing::info!(target: LOG_TARGET, "send next packet, seq nro = {seq_nro}");

                    let packet = PacketBuilder::new(this.send_stream_id)
                        .with_send_stream_id(this.recv_stream_id)
                        .with_seq_nro(seq_nro)
                        .with_payload(&this.read_buffer[..offset])
                        .build();

                    // TODO: retries
                    // TODO: cancel ack timer here if ok
                    if let Err(error) =
                        this.event_tx.try_send((this.remote.clone(), packet.to_vec()))
                    {
                        tracing::warn!(
                            target: LOG_TARGET,
                            local = %this.local,
                            remote = %this.remote,
                            ?error,
                            "failed to send packet",
                        );
                    }

                    this.read_state = SocketState::AwaitingAck {
                        seq_nro,
                        packet: packet.to_vec(),
                    };
                    break;
                }
                SocketState::AwaitingAck { seq_nro, packet } => {
                    this.read_state = SocketState::AwaitingAck { seq_nro, packet };
                    break;
                }
                SocketState::Poisoned => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        local = %this.local,
                        remote = %this.remote,
                        "read state is poisoned",
                    );
                    debug_assert!(false);
                    return Poll::Ready(this.recv_stream_id);
                }
            }
        }

        if this.inbound_context.poll_unpin(cx).is_ready() {
            let ack_through = this.inbound_context.seq_nro;

            let packet = PacketBuilder::new(this.send_stream_id)
                .with_send_stream_id(this.recv_stream_id)
                .with_ack_through(ack_through)
                .with_seq_nro(PLAIN_ACK)
                .build();

            match this.event_tx.try_send((this.remote.clone(), packet.to_vec())) {
                Err(error) => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        local = %this.local,
                        remote = %this.remote,
                        ?error,
                        "failed to send packet",
                    );
                }
                Ok(()) => {
                    this.inbound_context.last_acked = ack_through;
                }
            }
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{
        mock::{MockRuntime, MockTcpStream},
        Runtime, TcpStream,
    };
    use thingbuf::mpsc::channel;
    use tokio::io::{AsyncBufReadExt, BufReader};

    struct StreamBuilder {
        cmd_tx: Sender<Vec<u8>>,
        event_rx: Receiver<(DestinationId, Vec<u8>)>,
        stream: tokio::net::TcpStream,
    }

    impl StreamBuilder {
        pub async fn build_stream() -> (Stream<MockRuntime>, Self) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();

            let address = listener.local_addr().unwrap();
            let (stream1, stream2) =
                tokio::join!(listener.accept(), MockTcpStream::connect(address));
            let (stream, _) = stream1.unwrap();

            let (event_tx, event_rx) = channel(64);
            let (cmd_tx, cmd_rx) = channel(64);

            (
                Stream::new(
                    stream2.unwrap(),
                    None,
                    StreamContext {
                        cmd_rx,
                        event_tx,
                        local: DestinationId::random(),
                        recv_stream_id: 1337u32,
                        remote: DestinationId::random(),
                    },
                    Default::default(),
                    StreamKind::Inbound { payload: vec![] },
                ),
                Self {
                    cmd_tx,
                    event_rx,
                    stream,
                },
            )
        }
    }

    #[tokio::test]
    async fn receive_multiple_packets() {
        let (
            stream,
            StreamBuilder {
                cmd_tx,
                stream: client,
                mut event_rx,
            },
        ) = StreamBuilder::build_stream().await;

        tokio::spawn(stream);

        let messages = vec![
            b"hello\n".to_vec(),
            b"world\n".to_vec(),
            b"goodbye\n".to_vec(),
            b"world\n".to_vec(),
        ];

        for (i, message) in messages.iter().enumerate() {
            cmd_tx
                .send(
                    PacketBuilder::new(1338u32)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(i as u32 + 1)
                        .with_payload(message)
                        .build()
                        .to_vec(),
                )
                .await;
        }

        let mut reader = BufReader::new(client);
        let mut response = String::new();

        for message in messages.into_iter() {
            reader.read_line(&mut response).await.unwrap();
            assert_eq!(std::str::from_utf8(&message).unwrap(), response);
            response.clear();
        }

        // ignore syn packet
        let _ = event_rx.recv().await.unwrap();

        // all four messages acked with one packet
        {
            let (_, packet) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
                .await
                .expect("event")
                .expect("to succeed");

            let Packet {
                seq_nro,
                ack_through,
                nacks,
                payload,
                ..
            } = Packet::parse(&packet).unwrap();

            assert_eq!(ack_through, 4u32);
            assert_eq!(seq_nro, 0u32);
            assert!(nacks.is_empty());
            assert!(payload.is_empty());
        }

        // send one more packet and verify that it's acked
        cmd_tx
            .send(
                PacketBuilder::new(1338u32)
                    .with_send_stream_id(1337u32)
                    .with_seq_nro(5u32)
                    .with_payload(b"test message\n")
                    .build()
                    .to_vec(),
            )
            .await;

        let (_, packet) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("event")
            .expect("to succeed");

        let Packet {
            seq_nro,
            ack_through,
            nacks,
            payload,
            ..
        } = Packet::parse(&packet).unwrap();

        assert_eq!(ack_through, 5u32);
        assert_eq!(seq_nro, 0u32);
        assert!(nacks.is_empty());
        assert!(payload.is_empty());

        // read payload
        reader.read_line(&mut response).await.unwrap();
        assert_eq!("test message\n", response.as_str());
        response.clear();
    }
}
