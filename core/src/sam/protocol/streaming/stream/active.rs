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
    primitives::DestinationId,
    runtime::{AsyncRead, AsyncWrite, Runtime, TcpStream},
    sam::protocol::streaming::{
        config::StreamConfig,
        packet::{Packet, PacketBuilder},
    },
};

use chacha20poly1305::aead::Buffer;
use rand_core::RngCore;
use thingbuf::mpsc::{Receiver, Sender};

use alloc::collections::VecDeque;
use core::{
    future::Future,
    mem,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::sam::streaming::stream";

/// Read buffer size.
const READ_BUFFER_SIZE: usize = 8192;

/// Stream kind.
pub enum StreamKind {
    /// Stream is uninitialized and there has been no activity on it before.
    Inbound,

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

    /// ID of the local destination.
    local: DestinationId,

    /// Next sequence number.
    next_seq_nro: u32,

    /// Read buffer.
    read_buffer: Vec<u8>,

    /// Read state.
    read_state: ReadState,

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
enum ReadState {
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

    /// [`ReadState`] has been poisoned.
    Poisoned,
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

        let (send_stream_id, initial_message) = match state {
            StreamKind::Inbound => {
                let send_stream_id = R::rng().next_u32();
                let packet = PacketBuilder::new(send_stream_id)
                    .with_send_stream_id(recv_stream_id)
                    .with_seq_nro(0)
                    .with_synchronize()
                    .build();

                event_tx.try_send((remote.clone(), packet.to_vec())).unwrap();

                (send_stream_id, initial_message)
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
                )
            }
            StreamKind::Outbound { send_stream_id } => (
                send_stream_id,
                initial_message.is_some().then(|| b"STREAM STATUS RESULT=OK\n".to_vec()),
            ),
        };

        Self {
            cmd_rx,
            config,
            event_tx,
            local,
            next_seq_nro: 1u32,
            read_buffer: vec![0u8; READ_BUFFER_SIZE],
            read_state: ReadState::ReadMessage,
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
}

impl<R: Runtime> Future for Stream<R> {
    type Output = u32;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let mut stream = Pin::new(&mut this.stream);

        loop {
            match mem::replace(&mut this.write_state, WriteState::Poisoned) {
                WriteState::GetMessage => match this.cmd_rx.poll_recv(cx) {
                    Poll::Pending => {
                        this.write_state = WriteState::GetMessage;
                        break;
                    }
                    Poll::Ready(None) => return Poll::Ready(this.recv_stream_id),
                    Poll::Ready(Some(message)) => {
                        let Packet {
                            send_stream_id,
                            recv_stream_id,
                            seq_nro,
                            ack_through,
                            nacks,
                            resend_delay,
                            flags,
                            payload,
                        } = Packet::parse(&message).unwrap();

                        tracing::error!(target: LOG_TARGET, "ack through = {ack_through}");

                        match this.read_state {
                            ReadState::AwaitingAck { seq_nro, .. } => {
                                tracing::error!(
                                    target: LOG_TARGET,
                                    "waiting ack for {seq_nro}, got ack for {ack_through}"
                                );

                                if seq_nro <= ack_through {
                                    tracing::info!(target: LOG_TARGET, "ack received");
                                    this.read_state = ReadState::ReadMessage;
                                }
                            }
                            _ => {}
                        }

                        // send ack
                        let ack = PacketBuilder::new(send_stream_id)
                            .with_send_stream_id(recv_stream_id)
                            .with_ack_through(seq_nro)
                            .with_seq_nro(0)
                            .build();

                        if let Err(error) =
                            this.event_tx.try_send((this.remote.clone(), ack.to_vec()))
                        {
                            tracing::warn!(
                                target: LOG_TARGET,
                                ?error,
                                "failed to send ack",
                            );
                        }

                        if payload.is_empty() {
                            this.write_state = WriteState::GetMessage;
                            continue;
                        }

                        this.write_state = WriteState::WriteMessage {
                            offset: 0usize,
                            message: payload.to_vec(),
                        };
                    }
                },
                WriteState::WriteMessage { offset, message } =>
                    match stream.as_mut().poll_write(cx, &message[offset..]) {
                        Poll::Pending => {
                            this.write_state = WriteState::WriteMessage { offset, message };
                            break;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(this.recv_stream_id),
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
            match mem::replace(&mut this.read_state, ReadState::Poisoned) {
                ReadState::ReadMessage =>
                    match stream.as_mut().poll_read(cx, &mut this.read_buffer) {
                        Poll::Pending => {
                            this.read_state = ReadState::ReadMessage;
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
                        Poll::Ready((Ok(nread))) => {
                            if nread == 0 {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    local = %this.local,
                                    remote = %this.remote,
                                    "read zero bytes from socket",
                                );
                                return Poll::Ready(this.recv_stream_id);
                            }

                            this.read_state = ReadState::SendMessage { offset: nread };
                        }
                    },
                ReadState::SendMessage { offset } => {
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

                    this.read_state = ReadState::AwaitingAck {
                        seq_nro,
                        packet: packet.to_vec(),
                    };
                    break;
                }
                ReadState::AwaitingAck { seq_nro, packet } => {
                    this.read_state = ReadState::AwaitingAck { seq_nro, packet };
                    break;
                }
                ReadState::Poisoned => {
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

        Poll::Pending
    }
}
