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
    sam::protocol::streaming::packet::{Packet, PacketBuilder},
};

use rand_core::RngCore;
use thingbuf::mpsc::{Receiver, Sender};

use core::{
    future::Future,
    mem,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::sam::streaming::stream";

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

    /// TX channel for sending [`Packet`]s to the network.
    event_tx: Sender<(DestinationId, Vec<u8>)>,

    /// ID of the local destination.
    local: DestinationId,

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

impl<R: Runtime> Stream<R> {
    /// Create new [`Stream`]
    pub fn new(
        stream: R::TcpStream,
        initial_message: Option<Vec<u8>>,
        context: StreamContext,
    ) -> Self {
        let StreamContext {
            local,
            remote,
            cmd_rx,
            event_tx,
            recv_stream_id,
        } = context;

        let send_stream_id = R::rng().next_u32();
        let packet = PacketBuilder::new(send_stream_id)
            .with_send_stream_id(recv_stream_id)
            .with_seq_nro(0)
            .with_synchronize()
            .build();

        event_tx.try_send((remote.clone(), packet.freeze().to_vec())).unwrap();

        Self {
            cmd_rx,
            event_tx,
            local,
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

                        // TODO: ack message

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
                        "write state is poisoned",
                    );
                    debug_assert!(false);
                    return Poll::Ready(this.recv_stream_id);
                }
            }
        }

        Poll::Pending
    }
}
