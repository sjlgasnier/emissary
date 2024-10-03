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
    runtime::{AsyncRead, AsyncWrite, Runtime, TcpStream},
    Error,
};

use futures::Stream;

use alloc::vec::Vec;
use core::{
    mem,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::i2cp::socket";

/// Read state.
enum ReadState {
    /// Read I2CP frame length.
    ReadSize {
        /// Offset into read buffer.
        offset: usize,
    },

    /// Read I2CP frame.
    ReadFrame {
        /// Size of the next frame.
        size: usize,

        /// Offset into read buffer.
        offset: usize,
    },
}

/// Write state
enum WriteState {
    /// Read next outbound message from channel.
    GetMessage,

    /// Send message size.
    SendSize {
        /// Write offset.
        offset: usize,

        /// Obfuscated message size as a byte vector.
        size: Vec<u8>,

        /// I2NP message.
        message: Vec<u8>,
    },

    /// Send message.
    SendMessage {
        /// Write offset.
        offset: usize,

        /// I2CP message, potentially partially written.
        message: Vec<u8>,
    },

    /// [`WriteState`] has been poisoned due to a bug.
    Poisoned,
}

/// I2CP client socket.
pub struct I2cpSocket<R: Runtime> {
    /// Read buffer.
    read_buffer: Vec<u8>,

    /// Read state.
    read_state: ReadState,

    /// TCP stream.
    stream: R::TcpStream,

    /// Write state.
    write_state: WriteState,
}

impl<R: Runtime> I2cpSocket<R> {
    /// Create new [`I2cpSocket`].
    pub fn new(stream: R::TcpStream) -> Self {
        Self {
            read_buffer: vec![0u8; 0xffff],
            read_state: ReadState::ReadSize { offset: 0usize },
            stream,
            write_state: WriteState::GetMessage,
        }
    }
}

impl<R: Runtime> Stream for I2cpSocket<R> {
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        let mut stream = Pin::new(&mut this.stream);

        loop {
            match this.read_state {
                ReadState::ReadSize { offset } => {
                    match stream.as_mut().poll_read(cx, &mut this.read_buffer[offset..2]) {
                        Poll::Pending => break,
                        Poll::Ready(Err(error)) => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                ?error,
                                "socket read error",
                            );

                            return Poll::Ready(None);
                        }
                        Poll::Ready((Ok(nread))) => {
                            if nread == 0 {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    "read zero bytes from socket",
                                );

                                return Poll::Ready(None);
                            }

                            if offset + nread != 2 {
                                this.read_state = ReadState::ReadSize {
                                    offset: offset + nread,
                                };
                                continue;
                            }

                            let size = (this.read_buffer[0] as u16) << 8
                                | (this.read_buffer[1] as u16) & 0xff;

                            this.read_state = ReadState::ReadFrame {
                                size: size as usize,
                                offset: 0usize,
                            };
                        }
                    }
                }
                ReadState::ReadFrame { size, offset } => {
                    match stream.as_mut().poll_read(cx, &mut this.read_buffer[offset..size]) {
                        Poll::Pending => break,
                        Poll::Ready(Err(error)) => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                ?error,
                                "socket read error",
                            );

                            return Poll::Ready(None);
                        }
                        Poll::Ready((Ok(nread))) => {
                            if nread == 0 {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    "read zero bytes from socket",
                                );

                                return Poll::Ready(None);
                            }

                            // next frame hasn't been read completely
                            if offset + nread < size {
                                this.read_state = ReadState::ReadFrame {
                                    size,
                                    offset: offset + nread,
                                };
                                continue;
                            }

                            let _data_block = this.read_buffer[..size].to_vec();

                            // TODO: do something with data block

                            this.read_state = ReadState::ReadSize { offset: 0usize };
                        }
                    }
                }
            }
        }

        loop {
            match mem::replace(&mut this.write_state, WriteState::Poisoned) {
                WriteState::GetMessage => {
                    todo!();
                }
                WriteState::SendSize {
                    offset,
                    size,
                    message,
                } => match stream.as_mut().poll_write(cx, &size[offset..]) {
                    Poll::Pending => {
                        this.write_state = WriteState::SendSize {
                            offset,
                            size,
                            message,
                        };
                        break;
                    }
                    Poll::Ready(Err(error)) => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            ?error,
                            "socket write error",
                        );
                        return Poll::Ready(None);
                    }
                    Poll::Ready(Ok(nwritten)) if nwritten == 0 => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            "wrote zero bytes to socket",
                        );

                        return Poll::Ready(None);
                    }
                    Poll::Ready(Ok(nwritten)) => match nwritten + offset == size.len() {
                        true => {
                            this.write_state = WriteState::SendMessage {
                                offset: 0usize,
                                message,
                            };
                        }
                        false => {
                            this.write_state = WriteState::SendSize {
                                size,
                                offset: offset + nwritten,
                                message,
                            };
                        }
                    },
                },
                WriteState::SendMessage { offset, message } =>
                    match stream.as_mut().poll_write(cx, &message[offset..]) {
                        Poll::Pending => {
                            this.write_state = WriteState::SendMessage { offset, message };
                            break;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(None),
                        Poll::Ready(Ok(nwritten)) if nwritten == 0 => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                "wrote zero bytes to socket",
                            );

                            return Poll::Ready(None);
                        }
                        Poll::Ready(Ok(nwritten)) => match nwritten + offset == message.len() {
                            true => {
                                this.write_state = WriteState::GetMessage;
                            }
                            false => {
                                this.write_state = WriteState::SendMessage {
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
                    return Poll::Ready(None);
                }
            }
        }

        Poll::Pending
    }
}
