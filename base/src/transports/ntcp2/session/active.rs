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

//! Active NTCP2 session.
//!
//! https://geti2p.net/spec/ntcp2#data-phase

use crate::{
    crypto::{chachapoly::ChaChaPoly, siphash::SipHash},
    i2np::MessageType,
    primitives::{RouterId, RouterInfo},
    runtime::{AsyncRead, Runtime, TcpStream},
    subsystem::SubsystemCommand,
    transports::{
        ntcp2::{
            message::MessageBlock,
            session::{KeyContext, Role},
        },
        SubsystemHandle,
    },
    util::AsyncReadExt,
};

use thingbuf::mpsc::{channel, Receiver, Sender};

use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ntcp2::active";

/// Read state.
enum ReadState {
    /// Read NTCP2 frame length.
    ReadSize {
        /// Offset into read buffer.
        offset: usize,
    },

    /// Read NTCP2 frame.
    ReadFrame {
        /// Size of the next frame.
        size: usize,

        /// Offset into read buffer.
        offset: usize,
    },
}

/// Active NTCP2 session.
pub struct Ntcp2Session<R: Runtime> {
    /// Role of the session.
    role: Role,

    /// `RouterInfo` of the remote peer.
    router_info: RouterInfo,

    /// Router ID.
    router: RouterId,

    /// Runtime.
    runtime: R,

    /// TCP stream.
    stream: R::TcpStream,

    /// Cipher for outbound messages.
    send_cipher: ChaChaPoly,

    /// Read state.
    read_state: ReadState,

    /// Read buffer.
    read_buffer: Vec<u8>,

    /// Cipher for inbound messages.
    recv_cipher: ChaChaPoly,

    /// SipHasher for (deobfuscating) message lengths.
    sip: SipHash,

    /// Subsystem handle.
    subsystem_handle: SubsystemHandle,

    /// RX channel for receiving messages from subsystems.
    cmd_rx: Receiver<SubsystemCommand>,

    /// TX channel for sending commands for this connection.
    cmd_tx: Sender<SubsystemCommand>,
}

impl<R: Runtime> Ntcp2Session<R> {
    /// Create new active NTCP2 [`Session`].
    pub fn new(
        role: Role,
        router_info: RouterInfo,
        runtime: R,
        stream: R::TcpStream,
        key_context: KeyContext,
        mut subsystem_handle: SubsystemHandle,
    ) -> Self {
        let router = router_info.identity().id();
        let KeyContext {
            send_key,
            recv_key,
            sip,
        } = key_context;

        let (cmd_tx, cmd_rx) = channel(128);

        Self {
            role,
            router: router_info.identity().id(),
            router_info,
            runtime,
            read_buffer: vec![0u8; 0xffff],
            read_state: ReadState::ReadSize { offset: 0usize },
            stream,
            send_cipher: ChaChaPoly::new(&send_key),
            recv_cipher: ChaChaPoly::new(&recv_key),
            sip,
            subsystem_handle,
            cmd_rx,
            cmd_tx,
        }
    }

    /// Get role of the session.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Get `RouterInfo` of the remote peer.
    pub fn router(&self) -> RouterInfo {
        self.router_info.clone()
    }

    pub async fn run(mut self) {
        tracing::trace!(
            target: LOG_TARGET,
            router = %self.router,
            "start event ntcp2 event loop",
        );

        self.subsystem_handle
            .report_connection_established(self.router.clone(), self.cmd_tx.clone())
            .await;

        self.await
    }
}

impl<R: Runtime> Future for Ntcp2Session<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
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
                                "socket error",
                            );
                            return Poll::Ready(());
                        }
                        Poll::Ready((Ok(nread))) => {
                            if nread == 0 {
                                return Poll::Ready(());
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
                                size: this.sip.deobfuscate(size) as usize,
                                offset: 0usize,
                            };
                        }
                    }
                }
                ReadState::ReadFrame { size, offset } => {
                    match stream.as_mut().poll_read(cx, &mut this.read_buffer[offset..]) {
                        Poll::Pending => break,
                        Poll::Ready(Err(error)) => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                ?error,
                                "socket error",
                            );
                            return Poll::Ready(());
                        }
                        Poll::Ready((Ok(nread))) => {
                            if nread == 0 {
                                tracing::debug!(target: LOG_TARGET, "socket closed");
                                return Poll::Ready(());
                            }

                            // next frame hasn't been read completely
                            if offset + nread < size {
                                this.read_state = ReadState::ReadFrame {
                                    size,
                                    offset: offset + nread,
                                };
                                continue;
                            }

                            let data_block = this
                                .recv_cipher
                                .decrypt(this.read_buffer[..size].to_vec())
                                .unwrap();

                            match MessageBlock::parse(&data_block) {
                                Some(MessageBlock::I2Np { message }) => {
                                    let message_id = message.message_id();

                                    if let Err(error) =
                                        this.subsystem_handle.dispatch_message(message)
                                    {
                                        tracing::debug!(
                                            target: LOG_TARGET,
                                            ?message_id,
                                            ?error,
                                            "failed to deliver message to subsystem",
                                        );
                                    }
                                }
                                Some(message) => {
                                    tracing::debug!("message received: {message:?}");
                                }
                                None => {
                                    tracing::warn!("invalid message received, ignoring");
                                }
                            }

                            this.read_state = ReadState::ReadSize { offset: 0usize };
                        }
                    }
                }
            }
        }

        Poll::Pending
    }
}
