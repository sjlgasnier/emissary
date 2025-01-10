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
    crypto::{
        chachapoly::{ChaCha, ChaChaPoly},
        StaticPrivateKey,
    },
    runtime::{Runtime, UdpSocket},
    transports::ssu2::message::{Block, HeaderBuilder, MessageBuilder, MessageType},
};

use bytes::{Buf, BytesMut};
use hashbrown::HashMap;
use rand_core::RngCore;
use thingbuf::mpsc::{Receiver, Sender};

use alloc::collections::VecDeque;
use core::{
    future::Future,
    mem,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::socket";

/// Read buffer length.
const READ_BUFFER_LEN: usize = 2048usize;

/// Events emitted by [`Ssu2Socket`].
#[derive(Debug, Default, Clone)]
pub enum Ssu2SessionEvent {
    #[default]
    Dummy,
}

/// Write state.
enum WriteState {
    /// Get next packet.
    GetPacket,

    /// Send packet.
    SendPacket {
        /// Packet.
        pkt: BytesMut,

        /// Target.
        target: SocketAddr,
    },

    /// Poisoned.
    Poisoned,
}

/// SSU2 socket.
pub struct Ssu2Socket<R: Runtime> {
    /// Receive buffer.
    buffer: Vec<u8>,

    /// Intro key.
    intro_key: StaticPrivateKey,

    /// Raw intro key bytes.
    intro_key_raw: [u8; 32],

    /// Pending outbound packets.
    pending_pkts: VecDeque<(BytesMut, SocketAddr)>,

    /// TX channel for sending session events to [`Ssu2`].
    session_tx: Sender<Ssu2SessionEvent>,

    /// SSU2 sessions.
    sessions: HashMap<u64, ()>,

    /// UDP socket.
    socket: R::UdpSocket,

    /// Static key.
    static_key: StaticPrivateKey,

    /// Write state.
    write_state: WriteState,
}

impl<R: Runtime> Ssu2Socket<R> {
    /// Create new [`Ssu2Socket`].
    pub fn new(
        socket: R::UdpSocket,
        static_key: [u8; 32],
        intro_key: [u8; 32],
        session_tx: Sender<Ssu2SessionEvent>,
    ) -> Self {
        let intro_key = StaticPrivateKey::from(intro_key);
        let intro_key_raw =
            TryInto::<[u8; 32]>::try_into(intro_key.public().to_vec()).expect("to succeed");

        Self {
            buffer: vec![0u8; READ_BUFFER_LEN],
            intro_key,
            intro_key_raw,
            pending_pkts: VecDeque::new(),
            sessions: HashMap::new(),
            session_tx,
            socket,
            static_key: StaticPrivateKey::from(static_key),
            write_state: WriteState::GetPacket,
        }
    }

    /// Handle packet.
    //
    // TODO: needs as lot of refactoring
    fn handle_packet(&mut self, nread: usize, from: SocketAddr) {
        tracing::error!(
            target: LOG_TARGET,
            ?nread,
            "handle packet",
        );

        let iv1 = TryInto::<[u8; 12]>::try_into(&self.buffer[nread - 24..nread - 12])
            .expect("to succeed");
        let iv2 =
            TryInto::<[u8; 12]>::try_into(&self.buffer[nread - 12..nread]).expect("to succeed");
        let mut mask = [0u8; 8];
        ChaCha::with_iv(self.intro_key_raw, iv1).decrypt_ref(&mut mask);

        let connection_id = u64::from_be(mask.into_iter().zip(&mut self.buffer).fold(
            0u64,
            |connection_id, (a, b)| {
                *b ^= a;

                (connection_id << 8) | (*b as u64)
            },
        ));

        tracing::info!(
            target: LOG_TARGET,
            ?connection_id,
            "received message"
        );

        if self.sessions.contains_key(&connection_id) {
            todo!();
        }

        let mut mask = [0u8; 8];
        ChaCha::with_iv(self.intro_key_raw, iv2).decrypt_ref(&mut mask);
        mask.into_iter().zip(&mut self.buffer[8..]).for_each(|(a, b)| {
            *b ^= a;
        });

        match MessageType::try_from(self.buffer[12]) {
            Ok(MessageType::TokenRequest) => {
                let pkt_num = u32::from_le_bytes(
                    TryInto::<[u8; 4]>::try_into(&self.buffer[8..12]).expect("to succeed"),
                );

                tracing::info!(
                    target: LOG_TARGET,
                    ?pkt_num,
                    version = ?self.buffer[13],
                    net_id = ?self.buffer[14],
                    "handle token request",
                );

                ChaCha::with_iv(self.intro_key_raw, [0u8; 12])
                    .decrypt_ref(&mut self.buffer[16..32]);

                let src_connection_id = u64::from_le_bytes(
                    TryInto::<[u8; 8]>::try_into(&self.buffer[16..24]).expect("to succeed"),
                );
                let token = u64::from_le_bytes(
                    TryInto::<[u8; 8]>::try_into(&self.buffer[24..32]).expect("to succeed"),
                );

                let mut payload = self.buffer[32..nread].to_vec();
                ChaChaPoly::with_nonce(&self.intro_key_raw, pkt_num.to_be() as u64)
                    .decrypt_with_ad(&self.buffer[..32], &mut payload)
                    .unwrap();

                match Block::parse(&payload) {
                    Some(blocks) => blocks.into_iter().for_each(|block| {
                        tracing::info!(target: LOG_TARGET, "block = {block:?}");
                    }),
                    None => tracing::error!(
                        target: LOG_TARGET,
                        "failed to parse blocks",
                    ),
                }

                let token = R::rng().next_u64();
                let pkt = MessageBuilder::new(
                    HeaderBuilder::long()
                        .with_dst_id(connection_id)
                        .with_src_id(src_connection_id)
                        .with_token(token)
                        .with_message_type(MessageType::Retry)
                        .build::<R>(),
                )
                .with_key(self.intro_key_raw)
                .with_block(Block::DateTime {
                    timestamp: R::time_since_epoch().as_secs() as u32,
                })
                .with_block(Block::Address { address: from })
                .build();

                self.pending_pkts.push_back((pkt, from));
            }
            Ok(message_type) => {
                tracing::error!(
                    target: LOG_TARGET,
                    ?message_type,
                    "support not implemented for message type",
                );
            }
            Err(()) => tracing::warn!(
                target: LOG_TARGET,
                message_type = ?self.buffer[12],
                "unrecognized message type",
            ),
        }
    }
}

impl<R: Runtime> Future for Ssu2Socket<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        loop {
            match Pin::new(&mut this.socket).poll_recv_from(cx, &mut this.buffer.as_mut()) {
                Poll::Pending => break,
                Poll::Ready(None) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "socket closed",
                    );
                    return Poll::Ready(());
                }
                Poll::Ready(Some((nread, from))) => {
                    this.handle_packet(nread, from);
                }
            }
        }

        loop {
            match mem::replace(&mut this.write_state, WriteState::Poisoned) {
                WriteState::GetPacket => match this.pending_pkts.pop_front() {
                    None => {
                        this.write_state = WriteState::GetPacket;
                        break;
                    }
                    Some((pkt, target)) => {
                        this.write_state = WriteState::SendPacket { pkt, target };
                    }
                },
                WriteState::SendPacket { pkt, target } =>
                    match Pin::new(&mut this.socket).poll_send_to(cx, &pkt, target) {
                        Poll::Ready(Some(_)) => {
                            this.write_state = WriteState::GetPacket;
                        }
                        Poll::Ready(None) => return Poll::Ready(()),
                        Poll::Pending => {
                            this.write_state = WriteState::SendPacket { pkt, target };
                            break;
                        }
                    },
                WriteState::Poisoned => unreachable!(),
            }
        }

        Poll::Pending
    }
}
