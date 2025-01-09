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
    transports::ssu2::message::Block,
};

use bytes::{Buf, BytesMut};
use hashbrown::HashMap;
use thingbuf::mpsc::{Receiver, Sender};

use core::{
    future::Future,
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

/// SSU2 socket.
pub struct Ssu2Socket<R: Runtime> {
    /// Receive buffer.
    buffer: Vec<u8>,

    /// Intro key.
    intro_key: StaticPrivateKey,

    /// Raw intro key bytes.
    intro_key_raw: [u8; 32],

    /// SSU2 sessions.
    sessions: HashMap<u64, ()>,

    /// TX channel for sending session events to [`Ssu2`].
    session_tx: Sender<Ssu2SessionEvent>,

    /// UDP socket.
    socket: R::UdpSocket,

    /// Static key.
    static_key: StaticPrivateKey,
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
            session_tx,
            sessions: HashMap::new(),
            socket,
            static_key: StaticPrivateKey::from(static_key),
        }
    }

    /// Handle packet.
    fn handle_packet(&mut self, nread: usize) {
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
        ChaCha::with_iv(self.intro_key_raw, iv1).decrypt(&mut mask);

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
        ChaCha::with_iv(self.intro_key_raw, iv2).decrypt(&mut mask);
        mask.into_iter().zip(&mut self.buffer[8..]).for_each(|(a, b)| {
            *b ^= a;
        });

        match self.buffer[12] {
            10 => {
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

                ChaCha::with_iv(self.intro_key_raw, [0u8; 12]).decrypt(&mut self.buffer[16..32]);

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

                // TODO: send retry message
            }
            msg_type => todo!("unsupported message type = {msg_type}"),
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
                    this.handle_packet(nread);
                }
            }
        }

        Poll::Pending
    }
}
