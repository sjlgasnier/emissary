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

use crate::{primitives::RouterId, runtime::Runtime, transport::ssu2::Packet};

use thingbuf::mpsc::{Receiver, Sender};

use core::{
    future::Future,
    marker::PhantomData,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::session::active";

/// Key context for an active session.
pub struct KeyContext {
    /// Key for encrypting/decrypting `Data` payloads.
    k_data: [u8; 32],

    /// Key for encrypting/decrypting second part of the header.
    k_header_2: [u8; 32],
}

impl KeyContext {
    /// Create new [`KeyContext`].
    pub fn new(k_data: [u8; 32], k_header_2: [u8; 32]) -> Self {
        Self { k_data, k_header_2 }
    }
}

/// SSU2 active session context.
pub struct Ssu2SessionContext {
    /// Destination connection ID.
    pub dst_id: u64,

    /// Intro key of remote router.
    ///
    /// Used for encrypting the first part of the header.
    pub intro_key: [u8; 32],

    /// RX channel for receiving inbound packets from [`Ssu2Socket`].
    pub pkt_rx: Receiver<Packet>,

    /// Key context for inbound packets.
    pub recv_key_ctx: KeyContext,

    /// ID of the remote router.
    pub router_id: RouterId,

    /// Key context for outbound packets.
    pub send_key_ctx: KeyContext,
}

/// Active SSU2 session.
pub struct Ssu2Session<R: Runtime> {
    /// Destination connection ID.
    dst_id: u64,

    /// Intro key of remote router.
    ///
    /// Used for encrypting the first part of the header.
    intro_key: [u8; 32],

    /// RX channel for receiving inbound packets from [`Ssu2Socket`].
    pkt_rx: Receiver<Packet>,

    /// TX channel for sending packets to [`Ssu2Socket`].
    //
    // TODO: `R::UdpSocket` should be clonable
    pkt_tx: Sender<Packet>,

    /// Key context for inbound packets.
    recv_key_ctx: KeyContext,

    /// ID of the remote router.
    router_id: RouterId,

    /// Key context for outbound packets.
    send_key_ctx: KeyContext,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> Ssu2Session<R> {
    /// Create new [`Ssu2Session`].
    pub fn new(context: Ssu2SessionContext, pkt_tx: Sender<Packet>) -> Self {
        Self {
            dst_id: context.dst_id,
            intro_key: context.intro_key,
            pkt_rx: context.pkt_rx,
            recv_key_ctx: context.recv_key_ctx,
            router_id: context.router_id,
            send_key_ctx: context.send_key_ctx,
            pkt_tx,
            _runtime: Default::default(),
        }
    }

    fn on_packet(&mut self, pkt: Packet) {
        let Packet { pkt, address } = pkt;

        tracing::info!(
            target: LOG_TARGET,
            pkt_len = ?pkt.len(),
            ?address,
            "handle packet"
        );
    }
}

impl<R: Runtime> Future for Ssu2Session<R> {
    type Output = (RouterId, u64);

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.pkt_rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready((self.router_id.clone(), self.dst_id)),
                Poll::Ready(Some(pkt)) => self.on_packet(pkt),
            }
        }

        Poll::Pending
    }
}
