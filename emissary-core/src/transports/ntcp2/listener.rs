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
    runtime::{Runtime, TcpListener},
    transports::ntcp2::LOG_TARGET,
};

use futures::Stream;

use core::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

// TODO: fix listen address
// TODO: support both ipv4 and ipv6

/// NTCP2 listener.
pub struct Ntcp2Listener<R: Runtime> {
    /// TCP Listener.
    listener: R::TcpListener,
}

impl<R: Runtime> Ntcp2Listener<R> {
    /// Create new [`Ntcp2Listener`].
    pub async fn new(address: SocketAddr) -> crate::Result<Self> {
        let listener = R::TcpListener::bind(address).await.unwrap();

        tracing::trace!(
            target: LOG_TARGET,
            "starting ntcp2 listener",
        );

        Ok(Self { listener })
    }
}

impl<R: Runtime> Stream for Ntcp2Listener<R> {
    type Item = R::TcpStream;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.listener.poll_accept(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(stream)) => Poll::Ready(Some(stream)),
        }
    }
}
