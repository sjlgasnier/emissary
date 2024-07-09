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

use emissary::runtime::{JoinSet, Runtime, TcpListener, TcpStream};
use futures::{AsyncRead, AsyncWrite, Stream};
use rand_core::{CryptoRng, RngCore};
use tokio::{io::AsyncWriteExt, net, task};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use std::{
    future::Future,
    pin::{pin, Pin},
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
pub struct TokioRuntime {}

impl TokioRuntime {
    pub fn new() -> Self {
        Self {}
    }
}

pub struct TokioTcpStream(Compat<net::TcpStream>);

impl TokioTcpStream {
    fn new(stream: net::TcpStream) -> Self {
        let stream = TokioAsyncReadCompatExt::compat(stream).into_inner();
        let stream = TokioAsyncWriteCompatExt::compat_write(stream);

        Self(stream)
    }
}

impl AsyncRead for TokioTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let pinned = pin!(&mut self.0);
        pinned.poll_read(cx, buf)
    }

    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let pinned = pin!(&mut self.0);
        pinned.poll_read_vectored(cx, bufs)
    }
}

impl AsyncWrite for TokioTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let pinned = pin!(&mut self.0);
        pinned.poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let pinned = pin!(&mut self.0);
        pinned.poll_write_vectored(cx, bufs)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let pinned = pin!(&mut self.0);
        pinned.poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let pinned = pin!(&mut self.0);
        pinned.poll_close(cx)
    }
}

impl TcpStream for TokioTcpStream {
    async fn connect(address: &str) -> Option<Self> {
        net::TcpStream::connect(address)
            .await
            .map_err(|error| {
                tracing::warn!("error: {error:?}");
                ()
            })
            .ok()
            .map(|stream| Self::new(stream))
    }

    async fn close(&mut self) {
        let _ = self.0.get_mut().shutdown().await;
    }
}

pub struct TokioTcpListener(net::TcpListener);

impl TcpListener<TokioTcpStream> for TokioTcpListener {
    async fn bind(address: &str) -> Option<Self> {
        net::TcpListener::bind(&address)
            .await
            .ok()
            .map(|listener| TokioTcpListener(listener))
    }

    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<Option<TokioTcpStream>> {
        match futures::ready!(self.0.poll_accept(cx)) {
            Err(_) => return Poll::Ready(None),
            Ok((stream, _)) => return Poll::Ready(Some(TokioTcpStream::new(stream))),
        }
    }
}

pub struct TokioJoinSet<T>(task::JoinSet<T>);

impl<T: Send + 'static> JoinSet<T> for TokioJoinSet<T> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn push<F>(&mut self, future: F)
    where
        F: Future<Output = T> + Send + 'static,
        F::Output: Send,
    {
        let _ = self.0.spawn(future);
    }
}

impl<T: Send + 'static> Stream for TokioJoinSet<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match futures::ready!(self.0.poll_join_next(cx)) {
            None | Some(Err(_)) => Poll::Ready(None),
            Some(Ok(value)) => Poll::Ready(Some(value)),
        }
    }
}

impl Runtime for TokioRuntime {
    type TcpStream = TokioTcpStream;
    type TcpListener = TokioTcpListener;
    type JoinSet<T: Send + 'static> = TokioJoinSet<T>;

    fn spawn<F>(future: F)
    where
        F: Future + Send + 'static,
        F::Output: Send,
    {
        tokio::spawn(future);
    }

    fn time_since_epoch() -> Duration {
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("to succeed")
    }

    fn rng() -> impl RngCore + CryptoRng {
        rand_core::OsRng
    }

    fn join_set<T: Send + 'static>() -> Self::JoinSet<T> {
        TokioJoinSet(task::JoinSet::<T>::new())
    }
}
