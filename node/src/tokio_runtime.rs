use emissary::runtime::{Runtime, TcpListener, TcpStream};
use futures::{AsyncRead, AsyncWrite};
use tokio::{io::AsyncWriteExt, net};
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

    async fn accept(&mut self) -> Option<TokioTcpStream> {
        self.0
            .accept()
            .await
            .ok()
            .map(|(stream, _)| TokioTcpStream::new(stream))
    }
}

impl Runtime for TokioRuntime {
    type TcpStream = TokioTcpStream;
    type TcpListener = TokioTcpListener;

    fn spawn<F>(future: F)
    where
        F: Future + Send + 'static,
        F::Output: Send,
    {
        tokio::spawn(future);
    }

    fn time_since_epoch() -> Option<Duration> {
        SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()
    }
}
