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

use crate::runtime::{
    AsyncRead, AsyncWrite, Counter, Gauge, Histogram, JoinSet, MetricsHandle, Runtime, TcpListener,
    TcpStream,
};

use futures::{future::BoxFuture, Stream};
use rand_core::{CryptoRng, RngCore};

use std::{
    future::{pending, Future},
    marker::PhantomData,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

pub struct MockTcpStream {}

impl AsyncRead for MockTcpStream {
    fn poll_read<'a>(
        self: Pin<&mut Self>,
        cx: &mut Context<'a>,
        buf: &mut [u8],
    ) -> Poll<crate::Result<usize>> {
        Poll::Pending
    }
}

impl crate::runtime::AsyncWrite for MockTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<crate::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<crate::Result<()>> {
        Poll::Pending
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<crate::Result<()>> {
        Poll::Pending
    }
}

impl crate::runtime::TcpStream for MockTcpStream {
    fn connect(address: SocketAddr) -> impl Future<Output = Option<Self>> + Send {
        pending()
    }
}

#[derive(Debug)]
pub struct MockTcpListener {}

impl TcpListener<MockTcpStream> for MockTcpListener {
    fn bind(address: SocketAddr) -> impl Future<Output = Option<Self>> {
        pending()
    }

    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<Option<MockTcpStream>> {
        Poll::Pending
    }
}

pub struct MockMetricsCounter {}

impl Counter for MockMetricsCounter {
    fn increment(&mut self, value: usize) {
        todo!();
    }
}

pub struct MockMetricsGauge {}

impl Gauge for MockMetricsGauge {
    fn increment(&mut self, value: usize) {}
    fn decrement(&mut self, value: usize) {}
}

pub struct MockMetricsHistogram {}

impl Histogram for MockMetricsHistogram {
    fn record(&mut self, record: f64) {}
}

#[derive(Debug, Clone)]
pub struct MockMetricsHandle {}

impl MetricsHandle for MockMetricsHandle {
    fn counter(&self, name: &'static str) -> impl Counter {
        MockMetricsCounter {}
    }

    fn gauge(&self, name: &'static str) -> impl Gauge {
        MockMetricsGauge {}
    }

    fn histogram(&self, name: &'static str) -> impl Histogram {
        MockMetricsHistogram {}
    }
}

pub struct MockJoinSet<T> {
    _futures: Vec<BoxFuture<'static, T>>,
}

impl<T: Send + 'static> JoinSet<T> for MockJoinSet<T> {
    fn is_empty(&self) -> bool {
        true
    }

    fn push<F>(&mut self, _future: F)
    where
        F: Future<Output = T> + Send + 'static,
        F::Output: Send,
    {
        drop(_future);
    }
}

impl<T: Send + 'static> Stream for MockJoinSet<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Pending
    }
}

#[derive(Debug, Clone)]
pub struct MockRuntime {}

impl Runtime for MockRuntime {
    type TcpStream = MockTcpStream;
    type TcpListener = MockTcpListener;
    type JoinSet<T: Send + 'static> = MockJoinSet<T>;
    type MetricsHandle = MockMetricsHandle;

    /// Spawn `future` in the background.
    fn spawn<F>(future: F)
    where
        F: Future + Send + 'static,
        F::Output: Send,
    {
        todo!();
    }

    /// Return duration since Unix epoch.
    fn time_since_epoch() -> Duration {
        todo!();
    }

    /// Return opaque type for generating random bytes.
    fn rng() -> impl RngCore + CryptoRng {
        rand_core::OsRng
    }

    /// Create new instance of a join set which contains a collection
    /// of futures that are polled together.
    ///
    /// For `tokio` this would be `tokio::task::join_set::JoinSet` and
    /// for `futures` this would be `future::stream::FuturesUnordered`
    fn join_set<T: Send + 'static>() -> Self::JoinSet<T> {
        todo!();
    }

    /// Register `metrics` and return handle for registering metrics.
    fn register_metrics(metrics: Vec<crate::runtime::MetricType>) -> Self::MetricsHandle {
        todo!();
    }

    /// Return future which blocks for `duration` before returning.
    fn delay(duration: Duration) -> BoxFuture<'static, ()> {
        todo!();
    }
}
