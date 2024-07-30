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

// TODO: documentation

use futures::{future::BoxFuture, Stream};
use rand_core::{CryptoRng, RngCore};

use alloc::{string::String, vec::Vec};
use core::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

#[cfg(test)]
pub mod mock;

pub trait AsyncRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<crate::Result<usize>>;
}

pub trait AsyncWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<crate::Result<usize>>;
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<crate::Result<()>>;
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<crate::Result<()>>;
}

pub trait TcpStream: AsyncRead + AsyncWrite + Unpin + Send + Sized + 'static {
    /// Establish connection to remote peer at `address`.
    fn connect(address: SocketAddr) -> impl Future<Output = Option<Self>> + Send;
}

pub trait TcpListener<TcpStream>: Unpin + Send + Sized + 'static {
    fn bind(address: SocketAddr) -> impl Future<Output = Option<Self>>;
    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<Option<TcpStream>>;
}

pub trait JoinSet<T>: Stream<Item = T> + Unpin {
    /// Returns whether the `JoinSet` is empty.
    fn is_empty(&self) -> bool;

    /// Pushes `future` to `JoinSet`.
    fn push<F>(&mut self, future: F)
    where
        F: Future<Output = T> + Send + 'static,
        F::Output: Send;
}

pub trait Counter {
    fn increment(&mut self, value: usize);
}

pub trait Gauge {
    fn increment(&mut self, value: usize);
    fn decrement(&mut self, value: usize);
}

pub trait Histogram {
    fn record(&mut self, record: f64);
}

pub trait MetricsHandle: Clone + Send + Sync + Unpin {
    fn counter(&self, name: &'static str) -> impl Counter;
    fn gauge(&self, name: &'static str) -> impl Gauge;
    fn histogram(&self, name: &'static str) -> impl Histogram;
}

/// Metric type.
pub enum MetricType {
    /// Counter.
    Counter {
        /// Counter name.
        name: &'static str,

        /// Counter description.
        description: &'static str,
    },

    /// Gauge.
    Gauge {
        /// Gauge name.
        name: &'static str,

        /// Gauge description.
        description: &'static str,
    },

    /// Histogram
    Histogram {
        /// Histogram name.
        name: &'static str,

        /// Histogram description.
        description: &'static str,

        /// Buckets.
        buckets: Vec<f64>,
    },
}

pub trait Runtime: Clone + Unpin + Send + 'static {
    type TcpStream: TcpStream;
    type TcpListener: TcpListener<Self::TcpStream>;
    type JoinSet<T: Send + 'static>: JoinSet<T>;
    type MetricsHandle: MetricsHandle;

    /// Spawn `future` in the background.
    fn spawn<F>(future: F)
    where
        F: Future + Send + 'static,
        F::Output: Send;

    /// Return duration since Unix epoch.
    fn time_since_epoch() -> Duration;

    /// Return opaque type for generating random bytes.
    fn rng() -> impl RngCore + CryptoRng;

    /// Create new instance of a join set which contains a collection
    /// of futures that are polled together.
    ///
    /// For `tokio` this would be `tokio::task::join_set::JoinSet` and
    /// for `futures` this would be `future::stream::FuturesUnordered`
    fn join_set<T: Send + 'static>() -> Self::JoinSet<T>;

    /// Register `metrics` and return handle for registering metrics.
    fn register_metrics(metrics: Vec<MetricType>) -> Self::MetricsHandle;

    /// Return future which blocks for `duration` before returning.
    fn delay(duration: Duration) -> BoxFuture<'static, ()>;
}
