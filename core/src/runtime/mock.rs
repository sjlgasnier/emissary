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
    AsyncRead, AsyncWrite, Counter, Gauge, Histogram, Instant as InstantT, JoinSet, MetricsHandle,
    Runtime, TcpListener, TcpStream,
};

use futures::{future::BoxFuture, Stream};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use rand_core::{CryptoRng, RngCore};
use tokio::task;

use std::{
    borrow::Borrow,
    collections::HashMap,
    future::{pending, Future},
    marker::PhantomData,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::{Duration, Instant, SystemTime},
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

thread_local! {
    /// Counters and their values.
    static COUNTERS: Lazy<Arc<RwLock<HashMap<&'static str, usize>>>> = Lazy::new(|| Default::default());

    /// Gauges and their values.
    static GAUGES: Lazy<Arc<RwLock<HashMap<&'static str, usize>>>> = Lazy::new(|| Default::default());
}

pub struct MockMetricsCounter {
    name: &'static str,
}

impl Counter for MockMetricsCounter {
    fn increment(&mut self, value: usize) {
        COUNTERS.with(|v| {
            let mut inner = v.write();
            *inner.entry(self.name).or_default() += value;
        });
    }
}

pub struct MockMetricsGauge {
    name: &'static str,
}

impl Gauge for MockMetricsGauge {
    fn increment(&mut self, value: usize) {
        GAUGES.with(|v| {
            let mut inner = v.write();
            *inner.entry(self.name).or_default() += value;
        });
    }

    fn decrement(&mut self, value: usize) {
        GAUGES.with(|v| {
            let mut inner = v.write();
            *inner.entry(self.name).or_default() -= value;
        });
    }
}

pub struct MockMetricsHistogram {}

impl Histogram for MockMetricsHistogram {
    fn record(&mut self, record: f64) {}
}

#[derive(Debug, Clone)]
pub struct MockMetricsHandle {}

impl MetricsHandle for MockMetricsHandle {
    fn counter(&self, name: &'static str) -> impl Counter {
        MockMetricsCounter { name }
    }

    fn gauge(&self, name: &'static str) -> impl Gauge {
        MockMetricsGauge { name }
    }

    fn histogram(&self, name: &'static str) -> impl Histogram {
        MockMetricsHistogram {}
    }
}

pub struct MockJoinSet<T>(task::JoinSet<T>, Option<Waker>);

impl<T: Send + 'static> JoinSet<T> for MockJoinSet<T> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn push<F>(&mut self, future: F)
    where
        F: Future<Output = T> + Send + 'static,
        F::Output: Send,
    {
        let _ = self.0.spawn(future);
        self.1.as_mut().map(|waker| waker.wake_by_ref());
    }
}

impl<T: Send + 'static> Stream for MockJoinSet<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.0.poll_join_next(cx) {
            Poll::Pending | Poll::Ready(None) => {
                self.1 = Some(cx.waker().clone());
                Poll::Pending
            }
            Poll::Ready(Some(Err(_))) => Poll::Ready(None),
            Poll::Ready(Some(Ok(value))) => Poll::Ready(Some(value)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MockInstant(Instant);

impl MockInstant {
    /// Subtract `value` from inner `Instant`.
    pub fn subtract(mut self, value: Duration) -> Self {
        self.0 = self.0.checked_sub(value).unwrap();
        self
    }
}

impl InstantT for MockInstant {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockRuntime {}

impl MockRuntime {
    pub fn get_counter_value(name: &'static str) -> Option<usize> {
        COUNTERS.with(|v| v.read().get(name).copied())
    }

    pub fn get_gauge_value(name: &'static str) -> Option<usize> {
        GAUGES.with(|v| v.read().get(name).copied())
    }
}

impl Runtime for MockRuntime {
    type TcpStream = MockTcpStream;
    type TcpListener = MockTcpListener;
    type JoinSet<T: Send + 'static> = MockJoinSet<T>;
    type MetricsHandle = MockMetricsHandle;
    type Instant = MockInstant;

    /// Spawn `future` in the background.
    fn spawn<F>(future: F)
    where
        F: Future + Send + 'static,
        F::Output: Send,
    {
        tokio::spawn(future);
    }

    /// Return duration since Unix epoch.
    fn time_since_epoch() -> Duration {
        SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("to succeed")
    }

    /// Get current time.
    fn now() -> Self::Instant {
        MockInstant(Instant::now())
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
        MockJoinSet(task::JoinSet::<T>::new(), None)
    }

    /// Register `metrics` and return handle for registering metrics.
    fn register_metrics(metrics: Vec<crate::runtime::MetricType>) -> Self::MetricsHandle {
        MockMetricsHandle {}
    }

    /// Return future which blocks for `duration` before returning.
    fn delay(duration: Duration) -> impl Future<Output = ()> + Send {
        tokio::time::sleep(duration)
    }
}
