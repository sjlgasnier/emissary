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

use emissary::runtime::{
    AsyncRead, AsyncWrite, Counter, Gauge, Histogram, JoinSet, MetricType, MetricsHandle, Runtime,
    TcpListener, TcpStream,
};
use futures::{AsyncRead as _, AsyncWrite as _, Stream};
use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};
use rand_core::{CryptoRng, RngCore};
use tokio::{net, task};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use std::{
    future::Future,
    net::SocketAddr,
    pin::{pin, Pin},
    task::{Context, Poll, Waker},
    time::{Duration, SystemTime},
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
    ) -> Poll<emissary::Result<usize>> {
        let pinned = pin!(&mut self.0);

        match futures::ready!(pinned.poll_read(cx, buf)) {
            Ok(nread) => Poll::Ready(Ok(nread)),
            Err(error) => Poll::Ready(Err(emissary::Error::IoError(error.to_string()))),
        }
    }
}

impl AsyncWrite for TokioTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<emissary::Result<usize>> {
        let pinned = pin!(&mut self.0);

        match futures::ready!(pinned.poll_write(cx, buf)) {
            Ok(nwritten) => Poll::Ready(Ok(nwritten)),
            Err(error) => Poll::Ready(Err(emissary::Error::IoError(error.to_string()))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<emissary::Result<()>> {
        let pinned = pin!(&mut self.0);

        match futures::ready!(pinned.poll_flush(cx)) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(error) => Poll::Ready(Err(emissary::Error::IoError(error.to_string()))),
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<emissary::Result<()>> {
        let pinned = pin!(&mut self.0);

        match futures::ready!(pinned.poll_close(cx)) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(error) => Poll::Ready(Err(emissary::Error::IoError(error.to_string()))),
        }
    }
}

impl TcpStream for TokioTcpStream {
    async fn connect(address: SocketAddr) -> Option<Self> {
        net::TcpStream::connect(address)
            .await
            .map_err(|error| {
                tracing::debug!("error: {error:?}");
                ()
            })
            .ok()
            .map(|stream| Self::new(stream))
    }
}

pub struct TokioTcpListener(net::TcpListener);

impl TcpListener<TokioTcpStream> for TokioTcpListener {
    // TODO: can be made sync with `socket2`
    async fn bind(address: SocketAddr) -> Option<Self> {
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

pub struct TokioJoinSet<T>(task::JoinSet<T>, Option<Waker>);

impl<T: Send + 'static> JoinSet<T> for TokioJoinSet<T> {
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

impl<T: Send + 'static> Stream for TokioJoinSet<T> {
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

#[derive(Clone)]
struct TokioMetricsCounter(&'static str);

impl Counter for TokioMetricsCounter {
    fn increment(&mut self, value: usize) {
        counter!(self.0).increment(value as u64);
    }
}

#[derive(Clone)]
struct TokioMetricsGauge(&'static str);

impl Gauge for TokioMetricsGauge {
    fn increment(&mut self, value: usize) {
        gauge!(self.0).increment(value as f64);
    }

    fn decrement(&mut self, value: usize) {
        gauge!(self.0).decrement(value as f64);
    }
}

#[derive(Clone)]
struct TokioMetricsHistogram(&'static str);

impl Histogram for TokioMetricsHistogram {
    fn record(&mut self, record: f64) {
        histogram!(self.0).record(record);
    }
}

#[derive(Clone)]
pub struct TokioMetricsHandle;

impl MetricsHandle for TokioMetricsHandle {
    fn counter(&self, name: &'static str) -> impl Counter {
        TokioMetricsCounter(name)
    }

    fn gauge(&self, name: &'static str) -> impl Gauge {
        TokioMetricsGauge(name)
    }

    fn histogram(&self, name: &'static str) -> impl Histogram {
        TokioMetricsHistogram(name)
    }
}

impl Runtime for TokioRuntime {
    type TcpStream = TokioTcpStream;
    type TcpListener = TokioTcpListener;
    type JoinSet<T: Send + 'static> = TokioJoinSet<T>;
    type MetricsHandle = TokioMetricsHandle;

    fn spawn<F>(future: F)
    where
        F: Future + Send + 'static,
        F::Output: Send,
    {
        tokio::spawn(future);
    }

    fn time_since_epoch() -> Duration {
        SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("to succeed")
    }

    fn rng() -> impl RngCore + CryptoRng {
        rand_core::OsRng
    }

    fn join_set<T: Send + 'static>() -> Self::JoinSet<T> {
        TokioJoinSet(task::JoinSet::<T>::new(), None)
    }

    fn register_metrics(metrics: Vec<MetricType>) -> Self::MetricsHandle {
        let builder = PrometheusBuilder::new()
            .with_http_listener("127.0.0.1:12842".parse::<SocketAddr>().expect(""));

        metrics
            .into_iter()
            .fold(builder, |builder, metric| match metric {
                MetricType::Counter { name, description } => {
                    describe_counter!(name, description);
                    builder
                }
                MetricType::Gauge { name, description } => {
                    describe_gauge!(name, description);
                    builder
                }
                MetricType::Histogram {
                    name,
                    description,
                    buckets,
                } => {
                    describe_histogram!(name, description);
                    builder
                        .set_buckets_for_metric(Matcher::Full(name.to_string()), &buckets)
                        .expect("to succeed")
                }
            })
            .install()
            .expect("to succeed");

        TokioMetricsHandle {}
    }

    fn delay(duration: Duration) -> impl Future<Output = ()> + Send {
        tokio::time::sleep(duration)
    }
}
