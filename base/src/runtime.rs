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

use futures::{AsyncRead, AsyncWrite, Future, Stream};
use rand_core::{CryptoRng, RngCore};

use core::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

pub trait TcpStream: AsyncRead + AsyncWrite + Unpin + Send + Sized + 'static {
    fn connect(address: &str) -> impl Future<Output = Option<Self>>;
    fn close(&mut self) -> impl Future<Output = ()>;
}

pub trait TcpListener<TcpStream>: Unpin + Send + Sized + 'static {
    fn bind(address: &str) -> impl Future<Output = Option<Self>>;
    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<Option<TcpStream>>;
}

pub trait JoinSet<T>: Unpin + Stream<Item = T> {
    /// Returns whether the `JoinSet` is empty.
    fn is_empty(&self) -> bool;

    /// Pushes `future` to `JoinSet`.
    fn push<F>(&mut self, future: F)
    where
        F: Future<Output = T> + Send + 'static,
        F::Output: Send;
}

pub trait Runtime: Clone + Unpin + Send + 'static {
    type TcpStream: TcpStream;
    type TcpListener: TcpListener<Self::TcpStream>;
    type JoinSet<T: Send + 'static>: JoinSet<T>;

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
}
