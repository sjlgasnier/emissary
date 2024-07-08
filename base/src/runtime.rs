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

use futures::{AsyncRead, AsyncWrite, Future};
use rand_core::{CryptoRng, RngCore};

use core::time::Duration;

pub trait TcpStream: AsyncRead + AsyncWrite + Unpin + Send + Sized {
    fn connect(address: &str) -> impl Future<Output = Option<Self>>;
    fn close(&mut self) -> impl Future<Output = ()>;
}

pub trait TcpListener<TcpStream>: Send + Sized {
    fn bind(address: &str) -> impl Future<Output = Option<Self>>;
    fn accept(&mut self) -> impl Future<Output = Option<TcpStream>>;
}

pub trait Runtime: Clone {
    type TcpStream: TcpStream;
    type TcpListener: TcpListener<Self::TcpStream>;

    fn spawn<F>(future: F)
    where
        F: Future + Send + 'static,
        F::Output: Send;

    /// Return duration since Unix epoch.
    fn time_since_epoch() -> Duration;

    /// Return opaque type for generating random bytes.
    fn rng() -> impl RngCore + CryptoRng;
}
