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

//! I2CP implementation.
//!
//! https://geti2p.net/en/docs/protocol/i2cp

use crate::{
    runtime::{Runtime, TcpListener},
    Error,
};

use core::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::i2cp";

/// I2CP server
pub struct I2cpServer<R: Runtime> {
    /// TCP listener.
    listener: R::TcpListener,
}

impl<R: Runtime> I2cpServer<R> {
    /// Create new [`I2cpServer`].
    pub async fn new(port: u16) -> crate::Result<Self> {
        tracing::info!(
            target: LOG_TARGET,
            ?port,
            "starting i2cp server",
        );

        let address = SocketAddr::new("127.0.0.1".parse::<IpAddr>().expect("valid address"), port);
        let listener = R::TcpListener::bind(address)
            .await
            .ok_or(Error::IoError(String::from("failed to bind i2cp socket")))?;

        Ok(Self { listener })
    }
}

impl<R: Runtime> Future for I2cpServer<R> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}
