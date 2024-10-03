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
    error::I2cpError,
    i2cp::session::I2cpSession,
    runtime::{JoinSet, Runtime, TcpListener},
    util::AsyncReadExt,
    Error,
};

use futures::StreamExt;

use core::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

mod session;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::i2cp";

/// I2CP protocol byte.
const I2CP_PROTOCOL_BYTE: u8 = 0x2a;

/// I2CP server
///
/// Listens to incoming I2CP streams and dispatches them to a separate event loop
/// after the I2CP protocol byte has been received.
pub struct I2cpServer<R: Runtime> {
    /// TCP listener.
    listener: R::TcpListener,

    /// Pending connections.
    pending_connections: R::JoinSet<crate::Result<R::TcpStream>>,
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

        Ok(Self {
            listener,
            pending_connections: R::join_set(),
        })
    }
}

impl<R: Runtime> Future for I2cpServer<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.listener.poll_accept(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => {
                    tracing::error!(
                        target: LOG_TARGET,
                        "ready `None` from i2cp server socket",
                    );

                    return Poll::Ready(());
                }
                Poll::Ready(Some(mut stream)) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        "incoming connection, read protocol byte",
                    );

                    // complete handshake for the i2cp client session in the background by polling
                    // the connection until the protocol byte is received and comparing it against
                    // the expected protocol byte
                    self.pending_connections.push(async move {
                        let mut protocol_byte = vec![0u8; 1];

                        stream.read_exact(&mut protocol_byte).await?;

                        if protocol_byte[0] != I2CP_PROTOCOL_BYTE {
                            return Err(Error::I2cp(I2cpError::InvalidProtocolByte(
                                protocol_byte[0],
                            )));
                        }

                        Ok(stream)
                    });
                }
            }
        }

        loop {
            match self.pending_connections.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => {
                    tracing::error!(
                        target: LOG_TARGET,
                        "read `None` from pending connections",
                    );
                    return Poll::Ready(());
                }
                Poll::Ready(Some(Err(error))) => tracing::warn!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to accept inbound i2cp connection",
                ),
                Poll::Ready(Some(Ok(stream))) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        "i2cp client session accepted",
                    );

                    R::spawn(I2cpSession::<R>::new(stream));
                }
            }
        }

        Poll::Pending
    }
}
