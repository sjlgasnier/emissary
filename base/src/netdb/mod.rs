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

use crate::{primitives::RouterInfo, transports::TransportService};

use futures::{FutureExt, StreamExt};

use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::netdb";

/// Network database (NetDB).
pub struct NetDb {
    /// Transport service.
    service: TransportService,
}

impl NetDb {
    /// Create new [`NetDb`].
    pub fn new(service: TransportService) -> Self {
        tracing::trace!(
            target: LOG_TARGET,
            "starting netdb",
        );

        Self { service }
    }

    fn on_connection_established(&mut self) -> crate::Result<()> {
        Ok(())
    }

    fn on_connection_close(&mut self) -> crate::Result<()> {
        Ok(())
    }

    fn on_message(&mut self, message: ()) -> crate::Result<()> {
        Ok(())
    }
}

impl Future for NetDb {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.service.poll_next_unpin(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Some(event)) => todo!("handle event"),
            Poll::Ready(None) => return Poll::Ready(()),
        }
    }
}
