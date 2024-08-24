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

use crate::{
    error::ChannelError,
    i2np::Message,
    primitives::TunnelId,
    runtime::{JoinSet, Runtime},
    tunnel::{
        hop::{pending::PendingTunnel, Tunnel},
        pool::TUNNEL_BUILD_EXPIRATION,
    },
    Error,
};

use futures::{
    future::{select, Either},
    Stream, StreamExt,
};
use futures_channel::oneshot;

use alloc::boxed::Box;
use core::{
    pin::Pin,
    task::{Context, Poll},
};

/// Tunnel build listener.
pub struct TunnelBuildListener<R: Runtime, T: Tunnel + 'static> {
    /// Pending tunnels.
    pending: R::JoinSet<(TunnelId, crate::Result<T>)>,
}

impl<R: Runtime, T: Tunnel> TunnelBuildListener<R, T> {
    /// Create new [`TunnelBuildListener`].
    pub fn new() -> Self {
        Self {
            pending: R::join_set(),
        }
    }

    /// Get the number of pending tunnels.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Add pending tunnel into set of tunnels that are being waited.
    pub fn add_pending_tunnel(
        &mut self,
        tunnel: PendingTunnel<T>,
        message_rx: oneshot::Receiver<Message>,
    ) {
        self.pending.push(async move {
            match select(message_rx, Box::pin(R::delay(TUNNEL_BUILD_EXPIRATION))).await {
                Either::Right((_, _)) => (*tunnel.tunnel_id(), Err(Error::Timeout)),
                Either::Left((Err(_), _)) => (
                    *tunnel.tunnel_id(),
                    Err(Error::Channel(ChannelError::Closed)),
                ),
                Either::Left((Ok(message), _)) =>
                    (*tunnel.tunnel_id(), tunnel.try_build_tunnel::<R>(message)),
            }
        });
    }
}

impl<R: Runtime, T: Tunnel> Stream for TunnelBuildListener<R, T> {
    type Item = (TunnelId, crate::Result<T>);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.pending.poll_next_unpin(cx)
    }
}

#[cfg(test)]
mod tests {}
