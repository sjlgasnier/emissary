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
    crypto::{SigningPrivateKey, StaticPrivateKey},
    primitives::RouterInfo,
    runtime::Runtime,
    transports::ntcp2::Ntcp2Transport,
};

use futures::{Stream, StreamExt};

use core::{
    pin::Pin,
    task::{Context, Poll},
};

mod ntcp2;
mod ssu2;

#[derive(Debug)]
pub enum TransportEvent {
    /// Connection successfully established to remote peer.
    ConnectionEstablished {
        /// `RouterInfo` for the connected peer.
        router: RouterInfo,
    },
    ConnectionClosed {},
    ConnectionOpened {},
    ConnectionFailure {},
}

pub trait Transport: Stream + Unpin {
    /// Dial remote peer.
    //
    // TODO: how to signal preference for transport?
    fn dial(&mut self, router: RouterInfo) -> crate::Result<()>;
}

/// Transport manager.
pub struct TransportManager<R: Runtime> {
    ntcp2: Ntcp2Transport<R>,
}

impl<R: Runtime> TransportManager<R> {
    /// Create new [`TransportManager`].
    pub async fn new(
        runtime: R,
        local_key: StaticPrivateKey,
        local_signing_key: SigningPrivateKey,
        local_router_info: RouterInfo,
    ) -> crate::Result<Self> {
        Ok(Self {
            ntcp2: Ntcp2Transport::<R>::new(
                runtime,
                local_key,
                local_signing_key,
                local_router_info,
            )
            .await?,
        })
    }
}

impl<R: Runtime> Stream for TransportManager<R> {
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.ntcp2.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(event) => {
                    panic!("zzz");
                }
            }
        }
    }
}
