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
    crypto::base64_encode,
    crypto::{SigningPrivateKey, StaticPrivateKey},
    primitives::RouterInfo,
    runtime::Runtime,
    transports::TransportManager,
    Config,
};

use futures::{Stream, StreamExt};

use alloc::vec::Vec;
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::router";

#[derive(Debug)]
pub enum RouterEvent {}

/// Router.
pub struct Router<R: Runtime> {
    /// Runtime used by the router.
    runtime: R,

    /// Transport manager
    ///
    /// Polls both NTCP2 and SSU2 transports.
    transport_manager: TransportManager<R>,
}

impl<R: Runtime> Router<R> {
    /// Create new [`Router`].
    pub async fn new(runtime: R, config: Config, router: Vec<u8>) -> crate::Result<Self> {
        tracing::debug!(target: LOG_TARGET, "start emissary");

        // let router = RouterInfo::from_bytes(router).unwrap();
        let now = R::time_since_epoch().as_millis() as u64;
        let local_key = StaticPrivateKey::from(config.static_key.clone());
        let test = config.signing_key.clone();
        let local_signing_key = SigningPrivateKey::new(&test).unwrap();
        // let local_info = RouterInfo::new(now, config).serialize(key);
        let local_router_info = RouterInfo::new(now, config);
        // let local_router_hash = local_info.identity().hash().to_vec();
        // let local_info = local_info.serialize(&key);

        // tracing::info!(%local_info);
        // tracing::info!(hash = %base64_encode(local_info.identity().hash()));

        // Ok(local_info.serialize(key))

        // todo!();

        // let ntcp2_listener =
        //     Ntcp2Listener::<R>::new(runtime.clone(), router, local_info, local_router_hash, ss)
        //         .await?;

        // todo!();

        let transport_manager = TransportManager::new(
            runtime.clone(),
            local_key,
            local_signing_key,
            local_router_info,
        )
        .await?;

        Ok(Self {
            runtime,
            transport_manager,
        })
    }
}

impl<R: Runtime> Future for Router<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        tracing::trace!("poll transport manager");

        loop {
            tracing::info!("polling again");

            match self.transport_manager.poll_next_unpin(cx) {
                Poll::Ready(None) => {
                    tracing::error!(" got poll ready none");
                    return Poll::Ready(());
                }
                Poll::Ready(Some(event)) => {
                    tracing::error!("got event:");
                }
                Poll::Pending => break,
            }
        }

        tracing::error!("nothing to do, return");

        Poll::Pending
    }
}
