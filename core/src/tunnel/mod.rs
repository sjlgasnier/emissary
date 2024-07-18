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
    crypto::{base64_encode, EphemeralPublicKey, StaticPrivateKey},
    i2np::{HopRole, I2NpMessage, MessageType, RawI2npMessage, TunnelMessage},
    primitives::{RouterId, RouterInfo},
    runtime::Runtime,
    subsystem::SubsystemEvent,
    transports::TransportService,
    tunnel::noise::Noise,
};

use futures::{FutureExt, StreamExt};

use alloc::{string::String, vec::Vec};
use core::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use hashbrown::HashSet;

mod noise;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel-manager";

/// Tunnel manager.
pub struct TunnelManager<R: Runtime> {
    /// Transport service.
    service: TransportService,

    /// Noise key context.
    noise: Noise,

    /// Truncated router hash.
    truncated_hash: Vec<u8>,

    /// Connected routers.
    routers: HashSet<RouterId>,

    /// Marker for `Runtime`
    _marker: PhantomData<R>,
}

impl<R: Runtime> TunnelManager<R> {
    /// Create new [`TunnelManager`].
    pub fn new(
        service: TransportService,
        local_key: StaticPrivateKey,
        truncated_hash: Vec<u8>,
    ) -> Self {
        tracing::trace!(
            target: LOG_TARGET,
            "starting tunnel manager",
        );

        Self {
            service,
            truncated_hash,
            noise: Noise::new(local_key),
            routers: HashSet::new(),
            _marker: Default::default(),
        }
    }

    fn on_connection_established(&mut self, router: RouterId) {
        tracing::debug!(
            target: LOG_TARGET,
            %router,
            "connection established",
        );
        self.routers.insert(router);
    }

    fn on_connection_closed(&mut self, router: RouterId) {
        tracing::debug!(
            target: LOG_TARGET,
            %router,
            "connection closed",
        );
        self.routers.remove(&router);
    }

    // TODO: no unwraps
    fn on_message(&mut self, message: RawI2npMessage) {
        let RawI2npMessage {
            message_type,
            message_id,
            expiration,
            payload,
        } = message;

        match message_type {
            MessageType::VariableTunnelBuild => {
                // TODO: this should return destination?
                let (payload, hop, message_id, message_type) =
                    self.noise.create_tunnel_hop(&self.truncated_hash, payload).unwrap();

                let msg = RawI2npMessage {
                    message_type,
                    message_id,
                    expiration: (R::time_since_epoch() + Duration::from_secs(5 * 60)).as_secs()
                        as u32,
                    payload,
                }
                .serialize();

                if self.routers.contains(&hop) {
                    self.service.send(&hop, msg);
                } else {
                    tracing::warn!(target: LOG_TARGET, "router message to self");

                    // let message = RawI2npMessage::parse(&msg).unwrap();
                    // self.on_message(message);
                }
            }
            MessageType::ShortTunnelBuild => {
                let (payload, hop, message_id, message_type) =
                    self.noise.create_short_tunnel_hop(&self.truncated_hash, payload).unwrap();

                // tracing::info!("message id = {message_id}, next message id {_message_id}");

                let msg = RawI2npMessage {
                    message_type,
                    message_id,
                    expiration: (R::time_since_epoch() + Duration::from_secs(5 * 60)).as_secs()
                        as u32,
                    payload,
                }
                .serialize();

                if self.routers.contains(&hop) {
                    self.service.send(&hop, msg);
                } else {
                    tracing::warn!(target: LOG_TARGET, "router message to self");

                    // let message = RawI2npMessage::parse(&msg).unwrap();
                    // self.on_message(message);
                }
            }
            MessageType::TunnelData => {
                let Some((data, hop)) = self.noise.handle_tunnel_data(payload) else {
                    return;
                };
                // let (data, hop) = self.noise.handle_tunnel_data(payload);

                let msg = RawI2npMessage {
                    message_type,
                    message_id,
                    expiration: (R::time_since_epoch() + Duration::from_secs(5 * 60)).as_secs()
                        as u32,
                    payload: data,
                }
                .serialize();

                if self.routers.contains(&hop) {
                    self.service.send(&hop, msg);
                } else {
                    tracing::warn!(target: LOG_TARGET, "router message to self");

                    // let message = RawI2npMessage::parse(&msg).unwrap();
                    // self.on_message(message);
                }
            }
            message => tracing::warn!(
                target: LOG_TARGET,
                ?message,
                "unhandled message",
            ),
        }
    }
}

impl<R: Runtime> Future for TunnelManager<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.service.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(SubsystemEvent::ConnectionEstablished { router })) =>
                    self.on_connection_established(router),
                Poll::Ready(Some(SubsystemEvent::ConnectionClosed { router })) =>
                    self.on_connection_closed(router),
                Poll::Ready(Some(SubsystemEvent::I2Np { messages })) =>
                    messages.into_iter().for_each(|message| self.on_message(message)),
                Poll::Ready(Some(SubsystemEvent::Dummy)) => unreachable!(),
                Poll::Ready(None) => return Poll::Ready(()),
            }
        }
    }
}
