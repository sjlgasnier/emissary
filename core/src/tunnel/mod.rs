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
    i2np::{
        HopRole, I2NpMessage, MessageType, RawI2NpMessageBuilder, RawI2npMessage, TunnelMessage,
        I2NP_SHORT, I2NP_STANDARD,
    },
    primitives::{RouterId, RouterInfo},
    runtime::Runtime,
    subsystem::SubsystemEvent,
    transports::TransportService,
    tunnel::noise::Noise,
};

use futures::{FutureExt, StreamExt};
use hashbrown::HashMap;

use alloc::{string::String, vec, vec::Vec};
use core::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

mod noise;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel";

/// Router state.
#[derive(Debug)]
pub enum RouterState {
    /// Router is connected.
    Connected,

    /// Router is being dialed.
    Dialing {
        /// Pending messages.
        pending_messages: Vec<Vec<u8>>,
    },
}

/// Tunnel manager.
pub struct TunnelManager<R: Runtime> {
    /// Local router ID.
    local_router_id: RouterId,

    /// Noise key context.
    noise: Noise,

    /// Connected routers.
    routers: HashMap<RouterId, RouterState>,

    /// Transport service.
    service: TransportService,

    /// Truncated router hash.
    truncated_hash: Vec<u8>,

    /// Marker for `Runtime`
    _marker: PhantomData<R>,
}

impl<R: Runtime> TunnelManager<R> {
    /// Create new [`TunnelManager`].
    pub fn new(
        service: TransportService,
        local_key: StaticPrivateKey,
        truncated_hash: Vec<u8>,
        local_router_id: RouterId,
    ) -> Self {
        tracing::trace!(
            target: LOG_TARGET,
            "starting tunnel manager",
        );

        Self {
            local_router_id,
            noise: Noise::new(local_key),
            routers: HashMap::new(),
            service,
            truncated_hash,
            _marker: Default::default(),
        }
    }

    fn on_connection_established(&mut self, router: RouterId) {
        tracing::debug!(
            target: LOG_TARGET,
            %router,
            "connection established",
        );

        match self.routers.remove(&router) {
            Some(RouterState::Dialing { pending_messages }) if !pending_messages.is_empty() => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?router,
                    "router with pending messages connected",
                );

                for message in pending_messages {
                    self.service.send(&router, message);
                }
            }
            Some(RouterState::Dialing { .. }) | None => {}
            state => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?router,
                    ?state,
                    "invalid state for connected router",
                );
                debug_assert!(false);
            }
        }

        self.routers.insert(router.clone(), RouterState::Connected);
    }

    fn on_connection_closed(&mut self, router: &RouterId) {
        tracing::debug!(
            target: LOG_TARGET,
            %router,
            "connection closed",
        );
        self.routers.remove(router);
    }

    fn on_connection_failure(&mut self, router: &RouterId) {
        tracing::debug!(
            target: LOG_TARGET,
            %router,
            "failed to open connection to router",
        );

        if self.routers.remove(router).is_none() {
            tracing::warn!(
                target: LOG_TARGET,
                "connection failure for unknown router",
            );
            debug_assert!(false);
        }
    }

    fn send_message(&mut self, router: &RouterId, message: Vec<u8>) {
        match self.routers.get_mut(router) {
            Some(RouterState::Connected) => self.service.send(&router, message),
            Some(RouterState::Dialing {
                ref mut pending_messages,
            }) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?router,
                    "router is being dialed, buffer message",
                );
                pending_messages.push(message);
            }
            None => match router == &self.local_router_id {
                true => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "router message to self",
                    );
                    // todo!();
                    // let message = RawI2npMessage::parse::<I2NP_STANDARD>(&message).unwrap();
                    // self.on_message(message);
                }
                false => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?router,
                        "start dialing router",
                    );
                    // todo!();

                    // self.service.connect(&router);
                    // self.routers.insert(
                    //     router.clone(),
                    //     RouterState::Dialing {
                    //         pending_messages: vec![message],
                    //     },
                    // );
                }
            },
        }
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

                let msg = RawI2NpMessageBuilder::short()
                    .with_message_type(message_type)
                    .with_message_id(message_id)
                    .with_expiration(
                        (R::time_since_epoch() + Duration::from_secs(5 * 60)).as_secs(),
                    )
                    .with_payload(payload)
                    .serialize();

                // if hop == self.local_router_id {
                //     tracing::warn!(
                //         target: LOG_TARGET,
                //         "router message to self",
                //     );

                //     let message = RawI2npMessage::parse::<I2NP_SHORT>(&msg).unwrap();
                //     self.on_message(message);
                // } else {
                self.send_message(&hop, msg);
                // }
            }
            MessageType::ShortTunnelBuild => {
                let (payload, hop, message_id, message_type) =
                    self.noise.create_short_tunnel_hop(&self.truncated_hash, payload).unwrap();

                let msg = RawI2NpMessageBuilder::short()
                    .with_message_type(message_type)
                    .with_message_id(message_id)
                    .with_expiration(
                        (R::time_since_epoch() + Duration::from_secs(5 * 60)).as_secs(),
                    )
                    .with_payload(payload)
                    .serialize();

                // if hop == self.local_router_id {
                //     tracing::warn!(
                //         target: LOG_TARGET,
                //         "router message to self",
                //     );

                //     let message = RawI2npMessage::parse::<I2NP_SHORT>(&msg).unwrap();
                //     self.on_message(message);
                // } else {
                self.send_message(&hop, msg);
                // }
            }
            MessageType::TunnelData => {
                let Some((message, hop)) = self.noise.handle_tunnel_data(
                    &self.truncated_hash,
                    message.expiration,
                    payload,
                ) else {
                    return;
                };

                // if hop == self.local_router_id {
                //     tracing::warn!(
                //         target: LOG_TARGET,
                //         "router message to self",
                //     );

                //     let message = RawI2npMessage::parse::<I2NP_SHORT>(&msg).unwrap();
                //     self.on_message(message);
                // } else {
                self.send_message(&hop, message);
                // }
            }
            MessageType::Garlic => {
                let messages =
                    self.noise.handle_garlic_message(&self.truncated_hash, message_id, payload);

                for (payload, hop, message_id, message_type) in messages {
                    let msg = RawI2NpMessageBuilder::short()
                        .with_message_type(message_type)
                        .with_message_id(message_id)
                        .with_expiration(
                            (R::time_since_epoch() + Duration::from_secs(5 * 60)).as_secs(),
                        )
                        .with_payload(payload)
                        .serialize();

                    self.send_message(&hop, msg);
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
                    self.on_connection_closed(&router),
                Poll::Ready(Some(SubsystemEvent::I2Np { messages })) =>
                    messages.into_iter().for_each(|message| self.on_message(message)),
                Poll::Ready(Some(SubsystemEvent::ConnectionFailure { router })) =>
                    self.on_connection_failure(&router),
                Poll::Ready(Some(SubsystemEvent::Dummy)) => unreachable!(),
                Poll::Ready(None) => return Poll::Ready(()),
            }
        }
    }
}
