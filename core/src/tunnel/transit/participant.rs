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
    crypto::aes::{cbc, ecb},
    error::{RejectionReason, TunnelError},
    i2np::{
        tunnel::{data::EncryptedTunnelData, gateway::TunnelGateway},
        HopRole, Message, MessageBuilder, MessageType,
    },
    primitives::{RouterId, TunnelId},
    runtime::Runtime,
    tunnel::{
        noise::TunnelKeys, routing_table::RoutingTable, transit::TransitTunnel, TUNNEL_EXPIRATION,
    },
    Error,
};

use bytes::{BufMut, BytesMut};
use futures::{future::BoxFuture, FutureExt};
use rand_core::RngCore;

use alloc::{boxed::Box, vec, vec::Vec};
use core::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use thingbuf::mpsc::Receiver;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::transit::participant";

/// Tunnel participant.
///
/// Only accepts and handles `TunnelData` messages,
/// all other message types are rejected as invalid.
pub struct Participant<R: Runtime> {
    /// Tunnel expiration timer.
    expiration_timer: BoxFuture<'static, ()>,

    /// RX channel for receiving messages.
    message_rx: Receiver<Message>,

    /// Metrics handle.
    metrics_handle: R::MetricsHandle,

    /// Next router ID.
    next_router: RouterId,

    /// Next tunnel ID.
    next_tunnel_id: TunnelId,

    /// Routing table.
    routing_table: RoutingTable,

    /// Tunnel ID.
    tunnel_id: TunnelId,

    /// Tunnel keys.
    tunnel_keys: TunnelKeys,
}

impl<R: Runtime> Participant<R> {
    /// Handle tunnel data.
    ///
    /// Return `RouterId` of the next hop and the message that needs to be forwarded
    /// to them on success.
    fn handle_tunnel_data(
        &mut self,
        tunnel_data: &EncryptedTunnelData,
    ) -> crate::Result<(RouterId, Vec<u8>)> {
        tracing::trace!(
            target: LOG_TARGET,
            tunnel_id = %self.tunnel_id,
            "participant tunnel data",
        );

        // decrypt record and create new `TunnelData` message
        let (ciphertext, iv) = self.tunnel_keys.decrypt_record(tunnel_data);

        // tunnel id + iv key + tunnel data payload length
        let mut out = BytesMut::with_capacity(4 + 16 + ciphertext.len());

        out.put_u32(self.next_tunnel_id.into());
        out.put_slice(&iv);
        out.put_slice(&ciphertext);

        let message = MessageBuilder::short()
            .with_message_type(MessageType::TunnelData)
            .with_message_id(R::rng().next_u32())
            .with_expiration((R::time_since_epoch() + Duration::from_secs(8)).as_secs())
            .with_payload(&out)
            .build();

        return Ok((self.next_router.clone(), message));
    }
}

impl<R: Runtime> TransitTunnel<R> for Participant<R> {
    fn new(
        tunnel_id: TunnelId,
        next_tunnel_id: TunnelId,
        next_router: RouterId,
        tunnel_keys: TunnelKeys,
        routing_table: RoutingTable,
        metrics_handle: R::MetricsHandle,
        message_rx: Receiver<Message>,
    ) -> Self {
        Participant {
            expiration_timer: Box::pin(R::delay(TUNNEL_EXPIRATION)),
            message_rx,
            metrics_handle,
            next_router,
            next_tunnel_id,
            routing_table,
            tunnel_id,
            tunnel_keys,
        }
    }

    fn role(&self) -> HopRole {
        HopRole::Participant
    }
}

impl<R: Runtime> Future for Participant<R> {
    type Output = TunnelId;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        while let Poll::Ready(event) = self.message_rx.poll_recv(cx) {
            match event {
                None => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        tunnel_id = %self.tunnel_id,
                        "message channel closed",
                    );
                    return Poll::Ready(self.tunnel_id);
                }
                Some(message) => match message.message_type {
                    MessageType::TunnelData => match EncryptedTunnelData::parse(&message.payload) {
                        Some(message) => match self.handle_tunnel_data(&message) {
                            Ok((router, message)) => {
                                if let Err(error) = self.routing_table.send_message(router, message)
                                {
                                    tracing::error!(
                                        target: LOG_TARGET,
                                        tunnel_id = %self.tunnel_id,
                                        ?error,
                                        "failed to send message",
                                    )
                                }
                            }
                            Err(error) => tracing::warn!(
                                target: LOG_TARGET,
                                tunnel_id = %self.tunnel_id,
                                ?error,
                                "failed to handle tunnel data",
                            ),
                        },
                        None => todo!(),
                    },
                    message_type => tracing::warn!(
                        target: LOG_TARGET,
                        tunnel_id = %self.tunnel_id,
                        ?message_type,
                        "unsupported message",
                    ),
                },
            }
        }

        if let Poll::Ready(_) = self.expiration_timer.poll_unpin(cx) {
            return Poll::Ready(self.tunnel_id);
        }

        Poll::Pending
    }
}
