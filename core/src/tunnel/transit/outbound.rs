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
    crypto::{
        aes::{cbc, ecb},
        sha256::Sha256,
    },
    error::{RejectionReason, TunnelError},
    i2np::{
        tunnel::{
            data::{DeliveryInstructions, EncryptedTunnelData, MessageKind, TunnelData},
            gateway::TunnelGateway,
        },
        HopRole, Message, MessageBuilder, MessageType,
    },
    primitives::{MessageId, RouterId, TunnelId},
    runtime::Runtime,
    tunnel::{
        fragment::{FragmentHandler, OwnedDeliveryInstructions},
        noise::TunnelKeys,
        routing_table::RoutingTable,
        transit::TransitTunnel,
        TUNNEL_EXPIRATION,
    },
    Error,
};

use futures::{future::BoxFuture, FutureExt};
use rand_core::RngCore;

use alloc::{boxed::Box, vec::Vec};
use core::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use thingbuf::mpsc::Receiver;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::transit::obep";

/// Outbound endpoint.
pub struct OutboundEndpoint<R: Runtime> {
    /// Tunnel expiration timer.
    expiration_timer: BoxFuture<'static, ()>,

    /// Fragment handler.
    fragment: FragmentHandler,

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

impl<R: Runtime> OutboundEndpoint<R> {
    /// Find paylod start by locating the 0x00 byte at the end of the padding section and verify
    /// the checksum of the message before returning the index where the payload section starts.
    ///
    /// https://geti2p.net/spec/tunnel-message#tunnel-message-decrypted
    fn find_payload_start(&self, ciphertext: &[u8], iv: &[u8]) -> crate::Result<usize> {
        let padding_end =
            ciphertext[4..].iter().enumerate().find(|(_, byte)| byte == &&0x0).ok_or_else(
                || {
                    tracing::warn!(
                        target: LOG_TARGET,
                        tunnel_id = %self.tunnel_id,
                        "decrypted tunnel data doesn't contain zero byte",
                    );

                    Error::Tunnel(TunnelError::InvalidMessage)
                },
            )?;
        let checksum = Sha256::new()
            .update(&ciphertext[4 + padding_end.0 + 1..])
            .update(&iv)
            .finalize();

        if ciphertext[..4] != checksum[..4] {
            tracing::warn!(
                target: LOG_TARGET,
                tunnel_id = %self.tunnel_id,
                checksum = ?ciphertext[..4],
                calculated = ?checksum[..4],
                "tunnel data checksum mismatch",
            );

            return Err(Error::Tunnel(TunnelError::MessageRejected(
                RejectionReason::InvalidChecksum,
            )));
        }

        // neither checksum (+4) nor zero byte (+1) are part of the checksum
        let payload_start = padding_end.0 + 1 + 4;

        if payload_start >= ciphertext.len() {
            tracing::warn!(
                target: LOG_TARGET,
                tunnel_id = %self.tunnel_id,
                "decrypted tunnel data doesn't contain zero byte",
            );

            return Err(Error::Tunnel(TunnelError::InvalidMessage));
        }

        Ok(payload_start)
    }

    /// Handle tunnel data.
    ///
    /// Return `RouterId` of the next hop and the message that needs to be forwarded
    /// to them on success.
    fn handle_tunnel_data(
        &mut self,
        tunnel_data: &EncryptedTunnelData,
    ) -> crate::Result<impl Iterator<Item = (RouterId, Vec<u8>)>> {
        tracing::trace!(
            target: LOG_TARGET,
            tunnel_id = %self.tunnel_id,
            "outbound endpoint tunnel data",
        );

        // decrypt the tunnel data record into plaintext,
        // find where the payload starts and verify the checksum
        let (ciphertext, iv) = self.tunnel_keys.decrypt_record(tunnel_data);
        let payload_start = self.find_payload_start(&ciphertext, &iv)?;

        let our_message = ciphertext[payload_start..].to_vec();
        let message = TunnelData::parse(&our_message).ok_or_else(|| {
            tracing::warn!(
                target: LOG_TARGET,
                tunnel_id = %self.tunnel_id,
                "malformed tunnel data message",
            );

            Error::Tunnel(TunnelError::InvalidMessage)
        })?;

        // parse messages and fragments and return an iterator of ready messages
        let messages = TunnelData::parse(&ciphertext[payload_start..].to_vec())
            .ok_or_else(|| {
                tracing::warn!(
                    target: LOG_TARGET,
                    tunnel_id = %self.tunnel_id,
                    "malformed tunnel data message",
                );

                Error::Tunnel(TunnelError::InvalidMessage)
            })?
            .messages
            .into_iter()
            .filter_map(|message| {
                let (message, delivery_instructions) = match message.message_kind {
                    MessageKind::Unfragmented {
                        delivery_instructions,
                    } => (
                        Message::parse_standard(message.message)?,
                        OwnedDeliveryInstructions::from(&delivery_instructions),
                    ),
                    MessageKind::FirstFragment {
                        message_id,
                        delivery_instructions,
                    } => self.fragment.first_fragment(
                        MessageId::from(message_id),
                        &delivery_instructions,
                        message.message,
                    )?,
                    MessageKind::MiddleFragment {
                        message_id,
                        sequence_number,
                    } => self.fragment.middle_fragment(
                        MessageId::from(message_id),
                        sequence_number,
                        message.message,
                    )?,
                    MessageKind::LastFragment {
                        message_id,
                        sequence_number,
                    } => self.fragment.last_fragment(
                        MessageId::from(message_id),
                        sequence_number,
                        message.message,
                    )?,
                };

                match delivery_instructions {
                    OwnedDeliveryInstructions::Local => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            tunnel_id = %self.tunnel_id,
                            "local delivery not supported",
                        );

                        None
                    }
                    OwnedDeliveryInstructions::Router { hash } => {
                        let router = RouterId::from(hash);

                        tracing::trace!(
                            target: LOG_TARGET,
                            tunnel_id = %self.tunnel_id,
                            %router,
                            message_type = ?message.message_type,
                            "fragment router delivery",
                        );

                        let message = MessageBuilder::short()
                            .with_message_type(message.message_type)
                            .with_message_id(message.message_id)
                            .with_expiration(message.expiration)
                            .with_payload(&message.payload)
                            .build();

                        Some((router, message))
                    }
                    OwnedDeliveryInstructions::Tunnel { tunnel_id, hash } => {
                        let router = RouterId::from(hash);

                        tracing::trace!(
                            target: LOG_TARGET,
                            tunnel_id = %self.tunnel_id,
                            %router,
                            delivery_tunnel = ?tunnel_id,
                            "fragment router delivery",
                        );

                        let payload = TunnelGateway {
                            tunnel_id: TunnelId::from(tunnel_id),
                            payload: &message.serialize_standard(),
                        }
                        .serialize();

                        let message = MessageBuilder::short()
                            .with_message_type(MessageType::TunnelGateway)
                            .with_message_id(R::rng().next_u32())
                            .with_expiration(R::time_since_epoch() + Duration::from_secs(8))
                            .with_payload(&payload)
                            .build();

                        Some((router, message))
                    }
                }
            })
            .collect::<Vec<(RouterId, Vec<u8>)>>();

        Ok(messages.into_iter())
    }
}

impl<R: Runtime> TransitTunnel<R> for OutboundEndpoint<R> {
    /// Create new [`OutboundEndpoint`].
    fn new(
        tunnel_id: TunnelId,
        next_tunnel_id: TunnelId,
        next_router: RouterId,
        tunnel_keys: TunnelKeys,
        routing_table: RoutingTable,
        metrics_handle: R::MetricsHandle,
        message_rx: Receiver<Message>,
    ) -> Self {
        OutboundEndpoint {
            expiration_timer: Box::pin(R::delay(TUNNEL_EXPIRATION)),
            fragment: FragmentHandler::new(),
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
        HopRole::OutboundEndpoint
    }
}

impl<R: Runtime> Future for OutboundEndpoint<R> {
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
                            Ok(messages) => messages.into_iter().for_each(|(router, message)| {
                                if let Err(error) = self.routing_table.send_message(router, message)
                                {
                                    tracing::error!(
                                        target: LOG_TARGET,
                                        tunnel_id = %self.tunnel_id,
                                        ?error,
                                        "failed to send message",
                                    )
                                }
                            }),
                            Err(error) => tracing::warn!(
                                target: LOG_TARGET,
                                tunnel_id = %self.tunnel_id,
                                ?error,
                                "failed to handle tunnel data",
                            ),
                        },
                        None => tracing::warn!(
                            target: LOG_TARGET,
                            tunnel_id = %self.tunnel_id,
                            "malformed `TunnelData` message",
                        ),
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
