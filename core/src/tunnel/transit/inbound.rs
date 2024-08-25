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
            data::{EncryptedTunnelData, TunnelDataBuilder},
            gateway::TunnelGateway,
        },
        HopRole, Message, MessageBuilder, MessageType,
    },
    primitives::{RouterId, TunnelId},
    runtime::Runtime,
    tunnel::{
        noise::TunnelKeys, routing_table::RoutingTable, transit::TransitTunnel, TUNNEL_EXPIRATION,
    },
    Error,
};

use bytes::{Buf, BufMut, BytesMut};
use futures::{future::BoxFuture, FutureExt};
use rand_core::RngCore;
use thingbuf::mpsc::Receiver;

use alloc::{boxed::Box, vec::Vec};
use core::{
    future::Future,
    marker::PhantomData,
    ops::{Range, RangeFrom},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::transit::ibgw";

/// AES IV offset inside the `TunnelData` message.
const AES_IV_OFFSET: Range<usize> = 4..20;

/// Payload offset inside the `TunnelData` message.
const PAYLOAD_OFFSET: RangeFrom<usize> = 20..;

/// Inbound gateway.
pub struct InboundGateway<R: Runtime> {
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

    /// Random bytes used for tunnel data padding.
    padding_bytes: [u8; 1028],

    /// Routing table.
    routing_table: RoutingTable,

    /// Tunnel ID.
    tunnel_id: TunnelId,

    /// Tunnel key context.
    tunnel_keys: TunnelKeys,
}

impl<R: Runtime> InboundGateway<R> {
    /// Handle `TunnelGateway` message.
    fn handle_tunnel_data(
        &mut self,
        tunnel_data: &EncryptedTunnelData,
    ) -> crate::Result<(RouterId, Vec<u8>)> {
        tracing::warn!(
            target: LOG_TARGET,
            tunnel_id = %self.tunnel_id,
            "tunnel data received to inbound gateway",
        );

        Err(Error::Tunnel(TunnelError::MessageRejected(
            RejectionReason::NotSupported,
        )))
    }

    fn handle_tunnel_gateway<'a>(
        &'a self,
        tunnel_gateway: &'a TunnelGateway,
    ) -> crate::Result<(RouterId, impl Iterator<Item = Vec<u8>> + 'a)> {
        tracing::trace!(
            target: LOG_TARGET,
            tunnel_id = %self.tunnel_id,
            gateway_tunnel_id = %tunnel_gateway.tunnel_id,
            "tunnel gateway",
        );

        let messages = TunnelDataBuilder::new(self.next_tunnel_id)
            .with_local_delivery(&tunnel_gateway.payload)
            .build::<R>(&self.padding_bytes)
            .into_iter()
            .map(|mut message| {
                let mut aes = ecb::Aes::new_encryptor(&self.tunnel_keys.iv_key());
                let iv = aes.encrypt(&message[AES_IV_OFFSET]);

                let mut aes = cbc::Aes::new_encryptor(&self.tunnel_keys.layer_key(), &iv);
                let ciphertext = aes.encrypt(&message[PAYLOAD_OFFSET]);

                let mut aes = ecb::Aes::new_encryptor(&self.tunnel_keys.iv_key());
                let iv = aes.encrypt(iv);

                message[AES_IV_OFFSET].copy_from_slice(&iv);
                message[PAYLOAD_OFFSET].copy_from_slice(&ciphertext);

                MessageBuilder::short()
                    .with_message_type(MessageType::TunnelData)
                    .with_message_id(R::rng().next_u32())
                    .with_expiration((R::time_since_epoch() + Duration::from_secs(8)).as_secs())
                    .with_payload(&message)
                    .build()
            });

        Ok((self.next_router.clone(), messages))
    }
}

impl<R: Runtime> TransitTunnel<R> for InboundGateway<R> {
    fn new(
        tunnel_id: TunnelId,
        next_tunnel_id: TunnelId,
        next_router: RouterId,
        tunnel_keys: TunnelKeys,
        routing_table: RoutingTable,
        metrics_handle: R::MetricsHandle,
        message_rx: Receiver<Message>,
    ) -> Self {
        // generate random padding bytes used in `TunnelData` messages
        let padding_bytes = {
            let mut padding_bytes = [0u8; 1028];
            R::rng().fill_bytes(&mut padding_bytes);

            padding_bytes = TryInto::<[u8; 1028]>::try_into(
                padding_bytes
                    .into_iter()
                    .map(|byte| if byte == 0 { 1u8 } else { byte })
                    .collect::<Vec<_>>(),
            )
            .expect("to succeed");

            padding_bytes
        };

        InboundGateway {
            expiration_timer: Box::pin(R::delay(TUNNEL_EXPIRATION)),
            message_rx,
            metrics_handle,
            next_router,
            next_tunnel_id,
            padding_bytes,
            routing_table,
            tunnel_id,
            tunnel_keys,
        }
    }

    fn role(&self) -> HopRole {
        HopRole::InboundGateway
    }
}

impl<R: Runtime> Future for InboundGateway<R> {
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
                    MessageType::TunnelGateway => match TunnelGateway::parse(&message.payload) {
                        Some(message) => match self.handle_tunnel_gateway(&message) {
                            Ok((router, messages)) => messages.into_iter().for_each(|message| {
                                if let Err(error) =
                                    self.routing_table.send_message(router.clone(), message)
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
                                "failed to handle tunnel gateway",
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
