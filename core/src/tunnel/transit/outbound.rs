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
        DeliveryInstruction, EncryptedTunnelData, HopRole, MessageKind, MessageType,
        RawI2NpMessageBuilder, RawI2npMessage, TunnelData, TunnelGatewayMessage, I2NP_STANDARD,
    },
    primitives::{RouterId, TunnelId},
    runtime::Runtime,
    tunnel::{new_noise::TunnelKeys, transit::TransitTunnel},
    Error,
};

use alloc::vec::Vec;
use core::{marker::PhantomData, time::Duration};
use rand_core::RngCore;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::transit::obep";

/// Outbound endpoint.
pub struct OutboundEndpoint<R: Runtime> {
    /// Tunnel ID.
    tunnel_id: TunnelId,
    /// Next tunnel ID.
    next_tunnel_id: TunnelId,

    /// Next router ID.
    next_router: RouterId,

    /// Tunnel keys.
    tunnel_keys: TunnelKeys,

    /// Marker for `Runtime`.
    _marker: PhantomData<R>,
}

impl<R: Runtime> OutboundEndpoint<R> {
    /// Create new [`OutboundEndpoint`].
    pub fn new(
        tunnel_id: TunnelId,
        next_tunnel_id: TunnelId,
        next_router: RouterId,
        tunnel_keys: TunnelKeys,
    ) -> Self
    where
        Self: Sized,
    {
        OutboundEndpoint {
            tunnel_id,
            next_tunnel_id,
            next_router,
            tunnel_keys,
            _marker: Default::default(),
        }
    }

    /// Find paylod start by locating the 0x00 byte at the end of the padding section and verify
    /// the checksum of the message before returning the index where the payload section starts.
    ///
    /// TODO: spec
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

        // zero byte is not considered part of the payload (+1)
        // TODO: explain +4
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
}

impl<R: Runtime> TransitTunnel for OutboundEndpoint<R> {
    fn role(&self) -> HopRole {
        HopRole::OutboundEndpoint
    }

    fn handle_tunnel_data<'a>(
        &mut self,
        tunnel_data: EncryptedTunnelData<'a>,
    ) -> crate::Result<(RouterId, Vec<u8>)> {
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

        for message in message.messages {
            if let MessageKind::Unfragmented {
                delivery_instructions,
            } = message.message_kind
            {
                match delivery_instructions {
                    DeliveryInstruction::Router { hash } => {
                        let RawI2npMessage {
                            message_type,
                            message_id,
                            expiration,
                            payload,
                        } = RawI2npMessage::parse::<I2NP_STANDARD>(&message.message).ok_or_else(
                            || {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    tunnel_id = %self.tunnel_id,
                                    "fragment router delivery: invalid message",
                                );

                                Error::Tunnel(TunnelError::InvalidMessage)
                            },
                        )?;
                        let router = RouterId::from(hash);

                        tracing::trace!(
                            target: LOG_TARGET,
                            tunnel_id = %self.tunnel_id,
                            ?router,
                            ?message_type,
                            "fragment router delivery",
                        );

                        let message = RawI2NpMessageBuilder::short()
                            .with_message_type(message_type)
                            .with_message_id(message_id)
                            .with_expiration(expiration)
                            .with_payload(payload)
                            .serialize();

                        return Ok((router, message));
                    }
                    DeliveryInstruction::Tunnel { hash, tunnel_id } => {
                        let router = RouterId::from(hash);

                        tracing::trace!(
                            target: LOG_TARGET,
                            tunnel_id = %self.tunnel_id,
                            ?router,
                            delivery_tunnel = ?tunnel_id,
                            "fragment router delivery",
                        );

                        let payload = TunnelGatewayMessage {
                            tunnel_id,
                            payload: &message.message,
                        }
                        .serialize();

                        let message = RawI2NpMessageBuilder::short()
                            .with_message_type(MessageType::TunnelGateway)
                            .with_message_id(R::rng().next_u32())
                            .with_expiration(
                                (R::time_since_epoch() + Duration::from_secs(8)).as_secs(),
                            )
                            .with_payload(payload)
                            .serialize();

                        return Ok((RouterId::from(hash), message));
                    }
                    DeliveryInstruction::Local => tracing::warn!(
                        target: LOG_TARGET,
                        tunnel_id = %self.tunnel_id,
                        "local delivery not supported",
                    ),
                }
            }
        }

        Err(Error::Tunnel(TunnelError::MessageRejected(
            RejectionReason::NotSupported,
        )))
    }
}
