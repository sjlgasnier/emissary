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
        tunnel::data::{DeliveryInstructions, EncryptedTunnelData, MessageKind, TunnelData},
        HopRole,
    },
    primitives::{MessageId, RouterId, TunnelId},
    runtime::Runtime,
    tunnel::hop::{Tunnel, TunnelDirection, TunnelHop},
    Error,
};

use alloc::{vec, vec::Vec};
use core::{iter, num::NonZeroUsize};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::ibep";

/// Inbound tunnel.
#[derive(Debug)]
pub struct InboundTunnel {
    /// Tunnel ID.
    tunnel_id: TunnelId,

    /// Tunnel hops.
    hops: Vec<TunnelHop>,
}

impl InboundTunnel {
    /// Create new [`InboundTunnel`].
    pub fn new(tunnel_id: TunnelId, hops: Vec<TunnelHop>) -> Self {
        Self { tunnel_id, hops }
    }

    /// Get gateway information of the inbound tunnel.
    ///
    /// Returns a `(RouterId, TunnelId)` tuple, allowing OBEP to route the message correctly.
    pub fn gateway(&self) -> (RouterId, TunnelId) {
        // tunnel must exist since it was created by us
        let hop = &self.hops.first().expect("tunnel to exist");

        (hop.router.clone(), hop.tunnel_id)
    }

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

    /// Handle tunnel data.
    pub fn handle_tunnel_data<'a>(
        &mut self,
        tunnel_data: &EncryptedTunnelData<'a>,
    ) -> crate::Result<Vec<u8>> {
        tracing::trace!(
            target: LOG_TARGET,
            tunnel = %self.tunnel_id,
            message_len = ?tunnel_data.ciphertext().len(),
            "tunnel data",
        );

        // iterative decrypt the tunnel data message and aes iv
        let iv = tunnel_data.iv().to_vec();
        let ciphertext = tunnel_data.ciphertext().to_vec();

        let (iv, ciphertext) =
            self.hops.iter().rev().fold((iv, ciphertext), |(iv, message), hop| {
                let mut aes = ecb::Aes::new_decryptor(&hop.key_context.iv_key());
                let iv = aes.decrypt(&iv);

                let mut aes = cbc::Aes::new_decryptor(&hop.key_context.layer_key(), &iv);
                let ciphertext = aes.decrypt(message);

                let mut aes = ecb::Aes::new_decryptor(&hop.key_context.iv_key());
                let iv = aes.decrypt(iv);

                (iv, ciphertext)
            });

        // find where the payload starts and verify the checksum
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
            match message.message_kind {
                MessageKind::Unfragmented {
                    delivery_instructions,
                } => match delivery_instructions {
                    DeliveryInstructions::Local => return Ok(message.message.to_vec()),
                    delivery_instructions => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            tunnel = %self.tunnel_id,
                        );
                    }
                },
                fragment => tracing::warn!(
                    target: LOG_TARGET,
                    tunnel = %self.tunnel_id,
                    ?fragment,
                    "fragments not supported",
                ),
            }
        }

        Err(Error::NotSupported)
    }
}

impl Tunnel for InboundTunnel {
    fn new(tunnel_id: TunnelId, hops: Vec<TunnelHop>) -> Self {
        InboundTunnel::new(tunnel_id, hops)
    }

    fn hop_roles(num_hops: NonZeroUsize) -> impl Iterator<Item = HopRole> {
        match num_hops.get() == 1 {
            true => vec![HopRole::InboundGateway].into_iter(),
            false => iter::once(HopRole::InboundGateway)
                .chain((0..num_hops.get() - 1).map(|_| HopRole::Participant))
                .collect::<Vec<_>>()
                .into_iter(),
        }
    }

    fn direction() -> TunnelDirection {
        TunnelDirection::Inbound
    }

    fn tunnel_id(&self) -> &TunnelId {
        &self.tunnel_id
    }
}
