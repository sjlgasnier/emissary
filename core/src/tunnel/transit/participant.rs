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
        EncryptedTunnelData, HopRole, MessageType, RawI2NpMessageBuilder, TunnelGatewayMessage,
    },
    primitives::{RouterId, TunnelId},
    runtime::Runtime,
    tunnel::{new_noise::TunnelKeys, transit::TransitTunnel},
    Error,
};

use bytes::{BufMut, BytesMut};
use rand_core::RngCore;

use alloc::{vec, vec::Vec};
use core::{marker::PhantomData, time::Duration};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::transit::participant";

/// Tunnel participant.
///
/// Only accepts and handles `TunnelData` messages,
/// all other message types are rejected as invalid.
pub struct Participant<R: Runtime> {
    /// Tunnel ID.
    tunnel_id: TunnelId,

    /// Next tunnel ID.
    next_tunnel_id: TunnelId,

    /// Next router ID.
    next_router: RouterId,

    /// Tunnel keys.
    tunnel_keys: TunnelKeys,

    /// Marker for `Runtime`
    _marker: PhantomData<R>,
}

impl<R: Runtime> Participant<R> {
    /// Create new [`Participant`].
    pub fn new(
        tunnel_id: TunnelId,
        next_tunnel_id: TunnelId,
        next_router: RouterId,
        tunnel_keys: TunnelKeys,
    ) -> Self {
        Participant {
            tunnel_id,
            next_tunnel_id,
            next_router,
            tunnel_keys,
            _marker: Default::default(),
        }
    }
}

impl<R: Runtime> TransitTunnel for Participant<R> {
    fn role(&self) -> HopRole {
        HopRole::Participant
    }

    fn handle_tunnel_data<'a>(
        &mut self,
        tunnel_data: EncryptedTunnelData<'a>,
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

        // TODO: fix payload to take `AsRef<[u8]>`
        let message = RawI2NpMessageBuilder::short()
            .with_message_type(MessageType::TunnelData)
            .with_message_id(R::rng().next_u32())
            .with_expiration((R::time_since_epoch() + Duration::from_secs(8)).as_secs())
            .with_payload(out.freeze().to_vec())
            .serialize();

        return Ok((self.next_router.clone(), message));
    }

    fn handle_tunnel_gateway(
        &mut self,
        tunnel_gateway: TunnelGatewayMessage,
    ) -> crate::Result<(RouterId, Vec<u8>)> {
        Err(Error::Tunnel(TunnelError::MessageRejected(
            RejectionReason::NotSupported,
        )))
    }
}
