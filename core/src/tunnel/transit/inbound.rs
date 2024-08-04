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
    i2np::HopRole,
    primitives::{RouterId, TunnelId},
    tunnel::{new_noise::TunnelKeys, transit::TransitTunnel},
};

/// Inbound gateway.
pub struct InboundGateway {
    /// Tunnel ID.
    tunnel_id: TunnelId,
    /// Next tunnel ID.
    next_tunnel_id: TunnelId,

    /// Next router ID.
    next_router: RouterId,

    /// Tunnel key context.
    key_context: TunnelKeys,
}

impl InboundGateway {
    /// Create new [`InboundGateway`].
    pub fn new(
        tunnel_id: TunnelId,
        next_tunnel_id: TunnelId,
        next_router: RouterId,
        key_context: TunnelKeys,
    ) -> Self
    where
        Self: Sized,
    {
        InboundGateway {
            tunnel_id,
            next_tunnel_id,
            next_router,
            key_context,
        }
    }
}

impl TransitTunnel for InboundGateway {
    fn role(&self) -> HopRole {
        HopRole::InboundGateway
    }
}
