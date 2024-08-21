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

/// Logging target for the file:
const LOG_TARGET: &str = "emissary::tunnel::pool::zero-hop";

use crate::{
    i2np::{tunnel::gateway::TunnelGateway, Message},
    primitives::TunnelId,
    tunnel::routing_table::RoutingTable,
};

use rand_core::RngCore;
use thingbuf::mpsc;

use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// Fake 0-hop inbound tunnel.
///
/// These tunnels are used to receive one `TunnelGateway` message which contains a tunnel build
/// response which it routes back to the installed listener (if it exists), after which the tunnel
/// gets destructed.
pub struct ZeroHopInboundTunnel {
    /// RX channel for receiving a message.
    message_rx: mpsc::Receiver<Message>,

    /// Routing table.
    routing_table: RoutingTable,

    /// Tunnel ID.
    tunnel_id: TunnelId,
}

impl ZeroHopInboundTunnel {
    /// Create new [`ZeroHopInboundTunnel`].
    pub fn new(routing_table: RoutingTable, rng: &mut impl RngCore) -> (TunnelId, Self) {
        let (tunnel_id, message_rx) = routing_table.insert_tunnel::<1>(rng);

        (
            tunnel_id,
            Self {
                message_rx,
                routing_table,
                tunnel_id,
            },
        )
    }

    /// Handle receive I2NP message, presumably containing a tunnel build response.
    fn on_message(&self, message: Message) {
        tracing::trace!(
            target: LOG_TARGET,
            tunnel_id = %self.tunnel_id,
            message_type = ?message.message_type,
            "handle message",
        );

        let Some(TunnelGateway { payload, .. }) = TunnelGateway::parse(&message.payload) else {
            tracing::warn!(
                target: LOG_TARGET,
                tunnel_id = %self.tunnel_id,
                message_type = ?message.message_type,
                "invalid message, expected `TunnelGateway`",
            );
            return;
        };

        let Some(message) = Message::parse_standard(&payload) else {
            tracing::warn!(
                target: LOG_TARGET,
                tunnel_id = %self.tunnel_id,
                message_type = ?message.message_type,
                "invalid message, expected standard i2np message",
            );
            return;
        };

        self.routing_table.route_message(message);
    }
}

impl Future for ZeroHopInboundTunnel {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match futures::ready!(self.message_rx.poll_recv(cx)) {
            None => tracing::debug!(
                target: LOG_TARGET,
                tunnel_id = %self.tunnel_id,
                "channel closed while waiting for build response",
            ),
            Some(message) => self.on_message(message),
        }

        // remove the fake 0-hop tunnel from the routing table after processing the message because
        // it's only used for processing of one build reply record
        self.routing_table.remove_tunnel(&self.tunnel_id);

        Poll::Ready(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
