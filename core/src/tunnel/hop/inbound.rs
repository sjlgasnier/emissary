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
    primitives::{MessageId, TunnelId},
    runtime::Runtime,
    tunnel::hop::{Tunnel, TunnelDirection},
};

use alloc::vec::Vec;
use core::iter;

#[derive(Debug)]
pub struct InboundTunnel {}

impl InboundTunnel {
    pub fn new(tunnel_id: TunnelId, message_id: MessageId) -> Self {
        Self {}
    }
}

impl Tunnel for InboundTunnel {
    fn hop_roles(num_hops: usize) -> impl Iterator<Item = HopRole> {
        match num_hops == 1 {
            true => iter::once(HopRole::InboundGateway).collect::<Vec<_>>().into_iter(),
            false => iter::once(HopRole::InboundGateway)
                .chain((0..num_hops - 1).map(|_| HopRole::Intermediary))
                .collect::<Vec<_>>()
                .into_iter(),
        }
    }

    fn direction() -> TunnelDirection {
        TunnelDirection::Inbound
    }
}
