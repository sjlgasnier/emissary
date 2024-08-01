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
    crypto::StaticPublicKey,
    primitives::TunnelId,
    router_storage::RouterStorage,
    runtime::Runtime,
    tunnel::{
        hop::{inbound::InboundTunnel, outbound::OutboundTunnel},
        pool::TunnelPool,
    },
};

use alloc::vec::Vec;
use bytes::Bytes;

/// Tunnel selector.
///
/// Used to select inbound tunnels for outbound builds and vice versa.
pub trait TunnelSelector {
    /// Try to select inbound tunnel for an outbound tunnel build.
    ///
    /// Returns `None` if there are no available inbound tunnels.
    fn select_inbound_tunnel<'a>(
        &'a self,
        inbound_tunnels: impl Iterator<Item = (&'a TunnelId, &'a InboundTunnel)>,
    ) -> Option<(&'a TunnelId, &'a InboundTunnel)>;

    /// Try to select outbound tunnel for an inbound tunnel build.
    ///
    /// Returns `None` if there are no available outbound tunnels.
    fn select_outbound_tunnel<'a>(
        &'a self,
        outbound_tunnels: impl Iterator<Item = (&'a TunnelId, &'a OutboundTunnel)>,
    ) -> OutboundTunnel;
}

/// Hop selector.
pub trait HopSelector {
    /// Select `num_hops` many routers from router storage and return their router hash and static
    /// key to the caller.
    ///
    /// This function returns `None` if it's able to to fullfil the request for `num_hops` many
    /// routers.
    fn select_hops(&self, num_hops: usize) -> Option<Vec<(Bytes, StaticPublicKey)>>;
}

/// Tunnel selector for the exploratory tunnel pool.
pub struct ExploratorySelector<'a> {
    router_storage: &'a RouterStorage,
}

impl<'a> ExploratorySelector<'a> {
    /// Create new [`ExploratorySelector`].
    pub fn new(router_storage: &'a RouterStorage) -> Self {
        Self { router_storage }
    }
}

impl<'a> TunnelSelector for ExploratorySelector<'a> {
    fn select_inbound_tunnel<'b>(
        &'b self,
        mut inbound_tunnels: impl Iterator<Item = (&'b TunnelId, &'b InboundTunnel)>,
    ) -> Option<(&'b TunnelId, &'b InboundTunnel)> {
        inbound_tunnels.next()
    }

    fn select_outbound_tunnel<'b>(
        &'b self,
        outbound_tunnels: impl Iterator<Item = (&'b TunnelId, &'b OutboundTunnel)>,
    ) -> OutboundTunnel {
        todo!();
    }
}

impl<'a> HopSelector for ExploratorySelector<'a> {
    fn select_hops(&self, num_hops: usize) -> Option<Vec<(Bytes, StaticPublicKey)>> {
        let routers = self.router_storage.get_routers(num_hops, |_, _| true);

        if routers.len() != num_hops {
            return None;
        }

        Some(
            routers
                .into_iter()
                .map(|info| {
                    (
                        info.identity().hash().clone(),
                        info.identity().static_key().clone(),
                    )
                })
                .collect(),
        )
    }
}

/// Tunnel selector for client tunnel pools.
pub struct ClientSelector<'a, R> {
    /// Reference to exploratory tunnel pool which is used as a backup in case
    /// the client tunnel pool doesn't have any pools.
    exploratory: &'a TunnelPool<R>,

    /// Router storage.
    router_storage: &'a RouterStorage,
}

impl<'a, R: Runtime> ClientSelector<'a, R> {
    /// Create new [`ClientSelector`].
    pub fn new(exploratory: &'a TunnelPool<R>, router_storage: &'a RouterStorage) -> Self {
        Self {
            exploratory,
            router_storage,
        }
    }
}

impl<'a, R: Runtime> TunnelSelector for ClientSelector<'a, R> {
    fn select_inbound_tunnel<'b>(
        &'b self,
        inbound_tunnels: impl Iterator<Item = (&'b TunnelId, &'b InboundTunnel)>,
    ) -> Option<(&'b TunnelId, &'b InboundTunnel)> {
        inbound_tunnels.chain(self.exploratory.inbound().iter()).next()
    }

    fn select_outbound_tunnel<'b>(
        &'b self,
        outbound_tunnels: impl Iterator<Item = (&'b TunnelId, &'b OutboundTunnel)>,
    ) -> OutboundTunnel {
        todo!();
    }
}

impl<'a, R: Runtime> HopSelector for ClientSelector<'a, R> {
    fn select_hops(&self, num_hops: usize) -> Option<Vec<(Bytes, StaticPublicKey)>> {
        None
    }
}
