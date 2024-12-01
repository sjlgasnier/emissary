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

//! Tunnel/hop selector for exploratory/client tunnels.

use crate::{
    crypto::StaticPublicKey,
    primitives::{RouterId, TunnelId},
    router_storage::RouterStorage,
    runtime::JoinSet,
    tunnel::pool::TunnelPoolContextHandle,
};

use bytes::Bytes;
use futures::{FutureExt, StreamExt};
use hashbrown::{HashMap, HashSet};

#[cfg(feature = "std")]
use parking_lot::RwLock;
#[cfg(feature = "no_std")]
use spin::rwlock::RwLock;

use alloc::{sync::Arc, vec::Vec};

/// Tunnel selector for a tunnel pool.
///
/// This trait has two implementations: [`ExploratorySelector`] for exploratory tunnel pools and
/// [`ClientSelector`] for client tunnel pools.
///
/// [`ClientSelector`] takes [`ExploratorySelector`] in its constructor, allowing it to utilize
/// exploratory tunnels for tunnel building.
pub trait TunnelSelector: Send + Unpin {
    /// Attempt to select an outbound tunnel for delivery of an inbound tunnel build request.
    ///
    /// Returns `None` if there are no outbound tunnels available.
    fn select_outbound_tunnel(&self) -> Option<(TunnelId, &TunnelPoolContextHandle)>;

    /// Attempt to select an inbound tunnel for reception of an outbound tunnel build reply.
    ///
    /// Returns `None` if there are no inbound tunnels available.
    fn select_inbound_tunnel(&self) -> Option<(TunnelId, RouterId, &TunnelPoolContextHandle)>;

    /// Add a new tunnel into the set of active outbound tunnels.
    fn add_outbound_tunnel(&self, tunnel_id: TunnelId);

    /// Add a new tunnel into the set of active inbound tunnels.
    fn add_inbound_tunnel(&self, tunnel_id: TunnelId, router_id: RouterId);

    /// Remove tunnel from the set of active outbound tunnels.
    fn remove_outbound_tunnel(&self, tunnel_id: &TunnelId);

    /// Remove tunnel from the set of active inbound tunnels.
    fn remove_inbound_tunnel(&self, tunnel_id: &TunnelId);
}

/// Hop selector for a tunnel pool.
///
/// This trait has two implementations: [`ExploratorySelector`] for exploratory tunnel pools and
/// [`ClientSelector`] for client tunnel pools.
pub trait HopSelector: Send + Unpin {
    fn select_hops(&self, num_hops: usize) -> Option<Vec<(Bytes, StaticPublicKey)>>;
}

/// Tunnel/hop selector for the exploratory tunnel pool.
///
/// For inbound tunnel builds, an active outbound tunnel from the same pool is used
/// to deliver the build request. For outbound tunnel builds, an active inbound
/// tunnel is selected for the reception of the tunnel build reply.
///
/// If there are no active tunnels, a fake 0-hop inbound/outbound tunnel is used for
/// reception/delivery.
#[derive(Clone)]
pub struct ExploratorySelector {
    /// Exploratory tunnel pool handle.
    handle: TunnelPoolContextHandle,

    /// Active inbound tunnels.
    inbound: Arc<RwLock<HashMap<TunnelId, RouterId>>>,

    /// Active outbound tunnels.
    outbound: Arc<RwLock<HashSet<TunnelId>>>,

    /// Router storage for selecting hops.
    router_storage: RouterStorage,
}

impl ExploratorySelector {
    /// Create new [`ExploratorySelector`].
    pub fn new(router_storage: RouterStorage, handle: TunnelPoolContextHandle) -> Self {
        Self {
            handle,
            inbound: Default::default(),
            outbound: Default::default(),
            router_storage,
        }
    }

    /// Get reference to [`RouterStorage`].
    pub fn router_storage(&self) -> &RouterStorage {
        &self.router_storage
    }

    /// Get reference to exploratory tunnel pool's [`TunnePoolHandle`].
    pub fn handle(&self) -> &TunnelPoolContextHandle {
        &self.handle
    }
}

impl TunnelSelector for ExploratorySelector {
    fn select_outbound_tunnel(&self) -> Option<(TunnelId, &TunnelPoolContextHandle)> {
        self.outbound.read().iter().next().map(|tunnel_id| (*tunnel_id, &self.handle))
    }

    fn select_inbound_tunnel(&self) -> Option<(TunnelId, RouterId, &TunnelPoolContextHandle)> {
        self.inbound
            .read()
            .iter()
            .next()
            .map(|(tunnel_id, router_id)| (*tunnel_id, router_id.clone(), &self.handle))
    }

    fn add_outbound_tunnel(&self, tunnel_id: TunnelId) {
        self.outbound.write().insert(tunnel_id);
    }

    fn add_inbound_tunnel(&self, tunnel_id: TunnelId, router_id: RouterId) {
        self.inbound.write().insert(tunnel_id, router_id);
    }

    fn remove_outbound_tunnel(&self, tunnel_id: &TunnelId) {
        self.outbound.write().remove(tunnel_id);
    }

    fn remove_inbound_tunnel(&self, tunnel_id: &TunnelId) {
        self.inbound.write().remove(tunnel_id);
    }
}

impl HopSelector for ExploratorySelector {
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
                        info.identity.hash().clone(),
                        info.identity.static_key().clone(),
                    )
                })
                .collect(),
        )
    }
}

/// Tunnel/hop selector for a client tunnel pool.
///
/// For inbound tunnel builds, an active outbound tunnel from the same pool is selected for build
/// request delivery. For outbound tunnel builds, an active inbound tunnel is selected for reception
/// of the tunnel build reply.
///
/// If there are no active inbound/outbound tunnels, a tunnel from the exploratory tunnel pool is
/// selected for reception/delivery.
///
/// If there are no active tunnels in the exploratory pool, a fake 0-hop tunnel is used instead.
#[derive(Clone)]
pub struct ClientSelector {
    /// Exploratory tunnel pool selector.
    exploratory: ExploratorySelector,

    /// Client tunnel pool handle.
    handle: TunnelPoolContextHandle,

    /// Active inbound tunnels.
    inbound: Arc<RwLock<HashMap<TunnelId, RouterId>>>,

    /// Active outbound tunnels.
    outbound: Arc<RwLock<HashSet<TunnelId>>>,
}

impl ClientSelector {
    /// Create new [`ClientSelector`].
    pub fn new(exploratory: ExploratorySelector, handle: TunnelPoolContextHandle) -> Self {
        Self {
            exploratory,
            handle,
            inbound: Default::default(),
            outbound: Default::default(),
        }
    }
}

impl TunnelSelector for ClientSelector {
    fn select_outbound_tunnel(&self) -> Option<(TunnelId, &TunnelPoolContextHandle)> {
        self.outbound.read().iter().next().map_or_else(
            || self.exploratory.select_outbound_tunnel(),
            |tunnel_id| Some((*tunnel_id, &self.handle)),
        )
    }

    fn select_inbound_tunnel(&self) -> Option<(TunnelId, RouterId, &TunnelPoolContextHandle)> {
        self.inbound.read().iter().next().map_or_else(
            || self.exploratory.select_inbound_tunnel(),
            |(tunnel_id, router_id)| Some((*tunnel_id, router_id.clone(), &self.handle)),
        )
    }

    fn add_outbound_tunnel(&self, tunnel_id: TunnelId) {
        self.outbound.write().insert(tunnel_id);
    }

    fn add_inbound_tunnel(&self, tunnel_id: TunnelId, router_id: RouterId) {
        self.inbound.write().insert(tunnel_id, router_id);
    }

    fn remove_outbound_tunnel(&self, tunnel_id: &TunnelId) {
        self.outbound.write().remove(tunnel_id);
    }

    fn remove_inbound_tunnel(&self, tunnel_id: &TunnelId) {
        self.inbound.write().remove(tunnel_id);
    }
}

impl HopSelector for ClientSelector {
    fn select_hops(&self, num_hops: usize) -> Option<Vec<(Bytes, StaticPublicKey)>> {
        let routers = self.exploratory.router_storage().get_routers(num_hops, |_, _| true);

        if routers.len() != num_hops {
            return None;
        }

        Some(
            routers
                .into_iter()
                .map(|info| {
                    (
                        info.identity.hash().clone(),
                        info.identity.static_key().clone(),
                    )
                })
                .collect(),
        )
    }
}
