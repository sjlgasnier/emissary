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
    profile::{Bucket, ProfileStorage},
    runtime::Runtime,
    tunnel::pool::TunnelPoolContextHandle,
    util::shuffle,
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
pub struct ExploratorySelector<R: Runtime> {
    /// Exploratory tunnel pool handle.
    handle: TunnelPoolContextHandle,

    /// Active inbound tunnels.
    inbound: Arc<RwLock<HashMap<TunnelId, RouterId>>>,

    /// Active outbound tunnels.
    outbound: Arc<RwLock<HashSet<TunnelId>>>,

    /// Router storage for selecting hops.
    profile_storage: ProfileStorage<R>,
}

impl<R: Runtime> ExploratorySelector<R> {
    /// Create new [`ExploratorySelector`].
    pub fn new(profile_storage: ProfileStorage<R>, handle: TunnelPoolContextHandle) -> Self {
        Self {
            handle,
            inbound: Default::default(),
            outbound: Default::default(),
            profile_storage,
        }
    }

    /// Get reference to [`ProfileStorage`].
    pub fn profile_storage(&self) -> &ProfileStorage<R> {
        &self.profile_storage
    }

    /// Get reference to exploratory tunnel pool's [`TunnePoolHandle`].
    pub fn handle(&self) -> &TunnelPoolContextHandle {
        &self.handle
    }
}

impl<R: Runtime> TunnelSelector for ExploratorySelector<R> {
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

impl<R: Runtime> HopSelector for ExploratorySelector<R> {
    fn select_hops(&self, num_hops: usize) -> Option<Vec<(Bytes, StaticPublicKey)>> {
        let mut router_ids = self
            .profile_storage
            .get_router_ids(Bucket::Standard, |_, router_info, profile| {
                !profile.is_failing() && router_info.is_reachable()
            });

        // use fast routers if there aren't enough fast routers
        let router_ids = if router_ids.len() < num_hops {
            router_ids.extend(
                self.profile_storage.get_router_ids(Bucket::Fast, |_, router_info, profile| {
                    !profile.is_failing() && router_info.is_reachable()
                }),
            );

            if router_ids.len() < num_hops {
                return None;
            }

            router_ids
        } else {
            // shuffle routers so we don't end up choosing the same routers always
            shuffle(&mut router_ids, &mut R::rng());

            router_ids
        };

        let reader = self.profile_storage.reader();
        Some(
            (0..num_hops)
                .map(|i| {
                    let router_info = reader.router_info(&router_ids[i]);

                    (
                        router_info.identity.hash().clone(),
                        router_info.identity.static_key().clone(),
                    )
                })
                .collect::<Vec<_>>(),
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
pub struct ClientSelector<R: Runtime> {
    /// Exploratory tunnel pool selector.
    exploratory: ExploratorySelector<R>,

    /// Client tunnel pool handle.
    handle: TunnelPoolContextHandle,

    /// Active inbound tunnels.
    inbound: Arc<RwLock<HashMap<TunnelId, RouterId>>>,

    /// Active outbound tunnels.
    outbound: Arc<RwLock<HashSet<TunnelId>>>,
}

impl<R: Runtime> ClientSelector<R> {
    /// Create new [`ClientSelector`].
    pub fn new(exploratory: ExploratorySelector<R>, handle: TunnelPoolContextHandle) -> Self {
        Self {
            exploratory,
            handle,
            inbound: Default::default(),
            outbound: Default::default(),
        }
    }
}

impl<R: Runtime> TunnelSelector for ClientSelector<R> {
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

impl<R: Runtime> HopSelector for ClientSelector<R> {
    fn select_hops(&self, num_hops: usize) -> Option<Vec<(Bytes, StaticPublicKey)>> {
        let mut router_ids = self
            .exploratory
            .profile_storage()
            .get_router_ids(Bucket::Fast, |_, router_info, profile| {
                !profile.is_failing() && router_info.is_reachable()
            });

        // use standard routers if there aren't enough fast routers
        let router_ids = if router_ids.len() < num_hops {
            router_ids.extend(
                self.exploratory
                    .profile_storage()
                    .get_router_ids(Bucket::Standard, |_, router_info, profile| {
                        !profile.is_failing() && router_info.is_reachable()
                    }),
            );

            if router_ids.len() < num_hops {
                return None;
            }

            router_ids
        } else {
            // shuffle routers so we don't end up choosing the same routers always
            shuffle(&mut router_ids, &mut R::rng());

            router_ids
        };

        let reader = self.exploratory.profile_storage().reader();
        Some(
            (0..num_hops)
                .map(|i| {
                    let router_info = reader.router_info(&router_ids[i]);

                    (
                        router_info.identity.hash().clone(),
                        router_info.identity.static_key().clone(),
                    )
                })
                .collect::<Vec<_>>(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        primitives::{Capabilities, RouterInfo, Str},
        runtime::mock::MockRuntime,
        tunnel::pool::TunnelPoolBuildParameters,
    };

    #[test]
    fn not_enough_routers_for_exploratory_tunnel() {
        let build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        for _ in 0..3 {
            profile_storage.add_router({
                let mut info = RouterInfo::random::<MockRuntime>();
                info.capabilities = Capabilities::parse(&Str::from("LR")).unwrap();
                info
            });
        }

        let selector = ExploratorySelector::new(
            profile_storage.clone(),
            build_parameters.context_handle.clone(),
        );
        assert!(selector.select_hops(5).is_none());
    }

    #[test]
    fn select_exploratory_hops() {
        let build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        for _ in 0..10 {
            profile_storage.add_router({
                let mut info = RouterInfo::random::<MockRuntime>();
                info.capabilities = Capabilities::parse(&Str::from("LR")).unwrap();
                info
            });
        }

        let selector = ExploratorySelector::new(
            profile_storage.clone(),
            build_parameters.context_handle.clone(),
        );

        // select hops 5 times and verify that the same set of hops is not selected every time
        let hops = selector.select_hops(3).unwrap();

        let (num_same, _) = (0..5).fold((0usize, hops), |(count, prev), _| {
            let hops = selector.select_hops(3).unwrap();
            if prev
                .iter()
                .zip(hops.iter())
                .all(|(a, b)| a.0 == b.0 && a.1.to_bytes() == b.1.to_bytes())
            {
                (count + 1, hops)
            } else {
                (count, hops)
            }
        });
        assert_ne!(num_same, 5);
    }

    #[test]
    fn use_fast_routers_as_fallback() {
        let build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        for _ in 0..3 {
            profile_storage.add_router({
                let mut info = RouterInfo::random::<MockRuntime>();
                info.capabilities = Capabilities::parse(&Str::from("LR")).unwrap();
                info
            });
        }

        for _ in 0..5 {
            profile_storage.add_router({
                let mut info = RouterInfo::random::<MockRuntime>();
                info.capabilities = Capabilities::parse(&Str::from("XRf")).unwrap();
                info
            });
        }

        let selector = ExploratorySelector::new(
            profile_storage.clone(),
            build_parameters.context_handle.clone(),
        );

        // there are only 3 standard routers so 2 routers must be fast
        let mut standard = 0usize;
        let mut fast = 0usize;
        let reader = profile_storage.reader();

        for (hash, _) in selector.select_hops(5).unwrap() {
            let router_info = reader.router_info(&RouterId::from(hash));

            if router_info.capabilities.is_fast() {
                fast += 1;
            } else {
                standard += 1;
            }
        }

        assert_eq!(standard, 3);
        assert_eq!(fast, 2);
    }

    #[test]
    fn not_enough_routers_for_client_tunnel() {
        let exploratory_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let client_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        for _ in 0..3 {
            profile_storage.add_router({
                let mut info = RouterInfo::random::<MockRuntime>();
                info.capabilities = Capabilities::parse(&Str::from("X")).unwrap();
                info
            });
        }

        let exploratory = ExploratorySelector::new(
            profile_storage.clone(),
            exploratory_build_parameters.context_handle.clone(),
        );
        let selector =
            ClientSelector::new(exploratory, client_build_parameters.context_handle.clone());
        assert!(selector.select_hops(5).is_none());
    }

    #[test]
    fn select_client_hops() {
        let exploratory_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let client_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        for _ in 0..10 {
            profile_storage.add_router({
                let mut info = RouterInfo::random::<MockRuntime>();
                info.capabilities = Capabilities::parse(&Str::from("OR")).unwrap();
                info
            });
        }

        let exploratory = ExploratorySelector::new(
            profile_storage.clone(),
            exploratory_build_parameters.context_handle.clone(),
        );
        let selector =
            ClientSelector::new(exploratory, client_build_parameters.context_handle.clone());

        // select hops 5 times and verify that the same set of hops is not selected every time
        let hops = selector.select_hops(3).unwrap();

        let (num_same, _) = (0..5).fold((0usize, hops), |(count, prev), _| {
            let hops = selector.select_hops(3).unwrap();
            if prev
                .iter()
                .zip(hops.iter())
                .all(|(a, b)| a.0 == b.0 && a.1.to_bytes() == b.1.to_bytes())
            {
                (count + 1, hops)
            } else {
                (count, hops)
            }
        });
        assert_ne!(num_same, 5);
    }

    #[test]
    fn use_standard_routers_as_fallback() {
        let exploratory_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let client_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        for _ in 0..5 {
            profile_storage.add_router({
                let mut info = RouterInfo::random::<MockRuntime>();
                info.capabilities = Capabilities::parse(&Str::from("LR")).unwrap();
                info
            });
        }

        for _ in 0..3 {
            profile_storage.add_router({
                let mut info = RouterInfo::random::<MockRuntime>();
                info.capabilities = Capabilities::parse(&Str::from("XRf")).unwrap();
                info
            });
        }

        let exploratory = ExploratorySelector::new(
            profile_storage.clone(),
            exploratory_build_parameters.context_handle.clone(),
        );
        let selector =
            ClientSelector::new(exploratory, client_build_parameters.context_handle.clone());

        // there are only 3 fast routers so 2 routers must be standard
        let mut standard = 0usize;
        let mut fast = 0usize;
        let reader = profile_storage.reader();

        for (hash, _) in selector.select_hops(5).unwrap() {
            let router_info = reader.router_info(&RouterId::from(hash));

            if router_info.capabilities.is_fast() {
                fast += 1;
            } else {
                standard += 1;
            }
        }

        assert_eq!(standard, 2);
        assert_eq!(fast, 3);
    }
}
