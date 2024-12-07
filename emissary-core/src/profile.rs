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
    crypto::base64_decode,
    primitives::{RouterId, RouterInfo},
};

use hashbrown::HashMap;

#[cfg(feature = "std")]
use parking_lot::{RwLock, RwLockReadGuard};
#[cfg(feature = "no_std")]
use spin::rwlock::{RwLock, RwLockReadGuard};

use alloc::sync::Arc;
use core::time::Duration;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::profile";

/// Router profile.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Profile {
    /// Last activity, duration since UNIX epoch.
    pub last_activity: Duration,

    /// Number of accepted tunnels.
    pub num_accepted: usize,

    /// Number of successful connections.
    pub num_connection: usize,

    /// Number of dial failures.
    pub num_dial_failures: usize,

    /// Number of rejected tunnels.
    pub num_rejected: usize,

    /// Number of test failures for tunnels where the router was a selected hop.
    pub num_test_failures: usize,

    /// Number of test successes for tunnels where the router was a selected hop.
    pub num_test_successes: usize,

    /// Number of tunnel build request timeouts where this router was a selected hop.
    pub num_unaswered: usize,
}

impl Profile {
    pub fn new() -> Self {
        Self {
            last_activity: Duration::from_secs(0),
            num_accepted: 0usize,
            num_connection: 0usize,
            num_dial_failures: 0usize,
            num_rejected: 0usize,
            num_test_failures: 0usize,
            num_test_successes: 0usize,
            num_unaswered: 0usize,
        }
    }
}

/// Profile storage.
#[derive(Clone)]
pub struct ProfileStorage {
    /// Router profiles.
    profiles: Arc<RwLock<HashMap<RouterId, Profile>>>,

    /// Router infos.
    routers: Arc<RwLock<HashMap<RouterId, RouterInfo>>>,
}

impl ProfileStorage {
    /// Create new [`ProfileStorage`].
    pub fn new(routers: &Vec<Vec<u8>>, profiles: &Vec<(String, Profile)>) -> Self {
        tracing::info!(
            target: LOG_TARGET,
            num_routers = ?routers.len(),
            num_profiles = ?profiles.len(),
            "initialize profile storage",
        );

        let routers = routers
            .into_iter()
            .filter_map(|router| {
                RouterInfo::parse(router).map(|router| (router.identity.id(), router))
            })
            .collect::<HashMap<_, _>>();

        let mut profiles = profiles
            .iter()
            .filter_map(|(router_id, profile)| {
                let router_id =
                    RouterId::from(base64_decode(&router_id).expect("valid base64 name"));

                routers.contains_key(&router_id).then_some((router_id, *profile))
            })
            .collect::<HashMap<_, _>>();

        // empty profiles for all routers whose profiles were not found
        routers.keys().for_each(|router_id| {
            if !profiles.contains_key(router_id) {
                profiles.insert(router_id.clone(), Profile::new());
            }
        });

        Self {
            routers: Arc::new(RwLock::new(routers)),
            profiles: Arc::new(RwLock::new(profiles)),
        }
    }

    /// Insert `router` into [`ProfileStorage`].
    pub fn insert(&self, router: RouterInfo) {
        let router_id = router.identity.id();
        let mut inner = self.routers.write();

        inner.insert(router_id, router);
    }

    /// Return the number of routers in [`ProfileStorage`].
    pub fn len(&self) -> usize {
        self.routers.read().len()
    }

    /// Insert `router` into [`ProfileStorage`].
    pub fn add_router(&self, router: RouterInfo) {
        let router_id = router.identity.id();

        if self.routers.write().insert(router_id.clone(), router).is_none() {
            self.profiles.write().insert(router_id, Profile::new());
        }
    }

    // TODO: remove
    pub fn get(&self, router: &RouterId) -> Option<RouterInfo> {
        self.routers.read().get(router).map(|router_info| router_info.clone())
    }

    // TODO: remove
    pub fn get_routers(
        &self,
        num_routers: usize,
        filter: impl Fn(&RouterId, &RouterInfo) -> bool,
    ) -> Vec<RouterInfo> {
        let inner = self.routers.read();

        inner
            .iter()
            .filter_map(|(router, info)| filter(router, info).then_some(info.clone()))
            .take(num_routers)
            .collect()
    }

    // TODO: remove
    pub fn routers<'a>(&'a self) -> RwLockReadGuard<'a, HashMap<RouterId, RouterInfo>> {
        self.routers.read()
    }

    /// Returns `true` if router identified by `RouterId` is a floodfill router.
    ///
    /// Returns `false` if it's not or if the router is not found in [`ProfileManager`].
    pub fn is_floodfill(&self, router_id: &RouterId) -> bool {
        self.routers
            .read()
            .get(router_id)
            .map_or(false, |router_info| router_info.is_floodfill())
    }

    pub fn tunnel_build_accepted(&self, router_id: &RouterId) {}
    pub fn tunnel_build_rejected(&self, router_id: &RouterId) {}
    pub fn tunnel_build_not_answered(&self, router_id: &RouterId) {}
    pub fn tunnel_test_succeeded(&self) {}
    pub fn tunnel_test_failed(&self) {}
}

#[cfg(test)]
impl ProfileStorage {
    /// Create new [`ProfileStorage`] from random `routers`.
    ///
    /// Only used in tests.
    pub fn from_random(routers: Vec<RouterInfo>) -> Self {
        let routers = routers
            .into_iter()
            .map(|router| (router.identity.id(), router))
            .collect::<HashMap<_, _>>();

        let profiles =
            routers.keys().map(|router_id| (router_id.clone(), Profile::new())).collect();

        Self {
            routers: Arc::new(RwLock::new(routers)),
            profiles: Arc::new(RwLock::new(profiles)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::base64_encode, runtime::mock::MockRuntime};

    #[test]
    fn initialize_with_infos_without_profiles() {
        let (_, infos): (Vec<_>, Vec<_>) = (0..5)
            .map(|_| {
                let (info, _, sgn_key) = RouterInfo::random_with_keys::<MockRuntime>();
                let router_id = info.identity.id();

                (router_id, info.serialize(&sgn_key))
            })
            .unzip();

        let profiles = ProfileStorage::new(&infos, &Vec::new());

        assert_eq!(profiles.routers.read().len(), 5);
        assert_eq!(profiles.profiles.read().len(), 5);
        assert!(profiles
            .routers
            .read()
            .keys()
            .all(|key| profiles.profiles.read().contains_key(key)));
        assert!(profiles.profiles.read().values().all(|profile| profile == &Profile::new()));
    }

    #[test]
    fn initialize_with_infos_and_profiles() {
        let (router_ids, infos): (Vec<_>, Vec<_>) = (0..5)
            .map(|_| {
                let (info, _, sgn_key) = RouterInfo::random_with_keys::<MockRuntime>();
                let router_id = info.identity.id();

                (router_id, info.serialize(&sgn_key))
            })
            .unzip();

        let profiles = (0..3)
            .map(|i| {
                let router_id = base64_encode(router_ids[i].to_vec());

                (
                    router_id,
                    Profile {
                        last_activity: Duration::from_secs((i as u64 + 1) * 10000),
                        num_accepted: i + 1,
                        num_connection: i + 1,
                        num_dial_failures: i + 1,
                        num_rejected: i + 1,
                        num_test_failures: i + 1,
                        num_test_successes: i + 1,
                        num_unaswered: i + 1,
                    },
                )
            })
            .collect::<Vec<_>>();

        let profiles = ProfileStorage::new(&infos, &profiles);

        assert_eq!(profiles.routers.read().len(), 5);
        assert_eq!(profiles.profiles.read().len(), 5);
        assert!(profiles
            .routers
            .read()
            .keys()
            .all(|key| profiles.profiles.read().contains_key(key)));

        for i in 0..3 {
            assert_ne!(
                profiles.profiles.read().get(&router_ids[i]).unwrap(),
                &Profile::new()
            );
        }

        for i in 3..5 {
            assert_eq!(
                profiles.profiles.read().get(&router_ids[i]).unwrap(),
                &Profile::new()
            );
        }
    }

    #[test]
    fn profile_without_router_info() {
        let profiles = (0..3)
            .map(|i| {
                let router_id = base64_encode(RouterId::random().to_vec());

                (
                    router_id,
                    Profile {
                        last_activity: Duration::from_secs((i as u64 + 1) * 10000),
                        num_accepted: i + 1,
                        num_connection: i + 1,
                        num_dial_failures: i + 1,
                        num_rejected: i + 1,
                        num_test_failures: i + 1,
                        num_test_successes: i + 1,
                        num_unaswered: i + 1,
                    },
                )
            })
            .collect::<Vec<_>>();

        let profiles = ProfileStorage::new(&Vec::new(), &profiles);

        assert!(profiles.routers.read().is_empty());
        assert!(profiles.profiles.read().is_empty());
    }
}
