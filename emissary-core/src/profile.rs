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
    runtime::Runtime,
};

use hashbrown::{HashMap, HashSet};

#[cfg(feature = "std")]
use parking_lot::{RwLock, RwLockReadGuard};
#[cfg(feature = "no_std")]
use spin::rwlock::{RwLock, RwLockReadGuard};

use alloc::{string::String, sync::Arc, vec::Vec};
use core::{marker::PhantomData, time::Duration};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::profile";

/// Router bucket.
pub enum Bucket {
    /// Any bucket.
    Any,

    /// Fast bucket.
    Fast,

    /// Standard bucket.
    Standard,
}

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
    /// Create new [`Profile`].
    fn new() -> Self {
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

    /// Is the router considered failing.
    pub fn is_failing(&self) -> bool {
        false
    }
}

/// Router info/profile reader.
pub struct Reader<'a> {
    /// Read access to router infos.
    router_infos: RwLockReadGuard<'a, HashMap<RouterId, RouterInfo>>,

    /// Read access to profiles.
    _profiles: RwLockReadGuard<'a, HashMap<RouterId, Profile>>,
}

impl<'a> Reader<'a> {
    /// Get reference to [`RouterInfo`].
    pub fn router_info(&self, router_id: &RouterId) -> &RouterInfo {
        // router info must exist since they're managed by us
        self.router_infos.get(router_id).expect("to succeed")
    }
}

/// Profile storage.
#[derive(Clone)]
pub struct ProfileStorage<R: Runtime> {
    /// Fast routers.
    fast: Arc<RwLock<HashSet<RouterId>>>,

    /// Router profiles.
    profiles: Arc<RwLock<HashMap<RouterId, Profile>>>,

    /// Router infos.
    routers: Arc<RwLock<HashMap<RouterId, RouterInfo>>>,

    /// Standard routers.
    standard: Arc<RwLock<HashSet<RouterId>>>,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> ProfileStorage<R> {
    /// Create new [`ProfileStorage`].
    pub fn new(routers: &[Vec<u8>], profiles: &[(String, Profile)]) -> Self {
        tracing::info!(
            target: LOG_TARGET,
            num_routers = ?routers.len(),
            num_profiles = ?profiles.len(),
            "initialize profile storage",
        );

        let routers = routers
            .iter()
            .filter_map(|router| {
                RouterInfo::parse(router).map(|router| (router.identity.id(), router))
            })
            .collect::<HashMap<_, _>>();

        let mut profiles = profiles
            .iter()
            .filter_map(|(router_id, profile)| {
                let router_id =
                    RouterId::from(base64_decode(router_id).expect("valid base64 name"));

                routers.contains_key(&router_id).then_some((router_id, *profile))
            })
            .collect::<HashMap<_, _>>();

        // empty profiles for all routers whose profiles were not found
        routers.keys().for_each(|router_id| {
            if !profiles.contains_key(router_id) {
                profiles.insert(router_id.clone(), Profile::new());
            }
        });

        // split router infos into fast and standard buckets and filter out unusable routers
        let (fast, standard): (Vec<_>, Vec<_>) = routers
            .iter()
            .filter_map(|(router_id, router_info)| {
                if !router_info.is_reachable() || !router_info.capabilities.is_usable() {
                    return None;
                }

                match router_info.capabilities.is_fast() {
                    true => Some((Some(router_id.clone()), None)),
                    false => Some((None, Some(router_id.clone()))),
                }
            })
            .unzip();

        Self {
            fast: Arc::new(RwLock::new(fast.into_iter().flatten().collect())),
            profiles: Arc::new(RwLock::new(profiles)),
            routers: Arc::new(RwLock::new(routers)),
            standard: Arc::new(RwLock::new(standard.into_iter().flatten().collect())),
            _runtime: Default::default(),
        }
    }

    /// Insert `router` into [`ProfileStorage`].
    pub fn add_router(&self, router_info: RouterInfo) {
        let router_id = router_info.identity.id();

        if !router_info.is_reachable_ntcp2() {
            tracing::debug!(
                target: LOG_TARGET,
                %router_id,
                caps = %router_info.capabilities,
                "cannot add router, ntcp2 address is not reachable",
            );
            return;
        }

        if !router_info.is_reachable() || !router_info.capabilities.is_usable() {
            tracing::trace!(
                target: LOG_TARGET,
                %router_id,
                caps = %router_info.capabilities,
                "adding potentially unreachable/unusable router",
            );
        }

        {
            let mut fast = self.fast.write();
            let mut standard = self.standard.write();

            if router_info.capabilities.is_fast() {
                fast.insert(router_id.clone());
                standard.remove(&router_id);
            } else {
                standard.insert(router_id.clone());
                fast.remove(&router_id);
            }
        }

        if self.routers.write().insert(router_id.clone(), router_info).is_none() {
            self.profiles.write().insert(router_id, Profile::new());
        }
    }

    // TODO: remove
    pub fn get(&self, router: &RouterId) -> Option<RouterInfo> {
        self.routers.read().get(router).cloned()
    }

    /// Get `RouterId`s of those routers that pass `filter`.
    pub fn get_router_ids(
        &self,
        bucket: Bucket,
        filter: impl Fn(&RouterId, &RouterInfo, &Profile) -> bool,
    ) -> Vec<RouterId> {
        let routers = self.routers.read();
        let profiles = self.profiles.read();

        match bucket {
            Bucket::Any => {
                let fast = self.fast.read();
                let standard = self.standard.read();

                fast.iter()
                    .chain(standard.iter())
                    .filter_map(|router_id| {
                        // profile & router info must exist since they're managed by us
                        let profile = profiles.get(router_id).expect("to exist");
                        let router_info = routers.get(router_id).expect("to exist");

                        filter(router_id, router_info, profile).then_some(router_id.clone())
                    })
                    .collect()
            }
            Bucket::Fast => {
                let fast = self.fast.read();

                fast.iter()
                    .filter_map(|router_id| {
                        // profile & router info must exist since they're managed by us
                        let profile = profiles.get(router_id).expect("to exist");
                        let router_info = routers.get(router_id).expect("to exist");

                        filter(router_id, router_info, profile).then_some(router_id.clone())
                    })
                    .collect()
            }
            Bucket::Standard => {
                let standard = self.standard.read();

                standard
                    .iter()
                    .filter_map(|router_id| {
                        // profile & router info must exist since they're managed by us
                        let profile = profiles.get(router_id).expect("to exist");
                        let router_info = routers.get(router_id).expect("to exist");

                        filter(router_id, router_info, profile).then_some(router_id.clone())
                    })
                    .collect()
            }
        }
    }

    /// Get [`Reader`].
    pub fn reader(&self) -> Reader {
        Reader {
            router_infos: self.routers.read(),
            _profiles: self.profiles.read(),
        }
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

    /// Record that `router_id` accepted a tunnel build request.
    #[allow(unused)]
    pub fn tunnel_build_accepted(&self, router_id: &RouterId) {
        let mut inner = self.profiles.write();

        // profile must exist since it's controlled by us
        let profile = inner.get_mut(router_id).expect("to exist");

        profile.num_accepted += 1;
        profile.last_activity = R::time_since_epoch();
    }

    /// Record that `router_id` rejected a tunnel build request.
    #[allow(unused)]
    pub fn tunnel_build_rejected(&self, router_id: &RouterId) {
        let mut inner = self.profiles.write();

        // profile must exist since it's controlled by us
        let profile = inner.get_mut(router_id).expect("to exist");

        profile.num_rejected += 1;
        profile.last_activity = R::time_since_epoch();
    }

    /// Record that `router_id` failed to answer a tunnel build request.
    #[allow(unused)]
    pub fn tunnel_build_not_answered(&self, router_id: &RouterId) {
        let mut inner = self.profiles.write();

        // profile must exist since it's controlled by us
        let profile = inner.get_mut(router_id).expect("to exist");

        profile.num_unaswered += 1;
        profile.last_activity = R::time_since_epoch();
    }

    /// Record test success for a tunnel that `router_id` was a participant of.
    #[allow(unused)]
    pub fn tunnel_test_succeeded(&self, router_id: &RouterId) {
        let mut inner = self.profiles.write();

        // profile must exist since it's controlled by us
        let profile = inner.get_mut(router_id).expect("to exist");

        profile.num_test_successes += 1;
        profile.last_activity = R::time_since_epoch();
    }

    /// Record test failure for a tunnel that `router_id` was a participant of.
    #[allow(unused)]
    pub fn tunnel_test_failed(&self, router_id: &RouterId) {
        let mut inner = self.profiles.write();

        // profile must exist since it's controlled by us
        let profile = inner.get_mut(router_id).expect("to exist");

        profile.num_test_failures += 1;
        profile.last_activity = R::time_since_epoch();
    }

    /// Record dial success for `router_id`.
    ///
    /// Profile might not exist if this is an inbound connection.
    pub fn dial_succeeded(&self, router_id: &RouterId) {
        let mut inner = self.profiles.write();

        match inner.get_mut(router_id) {
            Some(profile) => {
                profile.num_connection += 1;
                profile.last_activity = R::time_since_epoch();
            }
            None => {
                let mut profile = Profile::new();
                profile.num_connection += 1;
                profile.last_activity = R::time_since_epoch();

                inner.insert(router_id.clone(), profile);
            }
        }
    }

    /// Record dial failure for `router_id`.
    ///
    /// Profile might not exist if this is an inbound connection.
    pub fn dial_failed(&self, router_id: &RouterId) {
        let mut inner = self.profiles.write();

        match inner.get_mut(router_id) {
            Some(profile) => {
                profile.num_dial_failures += 1;
                profile.last_activity = R::time_since_epoch();
            }
            None => {
                let mut profile = Profile::new();
                profile.num_dial_failures += 1;
                profile.last_activity = R::time_since_epoch();

                inner.insert(router_id.clone(), profile);
            }
        }
    }
}

#[cfg(test)]
impl<R: Runtime> ProfileStorage<R> {
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

        // split router infos into fast and standard buckets and filter out unusable routers
        let (fast, standard): (Vec<_>, Vec<_>) = routers
            .iter()
            .filter_map(|(router_id, router_info)| {
                if !router_info.is_reachable() || !router_info.capabilities.is_usable() {
                    return None;
                }

                match router_info.capabilities.is_fast() {
                    true => Some((Some(router_id.clone()), None)),
                    false => Some((None, Some(router_id.clone()))),
                }
            })
            .unzip();

        Self {
            fast: Arc::new(RwLock::new(fast.into_iter().flatten().collect())),
            profiles: Arc::new(RwLock::new(profiles)),
            routers: Arc::new(RwLock::new(routers)),
            standard: Arc::new(RwLock::new(standard.into_iter().flatten().collect())),
            _runtime: Default::default(),
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

        let profiles = ProfileStorage::<MockRuntime>::new(&infos, &Vec::new());

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

        let profiles = ProfileStorage::<MockRuntime>::new(&infos, &profiles);

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

        let profiles = ProfileStorage::<MockRuntime>::new(&Vec::new(), &profiles);

        assert!(profiles.routers.read().is_empty());
        assert!(profiles.profiles.read().is_empty());
    }

    #[test]
    fn create_profile_if_it_doesnt_exist() {
        let profiles = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());
        let router_id = RouterId::random();

        assert!(profiles.routers.read().is_empty());
        assert!(profiles.profiles.read().is_empty());

        profiles.dial_succeeded(&router_id);

        let reader = profiles.reader();
        assert_eq!(
            reader._profiles.get(&router_id).unwrap().num_connection,
            1usize
        );
    }
}
