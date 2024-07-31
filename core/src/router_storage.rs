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

use crate::primitives::{RouterId, RouterInfo};

use hashbrown::HashMap;
use spin::rwlock::RwLock;

use alloc::{sync::Arc, vec::Vec};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::router-storage";

/// Router storage.
#[derive(Clone)]
pub struct RouterStorage {
    routers: Arc<RwLock<HashMap<RouterId, RouterInfo>>>,
}

impl RouterStorage {
    /// Create new [`RouterStorage`].
    pub fn new(routers: &Vec<Vec<u8>>) -> Self {
        let routers = routers
            .into_iter()
            .filter_map(|router| {
                RouterInfo::from_bytes(router).map(|router| (router.identity().id(), router))
            })
            .collect::<HashMap<_, _>>();

        tracing::info!(
            target: "emissary::router-storage",
            num_routers = ?routers.len(),
            "initialize router storage",
        );

        Self {
            routers: Arc::new(RwLock::new(routers)),
        }
    }

    /// Return the number of routers in [`RouterStorage`].
    pub fn len(&self) -> usize {
        self.routers.read().len()
    }

    /// Get `RouterInfo` of `router` if it exists.
    //
    // TODO: no clones
    pub fn get(&self, router: &RouterId) -> Option<RouterInfo> {
        self.routers.read().get(router).map(|router_info| router_info.clone())
    }

    // TODO: zzz
    pub fn get_routers(
        &self,
        num_routers: usize,
        filter: impl Fn(&RouterId, &RouterInfo) -> bool,
    ) -> Vec<RouterInfo> {
        let this = self.routers.read();

        this.iter()
            .filter_map(|(router, info)| filter(router, info).then_some(info.clone()))
            .take(num_routers)
            .collect()
    }

    /// Create new [`RouterStorage`] from random `routers`.
    ///
    /// Only used in tests.
    #[cfg(test)]
    pub fn from_random(routers: Vec<RouterInfo>) -> Self {
        let routers = routers
            .into_iter()
            .map(|router| (router.identity().id(), router))
            .collect::<HashMap<_, _>>();

        Self {
            routers: Arc::new(RwLock::new(routers)),
        }
    }
}
