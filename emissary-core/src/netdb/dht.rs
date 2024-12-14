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
    crypto::sha256::Sha256,
    netdb::{routing_table::RoutingTable, types::Key},
    primitives::RouterId,
    runtime::Runtime,
};

use chrono::DateTime;
use hashbrown::HashSet;

use alloc::string::{String, ToString};

/// Kademlia DHT implementation.
pub struct Dht<R: Runtime> {
    /// Kademlia routing table.
    routing_table: RoutingTable<R>,

    /// Metrics handle.
    #[allow(unused)]
    metrics: R::MetricsHandle,
}

impl<R: Runtime> Dht<R> {
    /// Create new [`Dht`].
    pub fn new(
        local_router_id: RouterId,
        floodfills: HashSet<RouterId>,
        metrics: R::MetricsHandle,
    ) -> Self {
        let mut routing_table = RoutingTable::new(Key::from(local_router_id));

        floodfills.into_iter().for_each(|router_id| {
            routing_table.add_floodfill(router_id);
        });

        Self {
            routing_table,
            metrics,
        }
    }

    /// Get today's UTC date.
    fn utc_date() -> String {
        DateTime::from_timestamp(R::time_since_epoch().as_secs() as i64, 0u32)
            .expect("to succeed")
            .format("%Y%m%d")
            .to_string()
    }

    /// Insert new floodfill into [`Dht`].
    pub fn add_floodfill(&mut self, router_id: RouterId) {
        self.routing_table.add_floodfill(router_id);
    }

    /// Get `limit` many floodfills clost to `key`.
    pub fn closest(
        &mut self,
        key: impl AsRef<[u8]>,
        limit: usize,
    ) -> impl Iterator<Item = RouterId> + '_ {
        let target =
            Key::from(Sha256::new().update(&key).update(Self::utc_date().as_str()).finalize());

        self.routing_table.closest(target, limit)
    }

    /// Get closest floodfills to `key`.
    pub fn closest_with_ignore<'a>(
        &'a mut self,
        key: impl AsRef<[u8]>,
        limit: usize,
        ignore: &'a HashSet<RouterId>,
    ) -> impl Iterator<Item = RouterId> + 'a {
        let target =
            Key::from(Sha256::new().update(&key).update(Self::utc_date().as_str()).finalize());

        self.routing_table.closest_with_ignore(target, limit, ignore)
    }
}
