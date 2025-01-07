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
        routers: HashSet<RouterId>,
        metrics: R::MetricsHandle,
    ) -> Self {
        let mut routing_table = RoutingTable::new(Key::from(local_router_id));

        routers.into_iter().for_each(|router_id| {
            routing_table.add_router(router_id);
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

    /// Insert new router into [`Dht`].
    pub fn add_router(&mut self, router_id: RouterId) {
        self.routing_table.add_router(router_id);
    }

    /// Remove router from [`Dht`].
    #[allow(unused)]
    pub fn remove_router(&mut self, router_id: RouterId) {
        self.routing_table.remove_router(router_id);
    }

    /// Get `limit` many routers clost to `key`.
    pub fn closest(
        &mut self,
        key: impl AsRef<[u8]>,
        limit: usize,
    ) -> impl Iterator<Item = RouterId> + '_ {
        let target =
            Key::from(Sha256::new().update(&key).update(Self::utc_date().as_str()).finalize());

        self.routing_table.closest(target, limit)
    }

    /// Get closest routers to `key`.
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

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::{
        crypto::{base32_decode, base64_decode},
        runtime::mock::MockRuntime,
    };

    #[test]
    fn lookup() {
        let routers = HashSet::from_iter([
            RouterId::from(&base64_decode("4wlqrFG46mv7ujZi18KwEf9uJz2MgOIebdMMxDHsh~0=").unwrap()),
            RouterId::from(&base64_decode("909NkRdvZz4UnYKrEdkcPR0-nyjgIyXfcltdus3KbvI=").unwrap()),
            RouterId::from(&base64_decode("9FpLdQFPuslwleztm87UKZm9voRCErVkC5tQIzTIveE=").unwrap()),
            RouterId::from(&base64_decode("A27bo5gy~L8C9dMPm24YNVkQkkPUqr3jz74-zkHjr4E=").unwrap()),
            RouterId::from(&base64_decode("AFHNc~4qEeDC0pX35aKVZXlJYejqXlwIavJkb51X7Hw=").unwrap()),
            RouterId::from(&base64_decode("gOcHmAy4wEnAwiB5MGdVZUFMSd8R4xVXShLlLMK33ak=").unwrap()),
            RouterId::from(&base64_decode("-HrTE27w0UKFx98GgdKhZDtNzFAaqquctMvuUjwqKnw=").unwrap()),
            RouterId::from(&base64_decode("JT58CgCdJNk9Y9PiykRx7wz9cZIEI7a68sDNV8MBsLk=").unwrap()),
            RouterId::from(&base64_decode("o6~ANVCIdIiUomPN-GxHscI6KetllgsecHFFWNIzFYM=").unwrap()),
            RouterId::from(&base64_decode("o6Ax4-AapSSlKGTzDW8R6qUldj7sg9AszSYlvTxApwI=").unwrap()),
            RouterId::from(&base64_decode("O8Ih-eljywJJ-mQpn4Al1y~GQKU25nvlPRzktoeRnPQ=").unwrap()),
            RouterId::from(&base64_decode("o8qvvGZroVu1Jlo-9ICTamn5t8XlnNq49oJ2QywLVUQ=").unwrap()),
            RouterId::from(&base64_decode("QRbIdWrPvAp58Qf~asFdm1s-oz9NDmwimu61pndVpNY=").unwrap()),
            RouterId::from(&base64_decode("QVGqliH7Pdye7P7UAtM~fKQIfjKOzKbMVvhdKVSGlQ8=").unwrap()),
            RouterId::from(&base64_decode("x4Q9dpbvHfyUuIhK9xDiy1XL9lvrpe9Kmmy9Gg~wFeQ=").unwrap()),
        ]);
        let mut dht = Dht::<MockRuntime>::new(
            RouterId::random(),
            routers,
            MockRuntime::register_metrics(Vec::new(), None),
        );

        let key = Bytes::from(
            base32_decode("shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa").unwrap(),
        );
        let target = Key::from(Sha256::new().update(&key).update("20250105").finalize());
        let closest = dht.routing_table.closest(target, 3usize).collect::<Vec<_>>();

        assert_eq!(
            closest[0],
            RouterId::from(&base64_decode("o6~ANVCIdIiUomPN-GxHscI6KetllgsecHFFWNIzFYM=").unwrap())
        );
        assert_eq!(
            closest[1],
            RouterId::from(&base64_decode("o6Ax4-AapSSlKGTzDW8R6qUldj7sg9AszSYlvTxApwI=").unwrap())
        );
        assert_eq!(
            closest[2],
            RouterId::from(&base64_decode("o8qvvGZroVu1Jlo-9ICTamn5t8XlnNq49oJ2QywLVUQ=").unwrap())
        );
    }
}
