// Copyright 2018-2019 Parity Technologies (UK) Ltd.
// Copyright 2023 litep2p developers
//
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

//! Kademlia k-bucket implementation.

use crate::{
    netdb::types::{FloodFill, Key},
    primitives::RouterId,
    runtime::{Instant, Runtime},
};

use alloc::vec::Vec;
use core::time::Duration;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::netdb::k-bucket";

/// Eviction threshold.
const EVICTION_THRESHOLD: Duration = Duration::from_secs(10 * 60);

/// K-bucket entry.
#[derive(Debug, PartialEq, Eq)]
pub enum KBucketEntry<'a, R: Runtime> {
    /// Entry points to local node.
    LocalNode,

    /// Occupied entry to a connected node.
    Occupied(&'a mut FloodFill<R>),

    /// Vacant entry.
    Vacant(&'a mut FloodFill<R>),

    /// Entry not found and any present entry cannot be replaced.
    NoSlot,
}

impl<'a, R: Runtime> KBucketEntry<'a, R> {
    /// Insert new entry into the entry if possible.
    pub fn insert(&'a mut self, new: FloodFill<R>) {
        if let KBucketEntry::Vacant(old) = self {
            old.key = Key::from(new.key.into_preimage());
            old.last_update = R::now();
        }
    }
}

/// Kademlia k-bucket.
pub struct KBucket<R: Runtime> {
    /// Floodfill routers of the bucket.
    floodfills: Vec<FloodFill<R>>,
}

impl<R: Runtime> KBucket<R> {
    /// Create new [`KBucket`].
    pub fn new() -> Self {
        Self {
            floodfills: Vec::with_capacity(20),
        }
    }

    /// Get entry into the bucket.
    pub fn entry(&mut self, key: Key<RouterId>) -> KBucketEntry<'_, R> {
        for i in 0..self.floodfills.len() {
            if self.floodfills[i].key == key {
                return KBucketEntry::Occupied(&mut self.floodfills[i]);
            }
        }

        if self.floodfills.len() < 20 {
            self.floodfills.push(FloodFill::new(key.preimage().clone()));

            let len = self.floodfills.len() - 1;
            return KBucketEntry::Vacant(&mut self.floodfills[len]);
        }

        for i in 0..self.floodfills.len() {
            if self.floodfills[i].last_update.elapsed() > EVICTION_THRESHOLD {
                tracing::debug!(
                    target: LOG_TARGET,
                    router_id = %self.floodfills[i].key.preimage(),
                    index = ?i,
                    "evicting floodfill router from k-bucket"
                );

                return KBucketEntry::Vacant(&mut self.floodfills[i]);
            }
        }

        KBucketEntry::NoSlot
    }

    /// Get iterator over the k-bucket, sorting the k-bucket entries in increasing order
    /// by distance.
    pub fn closest_iter<K: Clone>(&self, target: &Key<K>) -> impl Iterator<Item = RouterId> {
        let mut floodfills = self.floodfills.clone();

        floodfills.sort_by(|a, b| target.distance(&a.key).cmp(&target.distance(&b.key)));
        floodfills.into_iter().map(|router| router.key.preimage().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;

    #[test]
    fn closest_iter() {
        let mut bucket = KBucket::<MockRuntime>::new();

        // add some random nodes to the bucket
        let _ = (0..10)
            .map(|_| {
                let peer = RouterId::random();
                bucket.floodfills.push(FloodFill::new(RouterId::random()));

                peer
            })
            .collect::<Vec<_>>();

        let target = Key::from(RouterId::random());
        let mut iter = bucket.closest_iter(&target);
        let mut prev = None;

        while let Some(router_id) = iter.next() {
            if let Some(distance) = prev {
                assert!(distance < target.distance(&Key::from(router_id.clone())));
            }

            prev = Some(target.distance(&Key::from(router_id)));
        }
    }

    #[test]
    fn old_floodfill_router_evicted() {
        let mut bucket = KBucket::<MockRuntime>::new();

        let _ = (0..20)
            .map(|_| {
                let peer = RouterId::random();
                bucket.floodfills.push(FloodFill::new(RouterId::random()));

                peer
            })
            .collect::<Vec<_>>();

        // try to add new floodfill router to k-bucket
        let router_id = RouterId::random();
        let key = Key::from(router_id.clone());
        assert_eq!(bucket.entry(key.clone()), KBucketEntry::NoSlot);

        // expire one floodfill router
        bucket.floodfills[2].last_update =
            MockRuntime::now().subtract(Duration::from_secs(20 * 60));

        // verify new peer is added
        let mut slot = bucket.entry(key.clone());
        assert!(std::matches!(slot, KBucketEntry::Vacant(_)));

        slot.insert(FloodFill::new(router_id));
        assert!(std::matches!(
            bucket.entry(key.clone()),
            KBucketEntry::Occupied(_)
        ));
    }
}
