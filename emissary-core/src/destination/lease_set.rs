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
    primitives::{Lease, TunnelId},
    runtime::Runtime,
};

use futures::{future::BoxFuture, FutureExt};
use hashbrown::HashMap;

use core::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};

/// Lease set republish timeout.
const REPUBLISH_TIMEOUT: Duration = Duration::from_secs(10);

/// [`LeaseSet2`] publish state.
enum PublishState {
    /// Publish state is inactive because there are no pending changes to the [`Destination`]'s
    /// inbound tunnels.
    Inactive,

    /// [`LeaseSetManager`] is awaiting for a timer to expire to publish a new [`LeaseSet2`].
    WaitingForInboundTunnels {
        /// Republish timer.
        timer: BoxFuture<'static, ()>,
    },
}

/// Local lease set manager.
pub struct LeaseSetManager<R: Runtime> {
    /// [`LeaseSet2`] publish state.
    state: PublishState,

    /// Active inbound tunnels.
    tunnels: HashMap<TunnelId, Lease>,

    /// Waker.
    waker: Option<Waker>,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> LeaseSetManager<R> {
    /// Create new [`LeaseSetManager`].
    ///
    /// `tunnels` contains the currently built tunnels and a lease set for these tunnels have
    /// already been created and published if the [`Destination`] is not unpublished.
    pub fn new(tunnels: Vec<Lease>) -> Self {
        Self {
            state: PublishState::Inactive,
            tunnels: HashMap::from_iter(tunnels.into_iter().map(|lease| (lease.tunnel_id, lease))),
            waker: None,
            _runtime: Default::default(),
        }
    }

    /// Register [`Lease`] for a newly built inbound tunnel.
    pub fn register_inbound_tunnel(&mut self, lease: Lease) {
        self.tunnels.insert(lease.tunnel_id, lease.clone());

        match self.state {
            PublishState::Inactive => {
                self.state = PublishState::WaitingForInboundTunnels {
                    timer: Box::pin(R::delay(REPUBLISH_TIMEOUT)),
                };

                if let Some(waker) = self.waker.take() {
                    waker.wake_by_ref();
                }
            }
            _ => {}
        }
    }

    /// Register that an inbound tunnel has expired.
    pub fn register_expired_inbound_tunnel(&mut self, tunnel_id: TunnelId) {
        self.tunnels.remove(&tunnel_id);

        match self.state {
            PublishState::Inactive => {
                self.state = PublishState::WaitingForInboundTunnels {
                    timer: Box::pin(R::delay(REPUBLISH_TIMEOUT)),
                };

                if let Some(waker) = self.waker.take() {
                    waker.wake_by_ref();
                }
            }
            _ => {}
        }
    }
}

impl<R: Runtime> Future for LeaseSetManager<R> {
    type Output = Vec<Lease>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut self.state {
            PublishState::Inactive => {}
            PublishState::WaitingForInboundTunnels { timer } => match timer.poll_unpin(cx) {
                Poll::Pending => {}
                Poll::Ready(_) => {
                    self.state = PublishState::Inactive;
                    return Poll::Ready(self.tunnels.values().cloned().collect());
                }
            },
        }

        self.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use hashbrown::HashSet;

    use super::*;
    use crate::runtime::mock::MockRuntime;

    #[tokio::test]
    async fn inbound_tunnel_registered() {
        let mut manager = LeaseSetManager::<MockRuntime>::new(vec![Lease::random()]);

        assert!(core::matches!(manager.state, PublishState::Inactive));
        assert_eq!(manager.tunnels.len(), 1);

        manager.register_inbound_tunnel(Lease::random());
        assert!(core::matches!(
            manager.state,
            PublishState::WaitingForInboundTunnels { .. }
        ));
        assert_eq!(manager.tunnels.len(), 2);

        manager.register_inbound_tunnel(Lease::random());
        assert!(core::matches!(
            manager.state,
            PublishState::WaitingForInboundTunnels { .. }
        ));
        assert_eq!(manager.tunnels.len(), 3);

        let leases = tokio::time::timeout(REPUBLISH_TIMEOUT + Duration::from_secs(2), &mut manager)
            .await
            .expect("no timeout");
        assert_eq!(leases.len(), 3);
    }

    #[tokio::test]
    async fn inbound_tunnel_expires() {
        let mut manager = LeaseSetManager::<MockRuntime>::new(vec![Lease::random()]);

        assert!(core::matches!(manager.state, PublishState::Inactive));
        assert_eq!(manager.tunnels.len(), 1);

        manager.register_inbound_tunnel(Lease::random());
        assert!(core::matches!(
            manager.state,
            PublishState::WaitingForInboundTunnels { .. }
        ));
        assert_eq!(manager.tunnels.len(), 2);

        manager.register_inbound_tunnel(Lease::random());
        assert!(core::matches!(
            manager.state,
            PublishState::WaitingForInboundTunnels { .. }
        ));
        assert_eq!(manager.tunnels.len(), 3);

        let leases = tokio::time::timeout(REPUBLISH_TIMEOUT + Duration::from_secs(2), &mut manager)
            .await
            .expect("no timeout")
            .into_iter()
            .map(|lease| lease.tunnel_id)
            .collect::<HashSet<_>>();
        assert_eq!(leases.len(), 3);

        // two new inbound tunnels are built
        manager.register_inbound_tunnel(Lease::random());
        manager.register_inbound_tunnel(Lease::random());

        // all original inbound tunnels expire
        for tunnel_id in &leases {
            manager.register_expired_inbound_tunnel(*tunnel_id);
        }

        // wait until the new lease set is published and verify that the expired tunnels no longer
        // exist
        let new_leases =
            tokio::time::timeout(REPUBLISH_TIMEOUT + Duration::from_secs(2), &mut manager)
                .await
                .expect("no timeout");
        assert_eq!(new_leases.len(), 2);
        assert!(new_leases.iter().all(|lease| !leases.contains(&lease.tunnel_id)));
    }
}
