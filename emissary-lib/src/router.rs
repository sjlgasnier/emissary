use crate::{
    runtime::{Runtime, TcpListener},
    transports::ntcp2::Ntcp2Listener,
};

use futures::Stream;

use core::{
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::router";

#[derive(Debug)]
pub enum RouterEvent {}

/// Router.
pub struct Router<R: Runtime> {
    /// Runtime used by the router.
    runtime: R,

    /// NTCP2 listener.
    ntcp2_listener: Ntcp2Listener<R>,
}

impl<R: Runtime> Router<R> {
    /// Create new router.
    pub async fn new(runtime: R) -> crate::Result<Self> {
        tracing::debug!(target: LOG_TARGET, "start router");

        let ntcp2_listener = Ntcp2Listener::<R>::new().await?;

        Ok(Self {
            runtime,
            ntcp2_listener,
        })
    }
}

impl<R: Runtime> Stream for Router<R> {
    type Item = RouterEvent;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Pending
    }
}
