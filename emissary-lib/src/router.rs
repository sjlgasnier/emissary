use crate::{
    crypto::SigningPrivateKey, primitives::RouterInfo, runtime::Runtime,
    transports::ntcp2::Ntcp2Listener, Config,
};

use futures::Stream;

use alloc::vec::Vec;
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
    pub async fn new(runtime: R, config: Config, router: Vec<u8>) -> crate::Result<Self> {
        tracing::debug!(target: LOG_TARGET, "start router, router size = {}", router.len());

        let router = RouterInfo::from_bytes(router).unwrap();
        let now = R::time_since_epoch().unwrap().as_millis() as u64;
        let ss: [u8; 32] = config.static_key.clone().try_into().unwrap();
        let ss = x25519_dalek::StaticSecret::from(ss);
        let test = config.signing_key.clone();
        let key = SigningPrivateKey::new(&test).unwrap();
        let local_info = RouterInfo::new(now, config).serialize(key);

        // let test = RouterInfo::from_bytes(&local_info).unwrap();
        // tracing::info!(%test);

        let ntcp2_listener = Ntcp2Listener::<R>::new(router, local_info, ss).await?;
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
