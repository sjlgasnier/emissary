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

//! SAMV3 server implementation.
//!
//! https://geti2p.net/en/docs/api/samv3

use crate::{
    error::Error,
    netdb::NetDbHandle,
    runtime::{MetricsHandle, Runtime, TcpListener},
    tunnel::TunnelManagerHandle,
};

use core::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

use alloc::string::String;

mod socket;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::sam";

/// Minimum supported version of SAMv3.
const MIN_SAMV3_VERSION: &str = "3.1";

/// Maximum supported version of SAMv3.
const MAX_SAMV3_VERSION: &str = "3.3";

/// SAMv3 server.
pub struct SamServer<R: Runtime> {
    /// TCP listener.
    listener: R::TcpListener,

    /// Metrics handle.
    metrics: R::MetricsHandle,

    /// Handle to `NetDb`.
    netdb_handle: NetDbHandle,

    /// Handle to `TunnelManager`.
    tunnel_manager_handle: TunnelManagerHandle,
}

impl<R: Runtime> SamServer<R> {
    /// Create new [`SamServer`]
    pub async fn new(
        tcp_port: u16,
        _udp_port: u16,
        netdb_handle: NetDbHandle,
        tunnel_manager_handle: TunnelManagerHandle,
        metrics: R::MetricsHandle,
    ) -> crate::Result<Self> {
        tracing::info!(
            target: LOG_TARGET,
            ?tcp_port,
            "starting sam server",
        );

        let address = SocketAddr::new(
            "127.0.0.1".parse::<IpAddr>().expect("valid address"),
            tcp_port,
        );
        let listener = R::TcpListener::bind(address)
            .await
            .ok_or(Error::IoError(String::from("failed to bind sam socket")))?;

        Ok(Self {
            listener,
            metrics,
            netdb_handle,
            tunnel_manager_handle,
        })
    }
}

impl<R: Runtime> Future for SamServer<R> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}
