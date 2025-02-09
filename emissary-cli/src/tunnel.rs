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

use crate::config::TunnelConfig;

use tokio::net::TcpListener;
use yosemite::{style, Session, SessionOptions, StreamOptions};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::client-tunnel";

/// Client tunnel.
pub struct Tunnel;

impl Tunnel {
    /// Create new [`Tunnel`].
    pub async fn start(config: TunnelConfig, samv3_tcp_port: u16) -> crate::Result<()> {
        tracing::info!(
            target: LOG_TARGET,
            name = %config.name,
            address = ?config.address,
            port = %config.port,
            destination = %config.destination,
            "starting client tunnel",
        );

        let mut session = Session::<style::Stream>::new(SessionOptions {
            publish: false,
            samv3_tcp_port,
            nickname: config.name,
            ..Default::default()
        })
        .await?;

        let mut i2p_stream = session
            .connect_with_options(
                &config.destination,
                StreamOptions {
                    dst_port: config.destination_port.unwrap_or(0),
                    ..Default::default()
                },
            )
            .await?;
        let listener = TcpListener::bind(format!(
            "{}:{}",
            config.address.unwrap_or(String::from("127.0.0.1")),
            config.port
        ))
        .await?;
        let (mut tcp_stream, _) = listener.accept().await?;

        tokio::io::copy_bidirectional(&mut i2p_stream, &mut tcp_stream).await?;

        Ok(())
    }
}
