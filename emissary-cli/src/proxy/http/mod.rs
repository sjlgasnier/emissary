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

use crate::config::HttpProxyConfig;

use anyhow::anyhow;
use httparse::{Request, EMPTY_HEADER};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    task::JoinSet,
};
use yosemite::{style::Stream, Session, SessionOptions};

use std::time::Duration;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::proxy::http";

/// HTTP proxy.
pub struct HttpProxy {
    // TCP listener.
    listener: TcpListener,

    /// Inbound requests.
    requests: JoinSet<anyhow::Result<(TcpStream, Vec<u8>)>>,

    /// SAMv3 streaming session for the HTTP proxy.
    session: Session<Stream>,
}

impl HttpProxy {
    /// Create new [`HttpProxy`].
    pub async fn new(config: HttpProxyConfig, samv3_tcp_port: u16) -> crate::Result<Self> {
        tracing::info!(
            target: LOG_TARGET,
            host = %config.host,
            port = %config.port,
            "starting http proxy",
        );

        let listener = TcpListener::bind(format!("{}:{}", config.host, config.port)).await?;
        let session = Session::<Stream>::new(SessionOptions {
            publish: false,
            samv3_tcp_port,
            nickname: "http-proxy".to_string(),
            ..Default::default()
        })
        .await?;

        Ok(Self {
            listener,
            requests: JoinSet::new(),
            session,
        })
    }

    /// Read request from browser.
    ///
    /// Returns a validated raw HTTP request on success.
    async fn read_request(mut stream: TcpStream) -> anyhow::Result<(TcpStream, Vec<u8>)> {
        let mut buffer = vec![0u8; 8192];
        let mut nread = 0usize;

        loop {
            nread += stream.read(&mut buffer[nread..]).await?;

            let mut headers = [EMPTY_HEADER; 64];

            if Request::new(&mut headers).parse(&buffer[..nread])?.is_complete() {
                return Ok((stream, buffer[..nread].to_vec()));
            }
        }
    }

    /// Run event loop of [`HttpProxy`].
    pub async fn run(mut self) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                connection = self.listener.accept() => match connection {
                    Ok((stream, _)) => {
                        self.requests.spawn(async move {
                            match tokio::time::timeout(Duration::from_secs(10), Self::read_request(stream)).await {
                                Err(_) => Err(anyhow!("timeout")),
                                Ok(Err(error)) => Err(anyhow!(error)),
                                Ok(Ok(request)) => Ok(request),
                            }
                        });
                    }
                    Err(error) => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            ?error,
                            "failed to read from socket"
                        );
                    }
                },
                request = self.requests.join_next(), if !self.requests.is_empty() => match request {
                    Some(Ok(Ok((_stream, request)))) => {
                        tracing::info!("{:?}", std::str::from_utf8(&request));
                    }
                    Some(Ok(Err(error))) => tracing::debug!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to read http request",
                    ),
                    Some(Err(error)) => tracing::debug!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to poll http request",
                    ),
                    None => {}
                }
            }
        }
    }
}
