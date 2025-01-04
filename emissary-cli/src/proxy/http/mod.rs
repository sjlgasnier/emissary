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
use futures::{AsyncReadExt, AsyncWriteExt};
use httparse::EMPTY_HEADER;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    task::JoinSet,
};
use yosemite::{style, Session, SessionOptions, Stream};

use std::{sync::LazyLock, time::Duration};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::proxy::http";

/// Illegal HTTP headers that get removed from the inbound HTTP request.
static ILLEGAL: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    Vec::from_iter([
        "accept",
        "referer",
        "x-requested-with",
        "via",
        "from",
        "forwarded",
        "dnt",
        "x-forwarded",
        "proxy-",
    ])
});

/// Parsed request.
struct Request {
    /// TCP stream.
    stream: TcpStream,

    /// Host.
    host: String,

    /// Serialized request.
    request: Vec<u8>,
}

/// HTTP proxy.
pub struct HttpProxy {
    // TCP listener.
    listener: TcpListener,

    /// Inbound requests.
    requests: JoinSet<anyhow::Result<Request>>,

    /// Outbound responses.
    responses: JoinSet<anyhow::Result<()>>,

    /// SAMv3 streaming session for the HTTP proxy.
    session: Session<style::Stream>,
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

        Ok(Self {
            listener: TcpListener::bind(format!("{}:{}", config.host, config.port)).await?,
            requests: JoinSet::new(),
            responses: JoinSet::new(),
            session: Session::<style::Stream>::new(SessionOptions {
                publish: false,
                samv3_tcp_port,
                nickname: "http-proxy".to_string(),
                ..Default::default()
            })
            .await?,
        })
    }

    /// Read request from browser.
    ///
    /// Reads the full request received from browser, parses it, removes any "prohibited" headers
    /// and reconstructs a new HTTP request that needs to be send to the requested destination,
    /// specified in the `Host` field of the original request.
    async fn read_request(mut stream: TcpStream) -> anyhow::Result<Request> {
        let mut buffer = vec![0u8; 8192];
        let mut nread = 0usize;

        // read from `stream` until complete request has been received
        loop {
            nread += stream.read(&mut buffer[nread..]).await?;

            let mut headers = [EMPTY_HEADER; 64];
            if httparse::Request::new(&mut headers).parse(&buffer[..nread])?.is_complete() {
                break;
            }
        }

        // parse request and create a new request with sanitized headers
        let request = &buffer[..nread].to_vec();
        let mut headers = [EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let body_start = req.parse(&request)?.unwrap();
        let host = req.path.ok_or(anyhow!("path not specified"))?.to_owned();

        tracing::trace!(
            target: LOG_TARGET,
            method = ?req.method,
            %host,
            num_headers = ?req.headers.len(),
            "inbound request",
        );

        let builder = req.headers.into_iter().fold(
            http::Request::builder()
                .method(req.method.ok_or(anyhow!("method not specified"))?)
                .uri(host.clone()),
            |builder, header| {
                if header.name.to_lowercase() == "user-agent" {
                    return builder.header("User-Agent", "MYOB/6.66 (AN/ON)");
                }

                if header.name.to_lowercase() == "accept-encoding" {
                    return builder.header(header.name, header.value);
                }

                if header.name.to_lowercase() == "connection" {
                    return builder.header(header.name, "close");
                }

                if ILLEGAL.iter().any(|illegal| header.name.to_lowercase().starts_with(illegal)) {
                    return builder;
                }

                builder.header(header.name, header.value)
            },
        );

        let request = if body_start > request.len() {
            builder.body(request[body_start..].to_vec())
        } else {
            builder.body(Vec::new())
        }?;

        Ok(Request {
            stream,
            host,
            request: {
                // serialize request into a byte vector
                let (parts, body) = request.into_parts();
                let mut request = Vec::new();

                request.extend_from_slice(&format!("{} ", parts.method.to_string()).as_bytes());
                request.extend_from_slice(&format!("{} ", parts.uri.to_string()).as_bytes());
                request.extend_from_slice(&"HTTP/1.1\r\n".as_bytes());

                for (name, value) in parts.headers {
                    if let (Some(name), value) = (name, value) {
                        request.extend_from_slice(&format!("{name}: ").as_bytes());
                        request.extend_from_slice(value.as_bytes());
                        request.extend_from_slice("\r\n".as_bytes());
                    }
                }
                request.extend_from_slice("\r\n".as_bytes());
                request.extend_from_slice(&body);

                request
            },
        })
    }

    /// Send `request` to remote destination over `i2p_stream`, read the full HTTP response
    /// and send it to the browser.
    async fn send_response(
        mut stream: TcpStream,
        mut i2p_stream: Stream,
        request: Vec<u8>,
    ) -> anyhow::Result<()> {
        let mut buffer = vec![0u8; 2048];

        // write request and read from the stream until it is closed
        i2p_stream.write_all(&request).await?;

        loop {
            match i2p_stream.read(&mut buffer).await {
                Ok(0) | Err(_) => {
                    break;
                }
                Ok(nread) => {
                    stream.write_all(&buffer[..nread]).await?;
                }
            };
        }

        Ok(())
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
                    Some(Ok(Ok(request))) => match self.session.connect(&request.host).await {
                        Ok(stream) => {
                            self.responses.spawn(Self::send_response(request.stream, stream, request.request));
                        }
                        Err(error) => tracing::debug!(
                            target: LOG_TARGET,
                            ?error,
                            "failed to connect to destination",
                        ),
                    },
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
