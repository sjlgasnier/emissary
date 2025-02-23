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

use crate::config::AddressBookConfig;

use emissary_core::runtime::AddressBook;
use futures::channel::oneshot;
use reqwest::{
    header::{HeaderMap, HeaderValue, CONNECTION},
    Client, Proxy,
};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
};

use std::{
    collections::HashMap, future::Future, path::PathBuf, pin::Pin, sync::Arc, time::Duration,
};

/// Logging target for the file
const LOG_TARGET: &str = "emissary::address-book";

/// Backoff if downloading the hosts file fails.
const RETRY_BACKOFF: Duration = Duration::from_secs(30);

/// How many times each subscription is tried before giving up.
const SUBSCRIPTION_NUM_RETRIES: usize = 5usize;

/// Address book.
pub struct AddressBookManager {
    /// Path to address book.
    address_book_path: &'static str,

    /// URL from which the primary `hosts.txt` is downloaded from.
    hosts_url: String,

    /// Additional subscriptions.
    subscriptions: Vec<String>,
}

impl AddressBookManager {
    /// Create new [`AddressBookManager`].
    pub fn new(base_path: PathBuf, config: AddressBookConfig) -> Self {
        Self {
            address_book_path: base_path
                .join("addressbook/addresses")
                .to_str()
                .expect("to succeed")
                .to_string()
                .leak(),
            hosts_url: config.default,
            subscriptions: config.subscriptions,
        }
    }

    /// Get opaque handling implementing [`AddressBook`].
    pub fn handle(&self) -> Arc<dyn AddressBook> {
        Arc::new(AddressBookHandle {
            address_book_path: self.address_book_path,
        })
    }

    /// Attempt to download `hosts.txt` from `url`.
    async fn download(client: &Client, url: &str) -> Option<String> {
        let response = match client
            .get(format!("{}", url))
            .headers(HeaderMap::from_iter([(
                CONNECTION,
                HeaderValue::from_static("close"),
            )]))
            .send()
            .await
        {
            Err(error) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?url,
                    ?error,
                    "failed to fetch hosts.txt"
                );
                return None;
            }
            Ok(response) => response,
        };

        if !response.status().is_success() {
            tracing::debug!(
                target: LOG_TARGET,
                ?url,
                status = ?response.status(),
                "request to address book server failed",
            );
            return None;
        }

        match response.bytes().await {
            Ok(response) => match std::str::from_utf8(&response) {
                Ok(response) => Some(response.to_owned()),
                Err(error) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?url,
                        ?error,
                        "failed to convert `hosts.txt` to utf-8",
                    );
                    None
                }
            },
            Err(error) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?url,
                    ?error,
                    "failed to get response from address book server"
                );
                return None;
            }
        }
    }

    /// Parse `hosts` into (key, value) tuple and merge it with `addresses`.
    ///
    /// Addresses already present in `addresses` will be ignored.
    async fn parse_and_merge(&self, addresses: &mut HashMap<String, String>, hosts: String) {
        for line in hosts.lines() {
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim().to_string();

                if addresses.contains_key(&key) {
                    tracing::trace!(
                        target: LOG_TARGET,
                        %key,
                        "skipping already-existing address",
                    );
                } else {
                    addresses.insert(key.trim().to_string(), value.trim().to_string());
                }
            }
        }

        match File::create(&self.address_book_path).await {
            Err(error) => tracing::error!(
                target: LOG_TARGET,
                ?error,
                "failed to open address book",
            ),
            Ok(mut file) => {
                let address_book = addresses.iter().fold(Vec::new(), |mut out, (key, value)| {
                    out.extend_from_slice(format!("{key}={value}\n").as_bytes());
                    out
                });

                if let Err(error) = file.write_all(&address_book).await {
                    tracing::error!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to write to address book",
                    );
                }
            }
        }
    }

    /// Start event loop for [`AddressBookManager`].
    ///
    /// Before the address book subscription download starts, [`AddressBook`] waits on
    /// `http_proxy_ready_rx` which the HTTP proxy sends a signal to once it's ready.
    pub async fn run(
        self,
        http_port: u16,
        http_host: String,
        http_proxy_ready_rx: oneshot::Receiver<()>,
    ) {
        if let Err(error) = http_proxy_ready_rx.await {
            tracing::error!(
                target: LOG_TARGET,
                ?error,
                "http proxy failed to start, cannot start address book",
            );
        }

        tracing::info!(
            target: LOG_TARGET,
            ?http_port,
            ?http_host,
            default = ?self.hosts_url,
            subscriptions = ?self.subscriptions,
            "create address book",
        );

        let client = Client::builder()
            .proxy(Proxy::http(format!("http://{http_host}:{http_port}")).expect("to succeed"))
            .http1_title_case_headers()
            .build()
            .expect("to succeed");

        let mut addresses = HashMap::<String, String>::new();

        loop {
            match Self::download(&client, &self.hosts_url).await {
                Some(hosts) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        url = %self.hosts_url,
                        "hosts.txt downloaded",
                    );

                    self.parse_and_merge(&mut addresses, hosts).await;
                    break;
                }
                None => tokio::time::sleep(RETRY_BACKOFF).await,
            }
        }

        for subscription in &self.subscriptions {
            for _ in 0..SUBSCRIPTION_NUM_RETRIES {
                match Self::download(&client, &subscription).await {
                    Some(hosts) => {
                        tracing::info!(
                            target: LOG_TARGET,
                            url = subscription,
                            "hosts.txt downloaded",
                        );

                        self.parse_and_merge(&mut addresses, hosts).await;
                        break;
                    }
                    None => tokio::time::sleep(RETRY_BACKOFF).await,
                }
            }
        }
    }
}

/// Address book handle.
#[derive(Clone)]
pub struct AddressBookHandle {
    /// Path to address book.
    address_book_path: &'static str,
}

impl AddressBook for AddressBookHandle {
    fn resolve(&self, host: String) -> Pin<Box<dyn Future<Output = Option<String>> + Send>> {
        let path = self.address_book_path;

        Box::pin(async move {
            let file = tokio::fs::File::open(path).await.ok()?;
            let mut reader = BufReader::new(file).lines();

            while let Ok(line) = reader.next_line().await {
                if let Some((key, value)) = line?.split_once('=') {
                    if key.trim() == host {
                        return Some(value.trim().to_string());
                    }
                }
            }

            None
        })
    }
}
