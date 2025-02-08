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
use reqwest::{
    header::{HeaderMap, HeaderValue, CONNECTION},
    Client, Proxy,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use std::{
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

/// Logging target for the file
const LOG_TARGET: &str = "emissary::address-book";

/// Address book.
pub struct AddressBookManager {
    /// Path to address book.
    address_book_path: &'static str,

    /// URL which hosts.txt is downloaded from.
    hosts_url: String,
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
        }
    }

    /// Get opaque handling implementing [`AddressBook`].
    pub fn handle(&self) -> Arc<dyn AddressBook> {
        Arc::new(AddressBookHandle {
            address_book_path: self.address_book_path,
        })
    }

    /// Start event loop for [`AddressBookManager`].
    pub async fn start(self, http_port: u16, http_host: String) {
        if Path::new(self.address_book_path).exists() {
            tracing::debug!(
                target: LOG_TARGET,
                "address book exists, skipping download",
            );
            return;
        }

        tracing::info!(
            target: LOG_TARGET,
            ?http_port,
            ?http_host,
            hosts_url = ?self.hosts_url,
            "create address book",
        );

        loop {
            let client = Client::builder()
                .proxy(Proxy::http(format!("http://{http_host}:{http_port}")).expect("to succeed"))
                .build()
                .expect("to succeed");

            let response = match client
                .get(format!("{}", self.hosts_url))
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
                        server = ?self.hosts_url,
                        ?error,
                        "failed to fetch hosts.txt"
                    );
                    tokio::time::sleep(Duration::from_secs(15)).await;
                    continue;
                }
                Ok(response) => response,
            };

            if !response.status().is_success() {
                tracing::debug!(
                    target: LOG_TARGET,
                    server = ?self.hosts_url,
                    status = ?response.status(),
                    "request to address book server failed",
                );
                tokio::time::sleep(Duration::from_secs(15)).await;
                continue;
            }

            let response = match response.bytes().await {
                Ok(response) => response,
                Err(error) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        server = ?self.hosts_url,
                        ?error,
                        "failed to get response from address book server"
                    );
                    tokio::time::sleep(Duration::from_secs(15)).await;
                    continue;
                }
            };

            let mut file = tokio::fs::File::create(self.address_book_path).await.unwrap();
            file.write_all(&response).await.unwrap();
            break;
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
