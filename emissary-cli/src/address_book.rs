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

#![allow(unused)]

use emissary_core::runtime::AddressBook;
use reqwest::{
    header::{HeaderMap, HeaderValue, CONNECTION, USER_AGENT},
    Client,
};

use std::{future::Future, path::PathBuf, pin::Pin, sync::Arc};

/// Address book.
pub struct AddressBookManager {
    /// Path to address book.
    address_book: &'static str,
}

impl AddressBookManager {
    /// Create new [`AddressBookManager`].
    pub fn new(base_path: PathBuf) -> Self {
        Self {
            address_book: base_path
                .join("addressbook/addresses")
                .to_str()
                .expect("to succeed")
                .to_string()
                .leak(),
        }
    }

    /// Get opaque handling implementing [`AddressBook`].
    pub fn handle(&self) -> Arc<dyn AddressBook> {
        Arc::new(AddressBookHandle {
            address_book: self.address_book,
        })
    }

    /// Start event loop for [`AddressBookManager`].
    pub async fn start(self, http_port: u16, http_host: String) {
        todo!();
    }
}

#[derive(Clone)]
pub struct AddressBookHandle {
    /// Path to address book.
    address_book: &'static str,
}

impl AddressBook for AddressBookHandle {
    fn resolve(&self, name: String) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send>> {
        Box::pin(async move { None })
    }
}
