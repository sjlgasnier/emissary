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

use alloc::{string::String, vec::Vec};

pub enum Transport {
    Enabled { port: u16, host: Option<String> },
    Disabled,
}

/// NTCP2 configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct Ntcp2Config {
    /// NTCP2 port.
    pub port: u16,

    /// NTCP2 listen address.
    pub host: String,

    /// NTCP2 key.
    pub key: Vec<u8>,

    /// NTCP2 IV.
    pub iv: [u8; 16],
}

/// Router configuration.
pub struct Config {
    /// Router static key.
    pub static_key: Vec<u8>,

    /// Router signing key.
    pub signing_key: Vec<u8>,

    /// NTCP2 config
    pub ntcp2_config: Option<Ntcp2Config>,

    /// Known routers.
    pub routers: Vec<Vec<u8>>,
}
