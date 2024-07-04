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

use crate::primitives::{Date, Mapping, Str};

use hashbrown::HashMap;
use nom::{number::complete::be_u8, IResult};

use core::fmt;

/// Router address information.
#[derive(Debug)]
pub struct RouterAddress {
    /// Router cost.
    cost: u8,

    /// When the router expires (always 0).
    expires: Date,

    /// Transport.
    transport: Str,

    /// Options.
    options: HashMap<Str, Str>,
}

impl fmt::Display for RouterAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RouterAddress (cost {}, transport {}, num options {})",
            self.cost,
            self.transport,
            self.options.len()
        )
    }
}

impl RouterAddress {
    /// Parse [`RouterAddress`] from `input`, returning rest of `input` and parsed address.
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], RouterAddress> {
        let (rest, cost) = be_u8(input)?;
        let (rest, expires) = Date::parse_frame(rest)?;
        let (rest, transport) = Str::parse_frame(rest)?;
        let (rest, options) = Mapping::parse_multi_frame(rest)?;

        Ok((
            rest,
            RouterAddress {
                cost,
                expires,
                transport,
                options: Mapping::into_hashmap(options),
            },
        ))
    }

    /// Try to convert `bytes` into a [`RouterAddress`].
    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Option<RouterAddress> {
        Some(Self::parse_frame(bytes.as_ref()).ok()?.1)
    }

    /// Get address cost.
    pub fn cost(&self) -> u8 {
        self.cost
    }

    /// Get address transport.
    pub fn transport(&self) -> &Str {
        &self.transport
    }

    /// Get address options.
    pub fn options(&self) -> &HashMap<Str, Str> {
        &self.options
    }
}
