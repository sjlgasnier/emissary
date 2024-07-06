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

use crate::{
    crypto::{base64_encode, StaticPublicKey},
    primitives::{Date, Mapping, Str},
};

use hashbrown::HashMap;
use nom::{number::complete::be_u8, IResult};

use alloc::{vec, vec::Vec};
use core::{fmt, str::FromStr};

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
            "RouterAddress (cost {}, transport {}, num options {})\n",
            self.cost,
            self.transport,
            self.options.len()
        )?;

        write!(f, "addresses:\n")?;
        for (key, value) in &self.options {
            write!(f, "--> {key}={value}\n")?;
        }

        Ok(())
    }
}

impl RouterAddress {
    /// Create new unpublished [`RouterAddress`].
    pub fn new_unpublished(static_key: Vec<u8>) -> Self {
        let static_key = StaticPublicKey::from_private_x25519(&static_key).unwrap();
        let key = base64_encode(&static_key.to_vec());

        let mut options = HashMap::<Str, Str>::new();
        options.insert(Str::from_str("v").unwrap(), Str::from_str("2").unwrap());
        options.insert(Str::from_str("s").unwrap(), Str::from_str(&key).unwrap());

        Self {
            cost: 10,
            expires: Date::new(0),
            transport: Str::from_str("NTCP2").unwrap(),
            options,
        }
    }

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

    // TODO: zzz
    pub fn serialize(&self) -> Vec<u8> {
        let options = self
            .options
            .clone()
            .into_iter()
            .map(|(key, value)| Mapping::new(key, value).serialize())
            .flatten()
            .collect::<Vec<_>>();

        let transport = self.transport.clone().serialize();
        let size = (options.len() as u16).to_be_bytes().to_vec();
        let mut out = vec![0u8; 1 + 8 + transport.len() + options.len() + 2];

        out[0] = self.cost;
        out[1..9].copy_from_slice(&self.expires.serialize());
        out[9..9 + transport.len()].copy_from_slice(&transport);
        out[9 + transport.len()..9 + transport.len() + 2].copy_from_slice(&size);
        out[9 + transport.len() + 2..9 + transport.len() + 2 + options.len()]
            .copy_from_slice(&options);

        out
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
