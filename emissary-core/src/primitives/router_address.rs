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

use bytes::{BufMut, BytesMut};
use hashbrown::HashMap;
use nom::{
    error::{make_error, ErrorKind},
    number::complete::be_u8,
    Err, IResult,
};

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

/// Transport kind.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum TransportKind {
    /// NTCP2.
    Ntcp2,

    /// SSU2.
    Ssu2,
}

impl TryFrom<Str> for TransportKind {
    type Error = ();

    fn try_from(value: Str) -> Result<Self, Self::Error> {
        if value.starts_with("SSU") {
            return Ok(TransportKind::Ssu2);
        }

        if value.starts_with("NTCP2") {
            return Ok(TransportKind::Ntcp2);
        }

        Err(())
    }
}

impl TransportKind {
    /// Serialize [`TransportKind`].
    fn serialize(&self) -> Vec<u8> {
        match self {
            Self::Ntcp2 => Str::from("NTCP2").serialize(),
            Self::Ssu2 => Str::from("SSU2").serialize(),
        }
    }
}

/// Router address.
#[derive(Debug, Clone)]
pub struct RouterAddress {
    /// Router cost.
    pub cost: u8,

    /// When the router expires (always 0).
    pub expires: Date,

    /// Transport.
    pub transport: TransportKind,

    /// Options.
    pub options: HashMap<Str, Str>,

    /// Router's socket address.
    pub socket_address: Option<SocketAddr>,
}

impl RouterAddress {
    /// Create new unpublished [`RouterAddress`].
    pub fn new_unpublished(static_key: Vec<u8>) -> Self {
        let static_key = StaticPublicKey::from_private_x25519(&static_key).unwrap();
        let key = base64_encode(static_key.to_vec());

        let mut options = HashMap::<Str, Str>::new();
        options.insert(Str::from_str("v").unwrap(), Str::from_str("2").unwrap());
        options.insert(Str::from_str("s").unwrap(), Str::from_str(&key).unwrap());

        Self {
            cost: 10,
            expires: Date::new(0),
            transport: TransportKind::Ntcp2,
            socket_address: None,
            options,
        }
    }

    /// Create new unpublished [`RouterAddress`].
    pub fn new_published(key: Vec<u8>, iv: [u8; 16], port: u16, host: String) -> Self {
        // conversion must succeed since `key` is managed by us
        let static_key = StaticPublicKey::from_private_x25519(&key).expect("to succeed");

        let mut options = HashMap::<Str, Str>::new();
        options.insert(Str::from("v"), Str::from("2"));
        options.insert(
            Str::from("s"),
            Str::from(base64_encode(static_key.to_vec())),
        );
        options.insert(Str::from("host"), Str::from(host.clone()));
        options.insert(Str::from("port"), Str::from(port.to_string()));
        options.insert(Str::from("i"), Str::from(base64_encode(iv)));

        Self {
            cost: 10,
            expires: Date::new(0),
            transport: TransportKind::Ntcp2,
            options,
            socket_address: Some(SocketAddr::new(
                host.parse::<IpAddr>().expect("valid address"),
                port,
            )),
        }
    }

    /// Parse [`RouterAddress`] from `input`, returning rest of `input` and parsed address.
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], RouterAddress> {
        let (rest, cost) = be_u8(input)?;
        let (rest, expires) = Date::parse_frame(rest)?;
        let (rest, transport) = Str::parse_frame(rest)?;
        let (rest, options) = Mapping::parse_multi_frame(rest)?;
        let options = Mapping::into_hashmap(options);
        let socket_address: Option<SocketAddr> = {
            let maybe_host = options.get(&Str::from("host"));
            let maybe_port = options.get(&Str::from("port"));

            match (maybe_host, maybe_port) {
                (Some(host), Some(port)) => {
                    let port = port.parse::<u16>().ok();
                    let host = host.parse::<IpAddr>().ok();

                    match (host, port) {
                        (Some(host), Some(port)) => Some(SocketAddr::new(host, port)),
                        (host, port) => {
                            tracing::warn!(
                                ?host,
                                ?port,
                                "failed to parse address into `SocketAddr`",
                            );
                            None
                        }
                    }
                }
                _ => {
                    tracing::warn!(
                        ?maybe_host,
                        ?maybe_port,
                        "ntcp2 host/port info not available",
                    );
                    None
                }
            }
        };

        Ok((
            rest,
            RouterAddress {
                cost,
                expires,
                transport: TransportKind::try_from(transport)
                    .map_err(|_| Err::Error(make_error(input, ErrorKind::Fail)))?,
                options,
                socket_address,
            },
        ))
    }

    /// Try to convert `bytes` into a [`RouterAddress`].
    pub fn parse(bytes: impl AsRef<[u8]>) -> Option<RouterAddress> {
        Some(Self::parse_frame(bytes.as_ref()).ok()?.1)
    }

    /// Serialize [`RouterAddress`].
    pub fn serialize(&self) -> BytesMut {
        let options = {
            let mut options = self.options.clone().into_iter().collect::<Vec<_>>();
            options.sort_by(|a, b| a.0.cmp(&b.0));

            options
                .into_iter()
                .flat_map(|(key, value)| Mapping::new(key, value).serialize())
                .collect::<Vec<_>>()
        };

        let transport = self.transport.serialize();
        let mut out = BytesMut::with_capacity(1 + 8 + transport.len() + options.len() + 2);

        out.put_u8(self.cost);
        out.put_slice(&self.expires.serialize());
        out.put_slice(&transport);
        out.put_u16(options.len() as u16);
        out.put_slice(&options);

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_deserialize_unpublished() {
        let serialized = RouterAddress::new_unpublished(vec![1u8; 32]).serialize();
        let static_key = StaticPublicKey::from_private_x25519(&vec![1u8; 32]).expect("to succeed");

        let address = RouterAddress::parse(&serialized).unwrap();
        assert_eq!(address.cost, 10);
        assert_eq!(
            address.options.get(&Str::from("s")),
            Some(&Str::from(base64_encode(static_key.to_vec())))
        );
        assert_eq!(address.options.get(&Str::from("v")), Some(&Str::from("2")));
        assert!(address.options.get(&Str::from("i")).is_none());
        assert!(address.options.get(&Str::from("host")).is_none());
        assert!(address.options.get(&Str::from("port")).is_none());
    }

    #[test]
    fn serialize_deserialize_published() {
        let serialized = RouterAddress::new_published(
            vec![1u8; 32],
            [0xaa; 16],
            8888,
            String::from("127.0.0.1"),
        )
        .serialize();
        let static_key = StaticPublicKey::from_private_x25519(&vec![1u8; 32]).expect("to succeed");

        let address = RouterAddress::parse(&serialized).unwrap();
        assert_eq!(address.cost, 10);
        assert_eq!(
            address.options.get(&Str::from("i")),
            Some(&Str::from(base64_encode(&[0xaa; 16])))
        );
        assert_eq!(
            address.options.get(&Str::from("s")),
            Some(&Str::from(base64_encode(static_key.to_vec())))
        );
        assert_eq!(address.options.get(&Str::from("v")), Some(&Str::from("2")));
        assert_eq!(
            address.options.get(&Str::from("host")),
            Some(&Str::from("127.0.0.1"))
        );
        assert_eq!(
            address.options.get(&Str::from("port")),
            Some(&Str::from("8888"))
        );
    }
}
