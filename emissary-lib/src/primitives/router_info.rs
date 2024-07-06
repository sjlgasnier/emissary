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
    crypto::SigningPrivateKey,
    primitives::{Date, Mapping, RouterAddress, RouterIdentity, Str, LOG_TARGET},
    Config,
};

use hashbrown::HashMap;
use nom::{
    error::{make_error, ErrorKind},
    number::complete::be_u8,
    Err, IResult,
};

use alloc::{vec, vec::Vec};
use core::str::FromStr;

/// Router information
pub struct RouterInfo {
    /// Router identity.
    identity: RouterIdentity,

    /// When the router info was published.
    published: Date,

    /// Router addresses.
    addresses: Vec<RouterAddress>,

    /// Router options.
    options: HashMap<Str, Str>,
}

impl RouterInfo {
    pub fn new(now: u64, config: Config) -> Self {
        let Config {
            static_key,
            signing_key,
            ..
        } = config;

        tracing::error!(
            "static key len = {}, signing key len = {}",
            static_key.len(),
            signing_key.len()
        );

        let identity =
            RouterIdentity::from_keys(static_key.clone(), signing_key).expect("to succeed");
        let ntcp2 = RouterAddress::new_unpublished(static_key);
        let net_id = Mapping::new(Str::from_str("netId").unwrap(), Str::from_str("2").unwrap());
        let caps = Mapping::new(Str::from_str("caps").unwrap(), Str::from_str("L").unwrap());
        let router_version = Mapping::new(
            Str::from_str("router.version").unwrap(),
            Str::from_str("0.9.62").unwrap(),
        );
        let options = Mapping::into_hashmap(vec![net_id, caps, router_version]);

        RouterInfo {
            identity,
            published: Date::new(now),
            addresses: vec![ntcp2],
            options,
        }
    }

    fn parse_frame(input: &[u8]) -> IResult<&[u8], RouterInfo> {
        let (rest, identity) = RouterIdentity::parse_frame(input.as_ref())?;
        let (rest, published) = Date::parse_frame(rest)?;
        let (mut rest, num_addresses) = be_u8(rest)?;
        let mut addresses = Vec::<RouterAddress>::new();

        for _ in 0..num_addresses {
            let (_rest, address) = RouterAddress::parse_frame(rest)?;

            addresses.push(address);
            rest = _rest;
        }

        // ignore `peer_size`
        let (rest, _) = be_u8(rest)?;
        let (rest, options) = Mapping::parse_multi_frame(rest)?;

        identity.signing_key().verify(input, rest).or_else(|_| {
            tracing::warn!(
                target: LOG_TARGET,
                "invalid signature for router info",
            );
            Err(Err::Error(make_error(input, ErrorKind::Fail)))
        })?;

        Ok((
            rest,
            RouterInfo {
                identity,
                published,
                addresses,
                options: Mapping::into_hashmap(options),
            },
        ))
    }

    // TODO: zzz
    pub fn serialize(&self, signing_key: SigningPrivateKey) -> Vec<u8> {
        let identity = self.identity.serialize();
        let published = self.published.serialize();
        let ntcp2 = self.addresses[0].serialize();
        let options = self
            .options
            .clone()
            .into_iter()
            .map(|(key, value)| Mapping::new(key, value).serialize())
            .flatten()
            .collect::<Vec<_>>();

        let size = identity.len() + published.len() + ntcp2.len() + options.len() + 4 + 64;
        let mut out = vec![0u8; size];

        out[..391].copy_from_slice(&identity);
        out[391..399].copy_from_slice(&published);
        out[399] = 1;
        out[400..400 + ntcp2.len()].copy_from_slice(&ntcp2);
        out[400 + ntcp2.len()] = 0;

        let mapping_size = (options.len() as u16).to_be_bytes().to_vec();
        out[400 + ntcp2.len() + 1..400 + ntcp2.len() + 3].copy_from_slice(&mapping_size);
        out[400 + ntcp2.len() + 3..400 + ntcp2.len() + 3 + options.len()].copy_from_slice(&options);

        let signature = signing_key.sign(&out[..size - 64]);
        out[400 + ntcp2.len() + 3 + options.len()..400 + ntcp2.len() + 3 + options.len() + 64]
            .copy_from_slice(&signature);

        out
    }

    /// Try to parse router information from `bytes`.
    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Option<Self> {
        Some(Self::parse_frame(bytes.as_ref()).ok()?.1)
    }

    /// Get reference to router addresses.
    pub fn addresses(&self) -> &Vec<RouterAddress> {
        &self.addresses
    }

    /// Get reference to router options.
    pub fn options(&self) -> &HashMap<Str, Str> {
        &self.options
    }

    /// Get reference to [`RouterIdentity`](super::RouterIdentity)
    pub fn identity(&self) -> &RouterIdentity {
        &self.identity
    }

    /// Get reference to router's publish date.
    pub fn date(&self) -> &Date {
        &self.published
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    #[test]
    fn parse_router_1() {
        let router_info_bytes = include_bytes!("../../test-vectors/router1.dat");
        let router_info = RouterInfo::from_bytes(router_info_bytes).unwrap();

        assert_eq!(router_info.addresses.len(), 2);

        // ssu
        assert_eq!(router_info.addresses[0].cost(), 10);
        assert_eq!(
            router_info.addresses[0].transport(),
            &Str::from_str("SSU").unwrap()
        );
        assert_eq!(
            router_info.addresses[0]
                .options()
                .get(&Str::from_str("host").unwrap()),
            Some(&Str::from_str("217.70.194.82").unwrap())
        );
        assert_eq!(
            router_info.addresses[0]
                .options()
                .get(&Str::from_str("port").unwrap()),
            Some(&Str::from_str("10994").unwrap())
        );

        // ntcp2
        assert_eq!(router_info.addresses[1].cost(), 14);
        assert_eq!(
            router_info.addresses[1].transport(),
            &Str::from_str("NTCP2").unwrap()
        );
        assert!(router_info.addresses[1]
            .options()
            .get(&Str::from_str("host").unwrap())
            .is_none());
        assert!(router_info.addresses[1]
            .options()
            .get(&Str::from_str("port").unwrap())
            .is_none());

        // options
        assert_eq!(
            router_info
                .options
                .get(&Str::from_str("router.version").unwrap()),
            Some(&Str::from_str("0.9.42").unwrap())
        );
        assert_eq!(
            router_info.options.get(&Str::from_str("caps").unwrap()),
            Some(&Str::from_str("LU").unwrap())
        );
        assert_eq!(
            router_info.options.get(&Str::from_str("netId").unwrap()),
            Some(&Str::from_str("2").unwrap())
        );
    }

    #[test]
    fn parse_router_2() {
        let router_info_bytes = include_bytes!("../../test-vectors/router2.dat");
        let router_info = RouterInfo::from_bytes(router_info_bytes).unwrap();

        assert_eq!(router_info.addresses.len(), 2);

        // ssu
        assert_eq!(router_info.addresses[0].cost(), 10);
        assert_eq!(
            router_info.addresses[0].transport(),
            &Str::from_str("SSU").unwrap()
        );
        assert_eq!(
            router_info.addresses[0]
                .options()
                .get(&Str::from_str("host").unwrap()),
            Some(&Str::from_str("68.202.112.209").unwrap())
        );
        assert_eq!(
            router_info.addresses[0]
                .options()
                .get(&Str::from_str("port").unwrap()),
            Some(&Str::from_str("11331").unwrap())
        );

        // ntcp2
        assert_eq!(router_info.addresses[1].cost(), 3);
        assert_eq!(
            router_info.addresses[1].transport(),
            &Str::from_str("NTCP2").unwrap()
        );
        assert_eq!(
            router_info.addresses[1]
                .options()
                .get(&Str::from_str("host").unwrap()),
            Some(&Str::from_str("68.202.112.209").unwrap())
        );
        assert_eq!(
            router_info.addresses[1]
                .options()
                .get(&Str::from_str("port").unwrap()),
            Some(&Str::from_str("11331").unwrap())
        );

        // options
        assert_eq!(
            router_info
                .options
                .get(&Str::from_str("router.version").unwrap()),
            Some(&Str::from_str("0.9.46").unwrap())
        );
        assert_eq!(
            router_info.options.get(&Str::from_str("caps").unwrap()),
            Some(&Str::from_str("LR").unwrap())
        );
        assert_eq!(
            router_info.options.get(&Str::from_str("netId").unwrap()),
            Some(&Str::from_str("2").unwrap())
        );
    }

    #[test]
    fn parse_router_3() {
        let router_info_bytes = include_bytes!("../../test-vectors/router3.dat");
        assert!(RouterInfo::from_bytes(router_info_bytes).is_none());
    }
}
