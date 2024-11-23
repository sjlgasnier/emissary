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
    crypto::{SigningPrivateKey, StaticPrivateKey},
    primitives::{Date, Mapping, RouterAddress, RouterIdentity, Str, LOG_TARGET},
    runtime::Runtime,
    Config,
};

use hashbrown::HashMap;
use nom::{
    error::{make_error, ErrorKind},
    number::complete::be_u8,
    Err, IResult,
};
use rand_core::RngCore;

use alloc::{vec, vec::Vec};
use core::str::FromStr;

use super::router_address::TransportKind;

/// Router information
//
// TODO: this should be cheaply clonable
#[derive(Debug, Clone)]
pub struct RouterInfo {
    /// Router identity.
    identity: RouterIdentity,

    /// When the router info was published.
    published: Date,

    /// Router addresses.
    addresses: HashMap<TransportKind, RouterAddress>,

    /// Router options.
    options: HashMap<Str, Str>,
}

// TODO: remove
impl core::fmt::Display for RouterInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "\n------------\n")?;
        write!(f, "RouterInfo\n")?;

        write!(f, "published = {:?}\n", &self.published)?;
        write!(f, "addresess:\n")?;

        for (key, address) in &self.addresses {
            write!(f, "--> {key:?} => {address}")?;
        }

        write!(f, "options:\n")?;
        for (key, value) in &self.options {
            write!(f, "--> {key}={value}\n")?;
        }
        write!(f, "------------")?;

        Ok(())
    }
}

impl RouterInfo {
    pub fn new(now: u64, config: Config) -> Self {
        let Config {
            static_key,
            signing_key,
            ntcp2_config,
            ..
        } = config;

        let identity =
            RouterIdentity::from_keys(static_key.clone(), signing_key).expect("to succeed");

        let ntcp2_config = ntcp2_config.unwrap();
        let ntcp2_port = ntcp2_config.port;
        let ntcp2_host = ntcp2_config.host;
        let ntcp2_key = ntcp2_config.key;
        let ntcp2_iv = ntcp2_config.iv;

        let ntcp2 = RouterAddress::new_published(ntcp2_key, ntcp2_iv, ntcp2_port, ntcp2_host);
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
            addresses: HashMap::from_iter([(TransportKind::Ntcp2, ntcp2)]),
            options,
        }
    }

    fn parse_frame(input: &[u8]) -> IResult<&[u8], RouterInfo> {
        let (rest, identity) = RouterIdentity::parse_frame(input.as_ref())?;
        let (rest, published) = Date::parse_frame(rest)?;
        let (mut rest, num_addresses) = be_u8(rest)?;
        let mut addresses = HashMap::<TransportKind, RouterAddress>::new();

        for _ in 0..num_addresses {
            let (_rest, address) = RouterAddress::parse_frame(rest)?;

            addresses.insert(*address.transport(), address);
            rest = _rest;
        }

        // ignore `peer_size`
        let (rest, _) = be_u8(rest)?;
        let (rest, options) = Mapping::parse_multi_frame(rest)?;

        identity.signing_key().verify(input, rest).or_else(|error| {
            tracing::warn!(
                target: LOG_TARGET,
                ?error,
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

    // TODO: ugliest thing i've seen in my life
    pub fn serialize(&self, signing_key: &SigningPrivateKey) -> Vec<u8> {
        let identity = self.identity.serialize();
        let published = self.published.serialize();
        let ntcp2 = self.addresses.get(&TransportKind::Ntcp2).unwrap().serialize();
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
    //
    // TODO: rename to `parse()`
    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Option<Self> {
        Some(Self::parse_frame(bytes.as_ref()).ok()?.1)
    }

    /// Get reference to router addresses.
    pub fn addresses(&self) -> &HashMap<TransportKind, RouterAddress> {
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

    /// Returns `true` if the router is a floodfill router.
    pub fn is_floodfill(&self) -> bool {
        self.options
            .get(&Str::from_str("caps").expect("valid string"))
            .map_or_else(|| false, |caps| caps.contains("f"))
    }
}

#[cfg(test)]
impl RouterInfo {
    /// Create new random [`RouterInfo`].
    pub fn random<R: Runtime>() -> Self {
        let static_key = {
            let mut key_bytes = vec![0u8; 32];
            R::rng().fill_bytes(&mut key_bytes);

            key_bytes
        };

        let signing_key = {
            let mut key_bytes = vec![0u8; 32];
            R::rng().fill_bytes(&mut key_bytes);

            key_bytes
        };

        Self::from_keys::<R>(static_key, signing_key)
    }

    /// Create new random [`RouterInfo`] for a floodfill router.
    pub fn floodfill<R: Runtime>() -> Self {
        let static_key = {
            let mut key_bytes = vec![0u8; 32];
            R::rng().fill_bytes(&mut key_bytes);

            key_bytes
        };

        let signing_key = {
            let mut key_bytes = vec![0u8; 32];
            R::rng().fill_bytes(&mut key_bytes);

            key_bytes
        };

        let mut info = Self::from_keys::<R>(static_key, signing_key);
        info.options.insert(Str::from("caps"), Str::from("f"));

        info
    }

    /// Create new random [`RouterInfo`] from static and signing keys.
    pub fn from_keys<R: Runtime>(static_key: Vec<u8>, signing_key: Vec<u8>) -> Self {
        let identity = RouterIdentity::from_keys(static_key, signing_key).expect("to succeed");

        // let ntcp2_config = ntcp2_config.unwrap();
        let ntcp2_port = R::rng().next_u32() as u16;
        let ntcp2_host = String::from("127.0.0.1");
        let ntcp2_key = {
            let mut key_bytes = vec![0u8; 32];
            R::rng().fill_bytes(&mut key_bytes);

            key_bytes
        };
        let ntcp2_iv = {
            let mut iv_bytes = [0u8; 16];
            R::rng().fill_bytes(&mut iv_bytes);

            iv_bytes
        };

        let ntcp2 = RouterAddress::new_published(ntcp2_key, ntcp2_iv, ntcp2_port, ntcp2_host);
        let net_id = Mapping::new(Str::from_str("netId").unwrap(), Str::from_str("2").unwrap());
        let caps = Mapping::new(Str::from_str("caps").unwrap(), Str::from_str("L").unwrap());
        let router_version = Mapping::new(
            Str::from_str("router.version").unwrap(),
            Str::from_str("0.9.62").unwrap(),
        );
        let options = Mapping::into_hashmap(vec![net_id, caps, router_version]);

        RouterInfo {
            identity,
            published: Date::new(R::rng().next_u64()),
            addresses: HashMap::from_iter([(TransportKind::Ntcp2, ntcp2)]),
            options,
        }
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
        assert_eq!(
            router_info.addresses.get(&TransportKind::Ssu2).unwrap().cost(),
            10
        );
        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ssu2)
                .unwrap()
                .options()
                .get(&Str::from_str("host").unwrap()),
            Some(&Str::from_str("217.70.194.82").unwrap())
        );
        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ssu2)
                .unwrap()
                .options()
                .get(&Str::from_str("port").unwrap()),
            Some(&Str::from_str("10994").unwrap())
        );

        // ntcp2
        assert_eq!(
            router_info.addresses.get(&TransportKind::Ntcp2).unwrap().cost(),
            14
        );
        assert!(router_info
            .addresses
            .get(&TransportKind::Ntcp2)
            .unwrap()
            .options()
            .get(&Str::from_str("host").unwrap())
            .is_none());
        assert!(router_info
            .addresses
            .get(&TransportKind::Ntcp2)
            .unwrap()
            .options()
            .get(&Str::from_str("port").unwrap())
            .is_none());

        // options
        assert_eq!(
            router_info.options.get(&Str::from_str("router.version").unwrap()),
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
        assert_eq!(
            router_info.addresses.get(&TransportKind::Ssu2).unwrap().cost(),
            10
        );
        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ssu2)
                .unwrap()
                .options()
                .get(&Str::from_str("host").unwrap()),
            Some(&Str::from_str("68.202.112.209").unwrap())
        );
        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ssu2)
                .unwrap()
                .options()
                .get(&Str::from_str("port").unwrap()),
            Some(&Str::from_str("11331").unwrap())
        );

        // ntcp2
        assert_eq!(
            router_info.addresses.get(&TransportKind::Ntcp2).unwrap().cost(),
            3
        );
        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ntcp2)
                .unwrap()
                .options()
                .get(&Str::from_str("host").unwrap()),
            Some(&Str::from_str("68.202.112.209").unwrap())
        );
        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ntcp2)
                .unwrap()
                .options()
                .get(&Str::from_str("port").unwrap()),
            Some(&Str::from_str("11331").unwrap())
        );

        // options
        assert_eq!(
            router_info.options.get(&Str::from_str("router.version").unwrap()),
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

    #[test]
    fn is_not_floodfill() {
        let router_info_bytes = include_bytes!("../../test-vectors/router2.dat");

        assert!(!RouterInfo::from_bytes(router_info_bytes).unwrap().is_floodfill())
    }

    #[test]
    fn is_floodfill() {
        let router_info_bytes = include_bytes!("../../test-vectors/router4.dat");

        assert!(RouterInfo::from_bytes(router_info_bytes).unwrap().is_floodfill())
    }
}
