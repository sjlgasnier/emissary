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
    config::Config,
    crypto::{SigningPrivateKey, StaticPrivateKey},
    primitives::{
        router_address::TransportKind, Capabilities, Date, Mapping, RouterAddress, RouterIdentity,
        Str, LOG_TARGET,
    },
    runtime::Runtime,
};

use bytes::{BufMut, BytesMut};
use hashbrown::HashMap;
use nom::{
    error::{make_error, ErrorKind},
    number::complete::be_u8,
    Err, IResult,
};

use alloc::{string::ToString, vec, vec::Vec};

/// Signature length.
const SIGNATURE_LEN: usize = 64usize;

/// Router information
#[derive(Debug, Clone)]
pub struct RouterInfo {
    /// Router addresses.
    pub addresses: HashMap<TransportKind, RouterAddress>,

    /// Router capabilities.
    pub capabilities: Capabilities,

    /// Router identity.
    pub identity: RouterIdentity,

    /// Network ID.
    pub net_id: u8,

    /// Router options.
    pub options: HashMap<Str, Str>,

    /// When the router info was published.
    pub published: Date,
}

impl RouterInfo {
    /// Create new [`RouterInfo`].
    ///
    /// `ntcp2` is `Some` if NTCP has been enabled.
    pub fn new<R: Runtime>(
        config: &Config,
        ntcp2: Option<RouterAddress>,
        ssu2: Option<RouterAddress>,
        static_key: &StaticPrivateKey,
        signing_key: &SigningPrivateKey,
    ) -> Self {
        let Config {
            caps, router_info, ..
        } = config;

        let identity = match router_info {
            None => {
                tracing::debug!(
                    target: LOG_TARGET,
                    "generating new router identity",
                );

                RouterIdentity::from_keys::<R>(static_key, signing_key).expect("to succeed")
            }
            Some(router_info) => RouterIdentity::parse(router_info).expect("to succeed"),
        };

        let net_id = Mapping::new(
            Str::from("netId"),
            config
                .net_id
                .map_or_else(|| Str::from("2"), |value| Str::from(value.to_string())),
        );

        let caps = match caps {
            Some(caps) => Str::from(caps.clone()),
            None => match config.floodfill {
                true => Str::from("Xf"),
                false => Str::from("L"),
            },
        };

        let router_version = Mapping::new(Str::from("router.version"), Str::from("0.9.62"));
        let caps_mapping = Mapping::new(Str::from("caps"), caps.clone());
        let options = Mapping::into_hashmap(vec![net_id, caps_mapping, router_version]);

        RouterInfo {
            addresses: {
                let mut addresses = HashMap::<TransportKind, RouterAddress>::new();

                if let Some(ntcp2) = ntcp2 {
                    addresses.insert(TransportKind::Ntcp2, ntcp2);
                }

                if let Some(ssu2) = ssu2 {
                    addresses.insert(TransportKind::Ssu2, ssu2);
                }

                addresses
            },
            capabilities: Capabilities::parse(&caps).expect("to succeed"),
            identity,
            net_id: config.net_id.unwrap_or(2),
            options,
            published: Date::new(R::time_since_epoch().as_millis() as u64),
        }
    }

    fn parse_frame(input: &[u8]) -> IResult<&[u8], RouterInfo> {
        let (rest, identity) = RouterIdentity::parse_frame(input)?;
        let (rest, published) = Date::parse_frame(rest)?;
        let (rest, num_addresses) = be_u8(rest)?;
        let (rest, addresses) = (0..num_addresses)
            .try_fold(
                (rest, HashMap::<TransportKind, RouterAddress>::new()),
                |(rest, mut addresses), _| {
                    let (rest, address) = RouterAddress::parse_frame(rest).ok()?;

                    // prefer `RouterAddress` which has a socket address specified
                    match addresses.get(&address.transport) {
                        None => {
                            addresses.insert(address.transport, address);
                        }
                        Some(old_address) =>
                            if old_address.socket_address.is_none() {
                                addresses.insert(address.transport, address);
                            },
                    }

                    Some((rest, addresses))
                },
            )
            .ok_or_else(|| {
                tracing::warn!(
                    target: LOG_TARGET,
                    "failed to parse router addresses",
                );
                Err::Error(make_error(input, ErrorKind::Fail))
            })?;

        // ignore `peer_size`
        let (rest, _) = be_u8(rest)?;
        let (rest, options) = Mapping::parse_multi_frame(rest)?;
        let options = Mapping::into_hashmap(options);

        let capabilities = match options.get(&Str::from("caps")) {
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    "router capabilities missing",
                );
                return Err(Err::Error(make_error(input, ErrorKind::Fail)));
            }
            Some(caps) => match Capabilities::parse(caps) {
                Some(caps) => caps,
                None => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        %caps,
                        "invalid capabilities",
                    );
                    return Err(Err::Error(make_error(input, ErrorKind::Fail)));
                }
            },
        };

        let net_id = match options.get(&Str::from("netId")) {
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    "network id not specified",
                );
                return Err(Err::Error(make_error(input, ErrorKind::Fail)));
            }
            Some(net_id) => match net_id.parse::<u8>() {
                Ok(net_id) => net_id,
                Err(error) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        %net_id,
                        ?error,
                        "failed to parse net id",
                    );
                    return Err(Err::Error(make_error(input, ErrorKind::Fail)));
                }
            },
        };

        identity
            .signing_key()
            .verify(&input[..input.len() - SIGNATURE_LEN], rest)
            .map_err(|error| {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?error,
                    "invalid signature for router info",
                );
                Err::Error(make_error(input, ErrorKind::Fail))
            })?;

        Ok((
            rest,
            RouterInfo {
                identity,
                published,
                addresses,
                options,
                capabilities,
                net_id,
            },
        ))
    }

    /// Serialize [`RouterInfo`] into a byte vector.
    pub fn serialize(&self, signing_key: &SigningPrivateKey) -> Vec<u8> {
        let identity = self.identity.serialize();
        let published = self.published.serialize();
        let maybe_ntcp2 =
            self.addresses.get(&TransportKind::Ntcp2).map(|address| address.serialize());
        let maybe_ssu2 =
            self.addresses.get(&TransportKind::Ssu2).map(|address| address.serialize());
        let options = {
            let mut options = self.options.clone().into_iter().collect::<Vec<_>>();
            options.sort_by(|a, b| a.0.cmp(&b.0));

            options
                .into_iter()
                .flat_map(|(key, value)| Mapping::new(key, value).serialize())
                .collect::<Vec<_>>()
        };

        let size = identity
            .len()
            .saturating_add(published.len())
            .saturating_add(1usize) // field for router address count
            .saturating_add(maybe_ntcp2.as_ref().map_or(0usize, |address| address.len()))
            .saturating_add(maybe_ssu2.as_ref().map_or(0usize, |address| address.len()))
            .saturating_add(options.len())
            .saturating_add(1usize) // psize
            .saturating_add(2usize) // field for options size
            .saturating_add(64usize); // signature

        let mut out = BytesMut::with_capacity(size);

        out.put_slice(&identity);
        out.put_slice(&published);

        match (maybe_ntcp2, maybe_ssu2) {
            (Some(ntcp2), Some(ssu2)) => {
                out.put_u8(2u8);
                out.put_slice(&ntcp2);
                out.put_slice(&ssu2);
            }
            (Some(info), None) | (None, Some(info)) => {
                out.put_u8(1u8);
                out.put_slice(&info);
            }
            (None, None) => panic!("tried to publish router info with no addresses"),
        }

        out.put_u8(0u8); // psize
        out.put_u16(options.len() as u16);
        out.put_slice(&options);

        let signature = signing_key.sign(&out[..size - 64]);
        out.put_slice(&signature);

        out.to_vec()
    }

    /// Try to parse router information from `bytes`.
    pub fn parse(bytes: impl AsRef<[u8]>) -> Option<Self> {
        Some(Self::parse_frame(bytes.as_ref()).ok()?.1)
    }

    /// Returns `true` if the router is a floodfill router.
    pub fn is_floodfill(&self) -> bool {
        self.capabilities.is_floodfill()
    }

    /// Returns `true` if the router is considered reachable.
    ///
    /// Router is considered reachable if its caps don't specify otherwise and it has at least one
    /// published address.
    pub fn is_reachable(&self) -> bool {
        if !self.capabilities.is_reachable() {
            return false;
        }

        if let Some(ntcp2) = self.addresses.get(&TransportKind::Ntcp2) {
            if ntcp2.options.get(&Str::from("host")).is_some()
                && ntcp2.options.get(&Str::from("port")).is_some()
            {
                return true;
            }
        }

        if let Some(ssu2) = self.addresses.get(&TransportKind::Ssu2) {
            if ssu2.options.get(&Str::from("host")).is_some()
                && ssu2.options.get(&Str::from("port")).is_some()
            {
                return true;
            }
        }

        false
    }

    /// Is the router usable.
    ///
    /// Any router who hasn't published `G` or `E` congestion caps is considered usable.
    pub fn is_usable(&self) -> bool {
        self.capabilities.is_usable()
    }

    /// Get network ID of the [`RouterInfo`].
    pub fn net_id(&self) -> u8 {
        self.net_id
    }

    /// Check if the router is reachable via NTCP2.
    pub fn is_reachable_ntcp2(&self) -> bool {
        let Some(ntcp2) = self.addresses.get(&TransportKind::Ntcp2) else {
            return false;
        };

        ntcp2.socket_address.is_some()
            && ntcp2.options.get(&Str::from("i")).is_some()
            && ntcp2.options.get(&Str::from("s")).is_some()
    }
}

#[cfg(test)]
impl RouterInfo {
    /// Create new random [`RouterInfo`].
    pub fn random<R: crate::runtime::Runtime>() -> Self {
        use rand_core::RngCore;

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

    /// Create new random [`RouterInfo`] and serialize it.
    pub fn random_with_keys<R: crate::runtime::Runtime>(
    ) -> (Self, crate::crypto::StaticPrivateKey, SigningPrivateKey) {
        use rand_core::RngCore;

        let raw_static_key = {
            let mut key_bytes = vec![0u8; 32];
            R::rng().fill_bytes(&mut key_bytes);

            key_bytes
        };
        let static_key = crate::crypto::StaticPrivateKey::from_bytes(&raw_static_key).unwrap();

        let raw_signing_key = {
            let mut key_bytes = vec![0u8; 32];
            R::rng().fill_bytes(&mut key_bytes);

            key_bytes
        };
        let signing_key = SigningPrivateKey::from_bytes(&raw_signing_key).unwrap();

        (
            Self::from_keys::<R>(raw_static_key, raw_signing_key),
            static_key,
            signing_key,
        )
    }

    /// Create new random [`RouterInfo`] for a floodfill router.
    pub fn floodfill<R: crate::runtime::Runtime>() -> Self {
        use rand_core::RngCore;

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
        info.options.insert(Str::from("caps"), Str::from("XfR"));
        info.options.insert(Str::from("netId"), Str::from("2"));
        info.capabilities = Capabilities::parse(&Str::from("XfR")).expect("to succeed");

        info
    }

    /// Create new random [`RouterInfo`] from static and signing keys.
    pub fn from_keys<R: crate::runtime::Runtime>(
        static_key: Vec<u8>,
        signing_key: Vec<u8>,
    ) -> Self {
        use rand_core::RngCore;

        let static_key = StaticPrivateKey::from_bytes(&static_key).unwrap();
        let signing_key = SigningPrivateKey::from_bytes(&signing_key).unwrap();
        let identity =
            RouterIdentity::from_keys::<R>(&static_key, &signing_key).expect("to succeed");

        let ntcp2_port = R::rng().next_u32() as u16;
        let ntcp2_host = format!(
            "{}.{}.{}.{}",
            {
                loop {
                    let address = R::rng().next_u32() % 256;

                    if address != 0 {
                        break address;
                    }
                }
            },
            R::rng().next_u32() % 256,
            R::rng().next_u32() % 256,
            R::rng().next_u32() % 256,
        );
        let ntcp2_key = {
            let mut key_bytes = [0u8; 32];
            R::rng().fill_bytes(&mut key_bytes);

            key_bytes
        };
        let ntcp2_iv = {
            let mut iv_bytes = [0u8; 16];
            R::rng().fill_bytes(&mut iv_bytes);

            iv_bytes
        };

        let ntcp2 = RouterAddress::new_published_ntcp2(
            ntcp2_key,
            ntcp2_iv,
            ntcp2_port,
            ntcp2_host.parse().unwrap(),
        );
        let net_id = Mapping::new(Str::from("netId"), Str::from("2"));
        let caps = Mapping::new(Str::from("caps"), Str::from("L"));
        let router_version = Mapping::new(Str::from("router.version"), Str::from("0.9.62"));
        let options = Mapping::into_hashmap(vec![net_id, caps, router_version]);

        RouterInfo {
            addresses: HashMap::from_iter([(TransportKind::Ntcp2, ntcp2)]),
            capabilities: Capabilities::parse(&Str::from("L")).expect("to succeed"),
            identity,
            net_id: 2,
            options,
            published: Date::new(R::rng().next_u64()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{mock::MockRuntime, Runtime};
    use std::{str::FromStr, time::Duration};

    #[test]
    fn parse_router_1() {
        let router_info_bytes = include_bytes!("../../test-vectors/router1.dat");
        let router_info = RouterInfo::parse(router_info_bytes).unwrap();

        assert_eq!(router_info.addresses.len(), 2);

        // ssu
        assert_eq!(
            router_info.addresses.get(&TransportKind::Ssu2).unwrap().cost,
            5
        );
        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ssu2)
                .unwrap()
                .options
                .get(&Str::from_str("host").unwrap()),
            Some(&Str::from_str("2.36.209.134").unwrap())
        );
        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ssu2)
                .unwrap()
                .options
                .get(&Str::from_str("port").unwrap()),
            Some(&Str::from_str("23154").unwrap())
        );

        // ntcp2
        assert_eq!(
            router_info.addresses.get(&TransportKind::Ntcp2).unwrap().cost,
            11
        );

        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ntcp2)
                .unwrap()
                .options
                .get(&Str::from("host")),
            Some(&Str::from("2.36.209.134"))
        );
        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ntcp2)
                .unwrap()
                .options
                .get(&Str::from_str("port").unwrap()),
            Some(&Str::from_str("1403").unwrap())
        );

        // options
        assert_eq!(
            router_info.options.get(&Str::from_str("router.version").unwrap()),
            Some(&Str::from_str("0.9.64").unwrap())
        );
        assert_eq!(
            router_info.options.get(&Str::from_str("caps").unwrap()),
            Some(&Str::from_str("NRD").unwrap())
        );
        assert_eq!(
            router_info.options.get(&Str::from_str("netId").unwrap()),
            Some(&Str::from_str("2").unwrap())
        );
    }

    #[test]
    fn parse_router_2() {
        let router_info_bytes = include_bytes!("../../test-vectors/router2.dat");
        let router_info = RouterInfo::parse(router_info_bytes).unwrap();

        assert_eq!(router_info.addresses.len(), 2);

        // ssu
        assert_eq!(
            router_info.addresses.get(&TransportKind::Ssu2).unwrap().cost,
            8,
        );
        // ntcp2
        assert_eq!(
            router_info.addresses.get(&TransportKind::Ntcp2).unwrap().cost,
            3
        );
        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ntcp2)
                .unwrap()
                .options
                .get(&Str::from_str("host").unwrap()),
            Some(&Str::from_str("64.53.67.11").unwrap())
        );
        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ntcp2)
                .unwrap()
                .options
                .get(&Str::from_str("port").unwrap()),
            Some(&Str::from_str("25313").unwrap())
        );

        // options
        assert_eq!(
            router_info.options.get(&Str::from_str("router.version").unwrap()),
            Some(&Str::from_str("0.9.58").unwrap())
        );
        assert_eq!(
            router_info.options.get(&Str::from_str("caps").unwrap()),
            Some(&Str::from_str("XR").unwrap())
        );
        assert_eq!(
            router_info.options.get(&Str::from_str("netId").unwrap()),
            Some(&Str::from_str("2").unwrap())
        );
    }

    #[test]
    fn parse_router_3() {
        let router_info_bytes = include_bytes!("../../test-vectors/router3.dat");
        assert!(RouterInfo::parse(router_info_bytes).is_none());
    }

    #[test]
    fn is_not_floodfill() {
        let router_info_bytes = include_bytes!("../../test-vectors/router2.dat");

        assert!(!RouterInfo::parse(router_info_bytes).unwrap().is_floodfill())
    }

    #[test]
    fn is_floodfill() {
        let router_info_bytes = include_bytes!("../../test-vectors/router4.dat");

        assert!(RouterInfo::parse(router_info_bytes).unwrap().is_floodfill())
    }

    #[test]
    fn net_id_missing() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([(
                TransportKind::Ntcp2,
                RouterAddress::new_published_ntcp2(
                    [1u8; 32],
                    [2u8; 16],
                    8888,
                    "127.0.0.1".parse().unwrap(),
                ),
            )]),
            options: HashMap::from_iter([(Str::from("caps"), Str::from("L"))]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("L")).unwrap(),
        }
        .serialize(&sgk);

        assert!(RouterInfo::parse(&serialized).is_none());
    }

    #[test]
    fn caps_missing() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([(
                TransportKind::Ntcp2,
                RouterAddress::new_published_ntcp2(
                    [1u8; 32],
                    [2u8; 16],
                    8888,
                    "127.0.0.1".parse().unwrap(),
                ),
            )]),
            options: HashMap::from_iter([(Str::from("netId"), Str::from("2"))]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("L")).unwrap(),
        }
        .serialize(&sgk);

        assert!(RouterInfo::parse(&serialized).is_none());
    }

    #[test]
    fn hidden_router_not_reachable() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([(
                TransportKind::Ntcp2,
                RouterAddress::new_published_ntcp2(
                    [1u8; 32],
                    [2u8; 16],
                    8888,
                    "127.0.0.1".parse().unwrap(),
                ),
            )]),
            options: HashMap::from_iter([
                (Str::from("netId"), Str::from("2")),
                (Str::from("caps"), Str::from("HL")),
            ]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("HL")).unwrap(),
        }
        .serialize(&sgk);

        assert!(!RouterInfo::parse(&serialized).unwrap().is_reachable());
    }

    #[test]
    fn unreachable_router_not_reachable() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([(
                TransportKind::Ntcp2,
                RouterAddress::new_unpublished_ntcp2([1u8; 32], 8888),
            )]),
            options: HashMap::from_iter([
                (Str::from("netId"), Str::from("2")),
                (Str::from("caps"), Str::from("UL")),
            ]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("UL")).unwrap(),
        }
        .serialize(&sgk);

        assert!(!RouterInfo::parse(&serialized).unwrap().is_reachable());
    }

    #[test]
    fn reachable_but_no_published_address() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([(
                TransportKind::Ntcp2,
                RouterAddress::new_unpublished_ntcp2([1u8; 32], 8888),
            )]),
            options: HashMap::from_iter([
                (Str::from("netId"), Str::from("2")),
                (Str::from("caps"), Str::from("LR")),
            ]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("LR")).unwrap(),
        }
        .serialize(&sgk);

        assert!(!RouterInfo::parse(&serialized).unwrap().is_reachable());
    }

    #[test]
    fn reachable_explicitly_specified() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([(
                TransportKind::Ntcp2,
                RouterAddress::new_published_ntcp2(
                    [1u8; 32],
                    [2u8; 16],
                    8888,
                    "127.0.0.1".parse().unwrap(),
                ),
            )]),
            options: HashMap::from_iter([
                (Str::from("netId"), Str::from("2")),
                (Str::from("caps"), Str::from("LR")),
            ]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("LR")).unwrap(),
        }
        .serialize(&sgk);

        assert!(RouterInfo::parse(&serialized).unwrap().is_reachable());
    }

    // router doesn't explicitly specify the `R` flag
    #[test]
    fn maybe_reachable() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([(
                TransportKind::Ntcp2,
                RouterAddress::new_published_ntcp2(
                    [1u8; 32],
                    [2u8; 16],
                    8888,
                    "127.0.0.1".parse().unwrap(),
                ),
            )]),
            options: HashMap::from_iter([
                (Str::from("netId"), Str::from("2")),
                (Str::from("caps"), Str::from("Xf")),
            ]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("Xf")).unwrap(),
        }
        .serialize(&sgk);

        assert!(RouterInfo::parse(&serialized).unwrap().is_reachable());
    }

    #[test]
    fn ssu2_reachable() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([
                (
                    TransportKind::Ntcp2,
                    RouterAddress::new_unpublished_ntcp2([1u8; 32], 8888),
                ),
                (
                    TransportKind::Ssu2,
                    RouterAddress::new_published_ssu2(
                        [1u8; 32],
                        [2u8; 32],
                        8888,
                        "127.0.0.1".parse().unwrap(),
                    ),
                ),
            ]),
            options: HashMap::from_iter([
                (Str::from("netId"), Str::from("2")),
                (Str::from("caps"), Str::from("LR")),
            ]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("LR")).unwrap(),
        }
        .serialize(&sgk);

        assert!(RouterInfo::parse(&serialized).unwrap().is_reachable());
    }

    #[test]
    fn ntcp2_reachable() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([
                (
                    TransportKind::Ntcp2,
                    RouterAddress::new_published_ntcp2(
                        [1u8; 32],
                        [2u8; 16],
                        8888,
                        "127.0.0.1".parse().unwrap(),
                    ),
                ),
                (
                    TransportKind::Ssu2,
                    RouterAddress::new_published_ssu2(
                        [1u8; 32],
                        [2u8; 32],
                        8888,
                        "127.0.0.1".parse().unwrap(),
                    ),
                ),
            ]),
            options: HashMap::from_iter([
                (Str::from("netId"), Str::from("2")),
                (Str::from("caps"), Str::from("LR")),
            ]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("LR")).unwrap(),
        }
        .serialize(&sgk);

        assert!(RouterInfo::parse(&serialized).unwrap().is_reachable());
    }

    #[test]
    fn both_transports_unpublished() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([
                (
                    TransportKind::Ntcp2,
                    RouterAddress::new_unpublished_ntcp2([1u8; 32], 8888),
                ),
                (
                    TransportKind::Ssu2,
                    RouterAddress::new_unpublished_ssu2([1u8; 32], [2u8; 32], 8888),
                ),
            ]),
            options: HashMap::from_iter([
                (Str::from("netId"), Str::from("2")),
                (Str::from("caps"), Str::from("LR")),
            ]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("LU")).unwrap(),
        }
        .serialize(&sgk);

        assert!(!RouterInfo::parse(&serialized).unwrap().is_reachable());
    }
}
