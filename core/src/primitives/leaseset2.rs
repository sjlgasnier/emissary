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
    crypto::{SigningPrivateKey, StaticPublicKey},
    primitives::{Destination, Mapping, RouterId, TunnelId, LOG_TARGET},
};

use bytes::{BufMut, BytesMut};
use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u32, be_u64, be_u8},
    Err, IResult,
};

use alloc::vec::Vec;
use core::time::Duration;

/// Header for [`LeaseSet2`].
///
/// https://geti2p.net/spec/common-structures#leaseset2header
#[derive(Clone)]
pub struct LeaseSet2Header {
    /// Destination for [`LeaseSet2`].
    pub destination: Destination,

    /// When [`LeaseSet2`] was published.
    pub published: u32,

    /// When [`LeaseSet2`] expires.
    pub expires: u32,
}

impl LeaseSet2Header {
    /// Attempt to parse [`LeaseSet2Header`] from `input`.
    ///
    /// Returns the parsed message and rest of `input` on success.
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], Self> {
        let (rest, destination) = Destination::parse_frame(input)?;
        let (rest, published) = be_u32(rest)?;
        let (rest, expires) = be_u16(rest)?;
        let (rest, flags) = be_u16(rest)?;

        if flags & 1 == 1 {
            todo!("offline signatures not supported");
        }

        Ok((
            rest,
            Self {
                destination,
                published,
                expires: published + expires as u32,
            },
        ))
    }

    /// Get serialized length of [`LeaseSet2Header`].
    pub fn serialized_len(&self) -> usize {
        // destination + published + expires + flags
        Destination::serialized_len() + 4usize + 2usize + 2usize
    }

    /// Serialize [`LeaseSet2Header`] into a byte vector.
    pub fn serialize(self) -> BytesMut {
        let mut out = BytesMut::with_capacity(self.serialized_len());

        out.put_slice(&self.destination.serialize());
        out.put_u32(self.published);
        out.put_u16(self.expires.saturating_sub(self.published) as u16);
        out.put_u16(0u16); // flags

        out
    }
}

/// Lease
///
/// [`Lease`] is common for `Lease` [1] and `Lease2` [2] and a difference
/// is made made only when serializing/deserializing them.
///
/// [1] https://geti2p.net/spec/common-structures#struct-lease
/// [2] https://geti2p.net/spec/common-structures#struct-lease2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// ID of the gateway router.
    pub router_id: RouterId,

    /// ID of the tunnel gateway.
    pub tunnel_id: TunnelId,

    /// When the lease expires.
    pub expires: Duration,
}

impl Lease {
    /// Attempt to parse `Lease2` from `input`.
    ///
    /// Returns the parsed lease and rest of `input` on success.
    pub fn parse_frame_lease2(input: &[u8]) -> IResult<&[u8], Self> {
        let (rest, tunnel_gateway) = take(32usize)(input)?;
        let (rest, tunnel_id) = be_u32(rest)?;
        let (rest, expires) = be_u32(rest)?;

        Ok((
            rest,
            Self {
                router_id: RouterId::from(tunnel_gateway),
                tunnel_id: TunnelId::from(tunnel_id),
                expires: Duration::from_secs(expires as u64),
            },
        ))
    }

    /// Attempt to parse `Lease` from `input`.
    ///
    /// Returns the parsed lease and rest of `input` on success.
    pub fn parse_frame_lease(input: &[u8]) -> IResult<&[u8], Self> {
        let (rest, tunnel_gateway) = take(32usize)(input)?;
        let (rest, tunnel_id) = be_u32(rest)?;
        let (rest, expires) = be_u64(rest)?;

        Ok((
            rest,
            Self {
                router_id: RouterId::from(tunnel_gateway),
                tunnel_id: TunnelId::from(tunnel_id),
                expires: Duration::from_millis(expires),
            },
        ))
    }

    /// Get serialized length of `Lease2`.
    pub fn serialized_len_lease2(&self) -> usize {
        // router hash length + tunnel id + expiration
        32usize + 4usize + 4usize
    }

    /// Get serialized length of `Lease`.
    pub fn serialized_len_lease(&self) -> usize {
        // router hash length + tunnel id + expiration
        32usize + 4usize + 8usize
    }

    /// Serialize [`Lease`] into a byte vector representing `Lease`.
    pub fn serialize_lease(self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(32usize + 4 + 8);

        out.put_slice(&Into::<Vec<u8>>::into(self.router_id));
        out.put_u32(*self.tunnel_id);
        out.put_u64(self.expires.as_millis() as u64);

        out.freeze().to_vec()
    }

    /// Serialize [`Lease`] into a byte vector representing `Lease2`.
    pub fn serialize_lease2(self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(32usize + 4 + 4);

        out.put_slice(&Into::<Vec<u8>>::into(self.router_id));
        out.put_u32(*self.tunnel_id);
        out.put_u32(self.expires.as_secs() as u32);

        out.freeze().to_vec()
    }
}

/// LeaseSet2
///
/// https://geti2p.net/spec/common-structures#struct-leaseset2
#[derive(Clone)]
pub struct LeaseSet2 {
    /// Header.
    pub header: LeaseSet2Header,

    /// Public keys.
    pub public_keys: Vec<StaticPublicKey>,

    /// Leases.
    pub leases: Vec<Lease>,
}

impl LeaseSet2 {
    /// Attempt to parse [`LeaseSet2`] from `input`.
    ///
    /// Returns the parsed message and rest of `input` on success.
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], Self> {
        let (rest, header) = LeaseSet2Header::parse_frame(input)?;
        let (rest, options) = Mapping::parse_multi_frame(rest)?;
        let (rest, num_key_types) = be_u8(rest)?;

        let (rest, public_keys) = (0..num_key_types)
            .try_fold(
                (rest, Vec::<StaticPublicKey>::new()),
                |(rest, mut public_keys), _| {
                    let (rest, pubkey_type) = be_u16::<&[u8], ()>(rest).ok()?;
                    let (rest, pubkey_len) = be_u16::<&[u8], ()>(rest).ok()?;
                    let (rest, pubkey) =
                        take::<usize, &[u8], ()>(pubkey_len as usize)(rest).ok()?;

                    match pubkey_type {
                        0x0004 => {
                            let key = StaticPublicKey::new_x25519(&pubkey)?;
                            public_keys.push(key);

                            Some((rest, public_keys))
                        }
                        pubkey_type => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                ?pubkey_type,
                                "ignoring public key"
                            );

                            Some((rest, public_keys))
                        }
                    }
                },
            )
            .ok_or_else(|| {
                tracing::warn!(
                    target: LOG_TARGET,
                    "failed to parse public key list",
                );

                Err::Error(make_error(input, ErrorKind::Fail))
            })?;

        // for now, emissary only supports curve25519-based crypto
        if public_keys.is_empty() {
            tracing::warn!(
                target: LOG_TARGET,
                "destination uses unsupported crypto",
            );

            return Err(Err::Error(make_error(input, ErrorKind::Fail)));
        }

        let (rest, num_leases) = be_u8(rest)?;

        if num_leases > 16 || num_leases == 0 {
            tracing::warn!(
                target: LOG_TARGET,
                ?num_leases,
                "invalid number of leases",
            );

            return Err(Err::Error(make_error(input, ErrorKind::Fail)));
        }

        let (rest, leases) = (0..num_leases)
            .try_fold((rest, Vec::<Lease>::new()), |(rest, mut leases), _| {
                let (rest, lease) = Lease::parse_frame_lease2(rest).ok()?;
                leases.push(lease);

                Some((rest, leases))
            })
            .ok_or_else(|| {
                tracing::warn!(
                    target: LOG_TARGET,
                    "failed to parse lease2 list",
                );

                Err::Error(make_error(input, ErrorKind::Fail))
            })?;

        // verify signature
        //
        // TODO: really inefficient
        let mut bytes = BytesMut::with_capacity(input.len() + 1);
        bytes.put_u8(3u8);
        bytes.put_slice(&input[..input.len()]);

        header.destination.signing_key().verify(&bytes, rest).or_else(|error| {
            tracing::warn!(
                target: LOG_TARGET,
                ?error,
                "invalid signature for leaseset2",
            );

            Err(Err::Error(make_error(input, ErrorKind::Fail)))
        })?;

        Ok((
            rest,
            Self {
                header,
                public_keys,
                leases,
            },
        ))
    }

    /// Attempt to parse `input` into [`LeaseSet2`].
    pub fn parse(input: &[u8]) -> Option<Self> {
        Some(Self::parse_frame(input).ok()?.1)
    }

    /// Get serialized length of [`LeaseSet2`].
    pub fn serialized_len(&self) -> usize {
        // header + no options + public keys + leases
        self.header.serialized_len()
            + 2usize
            + self.public_keys.iter().fold(0usize, |acc, _| acc + 32)
            + self.leases.iter().fold(0usize, |acc, x| acc + x.serialized_len_lease2())
            + 64usize // signature
    }

    /// Serialize [`LeaseSet2`] into a byte vector.
    pub fn serialize(self, signing_key: &SigningPrivateKey) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(self.serialized_len() + 1); // + 1 for signature

        out.put_u8(3u8); // leaset2
        out.put_slice(&self.header.serialize());
        out.put_u16(0u16); // no options
        out.put_u8(self.public_keys.len() as u8);

        self.public_keys.into_iter().for_each(|key| {
            out.put_u16(4); // x25519
            out.put_u16(32u16); // x25519 public key length
            out.put_slice(key.as_ref());
        });

        out.put_u8(self.leases.len() as u8);

        self.leases.into_iter().for_each(|lease| {
            out.put_slice(&lease.serialize_lease2());
        });

        let signature = signing_key.sign(&out[..out.len()]);
        out.put_slice(&signature);

        out[1..].to_vec()
    }

    #[cfg(test)]
    pub fn random() -> (LeaseSet2, SigningPrivateKey) {
        use crate::crypto::{SigningPublicKey, StaticPrivateKey};
        use rand::{Rng, RngCore};

        let mut rng = rand::thread_rng();

        let public_key = {
            let sk = StaticPrivateKey::new(&mut rng);

            sk.public()
        };

        let (destination, signing_private_key) = {
            let mut static_key = [0u8; 32];
            let mut signing_key = [0u8; 32];

            rng.fill_bytes(&mut static_key);
            rng.fill_bytes(&mut signing_key);

            (
                Destination::new(SigningPublicKey::from_private_ed25519(&signing_key).unwrap()),
                SigningPrivateKey::new(&signing_key).unwrap(),
            )
        };

        let mut leases = (0..rng.gen_range(1..16))
            .map(|_| {
                let router_id = RouterId::random();
                let tunnel_id = TunnelId::from(rng.next_u32());
                let expires = rng.next_u32();

                Lease {
                    router_id: RouterId::random(),
                    tunnel_id: TunnelId::from(rng.next_u32()),
                    expires: Duration::from_secs(rng.next_u32() as u64),
                }
            })
            .collect::<Vec<_>>();

        let published = rng.next_u32();
        let expires = rng.next_u32() / 10;

        (
            LeaseSet2 {
                header: LeaseSet2Header {
                    destination,
                    published,
                    expires: published.saturating_sub(expires),
                },
                public_keys: vec![public_key],
                leases,
            },
            signing_private_key,
        )
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use super::*;
    use crate::{
        crypto::{SigningPublicKey, StaticPrivateKey},
        runtime::{mock::MockRuntime, Runtime},
    };

    #[test]
    fn serialize_and_parse_leaset() {
        let sk = StaticPrivateKey::new(&mut MockRuntime::rng());
        let sgk = SigningPrivateKey::new(&[1u8; 32]).unwrap();
        let destination =
            Destination::new(SigningPublicKey::from_private_ed25519(&[1u8; 32]).unwrap());
        let id = destination.id();

        let (router1, tunnel1, expires1, lease1) = {
            let router_id = RouterId::random();
            let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
            let expires = Duration::from_secs(MockRuntime::rng().next_u32() as u64);

            (
                router_id.clone(),
                tunnel_id,
                expires,
                Lease {
                    router_id,
                    tunnel_id,
                    expires,
                },
            )
        };

        let (router2, tunnel2, expires2, lease2) = {
            let router_id = RouterId::random();
            let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
            let expires = Duration::from_secs(MockRuntime::rng().next_u32() as u64);

            (
                router_id.clone(),
                tunnel_id,
                expires,
                Lease {
                    router_id,
                    tunnel_id,
                    expires,
                },
            )
        };

        let mut serialized = LeaseSet2 {
            header: LeaseSet2Header {
                destination,
                published: 1337,
                expires: 2 * 1337,
            },
            public_keys: vec![sk.public()],
            leases: vec![lease1.clone(), lease2.clone()],
        }
        .serialize(&sgk);

        let leaseset = LeaseSet2::parse(&serialized).unwrap();

        assert_eq!(leaseset.public_keys.len(), 1);
        assert_eq!(leaseset.public_keys[0].to_bytes(), sk.public().to_bytes());
        assert_eq!(leaseset.leases.len(), 2);
        assert_eq!(leaseset.leases[0], lease1);
        assert_eq!(leaseset.leases[1], lease2);
        assert_eq!(leaseset.header.destination.id(), id);
    }

    #[test]
    fn serialize_and_parse_leaset_no_leasesets() {
        let sk = StaticPrivateKey::new(&mut MockRuntime::rng());
        let sgk = SigningPrivateKey::new(&[1u8; 32]).unwrap();
        let destination =
            Destination::new(SigningPublicKey::from_private_ed25519(&[1u8; 32]).unwrap());

        let mut serialized = LeaseSet2 {
            header: LeaseSet2Header {
                destination,
                published: 1337,
                expires: 2 * 1337,
            },
            public_keys: vec![sk.public()],
            leases: vec![],
        }
        .serialize(&sgk);

        assert!(LeaseSet2::parse(&serialized).is_none());
    }

    #[test]
    fn serialize_and_parse_leaset_no_public_keys() {
        let sgk = SigningPrivateKey::new(&[1u8; 32]).unwrap();
        let destination =
            Destination::new(SigningPublicKey::from_private_ed25519(&[1u8; 32]).unwrap());
        let id = destination.id();

        let (router1, tunnel1, expires1, lease1) = {
            let router_id = RouterId::random();
            let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
            let expires = Duration::from_secs(MockRuntime::rng().next_u32() as u64);

            (
                router_id.clone(),
                tunnel_id,
                expires,
                Lease {
                    router_id,
                    tunnel_id,
                    expires,
                },
            )
        };

        let (router2, tunnel2, expires2, lease2) = {
            let router_id = RouterId::random();
            let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
            let expires = Duration::from_secs(MockRuntime::rng().next_u32() as u64);

            (
                router_id.clone(),
                tunnel_id,
                expires,
                Lease {
                    router_id,
                    tunnel_id,
                    expires,
                },
            )
        };

        let mut serialized = LeaseSet2 {
            header: LeaseSet2Header {
                destination,
                published: 1337,
                expires: 2 * 1337,
            },
            public_keys: vec![],
            leases: vec![lease1.clone(), lease2.clone()],
        }
        .serialize(&sgk);

        assert!(LeaseSet2::parse(&serialized).is_none());
    }

    #[test]
    fn serialize_and_parse_random() {
        let (random, signing_key) = LeaseSet2::random();
        assert!(LeaseSet2::parse(&random.serialize(&signing_key)).is_some());
    }

    #[test]
    fn serialize_and_parse_leaset_too_many_leases() {
        let sk = StaticPrivateKey::new(&mut MockRuntime::rng());
        let sgk = SigningPrivateKey::new(&[1u8; 32]).unwrap();
        let destination =
            Destination::new(SigningPublicKey::from_private_ed25519(&[1u8; 32]).unwrap());
        let id = destination.id();

        let leases = (0..17)
            .map(|_| Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::from(MockRuntime::rng().next_u32()),
                expires: Duration::from_secs(MockRuntime::rng().next_u32() as u64),
            })
            .collect::<Vec<_>>();

        let mut serialized = LeaseSet2 {
            header: LeaseSet2Header {
                destination,
                published: 1337,
                expires: 2 * 1337,
            },
            public_keys: vec![sk.public()],
            leases,
        }
        .serialize(&sgk);

        assert!(LeaseSet2::parse(&serialized).is_none());
    }

    #[test]
    fn parse_leaseset2() {
        let buffer = vec![
            214, 155, 197, 98, 170, 161, 183, 41, 58, 103, 216, 196, 180, 218, 194, 93, 131, 248,
            109, 234, 196, 246, 15, 126, 91, 198, 187, 11, 54, 197, 115, 230, 214, 155, 197, 98,
            170, 161, 183, 41, 58, 103, 216, 196, 180, 218, 194, 93, 131, 248, 109, 234, 196, 246,
            15, 126, 91, 198, 187, 11, 54, 197, 115, 230, 214, 155, 197, 98, 170, 161, 183, 41, 58,
            103, 216, 196, 180, 218, 194, 93, 131, 248, 109, 234, 196, 246, 15, 126, 91, 198, 187,
            11, 54, 197, 115, 230, 214, 155, 197, 98, 170, 161, 183, 41, 58, 103, 216, 196, 180,
            218, 194, 93, 131, 248, 109, 234, 196, 246, 15, 126, 91, 198, 187, 11, 54, 197, 115,
            230, 214, 155, 197, 98, 170, 161, 183, 41, 58, 103, 216, 196, 180, 218, 194, 93, 131,
            248, 109, 234, 196, 246, 15, 126, 91, 198, 187, 11, 54, 197, 115, 230, 214, 155, 197,
            98, 170, 161, 183, 41, 58, 103, 216, 196, 180, 218, 194, 93, 131, 248, 109, 234, 196,
            246, 15, 126, 91, 198, 187, 11, 54, 197, 115, 230, 214, 155, 197, 98, 170, 161, 183,
            41, 58, 103, 216, 196, 180, 218, 194, 93, 131, 248, 109, 234, 196, 246, 15, 126, 91,
            198, 187, 11, 54, 197, 115, 230, 214, 155, 197, 98, 170, 161, 183, 41, 58, 103, 216,
            196, 180, 218, 194, 93, 131, 248, 109, 234, 196, 246, 15, 126, 91, 198, 187, 11, 54,
            197, 115, 230, 214, 155, 197, 98, 170, 161, 183, 41, 58, 103, 216, 196, 180, 218, 194,
            93, 131, 248, 109, 234, 196, 246, 15, 126, 91, 198, 187, 11, 54, 197, 115, 230, 214,
            155, 197, 98, 170, 161, 183, 41, 58, 103, 216, 196, 180, 218, 194, 93, 131, 248, 109,
            234, 196, 246, 15, 126, 91, 198, 187, 11, 54, 197, 115, 230, 214, 155, 197, 98, 170,
            161, 183, 41, 58, 103, 216, 196, 180, 218, 194, 93, 131, 248, 109, 234, 196, 246, 15,
            126, 91, 198, 187, 11, 54, 197, 115, 230, 64, 231, 155, 2, 143, 122, 48, 137, 247, 79,
            229, 220, 40, 212, 53, 67, 193, 196, 204, 21, 45, 109, 227, 237, 29, 17, 31, 189, 17,
            189, 195, 40, 5, 0, 4, 0, 7, 0, 0, 102, 216, 119, 64, 2, 88, 0, 0, 0, 0, 2, 0, 4, 0,
            32, 103, 57, 105, 36, 53, 6, 188, 207, 237, 100, 79, 208, 65, 73, 180, 118, 143, 162,
            202, 8, 103, 162, 220, 12, 95, 156, 67, 68, 62, 83, 112, 109, 0, 0, 1, 0, 119, 187, 61,
            243, 159, 159, 198, 178, 65, 81, 148, 19, 78, 105, 92, 175, 190, 170, 136, 62, 19, 45,
            23, 246, 228, 210, 215, 161, 129, 149, 160, 57, 137, 141, 144, 141, 163, 247, 34, 120,
            5, 161, 60, 107, 34, 107, 166, 40, 152, 252, 246, 205, 187, 51, 129, 52, 97, 95, 188,
            78, 176, 198, 254, 4, 19, 197, 215, 74, 73, 55, 135, 16, 43, 68, 159, 141, 78, 234, 63,
            118, 142, 114, 20, 96, 8, 38, 18, 211, 159, 107, 160, 236, 33, 3, 153, 100, 77, 117,
            145, 67, 173, 140, 69, 123, 31, 253, 172, 240, 74, 110, 148, 56, 229, 208, 81, 69, 175,
            122, 89, 252, 43, 29, 193, 100, 232, 33, 150, 48, 105, 230, 76, 125, 114, 135, 88, 222,
            21, 183, 56, 203, 58, 51, 187, 57, 64, 196, 238, 62, 35, 43, 226, 209, 160, 77, 171,
            252, 81, 125, 105, 3, 40, 216, 107, 1, 209, 223, 117, 237, 54, 151, 90, 133, 76, 32,
            217, 167, 214, 86, 42, 226, 222, 126, 45, 133, 138, 28, 77, 37, 28, 200, 74, 3, 240,
            188, 12, 47, 48, 49, 61, 154, 31, 74, 78, 229, 133, 62, 250, 249, 67, 180, 175, 156,
            60, 148, 227, 168, 127, 107, 118, 63, 220, 18, 242, 169, 94, 112, 58, 7, 196, 69, 243,
            206, 205, 89, 54, 174, 162, 106, 223, 195, 152, 90, 155, 98, 223, 122, 21, 248, 181,
            118, 208, 80, 41, 154, 232, 58, 3, 249, 0, 187, 182, 11, 128, 61, 16, 80, 73, 190, 216,
            57, 137, 166, 213, 35, 195, 36, 79, 56, 118, 161, 49, 37, 5, 174, 148, 94, 114, 242, 7,
            240, 177, 138, 122, 102, 216, 121, 152, 249, 0, 187, 182, 11, 128, 61, 16, 80, 73, 190,
            216, 57, 137, 166, 213, 35, 195, 36, 79, 56, 118, 161, 49, 37, 5, 174, 148, 94, 114,
            242, 7, 254, 77, 137, 9, 102, 216, 121, 152, 249, 0, 187, 182, 11, 128, 61, 16, 80, 73,
            190, 216, 57, 137, 166, 213, 35, 195, 36, 79, 56, 118, 161, 49, 37, 5, 174, 148, 94,
            114, 242, 7, 239, 37, 242, 32, 102, 216, 121, 152, 85, 131, 155, 161, 181, 62, 114,
            203, 208, 71, 210, 43, 204, 240, 181, 94, 146, 250, 118, 234, 79, 158, 201, 58, 167,
            187, 35, 177, 69, 215, 241, 60, 154, 198, 121, 194, 199, 142, 61, 196, 142, 139, 85,
            87, 210, 244, 83, 145, 143, 233, 154, 12, 60, 130, 140, 197, 170, 93, 124, 203, 142,
            46, 214, 11,
        ];

        let leaseset2 = LeaseSet2::parse_frame(&buffer).unwrap().1;

        assert_eq!(leaseset2.public_keys.len(), 1);
        assert_eq!(leaseset2.leases.len(), 3);
    }
}
