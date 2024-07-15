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
    crypto::{base64_encode, sha256::Sha256, SigningPublicKey, StaticPublicKey},
    Error,
};

use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u8},
    sequence::tuple,
    Err, IResult,
};
use zerocopy::AsBytes;

use alloc::{string::String, sync::Arc, vec::Vec};
use core::fmt;

/// Short router identity hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouterId {
    hash: Arc<String>,
}

impl fmt::Display for RouterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.hash)
    }
}

// TODO: doc
#[derive(Debug, AsBytes)]
#[repr(C)]
struct RouterIdentitySerialized {
    public_key: [u8; 32],
    padding: [u8; 320],
    signing_key: [u8; 32],
    certificate_type: u8,
    certificate_len: [u8; 2],
    signing_key_type: [u8; 2],
    public_key_type: [u8; 2],
}

/// Router identity.
//
// TODO: cheaply cloanble
#[derive(Debug, Clone)]
pub struct RouterIdentity {
    /// Router's public key.
    static_key: StaticPublicKey,

    /// Router's signing key.
    signing_key: SigningPublicKey,

    /// Identity hash.
    identity_hash: Vec<u8>,
}

impl RouterIdentity {
    /// Create new [`RouterIdentity`] from keys.
    pub fn from_keys(static_key: Vec<u8>, signing_key: Vec<u8>) -> crate::Result<Self> {
        let static_key =
            StaticPublicKey::from_private_x25519(&static_key).ok_or(Error::InvalidData)?;
        let signing_key =
            SigningPublicKey::from_private_ed25519(&signing_key).ok_or(Error::InvalidData)?;

        let identity_hash = Sha256::new()
            .update(
                &RouterIdentitySerialized {
                    public_key: static_key.clone().to_bytes(),
                    padding: [0u8; 320],
                    signing_key: signing_key.clone().to_bytes(),
                    certificate_type: 5u8,
                    certificate_len: 4u16.to_be_bytes(),
                    signing_key_type: 7u16.to_be_bytes(),
                    public_key_type: 4u16.to_be_bytes(),
                }
                .as_bytes(),
            )
            .finalize();

        Ok(Self {
            static_key,
            signing_key,
            identity_hash,
        })
    }

    /// Parse [`RouterIdentity`] from `input`, returning rest of `input` and parsed router identity.
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], RouterIdentity> {
        let (_, (initial_bytes, rest)) = tuple((take(384usize), take(input.len() - 384)))(input)?;

        let (rest, cert_type) = be_u8(rest)?;
        let (rest, cert_len) = be_u16(rest)?;
        let (rest, sig_key_type) = be_u16(rest)?;
        let (rest, pub_key_type) = be_u16(rest)?;

        let (0x5, 0x4) = (cert_type, cert_len) else {
            return Err(Err::Error(make_error(input, ErrorKind::Fail)));
        };

        let static_key = match pub_key_type {
            0x0000 => StaticPublicKey::new_elgamal(&initial_bytes[..256]),
            0x0004 => StaticPublicKey::new_x25519(&initial_bytes[..32]),
            _ => todo!("unsupported public key type"),
        }
        .ok_or(Err::Error(make_error(input, ErrorKind::Fail)))?;

        let signing_key = match sig_key_type {
            0x0007 => SigningPublicKey::from_bytes(&initial_bytes[384 - 32..384]),
            _ => todo!("unsupported signing key type"),
        }
        .ok_or(Err::Error(make_error(input, ErrorKind::Fail)))?;

        Ok((
            rest,
            RouterIdentity {
                static_key,
                signing_key,
                identity_hash: Sha256::new().update(&input[..391]).finalize(),
            },
        ))
    }

    /// Try to parse router information from `bytes`.
    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Option<Self> {
        Some(Self::parse_frame(bytes.as_ref()).ok()?.1)
    }

    /// Serialize [`RouterIdentity`] into a byte vector.
    pub fn serialize(&self) -> Vec<u8> {
        RouterIdentitySerialized {
            public_key: self.static_key.to_bytes(),
            padding: [0u8; 320],
            signing_key: self.signing_key.to_bytes(),
            certificate_type: 5u8,
            certificate_len: 4u16.to_be_bytes(),
            signing_key_type: 7u16.to_be_bytes(),
            public_key_type: 4u16.to_be_bytes(),
        }
        .as_bytes()
        .to_vec()
    }

    /// Get reference to router's static public key.
    pub fn static_key(&self) -> &StaticPublicKey {
        &self.static_key
    }

    /// Get reference to router's signing public key.
    pub fn signing_key(&self) -> &SigningPublicKey {
        &self.signing_key
    }

    /// Router identity hash as bytes.
    pub fn hash(&self) -> &[u8] {
        self.identity_hash.as_ref()
    }

    /// Get [`RouterId`].
    pub fn id(&self) -> RouterId {
        RouterId {
            hash: Arc::new(base64_encode(&self.identity_hash[..16])),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::base64_encode;

    #[test]
    fn expected_router_hash() {
        let router = include_bytes!("../../test-vectors/router1.dat");
        let identity = RouterIdentity::from_bytes(router).unwrap();

        assert_eq!(
            base64_encode(&identity.identity_hash),
            "jLD5rTYg4zg~d4oQ29ogPtGcZPQYM3pHAKY8VHNZv30="
        );
    }
}
