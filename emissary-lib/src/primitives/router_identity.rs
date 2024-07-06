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
    crypto::{base64_decode, base64_encode, SigningPublicKey, StaticPublicKey},
    Error,
};

use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u8},
    sequence::tuple,
    Err, IResult,
};
use sha2::{Digest, Sha256};

use alloc::{
    string::String,
    {vec, vec::Vec},
};

/// Router identity.
#[derive(Debug)]
pub struct RouterIdentity {
    /// Router's public key.
    static_key: StaticPublicKey,

    /// Router's signing key.
    signing_key: SigningPublicKey,

    /// Identity hash.
    identity_hash: String,
}

impl RouterIdentity {
    /// Create new [`RouterIdentity`] from keys.
    pub fn from_keys(static_key: Vec<u8>, signing_key: Vec<u8>) -> crate::Result<Self> {
        let static_key =
            StaticPublicKey::from_private_x25519(&static_key).ok_or(Error::InvalidData)?;
        let signing_key =
            SigningPublicKey::from_private_ed25519(&signing_key).ok_or(Error::InvalidData)?;

        Ok(Self {
            static_key,
            signing_key,
            identity_hash: String::from("fix"),
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

        let mut identity_hash = Sha256::new();
        identity_hash.update(&input[..391]);
        let digest = identity_hash.finalize().to_vec();
        let identity_hash = base64_encode(&digest);

        Ok((
            rest,
            RouterIdentity {
                static_key,
                signing_key,
                identity_hash,
            },
        ))
    }

    /// Try to parse router information from `bytes`.
    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Option<Self> {
        Some(Self::parse_frame(bytes.as_ref()).ok()?.1)
    }

    // TODO: zzz
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = vec![0u8; 391];

        out[..32].copy_from_slice(&self.static_key.to_vec());
        out[384 - 32..384].copy_from_slice(&self.signing_key.to_vec());

        out[384] = 0x05;
        out[385] = 0x00;
        out[386] = 0x04;

        out[387] = 0x00;
        out[388] = 0x07;
        out[389] = 0x00;
        out[390] = 0x04;

        out
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
    // TODO: optimize
    pub fn hash(&self) -> Vec<u8> {
        base64_decode(self.identity_hash.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_router_hash() {
        let router = include_bytes!("../../test-vectors/router1.dat");
        let identity = RouterIdentity::from_bytes(router).unwrap();

        assert_eq!(
            identity.identity_hash,
            "jLD5rTYg4zg~d4oQ29ogPtGcZPQYM3pHAKY8VHNZv30="
        );
    }
}
