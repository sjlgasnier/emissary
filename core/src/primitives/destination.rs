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

use crate::crypto::{base64_decode, base64_encode, sha256::Sha256, SigningPublicKey};

use bytes::{BufMut, Bytes, BytesMut};
use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u8},
    sequence::tuple,
    Err, IResult,
};

use alloc::{string::String, sync::Arc, vec::Vec};
use core::fmt;

/// Short router identity hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct DestinationId(Arc<String>);

impl DestinationId {
    #[cfg(test)]
    pub fn random() -> DestinationId {
        use rand::Rng;

        let bytes = rand::thread_rng().gen::<[u8; 32]>();
        DestinationId::from(bytes)
    }
}

impl fmt::Display for DestinationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.0[..8])
    }
}

impl<T: AsRef<[u8]>> From<T> for DestinationId {
    fn from(value: T) -> Self {
        DestinationId(Arc::new(base64_encode(value)))
    }
}

impl Into<Vec<u8>> for DestinationId {
    fn into(self) -> Vec<u8> {
        base64_decode(&self.0.as_bytes())
    }
}

/// Destination.
#[derive(Debug, Clone)]
pub struct Destination {
    /// Destination's signing key.
    pub signing_key: SigningPublicKey,

    /// Destinations' identity hash.
    pub identity_hash: Bytes,

    /// Destination ID.
    pub destination_id: DestinationId,
}

impl Destination {
    /// Create new [`Destination`] from `signing_key`.
    pub fn new(signing_key: SigningPublicKey) -> Self {
        let identity_hash = Sha256::new().update(&Self::serialize_inner(&signing_key)).finalize();

        Self {
            signing_key,
            identity_hash: Bytes::from(identity_hash.clone()),
            destination_id: DestinationId::from(identity_hash),
        }
    }

    /// Parse [`Destination`] from `input`, returning rest of `input` and parsed router identity.
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], Destination> {
        let (_, (initial_bytes, rest)) = tuple((take(384usize), take(input.len() - 384)))(input)?;

        let (rest, cert_type) = be_u8(rest)?;
        let (rest, cert_len) = be_u16(rest)?;
        let (rest, sig_key_type) = be_u16(rest)?;
        let (rest, _pub_key_type) = be_u16(rest)?;

        let (0x5, 0x4) = (cert_type, cert_len) else {
            return Err(Err::Error(make_error(input, ErrorKind::Fail)));
        };

        let signing_key = match sig_key_type {
            0x0007 => SigningPublicKey::from_bytes(&initial_bytes[384 - 32..384]),
            _ => todo!("unsupported signing key type"), // TODO: return error
        }
        .ok_or(Err::Error(make_error(input, ErrorKind::Fail)))?;

        let identity_hash = Bytes::from(Sha256::new().update(&input[..391]).finalize());

        Ok((
            rest,
            Destination {
                signing_key,
                identity_hash: identity_hash.clone(),
                destination_id: DestinationId::from(identity_hash),
            },
        ))
    }

    /// Try to parse router information from `bytes`.
    pub fn parse(bytes: impl AsRef<[u8]>) -> Option<Self> {
        Some(Self::parse_frame(bytes.as_ref()).ok()?.1)
    }

    /// Serialize [`Destination`] into a byte vector.
    pub fn serialize_inner(signing_key: &SigningPublicKey) -> BytesMut {
        let mut out = BytesMut::with_capacity(Self::serialized_len());

        out.put_slice(&[0u8; 32]);
        out.put_slice(&[0u8; 320]);
        out.put_slice(&signing_key.to_bytes());
        out.put_u8(5u8); // certificate type
        out.put_u16(4u16); // certificate length
        out.put_u16(7u16); // signing key type
        out.put_u16(0u16); // public key type

        out
    }

    /// Serialize [`Destination`] into a byte vector.
    pub fn serialize(&self) -> BytesMut {
        Self::serialize_inner(&self.signing_key)
    }

    /// Get serialized length of [`Destination`].
    pub fn serialized_len() -> usize {
        32usize // all zeros public key
            .saturating_add(320usize) // paddingA
            .saturating_add(32usize) // signing public key
            .saturating_add(1usize) // certificate type
            .saturating_add(2usize) // certificate length
            .saturating_add(2usize) // signing key type
            .saturating_add(2usize) // public key type
    }

    /// Get [`DestinationId`].
    pub fn id(&self) -> DestinationId {
        self.destination_id.clone()
    }

    /// Get reference to `SigningPublicKey` of the [`Destination`].
    pub fn signing_key(&self) -> &SigningPublicKey {
        &self.signing_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_and_parse_destination() {
        let signing_key = SigningPublicKey::from_private_ed25519(&[0xaa; 32]).unwrap();
        let destination = Destination::new(signing_key.clone());

        let serialized = destination.clone().serialize();
        let parsed = Destination::parse(&serialized).unwrap();

        assert_eq!(parsed.destination_id, destination.destination_id);
        assert_eq!(
            parsed.signing_key.to_bytes(),
            destination.signing_key.to_bytes()
        );
    }
}
