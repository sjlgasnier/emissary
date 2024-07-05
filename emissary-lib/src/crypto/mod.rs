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

use crate::Error;

use data_encoding::{Encoding, Specification};
use lazy_static::lazy_static;

use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryInto;

// Taken from `ire` which is licensed under MIT
//
// Credits to str4d
lazy_static! {
    pub static ref I2P_BASE64: Encoding = {
        let mut spec = Specification::new();
        spec.symbols
            .push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~");
        spec.padding = Some('=');
        spec.encoding().unwrap()
    };
}

/// Base64 encode `data`
pub fn base64_encode(data: &Vec<u8>) -> String {
    I2P_BASE64.encode(data)
}

/// Base64 decode `data`
pub fn base64_decode<T: AsRef<[u8]>>(data: T) -> Vec<u8> {
    I2P_BASE64.decode(data.as_ref()).unwrap()
}

// TODO: add tests

#[derive(Debug, Clone)]
pub enum StaticPublicKey {
    /// x25519
    X25519(x25519_dalek::PublicKey),

    /// ElGamal.
    ElGamal([u8; 256]),
}

impl StaticPublicKey {
    /// Create new x25519 static public key.
    pub fn new_x25519(key: &[u8]) -> Option<Self> {
        let key: [u8; 32] = key.try_into().ok()?;
        Some(StaticPublicKey::X25519(x25519_dalek::PublicKey::from(key)))
    }

    /// Create new ElGamal static public key.
    pub fn new_elgamal(key: &[u8]) -> Option<Self> {
        let key: [u8; 256] = key.try_into().ok()?;
        Some(StaticPublicKey::ElGamal(key))
    }
}

/// Static private key.
pub enum StaticPrivateKey {
    /// x25519.
    X25519(x25519_dalek::SharedSecret),
}

/// Signing private key.
pub enum SigningPrivateKey {
    /// EdDSA.
    Ed25519(ed25519_dalek::SecretKey),
}

/// Signing public key.
#[derive(Debug, Clone)]
pub enum SigningPublicKey {
    /// EdDSA.
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl SigningPublicKey {
    /// Create signing public key from bytes.
    pub fn from_bytes(key: &[u8]) -> Option<Self> {
        let key: [u8; 32] = key.to_vec().try_into().ok()?;

        Some(SigningPublicKey::Ed25519(
            ed25519_dalek::VerifyingKey::from_bytes(&key).ok()?,
        ))
    }

    /// Verify `signature` of `message`.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> crate::Result<()> {
        match self {
            Self::Ed25519(key) => {
                let signature: [u8; 64] = signature.try_into().map_err(|_| Error::InvalidData)?;
                let signature = ed25519_dalek::Signature::from_bytes(&signature);

                key.verify_strict(&message[..message.len() - 64], &signature)
                    .map_err(From::from)
            }
        }
    }
}
