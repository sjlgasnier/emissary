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
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use alloc::{string::String, vec::Vec};
use core::convert::TryInto;

pub mod aes;
pub mod chachapoly;
pub mod hmac;
pub mod sha256;
pub mod siphash;

// Taken from `ire` which is licensed under MIT
//
// Credits to str4d
//
// TODO: move to separate file?
// TODO: oncecell?
lazy_static! {
    pub static ref I2P_BASE64: Encoding = {
        let mut spec = Specification::new();
        spec.symbols
            .push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~");
        spec.padding = Some('=');
        spec.encoding().unwrap()
    };
    pub static ref I2P_BASE32: Encoding = {
        let mut spec = Specification::new();
        spec.symbols.push_str("abcdefghijklmnopqrstuvwxyz234567");
        spec.encoding().unwrap()
    };
}

/// Base64 encode `data`
pub fn base64_encode<T: AsRef<[u8]>>(data: T) -> String {
    I2P_BASE64.encode(data.as_ref())
}

/// Base64 decode `data`
//
// TODO: no unwraps
pub fn base64_decode<T: AsRef<[u8]>>(data: T) -> Vec<u8> {
    I2P_BASE64.decode(data.as_ref()).unwrap()
}

/// Base32 decode `data`.
pub fn base32_encode(data: impl AsRef<[u8]>) -> String {
    I2P_BASE32.encode(data.as_ref())
}

/// Base32 decode `data`.
pub fn base32_decode(data: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    I2P_BASE32.decode(data.as_ref()).ok()
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
    pub fn from_private_x25519(key: &[u8]) -> Option<Self> {
        let key: [u8; 32] = key.try_into().ok()?;
        let key = x25519_dalek::StaticSecret::from(key);
        let key = x25519_dalek::PublicKey::from(&key);

        Some(StaticPublicKey::X25519(key))
    }

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

    /// Convert public key to byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        match self {
            Self::X25519(key) => key.to_bytes(),
            Self::ElGamal(_) => todo!("elgamal not supported"),
        }
    }

    /// Convert public key to byte vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    /// Try to create [`StaticPublicKey`] from `bytes`.
    pub fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        let key: [u8; 32] = bytes.try_into().ok()?;

        Some(Self::X25519(x25519_dalek::PublicKey::from(key)))
    }

    /// Zeroize private key.
    pub fn zeroize(self) {
        match self {
            Self::X25519(mut key) => key.zeroize(),
            Self::ElGamal(_) => todo!(),
        }
    }
}

impl From<[u8; 32]> for StaticPublicKey {
    fn from(value: [u8; 32]) -> Self {
        StaticPublicKey::X25519(x25519_dalek::PublicKey::from(value))
    }
}

impl AsRef<[u8]> for StaticPublicKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::X25519(key) => key.as_ref(),
            Self::ElGamal(key) => key.as_ref(),
        }
    }
}

impl AsRef<x25519_dalek::PublicKey> for StaticPublicKey {
    fn as_ref(&self) -> &x25519_dalek::PublicKey {
        match self {
            Self::X25519(key) => &key,
            Self::ElGamal(_) => todo!(),
        }
    }
}

/// Static private key.
#[derive(Clone)]
pub enum StaticPrivateKey {
    /// x25519.
    X25519(x25519_dalek::StaticSecret),
}

impl StaticPrivateKey {
    /// Create new [`StaticPrivateKey`].
    pub fn new(csprng: impl RngCore + CryptoRng) -> Self {
        Self::X25519(x25519_dalek::StaticSecret::random_from_rng(csprng))
    }

    /// Get public key.
    pub fn public(&self) -> StaticPublicKey {
        match self {
            Self::X25519(key) => StaticPublicKey::X25519(x25519_dalek::PublicKey::from(key)),
        }
    }

    /// Perform Diffie-Hellman and return the shared secret as byte vector.
    pub fn diffie_hellman<T: AsRef<x25519_dalek::PublicKey>>(&self, public_key: &T) -> Vec<u8> {
        match self {
            Self::X25519(key) => key.diffie_hellman(public_key.as_ref()).to_bytes().to_vec(),
        }
    }
}

impl From<[u8; 32]> for StaticPrivateKey {
    fn from(value: [u8; 32]) -> Self {
        StaticPrivateKey::X25519(x25519_dalek::StaticSecret::from(value))
    }
}

impl From<Vec<u8>> for StaticPrivateKey {
    fn from(value: Vec<u8>) -> Self {
        let ss: [u8; 32] = value.try_into().expect("valid static private key");

        StaticPrivateKey::X25519(x25519_dalek::StaticSecret::from(ss))
    }
}

impl AsRef<[u8; 32]> for StaticPrivateKey {
    fn as_ref(&self) -> &[u8; 32] {
        match self {
            Self::X25519(key) => key.as_bytes(),
        }
    }
}

/// Ephemeral private key.
pub enum EphemeralPrivateKey {
    X25519(x25519_dalek::ReusableSecret),
}

impl EphemeralPrivateKey {
    /// Create new [`EphemeralPrivateKey`].
    pub fn new(csprng: impl RngCore + CryptoRng) -> Self {
        Self::X25519(x25519_dalek::ReusableSecret::random_from_rng(csprng))
    }

    /// Get associated public key.
    pub fn public_key(&self) -> EphemeralPublicKey {
        match self {
            Self::X25519(key) => EphemeralPublicKey::X25519(x25519_dalek::PublicKey::from(key)),
        }
    }

    /// Perform Diffie-Hellman and return the shared secret as byte vector.
    pub fn diffie_hellman<T: AsRef<x25519_dalek::PublicKey>>(&self, public_key: &T) -> Vec<u8> {
        match self {
            Self::X25519(key) => key.diffie_hellman(public_key.as_ref()).to_bytes().to_vec(),
        }
    }

    /// Zeroize private key.
    pub fn zeroize(self) {
        match self {
            Self::X25519(mut key) => key.zeroize(),
        }
    }
}

/// Ephemeral public key.
pub enum EphemeralPublicKey {
    X25519(x25519_dalek::PublicKey),
}

impl EphemeralPublicKey {
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::X25519(key) => key.as_bytes().to_vec(),
        }
    }

    /// Zeroize private key.
    pub fn zeroize(self) {
        match self {
            Self::X25519(mut key) => key.zeroize(),
        }
    }
}

impl TryFrom<&[u8]> for EphemeralPublicKey {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let key: [u8; 32] = value.try_into().map_err(|_| Error::InvalidData)?;

        Ok(Self::X25519(x25519_dalek::PublicKey::from(key)))
    }
}

impl AsRef<[u8]> for EphemeralPublicKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::X25519(key) => key.as_ref(),
        }
    }
}

impl AsRef<x25519_dalek::PublicKey> for EphemeralPublicKey {
    fn as_ref(&self) -> &x25519_dalek::PublicKey {
        match self {
            Self::X25519(key) => &key,
        }
    }
}

/// Signing private key.
#[derive(Clone)]
pub enum SigningPrivateKey {
    /// EdDSA.
    Ed25519(ed25519_dalek::SigningKey),
}

use ed25519_dalek::Signer;

impl SigningPrivateKey {
    pub fn new(key: &[u8]) -> Option<Self> {
        let key: [u8; 32] = key.to_vec().try_into().ok()?;
        let key = ed25519_dalek::SigningKey::from_bytes(&key);

        Some(SigningPrivateKey::Ed25519(key))
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Ed25519(key) => key.sign(&message).to_bytes().to_vec(),
        }
    }
}

/// Signing public key.
#[derive(Debug, Clone)]
pub enum SigningPublicKey {
    /// EdDSA.
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl SigningPublicKey {
    pub fn from_private_ed25519(key: &[u8]) -> Option<Self> {
        let key: [u8; 32] = key.to_vec().try_into().ok()?;
        let key = ed25519_dalek::SigningKey::from_bytes(&key);
        let key = key.verifying_key();

        Some(SigningPublicKey::Ed25519(key))
    }

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

    /// Convert public key to byte array
    pub fn to_bytes(&self) -> [u8; 32] {
        match self {
            Self::Ed25519(key) => key.to_bytes(),
        }
    }

    /// Convert public key to byte vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}
