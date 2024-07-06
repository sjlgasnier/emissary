use crate::Error;

use aes::cipher::generic_array::GenericArray;
use chacha20poly1305::{
    aead::{Aead, AeadInPlace, AeadMutInPlace, KeyInit},
    consts::U12,
    ChaCha20Poly1305,
};

use alloc::vec::Vec;

/// Nonce.
pub struct Nonce {
    nonce: u64,
}

impl Nonce {
    /// Create new [`Nonce`], starting from `nonce`.
    pub fn new(nonce: u64) -> Self {
        Self { nonce }
    }

    /// Get next nonce.
    ///
    /// The first 4 bytes of the 12-bytes are not used.
    ///
    /// Maximum value for for `nonce` is 2^64 - 2.
    pub fn next(&mut self) -> Option<GenericArray<u8, U12>> {
        let nonce = {
            let nonce = self.nonce;
            self.nonce = self.nonce.checked_add(1)?;
            nonce
        };

        let mut array = [0u8; 12];
        array.as_mut_slice()[4..].copy_from_slice(nonce.to_le_bytes().as_slice());

        Some(GenericArray::from(array))
    }
}

pub struct ChaChaPoly {
    nonce: GenericArray<u8, U12>,
    cipher: ChaCha20Poly1305,
}

impl ChaChaPoly {
    pub fn new(key: &[u8]) -> Self {
        let key: [u8; 32] = key.try_into().unwrap();
        let key = GenericArray::from(key);

        let nonce = GenericArray::from([0u8; 12]);
        let cipher = ChaCha20Poly1305::new(&key);

        Self { nonce, cipher }
    }

    pub fn with_nonce(key: &[u8], nonce: u8) -> Self {
        let key: [u8; 32] = key.try_into().unwrap();
        let key = GenericArray::from(key);

        let nonce = Nonce::new(nonce as u64).next().unwrap();
        let cipher = ChaCha20Poly1305::new(&key);

        Self { nonce, cipher }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
        self.cipher
            .encrypt(&self.nonce, plaintext)
            .map_err(|_| Error::InvalidData)
    }

    pub fn decrypt(
        &mut self,
        associated_data: &[u8],
        ciphertext: &mut Vec<u8>,
    ) -> crate::Result<()> {
        self.cipher
            .decrypt_in_place(&GenericArray::from([0u8; 12]), associated_data, ciphertext)
            .map_err(|error| {
                tracing::error!(?error, "failed to decrypt frame");

                Error::InvalidData
            })
    }

    pub fn decrypt_no_ad(&mut self, ciphertext: Vec<u8>) -> crate::Result<Vec<u8>> {
        self.cipher
            .decrypt(&GenericArray::from([0u8; 12]), &ciphertext[..])
            .map(|data| data)
            .map_err(|error| {
                tracing::error!(?error, "failed to decrypt frame");

                Error::InvalidData
            })
    }

    pub fn encrypt_detached(
        &mut self,
        associated_data: &[u8],
        plaintext: &mut [u8],
    ) -> crate::Result<Vec<u8>> {
        let tag = self
            .cipher
            .encrypt_in_place_detached(&self.nonce, associated_data, plaintext)
            .unwrap();

        Ok(tag.as_slice().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_nonce() {
        let mut nonce = Nonce::new(0);

        // verify the first nonce is zero
        assert_eq!(nonce.next(), Some(GenericArray::from([0u8; 12])));

        // verify the first nonce is zero
        let mut array = [0u8; 12];
        array[4] = 1;

        assert_eq!(nonce.next(), Some(GenericArray::from(array)));
    }

    #[test]
    fn nonce_exhausted() {
        let mut nonce = Nonce::new(u64::MAX - 1);

        let mut array = [0u8; 12];
        array[5..].fill(0xff);
        array[4] = 0xfe;

        assert_eq!(nonce.next(), Some(GenericArray::from(array)));
        assert_eq!(nonce.next(), None);
    }
}
