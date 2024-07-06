use crate::Error;

use aes::cipher::generic_array::GenericArray;
use chacha20poly1305::{
    aead::{Aead, AeadInPlace, AeadMutInPlace, KeyInit},
    consts::U12,
    ChaCha20Poly1305,
};

use alloc::vec::Vec;

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

        // TODO: needs fixing
        let mut array = [0u8; 12];
        array[4] = nonce;

        let nonce = GenericArray::from(array);
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
