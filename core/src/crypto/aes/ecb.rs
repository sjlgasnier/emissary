use aes::{
    cipher::{generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut, KeyInit},
    Aes256,
};
use ecb::{Decryptor, Encryptor};

use alloc::vec::Vec;

/// AES operation kind.
enum AesKind {
    /// Encryptor.
    Encryptor {
        /// Inner AES object.
        aes: Encryptor<Aes256>,
    },

    /// Decryptor.
    Decryptor {
        /// Inner AES object.
        aes: Decryptor<Aes256>,
    },
}

/// AES encryptor/decryptor.
pub struct Aes {
    /// AES operation kind.
    kind: AesKind,
}

impl Aes {
    /// Create new [`Aes`] encryptor instance.
    pub fn new_encryptor(key: &[u8]) -> Self {
        let key: [u8; 32] = key.try_into().expect("valid aes key");

        let aes = Encryptor::<Aes256>::new(&key.into());

        Self {
            kind: AesKind::Encryptor { aes },
        }
    }

    /// Create new [`Aes`] decryptor instance.
    pub fn new_decryptor(key: &[u8]) -> Self {
        let key: [u8; 32] = key.try_into().expect("valid aes key");

        let aes = Decryptor::<Aes256>::new(&key.into());

        Self {
            kind: AesKind::Decryptor { aes },
        }
    }

    /// Encrypt `plaintext` using AES-ECB-256.
    ///
    /// Length of `plaintext` must be a multiple of 16
    pub fn encrypt<T: AsRef<[u8]>>(&mut self, plaintext: T) -> Vec<u8> {
        assert!(plaintext.as_ref().len() % 16 == 0, "invalid plaintext");

        let AesKind::Encryptor { aes } = &mut self.kind else {
            panic!("tried to call `encrypt()` for an aes decryptor");
        };

        let mut blocks = plaintext
            .as_ref()
            .chunks(16)
            .into_iter()
            .map(|chunk| {
                GenericArray::from(TryInto::<[u8; 16]>::try_into(chunk).expect("to succeed"))
            })
            .collect::<Vec<_>>();

        let _ = aes.encrypt_blocks_mut(&mut blocks);

        blocks
            .into_iter()
            .map(|block| block.into_iter().collect::<Vec<u8>>())
            .flatten()
            .collect()
    }

    /// Dencrypt `ciphertext` using AES-EBC-256.
    ///
    /// Length of `ciphertext` must be a multiple of 16
    pub fn decrypt<T: AsRef<[u8]>>(&mut self, ciphertext: T) -> Vec<u8> {
        assert!(ciphertext.as_ref().len() % 16 == 0, "invalid ciphertext");

        let AesKind::Decryptor { aes } = &mut self.kind else {
            panic!("tried to call `decrypt()` for an aes encryptor");
        };

        let mut blocks = ciphertext
            .as_ref()
            .chunks(16)
            .into_iter()
            .map(|chunk| {
                GenericArray::from(TryInto::<[u8; 16]>::try_into(chunk).expect("to succeed"))
            })
            .collect::<Vec<_>>();

        let _ = aes.decrypt_blocks_mut(&mut blocks);

        blocks
            .into_iter()
            .map(|block| block.into_iter().collect::<Vec<u8>>())
            .flatten()
            .collect::<Vec<u8>>()
    }
}
