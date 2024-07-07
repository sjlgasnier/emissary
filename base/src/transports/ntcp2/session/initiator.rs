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

//! NTCP2 Noise handshake implementation for initiator (Alice)
//!
//! https://geti2p.net/spec/ntcp2#overview
//!
//! Implementation refers to `ck` as `chaining_key` and to `h` as `state`.

use crate::{
    crypto::{
        aes::Aes, base64_encode, chachapoly::ChaChaPoly, hmac::Hmac, sha256::Sha256,
        siphash::SipHash, EphemeralPrivateKey, StaticPrivateKey, StaticPublicKey,
    },
    runtime::Runtime,
    transports::ntcp2::{
        message::Message,
        session::{InitiatorOptions, KeyContext, ResponderOptions},
    },
    Error,
};

use zerocopy::{AsBytes, FromBytes};
use zeroize::Zeroize;

use alloc::vec::Vec;
use core::fmt;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ntcp2::initiator";

/// Noise protocol name.
const PROTOCOL_NAME: &str = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256";

/// Initiator state.
enum InitiatorState {
    /// Initiator has sent `SessionCreated` message to remote
    /// and is waitint to hear a response.
    SessionRequested {
        /// State.
        state: Vec<u8>,

        /// AES IV.
        iv: [u8; 16],

        /// Local router info.
        local_info: Vec<u8>,

        /// Ephemeral private key.
        ephemeral_key: EphemeralPrivateKey,

        /// Static private key.
        local_static_key: StaticPrivateKey,

        /// Router hash.
        router_hash: Vec<u8>,

        /// Chaining key.
        chaining_key: Vec<u8>,
    },

    /// Responder has accepted the session request and is waiting for initiator to confirm the session
    SessionCreated {
        /// State.
        state: Vec<u8>,

        /// Router hash.
        router_hash: Vec<u8>,

        /// Local router info.
        local_info: Vec<u8>,

        /// Static private key.
        local_static_key: StaticPrivateKey,

        /// Chaining key.
        chaining_key: Vec<u8>,

        /// Remote key.
        remote_key: Vec<u8>,

        // Responder's public key.
        responder_public: StaticPublicKey,
    },

    /// Initiator state has been poisoned.
    Poisoned,
}

impl fmt::Debug for InitiatorState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionRequested { .. } => {
                f.debug_struct("SessionRequested").finish_non_exhaustive()
            }
            Self::SessionCreated { .. } => f.debug_struct("SessionCreated").finish_non_exhaustive(),
            Self::Poisoned => f.debug_struct("Poisoned").finish(),
        }
    }
}

impl Default for InitiatorState {
    fn default() -> Self {
        Self::Poisoned
    }
}

/// Noise handshake initiator
pub struct Initiator {
    /// Initiator state.
    state: InitiatorState,
}

impl Initiator {
    /// Create new [`Handshaker`] for initiator.
    ///
    /// Implements KDF from [1], creates a `SessionRequest` message and returns that message
    /// together with an [`Initiator`] object which allows the call to drive progress on the
    /// opening connection.
    ///
    /// [1]: [KDF part 1](https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-handshake-message-1)
    pub fn new<R: Runtime>(
        state: Vec<u8>,
        chaining_key: Vec<u8>,
        local_info: Vec<u8>,
        local_static_key: StaticPrivateKey,
        remote_static_key: &StaticPublicKey,
        router_hash: Vec<u8>,
        iv: Vec<u8>,
    ) -> crate::Result<(Self, Vec<u8>)> {
        tracing::trace!(
            target: LOG_TARGET,
            router = ?base64_encode(&router_hash),
            "initiate new connection"
        );

        let chaining_key = chaining_key.clone();
        let state = Sha256::new()
            .update(&state)
            .update(&remote_static_key.to_vec())
            .finalize();

        // generate ephemeral key pair and apply MixHash(epub)
        let sk = EphemeralPrivateKey::new();
        let pk = sk.public_key();
        let state = Sha256::new().update(&state).update(&pk).finalize();

        // perform dh and return chaining & local key
        let (chaining_key, mut local_key) = {
            // perform DH
            let mut shared = sk.diffie_hellman(remote_static_key);

            // temp key
            let mut temp_key = Hmac::new(&chaining_key).update(&shared).finalize();

            // output 1
            let chaining_key = Hmac::new(&temp_key).update(&[0x01]).finalize();

            // output 2
            let local_key = Hmac::new(&temp_key)
                .update(&chaining_key)
                .update(&[0x02])
                .finalize();

            shared.zeroize();
            temp_key.zeroize();

            (chaining_key, local_key)
        };

        // encrypt X
        let mut aes = Aes::new_encryptor(&router_hash, &iv);
        let encrypted_x = aes.encrypt(pk.as_ref().to_vec());

        // create `SessionRequest` message
        let mut buffer = alloc::vec![0u8; 96];

        // TODO: generate random padding
        // TODO: request random bytes from runtime
        let padding = alloc::vec![3u8; 32];

        let mut options = InitiatorOptions {
            id: 2,
            version: 2,
            padding_length: 32u16.to_be_bytes(),
            m3_p2_len: (local_info.len() as u16 + 20u16).to_be_bytes(),
            reserved1: 0u16.to_be_bytes(),
            timestamp: (R::time_since_epoch()
                .expect("to acquire system time successfully")
                .as_secs() as u32)
                .to_be_bytes(),
            reserved2: 0u32.to_be_bytes(),
        }
        .as_bytes()
        .to_vec();

        let tag = ChaChaPoly::new(&local_key).encrypt_with_ad(&state, &mut options)?;

        local_key.zeroize();

        buffer[..32].copy_from_slice(&encrypted_x);
        buffer[32..48].copy_from_slice(&options);
        buffer[48..64].copy_from_slice(&tag);
        buffer[64..96].copy_from_slice(&padding);

        // https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-handshake-message-2-and-message-3-part-1
        let state = {
            // MixHash(encrypted payload)
            let state = Sha256::new()
                .update(&state)
                .update(&buffer[32..64])
                .finalize();

            // MixHash(padding)
            Sha256::new()
                .update(&state)
                .update(&buffer[64..96])
                .finalize()
        };

        Ok((
            Self {
                state: InitiatorState::SessionRequested {
                    state,
                    router_hash,
                    local_info,
                    chaining_key,
                    iv: aes.iv(),
                    ephemeral_key: sk,
                    local_static_key,
                },
            },
            buffer,
        ))
    }

    /// Register `SessionConfirmed` message from responder (Bob).
    ///
    /// Decrypt `Y` and perform KDF for messages 2 and 3 part 1
    ///
    /// [KDF part 2](https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-handshake-message-2-and-message-3-part-1)
    pub fn register_session_confirmed(&mut self, bytes: &[u8]) -> crate::Result<usize> {
        let InitiatorState::SessionRequested {
            mut state,
            iv,
            local_info,
            ephemeral_key,
            local_static_key,
            router_hash,
            chaining_key,
        } = core::mem::take(&mut self.state)
        else {
            return Err(Error::InvalidState);
        };

        tracing::trace!(
            target: LOG_TARGET,
            router = ?base64_encode(&router_hash),
            "session created"
        );

        // decrypt `Y`
        let mut aes = Aes::new_decryptor(&router_hash, &iv);
        let y = aes.decrypt(bytes[..32].to_vec());

        // MixHash(e.pubkey)
        state = Sha256::new().update(&state).update(&y).finalize();

        // TODO: epxlain what happens here
        let (chaining_key, remote_key, responder_public) = {
            let responder_public = StaticPublicKey::from_bytes(y).ok_or(Error::InvalidData)?;
            let mut shared = ephemeral_key.diffie_hellman(&responder_public);
            let mut temp_key = Hmac::new(&chaining_key).update(&shared).finalize();

            // output 1
            let chaining_key = Hmac::new(&temp_key).update(&[0x01]).finalize();

            // output 2
            let remote_key = Hmac::new(&temp_key)
                .update(&chaining_key)
                .update(&[0x02])
                .finalize();

            ephemeral_key.zeroize();
            shared.zeroize();
            temp_key.zeroize();

            (chaining_key, remote_key, responder_public)
        };

        // create new state by hashing the encrypted contents of `SessionCreated` but
        // don't save it to `self.state` as associated data for `bytes` (decrypted below)
        // refers to state before these payload bytes
        let new_state = Sha256::new()
            .update(&state)
            .update(&bytes[32..64])
            .finalize();

        // decrypt the chacha20poly1305 frame with generated remote key,
        // deserialize `ResponderOptions` and extract the padding length
        let padding = {
            let mut options = bytes[32..64].to_vec();
            ChaChaPoly::new(&remote_key).decrypt_with_ad(&state, &mut options)?;

            u16::from_be_bytes(
                ResponderOptions::ref_from_prefix(&options)
                    .ok_or(Error::InvalidData)?
                    .padding_length,
            ) as usize
        };

        self.state = InitiatorState::SessionCreated {
            state: new_state,
            local_info,
            local_static_key,
            router_hash,
            chaining_key,
            remote_key,
            responder_public,
        };

        Ok(padding)
    }

    /// Finalize session.
    ///
    /// Include `padding` bytes to current state, perform Diffie-Hellman key exchange
    /// between responder's public key and local private key, create `SessionConfirmed`
    /// message which contains local public key & router info and finally derive keys
    /// for the data phase.
    ///
    /// [KDF for data phase](https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-data-phase)
    pub fn finalize(&mut self, padding: &[u8]) -> crate::Result<(KeyContext, Vec<u8>)> {
        let InitiatorState::SessionCreated {
            mut state,
            local_info,
            local_static_key,
            chaining_key,
            router_hash,
            remote_key,
            responder_public,
        } = core::mem::take(&mut self.state)
        else {
            return Err(Error::InvalidState);
        };

        tracing::trace!(
            target: LOG_TARGET,
            router = ?base64_encode(&router_hash),
            "confirm session"
        );

        // MixHash(padding)
        state = Sha256::new().update(&state).update(&padding).finalize();

        // encrypt local public key
        let mut s_p_bytes = local_static_key.public().to_vec();
        let mut cipher = ChaChaPoly::with_nonce(&remote_key, 1);
        let tag1 = cipher.encrypt_with_ad(&state, &mut s_p_bytes)?;

        // MixHash(ciphertext)
        state = Sha256::new()
            .update(&state)
            .update(&s_p_bytes)
            .update(&tag1)
            .finalize();

        // perform diffie-hellman key exchange and derive keys for data phase
        let (key_context, message) = {
            let mut shared = local_static_key.diffie_hellman(&responder_public);

            // MixKey(DH())
            //
            // Generate a temp key from the chaining key and DH result
            // ck is the chaining key, from the KDF for handshake message 1
            let temp_key = Hmac::new(&chaining_key).update(&shared).finalize();

            // Output 1
            // Set a new chaining key from the temp key
            let mut chaining_key = Hmac::new(&temp_key).update(&[0x01]).finalize();

            // Output 2
            // Generate the cipher key k
            let k = Hmac::new(&temp_key)
                .update(&chaining_key)
                .update(&[0x02])
                .finalize();

            // h from message 3 part 1 is used as the associated data for the AEAD in message 3 part 2
            let mut message = Message::new_router_info(&local_info);

            let mut cipher = ChaChaPoly::with_nonce(&k, 0);
            let tag2 = cipher.encrypt_with_ad(&state, &mut message)?;

            // MixHash(ciphertext)
            let state = Sha256::new()
                .update(&state)
                .update(&message)
                .update(&tag2)
                .finalize();

            // create `SessionConfirmed` message
            let mut total_buffer = alloc::vec![0u8; local_info.len() + 20 + 48];

            total_buffer[..32].copy_from_slice(&s_p_bytes);
            total_buffer[32..48].copy_from_slice(&tag1);
            total_buffer[48..48 + local_info.len() + 4].copy_from_slice(&message);
            total_buffer[48 + local_info.len() + 4..4 + 48 + local_info.len() + 16]
                .copy_from_slice(&tag2);

            // create send and receive keys
            let temp_key = Hmac::new(&chaining_key).update(&[]).finalize();
            let send_key = Hmac::new(&temp_key).update(&[0x01]).finalize();
            let receive_key = Hmac::new(&temp_key)
                .update(&send_key)
                .update(&[0x02])
                .finalize();

            // siphash context for (de)obfuscating message sizes
            let sip = SipHash::new(&temp_key, &state);

            chaining_key.zeroize();
            shared.zeroize();
            responder_public.zeroize();

            (KeyContext::new(send_key, receive_key, sip), total_buffer)
        };

        Ok((key_context, message))
    }
}
