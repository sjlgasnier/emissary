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

//! NTCP2 Noise handshake implementation for responder (Bob)
//!
//! https://geti2p.net/spec/ntcp2#overview
//!
//! Implementation refers to `ck` as `chaining_key` and to `h` as `state`.

use crate::{
    crypto::{
        aes::cbc::Aes, chachapoly::ChaChaPoly, hmac::Hmac, sha256::Sha256, siphash::SipHash,
        EphemeralPrivateKey, StaticPrivateKey, StaticPublicKey,
    },
    primitives::RouterInfo,
    runtime::Runtime,
    transports::ntcp2::{
        message::MessageBlock,
        options::{InitiatorOptions, ResponderOptions},
        session::KeyContext,
    },
    Error,
};

use bytes::{BufMut, BytesMut};
use rand_core::RngCore;
use zeroize::Zeroize;

use alloc::{boxed::Box, vec::Vec};
use core::fmt;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ntcp2::responder";

/// Responder state.
enum ResponderState {
    /// Responder has received `SessionRequest` message from remote peer,
    /// has initialized NTCP2 session state and is waiting to read padding bytes
    SessionRequested {
        /// State.
        state: Vec<u8>,

        /// Local router hash.
        local_router_hash: Vec<u8>,

        /// AES IV.
        iv: [u8; 16],

        /// Initator's ephemeral public key.
        ephemeral_key: Box<StaticPublicKey>,

        /// Chaining key.
        chaining_key: Vec<u8>,

        /// Message 3 part 2 length.
        m3_p2_len: usize,
    },

    /// Responder has read the padding bytes and
    /// has accepted the session by creatin `SessionCreated` message.
    SessionCreated {
        /// State.
        state: Vec<u8>,

        /// Local key.
        local_key: Vec<u8>,

        /// Chaining key.
        chaining_key: Vec<u8>,

        /// Ephemeral public.
        ephemeral_private: EphemeralPrivateKey,
    },

    /// Responder state has been poisoned.
    Poisoned,
}

impl fmt::Debug for ResponderState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionRequested { .. } =>
                f.debug_struct("SessionRequested").finish_non_exhaustive(),
            Self::SessionCreated { .. } => f.debug_struct("SessionCreated").finish_non_exhaustive(),
            Self::Poisoned => f.debug_struct("Poisoned").finish(),
        }
    }
}

impl Default for ResponderState {
    fn default() -> Self {
        Self::Poisoned
    }
}

/// Noise handshake initiator
pub struct Responder {
    /// Responder state.
    state: ResponderState,
}

impl Responder {
    /// Create new [`Handshaker`] for responder.
    ///
    /// Decrypt and parse the `SessionCreated` message received from remote.
    ///
    /// If the session is accepted (no decryption errors, valid options),
    /// [`Responder::new()`] returns the amount of padding bytes that need
    /// to be read from the socket in order for the session to make progress.
    ///
    /// [1]: [KDF part 1](https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-handshake-message-1)
    pub fn new(
        state: &[u8],
        chaining_key: &[u8],
        local_router_hash: Vec<u8>,
        local_static_key: StaticPrivateKey,
        iv: [u8; 16],
        message: Vec<u8>,
        net_id: u8,
    ) -> crate::Result<(Self, usize)> {
        tracing::trace!(
            target: LOG_TARGET,
            "accept new connection"
        );

        // decrypt X
        let mut aes = Aes::new_decryptor(&local_router_hash, &iv);
        let x = aes.decrypt(&message[..32]);

        let state = Sha256::new().update(state).update(&x).finalize();

        // perform dh and return chaining & local key
        let (chaining_key, mut remote_key, ephemeral_key) = {
            let epub = StaticPublicKey::from_bytes(&x).ok_or(Error::InvalidData)?;
            let mut shared = local_static_key.diffie_hellman(&epub);
            let mut temp_key = Hmac::new(chaining_key).update(&shared).finalize();
            let chaining_key = Hmac::new(&temp_key).update([0x01]).finalize();
            let remote_key = Hmac::new(&temp_key).update(&chaining_key).update([0x02]).finalize();

            shared.zeroize();
            temp_key.zeroize();

            (chaining_key, remote_key, epub)
        };

        // calculate new state before decrypting options because associated date
        // for the chachapoly cipher round depends on current state
        //
        // padding hasn't been read from the socket yet so only the encrypted payload
        // is MixHash()ed
        //
        // padding is MixHash()ed in [`Responder::create_session()`]
        //
        // https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-handshake-message-2-and-message-3-part-1
        //
        // MixHash(encrypted payload)
        let new_state = Sha256::new().update(&state).update(&message[32..64]).finalize();

        let mut options = message[32..].to_vec();
        ChaChaPoly::new(&remote_key).decrypt_with_ad(&state, &mut options)?;

        remote_key.zeroize();

        let options = InitiatorOptions::parse(&options).ok_or(Error::InvalidData)?;
        if options.network_id != net_id {
            tracing::warn!(
                target: LOG_TARGET,
                local_net_id = ?net_id,
                remote_net_id = ?options.network_id,
                "network id mismatch",
            );
            return Err(Error::InvalidData);
        }

        if options.version != 2 {
            tracing::warn!(
                target: LOG_TARGET,
                local_version = 2,
                remote_version = ?options.version,
                "ntcp2 version mismatch",
            );
            return Err(Error::InvalidData);
        }

        let padding_len = options.padding_length as usize;
        let m3_p2_len = options.m3_p2_len as usize;

        tracing::trace!(
            target: LOG_TARGET,
            ?padding_len,
            ?m3_p2_len,
            "ntcp2 session accepted",
        );

        Ok((
            Self {
                state: ResponderState::SessionRequested {
                    state: new_state,
                    local_router_hash,
                    iv: aes.iv(),
                    chaining_key,
                    m3_p2_len,
                    ephemeral_key: Box::new(ephemeral_key),
                },
            },
            padding_len,
        ))
    }

    /// Register padding to `Responder`.
    ///
    /// `SessionRequest` message is variable-length and doesn't reveal how much
    /// padding the message contains so processing of the `SessionCreate` is split
    /// into two functions:
    ///
    /// - [`Responder::new()`]
    /// - [`Responder::create_session()`]
    ///
    /// If the session is accepted, `SessionCreated` message is returned which the
    /// caller must send to remote peer in order for the session to make progress.
    pub fn create_session<R: Runtime>(
        &mut self,
        padding: Vec<u8>,
    ) -> crate::Result<(BytesMut, usize)> {
        let ResponderState::SessionRequested {
            state,
            local_router_hash,
            iv,
            ephemeral_key,
            chaining_key,
            m3_p2_len,
        } = core::mem::take(&mut self.state)
        else {
            return Err(Error::InvalidState);
        };

        tracing::trace!(
            target: LOG_TARGET,
            padding_len = ?padding.len(),
            "create session",
        );

        // MixHash(padding)
        //
        // https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-handshake-message-2-and-message-3-part-1
        let state = Sha256::new().update(&state).update(&padding).finalize();

        // generate ephemeral key pair and apply MixHash(epub)
        let sk = EphemeralPrivateKey::random(R::rng());
        let pk = sk.public_key();
        let state = Sha256::new().update(&state).update(&pk).finalize();

        // perform dh between initator's and responder's ephemeral keys
        // and derive local key for encrypting message part 2
        let (chaining_key, local_key) = {
            let mut shared = sk.diffie_hellman(&*ephemeral_key);
            let mut temp_key = Hmac::new(&chaining_key).update(&shared).finalize();
            let chaining_key = Hmac::new(&temp_key).update([0x01]).finalize();
            let local_key = Hmac::new(&temp_key).update(&chaining_key).update([0x02]).finalize();

            shared.zeroize();
            temp_key.zeroize();

            (chaining_key, local_key)
        };

        // encrypt `Y`
        let mut aes = Aes::new_encryptor(&local_router_hash, &iv);
        let ciphertext = aes.encrypt(pk);

        // encrypt options and construct `SessionCreated message`
        let mut options = ResponderOptions {
            padding_length: 32u16,
            timestamp: R::time_since_epoch().as_secs() as u32,
        }
        .serialize();

        let tag = ChaChaPoly::new(&local_key).encrypt_with_ad(&state, &mut options)?;
        let message = {
            let mut padding = [0u8; 32];
            R::rng().fill_bytes(&mut padding);

            let mut message = BytesMut::with_capacity(96);
            message.put_slice(&ciphertext);
            message.put_slice(&options);
            message.put_slice(&tag);
            message.put_slice(&padding);

            message
        };

        // https://geti2p.net/spec/ntcp2#encryption-for-for-handshake-message-3-part-1-using-message-2-kdf
        let state = {
            // MixHash(ciphertext)
            let state = Sha256::new().update(&state).update(&message[32..64]).finalize();

            // MixHash(padding)
            Sha256::new().update(&state).update(&message[64..]).finalize()
        };

        self.state = ResponderState::SessionCreated {
            state,
            chaining_key,
            local_key,
            ephemeral_private: sk,
        };

        Ok((message, 48 + m3_p2_len))
    }

    /// Finalize handshake.
    ///
    /// `SessionConfirmed` has been received from the remote peer and the session can be finalize.
    ///
    /// This entails decrypting remote's public key, performing Diffie-Hellman key exchange on that
    /// public key and local private key, deriving ChaCha20Poly1305 keys for the data phase
    /// and generating SipHash keys for (de)obfuscation of payload lengths.
    ///
    /// https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-handshake-message-3-part-2
    /// https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-data-phase
    pub fn finalize(&mut self, message: Vec<u8>) -> crate::Result<(KeyContext, RouterInfo)> {
        let ResponderState::SessionCreated {
            state,
            chaining_key,
            local_key,
            ephemeral_private,
        } = core::mem::take(&mut self.state)
        else {
            return Err(Error::InvalidState);
        };

        tracing::trace!(
            target: LOG_TARGET,
            message_len = ?message.len(),
            "finalize ntcp2 handshake",
        );

        // calculate new state before decrypting initiator's public key
        // as the associated data for that call depends on state before
        // the the message is decrypted
        //
        // MixHash(ciphertext)
        let new_state = Sha256::new().update(&state).update(&message[..48]).finalize();

        // decrypt remote's static public key
        let mut initiator_public = message[..48].to_vec();
        let mut cipher = ChaChaPoly::with_nonce(&local_key, 1u64);

        cipher.decrypt_with_ad(&state, &mut initiator_public).inspect_err(|error| {
            tracing::debug!(
                target: LOG_TARGET,
                ?error,
                "failed to decrypt remote's public key"
            );
        })?;

        // perform diffie-hellman key exchange and derive keys for data phase
        //
        // https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-data-phase
        let initiator_public =
            StaticPublicKey::from_bytes(&initiator_public[..32]).ok_or(Error::InvalidData)?;
        let mut shared = ephemeral_private.diffie_hellman(&initiator_public);

        // MixKey(DH())
        //
        // Generate a temp key from the chaining key and DH result
        // ck is the chaining key, from the KDF for handshake message 1
        let temp_key = Hmac::new(&chaining_key).update(&shared).finalize();
        let mut chaining_key = Hmac::new(&temp_key).update([0x01]).finalize();
        let k = Hmac::new(&temp_key).update(&chaining_key).update([0x02]).finalize();

        // MixHash(ciphertext)
        //
        // the state needs to be stored in two variables because key generation
        // for message 3 part 2 depends on the state after message 3 part 1 whereas
        // key generation for the session (including siphash) depends on both ciphertexts
        let (state, next_state) = {
            let next_state = Sha256::new().update(&new_state).update(&message[48..]).finalize();

            (new_state, next_state)
        };

        // decrypt remote's router info and parse it into `RouterInfo`
        let router_info = {
            let mut router_info = message[48..].to_vec();
            let mut cipher = ChaChaPoly::with_nonce(&k, 0);

            cipher.decrypt_with_ad(&state, &mut router_info).inspect_err(|error| {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to decrypt remote's router info"
                );
            })?;

            match MessageBlock::parse(&router_info) {
                Some(MessageBlock::RouterInfo { router_info, .. }) =>
                    RouterInfo::parse(router_info).ok_or_else(|| {
                        tracing::warn!(
                            target: LOG_TARGET,
                            "received malformed `RouterInfo` message block"
                        );

                        Error::InvalidData
                    }),
                message => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?message,
                        "failed to parse router info",
                    );
                    Err(Error::InvalidData)
                }
            }
        }?;

        // create send and receive keys
        let temp_key = Hmac::new(&chaining_key).update([]).finalize();
        let send_key = Hmac::new(&temp_key).update([0x01]).finalize();
        let recv_key = Hmac::new(&temp_key).update(&send_key).update([0x02]).finalize();

        // siphash context for (de)obfuscating message sizes
        let sip = SipHash::new_responder(&temp_key, &next_state);

        chaining_key.zeroize();
        shared.zeroize();

        Ok((KeyContext::new(recv_key, send_key, sip), router_info))
    }
}
