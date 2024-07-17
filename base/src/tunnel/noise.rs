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

//! Noise implementation for ECIES tunnels.
//!
//! https://geti2p.net/spec/tunnel-creation-ecies
//!
//! Implementation refers to `ck` as `chaining_key` and to `h` as `state`.

use crate::{
    crypto::{
        base64_encode, chachapoly::ChaChaPoly, hmac::Hmac, sha256::Sha256, EphemeralPublicKey,
        StaticPrivateKey, StaticPublicKey,
    },
    i2np::{
        EncryptedTunnelBuildRequestRecord, MessageType, RawI2npMessage, ShortTunnelBuildRecord,
        TunnelBuildRecord,
    },
    primitives::RouterId,
    tunnel::LOG_TARGET,
};

use alloc::{vec, vec::Vec};
use zeroize::Zeroize;

/// Noise protocol name;.
const PROTOCOL_NAME: &str = "Noise_N_25519_ChaChaPoly_SHA256";

/// Noise key context.
pub struct Noise {
    /// Chaining key.
    chaining_key: Vec<u8>,

    /// Inbound state.
    inbound_state: Vec<u8>,

    /// Local static key.
    local_key: StaticPrivateKey,

    /// Outbound state.
    outbound_state: Vec<u8>,
}

impl Noise {
    /// Create new [`Noise`].
    ///
    /// https://geti2p.net/spec/tunnel-creation-ecies#kdf-for-initial-ck-and-h
    pub fn new(local_key: StaticPrivateKey) -> Self {
        let chaining_key = {
            let mut chaining_key = PROTOCOL_NAME.as_bytes().to_vec();
            chaining_key.append(&mut vec![0u8]);
            chaining_key
        };
        let outbound_state = Sha256::new().update(&chaining_key).finalize();
        let inbound_state = Sha256::new()
            .update(&outbound_state)
            .update(local_key.public().to_bytes())
            .finalize();

        Self {
            chaining_key,
            inbound_state,
            local_key,
            outbound_state,
        }
    }

    // MixKey(DH())
    fn derive_keys(&self, ephemeral_key: StaticPublicKey) -> (Vec<u8>, Vec<u8>) {
        let mut shared_secret = self.local_key.diffie_hellman(&ephemeral_key);
        let mut temp_key = Hmac::new(&self.chaining_key).update(&shared_secret).finalize();
        let chaining_key = Hmac::new(&temp_key).update(&[0x01]).finalize();
        let aead_key = Hmac::new(&temp_key).update(&chaining_key).update(&[0x02]).finalize();

        temp_key.zeroize();
        shared_secret.zeroize();

        (chaining_key, aead_key)
    }

    /// TODO: explain
    ///
    /// TODO: return `TunnelHop`?
    ///
    /// TODO: lot of refactoring needed
    ///
    /// https://geti2p.net/spec/tunnel-creation-ecies#kdf-for-request-record
    pub fn create_tunnel_hop(
        &mut self,
        truncated: &Vec<u8>,
        mut payload: Vec<u8>,
    ) -> Option<(Vec<u8>, RouterId, u32, MessageType)> {
        tracing::error!("payload size = {}", payload.len());

        // TODO: better abstraction
        let mut record = payload[1..].chunks_mut(528).find(|chunk| &chunk[..16] == truncated)?;

        // TODO: no unwraps
        let state = Sha256::new().update(&self.inbound_state).update(&record[16..48]).finalize();
        let (chaining_key, aead_key) =
            self.derive_keys(StaticPublicKey::from_bytes(record[16..48].to_vec()).unwrap());
        let new_state = Sha256::new().update(&state).update(&record[48..]).finalize();

        let mut test = record[48..528].to_vec();
        ChaChaPoly::new(&aead_key).decrypt_with_ad(&state, &mut test).unwrap();

        let (next_router, message_id) = {
            let record = TunnelBuildRecord::parse(&test).unwrap(); // TODO: no unwraps

            tracing::info!(
                target: LOG_TARGET,
                role = ?record.role(),
                next_message_id = record.next_message_id(),
                next_router_hash = ?base64_encode(record.next_router_hash()),
                "record info",
            );

            ((
                RouterId::from(base64_encode(&record.next_router_hash()[..16])),
                record.next_message_id(),
            ))
        };

        record[48] = 0x00; // no options
        record[49] = 0x00;
        record[511] = 0x00; // accept

        // TODO: needs to encrypt with aes?

        let tag = ChaChaPoly::new(&chaining_key)
            .encrypt_with_ad(&new_state, &mut record[0..512])
            .unwrap();
        record[512..528].copy_from_slice(&tag);

        Some((
            payload,
            next_router,
            message_id,
            MessageType::VariableTunnelBuildReply,
        ))
    }

    /// TODO: explain
    pub fn create_short_tunnel_hop(
        &mut self,
        truncated: &Vec<u8>,
        mut payload: Vec<u8>,
    ) -> Option<(Vec<u8>, RouterId, u32, MessageType)> {
        // TODO: better abstraction
        let (index, mut record) = payload[1..]
            .chunks_mut(218)
            .enumerate()
            .find(|(i, chunk)| &chunk[..16] == truncated)?;

        let state = Sha256::new().update(&self.inbound_state).update(&record[16..48]).finalize();
        let (chaining_key, aead_key) =
            self.derive_keys(StaticPublicKey::from_bytes(record[16..48].to_vec()).unwrap());

        let new_state = Sha256::new().update(&state).update(&record[48..]).finalize();

        let mut temp_key = Hmac::new(&chaining_key).update(&[]).finalize();
        let ck = Hmac::new(&temp_key).update(&b"SMTunnelReplyKey").update(&[0x01]).finalize();
        let reply_key = Hmac::new(&temp_key)
            .update(&ck)
            .update(&b"SMTunnelReplyKey")
            .update(&[0x02])
            .finalize();

        let mut temp_key = Hmac::new(&ck).update(&[]).finalize();
        let ck = Hmac::new(&temp_key).update(&b"SMTunnelLayerKey").update(&[0x01]).finalize();
        let layer_key = Hmac::new(&temp_key)
            .update(&ck)
            .update(&b"SMTunnelLayerKey")
            .update(&[0x02])
            .finalize();

        let else_key = ck.clone();

        let mut temp_key = Hmac::new(&ck).update(&[]).finalize();
        let ck = Hmac::new(&temp_key).update(&b"TunnelLayerIVKey").update(&[0x01]).finalize();
        let iv_key = Hmac::new(&temp_key)
            .update(&ck)
            .update(&b"TunnelLayerIVKey")
            .update(&[0x02])
            .finalize();

        let mut temp_key = Hmac::new(&ck).update(&[]).finalize();
        let ck = Hmac::new(&temp_key).update(&b"RGarlicKeyAndTag").update(&[0x01]).finalize();
        let garlic_key = Hmac::new(&temp_key)
            .update(&ck)
            .update(&b"RGarlicKeyAndTag")
            .update(&[0x02])
            .finalize();
        // TODO: garlic tag

        let mut test = record[48..].to_vec();
        ChaChaPoly::new(&aead_key).decrypt_with_ad(&state, &mut test).unwrap();

        let (next_router, message_id, message_type) = {
            let record = ShortTunnelBuildRecord::parse(&test).unwrap(); // TODO: no unwraps

            tracing::info!(
                target: LOG_TARGET,
                role = ?record.role(),
                // next_router_hash = ?base64_encode(record.next_router_hash()),
                tunnel_id = record.tunnel_id(),
                next_tunnel_id = record.next_tunnel_id(),
                next_message_id = record.next_message_id(),
                "record info",
            );

            ((
                RouterId::from(base64_encode(&record.next_router_hash()[..16])),
                record.next_message_id(),
                // TODO: fix
                match record.role() {
                    crate::i2np::HopRole::Intermediary => MessageType::ShortTunnelBuild,
                    _ => MessageType::OutboundTunnelBuildReply,
                },
            ))
        };

        record[48] = 0x00; // no options
        record[49] = 0x00;
        record[201] = 0x00; // accept

        tracing::info!("encrypt with = {reply_key:?}, nonce {index}");

        let tag = ChaChaPoly::with_nonce(&reply_key, index as u64)
            .encrypt_with_ad(&new_state, &mut record[0..202])
            .unwrap();
        record[202..218].copy_from_slice(&tag);

        // TODO: fix
        for (index_new, record) in payload[1..].chunks_mut(218).enumerate() {
            if index_new == index {
                continue;
            }

            let encrypted = ChaChaPoly::with_nonce(&reply_key, index_new as u64)
                .encrypt(&mut record[0..218])
                .unwrap();
            record[..218].copy_from_slice(&encrypted[..218]);
        }

        Some((payload, next_router, message_id, message_type))
    }
}
