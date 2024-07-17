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
        aes::{cbc, ecb},
        base64_encode,
        chachapoly::ChaChaPoly,
        hmac::Hmac,
        sha256::Sha256,
        EphemeralPublicKey, StaticPrivateKey, StaticPublicKey,
    },
    i2np::{
        DeliveryInstruction, EncryptedTunnelBuildRequestRecord, EncryptedTunnelData, HopRole,
        MessageKind, MessageType, RawI2npMessage, ShortTunnelBuildRecord, TunnelBuildRecord,
        TunnelData,
    },
    primitives::RouterId,
    tunnel::LOG_TARGET,
};

use hashbrown::HashMap;
use zeroize::Zeroize;

use alloc::{vec, vec::Vec};

/// Noise protocol name;.
const PROTOCOL_NAME: &str = "Noise_N_25519_ChaChaPoly_SHA256";

struct TunnelHop {
    /// Tunnel hop kind.
    role: HopRole,

    /// Tunnel ID.
    ///
    /// Assigned by the tunnel creator to us.
    tunnel_id: u32,

    /// Next tunnel ID.
    ///
    /// Assigned by the tunnel creator to the next hop.
    next_tunnel_id: u32,

    /// Next router ID.
    next_router_id: RouterId,

    /// Layer key.
    ///
    /// TODO: docs
    layer_key: Vec<u8>,

    /// IV key.
    ///
    /// TODO: docs
    iv_key: Vec<u8>,
}

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

    /// Tunnel hops.
    tunnels: HashMap<u32, TunnelHop>,
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
            tunnels: HashMap::new(),
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
        // TODO: better abstraction
        let mut record = payload[1..].chunks_mut(528).find(|chunk| &chunk[..16] == truncated)?;

        // TODO: no unwraps
        let state = Sha256::new().update(&self.inbound_state).update(&record[16..48]).finalize();
        let (chaining_key, aead_key) =
            self.derive_keys(StaticPublicKey::from_bytes(record[16..48].to_vec()).unwrap());
        let new_state = Sha256::new().update(&state).update(&record[48..]).finalize();

        let mut test = record[48..528].to_vec();
        ChaChaPoly::new(&aead_key).decrypt_with_ad(&state, &mut test).unwrap();

        let (next_router, message_id, message_type) = {
            let record = TunnelBuildRecord::parse(&test).unwrap(); // TODO: no unwraps

            let layer_key = record.tunnel_layer_key().to_vec();
            let iv_key = record.tunnel_iv_key().to_vec();

            tracing::trace!(
                target: LOG_TARGET,
                role = ?record.role(),
                next_message_id = record.next_message_id(),
                next_router_hash = ?base64_encode(record.next_router_hash()),
                "record info",
            );

            let hop = TunnelHop {
                role: record.role(),
                tunnel_id: record.tunnel_id(),
                next_tunnel_id: record.next_tunnel_id(),
                next_router_id: RouterId::from(base64_encode(&record.next_router_hash()[..16])),
                layer_key,
                iv_key,
            };
            self.tunnels.insert(record.tunnel_id(), hop);

            ((
                RouterId::from(base64_encode(&record.next_router_hash()[..16])),
                record.next_message_id(),
                match record.role() {
                    HopRole::OutboundEndpoint => MessageType::VariableTunnelBuildReply,
                    _ => MessageType::VariableTunnelBuild,
                },
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

        Some((payload, next_router, message_id, message_type))
    }

    /// TODO: explain
    // TODO: verify source of this message is the same as last message
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

        // TODO: garlic tag
        // TODO: save garlic key somewhere
        let mut temp_key = Hmac::new(&ck).update(&[]).finalize();
        let ck = Hmac::new(&temp_key).update(&b"RGarlicKeyAndTag").update(&[0x01]).finalize();
        let garlic_key = Hmac::new(&temp_key)
            .update(&ck)
            .update(&b"RGarlicKeyAndTag")
            .update(&[0x02])
            .finalize();

        let mut test = record[48..].to_vec();
        ChaChaPoly::new(&aead_key).decrypt_with_ad(&state, &mut test).unwrap();

        let (next_router, message_id, message_type) = {
            let record = ShortTunnelBuildRecord::parse(&test).unwrap(); // TODO: no unwraps

            tracing::trace!(
                target: LOG_TARGET,
                role = ?record.role(),
                tunnel_id = record.tunnel_id(),
                next_tunnel_id = record.next_tunnel_id(),
                next_message_id = record.next_message_id(),
                "record info",
            );

            let hop = TunnelHop {
                role: record.role(),
                tunnel_id: record.tunnel_id(),
                next_tunnel_id: record.next_tunnel_id(),
                next_router_id: RouterId::from(base64_encode(&record.next_router_hash()[..16])),
                layer_key,
                iv_key,
            };
            self.tunnels.insert(record.tunnel_id(), hop);

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

        let tag = ChaChaPoly::with_nonce(&reply_key, index as u64)
            .encrypt_with_ad(&new_state, &mut record[0..202])
            .unwrap();
        record[202..218].copy_from_slice(&tag);

        // TODO: fix
        // TODO: fix what?
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

    pub fn handle_tunnel_data(&mut self, mut payload: Vec<u8>) -> (RouterId, Vec<u8>) {
        // TODO: no unwraps
        let tunnel_data = EncryptedTunnelData::parse(&payload).unwrap();
        let hop = self.tunnels.get(&tunnel_data.tunnel_id()).unwrap();

        tracing::info!(
            target: LOG_TARGET,
            tunnel_id = ?hop.tunnel_id,
            next_tunnel_id = ?hop.next_tunnel_id,
            next_router_id = ?hop.next_router_id,
            payload_len = ?tunnel_data.ciphertext().len(),
            "tunnel data",
        );

        match hop.role {
            HopRole::InboundGateway => todo!("inbound gateway not supported"),
            HopRole::Intermediary => {
                let mut aes = ecb::Aes::new_encryptor(&hop.iv_key);
                let iv = aes.encrypt(tunnel_data.iv());

                let mut aes = cbc::Aes::new_encryptor(&hop.layer_key, &iv);
                let ciphertext = aes.encrypt(tunnel_data.ciphertext());

                let mut aes = ecb::Aes::new_encryptor(&hop.iv_key);
                let iv = aes.encrypt(iv);

                let mut out = vec![0u8; 4 + 16 + tunnel_data.ciphertext().len()];

                out[..4].copy_from_slice(&hop.next_tunnel_id.to_be_bytes().to_vec());
                out[4..20].copy_from_slice(&iv);
                out[20..].copy_from_slice(&tunnel_data.ciphertext());

                return (hop.next_router_id.clone(), out);
            }
            HopRole::OutboundEndpoint => {
                let mut aes = ecb::Aes::new_encryptor(&hop.iv_key);
                let iv = aes.encrypt(tunnel_data.iv());

                let mut aes = cbc::Aes::new_encryptor(&hop.layer_key, &iv);
                let ciphertext = aes.encrypt(tunnel_data.ciphertext());

                let mut aes = ecb::Aes::new_encryptor(&hop.iv_key);
                let iv = aes.encrypt(iv);

                let res =
                    ciphertext[4..].iter().enumerate().find(|(_, byte)| byte == &&0x0).unwrap();

                let checksum =
                    Sha256::new().update(&ciphertext[4 + res.0 + 1..]).update(&iv).finalize();

                if ciphertext[..4] != checksum[..4] {
                    tracing::warn!(
                        target: LOG_TARGET,
                        payload_checksum = ?ciphertext[..4],
                        calculated = ?checksum[..4],
                        "tunnel data checksum mismatch",
                    );
                    panic!("not handled");
                }

                let message = TunnelData::parse(&ciphertext[4 + res.0 + 1..]).unwrap();

                for message in &message.messages {
                    match message.message_kind {
                        MessageKind::Unfragmented {
                            ref delivery_instructions,
                        } => match delivery_instructions {
                            DeliveryInstruction::Local => tracing::error!("todo: local delivery"),
                            DeliveryInstruction::Router { hash } => {
                                tracing::debug!(hash = ?base64_encode(hash), "router delivery");

                                return (
                                    RouterId::from(base64_encode(&hash[..16])),
                                    message.message.to_vec(),
                                );
                            }
                            DeliveryInstruction::Tunnel { hash, tunnel_id } => tracing::debug!(
                                ?tunnel_id,
                                hash = ?base64_encode(hash),
                                "todo: tunnel delivery"
                            ),
                        },
                        ref message_kind => {
                            tracing::error!("todo: handle {message_kind:?}");
                        }
                    }
                }
            }
        }

        todo!();
    }
}
