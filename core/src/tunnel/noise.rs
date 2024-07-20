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
use core::fmt;

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
                tunnel_id = ?record.tunnel_id(),
                next_tunnel_id = ?record.next_tunnel_id(),
                // next_message_id = record.next_message_id(),
                // next_router_hash = ?base64_encode(record.next_router_hash()),
                "VARIABLE TUNNEL BUILT",
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

            // tracing::trace!(
            //     target: LOG_TARGET,
            //     role = ?record.role(),
            //     tunnel_id = record.tunnel_id(),
            //     next_tunnel_id = record.next_tunnel_id(),
            //     next_message_id = record.next_message_id(),
            //     "record info",
            // );
            tracing::trace!(
                target: LOG_TARGET,
                role = ?record.role(),
                tunnel_id = ?record.tunnel_id(),
                next_tunnel_id = ?record.next_tunnel_id(),
                // next_message_id = record.next_message_id(),
                // next_router_hash = ?base64_encode(record.next_router_hash()),
                "SHORT TUNNEL BUILT",
            );

            let hop = TunnelHop {
                role: record.role(),
                tunnel_id: record.tunnel_id(),
                next_tunnel_id: record.next_tunnel_id(),
                next_router_id: RouterId::from(base64_encode(&record.next_router_hash()[..16])),
                layer_key,
                iv_key: match record.role() {
                    HopRole::OutboundEndpoint => iv_key,
                    _ => else_key,
                },
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

    pub fn handle_tunnel_data(&mut self, mut payload: Vec<u8>) -> Option<(Vec<u8>, RouterId)> {
        // TODO: no unwraps
        let tunnel_data = EncryptedTunnelData::parse(&payload).unwrap();
        let hop = self.tunnels.get(&tunnel_data.tunnel_id()).unwrap();

        tracing::info!(
            target: LOG_TARGET,
            tunnel_id = ?hop.tunnel_id,
            next_tunnel_id = ?hop.next_tunnel_id,
            next_router_id = %hop.next_router_id,
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
                out[20..].copy_from_slice(&ciphertext);

                // TODO: copy
                return Some((out, hop.next_router_id.clone()));
            }
            HopRole::OutboundEndpoint => {
                tracing::error!("handle outbound endpoint");

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
                    panic!("zzz");
                    return None;
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

                                return Some((
                                    message.message.to_vec(),
                                    RouterId::from(base64_encode(&hash[..16])),
                                ));
                            }
                            DeliveryInstruction::Tunnel { hash, tunnel_id } => tracing::warn!(
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

        None
        // todo!();
    }
}

use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u32, be_u8},
    sequence::tuple,
    Err, IResult,
};

#[derive(Debug)]
enum GarlicMessageType {
    DateTime,
    Termination,
    Options,
    MessageNumber,
    NextKey,
    ACK,
    ACKRequest,
    GarlicClove,
    Padding,
}

impl GarlicMessageType {
    fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::DateTime),
            4 => Some(Self::Termination),
            5 => Some(Self::Options),
            6 => Some(Self::MessageNumber),
            7 => Some(Self::NextKey),
            8 => Some(Self::ACK),
            9 => Some(Self::ACKRequest),
            11 => Some(Self::GarlicClove),
            254 => Some(Self::Padding),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum DeliveryInstructions<'a> {
    /// Clove meant for the local node
    Local,

    /// Clove meant for a `Destination`.
    Destination {
        /// Hash of the destination.
        hash: &'a [u8],
    },

    /// Clove meant for a router.
    Router {
        /// Hash of the router.
        hash: &'a [u8],
    },

    /// Clove meant for a tunnel.
    Tunnel {
        /// Hash of the tunnel.
        hash: &'a [u8],

        /// Tunnel ID.
        tunnel_id: u32,
    },
}

impl<'a> DeliveryInstructions<'a> {
    fn serialized_len(&self) -> usize {
        match self {
            // 1-byte flag
            Self::Local => 1usize,

            // 1-byte flag + 32-byte router hash
            Self::Destination { .. } | Self::Router { .. } => 33usize,

            // 1-byte flag + 32-byte router hash + 4-byte tunnel id
            Self::Tunnel { .. } => 37usize,
        }
    }
}

enum GarlicMessageBlock<'a> {
    /// Date time.
    DateTime {
        /// Timestamp.
        timestamp: u32,
    },

    /// Session termination.
    Termination {},

    /// Options.
    Options {},

    ///
    MessageNumber {},
    NextKey {},
    ACK {},
    ACKRequest {},
    GarlicClove {
        /// I2NP message type.
        message_type: MessageType,

        /// Message ID.
        message_id: u32,

        /// Message expiration.
        expiration: u32,

        /// Delivery instructions.
        delivery_instructions: DeliveryInstructions<'a>,

        /// Message body.
        message_body: &'a [u8],
    },

    /// Padding
    Padding {
        /// Padding bytes.
        padding: &'a [u8],
    },
}

impl<'a> fmt::Debug for GarlicMessageBlock<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DateTime { timestamp } => f
                .debug_struct("GarlicMessageBlock::DateTime")
                .field("timestamp", &timestamp)
                .finish(),
            Self::GarlicClove {
                message_type,
                message_id,
                expiration,
                delivery_instructions,
                ..
            } => f
                .debug_struct("DeliveryInstructions::GarlicClove")
                .field("message_type", &message_type)
                .field("message_id", &message_id)
                .field("expiration", &expiration)
                .field("delivery_instructions", &delivery_instructions)
                .finish_non_exhaustive(),
            Self::Padding { .. } =>
                f.debug_struct("DeliveryInstructions::Padding").finish_non_exhaustive(),
            _ => todo!(),
        }
    }
}

#[derive(Debug)]
struct GarlicMessage<'a> {
    blocks: Vec<GarlicMessageBlock<'a>>,
}

impl<'a> GarlicMessage<'a> {
    /// Try to parse [`GarlicMessage::DateTime`] from `input`.
    fn parse_date_time(input: &'a [u8]) -> IResult<&'a [u8], GarlicMessageBlock<'a>> {
        let (rest, size) = be_u16(input)?;
        let (rest, timestamp) = be_u32(rest)?;

        debug_assert!(size == 4, "invalid size for datetime block");

        Ok((rest, GarlicMessageBlock::DateTime { timestamp }))
    }

    /// Try to parse [`DeliveryInstructions`] for [`GarlicMessage::GarlicClove`] from `input`.
    fn parse_delivery_instructions(input: &'a [u8]) -> IResult<&'a [u8], DeliveryInstructions<'a>> {
        let (rest, flag) = be_u8(input)?;

        // TODO: handle gracefully
        assert!(flag >> 7 & 1 == 0, "encrypted garlic");
        assert!(flag >> 4 & 1 == 0, "delay");

        match (flag >> 5) & 0x3 {
            0x00 => Ok((rest, DeliveryInstructions::Local)),
            0x01 => {
                let (rest, hash) = take(32usize)(rest)?;

                Ok((rest, DeliveryInstructions::Destination { hash }))
            }
            0x02 => {
                let (rest, hash) = take(32usize)(rest)?;

                Ok((rest, DeliveryInstructions::Router { hash }))
            }
            0x03 => {
                let (rest, hash) = take(32usize)(rest)?;
                let (rest, tunnel_id) = be_u32(rest)?;

                Ok((rest, DeliveryInstructions::Tunnel { hash, tunnel_id }))
            }
            _ => panic!("invalid garlic type"), // TODO: don't panic
        }
    }

    /// Try to parse [`GarlicMessage::GarlicClove`] from `input`.
    fn parse_garlic_clove(input: &'a [u8]) -> IResult<&'a [u8], GarlicMessageBlock<'a>> {
        let (rest, size) = be_u16(input)?;
        let (rest, delivery_instructions) = Self::parse_delivery_instructions(rest)?;
        let (rest, message_type) = be_u8(rest)?;
        let (rest, message_id) = be_u32(rest)?;
        let (rest, expiration) = be_u32(rest)?;

        let message_type = MessageType::from_u8(message_type)
            .ok_or_else(|| Err::Error(make_error(input, ErrorKind::Fail)))?;

        // parse body and make sure it has sane length
        let message_body_len =
            (size as usize).saturating_sub(delivery_instructions.serialized_len() + 1 + 2 * 4);
        let (rest, message_body) = take(message_body_len)(rest)?;

        Ok((
            rest,
            GarlicMessageBlock::GarlicClove {
                message_type,
                message_id,
                expiration,
                delivery_instructions,
                message_body,
            },
        ))
    }

    /// Try to parse [`GarlicMessage::Padding`] from `input`.
    fn parse_padding(input: &'a [u8]) -> IResult<&'a [u8], GarlicMessageBlock<'a>> {
        let (rest, size) = be_u16(input)?;
        let (rest, padding) = take(size)(rest)?;

        Ok((rest, GarlicMessageBlock::Padding { padding }))
    }

    fn parse_frame(input: &'a [u8]) -> IResult<&'a [u8], GarlicMessageBlock<'a>> {
        let (rest, message_type) = be_u8(input)?;

        match GarlicMessageType::from_u8(message_type) {
            Some(GarlicMessageType::DateTime) => Self::parse_date_time(rest),
            Some(GarlicMessageType::GarlicClove) => Self::parse_garlic_clove(rest),
            Some(GarlicMessageType::Padding) => Self::parse_padding(rest),
            message_type => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?message_type,
                    "invalid garlic message block",
                );
                return Err(Err::Error(make_error(input, ErrorKind::Fail)));
            }
        }
    }

    /// Recursively parse `input` into a vector of [`GarlicMessageBlock`]s
    fn parse_inner(
        input: &'a [u8],
        mut messages: Vec<GarlicMessageBlock<'a>>,
    ) -> Option<(Vec<GarlicMessageBlock<'a>>)> {
        let (rest, message) = Self::parse_frame(input).ok()?;
        messages.push(message);

        match rest.is_empty() {
            true => Some(messages),
            false => Self::parse_inner(rest, messages),
        }
    }

    /// Attempt to parse `input` into [`GarlicMessage`].
    pub fn parse(input: &'a [u8]) -> Option<Self> {
        Some(Self {
            blocks: Self::parse_inner(input, Vec::new())?,
        })
    }
}
