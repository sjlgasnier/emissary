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

//! I2NP message parser
//!
//! https://geti2p.net/spec/i2np

use crate::{
    crypto::base64_encode,
    primitives::{Date, Mapping},
    subsystem::SubsystemKind,
};

use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u32, be_u8},
    sequence::tuple,
    Err, IResult,
};

use alloc::{vec, vec::Vec};
use core::fmt;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::i2np";

/// Garlic certificate length.
const GARLIC_CERTIFICATE_LEN: usize = 3usize;

// Truncated identity hash length.
const TRUNCATED_IDENITTY_LEN: usize = 16usize;

// x25519 ephemeral key length.
const X25519_KEY_LEN: usize = 32usize;

/// Encrypted build request length.
const ENCRYPTED_BUILD_REQUEST_LEN: usize = 464usize;

/// Poly1305 authentication tag length.
const POLY1305_TAG_LEN: usize = 16usize;

/// Poly1305 authentication tag length.
const ROUTER_HASH_LEN: usize = 32usize;

/// AES key length.
const AES256_KEY_LEN: usize = 32usize;

/// AES IV length.
const AES256_IV_LEN: usize = 16usize;

/// Message type.
#[derive(Debug, Clone, Copy)]
pub enum MessageType {
    DatabaseStore,
    DatabaseLookup,
    DatabaseSearchReply,
    DeliveryStatus,
    Garlic,
    TunnelData,
    TunnelGateway,
    Data,
    TunnelBuild,
    TunnelBuildReply,
    VariableTunnelBuild,
    VariableTunnelBuildReply,
    ShortTunnelBuild,
    OutboundTunnelBuildReply,
}

impl MessageType {
    /// Serialize [`MessageType`].
    fn serialize(&self) -> u8 {
        match self {
            Self::DatabaseStore => 1,
            Self::DatabaseLookup => 2,
            Self::DatabaseSearchReply => 3,
            Self::DeliveryStatus => 10,
            Self::Garlic => 11,
            Self::TunnelData => 18,
            Self::TunnelGateway => 19,
            Self::Data => 20,
            Self::TunnelBuild => 21,
            Self::TunnelBuildReply => 22,
            Self::VariableTunnelBuild => 23,
            Self::VariableTunnelBuildReply => 24,
            Self::ShortTunnelBuild => 25,
            Self::OutboundTunnelBuildReply => 26,
        }
    }

    pub fn from_u8(msg_type: u8) -> Option<MessageType> {
        match msg_type {
            1 => Some(Self::DatabaseStore),
            2 => Some(Self::DatabaseLookup),
            3 => Some(Self::DatabaseSearchReply),
            10 => Some(Self::DeliveryStatus),
            11 => Some(Self::Garlic),
            18 => Some(Self::TunnelData),
            19 => Some(Self::TunnelGateway),
            20 => Some(Self::Data),
            21 => Some(Self::TunnelBuild),
            22 => Some(Self::TunnelBuildReply),
            23 => Some(Self::VariableTunnelBuild),
            24 => Some(Self::VariableTunnelBuildReply),
            25 => Some(Self::ShortTunnelBuild),
            26 => Some(Self::OutboundTunnelBuildReply),
            msg_type => {
                tracing::warn!(?msg_type, "invalid message id");
                None
            }
        }
    }
}

/// Encrypted tunnel build request.
#[derive(Debug)]
pub struct EncryptedTunnelBuildRequestRecord<'a> {
    /// Truncated router identity hash.
    truncated_hash: &'a [u8],

    /// Remote's ephemeral key.
    ephemeral_key: &'a [u8],

    /// Chacha20-encrypted payload + Poly1305 authentication tag.
    ciphertext: &'a [u8],
}

impl<'a> EncryptedTunnelBuildRequestRecord<'a> {
    /// Get reference to truncated router hash.
    pub fn truncated_hash(&self) -> &'a [u8] {
        self.truncated_hash
    }

    /// Get reference to ephemeral key.
    pub fn ephemeral_key(&self) -> &'a [u8] {
        self.ephemeral_key
    }

    /// Get reference to ciphertext.
    pub fn ciphertext(&self) -> &'a [u8] {
        self.ciphertext
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopRole {
    /// Router acts as the inbound endpoint.
    InboundGateway,

    /// Router acts as the outbound endpoint.
    OutboundEndpoint,

    /// Router acts as an intermediary participant.
    Intermediary,
}

impl HopRole {
    fn from_u8(role: u8) -> Option<HopRole> {
        match role {
            0x80 => Some(HopRole::InboundGateway),
            0x40 => Some(HopRole::OutboundEndpoint),
            0x00 => Some(HopRole::Intermediary),
            role => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?role,
                    "unrecognized flag"
                );
                debug_assert!(false);
                None
            }
        }
    }
}

/// Tunnel build record.
#[derive(Debug)]
pub struct TunnelBuildRecord<'a> {
    /// Tunnel ID.
    tunnel_id: u32,

    /// Next tunnel ID.
    next_tunnel_id: u32,

    /// Next router hash.
    next_router_hash: &'a [u8],

    /// Tunnel layer key (AES-256)
    tunnel_layer_key: &'a [u8],

    /// Tunnel layer IV (AES-256)
    tunnel_iv_key: &'a [u8],

    /// Tunnel reply key (AES-256)
    tunnel_reply_key: &'a [u8],

    /// Tunnel reply IV (AES-256)
    tunnel_reply_iv: &'a [u8],

    /// Flags.
    role: HopRole,

    /// Unused flags, size is always 3 bytes.
    reserved: &'a [u8],

    /// Request time, in minutes since Unix epoch.
    request_time: u32,

    /// Tunnel expiration, in seconds since creation.
    request_expiration: u32,

    /// Next message ID.
    ///
    /// Used as reply message's message ID.
    next_message_id: u32,

    /// Options.
    options: Mapping, // TODO: `MappingRef`?,

    /// Padding.
    padding: &'a [u8],
}

impl<'a> TunnelBuildRecord<'a> {
    pub fn parse_frame(input: &'a [u8]) -> IResult<&'a [u8], TunnelBuildRecord<'a>> {
        let (rest, tunnel_id) = be_u32(input)?;
        let (rest, next_tunnel_id) = be_u32(rest)?;
        // TODO: skip unneedes stuff?
        let (rest, next_router_hash) = take(ROUTER_HASH_LEN)(rest)?;
        let (rest, tunnel_layer_key) = take(AES256_KEY_LEN)(rest)?;
        let (rest, tunnel_iv_key) = take(AES256_KEY_LEN)(rest)?;
        let (rest, tunnel_reply_key) = take(AES256_KEY_LEN)(rest)?;
        let (rest, tunnel_reply_iv) = take(AES256_IV_LEN)(rest)?;
        let (rest, flags) = be_u8(rest)?;
        let (rest, reserved) = take(3usize)(rest)?;
        let (rest, request_time) = be_u32(rest)?;
        let (rest, request_expiration) = be_u32(rest)?;
        let (rest, next_message_id) = be_u32(rest)?;
        let (rest, options) = Mapping::parse_frame(rest)?;
        let (rest, padding) = take(input.len() - rest.len())(rest)?; // TODO: correct?
        let role = HopRole::from_u8(flags).ok_or(Err::Error(make_error(input, ErrorKind::Fail)))?;

        Ok((
            rest,
            TunnelBuildRecord {
                tunnel_id,
                next_tunnel_id,
                next_router_hash,
                tunnel_layer_key,
                tunnel_iv_key,
                tunnel_reply_key,
                tunnel_reply_iv,
                role,
                reserved,
                request_time,
                request_expiration,
                next_message_id,
                options,
                padding,
            },
        ))
    }

    pub fn parse(input: &'a [u8]) -> Option<TunnelBuildRecord<'a>> {
        Some(Self::parse_frame(input).ok()?.1)
    }

    /// Get tunnel ID.
    pub fn tunnel_id(&self) -> u32 {
        self.tunnel_id
    }

    /// Get next tunnel ID.
    pub fn next_tunnel_id(&self) -> u32 {
        self.next_tunnel_id
    }

    /// Get next router hash.
    pub fn next_router_hash(&self) -> &'a [u8] {
        self.next_router_hash
    }

    /// Get hop role.
    pub fn role(&self) -> HopRole {
        self.role
    }

    /// Get request time, in minutes since Unix epoch.
    pub fn request_time(&self) -> u32 {
        self.request_time
    }

    /// Get tunnel expiration, in seconds since creation.
    pub fn request_expiration(&self) -> u32 {
        self.request_expiration
    }

    /// Get next message ID.
    pub fn next_message_id(&self) -> u32 {
        self.next_message_id
    }

    pub fn tunnel_layer_key(&self) -> &[u8] {
        self.tunnel_layer_key
    }

    pub fn tunnel_iv_key(&self) -> &[u8] {
        self.tunnel_iv_key
    }
}

#[derive(Debug)]
pub struct ShortTunnelBuildRecord<'a> {
    tunnel_id: u32,
    next_tunnel_id: u32,
    next_router_hash: &'a [u8],
    role: HopRole,
    reserved: &'a [u8],
    encryption_type: u8,
    request_time: u32,
    request_expiration: u32,
    next_message_id: u32,
    options: Mapping,
    padding: &'a [u8],
}

impl<'a> ShortTunnelBuildRecord<'a> {
    pub fn parse_frame(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (rest, tunnel_id) = be_u32(input)?;
        let (rest, next_tunnel_id) = be_u32(rest)?;
        let (rest, next_router_hash) = take(ROUTER_HASH_LEN)(rest)?;
        let (rest, flags) = be_u8(rest)?;
        let (rest, reserved) = take(2usize)(rest)?;
        let (rest, encryption_type) = be_u8(rest)?;
        let (rest, request_time) = be_u32(rest)?;
        let (rest, request_expiration) = be_u32(rest)?;
        let (rest, next_message_id) = be_u32(rest)?;
        let (rest, options) = Mapping::parse_frame(rest)?;
        let (rest, padding) = take(input.len() - rest.len())(rest)?; // TODO: correct?
        let role = HopRole::from_u8(flags).ok_or(Err::Error(make_error(input, ErrorKind::Fail)))?;

        Ok((
            rest,
            ShortTunnelBuildRecord {
                tunnel_id,
                next_tunnel_id,
                next_router_hash,
                encryption_type,
                role,
                reserved,
                request_time,
                request_expiration,
                next_message_id,
                options,
                padding,
            },
        ))
    }

    pub fn parse(input: &'a [u8]) -> Option<Self> {
        Some(Self::parse_frame(input).ok()?.1)
    }

    /// Get tunnel ID.
    pub fn tunnel_id(&self) -> u32 {
        self.tunnel_id
    }

    /// Get next tunnel ID.
    pub fn next_tunnel_id(&self) -> u32 {
        self.next_tunnel_id
    }

    /// Get next router hash.
    pub fn next_router_hash(&self) -> &'a [u8] {
        self.next_router_hash
    }

    /// Get hop role.
    pub fn role(&self) -> HopRole {
        self.role
    }

    /// Get request time, in minutes since Unix epoch.
    pub fn request_time(&self) -> u32 {
        self.request_time
    }

    /// Get tunnel expiration, in seconds since creation.
    pub fn request_expiration(&self) -> u32 {
        self.request_expiration
    }

    /// Get next message ID.
    pub fn next_message_id(&self) -> u32 {
        self.next_message_id
    }
}

#[derive(Debug)]
pub struct OutboundTunnelBuildReply<'a> {
    /// Data.
    data: &'a [u8],
}

#[derive(Debug)]
pub enum GarlicClove<'a> {
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

#[derive(Debug)]
pub enum I2NpMessage<'a> {
    Tunnel(TunnelMessage<'a>),
    NetDb(DatabaseMessage<'a>),
}

impl<'a> I2NpMessage<'a> {
    /// Parse [`GarlicGlove`].
    fn parse_galic_clove(input: &'a [u8]) -> IResult<&'a [u8], GarlicClove<'a>> {
        let (rest, flag) = be_u8(input)?;

        assert!(flag >> 7 & 1 == 0, "encrypted garlic");
        assert!(flag >> 4 & 1 == 0, "delay");

        match (flag >> 5) & 0x3 {
            0x00 => Ok((rest, GarlicClove::Local)),
            0x01 => {
                let (rest, hash) = take(32usize)(rest)?;

                Ok((rest, GarlicClove::Destination { hash }))
            }
            0x02 => {
                let (rest, hash) = take(32usize)(rest)?;

                Ok((rest, GarlicClove::Router { hash }))
            }
            0x03 => {
                let (rest, hash) = take(32usize)(rest)?;
                let (rest, tunnel_id) = be_u32(rest)?;

                Ok((rest, GarlicClove::Tunnel { hash, tunnel_id }))
            }
            _ => panic!("invalid garlic type"),
        }
    }

    /// Parse [`I2NpMessageKind::Garlic`].
    fn parse_garlic(input: &'a [u8]) -> IResult<&'a [u8], I2NpMessage<'a>> {
        let (rest, size) = be_u32(input)?;

        // TODO: decrypt
        let (mut rest, num_cloves) = be_u8(rest)?;

        let (rest, cloves) = (0..num_cloves)
            .try_fold(
                (rest, Vec::<GarlicClove<'a>>::new()),
                |(rest, mut cloves), _| {
                    let (rest, clove) = Self::parse_galic_clove(rest).ok()?;
                    cloves.push(clove);

                    Some((rest, cloves))
                },
            )
            .ok_or_else(|| Err::Error(make_error(input, ErrorKind::Fail)))?;

        let (rest, _certificate) = take(GARLIC_CERTIFICATE_LEN)(rest)?;
        let (rest, message_id) = be_u32(rest)?;
        let (rest, expiration) = Date::parse_frame(rest)?;

        tracing::error!("size = {size}, input size = {}", input.len());

        todo!();
    }

    fn parse_variable_tunnel_build_request(input: &'a [u8]) -> IResult<&'a [u8], I2NpMessage<'a>> {
        let (rest, num_records) = be_u8(input)?;

        let (rest, records) = (0..num_records)
            .try_fold(
                (rest, Vec::<EncryptedTunnelBuildRequestRecord<'a>>::new()),
                |(rest, mut records), _| {
                    let (rest, truncated_hash) =
                        take::<usize, &[u8], ()>(TRUNCATED_IDENITTY_LEN)(rest).ok()?;
                    let (rest, ephemeral_key) =
                        take::<usize, &[u8], ()>(X25519_KEY_LEN)(rest).ok()?;
                    let (rest, ciphertext) = take::<usize, &[u8], ()>(
                        ENCRYPTED_BUILD_REQUEST_LEN + POLY1305_TAG_LEN,
                    )(rest)
                    .ok()?;

                    records.push(EncryptedTunnelBuildRequestRecord {
                        truncated_hash,
                        ephemeral_key,
                        ciphertext,
                    });

                    Some((rest, records))
                },
            )
            .ok_or_else(|| Err::Error(make_error(input, ErrorKind::Fail)))?;

        Ok((
            rest,
            I2NpMessage::Tunnel(TunnelMessage::VariableBuildRequest { records }),
        ))
    }

    fn parse_inner(
        message_type: MessageType,
        message_id: u32,
        short_expiration: u32,
        input: &'a [u8],
    ) -> IResult<&'a [u8], I2NpMessage<'a>> {
        match message_type {
            MessageType::Garlic => Self::parse_garlic(input),
            MessageType::VariableTunnelBuild => Self::parse_variable_tunnel_build_request(input),
            message_type => todo!("unsupported message type: {message_type:?}"),
        }
    }

    pub fn parse(message_type: MessageType, buffer: &'a [u8]) -> Option<I2NpMessage<'a>> {
        let parsed = Self::parse_inner(message_type, 1337u32, 1338u32, buffer).ok()?.1;

        Some(parsed)
    }
}

// Tunneling-related message.
#[derive(Debug)]
pub enum TunnelMessage<'a> {
    /// Data message.
    ///
    /// Used by garlic messages/cloves.
    Data {
        /// Data.
        data: &'a [u8],
    },

    /// Garlic
    Garlic {
        /// Garlic cloves.
        cloves: Vec<GarlicClove<'a>>,
    },

    /// Tunnel data.
    TunnelData {
        /// Tunnel ID.
        tunnel_id: u32,

        /// Data.
        ///
        /// Length is fixed 1024 bytes.
        data: &'a [u8],
    },

    /// Tunnel gateway.
    Gateway {
        /// Tunnel ID.
        tunnel_id: u32,

        /// Data.
        data: &'a [u8],
    },

    /// Tunnel build message, fixed to 8 records.
    BuildRequest {
        /// Build records.
        records: [TunnelBuildRecord<'a>; 8],
    },

    /// Variable tunnel build message.
    VariableBuildRequest {
        /// Build records.
        records: Vec<EncryptedTunnelBuildRequestRecord<'a>>,
    },

    /// Tunnel build reply.
    BuildReply {
        /// Reply byte (accept/reject).
        reply: u8,
    },

    /// Short tunnel build request.
    ShortBuildRequest {
        /// Records.
        records: Vec<ShortTunnelBuildRecord<'a>>,
    },

    /// Outbound tunnel build reply.
    OutboundBuildReply {
        /// Records.
        records: Vec<OutboundTunnelBuildReply<'a>>,
    },
}

/// NetDB-related message.
#[derive(Debug)]
pub enum DatabaseMessage<'a> {
    /// Database store request.
    Store {
        /// SHA256 hash of the key.
        key: &'a [u8],

        /// Store type.
        store_type: u8,

        /// Reply token.
        token: Option<u32>,

        /// Reply tunnel ID.
        tunnel_id: Option<u32>,

        /// SHA256 of the gateway `RouterInfo`
        gateway: Option<&'a [u8]>,

        /// Data.
        data: &'a [u8],
    },

    /// Database search request.
    Request {
        /// SHA256 hash of the key to look up.
        key: &'a [u8],

        /// SHA256 hash of the `RouterInfo` who is asking
        /// or the gateway where to send the reply.
        origin: &'a [u8],

        /// Flag
        flag: u8,

        /// Reply tunnel ID.
        tunnel_id: u32,

        /// Count of peer hashes to ignore
        exclude_size: u16,

        /// Peers to ignore.
        exclude: Vec<&'a [u8]>,

        /// Reply key.
        reply_key: &'a [u8],

        /// Size of reply tags.
        tags_size: u8,

        /// Reply tags.
        tags: &'a [u8],
    },

    /// Database search reply
    Reply {
        /// SHA256 hash of the key that was looked up.
        key: &'a [u8],

        /// Peer hashes.
        peers: Vec<&'a [u8]>,

        // SHA256 of the `RouterInfo` this reply was sent from.
        from: &'a [u8],
    },
}

/// Raw, unparsed I2NP message.
///
/// These messages are dispatched by the enabled transports
/// to appropriate subsystems, based on `message_type`.
#[derive(Clone)]
pub struct RawI2npMessage {
    /// Message type.
    pub message_type: MessageType,

    /// Message ID.
    pub message_id: u32,

    /// Expiration.
    pub expiration: u32,

    /// Raw, unparsed payload.
    pub payload: Vec<u8>,
}

// TODO: remove & remove thingbuf zzz
impl Default for RawI2npMessage {
    fn default() -> Self {
        Self {
            message_type: MessageType::DatabaseStore,
            message_id: 0u32,
            expiration: 0u32,
            payload: Vec::new(),
        }
    }
}

impl fmt::Debug for RawI2npMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawI2npMessage")
            .field("message_type", &self.message_type)
            .field("message_id", &self.message_id)
            .field("expiration", &self.expiration)
            .finish_non_exhaustive()
    }
}

impl RawI2npMessage {
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], RawI2npMessage> {
        let (rest, size) = be_u16(input)?;
        let (rest, message_type) = be_u8(rest)?;
        let (rest, message_id) = be_u32(rest)?;
        let (rest, expiration) = be_u32(rest)?;
        let (rest, payload) = take(size as usize - (1 + 2 * 4))(rest)?;
        let message_type = MessageType::from_u8(message_type)
            .ok_or_else(|| Err::Error(make_error(input, ErrorKind::Fail)))?;

        Ok((
            rest,
            RawI2npMessage {
                message_type,
                message_id,
                expiration,
                payload: payload.to_vec(),
            },
        ))
    }

    pub fn parse(input: &[u8]) -> Option<RawI2npMessage> {
        Some(Self::parse_frame(input).ok()?.1)
    }

    pub fn destination(&self) -> SubsystemKind {
        match self.message_type {
            MessageType::DatabaseStore
            | MessageType::DatabaseLookup
            | MessageType::DatabaseSearchReply => SubsystemKind::NetDb,
            _ => SubsystemKind::Tunnel,
        }
    }

    // TODO: use `zerocopy`
    pub fn serialize(self) -> Vec<u8> {
        let mut out = vec![0u8; self.payload.len() + 2 + 1 + 2 * 4];

        out[..2].copy_from_slice(&((self.payload.len() + 1 + 2 * 4) as u16).to_be_bytes());
        out[2] = self.message_type.serialize();
        out[3..7].copy_from_slice(&self.message_id.to_be_bytes());
        out[7..11].copy_from_slice(&self.expiration.to_be_bytes());
        out[11..].copy_from_slice(&self.payload);

        out
    }
}

pub struct EncryptedTunnelData<'a> {
    tunnel_id: u32,
    iv: &'a [u8],
    ciphertext: &'a [u8],
}

impl<'a> EncryptedTunnelData<'a> {
    pub fn parse_frame(input: &'a [u8]) -> IResult<&'a [u8], EncryptedTunnelData<'a>> {
        let (rest, tunnel_id) = be_u32(input)?;
        let (rest, iv) = take(AES256_IV_LEN)(rest)?;
        let (rest, ciphertext) = take(rest.len())(rest)?;

        Ok((
            rest,
            EncryptedTunnelData {
                tunnel_id,
                iv,
                ciphertext,
            },
        ))
    }

    pub fn parse(input: &'a [u8]) -> Option<Self> {
        Some(Self::parse_frame(input).ok()?.1)
    }

    pub fn tunnel_id(&self) -> u32 {
        self.tunnel_id
    }

    pub fn iv(&self) -> &[u8] {
        self.iv
    }

    pub fn ciphertext(&self) -> &[u8] {
        self.ciphertext
    }
}

#[derive(Debug)]
pub enum DeliveryInstruction<'a> {
    /// Fragment meant for the local node
    Local,

    /// Fragment meant for a router.
    Router {
        /// Hash of the router.
        hash: &'a [u8],
    },

    /// Fragment meant for a tunnel.
    Tunnel {
        /// Hash of the tunnel.
        hash: &'a [u8],

        /// Tunnel ID.
        tunnel_id: u32,
    },
}

#[derive(Debug)]
pub enum MessageKind<'a> {
    Unfragmented {
        delivery_instructions: DeliveryInstruction<'a>,
    },
    FirstFragment {
        message_id: u32,
        delivery_instructions: DeliveryInstruction<'a>,
    },
    MiddleFragment {
        message_id: u32,
        sequence_number: usize,
    },
    LastFragment {
        message_id: u32,
        sequence_number: usize,
    },
}

pub struct TunnelDataMessage<'a> {
    pub message_kind: MessageKind<'a>,
    pub message: &'a [u8],
}

impl<'a> fmt::Debug for TunnelDataMessage<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelDataMessage")
            .field("message_kind", &self.message_kind)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct TunnelData<'a> {
    pub messages: Vec<TunnelDataMessage<'a>>,
}

impl<'a> TunnelData<'a> {
    /// Parse first fragment delivery instructions.
    ///
    /// https://geti2p.net/spec/tunnel-message#first-fragment-delivery-instructions
    fn parse_frame(mut input: &'a [u8]) -> IResult<&'a [u8], TunnelDataMessage<'a>> {
        let (rest, flag) = be_u8(input)?;

        match flag >> 7 {
            0x01 => {
                let sequence_number = ((flag >> 1) & 0x3f) as usize;
                let (rest, message_id) = be_u32(rest)?;
                let (rest, size) = be_u16(rest)?;
                let (rest, message) = take(size as usize)(rest)?;

                let (rest, message_kind) = match flag & 0x01 {
                    0x00 => (
                        rest,
                        MessageKind::MiddleFragment {
                            message_id,
                            sequence_number,
                        },
                    ),
                    0x01 => (
                        rest,
                        MessageKind::LastFragment {
                            message_id,
                            sequence_number,
                        },
                    ),
                    _ => return Err(Err::Error(make_error(input, ErrorKind::Fail))),
                };

                return Ok((
                    rest,
                    TunnelDataMessage {
                        message_kind,
                        message,
                    },
                ));
            }
            0x00 => {}
            _ => return Err(Err::Error(make_error(input, ErrorKind::Fail))),
        }

        let (rest, delivery_instructions) = match (flag >> 5) & 0x03 {
            0x00 => (rest, DeliveryInstruction::Local),
            0x01 => {
                let (rest, tunnel_id) = be_u32(rest)?;
                let (rest, hash) = take(ROUTER_HASH_LEN)(rest)?;

                (rest, DeliveryInstruction::Tunnel { hash, tunnel_id })
            }
            0x02 => {
                let (rest, hash) = take(ROUTER_HASH_LEN)(rest)?;

                (rest, DeliveryInstruction::Router { hash })
            }
            _ => return Err(Err::Error(make_error(input, ErrorKind::Fail))),
        };

        let (rest, message_kind) = match (flag >> 3) & 0x01 {
            0x00 => (
                rest,
                MessageKind::Unfragmented {
                    delivery_instructions,
                },
            ),
            0x01 => {
                let (rest, message_id) = be_u32(rest)?;

                (
                    rest,
                    MessageKind::FirstFragment {
                        delivery_instructions,
                        message_id,
                    },
                )
            }
            _ => return Err(Err::Error(make_error(input, ErrorKind::Fail))),
        };

        let (rest, size) = be_u16(rest)?;
        let (rest, message) = take(size as usize)(rest)?;

        Ok((
            rest,
            TunnelDataMessage {
                message_kind,
                message,
            },
        ))
    }

    pub fn parse(mut input: &'a [u8]) -> Option<Self> {
        let mut messages = Vec::<TunnelDataMessage>::new();

        while !input.is_empty() {
            let (rest, message) = Self::parse_frame(input).ok()?;
            messages.push(message);
            input = rest;
        }

        Some(Self { messages })
    }
}
