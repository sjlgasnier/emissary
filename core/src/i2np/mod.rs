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
    crypto::{base64_encode, sha256::Sha256},
    primitives::{Date, Mapping, MessageId, TunnelId},
    runtime::Runtime,
    subsystem::SubsystemKind,
};

use bytes::{BufMut, BytesMut};
use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u32, be_u64, be_u8},
    sequence::tuple,
    Err, IResult,
};
use rand_core::RngCore;

use alloc::{vec, vec::Vec};
use core::fmt;

pub mod database;
pub mod delivery_status;
pub mod garlic;
pub mod tunnel;

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

/// I2NP short header size.
const I2NP_SHORT_HEADER_LEN: usize = 9usize;

/// I2NP standard header size.
const I2NP_STANDARD_HEADER_LEN: usize = 16usize;

/// Message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Database store.
    DatabaseStore,

    /// Database lookup.
    DatabaseLookup,

    /// Database search reply.
    DatabaseSearchReply,

    /// Delivery status.
    DeliveryStatus,

    /// Garlic message.
    Garlic,

    /// Tunnel data.
    TunnelData,

    /// Tunnel gateway.
    TunnelGateway,

    /// Generic data.
    Data,

    /// Tunnel build.
    TunnelBuild,

    /// Tunnel build reply.
    TunnelBuildReply,

    /// Variable tunnel build.
    VariableTunnelBuild,

    /// Variable tunnel build reply.
    VariableTunnelBuildReply,

    /// Short tunnel build.
    ShortTunnelBuild,

    /// Outbound tunnel build reply.
    OutboundTunnelBuildReply,
}

impl MessageType {
    /// Serialize [`MessageType`].
    fn as_u8(&self) -> u8 {
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

    /// Try to convert `msg_type` into `MessageType`.
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

/// Hop role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopRole {
    /// Router acts as the inbound endpoint.
    InboundGateway,

    /// Router acts as the outbound endpoint.
    OutboundEndpoint,

    /// Router acts as an intermediary participant.
    Participant,
}

impl HopRole {
    /// Serialize `HopRole`.
    fn as_u8(self) -> u8 {
        match self {
            HopRole::InboundGateway => 0x80,
            HopRole::OutboundEndpoint => 0x40,
            HopRole::Participant => 0x00,
        }
    }

    /// Try to convert `role` into `HopRole`.
    fn from_u8(role: u8) -> Option<HopRole> {
        match role {
            0x80 => Some(HopRole::InboundGateway),
            0x40 => Some(HopRole::OutboundEndpoint),
            0x00 => Some(HopRole::Participant),
            role => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?role,
                    "unrecognized flag"
                );
                None
            }
        }
    }
}

/// I2NP message builder.
#[derive(Debug)]
pub enum MessageBuilder<'a> {
    /// Standard I2NP header (tunnel messages).
    Standard {
        /// Message type.
        message_type: Option<MessageType>,

        /// Message ID.
        message_id: Option<u32>,

        /// Expiration.
        expiration: Option<u64>,

        /// Raw, unparsed payload.
        payload: Option<&'a [u8]>,
    },

    /// Short I2NP header (NTCP2/SSU2).
    Short {
        /// Message type.
        message_type: Option<MessageType>,

        /// Message ID.
        message_id: Option<u32>,

        /// Expiration.
        expiration: Option<u64>,

        /// Raw, unparsed payload.
        payload: Option<&'a [u8]>,
    },
}

impl<'a> MessageBuilder<'a> {
    /// Create I2NP message with short header.
    pub fn short() -> Self {
        Self::Short {
            message_type: None,
            message_id: None,
            expiration: None,
            payload: None,
        }
    }

    /// Create I2NP message with standard header.
    pub fn standard() -> Self {
        Self::Standard {
            message_type: None,
            message_id: None,
            expiration: None,
            payload: None,
        }
    }

    /// Add expiration.
    pub fn with_expiration<T: Into<u64>>(mut self, message_expiration: T) -> Self {
        match self {
            Self::Standard {
                expiration: ref mut exp,
                ..
            }
            | Self::Short {
                expiration: ref mut exp,
                ..
            } => *exp = Some(message_expiration.into()),
        }

        self
    }

    /// Add mesage type.
    pub fn with_message_type(mut self, message_type: MessageType) -> Self {
        match self {
            Self::Standard {
                message_type: ref mut msg_type,
                ..
            }
            | Self::Short {
                message_type: ref mut msg_type,
                ..
            } => *msg_type = Some(message_type),
        }

        self
    }

    /// Add message ID.
    pub fn with_message_id<T: Into<u32>>(mut self, message_id: T) -> Self {
        match self {
            Self::Standard {
                message_id: ref mut msg_id,
                ..
            }
            | Self::Short {
                message_id: ref mut msg_id,
                ..
            } => *msg_id = Some(message_id.into()),
        }

        self
    }

    /// Add payload
    pub fn with_payload(mut self, payload: &'a [u8]) -> Self {
        match self {
            Self::Standard {
                payload: ref mut msg_payload,
                ..
            }
            | Self::Short {
                payload: ref mut msg_payload,
                ..
            } => *msg_payload = Some(payload),
        }

        self
    }

    /// Serialize I2NP message.
    pub fn build(mut self) -> Vec<u8> {
        match self {
            Self::Standard {
                message_type,
                message_id,
                mut expiration,
                mut payload,
            } => {
                let payload = payload.take().expect("to exist");
                let mut out = BytesMut::with_capacity(payload.len() + I2NP_STANDARD_HEADER_LEN);

                out.put_u8(message_type.expect("to exist").as_u8());
                out.put_u32(message_id.expect("to exist"));
                out.put_u64(expiration.expect("to exist"));
                out.put_u16((payload.len() as u16));
                out.put_u8(0x00); // checksum
                out.put_slice(&payload);

                out.freeze().to_vec()
            }
            Self::Short {
                message_type,
                message_id,
                expiration,
                mut payload,
            } => {
                let payload = payload.take().expect("to exist");

                // two extra bytes for the length field
                let mut out = BytesMut::with_capacity(payload.len() + I2NP_SHORT_HEADER_LEN + 2);

                out.put_u16((payload.len() + I2NP_SHORT_HEADER_LEN) as u16);
                out.put_u8(message_type.expect("to exist").as_u8());
                out.put_u32(message_id.expect("to exist"));
                out.put_u32(expiration.expect("to exist") as u32);
                out.put_slice(&payload);

                out.freeze().to_vec()
            }
        }
    }
}

/// Raw, unparsed I2NP message.
///
/// These messages are dispatched by the enabled transports
/// to appropriate subsystems, based on `message_type`.
#[derive(Clone)]
pub struct Message {
    /// Message type.
    pub message_type: MessageType,

    /// Message ID.
    pub message_id: u32,

    /// Expiration.
    pub expiration: u64,

    /// Raw, unparsed payload.
    pub payload: Vec<u8>,
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("message_type", &self.message_type)
            .field("message_id", &self.message_id)
            .field("expiration", &self.expiration)
            .finish_non_exhaustive()
    }
}

impl Message {
    /// Attempt to parse I2NP message with short header from `input`.
    ///
    /// Returns the parsed message and rest of `input` on success.
    pub fn parse_frame_short(input: &[u8]) -> IResult<&[u8], Message> {
        let (rest, size) = be_u16(input)?;
        let (rest, message_type) = be_u8(rest)?;
        let (rest, message_id) = be_u32(rest)?;
        let (rest, expiration) = be_u32(rest)?;

        if size as usize <= I2NP_SHORT_HEADER_LEN {
            return Err(Err::Error(make_error(input, ErrorKind::Fail)));
        }

        let (rest, payload) = take(size as usize - I2NP_SHORT_HEADER_LEN)(rest)?;
        let message_type = MessageType::from_u8(message_type)
            .ok_or_else(|| Err::Error(make_error(input, ErrorKind::Fail)))?;

        Ok((
            rest,
            Message {
                message_type,
                message_id,
                expiration: expiration as u64,
                payload: payload.to_vec(),
            },
        ))
    }

    /// Attempt to parse I2NP message with standard header from `input`.
    ///
    /// Returns the parsed message and rest of `input` on success.
    pub fn parse_frame_standard(input: &[u8]) -> IResult<&[u8], Message> {
        let (rest, message_type) = be_u8(input)?;
        let (rest, message_id) = be_u32(rest)?;
        let (rest, expiration) = be_u64(rest)?;
        let (rest, size) = be_u16(rest)?;
        let (rest, _checksum) = be_u8(rest)?;
        let (rest, payload) = take(size as usize)(rest)?;

        if payload.is_empty() {
            return Err(Err::Error(make_error(input, ErrorKind::Fail)));
        }

        let message_type = MessageType::from_u8(message_type)
            .ok_or_else(|| Err::Error(make_error(input, ErrorKind::Fail)))?;

        Ok((
            rest,
            Message {
                message_type,
                message_id,
                expiration,
                payload: payload.to_vec(),
            },
        ))
    }

    /// Attempt to parse I2NP message with short header from `input`.
    pub fn parse_short(input: &[u8]) -> Option<Message> {
        Some(Self::parse_frame_short(input).ok()?.1)
    }

    /// Attempt to parse I2NP message with standard header from `input`.
    pub fn parse_standard(input: &[u8]) -> Option<Message> {
        Some(Self::parse_frame_standard(input).ok()?.1)
    }

    /// Get destination subsystem of the message based on its message type.
    pub fn destination(&self) -> SubsystemKind {
        match self.message_type {
            MessageType::DatabaseStore
            | MessageType::DatabaseLookup
            | MessageType::DatabaseSearchReply => SubsystemKind::NetDb,
            _ => SubsystemKind::Tunnel,
        }
    }
}

// TODO: remove `pub`
// TODO: implement asref when wrapp inside another message
pub struct TunnelGatewayMessage<'a> {
    /// Tunnel ID.
    pub tunnel_id: TunnelId,

    /// Payload.
    pub payload: &'a [u8],
}

impl<'a> TunnelGatewayMessage<'a> {
    fn parse_frame(input: &'a [u8]) -> IResult<&'a [u8], TunnelGatewayMessage<'a>> {
        let (rest, tunnel_id) = be_u32(input)?;
        let (rest, size) = be_u16(rest)?;
        let (rest, payload) = take(size as usize)(rest)?;

        Ok((
            rest,
            TunnelGatewayMessage {
                tunnel_id: TunnelId::from(tunnel_id),
                payload,
            },
        ))
    }

    pub fn parse(input: &'a [u8]) -> Option<TunnelGatewayMessage<'a>> {
        Some(Self::parse_frame(input).ok()?.1)
    }

    pub fn serialize(mut self) -> Vec<u8> {
        let mut out = vec![0u8; self.payload.len() + 2 + 4];

        out[..4].copy_from_slice(&self.tunnel_id.to_be_bytes());
        out[4..6].copy_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out[6..].copy_from_slice(self.payload);

        out
    }

    /// Get reference to `TunnelId`.
    pub fn tunnel_id(&self) -> &TunnelId {
        &self.tunnel_id
    }

    /// Get reference to `TunnelGateway` payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

#[derive(Debug)]
pub enum GarlicMessageType {
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

pub enum GarlicMessageBlock<'a> {
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
                .debug_struct("GarlicMessageBlock::GarlicClove")
                .field("message_type", &message_type)
                .field("message_id", &message_id)
                .field("expiration", &expiration)
                .field("delivery_instructions", &delivery_instructions)
                .finish_non_exhaustive(),
            Self::Padding { .. } =>
                f.debug_struct("DeliveryInstructions::Padding").finish_non_exhaustive(),
            _ => f.debug_struct("Unknown").finish_non_exhaustive(),
        }
    }
}

#[derive(Debug)]
pub struct GarlicMessage<'a> {
    pub blocks: Vec<GarlicMessageBlock<'a>>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_short_as_standard() {
        let message = MessageBuilder::short()
            .with_message_type(MessageType::DeliveryStatus)
            .with_message_id(1337u32)
            .with_expiration(0xdeadbeefu64)
            .with_payload(&vec![1, 2, 3, 4])
            .build();

        assert!(Message::parse_standard(&message).is_none());
    }

    #[test]
    fn parse_standard_as_short() {
        let message = MessageBuilder::standard()
            .with_message_type(MessageType::DeliveryStatus)
            .with_message_id(1337u32)
            .with_expiration(0xdeadbeefu64)
            .with_payload(&vec![1, 2, 3, 4])
            .build();

        assert!(Message::parse_short(&message).is_none());
    }

    #[test]
    fn invalid_message_type() {
        let mut out = BytesMut::with_capacity(4 + I2NP_SHORT_HEADER_LEN + 2);

        out.put_u16((4 + I2NP_SHORT_HEADER_LEN) as u16);
        out.put_u8(252);
        out.put_u32(13371338u32);
        out.put_u32(0xdeadbeefu32);
        out.put_slice(&vec![1, 2, 3, 4]);
        let serialized = out.freeze().to_vec();

        assert!(Message::parse_short(&serialized).is_none());
    }

    #[test]
    fn incomplete_short_header() {
        assert!(Message::parse_short(&vec![1, 2, 3, 4]).is_none());
    }

    #[test]
    fn incomplete_standard_header() {
        assert!(Message::parse_standard(&vec![1, 2, 3, 4]).is_none());
    }

    #[test]
    fn invalid_size_short() {
        let mut out = BytesMut::with_capacity(4 + I2NP_SHORT_HEADER_LEN + 2);

        out.put_u16(4u16); // invalid size
        out.put_u8(MessageType::DeliveryStatus.as_u8());
        out.put_u32(13371338u32);
        out.put_u32(0xdeadbeefu32);
        out.put_slice(&vec![1, 2, 3, 4]);
        let serialized = out.freeze().to_vec();

        assert!(Message::parse_short(&serialized).is_none());
    }

    #[test]
    fn empty_payload_short() {
        let mut out = BytesMut::with_capacity(I2NP_SHORT_HEADER_LEN + 2);

        out.put_u16(4u16); // invalid size
        out.put_u8(MessageType::DeliveryStatus.as_u8());
        out.put_u32(13371338u32);
        out.put_u32(0xdeadbeefu32);
        let serialized = out.freeze().to_vec();

        assert!(Message::parse_short(&serialized).is_none());
    }

    #[test]
    fn empty_payload_standard() {
        let mut out = BytesMut::with_capacity(I2NP_SHORT_HEADER_LEN + 2);

        out.put_u16(4u16); // invalid size
        out.put_u8(MessageType::DeliveryStatus.as_u8());
        out.put_u32(13371338u32);
        out.put_u32(0xdeadbeefu32);
        let serialized = out.freeze().to_vec();

        assert!(Message::parse_short(&serialized).is_none());
    }
}
