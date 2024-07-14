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

use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u32, be_u8},
    sequence::tuple,
    Err, IResult,
};

use alloc::vec::Vec;
use core::fmt;

use crate::{crypto::base64_encode, primitives::Date, transports::SubsystemKind};

/// Garlic certificate length.
const GARLIC_CERTIFICATE_LEN: usize = 3usize;

// Truncated identity hash length.
const TRUNCATED_IDENITTY_LEN: usize = 16usize;

// x25519 ephemeral key length.
const X25519_KEY_LENGTH: usize = 32usize;

/// Encrypted build request length.
const ENCRYPTED_BUILD_REQUEST_LEN: usize = 464usize;

/// Poly1305 authentication tag length.
const POLY1305_TAG_LENGTH: usize = 16usize;

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
    flags: u8,

    /// Unused flags.
    reserved: [u8; 3],

    /// Request time, in minutes since Unix epoch.
    request_time: u32,

    /// Tunnel expiration, in seconds since creation.
    request_expiration: u32,

    // Next message ID.
    next_message_id: u32,

    /// TODO:
    rest: &'a [u8],
}

#[derive(Debug)]
pub struct ShortTunnelBuildRecord<'a> {
    tunnel_id: u32,
    next_tunnel_id: u32,
    next_router_hash: &'a [u8],
    flags: u8,
    reserved: &'a [u8],
    encryption_type: u8,
    request_time: u32,
    request_expiration: u32,
    next_message_id: u32,
    // TODO: rest options
    // bytes    56-x: tunnel build options (Mapping)
    // bytes     x-x: other data as implied by flags or options
    // bytes   x-153: random padding (see below)
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

        /// Tunnel ID, if `delivery_type` is [`DeliveryType::Router`].
        tunnel_id: u32,
    },
}

#[derive(Debug)]
pub enum I2NpMessageKind<'a> {
    Tunnel(TunnelMessage<'a>),
    NetDb(DatabaseMessage<'a>),
    Dummy,
}

#[derive(Debug)]
pub struct I2npMessage<'a> {
    msg_id: u32,
    expiration: u32,
    kind: I2NpMessageKind<'a>,
}

impl<'a> I2npMessage<'a> {
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
    fn parse_garlic(input: &'a [u8]) -> IResult<&'a [u8], I2npMessage<'a>> {
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

    fn parse_variable_tunnel_build_request(input: &'a [u8]) -> IResult<&'a [u8], I2npMessage<'a>> {
        let (mut rest, num_records) = be_u8(input)?;

        for _ in 0..num_records {
            let (_rest, hash) = take(TRUNCATED_IDENITTY_LEN)(rest)?;
            let (_rest, ephemeral_key) = take(X25519_KEY_LENGTH)(_rest)?;
            let (_rest, payload) = take(ENCRYPTED_BUILD_REQUEST_LEN)(_rest)?;
            let (_rest, mac_tag) = take(POLY1305_TAG_LENGTH)(_rest)?;
            rest = _rest;

            tracing::error!("request contains {num_records} many records");
            tracing::error!("truncated hash = {:?}", base64_encode(hash));
        }

        todo!();
    }

    fn parse_inner(
        message_type: MessageType,
        message_id: u32,
        short_expiration: u32,
        input: &'a [u8],
    ) -> IResult<&'a [u8], I2npMessage<'a>> {
        match message_type {
            MessageType::Garlic => Self::parse_garlic(input),
            MessageType::VariableTunnelBuild => Self::parse_variable_tunnel_build_request(input),
            message_type => todo!("unsupported message type: {message_type:?}"),
        }
    }

    pub fn parse(message_type: MessageType, buffer: &'a [u8]) -> Option<I2npMessage<'a>> {
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
        records: Vec<TunnelBuildRecord<'a>>,
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
    message_type: MessageType,

    /// Message ID.
    message_id: u32,

    /// Expiration.
    expiration: u32,

    /// Raw, unparsed payload.
    payload: Vec<u8>,
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

    pub fn message_id(&self) -> u32 {
        self.message_id
    }

    pub fn message_type(&self) -> MessageType {
        self.message_type
    }

    pub fn destination(&self) -> SubsystemKind {
        match self.message_type {
            MessageType::DatabaseStore
            | MessageType::DatabaseLookup
            | MessageType::DatabaseSearchReply => SubsystemKind::NetDb,
            _ => SubsystemKind::Tunnel,
        }
    }
}
