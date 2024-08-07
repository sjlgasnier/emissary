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

/// Encrypted tunnel data.
pub struct EncryptedTunnelData<'a> {
    /// Tunnel ID.
    tunnel_id: TunnelId,

    /// AES-256-ECB IV.
    iv: &'a [u8],

    /// Encrypted [`TunnelData`].
    ciphertext: &'a [u8],
}

impl<'a> EncryptedTunnelData<'a> {
    /// Parse `input` into [`EncryptedTunnelData`].
    pub fn parse_frame(input: &'a [u8]) -> IResult<&'a [u8], EncryptedTunnelData<'a>> {
        let (rest, tunnel_id) = be_u32(input)?;
        let (rest, iv) = take(AES256_IV_LEN)(rest)?;
        let (rest, ciphertext) = take(rest.len())(rest)?;

        Ok((
            rest,
            EncryptedTunnelData {
                tunnel_id: TunnelId::from(tunnel_id),
                iv,
                ciphertext,
            },
        ))
    }

    /// Parse `input` into [`EncryptedTunnelData`].
    pub fn parse(input: &'a [u8]) -> Option<Self> {
        Some(Self::parse_frame(input).ok()?.1)
    }

    /// Get tunnel ID of the message.
    pub fn tunnel_id(&self) -> TunnelId {
        self.tunnel_id
    }

    /// Get reference to AES-256-ECB IV.
    pub fn iv(&self) -> &[u8] {
        self.iv
    }

    /// Get reference to ciphertext ([`TunnelData`]).
    pub fn ciphertext(&self) -> &[u8] {
        self.ciphertext
    }
}

/// I2NP message delivery instructions.
#[derive(Debug)]
pub enum DeliveryInstruction<'a> {
    /// Fragment meant for the local router.
    Local,

    /// Fragment meant for a router.
    Router {
        /// Hash of the router.
        hash: &'a [u8],
    },

    /// Fragment meant for a tunnel.
    Tunnel {
        /// Tunnel ID.
        tunnel_id: u32,

        /// Hash of the tunnel.
        hash: &'a [u8],
    },
}

impl<'a> DeliveryInstruction<'a> {
    pub fn to_owned(&self) -> OwnedDeliveryInstruction {
        match self {
            Self::Local => OwnedDeliveryInstruction::Local,
            Self::Router { hash } => OwnedDeliveryInstruction::Router {
                hash: hash.to_vec(),
            },
            Self::Tunnel { tunnel_id, hash } => OwnedDeliveryInstruction::Tunnel {
                tunnel_id: *tunnel_id,
                hash: hash.to_vec(),
            },
        }
    }
}

/// Owned I2NP message delivery instructions.
#[derive(Debug, Clone)]
pub enum OwnedDeliveryInstruction {
    /// Fragment meant for the local router.
    Local,

    /// Fragment meant for a router.
    Router {
        /// Hash of the router.
        hash: Vec<u8>,
    },

    /// Fragment meant for a tunnel.
    Tunnel {
        /// Tunnel ID.
        tunnel_id: u32,

        /// Hash of the tunnel.
        hash: Vec<u8>,
    },
}

/// I2NP message kind.
///
/// [`MessageKind::MiddleFragment`] and [`MessageKind::LastFragment`] do not have explicit
/// delivery instructions as they're delivered to the same destination as the first fragment.
#[derive(Debug)]
pub enum MessageKind<'a> {
    /// Unfragmented I2NP message.
    Unfragmented {
        /// Delivery instructions,
        delivery_instructions: DeliveryInstruction<'a>,
    },

    /// First fragment of a fragmented I2NP message.
    FirstFragment {
        /// Message ID.
        ///
        /// Rest of the fragments will use the same message ID.
        message_id: u32,

        /// Delivery instructions,
        delivery_instructions: DeliveryInstruction<'a>,
    },

    /// Middle fragment of a fragmented I2NP message.
    MiddleFragment {
        /// Message ID.
        ///
        /// Same as the first fragment's message ID.
        message_id: u32,

        /// Sequence number.
        sequence_number: usize,
    },

    /// Last fragment of a fragmented I2NP message.
    LastFragment {
        /// Message ID.
        ///
        /// Same as the first fragment's message ID.
        message_id: u32,

        /// Sequence number.
        sequence_number: usize,
    },
}

/// Parsed `TunnelData` message.
pub struct TunnelDataMessage<'a> {
    /// Message kind.
    ///
    /// Defines the fragmentation (if any) of the message and its delivery instructions.
    pub message_kind: MessageKind<'a>,

    /// I2NP message (fragment).
    pub message: &'a [u8],
}

impl<'a> fmt::Debug for TunnelDataMessage<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelDataMessage")
            .field("message_kind", &self.message_kind)
            .finish_non_exhaustive()
    }
}

/// Decrypted `TunnelData` message.
#[derive(Debug)]
pub struct TunnelData<'a> {
    /// Parsed messages.
    pub messages: Vec<TunnelDataMessage<'a>>,
}

impl<'a> TunnelData<'a> {
    /// Attempt to parse `input` into first or follow-on delivery instructions + payload.
    fn parse_frame(mut input: &'a [u8]) -> IResult<&'a [u8], TunnelDataMessage<'a>> {
        let (rest, flag) = be_u8(input)?;

        // parse follow-on fragment delivery instructions
        //
        // https://geti2p.net/spec/tunnel-message#follow-on-fragment-delivery-instructions
        match flag >> 7 {
            0x01 => {
                // format: 1nnnnnnd
                //  - msb set for a middle fragment
                //  - middle bits make up the sequence number
                //  - lsb specifies whether this is the last fragment
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

        // parse first fragment delivery instructions.
        //
        // https://geti2p.net/spec/tunnel-message#first-fragment-delivery-instructions
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

    /// Recursively parse `input` into a vector of [`TunnelDataMessage`]s
    fn parse_inner(
        input: &'a [u8],
        mut messages: Vec<TunnelDataMessage<'a>>,
    ) -> Option<(Vec<TunnelDataMessage<'a>>)> {
        let (rest, message) = Self::parse_frame(input).ok()?;
        messages.push(message);

        match rest.is_empty() {
            true => Some(messages),
            false => Self::parse_inner(rest, messages),
        }
    }

    /// Attempt to parse `input` into [`TunnelData`].
    pub fn parse(input: &'a [u8]) -> Option<Self> {
        Some(Self {
            messages: Self::parse_inner(input, Vec::new())?,
        })
    }
}

// TODO: remove
pub struct NewTunnelDataMessage<'a> {
    /// Delivery instructions.
    delivery_instructions: OwnedDeliveryInstruction,

    /// Message.
    message: &'a [u8],
}

pub struct TunnelDataBuilder<'a> {
    /// Next tunnel ID.
    next_tunnel_id: TunnelId,

    /// Messages.
    messages: Vec<NewTunnelDataMessage<'a>>,
}

impl<'a> TunnelDataBuilder<'a> {
    pub fn new(next_tunnel_id: TunnelId) -> Self {
        Self {
            next_tunnel_id,
            messages: Vec::new(),
        }
    }

    pub fn with_local_delivery(mut self, message: &'a [u8]) -> Self {
        self.messages.push(NewTunnelDataMessage {
            delivery_instructions: OwnedDeliveryInstruction::Local,
            message,
        });

        self
    }

    pub fn with_router_delivery(mut self, hash: Vec<u8>, message: &'a [u8]) -> Self {
        self.messages.push(NewTunnelDataMessage {
            delivery_instructions: OwnedDeliveryInstruction::Router { hash },
            message,
        });

        self
    }

    pub fn with_tunnel_delivery(
        mut self,
        hash: Vec<u8>,
        tunnel_id: TunnelId,
        message: &'a [u8],
    ) -> Self {
        self.messages.push(NewTunnelDataMessage {
            delivery_instructions: OwnedDeliveryInstruction::Tunnel {
                tunnel_id: tunnel_id.into(),
                hash,
            },
            message,
        });

        self
    }

    /// Serialize message fragments into a `TunnelData` message.
    //
    // TODO: return iterator of messages
    pub fn build<R: Runtime>(mut self) -> Vec<u8> {
        assert_eq!(self.messages.len(), 1);

        let mut out = BytesMut::with_capacity(1028);

        let message = self.messages.pop().unwrap();

        let delivery_instructions: Vec<u8> = match message.delivery_instructions {
            OwnedDeliveryInstruction::Local => vec![0x00],
            OwnedDeliveryInstruction::Router { hash } => {
                let mut out = BytesMut::with_capacity(33);
                out.put_u8(0x02 << 5);
                out.put_slice(&hash);

                out.freeze().to_vec()
            }
            OwnedDeliveryInstruction::Tunnel { tunnel_id, hash } => {
                let mut out = BytesMut::with_capacity(37);
                out.put_u8(0x01 << 5);
                out.put_u32(tunnel_id);
                out.put_slice(&hash);

                out.freeze().to_vec()
            }
        };

        // total message size - tunnel id - aes iv - checksum - flag - delivery instructions -
        // payload
        let padding_size =
            1028 - 4 - 16 - 4 - 1 - 2 - delivery_instructions.len() - message.message.len();
        let offset = (R::rng().next_u32() % (1028u32 - padding_size as u32)) as usize;
        let aes_iv = {
            let mut iv = [0u8; 16];
            R::rng().fill_bytes(&mut iv);

            iv
        };
        let padding = vec![3u8; padding_size];
        let checksum = Sha256::new()
            .update(&delivery_instructions)
            .update((message.message.len() as u16).to_be_bytes())
            .update(&message.message)
            .update(&aes_iv)
            .finalize();

        out.put_u32(self.next_tunnel_id.into());
        out.put_slice(&aes_iv);
        out.put_slice(&checksum[..4]);
        out.put_slice(&padding);
        out.put_u8(0x00); // zero byte (end of padding)
        out.put_slice(&delivery_instructions);
        out.put_u16(message.message.len() as u16);
        out.put_slice(message.message);

        out.freeze().to_vec()
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

    pub fn to_owned(&self) -> OwnedDeliveryInstruction {
        match self {
            Self::Local => OwnedDeliveryInstruction::Local,
            Self::Router { hash } => OwnedDeliveryInstruction::Router {
                hash: hash.to_vec(),
            },
            Self::Tunnel { tunnel_id, hash } => OwnedDeliveryInstruction::Tunnel {
                tunnel_id: *tunnel_id,
                hash: hash.to_vec(),
            },
            Self::Destination { .. } => todo!(),
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
}
