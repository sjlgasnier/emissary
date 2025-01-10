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

//! SSU2 message block implementation
//!
//! https://geti2p.net/spec/ssu2#noise-payload

use crate::{
    crypto::chachapoly::{ChaCha, ChaChaPoly},
    i2np::{Message, MessageType as I2npMessageType},
    primitives::{MessageId, RouterInfo},
    runtime::Runtime,
};

use bytes::{BufMut, BytesMut};
use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u32, be_u64, be_u8},
    Err, IResult,
};
use rand_core::RngCore;

use core::{
    fmt,
    net::{IpAddr, SocketAddr},
    ops::Deref,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::message";

/// Minimum size for [`Block::Options`].
const OPTIONS_MIN_SIZE: u16 = 12u16;

/// Minimum size for [`Block::Termination`].
const TERMINATION_MIN_SIZE: u16 = 9u16;

/// SSU2 block type.
#[derive(Debug)]
pub enum BlockType {
    DateTime,
    Options,
    RouterInfo,
    I2Np,
    FirstFragment,
    FollowOnFragment,
    Termination,
    RelayRequest,
    RelayResponse,
    RelayIntro,
    PeerTest,
    NextNonce,
    Ack,
    Address,
    RelayTagRequest,
    RelayTag,
    NewToken,
    PathChallenge,
    PathResponse,
    FirstPacketNumber,
    Congestion,
    Padding,
}

impl BlockType {
    fn as_u8(&self) -> u8 {
        match self {
            Self::DateTime => 0u8,
            Self::Options => 1u8,
            Self::RouterInfo => 2u8,
            Self::I2Np => 3u8,
            Self::FirstFragment => 4u8,
            Self::FollowOnFragment => 5u8,
            Self::Termination => 6u8,
            Self::RelayRequest => 7u8,
            Self::RelayResponse => 8u8,
            Self::RelayIntro => 9u8,
            Self::PeerTest => 10u8,
            Self::NextNonce => 11u8,
            Self::Ack => 12u8,
            Self::Address => 13u8,
            Self::RelayTagRequest => 15u8,
            Self::RelayTag => 16u8,
            Self::NewToken => 17u8,
            Self::PathChallenge => 18u8,
            Self::PathResponse => 19u8,
            Self::FirstPacketNumber => 20u8,
            Self::Congestion => 21u8,
            Self::Padding => 254u8,
        }
    }

    pub fn from_u8(block: u8) -> Option<Self> {
        match block {
            0u8 => Some(Self::DateTime),
            1u8 => Some(Self::Options),
            2u8 => Some(Self::RouterInfo),
            3u8 => Some(Self::I2Np),
            4u8 => Some(Self::FirstFragment),
            5u8 => Some(Self::FollowOnFragment),
            6u8 => Some(Self::Termination),
            7u8 => Some(Self::RelayRequest),
            8u8 => Some(Self::RelayResponse),
            9u8 => Some(Self::RelayIntro),
            10u8 => Some(Self::PeerTest),
            11u8 => Some(Self::NextNonce),
            12u8 => Some(Self::Ack),
            13u8 => Some(Self::Address),
            15u8 => Some(Self::RelayTagRequest),
            16u8 => Some(Self::RelayTag),
            17u8 => Some(Self::NewToken),
            18u8 => Some(Self::PathChallenge),
            19u8 => Some(Self::PathResponse),
            20u8 => Some(Self::FirstPacketNumber),
            21u8 => Some(Self::Congestion),
            254u8 => Some(Self::Padding),
            _ => None,
        }
    }
}

/// SSU2 message block.
pub enum Block {
    /// Date time.
    DateTime {
        /// Seconds since UNIX epoch.
        timestamp: u32,
    },

    /// Options.
    Options {
        /// Requested minimum padding for transfers.
        t_min: u8,

        /// Requested maximum padding for transfers.
        t_max: u8,

        /// Requested minimum padding for receptions.
        r_min: u8,

        /// Requested maximum padding for receptions.
        r_max: u8,

        /// Maximum dummy traffic router is willing to send.
        t_dmy: u16,

        /// Requested maximum dummy traffic.
        r_dmy: u16,

        /// Maximum intra-message delay router is willing to insert.
        t_delay: u16,

        /// Requested intra-message delay.
        r_delay: u16,
    },

    /// Router info.
    RouterInfo { router_info: RouterInfo },

    /// I2NP message.
    I2Np {
        /// Parsed I2NP message.
        message: Message,
    },

    /// First fragment.
    FirstFragment {
        /// Message type.
        message_type: I2npMessageType,

        /// Message ID.
        message_id: MessageId,

        /// Expiration, seconds since UNIX epoch.
        expiration: u32,

        /// Fragment of an I2NP message.
        fragment: Vec<u8>,
    },

    /// Follow-on fragment.
    FollowOnFragment {
        /// Last fragment.
        last: bool,

        /// Message ID.
        message_id: MessageId,

        /// Fragment number.
        fragment_num: u8,

        /// Fragment of an I2NP message.
        fragment: Vec<u8>,
    },

    /// Termination.
    Termination {
        /// Number of valid packets received.
        num_valid_pkts: u64,

        /// Reason for termination.
        reason: u8,
    },

    /// Relay request.
    RelayRequest {},

    /// Relay response.
    RelayResponse {},

    /// Relay intro.
    RelayIntro {},

    /// Peer test.
    PeerTest {},

    /// Next nonce.
    NextNonce {},

    /// Ack.
    Ack {
        /// ACK through.
        ack_through: u32,

        /// Number of ACKs below `ack_through`.
        num_acks: u8,

        /// NACK/ACK ranges.
        ///
        /// First element of the tuple is NACKs, second is ACKs.
        ranges: Vec<(u8, u8)>,
    },

    /// Address.
    Address {
        /// Socket address.
        address: SocketAddr,
    },

    /// Relay tag request.
    RelayTagRequest {},

    /// Relay tag.
    RelayTag {},

    /// New token.
    NewToken {
        /// Expiration, seconds since UNIX epoch.
        expires: u32,

        /// Token.
        token: u64,
    },

    /// Path challenge.
    PathChallenge {
        /// Challenge.
        challenge: Vec<u8>,
    },

    /// Path response.
    PathResponse {
        /// Response.
        response: Vec<u8>,
    },

    /// First packet number.
    FirstPacketNumber {
        /// First packet number.
        first_pkt_num: u32,
    },

    /// Congestion.
    Congestion {
        /// Flag.
        flag: u8,
    },

    /// Padding.
    Padding {
        /// Padding.
        padding: Vec<u8>,
    },

    /// Unsupported block.
    ///
    /// Will be removed once all block types are supported.
    Unsupported,
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::DateTime { timestamp } =>
                f.debug_struct("Block::DateTime").field("timestamp", &timestamp).finish(),
            Self::Options {
                t_min,
                t_max,
                r_min,
                r_max,
                t_dmy,
                r_dmy,
                t_delay,
                r_delay,
            } => f
                .debug_struct("Block::Options")
                .field("t_min", &t_min)
                .field("t_max", &t_max)
                .field("r_min", &r_min)
                .field("r_max", &r_max)
                .field("t_dmy", &t_dmy)
                .field("r_dmy", &r_dmy)
                .field("t_delay", &t_delay)
                .field("r_deay", &r_delay)
                .finish(),
            Self::RouterInfo { router_info } =>
                f.debug_struct("Block::RouterInfo").finish_non_exhaustive(),
            Self::I2Np { message } =>
                f.debug_struct("Block::I2NP").field("message", &message).finish(),
            Self::Termination {
                num_valid_pkts,
                reason,
            } => f
                .debug_struct("Block::Termination")
                .field("num_valid_pkts", &num_valid_pkts)
                .field("reason", &reason)
                .finish(),
            Self::Padding { padding } =>
                f.debug_struct("Block::Padding").field("padding_len", &padding.len()).finish(),
            Self::FirstFragment {
                message_type,
                message_id,
                expiration,
                fragment,
            } => f
                .debug_struct("Block::FirstFragment")
                .field("message_type", &message_type)
                .field("message_id", &message_id)
                .field("expiration", &expiration)
                .field("fragment_len", &fragment.len())
                .finish(),
            Self::FollowOnFragment {
                last,
                message_id,
                fragment_num,
                fragment,
            } => f
                .debug_struct("Block::FollowOnFragment")
                .field("last", &last)
                .field("message_id", &message_id)
                .field("fragment_num", &fragment_num)
                .field("fragment_len", &fragment.len())
                .finish(),
            Self::Termination {
                num_valid_pkts,
                reason,
            } => f
                .debug_struct("Block::Termination")
                .field("num_valid_pkts", &num_valid_pkts)
                .field("reason", &reason)
                .finish(),
            Self::Ack {
                ack_through,
                num_acks,
                ranges,
            } => f
                .debug_struct("Block::Ack")
                .field("ack_through", &ack_through)
                .field("num_acks", &num_acks)
                .field("ranges", &ranges)
                .finish(),
            Self::NewToken { expires, token } => f.debug_struct("Block::NewToken").finish(),
            Self::PathChallenge { challenge } =>
                f.debug_struct("Block::PathChallenge").field("challenge", &challenge).finish(),
            Self::PathResponse { response } =>
                f.debug_struct("Block::PathResponse").field("response", &response).finish(),
            Self::FirstPacketNumber { first_pkt_num } => f
                .debug_struct("Block::FirstPacketNumber")
                .field("first_pkt_num", &first_pkt_num)
                .finish(),
            Self::Congestion { flag } =>
                f.debug_struct("Block::Congestion").field("flag", &flag).finish(),
            _ => f.debug_struct("Unsupported").finish(),
        }
    }
}

impl Block {
    /// Attempt to parse [`Block::DateTime`] from `input`.
    fn parse_date_time(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, _size) = be_u16(input)?;
        let (rest, timestamp) = be_u32(rest)?;

        Ok((rest, Block::DateTime { timestamp }))
    }

    /// Attempt to parse [`Block::Options`] from `input`.
    fn parse_options(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, size) = be_u16(input)?;
        let (rest, t_min) = be_u8(rest)?;
        let (rest, t_max) = be_u8(rest)?;
        let (rest, r_min) = be_u8(rest)?;
        let (rest, r_max) = be_u8(rest)?;
        let (rest, t_dmy) = be_u16(rest)?;
        let (rest, r_dmy) = be_u16(rest)?;
        let (rest, t_delay) = be_u16(rest)?;
        let (rest, r_delay) = be_u16(rest)?;

        let rest = if size > OPTIONS_MIN_SIZE {
            let (rest, _) = take(size - OPTIONS_MIN_SIZE)(rest)?;
            rest
        } else {
            rest
        };

        Ok((
            rest,
            Block::Options {
                t_min,
                t_max,
                r_min,
                r_max,
                r_dmy,
                t_dmy,
                t_delay,
                r_delay,
            },
        ))
    }

    /// Attempt to parse [`Block::RouterInfo`] from `input`.
    fn parse_router_info(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, size) = be_u16(input)?;
        if size == 0 {
            tracing::warn!(
                target: LOG_TARGET,
                "received empty `RouterInfo` message",
            );
            return Err(Err::Error(make_error(input, ErrorKind::Fail)));
        }
        let (rest, flag) = be_u8(rest)?;
        let (rest, _frag) = be_u8(rest)?;
        let (rest, router_info) = take(size - 1)(rest)?;

        if flag & 1 == 1 {
            tracing::warn!(
                target: LOG_TARGET,
                "ignoring flood request for received router info",
            );
        }
        // TODO: implement
        if (flag >> 1) & 1 == 1 {
            tracing::warn!(
                target: LOG_TARGET,
                "ignoring gzip-compressed router info",
            );
            return Err(Err::Error(make_error(input, ErrorKind::Fail)));
        }

        let router_info = RouterInfo::parse(&router_info).ok_or_else(|| {
            tracing::warn!(
                target: LOG_TARGET,
                "malformed router info",
            );
            Err::Error(make_error(input, ErrorKind::Fail))
        })?;

        Ok((rest, Block::RouterInfo { router_info }))
    }

    /// Attempt to parse [`Block::I2Np`] from `input`.
    fn parse_i2np(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, message) = Message::parse_frame_short(input)?;

        Ok((rest, Block::I2Np { message }))
    }

    /// Attempt to parse [`Block::Termination`] from `input`.
    fn parse_termination(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, size) = be_u16(input)?;
        let (rest, num_valid_pkts) = be_u64(rest)?;
        let (rest, reason) = be_u8(rest)?;

        let rest = if size > TERMINATION_MIN_SIZE {
            let (rest, _) = take(size - TERMINATION_MIN_SIZE)(rest)?;
            rest
        } else {
            rest
        };

        Ok((
            rest,
            Block::Termination {
                num_valid_pkts,
                reason,
            },
        ))
    }

    /// Parse [`MessageBlock::Padding`].
    fn parse_padding(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, size) = be_u16(input)?;
        let (rest, padding) = take(size)(rest)?;

        Ok((
            rest,
            Block::Padding {
                padding: padding.to_vec(),
            },
        ))
    }

    /// Parse [`MessageBlock::FirstFragment`].
    fn parse_first_fragment(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, size) = be_u16(input)?;
        let (rest, message_type) = be_u8(rest)?;
        let (rest, message_id) = be_u32(rest)?;
        let (rest, expiration) = be_u32(rest)?;
        let fragment_len = size.saturating_sub(9) as usize; // type + id + size + expiration
        let message_type = I2npMessageType::from_u8(message_type).ok_or_else(|| {
            tracing::warn!(
                target: LOG_TARGET,
                ?message_type,
                "invalid message type for first fragment",
            );
            Err::Error(make_error(input, ErrorKind::Fail))
        })?;

        if fragment_len == 0 {
            tracing::warn!(
                target: LOG_TARGET,
                "first fragment is empty",
            );
            return Err(Err::Error(make_error(input, ErrorKind::Fail)));
        }

        if rest.len() < fragment_len {
            tracing::warn!(
                target: LOG_TARGET,
                "first fragment message is too short",
            );
            return Err(Err::Error(make_error(input, ErrorKind::Fail)));
        }
        let (rest, fragment) = take(fragment_len)(rest)?;

        Ok((
            rest,
            Block::FirstFragment {
                message_type,
                message_id: MessageId::from(message_id),
                expiration,
                fragment: fragment.to_vec(),
            },
        ))
    }

    /// Parse [`MessageBlock::FollowOnFragment`].
    fn parse_follow_on_fragment(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, size) = be_u16(input)?;
        let (rest, frag) = be_u8(rest)?;
        let (rest, message_id) = be_u32(rest)?;
        let fragment_len = size.saturating_sub(5) as usize; // frag + id

        if fragment_len == 0 {
            tracing::warn!(
                target: LOG_TARGET,
                "follow-on fragment is empty",
            );
            return Err(Err::Error(make_error(input, ErrorKind::Fail)));
        }

        if rest.len() < fragment_len {
            tracing::warn!(
                target: LOG_TARGET,
                "follow-on fragment message is too short",
            );
            return Err(Err::Error(make_error(input, ErrorKind::Fail)));
        }
        let (rest, fragment) = take(fragment_len)(rest)?;

        Ok((
            rest,
            Block::FollowOnFragment {
                last: frag & 1 == 1,
                message_id: MessageId::from(message_id),
                fragment_num: frag >> 1,
                fragment: fragment.to_vec(),
            },
        ))
    }

    /// Parse [`MessageBlock::Ack`].
    fn parse_ack(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, size) = be_u16(input)?;
        let (rest, ack_through) = be_u32(rest)?;
        let (rest, num_acks) = be_u8(rest)?;

        let (rest, ranges) = match size.saturating_sub(5) {
            0 => (rest, Vec::new()),
            num_ranges if num_ranges % 2 == 0 => {
                let (rest, ranges) = take(num_ranges)(rest)?;

                (
                    rest,
                    ranges.chunks(2usize).map(|chunk| (chunk[0], chunk[1])).collect::<Vec<_>>(),
                )
            }
            num_ranges => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?num_ranges,
                    "invalid nack/ack range count",
                );
                debug_assert!(false);

                (rest, Vec::new())
            }
        };

        Ok((
            rest,
            Block::Ack {
                ack_through,
                num_acks,
                ranges,
            },
        ))
    }

    /// Parse [`MessageBlock::NewToken`].
    fn parse_new_token(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, size) = be_u16(input)?;
        let (rest, expires) = be_u32(rest)?;
        let (rest, token) = be_u64(rest)?;

        Ok((rest, Block::NewToken { expires, token }))
    }

    /// Parse [`MessageBlock::PathChallenge`].
    fn parse_path_challenge(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, size) = be_u16(input)?;
        let (rest, data) = take(size)(rest)?;

        Ok((
            rest,
            Block::PathChallenge {
                challenge: data.to_vec(),
            },
        ))
    }

    /// Parse [`MessageBlock::PathResponse`].
    fn parse_path_response(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, size) = be_u16(input)?;
        let (rest, data) = take(size)(rest)?;

        Ok((
            rest,
            Block::PathResponse {
                response: data.to_vec(),
            },
        ))
    }

    /// Parse [`MessageBlock::FirstPacketNumber`].
    fn parse_first_packet_number(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, size) = be_u16(input)?;
        let (rest, first_pkt_num) = be_u32(input)?;

        Ok((rest, Block::FirstPacketNumber { first_pkt_num }))
    }

    /// Parse [`MessageBlock::Congestion`].
    fn parse_congestion(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, size) = be_u16(input)?;
        let (rest, flag) = be_u8(input)?;

        Ok((rest, Block::Congestion { flag }))
    }

    /// Attempt to parse unsupported block from `input`
    fn parse_unsupported_block(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, size) = be_u16(input)?;
        let (rest, _bytes) = take(size)(rest)?;

        Ok((rest, Block::Unsupported))
    }

    /// Attempt to parse [`Block`] from `input`, returning the parsed block
    // and the rest of `input` to caller.
    fn parse_inner(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, block_type) = be_u8(input)?;

        match BlockType::from_u8(block_type) {
            Some(BlockType::DateTime) => Self::parse_date_time(rest),
            Some(BlockType::Options) => Self::parse_options(rest),
            Some(BlockType::RouterInfo) => Self::parse_router_info(rest),
            Some(BlockType::I2Np) => Self::parse_i2np(rest),
            Some(BlockType::FirstFragment) => Self::parse_first_fragment(rest),
            Some(BlockType::FollowOnFragment) => Self::parse_follow_on_fragment(rest),
            Some(BlockType::Termination) => Self::parse_termination(rest),
            Some(BlockType::Ack) => Self::parse_ack(rest),
            Some(BlockType::NewToken) => Self::parse_new_token(rest),
            Some(BlockType::PathChallenge) => Self::parse_path_challenge(rest),
            Some(BlockType::PathResponse) => Self::parse_path_response(rest),
            Some(BlockType::FirstPacketNumber) => Self::parse_first_packet_number(rest),
            Some(BlockType::Congestion) => Self::parse_congestion(rest),
            Some(BlockType::Padding) => Self::parse_padding(rest),
            Some(block_type) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?block_type,
                    "ignoring block",
                );
                Self::parse_unsupported_block(rest)
            }
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?block_type,
                    "unrecognized ssu2 block type",
                );
                Err(Err::Error(make_error(input, ErrorKind::Fail)))
            }
        }
    }

    /// Attempt to parse `input` into an SSU2 message [`Block`] and recursive call
    /// `Block::parse_multiple()` until there are no bytes or an error was encountered.
    fn parse_multiple(input: &[u8], mut messages: Vec<Block>) -> Option<Vec<Block>> {
        let (rest, message) = Self::parse_inner(input).ok()?;
        messages.push(message);

        match rest.is_empty() {
            true => Some(messages),
            false => Self::parse_multiple(rest, messages),
        }
    }

    /// Attempt to parse `input` into one or more SSU2 message [`Block`]s.
    pub fn parse(input: &[u8]) -> Option<Vec<Block>> {
        Self::parse_multiple(input, Vec::new())
    }

    /// Get serialized length of a [`Block`].
    pub fn serialized_len(&self) -> usize {
        3usize // message type + size
            + match self {
                Block::DateTime { .. } => 4usize,
                Block::Options { .. } => OPTIONS_MIN_SIZE as usize,
                Block::RouterInfo { router_info } => todo!(),
                Block::I2Np { message } => message.serialized_len_short(),
                Block::FirstFragment { fragment, .. } => fragment
                    .len()
                    .saturating_add(1usize) // message type
                    .saturating_add(4usize) // message id
                    .saturating_add(4usize), // expiration
                Block::FollowOnFragment { fragment, .. } => fragment
                    .len()
                    .saturating_add(1usize) // fragmentation info
                    .saturating_add(4usize), // message id
                Block::Termination { .. } => TERMINATION_MIN_SIZE as usize,
                Block::Ack { ranges, .. } => 4usize // ack through
                    .saturating_add(1usize) // ack count
                    .saturating_add(ranges.len() * 2), // nack/ack ranges
                Block::NewToken { .. } => 12usize, // expires + token
                Block::PathChallenge { challenge } => challenge.len(),
                Block::PathResponse { response } => response.len(),
                Block::FirstPacketNumber { .. } => 4usize, // packet number
                Block::Congestion { .. } => 1usize, // flag
                Block::Padding { padding } => padding.len(),
                Block::Address { address } => match address.ip() {
                    IpAddr::V4(_) => 2usize + 4usize, // port + address
                    IpAddr::V6(_) => 2usize + 16usize, // port + address
                },
                block_type => todo!("unsupported block type: {block_type:?}"),
            }
    }

    /// Serialize [`Block`] into a byte vector.
    pub fn serialize(self) -> BytesMut {
        let mut out = BytesMut::with_capacity(self.serialized_len());

        match self {
            Self::DateTime { timestamp } => {
                out.put_u8(BlockType::DateTime.as_u8());
                out.put_u16(4u16);
                out.put_u32(timestamp);

                out
            }
            Self::Address { address } => {
                out.put_u8(BlockType::Address.as_u8());

                match address {
                    SocketAddr::V4(address) => {
                        out.put_u16(6u16);
                        out.put_u16(address.port());
                        out.put_slice(&address.ip().octets());
                    }
                    SocketAddr::V6(address) => {
                        out.put_u16(18u16);
                        out.put_u16(address.port());
                        out.put_slice(&address.ip().octets());
                    }
                }

                out
            }
            block_type => todo!("unsupported block type: {block_type:?}"),
        }
    }
}

/// SSU2 message type.
#[derive(Debug)]
pub enum MessageType {
    SessionRequest,
    SessionCreated,
    SessionConfirmed,
    Data,
    PeerTest,
    Retry,
    TokenRequest,
    HolePunch,
}

impl Deref for MessageType {
    type Target = u8;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::SessionRequest => &0u8,
            Self::SessionCreated => &1u8,
            Self::SessionConfirmed => &2u8,
            Self::Data => &6u8,
            Self::PeerTest => &7u8,
            Self::Retry => &9u8,
            Self::TokenRequest => &10u8,
            Self::HolePunch => &11u8,
        }
    }
}

impl TryFrom<u8> for MessageType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0u8 => Ok(Self::SessionRequest),
            1u8 => Ok(Self::SessionCreated),
            2u8 => Ok(Self::SessionConfirmed),
            6u8 => Ok(Self::Data),
            7u8 => Ok(Self::PeerTest),
            9u8 => Ok(Self::Retry),
            10u8 => Ok(Self::TokenRequest),
            11u8 => Ok(Self::HolePunch),
            _ => Err(()),
        }
    }
}

/// Flag for the message with short header.
pub enum ShortHeaderFlag {
    /// Short header for `Data`.
    Data {
        /// Should the message be immediately ACKed.
        immediate_ack: bool,
    },

    /// Short header for `SessionConfirmed`.
    SessionConfirmed {
        /// Fragment number.
        fragment_num: u8,

        /// Fragment count.
        fragment_count: u8,
    },
}

/// Header builder.
pub enum HeaderBuilder {
    /// Long header.
    Long {
        /// Destination connection ID.
        dst_id: Option<u64>,

        /// Source connection ID.
        src_id: Option<u64>,

        /// Packet number.
        pkt_num: Option<u32>,

        /// Token.
        token: Option<u64>,

        /// Message type.
        message_type: Option<MessageType>,

        /// Network ID.
        net_id: Option<u8>,
    },

    /// Short header.
    Short {
        /// Destination connection ID.
        dst_id: Option<u64>,

        /// Packet number.
        pkt_num: Option<u32>,

        /// Flag contents of the short header.
        ///
        /// Depends on message type.
        flag: Option<ShortHeaderFlag>,
    },
}

impl HeaderBuilder {
    /// Create long header.
    pub fn long() -> Self {
        Self::Long {
            src_id: None,
            dst_id: None,
            pkt_num: None,
            token: None,
            message_type: None,
            net_id: None,
        }
    }

    /// Create short header.
    pub fn short() -> Self {
        Self::Short {
            dst_id: None,
            flag: None,
            pkt_num: None,
        }
    }

    /// Specify destination connection ID.
    pub fn with_dst_id(mut self, value: u64) -> Self {
        match &mut self {
            Self::Long { dst_id, .. } => {
                *dst_id = Some(value);
            }
            Self::Short { dst_id, .. } => {
                *dst_id = Some(value);
            }
        }

        self
    }

    /// Specify source connection ID.
    pub fn with_src_id(mut self, value: u64) -> Self {
        match &mut self {
            Self::Long { src_id, .. } => {
                *src_id = Some(value);
            }
            Self::Short { .. } => unreachable!(),
        }

        self
    }

    /// Specify packet number.
    pub fn with_pkt_num(mut self, value: u32) -> Self {
        match &mut self {
            Self::Long { pkt_num, .. } => {
                *pkt_num = Some(value);
            }
            Self::Short { pkt_num, .. } => {
                *pkt_num = Some(value);
            }
        }

        self
    }

    /// Specify flag for short header.
    pub fn with_short_header_flag(mut self, value: ShortHeaderFlag) -> Self {
        match &mut self {
            Self::Short { flag, .. } => {
                *flag = Some(value);
            }
            Self::Long { .. } => unreachable!(),
        }

        self
    }

    /// Specify token.
    pub fn with_token(mut self, value: u64) -> Self {
        match &mut self {
            Self::Long { token, .. } => {
                *token = Some(value);
            }
            Self::Short { .. } => unreachable!(),
        }

        self
    }

    /// Specify message type.
    pub fn with_message_type(mut self, value: MessageType) -> Self {
        match &mut self {
            Self::Long { message_type, .. } => {
                *message_type = Some(value);
            }
            Self::Short { .. } => unreachable!(),
        }

        self
    }

    /// Specify network ID.
    pub fn with_net_id(mut self, value: u8) -> Self {
        match &mut self {
            Self::Long { net_id, .. } => {
                *net_id = Some(value);
            }
            Self::Short { .. } => unreachable!(),
        }

        self
    }

    /// Build [`HeaderBuilder`] into [`Header`].
    pub fn build<R: Runtime>(self) -> Header {
        match self {
            Self::Long {
                dst_id,
                src_id,
                pkt_num,
                token,
                message_type,
                net_id,
            } => Header::Long {
                dst_id: dst_id.expect("to exist"),
                src_id: src_id.expect("to exist"),
                pkt_num: pkt_num.unwrap_or(R::rng().next_u32()),
                token: token.expect("to exist"),
                message_type: message_type.expect("to exist"),
                net_id: net_id.unwrap_or(2u8),
            },
            Self::Short {
                dst_id,
                pkt_num,
                flag,
            } => Header::Short {
                dst_id: dst_id.expect("to exist"),
                pkt_num: pkt_num.unwrap_or(R::rng().next_u32()),
                flag: flag.expect("to exist"),
            },
        }
    }
}

/// SSU2 packet header.
pub enum Header {
    /// Long header.
    Long {
        /// Destination connection ID.
        dst_id: u64,

        /// Source connection ID.
        src_id: u64,

        /// Packet number.
        pkt_num: u32,

        /// Token.
        token: u64,

        /// Message type.
        message_type: MessageType,

        /// Network ID.
        net_id: u8,
    },

    /// Short header.
    Short {
        /// Destination connection ID.
        dst_id: u64,

        /// Packet number.
        pkt_num: u32,

        /// Flag contents of the short header.
        ///
        /// Depends on message type.
        flag: ShortHeaderFlag,
    },
}

impl Header {
    /// Get packet number.
    fn pkt_num(&self) -> u32 {
        match self {
            Self::Long { pkt_num, .. } => *pkt_num,
            Self::Short { pkt_num, .. } => *pkt_num,
        }
    }

    /// Serialize [`Header`] into a byte vector.
    fn serialize(&self) -> BytesMut {
        match self {
            Self::Long {
                dst_id,
                src_id,
                pkt_num,
                token,
                message_type,
                net_id,
            } => {
                let mut out = BytesMut::with_capacity(16usize);

                out.put_u64(*dst_id);
                out.put_u32(*pkt_num);
                out.put_u8(**message_type);
                out.put_u8(2u8);
                out.put_u8(*net_id);
                out.put_u8(0u8);
                out.put_u64(*src_id);
                out.put_u64(*token);

                out
            }
            Self::Short {
                dst_id,
                pkt_num,
                flag,
            } => {
                let mut out = BytesMut::with_capacity(8usize);

                out.put_u64(*dst_id);
                out.put_u32(*pkt_num);

                match flag {
                    ShortHeaderFlag::Data { immediate_ack } => {
                        out.put_u8(*MessageType::Data);
                        out.put_u8(*immediate_ack as u8);
                        out.put_u16(0u16); // more flags
                    }
                    ShortHeaderFlag::SessionConfirmed {
                        fragment_num,
                        fragment_count,
                    } => {
                        out.put_u8(*MessageType::SessionConfirmed);
                        out.put_u8(fragment_num << 4 | fragment_count);
                        out.put_u16(0u16); // more flags
                    }
                }

                out
            }
        }
    }
}

pub struct MessageBuilder {
    /// Message blocks.
    blocks: Vec<Block>,

    /// Header.
    header: Header,

    /// Header key 1.
    key1: Option<[u8; 32]>,

    /// Header key 2.
    ///
    /// May be `None` if `key1` is used.
    key2: Option<[u8; 32]>,

    /// Payload len.
    payload_len: usize,
}

impl MessageBuilder {
    /// Create new [`MessageBuilder`].
    pub fn new(header: Header) -> Self {
        Self {
            blocks: Vec::new(),
            header,
            key1: None,
            key2: None,
            payload_len: 0usize,
        }
    }

    /// Specify `key` to be both `key_header_1` and `key_header_2`.
    pub fn with_key(mut self, key: [u8; 32]) -> Self {
        self.key1 = Some(key);
        self
    }

    /// Specify distinct keys for header encryption.
    pub fn with_keypair(mut self, key1: [u8; 32], key2: [u8; 32]) -> Self {
        self.key1 = Some(key1);
        self.key2 = Some(key2);
        self
    }

    /// Push `block` into the list of blocks.
    pub fn with_block(mut self, block: Block) -> Self {
        self.payload_len += block.serialized_len();
        self.blocks.push(block);
        self
    }

    /// Serialize [`MessageBuilder`] into a byte vector.
    ///
    /// Panics if no header encryption key is specified or `key_header_2` is missing
    /// when it's supposed to exist (deduced based on message type).
    pub fn build(mut self) -> BytesMut {
        let key1 = self.key1.take().expect("to exist");
        let key2 = self.key2.take().unwrap_or(key1);
        let mut header = self.header.serialize();

        // serialize payload
        let mut payload = self
            .blocks
            .into_iter()
            .fold(
                BytesMut::with_capacity(self.payload_len),
                |mut out, block| {
                    out.put_slice(&block.serialize());

                    out
                },
            )
            .to_vec();

        // encryption must succeed since the parameters are controlled by us
        ChaChaPoly::with_nonce(&key1, self.header.pkt_num() as u64)
            .encrypt_with_ad_new(&header, &mut payload)
            .expect("to succeed");

        // encrypt first 16 bytes of the long header
        //
        // https://geti2p.net/spec/ssu2#header-encryption-kdf
        payload[payload.len() - 24..]
            .chunks(12usize)
            .zip(header.chunks_mut(8usize))
            .zip([key1, key2])
            .for_each(|((chunk, header_chunk), key)| {
                ChaCha::with_iv(
                    key,
                    TryInto::<[u8; 12]>::try_into(chunk).expect("to succeed"),
                )
                .decrypt([0u8; 8])
                .iter()
                .zip(header_chunk.iter_mut())
                .for_each(|(mask_byte, header_byte)| {
                    *header_byte ^= mask_byte;
                });
            });

        // encrypt rest of the header
        ChaCha::with_iv(key2, [0u8; 12]).encrypt_ref(&mut header[16..32]);

        let mut out = BytesMut::with_capacity(header.len() + payload.len());
        out.put_slice(&header);
        out.put_slice(&payload);

        out
    }
}
