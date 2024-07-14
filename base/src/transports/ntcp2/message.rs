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

//! NTCP2 message block implementation
//!
//! https://geti2p.net/spec/ntcp2#unencrypted-data

use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u32, be_u8},
    sequence::tuple,
    Err, IResult,
};

use alloc::{vec, vec::Vec};
use core::fmt;

use crate::i2np::RawI2npMessage;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ntcp2::message";

/// Block format identifier.
#[derive(Debug)]
enum BlockType {
    /// Date time.
    DateTime,

    /// Updated options.
    Options,

    /// Router information.
    RouterInfo,

    /// I2NP message.
    I2Np,

    /// NTCP2 termination.
    Termination,

    /// Padding
    Padding,
}

impl BlockType {
    /// Serialize [`BlockType`].
    fn as_u8(&self) -> u8 {
        match self {
            Self::DateTime => 0,
            Self::Options => 1,
            Self::RouterInfo => 2,
            Self::I2Np => 3,
            Self::Termination => 4,
            Self::Padding => 254,
        }
    }

    /// Deserialize [`BlockType`].
    fn from_u8(block: u8) -> Option<Self> {
        match block {
            0 => Some(Self::DateTime),
            1 => Some(Self::Options),
            2 => Some(Self::RouterInfo),
            3 => Some(Self::I2Np),
            4 => Some(Self::Termination),
            254 => Some(Self::Padding),
            _ => None,
        }
    }

    /// Get header size for a message block.
    fn header_size(&self) -> usize {
        match self {
            // `<1 byte block id><2 byte length>`
            Self::DateTime | Self::Options | Self::Termination | Self::Padding => 3,

            // `<1 byte block id><2 byte length><1 byte flag>`
            Self::RouterInfo => 4,

            // `<1 byte block id><2 byte length><1 byte type><4 byte message id><4 byte expiration`
            Self::I2Np => 12,
        }
    }
}

/// NTCP2 message block.
pub enum MessageBlock<'a> {
    /// Date time update, used for time synchronization.
    DateTime {
        /// Time since Unix epoch, in seconds.
        timestamp: u32,
    },

    /// Options update.
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
        t_dmy: u8,

        /// Maximum intra-message delay router is willing to insert.
        t_delay: u16,

        /// Requested intra-message delay.
        r_deay: u16,
    },

    /// Router info update.
    RouterInfo {
        /// Whether the received message was a floodfill request.
        floodfill_request: bool,

        /// Router info.
        router_info: &'a [u8],
    },

    /// I2NP message.
    I2Np {
        /// Raw, unparsed I2NP message.
        message: RawI2npMessage,
    },

    /// Session termination.
    Termination {
        /// How many valid frames have been received.
        valid_frames: u64,

        /// Reason for termination.
        reason: u8,
    },
}

impl<'a> fmt::Debug for MessageBlock<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::DateTime { timestamp } =>
                f.debug_struct("MessageBlock::DateTime").field("timestamp", &timestamp).finish(),
            Self::Options {
                t_min,
                t_max,
                r_min,
                r_max,
                t_dmy,
                t_delay,
                r_deay,
            } => f
                .debug_struct("MessageBlock::Options")
                .field("t_min", &t_min)
                .field("t_max", &t_max)
                .field("r_min", &r_min)
                .field("r_max", &r_max)
                .field("t_dmy", &t_dmy)
                .field("t_delay", &t_delay)
                .field("r_deay", &r_deay)
                .finish(),
            Self::RouterInfo {
                floodfill_request,
                router_info,
            } => f
                .debug_struct("MessageBlock::RouterInfo")
                .field("floodfill", &floodfill_request)
                .field("router_info_len", &router_info.len())
                .finish(),
            Self::I2Np { message } =>
                f.debug_struct("MessageBlock::I2NP").field("message", &message).finish(),
            Self::Termination {
                valid_frames,
                reason,
            } => f
                .debug_struct("MessageBlock::Termination")
                .field("valid_frames", &valid_frames)
                .field("reason", &reason)
                .finish(),
        }
    }
}

impl<'a> MessageBlock<'a> {
    /// Parse [`MessageBlock::DateTime`].
    fn parse_date_time(input: &'a [u8]) -> IResult<&'a [u8], MessageBlock<'a>> {
        let (rest, timestamp) = be_u32(input)?;

        Ok((rest, MessageBlock::DateTime { timestamp }))
    }

    /// Parse [`MessageBlock::`].
    fn parse_options(input: &'a [u8]) -> IResult<&'a [u8], MessageBlock<'a>> {
        todo!("options not supported");
    }

    /// Parse [`MessageBlock::RouterInfo`].
    fn parse_router_info(input: &'a [u8]) -> IResult<&'a [u8], MessageBlock<'a>> {
        let (rest, size) = be_u16(input)?;
        let (rest, flag) = be_u8(rest)?;
        let (rest, router_info) = take(size - 1)(rest)?;

        tracing::trace!(
            target: LOG_TARGET,
            block_len = ?size,
            input_len = ?input.len(),
            floodfill = ?flag & 1 == 1,
            "parse router info block",
        );
        assert!(flag == 0, "floodfill");

        Ok((
            rest,
            MessageBlock::RouterInfo {
                floodfill_request: flag & 1 == 1,
                router_info,
            },
        ))
    }

    /// Parse [`MessageBlock::I2Np`].
    fn parse_i2np(input: &'a [u8]) -> IResult<&'a [u8], MessageBlock<'a>> {
        let (rest, message) = RawI2npMessage::parse_frame(input)?;

        Ok((rest, MessageBlock::I2Np { message }))
    }

    /// Parse [`MessageBlock::Termination`].
    fn parse_termination(input: &'a [u8]) -> IResult<&'a [u8], MessageBlock<'a>> {
        todo!("termination support not implemented");
    }

    /// Parse [`MessageBlock::Padding`].
    fn parse_padding(input: &'a [u8]) -> IResult<&'a [u8], MessageBlock<'a>> {
        todo!("padding support not implemented");
    }

    fn parse_inner(input: &'a [u8]) -> IResult<&'a [u8], MessageBlock<'a>> {
        let (rest, block_type) = be_u8(input)?;

        match BlockType::from_u8(block_type) {
            None => return Err(Err::Error(make_error(input, ErrorKind::Fail))),
            Some(BlockType::DateTime) => Self::parse_date_time(rest),
            Some(BlockType::Options) => Self::parse_options(rest),
            Some(BlockType::RouterInfo) => Self::parse_router_info(rest),
            Some(BlockType::I2Np) => Self::parse_i2np(rest),
            Some(BlockType::Termination) => Self::parse_termination(rest),
            Some(BlockType::Padding) => Self::parse_padding(rest),
        }
    }

    /// Try to parse `input` into an NTCP message block
    //
    // TODO: handle multiple message blocks
    pub fn parse(input: &'a [u8]) -> Option<MessageBlock<'a>> {
        Some(MessageBlock::parse_inner(input).ok()?.1)
    }

    /// Create new NTCP2 `RouterInfo` message block.
    pub fn new_router_info(router_info: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; router_info.len() + BlockType::RouterInfo.header_size()];
        let block_size = router_info.len() as u16 + 1u16; // router info length + 1 byte for the flag

        out[0] = BlockType::RouterInfo.as_u8();
        out[1..3].copy_from_slice(&block_size.to_be_bytes().to_vec());
        out[3] = 0;
        out[4..].copy_from_slice(&router_info);

        out
    }
}

// TODO: tests
