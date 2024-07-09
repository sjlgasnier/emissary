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

use alloc::{vec, vec::Vec};
use core::fmt;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ntcp2::message";

/// Block format identifier.
#[derive(Debug)]
enum BlockFormat {
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

impl BlockFormat {
    /// Serialize [`BlockFormat`].
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

    /// Deserialize [`BlockFormat`].
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

/// NTCP2 message.
pub enum Message {
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
        router_info: Vec<u8>,
    },

    /// I2NP message.
    I2Np {
        /// I2NP message type.
        msg_type: u8,

        /// Message ID.
        message_id: u32,

        /// Message expiration.
        ///
        /// Time since Unix epoch, in seconds.
        expiration: u32,

        /// Message.
        message: Vec<u8>,
    },

    /// Session termination.
    Termination {
        /// How many valid frames have been received.
        valid_frames: u64,

        /// Reason for termination.
        reason: u8,
    },
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::DateTime { timestamp } => f
                .debug_struct("Message::DateTime")
                .field("timestamp", &timestamp)
                .finish(),
            Self::Options {
                t_min,
                t_max,
                r_min,
                r_max,
                t_dmy,
                t_delay,
                r_deay,
            } => f
                .debug_struct("Message::Options")
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
                .debug_struct("Message::RouterInfo")
                .field("floodfill", &floodfill_request)
                .field("router_info_len", &router_info.len())
                .finish(),
            Self::I2Np {
                msg_type,
                message_id,
                expiration,
                ..
            } => f
                .debug_struct("Message::I2NP")
                .field("msg_type", &msg_type)
                .field("message_id", &message_id)
                .field("expiration", &expiration)
                .finish_non_exhaustive(),
            Self::Termination {
                valid_frames,
                reason,
            } => f
                .debug_struct("Message::Termination")
                .field("valid_frames", &valid_frames)
                .field("reason", &reason)
                .finish(),
        }
    }
}

impl Message {
    /// Try to create new [`Message`] from `bytes`.
    //
    // TODO: use `nom`?
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes[0] {
            0 => {
                let ts = TryInto::<[u8; 4]>::try_into(&bytes[3..5]).ok()?;

                Some(Self::DateTime {
                    timestamp: u32::from_be_bytes(ts),
                })
            }
            1 => {
                tracing::warn!("options not supported");
                None
            }
            2 => {
                let size =
                    u16::from_be_bytes(TryInto::<[u8; 2]>::try_into(&bytes[1..3]).ok()?) as usize;

                tracing::trace!(
                    target: LOG_TARGET,
                    block_len = ?size,
                    input_len = ?bytes.len(),
                    floodfill = ?bytes[3] & 1 == 1,
                    "parse router info block",
                );
                assert!(bytes[3] == 0);

                (bytes.len() >= size).then(|| Self::RouterInfo {
                    floodfill_request: bytes[3] & 1 == 1,
                    router_info: bytes[4..size + 3].to_vec(),
                })
            }
            3 => {
                tracing::warn!("i2np messages not supported");
                None
            }
            4 => {
                tracing::warn!("termination not supported");
                None
            }
            block_id => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?block_id,
                    "unrecognized block id",
                );

                None
            }
        }
    }

    /// Create new NTCP2 `RouterInfo` message block.
    pub fn new_router_info(router_info: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; router_info.len() + BlockFormat::RouterInfo.header_size()];
        let block_size = router_info.len() as u16 + 1u16; // router info length + 1 byte for the flag

        out[0] = BlockFormat::RouterInfo.as_u8();
        out[1..3].copy_from_slice(&block_size.to_be_bytes().to_vec());
        out[3] = 0;
        out[4..].copy_from_slice(&router_info);

        out
    }
}

// TODO: tests
