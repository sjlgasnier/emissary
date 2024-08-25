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

use crate::{
    crypto::sha256::Sha256,
    i2np::{AES256_IV_LEN, ROUTER_HASH_LEN},
    primitives::TunnelId,
    runtime::Runtime,
};

use bytes::{BufMut, BytesMut};
use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u32, be_u8},
    Err, IResult,
};
use rand_core::RngCore;

use alloc::{vec, vec::Vec};
use core::fmt;

/// Local delivery
const LOCAL_DELIVERY: u8 = 0x00;

/// Tunnel delivery.
const TUNNEL_DELIVERY: u8 = 0x01;

/// Router delivery.
const ROUTER_DELIVERY: u8 = 0x02;

/// Unfragmented message.
const UNFRAGMENTED: u8 = 0x00;

/// Fragmented message.
const FRAGMENTED: u8 = 0x01;

/// First fragment.
const FIRST_FRAGMENT: u8 = 0x01;

/// Middle fragment.
const MIDDLE_FRAGMENT: u8 = 0x00;

/// Last fragment.
const LAST_FRAGMENT: u8 = 0x01;

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
    /// Attempt to parse [`EncryptedTunnelData`] from `input`.
    ///
    /// Returns the parsed message and rest of `input` on success.
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

    /// Attempt to parse `input` into [`EncryptedTunnelData`].
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

/// Delivery instructions for the wrapped I2NP message.
#[derive(Debug)]
pub enum DeliveryInstructions<'a> {
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

/// I2NP message kind.
///
/// [`MessageKind::MiddleFragment`] and [`MessageKind::LastFragment`] do not have explicit
/// delivery instructions as they're delivered to the same destination as the first fragment.
#[derive(Debug)]
pub enum MessageKind<'a> {
    /// Unfragmented I2NP message.
    Unfragmented {
        /// Delivery instructions,
        delivery_instructions: DeliveryInstructions<'a>,
    },

    /// First fragment of a fragmented I2NP message.
    FirstFragment {
        /// Message ID.
        ///
        /// Rest of the fragments will use the same message ID.
        message_id: u32,

        /// Delivery instructions,
        delivery_instructions: DeliveryInstructions<'a>,
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

/// Parsed `TunnelData` block.
pub struct TunnelDataBlock<'a> {
    /// Message kind.
    ///
    /// Defines the fragmentation (if any) of the message and its delivery instructions.
    pub message_kind: MessageKind<'a>,

    /// I2NP message (fragment).
    pub message: &'a [u8],
}

impl<'a> fmt::Debug for TunnelDataBlock<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelDataBlock")
            .field("message_kind", &self.message_kind)
            .finish_non_exhaustive()
    }
}

/// Decrypted `TunnelData` message.
#[derive(Debug)]
pub struct TunnelData<'a> {
    /// Parsed messages.
    pub messages: Vec<TunnelDataBlock<'a>>,
}

impl<'a> TunnelData<'a> {
    /// Attempt to parse `input` into first or follow-on delivery instructions and payload.
    fn parse_frame(input: &'a [u8]) -> IResult<&'a [u8], TunnelDataBlock<'a>> {
        let (rest, flag) = be_u8(input)?;

        // parse follow-on fragment delivery instructions
        //
        // https://geti2p.net/spec/tunnel-message#follow-on-fragment-delivery-instructions
        match flag >> 7 {
            FRAGMENTED => {
                // format: 1nnnnnnd
                //  - msb set for a middle fragment
                //  - middle bits make up the sequence number
                //  - lsb specifies whether this is the last fragment
                let sequence_number = ((flag >> 1) & 0x3f) as usize;
                let (rest, message_id) = be_u32(rest)?;
                let (rest, size) = be_u16(rest)?;
                let (rest, message) = take(size as usize)(rest)?;

                let (rest, message_kind) = match flag & 0x01 {
                    MIDDLE_FRAGMENT => (
                        rest,
                        MessageKind::MiddleFragment {
                            message_id,
                            sequence_number,
                        },
                    ),
                    LAST_FRAGMENT => (
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
                    TunnelDataBlock {
                        message_kind,
                        message,
                    },
                ));
            }
            UNFRAGMENTED => {}
            _ => return Err(Err::Error(make_error(input, ErrorKind::Fail))),
        }

        // parse first fragment delivery instructions.
        //
        // https://geti2p.net/spec/tunnel-message#first-fragment-delivery-instructions
        let (rest, delivery_instructions) = match (flag >> 5) & 0x03 {
            LOCAL_DELIVERY => (rest, DeliveryInstructions::Local),
            TUNNEL_DELIVERY => {
                let (rest, tunnel_id) = be_u32(rest)?;
                let (rest, hash) = take(ROUTER_HASH_LEN)(rest)?;

                (rest, DeliveryInstructions::Tunnel { hash, tunnel_id })
            }
            ROUTER_DELIVERY => {
                let (rest, hash) = take(ROUTER_HASH_LEN)(rest)?;

                (rest, DeliveryInstructions::Router { hash })
            }
            _ => return Err(Err::Error(make_error(input, ErrorKind::Fail))),
        };

        let (rest, message_kind) = match (flag >> 3) & 0x01 {
            UNFRAGMENTED => (
                rest,
                MessageKind::Unfragmented {
                    delivery_instructions,
                },
            ),
            FIRST_FRAGMENT => {
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
            TunnelDataBlock {
                message_kind,
                message,
            },
        ))
    }

    /// Recursively parse `input` into a vector of [`TunnelDataBlock`]s
    fn parse_inner(
        input: &'a [u8],
        mut messages: Vec<TunnelDataBlock<'a>>,
    ) -> Option<Vec<TunnelDataBlock<'a>>> {
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

/// Tunnel data builder.
pub struct TunnelDataBuilder<'a> {
    /// Next tunnel ID.
    next_tunnel_id: TunnelId,

    /// Messages.
    messages: Vec<TunnelDataBlock<'a>>,
}

impl<'a> TunnelDataBuilder<'a> {
    /// Create new [`TunnelDataBuilder`].
    pub fn new(next_tunnel_id: TunnelId) -> Self {
        Self {
            next_tunnel_id,
            messages: Vec::new(),
        }
    }

    /// Add [`TunnelData`] block with local delivery.
    pub fn with_local_delivery(mut self, message: &'a [u8]) -> Self {
        self.messages.push(TunnelDataBlock {
            message_kind: MessageKind::Unfragmented {
                delivery_instructions: DeliveryInstructions::Local,
            },
            message,
        });

        self
    }

    /// Add [`TunnelData`] block with router delivery.
    pub fn with_router_delivery(mut self, hash: &'a [u8], message: &'a [u8]) -> Self {
        self.messages.push(TunnelDataBlock {
            message_kind: MessageKind::Unfragmented {
                delivery_instructions: DeliveryInstructions::Router { hash },
            },
            message,
        });

        self
    }

    /// Add [`TunnelData`] block with tunnel delivery.
    pub fn with_tunnel_delivery(
        mut self,
        hash: &'a [u8],
        tunnel_id: TunnelId,
        message: &'a [u8],
    ) -> Self {
        self.messages.push(TunnelDataBlock {
            message_kind: MessageKind::Unfragmented {
                delivery_instructions: DeliveryInstructions::Tunnel {
                    tunnel_id: tunnel_id.into(),
                    hash,
                },
            },
            message,
        });

        self
    }

    /// Serialize message fragments into a `TunnelData` message.
    //
    // TODO: return iterator of messages
    pub fn build<R: Runtime>(mut self, padding: &[u8; 1028]) -> Vec<u8> {
        assert_eq!(self.messages.len(), 1);

        let mut out = BytesMut::with_capacity(1028);

        let message = self.messages.pop().unwrap();

        let delivery_instructions = match message.message_kind {
            MessageKind::Unfragmented {
                delivery_instructions,
            } => match delivery_instructions {
                DeliveryInstructions::Local => vec![0x00],
                DeliveryInstructions::Router { hash } => {
                    let mut out = BytesMut::with_capacity(33);
                    out.put_u8(0x02 << 5);
                    out.put_slice(&hash);

                    out.freeze().to_vec()
                }
                DeliveryInstructions::Tunnel { tunnel_id, hash } => {
                    let mut out = BytesMut::with_capacity(37);
                    out.put_u8(0x01 << 5);
                    out.put_u32(tunnel_id);
                    out.put_slice(&hash);

                    out.freeze().to_vec()
                }
            },
            _ => todo!("fragments not supported"),
        };

        // calculate padding size
        let padding_size = 1028usize
            .saturating_sub(4usize) // tunnel id
            .saturating_sub(16usize) // aes iv
            .saturating_sub(4usize) // checksum
            .saturating_sub(1) // flag
            .saturating_sub(2) // length
            .saturating_sub(delivery_instructions.len())
            .saturating_sub(message.message.len());
        let offset = (R::rng().next_u32() % (1028u32 - padding_size as u32)) as usize;
        let aes_iv = {
            let mut iv = [0u8; 16];
            R::rng().fill_bytes(&mut iv);

            iv
        };
        let checksum = Sha256::new()
            .update(&delivery_instructions)
            .update((message.message.len() as u16).to_be_bytes())
            .update(&message.message)
            .update(&aes_iv)
            .finalize();

        out.put_u32(self.next_tunnel_id.into());
        out.put_slice(&aes_iv);
        out.put_slice(&checksum[..4]);
        out.put_slice(&padding[offset..offset + padding_size]);
        out.put_u8(0x00); // zero byte (end of padding)
        out.put_slice(&delivery_instructions);
        out.put_u16(message.message.len() as u16);
        out.put_slice(message.message);

        out.freeze().to_vec()
    }
}
