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

use crate::{destination::protocol::streaming::LOG_TARGET, primitives::Destination};

use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u32, be_u8},
    Err, IResult,
};

use alloc::vec::Vec;
use core::{fmt, str};

/// Flags of the streaming packet.
pub struct Flags<'a> {
    /// Included destination, if received.
    destination: Option<Destination>,

    /// Flags.
    flags: u16,

    /// Maximum packet size, if received.
    max_packet_size: Option<u16>,

    /// Offline signature, if received.
    offline_signature: Option<&'a [u8]>,

    /// Requested delay, if received.
    requested_delay: Option<u16>,

    /// Included signature, if received.
    signature: Option<&'a [u8]>,
}

impl<'a> Flags<'a> {
    fn new(flags: u16, options: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (rest, requested_delay) = match (flags >> 6) & 1 == 1 {
            true => be_u16(options).map(|(rest, requested_delay)| (rest, Some(requested_delay)))?,
            false => (options, None),
        };

        let (rest, destination) = match (flags >> 5) & 1 == 1 {
            true => Destination::parse_frame(rest)
                .map(|(rest, destination)| (rest, Some(destination)))?,
            false => (rest, None),
        };

        let (rest, max_packet_size) = match (flags >> 7) & 1 == 1 {
            true => be_u16(options).map(|(rest, max_packet_size)| (rest, Some(max_packet_size)))?,
            false => (options, None),
        };

        let (rest, offline_signature) = match (flags >> 11) & 1 == 1 {
            true => todo!("offline signatures not supported"),
            false => (rest, None),
        };

        let (rest, signature) = match (flags >> 3) & 1 == 1 {
            true => take(64usize)(rest).map(|(rest, signature)| (rest, Some(signature)))?,
            false => (rest, None),
        };

        Ok((
            rest,
            Flags {
                destination,
                flags,
                max_packet_size,
                offline_signature,
                requested_delay,
                signature,
            },
        ))
    }

    /// Has `SYNCHRONIZE` flag been sent.
    pub fn synchronize(&self) -> bool {
        self.flags & 1 == 1
    }

    /// Has `CLOSE` flag been set.
    pub fn close(&self) -> bool {
        (self.flags >> 1) & 1 == 1
    }

    /// Has `RESET` flag been set.
    pub fn reset(&self) -> bool {
        (self.flags >> 2) & 1 == 1
    }

    /// Get included signature, if received.
    pub fn signature(&self) -> Option<&'a [u8]> {
        self.signature
    }

    /// Get included `Destination`, if received.
    pub fn from_included(&self) -> &Option<Destination> {
        &self.destination
    }

    /// Get requested delay, if received.
    pub fn delay_requested(&self) -> Option<u16> {
        self.requested_delay
    }

    /// Get maximum packet size, if received.
    pub fn max_packet_size(&self) -> Option<u16> {
        self.max_packet_size
    }

    /// Has `ECHO` flag been sent.
    pub fn echo(&self) -> bool {
        (self.flags >> 9) & 1 == 1
    }

    /// Has `NO_ACK` flag been sent.
    pub fn no_ack(&self) -> bool {
        (self.flags >> 10) & 1 == 1
    }

    /// Get included offline signature, if received.
    pub fn offline_signature(&self) -> Option<&'a [u8]> {
        self.offline_signature
    }
}

impl<'a> fmt::Debug for Flags<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Flags").field("flags", &self.flags).finish()
    }
}

/// Streaming protocol packet.
pub struct Packet<'a> {
    /// Send stream ID.
    pub send_stream_id: u32,

    /// Receive stream ID.
    pub recv_stream_id: u32,

    /// Sequence number of the packet.
    pub seq_nro: u32,

    /// ACK through bytes.
    pub ack_through: u32,

    /// Negative ACKs.
    pub nacks: Vec<u32>,

    /// Resend delay.
    pub resend_delay: u8,

    /// Flags.
    pub flags: Flags<'a>,

    /// Payload.
    pub payload: &'a [u8],
}

impl<'a> fmt::Debug for Packet<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let test = str::from_utf8(self.payload).unwrap_or("falure");

        f.debug_struct("Packet")
            .field("send_stream_id", &self.send_stream_id)
            .field("recv_stream_id", &self.recv_stream_id)
            .field("seq_nro", &self.seq_nro)
            .field("ack_through", &self.ack_through)
            .field("nacks", &self.nacks)
            .field("resend_delay", &self.resend_delay)
            .field("flags", &self.flags)
            .field("payload", &test)
            .finish()
    }
}

impl<'a> Packet<'a> {
    /// Attempt to parse [`Packet`] from `input`.
    ///
    /// Returns the parsed message and rest of `input` on success.
    fn parse_frame(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (rest, send_stream_id) = be_u32(input)?;
        let (rest, recv_stream_id) = be_u32(rest)?;
        let (rest, seq_nro) = be_u32(rest)?;
        let (rest, ack_through) = be_u32(rest)?;
        let (rest, nack_count) = be_u8(rest)?;
        let (rest, nacks) = (0..nack_count)
            .try_fold((rest, Vec::new()), |(rest, mut nacks), _| {
                be_u32::<_, ()>(rest).ok().map(|(rest, nack)| {
                    nacks.push(nack);

                    (rest, nacks)
                })
            })
            .ok_or_else(|| {
                tracing::warn!(
                    target: LOG_TARGET,
                    "failed to parse nack list",
                );

                Err::Error(make_error(input, ErrorKind::Fail))
            })?;

        let (rest, resend_delay) = be_u8(rest)?;
        let (rest, flags) = be_u16(rest)?;
        let (rest, options_size) = be_u16(rest)?;
        let (rest, options) = take(options_size)(rest)?;
        let (rest, flags) = Flags::new(flags, options)?;

        Ok((
            &[],
            Self {
                send_stream_id,
                recv_stream_id,
                seq_nro,
                ack_through,
                nacks,
                resend_delay,
                flags,
                payload: rest,
            },
        ))
    }

    /// Attempt to parse `input` into [`Packet`].
    pub fn parse(input: &'a [u8]) -> Option<Self> {
        Some(Self::parse_frame(input).ok()?.1)
    }
}
