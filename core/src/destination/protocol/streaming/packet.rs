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

use crate::destination::protocol::streaming::LOG_TARGET;

use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u32, be_u8},
    Err, IResult,
};

use alloc::vec::Vec;

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
    pub flags: u16,

    /// Payload.
    pub payload: &'a [u8],
}

impl<'a> core::fmt::Debug for Packet<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let test = core::str::from_utf8(self.payload).unwrap_or("falure");

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
    fn parse_frame(input: &'a [u8]) -> IResult<&[u8], Self> {
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
        let (rest, _options) = take(options_size)(rest)?;

        // TODO: parse options

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
