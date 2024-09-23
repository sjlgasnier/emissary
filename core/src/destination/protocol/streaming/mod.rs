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

use crate::{error::StreamingError, primitives::RouterIdentity, runtime::Runtime, Error};

use bytes::{BufMut, BytesMut};
use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u32, be_u8},
    Err, IResult,
};
use rand_core::RngCore;

use core::marker::PhantomData;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::protocol::streaming";

/// Streaming protocol packet.
struct Packet<'a> {
    /// Send stream ID.
    send_stream_id: u32,

    /// Receive stream ID.
    recv_stream_id: u32,

    /// Sequence number of the packet.
    seq_nro: u32,

    /// ACK through bytes.
    ack_through: u32,

    /// Negative ACKs.
    nacks: Vec<u32>,

    /// Resend delay.
    resend_delay: u8,

    /// Flags.
    flags: u16,

    /// Payload.
    payload: &'a [u8],
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

        tracing::info!(
            "option bytes = {}, flags = {flags}, rest size = {}",
            _options.len(),
            rest.len()
        );

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
    fn parse(input: &'a [u8]) -> Option<Self> {
        Some(Self::parse_frame(input).ok()?.1)
    }
}

/// Streaming protocol instance.
pub struct Stream<R: Runtime> {
    recv_stream_id: u32,
    send_stream_id: Option<u32>,
    seq_nro: u32,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> Stream<R> {
    pub fn new_outbound(destination: RouterIdentity) -> (Self, BytesMut) {
        let mut payload = "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\n\r\n".as_bytes();
        let mut out = BytesMut::with_capacity(payload.len() + 22 + destination.serialized_len());

        let recv_stream_id = R::rng().next_u32();
        let seq_nro = 0u32;

        out.put_u32(0u32); // send stream id
        out.put_u32(recv_stream_id);
        out.put_u32(seq_nro);
        out.put_u32(0u32); // ack through
        out.put_u8(0u8); // nack count

        // TODO: signature
        out.put_u8(10u8); // resend delay, in seconds
        out.put_u16(0x01 | 0x20); // flags: `SYN` + `FROM_INCLUDED`

        out.put_u16(destination.serialized_len() as u16);
        out.put_slice(&destination.serialize());
        out.put_slice(&payload);

        // out.put_u16(0x01 | 0x03 | 0x20); // flags: `SYN` + `SIGNATURE_INCLUDED` + `FROM_INCLUDED`

        tracing::error!(
            target: LOG_TARGET,
            destination = %destination.id(),
            ?recv_stream_id,
            "new outbound stream",
        );

        (
            Self {
                recv_stream_id,
                send_stream_id: None,
                seq_nro,
                _runtime: Default::default(),
            },
            out,
        )
    }

    /// Handle streaming protocol packet.
    ///
    /// Returns a serialized [`Packet`] if `payload` warrants sending a reply to remote.
    pub fn handle_packet(&mut self, payload: &[u8]) -> crate::Result<Option<Vec<u8>>> {
        let Packet {
            send_stream_id,
            recv_stream_id,
            seq_nro,
            ack_through,
            flags,
            payload,
            ..
        } = Packet::parse(payload).ok_or_else(|| {
            tracing::warn!(
                target: LOG_TARGET,
                recv_stream_id = ?self.recv_stream_id,
                "failed to parse streaming protocol packet",
            );

            Error::InvalidData
        })?;

        if self.recv_stream_id != send_stream_id {
            tracing::warn!(
                target: LOG_TARGET,
                recv_stream_id = ?self.recv_stream_id,
                ?send_stream_id,
                "stream id mismatch",
            );

            return Err(Error::Streaming(StreamingError::StreamIdMismatch(
                send_stream_id,
                self.recv_stream_id,
            )));
        }

        tracing::error!("recv stream id = {}", recv_stream_id);
        tracing::error!("send stream id = {}", send_stream_id);
        tracing::error!("payload = {:?}", core::str::from_utf8(payload));

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{mock::MockRuntime, Runtime};

    #[test]
    fn stream_id_mismatch() {
        let destination = RouterIdentity::from_keys(vec![0u8; 32], vec![1u8; 32]).unwrap();
        let (mut stream, _payload) = Stream::<MockRuntime>::new_outbound(destination.clone());
        let payload = "hello, world".as_bytes();

        let mut out = BytesMut::with_capacity(payload.len() + 22 + destination.serialized_len());

        let recv_stream_id = MockRuntime::rng().next_u32();
        let seq_nro = 0u32;

        out.put_u32(stream.recv_stream_id.overflowing_add(1).0);
        out.put_u32(recv_stream_id);
        out.put_u32(seq_nro);
        out.put_u32(0u32); // ack through
        out.put_u8(0u8); // nack count

        out.put_u8(10u8); // resend delay, in seconds
        out.put_u16(0x01 | 0x20); // flags: `SYN` + `FROM_INCLUDED`

        out.put_u16(destination.serialized_len() as u16);
        out.put_slice(&destination.serialize());
        out.put_slice(&payload);

        match stream.handle_packet(out.as_ref()).unwrap_err() {
            Error::Streaming(StreamingError::StreamIdMismatch(send, recv)) => {
                assert_eq!(send, stream.recv_stream_id.overflowing_add(1).0);
                assert_eq!(recv, stream.recv_stream_id);
            }
            _ => panic!("invalid error"),
        }
    }
}
