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
    destination::protocol::streaming::packet::Packet, error::StreamingError,
    primitives::Destination as Dest, runtime::Runtime, Error,
};

use bytes::{BufMut, BytesMut};
use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u32, be_u8},
    Err, IResult,
};
use rand_core::RngCore;

use alloc::vec::Vec;
use core::marker::PhantomData;

mod packet;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::protocol::streaming";

/// Stream state.
enum StreamState {
    /// Outbound stream has been initiated.
    OutboundInitiated {
        /// Receive stream ID.
        recv_stream_id: u32,

        /// Sequence number.
        seq_nro: u32,
    },

    /// Stream is open.
    Open {
        /// Receive stream ID.
        recv_stream_id: u32,

        /// Send stream ID.
        send_stream_id: u32,

        /// Sequence number.
        seq_nro: u32,
    },
}

impl StreamState {
    /// Get receive stream ID.
    fn recv_stream_id(&self) -> u32 {
        match self {
            Self::OutboundInitiated { recv_stream_id, .. } => *recv_stream_id,
            Self::Open { recv_stream_id, .. } => *recv_stream_id,
        }
    }
}

/// Streaming protocol instance.
pub struct Stream<R: Runtime> {
    /// Stream state.
    state: StreamState,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> Stream<R> {
    /// Create new outbound [`Stream`].
    pub fn new_outbound(destination: Dest) -> (Self, BytesMut) {
        let mut payload = "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\n\r\n".as_bytes();
        let mut out = BytesMut::with_capacity(payload.len() + 22 + Dest::serialized_len());

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

        out.put_u16(Dest::serialized_len() as u16);
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
                state: StreamState::OutboundInitiated {
                    recv_stream_id,
                    seq_nro,
                },
                _runtime: Default::default(),
            },
            out,
        )
    }

    /// Handle streaming protocol packet.
    ///
    /// Returns a serialized [`Packet`] if `payload` warrants sending a reply to remote.
    //
    // TODO: return bytesmut
    pub fn handle_packet(&mut self, payload: &[u8]) -> crate::Result<Option<Vec<u8>>> {
        let Packet {
            send_stream_id,
            recv_stream_id,
            seq_nro,
            ack_through,
            flags,
            payload,
            nacks,
            ..
        } = Packet::parse(payload).ok_or_else(|| {
            tracing::warn!(
                target: LOG_TARGET,
                recv_stream_id = ?self.state.recv_stream_id(),
                "failed to parse streaming protocol packet",
            );

            Error::InvalidData
        })?;

        if self.state.recv_stream_id() != send_stream_id {
            tracing::warn!(
                target: LOG_TARGET,
                recv_stream_id = ?self.state.recv_stream_id(),
                ?send_stream_id,
                "stream id mismatch",
            );

            return Err(Error::Streaming(StreamingError::StreamIdMismatch(
                send_stream_id,
                self.state.recv_stream_id(),
            )));
        }

        tracing::info!("ack received = {ack_through}, sequence number = {seq_nro:}");
        tracing::error!("payload = {:?}", core::str::from_utf8(payload));

        if (flags & 0x02) == 0x02 {
            tracing::info!("stream closed");
            return Ok(None);
        }

        let mut out = BytesMut::with_capacity(22);

        out.put_u32(recv_stream_id); // send stream id
        out.put_u32(self.state.recv_stream_id());
        out.put_u32(0);
        out.put_u32(seq_nro); // ack through
        out.put_u8(0u8); // nack count

        out.put_u8(10u8); // resend delay, in seconds
        out.put_u16(0); // no flags

        self.state = StreamState::Open {
            recv_stream_id: self.state.recv_stream_id(),
            send_stream_id: recv_stream_id,
            seq_nro: 1,
        };

        Ok(Some(out.freeze().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{SigningPrivateKey, SigningPublicKey},
        runtime::{mock::MockRuntime, Runtime},
    };

    #[test]
    fn stream_id_mismatch() {
        let destination =
            Dest::new(SigningPublicKey::from_private_ed25519(&vec![1u8; 32]).unwrap());
        let (mut stream, _payload) = Stream::<MockRuntime>::new_outbound(destination.clone());
        let payload = "hello, world".as_bytes();

        let mut out = BytesMut::with_capacity(payload.len() + 22 + Dest::serialized_len());

        let recv_stream_id = MockRuntime::rng().next_u32();
        let seq_nro = 0u32;

        out.put_u32(stream.state.recv_stream_id().overflowing_add(1).0);
        out.put_u32(recv_stream_id);
        out.put_u32(seq_nro);
        out.put_u32(0u32); // ack through
        out.put_u8(0u8); // nack count

        out.put_u8(10u8); // resend delay, in seconds
        out.put_u16(0x01 | 0x20); // flags: `SYN` + `FROM_INCLUDED`

        out.put_u16(Dest::serialized_len() as u16);
        out.put_slice(&destination.serialize());
        out.put_slice(&payload);

        match stream.handle_packet(out.as_ref()).unwrap_err() {
            Error::Streaming(StreamingError::StreamIdMismatch(send, recv)) => {
                assert_eq!(send, stream.state.recv_stream_id().overflowing_add(1).0);
                assert_eq!(recv, stream.state.recv_stream_id());
            }
            _ => panic!("invalid error"),
        }
    }
}
