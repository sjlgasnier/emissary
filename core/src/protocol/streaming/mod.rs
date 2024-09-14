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

use crate::{primitives::RouterIdentity, runtime::Runtime};

use bytes::{BufMut, BytesMut};
use rand_core::RngCore;

use core::marker::PhantomData;

pub struct Stream<R: Runtime> {
    recv_stream_id: u32,
    send_stream_id: Option<u32>,
    seq_nro: u32,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> Stream<R> {
    pub fn new_outbound(destination: RouterIdentity) -> (Self, BytesMut) {
        let mut payload = "GET / HTTP/1.1\r\n\n".as_bytes();
        let mut out = BytesMut::with_capacity(payload.len() + 22);

        let recv_stream_id = R::rng().next_u32();
        let seq_nro = 0u32;

        out.put_u32(0u32); // send stream id
        out.put_u32(recv_stream_id);
        out.put_u32(seq_nro);
        out.put_u32(0u32); // ack through
        out.put_u8(0u8); // nack count

        // TODO: signature
        out.put_u8(10u8); // resend delay, in seconds
        out.put_u16(0x1 | 0x20); // flags: `SYN` + `FROM_INCLUDED`

        out.put_u16(destination.serialized_len() as u16);
        out.put_slice(&destination.serialize());
        out.put_slice(&payload);

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
}
