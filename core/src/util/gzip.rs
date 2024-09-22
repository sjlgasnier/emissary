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

use crate::runtime::Runtime;

use alloc::vec::Vec;
use core::marker::PhantomData;

/// Gzip-encoder builder.
///
/// Compresses the payload and modifies the gzip header to contains I2CP protocol fields.
pub struct GzipEncoderBuilder<'a, R: Runtime> {
    /// Destination port.
    dst_port: Option<u16>,

    /// Payload.
    payload: &'a [u8],

    /// Protocol.
    protocol: Option<u8>,

    /// Source port.
    src_port: Option<u16>,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<'a, R: Runtime> GzipEncoderBuilder<'a, R> {
    /// Create new [`GzipEncoderBuilder`].
    pub fn new(payload: &'a [u8]) -> Self {
        Self {
            dst_port: None,
            payload,
            protocol: None,
            src_port: None,
            _runtime: Default::default(),
        }
    }

    /// Specify source port.
    pub fn with_source_port(mut self, src_port: u16) -> Self {
        self.src_port = Some(src_port);
        self
    }

    /// Specify destination port.
    pub fn with_destination_port(mut self, dst_port: u16) -> Self {
        self.dst_port = Some(dst_port);
        self
    }

    /// Specify protocol.
    pub fn with_protocol(mut self, protocol: u8) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Compress payload and modify the gzip
    ///
    /// All fields are expected to exist.
    pub fn build(mut self) -> Option<Vec<u8>> {
        let protocol = self.protocol.take().expect("protocol to exist");
        let dst_port = self.dst_port.take().expect("destination port to exist");
        let src_port = self.src_port.take().expect("source port to exist");

        R::gzip_compress(self.payload).map(|mut compressed| {
            compressed[4..6].copy_from_slice(&src_port.to_be_bytes());
            compressed[6..8].copy_from_slice(&dst_port.to_be_bytes());
            compressed[9] = protocol;

            compressed
        })
    }
}

/// Gzip decompressor.
///
/// Decompresses the payload and extracts I2CP-related fields from header.
pub struct GzipPayload {
    /// Destination port.
    pub dst_port: u16,

    /// Decompressed payload.
    pub payload: Vec<u8>,

    /// Protocol.
    pub protocol: u8,

    /// Source port.
    pub src_port: u16,
}

impl GzipPayload {
    /// Extract I2CP-related fields from gzip header and decompress `payload`.
    pub fn decompress<R: Runtime>(payload: impl AsRef<[u8]>) -> Option<Self> {
        if payload.as_ref().len() < 10 {
            return None;
        }

        // `TryInto::try_into()` must succeed as `payload` is guaranteed to have enough bytes
        // and slices taken of the payload are of correct size for a `u16`
        let src_port = TryInto::<[u8; 2]>::try_into(&payload.as_ref()[4..6]).expect("to succeed");
        let dst_port = TryInto::<[u8; 2]>::try_into(&payload.as_ref()[6..8]).expect("to succeed");
        let protocol = payload.as_ref()[9];

        Some(Self {
            src_port: u16::from_be_bytes(src_port),
            dst_port: u16::from_be_bytes(dst_port),
            protocol,
            payload: R::gzip_decompress(&payload)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{mock::MockRuntime, Runtime};
    use curve25519_elligator2::edwards::CompressedEdwardsY;

    #[test]
    fn compress_and_decompress() {
        let payload = "hello, world".as_bytes();

        let compressed = GzipEncoderBuilder::<MockRuntime>::new(&payload)
            .with_source_port(13)
            .with_destination_port(37)
            .with_protocol(6)
            .build()
            .unwrap();

        // normal compression works
        let decompressed = MockRuntime::gzip_decompress(&compressed).unwrap();
        assert_eq!(decompressed, "hello, world".as_bytes());

        // extracing i2cp data + decompression works
        let Some(GzipPayload {
            dst_port,
            payload,
            protocol,
            src_port,
        }) = GzipPayload::decompress::<MockRuntime>(&compressed)
        else {
            panic!("invalid data");
        };

        assert_eq!(dst_port, 37);
        assert_eq!(src_port, 13);
        assert_eq!(protocol, 6);
        assert_eq!(payload, "hello, world".as_bytes());
    }
}
