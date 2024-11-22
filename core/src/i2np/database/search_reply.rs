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
    i2np::{database::DATABASE_KEY_SIZE, LOG_TARGET, ROUTER_HASH_LEN},
    primitives::RouterId,
};

use bytes::{Bytes, BytesMut};
use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::be_u8,
    Err, IResult,
};

use alloc::vec::Vec;

/// Database search reply.
pub struct DatabaseSearchReply {
    /// Search key.
    pub key: Bytes,

    /// Router IDs.
    pub routers: Vec<RouterId>,
}

impl DatabaseSearchReply {
    /// Attempt to parse [`DatabaseSearchReply`] from `input`.
    ///
    /// Returns the parsed message and rest of `input` on success.
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], Self> {
        let (rest, key) = take(DATABASE_KEY_SIZE)(input)?;
        let (rest, num_hashes) = be_u8(rest)?;
        let (rest, routers) = (0..num_hashes)
            .try_fold((rest, Vec::new()), |(rest, mut hashes), _| {
                take::<usize, &[u8], ()>(ROUTER_HASH_LEN)(rest).ok().map(|(rest, router)| {
                    hashes.push(RouterId::from(router));

                    (rest, hashes)
                })
            })
            .ok_or_else(|| {
                tracing::warn!(
                    target: LOG_TARGET,
                    "failed to parse search reply hash list",
                );

                Err::Error(make_error(input, ErrorKind::Fail))
            })?;

        // `from` field is not needed
        let (rest, _from) = take(ROUTER_HASH_LEN)(rest)?;

        Ok((
            rest,
            Self {
                key: BytesMut::from(key).freeze(),
                routers,
            },
        ))
    }

    /// Attempt to parse `input` into [`DatabaseSearchReply`].
    pub fn parse(input: &[u8]) -> Option<Self> {
        Self::parse_frame(input).ok().map(|(_, message)| message)
    }
}
