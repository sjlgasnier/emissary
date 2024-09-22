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
    crypto::{EphemeralPublicKey, StaticPublicKey},
    primitives::{RouterId, RouterInfo, TunnelId},
};

use bytes::{BufMut, BytesMut};
use hashbrown::HashSet;
use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u32, be_u8},
    Err, IResult,
};

use alloc::vec::Vec;

/// New session message.
pub enum NewSession {
    /// New binding session.
    Binding {
        /// Ephemeral public key of the destination.
        ephemeral_key: EphemeralPublicKey,

        /// Static public key of the sender.
        static_key: StaticPublicKey,

        /// Payload.
        payload: (),
    },

    /// New non-binding session.
    NonBinding {
        /// Ephemeral public key of the destination.
        ephemeral_key: EphemeralPublicKey,

        /// Payload.
        payload: (),
    },

    /// One-time message without binding or session.
    OneTime {
        /// Ephemeral public key of the destination.
        ephemeral_key: EphemeralPublicKey,

        /// Payload.
        payload: (),
    },
}

impl NewSession {
    /// Attempt to parse [`NewSession`] from `input`.
    ///
    /// Returns the parsed message and rest of `input` on success.
    //
    // TODO: should this take `KeyManager` as input?
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], Self> {
        let (rest, ephemeral_key) = take(32usize)(input)?;
        let (rest, static_key) = take(32usize)(rest)?;

        // TODO: derive keys and decrypt?

        todo!();
    }
}
