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
    primitives::{RouterId, RouterInfo, TunnelId},
};

use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u32, be_u8},
    Err, IResult,
};
use zune_inflate::DeflateDecoder;

use alloc::vec::Vec;

/// "No reply" token/tunnel ID.
const NO_REPLY: u32 = 0u32;

#[derive(Debug)]
enum StoreType {
    /// Router info.
    RouterInfo,

    /// Lease set.
    LeaseSet,

    /// Lease set, type 2.
    LeaseSet2,

    /// Encrypted lease set.
    EncryptedLeaseSet,

    /// Meta lease set.
    MetaLeaseSet,
}

impl StoreType {
    /// Try to convert `store_type` into `StoreType`.
    fn from_u8(store_type: u8) -> Option<Self> {
        match store_type & 1 {
            0 => Some(Self::RouterInfo),
            _ => match (store_type >> 1) & 0x7 {
                0 => Some(Self::LeaseSet),
                1 => Some(Self::LeaseSet2),
                2 => Some(Self::EncryptedLeaseSet),
                3 => Some(Self::MetaLeaseSet),
                _ => None,
            },
        }
    }
}

/// Reply type.
enum ReplyType {
    /// Reply should be sent to tunnel.
    Tunnel {
        /// Reply token.
        reply_token: u32,

        /// ID of the gateway tunnel.
        tunnel_id: TunnelId,

        /// Router ID of the gateway tunnel.
        router_id: RouterId,
    },

    /// Reply should be sent to router.
    Router {
        /// Reply token.
        reply_token: u32,

        /// Router ID of the gateway tunnel.
        router_id: RouterId,
    },

    /// No reply required.
    None,
}

/// Payload contained within the `DatabaseStore` message.
pub enum DatabaseStorePayload {
    /// Router info.
    RouterInfo {
        /// Router info.
        router_info: RouterInfo,
    },
}

/// Database store message.
pub struct DatabaseStore {
    /// Search key.
    key: Vec<u8>,

    /// Payload contained within the `DatabaseStore` message.
    payload: DatabaseStorePayload,

    /// Reply type.
    reply: ReplyType,
}

impl DatabaseStore {
    /// Attempt to parse [`DatabaseStore`] from `input`.
    ///
    /// Returns the parsed message and rest of `input` on success.
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], Self> {
        let (rest, key) = take(DATABASE_KEY_SIZE)(input)?;
        let (rest, store_type) = be_u8(rest)?;
        let (rest, reply_token) = be_u32(rest)?;
        let store_type = StoreType::from_u8(store_type)
            .ok_or_else(|| Err::Error(make_error(input, ErrorKind::Fail)))?;

        let (rest, reply) = match reply_token == NO_REPLY {
            true => (rest, ReplyType::None),
            false => {
                let (rest, gateway_tunnel) = be_u32(rest)?;
                let (rest, gateway_router) = take(ROUTER_HASH_LEN)(rest)?;

                match gateway_tunnel == NO_REPLY {
                    true => (
                        rest,
                        ReplyType::Router {
                            reply_token,
                            router_id: RouterId::from(gateway_router),
                        },
                    ),
                    false => (
                        rest,
                        ReplyType::Tunnel {
                            reply_token,
                            tunnel_id: TunnelId::from(gateway_tunnel),
                            router_id: RouterId::from(gateway_router),
                        },
                    ),
                }
            }
        };

        match store_type {
            StoreType::RouterInfo => {
                let (rest, size) = be_u16(rest)?;
                let (rest, data) = take(size)(rest)?;

                let mut decoder = DeflateDecoder::new(&data);
                let data = decoder.decode_gzip().map_err(|error| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to decompress gzip",
                    );

                    Err::Error(make_error(input, ErrorKind::Fail))
                })?;

                let router_info = RouterInfo::from_bytes(&data).ok_or_else(|| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "failed to parse gzipped router info",
                    );

                    Err::Error(make_error(input, ErrorKind::Fail))
                })?;

                Ok((
                    rest,
                    Self {
                        key: key.to_vec(),
                        payload: DatabaseStorePayload::RouterInfo { router_info },
                        reply,
                    },
                ))
            }
            _ => todo!(),
        }
    }

    /// Attempt to parse `input` into [`DatabaseStore`].
    pub fn parse(input: &[u8]) -> Option<Self> {
        Self::parse_frame(input).ok().map(|(_, message)| message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_database_store() {
        let buffer = vec![
            249, 0, 187, 182, 11, 128, 61, 16, 80, 73, 190, 216, 57, 137, 166, 213, 35, 195, 36,
            79, 56, 118, 161, 49, 37, 5, 174, 148, 94, 114, 242, 7, 0, 101, 5, 15, 45, 0, 0, 0, 0,
            249, 0, 187, 182, 11, 128, 61, 16, 80, 73, 190, 216, 57, 137, 166, 213, 35, 195, 36,
            79, 56, 118, 161, 49, 37, 5, 174, 148, 94, 114, 242, 7, 2, 151, 31, 139, 8, 0, 0, 0, 0,
            0, 2, 255, 1, 128, 2, 127, 253, 222, 205, 6, 59, 50, 200, 120, 177, 26, 105, 6, 11, 22,
            247, 62, 125, 94, 166, 157, 159, 205, 26, 68, 197, 126, 246, 167, 208, 34, 44, 152, 53,
            156, 157, 71, 229, 212, 169, 64, 66, 197, 83, 19, 226, 150, 36, 242, 255, 56, 236, 227,
            27, 83, 149, 94, 207, 146, 177, 76, 222, 163, 237, 79, 111, 156, 157, 71, 229, 212,
            169, 64, 66, 197, 83, 19, 226, 150, 36, 242, 255, 56, 236, 227, 27, 83, 149, 94, 207,
            146, 177, 76, 222, 163, 237, 79, 111, 156, 157, 71, 229, 212, 169, 64, 66, 197, 83, 19,
            226, 150, 36, 242, 255, 56, 236, 227, 27, 83, 149, 94, 207, 146, 177, 76, 222, 163,
            237, 79, 111, 156, 157, 71, 229, 212, 169, 64, 66, 197, 83, 19, 226, 150, 36, 242, 255,
            56, 236, 227, 27, 83, 149, 94, 207, 146, 177, 76, 222, 163, 237, 79, 111, 156, 157, 71,
            229, 212, 169, 64, 66, 197, 83, 19, 226, 150, 36, 242, 255, 56, 236, 227, 27, 83, 149,
            94, 207, 146, 177, 76, 222, 163, 237, 79, 111, 156, 157, 71, 229, 212, 169, 64, 66,
            197, 83, 19, 226, 150, 36, 242, 255, 56, 236, 227, 27, 83, 149, 94, 207, 146, 177, 76,
            222, 163, 237, 79, 111, 156, 157, 71, 229, 212, 169, 64, 66, 197, 83, 19, 226, 150, 36,
            242, 255, 56, 236, 227, 27, 83, 149, 94, 207, 146, 177, 76, 222, 163, 237, 79, 111,
            156, 157, 71, 229, 212, 169, 64, 66, 197, 83, 19, 226, 150, 36, 242, 255, 56, 236, 227,
            27, 83, 149, 94, 207, 146, 177, 76, 222, 163, 237, 79, 111, 156, 157, 71, 229, 212,
            169, 64, 66, 197, 83, 19, 226, 150, 36, 242, 255, 56, 236, 227, 27, 83, 149, 94, 207,
            146, 177, 76, 222, 163, 237, 79, 111, 156, 157, 71, 229, 212, 169, 64, 66, 197, 83, 19,
            226, 150, 36, 242, 255, 56, 236, 227, 27, 83, 149, 94, 207, 146, 177, 76, 222, 163,
            237, 79, 111, 193, 118, 156, 13, 187, 24, 148, 135, 201, 57, 162, 146, 109, 209, 194,
            238, 49, 30, 8, 187, 55, 61, 104, 151, 23, 241, 84, 73, 35, 18, 228, 159, 5, 0, 4, 0,
            7, 0, 4, 0, 0, 1, 145, 153, 163, 42, 152, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 5, 78, 84, 67,
            80, 50, 0, 113, 4, 104, 111, 115, 116, 61, 9, 49, 50, 55, 46, 48, 46, 48, 46, 49, 59,
            1, 105, 61, 24, 77, 117, 115, 99, 83, 117, 67, 90, 106, 105, 57, 108, 72, 113, 102, 73,
            56, 121, 74, 73, 56, 103, 61, 61, 59, 4, 112, 111, 114, 116, 61, 4, 56, 56, 57, 48, 59,
            1, 115, 61, 44, 101, 49, 65, 97, 74, 80, 67, 126, 104, 80, 117, 80, 49, 54, 52, 80, 71,
            105, 71, 107, 97, 105, 52, 50, 119, 80, 55, 110, 89, 70, 117, 111, 56, 121, 74, 115,
            76, 119, 76, 77, 48, 106, 77, 61, 59, 1, 118, 61, 1, 50, 59, 0, 0, 43, 4, 99, 97, 112,
            115, 61, 1, 76, 59, 5, 110, 101, 116, 73, 100, 61, 1, 50, 59, 14, 114, 111, 117, 116,
            101, 114, 46, 118, 101, 114, 115, 105, 111, 110, 61, 6, 48, 46, 57, 46, 54, 50, 59,
            187, 28, 65, 149, 0, 49, 238, 139, 72, 152, 68, 124, 54, 114, 146, 48, 122, 88, 53, 97,
            92, 3, 49, 209, 233, 3, 27, 94, 50, 13, 78, 133, 155, 126, 53, 213, 174, 143, 152, 192,
            84, 122, 104, 147, 39, 185, 101, 38, 20, 216, 147, 187, 19, 47, 233, 162, 56, 58, 45,
            26, 246, 141, 69, 9, 132, 119, 99, 190, 128, 2, 0, 0,
        ];

        let _ = DatabaseStore::parse_frame(&buffer);
    }
}
