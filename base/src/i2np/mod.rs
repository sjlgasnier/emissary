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

//! I2NP message parser
//!
//! https://geti2p.net/spec/i2np

use alloc::vec::Vec;

/// Message type.
enum MessageType {
    DatabaseStore,
    DatabaseLookup,
    DatabaseSearchReply,
    DeliveryStatus,
    Garlic,
    TunnelData,
    TunnelGateway,
    Data,
    TunnelBuild,
    TunnelBuildReply,
    VariableTunnelBuild,
    VariableTunnelBuildReply,
    ShortTunnelBuild,
    OutboundTunnelBuildReply,
}

impl MessageType {
    /// Serialize [`MessageType`].
    fn serialize(&self) -> u8 {
        match self {
            Self::DatabaseStore => 1,
            Self::DatabaseLookup => 2,
            Self::DatabaseSearchReply => 3,
            Self::DeliveryStatus => 10,
            Self::Garlic => 11,
            Self::TunnelData => 18,
            Self::TunnelGateway => 19,
            Self::Data => 20,
            Self::TunnelBuild => 21,
            Self::TunnelBuildReply => 22,
            Self::VariableTunnelBuild => 23,
            Self::VariableTunnelBuildReply => 24,
            Self::ShortTunnelBuild => 25,
            Self::OutboundTunnelBuildReply => 26,
        }
    }
}

/// Tunnel build
pub struct TunnelBuildRecord<'a> {
    tunnel_id: u32,
    next_tunnel_id: u32,
    next_router_hash: &'a [u8],
    tunnel_layer_key: &'a [u8],
    tunnel_iv_key: &'a [u8],
    tunnel_reply_key: &'a [u8],
    tunnel_reply_iv: &'a [u8],
    flags: u8,
    reserved: [u8; 3],
    request_time: u32,
    request_expiration: u32,
    next_message_id: u32,
    rest: &'a [u8],
}

pub struct ShortTunnelBuildRecord<'a> {
    /// Data.
    data: &'a [u8],
}

pub struct OutboundTunnelBuildReply<'a> {
    /// Data.
    data: &'a [u8],
}

// Tunneling-related message.
pub enum TunnelMessage<'a> {
    /// Tunnel message.
    Message {
        /// Tunnel ID.
        tunnel_id: u32,

        /// Data.
        data: &'a [u8],
    },

    /// Tunnel gateway.
    Gateway {
        /// Tunnel ID.
        tunnel_id: u32,

        /// Data.
        data: &'a [u8],
    },

    /// Tunnel build message, fixed to 8 records.
    BuildRequest {
        /// Build records.
        records: [TunnelBuildRecord<'a>; 8],
    },

    /// Variable tunnel build message.
    VariableBuildRequest {
        /// Build records.
        records: Vec<TunnelBuildRecord<'a>>,
    },

    /// Tunne build reply.
    BuildReply {
        /// Reply byte (accept/reject).
        reply: u8,
    },

    /// Short tunnel build request.
    ShortBuildRequest {
        /// Records.
        records: Vec<ShortTunnelBuildRecord<'a>>,
    },

    /// Outbound tunnel build reply.
    OutboundBuildReply {
        /// Records.
        records: Vec<OutboundTunnelBuildReply<'a>>,
    },
}

/// NetDB-related message.
pub enum DatabaseMessage<'a> {
    /// Database store request.
    Store {
        /// SHA256 hash of the key.
        key: &'a [u8],

        /// Store type.
        store_type: u8,

        /// Reply token.
        token: Option<u32>,

        /// Reply tunnel ID.
        tunnel_id: Option<u32>,

        /// SHA256 of the gateway `RouterInfo`
        gateway: Option<&'a [u8]>,

        /// Data.
        data: &'a [u8],
    },

    /// Database search request.
    Request {
        /// SHA256 hash of the key to look up.
        key: &'a [u8],

        /// SHA256 hash of the `RouterInfo` who is asking
        /// or the gateway where to send the reply.
        origin: &'a [u8],

        /// Flag
        flag: u8,

        /// Reply tunnel ID.
        tunnel_id: u32,

        /// Count of peer hashes to ignore
        exclude_size: u16,

        /// Peers to ignore.
        exclude: Vec<&'a [u8]>,

        /// Reply key.
        reply_key: &'a [u8],

        /// Size of reply tags.
        tags_size: u8,

        /// Reply tags.
        tags: &'a [u8],
    },

    /// Database search reply
    Reply {
        /// SHA256 hash of the key that was looked up.
        key: &'a [u8],

        /// Peer hashes.
        peers: Vec<&'a [u8]>,

        // SHA256 of the `RouterInfo` this reply was sent from.
        from: &'a [u8],
    },
}
