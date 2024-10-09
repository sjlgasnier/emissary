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
    primitives::{Date, Destination, Mapping, Str},
    tunnel::TunnelPoolConfig,
};

use hashbrown::HashMap;
use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u32, be_u8},
    Err, IResult,
};

use alloc::vec::Vec;
use core::time::Duration;

pub use bandwidth::BandwidthLimits;
pub use leaseset::RequestVariableLeaseSet;
pub use session_status::{SessionStatus, SessionStatusKind};
pub use set_date::SetDate;

mod bandwidth;
mod leaseset;
mod session_status;
mod set_date;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::i2cp::message";

/// I2CP header length.
///
/// Header is payload size (4 bytes) + message type (1 bytes).
pub const I2CP_HEADER_SIZE: usize = 5;

/// Session ID.
#[derive(Debug)]
pub enum SessionId {
    /// Session with iD.
    Session(u16),

    /// No session, special value `0xffff`;
    NoSession,
}

impl SessionId {
    /// Serialize [`SessionId`].
    pub fn as_u16(self) -> u16 {
        match self {
            Self::Session(session_id) => session_id,
            Self::NoSession => 0xffff,
        }
    }
}

impl From<u16> for SessionId {
    fn from(value: u16) -> Self {
        match value {
            0xffff => SessionId::NoSession,
            value => SessionId::Session(value),
        }
    }
}

/// Request kind for host lookups.
#[derive(Debug)]
pub enum RequestKind {
    /// Host name.
    HostName {
        /// Host name.
        host_name: Str,
    },

    /// Hash.
    Hash {
        /// SHA256 hash.
        hash: Vec<u8>,
    },
}

/// I2CP message type.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MessageType {
    /// Bandwidth limit
    BandwidthLimits,

    /// Binding info.
    BlindingInfo,

    /// Create `LeaseSet`.
    CreateLeaseSet,

    /// Create `LeaseSet2`.
    CreateLeaseSet2,

    /// Create session.
    CreateSession,

    /// Lookup destination.
    DestLookup,

    /// Destination lookup reply.
    DestReply,

    /// Destroy session.
    DestroySession,

    /// Disconnect connection.
    Disconnect,

    /// Get bandwidth limits.
    GetBandwidthLimits,

    /// Get date.
    GetDate,

    /// Lookup host.
    HostLookup,

    /// Host lookup reply.
    HostReply,

    /// Delivery payload of message to client.
    MessagePayload,

    /// Notify client of a delivery status.
    MessageStatus,

    /// Start reception of a message.
    ReceiveMessageBegin,

    /// Inform router that a message was delivered successfully.
    ReceiveMessageEnd,

    /// Reconfigure session.
    ReconfigureSession,

    /// Report abuse.
    ReportAbuse,

    /// Request `LeaseSet`.
    RequestLeaseSet,

    /// Request `VariableLeaseSet`.
    RequestVariableLeaseSet,

    /// Send message to remote router.
    SendMessage,

    /// Send message to remote router with expiration and options.
    SendMessageExpires,

    /// Inform client about the status of the session.
    SessionStatus,

    /// Set date.
    SetDate,
}

impl MessageType {
    /// Serialize [`MessageType`].
    pub fn as_u8(self) -> u8 {
        match self {
            Self::BandwidthLimits => 23,
            Self::BlindingInfo => 42,
            Self::CreateLeaseSet => 4,
            Self::CreateLeaseSet2 => 41,
            Self::CreateSession => 1,
            Self::DestLookup => 34,
            Self::DestReply => 35,
            Self::DestroySession => 3,
            Self::Disconnect => 30,
            Self::GetBandwidthLimits => 8,
            Self::GetDate => 32,
            Self::HostLookup => 38,
            Self::HostReply => 39,
            Self::MessagePayload => 31,
            Self::MessageStatus => 22,
            Self::ReceiveMessageBegin => 6,
            Self::ReceiveMessageEnd => 7,
            Self::ReconfigureSession => 2,
            Self::ReportAbuse => 29,
            Self::RequestLeaseSet => 21,
            Self::RequestVariableLeaseSet => 37,
            Self::SendMessage => 5,
            Self::SendMessageExpires => 36,
            Self::SessionStatus => 20,
            Self::SetDate => 33,
        }
    }

    /// Try to convert `msg_type` into `MessageType`.
    pub fn from_u8(msg_type: u8) -> Option<Self> {
        match msg_type {
            23 => Some(Self::BandwidthLimits),
            42 => Some(Self::BlindingInfo),
            4 => Some(Self::CreateLeaseSet),
            41 => Some(Self::CreateLeaseSet2),
            1 => Some(Self::CreateSession),
            34 => Some(Self::DestLookup),
            35 => Some(Self::DestReply),
            3 => Some(Self::DestroySession),
            30 => Some(Self::Disconnect),
            8 => Some(Self::GetBandwidthLimits),
            32 => Some(Self::GetDate),
            38 => Some(Self::HostLookup),
            39 => Some(Self::HostReply),
            31 => Some(Self::MessagePayload),
            22 => Some(Self::MessageStatus),
            6 => Some(Self::ReceiveMessageBegin),
            7 => Some(Self::ReceiveMessageEnd),
            2 => Some(Self::ReconfigureSession),
            29 => Some(Self::ReportAbuse),
            21 => Some(Self::RequestLeaseSet),
            37 => Some(Self::RequestVariableLeaseSet),
            5 => Some(Self::SendMessage),
            36 => Some(Self::SendMessageExpires),
            20 => Some(Self::SessionStatus),
            33 => Some(Self::SetDate),
            byte => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?byte,
                    "unknown i2cp message type",
                );
                None
            }
        }
    }
}

/// I2CP message.
pub enum Message {
    /// Bandwidth limit
    BandwidthLimits,

    /// Binding info.
    BlindingInfo,

    /// Create `LeaseSet`.
    CreateLeaseSet,

    /// Create `LeaseSet2`.
    CreateLeaseSet2,

    /// Create session.
    CreateSession {
        /// Destination.
        destination: Destination,

        /// Create date.
        date: Date,

        /// Session options.
        options: HashMap<Str, Str>,
    },

    /// Lookup destination.
    DestLookup,

    /// Destination lookup reply.
    DestReply,

    /// Destroy session.
    DestroySession {
        /// Session ID.
        session_id: SessionId,
    },

    /// Disconnect connection.
    Disconnect,

    /// Get bandwidth limits.
    GetBandwidthLimits,

    /// Get date.
    GetDate {
        /// I2CP version.
        version: Str,

        /// Options.
        options: Vec<Mapping>,
    },

    /// Lookup host.
    HostLookup {
        /// Session ID.
        session_id: SessionId,

        /// Request ID.
        request_id: u32,

        /// Timeout.
        timeout: Duration,

        /// Lookup kind.
        kind: RequestKind,
    },

    /// Host lookup reply.
    HostReply,

    /// Delivery payload of message to client.
    MessagePayload,

    /// Notify client of a delivery status.
    MessageStatus,

    /// Start reception of a message.
    ReceiveMessageBegin,

    /// Inform router that a message was delivered successfully.
    ReceiveMessageEnd,

    /// Reconfigure session.
    ReconfigureSession,

    /// Report abuse.
    ReportAbuse,

    /// Request `LeaseSet`.
    RequestLeaseSet,

    /// Request `VariableLeaseSet`.
    RequestVariableLeaseSet,

    /// Send message to remote router.
    SendMessage,

    /// Send message to remote router with expiration and options.
    SendMessageExpires,

    /// Inform client about the status of the session.
    SessionStatus,

    /// Set date.
    SetDate {
        /// Date.
        date: Date,

        /// Version.
        version: Str,
    },
}

impl Message {
    /// Attempt to parse [`Message::GetDate`] from `input`.
    ///
    /// https://geti2p.net/spec/i2cp#getdatemessage
    fn parse_get_date(input: impl AsRef<[u8]>) -> Option<Self> {
        let (rest, version) = Str::parse_frame(input.as_ref()).ok()?;
        let (rest, options) = Mapping::parse_multi_frame(rest).ok()?;

        debug_assert!(rest.is_empty());

        Some(Message::GetDate { version, options })
    }

    /// Attempt to parse [`Message::SetDate`] from `input`.
    ///
    /// https://geti2p.net/spec/i2cp#setdatemessage
    fn parse_set_date(input: impl AsRef<[u8]>) -> Option<Self> {
        let (rest, date) = Date::parse_frame(input.as_ref()).ok()?;
        let (rest, version) = Str::parse_frame(rest).ok()?;

        debug_assert!(rest.is_empty());

        Some(Message::SetDate { date, version })
    }

    /// Attempt to parse [`Message::GetBandwidthLimits`] from `input`.
    ///
    /// https://geti2p.net/spec/i2cp#getbandwidthlimitsmessage
    fn parse_get_bandwidth_limits(input: impl AsRef<[u8]>) -> Option<Self> {
        debug_assert!(input.as_ref().is_empty());

        Some(Message::GetBandwidthLimits)
    }

    /// Attempt to parse [`Message::DestroySession`] from `input`.
    ///
    /// https://geti2p.net/spec/i2cp#destroysessionmessage
    fn parse_destroy_session(input: impl AsRef<[u8]>) -> Option<Self> {
        let (rest, session_id) = be_u16::<_, ()>(input.as_ref()).ok()?;

        debug_assert!(rest.is_empty());

        Some(Message::DestroySession {
            session_id: SessionId::from(session_id),
        })
    }

    /// Attempt to parse [`Message::CreateSession`] from `input`.
    ///
    /// https://geti2p.net/spec/i2cp#createsessionmessage
    fn parse_create_session(input: impl AsRef<[u8]>) -> Option<Self> {
        let (rest, destination) = Destination::parse_frame(input.as_ref()).ok()?;
        let (rest, options) = Mapping::parse_multi_frame(rest).ok()?;
        let (rest, date) = Date::parse_frame(rest).ok()?;
        let (rest, signature) = take::<_, _, ()>(64usize)(rest).ok()?;

        if let Err(error) = destination.signing_key().verify(input.as_ref(), signature) {
            tracing::warn!(
                target: LOG_TARGET,
                ?error,
                "failed to verify `CreateSession` signature",
            );

            return None;
        }

        Some(Message::CreateSession {
            destination,
            date,
            options: Mapping::into_hashmap(options),
        })
    }

    /// Attempt to parse [`Message::HostLookup`] from `input`.
    ///
    /// https://geti2p.net/spec/i2cp#hostlookupmessage
    fn parse_host_lookup(input: impl AsRef<[u8]>) -> Option<Self> {
        let (rest, session_id) = be_u16::<_, ()>(input.as_ref()).ok()?;
        let (rest, request_id) = be_u32::<_, ()>(rest).ok()?;
        let (rest, timeout) = be_u32::<_, ()>(rest).ok()?;
        let (rest, kind) = be_u8::<_, ()>(rest).ok()?;

        let kind = match kind {
            0 => RequestKind::Hash {
                hash: take::<_, _, ()>(32usize)(rest).ok()?.1.to_vec(),
            },
            1 => RequestKind::HostName {
                host_name: Str::parse_frame(rest).ok()?.1,
            },
            kind => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?kind,
                    "invalid host lookup kind",
                );
                return None;
            }
        };

        Some(Message::HostLookup {
            session_id: SessionId::from(session_id),
            request_id,
            timeout: Duration::from_millis(timeout as u64),
            kind,
        })
    }

    /// Attempt to parse `input` into [`Message`].
    pub fn parse(msg_type: MessageType, input: impl AsRef<[u8]>) -> Option<Self> {
        match msg_type {
            MessageType::GetDate => Self::parse_get_date(input),
            MessageType::SetDate => Self::parse_set_date(input),
            MessageType::GetBandwidthLimits => Self::parse_get_bandwidth_limits(input),
            MessageType::DestroySession => Self::parse_destroy_session(input),
            MessageType::CreateSession => Self::parse_create_session(input),
            MessageType::HostLookup => Self::parse_host_lookup(input),
            msg_type => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?msg_type,
                    "parser not implemented",
                );

                None
            }
        }
    }
}
