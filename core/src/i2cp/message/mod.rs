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

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::i2cp::message";

/// I2CP message type.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MessageType {
    /// Bandwidth limit
    BandwidthLimitsMessage,

    /// Binding info.
    BlindingInfoMessage,

    /// Create `LeaseSet`.
    CreateLeaseSetMessage,

    /// Create `LeaseSet2`.
    CreateLeaseSet2Message,

    /// Create session.
    CreateSessionMessage,

    /// Lookup destination.
    DestLookupMessage,

    /// Destination lookup reply.
    DestReplyMessage,

    /// Destroy session.
    DestroySessionMessage,

    /// Disconnect connection.
    DisconnectMessage,

    /// Get bandwidth limits.
    GetBandwidthLimitsMessage,

    /// Get date.
    GetDateMessage,

    /// Lookup host.
    HostLookupMessage,

    /// Host lookup reply.
    HostReplyMessage,

    /// Delivery payload of message to client.
    MessagePayloadMessage,

    /// Notify client of a delivery status.
    MessageStatusMessage,

    /// Start reception of a message.
    ReceiveMessageBeginMessage,

    /// Inform router that a message was delivered successfully.
    ReceiveMessageEndMessage,

    /// Reconfigure session.
    ReconfigureSessionMessage,

    /// Report abuse.
    ReportAbuseMessage,

    /// Request `LeaseSet`.
    RequestLeaseSetMessage,

    /// Request `VariableLeaseSet`.
    RequestVariableLeaseSetMessage,

    /// Send message to remote router.
    SendMessageMessage,

    /// Send message to remote router with expiration and options.
    SendMessageExpiresMessage,

    /// Inform client about the status of the session.
    SessionStatusMessage,

    /// Set date.
    SetDateMessage,
}

impl MessageType {
    /// Serialize [`MessageType`].
    pub fn as_u8(self) -> u8 {
        match self {
            Self::BandwidthLimitsMessage => 23,
            Self::BlindingInfoMessage => 42,
            Self::CreateLeaseSetMessage => 4,
            Self::CreateLeaseSet2Message => 41,
            Self::CreateSessionMessage => 1,
            Self::DestLookupMessage => 34,
            Self::DestReplyMessage => 35,
            Self::DestroySessionMessage => 3,
            Self::DisconnectMessage => 30,
            Self::GetBandwidthLimitsMessage => 8,
            Self::GetDateMessage => 32,
            Self::HostLookupMessage => 38,
            Self::HostReplyMessage => 39,
            Self::MessagePayloadMessage => 31,
            Self::MessageStatusMessage => 22,
            Self::ReceiveMessageBeginMessage => 6,
            Self::ReceiveMessageEndMessage => 7,
            Self::ReconfigureSessionMessage => 2,
            Self::ReportAbuseMessage => 29,
            Self::RequestLeaseSetMessage => 21,
            Self::RequestVariableLeaseSetMessage => 37,
            Self::SendMessageMessage => 5,
            Self::SendMessageExpiresMessage => 36,
            Self::SessionStatusMessage => 20,
            Self::SetDateMessage => 33,
        }
    }

    /// Try to convert `msg_type` into `MessageType`.
    pub fn from_u8(msg_type: u8) -> Option<Self> {
        match msg_type {
            23 => Some(Self::BandwidthLimitsMessage),
            42 => Some(Self::BlindingInfoMessage),
            4 => Some(Self::CreateLeaseSetMessage),
            41 => Some(Self::CreateLeaseSet2Message),
            1 => Some(Self::CreateSessionMessage),
            34 => Some(Self::DestLookupMessage),
            35 => Some(Self::DestReplyMessage),
            3 => Some(Self::DestroySessionMessage),
            30 => Some(Self::DisconnectMessage),
            8 => Some(Self::GetBandwidthLimitsMessage),
            32 => Some(Self::GetDateMessage),
            38 => Some(Self::HostLookupMessage),
            39 => Some(Self::HostReplyMessage),
            31 => Some(Self::MessagePayloadMessage),
            22 => Some(Self::MessageStatusMessage),
            6 => Some(Self::ReceiveMessageBeginMessage),
            7 => Some(Self::ReceiveMessageEndMessage),
            2 => Some(Self::ReconfigureSessionMessage),
            29 => Some(Self::ReportAbuseMessage),
            21 => Some(Self::RequestLeaseSetMessage),
            37 => Some(Self::RequestVariableLeaseSetMessage),
            5 => Some(Self::SendMessageMessage),
            36 => Some(Self::SendMessageExpiresMessage),
            20 => Some(Self::SessionStatusMessage),
            33 => Some(Self::SetDateMessage),
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
pub struct Message {}
