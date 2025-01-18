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
    crypto::{
        base64_decode,
        chachapoly::{ChaCha, ChaChaPoly},
        hmac::Hmac,
        sha256::Sha256,
        EphemeralPrivateKey, EphemeralPublicKey, StaticPrivateKey, StaticPublicKey,
    },
    primitives::{RouterId, Str, TransportKind},
    runtime::Runtime,
    transport::ssu2::{
        message::{
            AeadState, Block, HeaderBuilder, MessageBuilder, MessageType, NoiseContext,
            SessionConfirmedBuilder, SessionRequestBuilder, ShortHeaderFlag, TokenRequestBuilder,
        },
        session::active::{KeyContext, Ssu2SessionContext},
        Packet,
    },
};

use bytes::{Bytes, BytesMut};
use thingbuf::mpsc::{Receiver, Sender};

use core::{
    future::Future,
    marker::PhantomData,
    mem,
    net::SocketAddr,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};

pub mod inbound;
pub mod outbound;

/// Status returned by [`PendingSession`] to [`Ssu2Socket`].
pub enum PendingSsu2SessionStatus {
    /// New session has been opened.
    ///
    /// Session info is forwaded to [`Ssu2Socket`] and to [`TransportManager`] for validation and
    /// if the session is accepted, a new future is started for the session.
    NewInboundSession {
        /// Context for the active session.
        context: Ssu2SessionContext,

        /// ACK for `SessionConfirmed`.
        pkt: BytesMut,

        /// Socket address of the remote router.
        target: SocketAddr,
    },

    /// New outbound session.
    NewOutboundSession {
        /// Context for the active session.
        context: Ssu2SessionContext,
    },

    /// Pending session terminated due to fatal error, e.g., decryption error.
    SessionTermianted {},

    /// [`SSu2Socket`] has been closed.
    SocketClosed,
}
