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
    i2cp::{
        message::{BandwidthLimits, Message, SessionId, SessionStatus, SessionStatusKind, SetDate},
        socket::I2cpSocket,
    },
    netdb::NetDbHandle,
    primitives::{Date, Str},
    runtime::Runtime,
    tunnel::TunnelManagerHandle,
};

use futures::StreamExt;

use core::{
    future::Future,
    pin::Pin,
    str::FromStr,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::i2cp::session";

/// I2CP client session.
pub struct I2cpSession<R: Runtime> {
    /// Handle to `NetDb`.
    netdb_handle: NetDbHandle,

    /// Session ID.
    session_id: u16,

    /// I2CP socket.
    socket: I2cpSocket<R>,

    /// Handle to `TunnelManager`.
    tunnel_manager_handle: TunnelManagerHandle,
}

impl<R: Runtime> I2cpSession<R> {
    /// Create new [`I2cpSession`] from `stream`.
    pub fn new(
        session_id: u16,
        socket: I2cpSocket<R>,
        netdb_handle: NetDbHandle,
        tunnel_manager_handle: TunnelManagerHandle,
    ) -> Self {
        Self {
            netdb_handle,
            session_id,
            socket,
            tunnel_manager_handle,
        }
    }

    /// Handle I2CP message received from the client.
    fn on_message(&mut self, message: Message) {
        match message {
            Message::GetDate { version, options } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    %version,
                    ?options,
                    "get date, send set date",
                );

                self.socket.send_message(SetDate::new(
                    Date::new(R::time_since_epoch().as_millis() as u64),
                    Str::from_str("0.9.63").expect("to succeed"),
                ));
            }
            Message::GetBandwidthLimits => {
                tracing::trace!(
                    target: LOG_TARGET,
                    "handle bandwidth limit request",
                );

                self.socket.send_message(BandwidthLimits::new());
            }
            Message::DestroySession { session_id } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    ?session_id,
                    "destroy session",
                );

                self.socket
                    .send_message(SessionStatus::new(session_id, SessionStatusKind::Destroyed));
            }
            Message::CreateSession {
                destination,
                date,
                options,
            } => {
                tracing::info!(
                    target: LOG_TARGET,
                    destination = %destination.id(),
                    ?date,
                    num_options = ?options.len(),
                    "create session",
                );

                self.socket.send_message(SessionStatus::new(
                    SessionId::Session(self.session_id),
                    SessionStatusKind::Created,
                ));
            }
            _ => {}
        }
    }
}

impl<R: Runtime> Future for I2cpSession<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.socket.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(message)) => self.on_message(message),
            }
        }

        Poll::Pending
    }
}
