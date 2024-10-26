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
    runtime::Runtime,
    sam::{
        parser::{SamCommand, SamVersion},
        pending::session::SamSessionContext,
        socket::SamSocket,
    },
    tunnel::{TunnelPoolEvent, TunnelPoolHandle},
};

use futures::StreamExt;
use hashbrown::HashMap;
use thingbuf::mpsc::Receiver;

use alloc::sync::Arc;
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::sam::session";

/// Active SAMv3 session.
pub struct SamSession<R: Runtime> {
    /// Session options.
    options: HashMap<String, String>,

    /// Receiver for commands sent for this session.
    ///
    /// Commands are dispatched by `SamServer` which ensures that [`SamCommand::CreateSession`]
    /// is never received by an active session.
    receiver: Receiver<SamCommand>,

    /// Session ID.
    session_id: Arc<str>,

    /// Socket for reading session-related commands from the client.
    socket: SamSocket<R>,

    /// Tunnel pool handle.
    tunnel_pool_handle: TunnelPoolHandle,

    /// Negotiated SAMv3 version.
    version: SamVersion,
}

impl<R: Runtime> SamSession<R> {
    /// Create new [`SamSession`].
    pub fn new(context: SamSessionContext<R>) -> Self {
        let SamSessionContext {
            inbound,
            options,
            outbound,
            receiver,
            session_id,
            socket,
            tunnel_pool_handle,
            version,
        } = context;

        // TODO: crate new destination
        // TODO: send `SESSION CREATE` response to client

        tracing::info!(
            target: LOG_TARGET,
            %session_id,
            "start active session",
        );

        Self {
            options,
            receiver,
            session_id,
            socket,
            tunnel_pool_handle,
            version,
        }
    }

    /// Handle `event` received from the session's tunnel pool.
    fn on_tunnel_pool_event(&mut self, event: TunnelPoolEvent) {
        tracing::trace!(
            target: LOG_TARGET,
            session_id = ?self.session_id,
            ?event,
            "tunnel pool event",
        );

        match event {
            TunnelPoolEvent::InboundTunnelBuilt { tunnel_id, lease } => {}
            TunnelPoolEvent::OutboundTunnelBuilt { tunnel_id } => {}
            TunnelPoolEvent::InboundTunnelExpired { tunnel_id } => {}
            TunnelPoolEvent::OutboundTunnelExpired { tunnel_id } => {}
            TunnelPoolEvent::Message { message } =>
                tracing::warn!(target: LOG_TARGET, "ignoring tunnel message"),
            TunnelPoolEvent::TunnelPoolShutDown | TunnelPoolEvent::Dummy => unreachable!(),
        }
    }
}

impl<R: Runtime> Future for SamSession<R> {
    type Output = Arc<str>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.socket.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(Arc::clone(&self.session_id)),
                Poll::Ready(Some(command)) => match command {
                    command => tracing::warn!(
                        target: LOG_TARGET,
                        session_id = %self.session_id,
                        ?command,
                        "ignoring command"
                    ),
                },
            }
        }

        loop {
            match self.receiver.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(Arc::clone(&self.session_id)),
                Poll::Ready(Some(_)) => {}
            }
        }

        loop {
            match self.tunnel_pool_handle.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(Arc::clone(&self.session_id)),
                Poll::Ready(Some(TunnelPoolEvent::TunnelPoolShutDown)) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        session_id = ?self.session_id,
                        "tunnel pool shut down, shutting down session",
                    );

                    return Poll::Ready(Arc::clone(&self.session_id));
                }
                Poll::Ready(Some(event)) => self.on_tunnel_pool_event(event),
            }
        }

        Poll::Pending
    }
}
