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
    crypto::{SigningPrivateKey, StaticPrivateKey},
    i2np::RawI2npMessage,
    primitives::{RouterAddress, RouterInfo, TransportKind},
    runtime::Runtime,
    transports::ntcp2::Ntcp2Transport,
    Error,
};

use futures::{Stream, StreamExt};
use hashbrown::HashMap;
use thingbuf::mpsc::{channel, Receiver, Sender};

use alloc::{boxed::Box, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

mod ntcp2;
mod ssu2;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::transport-manager";

// TODO: introduce `Endpoint`?

#[derive(Debug, Hash, PartialEq, Eq)]
pub enum SubsystemKind {
    /// NetDB subsystem.
    NetDb,

    /// Tunneling subsystem.
    Tunnel,
}

#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// Connection successfully established to remote peer.
    ConnectionEstablished {
        /// `RouterInfo` for the connected peer.
        router: RouterInfo,
    },
    ConnectionClosed {},
    ConnectionFailure {},
    Message {},
}

// TODO: remove
/// Transport event.
#[derive(Debug)]
pub enum TransportEvent {
    /// Connection successfully established to remote peer.
    ConnectionEstablished {
        /// `RouterInfo` for the connected peer.
        router: RouterInfo,
    },
    ConnectionClosed {},
    ConnectionFailure {},
}

// TODO: `poll_progress()` - only poll pending streams
// TODO: `poll()` - poll pending streams and listener
pub trait Transport: Stream + Unpin {
    /// Connect to `router`.
    //
    // TODO: how to signal preference for transport?
    fn connect(&mut self, router: RouterInfo) -> crate::Result<()>;
}

#[derive(Debug, Clone)]
pub enum ProtocolCommand {
    /// Attempt to connect to remote peer.
    Connect {
        /// Remote's router info.
        router: RouterInfo,
    },

    /// Dummy event.
    Dummy,
}

impl Default for ProtocolCommand {
    fn default() -> Self {
        Self::Dummy
    }
}

/// Transport service.
///
/// Implements a handle that is given to subsystems of `emissary` are themselves not transports
/// but interact with them, namely `NetDb` and `TunnelManager`. [`TransportService`] allows
/// the subsystem to establish new connections, close existing connections, send and receive
/// messages to and from the network.
pub struct TransportService {
    /// TX channel for sending commands to [`TransportManager`].
    cmd_tx: Sender<ProtocolCommand>,

    /// RX channel for receiving events from [`TransportManager`] and enabled transports.
    event_rx: Receiver<RawI2npMessage>,

    /// Connected routers.
    routers: HashMap<usize, Sender<()>>,
}

impl TransportService {
    /// Attempt to establish connection to `router`.
    ///
    /// The connection is established in the background and the result
    /// can be received by polling [`TransportService`].
    ///
    /// [`TransportService::connect()`] returns an error if the channel is clogged
    /// and the caller should try again later.
    pub fn connect(&mut self, router: RouterInfo) -> Result<(), ()> {
        self.cmd_tx
            .try_send(ProtocolCommand::Connect { router })
            .map_err(|_| ())
    }
}

impl Stream for TransportService {
    type Item = RawI2npMessage;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.event_rx.poll_recv(cx).map(|event| event)
    }
}

#[derive(Clone)]
struct SubsystemHandle {
    subsystems: Vec<Sender<RawI2npMessage>>,
}

impl SubsystemHandle {
    fn new() -> Self {
        Self {
            subsystems: Vec::new(),
        }
    }

    // TODO: remove?
    fn register_subsystem(&mut self, event_tx: Sender<RawI2npMessage>) {
        self.subsystems.push(event_tx);
    }

    // TODO: fix error
    fn dispatch_message(&mut self, message: RawI2npMessage) -> crate::Result<()> {
        tracing::error!(destination = ?message.destination(), "dispatch message to subsystem");

        match message.destination() {
            SubsystemKind::NetDb => self.subsystems[0]
                .try_send(message)
                .map_err(|_| Error::NotSupported),
            SubsystemKind::Tunnel => self.subsystems[1]
                .try_send(message)
                .map_err(|_| Error::NotSupported),
        }
    }
}

/// Transport manager.
///
/// Transport manager is responsible for connecting the higher-level subsystems
/// together with enabled, lower-level transports and polling for polling those
/// transports so that they can make progress.
pub struct TransportManager<R: Runtime> {
    /// RX channel for receiving commands from other subsystems.
    cmd_rx: Receiver<ProtocolCommand>,

    /// TX channel passed onto other subsystems.
    cmd_tx: Sender<ProtocolCommand>,

    /// Local key.
    local_key: StaticPrivateKey,

    /// Local `RouterInfo`.
    local_router_info: RouterInfo,

    /// Local signing key.
    local_signing_key: SigningPrivateKey,

    /// Poll index for transports.
    poll_index: usize,

    // Runtime.
    runtime: R,

    /// Subsystem handle passed onto enabled transports.
    subsystem_handle: SubsystemHandle,

    /// Enabled transports.
    transports: Vec<Box<dyn Transport<Item = TransportEvent>>>,
}

impl<R: Runtime> TransportManager<R> {
    /// Create new [`TransportManager`].
    pub fn new(
        runtime: R,
        local_key: StaticPrivateKey,
        local_signing_key: SigningPrivateKey,
        local_router_info: RouterInfo,
    ) -> Self {
        let (cmd_tx, cmd_rx) = channel(256);

        Self {
            cmd_rx,
            cmd_tx,
            local_key,
            local_router_info,
            local_signing_key,
            poll_index: 0usize,
            runtime,
            subsystem_handle: SubsystemHandle::new(),
            transports: Vec::with_capacity(2),
        }
    }

    /// Register new subsystem to [`TransportManager`].
    ///
    /// The number of subsystems is fixed and the initialization order is important.
    pub fn register_subsystem(&mut self, kind: SubsystemKind) -> TransportService {
        let (event_tx, event_rx) = channel(64);

        tracing::debug!(
            target: LOG_TARGET,
            subsystem = ?kind,
            "register subsystem",
        );

        self.subsystem_handle.register_subsystem(event_tx);

        TransportService {
            event_rx,
            cmd_tx: self.cmd_tx.clone(),
            routers: HashMap::new(),
        }
    }

    /// Register enabled transport
    ///
    /// The number of transports is fixed and the initialization order is important.
    pub async fn register_transport(&mut self, kind: TransportKind) -> crate::Result<()> {
        let TransportKind::Ntcp2 = kind else {
            panic!("only ntcp2 is supported");
        };

        self.transports.push(Box::new(
            Ntcp2Transport::new(
                self.runtime.clone(),
                self.local_key.clone(),
                self.local_signing_key.clone(),
                self.local_router_info.clone(),
                self.subsystem_handle.clone(),
            )
            .await?,
        ));

        Ok(())
    }
}

impl<R: Runtime> Future for TransportManager<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let len = self.transports.len();
        let start_index = self.poll_index;

        loop {
            let index = self.poll_index % len;
            self.poll_index += 1;

            match self.transports[0].poll_next_unpin(cx) {
                Poll::Pending => {}
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(event)) => {
                    tracing::error!("todo: handle established connection");
                }
            }

            if self.poll_index == start_index + len {
                break;
            }
        }

        loop {
            match futures::ready!(self.cmd_rx.poll_recv(cx)) {
                None => return Poll::Ready(()),
                Some(ProtocolCommand::Connect { router }) => {
                    self.transports[0].connect(router);
                }
                Some(event) => {
                    todo!("event: {event:?}");
                }
            }
        }
    }
}
