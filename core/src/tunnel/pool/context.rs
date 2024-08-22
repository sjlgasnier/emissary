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

//! Tunnel pool context.

use crate::{
    error::{ChannelError, RoutingError},
    i2np::Message,
    primitives::{MessageId, RouterId, TunnelId},
    tunnel::pool::TUNNEL_CHANNEL_SIZE,
};

use futures::Stream;
use futures_channel::oneshot;
use hashbrown::HashMap;
use rand_core::RngCore;
use thingbuf::mpsc;

#[cfg(feature = "std")]
use parking_lot::RwLock;
#[cfg(feature = "no_std")]
use spin::rwlock::RwLock;

use alloc::{sync::Arc, vec::Vec};
use core::{
    pin::Pin,
    task::{Context, Poll},
};

/// Tunnel pool handle.
#[derive(Clone)]
pub struct TunnelPoolHandle {
    /// Message listeners.
    listeners: Arc<RwLock<HashMap<MessageId, oneshot::Sender<Message>>>>,

    /// TX channel for sending messages via one of the pool's outbound tunnels to remote routers.
    tx: mpsc::Sender<TunnelMessage>,
}

impl TunnelPoolHandle {
    /// Send `message` to `router_id` via an outbound tunnel identified by `gateway`.
    pub fn send_message(
        &self,
        gateway: TunnelId,
        router_id: RouterId,
        message: Vec<u8>,
    ) -> Result<(), ChannelError> {
        self.tx
            .try_send(TunnelMessage::Outbound {
                gateway,
                router_id,
                message,
            })
            .map_err(From::from)
    }

    /// Route `message` received into an inbound tunnel of the tunnel pool.
    ///
    /// Message is routed to an existing listener if one exists for the message and if there are no
    /// installed listeners, the message is routed to `TunnelPool` for further processing.
    pub fn route_message(&self, message: Message) -> Result<(), RoutingError> {
        let mut listeners = self.listeners.write();

        match listeners.remove(&MessageId::from(message.message_id)) {
            Some(listener) =>
                listener.send(message).map_err(|message| RoutingError::ChannelClosed(message)),
            None =>
                self.tx
                    .try_send(TunnelMessage::Inbound { message })
                    .map_err(|error| match error {
                        mpsc::errors::TrySendError::Full(message) => match message {
                            TunnelMessage::Inbound { message } =>
                                RoutingError::ChannelFull(message),
                            _ => unreachable!(),
                        },
                        mpsc::errors::TrySendError::Closed(message) => match message {
                            TunnelMessage::Inbound { message } =>
                                RoutingError::ChannelClosed(message),
                            _ => unreachable!(),
                        },
                        _ => unreachable!(),
                    }),
        }
    }

    /// Allocate new (`MessageId`, `oneshot::Receiver<Message>)` tuple for an inbound build
    /// response.
    pub fn add_listener(&self, rng: &mut impl RngCore) -> (MessageId, oneshot::Receiver<Message>) {
        let mut listeners = self.listeners.write();
        let (tx, rx) = oneshot::channel();

        loop {
            let message_id = MessageId::from(rng.next_u32());

            if !listeners.contains_key(&message_id) {
                listeners.insert(message_id, tx);

                return (message_id, rx);
            }
        }
    }

    /// Remove listener for `message_id` from listeners.
    pub fn remove_listener(&self, message_id: &MessageId) {
        self.listeners.write().remove(message_id);
    }
}

#[derive(Clone)]
pub enum TunnelMessage {
    /// I2NP message received into one of the pool's inbound tunnels
    ///
    /// This message needs to be routed internally to either one of the installed listeners or to
    /// the destination of the tunnel pool.
    Inbound {
        /// Message
        message: Message,
    },

    ///
    Outbound {
        /// Outbound gateway through which `message` should be sent.
        gateway: TunnelId,

        /// ID of the router to whom the message should be sent.
        router_id: RouterId,

        /// Serialize I2NP message.
        message: Vec<u8>,
    },

    Dummy,
}

impl Default for TunnelMessage {
    fn default() -> Self {
        Self::Dummy
    }
}

/// Tunnel pool context.
pub struct TunnelPoolContext {
    /// Message listeners.
    listeners: Arc<RwLock<HashMap<MessageId, oneshot::Sender<Message>>>>,

    /// RX channel for receiving messages destined to remote routers.
    rx: mpsc::Receiver<TunnelMessage>,

    /// TX channel given to pool's inbound tunnels, allowing them to send received I2NP messages to
    /// [`TunnelPool`] for routing.
    tx: mpsc::Sender<TunnelMessage>,
}

impl TunnelPoolContext {
    /// Create new [`TunnelPoolContext`].
    pub fn new() -> (Self, TunnelPoolHandle) {
        let listeners = Arc::new(RwLock::new(HashMap::new()));
        let (tx, rx) = mpsc::channel(TUNNEL_CHANNEL_SIZE);

        (
            Self {
                listeners: listeners.clone(),
                rx,
                tx: tx.clone(),
            },
            TunnelPoolHandle { listeners, tx },
        )
    }

    /// Try sending `message` to an installed listener.
    ///
    /// If the listener doesn't exist, the message is returned in `Result::Err`.
    pub fn try_route(&self, message: Message) -> Result<(), Message> {
        let mut listeners = self.listeners.write();

        match listeners.remove(&MessageId::from(message.message_id)) {
            Some(listener) => listener.send(message),
            None => Err(message),
        }
    }

    /// Allocate new [`TunnelPoolHandle`] for the context.
    pub fn handle(&self) -> TunnelPoolHandle {
        TunnelPoolHandle {
            listeners: self.listeners.clone(),
            tx: self.tx.clone(),
        }
    }
}

impl Stream for TunnelPoolContext {
    type Item = TunnelMessage;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}
