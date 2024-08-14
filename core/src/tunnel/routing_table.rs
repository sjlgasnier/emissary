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
    error::{RouteKind, RoutingError},
    i2np::{
        tunnel::{data::EncryptedTunnelData, gateway::TunnelGateway},
        Message, MessageType,
    },
    primitives::{MessageId, RouterId, TunnelId},
};

use futures_channel::oneshot;
use hashbrown::HashMap;
use thingbuf::mpsc::{errors, Receiver, Sender};

#[cfg(feature = "std")]
use parking_lot::RwLock;
#[cfg(feature = "no_std")]
use spin::rwlock::RwLock;

use alloc::sync::Arc;

/// Routing table.
#[derive(Debug, Clone)]
struct RoutingTable {
    /// Local router ID.
    router_hash: RouterId,

    /// Listeners for specific message.
    listeners: Arc<RwLock<HashMap<MessageId, oneshot::Sender<Message>>>>,

    /// Active tunnels.
    tunnels: Arc<RwLock<HashMap<TunnelId, Sender<Message>>>>,

    /// TX channel for sending inbound messages to `TransitTunnelManager`.
    transit: Sender<Message>,

    /// TX channel for sending outbound messages to `TunnelManager`.
    manager: Sender<(RouterId, Vec<u8>)>,
}

impl RoutingTable {
    /// Create new [`RoutingTable`].
    pub fn new(
        router_hash: RouterId,
        manager: Sender<(RouterId, Vec<u8>)>,
        transit: Sender<Message>,
    ) -> Self {
        Self {
            transit,
            manager,
            router_hash,
            listeners: Default::default(),
            tunnels: Default::default(),
        }
    }

    /// Add tunnel to routing table.
    ///
    /// This can either be a transit tunnel or a tunnel of one of the tunnel pols
    pub fn add_tunnel(&self, tunnel_id: TunnelId, sender: Sender<Message>) {
        self.tunnels.write().insert(tunnel_id, sender);
    }

    /// Remove tunnel from [`RoutingTable`].
    pub fn remove_tunnel(&self, tunnel_id: &TunnelId) {
        self.tunnels.write().remove(tunnel_id);
    }

    /// Add listener for a specific message.
    pub fn add_listener(&self, message_id: MessageId, sender: oneshot::Sender<Message>) {
        self.listeners.write().insert(message_id, sender);
    }

    /// Remove listener from [`RoutingTable`].
    pub fn remove_listener(&self, message_id: &MessageId) {
        self.listeners.write().remove(message_id);
    }

    /// Attempt to route tunnel message to correct subsystem.
    ///
    /// Different from [`RoutingTable::route_listener_message()`] in that an error is returned if
    /// route (tunnel) is not found for `message`.
    fn route_tunnel_message(&self, message: Message) -> Result<(), RoutingError> {
        let tunnel_id = match message.message_type {
            MessageType::TunnelData => {
                let Some(tunnel_data) = EncryptedTunnelData::parse(&message.payload) else {
                    return Err(RoutingError::FailedToParseRoute(message));
                };

                tunnel_data.tunnel_id()
            }
            MessageType::TunnelGateway => {
                let Some(tunnel_gateway) = TunnelGateway::parse(&message.payload) else {
                    return Err(RoutingError::FailedToParseRoute(message));
                };

                tunnel_gateway.tunnel_id
            }
            _ => unreachable!(),
        };
        let tunnels = self.tunnels.read();

        let Some(sender) = tunnels.get(&tunnel_id) else {
            return Err(RoutingError::RouteNotFound(
                message,
                RouteKind::Tunnel(tunnel_id),
            ));
        };

        sender.try_send(message).map_err(|error| match error {
            errors::TrySendError::Full(message) => RoutingError::ChannelFull(message),
            errors::TrySendError::Closed(message) => RoutingError::ChannelClosed(message),
            _ => unreachable!(),
        })
    }

    /// Attempt to route message to an installed listener, if the listener exists.
    ///
    /// If no listener exists, the message is routed to `TransitTunnelManager`.
    fn route_listener_message(&self, message: Message) -> Result<(), RoutingError> {
        let mut listeners = self.listeners.write();

        match listeners.remove(&MessageId::from(message.message_id)) {
            Some(listener) =>
                listener.send(message).map_err(|message| RoutingError::ChannelClosed(message)),
            None => {
                drop(listeners);

                self.transit.try_send(message).map_err(|error| match error {
                    errors::TrySendError::Full(message) => RoutingError::ChannelFull(message),
                    errors::TrySendError::Closed(message) => RoutingError::ChannelClosed(message),
                    _ => unreachable!(),
                })
            }
        }
    }

    /// Route `message` into correct subsystem.
    pub fn route_message(&self, message: Message) -> Result<(), RoutingError> {
        match message.message_type {
            MessageType::TunnelData | MessageType::TunnelGateway =>
                self.route_tunnel_message(message),
            _ => self.route_listener_message(message),
        }
    }

    /// Send `message` to `router`.
    ///
    /// `router` could point to local router which causes `message` to be routed locally.
    pub fn send_message(&self, message: Vec<u8>, router: RouterId) -> Result<(), RoutingError> {
        match router == self.router_hash {
            true => {
                let message = Message::parse_short(&message).expect("valid message");
                self.route_message(message)
            }
            false => self.manager.try_send((router, message)).map_err(|error| match error {
                errors::TrySendError::Full((router, message)) => RoutingError::ChannelFull(
                    Message::parse_short(&message).expect("valid message"),
                ),
                errors::TrySendError::Closed((router, message)) => RoutingError::ChannelClosed(
                    Message::parse_short(&message).expect("valid message"),
                ),
                _ => unreachable!(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        i2np::{tunnel::data::TunnelDataBuilder, MessageBuilder},
        runtime::{mock::MockRuntime, Runtime},
    };
    use futures_channel::oneshot;
    use rand_core::RngCore;
    use thingbuf::mpsc::channel;

    #[test]
    fn tunnel_doesnt_exist() {
        let (transit_tx, transit_rx) = channel(64);
        let (manager_tx, manager_rx) = channel(64);
        let routing_table =
            RoutingTable::new(RouterId::from(vec![1, 2, 3, 4]), manager_tx, transit_tx);

        let message = {
            let message = TunnelDataBuilder::new(TunnelId::from(MockRuntime::rng().next_u32()))
                .with_local_delivery(&vec![1, 3, 3, 7])
                .build::<MockRuntime>();

            let message = MessageBuilder::short()
                .with_message_type(MessageType::TunnelData)
                .with_message_id(MockRuntime::rng().next_u32())
                .with_expiration((MockRuntime::time_since_epoch()).as_secs())
                .with_payload(&message)
                .build();

            Message::parse_short(&message).unwrap()
        };

        match routing_table.route_message(message).unwrap_err() {
            RoutingError::RouteNotFound(_, _) => {}
            error => panic!("invalid error: {error:?}"),
        }
    }

    #[test]
    fn tunnel_exists() {
        let (transit_tx, transit_rx) = channel(64);
        let (manager_tx, manager_rx) = channel(64);
        let (tunnel_tx, tunnel_rx) = channel(64);
        let routing_table =
            RoutingTable::new(RouterId::from(vec![1, 2, 3, 4]), manager_tx, transit_tx);

        // add tunnel into routing table
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        routing_table.add_tunnel(tunnel_id, tunnel_tx);

        let message = {
            let message = TunnelDataBuilder::new(TunnelId::from(tunnel_id))
                .with_local_delivery(&vec![1, 3, 3, 7])
                .build::<MockRuntime>();

            let message = MessageBuilder::short()
                .with_message_type(MessageType::TunnelData)
                .with_message_id(MockRuntime::rng().next_u32())
                .with_expiration((MockRuntime::time_since_epoch()).as_secs())
                .with_payload(&message)
                .build();

            Message::parse_short(&message).unwrap()
        };

        assert!(routing_table.route_message(message).is_ok());
        assert!(tunnel_rx.try_recv().is_ok());
    }

    #[test]
    fn listener_doesnt_exist() {
        let (transit_tx, transit_rx) = channel(64);
        let (manager_tx, manager_rx) = channel(64);
        let routing_table =
            RoutingTable::new(RouterId::from(vec![1, 2, 3, 4]), manager_tx, transit_tx);

        let message = {
            let message = MessageBuilder::short()
                .with_message_type(MessageType::ShortTunnelBuild)
                .with_message_id(MockRuntime::rng().next_u32())
                .with_expiration((MockRuntime::time_since_epoch()).as_secs())
                .with_payload(&vec![1, 2, 3, 4, 5])
                .build();

            Message::parse_short(&message).unwrap()
        };

        assert!(routing_table.route_message(message).is_ok());
        assert!(transit_rx.try_recv().is_ok());
    }

    #[test]
    fn listener_exists() {
        let (transit_tx, transit_rx) = channel(64);
        let (manager_tx, manager_rx) = channel(64);
        let (listener_tx, mut listener_rx) = oneshot::channel();
        let routing_table =
            RoutingTable::new(RouterId::from(vec![1, 2, 3, 4]), manager_tx, transit_tx);

        // add listener for message into routing table
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        routing_table.add_listener(message_id, listener_tx);

        let message = {
            let message = MessageBuilder::short()
                .with_message_type(MessageType::ShortTunnelBuild)
                .with_message_id(message_id)
                .with_expiration((MockRuntime::time_since_epoch()).as_secs())
                .with_payload(&vec![1, 2, 3, 4, 5])
                .build();

            Message::parse_short(&message).unwrap()
        };

        assert!(routing_table.route_message(message).is_ok());
        assert!(listener_rx.try_recv().is_ok());
        assert!(transit_rx.try_recv().is_err());
    }

    #[test]
    fn channel_closed() {
        let (transit_tx, transit_rx) = channel(64);
        let (manager_tx, manager_rx) = channel(64);
        let (listener_tx, mut listener_rx) = oneshot::channel();
        let routing_table =
            RoutingTable::new(RouterId::from(vec![1, 2, 3, 4]), manager_tx, transit_tx);

        // add listener for message into routing table
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        routing_table.add_listener(message_id, listener_tx);

        let message = {
            let message = MessageBuilder::short()
                .with_message_type(MessageType::ShortTunnelBuild)
                .with_message_id(message_id)
                .with_expiration((MockRuntime::time_since_epoch()).as_secs())
                .with_payload(&vec![1, 2, 3, 4, 5])
                .build();

            Message::parse_short(&message).unwrap()
        };
        drop(listener_rx);

        match routing_table.route_message(message).unwrap_err() {
            RoutingError::ChannelClosed(_) => {}
            error => panic!("invalid error: {error:?}"),
        }
        assert!(transit_rx.try_recv().is_err());
    }

    #[test]
    fn channel_full() {
        let (transit_tx, transit_rx) = channel(64);
        let (manager_tx, manager_rx) = channel(64);
        let (tunnel_tx, tunnel_rx) = channel(2);
        let routing_table =
            RoutingTable::new(RouterId::from(vec![1, 2, 3, 4]), manager_tx, transit_tx);

        // add tunnel into routing table
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        routing_table.add_tunnel(tunnel_id, tunnel_tx);

        // fill the tunnel channel with messages
        for _ in 0..2 {
            let message = {
                let message = TunnelDataBuilder::new(TunnelId::from(tunnel_id))
                    .with_local_delivery(&vec![1, 3, 3, 7])
                    .build::<MockRuntime>();

                let message = MessageBuilder::short()
                    .with_message_type(MessageType::TunnelData)
                    .with_message_id(MockRuntime::rng().next_u32())
                    .with_expiration((MockRuntime::time_since_epoch()).as_secs())
                    .with_payload(&message)
                    .build();

                Message::parse_short(&message).unwrap()
            };

            assert!(routing_table.route_message(message).is_ok());
        }

        // try to send one more message
        let message = {
            let message = TunnelDataBuilder::new(TunnelId::from(tunnel_id))
                .with_local_delivery(&vec![1, 3, 3, 7])
                .build::<MockRuntime>();

            let message = MessageBuilder::short()
                .with_message_type(MessageType::TunnelData)
                .with_message_id(MockRuntime::rng().next_u32())
                .with_expiration((MockRuntime::time_since_epoch()).as_secs())
                .with_payload(&message)
                .build();

            Message::parse_short(&message).unwrap()
        };

        match routing_table.route_message(message).unwrap_err() {
            RoutingError::ChannelFull(_) => {}
            error => panic!("invalid error: {error:?}"),
        }

        for _ in 0..2 {
            assert!(tunnel_rx.try_recv().is_ok());
        }
    }

    #[test]
    fn send_message_to_remote() {
        let (transit_tx, transit_rx) = channel(64);
        let (manager_tx, manager_rx) = channel(64);
        let (listener_tx, mut listener_rx) = oneshot::channel();
        let routing_table =
            RoutingTable::new(RouterId::from(vec![1, 2, 3, 4]), manager_tx, transit_tx);

        // add listener for message into routing table
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        routing_table.add_listener(message_id, listener_tx);

        let message = MessageBuilder::short()
            .with_message_type(MessageType::ShortTunnelBuild)
            .with_message_id(message_id)
            .with_expiration((MockRuntime::time_since_epoch()).as_secs())
            .with_payload(&vec![1, 2, 3, 4, 5])
            .build();

        assert!(routing_table.send_message(message, RouterId::from(vec![1, 3, 3, 7])).is_ok());
        assert!(manager_rx.try_recv().is_ok());
    }

    #[test]
    fn route_message_locally() {
        let (transit_tx, transit_rx) = channel(64);
        let (manager_tx, manager_rx) = channel(64);
        let routing_table =
            RoutingTable::new(RouterId::from(vec![1, 2, 3, 4]), manager_tx, transit_tx);

        let message = MessageBuilder::short()
            .with_message_type(MessageType::ShortTunnelBuild)
            .with_message_id(MessageId::from(MockRuntime::rng().next_u32()))
            .with_expiration((MockRuntime::time_since_epoch()).as_secs())
            .with_payload(&vec![1, 2, 3, 4, 5])
            .build();

        assert!(routing_table.send_message(message, RouterId::from(vec![1, 2, 3, 4])).is_ok());
        assert!(transit_rx.try_recv().is_ok());
    }
}
