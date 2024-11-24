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
    i2np::{tunnel::data::DeliveryInstructions, Message},
    primitives::MessageId,
};

use hashbrown::HashMap;

use alloc::{collections::BTreeMap, vec::Vec};
use core::{fmt, iter};

/// Owned delivery instructions.
pub enum OwnedDeliveryInstructions {
    /// Fragment meant for the local router.
    Local,

    /// Fragment meant for a router.
    Router {
        /// Hash of the router.
        hash: Vec<u8>,
    },

    /// Fragment meant for a tunnel.
    Tunnel {
        /// Tunnel ID.
        tunnel_id: u32,

        /// Hash of the tunnel.
        hash: Vec<u8>,
    },
}

impl fmt::Debug for OwnedDeliveryInstructions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => f.debug_struct("OwnedDeliveryInstructions::Local").finish(),
            Self::Router { .. } =>
                f.debug_struct("OwnedDeliveryInstructions::Router").finish_non_exhaustive(),
            Self::Tunnel { tunnel_id, .. } => f
                .debug_struct("OwnedDeliveryInstructions::Tunnel")
                .field("tunnel", &tunnel_id)
                .finish_non_exhaustive(),
        }
    }
}

impl<'a> From<&'a DeliveryInstructions<'a>> for OwnedDeliveryInstructions {
    fn from(value: &DeliveryInstructions) -> Self {
        match value {
            DeliveryInstructions::Local => OwnedDeliveryInstructions::Local,
            DeliveryInstructions::Router { hash } => OwnedDeliveryInstructions::Router {
                hash: hash.to_vec(),
            },
            DeliveryInstructions::Tunnel { tunnel_id, hash } => OwnedDeliveryInstructions::Tunnel {
                tunnel_id: *tunnel_id,
                hash: hash.to_vec(),
            },
        }
    }
}

/// I2NP message fragment buffer.
#[derive(Default)]
pub struct Fragment {
    /// Delivery instructions for the I2NP message.
    ///
    /// `None` if last first hasn't been received.
    delivery_instructions: Option<OwnedDeliveryInstructions>,

    /// First fragment.
    ///
    /// `None` if last first hasn't been received.
    first_fragment: Option<Vec<u8>>,

    /// Fragments.
    fragments: BTreeMap<usize, Vec<u8>>,

    /// Total of fragments.
    ///
    /// `None` if last fragment hasn't been received.
    num_fragments: Option<usize>,

    /// Total size of the I2NP message.
    total_size: usize,
}

impl Fragment {
    /// Check if [`Fragment`] is ready for assembly.
    pub fn is_ready(&self) -> bool {
        self.num_fragments.is_some()
            && self.delivery_instructions.is_some()
            && self.first_fragment.is_some()
            && self.num_fragments == Some(self.fragments.len())
    }

    /// Construct I2NP message from received fragments.
    pub fn construct(mut self) -> Option<(Message, OwnedDeliveryInstructions)> {
        let delivery_instructions = self.delivery_instructions.take()?;
        let first_fragment = self.first_fragment.take()?;

        let message = iter::once(first_fragment).chain(self.fragments.into_values()).fold(
            Vec::<u8>::with_capacity(self.total_size),
            |mut message, fragment| {
                message.extend_from_slice(&fragment);
                message
            },
        );

        Message::parse_standard(&message).map(|message| (message, delivery_instructions))
    }
}

/// Fragment handler.
pub struct FragmentHandler {
    /// Pending messages.
    messages: HashMap<MessageId, Fragment>,
}

impl FragmentHandler {
    /// Create new [`FragmentHandler`].
    pub fn new() -> Self {
        Self {
            messages: HashMap::new(),
        }
    }

    /// Handle first fragment.
    ///
    /// If all fragments have been received, the constructed message is received.
    pub fn first_fragment(
        &mut self,
        message_id: MessageId,
        delivery_instructions: &DeliveryInstructions,
        payload: &[u8],
    ) -> Option<(Message, OwnedDeliveryInstructions)> {
        let message = self.messages.entry(message_id).or_default();

        message.total_size += payload.len();
        message.first_fragment = Some(payload.to_vec());
        message.delivery_instructions =
            Some(OwnedDeliveryInstructions::from(delivery_instructions));

        message
            .is_ready()
            .then(|| self.messages.remove(&message_id).expect("message to exist").construct())
            .flatten()
    }

    /// Handle middle fragment.
    ///
    /// If all fragments have been received, the constructed message is received.
    pub fn middle_fragment(
        &mut self,
        message_id: MessageId,
        sequence: usize,
        payload: &[u8],
    ) -> Option<(Message, OwnedDeliveryInstructions)> {
        let message = self.messages.entry(message_id).or_default();

        message.total_size += payload.len();
        message.fragments.insert(sequence, payload.to_vec());

        message
            .is_ready()
            .then(|| self.messages.remove(&message_id).expect("message to exist").construct())
            .flatten()
    }

    /// Handle last fragment.
    ///
    /// If all fragments have been received, the constructed message is received.
    pub fn last_fragment(
        &mut self,
        message_id: MessageId,
        sequence: usize,
        payload: &[u8],
    ) -> Option<(Message, OwnedDeliveryInstructions)> {
        let message = self.messages.entry(message_id).or_default();

        message.total_size += payload.len();
        message.fragments.insert(sequence, payload.to_vec());
        message.num_fragments = Some(sequence);

        message
            .is_ready()
            .then(|| self.messages.remove(&message_id).expect("message to exist").construct())
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        i2np::{MessageBuilder, MessageType},
        runtime::{mock::MockRuntime, Runtime},
    };
    use alloc::collections::VecDeque;
    use chacha20poly1305::aead::Buffer;
    use std::time::Duration;

    fn split(num_fragments: usize, message: Vec<u8>) -> VecDeque<Vec<u8>> {
        let remainder = message.len() % num_fragments;
        let fragment_len = message.len() / num_fragments;

        let mut fragments = message
            .chunks(fragment_len)
            .map(|chunk| chunk.to_vec())
            .collect::<VecDeque<_>>();

        let last = fragments.pop_back().unwrap();
        let mut second_to_last = fragments.pop_back().unwrap();

        second_to_last.extend_from_slice(&last);
        fragments.push_back(second_to_last);

        fragments
    }

    #[test]
    fn simple_fragmentation() {
        let expiration = MockRuntime::time_since_epoch();

        let mut message = MessageBuilder::standard()
            .with_expiration(expiration)
            .with_message_type(MessageType::Data)
            .with_message_id(1338u32)
            .with_payload(&vec![0u8; 1337])
            .build();

        let message_id = MessageId::from(1337);
        let mut handler = FragmentHandler::new();
        let mut fragments = split(4, message);

        assert_eq!(fragments.len(), 4);
        assert!(handler
            .first_fragment(
                message_id,
                &DeliveryInstructions::Local,
                &fragments.pop_front().unwrap(),
            )
            .is_none());

        for i in 1..=2 {
            assert!(handler
                .middle_fragment(message_id, i, &fragments.pop_front().unwrap())
                .is_none());
        }

        let (message, delivery_instructions) =
            handler.last_fragment(message_id, 3, &fragments.pop_front().unwrap()).unwrap();

        assert_eq!(
            message.expiration,
            Duration::from_millis(expiration.as_millis() as u64)
        );
        assert_eq!(message.message_id, 1338u32);
        assert_eq!(message.message_type, MessageType::Data);
        assert_eq!(message.payload, vec![0u8; 1337]);
    }

    #[test]
    fn first_and_last_fragment() {
        let expiration = MockRuntime::time_since_epoch();

        let mut message = MessageBuilder::standard()
            .with_expiration(expiration)
            .with_message_type(MessageType::Data)
            .with_message_id(1339u32)
            .with_payload(&vec![0xaau8; 1335])
            .build();

        let message_id = MessageId::from(1337);
        let mut handler = FragmentHandler::new();

        let mut fragments = split(2, message);

        assert_eq!(fragments.len(), 2);
        assert!(handler
            .first_fragment(
                message_id,
                &DeliveryInstructions::Local,
                &fragments.pop_front().unwrap(),
            )
            .is_none());

        let (message, delivery_instructions) =
            handler.last_fragment(message_id, 1, &fragments.pop_front().unwrap()).unwrap();

        assert_eq!(
            message.expiration,
            Duration::from_millis(expiration.as_millis() as u64)
        );
        assert_eq!(message.message_id, 1339u32);
        assert_eq!(message.message_type, MessageType::Data);
        assert_eq!(message.payload, vec![0xaau8; 1335]);
    }

    #[test]
    fn out_of_order_last_is_first() {
        let expiration = MockRuntime::time_since_epoch();

        let mut message = MessageBuilder::standard()
            .with_expiration(expiration)
            .with_message_type(MessageType::Data)
            .with_message_id(1338u32)
            .with_payload(&vec![0u8; 30_005])
            .build();

        let message_id = MessageId::from(1337);
        let mut handler = FragmentHandler::new();
        let mut fragments = split(4, message);
        assert_eq!(fragments.len(), 4);

        let first = fragments.pop_front().unwrap();

        // last fragment is delivered first
        assert!(handler.last_fragment(message_id, 3, &fragments.pop_back().unwrap()).is_none());

        for i in 1..=2 {
            assert!(handler
                .middle_fragment(message_id, i, &fragments.pop_front().unwrap())
                .is_none());
        }

        let (message, delivery_instructions) = handler
            .first_fragment(message_id, &DeliveryInstructions::Local, &first)
            .unwrap();

        assert_eq!(
            message.expiration,
            Duration::from_millis(expiration.as_millis() as u64)
        );
        assert_eq!(message.message_id, 1338u32);
        assert_eq!(message.message_type, MessageType::Data);
        assert_eq!(message.payload, vec![0u8; 30_005]);
    }

    #[test]
    fn middle_fragment_delivered_last() {
        let expiration = MockRuntime::time_since_epoch();

        let mut message = MessageBuilder::standard()
            .with_expiration(expiration)
            .with_message_type(MessageType::Data)
            .with_message_id(1338u32)
            .with_payload(&vec![0u8; 1337])
            .build();

        let message_id = MessageId::from(1337);
        let mut handler = FragmentHandler::new();
        let mut fragments = split(4, message);

        assert_eq!(fragments.len(), 4);
        assert!(handler
            .first_fragment(
                message_id,
                &DeliveryInstructions::Local,
                &fragments.pop_front().unwrap(),
            )
            .is_none());

        assert!(handler
            .middle_fragment(message_id, 1, &fragments.pop_front().unwrap())
            .is_none());

        assert!(handler.last_fragment(message_id, 3, &fragments.pop_back().unwrap()).is_none());

        let (message, delivery_instructions) =
            handler.middle_fragment(message_id, 2, &fragments.pop_front().unwrap()).unwrap();

        assert_eq!(
            message.expiration,
            Duration::from_millis(expiration.as_millis() as u64)
        );
        assert_eq!(message.message_id, 1338u32);
        assert_eq!(message.message_type, MessageType::Data);
        assert_eq!(message.payload, vec![0u8; 1337]);
    }
}
