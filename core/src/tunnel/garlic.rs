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
    crypto::{chachapoly::ChaChaPoly, EphemeralPublicKey},
    error::TunnelError,
    i2np::{
        self, tunnel::gateway::TunnelGateway, GarlicMessage, GarlicMessageBlock, Message,
        MessageBuilder,
    },
    primitives::{RouterId, TunnelId},
    runtime::Runtime,
    tunnel::new_noise::NoiseContext,
    Error,
};

use alloc::{vec, vec::Vec};
use core::time::Duration;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::garlic";

/// Garlic clove delivery instructions
pub enum DeliveryInstructions {
    /// Message meant for the local router.
    Local {
        /// I2NP message
        message: Message,
    },

    /// Message meant for router delivery.
    Router {
        /// Router.
        router: RouterId,

        /// Serialized I2NP message.
        message: Vec<u8>,
    },

    /// Message meant for tunnel delivery.
    Tunnel {
        /// Tunnel ID.
        tunnel: TunnelId,

        /// Router.
        router: RouterId,

        /// Serialized I2NP message wrapped in `TunnelGateway` message.
        message: Vec<u8>,
    },

    /// Unimplemented.
    Destination,
}

/// Garlic message handler.
pub struct GarlicHandler<R: Runtime> {
    /// Noise context.
    noise: NoiseContext,

    /// Metrics handle.
    metrics_handle: R::MetricsHandle,
}

impl<R: Runtime> GarlicHandler<R> {
    /// Create new [`GarlicHandler`].
    pub fn new(noise: NoiseContext, metrics_handle: R::MetricsHandle) -> Self {
        Self {
            noise,
            metrics_handle,
        }
    }

    /// Handle garlic message.
    pub fn handle_message(
        &mut self,
        message: Message,
    ) -> crate::Result<impl Iterator<Item = DeliveryInstructions>> {
        let Message {
            message_type,
            message_id,
            expiration,
            payload,
        } = message;

        tracing::trace!(
            target: LOG_TARGET,
            ?message_id,
            ?expiration,
            "garlic message",
        );

        if payload.len() < 36 {
            tracing::warn!(
                target: LOG_TARGET,
                ?message_id,
                ?expiration,
                "garlic message is too short",
            );

            return Err(Error::Tunnel(TunnelError::InvalidMessage));
        }

        // derive cipher key and associated data and decrypt the garlic message
        let message = {
            let (mut cipher_key, associated_data) = self.noise.derive_garlic_key(
                EphemeralPublicKey::try_from(&payload[4..36]).expect("valid public key"),
            );

            let mut message = payload[36..].to_vec();
            ChaChaPoly::new(&cipher_key).decrypt_with_ad(&associated_data, &mut message)?;

            message
        };

        let messages = GarlicMessage::parse(&message)
            .ok_or(Error::Tunnel(TunnelError::InvalidMessage))?
            .blocks
            .into_iter()
            .filter_map(|block| match block {
                GarlicMessageBlock::GarlicClove {
                    message_type,
                    message_id,
                    expiration,
                    delivery_instructions,
                    message_body,
                } => match delivery_instructions {
                    i2np::DeliveryInstructions::Local => Some(DeliveryInstructions::Local {
                        message: Message {
                            message_type,
                            message_id,
                            expiration: expiration.into(),
                            payload: message_body.to_vec(), // TODO: is this really needed
                        },
                    }),
                    i2np::DeliveryInstructions::Router { hash } =>
                        Some(DeliveryInstructions::Router {
                            router: RouterId::from(hash),
                            message: MessageBuilder::short()
                                .with_message_type(message_type)
                                .with_message_id(message_id)
                                .with_expiration(expiration)
                                .with_payload(&message_body)
                                .build(),
                        }),
                    i2np::DeliveryInstructions::Tunnel { hash, tunnel_id } => {
                        let message = MessageBuilder::standard()
                            .with_message_type(message_type)
                            .with_message_id(message_id)
                            .with_expiration(expiration)
                            .with_payload(&message_body)
                            .build();

                        let message = TunnelGateway {
                            tunnel_id: tunnel_id.into(),
                            payload: message_body,
                        }
                        .serialize();

                        Some(DeliveryInstructions::Tunnel {
                            tunnel: TunnelId::from(tunnel_id),
                            router: RouterId::from(hash),
                            message: MessageBuilder::short()
                                .with_message_type(message_type)
                                .with_message_id(message_id)
                                // TODO: fix expiration
                                .with_expiration(
                                    (R::time_since_epoch() + Duration::from_secs(5 * 60)).as_secs(),
                                )
                                .with_payload(&message)
                                .build(),
                        })
                    }
                    i2np::DeliveryInstructions::Destination { hash } => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?hash,
                            "ignoring destination",
                        );
                        None
                    }
                },
                block => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        ?block,
                        "ignoring garlic block",
                    );
                    None
                }
            })
            .collect::<Vec<_>>();

        Ok(messages.into_iter())
    }
}
