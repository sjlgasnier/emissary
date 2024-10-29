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
    crypto::{base64_encode, SigningPrivateKey, StaticPrivateKey},
    destination::{Destination, DestinationEvent},
    i2cp::I2cpPayload,
    i2np::{
        database::store::{DatabaseStoreBuilder, DatabaseStoreKind, DatabaseStorePayload},
        MessageBuilder, MessageType, I2NP_MESSAGE_EXPIRATION,
    },
    netdb::NetDbHandle,
    primitives::{Destination as Dest, LeaseSet2, LeaseSet2Header},
    protocol::Protocol,
    runtime::Runtime,
    sam::{
        parser::{SamCommand, SamVersion},
        pending::session::SamSessionContext,
        socket::SamSocket,
    },
    tunnel::{TunnelPoolEvent, TunnelPoolHandle},
};

use bytes::{BufMut, Bytes, BytesMut};
use futures::StreamExt;
use hashbrown::HashMap;
use rand_core::RngCore;
use thingbuf::mpsc::Receiver;

use alloc::sync::Arc;
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::sam::session";

/// Recycling strategy for [`SamSessionCommand`].
#[derive(Default, Clone)]
pub(super) struct SamSessionCommandRecycle(());

impl<R: Runtime> thingbuf::Recycle<SamSessionCommand<R>> for SamSessionCommandRecycle {
    fn new_element(&self) -> SamSessionCommand<R> {
        SamSessionCommand::Dummy
    }

    fn recycle(&self, element: &mut SamSessionCommand<R>) {
        *element = SamSessionCommand::Dummy;
    }
}

/// SAMv3 session commands.
pub enum SamSessionCommand<R: Runtime> {
    /// Open virtual stream to `destination` over this connection.
    Stream {
        /// SAMv3 socket associated with the outbound stream.
        socket: SamSocket<R>,

        /// Destination.
        destination: String,

        /// Options.
        options: HashMap<String, String>,
    },

    /// Accept inbond virtual stream over this connection.
    Accept {
        /// SAMv3 socket associated with the inbound stream.
        socket: SamSocket<R>,

        /// Options.
        options: HashMap<String, String>,
    },

    /// Forward incoming virtual streams to a TCP listener listening to `port`.
    Forward {
        /// SAMv3 socket associated with forwarding.
        socket: SamSocket<R>,

        /// Port which the TCP listener is listening.
        port: u16,

        /// Options.
        options: HashMap<String, String>,
    },

    /// Dummy event, never constructed.
    Dummy,
}

impl<R: Runtime> Default for SamSessionCommand<R> {
    fn default() -> Self {
        Self::Dummy
    }
}

/// Active SAMv3 session.
pub struct SamSession<R: Runtime> {
    /// [`Destination`] of the session.
    destination: Destination<R>,

    /// Session options.
    options: HashMap<String, String>,

    /// Receiver for commands sent for this session.
    ///
    /// Commands are dispatched by `SamServer` which ensures that [`SamCommand::CreateSession`]
    /// is never received by an active session.
    receiver: Receiver<SamSessionCommand<R>, SamSessionCommandRecycle>,

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
            mut socket,
            tunnel_pool_handle,
            version,
            netdb_handle,
        } = context;

        let (destination, privkey) = {
            // create encryption and signing keys as this is a transient session
            let (encryption_key, signing_key) = {
                let mut rng = R::rng();

                let signing_key = SigningPrivateKey::random(&mut rng);
                let encryption_key = StaticPrivateKey::new(rng);

                (encryption_key, signing_key)
            };

            let destination = Dest::new(signing_key.public());
            let destination_id = destination.id();

            // from specification:
            //
            // "The $privkey is the base 64 of the concatenation of the Destination followed by the
            // Private Key followed by the Signing Private Key, optionally followed by the Offline
            // Signature, which is 663 or more bytes in binary and 884 or more bytes in base 64,
            // depending on signature type. The binary format is specified in Private Key File."
            let privkey = {
                let mut out = BytesMut::with_capacity(destination.serialized_len() + 2 * 32);
                out.put_slice(&destination.serialize());
                out.put_slice(encryption_key.as_ref());
                out.put_slice(signing_key.as_ref());

                base64_encode(out)
            };

            // create leaseset for the destination and store it in `NetDb`
            let local_leaseset = Bytes::from(
                LeaseSet2 {
                    header: LeaseSet2Header {
                        destination: destination.clone(),
                        published: R::time_since_epoch().as_secs() as u32,
                        expires: (R::time_since_epoch() + Duration::from_secs(10 * 60)).as_secs()
                            as u32,
                    },
                    public_keys: vec![encryption_key.public()],
                    leases: inbound.values().cloned().collect(),
                }
                .serialize(&signing_key),
            );

            if let Err(error) = netdb_handle
                .store_leaseset(Bytes::from(destination_id.to_vec()), local_leaseset.clone())
            {
                tracing::warn!(
                    target: LOG_TARGET,
                    %destination_id,
                    ?error,
                    "failed to publish lease set"
                );
                todo!();
            }

            tracing::info!(
                target: LOG_TARGET,
                %session_id,
                %destination_id,
                "start active session",
            );

            (
                Destination::new(destination_id, encryption_key, local_leaseset, netdb_handle),
                privkey,
            )
        };

        socket.send_message(
            format!("SESSION STATUS RESULT=OK DESTINATION={privkey}\n").as_bytes().to_vec(),
        );

        Self {
            destination,
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
            TunnelPoolEvent::Message { message } => match self.destination.decrypt_message(message)
            {
                Err(error) => tracing::debug!(
                    target: LOG_TARGET,
                    session_id = ?self.session_id,
                    ?error,
                    "failed to decrypt garlic message",
                ),
                Ok(messages) =>
                    messages.for_each(|message| match I2cpPayload::decompress::<R>(message) {
                        Some(I2cpPayload {
                            dst_port,
                            payload,
                            protocol,
                            src_port,
                        }) => {
                            tracing::trace!(
                                target: LOG_TARGET,
                                session_id = ?self.session_id,
                                ?dst_port,
                                ?src_port,
                                ?protocol,
                                "handle protocol payload",
                            );
                        }
                        None => tracing::warn!(
                            target: LOG_TARGET,
                            session_id = ?self.session_id,
                            "failed to decompress i2cp payload",
                        ),
                    }),
            },
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
                Poll::Ready(Some(SamSessionCommand::Stream {
                    socket,
                    destination,
                    options,
                })) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        session_id = %self.session_id,
                        %destination,
                        "connect to destination",
                    );
                }
                Poll::Ready(Some(SamSessionCommand::Accept { socket, options })) => tracing::warn!(
                    target: LOG_TARGET,
                    session_id = %self.session_id,
                    "unhandled `STREAM ACCEPT`",
                ),
                Poll::Ready(Some(SamSessionCommand::Forward {
                    socket,
                    port,
                    options,
                })) => tracing::warn!(
                    target: LOG_TARGET,
                    session_id = %self.session_id,
                    "unhandled `STREAM FORWARD`",
                ),
                Poll::Ready(Some(SamSessionCommand::Dummy)) => unreachable!(),
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

        loop {
            match self.destination.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(Arc::clone(&self.session_id)),
                Poll::Ready(Some(DestinationEvent::SendMessage {
                    router_id,
                    tunnel_id,
                    message,
                })) => {
                    // wrap the garlic message inside a standard i2np message and send it over
                    // the one of the pool's outbound tunnels to remote destination
                    let message = MessageBuilder::standard()
                        .with_message_type(MessageType::Garlic)
                        .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
                        .with_message_id(R::rng().next_u32())
                        .with_payload(&message)
                        .build();

                    if let Err(error) =
                        self.tunnel_pool_handle.send_to_tunnel(router_id, tunnel_id, message)
                    {
                        tracing::warn!(
                            target: LOG_TARGET,
                            session_id = %self.session_id,
                            ?error,
                            "failed to send message to tunnel",
                        );
                    }
                }
            }
        }

        Poll::Pending
    }
}
