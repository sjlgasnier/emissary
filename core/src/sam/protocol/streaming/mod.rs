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
    crypto::SigningPrivateKey,
    error::StreamingError,
    primitives::{Destination as Dest, DestinationId},
    runtime::Runtime,
    sam::{
        protocol::streaming::packet::{Packet, PacketBuilder, PeekInfo},
        socket::SamSocket,
    },
    Error,
};

use bytes::{BufMut, BytesMut};
use hashbrown::HashMap;
use thingbuf::mpsc::{channel, Receiver, Sender};

use alloc::{collections::VecDeque, vec::Vec};
use core::{marker::PhantomData, time::Duration};

mod config;
mod packet;
mod stream;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::sam::streaming";

/// [`StreamManager`]'s message channel size.
///
/// Size of the channel used by all virtual streams to send messages to the network.
const STREAM_MANAGER_CHANNEL_SIZE: usize = 4096;

/// [`Stream`]'s message channel size.
///
/// Size of the channel used to send messages received from the network to a virtual stream.
const STREAM_CHANNEL_SIZE: usize = 512;

/// How long is an inbound stream kept pending if there are no listeners before it's closed.
const PENDING_STREAM_TIMEOUT: Duration = Duration::from_secs(30);

/// Signature length.
const SIGNATURE_LEN: usize = 64usize;

/// Virtual stream listener kind.
pub enum ListenerKind<R: Runtime> {
    /// Listener used to accept one inbound virtual stream (`STREAM ACCEPT`).
    Ephemeral {
        /// SAMv3 socket used to communicate with the client.
        socket: SamSocket<R>,

        /// Has the stream configured to be silent.
        silent: bool,
    },

    /// Listener used to accept all inbound virtual stream (`STREAM FORWARD`).
    Persistent {
        /// SAMv3 socket used the client used to send the `STREAM FORWARD` command.
        socket: SamSocket<R>,

        /// Port which the persistent TCP listener is listening on.
        port: u16,

        /// Has the stream configured to be silent.
        silent: bool,
    },
}

/// I2P virtual stream manager.
pub struct StreamManager<R: Runtime> {
    /// TX channels for sending [`Packet`]'s to active streams.
    ///
    /// Indexed with receive stream ID.
    active: HashMap<u32, Sender<Vec<u8>>>,

    /// ID of the `Destination` the stream manager is bound to.
    destination_id: DestinationId,

    /// Ephemeral listeners.
    listeners: VecDeque<SamSocket<R>>,

    /// RX channel for receiving [`Packet`]s from active streams.
    outbound_rx: Receiver<Vec<u8>>,

    /// TX channel given to active streams they use for sending messages to the network.
    outbound_tx: Sender<Vec<u8>>,

    /// Signing key.
    signing_key: SigningPrivateKey,
}

impl<R: Runtime> StreamManager<R> {
    /// Create new [`StreamManager`].
    pub fn new(destination_id: DestinationId, signing_key: SigningPrivateKey) -> Self {
        let (outbound_tx, outbound_rx) = channel(STREAM_MANAGER_CHANNEL_SIZE);

        Self {
            active: HashMap::new(),
            destination_id,
            listeners: VecDeque::new(),
            outbound_rx,
            outbound_tx,
            signing_key,
        }
    }

    /// Handle message with `SYN`.
    ///
    /// Ensure that signature and destination are in the message and verify their validity.
    /// Additionally ensure that the NACK field contains local destination's ID.
    ///
    /// If validity checks pass, send the message to a listener if it exists.
    fn on_synchronize(&mut self, packet: Vec<u8>) -> Result<(), StreamingError> {
        let Packet {
            send_stream_id,
            recv_stream_id,
            seq_nro,
            ack_through,
            nacks,
            resend_delay,
            flags,
            payload,
        } = Packet::parse(&packet).ok_or(StreamingError::Malformed)?;

        let signature = flags.signature().ok_or(StreamingError::SignatureMissing)?;
        let destination =
            flags.from_included().as_ref().ok_or(StreamingError::DestinationMissing)?;

        // verify that the nacks field contains local destination id for replay protection
        {
            let destination_id = nacks
                .into_iter()
                .fold(BytesMut::with_capacity(32), |mut acc, x| {
                    acc.put_slice(&x.to_be_bytes());
                    acc
                })
                .freeze()
                .to_vec();

            if destination_id != self.destination_id.to_vec() {
                return Err(StreamingError::ReplayProtectionCheckFailed);
            }
        }

        // verify signature
        {
            match destination.verifying_key() {
                None => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        "verifying key missing from destination",
                    );
                    return Err(StreamingError::VerifyingKeyMissing);
                }
                Some(verifying_key) => {
                    // signature field is the last field of options, meaning it starts at
                    // `original.len() - payload.len() - SIGNATURE_LEN`
                    //
                    // in order to verify the signature, the calculated signature must be filled
                    // with zeros
                    let mut original = packet.to_vec();
                    let signature_start = original.len() - payload.len() - SIGNATURE_LEN;
                    original[signature_start..signature_start + SIGNATURE_LEN]
                        .copy_from_slice(&[0u8; 64]);

                    verifying_key.verify_new(&original, signature).map_err(|error| {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?error,
                            "failed to verify packet signature"
                        );

                        StreamingError::InvalidSignature
                    })?;
                }
            }
        }

        tracing::info!(
            target: LOG_TARGET,
            local = %self.destination_id,
            payload_len = ?payload.len(),
            "inbound stream accepted",
        );

        // TODO: send `SYN` reply
        // TODO: implement packet builder

        // TODO: if there is an ephemeral listener, pop and create `Stream` future
        // TODO: if there is a persistent listener, connect to the listener
        // TODO: if there are no listeners, create timer for expiring a the connection
        // TODO: if listener is persisten, how to do handle initialization cleanly?

        Ok(())
    }

    /// Register listener into [`StreamManager`].
    ///
    /// If `kind` is [`ListenerKind::Ephemeral`], push the listener into a set of pending listeners
    /// from which it will be taken when an inbound stream is received.
    ///
    /// If `kind` is [`ListenerKind::Persistent`], the store the port of the active TCP listener (on
    /// client side) into [`StreamManager`]'s context and when an inbond stream is received,
    /// establish new connection to the TCP listener.
    ///
    /// Active `STREAM ACCEPT` and `STREAM FORWARD` are mutually exclusive as per the specification.
    //
    // TODO: finish this comment
    pub fn register_listener(&mut self, kind: ListenerKind<R>) -> Result<(), StreamingError> {
        match (kind, self.listeners.is_empty()) {
            (ListenerKind::Ephemeral { socket, silent }, true) => {
                tracing::trace!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    "add new ephemeral listener",
                );
            }
            (ListenerKind::Persistent { .. }, true) => {
                todo!();
            }
            _ => {}
        }

        Ok(())
    }

    /// Handle `payload` received from `src_port` to `dst_port`.
    pub fn on_message(
        &mut self,
        src_port: u16,
        dst_port: u16,
        payload: Vec<u8>,
    ) -> Result<(), StreamingError> {
        let packet = Packet::peek(&payload).ok_or(StreamingError::Malformed)?;

        // handle new stream
        //
        // both deserialized packet and the original payload are returned
        // so the included signature can be verified
        if packet.synchronize() {
            return self.on_synchronize(payload);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{
        mock::{MockRuntime, MockTcpStream},
        TcpStream,
    };
    use bytes::{BufMut, BytesMut};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn register_ephemeral_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let (mut stream, _) = stream1.unwrap();
        let mut socket = SamSocket::<MockRuntime>::new(stream2.unwrap());
    }

    #[tokio::test]
    async fn inbound_stream() {
        let destination_id = DestinationId::from([
            200, 35, 63, 139, 109, 209, 249, 106, 242, 177, 156, 87, 29, 241, 241, 117, 75, 81,
            133, 124, 14, 246, 56, 138, 8, 201, 219, 160, 118, 181, 191, 27,
        ]);
        let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
        let mut mananger = StreamManager::<MockRuntime>::new(destination_id, signing_key);

        let payload = vec![
            0, 0, 0, 0, 148, 23, 180, 82, 0, 0, 0, 0, 0, 0, 0, 0, 8, 200, 35, 63, 139, 109, 209,
            249, 106, 242, 177, 156, 87, 29, 241, 241, 117, 75, 81, 133, 124, 14, 246, 56, 138, 8,
            201, 219, 160, 118, 181, 191, 27, 9, 4, 169, 1, 201, 38, 195, 17, 125, 194, 201, 147,
            121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183,
            252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209,
            227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138,
            76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54,
            140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125,
            194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60,
            244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4,
            113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44,
            250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89,
            81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195,
            17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54,
            252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147,
            121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183,
            252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209,
            227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138,
            76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54,
            140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125,
            194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60,
            244, 107, 183, 252, 44, 250, 248, 138, 76, 180, 60, 50, 18, 127, 20, 227, 77, 70, 183,
            45, 98, 87, 86, 53, 211, 46, 229, 46, 211, 83, 237, 74, 202, 66, 177, 167, 84, 212,
            142, 59, 123, 5, 0, 4, 0, 7, 0, 0, 7, 20, 34, 64, 253, 113, 136, 137, 7, 144, 142, 165,
            147, 51, 145, 79, 234, 74, 126, 166, 86, 159, 203, 103, 202, 205, 154, 245, 129, 74,
            180, 253, 6, 52, 63, 37, 90, 147, 60, 180, 195, 134, 209, 104, 48, 24, 178, 46, 155,
            216, 187, 51, 17, 73, 220, 156, 1, 23, 130, 84, 245, 197, 171, 40, 76, 5,
        ];

        assert!(mananger.on_message(13, 37, payload).is_ok());
    }

    #[tokio::test]
    async fn invalid_signature() {
        let destination_id = DestinationId::from([
            200, 35, 63, 139, 109, 209, 249, 106, 242, 177, 156, 87, 29, 241, 241, 117, 75, 81,
            133, 124, 14, 246, 56, 138, 8, 201, 219, 160, 118, 181, 191, 27,
        ]);
        let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
        let mut mananger = StreamManager::<MockRuntime>::new(destination_id, signing_key);

        let payload = vec![
            0, 0, 0, 0, 148, 23, 180, 82, 0, 0, 0, 0, 0, 0, 0, 0, 8, 200, 35, 63, 139, 109, 209,
            249, 106, 242, 177, 156, 87, 29, 241, 241, 117, 75, 81, 133, 124, 14, 246, 56, 138, 8,
            201, 219, 160, 118, 181, 191, 27, 9, 4, 169, 1, 201, 38, 195, 17, 125, 194, 201, 147,
            121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183,
            252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209,
            227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138,
            76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54,
            140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125,
            194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60,
            244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4,
            113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44,
            250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89,
            81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195,
            17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54,
            252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147,
            121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183,
            252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209,
            227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138,
            76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54,
            140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125,
            194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60,
            244, 107, 183, 252, 44, 250, 248, 138, 76, 180, 60, 50, 18, 127, 20, 227, 77, 70, 183,
            45, 98, 87, 86, 53, 211, 46, 229, 46, 211, 83, 237, 74, 202, 66, 177, 167, 84, 212,
            142, 59, 123, 5, 0, 4, 0, 7, 0, 0, 7, 20, 34, 64, 253, 113, 136, 137, 7, 144, 142, 165,
            147, 51, 145, 79, 234, 74, 126, 166, 86, 159, 203, 103, 202, 205, 154, 245, 129, 74,
            180, 253, 6, 52, 63, 37, 90, 147, 60, 180, 195, 134, 209, 104, 48, 24, 178, 46, 155,
            216, 187, 51, 17, 73, 220, 156, 1, 23, 130, 84, 245, 197, 171, 40, 76, 6,
        ];

        assert_eq!(
            mananger.on_message(13, 37, payload),
            Err(StreamingError::InvalidSignature)
        );
    }

    #[tokio::test]
    async fn invalid_destination_id() {
        let destination_id = DestinationId::from([
            200, 200, 200, 139, 109, 209, 249, 106, 242, 177, 156, 87, 29, 241, 241, 117, 75, 81,
            133, 124, 14, 246, 56, 138, 8, 201, 219, 160, 118, 181, 191, 27,
        ]);
        let signing_key = SigningPrivateKey::new(&[0u8; 32]).unwrap();
        let mut mananger = StreamManager::<MockRuntime>::new(destination_id, signing_key);

        let payload = vec![
            0, 0, 0, 0, 148, 23, 180, 82, 0, 0, 0, 0, 0, 0, 0, 0, 8, 200, 35, 63, 139, 109, 209,
            249, 106, 242, 177, 156, 87, 29, 241, 241, 117, 75, 81, 133, 124, 14, 246, 56, 138, 8,
            201, 219, 160, 118, 181, 191, 27, 9, 4, 169, 1, 201, 38, 195, 17, 125, 194, 201, 147,
            121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183,
            252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209,
            227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138,
            76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54,
            140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125,
            194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60,
            244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4,
            113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44,
            250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89,
            81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195,
            17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54,
            252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147,
            121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183,
            252, 44, 250, 248, 138, 76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209,
            227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138,
            76, 38, 195, 17, 125, 194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54,
            140, 254, 54, 252, 60, 244, 107, 183, 252, 44, 250, 248, 138, 76, 38, 195, 17, 125,
            194, 201, 147, 121, 4, 113, 230, 209, 227, 66, 89, 81, 115, 54, 140, 254, 54, 252, 60,
            244, 107, 183, 252, 44, 250, 248, 138, 76, 180, 60, 50, 18, 127, 20, 227, 77, 70, 183,
            45, 98, 87, 86, 53, 211, 46, 229, 46, 211, 83, 237, 74, 202, 66, 177, 167, 84, 212,
            142, 59, 123, 5, 0, 4, 0, 7, 0, 0, 7, 20, 34, 64, 253, 113, 136, 137, 7, 144, 142, 165,
            147, 51, 145, 79, 234, 74, 126, 166, 86, 159, 203, 103, 202, 205, 154, 245, 129, 74,
            180, 253, 6, 52, 63, 37, 90, 147, 60, 180, 195, 134, 209, 104, 48, 24, 178, 46, 155,
            216, 187, 51, 17, 73, 220, 156, 1, 23, 130, 84, 245, 197, 171, 40, 76, 5,
        ];

        assert_eq!(
            mananger.on_message(13, 37, payload),
            Err(StreamingError::ReplayProtectionCheckFailed)
        );
    }
}
