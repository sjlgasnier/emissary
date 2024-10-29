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

// use bytes::{BufMut, BytesMut};
// use nom::{
//     bytes::complete::take,
//     error::{make_error, ErrorKind},
//     number::complete::{be_u16, be_u32, be_u8},
//     Err, IResult,
// };
// use rand_core::RngCore;

// use alloc::{collections::VecDeque, vec::Vec};
// use core::{
//     marker::PhantomData,
//     pin::Pin,
//     task::{Context, Poll, Waker},
// };

// /// Logging target for the file.
// const LOG_TARGET: &str = "emissary::protocol::streaming";

// /// Stream state.
// enum StreamState {
//     /// Outbound stream has been initiated.
//     OutboundInitiated {
//         /// Receive stream ID.
//         recv_stream_id: u32,

//         /// Sequence number.
//         seq_nro: u32,
//     },

//     /// Stream is open.
//     Open {
//         /// Receive stream ID.
//         recv_stream_id: u32,

//         /// Send stream ID.
//         send_stream_id: u32,

//         /// Sequence number.
//         seq_nro: u32,
//     },
// }

// impl StreamState {
//     /// Get receive stream ID.
//     fn recv_stream_id(&self) -> u32 {
//         match self {
//             Self::OutboundInitiated { recv_stream_id, .. } => *recv_stream_id,
//             Self::Open { recv_stream_id, .. } => *recv_stream_id,
//         }
//     }
// }

// /// Streaming protocol instance.
// pub struct Stream<R: Runtime> {
//     /// Stream state.
//     state: StreamState,

//     /// Pending events.
//     pending_events: VecDeque<StreamEvent>,

//     /// Waker.
//     waker: Option<Waker>,

//     /// Marker for `Runtime`.
//     _runtime: PhantomData<R>,
// }

// impl<R: Runtime> Stream<R> {
//     /// Create new outbound [`Stream`].
//     pub fn new_outbound(destination: Dest) -> (Self, BytesMut) {
//         let mut payload = "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent:
// Mozilla/5.0\r\nAccept: text/html\r\n\r\n".as_bytes();         let mut out =
// BytesMut::with_capacity(payload.len() + 22 + destination.serialized_len());

//         let recv_stream_id = R::rng().next_u32();
//         let seq_nro = 0u32;

//         out.put_u32(0u32); // send stream id
//         out.put_u32(recv_stream_id);
//         out.put_u32(seq_nro);
//         out.put_u32(0u32); // ack through
//         out.put_u8(0u8); // nack count

//         // TODO: signature
//         out.put_u8(10u8); // resend delay, in seconds
//         out.put_u16(0x01 | 0x20); // flags: `SYN` + `FROM_INCLUDED`

//         out.put_u16(destination.serialized_len() as u16);
//         out.put_slice(&destination.serialize());
//         out.put_slice(&payload);

//         // out.put_u16(0x01 | 0x03 | 0x20); // flags: `SYN` + `SIGNATURE_INCLUDED` +
// `FROM_INCLUDED`

//         tracing::error!(
//             target: LOG_TARGET,
//             destination = %destination.id(),
//             ?recv_stream_id,
//             "new outbound stream",
//         );

//         (
//             Self {
//                 state: StreamState::OutboundInitiated {
//                     recv_stream_id,
//                     seq_nro,
//                 },
//                 pending_events: VecDeque::new(),
//                 waker: None,
//                 _runtime: Default::default(),
//             },
//             out,
//         )
//     }

//     /// Handle streaming protocol packet.
//     ///
//     /// Returns a serialized [`Packet`] if `payload` warrants sending a reply to remote.
//     pub fn handle_packet(&mut self, payload: &[u8]) -> crate::Result<()> {
//         let Packet {
//             send_stream_id,
//             recv_stream_id,
//             seq_nro,
//             ack_through,
//             flags,
//             payload,
//             nacks,
//             ..
//         } = Packet::parse(payload).ok_or_else(|| {
//             tracing::warn!(
//                 target: LOG_TARGET,
//                 recv_stream_id = ?self.state.recv_stream_id(),
//                 "failed to parse streaming protocol packet",
//             );

//             Error::InvalidData
//         })?;

//         if self.state.recv_stream_id() != send_stream_id {
//             tracing::warn!(
//                 target: LOG_TARGET,
//                 recv_stream_id = ?self.state.recv_stream_id(),
//                 ?send_stream_id,
//                 "stream id mismatch",
//             );

//             return Err(Error::Streaming(StreamingError::StreamIdMismatch(
//                 send_stream_id,
//                 self.state.recv_stream_id(),
//             )));
//         }

//         tracing::info!("ack received = {ack_through}, sequence number = {seq_nro:}");
//         tracing::error!("payload = {:?}", core::str::from_utf8(payload));

//         if (flags & 0x02) == 0x02 {
//             tracing::info!("stream closed");

//             self.pending_events.push_back(StreamEvent::StreamClosed {
//                 recv_stream_id: self.state.recv_stream_id(),
//                 send_stream_id: recv_stream_id,
//             });
//         }

//         let mut out = BytesMut::with_capacity(22);

//         out.put_u32(recv_stream_id); // send stream id
//         out.put_u32(self.state.recv_stream_id());
//         out.put_u32(0);
//         out.put_u32(seq_nro); // ack through
//         out.put_u8(0u8); // nack count

//         out.put_u8(10u8); // resend delay, in seconds
//         out.put_u16(0); // no flags

//         if core::matches!(self.state, StreamState::OutboundInitiated { .. }) {
//             self.pending_events.push_back(StreamEvent::StreamOpened {
//                 recv_stream_id: self.state.recv_stream_id(),
//                 send_stream_id: recv_stream_id,
//             });
//         }

//         self.state = StreamState::Open {
//             recv_stream_id: self.state.recv_stream_id(),
//             send_stream_id: recv_stream_id,
//             seq_nro: 1,
//         };

//         self.pending_events.push_back(StreamEvent::SendPacket { packet: out });
//         self.waker.take().map(|waker| waker.wake_by_ref());

//         Ok(())
//     }
// }

// /// Events emitted by [`Stream`].
// pub enum StreamEvent {
//     /// Stream has been opened.
//     StreamOpened {
//         /// Receive stream ID.
//         recv_stream_id: u32,

//         /// Send stream ID.
//         send_stream_id: u32,
//     },

//     /// Stream has been closed.
//     StreamClosed {
//         /// Receive stream ID.
//         recv_stream_id: u32,

//         /// Send stream ID.
//         send_stream_id: u32,
//     },

//     /// Send packet to remote peer.
//     SendPacket {
//         /// Serialized [`Packet`].
//         packet: BytesMut,
//     },
// }

// impl<R: Runtime> futures::Stream for Stream<R> {
//     type Item = StreamEvent;

//     fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
//         self.pending_events.pop_front().map_or_else(
//             || {
//                 self.waker = Some(cx.waker().clone());
//                 Poll::Pending
//             },
//             |event| Poll::Ready(Some(event)),
//         )
//     }
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::{
//         crypto::{SigningPrivateKey, SigningPublicKey},
//         runtime::{mock::MockRuntime, Runtime},
//     };
//     use futures::StreamExt;

//     #[tokio::test]
//     async fn stream_id_mismatch() {
//         let destination =
//             Dest::new(SigningPublicKey::from_private_ed25519(&vec![1u8; 32]).unwrap());
//         let (mut stream, packet) = Stream::<MockRuntime>::new_outbound(destination.clone());
//         let payload = "hello, world".as_bytes();

//         let mut out = BytesMut::with_capacity(payload.len() + 22 + destination.serialized_len());

//         let recv_stream_id = MockRuntime::rng().next_u32();
//         let seq_nro = 0u32;

//         out.put_u32(stream.state.recv_stream_id().overflowing_add(1).0);
//         out.put_u32(recv_stream_id);
//         out.put_u32(seq_nro);
//         out.put_u32(0u32); // ack through
//         out.put_u8(0u8); // nack count

//         out.put_u8(10u8); // resend delay, in seconds
//         out.put_u16(0x01 | 0x20); // flags: `SYN` + `FROM_INCLUDED`

//         out.put_u16(destination.serialized_len() as u16);
//         out.put_slice(&destination.serialize());
//         out.put_slice(&payload);

//         match stream.handle_packet(out.as_ref()).unwrap_err() {
//             Error::Streaming(StreamingError::StreamIdMismatch(send, recv)) => {
//                 assert_eq!(send, stream.state.recv_stream_id().overflowing_add(1).0);
//                 assert_eq!(recv, stream.state.recv_stream_id());
//             }
//             _ => panic!("invalid error"),
//         }
//     }
// }

use crate::{
    error::StreamingError,
    primitives::{Destination as Dest, DestinationId},
    runtime::Runtime,
    Error,
};

use bytes::{BufMut, BytesMut};

use alloc::vec::Vec;

mod config;
mod packet;

pub use packet::Packet;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::protocol::streaming";

/// I2P virtual stream manager.
pub struct StreamManager<R: Runtime> {
    /// ID of the `Destination` the stream manager is bound to.
    destination_id: DestinationId,

    _runtime: core::marker::PhantomData<R>,
}

impl<R: Runtime> StreamManager<R> {
    /// Create new [`StreamManager`].
    pub fn new(destination_id: DestinationId) -> Self {
        Self {
            destination_id,
            _runtime: Default::default(),
        }
    }

    /// Handle message with `SYN`.
    ///
    /// Ensure that signature and destination are in the message and verify their validity.
    /// Additionally ensure that the NACK field contains local destination's ID.
    ///
    /// If validity checks pass, send the message to a listener if it exists.
    fn on_synchronize(&mut self, original: &[u8], packet: Packet) -> Result<(), StreamingError> {
        let Packet {
            send_stream_id,
            recv_stream_id,
            seq_nro,
            ack_through,
            nacks,
            resend_delay,
            flags,
            payload,
        } = packet;

        let signature = flags.signature().ok_or(StreamingError::SignatureMissing)?;
        let destination =
            flags.from_included().as_ref().ok_or(StreamingError::DestinationMissing)?;

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
                    let mut original = original.to_vec();
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

        Ok(())
    }

    /// Handle `payload` received from `src_port` to `dst_port`.
    pub fn on_message(
        &mut self,
        src_port: u16,
        dst_port: u16,
        payload: Vec<u8>,
    ) -> Result<(), StreamingError> {
        let packet = Packet::parse(&payload).ok_or(StreamingError::Malformed)?;

        // handle new stream
        //
        // both deserialized packet and the original payload are returned
        // so the included signature can be verified
        if packet.flags.synchronize() {
            return self.on_synchronize(&payload, packet);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;
    use bytes::{BufMut, BytesMut};

    #[tokio::test]
    async fn inbound_stream() {
        let destination_id = DestinationId::from([
            200, 35, 63, 139, 109, 209, 249, 106, 242, 177, 156, 87, 29, 241, 241, 117, 75, 81,
            133, 124, 14, 246, 56, 138, 8, 201, 219, 160, 118, 181, 191, 27,
        ]);
        let mut mananger = StreamManager::<MockRuntime>::new(destination_id);

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
    async fn invalid_destination_id() {
        let destination_id = DestinationId::from([
            200, 200, 200, 139, 109, 209, 249, 106, 242, 177, 156, 87, 29, 241, 241, 117, 75, 81,
            133, 124, 14, 246, 56, 138, 8, 201, 219, 160, 118, 181, 191, 27,
        ]);
        let mut mananger = StreamManager::<MockRuntime>::new(destination_id);

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
