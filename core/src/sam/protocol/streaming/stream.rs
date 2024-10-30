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

use crate::runtime::Runtime;

use thingbuf::mpsc::{Receiver, Sender};

use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// I2P virtual stream.
///
/// Implements a `Future` which returns the send stream ID after the virtual stream has been shut
/// down, either by the client or by the remote participant.
pub struct Stream<R: Runtime> {
    /// Underlying TCP stream used to communicate with the client.
    stream: R::TcpStream,

    /// RX channel for receiving [`Packet`]s from the network.
    cmd_rx: Receiver<Vec<u8>>,

    /// TX channel for sending [`Packet`]s to the network.
    event_tx: Sender<Vec<u8>>,
}

impl<R: Runtime> Future for Stream<R> {
    type Output = u32;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}
