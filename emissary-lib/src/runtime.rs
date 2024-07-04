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

use futures_lite::{AsyncRead, AsyncWrite, Future};

use core::task::Context;

pub trait TcpStream: AsyncRead + AsyncWrite + Send + Sized {
    async fn close(&mut self);
}

pub trait TcpListener<TcpStream>: Send + Sized {
    fn bind(address: &str) -> Self;
    async fn accept(&mut self) -> Option<TcpStream>;
}

pub trait UdpSocket: Send + Sized {
    fn connect(address: &str);
    fn bind(address: &str);

    fn poll_recv_from(&mut self, buffer: &mut &[u8], cx: Context<'_>);
    fn poll_send_to(&mut self, buffer: &mut &[u8], cx: Context<'_>);
}

pub trait Runtime: Clone {
    type TcpStream: TcpStream;
    type TcpListener: TcpListener<Self::TcpStream>;
    type UdpSocket: UdpSocket;

    fn spawn<F>(future: F)
    where
        F: Future + Send + 'static,
        F::Output: Send;
}
