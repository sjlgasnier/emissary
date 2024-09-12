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
    runtime::{AsyncRead, AsyncWrite},
    Error,
};

use alloc::string::String;
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

pub mod gzip;

pub trait AsyncReadExt: AsyncRead + Unpin {
    fn read_exact(&mut self, buffer: &mut [u8]) -> impl Future<Output = crate::Result<()>>;
}

struct ReadExact<'a, T: AsyncRead + Unpin> {
    inner: &'a mut T,
    buffer: &'a mut [u8],
}

impl<'a, T: AsyncRead + Unpin> ReadExact<'a, T> {
    pub fn new(inner: &'a mut T, buffer: &'a mut [u8]) -> Self {
        Self { inner, buffer }
    }
}

impl<'a, T: AsyncRead + Unpin> Future for ReadExact<'a, T> {
    type Output = crate::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let mut stream = Pin::new(&mut *this.inner);

        while !this.buffer.is_empty() {
            let n = match stream.as_mut().poll_read(cx, this.buffer) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(nread)) => nread,
            };

            {
                let (_, rest) = core::mem::take(&mut this.buffer).split_at_mut(n);
                this.buffer = rest;
            }
            if n == 0 {
                return Poll::Ready(Err(Error::IoError(String::from("eof"))));
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncRead + Unpin> AsyncReadExt for T {
    fn read_exact(&mut self, buffer: &mut [u8]) -> impl Future<Output = crate::Result<()>> {
        async move { ReadExact::new(self, buffer).await }
    }
}

pub trait AsyncWriteExt: AsyncWrite {
    fn write_all(&mut self, buffer: &[u8]) -> impl Future<Output = crate::Result<()>>;
    fn close(&mut self) -> impl Future<Output = crate::Result<()>>;
}

pub struct WriteAll<'a, T> {
    inner: &'a mut T,
    buffer: &'a [u8],
}

impl<'a, T: AsyncWrite + Unpin> WriteAll<'a, T> {
    fn new(inner: &'a mut T, buffer: &'a [u8]) -> Self {
        Self { inner, buffer }
    }
}

impl<T: AsyncWrite + Unpin> Future for WriteAll<'_, T> {
    type Output = crate::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let mut stream = Pin::new(&mut *this.inner);

        while !this.buffer.is_empty() {
            let n = match stream.as_mut().poll_write(cx, this.buffer) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(nread)) => nread,
            };

            {
                let (_, rest) = core::mem::take(&mut this.buffer).split_at(n);
                this.buffer = rest;
            }
            if n == 0 {
                return Poll::Ready(Err(Error::IoError(String::from("eof"))));
            }
        }

        Poll::Ready(Ok(()))
    }
}

pub struct Close<'a, T> {
    inner: &'a mut T,
}

impl<'a, T: AsyncWrite + Unpin> Close<'a, T> {
    fn new(inner: &'a mut T) -> Self {
        Self { inner }
    }
}

impl<T: AsyncWrite + Unpin> Future for Close<'_, T> {
    type Output = crate::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut *self.inner).poll_close(cx)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWriteExt for T {
    fn write_all(&mut self, buffer: &[u8]) -> impl Future<Output = crate::Result<()>> {
        async move { WriteAll::new(self, buffer).await }
    }

    fn close(&mut self) -> impl Future<Output = crate::Result<()>> {
        Close::new(self)
    }
}

#[cfg(test)]
pub fn init_logger() {
    use tracing_subscriber::prelude::*;

    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
}
