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

use alloc::string::String;
use core::fmt;

#[derive(Debug)]
pub enum Error {
    Ed25519(ed25519_dalek::ed25519::Error),
    Chacha20Poly1305(chacha20poly1305::Error),
    IoError(String),
    Socket,
    InvalidData,
    InvalidState,
    NonceOverflow,
    NotSupported,
    EssentialTaskClosed,
    RouterDoesntExist,
    DialFailure,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519(error) => write!(f, "ed25519 error: {error:?}"),
            Self::Chacha20Poly1305(error) => write!(f, "chacha20poly1305 error: {error:?}"),
            Self::Socket => write!(f, "socket failure"),
            Self::InvalidData => write!(f, "invalid data"),
            Self::InvalidState => write!(f, "invalid state"),
            Self::NonceOverflow => write!(f, "nonce overflow"),
            Self::IoError(error) => write!(f, "i/o error: {error:?}"),
            Self::NotSupported => write!(f, "protocol or operation not supported"),
            Self::EssentialTaskClosed => write!(f, "essential task closed"),
            Self::RouterDoesntExist => write!(f, "router doesn't exist"),
            Self::DialFailure => write!(f, "dial failure"),
        }
    }
}

impl From<ed25519_dalek::ed25519::Error> for Error {
    fn from(value: ed25519_dalek::ed25519::Error) -> Self {
        Error::Ed25519(value)
    }
}

impl From<chacha20poly1305::Error> for Error {
    fn from(value: chacha20poly1305::Error) -> Self {
        Error::Chacha20Poly1305(value)
    }
}
