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

#[derive(Debug, PartialEq, Eq)]
pub enum HttpError {
    /// Invalid, non-.i2p host.
    InvalidHost,

    // Invalid path.
    InvalidPath,

    /// I/O error.
    Io(std::io::ErrorKind),

    /// Parse error.
    Malformed,

    /// Method missing.
    MethodMissing,

    /// Method not supported.
    MethodNotSupported(String),
}

impl From<std::io::Error> for HttpError {
    fn from(value: std::io::Error) -> Self {
        HttpError::Io(value.kind())
    }
}

impl From<httparse::Error> for HttpError {
    fn from(_: httparse::Error) -> Self {
        HttpError::Malformed
    }
}
