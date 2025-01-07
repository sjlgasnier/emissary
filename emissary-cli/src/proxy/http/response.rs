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

/// Error status.
pub enum Status {
    /// HTTP 400 bad request.
    BadRequest,

    /// HTTP 502 bad gateway.
    BadGateway,
}

impl ToString for Status {
    fn to_string(&self) -> String {
        match self {
            Status::BadRequest => "400 Bad Request".to_string(),
            Self::BadGateway => "502 Bad Gateway".to_string(),
        }
    }
}

/// Response builder.
pub struct ResponseBuilder {
    /// Error string.
    error: Option<String>,

    /// Status code.
    status: Status,
}

impl ResponseBuilder {
    /// Create new [`ResponseBuilder`].
    pub fn new(status: Status) -> Self {
        Self {
            error: None,
            status,
        }
    }

    /// Add error for the HTTP response body.
    pub fn with_error(mut self, error: String) -> Self {
        self.error = Some(error);
        self
    }

    /// Build HTTP response.
    pub fn build(mut self) -> String {
        let http_error = self.status.to_string();
        let status_line = format!("HTTP/1.1 {http_error}");
        let headers = "Content-Type: text/html; charset=UTF-8";
        let error = self.error.take().expect("to exist");
        let body = format!(
            r#"
            <!DOCTYPE html>
            <html>
            <head>
                <title>{http_error}</title>
            </head>
            <body>
                <h1>{http_error}</h1>
                <p>{error}</p>
            </body>
            </html>
        "#
        );

        // Combine status line, headers, and body
        format!(
            "{status_line}\r\n{headers}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }
}
