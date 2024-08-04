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
    i2np::RawI2npMessage, primitives::RouterId, runtime::Runtime, tunnel::new_noise::NoiseContext,
};

use alloc::{vec, vec::Vec};

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
    //
    // TODO: docs
    pub fn handle_message(
        &mut self,
        message: RawI2npMessage,
    ) -> impl Iterator<Item = (RouterId, Vec<u8>)> {
        vec![].into_iter()
    }
}
