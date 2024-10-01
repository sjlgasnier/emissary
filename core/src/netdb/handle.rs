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
    error::{ChannelError, QueryError},
    primitives::LeaseSet2,
};

use bytes::Bytes;
use futures_channel::oneshot;
use thingbuf::mpsc;

/// Recycling strategy for [`QueryKind`].
#[derive(Default, Clone)]
pub(super) struct QueryRecycle(());

impl thingbuf::Recycle<QueryKind> for QueryRecycle {
    fn new_element(&self) -> QueryKind {
        QueryKind::Dummy
    }

    fn recycle(&self, element: &mut QueryKind) {
        *element = QueryKind::Dummy;
    }
}

/// Query kind.
pub(super) enum QueryKind {
    /// `LeaseSet2` query.
    LeaseSet2(Bytes, oneshot::Sender<Result<LeaseSet2, QueryError>>),

    /// Dummy value.
    Dummy,
}

impl Default for QueryKind {
    fn default() -> Self {
        Self::Dummy
    }
}

/// Handle to [`NetDb`].
#[derive(Clone)]
pub struct NetDbHandle {
    /// TX channel for sending queries to [`NetDb`].
    tx: mpsc::Sender<QueryKind, QueryRecycle>,
}

impl NetDbHandle {
    /// Create new [`NetDbHandle`].
    pub(super) fn new(tx: mpsc::Sender<QueryKind, QueryRecycle>) -> Self {
        Self { tx }
    }

    /// Send `DatabaseLookup` for a `LeaseSet2` identified by `key`.
    ///
    /// On success returns a `oneshot::Receiver` the caller must poll for a reply poll for a reply.
    /// If the query succeeded, `LeaseSet2` is returned and if ti failed, `QueryError` is returned.
    ///
    /// If the channel towards `NetDb` is full, `ChannelError::Full` is returned and the caller must
    /// retry later.
    pub fn query_leaseset(
        &self,
        key: Bytes,
    ) -> Result<oneshot::Receiver<Result<LeaseSet2, QueryError>>, ChannelError> {
        let (tx, rx) = oneshot::channel();

        self.tx.try_send(QueryKind::LeaseSet2(key, tx)).map(|_| rx).map_err(From::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_leaseset_query() {
        let (tx, mut rx) = mpsc::with_recycle(5, QueryRecycle(()));
        let handle = NetDbHandle::new(tx);

        assert!(handle.query_leaseset(Bytes::from(vec![1, 2, 3, 4])).is_ok());

        match rx.try_recv() {
            Ok(QueryKind::LeaseSet2(key, _)) => {
                assert_eq!(key, Bytes::from(vec![1, 2, 3, 4]));
            }
            _ => panic!("invalid event"),
        }
    }

    #[test]
    fn channel_full() {
        let (tx, mut rx) = mpsc::with_recycle(5, QueryRecycle(()));
        let handle = NetDbHandle::new(tx);

        for _ in 0..5 {
            assert!(handle.query_leaseset(Bytes::from(vec![1, 2, 3, 4])).is_ok());
        }

        // try to send one more element and ensure the call fails
        match handle.query_leaseset(Bytes::from(vec![1, 2, 3, 4])).unwrap_err() {
            ChannelError::Full => {}
            error => panic!("invalid error: {error}"),
        }
    }
}
