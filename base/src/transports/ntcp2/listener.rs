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
    primitives::RouterInfo,
    runtime::{Runtime, TcpListener},
    transports::ntcp2::LOG_TARGET,
};

use futures::{Future, FutureExt, Stream};

use alloc::{string::String, vec::Vec};
use core::{
    pin::{pin, Pin},
    task::{Context, Poll},
};

/// NTCP2 listener.
pub struct Ntcp2Listener<R: Runtime> {
    /// TCP Listener.
    listener: R::TcpListener,
}

impl<R: Runtime> Ntcp2Listener<R> {
    /// Create new [`Ntcp2Listener`].
    pub async fn new(address: String, port: u16) -> crate::Result<Self> {
        // TODO: fix listen address
        let mut listener = R::TcpListener::bind("127.0.0.1:8888").await.unwrap();

        tracing::trace!(
            target: LOG_TARGET,
            "starting ntcp2 listener",
        );

        Ok(Self { listener })
    }

    // /// Create new [`Ntcp2Listener`].
    // pub async fn new(
    //     runtime: R,
    //     router: RouterInfo,
    //     local_info: Vec<u8>,
    //     local_router_hash: Vec<u8>,
    //     local_static_key: StaticPrivateKey,
    // ) -> crate::Result<Self> {
    //     tracing::debug!(
    //         target: LOG_TARGET,
    //         address = "127.0.0.1:8888",
    //         "create ntcp2 listener",
    //     );

    //     let handshaker = SessionManager::new(local_static_key.public());

    //     let mut listener = R::TcpListener::bind("0.0.0.0:8888").await.unwrap();

    //     let mut stream = listener.accept().await.unwrap();

    //     let mut message = alloc::vec![0u8; 64];
    //     stream.read_exact(&mut message).await.unwrap();

    //     // TODO: generate proper iv for local node
    //     let (mut responder, padding_len) = handshaker
    //         .register_session::<R>(
    //             local_static_key,
    //             local_router_hash,
    //             alloc::vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
    //             message,
    //         )
    //         .unwrap();

    //     let mut padding = alloc::vec![0u8; padding_len];
    //     stream.read_exact(&mut padding).await.unwrap();

    //     let (message, message_len) = responder.register_padding::<R>(padding).unwrap();
    //     stream.write_all(&message).await.unwrap();

    //     let mut message = alloc::vec![0u8; message_len];
    //     stream.read_exact(&mut message).await.unwrap();

    //     let key_context = responder.finalize(message).unwrap();

    //     let session = Session::<R>::new(runtime.clone(), stream, key_context);

    //     let _ = session.run().await;
    //     // -------------------------------------------------------

    //     // let remote_static_key = {
    //     //     let static_key = ntcp2.options().get(&Str::from_str("s").unwrap()).unwrap();
    //     //     let decoded = base64_decode(static_key.string());
    //     //     StaticPublicKey::from_bytes(decoded).unwrap()
    //     // };
    //     // let router_hash = router.identity().hash();
    //     // let iv = {
    //     //     let i = ntcp2.options().get(&Str::from_str("i").unwrap()).unwrap();
    //     //     base64_decode(i.string())
    //     // };

    //     // let handshaker = SessionManager::new(local_static_key.public());
    //     // let (mut initiator, message) = handshaker
    //     //     .create_session::<R>(
    //     //         local_info,
    //     //         local_static_key,
    //     //         alloc::vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
    //     //     )
    //     //     .unwrap();

    //     // let ntcp2 = router.addresses().get(0).unwrap();

    //     // let mut stream = R::TcpStream::connect("0.0.0.0:8889").await.unwrap();

    //     // let remote_static_key = {
    //     //     let static_key = ntcp2.options().get(&Str::from_str("s").unwrap()).unwrap();
    //     //     let decoded = base64_decode(static_key.string());
    //     //     StaticPublicKey::from_bytes(decoded).unwrap()
    //     // };
    //     // let router_hash = router.identity().hash();
    //     // let iv = {
    //     //     let i = ntcp2.options().get(&Str::from_str("i").unwrap()).unwrap();
    //     //     base64_decode(i.string())
    //     // };

    //     // let handshaker = SessionManager::new(local_static_key.public());
    //     // let (mut initiator, message) = handshaker
    //     //     .create_session::<R>(
    //     //         local_info,
    //     //         local_static_key,
    //     //         &remote_static_key,
    //     //         router_hash.to_vec(),
    //     //         iv,
    //     //     )
    //     //     .unwrap();

    //     // stream.write_all(&message).await.unwrap();

    //     // let mut reply = alloc::vec![0u8; 64];
    //     // stream.read_exact(&mut reply).await.unwrap();

    //     // let padding = initiator.register_session_confirmed(&reply).unwrap();

    //     // let mut reply = alloc::vec![0u8; padding];
    //     // stream.read_exact(&mut reply).await.unwrap();

    //     // let (mut key_context, message) = initiator.finalize(&reply).unwrap();

    //     // stream.write_all(&message).await.unwrap();

    //     // // TODO: create session
    //     // let mut session = Session::<R>::new(runtime.clone(), stream, key_context);

    //     // let _ = session.run().await;

    //     todo!("siip huup");
    // }
}

impl<R: Runtime> Stream for Ntcp2Listener<R> {
    type Item = R::TcpStream;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // // let this = self.project();

        // let _ = self.listener.poll_accept(cx);
        // // self.listener.project();
        // // let this: Pin<&mut Self> = Pin::into_inner(self);

        // todo!();
        // match futures::ready!(self.listener.poll_accept(cx)) {
        //     None => return Poll::Ready(None),
        //     Some()
        //     _ => todo!(),
        // }

        self.listener.poll_accept(cx).map(|value| value)
    }
}
