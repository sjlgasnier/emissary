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
    crypto::{base64_decode, chachapoly::ChaChaPoly, StaticPrivateKey, StaticPublicKey},
    primitives::{RouterInfo, Str},
    runtime::{Runtime, TcpStream},
    transports::ntcp2::{
        message::Message,
        session::{Session, SessionManager},
    },
};

use futures::{AsyncReadExt, AsyncWriteExt};

use alloc::vec::Vec;
use core::str::FromStr;

mod message;
mod session;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ntcp2::listener";

/// Noise protocol name;.
const PROTOCOL_NAME: &str = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256";

/// NTCP2 listener.
pub struct Ntcp2Listener<R: Runtime> {
    /// TCP Listener.
    listener: R::TcpListener,
}

impl<R: Runtime> Ntcp2Listener<R> {
    /// Create new [`Ntcp2Listener`].
    pub async fn new(
        runtime: R,
        router: RouterInfo,
        local_info: Vec<u8>,
        local_static_key: StaticPrivateKey,
    ) -> crate::Result<Self> {
        tracing::debug!(
            target: LOG_TARGET,
            address = "127.0.0.1:8888",
            "create ntcp2 listener",
        );

        let ntcp2 = router.addresses().get(0).unwrap();

        let mut stream = R::TcpStream::connect("0.0.0.0:8889").await.unwrap();

        let remote_static_key = {
            let static_key = ntcp2.options().get(&Str::from_str("s").unwrap()).unwrap();
            let decoded = base64_decode(static_key.string());
            StaticPublicKey::from_bytes(decoded).unwrap()
        };
        let router_hash = router.identity().hash();
        let iv = {
            let i = ntcp2.options().get(&Str::from_str("i").unwrap()).unwrap();
            base64_decode(i.string())
        };

        let handshaker = SessionManager::new(local_static_key.public());
        let (mut initiator, message) = handshaker
            .create_session::<R>(
                local_info,
                local_static_key,
                &remote_static_key,
                router_hash.to_vec(),
                iv,
            )
            .unwrap();

        stream.write_all(&message).await.unwrap();

        let mut reply = alloc::vec![0u8; 64];
        stream.read_exact(&mut reply).await.unwrap();

        let padding = initiator.register_session_confirmed(&reply).unwrap();

        let mut reply = alloc::vec![0u8; padding];
        stream.read_exact(&mut reply).await.unwrap();

        let (mut key_context, message) = initiator.finalize(&reply).unwrap();

        stream.write_all(&message).await.unwrap();

        // TODO: create session
        let mut session = Session::<R>::new(runtime.clone(), stream, key_context);

        let _ = session.run().await;

        todo!("siip huup");
    }
}
