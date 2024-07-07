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
    crypto::{
        aes::Aes, base64_decode, chachapoly::ChaChaPoly, hmac::Hmac, sha256::Sha256,
        siphash::SipHash,
    },
    primitives::{RouterInfo, Str},
    runtime::{Runtime, TcpStream},
};

use futures::{AsyncReadExt, AsyncWriteExt};
use zerocopy::{AsBytes, FromBytes, FromZeroes};
use zeroize::Zeroize;

use alloc::vec::Vec;
use core::str::FromStr;

enum BlockFormat {
    DateTime,
    Options,
    RouterInfo,
    I2Np,
    Termination,
}

impl BlockFormat {
    fn as_u8(&self) -> u8 {
        match self {
            Self::DateTime => 0,
            Self::Options => 1,
            Self::RouterInfo => 2,
            Self::I2Np => 3,
            Self::Termination => 4,
        }
    }
}

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ntcp2::listener";

/// NTCP2 listener.
pub struct Ntcp2Listener<R: Runtime> {
    /// TCP Listener.
    listener: R::TcpListener,
}

impl<R: Runtime> Ntcp2Listener<R> {
    /// Create new [`Ntcp2Listener`].
    pub async fn new(
        router: RouterInfo,
        local_info: Vec<u8>,
        local_static_key: x25519_dalek::StaticSecret,
    ) -> crate::Result<Self> {
        tracing::debug!(
            target: LOG_TARGET,
            address = "127.0.0.1:8888",
            "create ntcp2 listener",
        );

        let ntcp2 = router.addresses().get(0).unwrap();

        let protocol_name: Vec<u8> = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256"
            .as_bytes()
            .to_vec();

        let h = Sha256::new().update(&protocol_name).finalize();
        let ck = h.clone();

        // MixHash (null prologue)
        let h = Sha256::new().update(&h).finalize();

        // MixHash(rs)
        let static_key = ntcp2.options().get(&Str::from_str("s").unwrap()).unwrap();
        let decoded = base64_decode(static_key.string());

        let h = Sha256::new().update(&h).update(&decoded).finalize();

        // generate ephemeral key pair
        // apply mixhash
        let se = x25519_dalek::ReusableSecret::random();
        let pe = x25519_dalek::PublicKey::from(&se);

        // MixHash(epub)
        let h = Sha256::new().update(&h).update(&pe).finalize();

        // perform DH
        let rs_b: [u8; 32] = decoded.try_into().unwrap();
        let mut shared = se.diffie_hellman(&x25519_dalek::PublicKey::from(rs_b));

        // temp key
        let temp_key = Hmac::new(&ck).update(shared.as_ref()).finalize();

        // output 1
        let ck = Hmac::new(&temp_key).update(&[0x01]).finalize();

        // output 2
        let l_k = Hmac::new(&temp_key).update(&ck).update(&[0x02]).finalize();

        shared.zeroize();

        // encrypt X
        let key = router.identity().hash();
        let iv = {
            let i = ntcp2.options().get(&Str::from_str("i").unwrap()).unwrap();
            base64_decode(i.string())
        };

        let mut aes = Aes::new_encryptor(&key, &iv);
        let test = aes.encrypt(pe.to_bytes().to_vec());
        let iv = aes.iv();

        // create `SessionRequest` message
        let mut buffer = alloc::vec![0u8; 96];

        // TODO: generate random padding
        // TODO: request random bytes from runtime
        let padding = alloc::vec![3u8; 32];

        #[derive(Debug, AsBytes, FromBytes, FromZeroes)]
        #[repr(packed)]
        struct Options {
            id: u8,
            version: u8,
            padding_length: [u8; 2],
            m3_p2_len: [u8; 2],
            reserved1: [u8; 2],
            timestamp: [u8; 4],
            reserved2: [u8; 4],
        }

        let time_since_epoch = R::time_since_epoch().unwrap().as_secs() as u32;

        let mut options = Options {
            id: 2,
            version: 2,
            padding_length: 32u16.to_be_bytes(),
            m3_p2_len: (local_info.len() as u16 + 20u16).to_be_bytes(),
            reserved1: 0u16.to_be_bytes(),
            timestamp: time_since_epoch.to_be_bytes(),
            reserved2: 0u32.to_be_bytes(),
        }
        .as_bytes()
        .to_vec();

        let tag = ChaChaPoly::new(&l_k)
            .encrypt_with_ad(&h, &mut options)
            .unwrap();

        buffer[..32].copy_from_slice(&test);
        buffer[32..48].copy_from_slice(&options);
        buffer[48..64].copy_from_slice(&tag);
        buffer[64..96].copy_from_slice(&padding);

        let mut stream = R::TcpStream::connect("0.0.0.0:8889").await.unwrap();

        // MixHash(encrypted payload)
        let h = Sha256::new().update(&h).update(&buffer[32..64]).finalize();

        // MixHash(padding)
        let h = Sha256::new().update(&h).update(&buffer[64..96]).finalize();

        stream.write_all(&buffer).await.unwrap();

        let mut reply = alloc::vec![0u8; 64];
        stream.read_exact(&mut reply).await.unwrap();

        // decrypt `Y`
        let mut aes = Aes::new_decryptor(&key, &iv);
        let y: [u8; 32] = aes
            .decrypt(reply[..32].to_vec())
            .try_into()
            .expect("to succeed");

        // MixHash(e.pubkey)
        let h = Sha256::new().update(&h).update(&y).finalize();
        let mut bob_public = x25519_dalek::PublicKey::from(y);

        let shared = se.diffie_hellman(&bob_public);

        // TODO: zero out out our public and private key

        // TODO: mixkey
        let temp_key = Hmac::new(&ck).update(shared).finalize();

        // TODO: zero out `shared`

        // output 1
        let ck = Hmac::new(&temp_key).update(&[0x01]).finalize();

        // output 2
        let k_r = Hmac::new(&temp_key).update(&ck).update(&[0x02]).finalize();

        // TODO: zeroize temp key

        let mut options = reply[32..64].to_vec();
        let clone = options.clone();

        let _result = ChaChaPoly::new(&k_r)
            .decrypt_with_ad(&h, &mut options)
            .unwrap();

        let options = Options::ref_from_prefix(&options).unwrap();
        let padding = u16::from_be_bytes(options.padding_length);
        let _timestamp = u32::from_be_bytes(options.timestamp);

        let mut reply = alloc::vec![0u8; padding as usize];
        stream.read_exact(&mut reply).await.unwrap();

        // MixHash(encrypted payload)
        let h = Sha256::new().update(&h).update(&clone).finalize();

        // MixHash(padding)
        let h = Sha256::new().update(&h).update(&reply).finalize();

        // generate static key and shared secret
        //
        // TODO: move static secret generation elsewhere
        let s_s = local_static_key;
        let s_p = x25519_dalek::PublicKey::from(&s_s);
        let mut s_p_bytes = s_p.to_bytes().to_vec();

        let mut cipher = ChaChaPoly::with_nonce(&k_r, 1);
        let tag1 = cipher.encrypt_with_ad(&h, &mut s_p_bytes).unwrap();

        // MixHash(ciphertext)
        let h = Sha256::new()
            .update(&h)
            .update(&s_p_bytes)
            .update(&tag1)
            .finalize();

        let mut shared = s_s.diffie_hellman(&bob_public);
        bob_public.zeroize();

        // MixKey(DH())

        // Define temp_key = 32 bytes
        // Define HMAC-SHA256(key, data) as in [RFC-2104]_
        // Generate a temp key from the chaining key and DH result
        // ck is the chaining key, from the KDF for handshake message 1
        let temp_key = Hmac::new(&ck).update(&shared).finalize();

        shared.zeroize();

        // Output 1
        // Set a new chaining key from the temp key
        let mut ck = Hmac::new(&temp_key).update(&[0x01]).finalize();

        // Output 2
        // Generate the cipher key k
        let k = Hmac::new(&temp_key).update(&ck).update(&[0x02]).finalize();

        // h from message 3 part 1 is used as the associated data for the AEAD in message 3 part 2
        let mut test = alloc::vec![0u8; local_info.len() + 4];
        test[0] = BlockFormat::RouterInfo.as_u8();
        test[1..3].copy_from_slice(&(local_info.len() as u16 + 1u16).to_be_bytes().to_vec());
        test[3] = 0;
        test[4..].copy_from_slice(&local_info);

        let mut cipher = ChaChaPoly::with_nonce(&k, 0);
        let tag2 = cipher.encrypt_with_ad(&h, &mut test).unwrap();

        // MixHash(ciphertext)
        let h = Sha256::new()
            .update(&h)
            .update(&test)
            .update(&tag2)
            .finalize();

        let mut total_buffer = alloc::vec![0u8; local_info.len() + 20 + 48];

        total_buffer[..32].copy_from_slice(&s_p_bytes);
        total_buffer[32..48].copy_from_slice(&tag1);
        total_buffer[48..48 + local_info.len() + 4].copy_from_slice(&test);
        total_buffer[48 + local_info.len() + 4..4 + 48 + local_info.len() + 16]
            .copy_from_slice(&tag2);

        stream.write_all(&total_buffer).await.unwrap();

        let temp_key = Hmac::new(&ck).update(&[]).finalize();

        ck.zeroize();

        // alice's key
        let send_key = Hmac::new(&temp_key).update(&[0x01]).finalize();

        // bob's key
        let receive_key = Hmac::new(&temp_key)
            .update(&send_key)
            .update(&[0x02])
            .finalize();

        let mut sip = SipHash::new(&temp_key, &h);

        let mut reply = alloc::vec![0u8; 2];
        stream.read_exact(&mut reply).await.unwrap();
        let test = u16::from_be_bytes(TryInto::<[u8; 2]>::try_into(reply).unwrap());

        let len = sip.deobfuscate(test);

        tracing::info!("read {len} bytes from socket");

        let mut test = alloc::vec![0u8; len as usize];
        stream.read_exact(&mut test).await.unwrap();

        let data_block = ChaChaPoly::new(&receive_key).decrypt(test).unwrap();

        tracing::info!("block type = {}", data_block[0]);
        tracing::info!("block size = {}{}", data_block[1], data_block[2]);

        todo!();
    }
}
