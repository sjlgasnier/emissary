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
    crypto::{aead::ChaChaPoly, base64_decode},
    primitives::{RouterInfo, Str},
    runtime::{Runtime, TcpListener, TcpStream},
    Error,
};

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, IvState, KeyIvInit};
use futures::{AsyncReadExt, AsyncWriteExt};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
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

        let mut hasher = Sha256::new();
        hasher.update(&protocol_name);

        let h = hasher.finalize();
        let ck = h.clone();

        // MixHash (null prologue)
        hasher = Sha256::new();
        hasher.update(&h);
        let h = hasher.finalize();

        // MixHash(rs)
        let static_key = ntcp2.options().get(&Str::from_str("s").unwrap()).unwrap();
        let decoded = base64_decode(static_key.string());

        // tracing::error!("len = {}", decoded.len());

        hasher = Sha256::new();
        hasher.update(&h);
        hasher.update(&decoded);
        let h = hasher.finalize();

        // generate ephemeral key pair
        // apply mixhash
        let se = x25519_dalek::ReusableSecret::random();
        let pe = x25519_dalek::PublicKey::from(&se);

        // MixHash(epub)
        hasher = Sha256::new();
        hasher.update(&h);
        hasher.update(&pe);
        let h = hasher.finalize();

        // perform DH
        let rs_b: [u8; 32] = decoded.try_into().unwrap();
        let mut shared = se.diffie_hellman(&x25519_dalek::PublicKey::from(rs_b));

        // temp key
        let mut mac = Hmac::<Sha256>::new_from_slice(&ck).expect("to succeed");
        mac.update(shared.as_ref());
        let temp_key = mac.finalize().into_bytes();

        // output 1
        mac = Hmac::<Sha256>::new_from_slice(&temp_key).expect("to succeed");
        mac.update(&[0x01]);
        let ck = mac.finalize().into_bytes();

        // output 2
        mac = Hmac::<Sha256>::new_from_slice(&temp_key).expect("to succeed");
        mac.update(&ck);
        mac.update(&[0x02]);
        let l_k = mac.finalize().into_bytes();

        shared.zeroize();

        // encrypt x
        let key: [u8; 32] = router.identity().hash().try_into().unwrap();
        let i = ntcp2.options().get(&Str::from_str("i").unwrap()).unwrap();
        let iv: [u8; 16] = base64_decode(i.string()).try_into().unwrap();

        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
        type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

        // encrypt alice's ephemeral key
        let pe_bytes = pe.to_bytes().to_vec();

        // tracing::info!("public key = {pe_bytes:?}");

        let pe_first: [u8; 16] = pe_bytes[..16].try_into().unwrap();
        let pe_second: [u8; 16] = pe_bytes[16..].try_into().unwrap();

        // XXX: works (now)
        let mut blocks = [GenericArray::from(pe_first), GenericArray::from(pe_second)];
        let mut enc = Aes256CbcEnc::new(&key.into(), &iv.into());
        let _ = enc.encrypt_blocks_mut(&mut blocks);
        let iv = enc.iv_state();

        let test = blocks
            .into_iter()
            .map(|block| block.into_iter().collect::<Vec<u8>>())
            .flatten()
            .collect::<Vec<u8>>();

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

        // tracing::info!("key = {l_k:?}");

        let tag = ChaChaPoly::new(&l_k)
            .encrypt_detached(&h, &mut options)
            .unwrap();

        buffer[..32].copy_from_slice(&test);
        buffer[32..48].copy_from_slice(&options);
        buffer[48..64].copy_from_slice(&tag);
        buffer[64..96].copy_from_slice(&padding);

        let mut stream = R::TcpStream::connect("0.0.0.0:8889").await.unwrap();

        // MixHash(encrypted payload)
        hasher = Sha256::new();
        hasher.update(&h);
        hasher.update(&buffer[32..64]);
        let h = hasher.finalize();

        // MixHash(padding)
        hasher = Sha256::new();
        hasher.update(&h);
        hasher.update(&buffer[64..96]);
        let h = hasher.finalize();

        stream.write_all(&buffer).await.unwrap();

        let mut reply = alloc::vec![0u8; 64];
        stream.read_exact(&mut reply).await.unwrap();

        // decrypt `Y`
        let b1 = GenericArray::from(TryInto::<[u8; 16]>::try_into(&reply[..16]).unwrap());
        let b2 = GenericArray::from(TryInto::<[u8; 16]>::try_into(&reply[16..32]).unwrap());
        let mut in_blocks = [b1, b2];

        let _ct = Aes256CbcDec::new(&key.into(), &iv.into()).decrypt_blocks_mut(&mut in_blocks);

        let y: [u8; 32] = in_blocks
            .into_iter()
            .map(|block| block.into_iter().collect::<Vec<u8>>())
            .flatten()
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();

        // MixHash(e.pubkey)
        hasher = Sha256::new();
        hasher.update(&h);
        hasher.update(&y);
        let h = hasher.finalize();
        let mut bob_public = x25519_dalek::PublicKey::from(y);

        let shared = se.diffie_hellman(&bob_public);

        // TODO: zero out out our public and private key

        // TODO: mixkey
        let mut mac = Hmac::<Sha256>::new_from_slice(&ck).expect("to succeed");
        mac.update(shared.as_ref());
        let temp_key = mac.finalize().into_bytes();

        // TODO: zero out `shared`

        // output 1
        mac = Hmac::<Sha256>::new_from_slice(&temp_key).expect("to succeed");
        mac.update(&[0x01]);
        let ck = mac.finalize().into_bytes();

        // output 2
        mac = Hmac::<Sha256>::new_from_slice(&temp_key).expect("to succeed");
        mac.update(&ck);
        mac.update(&[0x02]);
        let k_r = mac.finalize().into_bytes();

        // TODO: zeroize temp key

        let mut options = reply[32..64].to_vec();
        let clone = options.clone();

        let _result = ChaChaPoly::new(&k_r).decrypt(&h, &mut options).unwrap();

        let options = Options::ref_from_prefix(&options).unwrap();
        let padding = u16::from_be_bytes(options.padding_length);
        let timestamp = u32::from_be_bytes(options.timestamp);

        // tracing::info!(
        //     "local timestamp = {:?}, remote timestamp = {timestamp:?}",
        //     R::time_since_epoch().unwrap().as_secs() as u32
        // );
        // tracing::info!("padding = {padding}");

        let mut reply = alloc::vec![0u8; padding as usize];
        stream.read_exact(&mut reply).await.unwrap();

        // MixHash(encrypted payload)
        hasher = Sha256::new();
        hasher.update(&h);
        hasher.update(&clone);
        let h = hasher.finalize();

        // MixHash(padding)
        hasher = Sha256::new();
        hasher.update(&h);
        hasher.update(&reply);
        let h = hasher.finalize();

        // generate static key and shared secret
        //
        // TODO: move static secret generation elsewhere
        let s_s = local_static_key;
        let s_p = x25519_dalek::PublicKey::from(&s_s);
        let mut s_p_bytes = s_p.to_bytes().to_vec();

        let mut cipher = ChaChaPoly::with_nonce(&k_r, 1);
        let tag1 = cipher.encrypt_detached(&h, &mut s_p_bytes).unwrap();

        // MixHash(ciphertext)
        hasher = Sha256::new();
        hasher.update(&h);
        hasher.update(&s_p_bytes);
        hasher.update(&tag1);
        let h = hasher.finalize();

        let mut shared = s_s.diffie_hellman(&bob_public);
        bob_public.zeroize();

        // TODO: mixkey

        // MixKey(DH())

        // Define temp_key = 32 bytes
        // Define HMAC-SHA256(key, data) as in [RFC-2104]_
        // Generate a temp key from the chaining key and DH result
        // ck is the chaining key, from the KDF for handshake message 1
        let mut mac = Hmac::<Sha256>::new_from_slice(&ck).expect("to succeed");
        mac.update(shared.as_ref());
        let temp_key = mac.finalize().into_bytes();

        shared.zeroize();

        // Output 1
        // Set a new chaining key from the temp key
        // byte() below means a single byte
        mac = Hmac::<Sha256>::new_from_slice(&temp_key).expect("to succeed");
        mac.update(&[0x01]);
        let mut ck = mac.finalize().into_bytes();

        // Output 2
        // Generate the cipher key k
        mac = Hmac::<Sha256>::new_from_slice(&temp_key).expect("to succeed");
        mac.update(&ck);
        mac.update(&[0x02]);
        let k = mac.finalize().into_bytes();

        // h from message 3 part 1 is used as the associated data for the AEAD in message 3 part 2
        let mut test = alloc::vec![0u8; local_info.len() + 4];
        test[0] = BlockFormat::RouterInfo.as_u8();
        test[1..3].copy_from_slice(&(local_info.len() as u16 + 1u16).to_be_bytes().to_vec());
        test[3] = 0;
        test[4..].copy_from_slice(&local_info);

        let mut cipher = ChaChaPoly::with_nonce(&k, 0);
        let tag2 = cipher.encrypt_detached(&h, &mut test).unwrap();

        // MixHash(ciphertext)
        hasher = Sha256::new();
        hasher.update(&h);
        hasher.update(&test);
        hasher.update(&tag2);
        let h = hasher.finalize();

        let mut total_buffer = alloc::vec![0u8; local_info.len() + 20 + 48];

        total_buffer[..32].copy_from_slice(&s_p_bytes);
        total_buffer[32..48].copy_from_slice(&tag1);
        total_buffer[48..48 + local_info.len() + 4].copy_from_slice(&test);
        total_buffer[48 + local_info.len() + 4..4 + 48 + local_info.len() + 16]
            .copy_from_slice(&tag2);

        stream.write_all(&total_buffer).await.unwrap();

        mac = Hmac::<Sha256>::new_from_slice(&ck).expect("to succeed");
        mac.update(&[]);
        let mut temp_key = mac.finalize().into_bytes();

        ck.zeroize();

        // alice's key
        mac = Hmac::<Sha256>::new_from_slice(&temp_key).expect("to succeed");
        mac.update(&[0x01]);
        let send_key = mac.finalize().into_bytes();

        // bob's key
        mac = Hmac::<Sha256>::new_from_slice(&temp_key).expect("to succeed");
        mac.update(&send_key);
        mac.update(&[0x02]);
        let receive_key = mac.finalize().into_bytes();

        tracing::info!("alice's key: {send_key:?}");
        tracing::info!("bob's key: {receive_key:?}");

        mac = Hmac::<Sha256>::new_from_slice(&temp_key).expect("to succeed");
        mac.update(&b"ask"[..]);
        mac.update(&[0x01]);
        let mut ask_master = mac.finalize().into_bytes();

        tracing::info!("h = {h:?}");

        mac = Hmac::<Sha256>::new_from_slice(&ask_master).expect("to succeed");
        mac.update(&h);
        mac.update(&b"siphash"[..]);
        temp_key = mac.finalize().into_bytes();
        ask_master.zeroize();

        mac = Hmac::<Sha256>::new_from_slice(&temp_key).expect("to succeed");
        mac.update(&[0x01]);
        let mut sip_master = mac.finalize().into_bytes();

        mac = Hmac::<Sha256>::new_from_slice(&sip_master).expect("to succeed");
        mac.update(&[]);
        temp_key = mac.finalize().into_bytes();
        sip_master.zeroize();

        mac = Hmac::<Sha256>::new_from_slice(&temp_key).expect("to succeed");
        mac.update(&[0x01]);
        let sipkeys_ab = mac.finalize().into_bytes();

        let sipk1_ab =
            u64::from_le_bytes(TryInto::<[u8; 8]>::try_into(&sipkeys_ab[..8]).expect("to succeed"));
        let sipk2_ab = u64::from_le_bytes(
            TryInto::<[u8; 8]>::try_into(&sipkeys_ab[8..16]).expect("to succeed"),
        );
        let sipkiv_ab = sipkeys_ab[16..24].to_vec();

        mac = Hmac::<Sha256>::new_from_slice(&temp_key).expect("to succeed");
        mac.update(&sipkeys_ab);
        mac.update(&[0x02]);
        let sipkeys_ba = mac.finalize().into_bytes();

        let sipk1_ba =
            u64::from_le_bytes(TryInto::<[u8; 8]>::try_into(&sipkeys_ba[..8]).expect("to succeed"));
        let sipk2_ba = u64::from_le_bytes(
            TryInto::<[u8; 8]>::try_into(&sipkeys_ba[8..16]).expect("to succeed"),
        );
        let sipkiv_ba = sipkeys_ba[16..24].to_vec();

        tracing::info!("alice's iv: {sipkiv_ab:?}");
        tracing::info!("bob's iv: {sipkiv_ba:?}");

        tracing::warn!("try to read someting");

        let mut reply = alloc::vec![0u8; 2];
        stream.read_exact(&mut reply).await.unwrap();
        let test = u16::from_be_bytes(TryInto::<[u8; 2]>::try_into(reply).unwrap());

        use siphasher::sip::SipHasher24;

        let hasher = SipHasher24::new_with_keys(sipk1_ba, sipk2_ba);
        let hash = hasher.hash(&sipkiv_ba);

        let len = test ^ ((hash & 0xffff) as u16);

        // TODO: reset iv

        tracing::info!("read {len} bytes from socket");

        let mut test = alloc::vec![0u8; len as usize];
        stream.read_exact(&mut test).await.unwrap();

        let data_block = ChaChaPoly::new(&receive_key).decrypt_no_ad(test).unwrap();

        tracing::info!("block type = {}", data_block[0]);
        tracing::info!("block size = {}{}", data_block[1], data_block[2]);
        temp_key.zeroize();

        todo!();
    }
}
