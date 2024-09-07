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
    crypto::{sha256::Sha256, StaticPrivateKey, StaticPublicKey},
    runtime::Runtime,
};

use bytes::Bytes;
use curve25519_elligator2::{MapToPointVariant, MontgomeryPoint, Randomized};
use rand_core::RngCore;
use x25519_dalek::PublicKey;

use core::marker::PhantomData;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::session::context";

/// Noise protocol name.
const PROTOCOL_NAME: &str = "Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256";

/// Key context for an ECIES-X25519-AEAD-Ratchet session.
#[derive(Clone)]
pub struct KeyContext<R: Runtime> {
    /// Chaining key.
    chaining_key: Bytes,

    /// Inbound state.
    inbound_state: Bytes,

    /// Outbound state.
    outbound_state: Bytes,

    /// Static private key of the session.
    private_key: StaticPrivateKey,

    /// Static public key of the session.
    public_key: StaticPublicKey,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> KeyContext<R> {
    /// Create new [`NoiseContext`].
    ///
    /// https://geti2p.net/spec/ecies#f-kdfs-for-new-session-message
    pub fn new() -> Self {
        let chaining_key = Sha256::new().update(PROTOCOL_NAME.as_bytes()).finalize();

        // generate random static keypair for the session
        let private_key = StaticPrivateKey::new(&mut R::rng());
        let public_key = private_key.public();

        let outbound_state = Sha256::new().update(&chaining_key).finalize();
        let inbound_state =
            Sha256::new().update(&outbound_state).update(public_key.to_bytes()).finalize();

        println!("inbound state: {inbound_state:?}");

        Self {
            chaining_key: Bytes::from(chaining_key),
            inbound_state: Bytes::from(inbound_state),
            outbound_state: Bytes::from(outbound_state),
            private_key,
            public_key,
            _runtime: Default::default(),
        }
    }

    /// Generate private key which can be Elligator2-encoded.
    fn generate_ephemeral_keypair() -> ([u8; 32], u8) {
        let mut rng = R::rng();
        let tweak = rng.next_u32() as u8;

        loop {
            let mut private = [0u8; 32];
            rng.fill_bytes(&mut private);

            if let Some(_) = Randomized::to_representative(&private, tweak).into_option() {
                return (private, tweak);
            }
        }
    }

    /// Create new outbound session.
    ///
    /// https://geti2p.net/spec/ecies#f-kdfs-for-new-session-message
    //
    // TODO: leaseset
    pub fn create_oubound_session(&self, pubkey: StaticPublicKey) -> [u8; 32] {
        let (private_key, tweak) = Self::generate_ephemeral_keypair();
        let sk = StaticPrivateKey::from(private_key.clone().to_vec());
        let public_key =
            StaticPublicKey::from(Randomized::mul_base_clamped(private_key).to_montgomery().0);

        let state = Sha256::new()
            .update(&self.outbound_state)
            .update::<&[u8]>(pubkey.as_ref())
            .finalize();

        let state = Sha256::new().update(&state).update(&public_key).finalize();
        let shared = sk.diffie_hellman(&pubkey);

        println!("create_outbound_session(): state  {state:?}");
        println!("create_outbound_session(): shared {shared:?}");

        Randomized::to_representative(&private_key, tweak).unwrap()
        // println!("public key = {public_key:?}");
        // println!("test public key = {:?}", PublicKey::from(private_key));
        // println!("representative = {representative:?}");
        // let new_pubkey =
        // Randomized::from_representative(&representative).unwrap().to_montgomery();
        // println!("new public key = {new_pubkey:?}");
        // let state = Sha256::new().update(&state).update(&public_key).finalize();
        // println!("state = {state:?}");
        // let new_pubkey = Randomized::from_representative(&representative).unwrap();
    }

    /// Create inbound session.
    ///
    /// https://geti2p.net/spec/ecies#f-kdfs-for-new-session-message
    pub fn create_inbound_session(&self, representative: [u8; 32]) {
        let new_pubkey = Randomized::from_representative(&representative).unwrap().to_montgomery();
        let public_key = StaticPublicKey::from(new_pubkey.0);

        let state = Sha256::new().update(&self.inbound_state).update(&public_key).finalize();
        let shared = self.private_key.diffie_hellman(&public_key);

        println!("create_inbound_session(): state  {state:?}");
        println!("create_inbound_session(): shared {shared:?}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn ellig() {
        print!("alice ");
        let alice = KeyContext::<MockRuntime>::new();
        print!("bob ");
        let bob = KeyContext::<MockRuntime>::new();
        println!("");

        let repr = alice.create_oubound_session(bob.public_key.clone());
        println!("");

        bob.create_inbound_session(repr);

        // let ctx = KeyContext::<MockRuntime>::new();
        // let _ = ctx.create_oubound_session();

        // use curve25519_elligator2::{
        //     EdwardsPoint, MapToPointVariant, MontgomeryPoint, Randomized, RFC9380,
        // };
        // use rand::RngCore;

        // let keypair = StaticSecret::random_from_rng(MockRuntime::rng());
        // let pubkey = PublicKey::from(&keypair);

        // // Montgomery Points can be mapped to and from elligator representatives
        // // using any algorithm variant.
        // let tweak = rand::thread_rng().next_u32() as u8;
        // let mont_point = MontgomeryPoint::default(); // example point known to be representable
        // let r = mont_point.to_representative::<Randomized>(tweak).unwrap();

        // let test = StaticSecret::from(mont_point.0);
        // let shared1 = test.diffie_hellman(&pubkey);

        // let value = MontgomeryPoint::from_representative::<Randomized>(&r).unwrap();
        // let pubkey2 = PublicKey::from(value.0);

        // let shared2 = keypair.diffie_hellman(&pubkey2);

        // println!("{:?}\n{:?}", shared1.to_bytes(), shared2.to_bytes());
    }
}
