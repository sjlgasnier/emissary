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
        chachapoly::{ChaCha, ChaChaPoly},
        sha256::Sha256,
    },
    error::TunnelError,
    i2np::{
        HopRole, MessageType, RawI2NpMessageBuilder, RawI2npMessage, ShortTunnelBuildRecordBuilder,
        ShortTunnelBuildRequestBuilder,
    },
    primitives::{RouterId, TunnelId},
    runtime::Runtime,
    tunnel::{
        hop::{
            inbound::InboundTunnel, outbound::OutboundTunnel, Tunnel, TunnelBuildParameters,
            TunnelBuilder, TunnelHop,
        },
        noise::PendingTunnelKeyContext,
        LOG_TARGET,
    },
};

use aes::cipher::Key;
use rand_core::RngCore;

use alloc::{collections::VecDeque, vec::Vec};
use core::{iter, marker::PhantomData, num::NonZeroUsize, time::Duration};

/// How many build records should a `ShortTunnelBuildRequest` contain.
///
/// This includes the actual build request records and any fake records.
const NUM_BUILD_RECORDS: usize = 4;

/// How long is reply waited for a build request until it's considered expired.
const TUNNEL_BUILD_EXPIRATION: Duration = Duration::from_secs(10);

/// Outbound tunnel.
pub struct PendingTunnel<T: Tunnel> {
    /// Tunnel ID.
    tunnel_id: TunnelId,

    /// Pending tunnel hops.
    hops: VecDeque<TunnelHop>,

    /// Marker for tunnel.
    _tunnel: PhantomData<T>,
}

impl<T: Tunnel> PendingTunnel<T> {
    pub fn create_tunnel<R: Runtime>(
        parameters: TunnelBuildParameters,
    ) -> Result<(Self, RouterId, Vec<u8>), TunnelError> {
        let TunnelBuildParameters {
            hops,
            noise,
            message_id,
            tunnel_id,
            our_hash,
        } = parameters;

        tracing::trace!(
            target: LOG_TARGET,
            %message_id,
            %tunnel_id,
            direction = ?T::direction(),
            num_hops = ?hops.len(),
            "create tunnel",
        );

        if hops.len() > NUM_BUILD_RECORDS {
            return Err(TunnelError::TooManyHops(hops.len()));
        }

        // set build record to expire 10 seconds from now
        let time_now = R::time_since_epoch();
        let build_expiration = (time_now + TUNNEL_BUILD_EXPIRATION).as_secs() as u32;
        let num_hops =
            NonZeroUsize::new(hops.len()).ok_or(TunnelError::NotEnoughHops(hops.len()))?;

        // prepare router info for build records
        //
        // each hop is generated a random tunnel id and local info is chained at the end
        let (tunnel_ids, router_hashes): (Vec<_>, Vec<_>) = hops
            .iter()
            .map(|(router_hash, _)| (TunnelId::from(R::rng().next_u32()), router_hash.clone()))
            .chain(iter::once((tunnel_id, our_hash)))
            .unzip();

        // create build records and generate key contexts for each hop
        let (mut tunnel_hops, mut build_records): (VecDeque<TunnelHop>, Vec<Vec<u8>>) = tunnel_ids
            .iter()
            .zip(tunnel_ids.iter().skip(1))
            .zip(router_hashes.iter().skip(1))
            .zip(T::hop_roles(num_hops))
            .zip(hops.into_iter().map(|(_, key)| key))
            .map(
                |((((tunnel_id, next_tunnel_id), next_router_hash), hop_role), key)| {
                    (
                        TunnelHop {
                            role: hop_role,
                            tunnel_id: *tunnel_id,
                            // TODO: ???
                            key_context: noise.derive_outbound_tunnel_keys::<R>(key, hop_role),
                        },
                        ShortTunnelBuildRecordBuilder::default()
                            .with_tunnel_id((*tunnel_id).into())
                            .with_next_tunnel_id((*next_tunnel_id).into())
                            .with_next_router_hash(next_router_hash.as_ref())
                            .with_role(hop_role)
                            .with_request_time(time_now.as_secs() as u32)
                            .with_request_expiration(build_expiration)
                            .with_next_message_id(message_id.into())
                            .serialize(),
                    )
                },
            )
            .unzip();

        // encrypt build records with each hop's aead key and extend the build record into full
        // `ShortTunnelBuildRecord` by prepending hop's truncated router hash and ephemeral public
        // key of the local router
        //
        // additionally, append fake records at the end so that the length of the tunnel build
        // request message is `NUM_BUILD_RECORDS` records long
        let mut encrypted_records = router_hashes
            .iter()
            .zip(build_records.iter_mut())
            .zip(tunnel_hops.iter_mut())
            .filter_map(|(((router_hash), mut record), mut tunnel_hop)| {
                ChaChaPoly::new(&tunnel_hop.key_context.chacha)
                    .encrypt_with_ad_new(&tunnel_hop.key_context.state, &mut record)
                    .ok()
                    .map(|_| {
                        tunnel_hop.key_context.state = Sha256::new()
                            .update(&tunnel_hop.key_context.state)
                            .update(&record)
                            .finalize();

                        let mut full_record = router_hash[..16].to_vec();
                        full_record.extend_from_slice(&tunnel_hop.key_context.local_ephemeral);
                        full_record.extend_from_slice(&record);

                        full_record
                    })
            })
            .chain(
                (0..NUM_BUILD_RECORDS - num_hops.get())
                    .map(|_| ShortTunnelBuildRecordBuilder::random::<R>()),
            )
            .collect::<Vec<_>>();

        // double encrypt records
        //
        // TODO: randomize order
        tunnel_hops.iter().enumerate().for_each(|(hop_idx, hop)| {
            encrypted_records.iter_mut().skip(hop_idx + 1).enumerate().for_each(
                |(record_idx, mut record)| {
                    ChaCha::with_nonce(
                        &hop.key_context.reply_key,
                        (hop_idx + record_idx + 1) as u64,
                    )
                    .decrypt(&mut record);
                },
            )
        });

        Ok((
            Self {
                tunnel_id,
                hops: tunnel_hops,
                _tunnel: Default::default(),
            },
            RouterId::from(router_hashes[0].clone().to_vec()),
            RawI2NpMessageBuilder::short()
                .with_expiration(build_expiration)
                .with_message_type(MessageType::ShortTunnelBuild)
                .with_message_id(message_id.into())
                .with_payload(ShortTunnelBuildRequestBuilder::with_records(
                    encrypted_records,
                ))
                .serialize(),
        ))
    }

    /// Try to build tunnel from the tunnel build response contained in `payload`.
    ///
    /// This function consumes `self` and returns either a `Tunnel` which can then be used
    /// for tunnel messaging, or a `TunnelError` if the received message was malformed or one of the
    /// tunnel participants rejected the build request.
    pub fn try_build_tunnel(self, mut payload: Vec<u8>) -> Result<T, TunnelError> {
        self.hops
            .into_iter()
            .enumerate()
            .rev()
            .try_fold(
                TunnelBuilder::new(self.tunnel_id),
                |builder, (hop_idx, hop)| {
                    let mut record =
                        payload[1 + (hop_idx * 218)..1 + ((1 + hop_idx) * 218)].to_vec();

                    ChaChaPoly::with_nonce(&hop.key_context.reply_key, hop_idx as u64)
                        .decrypt_with_ad(&hop.key_context.state, &mut record)
                        .map_err(|error| {
                            tracing::debug!(
                                target: LOG_TARGET,
                                tunnel_id = ?self.tunnel_id,
                                hop_tunnel_id = ?hop.tunnel_id,
                                ?error,
                                "failed to decrypt build record"
                            );

                            TunnelError::InvalidMessage
                        })?;

                    match record[201] {
                        0x00 => {
                            tracing::trace!(
                                target: LOG_TARGET,
                                tunnel_id = ?self.tunnel_id,
                                hop_tunnel_id = ?hop.tunnel_id,
                                "outbound tunnel accepted",
                            );
                        }
                        reason => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                tunnel_id = ?self.tunnel_id,
                                hop_tunnel_id = ?hop.tunnel_id,
                                ?reason,
                                "outbound tunnel rejected",
                            );
                            return Err(TunnelError::TunnelRejected(reason));
                        }
                    }

                    payload[1..]
                        .chunks_mut(218)
                        .enumerate()
                        .filter(|(index, _)| index != &hop_idx)
                        .for_each(|(index, mut record)| {
                            ChaCha::with_nonce(&hop.key_context.reply_key, index as u64)
                                .encrypt(&mut record);
                        });

                    Ok(builder.with_hop(hop))
                },
            )
            .map(|builder| builder.build())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        crypto::{base64_encode, StaticPrivateKey, StaticPublicKey},
        i2np::ShortTunnelBuildRecord,
        primitives::MessageId,
        runtime::mock::MockRuntime,
        tunnel::noise::NoiseContext,
    };

    use bytes::Bytes;

    fn make_router() -> (Bytes, StaticPublicKey, NoiseContext) {
        let mut key_bytes = vec![0u8; 32];
        let mut router_hash = vec![0u8; 32];

        MockRuntime::rng().fill_bytes(&mut key_bytes);
        MockRuntime::rng().fill_bytes(&mut router_hash);

        let sk = StaticPrivateKey::from(key_bytes);
        let pk = sk.public();

        (Bytes::from(router_hash), pk, NoiseContext::new(sk))
    }

    #[test]
    fn create_outbound_tunnel() {
        let (hops, noise_contexts): (Vec<(Bytes, StaticPublicKey)>, Vec<NoiseContext>) = (0..3)
            .map(|_| make_router())
            .into_iter()
            .map(|(router_hash, pk, noise_context)| ((router_hash, pk), noise_context))
            .unzip();

        let (local_hash, local_pk, local_noise) = make_router();
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<OutboundTunnel>::create_tunnel::<MockRuntime>(TunnelBuildParameters {
                hops: hops.clone(),
                noise: local_noise,
                message_id,
                tunnel_id,
                our_hash: local_hash,
            })
            .unwrap();

        let Some(RawI2npMessage {
            message_type: MessageType::ShortTunnelBuild,
            message_id: parsed_message_id,
            expiration,
            mut payload,
        }) = RawI2npMessage::parse::<true>(&message)
        else {
            panic!("invalid message");
        };

        assert_eq!(parsed_message_id, message_id.into());
        assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));
        assert_eq!(payload[0], 4u8);
        assert_eq!(payload[1..].len() % 218, 0);

        fn find_own_record<'a>(
            hash: &Bytes,
            payload: &'a mut [u8],
        ) -> Option<(usize, &'a mut [u8])> {
            payload
                .chunks_mut(218)
                .enumerate()
                .find(|(_, chunk)| &chunk[..16] == &hash[..16])
        }

        // TODO: this needs to refactored
        for ((router_hash, _), noise) in hops.iter().zip(noise_contexts.iter()) {
            let (record_idx, record) = find_own_record(&router_hash, &mut payload[1..]).unwrap();

            let mut new_record = record[..].to_vec();

            let pk = StaticPublicKey::from_bytes(new_record[16..48].to_vec()).unwrap();

            let (chaining_key, aead_key, state) = noise.derive_inbound_keys(pk);
            let new_state = Sha256::new().update(&state).update(&new_record[48..]).finalize();

            let (tunnel_id, role) = {
                let mut test = new_record[48..].to_vec();
                ChaChaPoly::new(&aead_key).decrypt_with_ad(&state, &mut test).unwrap();

                let record = ShortTunnelBuildRecord::parse(&test).unwrap(); // TODO: no unwraps
                (record.tunnel_id(), record.role())
            };

            let context = noise.derive_inbound_tunnel_keys::<MockRuntime>(chaining_key, role);

            new_record[201] = 0x00;

            let mut new_record = new_record[..202].to_vec();

            ChaChaPoly::with_nonce(&context.reply_key, record_idx as u64)
                .encrypt_with_ad_new(&new_state, &mut new_record)
                .unwrap();

            record[..].copy_from_slice(&new_record);

            payload[1..]
                .chunks_mut(218)
                .enumerate()
                .filter(|(index, _)| index != &record_idx)
                .for_each(|(index, mut record)| {
                    ChaCha::with_nonce(&context.reply_key, index as u64).encrypt(&mut record);
                });
        }

        assert!(pending_tunnel.try_build_tunnel(payload).is_ok());
    }

    #[test]
    fn create_inbound_tunnel() {
        let (hops, noise_contexts): (Vec<(Bytes, StaticPublicKey)>, Vec<NoiseContext>) = (0..3)
            .map(|_| make_router())
            .into_iter()
            .map(|(router_hash, pk, noise_context)| ((router_hash, pk), noise_context))
            .unzip();

        let (local_hash, local_pk, local_noise) = make_router();
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<InboundTunnel>::create_tunnel::<MockRuntime>(TunnelBuildParameters {
                hops: hops.clone(),
                noise: local_noise,
                message_id,
                tunnel_id,
                our_hash: local_hash,
            })
            .unwrap();

        let Some(RawI2npMessage {
            message_type: MessageType::ShortTunnelBuild,
            message_id: parsed_message_id,
            expiration,
            mut payload,
        }) = RawI2npMessage::parse::<true>(&message)
        else {
            panic!("invalid message");
        };

        assert_eq!(parsed_message_id, message_id.into());
        assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));
        assert_eq!(payload[0], 4u8);
        assert_eq!(payload[1..].len() % 218, 0);

        fn find_own_record<'a>(
            hash: &Bytes,
            payload: &'a mut [u8],
        ) -> Option<(usize, &'a mut [u8])> {
            payload
                .chunks_mut(218)
                .enumerate()
                .find(|(_, chunk)| &chunk[..16] == &hash[..16])
        }

        // TODO: this needs to refactored
        for ((router_hash, _), noise) in hops.iter().zip(noise_contexts.iter()) {
            let (record_idx, record) = find_own_record(&router_hash, &mut payload[1..]).unwrap();

            let mut new_record = record[..].to_vec();

            let pk = StaticPublicKey::from_bytes(new_record[16..48].to_vec()).unwrap();

            let (chaining_key, aead_key, state) = noise.derive_inbound_keys(pk);
            let new_state = Sha256::new().update(&state).update(&new_record[48..]).finalize();

            let (tunnel_id, role) = {
                let mut test = new_record[48..].to_vec();
                ChaChaPoly::new(&aead_key).decrypt_with_ad(&state, &mut test).unwrap();

                let record = ShortTunnelBuildRecord::parse(&test).unwrap(); // TODO: no unwraps
                (record.tunnel_id(), record.role())
            };

            let context = noise.derive_inbound_tunnel_keys::<MockRuntime>(chaining_key, role);

            new_record[201] = 0x00;

            let mut new_record = new_record[..202].to_vec();

            ChaChaPoly::with_nonce(&context.reply_key, record_idx as u64)
                .encrypt_with_ad_new(&new_state, &mut new_record)
                .unwrap();

            record[..].copy_from_slice(&new_record);

            payload[1..]
                .chunks_mut(218)
                .enumerate()
                .filter(|(index, _)| index != &record_idx)
                .for_each(|(index, mut record)| {
                    ChaCha::with_nonce(&context.reply_key, index as u64).encrypt(&mut record);
                });
        }

        assert!(pending_tunnel.try_build_tunnel(payload).is_ok());
    }

    #[test]
    fn tunnel_rejected() {
        let (hops, noise_contexts): (Vec<(Bytes, StaticPublicKey)>, Vec<NoiseContext>) = (0..3)
            .map(|_| make_router())
            .into_iter()
            .map(|(router_hash, pk, noise_context)| ((router_hash, pk), noise_context))
            .unzip();

        let (local_hash, local_pk, local_noise) = make_router();
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<OutboundTunnel>::create_tunnel::<MockRuntime>(TunnelBuildParameters {
                hops: hops.clone(),
                noise: local_noise,
                message_id,
                tunnel_id,
                our_hash: local_hash,
            })
            .unwrap();

        let Some(RawI2npMessage {
            message_type: MessageType::ShortTunnelBuild,
            message_id: parsed_message_id,
            expiration,
            mut payload,
        }) = RawI2npMessage::parse::<true>(&message)
        else {
            panic!("invalid message");
        };

        assert_eq!(parsed_message_id, message_id.into());
        assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));
        assert_eq!(payload[0], 4u8);
        assert_eq!(payload[1..].len() % 218, 0);

        fn find_own_record<'a>(
            hash: &Bytes,
            payload: &'a mut [u8],
        ) -> Option<(usize, &'a mut [u8])> {
            payload
                .chunks_mut(218)
                .enumerate()
                .find(|(_, chunk)| &chunk[..16] == &hash[..16])
        }

        for ((router_hash, _), noise) in hops.iter().zip(noise_contexts.iter()) {
            let (record_idx, record) = find_own_record(&router_hash, &mut payload[1..]).unwrap();

            let mut new_record = record[..].to_vec();

            let pk = StaticPublicKey::from_bytes(new_record[16..48].to_vec()).unwrap();

            let (chaining_key, aead_key, state) = noise.derive_inbound_keys(pk);
            let new_state = Sha256::new().update(&state).update(&new_record[48..]).finalize();

            let (tunnel_id, role) = {
                let mut test = new_record[48..].to_vec();
                ChaChaPoly::new(&aead_key).decrypt_with_ad(&state, &mut test).unwrap();

                let record = ShortTunnelBuildRecord::parse(&test).unwrap();
                (record.tunnel_id(), record.role())
            };

            let context = noise.derive_inbound_tunnel_keys::<MockRuntime>(chaining_key, role);

            if record_idx % 2 == 0 {
                new_record[201] = 0x30;
            } else {
                new_record[201] = 0x00;
            }

            let mut new_record = new_record[..202].to_vec();

            ChaChaPoly::with_nonce(&context.reply_key, record_idx as u64)
                .encrypt_with_ad_new(&new_state, &mut new_record)
                .unwrap();

            record[..].copy_from_slice(&new_record);

            payload[1..]
                .chunks_mut(218)
                .enumerate()
                .filter(|(index, _)| index != &record_idx)
                .for_each(|(index, mut record)| {
                    ChaCha::with_nonce(&context.reply_key, index as u64).encrypt(&mut record);
                });
        }

        assert_eq!(
            pending_tunnel.try_build_tunnel(payload).unwrap_err(),
            TunnelError::TunnelRejected(0x30)
        );
    }

    #[test]
    fn invalid_ciphertext() {
        let (hops, noise_contexts): (Vec<(Bytes, StaticPublicKey)>, Vec<NoiseContext>) = (0..3)
            .map(|_| make_router())
            .into_iter()
            .map(|(router_hash, pk, noise_context)| ((router_hash, pk), noise_context))
            .unzip();

        let (local_hash, local_pk, local_noise) = make_router();
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<OutboundTunnel>::create_tunnel::<MockRuntime>(TunnelBuildParameters {
                hops: hops.clone(),
                noise: local_noise,
                message_id,
                tunnel_id,
                our_hash: local_hash,
            })
            .unwrap();

        let Some(RawI2npMessage {
            message_type: MessageType::ShortTunnelBuild,
            message_id: parsed_message_id,
            expiration,
            mut payload,
        }) = RawI2npMessage::parse::<true>(&message)
        else {
            panic!("invalid message");
        };

        assert_eq!(parsed_message_id, message_id.into());
        assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));
        assert_eq!(payload[0], 4u8);
        assert_eq!(payload[1..].len() % 218, 0);

        // try to parse the tunnel build request as a reply, ciphertexsts won't decrypt correctly
        assert_eq!(
            pending_tunnel.try_build_tunnel(payload).unwrap_err(),
            TunnelError::InvalidMessage
        );
    }
}
