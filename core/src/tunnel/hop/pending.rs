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
    tunnel::{hop::TunnelBuildParameters, noise::PendingTunnelKeyContext, LOG_TARGET},
};

use aes::cipher::Key;
use rand_core::RngCore;

use alloc::{collections::VecDeque, vec::Vec};
use core::{iter, time::Duration};

/// How many build records can a `ShortTunnelBuildRequest` contain.
///
/// This includes the actual build request records and any fake records.
const MAX_BUILD_RECORDS: usize = 4;

/// How long is reply waited for a build request until it's considered expired.
const TUNNEL_BUILD_EXPIRATION: Duration = Duration::from_secs(10);

/// Pending tunnel hop.
pub struct PendingTunnelHop {
    /// Hop role
    role: HopRole,

    /// Tunnel ID.
    tunnel_id: TunnelId,

    /// Key context.
    key_context: PendingTunnelKeyContext,
}

/// Outbound tunnel.
pub struct PendingTunnel {
    hops: VecDeque<PendingTunnelHop>,
}

impl PendingTunnel {
    /// Create new [`OutboundTunnel`].
    //
    // TODO: async and use `spawn_blocking()`?
    pub fn create_outbound_tunnel<R: Runtime>(
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
            num_hops = ?hops.len(),
            "create outbound tunnel",
        );

        if hops.len() > MAX_BUILD_RECORDS {
            return Err(TunnelError::TooManyHops(hops.len()));
        }

        // set build record to expire 10 seconds from now
        let time_now = R::time_since_epoch();
        let build_expiration = (time_now + TUNNEL_BUILD_EXPIRATION).as_secs() as u32;
        let num_hops = hops.len();

        // prepare router info for build records
        //
        // each hop is generated a random tunnel id and local info is chained at the end
        let (tunnel_ids, router_hashes): (Vec<_>, Vec<_>) = hops
            .iter()
            .map(|(router_hash, _)| (TunnelId::from(R::rng().next_u32()), router_hash.clone()))
            .chain(iter::once((tunnel_id, our_hash)))
            .unzip();

        // create build records and generate key contexts for each hop
        let (mut tunnel_hops, mut build_records): (VecDeque<PendingTunnelHop>, Vec<Vec<u8>>) =
            tunnel_ids
                .iter()
                .zip(tunnel_ids.iter().skip(1))
                .zip(router_hashes.iter().skip(1))
                .zip(
                    (0..num_hops - 1)
                        .map(|_| HopRole::Intermediary)
                        .chain(iter::once(HopRole::OutboundEndpoint)),
                )
                .zip(hops.into_iter().map(|(_, key)| key))
                .map(
                    |((((tunnel_id, next_tunnel_id), next_router_hash), hop_role), key)| {
                        (
                            PendingTunnelHop {
                                role: hop_role,
                                tunnel_id: *tunnel_id,
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
        // request message is `MAX_BUILD_RECORDS` records long
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
                (0..MAX_BUILD_RECORDS - num_hops)
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
            Self { hops: tunnel_hops },
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
}
