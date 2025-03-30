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

use crate::{config::Profile, error::Error};

use emissary_core::runtime::Storage;
use flate2::write::GzDecoder;

use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::router-storage";

/// Router torage.
#[derive(Clone)]
pub struct RouterStorage {
    /// Base path.
    base_path: PathBuf,
}

impl RouterStorage {
    /// Create new [`Storage`].
    pub fn new(base_path: PathBuf) -> Self {
        Self { base_path }
    }

    /// Store `router_info` for `router_id` in `netDb`.
    pub fn store_router_info(&self, router_id: String, router_info: Vec<u8>) -> crate::Result<()> {
        let dir = router_id.chars().next().ok_or(Error::Custom("invalid router id".to_string()))?;
        let name = match router_id.ends_with(".dat") {
            true => self.base_path.join(format!("netDb/r{dir}/routerInfo-{router_id}")),
            false => self.base_path.join(format!("netDb/r{dir}/routerInfo-{router_id}.dat")),
        };

        let mut file = File::create(name)?;
        file.write_all(&router_info)?;

        Ok(())
    }

    /// Store `profile` for `router_id` in `peerProfiles`.
    fn store_profile(
        &self,
        router_id: String,
        profile: emissary_core::Profile,
    ) -> crate::Result<()> {
        let dir = router_id.chars().next().ok_or(Error::Custom("invalid router id".to_string()))?;

        // don't store profile on disk if associated router info doesn't exist
        if !Path::exists(&self.base_path.join(format!("netDb/r{dir}/routerInfo-{router_id}.dat"))) {
            tracing::trace!(
                target: LOG_TARGET,
                %router_id,
                "router info doesn't exist, skipping router profile store",
            );

            return Ok(());
        }

        let profile_name =
            self.base_path.join(format!("peerProfiles/p{dir}/profile-{router_id}.toml"));

        let config = toml::to_string(&Profile::from(profile)).expect("to succeed");
        let mut file = File::create(profile_name)?;
        file.write_all(config.as_bytes())?;

        Ok(())
    }

    /// Decompress `bytes`.
    fn decompress(bytes: Vec<u8>) -> Option<Vec<u8>> {
        let mut e = GzDecoder::new(Vec::new());
        e.write_all(bytes.as_ref()).ok()?;

        e.finish().ok()
    }
}

impl Storage for RouterStorage {
    fn save_to_disk(&self, routers: Vec<(String, Option<Vec<u8>>, emissary_core::Profile)>) {
        let storage_handle = self.clone();

        tokio::task::spawn_blocking(move || {
            for (router_id, router_info, profile) in routers {
                if let Some(router_info) = router_info {
                    match RouterStorage::decompress(router_info) {
                        Some(router_info) =>
                            if let Err(error) =
                                storage_handle.store_router_info(router_id.clone(), router_info)
                            {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    ?router_id,
                                    ?error,
                                    "failed to store router info to disk",
                                );
                            },
                        None => tracing::warn!(
                            target: LOG_TARGET,
                            ?router_id,
                            "failed to decompress router info",
                        ),
                    }
                }

                if let Err(error) = storage_handle.store_profile(router_id.clone(), profile) {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?router_id,
                        ?error,
                        "failed to store router profile to disk",
                    );
                }
            }
        });
    }
}
