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

use std::{fs::File, io::Write, path::PathBuf};

/// Storage.
#[derive(Clone)]
pub struct Storage {
    /// Base path.
    base_path: PathBuf,
}

impl Storage {
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

        let mut file = File::create(self.base_path.join(name))?;
        file.write_all(&router_info)?;

        Ok(())
    }

    /// Store `profile` for `router_id` in `peerProfiles`.
    pub fn store_profile(
        &self,
        router_id: String,
        profile: emissary_core::Profile,
    ) -> crate::Result<()> {
        let dir = router_id.chars().next().ok_or(Error::Custom("invalid router id".to_string()))?;
        let name = self.base_path.join(format!("peerProfiles/p{dir}/profile-{router_id}.toml"));

        let config = toml::to_string(&Profile::from(profile)).expect("to succeed");
        let mut file = File::create(name)?;
        file.write_all(config.as_bytes())?;

        Ok(())
    }
}
