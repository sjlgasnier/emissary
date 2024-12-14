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

use crate::{cli::Arguments, error::Error, LOG_TARGET};

use home::home_dir;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Serialize, Deserialize)]
struct Profile {
    /// Last activity as seconds since UNIX epoch.
    last_activity: Option<u64>,

    /// Number of accepted tunnels.
    num_accepted: Option<usize>,

    /// Number of successful connections.
    num_connection: Option<usize>,

    /// Number of dial failures.
    num_dial_failures: Option<usize>,

    /// Number of rejected tunnels.
    num_rejected: Option<usize>,

    /// Number of test failures for tunnels where the router was a selected hop.
    num_test_failures: Option<usize>,

    /// Number of test successes for tunnels where the router was a selected hop.
    num_test_successes: Option<usize>,

    /// Number of tunnel build request timeouts where this router was a selected hop.
    num_unaswered: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExploratoryConfig {
    inbound_len: Option<usize>,
    inbound_count: Option<usize>,
    outbound_len: Option<usize>,
    outbound_count: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Ntcp2Config {
    port: u16,
    host: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct I2cpConfig {
    port: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SamConfig {
    tcp_port: u16,
    udp_port: u16,
    host: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EmissaryConfig {
    #[serde(default)]
    floodfill: bool,
    caps: Option<String>,
    net_id: Option<u8>,
    ntcp2: Option<Ntcp2Config>,
    i2cp: Option<I2cpConfig>,
    sam: Option<SamConfig>,
    exploratory: Option<ExploratoryConfig>,
    #[serde(default)]
    insecure_tunnels: bool,
}

/// Router configuration.
pub struct Config {
    /// Base path.
    pub base_path: PathBuf,

    /// I2CP config.
    pub i2cp_config: Option<emissary_core::I2cpConfig>,

    /// NTCP2 config.
    pub ntcp2_config: Option<emissary_core::Ntcp2Config>,

    /// Exploratory tunnel pool config.
    pub exploratory: Option<emissary_core::ExploratoryConfig>,

    /// Router info.
    pub routers: Vec<Vec<u8>>,

    /// Profiles.
    pub profiles: Vec<(String, emissary_core::Profile)>,

    /// SAMv3 config.
    pub sam_config: Option<emissary_core::SamConfig>,

    /// Signing key.
    pub signing_key: Vec<u8>,

    /// Static key.
    pub static_key: Vec<u8>,

    /// Should the node be run as a floodfill router.
    pub floodfill: bool,

    /// Router capabilities.
    pub caps: Option<String>,

    /// Network ID.
    pub net_id: Option<u8>,

    /// Are tunnels allowed to be insecure.
    pub insecure_tunnels: bool,
}

impl From<Config> for emissary_core::Config {
    fn from(val: Config) -> Self {
        emissary_core::Config {
            static_key: val.static_key,
            signing_key: val.signing_key,
            ntcp2_config: val.ntcp2_config,
            i2cp_config: val.i2cp_config,
            routers: val.routers,
            profiles: val.profiles,
            samv3_config: val.sam_config,
            floodfill: val.floodfill,
            caps: val.caps,
            net_id: val.net_id,
            exploratory: val.exploratory,
            insecure_tunnels: val.insecure_tunnels,
        }
    }
}

impl TryFrom<Option<PathBuf>> for Config {
    type Error = Error;

    fn try_from(path: Option<PathBuf>) -> Result<Self, Self::Error> {
        let path = path
            .map_or_else(
                || {
                    let mut path = home_dir()?;
                    (!path.as_os_str().is_empty()).then(|| {
                        path.push(".emissary");
                        path
                    })
                },
                Some,
            )
            .ok_or(Error::Custom(String::from("couldn't resolve base path")))?;

        tracing::trace!(
            target: LOG_TARGET,
            ?path,
            "parse router config",
        );

        // if base path doesn't exist, create it and return empty config
        if !path.exists() {
            fs::create_dir_all(&path)?;
            fs::create_dir_all(path.join("routers"))?;
            fs::create_dir_all(path.join("profiles"))?;

            return Config::new_empty(path);
        }

        // read static & signing keys from disk or generate new ones
        let static_key = match Self::load_key(path.clone(), "static") {
            Ok(key) => x25519_dalek::StaticSecret::from(key).to_bytes().to_vec(),
            Err(error) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    error = %error.to_string(),
                    "failed to load static key, regenerating",
                );

                Self::create_static_key(path.clone())?
            }
        };

        let signing_key = match Self::load_key(path.clone(), "signing") {
            Ok(key) => ed25519_dalek::SigningKey::from(key).to_bytes().to_vec(),
            Err(error) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    error = %error.to_string(),
                    "failed to load signing key, regenerating",
                );

                Self::create_signing_key(path.clone())?
            }
        };

        let (ntcp2_key, ntcp2_iv) = match Self::load_ntcp2_keys(path.clone()) {
            Ok((key, iv)) => (key, iv),
            Err(error) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    error = %error.to_string(),
                    "failed to load ntcp2 iv, regenerating",
                );

                Self::create_ntcp2_keys(path.clone())?
            }
        };

        // try to find `router.toml` and parse it into `EmissaryConfig`
        let router_config = Self::load_router_config(path.clone()).ok();

        let mut config = Config::new(
            path.clone(),
            static_key,
            signing_key,
            ntcp2_key,
            ntcp2_iv,
            router_config,
        )?;

        config.routers = Self::load_router_infos(&path);
        config.profiles = Self::load_router_profiles(&path);

        Ok(config)
    }
}

impl Config {
    /// Create static key.
    fn create_static_key(base_path: PathBuf) -> crate::Result<Vec<u8>> {
        let key = x25519_dalek::StaticSecret::random();
        Self::save_key(base_path, "static", &key).map(|_| key.to_bytes().to_vec())
    }

    /// Create signing key.
    fn create_signing_key(base_path: PathBuf) -> crate::Result<Vec<u8>> {
        let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        Self::save_key(base_path, "signing", key.as_bytes()).map(|_| key.to_bytes().to_vec())
    }

    /// Create NTCP2 key and store it on disk.
    fn create_ntcp2_keys(path: PathBuf) -> crate::Result<(Vec<u8>, [u8; 16])> {
        let key = x25519_dalek::StaticSecret::random().to_bytes().to_vec();
        let iv = {
            let mut iv = [0u8; 16];
            rand_core::OsRng.fill_bytes(&mut iv);

            iv
        };

        // append iv to key and write it to disk
        {
            let mut combined = vec![0u8; 32 + 16];
            combined[..32].copy_from_slice(&key);
            combined[32..].copy_from_slice(&iv);

            let mut file = fs::File::create(path.join("ntcp2.keys"))?;
            file.write_all(combined.as_ref())?;
        }

        Ok((key, iv))
    }

    /// Save key to disk.
    fn save_key<K: AsRef<[u8]>>(path: PathBuf, key_type: &str, key: &K) -> crate::Result<()> {
        let mut file = fs::File::create(path.join(format!("{key_type}.key")))?;
        file.write_all(key.as_ref())?;

        Ok(())
    }

    /// Load key from disk.
    fn load_key(path: PathBuf, key_type: &str) -> crate::Result<[u8; 32]> {
        let mut file = fs::File::open(path.join(format!("{key_type}.key")))?;
        let mut key_bytes = [0u8; 32];
        file.read_exact(&mut key_bytes)?;

        Ok(key_bytes)
    }

    /// Load NTCP2 key and IV from disk.
    fn load_ntcp2_keys(path: PathBuf) -> crate::Result<(Vec<u8>, [u8; 16])> {
        let key_bytes = {
            let mut file = fs::File::open(path.join("ntcp2.keys"))?;
            let mut key_bytes = [0u8; 32 + 16];
            file.read_exact(&mut key_bytes)?;

            key_bytes
        };

        Ok((
            key_bytes[..32].to_vec(),
            TryInto::<[u8; 16]>::try_into(&key_bytes[32..]).expect("to succeed"),
        ))
    }

    fn load_router_config(path: PathBuf) -> crate::Result<EmissaryConfig> {
        // parse configuration, if it exists
        let mut file = fs::File::open(path.join("router.toml"))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        toml::from_str::<EmissaryConfig>(&contents).map_err(|error| {
            tracing::warn!(
                target: LOG_TARGET,
                ?error,
                "failed to parser router config",
            );

            Error::InvalidData
        })
    }

    /// Create empty config.
    ///
    /// Creates a default config with NTCP2 enabled.
    fn new_empty(base_path: PathBuf) -> crate::Result<Self> {
        let static_key = Self::create_static_key(base_path.clone())?;
        let signing_key = Self::create_signing_key(base_path.clone())?;
        let (ntcp2_key, ntcp2_iv) = Self::create_ntcp2_keys(base_path.clone())?;

        let config = EmissaryConfig {
            exploratory: None,
            ntcp2: Some(Ntcp2Config {
                port: 8888u16,
                host: None,
            }),
            i2cp: Some(I2cpConfig { port: 7654 }),
            sam: Some(SamConfig {
                tcp_port: 7656,
                udp_port: 7655,
                host: None,
            }),
            floodfill: false,
            caps: None,
            net_id: None,
            insecure_tunnels: false,
        };
        let config = toml::to_string(&config).expect("to succeed");
        let mut file = fs::File::create(base_path.join("router.toml"))?;
        file.write_all(config.as_bytes())?;

        tracing::info!(
            target: LOG_TARGET,
            ?base_path,
            "emissary starting for the first time",
        );

        Ok(Self {
            base_path,
            routers: Vec::new(),
            profiles: Vec::new(),
            exploratory: None,
            ntcp2_config: Some(emissary_core::Ntcp2Config {
                port: 8888u16,
                host: String::from("127.0.0.1"),
                key: ntcp2_key,
                iv: ntcp2_iv,
            }),
            i2cp_config: Some(emissary_core::I2cpConfig { port: 7654u16 }),
            sam_config: Some(emissary_core::SamConfig {
                tcp_port: 7656u16,
                udp_port: 7655u16,
                host: String::from("127.0.0.1"),
            }),
            static_key,
            signing_key,
            floodfill: false,
            caps: None,
            net_id: None,
            insecure_tunnels: false,
        })
    }

    /// Create new [`Config`].
    fn new(
        base_path: PathBuf,
        static_key: Vec<u8>,
        signing_key: Vec<u8>,
        ntcp2_key: Vec<u8>,
        ntcp2_iv: [u8; 16],
        config: Option<EmissaryConfig>,
    ) -> crate::Result<Self> {
        let config = match config {
            Some(config) => config,
            None => {
                let config = EmissaryConfig {
                    exploratory: None,
                    ntcp2: Some(Ntcp2Config {
                        port: 8888u16,
                        host: None,
                    }),
                    i2cp: Some(I2cpConfig { port: 7654 }),
                    sam: Some(SamConfig {
                        tcp_port: 7656,
                        udp_port: 7655,
                        host: None,
                    }),
                    floodfill: false,
                    caps: None,
                    net_id: None,
                    insecure_tunnels: false,
                };

                let toml_config = toml::to_string(&config).expect("to succeed");
                let mut file = fs::File::create(base_path.join("router.toml"))?;
                file.write_all(toml_config.as_bytes())?;

                config
            }
        };

        Ok(Self {
            base_path,
            routers: Vec::new(),
            profiles: Vec::new(),
            exploratory: config.exploratory.map(|config| emissary_core::ExploratoryConfig {
                inbound_len: config.inbound_len,
                inbound_count: config.inbound_count,
                outbound_len: config.outbound_len,
                outbound_count: config.outbound_count,
            }),
            ntcp2_config: config.ntcp2.map(|config| emissary_core::Ntcp2Config {
                port: config.port,
                host: config.host.unwrap_or(String::from("127.0.0.1")),
                key: ntcp2_key,
                iv: ntcp2_iv,
            }),
            i2cp_config: config.i2cp.map(|config| emissary_core::I2cpConfig { port: config.port }),
            sam_config: config.sam.map(|config| emissary_core::SamConfig {
                tcp_port: config.tcp_port,
                udp_port: config.udp_port,
                host: config.host.unwrap_or(String::from("127.0.0.1")),
            }),
            static_key,
            signing_key,
            floodfill: config.floodfill,
            caps: config.caps,
            net_id: config.net_id,
            insecure_tunnels: config.insecure_tunnels,
        })
    }

    /// Attempt to load router infos.
    fn load_router_infos(path: &Path) -> Vec<Vec<u8>> {
        let Ok(router_dir) = fs::read_dir(path.join("routers")) else {
            return Vec::new();
        };

        router_dir
            .into_iter()
            .filter_map(|entry| {
                let dir = entry.ok()?;
                let mut file = fs::File::open(dir.path()).ok()?;

                let mut contents = Vec::new();
                file.read_to_end(&mut contents).ok()?;

                Some(contents)
            })
            .collect::<Vec<_>>()
    }

    /// Attempt to load router profiles.
    fn load_router_profiles(path: &Path) -> Vec<(String, emissary_core::Profile)> {
        let Ok(profile_dir) = fs::read_dir(path.join("profiles")) else {
            return Vec::new();
        };

        profile_dir
            .into_iter()
            .filter_map(|entry| {
                let dir = entry.ok()?;
                let mut file = fs::File::open(dir.path()).ok()?;

                let mut contents = String::new();
                file.read_to_string(&mut contents).ok()?;

                let profile = toml::from_str::<Profile>(&contents).ok()?;
                let name = {
                    let input = dir.path().to_owned();
                    let input = input.to_str().expect("to succeed");

                    let start = input.find("profile-")?;
                    let start = start + "profile-".len();
                    let end = input.find(".toml")?;

                    input[start..end].to_string()
                };

                Some((
                    name,
                    emissary_core::Profile {
                        last_activity: Duration::from_secs(profile.last_activity.unwrap_or(0)),
                        num_accepted: profile.num_accepted.unwrap_or(0),
                        num_connection: profile.num_connection.unwrap_or(0),
                        num_dial_failures: profile.num_dial_failures.unwrap_or(0),
                        num_rejected: profile.num_rejected.unwrap_or(0),
                        num_test_failures: profile.num_test_failures.unwrap_or(0),
                        num_test_successes: profile.num_test_successes.unwrap_or(0),
                        num_unaswered: profile.num_unaswered.unwrap_or(0),
                    },
                ))
            })
            .collect()
    }

    /// Attempt to merge `arguments` with [`Config`].
    pub fn merge(mut self, arguments: &Arguments) -> Self {
        if let Some(true) = arguments.floodfill {
            if !self.floodfill {
                self.floodfill = true;
            }
        }

        if let Some(true) = arguments.tunnel.insecure_tunnels {
            if !self.insecure_tunnels {
                self.insecure_tunnels = true;
            }
        }

        if let Some(ref caps) = arguments.caps {
            self.caps = Some(caps.clone());
        }

        if let Some(net_id) = arguments.net_id {
            self.net_id = Some(net_id);
        }

        self.exploratory = match &mut self.exploratory {
            None => Some(emissary_core::ExploratoryConfig {
                inbound_len: arguments.tunnel.exploratory_inbound_len,
                inbound_count: arguments.tunnel.exploratory_inbound_count,
                outbound_len: arguments.tunnel.exploratory_outbound_len,
                outbound_count: arguments.tunnel.exploratory_outbound_count,
            }),
            Some(config) => Some(emissary_core::ExploratoryConfig {
                inbound_len: arguments.tunnel.exploratory_inbound_len.or(config.inbound_len),
                inbound_count: arguments.tunnel.exploratory_inbound_count.or(config.inbound_count),
                outbound_len: arguments.tunnel.exploratory_outbound_len.or(config.outbound_len),
                outbound_count: arguments
                    .tunnel
                    .exploratory_outbound_count
                    .or(config.outbound_count),
            }),
        };

        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::tempdir;

    #[test]
    fn fresh_boot_directory_created() {
        let dir = tempdir().unwrap();
        let config = Config::try_from(Some(dir.path().to_owned())).unwrap();

        assert!(config.routers.is_empty());
        assert_eq!(config.static_key.len(), 32);
        assert_eq!(config.signing_key.len(), 32);
        assert_eq!(config.ntcp2_config.as_ref().unwrap().port, 8888);
        assert_eq!(
            config.ntcp2_config.as_ref().unwrap().host,
            String::from("127.0.0.1")
        );

        let (key, iv) = {
            let mut path = dir.path().to_owned();
            path.push("ntcp2.keys");
            let mut file = File::open(&path).unwrap();

            let mut contents = [0u8; 48];
            file.read_exact(&mut contents).unwrap();

            (
                contents[..32].to_vec(),
                TryInto::<[u8; 16]>::try_into(&contents[32..]).expect("to succeed"),
            )
        };

        assert_eq!(config.ntcp2_config.as_ref().unwrap().key, key);
        assert_eq!(config.ntcp2_config.as_ref().unwrap().iv, iv);
    }

    #[test]
    fn load_configs_correctly() {
        let dir = tempdir().unwrap();

        let (static_key, signing_key, ntcp2_config) = {
            let config = Config::try_from(Some(dir.path().to_owned())).unwrap();
            (config.static_key, config.signing_key, config.ntcp2_config)
        };

        let config = Config::try_from(Some(dir.path().to_owned())).unwrap();
        assert_eq!(config.static_key, static_key);
        assert_eq!(config.signing_key, signing_key);
        assert_eq!(
            config.ntcp2_config.as_ref().unwrap().port,
            ntcp2_config.as_ref().unwrap().port
        );
        assert_eq!(
            config.ntcp2_config.as_ref().unwrap().host,
            ntcp2_config.as_ref().unwrap().host
        );
        assert_eq!(
            config.ntcp2_config.as_ref().unwrap().key,
            ntcp2_config.as_ref().unwrap().key
        );
        assert_eq!(
            config.ntcp2_config.as_ref().unwrap().iv,
            ntcp2_config.as_ref().unwrap().iv
        );
    }

    #[test]
    fn config_update_works() {
        let dir = tempdir().unwrap();

        // create default config, verify the default ntcp2 port is 8888
        let (ntcp2_key, ntcp2_iv) = {
            let config = Config::try_from(Some(dir.path().to_owned())).unwrap();
            let ntcp2_config = config.ntcp2_config.unwrap();

            assert_eq!(ntcp2_config.port, 8888u16);

            (ntcp2_config.key, ntcp2_config.iv)
        };

        // create new ntcp2 config where the port is different
        let config = EmissaryConfig {
            exploratory: None,
            ntcp2: Some(Ntcp2Config {
                port: 1337u16,
                host: None,
            }),
            i2cp: Some(I2cpConfig { port: 0u16 }),
            sam: None,
            floodfill: false,
            caps: None,
            net_id: None,
            insecure_tunnels: false,
        };
        let config = toml::to_string(&config).expect("to succeed");
        let mut file = fs::File::create(dir.path().to_owned().join("router.toml")).unwrap();
        file.write_all(config.as_bytes()).unwrap();

        // load the new config
        //
        // verify that ntcp2 key & iv are the same but port is new
        let config = Config::try_from(Some(dir.path().to_owned())).unwrap();
        let ntcp2_config = config.ntcp2_config.unwrap();

        assert_eq!(ntcp2_config.port, 1337u16);
        assert_eq!(ntcp2_config.key, ntcp2_key);
        assert_eq!(ntcp2_config.iv, ntcp2_iv);
    }
}
