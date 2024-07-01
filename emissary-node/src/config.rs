use crate::{
    error::Error,
    su3::{ContentType, FileType, Su3},
    LOG_TARGET,
};

use home::home_dir;

use std::{
    fs,
    io::{self, Read, Write},
    path::PathBuf,
};

/// Router configuration.
pub struct Config {
    /// Base path.
    base_path: PathBuf,

    /// Router info.
    routers: Vec<Vec<u8>>,
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
                |path| Some(path),
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
            return Ok(Config::new_empty(path));
        }

        let config_path = {
            let mut path = path.clone();
            path.push("router.toml");
            path
        };

        // parse configuration, if it exists
        let mut config = match fs::File::open(&config_path) {
            Err(error) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?config_path,
                    %error,
                    "router config missing",
                );

                Config::new_empty(path.clone())
            }
            Ok(router) => {
                todo!();
            }
        };

        // parse router info
        let router_path = {
            let mut path = path.clone();
            path.push("routers");
            path
        };

        let router_dir = match fs::read_dir(&router_path) {
            Ok(router_dir) => router_dir,
            Err(error) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?router_path,
                    ?error,
                    "failed to open router directory, try reseeding",
                );

                return Ok(config);
            }
        };

        config.routers = router_dir
            .into_iter()
            .filter_map(|entry| {
                let dir = entry.ok()?;
                let mut file = fs::File::open(dir.path()).ok()?;

                let mut contents = Vec::new();
                file.read_to_end(&mut contents).ok()?;

                Some(contents)
            })
            .collect::<Vec<_>>();

        if config.routers.is_empty() {
            tracing::warn!(
                target: LOG_TARGET,
                "no routers, try reseeding the router",
            );
        }

        Ok(config)
    }
}

impl Config {
    /// Create empty config.
    fn new_empty(base_path: PathBuf) -> Self {
        Self {
            base_path,
            routers: Vec::new(),
        }
    }

    /// Reseed router from `file`.
    ///
    /// Returns the number of routers found in the reseed file
    pub fn reseed(&mut self, file: PathBuf) -> crate::Result<usize> {
        tracing::info!(
            target: LOG_TARGET,
            ?file,
            "reseed router from file"
        );

        let parsed = {
            let mut su3_file = fs::File::open(file)?;
            let mut contents = Vec::new();
            su3_file.read_to_end(&mut contents)?;

            Su3::from_bytes(&contents)?
        };

        assert_eq!(parsed.file_type, FileType::Zip);
        assert_eq!(parsed.content_type, ContentType::ReseedData);

        let (FileType::Zip, ContentType::ReseedData) = (parsed.file_type, parsed.content_type)
        else {
            tracing::error!(
                target: LOG_TARGET,
                file_type = ?parsed.file_type,
                content_type = ?parsed.content_type,
                "invalid file type",
            );
            return Err(Error::InvalidData);
        };

        // TODO: memory-mapped file
        let mut test_file = fs::File::create_new("/tmp/routers.zip")?;
        fs::File::write_all(&mut test_file, &parsed.content)?;

        let mut archive =
            zip::ZipArchive::new(test_file).map_err(|error| Error::Custom(error.to_string()))?;

        // create directory for router info if it doesn't exist yet
        let router_path = {
            let mut path = self.base_path.clone();
            path.push("routers");
            fs::create_dir_all(path.clone());

            path
        };

        tracing::trace!(
            target: LOG_TARGET,
            ?router_path,
            "parse router info",
        );

        let num_routers = (0..archive.len()).fold(0usize, |acc, i| {
            let mut file = archive.by_index(i).expect("to exist");
            let Some(outpath) = file.enclosed_name() else {
                return acc;
            };

            if !file.is_file() {
                tracing::warn!(
                    target: LOG_TARGET,
                    "non-file encountered in router info, ignoring",
                );
                return acc;
            }

            let path = {
                let mut path = router_path.clone();
                path.push(&outpath);
                path
            };

            tracing::trace!(
                target: LOG_TARGET,
                router = ?outpath.display(),
                size = ?file.size(),
                "save router to base path",
            );

            let mut outfile = fs::File::create(&path).unwrap();
            io::copy(&mut file, &mut outfile).unwrap();

            acc + 1
        });

        fs::remove_file("/tmp/routers.zip")?;

        Ok(num_routers)
    }
}
