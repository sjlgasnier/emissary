use anyhow::anyhow;
use tracing::Level;
use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    prelude::*,
};

use std::str::FromStr;

/// Initialize logger.
pub fn init_logger(log: Option<String>) -> anyhow::Result<()> {
    let mut targets = Targets::new().with_target("", Level::INFO);

    if let Some(log) = log {
        let mut log_targets = Vec::<&str>::new();

        for target in log.split(',') {
            let split = target.split('=').collect::<Vec<_>>();
            log_targets.push(split.first().ok_or(anyhow!("invalid log target"))?);

            let Some(level) = split.get(1) else {
                continue;
            };

            targets = log_targets
                .into_iter()
                .fold(targets, |targets, log_target| {
                    targets.with_target(
                        log_target,
                        LevelFilter::from_str(level).expect("valid level filter"),
                    )
                });
            log_targets = Vec::new();
        }
    }

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(targets)
        .try_init()
        .map_err(From::from)
}
