#![allow(unused)]

use crate::{
    cli::{Arguments, Command},
    logger::init_logger,
};

use clap::Parser;

mod cli;
mod logger;
mod su3;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Arguments { log, command } = Arguments::parse();

    init_logger(log)?;

    match command {
        None => tracing::info!(
            target: LOG_TARGET,
            "start router"
        ),
        Some(Command::Reseed { file }) => tracing::info!(
            target: LOG_TARGET,
            ?file,
            "reseed router from file"
        ),
    }

    Ok(())
}
