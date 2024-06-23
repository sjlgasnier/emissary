use crate::{cli::Arguments, logger::init_logger};

use clap::Parser;

mod cli;
mod logger;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Arguments { log } = Arguments::parse();

    init_logger(log)?;

    Ok(())
}
