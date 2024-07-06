use clap::{Parser, Subcommand};

use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about)]
pub struct Arguments {
    /// Base path where all i2p-related files are stored
    ///   
    /// Defaults to `$HOME/.emissary/router.toml` and if it doesn't exist,
    /// new directory is created
    #[arg(short, long, value_name = "PATH")]
    pub base_path: Option<PathBuf>,

    /// Logging targets.
    #[arg(short, long)]
    pub log: Option<String>,

    /// Command.
    ///
    /// If no command is provided, `emissary` starts as an i2p router
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Reseed router
    Reseed {
        /// Reseed `emissary` from file.
        #[arg(short = 'f', long, value_name = "FILE")]
        file: PathBuf,
    },
}
