use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about)]
pub struct Arguments {
    /// Logging targets.
    #[arg(short, long)]
    pub log: Option<String>,

    /// Command.
    ///
    /// If no command is provided, `emissary` starts as an i2p router.
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Reseed router
    Reseed {
        /// Reseed `emissary` from file.
        #[arg(short = 'f', long, value_name = "FILE")]
        file: String,
    },
}
