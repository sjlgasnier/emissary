use clap::Parser;

#[derive(Parser)]
#[command(version, about)]
pub struct Arguments {
    /// Logging targets.
    #[arg(short, long)]
    pub log: Option<String>,
}
