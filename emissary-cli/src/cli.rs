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

    /// Should the node be run as floodfill router.
    #[arg(long, action=clap::ArgAction::SetTrue)]
    pub floodfill: Option<bool>,

    /// Router capabilities.
    #[arg(long)]
    pub caps: Option<String>,

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
