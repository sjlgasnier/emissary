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

use clap::{Args, Parser};

use std::path::PathBuf;

/// Tunnel configuration.
#[derive(Args)]
pub struct TunnelConfig {
    /// Length of an inbound exploratory tunnel.
    #[arg(long, value_name = "NUM")]
    pub exploratory_inbound_len: Option<usize>,

    /// Number of inbound exploratory tunnels.
    #[arg(long, value_name = "NUM")]
    pub exploratory_inbound_count: Option<usize>,

    /// Length of an outbound exploratory tunnel.
    #[arg(long, value_name = "NUM")]
    pub exploratory_outbound_len: Option<usize>,

    /// Number of outbound exploratory tunnels.
    #[arg(long, value_name = "NUM")]
    pub exploratory_outbound_count: Option<usize>,
}

#[derive(Parser)]
#[command(version, about)]
pub struct Arguments {
    /// Base path where all i2p-related files are stored
    ///   
    /// Defaults to $HOME/.emissary/ and if it doesn't exist,
    /// new directory is created
    #[arg(short, long, value_name = "PATH")]
    pub base_path: Option<PathBuf>,

    /// Logging targets
    ///
    /// By default, INFO is enabled for all logging targets
    ///
    /// Example:
    ///   -lemissary::tunnel=debug,emissary::sam,emissary::streaming=trace,emissary::ntcp2=off
    ///
    /// Enables debug logging for tunnels, trace logging for SAM and streaming and turns off
    /// logging for NTCP2
    #[arg(short, long)]
    pub log: Option<String>,

    /// Run the router as a floodfill.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub floodfill: Option<bool>,

    /// Allow emissary to build insecure tunnels.
    ///
    /// Disables /16 subnet and maximum tunnel participation checks
    ///
    /// Should only be used for testing
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub insecure_tunnels: Option<bool>,

    /// Router capabilities
    #[arg(long)]
    pub caps: Option<String>,

    /// Network ID
    #[arg(long)]
    pub net_id: Option<u8>,

    /// Exploratory tunnel configuration
    #[clap(flatten)]
    pub exploratory: TunnelConfig,
}
