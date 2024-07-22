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

use crate::{
    cli::{Arguments, Command},
    config::Config,
    error::Error,
    logger::init_logger,
    tokio_runtime::TokioRuntime,
};

use clap::Parser;
use emissary::router::Router;

use std::{fs::File, io::Write};

mod cli;
mod config;
mod error;
mod logger;
mod su3;
mod tokio_runtime;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary";

/// Result type for the crate.
pub type Result<T> = std::result::Result<T, Error>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Arguments {
        base_path,
        log,
        command,
    } = Arguments::parse();

    // initialize logger
    init_logger(log)?;

    // parse router config
    // TODO: this should also take any cli params
    let mut config = Config::try_from(base_path)?;

    let router = include_bytes!("/home/altonen/.i2pd/router.info").to_vec();

    match command {
        None => {
            let path = config.base_path.clone();
            let config: emissary::Config = config.into();
            let (router, local_router_info) =
                Router::new(TokioRuntime::new(), config, router).await.unwrap();

            // TODO: ugly
            let mut file = File::create(path.join("routerInfo.dat"))?;
            file.write_all(&local_router_info)?;

            let _ = router.await;
        }
        Some(Command::Reseed { file }) => match config.reseed(file) {
            Ok(num_routers) => tracing::info!(
                target: LOG_TARGET,
                ?num_routers,
                "router reseeded",
            ),
            Err(error) => {
                tracing::error!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to reseed router",
                );
                todo!();
            }
        },
    }

    Ok(())
}
