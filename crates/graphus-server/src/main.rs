//! `graphus-server` binary entry point: parse config, build, and run the server until shutdown
//! (`04-technical-design.md` §9).
//!
//! Config is loaded from a TOML file named on the command line (`graphus-server <config.toml>`) or
//! pointed to by `GRAPHUS_CONFIG`, then overlaid with `GRAPHUS_*` environment variables; with none
//! given, built-in defaults apply (overridable by env). All listener wiring, admission control,
//! observability and graceful shutdown live in the `graphus_server` library.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use graphus_server::{Server, ServerConfig};

/// A multi-thread Tokio runtime drives the listeners and async glue (`04 §9.1`); the single-threaded
/// query engine runs on its own dedicated thread, spawned by the library.
#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Logging may not be initialised yet on an early config failure; print to stderr too.
            eprintln!("graphus-server: fatal: {e}");
            tracing::error!(error = %e, "graphus-server exiting with error");
            ExitCode::FAILURE
        }
    }
}

/// Loads config and runs the server to completion (a clean shutdown returns `Ok`).
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = resolve_config_path();
    let config = ServerConfig::load(config_path.as_deref())?;
    let server = Server::new(config);
    server.run().await?;
    Ok(())
}

/// Resolves the config-file path from the first CLI argument, else `GRAPHUS_CONFIG`, else `None`
/// (defaults + env only).
fn resolve_config_path() -> Option<PathBuf> {
    if let Some(arg) = std::env::args().nth(1) {
        return Some(PathBuf::from(arg));
    }
    std::env::var_os("GRAPHUS_CONFIG").map(PathBuf::from)
}
