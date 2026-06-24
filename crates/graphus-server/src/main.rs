//! `graphus-server` binary entry point: parse config, build the runtime, and run the server until
//! shutdown (`04-technical-design.md` §9).
//!
//! Config is loaded from a TOML file named on the command line (`graphus-server <config.toml>`) or
//! pointed to by `GRAPHUS_CONFIG`, then overlaid with `GRAPHUS_*` environment variables; with none
//! given, built-in defaults apply (overridable by env). All listener wiring, admission control,
//! observability and graceful shutdown live in the `graphus_server` library.
//!
//! `main` is **synchronous on purpose** (rmp #363): it loads configuration *first* so the Tokio
//! runtime can be built with a `max_blocking_threads` budget *derived from* `max_connections`. This
//! is load-bearing — every accepted Bolt session occupies one blocking thread for its whole lifetime
//! (`listeners::bolt::spawn_session` uses `spawn_blocking`), so with the framework's `#[tokio::main]`
//! default of 512 blocking threads, the 513th concurrent session would queue forever once
//! `max_connections > 512` (the sample config sets 4096). Sizing the pool from config makes that
//! silent stall impossible.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use graphus_server::{Server, ServerConfig};

fn main() -> ExitCode {
    match try_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Logging may not be initialised yet on an early config/runtime failure; print to stderr
            // too so the cause is never lost.
            eprintln!("graphus-server: fatal: {e}");
            tracing::error!(error = %e, "graphus-server exiting with error");
            ExitCode::FAILURE
        }
    }
}

/// Loads config, builds a correctly-sized multi-thread runtime, then runs the server to completion
/// (a clean shutdown returns `Ok`).
fn try_main() -> Result<(), Box<dyn std::error::Error>> {
    // Config must be loaded *before* the runtime is built so the blocking-thread budget can be
    // derived from `admission.max_connections` (rmp #363). `load` already applies file + env +
    // defaults; full validation runs again inside `Server::start`.
    let config_path = resolve_config_path();
    let config = ServerConfig::load(config_path.as_deref())?;

    let runtime = build_runtime(&config)?;
    runtime.block_on(run(config))
}

/// Builds the multi-thread Tokio runtime that drives the listeners and async glue (`04 §9.1`).
///
/// The worker-thread count keeps Tokio's default (one per CPU) — unchanged by this fix. What this
/// fix sizes is **`max_blocking_threads`**, derived from the connection cap via
/// `config.admission.blocking_thread_budget()`: each Bolt session runs
/// on a `spawn_blocking` task held for the connection's lifetime, so the blocking pool must seat
/// `max_connections` of them plus headroom for REST / engine-bridge / catalog-persistence blocking
/// work. Tokio creates these threads lazily and reaps idle ones after ~10 s, so a high cap costs
/// nothing until the connections actually arrive.
///
/// The single-threaded query engine runs on its own dedicated thread (spawned by the library), and
/// `Handle::block_on` is only ever invoked from those blocking session threads — never from a worker
/// thread — so a high blocking budget does not risk deadlocking the worker pool.
fn build_runtime(config: &ServerConfig) -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(config.admission.blocking_thread_budget())
        .build()
}

/// Runs the server to completion on the current runtime (a clean shutdown returns `Ok`).
async fn run(config: ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
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
