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

/// The heap profiler's allocator, installed **only** under the `dhat-heap` feature (CLAUDE.md,
/// "Empirical measurement"). It wraps the system allocator to record every allocation with its call
/// stack, so it is compiled out entirely in every normal build — including `--release` — and the
/// server keeps the platform allocator it ships with.
///
/// `#[global_allocator]` needs no `unsafe` at this site: the `GlobalAlloc` implementation (and its
/// obligations) live inside `dhat`, so the crate-level `#![forbid(unsafe_code)]` above stands.
#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() -> ExitCode {
    // Armed first so it observes the whole process, and bound to a named local (never `_`, which
    // would drop it immediately and profile nothing) so it lives until `main` returns. The report is
    // written by its `Drop`, which means it lands on a CLEAN exit only: a graceful shutdown or the
    // `adopt` early return produce `dhat-heap.json`, while `SIGKILL` — or any path through
    // `std::process::exit` — bypasses the destructor and produces no file at all.
    #[cfg(feature = "dhat-heap")]
    let _dhat_profiler = dhat::Profiler::new_heap();

    // The `adopt` subcommand (`rmp` #681) is an OFFLINE, synchronous operation that never starts the
    // server runtime: intercept it before the config-then-runtime `try_main` path. It is recognised
    // only as the FIRST argument, so a config file literally named `adopt` is still usable as
    // `graphus-server ./adopt` (it just cannot be the bare first token — an acceptable, documented
    // edge given the subcommand's utility).
    let mut args = std::env::args().skip(1);
    if let Some(first) = args.next() {
        if first == "adopt" {
            return match graphus_server::adopt::run(args.collect()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("graphus-server: adopt: {e}");
                    ExitCode::FAILURE
                }
            };
        }
    }

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
        // Give every runtime-spawned thread (workers AND `spawn_blocking` threads) a larger stack
        // than Tokio's ~2 MiB default. The REST response encoders (`graphus_rest::value_to_jolt` /
        // `value_to_cbor`) recurse one frame per value-nesting level up to
        // `graphus_rest::value::MAX_ENCODE_DEPTH` (1000, mirroring the engine's `MAX_VALUE_DEPTH`), and
        // a stack overflow on stable Rust is an *uncatchable* process abort. On **aarch64** (a Tier-1
        // target: Apple Silicon, arm64 Linux, Raspberry Pi 5) each recursive `serde_json`/`ciborium`
        // build-and-drop frame is materially larger than on x86_64, so a legal deep value that encodes
        // fine on x86_64's 2 MiB overflows aarch64's — aborting the server on the response path. 8 MiB
        // holds the deepest legal value with generous headroom on every arch (only the touched pages
        // are resident, so an idle blocking thread costs nothing). The graphus-rest regression test
        // `encoding_and_dropping_a_max_depth_value_is_safe_on_a_N_mib_stack` pins this same size.
        .thread_stack_size(WORKER_THREAD_STACK_BYTES)
        .build()
}

/// Per-thread stack size for the Tokio runtime (workers + blocking pool), sized so a
/// `MAX_ENCODE_DEPTH`-deep REST value encodes without overflowing on any Tier-1 arch (notably
/// aarch64, whose recursive frames are larger than x86_64's). See [`build_runtime`].
const WORKER_THREAD_STACK_BYTES: usize = 8 * 1024 * 1024;

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
