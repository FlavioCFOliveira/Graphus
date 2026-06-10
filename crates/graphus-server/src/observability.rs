//! Observability wiring (`04-technical-design.md` §9 / NFR-10): structured logging init, the
//! slow-query threshold, and the HTTP observability surface (`/metrics`, `/health/live`,
//! `/health/ready`) the server mounts alongside the REST API.
//!
//! Logging uses `tracing` + `tracing-subscriber` with an env-driven filter (`RUST_LOG`), so an
//! operator tunes verbosity without a rebuild. The slow-query log is a dedicated `tracing` target
//! (`graphus::slow_query`) the engine emits to when a query exceeds the configured threshold; the
//! threshold lives in a process-wide cell so the engine thread (which has no direct handle to the
//! config) can read it cheaply.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// The slow-query threshold, set once at startup and read by the engine thread for each query.
///
/// A `OnceLock<Duration>` rather than passing the config down to the engine: the engine task is
/// spawned with only the coordinator + channels, and the threshold is a single read-mostly value.
/// (Process-global; in a multi-server test process every server sets the same configured value.)
static SLOW_QUERY_THRESHOLD: OnceLock<Duration> = OnceLock::new();

/// A **per-server** readiness flag (`/health/ready`): `true` once the store is open + verified and the
/// engine is running, `false` while starting or shutting down. `/health/live` is always up while the
/// process runs.
///
/// Per-server (an `Arc<AtomicBool>` owned by the server and shared with its routes) rather than a
/// global, so multiple server instances in one process (e.g. parallel integration tests) do not race
/// on a single global readiness bit.
#[derive(Debug, Clone, Default)]
pub struct Readiness(Arc<AtomicBool>);

impl Readiness {
    /// A fresh, not-yet-ready flag.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks the server ready (store verified + engine running) or not-ready (shutting down).
    pub fn set(&self, ready: bool) {
        self.0.store(ready, Ordering::Release);
    }

    /// Whether the server is ready to serve.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Sets the global slow-query threshold (idempotent: only the first call wins, which is the server's
/// single startup call).
pub fn set_slow_query_threshold(threshold: Duration) {
    let _ = SLOW_QUERY_THRESHOLD.set(threshold);
}

/// The configured slow-query threshold, or a conservative 500 ms default if startup has not set it
/// (e.g. in a unit test that exercises the engine directly).
#[must_use]
pub fn slow_query_threshold() -> Duration {
    SLOW_QUERY_THRESHOLD
        .get()
        .copied()
        .unwrap_or(Duration::from_millis(500))
}

/// Initialises the global `tracing` subscriber (structured logs + slow-query log) from `RUST_LOG`.
///
/// Defaults to `info` when `RUST_LOG` is unset. Idempotent-safe: a second call (e.g. in a test that
/// also boots a server) is ignored rather than panicking, because the subscriber can only be set
/// once per process.
pub fn init_logging() {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::fmt;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    // `try_init` returns `Err` if a global subscriber is already installed; ignore it so multiple
    // server instances in one test process do not abort.
    let _ = fmt().with_env_filter(filter).with_target(true).try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ready_flag_round_trips() {
        let r = Readiness::new();
        assert!(!r.is_ready());
        r.set(true);
        assert!(r.is_ready());
        r.set(false);
        assert!(!r.is_ready());
    }

    #[test]
    fn readiness_clones_share_state() {
        let r = Readiness::new();
        let c = r.clone();
        r.set(true);
        assert!(c.is_ready(), "a clone observes the same flag");
    }

    #[test]
    fn slow_threshold_has_a_default() {
        // Without a prior `set` in this isolated assertion, the default is positive. (Other tests in
        // the process may have set it; either way it is a sane positive duration.)
        assert!(slow_query_threshold() > Duration::ZERO);
    }
}
