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

/// The application name reported in the startup banner (the Cargo package name of this binary crate,
/// resolved at compile time — no build script needed).
pub const APP_NAME: &str = env!("CARGO_PKG_NAME");

/// The current server version reported in the startup banner (the workspace version, resolved at
/// compile time from `Cargo.toml`).
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The build's data-model pointer width in bits (64 on 64-bit targets, 32 on 32-bit) — the "bits"
/// figure a database server traditionally reports at startup (cf. Redis's `64 bit` banner line).
const POINTER_WIDTH_BITS: u32 = usize::BITS;

/// Builds the human-readable platform descriptor for the startup banner, e.g. `linux/x86_64 (64-bit)`.
///
/// Every component is resolved from the standard library (`std::env::consts` + `usize::BITS`), so it
/// reflects the *build target* faithfully with no build-time git/rustc plumbing to keep in sync.
#[must_use]
pub fn platform_descriptor() -> String {
    format!(
        "{}/{} ({}-bit)",
        std::env::consts::OS,
        std::env::consts::ARCH,
        POINTER_WIDTH_BITS,
    )
}

/// Emits the traditional database-server startup banner: one structured `info` log line naming the
/// application, its version and the runtime platform, plus the process id (`04 §9` / NFR-10).
///
/// This mirrors the convention every mature database server follows — PostgreSQL's
/// `starting PostgreSQL <v> on <platform>`, Redis's version/bits/PID banner — so an operator can, at
/// a glance (or with a single `grep`), confirm exactly which build is running and on what hardware.
/// The facts come only from compile-time (`CARGO_PKG_*`, target consts) and runtime (`pid`) sources,
/// so the banner can never drift from the actual binary. Call it once, at the very start of the boot
/// sequence, right after [`init_logging`]; the matching end-of-boot line is `"graphus-server ready"`.
pub fn log_startup_banner() {
    tracing::info!(
        app = APP_NAME,
        version = APP_VERSION,
        os = std::env::consts::OS,
        arch = std::env::consts::ARCH,
        pointer_width = POINTER_WIDTH_BITS,
        pid = std::process::id(),
        "starting {APP_NAME} {APP_VERSION} on {} — pid {}",
        platform_descriptor(),
        std::process::id(),
    );
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

    #[test]
    fn banner_identifies_this_build() {
        // The banner must never drift from the actual binary: name comes from Cargo, version is the
        // workspace version (`X.Y.Z`), and both are non-empty.
        assert_eq!(APP_NAME, "graphus-server");
        assert!(!APP_VERSION.is_empty(), "version must be present");
        assert_eq!(
            APP_VERSION.split('.').count(),
            3,
            "workspace version is semver `major.minor.patch`, got {APP_VERSION:?}",
        );
    }

    #[test]
    fn platform_descriptor_reports_target() {
        let p = platform_descriptor();
        // e.g. `linux/x86_64 (64-bit)` — carries the runtime OS, arch and pointer width.
        assert!(p.contains(std::env::consts::OS), "must name the OS: {p:?}");
        assert!(
            p.contains(std::env::consts::ARCH),
            "must name the arch: {p:?}"
        );
        assert!(
            p.contains(&format!("{POINTER_WIDTH_BITS}-bit")),
            "must report pointer width: {p:?}",
        );
    }

    #[test]
    fn startup_banner_does_not_panic() {
        // Logging without a global subscriber installed is a no-op, not a panic; this guards the
        // banner call site (formatting + field capture) against regressions.
        log_startup_banner();
    }
}
