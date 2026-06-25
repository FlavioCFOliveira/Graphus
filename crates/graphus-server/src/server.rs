//! The top-level [`Server`]: wires config → store → engine → auth → listeners → shutdown into one
//! runnable process (`04-technical-design.md` §1.3 request lifecycle, §8 connectivity, §9 runtime).
//!
//! ## Startup sequence
//!
//! 1. Validate config; init logging + the slow-query threshold.
//! 2. Load the durable **security catalog** ([`crate::security`], rmp #92) — a present
//!    `security.toml` is authoritative, an absent one seeds from config bootstrap and is persisted,
//!    a malformed one fails startup closed. The per-listener authentication seam is a **live**
//!    [`graphus_auth::AuthProvider`] over that catalog ([`crate::security::LiveAuth`], rmp #94), so
//!    runtime security mutations affect authentication immediately; the TLS config is built from it.
//! 3. Load the **database catalog** ([`crate::dbcatalog`], decision `D-multi-db`) — a malformed
//!    catalog fails startup closed. Start the **default database's** engine thread, which
//!    constructs the `!Send` `TxnCoordinator` *on the thread*: it opens-or-creates the
//!    [`graphus_storage::RecordStore`], runs recovery, and — per `04 §4.6`/§4.8 — runs
//!    `verify_on_open`, **refusing to serve a corrupt store** (its failure fails startup, exactly
//!    the single-db behaviour). Then start every additional catalog database whose desired state
//!    is online; one of those failing is logged and never blocks the server.
//! 4. Start the three listeners (each enabled one) on the Tokio runtime.
//! 5. Mark ready; await a shutdown signal; drive graceful shutdown (`04 §9.4`) across every
//!    running database engine.
//!
//! The server is built with [`Server::new`] and run with [`Server::run`]; tests use
//! [`Server::start`] to boot it in the background and drive it over loopback.

use std::path::Path;
use std::sync::Arc;

use graphus_auth::AuthProvider;
use graphus_core::capability::Clock;
use rustls::ServerConfig as RustlsServerConfig;

use crate::audit::AuditLog;
use crate::config::ServerConfig;
use crate::dbcatalog::DatabaseCatalog;
use crate::engine::EngineHandle;
use crate::listeners::{self, Listeners};
use crate::metrics::Metrics;
use crate::observability;
use crate::security::SecurityCatalog;
use crate::shutdown::ShutdownCoordinator;

/// The production [`Clock`]: a **monotonic** timeline for elapsed/idle measurement and a separate
/// **wall-clock** timeline for absolute timestamps (rmp #395).
///
/// `04 §8.4`: the server derives the JWT validity clock and the REST inactivity timeout from its
/// production clock; the library crates take a `Clock` so their logic stays clock-agnostic and
/// deterministically testable. This is that production clock.
///
/// - [`now_nanos`](Clock::now_nanos) reads [`std::time::Instant`] (the OS monotonic clock,
///   `CLOCK_MONOTONIC`), anchored at process start via [`MONOTONIC_EPOCH`]. It never decreases, so a
///   backwards wall-clock adjustment (NTP step, operator change) can **never** make a query-latency
///   or transaction-idle duration wrap to zero or to a spurious multi-decade value (the rmp #395
///   bug). This is the source `finalize_inflight` (query latency / slow-query log) and the REST
///   transaction inactivity sweep (rmp #389) measure against.
/// - [`now_unix_nanos`](Clock::now_unix_nanos) reads [`std::time::SystemTime`] (the wall clock) for
///   the one place an absolute timestamp is needed: JWT validity (`04 §8.4`). It may step with the
///   system clock; it is never used to measure an interval.
#[derive(Debug, Default)]
pub struct SystemClock;

/// Process-start anchor for the monotonic clock. Captured once on first read so `now_nanos` returns
/// a non-decreasing nanosecond count since process start (a stable `u64` derived from
/// [`std::time::Instant`], which itself is not representable as an absolute integer).
static MONOTONIC_EPOCH: std::sync::LazyLock<std::time::Instant> =
    std::sync::LazyLock::new(std::time::Instant::now);

impl Clock for SystemClock {
    fn now_nanos(&self) -> u64 {
        // Monotonic (CLOCK_MONOTONIC via `Instant`): elapsed since the process-start anchor. `Instant`
        // is guaranteed non-decreasing, so this never wraps; saturate the (multi-century) nanosecond
        // range into `u64` rather than panic.
        u64::try_from(MONOTONIC_EPOCH.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    fn now_unix_nanos(&self) -> u64 {
        // Wall clock: absolute nanoseconds since the Unix epoch, for JWT validity only. A pre-epoch
        // system clock maps to 0; an out-of-range future to u64::MAX. NEVER used for elapsed time.
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }
}

/// What can go wrong starting the server.
#[derive(Debug)]
pub enum ServerError {
    /// The configuration is invalid.
    Config(crate::config::ConfigError),
    /// Opening/recovering/verifying the store failed (e.g. integrity-check failure — `04 §4.6`).
    Storage(graphus_core::GraphusError),
    /// Loading the durable database catalog failed (a malformed `databases.toml` fails startup
    /// closed — `crate::dbcatalog`).
    Catalog(crate::dbcatalog::CatalogError),
    /// Loading the durable security catalog failed (a malformed `security.toml` fails startup
    /// closed — `crate::security`).
    Security(crate::security::SecurityError),
    /// Opening (and crash-recovering) the audit log failed (rmp #70). A configured-and-enabled
    /// audit log that cannot be opened fails startup, since the security trail must be present.
    Audit(std::io::Error),
    /// Building the TLS config failed.
    Auth(String),
    /// Binding a listener socket failed.
    Listener(String),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(e) => write!(f, "config error: {e}"),
            Self::Storage(e) => write!(f, "storage error: {e}"),
            Self::Catalog(e) => write!(f, "catalog error: {e}"),
            Self::Security(e) => write!(f, "security catalog error: {e}"),
            Self::Audit(e) => write!(f, "audit log error: {e}"),
            Self::Auth(m) => write!(f, "auth setup error: {m}"),
            Self::Listener(m) => write!(f, "listener error: {m}"),
        }
    }
}

impl std::error::Error for ServerError {}

/// The configured server, ready to [`run`](Server::run) or [`start`](Server::start).
pub struct Server {
    config: ServerConfig,
}

/// A handle to a running server (from [`Server::start`]): lets a caller learn the bound addresses
/// and trigger a graceful shutdown, then await full teardown.
pub struct ServerHandle {
    /// The bound REST address (if the REST listener is enabled), for clients/tests.
    pub rest_addr: Option<std::net::SocketAddr>,
    /// The bound Bolt-TCP address (if enabled).
    pub bolt_tcp_addr: Option<std::net::SocketAddr>,
    /// The UDS path (if enabled).
    pub uds_path: Option<std::path::PathBuf>,
    /// The shared metrics registry (tests assert against it).
    pub metrics: Arc<Metrics>,
    /// The **default database's** engine client (tests can probe status / drive admin actions).
    /// The existing single-database consumers keep working against this handle unchanged.
    pub engine: EngineHandle,
    /// The database catalog: named databases, their durable lifecycle state, and the registry of
    /// running engines (decision `D-multi-db`, rmp #83 — the rmp-#84 admin surface drives it).
    pub catalog: Arc<DatabaseCatalog>,
    /// Triggers graceful shutdown when fired.
    shutdown: ShutdownCoordinator,
    /// Per-server readiness (`/health/ready`); tests may probe it directly.
    pub readiness: crate::observability::Readiness,
    /// The background task driving the run loop; awaited by [`ServerHandle::join`].
    runner: tokio::task::JoinHandle<Result<(), ServerError>>,
}

impl ServerHandle {
    /// Triggers a graceful shutdown and awaits full teardown (drain + flush + clean exit, `04 §9.4`).
    ///
    /// # Errors
    /// Any error encountered during the run/shutdown sequence.
    pub async fn shutdown(self) -> Result<(), ServerError> {
        self.shutdown.trigger();
        self.runner
            .await
            .map_err(|e| ServerError::Listener(format!("server task panicked: {e}")))?
    }

    /// Triggers shutdown without awaiting (fire-and-forget); use [`join`](Self::join) to await.
    pub fn trigger_shutdown(&self) {
        self.shutdown.trigger();
    }

    /// Awaits the run loop's completion (after a [`trigger_shutdown`](Self::trigger_shutdown) or a
    /// received signal).
    ///
    /// # Errors
    /// Any error encountered during the run/shutdown sequence.
    pub async fn join(self) -> Result<(), ServerError> {
        self.runner
            .await
            .map_err(|e| ServerError::Listener(format!("server task panicked: {e}")))?
    }

    /// Waits for SIGTERM/SIGINT, then drives graceful shutdown and awaits teardown (`04 §9.4`).
    ///
    /// # Errors
    /// Any error from the run/shutdown sequence.
    async fn shutdown_on_signal(self) -> Result<(), ServerError> {
        crate::shutdown::wait_for_signal().await;
        tracing::info!("shutdown signal received");
        self.shutdown().await
    }
}

impl Server {
    /// Builds a server from `config` (not yet started).
    #[must_use]
    pub fn new(config: ServerConfig) -> Self {
        Self { config }
    }

    /// Validates config, then runs the server until a shutdown signal (SIGTERM/SIGINT) is received,
    /// performing graceful shutdown before returning (`04 §9.4`).
    ///
    /// This is the entry point [`main`](../graphus_server/fn.main.html) calls.
    ///
    /// # Errors
    /// [`ServerError`] on a startup or shutdown failure.
    pub async fn run(self) -> Result<(), ServerError> {
        let handle = self.start().await?;
        // Wait for an OS signal, then shut down gracefully.
        handle.shutdown_on_signal().await
    }

    /// Boots the server in the background and returns a [`ServerHandle`] once every listener is bound
    /// and the engine is serving. Tests use this to drive a live server over loopback.
    ///
    /// # Errors
    /// [`ServerError`] if config is invalid, the store cannot be opened/verified, auth/TLS setup
    /// fails, or a listener cannot bind.
    pub async fn start(self) -> Result<ServerHandle, ServerError> {
        self.config.validate().map_err(ServerError::Config)?;
        observability::init_logging();
        observability::set_slow_query_threshold(self.config.timing.slow_query_threshold());

        let config = self.config;
        let metrics = Arc::new(Metrics::new());

        // 1) Security: load the durable, live RBAC model (rmp #92). A present `security.toml` is
        //    authoritative; an absent one seeds from config bootstrap and is persisted; a malformed
        //    one fails startup CLOSED (never silently resets the security model). The connectivity
        //    seams' **authentication** path now consults the LIVE catalog through a `LiveAuth`
        //    provider (rmp #94) — no longer a startup snapshot — so a user created/changed/dropped at
        //    runtime authenticates (or is refused) immediately. The admin-statement + `/admin/*`
        //    surfaces hold the same live `SecurityCatalog` and mutate it.
        let security = Arc::new(SecurityCatalog::load(&config).map_err(ServerError::Security)?);
        let auth: Arc<dyn AuthProvider> =
            Arc::new(crate::security::LiveAuth::new(Arc::clone(&security)));
        let tls = build_tls(&config, &security)?;

        // 1b) Security audit log (rmp #70): open (and crash-recover) the append-only JSONL sink
        //     under the store path. When `audit.enabled` is false this is a no-op sink (writes
        //     nothing). A configured-and-enabled log that cannot be opened fails startup — the
        //     security trail must be present when an operator asked for it.
        let audit =
            AuditLog::open(&config.audit, &config.store_path).map_err(ServerError::Audit)?;

        // 2) The database catalog + engines (`crate::dbcatalog`, decision `D-multi-db`): load the
        //    durable catalog (malformed ⇒ fail startup closed), start the default database (its
        //    failure fails startup — unchanged single-db behaviour; the `!Send` coordinator is
        //    constructed *on its engine thread*, opening/recovering/verifying there — `04
        //    §4.6`/§4.8), then start every additional database marked online (failures logged,
        //    never fatal). The returned handle already carries the admission limit (`04 §9.3`).
        let catalog = Arc::new(
            DatabaseCatalog::load(&config, Arc::clone(&metrics)).map_err(ServerError::Catalog)?,
        );
        let handle = catalog
            .start_default()
            .await
            .map_err(ServerError::Storage)?;
        catalog.start_catalog_databases().await;

        // 3) Durability model (`04 §9.1`). Each database engine performs its own `fdatasync`/`fsync`
        //    on its dedicated OS thread, which is *not* a Tokio runtime worker — so a durable sync
        //    never blocks an async worker, and no separate offload pool is needed on this path. (The
        //    reusable `graphus_io::FsyncPool` primitive remains available for the concurrent-pool path
        //    that is deferred by design — the production engine is single-writer.)

        // 4) Listeners.
        let shutdown = ShutdownCoordinator::new();
        let readiness = crate::observability::Readiness::new();
        let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SystemClock);
        // `rmp` #428: the engines are already running (each on its own OS thread). If any *later*
        // startup step fails — notably a listener failing to bind — returning `Err` here would drop the
        // catalog and the engine handles WITHOUT a graceful `shutdown_all()` (there is no `Drop` on the
        // catalog/engine that drains + hardens), detaching the engine threads and leaving each store
        // never marked clean (the next open then needlessly runs crash recovery). So every fallible
        // post-engine step funnels through `harden_on_startup_error`, which drives `shutdown_all()`
        // (drain → flush → join every engine thread, default last) before surfacing the original error.
        let bound = match listeners::start_all(
            &config,
            handle.clone(),
            Arc::clone(&catalog),
            Arc::clone(&security),
            Arc::clone(&auth),
            Arc::clone(&audit),
            clock,
            tls,
            Arc::clone(&metrics),
            shutdown.clone(),
            readiness.clone(),
        )
        .await
        {
            Ok(bound) => bound,
            Err(e) => return Err(harden_on_startup_error(&catalog, ServerError::Listener(e)).await),
        };

        // 5) Ready.
        readiness.set(true);
        tracing::info!(
            rest = ?bound.rest_addr,
            bolt_tcp = ?bound.bolt_tcp_addr,
            uds = ?bound.uds_path,
            "graphus-server ready",
        );

        // The run loop: own the catalog (every engine) + listeners, await the shutdown trigger, drain.
        let runner = tokio::spawn(run_loop(
            Arc::clone(&catalog),
            bound.clone(),
            Arc::clone(&audit),
            shutdown.clone(),
            readiness.clone(),
        ));

        Ok(ServerHandle {
            rest_addr: bound.rest_addr,
            bolt_tcp_addr: bound.bolt_tcp_addr,
            uds_path: bound.uds_path,
            metrics,
            engine: handle,
            catalog,
            shutdown,
            readiness,
            runner,
        })
    }
}

/// Drives a graceful [`DatabaseCatalog::shutdown_all`] (drain → flush → join every running engine
/// thread, default last) before returning the startup `err` that triggered it (`rmp` #428).
///
/// Called when a startup step *after* the engines were spawned fails (e.g. a listener fails to bind).
/// Without this, the early `return Err(..)` would drop the catalog and engine handles with no graceful
/// teardown — there is no `Drop` impl on the catalog/engine that drains in-flight transactions, flushes
/// dirty pages and `sync_all`s the device, so the engine threads would detach and each store would be
/// left never marked clean (a needless crash-recovery on the next open). Hardening here makes a failed
/// startup leave every store as durable + clean as a graceful shutdown would, then surfaces the
/// original error unchanged.
async fn harden_on_startup_error(catalog: &DatabaseCatalog, err: ServerError) -> ServerError {
    tracing::error!(
        error = %err,
        "startup failed after the engines were spawned; hardening every store (drain + flush + join) \
         before exiting (rmp #428)",
    );
    catalog.shutdown_all().await;
    err
}

/// The run loop owned by the background task: awaits the shutdown trigger, then performs the §9.4
/// graceful sequence — stop accepting (drop the listeners), then drain + flush every database engine
/// and join its thread (additional databases first, the default last — see
/// [`DatabaseCatalog::shutdown_all`]). Each engine fsyncs on its own dedicated OS thread.
async fn run_loop(
    catalog: Arc<DatabaseCatalog>,
    bound: Listeners,
    audit: Arc<AuditLog>,
    shutdown: ShutdownCoordinator,
    readiness: crate::observability::Readiness,
) -> Result<(), ServerError> {
    // Block here until shutdown is triggered (by signal or admin).
    shutdown.wait().await;
    readiness.set(false);
    tracing::info!("graceful shutdown: stop accepting connections");

    // Stop accepting: dropping the acceptors closes the listening sockets; in-flight connection
    // tasks keep running until they finish or the drain deadline forces them down (`04 §9.4`).
    bound.stop_accepting();

    // Bounded connection drain (`rmp` #429): give in-flight connections up to the configured deadline
    // to finish on their own before the engine drain force-closes them. This enforces the drain-
    // deadline the `04 §9.4` docstring promised but the prior `stop_accepting → shutdown_all` sequence
    // never actually waited on (connection tasks were neither joined nor time-bounded). A connection
    // still in flight at the deadline is not abandoned: the engine drain below rolls back its in-flight
    // transaction and hardens the store, so it is force-closed cleanly (never `engine_gone` racing a
    // half-applied write).
    if bound.drain_connections().await {
        tracing::info!("graceful shutdown: all in-flight connections drained within the deadline");
    } else {
        tracing::info!(
            "graceful shutdown: drain deadline elapsed; force-closing remaining connections via the \
             engine drain"
        );
    }

    // Drain in-flight transactions + flush + fdatasync + clean exit, on each engine's own thread.
    // Durable desired states are untouched: a database online now comes back online at next boot.
    tracing::info!("graceful shutdown: draining in-flight transactions and hardening the stores");
    catalog.shutdown_all().await;

    // Flush any batched (unsynced) data-change audit events so the final batch is durable before
    // exit (rmp #70). Best-effort: a flush error is logged, never fatal.
    if let Err(e) = audit.flush() {
        tracing::error!(target: "graphus::audit", error = %e, "failed to flush audit log on shutdown");
    }

    tracing::info!("graphus-server shutdown complete");
    Ok(())
}

/// Builds the shared rustls [`RustlsServerConfig`] from the configured PEM material, or `None` if no
/// TLS is configured (UDS-only deployment).
///
/// Building the TLS config only reads the PEM material from disk (no RBAC state is consulted), so it
/// takes a single brief startup read lock on the live [`SecurityCatalog`] via
/// [`SecurityCatalog::with_auth`] — the catalog owns the `tls_server_config` builder.
fn build_tls(
    config: &ServerConfig,
    security: &SecurityCatalog,
) -> Result<Option<Arc<RustlsServerConfig>>, ServerError> {
    if !config.tls.is_enabled() {
        return Ok(None);
    }
    let cert_path = config.tls.cert_path.as_ref().expect("is_enabled checked");
    let key_path = config.tls.key_path.as_ref().expect("is_enabled checked");
    let cert_pem = read_to_string(cert_path)?;
    let key_pem = read_to_string(key_path)?;
    let server_config = security
        .with_auth(|auth| auth.tls_server_config(&cert_pem, &key_pem))
        .map_err(|e| ServerError::Auth(format!("building TLS config: {e}")))?;
    Ok(Some(Arc::new(server_config)))
}

/// Reads a file to a string, mapping the I/O error to a [`ServerError::Auth`] (TLS material).
fn read_to_string(path: &Path) -> Result<String, ServerError> {
    std::fs::read_to_string(path)
        .map_err(|e| ServerError::Auth(format!("reading {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// rmp #395: the production clock's monotonic timeline (`now_nanos`) never decreases across
    /// successive reads, so it is safe for elapsed/idle measurement (no NTP-step regressions).
    #[test]
    fn system_clock_now_nanos_is_monotonic() {
        let clock = SystemClock;
        let mut prev = clock.now_nanos();
        for _ in 0..1_000 {
            let next = clock.now_nanos();
            assert!(
                next >= prev,
                "monotonic clock went backwards: {prev} -> {next}"
            );
            prev = next;
        }
    }

    /// rmp #395: the wall-clock timeline (`now_unix_nanos`) is an absolute Unix timestamp (well past
    /// the 2020 epoch in any realistic test environment) and is distinct from the monotonic
    /// process-start-relative `now_nanos`.
    #[test]
    fn system_clock_now_unix_nanos_is_absolute_wall_clock() {
        let clock = SystemClock;
        // 2020-01-01T00:00:00Z in nanoseconds since the Unix epoch.
        const Y2020_NANOS: u64 = 1_577_836_800 * 1_000_000_000;
        assert!(
            clock.now_unix_nanos() > Y2020_NANOS,
            "wall clock should report an absolute post-2020 Unix timestamp"
        );
        // The monotonic clock is process-start-relative, so it is far smaller than the wall clock —
        // proving the two timelines are genuinely different sources (rmp #395).
        assert!(clock.now_nanos() < Y2020_NANOS);
    }
}
