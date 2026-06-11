//! The top-level [`Server`]: wires config → store → engine → auth → listeners → shutdown into one
//! runnable process (`04-technical-design.md` §1.3 request lifecycle, §8 connectivity, §9 runtime).
//!
//! ## Startup sequence
//!
//! 1. Validate config; init logging + the slow-query threshold.
//! 2. Build the [`graphus_auth::Authenticator`] (RBAC bootstrap, JWT secret, UDS uid map, TLS config).
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

use graphus_auth::{Authenticator, Privilege};
use graphus_core::capability::Clock;
use graphus_io::FsyncPool;
use rustls::ServerConfig as RustlsServerConfig;

use crate::config::ServerConfig;
use crate::dbcatalog::DatabaseCatalog;
use crate::engine::EngineHandle;
use crate::listeners::{self, Listeners};
use crate::metrics::Metrics;
use crate::observability;
use crate::shutdown::ShutdownCoordinator;

/// A monotonic-nanoseconds [`Clock`] backed by the OS clock, for REST tx expiry + JWT validity.
///
/// `04 §8.4`: the server derives the JWT `now_unix_secs` and the REST inactivity clock from its
/// production clock; the library crates take a `Clock` so their logic stays wall-clock-free and
/// deterministically testable. This is that production clock.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_nanos(&self) -> u64 {
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
    /// Building the RBAC bootstrap or TLS config failed.
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

        // 1) Auth: RBAC bootstrap + JWT secret + UDS uid map + (optional) TLS config.
        let auth = Arc::new(build_authenticator(&config)?);
        let tls = build_tls(&config, &auth)?;

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

        // 3) Durability offload pool (`04 §9.1`). The engine thread does its own (off-runtime) syncs
        //    for the store image; the pool is the shared offload available to the runtime so no sync
        //    ever lands on a runtime worker. Sized from config.
        let fsync_pool = Arc::new(FsyncPool::new(
            config.fsync_threads,
            config.admission.engine_queue_capacity,
        ));

        // 4) Listeners.
        let shutdown = ShutdownCoordinator::new();
        let readiness = crate::observability::Readiness::new();
        let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SystemClock);
        let bound = listeners::start_all(
            &config,
            handle.clone(),
            Arc::clone(&auth),
            clock,
            tls,
            Arc::clone(&metrics),
            shutdown.clone(),
            readiness.clone(),
        )
        .await
        .map_err(ServerError::Listener)?;

        // 5) Ready.
        readiness.set(true);
        tracing::info!(
            rest = ?bound.rest_addr,
            bolt_tcp = ?bound.bolt_tcp_addr,
            uds = ?bound.uds_path,
            "graphus-server ready",
        );

        // The run loop: own the catalog (every engine) + listeners + pool, await the shutdown
        // trigger, drain.
        let runner = tokio::spawn(run_loop(
            Arc::clone(&catalog),
            bound.clone(),
            fsync_pool,
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

/// The run loop owned by the background task: awaits the shutdown trigger, then performs the §9.4
/// graceful sequence — stop accepting (drop the listeners), drain + flush every database engine
/// and join its thread (additional databases first, the default last — see
/// [`DatabaseCatalog::shutdown_all`]), and tear down the fsync pool.
async fn run_loop(
    catalog: Arc<DatabaseCatalog>,
    bound: Listeners,
    fsync_pool: Arc<FsyncPool>,
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

    // Drain in-flight transactions + flush + fdatasync + clean exit, on each engine's own thread.
    // Durable desired states are untouched: a database online now comes back online at next boot.
    tracing::info!("graceful shutdown: draining in-flight transactions and hardening the stores");
    catalog.shutdown_all().await;

    // Tear down the durability pool last (its Drop joins the sync threads).
    drop(fsync_pool);
    tracing::info!("graphus-server shutdown complete");
    Ok(())
}

/// Builds the [`Authenticator`]: JWT secret, the bootstrap admin user (with password + UDS uid as
/// configured), granted global `Admin`.
fn build_authenticator(config: &ServerConfig) -> Result<Authenticator, ServerError> {
    let mut auth = Authenticator::new(config.jwt_secret.as_bytes());

    let admin = &config.auth.admin_user;
    auth.catalog_mut()
        .create_user(admin)
        .map_err(|e| ServerError::Auth(format!("creating admin user: {e}")))?;
    auth.catalog_mut()
        .create_role("admin")
        .map_err(|e| ServerError::Auth(format!("creating admin role: {e}")))?;
    auth.catalog_mut()
        .grant_privilege("admin", Privilege::admin_database())
        .map_err(|e| ServerError::Auth(format!("granting admin privilege: {e}")))?;
    auth.catalog_mut()
        .grant_role(admin, "admin")
        .map_err(|e| ServerError::Auth(format!("granting admin role: {e}")))?;

    if !config.auth.admin_password.is_empty() {
        auth.set_password(admin, &config.auth.admin_password)
            .map_err(|e| ServerError::Auth(format!("setting admin password: {e}")))?;
    }
    if let Some(uid) = config.auth.admin_uid {
        auth.peers_mut().map_uid(uid, admin.clone());
    }
    Ok(auth)
}

/// Builds the shared rustls [`RustlsServerConfig`] from the configured PEM material, or `None` if no
/// TLS is configured (UDS-only deployment).
fn build_tls(
    config: &ServerConfig,
    auth: &Authenticator,
) -> Result<Option<Arc<RustlsServerConfig>>, ServerError> {
    if !config.tls.is_enabled() {
        return Ok(None);
    }
    let cert_path = config.tls.cert_path.as_ref().expect("is_enabled checked");
    let key_path = config.tls.key_path.as_ref().expect("is_enabled checked");
    let cert_pem = read_to_string(cert_path)?;
    let key_pem = read_to_string(key_path)?;
    let server_config = auth
        .tls_server_config(&cert_pem, &key_pem)
        .map_err(|e| ServerError::Auth(format!("building TLS config: {e}")))?;
    Ok(Some(Arc::new(server_config)))
}

/// Reads a file to a string, mapping the I/O error to a [`ServerError::Auth`] (TLS material).
fn read_to_string(path: &Path) -> Result<String, ServerError> {
    std::fs::read_to_string(path)
        .map_err(|e| ServerError::Auth(format!("reading {}: {e}", path.display())))
}
