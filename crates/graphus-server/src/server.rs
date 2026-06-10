//! The top-level [`Server`]: wires config → store → engine → auth → listeners → shutdown into one
//! runnable process (`04-technical-design.md` §1.3 request lifecycle, §8 connectivity, §9 runtime).
//!
//! ## Startup sequence
//!
//! 1. Validate config; init logging + the slow-query threshold.
//! 2. Build the [`graphus_auth::Authenticator`] (RBAC bootstrap, JWT secret, UDS uid map, TLS config).
//! 3. Spawn the **engine thread**, which constructs the `!Send` `TxnCoordinator` *on the thread*: it
//!    opens-or-creates the [`graphus_storage::RecordStore`], runs recovery, and — per `04 §4.6`/§4.8 —
//!    runs [`graphus_storage::check::verify_on_open`], **refusing to serve a corrupt store**.
//! 4. Start the three listeners (each enabled one) on the Tokio runtime.
//! 5. Mark ready; await a shutdown signal; drive graceful shutdown (`04 §9.4`).
//!
//! The server is built with [`Server::new`] and run with [`Server::run`]; tests use
//! [`Server::start`] to boot it in the background and drive it over loopback.

use std::path::Path;
use std::sync::Arc;

use graphus_auth::{Authenticator, Privilege};
use graphus_core::capability::Clock;
use graphus_cypher::TxnCoordinator;
use graphus_io::{FileBlockDevice, FsyncPool};
use graphus_storage::RecordStore;
use graphus_storage::check::verify_on_open;
use graphus_storage::recovery::recover_device;
use graphus_wal::{FileLogSink, WalManager};
use rustls::ServerConfig as RustlsServerConfig;

use crate::config::ServerConfig;
use crate::engine::{Engine, EngineHandle, spawn_engine};
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
    /// The engine client (tests can probe status / drive admin actions).
    pub engine: EngineHandle,
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

        // 2) Engine: spawn the thread, constructing the `!Send` coordinator *on the thread* (it owns
        //    the store; opening/recovering/verifying happens there — `04 §4.6`/§4.8).
        let engine = spawn_store_engine(&config, Arc::clone(&metrics))?;
        let handle = engine
            .handle
            .with_admission_limit(config.admission.max_concurrent_queries);

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

        // The run loop: own the engine + listeners + pool, await the shutdown trigger, drain.
        let runner = tokio::spawn(run_loop(
            engine,
            bound.clone(),
            handle.clone(),
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
            shutdown,
            readiness,
            runner,
        })
    }
}

/// The run loop owned by the background task: awaits the shutdown trigger, then performs the §9.4
/// graceful sequence — stop accepting (drop the listeners), drain + flush via the engine, join the
/// engine thread, and tear down the fsync pool.
async fn run_loop(
    engine: Engine,
    bound: Listeners,
    handle: EngineHandle,
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

    // Drain in-flight transactions + flush + fdatasync + clean exit, on the engine thread.
    tracing::info!("graceful shutdown: draining in-flight transactions and hardening the store");
    match handle.shutdown().await {
        Ok(()) => tracing::info!("store hardened and marked clean"),
        Err(e) => tracing::error!(error = %e, "error hardening the store on shutdown"),
    }

    // Join the engine thread (it exits its loop after the Shutdown command).
    let Engine { join, .. } = engine;
    if let Err(e) = tokio::task::spawn_blocking(move || join.join()).await {
        tracing::error!(error = %e, "joining engine thread");
    }

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

/// Spawns the engine thread, constructing the coordinator (and opening/recovering/verifying the
/// store) **on that thread** (`04 §4.6`/§4.8). The build closure captures only `Send` data (paths +
/// sizes), so the `!Send` coordinator never crosses the thread boundary.
fn spawn_store_engine(config: &ServerConfig, metrics: Arc<Metrics>) -> Result<Engine, ServerError> {
    // Ensure the store directory exists.
    std::fs::create_dir_all(&config.store_path).map_err(|e| {
        ServerError::Storage(graphus_core::GraphusError::Storage(format!(
            "creating store dir {}: {e}",
            config.store_path.display()
        )))
    })?;

    let device_file = config.device_file();
    let wal_file = config.wal_file();
    let pool_pages = config.buffer_pool_pages;
    let queue = config.admission.engine_queue_capacity;
    let result_buf = config.admission.result_buffer_capacity;

    let build = move || open_or_create_coordinator(&device_file, &wal_file, pool_pages);

    spawn_engine(build, queue, result_buf, metrics).map_err(ServerError::Storage)
}

/// Opens an existing store (recovering its WAL first) or creates a fresh one, then **verifies it**
/// (`04 §4.6`/§4.8) — refusing to serve a corrupt store. Runs on the engine thread.
///
/// A store is "existing" when its device file is a non-empty whole number of pages; otherwise a fresh
/// store is created. Recovery replays the durable WAL onto the device (ARIES redo+undo, `04 §4.8`)
/// before the catalog is read back.
fn open_or_create_coordinator(
    device_file: &Path,
    wal_file: &Path,
    pool_pages: usize,
) -> Result<TxnCoordinator<FileBlockDevice, FileLogSink>, graphus_core::GraphusError> {
    use graphus_core::GraphusError;

    let device_existing = device_file.metadata().map(|m| m.len() > 0).unwrap_or(false);

    let mut store = if device_existing {
        // Existing store: recover the WAL onto the device, then reopen.
        let mut device = FileBlockDevice::open(device_file)?;
        let mut wal = WalManager::open(
            FileLogSink::open(wal_file)
                .map_err(|e| GraphusError::Storage(format!("opening WAL: {e}")))?,
        )
        .map_err(|e| GraphusError::Storage(format!("opening WAL manager: {e}")))?;
        recover_device(&mut wal, &mut device)?;
        // Reopen the WAL fresh for serving (recovery consumed the recovery view).
        let wal = WalManager::open(
            FileLogSink::open(wal_file)
                .map_err(|e| GraphusError::Storage(format!("reopening WAL: {e}")))?,
        )
        .map_err(|e| GraphusError::Storage(format!("reopening WAL manager: {e}")))?;
        RecordStore::open(device, wal, pool_pages)?
    } else {
        // Fresh store on an empty device + a freshly-created WAL.
        let device = FileBlockDevice::open(device_file)?;
        let wal = WalManager::create(
            FileLogSink::open(wal_file)
                .map_err(|e| GraphusError::Storage(format!("creating WAL: {e}")))?,
        )
        .map_err(|e| GraphusError::Storage(format!("creating WAL manager: {e}")))?;
        // Seed element ids from 1 (`04 §2.2`).
        RecordStore::create(device, wal, pool_pages, 1)?
    };

    // The inviolable integrity gate (`04 §4.6`/§4.8): refuse to serve a corrupt store. The
    // coordinator's secondary index is in-memory candidate-only (rebuilt from the store), so an
    // empty `IndexAgreement` slice checks the store alone — correct here.
    verify_on_open(&mut store, &[])?;

    Ok(TxnCoordinator::new(store))
}
