//! The three listeners (`04-technical-design.md` §8): **UDS-Bolt**, **TCP-Bolt+TLS**, and
//! **REST+TLS**. [`start_all`] binds every enabled listener and spawns its async accept loop; the
//! returned [`Listeners`] records the bound addresses and lets the server stop accepting on shutdown.
//!
//! Each accept loop runs as its own Tokio task and selects on the shared [`ShutdownCoordinator`], so
//! a shutdown stops all three promptly (`04 §9.4`). Per-connection work is spawned as further tasks
//! (Bolt sessions on `spawn_blocking`, REST connections on the runtime).

mod bolt;
mod extra_routes;
mod rest;
mod transport;

use std::sync::Arc;

use std::time::Duration;

use graphus_auth::AuthProvider;
use graphus_core::capability::Clock;
use graphus_io::{TcpAcceptor, UdsAcceptor};
use rustls::ServerConfig as RustlsServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::admin::AdminContext;
use crate::audit::AuditLog;
use crate::config::ServerConfig;
use crate::dbcatalog::DatabaseCatalog;
use crate::engine::EngineHandle;
use crate::metrics::Metrics;
use crate::security::SecurityCatalog;
use crate::shutdown::ShutdownCoordinator;

/// The bound listeners: their public addresses and the handles that keep the accept loops alive.
///
/// Dropping (or [`stop_accepting`](Self::stop_accepting)) the struct stops every accept loop by
/// triggering the shared shutdown signal the loops select on; the listening sockets close as the
/// acceptors drop inside their tasks.
#[derive(Clone)]
pub struct Listeners {
    /// The bound REST address, if the REST listener is enabled.
    pub rest_addr: Option<std::net::SocketAddr>,
    /// The bound Bolt-TCP address, if enabled.
    pub bolt_tcp_addr: Option<std::net::SocketAddr>,
    /// The UDS path, if enabled.
    pub uds_path: Option<std::path::PathBuf>,
    /// The shared shutdown signal the accept loops select on.
    shutdown: ShutdownCoordinator,
    /// The process-wide connection-admission semaphore (rmp #118): each accepted connection holds one
    /// permit for its whole lifetime, so the count of *checked-out* permits is the count of in-flight
    /// connections. Used by [`drain_connections`](Self::drain_connections) to observe the graceful-
    /// shutdown connection drain (rmp #429).
    conn_limit: Arc<tokio::sync::Semaphore>,
    /// The configured connection cap (the semaphore's total permits) — the denominator for "all
    /// connections drained" (`available_permits() == max_connections`).
    max_connections: usize,
    /// The bounded connection-drain deadline applied on graceful shutdown between
    /// [`stop_accepting`](Self::stop_accepting) and the engine drain (rmp #429).
    drain_deadline: Duration,
}

impl Listeners {
    /// Stops accepting new connections by triggering the shared shutdown signal (`04 §9.4`).
    ///
    /// In-flight connection tasks keep running until they finish or the drain deadline forces them
    /// down; this only closes the *listening* sockets (the accept loops break out of their select).
    pub fn stop_accepting(&self) {
        self.shutdown.trigger();
    }

    /// Awaits the **graceful connection drain** up to the configured deadline (rmp #429): after
    /// [`stop_accepting`](Self::stop_accepting) has closed the listening sockets, in-flight connection
    /// tasks (Bolt sessions on `spawn_blocking`, REST connections on the runtime) keep running until
    /// the client finishes or this deadline elapses. Each connection holds one connection-admission
    /// permit (rmp #118) for its whole lifetime, so the drain is observed by waiting for the semaphore
    /// to return to full (`available_permits() == max_connections`).
    ///
    /// Returns `true` if every connection drained within the deadline, `false` if the deadline elapsed
    /// with connections still in flight (the caller then proceeds to the engine drain, which rolls back
    /// their in-flight transactions and hardens the store regardless — a forced close, never a
    /// half-applied write). Polls on a short interval rather than awaiting a permit so a connection that
    /// drops *after* the deadline cannot leave this future parked. Honours the documented `04 §9.4`
    /// drain-deadline contract that the prior `stop_accepting → shutdown_all` sequence left unenforced.
    pub async fn drain_connections(&self) -> bool {
        // A zero deadline disables the wait (proceed straight to the engine drain).
        if self.drain_deadline.is_zero() {
            return self.conn_limit.available_permits() >= self.max_connections;
        }
        // `Semaphore::MAX_PERMITS`-capped configs aside, `available_permits()` returns to
        // `max_connections` exactly when every accepted connection has released its permit on drop.
        let poll = Duration::from_millis(20).min(self.drain_deadline);
        let deadline = tokio::time::Instant::now() + self.drain_deadline;
        loop {
            if self.conn_limit.available_permits() >= self.max_connections {
                return true; // every connection drained.
            }
            if tokio::time::Instant::now() >= deadline {
                let in_flight = self
                    .max_connections
                    .saturating_sub(self.conn_limit.available_permits());
                tracing::warn!(
                    in_flight,
                    deadline_ms = self.drain_deadline.as_millis(),
                    "connection-drain deadline elapsed with connections still in flight; proceeding \
                     to force-close them via the engine drain (rmp #429)",
                );
                return false;
            }
            tokio::time::sleep(poll).await;
        }
    }
}

/// Binds and starts every enabled listener, returning the bound [`Listeners`].
///
/// `engine` is the **default database's** handle; `catalog` is the database registry the
/// per-session database targeting and the administrative statements resolve through (rmp #84) —
/// both seams share one [`AdminContext`] built here.
///
/// # Errors
/// A human-readable message if any enabled listener fails to bind.
#[allow(clippy::too_many_arguments)] // The listeners legitimately need all the shared services.
pub async fn start_all(
    config: &ServerConfig,
    engine: EngineHandle,
    catalog: Arc<DatabaseCatalog>,
    security: Arc<SecurityCatalog>,
    auth: Arc<dyn AuthProvider>,
    audit: Arc<AuditLog>,
    clock: Arc<dyn Clock + Send + Sync>,
    tls: Option<Arc<RustlsServerConfig>>,
    metrics: Arc<Metrics>,
    shutdown: ShutdownCoordinator,
    readiness: crate::observability::Readiness,
) -> Result<Listeners, String> {
    let tls_acceptor = tls.map(TlsAcceptor::from);

    // ---- Connection admission (rmp #118) ----
    // A single, process-wide semaphore caps the number of *concurrently-open* connections across all
    // three listeners. It is enforced at accept time, *before* any protocol bytes are read, so a flood
    // of half-open/abusive connections cannot exhaust file descriptors or per-connection tasks ahead
    // of the query-admission semaphore (which only engages once a connection is established and
    // submitting work). A global (not per-listener) cap is the correct shape: the resource being
    // protected — FDs and tasks — is process-wide. Each accepted connection moves its
    // `OwnedSemaphorePermit` into its session task, releasing it on drop when the connection ends.
    let conn_limit = Arc::new(tokio::sync::Semaphore::new(
        config.admission.max_connections,
    ));
    // The TLS-handshake deadline and optional idle/read deadline applied to network sessions.
    let handshake_timeout = config.timing.handshake_timeout();
    let idle_timeout = config.timing.idle_timeout();
    // The REST request-header read deadline (SEC-181) — bounds a post-TLS slow-loris drip.
    let header_read_timeout = config.timing.header_read_timeout();

    // The address routing (`neo4j://`) drivers are told to reconnect to in a `ROUTE` reply (rmp
    // #95): the explicit advertised address, else the Bolt-TCP bind address (see
    // `ServerConfig::resolved_advertised_bolt_address`).
    let advertised_bolt = config.resolved_advertised_bolt_address();

    // The shared database-targeting + admin-statement context (rmp #84/#92). One per server: both
    // Bolt loops clone it per connection, the REST adapter holds one. It carries the live
    // `SecurityCatalog` (admin authorization + security-command execution + persistence).
    let context = AdminContext::new(
        Arc::clone(&catalog),
        Arc::clone(&security),
        Arc::clone(&audit),
        tokio::runtime::Handle::current(),
        engine.clone(),
    );

    // ---- UDS-Bolt (peer-cred, no TLS) ----
    let uds_path = if let Some(path) = &config.uds_path {
        let acceptor =
            UdsAcceptor::bind(path).map_err(|e| format!("binding UDS {}: {e}", path.display()))?;
        let bound = acceptor.path().to_path_buf();
        tokio::spawn(bolt::run_uds_accept_loop(
            acceptor,
            context.clone(),
            Arc::clone(&auth),
            advertised_bolt.clone(),
            Arc::clone(&metrics),
            Arc::clone(&conn_limit),
            idle_timeout,
            shutdown.clone(),
        ));
        Some(bound)
    } else {
        None
    };

    // ---- TCP-Bolt (TLS) ----
    let bolt_tcp_addr = if let Some(addr) = &config.bolt_tcp_addr {
        let sock = parse_addr(addr)?;
        let acceptor = TcpAcceptor::bind(sock)
            .await
            .map_err(|e| format!("binding Bolt-TCP {addr}: {e}"))?;
        let bound = acceptor
            .local_addr()
            .map_err(|e| format!("Bolt-TCP local_addr: {e}"))?;
        let tls_acceptor = tls_acceptor
            .clone()
            .ok_or_else(|| "Bolt-TCP requires TLS but none configured".to_owned())?;
        tokio::spawn(bolt::run_tcp_accept_loop(
            acceptor,
            tls_acceptor,
            context.clone(),
            Arc::clone(&auth),
            advertised_bolt.clone(),
            Arc::clone(&metrics),
            Arc::clone(&conn_limit),
            handshake_timeout,
            idle_timeout,
            shutdown.clone(),
        ));
        Some(bound)
    } else {
        None
    };

    // ---- REST (TLS) ----
    let rest_addr = if let Some(addr) = &config.rest_addr {
        let sock = parse_addr(addr)?;
        let acceptor = TcpAcceptor::bind(sock)
            .await
            .map_err(|e| format!("binding REST {addr}: {e}"))?;
        let bound = acceptor
            .local_addr()
            .map_err(|e| format!("REST local_addr: {e}"))?;
        let router = build_rest_router(
            engine.clone(),
            context.clone(),
            Arc::clone(&catalog),
            Arc::clone(&auth),
            Arc::clone(&security),
            Arc::clone(&audit),
            Arc::clone(&clock),
            Arc::clone(&metrics),
            shutdown.clone(),
            readiness.clone(),
            config.metrics_scrape_token.as_deref().map(Arc::from),
            config.timing.transaction_idle_timeout(),
        );
        tokio::spawn(rest::run_rest_accept_loop(
            acceptor,
            tls_acceptor.clone(),
            router,
            Arc::clone(&metrics),
            Arc::clone(&conn_limit),
            handshake_timeout,
            header_read_timeout,
            shutdown.clone(),
        ));
        Some(bound)
    } else {
        None
    };

    Ok(Listeners {
        rest_addr,
        bolt_tcp_addr,
        uds_path,
        shutdown,
        conn_limit,
        max_connections: config.admission.max_connections,
        drain_deadline: config.timing.shutdown_drain_deadline(),
    })
}

/// Builds the full HTTP router: the `graphus_rest` transactional API merged with the server's own
/// observability + admin routes (`04 §8.2`, §9). `engine` (the default database's handle) feeds
/// the observability routes; the transactional API routes databases through `context` (rmp #84).
///
/// Authentication is LIVE everywhere (rmp #94): the transactional API holds the `AuthProvider`
/// (`auth`, a `LiveAuth` over the catalog), and the server's own `/admin/*` routes hold the
/// `SecurityCatalog` directly (`security`) and resolve each Bearer check through it.
#[allow(clippy::too_many_arguments)] // The router legitimately aggregates all the shared services.
fn build_rest_router(
    engine: EngineHandle,
    context: AdminContext,
    catalog: Arc<DatabaseCatalog>,
    auth: Arc<dyn AuthProvider>,
    security: Arc<SecurityCatalog>,
    audit: Arc<AuditLog>,
    clock: Arc<dyn Clock + Send + Sync>,
    metrics: Arc<Metrics>,
    shutdown: ShutdownCoordinator,
    readiness: crate::observability::Readiness,
    metrics_scrape_token: Option<Arc<str>>,
    transaction_idle_timeout: std::time::Duration,
) -> axum::Router {
    use graphus_rest::registry::TxRegistry;
    use graphus_rest::router::{AppState, router};

    let rest_engine = Arc::new(crate::engine::RestEngineAdapter::new(context));
    // The transaction TTL is the configured inactivity timeout (rmp #389), on the monotonic clock
    // (rmp #395). An open transaction idle past it is rolled back by the inactivity sweep spawned
    // below — a transaction abandoned by a client no longer leaks (pinning the GC watermark, growing
    // RAM/version slots) forever.
    let registry = Arc::new(TxRegistry::new(
        u64::try_from(transaction_idle_timeout.as_nanos()).unwrap_or(u64::MAX),
    ));
    // Spawn the periodic inactivity sweep (rmp #389): a single low-frequency background task that rolls
    // back every transaction idle past the timeout. It owns its own `Arc` clones of the registry,
    // engine and clock, runs until shutdown, and never blocks the request path.
    spawn_tx_inactivity_sweep(
        Arc::clone(&registry),
        Arc::clone(&rest_engine),
        Arc::clone(&clock),
        transaction_idle_timeout,
        shutdown.clone(),
    );
    // Wire the audit observer (rmp #70) so REST Bearer-validation outcomes are recorded with the
    // `Rest` source. The observer is a tiny server-side adapter over the shared `AuditLog`.
    let observer: Arc<dyn graphus_rest::router::AuthObserver> =
        Arc::new(crate::engine::RestAuthObserver::new(Arc::clone(&audit)));
    let api = router(
        AppState::new(rest_engine, auth, registry, Arc::clone(&clock)).with_auth_observer(observer),
    );

    let extra = extra_routes::routes(
        metrics,
        engine,
        catalog,
        security,
        clock,
        shutdown,
        readiness,
        metrics_scrape_token,
    );
    api.merge(extra)
}

/// The largest interval the inactivity sweep will sleep between passes, regardless of how long the
/// configured timeout is. Bounds reaping latency for a very long timeout (a transaction is reaped
/// within `timeout + SWEEP_MAX_INTERVAL` of going idle) while keeping the task near-idle.
const SWEEP_MAX_INTERVAL: Duration = Duration::from_secs(10);

/// Spawns the **REST transaction inactivity sweep** (rmp #389): a single low-frequency background task
/// that periodically rolls back every open explicit transaction idle past the configured timeout, so
/// a client that begins a transaction and never returns cannot leak it permanently (pinning the MVCC
/// GC watermark, growing RAM and version slots without bound).
///
/// The sweep is **race-safe with an explicit `DELETE`/commit**: [`TxRegistry::sweep_expired`] removes
/// each expired entry from the registry **under the registry lock** and only then calls
/// `engine.rollback` — so a concurrent `DELETE`/commit either takes the entry first (the sweep then
/// skips it) or loses the race (the entry is already gone, `take` returns `None`, the router 404s).
/// `RestEngine::rollback` is idempotent, so even an interleaving where both reach the engine for the
/// same handle is harmless. Time is read from the injected **monotonic** clock (rmp #395), so a
/// wall-clock NTP step can neither expire a fresh transaction nor perpetually reprieve a stale one.
///
/// The task runs until [`ShutdownCoordinator`] fires, then exits (the final shutdown drain rolls back
/// whatever remains). The sweep interval is the timeout (capped at [`SWEEP_MAX_INTERVAL`]) so reaping
/// is timely without busy-spinning.
fn spawn_tx_inactivity_sweep<E>(
    registry: Arc<graphus_rest::registry::TxRegistry>,
    engine: Arc<E>,
    clock: Arc<dyn Clock + Send + Sync>,
    timeout: Duration,
    shutdown: ShutdownCoordinator,
) where
    E: graphus_rest::engine::RestEngine + Send + Sync + 'static,
{
    let interval = timeout
        .min(SWEEP_MAX_INTERVAL)
        .max(Duration::from_millis(1));
    tokio::spawn(async move {
        loop {
            tokio::select! {
                // Cancellation-safe: `tokio::time::sleep` and `ShutdownCoordinator::wait` are both safe
                // to drop mid-await, and the sweep itself only runs between awaits (never across one).
                () = tokio::time::sleep(interval) => {
                    let reaped = registry.sweep_expired(clock.now_nanos(), engine.as_ref());
                    if !reaped.is_empty() {
                        tracing::info!(
                            target: "graphus::rest",
                            count = reaped.len(),
                            "rolled back idle REST transaction(s) past the inactivity timeout",
                        );
                    }
                }
                () = shutdown.wait() => break,
            }
        }
    });
}

/// Parses a `host:port` listen address.
fn parse_addr(addr: &str) -> Result<std::net::SocketAddr, String> {
    use std::net::ToSocketAddrs;
    addr.to_socket_addrs()
        .map_err(|e| format!("resolving listen address {addr}: {e}"))?
        .next()
        .ok_or_else(|| format!("listen address {addr} resolved to nothing"))
}
