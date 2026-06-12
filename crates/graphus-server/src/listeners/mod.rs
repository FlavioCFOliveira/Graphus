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

use graphus_auth::Authenticator;
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
}

impl Listeners {
    /// Stops accepting new connections by triggering the shared shutdown signal (`04 §9.4`).
    ///
    /// In-flight connection tasks keep running until they finish or the drain deadline forces them
    /// down; this only closes the *listening* sockets (the accept loops break out of their select).
    pub fn stop_accepting(&self) {
        self.shutdown.trigger();
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
    auth: Arc<Authenticator>,
    audit: Arc<AuditLog>,
    clock: Arc<dyn Clock + Send + Sync>,
    tls: Option<Arc<RustlsServerConfig>>,
    metrics: Arc<Metrics>,
    shutdown: ShutdownCoordinator,
    readiness: crate::observability::Readiness,
) -> Result<Listeners, String> {
    let tls_acceptor = tls.map(TlsAcceptor::from);

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
            Arc::clone(&auth),
            Arc::clone(&audit),
            Arc::clone(&clock),
            Arc::clone(&metrics),
            shutdown.clone(),
            readiness.clone(),
        );
        tokio::spawn(rest::run_rest_accept_loop(
            acceptor,
            tls_acceptor.clone(),
            router,
            Arc::clone(&metrics),
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
    })
}

/// Builds the full HTTP router: the `graphus_rest` transactional API merged with the server's own
/// observability + admin routes (`04 §8.2`, §9). `engine` (the default database's handle) feeds
/// the observability routes; the transactional API routes databases through `context` (rmp #84).
#[allow(clippy::too_many_arguments)] // The router legitimately aggregates all the shared services.
fn build_rest_router(
    engine: EngineHandle,
    context: AdminContext,
    auth: Arc<Authenticator>,
    audit: Arc<AuditLog>,
    clock: Arc<dyn Clock + Send + Sync>,
    metrics: Arc<Metrics>,
    shutdown: ShutdownCoordinator,
    readiness: crate::observability::Readiness,
) -> axum::Router {
    use graphus_rest::registry::TxRegistry;
    use graphus_rest::router::{AppState, DEFAULT_TX_TTL_NANOS, router};

    let rest_engine = Arc::new(crate::engine::RestEngineAdapter::new(context));
    let registry = Arc::new(TxRegistry::new(DEFAULT_TX_TTL_NANOS));
    // Wire the audit observer (rmp #70) so REST Bearer-validation outcomes are recorded with the
    // `Rest` source. The observer is a tiny server-side adapter over the shared `AuditLog`.
    let observer: Arc<dyn graphus_rest::router::AuthObserver> =
        Arc::new(crate::engine::RestAuthObserver::new(Arc::clone(&audit)));
    let api = router(
        AppState::new(rest_engine, Arc::clone(&auth), registry, Arc::clone(&clock))
            .with_auth_observer(observer),
    );

    let extra = extra_routes::routes(metrics, engine, auth, clock, shutdown, readiness);
    api.merge(extra)
}

/// Parses a `host:port` listen address.
fn parse_addr(addr: &str) -> Result<std::net::SocketAddr, String> {
    use std::net::ToSocketAddrs;
    addr.to_socket_addrs()
        .map_err(|e| format!("resolving listen address {addr}: {e}"))?
        .next()
        .ok_or_else(|| format!("listen address {addr} resolved to nothing"))
}
