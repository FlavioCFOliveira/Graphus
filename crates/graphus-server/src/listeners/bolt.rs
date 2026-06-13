//! The two Bolt listeners — **UDS** (peer-cred gated, no TLS) and **TCP** (TLS-wrapped, native
//! LOGON) — and the per-connection session driver (`04-technical-design.md` §8.1, §8.4).
//!
//! Both listeners run the same `graphus_bolt::BoltSession` state machine over the same engine-backed
//! `BoltExecutor`; "only the transport and auth differ" (`04 §8.1`):
//!
//! - **UDS**: a kernel-protected local channel — no TLS. The connection is admitted by resolving its
//!   `SO_PEERCRED` uid to a known RBAC user *at accept time* (`04 §8.4`); the session then runs the
//!   standard Bolt `HELLO`/`LOGON` over the wire (the local client still authenticates), and both the
//!   peer-cred gate and the LOGON resolve to the **same** shared `Authenticator` catalog.
//! - **TCP**: TLS is mandatory (`04 §8.4`). The accepted `TcpStream` is wrapped by a rustls server
//!   session before the Bolt handshake; auth is Bolt native `LOGON` over the encrypted channel.
//!
//! Each accepted connection runs its blocking session on a `tokio::task::spawn_blocking` task with
//! the async↔blocking [`AsyncToBlockingTransport`] bridge (`04 §9.1`).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use graphus_auth::{AuthProvider, PeerCred as AuthPeerCred, PeerCredSource};
use graphus_bolt::server::{BoltSession, SessionConfig};
use graphus_io::{TcpAcceptor, UdsAcceptor};
use tokio::runtime::Handle;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsAcceptor;

use super::transport::AsyncToBlockingTransport;
use crate::admin::AdminContext;
use crate::audit::AuditSource;
use crate::engine::BoltEngineExecutor;
use crate::metrics::Metrics;
use crate::security::SecurityCatalog;
use crate::shutdown::ShutdownCoordinator;

/// A process-wide monotonic counter minting a unique `connection_id` per accepted Bolt connection
/// (rmp #95). Shared across both the UDS and TCP accept loops so every connection's id is distinct
/// for the server's lifetime, regardless of which transport accepted it.
static CONNECTION_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Mints the next unique per-connection id (`bolt-<n>`), reported in `HELLO` `SUCCESS` so a driver
/// and the server logs can correlate one connection (rmp #95).
fn mint_connection_id() -> String {
    let n = CONNECTION_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("bolt-{n}")
}

/// Builds the per-connection [`SessionConfig`]: a freshly-minted unique `connection_id` plus the
/// server's advertised routing address (rmp #95). The default `server_agent`/`routing_ttl` apply.
fn session_config(advertised_bolt_address: Option<String>) -> SessionConfig {
    SessionConfig {
        connection_id: mint_connection_id(),
        advertised_bolt_address,
        ..SessionConfig::default()
    }
}

/// Runs the UDS Bolt accept loop until shutdown. Each accepted connection is admitted by the global
/// connection cap then by peer-cred, and finally handed to a blocking session task. `context` is the
/// shared database-targeting + admin surface every per-connection executor routes through (rmp #84).
/// `advertised_bolt_address` is the address routing drivers are told to reconnect to in a `ROUTE`
/// reply (rmp #95). `conn_limit` is the process-wide connection-admission semaphore (rmp #118);
/// `idle_timeout` reaps idle sessions when set (`None` = disabled).
#[allow(clippy::too_many_arguments)] // The accept loop legitimately needs all the shared services.
pub async fn run_uds_accept_loop(
    acceptor: UdsAcceptor,
    context: AdminContext,
    auth: Arc<dyn AuthProvider>,
    advertised_bolt_address: Option<String>,
    metrics: Arc<Metrics>,
    conn_limit: Arc<Semaphore>,
    idle_timeout: Option<Duration>,
    shutdown: ShutdownCoordinator,
) {
    let handle = Handle::current();
    loop {
        tokio::select! {
            biased;
            () = shutdown.wait() => break,
            accepted = acceptor.accept() => {
                let conn = match accepted {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(error = %e, "UDS accept failed");
                        continue;
                    }
                };

                // Connection-admission gate (rmp #118): take a permit *before* any protocol work. A
                // saturated cap means the process is at its connection budget; shed by closing the
                // socket and continue — never block the accept loop waiting for a permit.
                let Some(permit) = try_admit(&conn_limit, &metrics, "UDS") else {
                    drop(conn);
                    continue;
                };

                metrics.record_bolt_uds_conn();

                // Peer-cred admission gate (`04 §8.4`): resolve the uid to a known RBAC user against
                // the LIVE security catalog (rmp #94), so a uid mapping created at runtime admits
                // immediately and a removed/renamed mapping is refused immediately. A connection from
                // an unmapped/unknown uid is refused before any protocol bytes.
                let peer = conn.peer_cred();
                if let Err(reason) = admit_peer(context.security(), peer) {
                    metrics.record_auth_failure();
                    tracing::warn!(reason, "UDS connection refused by peer-cred gate");
                    // Drop the connection (and its permit): closing the socket is the refusal.
                    drop(permit);
                    drop(conn);
                    continue;
                }

                spawn_session(
                    conn,
                    handle.clone(),
                    context.clone(),
                    AuditSource::BoltUds,
                    Arc::clone(&auth),
                    session_config(advertised_bolt_address.clone()),
                    idle_timeout,
                    permit,
                    shutdown.clone(),
                );
            }
        }
    }
    tracing::info!("UDS accept loop stopped");
}

/// Tries to take a connection-admission permit (rmp #118), returning `Some(permit)` to admit or
/// `None` to **load-shed** (the global `max_connections` cap is saturated). A shed is recorded in
/// `graphus_connections_shed_total` and logged at `warn`; the caller closes the socket. This never
/// blocks: `try_acquire_owned` is non-waiting, so a saturated server keeps draining its accept queue
/// (fast-closing the excess) instead of stalling the loop.
fn try_admit(
    conn_limit: &Arc<Semaphore>,
    metrics: &Metrics,
    interface: &str,
) -> Option<OwnedSemaphorePermit> {
    match Arc::clone(conn_limit).try_acquire_owned() {
        Ok(permit) => Some(permit),
        Err(_) => {
            metrics.record_conn_shed();
            tracing::warn!(interface, "connection load-shed: max_connections reached");
            None
        }
    }
}

/// Runs the TCP Bolt accept loop until shutdown. Each accepted connection is admitted by the global
/// connection cap, TLS-wrapped under a handshake deadline, then handed to a blocking session task
/// (native LOGON auth happens inside the session). `context` is the shared database-targeting + admin
/// surface (rmp #84). `advertised_bolt_address` is the address routing drivers are told to reconnect
/// to in a `ROUTE` reply (rmp #95). `conn_limit` is the process-wide connection-admission semaphore,
/// `handshake_timeout` bounds the TLS handshake, and `idle_timeout` reaps idle sessions (rmp #118).
#[allow(clippy::too_many_arguments)] // The accept loop legitimately needs all the shared services.
pub async fn run_tcp_accept_loop(
    acceptor: TcpAcceptor,
    tls: TlsAcceptor,
    context: AdminContext,
    auth: Arc<dyn AuthProvider>,
    advertised_bolt_address: Option<String>,
    metrics: Arc<Metrics>,
    conn_limit: Arc<Semaphore>,
    handshake_timeout: Duration,
    idle_timeout: Option<Duration>,
    shutdown: ShutdownCoordinator,
) {
    let handle = Handle::current();
    loop {
        tokio::select! {
            biased;
            () = shutdown.wait() => break,
            accepted = acceptor.accept() => {
                let conn = match accepted {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(error = %e, "Bolt-TCP accept failed");
                        continue;
                    }
                };

                // Connection-admission gate (rmp #118): take a permit *before* the TLS handshake, so a
                // flood of connections that never complete a handshake cannot exhaust the process's
                // connection budget. The permit is moved into the handshake task and on into the
                // session, releasing on drop when the connection ends (success, timeout, or error).
                let Some(permit) = try_admit(&conn_limit, &metrics, "Bolt-TCP") else {
                    drop(conn);
                    continue;
                };

                metrics.record_bolt_tcp_conn();

                // TLS handshake on a task so a slow/abusive handshake never blocks the accept loop, and
                // bounded by `handshake_timeout` so a stalled handshake (slow-loris) is dropped rather
                // than pinning the task and socket indefinitely (rmp #118).
                let tls = tls.clone();
                let handle = handle.clone();
                let context = context.clone();
                let auth = Arc::clone(&auth);
                let shutdown = shutdown.clone();
                let metrics = Arc::clone(&metrics);
                let advertised = advertised_bolt_address.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(handshake_timeout, tls.accept(conn)).await {
                        Ok(Ok(tls_stream)) => {
                            // Mint the per-connection id only once TLS succeeds, so abandoned
                            // handshakes do not consume ids (rmp #95).
                            spawn_session(
                                tls_stream,
                                handle,
                                context,
                                AuditSource::BoltTcp,
                                auth,
                                session_config(advertised),
                                idle_timeout,
                                permit,
                                shutdown,
                            );
                        }
                        Ok(Err(e)) => {
                            metrics.record_auth_failure();
                            tracing::warn!(error = %e, "Bolt-TCP TLS handshake failed");
                            // `permit` drops here, freeing the connection budget.
                        }
                        Err(_elapsed) => {
                            metrics.record_handshake_timeout();
                            tracing::warn!(
                                timeout_ms = handshake_timeout.as_millis(),
                                "Bolt-TCP TLS handshake timed out; dropping connection"
                            );
                            // `permit` drops here, freeing the connection budget.
                        }
                    }
                });
            }
        }
    }
    tracing::info!("Bolt-TCP accept loop stopped");
}

/// Resolves a UDS connection's peer credentials to a known RBAC user against the **live** security
/// catalog (rmp #94), returning `Ok(())` to admit or `Err(reason)` to refuse (`04 §8.4`). Resolving
/// through `security.with_auth(...)` (a brief read lock) means a uid mapping added at runtime admits
/// at once, and a removed/renamed mapping is refused at once — no reboot.
///
/// A platform that does not surface peer-cred (`None`) is refused on the Bolt path: the spec keys
/// UDS identity on `SO_PEERCRED`, so without it the channel cannot establish an identity (the
/// listener could instead fall back to filesystem permissions; we fail closed, the safe default).
fn admit_peer(
    security: &SecurityCatalog,
    peer: Option<graphus_io::PeerCred>,
) -> Result<(), &'static str> {
    let Some(peer) = peer else {
        return Err("peer credentials unavailable on this platform");
    };
    // Bridge the io-layer PeerCred to the auth-layer source seam.
    let source = FixedPeerCred(AuthPeerCred {
        uid: peer.uid,
        gid: peer.gid,
        // The auth layer wants a concrete pid; default 0 when the kernel did not report one.
        pid: peer.pid.unwrap_or(0),
    });
    // One brief read lock on the live model: the peer path is not on the `AuthProvider` trait (it is
    // generic over `PeerCredSource`), so it resolves directly through the catalog here.
    match security.with_auth(|auth| auth.authenticate_peer(&source)) {
        Ok(_user) => Ok(()),
        Err(_) => Err("uid not mapped to a known user"),
    }
}

/// A [`PeerCredSource`] that returns a fixed, already-read [`AuthPeerCred`] (the listener reads the
/// kernel credential once at accept time via `graphus-io`; the auth crate models the read behind this
/// seam — `04 §8.4`).
struct FixedPeerCred(AuthPeerCred);

impl PeerCredSource for FixedPeerCred {
    fn peer_cred(&self) -> std::io::Result<AuthPeerCred> {
        Ok(self.0)
    }
}

/// Spawns one Bolt session on a blocking task: builds the async→blocking transport bridge and the
/// per-connection engine executor, then drives `BoltSession::run` to completion. `session_config`
/// carries this connection's minted id and the advertised routing address (rmp #95); `source` is
/// the connection's audit transport (`BoltUds`/`BoltTcp`) recorded on every audited event (rmp #70).
///
/// `idle_timeout`, when set, is installed as the transport's per-read deadline so a session that goes
/// silent (no inbound bytes) within the window is reaped: the bridged read returns EOF and the session
/// loop ends cleanly (rmp #118). `permit` is the connection-admission permit (rmp #118); it is moved
/// into the task and held for the whole session, releasing the global connection-budget slot on drop
/// when the connection ends.
///
/// The session is **blocking** (its `Transport` and engine submits block), so it runs on
/// `spawn_blocking`, never a runtime worker (`04 §9.1`). The [`AuthProvider`] seam is shared (`Arc`);
/// the session borrows it for its lifetime, so we move the `Arc` into the task and borrow from there.
/// Backed by `LiveAuth` (rmp #94), each `LOGON` resolves against the current security model.
#[allow(clippy::too_many_arguments)] // The session driver legitimately needs all the shared services.
fn spawn_session<S>(
    stream: S,
    handle: Handle,
    context: AdminContext,
    source: AuditSource,
    auth: Arc<dyn AuthProvider>,
    session_config: SessionConfig,
    idle_timeout: Option<Duration>,
    permit: OwnedSemaphorePermit,
    shutdown: ShutdownCoordinator,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        // Hold the connection-admission permit for the session's lifetime; it releases on drop when
        // this task returns (rmp #118).
        let _permit = permit;
        let transport = AsyncToBlockingTransport::new(stream, handle, shutdown, idle_timeout);
        let executor = BoltEngineExecutor::new(context, source);
        let mut session =
            BoltSession::with_config(transport, executor, auth.as_ref(), session_config);
        if let Err(e) = session.run() {
            // A transport/handshake error ends the session; a Cypher/auth FAILURE is *not* an error
            // here (it is delivered in-band — see `BoltSession::run` docs).
            tracing::debug!(error = %e, "Bolt session ended with a transport/handshake error");
        }
    });
}
