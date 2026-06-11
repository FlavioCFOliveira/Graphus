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

use graphus_auth::{Authenticator, PeerCred as AuthPeerCred, PeerCredSource};
use graphus_bolt::server::BoltSession;
use graphus_io::{TcpAcceptor, UdsAcceptor};
use tokio::runtime::Handle;
use tokio_rustls::TlsAcceptor;

use super::transport::AsyncToBlockingTransport;
use crate::admin::AdminContext;
use crate::engine::BoltEngineExecutor;
use crate::metrics::Metrics;
use crate::shutdown::ShutdownCoordinator;

/// Runs the UDS Bolt accept loop until shutdown. Each accepted connection is admitted by peer-cred
/// then handed to a blocking session task. `context` is the shared database-targeting + admin
/// surface every per-connection executor routes through (rmp #84).
pub async fn run_uds_accept_loop(
    acceptor: UdsAcceptor,
    context: AdminContext,
    auth: Arc<Authenticator>,
    metrics: Arc<Metrics>,
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
                metrics.record_bolt_uds_conn();

                // Peer-cred admission gate (`04 §8.4`): resolve the uid to a known RBAC user. A
                // connection from an unmapped/unknown uid is refused before any protocol bytes.
                let peer = conn.peer_cred();
                if let Err(reason) = admit_peer(&auth, peer) {
                    metrics.record_auth_failure();
                    tracing::warn!(reason, "UDS connection refused by peer-cred gate");
                    // Drop the connection: closing the socket is the refusal.
                    drop(conn);
                    continue;
                }

                spawn_session(
                    conn,
                    handle.clone(),
                    context.clone(),
                    Arc::clone(&auth),
                    shutdown.clone(),
                );
            }
        }
    }
    tracing::info!("UDS accept loop stopped");
}

/// Runs the TCP Bolt accept loop until shutdown. Each accepted connection is TLS-wrapped, then handed
/// to a blocking session task (native LOGON auth happens inside the session). `context` is the
/// shared database-targeting + admin surface (rmp #84).
pub async fn run_tcp_accept_loop(
    acceptor: TcpAcceptor,
    tls: TlsAcceptor,
    context: AdminContext,
    auth: Arc<Authenticator>,
    metrics: Arc<Metrics>,
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
                metrics.record_bolt_tcp_conn();

                // TLS handshake on a task so a slow/abusive handshake never blocks the accept loop.
                let tls = tls.clone();
                let handle = handle.clone();
                let context = context.clone();
                let auth = Arc::clone(&auth);
                let shutdown = shutdown.clone();
                let metrics = Arc::clone(&metrics);
                tokio::spawn(async move {
                    match tls.accept(conn).await {
                        Ok(tls_stream) => {
                            spawn_session(tls_stream, handle, context, auth, shutdown);
                        }
                        Err(e) => {
                            metrics.record_auth_failure();
                            tracing::warn!(error = %e, "Bolt-TCP TLS handshake failed");
                        }
                    }
                });
            }
        }
    }
    tracing::info!("Bolt-TCP accept loop stopped");
}

/// Resolves a UDS connection's peer credentials to a known RBAC user, returning `Ok(())` to admit or
/// `Err(reason)` to refuse (`04 §8.4`). A platform that does not surface peer-cred (`None`) is
/// refused on the Bolt path: the spec keys UDS identity on `SO_PEERCRED`, so without it the channel
/// cannot establish an identity (the listener could instead fall back to filesystem permissions; we
/// fail closed, which is the safe default).
fn admit_peer(
    auth: &Authenticator,
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
    match auth.authenticate_peer(&source) {
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
/// per-connection engine executor, then drives `BoltSession::run` to completion.
///
/// The session is **blocking** (its `Transport` and engine submits block), so it runs on
/// `spawn_blocking`, never a runtime worker (`04 §9.1`). The `Authenticator` is shared (`Arc`); the
/// session borrows it for its lifetime, so we move the `Arc` into the task and borrow from there.
fn spawn_session<S>(
    stream: S,
    handle: Handle,
    context: AdminContext,
    auth: Arc<Authenticator>,
    shutdown: ShutdownCoordinator,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let transport = AsyncToBlockingTransport::new(stream, handle, shutdown, None);
        let executor = BoltEngineExecutor::new(context);
        let mut session = BoltSession::new(transport, executor, &auth);
        if let Err(e) = session.run() {
            // A transport/handshake error ends the session; a Cypher/auth FAILURE is *not* an error
            // here (it is delivered in-band — see `BoltSession::run` docs).
            tracing::debug!(error = %e, "Bolt session ended with a transport/handshake error");
        }
    });
}
