//! The REST listener — the axum router (transactional API + the server's observability/admin routes)
//! served over TCP, TLS-terminated (`04-technical-design.md` §8.2, §8.4).
//!
//! ## Driving the synchronous router off the runtime workers
//!
//! `graphus_rest`'s handlers call the synchronous [`graphus_rest::RestEngine`] seam, which in this
//! server blocks on the engine's reply channel (the single-writer serialization point, `04 §9.1`).
//! To honour the hard rule "no blocking on runtime workers" (`04 §9.1`), each request's router future
//! is driven to completion **inside a `tokio::task::spawn_blocking` task** via [`Handle::block_on`]
//! (legal on a blocking-pool thread — see [`super::transport`]). The hyper connection I/O itself stays
//! async on the runtime; only the per-request handler (with its blocking engine call) is offloaded.
//!
//! This is wrapped as a small [`tower::Service`] ([`BlockingRouter`]) around the axum router, so the
//! whole HTTP surface (REST API + `/metrics` + `/health/*` + `/admin/*`) is served by one listener.

use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::response::Response;
use graphus_io::TcpAcceptor;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::runtime::Handle;
use tokio_rustls::TlsAcceptor;
use tower::Service;

use crate::shutdown::ShutdownCoordinator;

/// A [`tower::Service`] that drives the wrapped axum `Router` to completion on a blocking task, so the
/// synchronous, engine-blocking handlers never run on a runtime worker (`04 §9.1`).
#[derive(Clone)]
struct BlockingRouter {
    router: Router,
    handle: Handle,
}

impl Service<Request<Incoming>> for BlockingRouter {
    type Response = Response;
    type Error = Infallible;
    type Future =
        std::pin::Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // The router is always ready; readiness backpressure is provided by admission control on the
        // engine, not here.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        // Map the incoming body to axum's `Body` so the cloned router can serve it.
        let req: Request<Body> = req.map(Body::new);
        let router = self.router.clone();
        let handle = self.handle.clone();
        Box::pin(async move {
            // Offload the (synchronous-internally) router future to a blocking thread and drive it
            // there with `block_on` — keeping the engine-blocking handler off the runtime workers.
            // `ServiceExt::oneshot` handles `poll_ready` + `call`; the router's `Service` error is
            // `Infallible`, so the result always unwraps.
            let resp = tokio::task::spawn_blocking(move || {
                use tower::ServiceExt;
                handle.block_on(async move {
                    router
                        .oneshot(req)
                        .await
                        .expect("router Service error is Infallible")
                })
            })
            .await
            .unwrap_or_else(|join_err| {
                tracing::error!(error = %join_err, "REST handler task panicked");
                Response::builder()
                    .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("internal error"))
                    .expect("static response")
            });
            Ok(resp)
        })
    }
}

/// Runs the REST accept loop until shutdown, serving `router` over each accepted (optionally
/// TLS-wrapped) connection.
///
/// `conn_limit` is the process-wide connection-admission semaphore (rmp #118): a permit is taken at
/// accept time *before* the TLS handshake, and held for the connection's lifetime (moved into the
/// per-connection task), so a flood of REST connections cannot exhaust the process's connection budget
/// ahead of query admission. `handshake_timeout` bounds the TLS handshake so a stalled one is dropped
/// rather than pinning the task and socket. `header_read_timeout` (SEC-181) bounds how long a client
/// may take to send its complete request headers *after* TLS, closing the slow-loris HTTP vector that
/// the handshake deadline alone does not cover; `None` disables it.
#[allow(clippy::too_many_arguments)] // The accept loop legitimately needs all the shared services.
pub async fn run_rest_accept_loop(
    acceptor: TcpAcceptor,
    tls: Option<TlsAcceptor>,
    router: Router,
    metrics: Arc<crate::metrics::Metrics>,
    conn_limit: Arc<tokio::sync::Semaphore>,
    handshake_timeout: Duration,
    header_read_timeout: Option<Duration>,
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
                        tracing::warn!(error = %e, "REST accept failed");
                        continue;
                    }
                };

                // Connection-admission gate (rmp #118): take a permit before any TLS/HTTP work; shed
                // (close + count) when the global cap is saturated, never blocking the accept loop.
                let permit = match Arc::clone(&conn_limit).try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        metrics.record_conn_shed();
                        tracing::warn!(
                            interface = "REST",
                            "connection load-shed: max_connections reached"
                        );
                        drop(conn);
                        continue;
                    }
                };

                metrics.record_rest_request();
                let svc = BlockingRouter {
                    router: router.clone(),
                    handle: handle.clone(),
                };
                let tls = tls.clone();
                let conn_shutdown = shutdown.clone();
                let conn_metrics = Arc::clone(&metrics);
                tokio::spawn(async move {
                    // The permit is held for the whole connection, releasing on drop when this task
                    // returns (rmp #118).
                    let _permit = permit;
                    serve_connection(
                        conn,
                        tls,
                        svc,
                        handshake_timeout,
                        header_read_timeout,
                        conn_metrics,
                        conn_shutdown,
                    )
                    .await;
                });
            }
        }
    }
    tracing::info!("REST accept loop stopped");
}

/// Serves one HTTP connection: TLS-terminate if configured, then run hyper's auto (HTTP/1+2)
/// connection over the [`BlockingRouter`] service. A graceful-shutdown trigger stops the connection
/// after the in-flight request completes.
///
/// The TLS handshake is bounded by `handshake_timeout` (rmp #118): a stalled handshake is dropped
/// (and counted in `graphus_handshake_timeouts_total`) rather than pinning this task and the socket.
/// After TLS, `header_read_timeout` (SEC-181) bounds how long the client may take to send its
/// complete request headers, dropping a slow-loris HTTP drip that the handshake deadline cannot see.
async fn serve_connection(
    conn: graphus_io::TcpConn,
    tls: Option<TlsAcceptor>,
    svc: BlockingRouter,
    handshake_timeout: Duration,
    header_read_timeout: Option<Duration>,
    metrics: Arc<crate::metrics::Metrics>,
    shutdown: ShutdownCoordinator,
) {
    let mut builder = ConnBuilder::new(TokioExecutor::new());
    // SEC-181: bound HTTP/1 request-header reads so a post-TLS slow-loris drip is dropped rather than
    // pinning a connection-admission permit indefinitely. HTTP/2 has its own framing/flow control and
    // is covered by the connection idle handling; this targets the HTTP/1 header-read vector.
    // `header_read_timeout` requires a `Timer` on the builder; without one hyper panics at runtime, so
    // the timer is always installed alongside the timeout.
    if let Some(timeout) = header_read_timeout {
        builder.http1().timer(TokioTimer::new());
        builder.http1().header_read_timeout(timeout);
    }
    let service = hyper_util::service::TowerToHyperService::new(svc);

    match tls {
        Some(tls) => match tokio::time::timeout(handshake_timeout, tls.accept(conn)).await {
            Ok(Ok(tls_stream)) => {
                let io = TokioIo::new(tls_stream);
                let conn = builder.serve_connection(io, service);
                tokio::pin!(conn);
                tokio::select! {
                    r = conn.as_mut() => log_conn_result(r),
                    () = shutdown.wait() => {
                        conn.as_mut().graceful_shutdown();
                        let _ = conn.await;
                    }
                }
            }
            Ok(Err(e)) => tracing::warn!(error = %e, "REST TLS handshake failed"),
            Err(_elapsed) => {
                metrics.record_handshake_timeout();
                tracing::warn!(
                    timeout_ms = handshake_timeout.as_millis(),
                    "REST TLS handshake timed out; dropping connection"
                );
            }
        },
        None => {
            // No TLS (e.g. a test harness on loopback): serve plaintext HTTP. Production config
            // requires TLS for the REST listener (enforced by `ServerConfig::validate`).
            let io = TokioIo::new(conn);
            let conn = builder.serve_connection(io, service);
            tokio::pin!(conn);
            tokio::select! {
                r = conn.as_mut() => log_conn_result(r),
                () = shutdown.wait() => {
                    conn.as_mut().graceful_shutdown();
                    let _ = conn.await;
                }
            }
        }
    }
}

/// Logs a connection's terminal result at the right level (a client-closed connection is normal).
fn log_conn_result(r: Result<(), Box<dyn std::error::Error + Send + Sync>>) {
    if let Err(e) = r {
        tracing::debug!(error = %e, "REST connection ended");
    }
}
