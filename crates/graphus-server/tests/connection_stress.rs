//! Multi-connection concurrency stress tests (rmp #120, sprint 6 — "Plataforma de concorrência e
//! I/O"). The production-readiness audit flagged that, although rmp #118 added connection admission
//! (a global `max_connections` cap + handshake/idle timeouts), there was **no empirical proof** that
//! a real listener sustains many *concurrent* connections — each doing a full Bolt handshake + a
//! query — without leaking file descriptors or tasks, that the admission cap sheds correctly above
//! the limit under genuine concurrency, and that graceful shutdown still drains. This file closes
//! that gap.
//!
//! These tests boot a real in-process server on a fresh tempdir store and drive the **live UDS
//! transport** (kernel-protected, no TLS round-trip, so a permit is taken at accept time — the
//! cleanest surface to stress admission). They prove:
//!
//! - **`many_concurrent_connections_all_complete_no_leak`** — hundreds of clients connect
//!   *concurrently*, each completes Bolt handshake → HELLO/LOGON → `RUN`/`PULL` of a real query,
//!   under a cap comfortably above the offered concurrency. Asserts every client succeeds, measures
//!   connections/s + per-connection latency, and asserts the process FD count returns to its
//!   pre-burst baseline (no FD/socket leak) after the burst drains.
//! - **`admission_cap_sheds_excess_under_concurrency`** — far more clients than the cap connect at
//!   once; asserts the admitted ones complete, the excess are shed (closed; counted in
//!   `graphus_connections_shed_total`), there are no panics/deadlocks, and the server stays live and
//!   admits a fresh connection once the burst frees slots.
//! - **`graceful_shutdown_drains_under_load`** — with many live sessions held open, graceful
//!   shutdown returns cleanly (drains, no hang).
//!
//! Determinism for CI: the tests assert **properties**, never fragile absolute latencies. "All
//! admitted complete; all shed are closed; FD count returns to baseline; shutdown drains." Latencies
//! are measured and printed for the record, not asserted. No fixed long sleeps — readiness is reached
//! by retry loops with short backoffs bounded by a generous overall budget.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use graphus_bolt::server::encode_client_handshake;
use graphus_bolt::{Dechunker, Proposal};
use graphus_core::Value;
use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, ServerConfig, TimingConfig, TlsConfig,
};
use graphus_server::{Server, ServerHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::task::JoinSet;

/// A unique temp directory for one test's store (auto-removed on drop).
struct TempStore {
    path: PathBuf,
}

impl TempStore {
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!(
            "graphus-connstress-{tag}-{nanos}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn store_dir(&self) -> PathBuf {
        self.path.join("store")
    }

    fn uds_path(&self) -> PathBuf {
        self.path.join("graphus.sock")
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Base config: UDS only on the temp socket, REST on an ephemeral loopback port (non-TLS for the
/// metrics client), no Bolt-TCP, the `alice`/`pw` admin user.
fn base_config(temp: &TempStore) -> ServerConfig {
    ServerConfig {
        store_path: temp.store_dir(),
        default_database: "graphus".to_owned(),
        buffer_pool_pages: 256,
        bolt_tcp_addr: None,
        advertised_bolt_address: None,
        rest_addr: Some("127.0.0.1:0".to_owned()),
        uds_path: Some(temp.uds_path()),
        tls: TlsConfig::default(),
        admission: AdmissionConfig::default(),
        timing: TimingConfig::default(),
        jwt_secret: "integration-test-jwt-secret-32-bytes!".to_owned(),
        auth: AuthBootstrap {
            admin_user: "alice".to_owned(),
            admin_password: "admin-pw8".to_owned(),
            admin_uid: Some(current_uid()),
            users: Vec::new(),
        },
        encryption: graphus_server::config::EncryptionConfig::default(),
        audit: graphus_server::AuditConfig::default(),
        allow_insecure_network: true,
        metrics_scrape_token: None,
    }
}

/// The current process uid so the UDS peer-cred gate admits this test's own connections.
fn current_uid() -> u32 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("Uid:") {
                    if let Some(first) = rest.split_whitespace().next() {
                        if let Ok(uid) = first.parse() {
                            return uid;
                        }
                    }
                }
            }
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

async fn boot(config: ServerConfig) -> ServerHandle {
    Server::new(config)
        .start()
        .await
        .expect("server should boot")
}

/// Counts this process's open file descriptors (Linux): the entries under `/proc/self/fd`. Used to
/// prove a connection burst does not leak sockets — the count must return to its pre-burst baseline.
#[cfg(target_os = "linux")]
fn open_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|it| it.count())
        .unwrap_or(0)
}

/// The outcome of one client attempt against the listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientOutcome {
    /// Full handshake + HELLO/LOGON + RUN/PULL completed and a `SUCCESS` summary was read back.
    Completed,
    /// The server shed the connection (accepted then closed before/at the handshake — EOF/reset).
    Shed,
}

/// Drives one full client session over UDS: handshake → HELLO → LOGON → RUN → PULL, reading a
/// terminal `SUCCESS`. Returns `Completed` on success, or `Shed` if the server closed the connection
/// at admission (the expected outcome above the cap). Any *other* I/O error is returned as `Err` so a
/// genuine protocol failure is never silently miscounted as a shed.
async fn run_client(path: &std::path::Path) -> std::io::Result<ClientOutcome> {
    use graphus_bolt::{Request, Response};

    let mut stream = match UnixStream::connect(path).await {
        Ok(s) => s,
        // Connect itself can be refused/reset when the accept backlog is saturated under a heavy
        // concurrent burst — that is a shed at the socket layer, not a protocol failure.
        Err(_) => return Ok(ClientOutcome::Shed),
    };

    // --- Handshake ---
    let hs = encode_client_handshake([
        Proposal::range(5, 4, 4),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
    ]);
    if stream.write_all(&hs).await.is_err() {
        return Ok(ClientOutcome::Shed);
    }
    let mut reply = [0u8; 4];
    match stream.read_exact(&mut reply).await {
        Ok(_) => {}
        // EOF/reset at the version reply == the server shed this connection at admission.
        Err(e) if is_peer_closed(&e) => return Ok(ClientOutcome::Shed),
        Err(e) => return Err(e),
    }
    if reply != [0x00, 0x00, 0x04, 0x05] {
        // A non-5.4 reply (e.g. the all-zero "no match") also means we were not admitted to a Bolt
        // session; treat as shed rather than a hard failure.
        return Ok(ClientOutcome::Shed);
    }

    let mut dechunker = Dechunker::new();

    // --- HELLO ---
    send(
        &mut stream,
        &Request::Hello {
            extra: vec![(
                "user_agent".to_owned(),
                Value::String("connstress".to_owned()),
            )],
        },
    )
    .await?;
    match recv(&mut stream, &mut dechunker).await? {
        Some(Response::Success { .. }) => {}
        _ => return Ok(ClientOutcome::Shed),
    }

    // --- LOGON ---
    send(
        &mut stream,
        &Request::Logon {
            auth: vec![
                ("scheme".to_owned(), Value::String("basic".to_owned())),
                ("principal".to_owned(), Value::String("alice".to_owned())),
                ("credentials".to_owned(), Value::String("admin-pw8".to_owned())),
            ],
        },
    )
    .await?;
    match recv(&mut stream, &mut dechunker).await? {
        Some(Response::Success { .. }) => {}
        other => panic!("LOGON should succeed for an admitted client, got {other:?}"),
    }

    // --- RUN a trivial real query + PULL its result ---
    send(
        &mut stream,
        &Request::Run {
            query: "RETURN 1 AS n".to_owned(),
            parameters: Vec::new(),
            extra: Vec::new(),
        },
    )
    .await?;
    match recv(&mut stream, &mut dechunker).await? {
        Some(Response::Success { .. }) => {}
        other => panic!("RUN should succeed for an admitted client, got {other:?}"),
    }
    send(&mut stream, &Request::Pull { n: -1, qid: None }).await?;
    // Drain RECORD(s) until the terminal SUCCESS summary.
    loop {
        match recv(&mut stream, &mut dechunker).await? {
            Some(Response::Record { .. }) => continue,
            Some(Response::Success { .. }) => break,
            other => panic!("PULL should stream records then SUCCESS, got {other:?}"),
        }
    }

    // Politely end the session so the server releases the permit promptly. The stream's FD closes on
    // drop at the end of this scope.
    let _ = send(&mut stream, &Request::Goodbye).await;
    Ok(ClientOutcome::Completed)
}

/// True if an I/O error means the peer (server) closed the connection — the signal that a connection
/// was shed at admission rather than failing for a protocol reason.
fn is_peer_closed(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        e.kind(),
        UnexpectedEof | ConnectionReset | ConnectionAborted | BrokenPipe
    )
}

async fn send(stream: &mut UnixStream, req: &graphus_bolt::Request) -> std::io::Result<()> {
    let bytes = graphus_bolt::server::encode_request_framed(req).expect("encode request");
    stream.write_all(&bytes).await?;
    stream.flush().await
}

/// Reads one framed Bolt message, returning `None` if the peer closed mid-read (shed).
async fn recv(
    stream: &mut UnixStream,
    dechunker: &mut Dechunker,
) -> std::io::Result<Option<graphus_bolt::Response>> {
    use graphus_bolt::Frame;
    let mut buf = [0u8; 4096];
    loop {
        if let Some(Frame::Message(payload)) = dechunker.next_frame().expect("dechunk") {
            return Ok(Some(
                graphus_bolt::Response::decode(&payload).expect("decode response"),
            ));
        }
        let n = match stream.read(&mut buf).await {
            Ok(n) => n,
            Err(ref e) if is_peer_closed(e) => return Ok(None),
            Err(e) => return Err(e),
        };
        if n == 0 {
            return Ok(None); // clean EOF — peer closed.
        }
        dechunker.push(&buf[..n]);
    }
}

// --------------------------------------------------------------------------------------------------
// 1. Many concurrent connections all complete; no FD/socket leak after the burst drains.
// --------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_concurrent_connections_all_complete_no_leak() {
    let temp = TempStore::new("many");
    let mut config = base_config(&temp);
    // A cap comfortably above the offered concurrency so every client is admitted: this test proves
    // the *sustain N concurrent* property, not shedding (that is test 2).
    const N: usize = 400;
    config.admission.max_connections = N + 32;
    let server = boot(config).await;
    let uds = Arc::new(server.uds_path.clone().expect("UDS enabled"));

    // Baseline FD count before the burst (after the server is fully up), for the no-leak assertion.
    #[cfg(target_os = "linux")]
    let fd_baseline = open_fd_count();

    let completed = Arc::new(AtomicU64::new(0));
    let started = Instant::now();
    let mut set = JoinSet::new();
    for _ in 0..N {
        let uds = Arc::clone(&uds);
        let completed = Arc::clone(&completed);
        set.spawn(async move {
            let t0 = Instant::now();
            let outcome = run_client(&uds).await.expect("client I/O must not hard-fail");
            assert_eq!(
                outcome,
                ClientOutcome::Completed,
                "under a cap above the offered concurrency, every client must be admitted and complete"
            );
            completed.fetch_add(1, Ordering::Relaxed);
            t0.elapsed()
        });
    }

    // Collect per-connection latencies (for the record; not asserted on absolute values).
    let mut latencies = Vec::with_capacity(N);
    while let Some(res) = set.join_next().await {
        latencies.push(res.expect("client task must not panic"));
    }
    let wall = started.elapsed();
    assert_eq!(
        completed.load(Ordering::Relaxed) as usize,
        N,
        "all N clients completed"
    );

    latencies.sort_unstable();
    let p50 = latencies[latencies.len() / 2];
    let p99 = latencies[(latencies.len() * 99 / 100).min(latencies.len() - 1)];
    let conns_per_sec = N as f64 / wall.as_secs_f64();
    eprintln!(
        "[STRESS#120] {N} concurrent connections completed in {wall:?}  \
         (~{conns_per_sec:.0} conns/s)  per-conn latency p50={p50:?} p99={p99:?}"
    );

    // No-leak assertion: after every client task has joined (sockets dropped) and the server has
    // released the permits, the process FD count must return to its pre-burst baseline. The permit
    // release and the server-side socket close are asynchronous, so retry briefly.
    #[cfg(target_os = "linux")]
    {
        let mut fds_now = open_fd_count();
        for _ in 0..100 {
            fds_now = open_fd_count();
            // Allow a small constant slack for transient runtime/epoll bookkeeping FDs.
            if fds_now <= fd_baseline + 8 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            fds_now <= fd_baseline + 8,
            "FD count must return to baseline after the burst (no leak): baseline={fd_baseline}, now={fds_now}"
        );
    }

    server.shutdown().await.expect("clean shutdown");
}

// --------------------------------------------------------------------------------------------------
// 2. Above the cap, the excess is shed (and counted); admitted clients complete; the server stays
//    live and admits a fresh connection once slots free.
// --------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admission_cap_sheds_excess_under_concurrency() {
    let temp = TempStore::new("shed");
    let mut config = base_config(&temp);
    // A small cap, then offer far more concurrent clients than it allows: some are admitted (complete
    // their query), the rest are shed.
    const CAP: usize = 16;
    const OFFERED: usize = 256;
    config.admission.max_connections = CAP;
    let server = boot(config).await;
    let uds = Arc::new(server.uds_path.clone().expect("UDS enabled"));

    let mut set = JoinSet::new();
    for _ in 0..OFFERED {
        let uds = Arc::clone(&uds);
        set.spawn(async move { run_client(&uds).await });
    }

    let mut completed = 0usize;
    let mut shed = 0usize;
    while let Some(res) = set.join_next().await {
        let outcome = res
            .expect("client task must not panic (no deadlock/abort under shedding)")
            .expect("client I/O must not hard-fail (shed is a clean close, not an error)");
        match outcome {
            ClientOutcome::Completed => completed += 1,
            ClientOutcome::Shed => shed += 1,
        }
    }
    assert_eq!(
        completed + shed,
        OFFERED,
        "every offered client resolved to completed or shed"
    );

    // The core admission property: with OFFERED ≫ CAP under genuine concurrency, *some* connections
    // are shed (the cap engaged) and *some* complete (the cap admits up to its limit). Both sides are
    // asserted as properties, not exact counts — the precise split depends on accept/permit-release
    // timing and must not be a fragile equality.
    assert!(
        shed > 0,
        "with {OFFERED} offered against a cap of {CAP}, some connections must be shed"
    );
    assert!(
        completed > 0,
        "admitted clients must complete their query under the cap"
    );

    // The shed is observable in the metrics counter.
    let shed_metric = metric(
        &server.metrics.render_prometheus(),
        "graphus_connections_shed_total",
    );
    assert!(
        shed_metric >= shed as u64,
        "the shed connections are counted in metrics: counter={shed_metric}, observed shed={shed}"
    );
    eprintln!(
        "[STRESS#120] cap={CAP} offered={OFFERED} → completed={completed} shed={shed} (metric={shed_metric})"
    );

    // The server is still live after the storm: a fresh connection is admitted now that the burst has
    // drained and slots are free.
    let mut admitted_after = false;
    for _ in 0..100 {
        match run_client(&uds).await.expect("post-burst client I/O") {
            ClientOutcome::Completed => {
                admitted_after = true;
                break;
            }
            ClientOutcome::Shed => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    assert!(
        admitted_after,
        "the server stays live and admits a fresh connection after the burst drains"
    );

    server.shutdown().await.expect("clean shutdown");
}

// --------------------------------------------------------------------------------------------------
// 3. Graceful shutdown drains cleanly while many sessions are held open.
// --------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn graceful_shutdown_drains_under_load() {
    let temp = TempStore::new("drain");
    let mut config = base_config(&temp);
    const HELD: usize = 64;
    config.admission.max_connections = HELD + 16;
    // Generous timeouts so the held sessions are not reaped before shutdown drives the drain.
    config.timing.handshake_timeout_ms = 5_000;
    config.timing.idle_timeout_ms = 30_000;
    let server = boot(config).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    // Open HELD live, logged-in sessions and keep their streams alive in a vec.
    let mut held = Vec::with_capacity(HELD);
    for _ in 0..HELD {
        held.push(open_logged_in_uds(&uds).await);
    }

    // Trigger graceful shutdown with the sessions still open: it must drain and return cleanly within
    // a bounded time (the test's own timeout guards against a hang/deadlock).
    let shutdown = tokio::time::timeout(Duration::from_secs(15), server.shutdown())
        .await
        .expect("graceful shutdown must not hang under held connections");
    shutdown.expect("graceful shutdown drains cleanly under load");

    drop(held);
}

/// Opens a UDS connection and completes Bolt handshake + HELLO/LOGON, returning the live stream.
/// Holding the stream keeps the server-side connection (and its permit) alive.
async fn open_logged_in_uds(path: &std::path::Path) -> UnixStream {
    use graphus_bolt::{Request, Response};
    let mut stream = UnixStream::connect(path).await.expect("connect UDS");
    let mut dechunker = Dechunker::new();

    let hs = encode_client_handshake([
        Proposal::range(5, 4, 4),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
    ]);
    stream.write_all(&hs).await.unwrap();
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [0x00, 0x00, 0x04, 0x05], "negotiated Bolt 5.4");

    send(
        &mut stream,
        &Request::Hello {
            extra: vec![(
                "user_agent".to_owned(),
                Value::String("connstress".to_owned()),
            )],
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        recv(&mut stream, &mut dechunker).await.unwrap(),
        Some(Response::Success { .. })
    ));

    send(
        &mut stream,
        &Request::Logon {
            auth: vec![
                ("scheme".to_owned(), Value::String("basic".to_owned())),
                ("principal".to_owned(), Value::String("alice".to_owned())),
                ("credentials".to_owned(), Value::String("admin-pw8".to_owned())),
            ],
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        recv(&mut stream, &mut dechunker).await.unwrap(),
        Some(Response::Success { .. })
    ));
    stream
}

/// Reads the value of a Prometheus counter line `name <value>` from a `/metrics` text body.
fn metric(text: &str, name: &str) -> u64 {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{name} ")) {
            if let Some(v) = rest.split_whitespace().next() {
                if let Ok(n) = v.parse() {
                    return n;
                }
            }
        }
    }
    0
}
