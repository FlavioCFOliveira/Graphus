//! Integration tests for **connection admission control** (rmp #118): the listeners cap the number
//! of concurrently-open connections and bound TLS handshakes and idle sessions, so a hostile or
//! extreme load cannot exhaust file descriptors / per-connection tasks *before* the query-admission
//! semaphore engages (`04-technical-design.md` §8/§9; the "exemplary under extreme load" mandate).
//!
//! Each test boots a real server in-process on loopback over a fresh tempdir store, then drives the
//! live transports to prove:
//!
//! - connections beyond `max_connections` are shed (closed at accept time, counted in metrics), and
//!   freeing a slot re-opens admission;
//! - a stalled TLS handshake (a TCP peer that never sends a ClientHello) is dropped after
//!   `handshake_timeout_ms` and counted;
//! - an idle Bolt session is reaped after `idle_timeout_ms` (the server closes the socket);
//! - graceful shutdown still drains cleanly with the new admission knobs in effect.
//!
//! The connection cap is exercised over **UDS** (kernel-protected, no TLS) so a permit is taken at
//! accept time without a TLS round-trip; the handshake timeout is exercised over **Bolt-TCP+TLS** (a
//! `rcgen` self-signed cert builds the rustls config) by connecting a raw `TcpStream` that never
//! speaks TLS.

use std::path::PathBuf;
use std::time::Duration;

use graphus_bolt::server::encode_client_handshake;
use graphus_bolt::{Dechunker, Proposal};
use graphus_core::Value;
use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, ServerConfig, TimingConfig, TlsConfig,
};
use graphus_server::{Server, ServerHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

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
            "graphus-connadm-{tag}-{nanos}-{}",
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
/// test client), no Bolt-TCP, the `alice`/`pw` admin user, store in `temp`.
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
            admin_password: "pw".to_owned(),
            admin_uid: Some(current_uid()),
            users: Vec::new(),
        },
        encryption: graphus_server::config::EncryptionConfig::default(),
        audit: graphus_server::AuditConfig::default(),
        allow_insecure_network: true,
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

/// Reads the value of a Prometheus counter line `name <value>` from a `/metrics` text body.
fn metric(text: &str, name: &str) -> u64 {
    for line in text.lines() {
        // Match the exact sample line `name value` (a trailing space guards against a shorter name
        // matching a longer metric as a prefix).
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

/// Opens a UDS connection and completes the Bolt handshake + HELLO/LOGON, returning the live stream.
/// Holding the returned stream keeps the server-side connection (and its admission permit) alive.
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
            extra: vec![("user_agent".to_owned(), Value::String("connadm".to_owned()))],
        },
    )
    .await;
    assert!(matches!(
        recv(&mut stream, &mut dechunker).await,
        Response::Success { .. }
    ));

    send(
        &mut stream,
        &Request::Logon {
            auth: vec![
                ("scheme".to_owned(), Value::String("basic".to_owned())),
                ("principal".to_owned(), Value::String("alice".to_owned())),
                ("credentials".to_owned(), Value::String("pw".to_owned())),
            ],
        },
    )
    .await;
    assert!(matches!(
        recv(&mut stream, &mut dechunker).await,
        Response::Success { .. }
    ));
    stream
}

async fn send(stream: &mut UnixStream, req: &graphus_bolt::Request) {
    let bytes = graphus_bolt::server::encode_request_framed(req).expect("encode request");
    stream.write_all(&bytes).await.unwrap();
    stream.flush().await.unwrap();
}

async fn recv(stream: &mut UnixStream, dechunker: &mut Dechunker) -> graphus_bolt::Response {
    use graphus_bolt::Frame;
    let mut buf = [0u8; 4096];
    loop {
        if let Some(Frame::Message(payload)) = dechunker.next_frame().expect("dechunk") {
            return graphus_bolt::Response::decode(&payload).expect("decode response");
        }
        let n = stream.read(&mut buf).await.expect("read");
        assert!(n > 0, "server closed the connection mid-exchange");
        dechunker.push(&buf[..n]);
    }
}

// ----------------------------------------------------------------------------------------------
// 1. The connection cap sheds connections beyond `max_connections`, and freeing a slot re-admits.
// ----------------------------------------------------------------------------------------------

#[tokio::test]
async fn connection_cap_sheds_beyond_limit_and_frees_on_close() {
    let temp = TempStore::new("cap");
    let mut config = base_config(&temp);
    // Three concurrent connections allowed across the whole process. The global cap is shared by all
    // listeners, including REST — so we keep one slot free for the `/metrics` read below (which itself
    // consumes a permit for the duration of the request) by holding only three UDS sessions and then
    // freeing one before reading metrics.
    config.admission.max_connections = 3;
    let server = boot(config).await;
    let uds = server.uds_path.clone().expect("UDS enabled");
    let rest = server.rest_addr.expect("REST enabled");

    // Fill the cap: three live, logged-in UDS sessions, each holding a permit for its lifetime.
    let c1 = open_logged_in_uds(&uds).await;
    let c2 = open_logged_in_uds(&uds).await;
    let c3 = open_logged_in_uds(&uds).await;

    // A fourth connection is accepted at the socket layer but immediately shed (closed) by the server
    // before any Bolt bytes: our handshake write may succeed into the socket buffer, but the read of
    // the 4-byte version reply hits EOF/reset because the server dropped the connection.
    let mut c4 = UnixStream::connect(&uds).await.expect("connect 4th UDS");
    let hs = encode_client_handshake([
        Proposal::range(5, 4, 4),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
    ]);
    let _ = c4.write_all(&hs).await; // may succeed (socket buffer) or fail (already reset)
    let mut reply = [0u8; 4];
    let read = c4.read_exact(&mut reply).await;
    assert!(
        read.is_err(),
        "the shed 4th connection is closed by the server (read hits EOF/reset), got {read:?}"
    );

    // Free a slot so the REST `/metrics` read can be admitted, then assert the shed is observable.
    drop(c1);
    // The permit releases asynchronously when the session task finishes; retry the metrics read until
    // a slot is free (a shed REST request returns an empty/closed body).
    let mut shed_seen = 0;
    for _ in 0..50 {
        let (status, body) = http_get(rest, "/metrics").await;
        if status == 200 {
            shed_seen = metric(&body, "graphus_connections_shed_total");
            if shed_seen >= 1 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        shed_seen >= 1,
        "at least one connection was shed and is counted in metrics"
    );

    // A fresh connection is admitted on the freed slot (full handshake succeeds).
    let c5 = wait_for_admission(&uds).await;

    drop(c2);
    drop(c3);
    drop(c4);
    drop(c5);
    server.shutdown().await.expect("clean shutdown");
}

/// Retries opening a logged-in UDS connection until a permit frees up (the server releases the
/// dropped session's permit asynchronously). Fails the test if no slot opens within the budget.
async fn wait_for_admission(uds: &std::path::Path) -> UnixStream {
    for _ in 0..50 {
        // Try a full handshake; if the server has freed a slot, it succeeds. If still saturated, the
        // connection is shed (read EOF) and we retry after a short delay.
        let mut stream = match UnixStream::connect(uds).await {
            Ok(s) => s,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
        };
        let hs = encode_client_handshake([
            Proposal::range(5, 4, 4),
            Proposal::exact(0, 0),
            Proposal::exact(0, 0),
            Proposal::exact(0, 0),
        ]);
        if stream.write_all(&hs).await.is_err() {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        }
        let mut reply = [0u8; 4];
        if stream.read_exact(&mut reply).await.is_ok() {
            assert_eq!(
                reply,
                [0x00, 0x00, 0x04, 0x05],
                "negotiated Bolt 5.4 on the re-admitted slot"
            );
            return stream;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("a freed connection slot was never re-admitted within the budget");
}

// ----------------------------------------------------------------------------------------------
// 2. A stalled TLS handshake is dropped after the handshake timeout (Bolt-TCP+TLS).
// ----------------------------------------------------------------------------------------------

#[tokio::test]
async fn stalled_tls_handshake_is_dropped_after_timeout() {
    let temp = TempStore::new("handshake");

    // Self-signed cert/key for the TLS listener.
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_path = temp.path.join("cert.pem");
    let key_path = temp.path.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();

    let mut config = base_config(&temp);
    config.tls = TlsConfig {
        cert_path: Some(cert_path),
        key_path: Some(key_path),
    };
    config.bolt_tcp_addr = Some("127.0.0.1:0".to_owned());
    // Disable REST for this test: enabling TLS would make the plaintext metrics client unusable, and
    // the handshake-timeout signal is read directly off the metrics registry below.
    config.rest_addr = None;
    // A short handshake deadline so the test is fast and deterministic.
    config.timing.handshake_timeout_ms = 300;
    let server = boot(config).await;
    let bolt = server.bolt_tcp_addr.expect("Bolt-TCP enabled");

    // Connect a raw TCP socket and never send a TLS ClientHello: the server's `tls.accept` blocks,
    // and the handshake-timeout guard must drop the connection after ~300ms.
    let mut stalled = TcpStream::connect(bolt).await.expect("connect Bolt-TCP");

    // After the deadline elapses (plus slack), the server closes the connection: our read returns 0
    // (EOF) — or, if the close raced into a reset, a connection error. Either proves the server let
    // go; what must NOT happen is the read blocking forever.
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(5), stalled.read(&mut buf))
        .await
        .expect("the server must close the stalled handshake well within 5s");
    match read {
        Ok(0) => {} // clean EOF (FIN) — the expected path
        Ok(n) => panic!("a stalled-handshake socket must not yield bytes, got {n}"),
        Err(_) => {} // a reset is also an acceptable signal that the server dropped it
    }

    // The drop is observable in metrics (read directly off the shared registry; the REST listener is
    // TLS here so a plaintext metrics client cannot be used). The counter is set in the handshake task
    // as it closes the socket; retry briefly to avoid racing that increment.
    let mut seen = 0;
    for _ in 0..50 {
        seen = metric(
            &server.metrics.render_prometheus(),
            "graphus_handshake_timeouts_total",
        );
        if seen >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(seen >= 1, "the handshake timeout is counted in metrics");

    server.shutdown().await.expect("clean shutdown");
}

// ----------------------------------------------------------------------------------------------
// 3. An idle Bolt session is reaped after the idle timeout.
// ----------------------------------------------------------------------------------------------

#[tokio::test]
async fn idle_bolt_session_is_reaped_after_idle_timeout() {
    let temp = TempStore::new("idle");
    let mut config = base_config(&temp);
    // A short idle deadline: a session that sends nothing for >300ms is reaped.
    config.timing.idle_timeout_ms = 300;
    let server = boot(config).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    // Open + log in, then go completely silent. The server's per-read idle deadline fires and the
    // session ends, closing the socket; our blocking read returns EOF.
    let mut stream = open_logged_in_uds(&uds).await;

    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("the server must reap the idle session well within 5s");
    match read {
        Ok(0) => {} // clean EOF — the session loop ended and the socket closed
        Ok(n) => panic!("a reaped idle session must not yield bytes, got {n}"),
        Err(_) => {} // a reset is also acceptable evidence the server closed it
    }

    server.shutdown().await.expect("clean shutdown");
}

// ----------------------------------------------------------------------------------------------
// 4. Idle reaping disabled (the default) leaves a quiet-but-live session open.
// ----------------------------------------------------------------------------------------------

#[tokio::test]
async fn idle_reaping_disabled_keeps_session_open() {
    let temp = TempStore::new("noidle");
    let config = base_config(&temp); // idle_timeout_ms = 0 (default, disabled)
    let server = boot(config).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut stream = open_logged_in_uds(&uds).await;

    // With reaping disabled, a quiet session is NOT closed: a read blocks past any idle window. We
    // assert the read times out on *our* side (the server kept the connection open).
    let mut buf = [0u8; 16];
    let outcome = tokio::time::timeout(Duration::from_millis(600), stream.read(&mut buf)).await;
    assert!(
        outcome.is_err(),
        "with idle reaping off, a quiet session stays open (our read times out, not EOF)"
    );

    drop(stream);
    server.shutdown().await.expect("clean shutdown");
}

// ----------------------------------------------------------------------------------------------
// 5. Graceful shutdown still drains cleanly with the admission knobs in effect.
// ----------------------------------------------------------------------------------------------

#[tokio::test]
async fn graceful_shutdown_still_drains_with_admission_limits() {
    let temp = TempStore::new("drain");
    let mut config = base_config(&temp);
    config.admission.max_connections = 4;
    config.timing.handshake_timeout_ms = 1_000;
    config.timing.idle_timeout_ms = 5_000;
    let server = boot(config).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    // One live session, then trigger graceful shutdown: the drain (shutdown edge raced in the read
    // bridge) ends the session and `shutdown()` returns cleanly.
    let _live = open_logged_in_uds(&uds).await;
    server
        .shutdown()
        .await
        .expect("graceful shutdown drains cleanly");
}

// ----------------------------------------------------------------------------------------------
// A tiny raw HTTP/1.1 GET over a plain TcpStream (no TLS) for reading `/metrics`.
// ----------------------------------------------------------------------------------------------

async fn http_get(addr: std::net::SocketAddr, path: &str) -> (u16, String) {
    // The REST request itself consumes a connection permit: when the global cap is still full (e.g. a
    // just-dropped session's permit has not been released yet), the server *sheds* this connection —
    // it is accepted at the socket layer then immediately closed before any HTTP bytes. That surfaces
    // to the client as a connect/write/read error (EOF or ECONNRESET), NOT as a clean HTTP response.
    // Treat every such error as a sentinel `(0, "")` so the caller's retry loop simply tries again,
    // rather than panicking — the shed is an expected, transient outcome under a saturated cap.
    let Ok(mut stream) = TcpStream::connect(addr).await else {
        return (0, String::new());
    };
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAccept: text/plain\r\n\r\n"
    );
    if stream.write_all(req.as_bytes()).await.is_err() || stream.flush().await.is_err() {
        return (0, String::new());
    }
    let mut raw = Vec::new();
    if stream.read_to_end(&mut raw).await.is_err() {
        return (0, String::new());
    }
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    (status, body)
}
