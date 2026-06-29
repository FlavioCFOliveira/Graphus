//! Integration tests for the **per-source-IP connection cap** (rmp #478, D1/R1): the network listeners
//! cap the number of concurrently-open connections from a single source IP as an *inner* bound under the
//! global `max_connections` semaphore, so a single abusive source — or a distributed connect-then-
//! reconnect flood concentrated on a few sources — cannot keep the global budget saturated and shed
//! legitimate clients arriving from *other* IPs (`04-technical-design.md` §8/§9; the "exemplary under
//! extreme load" mandate, building on the rmp #118 global cap and the rmp #469 pre-auth deadline).
//!
//! The cap is exercised over the **REST** listener on plaintext loopback (`allow_insecure_network`), the
//! lightest surface to drive the accept-time gate: a permit + per-IP slot is taken before any TLS/HTTP
//! work, so merely connecting raw TCP sockets and holding them open occupies per-IP slots. The test
//! proves, end-to-end:
//!
//! - connections beyond an IP's cap are rejected (closed at accept time, counted in
//!   `graphus_connections_per_ip_rejected_total`) while the cap's worth are admitted;
//! - a connection from a **different source** (UDS — a distinct, IP-less local trust domain) is still
//!   admitted while loopback is per-IP-saturated, proving the cap sheds only the abusive source;
//! - the RAII guard **decrements on close**: after the saturating connections drop, fresh loopback
//!   connections are admitted again (no slot leak).
//!
//! Per-IP *counter* mechanics (precise increment/decrement, pruning, independence across IPs, the
//! disabled `cap == 0` mode, concurrency balance) are unit-tested in `listeners::ip_limit`; this file is
//! the listener-level proof that the cap is wired into the real accept path.

use std::path::PathBuf;
use std::time::Duration;

use graphus_bolt::Proposal;
use graphus_bolt::server::encode_client_handshake;
use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, ServerConfig, TimingConfig, TlsConfig,
};
use graphus_server::{Server, ServerHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

/// The per-source-IP cap this test configures.
const PER_IP_CAP: usize = 4;
/// Connections opened from the one loopback source — comfortably above the cap so the over-cap ones are
/// rejected while the global cap (set far higher) never binds.
const TOTAL_FROM_ONE_IP: usize = 10;

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
            "graphus-peripcap-{tag}-{nanos}-{}",
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
        // macOS/BSD: std exposes no `getuid()`; read the real uid via `id -u` so it matches the uid the
        // server's UDS peer-cred gate reports (via `getpeereid`). Returning 0 mismatched the runner's uid.
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(0)
    }
}

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
        admission: AdmissionConfig {
            // The global cap is far above the offered load, so it never binds — the per-IP cap is the
            // sole constraint under test.
            max_connections: 64,
            max_connections_per_ip: PER_IP_CAP,
            ..AdmissionConfig::default()
        },
        timing: TimingConfig {
            // Hold admitted-but-silent REST connections open well past the test's lifetime, so the cap
            // stays saturated for the duration (the held sockets pin per-IP slots until we drop them).
            header_read_timeout_ms: 30_000,
            ..TimingConfig::default()
        },
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

async fn boot(config: ServerConfig) -> ServerHandle {
    Server::new(config)
        .start()
        .await
        .expect("server should boot")
}

/// Reads the value of a Prometheus counter line `name <value>` from a rendered exposition.
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

/// A raw HTTP/1.1 GET over a plain `TcpStream` (no TLS). Returns the parsed status, or `0` when the
/// connection was rejected/closed before any HTTP bytes (a per-IP shed surfaces exactly this way).
async fn http_get(addr: std::net::SocketAddr, path: &str) -> u16 {
    let Ok(mut stream) = TcpStream::connect(addr).await else {
        return 0;
    };
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAccept: */*\r\n\r\n"
    );
    if stream.write_all(req.as_bytes()).await.is_err() || stream.flush().await.is_err() {
        return 0;
    }
    let mut raw = Vec::new();
    if stream.read_to_end(&mut raw).await.is_err() {
        return 0;
    }
    String::from_utf8_lossy(&raw)
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Connects a UDS socket and completes only the Bolt **handshake** (version negotiation), returning the
/// 4-byte negotiated-version reply. A reply of `[0,0,4,5]` proves the connection was *admitted* (the
/// session started and answered); a shed connection would instead close (the read errors). The handshake
/// alone suffices to prove admission — no HELLO/LOGON is needed for the "different source admitted" claim.
async fn uds_handshake_reply(path: &std::path::Path) -> std::io::Result<[u8; 4]> {
    let mut stream = UnixStream::connect(path).await?;
    let hs = encode_client_handshake([
        Proposal::range(5, 4, 4),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
    ]);
    stream.write_all(&hs).await?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    Ok(reply)
}

// ----------------------------------------------------------------------------------------------
// The per-IP cap binds, sheds only the abusive source, and frees its slots on close (RAII).
// ----------------------------------------------------------------------------------------------

#[tokio::test]
async fn per_ip_cap_rejects_over_cap_admits_other_sources_and_frees_on_close() {
    let temp = TempStore::new("bind");
    let server = boot(base_config(&temp)).await;
    let rest = server.rest_addr.expect("REST enabled");
    let uds = server.uds_path.clone().expect("UDS enabled");

    // --- 1. Saturate one source IP (loopback): open TOTAL raw TCP sockets and hold them open. ---
    // Each connect takes a global permit + a per-IP slot at accept time, before any HTTP bytes; sending
    // nothing leaves the admitted ones parked on the (30s) header-read deadline, pinning their slots.
    let mut held: Vec<TcpStream> = Vec::with_capacity(TOTAL_FROM_ONE_IP);
    for _ in 0..TOTAL_FROM_ONE_IP {
        if let Ok(s) = TcpStream::connect(rest).await {
            held.push(s);
        }
    }
    assert_eq!(
        held.len(),
        TOTAL_FROM_ONE_IP,
        "all sockets connect at the TCP layer (the cap is enforced after accept, not at connect)"
    );

    // The over-cap connections (TOTAL - CAP of them) are rejected at accept time and counted. Poll the
    // shared registry (reading /metrics over REST would itself consume a loopback slot under the cap).
    let want_rejected = (TOTAL_FROM_ONE_IP - PER_IP_CAP) as u64;
    let mut rejected = 0;
    for _ in 0..150 {
        rejected = metric(
            &server.metrics.render_prometheus(),
            "graphus_connections_per_ip_rejected_total",
        );
        if rejected >= want_rejected {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        rejected >= want_rejected,
        "the {} over-cap connections from one IP are rejected and counted (saw {rejected})",
        want_rejected
    );

    // --- 2. Exactly the cap's worth are admitted (held); the rest were closed by the server. ---
    let mut closed = 0usize;
    let mut still_held = 0usize;
    for s in &mut held {
        let mut buf = [0u8; 1];
        match tokio::time::timeout(Duration::from_millis(300), s.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => closed += 1, // rejected: server closed the socket (EOF/reset)
            Err(_) => still_held += 1,             // admitted + parked on the header-read deadline
            Ok(Ok(_)) => still_held += 1, // (unexpected) data without a request — not a shed
        }
    }
    assert!(
        still_held <= PER_IP_CAP,
        "no more than the cap ({PER_IP_CAP}) connections from one IP are admitted (held {still_held})"
    );
    assert!(
        closed >= TOTAL_FROM_ONE_IP - PER_IP_CAP,
        "the over-cap connections were closed at accept time (closed {closed})"
    );

    // --- 3. A DIFFERENT source is unaffected: UDS (a distinct, IP-less local trust domain) is still ---
    // admitted while loopback is per-IP-saturated — proving the cap sheds only the abusive source.
    let reply = uds_handshake_reply(&uds).await.expect(
        "a UDS connection (different source) is admitted while loopback is per-IP-saturated",
    );
    assert_eq!(
        reply,
        [0x00, 0x00, 0x04, 0x05],
        "the UDS connection negotiated Bolt 5.4 (it was admitted, not shed by the per-IP cap)"
    );

    // --- 4. While saturated, a FRESH loopback connection is rejected (the cap is binding). ---
    assert_eq!(
        http_get(rest, "/health/live").await,
        0,
        "a fresh loopback connection is rejected while the source IP is at its per-IP cap"
    );

    // --- 5. RAII: drop every held socket. Closing them must decrement the per-IP count (no leak), so ---
    // fresh loopback connections are admitted again.
    drop(held);
    let mut admitted_after = false;
    for _ in 0..150 {
        if http_get(rest, "/health/live").await == 200 {
            admitted_after = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        admitted_after,
        "after the saturating connections close, the RAII guard freed their per-IP slots and fresh \
         loopback connections are admitted again (no slot leak)"
    );

    server.shutdown().await.expect("clean shutdown");
}
