//! Red-team **security audit** battery for `graphus-server` / `graphus-cli` (cyber-security review).
//!
//! Each test pins one finding from the audit. They boot a real server in-process on loopback over a
//! fresh tempdir store (mirroring `connection_admission.rs`) and probe the live transports / on-disk
//! artifacts, OR they unit-check a pure surface (config `Debug` redaction).
//!
//! ## Convention
//!
//! Each finding below is **fixed**; the test is a `// Regression: SEC-<rmp-task-id>` guard that
//! asserts the **secure** post-fix state, so a future change that reintroduces the weakness fails the
//! suite. No test is `#[ignore]`d or skipped.
//!
//! Findings covered:
//! - SEC-176 — UDS socket restricted to owner-only (`mode & 0o077 == 0`). CWE-276/732.
//! - SEC-177 — `security.toml` (argon2 hashes + uid maps) owner-only (`mode & 0o077 == 0`). CWE-732/312.
//! - SEC-181 — REST request-header read timeout is configured (slow-loris guard). CWE-400/770.
//! - SEC-183 — `ServerConfig`/`AuthBootstrap` `Debug` redacts every secret. CWE-532/209.
//! - SEC-185 — the CLI argv password concern is regression-tested in `graphus-cli` (`password_source`).

use std::path::PathBuf;

use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, EncryptionConfig, ServerConfig, TimingConfig, TlsConfig,
    UserBootstrap,
};
// `TimingConfig` is used by the SEC-181 regression below as well as the base config builder.
use graphus_server::{Server, ServerHandle};

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
        path.push(format!("graphus-secaudit-{tag}-{nanos}-{}", std::process::id()));
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
        0
    }
}

/// Base config: UDS-only on the temp socket (no network listener => no TLS/secret needed), the
/// `alice` admin user bound to this process's uid, store under the tempdir.
fn uds_only_config(temp: &TempStore) -> ServerConfig {
    ServerConfig {
        store_path: temp.store_dir(),
        default_database: "graphus".to_owned(),
        buffer_pool_pages: 256,
        bolt_tcp_addr: None,
        advertised_bolt_address: None,
        rest_addr: None,
        uds_path: Some(temp.uds_path()),
        tls: TlsConfig::default(),
        admission: AdmissionConfig::default(),
        timing: TimingConfig::default(),
        jwt_secret: "security-audit-jwt-secret-32-bytes!!".to_owned(),
        auth: AuthBootstrap {
            admin_user: "alice".to_owned(),
            admin_password: "admin-pw8".to_owned(),
            admin_uid: Some(current_uid()),
            users: Vec::new(),
        },
        encryption: EncryptionConfig::default(),
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

// ================================================================================================
// SEC-176 — UDS socket file permissions (CWE-276 / CWE-732)
// ================================================================================================

/// The bound UDS socket must not be world-accessible: the documented UDS authorization story is
/// "SO_PEERCRED **plus filesystem permissions**", so the socket file should be at most group-
/// accessible (mode & 0o777 <= 0o660), never world-readable/writable/connectable.
///
/// `UdsAcceptor::bind` now restricts the socket to owner-only (`0o600`) immediately after `bind` and
/// *before* any connection is accepted (in-place `chmod`, not temp+rename — a UDS path is `SUN_LEN`
/// bounded), so no group/world bit is ever set on a socket that is being polled for connections.
#[cfg(unix)]
#[tokio::test]
async fn sec176_uds_socket_permissions_are_not_world_accessible() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempStore::new("uds-perms");
    let sock = temp.uds_path();
    let handle = boot(uds_only_config(&temp)).await;

    let meta = std::fs::metadata(&sock).expect("the UDS socket file exists once bound");
    let mode = meta.permissions().mode() & 0o777;

    // Regression: SEC-176 — no group/world access bit may be set on the published socket.
    assert_eq!(
        mode & 0o077,
        0,
        "the UDS socket must be owner-only (mode {mode:#o}); group/world bits indicate SEC-176 \
         regressed (the listener must restrict the socket before it is connectable)"
    );

    handle.shutdown().await.expect("clean shutdown");
}

// ================================================================================================
// SEC-177 — security.toml permissions (CWE-732 / CWE-312)
// ================================================================================================

/// The durable `security.toml` holds every user's argon2 password hash and the uid->user mappings.
/// It must be owner-only (mode & 0o777 <= 0o600), never group/world-readable, so a local user cannot
/// copy the hashes for offline cracking.
///
/// `persist_file` now creates the temp with mode `0o600` (and re-asserts it on the fd) before any
/// bytes are written; the atomic `rename` preserves it, so the published `security.toml` is
/// owner-only and a local user cannot copy the argon2 hashes for offline cracking.
#[cfg(unix)]
#[tokio::test]
async fn sec177_security_toml_is_not_world_or_group_readable() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempStore::new("sec-toml-perms");
    let store = temp.store_dir();
    let handle = boot(uds_only_config(&temp)).await;

    // The catalog persists `security.toml` under the store path during bootstrap seeding.
    let sec_file = store.join("security.toml");
    assert!(
        sec_file.exists(),
        "bootstrap must have persisted security.toml at {}",
        sec_file.display()
    );
    let mode = std::fs::metadata(&sec_file)
        .expect("stat security.toml")
        .permissions()
        .mode()
        & 0o777;

    // Regression: SEC-177 — no group/world bit may be set on the hash file.
    assert_eq!(
        mode & 0o077,
        0,
        "security.toml (argon2 hashes + uid maps) must be owner-only (mode {mode:#o}); a group/world \
         bit indicates SEC-177 regressed"
    );

    handle.shutdown().await.expect("clean shutdown");
}

// ================================================================================================
// SEC-183 — ServerConfig/AuthBootstrap Debug leaks secrets (CWE-532 / CWE-209)
// ================================================================================================

/// `format!("{:?}", config)` must not reveal the JWT secret, any password, or the scrape token: a
/// stray `tracing::debug!(?config)` or a panic carrying the config would otherwise spill every
/// secret into the logs / an error message.
///
/// `ServerConfig`/`AuthBootstrap`/`UserBootstrap` now implement `Debug` manually with every secret
/// redacted, so `format!("{:?}", config)` cannot spill the JWT secret, any password, or the scrape
/// token into a log line or an error message.
#[test]
fn sec183_config_debug_redacts_secrets() {
    let cfg = ServerConfig {
        jwt_secret: "TOP-SECRET-JWT-SIGNING-KEY-001".to_owned(),
        auth: AuthBootstrap {
            admin_user: "admin".to_owned(),
            admin_password: "TOP-SECRET-ADMIN-PW-002".to_owned(),
            admin_uid: None,
            users: vec![UserBootstrap {
                name: "app".to_owned(),
                password: "TOP-SECRET-APP-PW-003".to_owned(),
            }],
        },
        metrics_scrape_token: Some("TOP-SECRET-SCRAPE-TOKEN-004".to_owned()),
        ..ServerConfig::default()
    };

    let dbg = format!("{cfg:?}");

    // Regression: SEC-183 — no secret literal may appear in the rendered Debug.
    assert!(
        !dbg.contains("TOP-SECRET-JWT-SIGNING-KEY-001"),
        "jwt_secret leaked through Debug (SEC-183 regressed): {dbg}"
    );
    assert!(
        !dbg.contains("TOP-SECRET-ADMIN-PW-002"),
        "admin_password leaked through Debug (SEC-183 regressed): {dbg}"
    );
    assert!(
        !dbg.contains("TOP-SECRET-APP-PW-003"),
        "bootstrap user password leaked through Debug (SEC-183 regressed): {dbg}"
    );
    assert!(
        !dbg.contains("TOP-SECRET-SCRAPE-TOKEN-004"),
        "metrics_scrape_token leaked through Debug (SEC-183 regressed): {dbg}"
    );
    // The redaction marker is present (so a reader knows a secret was elided, not just absent) and
    // non-secret fields are still rendered for diagnosability.
    assert!(
        dbg.contains("<redacted>"),
        "redacted secrets should render a marker: {dbg}"
    );
    assert!(
        dbg.contains("admin_user: \"admin\""),
        "non-secret fields must still render: {dbg}"
    );
}

// ================================================================================================
// SEC-181 — REST header read timeout (CWE-400 / CWE-770)
// ================================================================================================

/// The REST listener must bound how long a client may take to send its complete request headers
/// after TLS, or a slow-loris drip pins a connection-admission permit indefinitely. The fix adds a
/// configurable `header_read_timeout` wired to hyper's `http1().header_read_timeout(...)`; the
/// default must be a finite, secure value (not disabled).
#[test]
fn sec181_rest_header_read_timeout_is_configured_by_default() {
    let timing = TimingConfig::default();
    // Regression: SEC-181 — the default must enable the guard with a finite deadline.
    assert!(
        timing.header_read_timeout_ms > 0,
        "the REST header-read timeout must default to a finite, enabled value (SEC-181)"
    );
    let configured = timing.header_read_timeout();
    assert_eq!(
        configured,
        Some(std::time::Duration::from_millis(timing.header_read_timeout_ms)),
        "header_read_timeout() must surface the configured deadline when non-zero (SEC-181)"
    );
    // Sanity: an explicit 0 disables it (operator opt-out), and the accessor reflects that.
    let disabled = TimingConfig {
        header_read_timeout_ms: 0,
        ..TimingConfig::default()
    };
    assert_eq!(disabled.header_read_timeout(), None);
}

// ================================================================================================
// Positive controls — defences that ARE in place (regression guards, not vulnerabilities)
// ================================================================================================

/// Defence-in-depth control: a network listener (REST) without TLS and without the insecure-network
/// escape hatch must be REFUSED by `validate` — fail-closed, no plaintext network by accident.
#[test]
fn control_network_listener_without_tls_is_refused() {
    let cfg = ServerConfig {
        rest_addr: Some("0.0.0.0:7474".to_owned()),
        bolt_tcp_addr: None,
        uds_path: None,
        jwt_secret: "a-real-secret-value-32-bytes-long!!".to_owned(),
        allow_insecure_network: false,
        ..ServerConfig::default()
    };
    assert!(
        cfg.validate().is_err(),
        "a TLS-less network listener must be refused (fail-closed)"
    );
}

/// Defence-in-depth control: shipping the known insecure default JWT secret with a REST listener is
/// refused, so a real deployment cannot accidentally sign Bearer tokens with a public secret.
#[test]
fn control_insecure_default_jwt_secret_is_refused_with_rest() {
    let cfg = ServerConfig {
        rest_addr: Some("127.0.0.1:7474".to_owned()),
        bolt_tcp_addr: None,
        uds_path: None,
        // Keep the insecure default; with REST enabled this must be rejected.
        tls: TlsConfig {
            cert_path: Some(PathBuf::from("c.pem")),
            key_path: Some(PathBuf::from("k.pem")),
        },
        allow_insecure_network: false,
        ..ServerConfig::default()
    };
    assert!(
        cfg.validate().is_err(),
        "the insecure default JWT secret must be refused for a REST listener"
    );
}

/// Defence-in-depth control: an explicitly-empty `metrics_scrape_token` is refused (a blank shared
/// secret authenticates nobody safely), so `/metrics` stays fail-closed.
#[test]
fn control_empty_metrics_scrape_token_is_refused() {
    let cfg = ServerConfig {
        rest_addr: None,
        bolt_tcp_addr: None,
        uds_path: Some(PathBuf::from("x.sock")),
        metrics_scrape_token: Some("   ".to_owned()),
        ..ServerConfig::default()
    };
    assert!(
        cfg.validate().is_err(),
        "a blank metrics scrape token must be refused"
    );
}
