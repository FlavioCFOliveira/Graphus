//! Server-level encryption-at-rest tests (rmp #85, #88): a fresh server configured with an
//! encryption key creates an **encrypted** store **and an encrypted WAL**, writes data, and on
//! restart with the **correct** key reads it back; with a **wrong** key, startup fails closed. A
//! server with **no** key configured behaves exactly as before (plaintext store + plaintext WAL).
//!
//! These boot a real in-process server over a fresh tempdir (UDS-only: no TLS, no network), mirroring
//! `multi_database.rs`. Backup encryption and key rotation are sub-task #89 — the record-store device
//! (#85) and the write-ahead log (#88) are both encrypted here.

use std::path::PathBuf;

use graphus_core::Value;
use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, EncryptionConfig, ServerConfig, TimingConfig, TlsConfig,
};
use graphus_server::engine::{AccessMode, EngineHandle};
use graphus_server::{Server, ServerHandle};

/// A unique temp directory for one test's data root + key file (auto-removed on drop).
struct TempStore {
    path: PathBuf,
}

impl TempStore {
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        path.push(format!("graphus-enc-{tag}-{nanos}-{}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn store_dir(&self) -> PathBuf {
        self.path.join("store")
    }

    fn uds_path(&self) -> PathBuf {
        self.path.join("graphus.sock")
    }

    /// Writes a 32-byte key file (`fill`-filled) and returns its path.
    fn write_key(&self, name: &str, fill: u8) -> PathBuf {
        let key_path = self.path.join(name);
        std::fs::write(&key_path, [fill; 32]).expect("write key file");
        key_path
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A UDS-only config (no network listener ⇒ no TLS / JWT secret needed) over `temp`'s store dir,
/// optionally with an encryption key file.
fn config_with_key(temp: &TempStore, key_path: Option<PathBuf>) -> ServerConfig {
    ServerConfig {
        store_path: temp.store_dir(),
        default_database: "graphus".to_owned(),
        buffer_pool_pages: 256,
        fsync_threads: 1,
        bolt_tcp_addr: None,
        rest_addr: None,
        uds_path: Some(temp.uds_path()),
        tls: TlsConfig::default(),
        admission: AdmissionConfig {
            max_concurrent_queries: 64,
            engine_queue_capacity: 256,
            result_buffer_capacity: 64,
        },
        timing: TimingConfig {
            slow_query_threshold_ms: 1_000,
            shutdown_drain_deadline_ms: 5_000,
        },
        jwt_secret: "enc-itest-jwt-secret-uds-only-here!!".to_owned(),
        auth: AuthBootstrap {
            admin_user: "alice".to_owned(),
            admin_password: "pw".to_owned(),
            admin_uid: None,
            users: Vec::new(),
        },
        encryption: EncryptionConfig { key_path },
        allow_insecure_network: false,
    }
}

async fn boot(config: ServerConfig) -> ServerHandle {
    Server::new(config)
        .start()
        .await
        .expect("server should boot")
}

/// Runs one auto-commit statement and returns all result rows.
async fn run_query(handle: &EngineHandle, query: &str) -> Vec<Vec<Value>> {
    let ticket = handle
        .begin_auto_commit(AccessMode::Write)
        .await
        .expect("begin auto-commit");
    let reply = handle
        // `None` privileges: the test harness runs unrestricted (no RBAC enforcement, rmp #93).
        .run(ticket, query.to_owned(), Vec::new(), true, None)
        .await
        .expect("run statement");
    tokio::task::spawn_blocking(move || {
        let mut rx = reply.rows;
        let mut rows = Vec::new();
        loop {
            match rx.next() {
                Ok(Some(row)) => rows.push(row),
                Ok(None) => break,
                Err(e) => panic!("row stream error: {e}"),
            }
        }
        rows
    })
    .await
    .expect("drain rows")
}

async fn count(handle: &EngineHandle, query: &str) -> i64 {
    let rows = run_query(handle, query).await;
    assert_eq!(rows.len(), 1, "count query returns exactly one row");
    match rows[0].first() {
        Some(Value::Integer(n)) => *n,
        other => panic!("expected an integer count, got {other:?}"),
    }
}

#[tokio::test]
async fn encrypted_store_persists_and_reopens_with_the_correct_key() {
    let temp = TempStore::new("roundtrip");
    let key = temp.write_key("master.key", 0xA1);

    // Boot #1: write data into the encrypted store.
    {
        let handle = boot(config_with_key(&temp, Some(key.clone()))).await;
        run_query(&handle.engine, "CREATE (:Secret {v: 42})").await;
        assert_eq!(
            count(&handle.engine, "MATCH (n:Secret) RETURN count(n)").await,
            1
        );
        handle.shutdown().await.expect("graceful shutdown");
    }

    // The store file exists and does NOT contain the plaintext label/property in the clear.
    let store_file = temp.store_dir().join("graphus.store");
    let bytes = std::fs::read(&store_file).expect("read store file");
    assert!(
        !bytes.windows(b"Secret".len()).any(|w| w == b"Secret"),
        "the label name must not appear in cleartext in the encrypted store file"
    );

    // The WAL file is encrypted too (rmp #88): the label written through the WAL must not appear in
    // cleartext, and the file must carry the encrypted-WAL sink magic ("GRAPHUSW") at its start.
    let wal_file = temp.store_dir().join("graphus.wal");
    let wal_bytes = std::fs::read(&wal_file).expect("read wal file");
    assert!(
        !wal_bytes.windows(b"Secret".len()).any(|w| w == b"Secret"),
        "the label name must not appear in cleartext in the encrypted WAL file"
    );
    assert!(
        wal_bytes.starts_with(b"GRAPHUSW"),
        "the encrypted WAL begins with the encrypted-WAL sink magic"
    );

    // Boot #2: with the SAME key the data reads back.
    let handle = boot(config_with_key(&temp, Some(key))).await;
    assert_eq!(
        count(&handle.engine, "MATCH (n:Secret) RETURN count(n)").await,
        1,
        "the encrypted data is recovered on restart with the correct key"
    );
    handle.shutdown().await.expect("graceful shutdown");
}

#[tokio::test]
async fn a_wrong_key_fails_startup_closed() {
    let temp = TempStore::new("wrongkey");
    let right = temp.write_key("right.key", 0xB1);
    let wrong = temp.write_key("wrong.key", 0xB2);

    // Boot #1 with the right key, write, shut down.
    {
        let handle = boot(config_with_key(&temp, Some(right))).await;
        run_query(&handle.engine, "CREATE (:Datum {v: 1})").await;
        handle.shutdown().await.expect("graceful shutdown");
    }

    // Boot #2 with a WRONG key must fail closed (KCV mismatch at the default DB's engine startup).
    let result = Server::new(config_with_key(&temp, Some(wrong)))
        .start()
        .await;
    assert!(
        result.is_err(),
        "a wrong encryption key must fail server startup, not silently open"
    );
}

#[tokio::test]
async fn plaintext_path_is_unchanged_without_a_key() {
    let temp = TempStore::new("plaintext");

    // No key configured: the store is plaintext, exactly as before encryption existed.
    {
        let handle = boot(config_with_key(&temp, None)).await;
        run_query(&handle.engine, "CREATE (:Plain {v: 7})").await;
        handle.shutdown().await.expect("graceful shutdown");
    }

    // A plaintext store reopens unchanged with no key.
    let handle = boot(config_with_key(&temp, None)).await;
    assert_eq!(
        count(&handle.engine, "MATCH (n:Plain) RETURN count(n)").await,
        1
    );
    handle.shutdown().await.expect("graceful shutdown");

    // The label DOES appear in cleartext in a plaintext store (the contrast that proves the
    // encrypted test above is meaningful).
    let store_file = temp.store_dir().join("graphus.store");
    let bytes = std::fs::read(&store_file).expect("read store file");
    assert!(
        bytes.windows(b"Plain".len()).any(|w| w == b"Plain"),
        "a plaintext store stores label names in the clear (the encrypted store must not)"
    );

    // The plaintext WAL is byte-identical to before WAL encryption existed: no encrypted-WAL magic,
    // and it carries the plaintext WAL magic ("GWAL", little-endian 0x4757414C) in its header.
    let wal_file = temp.store_dir().join("graphus.wal");
    let wal_bytes = std::fs::read(&wal_file).expect("read wal file");
    assert!(
        !wal_bytes.starts_with(b"GRAPHUSW"),
        "a plaintext WAL must not carry the encrypted-WAL sink magic"
    );
    assert_eq!(
        &wal_bytes[0..4],
        &0x4757_414Cu32.to_le_bytes(),
        "a plaintext WAL begins with the unchanged plaintext WAL magic"
    );
}
