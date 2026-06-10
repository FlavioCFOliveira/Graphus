//! Acceptance test for `graphus-cli` (rmp #21): the CLI runs queries **and** an admin/status op
//! against a **LIVE** Graphus server over a Unix domain socket.
//!
//! This is the deliverable's acceptance criterion proven end-to-end. It boots a real `graphus-server`
//! in-process (a multi-thread Tokio runtime, the single-threaded engine on its own thread, the real
//! `RecordStore` over a fresh tempdir), exactly as `crates/graphus-server/tests/server_integration.rs`
//! does — same `base_config`, the `alice`/`pw` admin user, `admin_uid = this process's uid` so the
//! UDS peer-cred gate (`SO_PEERCRED`) admits the test's own connections. Then it drives the **real**
//! synchronous [`graphus_cli::client::BoltClient`] and [`graphus_cli::repl::Repl`] over that socket.
//!
//! ## Sync client on an async server
//!
//! The CLI client is intentionally **synchronous and blocking** (the right shape for an interactive
//! REPL). The server is async. So every client interaction runs inside
//! [`tokio::task::spawn_blocking`], off the runtime's reactor threads, while the async listener
//! services it on the runtime. This is the same bridge the eventual production REPL would use if
//! embedded in an async host, and it keeps the blocking socket calls from starving the reactor.

use std::path::{Path, PathBuf};

use graphus_cli::client::BoltClient;
use graphus_cli::render::render_table;
use graphus_cli::repl::Repl;
use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, ServerConfig, TimingConfig, TlsConfig,
};
use graphus_server::{Server, ServerHandle};

/// A unique temp directory for one test's store (auto-removed on drop), mirroring the server's own
/// integration-test helper.
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
            "graphus-cli-itest-{tag}-{nanos}-{}",
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

/// The current process uid, so the UDS peer-cred gate admits this test's own connections (Linux
/// reads `/proc/self/status`; elsewhere falls back to 0). Same logic as the server's test helper.
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

/// A UDS-only server config (no network listeners, so no TLS/secret needed), with the `alice`/`pw`
/// admin user gated to this process's uid.
fn uds_only_config(temp: &TempStore) -> ServerConfig {
    ServerConfig {
        store_path: temp.store_dir(),
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
        // No network listener is enabled, so the insecure default secret is fine (and unused).
        jwt_secret: "cli-itest-jwt-secret-not-used-uds-only!".to_owned(),
        auth: AuthBootstrap {
            admin_user: "alice".to_owned(),
            admin_password: "pw".to_owned(),
            admin_uid: Some(current_uid()),
        },
        allow_insecure_network: false,
    }
}

/// Boots a server from `config` and returns its handle once ready.
async fn boot(config: ServerConfig) -> ServerHandle {
    Server::new(config)
        .start()
        .await
        .expect("server should boot")
}

/// Runs `f` with a fresh, logged-in blocking client on a blocking thread (off the reactor).
///
/// The client connects over `uds`, logs in as `alice`/`pw`, hands itself to `f`, and is dropped
/// (closing the session) when `f` returns.
async fn with_client<T, F>(uds: &Path, f: F) -> T
where
    T: Send + 'static,
    F: FnOnce(BoltClient<std::os::unix::net::UnixStream>) -> T + Send + 'static,
{
    let uds = uds.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut client = BoltClient::connect_uds(&uds).expect("connect over UDS");
        client.login("alice", "pw").expect("login as alice");
        f(client)
    })
    .await
    .expect("client task panicked")
}

// ----------------------------------------------------------------------------------------------
// (a) The CLI runs a query that returns records, over the live UDS socket.
// ----------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_runs_query_and_renders_records_over_live_uds() {
    let temp = TempStore::new("query");
    let server = boot(uds_only_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    // First session: write a node via an auto-commit RUN so the read below returns something. The
    // write must simply succeed (the run() call returns Ok); the read-back below is what proves it
    // persisted to the real store.
    with_client(&uds, |mut client| {
        client
            .run("CREATE (:Greeting {text: 'olá'})")
            .expect("create succeeds");
        let _ = client.goodbye();
    })
    .await;

    // Second session: read it back and assert both the parsed records and the rendered table.
    let (parsed_ok, rendered) = with_client(&uds, |mut client| {
        let result = client
            .run("MATCH (g:Greeting) RETURN g.text AS text")
            .expect("match");
        // Parsed records carry the committed value.
        let parsed_ok = result.records.iter().any(|row| {
            row.iter()
                .any(|v| matches!(v, graphus_core::Value::String(s) if s == "olá"))
        });
        let rendered = render_table(&result);
        let _ = client.goodbye();
        (parsed_ok, rendered)
    })
    .await;

    assert!(
        parsed_ok,
        "the committed node must read back over the CLI client"
    );
    // The rendered ASCII table must carry the column header, the quoted value, and a 1-row footer.
    assert!(
        rendered.contains("| text"),
        "header column present:\n{rendered}"
    );
    assert!(
        rendered.contains("\"olá\""),
        "value rendered Cypher-ish (quoted):\n{rendered}"
    );
    assert!(
        rendered.contains("(1 row)"),
        "row count footer:\n{rendered}"
    );

    server.shutdown().await.expect("clean shutdown");
}

// ----------------------------------------------------------------------------------------------
// (b) The CLI performs the admin/status op against the live server and it succeeds.
// ----------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_status_admin_op_reports_live_server() {
    let temp = TempStore::new("status");
    let server = boot(uds_only_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");
    let uds_for_repl = uds.clone();

    let report = with_client(&uds, move |client| {
        // Drive the *real* REPL's `:status` admin op (a RETURN-1 liveness probe + the server identity
        // learned at HELLO), exactly as the interactive `:status` command does.
        let mut repl = Repl::new(client, uds_for_repl);
        let report = repl
            .status()
            .expect("status op succeeds against the live server");
        repl.goodbye();
        report
    })
    .await;

    // The admin/status report reflects the live server's self-reported identity + a proven round-trip.
    assert!(
        report.contains("Bolt 5.4"),
        "negotiated protocol:\n{report}"
    );
    assert!(
        report.contains("Graphus/0.0.0"),
        "server agent string from HELLO:\n{report}"
    );
    assert!(
        report.contains("connection:"),
        "connection id reported:\n{report}"
    );
    assert!(
        report.contains("liveness:     OK"),
        "liveness proven by a live RETURN 1 round-trip:\n{report}"
    );

    server.shutdown().await.expect("clean shutdown");
}

// ----------------------------------------------------------------------------------------------
// (c) A bad password is surfaced as a clean client error (not a panic) over the live UDS socket.
// ----------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_bad_password_is_a_clean_failure() {
    let temp = TempStore::new("auth");
    let server = boot(uds_only_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let outcome = {
        let uds = uds.clone();
        tokio::task::spawn_blocking(move || {
            let mut client = BoltClient::connect_uds(&uds).expect("connect over UDS");
            // Wrong password: a Bolt FAILURE, surfaced as a clean ClientError::Failure.
            client
                .login("alice", "WRONG")
                .map(|_| ())
                .map_err(|e| e.to_string())
        })
        .await
        .expect("client task panicked")
    };

    match outcome {
        Err(msg) => assert!(
            msg.to_lowercase().contains("unauthor")
                || msg.to_lowercase().contains("credential")
                || msg.to_lowercase().contains("auth"),
            "a wrong password is a clean auth failure, got: {msg}"
        ),
        Ok(()) => panic!("login with a wrong password must fail"),
    }

    server.shutdown().await.expect("clean shutdown");
}

// ----------------------------------------------------------------------------------------------
// (d) The shell's REPL dispatch (multi-line accumulation + rendering) works over the live socket.
// ----------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_repl_dispatch_runs_multiline_statement_over_live_uds() {
    let temp = TempStore::new("repl");
    let server = boot(uds_only_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");
    let uds_for_repl = uds.clone();

    let out = with_client(&uds, move |client| {
        let mut repl = Repl::new(client, uds_for_repl);
        let mut out: Vec<u8> = Vec::new();
        // A statement split across two lines, terminated by ';'. The first line buffers (no output),
        // the second completes and runs it.
        use graphus_cli::repl::Action;
        assert_eq!(
            repl.dispatch("RETURN 1 AS one,", &mut out).unwrap(),
            Action::Continue
        );
        assert!(out.is_empty(), "a partial line produces no output yet");
        assert_eq!(
            repl.dispatch("2 AS two;", &mut out).unwrap(),
            Action::Continue
        );

        // :help is handled locally; :quit asks the loop to stop.
        assert_eq!(repl.dispatch(":help", &mut out).unwrap(), Action::Continue);
        assert_eq!(repl.dispatch(":quit", &mut out).unwrap(), Action::Quit);
        repl.goodbye();
        String::from_utf8(out).expect("utf8 output")
    })
    .await;

    // The completed two-line statement rendered a table with both columns and a 1-row footer.
    assert!(out.contains("| one"), "first column header:\n{out}");
    assert!(out.contains("two"), "second column header:\n{out}");
    assert!(out.contains("(1 row)"), "row count footer:\n{out}");
    // :help printed the command list.
    assert!(out.contains(":status"), ":help output present:\n{out}");

    server.shutdown().await.expect("clean shutdown");
}

// ----------------------------------------------------------------------------------------------
// (e) The compiled `graphus-cli` BINARY runs a one-shot `-c` query over the live UDS socket.
// ----------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_binary_one_shot_command_over_live_uds() {
    let temp = TempStore::new("binary");
    let server = boot(uds_only_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    // Invoke the actual built binary: `graphus-cli --uds <sock> -u alice -c "RETURN ..."`, with the
    // password supplied via the environment (never echoed, never on argv). Run it on a blocking
    // thread so the synchronous child does not block the async runtime servicing the server.
    let uds_str = uds.to_string_lossy().into_owned();
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_graphus-cli"))
            .args([
                "--uds",
                &uds_str,
                "-u",
                "alice",
                "-c",
                "RETURN 'pong' AS reply, 42 AS answer",
            ])
            .env("GRAPHUS_PASSWORD", "pw")
            .output()
            .expect("spawn graphus-cli")
    })
    .await
    .expect("binary task panicked");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "binary exited non-zero.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // The one-shot output is the rendered table for the query.
    assert!(stdout.contains("reply"), "column header:\n{stdout}");
    assert!(
        stdout.contains("\"pong\""),
        "quoted string value:\n{stdout}"
    );
    assert!(stdout.contains("42"), "integer value:\n{stdout}");
    assert!(stdout.contains("(1 row)"), "row count footer:\n{stdout}");

    server.shutdown().await.expect("clean shutdown");
}
