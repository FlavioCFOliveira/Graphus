//! **Permanent failures must not be announced as retryable** (`rmp` task #988).
//!
//! # The defect
//!
//! Retryability was derived from the [`GraphusError`] variant alone, and
//! [`GraphusError::Transaction`] was overloaded: it carried a genuine serialization abort
//! (retryable) *and* a pile of permanent misuse errors. Every one of those rendered as
//! `Neo.TransientError.Transaction.Outdated`, which the official Neo4j drivers classify as
//! **retryable**.
//!
//! The headline reproduction: `session.executeRead` running a `CREATE`. The driver replayed the unit
//! of work — which can never become legal — until `maxTransactionRetryTime` (**30 s** by default in
//! every official driver) was spent, and then reported a *timeout* instead of the real cause.
//!
//! # What these gates assert
//!
//! For **each** site that used to emit the overloaded variant, driven through the **real** engine,
//! the **real** Bolt seam and the **real** REST seam — never by constructing an error by hand:
//!
//! 1. the Neo4j status code a driver receives on the Bolt wire, spelled out **literally**;
//! 2. the retry answer the official drivers compute from it, via [`driver_is_retryable`] — a faithful
//!    re-implementation of the drivers' own rule (see that function for the pinned sources);
//! 3. the HTTP status the REST renderer answers for the same engine error.
//!
//! Plus the three properties the fix must not break: a genuine serialization abort stays retryable
//! **and a retry succeeds**; `TERMINATE TRANSACTIONS` keeps its exact code and message; and every
//! code Graphus emits survives the drivers' own parsers.
//!
//! # Non-vacuity
//!
//! Nothing here references the new `graphus_core::status` API, and every expected code is a literal
//! string. The file therefore **compiles unchanged against the pre-fix tree**, where
//! [`every_permanent_transaction_failure_is_announced_as_permanent`] fails on its first row
//! (`Neo.TransientError.Transaction.Outdated` != `Neo.ClientError.Statement.AccessMode`) — a genuine
//! assertion failure, not a build error.
//!
//! Each gate additionally proves it *reached* the condition it claims to test: the access-mode gates
//! run the identical `CREATE` in a WRITE transaction first and assert it succeeds, the stale-ticket
//! gates use a ticket that demonstrably worked before it was spent, and the serialization gate
//! asserts the retried transaction's write is readable afterwards.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use graphus_bolt::error::failure_from_error;
use graphus_bolt::executor::{AccessMode as BoltAccessMode, BoltExecutor, RecordStream, TxControl};
use graphus_core::GraphusError;
use graphus_rest::engine::{
    AccessMode as RestAccessMode, RestEngine, TxHandle, TxOrigin as RestOrigin,
};
use graphus_rest::problem::Problem;
use graphus_server::AuditConfig;
use graphus_server::admin::AdminContext;
use graphus_server::audit::{AuditLog, AuditSource};
use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, ServerConfig, TimingConfig, TlsConfig,
};
use graphus_server::dbcatalog::DatabaseCatalog;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{BoltEngineExecutor, EngineHandle, RestEngineAdapter};
use graphus_server::metrics::Metrics;
use graphus_server::security::SecurityCatalog;
use graphus_server::txn_registry::TransactionRegistry;

const JWT_SECRET: &str = "error-retryability-988-jwt-secret-min-32bytes!";
const ADMIN_USER: &str = "neo4j";
const DB: &str = "graphus";

// ---------------------------------------------------------------------------------------------
// The official drivers' retry rule, re-implemented from their sources
// ---------------------------------------------------------------------------------------------

/// The default `maxTransactionRetryTime` every official Neo4j driver ships — the budget a managed
/// transaction burns before giving up when the server keeps telling it "retryable".
///
/// Verified in all three reference drivers:
/// * Python `src/neo4j/_conf.py`: `max_transaction_retry_time = 30.0  # seconds`
/// * JavaScript `packages/core/src/internal/transaction-executor.ts`:
///   `const DEFAULT_MAX_RETRY_TIME_MS = 30 * 1000 // 30 seconds`
/// * Java `internal/retry/ExponentialBackoffRetryLogic.java`:
///   `public static final long DEFAULT_MAX_RETRY_TIME_MS = SECONDS.toMillis(30);`
const DRIVER_MAX_TRANSACTION_RETRY_TIME: Duration = Duration::from_secs(30);

/// The two codes the official drivers **rewrite** from `TransientError` to a non-retryable
/// `ClientError` before deciding — Neo4j's own "poison titles".
///
/// Python `src/neo4j/exceptions.py`, `ERROR_REWRITE_MAP`:
/// ```text
/// "Neo.TransientError.Transaction.Terminated":       (CLASSIFICATION_CLIENT, "Neo.ClientError.Transaction.Terminated"),
/// "Neo.TransientError.Transaction.LockClientStopped":(CLASSIFICATION_CLIENT, "Neo.ClientError.Transaction.LockClientStopped"),
/// ```
/// JavaScript `packages/bolt-connection/src/bolt/response-handler.js`, `_standardizeCode`, and Java
/// `internal/adaptedbolt/ErrorMapper.java` (`case "TransientError"`) implement the identical pair.
const DRIVER_POISON_TITLES: [&str; 2] = [
    "Neo.TransientError.Transaction.Terminated",
    "Neo.TransientError.Transaction.LockClientStopped",
];

/// The one code the drivers rewrite in the **opposite** direction — a `ClientError` they nevertheless
/// retry, after re-authenticating (Python `ERROR_REWRITE_MAP`; JavaScript `_isAuthorizationExpired`;
/// Java `AuthorizationExpiredException implements RetryableException`).
const DRIVER_RETRYABLE_CLIENT_ERROR: &str = "Neo.ClientError.Security.AuthorizationExpired";

/// **Does an official Neo4j driver retry a managed transaction that failed with this code?**
///
/// A faithful re-implementation of the rule the reference drivers apply, verified against source at
/// pinned commits (Python `5.0` @ `3badba6f`, JavaScript `5.0` @ `8b468788`, Java `5.0` @ `57bffc71`;
/// the current `6.x` branches are byte-identical bar a rename):
///
/// 1. `Neo.ClientError.Security.AuthorizationExpired` is retried (rewritten to transient).
/// 2. The two [`DRIVER_POISON_TITLES`] are rewritten to `ClientError` and are **not** retried, even
///    though the server sent them under `TransientError`.
/// 3. Otherwise the classification — the **second** dotted segment of
///    `Neo.<Classification>.<Category>.<Title>` — decides: `TransientError` retries, everything else
///    does not.
///
/// The driver implementations of step 3:
/// * Python `exceptions.py`: `_, classification, category, title = neo4j_code.split(".")` then
///   `_extract_error_class`, where `class TransientError(Neo4jError): _retryable = True` and the base
///   `Neo4jError._retryable = False`.
/// * Java `ErrorMapper.java`: `var parts = code.split("\\."); return parts[1];` dispatched by
///   `case "ClientError"` / `case "TransientError"`, where only `TransientException` implements the
///   marker interface `RetryableException`.
/// * JavaScript `packages/core/src/error.ts`: `_isTransientError` is
///   `code?.includes('TransientError')` — an *unanchored substring* test, which is why
///   [`no_client_error_code_can_be_misread_as_transient_by_the_javascript_driver`] exists.
///
/// Connectivity failures (`ServiceUnavailable` / `SessionExpired`) are also retryable, but they are
/// driver-side conditions with no server status code, so they are outside this function.
fn driver_is_retryable(code: &str) -> bool {
    if code == DRIVER_RETRYABLE_CLIENT_ERROR {
        return true;
    }
    if DRIVER_POISON_TITLES.contains(&code) {
        return false;
    }
    code.split('.').nth(1) == Some("TransientError")
}

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

/// A unique temp directory for the test's data root (auto-removed on drop).
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
        path.push(format!(
            "graphus-retryability-988-{tag}-{nanos}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A UDS-only config (no network listener) over the test's temp store.
fn config(temp: &TempStore) -> ServerConfig {
    ServerConfig {
        store_path: temp.path.join("store"),
        default_database: DB.to_owned(),
        buffer_pool_pages: 512,
        bolt_tcp_addr: None,
        advertised_bolt_address: None,
        bolt_server_agent: None,
        bolt_max_protocol_minor: None,
        rest_addr: None,
        uds_path: Some(temp.path.join("graphus.sock")),
        tls: TlsConfig::default(),
        admission: AdmissionConfig::default(),
        timing: TimingConfig::default(),
        jwt_secret: JWT_SECRET.to_owned(),
        auth: AuthBootstrap {
            admin_user: ADMIN_USER.to_owned(),
            admin_password: "retryability-988-pw8".to_owned(),
            admin_uid: None,
            users: Vec::new(),
        },
        encryption: graphus_server::config::EncryptionConfig::default(),
        audit: AuditConfig::default(),
        allow_insecure_network: false,
        bulk_import: graphus_server::config::BulkImportConfig::default(),
        metrics_scrape_token: None,
    }
}

/// One booted database, plus the real Bolt and REST seams built from ONE shared [`AdminContext`] —
/// exactly as a running server builds them.
struct Server {
    context: AdminContext,
    rest: RestEngineAdapter,
    engine: EngineHandle,
}

impl Server {
    async fn boot(temp: &TempStore) -> Self {
        let cfg = config(temp);
        let metrics = Arc::new(Metrics::new());
        let security = Arc::new(SecurityCatalog::load(&cfg).expect("load security catalog"));
        let audit = AuditLog::open(&cfg.audit, &cfg.store_path).expect("open audit log");
        let transactions = Arc::new(TransactionRegistry::new());
        let catalog = Arc::new(
            DatabaseCatalog::load(&cfg, Arc::clone(&metrics), Arc::clone(&transactions))
                .expect("load db catalog"),
        );
        let handle = catalog.start_default().await.expect("start default db");
        let context = AdminContext::new(
            catalog,
            security,
            audit,
            tokio::runtime::Handle::current(),
            handle.clone(),
            Arc::new(cfg),
            transactions,
        );
        let rest = RestEngineAdapter::new(context.clone());
        Self {
            context,
            rest,
            engine: handle,
        }
    }

    /// A fresh Bolt executor — one per "connection", as the accept loop builds it.
    fn bolt(&self) -> BoltEngineExecutor {
        let mut exec = BoltEngineExecutor::new(self.context.clone(), AuditSource::BoltUds);
        exec.set_principal(Some(ADMIN_USER));
        exec
    }

    fn rest_origin(&self) -> RestOrigin<'_> {
        RestOrigin {
            principal: ADMIN_USER,
            explicit: true,
        }
    }
}

/// Drains a Bolt record stream, returning the terminal error if the statement failed mid-stream.
///
/// A statement can fail either at submission (`run` returns `Err`) or as the stream's terminal item;
/// every gate here must accept both, because which one applies is an engine-dispatch detail, not part
/// of the contract under test.
fn drain(stream: Result<impl RecordStream, GraphusError>) -> Result<usize, GraphusError> {
    let mut stream = stream?;
    let mut rows = 0;
    while stream.next_record()?.is_some() {
        rows += 1;
    }
    Ok(rows)
}

/// The `(code, retryable, http_status)` triple a client observes for `error`, on both wires.
fn observed(error: &GraphusError) -> (String, bool, u16) {
    let code = failure_from_error(error).code;
    let retryable = driver_is_retryable(&code);
    let http = Problem::from_graphus_error(error).status;
    (code, retryable, http)
}

/// Records the full client-observable contract for one row of the table.
///
/// Deliberately **accumulating** rather than asserting: a table gate that panicked on its first bad
/// row would hide every other row, so a reader could not tell whether one site or ten were wrong —
/// and the non-vacuity run against the pre-fix tree could only ever demonstrate the first.
fn check(
    failures: &mut Vec<String>,
    error: &GraphusError,
    site: &str,
    expect_code: &str,
    expect_http: u16,
) {
    let (code, retryable, http) = observed(error);
    if code != expect_code {
        failures.push(format!(
            "{site}: Bolt FAILURE code is {code:?}, expected {expect_code:?} (message was: {error})"
        ));
    }
    if retryable {
        failures.push(format!(
            "{site}: a PERMANENT failure is announced as RETRYABLE ({code}), so the driver replays \
             it for the full {DRIVER_MAX_TRANSACTION_RETRY_TIME:?} and then reports a timeout \
             instead of the real cause — the whole of rmp #988"
        ));
    }
    if http != expect_http {
        failures.push(format!(
            "{site}: REST answers HTTP {http}, expected {expect_http}"
        ));
    }
}

// ---------------------------------------------------------------------------------------------
// 1. The table: every site that used to announce a permanent failure as retryable
// ---------------------------------------------------------------------------------------------

/// The table gate (`rmp` #988 acceptance criterion 1). Every row drives a **real** seam over a
/// **real** database and asserts the code, the drivers' retry answer, and the REST status.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_permanent_transaction_failure_is_announced_as_permanent() {
    let temp = TempStore::new("table");
    let server = Server::boot(&temp).await;

    // Every row's mismatches, reported together at the end.
    let mut failures: Vec<String> = Vec::new();

    // --- Non-vacuity control ------------------------------------------------------------------
    // The identical `CREATE` in a WRITE transaction succeeds. So the rows below fail because of the
    // condition each names, never because the statement, the seam or the database was broken.
    {
        let mut bolt = server.bolt();
        bolt.begin(BoltAccessMode::Write, Some(DB), None)
            .expect("a WRITE transaction opens");
        drain(bolt.run(
            "CREATE (:Control {v: 1})",
            vec![],
            TxControl::InExplicit { db: None },
        ))
        .expect("the control CREATE runs in a WRITE transaction");
        bolt.commit().expect("the control transaction commits");
    }

    // --- Row 1: a write statement inside an explicit READ transaction -------------------------
    // `engine/exec.rs` — the headline `session.executeRead` + `CREATE` reproduction.
    {
        let mut bolt = server.bolt();
        bolt.begin(BoltAccessMode::Read, Some(DB), None)
            .expect("a READ transaction opens");
        let err = drain(bolt.run("CREATE (:Nope)", vec![], TxControl::InExplicit { db: None }))
            .expect_err("a write in a READ transaction is refused");
        check(
            &mut failures,
            &err,
            "write statement in an explicit READ transaction (engine/exec.rs)",
            "Neo.ClientError.Statement.AccessMode",
            400,
        );
        let _ = bolt.rollback();
    }

    // --- Row 2: a write statement in a READ auto-commit ---------------------------------------
    // The same gate on the auto-commit path — the shape `session.executeRead` produces when the
    // driver sends a bare RUN rather than BEGIN/RUN/COMMIT.
    {
        let mut bolt = server.bolt();
        let err = drain(bolt.run(
            "CREATE (:Nope)",
            vec![],
            TxControl::AutoCommit {
                mode: BoltAccessMode::Read,
                db: Some(DB.to_owned()),
                timeout: None,
            },
        ))
        .expect_err("a write in a READ auto-commit is refused");
        check(
            &mut failures,
            &err,
            "write statement in a READ auto-commit (engine/exec.rs)",
            "Neo.ClientError.Statement.AccessMode",
            400,
        );
    }

    // --- Row 3: RUN against a ticket the engine no longer has ---------------------------------
    // `engine/exec.rs`. This is the ticket that is genuinely unknown — never opened, or already
    // committed or rolled back. A transaction the maximum-transaction-age sweep reaped is a
    // *different* answer (`TransactionTimedOut`: it existed, and here is why it is gone), pinned by
    // `a_transaction_reaped_for_age_says_it_timed_out_not_that_it_never_existed`.
    {
        let ticket = server
            .engine
            .begin_blocking(AccessMode::Write)
            .expect("begin a transaction directly on the engine");
        // Non-vacuity: the ticket demonstrably works BEFORE it is spent.
        server
            .engine
            .run_blocking(ticket, "RETURN 1".to_owned(), vec![], false, None, None)
            .expect("the live ticket runs a statement");
        server
            .engine
            .rollback_blocking(ticket)
            .expect("the ticket is spent by a rollback");

        let err = server
            .engine
            .run_blocking(ticket, "RETURN 1".to_owned(), vec![], false, None, None)
            .expect_err("a spent ticket cannot run a statement");
        check(
            &mut failures,
            &err,
            "RUN against an unknown transaction ticket (engine/exec.rs)",
            "Neo.ClientError.Transaction.TransactionNotFound",
            404,
        );
    }

    // --- Row 4: COMMIT against a ticket the engine no longer has ------------------------------
    // `engine/mod.rs::commit_prepare_tx` — the COMMIT twin of row 3.
    {
        let ticket = server
            .engine
            .begin_blocking(AccessMode::Write)
            .expect("begin a transaction directly on the engine");
        server
            .engine
            .rollback_blocking(ticket)
            .expect("the ticket is spent by a rollback");

        let err = server
            .engine
            .commit_blocking(ticket)
            .expect_err("a spent ticket cannot be committed");
        check(
            &mut failures,
            &err,
            "COMMIT of an unknown transaction ticket (engine/mod.rs)",
            "Neo.ClientError.Transaction.TransactionNotFound",
            404,
        );
    }

    // --- Row 5: RUN in an explicit transaction when none is open ------------------------------
    // `engine/seam_bolt.rs` — a Bolt state-machine violation.
    {
        let mut bolt = server.bolt();
        let err = drain(bolt.run("RETURN 1", vec![], TxControl::InExplicit { db: None }))
            .expect_err("RUN in an explicit transaction with none open is refused");
        check(
            &mut failures,
            &err,
            "RUN in an explicit transaction but none is open (engine/seam_bolt.rs)",
            "Neo.ClientError.Request.Invalid",
            400,
        );
    }

    // --- Row 6: BEGIN when a transaction is already open --------------------------------------
    {
        let mut bolt = server.bolt();
        bolt.begin(BoltAccessMode::Write, Some(DB), None)
            .expect("the first BEGIN opens a transaction");
        let err = bolt
            .begin(BoltAccessMode::Write, Some(DB), None)
            .expect_err("a second BEGIN is refused");
        check(
            &mut failures,
            &err,
            "BEGIN when a transaction is already open (engine/seam_bolt.rs)",
            "Neo.ClientError.Request.Invalid",
            400,
        );
        let _ = bolt.rollback();
    }

    // --- Row 7: COMMIT with no open transaction -----------------------------------------------
    {
        let mut bolt = server.bolt();
        let err = bolt
            .commit()
            .expect_err("COMMIT with no open transaction is refused");
        check(
            &mut failures,
            &err,
            "COMMIT with no open transaction (engine/seam_bolt.rs)",
            "Neo.ClientError.Request.Invalid",
            400,
        );
    }

    // --- Row 8: ROLLBACK with no open transaction ---------------------------------------------
    {
        let mut bolt = server.bolt();
        let err = bolt
            .rollback()
            .expect_err("ROLLBACK with no open transaction is refused");
        check(
            &mut failures,
            &err,
            "ROLLBACK with no open transaction (engine/seam_bolt.rs)",
            "Neo.ClientError.Request.Invalid",
            400,
        );
    }

    // --- Row 9: RUN against an unknown REST transaction handle --------------------------------
    // `engine/seam_rest.rs::lookup`.
    {
        // Non-vacuity: a real handle from the same seam demonstrably runs the same statement.
        let live = server
            .rest
            .begin(DB, RestAccessMode::Write, server.rest_origin())
            .expect("the REST seam opens a transaction");
        server
            .rest
            .run(live, "RETURN 1", vec![])
            .expect("the live handle runs a statement");
        server.rest.rollback(live).expect("roll the live one back");

        let err = server
            .rest
            .run(TxHandle(u64::MAX), "RETURN 1", vec![])
            .err()
            .expect("an unknown REST handle cannot run a statement");
        check(
            &mut failures,
            &err,
            "RUN against an unknown REST transaction handle (engine/seam_rest.rs)",
            "Neo.ClientError.Transaction.TransactionNotFound",
            404,
        );
    }

    // --- Row 10: COMMIT against an unknown REST transaction handle ----------------------------
    {
        let err = server
            .rest
            .commit(TxHandle(u64::MAX))
            .expect_err("an unknown REST handle cannot be committed");
        check(
            &mut failures,
            &err,
            "COMMIT of an unknown REST transaction handle (engine/seam_rest.rs)",
            "Neo.ClientError.Transaction.TransactionNotFound",
            404,
        );
    }

    assert!(
        failures.is_empty(),
        "{} of the table's rows announce a permanent failure incorrectly:\n  - {}",
        failures.len(),
        failures.join("\n  - ")
    );
}

/// An unavailable engine is the one condition in the table that is **genuinely** retryable — but it
/// is a *different* transient class from a serialization conflict, and it used to be indistinguishable
/// from one (`engine/handle.rs`, `rmp` #988).
///
/// It gets its own gate because reaching it means shutting the shared engine down, which no other row
/// could survive.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unavailable_engine_is_retryable_but_not_a_serialization_conflict() {
    let temp = TempStore::new("unavailable");
    let server = Server::boot(&temp).await;

    // Non-vacuity: the engine serves normally first, so the failure below is the shutdown and not a
    // database that never worked.
    server
        .engine
        .begin_blocking(AccessMode::Write)
        .and_then(|t| server.engine.rollback_blocking(t))
        .expect("the live engine serves a transaction");

    server.engine.shutdown().await.expect("engine shuts down");

    let err = server
        .engine
        .begin_blocking(AccessMode::Write)
        .expect_err("a shut-down engine cannot begin a transaction");

    let (code, retryable, http) = observed(&err);
    assert_eq!(
        code, "Neo.TransientError.General.DatabaseUnavailable",
        "an unavailable engine must say so, not borrow the serialization-conflict title \
         (message was: {err})"
    );
    assert!(
        retryable,
        "this one IS retryable — the fix must not make an unavailable engine permanent"
    );
    assert_eq!(http, 503, "REST: service unavailable, not 409 Conflict");

    // The point of the change: it is now distinguishable from a serialization abort, which is what a
    // routing driver needs in order to decide between replaying here and failing over.
    assert_ne!(code, "Neo.TransientError.Transaction.Outdated");
}

/// A transaction the **maximum-transaction-age sweep** stopped must say *that*, not "does not exist"
/// (`rmp` #988).
///
/// Both answers are permanent, non-retryable `ClientError`s, so the driver behaves identically — but
/// they are different **facts**, and the reference server keeps them apart on purpose. A reaped
/// transaction did exist and was killed for exceeding a configured bound; reporting it as
/// `TransactionNotFound` erases the only clue an operator has and sends them looking for a
/// transaction-lifecycle bug instead of reading `timing.max_transaction_age_ms`.
///
/// The reference server draws the same line, and by *who configured the bound*:
/// `TransactionTimedOut` for the server's own setting (this case) and
/// `TransactionTimedOutClientConfiguration` for a `tx_timeout` the client sent (already asserted in
/// `bolt_seam_tx_timeout_909.rs`). Graphus now emits the complete, symmetric pair.
///
/// Driven through the **real threaded engine** with a manually-advanced clock, so the sweep is
/// deterministic — no wall-clock, no flakiness.
#[test]
fn a_transaction_reaped_for_age_says_it_timed_out_not_that_it_never_existed() {
    use graphus_core::capability::Clock;
    use graphus_io::MemBlockDevice;
    use graphus_server::engine::{TxTicket, spawn_engine_with_timeout};
    use graphus_server::metrics::Metrics;
    use graphus_sim::SharedClock;
    use graphus_storage::RecordStore;
    use graphus_wal::{MemLogSink, WalManager};

    const MS: u64 = 1_000_000;
    const AGE_CAP: Duration = Duration::from_millis(300);

    let clock = SharedClock::new(0);
    let metrics = Arc::new(Metrics::new());
    let engine_clock: Arc<dyn Clock + Send + Sync> = Arc::new(clock.clone());
    let eng = spawn_engine_with_timeout::<MemBlockDevice, MemLogSink, _>(
        Arc::from("test"),
        || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            let store = RecordStore::create(device, wal, 8_192, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        4096,
        256,
        2,
        // One engine worker (`rmp` #1033).
        1,
        Arc::clone(&metrics),
        engine_clock,
        None,
        Some(AGE_CAP),
        None,
        Arc::new(graphus_server::txn_registry::TransactionRegistry::new()),
    )
    .expect("spawn threaded engine");
    let handle = eng.handle.clone();

    /// Wakes the engine loop (the reaper runs at the top of each tick) with an auto-commit write.
    fn wake(handle: &graphus_server::engine::EngineHandle) {
        let ticket = handle
            .begin_auto_commit_blocking(AccessMode::Write)
            .expect("begin auto-commit");
        let mut reply = handle
            .run_blocking(
                ticket,
                "CREATE (:Tick)".to_owned(),
                vec![],
                true,
                None,
                None,
            )
            .expect("auto-commit write runs");
        while reply.rows.next().expect("drain").is_some() {}
    }

    /// Runs a trivial statement inside `ticket` without finishing the transaction.
    fn touch(
        handle: &graphus_server::engine::EngineHandle,
        ticket: TxTicket,
    ) -> Result<(), GraphusError> {
        let mut reply =
            handle.run_blocking(ticket, "RETURN 1".to_owned(), vec![], false, None, None)?;
        while reply.rows.next()?.is_some() {}
        Ok(())
    }

    let victim = handle
        .begin_blocking(AccessMode::Write)
        .expect("open the explicit transaction the sweep will reap");

    // Non-vacuity: the transaction is alive and usable BEFORE the clock moves past the cap, so the
    // failure below is the reap and not a transaction that never worked.
    clock.set(100 * MS);
    wake(&handle);
    touch(&handle, victim).expect("the young transaction is alive and usable");

    // Now push the clock past the cap and wake the loop so the sweep runs.
    clock.set(400 * MS);
    wake(&handle);

    let err = touch(&handle, victim).expect_err("the over-age transaction must have been reaped");
    assert_contract_timed_out(&err, "RUN after the age sweep reaped the transaction");

    // The COMMIT path answers identically — it is a separate unknown-ticket site (`engine/mod.rs`).
    let second = handle
        .begin_blocking(AccessMode::Write)
        .expect("open a second victim");
    touch(&handle, second).expect("the second victim is alive before the sweep");
    clock.set(1_000 * MS);
    wake(&handle);
    let err = handle
        .commit_blocking(second)
        .expect_err("the over-age transaction must have been reaped");
    assert_contract_timed_out(&err, "COMMIT after the age sweep reaped the transaction");

    // A ticket that was NEVER issued keeps saying exactly that — the reap ledger must not smear
    // "timed out" over every unknown id, or the distinction it exists for would be worthless.
    let never_issued = TxTicket(u64::MAX);
    let err = handle
        .commit_blocking(never_issued)
        .expect_err("a ticket that was never issued cannot be committed");
    let (code, retryable, http) = observed(&err);
    assert_eq!(
        code, "Neo.ClientError.Transaction.TransactionNotFound",
        "an id that never existed must NOT be reported as a timeout (message was: {err})"
    );
    assert!(!retryable);
    assert_eq!(http, 404);

    // And the record is consumed: asking a second time about the same reaped ticket degrades to the
    // generic answer rather than re-reporting a timeout forever.
    let err = handle
        .commit_blocking(victim)
        .expect_err("the reaped ticket is still gone");
    assert_eq!(
        observed(&err).0,
        "Neo.ClientError.Transaction.TransactionNotFound",
        "the reap record is delivered once, to the owner asking first (message was: {err})"
    );

    // Dropping both handles closes the command channel, so the engine thread exits and joins.
    let graphus_server::engine::Engine {
        handle: inner,
        joins,
    } = eng;
    drop(handle);
    drop(inner);
    for join in joins {
        join.join().expect("engine worker joins cleanly");
    }
}

/// Asserts the full client-observable contract for a transaction stopped by the **server-configured**
/// maximum age.
#[track_caller]
fn assert_contract_timed_out(error: &GraphusError, site: &str) {
    let (code, retryable, http) = observed(error);
    assert_eq!(
        code, "Neo.ClientError.Transaction.TransactionTimedOut",
        "{site}: the client must learn its transaction TIMED OUT, not that it never existed \
         (message was: {error})"
    );
    assert!(
        !retryable,
        "{site}: both of the reference server's transaction timeouts are ClientError — replaying a \
         unit of work that ran past the bound would simply run past it again"
    );
    assert_eq!(http, 400, "{site}: REST status for a client-fault timeout");
    // The pair must stay distinct: this is the SERVER's bound, not the client's `tx_timeout`.
    assert_ne!(
        code, "Neo.ClientError.Transaction.TransactionTimedOutClientConfiguration",
        "{site}: the server-configured and client-configured timeouts must not collapse into one"
    );
}

// ---------------------------------------------------------------------------------------------
// 2. The reproduction: a write inside a READ transaction fails IMMEDIATELY
// ---------------------------------------------------------------------------------------------

/// **The `rmp` #988 reproduction, at the wire level** (acceptance criterion 2).
///
/// A write inside a READ transaction — what `session.executeRead(tx => tx.run("CREATE …"))` sends —
/// must fail *immediately*, not after the driver has spent its whole
/// [`DRIVER_MAX_TRANSACTION_RETRY_TIME`].
///
/// The real driver cannot run in the hermetic test suite (it needs Node/Python/Go toolchains and a
/// network), so this gate does what the task allows: it drives the real Bolt seam and applies the
/// drivers' own retry rule ([`driver_is_retryable`], re-implemented from the pinned driver sources)
/// to the code the server actually sent. The `neo4j-interop` feature carries the same scenario
/// against the genuine `neo4j-driver`.
///
/// Two independent things are asserted, because either alone is insufficient:
///
/// * the driver's rule says **do not retry** — so the 30 s loop is never entered; and
/// * the server answered in a small fraction of that budget — so a *future* regression that made the
///   server itself block cannot pass while the classification happens to be right.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_inside_a_read_transaction_fails_immediately_and_is_never_retried() {
    let temp = TempStore::new("executeread");
    let server = Server::boot(&temp).await;
    let mut bolt = server.bolt();

    // Non-vacuity: the very same statement, in the very same session, succeeds under WRITE access —
    // so the failure below is the access mode and nothing else.
    bolt.begin(BoltAccessMode::Write, Some(DB), None)
        .expect("a WRITE transaction opens");
    drain(bolt.run(
        "CREATE (:Proof {v: 1})",
        vec![],
        TxControl::InExplicit { db: None },
    ))
    .expect("the identical CREATE succeeds under WRITE access");
    bolt.commit().expect("and commits");

    // The reproduction: `session.executeRead` opens `BEGIN {mode: "r"}` and runs the statement in it.
    let started = Instant::now();
    bolt.begin(BoltAccessMode::Read, Some(DB), None)
        .expect("a READ transaction opens");
    let err = drain(bolt.run(
        "CREATE (:Proof {v: 2})",
        vec![],
        TxControl::InExplicit { db: None },
    ))
    .expect_err("a write in a READ transaction must be refused");
    let elapsed = started.elapsed();
    let _ = bolt.rollback();

    let failure = failure_from_error(&err);
    assert_eq!(
        failure.code, "Neo.ClientError.Statement.AccessMode",
        "the client must be told WHY (message was: {err})"
    );
    assert!(
        !driver_is_retryable(&failure.code),
        "the official drivers must classify {} as non-retryable, so `executeRead` raises at once \
         instead of replaying for {DRIVER_MAX_TRANSACTION_RETRY_TIME:?}",
        failure.code
    );

    // "Immediately": comfortably inside a tenth of the driver's retry budget. Generous enough never to
    // flake on a loaded runner, and still two orders of magnitude away from the 30 s the defect cost.
    let ceiling = DRIVER_MAX_TRANSACTION_RETRY_TIME / 10;
    assert!(
        elapsed < ceiling,
        "the refusal took {elapsed:?}, which is not 'immediate' against a \
         {DRIVER_MAX_TRANSACTION_RETRY_TIME:?} retry budget (ceiling {ceiling:?})"
    );

    // And the defect's signature is gone: the driver is no longer told to come back later.
    assert!(
        !failure.code.contains("TransientError"),
        "a permanent access-mode violation must not carry ANY transient marker: {}",
        failure.code
    );
}

// ---------------------------------------------------------------------------------------------
// 3. A genuine serialization abort is still retryable, and the retry succeeds
// ---------------------------------------------------------------------------------------------

/// **The property the fix must not break** (acceptance criterion 3): a genuine SSI serialization
/// abort stays a retryable `TransientError`, and replaying the unit of work — which is exactly what
/// the drivers' managed-transaction loop does — **succeeds**.
///
/// Under MVCC this is the normal, expected outcome of contention, and it becomes *more* frequent as
/// multi-writer lands. A fix that made permanent errors permanent by also making conflicts permanent
/// would be worse than the defect.
///
/// The scenario is the classic SSI write-skew: two transactions each read one label and write the
/// other, forming the dangerous structure; the pivot aborts at commit.
#[test]
fn a_serialization_abort_stays_retryable_and_the_retry_succeeds() {
    use graphus_core::capability::Clock;
    use graphus_io::MemBlockDevice;
    use graphus_server::engine::LocalEngine;
    use graphus_sim::SharedClock;
    use graphus_wal::MemLogSink;

    type Eng = LocalEngine<MemBlockDevice, MemLogSink>;

    /// Runs one statement to completion inside `ticket`, returning the terminal error if any.
    fn run_in(
        eng: &mut Eng,
        ticket: graphus_server::engine::TxTicket,
        stmt: &str,
    ) -> Result<(), GraphusError> {
        let mut reply = eng.run(ticket, stmt, vec![], false, None)?;
        while reply.rows.next()?.is_some() {}
        Ok(())
    }

    let clock = SharedClock::new(0);
    let mut eng: Eng = LocalEngine::in_memory(Arc::new(clock) as Arc<dyn Clock + Send + Sync>, 256)
        .expect("build in-memory engine");

    // Seed the two nodes the write-skew reads and writes.
    let seed = eng.begin(AccessMode::Write).expect("begin seed");
    run_in(&mut eng, seed, "CREATE (:A {v: 1}), (:B {v: 1})").expect("seed runs");
    eng.commit(seed).expect("seed commits");

    // T1 reads label A and writes it; left open so it overlaps T2.
    let t1 = eng.begin(AccessMode::Write).expect("begin t1");
    run_in(&mut eng, t1, "MATCH (a:A) SET a.v = 10").expect("t1 statement runs");

    // T2 is the symmetric partner: reads label B and writes it. Together they are the SSI dangerous
    // structure, and the pivot aborts at commit.
    let t2 = eng.begin(AccessMode::Write).expect("begin t2");
    run_in(&mut eng, t2, "MATCH (b:B) SET b.v = 20").expect("t2 statement runs");

    // Whichever of the two the coordinator picks as the pivot, the abort is what we assert on.
    let first = eng.commit(t1);
    let second = eng.commit(t2);
    let abort = match (first, second) {
        (Err(e), _) => e,
        (_, Err(e)) => e,
        (Ok(_), Ok(_)) => panic!(
            "NON-VACUITY FAILURE: the write-skew did not produce a serialization abort, so this \
             gate would prove nothing about retryability"
        ),
    };

    let failure = failure_from_error(&abort);
    assert_eq!(
        failure.code, "Neo.TransientError.Transaction.Outdated",
        "a genuine serialization abort keeps the retryable title (message was: {abort})"
    );
    assert!(
        driver_is_retryable(&failure.code),
        "the official drivers MUST retry {} — under MVCC this is the normal outcome of contention, \
         and a driver that cannot retry it cannot use the database under load",
        failure.code
    );
    // Regression guard (`rmp` #612): the title must stay off the drivers' rewrite map, which would
    // silently turn it into a non-retryable ClientError.
    assert!(
        !DRIVER_POISON_TITLES.contains(&failure.code.as_str()),
        "poison title breaks managed retry: {}",
        failure.code
    );
    // REST answers the retryable conflict with 409, unchanged.
    assert_eq!(Problem::from_graphus_error(&abort).status, 409);

    // The whole point of "retryable": replaying the unit of work succeeds. This is what the drivers'
    // managed-transaction loop does, and it is the half a classification assertion alone cannot prove.
    let retry = eng.begin(AccessMode::Write).expect("begin the retry");
    run_in(&mut eng, retry, "MATCH (b:B) SET b.v = 20").expect("the retried statement runs");
    eng.commit(retry)
        .expect("the RETRY COMMITS — this is why the abort is announced as retryable");

    // And the retried write is really there.
    let probe = eng
        .begin_auto_commit(AccessMode::Read)
        .expect("begin probe");
    let mut reply = eng
        .run(probe, "MATCH (b:B) RETURN b.v AS v", vec![], true, None)
        .expect("probe runs");
    let mut seen = Vec::new();
    while let Some(row) = reply.rows.next().expect("drain probe") {
        seen.push(format!("{row:?}"));
    }
    assert_eq!(seen.len(), 1, "exactly one :B node");
    assert!(
        seen[0].contains("20"),
        "the retried transaction's write must be durable: {seen:?}"
    );

    let _ = eng.shutdown();
}

// ---------------------------------------------------------------------------------------------
// 4. TERMINATE TRANSACTIONS is untouched
// ---------------------------------------------------------------------------------------------

/// **Acceptance criterion 4**: `TERMINATE TRANSACTIONS` (`rmp` #637) keeps the exact code *and* the
/// exact message it had, and stays non-retryable.
///
/// It is a deliberate operator kill, so a driver must not quietly resurrect the work by retrying it —
/// and `docs/transactions.md` publishes both strings, so neither may drift.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn terminate_transactions_keeps_its_exact_code_and_message_and_is_not_retryable() {
    let temp = TempStore::new("terminate");
    let server = Server::boot(&temp).await;

    let mut victim = server.bolt();
    victim
        .begin(BoltAccessMode::Write, Some(DB), None)
        .expect("the victim transaction opens");
    // Non-vacuity: it is live and usable before it is terminated.
    drain(victim.run(
        "CREATE (:Victim)",
        vec![],
        TxControl::InExplicit { db: None },
    ))
    .expect("the victim runs a statement while live");

    // Terminate it through the registry — the same object `TERMINATE TRANSACTIONS` reaches.
    let ids: Vec<String> = server
        .context
        .transactions()
        .snapshot()
        .into_iter()
        .map(|t| t.id)
        .collect();
    assert!(
        !ids.is_empty(),
        "NON-VACUITY FAILURE: the victim transaction was not in the live registry, so nothing was \
         terminated"
    );
    let terminated = server.context.transactions().terminate(&ids);
    assert_eq!(
        terminated.len(),
        ids.len(),
        "NON-VACUITY FAILURE: TERMINATE did not report every requested transaction as stopped"
    );

    let err = victim
        .commit()
        .expect_err("a terminated transaction must not commit");

    // Byte-for-byte, the contract `docs/transactions.md` publishes.
    let failure = failure_from_error(&err);
    assert_eq!(failure.code, "Neo.ClientError.Statement.ArgumentError");
    assert_eq!(
        failure.message,
        "the transaction has been terminated by an administrator (TERMINATE TRANSACTIONS)"
    );
    assert!(
        !driver_is_retryable(&failure.code),
        "an operator kill must not be silently retried by the driver"
    );
    assert_eq!(Problem::from_graphus_error(&err).status, 400);
}

// ---------------------------------------------------------------------------------------------
// 5. Every code Graphus emits survives the drivers' own parsers
// ---------------------------------------------------------------------------------------------

/// The status codes this task introduced or preserved, as literal strings.
const EMITTED_CODES: [&str; 8] = [
    "Neo.ClientError.Statement.AccessMode",
    "Neo.ClientError.Transaction.TransactionNotFound",
    "Neo.ClientError.Transaction.TransactionTimedOut",
    "Neo.ClientError.Request.Invalid",
    "Neo.ClientError.Statement.ArgumentError",
    "Neo.TransientError.General.DatabaseUnavailable",
    "Neo.TransientError.Transaction.Outdated",
    "Neo.ClientError.Transaction.TransactionTimedOutClientConfiguration",
];

/// The Python driver destructures a status code with an **exact-arity** four-way split:
///
/// ```python
/// try:
///     _, classification, category, title = neo4j_code.split(".")
/// except ValueError:
///     classification = CLASSIFICATION_DATABASE   # -> DatabaseError, NON-retryable
/// ```
///
/// A code with any other number of dotted segments raises `ValueError` and is silently reclassified as
/// `DatabaseError` — so a three- or five-segment code would make even a genuine serialization abort
/// **non-retryable**, invisibly. Every code Graphus emits must therefore have exactly four segments.
#[test]
fn every_emitted_code_has_the_four_segments_the_python_driver_requires() {
    for code in EMITTED_CODES {
        let segments: Vec<&str> = code.split('.').collect();
        assert_eq!(
            segments.len(),
            4,
            "{code} would raise ValueError in the Python driver's `neo4j_code.split('.')` \
             destructuring and be silently downgraded to a non-retryable DatabaseError"
        );
        assert_eq!(segments[0], "Neo", "{code} must be in the Neo namespace");
        assert!(
            matches!(
                segments[1],
                "ClientError" | "TransientError" | "DatabaseError"
            ),
            "{code} has an unknown classification segment {:?}, which the drivers map to the \
             non-retryable default",
            segments[1]
        );
    }
}

/// The JavaScript driver does **not** extract the classification segment — it tests the whole code
/// string for a substring:
///
/// ```javascript
/// function _isTransientError (code) {
///   return code?.includes('TransientError') === true
/// }
/// ```
///
/// So a `ClientError` code that merely *contained* "TransientError" anywhere (a category or title
/// named that way) would be retried forever by the JS driver while Python and Java refused to retry
/// it — the exact split-brain this whole task exists to prevent. This gate pins that none of our
/// permanent codes can be misread that way.
#[test]
fn no_client_error_code_can_be_misread_as_transient_by_the_javascript_driver() {
    for code in EMITTED_CODES {
        let is_client_error = code.starts_with("Neo.ClientError.");
        let js_sees_transient = code.contains("TransientError");
        assert!(
            !(is_client_error && js_sees_transient),
            "{code} is a ClientError, but the JavaScript driver's unanchored \
             `code.includes('TransientError')` test would retry it"
        );
        // ... and the converse: a code we mean to be retryable must actually contain the marker, or
        // the JS driver would refuse to retry it while Python and Java did.
        if code.starts_with("Neo.TransientError.") {
            assert!(
                js_sees_transient,
                "{code} is meant to be retryable but the JS driver would not see it as transient"
            );
        }
    }
}

/// The three drivers must agree on **every** code Graphus emits.
///
/// Python reads segment 1 of a 4-way split; Java reads `code.split("\\.")[1]`; JavaScript does a
/// substring test. Those are three different algorithms, and they only agree because our codes are
/// well-formed. This gate cross-checks all three against each other, so a future code that made them
/// disagree fails here rather than in production against one ecosystem only.
#[test]
fn the_three_official_drivers_agree_on_every_code_graphus_emits() {
    for code in EMITTED_CODES {
        // Python / Java: the second dotted segment (both reject the poison titles first).
        let poisoned = DRIVER_POISON_TITLES.contains(&code);
        let segment_says_transient = !poisoned && code.split('.').nth(1) == Some("TransientError");
        // JavaScript: an unanchored substring test, likewise after its `_standardizeCode` rewrite.
        let js_says_transient = !poisoned && code.contains("TransientError");
        assert_eq!(
            segment_says_transient, js_says_transient,
            "{code} splits the ecosystem: segment-based drivers (Python, Java) say \
             retryable={segment_says_transient} while the JavaScript substring test says \
             retryable={js_says_transient}"
        );
        assert_eq!(
            driver_is_retryable(code),
            segment_says_transient,
            "{code}: this test's model of the rule disagrees with the drivers' own algorithm"
        );
    }
}
