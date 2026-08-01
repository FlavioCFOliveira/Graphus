//! **`tx_timeout` on `BEGIN` bounds the whole transaction, and a late `COMMIT` is refused**
//! (`rmp` task #909).
//!
//! Bolt's `tx_timeout` bounds *the transaction*, not each statement in it: a client that sets one
//! second and then runs ten statements has asked for one second in total. That distinction lives in
//! the Bolt seam ([`BoltEngineExecutor`]), which fixes an absolute deadline at `BEGIN` and measures
//! every later message against what is left of it.
//!
//! The per-*statement* half of the contract — the downward clamp against the operator's configured
//! `statement_timeout_ms`, observed firing — is asserted in `bolt_tx_timeout_909.rs` against the raw
//! threaded engine. This file drives the **real seam** over a **real database**, the same object one
//! Bolt connection owns, and asserts the two things only the seam can answer:
//!
//! 1. [`a_statement_after_the_transaction_budget_is_refused`] — once the budget is spent, the next
//!    statement fails immediately rather than being handed a fresh copy of the client's figure. A
//!    per-statement reading of the field would let a client hold a transaction open forever by
//!    running one cheap statement after another, which is precisely the GC-watermark pin the bound
//!    exists to prevent.
//! 2. [`a_commit_after_the_transaction_budget_is_refused_and_nothing_is_applied`] — the load-bearing
//!    ACID property: a transaction that outlived its budget must not commit, and must leave **no**
//!    half-applied state. This is also the only place the bound is observable when the transaction
//!    spent its time *between* statements rather than inside one.
//!
//! Both assert the error a driver actually receives, not just that something failed: the FAILURE code
//! must be Neo4j's `TransactionTimedOutClientConfiguration` — the title the reference server reserves
//! for a bound the *client* configured — and it must be a non-retryable `ClientError`, because
//! replaying a transaction that ran out of its own budget would simply run out again.
//!
//! # Non-vacuity
//!
//! Every gate runs the identical sequence under a **generous** budget first and asserts it succeeds
//! (the statement runs, the commit lands, the write is readable). A gate can therefore not pass by
//! never getting far enough to matter, nor by a bug that failed every transaction.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use graphus_bolt::error::failure_from_error;
use graphus_bolt::executor::{AccessMode as BoltAccessMode, BoltExecutor, RecordStream, TxControl};
use graphus_core::{GraphusError, Value};
use graphus_server::AuditConfig;
use graphus_server::admin::AdminContext;
use graphus_server::audit::{AuditLog, AuditSource};
use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, ServerConfig, TimingConfig, TlsConfig,
};
use graphus_server::dbcatalog::DatabaseCatalog;
use graphus_server::engine::BoltEngineExecutor;
use graphus_server::metrics::Metrics;
use graphus_server::security::SecurityCatalog;
use graphus_server::txn_registry::TransactionRegistry;

const JWT_SECRET: &str = "bolt-tx-timeout-909-jwt-secret-min-32bytes!";
const ADMIN_USER: &str = "neo4j";
const DB: &str = "graphus";

/// The Neo4j leaf status code a client-configured transaction timeout must surface as. Spelled out
/// literally (not imported) so a change to this wire contract has to be made twice, on purpose.
const CLIENT_TIMEOUT_CODE: &str =
    "Neo.ClientError.Transaction.TransactionTimedOutClientConfiguration";

/// The client's budget in the "expired" gates: short enough to spend deliberately in a test.
const TIGHT_BUDGET: Duration = Duration::from_millis(300);

/// How long the test waits after `BEGIN` to be certain `TIGHT_BUDGET` is spent. Comfortably past it,
/// so the gate never flakes on a loaded runner.
const OVERSHOOT: Duration = Duration::from_millis(900);

/// The control budget: far beyond anything these gates take, so the identical sequence succeeds.
const GENEROUS_BUDGET: Duration = Duration::from_secs(300);

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
            "graphus-tx-timeout-909-{tag}-{nanos}-{}",
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

/// A UDS-only config over the test's temp store. The operator's per-statement timeout is left at its
/// shipped default, so nothing here can pass because the *server's* budget happened to fire.
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
            admin_password: "tx-timeout-909-pw8".to_owned(),
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

/// One booted database plus the shared context a Bolt connection's executor is built from.
struct Server {
    context: AdminContext,
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
            handle,
            Arc::new(cfg),
            transactions,
        );
        Self { context }
    }

    /// A fresh executor — one per "connection", as the accept loop builds it — as the admin principal.
    fn bolt(&self) -> BoltEngineExecutor {
        let mut exec = BoltEngineExecutor::new(self.context.clone(), AuditSource::BoltUds);
        exec.set_principal(Some(ADMIN_USER));
        exec
    }
}

/// Drives an auto-commit statement to completion, returning the single scalar cell of its last row.
fn scalar(exec: &mut BoltEngineExecutor, query: &str) -> Value {
    let mut stream = exec
        .run(
            query,
            vec![],
            TxControl::AutoCommit {
                mode: BoltAccessMode::Read,
                db: Some(DB.to_owned()),
                timeout: None,
            },
        )
        .expect("auto-commit read runs");
    let mut last = Value::Null;
    while let Some(row) = stream.next_record().expect("row") {
        if let Some(graphus_bolt::packstream::BoltValue::Value(v)) = row.into_iter().next() {
            last = v;
        }
    }
    last
}

/// Asserts `error` is the client-configured transaction timeout, as a driver would see it.
fn assert_client_timeout(error: &GraphusError, what: &str) {
    let failure = failure_from_error(error);
    assert_eq!(
        failure.code, CLIENT_TIMEOUT_CODE,
        "{what}: the client must be able to tell its own timeout from any other failure \
         (got {failure:?})"
    );
    // The classification a driver acts on: `ClientError` is non-retryable, which is right — replaying
    // a transaction that exhausted its own budget would exhaust it again. A `TransientError` here
    // would make the official drivers' managed-transaction retry burn its whole budget on it.
    assert!(
        failure.code.starts_with("Neo.ClientError."),
        "{what}: must be a non-retryable ClientError (got {})",
        failure.code
    );
}

/// The number of `:Applied` nodes committed to the database — the visible effect the ACID gate turns on.
fn applied_count(exec: &mut BoltEngineExecutor) -> i64 {
    match scalar(exec, "MATCH (n:Applied) RETURN count(n) AS c") {
        Value::Integer(n) => n,
        other => panic!("count returned {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_statement_after_the_transaction_budget_is_refused() {
    let temp = TempStore::new("stmt");
    let server = Server::boot(&temp).await;

    tokio::task::spawn_blocking(move || {
        // CONTROL first: the identical sequence under a generous budget succeeds, so the gate below
        // cannot pass by the transaction never having worked at all.
        let mut exec = server.bolt();
        exec.begin(BoltAccessMode::Write, Some(DB), Some(GENEROUS_BUDGET))
            .expect("BEGIN with a generous budget");
        std::thread::sleep(OVERSHOOT);
        let mut stream = exec
            .run("RETURN 1 AS x", vec![], TxControl::InExplicit { db: None })
            .expect("CONTROL: a statement is servable after the same wait under a generous budget");
        while stream.next_record().expect("row").is_some() {}
        drop(stream);
        exec.rollback().expect("CONTROL: rollback");

        // THE GATE: the same wait, under a budget that expires during it.
        let mut exec = server.bolt();
        exec.begin(BoltAccessMode::Write, Some(DB), Some(TIGHT_BUDGET))
            .expect("BEGIN with a tight budget");
        std::thread::sleep(OVERSHOOT);
        let error = exec
            .run("RETURN 1 AS x", vec![], TxControl::InExplicit { db: None })
            .err()
            .expect("a statement after the transaction budget must be refused");
        assert_client_timeout(&error, "RUN after the budget");
    })
    .await
    .expect("blocking task joins");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_commit_after_the_transaction_budget_is_refused_and_nothing_is_applied() {
    let temp = TempStore::new("commit");
    let server = Server::boot(&temp).await;

    tokio::task::spawn_blocking(move || {
        let mut probe = server.bolt();
        assert_eq!(applied_count(&mut probe), 0, "the database starts empty");

        // CONTROL: the identical write + wait + COMMIT under a generous budget DOES commit, and the
        // write is readable afterwards. Without this the gate below could pass on a server that
        // simply never commits anything.
        let mut exec = server.bolt();
        exec.begin(BoltAccessMode::Write, Some(DB), Some(GENEROUS_BUDGET))
            .expect("BEGIN with a generous budget");
        let mut stream = exec
            .run(
                "CREATE (:Applied {tag: 'control'})",
                vec![],
                TxControl::InExplicit { db: None },
            )
            .expect("CONTROL: the write runs");
        while stream.next_record().expect("row").is_some() {}
        drop(stream);
        std::thread::sleep(OVERSHOOT);
        exec.commit()
            .expect("CONTROL: a commit within the budget succeeds");
        assert_eq!(
            applied_count(&mut probe),
            1,
            "CONTROL: the committed write is visible"
        );

        // THE GATE: the same write, the same wait, but a budget that expires before the COMMIT.
        let mut exec = server.bolt();
        exec.begin(BoltAccessMode::Write, Some(DB), Some(TIGHT_BUDGET))
            .expect("BEGIN with a tight budget");
        let mut stream = exec
            .run(
                "CREATE (:Applied {tag: 'expired'})",
                vec![],
                TxControl::InExplicit { db: None },
            )
            .expect("the write runs — the budget has not expired yet");
        while stream.next_record().expect("row").is_some() {}
        drop(stream);
        std::thread::sleep(OVERSHOOT);

        let error = exec
            .commit()
            .expect_err("a COMMIT after the transaction budget must be refused");
        assert_client_timeout(&error, "COMMIT after the budget");

        // The ACID property: the refused transaction left NOTHING behind. Still exactly the one node
        // the control committed — the expired transaction's write was rolled back, not half-applied.
        assert_eq!(
            applied_count(&mut probe),
            1,
            "the timed-out transaction must leave no half-applied state"
        );

        // And the connection is reusable: the refusal closed the transaction rather than wedging it.
        exec.begin(BoltAccessMode::Write, Some(DB), None)
            .expect("a new transaction opens after a refused COMMIT");
        exec.rollback().expect("and rolls back cleanly");
    })
    .await
    .expect("blocking task joins");
}
