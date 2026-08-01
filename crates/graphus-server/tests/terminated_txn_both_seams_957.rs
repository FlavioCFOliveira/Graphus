//! **A terminated transaction must not commit — on either interface** (`rmp` task #957).
//!
//! `TERMINATE TRANSACTIONS` (`rmp` #637) reported success while the REST commit path went on to
//! commit: `RestEngineAdapter::commit` reached the engine with **no** termination check at all, unlike
//! the Bolt seam's `COMMIT`, which had one. An operator who kills a transaction and is told it was
//! stopped has no reason to look again, so a silent commit afterwards is worse than a `TERMINATE` that
//! refuses outright — the operator is left believing something that is not true.
//!
//! These gates drive the **real** stacks, side by side, over one shared server:
//!
//! * the production `graphus_rest` axum [`Router`] over the real [`RestEngineAdapter`], driven
//!   in-process by `tower::ServiceExt::oneshot` (no socket, no TLS — the hard rule);
//! * a real [`BoltEngineExecutor`], the same object one Bolt connection owns, driven through the
//!   [`BoltExecutor`] seam its session loop calls;
//!
//! both built from **one** [`AdminContext`], so they share one engine, one database, and — the point
//! of the exercise — one [`TransactionRegistry`], exactly as a running server does. Termination is
//! applied through that registry, the same object `TERMINATE TRANSACTIONS` reaches.
//!
//! # What is asserted
//!
//! 1. The three-step reproduction (begin → statement → terminate → commit) ends **rolled back**: the
//!    commit is refused and the statement's write is not in the database afterwards.
//! 2. The two interfaces answer with the **same error shape** — byte-identical message and identical
//!    Neo status code — because `Problem::from_graphus_error` and `graphus_bolt::failure_from_error`
//!    are both fed the one `terminated_error()` the shared guard returns.
//! 3. Every resumption point agrees across the interfaces: the next statement is refused on both, and
//!    a rollback still **succeeds** on both (rolling a terminated transaction back is what the operator
//!    asked for — refusing it would leave the client no way to discard it).
//! 4. A terminated `CREATE CONSTRAINT` (`rmp` task #903) is honoured identically over both interfaces.
//!
//! # Non-vacuity
//!
//! Every gate below opens a transaction, runs a statement in it, and asserts the LIVE behaviour first
//! (the statement runs, the commit path is reachable) before termination is applied — so a gate cannot
//! pass by never getting far enough to matter. The commit gates additionally assert the *absence* of
//! the write, which is the property the defect violated.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value as Json, json};
use tower::ServiceExt;

use graphus_auth::AuthProvider;
use graphus_bolt::executor::{AccessMode as BoltAccessMode, BoltExecutor, RecordStream, TxControl};
use graphus_core::capability::Clock;
use graphus_rest::registry::TxRegistry;
use graphus_rest::router::{AppState, DEFAULT_TX_TTL_NANOS, router};
use graphus_server::AuditConfig;
use graphus_server::admin::AdminContext;
use graphus_server::audit::{AuditLog, AuditSource};
use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, ServerConfig, TimingConfig, TlsConfig,
};
use graphus_server::dbcatalog::DatabaseCatalog;
use graphus_server::engine::command::{AccessMode, ConstraintCommand, ConstraintTypeFilter};
use graphus_server::engine::{BoltEngineExecutor, EngineHandle, RestEngineAdapter};
use graphus_server::metrics::Metrics;
use graphus_server::security::{LiveAuth, SecurityCatalog};
use graphus_server::txn_registry::TransactionRegistry;

const JWT_SECRET: &str = "terminated-txn-957-jwt-secret-min-32bytes!";
const ADMIN_USER: &str = "neo4j";
const DB: &str = "graphus";
const FIXED_SECS: u64 = 1_700_000_000;
const FIXED_NANOS: u64 = FIXED_SECS * 1_000_000_000;

/// How long a poller waits for the constraint DDL's internal registry entry to appear. Generous: the
/// assertion it guards is "the entry was addressable", and a machine slow enough to need more than this
/// is one where the DDL is slower still.
const APPEAR_TIMEOUT: Duration = Duration::from_secs(30);

/// Nodes seeded under the covered label for the constraint-DDL gate. Sized as in `rmp` task #903's own
/// gate, so the (now linear — `rmp` #956) uniqueness walk runs long enough that a concurrent operator
/// polling every millisecond reliably reaches it.
const SEEDED_NODES: usize = 20_000;

/// A `Clock` pinned to a fixed instant so the minted token's `exp` and the router's validation clock
/// agree deterministically (no wall-clock flakiness).
struct FixedClock(AtomicU64);
impl Clock for FixedClock {
    fn now_nanos(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

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
            "graphus-terminated-957-{tag}-{nanos}-{}",
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
        timing: TimingConfig {
            slow_query_threshold_ms: 1_000,
            shutdown_drain_deadline_ms: 5_000,
            ..TimingConfig::default()
        },
        jwt_secret: JWT_SECRET.to_owned(),
        auth: AuthBootstrap {
            admin_user: ADMIN_USER.to_owned(),
            admin_password: "terminated-957-pw8".to_owned(),
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

/// One server, two seams: the real REST router and a real Bolt executor over the SAME
/// [`AdminContext`], and therefore the same engine, database and live-transaction registry.
struct Server {
    rest: Router,
    token: String,
    context: AdminContext,
    transactions: Arc<TransactionRegistry>,
    handle: EngineHandle,
}

impl Server {
    async fn boot(temp: &TempStore) -> Self {
        let cfg = config(temp);
        let metrics = Arc::new(Metrics::new());

        let security = Arc::new(SecurityCatalog::load(&cfg).expect("load security catalog"));
        let auth: Arc<dyn AuthProvider> = Arc::new(LiveAuth::new(Arc::clone(&security)));
        let audit = AuditLog::open(&cfg.audit, &cfg.store_path).expect("open audit log");

        // The ONE server-wide registry, constructed before the catalog exactly as `Server::start` does
        // (`rmp` #637/#903): the engines take it from the catalog's captured params, and both seams
        // register into it through the shared `AdminContext`.
        let transactions = Arc::new(TransactionRegistry::new());

        let catalog = Arc::new(
            DatabaseCatalog::load(&cfg, Arc::clone(&metrics), Arc::clone(&transactions))
                .expect("load db catalog"),
        );
        let handle = catalog.start_default().await.expect("start default db");

        let context = AdminContext::new(
            Arc::clone(&catalog),
            Arc::clone(&security),
            audit,
            tokio::runtime::Handle::current(),
            handle.clone(),
            Arc::new(cfg.clone()),
            Arc::clone(&transactions),
        );

        let clock: Arc<dyn Clock + Send + Sync> = Arc::new(FixedClock(AtomicU64::new(FIXED_NANOS)));
        let rest_engine = Arc::new(RestEngineAdapter::new(context.clone()));
        let registry = Arc::new(TxRegistry::new(DEFAULT_TX_TTL_NANOS));
        let rest = router(AppState::new(rest_engine, auth, registry, clock));

        let token = security
            .with_auth(|a| a.issue_token(ADMIN_USER, FIXED_SECS, 3600))
            .expect("issue admin token");

        Self {
            rest,
            token,
            context,
            transactions,
            handle,
        }
    }

    /// A fresh Bolt executor — one per "connection", as the accept loop builds it — authenticated as
    /// the admin principal.
    fn bolt(&self) -> BoltEngineExecutor {
        let mut exec = BoltEngineExecutor::new(self.context.clone(), AuditSource::BoltUds);
        exec.set_principal(Some(ADMIN_USER));
        exec
    }

    /// Drives one REST request to completion on a blocking task (the adapter's begin/run/commit are
    /// synchronous blocking submits — production drives the router on a `spawn_blocking` thread for
    /// exactly this reason) and returns `(status, json_body)`.
    async fn send(&self, req: Request<Body>) -> (StatusCode, Json) {
        let app = self.rest.clone();
        tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(async move {
                let resp = app.oneshot(req).await.expect("router responds");
                let status = resp.status();
                let bytes = resp.into_body().collect().await.expect("body").to_bytes();
                let json = serde_json::from_slice(&bytes).unwrap_or(Json::Null);
                (status, json)
            })
        })
        .await
        .expect("blocking task joins")
    }

    async fn post(&self, uri: &str, body: Json) -> (StatusCode, Json) {
        self.send(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {}", self.token))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).expect("encode body")))
                .expect("build request"),
        )
        .await
    }

    async fn delete(&self, uri: &str) -> (StatusCode, Json) {
        self.send(
            Request::builder()
                .method("DELETE")
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {}", self.token))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
    }

    /// The live registry id of the single transaction registered by `protocol` (`"http"` /
    /// `"bolt-uds"`), which is what an operator reads out of `SHOW TRANSACTIONS`.
    fn live_id(&self, protocol: &str) -> String {
        let rows: Vec<_> = self
            .transactions
            .snapshot()
            .into_iter()
            .filter(|s| s.protocol == protocol)
            .collect();
        assert_eq!(
            rows.len(),
            1,
            "exactly one live {protocol} transaction is expected, saw {rows:?}"
        );
        rows[0].id.clone()
    }

    /// Terminates `id` through the **real operator surface** — `TERMINATE TRANSACTIONS '<id>'` run as an
    /// admin statement over the Bolt seam — and asserts the server reported `"Terminated"`, which is the
    /// promise the rest of the test holds it to.
    fn terminate(&self, id: &str) {
        let mut exec = self.bolt();
        let mut stream = exec
            .run(
                &format!("TERMINATE TRANSACTIONS '{id}'"),
                vec![],
                TxControl::AutoCommit {
                    mode: BoltAccessMode::Write,
                    db: Some(DB.to_owned()),
                    timeout: None,
                },
            )
            .expect("TERMINATE TRANSACTIONS is an admin statement the seam executes");
        let message = stream
            .next_record()
            .expect("the terminate result streams")
            .expect("TERMINATE TRANSACTIONS returns one row per requested id");
        let rendered = format!("{message:?}");
        assert!(
            rendered.contains("Terminated") && !rendered.contains("not found"),
            "the operator must be told the transaction was terminated, got {rendered}"
        );
    }

    /// `MATCH (n:Marker) RETURN count(n)` over an auto-commit read, as the durable witness of whether a
    /// transaction's write survived.
    fn marker_count(&self) -> i64 {
        let ticket = self
            .handle
            .begin_auto_commit_blocking(AccessMode::Read)
            .expect("begin count read");
        let reply = self
            .handle
            .run_blocking(
                ticket,
                "MATCH (n:Marker) RETURN count(n) AS c".to_owned(),
                vec![],
                true,
                None,
                None,
            )
            .expect("count read runs");
        let mut rows = reply.rows;
        let mut count = -1;
        while let Some(row) = rows.next().expect("drain count read") {
            if let Some(graphus_cypher::MaterializedValue::Value(graphus_core::Value::Integer(n))) =
                row.first()
            {
                count = *n;
            }
        }
        assert!(count >= 0, "the count read must yield an integer row");
        count
    }
}

/// The canonical terminated message both interfaces must carry, produced by the one shared constructor.
fn terminated_message() -> String {
    // `Display` prefixes the layer ("runtime error: "); both wire renderers strip it, so compare the
    // stripped form.
    let e = graphus_server::txn_registry::terminated_error();
    let s = e.to_string();
    s.split_once(": ")
        .map_or(s.clone(), |(_, rest)| rest.to_owned())
}

/// The `(code, detail)` pair of an RFC 9457 problem body.
fn problem_parts(body: &Json) -> (String, String) {
    (
        body["code"].as_str().unwrap_or_default().to_owned(),
        body["detail"].as_str().unwrap_or_default().to_owned(),
    )
}

// ================================================================================================
// 1. The reproduction
// ================================================================================================

/// **The `rmp` #957 reproduction, end to end.** Open an explicit REST transaction, run one write in it,
/// `TERMINATE` it (which reports success), then POST the commit with no further statements. The commit
/// must be refused and the write must not be in the database.
///
/// Before the fix this returned `200 OK` and the node was committed: the REST commit path had no
/// terminated check, so `TERMINATE TRANSACTIONS` was a lie on this interface.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_terminated_rest_transaction_must_not_commit() {
    let temp = TempStore::new("rest-commit");
    let server = Server::boot(&temp).await;

    // (1) Open a transaction and run one statement in it.
    let (status, begin) = server.post(&format!("/db/{DB}/tx"), json!({})).await;
    assert_eq!(status, StatusCode::CREATED);
    let id = begin["id"].as_str().expect("a transaction id").to_owned();

    let (status, _) = server
        .post(
            &format!("/db/{DB}/tx/{id}"),
            json!({ "statements": [{ "statement": "CREATE (:Marker {v: 1})" }] }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "non-vacuity: the statement must run normally in the LIVE transaction"
    );
    assert_eq!(
        server.marker_count(),
        0,
        "non-vacuity: the write is uncommitted, so it is not yet visible"
    );

    // (2) An administrator terminates it — and is told it was terminated.
    let live = server.live_id("http");
    server.terminate(&live);

    // (3) The client commits, without running anything further.
    let (status, body) = server
        .post(&format!("/db/{DB}/tx/{id}/commit"), json!({}))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a terminated transaction must not commit; got {status} with {body}"
    );
    let (code, detail) = problem_parts(&body);
    assert_eq!(code, "Neo.ClientError.Statement.ArgumentError");
    assert_eq!(detail, terminated_message());

    // The transaction was rolled back, not committed: its write is gone.
    assert_eq!(
        server.marker_count(),
        0,
        "the terminated transaction must have been ROLLED BACK, not committed"
    );
    assert!(
        server.transactions.is_empty(),
        "the registry entry must be deregistered once the transaction is finished"
    );
}

// ================================================================================================
// 2. Cross-interface consistency
// ================================================================================================

/// Bolt and REST answer a terminated `COMMIT` **identically**: the same rolled-back outcome, the same
/// Neo status code, and a byte-identical message — because both render the one `terminated_error()` the
/// shared guard returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bolt_and_rest_answer_a_terminated_commit_identically() {
    let temp = TempStore::new("both-commit");
    let server = Server::boot(&temp).await;

    // ---- Bolt ----------------------------------------------------------------------------------
    let mut bolt = server.bolt();
    bolt.begin(BoltAccessMode::Write, Some(DB), None)
        .expect("BEGIN opens an explicit Bolt transaction");
    {
        let mut stream = bolt
            .run(
                "CREATE (:Marker {v: 1})",
                vec![],
                TxControl::InExplicit { db: None },
            )
            .expect("non-vacuity: the statement runs in the LIVE transaction");
        while stream.next_record().expect("drain the write").is_some() {}
    }
    server.terminate(&server.live_id("bolt-uds"));
    let bolt_failure = graphus_bolt::failure_from_error(
        &bolt
            .commit()
            .expect_err("a terminated Bolt transaction must not commit"),
    );
    assert_eq!(
        server.marker_count(),
        0,
        "the terminated Bolt transaction must have been rolled back"
    );

    // ---- REST ----------------------------------------------------------------------------------
    let (_, begin) = server.post(&format!("/db/{DB}/tx"), json!({})).await;
    let id = begin["id"].as_str().expect("a transaction id").to_owned();
    let (status, _) = server
        .post(
            &format!("/db/{DB}/tx/{id}"),
            json!({ "statements": [{ "statement": "CREATE (:Marker {v: 1})" }] }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "non-vacuity: the statement runs");
    server.terminate(&server.live_id("http"));
    let (status, body) = server
        .post(&format!("/db/{DB}/tx/{id}/commit"), json!({}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (rest_code, rest_detail) = problem_parts(&body);
    assert_eq!(
        server.marker_count(),
        0,
        "the terminated REST transaction must have been rolled back"
    );

    // ---- the two interfaces agree ---------------------------------------------------------------
    assert_eq!(
        bolt_failure.code, rest_code,
        "a driver must classify the refusal the same way on both interfaces"
    );
    assert_eq!(
        bolt_failure.message, rest_detail,
        "the message a client reads must be byte-identical on both interfaces"
    );
    assert_eq!(rest_detail, terminated_message());
}

/// The **next statement** in a terminated transaction is refused identically on both interfaces, and
/// the transaction is gone afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bolt_and_rest_refuse_the_next_statement_identically() {
    let temp = TempStore::new("both-statement");
    let server = Server::boot(&temp).await;

    // ---- Bolt ----------------------------------------------------------------------------------
    let mut bolt = server.bolt();
    bolt.begin(BoltAccessMode::Write, Some(DB), None)
        .expect("BEGIN");
    {
        let mut stream = bolt
            .run("RETURN 1", vec![], TxControl::InExplicit { db: None })
            .expect("non-vacuity: a statement runs in the LIVE transaction");
        while stream.next_record().expect("drain").is_some() {}
    }
    server.terminate(&server.live_id("bolt-uds"));
    let bolt_failure = graphus_bolt::failure_from_error(
        &bolt
            .run("RETURN 2", vec![], TxControl::InExplicit { db: None })
            .err()
            .expect("a terminated Bolt transaction refuses its next statement"),
    );
    assert!(
        bolt.commit().is_err(),
        "the refused statement discards the transaction, so a later COMMIT has none to finish"
    );

    // ---- REST ----------------------------------------------------------------------------------
    let (_, begin) = server.post(&format!("/db/{DB}/tx"), json!({})).await;
    let id = begin["id"].as_str().expect("a transaction id").to_owned();
    let (status, _) = server
        .post(
            &format!("/db/{DB}/tx/{id}"),
            json!({ "statements": [{ "statement": "RETURN 1" }] }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "non-vacuity: a statement runs");
    server.terminate(&server.live_id("http"));
    let (status, body) = server
        .post(
            &format!("/db/{DB}/tx/{id}"),
            json!({ "statements": [{ "statement": "RETURN 2" }] }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (rest_code, rest_detail) = problem_parts(&body);

    assert_eq!(bolt_failure.code, rest_code);
    assert_eq!(bolt_failure.message, rest_detail);
    assert_eq!(rest_detail, terminated_message());
    assert!(
        server.transactions.is_empty(),
        "both refused transactions must be deregistered"
    );
}

/// The **keep-alive** — `POST …/tx/{id}` with an empty statement batch — must not extend a terminated
/// transaction's lease and report success. It reaches neither `run` nor `commit`, so it is the one REST
/// resumption point whose guard the handler applies itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_terminated_rest_transaction_refuses_the_keep_alive() {
    let temp = TempStore::new("keepalive");
    let server = Server::boot(&temp).await;

    let (_, begin) = server.post(&format!("/db/{DB}/tx"), json!({})).await;
    let id = begin["id"].as_str().expect("a transaction id").to_owned();

    // Non-vacuity: while the transaction is LIVE, the keep-alive succeeds and keeps it open.
    let (status, _) = server
        .post(&format!("/db/{DB}/tx/{id}"), json!({ "statements": [] }))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(server.transactions.len(), 1);

    server.terminate(&server.live_id("http"));

    let (status, body) = server
        .post(&format!("/db/{DB}/tx/{id}"), json!({ "statements": [] }))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a keep-alive must not resurrect a terminated transaction; got {status} with {body}"
    );
    assert_eq!(problem_parts(&body).1, terminated_message());
    assert!(
        server.transactions.is_empty(),
        "the terminated transaction must be rolled back and deregistered, not merely reported"
    );
}

/// Rollback is the deliberate **exemption** on both interfaces: rolling a terminated transaction back is
/// exactly what the terminating operator asked for, so a client is never denied the ability to discard
/// it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bolt_and_rest_both_still_roll_a_terminated_transaction_back() {
    let temp = TempStore::new("both-rollback");
    let server = Server::boot(&temp).await;

    // ---- Bolt ----------------------------------------------------------------------------------
    let mut bolt = server.bolt();
    bolt.begin(BoltAccessMode::Write, Some(DB), None)
        .expect("BEGIN");
    {
        let mut stream = bolt
            .run(
                "CREATE (:Marker {v: 1})",
                vec![],
                TxControl::InExplicit { db: None },
            )
            .expect("non-vacuity: the statement runs");
        while stream.next_record().expect("drain").is_some() {}
    }
    server.terminate(&server.live_id("bolt-uds"));
    bolt.rollback()
        .expect("ROLLBACK of a terminated transaction succeeds — it is what termination asks for");

    // ---- REST ----------------------------------------------------------------------------------
    let (_, begin) = server.post(&format!("/db/{DB}/tx"), json!({})).await;
    let id = begin["id"].as_str().expect("a transaction id").to_owned();
    let (status, _) = server
        .post(
            &format!("/db/{DB}/tx/{id}"),
            json!({ "statements": [{ "statement": "CREATE (:Marker {v: 1})" }] }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "non-vacuity: the statement runs");
    server.terminate(&server.live_id("http"));
    let (status, body) = server.delete(&format!("/db/{DB}/tx/{id}")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "DELETE of a terminated transaction succeeds on REST exactly as ROLLBACK does on Bolt; got {body}"
    );

    assert_eq!(
        server.marker_count(),
        0,
        "neither rolled-back transaction may leave a write behind"
    );
    assert!(server.transactions.is_empty());
}

// ================================================================================================
// 3. A terminated constraint DDL (`rmp` task #903) over both interfaces
// ================================================================================================

/// Seeds `n` `:P` nodes carrying a distinct `email`, in one committed auto-commit statement.
fn seed_people(handle: &EngineHandle, n: usize) {
    let ticket = handle
        .begin_auto_commit_blocking(AccessMode::Write)
        .expect("begin seed");
    let reply = handle
        .run_blocking(
            ticket,
            "UNWIND range(1, $n) AS i CREATE (:P {email: 'user' + toString(i)})".to_owned(),
            vec![("n".to_owned(), graphus_core::Value::Integer(n as i64))],
            true,
            None,
            None,
        )
        .expect("seed runs");
    let mut rows = reply.rows;
    while rows.next().expect("drain seed").is_some() {}
}

/// The declared constraints, as `SHOW CONSTRAINTS` reports them.
fn constraint_count(handle: &EngineHandle) -> usize {
    handle
        .constraint_ddl_blocking(
            ConstraintCommand::Show {
                filter: ConstraintTypeFilter::All,
                tail: None,
            },
            None,
        )
        .expect("show constraints")
        .rows
        .len()
}

/// Spawns a thread that waits for the DDL's `"internal"` registry entry (`rmp` #903) and terminates it,
/// returning a join handle that yields the id it stopped (or `None` if the DDL finished first).
fn terminator(transactions: &Arc<TransactionRegistry>) -> std::thread::JoinHandle<Option<String>> {
    let transactions = Arc::clone(transactions);
    std::thread::spawn(move || {
        let deadline = Instant::now() + APPEAR_TIMEOUT;
        while Instant::now() < deadline {
            if let Some(row) = transactions
                .snapshot()
                .into_iter()
                .find(|s| s.protocol == "internal")
            {
                let _ = transactions.terminate(std::slice::from_ref(&row.id));
                return Some(row.id);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        None
    })
}

/// A `CREATE CONSTRAINT` an operator terminates mid-walk behaves **identically** whichever interface
/// asked for it: the schema is never half-applied, and a stopped DDL reports the same termination.
///
/// The oracle is all-or-nothing rather than "it was aborted", for the reason `rmp` #903's own gate
/// documents: terminating in-flight work races that work finishing, and a test that demanded the abort
/// would be asserting it won the race. What must hold unconditionally is that the DDL either declared
/// the constraint or left **nothing** behind — and that when it *was* stopped, both interfaces say so
/// with the same words.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_terminated_constraint_ddl_is_honoured_identically_over_both_seams() {
    let temp = TempStore::new("constraint-ddl");
    let server = Server::boot(&temp).await;
    seed_people(&server.handle, SEEDED_NODES);
    assert!(
        server.transactions.is_empty(),
        "non-vacuity: seeding must leave the registry empty, so anything observed below is a DDL"
    );

    // ---- Bolt ----------------------------------------------------------------------------------
    let killer = terminator(&server.transactions);
    let bolt_error = {
        let mut bolt = server.bolt();
        let outcome = bolt.run(
            "CREATE CONSTRAINT u_bolt FOR (p:P) REQUIRE p.email IS UNIQUE",
            vec![],
            TxControl::AutoCommit {
                mode: BoltAccessMode::Write,
                db: Some(DB.to_owned()),
                timeout: None,
            },
        );
        match outcome {
            Ok(mut stream) => {
                while stream
                    .next_record()
                    .expect("drain the DDL result")
                    .is_some()
                {}
                None
            }
            Err(e) => Some(graphus_bolt::failure_from_error(&e)),
        }
    };
    assert!(
        killer.join().expect("terminator thread").is_some(),
        "the running CREATE CONSTRAINT must have been addressable by TERMINATE TRANSACTIONS"
    );
    let bolt_constraints = constraint_count(&server.handle);
    match &bolt_error {
        None => assert_eq!(
            bolt_constraints, 1,
            "a DDL that reached its uninterruptible tail must have declared the constraint"
        ),
        Some(f) => {
            assert!(
                f.message.contains("terminated"),
                "a stopped DDL must report the termination, got {}",
                f.message
            );
            assert_eq!(
                bolt_constraints, 0,
                "a terminated DDL must leave NOTHING behind — not a catalogue entry, not a rule"
            );
        }
    }
    assert!(
        server.transactions.is_empty(),
        "the DDL's internal entry must be deregistered on either arm"
    );

    // ---- REST ----------------------------------------------------------------------------------
    // Run the same DDL through the REST auto-commit endpoint. If the Bolt arm already declared the
    // constraint, use a distinct name and property so this run does real work rather than colliding.
    let (name, property) = if bolt_error.is_none() {
        ("u_rest", "email2")
    } else {
        ("u_rest", "email")
    };
    if property == "email2" {
        // The Bolt arm won its race, so give the REST arm its own covered property with the same
        // (distinct) values — otherwise it would trivially collide with the existing constraint and
        // never reach a walk to terminate.
        let ticket = server
            .handle
            .begin_auto_commit_blocking(AccessMode::Write)
            .expect("begin backfill");
        let reply = server
            .handle
            .run_blocking(
                ticket,
                "MATCH (p:P) SET p.email2 = p.email".to_owned(),
                vec![],
                true,
                None,
                None,
            )
            .expect("backfill runs");
        let mut rows = reply.rows;
        while rows.next().expect("drain backfill").is_some() {}
    }
    let before = constraint_count(&server.handle);

    let killer = terminator(&server.transactions);
    let (status, body) = server
        .post(
            &format!("/db/{DB}/tx/commit"),
            json!({ "statements": [{
                "statement": format!(
                    "CREATE CONSTRAINT {name} FOR (p:P) REQUIRE p.{property} IS UNIQUE"
                )
            }] }),
        )
        .await;
    assert!(
        killer.join().expect("terminator thread").is_some(),
        "the running CREATE CONSTRAINT must have been addressable over REST too"
    );
    let after = constraint_count(&server.handle);

    if status == StatusCode::OK {
        assert_eq!(
            after,
            before + 1,
            "a DDL that reached its uninterruptible tail must have declared the constraint"
        );
    } else {
        let (code, detail) = problem_parts(&body);
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a stopped DDL is a non-retryable client fault, got {status} with {body}"
        );
        assert!(
            detail.contains("terminated"),
            "a stopped DDL must report the termination over REST too, got {body}"
        );
        assert_eq!(
            after, before,
            "a terminated DDL must leave NOTHING behind over REST either"
        );
        // The two interfaces render the SAME stopped DDL identically. Asserted only when both arms were
        // actually stopped — otherwise there is no Bolt failure to compare against.
        if let Some(f) = &bolt_error {
            assert_eq!(
                f.code, code,
                "a driver must classify a terminated DDL the same way on both interfaces"
            );
            assert_eq!(
                f.message, detail,
                "a terminated DDL's message must be byte-identical on both interfaces"
            );
        }
    }
    assert!(
        server.transactions.is_empty(),
        "the DDL's internal entry must be deregistered on either arm"
    );
}
