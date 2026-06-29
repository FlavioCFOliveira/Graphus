//! **D4 re-audit (`rmp` #485): the REST open-transaction cap (`rmp` #448) is LEAK-FREE on its rejection
//! path — a `429`-shed `BEGIN` must roll back the engine-side transaction it already opened.**
//!
//! The router opens the engine transaction (`RestEngine::begin`) *before* it asks the registry to admit
//! it (`TxRegistry::try_open`). When the registry refuses past the cap, the engine transaction is already
//! live — and it pins the MVCC GC watermark. The router therefore MUST roll it back on the rejection
//! (router.rs `begin`, the `Err(too_many) => { engine.rollback(handle); … }` arm), or every over-cap
//! `BEGIN` would orphan a watermark-pinning snapshot **with no registry entry to ever reap it** — turning
//! the very cap that exists to *stop* the slow-OOM into a faster leak (CWE-770/CWE-400).
//!
//! The existing `resource_governance_audit.rs::probe2` proves the registry-level cap (429 + `open_count`
//! stays at the cap + idle-sweep reclaims), but its mock engine's `rollback` is a **no-op**, so it cannot
//! observe whether the engine-side transaction was actually released. This test closes that gap: it drives
//! the **real public router** with a **leak-tracking** engine that counts *live* engine transactions, and
//! asserts that after a flood of over-cap `BEGIN`s the live engine-transaction count stays bounded at the
//! cap — every rejected `BEGIN` rolled its engine handle back. Were router.rs's rollback-on-reject removed,
//! this test would fail (live count = cap + flood), making the leak a hard regression.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use axum::Router;
use axum::body::Body;
use http::{Request, StatusCode, header};
use tower::ServiceExt;

use graphus_auth::{AuthProvider, Authenticator, Privilege};
use graphus_core::capability::Clock;
use graphus_core::{GraphusError, Value};

use graphus_rest::engine::{
    AccessMode, RestEngine, ResultStream, Row, RunSummary, TxHandle, TxOrigin,
};
use graphus_rest::registry::TxRegistry;
use graphus_rest::router::{AppState, router};

/// A `ResultStream` that yields no rows (the leak test never runs statements, only BEGIN/COMMIT).
struct EmptyStream {
    fields: Vec<String>,
}
impl ResultStream for EmptyStream {
    fn fields(&self) -> &[String] {
        &self.fields
    }
    fn next_row(&mut self) -> Result<Option<Row>, GraphusError> {
        Ok(None)
    }
    fn summary(&self) -> RunSummary {
        RunSummary {
            query_type: Some("r".to_owned()),
            stats: Vec::new(),
        }
    }
}

/// A `RestEngine` that tracks the number of **live** engine transactions: `begin` bumps it, and
/// `commit`/`rollback` drop it. This is the load-bearing fixture — a leaked engine transaction (a
/// `begin` whose handle is never released) shows up as a live count above the registry's cap.
#[derive(Default)]
struct LeakTrackingEngine {
    next: AtomicU64,
    /// Live engine transactions (begin: +1; commit/rollback: −1). Must never exceed the open-tx cap.
    live: AtomicI64,
    /// Total `begin` calls (admitted + rejected).
    begins: AtomicU64,
    /// Total `rollback` calls (the rejection path must produce one per rejected BEGIN).
    rollbacks: AtomicU64,
}

impl LeakTrackingEngine {
    fn live(&self) -> i64 {
        self.live.load(Ordering::Relaxed)
    }
    fn begins(&self) -> u64 {
        self.begins.load(Ordering::Relaxed)
    }
    fn rollbacks(&self) -> u64 {
        self.rollbacks.load(Ordering::Relaxed)
    }
}

impl RestEngine for LeakTrackingEngine {
    type Stream = EmptyStream;

    fn begin(
        &self,
        _db: &str,
        _mode: AccessMode,
        _origin: TxOrigin<'_>,
    ) -> Result<TxHandle, GraphusError> {
        self.begins.fetch_add(1, Ordering::Relaxed);
        self.live.fetch_add(1, Ordering::Relaxed);
        Ok(TxHandle(self.next.fetch_add(1, Ordering::Relaxed) + 1))
    }

    fn run(
        &self,
        _tx: TxHandle,
        _query: &str,
        _params: Vec<(String, Value)>,
    ) -> Result<Self::Stream, GraphusError> {
        Ok(EmptyStream {
            fields: vec!["n".to_owned()],
        })
    }

    fn commit(&self, _tx: TxHandle) -> Result<RunSummary, GraphusError> {
        self.live.fetch_sub(1, Ordering::Relaxed);
        Ok(RunSummary::default())
    }

    fn rollback(&self, _tx: TxHandle) -> Result<(), GraphusError> {
        self.rollbacks.fetch_add(1, Ordering::Relaxed);
        self.live.fetch_sub(1, Ordering::Relaxed);
        Ok(())
    }
}

struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn now_nanos(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

const JWT_SECRET: &[u8] = b"a-test-jwt-signing-secret-at-least-32b!!";
const TTL_NANOS: u64 = 60 * 1_000_000_000; // the production REST inactivity window

fn fixture_auth() -> Authenticator {
    let mut a = Authenticator::new(JWT_SECRET).unwrap();
    a.catalog_mut().create_user("alice").unwrap();
    a.catalog_mut().create_role("rw").unwrap();
    a.catalog_mut()
        .grant_privilege("rw", Privilege::read_database())
        .unwrap();
    a.catalog_mut()
        .grant_privilege("rw", Privilege::write_database())
        .unwrap();
    a.catalog_mut().grant_role("alice", "rw").unwrap();
    a
}

struct Harness {
    router: Router,
    registry: Arc<TxRegistry>,
    engine: Arc<LeakTrackingEngine>,
    auth: Arc<Authenticator>,
    clock: Arc<TestClock>,
}

impl Harness {
    fn new(cap: usize) -> Self {
        let registry = Arc::new(TxRegistry::new(TTL_NANOS).with_max_open_transactions(cap));
        let engine = Arc::new(LeakTrackingEngine::default());
        let auth = Arc::new(fixture_auth());
        let clock = Arc::new(TestClock(AtomicU64::new(1_000_000_000)));
        let state = AppState::new(
            Arc::clone(&engine),
            Arc::clone(&auth) as Arc<dyn AuthProvider>,
            Arc::clone(&registry),
            Arc::clone(&clock) as Arc<dyn Clock + Send + Sync>,
        );
        Self {
            router: router(state),
            registry,
            engine,
            auth,
            clock,
        }
    }
    fn token(&self) -> String {
        let now = self.clock.0.load(Ordering::Relaxed) / 1_000_000_000;
        self.auth.issue_token("alice", now, 3600).unwrap()
    }
    async fn send(&self, req: Request<Body>) -> StatusCode {
        self.router.clone().oneshot(req).await.unwrap().status()
    }
}

fn begin_req(token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/db/neo4j/tx")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(b"{}".to_vec()))
        .unwrap()
}

/// The REST request-body cap (`router::MAX_REQUEST_BODY_BYTES` = 4 MiB, wired via axum
/// `DefaultBodyLimit::max`): a body past the cap is rejected with `413 Payload Too Large` **before** any
/// handler/engine work — bounding the "tiny request, giant body buffered into RAM" memory DoS. The limit
/// layer runs ahead of authentication, so an *unauthenticated* oversized POST is shed just the same.
#[tokio::test]
async fn oversized_request_body_is_rejected_413() {
    let h = Harness::new(64);
    // 5 MiB > the 4 MiB cap. Content-Length is set from the Vec, so the layer rejects up-front.
    let oversized = vec![b'x'; 5 * 1024 * 1024];
    let req = Request::builder()
        .method("POST")
        .uri("/db/neo4j/tx/commit")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(oversized))
        .unwrap();
    assert_eq!(
        h.send(req).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "a >4 MiB request body must be 413-rejected by the body-size cap (no unbounded buffering)"
    );
    // And the body-limit layer ran before any engine work: no transaction was opened.
    assert_eq!(
        h.engine.begins(),
        0,
        "an oversized body is shed before the handler runs"
    );
    assert_eq!(
        h.engine.live(),
        0,
        "no engine transaction opened for a rejected oversized body"
    );

    // A normal-sized authenticated request on the same router still works (the cap does not over-reject).
    let token = h.token();
    assert!(
        h.send(begin_req(&token)).await.is_success(),
        "a normal-sized BEGIN on the same router is admitted (the body cap does not over-reject)"
    );
}

/// THE GATE (`rmp` #448 leak-freedom): open exactly the cap, then flood many over-cap `BEGIN`s. Each
/// flood `BEGIN` must be `429`-shed AND must roll back the engine transaction it opened — so the engine's
/// **live** transaction count never exceeds the cap. A removed rollback-on-reject would show live =
/// cap + flood (an orphaned, GC-watermark-pinning snapshot per shed request).
#[tokio::test]
async fn rejected_begin_does_not_leak_engine_transaction() {
    const CAP: usize = 8;
    const FLOOD: usize = 50;
    let h = Harness::new(CAP);
    let token = h.token();

    // Open exactly the cap — every BEGIN admitted, every one a live engine transaction.
    for i in 0..CAP {
        assert!(
            h.send(begin_req(&token)).await.is_success(),
            "BEGIN #{i} under the cap must be admitted"
        );
    }
    assert_eq!(
        h.registry.open_count(),
        CAP,
        "registry holds exactly the cap"
    );
    assert_eq!(
        h.engine.live(),
        CAP as i64,
        "the cap's worth of engine transactions are live"
    );

    // Flood over-cap BEGINs: each one is 429-shed.
    for _ in 0..FLOOD {
        assert_eq!(
            h.send(begin_req(&token)).await,
            StatusCode::TOO_MANY_REQUESTS,
            "an over-cap BEGIN must be 429-shed (rmp #448)"
        );
    }

    // THE GATE: the registry count is unchanged, AND the engine's LIVE transaction count is STILL exactly
    // the cap — every shed BEGIN rolled its just-opened engine transaction back (no orphaned watermark pin).
    assert_eq!(
        h.registry.open_count(),
        CAP,
        "a 429-shed BEGIN never adds a registry entry"
    );
    assert_eq!(
        h.engine.live(),
        CAP as i64,
        "LEAK: every rejected BEGIN must roll back the engine transaction it opened (router.rs:488)"
    );
    // Accounting cross-check: every BEGIN opened an engine txn; every shed one (FLOOD) rolled back.
    assert_eq!(
        h.engine.begins(),
        (CAP + FLOOD) as u64,
        "every BEGIN opened an engine txn"
    );
    assert_eq!(
        h.engine.rollbacks(),
        FLOOD as u64,
        "exactly the FLOOD of rejected BEGINs each produced one engine rollback"
    );

    // And reclamation still works: advance past the TTL and sweep — the admitted ones roll back too,
    // returning the engine to zero live transactions (no residue from the rejection storm).
    h.clock
        .0
        .store(1_000_000_000 + TTL_NANOS + 1, Ordering::Relaxed);
    let reaped = h
        .registry
        .sweep_expired(h.clock.now_nanos(), h.engine.as_ref());
    assert_eq!(
        reaped.len(),
        CAP,
        "the idle sweep reclaims every admitted tx"
    );
    assert_eq!(
        h.engine.live(),
        0,
        "after the sweep no engine transaction is live — fully reclaimed"
    );

    println!(
        "[REAUDIT#485] REST open-tx cap leak-free: {FLOOD} over-cap BEGINs 429-shed, engine live held at \
         {CAP} (rollbacks={}), swept to 0",
        h.engine.rollbacks()
    );
}
