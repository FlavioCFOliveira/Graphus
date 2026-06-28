//! Production-confidence audit (rmp #472): **resource governance & DoS resistance** of the REST
//! surface under hostile load. Drives the **real** public [`graphus_rest::router`] in-process via
//! `tower::ServiceExt::oneshot` (no sockets/TLS — the project's hard rule), measuring server-side
//! resource curves rather than guessing.
//!
//! These tests are measurement vehicles **and** correctness regressions: they assert that the REST
//! path returns a *complete* large result (every row present, well-formed framing), and they PRINT
//! the resident-set (`VmRSS`) curve so a reviewer can read off whether server memory is **bounded**
//! (flat) or **grows with the result size** (a buffering DoS vector). The correctness assertions hold
//! whether the body is buffered (today) or truly streamed (a future fix), so the file does not encode
//! the bug — it documents the behaviour and guards completeness. Tagged `[AUDIT#472]` on stdout
//! (run with `--nocapture` to read the curve).
//!
//! Probe 1 — unbounded result materialization (JSON buffered + NDJSON "stream").
//! Probe 2 — open-transaction cap (429) + idle-sweep reclamation end-to-end.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::body::Body;
use http::{Request, Response, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value as Json, json};
use tower::ServiceExt;

use graphus_auth::{AuthProvider, Authenticator, Privilege};
use graphus_core::capability::Clock;
use graphus_core::{GraphusError, Value};

use graphus_rest::engine::{
    AccessMode, RestEngine, ResultStream, Row, RunSummary, TxHandle, TxOrigin,
};
use graphus_rest::registry::TxRegistry;
use graphus_rest::restvalue::RestValue;
use graphus_rest::router::{AppState, router};

// =============================== generative engine =============================================
//
// A `RestEngine` whose `run` yields rows **lazily** from a counter — O(1) engine-side state, no
// pre-built `Vec<Row>`. This is the load-bearing property of the probe: the engine never holds the
// result, so any growth of server RSS during egress is attributable to the **router** buffering the
// response, not to the test fixture. A statement `GEN:<n>` produces `n` rows, each a single
// `Integer` cell; any other statement produces zero rows.

/// A lazy stream of `remaining` single-`Integer`-cell rows (O(1) state).
struct GenStream {
    fields: Vec<String>,
    remaining: u64,
    summary: RunSummary,
}

impl ResultStream for GenStream {
    fn fields(&self) -> &[String] {
        &self.fields
    }
    fn next_row(&mut self) -> Result<Option<Row>, GraphusError> {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        // One freshly-allocated row of one scalar cell; dropped by the router as it consumes it.
        Ok(Some(vec![RestValue::Value(Value::Integer(
            self.remaining as i64,
        ))]))
    }
    fn summary(&self) -> RunSummary {
        self.summary.clone()
    }
}

#[derive(Default)]
struct GenEngine {
    next: AtomicU64,
}

impl GenEngine {
    fn new() -> Self {
        Self::default()
    }
    /// Parses `GEN:<n>` → `Some(n)`; anything else → `None` (zero rows).
    fn parse_gen(query: &str) -> Option<u64> {
        query
            .trim()
            .strip_prefix("GEN:")
            .and_then(|n| n.parse().ok())
    }
}

impl RestEngine for GenEngine {
    type Stream = GenStream;

    fn begin(
        &self,
        _db: &str,
        _mode: AccessMode,
        _origin: TxOrigin<'_>,
    ) -> Result<TxHandle, GraphusError> {
        Ok(TxHandle(self.next.fetch_add(1, Ordering::Relaxed) + 1))
    }

    fn run(
        &self,
        _tx: TxHandle,
        query: &str,
        _params: Vec<(String, Value)>,
    ) -> Result<Self::Stream, GraphusError> {
        Ok(GenStream {
            fields: vec!["n".to_owned()],
            remaining: Self::parse_gen(query).unwrap_or(0),
            summary: RunSummary {
                query_type: Some("r".to_owned()),
                stats: Vec::new(),
            },
        })
    }

    fn commit(&self, _tx: TxHandle) -> Result<RunSummary, GraphusError> {
        Ok(RunSummary::default())
    }
    fn rollback(&self, _tx: TxHandle) -> Result<(), GraphusError> {
        Ok(())
    }
}

// =============================== harness =======================================================

struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn now_nanos(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

const JWT_SECRET: &[u8] = b"a-test-jwt-signing-secret-at-least-32b!!";
const TTL_NANOS: u64 = 60 * 1_000_000_000; // 60s inactivity window (the production REST default).

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
    engine: Arc<GenEngine>,
    clock: Arc<TestClock>,
    auth: Arc<Authenticator>,
}

impl Harness {
    fn new() -> Self {
        Self::with_registry(Arc::new(TxRegistry::new(TTL_NANOS)))
    }
    fn with_registry(registry: Arc<TxRegistry>) -> Self {
        let engine = Arc::new(GenEngine::new());
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
            clock,
            auth,
        }
    }
    fn token(&self) -> String {
        let now = self.clock.0.load(Ordering::Relaxed) / 1_000_000_000;
        self.auth.issue_token("alice", now, 3600).unwrap()
    }
    async fn send(&self, req: Request<Body>) -> Response<Body> {
        self.router.clone().oneshot(req).await.unwrap()
    }
}

/// Resident set size of THIS process, in KiB, read from `/proc/self/status` (Linux). The audit host
/// is Linux (the project's primary target); `0` if the field is unreadable (the test then skips the
/// RSS assertion but still checks correctness).
fn vmrss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("VmRSS:"))
                .and_then(|v| v.split_whitespace().next().map(str::to_owned))
        })
        .and_then(|kib| kib.parse().ok())
        .unwrap_or(0)
}

fn auto_commit_req(token: &str, accept: &str, n: u64) -> Request<Body> {
    let body =
        serde_json::to_vec(&json!({ "statements": [ { "statement": format!("GEN:{n}") } ] }))
            .unwrap();
    Request::builder()
        .method("POST")
        .uri("/db/neo4j/tx/commit")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, accept)
        .body(Body::from(body))
        .unwrap()
}

// ============================================================================================
//  PROBE 1 — UNBOUNDED RESULT MATERIALIZATION (#304): JSON-buffered + NDJSON "stream"
// ============================================================================================
//
// The router builds the WHOLE response body in memory before sending: the JSON path collects a
// `serde_json::Value` tree (`run_one` → `data: Vec<Json>`) then serializes it; the NDJSON path
// accumulates every framed line into one `out: Vec<u8>` (`stream_single_statement_ndjson`). Neither
// is a true incremental stream. The request body is capped at 4 MiB (`413`), but the RESPONSE is
// uncapped — so a single small authenticated request asking for a huge result forces the server to
// materialize the entire body in RAM (an OOM / DoS vector that also affects co-tenants on the shared
// process). These tests MEASURE the RSS curve to quantify it.

/// JSON buffered path: a single auto-commit request returns ALL `n` rows (completeness), and the
/// server's resident memory GROWS with `n` (the printed curve is the audit evidence for #304).
#[tokio::test]
async fn probe1_json_buffered_result_rss_curve() {
    let h = Harness::new();
    let token = h.token();

    // CI-friendly default; override for a heavier headline run (e.g. GRAPHUS_AUDIT_MAX_ROWS=2000000).
    let max_rows: u64 = std::env::var("GRAPHUS_AUDIT_MAX_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300_000);
    let sizes = [max_rows / 25, max_rows / 5, max_rows];

    // Warm the path (page in code + allocator arenas) so the first measured point is not a cold-start
    // artifact.
    let _ = h
        .send(auto_commit_req(&token, "application/json", 1_000))
        .await;

    let baseline = vmrss_kib();
    println!("[AUDIT#472] PROBE 1 — JSON buffered result materialization");
    println!("[AUDIT#472]   baseline VmRSS = {baseline} KiB");
    println!("[AUDIT#472]   rows |  body bytes | VmRSS after | Δ vs before");

    let mut last_body_len = 0usize;
    for &n in &sizes {
        let before = vmrss_kib();
        let resp = h.send(auto_commit_req(&token, "application/json", n)).await;
        assert_eq!(resp.status(), StatusCode::OK, "n={n}: 200 OK");
        // Measure RSS while the Response (its buffered Body) is still held in memory.
        let after_holding = vmrss_kib();

        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body_len = bytes.len();
        last_body_len = body_len;
        let parsed: Json = serde_json::from_slice(&bytes).unwrap();
        let data_rows = parsed["results"][0]["data"].as_array().map_or(0, Vec::len);
        // Completeness: a single buffered response carried EVERY one of the n rows.
        assert_eq!(
            data_rows as u64, n,
            "n={n}: all rows present in one response"
        );

        let delta = after_holding as i64 - before as i64;
        println!(
            "[AUDIT#472]   {n:>9} | {body_len:>10} | {after_holding:>9} KiB | {delta:>+8} KiB"
        );
        drop(bytes);
    }

    // Evidence assertion (unconfounded by cross-test allocator reuse): the server returned the ENTIRE
    // large result as ONE materialized body — and that uncapped body DWARFS the 4 MiB request-body cap
    // (`MAX_REQUEST_BODY_BYTES`), the very asymmetry that makes this a DoS vector. The printed VmRSS
    // column is the resource curve; body_len is the deterministic proof of full materialization. When a
    // true streaming fix lands the body is delivered incrementally (RSS flat) but `collect()` still
    // yields all bytes, so this completeness assertion remains valid.
    assert!(
        last_body_len as u64 > 4 * 1024 * 1024,
        "PROBE 1 (JSON): the buffered response for {} rows was {last_body_len} bytes — \
         a single request materialized a body larger than the 4 MiB request cap",
        sizes[2]
    );
}

/// NDJSON "streaming" path: framed `fields` + one `row` line per row + `summary` (completeness via
/// exact line count), with the RSS curve printed. Despite the `application/x-ndjson` content type,
/// the body is assembled whole into `out: Vec<u8>` before the first byte is sent (#304).
#[tokio::test]
async fn probe1_ndjson_result_rss_curve() {
    let h = Harness::new();
    let token = h.token();

    let max_rows: u64 = std::env::var("GRAPHUS_AUDIT_MAX_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300_000);
    let sizes = [max_rows / 25, max_rows / 5, max_rows];

    let _ = h
        .send(auto_commit_req(&token, "application/x-ndjson", 1_000))
        .await;

    let baseline = vmrss_kib();
    println!("[AUDIT#472] PROBE 1 — NDJSON 'stream' result materialization");
    println!("[AUDIT#472]   baseline VmRSS = {baseline} KiB");
    println!("[AUDIT#472]   rows |  body bytes | VmRSS after | Δ vs before");

    let mut last_body_len = 0usize;
    for &n in &sizes {
        let before = vmrss_kib();
        let resp = h
            .send(auto_commit_req(&token, "application/x-ndjson", n))
            .await;
        assert_eq!(resp.status(), StatusCode::OK, "n={n}: 200 OK");
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/x-ndjson"),
            "n={n}: NDJSON content type"
        );
        let after_holding = vmrss_kib();

        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body_len = bytes.len();
        last_body_len = body_len;
        // Completeness: a `fields` line, one `row` line per row, and a `summary` line — exactly n+2
        // newline-terminated NDJSON records, the whole result in one body.
        let lines = bytes.iter().filter(|&&b| b == b'\n').count() as u64;
        assert_eq!(lines, n + 2, "n={n}: fields + n rows + summary = n+2 lines");

        let delta = after_holding as i64 - before as i64;
        println!(
            "[AUDIT#472]   {n:>9} | {body_len:>10} | {after_holding:>9} KiB | {delta:>+8} KiB"
        );
        drop(bytes);
    }

    // The `application/x-ndjson` body is assembled WHOLE into one `out: Vec<u8>` before the first byte
    // ships (`stream_single_statement_ndjson`) — so despite the content type it is not an incremental
    // stream. The complete body for the largest size again exceeds the 4 MiB request cap, materialized
    // server-side in one allocation. (The printed VmRSS Δ can read ~0 when an earlier probe in the same
    // test process already grew the allocator arena; body_len is the unconfounded proof.)
    assert!(
        last_body_len as u64 > 4 * 1024 * 1024,
        "PROBE 1 (NDJSON): the buffered NDJSON body for {} rows was {last_body_len} bytes — \
         a single request materialized a body larger than the 4 MiB request cap",
        sizes[2]
    );
}

// ============================================================================================
//  PROBE 2 — OPEN-TRANSACTION CAP (429) + IDLE-SWEEP RECLAMATION (rmp #448 / #389)
// ============================================================================================
//
// A REST explicit transaction outlives its connection and pins the MVCC GC watermark, so the registry
// caps the live count (DEFAULT_MAX_OPEN_TRANSACTIONS) and 429-rejects past it; the inactivity sweep
// reclaims idle ones. This verifies the bound holds END-TO-END through the real router (begin handler
// → `try_open` → 429) at the production default, and that a sweep frees slots so the cap bounds the
// LIVE count, not the cumulative one.

fn begin_req(token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/db/neo4j/tx")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(b"{}".to_vec()))
        .unwrap()
}

#[tokio::test]
async fn probe2_open_tx_cap_429_then_idle_sweep_reclaims() {
    // Use a modest explicit cap so the test is fast, but drive it END-TO-END through the router to
    // prove the wiring (the production default is 1024; the mechanism is identical).
    const CAP: usize = 64;
    let registry = Arc::new(TxRegistry::new(TTL_NANOS).with_max_open_transactions(CAP));
    let h = Harness::with_registry(registry);
    let token = h.token();

    // Open exactly the cap; every BEGIN is admitted (201/200 — created).
    for i in 0..CAP {
        let resp = h.send(begin_req(&token)).await;
        assert!(
            resp.status().is_success(),
            "BEGIN #{i} under the cap must be admitted, got {}",
            resp.status()
        );
    }
    assert_eq!(
        h.registry.open_count(),
        CAP,
        "registry holds exactly the cap"
    );

    // The next BEGIN is shed with 429 (retriable load-shed) — NOT admitted, NOT an unbounded grow.
    let resp = h.send(begin_req(&token)).await;
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "past the cap, BEGIN must be 429 (rmp #448)"
    );
    assert_eq!(
        h.registry.open_count(),
        CAP,
        "a 429-rejected BEGIN does not add an entry"
    );

    // Advance the clock past the inactivity TTL and sweep: every idle (untouched) tx is rolled back,
    // freeing the watermark and the slots (rmp #389). This is the reclamation a hostile 'open and
    // walk away' pattern is bounded by.
    h.clock
        .0
        .store(1_000_000_000 + TTL_NANOS + 1, Ordering::Relaxed);
    let reaped = h
        .registry
        .sweep_expired(h.clock.now_nanos(), h.engine.as_ref());
    assert_eq!(reaped.len(), CAP, "the sweep reclaimed every idle tx");
    assert_eq!(
        h.registry.open_count(),
        0,
        "all slots freed after the sweep"
    );

    // A fresh BEGIN is admitted again — the cap bounds the LIVE count, not the cumulative count.
    let resp = h.send(begin_req(&token)).await;
    assert!(
        resp.status().is_success(),
        "after reclamation a new BEGIN is admitted again, got {}",
        resp.status()
    );
    println!(
        "[AUDIT#472] PROBE 2 — open-tx cap held at {CAP}: 429 past the cap, idle-sweep reclaimed {} slots",
        reaped.len()
    );
}
