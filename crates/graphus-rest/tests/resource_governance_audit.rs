//! Production-confidence audit (rmp #472): **resource governance & DoS resistance** of the REST
//! surface under hostile load. Drives the **real** public [`graphus_rest::router`] in-process via
//! `tower::ServiceExt::oneshot` (no sockets/TLS — the project's hard rule), measuring server-side
//! resource curves rather than guessing.
//!
//! These tests are measurement vehicles **and** correctness regressions: they assert that the REST
//! path returns a *complete* large result (every row present, well-formed framing) **and** that the
//! server's resident memory stays **bounded** (flat) as the result grows — they PRINT the resident-set
//! (`VmRSS`) curve so a reviewer can read it off. The completeness assertions hold whether the body is
//! buffered or truly streamed; the bounded-RSS assertions are the regression guard for the
//! incremental-streaming fix (rmp #475). Tagged `[AUDIT#472/rmp#475]` on stdout (run with `--nocapture`
//! to read the curve).
//!
//! Probe 1 — incremental streaming keeps egress memory bounded (JSON array + NDJSON), rmp #475.
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

/// The response `Content-Type`, for the probes' wire-format assertions.
fn content_type(resp: &Response<Body>) -> String {
    resp.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned()
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
//  PROBE 1 — INCREMENTAL STREAMING KEEPS EGRESS MEMORY BOUNDED (rmp #475, was #304)
// ============================================================================================
//
// The router streams a single-statement JSON or NDJSON result incrementally: a `spawn_blocking`
// producer drains the `ResultStream` one row at a time, serializes it, and `blocking_send`s bounded
// chunks into a bounded `tokio::sync::mpsc` channel that backs an `axum::body::Body::from_stream`
// response. A row is serialized → flushed → dropped before the next is pulled, so server memory is
// FLAT regardless of result size — the Bolt `PULL` property. Before the fix (#304) the router built
// the WHOLE body in memory first (JSON: a `serde_json::Value` tree; NDJSON: one `Vec<u8>`), so a tiny
// authenticated request asking for a huge result forced the entire body into RAM (an OOM/DoS vector
// that also starved co-tenants). These tests MEASURE the RSS curve to prove the fix: each lazy
// `Response` is held WITHOUT draining, so the measured `VmRSS` reflects only what the SERVER buffered.

/// The maximum server-side buffering (`VmRSS` growth while a large response is *held but not yet
/// drained*) the streamed paths may exhibit. With incremental streaming (rmp #475) the server
/// materializes at most a few bounded egress chunks (≈ `STREAM_CHANNEL_CAP * STREAM_FLUSH_BYTES`) plus
/// per-response task overhead — sub-MiB; the generous 32 MiB bound clearly separates that from the
/// pre-fix behaviour, which materialized the **entire** body (≈ +585 MiB at 1M rows for JSON).
const STREAMING_RSS_BOUND_KIB: u64 = 32 * 1024;

/// JSON streaming path (rmp #475): a single auto-commit request returns ALL `n` rows (completeness),
/// and the server's resident memory stays **FLAT** as `n` grows — the body is streamed, never
/// materialized. The measurement holds each lazy `Response` *without draining it*: with streaming the
/// server has buffered ~nothing at that point; the pre-fix buffered path would have already
/// materialized the whole body inside the handler. The before/after curve is printed as evidence.
#[tokio::test]
async fn probe1_json_streamed_result_rss_is_bounded() {
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
        .await
        .into_body()
        .collect()
        .await;

    let baseline = vmrss_kib();
    println!("[AUDIT#472/rmp#475] PROBE 1 — JSON incremental streaming (bounded egress)");
    println!("[AUDIT#472/rmp#475]   baseline VmRSS = {baseline} KiB");
    println!(
        "[AUDIT#472/rmp#475]   rows | VmRSS held (pre-drain) | Δ vs baseline (server buffering)"
    );

    // Send each size and HOLD the lazy Response (do NOT drain) so the measured RSS reflects only what
    // the SERVER buffered. The lazy bodies are cheap channel receivers, so all three can be held at
    // once for a clean, cross-size comparison unconfounded by client-side `collect()` buffers.
    let mut held = Vec::new();
    for &n in &sizes {
        let resp = h.send(auto_commit_req(&token, "application/json", n)).await;
        assert_eq!(resp.status(), StatusCode::OK, "n={n}: 200 OK");
        assert_eq!(
            content_type(&resp),
            "application/json",
            "n={n}: JSON content type"
        );
        let after_holding = vmrss_kib();
        let delta = after_holding as i64 - baseline as i64;
        println!("[AUDIT#472/rmp#475]   {n:>9} | {after_holding:>9} KiB | {delta:>+8} KiB");
        held.push((n, resp, delta));
    }

    // BOUNDED-EGRESS ASSERTION: holding the largest result added only a bounded amount of resident
    // memory — the server did NOT materialize the whole body. (Pre-fix this delta was the full body
    // size, hundreds of MiB.)
    let (largest_n, _, largest_delta) = held.last().unwrap();
    assert!(
        *largest_delta < STREAMING_RSS_BOUND_KIB as i64,
        "PROBE 1 (JSON): holding the {largest_n}-row response added {largest_delta} KiB of resident \
         memory — streaming must keep this bounded (< {STREAMING_RSS_BOUND_KIB} KiB), independent of n"
    );

    // COMPLETENESS: draining each held response still yields EVERY row in a well-formed envelope, and
    // the largest body exceeds the 4 MiB request cap (the full result really is delivered — just
    // incrementally rather than buffered).
    let mut last_body_len = 0usize;
    for (n, resp, _) in held {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        last_body_len = bytes.len();
        let parsed: Json = serde_json::from_slice(&bytes).unwrap();
        let data_rows = parsed["results"][0]["data"].as_array().map_or(0, Vec::len);
        assert_eq!(
            data_rows as u64, n,
            "n={n}: all rows present in the streamed body"
        );
    }
    assert!(
        last_body_len as u64 > 4 * 1024 * 1024,
        "PROBE 1 (JSON): the streamed body for {} rows was {last_body_len} bytes — the full result \
         (larger than the 4 MiB request cap) is delivered incrementally, not buffered",
        sizes[2]
    );
}

/// NDJSON streaming path (rmp #475): framed `fields` + one `row` line per row + `summary`
/// (completeness via exact line count), with server RSS held **FLAT** as `n` grows. As with the JSON
/// probe, each lazy `Response` is held without draining so the measured RSS is the SERVER's buffering
/// only — bounded by the egress channel, independent of result size.
#[tokio::test]
async fn probe1_ndjson_streamed_result_rss_is_bounded() {
    let h = Harness::new();
    let token = h.token();

    let max_rows: u64 = std::env::var("GRAPHUS_AUDIT_MAX_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300_000);
    let sizes = [max_rows / 25, max_rows / 5, max_rows];

    let _ = h
        .send(auto_commit_req(&token, "application/x-ndjson", 1_000))
        .await
        .into_body()
        .collect()
        .await;

    let baseline = vmrss_kib();
    println!("[AUDIT#472/rmp#475] PROBE 1 — NDJSON incremental streaming (bounded egress)");
    println!("[AUDIT#472/rmp#475]   baseline VmRSS = {baseline} KiB");
    println!(
        "[AUDIT#472/rmp#475]   rows | VmRSS held (pre-drain) | Δ vs baseline (server buffering)"
    );

    let mut held = Vec::new();
    for &n in &sizes {
        let resp = h
            .send(auto_commit_req(&token, "application/x-ndjson", n))
            .await;
        assert_eq!(resp.status(), StatusCode::OK, "n={n}: 200 OK");
        assert_eq!(
            content_type(&resp),
            "application/x-ndjson",
            "n={n}: NDJSON content type"
        );
        let after_holding = vmrss_kib();
        let delta = after_holding as i64 - baseline as i64;
        println!("[AUDIT#472/rmp#475]   {n:>9} | {after_holding:>9} KiB | {delta:>+8} KiB");
        held.push((n, resp, delta));
    }

    // BOUNDED-EGRESS ASSERTION: holding the largest NDJSON result added only a bounded amount of
    // resident memory — the body is streamed, not assembled whole (pre-fix it was one `Vec<u8>`).
    let (largest_n, _, largest_delta) = held.last().unwrap();
    assert!(
        *largest_delta < STREAMING_RSS_BOUND_KIB as i64,
        "PROBE 1 (NDJSON): holding the {largest_n}-row response added {largest_delta} KiB of resident \
         memory — streaming must keep this bounded (< {STREAMING_RSS_BOUND_KIB} KiB), independent of n"
    );

    // COMPLETENESS: draining each held response yields exactly n+2 newline-terminated records (a
    // `fields` line, one `row` line per row, a `summary` line) — the whole result, framed incrementally.
    let mut last_body_len = 0usize;
    for (n, resp, _) in held {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        last_body_len = bytes.len();
        let lines = bytes.iter().filter(|&&b| b == b'\n').count() as u64;
        assert_eq!(lines, n + 2, "n={n}: fields + n rows + summary = n+2 lines");
    }
    assert!(
        last_body_len as u64 > 4 * 1024 * 1024,
        "PROBE 1 (NDJSON): the streamed NDJSON body for {} rows was {last_body_len} bytes — the full \
         result (larger than the 4 MiB request cap) is delivered incrementally, not buffered",
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
