//! `scenarios` — a named, documented catalogue of **known graph-DB usage patterns** exercised through
//! the deterministic simulator (rmp #173). It demonstrates breadth ("test all the known scenarios")
//! and is the CI-friendly entry point: [`run_sweep`] runs every scenario across a seed range and
//! reports pass/fail.
//!
//! Each scenario drives the *real* engine (inline, deterministic) and checks an oracle appropriate to
//! it (row counts, `created == persisted`, no spurious errors, SSI conflict detection). The workload
//! scenarios reuse [`crate::vopr`] + [`crate::mix`]; the structural ones drive a [`LocalEngine`]
//! directly. Everything is a pure function of the seed.

use std::collections::HashMap;
use std::sync::Arc;

use graphus_bulk::{ColumnRole, ImportStats, NodeHeader, PropertyType, RelHeader, ScalarType};
use graphus_core::{GraphusError, Value};
use graphus_cypher::MaterializedValue;
use graphus_elle::{Op, Transaction, check};
use graphus_io::{MemBlockDevice, atomic_replace_file};
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{
    BulkImportBatchInput, BulkImportBatchOutcome, BulkImportModeBChunkInput, LocalEngine, TxTicket,
};
use graphus_sim::{ClockFaultPlan, FaultyClock, SharedClock};
use graphus_wal::MemLogSink;

use crate::mix::{LoadProfile, MixProfile};
use crate::vopr::{self, VoprConfig};

type Eng = LocalEngine<MemBlockDevice, MemLogSink>;

/// The outcome of running one scenario at one seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioOutcome {
    /// The scenario's stable name.
    pub name: &'static str,
    /// Whether its oracle held.
    pub ok: bool,
    /// A short, reproducible detail line.
    pub detail: String,
}

impl ScenarioOutcome {
    fn pass(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            ok: true,
            detail: detail.into(),
        }
    }
    fn fail(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            ok: false,
            detail: detail.into(),
        }
    }
}

/// A scenario: a deterministic function of the seed returning its outcome.
pub type Scenario = fn(u64) -> ScenarioOutcome;

/// The full catalogue of `(name, scenario)` pairs.
///
/// The catalogue spans the production-readiness dimensions a graph database must satisfy under
/// **extreme concurrency and load** (see `specification/07-dst-simulator.md` §7):
///
/// - **OLTP / ingest / serving** — `oltp_mixed`, `bulk_ingest`, `read_serving`.
/// - **Traversal / structural** — `deep_traversal`, `supernode_fanout`, `large_result_stream`,
///   `cyclic_traversal`.
/// - **Index / aggregation** — `indexed_point_lookup`, `aggregation_analytics`.
/// - **Isolation / concurrency** — `contended_writes`, `concurrent_supernode`, `snapshot_isolation`.
/// - **Property / secondary index** — `property_index_oracle` (rmp #461: SET/DELETE churn under
///   contention cross-checked for property values + indexed-seek-vs-scan consistency).
/// - **Atomicity / churn** — `transaction_rollback`, `churn_create_delete`.
/// - **Durability / crash recovery** — `crash_recovery_durability`, `backup_restore_crash` (rmp #440:
///   a crash injected at each window of the backup → seal → file → restore → WAL/DWB-reset pipeline).
/// - **Network bulk import** — `network_bulk_ingest_mode_a` (rmp #519: per-batch cumulative-stats
///   correctness, an aborted-batch idempotent retry, and crash-mid-session durability of both the
///   ingested data and the checkpoint sentinel node, for `08-network-bulk-import.md` Mode A);
///   `network_bulk_ingest_mode_b` (rmp #520: Mode A's concurrent, higher-risk sibling — joint
///   serializability with ordinary concurrent traffic (Elle-checked), a seeded genuine SSI pivot
///   abort + idempotent retry, exact snapshot-visibility, a dense/hot pre-existing node targeted by
///   both the import and concurrent traffic, the chunking-bounds-a-dispatch mechanism, and crash
///   recovery mid-batch interleaved with other committing transactions).
/// - **Time / hostile clock** — `hostile_clock` (bounded skew, forward jumps, non-monotonic
///   regressions; the clock-fault tolerance contract of rmp #233).
/// - **Load shapes** — `spike_load`, `ramp_load`, `sustained_high_concurrency`.
#[must_use]
pub fn catalogue() -> Vec<(&'static str, Scenario)> {
    vec![
        // OLTP / ingest / serving
        ("oltp_mixed", oltp_mixed),
        ("bulk_ingest", bulk_ingest),
        ("read_serving", read_serving),
        // Traversal / structural
        ("deep_traversal", deep_traversal),
        ("supernode_fanout", supernode_fanout),
        ("large_result_stream", large_result_stream),
        ("cyclic_traversal", cyclic_traversal),
        // Lookup / aggregation
        ("point_lookup", point_lookup),
        ("aggregation_analytics", aggregation_analytics),
        // Isolation / concurrency
        ("contended_writes", contended_writes),
        ("concurrent_supernode", concurrent_supernode),
        ("snapshot_isolation", snapshot_isolation),
        // Property / secondary index (rmp #461)
        ("property_index_oracle", property_index_oracle),
        // Atomicity / churn
        ("transaction_rollback", transaction_rollback),
        ("churn_create_delete", churn_create_delete),
        // Durability / crash recovery
        ("crash_recovery_durability", crash_recovery_durability),
        ("backup_restore_crash", backup_restore_crash),
        // Network bulk import (rmp #519/#520)
        ("network_bulk_ingest_mode_a", network_bulk_ingest_mode_a),
        ("network_bulk_ingest_mode_b", network_bulk_ingest_mode_b),
        // Time / hostile clock
        ("hostile_clock", hostile_clock),
        // Load shapes
        ("spike_load", spike_load),
        ("ramp_load", ramp_load),
        ("sustained_high_concurrency", sustained_high_concurrency),
    ]
}

/// Runs every catalogue scenario for every seed in `seeds`, returning all outcomes (in a stable
/// order). A `false` `ok` anywhere is a scenario failure.
#[must_use]
pub fn run_sweep(seeds: impl IntoIterator<Item = u64>) -> Vec<ScenarioOutcome> {
    let cat = catalogue();
    let mut out = Vec::new();
    for seed in seeds {
        for (_, scenario) in &cat {
            out.push(scenario(seed));
        }
    }
    out
}

// ---- helpers -------------------------------------------------------------------------------------

fn engine() -> Eng {
    LocalEngine::in_memory(Arc::new(SharedClock::new(0)), 256).expect("engine")
}

/// Builds an engine while keeping a handle to its [`SharedClock`], so the caller can drive
/// [`LocalEngine::crash_restart`] (which needs a clock for the recovered engine).
fn engine_with_clock(pool_pages: usize) -> (Eng, Arc<SharedClock>) {
    let clock = Arc::new(SharedClock::new(0));
    let eng = LocalEngine::in_memory(clock.clone(), pool_pages).expect("engine");
    (eng, clock)
}

/// Builds an engine over a seed-driven [`FaultyClock`] (the hostile-clock scenario). Returns the
/// engine plus a handle to the *inner* [`SharedClock`], which the caller advances to drive logical
/// time forward; the [`FaultyClock`] perturbs every reading the engine takes (bounded skew, forward
/// jumps, non-monotonic regressions), all a pure function of `seed`.
fn engine_with_faulty_clock(seed: u64, pool_pages: usize) -> (Eng, Arc<SharedClock>) {
    let inner = Arc::new(SharedClock::new(0));
    // A genuinely hostile but bounded plan: a constant skew, frequent forward jumps, and frequent
    // backward regressions — exactly the readings the engine's `saturating_sub` duration arithmetic
    // must tolerate without ever producing a negative duration or a panic.
    let plan = ClockFaultPlan::new(seed)
        .with_skew(1_000_000) // ±1 ms constant skew
        .with_forward_jumps(300, 5_000_000) // 30% of reads jump up to +5 ms
        .with_regressions(300, 2_000_000); // 30% of reads step back up to 2 ms
    let clock = Arc::new(FaultyClock::new(SharedClock::clone(&inner), plan));
    let eng = LocalEngine::in_memory(clock, pool_pages).expect("engine");
    (eng, inner)
}

/// Runs an auto-commit write, returning whether it succeeded.
fn write(eng: &mut Eng, stmt: &str, params: Vec<(String, Value)>) -> bool {
    let Ok(ticket) = eng.begin_auto_commit(AccessMode::Write) else {
        return false;
    };
    match eng.run(ticket, stmt, params, true, None) {
        Ok(mut reply) => {
            while let Ok(Some(_)) = reply.rows.next() {}
            true
        }
        Err(_) => false,
    }
}

/// Runs an auto-commit read, returning the number of rows produced.
fn count_rows(eng: &mut Eng, stmt: &str, params: Vec<(String, Value)>) -> usize {
    let Ok(ticket) = eng.begin_auto_commit(AccessMode::Read) else {
        return usize::MAX;
    };
    match eng.run(ticket, stmt, params, true, None) {
        Ok(mut reply) => {
            let mut n = 0;
            while let Ok(Some(_)) = reply.rows.next() {
                n += 1;
            }
            n
        }
        Err(_) => usize::MAX,
    }
}

/// Runs an auto-commit read over an engine built on **any** block device (rmp #440 restore opens the
/// restored store over a [`graphus_io::FileBlockDevice`], not the in-memory device), returning the row
/// count. The generic mirror of [`count_rows`].
fn count_rows_dev<D: graphus_io::BlockDevice + Send + Sync + 'static>(
    eng: &mut LocalEngine<D, MemLogSink>,
    stmt: &str,
    params: Vec<(String, Value)>,
) -> usize {
    let Ok(ticket) = eng.begin_auto_commit(AccessMode::Read) else {
        return usize::MAX;
    };
    match eng.run(ticket, stmt, params, true, None) {
        Ok(mut reply) => {
            let mut n = 0;
            while let Ok(Some(_)) = reply.rows.next() {
                n += 1;
            }
            n
        }
        Err(_) => usize::MAX,
    }
}

/// Reads a single integer scalar (first cell of the first row), or `None`.
fn read_scalar(eng: &mut Eng, stmt: &str, params: Vec<(String, Value)>) -> Option<i64> {
    let ticket = eng.begin_auto_commit(AccessMode::Read).ok()?;
    let mut reply = eng.run(ticket, stmt, params, true, None).ok()?;
    let mut v = None;
    while let Ok(Some(row)) = reply.rows.next() {
        if let Some(MaterializedValue::Value(Value::Integer(n))) = row.first() {
            v = Some(*n);
        }
    }
    v
}

/// Reads a single integer scalar within an **already-open** transaction `ticket` (no auto-commit), so
/// the same transaction can observe the graph more than once. Returns `None` on error/empty.
fn scalar_in(
    eng: &mut Eng,
    ticket: graphus_server::engine::TxTicket,
    stmt: &str,
    params: Vec<(String, Value)>,
) -> Option<i64> {
    let mut reply = eng.run(ticket, stmt, params, false, None).ok()?;
    let mut v = None;
    while let Ok(Some(row)) = reply.rows.next() {
        if let Some(MaterializedValue::Value(Value::Integer(n))) = row.first() {
            v = Some(*n);
        }
    }
    v
}

// ---- workload scenarios (reuse the VOPR runner) --------------------------------------------------

/// Balanced OLTP traffic: a mixed read/write workload runs cleanly, is internally consistent
/// (`created == persisted`), and replays identically.
fn oltp_mixed(seed: u64) -> ScenarioOutcome {
    // These workload-shape scenarios certify clean per-op liveness, so they run on the legacy
    // auto-commit path; the explicit-transaction interleaver's contention is certified by the `vopr`
    // unit tests, not here.
    let cfg = VoprConfig::for_seed(seed)
        .with_mix(MixProfile::mixed())
        .with_load(LoadProfile::Steady { min: 1, max: 30 })
        .auto_commit_only();
    let a = vopr::run(cfg);
    let b = vopr::run(cfg);
    if a != b {
        return ScenarioOutcome::fail("oltp_mixed", "non-deterministic run");
    }
    if a.err_ops != 0 {
        return ScenarioOutcome::fail("oltp_mixed", format!("{} spurious errors", a.err_ops));
    }
    if a.created_nodes != a.persisted_nodes {
        return ScenarioOutcome::fail(
            "oltp_mixed",
            format!(
                "created {} != persisted {}",
                a.created_nodes, a.persisted_nodes
            ),
        );
    }
    ScenarioOutcome::pass(
        "oltp_mixed",
        format!("{} ops, {} nodes", a.steps, a.persisted_nodes),
    )
}

/// Bulk ingest: a write-heavy workload persists every acked create.
fn bulk_ingest(seed: u64) -> ScenarioOutcome {
    let cfg = VoprConfig::for_seed(seed)
        .with_mix(MixProfile::write_heavy())
        .auto_commit_only();
    let r = vopr::run(cfg);
    if r.created_nodes == r.persisted_nodes && r.err_ops == 0 {
        ScenarioOutcome::pass(
            "bulk_ingest",
            format!("ingested {} nodes", r.persisted_nodes),
        )
    } else {
        ScenarioOutcome::fail(
            "bulk_ingest",
            format!(
                "created {} persisted {} errs {}",
                r.created_nodes, r.persisted_nodes, r.err_ops
            ),
        )
    }
}

/// Read-serving: a read-heavy workload runs without spurious errors and is deterministic.
fn read_serving(seed: u64) -> ScenarioOutcome {
    let cfg = VoprConfig::for_seed(seed)
        .with_mix(MixProfile::read_heavy())
        .auto_commit_only();
    let a = vopr::run(cfg);
    let b = vopr::run(cfg);
    if a == b && a.err_ops == 0 {
        ScenarioOutcome::pass("read_serving", format!("{} ops served", a.steps))
    } else {
        ScenarioOutcome::fail("read_serving", format!("errs {} det {}", a.err_ops, a == b))
    }
}

// ---- structural scenarios (drive the engine directly) --------------------------------------------

/// Deep traversal: build a chain `n0-[:NEXT]->n1->…->nN` and traverse it variable-length, expecting
/// to reach the tail.
fn deep_traversal(seed: u64) -> ScenarioOutcome {
    const N: i64 = 20;
    let mut eng = engine();
    // Build the chain. (Seed only varies the starting id base, keeping it a pure function of seed.)
    let base = (seed % 1000) as i64;
    for i in 0..=N {
        if !write(
            &mut eng,
            "CREATE (:Node {id: $id})",
            vec![("id".into(), Value::Integer(base + i))],
        ) {
            return ScenarioOutcome::fail("deep_traversal", "create node failed");
        }
    }
    for i in 0..N {
        let ok = write(
            &mut eng,
            "MATCH (a:Node {id: $a}), (b:Node {id: $b}) CREATE (a)-[:NEXT]->(b)",
            vec![
                ("a".into(), Value::Integer(base + i)),
                ("b".into(), Value::Integer(base + i + 1)),
            ],
        );
        if !ok {
            return ScenarioOutcome::fail("deep_traversal", "create edge failed");
        }
    }
    // Reachable set from the head via 1..N hops should include the tail.
    let reached = count_rows(
        &mut eng,
        "MATCH (a:Node {id: $a})-[:NEXT*1..50]->(b) RETURN b",
        vec![("a".into(), Value::Integer(base))],
    );
    if reached >= N as usize {
        ScenarioOutcome::pass(
            "deep_traversal",
            format!("reached {reached} via var-length"),
        )
    } else {
        ScenarioOutcome::fail("deep_traversal", format!("only reached {reached} of {N}"))
    }
}

/// Supernode / hotspot: one hub with a large fan-out; counting its out-edges returns the fan-out.
fn supernode_fanout(seed: u64) -> ScenarioOutcome {
    const M: i64 = 60;
    let mut eng = engine();
    let base = (seed % 1000) as i64;
    if !write(
        &mut eng,
        "CREATE (:Hub {id: $id})",
        vec![("id".into(), Value::Integer(base))],
    ) {
        return ScenarioOutcome::fail("supernode_fanout", "create hub failed");
    }
    for i in 0..M {
        let ok = write(
            &mut eng,
            "MATCH (h:Hub {id: $h}) CREATE (h)-[:LINK]->(:Leaf {id: $l})",
            vec![
                ("h".into(), Value::Integer(base)),
                ("l".into(), Value::Integer(base * 1000 + i)),
            ],
        );
        if !ok {
            return ScenarioOutcome::fail("supernode_fanout", "create leaf failed");
        }
    }
    let fanout = read_scalar(
        &mut eng,
        "MATCH (h:Hub {id: $h})-[:LINK]->(x) RETURN count(x) AS c",
        vec![("h".into(), Value::Integer(base))],
    );
    if fanout == Some(M) {
        ScenarioOutcome::pass("supernode_fanout", format!("fan-out {M}"))
    } else {
        ScenarioOutcome::fail("supernode_fanout", format!("fan-out {fanout:?} != {M}"))
    }
}

/// Large result streaming: create many nodes and stream them all back in one query.
fn large_result_stream(seed: u64) -> ScenarioOutcome {
    const N: usize = 200;
    let mut eng = engine();
    let base = (seed % 1000) as i64;
    for i in 0..N as i64 {
        if !write(
            &mut eng,
            "CREATE (:Item {id: $id})",
            vec![("id".into(), Value::Integer(base + i))],
        ) {
            return ScenarioOutcome::fail("large_result_stream", "create failed");
        }
    }
    let rows = count_rows(&mut eng, "MATCH (n:Item) RETURN n", vec![]);
    if rows == N {
        ScenarioOutcome::pass("large_result_stream", format!("streamed {rows} rows"))
    } else {
        ScenarioOutcome::fail("large_result_stream", format!("streamed {rows} != {N}"))
    }
}

/// Contended concurrent writes: two transactions update the same node; SSI must not let both commit.
/// (Survivor-value durability is the known gap rmp #172 — not asserted here.)
fn contended_writes(seed: u64) -> ScenarioOutcome {
    let mut eng = engine();
    let base = (seed % 1000) as i64;
    let s = match eng.begin(AccessMode::Write) {
        Ok(t) => t,
        Err(_) => return ScenarioOutcome::fail("contended_writes", "begin setup failed"),
    };
    let _ = eng.run(
        s,
        "CREATE (:Acct {id: $id, bal: 100})",
        vec![("id".into(), Value::Integer(base))],
        false,
        None,
    );
    if eng.commit(s).is_err() {
        return ScenarioOutcome::fail("contended_writes", "commit setup failed");
    }
    let (Ok(t1), Ok(t2)) = (eng.begin(AccessMode::Write), eng.begin(AccessMode::Write)) else {
        return ScenarioOutcome::fail("contended_writes", "begin txns failed");
    };
    for t in [t1, t2] {
        if let Ok(mut r) = eng.run(
            t,
            "MATCH (a:Acct {id: $id}) SET a.bal = a.bal - 10",
            vec![("id".into(), Value::Integer(base))],
            false,
            None,
        ) {
            while let Ok(Some(_)) = r.rows.next() {}
        }
    }
    let c1 = eng.commit(t1).is_ok();
    let c2 = eng.commit(t2).is_ok();
    if c1 && c2 {
        ScenarioOutcome::fail(
            "contended_writes",
            "both concurrent writers committed (lost update)",
        )
    } else {
        ScenarioOutcome::pass(
            "contended_writes",
            format!("conflict detected (c1={c1} c2={c2})"),
        )
    }
}

/// Cyclic traversal: build a directed cycle `n0->n1->…->n(C-1)->n0` and traverse it variable-length.
/// Cypher relationship-uniqueness bounds the walk, so it **must terminate** (no hang) and every node
/// in the cycle is reachable from the head. Certifies the traversal engine is live on cyclic graphs.
fn cyclic_traversal(seed: u64) -> ScenarioOutcome {
    const C: i64 = 12;
    let mut eng = engine();
    let base = (seed % 1000) as i64;
    for i in 0..C {
        if !write(
            &mut eng,
            "CREATE (:Ring {id: $id})",
            vec![("id".into(), Value::Integer(base + i))],
        ) {
            return ScenarioOutcome::fail("cyclic_traversal", "create node failed");
        }
    }
    for i in 0..C {
        let a = base + i;
        let b = base + (i + 1) % C; // wrap to close the cycle
        let ok = write(
            &mut eng,
            "MATCH (a:Ring {id: $a}), (b:Ring {id: $b}) CREATE (a)-[:NEXT]->(b)",
            vec![
                ("a".into(), Value::Integer(a)),
                ("b".into(), Value::Integer(b)),
            ],
        );
        if !ok {
            return ScenarioOutcome::fail("cyclic_traversal", "create edge failed");
        }
    }
    // Distinct nodes reachable from the head along 1..N hops: in a single cycle that is every node.
    let reached = count_rows(
        &mut eng,
        "MATCH (a:Ring {id: $a})-[:NEXT*1..50]->(b) RETURN DISTINCT b.id",
        vec![("a".into(), Value::Integer(base))],
    );
    if reached == C as usize {
        ScenarioOutcome::pass(
            "cyclic_traversal",
            format!("reached all {C} cycle nodes (terminated)"),
        )
    } else {
        ScenarioOutcome::fail(
            "cyclic_traversal",
            format!("reached {reached} distinct of {C}"),
        )
    }
}

/// Point lookup: populate `:Item(id)`, then probe several exact keys by property equality. Each hit
/// must return exactly one row and a miss exactly zero. Certifies the serving-path equality-lookup is
/// exact (no missing/duplicate results). (Cypher index DDL is not part of the query surface here, so
/// this certifies the lookup semantics, not the physical index plan.)
fn point_lookup(seed: u64) -> ScenarioOutcome {
    const N: i64 = 50;
    let mut eng = engine();
    let base = (seed % 1000) as i64;
    for i in 0..N {
        if !write(
            &mut eng,
            "CREATE (:Item {id: $id})",
            vec![("id".into(), Value::Integer(base + i))],
        ) {
            return ScenarioOutcome::fail("point_lookup", "create item failed");
        }
    }
    // Probe a deterministic spread of keys; each must resolve to exactly one node.
    for k in [0, N / 3, N / 2, N - 1] {
        let rows = count_rows(
            &mut eng,
            "MATCH (n:Item {id: $id}) RETURN n.id",
            vec![("id".into(), Value::Integer(base + k))],
        );
        if rows != 1 {
            return ScenarioOutcome::fail(
                "point_lookup",
                format!("lookup id={} returned {rows} rows (expected 1)", base + k),
            );
        }
    }
    // A miss must return zero rows.
    let miss = count_rows(
        &mut eng,
        "MATCH (n:Item {id: $id}) RETURN n.id",
        vec![("id".into(), Value::Integer(base + N + 1000))],
    );
    if miss != 0 {
        return ScenarioOutcome::fail("point_lookup", format!("miss returned {miss} rows"));
    }
    ScenarioOutcome::pass("point_lookup", format!("{N} keys, exact lookups + miss"))
}

/// Aggregation / analytics: populate the graph, then a global `count(n)` must return the exact total.
/// Certifies OLAP-style aggregate reads are accurate over the full dataset.
fn aggregation_analytics(seed: u64) -> ScenarioOutcome {
    const N: i64 = 120;
    let mut eng = engine();
    let base = (seed % 1000) as i64;
    for i in 0..N {
        if !write(
            &mut eng,
            "CREATE (:Metric {id: $id})",
            vec![("id".into(), Value::Integer(base + i))],
        ) {
            return ScenarioOutcome::fail("aggregation_analytics", "create failed");
        }
    }
    let total = read_scalar(&mut eng, "MATCH (n:Metric) RETURN count(n) AS c", vec![]);
    if total == Some(N) {
        ScenarioOutcome::pass("aggregation_analytics", format!("count = {N}"))
    } else {
        ScenarioOutcome::fail("aggregation_analytics", format!("count {total:?} != {N}"))
    }
}

/// Concurrent supernode hotspot: two writers concurrently create an edge on the **same** hub. Both
/// must commit and **both edges must persist** (`fan-out == committed`) — no committed edge is lost.
/// Certifies the supported single-node write-concurrency guarantee.
///
/// Concurrency is a **supported, commutative** workload at every degree (`rmp` #220, FIXED): with
/// **three or more** concurrently-open writers on one node, SSI may abort some pivots, but every edge
/// that commits survives — `fan-out == committed`, never 0. The storage-layer fix (chain-head
/// compare-and-set logical undo + header-only creation undo + monotonic catalog floor on rollback)
/// guarantees an aborted writer's rollback never clobbers a concurrently-committed writer's edge. The
/// high-concurrency arm is exercised by [`tests::supernode_high_concurrency_keeps_committed_edges_guards_220`].
fn concurrent_supernode(seed: u64) -> ScenarioOutcome {
    let mut eng = engine();
    let base = (seed % 1000) as i64;
    if !write(
        &mut eng,
        "CREATE (:Hub {id: $id})",
        vec![("id".into(), Value::Integer(base))],
    ) {
        return ScenarioOutcome::fail("concurrent_supernode", "create hub failed");
    }
    let (committed, fanout) = two_concurrent_edge_writers(&mut eng, base);
    if committed == 2 && fanout == Some(2) {
        ScenarioOutcome::pass(
            "concurrent_supernode",
            "2 concurrent writers, both edges persisted",
        )
    } else {
        ScenarioOutcome::fail(
            "concurrent_supernode",
            format!("committed {committed} fan-out {fanout:?} (want 2 and 2)"),
        )
    }
}

/// Opens two concurrent write transactions, each creating one `:LINK` edge from `Hub {id: base}` to a
/// fresh leaf, commits both, and returns `(commits_ok, persisted_fan_out)`. Shared by the scenario and
/// the #220 regression pin.
fn two_concurrent_edge_writers(eng: &mut Eng, base: i64) -> (i64, Option<i64>) {
    let (Ok(t1), Ok(t2)) = (eng.begin(AccessMode::Write), eng.begin(AccessMode::Write)) else {
        return (-1, None);
    };
    for (t, l) in [(t1, base * 1000), (t2, base * 1000 + 1)] {
        if let Ok(mut r) = eng.run(
            t,
            "MATCH (h:Hub {id: $h}) CREATE (h)-[:LINK]->(:Leaf {id: $l})",
            vec![
                ("h".into(), Value::Integer(base)),
                ("l".into(), Value::Integer(l)),
            ],
            false,
            None,
        ) {
            while let Ok(Some(_)) = r.rows.next() {}
        }
    }
    let committed = i64::from(eng.commit(t1).is_ok()) + i64::from(eng.commit(t2).is_ok());
    let fanout = read_scalar(
        eng,
        "MATCH (h:Hub {id: $h})-[:LINK]->(x) RETURN count(x) AS c",
        vec![("h".into(), Value::Integer(base))],
    );
    (committed, fanout)
}

/// One concurrency degree's outcome from a supernode degree sweep: the degree `k`, how many of the `k`
/// concurrently-open writers committed, and the persisted hub fan-out afterwards (rmp #462).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DegreeOutcome {
    /// The number of concurrently-open write transactions for this rung.
    pub k: i64,
    /// How many of them committed (the rest were SSI-aborted).
    pub committed: i64,
    /// The hub's persisted out-edge count after all commits (must equal `committed`, never 0).
    pub fanout: Option<i64>,
}

/// **Reusable `#220` supernode degree sweep (rmp #462, F-DST-5).** Promotes the previously-hardcoded
/// `K ∈ {2,3,4,6,8,12,16,24}` regression sweep into a parameterised routine: for each degree in
/// `degrees`, opens `k` concurrently-open write transactions that each create one `:LINK` edge on the
/// **same** hub, commits them all, and records `(k, committed, fanout)`. A fresh engine per rung keeps
/// the rungs independent. The safety invariant a caller asserts is `fanout == committed` (every
/// committed edge survives) at every rung — but the routine itself is policy-free, so it can drive the
/// regression guard, an exploratory wider sweep, or a swarmed corner without duplicating the loop.
#[must_use]
pub fn supernode_degree_sweep(degrees: &[i64]) -> Vec<DegreeOutcome> {
    let mut out = Vec::with_capacity(degrees.len());
    for &k in degrees {
        let mut eng = engine();
        let _ = write(&mut eng, "CREATE (:Hub {id: 1})", vec![]);
        let mut tickets = Vec::new();
        for i in 0..k {
            let Ok(t) = eng.begin(AccessMode::Write) else {
                continue;
            };
            if let Ok(mut r) = eng.run(
                t,
                "MATCH (h:Hub {id: 1}) CREATE (h)-[:LINK]->(:Leaf {id: $l})",
                vec![("l".into(), Value::Integer(100 + i))],
                false,
                None,
            ) {
                while let Ok(Some(_)) = r.rows.next() {}
            }
            tickets.push(t);
        }
        let committed: i64 = tickets
            .into_iter()
            .map(|t| i64::from(eng.commit(t).is_ok()))
            .sum();
        let fanout = read_scalar(
            &mut eng,
            "MATCH (h:Hub {id: 1})-[:LINK]->(x) RETURN count(x) AS c",
            vec![],
        );
        out.push(DegreeOutcome {
            k,
            committed,
            fanout,
        });
    }
    out
}

/// Snapshot isolation: a read transaction's view must be **stable** while a concurrent writer commits
/// new data. The reader counts a label, a second transaction inserts and commits, and the reader
/// counts again within the *same* transaction — the two counts must match (repeatable read). After
/// the reader ends, a fresh read observes the new row. Certifies MVCC snapshot stability.
fn snapshot_isolation(seed: u64) -> ScenarioOutcome {
    let mut eng = engine();
    let base = (seed % 1000) as i64;
    // Baseline: one Acct.
    if !write(
        &mut eng,
        "CREATE (:Snap {id: $id})",
        vec![("id".into(), Value::Integer(base))],
    ) {
        return ScenarioOutcome::fail("snapshot_isolation", "setup failed");
    }
    // Open a long-lived reader and take its first observation.
    let Ok(reader) = eng.begin(AccessMode::Read) else {
        return ScenarioOutcome::fail("snapshot_isolation", "begin reader failed");
    };
    let first = scalar_in(
        &mut eng,
        reader,
        "MATCH (n:Snap) RETURN count(n) AS c",
        vec![],
    );
    // A concurrent writer inserts and commits a new node.
    let Ok(writer) = eng.begin(AccessMode::Write) else {
        return ScenarioOutcome::fail("snapshot_isolation", "begin writer failed");
    };
    if let Ok(mut r) = eng.run(
        writer,
        "CREATE (:Snap {id: $id})",
        vec![("id".into(), Value::Integer(base + 1))],
        false,
        None,
    ) {
        while let Ok(Some(_)) = r.rows.next() {}
    }
    if eng.commit(writer).is_err() {
        return ScenarioOutcome::fail("snapshot_isolation", "writer commit failed");
    }
    // The reader re-observes: its snapshot must be unchanged (repeatable read).
    let second = scalar_in(
        &mut eng,
        reader,
        "MATCH (n:Snap) RETURN count(n) AS c",
        vec![],
    );
    let _ = eng.commit(reader); // close the read transaction (read-only, may also rollback)
    if first != second {
        return ScenarioOutcome::fail(
            "snapshot_isolation",
            format!("reader snapshot moved: {first:?} -> {second:?}"),
        );
    }
    // A fresh reader now sees the committed write.
    let after = read_scalar(&mut eng, "MATCH (n:Snap) RETURN count(n) AS c", vec![]);
    if first == Some(1) && after == Some(2) {
        ScenarioOutcome::pass(
            "snapshot_isolation",
            "snapshot stable across concurrent commit",
        )
    } else {
        ScenarioOutcome::fail(
            "snapshot_isolation",
            format!("first {first:?} after {after:?} (expected 1 then 2)"),
        )
    }
}

/// Property + secondary-index oracle (rmp #461): drives a contended `CREATE`/`SET rank`/`CREATE edge`/
/// `DETACH DELETE` workload over a declared `(Person, rank)` index and, on every commit, cross-checks
/// the engine against the extended reference model for (a) **property values**, (b) the **indexed
/// `rank` seek vs the model**, and (c) the **indexed seek vs a forced full scan** (index-vs-base-store
/// consistency — the surface of rmp #313/#316). Closes the oracle's blindness to property values,
/// secondary indexes, and delete churn. The driver lives in [`crate::vopr_property`].
fn property_index_oracle(seed: u64) -> ScenarioOutcome {
    let a = crate::vopr_property::run(seed);
    let b = crate::vopr_property::run(seed);
    if a != b {
        return ScenarioOutcome::fail("property_index_oracle", "non-deterministic run");
    }
    if a.ok {
        ScenarioOutcome::pass("property_index_oracle", a.detail)
    } else {
        ScenarioOutcome::fail("property_index_oracle", a.detail)
    }
}

/// Transaction rollback (atomicity): writes in a rolled-back transaction must leave **no** trace.
/// Certifies all-or-nothing atomicity.
fn transaction_rollback(seed: u64) -> ScenarioOutcome {
    let mut eng = engine();
    let base = (seed % 1000) as i64;
    let Ok(t) = eng.begin(AccessMode::Write) else {
        return ScenarioOutcome::fail("transaction_rollback", "begin failed");
    };
    if let Ok(mut r) = eng.run(
        t,
        "CREATE (:Ghost {id: $id})",
        vec![("id".into(), Value::Integer(base))],
        false,
        None,
    ) {
        while let Ok(Some(_)) = r.rows.next() {}
    }
    if eng.rollback(t).is_err() {
        return ScenarioOutcome::fail("transaction_rollback", "rollback failed");
    }
    let rows = count_rows(&mut eng, "MATCH (n:Ghost) RETURN n", vec![]);
    if rows == 0 {
        ScenarioOutcome::pass("transaction_rollback", "rolled-back write left no trace")
    } else {
        ScenarioOutcome::fail(
            "transaction_rollback",
            format!("{rows} ghost rows after rollback"),
        )
    }
}

/// Create/delete churn: create N nodes, `DETACH DELETE` them all, then create N again. The count must
/// return to the baseline at each step, proving deletes are honoured and storage is reused (free-list)
/// without leaking. The final state is deterministic per seed.
fn churn_create_delete(seed: u64) -> ScenarioOutcome {
    const N: i64 = 60;
    let mut eng = engine();
    let base = (seed % 1000) as i64;
    let make = |eng: &mut Eng, off: i64| -> bool {
        for i in 0..N {
            if !write(
                eng,
                "CREATE (:Churn {id: $id})",
                vec![("id".into(), Value::Integer(base + off + i))],
            ) {
                return false;
            }
        }
        true
    };
    if !make(&mut eng, 0) {
        return ScenarioOutcome::fail("churn_create_delete", "first ingest failed");
    }
    if count_rows(&mut eng, "MATCH (n:Churn) RETURN n", vec![]) != N as usize {
        return ScenarioOutcome::fail("churn_create_delete", "first count != N");
    }
    if !write(&mut eng, "MATCH (n:Churn) DETACH DELETE n", vec![]) {
        return ScenarioOutcome::fail("churn_create_delete", "delete failed");
    }
    if count_rows(&mut eng, "MATCH (n:Churn) RETURN n", vec![]) != 0 {
        return ScenarioOutcome::fail("churn_create_delete", "count != 0 after delete");
    }
    // Re-create (exercises free-list reuse).
    if !make(&mut eng, 1000) {
        return ScenarioOutcome::fail("churn_create_delete", "second ingest failed");
    }
    if count_rows(&mut eng, "MATCH (n:Churn) RETURN n", vec![]) == N as usize {
        ScenarioOutcome::pass(
            "churn_create_delete",
            format!("churned {N} twice, baseline restored"),
        )
    } else {
        ScenarioOutcome::fail("churn_create_delete", "second count != N")
    }
}

/// Durability under crash/restart: an **acked commit must survive** a crash, and **uncommitted work
/// must not**. Drives [`LocalEngine::crash_restart`] (ARIES recovery from the durable WAL). Certifies
/// the core ACID durability guarantee under fault.
fn crash_recovery_durability(seed: u64) -> ScenarioOutcome {
    let (mut eng, clock) = engine_with_clock(256);
    let base = (seed % 1000) as i64;
    // Committed write (must survive).
    let Ok(c) = eng.begin(AccessMode::Write) else {
        return ScenarioOutcome::fail("crash_recovery_durability", "begin committed failed");
    };
    if let Ok(mut r) = eng.run(
        c,
        "CREATE (:Durable {id: $id})",
        vec![("id".into(), Value::Integer(base))],
        false,
        None,
    ) {
        while let Ok(Some(_)) = r.rows.next() {}
    }
    if eng.commit(c).is_err() {
        return ScenarioOutcome::fail("crash_recovery_durability", "commit failed");
    }
    // Uncommitted write (must NOT survive): begin + write, then crash without committing.
    let Ok(u) = eng.begin(AccessMode::Write) else {
        return ScenarioOutcome::fail("crash_recovery_durability", "begin uncommitted failed");
    };
    if let Ok(mut r) = eng.run(
        u,
        "CREATE (:Durable {id: $id})",
        vec![("id".into(), Value::Integer(base + 1))],
        false,
        None,
    ) {
        while let Ok(Some(_)) = r.rows.next() {}
    }
    // Crash + recover purely from the durable WAL.
    let mut recovered = match eng.crash_restart(clock.clone(), 256) {
        Ok(e) => e,
        Err(_) => {
            return ScenarioOutcome::fail("crash_recovery_durability", "crash_restart failed");
        }
    };
    let survived = count_rows(
        &mut recovered,
        "MATCH (n:Durable {id: $id}) RETURN n",
        vec![("id".into(), Value::Integer(base))],
    );
    let leaked = count_rows(
        &mut recovered,
        "MATCH (n:Durable {id: $id}) RETURN n",
        vec![("id".into(), Value::Integer(base + 1))],
    );
    if survived == 1 && leaked == 0 {
        ScenarioOutcome::pass(
            "crash_recovery_durability",
            "acked survived, uncommitted vanished",
        )
    } else {
        ScenarioOutcome::fail(
            "crash_recovery_durability",
            format!("survived {survived} (want 1), leaked {leaked} (want 0)"),
        )
    }
}

/// **Backup → seal → file → restore / key-rotation crash recovery (rmp #440).** Drives the genuine
/// operator backup/restore pipeline against **real temp files** and injects a crash at each of its
/// four atomicity windows, asserting that at every window the database opens to a **committed-only,
/// consistent** state **under exactly the expected key** (and that a wrong key fails closed).
///
/// # Why a DST scenario, and what it exercises
///
/// The constituent primitives are unit-tested in isolation (`restore_chain_file_atomic` round-trips;
/// `atomic_replace_file` leaves the original intact on an aborted fill; the crypto envelope opens only
/// under the right key), but before rmp #440 there was **no DST-driven crash injection across the full
/// pipeline**. This scenario reconstructs the pipeline at the **public-API level** — it cannot call the
/// server's private `dbcatalog` orchestration, so it drives the same building blocks the orchestration
/// composes:
///
/// 1. [`LocalEngine::backup`] captures a chain artifact of a store holding one **committed** node and
///    one **rolled-back** node (so "committed-only" has teeth).
/// 2. [`graphus_crypto::seal_backup`] seals it under the expected master key.
/// 3. [`graphus_io::atomic_replace_file`] writes the sealed file (the backup write) and
///    [`restore_chain_file_atomic`] writes the restored device file — both via the durable temp +
///    `rename(2)` idiom, whose crash semantics this scenario probes.
///
/// # The four crash windows (each asserted)
///
/// * **W1 — after `seal_artifact`, before the backup-file rename.** The sealed bytes exist but the
///   backup file's `atomic_replace_file` is interrupted mid-`fill` (the producer returns `Err` before
///   the rename). The backup path must be **untouched** (the prior whole image, or absent).
/// * **W2 — mid `write_file_atomic` over an existing backup.** A *second* sealed write crashes mid-fill;
///   the **previous** backup file must survive byte-for-byte (an aborted overwrite never destroys the
///   good backup).
/// * **W3 — mid `restore_chain_file_atomic` temp write.** The restore's device-file `fill` is
///   interrupted (the device open fails) before the rename. The device target must be **untouched**.
/// * **W4 — after the device temp-rename, before the WAL + DWB reset.** The restored device file is in
///   place (the new whole image), but the WAL/DWB reset step has not run. Because the chain restore
///   leaves the device at a **self-sufficient consistent committed point** (needing no WAL replay),
///   opening it with a fresh empty WAL + the consistency checker yields exactly the committed-only
///   state — so a crash in this window is healed by simply (re-)opening, never a torn or half-applied
///   database.
///
/// Deterministic and seed-swept: the committed payload, the key, and the partial-write content are all
/// pure functions of `seed`. Real temp files are created under the system temp dir and removed on
/// completion.
fn backup_restore_crash(seed: u64) -> ScenarioOutcome {
    const NAME: &str = "backup_restore_crash";
    use graphus_storage::{ChainArtifact, Plain, RestoreTarget, restore_chain_file_atomic};

    let base = (seed % 1000) as i64;
    // The expected master key (a pure function of seed); a different key must never open the envelope.
    let key = backup_key(seed);
    let wrong_key = backup_key(seed ^ 0xDEAD_BEEF);

    // 1. Build a store with one committed node and one rolled-back node, then capture the chain backup.
    let plaintext = match capture_committed_backup(base) {
        Ok(bytes) => bytes,
        Err(detail) => return ScenarioOutcome::fail(NAME, detail),
    };
    // 2. Seal under the expected key (this is the artifact an operator would write to disk).
    let Ok(sealed) = graphus_crypto::seal_backup(&plaintext, &key) else {
        return ScenarioOutcome::fail(NAME, "sealing the backup envelope failed");
    };

    let dir = TempDir::new(&format!("backup-crash-{seed}"));
    let backup_path = dir.path().join("graph.gba");
    let device_path = dir.path().join("graph.blk");

    // ---- W1: after seal, before the backup-file rename -------------------------------------------
    // A crash mid backup-file write must leave the (absent) target untouched: no half-written file.
    let crash_write = atomic_replace_file(&backup_path, |tmp| {
        // Write a deterministic partial prefix, then "crash" before the rename.
        let half = sealed.len() / 2;
        std::fs::write(tmp, &sealed[..half]).map_err(|e| {
            graphus_core::error::GraphusError::Storage(format!("partial write: {e}"))
        })?;
        Err(graphus_core::error::GraphusError::Storage(
            "simulated crash before backup rename".to_owned(),
        ))
    });
    if crash_write.is_ok() {
        return ScenarioOutcome::fail(NAME, "W1: interrupted backup write unexpectedly succeeded");
    }
    if backup_path.exists() {
        return ScenarioOutcome::fail(NAME, "W1: a crashed backup write left a partial file");
    }
    // Now complete the backup write atomically (the operator retries; the rename makes it whole).
    if atomic_replace_file(&backup_path, |tmp| write_durable(tmp, &sealed)).is_err() {
        return ScenarioOutcome::fail(NAME, "W1: completing the backup write failed");
    }

    // ---- W2: mid write_file_atomic over an EXISTING backup ---------------------------------------
    // A crashed overwrite of the good backup must leave the good backup byte-for-byte intact.
    let before = std::fs::read(&backup_path).unwrap_or_default();
    let crash_overwrite = atomic_replace_file(&backup_path, |tmp| {
        std::fs::write(tmp, b"GARBAGE-PARTIAL")
            .map_err(|e| graphus_core::error::GraphusError::Storage(format!("partial: {e}")))?;
        Err(graphus_core::error::GraphusError::Storage(
            "simulated crash mid write_file_atomic".to_owned(),
        ))
    });
    if crash_overwrite.is_ok() {
        return ScenarioOutcome::fail(NAME, "W2: interrupted overwrite unexpectedly succeeded");
    }
    let after = std::fs::read(&backup_path).unwrap_or_default();
    if before != after || before.is_empty() {
        return ScenarioOutcome::fail(NAME, "W2: a crashed overwrite damaged the good backup");
    }

    // The good backup must open only under the expected key (key-rotation correctness).
    let sealed_on_disk = match std::fs::read(&backup_path) {
        Ok(b) => b,
        Err(e) => return ScenarioOutcome::fail(NAME, format!("W2: reading backup: {e}")),
    };
    if graphus_crypto::open_backup(&sealed_on_disk, &wrong_key).is_ok() {
        return ScenarioOutcome::fail(
            NAME,
            "W2: backup opened under the WRONG key (not fail-closed)",
        );
    }
    let Ok(opened) = graphus_crypto::open_backup(&sealed_on_disk, &key) else {
        return ScenarioOutcome::fail(NAME, "W2: backup did not open under the expected key");
    };
    let Ok(artifact) = ChainArtifact::decode(&opened) else {
        return ScenarioOutcome::fail(NAME, "W2: decoding the restored chain artifact failed");
    };

    // ---- W3: mid restore_chain_file_atomic temp write --------------------------------------------
    // A crash during the restore's device-file fill (here: the device open fails) before the rename
    // must leave the (absent) device target untouched.
    let crash_restore = restore_chain_file_atomic(
        &artifact.manifest,
        &artifact.links,
        RestoreTarget::Latest,
        &Plain,
        &device_path,
        crash_during_restore_open,
        64,
    );
    if crash_restore.is_ok() {
        return ScenarioOutcome::fail(NAME, "W3: interrupted restore unexpectedly succeeded");
    }
    if device_path.exists() {
        return ScenarioOutcome::fail(NAME, "W3: a crashed restore left a partial device file");
    }

    // ---- W4: after the device temp-rename, before the WAL + DWB reset ----------------------------
    // Complete the atomic restore to the device file (the rename lands the whole new image). The
    // chain restore + the in-`fill` consistency check leave the device at a self-sufficient committed
    // point; we then open it with a FRESH empty WAL (the "WAL reset" the orchestration would do) and
    // assert the committed-only state — modelling recovery from a crash *between* the rename and the
    // WAL/DWB reset, which simply re-opens to the consistent committed image.
    let restored = restore_chain_file_atomic(
        &artifact.manifest,
        &artifact.links,
        RestoreTarget::Latest,
        &Plain,
        &device_path,
        |p| graphus_io::FileBlockDevice::open(p),
        64,
    );
    if let Err(e) = restored {
        return ScenarioOutcome::fail(NAME, format!("W4: completing the restore failed: {e}"));
    }
    let (survived, leaked) = match open_restored_and_count(&device_path, base) {
        Ok(counts) => counts,
        Err(detail) => return ScenarioOutcome::fail(NAME, detail),
    };
    if survived != 1 || leaked != 0 {
        return ScenarioOutcome::fail(
            NAME,
            format!("W4: restored state not committed-only (survived {survived}, leaked {leaked})"),
        );
    }

    ScenarioOutcome::pass(
        NAME,
        "crash at every backup/restore/key-rotation window opens committed-only under the right key",
    )
}

/// Derives the deterministic 32-byte backup master key for `seed` (a pure function of the seed, so the
/// whole [`backup_restore_crash`] scenario replays identically).
fn backup_key(seed: u64) -> [u8; graphus_crypto::KEY_LEN] {
    let mut key = [0u8; graphus_crypto::KEY_LEN];
    // SplitMix64-style fill from the seed — no external RNG, fully reproducible.
    let mut x = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    for chunk in key.chunks_mut(8) {
        x ^= x >> 30;
        x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x ^= x >> 27;
        x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
        x ^= x >> 31;
        for (i, b) in chunk.iter_mut().enumerate() {
            *b = (x >> (8 * i)) as u8;
        }
    }
    key
}

/// Builds a fresh engine, commits `:Durable {id: base}`, opens-and-rolls-back `:Durable {id: base+1}`,
/// and returns the captured **chain backup** plaintext (rmp #440 setup). The committed node must be in
/// the backup; the rolled-back node must not — so the restore's "committed-only" assertion has teeth.
fn capture_committed_backup(base: i64) -> std::result::Result<Vec<u8>, String> {
    let mut eng = engine();
    // Committed node.
    let Ok(c) = eng.begin(AccessMode::Write) else {
        return Err("setup: begin committed failed".to_owned());
    };
    if let Ok(mut r) = eng.run(
        c,
        "CREATE (:Durable {id: $id})",
        vec![("id".into(), Value::Integer(base))],
        false,
        None,
    ) {
        while let Ok(Some(_)) = r.rows.next() {}
    }
    if eng.commit(c).is_err() {
        return Err("setup: commit failed".to_owned());
    }
    // Rolled-back node (must NOT appear in the backup).
    if let Ok(t) = eng.begin(AccessMode::Write) {
        if let Ok(mut r) = eng.run(
            t,
            "CREATE (:Durable {id: $id})",
            vec![("id".into(), Value::Integer(base + 1))],
            false,
            None,
        ) {
            while let Ok(Some(_)) = r.rows.next() {}
        }
        let _ = eng.rollback(t);
    }
    let bytes = eng
        .backup()
        .map_err(|e| format!("setup: backup failed: {e}"))?;
    let _ = eng.shutdown();
    Ok(bytes)
}

/// Opens the restored device file as a queryable engine and returns `(survived, leaked)` — the row
/// count of the committed `:Durable {id: base}` (must be 1) and of the rolled-back `:Durable {id:
/// base+1}` (must be 0). Opens the store over a **fresh empty WAL** (the WAL the orchestration resets
/// to) and runs the consistency checker, so this is the "open after restore" path the W4 assertion
/// needs.
fn open_restored_and_count(
    device_path: &std::path::Path,
    base: i64,
) -> std::result::Result<(usize, usize), String> {
    use graphus_storage::{RecordStore, verify_on_open};
    use graphus_wal::WalManager;

    let dev = graphus_io::FileBlockDevice::open(device_path)
        .map_err(|e| format!("W4: reopening restored device: {e}"))?;
    let wal = WalManager::create(MemLogSink::new()).map_err(|e| format!("W4: fresh WAL: {e}"))?;
    let mut store =
        RecordStore::open(dev, wal, 64).map_err(|e| format!("W4: opening restored store: {e}"))?;
    // The restored device must pass the full consistency pass (committed, internally consistent).
    verify_on_open(&mut store, &[]).map_err(|e| format!("W4: restored store inconsistent: {e}"))?;

    let mut eng = LocalEngine::new(
        graphus_cypher::TxnCoordinator::new(store),
        Arc::new(SharedClock::new(0)),
    );
    let survived = count_rows_dev(
        &mut eng,
        "MATCH (n:Durable {id: $id}) RETURN n",
        vec![("id".into(), Value::Integer(base))],
    );
    let leaked = count_rows_dev(
        &mut eng,
        "MATCH (n:Durable {id: $id}) RETURN n",
        vec![("id".into(), Value::Integer(base + 1))],
    );
    let _ = eng.shutdown();
    // `count_rows_dev` returns `usize::MAX` if a read-back query itself failed (begin/run error). That
    // is a read-back failure, NOT a "wrong count" — surface it distinctly so the W4 diagnosis isn't
    // mislabelled as data corruption when the real fault is a query/store error.
    if survived == usize::MAX || leaked == usize::MAX {
        return Err("W4: read-back query against the restored store failed".to_owned());
    }
    Ok((survived, leaked))
}

/// The `open_device` closure for the **crashed** restore leg (rmp #440 W3): it always fails, modelling
/// a crash the instant the restore opens its device temp file — *before* any page is written. Named
/// (rather than an inline closure) so its concrete `MemBlockDevice` return type pins
/// [`restore_chain_file_atomic`]'s device parameter without a higher-ranked-lifetime inference failure.
fn crash_during_restore_open(
    _tmp: &std::path::Path,
) -> graphus_core::error::Result<MemBlockDevice> {
    Err(graphus_core::error::GraphusError::Storage(
        "simulated crash opening restore device".to_owned(),
    ))
}

/// Writes `bytes` to `path` durably (`sync_all`) — the fill closure for the *successful* leg of an
/// [`atomic_replace_file`] (the crashed legs write a partial then return `Err`).
fn write_durable(path: &std::path::Path, bytes: &[u8]) -> graphus_core::error::Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(path)
        .map_err(|e| graphus_core::error::GraphusError::Storage(format!("create temp: {e}")))?;
    f.write_all(bytes)
        .map_err(|e| graphus_core::error::GraphusError::Storage(format!("write temp: {e}")))?;
    f.sync_all()
        .map_err(|e| graphus_core::error::GraphusError::Storage(format!("sync temp: {e}")))
}

/// A self-cleaning temporary directory under the system temp dir, unique per `(tag, pid, nanos,
/// counter)`. Used by [`backup_restore_crash`] for the real-file backup/restore pipeline; removed on
/// drop so a sweep leaves no residue.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!(
            "graphus-dst-{tag}-{}-{n}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&p).expect("create temp dir");
        Self(p)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// **Network bulk import Mode A (rmp #519, `08-network-bulk-import.md` §10.1).** Drives
/// [`LocalEngine::bulk_import_batch`] — the same low-level, per-batch-commit ingestion dispatch the
/// REST `POST /admin/db/{db}/bulk-import` endpoint
/// (`crates/graphus-server/src/listeners/extra_routes/bulk_import.rs`) drives through the engine
/// command channel — against a fresh database, proving the storage/engine-level substance of `08`
/// §7.1's resumability and crash-durability guarantees.
///
/// # Scope: what this scenario does **not** cover, and why (a deliberate, already-made split)
///
/// `08` §10.1's bullet list mixes three architectural layers that this project's *other* test suites
/// already cover more appropriately than DST can, because DST structurally never touches HTTP/axum
/// (`grep -r "axum\|hyper" crates/graphus-dst/src` returns nothing outside doc comments) and never
/// instantiates a `DatabaseCatalog` (the same precedent [`backup_restore_crash`] already established:
/// it reconstructs its pipeline at the *public-API* level precisely because the server's `dbcatalog`
/// orchestration is private):
///
/// - **`Loading`-state catalog crash-recovery, and "ordinary traffic rejected while `Loading`, other
///   databases unaffected"** are `DatabaseCatalog`-level concerns, already covered by
///   `crates/graphus-server/src/dbcatalog.rs`'s `mod tests` (`begin_loading_transitions_online_to_loading_and_moves_the_handle`
///   and siblings) and by `crates/graphus-server/tests/bulk_import_endpoint.rs`'s
///   `loading_database_rejects_queries_while_an_unrelated_database_keeps_serving` (a real end-to-end
///   REST test proving exactly this). **Not re-tested here.**
/// - **HTTP-transport-level fault injection (mid-stream disconnect, partial-chunk delivery)** would
///   need a new async-Stream-over-`SimEndpoint` adapter driving axum's chunked `Body`/`frame()`
///   machinery, plus a hand-rolled executor, without a real tokio reactor — a materially separate,
///   large undertaking, out of scope for this stage. That layer's own resumability/dropped-connection
///   contract is instead covered by `bulk_import_endpoint.rs`'s real streamed-upload tests
///   (`start_paused_upload`, `oversized_streamed_upload`) and its module doc's explicit
///   dropped-connection contract.
/// - **What this scenario DOES cover**, and it is the correct, non-redundant DST contribution: the
///   storage/engine-level substance of resumability and crash-durability that
///   `LocalEngine`/`raw_txn`/the checkpoint sentinel actually implement — byte-for-byte deterministic
///   outcomes across a seed sweep, an aborted-batch retry proven idempotent (mirroring
///   `crates/graphus-bulk/tests/idmap_abort_retry.rs`'s already-proven pattern, now exercised through
///   the coordinator's `raw_txn` seam via [`LocalEngine::bulk_import_batch`] instead of
///   `BulkImporter`'s own counter), and a crash mid-session proving the checkpoint sentinel + all
///   previously committed data survive ARIES recovery intact — squarely what
///   `crash_recovery_durability`/`backup_restore_crash` already prove for *other* durability-critical
///   paths in this codebase, applied to this new one.
///
/// # `End` on a freshly-recovered engine cleans up the orphaned sentinel
///
/// `crates/graphus-server/src/engine/bulk_load.rs`'s own module doc states the resumability contract
/// precisely: after [`LocalEngine::crash_restart`], the rebuilt engine's in-memory `LoadingSession` is
/// unconditionally `None` (a fresh process has no way to recover the abandoned session's `id_map` from
/// the sentinel node's properties — that residual gap stands, see the module doc). But
/// `BulkImportBatchInput::End` dispatched on a freshly-recovered engine is **not** a silent no-op:
/// `handle_bulk_import_batch`'s `End` arm takes `session.take()`, finds `None`, and falls back to
/// `recover_and_delete_orphaned_sentinel` — a full store scan for the reserved sentinel label, reading
/// back its last-recorded `nodes`/`relationships`/`properties` counters (an accurate final summary,
/// even without the in-memory `id_map`) before deleting it. An operator who decides to **abandon**
/// (rather than resume) a crashed session therefore still ends up with a database holding exactly the
/// imported graph data and nothing else — no permanent orphaned bookkeeping node. This scenario asserts
/// that recovered-`End` contract as a positive, regression-guarding assertion (the recovered stats must
/// equal the pre-crash committed totals, the sentinel must be gone afterward, and a second `End` is a
/// genuine, harmless no-op) — and separately proves the **uninterrupted-session** `End`/sentinel-deletion
/// contract (never crashed), which is the more common case.
fn network_bulk_ingest_mode_a(seed: u64) -> ScenarioOutcome {
    const NAME: &str = "network_bulk_ingest_mode_a";

    let node_header = bulk_node_header();
    let rel_header = bulk_rel_header();

    let (mut eng, clock) = engine_with_clock(256);

    // Seed-derived batch shape (1..=3 batches per phase, 2..=5 rows per node batch, 1..=3 rows per
    // relationship batch) — mirrors how `deep_traversal`/`supernode_fanout` derive a seed-scoped
    // `base` from `seed % N` rather than pulling in a new RNG dependency.
    let n_node_batches = 1 + (seed % 3); // 1..=3
    let n_rel_batches = 1 + ((seed / 3) % 3); // 1..=3

    let mut node_ext_ids: Vec<String> = Vec::new();
    let mut expect = ImportStats::default();
    let mut committed_batches: u64 = 0;

    // ---- node batches: cumulative-stats correctness (§10.1 bullet 1) -----------------------------
    for b in 0..n_node_batches {
        let rows = 2 + ((seed + b) % 4); // 2..=5
        let mut records = Vec::with_capacity(rows as usize);
        for _ in 0..rows {
            let ext = format!("n{}", node_ext_ids.len());
            records.push(bulk_node_row(&ext, "Ada"));
            node_ext_ids.push(ext);
        }
        let out = match eng.bulk_import_batch(BulkImportBatchInput::Nodes {
            header: Arc::clone(&node_header),
            records,
        }) {
            Ok(o) => o,
            Err(e) => return ScenarioOutcome::fail(NAME, format!("node batch {b} failed: {e}")),
        };
        expect.nodes += rows;
        expect.properties += rows; // one `name` property per row
        committed_batches += 1;
        if let Some(mismatch) = stats_mismatch(NAME, "node batch", b, &out, &expect) {
            return mismatch;
        }
    }

    // ---- relationship batches: cumulative-stats correctness (§10.1 bullet 1) ---------------------
    let mut rel_cursor: u64 = 0;
    for b in 0..n_rel_batches {
        let rows = 1 + ((seed + b * 7) % 3); // 1..=3
        let mut records = Vec::with_capacity(rows as usize);
        for r in 0..rows {
            let idx = (rel_cursor + r) as usize;
            let a = &node_ext_ids[idx % node_ext_ids.len()];
            let bnode = &node_ext_ids[(idx + 1) % node_ext_ids.len()];
            records.push(bulk_rel_row(a, bnode));
        }
        rel_cursor += rows;
        let out = match eng.bulk_import_batch(BulkImportBatchInput::Relationships {
            header: Arc::clone(&rel_header),
            records,
        }) {
            Ok(o) => o,
            Err(e) => return ScenarioOutcome::fail(NAME, format!("rel batch {b} failed: {e}")),
        };
        expect.relationships += rows;
        expect.properties += rows; // one `since` property per row
        committed_batches += 1;
        if let Some(mismatch) = stats_mismatch(NAME, "rel batch", b, &out, &expect) {
            return mismatch;
        }
    }

    // ---- idempotent-retry: an aborted batch leaves no trace (§10.1 bullet 1, the §7.2.2-style proof)
    // A batch with a duplicate `:ID` under the default Strict policy must fail WHOLE (not just the
    // offending row): `graphus_bulk::ingest_node_row`'s doc (SEC-196) — reject a duplicate non-empty
    // external `:ID` — and `LoadingSession::ingest_nodes`'s abort-safety contract (`stats` reverted to
    // its pre-batch snapshot on any row error) together mean this batch must leave `expect` untouched.
    let stats_before_failure = expect;
    let dup_id = node_ext_ids[0].clone();
    let doomed = vec![
        bulk_node_row("n-should-not-land", "Eve"),
        bulk_node_row(&dup_id, "Duplicate"),
    ];
    let doomed_result = eng.bulk_import_batch(BulkImportBatchInput::Nodes {
        header: Arc::clone(&node_header),
        records: doomed,
    });
    if doomed_result.is_ok() {
        return ScenarioOutcome::fail(
            NAME,
            "a batch containing a duplicate :ID under the Strict policy unexpectedly succeeded",
        );
    }
    // Retry with the SAME shape corrected (the duplicate row replaced by a fresh id) — this must
    // succeed and the cumulative stats must advance by EXACTLY this retry's own rows, proving the
    // doomed attempt (including its otherwise-valid first row) left no trace to trip up the retry.
    let retry_id = format!("n{}", node_ext_ids.len());
    let retry = vec![bulk_node_row(&retry_id, "Eve")];
    let retry_out = match eng.bulk_import_batch(BulkImportBatchInput::Nodes {
        header: Arc::clone(&node_header),
        records: retry,
    }) {
        Ok(o) => o,
        Err(e) => return ScenarioOutcome::fail(NAME, format!("retry batch failed: {e}")),
    };
    node_ext_ids.push(retry_id);
    expect.nodes = stats_before_failure.nodes + 1;
    expect.properties = stats_before_failure.properties + 1;
    committed_batches += 1;
    if let Some(mismatch) = stats_mismatch(NAME, "retry batch", 0, &retry_out, &expect) {
        return mismatch;
    }

    // One more committed relationship batch after the retry episode, so the crash point below covers
    // both node and relationship data committed *after* an aborted attempt, not just before it.
    let a = node_ext_ids[0].clone();
    let bnode = node_ext_ids[node_ext_ids.len() - 1].clone();
    let post_retry_rel_out = match eng.bulk_import_batch(BulkImportBatchInput::Relationships {
        header: Arc::clone(&rel_header),
        records: vec![bulk_rel_row(&a, &bnode)],
    }) {
        Ok(o) => o,
        Err(e) => return ScenarioOutcome::fail(NAME, format!("post-retry rel batch failed: {e}")),
    };
    expect.relationships += 1;
    expect.properties += 1;
    committed_batches += 1;
    if let Some(mismatch) = stats_mismatch(
        NAME,
        "post-retry rel batch",
        0,
        &post_retry_rel_out,
        &expect,
    ) {
        return mismatch;
    }

    // ---- crash mid-session: data + checkpoint sentinel survive ARIES recovery intact (§10.1 bullet 2)
    let mut recovered = match eng.crash_restart(clock.clone(), 256) {
        Ok(e) => e,
        Err(e) => return ScenarioOutcome::fail(NAME, format!("crash_restart failed: {e}")),
    };

    let survived_nodes = read_scalar(
        &mut recovered,
        "MATCH (n:Person) RETURN count(n) AS c",
        vec![],
    );
    if survived_nodes != Some(expect.nodes as i64) {
        return ScenarioOutcome::fail(
            NAME,
            format!(
                "post-crash node count {survived_nodes:?} != expected {}",
                expect.nodes
            ),
        );
    }
    let survived_rels = read_scalar(
        &mut recovered,
        "MATCH ()-[r:KNOWS]->() RETURN count(r) AS c",
        vec![],
    );
    if survived_rels != Some(expect.relationships as i64) {
        return ScenarioOutcome::fail(
            NAME,
            format!(
                "post-crash relationship count {survived_rels:?} != expected {}",
                expect.relationships
            ),
        );
    }

    // The durable checkpoint sentinel: exactly one node, its counters matching the last committed
    // batch's cumulative stats and its `batch_seq` matching the number of batches that actually
    // committed (the doomed batch never advanced it).
    let sentinel_rows = count_rows(
        &mut recovered,
        "MATCH (n:__graphus_bulk_import_session__) RETURN n",
        vec![],
    );
    if sentinel_rows != 1 {
        return ScenarioOutcome::fail(
            NAME,
            format!("post-crash sentinel node count {sentinel_rows} != 1"),
        );
    }
    let sentinel_batch_seq = read_scalar(
        &mut recovered,
        "MATCH (n:__graphus_bulk_import_session__) RETURN n.batch_seq AS c",
        vec![],
    );
    let sentinel_nodes = read_scalar(
        &mut recovered,
        "MATCH (n:__graphus_bulk_import_session__) RETURN n.nodes AS c",
        vec![],
    );
    let sentinel_rels = read_scalar(
        &mut recovered,
        "MATCH (n:__graphus_bulk_import_session__) RETURN n.relationships AS c",
        vec![],
    );
    let sentinel_props = read_scalar(
        &mut recovered,
        "MATCH (n:__graphus_bulk_import_session__) RETURN n.properties AS c",
        vec![],
    );
    if sentinel_batch_seq != Some(committed_batches as i64)
        || sentinel_nodes != Some(expect.nodes as i64)
        || sentinel_rels != Some(expect.relationships as i64)
        || sentinel_props != Some(expect.properties as i64)
    {
        return ScenarioOutcome::fail(
            NAME,
            format!(
                "post-crash sentinel (batch_seq={sentinel_batch_seq:?} nodes={sentinel_nodes:?} \
                 relationships={sentinel_rels:?} properties={sentinel_props:?}) != expected \
                 (batch_seq={committed_batches} nodes={} relationships={} properties={})",
                expect.nodes, expect.relationships, expect.properties
            ),
        );
    }

    // ---- `End` on a freshly-recovered engine (no in-memory `LoadingSession` — the crash-restart
    // case) is NOT a silent no-op: `bulk_load::recover_and_delete_orphaned_sentinel` scans for the
    // durable checkpoint sentinel by its reserved label, reports the last-recorded
    // `nodes`/`relationships`/`properties` counters (== `expect`, the pre-crash committed total —
    // an accurate final summary even though the in-memory `id_map` is gone), and deletes it, so an
    // operator abandoning a crashed session still ends up with a database holding exactly the
    // imported graph data and nothing else. Asserted as a positive regression guard.
    let recovered_end = match recovered.bulk_import_batch(BulkImportBatchInput::End) {
        Ok(o) => o,
        Err(e) => {
            return ScenarioOutcome::fail(
                NAME,
                format!("End on the recovered engine errored: {e}"),
            );
        }
    };
    if recovered_end.stats.nodes != expect.nodes
        || recovered_end.stats.relationships != expect.relationships
        || recovered_end.stats.properties != expect.properties
    {
        return ScenarioOutcome::fail(
            NAME,
            format!(
                "End on a freshly-recovered engine reported stats {:?}, expected the pre-crash \
                 committed totals (nodes={} relationships={} properties={})",
                recovered_end.stats, expect.nodes, expect.relationships, expect.properties
            ),
        );
    }
    let sentinel_after_recovered_end = count_rows(
        &mut recovered,
        "MATCH (n:__graphus_bulk_import_session__) RETURN n",
        vec![],
    );
    if sentinel_after_recovered_end != 0 {
        return ScenarioOutcome::fail(
            NAME,
            format!(
                "sentinel count after the crash-recovered End is {sentinel_after_recovered_end} \
                 != 0 (End must clean up an orphaned sentinel even after a crash restart)"
            ),
        );
    }
    // Idempotent: a second `End` on the same (now sentinel-free) recovered engine is a genuine,
    // harmless no-op.
    let second_end = match recovered.bulk_import_batch(BulkImportBatchInput::End) {
        Ok(o) => o,
        Err(e) => {
            return ScenarioOutcome::fail(
                NAME,
                format!("second End on the recovered engine errored: {e}"),
            );
        }
    };
    if second_end.stats.nodes != 0 || second_end.stats.relationships != 0 {
        return ScenarioOutcome::fail(
            NAME,
            format!(
                "a second End (nothing left to clean up) reported non-zero stats {:?}",
                second_end.stats
            ),
        );
    }

    // ---- clean session lifecycle: End on an UNINTERRUPTED session deletes the sentinel and reports
    // the final cumulative stats (§10.1's `End` contract, on the case it actually covers today).
    let mut clean_eng = engine();
    let clean_out = match clean_eng.bulk_import_batch(BulkImportBatchInput::Nodes {
        header: Arc::clone(&node_header),
        records: vec![bulk_node_row("c0", "Fin"), bulk_node_row("c1", "Fon")],
    }) {
        Ok(o) => o,
        Err(e) => {
            return ScenarioOutcome::fail(NAME, format!("clean-lifecycle node batch failed: {e}"));
        }
    };
    if clean_out.stats.nodes != 2 || clean_out.stats.properties != 2 {
        return ScenarioOutcome::fail(
            NAME,
            format!(
                "clean-lifecycle node batch stats {:?} != expected 2/2",
                clean_out.stats
            ),
        );
    }
    let clean_rel_out = match clean_eng.bulk_import_batch(BulkImportBatchInput::Relationships {
        header: Arc::clone(&rel_header),
        records: vec![bulk_rel_row("c0", "c1")],
    }) {
        Ok(o) => o,
        Err(e) => {
            return ScenarioOutcome::fail(NAME, format!("clean-lifecycle rel batch failed: {e}"));
        }
    };
    if clean_rel_out.stats.nodes != 2
        || clean_rel_out.stats.relationships != 1
        || clean_rel_out.stats.properties != 3
    {
        return ScenarioOutcome::fail(
            NAME,
            format!(
                "clean-lifecycle rel batch stats {:?} != expected 2/1/3",
                clean_rel_out.stats
            ),
        );
    }
    let clean_end_out = match clean_eng.bulk_import_batch(BulkImportBatchInput::End) {
        Ok(o) => o,
        Err(e) => return ScenarioOutcome::fail(NAME, format!("clean-lifecycle End failed: {e}")),
    };
    if clean_end_out.stats.nodes != 2
        || clean_end_out.stats.relationships != 1
        || clean_end_out.stats.properties != 3
    {
        return ScenarioOutcome::fail(
            NAME,
            format!(
                "clean-lifecycle End stats {:?} != expected 2/1/3 (final cumulative stats)",
                clean_end_out.stats
            ),
        );
    }
    let clean_sentinel_after_end = count_rows(
        &mut clean_eng,
        "MATCH (n:__graphus_bulk_import_session__) RETURN n",
        vec![],
    );
    if clean_sentinel_after_end != 0 {
        return ScenarioOutcome::fail(
            NAME,
            format!(
                "clean-lifecycle sentinel count after End is {clean_sentinel_after_end} != 0 \
                 (End must delete the sentinel on an uninterrupted session)"
            ),
        );
    }

    ScenarioOutcome::pass(
        NAME,
        format!(
            "{committed_batches} batches committed ({} nodes, {} relationships), 1 aborted batch \
             left no trace, checkpoint sentinel + data survived a crash, clean End cleaned up",
            expect.nodes, expect.relationships
        ),
    )
}

// ------------------------------------------------------------------------------------------------
// network_bulk_ingest_mode_b (`08` §10.2, `rmp` #520): the higher-priority scenario — Mode B
// (already-live database, concurrent, no exclusivity) must be jointly serializable against ordinary
// concurrent traffic, its batch-retry must be idempotent under a genuine seeded pivot abort, its
// visibility must be exactly "everything committed before my snapshot began", it must not lose edges
// on a dense/hot pre-existing node under concurrent writers, its chunking must genuinely bound a
// single engine dispatch (the `08` §7.2.6 fairness requirement — DST asserts the MECHANISM; real
// wall-clock latency is proven separately by `crates/graphus-server/tests/bulk_import_mode_b_fairness.rs`,
// per the SAME DST/integration split `network_bulk_ingest_mode_a`'s own doc cites for HTTP-transport
// concerns: "`08-network-bulk-import.md`'s HTTP-transport and `DatabaseCatalog`/`Loading`-state layers
// are DST's structural non-goals... covered instead by... `graphus-server/tests/bulk_import_endpoint.rs`"),
// and it must recover correctly from a crash mid-batch interleaved with other committing transactions.
//
// `drive_mode_b_batch` (the real async retry-loop driver, `graphus_server::bulk_import_mode_b`) cannot
// run inline against a synchronous `LocalEngine` (it is written against the async `EngineHandle`, and
// this DST harness's whole determinism model is "no real async scheduler, no real clock"). Per this
// task's own guidance this scenario instead reimplements the retry loop's SHAPE synchronously
// ([`drive_mode_b_batch_sync`], below) over `LocalEngine::begin`/`bulk_import_mode_b_chunk`/`commit`/
// `rollback` — the exact same primitives the real driver calls, just sequenced inline. The scenario's
// job is to prove the STATE-MACHINE/data outcome is correct, not to re-exercise the async wrapper
// (which has its own real-engine, real-tokio tests in `graphus-server`'s own `bulk_import_mode_b.rs`).
// ------------------------------------------------------------------------------------------------

/// Which kind of rows a [`drive_mode_b_batch_sync`] call ingests.
enum ModeBRowsSync {
    Nodes(Arc<NodeHeader>),
    Relationships(Arc<RelHeader>, Arc<HashMap<String, u64>>),
}

/// The outcome of a successful [`drive_mode_b_batch_sync`] call: new `(external_id, physical_id)`
/// node bindings plus the `(nodes, relationships, properties)` cumulative deltas.
type ModeBBatchOk = (Vec<(String, u64)>, u64, u64, u64);

/// A synchronous, DST-local mirror of `graphus_server::bulk_import_mode_b::drive_mode_b_batch`'s
/// retry-loop SHAPE (see this section's module doc for why the real async driver cannot run here):
/// dispatches `records` in `chunk_rows`-sized [`BulkImportModeBChunkInput`] chunks under ONE
/// transaction, retrying up to `max_retries` times on a [`GraphusError::Transaction`] (the same
/// structural-match retriability rule the real driver uses), exactly reproducing the `08` §7.2.2
/// `id_map`-staging invariant: a failed attempt's bindings/deltas are discarded, never merged.
///
/// `first_ticket`, when `Some`, is used as the FIRST attempt's transaction instead of an ordinary
/// `eng.begin()` — a small testability seam (mirrors
/// `graphus_server::bulk_import_mode_b::drive_mode_b_batch_from`'s identical one, for the identical
/// reason): it lets a caller open a ticket, seed a genuine SSI conflict against it (in program order,
/// no race), and hand it in, so the doomed first attempt's timing is deterministic. Every retry after
/// the first still opens its own fresh ticket via the ordinary path.
///
/// # Errors
/// The terminal error once retries are exhausted, or a non-retriable row/storage error.
fn drive_mode_b_batch_sync(
    eng: &mut Eng,
    kind: &ModeBRowsSync,
    records: &[csv::StringRecord],
    chunk_rows: usize,
    max_retries: u32,
    first_ticket: Option<TxTicket>,
) -> Result<ModeBBatchOk, GraphusError> {
    let mut attempt = 0u32;
    let mut pending_first_ticket = first_ticket;
    loop {
        let ticket = match pending_first_ticket.take() {
            Some(t) => t,
            None => eng.begin(AccessMode::Write)?,
        };
        let mut bindings = Vec::new();
        let (mut nodes, mut rels, mut props) = (0u64, 0u64, 0u64);
        let mut failure: Option<GraphusError> = None;
        for chunk in records.chunks(chunk_rows.max(1)) {
            let input = match kind {
                ModeBRowsSync::Nodes(header) => BulkImportModeBChunkInput::Nodes {
                    header: Arc::clone(header),
                    records: chunk.to_vec(),
                },
                ModeBRowsSync::Relationships(header, id_map) => {
                    BulkImportModeBChunkInput::Relationships {
                        header: Arc::clone(header),
                        records: chunk.to_vec(),
                        id_map: Arc::clone(id_map),
                    }
                }
            };
            match eng.bulk_import_mode_b_chunk(ticket, input) {
                Ok(out) => {
                    bindings.extend(out.new_node_bindings);
                    nodes += out.nodes;
                    rels += out.relationships;
                    props += out.properties;
                }
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            }
        }
        let commit_result = match failure {
            Some(e) => {
                let _ = eng.rollback(ticket);
                Err(e)
            }
            None => eng.commit(ticket).map(|_| ()),
        };
        match commit_result {
            Ok(()) => return Ok((bindings, nodes, rels, props)),
            Err(e) => {
                if matches!(e, GraphusError::Transaction(_)) && attempt < max_retries {
                    attempt += 1;
                    continue;
                }
                return Err(e);
            }
        }
    }
}

/// The node-file header [`network_bulk_ingest_mode_b`] uses: `:ID`, `:LABEL` (fixed `Entity`), and a
/// per-row-unique `seq` integer property — the same "distinct-per-row property" shape
/// `crate::mode_b_batch_size_measurement` empirically found necessary for a concurrent reader to
/// register a genuine `Equality` predicate marker against a *specific*, not-yet-created row (an
/// unlabeled node registers no `Equality` marker at all — `reindex_node`'s footprint loop is nested
/// inside "for each label the node carries").
fn mode_b_node_header() -> Arc<NodeHeader> {
    Arc::new(NodeHeader {
        columns: vec![
            ColumnRole::Id,
            ColumnRole::Label,
            ColumnRole::Property {
                key: "seq".to_owned(),
                ty: PropertyType::Scalar(ScalarType::Integer),
            },
        ],
        id_index: 0,
    })
}

fn mode_b_node_row(external_id: &str, seq: i64) -> csv::StringRecord {
    csv::StringRecord::from(vec![external_id, "Entity", &seq.to_string()])
}

fn mode_b_rel_header() -> Arc<RelHeader> {
    Arc::new(RelHeader {
        columns: vec![ColumnRole::StartId, ColumnRole::EndId, ColumnRole::Type],
        start_index: 0,
        end_index: 1,
        type_index: 2,
    })
}

fn mode_b_rel_row(start: &str, end: &str, rel_type: &str) -> csv::StringRecord {
    csv::StringRecord::from(vec![start, end, rel_type])
}

/// Seeds a genuine SSI pivot abort against whichever transaction next creates the `Entity` node whose
/// `seq` property equals `target_seq` — the exact rw-edge sequence
/// `graphus_txn::ssi::SsiTracker::add_edge`'s eager committed-pivot-break rule dooms (proven against a
/// real `EngineHandle` in `graphus_server::bulk_import_mode_b`'s own tests, and against `LocalEngine`
/// in `crate::mode_b_batch_size_measurement`): `trdr` (caller-owned, already open, reading an unrelated
/// marker predicate — kept open by the caller so `forget()`'s edge-cleanup never erases the edge it
/// contributes) plus a fresh `r` that reads the specific not-yet-created `seq=target_seq` node (a
/// realistic "does entity X exist yet" probe), writes the marker predicate `trdr` already read
/// (closing `trdr --rw--> r`), and commits — becoming a genuine committed pivot. The caller's next
/// chunk creating that exact `seq` value closes `r --rw--> target` and dooms it.
fn seed_mode_b_pivot_abort(eng: &mut Eng, trdr: TxTicket, target_seq: i64) {
    let Ok(r) = eng.begin(AccessMode::Write) else {
        return;
    };
    let read_ok = eng
        .run(
            r,
            "MATCH (n:Entity {seq: $s}) RETURN n",
            vec![("s".to_owned(), Value::Integer(target_seq))],
            false,
            None,
        )
        .is_ok_and(|mut reply| {
            while let Ok(Some(_)) = reply.rows.next() {}
            true
        });
    let write_ok = read_ok
        && eng
            .run(r, "CREATE (:Marker)", vec![], false, None)
            .is_ok_and(|mut reply| {
                while let Ok(Some(_)) = reply.rows.next() {}
                true
            });
    if write_ok {
        let _ = eng.commit(r);
    } else {
        let _ = eng.rollback(r);
    }
    let _ = trdr;
}

/// Reads `key`'s append-list in `ticket`, returning the observed values in order — the Elle
/// list-append model's read primitive (mirrors `isolation.rs`'s identical test-only helper, redefined
/// here since that one is private to that module's `#[cfg(test)]`).
fn read_list(eng: &mut Eng, ticket: TxTicket, key: &str) -> Vec<i64> {
    let mut reply = match eng.run(
        ticket,
        "MATCH (e:Entry {key: $k}) RETURN e.val AS val ORDER BY e.val",
        vec![("k".to_owned(), Value::String(key.to_owned()))],
        false,
        None,
    ) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    while let Ok(Some(row)) = reply.rows.next() {
        if let Some(MaterializedValue::Value(Value::Integer(n))) = row.first() {
            out.push(*n);
        }
    }
    out
}

/// Appends `val` to `key`'s list in `ticket` — the Elle list-append model's write primitive (mirrors
/// `isolation.rs`'s identical test-only helper).
fn append(eng: &mut Eng, ticket: TxTicket, key: &str, val: i64) {
    if let Ok(mut reply) = eng.run(
        ticket,
        "CREATE (:Entry {key: $k, val: $v})",
        vec![
            ("k".to_owned(), Value::String(key.to_owned())),
            ("v".to_owned(), Value::Integer(val)),
        ],
        false,
        None,
    ) {
        while let Ok(Some(_)) = reply.rows.next() {}
    }
}

/// **`network_bulk_ingest_mode_b`** (`08` §10.2, `rmp` #520). See the section doc comment above for
/// the DST/integration split and the synchronous retry-loop mirror this scenario drives through.
#[allow(clippy::too_many_lines)]
fn network_bulk_ingest_mode_b(seed: u64) -> ScenarioOutcome {
    const NAME: &str = "network_bulk_ingest_mode_b";
    let (mut eng, clock) = engine_with_clock(256);
    let node_header = mode_b_node_header();
    let rel_header = mode_b_rel_header();

    // ---- bullet 4 prep: a dense/hot pre-existing node, seeded before anything else ----------------
    if !write(&mut eng, "CREATE (:Hub {id: 0})", vec![]) {
        return ScenarioOutcome::fail(NAME, "seed hub node failed");
    }

    // ============================================================================================
    // Bullet 1: joint serializability (Elle, list-append model) — a Mode B node batch interleaved
    // with an ordinary concurrent Cypher read-then-append transaction over the SAME shared key.
    // ============================================================================================
    let key = "shared";
    let t_ordinary = match eng.begin(AccessMode::Write) {
        Ok(t) => t,
        Err(e) => return ScenarioOutcome::fail(NAME, format!("begin ordinary txn: {e}")),
    };
    let ordinary_read = read_list(&mut eng, t_ordinary, key);

    // The Mode B batch commits BEFORE the ordinary txn (both were concurrent: the ordinary txn began
    // first but has not yet committed its own append).
    let modeb_ext = format!("e-modeb-{seed}");
    let modeb_records = vec![mode_b_node_row(&modeb_ext, 1)];
    let modeb_result = drive_mode_b_batch_sync(
        &mut eng,
        &ModeBRowsSync::Nodes(Arc::clone(&node_header)),
        &modeb_records,
        10,
        3,
        None,
    );
    let modeb_committed = modeb_result.is_ok();
    if !modeb_committed {
        return ScenarioOutcome::fail(
            NAME,
            format!("bullet 1: unconflicted mode-b batch unexpectedly failed: {modeb_result:?}"),
        );
    }
    // Model the Mode B batch's committed row as a list-append on `key` (mirroring `isolation.rs`'s
    // convention): its "value" is a fixed sentinel distinguishing it from the ordinary txn's append.
    append(&mut eng, t_ordinary, key, 999);
    let c_ordinary = eng.commit(t_ordinary).is_ok();

    let history = vec![
        Transaction {
            id: 1,
            ops: vec![
                Op::Read {
                    key: key.to_owned(),
                    observed: ordinary_read,
                },
                Op::Append {
                    key: key.to_owned(),
                    val: 999,
                },
            ],
            committed: c_ordinary,
        },
        Transaction {
            id: 2,
            ops: vec![Op::Append {
                key: "modeb-nodes".to_owned(),
                val: 1,
            }],
            committed: modeb_committed,
        },
    ];
    let elle = check(&history);
    if !elle.serializable {
        return ScenarioOutcome::fail(
            NAME,
            format!("bullet 1: committed history is not serializable: {elle:?}"),
        );
    }

    // ============================================================================================
    // Bullet 2: a seeded pivot abort of an in-progress batch, and idempotent-retry convergence.
    // A long-lived `trdr` anchors the doom (see `seed_mode_b_pivot_abort`'s doc for why it must stay
    // open — `forget()`'s edge-cleanup otherwise erases the edge it contributes). `trdr` is reused for
    // BOTH sub-phases below (2a, 2b): it only needs to stay open reading the Marker predicate; each
    // seed targets a DIFFERENT, not-yet-created row, so the two phases do not interfere.
    // ============================================================================================
    let trdr = match eng.begin(AccessMode::Write) {
        Ok(t) => t,
        Err(e) => return ScenarioOutcome::fail(NAME, format!("begin trdr anchor: {e}")),
    };
    let _ = eng.run(
        trdr,
        "MATCH (:Marker) RETURN count(*) AS c",
        vec![],
        false,
        None,
    );

    // ---- 2a: 0 retries — the seeded conflict must surface immediately, terminally, atomically. ----
    // The ticket is opened FIRST (before seeding), matching the ordering
    // `seed_mode_b_pivot_abort`'s doc requires (the target must begin before `r` commits).
    let ticket_a = match eng.begin(AccessMode::Write) {
        Ok(t) => t,
        Err(e) => return ScenarioOutcome::fail(NAME, format!("bullet 2a: begin ticket_a: {e}")),
    };
    seed_mode_b_pivot_abort(&mut eng, trdr, 1000);
    let doomed_records = vec![mode_b_node_row(&format!("e-doomed-{seed}"), 1000)];
    let doomed_result = drive_mode_b_batch_sync(
        &mut eng,
        &ModeBRowsSync::Nodes(Arc::clone(&node_header)),
        &doomed_records,
        10,
        0,
        Some(ticket_a),
    );
    if doomed_result.is_ok() {
        return ScenarioOutcome::fail(
            NAME,
            "bullet 2a: the seeded pivot conflict unexpectedly did not abort the 0-retry batch",
        );
    }
    let doomed_err = doomed_result.unwrap_err();
    if !matches!(doomed_err, GraphusError::Transaction(_)) {
        return ScenarioOutcome::fail(
            NAME,
            format!(
                "bullet 2a: the seeded abort was not classified Transaction/retriable: {doomed_err}"
            ),
        );
    }
    let doomed_visible = count_rows(
        &mut eng,
        "MATCH (n:Entity {seq: $s}) RETURN n",
        vec![("s".to_owned(), Value::Integer(1000))],
    );
    if doomed_visible != 0 {
        return ScenarioOutcome::fail(
            NAME,
            format!("bullet 2a: the doomed row is visible ({doomed_visible} rows) — not atomic"),
        );
    }

    // ---- 2b: retries enabled — the SAME real retry loop must converge to exactly the retry's own
    // contribution, no duplication, no stale bindings from the aborted first attempt. ----
    let ticket_b = match eng.begin(AccessMode::Write) {
        Ok(t) => t,
        Err(e) => return ScenarioOutcome::fail(NAME, format!("bullet 2b: begin ticket_b: {e}")),
    };
    seed_mode_b_pivot_abort(&mut eng, trdr, 1001);
    let retry_records = vec![mode_b_node_row(&format!("e-retry-{seed}"), 1001)];
    let retry_result = drive_mode_b_batch_sync(
        &mut eng,
        &ModeBRowsSync::Nodes(Arc::clone(&node_header)),
        &retry_records,
        10,
        3,
        Some(ticket_b),
    );
    let (retry_bindings, retry_nodes, ..) = match retry_result {
        Ok(o) => o,
        Err(e) => return ScenarioOutcome::fail(NAME, format!("bullet 2b: retry failed: {e}")),
    };
    if retry_nodes != 1 || retry_bindings.len() != 1 {
        return ScenarioOutcome::fail(
            NAME,
            format!(
                "bullet 2b: retry outcome != exactly 1 new node: nodes={retry_nodes} bindings={retry_bindings:?}"
            ),
        );
    }
    let final_visible = count_rows(
        &mut eng,
        "MATCH (n:Entity {seq: $s}) RETURN n",
        vec![("s".to_owned(), Value::Integer(1001))],
    );
    if final_visible != 1 {
        return ScenarioOutcome::fail(
            NAME,
            format!(
                "bullet 2b: post-retry seq=1001 row count {final_visible} != 1 (no duplicate, no orphan)"
            ),
        );
    }

    // ============================================================================================
    // Bullet 3: concurrent readers at various snapshot begin timestamps observe exactly "everything
    // committed strictly before my snapshot began" — never a partial/torn batch.
    // ============================================================================================
    let reader_before = match eng.begin(AccessMode::Read) {
        Ok(t) => t,
        Err(e) => return ScenarioOutcome::fail(NAME, format!("begin reader_before: {e}")),
    };
    let before_count = scalar_in(
        &mut eng,
        reader_before,
        "MATCH (n:Entity) RETURN count(n) AS c",
        vec![],
    )
    .unwrap_or(-1);
    let expected_before_count = 2i64; // e-modeb-{seed} (bullet 1) + e-doomed-{seed} retry (bullet 2)
    if before_count != expected_before_count {
        return ScenarioOutcome::fail(
            NAME,
            format!(
                "bullet 3: reader_before saw {before_count} Entity nodes, expected {expected_before_count}"
            ),
        );
    }
    let more_ext = format!("e-more-{seed}");
    let more_records = vec![mode_b_node_row(&more_ext, 2)];
    if drive_mode_b_batch_sync(
        &mut eng,
        &ModeBRowsSync::Nodes(Arc::clone(&node_header)),
        &more_records,
        10,
        0,
        None,
    )
    .is_err()
    {
        return ScenarioOutcome::fail(NAME, "bullet 3: unconflicted batch unexpectedly failed");
    }
    // `reader_before`'s snapshot must NOT see the just-committed row (it began strictly earlier).
    let before_count_after = scalar_in(
        &mut eng,
        reader_before,
        "MATCH (n:Entity) RETURN count(n) AS c",
        vec![],
    )
    .unwrap_or(-1);
    if before_count_after != expected_before_count {
        return ScenarioOutcome::fail(
            NAME,
            format!(
                "bullet 3: reader_before's view changed after a LATER commit ({before_count} -> \
                 {before_count_after}) — snapshot isolation violated"
            ),
        );
    }
    let _ = eng.commit(reader_before);
    let reader_after = match eng.begin(AccessMode::Read) {
        Ok(t) => t,
        Err(e) => return ScenarioOutcome::fail(NAME, format!("begin reader_after: {e}")),
    };
    let after_count =
        read_scalar(&mut eng, "MATCH (n:Entity) RETURN count(n) AS c", vec![]).unwrap_or(-1);
    let _ = eng.rollback(reader_after);
    if after_count != expected_before_count + 1 {
        return ScenarioOutcome::fail(
            NAME,
            format!(
                "bullet 3: reader_after saw {after_count}, expected {}",
                expected_before_count + 1
            ),
        );
    }

    // ============================================================================================
    // Bullet 4: dense/hot pre-existing node targeted by BOTH the import and concurrent live traffic
    // — every edge that commits must persist (the #220 invariant `concurrent_supernode` already pins,
    // reused here with Mode B as one of the two concurrent writers).
    // ============================================================================================
    let ordinary_writer = match eng.begin(AccessMode::Write) {
        Ok(t) => t,
        Err(e) => return ScenarioOutcome::fail(NAME, format!("begin hub ordinary writer: {e}")),
    };
    let mut ordinary_reply = match eng.run(
        ordinary_writer,
        "MATCH (h:Hub {id: 0}) CREATE (h)-[:LINK]->(:Leaf {tag: 'ordinary'})",
        vec![],
        false,
        None,
    ) {
        Ok(r) => r,
        Err(e) => return ScenarioOutcome::fail(NAME, format!("bullet 4: ordinary hub write: {e}")),
    };
    while let Ok(Some(_)) = ordinary_reply.rows.next() {}

    // Mode B's own batch adds an edge to the SAME hub, via an existing-node relationship row (start
    // id resolves through a durable id_map entry seeded via a tiny prior node batch naming the hub).
    let hub_ext = "hub-anchor";
    let leaf_ext = format!("leaf-modeb-{seed}");
    let mut anchor_id_map: HashMap<String, u64> = HashMap::new();
    let hub_physical = read_scalar(&mut eng, "MATCH (h:Hub {id: 0}) RETURN id(h) AS i", vec![]);
    let Some(hub_physical) = hub_physical else {
        return ScenarioOutcome::fail(NAME, "bullet 4: could not resolve the hub's physical id");
    };
    anchor_id_map.insert(hub_ext.to_owned(), hub_physical as u64);
    let leaf_batch = drive_mode_b_batch_sync(
        &mut eng,
        &ModeBRowsSync::Nodes(Arc::clone(&node_header)),
        &[mode_b_node_row(&leaf_ext, 3)],
        10,
        0,
        None,
    );
    let leaf_physical = match leaf_batch {
        Ok((bindings, ..)) => bindings.first().map(|(_, id)| *id),
        Err(e) => {
            return ScenarioOutcome::fail(NAME, format!("bullet 4: mode-b leaf node batch: {e}"));
        }
    };
    let Some(leaf_physical) = leaf_physical else {
        return ScenarioOutcome::fail(NAME, "bullet 4: mode-b leaf node batch produced no binding");
    };
    anchor_id_map.insert(leaf_ext.clone(), leaf_physical);
    let rel_id_map = Arc::new(anchor_id_map);
    let hub_edge_result = drive_mode_b_batch_sync(
        &mut eng,
        &ModeBRowsSync::Relationships(Arc::clone(&rel_header), Arc::clone(&rel_id_map)),
        &[mode_b_rel_row(hub_ext, &leaf_ext, "LINK")],
        10,
        3,
        None,
    );
    let modeb_hub_committed = hub_edge_result.is_ok();
    let ordinary_hub_committed = eng.commit(ordinary_writer).is_ok();
    if !modeb_hub_committed && !ordinary_hub_committed {
        return ScenarioOutcome::fail(NAME, "bullet 4: BOTH concurrent hub writers were lost");
    }
    let expected_hub_fanout = i64::from(modeb_hub_committed) + i64::from(ordinary_hub_committed);
    let hub_fanout = read_scalar(
        &mut eng,
        "MATCH (h:Hub {id: 0})-[:LINK]->(x) RETURN count(x) AS c",
        vec![],
    )
    .unwrap_or(-1);
    if hub_fanout != expected_hub_fanout {
        return ScenarioOutcome::fail(
            NAME,
            format!(
                "bullet 4: hub fan-out {hub_fanout} != expected {expected_hub_fanout} \
                 (modeb_committed={modeb_hub_committed} ordinary_committed={ordinary_hub_committed}) \
                 — a committed edge was lost"
            ),
        );
    }

    // ============================================================================================
    // Bullet 5 (mechanism only — real wall-clock latency is `bulk_import_mode_b_fairness.rs`'s job,
    // per this section's doc comment): the chunking genuinely bounds a single dispatch's row count.
    // ============================================================================================
    let chunk_rows = 7usize;
    let fairness_records: Vec<_> = (0..25i64)
        .map(|i| mode_b_node_row(&format!("e-fair-{seed}-{i}"), 10_000 + i))
        .collect();
    let mut max_dispatched = 0usize;
    {
        let ticket = match eng.begin(AccessMode::Write) {
            Ok(t) => t,
            Err(e) => return ScenarioOutcome::fail(NAME, format!("bullet 5: begin: {e}")),
        };
        for chunk in fairness_records.chunks(chunk_rows) {
            max_dispatched = max_dispatched.max(chunk.len());
            let out = eng.bulk_import_mode_b_chunk(
                ticket,
                BulkImportModeBChunkInput::Nodes {
                    header: Arc::clone(&node_header),
                    records: chunk.to_vec(),
                },
            );
            if out.is_err() {
                return ScenarioOutcome::fail(NAME, "bullet 5: fairness chunk dispatch failed");
            }
        }
        if eng.commit(ticket).is_err() {
            return ScenarioOutcome::fail(NAME, "bullet 5: fairness batch commit failed");
        }
    }
    if max_dispatched > chunk_rows {
        return ScenarioOutcome::fail(
            NAME,
            format!("bullet 5: a chunk dispatched {max_dispatched} rows > configured {chunk_rows}"),
        );
    }

    // ============================================================================================
    // Bullet 6: a crash mid-batch while other, unrelated transactions are concurrently committing —
    // recovery must reconcile the interleaved WAL correctly (nothing torn, nothing lost).
    // ============================================================================================
    let pre_crash_entities =
        read_scalar(&mut eng, "MATCH (n:Entity) RETURN count(n) AS c", vec![]).unwrap_or(-1);
    // An unrelated ordinary transaction commits.
    if !write(&mut eng, "CREATE (:Unrelated {tag: 1})", vec![]) {
        return ScenarioOutcome::fail(NAME, "bullet 6: unrelated pre-crash write failed");
    }
    // A Mode B batch is left DELIBERATELY UNCOMMITTED (mid-flight) at the moment of the crash.
    let crash_ticket = match eng.begin(AccessMode::Write) {
        Ok(t) => t,
        Err(e) => return ScenarioOutcome::fail(NAME, format!("bullet 6: begin in-flight: {e}")),
    };
    let inflight_records = vec![mode_b_node_row(&format!("e-inflight-{seed}"), 20_000)];
    let inflight_out = eng.bulk_import_mode_b_chunk(
        crash_ticket,
        BulkImportModeBChunkInput::Nodes {
            header: Arc::clone(&node_header),
            records: inflight_records,
        },
    );
    if inflight_out.is_err() {
        return ScenarioOutcome::fail(NAME, "bullet 6: in-flight chunk dispatch failed");
    }
    // Another unrelated ordinary transaction ALSO commits, interleaved with the still-open ticket.
    if !write(&mut eng, "CREATE (:Unrelated {tag: 2})", vec![]) {
        return ScenarioOutcome::fail(NAME, "bullet 6: second unrelated pre-crash write failed");
    }

    let mut recovered = match eng.crash_restart(clock.clone(), 256) {
        Ok(e) => e,
        Err(e) => {
            return ScenarioOutcome::fail(NAME, format!("bullet 6: crash_restart failed: {e}"));
        }
    };
    let recovered_entities = read_scalar(
        &mut recovered,
        "MATCH (n:Entity) RETURN count(n) AS c",
        vec![],
    )
    .unwrap_or(-1);
    if recovered_entities != pre_crash_entities {
        return ScenarioOutcome::fail(
            NAME,
            format!(
                "bullet 6: post-crash Entity count {recovered_entities} != pre-crash committed \
                 count {pre_crash_entities} (the in-flight, never-committed batch must NOT survive)"
            ),
        );
    }
    let recovered_unrelated = read_scalar(
        &mut recovered,
        "MATCH (n:Unrelated) RETURN count(n) AS c",
        vec![],
    )
    .unwrap_or(-1);
    if recovered_unrelated != 2 {
        return ScenarioOutcome::fail(
            NAME,
            format!(
                "bullet 6: post-crash Unrelated count {recovered_unrelated} != 2 (both committed \
                 concurrent transactions must survive, interleaved correctly around the crash)"
            ),
        );
    }
    let inflight_visible = count_rows(
        &mut recovered,
        "MATCH (n:Entity {seq: 20000}) RETURN n",
        vec![],
    );
    if inflight_visible != 0 {
        return ScenarioOutcome::fail(
            NAME,
            format!(
                "bullet 6: the never-committed in-flight row is visible after recovery ({inflight_visible})"
            ),
        );
    }

    ScenarioOutcome::pass(
        NAME,
        format!(
            "Elle-serializable, seeded-abort retry converged, snapshot visibility exact, hub \
             fan-out {hub_fanout} preserved, chunking bounded to {max_dispatched}<={chunk_rows}, \
             crash mid-batch reconciled ({recovered_unrelated} unrelated + {recovered_entities} \
             entities survived, in-flight row correctly absent)"
        ),
    )
}

/// Builds the fixed `NodeHeader` used by [`network_bulk_ingest_mode_a`]: `:ID`, `:LABEL`, and one
/// `name` string property — mirrors `crates/graphus-server/src/engine/bulk_load.rs`'s own
/// `#[cfg(test)]` fixture exactly.
fn bulk_node_header() -> Arc<NodeHeader> {
    Arc::new(NodeHeader {
        columns: vec![
            ColumnRole::Id,
            ColumnRole::Label,
            ColumnRole::Property {
                key: "name".to_owned(),
                ty: PropertyType::Scalar(ScalarType::String),
            },
        ],
        id_index: 0,
    })
}

/// Builds the fixed `RelHeader` used by [`network_bulk_ingest_mode_a`]: `:START_ID`, `:END_ID`,
/// `:TYPE`, and one `since` integer property — mirrors `bulk_load.rs`'s own test fixture.
fn bulk_rel_header() -> Arc<RelHeader> {
    Arc::new(RelHeader {
        columns: vec![
            ColumnRole::StartId,
            ColumnRole::EndId,
            ColumnRole::Type,
            ColumnRole::Property {
                key: "since".to_owned(),
                ty: PropertyType::Scalar(ScalarType::Integer),
            },
        ],
        start_index: 0,
        end_index: 1,
        type_index: 2,
    })
}

/// One `Person` node row matching [`bulk_node_header`]'s column order.
fn bulk_node_row(external_id: &str, name: &str) -> csv::StringRecord {
    csv::StringRecord::from(vec![external_id, "Person", name])
}

/// One `KNOWS` relationship row matching [`bulk_rel_header`]'s column order.
fn bulk_rel_row(start_external_id: &str, end_external_id: &str) -> csv::StringRecord {
    csv::StringRecord::from(vec![start_external_id, end_external_id, "KNOWS", "2020"])
}

/// Compares `out`'s cumulative stats against `expect`'s `nodes`/`relationships`/`properties`
/// (`ImportStats` derives no `PartialEq`, so this is a field-by-field check), returning `Some` of a
/// failing [`ScenarioOutcome`] naming `phase`/`index` on a mismatch, `None` on a match.
fn stats_mismatch(
    name: &'static str,
    phase: &str,
    index: u64,
    out: &BulkImportBatchOutcome,
    expect: &ImportStats,
) -> Option<ScenarioOutcome> {
    if out.stats.nodes != expect.nodes
        || out.stats.relationships != expect.relationships
        || out.stats.properties != expect.properties
    {
        Some(ScenarioOutcome::fail(
            name,
            format!(
                "{phase} {index}: cumulative stats {:?} != expected nodes={} relationships={} \
                 properties={}",
                out.stats, expect.nodes, expect.relationships, expect.properties
            ),
        ))
    } else {
        None
    }
}

/// **Hostile clock (rmp #233).** Drives the real engine under a seed-driven [`FaultyClock`] — bounded
/// skew, forward jumps, and **non-monotonic regressions** — while advancing logical time, and asserts
/// the engine's documented tolerance contract holds end to end:
///
/// 1. **No panic** — every statement (including temporal `datetime()` reads and latency-measured runs)
///    completes against the hostile clock without unwinding.
/// 2. **No temporal-correctness violation** — the engine's elapsed/latency arithmetic is
///    `saturating_sub`, so even a backward clock yields a non-negative duration; this scenario reaches
///    that path on every run and never observes a negative duration (it cannot, by construction, but
///    exercising it under a regressing clock certifies the contract empirically).
/// 3. **Liveness + consistency** — under the hostile clock every committed write is still readable and
///    no work is lost: a fixed batch of creates is read back exactly.
///
/// The whole scenario is a pure function of `seed`: the clock faults derive from it and the engine is
/// otherwise deterministic.
fn hostile_clock(seed: u64) -> ScenarioOutcome {
    const NAME: &str = "hostile_clock";
    let (mut eng, inner) = engine_with_faulty_clock(seed, 256);
    let n = 24i64;

    // Interleave writes with logical-time advances so the FaultyClock perturbs a different base instant
    // on each statement (skew + jumps + regressions all exercised across the run). The advances are
    // small so a backward regression can dip below the previous reading — the hostile case.
    for i in 0..n {
        inner.set(1_000_000 + (i as u64) * 1_000);
        if !write(
            &mut eng,
            "CREATE (:Clocked {id: $id, t: datetime()})",
            vec![("id".into(), Value::Integer(i))],
        ) {
            return ScenarioOutcome::fail(NAME, format!("write {i} failed under hostile clock"));
        }
    }

    // A temporal read that reads the (hostile) statement clock must still succeed and not panic.
    inner.set(2_000_000);
    let now_rows = count_rows(&mut eng, "RETURN datetime() AS now", vec![]);
    if now_rows != 1 {
        return ScenarioOutcome::fail(NAME, format!("datetime() read returned {now_rows} rows"));
    }

    // Liveness + consistency: every committed node is readable back, none lost under the hostile clock.
    let present = count_rows(&mut eng, "MATCH (n:Clocked) RETURN n.id", vec![]);
    if present as i64 != n {
        return ScenarioOutcome::fail(
            NAME,
            format!("present {present} != created {n} under hostile clock"),
        );
    }

    ScenarioOutcome::pass(NAME, format!("{n} writes survived skew/jump/regression"))
}

// ---- load-shape scenarios (reuse the VOPR runner) -------------------------------------------------

/// Asserts a VOPR run replays identically, produces no spurious errors, and is internally consistent
/// (`created == persisted`). The shared oracle for the load-shape scenarios.
fn vopr_live_and_consistent(name: &'static str, cfg: VoprConfig) -> ScenarioOutcome {
    let a = vopr::run(cfg);
    let b = vopr::run(cfg);
    if a != b {
        return ScenarioOutcome::fail(name, "non-deterministic run");
    }
    if a.err_ops != 0 {
        return ScenarioOutcome::fail(name, format!("{} spurious errors", a.err_ops));
    }
    if a.created_nodes != a.persisted_nodes {
        return ScenarioOutcome::fail(
            name,
            format!(
                "created {} != persisted {}",
                a.created_nodes, a.persisted_nodes
            ),
        );
    }
    ScenarioOutcome::pass(
        name,
        format!("{} ops, {} nodes", a.steps, a.persisted_nodes),
    )
}

/// A light VOPR config (8 clients × 24 ops) for the load-shape scenarios — enough interleaving to
/// exercise the arrival shape while staying fast in a debug build.
fn load_shape_cfg(seed: u64, load: LoadProfile) -> VoprConfig {
    // These scenarios certify the *arrival-shape* liveness of the legacy per-op path, so they run in
    // pure auto-commit mode (`auto_commit_permille = 1000`): every op is its own one-statement
    // transaction, exactly the pre-#235 behaviour. The cooperative-interleaver overlap and contention
    // are certified separately by the `vopr` unit tests.
    VoprConfig {
        clients: 8,
        ops_per_client: 24,
        load,
        auto_commit_permille: 1000,
        ..VoprConfig::for_seed(seed)
    }
}

/// Spike load: a thundering-herd arrival shape (periodic back-to-back bursts) stays live + consistent.
fn spike_load(seed: u64) -> ScenarioOutcome {
    let cfg = load_shape_cfg(
        seed,
        LoadProfile::Spike {
            base: 40,
            period: 16,
            burst: 6,
        },
    );
    vopr_live_and_consistent("spike_load", cfg)
}

/// Ramp load: accelerating arrivals (inter-arrival delay shrinking over the run) stay live + consistent.
fn ramp_load(seed: u64) -> ScenarioOutcome {
    let cfg = load_shape_cfg(seed, LoadProfile::Ramp { start: 200, end: 1 });
    vopr_live_and_consistent("ramp_load", cfg)
}

/// Sustained high concurrency: many interleaved clients issuing many ops complete with monotone
/// progress and no lost/duplicated work. Certifies liveness + consistency under heavy concurrency.
///
/// Sized to stay fast in a debug build (the workload's `MATCH (:Person {id})` is an unindexed scan, so
/// cost grows with the graph) while still driving deep interleaving across many clients. Raw scale is
/// the job of the `vopr` CLI seed-sweep, not this in-crate quick battery.
fn sustained_high_concurrency(seed: u64) -> ScenarioOutcome {
    // Pure auto-commit (legacy per-op) mode: this scenario certifies sustained-concurrency liveness of
    // the auto-commit path with no spurious errors; the explicit-transaction interleaver's contention
    // outcomes are certified by the `vopr` unit tests.
    let cfg = VoprConfig {
        clients: 16,
        ops_per_client: 12,
        pool_pages: 512,
        mix: MixProfile::write_heavy(),
        load: LoadProfile::Steady { min: 1, max: 30 },
        auto_commit_permille: 1000,
        ..VoprConfig::for_seed(seed)
    };
    // Determinism + consistency (two runs).
    let a = vopr::run(cfg);
    let b = vopr::run(cfg);
    if a != b {
        return ScenarioOutcome::fail("sustained_high_concurrency", "non-deterministic run");
    }
    if a.err_ops != 0 {
        return ScenarioOutcome::fail(
            "sustained_high_concurrency",
            format!("{} spurious errors", a.err_ops),
        );
    }
    if a.created_nodes != a.persisted_nodes {
        return ScenarioOutcome::fail(
            "sustained_high_concurrency",
            format!(
                "created {} != persisted {}",
                a.created_nodes, a.persisted_nodes
            ),
        );
    }
    // Non-vacuous: every scheduled op ran (monotone progress) and real work happened.
    if a.steps == (cfg.clients * cfg.ops_per_client) as usize && a.created_nodes > 50 {
        ScenarioOutcome::pass(
            "sustained_high_concurrency",
            format!(
                "{} clients, {} ops, {} nodes",
                cfg.clients, a.steps, a.created_nodes
            ),
        )
    } else {
        ScenarioOutcome::fail(
            "sustained_high_concurrency",
            format!(
                "under-exercised: steps {} nodes {}",
                a.steps, a.created_nodes
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_catalogue_passes_across_a_seed_sweep() {
        let outcomes = run_sweep(1..=3);
        let failures: Vec<&ScenarioOutcome> = outcomes.iter().filter(|o| !o.ok).collect();
        assert!(
            failures.is_empty(),
            "all catalogue scenarios must pass across the seed sweep; failures: {failures:?}"
        );
        // The sweep actually ran every scenario for every seed.
        assert_eq!(outcomes.len(), catalogue().len() * 3);
    }

    /// **Guards rmp #220 (FIXED).** Concurrent edge writers on one supernode must keep **exactly the
    /// committed edges**, for every concurrency K: fan-out == number of committed writers, never 0.
    /// This was previously a *pin* of the bug (at K>=3 fan-out collapsed to 0 because an SSI loser's
    /// rollback clobbered the shared chain head and severed the freshly-created records below it, and
    /// — at the catalog level — reset the id high-water / token dictionary that committed concurrent
    /// records depended on). The storage-layer fix (chain-head compare-and-set logical undo +
    /// header-only creation undo + monotonic catalog floor on rollback) turns the pin into this guard.
    #[test]
    fn supernode_high_concurrency_keeps_committed_edges_guards_220() {
        // Safe boundary: two concurrent writers — both edges persist.
        let mut eng = engine();
        let _ = write(&mut eng, "CREATE (:Hub {id: 1})", vec![]);
        let (c2, f2) = two_concurrent_edge_writers(&mut eng, 1);
        assert_eq!(
            (c2, f2),
            (2, Some(2)),
            "two concurrent writers must keep both edges"
        );

        // With K>=3 concurrently-open writers, SSI aborts the dangerous pivots; every edge that
        // COMMITS must survive — fan-out equals the committed count (NOT 0). Driven through the reusable
        // degree-sweep parameter (rmp #462) so the guarantee holds at every K, not just one.
        for o in supernode_degree_sweep(&[2, 3, 4, 6, 8, 12, 16, 24]) {
            assert!(o.committed >= 1, "at least one writer commits at K={}", o.k);
            assert_eq!(
                o.fanout,
                Some(o.committed),
                "rmp #220 (fixed): at K={} every committed edge must survive (fan-out == committed)",
                o.k
            );
        }
    }

    /// **rmp #462 (F-DST-5).** The promoted, reusable [`supernode_degree_sweep`] drives an arbitrary set
    /// of degrees and is policy-free: here a *wider* exploratory sweep (including odd corners beyond the
    /// pinned set) still upholds `fanout == committed` at every rung, proving the parameter is genuinely
    /// reusable for corner exploration, not just the fixed regression set.
    #[test]
    fn reusable_degree_sweep_holds_for_arbitrary_degrees() {
        let outcomes = supernode_degree_sweep(&[1, 5, 7, 10, 20, 32]);
        assert_eq!(
            outcomes.len(),
            6,
            "every requested degree produced an outcome"
        );
        for o in outcomes {
            assert_eq!(
                o.fanout,
                Some(o.committed),
                "rmp #462: the reusable sweep upholds fan-out == committed at K={}",
                o.k
            );
        }
    }

    /// **rmp #462 (F-DST-5 coverage watermark).** Proves the swarmed VOPR actually **reaches the corner
    /// that matters**: across a bounded swarmed seed range, some seed drives **≥3 concurrently-open
    /// writers** *and* some seed runs under **buffer-pool eviction pressure** (a working set larger than
    /// the pool, so the pool cannot hold it and must evict/steal). The `#220` lesson — the bug only
    /// surfaced at ≥3 concurrent writers — is why corner-reaching, not just raw seed count, must be
    /// asserted. Without this watermark a "256-seed swarm" could silently never reach the corner.
    #[test]
    fn swarm_reaches_three_writers_and_eviction_pressure() {
        use crate::vopr::{self, VoprConfig};

        let mut max_open_seen = 0usize;
        let mut eviction_pressure_seen = false;
        // A bounded swarmed range — enough to hit the corners, fast in a debug build.
        for seed in 1u64..=128 {
            let cfg = VoprConfig::swarm(seed);
            let pool_pages = cfg.pool_pages;
            let r = vopr::run(cfg);
            max_open_seen = max_open_seen.max(r.max_open_txns);
            // Eviction pressure: the committed working set exceeds the buffer pool, so the pool provably
            // could not hold it all resident — eviction/steal must have occurred during the run.
            if (r.persisted_nodes as usize) > pool_pages {
                eviction_pressure_seen = true;
            }
        }
        assert!(
            max_open_seen >= 3,
            "the swarm must reach >=3 concurrently-open writers on some seed (max seen {max_open_seen})"
        );
        assert!(
            eviction_pressure_seen,
            "the swarm must reach buffer-pool eviction pressure (working set > pool) on some seed"
        );
    }

    /// **rmp #233.** The hostile-clock scenario certifies the clock-fault tolerance contract: under a
    /// seed-driven [`FaultyClock`] (skew + forward jumps + non-monotonic regressions) the engine never
    /// panics, never produces a negative duration (its latency arithmetic saturates), and loses no
    /// committed work. Asserted across a seed sweep so the property holds for many fault sequences,
    /// and replayed per seed to confirm determinism.
    #[test]
    fn hostile_clock_tolerance_holds_across_seeds() {
        for seed in 1u64..=8 {
            let a = hostile_clock(seed);
            let b = hostile_clock(seed);
            assert_eq!(
                a, b,
                "hostile_clock must replay identically for seed {seed}"
            );
            assert!(
                a.ok,
                "engine must tolerate the hostile clock at seed {seed}: {}",
                a.detail
            );
        }
    }

    #[test]
    fn catalogue_is_deterministic() {
        // Each scenario replays identically for a fixed seed.
        for (name, scenario) in catalogue() {
            let a = scenario(7);
            let b = scenario(7);
            assert_eq!(a, b, "scenario {name} must be deterministic");
        }
    }

    #[test]
    fn scenarios_cover_the_known_patterns() {
        let names: Vec<&str> = catalogue().iter().map(|(n, _)| *n).collect();
        for expected in [
            "oltp_mixed",
            "bulk_ingest",
            "read_serving",
            "deep_traversal",
            "supernode_fanout",
            "large_result_stream",
            "cyclic_traversal",
            "point_lookup",
            "aggregation_analytics",
            "contended_writes",
            "concurrent_supernode",
            "snapshot_isolation",
            "property_index_oracle",
            "transaction_rollback",
            "churn_create_delete",
            "crash_recovery_durability",
            "backup_restore_crash",
            "network_bulk_ingest_mode_a",
            "hostile_clock",
            "spike_load",
            "ramp_load",
            "sustained_high_concurrency",
        ] {
            assert!(
                names.contains(&expected),
                "catalogue must include {expected}"
            );
        }
    }

    /// **rmp #440.** The backup → seal → file → restore / key-rotation crash scenario opens to a
    /// committed-only, consistent state under exactly the expected key at every crash window, and
    /// replays identically per seed (determinism). A real regression gate: a torn backup/device write,
    /// a wrong-key open, or a half-applied restore makes some seed fail here.
    #[test]
    fn backup_restore_crash_recovers_at_every_window_across_seeds() {
        for seed in 1u64..=6 {
            let a = backup_restore_crash(seed);
            let b = backup_restore_crash(seed);
            assert_eq!(
                a, b,
                "backup_restore_crash must replay identically for seed {seed}"
            );
            assert!(
                a.ok,
                "backup/restore crash recovery must hold at seed {seed}: {}",
                a.detail
            );
        }
    }

    /// **rmp #519.** The network-bulk-import Mode A scenario replays identically and holds across a
    /// wider seed range than the catalogue's own quick 1..=3 sweep, so a regression in JUST this
    /// scenario (batching stats, the idempotent-retry proof, or crash-mid-session sentinel/data
    /// durability) fails clearly and fast without needing the whole-catalogue sweep.
    #[test]
    fn network_bulk_ingest_mode_a_holds_across_seeds() {
        for seed in 1u64..=20 {
            let a = network_bulk_ingest_mode_a(seed);
            let b = network_bulk_ingest_mode_a(seed);
            assert_eq!(
                a, b,
                "network_bulk_ingest_mode_a must replay identically for seed {seed}"
            );
            assert!(
                a.ok,
                "network_bulk_ingest_mode_a must hold at seed {seed}: {}",
                a.detail
            );
        }
    }

    /// **rmp #520.** The network-bulk-import Mode B scenario replays identically and holds across a
    /// wider seed range than the catalogue's own quick 1..=3 sweep, so a regression in JUST this
    /// scenario (joint serializability, the seeded-abort idempotent-retry proof, snapshot visibility,
    /// dense-node fan-out, chunking bounds, or crash-mid-batch reconciliation) fails clearly and fast
    /// without needing the whole-catalogue sweep.
    #[test]
    fn network_bulk_ingest_mode_b_holds_across_seeds() {
        for seed in 1u64..=20 {
            let a = network_bulk_ingest_mode_b(seed);
            let b = network_bulk_ingest_mode_b(seed);
            assert_eq!(
                a, b,
                "network_bulk_ingest_mode_b must replay identically for seed {seed}"
            );
            assert!(
                a.ok,
                "network_bulk_ingest_mode_b must hold at seed {seed}: {}",
                a.detail
            );
        }
    }
}
