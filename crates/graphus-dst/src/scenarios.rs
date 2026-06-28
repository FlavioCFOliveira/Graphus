//! `scenarios` — a named, documented catalogue of **known graph-DB usage patterns** exercised through
//! the deterministic simulator (rmp #173). It demonstrates breadth ("test all the known scenarios")
//! and is the CI-friendly entry point: [`run_sweep`] runs every scenario across a seed range and
//! reports pass/fail.
//!
//! Each scenario drives the *real* engine (inline, deterministic) and checks an oracle appropriate to
//! it (row counts, `created == persisted`, no spurious errors, SSI conflict detection). The workload
//! scenarios reuse [`crate::vopr`] + [`crate::mix`]; the structural ones drive a [`LocalEngine`]
//! directly. Everything is a pure function of the seed.

use std::sync::Arc;

use graphus_core::Value;
use graphus_cypher::MaterializedValue;
use graphus_io::{MemBlockDevice, atomic_replace_file};
use graphus_server::engine::LocalEngine;
use graphus_server::engine::command::AccessMode;
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
}
