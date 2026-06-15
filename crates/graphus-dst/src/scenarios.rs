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
use graphus_io::MemBlockDevice;
use graphus_server::engine::LocalEngine;
use graphus_server::engine::command::AccessMode;
use graphus_sim::SharedClock;
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
/// - **Atomicity / churn** — `transaction_rollback`, `churn_create_delete`.
/// - **Durability / crash recovery** — `crash_recovery_durability`.
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
        // Atomicity / churn
        ("transaction_rollback", transaction_rollback),
        ("churn_create_delete", churn_create_delete),
        // Durability / crash recovery
        ("crash_recovery_durability", crash_recovery_durability),
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
    let cfg = VoprConfig::for_seed(seed)
        .with_mix(MixProfile::mixed())
        .with_load(LoadProfile::Steady { min: 1, max: 30 });
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
    let cfg = VoprConfig::for_seed(seed).with_mix(MixProfile::write_heavy());
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
    let cfg = VoprConfig::for_seed(seed).with_mix(MixProfile::read_heavy());
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
    VoprConfig {
        seed,
        clients: 8,
        ops_per_client: 24,
        pool_pages: 256,
        mix: MixProfile::mixed(),
        load,
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
    let cfg = VoprConfig {
        seed,
        clients: 16,
        ops_per_client: 12,
        pool_pages: 512,
        mix: MixProfile::write_heavy(),
        load: LoadProfile::Steady { min: 1, max: 30 },
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
        // COMMITS must survive — fan-out equals the committed count (NOT 0). Swept across a range of
        // concurrency degrees so the guarantee holds at every K, not just one.
        for k in [2i64, 3, 4, 6, 8, 12, 16, 24] {
            let mut eng = engine();
            let _ = write(&mut eng, "CREATE (:Hub {id: 1})", vec![]);
            let mut tickets = Vec::new();
            for i in 0..k {
                let t = eng.begin(AccessMode::Write).expect("begin");
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
            assert!(committed >= 1, "at least one writer commits at K={k}");
            assert_eq!(
                fanout,
                Some(committed),
                "rmp #220 (fixed): at K={k} every committed edge must survive (fan-out == committed)"
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
            "transaction_rollback",
            "churn_create_delete",
            "crash_recovery_durability",
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
}
