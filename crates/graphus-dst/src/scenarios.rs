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
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::LocalEngine;
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
        Self { name, ok: true, detail: detail.into() }
    }
    fn fail(name: &'static str, detail: impl Into<String>) -> Self {
        Self { name, ok: false, detail: detail.into() }
    }
}

/// A scenario: a deterministic function of the seed returning its outcome.
pub type Scenario = fn(u64) -> ScenarioOutcome;

/// The full catalogue of `(name, scenario)` pairs.
#[must_use]
pub fn catalogue() -> Vec<(&'static str, Scenario)> {
    vec![
        ("oltp_mixed", oltp_mixed),
        ("bulk_ingest", bulk_ingest),
        ("read_serving", read_serving),
        ("deep_traversal", deep_traversal),
        ("supernode_fanout", supernode_fanout),
        ("large_result_stream", large_result_stream),
        ("contended_writes", contended_writes),
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
            format!("created {} != persisted {}", a.created_nodes, a.persisted_nodes),
        );
    }
    ScenarioOutcome::pass("oltp_mixed", format!("{} ops, {} nodes", a.steps, a.persisted_nodes))
}

/// Bulk ingest: a write-heavy workload persists every acked create.
fn bulk_ingest(seed: u64) -> ScenarioOutcome {
    let cfg = VoprConfig::for_seed(seed).with_mix(MixProfile::write_heavy());
    let r = vopr::run(cfg);
    if r.created_nodes == r.persisted_nodes && r.err_ops == 0 {
        ScenarioOutcome::pass("bulk_ingest", format!("ingested {} nodes", r.persisted_nodes))
    } else {
        ScenarioOutcome::fail(
            "bulk_ingest",
            format!("created {} persisted {} errs {}", r.created_nodes, r.persisted_nodes, r.err_ops),
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
        if !write(&mut eng, "CREATE (:Node {id: $id})", vec![("id".into(), Value::Integer(base + i))]) {
            return ScenarioOutcome::fail("deep_traversal", "create node failed");
        }
    }
    for i in 0..N {
        let ok = write(
            &mut eng,
            "MATCH (a:Node {id: $a}), (b:Node {id: $b}) CREATE (a)-[:NEXT]->(b)",
            vec![("a".into(), Value::Integer(base + i)), ("b".into(), Value::Integer(base + i + 1))],
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
        ScenarioOutcome::pass("deep_traversal", format!("reached {reached} via var-length"))
    } else {
        ScenarioOutcome::fail("deep_traversal", format!("only reached {reached} of {N}"))
    }
}

/// Supernode / hotspot: one hub with a large fan-out; counting its out-edges returns the fan-out.
fn supernode_fanout(seed: u64) -> ScenarioOutcome {
    const M: i64 = 60;
    let mut eng = engine();
    let base = (seed % 1000) as i64;
    if !write(&mut eng, "CREATE (:Hub {id: $id})", vec![("id".into(), Value::Integer(base))]) {
        return ScenarioOutcome::fail("supernode_fanout", "create hub failed");
    }
    for i in 0..M {
        let ok = write(
            &mut eng,
            "MATCH (h:Hub {id: $h}) CREATE (h)-[:LINK]->(:Leaf {id: $l})",
            vec![("h".into(), Value::Integer(base)), ("l".into(), Value::Integer(base * 1000 + i))],
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
        if !write(&mut eng, "CREATE (:Item {id: $id})", vec![("id".into(), Value::Integer(base + i))]) {
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
        ScenarioOutcome::fail("contended_writes", "both concurrent writers committed (lost update)")
    } else {
        ScenarioOutcome::pass("contended_writes", format!("conflict detected (c1={c1} c2={c2})"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_catalogue_passes_across_a_seed_sweep() {
        let outcomes = run_sweep(1..=5);
        let failures: Vec<&ScenarioOutcome> = outcomes.iter().filter(|o| !o.ok).collect();
        assert!(
            failures.is_empty(),
            "all catalogue scenarios must pass across the seed sweep; failures: {failures:?}"
        );
        // The sweep actually ran every scenario for every seed.
        assert_eq!(outcomes.len(), catalogue().len() * 5);
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
            "contended_writes",
        ] {
            assert!(names.contains(&expected), "catalogue must include {expected}");
        }
    }
}
