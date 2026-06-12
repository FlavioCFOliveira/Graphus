//! LDBC-SNB-*flavoured* macro benchmark harness for Graphus (`rmp` task #27).
//!
//! This is the **macro** half of the standing verification arsenal: where the Criterion micro-
//! benchmarks (`benches/commit_path.rs`, `benches/read_path.rs`) isolate one path, this harness runs
//! a whole social-network workload — generate a synthetic graph, then drive a mix of representative
//! Social-Network-Benchmark-style read and write operations through the **real** engine pipeline
//! (`TxnCoordinator` over a `RecordStore`) — and reports end-to-end throughput and latency
//! percentiles per operation.
//!
//! It is a *scaled, inspired* harness, **not** the official LDBC SNB driver: see [`generator`] and
//! `crates/graphus-bench/LDBC.md` for the precise provenance and the mapping of each operation to
//! the official Interactive/BI query it is modelled on (and which official queries are deferred
//! because they need Cypher the engine does not yet support).
//!
//! Run it:
//! ```text
//! cargo run -p graphus-bench --bin ldbc_snb            # tiny scale (seconds)
//! cargo run -p graphus-bench --release --bin ldbc_snb -- --medium
//! ```

pub mod correctness;
pub mod driver;
pub mod generator;
pub mod operations;

use std::time::{Duration, Instant};

use generator::{GraphStats, ScaleFactor, SnbModel};
use graphus_cypher::binding::Parameters;
use graphus_txn::IsolationLevel;
use operations::Operation;

use driver::{Coord, RunError, fresh_coord, run_statement};

/// How many invocations of each operation to time (the working set per operation). Small by default
/// so the whole harness runs in seconds; the report notes it.
pub const INVOCATIONS_PER_OP: u64 = 200;

/// The measured result for one operation across all its invocations.
pub struct OpReport {
    pub id: &'static str,
    pub label: &'static str,
    pub inspired_by: &'static str,
    pub is_write: bool,
    /// `Ok` with the latency histogram (nanoseconds, one per successful invocation), or `Err` with
    /// the classified reason the engine could not run this operation (so it is reported deferred).
    pub outcome: Result<Vec<u128>, RunError>,
    /// A representative row count from the first successful invocation (sanity that it did work).
    pub sample_rows: usize,
}

/// The property indexes the harness creates after the load, mirroring the official SNB setup
/// (every Interactive point lookup anchors on an `id` property). With these in place the planner's
/// inline-equality index selection turns `MATCH (:Person {id: x})` from an O(n) label scan into an
/// index seek (`rmp` #58).
const INDEXES: &[(&str, &str)] = &[("Person", "id"), ("Forum", "id"), ("Post", "id")];

/// The full harness report.
pub struct Report {
    pub scale: ScaleFactor,
    pub stats: GraphStats,
    pub load_latency: Duration,
    /// Time to build the standard SNB-style `id` property indexes after the load.
    pub index_build_latency: Duration,
    pub ops: Vec<OpReport>,
}

/// Runs the whole harness: generate the graph at `scale`, build the standard SNB-style property
/// indexes, then time every operation in the catalog. Reads run against the loaded graph; the
/// single write operation runs against the same coordinator (its inserts use disjoint synthetic
/// ids so they neither collide nor distort read results materially at this scale).
///
/// # Errors
/// Returns an error only if **graph generation or index creation** fails (a harness bug — a
/// generator statement outside the engine's subset). Per-operation failures are captured in
/// [`OpReport::outcome`], never propagated, so the macro benchmark always runs to completion.
pub fn run(scale: ScaleFactor) -> Result<Report, RunError> {
    run_with(scale, INVOCATIONS_PER_OP)
}

/// As [`run`], but with an explicit per-operation invocation count. Used by the standing completion
/// test with a small count (so the unoptimized test build stays fast while still exercising every
/// operation end to end); the `ldbc_snb` binary and a release run use [`INVOCATIONS_PER_OP`] via
/// [`run`].
///
/// # Errors
/// Same contract as [`run`]: only graph generation / index creation failures propagate.
pub fn run_with(scale: ScaleFactor, invocations: u64) -> Result<Report, RunError> {
    let mut coord = fresh_coord();

    let load_start = Instant::now();
    let (model, stats) = generator::generate(&mut coord, scale)?;
    let load_latency = load_start.elapsed();

    let index_start = Instant::now();
    for (label, property) in INDEXES {
        coord
            .create_node_property_index(label, property)
            .map_err(|e| RunError::Execute(format!("create index {label}.{property}: {e}")))?;
    }
    let index_build_latency = index_start.elapsed();

    let mut ops = Vec::new();
    for op in operations::catalog() {
        ops.push(time_operation(&mut coord, &op, &model, invocations));
    }

    Ok(Report {
        scale,
        stats,
        load_latency,
        index_build_latency,
        ops,
    })
}

/// Times one operation over `invocations` invocations. The first failure short-circuits to a
/// deferred outcome (if the engine rejects this query form, it rejects every invocation of it).
fn time_operation(
    coord: &mut Coord,
    op: &Operation,
    model: &SnbModel,
    invocations: u64,
) -> OpReport {
    let mut latencies = Vec::with_capacity(invocations as usize);
    let mut sample_rows = 0usize;
    let isolation = if op.is_write {
        IsolationLevel::Serializable
    } else {
        // Reads run at snapshot isolation — the common OLTP read level; they take a consistent
        // snapshot and never block writers (`04 §5.4`/§9.1).
        IsolationLevel::Snapshot
    };

    for i in 0..invocations {
        let src = (op.build)(i, model);
        match run_statement(coord, &src, &Parameters::new(), isolation) {
            Ok(result) => {
                if i == 0 {
                    sample_rows = result.rows.len();
                }
                latencies.push(result.latency.as_nanos());
            }
            Err(e) => {
                // First invocation failed → the form is unsupported; report deferred. A *later*
                // failure (e.g. a write SSI abort) is rarer; treat it the same — surface the reason.
                return OpReport {
                    id: op.id,
                    label: op.label,
                    inspired_by: op.inspired_by,
                    is_write: op.is_write,
                    outcome: Err(e),
                    sample_rows: 0,
                };
            }
        }
    }

    OpReport {
        id: op.id,
        label: op.label,
        inspired_by: op.inspired_by,
        is_write: op.is_write,
        outcome: Ok(latencies),
        sample_rows,
    }
}

/// The percentile `p` (0.0..=1.0) of an already-sorted nanosecond slice (nearest-rank).
#[must_use]
pub fn percentile(sorted_nanos: &[u128], p: f64) -> u128 {
    if sorted_nanos.is_empty() {
        return 0;
    }
    let rank = (p * (sorted_nanos.len() - 1) as f64).round() as usize;
    sorted_nanos[rank.min(sorted_nanos.len() - 1)]
}

/// Renders the report as a human-readable text block (printed by the binary; also asserted on in
/// tests). Latency is in microseconds; throughput in operations/second from the mean latency.
#[must_use]
pub fn render(report: &Report) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();

    let _ = writeln!(
        out,
        "================================================================"
    );
    let _ = writeln!(out, " Graphus LDBC-SNB-flavoured macro benchmark");
    let _ = writeln!(
        out,
        "================================================================"
    );
    let s = &report.scale;
    let st = &report.stats;
    let _ = writeln!(
        out,
        " scale: persons={} knows/p={} forums={} posts/forum={} comments/post={} batch={}",
        s.persons, s.knows_per_person, s.forums, s.posts_per_forum, s.comments_per_post, s.batch
    );
    let _ = writeln!(
        out,
        " graph: {} nodes ({} persons, {} forums, {} posts, {} comments), {} rels ({} KNOWS)",
        st.nodes(),
        st.persons,
        st.forums,
        st.posts,
        st.comments,
        st.rels(),
        st.knows_edges
    );
    let _ = writeln!(
        out,
        " load:  {} write transactions in {:.3}s ({:.0} commits/s)",
        st.load_txns,
        report.load_latency.as_secs_f64(),
        st.load_txns as f64 / report.load_latency.as_secs_f64().max(1e-9)
    );
    let _ = writeln!(
        out,
        " index: {} property indexes built in {:.3}s ({})",
        INDEXES.len(),
        report.index_build_latency.as_secs_f64(),
        INDEXES
            .iter()
            .map(|(l, p)| format!("{l}.{p}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let _ = writeln!(
        out,
        " each operation timed over {INVOCATIONS_PER_OP} invocations"
    );
    let _ = writeln!(
        out,
        "----------------------------------------------------------------"
    );
    let _ = writeln!(
        out,
        " {:<14} {:>3} {:>9} {:>9} {:>9} {:>12} {:>6}",
        "operation", "rw", "p50(us)", "p99(us)", "max(us)", "ops/s", "rows"
    );
    let _ = writeln!(
        out,
        "----------------------------------------------------------------"
    );

    for op in &report.ops {
        let rw = if op.is_write { "W" } else { "R" };
        match &op.outcome {
            Ok(latencies) => {
                let mut sorted = latencies.clone();
                sorted.sort_unstable();
                let p50 = percentile(&sorted, 0.50) as f64 / 1000.0;
                let p99 = percentile(&sorted, 0.99) as f64 / 1000.0;
                let max = *sorted.last().unwrap_or(&0) as f64 / 1000.0;
                let mean_ns = sorted.iter().sum::<u128>() as f64 / sorted.len().max(1) as f64;
                let ops_per_sec = if mean_ns > 0.0 {
                    1_000_000_000.0 / mean_ns
                } else {
                    0.0
                };
                let _ = writeln!(
                    out,
                    " {:<14} {:>3} {:>9.2} {:>9.2} {:>9.2} {:>12.0} {:>6}",
                    op.id, rw, p50, p99, max, ops_per_sec, op.sample_rows
                );
            }
            Err(reason) => {
                let _ = writeln!(
                    out,
                    " {:<14} {:>3} {:>9} {:>9} {:>9} {:>12} {:>6}   DEFERRED: {}",
                    op.id, rw, "-", "-", "-", "-", "-", reason
                );
            }
        }
    }
    let _ = writeln!(
        out,
        "----------------------------------------------------------------"
    );

    let supported = report.ops.iter().filter(|o| o.outcome.is_ok()).count();
    let _ = writeln!(
        out,
        " {supported}/{} operations supported and measured; the rest are deferred (unsupported Cypher).",
        report.ops.len()
    );
    let _ = writeln!(
        out,
        " Correctness: every operation is checked against the deterministic generator's ground truth"
    );
    let _ = writeln!(
        out,
        "   by `cargo test -p graphus-bench` (the offline substitute for official LDBC validation)."
    );

    // Transparently list the official queries this offline harness does not attempt, and why.
    let deferred = operations::deferred_official_queries();
    if !deferred.is_empty() {
        let _ = writeln!(
            out,
            "----------------------------------------------------------------"
        );
        let _ = writeln!(out, " Deferred official LDBC queries (offline scope):");
        for (query, reason) in &deferred {
            let _ = writeln!(out, "   - {query}: {reason}");
        }
    }

    let _ = writeln!(
        out,
        "----------------------------------------------------------------"
    );
    let _ = writeln!(
        out,
        " Provenance: inspired, scaled SNB workload — NOT the official LDBC driver (see LDBC.md)."
    );
    let _ = writeln!(
        out,
        " Offline scope: no official Datagen/dataset/audited validation; numbers are a RELATIVE"
    );
    let _ = writeln!(
        out,
        "   Graphus-vs-Graphus regression signal, not comparable to published LDBC results."
    );
    let _ = writeln!(
        out,
        "================================================================"
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small invocation count for the standing completion test, so the unoptimized test build stays
    /// fast across all 24 operations (the full [`INVOCATIONS_PER_OP`] is the perf-run default used by
    /// the `ldbc_snb` binary). Correctness is verified separately by [`crate::ldbc::correctness`].
    const TEST_INVOCATIONS: u64 = 8;

    /// The harness runs to completion at the micro scale, builds a non-trivial graph, and measures
    /// every operation — including the canonical 2-hop friends-of-friends traversal. This is the test
    /// embodiment of the AC "LDBC SNB runs".
    ///
    /// One `run_with()` builds the whole graph (an O(persons²) label-scan load), so every assertion
    /// shares that single run. Uses the `micro` scale + a small invocation count so the unoptimized
    /// test build stays fast; the larger `tiny`/`medium` scales and the full invocation count are for
    /// the `ldbc_snb` binary in release.
    #[test]
    fn ldbc_harness_runs_to_completion_at_micro_scale() {
        let scale = ScaleFactor::micro();
        let report = run_with(scale, TEST_INVOCATIONS).expect("harness runs");

        // The graph was actually built at the configured scale.
        assert_eq!(
            report.stats.persons, scale.persons,
            "person count matches the scale"
        );
        assert!(report.stats.knows_edges > 0, "KNOWS edges were created");
        assert!(report.stats.posts > 0, "posts were created");
        assert!(report.stats.comments > 0, "comments were created");
        assert!(
            report.stats.load_txns > 0,
            "the load committed transactions"
        );

        let by_id = |id: &str| report.ops.iter().find(|o| o.id == id).expect("op present");

        // The core read operations the engine supports — incl. the 2-hop friends-of-friends traversal
        // (`IC-fof`), proving the harness exercises real multi-hop traversal, not just point reads —
        // must have measured (not deferred) and timed every invocation.
        for id in ["IS1-profile", "IS3-friends", "IC-fof", "BI-pop"] {
            let op = by_id(id);
            assert!(
                op.outcome.is_ok(),
                "core operation {id} must be supported, got: {:?}",
                op.outcome.as_ref().err().map(ToString::to_string)
            );
            let lat = op.outcome.as_ref().unwrap();
            assert_eq!(
                lat.len() as u64,
                TEST_INVOCATIONS,
                "{id} timed every invocation"
            );
        }

        // Every catalog operation must be supported and measured at this scale (0 deferred) — the
        // broadened set is fully exercised, not partially.
        for op in &report.ops {
            assert!(
                op.outcome.is_ok(),
                "operation {} must be supported (not deferred), got: {:?}",
                op.id,
                op.outcome.as_ref().err().map(ToString::to_string)
            );
        }

        // The population aggregate over all persons returns exactly one row.
        assert_eq!(
            by_id("BI-pop").sample_rows,
            1,
            "an aggregate returns exactly one row"
        );

        // The rendered report is non-empty and mentions the provenance disclaimer + the scale, plus
        // the offline-scope transparency: the deferred official queries and the "relative signal"
        // caveat (so the honest-scope requirement is regression-guarded).
        let text = render(&report);
        assert!(text.contains("NOT the official LDBC driver"));
        assert!(text.contains(&format!("persons={}", scale.persons)));
        assert!(
            text.contains("Deferred official LDBC queries"),
            "report lists the deferred official queries"
        );
        assert!(
            text.contains("RELATIVE"),
            "report states the numbers are a relative regression signal"
        );
        assert!(
            text.contains("ground truth"),
            "report points at the ground-truth correctness check"
        );
    }
}
