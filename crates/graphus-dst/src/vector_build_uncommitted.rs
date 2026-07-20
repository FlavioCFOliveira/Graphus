//! Focused deterministic reproducer for a **vector (HNSW) index build baking an UNCOMMITTED embedding
//! over the committed one** (`rmp` #780) — the vector member of the `rmp` #766 family, whose text
//! sibling is `rmp` #773, full-text sibling `rmp` #778 and spatial sibling `rmp` #779.
//!
//! ## The defect
//!
//! The per-entity vector build helpers collapsed an embedding property's version chain **newest-wins**.
//! When the newest version belonged to a still-open transaction, that dirty embedding was the only one
//! indexed and the COMMITTED one was indexed **nowhere**.
//!
//! Vector is the one index kind with no approximate fallback, so the symptom is not a missing row but a
//! **wrong** one: a FRESH auto-commit reader's `k = 1` returned the wrong entity, and the `score` it
//! reported was computed from a vector that reader's snapshot cannot observe — a dirty read on the
//! score channel, not a recall artifact. The consumer could not repair either: its per-candidate
//! re-check validates the embedding's SHAPE, never its geometry.
//!
//! As with `rmp` #779, the `rmp` #467 freshness marker did not save it, and for the same reason: a
//! writer that **predates the index** is never recorded as a mutator, because the registration list the
//! write path iterates is empty before the index exists.
//!
//! ## The fix this pins
//!
//! The build now detects the conflict (`active_writer_holds_newest_covered`, the predicate written for
//! `rmp` #778), **skips** the entity rather than baking a dirty vector, and records the blocking
//! writers against that index. While any blocker is unresolved, every k-NN **declines to an exact
//! brute-force scan** over snapshot-visible embeddings — the "decline to the scan" contract every other
//! index kind already had, which vector was thought not to be able to have. It can: the scan shares
//! `graphus_index::similarity_score` with both the HNSW and the Cypher `vector.similarity.*` functions,
//! so it is identical in scale and *exact* where the index is approximate. Once every blocker resolves,
//! a re-fill wipes and rebuilds the graph and the fast path returns.
//!
//! ## Why the DST, not only the coordinator tests
//!
//! The anomaly needs a statement-interleaved timeline — a seed committing an embedding; a writer moving
//! it and staying **open**; the production `CREATE VECTOR INDEX` route running *while that writer is
//! open*; then a fresh reader — observed on the production build route driven Online. Driven inline
//! over the deterministic `MemBlockDevice` + `MemLogSink` coordinator it is fully reproducible.
//!
//! ## The crash variant proves the rebuild claim
//!
//! The HNSW is **ephemeral**: discarded on close and rebuilt from the recovered store on open, by the
//! same helpers this fix changed. Before the fix that was the ONLY thing that healed the defect — the
//! wrong answer survived the writer's rollback for the life of the process — so the reproducer crashes
//! after the writer's fate is sealed and asserts the reopened engine answers correctly for BOTH
//! endings.

use std::collections::HashMap;

use graphus_core::{TxnId, Value};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::recovery::recover_device;
use graphus_storage::{RecordStore, VectorEntity, VectorSimilarity};
use graphus_wal::{LogSink, MemLogSink, WalManager};

/// The coordinator type the reproducer drives.
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

/// A small buffer-pool capacity, so eviction + the WAL rule are exercised during the run.
const POOL_CAPACITY: usize = 16;

/// The query direction. `x` starts exactly here (cosine 1.0 -> score 1.0); `y` sits at cosine 0.9
/// (score 0.95). Both are unit vectors, so both scores are exact rather than approximate.
const QUERY: [f32; 3] = [1.0, 0.0, 0.0];

/// Decoys seeded around the query, node and relationship alike.
///
/// THE LOAD-BEARING PARAMETER (`rmp` #780 vacuity audit). With a two-entity corpus the procedure's
/// `2k` over-fetch returns EVERYTHING, so the ANN never makes a selection and the answer is decided
/// entirely by the consumer's re-score — which let an earlier version of this scenario pass with the
/// whole build gate deleted. Each decoy sits at cosine ~0.955, strictly between `x`'s committed
/// `[1,0,0]` (1.0) and its dirty `[0,0,1]` (0.0), so `x` wins only if the graph OFFERS it.
const DISTRACTORS: usize = 200;

/// The score of the nearest decoy — the answer once `x` is no longer the committed nearest.
#[cfg(test)]
const DISTRACTOR_TOP_SCORE: f64 = 0.977_668_285_369_873;

/// How the in-flight writer ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterEnding {
    /// The writer commits after the build ran: ITS embedding becomes the committed one, so `y`
    /// legitimately becomes the nearest neighbour.
    Commits,
    /// The writer rolls back after the build ran: the ORIGINAL embedding stays committed, so `x` must
    /// still be the nearest neighbour.
    RollsBack,
}

/// One reproduction's observations: the `(name, score)` of the single nearest neighbour, for nodes and
/// relationships, after the writer's fate is sealed and again after a crash + recovery.
#[derive(Debug, Clone, PartialEq)]
pub struct VectorBuildReport {
    /// The nearest `:Doc`, read after the writer's fate was sealed.
    pub node_nearest_after: Option<(String, f64)>,
    /// The nearest `:SIMILAR` relationship, read after the writer's fate was sealed.
    pub rel_nearest_after: Option<(String, f64)>,
    /// The nearest `:Doc`, read after a crash + recovery + HNSW rebuild.
    pub node_nearest_recovered: Option<(String, f64)>,
    /// The nearest `:SIMILAR` relationship, read after a crash + recovery + HNSW rebuild.
    pub rel_nearest_recovered: Option<(String, f64)>,
}

impl VectorBuildReport {
    /// The `rmp` #780 invariant: the nearest neighbour, and the score reported for it, are exactly what
    /// the committed state implies — before AND after recovery, for nodes and relationships alike.
    #[must_use]
    pub fn agrees_with(&self, expected: &(String, f64)) -> bool {
        let same = |got: &Option<(String, f64)>| {
            got.as_ref()
                .is_some_and(|g| g.0 == expected.0 && (g.1 - expected.1).abs() < 1e-6)
        };
        same(&self.node_nearest_after)
            && same(&self.rel_nearest_after)
            && same(&self.node_nearest_recovered)
            && same(&self.rel_nearest_recovered)
    }
}

fn compile(src: &str) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

fn rows(coord: &Coord, txn: TxnId, plan: &PhysicalPlan) -> Vec<graphus_cypher::runtime::Row> {
    let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let mut cursor = execute(plan, &bound, &mut graph).expect("open cursor");
    cursor.collect_all().expect("collect")
}

fn run_write(coord: &mut Coord, src: &str) {
    let plan = compile(src);
    let txn = coord.begin_serializable();
    let _ = rows(coord, txn, &plan);
    coord.commit(txn).expect("write commits");
}

fn vec_lit(v: &[f32]) -> String {
    let elems: Vec<String> = v.iter().map(|x| format!("{x:?}")).collect();
    format!("[{}]", elems.join(", "))
}

fn pid_map(coord: &Coord, txn: TxnId, pattern: &str) -> HashMap<u64, String> {
    rows(coord, txn, &compile(pattern))
        .iter()
        .map(|r| {
            let pid = match r.value("pid") {
                Value::Integer(i) => i as u64,
                other => panic!("pid must be an integer, got {other:?}"),
            };
            let name = match r.value("name") {
                Value::String(s) => s,
                other => panic!("name must be a string, got {other:?}"),
            };
            (pid, name)
        })
        .collect()
}

/// The single nearest `(name, score)` through `db.index.vector.queryNodes`, at a fresh snapshot.
fn nearest_node(coord: &mut Coord) -> Option<(String, f64)> {
    let txn = coord.begin_serializable();
    let map = pid_map(
        coord,
        txn,
        "MATCH (n:Doc) RETURN id(n) AS pid, n.name AS name",
    );
    let src = format!(
        "CALL db.index.vector.queryNodes('doc_vec', 1, {}) YIELD node, score \
         RETURN id(node) AS pid, score",
        vec_lit(&QUERY)
    );
    let out = first_hit(coord, txn, &src, &map);
    coord.commit(txn).expect("read commits");
    out
}

/// The relationship twin, through `db.index.vector.queryRelationships`.
fn nearest_rel(coord: &mut Coord) -> Option<(String, f64)> {
    let txn = coord.begin_serializable();
    let map = pid_map(
        coord,
        txn,
        "MATCH ()-[r:SIMILAR]->() RETURN id(r) AS pid, r.name AS name",
    );
    let src = format!(
        "CALL db.index.vector.queryRelationships('rel_vec', 1, {}) YIELD relationship, score \
         RETURN id(relationship) AS pid, score",
        vec_lit(&QUERY)
    );
    let out = first_hit(coord, txn, &src, &map);
    coord.commit(txn).expect("read commits");
    out
}

/// The single nearest `(name, score)` a k-NN offered, or `None` when it offered nothing at all —
/// a distinct observation from a named hit, and one `agrees_with` treats as a failure.
fn first_hit(
    coord: &Coord,
    txn: TxnId,
    src: &str,
    map: &HashMap<u64, String>,
) -> Option<(String, f64)> {
    let result = rows(coord, txn, &compile(src));
    let row = result.first()?;
    let pid = match row.value("pid") {
        Value::Integer(i) => i as u64,
        other => panic!("pid must be an integer, got {other:?}"),
    };
    let score = match row.value("score") {
        Value::Float(f) => f,
        other => panic!("score must be a float, got {other:?}"),
    };
    Some((
        map.get(&pid).cloned().unwrap_or_else(|| format!("<{pid}>")),
        score,
    ))
}

/// Recovers a fresh coordinator from `store`'s device + WAL image — the crash + reopen the HNSW is
/// rebuilt by.
fn recover(store: &RecordStore<MemBlockDevice, MemLogSink>) -> Coord {
    // Replay only the DURABLE WAL prefix onto a blank device — a genuine crash, not a clean close.
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    let recovered = RecordStore::open(device, wal, POOL_CAPACITY).expect("open store");
    TxnCoordinator::new(recovered)
}

/// Drives the interleaving for `ending` and returns the report.
///
/// Timeline: seeds commit `x` at the query direction and `y` at cosine 0.9, for nodes and for
/// relationships; a writer moves BOTH `x` values orthogonal to the query and stays **open**; both
/// vector indexes are created through the production route **while that writer is open**; the writer
/// then commits or rolls back; the nearest neighbour is observed; the engine is crashed, recovered, and
/// the nearest neighbour observed again against the rebuilt graphs.
#[must_use]
pub fn run_vector_build_uncommitted(ending: WriterEnding) -> VectorBuildReport {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store = RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");
    let mut coord = TxnCoordinator::new(store);

    // Seed the node corpus.
    run_write(
        &mut coord,
        "CREATE (:Doc {name: 'x', embedding: [1.0, 0.0, 0.0]})",
    );
    run_write(
        &mut coord,
        "CREATE (:Doc {name: 'y', embedding: [0.9, 0.4358899, 0.0]})",
    );
    for i in 0..DISTRACTORS {
        let t = 0.30 + (i as f32) * 0.001;
        run_write(
            &mut coord,
            &format!(
                "CREATE (:Doc {{name: 'd{i}', embedding: [{:?}, {:?}, 0.0]}})",
                t.cos(),
                t.sin()
            ),
        );
    }

    // Seed the relationship corpus.
    run_write(
        &mut coord,
        "CREATE (:P {n: 'p1'}), (:P {n: 'p2'}), (:P {n: 'p3'})",
    );
    run_write(
        &mut coord,
        "MATCH (a:P {n: 'p1'}), (b:P {n: 'p2'}) \
         CREATE (a)-[:SIMILAR {name: 'x', vec: [1.0, 0.0, 0.0]}]->(b)",
    );
    run_write(
        &mut coord,
        "MATCH (a:P {n: 'p2'}), (b:P {n: 'p3'}) \
         CREATE (a)-[:SIMILAR {name: 'y', vec: [0.9, 0.4358899, 0.0]}]->(b)",
    );

    for i in 0..DISTRACTORS {
        let t = 0.30 + (i as f32) * 0.001;
        run_write(
            &mut coord,
            &format!(
                "MATCH (a:P {{n: 'p1'}}), (b:P {{n: 'p3'}}) \
                 CREATE (a)-[:SIMILAR {{name: 'd{i}', vec: [{:?}, {:?}, 0.0]}}]->(b)",
                t.cos(),
                t.sin()
            ),
        );
    }

    // A writer moves BOTH `x` embeddings orthogonal to the query and stays OPEN. It PREDATES the
    // indexes, which is exactly why the #467 freshness marker never learns about it.
    let writer = coord.begin_serializable();
    let _ = rows(
        &coord,
        writer,
        &compile("MATCH (n:Doc {name: 'x'}) SET n.embedding = [0.0, 0.0, 1.0]"),
    );
    let _ = rows(
        &coord,
        writer,
        &compile("MATCH ()-[r:SIMILAR {name: 'x'}]->() SET r.vec = [0.0, 0.0, 1.0]"),
    );

    // THE PRODUCTION ROUTE, driven Online, while that writer is still open.
    coord
        .begin_online_vector_index_named(
            Some("doc_vec"),
            VectorEntity::Node,
            "Doc",
            "embedding",
            3,
            VectorSimilarity::Cosine,
            16,
            200,
            false,
        )
        .expect("create node vector index");
    coord
        .begin_online_vector_index_named(
            Some("rel_vec"),
            VectorEntity::Relationship,
            "SIMILAR",
            "vec",
            3,
            VectorSimilarity::Cosine,
            16,
            200,
            false,
        )
        .expect("create rel vector index");
    assert_eq!(
        coord.list_vector_index_listings().len(),
        2,
        "non-vacuity: both vector indexes must be declared",
    );

    // Seal the writer's fate, then let the command path drive any repair.
    match ending {
        WriterEnding::Commits => {
            coord.commit(writer).expect("writer commits");
        }
        WriterEnding::RollsBack => {
            coord.rollback(writer).expect("writer rolls back");
        }
    }
    while coord.advance_index_builds(usize::MAX) {}

    let node_nearest_after = nearest_node(&mut coord);
    let rel_nearest_after = nearest_rel(&mut coord);

    // Crash + recovery: the HNSW graphs are discarded and rebuilt from the recovered store.
    let store = coord.into_store();
    let mut coord2 = recover(&store);
    assert_eq!(
        coord2.list_vector_index_listings().len(),
        2,
        "non-vacuity: the recovered engine must still carry both vector indexes",
    );
    let node_nearest_recovered = nearest_node(&mut coord2);
    let rel_nearest_recovered = nearest_rel(&mut coord2);

    VectorBuildReport {
        node_nearest_after,
        rel_nearest_after,
        node_nearest_recovered,
        rel_nearest_recovered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The headline `rmp` #780 property, for a writer that ROLLS BACK: `x` is still the committed
    /// nearest neighbour and must be returned, at its own snapshot-visible score.
    ///
    /// Before the fix the build baked the uncommitted `[0,0,1]`, so `x` was offered by the graph at a
    /// direction its own snapshot cannot observe and `k = 1` returned the nearest DECOY instead —
    /// measured as `("d0", 0.977668285369873)` — and kept returning it after the rollback, for the life
    /// of the process.
    #[test]
    fn a_rolled_back_writer_leaves_the_committed_nearest_neighbour_findable_780() {
        let report = run_vector_build_uncommitted(WriterEnding::RollsBack);
        let expected = ("x".to_owned(), 1.0);
        assert!(
            report.agrees_with(&expected),
            "rmp #780: the committed nearest neighbour must be x at score 1.0: {report:?}"
        );
    }

    /// The other reader: once the in-flight writer COMMITS, its embedding IS the committed truth, so
    /// the nearest DECOY legitimately becomes the nearest neighbour. This is the counterexample that rejects "just
    /// index the newest COMMITTED version" — that would leave the writer's own value unindexed once it
    /// committed, since `commit` re-inserts no index entries.
    #[test]
    fn a_committed_writer_makes_its_own_embedding_the_committed_truth_780() {
        let report = run_vector_build_uncommitted(WriterEnding::Commits);
        let expected = ("d0".to_owned(), DISTRACTOR_TOP_SCORE);
        assert!(
            report.agrees_with(&expected),
            "rmp #780: after the writer committed, y is genuinely nearest: {report:?}"
        );
    }

    /// The HNSW is ephemeral and rebuilt from the recovered store by the same helpers this fix
    /// changed, so the property must survive a crash for BOTH endings.
    ///
    /// NOT a regression test, and it says so rather than being claimed as one: this **passes before the
    /// fix too**, and that is the finding, not a weakness. The pre-fix report reads
    /// `node_nearest_after: ("y", 0.95) … node_nearest_recovered: ("x", 1.0)` — the defect was
    /// LIVE-PROCESS ONLY, so recovery was the only thing that healed it. That is exactly why any test
    /// which reopened the store would have seen nothing wrong, and why the defect survived this long.
    /// It is kept to pin that recovery stays correct now that the build skips conflicted entities.
    #[test]
    fn the_rebuilt_graphs_after_recovery_still_answer_correctly_780() {
        for (ending, expected) in [
            (WriterEnding::RollsBack, ("x".to_owned(), 1.0)),
            (
                WriterEnding::Commits,
                ("d0".to_owned(), DISTRACTOR_TOP_SCORE),
            ),
        ] {
            let report = run_vector_build_uncommitted(ending);
            let same = |got: &Option<(String, f64)>| {
                got.as_ref()
                    .is_some_and(|g| g.0 == expected.0 && (g.1 - expected.1).abs() < 1e-6)
            };
            assert!(
                same(&report.node_nearest_recovered),
                "{ending:?}: rebuilt node graph answers wrongly: {report:?}"
            );
            assert!(
                same(&report.rel_nearest_recovered),
                "{ending:?}: rebuilt rel graph answers wrongly: {report:?}"
            );
        }
    }

    #[test]
    fn reproduction_is_deterministic() {
        assert_eq!(
            run_vector_build_uncommitted(WriterEnding::RollsBack),
            run_vector_build_uncommitted(WriterEnding::RollsBack)
        );
        assert_eq!(
            run_vector_build_uncommitted(WriterEnding::Commits),
            run_vector_build_uncommitted(WriterEnding::Commits)
        );
    }
}
