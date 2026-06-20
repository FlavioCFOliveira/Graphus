//! `vopr_oracle` — the **strong reference-model oracle** for the VOPR loop (rmp #238).
//!
//! The pre-#238 VOPR oracle was weak: it compared a *count* of committed creates against the count
//! of persisted `:Person` rows, plus a state hash of two read-back queries. A count check passes
//! even when the engine returns the *wrong rows with the right cardinality* — a wrong neighbour set,
//! a swapped endpoint, a duplicated-then-lost pair that nets to the same count. This module replaces
//! that with a **deterministic in-memory shadow model** of the multigraph that applies exactly the
//! committed workload operations, then asserts **full cell-by-cell equivalence** between the model
//! and the engine queried back: the multiset of `:Person` ids, the full multiset of `:KNOWS`
//! relationships by stable `(src_id, dst_id)` property key, and the `CountNodes` / `Neighbors`
//! read results.
//!
//! # Why stable property keys, not server ids
//!
//! The model cannot predict the engine's internal node record numbers (they depend on allocation,
//! free-list reuse and GC). It therefore keys everything on the workload's **`id` property** — the
//! stable handle both sides agree on. Comparing on `id` absorbs the server's physical ids.
//!
//! # Exact engine semantics this model mirrors (probed against the real engine)
//!
//! The workload uses `CREATE`, not `MERGE`, on a **multigraph**, so the model must mirror these
//! measured facts (see the module tests, which assert them against the real engine):
//!
//! * **Duplicate id ⇒ a second node.** `CREATE (:Person {id: 0})` twice yields *two* `id = 0`
//!   nodes. The model tracks a **multiplicity per id**, not a set.
//! * **`CreateEdge{a, b}` is a Cartesian product over the matches.** Its Cypher
//!   `MATCH (a:Person {id:$a}), (b:Person {id:$b}) CREATE (a)-[:KNOWS]->(b)` matches *every* node
//!   with `id = a` against *every* node with `id = b`, so it creates `mult(a) * mult(b)` parallel
//!   `:KNOWS` edges. If either id is absent, it creates **zero** edges (the `MATCH` finds nothing).
//!   A self-loop on a single `id` node creates one edge.
//! * **Parallel edges are allowed.** Repeating the same `CreateEdge` adds more parallel edges; the
//!   model holds an edge **multiset** keyed by `(src_id, dst_id)`.
//!
//! # Commit-only application
//!
//! Only **committed** operations mutate the real graph, so the oracle buffers each transaction's ops
//! and flushes them into the model **only when that transaction's `COMMIT` is acknowledged**. A
//! rolled-back, SSI-aborted, or crash-lost transaction's buffered ops are **discarded**, never
//! applied — exactly mirroring the engine's durability contract.
//!
//! # Determinism
//!
//! The oracle is an *observer*. Its read-back queries run in their own auto-commit read transactions
//! and are **not** folded into the canonical workload trace, so wiring the oracle in does not perturb
//! `trace_hash`: same seed ⇒ identical trace. A divergence is surfaced as a precise [`OracleError`]
//! naming the offending id or edge.

use std::collections::BTreeMap;

use graphus_core::Value;
use graphus_cypher::result::MaterializedValue;
use graphus_io::MemBlockDevice;
use graphus_server::engine::LocalEngine;
use graphus_server::engine::command::AccessMode;
use graphus_wal::MemLogSink;

use crate::mix::WorkloadOp;

/// The simulated engine type (must match [`crate::vopr`]'s alias).
type SimEngine = LocalEngine<MemBlockDevice, MemLogSink>;

/// An ascending node-id multiset: `(id, multiplicity)` pairs.
type NodeMultiset = Vec<(i64, u64)>;

/// An ascending edge multiset: `((src_id, dst_id), parallel_count)` pairs.
type EdgeMultiset = Vec<((i64, i64), u64)>;

/// A deterministic in-memory shadow of the `:Person` / `:KNOWS` multigraph, built purely from
/// **committed** workload operations and keyed on the stable `id` property.
///
/// It is an independent re-derivation of the expected committed state — never a copy of engine
/// state — so a bug that fools the engine cannot fool the model.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ShadowGraph {
    /// `id` property -> how many `:Person` nodes carry that id (multiplicity; `CREATE` is not
    /// `MERGE`, so duplicates accumulate).
    nodes: BTreeMap<i64, u64>,
    /// `(src_id, dst_id)` -> number of parallel `:KNOWS` edges between persons with those ids.
    edges: BTreeMap<(i64, i64), u64>,
}

impl ShadowGraph {
    /// An empty shadow graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Applies one committed [`WorkloadOp`] to the model **directly** against the current committed
    /// node multiset.
    ///
    /// This is correct only for a transaction whose snapshot is the *current* committed state — i.e.
    /// an auto-commit (one-statement) transaction that opens, runs and commits with nothing committing
    /// concurrently between its begin and its statement. Multi-statement transactions under MVCC
    /// snapshot isolation must instead use [`commit_transaction`](Self::commit_transaction), which
    /// evaluates each edge's `MATCH` against the snapshot the transaction *began* with (plus its own
    /// earlier creates), not the final state — see that method for why a direct apply would
    /// over-count edges to nodes a concurrent transaction committed after this one began.
    pub fn apply(&mut self, op: WorkloadOp) {
        match op {
            WorkloadOp::CreateNode { id } => {
                *self.nodes.entry(id).or_insert(0) += 1;
            }
            WorkloadOp::CreateEdge { a, b } => {
                let added = edge_cardinality(&self.nodes, a, b);
                if added > 0 {
                    *self.edges.entry((a, b)).or_insert(0) += added;
                }
            }
            WorkloadOp::CountNodes | WorkloadOp::Neighbors { .. } => {}
        }
    }

    /// Commits a whole transaction's buffered ops under **MVCC snapshot-isolation** semantics, the way
    /// the engine actually evaluates them.
    ///
    /// `snapshot` is the committed node multiset captured when this transaction **began** — the only
    /// nodes its `MATCH` clauses can see (a node a *concurrent* transaction committed after this one
    /// began is invisible to it, exactly as the engine's snapshot isolation hides it). The
    /// transaction's own `CreateNode`s are visible to its later statements, so they are layered on top
    /// of `snapshot` as the ops replay in order. Edges are evaluated against that visible multiset;
    /// then the net node creates and the produced edges are merged into the committed model.
    ///
    /// This is the heart of a faithful reference model: applying an edge against the *final* committed
    /// state (rather than the transaction's snapshot) over-counts edges whenever the workload
    /// interleaves an edge transaction with the commit of the node it targets — a divergence the
    /// real engine (correctly) does not produce.
    pub fn commit_transaction(&mut self, snapshot: &BTreeMap<i64, u64>, ops: &[WorkloadOp]) {
        // The multiset visible to this transaction: its begin-snapshot plus its own creates so far.
        let mut visible = snapshot.clone();
        for &op in ops {
            match op {
                WorkloadOp::CreateNode { id } => {
                    // Persist into the committed model and make it visible to this txn's later stmts.
                    *self.nodes.entry(id).or_insert(0) += 1;
                    *visible.entry(id).or_insert(0) += 1;
                }
                WorkloadOp::CreateEdge { a, b } => {
                    let added = edge_cardinality(&visible, a, b);
                    if added > 0 {
                        *self.edges.entry((a, b)).or_insert(0) += added;
                    }
                }
                WorkloadOp::CountNodes | WorkloadOp::Neighbors { .. } => {}
            }
        }
    }

    /// A clone of the committed node multiset — the snapshot a transaction sees when it begins.
    #[must_use]
    pub fn node_snapshot(&self) -> BTreeMap<i64, u64> {
        self.nodes.clone()
    }

    /// Total `:Person` nodes (sum of multiplicities) — the model's `CountNodes` answer.
    #[must_use]
    pub fn count_nodes(&self) -> u64 {
        self.nodes.values().copied().sum()
    }

    /// The number of outgoing `:KNOWS` rows a `Neighbors{a}` traversal must return: one row per
    /// outgoing edge from *any* node with `id = a` (the engine returns a row per matched edge, so
    /// parallel edges and the source multiplicity both multiply the row count).
    #[must_use]
    pub fn neighbor_rows(&self, a: i64) -> u64 {
        self.edges
            .iter()
            .filter(|((src, _), _)| *src == a)
            .map(|(_, &c)| c)
            .sum()
    }

    /// The full node-id multiset as an ascending `(id, multiplicity)` vector — the canonical form to
    /// compare against the engine's `MATCH (n:Person) RETURN n.id` read-back.
    #[must_use]
    pub fn node_multiset(&self) -> NodeMultiset {
        self.nodes
            .iter()
            .filter(|(_, m)| **m > 0)
            .map(|(&id, &m)| (id, m))
            .collect()
    }

    /// The full edge multiset as an ascending `((src, dst), count)` vector — the canonical form to
    /// compare against the engine's `MATCH (a)-[:KNOWS]->(b) RETURN a.id, b.id` read-back.
    #[must_use]
    pub fn edge_multiset(&self) -> EdgeMultiset {
        self.edges
            .iter()
            .filter(|(_, c)| **c > 0)
            .map(|(&k, &c)| (k, c))
            .collect()
    }
}

/// The number of `:KNOWS` edges a `CreateEdge{a, b}` produces against a given visible node multiset:
/// the Cartesian product `mult(a) * mult(b)`. An absent endpoint contributes multiplicity 0, so the
/// product is 0 (no `MATCH` binding ⇒ no edge); a self-loop on a single node yields 1.
fn edge_cardinality(visible: &BTreeMap<i64, u64>, a: i64, b: i64) -> u64 {
    let ma = visible.get(&a).copied().unwrap_or(0);
    let mb = visible.get(&b).copied().unwrap_or(0);
    ma.saturating_mul(mb)
}

/// A precise description of a model⇄engine divergence the oracle caught.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleError {
    /// The `:Person` id multiset disagreed. Carries the first diverging id and the two
    /// multiplicities (model vs engine).
    NodeMultisetMismatch {
        /// The id whose multiplicity differs (or that is present on only one side).
        id: i64,
        /// The model's multiplicity for `id`.
        model: u64,
        /// The engine's multiplicity for `id`.
        engine: u64,
    },
    /// The `:KNOWS` edge multiset disagreed. Carries the first diverging `(src, dst)` and the two
    /// parallel-edge counts (model vs engine).
    EdgeMultisetMismatch {
        /// The `(src_id, dst_id)` whose parallel-edge count differs.
        edge: (i64, i64),
        /// The model's edge count for `edge`.
        model: u64,
        /// The engine's edge count for `edge`.
        engine: u64,
    },
    /// A `CountNodes` read disagreed with the model.
    CountMismatch {
        /// The model's node count.
        model: u64,
        /// The engine's `count(n)` result.
        engine: u64,
    },
    /// A `Neighbors{a}` read returned a different number of rows than the model expects.
    NeighborMismatch {
        /// The person whose neighbourhood was queried.
        a: i64,
        /// The model's expected row count.
        model: u64,
        /// The engine's row count.
        engine: u64,
    },
    /// A read-back query failed against the engine (could not begin / run / drain). Carries a coarse
    /// class so the failure is reproducible without leaking incidental wording.
    ReadBack {
        /// What was being read when it failed.
        what: &'static str,
    },
}

/// Reads the engine's `:Person` id multiset via Cypher: `(id, multiplicity)` ascending.
fn engine_node_multiset(eng: &mut SimEngine) -> Result<NodeMultiset, OracleError> {
    let ids = read_int_column(
        eng,
        "MATCH (n:Person) RETURN n.id AS id ORDER BY n.id",
        "nodes",
    )?;
    Ok(fold_multiset_single(&ids))
}

/// Reads the engine's `:KNOWS` edge multiset via Cypher: `((src, dst), count)` ascending.
fn engine_edge_multiset(eng: &mut SimEngine) -> Result<EdgeMultiset, OracleError> {
    let pairs = read_int_pairs(
        eng,
        "MATCH (a:Person)-[:KNOWS]->(b:Person) RETURN a.id AS a, b.id AS b ORDER BY a.id, b.id",
        "edges",
    )?;
    let mut acc: BTreeMap<(i64, i64), u64> = BTreeMap::new();
    for p in pairs {
        *acc.entry(p).or_insert(0) += 1;
    }
    Ok(acc.into_iter().collect())
}

/// Reads `count(n)` for `:Person` from the engine.
fn engine_count(eng: &mut SimEngine) -> Result<u64, OracleError> {
    let v = read_int_column(eng, "MATCH (n:Person) RETURN count(n) AS c", "count")?;
    // A `count(n)` aggregate yields exactly one row; default to 0 defensively.
    Ok(v.first().copied().map(|c| c.max(0) as u64).unwrap_or(0))
}

/// Reads the number of `Neighbors{a}` rows the engine returns.
fn engine_neighbor_rows(eng: &mut SimEngine, a: i64) -> Result<u64, OracleError> {
    let rows = read_int_column_param(
        eng,
        "MATCH (:Person {id: $a})-[:KNOWS]->(b) RETURN b.id AS id ORDER BY b.id",
        vec![("a".to_owned(), Value::Integer(a))],
        "neighbors",
    )?;
    Ok(rows.len() as u64)
}

/// Folds a sorted integer column into an ascending `(value, count)` multiset.
fn fold_multiset_single(values: &[i64]) -> NodeMultiset {
    let mut acc: BTreeMap<i64, u64> = BTreeMap::new();
    for &v in values {
        *acc.entry(v).or_insert(0) += 1;
    }
    acc.into_iter().collect()
}

/// Runs a parameterless read returning a single integer column.
fn read_int_column(
    eng: &mut SimEngine,
    stmt: &str,
    what: &'static str,
) -> Result<Vec<i64>, OracleError> {
    read_int_column_param(eng, stmt, vec![], what)
}

/// Runs a read returning a single integer column, with parameters. The read runs in its own
/// auto-commit read transaction and is **not** folded into the canonical trace (it is an observer).
fn read_int_column_param(
    eng: &mut SimEngine,
    stmt: &str,
    params: Vec<(String, Value)>,
    what: &'static str,
) -> Result<Vec<i64>, OracleError> {
    let rows = run_read(eng, stmt, params, what)?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(first_int(&row, what)?);
    }
    Ok(out)
}

/// Runs a read returning two integer columns `(a, b)` per row.
fn read_int_pairs(
    eng: &mut SimEngine,
    stmt: &str,
    what: &'static str,
) -> Result<Vec<(i64, i64)>, OracleError> {
    let rows = run_read(eng, stmt, vec![], what)?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        if row.len() < 2 {
            return Err(OracleError::ReadBack { what });
        }
        out.push((cell_int(&row[0], what)?, cell_int(&row[1], what)?));
    }
    Ok(out)
}

/// Begins an auto-commit read, runs `stmt`, and drains its materialized rows. Read-only and isolated
/// so it never perturbs the workload.
fn run_read(
    eng: &mut SimEngine,
    stmt: &str,
    params: Vec<(String, Value)>,
    what: &'static str,
) -> Result<Vec<Vec<MaterializedValue>>, OracleError> {
    let ticket = eng
        .begin_auto_commit(AccessMode::Read)
        .map_err(|_| OracleError::ReadBack { what })?;
    let mut reply = eng
        .run(ticket, stmt, params, true, None)
        .map_err(|_| OracleError::ReadBack { what })?;
    let mut rows = Vec::new();
    loop {
        match reply.rows.next() {
            Ok(Some(row)) => rows.push(row),
            Ok(None) => break,
            Err(_) => return Err(OracleError::ReadBack { what }),
        }
    }
    Ok(rows)
}

/// Extracts the first cell of a row as an `i64`.
fn first_int(row: &[MaterializedValue], what: &'static str) -> Result<i64, OracleError> {
    let cell = row.first().ok_or(OracleError::ReadBack { what })?;
    cell_int(cell, what)
}

/// Extracts an `i64` from a materialized cell (the workload only ever returns integer ids / counts).
fn cell_int(cell: &MaterializedValue, what: &'static str) -> Result<i64, OracleError> {
    match cell {
        MaterializedValue::Value(Value::Integer(i)) => Ok(*i),
        _ => Err(OracleError::ReadBack { what }),
    }
}

/// Asserts **full cell-by-cell equivalence** between `model` and the engine queried back: the node-id
/// multiset, the edge multiset, the `count(n)` aggregate, and the per-person neighbour row counts for
/// every id the model knows. Returns the first divergence found (deterministic ordering), or `Ok(())`.
///
/// # Errors
///
/// Returns an [`OracleError`] naming the exact diverging id / edge, or a read-back failure class.
pub fn assert_equivalent(eng: &mut SimEngine, model: &ShadowGraph) -> Result<(), OracleError> {
    // 1. Node-id multiset.
    let want_nodes = model.node_multiset();
    let got_nodes = engine_node_multiset(eng)?;
    diff_multiset_i64(&want_nodes, &got_nodes).map_or(Ok(()), |(id, model_m, engine_m)| {
        Err(OracleError::NodeMultisetMismatch {
            id,
            model: model_m,
            engine: engine_m,
        })
    })?;

    // 2. Edge multiset.
    let want_edges = model.edge_multiset();
    let got_edges = engine_edge_multiset(eng)?;
    diff_multiset_pair(&want_edges, &got_edges).map_or(Ok(()), |(edge, model_c, engine_c)| {
        Err(OracleError::EdgeMultisetMismatch {
            edge,
            model: model_c,
            engine: engine_c,
        })
    })?;

    // 3. `CountNodes` aggregate.
    let engine_c = engine_count(eng)?;
    if engine_c != model.count_nodes() {
        return Err(OracleError::CountMismatch {
            model: model.count_nodes(),
            engine: engine_c,
        });
    }

    // 4. `Neighbors{a}` row count, for every id the model knows (deterministic, ascending).
    for &(id, _) in &want_nodes {
        let want = model.neighbor_rows(id);
        let got = engine_neighbor_rows(eng, id)?;
        if want != got {
            return Err(OracleError::NeighborMismatch {
                a: id,
                model: want,
                engine: got,
            });
        }
    }

    Ok(())
}

/// Finds the first `(key, model_count, engine_count)` where two ascending `(i64, count)` multisets
/// disagree, or `None` if equal. Treats an absent key as count 0 on that side.
fn diff_multiset_i64(model: &[(i64, u64)], engine: &[(i64, u64)]) -> Option<(i64, u64, u64)> {
    diff_sorted(model, engine)
}

/// Finds the first `((src, dst), model_count, engine_count)` where two ascending edge multisets
/// disagree, or `None` if equal.
fn diff_multiset_pair(
    model: &[((i64, i64), u64)],
    engine: &[((i64, i64), u64)],
) -> Option<((i64, i64), u64, u64)> {
    diff_sorted(model, engine)
}

/// Merge-walks two ascending `(key, count)` slices and returns the first key whose counts differ.
/// Generic over the (ordered) key so it serves both the node and edge multisets.
fn diff_sorted<K: Ord + Copy>(model: &[(K, u64)], engine: &[(K, u64)]) -> Option<(K, u64, u64)> {
    let mut i = 0;
    let mut j = 0;
    while i < model.len() || j < engine.len() {
        match (model.get(i), engine.get(j)) {
            (Some(&(mk, mc)), Some(&(ek, ec))) => {
                if mk == ek {
                    if mc != ec {
                        return Some((mk, mc, ec));
                    }
                    i += 1;
                    j += 1;
                } else if mk < ek {
                    // `mk` present in model, absent (count 0) in engine.
                    return Some((mk, mc, 0));
                } else {
                    // `ek` present in engine, absent in model.
                    return Some((ek, 0, ec));
                }
            }
            (Some(&(mk, mc)), None) => return Some((mk, mc, 0)),
            (None, Some(&(ek, ec))) => return Some((ek, 0, ec)),
            (None, None) => break,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_core::capability::Clock;
    use graphus_sim::SharedClock;
    use std::sync::Arc;

    fn engine() -> SimEngine {
        let clock = SharedClock::new(0);
        LocalEngine::in_memory(Arc::new(clock) as Arc<dyn Clock + Send + Sync>, 256)
            .expect("build in-memory engine")
    }

    /// Applies a committed op to BOTH the model and the engine (auto-commit), so the two stay in
    /// lockstep — the same path the oracle wiring uses, exercised directly here.
    fn apply_both(eng: &mut SimEngine, model: &mut ShadowGraph, op: WorkloadOp) {
        let (stmt, params) = op.to_cypher();
        let mode = if op.is_write() {
            AccessMode::Write
        } else {
            AccessMode::Read
        };
        let ticket = eng.begin_auto_commit(mode).expect("begin");
        let mut reply = eng.run(ticket, stmt, params, true, None).expect("run");
        while reply.rows.next().expect("drain").is_some() {}
        model.apply(op);
    }

    /// The model mirrors the engine's exact multigraph semantics: duplicate ids accumulate, an edge
    /// is a Cartesian product over matches, absent endpoints add nothing, self-loops add one.
    #[test]
    fn model_mirrors_engine_for_all_op_shapes() {
        let mut eng = engine();
        let mut model = ShadowGraph::new();

        apply_both(&mut eng, &mut model, WorkloadOp::CreateNode { id: 0 });
        apply_both(&mut eng, &mut model, WorkloadOp::CreateNode { id: 0 }); // duplicate id
        apply_both(&mut eng, &mut model, WorkloadOp::CreateNode { id: 1 });
        // Cartesian: two id=0 sources × one id=1 target = 2 edges.
        apply_both(&mut eng, &mut model, WorkloadOp::CreateEdge { a: 0, b: 1 });
        // Repeat ⇒ 2 more parallel edges.
        apply_both(&mut eng, &mut model, WorkloadOp::CreateEdge { a: 0, b: 1 });
        // Missing endpoint ⇒ no edge.
        apply_both(&mut eng, &mut model, WorkloadOp::CreateEdge { a: 0, b: 9 });
        // Self-loop on the single id=1 node ⇒ one edge.
        apply_both(&mut eng, &mut model, WorkloadOp::CreateEdge { a: 1, b: 1 });

        assert_eq!(
            assert_equivalent(&mut eng, &model),
            Ok(()),
            "the shadow model must agree with the engine cell-by-cell"
        );
        // And the model's own accounting matches the measured semantics.
        assert_eq!(model.count_nodes(), 3, "two id=0 + one id=1");
        assert_eq!(
            model.neighbor_rows(0),
            4,
            "4 outgoing edges from id=0 nodes"
        );
        assert_eq!(model.neighbor_rows(1), 1, "the self-loop");
        let _ = eng.shutdown();
    }

    /// Teeth (unit level): a model with an injected extra edge diverges and the oracle catches it,
    /// naming the offending edge.
    #[test]
    fn oracle_catches_an_injected_extra_edge() {
        let mut eng = engine();
        let mut model = ShadowGraph::new();
        apply_both(&mut eng, &mut model, WorkloadOp::CreateNode { id: 0 });
        apply_both(&mut eng, &mut model, WorkloadOp::CreateNode { id: 1 });
        apply_both(&mut eng, &mut model, WorkloadOp::CreateEdge { a: 0, b: 1 });

        // Perturb ONLY the model: claim a parallel edge the engine never made.
        model.apply(WorkloadOp::CreateEdge { a: 0, b: 1 });
        let err = assert_equivalent(&mut eng, &model).expect_err("must diverge");
        assert_eq!(
            err,
            OracleError::EdgeMultisetMismatch {
                edge: (0, 1),
                model: 2,
                engine: 1,
            }
        );
        let _ = eng.shutdown();
    }

    /// Teeth: an injected phantom node id is caught with the exact id and multiplicities.
    #[test]
    fn oracle_catches_a_phantom_node() {
        let mut eng = engine();
        let mut model = ShadowGraph::new();
        apply_both(&mut eng, &mut model, WorkloadOp::CreateNode { id: 0 });
        model.apply(WorkloadOp::CreateNode { id: 7 }); // phantom: model only
        let err = assert_equivalent(&mut eng, &model).expect_err("must diverge");
        assert_eq!(
            err,
            OracleError::NodeMultisetMismatch {
                id: 7,
                model: 1,
                engine: 0,
            }
        );
        let _ = eng.shutdown();
    }

    /// The multiset differ finds the first divergence deterministically, treating absent keys as 0.
    #[test]
    fn diff_sorted_finds_first_divergence() {
        assert_eq!(diff_sorted(&[(1, 1), (2, 2)], &[(1, 1), (2, 2)]), None);
        assert_eq!(diff_sorted(&[(1, 2)], &[(1, 1)]), Some((1, 2, 1)));
        assert_eq!(diff_sorted(&[(1, 1), (3, 1)], &[(1, 1)]), Some((3, 1, 0)));
        assert_eq!(diff_sorted::<i64>(&[], &[(5, 4)]), Some((5, 0, 4)));
    }
}
