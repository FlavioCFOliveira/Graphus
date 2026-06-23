//! Equivalence guard for the **morsel-driven** parallel traversal (`ExpandAll`-over-anchor) read path
//! (`rmp` task #339, Slice 3c — the final slice, parallelizing the per-anchor expand of degree /
//! friends / FoF / mutual shapes).
//!
//! Slice 3c parallelizes the **per-anchor single-hop `ExpandAll`** of a bare
//! `MATCH (a:Label)-[r(:T…)?]->(b) ...`: the seam ([`RecordStoreGraph::morsel_label_scan`]) hands the
//! executor the **anchor** candidate-id vector + an erased, `Send`, cheap-cloneable read surface; the
//! executor splits the anchors into contiguous morsels expanded concurrently on a dedicated pool, each
//! running the per-anchor `expand` (+ a local count or per-row projection) on a `Send`
//! [`ReadOnlyGraph`], then converges:
//!
//! * **degree / count-over-expand** (`RETURN count(b) | count(*)`) — the per-anchor matching degrees are
//!   **summed** (order-independent), reproducing serial `count`;
//! * **neighbour-collect** (`RETURN <pure projection of a/r/b>`) — the projected expansion rows are
//!   **concatenated in ascending anchor source-index order**, reproducing the serial scan→expand→project
//!   row sequence exactly.
//!
//! The crux is the same inviolable obligation as Slices 3a/3b — the parallel path must be **provably
//! identical to serial** — extended here to the traversal. This guard asserts it three ways:
//!
//! 1. **End-to-end through the real executor + coordinator** (the strongest, TCK-aligned check): the same
//!    query run with the morsel knob on (`set_morsel_threads(8)`) returns the **exact same result** (count
//!    value, or row sequence with order) as with the knob off (`set_morsel_threads(1)`, serial) — across
//!    directed / undirected / typed expands, degree and neighbour-collect, over fresh / overwritten /
//!    deleted (rel + node) data and a graph containing **self-loops** (the dedup hazard). Concat shapes
//!    are also asserted deterministic regardless of worker count.
//! 2. **Direct morsel-vs-serial at the bundle level** (small graphs, explicit anchor-morsel counts
//!    1 / 2 / 8): the morsels' converged result equals the serial reference, AND the SIREAD-marker UNION
//!    (per-edge keys + rel-pattern predicates) is byte-identical to the serial scan→expand's marker set
//!    (the load-bearing ACID assertion — moving the traversal onto morsels must not change which rw-edges
//!    form).
//! 3. Focused guards that a restricted RBAC principal and `MemGraph` **decline** the morsel scan (so a
//!    restricted reader never bypasses per-relationship/endpoint RBAC through an off-thread expand), and
//!    that knob=1 is serial-identical.

use std::cell::RefCell;
use std::rc::Rc;

use graphus_core::{TxnId, Value};
use graphus_cypher::authorized_graph::{AuthorizedGraph, PrivilegeOracle};
use graphus_cypher::binding::{BoundParameters, Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::GraphAccess;
use graphus_cypher::index_set::IndexSet;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::morsel::{
    ExpandConverged, MorselExpandPlan, MorselExpandPostWork, MorselLabelScan,
    converge_expand_outcomes,
};
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalOp, PhysicalPlan, plan_physical};
use graphus_cypher::record_graph::RecordStoreGraph;
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_txn::{LockTable, Snapshot, SsiReadBuffer, SsiTracker};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Live = RecordStoreGraph<MemBlockDevice, MemLogSink>;

// =================================================================================================
// End-to-end through the real executor + coordinator: knob=8 must be IDENTICAL to knob=1.
// =================================================================================================

/// Bulk-seeds a committed social-network-shaped graph directly on the store (fast, no per-node query):
/// `n` `:Person {age, name}` anchors, each with `fanout` outgoing `KNOWS` edges to pseudo-random other
/// people, plus a sprinkling of `FOLLOWS` edges and (for `i % 37 == 0`) a **self-loop** (the dedup
/// hazard). Then wraps it in a `TxnCoordinator` whose durable statistics report
/// `nodes_with_label("Person") == n` (so the morsel tier's cardinality gate engages above
/// `MORSEL_MIN_ROWS`). A deliberately small pool (64 frames) so the concurrent morsel expand exercises
/// the eviction path (the `rmp` #337 lost-pin race regression surface).
fn coord_with_social(n: i64, fanout: i64) -> TxnCoordinator<MemBlockDevice, MemLogSink> {
    let store = seed_social(n, fanout, 64);
    TxnCoordinator::new(store)
}

/// Seeds the social graph onto a fresh store with `pool_frames` buffer frames and returns it committed.
fn seed_social(n: i64, fanout: i64, pool_frames: usize) -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut s = RecordStore::create(device, wal, pool_frames, 1).expect("create store");
    let txn = TxnId(1);
    s.begin(txn);
    let l_person = s.intern_token(Namespace::Label, "Person").unwrap();
    let k_age = s.intern_token(Namespace::PropKey, "age").unwrap();
    let k_name = s.intern_token(Namespace::PropKey, "name").unwrap();
    let t_knows = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let t_follows = s.intern_token(Namespace::RelType, "FOLLOWS").unwrap();
    let k_since = s.intern_token(Namespace::PropKey, "since").unwrap();

    // Create the nodes first (ids are 1..=n in creation order).
    let mut ids = Vec::with_capacity(n as usize);
    for i in 0..n {
        let (id, _) = s.create_node(txn).unwrap();
        s.add_label(txn, id, l_person).unwrap();
        s.set_node_property_value(txn, id, k_age, &Value::Integer(i % 100))
            .unwrap();
        s.set_node_property_value(txn, id, k_name, &Value::String(format!("p{i:05}")))
            .unwrap();
        ids.push(id);
    }
    // Then the edges (a deterministic pseudo-random fan-out, so the degree distribution is non-trivial).
    if n > 0 {
        for i in 0..n {
            let src = ids[i as usize];
            for k in 0..fanout {
                // A deterministic LCG-ish target distinct from a pure linear pattern.
                let tgt_idx = ((i
                    .wrapping_mul(2654435761)
                    .wrapping_add(k.wrapping_mul(40503)))
                .rem_euclid(n)) as usize;
                let tgt = ids[tgt_idx];
                let (rid, _) = s.create_rel(txn, t_knows, src, tgt).unwrap();
                s.set_rel_property_value(txn, rid, k_since, &Value::Integer((i + k) % 50))
                    .unwrap();
            }
            // A FOLLOWS edge to the next person (cyclic), a second rel-type the typed-expand exercises.
            let nxt = ids[((i + 1).rem_euclid(n)) as usize];
            s.create_rel(txn, t_follows, src, nxt).unwrap();
            // A self-loop on a subset (the self-loop dedup hazard): KNOWS from a node to itself.
            if i % 37 == 0 {
                s.create_rel(txn, t_knows, src, src).unwrap();
            }
        }
    }
    s.commit(txn).unwrap();
    s
}

/// Runs `src` over the coordinator in a fresh committed read transaction, returning the FULL ordered row
/// sequence (each row rendered to a stable `Vec<(column, Debug-of-value)>` for order-sensitive compare).
fn run_rows(
    coord: &mut TxnCoordinator<MemBlockDevice, MemLogSink>,
    src: &str,
) -> Vec<Vec<(String, String)>> {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let plan = plan_physical(
        &lower(&analyze(&ast).expect("analyze")),
        &IndexCatalog::empty(),
    );
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");

    let txn = coord.begin_serializable();
    let rendered = {
        let mut graph = coord.statement(txn).expect("statement");
        let rows = {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect")
        };
        assert!(
            !graph.has_error(),
            "statement captured an error: {:?}",
            graph.take_error()
        );
        rows.iter().map(render_row).collect()
    };
    coord.commit(txn).expect("read commits");
    rendered
}

/// A row as an order-preserving `Vec<(column_name, Debug-of-value)>`.
fn render_row(row: &Row) -> Vec<(String, String)> {
    row.columns()
        .iter()
        .zip(row.values())
        .map(|(c, v)| (c.clone(), format!("{v:?}")))
        .collect()
}

/// Asserts that `q`, run through the real executor + coordinator, returns the **exact same result** with
/// the morsel knob on (8 workers) as off (1 worker, serial) — the inviolable Slice-3c obligation, across
/// worker counts (8 and 2) to prove the contiguous concat / degree sum is worker-count-independent.
fn assert_knob_identical(
    coord: &mut TxnCoordinator<MemBlockDevice, MemLogSink>,
    q: &str,
) -> Vec<Vec<(String, String)>> {
    graphus_cypher::morsel::set_morsel_threads(1);
    let serial = run_rows(coord, q);

    graphus_cypher::morsel::set_morsel_threads(8);
    let morsel8 = run_rows(coord, q);

    graphus_cypher::morsel::set_morsel_threads(2);
    let morsel2 = run_rows(coord, q);

    graphus_cypher::morsel::set_morsel_threads(1);

    assert_eq!(
        serial, morsel8,
        "`{q}`: morsel(8) result (order included) must equal serial"
    );
    assert_eq!(
        serial, morsel2,
        "`{q}`: morsel(2) result must equal serial (worker-count-independent)"
    );
    serial
}

/// The traversal query matrix exercised end-to-end: degree (directed / undirected / typed) and
/// neighbour-collect (directed / typed / projected-property / CASE), all single-hop fresh expands.
fn expand_query_matrix() -> Vec<&'static str> {
    vec![
        // --- degree / count-over-expand (order-independent combine) ---
        "MATCH (a:Person)-->(b) RETURN count(b)",
        "MATCH (a:Person)-->(b) RETURN count(*)",
        "MATCH (a:Person)-[:KNOWS]->(b) RETURN count(b)",
        "MATCH (a:Person)-[:FOLLOWS]->(b) RETURN count(b)",
        "MATCH (a:Person)--(b) RETURN count(b)", // undirected (self-loop dedup hazard)
        "MATCH (a:Person)-[:KNOWS]-(b) RETURN count(*)", // undirected + typed
        "MATCH (a:Person)<--(b) RETURN count(b)", // incoming
        // --- neighbour-collect (contiguous concat in anchor order) ---
        "MATCH (a:Person)-->(b) RETURN a.name AS a, b.name AS b",
        "MATCH (a:Person)-[r:KNOWS]->(b) RETURN a.name AS a, b.name AS b, r.since AS since",
        "MATCH (a:Person)-[:KNOWS]->(b) RETURN b.age AS age",
        "MATCH (a:Person)-->(b) RETURN a.age + b.age AS s",
        "MATCH (a:Person)-->(b) RETURN CASE WHEN b.age > 50 THEN 'old' ELSE 'young' END AS k",
        "MATCH (a:Person)--(b) RETURN a.name AS a, b.name AS b", // undirected rows (self-loop hazard)
    ]
}

/// FRESH data: the full traversal query matrix is identical between morsel and serial, over a large
/// (> MORSEL_MIN_ROWS) `:Person` graph so the tier actually engages.
#[test]
fn morsel_expand_end_to_end_match_serial() {
    let mut coord = coord_with_social(60_000, 4);
    for q in expand_query_matrix() {
        let serial = assert_knob_identical(&mut coord, q);
        assert!(!serial.is_empty(), "`{q}` should not be vacuously empty");
    }
}

/// OVERWRITE + DELETE (rel + isolated node): the matrix stays identical after in-place property
/// overwrites, after deleting a band of RELATIONSHIPS (edge-tombstone MVCC visibility), and after
/// DETACH-deleting a band of anchors via the real executor (anchor-tombstone visibility). A second
/// coordinator after the mutation commit. The DETACH DELETE is driven through the executor so the
/// detach semantics (drop incident rels, then the node) are handled correctly — no dangling rel points
/// at a tombstone, which keeps the post-delete neighbour-collect projection well-defined on both paths.
#[test]
fn morsel_expand_end_to_end_after_mutations() {
    let mut store = seed_social(60_000, 4, 64);

    // (1) In-place property overwrites directly on the store (changes b.age / the CASE bucket).
    let txn2 = TxnId(2);
    store.begin(txn2);
    let k_age = store.token_id(Namespace::PropKey, "age").expect("age");
    for id in (1..=60_000u64).step_by(500) {
        store
            .set_node_property_value(txn2, id, k_age, &Value::Integer(-(id as i64)))
            .unwrap();
    }
    // (2) Delete a band of RELATIONSHIPS by id (a clean edge-tombstone test; rel ids are 1.. in the Rel
    // store, allocated after the nodes). A surviving anchor whose edge is tombstoned loses that expansion.
    let rel_ids = store.scan_rel_ids().expect("scan rel ids");
    for &rid in rel_ids.iter().step_by(97) {
        let _ = store.delete_rel(txn2, rid); // idempotent; ignore an already-gone rel
    }
    store.commit(txn2).unwrap();

    // (3) DETACH DELETE a band of anchors through the REAL executor (so incident rels are detached first —
    // no dangling rel to a tombstone). Run with the morsel knob OFF so the delete itself is unambiguous.
    graphus_cypher::morsel::set_morsel_threads(1);
    let mut coord = TxnCoordinator::new(store);
    run_write(
        &mut coord,
        "MATCH (a:Person) WHERE a.age = -500 OR a.age = -1000 DETACH DELETE a",
    );

    for q in expand_query_matrix() {
        assert_knob_identical(&mut coord, q);
    }
}

/// Runs a writing statement `src` through the coordinator in a committed write transaction (used to drive
/// DETACH DELETE through the real executor so detach semantics are correct).
fn run_write(coord: &mut TxnCoordinator<MemBlockDevice, MemLogSink>, src: &str) {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let plan = plan_physical(
        &lower(&analyze(&ast).expect("analyze")),
        &IndexCatalog::empty(),
    );
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let txn = coord.begin_serializable();
    {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect");
        assert!(
            !graph.has_error(),
            "write captured an error: {:?}",
            graph.take_error()
        );
    }
    coord.commit(txn).expect("write commits");
}

// =================================================================================================
// Direct morsel-vs-serial at the bundle level: explicit anchor-morsel counts 1/2/8, with the
// SIREAD-marker UNION asserted byte-identical to serial (the ACID assertion).
// =================================================================================================

/// A coordinated harness over an `Rc<RefCell<Store>>` (so `morsel_label_scan` can capture a read view and
/// the equivalence test can drive an explicit anchor-morsel split through the production converge), with a
/// shared `SsiTracker` so the serial reference's and the morsels' markers land in comparable buffers.
struct Coordinated {
    store: Rc<RefCell<Store>>,
    ssi: Rc<RefCell<SsiTracker>>,
    locks: Rc<RefCell<LockTable>>,
    index: Rc<RefCell<IndexSet>>,
    columns: Rc<RefCell<graphus_cypher::column_cache::ColumnCache>>,
    zones: Rc<RefCell<graphus_cypher::zone_map::ZoneMap>>,
}

impl Coordinated {
    fn new(store: Store) -> Self {
        let index = Rc::new(RefCell::new(IndexSet::new()));
        {
            let node_ids = store.scan_node_ids().expect("scan node ids");
            let mut idx = index.borrow_mut();
            for id in node_ids {
                if let Ok(labels) = store.node_labels(id) {
                    for token in labels {
                        idx.insert_label(token, id);
                    }
                }
            }
        }
        Self {
            store: Rc::new(RefCell::new(store)),
            ssi: Rc::new(RefCell::new(SsiTracker::new())),
            locks: Rc::new(RefCell::new(LockTable::new())),
            index,
            columns: Rc::new(RefCell::new(
                graphus_cypher::column_cache::ColumnCache::new(),
            )),
            zones: Rc::new(RefCell::new(graphus_cypher::zone_map::ZoneMap::new())),
        }
    }

    fn live_at(&self, txn: TxnId, ts: graphus_core::Timestamp) -> Live {
        let snapshot = Snapshot { owner: txn, ts };
        self.ssi.borrow_mut().register(txn, ts);
        RecordStoreGraph::attach(
            Rc::clone(&self.store),
            txn,
            snapshot,
            Rc::clone(&self.ssi),
            Rc::clone(&self.locks),
            Rc::clone(&self.index),
            Rc::clone(&self.columns),
            Rc::clone(&self.zones),
        )
    }
}

/// The decomposed expand-plan pieces the executor 3c tier hands the morsel, extracted by walking the real
/// physical plan of `src` — so this drives the *real* planner output, not a hand-built AST. Carries the
/// post-work discriminant (count vs the projection columns) so the bundle harness can rebuild a
/// `MorselExpandPlan`.
struct ExpandPieces {
    label: String,
    from: graphus_cypher::logical::Var,
    relationship: graphus_cypher::logical::Var,
    to: graphus_cypher::logical::Var,
    direction: graphus_cypher::ast::RelDirection,
    types: Vec<graphus_cypher::ast::RelType>,
    /// `None` for the degree (count) shape; `Some(cols)` for the neighbour-collect (projection) shape.
    projection: Option<Vec<graphus_cypher::logical::ProjectionColumn>>,
}

impl ExpandPieces {
    fn plan(&self) -> MorselExpandPlan<'_> {
        MorselExpandPlan {
            from: &self.from,
            relationship: &self.relationship,
            to: &self.to,
            direction: self.direction,
            types: &self.types,
            post: match &self.projection {
                None => MorselExpandPostWork::Count,
                Some(cols) => MorselExpandPostWork::Project(cols),
            },
        }
    }
}

/// Plans `src` and extracts the exact 3c expand pieces. The accepted shapes are
/// `Aggregation { ExpandAll { LabelScan } }` (count(b)/count(*)) and
/// `Projection { ExpandAll { LabelScan } }` (pure projection). Panics if `src` is not one of these.
fn expand_pieces(src: &str) -> ExpandPieces {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let plan: PhysicalPlan = plan_physical(
        &lower(&analyze(&ast).expect("analyze")),
        &IndexCatalog::empty(),
    );

    // Peel the post-work above the ExpandAll: an Aggregation (count) or a Projection.
    let (projection, expand_op): (
        Option<Vec<graphus_cypher::logical::ProjectionColumn>>,
        &PhysicalOp,
    ) = match &plan.root {
        PhysicalOp::Aggregation {
            input,
            group_keys,
            aggregates,
        } => {
            assert!(group_keys.is_empty(), "expected a single-group aggregation");
            assert_eq!(aggregates.len(), 1, "expected one aggregate column");
            (None, input.as_ref())
        }
        PhysicalOp::Projection {
            input,
            items,
            distinct: false,
        } => (Some(items.clone()), input.as_ref()),
        other => panic!("expected Aggregation/Projection at the root, got {other:?}"),
    };

    let PhysicalOp::ExpandAll {
        input,
        from,
        relationship,
        to,
        direction,
        types,
        range,
        prior_rels,
        rel_props,
    } = expand_op
    else {
        panic!("expected an ExpandAll below the post-work, got {expand_op:?}");
    };
    assert!(range.is_none(), "expected a fixed-length hop");
    assert!(prior_rels.is_empty(), "expected no prior rels");
    assert!(rel_props.is_none(), "expected no inline rel-prop map");

    let label = match input.as_ref() {
        PhysicalOp::NodeByLabelScan { label, .. } | PhysicalOp::TokenLookupScan { label, .. } => {
            label.name.clone()
        }
        other => panic!("expected a bare label scan as the ExpandAll input, got {other:?}"),
    };

    ExpandPieces {
        label,
        from: from.clone(),
        relationship: relationship.clone(),
        to: to.clone(),
        direction: *direction,
        types: types.clone(),
        projection,
    }
}

/// The serial (single-anchor-morsel) reference: expand the WHOLE anchor set as ONE morsel, converged
/// through the production [`converge_expand_outcomes`] — the no-parallelism baseline. Returns the ordered
/// rendered rows, the converged count, and the seam's full SIREAD buffer.
fn serial_reference(
    coord: &Coordinated,
    txn: TxnId,
    ts: graphus_core::Timestamp,
    pieces: &ExpandPieces,
) -> (Vec<Vec<(String, String)>>, i64, SsiReadBuffer) {
    let live = coord.live_at(txn, ts);
    let scan = live
        .morsel_label_scan(&pieces.label)
        .expect("coordinated seam yields a morsel scan bundle");
    let n = scan.candidates.len();
    let params = BoundParameters::empty();
    let plan = pieces.plan();
    let outcome = scan.expand_morsel(0, n, &plan, &params);
    drop(scan);
    let converged = converge_expand_outcomes(vec![outcome]);
    assert!(converged.error.is_none(), "serial reference morsel errored");
    let rows: Vec<Vec<(String, String)>> = converged.rows.iter().map(render_row).collect();

    let mut buf = live
        .take_read_buffer()
        .expect("coordinated live seam holds a SIREAD buffer");
    for b in converged.buffers {
        absorb(&mut buf, b);
    }
    assert!(!live.has_error(), "serial reference captured an error");
    (rows, converged.count, buf)
}

/// Drives the morsel expand converge for `pieces` at snapshot `ts` with `morsel_count` morsels (explicit
/// anchor split through the production converge), returning the ordered rendered rows, the converged
/// count, and the UNION of all SIREAD markers.
fn morsel_run(
    coord: &Coordinated,
    txn: TxnId,
    ts: graphus_core::Timestamp,
    pieces: &ExpandPieces,
    morsel_count: usize,
) -> (Vec<Vec<(String, String)>>, i64, SsiReadBuffer) {
    let live = coord.live_at(txn, ts);
    let scan = live
        .morsel_label_scan(&pieces.label)
        .expect("coordinated seam yields a morsel scan bundle");
    let params = BoundParameters::empty();
    let plan = pieces.plan();

    let converged = run_in_morsels(&scan, &plan, &params, morsel_count);
    drop(scan);
    assert!(converged.error.is_none(), "a morsel captured an error");
    let rows: Vec<Vec<(String, String)>> = converged.rows.iter().map(render_row).collect();

    let mut union = live
        .take_read_buffer()
        .expect("coordinated live seam holds a SIREAD buffer");
    for b in converged.buffers {
        absorb(&mut union, b);
    }
    assert!(!live.has_error(), "the live seam captured an error");
    (rows, converged.count, union)
}

/// Folds buffer `b`'s markers into `into` (the union accumulation the executor's `merge_morsel_buffer`
/// performs).
fn absorb(into: &mut SsiReadBuffer, b: SsiReadBuffer) {
    let (_, keys, preds) = b.into_sorted_markers();
    for k in keys {
        into.record_read(k);
    }
    for p in preds {
        into.record_predicate_read(p);
    }
}

/// Splits `scan.candidates` (the anchors) into `morsel_count` contiguous ranges, expands each as a morsel
/// via [`MorselLabelScan::expand_morsel`], then converges through the **production**
/// [`converge_expand_outcomes`] — so the test exercises the exact engine-thread converge with an explicit
/// anchor-morsel count a small fixture can drive (the production `run_expand_morsels` coalesces a small
/// candidate set into one morsel via the 4096-id minimum chunk, a perf knob, not a correctness one).
fn run_in_morsels(
    scan: &MorselLabelScan,
    plan: &MorselExpandPlan<'_>,
    params: &BoundParameters,
    morsel_count: usize,
) -> ExpandConverged {
    let n = scan.candidates.len();
    if n == 0 {
        return ExpandConverged::default();
    }
    let count = morsel_count.max(1).min(n);
    let base = n / count;
    let mut outcomes = Vec::with_capacity(count);
    let mut lo = 0usize;
    for m in 0..count {
        let hi = if m + 1 == count { n } else { lo + base };
        outcomes.push(scan.expand_morsel(lo, hi, plan, params));
        lo = hi;
    }
    converge_expand_outcomes(outcomes)
}

/// Asserts the morsel converge equals the serial reference for `pieces` at `ts`, across anchor-morsel
/// counts 1 / 2 / 8: the ordered rendered rows, the converged count, AND the SIREAD-marker UNION (per-edge
/// keys + rel-pattern predicates) are byte-identical to serial. `what` labels the case in failures.
fn assert_morsel_equals_serial(
    coord: &Coordinated,
    ts: graphus_core::Timestamp,
    src: &str,
    what: &str,
) {
    let pieces = expand_pieces(src);
    let (srows, scount, sbuf) = serial_reference(coord, TxnId(1000), ts, &pieces);
    let (s_keys, s_preds) = {
        let m = sbuf.into_sorted_markers();
        (m.1, m.2)
    };

    for (i, &morsel_count) in [1usize, 2, 8].iter().enumerate() {
        let txn = TxnId(2000 + i as u64);
        let (mrows, mcount, mbuf) = morsel_run(coord, txn, ts, &pieces, morsel_count);

        assert_eq!(
            mcount, scount,
            "{what} [{morsel_count} morsels]: degree COUNT differs from serial"
        );
        assert_eq!(
            mrows, srows,
            "{what} [{morsel_count} morsels]: expansion ROW SEQUENCE (order included) differs from serial"
        );

        let (m_keys, m_preds) = {
            let m = mbuf.into_sorted_markers();
            (m.1, m.2)
        };
        assert_eq!(
            m_keys, s_keys,
            "{what} [{morsel_count} morsels]: per-edge SIREAD key UNION differs from serial"
        );
        assert_eq!(
            m_preds, s_preds,
            "{what} [{morsel_count} morsels]: rel-pattern predicate SIREAD UNION differs from serial"
        );
    }

    // The per-edge SIREAD markers must be non-empty for a graph with edges (else the marker assertion is
    // vacuous and would not actually guard the traversal's rw-edges).
    assert!(
        !s_keys.is_empty(),
        "{what}: expected non-empty per-edge SIREAD markers (assertion would be vacuous)"
    );
}

/// The bundle-level query matrix (each must be one of the two accepted 3c shapes). Smaller than the
/// end-to-end matrix to keep the per-shape 3-morsel sweep fast, but spans degree (directed / undirected /
/// typed / incoming) and neighbour-collect (directed / typed-with-rel-prop / undirected-self-loop).
fn bundle_query_matrix() -> Vec<&'static str> {
    vec![
        "MATCH (a:Person)-->(b) RETURN count(b)",
        "MATCH (a:Person)-->(b) RETURN count(*)",
        "MATCH (a:Person)-[:KNOWS]->(b) RETURN count(b)",
        "MATCH (a:Person)--(b) RETURN count(b)", // undirected: self-loop counted ONCE per anchor
        "MATCH (a:Person)<--(b) RETURN count(b)",
        "MATCH (a:Person)-->(b) RETURN a.name AS a, b.name AS b",
        "MATCH (a:Person)-[r:KNOWS]->(b) RETURN b.name AS b, r.since AS since",
        "MATCH (a:Person)--(b) RETURN a.name AS a, b.name AS b", // undirected rows: self-loop one row
    ]
}

/// FRESH data at the bundle level: every shape's morsel converge equals serial (rows in order + count +
/// marker union), across anchor-morsel counts 1/2/8.
#[test]
fn morsel_expand_equals_serial_fresh() {
    let store = seed_social(400, 5, 16);
    let ts = store.snapshot_ts();
    let coord = Coordinated::new(store);
    for q in bundle_query_matrix() {
        assert_morsel_equals_serial(&coord, ts, q, "fresh");
    }
}

/// OVERWRITE: in-place property overwrites (changing projected `b.name`/`r.since`) keep the morsel
/// converge identical to serial.
#[test]
fn morsel_expand_equals_serial_overwrite() {
    let mut store = seed_social(400, 5, 16);
    let txn2 = TxnId(2);
    store.begin(txn2);
    let k_name = store.token_id(Namespace::PropKey, "name").expect("name");
    for id in (1..=400u64).step_by(7) {
        store
            .set_node_property_value(txn2, id, k_name, &Value::String(format!("NEW{id}")))
            .unwrap();
    }
    store.commit(txn2).unwrap();
    let ts = store.snapshot_ts();
    let coord = Coordinated::new(store);
    for q in bundle_query_matrix() {
        assert_morsel_equals_serial(&coord, ts, q, "overwrite");
    }
}

/// INSERT: appending new `:Person` anchors + edges after the seed keeps the morsel converge identical to
/// serial at the latest snapshot.
#[test]
fn morsel_expand_equals_serial_insert() {
    let mut store = seed_social(400, 5, 16);
    let txn2 = TxnId(2);
    store.begin(txn2);
    let l_person = store.token_id(Namespace::Label, "Person").expect("person");
    let t_knows = store.token_id(Namespace::RelType, "KNOWS").expect("knows");
    let k_name = store.token_id(Namespace::PropKey, "name").expect("name");
    let k_age = store.token_id(Namespace::PropKey, "age").expect("age");
    let mut new_ids = Vec::new();
    for j in 0..50 {
        let (id, _) = store.create_node(txn2).unwrap();
        store.add_label(txn2, id, l_person).unwrap();
        store
            .set_node_property_value(txn2, id, k_age, &Value::Integer(j))
            .unwrap();
        store
            .set_node_property_value(txn2, id, k_name, &Value::String(format!("new{j}")))
            .unwrap();
        new_ids.push(id);
    }
    // Link the new nodes to node id 1 (a pre-existing anchor) so a fresh anchor expand has matches.
    for &id in &new_ids {
        store.create_rel(txn2, t_knows, id, 1).unwrap();
    }
    store.commit(txn2).unwrap();
    let ts = store.snapshot_ts();
    let coord = Coordinated::new(store);
    for q in bundle_query_matrix() {
        assert_morsel_equals_serial(&coord, ts, q, "insert");
    }
}

/// DELETE (rel + isolated node): deleting RELATIONSHIPS (edge tombstones) and a band of ISOLATED anchors
/// created edge-free (anchor tombstones) keeps the morsel converge identical to serial. Edge-free anchors
/// avoid leaving a dangling rel pointing at a tombstone (which would make the neighbour-collect projection
/// hit a deleted node — both paths identically, but that is a separate error-equivalence concern; here we
/// keep the converge clean so the row/marker assertions are exercised).
#[test]
fn morsel_expand_equals_serial_delete() {
    let mut store = seed_social(400, 5, 16);
    // Add a handful of EDGE-FREE :Person anchors to delete (anchor-tombstone test, no dangling rels).
    let txn_iso = TxnId(2);
    store.begin(txn_iso);
    let l = store.token_id(Namespace::Label, "Person").expect("person");
    let k_name = store.token_id(Namespace::PropKey, "name").expect("name");
    let k_age = store.token_id(Namespace::PropKey, "age").expect("age");
    let mut iso = Vec::new();
    for j in 0..20 {
        let (id, _) = store.create_node(txn_iso).unwrap();
        store.add_label(txn_iso, id, l).unwrap();
        store
            .set_node_property_value(txn_iso, id, k_age, &Value::Integer(j))
            .unwrap();
        store
            .set_node_property_value(txn_iso, id, k_name, &Value::String(format!("iso{j}")))
            .unwrap();
        iso.push(id);
    }
    store.commit(txn_iso).unwrap();

    let txn2 = TxnId(3);
    store.begin(txn2);
    // Delete a band of RELATIONSHIPS by id (edge tombstones).
    let rel_ids = store.scan_rel_ids().expect("scan rel ids");
    for &rid in rel_ids.iter().step_by(13) {
        let _ = store.delete_rel(txn2, rid);
    }
    // Delete the edge-free anchors (anchor tombstones — they vanish from the :Person scan, producing no
    // expansion; no dangling rel since they had none).
    for &id in &iso {
        store.delete_node(txn2, id).unwrap();
    }
    store.commit(txn2).unwrap();
    let ts = store.snapshot_ts();
    let coord = Coordinated::new(store);
    for q in bundle_query_matrix() {
        assert_morsel_equals_serial(&coord, ts, q, "delete");
    }
}

/// CROSS-SNAPSHOT: at an EARLIER committed snapshot the morsel converge must reproduce the older view, in
/// serial order; at the latest it reflects the relationship deletions. Proves MVCC edge-tombstone
/// visibility filters identically on the morsel and serial expand paths.
#[test]
fn morsel_expand_equals_serial_cross_snapshot() {
    let mut store = seed_social(400, 5, 16);
    let ts_early = store.snapshot_ts();
    let txn2 = TxnId(2);
    store.begin(txn2);
    let rel_ids = store.scan_rel_ids().expect("scan rel ids");
    for &rid in rel_ids.iter().step_by(7) {
        let _ = store.delete_rel(txn2, rid);
    }
    store.commit(txn2).unwrap();
    let ts_latest = store.snapshot_ts();
    assert_ne!(ts_early, ts_latest, "the two snapshots must differ");

    let coord = Coordinated::new(store);
    for q in bundle_query_matrix() {
        assert_morsel_equals_serial(&coord, ts_early, q, "cross-snapshot-early");
        assert_morsel_equals_serial(&coord, ts_latest, q, "cross-snapshot-latest");
    }
}

/// SELF-LOOP focused: a graph that is ALL self-loops (every anchor has a `KNOWS` self-edge and nothing
/// else) — the dedup hazard at its extreme. The serial `Operator::Expand` deduplicates a self-loop to ONE
/// row for a directed hop and (since `Both` reports it twice) ALSO ONE row for an undirected hop; the
/// morsel must reproduce both EXACTLY. Asserts degree == anchor count for directed AND undirected.
#[test]
fn morsel_expand_self_loops_dedup_identical() {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("wal");
    let mut s = RecordStore::create(device, wal, 16, 1).expect("store");
    let txn = TxnId(1);
    s.begin(txn);
    let l = s.intern_token(Namespace::Label, "Person").unwrap();
    let k_name = s.intern_token(Namespace::PropKey, "name").unwrap();
    let t = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let n = 200u64;
    for i in 0..n {
        let (id, _) = s.create_node(txn).unwrap();
        s.add_label(txn, id, l).unwrap();
        s.set_node_property_value(txn, id, k_name, &Value::String(format!("p{i}")))
            .unwrap();
        s.create_rel(txn, t, id, id).unwrap(); // a self-loop, and ONLY a self-loop
    }
    s.commit(txn).unwrap();
    let ts = s.snapshot_ts();
    let coord = Coordinated::new(s);

    // Directed: each anchor expands its self-loop to exactly ONE row ⇒ degree == anchor count.
    let pieces = expand_pieces("MATCH (a:Person)-[:KNOWS]->(b) RETURN count(b)");
    let (_, scount, _) = serial_reference(&coord, TxnId(1000), ts, &pieces);
    assert_eq!(
        scount, n as i64,
        "directed self-loop degree must be exactly the anchor count (one row per self-loop)"
    );
    assert_morsel_equals_serial(
        &coord,
        ts,
        "MATCH (a:Person)-[:KNOWS]->(b) RETURN count(b)",
        "self-loop-directed",
    );

    // Undirected: `expand` reports the self-loop's side TWICE (start+end), but serial deduplicates by rel
    // id to ONE row ⇒ still degree == anchor count. The morsel must reproduce the dedup EXACTLY.
    let pieces_u = expand_pieces("MATCH (a:Person)-[:KNOWS]-(b) RETURN count(b)");
    let (_, ucount, _) = serial_reference(&coord, TxnId(1001), ts, &pieces_u);
    assert_eq!(
        ucount, n as i64,
        "undirected self-loop degree must be exactly the anchor count (dedup collapses the 2 sides)"
    );
    assert_morsel_equals_serial(
        &coord,
        ts,
        "MATCH (a:Person)-[:KNOWS]-(b) RETURN count(b)",
        "self-loop-undirected",
    );
    // And the neighbour-collect rows for the undirected self-loop are one row per anchor.
    assert_morsel_equals_serial(
        &coord,
        ts,
        "MATCH (a:Person)--(b) RETURN a.name AS a, b.name AS b",
        "self-loop-rows",
    );
}

// =================================================================================================
// RBAC / MemGraph decline + knob=1 parity.
// =================================================================================================

/// A test oracle reporting a fixed restricted/unrestricted verdict.
struct FixedOracle {
    unrestricted: bool,
}

impl PrivilegeOracle for FixedOracle {
    fn is_unrestricted(&self) -> bool {
        self.unrestricted
    }
    fn can_traverse_label(&self, _label: &str) -> bool {
        true
    }
    fn can_read_property(&self, _label: &str, _property: &str) -> bool {
        true
    }
    fn can_traverse_rel_type(&self, _rel_type: &str) -> bool {
        true
    }
    fn can_read_rel_property(&self, _rel_type: &str, _property: &str) -> bool {
        true
    }
    fn can_write_label(&self, _label: &str) -> bool {
        true
    }
    fn can_write_rel_type(&self, _rel_type: &str) -> bool {
        true
    }
    fn can_write_property(&self, _label: &str, _property: &str) -> bool {
        true
    }
    fn can_write_rel_property(&self, _rel_type: &str, _property: &str) -> bool {
        true
    }
}

/// A restricted principal's `AuthorizedGraph` declines `morsel_label_scan` (`None`) so the executor runs
/// serial (which RBAC-composes per relationship + endpoint) — a restricted reader must NEVER traverse via
/// an off-thread expand that has no per-edge RBAC gate. The morsel-scan seam is shared with Slices 3a/3b,
/// so the 3c traversal tiers inherit the decline automatically.
#[test]
fn restricted_principal_declines_morsel_expand() {
    let store = seed_social(200, 4, 16);
    let ts = store.snapshot_ts();
    let coord = Coordinated::new(store);
    let mut live = coord.live_at(TxnId(1), ts);
    {
        let restricted = AuthorizedGraph::new(
            &mut live,
            FixedOracle {
                unrestricted: false,
            },
        );
        assert!(
            restricted.morsel_label_scan("Person").is_none(),
            "a restricted principal must DECLINE the morsel scan (so the 3c expand never bypasses per-edge RBAC)"
        );
    }
    {
        let unrestricted = AuthorizedGraph::new(&mut live, FixedOracle { unrestricted: true });
        assert!(
            unrestricted.morsel_label_scan("Person").is_some(),
            "an unrestricted principal forwards the inner morsel scan bundle"
        );
    }
}

/// `MemGraph` has no off-thread read view, so it declines `morsel_label_scan` — the 3c traversal tiers
/// always run serial against it (the library / doctest path stays serial).
#[test]
fn mem_graph_declines_morsel_expand() {
    use graphus_cypher::graph_access::MemGraph;
    let mut g = MemGraph::new();
    let a = g.add_node(["Person"], [("age", Value::Integer(1))]);
    let b = g.add_node(["Person"], [("age", Value::Integer(2))]);
    g.add_rel("KNOWS", a, b, Vec::<(String, Value)>::new());
    assert!(
        g.morsel_label_scan("Person").is_none(),
        "MemGraph must decline the morsel scan (serial path)"
    );
}

// =================================================================================================
// The MEASURED AC bench (Slice 3c): a single heavy TRAVERSAL query must use > 1 core under the knob.
// =================================================================================================

/// The MEASURED AC bench (`rmp` task #339, Slice 3c): a SINGLE
/// `MATCH (a:Person)-->(b) RETURN count(b)` (a degree over the social-network shape) over ~200k `:Person`
/// anchors with a moderate fan-out must use **more than one core** in its READ phase with the morsel knob
/// on, where the serial pipeline uses one.
///
/// The morsel pool is process-global and sized once at first use, so a fair core-count comparison runs
/// **one knob per process invocation** (matching the prompt's `/usr/bin/time -v` mean-cores =
/// (User+Sys)/Wall driver, which runs the binary fresh per knob). The knob + graph size are read from the
/// environment so an external driver controls them:
///
/// ```text
/// # baseline (≈1.0 core):
/// GRAPHUS_BENCH_MORSEL=1  /usr/bin/time -v cargo test -p graphus-cypher --release \
///     --test morsel_expand measure_morsel_expand_cores -- --ignored --nocapture
/// # parallel (>1 core — the AC):
/// GRAPHUS_BENCH_MORSEL=8  /usr/bin/time -v cargo test -p graphus-cypher --release \
///     --test morsel_expand measure_morsel_expand_cores -- --ignored --nocapture
/// ```
///
/// `mean cores = (User + Sys) / Wall` over the read loop (isolated from the serial preload via
/// `/proc/self/stat` utime+stime). The printed per-iter wall time also shows the speedup directly.
#[test]
#[ignore = "measurement bench — run explicitly with --ignored --nocapture under release (one knob per process)"]
fn measure_morsel_expand_cores() {
    use std::time::Instant;

    let knob: usize = std::env::var("GRAPHUS_BENCH_MORSEL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let people: i64 = std::env::var("GRAPHUS_BENCH_PEOPLE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000);
    let fanout: i64 = std::env::var("GRAPHUS_BENCH_FANOUT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8);
    let iters: usize = std::env::var("GRAPHUS_BENCH_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);

    graphus_cypher::morsel::set_morsel_threads(knob);

    // Preload (NOT measured for cores: the serial bulk insert + commit on the engine thread).
    let preload_start = Instant::now();
    let mut coord = coord_with_social(people, fanout);
    let preload = preload_start.elapsed();

    // The Slice-3c AC query: the per-anchor single-hop expand is the heavy parallelized work; the degree
    // sum is trivial.
    let q = "MATCH (a:Person)-->(b) RETURN count(b)";

    // Warm one run (fault pages into the buffer pool), then time the read loop — the phase whose
    // mean-cores is the AC. CPU time is read in ISOLATION via `/proc/self/stat` so the serial preload does
    // not dilute the core count the external `time -v` reports.
    let warm = run_rows(&mut coord, q);
    assert_eq!(warm.len(), 1, "a bare count must return exactly one row");
    let degree = warm[0][0].1.clone();

    let (cpu0, wall0) = (proc_cpu_secs(), Instant::now());
    let mut last = String::new();
    for _ in 0..iters {
        let r = run_rows(&mut coord, q);
        last = r[0][0].1.clone();
    }
    let elapsed = wall0.elapsed();
    let cpu = proc_cpu_secs() - cpu0;
    assert_eq!(last, degree, "the count must be stable under knob={knob}");

    let read_cores = cpu / elapsed.as_secs_f64();
    println!(
        "morsel-expand knob={knob} people={people} fanout={fanout} (degree={degree}): preload {:.2}s \
         | read {iters} iters in {:?} ({:.2} ms/iter) | READ-PHASE mean cores = {read_cores:.2} \
         (cpu {cpu:.2}s / wall {:.2}s)",
        preload.as_secs_f64(),
        elapsed,
        elapsed.as_secs_f64() * 1000.0 / iters as f64,
        elapsed.as_secs_f64(),
    );

    graphus_cypher::morsel::set_morsel_threads(1);
}

/// This process's total CPU time (user + system) in seconds, read from `/proc/self/stat` (Linux). Used by
/// the bench to isolate the READ phase's mean-core utilisation from the serial preload. Returns 0.0 off
/// Linux (the bench then reports only wall time).
#[cfg(target_os = "linux")]
fn proc_cpu_secs() -> f64 {
    let ticks_per_sec = 100.0; // _SC_CLK_TCK is 100 on every mainstream Linux; good enough for a bench.
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let after = stat.rsplit_once(')').map(|(_, t)| t).unwrap_or("");
    let fields: Vec<&str> = after.split_whitespace().collect();
    let utime: f64 = fields.get(11).and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let stime: f64 = fields.get(12).and_then(|s| s.parse().ok()).unwrap_or(0.0);
    (utime + stime) / ticks_per_sec
}

#[cfg(not(target_os = "linux"))]
fn proc_cpu_secs() -> f64 {
    0.0
}
