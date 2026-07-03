//! Equivalence + determinism guard for the **morsel-driven parallel grouped-aggregation-over-expand**
//! tier (`rmp` task #558 / #340 — the `top_liked` class:
//! `MATCH (:USER)-[:LIKE]->(a:ARTICLE) WITH a, count(*) AS likes RETURN a.id ORDER BY likes DESC LIMIT 1`).
//!
//! This tier fuses the Slice-3c per-anchor `ExpandAll` (parallelizing the traversal) with the #360 grouped
//! merge (parallelizing the group-by): it partitions the **anchors** (the `USER` scan) into contiguous
//! morsels, each expanding + filtering + grouping + aggregating the surviving `(a, r, b)` rows into a LOCAL
//! group table, then merges the partials **deterministically** on the engine thread (groups emitted in
//! serial first-seen order — the #360 merge reused verbatim). It covers exactly the shape both #360 (needs
//! a bare scan under the `Aggregation`) and Slice-3c (only a single-group `count`) decline: an
//! `Aggregation` over an `[Filter →] ExpandAll → scan` (the far-endpoint label `(a:ARTICLE)` lowers to an
//! interposed `Filter`).
//!
//! The inviolable obligation is that the parallel path is **byte-identical to serial** — rows, values AND
//! order — and preserves the SSI marker set. This guard asserts it two ways:
//!
//! 1. **End-to-end through the real executor + coordinator** (the strongest, TCK-aligned check): the same
//!    query run with the morsel knob on returns the exact same result (grouped rows + values + order, incl.
//!    the `ORDER BY … LIMIT` top-k above the aggregation) as with the knob off (serial) — across
//!    group-by-node / group-by-property, with / without the interposed `Filter(a:ARTICLE)`, and every
//!    mergeable aggregate (`count(*)` / `sum` / `min` / `max` / `collect`), plus the decline paths (`avg`,
//!    an impure filter) which fall back to serial and so must still be identical.
//! 2. **Direct morsel-vs-serial at the bundle level** (small graph, explicit anchor-morsel counts 1/2/8):
//!    the merged group-key sequence (first-seen order) is byte-identical across worker counts, AND the
//!    SIREAD-marker UNION (per-anchor label + per-edge + per-row filter/property reads) is byte-identical
//!    to the serial single-morsel reference (the load-bearing ACID assertion — moving the
//!    scan→expand→filter→aggregate onto morsels must not change which rw-edges form).

use std::cell::RefCell;
use std::rc::Rc;

use graphus_core::{TxnId, Value};
use graphus_cypher::ast::{Expr, RelDirection, RelType};
use graphus_cypher::binding::{BoundParameters, Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::GraphAccess;
use graphus_cypher::index_set::IndexSet;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::logical::{ProjectionColumn, Var};
use graphus_cypher::lower::lower;
use graphus_cypher::morsel::{
    GroupAggConverged, MorselExpandGroupSpec, MorselLabelScan, converge_group_aggregate_outcomes,
};
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalOp, PhysicalPlan, plan_physical};
use graphus_cypher::record_graph::RecordStoreGraph;
use graphus_cypher::runtime::{Row, RowValue};
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_txn::{LockTable, Snapshot, SsiReadBuffer, SsiTracker};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Live = RecordStoreGraph<MemBlockDevice, MemLogSink>;

// =================================================================================================
// Seed: a USER -[LIKE]-> {ARTICLE | TAG} multigraph (the top_liked topology).
// =================================================================================================

/// Bulk-seeds a committed `top_liked`-shaped graph directly on the store: `n_users` `:USER` anchors, each
/// with `LIKE` edges (carrying a `weight`) to a deterministic subset of `n_articles` `:ARTICLE` targets and
/// occasionally a `:TAG` target (so the interposed `Filter(a:ARTICLE)` actually drops rows — a non-vacuous
/// filter). Each article is liked by users spread across the whole id range, so a single article's group is
/// assembled from **many morsels** at parallel convergence (the cross-morsel merge the tier must get right).
/// A subset of users like the same article twice (the multigraph: `count(*)` counts each `LIKE` row).
///
/// The store's durable statistics report `nodes_with_label("USER") == n_users`, so the tier's cardinality
/// gate would engage above `MORSEL_MIN_ROWS` — but the tests force engagement on this modest fixture via
/// `set_morsel_min_rows(0)` (fast, and still multi-morsel at the bundle level). A small pool (64 frames)
/// makes the concurrent morsel expand ride the eviction path (the `rmp` #337 lost-pin regression surface).
fn seed_top_liked(n_users: i64, n_articles: i64, pool_frames: usize) -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut s = RecordStore::create(device, wal, pool_frames, 1).expect("create store");
    let txn = TxnId(1);
    s.begin(txn);
    let l_user = s.intern_token(Namespace::Label, "USER").unwrap();
    let l_article = s.intern_token(Namespace::Label, "ARTICLE").unwrap();
    let l_tag = s.intern_token(Namespace::Label, "TAG").unwrap();
    let k_id = s.intern_token(Namespace::PropKey, "id").unwrap();
    let t_like = s.intern_token(Namespace::RelType, "LIKE").unwrap();
    let k_weight = s.intern_token(Namespace::PropKey, "weight").unwrap();

    // Articles first, then a few tags, then users — so ids are stable and the far nodes exist before edges.
    let mut articles = Vec::with_capacity(n_articles as usize);
    for a in 0..n_articles {
        let (id, _) = s.create_node(txn).unwrap();
        s.add_label(txn, id, l_article).unwrap();
        s.set_node_property_value(txn, id, k_id, &Value::Integer(a))
            .unwrap();
        articles.push(id);
    }
    // A handful of tags (non-ARTICLE far nodes the label filter must drop).
    let n_tags = (n_articles / 8).max(1);
    let mut tags = Vec::with_capacity(n_tags as usize);
    for t in 0..n_tags {
        let (id, _) = s.create_node(txn).unwrap();
        s.add_label(txn, id, l_tag).unwrap();
        s.set_node_property_value(txn, id, k_id, &Value::Integer(1_000_000 + t))
            .unwrap();
        tags.push(id);
    }
    // Users + their LIKE edges.
    for u in 0..n_users {
        let (uid, _) = s.create_node(txn).unwrap();
        s.add_label(txn, uid, l_user).unwrap();
        s.set_node_property_value(txn, uid, k_id, &Value::Integer(u))
            .unwrap();

        // Two deterministic articles (spread across the whole range so each article is cross-morsel).
        let a0 = articles[(u.rem_euclid(n_articles)) as usize];
        let a1 = articles[((u.wrapping_mul(2654435761)).rem_euclid(n_articles)) as usize];
        let (r0, _) = s.create_rel(txn, t_like, uid, a0).unwrap();
        s.set_rel_property_value(txn, r0, k_weight, &Value::Integer(u % 20))
            .unwrap();
        let (r1, _) = s.create_rel(txn, t_like, uid, a1).unwrap();
        s.set_rel_property_value(txn, r1, k_weight, &Value::Integer((u * 3 + 1) % 20))
            .unwrap();

        // Every 5th user likes `a0` a SECOND time (multigraph: two LIKE rows to the same article).
        if u % 5 == 0 {
            let (r2, _) = s.create_rel(txn, t_like, uid, a0).unwrap();
            s.set_rel_property_value(txn, r2, k_weight, &Value::Integer((u + 7) % 20))
                .unwrap();
        }
        // Every 3rd user also likes a TAG (a far node the `a:ARTICLE` filter drops).
        if u % 3 == 0 {
            let tag = tags[(u.rem_euclid(n_tags)) as usize];
            let (rt, _) = s.create_rel(txn, t_like, uid, tag).unwrap();
            s.set_rel_property_value(txn, rt, k_weight, &Value::Integer((u + 2) % 20))
                .unwrap();
        }
    }
    s.commit(txn).unwrap();
    s
}

// =================================================================================================
// (1) End-to-end through the real executor + coordinator: knob=8 must be IDENTICAL to knob=1.
// =================================================================================================

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

/// Asserts `q`, run through the real executor + coordinator, returns the exact same result with the morsel
/// knob on (8 and 2 workers) as off (1, serial) — the inviolable obligation, worker-count-independent.
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
        "`{q}`: morsel(8) grouped-over-expand result (order included) must equal serial"
    );
    assert_eq!(
        serial, morsel2,
        "`{q}`: morsel(2) result must equal serial (worker-count-independent)"
    );
    serial
}

/// The grouped-over-expand query matrix exercised end-to-end. Spans: group-by-property vs group-by-node;
/// with / without the interposed far-endpoint `Filter(a:ARTICLE)`; every mergeable aggregate; the exact
/// `top_liked` `ORDER BY … LIMIT` top-k above the aggregation; and the DECLINE paths (`avg` / impure
/// filter) which fall back to serial and so must still be byte-identical.
fn query_matrix() -> Vec<&'static str> {
    vec![
        // --- group by far-node property, no filter ---
        "MATCH (u:USER)-[:LIKE]->(a) RETURN a.id AS id, count(*) AS c",
        // --- group by the ANCHOR (source) — each group is confined to one morsel (per-user out-degree) ---
        "MATCH (u:USER)-[:LIKE]->(a) RETURN u.id AS uid, count(*) AS c",
        // --- group by the bare far NODE, no filter (the `WITH a` shape) ---
        "MATCH (u:USER)-[:LIKE]->(a) WITH a, count(*) AS c RETURN a.id AS id, c",
        // --- the top_liked class: interposed Filter(a:ARTICLE) drops the TAG rows ---
        "MATCH (:USER)-[:LIKE]->(a:ARTICLE) WITH a, count(*) AS c RETURN a.id AS id, c",
        // --- sum / min / max over the rel property, with the filter ---
        "MATCH (u:USER)-[l:LIKE]->(a:ARTICLE) RETURN a.id AS id, sum(l.weight) AS w",
        "MATCH (u:USER)-[l:LIKE]->(a:ARTICLE) RETURN a.id AS id, min(l.weight) AS lo, max(l.weight) AS hi",
        // --- collect (order-sensitive) over the rel property ---
        "MATCH (u:USER)-[l:LIKE]->(a:ARTICLE) RETURN a.id AS id, count(*) AS c, collect(l.weight) AS ws",
        // --- multiple aggregates + the filter ---
        "MATCH (u:USER)-[l:LIKE]->(a:ARTICLE) RETURN a.id AS id, count(*) AS c, sum(l.weight) AS w, min(l.weight) AS lo, max(l.weight) AS hi",
        // --- the EXACT top_liked query (TopN above the aggregation); total order via secondary key ---
        "MATCH (:USER)-[:LIKE]->(a:ARTICLE) WITH a, count(*) AS likes RETURN a.id AS id, likes ORDER BY likes DESC, id ASC LIMIT 5",
        // --- the EXACT top_liked query VERBATIM (no secondary sort key): a genuine top-1 whose tie-break
        //     falls to the aggregation's first-seen output order, so parallel==serial proves the merge
        //     reproduces that order (the load-bearing determinism AC for the real query) ---
        "MATCH (:USER)-[:LIKE]->(a:ARTICLE) WITH a, count(*) AS likes RETURN a.id AS id ORDER BY likes DESC LIMIT 1",
        // --- LIMIT 1 with a total order (tie-free) ---
        "MATCH (:USER)-[:LIKE]->(a:ARTICLE) WITH a, count(*) AS likes RETURN a.id AS id ORDER BY likes DESC, id ASC LIMIT 1",
        // --- DECLINE: avg is non-associative in parallel ⇒ falls back to serial (still identical) ---
        "MATCH (u:USER)-[l:LIKE]->(a:ARTICLE) RETURN a.id AS id, avg(l.weight) AS av",
        // --- DECLINE: an impure (function-call) residual filter ⇒ serial ---
        "MATCH (u:USER)-[:LIKE]->(a) WHERE toString(a.id) <> '' RETURN a.id AS id, count(*) AS c",
    ]
}

/// The headline end-to-end guard: every query in the matrix is byte-identical between the serial and
/// parallel executor. `set_morsel_min_rows(0)` forces the tier through the merge on this modest fixture
/// (>4096 anchors ⇒ knob=8 fans into multiple morsels, exercising the cross-morsel group merge).
#[test]
fn expand_group_end_to_end_matches_serial() {
    graphus_cypher::morsel::set_morsel_min_rows(0);
    let store = seed_top_liked(6_000, 300, 64);
    let mut coord = TxnCoordinator::new(store);

    for q in query_matrix() {
        let rows = assert_knob_identical(&mut coord, q);
        assert!(
            !rows.is_empty(),
            "`{q}`: expected a non-empty grouped result (else the equivalence is vacuous)"
        );
    }

    graphus_cypher::morsel::set_morsel_min_rows(u64::MAX);
    graphus_cypher::morsel::set_morsel_threads(1);
}

/// Engagement proof (so the equivalence guard above is non-vacuous — a fully-declined tier would also pass
/// serial==serial): the parallel grouped-over-expand tier records a `parallel_scan_hit` when it fires. An
/// eligible query at knob=8 must increment the coordinator's hit counter; the same query at knob=1 must NOT
/// (serial); and a DECLINE shape (`avg` over the expand) must NOT increment even at knob=8.
#[test]
fn expand_group_tier_actually_engages() {
    graphus_cypher::morsel::set_morsel_min_rows(0);
    let store = seed_top_liked(6_000, 300, 64);
    let mut coord = TxnCoordinator::new(store);

    let eligible = "MATCH (:USER)-[:LIKE]->(a:ARTICLE) WITH a, count(*) AS c RETURN a.id AS id, c";

    // knob=1 (serial): no parallel hit.
    graphus_cypher::morsel::set_morsel_threads(1);
    let before_serial = coord.parallel_scan_hits();
    let _ = run_rows(&mut coord, eligible);
    assert_eq!(
        coord.parallel_scan_hits(),
        before_serial,
        "serial (knob=1) must not engage the parallel tier"
    );

    // knob=8: the tier fires.
    graphus_cypher::morsel::set_morsel_threads(8);
    let before_par = coord.parallel_scan_hits();
    let _ = run_rows(&mut coord, eligible);
    assert!(
        coord.parallel_scan_hits() > before_par,
        "the eligible grouped-over-expand query must engage the parallel tier at knob=8"
    );

    // A DECLINE shape (`avg`, non-associative in parallel) must NOT engage even at knob=8.
    let declined = "MATCH (u:USER)-[l:LIKE]->(a:ARTICLE) RETURN a.id AS id, avg(l.weight) AS av";
    let before_decl = coord.parallel_scan_hits();
    let _ = run_rows(&mut coord, declined);
    assert_eq!(
        coord.parallel_scan_hits(),
        before_decl,
        "an `avg`-over-expand query must decline the parallel tier (fall back to serial)"
    );

    graphus_cypher::morsel::set_morsel_min_rows(u64::MAX);
    graphus_cypher::morsel::set_morsel_threads(1);
}

// =================================================================================================
// (2) Bundle level: explicit anchor-morsel split 1/2/8 — group-key order + SIREAD marker union == serial.
// =================================================================================================

/// A minimal coordinated harness owning the store + SSI tracker + label index, so a live
/// [`RecordStoreGraph`] seam can be attached at a chosen snapshot and its morsel scan bundle driven.
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
            None,
        )
    }
}

/// The decomposed grouped-over-expand plan pieces, extracted by walking the real physical plan of `src`
/// (so the bundle harness drives the *real* planner output, not a hand-built AST). Owns the columns so the
/// borrowed [`MorselExpandGroupSpec`] can point into them.
struct ExpandGroupPieces {
    label: String,
    from: Var,
    relationship: Var,
    to: Var,
    direction: RelDirection,
    types: Vec<RelType>,
    filter: Option<Expr>,
    group_keys: Vec<ProjectionColumn>,
    aggregates: Vec<ProjectionColumn>,
}

impl ExpandGroupPieces {
    fn spec(&self) -> MorselExpandGroupSpec<'_> {
        MorselExpandGroupSpec {
            from: &self.from,
            relationship: &self.relationship,
            to: &self.to,
            direction: self.direction,
            types: &self.types,
            filter: self.filter.as_ref(),
            group_keys: &self.group_keys,
            aggregates: &self.aggregates,
        }
    }
}

/// Descends through the single-input wrapper operators (`Projection` / `Sort` / `TopN` / `Skip` /
/// `Limit`) the outer `RETURN … ORDER BY … LIMIT` produces, returning the first `Aggregation` — the node
/// the tier fires on.
fn find_aggregation(op: &PhysicalOp) -> Option<&PhysicalOp> {
    match op {
        PhysicalOp::Aggregation { .. } => Some(op),
        PhysicalOp::Projection { input, .. }
        | PhysicalOp::Sort { input, .. }
        | PhysicalOp::TopN { input, .. }
        | PhysicalOp::Skip { input, .. }
        | PhysicalOp::Limit { input, .. }
        | PhysicalOp::Filter { input, .. } => find_aggregation(input.as_ref()),
        _ => None,
    }
}

/// Plans `src` and extracts the grouped-over-expand pieces. The plan must contain an `Aggregation` (under
/// any outer `RETURN` / `ORDER BY` / `LIMIT` wrappers) over `[Filter →] ExpandAll → bare label scan`.
/// Panics if `src` is not that shape (so a planner change that alters the shape is caught loudly).
fn expand_group_pieces(src: &str) -> ExpandGroupPieces {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let plan: PhysicalPlan = plan_physical(
        &lower(&analyze(&ast).expect("analyze")),
        &IndexCatalog::empty(),
    );

    let Some(PhysicalOp::Aggregation {
        input,
        group_keys,
        aggregates,
    }) = find_aggregation(&plan.root)
    else {
        panic!("expected an Aggregation in the plan, got {:?}", plan.root);
    };
    assert!(!group_keys.is_empty(), "expected a non-empty GROUP BY");

    // Peel an optional interposed Filter (the far-endpoint label `(a:ARTICLE)`).
    let (filter, expand_op): (Option<Expr>, &PhysicalOp) = match input.as_ref() {
        PhysicalOp::Filter { input, predicate } => (Some(predicate.clone()), input.as_ref()),
        other => (None, other),
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
        panic!("expected an ExpandAll below the aggregation, got {expand_op:?}");
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

    ExpandGroupPieces {
        label,
        from: from.clone(),
        relationship: relationship.clone(),
        to: to.clone(),
        direction: *direction,
        types: types.clone(),
        filter,
        group_keys: group_keys.clone(),
        aggregates: aggregates.clone(),
    }
}

/// The merged group-key sequence (in first-seen order) rendered for byte comparison.
fn render_keys(converged: &GroupAggConverged) -> Vec<Vec<String>> {
    converged
        .groups
        .iter()
        .map(|g| g.key.iter().map(|v: &RowValue| format!("{v:?}")).collect())
        .collect()
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

/// Splits `scan.candidates` (the anchors) into `morsel_count` contiguous ranges, drives
/// [`MorselLabelScan::expand_group_aggregate_morsel`] per morsel, then converges through the **production**
/// [`converge_group_aggregate_outcomes`] — so the test exercises the exact engine-thread merge with an
/// explicit anchor-morsel count a small fixture can drive (the production runner coalesces a small candidate
/// set into one morsel via the 4096-id minimum chunk, a perf knob, not a correctness one).
fn run_in_morsels(
    scan: &MorselLabelScan,
    spec: &MorselExpandGroupSpec<'_>,
    params: &BoundParameters,
    morsel_count: usize,
) -> GroupAggConverged {
    let n = scan.candidates.len();
    if n == 0 {
        return GroupAggConverged::default();
    }
    let count = morsel_count.max(1).min(n);
    let base = n / count;
    let mut outcomes = Vec::with_capacity(count);
    let mut lo = 0usize;
    for m in 0..count {
        let hi = if m + 1 == count { n } else { lo + base };
        outcomes.push(scan.expand_group_aggregate_morsel(lo, hi, spec, params));
        lo = hi;
    }
    converge_group_aggregate_outcomes(outcomes)
}

/// Drives the grouped-over-expand converge for `pieces` at snapshot `ts` with `morsel_count` morsels,
/// returning the merged group-key sequence (first-seen order) and the UNION of all SIREAD markers.
fn morsel_run(
    coord: &Coordinated,
    txn: TxnId,
    ts: graphus_core::Timestamp,
    pieces: &ExpandGroupPieces,
    morsel_count: usize,
) -> (Vec<Vec<String>>, SsiReadBuffer) {
    let live = coord.live_at(txn, ts);
    let scan = live
        .morsel_label_scan(&pieces.label)
        .expect("coordinated seam yields a morsel scan bundle");
    let params = BoundParameters::empty();
    let spec = pieces.spec();

    let converged = run_in_morsels(&scan, &spec, &params, morsel_count);
    drop(scan);
    assert!(converged.error.is_none(), "a morsel captured an error");
    let keys = render_keys(&converged);

    let mut union = live
        .take_read_buffer()
        .expect("coordinated live seam holds a SIREAD buffer");
    for b in converged.buffers {
        absorb(&mut union, b);
    }
    assert!(!live.has_error(), "the live seam captured an error");
    (keys, union)
}

/// Asserts the morsel converge equals the serial (single-morsel) reference for `pieces` at `ts`, across
/// anchor-morsel counts 1/2/8: the merged group-key sequence (first-seen order) AND the SIREAD-marker UNION
/// (per-anchor label + per-edge + per-row reads) are byte-identical to serial. `what` labels failures.
fn assert_morsel_equals_serial(
    coord: &Coordinated,
    ts: graphus_core::Timestamp,
    src: &str,
    what: &str,
) {
    let pieces = expand_group_pieces(src);
    let (skeys, sbuf) = morsel_run(coord, TxnId(1000), ts, &pieces, 1);
    let (s_keys, s_preds) = {
        let m = sbuf.into_sorted_markers();
        (m.1, m.2)
    };

    for (i, &morsel_count) in [2usize, 8].iter().enumerate() {
        let txn = TxnId(2000 + i as u64);
        let (mkeys, mbuf) = morsel_run(coord, txn, ts, &pieces, morsel_count);

        assert_eq!(
            mkeys, skeys,
            "{what} [{morsel_count} morsels]: merged group-key sequence (first-seen order) differs from serial"
        );

        let (m_keys, m_preds) = {
            let m = mbuf.into_sorted_markers();
            (m.1, m.2)
        };
        assert_eq!(
            m_keys, s_keys,
            "{what} [{morsel_count} morsels]: per-edge/row SIREAD key UNION differs from serial"
        );
        assert_eq!(
            m_preds, s_preds,
            "{what} [{morsel_count} morsels]: predicate SIREAD UNION differs from serial"
        );
    }

    // The SIREAD markers must be non-empty (else the ACID assertion is vacuous).
    assert!(
        !s_keys.is_empty(),
        "{what}: expected non-empty SIREAD markers (assertion would be vacuous)"
    );
    // The grouping must be non-trivial (more than one group), else the merge is under-exercised.
    assert!(
        skeys.len() > 1,
        "{what}: expected more than one group (merge would be under-exercised)"
    );
}

/// The bundle-level query matrix (each an `Aggregation` over `[Filter →] ExpandAll → scan`). Smaller than
/// the end-to-end matrix to keep the per-shape 3-morsel sweep fast, but spans group-by-property /
/// group-by-node, with / without the interposed filter, and the mergeable aggregate kinds.
fn bundle_query_matrix() -> Vec<&'static str> {
    vec![
        "MATCH (u:USER)-[:LIKE]->(a) RETURN a.id AS id, count(*) AS c",
        "MATCH (u:USER)-[:LIKE]->(a) RETURN u.id AS uid, count(*) AS c",
        "MATCH (u:USER)-[:LIKE]->(a) WITH a, count(*) AS c RETURN a.id AS id, c",
        "MATCH (:USER)-[:LIKE]->(a:ARTICLE) WITH a, count(*) AS c RETURN a.id AS id, c",
        "MATCH (u:USER)-[l:LIKE]->(a:ARTICLE) RETURN a.id AS id, sum(l.weight) AS w",
        "MATCH (u:USER)-[l:LIKE]->(a:ARTICLE) RETURN a.id AS id, min(l.weight) AS lo, max(l.weight) AS hi",
        "MATCH (u:USER)-[l:LIKE]->(a:ARTICLE) RETURN a.id AS id, collect(l.weight) AS ws",
    ]
}

/// FRESH data at the bundle level: every shape's morsel converge equals the serial single-morsel reference
/// (merged group-key order + SIREAD marker union), across anchor-morsel counts 1/2/8.
#[test]
fn expand_group_bundle_equals_serial_fresh() {
    // Small graph but > 1 group and edges to many articles across the id range (cross-morsel groups).
    let store = seed_top_liked(400, 40, 16);
    let ts = store.snapshot_ts();
    let coord = Coordinated::new(store);
    for q in bundle_query_matrix() {
        assert_morsel_equals_serial(&coord, ts, q, "fresh");
    }
}

/// OVERWRITE: after in-place rel-weight overwrites (a second committed txn), the morsel converge is still
/// group-key-order + marker-union identical to serial at the newest snapshot (MVCC visibility preserved).
#[test]
fn expand_group_bundle_equals_serial_after_overwrite() {
    let mut store = seed_top_liked(400, 40, 16);

    // A second committed transaction overwrites some LIKE-edge weights (does not change the topology, so the
    // group-key set / order is unchanged, but the property reads the aggregates perform are re-validated).
    let txn2 = TxnId(2);
    store.begin(txn2);
    let t_like = store.intern_token(Namespace::RelType, "LIKE").unwrap();
    let k_weight = store.intern_token(Namespace::PropKey, "weight").unwrap();
    let rel_ids = store.scan_rel_ids().expect("scan rel ids");
    for (i, rid) in rel_ids.into_iter().enumerate() {
        if i % 4 == 0 {
            // Only LIKE edges carry a weight; setting it on a LIKE rel is valid, and every rel here is LIKE.
            let _ = t_like;
            store
                .set_rel_property_value(txn2, rid, k_weight, &Value::Integer((i as i64) % 20))
                .unwrap();
        }
    }
    store.commit(txn2).unwrap();

    let ts = store.snapshot_ts();
    let coord = Coordinated::new(store);
    for q in bundle_query_matrix() {
        assert_morsel_equals_serial(&coord, ts, q, "overwrite");
    }
}

// =================================================================================================
// (3) Measurement bench: wall-clock + read-phase mean cores of the `top_liked` query (`rmp` #558 / #340).
// =================================================================================================

/// Measures the wall-clock + READ-PHASE mean cores of the exact `top_liked` query
/// (`MATCH (:USER)-[:LIKE]->(a:ARTICLE) WITH a, count(*) AS likes RETURN a.id ORDER BY likes DESC LIMIT 1`)
/// at the morsel knob in `GRAPHUS_BENCH_MORSEL` (one knob per process). `mean cores = (User + Sys) / Wall`
/// over the read loop, isolated from the serial preload via `/proc/self/stat` utime+stime. At the default
/// `GRAPHUS_BENCH_USERS = 400_000` (≈ 1M `LIKE` edges) the anchor-cardinality gate (`USER >= 50k`) engages
/// the tier on its own merit (no `set_morsel_min_rows` override), so this measures the realistic path.
#[test]
#[ignore = "measurement bench — run explicitly with --ignored --nocapture under release (one knob per process)"]
fn measure_top_liked_cores() {
    use std::time::Instant;

    let knob: usize = std::env::var("GRAPHUS_BENCH_MORSEL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let users: i64 = std::env::var("GRAPHUS_BENCH_USERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(400_000);
    let articles: i64 = std::env::var("GRAPHUS_BENCH_ARTICLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5_000);
    let iters: usize = std::env::var("GRAPHUS_BENCH_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);

    graphus_cypher::morsel::set_morsel_threads(knob);

    // Preload (NOT measured for cores: the serial bulk insert + commit on the engine thread).
    let preload_start = Instant::now();
    let store = seed_top_liked(users, articles, 4096);
    let mut coord = TxnCoordinator::new(store);
    let preload = preload_start.elapsed();

    // The exact `top_liked` query (the measured bottleneck): expand all LIKE edges, group by ARTICLE, count,
    // then ORDER BY likes DESC LIMIT 1. The expand + grouped fold is the heavy parallelized work; the
    // top-1 over the (≈ `articles`) distinct groups is trivial.
    let q = "MATCH (:USER)-[:LIKE]->(a:ARTICLE) WITH a, count(*) AS likes RETURN a.id AS id ORDER BY likes DESC LIMIT 1";

    // Warm one run (fault pages into the buffer pool), then time the read loop — the phase whose mean-cores
    // is the AC. CPU time is read in ISOLATION via `/proc/self/stat` so the serial preload does not dilute it.
    let warm = run_rows(&mut coord, q);
    let top = warm.first().map(|r| format!("{r:?}")).unwrap_or_default();

    let (cpu0, wall0) = (proc_cpu_secs(), Instant::now());
    let mut last = String::new();
    for _ in 0..iters {
        let r = run_rows(&mut coord, q);
        last = r.first().map(|row| format!("{row:?}")).unwrap_or_default();
    }
    let elapsed = wall0.elapsed();
    let cpu = proc_cpu_secs() - cpu0;
    assert_eq!(
        last, top,
        "the top article must be stable under knob={knob}"
    );

    let read_cores = cpu / elapsed.as_secs_f64();
    println!(
        "top_liked knob={knob} users={users} articles={articles} (top={top}): preload {:.2}s \
         | read {iters} iters in {:?} ({:.2} ms/iter) | READ-PHASE mean cores = {read_cores:.2} \
         (cpu {cpu:.2}s / wall {:.2}s)",
        preload.as_secs_f64(),
        elapsed,
        elapsed.as_secs_f64() * 1000.0 / iters as f64,
        elapsed.as_secs_f64(),
    );

    graphus_cypher::morsel::set_morsel_threads(1);
}

/// This process's total CPU time (user + system) in seconds, from `/proc/self/stat` (Linux). Isolates the
/// READ phase's mean-core utilisation from the serial preload. Returns 0.0 off Linux (wall time only).
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
