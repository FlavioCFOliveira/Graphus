//! Equivalence guard for the **morsel-driven** parallel scan→filter→project (+ stable ORDER BY / top-k)
//! read path (`rmp` task #339, Slice 3b — the slice that extends morsel intra-query parallelism from the
//! bare-aggregate shape to filtered, projected, ordered *rows out*).
//!
//! Slice 3b parallelizes the **read + filter + projection** of a bare
//! `MATCH (n:Label) [WHERE <pure>] RETURN <per-row projection> [ORDER BY <pure keys> [LIMIT n]]`: the
//! seam ([`RecordStoreGraph::morsel_label_scan`]) hands the executor the candidate-id vector + an erased,
//! `Send`, cheap-cloneable read surface; the executor splits the candidates into contiguous morsels read
//! concurrently on a dedicated pool, each filtering + projecting (and, for ORDER BY, pre-sorting) on a
//! `Send` [`ReadOnlyGraph`], then converges **row-order-identically to serial** (contiguous concat, or a
//! stable k-way merge for ORDER BY / TopN).
//!
//! The crux of this slice is the **inviolable ordering obligation**: every parallel path must be
//! provably row-order-identical to serial. This guard asserts it two ways:
//!
//! 1. **End-to-end through the real executor + coordinator** (the strongest, TCK-aligned check): the same
//!    query run with the morsel knob on (`set_morsel_threads(8)`) returns the **exact same row sequence**
//!    (order included) as with the knob off (`set_morsel_threads(1)`, fully serial) — for unfiltered /
//!    filtered / projected / ORDER BY (asc + desc + ties) / TopN shapes, over fresh / overwritten /
//!    deleted data. Contiguous-concat shapes (no ORDER BY) are also asserted **deterministic regardless
//!    of worker count**.
//! 2. **Direct morsel-vs-serial at the bundle level** (small graphs, explicit morsel counts 1 / 2 / 8):
//!    the morsels' converged rows equal the serial reference **in order**, AND the SIREAD-marker UNION is
//!    byte-identical to the serial scan's marker set (the load-bearing ACID assertion — moving the
//!    scan→filter→project onto morsels must not change which rw-edges form).
//!
//! Plus focused guards that a restricted RBAC principal and `MemGraph` **decline** the morsel scan, that
//! the purity gate rejects impure shapes, and that the stable k-way merge reproduces serial tie order.

use std::cell::RefCell;
use std::rc::Rc;

use graphus_core::{TxnId, Value};
use graphus_cypher::authorized_graph::{AuthorizedGraph, PrivilegeOracle};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::GraphAccess;
use graphus_cypher::index_set::IndexSet;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::morsel::{
    MorselLabelScan, ScanFilterConverged, converge_scan_filter_outcomes, is_pure_per_row_expr,
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
// End-to-end through the real executor + coordinator: knob=8 must be ROW-ORDER-IDENTICAL to knob=1.
// =================================================================================================

/// Bulk-seeds `n` committed `:Person {age, name, active}` nodes directly on the store (fast, no per-node
/// query), then wraps it in a `TxnCoordinator` whose durable statistics report
/// `nodes_with_label("Person") == n` (so the morsel tier's cardinality gate engages above
/// `MORSEL_MIN_ROWS`). A deliberately small pool (64 frames) so the concurrent morsel scan exercises the
/// eviction path (the `rmp` #337 lost-pin race regression surface).
///
/// `age = i % 1000` deliberately creates **many ties** on `age` so ORDER BY tie-order is exercised; the
/// secondary `name = format!("p{i}")` is unique and monotone with `i` (the candidate order), so a stable
/// sort on `age` then implicitly on candidate order is observable.
fn coord_with_people(n: i64) -> TxnCoordinator<MemBlockDevice, MemLogSink> {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut s = RecordStore::create(device, wal, 64, 1).expect("create store");
    let txn = TxnId(1);
    s.begin(txn);
    let l_person = s.intern_token(Namespace::Label, "Person").unwrap();
    let k_age = s.intern_token(Namespace::PropKey, "age").unwrap();
    let k_name = s.intern_token(Namespace::PropKey, "name").unwrap();
    let k_active = s.intern_token(Namespace::PropKey, "active").unwrap();
    for i in 0..n {
        let (id, _) = s.create_node(txn).unwrap();
        s.add_label(txn, id, l_person).unwrap();
        s.set_node_property_value(txn, id, k_age, &Value::Integer(i % 1000))
            .unwrap();
        s.set_node_property_value(txn, id, k_name, &Value::String(format!("p{i}")))
            .unwrap();
        s.set_node_property_value(txn, id, k_active, &Value::Boolean(i % 2 == 0))
            .unwrap();
    }
    s.commit(txn).unwrap();
    TxnCoordinator::new(s)
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

/// A row as an order-preserving `Vec<(column_name, Debug-of-value)>` (the `Debug` form gives a stable,
/// total textual key over any `RowValue`, so two runs compare exactly including value identity + order).
fn render_row(row: &Row) -> Vec<(String, String)> {
    row.columns()
        .iter()
        .zip(row.values())
        .map(|(c, v)| (c.clone(), format!("{v:?}")))
        .collect()
}

/// Asserts that `q`, run through the real executor + coordinator, returns the **exact same ordered row
/// sequence** with the morsel knob on (8 workers) as off (1 worker, serial) — the inviolable Slice-3b
/// ordering obligation. The knob is a process global, so it is set around each phase; reset after.
fn assert_knob_row_order_identical(
    coord: &mut TxnCoordinator<MemBlockDevice, MemLogSink>,
    q: &str,
) -> Vec<Vec<(String, String)>> {
    graphus_cypher::morsel::set_morsel_threads(1);
    let serial = run_rows(coord, q);

    graphus_cypher::morsel::set_morsel_threads(8);
    let morsel8 = run_rows(coord, q);

    // A second worker count: the contiguous-concat order must be invariant to it (determinism AC); the
    // stable merge likewise.
    graphus_cypher::morsel::set_morsel_threads(2);
    let morsel2 = run_rows(coord, q);

    graphus_cypher::morsel::set_morsel_threads(1);

    assert_eq!(
        serial, morsel8,
        "`{q}`: morsel(8) row sequence (order included) must equal serial"
    );
    assert_eq!(
        serial, morsel2,
        "`{q}`: morsel(2) row sequence must equal serial (worker-count-independent order)"
    );
    serial
}

/// END-TO-END: the full Slice-3b query matrix is row-order-identical between morsel and serial, over a
/// large (60k > MORSEL_MIN_ROWS) `:Person` graph so the tier actually engages.
#[test]
fn morsel_rows_end_to_end_match_serial() {
    let mut coord = coord_with_people(60_000);

    // (query, expected non-empty result — a smoke check that the run isn't vacuously empty)
    let queries = [
        // Unfiltered project of the node itself (contiguous concat; Cypher order unspecified but the
        // morsel path is deterministic = serial candidate order).
        "MATCH (n:Person) RETURN n",
        // Projected scalar property.
        "MATCH (n:Person) RETURN n.age AS age",
        // Filtered (pure residual) + projected.
        "MATCH (n:Person) WHERE n.age > 500 RETURN n.age AS age, n.name AS name",
        // Filtered with a boolean property + arithmetic projection.
        "MATCH (n:Person) WHERE n.active RETURN n.age + 1 AS a1",
        // ORDER BY asc with MANY ties on age (tie order = stable candidate order); LIMIT (TopN).
        "MATCH (n:Person) WHERE n.age >= 0 RETURN n.age AS age, n.name AS name ORDER BY n.age LIMIT 100",
        // ORDER BY desc + LIMIT.
        "MATCH (n:Person) RETURN n.age AS age, n.name AS name ORDER BY n.age DESC LIMIT 50",
        // ORDER BY a two-key vector (age asc, name desc) — full sort, no limit.
        "MATCH (n:Person) WHERE n.age < 10 RETURN n.age AS age, n.name AS name ORDER BY n.age, n.name DESC",
        // CASE projection (pure, no function call) + filter.
        "MATCH (n:Person) WHERE n.age > 900 RETURN CASE WHEN n.age > 950 THEN 'hi' ELSE 'lo' END AS bucket, n.name AS name ORDER BY n.name LIMIT 25",
    ];

    for q in queries {
        let rows = assert_knob_row_order_identical(&mut coord, q);
        assert!(!rows.is_empty(), "`{q}`: expected a non-empty result");
    }

    graphus_cypher::morsel::set_morsel_threads(1);
}

/// END-TO-END over OVERWRITTEN + DELETED data: the morsel path must see the newest-visible value and drop
/// tombstoned nodes via per-candidate MVCC re-validation, exactly as serial — order included.
#[test]
fn morsel_rows_end_to_end_overwrite_delete() {
    // Seed via the bulk path, then overwrite + delete in committed follow-on transactions.
    let mut coord = coord_with_people(55_000);

    // Run a write transaction through the coordinator to overwrite some ages and delete some nodes, so the
    // candidate index keeps the (now-tombstoned / overwritten) ids.
    graphus_cypher::morsel::set_morsel_threads(1);
    run_write(
        &mut coord,
        "MATCH (n:Person) WHERE n.age = 0 SET n.age = 9999",
    );
    run_write(&mut coord, "MATCH (n:Person) WHERE n.age = 1 DELETE n");

    let queries = [
        "MATCH (n:Person) WHERE n.age > 9000 RETURN n.age AS age, n.name AS name ORDER BY n.name LIMIT 100",
        "MATCH (n:Person) RETURN n.age AS age ORDER BY n.age DESC LIMIT 100",
        "MATCH (n:Person) WHERE n.age < 5 RETURN n.name AS name ORDER BY n.name",
    ];
    for q in queries {
        assert_knob_row_order_identical(&mut coord, q);
    }
    graphus_cypher::morsel::set_morsel_threads(1);
}

/// Runs a write query through the coordinator and commits it (used to mutate the graph between read
/// assertions). Returns the affected-row count is irrelevant here — it just applies the side effects.
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
        let _ = cursor.collect_all().expect("collect");
        assert!(!graph.has_error(), "write captured an error");
    }
    coord.commit(txn).expect("write commits");
}

// =================================================================================================
// Direct morsel-vs-serial at the bundle level: row-order + marker-union, across morsel counts 1/2/8.
// =================================================================================================

/// A shared coordinated environment over one `Rc`-shared store: the `ssi` tracker (so reads register
/// SIREAD markers), the lock table, and the populated derived sidecars `attach` requires. Mirrors
/// `tests/morsel_label_aggregate.rs::Coordinated`.
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

/// The decomposed plan pieces the executor tier hands the morsel: `(scan_var, label, filter, projection,
/// sort_keys, top_n)`, extracted by walking the physical plan of `src` — so this drives the *real*
/// planner output, not a hand-built AST.
struct PlanPieces {
    label: String,
    scan_var: String,
    filter: Option<graphus_cypher::ast::Expr>,
    projection: Vec<graphus_cypher::logical::ProjectionColumn>,
    sort_keys: Vec<graphus_cypher::logical::SortKey>,
}

/// Plans `src` and extracts the **exact pieces the executor tier receives** for the Slice-3b shape.
///
/// The planner's real shape for an `ORDER BY` that references a pre-projection variable is
/// `Projection[narrowing] ▸ Sort/TopN ▸ Projection[widened] ▸ Filter? ▸ scan` (the widened projection
/// carries the dual-scope variable for the sort keys; the narrowing one drops it afterwards). The
/// executor tier fires at the **Sort/TopN site**, receiving `Sort ▸ Projection[widened] ▸ Filter? ▸ scan`
/// — so this peels an optional outer narrowing `Projection`, then the `Sort`/`TopN`, then the widened
/// `Projection`, then an optional `Filter`, down to the bare label scan. The extracted `projection` is the
/// **widened** one, matching what the morsel produces; the (deterministic, identical) narrowing above is
/// not applied, so the test compares the widened rows. Panics if `src` is not the expected shape.
fn plan_pieces(src: &str) -> PlanPieces {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let plan: PhysicalPlan = plan_physical(
        &lower(&analyze(&ast).expect("analyze")),
        &IndexCatalog::empty(),
    );

    // Skip a leading narrowing Projection IFF its input is a Sort/TopN (the dual-scope narrowing shape);
    // otherwise the root IS the (sole) projection of a no-ORDER-BY query.
    let after_narrowing: &PhysicalOp = match &plan.root {
        PhysicalOp::Projection { input, .. }
            if matches!(
                input.as_ref(),
                PhysicalOp::Sort { .. } | PhysicalOp::TopN { .. }
            ) =>
        {
            input.as_ref()
        }
        other => other,
    };

    // Peel an optional Sort / TopN to capture the sort keys, then the (widened) Projection.
    let (sort_keys, proj_op): (Vec<_>, &PhysicalOp) = match after_narrowing {
        PhysicalOp::Sort { input, keys } => (keys.clone(), input.as_ref()),
        PhysicalOp::TopN { input, keys, .. } => (keys.clone(), input.as_ref()),
        other => (Vec::new(), other),
    };
    let PhysicalOp::Projection {
        input: proj_input,
        items,
        distinct: false,
    } = proj_op
    else {
        panic!("expected a non-DISTINCT Projection below the Sort, got {proj_op:?}");
    };
    let (filter, scan_op): (Option<graphus_cypher::ast::Expr>, &PhysicalOp) =
        match proj_input.as_ref() {
            PhysicalOp::Filter { input, predicate } => (Some(predicate.clone()), input.as_ref()),
            other => (None, other),
        };
    let (scan_var, label) = match scan_op {
        PhysicalOp::NodeByLabelScan { variable, label }
        | PhysicalOp::TokenLookupScan {
            variable, label, ..
        } => (variable.name.clone(), label.name.clone()),
        other => panic!("expected a bare label scan leaf, got {other:?}"),
    };
    PlanPieces {
        label,
        scan_var,
        filter,
        projection: items.clone(),
        sort_keys,
    }
}

/// The serial (single-morsel) reference: read + filter + project + (stable sort + `top_n`) the **whole**
/// candidate set as ONE morsel, converged through the production [`converge_scan_filter_outcomes`] — i.e.
/// the no-parallelism baseline. Returns the ordered rendered rows and the seam's full SIREAD buffer. The
/// 1/2/8-morsel runs are then asserted equal to this (split-invariance); the end-to-end test asserts
/// equality against the *independent* serial executor pipeline.
fn serial_reference(
    coord: &Coordinated,
    txn: TxnId,
    ts: graphus_core::Timestamp,
    pieces: &PlanPieces,
    top_n: Option<usize>,
) -> (Vec<Vec<(String, String)>>, SsiReadBuffer) {
    let live = coord.live_at(txn, ts);
    let scan = live
        .morsel_label_scan(&pieces.label)
        .expect("coordinated seam yields a morsel scan bundle");
    let n = scan.candidates.len();
    let params = graphus_cypher::binding::BoundParameters::empty();
    let outcome = scan.read_filter_project_morsel(
        0,
        n,
        &pieces.scan_var,
        pieces.filter.as_ref(),
        &pieces.projection,
        &pieces.sort_keys,
        &params,
    );
    drop(scan);
    // Converge the single outcome through the PRODUCTION converge so `top_n` truncation matches the
    // multi-morsel runs exactly.
    let converged = converge_scan_filter_outcomes(vec![outcome], &pieces.sort_keys, top_n);
    assert!(converged.error.is_none(), "serial reference morsel errored");
    let rows: Vec<Vec<(String, String)>> = converged.rows.iter().map(render_row).collect();

    // Fold the morsel buffer into the seam's buffer (so the serial reference's marker set includes both
    // the engine-thread coarse footprint AND the per-candidate / per-row markers).
    let mut buf = live
        .take_read_buffer()
        .expect("coordinated live seam holds a SIREAD buffer");
    for b in converged.buffers {
        let (_, mkeys, mpreds) = b.into_sorted_markers();
        for k in mkeys {
            buf.record_read(k);
        }
        for p in mpreds {
            buf.record_predicate_read(p);
        }
    }
    assert!(!live.has_error(), "serial reference captured an error");
    (rows, buf)
}

/// Drives the morsel scan→filter→project converge for `pieces` at snapshot `ts` with `morsel_count`
/// morsels (via the public `run_scan_filter_morsels`-equivalent explicit split), returning the ordered
/// rendered rows and the UNION of all SIREAD markers.
fn morsel_run(
    coord: &Coordinated,
    txn: TxnId,
    ts: graphus_core::Timestamp,
    pieces: &PlanPieces,
    top_n: Option<usize>,
    morsel_count: usize,
) -> (Vec<Vec<(String, String)>>, SsiReadBuffer) {
    let live = coord.live_at(txn, ts);
    let scan = live
        .morsel_label_scan(&pieces.label)
        .expect("coordinated seam yields a morsel scan bundle");
    let params = graphus_cypher::binding::BoundParameters::empty();

    let converged = run_in_morsels(&scan, pieces, top_n, &params, morsel_count);
    drop(scan);
    assert!(converged.error.is_none(), "a morsel captured an error");
    let rows: Vec<Vec<(String, String)>> = converged.rows.iter().map(render_row).collect();

    // The union buffer starts from the engine-thread coarse markers, then absorbs every morsel buffer.
    let mut union = live
        .take_read_buffer()
        .expect("coordinated live seam holds a SIREAD buffer");
    for b in converged.buffers {
        let (_, mkeys, mpreds) = b.into_sorted_markers();
        for k in mkeys {
            union.record_read(k);
        }
        for p in mpreds {
            union.record_predicate_read(p);
        }
    }
    assert!(!live.has_error(), "the live seam captured an error");
    (rows, union)
}

/// Splits `scan.candidates` into `morsel_count` contiguous ranges, reads + filters + projects each as a
/// morsel via the public [`MorselLabelScan::read_filter_project_morsel`], then converges through the
/// **production** [`converge_scan_filter_outcomes`] (contiguous concat, or stable k-way merge for ORDER BY
/// / TopN) — so the test exercises the exact engine-thread converge, with an explicit morsel count
/// (1 / 2 / 8) a small fixture can drive (the production `run_scan_filter_morsels` would coalesce a small
/// candidate set into a single morsel via its 4096-id minimum chunk, which is a perf knob, not a
/// correctness one).
fn run_in_morsels(
    scan: &MorselLabelScan,
    pieces: &PlanPieces,
    top_n: Option<usize>,
    params: &graphus_cypher::binding::BoundParameters,
    morsel_count: usize,
) -> ScanFilterConverged {
    let n = scan.candidates.len();
    if n == 0 {
        return ScanFilterConverged::default();
    }
    let count = morsel_count.max(1).min(n);
    let base = n / count;
    let mut outcomes = Vec::with_capacity(count);
    let mut lo = 0usize;
    for m in 0..count {
        let hi = if m + 1 == count { n } else { lo + base };
        outcomes.push(scan.read_filter_project_morsel(
            lo,
            hi,
            &pieces.scan_var,
            pieces.filter.as_ref(),
            &pieces.projection,
            &pieces.sort_keys,
            params,
        ));
        lo = hi;
    }
    converge_scan_filter_outcomes(outcomes, &pieces.sort_keys, top_n)
}

/// Asserts the morsel converge equals the serial reference for `pieces` at `ts`, across morsel counts
/// 1 / 2 / 8: the ordered rendered row sequence AND the SIREAD-marker UNION (keys + predicates) are
/// byte-identical to serial. `what` labels the case in failures.
fn assert_morsel_equals_serial(
    coord: &Coordinated,
    ts: graphus_core::Timestamp,
    src: &str,
    top_n: Option<usize>,
    what: &str,
) {
    let pieces = plan_pieces(src);
    let (srows, sbuf) = serial_reference(coord, TxnId(1000), ts, &pieces, top_n);
    let (s_keys, s_preds) = {
        let m = sbuf.into_sorted_markers();
        (m.1, m.2)
    };

    for (i, &morsel_count) in [1usize, 2, 8].iter().enumerate() {
        let txn = TxnId(2000 + i as u64);
        let (mrows, mbuf) = morsel_run(coord, txn, ts, &pieces, top_n, morsel_count);

        assert_eq!(
            mrows, srows,
            "{what} [{morsel_count} morsels]: ROW SEQUENCE (order included) differs from serial"
        );

        let (m_keys, m_preds) = {
            let m = mbuf.into_sorted_markers();
            (m.1, m.2)
        };
        assert_eq!(
            m_keys, s_keys,
            "{what} [{morsel_count} morsels]: per-candidate SIREAD key UNION differs from serial"
        );
        assert_eq!(
            m_preds, s_preds,
            "{what} [{morsel_count} morsels]: predicate SIREAD marker UNION differs from serial"
        );
    }

    assert!(
        !s_keys.is_empty(),
        "{what}: expected non-empty per-candidate SIREAD markers (assertion would be vacuous)"
    );
}

/// Seeds `n` `(:Person {age: i%50, name, active})` nodes plus two non-`Person` nodes carrying `age`
/// (which must never leak into a `:Person` scan). Returns the committed store + its snapshot timestamp.
/// `age = i % 50` creates dense ties for ORDER BY tie-order coverage.
fn seed_people(n: i64) -> (Store, graphus_core::Timestamp) {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut s = RecordStore::create(device, wal, 8, 1).expect("create store");
    let txn = TxnId(1);
    s.begin(txn);
    let l_person = s.intern_token(Namespace::Label, "Person").unwrap();
    let l_company = s.intern_token(Namespace::Label, "Company").unwrap();
    let k_age = s.intern_token(Namespace::PropKey, "age").unwrap();
    let k_name = s.intern_token(Namespace::PropKey, "name").unwrap();
    let k_active = s.intern_token(Namespace::PropKey, "active").unwrap();
    for i in 0..n {
        let (id, _) = s.create_node(txn).unwrap();
        s.add_label(txn, id, l_person).unwrap();
        s.set_node_property_value(txn, id, k_age, &Value::Integer(i % 50))
            .unwrap();
        s.set_node_property_value(txn, id, k_name, &Value::String(format!("p{i:04}")))
            .unwrap();
        s.set_node_property_value(txn, id, k_active, &Value::Boolean(i % 3 == 0))
            .unwrap();
    }
    let (c1, _) = s.create_node(txn).unwrap();
    s.add_label(txn, c1, l_company).unwrap();
    s.set_node_property_value(txn, c1, k_age, &Value::Integer(9999))
        .unwrap();
    let (c2, _) = s.create_node(txn).unwrap();
    s.add_label(txn, c2, l_company).unwrap();
    s.commit(txn).unwrap();
    let ts = s.snapshot_ts();
    (s, ts)
}

/// The query matrix exercised by every data variation: unfiltered / filtered / projected / ORDER BY
/// (asc / desc / ties / multi-key) / TopN. Each entry is `(query, top_n)` — `top_n` mirrors the planner's
/// TopN fusion so the direct converge truncates identically.
fn query_matrix() -> Vec<(&'static str, Option<usize>)> {
    vec![
        ("MATCH (n:Person) RETURN n.age AS age", None),
        (
            "MATCH (n:Person) WHERE n.age > 25 RETURN n.age AS age, n.name AS name",
            None,
        ),
        (
            "MATCH (n:Person) WHERE n.active RETURN n.age + 1 AS a",
            None,
        ),
        (
            "MATCH (n:Person) RETURN n.age AS age, n.name AS name ORDER BY n.age, n.name",
            None,
        ),
        (
            "MATCH (n:Person) RETURN n.age AS age, n.name AS name ORDER BY n.age DESC, n.name",
            None,
        ),
        (
            "MATCH (n:Person) WHERE n.age < 10 RETURN n.age AS age, n.name AS name ORDER BY n.age LIMIT 7",
            Some(7),
        ),
    ]
}

/// FRESH data: the full query matrix's morsel converge equals serial (rows in order + marker union),
/// across morsel counts 1/2/8.
#[test]
fn morsel_rows_equals_serial_fresh() {
    let (store, ts) = seed_people(300);
    let coord = Coordinated::new(store);
    for (q, top_n) in query_matrix() {
        assert_morsel_equals_serial(&coord, ts, q, top_n, "fresh");
    }
}

/// OVERWRITTEN data: a later committed transaction overwrites some ages (older versions tombstoned). The
/// morsel converge must see newest-visible values, in serial order, across morsel counts.
#[test]
fn morsel_rows_equals_serial_overwritten() {
    let (mut store, _) = seed_people(300);
    let txn2 = TxnId(2);
    store.begin(txn2);
    let k_age = store
        .token_id(Namespace::PropKey, "age")
        .expect("age token");
    for id in 1..=60u64 {
        store
            .set_node_property_value(txn2, id, k_age, &Value::Integer(1_000 + id as i64))
            .unwrap();
    }
    store.commit(txn2).unwrap();
    let ts = store.snapshot_ts();
    let coord = Coordinated::new(store);
    for (q, top_n) in query_matrix() {
        assert_morsel_equals_serial(&coord, ts, q, top_n, "overwritten");
    }
}

/// DELETED data: a later committed transaction deletes some `:Person` nodes (tombstoned, still indexed).
/// The morsel converge must drop them via per-candidate MVCC re-validation, in serial order.
#[test]
fn morsel_rows_equals_serial_deleted() {
    let (mut store, _) = seed_people(300);
    let txn2 = TxnId(2);
    store.begin(txn2);
    for id in (5..=300u64).step_by(5) {
        store.delete_node(txn2, id).unwrap();
    }
    store.commit(txn2).unwrap();
    let ts = store.snapshot_ts();
    let coord = Coordinated::new(store);
    for (q, top_n) in query_matrix() {
        assert_morsel_equals_serial(&coord, ts, q, top_n, "deleted");
    }
}

/// INSERTED data: a later committed transaction adds new `:Person` nodes (the index is rebuilt from the
/// final store by `Coordinated::new`, so they are candidates). The morsel converge equals serial.
#[test]
fn morsel_rows_equals_serial_inserted() {
    let (mut store, _) = seed_people(250);
    let txn2 = TxnId(2);
    store.begin(txn2);
    let l_person = store
        .token_id(Namespace::Label, "Person")
        .expect("Person token");
    let k_age = store
        .token_id(Namespace::PropKey, "age")
        .expect("age token");
    let k_name = store
        .token_id(Namespace::PropKey, "name")
        .expect("name token");
    for i in 250..320i64 {
        let (id, _) = store.create_node(txn2).unwrap();
        store.add_label(txn2, id, l_person).unwrap();
        store
            .set_node_property_value(txn2, id, k_age, &Value::Integer(i % 50))
            .unwrap();
        store
            .set_node_property_value(txn2, id, k_name, &Value::String(format!("p{i:04}")))
            .unwrap();
    }
    store.commit(txn2).unwrap();
    let ts = store.snapshot_ts();
    let coord = Coordinated::new(store);
    for (q, top_n) in query_matrix() {
        assert_morsel_equals_serial(&coord, ts, q, top_n, "inserted");
    }
}

/// CROSS-SNAPSHOT: at an EARLIER committed snapshot the morsel converge must reproduce the older view
/// (MVCC visibility filters identically on the morsel and serial paths), in serial order.
#[test]
fn morsel_rows_equals_serial_cross_snapshot() {
    let (mut store, ts_early) = seed_people(300);
    let txn2 = TxnId(2);
    store.begin(txn2);
    let k_age = store
        .token_id(Namespace::PropKey, "age")
        .expect("age token");
    for id in (3..=297u64).step_by(3) {
        store.delete_node(txn2, id).unwrap();
    }
    for id in [1u64, 4, 7, 10, 13] {
        store
            .set_node_property_value(txn2, id, k_age, &Value::Integer(-(id as i64)))
            .unwrap();
    }
    store.commit(txn2).unwrap();
    let ts_latest = store.snapshot_ts();
    assert_ne!(ts_early, ts_latest, "the two snapshots must differ");

    let coord = Coordinated::new(store);
    for (q, top_n) in query_matrix() {
        assert_morsel_equals_serial(&coord, ts_early, q, top_n, "cross-snapshot-early");
        assert_morsel_equals_serial(&coord, ts_latest, q, top_n, "cross-snapshot-latest");
    }
}

// =================================================================================================
// Purity gate + RBAC / MemGraph decline.
// =================================================================================================

/// The purity gate accepts pure per-row shapes and rejects impure ones (aggregates / function calls /
/// comprehensions / subqueries). Drives `is_pure_per_row_expr` over parsed projection expressions.
#[test]
fn purity_gate_accepts_pure_rejects_impure() {
    // Pure (accepted): property, arithmetic, comparison, boolean, CASE, list/map literal, label pred.
    for src in [
        "MATCH (n:Person) RETURN n.age",
        "MATCH (n:Person) RETURN n.age + 1 * 2 - 3",
        "MATCH (n:Person) RETURN n.age > 5 AND n.active",
        "MATCH (n:Person) RETURN CASE WHEN n.age > 5 THEN 'a' ELSE 'b' END",
        "MATCH (n:Person) RETURN [n.age, n.age + 1]",
        "MATCH (n:Person) RETURN n.age STARTS WITH 'x'",
        "MATCH (n:Person) RETURN n:Person",
    ] {
        let pieces = plan_pieces(src);
        assert!(
            pieces
                .projection
                .iter()
                .all(|c| is_pure_per_row_expr(&c.expr)),
            "expected `{src}` projection to be PURE per-row"
        );
    }

    // Impure (rejected): a function call (toUpper / size / rand), an aggregate, a comprehension. These are
    // recognized as projections/filters that the gate must reject so the tier declines to serial.
    let impure_exprs = ["toUpper(n.name)", "size(n.name)", "rand()"];
    for e in impure_exprs {
        let src = format!("MATCH (n:Person) RETURN {e} AS x");
        let pieces = plan_pieces(&src);
        assert!(
            pieces
                .projection
                .iter()
                .any(|c| !is_pure_per_row_expr(&c.expr)),
            "expected `{e}` to be REJECTED by the purity gate (function call)"
        );
    }
}

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
/// serial (which RBAC-composes per node); an unrestricted principal forwards the inner bundle. Identical
/// decline behaviour to the Slice-3a aggregate path (the morsel-scan seam is shared).
#[test]
fn restricted_principal_declines_morsel_scan() {
    let (store, ts) = seed_people(200);
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
            "a restricted principal must DECLINE the morsel scan (falls back to serial)"
        );
    }
    {
        let unrestricted = AuthorizedGraph::new(&mut live, FixedOracle { unrestricted: true });
        assert!(
            unrestricted.morsel_label_scan("Person").is_some(),
            "an unrestricted principal must forward the inner morsel scan bundle"
        );
    }
}

/// `MemGraph` has no off-thread read view, so it declines `morsel_label_scan` — the executor always runs
/// serial against it (the library / doctest path stays serial).
#[test]
fn mem_graph_declines_morsel_scan() {
    use graphus_cypher::graph_access::MemGraph;
    let mut g = MemGraph::new();
    for i in 0..10 {
        g.add_node(["Person"], [("age", Value::Integer(i))]);
    }
    assert!(
        g.morsel_label_scan("Person").is_none(),
        "MemGraph must decline the morsel scan (serial path)"
    );
}

// =================================================================================================
// The MEASURED AC bench (Slice 3b): a single ORDER BY top-k query must use > 1 core under the knob.
// =================================================================================================

/// The MEASURED AC bench (`rmp` task #339, Slice 3b): a SINGLE
/// `MATCH (n:Person) WHERE n.age > k RETURN n ORDER BY n.age LIMIT 100` over ~200k `:Person` must use
/// **more than one core** in its READ phase with the morsel knob on, where the serial pipeline uses one.
///
/// The morsel pool is process-global and sized once at first use, so a fair core-count comparison runs
/// **one knob per process invocation** (matching the prompt's `/usr/bin/time -v` mean-cores =
/// (User+Sys)/Wall driver, which runs the binary fresh per knob). The knob + working-set size are read
/// from the environment so an external driver controls them:
///
/// ```text
/// # baseline (≈1.0 core):
/// GRAPHUS_BENCH_MORSEL=1  /usr/bin/time -v cargo test -p graphus-cypher --release \
///     --test morsel_rows measure_morsel_rows_cores -- --ignored --nocapture
/// # parallel (>1 core — the AC):
/// GRAPHUS_BENCH_MORSEL=8  /usr/bin/time -v cargo test -p graphus-cypher --release \
///     --test morsel_rows measure_morsel_rows_cores -- --ignored --nocapture
/// ```
///
/// `mean cores = (User + Sys) / Wall` over the read loop (isolated from the serial preload via
/// `/proc/self/stat` utime+stime). The printed per-iter wall time also shows the speedup directly.
#[test]
#[ignore = "measurement bench — run explicitly with --ignored --nocapture under release (one knob per process)"]
fn measure_morsel_rows_cores() {
    use std::time::Instant;

    let knob: usize = std::env::var("GRAPHUS_BENCH_MORSEL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let people: i64 = std::env::var("GRAPHUS_BENCH_PEOPLE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000);
    let iters: usize = std::env::var("GRAPHUS_BENCH_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);

    graphus_cypher::morsel::set_morsel_threads(knob);

    // Preload (NOT measured for cores: the serial bulk insert + commit on the engine thread).
    let preload_start = Instant::now();
    let mut coord = coord_with_people(people);
    let preload = preload_start.elapsed();

    // The Slice-3b AC query: filtered scan → projection → stable ORDER BY → top-k.
    let q = "MATCH (n:Person) WHERE n.age > 100 RETURN n.age AS age, n.name AS name ORDER BY n.age LIMIT 100";

    // Warm one run (fault pages into the buffer pool), then time the read loop — the phase whose
    // mean-cores is the AC. CPU time is read in ISOLATION via `/proc/self/stat` so the serial preload does
    // not dilute the core count the external `time -v` reports.
    let warm = run_rows(&mut coord, q);
    assert_eq!(
        warm.len(),
        100,
        "the ORDER BY ... LIMIT 100 must return 100 rows"
    );
    let (cpu0, wall0) = (proc_cpu_secs(), Instant::now());
    let mut last_len = 0usize;
    for _ in 0..iters {
        last_len = run_rows(&mut coord, q).len();
    }
    let elapsed = wall0.elapsed();
    let cpu = proc_cpu_secs() - cpu0;
    assert_eq!(last_len, 100, "result must be stable under knob={knob}");

    let read_cores = cpu / elapsed.as_secs_f64();
    println!(
        "morsel-rows knob={knob} people={people}: preload {:.2}s | read {iters} iters in {:?} \
         ({:.2} ms/iter) | READ-PHASE mean cores = {read_cores:.2} (cpu {cpu:.2}s / wall {:.2}s)",
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
