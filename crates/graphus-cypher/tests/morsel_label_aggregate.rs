//! Equivalence guard for the **morsel-driven** parallel label-aggregate read path (`rmp` task #339,
//! Slice 3a — the first slice that makes a single heavy analytical query use more than one core).
//!
//! Slice 3a parallelizes the **read** of a bare `MATCH (n:Label) RETURN <exact-agg>(n.p)`: the seam
//! ([`RecordStoreGraph::morsel_label_scan`]) hands the executor the authoritative candidate-id vector
//! plus an erased, `Send`, cheap-cloneable read surface ([`MorselSource`]); the executor splits the
//! candidates into contiguous morsels read concurrently on a dedicated pool, then folds the survivors'
//! values + converges the per-morsel SIREAD buffers. The whole point is that this is **bit-identical**
//! to reading the same label scan serially.
//!
//! This guard drives the morsel machinery **directly** (so it can use small graphs and exercise an
//! arbitrary number of morsels, independent of the executor's 50k-row engagement gate — which is a
//! perf threshold, not a correctness one) and asserts, for fresh / overwritten / inserted / deleted /
//! cross-snapshot data and across morsel counts 1 / 2 / 8:
//!
//! 1. **value-multiset + count equality** — the morsels' surviving `(value)` multiset and matched-node
//!    count equal the serial `scan_nodes_by_label` + per-node `node_property` over the same snapshot;
//! 2. **SIREAD-marker UNION byte-identity** — the union of the engine-thread coarse markers
//!    ([`morsel_label_scan`] registers `PredicateRead::Label` + the all-live-nodes footprint) and every
//!    per-morsel buffer, in canonical sorted+deduped form, equals the serial scan's full marker set.
//!    This is the load-bearing ACID assertion: moving the scan onto morsels must not change which
//!    markers / rw-edges form (the conflict graph stays the union = the serial set).
//!
//! Plus a focused guard that a restricted RBAC principal **declines** the morsel path (`None`) so it
//! always runs serial, and that the knob (`morsel_threads`) gates the executor tier.

use std::cell::RefCell;
use std::rc::Rc;

use graphus_core::{TxnId, Value};
use graphus_cypher::authorized_graph::{AuthorizedGraph, PrivilegeOracle};
use graphus_cypher::graph_access::GraphAccess;
use graphus_cypher::index_set::IndexSet;
use graphus_cypher::morsel::{MorselLabelScan, MorselReadOutcome};
use graphus_cypher::record_graph::RecordStoreGraph;
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_txn::{LockTable, Snapshot, SsiReadBuffer, SsiTracker};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Live = RecordStoreGraph<MemBlockDevice, MemLogSink>;

/// A fresh store over an in-memory device + log. A small page capacity (8 frames) forces real
/// buffer-pool eviction / reload during the scans — the same `with_page_fetched` cold path the live and
/// morsel routes share, exercising concurrent reads against the shared pool.
fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 8, 1).expect("create store")
}

/// A shared coordinated environment over one `Rc`-shared store: the `ssi` tracker (so reads register
/// SIREAD markers), the lock table, and the populated derived index/column/zone sidecars `attach`
/// requires. Mirrors `tests/read_only_graph_equivalence.rs::Coordinated`.
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
        // Populate the label index from the committed nodes (so `morsel_label_scan` / `scan_nodes_by_
        // label` take the index arm, the coordinated path the morsel seam requires).
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

    /// A coordinated live `RecordStoreGraph` for a read transaction at snapshot `ts`, registered with the
    /// shared SSI tracker — the same shape the coordinator's `statement` builds.
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

/// Splits `scan.candidates` into `morsel_count` contiguous ranges and reads each as a morsel (via the
/// public [`MorselLabelScan::read_morsel`]), returning the outcomes in ascending candidate order. This
/// drives the *same* per-morsel read the executor's tier runs, but with an explicit morsel count so a
/// small fixture can exercise 1 / 2 / 8 morsels deterministically.
fn read_in_morsels(
    scan: &MorselLabelScan,
    property: &str,
    morsel_count: usize,
) -> Vec<MorselReadOutcome> {
    let n = scan.candidates.len();
    if n == 0 {
        return Vec::new();
    }
    let count = morsel_count.max(1).min(n);
    // Even contiguous split; the last morsel absorbs the remainder.
    let base = n / count;
    let mut out = Vec::with_capacity(count);
    let mut lo = 0usize;
    for m in 0..count {
        let hi = if m + 1 == count { n } else { lo + base };
        out.push(scan.read_morsel(lo, hi, property));
        lo = hi;
    }
    out
}

/// The serial reference: read the label scan the way the serial executor path does — `scan_nodes_by_
/// label` (registers `Label` + all-live-nodes predicate markers + per-candidate SIREADs) then
/// `node_property` per surviving node (newest-visible-wins) — and return the surviving value multiset,
/// the matched-node count, and the seam's full SIREAD buffer.
fn serial_reference(
    coord: &Coordinated,
    txn: TxnId,
    ts: graphus_core::Timestamp,
    label: &str,
    property: &str,
) -> (Vec<Value>, usize, SsiReadBuffer) {
    let live = coord.live_at(txn, ts);
    let members = live.scan_nodes_by_label(label);
    let mut values: Vec<Value> = Vec::new();
    for node in &members {
        if let Some(v) = live.node_property(*node, property) {
            values.push(v);
        }
    }
    assert!(!live.has_error(), "serial reference captured an error");
    let buf = live
        .take_read_buffer()
        .expect("coordinated live seam holds a SIREAD buffer");
    (values, members.len(), buf)
}

/// Drives the morsel path for `(label, property)` at snapshot `ts` with `morsel_count` morsels, and
/// returns the surviving value multiset, the matched-node count, and the **union** of all SIREAD markers
/// (the engine-thread coarse footprint from `morsel_label_scan` ∪ every per-morsel buffer).
fn morsel_run(
    coord: &Coordinated,
    txn: TxnId,
    ts: graphus_core::Timestamp,
    label: &str,
    property: &str,
    morsel_count: usize,
) -> (Vec<Value>, usize, SsiReadBuffer) {
    let live = coord.live_at(txn, ts);
    let scan = live
        .morsel_label_scan(label)
        .expect("coordinated seam yields a morsel scan bundle");
    let outcomes = read_in_morsels(&scan, property, morsel_count);
    drop(scan);

    let mut values: Vec<Value> = Vec::new();
    let mut matches = 0usize;
    // The union buffer starts from the engine-thread coarse markers `morsel_label_scan` registered into
    // the live seam (the `Label` predicate + the all-live-nodes footprint), then absorbs every morsel
    // buffer's per-candidate markers — the exact set the executor folds back via `merge_morsel_buffer`.
    let mut union = live
        .take_read_buffer()
        .expect("coordinated live seam holds a SIREAD buffer");
    for o in outcomes {
        assert!(o.error.is_none(), "a morsel captured an error");
        matches += o.label_matches;
        values.extend(o.values);
        // Fold the morsel's markers into the union exactly as `SsiTracker::merge_read_buffer` would
        // replay them (sorted+deduped at the end via `into_sorted_markers`).
        let (_, mkeys, mpreds) = o.buffer.into_sorted_markers();
        for k in mkeys {
            union.record_read(k);
        }
        for p in mpreds {
            union.record_predicate_read(p);
        }
    }
    assert!(!live.has_error(), "the live seam captured an error");
    (values, matches, union)
}

/// A value multiset, canonicalised for order-independent comparison (the morsels concat in ascending
/// candidate order, so the order already matches serial, but compare as a sorted multiset to be robust).
fn multiset(mut values: Vec<Value>) -> Vec<Value> {
    values.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    values
}

/// Asserts the morsel path equals the serial reference for `(label, property)` at `ts`, across morsel
/// counts 1 / 2 / 8: value multiset + matched count, AND the SIREAD-marker UNION (keys + predicates) is
/// byte-identical to the serial scan's marker set.
fn assert_morsel_equals_serial(
    coord: &Coordinated,
    ts: graphus_core::Timestamp,
    label: &str,
    property: &str,
    what: &str,
) {
    let (svals, scount, sbuf) = serial_reference(coord, TxnId(1000), ts, label, property);
    let (s_keys, s_preds) = {
        let m = sbuf.into_sorted_markers();
        (m.1, m.2)
    };
    let svals = multiset(svals);

    for (i, &morsel_count) in [1usize, 2, 8].iter().enumerate() {
        let txn = TxnId(2000 + i as u64);
        let (mvals, mcount, mbuf) = morsel_run(coord, txn, ts, label, property, morsel_count);
        let mvals = multiset(mvals);

        assert_eq!(
            mvals, svals,
            "{what} [{morsel_count} morsels]: value multiset differs from serial"
        );
        assert_eq!(
            mcount, scount,
            "{what} [{morsel_count} morsels]: matched-node count differs from serial"
        );

        // The load-bearing assertion: the marker union == the serial scan's marker set.
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

    // Sanity: the scan actually touched something (else the equality is vacuous). The fixtures all carry
    // live `:Person` nodes, so a scan SIREAD-marks every live node + registers the `Label` predicate.
    assert!(
        !s_keys.is_empty(),
        "{what}: expected non-empty per-candidate SIREAD markers (assertion would be vacuous)"
    );
    assert!(
        !s_preds.is_empty(),
        "{what}: expected non-empty predicate SIREAD markers (assertion would be vacuous)"
    );
}

/// Seeds `n` `(:Person {age: i})` nodes (ages `0..n`), plus two non-`Person` nodes carrying `age` that
/// must never leak into a `:Person` scan. Returns the committed store + its snapshot timestamp.
fn seed_people(n: i64) -> (Store, graphus_core::Timestamp) {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let l_person = s.intern_token(Namespace::Label, "Person").unwrap();
    let l_company = s.intern_token(Namespace::Label, "Company").unwrap();
    let k_age = s.intern_token(Namespace::PropKey, "age").unwrap();
    for i in 0..n {
        let (id, _) = s.create_node(txn).unwrap();
        s.add_label(txn, id, l_person).unwrap();
        s.set_node_property_value(txn, id, k_age, &Value::Integer(i))
            .unwrap();
    }
    // Non-Person nodes carrying `age` (must not count toward a :Person scan).
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

/// FRESH data: a clean committed graph of `:Person {age}` nodes — the morsel read equals serial across
/// morsel counts, values + count + marker union all byte-identical.
#[test]
fn morsel_equals_serial_fresh() {
    let (store, ts) = seed_people(200);
    let coord = Coordinated::new(store);
    assert_morsel_equals_serial(&coord, ts, "Person", "age", "fresh");
}

/// OVERWRITTEN data: some nodes' `age` is overwritten in a later committed transaction (the older
/// versions tombstoned, left un-GC'd). The morsel read must see the newest-visible value, exactly as
/// serial, across morsel counts.
#[test]
fn morsel_equals_serial_overwritten() {
    let (mut store, _) = seed_people(200);
    // Overwrite the age of the first 40 Persons (ids 1..=40) in a second committed transaction.
    let txn2 = TxnId(2);
    store.begin(txn2);
    let k_age = store
        .token_id(Namespace::PropKey, "age")
        .expect("age token");
    for id in 1..=40u64 {
        store
            .set_node_property_value(txn2, id, k_age, &Value::Integer(1_000 + id as i64))
            .unwrap();
    }
    store.commit(txn2).unwrap();
    let ts = store.snapshot_ts();
    let coord = Coordinated::new(store);
    assert_morsel_equals_serial(&coord, ts, "Person", "age", "overwritten");
}

/// INSERTED data: new `:Person` nodes are added in a later committed transaction (not in the original
/// candidate set when the index was first populated — but `Coordinated::new` rebuilds the index from the
/// final committed store, so the candidate set includes them). The morsel read equals serial.
#[test]
fn morsel_equals_serial_inserted() {
    let (mut store, _) = seed_people(150);
    let txn2 = TxnId(2);
    store.begin(txn2);
    let l_person = store
        .token_id(Namespace::Label, "Person")
        .expect("Person token");
    let k_age = store
        .token_id(Namespace::PropKey, "age")
        .expect("age token");
    for i in 150..210i64 {
        let (id, _) = store.create_node(txn2).unwrap();
        store.add_label(txn2, id, l_person).unwrap();
        store
            .set_node_property_value(txn2, id, k_age, &Value::Integer(i))
            .unwrap();
    }
    store.commit(txn2).unwrap();
    let ts = store.snapshot_ts();
    let coord = Coordinated::new(store);
    assert_morsel_equals_serial(&coord, ts, "Person", "age", "inserted");
}

/// DELETED data: some `:Person` nodes are deleted in a later committed transaction (tombstoned, left
/// un-GC'd, but still in the candidate index). The morsel read must drop them via the per-candidate MVCC
/// re-validation, exactly as serial — the index over-broadness is corrected by the visibility re-check.
#[test]
fn morsel_equals_serial_deleted() {
    let (mut store, _) = seed_people(200);
    let txn2 = TxnId(2);
    store.begin(txn2);
    // Delete every 5th Person (ids 5,10,...,200).
    for id in (5..=200u64).step_by(5) {
        store.delete_node(txn2, id).unwrap();
    }
    store.commit(txn2).unwrap();
    let ts = store.snapshot_ts();
    let coord = Coordinated::new(store);
    assert_morsel_equals_serial(&coord, ts, "Person", "age", "deleted");
}

/// CROSS-SNAPSHOT: at an EARLIER committed snapshot (before a later transaction's deletes/overwrites),
/// the morsel read must reproduce the older snapshot's view — MVCC visibility filters identically on the
/// morsel and serial paths.
#[test]
fn morsel_equals_serial_cross_snapshot() {
    let (mut store, ts_early) = seed_people(200);
    // A later transaction deletes + overwrites, advancing the snapshot. The early snapshot must NOT see
    // any of it on either path.
    let txn2 = TxnId(2);
    store.begin(txn2);
    let k_age = store
        .token_id(Namespace::PropKey, "age")
        .expect("age token");
    for id in (3..=198u64).step_by(3) {
        store.delete_node(txn2, id).unwrap();
    }
    // Overwrite the age of a few NON-deleted nodes (ids ≡ 1 mod 3, disjoint from the deletes above).
    for id in [1u64, 4, 7, 10, 13] {
        store
            .set_node_property_value(txn2, id, k_age, &Value::Integer(-(id as i64)))
            .unwrap();
    }
    store.commit(txn2).unwrap();
    let ts_latest = store.snapshot_ts();
    assert_ne!(ts_early, ts_latest, "the two snapshots must differ");

    let coord = Coordinated::new(store);
    // As-of-early: sees the original 200 Persons with original ages (no deletes/overwrites).
    assert_morsel_equals_serial(&coord, ts_early, "Person", "age", "cross-snapshot-early");
    // As-of-latest: sees the deletes + overwrites — both paths agree on the new view too.
    assert_morsel_equals_serial(&coord, ts_latest, "Person", "age", "cross-snapshot-latest");
}

// =================================================================================================
// RBAC decline — a restricted principal must NOT take the morsel path
// =================================================================================================

/// A test oracle that reports a fixed restricted/unrestricted verdict.
struct FixedOracle {
    unrestricted: bool,
}

impl PrivilegeOracle for FixedOracle {
    fn is_unrestricted(&self) -> bool {
        self.unrestricted
    }
    // The remaining grants are irrelevant for this test: the restricted path declines `morsel_label_scan`
    // at `is_unrestricted()` before any per-entity gate. They return `true` so a restricted traversal (if
    // it ran the serial path) would not over-filter — only the morsel-decline behaviour is asserted here.
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
/// the serial path (which RBAC-composes per node); an unrestricted principal forwards the inner bundle.
#[test]
fn restricted_principal_declines_morsel_scan() {
    let (store, ts) = seed_people(200);
    let coord = Coordinated::new(store);
    let mut live = coord.live_at(TxnId(1), ts);

    // Restricted → the decorator must decline (None).
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
    // Unrestricted → the decorator forwards the inner bundle (Some).
    {
        let unrestricted = AuthorizedGraph::new(&mut live, FixedOracle { unrestricted: true });
        assert!(
            unrestricted.morsel_label_scan("Person").is_some(),
            "an unrestricted principal must forward the inner morsel scan bundle"
        );
    }
}

// =================================================================================================
// MemGraph + standalone decline (the non-coordinated paths run serial)
// =================================================================================================

/// `MemGraph` (the in-memory test backend) has no off-thread read view, so it declines `morsel_label_
/// scan` (the trait default `None`) — the executor always runs serial against it (the library / doctest
/// path stays serial).
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
// End-to-end through the executor: the morsel tier (knob > 1) is bit-identical to serial (knob = 1),
// and TCK-identical regardless of the knob.
// =================================================================================================

/// Bulk-seeds `n` committed `:Person {age: i}` nodes directly on the store (fast, no per-node query),
/// then wraps it in a `TxnCoordinator` whose durable statistics report `nodes_with_label("Person") == n`
/// (so the morsel tier's cardinality gate engages above `MORSEL_MIN_ROWS`).
fn coord_with_people(
    n: i64,
) -> graphus_cypher::coordinator::TxnCoordinator<MemBlockDevice, MemLogSink> {
    // A deliberately SMALL pool (64 frames) so the concurrent morsel scan over a much larger node store
    // exercises the concurrent **eviction** path, not just resident-page reads. This is the workload that
    // surfaced the `rmp` #337 lost-pin eviction race (fixed in `graphus-bufpool`, regression
    // `concurrent_eviction.rs` / `loom_eviction_storm.rs`); running the morsel end-to-end test over a
    // small pool guards that the parallel read stays correct under eviction.
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut s = RecordStore::create(device, wal, 64, 1).expect("create store");
    let txn = TxnId(1);
    s.begin(txn);
    let l_person = s.intern_token(Namespace::Label, "Person").unwrap();
    let k_age = s.intern_token(Namespace::PropKey, "age").unwrap();
    for i in 0..n {
        let (id, _) = s.create_node(txn).unwrap();
        s.add_label(txn, id, l_person).unwrap();
        s.set_node_property_value(txn, id, k_age, &Value::Integer(i))
            .unwrap();
    }
    s.commit(txn).unwrap();
    graphus_cypher::coordinator::TxnCoordinator::new(s)
}

/// Runs `src` over the coordinator in a fresh committed read transaction, returning the single row's
/// column `col`. Mirrors `tests/columnar_analytical.rs::read_scalar`.
fn read_scalar(
    coord: &mut graphus_cypher::coordinator::TxnCoordinator<MemBlockDevice, MemLogSink>,
    src: &str,
    col: &str,
) -> Value {
    use graphus_cypher::binding::{Parameters, bind_parameters};
    use graphus_cypher::catalog::IndexCatalog;
    use graphus_cypher::executor::execute;
    use graphus_cypher::lexer::tokenize;
    use graphus_cypher::lower::lower;
    use graphus_cypher::parser::parse_tokens;
    use graphus_cypher::physical::plan_physical;
    use graphus_cypher::semantics::analyze;

    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let plan = plan_physical(
        &lower(&analyze(&ast).expect("analyze")),
        &IndexCatalog::empty(),
    );
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");

    let txn = coord.begin_serializable();
    let value = {
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
        assert_eq!(rows.len(), 1, "an ungrouped aggregation returns one row");
        rows[0].value(col)
    };
    coord.commit(txn).expect("read commits");
    value
}

/// END-TO-END: with the morsel knob enabled (`set_morsel_threads(8)`), a large
/// `MATCH (n:Person) RETURN <exact-agg>(n.age)` driven through the **real executor + coordinator** (so
/// it actually engages the morsel tier — the cardinality gate is satisfied at 60k > 50k) returns the
/// **bit-identical** result to running it with the knob off (`set_morsel_threads(1)`, fully serial).
///
/// Serialized (`#[ignore]`-free but `serial`-guarded by the shared global knob): the knob is a process
/// global, so this test sets it around each phase. It is the small sibling of the `#[ignore]`d 200k
/// mean-cores bench below.
#[test]
fn morsel_tier_end_to_end_matches_serial() {
    // 60k > MORSEL_MIN_ROWS (50k), so the tier's cardinality gate engages.
    let mut coord = coord_with_people(60_000);
    let n: i64 = 60_000;
    let expected_sum = (0..n).sum::<i64>();

    let queries = [
        (
            "MATCH (n:Person) RETURN sum(n.age) AS r",
            "r",
            Value::Integer(expected_sum),
        ),
        (
            "MATCH (n:Person) RETURN count(n.age) AS r",
            "r",
            Value::Integer(n),
        ),
        (
            "MATCH (n:Person) RETURN count(*) AS r",
            "r",
            Value::Integer(n),
        ),
        (
            "MATCH (n:Person) RETURN min(n.age) AS r",
            "r",
            Value::Integer(0),
        ),
        (
            "MATCH (n:Person) RETURN max(n.age) AS r",
            "r",
            Value::Integer(n - 1),
        ),
    ];

    for (q, col, want) in queries {
        // Serial (knob = 1): the morsel tier early-returns; the serial tiers compute the result.
        graphus_cypher::morsel::set_morsel_threads(1);
        let serial = read_scalar(&mut coord, q, col);

        // Morsel (knob = 8): the morsel tier engages (cardinality + shape gates pass).
        graphus_cypher::morsel::set_morsel_threads(8);
        let morsel = read_scalar(&mut coord, q, col);

        assert_eq!(
            serial, morsel,
            "`{q}`: morsel result {morsel:?} must equal serial {serial:?}"
        );
        assert_eq!(morsel, want, "`{q}`: result {morsel:?} must be {want:?}");
    }

    // Reset the global so it does not leak into other tests in this binary.
    graphus_cypher::morsel::set_morsel_threads(1);
}

/// The MEASURED AC bench (`rmp` task #339, Slice 3a): a SINGLE heavy `MATCH (n:Person) RETURN sum(n.age)`
/// over ~200k `:Person` must use **more than one core** with the morsel knob on, where the `rmp` #352
/// fold-parallel tier measured zero gain.
///
/// The morsel pool is process-global and sized once at first use, so a fair core-count comparison runs
/// **one knob per process invocation** (matching the prompt's `/usr/bin/time -v` mean-cores =
/// (User+Sys)/Wall driver, which runs the binary fresh per knob). The knob + the working-set size are
/// read from the environment so the external driver controls them:
///
/// ```text
/// # baseline (≈1.0 core):
/// GRAPHUS_BENCH_MORSEL=1  /usr/bin/time -v cargo test -p graphus-cypher --release \
///     --test morsel_label_aggregate measure_morsel_cores -- --ignored --nocapture
/// # parallel (>1 core — the AC):
/// GRAPHUS_BENCH_MORSEL=16 /usr/bin/time -v cargo test -p graphus-cypher --release \
///     --test morsel_label_aggregate measure_morsel_cores -- --ignored --nocapture
/// ```
///
/// `mean cores = (User + Sys) / Wall` from the `time -v` output (isolating the read loop, which dominates
/// the preload here). The printed per-iter wall time also shows the speedup directly.
#[test]
#[ignore = "measurement bench — run explicitly with --ignored --nocapture under release (one knob per process)"]
fn measure_morsel_cores() {
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

    // Preload phase (NOT measured for cores: it is the serial bulk insert + commit on the engine thread).
    let preload_start = Instant::now();
    let mut coord = coord_with_people(people);
    let preload = preload_start.elapsed();

    let q = "MATCH (n:Person) RETURN sum(n.age) AS r";
    let expected = Value::Integer((0..people).sum::<i64>());

    // Warm one run (fault the pages into the buffer pool), then time the read loop — the phase whose
    // mean-cores is the AC. We measure the read loop's CPU time in ISOLATION (via `/proc/self/stat`
    // utime+stime) so the serial preload does not dilute the core count the external `time -v` reports.
    let _ = read_scalar(&mut coord, q, "r");
    let (cpu0, wall0) = (proc_cpu_secs(), Instant::now());
    let mut last = Value::Null;
    for _ in 0..iters {
        last = read_scalar(&mut coord, q, "r");
    }
    let elapsed = wall0.elapsed();
    let cpu = proc_cpu_secs() - cpu0;
    assert_eq!(last, expected, "sum must be correct under knob={knob}");

    let read_cores = cpu / elapsed.as_secs_f64();
    println!(
        "morsel knob={knob} people={people}: preload {:.2}s | read {iters} iters in {:?} \
         ({:.2} ms/iter) | READ-PHASE mean cores = {read_cores:.2} (cpu {cpu:.2}s / wall {:.2}s)",
        preload.as_secs_f64(),
        elapsed,
        elapsed.as_secs_f64() * 1000.0 / iters as f64,
        elapsed.as_secs_f64(),
    );

    graphus_cypher::morsel::set_morsel_threads(1);
}

/// This process's total CPU time (user + system) in seconds, read from `/proc/self/stat` (Linux). Used
/// by the bench to isolate the READ phase's mean-core utilisation from the serial preload. Returns 0.0
/// off Linux (the bench then reports only wall time).
#[cfg(target_os = "linux")]
fn proc_cpu_secs() -> f64 {
    let ticks_per_sec = 100.0; // _SC_CLK_TCK is 100 on every mainstream Linux; good enough for a bench.
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    // Fields after the (comm) parenthesised name: utime is field 14, stime field 15 (1-based, per
    // proc(5)). Split on the LAST ')' to skip a comm that may contain spaces/parens.
    let after = stat.rsplit_once(')').map(|(_, t)| t).unwrap_or("");
    let fields: Vec<&str> = after.split_whitespace().collect();
    // After ')' the first field is `state` (index 0 == field 3), so utime (field 14) is index 11,
    // stime (field 15) is index 12.
    let utime: f64 = fields.get(11).and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let stime: f64 = fields.get(12).and_then(|s| s.parse().ok()).unwrap_or(0.0);
    (utime + stime) / ticks_per_sec
}

#[cfg(not(target_os = "linux"))]
fn proc_cpu_secs() -> f64 {
    0.0
}
