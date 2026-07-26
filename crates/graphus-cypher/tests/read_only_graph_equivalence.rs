//! Equivalence guard for the off-thread read-only graph (`rmp` task #336, Slice 3b-i — the
//! off-thread-read enabler).
//!
//! Slice 3b-i lifted [`RecordStoreGraph`]'s read path into one shared body
//! ([`graphus_cypher::read_source`]) that both the live seam and the new owned, `Send`
//! [`ReadOnlyGraph`](graphus_cypher::read_only_graph::ReadOnlyGraph) run — the live seam sourcing store
//! data from `Rc<RefCell<RecordStore>>`, the reader from an owned
//! [`StoreReadView`](graphus_storage::StoreReadView) + [`TokenSnapshot`](graphus_storage::TokenSnapshot)
//! captured on the engine thread. The whole point is to prove the reader produces **byte-identical**
//! observable behaviour to the live path — same result, same captured error, **and the same SIREAD
//! markers / rw-edges** — so Slice 3b-ii can move reads off-thread with no change to serializability or
//! visibility.
//!
//! This test populates a multi-store fixture across **multiple committed snapshots** so MVCC visibility
//! actually filters (a row visible as-of-latest is invisible as-of-an-earlier-snapshot), exercising the
//! full `GraphAccess` read surface — nodes / relationships / property chains, a multi-block overflow
//! `String` + a `List`, a multi-label node, a self-loop, MVCC tombstones (a deleted node + rel, an
//! overwritten + a removed property left un-GC'd), a `#220` rolled-back-rel-create corpse, and a
//! same-transaction self-`DELETE` (for `entity_deleted_by_txn` / `rel_data_including_deleted`) — and for
//! **every** `GraphAccess` read method over **every** relevant id, at **two** read snapshots, asserts:
//!
//! 1. **result equality** — `RecordStoreGraph::<m>` and `ReadOnlyGraph::<m>` agree (Some/None, the whole
//!    `Vec` / `Value` contents, key-sorted + label-sorted order, byte-identical);
//! 2. **captured-error `Display` equality** — the first error each seam captured renders identically;
//! 3. **SIREAD-marker byte-identity** — the two seams' accumulated [`SsiReadBuffer`]s, in canonical
//!    sorted+deduped form, are equal. This is the load-bearing ACID assertion: moving reads off-thread
//!    must not change which markers / rw-edges form.
//!
//! The live seam is built coordinated (an `ssi` tracker + a populated label `IndexSet`), so a
//! `MATCH (n:Label)` takes the **index arm** there while the reader takes the **scan-fallback arm** —
//! and the test proves index-arm == scan-fallback (results + markers), exactly the
//! "index-present == index-absent" guarantee the seam promises.

use std::rc::Rc;

use graphus_core::value::temporal::Date;
use graphus_core::{Crs, Point, TxnId, Value};
use graphus_cypher::graph_access::{
    DeletedEntity, ExpandDirection, GraphAccess, NodeId, RelData, RelId, ScannedRel,
};
use graphus_cypher::index_set::IndexSet;
use graphus_cypher::read_only_graph::ReadOnlyGraph;
use graphus_cypher::read_source::rel_ssi_key;
use graphus_cypher::record_graph::RecordStoreGraph;
use graphus_io::MemBlockDevice;
use graphus_storage::{BLOCK_PAYLOAD, IndexState, Namespace, RecordStore};
use graphus_txn::{LockTable, PredicateRead, Snapshot, SsiReadBuffer, SsiTracker};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Live = RecordStoreGraph<MemBlockDevice, MemLogSink>;
type ReadOnly = ReadOnlyGraph<MemBlockDevice, MemLogSink>;

/// A fresh store over an in-memory device + log. Small page capacity (8 frames) deliberately, so the
/// fixture forces real buffer-pool eviction + reload during the scans — the same `with_page_fetched`
/// cold path both read routes share.
fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 8, 1).expect("create store")
}

/// The committed fixture plus the two read snapshots it exposes.
struct Fixture {
    store: Store,
    /// The latest committed snapshot timestamp (sees every commit).
    ts_latest: graphus_core::Timestamp,
    /// An earlier committed snapshot timestamp (sees only transaction 1's commit — so the deletes,
    /// the rolled-back corpse and the later rel are invisible, proving visibility actually filters).
    ts_early: graphus_core::Timestamp,
    /// The `KNOWS` relationship created by the still-in-flight transaction 4, both of whose endpoints
    /// are that writer's own uncommitted nodes. Invisible at both snapshots; the relationship-scan SSI
    /// footprint test uses it to pin *why* the scan's marker set is a proper superset of the walk's.
    inflight_rel: RelId,
}

/// Builds the populated fixture directly on the store (the standalone write path commits each
/// transaction so the data is durable), returning the committed store and the two read snapshots.
///
/// Three committed transactions plus one rolled-back one give two distinct visible snapshots:
/// `ts_early` (after txn 1) sees the full graph as built; `ts_latest` (after txn 2) additionally sees
/// txn 2's deletes. The rolled-back txn 3 leaves a dead-link corpse visible at neither.
fn populated() -> Fixture {
    let mut s = fresh();

    // ---- transaction 1: build the live graph (commit so it is durable, settled state) ----
    let txn = TxnId(1);
    s.begin(txn);

    let k_int = s.intern_token(Namespace::PropKey, "i").unwrap();
    let k_float = s.intern_token(Namespace::PropKey, "f").unwrap();
    let k_bool = s.intern_token(Namespace::PropKey, "b").unwrap();
    let k_str = s.intern_token(Namespace::PropKey, "s").unwrap();
    let k_list = s.intern_token(Namespace::PropKey, "l").unwrap();
    let k_date = s.intern_token(Namespace::PropKey, "d").unwrap();
    let k_point = s.intern_token(Namespace::PropKey, "p").unwrap();
    let k_overwrite = s.intern_token(Namespace::PropKey, "ow").unwrap();
    let k_removed = s.intern_token(Namespace::PropKey, "rm").unwrap();

    let l_person = s.intern_token(Namespace::Label, "Person").unwrap();
    let l_admin = s.intern_token(Namespace::Label, "Admin").unwrap();
    let l_account = s.intern_token(Namespace::Label, "Account").unwrap();
    let t_knows = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let t_owns = s.intern_token(Namespace::RelType, "OWNS").unwrap();

    // Node 1: multi-label, scalars + overflow String/List + a temporal + a point, plus an overwritten
    // property (old versions tombstoned) and a removed property (tombstoned, no live version), both
    // left un-GC'd so the chain carries dead versions.
    let (n1, _) = s.create_node(txn).unwrap();
    s.add_label(txn, n1, l_person).unwrap();
    s.add_label(txn, n1, l_admin).unwrap();
    s.add_label(txn, n1, l_account).unwrap();
    s.set_node_property_value(txn, n1, k_int, &Value::Integer(-42))
        .unwrap();
    s.set_node_property_value(txn, n1, k_float, &Value::Float(2.5))
        .unwrap();
    s.set_node_property_value(txn, n1, k_bool, &Value::Boolean(true))
        .unwrap();
    // A multi-block string (spills into the strings overflow heap).
    let long = "z".repeat(BLOCK_PAYLOAD * 4 + 7);
    s.set_node_property_value(txn, n1, k_str, &Value::String(long))
        .unwrap();
    s.set_node_property_value(
        txn,
        n1,
        k_list,
        &Value::List(vec![
            Value::Integer(1),
            Value::Integer(2),
            Value::Integer(3),
        ]),
    )
    .unwrap();
    s.set_node_property_value(
        txn,
        n1,
        k_date,
        &Value::Date(Date {
            days_since_epoch: -719_528,
        }),
    )
    .unwrap();
    s.set_node_property_value(
        txn,
        n1,
        k_point,
        &Value::Point(Point::new_3d(Crs::Wgs84_3D, 12.5, -7.25, 100.0)),
    )
    .unwrap();
    s.set_node_property_value(txn, n1, k_overwrite, &Value::Integer(1))
        .unwrap();
    s.set_node_property_value(txn, n1, k_overwrite, &Value::Integer(2))
        .unwrap();
    s.set_node_property_value(txn, n1, k_overwrite, &Value::Integer(3))
        .unwrap();
    s.set_node_property_value(txn, n1, k_removed, &Value::String("gone".repeat(40)))
        .unwrap();
    s.remove_node_property_value(txn, n1, k_removed).unwrap();

    // Nodes 2..=4: plain nodes for relationships + a self-loop owner.
    let (n2, _) = s.create_node(txn).unwrap();
    let (n3, _) = s.create_node(txn).unwrap();
    let (n4, _) = s.create_node(txn).unwrap();
    s.add_label(txn, n2, l_person).unwrap();
    s.add_label(txn, n3, l_account).unwrap();
    s.set_node_property_value(txn, n2, k_int, &Value::Integer(7))
        .unwrap();

    // Relationships: a chain on n1, a typed rel with an overflow property, and a self-loop on n4.
    let (r1, _) = s.create_rel(txn, t_knows, n1, n2).unwrap();
    let (_r2, _) = s.create_rel(txn, t_knows, n1, n3).unwrap();
    let (r3, _) = s.create_rel(txn, t_owns, n2, n3).unwrap();
    s.set_rel_property_value(txn, r1, k_int, &Value::Integer(99))
        .unwrap();
    s.set_rel_property_value(txn, r3, k_str, &Value::String("rel-".repeat(50)))
        .unwrap();
    s.set_rel_property_value(txn, r3, k_overwrite, &Value::Integer(10))
        .unwrap();
    s.set_rel_property_value(txn, r3, k_overwrite, &Value::Integer(20))
        .unwrap();
    let (_self_loop, _) = s.create_rel(txn, t_knows, n4, n4).unwrap();

    s.commit(txn).unwrap();
    let ts_early = s.snapshot_ts();

    // ---- transaction 2: MVCC tombstones left un-GC'd (a deleted node + a deleted rel) ----
    let txn2 = TxnId(2);
    s.begin(txn2);
    s.delete_rel(txn2, r3).unwrap();
    let (n5, _) = s.create_node(txn2).unwrap();
    s.add_label(txn2, n5, l_admin).unwrap();
    s.delete_node(txn2, n5).unwrap();
    s.commit(txn2).unwrap();
    let ts_latest = s.snapshot_ts();

    // ---- transaction 3: a ROLLED-BACK rel creation, leaving a dead-link corpse (#220) ----
    let txn3 = TxnId(3);
    s.begin(txn3);
    let (_corpse, _) = s.create_rel(txn3, t_knows, n2, n4).unwrap();
    s.rollback(txn3).unwrap();

    // ---- transaction 4: left IN-FLIGHT, so its records are slot-occupied but invisible ----
    //
    // A `KNOWS` edge whose BOTH endpoints are this writer's own uncommitted nodes. This is the case that
    // separates the two relationship enumerations' SSI footprints (`rmp` task #867): the node-walk only
    // ever reaches an edge through a **visible** endpoint, so it never marks this one, while the
    // whole-store relationship scan marks every slot-occupied matching edge before filtering. Neither
    // route RETURNS it (both apply the same visibility filter), so the divergence is confined to the
    // conflict graph — in the safe, over-marking direction. Without this edge in the fixture, the
    // superset assertion in `relationship_scan_ssi_footprint_is_a_superset_of_the_node_walk` would be
    // vacuously an equality and would not describe the real contract.
    //
    // Deliberately unlabelled, so the label index (and every label-scan assertion) is untouched.
    let txn4 = TxnId(4);
    s.begin(txn4);
    let (inflight_a, _) = s.create_node(txn4).unwrap();
    let (inflight_b, _) = s.create_node(txn4).unwrap();
    let (inflight_rel, _) = s.create_rel(txn4, t_knows, inflight_a, inflight_b).unwrap();
    // NOT committed and NOT rolled back: the transaction stays open for the lifetime of the fixture.

    // Deliberately do NOT run GC: both read routes must face the tombstones, dead versions and corpse.
    Fixture {
        store: s,
        ts_latest,
        ts_early,
        inflight_rel: RelId(inflight_rel),
    }
}

/// Populates a shared label [`IndexSet`] from the committed nodes of `store` (the always-maintained
/// label index, so a coordinated `scan_nodes_by_label` takes the index arm). Mirrors what the
/// coordinator's `rebuild_index` does for the label index: insert every node id under each of its
/// current label tokens. The seek's per-candidate re-check then drops tombstoned / relabelled nodes, so
/// an over-broad candidate set is always correct.
fn populate_label_index(store: &Store, index: &Rc<std::cell::RefCell<IndexSet>>) {
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

/// A shared coordinated environment over one `Rc`-shared store: the `ssi` tracker (so reads register
/// SIREAD markers), the lock table, and the populated derived index/column/zone sidecars `attach`
/// requires. Owning the `Rc<RefCell<Store>>` here is what lets the test build the off-thread
/// `StoreReadView` from the very same store the live seam reads.
struct Coordinated {
    store: Rc<std::cell::RefCell<Store>>,
    ssi: Rc<std::cell::RefCell<SsiTracker>>,
    locks: Rc<std::cell::RefCell<LockTable>>,
    index: Rc<std::cell::RefCell<IndexSet>>,
    columns: Rc<std::cell::RefCell<graphus_cypher::column_cache::ColumnCache>>,
    zones: Rc<std::cell::RefCell<graphus_cypher::zone_map::ZoneMap>>,
}

impl Coordinated {
    fn new(store: Store) -> Self {
        let index = Rc::new(std::cell::RefCell::new(IndexSet::new()));
        populate_label_index(&store, &index);
        Self {
            store: Rc::new(std::cell::RefCell::new(store)),
            ssi: Rc::new(std::cell::RefCell::new(SsiTracker::new())),
            locks: Rc::new(std::cell::RefCell::new(LockTable::new())),
            index,
            columns: Rc::new(std::cell::RefCell::new(
                graphus_cypher::column_cache::ColumnCache::new(),
            )),
            zones: Rc::new(std::cell::RefCell::new(
                graphus_cypher::zone_map::ZoneMap::new(),
            )),
        }
    }

    /// Mints a read transaction at snapshot `ts`, registers it with the SSI tracker (so its reads form
    /// rw-edges from `ts`), and returns a **coordinated** live `RecordStoreGraph` seam for it — the same
    /// shape the coordinator's `statement` builds.
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

    /// Builds an off-thread [`ReadOnlyGraph`] over the **same** store, at the same snapshot `ts`, with a
    /// freshly captured read view + token snapshot + the same cloned commit registry + a fresh empty
    /// SIREAD buffer for `txn`. This is exactly the package Slice 3b-ii will capture on the engine
    /// thread and hand to a reader thread.
    fn reader_at(&self, txn: TxnId, ts: graphus_core::Timestamp) -> ReadOnly {
        let store = self.store.borrow();
        let snapshot = Snapshot { owner: txn, ts };
        ReadOnlyGraph::new(
            store.read_view(),
            store.token_snapshot(),
            snapshot,
            store.commit_registry().clone(),
            txn,
            SsiReadBuffer::new(txn),
        )
    }
}

/// The relationship-type sets swept by every `scan_rels_by_type` assertion (`rmp` task #867): the
/// untyped "any type" case, each fixture type alone, both together, and a type no relationship carries.
const REL_SCAN_TYPE_SETS: [&[&str]; 5] =
    [&[], &["KNOWS"], &["OWNS"], &["KNOWS", "OWNS"], &["NEVER"]];

fn rel_type_set(types: &&[&str]) -> Vec<String> {
    types.iter().map(|t| (*t).to_owned()).collect()
}

/// Asserts two `Option<T: PartialEq>` read results are byte-equal, naming the method+id on failure.
fn eq_opt<T: PartialEq + std::fmt::Debug>(what: &str, live: Option<T>, ro: Option<T>) {
    assert_eq!(
        live, ro,
        "{what}: ReadOnlyGraph result differs from RecordStoreGraph"
    );
}

/// Asserts two `Vec<T: PartialEq>` read results are byte-equal (order included — the seam promises a
/// deterministic order on both routes).
fn eq_vec<T: PartialEq + std::fmt::Debug>(what: &str, live: Vec<T>, ro: Vec<T>) {
    assert_eq!(
        live, ro,
        "{what}: ReadOnlyGraph result differs from RecordStoreGraph"
    );
}

/// Runs every `GraphAccess` read method on both seams over the fixture's id ranges, asserting result
/// equality for each. The id ranges deliberately overrun the live ids (probing tombstones, the corpse,
/// and unallocated holes — each must agree, e.g. both `None`).
fn assert_reads_equal(what_snap: &str, live: &Live, ro: &ReadOnly, node_hi: u64, rel_hi: u64) {
    eq_vec(
        &format!("{what_snap}: scan_nodes"),
        live.scan_nodes(),
        ro.scan_nodes(),
    );
    for label in ["Person", "Admin", "Account", "Ghost"] {
        eq_vec(
            &format!("{what_snap}: scan_nodes_by_label({label})"),
            live.scan_nodes_by_label(label),
            ro.scan_nodes_by_label(label),
        );
    }
    // The whole-store relationship scan (`rmp` task #867) — the access path behind
    // `AllRelationshipsScan`. Off-thread parity is mandatory for every access path (`rmp` #768), and
    // this one is served by the reader from its own read view, so it must agree id-for-id AND
    // marker-for-marker with the inline seam.
    for types in REL_SCAN_TYPE_SETS.iter().map(rel_type_set) {
        eq_opt(
            &format!("{what_snap}: scan_rels_by_type({types:?})"),
            live.scan_rels_by_type(&types),
            ro.scan_rels_by_type(&types),
        );
    }

    for id in 0..=node_hi {
        let n = NodeId(id);
        eq_opt(
            &format!("{what_snap}: node_exists({id})"),
            Some(live.node_exists(n)),
            Some(ro.node_exists(n)),
        );
        eq_opt(
            &format!("{what_snap}: node_labels({id})"),
            live.node_labels(n),
            ro.node_labels(n),
        );
        eq_opt(
            &format!("{what_snap}: node_properties({id})"),
            live.node_properties(n),
            ro.node_properties(n),
        );
        for key in ["i", "f", "b", "s", "l", "d", "p", "ow", "rm", "missing"] {
            eq_opt(
                &format!("{what_snap}: node_property({id}, {key})"),
                live.node_property(n, key),
                ro.node_property(n, key),
            );
        }
        eq_vec(
            &format!("{what_snap}: incident_rels({id})"),
            live.incident_rels(n),
            ro.incident_rels(n),
        );
        for dir in [
            ExpandDirection::Outgoing,
            ExpandDirection::Incoming,
            ExpandDirection::Both,
        ] {
            for types in [
                Vec::new(),
                vec!["KNOWS".to_owned()],
                vec!["OWNS".to_owned()],
                vec!["KNOWS".to_owned(), "OWNS".to_owned()],
                vec!["NEVER".to_owned()],
            ] {
                eq_vec(
                    &format!("{what_snap}: expand({id}, {dir:?}, {types:?})"),
                    live.expand(n, dir, &types),
                    ro.expand(n, dir, &types),
                );
            }
        }
        eq_opt(
            &format!("{what_snap}: entity_deleted_by_txn(Node {id})"),
            Some(live.entity_deleted_by_txn(DeletedEntity::Node(n))),
            Some(ro.entity_deleted_by_txn(DeletedEntity::Node(n))),
        );
    }

    for id in 0..=rel_hi {
        let r = RelId(id);
        eq_opt(
            &format!("{what_snap}: rel_exists({id})"),
            Some(live.rel_exists(r)),
            Some(ro.rel_exists(r)),
        );
        eq_opt::<RelData>(
            &format!("{what_snap}: rel_data({id})"),
            live.rel_data(r),
            ro.rel_data(r),
        );
        eq_opt::<RelData>(
            &format!("{what_snap}: rel_data_including_deleted({id})"),
            live.rel_data_including_deleted(r),
            ro.rel_data_including_deleted(r),
        );
        eq_opt(
            &format!("{what_snap}: rel_properties({id})"),
            live.rel_properties(r),
            ro.rel_properties(r),
        );
        for key in ["i", "s", "ow", "missing"] {
            eq_opt(
                &format!("{what_snap}: rel_property({id}, {key})"),
                live.rel_property(r, key),
                ro.rel_property(r, key),
            );
        }
        eq_opt(
            &format!("{what_snap}: entity_deleted_by_txn(Rel {id})"),
            Some(live.entity_deleted_by_txn(DeletedEntity::Rel(r))),
            Some(ro.entity_deleted_by_txn(DeletedEntity::Rel(r))),
        );
    }
}

/// The canonical sorted+deduped marker form of a buffer, for byte-identity comparison.
fn canonical(buf: SsiReadBuffer) -> (TxnId, Vec<u64>, Vec<PredicateRead>) {
    buf.into_sorted_markers()
}

/// The core guard at one read snapshot: build a coordinated live seam and an off-thread reader over the
/// same store at the same snapshot, run every read on both (asserting result equality), then assert the
/// captured-error `Display` and the canonical SIREAD buffers are byte-identical.
fn assert_seam_equivalence_at(coord: &Coordinated, ts: graphus_core::Timestamp, what_snap: &str) {
    // Distinct reader txn ids so they register independently in the shared tracker (the markers are
    // compared by *content*, under each reader's own id — which equal `into_sorted_markers().0`).
    let live = coord.live_at(TxnId(100), ts);
    let ro = coord.reader_at(TxnId(100), ts);

    // Derive the sweep upper bounds from the store's high-water marks, overrunning the live ids.
    let (node_hw, rel_hw) = {
        let store = coord.store.borrow();
        (store.node_high_water(), store.rel_high_water())
    };
    assert_reads_equal(what_snap, &live, &ro, node_hw + 2, rel_hw + 2);

    // (2) captured-error Display equality (both must be `None` for this clean fixture, but compare the
    // rendered string so a future regression that captures on one route and not the other is caught).
    let live_err = live.take_error().map(|e| e.to_string());
    let ro_err = ro.take_error().map(|e| e.to_string());
    assert_eq!(
        live_err, ro_err,
        "{what_snap}: captured-error Display differs between the seams"
    );

    // (3) SIREAD-marker byte-identity — the load-bearing ACID assertion. Take the live seam's buffer
    // BEFORE it drops (so it is not merged into the shared tracker), and the reader's owned buffer, then
    // compare their canonical sorted+deduped forms. Equal markers ⇒ identical rw-edges ⇒ moving reads
    // off-thread cannot change serializability.
    let live_buf = live
        .take_read_buffer()
        .expect("coordinated live seam holds a SIREAD buffer");
    let ro_buf = ro.take_buffer();
    let (live_reader, live_keys, live_preds) = canonical(live_buf);
    let (ro_reader, ro_keys, ro_preds) = canonical(ro_buf);
    assert_eq!(
        live_reader, ro_reader,
        "{what_snap}: SIREAD buffer reader id differs"
    );
    assert_eq!(
        live_keys, ro_keys,
        "{what_snap}: per-record SIREAD key markers differ (sorted+deduped)"
    );
    assert_eq!(
        live_preds, ro_preds,
        "{what_snap}: predicate SIREAD markers differ (sorted+deduped)"
    );

    // Sanity: the reads must actually have produced markers, else the assertion above is vacuous. The
    // fixture has live nodes/rels, so a full sweep SIREAD-marks many keys and registers predicate
    // markers (AllNodes / Label / AnyRel / RelType).
    assert!(
        !live_keys.is_empty(),
        "{what_snap}: expected non-empty per-record SIREAD markers (assertion would be vacuous)"
    );
    assert!(
        !live_preds.is_empty(),
        "{what_snap}: expected non-empty predicate SIREAD markers (assertion would be vacuous)"
    );
}

/// The whole guard: at the latest snapshot (sees every commit) and an earlier snapshot (sees only
/// transaction 1, so the deletes / corpse / later rel are invisible — MVCC visibility actually
/// filters), the off-thread `ReadOnlyGraph` is byte-identical to the live `RecordStoreGraph` for every
/// read, every captured error, and every SIREAD marker.
#[test]
fn read_only_graph_is_byte_identical_to_record_store_graph() {
    let fx = populated();
    let ts_latest = fx.ts_latest;
    let ts_early = fx.ts_early;
    let coord = Coordinated::new(fx.store);

    assert_seam_equivalence_at(&coord, ts_latest, "as-of-latest");
    assert_seam_equivalence_at(&coord, ts_early, "as-of-early");

    // The two snapshots must genuinely differ (otherwise "multiple committed snapshots" is a no-op):
    // the OWNS rel r3 (id 3) is deleted by txn 2, so it is visible as-of-early but not as-of-latest.
    let early = coord.reader_at(TxnId(200), ts_early);
    let latest = coord.reader_at(TxnId(201), ts_latest);
    assert!(
        early.rel_exists(RelId(3)),
        "the OWNS rel must be visible at the early snapshot"
    );
    assert!(
        !latest.rel_exists(RelId(3)),
        "the OWNS rel must be invisible (tombstoned) at the latest snapshot"
    );
}

/// The **SSI read footprint** of the whole-store relationship scan **contains** that of the
/// `scan_nodes` + `expand` node-walk it replaces (`rmp` task #867) — a superset, never a subset.
///
/// This is the ACID bar the access path has to clear, and it is a *containment*, not an equality.
/// A **narrower** footprint would drop rw-edges the node-walk created and could admit an anomaly SSI
/// used to catch; a **wider** one only adds rw-edges, so at worst it costs a false abort and can never
/// miss a conflict. Serializability is therefore preserved in the safe direction either way, and the
/// assertion is directional to match.
///
/// The scan is genuinely wider, and the fixture makes it so on purpose: the node-walk reaches an edge
/// only through a **visible** endpoint, so a matching edge both of whose endpoints are invisible — the
/// still-in-flight transaction 4's `KNOWS` pair — is marked by the scan and not by the walk. Part (3)
/// below pins exactly that, so the relaxation from equality to containment is itself non-vacuous.
/// Neither route *returns* that edge (both apply the same visibility filter), which is why part (1) can
/// still assert the answers are equal.
///
/// Both routes run on their own live seam over the same store at the same snapshot, so the buffers are
/// directly comparable in canonical sorted+deduped form. The comparison is repeated at two snapshots
/// (visibility genuinely filters at the later one) and for every relationship-type set, including the
/// untyped case and a type no relationship carries.
///
/// # What still holds it down
///
/// Containment is a weaker assertion than equality, so it is paired with the exact-presence checks in
/// part (2b). Together they kill every way the marking can be under-registered — verified by mutation:
/// dropping the `AllNodes` predicate, dropping the per-node SIREADs, dropping the relationship-type
/// predicate, and moving the per-edge SIREAD behind the visibility filter each fail this test.
#[test]
fn relationship_scan_ssi_footprint_is_a_superset_of_the_node_walk() {
    let fx = populated();
    let coord = Coordinated::new(fx.store);
    let mut txn_seq = 300;

    for (what_snap, ts) in [("as-of-latest", fx.ts_latest), ("as-of-early", fx.ts_early)] {
        for types in REL_SCAN_TYPE_SETS.iter().map(rel_type_set) {
            // Route A: the store scan.
            txn_seq += 1;
            let scan_seam = coord.live_at(TxnId(txn_seq), ts);
            let scanned = scan_seam
                .scan_rels_by_type(&types)
                .expect("the live seam serves the relationship scan");
            assert!(scan_seam.take_error().is_none(), "{what_snap}: {types:?}");
            let (_, scan_keys, scan_preds) = canonical(
                scan_seam
                    .take_read_buffer()
                    .expect("coordinated seam holds a SIREAD buffer"),
            );

            // Route B: the node-walk `all_rel_scan` falls back to — every node's OUTGOING incidences,
            // which visits each relationship exactly once (a relationship has one start node) and yields
            // its endpoints without a second read (the anchor IS the start, the neighbour the end).
            txn_seq += 1;
            let walk_seam = coord.live_at(TxnId(txn_seq), ts);
            let mut walked: Vec<ScannedRel> = Vec::new();
            for node in walk_seam.scan_nodes() {
                for inc in walk_seam.expand(node, ExpandDirection::Outgoing, &types) {
                    walked.push(ScannedRel {
                        rel: inc.rel,
                        start: node,
                        end: inc.neighbour,
                    });
                }
            }
            assert!(walk_seam.take_error().is_none(), "{what_snap}: {types:?}");
            let (_, walk_keys, walk_preds) = canonical(
                walk_seam
                    .take_read_buffer()
                    .expect("coordinated seam holds a SIREAD buffer"),
            );

            // (1) Same answer — relationship AND both endpoint ids. Sorted, because the two routes
            // enumerate in different orders (ascending physical id vs grouped by start node), an
            // ordering openCypher leaves unconstrained.
            let mut scanned_sorted = scanned.clone();
            scanned_sorted.sort_unstable();
            walked.sort_unstable();
            assert_eq!(
                scanned_sorted, walked,
                "{what_snap}: scan_rels_by_type({types:?}) returned a different relationship set than the node-walk"
            );

            // (2a) CONTAINMENT — the load-bearing assertion. Every marker the node-walk registers must
            // also be registered by the scan. The converse is deliberately NOT asserted (see the doc):
            // extra markers only add rw-edges, which can over-abort but never miss a conflict.
            //
            // This is what kills an under-registering regression. Dropping the per-node SIREADs, or
            // moving the per-edge SIREAD behind the visibility filter (so a matching-but-invisible edge
            // whose endpoint IS visible — the fixture's tombstoned `OWNS` rel at the latest snapshot —
            // stops being marked), each leave a walk key with no scan counterpart and fail here.
            let missing_keys: Vec<u64> = walk_keys
                .iter()
                .copied()
                .filter(|k| !scan_keys.contains(k))
                .collect();
            assert!(
                missing_keys.is_empty(),
                "{what_snap}: the scan MISSED per-record SIREAD markers the node-walk registered for \
                 {types:?}: {missing_keys:?}\n  scan={scan_keys:?}\n  walk={walk_keys:?}"
            );
            // Dropping the `AllNodes` predicate or the relationship-type predicate each fail here.
            let missing_preds: Vec<&PredicateRead> = walk_preds
                .iter()
                .filter(|p| !scan_preds.contains(p))
                .collect();
            assert!(
                missing_preds.is_empty(),
                "{what_snap}: the scan MISSED predicate SIREAD markers the node-walk registered for \
                 {types:?}: {missing_preds:?}\n  scan={scan_preds:?}\n  walk={walk_preds:?}"
            );

            // (2b) EXACT PRESENCE of the markers the contract names, so containment cannot be satisfied
            // by a scan that simply marks everything and happens to swallow a real regression.
            assert!(
                scan_preds.contains(&PredicateRead::AllNodes),
                "{what_snap}: the scan must register the `AllNodes` predicate for {types:?}: {scan_preds:?}"
            );
            let has_rel_predicate = scan_preds
                .iter()
                .any(|p| matches!(p, PredicateRead::AnyRel | PredicateRead::RelType(_)));
            assert!(
                has_rel_predicate,
                "{what_snap}: the scan must register a relationship-pattern predicate for {types:?}: \
                 {scan_preds:?}"
            );

            // (3) The superset is PROPER, for the documented reason: the still-in-flight transaction's
            // edge — invisible, and with both endpoints invisible too — is marked by the scan and not by
            // the walk. Only for the type sets that cover its `KNOWS` type; a set that excludes it must
            // not mark it either. This is what makes the relaxation from equality to containment
            // meaningful rather than a quietly weakened assertion.
            let inflight_key = rel_ssi_key(fx.inflight_rel.0);
            let covers_knows = types.is_empty() || types.iter().any(|t| t == "KNOWS");
            if covers_knows {
                assert!(
                    scan_keys.contains(&inflight_key),
                    "{what_snap}: the scan must mark the in-flight (invisible) KNOWS edge for {types:?}"
                );
                assert!(
                    !walk_keys.contains(&inflight_key),
                    "{what_snap}: the node-walk must NOT reach the in-flight edge (both endpoints \
                     invisible) for {types:?} — if it does, the fixture no longer exercises the \
                     superset case this test exists to describe"
                );
            } else {
                assert!(
                    !scan_keys.contains(&inflight_key),
                    "{what_snap}: a type set excluding KNOWS must not mark the in-flight edge: {types:?}"
                );
            }

            // (4) Non-vacuity: the fixture must have produced real markers for EVERY type set — even
            // `NEVER`, and even `OWNS` at the latest snapshot (where the fixture's only OWNS rel is
            // tombstoned): a set that matches nothing still registers the node + relationship-type
            // markers, and those are exactly what (2) compares. The row-level non-vacuity is pinned on
            // the untyped sweep, which always matches.
            assert!(
                !scan_keys.is_empty() && !scan_preds.is_empty(),
                "{what_snap}: expected non-empty markers for {types:?} (comparison would be vacuous)"
            );
            if types.is_empty() {
                assert!(
                    !scanned.is_empty(),
                    "{what_snap}: the untyped scan must find relationships, else the row comparison is vacuous"
                );
            }
        }
    }
}

/// A focused guard for the same-transaction self-`DELETE` path: `entity_deleted_by_txn` and
/// `rel_data_including_deleted` must agree between the seams when the reader's own transaction is the
/// one that wrote the tombstone. Because `ReadOnlyGraph` cannot itself write, the self-delete is staged
/// by an UNCOMMITTED writer transaction on the store, and BOTH seams read as that writer's snapshot
/// (owner = the writer) so its in-flight tombstone is "ours".
#[test]
fn self_delete_visibility_is_identical() {
    let mut s = fresh();
    let setup = TxnId(1);
    s.begin(setup);
    let l = s.intern_token(Namespace::Label, "T").unwrap();
    let t = s.intern_token(Namespace::RelType, "R").unwrap();
    let (a, _) = s.create_node(setup).unwrap();
    let (b, _) = s.create_node(setup).unwrap();
    s.add_label(setup, a, l).unwrap();
    let (rel, _) = s.create_rel(setup, t, a, b).unwrap();
    s.commit(setup).unwrap();
    let committed_ts = s.snapshot_ts();

    // An in-flight writer that deletes the node and the rel in its own (uncommitted) transaction — the
    // same-query self-DELETE shape. Its snapshot reads its own tombstones as "deleted by self".
    let writer = TxnId(2);
    s.begin(writer);
    s.delete_rel(writer, rel).unwrap();
    s.delete_node(writer, a).unwrap();

    // Build both seams as the *writer* (owner = writer, snapshot ts = the committed base): the writer's
    // own in-flight tombstones are visible to its self-delete discriminator. The live seam is
    // standalone here (no coordinator needed — this path records no SIREAD markers), and the reader uses
    // the same snapshot + registry.
    let registry = s.commit_registry().clone();
    let view = s.read_view();
    let tokens = s.token_snapshot();
    let live = RecordStoreGraph::begin_at_snapshot(s, writer, committed_ts);
    let ro = ReadOnlyGraph::new(
        view,
        tokens,
        Snapshot {
            owner: writer,
            ts: committed_ts,
        },
        registry,
        writer,
        SsiReadBuffer::new(writer),
    );

    // The node and rel were deleted by `writer` itself → both seams report the self-delete identically.
    let node_a = NodeId(a);
    let rel_id = RelId(rel);
    assert_eq!(
        live.entity_deleted_by_txn(DeletedEntity::Node(node_a)),
        ro.entity_deleted_by_txn(DeletedEntity::Node(node_a)),
    );
    assert!(
        ro.entity_deleted_by_txn(DeletedEntity::Node(node_a)),
        "the reader must see the node as deleted by its own txn"
    );
    assert_eq!(
        live.entity_deleted_by_txn(DeletedEntity::Rel(rel_id)),
        ro.entity_deleted_by_txn(DeletedEntity::Rel(rel_id)),
    );
    // `rel_data_including_deleted` keeps the type readable through the self-delete tombstone on BOTH
    // seams (openCypher `type(r)` after `DELETE r`); plain `rel_data` hides it on both.
    assert_eq!(
        live.rel_data_including_deleted(rel_id),
        ro.rel_data_including_deleted(rel_id),
    );
    assert!(
        ro.rel_data_including_deleted(rel_id).is_some(),
        "type(r) must stay readable through the self-delete tombstone"
    );
    eq_opt::<RelData>(
        "rel_data(self-deleted)",
        live.rel_data(rel_id),
        ro.rel_data(rel_id),
    );
    assert!(
        ro.rel_data(rel_id).is_none(),
        "rel_data must hide the self-deleted rel"
    );
}

/// A focused guard that a write reaching the (statically unreachable) reader path is captured as a
/// degrade error rather than panicking or corrupting — the `ReadOnlyGraph` write capture-degrade
/// contract.
#[test]
fn writes_on_the_reader_path_capture_a_degrade_error() {
    let fx = populated();
    let coord = Coordinated::new(fx.store);
    let mut ro = coord.reader_at(TxnId(300), fx.ts_latest);

    assert!(!ro.has_error(), "a fresh reader has no captured error");
    // Reach a write method directly (the executor never does on a Read txn — this proves the safety net).
    let _ = ro.create_node(&["X".to_owned()], &[("k".to_owned(), Value::Integer(1))]);
    assert!(
        ro.has_error(),
        "a write on the reader path must capture a degrade error"
    );
    let err = ro.take_error().expect("degrade error present");
    assert!(
        err.to_string().contains("read-only reader path"),
        "the degrade error names the read-only reader path: {err}"
    );
}

/// Off-thread **full-text** equivalence (`rmp` task #546): a `db.index.fulltext.queryNodes` served on
/// the off-thread reader — which has no inverted index and recomputes matches from its MVCC snapshot
/// (`read_source::fulltext_scan_fallback`) via the catalogue captured in `ReadTaskInputs.fulltext` —
/// is **byte-identical** to the inline fast index path: same candidate set, same per-candidate score,
/// same "no such index" outcome, AND the same canonical SIREAD markers.
///
/// The live seam takes the **fast index arm** (an `IndexSet` with a populated full-text index, a fresh
/// `effective_ft_spatial_marker`), while the reader takes the **scan-fallback arm** — so this proves
/// index-arm == scan-fallback for full-text, the same "index-present == index-absent" guarantee the
/// seam gives every other read (and the reason moving a full-text procedure off-thread is safe).
#[test]
fn fulltext_query_off_thread_is_byte_identical_to_inline() {
    // A discriminating fixture: four `Person` nodes with a `bio` STRING property (overlapping terms),
    // plus a NON-`Person` node whose bio also contains "graph" — it must be excluded by BOTH routes
    // (the index is label-scoped; the scan fallback filters by label), proving the label scoping.
    let bios = [
        "graph database engineer",
        "rust systems programmer",
        "database and graph theory",
        "marketing lead",
    ];
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let l_person = s.intern_token(Namespace::Label, "Person").unwrap();
    let l_company = s.intern_token(Namespace::Label, "Company").unwrap();
    let k_bio = s.intern_token(Namespace::PropKey, "bio").unwrap();
    let mut person_ids = Vec::new();
    for bio in bios {
        let (n, _) = s.create_node(txn).unwrap();
        s.add_label(txn, n, l_person).unwrap();
        s.set_node_property_value(txn, n, k_bio, &Value::String(bio.to_owned()))
            .unwrap();
        person_ids.push(n);
    }
    let (company, _) = s.create_node(txn).unwrap();
    s.add_label(txn, company, l_company).unwrap();
    s.set_node_property_value(
        txn,
        company,
        k_bio,
        &Value::String("graph analytics company".to_owned()),
    )
    .unwrap();
    s.commit(txn).unwrap();
    let ts = s.snapshot_ts();

    // Coordinated env; register + populate a full-text index over `(Person, bio)` in the shared
    // `IndexSet` so the live seam's fast index path is live. `clear_ft_spatial_dirty` mirrors the
    // coordinator's rebuild path: the populate reflects committed state, not an open transaction, so it
    // must not leak an in-flight-mutator marker (which would force the live seam onto its OWN
    // scan-fallback and make the fast-vs-fallback comparison vacuous).
    let coord = Coordinated::new(s);
    {
        let mut idx = coord.index.borrow_mut();
        idx.register_fulltext(
            "people_bio",
            vec![l_person],
            vec![k_bio],
            graphus_index::fulltext::Analyzer::Standard,
            IndexState::Online,
        );
        for (i, bio) in bios.iter().enumerate() {
            idx.reindex_fulltext_node(person_ids[i], &[l_person], &[(k_bio, (*bio).to_owned())]);
        }
        idx.clear_ft_spatial_dirty();
    }

    // Every search exercises a distinct shape: single-term matches, a multi-term OR, a term ONLY on the
    // excluded non-Person node, a miss, and the empty (all-stop-word) query.
    for search in [
        "graph",
        "database",
        "rust",
        "graph database",
        "analytics",
        "nonexistentterm",
        "",
    ] {
        let live = coord.live_at(TxnId(100), ts);
        let ro = coord
            .reader_at(TxnId(100), ts)
            .with_fulltext(coord.index.borrow().fulltext_snapshot());

        // (1) candidate set: index arm == scan-fallback arm (byte-identical, order included).
        let live_q = live.fulltext_query("people_bio", search);
        let ro_q = ro.fulltext_query("people_bio", search);
        assert_eq!(
            live_q, ro_q,
            "fulltext_query({search:?}): off-thread candidate set differs from inline"
        );

        // (2) per-candidate score: recomputed-from-snapshot == inverted-index score.
        if let Some(cands) = &live_q {
            for &c in cands {
                assert_eq!(
                    live.fulltext_score("people_bio", c, search),
                    ro.fulltext_score("people_bio", c, search),
                    "fulltext_score({search:?}, {c:?}): off-thread score differs from inline"
                );
            }
        }

        // (3) an unknown index name is `None` on BOTH routes (a clear procedure error, not empty rows).
        assert_eq!(
            live.fulltext_query("no_such_index", search),
            ro.fulltext_query("no_such_index", search),
            "fulltext_query on an unknown index must agree (both None)"
        );
        assert!(
            live.fulltext_query("no_such_index", search).is_none(),
            "unknown full-text index must resolve to None"
        );

        // (4) SIREAD markers byte-identical (the load-bearing ACID assertion): the live fast path's
        // `mark_all_live_nodes` dominates its candidate-only markers, and the reader's scan-fallback
        // marks every live node — so both deduped key sets are `{all live node keys}`, and neither
        // records a predicate marker. Take the live buffer BEFORE it drops (unmerged).
        let live_buf = live
            .take_read_buffer()
            .expect("coordinated live seam holds a SIREAD buffer");
        let ro_buf = ro.take_buffer();
        let (live_reader, live_keys, live_preds) = canonical(live_buf);
        let (ro_reader, ro_keys, ro_preds) = canonical(ro_buf);
        assert_eq!(
            live_reader, ro_reader,
            "{search:?}: SIREAD reader id differs"
        );
        assert_eq!(
            live_keys, ro_keys,
            "{search:?}: per-record SIREAD key markers differ (sorted+deduped)"
        );
        assert_eq!(
            live_preds, ro_preds,
            "{search:?}: predicate SIREAD markers differ (sorted+deduped)"
        );
        assert!(
            !live_keys.is_empty(),
            "{search:?}: expected non-empty SIREAD key markers (assertion would be vacuous)"
        );

        // No storage/degrade error on either route.
        assert_eq!(
            live.take_error().map(|e| e.to_string()),
            ro.take_error().map(|e| e.to_string()),
            "{search:?}: captured-error Display differs between the seams"
        );
    }

    // Cross-check the actual match sets are what we expect (so a bug that makes BOTH routes wrong the
    // same way cannot pass): "graph" hits the two Person bios containing it, never the Company node.
    let live = coord.live_at(TxnId(101), ts);
    let graph_hits = live
        .fulltext_query("people_bio", "graph")
        .expect("index exists");
    assert_eq!(
        graph_hits,
        vec![NodeId(person_ids[0]), NodeId(person_ids[2])],
        "\"graph\" must match exactly the two Person bios that contain it (not the Company node)"
    );
}

/// `rmp` task #663: the **relationship** full-text query is byte-identical off-thread vs inline
/// (candidate set, per-candidate score, unknown-index `None`, and — the load-bearing ACID assertion —
/// the SIREAD marker sets), the relationship analogue of
/// `fulltext_query_off_thread_is_byte_identical_to_inline`. The live seam takes the fast inverted-index
/// arm; the reader takes the snapshot-correct relationship scan-fallback arm.
#[test]
fn fulltext_query_rel_off_thread_is_byte_identical_to_inline() {
    let notes = [
        "graph database engineer",
        "rust systems programmer",
        "database and graph theory",
    ];
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let t_knows = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let t_likes = s.intern_token(Namespace::RelType, "LIKES").unwrap();
    let k_note = s.intern_token(Namespace::PropKey, "note").unwrap();
    // A tiny node scaffold to anchor the relationships.
    let mut nodes = Vec::new();
    for _ in 0..(notes.len() + 2) {
        let (n, _) = s.create_node(txn).unwrap();
        nodes.push(n);
    }
    // KNOWS relationships carrying the covered text.
    let mut knows_ids = Vec::new();
    for (i, note) in notes.iter().enumerate() {
        let (r, _) = s.create_rel(txn, t_knows, nodes[i], nodes[i + 1]).unwrap();
        s.set_rel_property_value(txn, r, k_note, &Value::String((*note).to_owned()))
            .unwrap();
        knows_ids.push(r);
    }
    // A LIKES relationship whose note ALSO contains "graph" — must be excluded by BOTH routes (the index
    // is type-scoped; the scan fallback filters by type), proving the type scoping.
    let (likes, _) = s.create_rel(txn, t_likes, nodes[0], nodes[1]).unwrap();
    s.set_rel_property_value(
        txn,
        likes,
        k_note,
        &Value::String("graph excluded by type".to_owned()),
    )
    .unwrap();
    s.commit(txn).unwrap();
    let ts = s.snapshot_ts();

    let coord = Coordinated::new(s);
    {
        let mut idx = coord.index.borrow_mut();
        idx.register_fulltext_rel(
            "knows_notes",
            vec![t_knows],
            vec![k_note],
            graphus_index::fulltext::Analyzer::Standard,
            IndexState::Online,
        );
        for (i, note) in notes.iter().enumerate() {
            idx.reindex_fulltext_rel(knows_ids[i], t_knows, &[(k_note, (*note).to_owned())]);
        }
        idx.clear_ft_spatial_dirty();
    }

    for search in [
        "graph",
        "database",
        "rust",
        "graph database",
        "nonexistentterm",
        "",
    ] {
        let live = coord.live_at(TxnId(100), ts);
        let ro = coord
            .reader_at(TxnId(100), ts)
            .with_fulltext(coord.index.borrow().fulltext_snapshot());

        let live_q = live.fulltext_query_rel("knows_notes", search);
        let ro_q = ro.fulltext_query_rel("knows_notes", search);
        assert_eq!(
            live_q, ro_q,
            "fulltext_query_rel({search:?}): off-thread candidate set differs from inline"
        );

        if let Some(cands) = &live_q {
            for &c in cands {
                assert_eq!(
                    live.fulltext_score_rel("knows_notes", c, search),
                    ro.fulltext_score_rel("knows_notes", c, search),
                    "fulltext_score_rel({search:?}, {c:?}): off-thread score differs from inline"
                );
            }
        }

        // An unknown relationship index name is `None` on BOTH routes.
        assert_eq!(
            live.fulltext_query_rel("no_such_index", search),
            ro.fulltext_query_rel("no_such_index", search),
            "fulltext_query_rel on an unknown index must agree (both None)"
        );
        assert!(live.fulltext_query_rel("no_such_index", search).is_none());

        // SIREAD markers byte-identical: both routes mark every live relationship.
        let live_buf = live
            .take_read_buffer()
            .expect("coordinated live seam holds a SIREAD buffer");
        let ro_buf = ro.take_buffer();
        let (live_reader, live_keys, live_preds) = canonical(live_buf);
        let (ro_reader, ro_keys, ro_preds) = canonical(ro_buf);
        assert_eq!(
            live_reader, ro_reader,
            "{search:?}: SIREAD reader id differs"
        );
        assert_eq!(
            live_keys, ro_keys,
            "{search:?}: per-record SIREAD key markers differ (sorted+deduped)"
        );
        assert_eq!(
            live_preds, ro_preds,
            "{search:?}: predicate SIREAD markers differ (sorted+deduped)"
        );
        assert!(
            !live_keys.is_empty(),
            "{search:?}: expected non-empty SIREAD key markers (assertion would be vacuous)"
        );
        assert_eq!(
            live.take_error().map(|e| e.to_string()),
            ro.take_error().map(|e| e.to_string()),
            "{search:?}: captured-error Display differs between the seams"
        );
    }

    // Cross-check: "graph" matches exactly the two KNOWS relationships whose note contains it (never
    // the LIKES one), ascending by id.
    let live = coord.live_at(TxnId(101), ts);
    let graph_hits = live
        .fulltext_query_rel("knows_notes", "graph")
        .expect("index exists");
    assert_eq!(
        graph_hits,
        vec![RelId(knows_ids[0]), RelId(knows_ids[2])],
        "\"graph\" must match exactly the two KNOWS relationships that contain it"
    );
}

/// The off-thread **index seek** is byte-identical to the inline seek — and to the exact scan — for a
/// reader whose snapshot is STALE relative to the capture (`rmp` task #755, Slice S2).
///
/// # What this pins
///
/// Slice S2 lets an off-thread reader serve `index_seek_eq` from a memo of candidate ids captured on the
/// engine thread at dispatch. That memo is taken at instant `W`, but the reader runs at its own snapshot
/// `T <= W` — so the memo describes a **later** world than the one the reader must report. The claim that
/// makes this sound is that the memo is a **superset** of the reader's true matches, never a subset,
/// because the node-property index is append-only per entry (`insert_node_property` is its only
/// per-entry mutation; there is no `remove_node_property`).
///
/// This fixture attacks that claim from **both** sides at once. Between the reader's snapshot `ts_stale`
/// and the capture, a committed writer:
///
/// * **moves** `p0` off the sought value (`a@x.io` → `zz@x.io`) — leaving a **stale** index entry
///   `(a@x.io → p0)` behind. The stale reader MUST still return `p0` (it is genuinely `a@x.io` at
///   `ts_stale`). Were the index to remove entries on update, the memo would be a SUBSET here and `p0`
///   would silently vanish — the exact row-loss this design turns on; and
/// * **creates** `p_new` holding the sought value `a@x.io` — a **fresh** entry the memo contains but the
///   stale reader must NOT return (invisible at `ts_stale`). This proves the extras are filtered.
///
/// So the memo for `a@x.io` at capture time is `{p0, p_new}`, while the truth at `ts_stale` is `{p0}` —
/// a strict superset in one direction and a strict subset of the memo in the other. Only a correct
/// per-candidate MVCC re-check turns one into the other.
///
/// Three-way equality is asserted at both snapshots: **off-thread seek == off-thread scan == inline
/// seek**. The scan arm is the independent oracle (it never consults an index), so agreement cannot be
/// an artifact of the seek paths sharing a bug.
#[test]
fn off_thread_index_seek_equals_inline_seek_and_scan_across_snapshots() {
    let mut s = fresh();

    // --- t1: four Person nodes; `p0` holds the value we will seek. -------------------------------
    let txn1 = TxnId(1);
    s.begin(txn1);
    let l_person = s.intern_token(Namespace::Label, "Person").unwrap();
    let k_email = s.intern_token(Namespace::PropKey, "email").unwrap();
    let emails = ["a@x.io", "b@x.io", "c@x.io", "d@x.io"];
    let mut ids = Vec::new();
    for email in emails {
        let (n, _) = s.create_node(txn1).unwrap();
        s.add_label(txn1, n, l_person).unwrap();
        s.set_node_property_value(txn1, n, k_email, &Value::String((*email).to_owned()))
            .unwrap();
        ids.push(n);
    }
    s.commit(txn1).unwrap();
    let ts_stale = s.snapshot_ts();

    let coord = Coordinated::new(s);
    {
        // An `Online` node-property index over `(Person, email)`, populated from committed state —
        // exactly what the coordinator's build leaves behind.
        let mut idx = coord.index.borrow_mut();
        idx.register_node_property_with_state(l_person, k_email, IndexState::Online);
        for (i, email) in emails.iter().enumerate() {
            idx.insert_node_property(
                l_person,
                k_email,
                &Value::String((*email).to_owned()),
                ids[i],
            );
        }
    }

    // --- t2: the concurrent writer commits AFTER the stale snapshot. -----------------------------
    let p_new = {
        let mut store = coord.store.borrow_mut();
        let txn2 = TxnId(2);
        store.begin(txn2);
        // (a) move `p0` OFF the sought value: the `(a@x.io → p0)` index entry becomes stale but REMAINS.
        store
            .set_node_property_value(txn2, ids[0], k_email, &Value::String("zz@x.io".to_owned()))
            .unwrap();
        // (b) a NEW node that takes the sought value.
        let (n, _) = store.create_node(txn2).unwrap();
        store.add_label(txn2, n, l_person).unwrap();
        store
            .set_node_property_value(txn2, n, k_email, &Value::String("a@x.io".to_owned()))
            .unwrap();
        store.commit(txn2).unwrap();
        n
    };
    {
        // The writer's index maintenance: append the two new entries (`reindex_node` never removes).
        let mut idx = coord.index.borrow_mut();
        idx.insert_node_property(
            l_person,
            k_email,
            &Value::String("zz@x.io".to_owned()),
            ids[0],
        );
        idx.insert_node_property(
            l_person,
            k_email,
            &Value::String("a@x.io".to_owned()),
            p_new,
        );
    }
    let ts_fresh = coord.store.borrow().snapshot_ts();

    // The memo the engine thread would hand a reader at snapshot `ts` — captured at `W`, strictly after
    // the writer committed, for BOTH snapshots below. This fixture drives no rebuild, so the rebuild gate
    // (`rebuilt_trees_trustworthy_from`) sits at its `0` default and admits every reader — which is what
    // keeps this test about the MVCC re-check. The gate is pinned separately by
    // `rebuild_gate_declines_the_capture_for_an_older_snapshot` (tests/index_wiring.rs).
    let capture = |ts: graphus_core::Timestamp, v: &str| {
        coord
            .index
            .borrow_mut()
            .capture_node_property_eq(ts, &[(l_person, k_email, Value::String(v.to_owned()))])
    };

    // Pin the premise this design rests on: the memo really is a superset containing BOTH the stale and
    // the fresh id. If this ever fails, the index stopped being append-only and S2 is unsound.
    {
        let memo = capture(ts_fresh, "a@x.io");
        let cands = memo
            .get(l_person, k_email, &Value::String("a@x.io".to_owned()))
            .expect("the seek must be captured");
        let mut got: Vec<u64> = cands.to_vec();
        got.sort_unstable();
        got.dedup();
        assert!(
            got.contains(&ids[0]) && got.contains(&p_new),
            "the capture must be a SUPERSET holding both the stale entry (p0={}) and the fresh one \
             (p_new={p_new}): {got:?}. A missing p0 means the index removed an entry on update, which \
             would make an off-thread seek lose rows for a stale reader.",
            ids[0]
        );
    }

    // --- the three-way equality, at the stale and the fresh snapshot. ----------------------------
    for (what, ts, txn) in [
        ("stale snapshot", ts_stale, TxnId(100)),
        ("fresh snapshot", ts_fresh, TxnId(101)),
    ] {
        for probe in ["a@x.io", "zz@x.io", "b@x.io", "nobody@x.io"] {
            let seek = Value::String(probe.to_owned());

            let live = coord.live_at(txn, ts);
            let inline = live
                .index_seek_eq("Person", "email", &seek)
                .expect("the inline seam has an Online index: it must serve the seek");

            let ro = coord
                .reader_at(txn, ts)
                .with_index_candidates(capture(ts, probe));
            let off_thread = ro
                .index_seek_eq("Person", "email", &seek)
                .expect("the reader has a captured memo: it must serve the seek");

            // The independent oracle: a full scan, which consults no index at all.
            let scan = coord
                .reader_at(txn, ts)
                .scan_filter_eq("Person", "email", &seek)
                .matched;
            let mut scan_sorted = scan;
            scan_sorted.sort_unstable();

            assert_eq!(
                off_thread, inline,
                "{what}, {probe:?}: the off-thread seek disagrees with the inline seek"
            );
            assert_eq!(
                off_thread, scan_sorted,
                "{what}, {probe:?}: the off-thread seek disagrees with the exact scan (the oracle)"
            );
            assert!(
                !ro.has_error(),
                "{what}, {probe:?}: reader captured an error"
            );
        }
    }

    // The headline case, stated explicitly so a regression names itself: at the stale snapshot the
    // sought value must resolve to the node that has since moved off it — and to nothing else.
    let ro = coord
        .reader_at(TxnId(200), ts_stale)
        .with_index_candidates(capture(ts_stale, "a@x.io"));
    assert_eq!(
        ro.index_seek_eq("Person", "email", &Value::String("a@x.io".to_owned())),
        Some(vec![NodeId(ids[0])]),
        "the stale reader must see p0 (still `a@x.io` at its snapshot) and NOT the later p_new"
    );
}

/// `rmp` task #768: a node **RANGE**, **COMPOSITE**, and **TEXT** seek is byte-identical off-thread vs
/// inline — both the **rows** and the **canonical SIREAD buffer** — the way `rmp` #755 pinned the
/// equality seek. Both routes run the SAME lifted re-check body (`index_seek_range_recheck` /
/// `index_seek_composite_recheck` / `index_seek_text_recheck`); the engine thread contributes only the
/// candidate ids (from the live index inline, from the `IndexCandidateCapture` off-thread). This measures
/// the identity that body guarantees — the load-bearing ACID assertion that moving these seeks off-thread
/// changes neither the answer nor the serializability footprint.
///
/// Non-vacuity is built in three ways: the inline seek must return `Some` (an `Online` index really
/// serves it), the off-thread seek must return `Some` (the memo really serves it — a decline would be
/// `None`, failing the `expect`), and the SIREAD buffers must be **non-empty** (a range/composite/text
/// seek `mark_all_live_nodes`, so the buffers carry every live node key).
#[test]
fn off_thread_range_composite_text_seeks_equal_inline_rows_and_ssi_footprint() {
    use graphus_cypher::physical::TextSeekOp;

    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let l_person = s.intern_token(Namespace::Label, "Person").unwrap();
    let l_company = s.intern_token(Namespace::Label, "Company").unwrap();
    let k_age = s.intern_token(Namespace::PropKey, "age").unwrap();
    let k_dept = s.intern_token(Namespace::PropKey, "dept").unwrap();
    let k_team = s.intern_token(Namespace::PropKey, "team").unwrap();
    let k_bio = s.intern_token(Namespace::PropKey, "bio").unwrap();

    // Eight People with a unique (dept, team) pair, an int age = index, and a distinct bio.
    let mut ids = Vec::new();
    for i in 0..8u64 {
        let (n, _) = s.create_node(txn).unwrap();
        s.add_label(txn, n, l_person).unwrap();
        s.set_node_property_value(txn, n, k_age, &Value::Integer(i as i64))
            .unwrap();
        s.set_node_property_value(txn, n, k_dept, &Value::String(format!("D{i}")))
            .unwrap();
        s.set_node_property_value(txn, n, k_team, &Value::String(format!("T{i}")))
            .unwrap();
        s.set_node_property_value(txn, n, k_bio, &Value::String(format!("bio{i}end")))
            .unwrap();
        ids.push(n);
    }
    // A Company that shares the same property values as a Person — it must be excluded by BOTH routes on
    // the label re-check (so a bug that ignores the label cannot pass by matching on value alone).
    let (company, _) = s.create_node(txn).unwrap();
    s.add_label(txn, company, l_company).unwrap();
    s.set_node_property_value(txn, company, k_age, &Value::Integer(7))
        .unwrap();
    s.set_node_property_value(txn, company, k_dept, &Value::String("D3".to_owned()))
        .unwrap();
    s.set_node_property_value(txn, company, k_team, &Value::String("T3".to_owned()))
        .unwrap();
    s.set_node_property_value(txn, company, k_bio, &Value::String("bio3end".to_owned()))
        .unwrap();
    s.commit(txn).unwrap();
    let ts = s.snapshot_ts();

    // Register + populate all three indexes over committed state, exactly what the coordinator's build
    // leaves behind. The fixture drives no rebuild, so the node-property rebuild watermark and the
    // ft/spatial marker both sit at their defaults and admit this reader (the watermark gates are pinned
    // separately in tests/index_wiring.rs).
    let coord = Coordinated::new(s);
    {
        let mut idx = coord.index.borrow_mut();
        idx.register_node_property_with_state(l_person, k_age, IndexState::Online);
        idx.register_composite(l_person, vec![k_dept, k_team]);
        idx.register_text(l_person, k_bio, IndexState::Online);
        for (i, &id) in ids.iter().enumerate() {
            idx.insert_node_property(l_person, k_age, &Value::Integer(i as i64), id);
            idx.insert_composite(
                l_person,
                &[k_dept, k_team],
                &[
                    Value::String(format!("D{i}")),
                    Value::String(format!("T{i}")),
                ],
                id,
            );
            idx.insert_text_value(l_person, k_bio, &Value::String(format!("bio{i}end")), id);
        }
        // The populate reflects committed state, not an open transaction; clear the in-flight ft/spatial
        // marker so the live text seam takes its fast index arm (else the comparison would be vacuous).
        idx.clear_ft_spatial_dirty();
    }

    // A helper: run one seek on the inline seam and on an off-thread reader fed the engine-captured memo,
    // assert the ROWS are equal (and hold `expected`), then assert the canonical SIREAD buffers are
    // byte-identical and non-empty. `run` performs the seek on a `&dyn GraphAccess`-shaped closure.
    let compare = |what: &str,
                   capture: graphus_cypher::read_source::IndexCandidateCapture,
                   inline_seek: &dyn Fn(&Live) -> Option<Vec<NodeId>>,
                   reader_seek: &dyn Fn(&ReadOnly) -> Option<Vec<NodeId>>,
                   expected_subset: &[NodeId]| {
        let live = coord.live_at(TxnId(100), ts);
        let inline = inline_seek(&live).unwrap_or_else(|| {
            panic!("{what}: the inline seam has an Online index — it must seek")
        });

        let ro = coord
            .reader_at(TxnId(100), ts)
            .with_index_candidates(capture);
        let off_thread = reader_seek(&ro)
            .unwrap_or_else(|| panic!("{what}: the reader has a captured memo — it must seek"));

        assert_eq!(
            off_thread, inline,
            "{what}: the off-thread seek rows disagree with the inline seek"
        );
        for id in expected_subset {
            assert!(
                off_thread.contains(id),
                "{what}: the seek must contain {id:?} (rows={off_thread:?})"
            );
        }
        assert!(
            !off_thread.contains(&NodeId(company)),
            "{what}: the Company node must be excluded by the label re-check (rows={off_thread:?})"
        );

        // The load-bearing ACID assertion: byte-identical SIREAD footprint. Take the live buffer BEFORE
        // it drops (unmerged), and the reader's owned buffer, then compare canonical sorted+deduped forms.
        let live_buf = live
            .take_read_buffer()
            .expect("coordinated live seam holds a SIREAD buffer");
        let ro_buf = ro.take_buffer();
        let (lr, lk, lp) = canonical(live_buf);
        let (rr, rk, rp) = canonical(ro_buf);
        assert_eq!(lr, rr, "{what}: SIREAD reader id differs");
        assert_eq!(
            lk, rk,
            "{what}: per-record SIREAD key markers differ (sorted+deduped)"
        );
        assert_eq!(
            lp, rp,
            "{what}: predicate SIREAD markers differ (sorted+deduped)"
        );
        assert!(
            !lk.is_empty(),
            "{what}: expected non-empty SIREAD key markers (mark_all_live_nodes) — assertion vacuous otherwise"
        );
        assert!(!ro.has_error(), "{what}: reader captured an error");
    };

    // Each capture is hoisted into a `let` so the engine index's `borrow_mut()` guard is released before
    // `compare` runs — inside `compare` the inline seam borrows the same `Rc<RefCell<IndexSet>>`.

    // RANGE: `age >= 4` → the top four People (ids 4..=7), never the Company.
    let range_cap = coord.index.borrow_mut().capture_node_property_range(
        ts,
        &[(l_person, k_age, Some((Value::Integer(4), true)), None)],
    );
    compare(
        "range age>=4",
        range_cap,
        &|live: &Live| {
            live.index_seek_range("Person", "age", Some((&Value::Integer(4), true)), None)
        },
        &|ro: &ReadOnly| {
            ro.index_seek_range("Person", "age", Some((&Value::Integer(4), true)), None)
        },
        &[
            NodeId(ids[4]),
            NodeId(ids[5]),
            NodeId(ids[6]),
            NodeId(ids[7]),
        ],
    );

    // COMPOSITE: `{dept:'D3', team:'T3'}` → exactly Person 3, never the same-valued Company.
    let comp_props = ["dept".to_owned(), "team".to_owned()];
    let comp_vals = [
        Value::String("D3".to_owned()),
        Value::String("T3".to_owned()),
    ];
    let composite_cap = coord.index.borrow_mut().capture_node_property_composite(
        ts,
        &[(l_person, vec![k_dept, k_team], comp_vals.to_vec())],
    );
    compare(
        "composite (D3,T3)",
        composite_cap,
        &|live: &Live| live.index_seek_composite_eq("Person", &comp_props, &comp_vals),
        &|ro: &ReadOnly| ro.index_seek_composite_eq("Person", &comp_props, &comp_vals),
        &[NodeId(ids[3])],
    );

    // TEXT: `CONTAINS 'o3e'` → the trigram candidate superset (Person 3's `bio3end` matches); the residual
    // filter above the operator restores exactness in the executor, so here we only require the true match
    // is present and the two routes agree exactly.
    let text_cap = coord.index.borrow_mut().capture_node_property_text(
        ts,
        &[(l_person, k_bio, TextSeekOp::Contains, "o3e".to_owned())],
    );
    compare(
        "text CONTAINS o3e",
        text_cap,
        &|live: &Live| live.index_seek_text("Person", "bio", TextSeekOp::Contains, "o3e"),
        &|ro: &ReadOnly| ro.index_seek_text("Person", "bio", TextSeekOp::Contains, "o3e"),
        &[NodeId(ids[3])],
    );
}

/// `rmp` task #769: a RELATIONSHIP **eq**, **range**, and **composite** seek is byte-identical off-thread
/// vs inline — both the **rows** and the **canonical SIREAD buffer** — the relationship twin of
/// `off_thread_range_composite_text_seeks_equal_inline_rows_and_ssi_footprint`. Both routes run the SAME
/// lifted per-candidate re-check body (`rel_index_seek_eq_recheck` / `_range_recheck` / `_composite_recheck`),
/// which is what backs the `rmp` #683 uniqueness path, so this pins the load-bearing ACID guarantee that
/// moving these seeks off-thread changes neither the answer nor the serializability footprint.
///
/// Non-vacuity: the inline seek must return `Some`, the off-thread seek must return `Some` (a decline
/// would be `None`), and — for eq — the SIREAD buffer carries the precise `RelEquality` predicate marker
/// (for range/composite the blanket `mark_all_live_rels` fills the key set).
#[test]
fn off_thread_rel_seeks_equal_inline_rows_and_ssi_footprint() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let t_likes = s.intern_token(Namespace::RelType, "LIKES").unwrap();
    let t_knows = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let k_n = s.intern_token(Namespace::PropKey, "n").unwrap();
    let k_acct = s.intern_token(Namespace::PropKey, "acct").unwrap();
    let k_cur = s.intern_token(Namespace::PropKey, "cur").unwrap();

    // A node scaffold, then 8 LIKES rels with a unique n / (acct, cur), plus one KNOWS rel sharing the
    // same values — it must be excluded by BOTH routes on the type re-check (a bug that ignores the type
    // cannot pass by matching on value alone).
    let mut nodes = Vec::new();
    for _ in 0..9 {
        let (n, _) = s.create_node(txn).unwrap();
        nodes.push(n);
    }
    let mut ids = Vec::new();
    for i in 0..8u64 {
        let (r, _) = s
            .create_rel(txn, t_likes, nodes[i as usize], nodes[i as usize + 1])
            .unwrap();
        s.set_rel_property_value(txn, r, k_n, &Value::Integer(i as i64))
            .unwrap();
        s.set_rel_property_value(txn, r, k_acct, &Value::String(format!("A{i}")))
            .unwrap();
        s.set_rel_property_value(txn, r, k_cur, &Value::String(format!("C{i}")))
            .unwrap();
        ids.push(r);
    }
    let (knows, _) = s.create_rel(txn, t_knows, nodes[0], nodes[1]).unwrap();
    s.set_rel_property_value(txn, knows, k_n, &Value::Integer(3))
        .unwrap();
    s.set_rel_property_value(txn, knows, k_acct, &Value::String("A3".to_owned()))
        .unwrap();
    s.set_rel_property_value(txn, knows, k_cur, &Value::String("C3".to_owned()))
        .unwrap();
    s.commit(txn).unwrap();
    let ts = s.snapshot_ts();

    // Register + populate the rel-property (n) and rel-composite (acct, cur) indexes over committed state.
    let coord = Coordinated::new(s);
    {
        let mut idx = coord.index.borrow_mut();
        idx.register_rel_property_with_state(t_likes, k_n, IndexState::Online);
        idx.register_rel_composite(t_likes, vec![k_acct, k_cur]);
        for (i, &r) in ids.iter().enumerate() {
            idx.insert_rel_property(t_likes, k_n, &Value::Integer(i as i64), r);
            idx.insert_rel_composite(
                t_likes,
                &[k_acct, k_cur],
                &[
                    Value::String(format!("A{i}")),
                    Value::String(format!("C{i}")),
                ],
                r,
            );
        }
    }

    // Compare one rel seek on the inline seam and an off-thread reader fed the engine-captured memo:
    // rows equal (and hold `expected`, exclude the KNOWS rel), then canonical SIREAD buffers byte-equal.
    let compare = |what: &str,
                   capture: graphus_cypher::read_source::IndexCandidateCapture,
                   inline_seek: &dyn Fn(&Live) -> Option<Vec<RelId>>,
                   reader_seek: &dyn Fn(&ReadOnly) -> Option<Vec<RelId>>,
                   expected: &[RelId]| {
        let live = coord.live_at(TxnId(100), ts);
        let inline = inline_seek(&live).unwrap_or_else(|| {
            panic!("{what}: the inline seam has an Online index — it must seek")
        });

        let ro = coord
            .reader_at(TxnId(100), ts)
            .with_index_candidates(capture);
        let off_thread = reader_seek(&ro)
            .unwrap_or_else(|| panic!("{what}: the reader has a captured memo — it must seek"));

        assert_eq!(
            off_thread, inline,
            "{what}: off-thread rel seek rows disagree with inline"
        );
        assert_eq!(
            off_thread, expected,
            "{what}: rel seek rows are not the expected set"
        );
        assert!(
            !off_thread.contains(&RelId(knows)),
            "{what}: the KNOWS rel must be excluded by the type re-check (rows={off_thread:?})"
        );

        let live_buf = live
            .take_read_buffer()
            .expect("coordinated live seam holds a SIREAD buffer");
        let ro_buf = ro.take_buffer();
        let (lr, lk, lp) = canonical(live_buf);
        let (rr, rk, rp) = canonical(ro_buf);
        assert_eq!(lr, rr, "{what}: SIREAD reader id differs");
        assert_eq!(
            lk, rk,
            "{what}: per-record SIREAD key markers differ (sorted+deduped)"
        );
        assert_eq!(
            lp, rp,
            "{what}: predicate SIREAD markers differ (sorted+deduped)"
        );
        assert!(
            !lk.is_empty(),
            "{what}: expected non-empty SIREAD key markers — assertion vacuous otherwise"
        );
        assert!(!ro.has_error(), "{what}: reader captured an error");
    };

    // REL EQ: `n == 3` → exactly LIKES rel 3, never the KNOWS rel.
    let eq_cap = coord
        .index
        .borrow_mut()
        .capture_rel_property_eq(ts, &[(t_likes, k_n, Value::Integer(3))]);
    compare(
        "rel eq n=3",
        eq_cap,
        &|live: &Live| live.index_seek_rel_eq("LIKES", "n", &Value::Integer(3)),
        &|ro: &ReadOnly| ro.index_seek_rel_eq("LIKES", "n", &Value::Integer(3)),
        &[RelId(ids[3])],
    );

    // REL RANGE (#680): `n >= 5` → LIKES rels 5,6,7.
    let range_cap = coord
        .index
        .borrow_mut()
        .capture_rel_property_range(ts, &[(t_likes, k_n, Some((Value::Integer(5), true)), None)]);
    compare(
        "rel range n>=5",
        range_cap,
        &|live: &Live| {
            live.index_seek_rel_range("LIKES", "n", Some((&Value::Integer(5), true)), None)
        },
        &|ro: &ReadOnly| {
            ro.index_seek_rel_range("LIKES", "n", Some((&Value::Integer(5), true)), None)
        },
        &[RelId(ids[5]), RelId(ids[6]), RelId(ids[7])],
    );

    // REL COMPOSITE (#666): `{acct:'A3', cur:'C3'}` → exactly LIKES rel 3, never the same-valued KNOWS rel.
    let comp_props = ["acct".to_owned(), "cur".to_owned()];
    let comp_vals = [
        Value::String("A3".to_owned()),
        Value::String("C3".to_owned()),
    ];
    let comp_cap = coord
        .index
        .borrow_mut()
        .capture_rel_composite(ts, &[(t_likes, vec![k_acct, k_cur], comp_vals.to_vec())]);
    compare(
        "rel composite (A3,C3)",
        comp_cap,
        &|live: &Live| live.index_seek_rel_composite_eq("LIKES", &comp_props, &comp_vals),
        &|ro: &ReadOnly| ro.index_seek_rel_composite_eq("LIKES", &comp_props, &comp_vals),
        &[RelId(ids[3])],
    );
}

/// `rmp` task #770: a NODE and a RELATIONSHIP **spatial (point)** seek is byte-identical off-thread vs
/// inline — both the **rows** and the **canonical SIREAD buffer** — the spatial twin of
/// `off_thread_range_composite_text_seeks_equal_inline_rows_and_ssi_footprint`. Both routes run the SAME
/// lifted body (`index_seek_spatial_recheck` / `rel_index_seek_spatial_recheck`), so this proves the
/// off-thread reader serves the grid seek from the dispatch-time memo with an identical footprint. A
/// same-position **wrong-label / wrong-type** entry is forced into each grid so the per-candidate
/// label/type re-check is genuinely exercised (a bug that ignored it would return the extra id).
#[test]
fn off_thread_spatial_seeks_equal_inline_rows_and_ssi_footprint() {
    let cart = |x: f64, y: f64| Value::Point(Point::new_2d(Crs::Cartesian, x, y));

    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let l_city = s.intern_token(Namespace::Label, "City").unwrap();
    let l_town = s.intern_token(Namespace::Label, "Town").unwrap();
    let t_visited = s.intern_token(Namespace::RelType, "VISITED").unwrap();
    let t_knows = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let k_loc = s.intern_token(Namespace::PropKey, "loc").unwrap();
    let k_at = s.intern_token(Namespace::PropKey, "at").unwrap();

    // Six City nodes along the x-axis at (i, 0). A Town at the ORIGIN shares the query cell but must be
    // excluded on the label re-check. Also seed a node scaffold for the relationships.
    let mut city_ids = Vec::new();
    for i in 0..6u64 {
        let (n, _) = s.create_node(txn).unwrap();
        s.add_label(txn, n, l_city).unwrap();
        s.set_node_property_value(txn, n, k_loc, &cart(i as f64, 0.0))
            .unwrap();
        city_ids.push(n);
    }
    let (town, _) = s.create_node(txn).unwrap();
    s.add_label(txn, town, l_town).unwrap();
    s.set_node_property_value(txn, town, k_loc, &cart(0.0, 0.0))
        .unwrap();

    // Six VISITED rels whose point `at` is (i, 0), plus a KNOWS rel at the origin sharing the query cell —
    // excluded on the type re-check.
    let mut rel_ids = Vec::new();
    for i in 0..6u64 {
        let (r, _) = s.create_rel(txn, t_visited, city_ids[0], town).unwrap();
        s.set_rel_property_value(txn, r, k_at, &cart(i as f64, 0.0))
            .unwrap();
        rel_ids.push(r);
    }
    let (knows, _) = s.create_rel(txn, t_knows, city_ids[0], town).unwrap();
    s.set_rel_property_value(txn, knows, k_at, &cart(0.0, 0.0))
        .unwrap();
    s.commit(txn).unwrap();
    let ts = s.snapshot_ts();

    // Register + populate the node and relationship spatial grids over committed state. The Town id is
    // forced into the CITY grid, and the KNOWS id into the VISITED grid, both at the origin — so each
    // grid returns it as a geometric candidate and only the label/type re-check can drop it.
    let coord = Coordinated::new(s);
    {
        let mut idx = coord.index.borrow_mut();
        idx.register_spatial(l_city, k_loc, 1.0, IndexState::Online);
        idx.register_spatial_rel(t_visited, k_at, 1.0, IndexState::Online);
        for (i, &id) in city_ids.iter().enumerate() {
            idx.insert_spatial_point(l_city, k_loc, &cart(i as f64, 0.0), id);
        }
        idx.insert_spatial_point(l_city, k_loc, &cart(0.0, 0.0), town);
        for (i, &r) in rel_ids.iter().enumerate() {
            idx.insert_spatial_rel_point(t_visited, k_at, &cart(i as f64, 0.0), r);
        }
        idx.insert_spatial_rel_point(t_visited, k_at, &cart(0.0, 0.0), knows);
        // The populate reflects committed state; clear the in-flight ft/spatial marker so the live seam
        // takes its fast grid arm and the capture is admitted (else the comparison is vacuous).
        idx.clear_ft_spatial_dirty();
    }

    // --- NODE spatial: within radius 2 of the origin → Cities at x=0,1,2; never the Town. ---
    let node_cap = coord
        .index
        .borrow_mut()
        .capture_node_spatial(ts, &[(l_city, k_loc, 0.0, 0.0, 2.0)]);
    {
        let live = coord.live_at(TxnId(100), ts);
        let inline = live
            .index_seek_spatial("City", "loc", 0.0, 0.0, 2.0)
            .expect("inline City grid is Online — it must seek");
        let ro = coord
            .reader_at(TxnId(100), ts)
            .with_index_candidates(node_cap);
        let off_thread = ro
            .index_seek_spatial("City", "loc", 0.0, 0.0, 2.0)
            .expect("the reader has a captured memo — it must seek");

        assert_eq!(
            off_thread, inline,
            "node spatial: off-thread rows disagree with inline"
        );
        for id in [city_ids[0], city_ids[1], city_ids[2]] {
            assert!(
                off_thread.contains(&NodeId(id)),
                "node spatial: the seek must contain {id} (rows={off_thread:?})"
            );
        }
        assert!(
            !off_thread.contains(&NodeId(town)),
            "node spatial: the Town must be excluded by the label re-check (rows={off_thread:?})"
        );

        let live_buf = live
            .take_read_buffer()
            .expect("coordinated live seam holds a SIREAD buffer");
        let ro_buf = ro.take_buffer();
        let (lr, lk, lp) = canonical(live_buf);
        let (rr, rk, rp) = canonical(ro_buf);
        assert_eq!(lr, rr, "node spatial: SIREAD reader id differs");
        assert_eq!(lk, rk, "node spatial: per-record SIREAD markers differ");
        assert_eq!(lp, rp, "node spatial: predicate SIREAD markers differ");
        assert!(
            !lk.is_empty(),
            "node spatial: expected non-empty SIREAD markers (mark_all_live_nodes) — else vacuous"
        );
        assert!(!ro.has_error(), "node spatial: reader captured an error");
    }

    // --- REL spatial: within radius 2 of the origin → VISITED rels at x=0,1,2; never the KNOWS rel. ---
    let rel_cap = coord
        .index
        .borrow_mut()
        .capture_rel_spatial(ts, &[(t_visited, k_at, 0.0, 0.0, 2.0)]);
    {
        let live = coord.live_at(TxnId(101), ts);
        let inline = live
            .index_seek_spatial_rel("VISITED", "at", 0.0, 0.0, 2.0)
            .expect("inline VISITED grid is Online — it must seek");
        let ro = coord
            .reader_at(TxnId(101), ts)
            .with_index_candidates(rel_cap);
        let off_thread = ro
            .index_seek_spatial_rel("VISITED", "at", 0.0, 0.0, 2.0)
            .expect("the reader has a captured memo — it must seek");

        assert_eq!(
            off_thread, inline,
            "rel spatial: off-thread rows disagree with inline"
        );
        for id in [rel_ids[0], rel_ids[1], rel_ids[2]] {
            assert!(
                off_thread.contains(&RelId(id)),
                "rel spatial: the seek must contain {id} (rows={off_thread:?})"
            );
        }
        assert!(
            !off_thread.contains(&RelId(knows)),
            "rel spatial: the KNOWS rel must be excluded by the type re-check (rows={off_thread:?})"
        );

        let live_buf = live
            .take_read_buffer()
            .expect("coordinated live seam holds a SIREAD buffer");
        let ro_buf = ro.take_buffer();
        let (lr, lk, lp) = canonical(live_buf);
        let (rr, rk, rp) = canonical(ro_buf);
        assert_eq!(lr, rr, "rel spatial: SIREAD reader id differs");
        assert_eq!(lk, rk, "rel spatial: per-record SIREAD markers differ");
        assert_eq!(lp, rp, "rel spatial: predicate SIREAD markers differ");
        assert!(
            !lk.is_empty(),
            "rel spatial: expected non-empty SIREAD markers (mark_all_live_rels) — else vacuous"
        );
        assert!(!ro.has_error(), "rel spatial: reader captured an error");
    }
}
