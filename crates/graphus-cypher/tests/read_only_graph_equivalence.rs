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
    DeletedEntity, ExpandDirection, GraphAccess, NodeId, RelData, RelId,
};
use graphus_cypher::index_set::IndexSet;
use graphus_cypher::read_only_graph::ReadOnlyGraph;
use graphus_cypher::record_graph::RecordStoreGraph;
use graphus_io::MemBlockDevice;
use graphus_storage::{BLOCK_PAYLOAD, Namespace, RecordStore};
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

    // Deliberately do NOT run GC: both read routes must face the tombstones, dead versions and corpse.
    Fixture {
        store: s,
        ts_latest,
        ts_early,
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
