//! Regression: `rmp` #721 — an off-thread reader must never fail a legitimate read with
//! `"{kind} store page N not allocated"` because a **concurrent writer grew the store** underneath it.
//!
//! # The defect
//!
//! [`RecordStore::capture_read_meta`] used to freeze the record-id → device-page **map**
//! (`device_pages`) into the reader's [`MetaSnapshot`], while [`RecordStore::read_view`] shares the
//! page cache **live**. So the reader's *location oracle* was a snapshot but the record *content* it
//! navigates was live — and the two were not consistent with each other.
//!
//! The published safety argument ("the writer only appends to `device_pages` and advances
//! `high_water`, so a reader scanning `1..high_water` only ever indexes already-existing entries; any
//! id allocated later is invisible anyway") is true for **scans** and false for **chain walks**. A
//! chain walk FOLLOWS POINTERS (`node.first_rel`, `node.first_prop`, `prop.next_prop`) read out of
//! LIVE, in-place-updated record content. A concurrently committed writer prepends its new record to
//! the chain head, so the reader reads a pointer to a record that lives on a page allocated AFTER its
//! snapshot. The "invisible anyway" clause cannot save it: visibility is decided ABOVE the location
//! oracle, so a record the reader cannot LOCATE is never filtered — the walk dies first, with an
//! internal server error (`Neo.DatabaseError.General.UnknownError`).
//!
//! # The shape reproduced here
//!
//! Single-threaded and fully deterministic — true parallelism is not needed to express the race,
//! only the *ordering*: (1) the reader captures its view; (2) the writer commits records that grow
//! the store onto a NEW device page and re-point a chain head at them; (3) the reader, still holding
//! its view, walks that chain. Both chain kinds that the mixed OLTP workload of `rmp` #714 exercises
//! are covered: the **relationship** chain (`CREATE (u)-[:PURCHASED]->(p)`) and the **property**
//! chain (`SET p.hot = coalesce(p.hot,0)+1`).
//!
//! The true-parallel companion is `graphus-dst/tests/real_thread_reader_vs_growing_writer_721.rs`;
//! the DST scenario is `graphus_dst::scenarios::reader_vs_store_growth`.

use graphus_core::{TxnId, Value};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore, StoreKind};
use graphus_wal::{MemLogSink, WalManager};

fn fresh(cap: usize) -> RecordStore<MemBlockDevice, MemLogSink> {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, cap, 1).expect("create store")
}

/// The relationship-chain face of #721: a reader holding a view captured BEFORE the growth walks the
/// incidence chain of a hub whose `first_rel` a concurrently committed writer has re-pointed at a
/// relationship record on a **newly allocated** rel-store page.
///
/// Pre-fix this fails with `Storage("Rel store page 1 not allocated")` — the exact
/// `Neo.DatabaseError.General.UnknownError` the reader pool surfaced to clients.
#[test]
fn reader_view_follows_rel_chain_onto_a_page_allocated_after_its_snapshot() {
    let s = fresh(512);

    let txn = TxnId(1);
    s.begin(txn);
    let t = s.intern_token(Namespace::RelType, "PURCHASED").unwrap();
    s.commit(txn).unwrap();

    // A hub with a single edge: the rel store now has exactly ONE device page.
    let txn = TxnId(2);
    s.begin(txn);
    let (hub, _) = s.create_node(txn).unwrap();
    let (leaf, _) = s.create_node(txn).unwrap();
    s.create_rel(txn, t, hub, leaf).unwrap();
    s.commit(txn).unwrap();

    // (1) The reader captures its view. Its `device_pages` for the Rel store names ONE page.
    let view = s.read_view();
    let before = view.incident_rels(hub).expect("baseline walk");
    assert_eq!(before.len(), 1, "hub starts with one edge");

    // (2) The writer commits enough new edges on the SAME hub to spill the rel store onto a new
    // device page. Each `create_rel` PREPENDS to the hub's chain, so `hub.first_rel` — read LIVE by
    // the reader below — ends up naming a record on a page the reader's snapshot never saw.
    for i in 0..400u64 {
        let txn = TxnId(100 + i);
        s.begin(txn);
        let (leaf, _) = s.create_node(txn).unwrap();
        s.create_rel(txn, t, hub, leaf).unwrap();
        s.commit(txn).unwrap();
    }

    // (3) The reader — still on its pre-growth view — walks the hub's chain. It must NOT fail: the
    // page map is the location oracle, and locating a record is not the same as making it visible.
    // Records committed after the snapshot are filtered ABOVE this layer by `is_visible_via`; the read
    // path's only job is to be able to READ them.
    let walked = view
        .incident_rels(hub)
        .expect("a concurrent writer growing the store must never fail a reader's chain walk");

    // The walk sees a SUPERSET of the reader's snapshot (that is the documented, MVCC-safe contract:
    // the extra ids are filtered by visibility above this layer). What it must never do is error.
    assert!(
        walked.contains(&before[0]),
        "the edge that was committed before the snapshot must still be reachable"
    );
    assert!(
        walked.len() >= before.len(),
        "the live chain walk is a superset of the snapshot's"
    );
}

/// The property-chain face of #721: a writer that adds properties re-points `node.first_prop` at a
/// record on a **newly allocated** prop-store page, which a reader holding a pre-growth view must
/// still be able to locate.
///
/// Pre-fix this fails with `Storage("Prop store page N not allocated")`.
///
/// # Re-armed for `rmp` #967
///
/// This test used to churn ONE key 600 times, relying on the pre-#967 write path allocating a fresh
/// `props.store` record per `SET`. After #967 that loop rewrites a single cell in place and allocates
/// **nothing**, so the store never grows and the #721 hazard is never exercised — the test would
/// still pass, while proving nothing. It now writes 600 **distinct** keys, which genuinely grows the
/// store, and asserts the growth crossed a device-page boundary before the reader walks. Without
/// that assertion the re-arming would itself be unverified.
#[test]
fn reader_view_follows_prop_chain_onto_a_page_allocated_after_its_snapshot() {
    let s = fresh(512);

    let txn = TxnId(1);
    s.begin(txn);
    let key0 = s.intern_token(Namespace::PropKey, "k0").unwrap();
    let (node, _) = s.create_node(txn).unwrap();
    s.set_node_property_value(txn, node, key0, &Value::Integer(0))
        .unwrap();
    s.commit(txn).unwrap();

    // (1) The reader captures its view: the Prop store has exactly one device page.
    let view = s.read_view();
    let before = view
        .superset_scan_node_properties(node)
        .expect("baseline chain");
    assert_eq!(before.len(), 1, "one live property to start with");
    // The page map is shared LIVE (that is the #721 fix), so this handle tracks the writer's growth.
    let pages_before = view.meta().store(StoreKind::Prop).device_pages.len();

    // (2) The writer adds 600 DISTINCT keys, so the prop store grows monotonically and
    // `node.first_prop` chases the newest record onto pages the reader never saw.
    for i in 1..600i64 {
        let txn = TxnId(100 + i as u64);
        s.begin(txn);
        let key = s
            .intern_token(Namespace::PropKey, &format!("k{i}"))
            .unwrap();
        s.set_node_property_value(txn, node, key, &Value::Integer(i))
            .unwrap();
        s.commit(txn).unwrap();
    }

    // NON-VACUITY: the hazard only exists if the store actually grew onto new device pages.
    let pages_after = view.meta().store(StoreKind::Prop).device_pages.len();
    assert!(
        pages_after > pages_before,
        "the prop store must have crossed a device-page boundary for this test to exercise \
         anything: {pages_before} -> {pages_after} pages",
    );

    // (3) The pre-growth reader walks the property chain. It must not fail, and it must reach every
    // record the writer added.
    let walked = view
        .superset_scan_node_properties(node)
        .expect("a concurrent writer growing the prop store must never fail a reader's chain walk");
    assert_eq!(
        walked.len(),
        600,
        "the walk must reach every cell, including those on post-snapshot pages",
    );
}

/// The **overflow-heap** face of #721: an overflow (long-string) property value is reassembled by
/// walking the `strings.store` block chain, whose head id comes from the LIVE prop record. A writer
/// that grows the strings store after the reader's snapshot re-points that head at a block on a newly
/// allocated page.
///
/// Pre-fix this fails with `Storage("Strings store page N not allocated")`.
#[test]
fn reader_view_follows_overflow_chain_onto_a_page_allocated_after_its_snapshot() {
    let s = fresh(512);

    // A value comfortably past the inline threshold, so it spills into the strings heap.
    let long = |i: usize| Value::String("x".repeat(400 + i));

    let txn = TxnId(1);
    s.begin(txn);
    let key = s.intern_token(Namespace::PropKey, "blob").unwrap();
    let (node, _) = s.create_node(txn).unwrap();
    s.set_node_property_value(txn, node, key, &long(0)).unwrap();
    s.commit(txn).unwrap();

    let view = s.read_view();
    let before = view.superset_scan_node_properties(node).unwrap();
    let (_, p0) = before.cells_ignoring_history()[0];
    view.decode_property_value(p0.type_tag, p0.value_inline)
        .expect("baseline overflow decode");

    // Grow the strings store well past the reader's snapshot.
    for i in 1..300usize {
        let txn = TxnId(100 + i as u64);
        s.begin(txn);
        s.set_node_property_value(txn, node, key, &long(i)).unwrap();
        s.commit(txn).unwrap();
    }

    // The pre-growth reader re-reads the property chain and decodes every value it finds. Every
    // record it can REACH it must be able to READ — including the newest versions, which it will then
    // filter by visibility above this layer.
    let walked = view
        .superset_scan_node_properties(node)
        .expect("prop chain walk");
    // Every CANDIDATE, not merely every cell: after `rmp` #967 the historical values live on the
    // undo chain, and their `strings.store` chains are exactly the ones that sit on pages allocated
    // after the reader's snapshot. Decoding only the cell would walk one chain and miss the hazard.
    let candidates: Vec<_> = walked.candidates().collect();
    assert!(
        candidates.len() > 1,
        "the churn must leave historical values on the undo chain: found {} candidates",
        candidates.len(),
    );
    for c in candidates {
        view.decode_property_value(c.type_tag, c.value_inline)
            .unwrap_or_else(|e| panic!("overflow decode of {:?} failed: {e}", c.source));
    }
}
