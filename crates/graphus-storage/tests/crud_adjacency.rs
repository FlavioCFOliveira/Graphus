//! Integration tests for the public CRUD + index-free-adjacency surface of
//! [`graphus_storage::RecordStore`] (`rmp` task #13 acceptance criteria 1–3).
//!
//! These exercise the store over the in-memory DST device + log: node/relationship/property CRUD,
//! parallel edges, self-loops, the doubly-linked incidence-chain invariants, and free-list reuse.
//! Crash-recovery is covered separately in `crash_recovery.rs`; the property-based adjacency
//! fuzzing in `adjacency_props.rs`.

use graphus_io::MemBlockDevice;
use graphus_storage::store::StoreKind;
use graphus_storage::{NULL_ID, Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

/// Builds a fresh store over an in-memory device + log with `cap` buffer frames and id seed 1.
fn fresh(cap: usize) -> RecordStore<MemBlockDevice, MemLogSink> {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, cap, 1).expect("create store")
}

#[test]
fn create_two_nodes_and_an_edge_then_traverse() {
    let mut s = fresh(64);
    let txn = graphus_core::TxnId(1);
    s.begin(txn);
    let (a, eid_a) = s.create_node(txn).unwrap();
    let (b, eid_b) = s.create_node(txn).unwrap();
    assert_ne!(a, b);
    assert_ne!(eid_a, eid_b, "element ids are never reused");
    let kt = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let (r, _eid_r) = s.create_rel(txn, kt, a, b).unwrap();
    s.commit(txn).unwrap();

    // Both endpoints see exactly the one edge.
    assert_eq!(s.incident_rels(a).unwrap(), vec![r]);
    assert_eq!(s.incident_rels(b).unwrap(), vec![r]);
    assert_eq!(s.degree(a).unwrap(), 1);
    assert_eq!(s.degree(b).unwrap(), 1);

    // The relationship record points at the right endpoints and type.
    let rel = s.rel(r).unwrap();
    assert_eq!((rel.start_node, rel.end_node, rel.type_id), (a, b, kt));
    assert!(rel.mvcc.in_use());
}

#[test]
fn parallel_edges_are_distinct_records_in_both_chains() {
    let mut s = fresh(64);
    let txn = graphus_core::TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "LINK").unwrap();
    // Three parallel edges a -> b.
    let r1 = s.create_rel(txn, t, a, b).unwrap().0;
    let r2 = s.create_rel(txn, t, a, b).unwrap().0;
    let r3 = s.create_rel(txn, t, a, b).unwrap().0;
    s.commit(txn).unwrap();

    let mut a_inc = s.incident_rels(a).unwrap();
    let mut b_inc = s.incident_rels(b).unwrap();
    a_inc.sort_unstable();
    b_inc.sort_unstable();
    assert_eq!(a_inc, vec![r1, r2, r3]);
    assert_eq!(b_inc, vec![r1, r2, r3]);
    assert_eq!(s.degree(a).unwrap(), 3);
    assert_eq!(s.degree(b).unwrap(), 3);
    assert_ne!(r1, r2);
    assert_ne!(r2, r3);
}

#[test]
fn self_loop_appears_once_in_distinct_traversal_but_is_threaded_twice() {
    let mut s = fresh(64);
    let txn = graphus_core::TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "SELF").unwrap();
    let r = s.create_rel(txn, t, a, a).unwrap().0;
    s.commit(txn).unwrap();

    // Distinct incident-relationship traversal dedupes the loop's two chain links.
    assert_eq!(s.incident_rels(a).unwrap(), vec![r]);
    assert_eq!(s.degree(a).unwrap(), 1);

    // The relationship is a genuine self-loop with both endpoints equal.
    let rel = s.rel(r).unwrap();
    assert_eq!(rel.start_node, rel.end_node);
    assert_eq!(rel.start_node, a);
}

#[test]
fn self_loop_mixed_with_normal_edges_traverses_correctly() {
    let mut s = fresh(64);
    let txn = graphus_core::TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "E").unwrap();
    let r_ab = s.create_rel(txn, t, a, b).unwrap().0;
    let r_loop = s.create_rel(txn, t, a, a).unwrap().0;
    let r_ab2 = s.create_rel(txn, t, a, b).unwrap().0;
    s.commit(txn).unwrap();

    let mut a_inc = s.incident_rels(a).unwrap();
    a_inc.sort_unstable();
    let mut expect = vec![r_ab, r_loop, r_ab2];
    expect.sort_unstable();
    assert_eq!(a_inc, expect);
    assert_eq!(s.degree(a).unwrap(), 3);
    assert_eq!(s.incident_rels(b).unwrap().len(), 2);
}

#[test]
fn multiple_self_loops_on_one_node_traverse_and_delete() {
    let mut s = fresh(64);
    let txn = graphus_core::TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "E").unwrap();
    let l1 = s.create_rel(txn, t, a, a).unwrap().0; // self-loop
    let n1 = s.create_rel(txn, t, a, b).unwrap().0; // normal edge between two loops
    let l2 = s.create_rel(txn, t, a, a).unwrap().0; // self-loop
    s.commit(txn).unwrap();

    let mut inc = s.incident_rels(a).unwrap();
    inc.sort_unstable();
    let mut expect = vec![l1, n1, l2];
    expect.sort_unstable();
    assert_eq!(inc, expect, "both self-loops + the normal edge, each once");
    assert_eq!(s.degree(a).unwrap(), 3);

    // Delete one self-loop; the other and the normal edge remain.
    let txn2 = graphus_core::TxnId(2);
    s.begin(txn2);
    s.delete_rel(txn2, l1).unwrap();
    s.commit(txn2).unwrap();
    let mut inc = s.incident_rels(a).unwrap();
    inc.sort_unstable();
    let mut expect = vec![n1, l2];
    expect.sort_unstable();
    assert_eq!(inc, expect);
    assert_eq!(s.degree(a).unwrap(), 2);
}

#[test]
fn delete_edge_unlinks_from_both_chains() {
    let mut s = fresh(64);
    let txn = graphus_core::TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "E").unwrap();
    let r1 = s.create_rel(txn, t, a, b).unwrap().0;
    let r2 = s.create_rel(txn, t, a, b).unwrap().0;
    let r3 = s.create_rel(txn, t, a, b).unwrap().0;
    // Delete the middle-of-chain edge r2 (it is neither head nor tail of a's chain).
    s.delete_rel(txn, r2).unwrap();
    s.commit(txn).unwrap();

    let mut a_inc = s.incident_rels(a).unwrap();
    let mut b_inc = s.incident_rels(b).unwrap();
    a_inc.sort_unstable();
    b_inc.sort_unstable();
    assert_eq!(a_inc, vec![r1, r3]);
    assert_eq!(b_inc, vec![r1, r3]);
    assert!(!s.rel(r2).unwrap().mvcc.in_use());
}

#[test]
fn delete_self_loop_unlinks_both_links() {
    let mut s = fresh(64);
    let txn = graphus_core::TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "E").unwrap();
    let r_ab_pre = {
        let (b, _) = s.create_node(txn).unwrap();
        s.create_rel(txn, t, a, b).unwrap().0
    };
    let r_loop = s.create_rel(txn, t, a, a).unwrap().0;
    s.delete_rel(txn, r_loop).unwrap();
    s.commit(txn).unwrap();

    // After deleting the loop, only the normal edge remains incident to a.
    assert_eq!(s.incident_rels(a).unwrap(), vec![r_ab_pre]);
    assert_eq!(s.degree(a).unwrap(), 1);
    assert!(!s.rel(r_loop).unwrap().mvcc.in_use());
}

#[test]
fn delete_head_then_tail_keeps_chain_consistent() {
    let mut s = fresh(64);
    let txn = graphus_core::TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "E").unwrap();
    let r1 = s.create_rel(txn, t, a, b).unwrap().0; // becomes tail (pushed first)
    let r2 = s.create_rel(txn, t, a, b).unwrap().0;
    let r3 = s.create_rel(txn, t, a, b).unwrap().0; // head (pushed last)

    s.delete_rel(txn, r3).unwrap(); // delete head
    s.delete_rel(txn, r1).unwrap(); // delete tail
    s.commit(txn).unwrap();

    assert_eq!(s.incident_rels(a).unwrap(), vec![r2]);
    assert_eq!(s.incident_rels(b).unwrap(), vec![r2]);
}

#[test]
fn regression_pushing_a_head_before_a_self_loop_keeps_both_links() {
    // Regression for an index-free-adjacency bug found by the property tests: when a new head was
    // pushed onto a node whose existing head was a self-loop, `relink_old_head` repointed *both*
    // sides of the loop (because both face the node), corrupting the loop's internal link. The fix
    // repoints only the head link (the side with prev == NULL). This test pins the exact shape.
    let mut s = fresh(64);
    let txn = graphus_core::TxnId(1);
    s.begin(txn);
    let (n1, _) = s.create_node(txn).unwrap();
    let (n2, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "E").unwrap();
    let r_loop = s.create_rel(txn, t, n2, n2).unwrap().0; // self-loop becomes head of n2
    let r_norm = s.create_rel(txn, t, n2, n1).unwrap().0; // pushed in front of the loop
    s.commit(txn).unwrap();

    // n2 sees both, deduped; the loop's internal link survived.
    let mut inc = s.incident_rels(n2).unwrap();
    inc.sort_unstable();
    let mut expect = vec![r_loop, r_norm];
    expect.sort_unstable();
    assert_eq!(inc, expect);
    assert_eq!(s.degree(n2).unwrap(), 2);

    // The self-loop's two links remain internally consistent: end-side.next == start-side, and the
    // start-side's prev points back at the loop record (NULL_ID would mean the link was lost).
    let loop_rec = s.rel(r_loop).unwrap();
    assert_eq!(
        loop_rec.end_next_rel, r_loop,
        "end-side links to start-side"
    );
    assert_eq!(
        loop_rec.start_prev_rel, r_loop,
        "start-side links back to end-side"
    );
}

#[test]
fn properties_chain_head_to_tail() {
    let mut s = fresh(64);
    let txn = graphus_core::TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let name = s.intern_token(Namespace::PropKey, "name").unwrap();
    let age = s.intern_token(Namespace::PropKey, "age").unwrap();
    let p1 = s.add_node_property(txn, a, name, 4, 0xABCD).unwrap();
    let p2 = s.add_node_property(txn, a, age, 2, 42).unwrap();
    s.commit(txn).unwrap();

    let props = s.node_properties(a).unwrap();
    // Prepend order: p2 (age) then p1 (name).
    assert_eq!(props.len(), 2);
    assert_eq!(props[0].0, p2);
    assert_eq!(props[0].1.key, age);
    assert_eq!(props[0].1.value_inline, 42);
    assert_eq!(props[1].0, p1);
    assert_eq!(props[1].1.key, name);
    assert_eq!(props[1].1.value_inline, 0xABCD);
}

#[test]
fn freed_physical_ids_are_reused_lifo() {
    let mut s = fresh(64);
    let txn = graphus_core::TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let (c, _) = s.create_node(txn).unwrap();
    s.commit(txn).unwrap();

    let txn2 = graphus_core::TxnId(2);
    s.begin(txn2);
    s.delete_node(txn2, b).unwrap();
    s.delete_node(txn2, c).unwrap();
    s.commit(txn2).unwrap();

    let txn3 = graphus_core::TxnId(3);
    s.begin(txn3);
    let (d, _) = s.create_node(txn3).unwrap();
    let (e, _) = s.create_node(txn3).unwrap();
    s.commit(txn3).unwrap();

    // LIFO reuse: the last freed id (c) comes back first, then b. `a` is untouched.
    assert_eq!(d, c, "freed id c is reused first (LIFO)");
    assert_eq!(e, b, "freed id b is reused next");
    assert!(s.node(a).unwrap().mvcc.in_use());
}

#[test]
fn store_grows_across_pages() {
    // Force the node store to span several pages (125 node records per 8 KiB page).
    let mut s = fresh(8);
    let txn = graphus_core::TxnId(1);
    s.begin(txn);
    let mut ids = Vec::new();
    for _ in 0..400 {
        ids.push(s.create_node(txn).unwrap().0);
    }
    s.commit(txn).unwrap();

    // Every node is readable and in use; ids are dense and start at 1 (id 0 is the null pointer).
    assert_eq!(ids.first(), Some(&1));
    assert_eq!(ids.last(), Some(&400));
    for &id in &ids {
        assert!(
            s.node(id).unwrap().mvcc.in_use(),
            "node {id} should be live"
        );
    }
    // Sanity on the records-per-page constant.
    assert!(graphus_storage::paging::records_per_page(StoreKind::Node.record_size()) >= 100);
    let _ = NULL_ID; // referenced to document the reserved-id invariant in this test module
}
