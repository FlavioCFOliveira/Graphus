//! Correctness guard for the typed single-pass incidence walk `incident_rels_typed` (`rmp` #324,
//! "Win 1").
//!
//! The Cypher `expand` body used to read every incident relationship TWICE for a type-selective
//! traversal — once to walk the chain (`incident_rels`) and again per id (`rel()`) to learn its
//! type before filtering — and SSI-marked every non-matching edge. `incident_rels_typed` collapses
//! that into a single chain walk that reads each link once and returns the decoded record only for
//! the requested types. These tests pin the five MUST-preserve invariants of `rmp` #324 at the
//! storage layer:
//!
//! 1. **Typed prune correctness** — the typed result is exactly the type-filtered subset of
//!    `incident_rels`, and every returned record's `type_id` is one of the requested types (no
//!    non-matching record is ever materialised).
//! 2. **Untyped still all** — an empty filter returns the same membership as `incident_rels`.
//! 3. **Multigraph parallel edges** — N parallel edges of the same type between the same pair are
//!    all enumerated.
//! 4. **Self-loop dedupe** — a self-loop appears once, exactly as `incident_rels`.
//! 5. **#220 corpse threading** — the typed walk threads transparently through a dead-link corpse to
//!    the live successor below it (a corpse of the requested type is NOT emitted; a live successor of
//!    the requested type threaded *through* the corpse IS).
//!
//! MVCC visibility is decided ABOVE this layer (in `graphus-cypher`), so these tests assert on the
//! raw chain membership, exactly the contract `incident_rels` already carries.

use graphus_core::TxnId;
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 16, 1).expect("create store")
}

/// The physical ids the typed walk emits, for ergonomic membership comparison.
fn typed_ids(s: &Store, node: u64, types: &[u32]) -> Vec<u64> {
    s.incident_rels_typed(node, types)
        .unwrap()
        .into_iter()
        .map(|(id, _)| id)
        .collect()
}

#[test]
fn typed_prune_matches_filtered_incident_rels() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let t_friend = s.intern_token(Namespace::RelType, "FRIEND").unwrap();
    let t_like = s.intern_token(Namespace::RelType, "LIKE").unwrap();

    let (a, _) = s.create_node(txn).unwrap();
    // A representative mixed-incidence hub: many FRIEND edges, a few LIKE edges, interleaved.
    let mut all_friend = Vec::new();
    let mut all_like = Vec::new();
    for i in 0..20u64 {
        let (b, _) = s.create_node(txn).unwrap();
        if i % 3 == 0 {
            let (r, _) = s.create_rel(txn, t_like, a, b).unwrap();
            all_like.push(r);
        } else {
            let (r, _) = s.create_rel(txn, t_friend, a, b).unwrap();
            all_friend.push(r);
        }
    }
    s.commit(txn).unwrap();

    let all = s.incident_rels(a).unwrap();
    assert_eq!(all.len(), 20, "every incident edge enumerated untyped");

    // 1. Typed prune == type-filtered subset of incident_rels, AND every returned record matches.
    let like_typed = s.incident_rels_typed(a, &[t_like]).unwrap();
    let like_ids: Vec<u64> = like_typed.iter().map(|(id, _)| *id).collect();
    let mut expected_like: Vec<u64> = all
        .iter()
        .copied()
        .filter(|id| all_like.contains(id))
        .collect();
    let mut got_like = like_ids.clone();
    expected_like.sort_unstable();
    got_like.sort_unstable();
    assert_eq!(got_like, expected_like, "LIKE-typed prune is exact");
    for (_, rec) in &like_typed {
        assert_eq!(rec.type_id, t_like, "no non-LIKE record is materialised");
    }

    // The wasted-read elimination, demonstrated structurally: the typed walk materialises ONLY the
    // matching records, so the count of records that reach the caller drops from 20 (every edge,
    // re-read in the old expand loop) to 7 (the LIKE edges) — a 65% reduction here, matching the
    // ~64% top_liked figure.
    assert_eq!(like_typed.len(), all_like.len());
    let pruned = all.len() - like_typed.len();
    assert!(
        pruned * 100 / all.len() >= 60,
        "typed prune skips >=60% of the records (skipped {pruned}/{})",
        all.len()
    );

    // Multiple requested types union correctly.
    let both = typed_ids(&s, a, &[t_like, t_friend]);
    let mut both_sorted = both.clone();
    both_sorted.sort_unstable();
    let mut all_sorted = all.clone();
    all_sorted.sort_unstable();
    assert_eq!(both_sorted, all_sorted, "union of both types == all edges");
}

#[test]
fn untyped_returns_all_like_incident_rels() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let t_a = s.intern_token(Namespace::RelType, "A").unwrap();
    let t_b = s.intern_token(Namespace::RelType, "B").unwrap();
    let (hub, _) = s.create_node(txn).unwrap();
    for i in 0..10u64 {
        let (n, _) = s.create_node(txn).unwrap();
        let t = if i % 2 == 0 { t_a } else { t_b };
        s.create_rel(txn, t, hub, n).unwrap();
    }
    s.commit(txn).unwrap();

    let mut all = s.incident_rels(hub).unwrap();
    let mut typed_all = typed_ids(&s, hub, &[]);
    all.sort_unstable();
    typed_all.sort_unstable();
    assert_eq!(typed_all, all, "empty filter == incident_rels membership");
}

#[test]
fn multigraph_parallel_same_type_edges_all_enumerated() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let t = s.intern_token(Namespace::RelType, "LINK").unwrap();
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    // Five PARALLEL edges of the SAME type between the SAME pair (multigraph).
    let mut parallel = Vec::new();
    for _ in 0..5 {
        let (r, _) = s.create_rel(txn, t, a, b).unwrap();
        parallel.push(r);
    }
    s.commit(txn).unwrap();

    let mut typed = typed_ids(&s, a, &[t]);
    parallel.sort_unstable();
    typed.sort_unstable();
    assert_eq!(typed, parallel, "all 5 parallel same-type edges enumerated");
    assert_eq!(typed.len(), 5);
}

#[test]
fn self_loop_emitted_once_typed() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let t = s.intern_token(Namespace::RelType, "SELF").unwrap();
    let t_other = s.intern_token(Namespace::RelType, "OTHER").unwrap();
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let (loop_id, _) = s.create_rel(txn, t, a, a).unwrap();
    s.create_rel(txn, t_other, a, b).unwrap();
    s.commit(txn).unwrap();

    // The self-loop is threaded into a's chain twice but must be emitted once (identity dedupe).
    let typed = s.incident_rels_typed(a, &[t]).unwrap();
    let ids: Vec<u64> = typed.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, vec![loop_id], "self-loop emitted exactly once, typed");

    // It is also exactly once in the untyped enumeration (matches `incident_rels`).
    let untyped = typed_ids(&s, a, &[]);
    assert_eq!(
        untyped.iter().filter(|&&id| id == loop_id).count(),
        1,
        "self-loop counted once untyped"
    );
}

#[test]
fn typed_walk_threads_through_dead_link_corpse() {
    // #220: a rolled-back rel creation leaves a dead-link corpse (`!in_use`, preserved body). A live
    // edge prepended BEFORE the corpse, and a live edge that the corpse's chain threads THROUGH, must
    // both still be reachable by the typed walk — the corpse itself must NOT be emitted.
    let mut s = fresh();
    let setup = TxnId(1);
    s.begin(setup);
    let t = s.intern_token(Namespace::RelType, "T").unwrap();
    let (a, _) = s.create_node(setup).unwrap();
    let (b, _) = s.create_node(setup).unwrap();
    let (c, _) = s.create_node(setup).unwrap();
    // First committed edge (becomes the chain tail relative to later prepends).
    let (live1, _) = s.create_rel(setup, t, a, b).unwrap();
    s.commit(setup).unwrap();

    // A rolled-back creation on `a` leaves a corpse at the head of a's chain (its header-only undo
    // cleared in_use but preserved the forward link to `live1`).
    let txn_abort = TxnId(2);
    s.begin(txn_abort);
    let (corpse, _) = s.create_rel(txn_abort, t, a, c).unwrap();
    s.rollback(txn_abort).unwrap();

    // A later committed prepend threads on top of the corpse.
    let txn3 = TxnId(3);
    s.begin(txn3);
    let (live2, _) = s.create_rel(txn3, t, a, c).unwrap();
    s.commit(txn3).unwrap();

    let typed = s.incident_rels_typed(a, &[t]).unwrap();
    let ids: Vec<u64> = typed.iter().map(|(id, _)| *id).collect();
    // Both live edges reachable; the corpse never emitted.
    assert!(ids.contains(&live1), "live1 reachable through the corpse");
    assert!(ids.contains(&live2), "live2 reachable");
    assert!(
        !ids.contains(&corpse),
        "corpse is NOT emitted (it is !in_use)"
    );
    assert_eq!(ids.len(), 2, "exactly the two live edges");

    // Membership matches the untyped chain walk restricted to type T (= all of them here).
    let mut untyped = s.incident_rels(a).unwrap();
    let mut got = ids.clone();
    untyped.sort_unstable();
    got.sort_unstable();
    assert_eq!(got, untyped, "typed walk membership == incident_rels");
}
