//! Property tests for the B+-tree against a `std::collections::BTreeMap` model
//! (`04-technical-design.md` §6.1).
//!
//! For many deterministic seeds (`graphus_sim::SimRng`) we drive a random sequence of
//! insert / delete / lookup / range operations against both the [`BTree`] and a `BTreeMap`, and
//! assert:
//!
//! * **point parity** — every lookup returns the same result in both;
//! * **range parity** — every range scan returns the same ordered `(key, value)` list;
//! * **structural invariants** — after each batch, [`BTree::check_invariants`] holds: every node's
//!   keys are sorted and the leaf right-sibling chain links all leaves in strictly ascending key
//!   order (so all leaves are reachable in order — the range-scan correctness foundation).
//!
//! Keys are encoded `i64`s via [`encode_i64_bits`], so the test also exercises the order-preserving
//! encoding end-to-end (negative/zero/positive keys round-trip through the tree in numeric order).
//! Large key counts force many node splits, spanning multiple pages.

use std::collections::BTreeMap;

use graphus_bufpool::BufferPool;
use graphus_core::TxnId;
use graphus_core::capability::Rng;
use graphus_index::BTree;
use graphus_index::keycodec::encode_i64_bits;
use graphus_index::recovery::SharedWal;
use graphus_io::MemBlockDevice;
use graphus_sim::SimRng;
use graphus_wal::{MemLogSink, WalManager};

type Tree = BTree<MemBlockDevice, MemLogSink>;

fn fresh_tree() -> Tree {
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let shared = SharedWal::new(wal);
    // A small pool (relative to the key count) forces eviction + reload through checksums, the WAL
    // rule, and disk I/O — exercising the durability path under the model, not just the cache.
    let pool = BufferPool::with_wal(MemBlockDevice::new(0), shared.clone(), 16);
    BTree::create(pool, shared).expect("create btree")
}

fn key(k: i64) -> Vec<u8> {
    encode_i64_bits(k).to_vec()
}

fn val(v: u64) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

/// One transaction wrapping `f`, committed at the end.
fn in_txn(tree: &mut Tree, id: u64, f: impl FnOnce(&mut Tree, TxnId)) {
    let txn = TxnId(id);
    tree.with_wal(|w| {
        w.begin(txn);
    });
    f(tree, txn);
    tree.with_wal(|w| w.commit(txn).expect("commit"));
}

#[test]
fn random_ops_match_btreemap_model_many_seeds() {
    for seed in 1..=24u64 {
        let mut rng = SimRng::new(seed);
        let mut tree = fresh_tree();
        let mut model: BTreeMap<i64, u64> = BTreeMap::new();

        // Use a small key domain so deletes actually hit existing keys often.
        let key_domain: i64 = 200;
        let batches = 8;
        let ops_per_batch = 40;

        for batch in 0..batches {
            in_txn(&mut tree, seed * 100 + batch, |tree, txn| {
                for _ in 0..ops_per_batch {
                    let r = rng.next_u64();
                    let k = (r % (key_domain as u64)) as i64 - key_domain / 2; // negatives too
                    match r % 4 {
                        0 | 1 => {
                            // insert / update
                            let v = rng.next_u64();
                            tree.insert(txn, &key(k), &val(v)).expect("insert");
                            model.insert(k, v);
                        }
                        2 => {
                            // delete
                            let removed = tree.delete(txn, &key(k)).expect("delete");
                            let model_removed = model.remove(&k).is_some();
                            assert_eq!(
                                removed, model_removed,
                                "seed {seed}: delete presence mismatch for key {k}"
                            );
                        }
                        _ => {
                            // lookup
                            let got = tree.lookup(&key(k)).expect("lookup");
                            let want = model.get(&k).map(|v| val(*v));
                            assert_eq!(got, want, "seed {seed}: lookup mismatch for key {k}");
                        }
                    }
                }
            });

            // After every committed batch: structural invariants + full-scan parity.
            tree.check_invariants()
                .unwrap_or_else(|e| panic!("seed {seed} batch {batch}: invariant: {e}"));

            let scanned: Vec<(i64, u64)> = tree
                .scan_all()
                .expect("scan")
                .into_iter()
                .map(|(k, v)| {
                    (
                        decode_i64(&k),
                        u64::from_le_bytes(v.try_into().expect("8-byte value")),
                    )
                })
                .collect();
            let model_vec: Vec<(i64, u64)> = model.iter().map(|(k, v)| (*k, *v)).collect();
            assert_eq!(
                scanned, model_vec,
                "seed {seed} batch {batch}: full ordered scan mismatch"
            );
        }

        // Random range parity across the domain.
        let mut rng2 = SimRng::new(seed ^ 0xABCD);
        for _ in 0..20 {
            let a = (rng2.next_u64() % (key_domain as u64)) as i64 - key_domain / 2;
            let b = (rng2.next_u64() % (key_domain as u64)) as i64 - key_domain / 2;
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            let got: Vec<(i64, u64)> = tree
                .range(&key(lo), &key(hi))
                .expect("range")
                .into_iter()
                .map(|(k, v)| (decode_i64(&k), u64::from_le_bytes(v.try_into().unwrap())))
                .collect();
            let want: Vec<(i64, u64)> = model.range(lo..hi).map(|(k, v)| (*k, *v)).collect();
            assert_eq!(got, want, "seed {seed}: range [{lo}, {hi}) mismatch");
        }
    }
}

#[test]
fn many_keys_force_splits_and_span_pages() {
    let mut tree = fresh_tree();
    let n = 5_000i64; // far more than one page of keys -> a multi-level tree

    in_txn(&mut tree, 1, |tree, txn| {
        for k in 0..n {
            // Interleave to avoid purely-ascending inserts always splitting the rightmost leaf.
            let kk = if k % 2 == 0 { k } else { n - k };
            tree.insert(txn, &key(kk), &val(kk as u64)).expect("insert");
        }
    });

    // The tree must have grown past a single leaf.
    assert!(
        tree.height().expect("height") >= 2,
        "5000 keys should produce a multi-level tree"
    );
    tree.check_invariants().expect("invariants after bulk load");

    // Every key is present with the right value.
    for k in 0..n {
        let got = tree.lookup(&key(k)).expect("lookup");
        assert_eq!(got, Some(val(k as u64)), "missing key {k} after splits");
    }

    // Full scan is exactly the sorted key set.
    let scanned: Vec<i64> = tree
        .scan_all()
        .expect("scan")
        .into_iter()
        .map(|(k, _)| decode_i64(&k))
        .collect();
    let expected: Vec<i64> = (0..n).collect();
    assert_eq!(scanned, expected, "scan must yield all keys in order");
}

#[test]
fn ascending_and_descending_bulk_loads_are_correct() {
    for &descending in &[false, true] {
        let mut tree = fresh_tree();
        let n = 2_000i64;
        in_txn(&mut tree, 1, |tree, txn| {
            for i in 0..n {
                let k = if descending { n - 1 - i } else { i };
                tree.insert(txn, &key(k), &val(k as u64)).expect("insert");
            }
        });
        tree.check_invariants().expect("invariants");
        let scanned: Vec<i64> = tree
            .scan_all()
            .expect("scan")
            .into_iter()
            .map(|(k, _)| decode_i64(&k))
            .collect();
        assert_eq!(scanned, (0..n).collect::<Vec<_>>());
    }
}

#[test]
fn delete_down_to_empty_keeps_invariants() {
    let mut tree = fresh_tree();
    let n = 1_000i64;
    in_txn(&mut tree, 1, |tree, txn| {
        for k in 0..n {
            tree.insert(txn, &key(k), &val(k as u64)).expect("insert");
        }
    });
    // Delete every other key, then the rest.
    in_txn(&mut tree, 2, |tree, txn| {
        for k in (0..n).step_by(2) {
            assert!(tree.delete(txn, &key(k)).expect("delete"));
        }
    });
    tree.check_invariants().expect("invariants mid-delete");
    let remaining: Vec<i64> = tree
        .scan_all()
        .expect("scan")
        .into_iter()
        .map(|(k, _)| decode_i64(&k))
        .collect();
    assert_eq!(remaining, (0..n).filter(|k| k % 2 == 1).collect::<Vec<_>>());

    in_txn(&mut tree, 3, |tree, txn| {
        for k in (1..n).step_by(2) {
            assert!(tree.delete(txn, &key(k)).expect("delete"));
        }
    });
    tree.check_invariants().expect("invariants after empty");
    assert!(tree.scan_all().expect("scan").is_empty());
}

/// Decodes a key encoded by [`encode_i64_bits`] (sign-bit flip, big-endian) back to `i64`.
fn decode_i64(bytes: &[u8]) -> i64 {
    let arr: [u8; 8] = bytes.try_into().expect("8-byte key");
    (u64::from_be_bytes(arr) ^ 0x8000_0000_0000_0000) as i64
}

// ---------------------------------------------------------------------------------------------
// Page-reclamation behaviour on delete (rmp #222 → #225).
//
// The B+-tree delete policy (`btree.rs::delete`, `04 §6.3`) removes the entry in-place and lets the
// leaf underflow WITHOUT eager merge/rebalance. Two reclamation behaviours are pinned here:
//
//   * Common case (delete-then-reinsert churn / updates): an emptied-but-still-referenced leaf is
//     REUSED in place — the parent separators are unchanged, so a later in-range key routes back to
//     the same physical page and refills it. Net page leak is ZERO. This is the workload the vast
//     majority of OLTP graphs exhibit.
//   * Monotonic delete-without-reinsert (time-series / TTL / log-retention): a delete that drains a
//     leaf to empty now UNLINKS the leaf and returns its page to a **persistent free list** (rmp
//     #225); a later insert into a disjoint higher range pops those freed pages instead of extending
//     the device, so the page high-water stays BOUNDED instead of growing one page per drained leaf
//     for the database lifetime. This test asserts that bound — on the pre-#225 append-only allocator
//     the high-water instead GREW (`high_fill > low_fill`), so the flipped assertion direction is
//     itself the empirical before/after proof.

/// Common-case churn (the OLTP norm): filling, deleting everything, then re-inserting the SAME keys
/// allocates NO new device pages — the emptied leaves are reused. This is the empirical proof that
/// the delete-policy leak is zero for delete-then-reinsert workloads.
#[test]
fn refilling_emptied_leaves_allocates_no_new_pages() {
    let mut tree = fresh_tree();
    let n: i64 = 600; // enough keys to force many leaf splits → a multi-leaf tree

    in_txn(&mut tree, 1, |tree, txn| {
        for k in 0..n {
            tree.insert(txn, &key(k), &val(k as u64)).expect("insert");
        }
    });
    let pages_after_fill = tree.mapped_pages().len();
    assert!(
        pages_after_fill > 3,
        "expected a multi-page tree, got {pages_after_fill} pages"
    );

    // Delete every key: the tree drains to empty, leaves underflow but stay linked.
    in_txn(&mut tree, 2, |tree, txn| {
        for k in 0..n {
            assert!(tree.delete(txn, &key(k)).expect("delete"));
        }
    });
    tree.check_invariants().expect("invariants after drain");
    assert!(tree.scan_all().expect("scan").is_empty());

    // Re-insert the identical key set: every key routes back to its (now empty) original leaf and
    // refills it. No split, no allocation.
    in_txn(&mut tree, 3, |tree, txn| {
        for k in 0..n {
            tree.insert(txn, &key(k), &val(k as u64)).expect("insert");
        }
    });
    let pages_after_refill = tree.mapped_pages().len();

    assert_eq!(
        pages_after_refill, pages_after_fill,
        "delete-then-reinsert of the same keys must reuse the emptied leaves and allocate no new \
         pages (fill={pages_after_fill}, refill={pages_after_refill})"
    );
    // And the data is fully intact after the churn cycle.
    let scanned: Vec<i64> = tree
        .scan_all()
        .expect("scan")
        .into_iter()
        .map(|(k, _)| decode_i64(&k))
        .collect();
    assert_eq!(scanned, (0..n).collect::<Vec<_>>());
}

/// The `rmp` #225 win: a monotonically advancing delete-without-reinsert workload (time-series /
/// TTL / log-retention) now reuses the pages its drained leaves freed instead of stranding one per
/// leaf. Fill a low range, delete it all (TTL expiry), then fill a DISJOINT higher range whose keys
/// are all greater than every freed leaf — on the pre-#225 append-only allocator that higher range
/// split forward into NEW pages and the high-water GREW; with the persistent free list it pops the
/// freed low pages and the high-water stays BOUNDED (does not exceed the low-fill high-water). The
/// flip of this assertion's direction (was `high_fill > low_fill`) is the empirical before/after
/// proof against the append-only allocator.
#[test]
fn monotonic_delete_without_reinsert_reuses_freed_pages() {
    let mut tree = fresh_tree();
    let n: i64 = 3_000; // multi-level tree → also exercises internal-node reclaim + root collapse

    // Fill the low range [0, n) → a multi-level tree.
    in_txn(&mut tree, 1, |tree, txn| {
        for k in 0..n {
            tree.insert(txn, &key(k), &val(k as u64)).expect("insert");
        }
    });
    let pages_after_low_fill = tree.mapped_pages().len();
    assert!(
        tree.height().expect("height") >= 2,
        "want a multi-level tree so internal reclamation + collapse are exercised"
    );

    // Delete the entire low range (TTL expiry): every drained leaf is unlinked and freed.
    in_txn(&mut tree, 2, |tree, txn| {
        for k in 0..n {
            assert!(tree.delete(txn, &key(k)).expect("delete"));
        }
    });
    tree.check_invariants().expect("invariants after expiry");
    assert!(tree.scan_all().expect("scan").is_empty());

    // Insert a DISJOINT higher range [n, 2n): every key is greater than all freed leaves. On the
    // append-only allocator this split forward into fresh pages; with the free list it pops the freed
    // low pages first.
    in_txn(&mut tree, 3, |tree, txn| {
        for k in n..(2 * n) {
            tree.insert(txn, &key(k), &val(k as u64)).expect("insert");
        }
    });
    tree.check_invariants().expect("invariants after high fill");
    let pages_after_high_fill = tree.mapped_pages().len();

    // BOUNDED: the high-water did not grow — the freed low pages were reused (append-only would give
    // `high_fill > low_fill`, i.e. roughly double).
    assert!(
        pages_after_high_fill <= pages_after_low_fill,
        "monotonic delete-without-reinsert must reuse freed pages and keep the high-water bounded \
         (low_fill={pages_after_low_fill}, high_fill={pages_after_high_fill})"
    );

    // Correctness is unaffected: only the high range remains, fully intact and ordered.
    let scanned: Vec<i64> = tree
        .scan_all()
        .expect("scan")
        .into_iter()
        .map(|(k, _)| decode_i64(&k))
        .collect();
    assert_eq!(scanned, (n..(2 * n)).collect::<Vec<_>>());
}

/// Explicit regression for the reclamation edge cases the `rmp` #225 design calls out: emptying the
/// **leftmost** leaf (its chain predecessor is `None` — the global chain head, so step (b) is a
/// no-op) and the leftmost subtree draining until a **parent becomes childless** and is itself
/// reclaimed, cascading to a **root collapse**. Ascending, contiguous, front-to-back deletes are the
/// worst case for the leftmost path: each delete drains the current leftmost leaf, so every leftmost
/// / parent-emptying / collapse branch is exercised, and the tree must stay a valid `BTreeMap` model
/// and pass its structural invariants after every batch — down to a single empty leaf root.
#[test]
fn reclaim_leftmost_parent_emptying_and_root_collapse() {
    let mut tree = fresh_tree();
    // Enough keys to force a height-3 tree (leaves ≈ 166 keys, internal fan-out ≈ 340, so height 3
    // needs > ~56 000 keys) — required so that draining a whole leftmost subtree empties a *non-root*
    // internal node (parent-emptying recursion) and the root collapses more than once.
    let n: i64 = 70_000;
    in_txn(&mut tree, 1, |tree, txn| {
        for k in 0..n {
            tree.insert(txn, &key(k), &val(k as u64)).expect("insert");
        }
    });
    assert!(
        tree.height().expect("height") >= 3,
        "want a 3+ level tree so parent-emptying recurses and the root collapses more than once"
    );

    // Delete front-to-back in batches. Ascending deletes always target the current leftmost leaf → the
    // cross-parent-predecessor (`None`) branch, parent-emptying, and successive root collapses all
    // fire. Invariants + model parity are checked at each batch boundary (O(n) walks, so batched
    // coarsely to keep the debug-build runtime reasonable).
    let batch = 5_000i64;
    let mut deleted = 0i64;
    let mut batch_id = 2u64;
    while deleted < n {
        let end = (deleted + batch).min(n);
        in_txn(&mut tree, batch_id, |tree, txn| {
            for k in deleted..end {
                assert!(tree.delete(txn, &key(k)).expect("delete"), "key {k} present");
            }
        });
        tree.check_invariants()
            .unwrap_or_else(|e| panic!("invariants after deleting [0,{end}): {e}"));
        let remaining: Vec<i64> = tree
            .scan_all()
            .expect("scan")
            .into_iter()
            .map(|(k, _)| decode_i64(&k))
            .collect();
        assert_eq!(
            remaining,
            (end..n).collect::<Vec<_>>(),
            "surviving keys must be exactly [{end}, {n}) after front-to-back drain"
        );
        deleted = end;
        batch_id += 1;
    }
    assert!(tree.scan_all().expect("scan").is_empty(), "fully drained");
    tree.check_invariants().expect("invariants when empty");

    // The tree is reusable after a full collapse: refilling a fresh range pops the freed pages
    // (bounded high-water) and round-trips correctly.
    let before = tree.mapped_pages().len();
    in_txn(&mut tree, batch_id, |tree, txn| {
        for k in n..(2 * n) {
            tree.insert(txn, &key(k), &val(k as u64)).expect("insert");
        }
    });
    let after = tree.mapped_pages().len();
    assert!(
        after <= before,
        "refill after full collapse must reuse freed pages (before={before}, after={after})"
    );
    tree.check_invariants().expect("invariants after refill");
    let scanned: Vec<i64> = tree
        .scan_all()
        .expect("scan")
        .into_iter()
        .map(|(k, _)| decode_i64(&k))
        .collect();
    assert_eq!(scanned, (n..(2 * n)).collect::<Vec<_>>());
}
