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
