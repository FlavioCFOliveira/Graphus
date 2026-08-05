//! **The cost of an abort is bounded by the transaction's own writes** (`rmp` #970, acceptance
//! criterion 2; `04-technical-design.md` §5.1.5 row 4).
//!
//! The physical rollback was `O(store)` and not by accident: it called `reload_catalog`, which
//! rebuilds the in-memory catalog — every free list, the whole token dictionary, the whole
//! `Statistics` — from the durable metadata page, and then had to put back, from pre-rollback
//! snapshots, everything that reload had thrown away and did not belong to the aborting transaction
//! (`rmp` #578 free lists, #866 counters, #220/#172 high-waters, #534/#734 schema). Measured on this
//! fixture before the change, the rollback of a transaction that wrote **eight** records cost:
//!
//! | committed nodes | freed ids | interned keys | rollback |
//! | ---: | ---: | ---: | ---: |
//! | 500 | 250 | 200 | 66 µs |
//! | 4 000 | 2 000 | 200 | 142 µs |
//! | 16 000 | 8 000 | 200 | 430 µs |
//! | 16 000 | **0** | 200 | 77 µs |
//! | 500 | 250 | **4 000** | 689 µs |
//! | 16 000 | 8 000 | **4 000** | 1 087 µs |
//!
//! The two controls in bold isolate the cause: with the same 16 000 nodes but an empty free list the
//! cost collapses to 77 µs, and holding the store size fixed while widening the token dictionary
//! alone takes it from 66 µs to 689 µs. The transaction's own eight writes are constant throughout —
//! the WAL bytes it appends are byte-identical in all six rows.
//!
//! # What this file asserts, and why the first assertion is not a clock
//!
//! A wall-clock ratio is evidence, not a contract: it drifts with the machine. The contract is
//! **structural** — a data transaction's rollback performs no catalog reload at all — and
//! [`RecordStore::catalog_reloads`] is the deterministic witness for it. The timing test that follows
//! is deliberately generous; it exists to catch a re-introduction of *some* store-proportional term
//! that is not the catalog reload.

use graphus_core::{TxnId, Value};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

const POOL: usize = 256;
/// The writes the transaction under measurement makes. Fixed across every store size — that is the
/// whole point of the comparison.
const WRITES: usize = 8;

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, POOL, 1).expect("create store")
}

/// Builds a store holding `nodes` committed nodes, `keys` interned property keys and — when `churn`
/// — a free list carrying `nodes / 2` reclaimed ids, then opens a transaction that writes exactly
/// [`WRITES`] records and returns it ready to be rolled back.
fn build(nodes: usize, keys: usize, churn: bool) -> (Store, Vec<u64>, Vec<u32>) {
    let mut s = fresh();

    let mut key_ids = Vec::with_capacity(keys);
    s.begin(TxnId(1));
    for i in 0..keys {
        key_ids.push(
            s.intern_token(Namespace::PropKey, &format!("k{i}"))
                .expect("intern"),
        );
    }
    s.commit(TxnId(1)).expect("commit tokens");

    s.begin(TxnId(2));
    let mut ids = Vec::with_capacity(nodes);
    for _ in 0..nodes {
        let (id, _) = s.create_node(TxnId(2)).expect("create");
        s.set_node_property_value(TxnId(2), id, key_ids[0], &Value::Integer(7))
            .expect("set");
        ids.push(id);
    }
    s.commit(TxnId(2)).expect("commit nodes");

    if churn {
        s.begin(TxnId(3));
        for &id in ids.iter().take(nodes / 2) {
            s.delete_node(TxnId(3), id).expect("delete");
        }
        s.commit(TxnId(3)).expect("commit deletes");
        s.begin(TxnId(4));
        s.gc(TxnId(4), s.snapshot_ts()).expect("gc");
        s.commit(TxnId(4)).expect("commit gc");
    }
    (s, ids, key_ids)
}

/// Opens the transaction under measurement on `s` and leaves it open with [`WRITES`] × 2 writes
/// staged (fresh nodes plus overwrites of committed ones).
fn stage_writes(s: &mut Store, ids: &[u64], key_ids: &[u32], nodes: usize) -> TxnId {
    let t = TxnId(100);
    s.begin(t);
    for _ in 0..WRITES {
        s.create_node(t).expect("create");
    }
    for &id in ids.iter().skip(nodes / 2).take(WRITES) {
        s.set_node_property_value(t, id, key_ids[0], &Value::Integer(9))
            .expect("set");
    }
    t
}

/// **The contract.** A data transaction's rollback rebuilds no catalog — at any store size.
///
/// # Non-vacuity
///
/// Two guards keep this from passing over an empty question. The `assert!(before > 0)` proves the
/// counter *does* advance for the operations that legitimately reload (opening the store, and the
/// physical rollback of a transaction with no deltas), so "unchanged" is a measured preservation and
/// not a counter that never moves. And the rollback is asserted to have actually undone something:
/// the eight fresh nodes are gone afterwards.
#[test]
fn a_data_transactions_rollback_reloads_no_catalog() {
    for (nodes, keys) in [(500usize, 200usize), (16_000, 4_000)] {
        let (mut s, ids, key_ids) = build(nodes, keys, true);
        let live_before = s.scan_node_ids().expect("scan").len();

        // A transaction with NO deltas still takes the physical path, so the counter moves for it —
        // the baseline that makes the assertion below a real preservation claim.
        let empty = TxnId(50);
        s.begin(empty);
        s.intern_token(Namespace::PropKey, "catalog_only")
            .expect("intern");
        s.rollback(empty).expect("rollback the catalog-only txn");
        let before = s.catalog_reloads();
        assert!(
            before > 0,
            "non-vacuity: the counter must advance for the paths that do reload, or `unchanged` \
             below would hold for the wrong reason"
        );

        let t = stage_writes(&mut s, &ids, &key_ids, nodes);
        s.rollback(t).expect("rollback");

        assert_eq!(
            s.catalog_reloads(),
            before,
            "rmp #970: the rollback of a data transaction ({nodes} nodes, {keys} keys) must not \
             reload the catalog — that is the O(store) term the logical rollback removes"
        );
        assert_eq!(
            s.scan_node_ids().expect("scan").len(),
            live_before,
            "non-vacuity: the rollback must actually have undone the eight fresh nodes"
        );
        // And that it undid the eight OVERWRITES too, not only the eight creations: the committed
        // value is 7 and the aborted transaction wrote 9 over it.
        let snapshot = graphus_txn::Snapshot::new(TxnId(999), s.snapshot_ts());
        for &id in ids.iter().skip(nodes / 2).take(WRITES) {
            let decided = s
                .decision_scan_node_properties(id, snapshot)
                .expect("decided props");
            let v = decided
                .visible_version(key_ids[0])
                .expect("the committed property is still there");
            assert_eq!(
                v.value_inline, 7,
                "non-vacuity: the rollback must restore the committed value of node {id}, not leave \
                 the aborted 9 in place"
            );
        }
    }
}

/// The wall-clock evidence, recorded and bounded. Deliberately generous: the pre-#970 spread over
/// this exact fixture was 16x (66 µs → 1 087 µs), so a 4x ceiling catches a regression of the same
/// kind without turning machine noise into a failure.
#[test]
fn the_cost_of_a_rollback_does_not_grow_with_the_store() {
    // Least-of-three: the minimum is the least noise-contaminated estimator of a cost that only ever
    // gets *slower* under interference, and it makes the test stable on a loaded machine.
    let measure = |nodes: usize, keys: usize| -> u128 {
        (0..3)
            .map(|_| {
                let (mut s, ids, key_ids) = build(nodes, keys, true);
                let t = stage_writes(&mut s, &ids, &key_ids, nodes);
                let started = std::time::Instant::now();
                s.rollback(t).expect("rollback");
                started.elapsed().as_nanos()
            })
            .min()
            .expect("three samples")
    };

    let small = measure(500, 200);
    let large = measure(16_000, 4_000);
    println!("rollback of {WRITES} writes: small store {small} ns, large store {large} ns");
    assert!(
        large <= small.saturating_mul(4).max(50_000),
        "rmp #970: a 32x bigger store with a 20x wider token dictionary must not make the rollback \
         of the same eight writes materially more expensive (small {small} ns, large {large} ns)"
    );
}
