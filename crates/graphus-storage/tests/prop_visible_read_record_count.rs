//! Acceptance criterion 2 of `rmp` #967: **reading the visible property does not walk the chain when
//! the reader sees the live version**, proven by a record-read count.
//!
//! # STATUS: green since `rmp` #967 landed
//!
//! [`visible_read_record_count_is_identical_at_m1000_and_m8000`] is the criterion. It was written to
//! fail on the pre-#967 tombstone-and-prepend read path — which walked the whole version chain, so
//! the count scaled with M — and it turned green the moment the newest version was read in place and
//! the chain walk stopped at the first delta the reader already reflects.
//!
//! `read-probe` is off by default, so without it this whole file compiles away (see the `#![cfg]`
//! below) and `cargo test --all` is unaffected; the counts are asserted only under the explicit
//! `--features read-probe` invocation.
//!
//! # Why a count and not a timing
//!
//! The claim is structural — "serving one visible-property read touches a bounded number of records,
//! independent of how many times the key was overwritten" — so it deserves a structural proof. A
//! latency assertion would be a property of the host: the whole chain is resident in the buffer pool
//! after the writes, so a chain step is a pinned-page read plus a 46-byte decode, and a machine with
//! a large enough cache can walk thousands of records fast enough to pass any threshold loose enough
//! not to be flaky. The record count cannot be satisfied by a faster machine. See
//! `graphus_storage::read_probe` for the full rationale, including why the existing buffer-pool
//! counters (which count cache-miss *device* reads) and a page-fetch count both measure the wrong
//! layer.
//!
//! # What these tests pin
//!
//! [`visible_read_record_count_is_identical_at_m1000_and_m8000`] is the criterion itself: it measures
//! the reads at two chain lengths and asserts the whole `(prop, undo, commit)` triple is identical.
//! Comparing the triple rather than its total is what stops the walk from being *relocated* — moving
//! it from `props.store` into the undo chain or into the commit indirection changes which field
//! grows, never whether one does.
//!
//! [`a_visible_read_costs_exactly_one_record_in_each_store`] pins the exact constant, and
//! [`distinct_keys_still_cost_one_record_read_each`] pins the direction in which growth is still
//! correct. Together the three fix both ends: the count must be flat where flatness is the fix, must
//! be the right constant, and must still grow where growth is legitimate.
//!
//! # Running
//!
//! ```text
//! cargo test -p graphus-storage --features read-probe --test prop_visible_read_record_count
//! ```
//!
//! The `read-probe` feature is required and is not defaulted (it instruments the hottest read in the
//! engine). Without it the observation API does not exist and this file does not compile — chosen
//! over a stubbed zero, which would let these assertions pass while proving nothing.
#![cfg(feature = "read-probe")]

use graphus_core::{TxnId, Value};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore, read_probe};
use graphus_txn::Snapshot;
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 256, 1).expect("create store")
}

/// Builds a node whose property `key` has been overwritten `overwrites` times, each in its own
/// committed transaction, and returns the store, the node id, the key token and a snapshot that sees
/// every one of those commits.
fn node_with_overwrites(overwrites: u64) -> (Store, u64, u32, Snapshot) {
    assert!(overwrites > 0);
    let mut store = fresh();
    let key = store
        .intern_token(Namespace::PropKey, "batch_seq")
        .expect("intern propkey");

    let mut next = 1u64;
    let t = TxnId(next);
    next += 1;
    store.begin(t);
    let (node, _eid) = store.create_node(t).expect("create node");
    store.commit(t).expect("commit node");

    for i in 0..overwrites {
        let t = TxnId(next);
        next += 1;
        store.begin(t);
        store
            .set_node_property_value(t, node, key, &Value::Integer(i as i64))
            .expect("set property");
        store.commit(t).expect("commit overwrite");
    }

    let snap = Snapshot::new(TxnId(next), store.snapshot_ts());
    (store, node, key, snap)
}

/// Reads the visible value of `key` on `node` and returns the record reads that cost.
///
/// The read goes through the decision polarity — the same path a `MATCH` in the same transaction
/// takes — and the value is asserted present, so a count of zero can never come from reading nothing.
fn reads_for_one_visible_read(
    store: &Store,
    node: u64,
    key: u32,
    snap: Snapshot,
) -> read_probe::RecordReads {
    let (found, counts) = read_probe::counting(|| {
        let decided = store
            .decision_scan_node_properties(node, snap)
            .expect("decision scan");
        decided.visible_version(key).is_some()
    });
    assert!(found, "the overwritten key must be visible");
    counts
}

/// **`rmp` #967 acceptance criterion 2.** One visible-property read costs the same number of record
/// reads at M = 1000 and at M = 8000.
///
/// The non-vacuous form of this criterion is **identity between the two chain lengths**, not "the
/// count is small". A read that cost, say, 3 records at M = 1000 and 5 at M = 8000 would look small
/// at both and still be walking a chain. Comparing the whole `(prop, undo, commit)` triple rather
/// than only its total is what stops the walk from being relocated: moving it from `props.store`
/// into the undo chain or into the commit indirection changes which field grows, never whether one
/// does.
///
/// Fails on the pre-#967 tombstone-and-prepend path (the read walks the whole chain, so `prop`
/// scales with M) and passes once the newest version is read in place.
#[test]
fn visible_read_record_count_is_identical_at_m1000_and_m8000() {
    let (small_store, small_node, small_key, small_snap) = node_with_overwrites(1_000);
    let small = reads_for_one_visible_read(&small_store, small_node, small_key, small_snap);

    let (big_store, big_node, big_key, big_snap) = node_with_overwrites(8_000);
    let big = reads_for_one_visible_read(&big_store, big_node, big_key, big_snap);

    assert_eq!(
        big, small,
        "reading the visible value of one key must cost an IDENTICAL record-read triple at M=1000 \
         and M=8000: M=1000 cost {small:?}, M=8000 cost {big:?}. Any field that grows with M means \
         the reader is still walking a chain — in `props.store` if `prop` grows, in the undo chain \
         if `undo` grows, in the commit indirection if `commit` grows — instead of reading the live \
         version in place (`rmp` #967 AC 2)"
    );
}

/// The cost, pinned exactly: at any chain length a visible-property read performs **one**
/// `props.store` read, **one** `undo.store` read and **one** `commit.store` read.
///
/// **Semantic equivalent of** the retired `todays_visible_read_walks_the_whole_chain`, which pinned
/// the pre-#967 cost (`M` property reads at chain length `M`) as the "before" evidence. That number
/// is now unreachable, so the test is re-pointed at the constant it must hold instead — and this is
/// the point at which someone has to look at the triple and agree it is `(1, 1, 1)`:
///
/// * `prop = 1` — the entity holds exactly one cell for the key, rewritten in place.
/// * `undo = 1` — the walk reads the newest delta, sees it committed at or before the reader's
///   snapshot, and **stops**. It does not read the `M - 1` deltas below it.
/// * `commit = 1` — resolving that one delta's status costs one commit-slot read.
///
/// It is the non-vacuity control for the identity assertion above: pinning the exact triple, rather
/// than only its invariance, is what stops a change that silently made the read cost 3 records at
/// every M from passing both tests.
#[test]
fn a_visible_read_costs_exactly_one_record_in_each_store() {
    for overwrites in [1u64, 8, 64, 512, 1_000, 8_000] {
        let (store, node, key, snap) = node_with_overwrites(overwrites);

        // Non-vacuity, both halves: the entity really does hold ONE cell (the in-place rewrite) and
        // the undo chain really did accumulate one delta per overwrite (so there is a chain to walk
        // past, and "1 undo read" is a genuine early stop rather than an empty chain).
        let chain = store
            .superset_scan_node_properties(node)
            .expect("superset scan");
        assert_eq!(
            chain.len() as u64,
            1,
            "one cell per key after {overwrites} overwrites"
        );
        assert!(
            chain.history_len() as u64 >= overwrites,
            "the undo chain must hold at least one delta per overwrite ({overwrites}), else the \
             read has nothing to stop early on: found {}",
            chain.history_len(),
        );

        let counts = reads_for_one_visible_read(&store, node, key, snap);
        assert_eq!(
            counts.prop, 1,
            "at chain length {overwrites} the read touches exactly one property cell"
        );
        assert_eq!(
            counts.undo, 1,
            "and exactly one delta: it stops at the newest one, which this snapshot already reflects"
        );
        assert_eq!(
            counts.commit, 1,
            "and one commit slot: the single indirection that resolves that delta's status"
        );
    }
}

/// The **positive control** for the counter itself: with K DISTINCT keys the read must keep costing
/// `K` record reads even after #967, because the entity genuinely holds K live properties.
///
/// Without this, [`visible_read_record_count_is_identical_at_m1000_and_m8000`] could be satisfied by
/// a change that simply stopped counting — a counter wired to a constant passes an identity
/// assertion perfectly. This test fails in that case, so the two together pin both directions: the
/// count must be flat where flatness is the fix, and must still grow where growth is correct.
#[test]
fn distinct_keys_still_cost_one_record_read_each() {
    for k in [8u64, 64, 512] {
        let mut store = fresh();
        let keys: Vec<u32> = (0..k)
            .map(|i| {
                store
                    .intern_token(Namespace::PropKey, &format!("k{i}"))
                    .expect("intern propkey")
            })
            .collect();

        let mut next = 1u64;
        let t = TxnId(next);
        next += 1;
        store.begin(t);
        let (node, _eid) = store.create_node(t).expect("create node");
        store.commit(t).expect("commit node");

        for (i, &key) in keys.iter().enumerate() {
            let t = TxnId(next);
            next += 1;
            store.begin(t);
            store
                .set_node_property_value(t, node, key, &Value::Integer(i as i64))
                .expect("set property");
            store.commit(t).expect("commit write");
        }

        let snap = Snapshot::new(TxnId(next), store.snapshot_ts());
        let counts = reads_for_one_visible_read(&store, node, keys[k as usize - 1], snap);
        assert_eq!(
            counts.prop, k,
            "an entity with {k} live properties legitimately costs {k} record reads; a counter that \
             reports fewer has stopped observing the read rather than the read having got cheaper"
        );
        assert_eq!(
            (counts.undo, counts.commit),
            (1, 1),
            "the undo walk is still O(1) here: K distinct keys means K CELLS, not a longer chain"
        );
    }
}
