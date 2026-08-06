//! `rmp` #1011 (layer 3 of #975) — the undo-delta slab belongs to the **transaction**, not the store.
//!
//! # What the slab is, and what was wrong with it
//!
//! `undo_slab` is a half-open run `[next, end)` of freshly-allocated `undo.store` ids, all inside ONE
//! store page, from which `alloc_undo_id` hands out deltas by a bare counter increment. Its own
//! documentation names Memgraph's `delta_container` as its model — and that is a member of
//! `Transaction` (`/data/refsrc/memgraph/src/storage/v2/transaction.hpp:234`). In Graphus it was a
//! field of `RecordStore`.
//!
//! **Be precise about why that is wrong, because the obvious framing does not survive contact with
//! the code.** With one writer holding `&mut self`, a shared cursor still hands out *distinct* ids:
//! the counter is monotonic, so two transactions interleaving their writes get `n`, `n+1`, `n+2`, …
//! and never collide. A first version of this test asserted disjoint ids and was **vacuous** — a
//! mutation that restored the shared cursor did not fail it. That is recorded here rather than
//! quietly fixed, because the same mistake is available to the next reader.
//!
//! Two things are genuinely wrong, on two different horizons:
//!
//! 1. **Page locality — observable TODAY, and asserted below.** The field's own doc justifies the
//!    slab by "a transaction's deltas land contiguously in one page, so its chain writes dirty one
//!    page and its WAL patches all name that page". With the cursor SHARED, two interleaved
//!    transactions' deltas land in the *same* page, and that claim is simply false. The page then
//!    becomes a point of frame-latch contention the moment writers are parallel, and both writers
//!    dirty it, so they serialise on its eviction and doublewrite too.
//! 2. **A data race on the cursor — NOT reachable today, and deliberately not asserted here.** Once
//!    layer 5 (`rmp` #1013`/`#1014`) turns the write path into `&self`, two threads can read `next`
//!    before either writes it back and both take the same id. That is a race, not a logic error: no
//!    single-threaded test can express it, and pretending otherwise would be exactly the vacuity this
//!    module docs warn about. It is the reason the field must move *before* the writers arrive, and
//!    the guard for it is the deterministic scheduler (`rmp` #973), not this file.
//!
//! # Why this test can prove (1) without two threads
//!
//! The property is about **which page a transaction's deltas land in**, not about parallelism. Two
//! transactions open at once, writing in an interleaved order on one thread, exercise the identical
//! sharing: under the old field they draw from one run in one page, under the fix each draws from its
//! own. Same device `graphus_dst::reader_store_growth` uses for `rmp` #721 — "the bug is about
//! ordering, not parallelism".
//!
//! Run with `cargo test -p graphus-storage --test per_txn_undo_slab_1011`.

use std::collections::HashSet;

use graphus_core::{TxnId, Value};
use graphus_io::MemBlockDevice;
use graphus_storage::{RecordStore, StoreKind};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// The property key every writer sets, so each `set_node_property_value` links one `SetProperty`
/// delta and therefore consumes exactly one slab id.
const KEY: u32 = 11;

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 256, 1).expect("create store")
}

/// Commits one node and returns its physical id.
fn seed_node(s: &mut Store, txn: u64) -> u64 {
    let t = TxnId(txn);
    s.begin(t);
    let (n, _) = s.create_node(t).expect("create node");
    s.set_node_property_value(t, n, KEY, &Value::Integer(0))
        .expect("seed property");
    s.commit(t).expect("commit seed");
    n
}

/// Every live delta id on `node`'s undo chain, newest first.
fn chain_delta_ids(s: &Store, node: u64) -> Vec<u64> {
    s.undo_chain_for_test(StoreKind::Node, node)
        .expect("walk the undo chain")
        .into_iter()
        .map(|(id, _)| id)
        .collect()
}

/// How many `undo.store` records fit in one page — the slab's granularity, and therefore the unit
/// the locality claim is about. Derived here rather than imported so the test names a *layout fact*,
/// not an internal.
const UNDO_RECORDS_PER_PAGE: u64 = 145;

/// The set of `undo.store` PAGES a transaction's deltas landed in.
fn pages_of(ids: &[u64]) -> HashSet<u64> {
    ids.iter().map(|id| id / UNDO_RECORDS_PER_PAGE).collect()
}

/// **The invariant, as it is actually observable.** Two transactions open at the same time, writing
/// in an interleaved order, must land their deltas in **disjoint pages**.
///
/// This is the claim the field's own documentation makes and the one a shared cursor breaks. It is
/// asserted on pages and not on ids on purpose — see the module docs: a shared cursor still yields
/// distinct ids under one writer, so an id-disjointness assertion passes either way and proves
/// nothing.
#[test]
fn two_interleaved_transactions_land_their_deltas_in_disjoint_pages() {
    let mut s = fresh();
    let a_node = seed_node(&mut s, 1);
    let b_node = seed_node(&mut s, 2);

    // The seed transaction's own deltas are already on these chains, and they are NOT under test —
    // measuring the whole chain would attribute the seed's page to whichever writer inherited the
    // node. Capture them so the assertion below is about the deltas A and B actually wrote.
    let a_seed: HashSet<u64> = chain_delta_ids(&s, a_node).into_iter().collect();
    let b_seed: HashSet<u64> = chain_delta_ids(&s, b_node).into_iter().collect();

    let (a, b) = (TxnId(10), TxnId(11));
    s.begin(a);
    s.begin(b);

    // Interleave deliberately: A, B, A, B, … Each write links exactly one `SetProperty` delta, so the
    // two transactions alternate their draws — the shape that makes a shared cursor observable.
    for i in 1..=8i64 {
        s.set_node_property_value(a, a_node, KEY, &Value::Integer(i))
            .expect("A writes");
        s.set_node_property_value(b, b_node, KEY, &Value::Integer(i))
            .expect("B writes");
    }

    let a_ids: Vec<u64> = chain_delta_ids(&s, a_node)
        .into_iter()
        .filter(|id| !a_seed.contains(id))
        .collect();
    let b_ids: Vec<u64> = chain_delta_ids(&s, b_node)
        .into_iter()
        .filter(|id| !b_seed.contains(id))
        .collect();
    assert!(
        a_ids.len() >= 8 && b_ids.len() >= 8,
        "NON-VACUITY: both transactions must actually have linked the deltas whose placement is \
         under test (A: {}, B: {})",
        a_ids.len(),
        b_ids.len()
    );

    let (a_pages, b_pages) = (pages_of(&a_ids), pages_of(&b_ids));
    let shared: Vec<u64> = a_pages.intersection(&b_pages).copied().collect();
    assert!(
        shared.is_empty(),
        "two open transactions put their deltas in the SAME undo page(s) {shared:?} — the slab \
         cursor is being shared, so the per-transaction locality the slab exists for is gone and \
         that page becomes a frame-latch contention point the moment writers are parallel \
         (`rmp` #1011). A pages: {a_pages:?}, B pages: {b_pages:?}"
    );

    s.commit(a).expect("A commits");
    s.commit(b).expect("B commits");
}

/// The slab drops with the transaction that owned it: a committed or aborted transaction leaves no
/// cursor behind for the next one to inherit.
///
/// Stated because "it lives on `ActiveTxn`" is only useful if `ActiveTxn` is genuinely taken at both
/// endings — it is what lets the rollback path stop clearing the field by hand.
#[test]
fn the_slab_does_not_outlive_its_transaction() {
    let mut s = fresh();
    let node = seed_node(&mut s, 1);

    let a = TxnId(10);
    s.begin(a);
    s.set_node_property_value(a, node, KEY, &Value::Integer(1))
        .expect("A writes");
    s.commit(a).expect("A commits");

    let b = TxnId(11);
    s.begin(b);
    s.set_node_property_value(b, node, KEY, &Value::Integer(2))
        .expect("B writes");
    let all = chain_delta_ids(&s, node);
    let unique: HashSet<u64> = all.iter().copied().collect();
    assert_eq!(
        unique.len(),
        all.len(),
        "a delta id appears twice on one chain {all:?}: a slab cursor survived its transaction and \
         was handed out again while the first use was still live"
    );
    s.commit(b).expect("B commits");
}
