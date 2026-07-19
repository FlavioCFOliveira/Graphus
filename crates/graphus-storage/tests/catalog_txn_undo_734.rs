//! Per-transaction catalog (schema DDL) undo — `rmp` #734.
//!
//! A rolling-back transaction must discard **its own** pending catalog DDL while preserving every
//! **other** open transaction's pending DDL. Before #734 the store could do only one of the two: the
//! `rmp` #534 branch superset-preserved the whole in-memory schema whenever any unrelated transaction
//! was open, because it could not tell whose pending DDL was whose. The observable consequence was an
//! ACID breach with a *non-deterministic* face: the same `BEGIN; <catalog DDL>; ROLLBACK` either
//! discarded the DDL or persisted it, depending only on whether some unrelated transaction happened to
//! be open at the time.

use graphus_core::TxnId;
use graphus_io::{MemBlockDevice, Page};
use graphus_storage::{IndexState, Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

fn fresh(cap: usize) -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, cap, 1).expect("create store")
}

/// Clean reopen: flush, stage every mapped page onto a fresh device, reopen over the same WAL sink.
/// What is asserted after this is what is **durable**, not what is merely in memory.
fn reopen(mut s: Store) -> Store {
    s.flush().expect("flush");
    let pages = s.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    {
        let mut staged: Vec<(u64, Box<Page>)> = Vec::new();
        for p in &pages {
            staged.push((p.0, s.read_device_page(*p).expect("read device page")));
        }
        use graphus_io::BlockDevice;
        for (idx, bytes) in staged {
            device
                .write_page(graphus_core::PageId(idx), &bytes)
                .expect("stage page");
        }
        device.sync_all().expect("persist disk image");
    }
    let sink = s.with_wal(|w| w.sink().clone());
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, 64).expect("reopen store")
}

/// The acceptance criterion of `rmp` #734, in one scenario: two concurrently open transactions A and
/// B each hold pending, **disjoint** catalog DDL; B rolls back; A's DDL must survive and B's must be
/// gone — in memory *and* durably once A commits.
#[test]
fn rolling_back_txn_discards_only_its_own_pending_catalog_ddl() {
    let mut s = fresh(64);

    // --- committed baseline: tokens + one committed index/histogram pair -------------------------
    let t0 = TxnId(1);
    s.begin(t0);
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let age = s.intern_token(Namespace::PropKey, "age").unwrap();
    let name = s.intern_token(Namespace::PropKey, "name").unwrap();
    let city = s.intern_token(Namespace::PropKey, "city").unwrap();
    let baseline_hist = vec![7u8, 7, 7];
    s.set_property_histogram(t0, person, age, baseline_hist.clone());
    s.set_node_property_index(t0, person, age, IndexState::Online);
    s.commit(t0).unwrap();

    // --- two concurrently open transactions, each with its own pending DDL -----------------------
    let a = TxnId(2);
    let b = TxnId(3);
    s.begin(a);
    s.begin(b);

    // A declares an index + histogram on `name`.
    s.set_node_property_index(a, person, name, IndexState::Online);
    s.set_property_histogram(a, person, name, vec![0xAA, 0xAA]);
    // B declares an index + histogram on `city`, and also REPLACES the committed `age` histogram.
    s.set_node_property_index(b, person, city, IndexState::Online);
    s.set_property_histogram(b, person, city, vec![0xBB, 0xBB]);
    s.set_property_histogram(b, person, age, vec![0xBB; 32]);

    // --- B rolls back ---------------------------------------------------------------------------
    s.rollback(b).unwrap();

    // A's pending DDL must survive B's rollback (this is what `rmp` #534 got right).
    assert_eq!(
        s.node_property_index_state(person, name),
        Some(IndexState::Online),
        "A's pending index declaration must survive an unrelated transaction's rollback"
    );
    assert_eq!(
        s.property_histogram(person, name),
        Some(&[0xAAu8, 0xAA][..]),
        "A's pending histogram must survive an unrelated transaction's rollback"
    );

    // B's own pending DDL must be GONE (this is what `rmp` #734 fixes).
    assert_eq!(
        s.node_property_index_state(person, city),
        None,
        "B's own index declaration must not survive B's rollback"
    );
    assert_eq!(
        s.property_histogram(person, city),
        None,
        "B's own histogram must not survive B's rollback"
    );
    assert_eq!(
        s.property_histogram(person, age),
        Some(baseline_hist.as_slice()),
        "B's own replacement of a committed histogram must be undone by B's rollback"
    );

    // --- A commits; only A's DDL (plus the committed baseline) may be durable --------------------
    s.commit(a).unwrap();
    let r = reopen(s);

    assert_eq!(
        r.node_property_index_state(person, name),
        Some(IndexState::Online),
        "A's committed index declaration must be durable"
    );
    assert_eq!(
        r.property_histogram(person, name),
        Some(&[0xAAu8, 0xAA][..]),
        "A's committed histogram must be durable"
    );
    assert_eq!(
        r.node_property_index_state(person, city),
        None,
        "B's rolled-back index declaration must NOT be durable"
    );
    assert_eq!(
        r.property_histogram(person, city),
        None,
        "B's rolled-back histogram must NOT be durable"
    );
    assert_eq!(
        r.property_histogram(person, age),
        Some(baseline_hist.as_slice()),
        "the committed baseline histogram must be untouched by B's rolled-back replacement"
    );
    assert_eq!(
        r.node_property_index_state(person, age),
        Some(IndexState::Online),
        "the committed baseline index must be untouched"
    );
}

/// Runs `BEGIN; set_property_histogram(...); ROLLBACK` and returns what is **durable** afterwards.
/// `bystander` decides whether an unrelated transaction is open across the rollback — the only
/// difference between the two calls below.
fn durable_histogram_after_rolled_back_set(bystander: bool) -> Option<Vec<u8>> {
    let mut s = fresh(64);

    let t0 = TxnId(1);
    s.begin(t0);
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let age = s.intern_token(Namespace::PropKey, "age").unwrap();
    s.commit(t0).unwrap();

    // The unrelated transaction: open, holds NO catalog DDL of its own, and is never committed here.
    // Its only role is to be present in the store's active set while the rollback below runs.
    let idle = TxnId(2);
    if bystander {
        s.begin(idle);
    }

    let t = TxnId(3);
    s.begin(t);
    s.set_property_histogram(t, person, age, vec![55u8; 8]);
    s.rollback(t).unwrap();

    // Force the catalog to disk the way a subsequent ordinary commit would, then reopen. If the
    // rolled-back DDL is still in memory it becomes durable here — the #572 "DURABLE after reopen"
    // observation.
    let t2 = TxnId(4);
    s.begin(t2);
    let ignored = s.intern_token(Namespace::PropKey, "unrelated").unwrap();
    s.set_property_histogram(t2, person, ignored, vec![1u8]);
    s.commit(t2).unwrap();
    if bystander {
        s.rollback(idle).unwrap();
    }

    let r = reopen(s);
    r.property_histogram(person, age).map(<[u8]>::to_vec)
}

/// The ACID face of #734: a rolled-back catalog mutation must be discarded **regardless** of whether
/// an unrelated transaction happens to be open. Before the fix these two runs disagreed — the same
/// statement over the same data produced two different durable outcomes.
#[test]
fn a_rolled_back_catalog_mutation_is_discarded_whether_or_not_a_bystander_txn_is_open() {
    let alone = durable_histogram_after_rolled_back_set(false);
    let with_bystander = durable_histogram_after_rolled_back_set(true);

    assert_eq!(
        alone, None,
        "a rolled-back histogram must not be durable (no bystander transaction)"
    );
    assert_eq!(
        with_bystander, None,
        "a rolled-back histogram must not be durable just because an unrelated transaction was open"
    );
    assert_eq!(
        alone, with_bystander,
        "rollback durability must not depend on whether an unrelated transaction is open"
    );
}

// =================================================================================================
// The intervening-commit interleaving: an UNRELATED transaction commits — running the catalog
// checkpoint — while the DDL-holding transaction is still open, and only then does it roll back.
//
// This is the ordering that makes the durable image an unreliable baseline. The checkpoint persists
// the whole catalog, so it used to bake the open transaction's uncommitted DDL onto the metadata page
// under the committing transaction's id. The rollback's `reload_catalog` then restored that image —
// reading the rolled-back DDL back IN. Additive DDL therefore survived its own rollback; and a
// rolled-back DROP destroyed committed catalog state permanently, because the reload restored the
// image in which the drop had already happened.
// =================================================================================================

/// A rolled-back **addition** must not survive, even when an unrelated commit checkpointed the catalog
/// while it was pending.
#[test]
fn a_rolled_back_addition_does_not_survive_an_intervening_commit() {
    let mut s = fresh(64);

    let t0 = TxnId(1);
    s.begin(t0);
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let city = s.intern_token(Namespace::PropKey, "city").unwrap();
    s.commit(t0).unwrap();

    // B declares DDL and stays open.
    let b = TxnId(2);
    s.begin(b);
    s.set_node_property_index(b, person, city, IndexState::Online);
    s.set_property_histogram(b, person, city, vec![0xBB, 0xBB]);

    // An unrelated transaction commits, running the catalog checkpoint while B is pending.
    let a = TxnId(3);
    s.begin(a);
    let _ = s.create_node(a).unwrap();
    s.commit(a).unwrap();

    s.rollback(b).unwrap();

    assert_eq!(
        s.node_property_index_state(person, city),
        None,
        "B's rolled-back index must be gone in memory"
    );
    let r = reopen(s);
    assert_eq!(
        r.node_property_index_state(person, city),
        None,
        "B's rolled-back index must not be durable after an intervening commit checkpointed it"
    );
    assert_eq!(
        r.property_histogram(person, city),
        None,
        "B's rolled-back histogram must not be durable after an intervening commit checkpointed it"
    );
}

/// A rolled-back **removal** must not destroy the committed entry it would have dropped — the sharper
/// face of the same interleaving, because here the damage is to data that WAS committed.
#[test]
fn a_rolled_back_drop_does_not_destroy_committed_catalog_state() {
    let mut s = fresh(64);

    // Committed baseline: an index, its name, and a histogram.
    let t0 = TxnId(1);
    s.begin(t0);
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let age = s.intern_token(Namespace::PropKey, "age").unwrap();
    let baseline_hist = vec![7u8, 7, 7];
    s.set_node_property_index(t0, person, age, IndexState::Online);
    s.set_node_property_index_name(t0, "ix_age".to_owned(), person, age);
    s.set_property_histogram(t0, person, age, baseline_hist.clone());
    s.commit(t0).unwrap();

    // B drops all three and stays open.
    let b = TxnId(2);
    s.begin(b);
    s.remove_node_property_index(b, person, age);
    s.remove_node_property_index_name(b, "ix_age");
    s.remove_property_histogram(b, person, age);

    // An unrelated transaction commits, checkpointing the catalog mid-drop.
    let a = TxnId(3);
    s.begin(a);
    let _ = s.create_node(a).unwrap();
    s.commit(a).unwrap();

    s.rollback(b).unwrap();

    let r = reopen(s);
    assert_eq!(
        r.node_property_index_state(person, age),
        Some(IndexState::Online),
        "a rolled-back DROP must leave the committed index intact"
    );
    assert_eq!(
        r.node_property_index_name("ix_age"),
        Some((person, age)),
        "a rolled-back DROP must leave the committed index NAME intact"
    );
    assert_eq!(
        r.property_histogram(person, age),
        Some(baseline_hist.as_slice()),
        "a rolled-back DROP must leave the committed histogram intact"
    );
}

/// A checkpoint must never publish a **half-applied** DDL sequence. Dropping an index by target is two
/// store calls (the index, then its name); the durable catalog rejects a name with no index behind it,
/// so a checkpoint landing between the two used to write an image the store cannot reopen at all.
#[test]
fn an_intervening_commit_cannot_bake_a_half_applied_drop() {
    let mut s = fresh(64);

    let t0 = TxnId(1);
    s.begin(t0);
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let age = s.intern_token(Namespace::PropKey, "age").unwrap();
    s.set_node_property_index(t0, person, age, IndexState::Online);
    s.set_node_property_index_name(t0, "ix_age".to_owned(), person, age);
    s.commit(t0).unwrap();

    // B removes the index but NOT (yet) its name — the transient half-applied state.
    let b = TxnId(2);
    s.begin(b);
    s.remove_node_property_index(b, person, age);

    // An unrelated transaction commits right in that window.
    let a = TxnId(3);
    s.begin(a);
    let _ = s.create_node(a).unwrap();
    s.commit(a).unwrap();

    // The store must still reopen: the checkpoint may only ever have written the committed image, in
    // which the index and its name are both present and consistent.
    let r = reopen(s);
    assert_eq!(
        r.node_property_index_state(person, age),
        Some(IndexState::Online),
        "the committed index must be intact — B's half-applied drop was never committed"
    );
    assert_eq!(
        r.node_property_index_name("ix_age"),
        Some((person, age)),
        "the committed index name must be intact and still point at a declared index"
    );
}

// =================================================================================================
// Out-of-order (non-LIFO) aborts on a SHARED catalog entry.
//
// The undo log is a CHAIN: each entry names the generation it superseded. When the newest writer is
// not the first to abort, the older writer's undo correctly DECLINES (it is no longer the entry's last
// writer) — but declining leaves the newer writer's entry still pointing at the declined mutation as
// its predecessor. Unless that link is spliced out, the newer writer's own rollback later restores a
// value written ONLY by the transaction that already aborted: both transactions rolled back, yet a
// value neither committed is live. Same family as the `rmp` #239 non-LIFO prepender-abort defect.
// =================================================================================================

/// Two writers, one entry, aborting newest-last. After both roll back the entry must hold the
/// COMMITTED value — not the value the first-aborting transaction wrote.
#[test]
fn out_of_order_aborts_on_one_entry_restore_the_committed_value() {
    let mut s = fresh(64);

    let t0 = TxnId(1);
    s.begin(t0);
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let age = s.intern_token(Namespace::PropKey, "age").unwrap();
    let committed = vec![0xCCu8];
    s.set_property_histogram(t0, person, age, committed.clone());
    s.commit(t0).unwrap();

    // T1 writes V1, T2 writes V2 over it. Both distinct, both uncommitted.
    let t1 = TxnId(2);
    s.begin(t1);
    s.set_property_histogram(t1, person, age, vec![0x11u8]);
    let t2 = TxnId(3);
    s.begin(t2);
    s.set_property_histogram(t2, person, age, vec![0x22u8]);

    // Abort NEWEST-LAST: T1 first (declines — T2 owns the entry), then T2.
    s.rollback(t1).unwrap();
    s.rollback(t2).unwrap();

    assert_eq!(
        s.property_histogram(person, age),
        Some(committed.as_slice()),
        "after both writers aborted, the entry must hold the committed value — not T1's aborted write"
    );
    let r = reopen(s);
    assert_eq!(
        r.property_histogram(person, age),
        Some(committed.as_slice()),
        "the aborted value must not be durable either"
    );
}

/// The same hole, reached by an interleaved T1/T2/T1 write sequence on one entry, so the declined
/// link is in the middle of a chain the aborting transaction itself extended.
#[test]
fn out_of_order_aborts_unwind_an_interleaved_chain() {
    let mut s = fresh(64);

    let t0 = TxnId(1);
    s.begin(t0);
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let age = s.intern_token(Namespace::PropKey, "age").unwrap();
    let committed = vec![0xCCu8];
    s.set_property_histogram(t0, person, age, committed.clone());
    s.commit(t0).unwrap();

    let t1 = TxnId(2);
    let t2 = TxnId(3);
    s.begin(t1);
    s.begin(t2);
    s.set_property_histogram(t1, person, age, vec![0x11u8]); // T1
    s.set_property_histogram(t2, person, age, vec![0x22u8]); // T2
    s.set_property_histogram(t1, person, age, vec![0x33u8]); // T1 again
    s.set_property_histogram(t2, person, age, vec![0x44u8]); // T2 again

    s.rollback(t1).unwrap();
    s.rollback(t2).unwrap();

    assert_eq!(
        s.property_histogram(person, age),
        Some(committed.as_slice()),
        "an interleaved chain must unwind all the way back to the committed value"
    );
}

/// Three concurrent writers on one entry, aborting in an order that is neither LIFO nor FIFO. Also the
/// only test that drives the `committed_statistics` merge/sort path with a SHARED key.
#[test]
fn three_concurrent_writers_on_one_entry_unwind_in_any_abort_order() {
    for order in [
        [0usize, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let mut s = fresh(64);

        let t0 = TxnId(1);
        s.begin(t0);
        let person = s.intern_token(Namespace::Label, "Person").unwrap();
        let age = s.intern_token(Namespace::PropKey, "age").unwrap();
        let committed = vec![0xCCu8];
        s.set_property_histogram(t0, person, age, committed.clone());
        s.commit(t0).unwrap();

        let txns = [TxnId(2), TxnId(3), TxnId(4)];
        for (i, &t) in txns.iter().enumerate() {
            s.begin(t);
            s.set_property_histogram(t, person, age, vec![0xA0 + u8::try_from(i).unwrap()]);
        }
        for &i in &order {
            s.rollback(txns[i]).unwrap();
        }

        assert_eq!(
            s.property_histogram(person, age),
            Some(committed.as_slice()),
            "abort order {order:?}: three aborted writers must leave the committed value"
        );
        let r = reopen(s);
        assert_eq!(
            r.property_histogram(person, age),
            Some(committed.as_slice()),
            "abort order {order:?}: no aborted value may be durable"
        );
    }
}

/// The chain hole reaching **disk**: T1 aborts out of order, then an unrelated transaction commits
/// while T2 is still open. `committed_statistics` replays the chain to build the durable image, so a
/// holed chain publishes T1's aborted value as though it were committed.
#[test]
fn an_out_of_order_abort_does_not_publish_its_value_through_a_checkpoint() {
    let mut s = fresh(64);

    let t0 = TxnId(1);
    s.begin(t0);
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let age = s.intern_token(Namespace::PropKey, "age").unwrap();
    let committed = vec![0xCCu8];
    s.set_property_histogram(t0, person, age, committed.clone());
    s.commit(t0).unwrap();

    let t1 = TxnId(2);
    s.begin(t1);
    s.set_property_histogram(t1, person, age, vec![0x11u8]);
    let t2 = TxnId(3);
    s.begin(t2);
    s.set_property_histogram(t2, person, age, vec![0x22u8]);

    // T1 aborts out of order; T2 stays open holding the (now-holed) link.
    s.rollback(t1).unwrap();

    // An unrelated transaction commits, driving the catalog checkpoint while T2 is open.
    let t3 = TxnId(4);
    s.begin(t3);
    let _ = s.create_node(t3).unwrap();
    s.commit(t3).unwrap();

    let r = reopen(s);
    assert_eq!(
        r.property_histogram(person, age),
        Some(committed.as_slice()),
        "the checkpoint published a value written only by an aborted transaction"
    );
}

/// After a rollback whose net schema effect is nil, the generation map and the catalog must still
/// agree — the `schema_eq`-equal branch skips `adopt_schema_from`, so nothing else asserts it.
#[test]
fn the_generation_map_and_the_catalog_agree_after_a_no_net_change_rollback() {
    let mut s = fresh(64);

    let t0 = TxnId(1);
    s.begin(t0);
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let age = s.intern_token(Namespace::PropKey, "age").unwrap();
    let committed = vec![0xCCu8];
    s.set_property_histogram(t0, person, age, committed.clone());
    s.commit(t0).unwrap();

    // A bystander keeps the store on the superset-preserve path; T1's own DDL nets out to nothing.
    let idle = TxnId(2);
    s.begin(idle);

    let t1 = TxnId(3);
    s.begin(t1);
    s.set_property_histogram(t1, person, age, vec![0x11u8]);
    s.rollback(t1).unwrap();
    assert_eq!(
        s.property_histogram(person, age),
        Some(committed.as_slice())
    );

    // If the generation map were left stamped with T1's (now-reverted) generation, this second write
    // would record a `prev` chained to a generation the catalog no longer reflects, and its own
    // rollback would restore T1's aborted value.
    let t2 = TxnId(4);
    s.begin(t2);
    s.set_property_histogram(t2, person, age, vec![0x22u8]);
    s.rollback(t2).unwrap();

    assert_eq!(
        s.property_histogram(person, age),
        Some(committed.as_slice()),
        "a later writer's rollback restored a stale generation's value"
    );
    s.rollback(idle).unwrap();
    let r = reopen(s);
    assert_eq!(
        r.property_histogram(person, age),
        Some(committed.as_slice())
    );
}

/// The undo's last-writer test must be an **owner** test, not a value test.
///
/// Two transactions writing the *same* value to the same catalog entry are indistinguishable by value.
/// A value-witnessed undo therefore fires on T2's write when T1 rolls back, silently reverting a write
/// that belongs to T2 — and, because the reverted state then matches the durable image, leaves the
/// catalog undirtied so T2's own commit persists nothing at all.
#[test]
fn a_rollback_does_not_revert_a_concurrent_identical_write() {
    let mut s = fresh(64);

    let t0 = TxnId(1);
    s.begin(t0);
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let age = s.intern_token(Namespace::PropKey, "age").unwrap();
    s.commit(t0).unwrap();

    let identical = vec![9u8, 9, 9, 9];

    // T1 writes a value and stays open.
    let t1 = TxnId(2);
    s.begin(t1);
    s.set_property_histogram(t1, person, age, identical.clone());
    s.set_node_property_index(t1, person, age, IndexState::Online);

    // T2 writes the BYTE-IDENTICAL value over it — the shape two concurrent ANALYZE passes, or two
    // racing `CREATE INDEX ... IF NOT EXISTS`, produce.
    let t2 = TxnId(3);
    s.begin(t2);
    s.set_property_histogram(t2, person, age, identical.clone());
    s.set_node_property_index(t2, person, age, IndexState::Online);

    // T1 rolls back. T2 is now the entry's owner, so nothing of T2's may be reverted.
    s.rollback(t1).unwrap();
    assert_eq!(
        s.property_histogram(person, age),
        Some(identical.as_slice()),
        "T1's rollback reverted T2's identical-valued write (ABA)"
    );
    assert_eq!(
        s.node_property_index_state(person, age),
        Some(IndexState::Online),
        "T1's rollback reverted T2's identical-valued index declaration (ABA)"
    );

    // ...and T2's commit must actually persist it: reverting above would also have left the catalog
    // looking clean, so the commit would take the read-only fast path and write nothing.
    s.commit(t2).unwrap();
    let r = reopen(s);
    assert_eq!(
        r.property_histogram(person, age),
        Some(identical.as_slice()),
        "T2's committed histogram was not persisted"
    );
    assert_eq!(
        r.node_property_index_state(person, age),
        Some(IndexState::Online),
        "T2's committed index declaration was not persisted"
    );
}

/// The sibling of the test above, ending in T2 **rolling back** instead of committing.
///
/// Committing hides the chain hole: T2's own entry is discarded with its `ActiveTxn`, so the link it
/// still holds is never replayed. Rolling back replays it — and if T1's declined mutation was not
/// spliced out of the chain, T2 restores T1's value, leaving a value written only by aborted
/// transactions live and durable.
#[test]
fn identical_concurrent_writes_both_rolling_back_restore_the_committed_value() {
    let mut s = fresh(64);

    let t0 = TxnId(1);
    s.begin(t0);
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let age = s.intern_token(Namespace::PropKey, "age").unwrap();
    let committed = vec![0xCCu8];
    s.set_property_histogram(t0, person, age, committed.clone());
    s.set_node_property_index(t0, person, age, IndexState::Populating);
    s.commit(t0).unwrap();

    let identical = vec![9u8, 9, 9, 9];
    let t1 = TxnId(2);
    s.begin(t1);
    s.set_property_histogram(t1, person, age, identical.clone());
    s.set_node_property_index(t1, person, age, IndexState::Online);
    let t2 = TxnId(3);
    s.begin(t2);
    s.set_property_histogram(t2, person, age, identical.clone());
    s.set_node_property_index(t2, person, age, IndexState::Online);

    s.rollback(t1).unwrap();
    s.rollback(t2).unwrap();

    assert_eq!(
        s.property_histogram(person, age),
        Some(committed.as_slice()),
        "both writers aborted: the committed histogram must be restored"
    );
    assert_eq!(
        s.node_property_index_state(person, age),
        Some(IndexState::Populating),
        "both writers aborted: the committed index STATE must be restored"
    );
    let r = reopen(s);
    assert_eq!(
        r.property_histogram(person, age),
        Some(committed.as_slice()),
        "the aborted histogram must not be durable"
    );
    assert_eq!(
        r.node_property_index_state(person, age),
        Some(IndexState::Populating),
        "the aborted index state must not be durable"
    );
}
