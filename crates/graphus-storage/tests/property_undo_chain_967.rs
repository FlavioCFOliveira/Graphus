//! `rmp` #967 — the property path on the unified undo chain: the invariants that are new with it,
//! and the two failure modes it introduces if they are not held.
//!
//! Every scenario here is **deterministic**: a single-threaded store over the DST substrate
//! (`MemBlockDevice` + `MemLogSink`, the same in-memory device and log every deterministic scenario
//! in this project runs on), driven by an explicit transaction interleaving. Concurrency is expressed
//! as *ordering*, not as threads, so a failure reproduces byte-for-byte on every machine and every
//! run — which is what `CLAUDE.md` requires of a concurrency scenario and what a thread-based test
//! could not give.
//!
//! # The four things under test
//!
//! 1. **The corpse double-free** (`the_corpse_delta_of_an_aborted_overwrite_never_frees_the_restored_chain`).
//!    A live `SetProperty` delta owns the old value's `strings.store` chain, so GC frees it with the
//!    delta. A **corpse** delta — an aborted writer's — names a chain that the abort handed *back* to
//!    the live cell, so freeing it is silent corruption. Nothing in the suite covered this before.
//!
//! 2. **The non-repeatable read, asserted on the EXACT value**
//!    (`an_older_snapshot_reads_the_exact_old_value_never_absent`). The failure this task introduces
//!    is not "the older snapshot sees the new value" — it is that the older snapshot finds the cell
//!    invisible, finds no other record, and reads the property as **absent**. Every "≠ the new value"
//!    assertion passes in that case. Only asserting the exact old value catches it.
//!
//! 3. **The write-conflict check** (`a_second_writer_on_the_same_entity_is_refused_...`), which is
//!    the precondition of the read path's `Stop` rule rather than a policy choice: without it two
//!    transactions interleave deltas on one chain, their commit timestamps can ascend down the chain,
//!    and a snapshot between them stops the walk early and keeps a value it must not see.
//!
//! 4. **Three writers**, which is the smallest history that can express (3): two transactions can
//!    only ever produce a chain whose ordering is trivially correct.
//!
//! Run with `cargo test -p graphus-storage --test property_undo_chain_967`.

use graphus_bufpool::page;
use graphus_core::{GraphusError, HeaderStamp, PageId, Timestamp, TxnId, Value, VersionStamp};
use graphus_io::{BlockDevice, MemBlockDevice, Page};
use graphus_storage::{Namespace, RecordStore, recovery};
use graphus_txn::Snapshot;
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// `HeapBlock`'s payload capacity, as `graphus-storage`'s heap module defines it. Kept as a local
/// constant rather than imported so this test names a *value size*, not an internal.
const BLOCK_PAYLOAD: usize = 48;

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 256, 1).expect("create store")
}

/// Runs one GC pass under a fresh `txn` at `watermark`.
fn gc_at(s: &mut Store, txn: u64, watermark: graphus_core::Timestamp) {
    let t = TxnId(txn);
    s.begin(t);
    s.gc(t, watermark).expect("gc pass");
    s.commit(t).expect("commit gc");
}

/// The value `snapshot` reads for `node`'s property `key`, or `None` if the key is absent to it.
fn value_at(s: &Store, node: u64, key: u32, snapshot: Snapshot) -> Option<Value> {
    let decided = s
        .decision_scan_node_properties(node, snapshot)
        .expect("decision-polarity read");
    let seen = decided.visible_version(key)?;
    Some(
        s.decode_property_value(seen.type_tag, seen.value_inline)
            .expect("decode the visible value"),
    )
}

/// The value the newest committed state holds for `key`.
fn current_value(s: &Store, node: u64, key: u32) -> Option<Value> {
    let snapshot = Snapshot::new(TxnId(9_999), s.snapshot_ts());
    value_at(s, node, key, snapshot)
}

// ===========================================================================================
// 1. The corpse double-free
// ===========================================================================================

/// **THE dangerous line of `rmp` #967**, in the form that makes it observable.
///
/// `free_delta` frees the `strings.store` chain a `SetProperty` delta names. A corpse delta — an
/// aborting transaction's, whose creation undo cleared its `in_use` flag while preserving the body —
/// names the chain that the *same* rollback restored into the live cell. `delta_is_dead` returns
/// `true` for a corpse, so `free_undo_chain` **does** reach `free_delta` with one; without the
/// `in_use()` gate those blocks go on the free list while a live property still reads through them.
///
/// # This test changed subject in `rmp` #968, and the reason is the point
///
/// A corpse only stays **threaded** when another transaction prepended on top of it before it
/// aborted, so its compare-and-set undo no-ops. When this test was written, `D-property-write-conflict`
/// stopped a second *property* writer from doing that — but a `DELETE` could: `delete_node` linked its
/// `RecreateObject` delta through the same chain and was **not** gated, because the check sat on the
/// three property entry points instead of on the chain itself. So the original history was: T2
/// overwrites, T3 deletes on top, T2 aborts (its undo no-ops — T3 owns the head), T3 aborts.
///
/// `rmp` #968 moved the check into [`link_delta`], the single door every delta passes through, because
/// that gap was about to become a wrong read: a label delta lands on the same chain and — unlike a
/// deletion — a label change does not make the entity invisible, so the ascending commit timestamps
/// the interleaving produces would be read, not skipped. The very interleaving this test used to
/// perform is therefore now **refused**, and that refusal is what this test asserts.
///
/// **What that costs, stated plainly.** With no transaction able to prepend onto an open
/// transaction's chain head, an aborting transaction's delta is always still the head at its own
/// rollback, so its compare-and-set undo always fires and the delta is *unlinked*. The threaded-corpse
/// state has no reachable live route left, and `free_delta`'s `in_use()` gate is retained as defence
/// in depth rather than as a reachable path — see `reclaim_aborted_deltas`. This test can no longer
/// exercise that gate, and pretending otherwise by keeping a sequence that now returns an error would
/// be worse than saying so: what it asserts instead is the **stronger** invariant that replaced it,
/// which fails loudly if the guard is ever removed. The lone-abort accounting below is kept because it
/// is still true and still worth pinning; the note that it alone "proves nothing" about the `in_use()`
/// gate remains accurate, and is exactly why the refusal assertion carries the test.
#[test]
fn the_corpse_delta_of_an_aborted_overwrite_never_frees_the_restored_chain() {
    let mut s = fresh();
    let key = s.intern_token(Namespace::PropKey, "blob").expect("intern");

    let first = Value::String("a".repeat(BLOCK_PAYLOAD * 4)); // 4 blocks
    let second = Value::String("b".repeat(BLOCK_PAYLOAD * 2)); // 2 blocks

    let t1 = TxnId(1);
    s.begin(t1);
    let (n, _) = s.create_node(t1).expect("create node");
    s.set_node_property_value(t1, n, key, &first)
        .expect("set the first value");
    s.commit(t1).expect("commit");
    let after_first = s.heap_block_usage().expect("heap usage");
    assert_eq!(after_first, 4, "the first value occupies four blocks");

    // T2 overwrites (allocating a second chain) and stays open.
    let t2 = TxnId(2);
    s.begin(t2);
    s.set_node_property_value(t2, n, key, &second)
        .expect("set the second value");
    assert_eq!(
        s.heap_block_usage().expect("heap usage"),
        6,
        "both chains are allocated while the overwrite is in flight",
    );

    // THE INVARIANT (`rmp` #968): T3 tries to delete the node, which links a `RecreateObject` delta
    // onto the very chain T2 still holds. That is the prepend that used to thread T2's corpse, and it
    // must now be REFUSED — a retriable serialization failure, not a silent interleave. If this ever
    // starts succeeding again, the chain can carry ascending commit timestamps and the read path's
    // early stop becomes a wrong read.
    let t3 = TxnId(3);
    s.begin(t3);
    let refused = s.delete_node(t3, n);
    let err = refused.expect_err(
        "a second transaction must not prepend onto a chain an OPEN transaction holds: without this \
         the deletion path interleaves its delta with T2's and the chain's commit timestamps can \
         ascend, which is exactly what `DeltaVerdict::Stop` assumes cannot happen",
    );
    assert!(
        matches!(err, GraphusError::Transaction(_)),
        "the refusal must be a RETRIABLE serialization failure, so a coordinator retries the \
         transaction instead of surfacing corruption: got {err:?}",
    );
    assert!(
        format!("{err}").contains("write-write conflict"),
        "and it must name the conflict so an operator can act on it: {err}",
    );
    s.rollback(t3).expect("abort the refused delete");

    // NON-VACUITY of the refusal: it must be the *holder* that caused it, not some unrelated error
    // path. The same delete succeeds the moment T2 is no longer open.
    s.rollback(t2).expect("abort the overwrite");
    assert_eq!(
        s.heap_block_usage().expect("heap usage"),
        4,
        "the abort releases the blocks the aborted value allocated, and only those",
    );
    assert_eq!(
        current_value(&s, n, key),
        Some(first.clone()),
        "the abort restores the first value",
    );
    let t5 = TxnId(5);
    s.begin(t5);
    s.delete_node(t5, n)
        .expect("with no open holder the very same deletion is allowed");
    s.rollback(t5).expect("put the node back");

    // GC past the watermark, which is where a wrongly-freed overflow chain would surface.
    let watermark = s.snapshot_ts();
    gc_at(&mut s, 4, watermark);

    assert_eq!(
        s.heap_block_usage().expect("heap usage"),
        4,
        "GC must NOT free the chain the rollback gave back to the live cell — freeing it is a \
         double-free (the `in_use()` gate in `free_delta`)",
    );
    assert_eq!(
        current_value(&s, n, key),
        Some(first.clone()),
        "the value still reads back immediately after GC",
    );

    // Now make a latent double-free observable: consume the free list with fresh overflow values, so
    // any wrongly-freed block is handed to a new owner, and re-read.
    for i in 0..6i64 {
        let t = TxnId(10 + i as u64);
        s.begin(t);
        let (other, _) = s.create_node(t).expect("create node");
        let filler = s
            .intern_token(Namespace::PropKey, &format!("filler{i}"))
            .expect("intern");
        s.set_node_property_value(
            t,
            other,
            filler,
            &Value::String("z".repeat(BLOCK_PAYLOAD * 4)),
        )
        .expect("set filler");
        s.commit(t).expect("commit filler");
    }

    assert_eq!(
        current_value(&s, n, key),
        Some(first),
        "after the freed slots have been handed out, the surviving property must STILL read back \
         its own bytes — this is the assertion a double-free actually fails",
    );

    let report = graphus_storage::check::check_store(&s, &[]).expect("consistency check");
    assert!(
        report.is_consistent(),
        "store consistent after the aborted overwrite + GC: {:?}",
        report.violations,
    );
}

/// The **negative control** for the test above: heap usage must *not* drop while a live snapshot
/// still needs the old value.
///
/// Without this, `the_corpse_delta_...` could be satisfied by a GC that simply never frees an
/// overflow chain at all — which would leak every historical value for the life of the store and
/// still pass an assertion that says "the blocks are still there".
#[test]
fn a_committed_overwrites_old_chain_survives_until_the_watermark_passes_it() {
    let mut s = fresh();
    let key = s.intern_token(Namespace::PropKey, "blob").expect("intern");
    let first = Value::String("a".repeat(BLOCK_PAYLOAD * 4));
    let second = Value::String("b".repeat(BLOCK_PAYLOAD * 2));

    let t1 = TxnId(1);
    s.begin(t1);
    let (n, _) = s.create_node(t1).expect("create node");
    s.set_node_property_value(t1, n, key, &first).expect("set");
    s.commit(t1).expect("commit");
    let before_overwrite = s.snapshot_ts();

    let t2 = TxnId(2);
    s.begin(t2);
    s.set_node_property_value(t2, n, key, &second)
        .expect("overwrite");
    s.commit(t2).expect("commit");
    assert_eq!(
        s.heap_block_usage().expect("heap usage"),
        6,
        "both chains are live: the cell owns the new one, the delta owns the old one",
    );

    // GC at a watermark BELOW the overwrite: an older reader still resolves through the delta.
    gc_at(&mut s, 3, before_overwrite);
    assert_eq!(
        s.heap_block_usage().expect("heap usage"),
        6,
        "the old chain must NOT be freed while a live snapshot can still reconstruct it",
    );
    let old_reader = Snapshot::new(TxnId(90), before_overwrite);
    assert_eq!(
        value_at(&s, n, key, old_reader),
        Some(first),
        "and that snapshot still reads the old value out of it",
    );

    // Once the watermark passes the overwrite, the delta and its chain go.
    let latest = s.snapshot_ts();
    gc_at(&mut s, 4, latest);
    assert_eq!(
        s.heap_block_usage().expect("heap usage"),
        2,
        "GC frees the old chain with the delta that owned it — exactly once, and only then",
    );
    assert_eq!(current_value(&s, n, key), Some(second));
}

// ===========================================================================================
// 2. The non-repeatable read, on the exact value
// ===========================================================================================

/// An older snapshot must read the **exact** previous value — never `None`.
///
/// This is the failure mode `rmp` #967 introduces if the "was absent" delta or the chain walk is
/// wrong: the reader finds the cell (which now holds the new value), finds no reason to trust it,
/// finds no other record, and answers *absent*. `assert_ne!(seen, new_value)` passes in that case;
/// `assert_eq!(seen, old_value)` does not. Both the presence and the value are asserted, over both
/// an overwrite and a removal, and over both owner kinds.
#[test]
fn an_older_snapshot_reads_the_exact_old_value_never_absent() {
    let s = fresh();
    let key = s.intern_token(Namespace::PropKey, "v").expect("intern");
    let rtype = s.intern_token(Namespace::RelType, "R").expect("intern");

    let t1 = TxnId(1);
    s.begin(t1);
    let (a, _) = s.create_node(t1).expect("node a");
    let (b, _) = s.create_node(t1).expect("node b");
    let r = s.create_rel(t1, rtype, a, b).expect("rel").0;
    s.set_node_property_value(t1, a, key, &Value::Integer(1))
        .expect("node set");
    s.set_rel_property_value(t1, r, key, &Value::String("one".to_owned()))
        .expect("rel set");
    s.commit(t1).expect("commit");
    let epoch1 = s.snapshot_ts();

    // Overwrite the node property, remove the relationship property.
    let t2 = TxnId(2);
    s.begin(t2);
    s.set_node_property_value(t2, a, key, &Value::Integer(2))
        .expect("node overwrite");
    assert!(
        s.remove_rel_property_value(t2, r, key).expect("rel remove"),
        "the removal must report that it changed something",
    );
    s.commit(t2).expect("commit");

    let old = Snapshot::new(TxnId(90), epoch1);

    // The node property: the exact previous integer, not absent and not the new one.
    let seen = value_at(&s, a, key, old);
    assert_eq!(
        seen,
        Some(Value::Integer(1)),
        "an older snapshot must read the EXACT previous value; `None` here would mean the property \
         reads as ABSENT, which every `!= new value` assertion would have accepted",
    );

    // The relationship property: same, through the relationship path.
    let decided = s
        .decision_scan_rel_properties(r, old)
        .expect("rel decision read");
    let seen = decided
        .visible_version(key)
        .expect("the older snapshot must still HOLD the relationship key, not read it as absent");
    assert_eq!(
        s.decode_property_value(seen.type_tag, seen.value_inline)
            .expect("decode"),
        Value::String("one".to_owned()),
    );

    // And the current state is what the newest snapshot sees.
    assert_eq!(current_value(&s, a, key), Some(Value::Integer(2)));
    let now = Snapshot::new(TxnId(91), s.snapshot_ts());
    assert!(
        s.decision_scan_rel_properties(r, now)
            .expect("rel decision read")
            .visible_version(key)
            .is_none(),
        "a committed removal makes the relationship key absent to a new reader",
    );
}

// ===========================================================================================
// 3 & 4. Three writers and the write-conflict check
// ===========================================================================================

/// **The three-writer ordering scenario.** T1 writes `a` on the node and stays open; T2 tries to
/// write `b` on the *same* node and would commit first; a reader between the two commits must still
/// see T1's OLD `a`.
///
/// Two transactions can never express this: with only a writer and a reader the chain has one
/// writer's deltas and its ordering is trivially correct. It takes a **third** transaction — the
/// reader holding a snapshot between two writers' commits — for the ordering to matter at all.
///
/// **Without the write-conflict check this test fails**, and that is its non-vacuity proof. Without
/// it, T2's delta is prepended on top of T1's; T2 commits at `ts₂` and T1 at `ts₃ > ts₂`; the chain
/// then reads `T2(ts₂) → T1(ts₃)` — *ascending* — and a reader at `ts₂` stops at T2's delta and
/// keeps T1's uncommitted `a`. Verified by temporarily returning `Ok(())` from
/// `ensure_no_conflicting_writer`, at which point the first assertion below fails (the conflicting
/// write is accepted) and, with the write accepted, the reader sees T1's new value for `a`.
#[test]
fn a_second_writer_on_the_same_entity_is_refused_with_a_retriable_serialization_failure() {
    let s = fresh();
    let ka = s.intern_token(Namespace::PropKey, "a").expect("intern");
    let kb = s.intern_token(Namespace::PropKey, "b").expect("intern");

    let setup = TxnId(1);
    s.begin(setup);
    let (n, _) = s.create_node(setup).expect("create node");
    s.set_node_property_value(setup, n, ka, &Value::Integer(10))
        .expect("seed a");
    s.set_node_property_value(setup, n, kb, &Value::Integer(20))
        .expect("seed b");
    s.commit(setup).expect("commit setup");
    let epoch = s.snapshot_ts();

    // T1 writes `a` and stays open: it now HOLDS the entity.
    let t1 = TxnId(2);
    s.begin(t1);
    s.set_node_property_value(t1, n, ka, &Value::Integer(11))
        .expect("T1 writes a");

    // T2 tries to write a DIFFERENT key on the SAME entity. The check is at entity granularity, so
    // this is refused even though no key collides.
    let t2 = TxnId(3);
    s.begin(t2);
    let err = s
        .set_node_property_value(t2, n, kb, &Value::Integer(21))
        .expect_err("a second writer on a held entity must be refused");
    assert!(
        matches!(err, GraphusError::Transaction(_)),
        "the refusal must be a RETRIABLE serialization failure, not a storage error: {err:?}",
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("serialization failure"),
        "the message must name the class the driver retry logic keys on: {msg}",
    );

    // A removal and a whole-set clear are refused for the same reason and by the same check.
    assert!(matches!(
        s.remove_node_property_value(t2, n, ka),
        Err(GraphusError::Transaction(_))
    ));
    assert!(matches!(
        s.clear_node_properties(t2, n),
        Err(GraphusError::Transaction(_))
    ));
    s.rollback(t2).expect("T2 rolls back");

    // The reader in between still sees the committed state: T1 is open, so neither of its writes is
    // visible, and `b` is untouched because T2 never got to write it.
    let reader = Snapshot::new(TxnId(4), epoch);
    assert_eq!(value_at(&s, n, ka, reader), Some(Value::Integer(10)));
    assert_eq!(value_at(&s, n, kb, reader), Some(Value::Integer(20)));

    // Once T1 commits and releases the entity, T2's successor writes normally — the check refuses a
    // conflict, it does not wedge the entity.
    s.commit(t1).expect("T1 commits");
    let t3 = TxnId(5);
    s.begin(t3);
    s.set_node_property_value(t3, n, kb, &Value::Integer(21))
        .expect("a later writer succeeds once the entity is released");
    s.commit(t3).expect("commit T3");

    assert_eq!(current_value(&s, n, ka), Some(Value::Integer(11)));
    assert_eq!(current_value(&s, n, kb), Some(Value::Integer(21)));
    // And the pre-T1 reader still reads the original pair: the two later commits are both invisible
    // to it, which is exactly what the descending chain lets it conclude in O(1) reads.
    assert_eq!(value_at(&s, n, ka, reader), Some(Value::Integer(10)));
    assert_eq!(value_at(&s, n, kb, reader), Some(Value::Integer(20)));

    let report = graphus_storage::check::check_store(&s, &[]).expect("consistency check");
    assert!(
        report.is_consistent(),
        "store consistent after the refused interleaving: {:?}",
        report.violations,
    );
}

/// The writer that already holds the entity is **not** refused: the check keys on "another
/// transaction", so a transaction writing several properties in a row must go through.
///
/// The positive control for the check itself. A conflict check that refused everything would satisfy
/// the test above perfectly.
#[test]
fn the_holder_of_an_entity_keeps_writing_it() {
    let s = fresh();
    let keys: Vec<u32> = (0..5)
        .map(|i| {
            s.intern_token(Namespace::PropKey, &format!("k{i}"))
                .expect("intern")
        })
        .collect();

    let t = TxnId(1);
    s.begin(t);
    let (n, _) = s.create_node(t).expect("create node");
    for (i, &k) in keys.iter().enumerate() {
        s.set_node_property_value(t, n, k, &Value::Integer(i as i64))
            .expect("a holder writes its own entity");
    }
    // Overwrite them all again, then remove one, then clear the lot — all in the same transaction.
    for (i, &k) in keys.iter().enumerate() {
        s.set_node_property_value(t, n, k, &Value::Integer(100 + i as i64))
            .expect("the holder overwrites");
    }
    assert!(s.remove_node_property_value(t, n, keys[0]).expect("remove"));
    assert_eq!(
        s.clear_node_properties(t, n).expect("clear"),
        4,
        "the clear reports the cells it emptied — the already-empty one is not counted",
    );
    s.commit(t).expect("commit");

    for &k in &keys {
        assert_eq!(current_value(&s, n, k), None, "every key was cleared");
    }
    let report = graphus_storage::check::check_store(&s, &[]).expect("consistency check");
    assert!(
        report.is_consistent(),
        "store consistent after a single writer's full property lifecycle: {:?}",
        report.violations,
    );
}

/// `SET n = map` semantics: the whole previous property set must be reconstructible by an older
/// snapshot, key by key, with the exact values it held.
#[test]
fn clearing_the_property_set_keeps_every_old_value_for_an_older_snapshot() {
    let s = fresh();
    let keys: Vec<u32> = (0..4)
        .map(|i| {
            s.intern_token(Namespace::PropKey, &format!("k{i}"))
                .expect("intern")
        })
        .collect();

    let t1 = TxnId(1);
    s.begin(t1);
    let (n, _) = s.create_node(t1).expect("create node");
    for (i, &k) in keys.iter().enumerate() {
        s.set_node_property_value(t1, n, k, &Value::Integer(i as i64))
            .expect("seed");
    }
    s.commit(t1).expect("commit");
    let before_clear = s.snapshot_ts();

    let t2 = TxnId(2);
    s.begin(t2);
    assert_eq!(s.clear_node_properties(t2, n).expect("clear"), 4);
    s.commit(t2).expect("commit");

    let old = Snapshot::new(TxnId(90), before_clear);
    for (i, &k) in keys.iter().enumerate() {
        assert_eq!(
            value_at(&s, n, k, old),
            Some(Value::Integer(i as i64)),
            "an older snapshot must reconstruct the WHOLE previous property set, key by key",
        );
        assert_eq!(current_value(&s, n, k), None, "and the key is gone now");
    }
}

// ===========================================================================================
// 5. Own-write visibility, through the real early-stopping walk
// ===========================================================================================

/// A transaction must read **its own uncommitted** property write, and it must read it through the
/// production walk — the `InFlight(w) if w == snapshot.owner => Stop` arm of `delta_verdict`.
///
/// # Why this test exists (`rmp` #967 audit)
///
/// Own-write is one of the three isolation semantics `rmp` #967 must preserve, and it was the only
/// one with no end-to-end coverage. Dirty read and the non-repeatable read are exercised above with
/// real transactions; own-write was exercised only over the pure fold with **synthetic** deltas, and
/// every `Snapshot` in this suite otherwise names a spectator owner (`TxnId(90)`, `TxnId(91)`, …), so
/// the owner-match arm was never reached by a real in-flight writer on a real chain.
///
/// The shape matters. Post-#967 the *cell* always holds the newest value, including a writer's own
/// uncommitted one, so a reader that never walks the chain reads own-writes correctly by accident.
/// What decides the answer is where the walk **stops**: the writer's own delta carries the value it
/// overwrote, so applying it would hand the writer back the value it just replaced. That is why the
/// spectator arm is asserted alongside — it is the positive control that proves the delta is really
/// on the chain and really carries the old value, so "the writer sees the new value" is a decision
/// and not an absence of history.
///
/// **Non-vacuity.** Verified by changing that arm to `DeltaVerdict::Apply`: the writer's own read
/// then returns the pre-write value (`Integer(1)` / the short string) and both own-write assertions
/// fail, while the spectator assertions stay green.
#[test]
fn a_writer_reads_its_own_uncommitted_property_write_and_a_spectator_does_not() {
    let s = fresh();
    let key = s.intern_token(Namespace::PropKey, "v").expect("intern");
    let big = s.intern_token(Namespace::PropKey, "big").expect("intern");
    let rtype = s.intern_token(Namespace::RelType, "R").expect("intern");

    // A committed baseline: one inline value, one overflow value, on a node and on a relationship.
    let long_before = "b".repeat(BLOCK_PAYLOAD * 2);
    let t1 = TxnId(1);
    s.begin(t1);
    let (a, _) = s.create_node(t1).expect("node a");
    let (b, _) = s.create_node(t1).expect("node b");
    let r = s.create_rel(t1, rtype, a, b).expect("rel").0;
    s.set_node_property_value(t1, a, key, &Value::Integer(1))
        .expect("seed node");
    s.set_node_property_value(t1, a, big, &Value::String(long_before.clone()))
        .expect("seed overflow");
    s.set_rel_property_value(t1, r, key, &Value::String("one".to_owned()))
        .expect("seed rel");
    s.commit(t1).expect("commit");
    let before = s.snapshot_ts();

    // T2 overwrites both node keys and REMOVES the relationship key, and stays OPEN.
    let t2 = TxnId(2);
    let long_after = "c".repeat(BLOCK_PAYLOAD * 2);
    s.begin(t2);
    s.set_node_property_value(t2, a, key, &Value::Integer(2))
        .expect("own overwrite");
    s.set_node_property_value(t2, a, big, &Value::String(long_after.clone()))
        .expect("own overflow overwrite");
    assert!(
        s.remove_rel_property_value(t2, r, key).expect("own remove"),
        "the removal must report that it changed something",
    );

    // The writer's own snapshot: `ts` is deliberately the PRE-write timestamp, so nothing but the
    // owner match can make the walk stop at T2's deltas. Reading the current `snapshot_ts()` here
    // would let a `Committed(ts) if ts <= snapshot.ts` arm stop the walk for the wrong reason and
    // make the test vacuous.
    let own = Snapshot::new(t2, before);
    assert_eq!(
        value_at(&s, a, key, own),
        Some(Value::Integer(2)),
        "a transaction must see its OWN uncommitted overwrite",
    );
    assert_eq!(
        value_at(&s, a, big, own),
        Some(Value::String(long_after)),
        "including one whose value lives in the overflow heap",
    );
    assert!(
        s.decision_scan_rel_properties(r, own)
            .expect("rel decision read")
            .visible_version(key)
            .is_none(),
        "and its own uncommitted REMOVE: the key is absent to itself",
    );

    // The positive control, on the same chain at the same instant: a spectator at the same `ts` must
    // undo every one of T2's deltas and read the committed baseline back.
    let spectator = Snapshot::new(TxnId(90), before);
    assert_eq!(
        value_at(&s, a, key, spectator),
        Some(Value::Integer(1)),
        "a spectator undoes T2's delta — which is what proves the delta is on the chain",
    );
    assert_eq!(
        value_at(&s, a, big, spectator),
        Some(Value::String(long_before.clone())),
    );
    let decided = s
        .decision_scan_rel_properties(r, spectator)
        .expect("rel decision read");
    let seen = decided
        .visible_version(key)
        .expect("a spectator must still hold the removed relationship key");
    assert_eq!(
        s.decode_property_value(seen.type_tag, seen.value_inline)
            .expect("decode"),
        Value::String("one".to_owned()),
    );

    // After the writer commits, its own reads are unchanged and the spectator's snapshot still reads
    // the baseline — the own-write answer was never an artefact of the transaction being open.
    s.commit(t2).expect("commit T2");
    assert_eq!(current_value(&s, a, key), Some(Value::Integer(2)));
    assert_eq!(
        value_at(&s, a, key, spectator),
        Some(Value::Integer(1)),
        "the pre-write snapshot is still repeatable after the commit",
    );
    assert_eq!(
        value_at(&s, a, big, spectator),
        Some(Value::String(long_before)),
    );

    let report = graphus_storage::check::check_store(&s, &[]).expect("consistency check");
    assert!(
        report.is_consistent(),
        "store consistent after an own-write interleaving: {:?}",
        report.violations,
    );
}

// ===========================================================================================
// 6. Reclamation liveness: a deferred empty cell must still be reclaimed
// ===========================================================================================

/// An empty property cell a GC pass could not free must be freed by a **later** pass, with no further
/// property write to re-arm the sweep.
///
/// # The regression (`rmp` #967 audit)
///
/// `gc_property_chain` frees an empty cell only when the write that emptied it committed at or below
/// the watermark **and** the owner holds no version chain. A pass that meets neither condition frees
/// nothing — which is correct — but the sweep gate (`pending_empty_prop_cells`) used to be cleared
/// unconditionally after every sweep, so that pass also disarmed the gate. The next pass then skipped
/// Phase D entirely and the cell stayed allocated until an unrelated removal re-armed the flag or the
/// store reopened. This is the minimal history that reaches it: one reader-held watermark, one
/// removal, two passes, and no write in between.
///
/// **Non-vacuity.** Verified by restoring the unconditional `self.pending_empty_prop_cells = false;`
/// after the sweep: the second pass then skips Phase D and the final assertion fails with the cell
/// still allocated (`2` used property slots instead of `1`).
#[test]
fn an_empty_cell_deferred_by_the_watermark_is_reclaimed_by_a_later_pass() {
    let mut s = fresh();
    let gone = s.intern_token(Namespace::PropKey, "gone").expect("intern");
    let kept = s.intern_token(Namespace::PropKey, "kept").expect("intern");

    let t1 = TxnId(1);
    s.begin(t1);
    let (n, _) = s.create_node(t1).expect("create node");
    s.set_node_property_value(t1, n, gone, &Value::Integer(1))
        .expect("seed the key that will be removed");
    s.set_node_property_value(t1, n, kept, &Value::Integer(2))
        .expect("seed the key that stays");
    s.commit(t1).expect("commit");
    let before_removal = s.snapshot_ts();
    assert_eq!(
        s.used_prop_slots(),
        2,
        "two cells, one per key, before anything is removed",
    );

    // The removal empties the cell in place and descends the old value onto the node's undo chain.
    let t2 = TxnId(2);
    s.begin(t2);
    assert!(s.remove_node_property_value(t2, n, gone).expect("remove"));
    s.commit(t2).expect("commit");
    assert_eq!(
        s.used_prop_slots(),
        2,
        "the emptied cell keeps its slot: `D-property-removal` rewrites in place",
    );

    // Pass 1 runs at a watermark BELOW the removal — an older reader is still entitled to the value —
    // so the cell is deferred, not freed. This is the pass that used to disarm the sweep gate.
    gc_at(&mut s, 3, before_removal);
    assert_eq!(
        s.used_prop_slots(),
        2,
        "nothing may be freed while a snapshot below the removal is still entitled to the value",
    );
    let old = Snapshot::new(TxnId(90), before_removal);
    assert_eq!(
        value_at(&s, n, gone, old),
        Some(Value::Integer(1)),
        "and that snapshot still reconstructs it",
    );

    // The reader is gone: pass 2 runs at the current timestamp, with NO property write in between to
    // re-arm the gate. Phase F retires the chain, Phase D then sees an unchained owner and frees the
    // cell — provided the gate is still armed.
    let now = s.snapshot_ts();
    gc_at(&mut s, 4, now);
    assert_eq!(
        s.used_prop_slots(),
        1,
        "the deferred empty cell must be reclaimed by the NEXT pass, with no write to re-arm the \
         sweep — otherwise every removal under a long-running reader strands its cell",
    );

    // The surviving key is untouched by the reclamation, and the store is structurally sound.
    assert_eq!(current_value(&s, n, kept), Some(Value::Integer(2)));
    assert_eq!(current_value(&s, n, gone), None);
    let report = graphus_storage::check::check_store(&s, &[]).expect("consistency check");
    assert!(
        report.is_consistent(),
        "store consistent after the deferred reclamation: {:?}",
        report.violations,
    );
}

// ===========================================================================================
// 7. Refusing a pre-#967 image rather than misreading it
// ===========================================================================================

/// A durable image of a store: every mapped device page plus the durable WAL.
type Image = (Vec<(u64, Box<Page>)>, Vec<u8>);

/// Flushes `s` and captures its durable image, exactly as the startup path would find it on disk.
fn capture(s: &mut Store) -> Image {
    s.flush().expect("flush");
    let pages = s
        .mapped_pages()
        .into_iter()
        .map(|p| (p.0, s.read_device_page(p).expect("read page")))
        .collect();
    let log = s.with_wal(|w| w.sink().durable_bytes().to_vec());
    (pages, log)
}

/// Materialises `image` onto a device + WAL, recovers it, and opens it — the production
/// stage → `recover_device` → `RecordStore::open` sequence, with the open's `Result` handed back
/// instead of unwrapped so a **refusal** can be asserted.
fn open_image(image: &Image) -> Result<Store, GraphusError> {
    let (pages, log) = image;
    let max = pages.iter().map(|(i, _)| *i).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    for (idx, bytes) in pages {
        device.write_page(PageId(*idx), bytes).expect("stage page");
    }
    device.sync_all().expect("persist");

    let mut sink = MemLogSink::new();
    sink.append(log);
    sink.sync().expect("sync log");
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recovery::recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, 256)
}

/// Rewrites `image`'s metadata page into a genuine catalog of format version `target` (1, 2 or 5).
///
/// Both surgeries produce a real image rather than a mutilated one, because of how the catalog is
/// laid out (`meta.rs::encode`):
///
/// * **version 1** — the undo-area block is the catalog's *trailing* block and every earlier block is
///   byte-identical across versions, so a pre-`rmp`-#966 image is precisely this image with the block
///   cut off. Truncating the head page's chunk length at the block's magic word does exactly that,
///   and drops the version flag from the length word, which is what that build wrote.
/// * **version 2** — the block's layout has not changed since #966; `rmp` #967 changed what a
///   property cell *means*, not where anything sits. So a version-2 image is this image with `2` in
///   the version word after the magic, which is exactly what an unreleased build between #966 and
///   #967 wrote.
fn downgrade_catalog_to(image: &mut Image, target: u32) {
    let meta = &mut image
        .0
        .iter_mut()
        .find(|(id, _)| *id == 0)
        .expect("the metadata page is page 0")
        .1;
    let len_at = page::HEADER_SIZE;
    let chunk_at = len_at + 12;
    let framed = u32::from_le_bytes(meta[len_at..len_at + 4].try_into().expect("4 bytes"));
    let chunk_len = (framed & 0x7fff_ffff) as usize;
    let next = u64::from_le_bytes(meta[len_at + 4..len_at + 12].try_into().expect("8 bytes"));
    assert_eq!(
        next, 0,
        "this fixture's catalog must fit in the head page; a continuation chain would need the \
         surgery applied to the tail page instead",
    );
    let magic_at = meta[chunk_at..chunk_at + chunk_len]
        .windows(8)
        .position(|w| w == b"GRPHUNDO")
        .expect("a current-version catalog carries the undo-area magic");
    match target {
        // Version 1: cut the trailing block off, which is literally what a pre-#966 image is.
        1 => meta[len_at..len_at + 4].copy_from_slice(&(magic_at as u32).to_le_bytes()),
        // Version 2: keep the undo-area block — its layout is unchanged since #966 — and write 2
        // into the version word that follows the magic. Between a version-2 and a version-3 image
        // that number is the ONLY difference, which is exactly why it had to be bumped for
        // `rmp` #967.
        //
        // It is no longer the only surgery, though (`rmp` #1066). A version-4 image carries a
        // TRAILING applied-transaction-set block after the undo-area one, and no version-2 build
        // ever wrote such a thing — so an image that declares 2 and still carries it is not a
        // forgery of a version-2 store, it is a self-contradictory image, and `Meta::decode`
        // rightly refuses it before any of the #967 gate's semantics are reached. Cutting the block
        // off is what makes the forgery faithful again, and it is the same cut the version-1 arm
        // above already performs (that arm truncates at the undo-area magic, so it removes both
        // blocks at once and needed no change).
        2 => {
            let ver_at = chunk_at + magic_at + 8;
            meta[ver_at..ver_at + 4].copy_from_slice(&2u32.to_le_bytes());
            let counts_at = meta[chunk_at..chunk_at + chunk_len]
                .windows(8)
                .position(|w| w == b"GRPHCNTD")
                .expect("a current-version catalog carries the applied-counts magic");
            // The high bit of the framed length is the format flag that makes a pre-#966 build
            // refuse the head page, and a version-2 image DOES carry it — only the version-1 arm
            // above clears it, deliberately. Truncating must therefore preserve whatever flag bits
            // were already there; writing the bare length would silently forge a version-1 header
            // on an image whose block says 2.
            let truncated = (counts_at as u32) | (framed & 0x8000_0000);
            meta[len_at..len_at + 4].copy_from_slice(&truncated.to_le_bytes());
        }
        // Version 5: write 5 into the version word and cut NOTHING (`rmp` #1069). Version 6 adds no
        // block and moves no byte — it changes what an unsettled MVCC stamp MEANS — so a version-5
        // image is byte-for-byte this image with a different number, which is exactly the property
        // that made the bump mandatory. Note what this arm deliberately does NOT do: it does not
        // touch the framed length, so the format flag bit in its high bit is preserved. Clearing it
        // would forge a version-1 header onto an image whose block says 5, and the fixture would be
        // testing its own self-contradiction instead of the gate.
        5 => {
            let ver_at = chunk_at + magic_at + 8;
            meta[ver_at..ver_at + 4].copy_from_slice(&5u32.to_le_bytes());
        }
        other => panic!("this fixture only forges versions 1, 2 and 5, not {other}"),
    }
    page::write_checksum(meta);
}

/// Builds a store holding one node with one property, with **no surviving undo chain** (a GC pass at
/// the current timestamp retires it), and returns it together with the physical id of the property
/// cell. That is the shape a pre-#967 store had: cells, and no version chains at all.
fn legacy_shaped_store(key_name: &str) -> (Store, u64, u32) {
    let mut s = fresh();
    let key = s
        .intern_token(Namespace::PropKey, key_name)
        .expect("intern");
    let t1 = TxnId(1);
    s.begin(t1);
    let (n, _) = s.create_node(t1).expect("create node");
    s.set_node_property_value(t1, n, key, &Value::Integer(7))
        .expect("set");
    s.commit(t1).expect("commit");
    // Retire the node's version chain, so the image really is chain-free like a version-1 store.
    let now = s.snapshot_ts();
    gc_at(&mut s, 2, now);
    let cells = s
        .superset_scan_node_property_values(n)
        .expect("superset scan");
    assert_eq!(cells.len(), 1, "one cell, one key, no history left");
    (s, cells[0].0, key)
}

/// **A pre-#967 store must be REFUSED, not misread.**
///
/// # The hazard
///
/// A released build (v0.0.10 and earlier) recorded a committed `REMOVE n.p` as one property cell left
/// `in_use` with `expired_ts` stamped and **its value intact**; visibility came from that header.
/// This build no longer reads it — `DecisionFold::seed` filters on `type_tag` and
/// `collect_prop_chain` admits every `in_use` cell — so such a store would read every committed
/// removal back as a live property, reject the next `SET` on those keys for ever
/// (`write_prop_cell` fails closed on a non-zero `expired_ts`), and never reclaim the slots. Nothing
/// else stops it: `Meta::decode` accepts a version-1 image as an explicit lossless upgrade, and no
/// property-chain migration exists.
///
/// # What is forged, and what is not
///
/// The two things the gate keys on are forged for real: a legacy catalog (version 1 by cutting the
/// trailing undo-area block, version 2 by writing `2` into the block's version word — those are
/// literally the two differences) and a stamped `expired_ts` on a live property cell, which this
/// build's write path can no longer produce, hence the dedicated forging accessor. The image is
/// otherwise a real store, recovered through the real `recover_device` → `open` path.
///
/// # Both legacy versions, because both carry the hazard
///
/// Version 1 is what every released build writes. Version 2 is what an unreleased build between
/// `rmp` #966 and #967 writes: #966 bumped the version for the undo area while the property path was
/// still tombstone-and-prepend. #967 bumped it again to 3 precisely so this gate has something to key
/// on — versions 2 and 3 are byte-identical apart from that number.
///
/// **Non-vacuity.** Per legacy version, two controls: the same image WITHOUT the stamp opens and
/// reports that exact version (so the gate is selective, not "refuse every legacy store"), and the
/// data reads back intact (so the upgrade it allows is really lossless). Across versions, a third:
/// the same stamp in a **version-3** image opens, proving the refusal is the version gate firing and
/// not the stamp tripping something else — and the consistency checker is then shown to catch that
/// image instead, which is the second tier. Verified additionally by making
/// `refuse_legacy_property_tombstones` return `Ok(())` unconditionally, at which point the refusal
/// assertion fails with a store that opened.
#[test]
fn a_legacy_store_carrying_a_property_tombstone_is_refused_at_open() {
    // ---- The cross-version control: a CURRENT-version image with the same stamp OPENS. ----
    // The gate is version-scoped, so the refusals below are attributable to the version and to
    // nothing else. A tombstone in a version-3 image is a state no version number can describe and
    // only a bug could produce; the checker is the tier that catches it.
    let (mut s, prop_id, _key) = legacy_shaped_store("v");
    let t = TxnId(3);
    s.begin(t);
    s.stamp_property_tombstone_for_test(t, prop_id, VersionStamp::committed(Timestamp(2)))
        .expect("forge the pre-#967 tombstone");
    s.commit(t).expect("commit the forged stamp");
    let current = capture(&mut s);
    drop(s);

    let v3 = open_image(&current).expect("a current-version image is not refused by this gate");
    assert_eq!(
        v3.opened_format_version(),
        graphus_core::constants::FORMAT_VERSION,
    );
    let report = graphus_storage::check::check_store(&v3, &[]).expect("consistency check");
    assert!(
        !report.is_consistent(),
        "the second tier must catch what the open-time gate deliberately does not: {:?}",
        report.violations,
    );
    let flagged = format!("{:?}", report.violations);
    assert!(
        flagged.contains("PropertyCellTombstoned"),
        "and it must name the property tombstone specifically: {flagged}",
    );
    drop(v3);

    // ---- Every legacy version: tombstoned is REFUSED, tombstone-free still OPENS. ----
    for legacy in [1u32, 2] {
        let mut tombstoned = current.clone();
        downgrade_catalog_to(&mut tombstoned, legacy);
        let err = open_image(&tombstoned).err().unwrap_or_else(|| {
            panic!("a version-{legacy} image carrying a property tombstone MUST be refused")
        });
        let msg = format!("{err}");
        for expected in [
            "refusing to open",
            &format!("format version {legacy}"),
            "props.store record",
            "D-property-visibility",
            "graphus-bulk dump",
        ] {
            assert!(
                msg.contains(expected),
                "the refusal must be actionable — missing {expected:?} in: {msg}",
            );
        }
        // The provenance must be TRUE for this version, not merely present: pointing a version-2
        // operator at v0.0.10 would send them to a build that cannot open their store at all.
        if legacy == 1 {
            assert!(
                msg.contains("v0.0.10"),
                "a version-1 store was written by a released build, and the message must say so: \
                 {msg}",
            );
        } else {
            assert!(
                msg.contains("unreleased build") && !msg.contains("v0.0.10"),
                "a version-2 store was NOT written by a released build, and the message must not \
                 claim it was: {msg}",
            );
        }

        // The control: the SAME downgrade WITHOUT the stamp must open cleanly, at that version, with
        // its data intact. A gate that refused every legacy store would satisfy the assertion above
        // perfectly.
        let (mut clean, _, key) = legacy_shaped_store("v");
        let mut clean_image = capture(&mut clean);
        drop(clean);
        downgrade_catalog_to(&mut clean_image, legacy);
        let opened = open_image(&clean_image)
            .unwrap_or_else(|e| panic!("a tombstone-free version-{legacy} image must open: {e}"));
        assert_eq!(
            opened.opened_format_version(),
            legacy,
            "and it really is being read as a version-{legacy} image",
        );
        let node = opened.scan_node_ids().expect("scan")[0];
        assert_eq!(
            current_value(&opened, node, key),
            Some(Value::Integer(7)),
            "with its data intact — the upgrade is lossless, which is why it is allowed",
        );
    }
}

// ===========================================================================================
// 8. Refusing a pre-#1069 image rather than misreading its MVCC stamps
// ===========================================================================================
//
// These live beside the #967 gate rather than in a file of their own because they need the same
// apparatus — `capture`, `open_image`, `downgrade_catalog_to` — and that apparatus is the whole
// point: forging a genuine older image, not a mutilated one, is what makes a version gate testable
// at all. The two gates are also the same class of defect (`04 §5.2`, `05 §12.6`): identical bytes,
// changed meaning.

/// A store whose in-use records still carry **unsettled** MVCC stamps: one committed node with one
/// property, and **no GC pass**, so nothing has been settled to a commit timestamp.
///
/// This is the shape the `rmp` #1069 gate must catch. It is deliberately the opposite of
/// [`legacy_shaped_store`], whose GC pass settles every stamp — that one is the control.
fn unsettled_store(key_name: &str) -> (Store, u32) {
    let s = fresh();
    let key = s
        .intern_token(Namespace::PropKey, key_name)
        .expect("intern");
    let t1 = TxnId(1);
    s.begin(t1);
    let (n, _) = s.create_node(t1).expect("create node");
    s.set_node_property_value(t1, n, key, &Value::Integer(7))
        .expect("set");
    s.commit(t1).expect("commit");
    // NO gc: the node's and the cell's `created_ts` still name `t1`'s commit slot.
    (s, key)
}

/// Every in-use record of the three MVCC stores whose `created_ts`/`expired_ts` is unsettled.
fn unsettled_count(s: &Store) -> usize {
    let mut n = 0;
    for id in s.scan_node_ids().expect("scan nodes") {
        let m = s.node(id).expect("node").mvcc;
        n += usize::from(HeaderStamp::from_raw(m.created_ts).slot_id().is_some());
        n += usize::from(HeaderStamp::from_raw(m.expired_ts).slot_id().is_some());
    }
    n
}

/// **`rmp` #1069 phase 3.** An image written before the bump, still carrying an unsettled MVCC
/// stamp, must be **refused** at open — and an image written before the bump that is fully settled
/// must **open**, because nothing in it can be misread.
///
/// # What the refusal prevents
///
/// Before version 6 an unsettled `created_ts`/`expired_ts` held the writer's `TxnId`; from version 6
/// it holds the physical id of that writer's slot in `commit.store`. The encodings are
/// byte-identical, so this build would resolve such a stamp against whatever transaction happens to
/// own the slot numbered like the old writer's id: a committed version read as absent, an aborted
/// one read as present, or a hard read fault. Silent misattribution of committed data — the class
/// the version-3 gate exists for, applied to the other half of the header.
///
/// # Non-vacuity, three controls
///
/// 1. **Selectivity within the version.** The same forged version-5 image with every stamp SETTLED
///    opens, at that version, with its data intact. A gate that refused every legacy store would
///    pass the refusal assertion perfectly and fail this one.
/// 2. **Selectivity across versions.** The same UNSETTLED image at the CURRENT version opens and
///    reads correctly, so the refusal is attributable to the version number and to nothing else.
/// 3. **The subject really is present.** The unsettled image is asserted to carry at least one
///    unsettled stamp before it is forged, so the refusal cannot be passing on an empty scan.
#[test]
fn a_pre_1069_image_carrying_an_unsettled_stamp_is_refused_at_open() {
    // ---- Control 3 + control 2: the CURRENT-version unsettled image opens and reads correctly. ----
    let (mut s, key) = unsettled_store("v");
    assert!(
        unsettled_count(&s) > 0,
        "the fixture must actually carry an unsettled stamp, or the refusal below proves nothing",
    );
    let unsettled = capture(&mut s);
    drop(s);

    let current =
        open_image(&unsettled).expect("a current-version image is not refused by this gate");
    assert_eq!(
        current.opened_format_version(),
        graphus_core::constants::FORMAT_VERSION,
    );
    let node = current.scan_node_ids().expect("scan")[0];
    assert_eq!(
        current_value(&current, node, key),
        Some(Value::Integer(7)),
        "and it reads correctly, because its stamps name slots this build understands",
    );
    drop(current);

    // ---- The refusal: the same image, forged as version 5. ----
    let mut forged = unsettled.clone();
    downgrade_catalog_to(&mut forged, 5);
    let err = open_image(&forged)
        .err()
        .expect("a version-5 image carrying an unsettled MVCC stamp MUST be refused");
    let msg = format!("{err}");
    for expected in [
        "refusing to open",
        "format version 5",
        "WRITER'S TRANSACTION ID",
        "commit.store",
        "force a full freeze",
    ] {
        assert!(
            msg.contains(expected),
            "the refusal must be actionable — missing {expected:?} in: {msg}",
        );
    }
    assert!(
        msg.contains("Node store record") || msg.contains("Prop store record"),
        "and it must name the first offending record: {msg}",
    );

    // ---- Control 1: the SAME forgery over a fully SETTLED image opens, with its data intact. ----
    let (mut clean, _prop, clean_key) = legacy_shaped_store("v");
    assert_eq!(
        unsettled_count(&clean),
        0,
        "the control image must be fully settled, or it is not a control",
    );
    let mut clean_image = capture(&mut clean);
    drop(clean);
    downgrade_catalog_to(&mut clean_image, 5);
    let opened = open_image(&clean_image)
        .unwrap_or_else(|e| panic!("a fully settled version-5 image must open: {e}"));
    assert_eq!(
        opened.opened_format_version(),
        5,
        "and it really is being read as a version-5 image",
    );
    let node = opened.scan_node_ids().expect("scan")[0];
    assert_eq!(
        current_value(&opened, node, clean_key),
        Some(Value::Integer(7)),
        "with its data intact — the upgrade is lossless, which is why it is allowed",
    );
}
