//! **`rmp` #1069 phase 3 — the record header names the commit slot, so there is ONE commit oracle.**
//!
//! Until this phase the engine carried two. An undo delta resolved its commit status through the
//! **durable** slot in `commit.store`; a record header carried the writer's `TxnId`, translatable
//! only by the **in-memory** [`CommitRegistry`](graphus_txn::CommitRegistry). Everything expensive
//! about MVCC bookkeeping followed from that second oracle being volatile: an `O(N)` freeze sweep to
//! rewrite stamps before the table could be pruned, a freeze frontier to bound it, and a WAL
//! retention floor so a crash could rebuild the table.
//!
//! The header now names the slot. This file pins what that buys, in the one experiment that could
//! not be written before it: **destroy the in-memory table's entry for a committed writer and read
//! the row anyway.**
//!
//! Two more properties are pinned beside it, because each is a way the change could have been made
//! wrongly and still looked right:
//!
//! * the reserved `SYSTEM_TXN` never acquires a commit slot (its arithmetic impossibility
//!   evaporated with the encoding change — see `RecordStore::commit_slot_for`);
//! * a header naming a slot that does not decode **fails the read closed**, never guesses (`rmp`
//!   #733).

use graphus_core::{HeaderStamp, TxnId, Value};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore, StoreKind};
use graphus_txn::{CommitOracle, Snapshot, StampOutcome, TxnOutcome, is_visible_via};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 64, 1).expect("create store")
}

/// A snapshot belonging to an uninvolved reader, at the store's latest commit.
fn spectator(s: &Store) -> Snapshot {
    Snapshot::new(TxnId(u64::MAX - 1), s.snapshot_ts())
}

/// **The test that was impossible to write before `rmp` #1069 phase 3 (acceptance criterion 1).**
///
/// A transaction commits a node with a property. No GC runs, so no stamp is settled: the records
/// still carry an *unsettled* header stamp. Its writer is then **erased from the in-memory
/// Active/Recent Transaction Table** — the state the pre-phase-3 engine went to considerable expense
/// to make unreachable, because reaching it meant losing the data.
///
/// # Why it failed before, and what it proves now
///
/// Before phase 3 the stamp held the writer's `TxnId`, and
/// [`CommitRegistry::outcome`](graphus_txn::CommitRegistry) maps an id it does not know to
/// [`TxnOutcome::Aborted`]. Erase the entry and the committed version resolves as aborted, i.e.
/// **invisible**: the row disappears, silently, with no error and no corruption anywhere on disk.
/// That is exactly the shape of `rmp` #522, and it is why the freeze sweep had to settle every stamp
/// *before* the table could be pruned, why the frontier had to be exact, and why the WAL floor had
/// to retain the commit records that rebuild the table after a crash.
///
/// Since phase 3 the stamp names a slot in `commit.store`, which is durable and which no in-memory
/// pruning can touch. The row stays. That is the whole phase, expressed as one assertion.
///
/// # And why the AC 2 equivalence audit stays silent through it
///
/// That audit asserts the pre-phase-3 registry reaches the same *verdict* as the slot. Here it
/// deliberately cannot: the writer has been erased, so the registry has no answer to preserve — only
/// its documented `Aborted` default, which is not a verdict about this store. The audit is scoped to
/// writers it **recorded** or that are still **active**, so it skips this word rather than firing.
/// That scope is not a concession to this test: the deterministic backup/restore scenarios reach the
/// same state through the front door, because a restore carries the data image and not the log.
#[test]
fn a_committed_version_survives_the_registry_forgetting_its_writer() {
    let s = fresh();
    let key = s.intern_token(Namespace::PropKey, "v").expect("intern");
    let writer = TxnId(1);
    s.begin(writer);
    let (node, _eid) = s.create_node(writer).expect("create node");
    s.set_node_property_value(writer, node, key, &Value::Integer(42))
        .expect("set property");
    s.commit(writer).expect("commit");

    // The premise: no GC has run, so the header is UNSETTLED and names the writer's commit slot.
    // Without this the test would be vacuous — a settled header needs no oracle at all.
    let mvcc = s.node(node).expect("read node").mvcc;
    let slot = HeaderStamp::from_raw(mvcc.created_ts)
        .slot_id()
        .expect("the committed version's xmin is still unsettled and names a commit slot");
    assert_eq!(
        s.names_writer(mvcc.created_ts).expect("resolve writer"),
        Some(writer),
        "and the slot attributes it to the transaction that created it",
    );
    assert!(
        matches!(
            s.resolve_stamp(mvcc.created_ts).expect("resolve stamp"),
            StampOutcome::Committed(_)
        ),
        "the durable slot says the writer committed",
    );

    // Destroy the ONLY thing that could have translated a pre-#1069 stamp.
    s.forget_committed_writer_for_test(writer);
    assert_eq!(
        s.commit_registry().outcome(writer),
        TxnOutcome::Aborted,
        "an id the table does not know reads as aborted — the mechanism that used to lose the row",
    );

    // The row is still there, and still says 42.
    {
        let snap = spectator(&s);
        assert!(
            is_visible_via(&s, snap, mvcc.created_ts, mvcc.expired_ts).expect("resolve visibility"),
            "the committed version must stay visible: the commit slot, not the in-memory table, is \
             the oracle since rmp #1069 phase 3",
        );
        assert!(
            s.entity_visible_at(StoreKind::Node, node, mvcc, snap)
                .expect("existence at snapshot"),
            "and the statement-granular existence path must agree",
        );
        let cand = s
            .decision_scan_node_properties(node, snap)
            .expect("decision scan")
            .visible_version(key)
            .expect("the property must still be readable");
        assert_eq!(
            s.decode_property_value(cand.type_tag, cand.value_inline)
                .expect("decode the value"),
            Value::Integer(42),
            "and it must still say 42",
        );
        // The outcome is still resolvable too, from the slot alone.
        assert!(
            s.resolve_commit_ts(mvcc.created_ts)
                .expect("resolve commit ts")
                .is_some(),
            "the commit timestamp is recoverable with no in-memory state whatsoever",
        );
    }

    // And the slot it names is still the one it named: nothing recycled it under the reader.
    assert_eq!(
        HeaderStamp::from_raw(s.node(node).expect("re-read node").mvcc.created_ts).slot_id(),
        Some(slot),
    );
}

/// The reserved `SYSTEM_TXN` must never own a commit slot (`rmp` #1069 phase 3).
///
/// Before the phase this was **arithmetically impossible**: `SYSTEM_TXN` is `TxnId(u64::MAX)` and a
/// header carried `VersionStamp::in_flight(txn)`, which asserts the id fits in 63 bits — so stamping
/// one panicked, and that is why it never happened. A header now carries a small, perfectly
/// encodable slot id, so the barrier evaporated and had to be restated deliberately at the single
/// door a slot is born at.
///
/// It matters because `SYSTEM_TXN` neither commits nor aborts: it writes only the catalog and is
/// never in the active set. A header naming its slot would be unresolvable **for ever** — not
/// "invisible", which is at least an answer, but a hard read fault on every access to that record,
/// because the door fails closed (`rmp` #733). One reserved id would poison a row permanently.
#[test]
fn the_system_transaction_never_acquires_a_commit_slot() {
    let s = fresh();
    // Everything `SYSTEM_TXN` legitimately does — the catalog checkpoint the store takes on create
    // and on flush — must leave `commit.store` untouched by it. The direct assertion is that no
    // in-use record anywhere names a slot whose owner is the reserved id.
    s.flush().expect("flush");
    let writer = TxnId(1);
    s.begin(writer);
    let (node, _) = s.create_node(writer).expect("create node");
    s.commit(writer).expect("commit");
    s.flush().expect("flush again");

    let mvcc = s.node(node).expect("read node").mvcc;
    for word in [mvcc.created_ts, mvcc.expired_ts] {
        if let Some(w) = s.names_writer(word).expect("resolve writer") {
            assert_ne!(
                w,
                TxnId(u64::MAX),
                "no record header may name the reserved SYSTEM_TXN's commit slot",
            );
        }
    }
}

/// A header naming a slot that was never written **fails the read closed** (`rmp` #733).
///
/// The door is fallible for exactly this reason. An unresolvable existence question must abort the
/// read, never be answered with a default — "invisible" would be silent data loss and "visible"
/// would be a dirty read, and both look like data rather than like a fault.
#[test]
fn a_header_naming_an_unwritten_slot_fails_the_read_closed() {
    let s = fresh();
    // A slot id far beyond anything `commit.store` has allocated.
    let bogus = HeaderStamp::slot(1 << 40);
    let err = s
        .resolve_stamp(bogus)
        .expect_err("an unresolvable stamp must be an error, never a verdict");
    let msg = format!("{err}");
    assert!(
        msg.contains("outside") || msg.contains("never written"),
        "and the error must say which slot could not be resolved: {msg}",
    );
    // The whole visibility predicate propagates it rather than folding it into `false`.
    assert!(
        is_visible_via(&s, spectator(&s), bogus, 0).is_err(),
        "is_visible_via must propagate the fault, not answer `invisible`",
    );
}
