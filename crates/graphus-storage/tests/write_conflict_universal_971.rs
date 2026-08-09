//! The write-write conflict check, universalised (`rmp` #971, `04-technical-design.md` §5.7).
//!
//! Task #967 put the check on the property write path; #971 makes it the **only** concurrency
//! control by retiring the lock table. That retirement is only safe if the check covers every path
//! the lock covered, and an audit of the 289-cell holder × challenger matrix found exactly two cells
//! where it did not — both label writes, both losing a committed write. This file is those two cells
//! plus the error-class defect the same audit surfaced.
//!
//! Run with `cargo test -p graphus-storage --test write_conflict_universal_971`.

use graphus_core::{GraphusError, TxnId, Value};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 256, 1).expect("create store")
}

fn assert_retriable(err: &GraphusError, what: &str) {
    assert!(
        matches!(err, GraphusError::Transaction(_)),
        "{what} must be a RETRIABLE serialization failure, not a storage error: {err:?}"
    );
    assert!(
        format!("{err}").contains("serialization failure"),
        "{what} must name the class the driver retry logic keys on: {err}"
    );
}

/// **The lost update the idempotent no-op hid.**
///
/// `add_label` reads the **live** label word, so a bit another open transaction wrote in place is
/// already visible in it. Testing "already present" against that word and returning `Ok(())` is a
/// dirty read reported as a successful write: when the holder aborts, the label is gone and the
/// transaction that was told it succeeded has lost its write.
///
/// Two transactions are enough. Until `rmp` #971 the only thing that refused the second writer was
/// the lock table at the Cypher seam — which the bulk-import path never passes through at all.
///
/// **Non-vacuity.** Move `ensure_no_conflicting_writer` back below the `next == node.labels` exit in
/// `add_label` and the second `add_label` returns `Ok(())`, both transactions report success, and the
/// final count of nodes carrying the label is **0** instead of 1.
#[test]
fn a_second_writer_of_the_same_label_bit_is_refused_not_silently_dropped() {
    let s = fresh();
    let label = s.intern_token(Namespace::Label, "Extra").expect("intern");

    let setup = TxnId(1);
    s.begin(setup);
    let (n, _) = s.create_node(setup).expect("node");
    s.commit(setup).expect("commit setup");

    let holder = TxnId(2);
    s.begin(holder);
    s.add_label(holder, n, label)
        .expect("the first writer wins");

    let challenger = TxnId(3);
    s.begin(challenger);
    let err = s
        .add_label(challenger, n, label)
        .expect_err("the second writer of the same bit must be refused, not told it succeeded");
    assert_retriable(&err, "a conflicting `add_label`");

    // The holder aborts. Had the challenger been told "already present", the label would now be gone
    // while that transaction believed it had set it.
    s.rollback(holder).expect("the holder aborts");
    assert!(
        !s.node_has_label(n, label).expect("read the label"),
        "the aborted holder's label is gone — which is exactly why the challenger had to be refused"
    );

    // And with the holder resolved, the same write proceeds.
    s.add_label(challenger, n, label)
        .expect("with the holder gone the write proceeds");
    s.commit(challenger).expect("the challenger commits");
    assert!(
        s.node_has_label(n, label).expect("read the label"),
        "the committed label is present"
    );
}

/// The mirror of the test above: `remove_label`'s "already absent" exit hid the same lost update in
/// the other direction — the label stayed standing after the challenger committed its removal.
///
/// **Non-vacuity.** Move the check back below the `next == node.labels` exit in `remove_label` and the
/// second `remove_label` returns `Ok(())`, after which the rollback leaves the label **present**
/// while the committed transaction was told it removed it.
#[test]
fn a_second_remover_of_the_same_label_bit_is_refused_not_silently_dropped() {
    let s = fresh();
    let label = s.intern_token(Namespace::Label, "Extra").expect("intern");

    let setup = TxnId(1);
    s.begin(setup);
    let (n, _) = s.create_node(setup).expect("node");
    s.add_label(setup, n, label).expect("seed the label");
    s.commit(setup).expect("commit setup");

    let holder = TxnId(2);
    s.begin(holder);
    s.remove_label(holder, n, label)
        .expect("the first remover wins");

    let challenger = TxnId(3);
    s.begin(challenger);
    let err = s
        .remove_label(challenger, n, label)
        .expect_err("the second remover of the same bit must be refused");
    assert_retriable(&err, "a conflicting `remove_label`");

    s.rollback(holder).expect("the holder aborts");
    assert!(
        s.node_has_label(n, label).expect("read the label"),
        "the aborted holder's removal is undone — which is why the challenger had to be refused"
    );
}

/// A challenger that meets an entity **tombstoned by an unresolved holder** must be told to retry,
/// not that the entity does not exist.
///
/// The liveness test used to run before the conflict check, so the challenger got
/// `GraphusError::Storage("… not in use")` — which is not retriable at the Bolt seam and does not
/// trigger the statement-level rollback, leaving the refused transaction open. The holder has not
/// committed, so "not in use" is not even true from the challenger's snapshot.
///
/// **Non-vacuity.** Move `ensure_no_conflicting_writer` back below the `is_live_version` test in the
/// three `*_entity_propert*` functions and every assertion below fails on the error class.
#[test]
fn a_challenger_meeting_an_unresolved_tombstone_is_told_to_retry_not_that_it_is_gone() {
    let s = fresh();
    let key = s.intern_token(Namespace::PropKey, "p").expect("intern");
    let label = s.intern_token(Namespace::Label, "L").expect("intern");

    let setup = TxnId(1);
    s.begin(setup);
    let (n, _) = s.create_node(setup).expect("node");
    s.set_node_property_value(setup, n, key, &Value::Integer(1))
        .expect("seed");
    s.commit(setup).expect("commit setup");

    let holder = TxnId(2);
    s.begin(holder);
    s.delete_node(holder, n)
        .expect("the holder tombstones the node");

    let challenger = TxnId(3);
    s.begin(challenger);
    for (what, err) in [
        (
            "a property write",
            s.set_node_property_value(challenger, n, key, &Value::Integer(2))
                .expect_err("must be refused"),
        ),
        (
            "a property removal",
            s.remove_node_property_value(challenger, n, key)
                .expect_err("must be refused"),
        ),
        (
            "a whole-set clear",
            s.clear_node_properties(challenger, n)
                .expect_err("must be refused"),
        ),
        (
            "a label add",
            s.add_label(challenger, n, label)
                .expect_err("must be refused"),
        ),
        (
            "a label removal",
            s.remove_label(challenger, n, label)
                .expect_err("must be refused"),
        ),
    ] {
        assert_retriable(&err, what);
    }
}

/// The bulk-import twin: `set_node_labels` writes the whole label word at once and is the path
/// `graphus-bulk` and the server's bulk loader take. It **never** passed through the Cypher seam
/// where the retired lock table lived, so until `rmp` #971 it had no write-write protection at all.
///
/// If the requested set happens to equal the live word another open transaction just wrote in place,
/// nothing changes, no delta is linked, and the conflict check inside `link_delta` is never reached.
///
/// **Non-vacuity.** Remove the `ensure_no_conflicting_writer` at the top of `set_node_labels` and the
/// second writer returns `Ok(())`, after which the holder's rollback leaves the node with **no**
/// labels while the committed transaction was told it set them.
#[test]
fn a_second_whole_word_label_writer_is_refused_on_the_bulk_import_path() {
    let s = fresh();
    let a = s.intern_token(Namespace::Label, "A").expect("intern");
    let b = s.intern_token(Namespace::Label, "B").expect("intern");

    let setup = TxnId(1);
    s.begin(setup);
    let (n, _) = s.create_node(setup).expect("node");
    s.commit(setup).expect("commit setup");

    let holder = TxnId(2);
    s.begin(holder);
    s.set_node_labels(holder, n, &[a, b])
        .expect("the first writer wins");

    let challenger = TxnId(3);
    s.begin(challenger);
    let err = s
        .set_node_labels(challenger, n, &[a, b])
        .expect_err("the second whole-word writer must be refused, not told it succeeded");
    assert_retriable(&err, "a conflicting `set_node_labels`");

    s.rollback(holder).expect("the holder aborts");
    assert!(
        !s.node_has_label(n, a).expect("read") && !s.node_has_label(n, b).expect("read"),
        "the aborted holder's labels are gone — which is why the challenger had to be refused"
    );
}
