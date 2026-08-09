//! `RecordStore::uncommitted_data_writer` — the "is the committed image decidable right now?"
//! predicate (`rmp` task #902).
//!
//! The constraint DDL judges existing data and never re-checks its decision, so it must refuse rather
//! than decide while another transaction holds writes that may still be rolled back (or may still
//! commit). This pins the predicate that gates that refusal:
//!
//! * a transaction that has written **nothing** is invisible to it — an open reader must not be able
//!   to block a schema change;
//! * every kind of data write makes its transaction visible to it, including a **label-only** change,
//!   which writes no record version at all (it mutates the node's bitmap in place, `rmp` #767) and is
//!   therefore the one a footprint check is most likely to miss;
//! * it clears on both commit and rollback;
//! * with several writers open it reports the **lowest** id, deterministically — `active` is a
//!   `HashMap`, and a non-deterministic answer would leak into an error message, a test, and DST
//!   replay.

use graphus_core::TxnId;
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 64, 1).expect("create store")
}

/// Creates one committed node and returns its physical id, so a later transaction has something to
/// mutate without creating a record of its own.
fn committed_node(store: &mut Store) -> u64 {
    let txn = TxnId(1);
    store.begin(txn);
    let (id, _eid) = store.create_node(txn).expect("create node");
    store.commit(txn).expect("commit");
    id
}

#[test]
fn a_store_with_no_open_transaction_has_no_uncommitted_writer() {
    let store = fresh();
    assert_eq!(store.uncommitted_data_writer(), None);
}

#[test]
fn an_open_transaction_that_has_written_nothing_is_not_a_writer() {
    let store = fresh();
    store.begin(TxnId(7));
    assert_eq!(
        store.uncommitted_data_writer(),
        None,
        "a read-only transaction holds no uncommitted state and must not gate a schema change"
    );
}

#[test]
fn a_created_record_makes_its_transaction_a_writer() {
    let store = fresh();
    store.begin(TxnId(7));
    let _ = store.create_node(TxnId(7)).expect("create node");
    assert_eq!(store.uncommitted_data_writer(), Some(TxnId(7)));
}

#[test]
fn a_property_write_on_a_committed_node_makes_its_transaction_a_writer() {
    let mut store = fresh();
    let node = committed_node(&mut store);
    assert_eq!(store.uncommitted_data_writer(), None, "precondition");

    // Interned in a transaction of its own, so the writer below starts with a clean footprint.
    let key = {
        store.begin(TxnId(2));
        let key = store
            .intern_token(Namespace::PropKey, "email")
            .expect("intern");
        store.commit(TxnId(2)).expect("commit");
        key
    };

    store.begin(TxnId(3));
    store
        .set_node_property_value(TxnId(3), node, key, &graphus_core::Value::Integer(1))
        .expect("set property");
    assert_eq!(
        store.uncommitted_data_writer(),
        Some(TxnId(3)),
        "an uncommitted SET is exactly the state the constraint DDL must not judge"
    );
}

/// The one a footprint check is most likely to miss: a relabel writes **no record version**, it
/// perturbs the node's inline bitmap in place (`rmp` #767), so it can only be seen through the
/// transaction's `labelled_nodes` list.
#[test]
fn a_label_only_change_makes_its_transaction_a_writer() {
    let mut store = fresh();
    let node = committed_node(&mut store);

    let token = {
        store.begin(TxnId(2));
        let t = store
            .intern_token(Namespace::Label, "Person")
            .expect("intern");
        store.commit(TxnId(2)).expect("commit");
        t
    };

    store.begin(TxnId(3));
    store.add_label(TxnId(3), node, token).expect("add label");
    assert_eq!(
        store.uncommitted_data_writer(),
        Some(TxnId(3)),
        "an in-place label change is a data write with no record version — it must still be seen"
    );
}

#[test]
fn a_delete_makes_its_transaction_a_writer() {
    let mut store = fresh();
    let node = committed_node(&mut store);

    store.begin(TxnId(3));
    store.delete_node(TxnId(3), node).expect("delete node");
    assert_eq!(store.uncommitted_data_writer(), Some(TxnId(3)));
}

#[test]
fn resolving_the_writer_clears_it_whichever_way_it_resolves() {
    for commit in [true, false] {
        let store = fresh();
        store.begin(TxnId(7));
        let _ = store.create_node(TxnId(7)).expect("create node");
        assert_eq!(store.uncommitted_data_writer(), Some(TxnId(7)));

        if commit {
            store.commit(TxnId(7)).expect("commit");
        } else {
            store.rollback(TxnId(7)).expect("rollback");
        }
        assert_eq!(
            store.uncommitted_data_writer(),
            None,
            "a resolved transaction holds nothing uncommitted (commit = {commit})"
        );
    }
}

/// Determinism: `active` is a `HashMap`, so "any writer" would answer differently between runs. The
/// answer reaches an operator-visible error message and a DST replay, both of which must be stable.
#[test]
fn several_open_writers_report_the_lowest_id_deterministically() {
    let store = fresh();
    for txn in [TxnId(9), TxnId(4), TxnId(6)] {
        store.begin(txn);
        let _ = store.create_node(txn).expect("create node");
    }
    for _ in 0..32 {
        assert_eq!(store.uncommitted_data_writer(), Some(TxnId(4)));
    }

    // Retiring the lowest promotes the next-lowest, still deterministically.
    store.rollback(TxnId(4)).expect("rollback");
    assert_eq!(store.uncommitted_data_writer(), Some(TxnId(6)));
}
