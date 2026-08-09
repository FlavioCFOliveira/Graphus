//! A property that was **removed** must not reappear in a dump (`rmp` task #967).
//!
//! # The defect
//!
//! `dump_nodes` / `dump_relationships` resolve each entity's properties with `newest_by_name`, which
//! folds "first occurrence per key wins" over the decoded
//! `RecordStore::superset_scan_{node,rel}_property_values`. That was the physical image while every
//! version of a key was a cell carrying its own MVCC stamps.
//!
//! Since #967 an overwrite is written **in place** and the superseded value descends onto the
//! entity's undo chain, so that read yields the **candidate superset**: the live cells, with the
//! EMPTY cell a removal leaves behind skipped, followed by every retained historical value. For a
//! removed key the first surviving candidate is therefore its **pre-removal value**, and the dump
//! emitted a property the store no longer holds — in a column the importer would then re-create on
//! the way back in, so the round trip was not lossless either.
//!
//! An overwrite was never affected: the live cell holds the newest value and comes first.
//!
//! # The polarity a dump owes
//!
//! The dumper is an offline surface with no reader snapshot — it opens the store after recovery, so
//! there is no in-flight writer and the **current image** is the committed image. That is the
//! `cells_ignoring_history()` read, with the empty cells skipped: exactly one value per key, exactly
//! one CSV cell per (row, column).

use graphus_bulk::{dump_nodes, dump_relationships};
use graphus_core::{TxnId, Value};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

fn fresh_store() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("wal create");
    RecordStore::create(device, wal, 256, 1).expect("store create")
}

/// Interns `name` as a property key.
fn key(store: &mut Store, name: &str) -> u32 {
    store
        .intern_token(Namespace::PropKey, name)
        .expect("intern prop key")
}

/// A committed `REMOVE n.p` must leave the node's column **empty** in the dump, not repopulated with
/// the value the removal vacated.
#[test]
fn a_removed_node_property_is_not_dumped() {
    let mut store = fresh_store();
    let label = store
        .intern_token(Namespace::Label, "Doc")
        .expect("intern label");
    let title = key(&mut store, "title");
    let tag = key(&mut store, "tag");

    let txn = TxnId(1);
    let (node, _eid) = store.create_node(txn).expect("create node");
    store.add_label(txn, node, label).expect("add label");
    store
        .set_node_property_value(txn, node, title, &Value::String("secret".into()))
        .expect("set title");
    store
        .set_node_property_value(txn, node, tag, &Value::String("kept".into()))
        .expect("set tag");
    store.commit(txn).expect("commit writes");

    let txn = TxnId(2);
    store
        .remove_node_property_value(txn, node, title)
        .expect("remove title");
    store.commit(txn).expect("commit removal");

    let mut out = Vec::new();
    dump_nodes(&store, &mut out).expect("dump nodes");
    let dump = String::from_utf8(out).expect("utf8 dump");

    assert!(
        !dump.contains("secret"),
        "the dump must not contain the value a committed removal vacated — after `rmp` #967 the \
         decoded superset yields the pre-removal value for a key whose cell is empty, and \
         first-occurrence-wins then resurrects it:\n{dump}"
    );
    assert!(
        dump.contains("kept"),
        "the surviving property must still be dumped (the fix must not drop live values):\n{dump}"
    );
}

/// The relationship twin: a committed `REMOVE r.p` must not reappear in the relationship dump.
#[test]
fn a_removed_relationship_property_is_not_dumped() {
    let mut store = fresh_store();
    let rel_type = store
        .intern_token(Namespace::RelType, "CITES")
        .expect("intern rel type");
    let note = key(&mut store, "note");
    let tag = key(&mut store, "tag");

    let txn = TxnId(1);
    let (a, _ea) = store.create_node(txn).expect("create a");
    let (b, _eb) = store.create_node(txn).expect("create b");
    let (rel, _er) = store.create_rel(txn, rel_type, a, b).expect("create rel");
    store
        .set_rel_property_value(txn, rel, note, &Value::String("secret".into()))
        .expect("set note");
    store
        .set_rel_property_value(txn, rel, tag, &Value::String("kept".into()))
        .expect("set tag");
    store.commit(txn).expect("commit writes");

    let txn = TxnId(2);
    store
        .remove_rel_property_value(txn, rel, note)
        .expect("remove note");
    store.commit(txn).expect("commit removal");

    let mut out = Vec::new();
    dump_relationships(&store, &mut out).expect("dump relationships");
    let dump = String::from_utf8(out).expect("utf8 dump");

    assert!(
        !dump.contains("secret"),
        "the relationship dump must not contain the value a committed removal vacated:\n{dump}"
    );
    assert!(
        dump.contains("kept"),
        "the surviving property must still be dumped:\n{dump}"
    );
}

/// An **overwrite** must dump the newest value and only the newest value — the direction the
/// superset read never got wrong, pinned so the fix cannot regress it.
#[test]
fn an_overwritten_property_dumps_only_its_newest_value() {
    let mut store = fresh_store();
    let label = store
        .intern_token(Namespace::Label, "Doc")
        .expect("intern label");
    let title = key(&mut store, "title");

    let txn = TxnId(1);
    let (node, _eid) = store.create_node(txn).expect("create node");
    store.add_label(txn, node, label).expect("add label");
    store
        .set_node_property_value(txn, node, title, &Value::String("old".into()))
        .expect("set old");
    store.commit(txn).expect("commit v1");

    let txn = TxnId(2);
    store
        .set_node_property_value(txn, node, title, &Value::String("new".into()))
        .expect("set new");
    store.commit(txn).expect("commit v2");

    let mut out = Vec::new();
    dump_nodes(&store, &mut out).expect("dump nodes");
    let dump = String::from_utf8(out).expect("utf8 dump");

    assert!(
        dump.contains("new"),
        "the newest value must be dumped:\n{dump}"
    );
    assert!(
        !dump.contains("old"),
        "the superseded value lives on the undo chain and must not be dumped:\n{dump}"
    );
}
