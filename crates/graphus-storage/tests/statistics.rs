//! Acceptance tests for the durable storage statistics — per-label node counts and
//! per-relationship-type counts (`rmp` task #79).
//!
//! The cardinality estimator (a later sub-task) needs exact, persisted cardinalities. These tests
//! pin the inviolable correctness property the planner depends on:
//!
//! 1. **Counts equal a full re-scan** of the currently-live records after arbitrary
//!    create/delete/label-add/label-remove sequences ([`counts_equal_a_full_rescan_after_*`]).
//! 2. **Counts persist across a clean reopen** ([`counts_persist_across_reopen`]).
//! 3. **Counts are correct after a crash + recovery** (no-force and steal,
//!    [`counts_recover_after_a_*_crash`]).
//! 4. **Abort/rollback does not overcount** ([`rolled_back_*_does_not_change_counts`]).
//!
//! The re-scan oracle is the same notion of "live" the store counts: a node/relationship is live
//! when its slot is in use **and** it carries no MVCC tombstone (`xmax == 0`) — the latest visible
//! version (`04 §5.3`). A node contributes `1` to each of its label token ids; a relationship `1` to
//! its relationship-type token id. The oracle is derived purely from the public record reads, so it
//! is independent of the incremental maintenance under test.

use std::collections::BTreeMap;

use graphus_core::TxnId;
use graphus_io::{MemBlockDevice, Page};
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// Builds a fresh store over an in-memory device + log.
fn fresh(cap: usize) -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, cap, 1).expect("create store")
}

/// Independent re-scan oracle: counts every currently-**live** node's labels and live
/// relationship's type, exactly as the persisted statistics must. Returns
/// `(nodes_per_label, rels_per_type)`. "Live" == slot in use **and** `xmax == 0`.
fn rescan(s: &mut Store) -> (BTreeMap<u32, u64>, BTreeMap<u32, u64>) {
    let mut nodes_per_label: BTreeMap<u32, u64> = BTreeMap::new();
    let mut rels_per_type: BTreeMap<u32, u64> = BTreeMap::new();

    for id in s.scan_node_ids().expect("scan nodes") {
        let rec = s.node(id).expect("read node");
        // `scan_node_ids` returns slot-occupied ids (includes tombstones); keep only live versions.
        if rec.mvcc.expired_ts != 0 {
            continue;
        }
        for token_id in s.node_labels(id).expect("node labels") {
            *nodes_per_label.entry(token_id).or_insert(0) += 1;
        }
    }
    for id in s.scan_rel_ids().expect("scan rels") {
        let rec = s.rel(id).expect("read rel");
        if rec.mvcc.expired_ts != 0 {
            continue;
        }
        *rels_per_type.entry(rec.type_id).or_insert(0) += 1;
    }
    (nodes_per_label, rels_per_type)
}

/// Asserts the persisted statistics exactly equal a fresh full re-scan (the core invariant).
fn assert_stats_match_rescan(s: &mut Store) {
    let (want_nodes, want_rels) = rescan(s);
    let stats = s.statistics();
    assert_eq!(
        stats.nodes_per_label, want_nodes,
        "per-label node counts must equal a full re-scan"
    );
    assert_eq!(
        stats.rels_per_type, want_rels,
        "per-relationship-type counts must equal a full re-scan"
    );
}

/// The durable WAL bytes of a store (its group-committed log prefix).
fn durable_log(store: &Store) -> Vec<u8> {
    store.with_wal(|w| w.sink().durable_bytes().to_vec())
}

/// Recovers a *no-force* crash: committed work lives only in the durable WAL; the data device was
/// never flushed. Replays the WAL onto a fresh empty device, then opens the store.
fn recover_no_force(store: &Store) -> Store {
    let log = durable_log(store);
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");

    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");

    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, 64).expect("open store")
}

/// Recovers a *steal* crash: `store` is flushed so its (committed and uncommitted) dirty pages are
/// on disk; the disk image and durable WAL are captured, then recovery rolls back the uncommitted
/// work. Mirrors `tests/crash_recovery.rs`.
fn recover_steal(store: &mut Store) -> Store {
    store.flush().expect("flush (steal: pages written home)");
    let pages = store.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    {
        let mut staged: Vec<(u64, Box<Page>)> = Vec::new();
        for p in &pages {
            staged.push((p.0, store.read_device_page(*p).expect("read device page")));
        }
        use graphus_io::BlockDevice;
        for (idx, bytes) in staged {
            device
                .write_page(graphus_core::PageId(idx), &bytes)
                .expect("stage page");
        }
        device.sync_all().expect("persist disk image");
    }

    let log = durable_log(store);
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");

    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, 64).expect("open store")
}

/// Runs one committed GC pass at the current snapshot watermark (reclaims every committed tombstone).
fn gc_pass(s: &mut Store, txn: TxnId) {
    let watermark = s.snapshot_ts();
    s.begin(txn);
    s.gc(txn, watermark).unwrap();
    s.commit(txn).unwrap();
}

#[test]
fn fresh_store_has_empty_statistics() {
    let mut s = fresh(64);
    assert!(s.statistics().nodes_per_label.is_empty());
    assert!(s.statistics().rels_per_type.is_empty());
    assert_eq!(s.node_count_for_label(0), 0);
    assert_eq!(s.rel_count_for_type(0), 0);
    assert_stats_match_rescan(&mut s);
}

#[test]
fn create_rel_increments_and_labels_track_the_live_set() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let admin = s.intern_token(Namespace::Label, "Admin").unwrap();
    let knows = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let likes = s.intern_token(Namespace::RelType, "LIKES").unwrap();

    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    // A node with two labels contributes to both label counts.
    s.set_node_labels(txn, a, &[person, admin]).unwrap();
    s.add_label(txn, b, person).unwrap();
    let (_r1, _) = s.create_rel(txn, knows, a, b).unwrap();
    let (_r2, _) = s.create_rel(txn, likes, a, b).unwrap();
    let (_r3, _) = s.create_rel(txn, knows, b, a).unwrap();
    s.commit(txn).unwrap();

    assert_eq!(s.node_count_for_label(person), 2);
    assert_eq!(s.node_count_for_label(admin), 1);
    assert_eq!(s.rel_count_for_type(knows), 2);
    assert_eq!(s.rel_count_for_type(likes), 1);
    assert_stats_match_rescan(&mut s);
}

#[test]
fn counts_equal_a_full_rescan_after_an_arbitrary_sequence() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let l0 = s.intern_token(Namespace::Label, "L0").unwrap();
    let l1 = s.intern_token(Namespace::Label, "L1").unwrap();
    let l2 = s.intern_token(Namespace::Label, "L2").unwrap();
    let t0 = s.intern_token(Namespace::RelType, "T0").unwrap();
    let t1 = s.intern_token(Namespace::RelType, "T1").unwrap();

    // Create five nodes with assorted label sets.
    let mut nodes = Vec::new();
    for _ in 0..5 {
        nodes.push(s.create_node(txn).unwrap().0);
    }
    s.set_node_labels(txn, nodes[0], &[l0, l1]).unwrap();
    s.set_node_labels(txn, nodes[1], &[l1]).unwrap();
    s.set_node_labels(txn, nodes[2], &[l0, l1, l2]).unwrap();
    s.add_label(txn, nodes[3], l2).unwrap();
    // nodes[4] stays unlabelled.

    // Relationships of mixed types.
    let r_a = s.create_rel(txn, t0, nodes[0], nodes[1]).unwrap().0;
    let r_b = s.create_rel(txn, t1, nodes[1], nodes[2]).unwrap().0;
    let r_c = s.create_rel(txn, t0, nodes[2], nodes[3]).unwrap().0;
    let _self_loop = s.create_rel(txn, t1, nodes[4], nodes[4]).unwrap().0;
    s.commit(txn).unwrap();
    assert_stats_match_rescan(&mut s);

    // Now mutate: remove a label, add another, delete a node and a relationship — each its own txn.
    let t2 = TxnId(2);
    s.begin(t2);
    s.remove_label(t2, nodes[2], l1).unwrap(); // L1: 3 -> 2
    s.add_label(t2, nodes[4], l0).unwrap(); // L0: 2 -> 3
    s.delete_rel(t2, r_a).unwrap(); // T0: 2 -> 1
    s.commit(t2).unwrap();
    assert_stats_match_rescan(&mut s);

    let t3 = TxnId(3);
    s.begin(t3);
    // Delete a labelled node: its labels (l0, l1, l2 minus the removed l1 => l0, l2) drop out.
    s.delete_node(t3, nodes[2]).unwrap();
    s.delete_rel(t3, r_b).unwrap();
    s.commit(t3).unwrap();
    assert_stats_match_rescan(&mut s);

    // Spot-check explicit values against the surviving live set, derived from the oracle so there is
    // no hand-counting drift. After the mutations the live l0-carrying nodes are n0 and n4 (n2 was
    // deleted): two.
    let (want_nodes, want_rels) = rescan(&mut s);
    assert_eq!(want_nodes[&l0], 2, "live l0 nodes: n0 and n4");
    assert_eq!(s.node_count_for_label(l0), want_nodes[&l0]);
    assert_eq!(
        s.node_count_for_label(l2),
        want_nodes.get(&l2).copied().unwrap_or(0)
    );
    assert_eq!(
        s.rel_count_for_type(t0),
        want_rels.get(&t0).copied().unwrap_or(0)
    );
    let _ = (r_c, want_rels); // r_c remains live; the oracle accounts for it
}

#[test]
fn deleting_a_node_drops_all_its_label_contributions() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let a_lbl = s.intern_token(Namespace::Label, "A").unwrap();
    let b_lbl = s.intern_token(Namespace::Label, "B").unwrap();
    let (n0, _) = s.create_node(txn).unwrap();
    let (n1, _) = s.create_node(txn).unwrap();
    s.set_node_labels(txn, n0, &[a_lbl, b_lbl]).unwrap();
    s.set_node_labels(txn, n1, &[a_lbl]).unwrap();
    s.commit(txn).unwrap();
    assert_eq!(s.node_count_for_label(a_lbl), 2);
    assert_eq!(s.node_count_for_label(b_lbl), 1);

    let t2 = TxnId(2);
    s.begin(t2);
    s.delete_node(t2, n0).unwrap();
    s.commit(t2).unwrap();
    // n0 carried both A and B; both counts drop. B reaches 0 and the entry is removed entirely.
    assert_eq!(s.node_count_for_label(a_lbl), 1);
    assert_eq!(s.node_count_for_label(b_lbl), 0);
    assert!(
        !s.statistics().nodes_per_label.contains_key(&b_lbl),
        "a count that reached 0 must not linger in the map"
    );
    assert_stats_match_rescan(&mut s);
}

#[test]
fn gc_reclamation_does_not_change_counts() {
    // The decrement happens at the tombstone-stamping delete; GC reclaiming the tombstone must NOT
    // decrement again. After GC the counts are unchanged and still match the (now smaller) live set.
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let lbl = s.intern_token(Namespace::Label, "L").unwrap();
    let ty = s.intern_token(Namespace::RelType, "T").unwrap();
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    s.add_label(txn, a, lbl).unwrap();
    s.add_label(txn, b, lbl).unwrap();
    let (r, _) = s.create_rel(txn, ty, a, b).unwrap();
    s.commit(txn).unwrap();
    assert_eq!(s.node_count_for_label(lbl), 2);
    assert_eq!(s.rel_count_for_type(ty), 1);

    // Delete the relationship and one node (DETACH-style: rel first), commit.
    let t2 = TxnId(2);
    s.begin(t2);
    s.delete_rel(t2, r).unwrap();
    s.delete_node(t2, a).unwrap();
    s.commit(t2).unwrap();
    assert_eq!(s.node_count_for_label(lbl), 1, "decremented at delete");
    assert_eq!(s.rel_count_for_type(ty), 0, "decremented at delete");
    let snapshot = (
        s.statistics().nodes_per_label.clone(),
        s.statistics().rels_per_type.clone(),
    );

    // GC physically reclaims the tombstones — counts must be byte-for-byte identical afterwards.
    gc_pass(&mut s, TxnId(3));
    assert_eq!(
        (
            s.statistics().nodes_per_label.clone(),
            s.statistics().rels_per_type.clone()
        ),
        snapshot,
        "GC reclamation must not double-decrement the statistics"
    );
    assert_stats_match_rescan(&mut s);
}

#[test]
fn counts_persist_across_reopen() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let knows = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    s.add_label(txn, a, person).unwrap();
    s.add_label(txn, b, person).unwrap();
    let (_r, _) = s.create_rel(txn, knows, a, b).unwrap();
    s.commit(txn).unwrap();
    s.flush().unwrap();

    // Reopen over the same device + log (a clean shutdown then restart).
    let (device, wal) = into_parts(s);
    let mut reopened = RecordStore::open(device, wal, 64).expect("reopen");
    assert_eq!(reopened.node_count_for_label(person), 2);
    assert_eq!(reopened.rel_count_for_type(knows), 1);
    assert_stats_match_rescan(&mut reopened);
}

/// Splits a flushed store into its device + a freshly-opened WAL over the same durable log, so the
/// store can be reopened. The pages were flushed home, so this is a clean reopen (no recovery work).
fn into_parts(mut s: Store) -> (MemBlockDevice, WalManager<MemLogSink>) {
    s.flush().unwrap();
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
    (device, wal)
}

#[test]
fn counts_recover_after_a_no_force_crash() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let admin = s.intern_token(Namespace::Label, "Admin").unwrap();
    let knows = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let (c, _) = s.create_node(txn).unwrap();
    s.set_node_labels(txn, a, &[person, admin]).unwrap();
    s.add_label(txn, b, person).unwrap();
    let (_r1, _) = s.create_rel(txn, knows, a, b).unwrap();
    let (_r2, _) = s.create_rel(txn, knows, b, c).unwrap();
    s.commit(txn).unwrap();

    // Delete one labelled node in a second committed txn so a decrement is part of the durable log.
    let t2 = TxnId(2);
    s.begin(t2);
    s.delete_node(t2, b).unwrap(); // person: 2 -> 1
    s.commit(t2).unwrap();

    let mut rec = recover_no_force(&s);
    assert_eq!(rec.node_count_for_label(person), 1);
    assert_eq!(rec.node_count_for_label(admin), 1);
    // b's deletion does not remove its incident relationships' types from the live count: the rels
    // are still live versions (DETACH was not performed), so both KNOWS rels are still counted.
    assert_eq!(rec.rel_count_for_type(knows), 2);
    assert_stats_match_rescan(&mut rec);
}

#[test]
fn counts_recover_after_a_steal_crash() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let lbl = s.intern_token(Namespace::Label, "L").unwrap();
    let ty = s.intern_token(Namespace::RelType, "T").unwrap();
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    s.add_label(txn, a, lbl).unwrap();
    s.add_label(txn, b, lbl).unwrap();
    let (_r, _) = s.create_rel(txn, ty, a, b).unwrap();
    s.commit(txn).unwrap();

    let mut rec = recover_steal(&mut s);
    assert_eq!(rec.node_count_for_label(lbl), 2);
    assert_eq!(rec.rel_count_for_type(ty), 1);
    assert_stats_match_rescan(&mut rec);
}

#[test]
fn an_uncommitted_transaction_does_not_contribute_to_recovered_counts() {
    let mut s = fresh(64);
    // Committed baseline.
    let t1 = TxnId(1);
    s.begin(t1);
    let lbl = s.intern_token(Namespace::Label, "L").unwrap();
    let ty = s.intern_token(Namespace::RelType, "T").unwrap();
    let (a, _) = s.create_node(t1).unwrap();
    let (b, _) = s.create_node(t1).unwrap();
    s.add_label(t1, a, lbl).unwrap();
    let (_r, _) = s.create_rel(t1, ty, a, b).unwrap();
    s.commit(t1).unwrap();

    // T2 mutates statistics-affecting state but never commits (a loser). Harden its tail so the
    // crash log carries it and undo runs.
    let t2 = TxnId(2);
    s.begin(t2);
    let (_c, _) = s.create_node(t2).unwrap();
    s.add_label(t2, b, lbl).unwrap(); // would be L: 1 -> 2 if committed
    let (_r2, _) = s.create_rel(t2, ty, b, a).unwrap(); // would be T: 1 -> 2 if committed
    s.with_wal(graphus_wal::WalManager::flush);

    let mut rec = recover_no_force(&s);
    // Only T1's committed effect survives: the loser's increments are not in the recovered catalog
    // (the catalog is checkpointed only at commit; T2 never committed one).
    assert_eq!(rec.node_count_for_label(lbl), 1);
    assert_eq!(rec.rel_count_for_type(ty), 1);
    assert_stats_match_rescan(&mut rec);
}

#[test]
fn rolled_back_creates_and_deletes_do_not_change_counts() {
    let mut s = fresh(64);
    let t1 = TxnId(1);
    s.begin(t1);
    let lbl = s.intern_token(Namespace::Label, "L").unwrap();
    let ty = s.intern_token(Namespace::RelType, "T").unwrap();
    let (a, _) = s.create_node(t1).unwrap();
    let (b, _) = s.create_node(t1).unwrap();
    s.add_label(t1, a, lbl).unwrap();
    s.add_label(t1, b, lbl).unwrap();
    let (r, _) = s.create_rel(t1, ty, a, b).unwrap();
    s.commit(t1).unwrap();
    let baseline = (
        s.statistics().nodes_per_label.clone(),
        s.statistics().rels_per_type.clone(),
    );
    assert_eq!(baseline.0[&lbl], 2);
    assert_eq!(baseline.1[&ty], 1);

    // T2: create + label + delete a bunch, then ROLL BACK. The counts must be byte-identical to the
    // committed baseline afterwards — no overcount from the aborted increments, no undercount from
    // the aborted decrements.
    let t2 = TxnId(2);
    s.begin(t2);
    let (c, _) = s.create_node(t2).unwrap();
    s.add_label(t2, c, lbl).unwrap(); // would push L to 3
    let (_r2, _) = s.create_rel(t2, ty, a, c).unwrap(); // would push T to 2
    s.delete_node(t2, a).unwrap(); // would drop L by 1
    s.delete_rel(t2, r).unwrap(); // would drop T by 1
    s.remove_label(t2, b, lbl).unwrap(); // would drop L by 1
    s.rollback(t2).unwrap();

    assert_eq!(
        (
            s.statistics().nodes_per_label.clone(),
            s.statistics().rels_per_type.clone()
        ),
        baseline,
        "a rolled-back transaction must leave the counts at their committed values"
    );
    assert_eq!(s.node_count_for_label(lbl), 2);
    assert_eq!(s.rel_count_for_type(ty), 1);
    assert_stats_match_rescan(&mut s);
}

#[test]
fn rolled_back_then_committed_transactions_keep_counts_exact() {
    // A rollback followed by fresh committed work must still leave counts equal to a re-scan: proves
    // the in-memory counts were actually reverted to disk state, not merely left stale.
    let mut s = fresh(64);
    let t1 = TxnId(1);
    s.begin(t1);
    let lbl = s.intern_token(Namespace::Label, "L").unwrap();
    let (a, _) = s.create_node(t1).unwrap();
    s.add_label(t1, a, lbl).unwrap();
    s.commit(t1).unwrap();

    let t2 = TxnId(2);
    s.begin(t2);
    let (b, _) = s.create_node(t2).unwrap();
    s.add_label(t2, b, lbl).unwrap();
    s.rollback(t2).unwrap();
    assert_eq!(
        s.node_count_for_label(lbl),
        1,
        "rollback reverted the count"
    );

    let t3 = TxnId(3);
    s.begin(t3);
    let (c, _) = s.create_node(t3).unwrap();
    s.add_label(t3, c, lbl).unwrap();
    s.commit(t3).unwrap();
    assert_eq!(s.node_count_for_label(lbl), 2);
    assert_stats_match_rescan(&mut s);
}
