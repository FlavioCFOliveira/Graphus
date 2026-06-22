//! Storage-layer MVCC regression tests (`04-technical-design.md` §5.2/§5.3/§5.5; `rmp` task #45).
//!
//! These pin the record store's MVCC mechanism directly (the visibility *rule* itself lives in
//! `graphus-txn` and is exercised end-to-end through Cypher in `graphus-cypher`):
//!
//! * a created record is stamped `xmin = in_flight(TxnId)`; with **lazy GC-time freezing** (`rmp`
//!   task #49) it keeps that in-flight stamp at commit and resolves through the Active/Recent
//!   Transaction Table (rebuilt on recovery from the WAL commit records) until GC freezes it to the
//!   commit timestamp — commit no longer rewrites per-record headers;
//! * a delete is an MVCC **tombstone** (`xmax`) that keeps the slot until [`RecordStore::gc`]
//!   physically reclaims it;
//! * the commit-timestamp high-water mark is durable, so timestamps stay strictly monotonic across
//!   a crash + recovery (a reader's snapshot can never alias or regress past a committed version);
//! * a GC pass **freezes** committed in-flight stamps to `Committed(ts)` across every MVCC record
//!   kind and **prunes** the now-unreferenced writers from the Active/Recent Transaction Table only
//!   once the freeze is durable — bounding the table (`rmp` task #59); a rolled-back or crashed GC
//!   pass prunes nothing and leaves every restored in-flight stamp resolvable.

use graphus_core::{Timestamp, TxnId, Value, VersionStamp};
use graphus_io::MemBlockDevice;
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 64, 1).expect("create store")
}

/// Recovers a no-force crash: replay the durable WAL prefix onto a fresh device and reopen.
fn recover_no_force(store: &Store) -> Store {
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, 64).expect("open store")
}

#[test]
fn created_ts_stays_inflight_after_commit_and_resolves_through_the_registry() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let (id, _eid) = s.create_node(txn).unwrap();

    // Before commit: xmin is the writer's in-flight TxnId, xmax is the live sentinel, and no commit
    // timestamp has been issued yet.
    let mvcc = s.node(id).unwrap().mvcc;
    assert_eq!(
        VersionStamp::from_raw(mvcc.created_ts),
        VersionStamp::InFlight(txn)
    );
    assert_eq!(mvcc.expired_ts, 0);
    assert_eq!(s.snapshot_ts(), Timestamp(0));

    s.commit(txn).unwrap();

    // After commit (lazy GC-time freezing, `rmp` task #49): the header is NOT eagerly settled — xmin
    // still carries the writer's in-flight TxnId — but the Active/Recent Transaction Table resolves
    // that stamp to the commit timestamp (1), and the snapshot high-water advanced. GC freezes the
    // header to `Committed(1)` later; until then this resolution is what makes the version visible.
    let mvcc = s.node(id).unwrap().mvcc;
    assert_eq!(
        VersionStamp::from_raw(mvcc.created_ts),
        VersionStamp::InFlight(txn),
        "lazy freeze keeps the committed version's in-flight xmin until GC settles it"
    );
    assert_eq!(
        s.commit_registry().resolve_commit_ts(mvcc.created_ts),
        Some(Timestamp(1)),
        "the transaction table resolves the in-flight stamp to its commit timestamp"
    );
    assert_eq!(s.snapshot_ts(), Timestamp(1));
}

#[test]
fn delete_is_a_tombstone_reclaimed_only_by_gc() {
    let mut s = fresh();
    s.begin(TxnId(1));
    let (id, _eid) = s.create_node(TxnId(1)).unwrap();
    s.commit(TxnId(1)).unwrap(); // committed at ts 1

    s.begin(TxnId(2));
    s.delete_node(TxnId(2), id).unwrap();
    s.commit(TxnId(2)).unwrap(); // tombstone xmax committed at ts 2

    // The tombstone keeps the slot in use (an older snapshot could still need it) and stamps xmax;
    // a scan still enumerates the slot (visibility filtering is the reader's concern, layered above).
    let mvcc = s.node(id).unwrap().mvcc;
    assert!(mvcc.in_use(), "a tombstone keeps its slot in use until GC");
    // Lazy freeze (`rmp` task #49): xmax keeps the deleter's in-flight TxnId; the transaction table
    // resolves it to its commit timestamp (2), which is how GC and readers see the deletion.
    assert_eq!(
        VersionStamp::from_raw(mvcc.expired_ts),
        VersionStamp::InFlight(TxnId(2))
    );
    assert_eq!(
        s.commit_registry().resolve_commit_ts(mvcc.expired_ts),
        Some(Timestamp(2))
    );
    assert_eq!(s.scan_node_ids().unwrap(), vec![id]);

    // GC at a watermark past the deletion reclaims the slot.
    let watermark = s.snapshot_ts();
    s.begin(TxnId(3));
    let report = s.gc(TxnId(3), watermark).unwrap();
    s.commit(TxnId(3)).unwrap();
    assert_eq!(report.reclaimed, 1, "GC reclaimed the one tombstoned node");
    assert!(
        !s.node(id).unwrap().mvcc.in_use(),
        "the reclaimed slot is no longer in use"
    );
    assert!(
        s.scan_node_ids().unwrap().is_empty(),
        "the reclaimed node no longer appears in a scan"
    );
}

#[test]
fn commit_timestamp_high_water_survives_recovery_and_stays_monotonic() {
    let mut s = fresh();
    s.begin(TxnId(1));
    let (first, _eid) = s.create_node(TxnId(1)).unwrap();
    s.commit(TxnId(1)).unwrap(); // ts 1
    assert_eq!(s.snapshot_ts(), Timestamp(1));

    // Crash + recover: the durable commit-timestamp high-water is restored from the metadata page.
    let mut s = recover_no_force(&s);
    assert_eq!(
        s.snapshot_ts(),
        Timestamp(1),
        "the commit-timestamp high-water survives recovery"
    );
    // Lazy freeze (`rmp` task #49): the committed node's header is NOT settled on disk — it keeps the
    // writer's in-flight TxnId — but the Active/Recent Transaction Table, **rebuilt on recovery from
    // the WAL commit records** (each carries its commit_ts), resolves that stamp to the commit
    // timestamp. This is exactly what makes a committed-but-unfrozen version survive a crash.
    let first_mvcc = s.node(first).unwrap().mvcc;
    assert_eq!(
        VersionStamp::from_raw(first_mvcc.created_ts),
        VersionStamp::InFlight(TxnId(1))
    );
    assert_eq!(
        s.commit_registry().resolve_commit_ts(first_mvcc.created_ts),
        Some(Timestamp(1)),
        "recovery rebuilt the transaction table from the WAL, so the committed version resolves"
    );

    // A new transaction after recovery gets a strictly greater timestamp — no alias, no regression.
    s.begin(TxnId(2));
    let (second, _eid) = s.create_node(TxnId(2)).unwrap();
    s.commit(TxnId(2)).unwrap();
    assert_eq!(s.snapshot_ts(), Timestamp(2));
    let second_mvcc = s.node(second).unwrap().mvcc;
    assert_eq!(
        VersionStamp::from_raw(second_mvcc.created_ts),
        VersionStamp::InFlight(TxnId(2))
    );
    assert_eq!(
        s.commit_registry()
            .resolve_commit_ts(second_mvcc.created_ts),
        Some(Timestamp(2))
    );
}

#[test]
fn lazy_committed_version_survives_recovery_while_a_loser_resolves_invisible() {
    // `rmp` task #49: with lazy GC-time freezing a committed version keeps its writer's in-flight
    // stamp on disk (no GC ran), yet must resolve as committed after a crash — which works only
    // because recovery rebuilds the Active/Recent Transaction Table from the WAL commit records.
    // Conversely an uncommitted (loser) transaction must resolve as invisible.
    let mut s = fresh();
    s.begin(TxnId(1));
    let (committed_node, _) = s.create_node(TxnId(1)).unwrap();
    s.commit(TxnId(1)).unwrap(); // committed at ts 1; header left in-flight (no GC freeze)

    // A second transaction writes but never commits — a recovery loser.
    s.begin(TxnId(2));
    let _ = s.create_node(TxnId(2)).unwrap();

    let s = recover_no_force(&s);

    // The committed version's header is unfrozen, yet the rebuilt table resolves it to ts 1.
    let mvcc = s.node(committed_node).unwrap().mvcc;
    assert!(mvcc.in_use(), "the committed node survives recovery");
    assert_eq!(
        VersionStamp::from_raw(mvcc.created_ts),
        VersionStamp::InFlight(TxnId(1)),
        "no GC ran, so the committed version keeps its writer's in-flight stamp"
    );
    assert_eq!(
        s.commit_registry().resolve_commit_ts(mvcc.created_ts),
        Some(Timestamp(1)),
        "the table rebuilt from the WAL resolves the committed-but-unfrozen version"
    );

    // The loser left no commit record, so the table has no entry for it: its in-flight stamp
    // resolves to "not committed" — invisible to every snapshot.
    assert_eq!(
        s.commit_registry()
            .resolve_commit_ts(VersionStamp::in_flight(TxnId(2))),
        None,
        "an uncommitted (loser) transaction never resolves as committed after recovery"
    );
}

// ============================ GC-time freezing + table pruning (`rmp` task #59) ============================

/// (i) **Freeze**: a GC pass settles every committed in-flight stamp — `xmin` of survivors and
/// `xmax` of tombstones, across nodes, relationships and per-value property versions — to its
/// `Committed(ts)` form, and (ii) **safe prune**: once the GC transaction commits, the
/// Active/Recent Transaction Table forgets the frozen writers, holding only writers that committed
/// after the freeze sweep (the GC transaction itself here; in-flight writers are never table
/// entries at the store level — their stamps resolve as not-committed by absence).
#[test]
fn gc_freezes_committed_headers_and_prunes_the_transaction_table() {
    let mut s = fresh();
    let key = s.intern_token(Namespace::PropKey, "v").unwrap();
    let knows = s.intern_token(Namespace::RelType, "KNOWS").unwrap();

    // t1: two nodes, a relationship, a property — committed at ts 1.
    let t1 = TxnId(1);
    s.begin(t1);
    let (a, _) = s.create_node(t1).unwrap();
    let (b, _) = s.create_node(t1).unwrap();
    let (r, _) = s.create_rel(t1, knows, a, b).unwrap();
    let p1 = s
        .set_node_property_value(t1, a, key, &Value::Integer(1))
        .unwrap();
    s.commit(t1).unwrap();

    // t2: tombstone the relationship and overwrite the property — committed at ts 2.
    let t2 = TxnId(2);
    s.begin(t2);
    s.delete_rel(t2, r).unwrap();
    let p2 = s
        .set_node_property_value(t2, a, key, &Value::Integer(2))
        .unwrap();
    s.commit(t2).unwrap();
    assert_eq!(
        s.commit_registry().len(),
        2,
        "two committed writers retained"
    );

    // GC at a watermark BELOW t2's commit (an older reader could still see the tombstoned
    // versions): nothing is reclaimable, but freezing is watermark-independent — every committed
    // stamp settles, and the full prune is scheduled.
    let t3 = TxnId(3);
    s.begin(t3);
    let report = s.gc(t3, Timestamp(1)).unwrap();
    assert_eq!(
        report.reclaimed, 0,
        "watermark 1 protects the t2 tombstones"
    );
    // Frozen words: a.xmin, b.xmin, r.xmin, r.xmax, p1.xmin, p1.xmax, p2.xmin.
    assert_eq!(
        report.frozen, 7,
        "every committed stamp across all record kinds froze"
    );
    assert_eq!(report.prune_scheduled, 2, "t1 and t2 scheduled for pruning");
    s.commit(t3).unwrap(); // the freeze is durable: the prune applies now

    // (i) The headers are self-describing `Committed(ts)` stamps.
    assert_eq!(
        VersionStamp::from_raw(s.node(a).unwrap().mvcc.created_ts),
        VersionStamp::Committed(Timestamp(1))
    );
    let rel = s.rel(r).unwrap();
    assert!(
        rel.mvcc.in_use(),
        "the tombstone survives (older snapshots may need it)"
    );
    assert_eq!(
        VersionStamp::from_raw(rel.mvcc.created_ts),
        VersionStamp::Committed(Timestamp(1))
    );
    assert_eq!(
        VersionStamp::from_raw(rel.mvcc.expired_ts),
        VersionStamp::Committed(Timestamp(2))
    );
    let old_prop = s.property(p1).unwrap();
    assert_eq!(
        VersionStamp::from_raw(old_prop.mvcc.created_ts),
        VersionStamp::Committed(Timestamp(1))
    );
    assert_eq!(
        VersionStamp::from_raw(old_prop.mvcc.expired_ts),
        VersionStamp::Committed(Timestamp(2))
    );
    assert_eq!(
        VersionStamp::from_raw(s.property(p2).unwrap().mvcc.created_ts),
        VersionStamp::Committed(Timestamp(2))
    );

    // (ii) The table shrank to exactly the writers not yet frozen: only the GC transaction itself.
    assert_eq!(s.commit_registry().len(), 1, "only the GC writer remains");
    assert_eq!(
        s.commit_registry()
            .resolve_commit_ts(VersionStamp::in_flight(t1)),
        None,
        "t1 was pruned — safe, because no header carries its in-flight stamp any more"
    );

    // A later pass at the latest watermark reclaims the tombstones (their frozen `Committed(2)`
    // xmax resolves directly, no table entry needed) and prunes the previous GC writer.
    let latest = s.snapshot_ts();
    let t4 = TxnId(4);
    s.begin(t4);
    let report = s.gc(t4, latest).unwrap();
    s.commit(t4).unwrap();
    assert_eq!(
        report.reclaimed, 2,
        "the rel tombstone and the old property version"
    );
    assert_eq!(report.prune_scheduled, 1, "the previous GC writer (t3)");
    assert_eq!(s.commit_registry().len(), 1, "only t4 remains");
}

/// A writer that commits **between** the GC freeze sweep and the GC transaction's commit is not in
/// the scheduled prune set: its stamps were not frozen this pass (it was still in flight during the
/// sweep), so its table entry must survive — it is pruned only by a *later* pass that freezes it.
#[test]
fn a_writer_committing_during_the_gc_window_is_not_pruned() {
    let mut s = fresh();
    let t1 = TxnId(1);
    s.begin(t1);
    let (_a, _) = s.create_node(t1).unwrap();
    s.commit(t1).unwrap(); // ts 1

    // t2 is still in flight while the GC pass runs.
    let t2 = TxnId(2);
    s.begin(t2);
    let (b, _) = s.create_node(t2).unwrap();

    let t3 = TxnId(3);
    s.begin(t3);
    let report = s.gc(t3, s.snapshot_ts()).unwrap();
    assert_eq!(
        report.prune_scheduled, 1,
        "only t1 was committed at sweep time"
    );

    // t2 commits inside the GC window; then the GC transaction commits and prunes.
    s.commit(t2).unwrap(); // ts 2
    s.commit(t3).unwrap(); // applies the prune of {t1}

    // t2's version still carries an in-flight stamp (not frozen this pass) and MUST resolve.
    let mvcc = s.node(b).unwrap().mvcc;
    assert_eq!(
        VersionStamp::from_raw(mvcc.created_ts),
        VersionStamp::InFlight(t2)
    );
    assert_eq!(
        s.commit_registry().resolve_commit_ts(mvcc.created_ts),
        Some(Timestamp(2)),
        "the mid-window committer survives the prune"
    );
    // And t1 is gone (its stamps froze before the prune).
    assert_eq!(
        s.commit_registry()
            .resolve_commit_ts(VersionStamp::in_flight(t1)),
        None
    );
}

/// (iii) **Mid-GC rollback**: rolling the GC transaction back undoes its header freezes (WAL undo
/// restores the in-flight stamps) and MUST discard the scheduled prune — otherwise a restored
/// in-flight stamp would be stranded as unresolvable (it would wrongly read as aborted).
#[test]
fn rolled_back_gc_pass_prunes_nothing_and_strands_no_stamp() {
    let mut s = fresh();
    let t1 = TxnId(1);
    s.begin(t1);
    let (a, _) = s.create_node(t1).unwrap();
    s.commit(t1).unwrap(); // ts 1

    // A GC pass freezes a's xmin and schedules the prune of {t1} — then rolls back.
    let t2 = TxnId(2);
    s.begin(t2);
    let report = s.gc(t2, s.snapshot_ts()).unwrap();
    assert_eq!(report.frozen, 1);
    assert_eq!(report.prune_scheduled, 1);
    assert_eq!(
        VersionStamp::from_raw(s.node(a).unwrap().mvcc.created_ts),
        VersionStamp::Committed(Timestamp(1)),
        "the freeze is applied in-cache before the rollback"
    );
    s.rollback(t2).unwrap();

    // The WAL undo restored the in-flight stamp, and the table still resolves it: no prune ran.
    let mvcc = s.node(a).unwrap().mvcc;
    assert_eq!(
        VersionStamp::from_raw(mvcc.created_ts),
        VersionStamp::InFlight(t1),
        "rollback undid the freeze"
    );
    assert_eq!(
        s.commit_registry().resolve_commit_ts(mvcc.created_ts),
        Some(Timestamp(1)),
        "the rolled-back pass pruned nothing — the restored stamp still resolves"
    );

    // A subsequent committed pass freezes and prunes normally.
    let t3 = TxnId(3);
    s.begin(t3);
    s.gc(t3, s.snapshot_ts()).unwrap();
    s.commit(t3).unwrap();
    assert_eq!(
        VersionStamp::from_raw(s.node(a).unwrap().mvcc.created_ts),
        VersionStamp::Committed(Timestamp(1))
    );
    assert_eq!(
        s.commit_registry().len(),
        1,
        "only the GC writer (t3) remains"
    );
}

/// A **crash mid-GC** (the GC transaction never committed, but its freeze writes reached the
/// durable WAL) leaves the table correct after recovery: the GC transaction is a loser — its
/// header freezes are undone — and the table rebuilt from the WAL commit records still resolves
/// every restored in-flight stamp. No prune survives the crash (it was never applied).
#[test]
fn crash_mid_gc_restores_inflight_stamps_and_a_resolving_table() {
    let mut s = fresh();
    let t1 = TxnId(1);
    s.begin(t1);
    let (a, _) = s.create_node(t1).unwrap();
    s.commit(t1).unwrap(); // ts 1

    // The GC pass runs but never commits; flushing pages home forces the WAL durable through the
    // freeze writes' LSNs (the WAL rule), so the crash log carries the loser's updates and
    // recovery's undo must actually run.
    let t2 = TxnId(2);
    s.begin(t2);
    let report = s.gc(t2, s.snapshot_ts()).unwrap();
    assert_eq!(report.frozen, 1);
    s.flush().unwrap();

    let mut s = recover_no_force(&s);

    // The loser GC's freeze was undone; the rebuilt table resolves the restored in-flight stamp.
    let mvcc = s.node(a).unwrap().mvcc;
    assert!(mvcc.in_use());
    assert_eq!(
        VersionStamp::from_raw(mvcc.created_ts),
        VersionStamp::InFlight(t1),
        "recovery rolled the uncommitted freeze back"
    );
    assert_eq!(
        s.commit_registry().resolve_commit_ts(mvcc.created_ts),
        Some(Timestamp(1)),
        "the table rebuilt from the WAL still resolves the committed writer"
    );

    // A fresh committed GC pass after recovery freezes and prunes normally.
    let t3 = TxnId(3);
    s.begin(t3);
    let report = s.gc(t3, s.snapshot_ts()).unwrap();
    assert_eq!(report.frozen, 1);
    s.commit(t3).unwrap();
    assert_eq!(
        VersionStamp::from_raw(s.node(a).unwrap().mvcc.created_ts),
        VersionStamp::Committed(Timestamp(1))
    );
    assert_eq!(
        s.commit_registry().len(),
        1,
        "only the GC writer (t3) remains"
    );
}

/// Frozen-then-pruned state survives a crash: after a committed GC pass and a crash, the table is
/// rebuilt from the WAL commit records (pruned writers harmlessly reappear), every frozen header
/// reads back as `Committed(ts)`, and the next pass simply prunes the stale entries again.
#[test]
fn frozen_headers_survive_a_crash_and_stale_entries_reprune() {
    let mut s = fresh();
    let t1 = TxnId(1);
    s.begin(t1);
    let (a, _) = s.create_node(t1).unwrap();
    s.commit(t1).unwrap(); // ts 1

    let t2 = TxnId(2);
    s.begin(t2);
    s.gc(t2, s.snapshot_ts()).unwrap();
    s.commit(t2).unwrap(); // freeze durable; t1 pruned
    assert_eq!(s.commit_registry().len(), 1);

    let mut s = recover_no_force(&s);

    // The frozen header is durable; the rebuilt table again holds every WAL-committed writer —
    // t1, t2, and the create-time system catalog transaction (its commit record carries the ts-0
    // sentinel) — stale but harmless, since no header references any of them any more.
    assert_eq!(
        VersionStamp::from_raw(s.node(a).unwrap().mvcc.created_ts),
        VersionStamp::Committed(Timestamp(1)),
        "the committed freeze survived the crash"
    );
    assert_eq!(
        s.commit_registry().len(),
        3,
        "rebuild restores WAL-committed writers (t1, t2, system catalog txn)"
    );

    // The next pass re-prunes the stale entries (nothing left to freeze).
    let t3 = TxnId(3);
    s.begin(t3);
    let report = s.gc(t3, s.snapshot_ts()).unwrap();
    assert_eq!(report.frozen, 0, "everything already frozen");
    assert_eq!(report.prune_scheduled, 3, "the stale t1/t2/system entries");
    s.commit(t3).unwrap();
    assert_eq!(
        s.commit_registry().len(),
        1,
        "only the GC writer (t3) remains"
    );
}

/// Crash-recovery variant of the aborted-creation dead-link survivor (`rmp` #220): instead of an
/// explicit live `rollback`, the creating transaction of the middle relationship NEVER commits and
/// the system crashes. On recovery, redo repeats history (the middle rel is written, in_use) and the
/// global descending-LSN undo of the losing (uncommitted) transaction applies the **header-only**
/// creation undo, leaving the middle rel as the IDENTICAL transparent dead link as live rollback — so
/// the two surviving committed edges are preserved and the chain is not severed.
#[test]
fn crash_recovery_aborted_middle_rel_keeps_both_committed_edges() {
    let mut s = fresh();
    let rt = s.intern_token(Namespace::RelType, "R").unwrap();

    // Setup (committed): hub + three leaves.
    let setup = TxnId(1);
    s.begin(setup);
    let (hub, _) = s.create_node(setup).unwrap();
    let (l1, _) = s.create_node(setup).unwrap();
    let (l2, _) = s.create_node(setup).unwrap();
    let (l3, _) = s.create_node(setup).unwrap();
    s.commit(setup).unwrap();

    // Interleave three prepends onto hub's chain. T2 (the middle, r2) is the loser: it is left
    // in-flight (never committed) when we crash. T1 and T3 commit, so their work — and r2's
    // updates, made durable by T1/T3's group commits under no-force — is in the durable WAL prefix.
    let t1 = TxnId(2);
    let t2 = TxnId(3);
    let t3 = TxnId(4);
    s.begin(t1);
    s.begin(t2);
    s.begin(t3);
    let (r1, _) = s.create_rel(t1, rt, hub, l1).unwrap();
    let (r2, _) = s.create_rel(t2, rt, hub, l2).unwrap();
    let (r3, _) = s.create_rel(t3, rt, hub, l3).unwrap();
    s.commit(t1).unwrap();
    s.commit(t3).unwrap();
    // CRASH: t2 never commits. Recover the durable WAL prefix onto a fresh device.
    let mut s = recover_no_force(&s);

    // Both committed edges survive; the loser r2 was undone to a transparent dead link, threaded
    // through by the forward walk. Recovery must reconstruct the exact same survivor set as live
    // rollback did.
    let mut incident = s.incident_rels(hub).unwrap();
    incident.sort_unstable();
    assert_eq!(
        incident,
        vec![r1, r3],
        "after crash recovery the hub keeps both committed edges r1 and r3"
    );
    assert_eq!(s.degree(hub).unwrap(), 2);

    // GC after recovery splices and reclaims the dead-link corpse and keeps the survivors reachable.
    let used_before = s.used_rel_slots();
    let watermark = s.snapshot_ts();
    s.begin(TxnId(5));
    s.gc(TxnId(5), watermark).unwrap();
    s.commit(TxnId(5)).unwrap();
    let mut incident = s.incident_rels(hub).unwrap();
    incident.sort_unstable();
    assert_eq!(
        incident,
        vec![r1, r3],
        "survivors remain after the post-recovery corpse splice"
    );
    assert_eq!(
        s.degree(hub).unwrap(),
        2,
        "degree is exactly the two survivors"
    );
    // The corpse slot r2 is now freed: used rel slots drop by one to the two-survivor baseline, and
    // the freed id is r2 itself.
    assert_eq!(
        s.used_rel_slots(),
        used_before - 1,
        "the corpse slot is reclaimed by the post-recovery GC"
    );
    assert_eq!(
        s.used_rel_slots(),
        2,
        "only the two committed edges remain allocated"
    );
    assert!(
        !s.rel(r2).unwrap().mvcc.in_use(),
        "the reclaimed corpse slot {r2} is no longer in use"
    );

    // The store is structurally consistent after the splice (the checker enforces the doubly-linked
    // incidence invariants: head prev == NULL, back-pointer symmetry, independent re-derivation).
    let report = graphus_storage::check::check_store(&mut s, &[]).unwrap();
    assert!(
        report.is_consistent(),
        "store is consistent after corpse splice: {:?}",
        report.violations
    );
}

/// LIVE rollback (`rmp` #220, not the crash path of the test above) of the **middle** writer among
/// three concurrent prepends onto one supernode. The two committed edges must survive and — crucially
/// for the space-leak fix — the aborted middle writer's relationship corpse must be **reclaimed** by a
/// subsequent GC, returning the used rel-slot count to the no-corpse baseline (degree stays 2).
#[test]
fn live_rollback_of_middle_prepend_reclaims_the_corpse() {
    let mut s = fresh();
    let rt = s.intern_token(Namespace::RelType, "R").unwrap();

    // Setup (committed): hub + three leaves.
    let setup = TxnId(1);
    s.begin(setup);
    let (hub, _) = s.create_node(setup).unwrap();
    let (l1, _) = s.create_node(setup).unwrap();
    let (l2, _) = s.create_node(setup).unwrap();
    let (l3, _) = s.create_node(setup).unwrap();
    s.commit(setup).unwrap();

    // Three interleaved prepends onto hub; T2 (the MIDDLE, r2) is rolled back LIVE while T1/T3 commit.
    let t1 = TxnId(2);
    let t2 = TxnId(3);
    let t3 = TxnId(4);
    s.begin(t1);
    s.begin(t2);
    s.begin(t3);
    let (r1, _) = s.create_rel(t1, rt, hub, l1).unwrap();
    let (r2, _) = s.create_rel(t2, rt, hub, l2).unwrap();
    let (r3, _) = s.create_rel(t3, rt, hub, l3).unwrap();
    s.commit(t1).unwrap();
    s.rollback(t2).unwrap(); // the middle writer aborts: leaves r2 as a dead-link corpse
    s.commit(t3).unwrap();

    // Both committed edges survive; the corpse r2 is threaded through but not collected.
    let mut incident = s.incident_rels(hub).unwrap();
    incident.sort_unstable();
    assert_eq!(
        incident,
        vec![r1, r3],
        "the two committed edges survive the abort"
    );
    assert_eq!(s.degree(hub).unwrap(), 2);
    let used_with_corpse = s.used_rel_slots();
    assert_eq!(
        used_with_corpse, 3,
        "before GC the corpse r2 still occupies a slot (2 live + 1 corpse)"
    );
    assert!(
        !s.rel(r2).unwrap().mvcc.in_use(),
        "r2 is a not-in-use corpse before GC"
    );

    // A GC pass splices and reclaims the corpse: used slots drop to the two-survivor baseline.
    let watermark = s.snapshot_ts();
    s.begin(TxnId(5));
    s.gc(TxnId(5), watermark).unwrap();
    s.commit(TxnId(5)).unwrap();

    let mut incident = s.incident_rels(hub).unwrap();
    incident.sort_unstable();
    assert_eq!(
        incident,
        vec![r1, r3],
        "survivors remain after the corpse splice"
    );
    assert_eq!(s.degree(hub).unwrap(), 2, "degree stays 2 after the splice");
    assert_eq!(
        s.used_rel_slots(),
        2,
        "the corpse slot is reclaimed: used rel slots return to the no-corpse baseline"
    );
    assert!(
        !s.rel(r2).unwrap().mvcc.in_use(),
        "the reclaimed corpse slot {r2} is no longer in use"
    );

    // Re-running GC is idempotent (the corpse is already gone — nothing more to splice).
    let watermark = s.snapshot_ts();
    s.begin(TxnId(6));
    s.gc(TxnId(6), watermark).unwrap();
    s.commit(TxnId(6)).unwrap();
    assert_eq!(
        s.used_rel_slots(),
        2,
        "a second GC pass reclaims nothing further"
    );

    let report = graphus_storage::check::check_store(&mut s, &[]).unwrap();
    assert!(
        report.is_consistent(),
        "store is consistent after corpse splice: {:?}",
        report.violations
    );
}

/// Leak-BOUNDARY regression (`rmp` #220, the empirical proof the leak is fixed): drive the
/// create/abort churn workload — repeatedly open three concurrent writers prepending an edge onto a
/// shared hub, commit two and abort the pivot (leaving a corpse), then delete the two committed edges
/// — for many iterations, running GC each round. The physical rel-slot high-water and the used-slot
/// count MUST stay BOUNDED (return to a flat baseline after GC), so the corpse leak cannot silently
/// regress. Before the fix, `used_rel_slots` grew by one per aborted creation, monotonically forever.
#[test]
fn churn_create_abort_keeps_rel_slots_bounded() {
    let mut s = fresh();
    let rt = s.intern_token(Namespace::RelType, "R").unwrap();

    // Committed hub + three reusable leaves.
    let setup = TxnId(1);
    s.begin(setup);
    let (hub, _) = s.create_node(setup).unwrap();
    let (a, _) = s.create_node(setup).unwrap();
    let (b, _) = s.create_node(setup).unwrap();
    let (c, _) = s.create_node(setup).unwrap();
    s.commit(setup).unwrap();

    let mut txn = 2u64;
    let mut next = || {
        let t = TxnId(txn);
        txn += 1;
        t
    };

    let mut high_water_after_gc = Vec::new();
    let mut used_after_gc = Vec::new();

    for _round in 0..40 {
        // Three concurrent prepends onto the shared hub; commit two, abort the middle pivot.
        let t1 = next();
        let t2 = next();
        let t3 = next();
        s.begin(t1);
        s.begin(t2);
        s.begin(t3);
        let (r1, _) = s.create_rel(t1, rt, hub, a).unwrap();
        let (_r2, _) = s.create_rel(t2, rt, hub, b).unwrap(); // the pivot -> corpse on abort
        let (r3, _) = s.create_rel(t3, rt, hub, c).unwrap();
        s.commit(t1).unwrap();
        s.rollback(t2).unwrap();
        s.commit(t3).unwrap();
        assert_eq!(s.degree(hub).unwrap(), 2, "two committed edges this round");

        // Delete the two committed edges (tombstone), so the LOGICAL rel count returns to zero each
        // round — the only thing that should accumulate without the fix is the leaked corpse slots.
        let td = next();
        s.begin(td);
        s.delete_rel(td, r1).unwrap();
        s.delete_rel(td, r3).unwrap();
        s.commit(td).unwrap();
        // delete_rel is an MVCC tombstone: the slots stay in_use and in the incidence chain (degree
        // still 2) until GC reclaims them — so the logical count returns to zero only after GC below.

        // GC at a watermark past everything: reclaims the two tombstones AND splices the corpse.
        let watermark = s.snapshot_ts();
        let tg = next();
        s.begin(tg);
        s.gc(tg, watermark).unwrap();
        s.commit(tg).unwrap();

        // After GC the hub has no incident rels and ZERO used rel slots remain — the corpse was
        // freed, not leaked.
        assert_eq!(s.degree(hub).unwrap(), 0);
        assert_eq!(
            s.used_rel_slots(),
            0,
            "after GC no rel slot is used (corpse reclaimed, not leaked)"
        );

        high_water_after_gc.push(s.rel_high_water());
        used_after_gc.push(s.used_rel_slots());
    }

    // BOUNDEDNESS: the used-slot count is a flat zero across all rounds (the corpse never accumulates),
    // and the physical high-water stops growing — it never exceeds the few slots one round needs,
    // because freed corpse + tombstone slots are reused from the free list round after round.
    assert!(
        used_after_gc.iter().all(|&u| u == 0),
        "used rel slots stay flat at 0 across all churn rounds: {used_after_gc:?}"
    );
    let max_hw = high_water_after_gc.iter().copied().max().unwrap();
    assert!(
        max_hw <= 4,
        "rel high-water stays bounded under churn (freed slots are reused), max was {max_hw}: \
         {high_water_after_gc:?}"
    );
    // The high-water is identical from the second round on — proof the leak does not creep.
    assert!(
        high_water_after_gc.windows(2).skip(1).all(|w| w[0] == w[1]),
        "rel high-water is stable across rounds (no monotonic creep): {high_water_after_gc:?}"
    );

    let report = graphus_storage::check::check_store(&mut s, &[]).unwrap();
    assert!(
        report.is_consistent(),
        "store stays consistent across churn: {:?}",
        report.violations
    );
}

/// A **run of consecutive corpses** (`rmp` #220): two adjacent aborted prepends between two committed
/// edges on one hub. The splice must collapse the whole run LIVE-to-LIVE in one bridge — never leaving
/// a live link pointing at a freed corpse slot — so both committed edges survive and BOTH corpse slots
/// are reclaimed. This pins the exact hazard a per-corpse splice mishandled (it severed the chain).
#[test]
fn consecutive_corpse_run_is_collapsed_and_both_reclaimed() {
    let mut s = fresh();
    let rt = s.intern_token(Namespace::RelType, "R").unwrap();

    let setup = TxnId(1);
    s.begin(setup);
    let (hub, _) = s.create_node(setup).unwrap();
    let (l1, _) = s.create_node(setup).unwrap();
    let (l2, _) = s.create_node(setup).unwrap();
    let (l3, _) = s.create_node(setup).unwrap();
    let (l4, _) = s.create_node(setup).unwrap();
    s.commit(setup).unwrap();

    // Four interleaved prepends. The chain head ends up:  r4 -> r3 -> r2 -> r1.
    // Commit the OUTER two (r1 oldest, r4 newest); abort the INNER two (r2, r3) so they form a run of
    // two consecutive corpses sandwiched between the two committed edges.
    let (t1, t2, t3, t4) = (TxnId(2), TxnId(3), TxnId(4), TxnId(5));
    s.begin(t1);
    s.begin(t2);
    s.begin(t3);
    s.begin(t4);
    let (r1, _) = s.create_rel(t1, rt, hub, l1).unwrap();
    let (r2, _) = s.create_rel(t2, rt, hub, l2).unwrap();
    let (r3, _) = s.create_rel(t3, rt, hub, l3).unwrap();
    let (r4, _) = s.create_rel(t4, rt, hub, l4).unwrap();
    // Commit the OUTER two first, so that when the inner two abort a committed writer (r4, the head) is
    // threaded above them: the header-only creation undo then leaves them as corpses (instead of the
    // plain-unlink path an abort with nothing committed on top would take), forming the run of two
    // consecutive corpses r3 -> r2 between live head r4 and live tail r1.
    s.commit(t1).unwrap();
    s.commit(t4).unwrap();
    s.rollback(t3).unwrap(); // corpse (r4 committed above it)
    s.rollback(t2).unwrap(); // corpse, adjacent to r3 -> a run of length 2
    let _ = (r2, r3); // r2, r3 are the two corpses in the run

    let mut incident = s.incident_rels(hub).unwrap();
    incident.sort_unstable();
    assert_eq!(
        incident,
        vec![r1, r4],
        "both committed edges survive a 2-corpse run"
    );
    assert_eq!(s.used_rel_slots(), 4, "2 live + 2 corpses before GC");

    let watermark = s.snapshot_ts();
    s.begin(TxnId(6));
    s.gc(TxnId(6), watermark).unwrap();
    s.commit(TxnId(6)).unwrap();

    let mut incident = s.incident_rels(hub).unwrap();
    incident.sort_unstable();
    assert_eq!(
        incident,
        vec![r1, r4],
        "both committed edges survive the run collapse — the chain was not severed"
    );
    assert_eq!(s.degree(hub).unwrap(), 2);
    assert_eq!(
        s.used_rel_slots(),
        2,
        "both corpse slots in the run are reclaimed"
    );
    assert!(!s.rel(r2).unwrap().mvcc.in_use());
    assert!(!s.rel(r3).unwrap().mvcc.in_use());

    let report = graphus_storage::check::check_store(&mut s, &[]).unwrap();
    assert!(
        report.is_consistent(),
        "store is consistent after the run collapse: {:?}",
        report.violations
    );
}

/// A **self-loop corpse** (`rmp` #220, `04 §2.4`): an aborted self-loop creation threads its corpse
/// into the node's single chain TWICE (once per side). The splice must remove both links and reclaim
/// the one slot, leaving a committed neighbouring edge and a committed self-loop intact.
#[test]
fn self_loop_corpse_is_spliced_from_both_links() {
    let mut s = fresh();
    let rt = s.intern_token(Namespace::RelType, "R").unwrap();

    let setup = TxnId(1);
    s.begin(setup);
    let (hub, _) = s.create_node(setup).unwrap();
    let (leaf, _) = s.create_node(setup).unwrap();
    s.commit(setup).unwrap();

    // A committed plain edge, then an aborted self-loop (the corpse, threaded twice into hub's chain),
    // then a committed self-loop on top.
    let (t1, t2, t3) = (TxnId(2), TxnId(3), TxnId(4));
    s.begin(t1);
    s.begin(t2);
    s.begin(t3);
    let (r1, _) = s.create_rel(t1, rt, hub, leaf).unwrap(); // plain committed edge
    let (loop_corpse, _) = s.create_rel(t2, rt, hub, hub).unwrap(); // self-loop, will abort
    let (loop_live, _) = s.create_rel(t3, rt, hub, hub).unwrap(); // self-loop, committed
    s.commit(t1).unwrap();
    s.rollback(t2).unwrap(); // self-loop corpse
    s.commit(t3).unwrap();

    let mut incident = s.incident_rels(hub).unwrap();
    incident.sort_unstable();
    assert_eq!(
        incident,
        vec![r1, loop_live],
        "the committed edge and committed self-loop survive the aborted self-loop"
    );
    assert_eq!(
        s.degree(hub).unwrap(),
        2,
        "self-loop counted once: degree 2"
    );
    assert_eq!(
        s.used_rel_slots(),
        3,
        "2 live + 1 self-loop corpse before GC"
    );

    let watermark = s.snapshot_ts();
    s.begin(TxnId(5));
    s.gc(TxnId(5), watermark).unwrap();
    s.commit(TxnId(5)).unwrap();

    let mut incident = s.incident_rels(hub).unwrap();
    incident.sort_unstable();
    assert_eq!(
        incident,
        vec![r1, loop_live],
        "survivors remain after the self-loop corpse is spliced from both links"
    );
    assert_eq!(s.degree(hub).unwrap(), 2);
    assert_eq!(
        s.used_rel_slots(),
        2,
        "the self-loop corpse's single slot is reclaimed"
    );
    assert!(!s.rel(loop_corpse).unwrap().mvcc.in_use());

    let report = graphus_storage::check::check_store(&mut s, &[]).unwrap();
    assert!(
        report.is_consistent(),
        "store is consistent after the self-loop corpse splice: {:?}",
        report.violations
    );
}
