//! Coordinator-level tests for the GC **min-active-snapshot watermark** accounting (`rmp` #337
//! Slice 2; the #220 premature-reclamation class), exercised through the production
//! [`TxnCoordinator`] seam end-to-end via Cypher.
//!
//! [`TxnCoordinator::oldest_active_snapshot`] is the begin timestamp of the oldest still-open reader
//! (read-only readers included); [`TxnCoordinator::gc_watermark`] is that value, or the store's
//! current snapshot high-water when no transaction is open; and [`TxnCoordinator::gc`] runs one MVCC
//! GC pass at that reader-safe watermark. Together they guarantee a GC pass can never physically
//! reclaim a version a live reader's snapshot must still observe — staging for the #305 GC trigger.
//!
//! There is no production GC trigger yet (`rmp` #305 owns scheduling), so these tests *are* the teeth
//! that keep the accounting honest: the deterministic `graphus-dst` scenario
//! (`gc_watermark_teeth.rs`) proves the storage-level mechanism; this proves the coordinator computes
//! and applies the safe watermark over the real engine.

use graphus_core::{Timestamp, TxnId, Value};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: RecordStore<MemBlockDevice, MemLogSink> =
        RecordStore::create(device, wal, 64, 1).expect("create store");
    TxnCoordinator::new(store)
}

fn compile(src: &str) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

/// Runs one statement under `txn` and returns its rows (asserting no captured error).
fn run_stmt(coord: &Coord, txn: TxnId, src: &str) -> Vec<Row> {
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let rows = {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    assert!(graph.take_error().is_none(), "captured error in: {src}");
    rows
}

/// The integer value of `n.v` for the single `:Reg` node, as visible to `txn`'s snapshot, or `None`.
fn read_v(coord: &Coord, txn: TxnId) -> Option<i64> {
    let rows = run_stmt(coord, txn, "MATCH (n:Reg) RETURN n.v AS v");
    match rows.first().map(|r| r.value("v")) {
        Some(Value::Integer(v)) => Some(v),
        _ => None,
    }
}

/// The store's current snapshot high-water, read through the lending seam (no coordinator accessor
/// is needed for it). A transaction that begins now snapshots at exactly this timestamp.
fn snapshot_ts(coord: &Coord) -> Timestamp {
    coord.with_store_mut(|s| s.snapshot_ts())
}

/// `oldest_active_snapshot()` is `None` with no open transaction, equals the single open reader's
/// begin snapshot, and reduces to the **minimum** across several overlapping readers. Asserted
/// relationally (every committed transaction — readers included — advances the store's commit
/// timestamp via `next_commit_ts`, so begin snapshots are captured live rather than hard-coded).
#[test]
fn oldest_active_snapshot_is_the_min_over_open_readers() {
    let mut coord = fresh_coord();

    assert_eq!(
        coord.oldest_active_snapshot(),
        None,
        "no open transaction → no low-water mark"
    );

    // Seed two commits so overlapping readers can begin at distinct, advanced snapshots.
    let t1 = coord.begin_serializable();
    run_stmt(&coord, t1, "CREATE (:Reg {v: 1})");
    coord.commit(t1).expect("commit t1");
    let t2 = coord.begin_serializable();
    run_stmt(&coord, t2, "MATCH (n:Reg) SET n.v = 2");
    coord.commit(t2).expect("commit t2");

    // The first reader: its begin snapshot is the store's current high-water.
    let r_old_begin = snapshot_ts(&coord);
    let r_old = coord.begin_serializable();
    assert_eq!(
        coord.oldest_active_snapshot(),
        Some(r_old_begin),
        "the only open reader began at the then-current snapshot"
    );
    assert_eq!(
        coord.gc_watermark(),
        r_old_begin,
        "gc_watermark == the open reader's snapshot"
    );

    // A second, later reader begins at a strictly newer snapshot; the low-water stays at the OLDER.
    let r_new_begin = snapshot_ts(&coord);
    let r_new = coord.begin_serializable();
    assert!(
        r_new_begin >= r_old_begin,
        "the later reader's begin snapshot is not older"
    );
    assert_eq!(
        coord.oldest_active_snapshot(),
        Some(r_old_begin),
        "the min across the two overlapping readers is the older reader's snapshot"
    );

    // Closing the older reader lifts the low-water to the younger reader's snapshot.
    coord.commit(r_old).expect("commit r_old");
    assert_eq!(
        coord.oldest_active_snapshot(),
        Some(r_new_begin),
        "with the old reader gone, the young reader now pins the low-water"
    );

    // Closing the last reader: no low-water; gc_watermark falls back to the current snapshot ts.
    coord.commit(r_new).expect("commit r_new");
    assert_eq!(coord.oldest_active_snapshot(), None);
    assert_eq!(
        coord.gc_watermark(),
        snapshot_ts(&coord),
        "no open reader → gc_watermark falls back to the store snapshot high-water"
    );
}

/// End-to-end: an old reader open across a concurrent overwrite + a coordinator GC pass still reads
/// its snapshot's value, because [`TxnCoordinator::gc`] uses the reader-safe watermark. This is the
/// production-seam analogue of the storage-level teeth in `graphus-dst/tests/gc_watermark_teeth.rs`.
#[test]
fn coordinator_gc_preserves_an_open_readers_version() {
    let mut coord = fresh_coord();

    // Seed the register at v = 1.
    let t1 = coord.begin_serializable();
    run_stmt(&coord, t1, "CREATE (:Reg {v: 1})");
    coord.commit(t1).expect("commit t1");

    // Open a long-running reader R; capture its begin snapshot. It reads v = 1.
    let r_begin = snapshot_ts(&coord);
    let r = coord.begin_serializable();
    assert_eq!(read_v(&coord, r), Some(1), "R sees v = 1 at its snapshot");
    assert_eq!(
        coord.oldest_active_snapshot(),
        Some(r_begin),
        "R pins the low-water mark at its begin snapshot"
    );

    // A concurrent writer overwrites v = 2 and commits (the old version is now a tombstone whose
    // xmax committed strictly after R's snapshot).
    let w = coord.begin_serializable();
    run_stmt(&coord, w, "MATCH (n:Reg) SET n.v = 2");
    coord.commit(w).expect("commit w");

    // While R is still open, the safe watermark is R's snapshot, NOT the latest commit.
    assert_eq!(
        coord.gc_watermark(),
        r_begin,
        "the open reader keeps the GC watermark at its snapshot"
    );
    assert!(
        snapshot_ts(&coord) > r_begin,
        "the writer's commit advanced the store snapshot past R's — the watermark must NOT follow it"
    );

    // Run a coordinator GC pass: it derives the watermark from R's snapshot, so it cannot reclaim the
    // old version R still needs. (It freezes committed headers — `frozen` may be > 0 — but reclaims
    // nothing protected by R.)
    let report = coord.gc().expect("coordinator gc pass");
    assert_eq!(
        report.reclaimed, 0,
        "the open reader R protects the old version from reclamation: reclaimed = {}",
        report.reclaimed
    );

    // R, still open, still reads its snapshot's value — no lost version (the ACID guarantee).
    assert_eq!(
        read_v(&coord, r),
        Some(1),
        "after the coordinator GC, the old reader still reads v = 1"
    );
    coord.commit(r).expect("commit R");

    // Once R is gone, the watermark advances to the store's current snapshot (no reader pins it), so
    // a GC pass may now reclaim the old version R was protecting.
    assert_eq!(
        coord.gc_watermark(),
        snapshot_ts(&coord),
        "no reader → watermark = the store snapshot high-water"
    );
    let report2 = coord.gc().expect("second gc pass");
    assert!(
        report2.reclaimed >= 1,
        "with no open reader the old tombstoned version becomes reclaimable: reclaimed = {}",
        report2.reclaimed
    );

    // A fresh reader sees the surviving current value v = 2.
    let r2 = coord.begin_serializable();
    assert_eq!(
        read_v(&coord, r2),
        Some(2),
        "the current value v = 2 survives GC"
    );
    coord.commit(r2).expect("commit r2");
}
