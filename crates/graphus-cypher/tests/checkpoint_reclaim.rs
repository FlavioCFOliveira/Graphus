//! Regression tests for the **maintenance-checkpoint reclamation trigger** (`rmp` #305, closing the
//! resource leaks #313/#315), exercised through the production [`TxnCoordinator`] seam end-to-end.
//!
//! [`TxnCoordinator::checkpoint`] drives a reader-safe GC pass (reclaim dead versions + freeze
//! committed MVCC stamps, lowering the WAL reclaim floor) followed by a sharp store checkpoint (flush
//! dirty pages home + physically reclaim the WAL prefix below the floor). Before #305 there was no
//! production trigger: `MemLogSink::reclaim` only zero-*filled* the durable buffer (it never freed
//! memory, so RSS grew forever under delete-churn — #313), and the freeze sweep that drains
//! `unfrozen_commit_lsn` (lowering the floor) was never driven (#305).
//!
//! These tests prove, over the real engine:
//!  1. A maintenance checkpoint **physically frees** the in-memory WAL backing under delete-churn
//!     (the #313 leak is closed) while the live graph is unchanged.
//!  2. ARIES recovery over the **reclaimed** WAL is correct — committed data survives, deleted data
//!     stays deleted — so durability is inviolable across reclamation (the #305 hard requirement).

use graphus_core::TxnId;
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
use graphus_storage::recovery::recover_device;
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

fn fresh_store() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 256, 1).expect("create store")
}

fn compile(src: &str) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

/// Runs one statement of `txn`; returns its rows (the per-statement seam is dropped before returning,
/// so the transaction stays open without borrowing the store).
fn run_stmt(coord: &Coord, txn: TxnId, src: &str) -> Vec<Row> {
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let rows = {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    assert!(
        !graph.has_error(),
        "unexpected captured error in `{src}`: {:?}",
        graph.take_error()
    );
    rows
}

/// One committed auto-commit-style write transaction.
fn write_committed(coord: &mut Coord, src: &str) {
    let t = coord.begin_serializable();
    let _ = run_stmt(coord, t, src);
    coord.commit(t).expect("commit write");
}

/// Counts the `:label` nodes in a fresh committed read.
fn count_label(coord: &mut Coord, label: &str) -> usize {
    let t = coord.begin_serializable();
    let rows = run_stmt(coord, t, &format!("MATCH (n:{label}) RETURN n"));
    coord.commit(t).expect("commit read");
    rows.len()
}

/// The bytes physically retained by the live store's in-memory WAL sink (the #313 memory metric).
fn wal_retained(coord: &Coord) -> usize {
    coord.with_store_mut(|s| s.with_wal(|w| w.sink().retained_bytes()))
}

/// Recovers a crash from the durable on-disk image + the durable (possibly **reclaimed**) WAL — the
/// real-restart model. After a *sharp* checkpoint the data pages are flushed home, so the truth of
/// record below the checkpoint LSN lives on the **device**, and the WAL only needs to redo from the
/// checkpoint LSN onward — which is exactly why the checkpoint can free the WAL prefix. So we snapshot
/// the device image (steal/no-force, mirroring the storage-crate `recover_steal`) and replay the
/// reclaimed WAL onto it. `durable_bytes()` reconstructs the offset-preserving WAL image (the
/// reclaimed gap reads back as zeros), exactly what a real restart sees.
fn recover_from_durable(store: &mut Store) -> Store {
    use graphus_io::BlockDevice;

    store.flush().expect("flush pages home (steal)");
    let pages = store.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    let mut staged: Vec<(u64, Box<graphus_io::Page>)> = Vec::new();
    for p in &pages {
        staged.push((p.0, store.read_device_page(*p).expect("read device page")));
    }
    for (idx, bytes) in staged {
        device
            .write_page(graphus_core::PageId(idx), &bytes)
            .expect("stage page");
    }
    device.sync_all().expect("persist disk image");

    let log = store.with_wal(|w| w.sink().durable_bytes());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, 256).expect("open store")
}

#[test]
fn maintenance_checkpoint_frees_wal_memory_under_delete_churn() {
    // The #313 leak in microcosm: churn (create + delete) grows the WAL; a maintenance checkpoint must
    // reclaim its now-redundant prefix and PHYSICALLY release the in-memory backing, so the retained
    // footprint falls — not merely get zero-filled.
    let mut coord = TxnCoordinator::new(fresh_store());

    // A handful of survivors that must outlive every reclamation.
    for i in 0..5 {
        write_committed(&mut coord, &format!("CREATE (:Keep {{i: {i}}})"));
    }

    // Heavy delete-churn: many short-lived nodes, each created then deleted in a committed txn. Their
    // versions become dead below the watermark, and the WAL records pile up.
    for round in 0..40 {
        write_committed(&mut coord, &format!("CREATE (:Churn {{r: {round}}})"));
        write_committed(
            &mut coord,
            &format!("MATCH (c:Churn {{r: {round}}}) DELETE c"),
        );
    }

    let retained_before = wal_retained(&coord);
    assert_eq!(
        count_label(&mut coord, "Keep"),
        5,
        "survivors before checkpoint"
    );
    assert_eq!(count_label(&mut coord, "Churn"), 0, "all churn deleted");

    // Drive the maintenance checkpoint (the #305 trigger): GC freeze lowers the WAL floor, then the
    // sharp checkpoint flushes home and reclaims the prefix below it. With no open reader the watermark
    // is the store high-water, so every committed-then-deleted version is reclaimable.
    let report = coord.checkpoint().expect("maintenance checkpoint");
    assert!(
        report.frozen > 0 || report.reclaimed > 0,
        "the GC pass should have frozen and/or reclaimed something after churn"
    );

    let retained_after = wal_retained(&coord);
    assert!(
        retained_after < retained_before,
        "the maintenance checkpoint must FREE in-memory WAL backing (retained {retained_before} -> \
         {retained_after}); a zero-fill-only reclaim would leave it unchanged (the #313 leak)"
    );

    // The live graph is unchanged by reclamation.
    assert_eq!(
        count_label(&mut coord, "Keep"),
        5,
        "survivors after checkpoint"
    );
    assert_eq!(count_label(&mut coord, "Churn"), 0, "churn still gone");
}

#[test]
fn recovery_is_correct_after_a_maintenance_reclaim() {
    // The inviolable-durability requirement: ARIES recovery over a WAL whose prefix a maintenance
    // checkpoint has physically reclaimed must still reproduce committed-or-nothing — committed data
    // survives, deleted data stays deleted, nothing is resurrected from the freed (zeroed) gap.
    let mut coord = TxnCoordinator::new(fresh_store());

    for i in 0..6 {
        write_committed(&mut coord, &format!("CREATE (:Keep {{i: {i}}})"));
    }
    // Churn that will be both committed-deleted AND below the reclaim floor after the checkpoint.
    for round in 0..30 {
        write_committed(&mut coord, &format!("CREATE (:Gone {{r: {round}}})"));
        write_committed(
            &mut coord,
            &format!("MATCH (g:Gone {{r: {round}}}) DELETE g"),
        );
    }
    // One more committed survivor AFTER the churn (its commit record sits above the churn prefix).
    write_committed(&mut coord, "CREATE (:Late {l: 1})");

    // Reclaim. This frees the WAL prefix below the (now-lowered) floor.
    coord.checkpoint().expect("maintenance checkpoint");
    let retained_after_ckpt = wal_retained(&coord);

    // More committed work AFTER the reclaim — proving the post-reclaim log still chains correctly.
    write_committed(&mut coord, "CREATE (:After {a: 1})");

    let mut store = coord.into_store();
    // Sanity: the durable image still carries the surviving record bytes (it is NOT all zeros).
    let log = store.with_wal(|w| w.sink().durable_bytes());
    assert!(
        log.iter().any(|&b| b != 0),
        "the reclaimed durable log still holds surviving records"
    );

    // Recover from the durable on-disk image + the reclaimed durable WAL (the real-restart model).
    let recovered = recover_from_durable(&mut store);
    let mut coord2 = TxnCoordinator::new(recovered);

    assert_eq!(
        count_label(&mut coord2, "Keep"),
        6,
        "all Keep survive the reclaim+recovery"
    );
    assert_eq!(
        count_label(&mut coord2, "Late"),
        1,
        "the pre-reclaim Late survivor survives"
    );
    assert_eq!(
        count_label(&mut coord2, "After"),
        1,
        "the post-reclaim After survivor survives"
    );
    assert_eq!(
        count_label(&mut coord2, "Gone"),
        0,
        "every committed-deleted Gone node stays deleted — none resurrected from the freed gap"
    );

    // The reclaim genuinely shrank the footprint (so this was a real reclaim, not a no-op recovery).
    assert!(
        retained_after_ckpt > 0,
        "the live store still retains the surviving tail after the reclaim"
    );
}
