//! Crash-consistency verification of concurrent Cypher over the real store (`04 §4`/§11;
//! `rmp` task #47): committed transactions are durable and in-flight (loser) transactions are
//! undone after a crash + recovery, driven through the [`TxnCoordinator`] (`rmp` task #46).
//!
//! A crash is modelled with the Deterministic-Simulation-Testing devices (`04 §11`): the durable
//! WAL prefix (everything a committed transaction's group-commit `fdatasync` hardened) is replayed
//! onto a fresh device by [`recover_device`], then the store is reopened. The scenario interleaves
//! committed and never-committed transactions and **commits the keepers after the losers' writes**,
//! so the losers' records are hardened into the durable log and recovery must actively roll them
//! back (the committed-or-nothing guarantee), not merely omit them.

use graphus_core::TxnId;
use graphus_core::capability::Rng;
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
use graphus_sim::SimRng;
use graphus_storage::RecordStore;
use graphus_storage::recovery::recover_device;
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

fn fresh_store() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 64, 1).expect("create store")
}

fn compile(src: &str) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

/// Runs one statement of `txn` over the coordinator; returns its rows (the per-statement seam is
/// dropped before returning, so the transaction stays open without borrowing the store).
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
        "unexpected captured error: {:?}",
        graph.take_error()
    );
    rows
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

/// Counts the nodes carrying `label` in a fresh read transaction on `coord` — as the number of
/// `MATCH (n:label) RETURN n` rows. (We count rows rather than `count(n)`: a node-valued aggregate
/// needs the `Node` [`Value`](graphus_core::Value) variant, which is a deferred part of the value
/// model; the row count is exact for this purpose.)
fn count_label(coord: &mut Coord, label: &str) -> usize {
    let t = coord.begin_serializable();
    let rows = run_stmt(coord, t, &format!("MATCH (n:{label}) RETURN n"));
    coord.commit(t).expect("read commits");
    rows.len()
}

/// One crash scenario for `seed`: `keeps` committed `:Keep` nodes interleaved with `losers`
/// never-committed `:Loser` nodes, with the keepers committing after the losers so their records are
/// hardened into the durable log. After recovery, every `:Keep` must survive and no `:Loser` may.
fn run_crash_scenario(seed: u64, keeps: usize, losers: usize) {
    let mut rng = SimRng::new(seed);
    let mut coord = TxnCoordinator::new(fresh_store());

    // Open all the loser transactions first and write through them, but never commit them.
    let loser_txns: Vec<TxnId> = (0..losers).map(|_| coord.begin_serializable()).collect();
    for &lt in &loser_txns {
        // A distinct uncommitted node per loser; some also touch the overflow heap.
        let payload = if rng.next_u64() % 2 == 0 {
            "x".repeat(80)
        } else {
            "y".to_owned()
        };
        let _ = run_stmt(&coord, lt, &format!("CREATE (:Loser {{tag: '{payload}'}})"));
    }

    // Commit the keepers; each commit group-commits the WAL, hardening the losers' earlier writes
    // into the durable prefix — so recovery must actively undo them.
    for i in 0..keeps {
        let kt = coord.begin_serializable();
        let _ = run_stmt(&coord, kt, &format!("CREATE (:Keep {{i: {i}}})"));
        coord.commit(kt).expect("keeper commits");
    }

    // Crash: reclaim the store (the loser transactions remain open and uncommitted), then recover
    // from the durable WAL alone onto a fresh device.
    let store = coord.into_store();
    let recovered = recover_no_force(&store);

    let mut coord2 = TxnCoordinator::new(recovered);
    assert_eq!(
        count_label(&mut coord2, "Keep"),
        keeps,
        "seed {seed}: all {keeps} committed :Keep nodes survive the crash"
    );
    assert_eq!(
        count_label(&mut coord2, "Loser"),
        0,
        "seed {seed}: every uncommitted :Loser node is rolled back by recovery"
    );
}

#[test]
fn committed_durable_and_losers_rolled_back_across_seeds() {
    // A spread of seeds and keep/loser mixes; each must come back committed-or-nothing.
    for seed in 1..=8u64 {
        let keeps = 1 + (seed as usize % 4); // 1..=4 committed transactions
        let losers = 1 + ((seed as usize + 1) % 3); // 1..=3 in-flight (loser) transactions
        run_crash_scenario(seed, keeps, losers);
    }
}

#[test]
fn no_loser_writes_means_clean_recovery() {
    // Pure-commit baseline: with no in-flight transactions, recovery reproduces exactly the
    // committed graph (a sanity floor for the scenario above).
    run_crash_scenario(100, 5, 0);
}
