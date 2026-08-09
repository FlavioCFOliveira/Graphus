//! Elle/Jepsen-style serializability verification of concurrent Cypher over the real store
//! (`04-technical-design.md` §5.4/§11; `rmp` task #47).
//!
//! This drives **concurrent** Cypher transactions through the [`TxnCoordinator`] (`rmp` task #46),
//! records each committed transaction's read/write history, and feeds it to `graphus-txn`'s
//! Direct-Serialization-Graph [`HistoryChecker`] — the deterministic anomaly oracle (Adya / Berenson,
//! `04 §13`). An execution is serializable iff its DSG is acyclic, so the empirical claim is:
//!
//! > over many randomized concurrent histories, the SERIALIZABLE coordinator's committed
//! > transactions never form a serialization cycle.
//!
//! ## Register workload (write-skew prone)
//!
//! Each `(:Reg {k, v})` node is a versioned register whose **value is its version** (`v` starts at
//! `0` and every committed write installs the previous value `+1`, so committed per-key versions are
//! consecutive — exactly the version order the checker expects). Each transaction reads **two**
//! registers and writes **one** of them to `read_value + 1` — the write-skew shape that produces
//! rw-antidependencies. Under SERIALIZABLE the coordinator aborts a pivot on any dangerous structure,
//! so the committed histories stay acyclic; under the SNAPSHOT opt-in the same shape commits both and
//! the checker **catches** the cycle (the teeth test, proving the check is not vacuous).
//!
//! The recorded read set is the *logical* one (the two registers the workload chose), a subset of
//! the physical full-scan read set; a subset of an acyclic graph's edges is acyclic, so this never
//! reports a false anomaly, and it carries real wr/ww/rw edges so a pass is meaningful.

use graphus_core::capability::Rng;
use graphus_core::{TxnId, Value};
use graphus_cypher::ConstraintKind;
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
use graphus_txn::{HistoryChecker, IsolationLevel, TxnHistory};
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

/// Runs one statement of `txn`, returning its rows and whether it succeeded (no captured error).
fn run_stmt(coord: &Coord, txn: TxnId, src: &str) -> (Vec<Row>, bool) {
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let rows = {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    let ok = graph.take_error().is_none();
    (rows, ok)
}

/// Reads register `k`'s value on `txn`'s snapshot; `None` if the statement captured an error.
fn read_reg(coord: &Coord, txn: TxnId, k: u64) -> Option<i64> {
    let (rows, ok) = run_stmt(
        coord,
        txn,
        &format!("MATCH (n:Reg {{k: {k}}}) RETURN n.v AS v"),
    );
    if !ok {
        return None;
    }
    match rows.first().map(|r| r.value("v")) {
        Some(Value::Integer(v)) => Some(v),
        _ => None,
    }
}

/// Writes register `k`'s value to `new_v`; returns whether the statement succeeded (no conflict).
fn write_reg(coord: &Coord, txn: TxnId, k: u64, new_v: i64) -> bool {
    let (_rows, ok) = run_stmt(
        coord,
        txn,
        &format!("MATCH (n:Reg {{k: {k}}}) SET n.v = {new_v}"),
    );
    ok
}

/// Seeds `n` registers `(:Reg {k:i, v:0})` and commits them.
fn seed_registers(coord: &mut Coord, n: u64) {
    let t = coord.begin_serializable();
    for k in 0..n {
        let (_r, ok) = run_stmt(coord, t, &format!("CREATE (:Reg {{k: {k}, v: 0}})"));
        assert!(ok, "seed register {k}");
    }
    coord.commit(t).expect("seed commits");
}

/// Runs one write-skew-shaped transaction (read `a`, read `b`, write `a := a+1`) on the already-open
/// `txn`, building its [`TxnHistory`]. Returns `None` (the transaction should be rolled back) if a
/// read failed or the write hit a write-write conflict.
fn run_skew(coord: &Coord, txn: TxnId, a: u64, b: u64) -> Option<TxnHistory> {
    let va = read_reg(coord, txn, a)?;
    let vb = read_reg(coord, txn, b)?;
    if !write_reg(coord, txn, a, va + 1) {
        return None;
    }
    let mut h = TxnHistory::new(txn);
    h.read(a, va as u64);
    h.read(b, vb as u64);
    h.write(a, (va + 1) as u64);
    Some(h)
}

#[test]
fn serializable_concurrent_histories_have_no_anomaly() {
    const REGISTERS: u64 = 4;
    const ROUNDS: usize = 40;

    for seed in 1..=12u64 {
        let mut coord = fresh_coord();
        seed_registers(&mut coord, REGISTERS);
        let mut rng = SimRng::new(seed);
        let mut checker = HistoryChecker::new();

        for _ in 0..ROUNDS {
            // Two concurrent write-skew-prone transactions per round.
            let t1 = coord.begin_serializable();
            let t2 = coord.begin_serializable();

            let a1 = rng.next_u64() % REGISTERS;
            let b1 = (a1 + 1 + rng.next_u64() % (REGISTERS - 1)) % REGISTERS; // distinct from a1
            let a2 = rng.next_u64() % REGISTERS;
            let b2 = (a2 + 1 + rng.next_u64() % (REGISTERS - 1)) % REGISTERS;

            let h1 = run_skew(&coord, t1, a1, b1);
            let h2 = run_skew(&coord, t2, a2, b2);

            // Commit (or roll back the transactions whose statements already failed); only a
            // successfully committed transaction's history enters the checker.
            match h1 {
                Some(h) if coord.commit(t1).is_ok() => checker.add(h),
                _ => {
                    let _ = coord.rollback(t1);
                }
            }
            match h2 {
                Some(h) if coord.commit(t2).is_ok() => checker.add(h),
                _ => {
                    let _ = coord.rollback(t2);
                }
            }
        }

        assert_eq!(
            checker.find_anomaly(),
            None,
            "seed {seed}: SERIALIZABLE coordinator produced a non-serializable history"
        );
    }
}

#[test]
fn checker_catches_write_skew_permitted_under_snapshot_isolation() {
    // Teeth on Cypher-generated histories: the SAME write-skew shape under the SNAPSHOT opt-in
    // commits both transactions, and the Elle checker reports the serialization cycle (`04 §5.4`).
    let mut coord = fresh_coord();
    seed_registers(&mut coord, 2);

    let t1 = coord.begin(IsolationLevel::Snapshot);
    let t2 = coord.begin(IsolationLevel::Snapshot);

    // T1 reads regs 0 and 1, writes reg 0; T2 reads 1 and 0, writes reg 1 — both off the same v=0
    // snapshot, so neither sees the other's write.
    let h1 = run_skew(&coord, t1, 0, 1).expect("t1 statements succeed under SI");
    let h2 = run_skew(&coord, t2, 1, 0).expect("t2 statements succeed under SI");

    coord.commit(t1).expect("SI t1 commits");
    coord.commit(t2).expect("SI t2 commits");

    let mut checker = HistoryChecker::new();
    checker.add(h1);
    checker.add(h2);
    let cycle = checker
        .find_anomaly()
        .expect("write-skew under Snapshot Isolation must be flagged as an anomaly");
    assert!(
        cycle.contains(&t1) && cycle.contains(&t2),
        "the cycle runs through both write-skew transactions: {cycle:?}"
    );
}

// =================================================================================================
// Relationship-property registers under a RELATIONSHIP KEY (`rmp` #683)
// =================================================================================================
//
// #683 replaced the relationship equality-seek's `mark_all_live_rels()` blanket with the precise
// `PredicateRead::RelEquality` marker, and made the write-path enforcement index-backed. That is a
// change to which rw-edges FORM, so it must be exercised against the deterministic serializability
// oracle over many randomized interleavings — not only the hand-built pivots in
// `tests/rel_seek_phantom_oracle.rs` and `tests/ssi_rel_write_path_oracle.rs`, which check specific
// shapes the author thought of.
//
// The DST caveat is honest and worth stating: this simulator is **statement-granular on one thread**,
// so it explores the interleavings of whole statements, not of the instructions inside them. It cannot
// find a data race inside a statement; it can and does find missing rw-edges between statements, which
// is exactly the failure mode #683 could introduce.

/// The relationship-register twin of [`compile`], planning against the coordinator's REAL catalog so
/// the reads are served by the `RelIndexSeek` whose footprint #683 changed. With
/// `IndexCatalog::empty()` these histories would silently exercise the scan fallback instead.
fn compile_rel(coord: &Coord, src: &str) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &coord.catalog())
}

fn run_rel_stmt(coord: &Coord, txn: TxnId, src: &str) -> (Vec<Row>, bool) {
    let plan = compile_rel(coord, src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let rows = {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    let ok = graph.take_error().is_none();
    (rows, ok)
}

/// Seeds `n` relationship registers `(:Src)-[:REG {k:i, v:0}]->(:Dst)` and declares a REL KEY on `k`,
/// so every subsequent `SET r.v` runs the relationship-key enforcement reader (the #683 path).
fn seed_rel_registers(coord: &mut Coord, n: u64) {
    let t = coord.begin_serializable();
    let (_r, ok) = run_stmt(coord, t, "CREATE (:Src), (:Dst)");
    assert!(ok, "seed endpoints");
    coord.commit(t).expect("endpoints commit");
    for k in 0..n {
        let t = coord.begin_serializable();
        let (_r, ok) = run_stmt(
            coord,
            t,
            &format!("MATCH (s:Src), (d:Dst) CREATE (s)-[:REG {{k: {k}, v: 0}}]->(d)"),
        );
        assert!(ok, "seed rel register {k}");
        coord.commit(t).expect("rel register commits");
    }
    coord
        .create_constraint_general("reg_key", "REG", &["k"], ConstraintKind::RelKey, None)
        .expect("declare REL KEY over conforming data");
}

fn read_rel_reg(coord: &Coord, txn: TxnId, k: u64) -> Option<i64> {
    let (rows, ok) = run_rel_stmt(
        coord,
        txn,
        &format!("MATCH ()-[r:REG]->() WHERE r.k = {k} RETURN r.v AS v"),
    );
    if !ok {
        return None;
    }
    match rows.first().map(|r| r.value("v")) {
        Some(Value::Integer(v)) => Some(v),
        _ => None,
    }
}

fn write_rel_reg(coord: &Coord, txn: TxnId, k: u64, new_v: i64) -> bool {
    let (_rows, ok) = run_rel_stmt(
        coord,
        txn,
        &format!("MATCH ()-[r:REG]->() WHERE r.k = {k} SET r.v = {new_v}"),
    );
    ok
}

/// The write-skew shape over relationship registers: read `a`, read `b`, write `a := a+1`.
fn run_rel_skew(coord: &Coord, txn: TxnId, a: u64, b: u64) -> Option<TxnHistory> {
    let va = read_rel_reg(coord, txn, a)?;
    let vb = read_rel_reg(coord, txn, b)?;
    if !write_rel_reg(coord, txn, a, va + 1) {
        return None;
    }
    let mut h = TxnHistory::new(txn);
    h.read(a, va as u64);
    h.read(b, vb as u64);
    h.write(a, (va + 1) as u64);
    Some(h)
}

#[test]
fn serializable_concurrent_relationship_histories_have_no_anomaly() {
    // The relationship twin of `serializable_concurrent_histories_have_no_anomaly`, over the #683
    // footprint: every read is a `RelIndexSeek` (which now registers `RelEquality` instead of marking
    // every live relationship) and every write runs the index-backed REL KEY enforcement. If the
    // narrower footprint lost an rw-edge that mattered, a committed history would form a DSG cycle.
    const REGISTERS: u64 = 4;
    const ROUNDS: usize = 40;

    // NON-VACUITY: a serializability check over an empty (all-aborted) history passes trivially.
    // Count what actually committed and require a real history.
    let mut total_committed = 0usize;

    for seed in 1..=12u64 {
        let mut coord = fresh_coord();
        seed_rel_registers(&mut coord, REGISTERS);
        let mut rng = SimRng::new(seed);
        let mut checker = HistoryChecker::new();

        for _ in 0..ROUNDS {
            let t1 = coord.begin_serializable();
            let t2 = coord.begin_serializable();

            let a1 = rng.next_u64() % REGISTERS;
            let b1 = (a1 + 1 + rng.next_u64() % (REGISTERS - 1)) % REGISTERS; // distinct from a1
            let a2 = rng.next_u64() % REGISTERS;
            let b2 = (a2 + 1 + rng.next_u64() % (REGISTERS - 1)) % REGISTERS;

            let h1 = run_rel_skew(&coord, t1, a1, b1);
            let h2 = run_rel_skew(&coord, t2, a2, b2);

            match h1 {
                Some(h) if coord.commit(t1).is_ok() => {
                    checker.add(h);
                    total_committed += 1;
                }
                _ => {
                    let _ = coord.rollback(t1);
                }
            }
            match h2 {
                Some(h) if coord.commit(t2).is_ok() => {
                    checker.add(h);
                    total_committed += 1;
                }
                _ => {
                    let _ = coord.rollback(t2);
                }
            }
        }

        assert_eq!(
            checker.find_anomaly(),
            None,
            "seed {seed}: SERIALIZABLE coordinator produced a non-serializable relationship history \
             — the #683 RelEquality footprint lost an rw-edge that the blanket used to supply"
        );
    }

    // NON-VACUITY CONTROL: the histories checked above must be substantial. If the #683 footprint
    // were somehow aborting everything, `find_anomaly` would trivially return None and this test
    // would pass while proving nothing.
    assert!(
        total_committed > 100,
        "NON-VACUITY CONTROL FAILED: only {total_committed} relationship transactions committed \
         across 12 seeds x {ROUNDS} rounds — the serializability check above is near-vacuous"
    );
}

#[test]
fn rel_uniqueness_never_commits_a_duplicate_under_randomized_interleavings() {
    // The ACID invariant #683 must never break, driven deterministically over many interleavings:
    // concurrent creators frequently drawing the SAME `tx_id` must never leave two relationships
    // holding it.
    //
    // This is the property that a narrower SSI footprint could plausibly break, and it is checked as
    // an invariant of the resulting GRAPH — not of any particular abort decision — so it holds the
    // implementation to the guarantee rather than to a mechanism.
    //
    // WORKLOAD SHAPE (this matters — an earlier draft drew from a fixed 3-value domain, which
    // saturated after 3 commits per seed and then rejected every write at statement time: the
    // invariant held vacuously over a graph that never grew). Each round draws from its OWN 2-value
    // window, so ~half the rounds are genuine concurrent duplicate attempts while the relationship
    // set keeps GROWING — which also keeps the index-backed enforcement honest as the graph scales.
    const WINDOW: u64 = 2; // per-round value window => ~50% concurrent collisions
    const ROUNDS: usize = 30;

    // NON-VACUITY: the invariant is only meaningful if the workload actually ATTEMPTS duplicates
    // (both writers drawing the same value concurrently) and actually COMMITS relationships.
    let mut collisions_attempted = 0usize;
    let mut total_committed = 0usize;

    for seed in 1..=12u64 {
        let coord = fresh_coord();
        let t = coord.begin_serializable();
        let (_r, ok) = run_stmt(&coord, t, "CREATE (:Src), (:Dst)");
        assert!(ok, "seed endpoints");
        coord.commit(t).expect("endpoints commit");
        coord
            .create_constraint_general(
                "uniq_tx",
                "TRANSFER",
                &["tx_id"],
                ConstraintKind::RelUnique,
                None,
            )
            .expect("declare rel uniqueness over empty data");

        let mut rng = SimRng::new(seed);
        for round in 0..ROUNDS {
            let t1 = coord.begin_serializable();
            let t2 = coord.begin_serializable();
            let base = (round as u64) * WINDOW;
            let v1 = base + rng.next_u64() % WINDOW;
            let v2 = base + rng.next_u64() % WINDOW;
            if v1 == v2 {
                collisions_attempted += 1;
            }

            let (_r, ok1) = run_rel_stmt(
                &coord,
                t1,
                &format!("MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {{tx_id: {v1}}}]->(d)"),
            );
            let (_r, ok2) = run_rel_stmt(
                &coord,
                t2,
                &format!("MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {{tx_id: {v2}}}]->(d)"),
            );
            if ok1 {
                if coord.commit(t1).is_ok() {
                    total_committed += 1;
                }
            } else {
                let _ = coord.rollback(t1);
            }
            if ok2 {
                if coord.commit(t2).is_ok() {
                    total_committed += 1;
                }
            } else {
                let _ = coord.rollback(t2);
            }

            // INVARIANT after every round: no value in this round's window is held twice.
            let tc = coord.begin_serializable();
            for v in base..base + WINDOW {
                let (rows, ok) = run_rel_stmt(
                    &coord,
                    tc,
                    &format!("MATCH ()-[r:TRANSFER]->() WHERE r.tx_id = {v} RETURN count(r) AS c"),
                );
                assert!(ok, "invariant check read failed");
                let n = match rows.first().map(|r| r.value("c")) {
                    Some(Value::Integer(n)) => n,
                    other => panic!("expected a count, got {other:?}"),
                };
                assert!(
                    n <= 1,
                    "seed {seed}: {n} relationships hold tx_id={v} under a declared uniqueness \
                     constraint — a COMMITTED DUPLICATE, i.e. corrupt data"
                );
            }
            coord.commit(tc).expect("invariant check commits");
        }
    }

    // NON-VACUITY CONTROLS.
    assert!(
        collisions_attempted > 20,
        "NON-VACUITY CONTROL FAILED: only {collisions_attempted} concurrent same-value attempts \
         across 12 seeds x {ROUNDS} rounds — the duplicate invariant was barely exercised"
    );
    assert!(
        total_committed > 50,
        "NON-VACUITY CONTROL FAILED: only {total_committed} relationships committed — an empty \
         graph satisfies 'no duplicates' trivially"
    );
}
