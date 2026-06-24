//! Staggered-lifetime serializability cross-check of the **production Cypher coordinator** (`rmp`
//! #115, storage audit F9 follow-up).
//!
//! `elle.rs` drives the coordinator but commits transactions in synchronized pairs per round, so no
//! transaction outlives its round. That cannot reach the cross-commit structures the audit flagged:
//! a pivot (or a write-write conflict) whose closing edge forms only after another participant has
//! already committed. This harness interleaves transactions with **overlapping lifetimes** — at each
//! step it begins a new transaction, advances a random in-flight one by one Cypher read/write, or
//! commits a random in-flight one — and feeds every committed transaction's history to the DSG
//! oracle. The acceptance property: **every history the SERIALIZABLE coordinator admits is
//! serializable** (acyclic DSG), exercising the shared `SsiTracker`'s committed-pivot detection and
//! the coordinator's write-conflict handling over the real record store.
//!
//! ## Version observation
//! Each register's `v` stores the **writer transaction id** of the value last committed to it (the
//! seed writes writer `0`). A read records the writer id it observed; post-hoc, the committed writers
//! of each register in commit order define that register's version sequence (seed = version 1). A
//! read of a transaction's own pending write creates no inter-transaction edge and is dropped.

use std::collections::HashMap;

use graphus_core::capability::Rng;
use graphus_core::{TxnId, Value};
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
use graphus_txn::{HistoryChecker, TxnHistory};
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

fn run_stmt(coord: &Coord, txn: TxnId, src: &str) -> (Vec<Row>, bool) {
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    // A SERIALIZABLE commit can abort *another* still-open transaction (the poisoned-victim model:
    // `coordinator::commit` aborts a pivot that is another open txn so a safe member can commit). That
    // victim's next statement then fails as "inactive txn", which is **expected** serializable behaviour,
    // not a harness error — so treat it exactly like a captured serialization failure (`ok == false`),
    // and let the driver roll the txn out of the active set. (Before `rmp` #325 tightened the label-scan
    // SSI footprint, the seeds here happened never to poison a cross-txn victim; the precise footprint
    // now reaches that legitimate structure, which this harness must tolerate.)
    let mut graph = match coord.statement(txn) {
        Ok(graph) => graph,
        Err(_) => return (Vec::new(), false),
    };
    let rows = {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    let ok = graph.take_error().is_none();
    (rows, ok)
}

/// The writer id recorded in register `k` as visible to `txn`'s snapshot, or `None` on error / no
/// visible value.
fn read_writer(coord: &Coord, txn: TxnId, k: u64) -> Option<u64> {
    let (rows, ok) = run_stmt(
        coord,
        txn,
        &format!("MATCH (n:Reg {{k: {k}}}) RETURN n.v AS v"),
    );
    if !ok {
        return None;
    }
    match rows.first().map(|r| r.value("v")) {
        Some(Value::Integer(v)) => Some(v as u64),
        _ => None,
    }
}

/// Stamps register `k` with `txn`'s id as its value; returns whether the write succeeded (no
/// write-write conflict / serialization failure).
fn write_writer(coord: &Coord, txn: TxnId, k: u64) -> bool {
    let (_rows, ok) = run_stmt(
        coord,
        txn,
        &format!("MATCH (n:Reg {{k: {k}}}) SET n.v = {}", txn.0),
    );
    ok
}

fn seed_registers(coord: &mut Coord, n: u64) {
    let t = coord.begin_serializable();
    for k in 0..n {
        let (_r, ok) = run_stmt(coord, t, &format!("CREATE (:Reg {{k: {k}, v: 0}})"));
        assert!(ok, "seed register {k}");
    }
    coord.commit(t).expect("seed commits");
}

#[derive(Clone, Copy)]
enum PlannedOp {
    Read(u64),
    Write(u64),
}

struct InFlight {
    id: TxnId,
    plan: Vec<PlannedOp>,
    cursor: usize,
    reads: Vec<(u64, u64)>, // (key, observed writer)
    writes: Vec<u64>,       // keys written
}

/// A committed transaction's recorded history: `(id, reads, written keys)`.
type CommittedTxn = (TxnId, Vec<(u64, u64)>, Vec<u64>);

fn generate(rng: &mut SimRng, n_txns: usize, n_keys: u64) -> Vec<Vec<PlannedOp>> {
    (0..n_txns)
        .map(|_| {
            let n_ops = 2 + (rng.next_u64() % 3) as usize;
            (0..n_ops)
                .map(|_| {
                    let key = rng.next_u64() % n_keys;
                    if rng.next_u64() % 2 == 0 {
                        PlannedOp::Read(key)
                    } else {
                        PlannedOp::Write(key)
                    }
                })
                .collect()
        })
        .collect()
}

/// Drives one staggered workload through the real coordinator under SERIALIZABLE and returns any DSG
/// cycle the committed histories contain (`None` ⇒ serializable).
fn run_staggered(seed: u64) -> Option<Vec<TxnId>> {
    let mut rng = SimRng::new(seed);
    let n_keys = 3u64;
    let cap = 4usize;
    let plans = generate(&mut rng, 16, n_keys);

    let mut coord = fresh_coord();
    seed_registers(&mut coord, n_keys);

    let mut key_writers: HashMap<u64, Vec<u64>> = (0..n_keys).map(|k| (k, vec![0u64])).collect();
    let mut committed: Vec<CommittedTxn> = Vec::new();
    let mut active: Vec<InFlight> = Vec::new();
    let mut next_plan = 0usize;
    let mut guard = 0u64;

    let commit_one = |coord: &mut Coord,
                      t: InFlight,
                      key_writers: &mut HashMap<u64, Vec<u64>>,
                      committed: &mut Vec<CommittedTxn>| {
        if coord.commit(t.id).is_ok() {
            for &k in &t.writes {
                key_writers.get_mut(&k).expect("seeded key").push(t.id.0);
            }
            committed.push((t.id, t.reads, t.writes));
        }
    };

    while (next_plan < plans.len() || !active.is_empty()) && guard < 1_000_000 {
        guard += 1;
        let can_begin = next_plan < plans.len() && active.len() < cap;
        let action = rng.next_u64() % 3;

        if active.is_empty() || (action == 0 && can_begin) {
            let id = coord.begin_serializable();
            active.push(InFlight {
                id,
                plan: plans[next_plan].clone(),
                cursor: 0,
                reads: Vec::new(),
                writes: Vec::new(),
            });
            next_plan += 1;
            continue;
        }

        let idx = (rng.next_u64() as usize) % active.len();
        let has_more = active[idx].cursor < active[idx].plan.len();

        if action == 1 && has_more {
            let op = active[idx].plan[active[idx].cursor];
            active[idx].cursor += 1;
            let id = active[idx].id;
            match op {
                PlannedOp::Read(key) => match read_writer(&coord, id, key) {
                    Some(writer) => {
                        if writer != id.0 {
                            active[idx].reads.push((key, writer));
                        }
                    }
                    None => {
                        let _ = coord.rollback(id);
                        active.remove(idx);
                    }
                },
                PlannedOp::Write(key) => {
                    if write_writer(&coord, id, key) {
                        if !active[idx].writes.contains(&key) {
                            active[idx].writes.push(key);
                        }
                    } else {
                        let _ = coord.rollback(id);
                        active.remove(idx);
                    }
                }
            }
        } else {
            let t = active.remove(idx);
            commit_one(&mut coord, t, &mut key_writers, &mut committed);
        }
    }

    for t in std::mem::take(&mut active) {
        commit_one(&mut coord, t, &mut key_writers, &mut committed);
    }

    let mut version_of: HashMap<(u64, u64), u64> = HashMap::new();
    for (k, writers) in &key_writers {
        for (i, w) in writers.iter().enumerate() {
            version_of.insert((*k, *w), i as u64 + 1);
        }
    }

    let mut checker = HistoryChecker::new();
    for (id, reads, writes) in &committed {
        let mut h = TxnHistory::new(*id);
        for (k, writer) in reads {
            h.read(*k, *version_of.get(&(*k, *writer)).unwrap_or(&0));
        }
        for k in writes {
            h.write(
                *k,
                *version_of
                    .get(&(*k, id.0))
                    .expect("a committed writer has a version"),
            );
        }
        checker.add(h);
    }
    checker.find_anomaly()
}

#[test]
fn serializable_staggered_coordinator_histories_have_no_anomalies() {
    // Overlapping transaction lifetimes over the real Cypher coordinator + record store — the
    // cross-commit structures the wave-synchronized elle.rs cannot reach. Every committed
    // SERIALIZABLE history must be serializable (storage audit F9 follow-up, #115).
    for seed in 1..=300u64 {
        if let Some(cycle) = run_staggered(seed) {
            panic!(
                "SERIALIZABLE staggered coordinator run for seed {seed} committed a \
                 non-serializable history; DSG cycle over {cycle:?}"
            );
        }
    }
}
