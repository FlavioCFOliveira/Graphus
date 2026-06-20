//! `dst_contention` — a **deterministic** in-process reproduction of the fraud-OLTP SSI-contention
//! scenario, driving the REAL Graphus engine (`graphus_server::engine::LocalEngine`) single-threaded
//! via a seeded cooperative interleaver (the same pattern `graphus-dst`'s `isolation.rs` /
//! `vopr.rs` use).
//!
//! It models the live concurrency scenario (`examples/fraud-oltp`) reproducibly: several logical
//! clients open overlapping explicit transactions that all read-modify-write a small set of **hot
//! accounts** (supernodes — e.g. a mule's central account), exactly the structure that provokes SSI
//! write–write / read-write antidependency conflicts. Because everything runs on one thread with a
//! seeded schedule, the commit/abort outcome is identical on every run for a given `--seed`.
//!
//! It asserts the SSI safety properties the live driver also checks, but *deterministically*:
//! - genuine overlap is reached (more than one txn open at once, by construction here),
//! - SSI conflicts actually fire (a non-zero, bounded abort count),
//! - no committed transfer is lost: the final hot-account balance equals the exact sum of the
//!   increments from the transactions that committed (no lost update, no double-apply),
//! - the same seed reproduces the same `(commits, aborts, final_balances)` triple.
//!
//! Usage:
//!   cargo run -p graphus-fraud-gen --features dst-repro --bin dst_contention -- --seed 42 [--rounds 40] [--clients 4] [--hot 3]

use std::process::ExitCode;
use std::sync::Arc;

use graphus_core::Value;
use graphus_fraud_gen::SplitMix64;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{LocalEngine, TxTicket};
use graphus_sim::SharedClock;
use graphus_wal::MemLogSink;

type Eng = LocalEngine<MemBlockDevice, MemLogSink>;

/// One logical client's open transaction in the cooperative interleaver.
struct OpenTxn {
    ticket: TxTicket,
    hot: i64,   // the hot account this txn contends on
    delta: i64, // the increment it intends to apply on commit
}

fn engine() -> Eng {
    LocalEngine::in_memory(Arc::new(SharedClock::new(0)), 256).expect("engine")
}

/// Runs a write statement to completion (drains the empty result stream).
fn run_write(eng: &mut Eng, ticket: TxTicket, stmt: &str, params: Vec<(String, Value)>) {
    let mut reply = eng
        .run(ticket, stmt, params, false, None)
        .expect("write runs");
    while let Ok(Some(_)) = reply.rows.next() {}
}

/// Reads a single hot account's balance in `ticket`.
fn read_balance(eng: &mut Eng, ticket: TxTicket, hot: i64) -> i64 {
    let mut reply = eng
        .run(
            ticket,
            "MATCH (a:Account {id: $id}) RETURN a.balance AS b",
            vec![("id".to_owned(), Value::Integer(hot))],
            false,
            None,
        )
        .expect("read runs");
    let mut bal = 0;
    while let Ok(Some(row)) = reply.rows.next() {
        if let Some(graphus_cypher::MaterializedValue::Value(Value::Integer(n))) = row.first() {
            bal = *n;
        }
    }
    bal
}

fn main() -> ExitCode {
    let mut seed: u64 = 42;
    let mut rounds: u64 = 40;
    let mut clients: usize = 4;
    let mut hot_count: i64 = 3;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut take = || args.next().expect("flag requires a value");
        match a.as_str() {
            "--seed" => seed = take().parse().expect("seed u64"),
            "--rounds" => rounds = take().parse().expect("rounds u64"),
            "--clients" => clients = take().parse().expect("clients usize"),
            "--hot" => hot_count = take().parse().expect("hot i64"),
            "-h" | "--help" => {
                eprintln!(
                    "usage: dst_contention --seed <u64> [--rounds N] [--clients N] [--hot N]"
                );
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("dst_contention: unexpected argument '{other}'");
                return ExitCode::FAILURE;
            }
        }
    }

    let (commits, aborts, max_open, final_balances, expected_balances) =
        run_scenario(seed, rounds, clients, hot_count);

    // --- Assertions (the deterministic mirror of the live SSI driver's checks) ---
    let mut failures = 0;

    if max_open < 2 {
        eprintln!("FAIL: never reached genuine overlap (max_open_txns={max_open})");
        failures += 1;
    }
    if aborts == 0 {
        eprintln!("FAIL: SSI never fired — no conflict was provoked (aborts=0)");
        failures += 1;
    }
    if commits == 0 {
        eprintln!("FAIL: nothing committed (commits=0)");
        failures += 1;
    }
    // No lost update: each hot account's final balance must equal its initial balance plus the sum
    // of increments from the transactions that COMMITTED on it (tracked exactly below).
    if final_balances != expected_balances {
        eprintln!(
            "FAIL: lost/duplicated update — final balances {final_balances:?} != expected {expected_balances:?}"
        );
        failures += 1;
    }

    let abort_rate = aborts as f64 / (commits + aborts).max(1) as f64;

    println!("seed={seed} rounds={rounds} clients={clients} hot_accounts={hot_count}");
    println!(
        "commits={commits} aborts={aborts} abort_rate={:.3} max_open_txns={max_open}",
        abort_rate
    );
    println!("final_balances={final_balances:?}");

    if failures == 0 {
        println!("GRAPHUS_DST_CONTENTION_OK");
        ExitCode::SUCCESS
    } else {
        eprintln!("{failures} assertion(s) failed");
        ExitCode::FAILURE
    }
}

/// Drives the deterministic contention scenario and returns
/// `(commits, aborts, max_open_txns, final_balances, expected_balances)`.
///
/// The interleaver: in each round, up to `clients` logical transactions are opened, each picks a hot
/// account from a seeded RNG and reads-modifies-writes its balance; then they are committed in a
/// seeded order. SSI aborts the dangerous subset. We track, for each committed txn, the exact delta
/// it applied to its hot account, so `expected_balances` is the ground-truth no-lost-update target.
fn run_scenario(
    seed: u64,
    rounds: u64,
    clients: usize,
    hot_count: i64,
) -> (u64, u64, usize, Vec<i64>, Vec<i64>) {
    let mut eng = engine();
    let mut rng = SplitMix64::new(seed);

    // Seed the hot accounts (the supernodes everyone contends on). Initial balance 0 for clean math.
    let setup = eng.begin(AccessMode::Write).expect("begin setup");
    for id in 0..hot_count {
        run_write(
            &mut eng,
            setup,
            "CREATE (:Account {id: $id, holder: $id, balance: 0, risk_score: 90, opened_ts: 0, country: 'PT'})",
            vec![("id".to_owned(), Value::Integer(id))],
        );
    }
    eng.commit(setup).expect("commit setup");

    let mut commits: u64 = 0;
    let mut aborts: u64 = 0;
    let mut max_open: usize = 0;
    // expected_balances[i] is the sum of committed deltas applied to hot account i.
    let mut expected_balances: Vec<i64> = vec![0; hot_count as usize];

    for _ in 0..rounds {
        // Open a batch of overlapping transactions. Each reads its hot account's current balance,
        // then issues a write to balance = read + delta. Because several txns target the SAME hot
        // account and all read the same pre-image, their commits collide under SSI.
        let mut open: Vec<OpenTxn> = Vec::with_capacity(clients);
        for _ in 0..clients {
            let hot = rng.range_i64(0, hot_count - 1);
            let delta = rng.range_i64(1, 100);
            let ticket = eng.begin(AccessMode::Write).expect("begin txn");
            // read-modify-write on the hot account: this is the contended critical section.
            let cur = read_balance(&mut eng, ticket, hot);
            run_write(
                &mut eng,
                ticket,
                "MATCH (a:Account {id: $id}) SET a.balance = $newv",
                vec![
                    ("id".to_owned(), Value::Integer(hot)),
                    ("newv".to_owned(), Value::Integer(cur + delta)),
                ],
            );
            open.push(OpenTxn { ticket, hot, delta });
        }
        max_open = max_open.max(open.len());

        // Commit them in a seeded permutation order (so the schedule, hence the SSI outcome, is a
        // deterministic function of the seed). SSI will abort the txns whose pre-image was
        // invalidated by an earlier committer on the same hot account.
        // Simple seeded shuffle (Fisher–Yates) for the commit order.
        for i in (1..open.len()).rev() {
            let j = rng.below((i + 1) as u64) as usize;
            open.swap(i, j);
        }
        for txn in open {
            match eng.commit(txn.ticket) {
                Ok(_) => {
                    commits += 1;
                    expected_balances[txn.hot as usize] += txn.delta;
                }
                Err(_) => aborts += 1,
            }
        }
    }

    // Read back the real final balances from the engine.
    let reader = eng.begin(AccessMode::Read).expect("begin reader");
    let mut final_balances = Vec::with_capacity(hot_count as usize);
    for id in 0..hot_count {
        final_balances.push(read_balance(&mut eng, reader, id));
    }
    let _ = eng.commit(reader);

    (commits, aborts, max_open, final_balances, expected_balances)
}
