//! `durability_faults` — the **full fault-catalogue** matrix (`rmp` #698).
//!
//! The example's headline sweep crashes the engine and rebuilds it from the durable WAL prefix onto a
//! FRESH device: the easiest ARIES case, where recovery only has to redo. This binary drives
//! `graphus-dst`'s storage harness through **every** [`FaultKind`](graphus_dst::FaultKind) it can
//! physically inject through the full `RecordStore` engine, over a seed range, asserting each one
//! recovers SAFE and deterministically:
//!
//! * `crash(no-force)`   — redo the acked commits onto an empty device;
//! * `crash(steal)`      — **UNDO** uncommitted dirty pages that were stolen home before the crash;
//! * `torn-wal-tail`     — stop cleanly at the last intact record (a half-written record is no commit);
//! * `torn-data-page`    — repair the torn home page from the **doublewrite buffer** *before* redo;
//! * `write-reordering`  — reconstruct every committed page a non-atomic sync failed to persist;
//! * `write-io-error`    — **surface** the hard error / checksum rejection; never serve corrupt data.
//!
//! The faults the harness does NOT physically inject are printed with their reason, so the coverage
//! claim is honest rather than implied.
//!
//! Exit status is non-zero iff any cell was unsafe or non-deterministic; the offending `(fault, seed)`
//! pairs are printed as one-line reproducers.
#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::time::Instant;

use graphus_durability_demo::faults::{deferred, run_matrix};

struct Args {
    start: u64,
    seeds: u64,
}

fn usage() -> String {
    "durability_faults — drive EVERY DST fault kind through the engine and assert SAFE recovery\n\n\
     USAGE:\n    \
     durability_faults [--seed START] [--seeds COUNT]\n\n\
     OPTIONS:\n    \
     --seed START   first seed (default 1)\n    \
     --seeds COUNT  seeds per fault kind (default 25)\n    \
     -h, --help     print this help\n"
        .to_owned()
}

fn parse_args() -> Result<Args, String> {
    let mut start = 1u64;
    let mut seeds = 25u64;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut val = |label: &str| -> Result<String, String> {
            it.next()
                .ok_or_else(|| format!("flag {label} needs a value"))
        };
        match arg.as_str() {
            "--seed" => {
                start = val("--seed")?
                    .parse()
                    .map_err(|_| "--seed needs an integer")?;
            }
            "--seeds" => {
                seeds = val("--seeds")?
                    .parse()
                    .map_err(|_| "--seeds needs an integer")?;
            }
            "-h" | "--help" => return Err(usage()),
            other => return Err(format!("unknown flag {other}\n\n{}", usage())),
        }
    }
    Ok(Args {
        start,
        seeds: seeds.max(1),
    })
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            if msg.starts_with("durability_faults —") {
                println!("{msg}");
                return ExitCode::SUCCESS;
            }
            eprintln!("error: {msg}");
            return ExitCode::FAILURE;
        }
    };

    println!("graphus durability — FULL FAULT CATALOGUE through the real storage engine");
    println!("========================================================================");
    println!(
        "seeds {}..{} per fault | each cell: seeded workload -> fault -> ARIES recovery -> invariants",
        args.start,
        args.start + args.seeds
    );

    let t0 = Instant::now();
    let matrix = run_matrix(args.start, args.seeds);
    let elapsed = t0.elapsed();

    println!();
    for v in &matrix.verdicts {
        println!(
            "fault={:<28} seeds={:<3} safe={:<3} non_vacuous={:<3} acked_commits={:<5} \
             recovery_losers={:<4} torn_tails={:<3} verdict={}",
            v.label,
            v.seeds,
            v.safe,
            v.non_vacuous,
            v.acked_commits,
            v.recovery_losers,
            v.tail_truncated,
            if v.passed() { "SAFE" } else { "UNSAFE" },
        );
        for (seed, why) in &v.unsafe_seeds {
            println!("    UNSAFE seed={seed}: {why}");
        }
        for seed in &v.nondeterministic {
            println!("    NON-DETERMINISTIC seed={seed} (a re-run produced a different report)");
        }
    }

    println!();
    println!("deferred (planned but NOT physically injected — declared, not hidden):");
    for (label, reason) in deferred() {
        println!("  {label}: {reason}");
    }

    println!();
    println!(
        "matrix: {} fault kind(s) x {} seed(s) = {} cells in {:.1} ms",
        matrix.verdicts.len(),
        matrix.seeds,
        matrix.cells(),
        elapsed.as_secs_f64() * 1_000.0,
    );
    if matrix.all_safe() {
        println!(
            "RESULT: ALL FAULTS SAFE — every fault the engine can be subjected to (steal/undo, torn \
             WAL tail, torn data page + doublewrite repair, write reordering, write I/O error, plain \
             crash) recovered with every invariant intact, deterministically."
        );
        ExitCode::SUCCESS
    } else {
        println!(
            "RESULT: FAIL — at least one fault kind broke an invariant. Reproduce a cell with \
             `durability_faults --seed <N> --seeds 1`."
        );
        ExitCode::FAILURE
    }
}
