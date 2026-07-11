//! `durability_demo` — drives the deterministic OLTP durability + crash-recovery scenario over a seed
//! range and emits the standardized evidence report (rmp #271/#272/#273).
//!
//! It REUSES the `graphus-dst` VOPR safety oracle end to end: each seed runs a concurrent OLTP workload
//! (overlapping explicit transactions, write-heavy create/relate/property/delete mix) under disk/clock
//! faults and a mid-workload crash, rebuilds the engine via ARIES recovery, then asserts the four
//! durability properties (serializability / durability / atomicity / reference-model equivalence) on
//! the *recovered* engine — comparing it cell-by-cell against the committed-only shadow LPG.
//!
//! Output:
//!   * a human-readable summary of the sweep (zero violations expected) + a focused seed's acked vs
//!     in-flight crash partition (the empirical committed-or-nothing proof);
//!   * (with `--evidence-dir`) the standardized, schema-versioned `report.json` + `report.md`.
//!
//! Usage:
//!
//! ```text
//! durability_demo --seed <START> --seeds <COUNT> [--focus <SEED>] [--evidence-dir <DIR>]
//! ```
//!
//! Exit status is non-zero iff any seed's durability oracle reported a violation or a non-determinism.
#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::time::{Duration, Instant};

use graphus_durability_demo::{
    DurabilityRun, SweepReport, certified_properties, evidence, run_seed, run_sweep,
};

struct Args {
    start: u64,
    count: u64,
    focus: u64,
    evidence_dir: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut start = 1u64;
    let mut count = 100u64;
    let mut focus: Option<u64> = None;
    let mut evidence_dir = None;

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
                    .map_err(|_| "--seed needs an integer")?
            }
            "--seeds" => {
                count = val("--seeds")?
                    .parse()
                    .map_err(|_| "--seeds needs an integer")?
            }
            "--focus" => {
                focus = Some(
                    val("--focus")?
                        .parse()
                        .map_err(|_| "--focus needs an integer")?,
                )
            }
            "--evidence-dir" => evidence_dir = Some(val("--evidence-dir")?),
            "-h" | "--help" => return Err(usage()),
            other => return Err(format!("unknown flag {other}\n\n{}", usage())),
        }
    }
    let count = count.max(1);
    Ok(Args {
        start,
        count,
        // Focus on the first seed of the sweep by default.
        focus: focus.unwrap_or(start),
        evidence_dir,
    })
}

fn usage() -> String {
    "durability_demo — deterministic OLTP durability + crash-recovery scenario (DST-driven)\n\n\
     USAGE:\n    \
     durability_demo [--seed START] [--seeds COUNT] [--focus SEED] [--evidence-dir DIR]\n\n\
     OPTIONS:\n    \
     --seed START        first seed (default 1)\n    \
     --seeds COUNT       number of consecutive seeds (default 100)\n    \
     --focus SEED        seed whose acked/in-flight crash partition is detailed (default: START)\n    \
     --evidence-dir DIR  write the standardized report.json + report.md here\n    \
     -h, --help          print this help\n"
        .to_owned()
}

fn print_focus(run: &DurabilityRun) {
    println!(
        "\n-- focused seed {} — acked vs in-flight at each crash --",
        run.seed
    );
    println!(
        "   crash restarts={}  faults injected={}  recovered txns={}  trace_hash={:016x}",
        run.crash_restarts, run.faults_injected, run.recovered_txns, run.trace_hash
    );
    for (i, c) in run.crashes.iter().enumerate() {
        println!(
            "   crash #{i} @ step {:>3}: acked(durable)={:>3}  in-flight(discarded)={:>2}  recovered_state_hash={:016x}",
            c.fire_step, c.acked_commits, c.inflight_txns, c.recovered_state_hash
        );
    }
    println!(
        "   committed-or-nothing: recovered :Person rows={} == distinct committed ids={} ({})",
        run.recovered_nodes,
        run.committed_nodes,
        if run.recovered_nodes == run.committed_nodes {
            "HOLDS"
        } else {
            "VIOLATED"
        }
    );
    println!(
        "   relationships: recovered :KNOWS edges={} == committed edges={} ({})",
        run.recovered_edges,
        run.committed_edges,
        if run.recovered_edges == run.committed_edges {
            "HOLDS"
        } else {
            "VIOLATED"
        }
    );
    if !run.violations.is_empty() {
        println!("   VIOLATIONS:");
        for (prop, detail) in &run.violations {
            println!("     - {prop}: {detail}");
        }
    }
}

/// Writes the standardized evidence report through the crate's honest evidence builder.
///
/// The report's `total_millis` is the MEASURED sweep wall-time (it used to be the report-builder's own
/// elapsed time — 3.8 microseconds for a 400 ms sweep), the dataset's relationship count is the REAL
/// recovered `:KNOWS` count (it used to be hard-coded `0`), and CPU/RSS are this process's measured
/// figures (the hermetic engine IS this process). See `graphus_durability_demo::evidence`.
fn write_evidence(
    dir: &str,
    sweep: &SweepReport,
    focus: &DurabilityRun,
    sweep_duration: Duration,
    process_wall: Duration,
) {
    let report = evidence::build_report(
        sweep,
        focus,
        sweep_duration,
        process_wall,
        Some(
            "the FULL fault catalogue (crash steal/no-force, torn WAL tail, torn data page + \
             doublewrite repair, write reordering, write I/O error) is driven by the sibling \
             `durability_faults` binary, which this example's run.sh asserts SAFE — this sweep is the \
             crash-and-redo core, not the whole fault surface."
                .to_string(),
        ),
    );
    match report.write_to(dir) {
        Ok((json, md)) => println!(
            "\nevidence written:\n  {}\n  {}",
            json.display(),
            md.display()
        ),
        Err(e) => eprintln!("warning: could not write evidence to {dir}: {e} (non-fatal)"),
    }
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            if msg.starts_with("durability_demo —") {
                println!("{msg}");
                return ExitCode::SUCCESS;
            }
            eprintln!("error: {msg}");
            return ExitCode::FAILURE;
        }
    };

    println!("graphus durability + crash-recovery — deterministic DST scenario");
    println!("================================================================");
    println!(
        "seeds {}..{}  |  workload: concurrent OLTP (overlapping txns, write-heavy)  |  per seed: \
         disk/clock faults + mid-workload crash + ARIES recovery",
        args.start,
        args.start + args.count
    );
    println!(
        "oracle (asserted on the RECOVERED engine): {:?}",
        certified_properties()
    );

    let process_start = Instant::now();
    let t0 = Instant::now();
    let sweep = run_sweep(args.start, args.count);
    let sweep_duration = t0.elapsed();

    println!(
        "\nsweep: {} seed(s) | crashes={} faults={} | acked-durable={} in-flight-discarded={} | \
         non-vacuous={}/{}",
        sweep.count,
        sweep.total_crashes(),
        sweep.total_faults(),
        sweep.total_acked_durable(),
        sweep.total_inflight_discarded(),
        sweep.non_vacuous_runs(),
        sweep.count,
    );

    let focus = run_seed(args.focus);
    print_focus(&focus);

    if let Some(dir) = &args.evidence_dir {
        write_evidence(dir, &sweep, &focus, sweep_duration, process_start.elapsed());
    }

    println!();
    if sweep.all_safe() {
        println!(
            "RESULT: DURABLE — {} seed(s), zero durability violations, fully deterministic. Every \
             acknowledged commit survived its crash; no in-flight effect did.",
            sweep.count
        );
        ExitCode::SUCCESS
    } else {
        println!(
            "RESULT: FAIL — unsafe seed(s): {:?}; non-deterministic: {}. Reproduce a seed with \
             `graphus-dst vopr safety --seed <N> --seeds 1`.",
            sweep.unsafe_seeds(),
            sweep.nondeterministic
        );
        ExitCode::FAILURE
    }
}
