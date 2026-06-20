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
use std::time::Instant;

use graphus_durability_demo::{
    DurabilityRun, SweepReport, certified_properties, run_seed, run_sweep,
};
use graphus_examples_harness::{DatasetScale, EvidenceCollector, RunMetadata};

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
    if !run.violations.is_empty() {
        println!("   VIOLATIONS:");
        for (prop, detail) in &run.violations {
            println!("     - {prop}: {detail}");
        }
    }
}

fn build_collector(sweep: &SweepReport, focus: &DurabilityRun) -> EvidenceCollector {
    let metadata = RunMetadata::new(
        "durability-crash-recovery",
        "Deterministic OLTP durability + crash-recovery under load, driven by the DST simulator: a \
         concurrent overlapping-transaction workload under disk/clock faults and a seeded mid-workload \
         crash, rebuilt via ARIES recovery, with the four ACID-durability properties \
         (serializability / durability / atomicity / reference-model equivalence) asserted on the \
         recovered engine against the committed-only shadow LPG.",
    )
    .with_dataset(DatasetScale::new(
        focus.committed_nodes.max(0) as u64,
        // The safety workload relates nodes as it creates them; the recovered-edge count is folded into
        // the reference-model check rather than reported separately, so we record the node scale only.
        0,
    ))
    .workload_param("scenario", "oltp-durability")
    .workload_param("driver", "graphus-dst VOPR safety oracle (run_safety)")
    .workload_param("seeds", format!("{}..{}", sweep.start, sweep.start + sweep.count))
    .workload_param("clients", "6 (overlapping explicit transactions)")
    .workload_param("crashes_per_seed", "<=2 (mid-workload crash + ARIES restart)")
    .workload_param("focus_seed", focus.seed.to_string())
    // --- Deterministic recovery metrics (rmp #274). These are byte-stable for a fixed seed range
    // and are the "recovery work" the regression gate holds: the redo set ARIES replayed (= acked
    // commits, the in-process analogue of WAL redo records), the undo set it discarded, and how many
    // crash + ARIES restarts fired. The on-disk WAL byte footprint + wall-clock recovery time are
    // machine-variant and are collected by the sibling REAL-server SIGKILL run (rmp #275), not here.
    .workload_param(
        "recovery_records_replayed",
        sweep.total_acked_durable().to_string(),
    )
    .workload_param(
        "recovery_inflight_undone",
        sweep.total_inflight_discarded().to_string(),
    )
    .workload_param("recovery_crashes", sweep.total_crashes().to_string())
    .workload_param(
        "focus_recovery_records_replayed",
        focus.acked_at_last_crash().to_string(),
    )
    .workload_param(
        "focus_recovered_txns",
        focus.recovered_txns.to_string(),
    );

    EvidenceCollector::new(metadata)
}

fn finalize_evidence(dir: &str, mut c: EvidenceCollector, sweep: &SweepReport, sweep_millis: f64) {
    // The sweep is the one timed phase (a pure-CPU, hermetic, in-process simulation — no server, no
    // disk store to size, so storage/memory of a *server* are not applicable; the throughput vector
    // carries the seed rate honestly).
    c.phase(
        "durability sweep (workload + crash + ARIES recovery + 4-property oracle)",
        std::time::Duration::from_secs_f64(sweep_millis / 1_000.0),
    );

    // Throughput vector: seeds (each a full crash-recovery scenario) per second — an honest,
    // deterministic rate for this hermetic CPU workload.
    let secs = (sweep_millis / 1_000.0).max(1e-9);
    let tp = c.throughput_mut();
    tp.operations = sweep.count;
    tp.ops_per_sec = sweep.count as f64 / secs;

    c.note(format!(
        "durability oracle: {} seed(s) checked, {} unsafe, {} non-deterministic — properties: {:?}",
        sweep.count,
        sweep.unsafe_seeds().len(),
        sweep.nondeterministic,
        certified_properties(),
    ));
    c.note(format!(
        "crash + ARIES restarts across sweep: {}; faults injected: {}; acked commits proven durable: \
         {}; in-flight transactions discarded by undo: {}; non-vacuous runs (both halves of \
         committed-or-nothing under test): {}/{}",
        sweep.total_crashes(),
        sweep.total_faults(),
        sweep.total_acked_durable(),
        sweep.total_inflight_discarded(),
        sweep.non_vacuous_runs(),
        sweep.count,
    ));
    c.note(format!(
        "recovery work vs WAL/redo size (DETERMINISTIC, rmp #274): ARIES redo replayed {} acked \
         commits and undo discarded {} in-flight transactions across {} crash + ARIES restart(s) in \
         this sweep. In-process there is no on-disk WAL to size, so the redo-record count (= acked \
         commits) is the deterministic analogue of the WAL records replayed during recovery; it is \
         byte-stable for a fixed seed range. The on-disk WAL byte footprint and the wall-clock \
         recovery time scale with this redo set and are measured by the sibling REAL-server SIGKILL \
         run (rmp #275), which records a `recovery` phase timing + the post-crash `storage.wal_bytes` \
         so recovery-time-vs-WAL-size can be read directly.",
        sweep.total_acked_durable(),
        sweep.total_inflight_discarded(),
        sweep.total_crashes(),
    ));
    c.note(
        "deterministic-vs-machine-variant split: the recovery-work counts (recovery_records_replayed \
         / recovery_inflight_undone / recovery_crashes), the durability verdict, the recovered \
         hashes and the dataset size are EXACTLY reproducible (a pure function of the seed range) and \
         are the structural metrics the committed baseline gates; the sweep wall-time / seed-rate \
         throughput here, and the real-server WAL bytes / recovery time / peak RSS in the sibling \
         run, are machine-variant and are NOT gated."
            .to_string(),
    );
    c.note(
        "hermetic: this scenario runs the storage/WAL/txn engine in-process under the DST simulator \
         (no server, no Node, no network) — so the report carries the deterministic seed-rate \
         throughput; server CPU/RAM/on-disk storage are exercised by the sibling real-server SIGKILL \
         run (rmp #274-276) layered over this same scenario."
            .to_string(),
    );

    let report = c.finish();
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

    let t0 = Instant::now();
    let sweep = run_sweep(args.start, args.count);
    let sweep_millis = t0.elapsed().as_secs_f64() * 1_000.0;

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
        // The collector's own wall-clock window starts here; the authoritative scenario duration is the
        // sweep phase timing (`sweep_millis`), recorded as the single phase + the throughput window.
        let mut c = build_collector(&sweep, &focus);
        c.start();
        finalize_evidence(dir, c, &sweep, sweep_millis);
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
