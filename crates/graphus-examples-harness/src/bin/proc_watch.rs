//! `proc_watch` — sample a **live server process** (CPU + RSS) from outside it (`rmp #717`).
//!
//! The examples' house rule is *sample the SERVER, not the driver*: when the goal is server evidence,
//! the figure must come from the server's own pid, never from the client that drove it. Until now each
//! example that needed that re-implemented an ad-hoc `/proc` read in bash — and the ones whose driver
//! is a Node or Python client had no way to do it at all, so their CPU evidence was either absent or
//! (worse) the driver's. This binary is the shared, portable seam: it exposes the harness's tested
//! [`graphus_examples_harness::resource`] metering (Linux `/proc`, macOS `ps`) as a tiny CLI that any
//! driver — bash, Node, Python — can call.
//!
//! Two modes:
//!
//! * `--snapshot` — read the pid's **cumulative** CPU counters and current RSS **once** and print one
//!   JSON line. Because `utime`/`stime` are cumulative counters (not samples), bracketing a phase with
//!   two snapshots yields the EXACT CPU that process burned during it, to the OS's clock-tick
//!   resolution (10 ms on Linux). That is what makes a *per-algorithm* core-utilisation figure real:
//!
//!   ```text
//!   before = proc_watch --pid $SRV --snapshot     # cumulative counters
//!   t0 = now;  <run one GDS algorithm over the wire>;  t1 = now
//!   after  = proc_watch --pid $SRV --snapshot
//!   cores  = (after.cpu - before.cpu) / (t1 - t0)
//!   ```
//!
//!   The snapshot spawns sit OUTSIDE the timed window, and the server is idle across them, so neither
//!   the numerator nor the denominator is inflated by the probe itself.
//!
//! * `--watch` — sample RSS on a fixed cadence until told to stop, then write a JSON report with the
//!   **peak** and — the figure that actually matters for a buffering bug — the **peak delta over the
//!   baseline RSS the process held when the watch began**. A REST response that is materialised
//!   server-side before a byte is flushed shows up here and nowhere else.
//!
//! The watch ends on whichever comes first: the `--stop-file` appears (the caller's `touch`), the
//! monitored pid exits, or `--max-secs` elapses. There is deliberately no signal handler: a stop-file
//! is portable, race-free (the caller creates it, then waits for this process to exit), and needs no
//! `unsafe`.
//!
//! **Never zero-fills.** A pid it cannot read produces an error and a non-zero exit, never a report of
//! zeros — a fabricated `0` here would flow straight into an evidence report and read as "the server
//! burned no CPU" (`examples/README.md`, evidence-honesty rule 1).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use graphus_examples_harness::resource::{
    RssSample, Target, cumulative_cpu_times, current_rss_bytes,
};

const USAGE: &str = "\
usage:
  proc_watch --pid <PID> --snapshot
      Print one JSON line with the pid's CUMULATIVE cpu counters and current RSS:
        {\"pid\":N,\"rss_bytes\":N,\"user_secs\":F,\"system_secs\":F}
      Bracket a phase with two snapshots to get the EXACT cpu it consumed.

  proc_watch --pid <PID> --watch --out <FILE> [--interval-ms 20] [--stop-file <PATH>] [--max-secs 600]
      Sample RSS every --interval-ms until --stop-file appears, the pid exits, or --max-secs elapses;
      then write a JSON report (cpu delta, baseline/peak/final RSS, peak delta, the RSS series).

Exits non-zero (and writes NOTHING) if the pid's counters cannot be read: an unmeasured vector must be
ABSENT from the evidence, never a zero placeholder.";

/// Parsed command line.
struct Args {
    pid: u32,
    snapshot: bool,
    out: Option<PathBuf>,
    interval_ms: u64,
    stop_file: Option<PathBuf>,
    max_secs: f64,
}

fn parse_args() -> Result<Args, String> {
    let mut pid: Option<u32> = None;
    let mut snapshot = false;
    let mut watch = false;
    let mut out: Option<PathBuf> = None;
    let mut interval_ms: u64 = 20;
    let mut stop_file: Option<PathBuf> = None;
    let mut max_secs: f64 = 600.0;

    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        let flag = argv[i].as_str();
        let mut value = || -> Result<String, String> {
            i += 1;
            argv.get(i)
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        match flag {
            "--pid" => pid = Some(value()?.parse().map_err(|e| format!("--pid: {e}"))?),
            "--snapshot" => snapshot = true,
            "--watch" => watch = true,
            "--out" => out = Some(PathBuf::from(value()?)),
            "--interval-ms" => {
                interval_ms = value()?
                    .parse()
                    .map_err(|e| format!("--interval-ms: {e}"))?;
            }
            "--stop-file" => stop_file = Some(PathBuf::from(value()?)),
            "--max-secs" => {
                max_secs = value()?.parse().map_err(|e| format!("--max-secs: {e}"))?;
            }
            "-h" | "--help" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown argument '{other}'\n\n{USAGE}")),
        }
        i += 1;
    }

    let pid = pid.ok_or_else(|| format!("--pid is required\n\n{USAGE}"))?;
    if snapshot == watch {
        return Err(format!(
            "exactly one of --snapshot / --watch is required\n\n{USAGE}"
        ));
    }
    if watch && out.is_none() {
        return Err(format!("--watch requires --out <FILE>\n\n{USAGE}"));
    }
    if interval_ms == 0 {
        return Err("--interval-ms must be > 0".to_owned());
    }

    Ok(Args {
        pid,
        snapshot,
        out,
        interval_ms,
        stop_file,
        max_secs,
    })
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };

    let result = if args.snapshot {
        snapshot(args.pid)
    } else {
        watch(&args)
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("proc_watch: {msg}");
            ExitCode::FAILURE
        }
    }
}

/// RSS of `target`, treating a **zero** reading as "the process is gone", not as a measurement.
///
/// A process that has exited but not yet been reaped is a **zombie**, and a zombie still has a
/// `/proc/<pid>/` directory: `statm` reads back all zeros and `ps -o rss=` reports `0`. That is
/// exactly the shape every example produces — `run.sh` backgrounds the server and does not reap it
/// until `wait` — so without this the watcher would happily keep "sampling" a dead server: RSS 0 for
/// the rest of the window, `final_rss_bytes: 0`, the wall clock running on to `--max-secs`, and the
/// CPU delta divided by that inflated window, silently deflating `mean_core_utilisation`. A live
/// process always has resident pages, so `0` cannot be a real RSS — it is the kernel telling us the
/// process is no longer there.
fn live_rss(target: Target) -> Option<u64> {
    current_rss_bytes(target).filter(|&rss| rss > 0)
}

/// One cumulative CPU + current RSS reading for `pid`, as a single JSON line on stdout.
fn snapshot(pid: u32) -> Result<(), String> {
    let target = Target::Pid(pid);
    let cpu = cumulative_cpu_times(target).ok_or_else(|| {
        format!("cannot read cpu counters for pid {pid} (exited? not permitted?)")
    })?;
    let rss = live_rss(target)
        .ok_or_else(|| format!("cannot read RSS for pid {pid} (exited? not permitted?)"))?;
    println!(
        "{{\"pid\":{pid},\"rss_bytes\":{rss},\"user_secs\":{:.6},\"system_secs\":{:.6}}}",
        cpu.user_secs, cpu.system_secs
    );
    Ok(())
}

/// Samples `pid` until the stop condition, then writes the JSON report to `--out`.
fn watch(args: &Args) -> Result<(), String> {
    let pid = args.pid;
    let target = Target::Pid(pid);

    // Baseline: the CPU already burned and the RSS already held when the window opens. Every figure
    // this binary reports is a DELTA over this instant, which is what makes "the RSS this phase added"
    // a real measurement rather than "the RSS the process happens to hold".
    let cpu0 = cumulative_cpu_times(target).ok_or_else(|| {
        format!("cannot read cpu counters for pid {pid} (exited? not permitted?)")
    })?;
    let baseline_rss = live_rss(target)
        .ok_or_else(|| format!("cannot read RSS for pid {pid} (exited? not permitted?)"))?;

    let started = Instant::now();
    let interval = Duration::from_millis(args.interval_ms);
    let mut samples: Vec<RssSample> = Vec::new();
    let mut peak = baseline_rss;
    let mut last_rss = baseline_rss;
    samples.push(RssSample {
        elapsed_secs: 0.0,
        rss_bytes: baseline_rss,
    });

    // The CPU counters are read on EVERY iteration and the last successful reading is kept, because a
    // process that exits mid-watch can no longer be read at all — and reading them only after the loop
    // would then silently fall back to the baseline and report a CPU delta of ZERO for a process that
    // in fact burned a full core. (Caught by this binary's own self-test: a 1-second CPU burner
    // reported `mean_core_utilisation: 0.0`. That is exactly the fabricated zero the evidence-honesty
    // rules exist to forbid, and it would have been believed.)
    let mut cpu_last = cpu0;
    let mut pid_exited = false;
    let mut cpu_wall_secs = 0.0_f64;

    let stop_requested = |p: &Option<PathBuf>| p.as_deref().is_some_and(Path::exists);

    loop {
        if stop_requested(&args.stop_file) {
            break;
        }
        if started.elapsed().as_secs_f64() >= args.max_secs {
            break;
        }
        thread::sleep(interval);
        // The pid exiting mid-watch is a normal end (the caller shut the server down), not an error:
        // we keep everything sampled up to that point, and say so in the report.
        let (Some(rss), Some(cpu)) = (live_rss(target), cumulative_cpu_times(target)) else {
            pid_exited = true;
            break;
        };
        peak = peak.max(rss);
        last_rss = rss;
        cpu_last = cpu;
        cpu_wall_secs = started.elapsed().as_secs_f64();
        samples.push(RssSample {
            elapsed_secs: cpu_wall_secs,
            rss_bytes: rss,
        });
    }

    // The wall window the CPU delta is divided by must be the window the CPU was actually OBSERVED
    // over — i.e. up to the last successful counter read — not the loop's total runtime. They differ
    // precisely when the pid exited early, and using the longer one would understate the utilisation.
    let wall_secs = if pid_exited {
        cpu_wall_secs
    } else {
        started.elapsed().as_secs_f64()
    };
    let user = (cpu_last.user_secs - cpu0.user_secs).max(0.0);
    let system = (cpu_last.system_secs - cpu0.system_secs).max(0.0);
    let total = user + system;

    let out = args
        .out
        .as_ref()
        .expect("--watch requires --out (validated)");
    let series: Vec<String> = samples
        .iter()
        .map(|s| {
            format!(
                "{{\"elapsed_secs\":{:.4},\"rss_bytes\":{}}}",
                s.elapsed_secs, s.rss_bytes
            )
        })
        .collect();
    let mean_cores = if wall_secs > 0.0 {
        format!("{:.4}", total / wall_secs)
    } else {
        // No window to divide by => not measurable. `null`, never a 0.0 that reads like a result.
        "null".to_owned()
    };
    let json = format!(
        "{{\n\
         \x20 \"pid\": {pid},\n\
         \x20 \"interval_ms\": {},\n\
         \x20 \"wall_secs\": {:.4},\n\
         \x20 \"sample_count\": {},\n\
         \x20 \"monitored_pid_exited\": {},\n\
         \x20 \"cpu\": {{\"user_secs\": {:.4}, \"system_secs\": {:.4}, \"total_secs\": {:.4}, \"mean_core_utilisation\": {}}},\n\
         \x20 \"memory\": {{\"baseline_rss_bytes\": {}, \"peak_rss_bytes\": {}, \"final_rss_bytes\": {}, \"peak_delta_bytes\": {}}},\n\
         \x20 \"samples\": [{}]\n\
         }}\n",
        args.interval_ms,
        wall_secs,
        samples.len(),
        pid_exited,
        user,
        system,
        total,
        mean_cores,
        baseline_rss,
        peak,
        last_rss,
        peak.saturating_sub(baseline_rss),
        series.join(","),
    );
    if let Some(parent) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    fs::write(out, json).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
    Ok(())
}
