//! `emit_evidence` — a minimal driver that exercises the [`graphus_examples_harness`] scaffold and
//! writes an evidence directory (`evidence.json` + `evidence.md`).
//!
//! It is the end-to-end proof that the evidence-collection seam works, invoked by the smoke example
//! (`examples/smoke-evidence/run.sh`). The real examples (`rmp #27-#33`) follow the same shape but
//! drive a live `graphus-server` between `start()` and `finish()` and populate the metric sections
//! as the metering tasks (`rmp #246/#247/#248`) come online.
//!
//! Usage:
//!   `cargo run -p graphus-examples-harness --bin emit_evidence -- <evidence-dir>`
//!
//! The evidence directory defaults to `./evidence` when no argument is given.

use std::process::ExitCode;
use std::time::Duration;

use graphus_examples_harness::{EvidenceCollector, RunMetadata};

fn main() -> ExitCode {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "evidence".to_string());

    // A coarse host hint; `rmp #246` will enrich this from the platform.
    let host = format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH);

    let mut collector = EvidenceCollector::new(RunMetadata::new(
        "smoke-evidence",
        "Scaffold smoke test: drives the harness end to end and emits an evidence directory.",
        host,
    ));

    collector.start();

    // Stand-in for "exercise the server": two trivially-timed phases prove phase capture works.
    let t0 = std::time::Instant::now();
    std::thread::sleep(Duration::from_millis(2));
    collector.phase("warmup", t0.elapsed());

    let t1 = std::time::Instant::now();
    std::thread::sleep(Duration::from_millis(3));
    collector.phase("workload", t1.elapsed());

    collector.note("Smoke run: metric sections intentionally zeroed (see standing TODO).");

    let report = collector.finish();
    match report.write_to(&dir) {
        Ok((json, md)) => {
            println!("wrote {}", json.display());
            println!("wrote {}", md.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("failed to write evidence to {dir}: {e}");
            ExitCode::FAILURE
        }
    }
}
