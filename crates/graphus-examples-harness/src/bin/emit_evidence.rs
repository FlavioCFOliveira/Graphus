//! `emit_evidence` — a minimal driver that exercises the [`graphus_examples_harness`] scaffold and
//! writes an evidence directory (`report.json` + `report.md`).
//!
//! It is the end-to-end proof that the evidence-collection seam works, invoked by the smoke example
//! (`examples/smoke-evidence/run.sh`). The real examples (`rmp #27-#33`) follow the same shape but
//! drive a live `graphus-server` between `start()` and `finish()` and populate the metric sections
//! from the injected meters (`graphus_examples_harness::resource` / `::metrics`).
//!
//! It demonstrates the full report lifecycle: detect host → fill scenario / dataset / workload →
//! populate the CPU / memory / storage / throughput sections → `write_to(dir)` → optionally
//! `compare_to_baseline`.
//!
//! Usage:
//!   `cargo run -p graphus-examples-harness --bin emit_evidence -- <evidence-dir> [baseline.json]`
//!
//! The evidence directory defaults to `./evidence`. If a baseline `report.json` path is given, the
//! produced report is diffed against it and the comparison summary is printed (exiting non-zero on a
//! flagged regression).

use std::process::ExitCode;
use std::time::Duration;

use graphus_examples_harness::{
    CpuSection, DatasetScale, EvidenceCollector, EvidenceReport, MemorySection,
    RegressionThresholds, RunMetadata, StorageSection, ThroughputSection,
};

fn main() -> ExitCode {
    let evidence_dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "evidence".to_string());
    let baseline_path = std::env::args().nth(2);

    // Scenario metadata: a stable id, a dataset, and the run's knobs. Host/env is auto-detected.
    let metadata = RunMetadata::new(
        "smoke-evidence",
        "Scaffold smoke test: drives the harness end to end and emits a full evidence report.",
    )
    .with_dataset(DatasetScale::new(1_000, 4_000))
    .workload_param("clients", "1")
    .workload_param("operations", "1000");

    let mut collector = EvidenceCollector::new(metadata);
    collector.start();

    // Stand-in for "exercise the server": two trivially-timed phases prove phase capture works.
    let t0 = std::time::Instant::now();
    std::thread::sleep(Duration::from_millis(2));
    collector.phase("warmup", t0.elapsed());

    let t1 = std::time::Instant::now();
    std::thread::sleep(Duration::from_millis(3));
    collector.phase("workload", t1.elapsed());

    // The real examples fill these from `ResourceMeter::finish` / `StorageMeter` / the throughput +
    // latency collectors. The smoke driver injects representative figures so the report carries a
    // fully-populated example of every documented vector.
    *collector.cpu_mut() = CpuSection {
        user_secs: 0.012,
        system_secs: 0.004,
        mean_core_utilisation: 0.32,
    };
    *collector.memory_mut() = MemorySection {
        peak_rss_bytes: 18_874_368,
        final_rss_bytes: 12_582_912,
    };
    *collector.storage_mut() = StorageSection {
        store_bytes: 81_920,
        wal_bytes: 16_384,
        store_pages: 10,
        wal_pages: 2,
        bytes_fsynced: 16_384,
        write_amplification: 1.20,
        space_amplification: 1.45,
    };
    *collector.throughput_mut() = ThroughputSection {
        operations: 1_000,
        ops_per_sec: 200_000.0,
        p50_latency_ms: 0.004,
        p99_latency_ms: 0.012,
        p999_latency_ms: 0.031,
        abort_rate: 0.0,
    };

    collector
        .note("Smoke run: metric values are injected representative figures, not a live server.");

    let report = collector.finish();
    let (json, md) = match report.write_to(&evidence_dir) {
        Ok(paths) => paths,
        Err(e) => {
            eprintln!("failed to write evidence to {evidence_dir}: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("wrote {}", json.display());
    println!("wrote {}", md.display());

    // Optional baseline diff: prove the regression helper end to end.
    if let Some(path) = baseline_path {
        match EvidenceReport::load(&path) {
            Ok(baseline) => {
                let cmp = report.compare_to_baseline(&baseline, &RegressionThresholds::default());
                print!("{}", cmp.summary());
                if cmp.regressed {
                    return ExitCode::FAILURE;
                }
            }
            Err(e) => {
                eprintln!("failed to load baseline {path}: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    ExitCode::SUCCESS
}
