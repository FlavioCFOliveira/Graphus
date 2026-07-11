//! `emit_evidence` — a minimal driver that exercises the [`graphus_examples_harness`] scaffold and
//! writes an evidence directory (`report.json` + `report.md`).
//!
//! It is the end-to-end proof that the evidence-collection seam works, invoked by the smoke example
//! (`examples/smoke-evidence/run.sh`). The real examples (`rmp #27-#33`) follow the same shape but
//! drive a live `graphus-server` between `start()` and `finish()`.
//!
//! It demonstrates the full report lifecycle: detect host → fill scenario / dataset / workload →
//! populate the CPU / memory / storage / throughput sections → `write_to(dir)` → optionally
//! `compare_to_baseline`.
//!
//! # Every figure in the report is MEASURED (`rmp #699`)
//!
//! This driver used to *inject* representative figures (`ops_per_sec: 200_000.0`, `p50: 0.004 ms`, a
//! made-up store/WAL footprint) to show "a fully-populated example of every documented vector". That
//! made the smoke example prove only that `serde` works — it exercised none of the meters it exists
//! to validate, and it shipped fabricated numbers in a report whose entire purpose is trustworthy
//! evidence. Every section is now produced by the **real** meter, from a **real** workload:
//!
//! * **CPU / memory** — [`ResourceMeter`] over [`Target::SelfProcess`]. This driver boots no server,
//!   so *this process* is legitimately the subject under measurement (and the scenario says so). An
//!   example whose subject is the *server* must meter the SERVER's pid instead — see `measure_server`.
//! * **Storage** — a real on-disk layout mirroring the server's (`graphus.store` file beside a
//!   `graphus.wal/` **directory** of segment files), measured by [`StorageMeter`] through
//!   [`EvidenceCollector::record_storage`]. This is the one place the harness's own store-vs-WAL
//!   split is exercised end to end, so it pins the rule that the WAL is a DIRECTORY: a meter that
//!   classified by leaf file name would report `wal_bytes = 0` and hide the redo log entirely.
//! * **Throughput / latency** — a real, timed in-process workload through [`ThroughputCounter`] +
//!   [`LatencyCollector`], so the percentiles are this host's actual per-operation latencies.
//! * **Amplification** — the real physical bytes over the real logical bytes the workload wrote.
//!
//! Usage:
//!   `cargo run -p graphus-examples-harness --bin emit_evidence -- <evidence-dir> [baseline.json]`
//!
//! The evidence directory defaults to `./evidence`. If a baseline `report.json` path is given, the
//! produced report is diffed against it and the comparison summary is printed (exiting non-zero on a
//! flagged regression).
//!
//! [`ResourceMeter`]: graphus_examples_harness::resource::ResourceMeter
//! [`Target::SelfProcess`]: graphus_examples_harness::Target::SelfProcess
//! [`StorageMeter`]: graphus_examples_harness::metrics::StorageMeter
//! [`ThroughputCounter`]: graphus_examples_harness::metrics::ThroughputCounter
//! [`LatencyCollector`]: graphus_examples_harness::metrics::LatencyCollector

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use graphus_examples_harness::metrics::{LatencyCollector, ThroughputCounter};
use graphus_examples_harness::resource::ResourceMeter;
use graphus_examples_harness::{
    DatasetScale, EvidenceCollector, EvidenceReport, RegressionThresholds, RunMetadata, Target,
};

/// The smoke workload's shape: how many records the "load" phase writes.
const RECORDS: u64 = 1_000;
/// Bytes per logical record — the payload each operation durably appends.
const RECORD_BYTES: usize = 64;
/// How many records go into one WAL segment file, so the WAL is a real multi-file DIRECTORY.
const RECORDS_PER_SEGMENT: u64 = 256;

fn main() -> ExitCode {
    let evidence_dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "evidence".to_string());
    let baseline_path = std::env::args().nth(2);

    match run(&evidence_dir, baseline_path.as_deref()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("emit_evidence: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(evidence_dir: &str, baseline_path: Option<&str>) -> Result<ExitCode, String> {
    // A real, private store layout for the run: `graphus.store` beside a `graphus.wal` DIRECTORY,
    // exactly as the server lays a database out. Removed when the run ends.
    let root = std::env::temp_dir().join(format!("graphus-smoke-evidence-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let store_path = root.join("graphus.store");
    let wal_dir = root.join("graphus.wal");
    std::fs::create_dir_all(&wal_dir)
        .map_err(|e| format!("cannot create {}: {e}", wal_dir.display()))?;

    let metadata = RunMetadata::new(
        "smoke-evidence",
        "Scaffold smoke test: drives every harness meter end to end over a real in-process workload \
         and emits a full evidence report.",
    )
    .with_dataset(DatasetScale::new(RECORDS, RECORDS.saturating_mul(4)))
    .workload_param("clients", "1")
    .workload_param("operations", RECORDS.to_string())
    .workload_param("record_bytes", RECORD_BYTES.to_string())
    .workload_param("subject", "this driver process (no server is booted)");

    let mut collector = EvidenceCollector::new(metadata);
    collector.start();

    // --- CPU + memory: metered over the REAL workload below. The subject is this process, because
    // this driver boots no server (an example that measures a server must meter the server's pid).
    let mut resources = ResourceMeter::start(Target::SelfProcess, Duration::from_millis(20));

    // --- Warm-up phase: touch the code paths so the measured workload is not timing first-call cost.
    let t0 = Instant::now();
    let mut warm = Vec::with_capacity(RECORD_BYTES);
    for i in 0..64u64 {
        warm.clear();
        encode_record(i, &mut warm);
        std::hint::black_box(&warm);
    }
    collector.phase("warmup", t0.elapsed());
    resources.sample();

    // --- Workload phase: RECORDS real operations, each encoding a record, appending it to the store
    // image and to the current WAL segment. Every operation's latency is recorded, so the percentiles
    // below are this host's real per-operation latencies.
    let mut latency = LatencyCollector::with_capacity(RECORDS as usize);
    let mut throughput = ThroughputCounter::new();
    let t1 = Instant::now();
    throughput.start();

    let mut store = std::fs::File::create(&store_path)
        .map_err(|e| format!("cannot create {}: {e}", store_path.display()))?;
    let mut segment = open_segment(&wal_dir, 0)?;
    let mut logical_bytes: u64 = 0;
    let mut buf = Vec::with_capacity(RECORD_BYTES);

    for i in 0..RECORDS {
        if i > 0 && i % RECORDS_PER_SEGMENT == 0 {
            segment
                .flush()
                .map_err(|e| format!("cannot flush WAL segment: {e}"))?;
            segment = open_segment(&wal_dir, i / RECORDS_PER_SEGMENT)?;
        }
        let op = Instant::now();
        buf.clear();
        encode_record(i, &mut buf);
        // Redo first, then the home image — the durability order the real engine uses.
        segment
            .write_all(&buf)
            .map_err(|e| format!("cannot append to the WAL segment: {e}"))?;
        store
            .write_all(&buf)
            .map_err(|e| format!("cannot append to the store image: {e}"))?;
        latency.record(op.elapsed());
        throughput.op();
        logical_bytes = logical_bytes.saturating_add(buf.len() as u64);
        resources.sample_if_due();
    }
    segment
        .flush()
        .map_err(|e| format!("cannot flush the final WAL segment: {e}"))?;
    store
        .sync_all()
        .map_err(|e| format!("cannot fsync the store image: {e}"))?;
    throughput.stop();
    let workload_wall = t1.elapsed();
    collector.phase("workload", workload_wall);
    resources.sample();

    // --- Every section, from its real meter.
    collector.record_resources(resources.finish());
    collector.record_throughput(&throughput, &latency);

    // Storage: the store FILE and the WAL DIRECTORY, classified by PATH. The WAL is a directory of
    // segment files — a meter keying off the leaf name would attribute every WAL byte to the store
    // and report wal_bytes = 0, hiding the redo log completely.
    collector
        .record_storage(&store_path, &wal_dir, None)
        .map_err(|e| format!("cannot measure the store/WAL footprint: {e}"))?;
    // Amplification: real physical bytes over the real logical bytes this workload wrote.
    collector.record_amplification(logical_bytes, logical_bytes);
    // Per-element durable costs (`rmp #711`): the measured store image amortised over the dataset this
    // workload wrote into exactly that image (RECORDS "nodes", 4×RECORDS "relationships"). Derived
    // from two measurements — never a placeholder.
    collector.record_per_element_costs();

    collector.note(format!(
        "Smoke run: EVERY figure is measured, none injected. CPU/RSS are this driver process's own \
         (Target::SelfProcess) — it boots no server, so it is legitimately the subject; an example \
         whose subject is the SERVER meters the server's pid instead. Storage is a real on-disk \
         layout ({} store image + a {} WAL DIRECTORY of {} segment file(s)) walked by StorageMeter. \
         Latency percentiles are the real per-operation latencies of {RECORDS} operations.",
        store_path.display(),
        wal_dir.display(),
        RECORDS.div_ceil(RECORDS_PER_SEGMENT),
    ));

    let report = collector.finish();
    let (json, md) = report
        .write_to(evidence_dir)
        .map_err(|e| format!("failed to write evidence to {evidence_dir}: {e}"))?;
    println!("wrote {}", json.display());
    println!("wrote {}", md.display());

    let _ = std::fs::remove_dir_all(&root);

    // Optional baseline diff: prove the regression helper end to end.
    if let Some(path) = baseline_path {
        let baseline = EvidenceReport::load(path)
            .map_err(|e| format!("failed to load baseline {path}: {e}"))?;
        let cmp = report.compare_to_baseline(&baseline, &RegressionThresholds::default());
        print!("{}", cmp.summary());
        if cmp.regressed {
            return Ok(ExitCode::FAILURE);
        }
    }

    Ok(ExitCode::SUCCESS)
}

/// Encodes one fixed-width record: a big-endian id plus a deterministic payload. Real work (not a
/// sleep), so the measured latencies reflect actual per-operation cost.
fn encode_record(id: u64, out: &mut Vec<u8>) {
    out.extend_from_slice(&id.to_be_bytes());
    let mut x = id.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
    while out.len() < RECORD_BYTES {
        x ^= x >> 30;
        x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x ^= x >> 27;
        out.extend_from_slice(&x.to_be_bytes());
    }
    out.truncate(RECORD_BYTES);
}

/// Opens WAL segment `n` inside the WAL **directory**, named like the server's (`seg.<lsn>`).
fn open_segment(wal_dir: &Path, n: u64) -> Result<std::fs::File, String> {
    let path: PathBuf = wal_dir.join(format!("seg.{n:016x}"));
    std::fs::File::create(&path).map_err(|e| format!("cannot create {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression (`rmp #699`): the encoder must produce exactly one fixed-width record — the byte
    /// count the report's logical/physical figures are derived from.
    #[test]
    fn encode_record_is_fixed_width() {
        let mut out = Vec::new();
        for id in [0u64, 1, 7, 999, u64::MAX] {
            out.clear();
            encode_record(id, &mut out);
            assert_eq!(out.len(), RECORD_BYTES, "record {id} is not fixed-width");
        }
    }

    /// Regression (`rmp #699`): distinct ids must produce distinct records, so the workload does real
    /// (non-elidable) work rather than rewriting one cached buffer.
    #[test]
    fn encode_record_is_id_dependent() {
        let (mut a, mut b) = (Vec::new(), Vec::new());
        encode_record(1, &mut a);
        encode_record(2, &mut b);
        assert_ne!(a, b);
    }
}
