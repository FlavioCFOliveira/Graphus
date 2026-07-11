//! `bulk_reopen` — measures the **cost of REOPENING a bulk-loaded store** (`rmp` #716).
//!
//! # Why this is a first-class ETL vector
//!
//! An offline bulk load is only half the operation. The other half is what an operator pays the
//! *next* time the store is opened — and for a WAL-logged loader that cost is not incidental, it is
//! the whole retained redo log being replayed. Two measured findings make this the single most
//! important thing a bulk-ETL example can expose:
//!
//! - **`rmp` #576** — reopening a large bulk-loaded store took **~33 s**, because a store REOPEN
//!   reads the entire un-reclaimed WAL.
//! - **`rmp` #579** — the same path blew the resident set up to **~25 GB** on a large import,
//!   because nothing reclaimed the WAL at the end of the load.
//!
//! Both are *reopen* costs, invisible to a run that only times the import. This driver makes them
//! measurable, so the example can assert on them rather than discover them in production.
//!
//! # What it measures
//!
//! It is deliberately a **separate process** so that every figure is attributable to the reopen
//! alone (its peak RSS is the reopen's peak RSS, not an importer's), and so the caller can meter it
//! by PID exactly as it meters the import child.
//!
//! 1. **Pre-open footprint** — the durable `graph.store` image and the **WAL residual**: the redo-log
//!    bytes the completed load left behind, which are precisely what a reopen must read.
//! 2. **`open_secs`** — the wall time of the store open itself: WAL recovery (`recover_device`) plus
//!    [`RecordStore::open`]. This is the #576/#579 path.
//! 3. **`scan_secs`** — the wall time of a full node + relationship id scan afterwards, reported
//!    separately so the *open* cost is never inflated by the cost of reading the graph back.
//! 4. **Post-open footprint** — the store and WAL bytes *after* the reopen, so a recovery that
//!    rewrites the device (or a WAL nothing ever reclaims) is visible as a delta rather than assumed.
//! 5. **`peak_rss_bytes`** — the reopen process's own high-water resident set (the #579 vector).
//!
//! The node/relationship counts are asserted against `--expect-nodes` / `--expect-rels` when given,
//! so a reopen that loses data fails loudly instead of reporting a fast, empty store.
//!
//! # Usage
//!
//! ```text
//! bulk_reopen --db <store-dir> [--expect-nodes N] [--expect-rels M] [--out reopen.json]
//! ```
//!
//! Emits a stable `GRAPHUS_BULK_REOPEN_OK key=value …` line on stdout (parsed by `run.sh`) and, with
//! `--out`, the same figures as JSON.

#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use graphus_bulk_gen::footprint::measure_store_dir;
use graphus_bulk_gen::store_io::open_store;
use graphus_examples_harness::{Target, current_rss_bytes, peak_rss_self_bytes};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bulk_reopen: error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut db: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut expect_nodes: Option<u64> = None;
    let mut expect_rels: Option<u64> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--db" => db = Some(PathBuf::from(next(&mut args, "--db")?)),
            "--out" => out = Some(PathBuf::from(next(&mut args, "--out")?)),
            "--expect-nodes" => {
                expect_nodes = Some(
                    next(&mut args, "--expect-nodes")?
                        .parse()
                        .map_err(|e| format!("--expect-nodes: {e}"))?,
                );
            }
            "--expect-rels" => {
                expect_rels = Some(
                    next(&mut args, "--expect-rels")?
                        .parse()
                        .map_err(|e| format!("--expect-rels: {e}"))?,
                );
            }
            "-h" | "--help" => {
                eprintln!(
                    "usage: bulk_reopen --db <store-dir> [--expect-nodes N] [--expect-rels M] \
                     [--out <reopen.json>]"
                );
                return Ok(());
            }
            other => return Err(format!("unexpected argument '{other}'")),
        }
    }
    let db = db.ok_or("--db is required (the bulk-loaded store directory)")?;

    // ----- 1. The footprint the load LEFT BEHIND — what a reopen has to read. -----
    let before = measure_store_dir(&db).map_err(|e| format!("measuring {}: {e}", db.display()))?;

    // ----- 2. The reopen itself: WAL recovery + RecordStore::open. THE #576/#579 path. -----
    let t_open = Instant::now();
    let store = open_store(&db).map_err(|e| format!("reopening store: {e}"))?;
    let open_secs = t_open.elapsed().as_secs_f64();

    // ----- 3. A full scan, timed SEPARATELY so it never inflates the open cost. -----
    let t_scan = Instant::now();
    let nodes = store
        .scan_node_ids()
        .map_err(|e| format!("scanning nodes: {e}"))?
        .len() as u64;
    let rels = store
        .scan_rel_ids()
        .map_err(|e| format!("scanning relationships: {e}"))?
        .len() as u64;
    let scan_secs = t_scan.elapsed().as_secs_f64();

    // The reopened store must hold the graph the load put there. A reopen that came back FAST because
    // it came back EMPTY is the failure this assertion exists to catch.
    if let Some(expected) = expect_nodes {
        if nodes != expected {
            return Err(format!(
                "reopened store holds {nodes} nodes, expected {expected} — the reopen LOST data"
            ));
        }
    }
    if let Some(expected) = expect_rels {
        if rels != expected {
            return Err(format!(
                "reopened store holds {rels} relationships, expected {expected} — the reopen LOST \
                 data"
            ));
        }
    }

    // ----- 4/5. The post-reopen footprint + this process's peak RSS (the #579 memory vector). -----
    let after =
        measure_store_dir(&db).map_err(|e| format!("re-measuring {}: {e}", db.display()))?;
    // The OS-reported HIGH-WATER mark of this process (`getrusage`'s `ru_maxrss`) — authoritative and
    // impossible to miss between samples, unlike a poll of the current RSS. This process did nothing
    // but reopen this store, so its peak IS the reopen's peak (the `rmp` #579 vector). The current-RSS
    // read is only a fallback for a platform with no `getrusage` backend.
    let peak_rss = peak_rss_self_bytes()
        .or_else(|| current_rss_bytes(Target::SelfProcess))
        .unwrap_or(0);

    // Drop the store handle before reporting, so nothing below is attributed to a live buffer pool.
    drop(store);

    let report = ReopenReport {
        open_secs,
        scan_secs,
        nodes,
        relationships: rels,
        store_bytes_before: before.store_bytes,
        wal_bytes_before: before.wal_bytes,
        store_bytes_after: after.store_bytes,
        wal_bytes_after: after.wal_bytes,
        peak_rss_bytes: peak_rss,
    };

    eprintln!(
        "bulk_reopen: open={:.4}s scan={:.4}s ({} nodes, {} rels); WAL residual the reopen had to \
         read = {} B; store {} B -> {} B, wal {} B -> {} B; peak_rss={} B",
        report.open_secs,
        report.scan_secs,
        report.nodes,
        report.relationships,
        report.wal_bytes_before,
        report.store_bytes_before,
        report.store_bytes_after,
        report.wal_bytes_before,
        report.wal_bytes_after,
        report.peak_rss_bytes,
    );
    // The stable, machine-readable line run.sh parses + asserts on.
    println!(
        "GRAPHUS_BULK_REOPEN_OK open_secs={:.4} scan_secs={:.4} nodes={} relationships={} \
         wal_residual_bytes={} store_bytes={} peak_rss_bytes={}",
        report.open_secs,
        report.scan_secs,
        report.nodes,
        report.relationships,
        report.wal_bytes_before,
        report.store_bytes_before,
        report.peak_rss_bytes,
    );

    if let Some(path) = &out {
        std::fs::write(path, render_json(&report))
            .map_err(|e| format!("writing {}: {e}", path.display()))?;
    }
    Ok(())
}

/// The measured cost of one store reopen (stable JSON field names).
struct ReopenReport {
    open_secs: f64,
    scan_secs: f64,
    nodes: u64,
    relationships: u64,
    store_bytes_before: u64,
    wal_bytes_before: u64,
    store_bytes_after: u64,
    wal_bytes_after: u64,
    peak_rss_bytes: u64,
}

fn render_json(r: &ReopenReport) -> String {
    let mut s = String::with_capacity(512);
    s.push_str("{\n");
    let _ = writeln!(s, "  \"open_secs\": {:.6},", r.open_secs);
    let _ = writeln!(s, "  \"scan_secs\": {:.6},", r.scan_secs);
    let _ = writeln!(s, "  \"nodes\": {},", r.nodes);
    let _ = writeln!(s, "  \"relationships\": {},", r.relationships);
    let _ = writeln!(s, "  \"store_bytes_before\": {},", r.store_bytes_before);
    let _ = writeln!(s, "  \"wal_bytes_before\": {},", r.wal_bytes_before);
    let _ = writeln!(s, "  \"store_bytes_after\": {},", r.store_bytes_after);
    let _ = writeln!(s, "  \"wal_bytes_after\": {},", r.wal_bytes_after);
    let _ = writeln!(s, "  \"peak_rss_bytes\": {},", r.peak_rss_bytes);
    s.push_str(
        "  \"note\": \"open_secs is the store REOPEN: WAL recovery (recover_device) + \
         RecordStore::open — the path rmp #576 measured at ~33s and rmp #579 blew up to ~25GB of \
         RSS on a large load, because a reopen reads the whole un-reclaimed WAL. wal_bytes_before is \
         the WAL RESIDUAL the completed load left behind (exactly what the reopen must replay). \
         scan_secs is a separate full id scan, reported apart so it never inflates the open cost. \
         peak_rss_bytes is this process's own high-water RSS — it did nothing but reopen the \
         store.\"\n",
    );
    s.push_str("}\n");
    s
}

fn next(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} requires a value"))
}
