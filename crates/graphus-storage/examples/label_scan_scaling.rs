//! `label_scan_scaling` — reproduces the `rmp` #808 armed/unarmed multi-core scaling collapse of
//! [`LabelHistory::resolve`], the hottest predicate re-check in the engine.
//!
//! It measures **aggregate label-scan throughput** (a "scan" = resolving the label bitmap of every
//! node in a fixed set) at 1/2/4/8/16 reader threads, in two states:
//!
//! * **unarmed** — no node has a tracked change, so `resolve` short-circuits on the `any()` gate
//!   (the shipped steady-state path); scales freely.
//! * **armed** — a small number of already-committed, GC-not-yet-pruned relabels are tracked
//!   (the realistic armed window), so under the *current* design every re-check takes a shared
//!   `RwLock` read acquisition — an atomic RMW on one cache line, contended by every reader.
//!
//! Run on an idle host, release build:
//! ```text
//! cargo run -p graphus-storage --release --example label_scan_scaling
//! ```
//!
//! Optional args: `<scan_nodes> <tracked_nodes> <secs_per_cell>` (defaults: 20000 2 1.5).

use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use graphus_core::{Timestamp, TxnId};
use graphus_storage::LabelHistory;
use graphus_txn::{CommitRegistry, Snapshot};

const THREAD_COUNTS: &[usize] = &[1, 2, 4, 8, 16];

fn main() {
    let mut args = std::env::args().skip(1);
    let scan_nodes: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(20_000);
    let tracked_nodes: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(2);
    let secs: f64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(1.5);
    let budget = Duration::from_secs_f64(secs);

    eprintln!(
        "[label_scan_scaling] scan_nodes={scan_nodes} tracked_nodes={tracked_nodes} \
         secs_per_cell={secs}"
    );
    eprintln!("[label_scan_scaling] one 'scan' resolves {scan_nodes} node label bitmaps\n");

    // A registry the resolved (settled) versions never actually consult, but that the signature
    // requires; the reader snapshot is fixed and old enough to see every settled version.
    let registry = Arc::new(build_registry(tracked_nodes));
    let snapshot = Snapshot {
        owner: TxnId(u64::MAX / 2),
        ts: Timestamp(u64::MAX / 2),
    };

    for &armed in &[false, true] {
        println!("==== gate {} ====", if armed { "ARMED" } else { "UNARMED" });
        println!(" {:>7} {:>16} {:>10}", "threads", "scans/s", "speedup");
        let mut base = 0.0f64;
        for (i, &nthreads) in THREAD_COUNTS.iter().enumerate() {
            let hist = Arc::new(build_history(armed, tracked_nodes));
            let per_s = run_cell(&hist, &registry, snapshot, scan_nodes, nthreads, budget);
            if i == 0 {
                base = per_s;
            }
            println!(
                " {:>7} {:>16.0} {:>9.2}x",
                nthreads,
                per_s,
                if base > 0.0 { per_s / base } else { 0.0 }
            );
        }
        println!();
    }
}

/// Builds a history in the requested state. Armed: `tracked_nodes` already-committed, settled
/// relabels (ids `0..tracked_nodes`), the realistic armed window (committed but not yet GC-pruned).
fn build_history(armed: bool, tracked_nodes: u64) -> LabelHistory {
    let hist = LabelHistory::new();
    if armed {
        for id in 0..tracked_nodes {
            let txn = TxnId(id + 1);
            // A committed relabel: bit flip, then settle to a commit ts the reader snapshot sees.
            hist.record(id, txn, 0b1, 0b11);
            hist.settle(txn, Timestamp(1), &[id]);
        }
        assert!(hist.any(), "armed history must arm the gate");
    } else {
        assert!(!hist.any(), "unarmed history must not arm the gate");
    }
    hist
}

/// A registry whose committed writers match the settled versions (not consulted for settled reads,
/// but constructed consistently).
fn build_registry(tracked_nodes: u64) -> CommitRegistry {
    let mut reg = CommitRegistry::new();
    for id in 0..tracked_nodes {
        reg.record_commit(TxnId(id + 1), Timestamp(1));
    }
    reg
}

/// Runs one (threads, armed) cell: `nthreads` reader threads each repeatedly scan the id range,
/// resolving every node's label bitmap, for `budget` wall-time. Returns aggregate scans/second.
fn run_cell(
    hist: &Arc<LabelHistory>,
    registry: &Arc<CommitRegistry>,
    snapshot: Snapshot,
    scan_nodes: u64,
    nthreads: usize,
    budget: Duration,
) -> f64 {
    let start_gate = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::with_capacity(nthreads);
    for _ in 0..nthreads {
        let hist = Arc::clone(hist);
        let registry = Arc::clone(registry);
        let start_gate = Arc::clone(&start_gate);
        handles.push(thread::spawn(move || {
            while !start_gate.load(Ordering::Acquire) {
                std::hint::spin_loop();
            }
            let deadline = Instant::now() + budget;
            let mut scans = 0u64;
            let mut acc = 0u64;
            loop {
                // One scan: resolve every node's label bitmap. The `live` word stands in for the
                // value already decoded from the record on the real read path.
                for id in 0..scan_nodes {
                    acc ^= hist.resolve(id, 0b1, snapshot, &registry);
                }
                scans += 1;
                if Instant::now() >= deadline {
                    break;
                }
            }
            black_box(acc);
            scans
        }));
    }
    // Release all readers together and time the real window.
    let wall_start = Instant::now();
    start_gate.store(true, Ordering::Release);
    let total_scans: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    let elapsed = wall_start.elapsed().as_secs_f64();
    total_scans as f64 / elapsed
}
