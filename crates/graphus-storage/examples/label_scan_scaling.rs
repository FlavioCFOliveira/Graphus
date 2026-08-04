//! `label_scan_scaling` — multi-core scaling of the label predicate re-check, the hottest read in
//! the engine, measured against the `rmp` #968 undo-chain design.
//!
//! It measures **aggregate label-scan throughput** (a "scan" = resolving the label bitmap of every
//! node in a fixed set) at 1/2/4/8/16 reader threads, in two states:
//!
//! * **unarmed** — no node has an undo chain, so every resolution short-circuits on `head == 0` and
//!   reads nothing. This is the steady state and what a pure label scan pays.
//! * **armed** — a small number of already-committed, GC-not-yet-reclaimed relabels carry a chain
//!   (the realistic armed window). Only those nodes walk; the untracked majority still short-circuits.
//!
//! # Why this replaces the `rmp` #767 / #808 harness
//!
//! Labels used to be versioned in an in-process, id-keyed map (`LabelHistory`), whose armed state put
//! an atomic `Acquire` load on **every** candidate — and, before #808's lock-free Bloom pre-filter, a
//! shared `RwLock` acquisition on every candidate, which collapsed aggregate throughput to 0.12x of
//! single-thread at 16 threads. #968 retired that map: a label version is a delta on the node's own
//! undo chain, so an untracked node costs a comparison against a word the caller already decoded —
//! no atomic, no filter probe, no lock, and nothing shared between cores at all.
//!
//! That is the claim this harness exists to check, and the reason the armed/unarmed split is kept:
//! the interesting number is not raw throughput but whether **arming still costs the untracked
//! majority anything**.
//!
//! Run on an idle host, release build:
//! ```text
//! cargo run -p graphus-storage --release --example label_scan_scaling
//! ```
//!
//! Optional args: `<scan_nodes> <tracked_nodes> <secs_per_cell>` (defaults: 20000 2 1.5).
//!
//! # Measured (`rmp` #968 acceptance criterion 6)
//!
//! AMD Ryzen 9 5900HX (8C/16T), `--release`, idle host, defaults above. `scans/s`:
//!
//! | threads | UNARMED before | UNARMED after | ARMED before | ARMED after |
//! |---:|---:|---:|---:|---:|
//! | 1 | 29 529 | **47 540** | 19 151 | **44 602** |
//! | 8 | 208 500 | **332 459** | 133 909 | **323 365** |
//! | 16 | 205 268 | **340 083** | 133 675 | **333 256** |
//!
//! Better on every cell — 1.6x unarmed, 2.3-2.5x armed — and scaling is unchanged (6.95x -> 7.15x
//! unarmed, 6.98x -> 7.47x at 16 threads), so the gain is per-candidate cost rather than contention
//! that happened to move.
//!
//! The number that carries the design claim is the **armed/unarmed gap at one thread**: 35% before
//! (19 151 vs 29 529), 6% after (44 602 vs 47 540). Arming used to tax every candidate with an atomic
//! load plus a filter probe; now an untracked node compares one already-decoded word against zero, so
//! a relabel somewhere in the store costs the rest of the scan essentially nothing.

use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use graphus_core::{Timestamp, TxnId};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore, StoreReadView};
use graphus_txn::Snapshot;
use graphus_wal::{MemLogSink, WalManager};

const THREAD_COUNTS: &[usize] = &[1, 2, 4, 8, 16];

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// Builds a store of `scan_nodes` committed nodes all carrying label bit 0, then — when `armed` —
/// relabels the first `tracked_nodes` of them in a second committed transaction, so exactly those
/// carry a non-zero `undo_ptr` while every other node's is `0`.
fn build_store(armed: bool, scan_nodes: u64, tracked_nodes: u64) -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    // A pool large enough that the scan is CPU-bound rather than an I/O benchmark: the subject is
    // the per-candidate cost of the resolution, not the buffer pool.
    let mut store: Store = RecordStore::create(device, wal, 65_536, 1).expect("create store");

    let l0 = store
        .intern_token(Namespace::Label, "Scanned")
        .expect("intern Scanned");
    let l1 = store
        .intern_token(Namespace::Label, "Relabelled")
        .expect("intern Relabelled");

    let t0 = TxnId(1);
    store.begin(t0);
    for _ in 0..scan_nodes {
        let (id, _) = store.create_node(t0).expect("create node");
        store.add_label(t0, id, l0).expect("seed label");
    }
    store.commit(t0).expect("seed commits");

    // A GC pass at the full watermark, because THE STEADY STATE IS WHAT THIS MEASURES. A node's
    // creation links a `DeleteObject` delta, so `undo_ptr` is non-zero from the moment it is created
    // and only becomes `0` once GC reclaims that delta — which, for a committed live node below the
    // watermark, is the very next pass. Without this the "unarmed" cell would measure every node
    // walking its creation delta, i.e. a state a running server leaves within one GC tick, and the
    // comparison against the pre-#968 numbers would be against the wrong thing.
    let tgc = TxnId(90);
    store.begin(tgc);
    let wm = store.snapshot_ts();
    store.gc(tgc, wm).expect("gc pass");
    store.commit(tgc).expect("gc commits");

    if armed {
        // A SECOND, committed transaction: the nodes were created earlier, so the creator gate does
        // not apply and each relabel genuinely links a delta. Committed and not GC'd — the realistic
        // armed window.
        let t1 = TxnId(2);
        store.begin(t1);
        for id in 1..=tracked_nodes {
            store.add_label(t1, id, l1).expect("relabel");
        }
        store.commit(t1).expect("relabel commits");
    }
    store
}

/// Runs one (threads, armed) cell: `nthreads` reader threads each repeatedly scan the id range,
/// resolving every node's label bitmap through the read view, for `budget` wall-time. Returns
/// aggregate scans/second.
fn run_cell(
    view: &StoreReadView<MemBlockDevice, MemLogSink>,
    nodes: &Arc<Vec<(u64, u64, u64)>>,
    snapshot: Snapshot,
    nthreads: usize,
    budget: Duration,
) -> f64 {
    let start_gate = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::with_capacity(nthreads);
    for _ in 0..nthreads {
        let view = view.clone();
        let nodes = Arc::clone(nodes);
        let start_gate = Arc::clone(&start_gate);
        handles.push(thread::spawn(move || {
            while !start_gate.load(Ordering::Acquire) {
                std::hint::spin_loop();
            }
            let deadline = Instant::now() + budget;
            let mut scans = 0u64;
            let mut acc = 0u64;
            loop {
                // One scan: resolve every node's label bitmap. `live` and `head` stand in for the
                // two words the real read path has already decoded from the record.
                for &(id, live, head) in nodes.iter() {
                    acc ^= view
                        .label_bitmap_at(id, live, head, snapshot)
                        .expect("resolve labels");
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let parse = |i: usize, d: f64| -> f64 { args.get(i).and_then(|s| s.parse().ok()).unwrap_or(d) };
    let scan_nodes = parse(1, 20_000.0) as u64;
    let tracked_nodes = parse(2, 2.0) as u64;
    let secs = parse(3, 1.5);
    let budget = Duration::from_secs_f64(secs);

    println!(
        "[label_scan_scaling] scan_nodes={scan_nodes} tracked_nodes={tracked_nodes} \
         secs_per_cell={secs}"
    );
    println!("[label_scan_scaling] one 'scan' resolves {scan_nodes} node label bitmaps");

    for armed in [false, true] {
        let store = build_store(armed, scan_nodes, tracked_nodes);
        let view = store.read_view();
        // Decode each record ONCE, exactly as the real read path does before it asks for the
        // resolution; the per-candidate cost under test is what happens after that.
        let nodes: Arc<Vec<(u64, u64, u64)>> = Arc::new(
            (1..=scan_nodes)
                .map(|id| {
                    let rec = store.node(id).expect("read node");
                    (id, rec.labels, rec.mvcc.undo_ptr)
                })
                .collect(),
        );
        let chained = nodes.iter().filter(|(_, _, head)| *head != 0).count();
        assert_eq!(
            chained,
            if armed { tracked_nodes as usize } else { 0 },
            "the {} state must have exactly {} chained nodes, else the cell is not measuring what \
             its name says",
            if armed { "ARMED" } else { "UNARMED" },
            if armed { tracked_nodes } else { 0 },
        );
        let snapshot = Snapshot {
            owner: TxnId(u64::MAX),
            ts: Timestamp(u64::MAX),
        };

        println!(
            "\n==== chain {} ====",
            if armed { "ARMED" } else { "UNARMED" }
        );
        println!("{:>8} {:>16} {:>10}", "threads", "scans/s", "speedup");
        let mut base = 0.0;
        for &t in THREAD_COUNTS {
            let rate = run_cell(&view, &nodes, snapshot, t, budget);
            if t == 1 {
                base = rate;
            }
            println!("{t:>8} {:>16.0} {:>9.2}x", rate, rate / base);
        }
    }
}
