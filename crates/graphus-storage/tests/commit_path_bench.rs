//! `#[ignore]` micro-benchmark + allocation audit for the OLTP write path (`rmp` #373).
//!
//! Run with: `cargo test -p graphus-storage --test commit_path_bench -- --ignored --nocapture`
//!
//! Quantifies the before/after of the per-record WAL-logged write path. The optimization replaces
//! the per-field `encode_patch` heap `Vec` (two per write: redo + undo) with an inline
//! [`graphus_storage::paging`]-style `SmallVec` patch built with zero allocation, and lends the redo
//! image to the WAL by borrow (`WalManager::log_update_borrowed`) so the redo image — read and
//! dropped, never retained — costs no allocation at all. Only the genuinely-retained undo image
//! still becomes an owned `Vec` (the WAL keeps it for rollback/recovery).
//!
//! Two figures are reported, both for a representative `CREATE (n {a, b, c})` shape (one node-record
//! body write + three property creates, each = record-body creation undo + a `first_prop` chain-head
//! compare-and-set undo):
//!
//! 1. **Allocation count per transaction** — measured by a counting global allocator, so the
//!    reduction is exact and deterministic, not timing-noisy.
//! 2. **Wall-clock CPU per transaction** — a deterministic single-threaded timing loop.
//!
//! The allocation figure is the primary acceptance signal (`rmp` #373 acceptance criterion 1:
//! reduced allocations per txn); the timing figure corroborates the CPU win.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use graphus_core::TxnId;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// A counting allocator: tallies every allocation while `COUNTING` is armed, so a benchmarked region
/// can read the exact number of heap allocations it performed. Delegates all work to the System
/// allocator — it adds only an atomic increment, never changes allocation behaviour.
struct CountingAllocator;

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static COUNTING: AtomicBool = AtomicBool::new(false);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("wal");
    // A pool large enough to hold the working set so the bench measures the write-path
    // synchronisation/allocation tax, not eviction churn.
    RecordStore::create(device, wal, 4096, 1).expect("store")
}

/// One `CREATE (n {a, b, c})`-shaped transaction: a node and three inline properties.
fn create_node_with_three_props(s: &mut Store, txn: TxnId) {
    s.begin(txn);
    let (node, _) = s.create_node(txn).unwrap();
    s.add_node_property(txn, node, 7, 1, 0x1111).unwrap();
    s.add_node_property(txn, node, 8, 1, 0x2222).unwrap();
    s.add_node_property(txn, node, 9, 1, 0x3333).unwrap();
    s.commit(txn).unwrap();
}

#[test]
#[ignore = "timing/allocation bench; run explicitly with --ignored --nocapture"]
fn bench_commit_path_allocations_and_cpu() {
    let txns: u64 = 50_000;

    // --- Allocation audit: count heap allocations across `txns` create transactions. ---
    let mut s = fresh();
    // Warm one transaction first so any one-time lazy allocations (catalog growth, page faults) are
    // not attributed to the measured steady-state.
    create_node_with_three_props(&mut s, TxnId(1));

    ALLOCS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    for i in 0..txns {
        create_node_with_three_props(&mut s, TxnId(i + 2));
    }
    COUNTING.store(false, Ordering::Relaxed);
    let total_allocs = ALLOCS.load(Ordering::Relaxed);
    let per_txn = total_allocs as f64 / txns as f64;

    // --- CPU: deterministic single-threaded timing of the same workload. ---
    let mut s2 = fresh();
    create_node_with_three_props(&mut s2, TxnId(1));
    let start = Instant::now();
    for i in 0..txns {
        create_node_with_three_props(&mut s2, TxnId(i + 2));
    }
    let elapsed = start.elapsed();
    let per_txn_ns = elapsed.as_nanos() as f64 / txns as f64;

    println!("commit-path bench (rmp #373): CREATE (n {{a, b, c}}) x {txns}");
    println!("  heap allocations: total={total_allocs}  per-txn={per_txn:.2}");
    println!(
        "  CPU: total={:?}  per-txn={per_txn_ns:.0} ns  ({:.0} txn/s)",
        elapsed,
        1e9 / per_txn_ns
    );
}
