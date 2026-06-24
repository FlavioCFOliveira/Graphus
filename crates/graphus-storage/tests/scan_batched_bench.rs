//! `#[ignore]` micro-benchmark for the page-batched scan primitive (`rmp` #365).
//!
//! Run with: `cargo test -p graphus-storage --test scan_batched_bench -- --ignored --nocapture`
//!
//! Deterministic, single-threaded timing measurement (not a criterion harness) quantifying the
//! before/after of the full-store node/rel scan. The OLD path is the pre-#365 one-latch-per-record
//! loop (`node(id)` per id over `1..high_water`); the NEW path is the page-batched
//! `scan_node_ids` (one pin + read latch per 8 KiB page, 125 node / 80 rel slots per latch). The
//! measured corpus throughput is reported in Melem/s for each. Both paths return the **same** id
//! set (asserted), so the speedup is a pure synchronisation-amortisation win.

use std::time::Instant;

use graphus_core::TxnId;
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// The pre-#365 per-id node scan: one `node(id)` (one pin + read latch + unpin) per record id over
/// the contiguous `1..=count` physical-id space, keeping the slot-occupied ids.
fn per_id_scan_node_ids(s: &Store, count: u64) -> Vec<u64> {
    (1..=count)
        .filter(|&id| s.node(id).unwrap().mvcc.in_use())
        .collect()
}

fn per_id_scan_rel_ids(s: &Store, count: u64) -> Vec<u64> {
    (1..=count)
        .filter(|&id| s.rel(id).unwrap().mvcc.in_use())
        .collect()
}

#[test]
#[ignore = "timing bench; run explicitly with --ignored --nocapture"]
fn bench_batched_vs_per_id_node_scan() {
    // A pool large enough to hold the working set so the bench measures the per-record
    // synchronisation tax (the #365 target), not eviction churn: 200_000 nodes span ~1600 node
    // pages, so a 4096-frame pool keeps them resident.
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("wal");
    let mut s = RecordStore::create(device, wal, 4096, 1).expect("store");
    let n: u64 = 200_000;
    let txn = TxnId(1);
    s.begin(txn);
    for _ in 0..n {
        s.create_node(txn).unwrap();
    }
    s.commit(txn).unwrap();

    // Warm the cache so neither path pays the cold device-read cost.
    let warm = s.scan_node_ids().unwrap();
    assert_eq!(warm.len() as u64, n);

    // OLD: one latch per record.
    let start = Instant::now();
    let old_ids = per_id_scan_node_ids(&s, n);
    let old = start.elapsed();

    // NEW: one latch per page.
    let start = Instant::now();
    let new_ids = s.scan_node_ids().unwrap();
    let new = start.elapsed();

    assert_eq!(old_ids, new_ids, "batched scan must equal the per-id scan");

    let old_melem = n as f64 / old.as_secs_f64() / 1e6;
    let new_melem = n as f64 / new.as_secs_f64() / 1e6;
    println!(
        "scan-batched node bench: n={n} (resident) | OLD(per-id, one latch/record)={:?} ({:.1} Melem/s) NEW(page-batched, one latch/page)={:?} ({:.1} Melem/s) speedup={:.2}x",
        old,
        old_melem,
        new,
        new_melem,
        old.as_secs_f64() / new.as_secs_f64().max(1e-9),
    );
}

#[test]
#[ignore = "timing bench; run explicitly with --ignored --nocapture"]
fn bench_batched_vs_per_id_rel_scan() {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("wal");
    let mut s = RecordStore::create(device, wal, 4096, 1).expect("store");
    let txn = TxnId(1);
    s.begin(txn);
    let hubs: Vec<u64> = (0..100).map(|_| s.create_node(txn).unwrap().0).collect();
    let t = s.intern_token(Namespace::RelType, "LINK").unwrap();
    let n: u64 = 200_000;
    for i in 0..n {
        let a = hubs[(i as usize) % hubs.len()];
        let b = hubs[((i + 1) as usize) % hubs.len()];
        s.create_rel(txn, t, a, b).unwrap();
    }
    s.commit(txn).unwrap();

    let warm = s.scan_rel_ids().unwrap();
    assert_eq!(warm.len() as u64, n);

    let start = Instant::now();
    let old_ids = per_id_scan_rel_ids(&s, n);
    let old = start.elapsed();

    let start = Instant::now();
    let new_ids = s.scan_rel_ids().unwrap();
    let new = start.elapsed();

    assert_eq!(
        old_ids, new_ids,
        "batched rel scan must equal the per-id scan"
    );

    let old_melem = n as f64 / old.as_secs_f64() / 1e6;
    let new_melem = n as f64 / new.as_secs_f64() / 1e6;
    println!(
        "scan-batched rel bench: n={n} (resident) | OLD(per-id, one latch/record)={:?} ({:.1} Melem/s) NEW(page-batched, one latch/page)={:?} ({:.1} Melem/s) speedup={:.2}x",
        old,
        old_melem,
        new,
        new_melem,
        old.as_secs_f64() / new.as_secs_f64().max(1e-9),
    );
}
