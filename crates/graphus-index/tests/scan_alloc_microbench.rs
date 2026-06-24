//! `#[ignore]` allocation micro-bench for the `rmp` #369 streaming scan forms.
//!
//! Measures heap allocations + peak resident bytes for a label scan (`TokenIndex::scan_token`) and a
//! bitmap probe (`BitmapIndex::seek_eq`) **before** (eager `range(...).collect::<Vec<_>>()` /
//! `seek_eq().into_iter()`) vs **after** (streaming `range_for_each` / `seek_eq_iter`), proving the
//! per-row owned-pair allocations are gone with an IDENTICAL candidate set.
//!
//! Run with:
//!   cargo test -p graphus-index --release scan_alloc_microbench -- --ignored --nocapture

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use graphus_bufpool::BufferPool;
use graphus_core::{TxnId, Value};
use graphus_index::bitmap::BitmapIndex;
use graphus_index::recovery::SharedWal;
use graphus_index::{BTree, TokenIndex};
use graphus_io::MemBlockDevice;
use graphus_wal::{MemLogSink, WalManager};

/// A counting allocator: tracks number of allocations and live/peak bytes.
struct Counting;

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static A: Counting = Counting;

struct Snap {
    allocs: u64,
    peak: usize,
}

fn measure<R>(f: impl FnOnce() -> R) -> (Snap, R) {
    let a0 = ALLOCS.load(Ordering::Relaxed);
    LIVE.store(0, Ordering::Relaxed);
    PEAK.store(0, Ordering::Relaxed);
    let r = f();
    let snap = Snap {
        allocs: ALLOCS.load(Ordering::Relaxed) - a0,
        peak: PEAK.load(Ordering::Relaxed),
    };
    (snap, r)
}

type Dev = MemBlockDevice;
type Sink = MemLogSink;

fn fresh_tree() -> BTree<Dev, Sink> {
    let wal = WalManager::create(MemLogSink::new()).unwrap();
    let shared = SharedWal::new(wal);
    let pool = BufferPool::with_wal(MemBlockDevice::new(0), shared.clone(), 64);
    BTree::create(pool, shared).unwrap()
}

#[test]
#[ignore = "alloc micro-bench; run explicitly with --ignored --release --nocapture"]
fn scan_alloc_microbench() {
    const N: u64 = 200_000;

    // ---- Label scan (TokenIndex::scan_token over one token of N ids) ----
    let mut idx = TokenIndex::new(fresh_tree());
    let txn = TxnId(1);
    idx.tree_mut().with_wal(|w| w.begin(txn));
    for id in 0..N {
        idx.insert(txn, 7, id).unwrap();
    }
    idx.tree_mut().with_wal(|w| w.commit(txn).unwrap());

    // BEFORE: eager range + filter_map (one owned (Vec,Vec) per row, key copy discarded).
    let lo = label_key(7, 0);
    let hi = label_key(7, u64::MAX);
    let (before, eager_ids) = measure(|| {
        let v: Vec<u64> = idx
            .tree_mut()
            .range(&lo, &hi)
            .unwrap()
            .into_iter()
            .filter_map(|(_, val)| val.as_slice().try_into().ok().map(u64::from_le_bytes))
            .collect();
        v
    });
    // AFTER: streaming scan_token (decodes rid straight out of the value slice).
    let (after, stream_ids) = measure(|| idx.scan_token(7).unwrap());

    assert_eq!(eager_ids, stream_ids, "IDENTICAL candidate set required");
    println!(
        "label-scan  N={N}: BEFORE {} allocs / peak {} KiB  ->  AFTER {} allocs / peak {} KiB  \
         ({:.1}x fewer allocs, {:.1}x less peak)",
        before.allocs,
        before.peak / 1024,
        after.allocs,
        after.peak / 1024,
        before.allocs as f64 / after.allocs.max(1) as f64,
        before.peak as f64 / after.peak.max(1) as f64,
    );

    // ---- Bitmap probe (one value over N ids) ----
    let mut bm = BitmapIndex::new();
    for id in 0..N {
        bm.insert(&Value::Boolean(true), id);
    }
    // BEFORE: eager seek_eq -> Vec then iterate-and-sum (the flat Vec materialization).
    let (bbefore, bsum_eager) = measure(|| bm.seek_eq(&Value::Boolean(true)).iter().sum::<u64>());
    // AFTER: streaming seek_eq_iter (no flat Vec; sum lazily).
    let (bafter, bsum_stream) = measure(|| {
        bm.seek_eq_iter(&Value::Boolean(true))
            .map(|it| it.sum::<u64>())
            .unwrap_or(0)
    });

    assert_eq!(bsum_eager, bsum_stream, "IDENTICAL candidate set required");
    println!(
        "bitmap-probe N={N}: BEFORE {} allocs / peak {} KiB  ->  AFTER {} allocs / peak {} KiB  \
         ({:.1}x fewer allocs, {:.1}x less peak)",
        bbefore.allocs,
        bbefore.peak / 1024,
        bafter.allocs,
        bafter.peak / 1024,
        bbefore.allocs as f64 / bafter.allocs.max(1) as f64,
        bbefore.peak as f64 / bafter.peak.max(1) as f64,
    );
}

/// `TokenIndex` label key layout, re-stated for the BEFORE arm (`token: u32 BE || id: u64 BE`).
fn label_key(token: u32, id: u64) -> Vec<u8> {
    let mut k = token.to_be_bytes().to_vec();
    k.extend_from_slice(&id.to_be_bytes());
    k
}
