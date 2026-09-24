//! **The Active Transaction Table and the process heap plateau under sustained write load from
//! concurrent writers** (`rmp` #1070 acceptance criterion 4, audit finding F; `rmp` #1071 acceptance
//! criterion 4).
//!
//! The shape that matters in production is writers committing WHILE a GC pass runs, so every pass
//! meets writers that committed behind its settle walk. This file drives two real writer threads that
//! commit a fixed batch in every round concurrently with that round's GC pass, and asserts after each
//! round that:
//!
//! 1. the Active Transaction Table never holds more than the open writers;
//! 2. the process's live heap bytes, counted by this binary's global allocator, stop growing.
//!
//! Until `rmp` #1071 it also bounded the in-memory Active/Recent Transaction Table and the per-writer
//! WAL floor (`unfrozen_commit_lsn`) by the traffic of one pass. Both are gone: nothing read the table
//! after `rmp` #1069, and the floor's one remaining job — keeping a `TxnId` a commit slot records from
//! being re-issued — is done by reading `commit.store` at `open`. The heap assertion is what now
//! proves nothing took their place as a leak.
//!
//! # Non-vacuity
//!
//! * **The inverse edit that makes it fail**: pin WAL reclamation — in `RecordStore::checkpoint`,
//!   clamp the reclaim floor to `0`, which is what a per-writer floor that is never drained amounts
//!   to (the failure the removed prune existed to prevent). The in-memory log then keeps every record
//!   and the heap climbs with the commit count.
//! * **The positive controls**: both writers must commit thousands of transactions, and some of those
//!   commits must land INSIDE a GC pass — otherwise this is a single-threaded test.
//!
//! Run in release for a representative load: the debug build is an order of magnitude slower.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use graphus_core::{TxnId, Value};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

/// Live heap bytes, maintained by [`Counting`].
static LIVE: AtomicUsize = AtomicUsize::new(0);

/// A counting allocator: tracks the bytes currently allocated. Delegates every call to [`System`] and
/// adds one atomic update, so it changes no allocation behaviour.
struct Counting;

// SAFETY: every method forwards to `System` with the caller's own arguments, so `System`'s contract
// is the contract here; the atomic bookkeeping touches no memory the allocator hands out.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged; the caller upholds `GlobalAlloc::alloc`'s contract.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded unchanged; the caller upholds `GlobalAlloc::dealloc`'s contract.
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarded unchanged; the caller upholds `GlobalAlloc::realloc`'s contract.
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            LIVE.fetch_add(new_size, Ordering::Relaxed);
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        new
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Writer threads. Two is the minimum the acceptance criterion asks for, and enough to have commits
/// land inside every pass.
const WRITERS: u64 = 2;

/// Rounds, one GC pass each, run while the writers commit.
const PASSES: usize = 45;

/// Passes discarded before the plateau is judged, while the store and the pool fill to size.
const WARMUP: usize = 15;

/// Nodes each writer keeps alive: once it holds this many, every transaction deletes its oldest, so
/// the live graph is bounded and anything that still grows is a leak.
const LIVE_PER_WRITER: usize = 8;

/// Transactions each writer commits per round, concurrently with that round's GC pass.
const COMMITS_PER_WRITER_PER_ROUND: u64 = 100;

/// One sample, taken after a round: its GC pass committed, the log was checkpointed, and every
/// writer is parked.
#[derive(Debug, Clone, Copy)]
struct Sample {
    active: usize,
    heap: usize,
}

/// Checkpoints, retrying a refusal. A checkpoint that meets another thread's freshly-mapped,
/// not-yet-logged page refuses to write it home (`rmp` #1087, open in this sprint); the refusal leaves
/// the store intact, and the window closes as soon as that writer logs its first record, so a retry
/// is the correct response here — this test is about what a SUCCESSFUL checkpoint can reclaim.
fn checkpoint_retrying(store: &RecordStore<MemBlockDevice, MemLogSink>) {
    let mut last = None;
    for _ in 0..1_000 {
        match store.checkpoint() {
            Ok(()) => return,
            Err(e) => {
                last = Some(e);
                std::thread::yield_now();
            }
        }
    }
    panic!("checkpoint refused 1000 times in a row: {last:?}");
}

#[test]
fn the_active_table_and_the_heap_plateau_under_concurrent_writers_1070() {
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store = Arc::new(RecordStore::create(MemBlockDevice::new(0), wal, 256, 1).expect("store"));
    let key = store.intern_token(Namespace::PropKey, "v").expect("key");
    let stop = Arc::new(AtomicBool::new(false));
    let commits = Arc::new(AtomicU64::new(0));
    let in_gc = Arc::new(AtomicBool::new(false));
    let inside = Arc::new(AtomicU64::new(0));
    // Rounds, not a free run: each round the writers commit a FIXED number of transactions while the
    // main thread's GC pass runs beside them, and all three meet at the end before the sample. A free
    // run lets the writers outpace the collector, so the garbage one pass leaves grows with the length
    // of the pass — which grows with the garbage — and the heap then measures that feedback rather
    // than whether any table leaks. Bounding the traffic per round keeps the concurrency (commits
    // still land inside the pass) and makes "plateau" a statement about the store.
    let start = Arc::new(Barrier::new(WRITERS as usize + 1));
    let end = Arc::new(Barrier::new(WRITERS as usize + 1));

    let writers: Vec<_> = (0..WRITERS)
        .map(|w| {
            let (store, stop) = (Arc::clone(&store), Arc::clone(&stop));
            let (commits, in_gc, inside) = (
                Arc::clone(&commits),
                Arc::clone(&in_gc),
                Arc::clone(&inside),
            );
            let (start, end) = (Arc::clone(&start), Arc::clone(&end));
            std::thread::spawn(move || {
                let mut mine: std::collections::VecDeque<u64> = std::collections::VecDeque::new();
                let mut attempt = 0u64;
                loop {
                    start.wait();
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    let mut done = 0u64;
                    while done < COMMITS_PER_WRITER_PER_ROUND {
                        attempt += 1;
                        let t = TxnId(1_000_000 * (w + 1) + attempt);
                        store.begin(t);
                        let outcome = (|| {
                            let (n, _) = store.create_node(t)?;
                            store.set_node_property_value(t, n, key, &Value::Integer(1))?;
                            let evicted = if mine.len() >= LIVE_PER_WRITER {
                                let old = *mine.front().expect("non-empty");
                                store.delete_node(t, old)?;
                                Some(old)
                            } else {
                                None
                            };
                            store.commit(t)?;
                            Ok::<_, graphus_core::GraphusError>((n, evicted))
                        })();
                        match outcome {
                            Ok((n, evicted)) => {
                                if evicted.is_some() {
                                    mine.pop_front();
                                }
                                mine.push_back(n);
                                done += 1;
                                commits.fetch_add(1, Ordering::SeqCst);
                                if in_gc.load(Ordering::SeqCst) {
                                    inside.fetch_add(1, Ordering::SeqCst);
                                }
                            }
                            Err(_) => {
                                // A retriable refusal: withdraw and retry with a fresh transaction.
                                let _ = store.rollback(t);
                            }
                        }
                    }
                    end.wait();
                }
            })
        })
        .collect();

    let mut samples: Vec<Sample> = Vec::with_capacity(PASSES);
    for pass in 0..PASSES {
        let g = TxnId(10_000 + pass as u64);
        start.wait();
        let watermark = store.snapshot_ts();
        store.begin(g);
        in_gc.store(true, Ordering::SeqCst);
        store.gc(g, watermark).expect("gc pass");
        in_gc.store(false, Ordering::SeqCst);
        store.commit(g).expect("commit the gc pass");
        checkpoint_retrying(&store);
        end.wait();
        // Quiescent: every writer is parked at the next round's start. One more checkpoint now, with
        // no writer open, reclaims whatever the in-round checkpoint could not (an open writer's first
        // record floors reclamation), so the heap sampled below is the store's retained state rather
        // than the log a writer happened to be holding at the in-round checkpoint.
        checkpoint_retrying(&store);
        samples.push(Sample {
            active: store.active_transaction_count(),
            heap: LIVE.load(Ordering::Relaxed),
        });
    }
    stop.store(true, Ordering::SeqCst);
    start.wait();
    for w in writers {
        w.join().expect("writer joins");
    }

    let total = commits.load(Ordering::SeqCst);
    let inside = inside.load(Ordering::SeqCst);
    assert!(
        total >= 1_000 && inside > 0,
        "positive control: the writers must commit a sustained load ({total}) and some of it must \
         land inside a GC pass ({inside}), or this is the single-threaded test again"
    );

    for (pass, s) in samples.iter().enumerate().skip(WARMUP) {
        assert!(
            s.active as u64 <= WRITERS,
            "pass {pass}: the Active Transaction Table holds {} entries with every writer parked \
             ({s:?})",
            s.active
        );
    }

    // The heap: the mean of the last third against the mean of the third after the warm-up. A leak
    // proportional to the commit count shows as a steadily rising line; a plateau as noise around a
    // level. The allowance (2 % + 128 KiB) absorbs allocator noise, not a per-commit term: measured
    // across repeated release runs the late-minus-early drift is within ±1 B per commit, where a
    // retained log costs hundreds.
    let judged = &samples[WARMUP..];
    let third = judged.len() / 3;
    let mean = |xs: &[Sample]| xs.iter().map(|s| s.heap as f64).sum::<f64>() / xs.len() as f64;
    let early = mean(&judged[..third]);
    let late = mean(&judged[judged.len() - third..]);
    let per_commit_growth = (late - early) / total as f64;
    eprintln!(
        "transaction tables plateau: {total} commits ({inside} inside a pass); heap early {:.0} B, \
         late {:.0} B ({per_commit_growth:+.2} B/commit); last sample {:?}",
        early,
        late,
        samples.last().expect("samples")
    );
    assert!(
        late <= early * 1.02 + 131_072.0,
        "the live heap keeps growing under a bounded live graph: {early:.0} B -> {late:.0} B over \
         {total} commits ({per_commit_growth:+.2} B/commit)"
    );
}
