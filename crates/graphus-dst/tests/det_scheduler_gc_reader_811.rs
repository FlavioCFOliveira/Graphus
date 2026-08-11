//! **The `rmp` #811 severance window, reproduced deterministically from a seed** (`rmp` #973).
//!
//! # What this is
//!
//! `graphus-storage`'s own `offthread_reader_never_loses_live_property_across_gc_811` drives the same
//! two real threads, but it is **probabilistic**: it hammers 20 000 GC cycles and hopes the OS
//! scheduler puts the reader inside the window at least once. Nothing in it can say *whether* the
//! window was entered, and nothing in it can put the reader there again on demand.
//!
//! This suite does. Every thread runs under the deterministic scheduler
//! ([`graphus_dst::detsched`]), so the interleaving is a pure function of the seed, and the scenario
//! is small enough (tens of cycles, not tens of thousands) that the whole run is replayable byte for
//! byte.
//!
//! # The window
//!
//! The owner's property chain is `B(tombstone) → A(live)`. The reader
//! (`StoreReadView::superset_scan_node_properties`, the production off-thread read path — the view is
//! `Send + Sync`) walks it with `read_prop(cur)` → `cur = p.next_prop`, one
//! `ConcurrentBufferPool::with_page_fetched` per link. The severance window is *between two of those
//! reads*: the reader has captured `cur = B` and not yet read it.
//!
//! The scheduler puts it exactly there. The reader yields inside `with_page_fetched` with `cur = B`
//! captured; the seed picks the engine thread; the engine runs GC phase D
//! (`sweep_property_chains` → `gc_property_chain` → `write_prop`), which rewrites B in place; the
//! token comes back and the reader reads B. **Pre-fix** that record's `next_prop` was zeroed, the
//! walk terminated, and the live, committed, snapshot-visible property A vanished from the result.
//! **Post-fix** `next_prop` is preserved and the walk threads through to A.
//!
//! # What each test asserts
//!
//! | Test | Acceptance criterion |
//! |---|---|
//! | [`same_seed_replays_the_engine_byte_identically`] | 1 — byte-identical history across repeated runs |
//! | [`different_seeds_produce_different_engine_interleavings`] | 2 — the scheduler explores rather than collapses |
//! | [`the_811_window_is_reproducible_from_a_seed`] | 4 — a known concurrency defect is now seed-reproducible |
//!
//! Criteria 1 and 2 are asserted **over this scenario**, not over a synthetic self-test of the
//! scheduler. A self-test of the mechanism (`graphus_dst::detsched`'s own unit tests) is a legitimate
//! unit test *of the mechanism*, but it cannot stand in for these criteria: it would let the task
//! pass without the engine ever having been scheduled, which is precisely the shape of vacuity this
//! project has caught more than once.
//!
//! # Running it
//!
//! ```text
//! cargo test -p graphus-dst --features det-sched --test det_scheduler_gc_reader_811
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use graphus_core::TxnId;
use graphus_core::sched::YieldSite;
use graphus_dst::detsched::{DetSchedConfig, SchedHistory, run_scheduled};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

/// GC cycles the engine thread runs. Each one re-tombstones B, GC-reclaims it (the severance
/// window), and re-adds B reusing the freed slot.
///
/// Deliberately small. The probabilistic test needs 20 000 because it is waiting for luck; a
/// scheduled run enters the window by construction, so the count only has to be large enough for the
/// seeds to differ in *where* they enter it.
const CYCLES: u64 = 24;

/// What one scheduled run of the scenario observed.
#[derive(Debug)]
struct Run {
    /// Scans in which the live property A was missing, or the walk errored. Must be zero.
    losses: u64,
    /// Scans the reader completed — the reader's own non-vacuity number.
    reads: u64,
    history: SchedHistory,
}

/// Runs the whole scenario — store, engine thread, off-thread reader — under a scheduler seeded with
/// `seed`.
fn scenario(seed: u64) -> Run {
    // Switch at EVERY yield point: the window this scenario targets is a handful of record reads
    // wide, so amortised sampling would step over it. The lower default is for long soaks.
    let cfg = DetSchedConfig::exhaustive(seed);
    let ((losses, reads), history) = run_scheduled(cfg, || {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        // 64 frames — the same small pool the storage-crate reproducer uses, so eviction is live and
        // the victim-selection path is genuinely exercised rather than sitting idle behind a pool
        // larger than the working set.
        let store = RecordStore::create(device, wal, 64, 1).expect("create store");

        let ka = store
            .intern_token(Namespace::PropKey, "a")
            .expect("intern a");
        let kb = store
            .intern_token(Namespace::PropKey, "b")
            .expect("intern b");

        // Owner with the live property A, then the head property B, both committed. The read view is
        // captured AFTER both exist, so its snapshot high-water covers them; the churn below reuses
        // B's freed slot, so no new property page ever appears above that snapshot.
        let t0 = TxnId(1);
        store.begin(t0);
        let (node, _) = store.create_node(t0).expect("create node");
        let a = store
            .add_node_property(t0, node, ka, 1, 0xAA)
            .expect("add a");
        let _b = store
            .add_node_property(t0, node, kb, 1, 0xBB)
            .expect("add b");
        store.commit(t0).expect("commit seed txn");

        let view = store.read_view();
        let stop = Arc::new(AtomicBool::new(false));
        let losses = Arc::new(AtomicU64::new(0));
        let reads = Arc::new(AtomicU64::new(0));

        let reader = {
            let stop = Arc::clone(&stop);
            let losses = Arc::clone(&losses);
            let reads = Arc::clone(&reads);
            graphus_core::sched::spawn("reader", move || {
                while !stop.load(Ordering::Relaxed) {
                    match view.superset_scan_node_properties(node) {
                        // A is NEVER deleted, so it must be present on every scan: only a severed
                        // walk can drop it.
                        Ok(props) => {
                            if !props
                                .cells_ignoring_history()
                                .iter()
                                .any(|(pid, _)| *pid == a)
                            {
                                losses.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        // A live-chain walk must not error either — a torn pointer surfaces here.
                        Err(_) => {
                            losses.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    reads.fetch_add(1, Ordering::Relaxed);
                }
            })
        };

        let mut txn = 10u64;
        for _ in 0..CYCLES {
            store.begin(TxnId(txn));
            store
                .remove_node_property_value(TxnId(txn), node, kb)
                .expect("remove b");
            store.commit(TxnId(txn)).expect("commit remove");
            txn += 1;

            let watermark = store.snapshot_ts();
            store.begin(TxnId(txn));
            store.gc(TxnId(txn), watermark).expect("gc pass");
            store.commit(TxnId(txn)).expect("commit gc");
            txn += 1;

            store.begin(TxnId(txn));
            store
                .add_node_property(TxnId(txn), node, kb, 1, 0xBB)
                .expect("re-add b");
            store.commit(TxnId(txn)).expect("commit re-add");
            txn += 1;
        }

        stop.store(true, Ordering::Relaxed);
        reader.join().expect("reader thread joined");
        (
            losses.load(Ordering::Relaxed),
            reads.load(Ordering::Relaxed),
        )
    });
    Run {
        losses,
        reads,
        history,
    }
}

/// The thread that ran GC (the engine thread), taken from the history rather than assumed.
fn writer_thread(history: &SchedHistory) -> u32 {
    history
        .decode()
        .into_iter()
        .find(|(_, _, site, _, _)| *site == YieldSite::GcPhaseD.code())
        .map(|(_, thread, _, _, _)| thread)
        .expect("the engine thread must have reached GC phase D")
}

/// Whether the engine's GC property sweep ran **inside** the reader's stream of record reads — the
/// exact shape of the `rmp` #811 window.
///
/// This is the teeth of the whole suite. `losses == 0` is trivially true in a run where the reader
/// and the writer never overlapped, so the assertion is worth nothing without proof that a GC pass
/// landed *between* two of the reader's `with_page_fetched` visits.
fn gc_ran_inside_a_reader_read_stream(history: &SchedHistory) -> bool {
    let steps = history.decode();
    let writer = writer_thread(history);
    let fetched = YieldSite::FrameReadFetched.code();
    let phase_d = YieldSite::GcPhaseD.code();

    let mut reader_read_before = false;
    for (i, (_, thread, site, _, _)) in steps.iter().enumerate() {
        if *thread != writer && *site == fetched {
            reader_read_before = true;
            continue;
        }
        // A property sweep starting with the reader already mid-walk: now require the reader to come
        // back and keep reading after it.
        if *thread == writer && *site == phase_d && reader_read_before {
            return steps[i + 1..]
                .iter()
                .any(|(_, t, s, _, _)| *t != writer && *s == fetched);
        }
    }
    false
}

/// **Acceptance criterion 1** — the same seed replays the engine byte for byte.
///
/// Asserted over the real two-thread engine scenario, and compared on the raw fixed-width history
/// records rather than on a digest, so a difference is located, not merely detected.
#[test]
fn same_seed_replays_the_engine_byte_identically() {
    let first = scenario(0x811_0973);
    let second = scenario(0x811_0973);

    assert_eq!(
        first.history.bytes.len(),
        second.history.bytes.len(),
        "the same seed produced histories of different length ({} vs {} steps)",
        first.history.steps,
        second.history.steps
    );
    if first.history.bytes != second.history.bytes {
        let a = first.history.decode();
        let b = second.history.decode();
        let at = a
            .iter()
            .zip(&b)
            .position(|(x, y)| x != y)
            .expect("lengths are equal, so a difference must have an index");
        panic!(
            "the same seed diverged at step {at}: {:?} vs {:?}",
            a[at], b[at]
        );
    }
    assert_eq!(first.history.hash, second.history.hash);

    // Non-vacuity: a history that never switched, or that only ever saw one thread, would be
    // perfectly deterministic and perfectly useless.
    assert!(
        first.history.switches >= 100,
        "only {} context switches — the run barely interleaved",
        first.history.switches
    );
    assert_eq!(
        first.history.threads, 2,
        "the history must contain BOTH the engine thread and the off-thread reader"
    );
    assert!(first.reads > 0, "the reader never completed a scan");
}

/// **Acceptance criterion 2** — different seeds produce different interleavings.
///
/// A **fixed** set of constant seeds, asserted for full distinctness. That makes the test either
/// always-pass or always-fail: there is no sampling, so there is nothing to be flaky about.
#[test]
fn different_seeds_produce_different_engine_interleavings() {
    const SEEDS: [u64; 8] = [1, 7, 42, 1234, 0xDEAD, 0xBEEF, 0x811, 0x973];

    let runs: Vec<Run> = SEEDS.iter().map(|s| scenario(*s)).collect();
    let mut hashes: Vec<u64> = runs.iter().map(|r| r.history.hash).collect();
    hashes.sort_unstable();
    hashes.dedup();
    assert_eq!(
        hashes.len(),
        SEEDS.len(),
        "different seeds collapsed onto the same interleaving — the scheduler is not exploring"
    );

    // Every one of them must be a genuinely interleaved run, not a degenerate one that happens to
    // hash differently.
    for (seed, run) in SEEDS.iter().zip(&runs) {
        assert_eq!(
            run.history.threads, 2,
            "seed {seed:#x}: only {} thread(s) in the history",
            run.history.threads
        );
        assert!(
            run.history.switches >= 100,
            "seed {seed:#x}: only {} context switches",
            run.history.switches
        );
    }
}

/// **Acceptance criterion 4** — the `rmp` #811 defect class is now reproducible deterministically
/// from a seed.
///
/// For every seed: the GC property sweep provably ran *inside* the reader's chain walk (the teeth),
/// and the live property A was never lost (the invariant).
#[test]
fn the_811_window_is_reproducible_from_a_seed() {
    const SEEDS: [u64; 6] = [3, 11, 0x811, 0x973, 20_260_805, 0xC0FFEE];

    for seed in SEEDS {
        let run = scenario(seed);

        assert!(
            run.reads > 0,
            "seed {seed:#x}: the reader never ran concurrently with the churn"
        );
        assert!(
            run.history.count_site(YieldSite::GcPhaseD) > 0,
            "seed {seed:#x}: the GC property sweep never ran, so the window was never opened"
        );
        assert!(
            gc_ran_inside_a_reader_read_stream(&run.history),
            "seed {seed:#x}: the GC property sweep never landed between two of the reader's record \
             reads. `losses == 0` would then be vacuous — the reader and the writer simply never \
             overlapped. ({} steps, {} switches)",
            run.history.steps,
            run.history.switches
        );

        assert_eq!(
            run.losses, 0,
            "seed {seed:#x}: `rmp` #811/#821 — the off-thread reader lost the live property A while \
             GC reclaimed the tombstone above it, over {} scans. Replay this exact interleaving with \
             seed {seed:#x}.",
            run.reads
        );
    }
}

/// The scheduler must not have silently disarmed itself: the engine's hottest record-read latch and
/// its release must both appear, and the run must have visited the storage-layer sites this task
/// installed.
///
/// Without this, every assertion above could hold in a run where the seam compiled to nothing on the
/// paths that matter.
#[test]
fn the_installed_yield_points_are_actually_reached() {
    let run = scenario(0x973);
    let h = &run.history;

    for site in [
        YieldSite::FrameReadFetched,
        YieldSite::FrameLatchRelease,
        YieldSite::FrameWriteWithPageMutLsn,
        YieldSite::CommitPublishSlot,
        YieldSite::CommitRegistryRecord,
        YieldSite::CommitSettle,
        YieldSite::GcPhaseA,
        YieldSite::GcPhaseD,
        YieldSite::GcPhaseE,
        YieldSite::FreeListPush,
        YieldSite::ThreadSpawn,
        YieldSite::ThreadStart,
        YieldSite::ThreadExit,
        YieldSite::ThreadJoin,
    ] {
        assert!(
            h.count_site(site) > 0,
            "{site:?} was never reached: the yield point is installed but the scenario does not \
             exercise it, so nothing in this suite proves it works"
        );
    }
}
