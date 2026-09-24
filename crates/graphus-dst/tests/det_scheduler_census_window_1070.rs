//! **`rmp` #1070, audit findings A and B — a writer alive across every GC pass loses no committed
//! row, and no settle overwrites a writer's stamp.**
//!
//! # The census window (finding A)
//!
//! Since `rmp` #1069 a `commit.store` slot is retired by a reference census: a GC pass proves that no
//! live delta, no in-use MVCC header and no unresolved owner names the slot, clears its `in_use` bit
//! and parks it for recycling. The census reads the store in several walks — the header walk, the
//! undo-store scan, and (before the fix) a late sample of the open transactions — and none of them
//! is atomic against writers. A writer that began after the undo snapshot and committed before the
//! open-set sample was seen by nothing: its slot was retired while its committed node's `created_ts`
//! still named it, the node read as never created, and the id went back into circulation to be
//! handed to an unrelated transaction.
//!
//! The fix samples, BEFORE the header walk, everything that can name an owner the walk cannot prove
//! resolved — the allocator's high-water and free list, the open slots, a journal of slot
//! registrations, and the allocations still in flight (see `RecordStore::gc_sweep_undo_orphans`).
//! [`a_writer_alive_across_every_gc_pass_loses_no_committed_row_1070`] drives the only shape that
//! reaches the window: one writer that commits continuously — and aborts every seventh transaction —
//! while the main thread runs full GC pass after full GC pass, under a scheduler that may switch at
//! every yield point. Because the debug assertions are on, the same run also checks finding B: the
//! prune set is sampled before the header walk, so no writer that committed behind the walk is
//! pruned with its headers unsettled (`RecordStore::debug_assert_prune_precondition` fires if one
//! is).
//!
//! # The settle race
//!
//! The settle read a header word in one step and rewrote it in another, so a writer landing between
//! the two had its fresh in-flight stamp overwritten by the previous writer's committed one: the cell
//! claimed an older installer for a newer value. [`a_settle_never_overwrites_a_concurrent_writers_stamp_1070`]
//! reaches it with a writer that overwrites existing cells in place while the main thread runs
//! settle-only passes (`gc_freeze_only`), which walk every header but reclaim nothing.
//!
//! # Non-vacuity
//!
//! * Each sweep asserts that at least one writer commit landed INSIDE a GC pass — otherwise the
//!   scheduler never entered the window and the oracle proves nothing.
//! * **What this sweep does, and does NOT, catch.** It catches the defect as it shipped: against the
//!   pre-fix store (`ed88981`, no window at all) the census sweep loses committed rows on 40 of 40
//!   seeds. Its own oracle does NOT catch the removal of any single one of the four window facts
//!   (`RecordStore::gc_sweep_undo_orphans`) from the fixed store: each such inverse edit leaves its
//!   assertions green (facts 2–4 across 400 seeds; a fact-1 removal is noticed only by a debug-build
//!   cross-check against the in-memory commit table, which `rmp` #1071 removes), because the scheduler's yield points almost never put
//!   a writer's slot allocation, its registration and its first reference on the precise sides of
//!   the window that one fact alone guards. Each fact is instead pinned by a single-threaded unit
//!   test in `graphus-storage`'s `store.rs` that places the writer in that window by hand, and each
//!   is red when only its own fact is removed: `census_window_excludes_a_slot_popped_after_the_sample_1070`
//!   (fact 1), `census_window_excludes_a_writer_registered_before_the_sample_1070` (fact 2),
//!   `census_window_excludes_a_slot_registered_after_the_fold_1070` (fact 3) and
//!   `census_window_writes_no_slot_an_allocation_is_still_claiming_1070` (fact 4).
//! * **The settle race** is caught here: replace the compare-and-set `settle_header_word` in
//!   `RecordStore::settle_and_census_headers` with the unconditional `patch_header_word`, and the
//!   settle sweep fails with cells claiming an older writer's commit (6 of 40 seeds).
//!
//! # Running it
//!
//! An installed scheduler is process-global, so the run must be filtered to this target:
//!
//! ```text
//! cargo test --profile gate -p graphus-dst --features det-sched --test det_scheduler_census_window_1070
//! ```

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use graphus_core::{HeaderStamp, Timestamp, TxnId, Value};
use graphus_dst::detsched::{DetSchedConfig, run_scheduled};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore, StoreKind};
use graphus_txn::{CommitOracle, Snapshot, is_visible_via};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// Seeds swept per property. The pre-fix store loses rows on every one of them, so the margin is for
/// the fixed store: forty independent schedules through a window that opens on every pass.
const SEEDS: u64 = 40;

/// GC passes the main thread runs while the writer is alive.
const PASSES: u64 = 6;

/// Nodes committed before the writer starts.
const SEED_NODES: usize = 12;

/// Every `ABORT_EVERY`-th writer transaction of the census sweep rolls back instead of committing.
const ABORT_EVERY: u64 = 7;

/// Upper bound on writer transactions, so a schedule that starves the GC thread still terminates.
const MAX_WRITES: u64 = 3_000;

/// What one scheduled run produced.
#[derive(Debug, Default, PartialEq, Eq)]
struct Run {
    /// Transactions the writer committed.
    committed: usize,
    /// Writer commits that returned while the main thread was inside a GC pass — the window.
    commits_inside_gc: usize,
    /// Oracle failures, each naming the row or cell and what was wrong with it.
    failures: Vec<String>,
    /// What the consistency checker found.
    violations: Vec<String>,
}

/// A fresh in-memory store with `SEED_NODES` committed nodes, each carrying property `v = 0`.
fn seeded_store() -> (Arc<Store>, u32, Vec<u64>, Timestamp) {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store = Arc::new(RecordStore::create(device, wal, 64, 1).expect("create store"));
    // Interning takes the catalogue latch, which the scheduler does not mediate; done on the root
    // thread so the run's contention is only where the scenario means it to be.
    let key = store
        .intern_token(Namespace::PropKey, "v")
        .expect("intern the property key");
    let setup = TxnId(1);
    store.begin(setup);
    let seeds: Vec<u64> = (0..SEED_NODES)
        .map(|_| {
            let (n, _) = store.create_node(setup).expect("seed node");
            store
                .set_node_property_value(setup, n, key, &Value::Integer(0))
                .expect("seed property");
            n
        })
        .collect();
    let seed_ts = store.commit(setup).expect("commit the seed");
    (store, key, seeds, seed_ts)
}

/// Runs `PASSES` GC passes on the calling (root) thread, flagging `in_gc` around each so the writer can
/// count the commits that landed inside one.
fn run_passes(store: &Store, in_gc: &AtomicBool, settle_only: bool) {
    for pass in 0..PASSES {
        let g = TxnId(100_000 + pass);
        let watermark = store.snapshot_ts();
        store.begin(g);
        in_gc.store(true, Ordering::SeqCst);
        if settle_only {
            store
                .gc_freeze_only(g, watermark)
                .expect("settle-only pass");
        } else {
            store.gc(g, watermark).expect("gc pass");
        }
        in_gc.store(false, Ordering::SeqCst);
        store.commit(g).expect("commit the gc pass");
    }
}

/// The consistency checker's findings, as text.
fn checker(store: &Store) -> Vec<String> {
    graphus_storage::check::check_store(store, &[])
        .expect("consistency pass")
        .violations
        .iter()
        .map(|v| format!("{v:?}"))
        .collect()
}

/// **Finding A.** A writer creates nodes — and aborts every seventh transaction — while full GC
/// passes run.
fn census_scenario(seed: u64) -> Run {
    let (run, _history) = run_scheduled(DetSchedConfig::exhaustive(seed), || {
        let (store, key, _seeds, _) = seeded_store();
        let committed: Arc<Mutex<Vec<(u64, TxnId)>>> = Arc::new(Mutex::new(Vec::new()));
        let in_gc = Arc::new(AtomicBool::new(false));
        let inside = Arc::new(AtomicUsize::new(0));
        let done = Arc::new(AtomicBool::new(false));
        let writer = {
            let (store, committed) = (Arc::clone(&store), Arc::clone(&committed));
            let (in_gc, inside, done) =
                (Arc::clone(&in_gc), Arc::clone(&inside), Arc::clone(&done));
            graphus_core::sched::spawn("writer", move || {
                let mut i = 0u64;
                while !done.load(Ordering::SeqCst) && i < MAX_WRITES {
                    i += 1;
                    let t = TxnId(1_000 + i);
                    store.begin(t);
                    let (n, _) = store.create_node(t).expect("create");
                    store
                        .set_node_property_value(t, n, key, &Value::Integer(1))
                        .expect("the new node's property");
                    if i % ABORT_EVERY == 0 {
                        store.rollback(t).expect("rollback");
                        continue;
                    }
                    store.commit(t).expect("commit");
                    if in_gc.load(Ordering::SeqCst) {
                        inside.fetch_add(1, Ordering::SeqCst);
                    }
                    committed.lock().expect("committed list").push((n, t));
                }
            })
        };
        run_passes(&store, &in_gc, false);
        done.store(true, Ordering::SeqCst);
        writer.join().expect("the writer joins");

        let reader = Snapshot::new(TxnId(9_999_999), store.snapshot_ts());
        let nodes = committed.lock().expect("committed list").clone();
        let mut run = Run {
            committed: nodes.len(),
            commits_inside_gc: inside.load(Ordering::SeqCst),
            ..Run::default()
        };
        for &(n, t) in &nodes {
            let m = store
                .read_mvcc_for_test(StoreKind::Node, n)
                .expect("read the node's header");
            let visible = m.in_use()
                && is_visible_via(&*store, reader, m.created_ts, m.expired_ts)
                    .expect("resolve the node's header");
            if !visible {
                run.failures.push(format!(
                    "node {n} committed by {t:?} is invisible (created_ts {:#x})",
                    m.created_ts
                ));
                continue;
            }
            // A slot the census recycled would now name a stranger — or nothing.
            if let Some(slot_id) = HeaderStamp::from_raw(m.created_ts).slot_id() {
                match store.commit_slot(slot_id).expect("read the named slot") {
                    Some(s) if s.in_use() && s.txn_id == t.0 => {}
                    other => run.failures.push(format!(
                        "node {n} committed by {t:?} names slot {slot_id}, which now holds {other:?}"
                    )),
                }
            }
        }
        run.violations = checker(&store);
        run
    });
    run
}

/// **The settle race.** A writer overwrites the seed nodes' property in place while settle-only
/// passes run.
fn settle_scenario(seed: u64) -> Run {
    let (run, _history) = run_scheduled(DetSchedConfig::exhaustive(seed), || {
        let (store, key, seeds, seed_ts) = seeded_store();
        // Per seed node: the value and commit timestamp of the last committed overwrite.
        let last: Arc<Mutex<Vec<(i64, Timestamp)>>> =
            Arc::new(Mutex::new(vec![(0, seed_ts); SEED_NODES]));
        let in_gc = Arc::new(AtomicBool::new(false));
        let inside = Arc::new(AtomicUsize::new(0));
        let committed = Arc::new(AtomicUsize::new(0));
        let done = Arc::new(AtomicBool::new(false));
        let writer = {
            let (store, last, seeds) = (Arc::clone(&store), Arc::clone(&last), seeds.clone());
            let (in_gc, inside, done) =
                (Arc::clone(&in_gc), Arc::clone(&inside), Arc::clone(&done));
            let committed = Arc::clone(&committed);
            graphus_core::sched::spawn("writer", move || {
                let mut i = 0u64;
                while !done.load(Ordering::SeqCst) && i < MAX_WRITES {
                    i += 1;
                    let t = TxnId(1_000 + i);
                    let value = i64::try_from(i).expect("small");
                    let target = usize::try_from(i).expect("small") % SEED_NODES;
                    store.begin(t);
                    store
                        .set_node_property_value(t, seeds[target], key, &Value::Integer(value))
                        .expect("in-place overwrite");
                    let ts = store.commit(t).expect("commit");
                    if in_gc.load(Ordering::SeqCst) {
                        inside.fetch_add(1, Ordering::SeqCst);
                    }
                    committed.fetch_add(1, Ordering::SeqCst);
                    last.lock().expect("last-overwrite table")[target] = (value, ts);
                }
            })
        };
        run_passes(&store, &in_gc, true);
        done.store(true, Ordering::SeqCst);
        writer.join().expect("the writer joins");

        let reader = Snapshot::new(TxnId(9_999_999), store.snapshot_ts());
        let last = last.lock().expect("last-overwrite table").clone();
        let mut run = Run {
            committed: committed.load(Ordering::SeqCst),
            commits_inside_gc: inside.load(Ordering::SeqCst),
            ..Run::default()
        };
        for (i, &n) in seeds.iter().enumerate() {
            let (value, ts) = last[i];
            let decided = store
                .decision_scan_node_properties(n, reader)
                .expect("read the seed node's property");
            let seen = decided.visible_version(key).map(|pv| {
                store
                    .decode_property_value(pv.type_tag, pv.value_inline)
                    .expect("decode")
            });
            if seen != Some(Value::Integer(value)) {
                run.failures.push(format!(
                    "seed node {n} reads {seen:?}, last committed overwrite was {value}"
                ));
            }
            let chain = store
                .superset_scan_node_properties(n)
                .expect("read the seed node's cells");
            for &(pid, cell) in chain.cells_ignoring_history() {
                if cell.key != key {
                    continue;
                }
                let stamped = store
                    .resolve_commit_ts(cell.mvcc.created_ts)
                    .expect("resolve the cell's stamp");
                if stamped != Some(ts) {
                    run.failures.push(format!(
                        "seed node {n}'s cell {pid} resolves to {stamped:?}, but its value was \
                         installed by the overwrite committed at {ts:?}"
                    ));
                }
            }
        }
        run.violations = checker(&store);
        run
    });
    run
}

/// Runs `scenario` over every seed and asserts the sweep entered its window and broke nothing.
fn sweep(what: &str, scenario: fn(u64) -> Run) {
    let mut broken = Vec::new();
    let (mut inside, mut committed) = (0usize, 0usize);
    for seed in 0..SEEDS {
        let run = scenario(seed);
        inside += run.commits_inside_gc;
        committed += run.committed;
        if !run.failures.is_empty() || !run.violations.is_empty() {
            broken.push((seed, run));
        }
    }
    assert!(
        inside > 0,
        "non-vacuity ({what}): no writer commit landed inside a GC pass in {SEEDS} seeds \
         ({committed} commits in total), so the window was never entered and this sweep proves \
         nothing"
    );
    assert!(
        broken.is_empty(),
        "{what}: {} of {SEEDS} seeds failed (first: seed {} — {:?}; checker {:?})",
        broken.len(),
        broken[0].0,
        broken[0].1.failures.iter().take(3).collect::<Vec<_>>(),
        broken[0].1.violations.iter().take(3).collect::<Vec<_>>(),
    );
}

/// **Finding A.** Every node the writer committed stays visible and keeps its own slot, and the
/// checker finds nothing — on every seed.
#[test]
fn a_writer_alive_across_every_gc_pass_loses_no_committed_row_1070() {
    sweep("census window", census_scenario);
}

/// **The settle race.** Every overwritten cell reads its last committed value AND is stamped with
/// that overwrite's commit — never an older writer's — on every seed.
#[test]
fn a_settle_never_overwrites_a_concurrent_writers_stamp_1070() {
    sweep("settle compare-and-set", settle_scenario);
}

/// The same seed replays byte-for-byte, so a failing seed from either sweep is a reproduction, not
/// an anecdote.
#[test]
fn the_same_seed_replays_the_run_identically() {
    let first = run_scheduled(DetSchedConfig::exhaustive(7), census_scenario_body).1;
    let second = run_scheduled(DetSchedConfig::exhaustive(7), census_scenario_body).1;
    assert_eq!(
        first.decode(),
        second.decode(),
        "two runs of seed 7 took different schedules"
    );
}

/// The census scenario's body without its oracle, for the replay test: the history compared is the
/// scheduler's alone.
fn census_scenario_body() {
    let (store, key, _seeds, _) = seeded_store();
    let done = Arc::new(AtomicBool::new(false));
    let writer = {
        let (store, done) = (Arc::clone(&store), Arc::clone(&done));
        graphus_core::sched::spawn("writer", move || {
            let mut i = 0u64;
            while !done.load(Ordering::SeqCst) && i < 200 {
                i += 1;
                let t = TxnId(1_000 + i);
                store.begin(t);
                let (n, _) = store.create_node(t).expect("create");
                store
                    .set_node_property_value(t, n, key, &Value::Integer(1))
                    .expect("property");
                store.commit(t).expect("commit");
            }
        })
    };
    run_passes(&store, &AtomicBool::new(false), false);
    done.store(true, Ordering::SeqCst);
    writer.join().expect("the writer joins");
}
