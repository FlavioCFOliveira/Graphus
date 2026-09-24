//! **`rmp` #1092 — GC phase F never frees a delta a live writer has just prepended.**
//!
//! # The defect
//!
//! Phase F of a GC pass ([`RecordStore::gc`]) reclaims an entity's undo chain whole, once every delta
//! on it is dead. It used to decide that on one read of the chain and then act on a SECOND read: the
//! reclaiming call re-walked the chain, cleared the entity's `undo_ptr` with an unconditional write and
//! freed every delta it found. A GC pass is not a non-yielding call — writers run beside it — so a
//! writer that prepended onto the entity between the two reads had its in-flight delta freed with the
//! dead ones and unlinked from the chain. Observed: `DeltaCountMismatch { recorded: 1, actual: 0 }` on
//! the slot of a writer that went on to commit, whose delta was already gone.
//!
//! The fix acts on the chain that was checked: the head is cleared by a compare-and-set against the
//! head observed when the chain was judged dead, and only that chain's deltas are freed. A writer that
//! prepended in between makes the compare fail, and the chain is left for a later pass.
//!
//! # The sibling path in the same pass
//!
//! The first full pass after `open` also runs the undo area's orphan sweep, which frees `!in_use`
//! deltas no chain reaches — what a crash strands. Phase F lists a delta slot; a writer pops it and
//! has not yet written its new delta; the sweep, later in the same pass, finds the slot `!in_use`
//! (the stale body of its previous life), off the free list and named by nothing, and lists it
//! AGAIN; a second writer pops it too, and two transactions share one delta. The sweep now only
//! considers ids no writer can be holding — see `Maintenance::open_allocator_sample`.
//! [`first_pass_after_open_never_frees_a_delta_a_writer_holds_1092`] reaches it with a writer that
//! creates relationships (each one links fresh deltas) beside the first full pass of a reopened store.
//!
//! # The scenario
//!
//! One writer overwrites the property of a set of committed nodes in place, one node per transaction,
//! for as long as the main thread keeps running FULL GC passes. Every overwrite prepends a delta onto
//! a chain whose older deltas are committed below the watermark — exactly a chain phase F judges dead
//! — so every pass offers the window, and the deterministic scheduler may switch at every yield point.
//!
//! # The oracle
//!
//! * every seed node reads the value of its last committed overwrite, stamped with that overwrite's
//!   commit;
//! * the consistency checker finds nothing — in particular no commit slot whose recorded delta count
//!   exceeds the deltas that still name it, which is what a freed in-flight delta leaves behind.
//!
//! # Non-vacuity
//!
//! Each sweep asserts that writer commits landed inside GC passes. Against the pre-fix store the
//! first sweep fails (inverse edit: `free_undo_chain` re-reading the chain and clearing the head
//! unconditionally — 23 of 400 seeds), and the second fails when the orphan sweep's candidate filter
//! is dropped; both are green with the fix.
//!
//! # Running it
//!
//! An installed scheduler is process-global, so the run must be filtered to this target:
//!
//! ```text
//! cargo test --profile gate -p graphus-dst --features det-sched --test det_scheduler_phase_f_toctou_1092
//! ```

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use graphus_core::{PageId, Timestamp, TxnId, Value};
use graphus_dst::detsched::{DetSchedConfig, run_scheduled};
use graphus_io::{BlockDevice, MemBlockDevice};
use graphus_storage::{Namespace, RecordStore};
use graphus_txn::{CommitOracle, Snapshot};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// Seeds swept. The acceptance criterion of `rmp` #1092 is "no in-flight delta freed across 400
/// seeds"; the pre-fix store failed on roughly one seed in forty.
const SEEDS: u64 = 400;

/// Full GC passes the main thread runs while the writer is alive.
const PASSES: u64 = 6;

/// Nodes committed before the writer starts; the writer overwrites them round-robin.
const SEED_NODES: usize = 12;

/// Upper bound on writer transactions, so a schedule that starves the GC thread still terminates.
const MAX_WRITES: u64 = 3_000;

/// What one scheduled run produced.
#[derive(Debug, Default, PartialEq, Eq)]
struct Run {
    /// Transactions the writer committed.
    committed: usize,
    /// Writer commits that returned while the main thread was inside a GC pass — the window.
    commits_inside_gc: usize,
    /// Oracle failures, each naming the cell and what was wrong with it.
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

/// Runs `PASSES` full GC passes on the calling (root) thread, flagging `in_gc` around each so the
/// writer can count the commits that landed inside one.
fn run_passes(store: &Store, in_gc: &AtomicBool) {
    for pass in 0..PASSES {
        let g = TxnId(100_000 + pass);
        let watermark = store.snapshot_ts();
        store.begin(g);
        in_gc.store(true, Ordering::SeqCst);
        store.gc(g, watermark).expect("gc pass");
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

/// One scheduled run: a writer overwrites the seed nodes' property in place while full GC passes run.
fn scenario(seed: u64) -> Run {
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
        run_passes(&store, &in_gc);
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

/// **`rmp` #1092.** Across 400 schedules, no writer's delta is freed by a concurrent phase F: every
/// overwrite reads back, stamped with its own commit, and the checker's delta accounting balances.
#[test]
fn phase_f_never_frees_a_delta_a_live_writer_prepended_1092() {
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
        "non-vacuity: no writer commit landed inside a GC pass in {SEEDS} seeds ({committed} \
         commits in total), so the window was never entered and this sweep proves nothing"
    );
    assert!(
        broken.is_empty(),
        "phase F freed a live writer's delta: {} of {SEEDS} seeds failed (first: seed {} — {:?}; \
         checker {:?})",
        broken.len(),
        broken[0].0,
        broken[0].1.failures.iter().take(3).collect::<Vec<_>>(),
        broken[0].1.violations.iter().take(3).collect::<Vec<_>>(),
    );
}

/// A store with two committed nodes and an edge between them, closed cleanly and reopened — so the
/// next full GC pass is the first after `open`, the one that runs the orphan sweep.
fn reopened_store() -> (Arc<Store>, u32, u64, u64) {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store = Store::create(device, wal, 64, 1).expect("create store");
    let setup = TxnId(1);
    store.begin(setup);
    let ty = store
        .intern_token(Namespace::RelType, "E")
        .expect("intern reltype");
    let (a, _) = store.create_node(setup).expect("node a");
    let (b, _) = store.create_node(setup).expect("node b");
    store.create_rel(setup, ty, a, b).expect("committed edge");
    store.commit(setup).expect("commit setup");
    store.checkpoint().expect("checkpoint");
    store.flush().expect("flush home");
    let pages = store.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    for p in &pages {
        let bytes = store.read_device_page(*p).expect("read device page");
        device.write_page(PageId(p.0), &bytes).expect("stage page");
    }
    device.sync_all().expect("persist the image");
    let log = store.with_wal(|w| w.sink().durable_bytes());
    drop(store);
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log");
    let wal = WalManager::open(sink).expect("reopen wal");
    let store = Store::open(device, wal, 64).expect("reopen");
    (Arc::new(store), ty, a, b)
}

/// One scheduled run: a writer creates edges between two committed nodes while the main thread runs
/// the first full GC pass after `open`. The shape of the certification probe that found the sibling
/// path, kept as it was: the reproduction depends on the schedule, and a change of shape moves it.
fn first_pass_scenario(seed: u64) -> Run {
    let (run, _history) = run_scheduled(DetSchedConfig::exhaustive(seed), || {
        let (store, ty, a, b) = reopened_store();
        let done = Arc::new(AtomicBool::new(false));
        let committed = Arc::new(AtomicUsize::new(0));
        let in_gc = Arc::new(AtomicBool::new(false));
        let inside = Arc::new(AtomicUsize::new(0));
        let writer = {
            let (store, done, committed) = (
                Arc::clone(&store),
                Arc::clone(&done),
                Arc::clone(&committed),
            );
            let (in_gc, inside) = (Arc::clone(&in_gc), Arc::clone(&inside));
            graphus_core::sched::spawn("writer", move || {
                let mut i = 0u64;
                while !done.load(Ordering::SeqCst) && i < 200 {
                    i += 1;
                    let t = TxnId(1_000 + i);
                    store.begin(t);
                    store.create_rel(t, ty, a, b).expect("create edge");
                    store.commit(t).expect("commit");
                    if in_gc.load(Ordering::SeqCst) {
                        inside.fetch_add(1, Ordering::SeqCst);
                    }
                    committed.fetch_add(1, Ordering::SeqCst);
                }
            })
        };
        let g = TxnId(900);
        store.begin(g);
        in_gc.store(true, Ordering::SeqCst);
        store.gc(g, store.snapshot_ts()).expect("gc pass");
        in_gc.store(false, Ordering::SeqCst);
        store.commit(g).expect("commit the gc pass");
        done.store(true, Ordering::SeqCst);
        writer.join().expect("the writer joins");

        let committed = committed.load(Ordering::SeqCst);
        let mut run = Run {
            committed,
            commits_inside_gc: inside.load(Ordering::SeqCst),
            ..Run::default()
        };
        let on_chain = store.incident_rels(a).expect("walk a's chain").len();
        if on_chain != committed + 1 {
            run.failures.push(format!(
                "node {a}'s chain holds {on_chain} edges; {} were committed",
                committed + 1
            ));
        }
        run.violations = checker(&store);
        run
    });
    run
}

/// **`rmp` #1092, the sibling path.** Across 400 schedules, the first full pass after `open` never
/// frees a delta slot a writer holds: every committed edge stays on its chain and the checker's
/// delta accounting balances.
#[test]
fn first_pass_after_open_never_frees_a_delta_a_writer_holds_1092() {
    let mut broken = Vec::new();
    let (mut inside, mut committed) = (0usize, 0usize);
    for seed in 0..SEEDS {
        let run = first_pass_scenario(seed);
        inside += run.commits_inside_gc;
        committed += run.committed;
        if !run.failures.is_empty() || !run.violations.is_empty() {
            broken.push((seed, run));
        }
    }
    assert!(
        inside > 0,
        "non-vacuity: no writer commit landed inside a GC pass in {SEEDS} seeds ({committed} \
         commits in total)"
    );
    assert!(
        broken.is_empty(),
        "a GC pass freed a delta slot a writer held: {} of {SEEDS} seeds failed (first: seed {} — \
         {:?}; checker {:?})",
        broken.len(),
        broken[0].0,
        broken[0].1.failures.iter().take(3).collect::<Vec<_>>(),
        broken[0].1.violations.iter().take(3).collect::<Vec<_>>(),
    );
}
