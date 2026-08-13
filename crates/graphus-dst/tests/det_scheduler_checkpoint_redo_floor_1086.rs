//! **`rmp` #1086 — the checkpoint claimed to be sharp, and a second worker made that false.**
//!
//! # The window
//!
//! `RecordStore::checkpoint` flushes every dirty page home and then appends a `CHECKPOINT-END`
//! record whose Dirty Page Table is **empty**. Recovery reads an empty DPT as a *sharp* checkpoint:
//! [`CheckpointSnapshot::redo_start`](graphus_wal::CheckpointSnapshot::redo_start) returns `None`,
//! so `redo_start` falls back to the checkpoint record's OWN LSN and redo skips every record below
//! it. The same LSN also floors the WAL prefix the checkpoint reclaims.
//!
//! That is sound only while no page can be left dirty carrying a change logged *below* that LSN —
//! which the flush guarantees only while nothing else is writing.
//! [`ConcurrentBufferPool::flush_all`](graphus_bufpool::ConcurrentBufferPool::flush_all) says so in
//! its own contract: a caller needing the stronger barrier "must quiesce writers", which it notes
//! the single-threaded engine did by construction. Since `rmp` #1033/#975 that premise is false —
//! `W` workers share one store, and `commit` reaches the checkpoint through `maybe_checkpoint`.
//!
//! So between the instant the flush returns and the instant the record is appended there is a window
//! in which another worker can commit **completely**: its `COMMIT` record lands below the checkpoint
//! record, and its pages are still in the buffer pool. A power loss then finds those pages missing
//! from the device and the checkpoint record telling recovery not to look for them.
//!
//! # What this suite drives
//!
//! [`WRITERS`] scheduled writers commit [`ROUNDS`] transactions each against one store while a
//! separate scheduled worker takes the redo-bounding checkpoint. `YieldSite::CheckpointRecordAppend`
//! offers the token inside the window; without it the scheduler cannot place a committer there at
//! all, because the checkpoint runs straight from the flush to the append (the same reason
//! `YieldSite::SnapshotBegin` exists for `rmp` #1056).
//!
//! **The checkpoint has to be on a different worker from the commit, and that is the measurement
//! this shape came from.** The first version of this suite set the automatic cadence to one byte so
//! that every commit checkpointed. The hazard window was entered on many seeds and NOTHING was ever
//! lost — because a commit reaches `maybe_checkpoint` immediately after its own `harden_wal`, so a
//! transaction that commits inside another checkpoint's window flushes its own pages home one step
//! later and repairs the hazard before any crash can find it. What survives that repair is a
//! checkpoint taken by a worker that is not the committer, which is exactly the shape `rmp` #1033
//! introduced and the shape the production cadence produces: checkpoints are ~64 MiB apart, so a
//! commit inside one is followed by a great deal of work before anything flushes again.
//!
//! Then a **power loss**: the device keeps only what was `fsync`ed (`MemBlockDevice::crash` discards
//! the un-synced cache), the log keeps only its durable prefix, and ARIES recovery runs over that
//! pair. Nothing is flushed first — a flush before the snapshot would hand the pool's dirty pages to
//! the device and hide the very loss this measures.
//!
//! # The oracle, and why the counters are NOT it
//!
//! The primary oracle is the **node record read back out of the recovered store**: for every commit
//! the writer acknowledged, `node()` must report an in-use record and `node_labels()` must report the
//! label that transaction wrote. That is the same durability check
//! [`graphus_dst::checker::verify`] applies, and it is physical — it reads what recovery actually put
//! on the page.
//!
//! The durable **counters** are recorded too, and they are deliberately *not* the oracle:
//! since `rmp` #1067 a commit's cardinality change is its own WAL record folded over a base, so the
//! count survives a loss of the node's own page and reports the right total for a node that is no
//! longer there. **Measured, on the code as it stood before the fix:** on all seven seeds that lost
//! records the recovered catalogue answered `total_nodes = 14`, which is the number the workload
//! predicts — a suite built on the counters would have come back green with the data gone.
//! [`the_counters_are_right_even_where_the_records_would_not_be`] keeps that half checkable; the
//! divergence itself is a recorded measurement and not something a passing build can re-derive.
//!
//! # Two windows, and the second one is the whole correction
//!
//! The fix is not "carry a floor in the record". It is "carry a floor sampled **before the flush**",
//! and this suite has to be able to tell that apart from a floor sampled after — otherwise the next
//! person to touch `checkpoint` can move one line, reopen the defect completely, and watch the build
//! stay green. So there are two windows here, each with its own yield site and its own control:
//!
//! 1. **After the flush, before the record** (`YieldSite::CheckpointRecordAppend`). A commit here
//!    logs below the checkpoint record with its pages still in the pool. This is the window the
//!    ficha describes, and an empty Dirty Page Table is what loses it —
//!    [`the_hazard_window_is_entered`].
//! 2. **Inside the flush, after its latches are released** (`YieldSite::FrameWriteFlushBatchReleased`).
//!    A commit here is missed by that flush *and* has left the WAL active table by the time the flush
//!    returns — so a floor sampled after the flush sits ABOVE its records and redo skips them, while a
//!    floor sampled before the flush cannot — [`the_in_flush_window_is_entered`].
//!
//! Both are measured by ablation rather than argued, over [`SEEDS`] seeds:
//!
//! | ablation (one line, reverted by patch) | seeds losing committed records |
//! |---|---|
//! | the record carries an empty DPT again | **14** |
//! | the sample moves to *after* `self.flush()?` | **2** (seeds 1 and 155) |
//! | none — the code as it ships | **0** |
//!
//! The second row is the one that matters most and the one that was missing: without window 2 this
//! suite passed with the sample on either side of the flush, and the central claim of the fix — that
//! the window is **empty, not merely narrow** — was argued and not measured.
//!
//! # Non-vacuity
//!
//! Asserted, never assumed:
//!
//! * every logical thread really ran and the token really moved ([`the_run_is_contended`]);
//! * the window is really **entered**: on named seeds a writer's whole commit publication — its
//!   `CommitPublishSlot` and the `CommitRegistryRecord` that follows its `COMMIT` record — falls
//!   strictly inside the segment another thread spent parked at `CheckpointRecordAppend`
//!   ([`the_hazard_window_is_entered`]). That interval is where the `COMMIT` record is appended, so
//!   a commit located there provably logged below the checkpoint record;
//! * the **in-flush** window is really entered too ([`the_in_flush_window_is_entered`]), which is
//!   what makes the placement of the sample a measurement rather than an argument;
//! * the writers' work is read back out of the LIVE store before the crash, so a run that persisted
//!   nothing cannot pass by having written nothing ([`the_live_store_holds_every_commit`]).
//!
//! # Running it
//!
//! ```text
//! cargo test -p graphus-dst --features det-sched --test det_scheduler_checkpoint_redo_floor_1086
//! ```

use std::sync::Arc;

use graphus_core::sched::YieldSite;
use graphus_core::{PageId, TxnId};
use graphus_dst::detsched::{DetSchedConfig, SchedHistory, run_scheduled};
use graphus_io::{BlockDevice, MemBlockDevice, PAGE_SIZE, Page};
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

/// Scheduled committing writer threads. Two is the control: with one writer the window cannot be
/// entered at all, because the thread inside the checkpoint is the only one that could commit.
const WRITERS: usize = 2;

/// Transactions each writer commits — one node, one label, one commit each.
///
/// Enough that the writers are still committing when the checkpointing worker takes its checkpoint,
/// which is what gives the window something to catch.
const ROUNDS: u64 = 6;

/// Buffer-pool frames, comfortably above this workload's working set: what is measured is the
/// checkpoint's redo floor, not the pool's eviction behaviour.
const POOL_PAGES: usize = 256;

/// Seeds pinned by this suite: `0..SEEDS`. A fixed range, not a sample.
const SEEDS: u64 = 256;

/// Probability, per mille, that a yield point hands the token over.
///
/// **Not** the exhaustive 1000 this workspace usually reaches for, and the number is measured rather
/// than chosen. The window needs another writer to run a WHOLE commit publication while the
/// checkpointing worker stays parked; at 1000 the scheduler re-picks between the runnable threads at
/// every one of that commit's yields, so the parked checkpointer tends to be resumed before the
/// committer is done. At 250 a thread that takes the token keeps it for a run of yields, which is
/// what lets a commit complete inside the window.
///
/// Measured on the code as it stood before the fix, at 128 seeds: **7 seeds lose committed records
/// at 250, and 3 at 1000**. Both reproduce the defect; 250 reproduces more of it, so it is what this
/// suite pins. At the [`SEEDS`] width this suite now runs, the same ablation reports **14**.
const SWITCH_PERMILLE: u32 = 250;

/// Transaction-id stride per writer, so a transaction id in a recorded history names one writer.
const WRITER_STRIDE: u64 = 1_000;

/// The transaction id writer `w` uses in round `r`.
fn txn_of(w: usize, r: u64) -> TxnId {
    TxnId((w as u64 + 1) * WRITER_STRIDE + r + 1)
}

/// What the scheduled body produced, before the history is attached.
struct Observed {
    /// `(node id, label token)` for every commit a writer ACKNOWLEDGED, in creation order.
    committed: Vec<(u64, u32)>,
    /// The labels the LIVE store reported for those nodes, before the crash.
    live_labels: Vec<Vec<u32>>,
    /// The labels the RECOVERED store reports for those nodes. The primary oracle.
    recovered_labels: Vec<Vec<u32>>,
    /// Whether the RECOVERED store reports each of those node records as in-use.
    recovered_in_use: Vec<bool>,
    /// `total_nodes` as the RECOVERED store's catalogue answers it — recorded to be compared against
    /// the record read-back, never trusted as the oracle.
    recovered_total_nodes: u64,
    /// `total_nodes` the workload's own constants predict.
    expected_total_nodes: u64,
    /// How many attempts the checkpointing worker needed. `1` is the uncontended case; more means it
    /// raced another worker's page allocation (see the checkpointer's own note).
    checkpoint_attempts: u32,
}

/// One scheduled run: what it produced, and the schedule that produced it.
struct Run {
    observed: Observed,
    history: SchedHistory,
}

impl std::ops::Deref for Run {
    type Target = Observed;

    fn deref(&self) -> &Observed {
        &self.observed
    }
}

impl Observed {
    /// The nodes an acknowledged commit created that the recovered store does not hold — an empty
    /// vector is the durability property this suite exists for.
    fn lost(&self) -> Vec<u64> {
        self.committed
            .iter()
            .enumerate()
            .filter(|&(i, &(_, label))| {
                !self.recovered_in_use[i] || !self.recovered_labels[i].contains(&label)
            })
            .map(|(_, &(node, _))| node)
            .collect()
    }
}

/// Runs [`WRITERS`] scheduled committers against one store under the schedule `seed` names, then
/// crashes it (power loss) and recovers.
fn scenario(seed: u64) -> Run {
    let cfg = DetSchedConfig {
        switch_permille: SWITCH_PERMILLE,
        ..DetSchedConfig::new(seed)
    };
    let (out, history) = run_scheduled(cfg, || {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store =
            Arc::new(RecordStore::create(device, wal, POOL_PAGES, 1).expect("create store"));
        // The automatic cadence is OFF, so the only checkpoint in this run is the one the
        // checkpointing worker takes below. With the cadence on, every committer would checkpoint
        // straight after its own commit and repair the window before the crash — see the module
        // header. The production cadence (64 MiB) never fires inside a scenario this size anyway.
        store.set_checkpoint_interval_bytes(0);

        // Interning takes the catalogue write latch, which the scheduler does not mediate; done on
        // the root thread so the run's contention is only where this scenario means it to be.
        let labels: Vec<u32> = (0..WRITERS)
            .map(|w| {
                store
                    .intern_token(Namespace::Label, &format!("L{w}"))
                    .expect("intern a label token")
            })
            .collect();

        // One committed node per label before any writer starts, so the store is not empty and a
        // page that must survive already exists.
        let seed_txn = TxnId(1);
        store.begin(seed_txn);
        for &label in &labels {
            let (node, _) = store.create_node(seed_txn).expect("create the seed node");
            store
                .add_label(seed_txn, node, label)
                .expect("label the seed");
        }
        store.commit(seed_txn).expect("commit the seed");

        // THE CHECKPOINTING WORKER. It runs `RecordStore::checkpoint` — the exact method the
        // automatic cadence calls from `maybe_checkpoint`, and the one `checkpoint_if_due` exposes
        // for the engine's group-commit path — on a worker that is not the committer.
        let checkpointer = {
            let store = Arc::clone(&store);
            graphus_core::sched::spawn("checkpointer", move || {
                // RETRIED, because a checkpoint that overlaps another worker's page ALLOCATION fails
                // — the allocator stamps a fresh page's header with an unlogged write and seeds its
                // checksum through `flush_unlogged` a moment later, and a `flush_all` that catches the
                // frame in between sees a dirty page with `page_lsn == 0` and refuses it. That is a
                // second, separate consequence of `rmp` #1033 sharing one pool between workers, and it
                // is NOT what this suite measures; production absorbs it through
                // `defer_failed_checkpoint` (`rmp` #1079) and retries on a later commit, which is
                // exactly what this loop does. `attempts` is reported so the retry can never quietly
                // become "no checkpoint was taken".
                let mut attempts = 0u32;
                loop {
                    attempts += 1;
                    match store.checkpoint() {
                        Ok(()) => return attempts,
                        Err(e) => assert!(
                            attempts < 64,
                            "the checkpoint never succeeded in {attempts} attempts: {e}"
                        ),
                    }
                }
            })
        };

        let threads: Vec<_> = (0..WRITERS)
            .map(|w| {
                let store = Arc::clone(&store);
                let label = labels[w];
                graphus_core::sched::spawn("writer", move || {
                    let mut created = Vec::with_capacity(ROUNDS as usize);
                    for r in 0..ROUNDS {
                        // Every writer's node is its own, so no round can be refused by the
                        // write-write conflict check and every round is an acknowledged commit.
                        let txn = txn_of(w, r);
                        store.begin(txn);
                        let (node, _) = store.create_node(txn).expect("create a node");
                        store.add_label(txn, node, label).expect("label the node");
                        store.commit(txn).expect("a disjoint write always commits");
                        // Pushed only AFTER `commit` returned, so this vector holds exactly the
                        // commits the store acknowledged as durable.
                        created.push((node, label));
                    }
                    created
                })
            })
            .collect();
        let committed: Vec<(u64, u32)> = threads
            .into_iter()
            .flat_map(|t| t.join().expect("a writer thread joins"))
            .collect();
        let checkpoint_attempts = checkpointer.join().expect("the checkpointer joins");

        // Read back out of the LIVE store first: a run that never persisted anything must not be
        // able to pass this suite by having written nothing.
        let live_labels: Vec<Vec<u32>> = committed
            .iter()
            .map(|&(node, _)| store.node_labels(node).expect("live node labels"))
            .collect();

        // THE CRASH — a power loss, and deliberately NOT the `flush`-first steal crash the rest of
        // the workspace uses. A flush here would write the pool's dirty pages home and hand the
        // checkpoint the barrier it does not have, hiding the defect entirely. What survives is what
        // was `fsync`ed: the durable log prefix, and the device minus its un-synced cache.
        let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
        let image: Vec<Box<Page>> = store.with_device_mut(|d| {
            d.crash();
            (0..d.page_count())
                .map(|i| {
                    let mut page: Box<Page> = Box::new([0u8; PAGE_SIZE]);
                    d.read_page(PageId(i), &mut page).expect("read device page");
                    page
                })
                .collect()
        });

        let mut device = MemBlockDevice::new(image.len() as u64);
        for (i, page) in image.iter().enumerate() {
            device
                .write_page(PageId(i as u64), page)
                .expect("stage the persisted page");
        }
        device.sync_all().expect("persist the disk image");

        let mut sink = MemLogSink::new();
        sink.append(&log);
        sink.sync().expect("sync the durable log prefix");
        let mut wal = WalManager::open(sink.clone()).expect("open wal");
        recover_device(&mut wal, &mut device).expect("ARIES recovery");
        let wal = WalManager::open(sink).expect("reopen wal");
        let reopened =
            RecordStore::open(device, wal, POOL_PAGES).expect("open the recovered store");

        let recovered_in_use: Vec<bool> = committed
            .iter()
            .map(|&(node, _)| {
                reopened
                    .node(node)
                    .map(|rec| rec.mvcc.in_use())
                    .unwrap_or(false)
            })
            .collect();
        let recovered_labels: Vec<Vec<u32>> = committed
            .iter()
            .map(|&(node, _)| reopened.node_labels(node).unwrap_or_default())
            .collect();
        let recovered_total_nodes = reopened.statistics().total_nodes();

        Observed {
            committed,
            live_labels,
            recovered_labels,
            recovered_in_use,
            recovered_total_nodes,
            // From the workload's CONSTANTS: one seeded node per label plus ROUNDS per writer.
            expected_total_nodes: WRITERS as u64 * (ROUNDS + 1),
            checkpoint_attempts,
        }
    });
    Run {
        observed: out,
        history,
    }
}

/// The step at which `thread` next resumes after yielding at `from`, i.e. the end of the segment in
/// which the code following that yield actually ran.
fn resumed_after(steps: &[(u64, u32, u16, u8, u64)], from: usize, thread: u32) -> Option<usize> {
    (from + 1..steps.len()).find(|&j| steps[j].1 == thread)
}

/// Every `[open, close)` history interval a thread spent parked at `site`.
fn windows_at(history: &SchedHistory, site: YieldSite) -> Vec<(usize, usize)> {
    let steps = history.decode();
    steps
        .iter()
        .enumerate()
        .filter(|(_, s)| s.2 == site.code())
        .filter_map(|(i, s)| resumed_after(&steps, i, s.1).map(|close| (i, close)))
        .collect()
}

/// Every interval a thread spent parked between its flush and its `CHECKPOINT-END` record.
fn windows(history: &SchedHistory) -> Vec<(usize, usize)> {
    windows_at(history, YieldSite::CheckpointRecordAppend)
}

/// Every interval a thread spent parked **inside** a flush, after that flush released its latches.
///
/// This is the window that decides where the redo floor may be sampled. See
/// [`the_in_flush_window_is_entered`].
fn in_flush_windows(history: &SchedHistory) -> Vec<(usize, usize)> {
    windows_at(history, YieldSite::FrameWriteFlushBatchReleased)
}

/// How many whole commit publications fall strictly inside a checkpoint window on this run.
///
/// A commit publication is a thread's `CommitPublishSlot` followed by its own `CommitRegistryRecord`
/// — the `COMMIT` record is appended between them — so a publication located entirely inside the
/// window is a `COMMIT` record appended while a checkpoint's flush was already behind it and its
/// `CHECKPOINT-END` record was not yet written.
fn commits_inside_windows(history: &SchedHistory) -> usize {
    commits_inside(history, &windows(history))
}

/// How many whole commit publications fall strictly inside one of `intervals`.
fn commits_inside(history: &SchedHistory, intervals: &[(usize, usize)]) -> usize {
    let steps = history.decode();
    let mut found = 0;
    for &(open, close) in intervals {
        for i in open + 1..close {
            if steps[i].2 != YieldSite::CommitPublishSlot.code() {
                continue;
            }
            let thread = steps[i].1;
            if (i + 1..close).any(|j| {
                steps[j].1 == thread && steps[j].2 == YieldSite::CommitRegistryRecord.code()
            }) {
                found += 1;
            }
        }
    }
    found
}

/// **The property.** Every commit the store acknowledged survives the power loss.
#[test]
fn every_acknowledged_commit_survives_the_crash() {
    let mut failing = Vec::new();
    for seed in 0..SEEDS {
        let run = scenario(seed);
        let lost = run.lost();
        if !lost.is_empty() {
            failing.push((seed, lost, run.recovered_total_nodes));
        }
    }
    assert!(
        failing.is_empty(),
        "committed data did not survive a power loss taken around a checkpoint: {} of {SEEDS} \
         seeds lost node records that a writer's `commit` had already acknowledged. \
         seed / lost node ids / the catalogue's `total_nodes` on that same recovered store: {:?}",
        failing.len(),
        failing
    );
}

/// Non-vacuity: the run really is contended — every thread ran and the token really moved.
#[test]
fn the_run_is_contended() {
    for seed in 0..SEEDS {
        let run = scenario(seed);
        assert!(
            run.history.threads >= WRITERS + 2,
            "seed {seed}: only {} logical threads appear in the history; the writers and the \
             checkpointing worker did not all run",
            run.history.threads
        );
        assert!(
            run.history.switches > 0,
            "seed {seed}: the token never moved, so nothing was interleaved"
        );
    }
}

/// Non-vacuity: the writers' commits really are in the store before the crash, so a run cannot pass
/// the durability property by having persisted nothing.
#[test]
fn the_live_store_holds_every_commit() {
    for seed in 0..SEEDS {
        let run = scenario(seed);
        assert_eq!(
            run.committed.len(),
            WRITERS * ROUNDS as usize,
            "seed {seed}: not every writer round was acknowledged"
        );
        for (i, &(node, label)) in run.committed.iter().enumerate() {
            assert!(
                run.live_labels[i].contains(&label),
                "seed {seed}: the LIVE store does not hold node {node}'s label {label}"
            );
        }
    }
}

/// Non-vacuity: a checkpoint really was taken on every seed.
///
/// The checkpointing worker retries, because a checkpoint that overlaps another worker's page
/// allocation is refused (see its own note). Without this control that retry could quietly become
/// "the checkpoint kept failing and the run measured a store nobody ever checkpointed", which every
/// other assertion in this file would survive.
#[test]
fn every_seed_really_took_a_checkpoint() {
    let mut retried = 0usize;
    for seed in 0..SEEDS {
        let run = scenario(seed);
        assert!(
            run.checkpoint_attempts >= 1,
            "seed {seed}: the checkpointing worker reported no attempt at all"
        );
        assert!(
            run.history.count_site(YieldSite::CheckpointRecordAppend) >= 1,
            "seed {seed}: no `CHECKPOINT-END` was ever reached — the checkpoint never got past its \
             flush, so this seed measures nothing"
        );
        if run.checkpoint_attempts > 1 {
            retried += 1;
        }
    }
    // Reported rather than asserted either way: it is the visible footprint of the separate
    // allocation-vs-flush race, and a change in it is a signal, not a failure.
    println!("checkpoint needed a retry on {retried} of {SEEDS} seeds");
}

/// Non-vacuity: the hazard window is really entered — on at least one seed a whole commit
/// publication falls strictly inside the interval a checkpoint spent between its flush and its
/// `CHECKPOINT-END` record.
#[test]
fn the_hazard_window_is_entered() {
    let mut entered = Vec::new();
    let mut windows_seen = 0usize;
    for seed in 0..SEEDS {
        let run = scenario(seed);
        windows_seen += windows(&run.history).len();
        let n = commits_inside_windows(&run.history);
        if n > 0 {
            entered.push((seed, n));
        }
    }
    assert!(
        windows_seen > 0,
        "no checkpoint ever offered the token at `CheckpointRecordAppend`: the window this suite \
         measures was never even opened"
    );
    assert!(
        !entered.is_empty(),
        "the hazard window was opened {windows_seen} times but no commit ever landed inside one, so \
         this suite proves nothing about it"
    );
}

/// **The control that makes the placement of the sample measurable, not merely argued.**
///
/// The correction of `rmp` #1086 is not "carry a floor in the record" — it is "carry a floor sampled
/// **before** the flush". Everything else can be right and the defect still be open if that sample
/// moves after the flush, and a suite that cannot tell the two apart lets the next person reopen the
/// whole thing with a green build.
///
/// `YieldSite::FrameWriteFlushBatchReleased` is what makes them distinguishable. It fires inside
/// `flush_batch` after the batch has written its pages home and dropped every latch, and before the
/// trailing durability barrier. A transaction that commits **there**:
///
/// * has its page missed by that flush entirely — the writes are behind it and the barrier covers
///   only what was written;
/// * has left the WAL active table by the time the flush returns.
///
/// So a floor sampled *after* the flush is `min(oldest_active_first_lsn, end)` computed with that
/// transaction already gone: it sits ABOVE the transaction's records, redo skips them, and the
/// commit is lost. A floor sampled *before* the flush cannot, because every record that transaction
/// logs is at or above the end the sample saw.
///
/// This test asserts the window is really entered. [`every_acknowledged_commit_survives_the_crash`]
/// is what then fails if the sample moves — verified by ablation: with the sample hoisted to after
/// `self.flush()?` in `RecordStore::checkpoint`, that property reports lost records; with it back
/// before the flush, it is green.
#[test]
fn the_in_flush_window_is_entered() {
    let mut entered = Vec::new();
    let mut opened = 0usize;
    for seed in 0..SEEDS {
        let run = scenario(seed);
        let intervals = in_flush_windows(&run.history);
        opened += intervals.len();
        let n = commits_inside(&run.history, &intervals);
        if n > 0 {
            entered.push((seed, n));
        }
    }
    assert!(
        opened > 0,
        "no flush ever offered the token after releasing its latches: the site that distinguishes a \
         pre-flush sample from a post-flush one was never reached"
    );
    assert!(
        !entered.is_empty(),
        "the in-flush window was opened {opened} times but no commit ever completed inside one, so \
         nothing in this suite can tell a pre-flush sample from a post-flush one — which is the \
         whole of the `rmp` #1086 correction"
    );
}

/// The durable counters agree with the workload's constants on **every** seed — which is the whole
/// reason they are not this suite's oracle.
///
/// # This is not the pre-fix measurement, and it deliberately is not
///
/// The pre-fix measurement is a recorded number, in the module header: on the seven seeds that lost
/// records, the recovered catalogue answered `total_nodes = 14` — the right number, for a store the
/// nodes had gone missing from. Since `rmp` #1067 a commit's cardinality change is its own WAL
/// record folded over a base, so it is replayed independently of the node's own page.
///
/// An earlier version of this test tried to assert that divergence directly, by skipping every seed
/// with nothing lost. With the fix in place nothing is ever lost, so it skipped all 128 seeds and
/// asserted **nothing** — a test that had become incapable of failing while its own documentation
/// claimed it was measuring something. It is rewritten as the property that is true *now* and
/// remains checkable: the counters are correct on every seed, so on any seed where
/// [`every_acknowledged_commit_survives_the_crash`] reports lost records the two oracles have
/// visibly disagreed, and the record read-back is the one that spoke.
#[test]
fn the_counters_are_right_even_where_the_records_would_not_be() {
    for seed in 0..SEEDS {
        let run = scenario(seed);
        assert_eq!(
            run.recovered_total_nodes, run.expected_total_nodes,
            "seed {seed}: the recovered catalogue disagrees with the workload's constants; the \
             counter path (`rmp` #1067) has a defect of its own, independent of what this suite \
             measures"
        );
    }
}
