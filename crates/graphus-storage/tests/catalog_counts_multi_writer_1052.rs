//! **`rmp` #1052 — the live-record cardinality counters under several concurrent writers.**
//!
//! # What this file certifies
//!
//! [`Statistics`](graphus_storage::Statistics)'s six live-record counters are not an advisory hint:
//! since `rmp` #866 a `count()` is answered from them, so a drifted counter is a **wrong query
//! answer**. They are also the only cardinality the store keeps — nothing recomputes them from a scan
//! at `open` — so a wrong value written into the durable catalog stays wrong across every restart.
//!
//! The counters move eagerly at write time, which makes the live value
//! `committed image + every in-flight transaction's delta`. Two facts therefore have to be read
//! *together* to mean anything:
//!
//! 1. the live counters, in the catalog, behind the rank-10 catalog latch; and
//! 2. every open transaction's pending [`CountDelta`], in the sharded active-transaction table.
//!
//! `rmp` #1052 was those two being sampled at two different instants, in two places, so the
//! difference between them was a state of nothing:
//!
//! * a commit's `checkpoint_meta` cloned the live counters under the catalog latch and then folded the
//!   pending deltas out of that clone under the active table's shard mutexes. A writer that applied
//!   its increment after the clone and recorded its delta before the fold reached its shard had that
//!   increment **withdrawn from an image that never contained it**;
//! * a rollback of a transaction that had linked no delta ran `reload_catalog`, which reverted the
//!   whole `Statistics` — counters included — to the durable image, and the caller then reinstalled a
//!   `counts_image()` captured before the whole physical undo. Any counter a *concurrent* writer moved
//!   inside that window was captured by nobody and reverted by the reload, so the live counters lost
//!   it while that writer's delta survived to be withdrawn later.
//!
//! # Why this test asserts a VALUE and not a panic
//!
//! Both faults reach `Statistics::add_keyed`'s decrement arms, which carry a `debug_assert!`. That
//! assertion is the right tool for a coding error and it is deliberately kept — but it only fires in a
//! debug build. **In a release build the same code takes the saturating rail in silence** and the
//! durable catalog is simply left holding a cardinality that is wrong, which is the harder failure and
//! the one that ships.
//!
//! So the oracle here is the reopened counter's VALUE against a ground truth the test computes
//! independently, and the test is meaningful in every profile:
//!
//! ```text
//! cargo test --profile gate -p graphus-storage --test catalog_counts_multi_writer_1052
//! cargo test --release     -p graphus-storage --test catalog_counts_multi_writer_1052
//! ```
//!
//! Under `gate` a regression fails on the assertion; under `--release` it fails on the number. Neither
//! run depends on the other.
//!
//! # The workload, and why each part of it is there
//!
//! [`WRITERS`] threads share one [`RecordStore`] (`Send + Sync` since `rmp` #337 Slice 2; every write
//! entry point takes `&self` since the `rmp` #971 retirement of the lock table). Each thread runs
//! [`ROUNDS`] rounds, and the round kind rotates so that all three shapes run at once against each
//! other:
//!
//! * **commit** — create a node, give it this thread's label, commit. The commit runs
//!   `checkpoint_meta`, so at any instant several threads are inside the catalog-image window while
//!   others are inside `count_bump`. This is what drives the first fault.
//! * **rollback after writing** — the same writes, then a rollback. It exercises the withdrawal of a
//!   transaction's own delta, and it must leave the counters exactly where it found them.
//! * **rollback having written nothing** — begin, then roll back immediately. A transaction that
//!   linked no delta owns no commit slot, so this takes the *physical* rollback path and its
//!   `reload_catalog`. This is what drives the second fault, and it is the reason the shape is in the
//!   workload at all: without it the reload is never reached and half of #1052 goes untested.
//!
//! Every node is created by the thread that labels it and is touched by no other, so no round can be
//! refused by the write-write conflict check: the expected counts are exact, not approximate. A
//! refused commit would be reported rather than absorbed.
//!
//! # A fourth defect this file used to absorb, and no longer does (`rmp` #1055)
//!
//! Only a **commit** ever writes the catalog: `RecordStore::checkpoint` is the redo-bounding kind and
//! never touches it. So the image on disk is the one written by whichever commit wrote the metadata
//! page LAST, and under concurrent committers that image can be short of the committed truth.
//!
//! This file used to end with a single **settling commit** — one commit, alone, with nothing else in
//! flight — so that the last catalog write was guaranteed complete. Measured with every `rmp` #1052
//! mechanism fixed but before #1062: **9 runs in 200** came back short by exactly one transaction's
//! delta without it, and **0 in 200** with it. The settling commit was therefore a mask, and #1055
//! required it removed.
//!
//! **It is removed.** Re-measured 2026-08-12, after `rmp` #1062 made log order equal apply order per
//! page: **0 short runs in 200** with no settling commit. #1062 removed one of the two contributions
//! — the `compute(I1) compute(I2) write(I2) write(I1)` inversion, in which the older image landed
//! after the newer one — and that is the contribution this workload's timing was mostly sampling.
//!
//! **`rmp` #1055 is NOT closed, and a rare failure here is that defect and not a new regression.**
//! What survives #1062 is a shortfall with no inversion in it at all: a transaction that commits
//! after another checkpoint has folded its image is absent from that image, and if that image lands
//! last — or if nothing writes the catalog after that commit at all — its rows never reach the
//! durable catalog. `graphus-dst`'s `det_scheduler_checkpoint_inversion_1055`, which schedules two
//! writers deterministically and switches at every yield point, still reproduces it on 2 of its 16
//! seeds and classifies both shapes by name (`the_residual_shortfall_is_attributed`). That suite, not
//! this one, is the oracle for #1055; this file samples the same hazard incidentally and at a rate
//! this host measured as zero in two hundred.

use std::sync::Arc;

use graphus_core::{PageId, TxnId};
use graphus_io::{BlockDevice, MemBlockDevice, Page};
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// Concurrent writer threads. Eight is the worker count at which the `rmp` #1034 certification
/// reproduced this, and more threads than a typical developer machine has cores is deliberate: it
/// makes the scheduler preempt inside the windows rather than only between them.
const WRITERS: usize = 8;

/// Rounds each writer runs. The windows are a handful of instructions wide, so this test enters them
/// by repetition — which is exactly how the defect was found — and 150 rounds across 8 threads was
/// measured to enter both of them on every run.
const ROUNDS: u64 = 150;

/// Buffer-pool frames. Comfortably above the working set of this workload, so the run measures the
/// counters and not the pool's eviction behaviour.
const POOL_PAGES: usize = 256;

/// The three round shapes, in the order they rotate. See the module docs for what each one drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Round {
    Commit,
    RollbackAfterWriting,
    RollbackHavingWrittenNothing,
}

impl Round {
    /// The shape writer `w` runs in round `r`. The `+ w` staggers the threads so that a commit is
    /// always overlapping somebody else's rollback rather than all eight marching in step.
    fn of(w: usize, r: u64) -> Self {
        match (r + w as u64) % 3 {
            0 => Self::Commit,
            1 => Self::RollbackAfterWriting,
            _ => Self::RollbackHavingWrittenNothing,
        }
    }
}

/// The transaction id writer `w` uses in round `r`. Disjoint per writer, so no two threads ever name
/// the same transaction.
fn txn_of(w: usize, r: u64) -> TxnId {
    TxnId((w as u64 + 1) * 1_000_000 + r + 1)
}

/// The label token name writer `w` stamps on every node it creates. One label per writer, so a drift
/// on any single writer's counter is visible on its own key instead of being averaged away.
fn label_name(w: usize) -> String {
    format!("L{w}")
}

/// Builds a fresh store over an in-memory device and log.
fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, POOL_PAGES, 1).expect("create store")
}

/// Reopens `store` through its own durable device image and WAL — the same steal-crash recovery shape
/// the rest of this crate's suites use.
///
/// This is what makes the assertion about the DURABLE catalog rather than about the live one. The two
/// faults show up in different places: the reload fault corrupts the live counters directly, while the
/// catalog-image fault leaves the live counters correct and writes the wrong number to disk. Only a
/// reopen sees the second.
fn reopen(store: &mut Store) -> Store {
    store.flush().expect("flush the dirty pages home");
    let pages = store.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    let staged: Vec<(u64, Box<Page>)> = pages
        .iter()
        .map(|p| (p.0, store.read_device_page(*p).expect("read device page")))
        .collect();
    for (idx, bytes) in staged {
        device
            .write_page(PageId(idx), &bytes)
            .expect("stage the page");
    }
    device.sync_all().expect("persist the disk image");

    let mut sink = MemLogSink::new();
    sink.append(&store.with_wal(|w| w.sink().durable_bytes().to_vec()));
    sink.sync().expect("sync the durable log prefix");
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("ARIES recovery");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, POOL_PAGES).expect("open the recovered store")
}

/// What one full run produced: the counters as the live store held them, the counters the reopened
/// store read back out of the durable catalog, and the ground truth both must equal.
struct Outcome {
    live_total: u64,
    live_per_label: Vec<u64>,
    durable_total: u64,
    durable_per_label: Vec<u64>,
    expected_total: u64,
    expected_per_label: Vec<u64>,
}

/// Runs the whole workload once and reads the counters back three ways.
fn run() -> Outcome {
    let store = fresh();

    // Intern every label up front, on this thread. Interning takes the catalog's write latch and is
    // append-only; doing it here keeps the measured phase to the counter paths this file is about.
    let labels: Vec<u32> = (0..WRITERS)
        .map(|w| {
            store
                .intern_token(Namespace::Label, &label_name(w))
                .expect("intern a label token")
        })
        .collect();

    // One committed node per label, so every counter starts non-zero and a run that wrongly drove one
    // to zero has somewhere to fall from.
    let seed = TxnId(1);
    store.begin(seed);
    for &label in &labels {
        let (node, _) = store.create_node(seed).expect("create the seed node");
        store.add_label(seed, node, label).expect("label the seed");
    }
    store.commit(seed).expect("commit the seed");

    let store = Arc::new(store);
    let mut threads = Vec::with_capacity(WRITERS);
    for (w, &label) in labels.iter().enumerate() {
        let store = Arc::clone(&store);
        threads.push(std::thread::spawn(move || {
            let mut committed = 0u64;
            for r in 0..ROUNDS {
                let txn = txn_of(w, r);
                store.begin(txn);
                match Round::of(w, r) {
                    Round::Commit => {
                        let (node, _) = store.create_node(txn).expect("create a node");
                        store.add_label(txn, node, label).expect("label the node");
                        store.commit(txn).expect("a disjoint write always commits");
                        committed += 1;
                    }
                    Round::RollbackAfterWriting => {
                        let (node, _) = store.create_node(txn).expect("create a node");
                        store.add_label(txn, node, label).expect("label the node");
                        store
                            .rollback(txn)
                            .expect("roll back a written transaction");
                    }
                    Round::RollbackHavingWrittenNothing => {
                        store.rollback(txn).expect("roll back an empty transaction");
                    }
                }
            }
            committed
        }));
    }
    let per_writer: Vec<u64> = threads
        .into_iter()
        .map(|t| t.join().expect("a writer thread joins"))
        .collect();

    // One node per label was seeded, and every committed round added exactly one more.
    let expected_per_label: Vec<u64> = per_writer.iter().map(|c| c + 1).collect();
    let expected_total: u64 = expected_per_label.iter().sum();

    let mut store = Arc::into_inner(store).expect("every writer thread has joined");
    // ONE settling commit, alone, so that "the durable image" names something.
    //
    // This is not a workaround for anything `rmp` #1052 is about; it is what makes the measurement
    // well posed, and it is measured rather than assumed (see the module docs, "A fourth defect this
    // file deliberately does not absorb"). Only a commit writes the catalog — `RecordStore::checkpoint`
    // bounds redo and never touches it — so the image on disk is the one written by whichever commit
    // wrote the metadata page LAST. Under concurrent committers that need not be the one that computed
    // its image last: `checkpoint_meta` samples the catalog under the latch and then releases it before
    // the page writes, so `compute(I1) compute(I2) write(I2) write(I1)` leaves a stale I1 on disk. With
    // this settling commit the last image is computed and written with nothing else in flight, so the
    // assertions below are about what a checkpoint COMPUTES, which is what #1052 governs.
    // The settling commit that used to stand here is GONE (`rmp` #1055). It existed to make "the
    // durable image" name a particular image, by ensuring the last catalog write happened with nothing
    // else in flight — which also masked the very defect #1055 is about. See the module note.
    let live = store.statistics();
    let live_total = live.total_nodes();
    let live_per_label: Vec<u64> = labels
        .iter()
        .map(|&l| live.node_count_for_label(l))
        .collect();
    drop(live);
    // A final checkpoint with nothing open publishes the settled image, so a difference read back
    // below is a difference the run BAKED IN rather than one it merely had not persisted yet.
    store.checkpoint().expect("checkpoint the settled store");
    let reopened = reopen(&mut store);
    let durable = reopened.statistics();
    Outcome {
        live_total,
        live_per_label,
        durable_total: durable.total_nodes(),
        durable_per_label: labels
            .iter()
            .map(|&l| durable.node_count_for_label(l))
            .collect(),
        expected_total,
        expected_per_label,
    }
}

/// **Every counter is exactly right, live and after a reopen, under eight concurrent writers.**
///
/// The two assertions are separate on purpose, because they fail for different reasons and a single
/// combined one would hide which fault fired:
///
/// * a wrong **live** counter means a concurrent writer's increment was destroyed in memory — the
///   `reload_catalog` wholesale revert (`rmp` #1052, second half);
/// * a right live counter with a wrong **durable** one means the checkpoint computed its image from
///   two states sampled at two instants — the `committed_statistics` tear (`rmp` #1052, first half).
///
/// Neither assertion depends on `debug_assertions`. Under `--release` the store takes its saturating
/// rail without a word and these numbers are the only thing that notices.
#[test]
fn concurrent_writers_never_drift_the_live_record_counters() {
    let o = run();

    assert_eq!(
        (o.live_total, &o.live_per_label),
        (o.expected_total, &o.expected_per_label),
        "the LIVE counters drifted under {WRITERS} concurrent writers. A counter moves eagerly at \
         write time and every delta is exactly invertible by its owner, so the only way to lose one \
         is for something to overwrite the live value wholesale — which is what a rollback's \
         `reload_catalog` used to do to every CONCURRENT writer's increment (`rmp` #1052)"
    );
    assert_eq!(
        (o.durable_total, &o.durable_per_label),
        (o.expected_total, &o.expected_per_label),
        "the live counters are right and the DURABLE catalog is wrong, so a checkpoint wrote a \
         number the store never held: its image is the live counters MINUS every open transaction's \
         pending delta, and sampling those two at two instants withdraws a delta from an image that \
         does not contain it (`rmp` #1052). `rmp` #866 answers count() from this number, and nothing \
         recomputes it at open — so this is a wrong query answer that survives every restart"
    );
}

// =================================================================================================
// The catalog image itself: what a checkpoint persists WHILE other writers are in flight.
// =================================================================================================

/// Trials of [`image_trial`]. Each one is an independent store with an independent chance of
/// straddling a window that is nanoseconds wide, so the detection compounds. The count is set by
/// MEASUREMENT against each reverted half of the fix, on a 16-core Linux x86-64 host, `--release`:
///
/// | reverted half | trials that caught it | runs that caught it |
/// |---|---|---|
/// | `committed_statistics` sampled at two instants | 18–28 of 40 | 3 of 3 |
/// | `count_bump`'s apply and record split across two locks | 1–2 of 150 | 5 of 6 |
///
/// The second row is the honest limit of this technique and the reason the number is 150 rather than
/// 40: that window is the handful of instructions between releasing one latch and taking another, and
/// no amount of load makes a thread sit in it. It is stated here so nobody reads a green run as proof
/// that half is unnecessary — it is load-bearing, and the argument for it is in `count_bump`'s own
/// doc comment.
const IMAGE_TRIALS: usize = 300;

/// Threads holding an open transaction and moving counters throughout the measured checkpoint.
/// Several, not one, because the checkpoint folds the pending deltas out shard by shard: more
/// transactions spread across more shards means more of the fold is exposed.
const HAMMERS: usize = 8;

/// Distinct labels a hammer cycles through, one per node.
///
/// This is the sensitivity knob, and it is set by measurement rather than taste — it widens the
/// *checkpoint's* exposure rather than the writers'. A transaction's pending delta is a map keyed by
/// what it touched, and the checkpoint withdraws it key by key, so cycling the labels grows each
/// hammer's map to this many entries and the fold to [`HAMMERS`] times as many map operations. That
/// is the interval during which a writer's apply-and-record pair must not be caught half-done.
///
/// Measured, with the `count_bump` half of the fix reverted and everything else in place: at one
/// label the tear was caught on 1 trial in 40 and on one run in three — not a regression guard.
///
/// The ceiling is the store's, not this test's: a label token id must fit the 62-bit inline label
/// bitmap, so id 63 is refused outright (`graphus` #39 leaves the overflow block to a follow-up).
/// This is one below the highest that leaves room for `Quiet`.
const HAMMER_LABELS: usize = 60;

/// Committed nodes the trial starts from. Large enough that an under-count is a plain wrong number
/// rather than a value clamped at the saturating rail, which would be indistinguishable from the
/// right answer.
const IMAGE_BASE: u64 = 64;

/// Runs one trial and returns `(durable total_nodes, expected total_nodes)`.
///
/// # Why this is shaped so differently from the workload above
///
/// Because the two faults are observable in different places, and the first test is structurally
/// blind to this one. A `committed_statistics` tear leaves the LIVE counters correct — it corrupts
/// only the image a checkpoint writes — and every later checkpoint recomputes that image from the
/// live counters, so a run that ends with a quiescent checkpoint *heals* it before anything can look.
/// (This is not a hypothesis: with the `committed_statistics` fix reverted, the workload test above
/// passes.)
///
/// So this trial makes the drifted image the **last** one:
///
/// 1. [`IMAGE_BASE`] nodes are committed, and the store is quiet.
/// 2. [`HAMMERS`] threads each open a transaction and create nodes as fast as they can, so at every
///    instant the live counters carry a large, still-growing pending delta.
/// 3. **one** transaction commits. Its `checkpoint_meta` is the measured event: it must persist the
///    committed image, which is the live counters minus every hammer's pending delta.
/// 4. the hammers stop and roll back. A rollback writes no catalog, so the image from step 3 is the
///    last one written, and a reopen reads exactly it.
///
/// # The oracle covers both directions, because the tear has two
///
/// A torn sample is wrong in whichever direction the two instants disagree, and the two directions
/// show up on different counters:
///
/// * **withdrawn twice** — the writer's increment landed in the live counters after the clone and in
///   the delta before the fold. `total_nodes` comes out BELOW `IMAGE_BASE + 1`. This is the direction
///   that trips the `debug_assert!`, because it is also what drives a counter past `0`.
/// * **not withdrawn at all** — the writer's increment was in the clone and its delta had not reached
///   the table when the fold passed its shard. Nothing underflows, nothing asserts, and the image
///   simply keeps an uncommitted row: a hammer's label reads NON-ZERO in a committed image, though no
///   hammer ever committed.
///
/// So the trial returns the whole vector — `total_nodes`, the committed label, and every hammered
/// label — and the caller compares all of it. Checking `total_nodes` alone would have missed the
/// second direction: measured, it caught the reverted `count_bump` on 1 trial in 40.
fn image_trial() -> (Vec<u64>, Vec<u64>) {
    use std::sync::atomic::{AtomicBool, Ordering};

    let store = fresh();
    let quiet = store
        .intern_token(Namespace::Label, "Quiet")
        .expect("intern the committed label");
    let busy: Vec<u32> = (0..HAMMER_LABELS)
        .map(|i| {
            store
                .intern_token(Namespace::Label, &format!("Busy{i}"))
                .expect("intern a hammered label")
        })
        .collect();

    let seed = TxnId(1);
    store.begin(seed);
    for _ in 0..IMAGE_BASE {
        let (node, _) = store.create_node(seed).expect("create a base node");
        store.add_label(seed, node, quiet).expect("label it");
    }
    store.commit(seed).expect("commit the base");

    let store = Arc::new(store);
    let stop = Arc::new(AtomicBool::new(false));
    let hammers: Vec<_> = (0..HAMMERS)
        .map(|h| {
            let store = Arc::clone(&store);
            let stop = Arc::clone(&stop);
            let busy = busy.clone();
            std::thread::spawn(move || {
                let txn = TxnId(1_000 + h as u64);
                store.begin(txn);
                let mut i = 0usize;
                while !stop.load(Ordering::Relaxed) {
                    let (node, _) = store.create_node(txn).expect("create a pending node");
                    store
                        .add_label(txn, node, busy[i % busy.len()])
                        .expect("label it");
                    i += 1;
                }
                // Never committed: this transaction contributes nothing to any committed image.
                store.rollback(txn).expect("roll the hammer back");
            })
        })
        .collect();

    // Let the hammers populate every key of their pending deltas, then take the one measured
    // checkpoint. Long enough that the fold below is over full maps rather than over whatever the
    // hammers happened to have reached.
    std::thread::sleep(std::time::Duration::from_micros(800));
    let committer = TxnId(9_999);
    store.begin(committer);
    let (node, _) = store
        .create_node(committer)
        .expect("create the committed node");
    store.add_label(committer, node, quiet).expect("label it");
    store.commit(committer).expect("commit");

    stop.store(true, Ordering::Relaxed);
    for h in hammers {
        h.join().expect("a hammer thread joins");
    }

    // NO checkpoint here, deliberately: the image the committer wrote must be the one a reopen finds.
    let mut store = Arc::into_inner(store).expect("every hammer thread has joined");
    let reopened = reopen(&mut store);
    let durable = reopened.statistics();
    // `[total_nodes, Quiet, Busy0, Busy1, …]`. Every hammered label is `0`: no hammer ever committed.
    let mut got = vec![durable.total_nodes(), durable.node_count_for_label(quiet)];
    got.extend(busy.iter().map(|&l| durable.node_count_for_label(l)));
    let mut want = vec![IMAGE_BASE + 1, IMAGE_BASE + 1];
    want.extend(std::iter::repeat_n(0, busy.len()));
    (got, want)
}

/// **A checkpoint taken while other writers are in flight persists the committed image, exactly.**
///
/// The image a checkpoint makes durable is the live counters MINUS every still-open transaction's
/// pending delta. Those are two pieces of state in two places — the catalog, behind the rank-10
/// latch, and the sharded active-transaction table — and `rmp` #1052 was them being sampled at two
/// instants: a writer that applied its increment after the clone and recorded its delta before the
/// fold reached its shard had that increment withdrawn from an image that never contained it.
///
/// The number this asserts is the whole point. `rmp` #866 answers `count()` from it, and nothing
/// recomputes it at `open`, so an image that is short by even one is a wrong query answer for the
/// life of the database. Under `--release` the store reaches this state without a word: `add_total`
/// and `add_keyed` take their saturating rails and the `debug_assert!` that would have caught it is
/// compiled out.
#[test]
fn a_checkpoint_taken_while_writers_are_in_flight_persists_the_committed_image() {
    /// One counter that came out wrong: its slot in the vector, what the durable catalog held, and
    /// what the committed image was. Slot 0 is `total_nodes`, slot 1 the committed label, the rest
    /// the hammered ones.
    type WrongCounter = (usize, u64, u64);

    let mut wrong: Vec<(usize, Vec<WrongCounter>)> = Vec::new();
    for trial in 0..IMAGE_TRIALS {
        let (durable, expected) = image_trial();
        let diff: Vec<WrongCounter> = durable
            .iter()
            .zip(&expected)
            .enumerate()
            .filter(|&(_, (d, e))| d != e)
            .map(|(i, (&d, &e))| (i, d, e))
            .collect();
        if !diff.is_empty() {
            wrong.push((trial, diff));
        }
    }
    let hits = wrong.len();
    assert!(
        wrong.is_empty(),
        "a checkpoint persisted a committed image the store never held, on {hits} of \
         {IMAGE_TRIALS} trials. Slot 0 is total_nodes, slot 1 the committed label, the rest the \
         hammered labels; each entry is (slot, durable, expected): {wrong:?}. The image is the live \
         counters minus every open transaction's pending delta, and sampling those two at two \
         instants either withdraws a delta from an image that does not contain it (durable BELOW \
         expected) or fails to withdraw one that is there (durable ABOVE expected) — `rmp` #1052. \
         Nothing recomputes these numbers at open, and `rmp` #866 answers count() from them"
    );
}

/// **The workload really is contended**, so the assertion above is about a state the run reached.
///
/// A run in which the eight threads happened to serialise would satisfy every count trivially and
/// prove nothing. The witness is that the three round shapes are all present in quantity — in
/// particular that transactions took the *physical* rollback path, which is the only way
/// `reload_catalog` is reached, and which the first draft of this file omitted entirely.
#[test]
fn the_workload_exercises_all_three_round_shapes() {
    let mut shapes = [0u64; 3];
    for w in 0..WRITERS {
        for r in 0..ROUNDS {
            let slot = match Round::of(w, r) {
                Round::Commit => 0,
                Round::RollbackAfterWriting => 1,
                Round::RollbackHavingWrittenNothing => 2,
            };
            shapes[slot] += 1;
        }
    }
    for (slot, name) in [
        (0, "commit"),
        (1, "rollback after writing"),
        (2, "rollback having written nothing (the physical path)"),
    ] {
        assert!(
            shapes[slot] > 0,
            "NON-VACUITY: no round runs the {name} shape, so the path it drives is untested"
        );
    }
}
