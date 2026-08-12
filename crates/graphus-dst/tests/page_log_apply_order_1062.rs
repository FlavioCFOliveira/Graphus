//! **`rmp` #1062 — for every page, log order is apply order.**
//!
//! # The invariant
//!
//! A logged page write is two instants: the record enters the WAL (under the WAL mutex, rank 30) and
//! the change takes effect on the cached page (under the frame latch, rank 40). ARIES replays
//! **strictly in log order** and gates each record on the page's `page_lsn`
//! (`record.lsn > page_lsn`). So if two writers of one page enter the log in one order and take
//! effect in the other, recovery reconstructs an image the live system never held — the durable
//! answer with no crash and the durable answer after a crash **differ**, and neither is wrong on its
//! own terms, which is why no result-checking test catches it.
//!
//! The observable signature is a page being offered an LSN **below** the one its header already
//! carries. That is exactly what
//! [`RecordStore::page_lsn_descents`](graphus_storage::RecordStore::page_lsn_descents) counts, and
//! **zero** is the invariant this suite asserts.
//!
//! The stamp itself has been a maximum since `rmp` #1029, so a descent never lowers `page_lsn` and
//! never breaks WAL-before-data. #1029 measured descents, declined to assert on them so that a live
//! ordering question would not brick every debug build, and named the question as #1028's. #1062
//! answers it: every logged page write now appends and applies inside one rank-27
//! [`PageOrderLatchScope`](graphus_core::latch::PageOrderLatchScope) section keyed by the **device
//! page**, so the maximum never has to clamp.
//!
//! # Why it has to be the page and not the record
//!
//! `rmp` #1028 introduced the rank-27 latch keyed by `(store kind, record id)`, which orders the
//! writers of one chain head and leaves everything else unordered. `page_lsn` is a property of the
//! **page**, so two writers of two different records that share a page have to be ordered exactly as
//! much as two writers of one record. Measured on the sister scenario
//! `det_scheduler_checkpoint_inversion_1055` before the fix: **32** descents across its sixteen
//! seeds, and not one of them on a chain head — the catalog image (`write_region`), the commit slot
//! (`patch_commit_slot_word` → `write_region`), the undo area (`write_undo_area_create`) and a node's
//! label word (`write_node_labels`).
//!
//! # Non-vacuity, and the positive control
//!
//! "Zero descents" is satisfied trivially by a run in which the writers never touch the same page, so
//! two things are asserted rather than hoped for:
//!
//! * [`the_writers_really_wrote_the_same_page`] requires, on **every** seed, that at least one buffer
//!   frame was LSN-stamped by two different logical threads — read out of the recorded schedule, so
//!   it is a fact about the run and not about the workload's intent;
//! * [`the_run_really_commits_under_contention`] requires the scheduler to have handed the token
//!   over, every logical thread to have run, and the writes to be **in the store** — the catalog's
//!   own node counters and every created node's labels read back through `node_labels`, never a
//!   counter incremented in the writer loop (see that test for why such a counter cannot fail).
//!
//! And the measured positive control, run 2026-08-12 on this exact file, Linux x86-64, `cargo test`
//! (debug) profile: with `RecordStore::in_page_order`'s rank-27 section ablated to a bare `body()` —
//! the latch not taken, everything else identical —
//! [`no_page_ever_applies_a_change_out_of_log_order`] fails on **13 of the 16 seeds**, 1 to 4
//! descents each, 30 in total:
//!
//! ```text
//! seed 0x0: 1   seed 0x3: 1   seed 0x4: 3   seed 0x6: 1   seed 0x7: 3
//! seed 0x8: 3   seed 0x9: 2   seed 0xa: 4   seed 0xb: 2   seed 0xc: 4
//! seed 0xd: 4   seed 0xe: 1   seed 0xf: 1
//! ```
//!
//! The other three assertions in this file pass under the ablation, which is the point of separating
//! them: they establish that the run really contended, so the zero this file asserts with the fix in
//! place is a zero the workload could have broken. With the section restored, all sixteen seeds
//! report zero.
//!
//! # Running it
//!
//! ```text
//! cargo test -p graphus-dst --features det-sched --test page_log_apply_order_1062
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use graphus_core::TxnId;
use graphus_core::sched::YieldSite;
use graphus_dst::detsched::{DetSchedConfig, SchedHistory, run_scheduled};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

/// Scheduled committing writer threads. Two is the minimum that can produce the defect at all: a
/// single writer's appends and applies are already in program order.
const WRITERS: usize = 2;

/// Transactions each writer commits. Each is one node, one label and one commit — and therefore one
/// record-store page write, one undo-area write, one commit-slot write and one whole catalog image.
const ROUNDS: u64 = 4;

/// Buffer-pool frames. Comfortably above this workload's working set, so what is measured is the
/// ordering of the writes and not the pool's eviction behaviour.
const POOL_PAGES: usize = 256;

/// The seeds this suite pins. A fixed list, not a sample: a seed that reproduces a defect is evidence
/// only if it is still run tomorrow.
const SEEDS: [u64; 16] = [
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
];

/// Transaction-id stride per writer, so a transaction id in the history resolves to one writer.
const WRITER_STRIDE: u64 = 1_000;

/// The resource class `ResourceId::frame` tags a buffer-pool frame with, fixed by
/// `graphus_core::sched::ResourceId`: the class in the top byte, the value in the low 56 bits.
const CLASS_FRAME: u64 = 1;

/// The frame index a `ResourceId` names, or [`None`] for any other resource class.
fn frame_of_resource(resource: u64) -> Option<u64> {
    const VALUE_MASK: u64 = (1u64 << 56) - 1;
    (resource >> 56 == CLASS_FRAME).then_some(resource & VALUE_MASK)
}

/// What one scheduled run produced.
struct Run {
    /// Pages of this store stamped with an LSN below the one they already carried. **Zero** is the
    /// invariant; see the module note.
    descents: u64,
    /// `[total_nodes, L0, L1, …]` read out of the STORE'S OWN catalog once every writer had joined —
    /// not counted in the writer loop. See [`the_run_really_commits_under_contention`] for why the
    /// distinction is the whole point of the field.
    live: Vec<u64>,
    /// The label token ids the store reports for each node the writers created, in creation order,
    /// read back through `node_labels` after the run.
    labels_read_back: Vec<Vec<u32>>,
    /// The label token id each of those nodes was created WITH, in the same order — the expectation
    /// `labels_read_back` is matched against.
    labels_written: Vec<u32>,
    history: SchedHistory,
}

/// Runs [`WRITERS`] scheduled committers against one store under the schedule `seed` names.
///
/// Each writer creates its own node and labels it with its own label, so no round can be refused by
/// the write-write conflict check and every acknowledged commit is a real one. The two writers'
/// nodes are consecutive physical ids and therefore share a `nodes.store` page — which is the point:
/// the contention this suite measures is two writers of ONE page, not of one record.
fn scenario(seed: u64) -> Run {
    // Switch at EVERY yield point: the window is the interval between a record entering the log and
    // the same record reaching the page, which the amortised default would step over.
    let cfg = DetSchedConfig::exhaustive(seed);
    let ((descents, live, labels_read_back, labels_written), history) = run_scheduled(cfg, || {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store =
            Arc::new(RecordStore::create(device, wal, POOL_PAGES, 1).expect("create store"));

        // Interning takes the catalogue's write latch, which the scheduler does not mediate. Done on
        // the root thread, so the run's contention is only where the scenario means it to be.
        let labels: Vec<u32> = (0..WRITERS)
            .map(|w| {
                store
                    .intern_token(Namespace::Label, &format!("L{w}"))
                    .expect("intern a label token")
            })
            .collect();

        let threads: Vec<_> = (0..WRITERS)
            .map(|w| {
                let store = Arc::clone(&store);
                let label = labels[w];
                graphus_core::sched::spawn("writer", move || {
                    // The physical ids this writer created, so the run can be checked against what
                    // the STORE holds rather than against how many times this loop went round.
                    let mut created = Vec::with_capacity(ROUNDS as usize);
                    for r in 0..ROUNDS {
                        let txn = TxnId((w as u64 + 1) * WRITER_STRIDE + r + 1);
                        store.begin(txn);
                        let (node, _) = store.create_node(txn).expect("create a node");
                        store.add_label(txn, node, label).expect("label the node");
                        store.commit(txn).expect("a disjoint write always commits");
                        created.push((node, label));
                    }
                    created
                })
            })
            .collect();
        let created: Vec<(u64, u32)> = threads
            .into_iter()
            .flat_map(|t| t.join().expect("a writer thread joins"))
            .collect();

        // Every number below is read back OUT OF THE STORE after the writers have joined.
        let stats = store.statistics();
        let mut live = vec![stats.total_nodes()];
        live.extend(labels.iter().map(|&l| stats.node_count_for_label(l)));
        drop(stats);

        let labels_written: Vec<u32> = created.iter().map(|&(_, l)| l).collect();
        let labels_read_back: Vec<Vec<u32>> = created
            .iter()
            .map(|&(node, _)| {
                store
                    .node_labels(node)
                    .expect("read a created node's labels")
            })
            .collect();

        (
            store.page_lsn_descents(),
            live,
            labels_read_back,
            labels_written,
        )
    });
    Run {
        descents,
        live,
        labels_read_back,
        labels_written,
        history,
    }
}

/// Every buffer frame that was LSN-stamped in this run, with the set of logical threads that stamped
/// it. Read out of the recorded schedule: `YieldSite::FrameWriteWithPageMutLsn` is offered by
/// `latch_write` immediately before the frame's write latch is taken, and its resource is the frame.
fn stampers_per_frame(history: &SchedHistory) -> HashMap<u64, Vec<u32>> {
    let mut out: HashMap<u64, Vec<u32>> = HashMap::new();
    for (_, thread, site, _, resource) in history.decode() {
        if site == YieldSite::FrameWriteWithPageMutLsn.code()
            && let Some(frame) = frame_of_resource(resource)
        {
            let threads = out.entry(frame).or_default();
            if !threads.contains(&thread) {
                threads.push(thread);
            }
        }
    }
    out
}

/// **The property.** No page ever applies a change out of log order.
///
/// A non-zero count means some page took a higher-LSN change before a lower-LSN one, so ARIES redo
/// — which replays strictly in log order — reconstructs a different image from the one the running
/// system holds. The two are each internally consistent, which is precisely why only this oracle
/// sees the difference.
#[test]
fn no_page_ever_applies_a_change_out_of_log_order() {
    let mut offenders = Vec::new();
    for seed in SEEDS {
        let run = scenario(seed);
        if run.descents != 0 {
            offenders.push(format!(
                "seed {seed:#x}: {} page-LSN descent(s)",
                run.descents
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "a page was stamped with an LSN below the one it already carried, so the order in which \
         records entered the WAL is not the order in which they took effect on the page. ARIES \
         replays in log order and gates redo on `page_lsn`, so a reopen rebuilds an image the live \
         system never held (`rmp` #1062). Every logged page write must append and apply inside one \
         `RecordStore::in_page_order` section keyed by the device page:\n{}",
        offenders.join("\n")
    );
}

/// **Non-vacuity.** The writers really wrote the SAME page — otherwise "zero descents" is a
/// statement about a workload with no contention in it.
///
/// Asserted per seed, from the recorded schedule alone: at least one buffer frame was LSN-stamped by
/// two distinct logical threads. A frame is a resident page, so two threads stamping one frame is
/// two writers of one page, which is the only configuration in which the defect exists at all.
#[test]
fn the_writers_really_wrote_the_same_page() {
    for seed in SEEDS {
        let run = scenario(seed);
        let per_frame = stampers_per_frame(&run.history);
        let shared: Vec<_> = per_frame
            .iter()
            .filter(|(_, threads)| threads.len() >= 2)
            .map(|(frame, threads)| format!("frame {frame} stamped by threads {threads:?}"))
            .collect();
        assert!(
            !shared.is_empty(),
            "seed {seed:#x}: no buffer frame was LSN-stamped by two different threads, so the two \
             writers never wrote the same page and this seed proves nothing about the ordering \
             between them. {} frame(s) were stamped in total",
            per_frame.len()
        );
    }
}

/// **Non-vacuity of the run itself.** The scheduler really interleaved the threads, every logical
/// thread ran, and the writes the writers made are really IN THE STORE.
///
/// # Why the evidence is read out of the store and not counted in the loop
///
/// The obvious form of the last assertion — a counter incremented after `commit` returned, compared
/// against `ROUNDS` — cannot fail. `commit` is followed by `.expect(...)`, so a refused commit panics
/// in the writer thread and is re-raised by `join().expect(...)`; the counter is therefore either
/// `ROUNDS` or the test has already failed somewhere else. Worse, it cannot see the failure it is
/// nominally there to catch: a `commit` that returns `Ok` having persisted nothing increments it just
/// the same. "Counted after the call returned, not read off the loop bound" is literally true of such
/// a counter and operationally empty (`rmp` #1062, audit S2).
///
/// So the numbers below come from the store: `total_nodes` and the per-label counters as the catalog
/// holds them once every writer has joined, and every created node's labels read back through
/// `node_labels`. A commit that did nothing leaves the counters short; a commit that wrote the record
/// but lost the label leaves the read-back empty.
#[test]
fn the_run_really_commits_under_contention() {
    // Slot 0 is `total_nodes`; slot w+1 is writer w's label. Nothing is seeded, so every count is
    // exactly what the writers committed.
    let expected: Vec<u64> = std::iter::once(WRITERS as u64 * ROUNDS)
        .chain(std::iter::repeat_n(ROUNDS, WRITERS))
        .collect();
    for seed in SEEDS {
        let run = scenario(seed);
        assert!(
            run.history.switches > 0,
            "seed {seed:#x}: the scheduler never handed the token over, so the run was serial"
        );
        // `> WRITERS` is `>= WRITERS + 1`: every writer AND the root thread appear in the history.
        assert!(
            run.history.threads > WRITERS,
            "seed {seed:#x}: only {} logical thread(s) ran, so the {WRITERS} writers were not all \
             interleaved",
            run.history.threads
        );
        assert_eq!(
            run.live, expected,
            "seed {seed:#x}: the STORE's catalog holds {:?}, not {expected:?} — so a commit that \
             returned `Ok` did not leave its node behind, and every ordering verdict this file \
             reports was measured on a run that did less work than it claims",
            run.live
        );
        assert_eq!(
            run.labels_read_back.len(),
            WRITERS * ROUNDS as usize,
            "seed {seed:#x}: {} node(s) were created, not {}",
            run.labels_read_back.len(),
            WRITERS * ROUNDS as usize
        );
        for (i, (read, &written)) in run
            .labels_read_back
            .iter()
            .zip(run.labels_written.iter())
            .enumerate()
        {
            assert_eq!(
                read.as_slice(),
                &[written],
                "seed {seed:#x}: node #{i} was committed with label {written} but the store reads \
                 back {read:?}"
            );
        }
    }
}

/// **Determinism.** The same seed replays the same interleaving and the same verdict, which is what
/// makes a reproduction from a seed a reproduction at all.
#[test]
fn the_same_seed_replays_the_run_identically() {
    for seed in [SEEDS[0], SEEDS[7], SEEDS[15]] {
        let first = scenario(seed);
        let second = scenario(seed);
        assert_eq!(
            first.history.hash, second.history.hash,
            "seed {seed:#x}: the same seed produced two different interleavings"
        );
        assert_eq!(
            (first.descents, first.live),
            (second.descents, second.live),
            "seed {seed:#x}: the same seed produced two different verdicts"
        );
    }
}
