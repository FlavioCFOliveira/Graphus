//! **`rmp` #1055 — two commits' catalog images, and which one is left on disk.**
//!
//! # Closed, and by removing the question rather than by answering it (`rmp` #1067)
//!
//! Everything below this section describes the defect as it stood, and it is kept verbatim because
//! it is the measurement that chose the fix. What changed is the last line of the argument:
//!
//! > The durable counters are no longer an image of anything. A commit logs its cardinality change
//! > as its own WAL record before its `COMMIT` record, and the catalogue image carries a **base**
//! > plus the SET of transactions that base already accounts for. The durable answer is the base
//! > plus every retained delta the set does not name.
//!
//! Which of two concurrently computed images lands last therefore stops being a question anyone has
//! to answer. A stale image is not a wrong image: it names fewer transactions, and the ones it does
//! not name are still in the log. That is what makes both measured classes disappear **by
//! construction** rather than by becoming rarer:
//!
//! * **class A** — the image was correct when it was folded and stale when it landed. Whatever
//!   committed in between logged a delta, and the landed image does not claim to have folded it.
//! * **class B** — the transaction committed after the last catalogue write of the whole run, so no
//!   image could have contained it. Its delta is in the log all the same, and nothing has to write
//!   the catalogue again for recovery to find it.
//!
//! [`the_residual_shortfall_is_attributed`] is what keeps that honest: it asserts that the hazard
//! windows are **still entered** on these seeds — the fix removed the consequence, not the race.
//!
//! # The window
//!
//! **Every line number below names the code as it stood BEFORE `rmp` #1067**, which is the code the
//! measurement was taken against; they are kept because a measurement whose subject has been
//! paraphrased is no longer a measurement.
//!
//! Only a **commit** ever writes the catalog: `RecordStore::checkpoint` is the redo-bounding kind and
//! never touches it. So the durable catalog is whatever image the commit that wrote the metadata page
//! LAST put there — and `checkpoint_meta` does not compute and write that image as one step:
//!
//! * `crates/graphus-storage/src/store.rs:2941` SAMPLES the image (`snapshot_meta`, which reads the
//!   tokens and then `committed_statistics` — each under its own **shared** hold of the rank-10
//!   catalog latch, both released before it returns);
//! * `store.rs:2942` encodes it into the payload that will be written;
//! * `store.rs:2963` takes the catalog latch **exclusively**, but only to grow and copy the metadata
//!   page chain — the payload is already fixed by then — and `store.rs:2988` drops it;
//! * `store.rs:2990..3007` WRITES that payload, one `write_region` per metadata page.
//!
//! Nothing is held across the sample and the write, so with two committers
//! `compute(I1) compute(I2) write(I2) write(I1)` is a legal interleaving and the older `I1` is what
//! survives. That is a **lost update on the metadata page**, not a torn read of the counters — the
//! torn read was `rmp` #1052 and is fixed.
//!
//! # The hazard window is wider than the inversion
//!
//! Measured here rather than argued, because it decides what a fix has to cover.
//!
//! A checkpoint's image is the live counters MINUS every transaction whose delta is still pending.
//! `rmp` #1052 already retires a committing transaction's delta as early as it soundly can — at
//! `store.rs:4189..4193`, under the catalog latch, on the line after the `COMMIT` record is appended,
//! which is well before `settle_committed_txn`. So a transaction `T` is invisible to another
//! checkpoint's image over exactly the interval
//!
//! ```text
//!   [ T samples its own image , T retires its delta )
//!     store.rs:2941             store.rs:4189
//! ```
//!
//! and any checkpoint that folds inside that interval writes an image without `T`. The ficha's
//! inversion is the SUBSET of that in which the two page writes also swap:
//!
//! ```text
//! compute(I1) compute(I2) write(I2) write(I1)   -> I1 lands last, and I1 has no W2   (the inversion)
//! compute(I1) write(I1) compute(I2) write(I2)   -> I2 lands last, and I2 has no W1   (plain overlap:
//!                                                  I2 folded after W1 but before W1 retired)
//! ```
//!
//! Both leave the durable counters short by exactly one transaction's delta, and both are produced by
//! these seeds. [`the_checkpoint_order_is_attributed`] reports which shape each seed took, so the fix
//! is chosen against the measurement and not against the ficha.
//!
//! # What these seeds say about "elect the newest image"
//!
//! Measured 2026-08-12 on the sixteen seeds below, `gate` profile, Linux x86-64.
//! `the_durable_catalog_is_an_image_some_checkpoint_computed` (since `rmp` #1067
//! [`the_log_and_not_the_image_completes_the_durable_catalog`]) prints, per seed, the image that
//! landed AND the image that was sampled last. Ten seeds come back short, and on **all ten of them
//! the newest image sampled is itself incomplete** — on nine it is also the image that landed, so
//! electing it changes nothing whatsoever.
//!
//! That is the measurement a fix has to answer, and it is stated here rather than in a report because
//! it survives only if it is re-run: any scheme whose effect is "the newest image wins" — serialising
//! a checkpoint's sample against its own page writes, or refusing a write whose image has been
//! overtaken — leaves every one of these ten seeds short. Seed `0x3` is the cleanest witness: txn
//! 2004 sampled at step 559 and did not retire until 597, txn 1004 sampled at 587 — inside that
//! window, and last — so the newest image is the one missing a committed transaction's rows, and it
//! is the one already on disk.
//!
//! Only five of the ten failing seeds show the ficha's inversion at all (`0x2 0x5 0x8 0xb 0xf`); the
//! other five (`0x1 0x3 0xc 0xd 0xe`) fail with none.
//!
//! # The oracle
//!
//! Every writer's node is its own, so the ground truth is exact: after [`WRITERS`] writers have each
//! committed [`ROUNDS`] transactions that create one labelled node, `total_nodes` is the seeded count
//! plus the acknowledged commits, and each label's counter is its own writer's share plus its seed.
//! The counters are read **twice**:
//!
//! * **live** — the in-memory catalog. That is `rmp` #1052's property and it is expected to hold; it
//!   is asserted first and separately, so a failure of the durable assertion cannot be blamed on it.
//! * **durable** — the store reopened through its own device image and WAL. `rmp` #866 answers
//!   `count()` from this number and nothing recomputes it at `open`, so a short one is a wrong query
//!   answer that survives every restart.
//!
//! # Non-vacuity
//!
//! Asserted on every seed, never claimed:
//!
//! * the scheduler really handed the token over, every logical thread really ran, and the writes are
//!   **in the store** — the catalog's own counters against the workload's constants, and every
//!   created node's labels read back through `node_labels`. Never a tally incremented in the writer
//!   loop: such a tally cannot fail (a refused commit panics on its `expect` and is re-raised by
//!   `join`) and cannot see a `commit` that returns `Ok` having persisted nothing (`rmp` #1055);
//! * every acknowledged commit really yielded a fully located checkpoint — its image sample, its
//!   metadata-page write and its delta retirement — so a pairing rule that silently found nothing
//!   fails the suite instead of quietly emptying every order derived from it;
//! * the `compute(I1) compute(I2) write(I2) write(I1)` order really occurred, on named seeds, between
//!   named transactions ([`the_checkpoint_order_is_attributed`]);
//! * the hazard windows are still entered, and the image that landed last would still have been
//!   short of the committed truth had the log not covered it
//!   ([`the_log_and_not_the_image_completes_the_durable_catalog`]) — reconstructed from the recorded
//!   schedule alone and compared against a number read out of a real recovered store, so what the
//!   log is doing is demonstrated rather than assumed.
//!
//! # How the three instants are attributed
//!
//! A recorded step is where a thread hands the token OVER; the code after it runs when that thread is
//! scheduled again, in the segment ending at its next recorded step. Because the scheduler runs one
//! thread at a time, those segments are totally ordered by that index, so comparing two of them
//! compares when two pieces of code actually ran. All three instants below are resolved that way
//! (see [`resumed_after`]), and the distinction is load-bearing: on seed `0x7` a compute and a
//! retirement are one step apart and the naive comparison gets the image wrong.
//!
//! * **compute** — [`YieldSite::CatalogCommittedImage`], which `committed_statistics` offers with the
//!   committing transaction as its resource, so it names the transaction directly. The fold itself
//!   runs in the following segment, and takes no yield of its own (the catalog latch and the
//!   active-table shards are not scheduler-mediated), so it is that whole segment.
//! * **write** — the first [`YieldSite::FrameWriteWithPageMutLsn`] on the SAME thread after the
//!   compute. Exact rather than approximate: `checkpoint_meta` performs no other LSN-stamped page
//!   write in between — the chain-growth loop uses `with_page_mut` and `flush_unlogged` (distinct
//!   sites), `map_pages_up_to_high_water` runs strictly before the image is sampled, and the commit
//!   slot is published strictly after every metadata page has been written.
//! * **retirement** — [`YieldSite::CommitRegistryRecord`]. The delta is cleared at `store.rs:4189`,
//!   between the `COMMIT` record and that yield, with no other yield in between, so it runs in the
//!   segment ending at that step. `YieldSite::CommitSettle` is NOT the marker: by the time it is
//!   reached the delta has been empty for several steps.
//!
//! # Running it
//!
//! ```text
//! cargo test -p graphus-dst --features det-sched --test det_scheduler_checkpoint_inversion_1055
//! ```

use std::sync::Arc;

use graphus_core::sched::YieldSite;
use graphus_core::{PageId, TxnId};
use graphus_dst::detsched::{DetSchedConfig, SchedHistory, run_scheduled};
use graphus_io::{BlockDevice, MemBlockDevice, Page};
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

/// Scheduled committing writer threads. Two, which is the control the ficha records: at one writer
/// the window cannot be entered at all, because a second committer is what has to fold its image
/// inside the first one's.
const WRITERS: usize = 2;

/// Transactions each writer commits. Each is one node, one label, one commit — and therefore one
/// whole `checkpoint_meta`.
const ROUNDS: u64 = 4;

/// Buffer-pool frames. Comfortably above this workload's working set, so what is measured is the
/// checkpoint order and not the pool's eviction behaviour.
const POOL_PAGES: usize = 256;

/// The seeds this suite pins: `0..SEEDS`. A fixed range, not a sample — a seed that reproduces a
/// defect is evidence only if it is still run tomorrow.
///
/// **Two hundred and fifty-six, and the number is load-bearing.** At sixteen seeds this suite
/// reported two short seeds and the first proposed fix looked total; measured across 256 the same
/// build comes back short on 69, and a fix that closed the sixteen would have shipped as a 42 %
/// mitigation. The whole file runs in a few seconds per test at this width, so there is no reason to
/// measure a defect on a sixteenth of the evidence.
const SEEDS: u64 = 256;

/// Transaction-id stride per writer. Disjoint per writer, and far above the seed transaction, so a
/// transaction id in the recorded history resolves to exactly one writer.
const WRITER_STRIDE: u64 = 1_000;

/// The transaction id writer `w` uses in round `r`.
fn txn_of(w: usize, r: u64) -> TxnId {
    TxnId((w as u64 + 1) * WRITER_STRIDE + r + 1)
}

/// The writer a transaction id belongs to, or [`None`] for the seed transaction — which commits on
/// the root thread before any writer starts and is not part of the contended phase.
fn writer_of(txn: u64) -> Option<usize> {
    if txn < WRITER_STRIDE {
        return None;
    }
    let w = (txn / WRITER_STRIDE - 1) as usize;
    (w < WRITERS).then_some(w)
}

/// The transaction id a `ResourceId::txn(id)` names, or [`None`] for any other resource class.
///
/// The encoding is fixed by `graphus_core::sched::ResourceId`: class `5` in the top byte, the value
/// in the low 56 bits.
fn txn_of_resource(resource: u64) -> Option<u64> {
    const CLASS_TXN: u64 = 5;
    const VALUE_MASK: u64 = (1u64 << 56) - 1;
    (resource >> 56 == CLASS_TXN).then_some(resource & VALUE_MASK)
}

/// The step at which `thread` next RESUMES after yielding at `from` — i.e. the end of the segment in
/// which the code following that yield actually ran. See the module note on attribution.
fn resumed_after(steps: &[(u64, u32, u16, u8, u64)], from: usize, thread: u32) -> Option<usize> {
    (from + 1..steps.len()).find(|&j| steps[j].1 == thread)
}

/// One writer commit's `checkpoint_meta`, located in the recorded history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Checkpoint {
    /// The committing transaction.
    txn: u64,
    /// The logical thread that ran it.
    thread: u32,
    /// The step at which it offered the token before sampling its image
    /// (`YieldSite::CatalogCommittedImage`). Reported, because it is what names the ficha's order.
    compute: usize,
    /// The segment in which the image sample actually RAN.
    fold_at: usize,
    /// The step at which it WROTE the head metadata page.
    write: usize,
    /// The segment in which this transaction's count delta was RETIRED (`store.rs:4189`), after which
    /// no other checkpoint withdraws it.
    retire_at: usize,
}

/// What one scheduled run produced.
struct Run {
    /// `[total_nodes, L0, L1, …]` as the LIVE catalog held them once every writer had finished.
    live: Vec<u64>,
    /// The same vector, read out of the catalog a REOPEN recovered from the device image and the WAL.
    durable: Vec<u64>,
    /// The same vector, computed from the workload's own CONSTANTS — one seeded node per label plus
    /// [`ROUNDS`] per writer — and therefore from nothing the run itself reports.
    expected: Vec<u64>,
    /// The label token ids the store reports for each node the writers created, in creation order,
    /// read back through `node_labels` after every writer has joined.
    labels_read_back: Vec<Vec<u32>>,
    /// The label token id each of those nodes was created WITH, in the same order — the expectation
    /// `labels_read_back` is matched against.
    labels_written: Vec<u32>,
    /// `RecordStore::page_lsn_descents` on the live store, read after every writer has joined: the
    /// direct oracle for `rmp` #1062 (log order is apply order, per page). Zero is the invariant.
    page_lsn_descents: u64,
    history: SchedHistory,
}

/// Runs [`WRITERS`] scheduled committers against one store under the schedule `seed` names, then
/// reopens that store and reads the durable catalog back.
fn scenario(seed: u64) -> Run {
    // Switch at EVERY yield point: the window this scenario targets is the interval between a
    // checkpoint sampling its image and the committer it races retiring its delta, which the
    // amortised default would step over.
    let cfg = DetSchedConfig::exhaustive(seed);
    let ((live, durable, expected, labels_read_back, labels_written, page_lsn_descents), history) =
        run_scheduled(cfg, || {
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

            // One committed node per label, so every counter starts non-zero and a counter wrongly driven
            // to zero has somewhere to fall from. This transaction retires long before any writer starts,
            // so every writer's image legitimately contains it.
            let seed_txn = TxnId(1);
            store.begin(seed_txn);
            for &label in &labels {
                let (node, _) = store.create_node(seed_txn).expect("create the seed node");
                store
                    .add_label(seed_txn, node, label)
                    .expect("label the seed");
            }
            store.commit(seed_txn).expect("commit the seed");

            let threads: Vec<_> = (0..WRITERS)
                .map(|w| {
                    let store = Arc::clone(&store);
                    let label = labels[w];
                    graphus_core::sched::spawn("writer", move || {
                        // The physical ids this writer created, so the run is checked against what the
                        // STORE holds rather than against how many times this loop went round.
                        let mut created = Vec::with_capacity(ROUNDS as usize);
                        for r in 0..ROUNDS {
                            // Every writer's node is its own, so no round can be refused by the
                            // write-write conflict check and the expected counts are exact.
                            let txn = txn_of(w, r);
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

            let stats = store.statistics();
            let mut live = vec![stats.total_nodes()];
            live.extend(labels.iter().map(|&l| stats.node_count_for_label(l)));
            drop(stats);

            // Read back OUT OF THE STORE, after every writer has joined.
            let labels_written: Vec<u32> = created.iter().map(|&(_, l)| l).collect();
            let labels_read_back: Vec<Vec<u32>> = created
                .iter()
                .map(|&(node, _)| {
                    store
                        .node_labels(node)
                        .expect("read a created node's labels")
                })
                .collect();

            // From the workload's CONSTANTS, not from anything the run counted: one node per label was
            // seeded, and each of the [`WRITERS`] writers commits exactly [`ROUNDS`] more. Deriving it
            // from a per-writer tally would route the ground truth through a counter incremented after
            // `commit` returned — which cannot disagree with `ROUNDS`, because a refused commit panics on
            // the `expect` above and is re-raised by `join`, and which in any case cannot see a `commit`
            // that returns `Ok` having persisted nothing.
            let mut expected = vec![WRITERS as u64 * ROUNDS + WRITERS as u64];
            expected.extend(std::iter::repeat_n(ROUNDS + 1, WRITERS));

            // The `rmp` #1062 oracle, read off the store that did the writing and BEFORE the reopen
            // stages a fresh device: it counts what the runtime did to the pages, which is what
            // recovery's `record.lsn > page_lsn` gate is compared against.
            let page_lsn_descents = store.page_lsn_descents();

            // THE REOPEN, and it is what makes this suite about the DURABLE catalog rather than the live
            // one. NO `checkpoint()` first, deliberately: the image the last commit wrote must be the one
            // a reopen finds, and `checkpoint()` would not rewrite it anyway. The shape is the
            // steal-crash recovery the rest of the workspace uses — flush the dirty pages home, stage
            // that device image, replay the durable WAL prefix over it.
            store.flush().expect("flush the dirty pages home");
            let mapped = store.mapped_pages();
            let max = mapped.iter().map(|p| p.0).max().unwrap_or(0);
            let staged: Vec<(u64, Box<Page>)> = mapped
                .iter()
                .map(|p| (p.0, store.read_device_page(*p).expect("read device page")))
                .collect();
            let mut device = MemBlockDevice::new(max + 1);
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
            let reopened =
                RecordStore::open(device, wal, POOL_PAGES).expect("open the recovered store");
            let stats = reopened.statistics();
            let mut durable = vec![stats.total_nodes()];
            durable.extend(labels.iter().map(|&l| stats.node_count_for_label(l)));
            drop(stats);

            (
                live,
                durable,
                expected,
                labels_read_back,
                labels_written,
                page_lsn_descents,
            )
        });
    Run {
        live,
        durable,
        expected,
        labels_read_back,
        labels_written,
        page_lsn_descents,
        history,
    }
}

/// Every writer commit's `checkpoint_meta`, with the instants this suite reasons from. A commit
/// contributes an entry only when ALL of them are located, and
/// [`the_run_really_checkpoints_under_contention`] requires one entry per acknowledged commit.
fn checkpoints(history: &SchedHistory) -> Vec<Checkpoint> {
    let steps = history.decode();
    // The delta is cleared between the `COMMIT` record and this yield, with no other yield in
    // between, so it runs in the segment ending here. See the module note on attribution.
    let mut retire: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for (i, &(_, _, site, _, resource)) in steps.iter().enumerate() {
        if site == YieldSite::CommitRegistryRecord.code()
            && let Some(txn) = txn_of_resource(resource)
            && writer_of(txn).is_some()
        {
            retire.insert(txn, i);
        }
    }

    let mut out = Vec::new();
    for (i, &(_, thread, site, _, resource)) in steps.iter().enumerate() {
        if site != YieldSite::CatalogCommittedImage.code() {
            continue;
        }
        let Some(txn) = txn_of_resource(resource) else {
            continue;
        };
        if writer_of(txn).is_none() {
            continue;
        }
        let Some(write) = (i + 1..steps.len()).find(|&j| {
            steps[j].1 == thread && steps[j].2 == YieldSite::FrameWriteWithPageMutLsn.code()
        }) else {
            continue;
        };
        let Some(fold_at) = resumed_after(&steps, i, thread) else {
            continue;
        };
        let Some(&retire_at) = retire.get(&txn) else {
            continue;
        };
        out.push(Checkpoint {
            txn,
            thread,
            compute: i,
            fold_at,
            write,
            retire_at,
        });
    }
    out
}

/// **The counters checkpoint `owner`'s image would have carried before `rmp` #1067** —
/// reconstructed from the recorded schedule alone.
///
/// The image is the seeded node per label, plus `owner`'s own commit — which `committed_statistics`
/// excludes from the withdrawal by name — plus every other writer commit that had already RETIRED its
/// delta when `owner` folded.
///
/// Since #1067 no image carries these numbers: the counters left the image and what is persisted is
/// a base plus the set of transactions folded into it, and in this scenario nothing ever folds (the
/// 64 MiB checkpoint cadence is never reached), so every image's base is the same empty one. That
/// makes this function **the shortfall the log now covers**, which is precisely why it is kept: it
/// is the only way to state what the durable catalogue would have been without the log, and
/// therefore the only way to show that the log is what completes it
/// ([`the_log_and_not_the_image_completes_the_durable_catalog`]).
fn image_without_the_log(owner: &Checkpoint, cps: &[Checkpoint]) -> Option<Vec<u64>> {
    // Slot 0 is total_nodes; slot w+1 is writer w's label. Each starts at its seeded node.
    let mut out = vec![WRITERS as u64];
    out.extend(std::iter::repeat_n(1u64, WRITERS));
    for c in cps {
        let w = writer_of(c.txn)?;
        if c.txn == owner.txn || c.retire_at < owner.fold_at {
            out[0] += 1;
            out[w + 1] += 1;
        }
    }
    Some(out)
}

/// Every `compute(I1) compute(I2) write(I2) write(I1)` pair in one run: `(older image, newer image)`.
///
/// `a.compute < b.compute` makes `a`'s image the OLDER one and `b.write < a.write` puts `a`'s write
/// last, so the newer image `b` computed is overwritten by the older image `a` computed. `b`'s own
/// `compute < write` holds by construction, so the four steps stand in exactly that order.
fn inversions(cps: &[Checkpoint]) -> Vec<(Checkpoint, Checkpoint)> {
    let mut out = Vec::new();
    for a in cps {
        for b in cps {
            if a.txn != b.txn && a.compute < b.compute && b.write < a.write {
                out.push((*a, *b));
            }
        }
    }
    out
}

/// Every pair `(victim, folder)` in which `folder` sampled its image inside `victim`'s hazard window
/// — after `victim` sampled its own and before `victim` retired its delta — so `folder`'s image is
/// missing `victim`'s rows. This is the general shape; [`inversions`] is the subset in which the two
/// page writes also swap.
fn hazard_folds(cps: &[Checkpoint]) -> Vec<(Checkpoint, Checkpoint)> {
    let mut out = Vec::new();
    for victim in cps {
        for folder in cps {
            if victim.txn != folder.txn
                && victim.fold_at < folder.fold_at
                && folder.fold_at < victim.retire_at
            {
                out.push((*victim, *folder));
            }
        }
    }
    out
}

/// **The property.** The catalog a reopen recovers holds every acknowledged commit.
///
/// FAILS today: `rmp` #1055 is live. The live counters are asserted first and separately, because the
/// two failures have different causes and one combined assertion would hide which fired — a wrong
/// LIVE counter is `rmp` #1052 (fixed), while a right live counter with a wrong DURABLE one is this
/// task's lost update on the metadata page.
#[test]
fn the_durable_catalog_holds_every_committed_delta() {
    let mut short = Vec::new();
    for seed in 0..SEEDS {
        let run = scenario(seed);
        assert_eq!(
            run.live, run.expected,
            "seed {seed:#x}: the LIVE counters drifted, which is `rmp` #1052 and not this task. Slot \
             0 is total_nodes and slot w+1 is writer w's label"
        );
        if run.durable != run.expected {
            let cps = checkpoints(&run.history);
            short.push(format!(
                "seed {seed:#x}: durable {:?} != committed {:?} (short by {}), {} inversion(s), {} \
                 hazard-window fold(s)",
                run.durable,
                run.expected,
                run.expected[0] as i64 - run.durable[0] as i64,
                inversions(&cps).len(),
                hazard_folds(&cps).len(),
            ));
        }
    }
    assert!(
        short.is_empty(),
        "the durable catalog is short of what the writers committed, so a commit's catalog image was \
         overwritten by an image that did not contain it. Only a commit writes the catalog \
         (`RecordStore::checkpoint` bounds redo and never touches it), and `checkpoint_meta` samples \
         its image at `store.rs:2941` and writes it at `store.rs:2990..3007` holding nothing in \
         between (`rmp` #1055). `rmp` #866 answers count() from this number and nothing recomputes it \
         at open, so this is a wrong query answer that survives every restart:\n{}",
        short.join("\n")
    );
}

/// **Non-vacuity, and the window by name.** The `compute(I1) compute(I2) write(I2) write(I1)` order
/// really occurred, on named seeds, between named transactions.
///
/// Fully attributed rather than inferred: every endpoint of both checkpoints is located in the
/// recorded history (see the module note on how, and why each is exact). Without this the property
/// above would be satisfied by sixteen runs in which no two checkpoints ever raced — a by-seed
/// reproduction that reproduces nothing.
///
/// The hazard-window folds are counted and printed beside it, because they lose a delta too and the
/// choice of fix depends on which shape the seeds actually take.
#[test]
fn the_checkpoint_order_is_attributed() {
    let mut inverted = Vec::new();
    let mut hazard = Vec::new();
    for seed in 0..SEEDS {
        let run = scenario(seed);
        let cps = checkpoints(&run.history);
        let short = run.durable != run.expected;
        let tag = if short { " (durable short)" } else { "" };
        for (older, newer) in inversions(&cps) {
            inverted.push(format!(
                "seed {seed:#x}: txn {} computed at step {} and wrote at step {}; txn {} computed at \
                 step {} and wrote at step {} — so the OLDER image landed last{tag}",
                older.txn, older.compute, older.write, newer.txn, newer.compute, newer.write,
            ));
        }
        for (victim, folder) in hazard_folds(&cps) {
            hazard.push(format!(
                "seed {seed:#x}: txn {} folded at {} and retired at {}; txn {} folded at {} — inside \
                 that window — so txn {}'s image has no rows of txn {}{tag}",
                victim.txn,
                victim.fold_at,
                victim.retire_at,
                folder.txn,
                folder.fold_at,
                folder.txn,
                victim.txn,
            ));
        }
    }
    // Printed so the strength of the witness is a measured number rather than a claim.
    println!(
        "{} inverted pair(s) across {} seeds:\n{}",
        inverted.len(),
        SEEDS,
        inverted.join("\n")
    );
    println!(
        "{} hazard-window fold(s) across {} seeds:\n{}",
        hazard.len(),
        SEEDS,
        hazard.join("\n")
    );
    assert!(
        !inverted.is_empty(),
        "no seed produced `compute(I1) compute(I2) write(I2) write(I1)`, so the interleaving `rmp` \
         #1055 names was never sampled and these seeds prove nothing about it"
    );
}

/// **The mechanism, demonstrated: the LOG is what completes the durable catalog, not the image.**
///
/// This is the re-aimed successor of `the_durable_catalog_is_an_image_some_checkpoint_computed`,
/// which asserted that a reopen always recovers exactly the counters ONE of this run's checkpoints
/// sampled. That was true, and it was the whole defect: the durable number was decided by an image,
/// so it was decided by whichever commit wrote the metadata page last. Since `rmp` #1067 the
/// counters are not in the image at all, so the old claim is not merely no longer asserted — it is
/// **false by design**, and a suite that still asserted it would be asserting the defect.
///
/// What replaces it has to be stronger, not weaker, so it asserts the two halves that together say
/// the log did the work:
///
/// 1. **the image alone would have been short.** [`image_without_the_log`] reconstructs, from the
///    recorded schedule alone, the counters the image that landed LAST would have carried under the
///    old design. On the seeds where that is short of the committed truth, the durable catalog is
///    nevertheless exact — so the difference came from somewhere, and the only other thing a reopen
///    reads is the log;
/// 2. **that case really occurs**, on a counted number of these seeds. Without this the test would
///    pass on a battery in which every image happened to be complete and would prove nothing about
///    the log at all. It is the same non-vacuity the old test bought with `unmatched.is_empty()`,
///    pointed at the mechanism that is now load-bearing.
#[test]
fn the_log_and_not_the_image_completes_the_durable_catalog() {
    let mut short_images = Vec::new();
    let mut durable_wrong = Vec::new();
    for seed in 0..SEEDS {
        let run = scenario(seed);
        let cps = checkpoints(&run.history);
        let last = cps
            .iter()
            .max_by_key(|c| c.write)
            .expect("every seed runs at least one checkpoint");
        let landed = image_without_the_log(last, &cps)
            .expect("the last checkpoint's image is reconstructible");
        if landed != run.expected {
            short_images.push(format!(
                "seed {seed:#x}: the image txn {} wrote last would have carried {:?} against a \
                 committed {:?} (short by {}); the durable catalog read back {:?}",
                last.txn,
                landed,
                run.expected,
                run.expected[0] as i64 - landed[0] as i64,
                run.durable,
            ));
        }
        if run.durable != run.expected {
            durable_wrong.push(format!(
                "seed {seed:#x}: durable {:?} != committed {:?}",
                run.durable, run.expected
            ));
        }
    }
    println!(
        "{} of {SEEDS} seed(s) landed an image that is short of the committed truth; the log \
         covered every one of them:\n{}",
        short_images.len(),
        short_images.join("\n")
    );
    assert!(
        durable_wrong.is_empty(),
        "a reopen came back with counters the workload did not commit, so the base plus the \
         retained deltas is not the committed truth (`rmp` #1067):\n{}",
        durable_wrong.join("\n")
    );
    assert!(
        !short_images.is_empty(),
        "NON-VACUITY: on every one of these {SEEDS} seeds the image that landed last was ALREADY \
         complete, so this battery never exercised the case the logged delta exists for and the \
         assertion above proves nothing about the log. The seeds, the writer count or the round \
         count must be changed until the case reappears"
    );
}

/// **`rmp` #1062 — log order is apply order, per page.**
///
/// # Why this test had to be re-aimed, and what it lost
///
/// It used to compare the counters a reopen recovered against the counters the LAST metadata-page
/// write in the recorded schedule would have applied — a derived oracle for #1062, and a sharp one:
/// it caught seed `0x1` recovering txn 1004's image while txn 2004's write was the one that landed,
/// because `write_region` appended its record and applied it to the page as two separately scheduled
/// steps, so the record recovery replayed last was not the write that reached the page last.
///
/// That oracle **cannot discriminate any more**, and saying so is the point. Since `rmp` #1067 the
/// counters are not decided by the image: this scenario never reaches the 64 MiB checkpoint cadence,
/// so no fold ever runs, so every image carries the same empty base and two images differ in nothing
/// a reopen can read back. A test comparing them would be comparing two equal vectors on every seed
/// — green for ever, and vacuous.
///
/// So this asserts the **direct** oracle instead, in this scenario, on every seed:
/// [`RecordStore::page_lsn_descents`] counts pages stamped with an LSN below the one they already
/// carried, which is the inversion itself rather than a consequence of it. Zero is the invariant.
///
/// The positive control for it is `graphus-dst`'s `page_log_apply_order_1062` battery, which drives
/// the same counter under a workload built to invert it and asserts what a reverted
/// `RecordStore::in_page_order` produces. What this test adds is coverage of THIS schedule: two
/// committers hammering the metadata page chain, which is the shape #1062 was found in.
///
/// MEASURED, `gate` profile, Linux x86-64, 2026-08-12: zero descents on all 256 seeds.
#[test]
fn the_runtime_and_recovery_agree_on_page_order() {
    let mut diverged = Vec::new();
    for seed in 0..SEEDS {
        let run = scenario(seed);
        if run.page_lsn_descents != 0 {
            diverged.push(format!(
                "seed {seed:#x}: {} page(s) were stamped with an LSN below the one they already \
                 carried",
                run.page_lsn_descents
            ));
        }
    }
    assert!(
        diverged.is_empty(),
        "a page took an LSN backwards, so the order in which writes entered the log is not the order \
         in which they took effect on the page (`rmp` #1062). Every logged page write must append and \
         apply inside one `RecordStore::in_page_order` section keyed by the device page; recovery is \
         gated on `record.lsn > page_lsn`, so a descent lets redo re-apply an older record over a \
         newer page:\n{}",
        diverged.join("\n")
    );
}

/// **The residual shortfall, classified — and the measurement that refutes both proposed fixes.**
///
/// Run 2026-08-12, after `rmp` #1062 closed the log-order/apply-order divergence, on the sixteen
/// seeds below. Two remain short (`0x2`, `0xe`), and they are **two different mechanisms**. This test
/// names which, per seed, so that a fix is chosen against the measurement instead of against the
/// ficha's description.
///
/// Write `L` for the checkpoint whose metadata-page write landed LAST, and `C` for any other
/// checkpoint. `L`'s image contains `C`'s rows **iff** `C` retired its count delta before `L` folded
/// its image ([`image_without_the_log`]). So a shortfall is one of exactly two shapes:
///
/// * **Class A — the image was wrong by the time it landed.** `L.fold_at <= C.retire_at < L.write`:
///   `C` committed after `L` sampled but before `L`'s write landed. The image `L` wrote was correct
///   when it was folded and had become stale by the time it hit the page. Seed `0x2`: `L` = txn 2004
///   (fold 585, write 597), `C` = txn 1004 (retire **591**).
/// * **Class B — the last commit is not the last catalog write.** `C.retire_at >= L.write`: `C`
///   committed after the last catalog write in the whole run, so **no** image could have contained it
///   — nothing wrote the catalog afterwards. Seed `0xe`: `L` = txn 2004 (fold 585, write **589**),
///   `C` = txn 1004 (retire **598**).
///
/// # What this costs the two options in the ficha
///
/// Both are refuted, and by the same run:
///
/// * *"hold the catalog latch across the writes"* — serialises a checkpoint's sample against its own
///   page writes. It cannot help either class. In class A the two are already in order (`L` folded
///   before it wrote); what changed underneath was another transaction's retirement, which that latch
///   does not order against. In class B there is no second write to order at all.
/// * *"compare-and-publish on an image version, refusing a write whose image has been overtaken"* —
///   elects the newest image. On **both** short seeds the newest image sampled IS the image that
///   landed and IS the incomplete one, so refusing anything changes nothing. Stronger still, and
///   printed below: **no checkpoint in either run ever sampled a complete image**, so no scheme that
///   elects among the images that exist can produce the right answer.
///
/// Class B also refutes the sharper invariant *"the image that lands last must reflect every
/// transaction that committed before it landed"*: seed `0xe` **satisfies** it and is still short.
///
/// # What this test asserts NOW (`rmp` #1067), and why it is the fix's positive control
///
/// The two classes above are closed, so there are no short seeds left to classify — and a test whose
/// only assertion is "every short seed is explained" would pass on an empty list for ever. That is
/// the vacuity trap this file has already fallen into once (the settling commit `rmp` #1055 removed),
/// so the assertion is turned around and now carries the burden the other direction:
///
/// 1. **the windows are still ENTERED.** Class A and class B are counted over the whole battery from
///    the recorded schedule, exactly as before, and the test fails if neither occurs. The fix removed
///    the consequence, not the race: a build in which these windows stopped happening — a scheduler
///    change, a workload change, a serialisation someone added to the commit path — would make every
///    other assertion in this file a statement about a run that no longer reproduces anything;
/// 2. **and no seed is short anyway.** Kept here as well as in
///    [`the_durable_catalog_holds_every_committed_delta`], because the pairing is the whole claim:
///    "the window was entered AND the answer is right" is what "closed by construction" means, and
///    the two halves asserted in different tests could drift apart without anyone noticing.
///
/// Anything short is still classified, and an unclassified shortfall still fails: if this ever goes
/// red, the printed row says which of the two shapes came back.
#[test]
fn the_residual_shortfall_is_attributed() {
    let mut rows = Vec::new();
    let mut unexplained = Vec::new();
    let mut seeds_with_class_a = 0usize;
    let mut seeds_with_class_b = 0usize;
    for seed in 0..SEEDS {
        let run = scenario(seed);
        let cps = checkpoints(&run.history);
        let last = cps
            .iter()
            .max_by_key(|c| c.write)
            .expect("every seed runs at least one checkpoint");
        // The two shapes, computed on EVERY seed and not only on the short ones: since `rmp` #1067
        // they are windows that were entered rather than failures that occurred, and counting them
        // only where the answer came out wrong would count nothing at all.
        let class_a: Vec<u64> = cps
            .iter()
            .filter(|c| {
                c.txn != last.txn && c.retire_at >= last.fold_at && c.retire_at < last.write
            })
            .map(|c| c.txn)
            .collect();
        let class_b: Vec<u64> = cps
            .iter()
            .filter(|c| c.txn != last.txn && c.retire_at >= last.write)
            .map(|c| c.txn)
            .collect();
        seeds_with_class_a += usize::from(!class_a.is_empty());
        seeds_with_class_b += usize::from(!class_b.is_empty());
        if run.durable == run.expected {
            continue;
        }
        let complete: Vec<u64> = cps
            .iter()
            .filter(|c| image_without_the_log(c, &cps).as_ref() == Some(&run.expected))
            .map(|c| c.txn)
            .collect();
        let row = format!(
            "seed {seed:#x}: durable {:?} expected {:?}; LAST write txn {} (fold {}, write {}), \
             image-without-the-log {:?}. Class A (committed between the fold and the landing): \
             {class_a:?}. Class B (committed after the last catalog write): {class_b:?}. \
             Checkpoints whose image is COMPLETE: {complete:?}",
            run.durable,
            run.expected,
            last.txn,
            last.fold_at,
            last.write,
            image_without_the_log(last, &cps),
        );
        if class_a.is_empty() && class_b.is_empty() {
            unexplained.push(row.clone());
        }
        rows.push(row);
    }
    println!(
        "{} short seed(s) of {SEEDS}; class A entered on {seeds_with_class_a} seed(s), class B on \
         {seeds_with_class_b}:\n{}",
        rows.len(),
        rows.join("\n")
    );
    assert!(
        seeds_with_class_a > 0 && seeds_with_class_b > 0,
        "NON-VACUITY: class A was entered on {seeds_with_class_a} of {SEEDS} seeds and class B on \
         {seeds_with_class_b}, and both must be non-zero. These are the two windows `rmp` #1055 \
         measured — a transaction committing between another checkpoint's fold and its landing, and \
         a transaction committing after the last catalog write of the whole run. #1067 removed what \
         they COST, not the windows themselves, so a battery that no longer enters them proves \
         nothing about the fix and every other assertion here is about a run that reproduces nothing"
    );
    assert!(
        rows.is_empty(),
        "a seed came back short. The durable counters are a base plus every retained delta the \
         applied set does not name, so a shortfall means one of the two is wrong — a delta that was \
         never logged, a record reclaimed before the base absorbed it, or an applied set naming a \
         transaction the base does not hold (`rmp` #1067):\n{}",
        rows.join("\n")
    );
    assert!(
        unexplained.is_empty(),
        "a seed came back short and fits NEITHER named mechanism, so the cause is not the one this \
         file describes:\n{}",
        unexplained.join("\n")
    );
}

/// **Non-vacuity of the run itself.** The scheduler really interleaved the threads, every writer
/// acknowledged every commit, and every one of those commits produced a checkpoint whose three
/// instants were all located.
///
/// The last clause is what stops the attribution above from being quietly empty: a pairing rule that
/// located nothing would make [`inversions`] and [`hazard_folds`] trivially empty and the whole suite
/// vacuous.
#[test]
fn the_run_really_checkpoints_under_contention() {
    for seed in 0..SEEDS {
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
        // Store-side evidence, not a loop counter (`rmp` #1055). A tally incremented on the line
        // after `commit` returned cannot fail — a refused commit panics on the `expect` and is
        // re-raised by `join`, so the tally is either `ROUNDS` or the test already failed elsewhere —
        // and it cannot see the failure it would nominally be there to catch: a `commit` that returns
        // `Ok` having persisted nothing increments it just the same. These numbers come out of the
        // store: the catalog's own counters, and every created node's labels read back.
        assert_eq!(
            run.live, run.expected,
            "seed {seed:#x}: the STORE's catalog holds {:?}, not the {:?} this workload commits by \
             construction — so a commit that returned `Ok` did not leave its node behind, and every \
             checkpoint order derived from this run was measured on less work than it claims",
            run.live, run.expected
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
        let cps = checkpoints(&run.history);
        assert_eq!(
            cps.len(),
            WRITERS * ROUNDS as usize,
            "seed {seed:#x}: {} checkpoint(s) were attributed for {} acknowledged commits, so the \
             pairing missed some and every order derived from it is unsound",
            cps.len(),
            WRITERS * ROUNDS as usize
        );
        // Each instant fires, and in the only order `checkpoint_meta` can produce.
        for c in &cps {
            assert!(
                c.compute < c.fold_at && c.fold_at <= c.write && c.write < c.retire_at,
                "seed {seed:#x}: txn {}'s checkpoint reads compute {} fold {} write {} retire {}, \
                 which is not the order `commit_prepare_at` executes them in",
                c.txn,
                c.compute,
                c.fold_at,
                c.write,
                c.retire_at
            );
            assert!(
                image_without_the_log(c, &cps).is_some(),
                "seed {seed:#x}: txn {}'s image could not be reconstructed",
                c.txn
            );
        }
    }
}

/// **Determinism.** The same seed replays the same interleaving and the same durable catalog, which
/// is what makes a reproduction from a seed a reproduction at all.
#[test]
fn the_same_seed_replays_the_run_identically() {
    for seed in [0, 0x2, 0xe, SEEDS - 1] {
        let first = scenario(seed);
        let second = scenario(seed);
        assert_eq!(
            first.history.hash, second.history.hash,
            "seed {seed:#x}: the same seed produced two different interleavings"
        );
        assert_eq!(
            (first.live, first.durable),
            (second.live, second.durable),
            "seed {seed:#x}: the same seed produced two different catalogs"
        );
    }
}
