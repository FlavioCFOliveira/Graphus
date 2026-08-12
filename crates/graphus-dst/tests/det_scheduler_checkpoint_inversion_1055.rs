//! **`rmp` #1055 — two commits' catalog images, and which one is left on disk.**
//!
//! # The window
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
//! [`the_durable_catalog_is_an_image_some_checkpoint_computed`] prints, per seed, the image that
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
//! * the scheduler really handed the token over, every logical thread really ran, and the writers
//!   **acknowledged** every commit — counted after `commit` returned, never read off the loop bound;
//! * every acknowledged commit really yielded a fully located checkpoint — its image sample, its
//!   metadata-page write and its delta retirement — so a pairing rule that silently found nothing
//!   fails the suite instead of quietly emptying every order derived from it;
//! * the `compute(I1) compute(I2) write(I2) write(I1)` order really occurred, on named seeds, between
//!   named transactions ([`the_checkpoint_order_is_attributed`]);
//! * what a reopen recovered really is one of the images this run's checkpoints sampled, and which
//!   one ([`the_durable_catalog_is_an_image_some_checkpoint_computed`]) — the reconstruction is made
//!   from the recorded schedule alone and matched against a number read out of a real recovered
//!   store, so the mechanism is demonstrated rather than assumed.
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

/// The seeds this suite pins. A fixed list, not a sample: a seed that reproduces a defect is evidence
/// only if it is still run tomorrow.
const SEEDS: [u64; 16] = [
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
];

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
    /// The same vector, computed from what the writers acknowledged.
    expected: Vec<u64>,
    /// Commits each writer ACKNOWLEDGED, counted on the line after `commit` returned.
    committed: Vec<u64>,
    history: SchedHistory,
}

/// Runs [`WRITERS`] scheduled committers against one store under the schedule `seed` names, then
/// reopens that store and reads the durable catalog back.
fn scenario(seed: u64) -> Run {
    // Switch at EVERY yield point: the window this scenario targets is the interval between a
    // checkpoint sampling its image and the committer it races retiring its delta, which the
    // amortised default would step over.
    let cfg = DetSchedConfig::exhaustive(seed);
    let ((live, durable, expected, committed), history) = run_scheduled(cfg, || {
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
                    // COUNTED on the line after `commit` returns, never assumed from the loop bound.
                    let mut committed = 0u64;
                    for r in 0..ROUNDS {
                        // Every writer's node is its own, so no round can be refused by the
                        // write-write conflict check and the expected counts are exact.
                        let txn = txn_of(w, r);
                        store.begin(txn);
                        let (node, _) = store.create_node(txn).expect("create a node");
                        store.add_label(txn, node, label).expect("label the node");
                        store.commit(txn).expect("a disjoint write always commits");
                        committed += 1;
                    }
                    committed
                })
            })
            .collect();
        let committed: Vec<u64> = threads
            .into_iter()
            .map(|t| t.join().expect("a writer thread joins"))
            .collect();

        let stats = store.statistics();
        let mut live = vec![stats.total_nodes()];
        live.extend(labels.iter().map(|&l| stats.node_count_for_label(l)));
        drop(stats);

        // One node per label was seeded; every acknowledged round added exactly one more.
        let mut expected = vec![committed.iter().sum::<u64>() + WRITERS as u64];
        expected.extend(committed.iter().map(|c| c + 1));

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

        (live, durable, expected, committed)
    });
    Run {
        live,
        durable,
        expected,
        committed,
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

/// The counters checkpoint `owner` SAMPLED, reconstructed from the recorded schedule alone.
///
/// The image is the seeded node per label, plus `owner`'s own commit — which `committed_statistics`
/// excludes from the withdrawal by name — plus every other writer commit that had already RETIRED its
/// delta when `owner` folded.
fn image_of(owner: &Checkpoint, cps: &[Checkpoint]) -> Option<Vec<u64>> {
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
    for seed in SEEDS {
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
    for seed in SEEDS {
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
        SEEDS.len(),
        inverted.join("\n")
    );
    println!(
        "{} hazard-window fold(s) across {} seeds:\n{}",
        hazard.len(),
        SEEDS.len(),
        hazard.join("\n")
    );
    assert!(
        !inverted.is_empty(),
        "no seed produced `compute(I1) compute(I2) write(I2) write(I1)`, so the interleaving `rmp` \
         #1055 names was never sampled and these seeds prove nothing about it"
    );
}

/// **The mechanism, demonstrated.** What a reopen recovers is always the image ONE of this run's
/// checkpoints sampled — never a blend, and never the committed truth unless that one image happened
/// to be complete.
///
/// This is what turns "the durable catalog is short" into a named cause. Every candidate image is
/// reconstructed from the recorded schedule alone and the number a real recovered store read back is
/// matched against the set. The matching checkpoint is printed beside the last one by **page-apply**
/// order, and the two need not agree: `write_region` appends its WAL record (`store.rs:3198`) and
/// applies it to the page (`store.rs:3201`) as two separately scheduled steps, so the record recovery
/// replays last need not be the write that landed on the page last — the `rmp` #1028 hazard, log
/// order against apply order, measured here rather than assumed.
#[test]
fn the_durable_catalog_is_an_image_some_checkpoint_computed() {
    let mut rows = Vec::new();
    let mut unmatched = Vec::new();
    for seed in SEEDS {
        let run = scenario(seed);
        let cps = checkpoints(&run.history);
        let last = cps
            .iter()
            .max_by_key(|c| c.write)
            .expect("every seed runs at least one checkpoint");
        // The image sampled LAST, which is what a compare-and-publish scheme keyed on an image
        // version would elect. Reported beside the one that actually landed, because the two together
        // say whether electing the newest image would have been enough.
        let newest = cps
            .iter()
            .max_by_key(|c| c.fold_at)
            .expect("every seed runs at least one checkpoint");
        let matching: Vec<u64> = cps
            .iter()
            .filter(|c| image_of(c, &cps).as_ref() == Some(&run.durable))
            .map(|c| c.txn)
            .collect();
        let row = format!(
            "seed {seed:#x}: durable {:?}, committed {:?} — is the image of txn {:?}; the LAST page \
             write was txn {}'s, image {:?}; the NEWEST image sampled was txn {}'s, image {:?} — {} \
             inversion(s), {} hazard-window fold(s)",
            run.durable,
            run.expected,
            matching,
            last.txn,
            image_of(last, &cps),
            newest.txn,
            image_of(newest, &cps),
            inversions(&cps).len(),
            hazard_folds(&cps).len(),
        );
        if matching.is_empty() {
            unmatched.push(row.clone());
        }
        rows.push(row);
    }
    println!("{}", rows.join("\n"));
    assert!(
        unmatched.is_empty(),
        "the durable catalog matches NO image any checkpoint sampled, so `rmp` #1055 is not the whole \
         cause of what these seeds produce and a fix would be chosen against a mechanism that has not \
         been identified:\n{}",
        unmatched.join("\n")
    );
}

/// **`rmp` #1062 — what recovery rebuilds is what the last page write applied.**
///
/// The two are separate claims and this is the one that says they coincide. `run.durable` is read out
/// of a store a reopen genuinely recovered from a device image and a WAL prefix; `last.write` is the
/// last `checkpoint_meta` page write in the recorded schedule, i.e. what a crash-free execution left
/// on the page. If ARIES and the runtime disagree about which image is last, the durable answer with
/// no crash and the durable answer after a crash differ, and no discussion of *which* image ought to
/// win can even be held — the durable catalog is not yet a well-defined object.
///
/// This is deliberately NOT the completeness property above: the image that landed may still be
/// missing a committed transaction's rows (the hazard-window fold, `rmp` #1055), and on the seeds
/// that produce one this test passes while
/// [`the_durable_catalog_holds_every_committed_delta`] fails. What it asserts is only that the two
/// mechanisms name the SAME image.
///
/// MEASURED, `gate` profile, Linux x86-64, 2026-08-12:
///
/// * before `rmp` #1062 — seed `0x1` recovered `[9, 5, 4]`, txn 1004's image, while the last page
///   write in the recorded schedule was txn 2004's `[9, 4, 5]`. `write_region` appended its record
///   (`store.rs:3198`) and applied it (`store.rs:3201`) as two separately scheduled steps, so txn
///   1004 appended LAST and applied FIRST: `page_lsn` came to rest at txn 2004's lower LSN, and
///   redo — gated on `record.lsn > page_lsn` — then re-applied txn 1004's higher-LSN record on top
///   of a page that did not contain it. One seed of sixteen;
/// * after — all sixteen seeds recover exactly the image their last page write applied.
///
/// It is therefore also this task's positive control: revert
/// `RecordStore::in_page_order`'s rank-27 section to a bare `body()` and seed `0x1` fails here again.
#[test]
fn the_durable_catalog_is_the_image_the_last_page_write_applied() {
    let mut diverged = Vec::new();
    for seed in SEEDS {
        let run = scenario(seed);
        let cps = checkpoints(&run.history);
        let last = cps
            .iter()
            .max_by_key(|c| c.write)
            .expect("every seed runs at least one checkpoint");
        let applied = image_of(last, &cps).expect("the last checkpoint's image is reconstructible");
        if run.durable != applied {
            diverged.push(format!(
                "seed {seed:#x}: a reopen recovered {:?}, but the LAST metadata-page write in the \
                 recorded schedule was txn {}'s, whose image is {:?} (it wrote at step {})",
                run.durable, last.txn, applied, last.write
            ));
        }
    }
    assert!(
        diverged.is_empty(),
        "what ARIES rebuilds is not what the runtime left on the page, so the order in which \
         catalog images entered the log is not the order in which they took effect (`rmp` #1062). \
         Every logged page write must append and apply inside one `RecordStore::in_page_order` \
         section keyed by the device page; `RecordStore::page_lsn_descents` is the direct oracle for \
         the same invariant and `page_log_apply_order_1062` asserts it is zero:\n{}",
        diverged.join("\n")
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
            run.committed,
            vec![ROUNDS; WRITERS],
            "seed {seed:#x}: the writers acknowledged {:?} commits, not {ROUNDS} each",
            run.committed
        );
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
                image_of(c, &cps).is_some(),
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
    for seed in [SEEDS[0], SEEDS[7], SEEDS[15]] {
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
