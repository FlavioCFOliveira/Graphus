//! **A crash in the middle of a rollback (`rmp` #1062).**
//!
//! # The window this file exists for
//!
//! `rmp` #1062 changed the shape of `RecordStore::rollback_physical`. It used to append **every**
//! CLR and the `ABORT` under one hold of the WAL mutex, harden once, and only then replay all the
//! compensating images into the buffer pool. It now drains the undo chain **one compensation at a
//! time**, each inside its own page log-apply-order section: peek the page, pin it, take the rank-27
//! latch, append that one CLR, apply it, release — and the `ABORT` with its `fdatasync` comes at the
//! end, after the applies rather than before them.
//!
//! That was necessary — a batch of appends followed by a batch of applies lets a concurrent writer
//! interleave between them, so the CLRs enter the log in one order and take effect in another, which
//! is the whole subject of #1062 — but it **opens a window that did not exist before**. Under the old
//! shape, a crash after `rollback` returned found a durable `ABORT`, so the transaction was never a
//! recovery loser and recovery merely redid its (already durable) CLRs. Under the new shape a crash
//! part-way through leaves *k* CLRs in the log and **no `ABORT`**, so the transaction IS a loser and
//! recovery has to finish the undo itself.
//!
//! It is correct only because ARIES resumes rather than restarts: the undo phase walks the loser's
//! back-chain from its last record, meets the CLRs this drain already wrote, and follows each one's
//! `undo_next_lsn` past the action it compensated (`graphus_wal::recovery`, the `RecordType::Clr`
//! arm). Without that, recovery would re-apply pre-images for actions already undone. This file is
//! what turns that reading of the code into a checked property.
//!
//! # The oracle
//!
//! **Equality against an uninterrupted drain**, page for page. Two stores are built from the
//! identical script; one has its undo chain drained completely by the runtime, the other is
//! interrupted after *k* compensations and then crash-recovered. Their device images must agree byte
//! for byte on every mapped page — not "both look plausible", not "the node is gone", but the same
//! bytes.
//!
//! The two sides are independent implementations of the same undo, which is what makes the comparison
//! worth making: the reference is produced by `RecordStore`'s own drain (`compensate_one`, the loop
//! body of `rollback_physical`), and the subject by `graphus_wal::recovery`'s undo phase writing
//! through `graphus_storage::recovery::DeviceTarget` — different code, different medium, no shared
//! step. Byte equality is then a real claim about ARIES agreeing with the runtime, not a tautology.
//!
//! `k` is swept across **every** interior stopping point, `1 ..= n-1`, rather than the two endpoints:
//! the cost is a few milliseconds and it removes the question of whether the one `k` that was tried
//! happened to be the easy one.
//!
//! # Why the reference is the DRAIN and not `RecordStore::rollback`
//!
//! Measured, not assumed, and it is the thing about this file a reader is most likely to get wrong.
//! `RecordStore::rollback` dispatches on whether the transaction owns a commit-info slot
//! (`D-rollback-dispatch`): with one it takes the **logical** path, which applies the transaction's
//! own MVCC deltas, and only without one does it take the physical path whose drain `rmp` #1062
//! rewrote. A transaction that creates and labels nodes acquires a slot the moment its first undo
//! delta is linked, so `store.rollback(...)` on this workload runs `rollback_logical` and never
//! reaches the code under test.
//!
//! Using it as the reference would not merely be imprecise, it would compare two different
//! algorithms: measured on this script, the logical path leaves twelve bytes on page 1 that the
//! physical drain never writes. [`the_two_rollback_paths_are_observably_different`] pins that, so if
//! the dispatch rule ever changes this file says so instead of silently comparing the wrong thing.
//!
//! The end-user-facing property — that the database *answers* the same after the crash — is asserted
//! separately by [`a_crash_mid_rollback_leaves_the_committed_baseline_readable`], which reopens the
//! recovered store and reads it.
//!
//! # Non-vacuity
//!
//! Asserted per `k`, never assumed:
//!
//! * the interruption really stopped early — `compensate_prefix_for_test` reports exactly `k` steps
//!   taken, and the WAL still names an un-compensated entry afterwards;
//! * recovery really had work left to do and really **resumed** — `RecoveryReport::clrs_written` is
//!   strictly between zero and the full chain length `n`. Zero would mean the crash left nothing to
//!   undo (the test would be checking recovery of an already-finished rollback); `n` would mean
//!   recovery re-compensated the whole chain, i.e. it ignored the CLRs already written and the
//!   `undo_next_lsn` resume path was never exercised. Both are the shapes that would make this file
//!   pass while proving nothing;
//! * exactly one loser was found, so the interrupted transaction really was classified as one.
//!
//! # Running it
//!
//! ```text
//! cargo test -p graphus-storage --test rollback_crash_resume_1062
//! ```

use graphus_core::{PageId, TxnId};
use graphus_io::{BlockDevice, MemBlockDevice, Page};
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, RecoveryReport, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// Buffer-pool frames. Comfortably above the working set, so what is measured is the rollback and
/// recovery and not the pool's eviction behaviour.
const POOL_PAGES: usize = 64;

/// Nodes the doomed transaction creates and labels. Each creation and each label change is an
/// undoable action, so the undo chain is comfortably longer than the two endpoints `k` could take —
/// which is what makes sweeping the interior meaningful.
const DOOMED_NODES: u64 = 6;

/// The transaction that lays down the committed baseline every run shares.
const BASE_TXN: TxnId = TxnId(1);

/// The transaction that writes and is then rolled back.
const DOOMED_TXN: TxnId = TxnId(2);

/// Builds a store, commits a baseline, then opens [`DOOMED_TXN`] and leaves it holding
/// `DOOMED_NODES` uncommitted creations, each carrying a label.
///
/// The baseline matters: a rollback that wrongly reverts more than its own transaction has to have
/// something of somebody else's to damage, and an empty store gives it none.
fn store_with_a_doomed_txn() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: Store = RecordStore::create(device, wal, POOL_PAGES, 1).expect("create store");

    let keep = store
        .intern_token(Namespace::Label, "KEEP")
        .expect("intern KEEP");
    let doomed = store
        .intern_token(Namespace::Label, "DOOMED")
        .expect("intern DOOMED");

    store.begin(BASE_TXN);
    for _ in 0..DOOMED_NODES {
        let (node, _) = store.create_node(BASE_TXN).expect("create a baseline node");
        store
            .add_label(BASE_TXN, node, keep)
            .expect("label a baseline node");
    }
    store.commit(BASE_TXN).expect("commit the baseline");

    store.begin(DOOMED_TXN);
    for _ in 0..DOOMED_NODES {
        let (node, _) = store.create_node(DOOMED_TXN).expect("create a doomed node");
        store
            .add_label(DOOMED_TXN, node, doomed)
            .expect("label a doomed node");
    }
    store
}

/// The number of undoable actions [`DOOMED_TXN`] has logged — the length of its WAL undo chain,
/// counted by draining nothing.
fn undo_chain_len(store: &Store) -> usize {
    store.with_wal(|w| w.undo_chain_len(DOOMED_TXN))
}

/// Every mapped page of `store`'s device, as `(page id, bytes)`, after flushing dirty pages home.
fn device_image(store: &Store) -> Vec<(u64, Box<Page>)> {
    store.flush().expect("flush the dirty pages home");
    let mut pages = store.mapped_pages();
    pages.sort_unstable_by_key(|p| p.0);
    pages
        .iter()
        .map(|p| (p.0, store.read_device_page(*p).expect("read device page")))
        .collect()
}

/// Stages `store`'s flushed device image and its durable WAL prefix, runs ARIES over them, and
/// returns the recovered device image plus the report.
///
/// This is the steal-crash shape the rest of the workspace uses: the pages the pool had written home
/// survive, everything still in memory does not, and the log is whatever was hardened.
fn crash_and_recover(store: &Store) -> (Vec<(u64, Box<Page>)>, RecoveryReport) {
    let staged = device_image(store);
    let max = staged.iter().map(|(id, _)| *id).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    for (id, bytes) in &staged {
        device.write_page(PageId(*id), bytes).expect("stage a page");
    }
    device.sync_all().expect("persist the disk image");

    let mut sink = MemLogSink::new();
    sink.append(&store.with_wal(|w| w.sink().durable_bytes().to_vec()));
    sink.sync().expect("sync the durable log prefix");

    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    let report = recover_device(&mut wal, &mut device).expect("ARIES recovery");

    let recovered = staged
        .iter()
        .map(|(id, _)| {
            let mut buf = Box::new([0u8; graphus_io::PAGE_SIZE]);
            device.read_page(PageId(*id), &mut buf).expect("read back");
            (*id, buf)
        })
        .collect();
    (recovered, report)
}

/// Stages a crash of `store`, recovers it, and OPENS the recovered device as a live store.
fn reopen_after_crash(store: &Store) -> Store {
    let staged = device_image(store);
    let max = staged.iter().map(|(id, _)| *id).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    for (id, bytes) in &staged {
        device.write_page(PageId(*id), bytes).expect("stage a page");
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

/// The reference image: a store whose doomed transaction had its undo chain drained **completely** by
/// the runtime, with no crash anywhere, flushed home. This is what a correct recovery has to
/// reproduce.
///
/// It drives `compensate_prefix_for_test` to exhaustion plus `finish_rollback`, which together are
/// exactly `rollback_physical`'s drain — the same `compensate_one` body, the same `ABORT`. It is
/// deliberately NOT `RecordStore::rollback`; see the module note for the measurement that decided
/// that.
fn drained_reference_image() -> Vec<(u64, Box<Page>)> {
    let store = store_with_a_doomed_txn();
    let taken = store
        .compensate_prefix_for_test(DOOMED_TXN, usize::MAX)
        .expect("drain the whole undo chain");
    assert!(taken > 0, "the doomed transaction logged nothing to undo");
    store.with_wal(|w| w.finish_rollback(DOOMED_TXN));
    device_image(&store)
}

/// Byte range of a page's `page_lsn` (`graphus_bufpool::page`: checksum `0..4`, page type `4..8`,
/// page LSN `8..16`, page id `16..24`).
const PAGE_LSN_RANGE: std::ops::Range<usize> = 8..16;

/// Byte range of a page's checksum, which covers `4..PAGE_SIZE` and therefore moves with the
/// `page_lsn`.
const CHECKSUM_RANGE: std::ops::Range<usize> = 0..4;

/// Compares two device images page for page, naming the first byte that differs.
///
/// # Two header fields are excluded, and only two
///
/// **`page_lsn`, and the checksum that covers it.** A page's LSN names the last log record applied to
/// it, and the two runs legitimately reach the same *content* through different records: the clean
/// run's compensations are CLRs the runtime appended, while the crashed run's tail compensations are
/// CLRs **recovery** appended, at its own LSNs, after the log had grown. Requiring those to match
/// would be requiring the two runs to have written the same log, which is not the property — the
/// property is that they left the same data. `page_type` (`4..8`) and `page_id` (`16..24`) are NOT
/// excluded, so a page that came back as the wrong kind or under the wrong identity still fails, and
/// neither is a single byte of the body from [`HEADER_SIZE`] on.
///
/// The exclusion is deliberately expressed as two named ranges rather than "skip the header": it is
/// the one place this file weakens byte equality, so it says exactly how far.
fn diff(reference: &[(u64, Box<Page>)], actual: &[(u64, Box<Page>)]) -> Option<String> {
    if reference.len() != actual.len() {
        return Some(format!(
            "the images map {} and {} page(s)",
            reference.len(),
            actual.len()
        ));
    }
    for ((rid, rbytes), (aid, abytes)) in reference.iter().zip(actual.iter()) {
        if rid != aid {
            return Some(format!("page ids diverge: {rid} vs {aid}"));
        }
        let compared = (0..graphus_io::PAGE_SIZE)
            .filter(|i| !PAGE_LSN_RANGE.contains(i) && !CHECKSUM_RANGE.contains(i));
        if let Some(off) = compared.into_iter().find(|&i| rbytes[i] != abytes[i]) {
            let what = if off < graphus_bufpool::page::HEADER_SIZE {
                "in the page header"
            } else {
                "in the page body"
            };
            return Some(format!(
                "page {rid} differs at byte {off} ({what}): reference has {:#04x}, subject has \
                 {:#04x}",
                rbytes[off], abytes[off]
            ));
        }
    }
    None
}

/// **The property.** A crash at any interior point of the drain recovers to exactly the state a
/// complete, uninterrupted drain would have left.
#[test]
fn a_crash_mid_rollback_recovers_to_the_drained_reference_image() {
    let reference = drained_reference_image();
    let n = undo_chain_len(&store_with_a_doomed_txn());
    assert!(
        n >= 3,
        "the doomed transaction logged only {n} undoable action(s), so there is no interior \
         stopping point to crash at and this suite would test nothing"
    );

    for k in 1..n {
        let store = store_with_a_doomed_txn();
        let taken = store
            .compensate_prefix_for_test(DOOMED_TXN, k)
            .expect("take k compensations");
        assert_eq!(
            taken, k,
            "the drain stopped after {taken} compensation(s), not {k}: the crash was not staged \
             where this iteration says it was"
        );
        assert!(
            store.with_wal(|w| w.undo_chain_len(DOOMED_TXN)) > 0,
            "k={k}: the undo chain was already empty, so this is not an INTERRUPTED rollback"
        );

        let (recovered, report) = crash_and_recover(&store);

        assert_eq!(
            report.losers, 1,
            "k={k}: recovery found {} loser(s), not the one interrupted transaction — so the crash \
             did not leave the transaction un-aborted and the resume path was not the thing tested",
            report.losers
        );
        // Strictly between: 0 means the crash left nothing to undo, n means recovery re-compensated
        // the whole chain and therefore ignored the CLRs the drain had already written.
        assert!(
            report.clrs_written > 0 && report.clrs_written < n,
            "k={k}: recovery wrote {} CLR(s) for a chain of {n} with {k} already compensated. It \
             must write strictly between 0 and {n}: 0 would mean there was nothing left to undo, \
             and {n} would mean the `undo_next_lsn` resume path was never taken and every action \
             was compensated twice",
            report.clrs_written
        );
        assert_eq!(
            report.clrs_written,
            n - k,
            "k={k}: recovery wrote {} CLR(s), but exactly the {} un-compensated action(s) were \
             owed — so it resumed at the wrong point in the back-chain",
            report.clrs_written,
            n - k
        );

        assert!(
            diff(&reference, &recovered).is_none(),
            "k={k}: a crash after {k} of {n} compensations recovered to a DIFFERENT image from the \
             one an uninterrupted drain leaves. `rmp` #1062 moved the `ABORT` and its \
             fdatasync from before the applies to after them, so this crash makes the transaction a \
             recovery loser and correctness depends on ARIES meeting the already-written CLRs and \
             resuming at their `undo_next_lsn` instead of compensating those actions twice: {}",
            diff(&reference, &recovered).unwrap_or_default()
        );
    }
}

/// **Non-vacuity of the oracle.** The reference image is not trivially equal to everything — an
/// image taken with the rollback NOT performed differs from it.
///
/// Without this, `diff` returning `None` on every comparison above would be consistent with a `diff`
/// that cannot see any difference at all, and the whole file would pass against a broken oracle.
#[test]
fn the_reference_image_distinguishes_a_rollback_from_no_rollback() {
    let reference = drained_reference_image();
    let not_rolled_back = device_image(&store_with_a_doomed_txn());
    assert!(
        diff(&reference, &not_rolled_back).is_some(),
        "a store whose doomed transaction was NEVER undone produced the same device image as one \
         whose undo chain was fully drained, so the comparison used by \
         `a_crash_mid_rollback_recovers_to_the_drained_image` cannot detect a missed undo and \
         that test proves nothing"
    );
}

/// **The two rollback paths are different code, and this pins it.**
///
/// `RecordStore::rollback` takes the **logical** path for a transaction that owns a commit-info slot,
/// and this workload's transaction owns one. If that ever stops being true — or if the two paths ever
/// converge on the same bytes — this assertion fails and whoever changed it is told, here, that
/// [`drained_reference_image`] may now be replaceable by the public entry point. Without it, the
/// reason this file drives the drain directly survives only as a comment.
#[test]
fn the_two_rollback_paths_are_observably_different() {
    let via_public_rollback = {
        let store = store_with_a_doomed_txn();
        store
            .rollback(DOOMED_TXN)
            .expect("roll back via the public entry point");
        device_image(&store)
    };
    assert!(
        diff(&drained_reference_image(), &via_public_rollback).is_some(),
        "`RecordStore::rollback` produced the same device image as the physical drain, so either the \
         dispatch rule of `D-rollback-dispatch` changed and this workload no longer takes the logical \
         path, or the two paths converged. Either way the module note explaining why this file drives \
         `compensate_prefix_for_test` instead of `rollback` is now wrong and must be revisited \
         (`rmp` #1062)"
    );
}

/// **What the database answers after the crash.** The committed baseline survives, readable, and the
/// interrupted transaction's rows do not.
///
/// The byte-equality property above is about the mechanism; this is about the guarantee. It is
/// asserted separately because the two can fail independently: an undo that reproduced the reference
/// bytes but left the catalog naming rows that are gone would pass one and fail the other.
#[test]
fn a_crash_mid_rollback_leaves_the_committed_baseline_readable() {
    let n = undo_chain_len(&store_with_a_doomed_txn());
    for k in 1..n {
        let store = store_with_a_doomed_txn();
        store
            .compensate_prefix_for_test(DOOMED_TXN, k)
            .expect("take k compensations");
        let reopened = reopen_after_crash(&store);

        let stats = reopened.statistics();
        assert_eq!(
            stats.total_nodes(),
            DOOMED_NODES,
            "k={k}: the recovered catalog holds {} node(s); only the {DOOMED_NODES} COMMITTED \
             baseline nodes may survive an interrupted rollback",
            stats.total_nodes()
        );
        let keep = reopened
            .intern_token(Namespace::Label, "KEEP")
            .expect("resolve KEEP");
        assert_eq!(
            stats.node_count_for_label(keep),
            DOOMED_NODES,
            "k={k}: the recovered catalog counts {} node(s) labelled KEEP, not {DOOMED_NODES}",
            stats.node_count_for_label(keep)
        );
        drop(stats);

        // Read the baseline records themselves, not just the counters: a counter is a summary and
        // could be right over records that are gone.
        for id in 1..=DOOMED_NODES {
            assert_eq!(
                reopened.node_labels(id).expect("read a baseline node"),
                vec![keep],
                "k={k}: baseline node {id} did not read back with its committed KEEP label after a \
                 crash {k} compensation(s) into the rollback"
            );
        }
    }
}

/// **Determinism of the reference.** Two identical scripts produce identical device images, which is
/// what makes byte equality a usable oracle at all.
#[test]
fn the_drained_reference_image_is_reproducible() {
    assert!(
        diff(&drained_reference_image(), &drained_reference_image()).is_none(),
        "two identical drained-reference runs produced different device images, so byte equality is \
         not a sound oracle for this workload"
    );
}
