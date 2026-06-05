//! Three-phase ARIES recovery (`specification/04-technical-design.md` §4.8).
//!
//! On restart after an unclean shutdown, [`recover`] brings the database to the last durable
//! *committed-or-nothing* state:
//!
//! 1. **Analysis** — scan the durable log to find committed transactions, the loser set, and the
//!    last fuzzy checkpoint (which fixes where redo starts).
//! 2. **Redo (repeating history)** — replay every logged page change (winners *and* losers) from
//!    the redo start, skipping any whose effect is already on the page (`record.lsn >
//!    page_lsn`). This deterministically rebuilds the exact pre-crash page state, which is what
//!    makes logical undo sound across interleaved writers.
//! 3. **Undo** — roll back every loser, in strict global descending-LSN order (so interleaved
//!    writes to the same page unwind in the right order), writing a redo-only **CLR** per undone
//!    action so a crash during recovery resumes instead of double-undoing (`§4.4`).
//!
//! The page-application semantics are injected through [`ApplyTarget`]: this crate owns the log
//! and the recovery control flow, while `graphus-storage` owns what a redo/undo image *means*
//! for a page. Recovery reads the whole durable log into memory; a streaming scan is a later
//! optimisation tracked with the storage integration.

use std::collections::{BinaryHeap, HashMap, HashSet};

use graphus_core::error::Result;
use graphus_core::{Lsn, PageId, TxnId};

use crate::checkpoint::CheckpointSnapshot;
use crate::manager::{HEADER_LEN, WalManager};
use crate::record::{DecodeError, LogRecord, RecordType};
use crate::sink::LogSink;

/// What a redo/undo image means for a page. Implemented by the storage layer (and by recovery
/// tests); recovery itself never interprets the bytes.
pub trait ApplyTarget {
    /// The `page_lsn` currently recorded for `page` (the LSN of the last change reflected on it),
    /// or [`Lsn(0)`](graphus_core::Lsn) if the page is absent or never modified.
    fn page_lsn(&self, page: PageId) -> Lsn;

    /// Applies `image` to `page` and stamps `lsn` as the page's new `page_lsn`. Used both to redo
    /// a logged change and to apply a CLR's compensating image during undo.
    ///
    /// # Errors
    /// Returns a storage error if the change cannot be applied.
    fn apply(&mut self, page: PageId, lsn: Lsn, image: &[u8]) -> Result<()>;
}

/// A summary of what a [`recover`] run did (for tests and observability).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Number of records read during analysis.
    pub records_scanned: usize,
    /// The LSN redo started from.
    pub redo_start: Lsn,
    /// Number of logged changes actually re-applied during redo.
    pub redo_applied: usize,
    /// Number of loser transactions rolled back.
    pub losers: usize,
    /// Number of CLRs written during undo.
    pub clrs_written: usize,
    /// Whether the scan stopped at a truncated/torn tail (an un-acknowledged tail was lost).
    pub tail_truncated: bool,
}

/// Replays `wal`'s durable log against `target`, leaving only committed work applied.
///
/// # Errors
/// Propagates an [`ApplyTarget::apply`] or sink read failure.
///
/// # Panics
/// Panics if hardening the CLRs written during undo fails (`§4.9`).
pub fn recover<S: LogSink, T: ApplyTarget>(
    wal: &mut WalManager<S>,
    target: &mut T,
) -> Result<RecoveryReport> {
    let mut log = Vec::new();
    wal.read_durable(Lsn(0), &mut log)?;

    // --- Phase 1: analysis ---
    let mut ordered: Vec<LogRecord> = Vec::new();
    let mut committed: HashSet<u64> = HashSet::new();
    let mut ended: HashSet<u64> = HashSet::new();
    let mut txn_last: HashMap<u64, Lsn> = HashMap::new();
    let mut last_checkpoint: Option<CheckpointSnapshot> = None;
    let mut tail_truncated = false;

    let mut cursor = HEADER_LEN as usize;
    while cursor < log.len() {
        match LogRecord::decode(&log[cursor..]) {
            Ok((rec, n)) => {
                cursor += n;
                match rec.rec_type {
                    RecordType::Commit => {
                        committed.insert(rec.txn_id.0);
                    }
                    RecordType::Abort => {
                        ended.insert(rec.txn_id.0);
                    }
                    RecordType::CheckpointEnd => {
                        if let Some(s) = CheckpointSnapshot::decode(&rec.redo) {
                            last_checkpoint = Some(s);
                        }
                    }
                    _ => {}
                }
                if rec.txn_id.0 != 0 {
                    txn_last.insert(rec.txn_id.0, rec.lsn);
                }
                ordered.push(rec);
            }
            // A decode failure means the durable log ends here: either a clean torn tail
            // (un-acknowledged records, legitimately lost) or trailing garbage. Either way the
            // scan stops at the last intact record, which preserves committed-or-nothing.
            Err(DecodeError::Incomplete | DecodeError::BadCrc | DecodeError::Corrupt) => {
                tail_truncated = true;
                break;
            }
        }
    }

    let records_scanned = ordered.len();
    let index: HashMap<u64, usize> = ordered
        .iter()
        .enumerate()
        .map(|(i, r)| (r.lsn.0, i))
        .collect();

    // --- Phase 2: redo (repeating history) ---
    let redo_start = last_checkpoint
        .as_ref()
        .and_then(CheckpointSnapshot::redo_start)
        .unwrap_or(Lsn(HEADER_LEN));

    let mut redo_applied = 0usize;
    for rec in &ordered {
        if rec.lsn >= redo_start
            && rec.rec_type.is_page_change()
            && !rec.redo.is_empty()
            && rec.lsn > target.page_lsn(rec.page_id)
        {
            target.apply(rec.page_id, rec.lsn, &rec.redo)?;
            redo_applied += 1;
        }
    }

    // --- Phase 3: undo losers ---
    let losers: Vec<u64> = txn_last
        .keys()
        .copied()
        .filter(|t| !committed.contains(t) && !ended.contains(t))
        .collect();

    // Undo all losers in one merged backward pass: a max-heap over "next LSN to undo" yields
    // strict global descending-LSN order, so writes interleaved across losers on the same page
    // unwind newest-first.
    let mut heap: BinaryHeap<u64> = BinaryHeap::new();
    for t in &losers {
        if let Some(l) = txn_last.get(t) {
            if l.0 != 0 {
                heap.push(l.0);
            }
        }
    }

    let mut clrs_written = 0usize;
    while let Some(lsn_u) = heap.pop() {
        let Some(&i) = index.get(&lsn_u) else {
            continue;
        };
        let rec = &ordered[i];
        match rec.rec_type {
            // A CLR records an undo that already happened; resume at the next LSN to undo.
            RecordType::Clr => {
                if rec.undo_next_lsn.0 != 0 {
                    heap.push(rec.undo_next_lsn.0);
                }
            }
            t if t.is_undoable_action() => {
                let clr_lsn =
                    wal.write_clr(rec.txn_id, rec.page_id, rec.lsn, &rec.undo, rec.prev_lsn);
                if !rec.undo.is_empty() {
                    target.apply(rec.page_id, clr_lsn, &rec.undo)?;
                }
                clrs_written += 1;
                if rec.prev_lsn.0 != 0 {
                    heap.push(rec.prev_lsn.0);
                }
            }
            // A BEGIN (or any non-undoable control record) just continues the back-chain.
            _ => {
                if rec.prev_lsn.0 != 0 {
                    heap.push(rec.prev_lsn.0);
                }
            }
        }
    }

    for t in &losers {
        wal.write_end(TxnId(*t));
    }
    wal.flush();

    Ok(RecoveryReport {
        records_scanned,
        redo_start,
        redo_applied,
        losers: losers.len(),
        clrs_written,
        tail_truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::MemLogSink;

    /// A page-per-counter store whose redo/undo images are 8-byte little-endian **deltas**
    /// (physiological redo + logical undo, as `§4.1` requires for interleaving soundness).
    #[derive(Debug, Default)]
    struct DeltaStore {
        pages: HashMap<u64, (Lsn, i64)>,
    }

    impl DeltaStore {
        fn value(&self, p: u64) -> i64 {
            self.pages.get(&p).map_or(0, |&(_, v)| v)
        }
    }

    impl ApplyTarget for DeltaStore {
        fn page_lsn(&self, page: PageId) -> Lsn {
            self.pages.get(&page.0).map_or(Lsn(0), |&(l, _)| l)
        }

        fn apply(&mut self, page: PageId, lsn: Lsn, image: &[u8]) -> Result<()> {
            let delta = i64::from_le_bytes(image.try_into().expect("8-byte delta"));
            let e = self.pages.entry(page.0).or_insert((Lsn(0), 0));
            e.0 = lsn;
            e.1 += delta;
            Ok(())
        }
    }

    fn d(v: i64) -> Vec<u8> {
        v.to_le_bytes().to_vec()
    }

    #[test]
    fn committed_work_is_redone() {
        let mut wal = WalManager::create(MemLogSink::new()).unwrap();
        wal.begin(TxnId(1));
        wal.log_update(TxnId(1), PageId(0), d(10), d(-10));
        wal.commit(TxnId(1)).unwrap();

        // Recover into a fresh (empty) store, modelling no-force: the committed delta was never
        // flushed and must be reconstructed by redo.
        let sink = wal.sink().clone();
        let mut wal2 = WalManager::open(sink).unwrap();
        let mut store = DeltaStore::default();
        let report = recover(&mut wal2, &mut store).unwrap();
        assert_eq!(store.value(0), 10);
        assert_eq!(report.redo_applied, 1);
        assert_eq!(report.losers, 0);
    }

    #[test]
    fn uncommitted_work_is_undone() {
        let mut wal = WalManager::create(MemLogSink::new()).unwrap();
        wal.begin(TxnId(1));
        wal.log_update(TxnId(1), PageId(0), d(10), d(-10));
        wal.flush(); // make the (uncommitted) update durable, but never a COMMIT

        let sink = wal.sink().clone();
        let mut wal2 = WalManager::open(sink).unwrap();
        let mut store = DeltaStore::default();
        let report = recover(&mut wal2, &mut store).unwrap();
        assert_eq!(store.value(0), 0); // redone then undone -> net zero
        assert_eq!(report.losers, 1);
        assert_eq!(report.clrs_written, 1);
    }

    #[test]
    fn steal_uncommitted_page_on_disk_is_undone() {
        let mut wal = WalManager::create(MemLogSink::new()).unwrap();
        wal.begin(TxnId(1));
        let u = wal.log_update(TxnId(1), PageId(0), d(10), d(-10));
        wal.flush();

        // Model steal: the dirty, *uncommitted* page was evicted to disk before the crash.
        let sink = wal.sink().clone();
        let mut wal2 = WalManager::open(sink).unwrap();
        let mut store = DeltaStore::default();
        store.apply(PageId(0), u, &d(10)).unwrap(); // disk already holds the stolen change
        recover(&mut wal2, &mut store).unwrap();
        assert_eq!(store.value(0), 0); // undo reverts the stolen, uncommitted change
    }

    #[test]
    fn interleaved_losers_unwind_in_global_lsn_order() {
        // Two transactions write the same page; one commits, one does not. Undo must respect
        // global LSN order or the committed delta would be clobbered.
        let mut wal = WalManager::create(MemLogSink::new()).unwrap();
        wal.begin(TxnId(2)); // loser
        wal.log_update(TxnId(2), PageId(0), d(-20), d(20));
        wal.begin(TxnId(1)); // winner, writes the same page after the loser
        wal.log_update(TxnId(1), PageId(0), d(-30), d(30));
        wal.commit(TxnId(1)).unwrap();
        // T2 never commits.

        let sink = wal.sink().clone();
        let mut wal2 = WalManager::open(sink).unwrap();
        let mut store = DeltaStore::default();
        store.apply(PageId(0), Lsn(0), &d(100)).unwrap(); // initial balance 100, pageLSN 0
        // Reset pageLSN to 0 so redo replays both deltas.
        store.pages.insert(0, (Lsn(0), 100));
        recover(&mut wal2, &mut store).unwrap();
        assert_eq!(store.value(0), 70); // 100 - 30 (committed); the loser's -20 is undone
    }
}
