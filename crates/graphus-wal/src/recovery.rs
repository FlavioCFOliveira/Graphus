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

use graphus_core::error::{GraphusError, Result};
use graphus_core::{Lsn, PageId, TxnId};

use crate::checkpoint::CheckpointSnapshot;
use crate::manager::{HEADER_LEN, WalManager};
use crate::record::{DecodeError, LogRecord, LogRecordRef, MIN_RECORD_LEN, RecordType};
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
/// This scans the whole durable log from just after the WAL header. For a log whose first record
/// does not sit immediately after the header — e.g. a *logical* WAL reconstructed from a backup
/// chain, whose records begin at the chain's `base_lsn` (`rmp` task #71) — use
/// [`recover_from`] with that start offset.
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
    recover_from(wal, target, Lsn(HEADER_LEN))
}

/// Replays `wal`'s durable log against `target` exactly like [`recover`], but begins the forward
/// analysis scan at `scan_start` (a record-boundary LSN) instead of right after the WAL header.
///
/// The only difference from [`recover`] is *where the forward scan begins*; every other phase — redo
/// from the checkpoint's `redo_start` (or `HEADER_LEN` when the scanned range holds no checkpoint),
/// and undo of all losers — is identical. This exists so a logical WAL whose records legitimately
/// start at a non-header offset can be replayed without re-encoding it: a backup chain lays the base
/// page images down to WAL position `base_lsn`, then concatenates the increment byte ranges starting
/// at `base_lsn`, leaving the bytes in `[HEADER_LEN, base_lsn)` as an unscanned gap (`rmp` task #71).
/// Pointing the scan at `base_lsn` makes recovery read exactly the chain's real records and skip the
/// gap, so the proven three-phase semantics apply unchanged. `scan_start` must land on a record
/// boundary (the chain guarantees this: `base_lsn` is a WAL `durable_len`, always a boundary).
///
/// # Errors
/// Propagates an [`ApplyTarget::apply`] or sink read failure.
///
/// # Panics
/// Panics if hardening the CLRs written during undo fails (`§4.9`).
pub fn recover_from<S: LogSink, T: ApplyTarget>(
    wal: &mut WalManager<S>,
    target: &mut T,
    scan_start: Lsn,
) -> Result<RecoveryReport> {
    // The scan begins at `scan_start` for a logical/chain WAL, or at `HEADER_LEN` for a normal log.
    // Clamp to at least `HEADER_LEN` (offset 0 is the null LSN; the header is never a record) and to
    // at least the sink's own `reclaimed_floor()` (`rmp` #525): reading from any lower LSN would make
    // `read_durable` allocate and zero-fill a buffer sized by the log's entire lifetime byte offset,
    // not by what is actually retained — the exact mechanism behind a real crash (a ~3.5 GiB retained
    // WAL demanding a ~61 GiB allocation on reopen, because `durable_len` had grown far larger than
    // the retained window over the database's lifetime). `reclaimed_floor()` is provably safe to read
    // from: it never exceeds an LSN `WalManager::reclaim` has already established is unneeded by
    // recovery — the same guarantee the leading-zero-skip below already relies on.
    let base = scan_start
        .0
        .max(HEADER_LEN)
        .max(wal.sink().reclaimed_floor());
    let mut log = Vec::new();
    wal.read_durable(Lsn(base), &mut log)?;

    // --- Phase 1: analysis ---
    let mut ordered: Vec<LogRecord> = Vec::new();
    let mut committed: HashSet<u64> = HashSet::new();
    let mut ended: HashSet<u64> = HashSet::new();
    let mut txn_last: HashMap<u64, Lsn> = HashMap::new();
    let mut last_checkpoint: Option<CheckpointSnapshot> = None;
    let mut last_checkpoint_lsn: Option<Lsn> = None;
    let mut tail_truncated = false;

    // `log[0]` corresponds to absolute LSN `base` (read_durable was bounded to start there), so the
    // scan cursor starts at the beginning of the buffer, not at `base` itself.
    let mut cursor = 0usize;
    // Skip a leading run of zero bytes: a **reclaimed WAL prefix** (deleted segments / punched holes
    // below the recovery floor, `rmp` #114) reads back as zeros, and a real record never begins with
    // a zero byte (its leading `total_len` is `>= MIN_RECORD_LEN`). This advances the scan to the
    // first surviving record. It is confined to the *leading* prefix: once a record is found the loop
    // governs, so the interior-corruption detection below still fires on any zero/garbage gap that
    // appears *between* real records (a reclaim only ever frees a contiguous front prefix).
    while cursor < log.len() && log[cursor] == 0 {
        cursor += 1;
    }
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
                            last_checkpoint_lsn = Some(rec.lsn);
                        }
                    }
                    _ => {}
                }
                if rec.txn_id.0 != 0 {
                    txn_last.insert(rec.txn_id.0, rec.lsn);
                }
                ordered.push(rec);
            }
            // A record failed to decode. This is EITHER a benign torn tail (the last, still
            // un-acknowledged append never completed — those records are legitimately lost) OR
            // INTERIOR corruption of the durable log (bit-rot / a bad block in the middle). The two
            // must not be conflated: silently truncating on interior corruption (the original
            // behaviour) would drop EVERY committed transaction logged after the bad spot and report
            // success — a silent loss of acknowledged committed data, the cardinal ACID violation
            // (storage audit F4).
            //
            // A genuine record stamps its own LSN == its byte offset, and that field is covered by
            // the record's CRC32C. So if any later offset in the durable range decodes to a
            // *self-consistent* record (`lsn == offset`), there is real committed data beyond the
            // failure point: this is interior corruption, and recovery FAILS LOUD (refuses to open)
            // rather than truncate. If no such record follows, it is a clean torn tail and the scan
            // stops here, preserving committed-or-nothing. Biasing an ambiguous tail toward
            // fail-closed (the operator investigates; no bytes are discarded) is the correct ACID
            // choice versus silently dropping possibly-committed data.
            Err(DecodeError::Incomplete | DecodeError::BadCrc | DecodeError::Corrupt) => {
                // Diagnostics report absolute LSNs (`base + cursor`), not the buffer-relative index,
                // now that the buffer may start at a nonzero `base` (`rmp` #525).
                let abs_cursor = base + cursor as u64;
                if let Some(abs_off) = next_self_consistent_record(&log, cursor + 1, base) {
                    return Err(GraphusError::Storage(format!(
                        "WAL interior log corruption: an undecodable record at offset {abs_cursor} is \
                         followed by a valid record at offset {abs_off}; refusing to recover, because \
                         truncating here would silently drop the committed transactions logged \
                         after offset {abs_cursor}"
                    )));
                }
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
    // Redo starts at the smallest dirty-page `recovery_lsn` the checkpoint captured (a fuzzy
    // checkpoint). When the checkpoint's DPT is **empty** — i.e. it was taken after a flush that made
    // every prior change durable on its data page (a sharp checkpoint, as the storage engine and
    // `backup_store` take) — redo starts at the **checkpoint's own LSN**: nothing before it needs
    // redo, only the changes logged after it. With no checkpoint at all, redo must scan from the
    // header. Either way, per-page `page_lsn` gating below still skips any change already on its page,
    // so this floor only bounds *how much* is scanned, never correctness (`04 §4.8`).
    let redo_start = last_checkpoint
        .as_ref()
        .and_then(CheckpointSnapshot::redo_start)
        .or(last_checkpoint_lsn)
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

/// Scans `log[from..]` for the first offset that decodes to a **self-consistent** record — one whose
/// stamped LSN equals its own **absolute** byte offset (`record.lsn == base + offset`). A record's LSN
/// is its byte offset (`§4.1`) and is covered by the record's CRC32C, so a self-consistent decode is a
/// record genuinely written at that position, not a chance CRC match (a stray CRC32C hit would
/// additionally have to carry exactly the right 8-byte offset — astronomically unlikely).
///
/// `base` is the absolute LSN of `log[0]` (`rmp` #525: the caller may have read `log` starting at a
/// nonzero floor, not true LSN `0`, to avoid materialising an already-reclaimed gap) — `0` recovers the
/// original "index is the absolute offset" behaviour.
///
/// Used by [`recover_from`] to tell interior log corruption (a valid record follows an undecodable
/// one ⇒ committed data exists beyond the failure ⇒ fail loud) from a benign torn tail (no genuine
/// record follows ⇒ truncate). Returns the **absolute** LSN of the first such record, or `None` if none
/// remains in the durable range.
pub(crate) fn next_self_consistent_record(log: &[u8], from: usize, base: u64) -> Option<u64> {
    let mut off = from;
    while off + MIN_RECORD_LEN <= log.len() {
        // Probes only the self-consistency of the header (`lsn == base + off`), never redo/undo, so
        // decode in place without allocating — this runs once per byte across the corrupt region.
        if let Ok((rec, _)) = LogRecordRef::decode(&log[off..]) {
            if rec.lsn.0 == base + off as u64 {
                return Some(rec.lsn.0);
            }
        }
        off += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::MemLogSink;
    use crate::test_support::CountingSink;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

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

    /// **`rmp` #525 regression gate.** Reproduces the exact production crash — a WAL whose *lifetime*
    /// byte offset (`durable_len`) has grown far larger than its *currently retained* window, because
    /// many commit+reclaim cycles ran over the database's life (exactly what a long bulk-import session
    /// with the widened maintenance-checkpoint interval, or simply a long-lived busy database, produces)
    /// — then reopens it (the real crash-recovery boot path: `recover`/`committed_transactions`/
    /// `max_recovered_txn_id`, all of which used to call `read_durable(Lsn(0), ..)` unconditionally) and
    /// asserts BOTH halves of the fix:
    ///
    /// 1. **The read is actually bounded** — `read_durable` from `reclaimed_floor()` returns a buffer
    ///    close to the retained window's size, not the log's entire lifetime length (this is the direct,
    ///    measurable effect of the fix; before it, this same read would have been `lifetime_len` bytes,
    ///    which is exactly what turned into the ~61 GiB allocation in production).
    /// 2. **Nothing needed for recovery is silently skipped by the new boundary** — every one of the
    ///    still-retained committed transactions is correctly recovered (`committed_transactions`,
    ///    `max_recovered_txn_id`, and a full `recover` redo/undo pass all agree), which is the primary
    ///    correctness concern for narrowing a crash-recovery read boundary.
    #[test]
    fn reopen_after_heavy_reclaim_churn_bounds_the_read_and_recovers_every_retained_commit() {
        // Wrap the backing so we can OBSERVE the largest buffer the recovery methods
        // (`committed_transactions` / `max_recovered_txn_id` / `recover`) actually allocate — the part
        // the earlier version of this test never asserted, which left it non-gating (it passed even on
        // the pre-fix `read_durable(Lsn(0)/HEADER_LEN, ..)` code because those reads still returned the
        // *correct* bytes, only a lifetime-sized buffer). See the counter assertion below.
        let counter = Arc::new(AtomicU64::new(0));
        let syncs = Arc::new(AtomicU64::new(0));
        let mut wal = WalManager::create(CountingSink::new(
            MemLogSink::new(),
            Arc::clone(&counter),
            Arc::clone(&syncs),
        ))
        .unwrap();

        const CHURN_CYCLES: u64 = 500;
        const RETAINED_TXNS: u64 = 5;

        for i in 1..=CHURN_CYCLES {
            let txn = TxnId(i);
            wal.begin(txn);
            wal.log_update(txn, PageId(0), d(1), d(-1));
            wal.commit(txn).unwrap();
            // Reclaim everything durable so far behind every commit except the last few, so the WAL
            // ends with a LARGE lifetime offset (500 commits' worth of LSN space issued) but a SMALL
            // retained window (only the last `RETAINED_TXNS` commits' bytes still on "disk").
            if i <= CHURN_CYCLES - RETAINED_TXNS {
                wal.reclaim(Lsn(wal.sink().durable_len())).unwrap();
            }
        }

        let lifetime_len = wal.sink().durable_len();
        let floor = wal.sink().reclaimed_floor();
        assert!(
            floor > 0,
            "many commit+reclaim cycles must have advanced the floor well past LSN 0 \
             (floor={floor}, lifetime_len={lifetime_len})"
        );
        let retained_span = lifetime_len - floor;
        // The reproduction is only meaningful if the retained window is genuinely small relative to
        // the lifetime length — assert the scenario itself, not just the fix.
        assert!(
            retained_span * 20 < lifetime_len,
            "test setup did not reproduce a small-retention/high-lifetime-offset WAL: \
             retained_span={retained_span} lifetime_len={lifetime_len}"
        );

        // --- 1. The fix's direct, measurable effect: the bounded read stays small. ---
        let mut bounded = Vec::new();
        wal.sink().read_durable(floor, &mut bounded).unwrap();
        assert_eq!(bounded.len() as u64, retained_span);
        assert!(
            (bounded.len() as u64) * 20 < lifetime_len,
            "a read bounded to reclaimed_floor() must stay close to the retained window, not scale \
             with the log's lifetime length (bounded={} lifetime_len={lifetime_len})",
            bounded.len()
        );

        // --- 2. Reopen (the real crash-recovery boot path) must succeed and recover EXACTLY the
        // --- retained commits — none silently dropped, none phantom.
        let sink = wal.sink().clone();
        // Reset the counter so it measures ONLY the reopen + recovery reads that follow.
        counter.store(0, Ordering::SeqCst);
        let mut wal2 = WalManager::open(sink).unwrap();

        let committed = wal2.committed_transactions().unwrap();
        assert_eq!(
            committed.len(),
            RETAINED_TXNS as usize,
            "must recover exactly the retained commits"
        );
        let mut recovered_ids: Vec<u64> = committed.iter().map(|(t, _, _)| t.0).collect();
        recovered_ids.sort_unstable();
        let expected_ids: Vec<u64> = ((CHURN_CYCLES - RETAINED_TXNS + 1)..=CHURN_CYCLES).collect();
        assert_eq!(
            recovered_ids, expected_ids,
            "recovered exactly the still-retained transaction ids, none skipped, none phantom"
        );

        assert_eq!(
            wal2.max_recovered_txn_id().unwrap(),
            CHURN_CYCLES,
            "the id high-water mark must still be seeded from the last retained commit"
        );

        let mut store = DeltaStore::default();
        let report = recover(&mut wal2, &mut store).unwrap();
        assert_eq!(
            report.losers, 0,
            "every retained transaction committed; no losers to undo"
        );
        assert_eq!(
            report.redo_applied, RETAINED_TXNS as usize,
            "every retained commit's single update must be redone"
        );
        assert_eq!(
            store.value(0),
            RETAINED_TXNS as i64,
            "each retained commit added +1 to page 0; the reclaimed-away commits' effects predate \
             this store (a fresh redo target, modelling a no-force page that was never flushed) so \
             they correctly do not appear here — this asserts the RETAINED commits are complete, not \
             that reclaimed history is (impossibly) still redoable"
        );

        // --- 3. GATING: the recovery methods above must have read only the RETAINED window, never a
        // --- buffer sized by the log's lifetime. This is what makes the test fail on the pre-fix code:
        // --- reverting the recovery-path `.max(reclaimed_floor())` makes these reads start at
        // --- `HEADER_LEN`, spiking the observed allocation to ~`lifetime_len`.
        let max_recovery_read = counter.load(Ordering::SeqCst);
        assert!(
            max_recovery_read <= retained_span + HEADER_LEN,
            "recovery allocated {max_recovery_read} bytes — it must stay bounded by the retained \
             window {retained_span}, not scale with the lifetime length {lifetime_len}"
        );
        assert!(
            max_recovery_read * 20 < lifetime_len,
            "recovery read {max_recovery_read} must be well below the lifetime length {lifetime_len} \
             (bounded to the retained window, not the whole history)"
        );
    }

    /// **`rmp` #525** — the same gate over a **real segmented [`FileLogSink`]** (not the in-memory
    /// sink): after many commit+reclaim cycles the WAL directory has physically deleted its below-floor
    /// segments, so `durable_len` (the lifetime byte offset) far exceeds the retained window. Reopening
    /// from disk and recovering must read only the retained window — reverting the recovery-path
    /// `.max(reclaimed_floor())` makes the read scale with the lifetime and fails the gate — while still
    /// recovering every retained commit (the last commit is always retained).
    #[cfg_attr(
        miri,
        ignore = "real filesystem I/O is outside miri's isolation/UB scope"
    )]
    #[test]
    fn file_backed_reopen_after_heavy_reclaim_bounds_the_recovery_read() {
        use crate::sink::FileLogSink;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("graphus-wal-recl-{nanos}-{}", std::process::id()));

        const CHURN_CYCLES: u64 = 400;

        // --- Build phase: churn commits + reclaim, on a REAL file backing with tiny segments so the
        // --- reclaim frees whole segments at a fine granularity. Then drop the manager (close files).
        {
            let backing =
                FileLogSink::open_with_segment_target(&dir, 512).expect("open file backing");
            let mut wal = WalManager::create(backing).expect("create wal on file backing");
            for i in 1..=CHURN_CYCLES {
                let txn = TxnId(i);
                wal.begin(txn);
                wal.log_update(txn, PageId(0), d(1), d(-1));
                wal.commit(txn).expect("commit");
                // Reclaim everything durable so far; the active segment is always kept, so the retained
                // window stays a small suffix while the lifetime offset grows with every commit.
                wal.reclaim(Lsn(wal.sink().durable_len())).expect("reclaim");
            }
        }

        // --- Reopen phase: fresh FileLogSink over the same directory (the real crash-recovery boot
        // --- path), wrapped so we can observe the recovery reads.
        let counter = Arc::new(AtomicU64::new(0));
        let syncs = Arc::new(AtomicU64::new(0));
        let backing =
            FileLogSink::open_with_segment_target(&dir, 512).expect("reopen file backing");
        let mut wal = WalManager::open(CountingSink::new(
            backing,
            Arc::clone(&counter),
            Arc::clone(&syncs),
        ))
        .expect("reopen wal manager");

        let lifetime_len = wal.sink().durable_len();
        let floor = wal.sink().reclaimed_floor();
        assert!(
            floor > 0,
            "the segmented file reclaim must have advanced the floor past LSN 0 \
             (floor={floor}, lifetime_len={lifetime_len})"
        );
        let retained_span = lifetime_len - floor;
        assert!(
            retained_span * 10 < lifetime_len,
            "test setup did not reproduce a small-retention/high-lifetime WAL on disk: \
             retained_span={retained_span} lifetime_len={lifetime_len}"
        );

        // Recovery must succeed and see the last (always-retained) commit.
        let committed = wal.committed_transactions().expect("committed txns");
        assert!(
            !committed.is_empty() && committed.iter().any(|(t, _, _)| t.0 == CHURN_CYCLES),
            "the last committed transaction must be among the recovered retained set"
        );
        assert_eq!(
            wal.max_recovered_txn_id().expect("max id"),
            CHURN_CYCLES,
            "the id high-water mark is seeded from the last retained commit"
        );
        let mut store = DeltaStore::default();
        recover(&mut wal, &mut store).expect("recover from the reopened file WAL");

        // GATING: the recovery reads stayed bounded by the retained window.
        let max_recovery_read = counter.load(Ordering::SeqCst);
        assert!(
            max_recovery_read <= retained_span + HEADER_LEN,
            "recovery allocated {max_recovery_read} bytes from the file WAL — it must stay bounded by \
             the retained window {retained_span}, not scale with the lifetime length {lifetime_len}"
        );
        assert!(
            max_recovery_read * 10 < lifetime_len,
            "recovery read {max_recovery_read} must be well below the lifetime length {lifetime_len}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
