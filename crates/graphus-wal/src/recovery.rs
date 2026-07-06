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
//! for a page.
//!
//! # Streaming, windowed recovery (`rmp` #599)
//!
//! Recovery never materialises the whole durable log. Each of the three phases reads the durable
//! byte range **one [`RECOVERY_WINDOW_BYTES`]-sized window at a time** through
//! [`LogSink::read_bounded`], and undo reads a single record on demand at its LSN
//! ([`read_record_at`]). Peak reopen memory is therefore **O(window) + O(active-transaction-state)**
//! — independent of the total WAL byte size — for *every* large-WAL reopen, not just the
//! bulk-import case (`rmp` #590) or the heavily-reclaimed case (`rmp` #525). Before this a single
//! very large transaction (a real ~3.5 GiB retained WAL) forced a ~2.5× (~61 GiB) allocation on
//! reopen. The whole-log invariants are preserved byte-for-byte — LSN == byte offset (`§4.1`) is
//! what makes a windowed scan and an LSN-targeted undo read exact: any record is read directly by
//! seeking to its LSN, and a straddling record (one spanning a window boundary) is re-read from its
//! own offset (growing the window if a single record ever exceeds it).

use std::collections::{BinaryHeap, HashMap, HashSet};

use graphus_core::error::{GraphusError, Result};
use graphus_core::{Lsn, PageId, TxnId};

use crate::checkpoint::CheckpointSnapshot;
use crate::manager::{HEADER_LEN, WalManager};
use crate::record::{DecodeError, LogRecord, LogRecordRef, RecordType};
use crate::sink::LogSink;

/// The size of the sliding byte window each streaming recovery pass materialises at once
/// (`rmp` #599). Recovery reads the durable log window-by-window through
/// [`LogSink::read_bounded`] instead of slurping the whole retained range into one buffer, so peak
/// reopen memory is **O(window) + O(active-transaction-state)**, independent of the total WAL byte
/// size.
///
/// 4 MiB is chosen so that (a) it dwarfs any single WAL record the engine ever writes — a record
/// carries at most one page image plus a fixed header (tens of KiB) — so a record practically never
/// straddles more than one window boundary and the grow-on-oversize path is effectively never
/// taken; (b) it keeps the number of windowed reads over a multi-GiB log modest (a 3.5 GiB retained
/// window is ~900 reads, not one 3.5 GiB — formerly ~2.5×, ~61 GiB — allocation); and (c) it is
/// small enough that even several concurrent reopens cost only single-digit MiB of transient
/// buffers. A single record larger than this (never produced today) is handled by *growing* the
/// window for that read rather than failing (see [`scan_forward`] / [`read_record_at`]).
pub(crate) const RECOVERY_WINDOW_BYTES: u64 = 4 * 1024 * 1024;

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
    recover_from_windowed(wal, target, scan_start, RECOVERY_WINDOW_BYTES)
}

/// [`recover_from`] with an explicit streaming window size — the real implementation. Only the
/// window differs; correctness is independent of it (a smaller window just means more, smaller
/// windowed reads). `pub(crate)` so a test can drive a deliberately tiny window over a modest WAL to
/// prove the memory bound without building a multi-GiB log (`rmp` #599).
pub(crate) fn recover_from_windowed<S: LogSink, T: ApplyTarget>(
    wal: &mut WalManager<S>,
    target: &mut T,
    scan_start: Lsn,
    window: u64,
) -> Result<RecoveryReport> {
    // The scan begins at `scan_start` for a logical/chain WAL, or at `HEADER_LEN` for a normal log.
    // Clamp to at least `HEADER_LEN` (offset 0 is the null LSN; the header is never a record) and to
    // at least the sink's own `reclaimed_floor()` — the **`rmp` #525 reclaimed-floor bound**,
    // preserved verbatim: reading from any lower LSN would make the sink zero-fill an already-freed
    // gap, and (before streaming) size a buffer by the log's entire lifetime byte offset rather than
    // by what is retained. `reclaimed_floor()` never exceeds an LSN `WalManager::reclaim` has already
    // established is unneeded by recovery — the same guarantee the leading-zero-skip below relies on.
    let base = scan_start
        .0
        .max(HEADER_LEN)
        .max(wal.sink().reclaimed_floor());
    // Capture the durable frontier ONCE, before undo appends any CLR/END record: every windowed read
    // in all three passes is bounded to this frontier, and every LSN the undo pass reads was already
    // decoded by analysis (so it is `< durable_len`) — never one of the un-synced CLRs undo appends.
    let durable_len = wal.durable_len();

    // --- Phase 1: analysis (streaming) ---
    // Retain ONLY summary state that is O(#txns), never O(#records): no `ordered` Vec, no `index`
    // HashMap, no whole-log buffer. This is what makes peak analysis memory O(window)+O(#txns).
    let mut committed: HashSet<u64> = HashSet::new();
    let mut ended: HashSet<u64> = HashSet::new();
    let mut txn_last: HashMap<u64, Lsn> = HashMap::new();
    let mut last_checkpoint: Option<CheckpointSnapshot> = None;
    let mut last_checkpoint_lsn: Option<Lsn> = None;
    let mut records_scanned = 0usize;

    // The first surviving record's absolute offset (past any leading reclaimed-zero prefix, `#114`).
    let first = find_first_record_offset(wal, base, durable_len, window)?;
    let tail_truncated = match first {
        // Empty (or entirely-reclaimed-to-zeros) retained range: nothing to analyse, no torn tail.
        None => false,
        Some(start) => {
            let outcome = scan_forward(wal, start, durable_len, window, true, |rec, _abs| {
                records_scanned += 1;
                match rec.rec_type {
                    RecordType::Commit => {
                        committed.insert(rec.txn_id.0);
                    }
                    RecordType::Abort => {
                        ended.insert(rec.txn_id.0);
                    }
                    RecordType::CheckpointEnd => {
                        if let Some(s) = CheckpointSnapshot::decode(rec.redo) {
                            last_checkpoint = Some(s);
                            last_checkpoint_lsn = Some(rec.lsn);
                        }
                    }
                    _ => {}
                }
                if rec.txn_id.0 != 0 {
                    txn_last.insert(rec.txn_id.0, rec.lsn);
                }
                Ok(())
            })?;
            match outcome {
                ScanOutcome::Complete => false,
                ScanOutcome::TornTail => true,
                // The cardinal ACID F4 invariant (unchanged): an undecodable record FOLLOWED by a
                // genuine self-consistent record is interior corruption — real committed data exists
                // beyond the failure, so truncating there would silently drop it. FAIL LOUD.
                ScanOutcome::InteriorCorruption { at, next } => {
                    return Err(GraphusError::Storage(format!(
                        "WAL interior log corruption: an undecodable record at offset {at} is \
                         followed by a valid record at offset {next}; refusing to recover, because \
                         truncating here would silently drop the committed transactions logged \
                         after offset {at}"
                    )));
                }
            }
        }
    };

    // --- Phase 2: redo (repeating history), streaming ---
    // Redo starts at the smallest dirty-page `recovery_lsn` the checkpoint captured (fuzzy
    // checkpoint), or the checkpoint's own LSN when its DPT is empty (sharp checkpoint), or the
    // header with no checkpoint. Per-page `page_lsn` gating below still skips any change already on
    // its page, so this floor only bounds *how much* is scanned, never correctness (`04 §4.8`).
    let redo_start = last_checkpoint
        .as_ref()
        .and_then(CheckpointSnapshot::redo_start)
        .or(last_checkpoint_lsn)
        .unwrap_or(Lsn(HEADER_LEN));

    let mut redo_applied = 0usize;
    if let Some(start) = first {
        // Re-scan the SAME retained record stream and apply page changes at/after `redo_start`,
        // in ascending LSN (scan) order — byte-identical to the old redo, which iterated every
        // scanned record and filtered by `rec.lsn >= redo_start`. We re-scan from `start` and gate
        // with the filter rather than *seeking* to `redo_start`, because `redo_start` is
        // checkpoint-derived and the old code never trusted it as a decode start offset. `probe =
        // false`: analysis already proved there is no interior corruption, so redo stops at the SAME
        // torn point without re-running the (now-unneeded) self-consistency probe. The redo
        // `page_lsn` gate is unchanged, so the doublewrite / floor-LSN gate the storage
        // `ApplyTarget` relies on is not weakened.
        scan_forward(wal, start, durable_len, window, false, |rec, _abs| {
            if rec.lsn >= redo_start
                && rec.rec_type.is_page_change()
                && !rec.redo.is_empty()
                && rec.lsn > target.page_lsn(rec.page_id)
            {
                target.apply(rec.page_id, rec.lsn, rec.redo)?;
                redo_applied += 1;
            }
            Ok(())
        })?;
    }

    // --- Phase 3: undo losers (LSN-targeted reads) ---
    let losers: Vec<u64> = txn_last
        .keys()
        .copied()
        .filter(|t| !committed.contains(t) && !ended.contains(t))
        .collect();

    // Undo all losers in one merged backward pass: a max-heap over "next LSN to undo" yields strict
    // global descending-LSN order (deterministic, no HashMap iteration order leaks into applied-image
    // order), so writes interleaved across losers on the same page unwind newest-first. Each pop
    // reads exactly ONE record at its LSN ([`read_record_at`]) — O(1) resident records regardless of
    // a chain's length — instead of indexing a materialised `Vec<LogRecord>` of the whole log.
    let mut heap: BinaryHeap<u64> = BinaryHeap::new();
    for t in &losers {
        if let Some(l) = txn_last.get(t) {
            if l.0 != 0 {
                heap.push(l.0);
            }
        }
    }

    // A back-chain LSN below the first retained record was reclaimed away: the old in-memory `index`
    // simply had no entry for it and the loop `continue`d. Replicate that with a boundary check (the
    // reclaim floor guarantees a *loser's* full chain is retained, so this only ever fires for a
    // logical/backup-chain WAL whose `base` sits above an earlier record, `rmp` #71).
    let undo_floor = first.unwrap_or(base);

    let mut clrs_written = 0usize;
    while let Some(lsn_u) = heap.pop() {
        if lsn_u < undo_floor {
            continue;
        }
        let rec = read_record_at(wal, lsn_u)?;
        match rec.rec_type {
            // A CLR records an undo that already happened (redo-only); resume at the next LSN to
            // undo. Honouring a CLR written by a PREVIOUS interrupted recovery is what makes a crash
            // during recovery idempotent — the back-chain skips the already-compensated action.
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

/// How a streaming forward scan ([`scan_forward`]) ended (`rmp` #599).
pub(crate) enum ScanOutcome {
    /// Consumed every durable byte, decoding cleanly to `durable_len` (no tail loss).
    Complete,
    /// Stopped at a clean torn tail — an undecodable record with **no** self-consistent record after
    /// it (an un-acknowledged tail append that never completed).
    TornTail,
    /// Hit an undecodable record at `at` that a genuine, self-consistent record at `next` follows —
    /// interior corruption. Only returned when the caller requested the probe; the caller formats
    /// its own fail-loud error (the message differs by caller).
    InteriorCorruption { at: u64, next: u64 },
}

/// Finds the absolute offset of the first surviving record at/after `base`, skipping a leading run
/// of zero bytes — a **reclaimed WAL prefix** (`rmp` #114): freed segments / a drained tail read
/// back as zeros, and a real record never begins with a zero byte (its leading `total_len` is
/// `>= MIN_RECORD_LEN`). The skip is confined to the *leading* prefix; a reclaim only ever frees a
/// contiguous front prefix, so interior zero/garbage between real records is still caught by the
/// [`scan_forward`] corruption check. Windowed, so even a large reclaimed gap costs O(window) memory.
/// Returns `None` if `[base, durable_len)` is empty or entirely zero.
pub(crate) fn find_first_record_offset<S: LogSink>(
    wal: &WalManager<S>,
    base: u64,
    durable_len: u64,
    window: u64,
) -> Result<Option<u64>> {
    let mut abs = base;
    let mut buf = Vec::new();
    while abs < durable_len {
        let win_end = (abs + window).min(durable_len);
        wal.read_bounded(Lsn(abs), Lsn(win_end), &mut buf)?;
        if let Some(pos) = buf.iter().position(|&b| b != 0) {
            return Ok(Some(abs + pos as u64));
        }
        abs = win_end; // the whole window was zeros; keep skipping
    }
    Ok(None)
}

/// Streams the durable record range `[first_offset, durable_len)` window-by-window, invoking
/// `on_record` for every decoded record in ascending-LSN (scan) order, holding at most one
/// `window`-sized buffer at a time (`rmp` #599). Shared by the analysis and redo passes and by the
/// reopen transaction-table / id-high-water scans ([`WalManager::committed_transactions`],
/// [`WalManager::max_recovered_txn_id`]).
///
/// **Straddle handling.** A record whose `total_len` reaches past the current window decodes as
/// [`DecodeError::Incomplete`] — never `BadCrc`/`Corrupt`, which both require the whole record to be
/// present (a window cut always leaves too few bytes ⇒ `Incomplete`). On `Incomplete` in a non-final
/// window the next window restarts at that record's own offset; a single record larger than the
/// window *grows* the window rather than failing.
///
/// **Tail decision (the F4 invariant, byte-for-byte preserved).** On the FIRST undecodable record,
/// with `probe_interior_corruption` set, [`scan_for_self_consistent`] streams forward for a genuine
/// `lsn == offset` record: if one exists there is committed data beyond the failure ⇒
/// [`ScanOutcome::InteriorCorruption`] (caller fails loud); otherwise a clean
/// [`ScanOutcome::TornTail`]. With the probe off (the id-high-water scan, and the redo re-scan whose
/// interior corruption analysis already ruled out) any undecodable record simply ends the scan as a
/// torn tail.
pub(crate) fn scan_forward<S, F>(
    wal: &WalManager<S>,
    first_offset: u64,
    durable_len: u64,
    window: u64,
    probe_interior_corruption: bool,
    mut on_record: F,
) -> Result<ScanOutcome>
where
    S: LogSink,
    F: FnMut(LogRecordRef<'_>, u64) -> Result<()>,
{
    let mut abs = first_offset;
    let mut win = window;
    let mut buf = Vec::new();
    while abs < durable_len {
        let win_end = (abs + win).min(durable_len);
        wal.read_bounded(Lsn(abs), Lsn(win_end), &mut buf)?;
        let last_window = win_end == durable_len;
        let mut off = 0usize;
        let progress = loop {
            if off >= buf.len() {
                break off; // consumed cleanly to the window boundary (always a record boundary)
            }
            match LogRecordRef::decode(&buf[off..]) {
                Ok((rec, n)) => {
                    on_record(rec, abs + off as u64)?;
                    off += n;
                }
                Err(DecodeError::Incomplete) => {
                    if last_window {
                        // The true tail: torn-vs-interior decision at this offset.
                        return decide_tail(
                            wal,
                            abs + off as u64,
                            durable_len,
                            window,
                            probe_interior_corruption,
                        );
                    }
                    // Straddle: re-read from this record's start (`off == 0` ⇒ oversized record).
                    break off;
                }
                Err(DecodeError::BadCrc | DecodeError::Corrupt) => {
                    // A genuinely undecodable record (a window cut can only ever be `Incomplete`).
                    return decide_tail(
                        wal,
                        abs + off as u64,
                        durable_len,
                        window,
                        probe_interior_corruption,
                    );
                }
            }
        };
        if progress == 0 && !last_window {
            // A single record larger than the window straddles it: grow and retry from `abs`.
            win = win.checked_mul(2).ok_or_else(|| {
                GraphusError::Storage(
                    "WAL recovery window overflow: a single record exceeds addressable size"
                        .to_owned(),
                )
            })?;
            continue;
        }
        abs += progress as u64;
        win = window; // reset to the base window after making progress
    }
    Ok(ScanOutcome::Complete)
}

/// The torn-tail-vs-interior-corruption decision at the first undecodable record (`bad_at`),
/// preserving the whole-buffer semantics while streaming the probe (`rmp` #599): with the probe on,
/// an interior self-consistent record ⇒ interior corruption; otherwise (or with the probe off) a
/// clean torn tail.
fn decide_tail<S: LogSink>(
    wal: &WalManager<S>,
    bad_at: u64,
    durable_len: u64,
    window: u64,
    probe: bool,
) -> Result<ScanOutcome> {
    if !probe {
        return Ok(ScanOutcome::TornTail);
    }
    match scan_for_self_consistent(wal, bad_at + 1, durable_len, window)? {
        Some(next) => Ok(ScanOutcome::InteriorCorruption { at: bad_at, next }),
        None => Ok(ScanOutcome::TornTail),
    }
}

/// Streams `[from, durable_len)` for the first offset that decodes to a **self-consistent** record —
/// one whose stamped LSN equals its own absolute byte offset (`§4.1`: LSN == offset, and the offset
/// is covered by the record's CRC32C, so this is a record genuinely written at that position, not a
/// chance CRC hit — a stray hit would additionally have to carry exactly the right 8-byte offset).
///
/// Byte-for-byte equivalent to the pre-streaming whole-buffer probe: it advances **one byte at a
/// time** past any non-self-consistent decode (including a valid-but-wrong-offset decode), exactly as
/// before. It is windowed with **reslide-on-straddle** so a self-consistent record spanning a window
/// boundary is never missed — missing one would wrongly downgrade interior corruption to a torn tail
/// and silently drop committed data (the F4 violation). A candidate record larger than the window
/// grows it. Returns the absolute LSN of the first such record, or `None` if none remains.
fn scan_for_self_consistent<S: LogSink>(
    wal: &WalManager<S>,
    from: u64,
    durable_len: u64,
    window: u64,
) -> Result<Option<u64>> {
    let mut win_start = from;
    let mut win = window;
    let mut buf = Vec::new();
    while win_start < durable_len {
        let win_end = (win_start + win).min(durable_len);
        wal.read_bounded(Lsn(win_start), Lsn(win_end), &mut buf)?;
        let last_window = win_end == durable_len;
        let mut p = 0usize;
        while p < buf.len() {
            match LogRecordRef::decode(&buf[p..]) {
                Ok((rec, _)) => {
                    if rec.lsn.0 == win_start + p as u64 {
                        return Ok(Some(win_start + p as u64));
                    }
                    p += 1; // decoded but not self-consistent — advance one byte (as the old probe)
                }
                Err(DecodeError::Incomplete) => {
                    if last_window {
                        p += 1; // no full record can start here; scan on through the trailing bytes
                        continue;
                    }
                    break; // straddle: reslide so a boundary-spanning candidate is fully covered
                }
                Err(DecodeError::BadCrc | DecodeError::Corrupt) => {
                    p += 1;
                }
            }
        }
        if last_window {
            return Ok(None);
        }
        if p == 0 {
            // The candidate record at `win_start` is larger than the window: grow to cover it.
            win = win.checked_mul(2).ok_or_else(|| {
                GraphusError::Storage("WAL corruption-probe window overflow".to_owned())
            })?;
            continue;
        }
        // Reslide at the first offset we could not fully cover; `[win_start, win_start+p)` was fully
        // probed and held no self-consistent record, so no overlap re-probe is needed.
        win_start += p as u64;
        win = window;
    }
    Ok(None)
}

/// Reads exactly the one record at absolute offset `lsn` (its LSN == its offset, `§4.1`) for the undo
/// pass — materialising only that record, so a loser's undo back-chain costs O(1) resident records
/// regardless of its length (`rmp` #599). Reads the 4-byte `total_len` prefix first, then the exact
/// record bytes. Every LSN the undo pass reads was decoded successfully during analysis (it is on a
/// loser's back-chain built from scanned records), so its `total_len` is valid and bounded;
/// [`LogSink::read_bounded`] additionally caps every read at the sink's durable length.
fn read_record_at<S: LogSink>(wal: &WalManager<S>, lsn: u64) -> Result<LogRecord> {
    let mut hdr = Vec::new();
    wal.read_bounded(Lsn(lsn), Lsn(lsn.saturating_add(4)), &mut hdr)?;
    if hdr.len() < 4 {
        return Err(GraphusError::Storage(format!(
            "WAL undo: record at offset {lsn} is truncated below its 4-byte length prefix"
        )));
    }
    let total = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as u64;
    let mut buf = Vec::new();
    wal.read_bounded(Lsn(lsn), Lsn(lsn.saturating_add(total)), &mut buf)?;
    let (rec, _) = LogRecord::decode(&buf).map_err(|e| {
        GraphusError::Storage(format!(
            "WAL undo: record at offset {lsn} failed to decode ({e:?}) — the undo back-chain \
             references a non-record offset"
        ))
    })?;
    Ok(rec)
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

    // ---------------------------------------------------------------- `rmp` #599 streaming recovery

    /// An [`ApplyTarget`] that accepts any image (no fixed delta width) and never guards redo — used
    /// where the payload is not an 8-byte delta (the oversized-record and multi-MiB gates).
    #[derive(Debug, Default)]
    struct NullStore {
        applied: usize,
    }
    impl ApplyTarget for NullStore {
        fn page_lsn(&self, _page: PageId) -> Lsn {
            Lsn(0)
        }
        fn apply(&mut self, _page: PageId, _lsn: Lsn, _image: &[u8]) -> Result<()> {
            self.applied += 1;
            Ok(())
        }
    }

    /// **`rmp` #599 acceptance gate #1 (miri-friendly).** A retained WAL many *windows* larger than
    /// the streaming window must recover with the largest single physical read bounded by the window
    /// — O(window) memory, not O(WAL). A deliberately TINY window (via [`recover_from_windowed`]) lets
    /// a modest, fast, miri-runnable WAL still span dozens of windows, and a [`CountingSink`] observes
    /// the largest `read_bounded` any pass produced.
    #[test]
    fn large_wal_reopens_with_bounded_window_memory() {
        const TINY_WINDOW: u64 = 512; // >> a single ~80-byte record here, so no window growth occurs
        let counter = Arc::new(AtomicU64::new(0));
        let syncs = Arc::new(AtomicU64::new(0));
        let mut wal = WalManager::create(CountingSink::new(
            MemLogSink::new(),
            Arc::clone(&counter),
            Arc::clone(&syncs),
        ))
        .unwrap();

        const TXNS: u64 = 300; // ~300 small committed txns → many KiB of WAL, dozens of 512 B windows
        for i in 1..=TXNS {
            let txn = TxnId(i);
            wal.begin(txn);
            wal.log_update(txn, PageId(i % 8), d(1), d(-1));
            wal.commit(txn).unwrap();
        }
        let lifetime = wal.sink().durable_len();
        assert!(
            lifetime > TINY_WINDOW * 8,
            "WAL must span many windows (len={lifetime}, window={TINY_WINDOW})"
        );

        // Reopen and recover through the WINDOWED entry point with the tiny window.
        let sink = wal.sink().clone();
        counter.store(0, Ordering::SeqCst); // measure only the reopen + recovery reads
        let mut wal2 = WalManager::open(sink).unwrap();
        let mut store = DeltaStore::default();
        let report =
            recover_from_windowed(&mut wal2, &mut store, Lsn(HEADER_LEN), TINY_WINDOW).unwrap();

        // O(window): the largest single read stayed bounded by the window, though the WAL is many× it.
        let max_read = counter.load(Ordering::SeqCst);
        assert!(
            max_read <= TINY_WINDOW,
            "largest read {max_read} must be <= window {TINY_WINDOW} (WAL len {lifetime})"
        );
        assert!(
            max_read * 8 < lifetime,
            "the window ({max_read}) must be far below the WAL length ({lifetime}) — proof the read \
             is bounded by the window, not the log size"
        );

        // Correctness: every committed txn's +1 delta is redone; no losers; every record scanned.
        assert_eq!(report.losers, 0, "every txn committed");
        assert_eq!(
            report.redo_applied as u64, TXNS,
            "each commit's update is redone"
        );
        assert_eq!(
            report.records_scanned as u64,
            TXNS * 3,
            "begin + update + commit per txn"
        );
        assert!(!report.tail_truncated, "a clean log has no torn tail");
        let total: i64 = (0..8).map(|p| store.value(p)).sum();
        assert_eq!(total, TXNS as i64, "every committed +1 delta is present");
    }

    /// **`rmp` #599 grow path.** A single record whose encoded size exceeds the window must still
    /// recover: the window *grows* to cover it rather than the scan wedging. Uses a tiny window and a
    /// redo image larger than it, and asserts the record was decoded + redone AND that the observed
    /// read grew past the record size.
    #[test]
    fn oversized_single_record_grows_the_window() {
        const TINY_WINDOW: u64 = 512;
        let counter = Arc::new(AtomicU64::new(0));
        let syncs = Arc::new(AtomicU64::new(0));
        let mut wal = WalManager::create(CountingSink::new(
            MemLogSink::new(),
            Arc::clone(&counter),
            Arc::clone(&syncs),
        ))
        .unwrap();

        wal.begin(TxnId(1));
        // A redo image (2000 bytes) far larger than the 512-byte window; the whole record is ~2067 B.
        wal.log_update(TxnId(1), PageId(0), vec![7u8; 2000], vec![9u8; 10]);
        wal.commit(TxnId(1)).unwrap();

        let sink = wal.sink().clone();
        counter.store(0, Ordering::SeqCst);
        let mut wal2 = WalManager::open(sink).unwrap();
        let mut store = NullStore::default();
        let report =
            recover_from_windowed(&mut wal2, &mut store, Lsn(HEADER_LEN), TINY_WINDOW).unwrap();

        assert_eq!(
            report.redo_applied, 1,
            "the oversized record must be decoded and redone after the window grows"
        );
        assert_eq!(report.losers, 0);
        let max_read = counter.load(Ordering::SeqCst);
        assert!(
            max_read >= 2000,
            "the window must have grown to cover the oversized record (max_read={max_read})"
        );
    }

    /// **`rmp` #599 F4 in the streaming world.** Interior corruption whose FOLLOWING self-consistent
    /// record spans a window boundary must still be detected (fail loud), never downgraded to a torn
    /// tail. A window SMALLER than a record forces the reslide-and-grow path in
    /// [`scan_for_self_consistent`] to be exercised on every candidate — if it ever missed a
    /// boundary-spanning record it would silently truncate and drop committed data.
    #[test]
    fn interior_corruption_detected_across_window_boundaries() {
        let mut wal = WalManager::create(MemLogSink::new()).unwrap();
        for t in 1..=5u64 {
            wal.begin(TxnId(t));
            wal.log_update(TxnId(t), PageId(0), d(1), d(-1));
            wal.commit(TxnId(t)).unwrap();
        }
        let mut full = wal.sink().durable_bytes();
        // Corrupt the txn-id byte of the FIRST record (BadCrc), leaving records 2.. self-consistent.
        full[HEADER_LEN as usize + 20] ^= 0xFF;

        let mut sink = MemLogSink::new();
        sink.append(&full);
        sink.sync().unwrap();
        let mut wal2 = WalManager::open(sink).unwrap();
        let mut store = DeltaStore::default();
        // Window = 40 bytes, smaller than a record (~65 B): every self-consistency probe must reslide
        // and grow to fully cover a candidate — the streaming stress of the F4 detection path.
        let err = recover_from_windowed(&mut wal2, &mut store, Lsn(HEADER_LEN), 40)
            .expect_err("interior corruption spanning windows must fail loud, not truncate");
        assert!(
            err.to_string().contains("interior log corruption"),
            "must report interior corruption; got: {err}"
        );
    }

    /// **`rmp` #599 torn-tail complement.** A GENUINE torn tail (no self-consistent record after the
    /// torn point) must NOT false-positive as interior corruption even with a sub-record window — the
    /// streaming probe must return "no record follows" and truncate cleanly, recovering the committed
    /// prefix and rolling back the torn loser.
    #[test]
    fn genuine_torn_tail_across_windows_truncates_cleanly() {
        let mut wal = WalManager::create(MemLogSink::new()).unwrap();
        wal.begin(TxnId(1));
        wal.log_update(TxnId(1), PageId(0), d(-10), d(10));
        wal.commit(TxnId(1)).unwrap();
        wal.begin(TxnId(2));
        wal.log_update(TxnId(2), PageId(0), d(-5), d(5));
        let c2 = wal.commit(TxnId(2)).unwrap();
        let full = wal.sink().durable_bytes();
        let torn_len = (c2.0 + 3) as usize; // a few bytes into T2's COMMIT record: a torn tail

        let mut sink = MemLogSink::new();
        sink.append(&full[..torn_len]);
        sink.sync().unwrap();
        let mut wal2 = WalManager::open(sink).unwrap();
        let mut store = DeltaStore::default();
        // Tiny sub-record window: the torn record and the probe both straddle windows repeatedly.
        let report = recover_from_windowed(&mut wal2, &mut store, Lsn(HEADER_LEN), 40)
            .expect("a clean torn tail must recover, not fail loud");
        assert!(report.tail_truncated, "the torn COMMIT ends the scan");
        assert_eq!(report.losers, 1, "T2 is a loser (its COMMIT was torn)");
        assert_eq!(
            store.value(0),
            -10,
            "only T1's committed delta survives (undo reverts T2)"
        );
    }

    /// **`rmp` #599 acceptance gate #1 over the REAL default window and ALL reopen scans.** A retained
    /// WAL larger than [`RECOVERY_WINDOW_BYTES`] — with NO reclamation shrinking it (the "one very
    /// large transaction / large retained window" case the task targets) — must keep every reopen
    /// scan (`committed_transactions`, `max_recovered_txn_id`, `recover`) bounded to the window. This
    /// is the whole point of the task, exercised through the production entry points and the true
    /// 4 MiB window. Non-miri (a multi-MiB WAL is too slow under miri; the tiny-window gates above run
    /// the same logic under miri).
    #[cfg_attr(
        miri,
        ignore = "a multi-MiB WAL is too slow under miri; the tiny-window gates cover the logic"
    )]
    #[test]
    fn reopen_scans_stay_window_bounded_over_a_multi_mib_wal() {
        use graphus_core::Timestamp;

        let counter = Arc::new(AtomicU64::new(0));
        let syncs = Arc::new(AtomicU64::new(0));
        let mut wal = WalManager::create(CountingSink::new(
            MemLogSink::new(),
            Arc::clone(&counter),
            Arc::clone(&syncs),
        ))
        .unwrap();

        // Build > 1.5× RECOVERY_WINDOW_BYTES of committed records using ~8 KiB redo images, so the
        // retained window genuinely exceeds one default window with nothing reclaimed away.
        let redo = vec![0xABu8; 8 * 1024];
        let undo = vec![0xCDu8; 16];
        let target_len = RECOVERY_WINDOW_BYTES + RECOVERY_WINDOW_BYTES / 2;
        let mut n = 0u64;
        while wal.sink().durable_len() < target_len {
            n += 1;
            let txn = TxnId(n);
            wal.begin(txn);
            wal.log_update_borrowed(txn, PageId(n % 32), &redo, undo.clone());
            wal.commit_at(txn, Timestamp(n)).unwrap();
        }
        let lifetime = wal.sink().durable_len();
        assert!(
            lifetime > RECOVERY_WINDOW_BYTES,
            "the retained WAL must exceed one default window (len={lifetime})"
        );

        let sink = wal.sink().clone();
        counter.store(0, Ordering::SeqCst); // measure only the reopen scans below
        let mut wal2 = WalManager::open(sink).unwrap();

        // 1. committed_transactions — the real store reopen path — recovers all, bounded.
        let committed = wal2.committed_transactions().unwrap();
        assert_eq!(
            committed.len() as u64,
            n,
            "every committed txn is recovered"
        );
        // 2. max_recovered_txn_id — the id high-water reopen path — bounded.
        assert_eq!(
            wal2.max_recovered_txn_id().unwrap(),
            n,
            "id high-water is the last commit"
        );
        // 3. recover — the three-phase replay — bounded (no losers: all committed).
        let mut store = NullStore::default();
        let report = recover(&mut wal2, &mut store).unwrap();
        assert_eq!(report.losers, 0);
        assert_eq!(report.records_scanned as u64, n * 3);

        let max_read = counter.load(Ordering::SeqCst);
        assert!(
            max_read <= RECOVERY_WINDOW_BYTES,
            "largest reopen read {max_read} must be <= the window {RECOVERY_WINDOW_BYTES} even though \
             the retained WAL is {lifetime} bytes (>1 window) — this is the O(window) reopen bound"
        );
        assert!(
            max_read < lifetime,
            "the reopen read {max_read} must be strictly below the WAL length {lifetime}"
        );
    }
}
