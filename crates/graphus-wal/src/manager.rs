//! The write-ahead-log manager: LSN allocation, the per-transaction undo back-chain, group
//! commit, the buffer-pool WAL rule, fuzzy checkpoints, and the PANIC-on-fsync-failure policy.
//!
//! `WalManager` owns a [`LogSink`] and turns logical operations (begin / update / commit /
//! rollback / checkpoint) into [`LogRecord`]s. An LSN is a record's byte offset in the log
//! (`§4.1`), so allocating one is just reading the sink's buffered length. Group commit
//! (`§4.2`) is the [`commit`](WalManager::commit) path: it appends the `COMMIT` record and then
//! `fdatasync`s, so a batch of concurrent committers is hardened by one sync. Per `§4.9`, **any**
//! sync failure is unrecoverable and aborts the process (a controlled `panic!`).

use std::collections::BTreeMap;

use graphus_core::error::{GraphusError, Result};
use graphus_core::{Lsn, PageId, Timestamp, TxnId};

use crate::checkpoint::CheckpointSnapshot;
use crate::record::{LogRecord, LogRecordRef, RecordType};
use crate::recovery::ApplyTarget;
use crate::sink::LogSink;

/// Bytes reserved at the start of the log for its header, so that offset `0` is never a record
/// LSN and [`Lsn(0)`](graphus_core::Lsn) is unambiguously the null LSN.
pub const HEADER_LEN: u64 = 8;

/// The WAL file-header magic (`"GWAL"`, little-endian `u32`). Public so an out-of-crate consumer
/// reconstructing a logical WAL image (e.g. the backup-chain restore in `graphus-storage`, `rmp`
/// task #71) can stamp a header that [`WalManager::open`] accepts.
pub const WAL_MAGIC: u32 = 0x4757_414C; // "GWAL"

/// The WAL file-header version. Public alongside [`WAL_MAGIC`] for header reconstruction; bumped on
/// any incompatible log-header change.
pub const WAL_VERSION: u32 = 1;

/// One undoable action of an in-flight transaction, kept in memory so a live rollback never has
/// to read back un-synced log bytes.
struct UndoEntry {
    lsn: Lsn,
    page_id: PageId,
    undo: Vec<u8>,
    prev_lsn: Lsn,
}

/// In-memory state of an active transaction (its Active-Transaction-Table entry).
struct TxnState {
    /// LSN of this transaction's **first** logged record (its `BEGIN`, or its earliest record if it
    /// was reconstructed without one). Bounds WAL reclamation: the log below the oldest active
    /// transaction's `first_lsn` must be retained so a loser's undo back-chain stays readable.
    first_lsn: Lsn,
    last_lsn: Lsn,
    undo: Vec<UndoEntry>,
}

/// The write-ahead log over a [`LogSink`].
pub struct WalManager<S: LogSink> {
    sink: S,
    active: BTreeMap<TxnId, TxnState>,
    buf: Vec<u8>,
}

impl<S: LogSink> WalManager<S> {
    /// Initialises a fresh log on an empty `sink` (writes and hardens the header).
    ///
    /// # Errors
    /// Returns an error if the sink already holds bytes (use [`open`](WalManager::open)).
    pub fn create(mut sink: S) -> Result<Self> {
        if sink.buffered_len() != 0 {
            return Err(GraphusError::Storage(
                "WalManager::create requires an empty sink".to_owned(),
            ));
        }
        let mut hdr = [0u8; HEADER_LEN as usize];
        hdr[0..4].copy_from_slice(&WAL_MAGIC.to_le_bytes());
        hdr[4..8].copy_from_slice(&WAL_VERSION.to_le_bytes());
        sink.append(&hdr);
        let mut m = Self {
            sink,
            active: BTreeMap::new(),
            buf: Vec::new(),
        };
        m.harden();
        Ok(m)
    }

    /// Opens an existing log, validating its header. The returned manager has no active
    /// transactions; call [`crate::recover`] to replay the log before resuming operation.
    ///
    /// # Errors
    /// Returns an error if the header is missing or not a recognised Graphus WAL.
    pub fn open(sink: S) -> Result<Self> {
        if sink.durable_len() < HEADER_LEN {
            return Err(GraphusError::Storage(
                "WAL too short to contain a header".to_owned(),
            ));
        }
        // Bounded to exactly the header (`rmp` #525): `read_durable(0, ..)` would allocate and
        // zero-fill a buffer sized by the log's entire lifetime byte offset on a long-lived,
        // heavily-reclaimed WAL, for a check that only ever wants 8 bytes — this is called on every
        // reopen, so it must not scale with the log's history. See `LogSink::read_bounded`'s doc
        // comment for the full rationale (the exact mechanism behind a real crash).
        let mut hdr = Vec::new();
        sink.read_bounded(0, HEADER_LEN, &mut hdr)?;
        let magic = u32::from_le_bytes(hdr[0..4].try_into().expect("4-byte slice"));
        let version = u32::from_le_bytes(hdr[4..8].try_into().expect("4-byte slice"));
        if magic != WAL_MAGIC {
            return Err(GraphusError::Storage(
                "not a Graphus WAL (bad magic)".to_owned(),
            ));
        }
        if version != WAL_VERSION {
            return Err(GraphusError::Storage(format!(
                "unsupported WAL version {version}"
            )));
        }
        Ok(Self {
            sink,
            active: BTreeMap::new(),
            buf: Vec::new(),
        })
    }

    /// The LSN that the next appended record will receive (its byte offset).
    #[must_use]
    pub fn next_lsn(&self) -> Lsn {
        Lsn(self.sink.buffered_len())
    }

    /// The number of durable log bytes (the group-commit watermark).
    #[must_use]
    pub fn durable_len(&self) -> u64 {
        self.sink.durable_len()
    }

    /// Reads durable log bytes `[from, durable_len)` into `into` (cleared first). Used by
    /// recovery to scan the log.
    ///
    /// # Errors
    /// Propagates a sink read error.
    pub fn read_durable(&self, from: Lsn, into: &mut Vec<u8>) -> Result<()> {
        self.sink.read_durable(from.0, into)
    }

    /// Borrows the underlying sink (test/inspection helper).
    #[must_use]
    pub fn sink(&self) -> &S {
        &self.sink
    }

    /// Scans the durable log and returns every committed transaction with the MVCC `commit_ts` its
    /// commit record carries (`rmp` task #49).
    ///
    /// This is how a reopened [`RecordStore`](../../graphus_storage) rebuilds its Active/Recent
    /// Transaction Table after recovery: with lazy GC-time header freezing a committed version keeps
    /// the writer's in-flight `TxnId` on disk, so visibility must resolve that id to a commit
    /// timestamp, and the durable commit records are the source of truth. Non-MVCC commits (index /
    /// system transactions written via [`commit`](Self::commit)) carry the `0` sentinel timestamp;
    /// they are harmless to include (no version header references their `TxnId`).
    ///
    /// Corruption handling matches [`recover_from`](crate::recover_from) exactly: an undecodable
    /// record that is **followed** by a genuine, self-consistent record is *interior corruption* —
    /// there is committed data beyond the failure point, so stopping here would silently drop it (and
    /// thus drop those transactions from the rebuilt transaction table). That is the cardinal ACID
    /// violation, so this FAILS LOUD. An undecodable record with no genuine record after it is a
    /// benign torn tail (the last, un-acknowledged append never completed) and the scan stops there,
    /// preserving committed-or-nothing.
    ///
    /// # Errors
    /// Propagates a sink read error, or returns a storage error on interior WAL corruption.
    pub fn committed_transactions(&self) -> Result<Vec<(TxnId, Timestamp, Lsn)>> {
        // Bound the read to the sink's `reclaimed_floor()` (`rmp` #525): reading unconditionally from
        // `HEADER_LEN` makes `read_durable` allocate and zero-fill a buffer sized by the log's entire
        // lifetime byte offset once enough has been reclaimed, not by what is actually retained — see
        // `LogSink::reclaimed_floor`'s doc comment for the full rationale (this is the exact mechanism
        // behind a real OOM-abort crash on reopen).
        let base = HEADER_LEN.max(self.sink.reclaimed_floor());
        let mut log = Vec::new();
        self.read_durable(Lsn(base), &mut log)?;
        let mut out = Vec::new();
        // `log[0]` corresponds to absolute LSN `base`, so the scan starts at the buffer's beginning.
        let mut cursor = 0usize;
        // Skip a reclaimed (zero) prefix to the first surviving record (`rmp` #114; see
        // `recover_from`). A real record never begins with a zero byte.
        while cursor < log.len() && log[cursor] == 0 {
            cursor += 1;
        }
        while cursor < log.len() {
            // This scan reads only header fields and the commit timestamp prefix of `redo`, never the
            // owned redo/undo images, so decode in place (no per-record heap allocation).
            match LogRecordRef::decode(&log[cursor..]) {
                Ok((rec, n)) => {
                    cursor += n;
                    if rec.rec_type == RecordType::Commit {
                        if let Some(ts) = rec.commit_ts() {
                            out.push((rec.txn_id, ts, rec.lsn));
                        }
                    }
                }
                // Same interior-corruption guard as `recover_from`: only truncate on a genuine torn
                // tail; fail loud if real committed data follows the undecodable spot. Diagnostics
                // report absolute LSNs (`base + cursor`), not the buffer-relative index.
                Err(_) => {
                    let abs_cursor = base + cursor as u64;
                    if let Some(abs_off) =
                        crate::recovery::next_self_consistent_record(&log, cursor + 1, base)
                    {
                        return Err(GraphusError::Storage(format!(
                            "WAL interior log corruption: an undecodable record at offset \
                             {abs_cursor} is followed by a valid record at offset {abs_off}; \
                             refusing to rebuild the transaction table, because stopping here would \
                             silently drop the committed transactions logged after offset \
                             {abs_cursor}"
                        )));
                    }
                    break;
                }
            }
        }
        Ok(out)
    }

    /// Scans the durable log and returns the **largest real transaction id** that appears in *any*
    /// record (begin, update, commit, abort, CLR), or `0` if the log holds no real transaction.
    ///
    /// This is how a reopened engine restores a **monotonic, crash-durable transaction-id counter**:
    /// transaction ids are written into the durable WAL but are *not* otherwise persisted, so a fresh
    /// coordinator that restarted its counter from `0` would **reuse** ids already present in the log.
    /// A reused id is catastrophic for ARIES recovery: a later crash's analysis pass collapses both
    /// incarnations of the id into a single Active-Transaction-Table entry, so if the post-recovery
    /// incarnation committed, the analysis marks the id `committed`/`ended` and the **pre-crash,
    /// uncommitted incarnation is no longer classified as a loser** — its redone effects are never
    /// undone and an uncommitted record survives (an atomicity violation). Seeding the counter past
    /// every id in the durable log makes ids globally unique across recovery, which the loser/winner
    /// classification depends on.
    ///
    /// The system sentinel [`TxnId(u64::MAX)`] (used for internal catalog/checkpoint writes) and the
    /// null id `0` are excluded: the issued-id space is `1..u64::MAX`, so the sentinel must never
    /// become the high-water (it would overflow the next `+= 1`).
    ///
    /// # Errors
    /// Propagates a sink read error. (Corruption is handled exactly as
    /// [`committed_transactions`](Self::committed_transactions): a torn tail stops the scan; interior
    /// corruption is rejected by the recovery path that runs alongside this, so this scan simply stops
    /// at the first undecodable record and never reads past it.)
    pub fn max_recovered_txn_id(&self) -> Result<u64> {
        // Bound the read to `reclaimed_floor()`, exactly like `committed_transactions` (`rmp` #525) —
        // see that method's comment and `LogSink::reclaimed_floor`'s doc comment for the rationale.
        let base = HEADER_LEN.max(self.sink.reclaimed_floor());
        let mut log = Vec::new();
        self.read_durable(Lsn(base), &mut log)?;
        let mut max_id = 0u64;
        // `log[0]` corresponds to absolute LSN `base`, so the scan starts at the buffer's beginning.
        let mut cursor = 0usize;
        // Skip a reclaimed (zero) prefix to the first surviving record (`rmp` #114; see
        // `recover_from`). A real record never begins with a zero byte.
        while cursor < log.len() && log[cursor] == 0 {
            cursor += 1;
        }
        while cursor < log.len() {
            match LogRecordRef::decode(&log[cursor..]) {
                Ok((rec, n)) => {
                    cursor += n;
                    let id = rec.txn_id.0;
                    if id != 0 && id != u64::MAX {
                        max_id = max_id.max(id);
                    }
                }
                // A torn tail (or any undecodable record): stop. The recovery path running over the
                // same log fails loud on interior corruption (`recover_from`); here we only need a
                // safe upper bound for the id counter, and a torn tail carries no committed work.
                Err(_) => break,
            }
        }
        Ok(max_id)
    }

    /// Logs the start of transaction `txn`.
    pub fn begin(&mut self, txn: TxnId) -> Lsn {
        let mut r = LogRecord::new(RecordType::Begin, txn, PageId(0));
        let lsn = self.append(&mut r);
        self.active.insert(
            txn,
            TxnState {
                first_lsn: lsn,
                last_lsn: lsn,
                undo: Vec::new(),
            },
        );
        lsn
    }

    /// Logs a page modification by `txn`: `redo` re-applies it, `undo` rolls it back. Returns the
    /// record's LSN, which the caller stamps as the page's `page_lsn`.
    pub fn log_update(&mut self, txn: TxnId, page_id: PageId, redo: Vec<u8>, undo: Vec<u8>) -> Lsn {
        // Single code path with the borrowed-redo entry point (`rmp` #373): the redo `Vec` is only
        // read (encoded into the durable record) and then dropped, so borrowing it here is exactly
        // equivalent to the prior owned encoding — same LSN, same durable bytes, same `UndoEntry`.
        self.log_update_borrowed(txn, page_id, &redo, undo)
    }

    /// Logs a page modification by `txn` taking the **redo image by borrow** (`rmp` #373): identical
    /// in every observable respect to [`log_update`](Self::log_update) — same LSN assignment, same
    /// durable bytes, same in-memory [`UndoEntry`] — but the caller need not heap-allocate a `Vec`
    /// for the redo image, which this method only reads (encodes into the durable record) and never
    /// retains. The `undo` image *is* retained (it backs rollback/recovery), so it is taken by value.
    ///
    /// This is the OLTP write path's allocation-lean entry point: storage builds redo/undo as inline
    /// [`graphus_storage`-style `SmallVec`] patches and passes `redo.as_slice()` here, so a tiny
    /// record/field patch (<=128 bytes) reaches the WAL with zero redo allocation. Because the
    /// encoder ([`LogRecord::encode_header_to`]) sources the redo from the slice, the produced WAL
    /// frame is byte-for-byte identical to the owned-`Vec` path.
    pub fn log_update_borrowed(
        &mut self,
        txn: TxnId,
        page_id: PageId,
        redo: &[u8],
        undo: Vec<u8>,
    ) -> Lsn {
        let prev = self.active.get(&txn).map_or(Lsn(0), |s| s.last_lsn);
        let mut r = LogRecord::new(RecordType::Update, txn, page_id);
        r.prev_lsn = prev;
        // Encode directly from the borrowed `redo` and the soon-to-be-retained `undo` — no owned
        // `r.redo`/`r.undo` Vec is built, so the redo image never allocates. Mirror `append`'s
        // LSN-then-encode-then-sink sequence exactly so byte layout and ordering are unchanged.
        let lsn = self.next_lsn();
        self.buf.clear();
        r.encode_header_to(lsn, redo, &undo, &mut self.buf);
        self.sink.append(&self.buf);
        let st = self.active.entry(txn).or_insert(TxnState {
            first_lsn: lsn,
            last_lsn: lsn,
            undo: Vec::new(),
        });
        st.last_lsn = lsn;
        st.undo.push(UndoEntry {
            lsn,
            page_id,
            undo,
            prev_lsn: prev,
        });
        lsn
    }

    /// Commits `txn` (group commit): appends its `COMMIT` record and hardens the log so the commit
    /// and everything before it are durable before returning. The record carries no MVCC timestamp
    /// (it decodes to the `0` sentinel via [`LogRecord::commit_ts`]); generic transactions that are
    /// not MVCC version-stamped — e.g. the index/system transactions — use this. MVCC record-store
    /// commits use [`commit_at`](Self::commit_at) so recovery can rebuild the transaction table.
    ///
    /// # Errors
    /// Returns an error if `txn` is not active.
    ///
    /// # Panics
    /// Panics (controlled abort) if the durability `fdatasync` fails (`§4.9`).
    pub fn commit(&mut self, txn: TxnId) -> Result<Lsn> {
        let prev = self.commit_prev_lsn(txn)?;
        // Built exactly as before commit records carried a timestamp (empty `redo`), so existing
        // logs/LSNs are byte-for-byte unchanged; `commit_ts()` still reads the `0` sentinel.
        let mut r = LogRecord::new(RecordType::Commit, txn, PageId(0));
        r.prev_lsn = prev;
        Ok(self.finish_commit(txn, &mut r))
    }

    /// Commits `txn` (group commit) carrying its MVCC `commit_ts` (`04 §5.2`, `rmp` task #49) in the
    /// commit record, then hardens the log.
    ///
    /// The `commit_ts` is embedded in the commit record so recovery can rebuild the Active/Recent
    /// Transaction Table: with lazy GC-time header freezing a committed version keeps the writer's
    /// in-flight `TxnId` on disk, and the commit record is the only durable proof of the timestamp it
    /// committed at (robust to checkpoint truncation — see [`LogRecord::commit`]).
    ///
    /// # Errors
    /// Returns an error if `txn` is not active.
    ///
    /// # Panics
    /// Panics (controlled abort) if the durability `fdatasync` fails (`§4.9`).
    pub fn commit_at(&mut self, txn: TxnId, commit_ts: Timestamp) -> Result<Lsn> {
        let prev = self.commit_prev_lsn(txn)?;
        let mut r = LogRecord::commit(txn, prev, commit_ts);
        Ok(self.finish_commit(txn, &mut r))
    }

    /// Commit-**PREPARE** (cross-transaction group commit, phase 1, `§4.2` / `rmp` #528): appends
    /// `txn`'s MVCC `commit_ts`-bearing `COMMIT` record and retires it from the active table, but does
    /// **NOT** `fdatasync` — the record sits in the sink's pending buffer until a later
    /// [`flush`](Self::flush) hardens the whole batch.
    ///
    /// The produced durable bytes and returned LSN are **byte-for-byte identical** to
    /// [`commit_at`](Self::commit_at); only the sync is deferred, so a batch of concurrent committers is
    /// hardened by ONE `fdatasync` instead of one each. The commit is committed-**visible** the instant
    /// its store publishes the timestamp, but only committed-**durable** once a covering `flush` returns
    /// — so the caller MUST `flush()` (past the returned LSN) **before** acknowledging `txn` to its
    /// client (the ack-after-fsync rule). A crash before that `flush` loses this record (a torn tail
    /// recovery truncates), which is correct precisely because the client was never acked.
    ///
    /// # Errors
    /// Returns an error if `txn` is not active.
    pub fn commit_at_no_sync(&mut self, txn: TxnId, commit_ts: Timestamp) -> Result<Lsn> {
        let prev = self.commit_prev_lsn(txn)?;
        let mut r = LogRecord::commit(txn, prev, commit_ts);
        Ok(self.append_commit_record(txn, &mut r))
    }

    /// The `prev_lsn` to thread into `txn`'s commit record (its last logged action).
    fn commit_prev_lsn(&self, txn: TxnId) -> Result<Lsn> {
        Ok(self
            .active
            .get(&txn)
            .ok_or_else(|| GraphusError::Transaction(format!("commit of inactive txn {}", txn.0)))?
            .last_lsn)
    }

    /// Appends `txn`'s prepared commit record and retires `txn` from the active table, but does **not**
    /// harden — the group-commit PREPARE step (`§4.2`, `rmp` #528). Shared by the deferred
    /// [`commit_at_no_sync`](Self::commit_at_no_sync) and the eager [`finish_commit`](Self::finish_commit).
    ///
    /// Removing `txn` from the active table before the (deferred) harden is sound: nothing runs between
    /// this and the batch `flush` that reads the active table (the single writer appends the rest of the
    /// batch and then hardens), and once the `COMMIT` record is durable `txn` is a recovery *winner* whose
    /// undo back-chain is no longer needed. A crash before the `flush` loses this un-synced record, so
    /// `txn` reverts to a loser whose still-durable earlier records (if any) recovery undoes normally.
    fn append_commit_record(&mut self, txn: TxnId, r: &mut LogRecord) -> Lsn {
        let lsn = self.append(r);
        self.active.remove(&txn);
        lsn
    }

    /// Appends `txn`'s prepared commit record, hardens the log (group commit, `§4.2`), and retires
    /// `txn` from the active table. Shared by [`commit`](Self::commit) and
    /// [`commit_at`](Self::commit_at).
    fn finish_commit(&mut self, txn: TxnId, r: &mut LogRecord) -> Lsn {
        let lsn = self.append_commit_record(txn, r);
        self.harden();
        lsn
    }

    /// Rolls `txn` back: undoes its actions newest-first, writing a CLR per action and applying
    /// the compensating change to `target`, then logs `ABORT` and hardens.
    ///
    /// A transaction that logged **nothing** — a read-only transaction, now that `BEGIN` is lazy
    /// (`rmp` #529): the WAL active-table entry is created only by the first data record, so a
    /// transaction that never called [`log_update`](Self::log_update) has no entry — has nothing to
    /// undo, so its rollback is a **no-op**: no CLRs, no `ABORT` record, and no `fdatasync`. This is
    /// exactly what makes a read-only abort (e.g. an SSI pivot victim, `04 §5.4`) cost zero WAL bytes
    /// and zero syncs. It is also idempotent for a genuinely absent id (a double rollback), which the
    /// old error return forbade; the store layer never rolls back an id it did not open, so relaxing
    /// this cannot mask a real bug.
    ///
    /// # Errors
    /// Returns an error if a compensating apply fails.
    ///
    /// # Panics
    /// Panics if the final `fdatasync` fails (`§4.9`).
    pub fn rollback<T: ApplyTarget>(&mut self, txn: TxnId, target: &mut T) -> Result<()> {
        let Some(st) = self.active.remove(&txn) else {
            return Ok(());
        };
        for entry in st.undo.iter().rev() {
            let clr_lsn =
                self.write_clr(txn, entry.page_id, entry.lsn, &entry.undo, entry.prev_lsn);
            target.apply(entry.page_id, clr_lsn, &entry.undo)?;
        }
        let mut end = LogRecord::new(RecordType::Abort, txn, PageId(0));
        self.append(&mut end);
        self.harden();
        Ok(())
    }

    /// Writes a fuzzy checkpoint (`§4.7`): a `CHECKPOINT-BEGIN`, then a `CHECKPOINT-END`
    /// embedding the caller-supplied Dirty Page Table and the current Active Transaction Table.
    /// Returns the `CHECKPOINT-END` LSN (the "last clean checkpoint LSN"). Hardened before
    /// returning.
    ///
    /// # Panics
    /// Panics if the `fdatasync` fails (`§4.9`).
    pub fn checkpoint(&mut self, dirty_page_table: &[(PageId, Lsn)]) -> Lsn {
        let mut begin = LogRecord::new(RecordType::CheckpointBegin, TxnId(0), PageId(0));
        self.append(&mut begin);
        let snapshot = CheckpointSnapshot {
            dirty_pages: dirty_page_table.to_vec(),
            active_txns: self.active.iter().map(|(t, s)| (*t, s.last_lsn)).collect(),
        };
        let mut end = LogRecord::new(RecordType::CheckpointEnd, TxnId(0), PageId(0));
        end.redo = snapshot.encode();
        let lsn = self.append(&mut end);
        self.harden();
        lsn
    }

    /// Physically reclaims the durable log below `up_to` (`§4.7`, `rmp` #114), bounding WAL disk and
    /// the recovery analysis scan. `up_to` is the caller's recovery floor — typically the last
    /// checkpoint's `redo_start` (after a sharp checkpoint, the checkpoint LSN). This method further
    /// clamps it to the **oldest active transaction's first LSN**, so a loser's undo back-chain is
    /// never reclaimed; with that floor the reclaimed prefix is provably unneeded by recovery.
    ///
    /// Byte offsets / LSNs are unchanged (the reclaimed prefix simply reads back as zeros, which
    /// recovery skips). A sink that cannot reclaim (the default [`LogSink::reclaim`]) makes this a
    /// no-op — always correct, just not disk-bounded.
    ///
    /// # Errors
    /// Propagates a sink reclaim failure.
    pub fn reclaim(&mut self, up_to: Lsn) -> Result<()> {
        let floor = self
            .active
            .values()
            .map(|s| s.first_lsn.0)
            .min()
            .map_or(up_to.0, |oldest| up_to.0.min(oldest));
        self.sink.reclaim(HEADER_LEN, floor)
    }

    /// The **first LSN** (its `BEGIN`, or earliest logged record) of the **oldest still-active**
    /// (uncommitted, un-aborted) transaction, or `None` if no transaction is currently active.
    ///
    /// This is the WAL position at and after which an online backup must capture the log so that a
    /// restore can roll back any transaction that was in flight when the backup was taken (`rmp`
    /// #413). A `backup_store` steals an in-flight transaction's dirty pages into the base image
    /// (steal/no-force), so the chain must also carry that transaction's *undo* records — every one
    /// from its first LSN onward — or recovery's loser-undo back-chain walks a `prev_lsn` into an
    /// LSN that is not in the restored log and silently stops, leaving uncommitted data baked into
    /// the base as if committed (an atomicity violation).
    #[must_use]
    pub fn oldest_active_first_lsn(&self) -> Option<Lsn> {
        self.active.values().map(|s| s.first_lsn).min()
    }

    /// Whether `txn` currently has an Active-Transaction-Table entry — i.e. it has logged at least
    /// one record. Since `BEGIN` is lazy (`rmp` #529, [`begin`](Self::begin) is no longer emitted by
    /// the store's `begin`), the entry is created on demand by the first
    /// [`log_update`](Self::log_update); so a transaction that has logged **nothing** — a read-only
    /// transaction — has no entry.
    ///
    /// This is the signal [`RecordStore::commit`](../../graphus_storage) uses to decide a transaction
    /// wrote nothing durable and so may skip its WAL `COMMIT` record, its catalog checkpoint, and the
    /// group-commit `fdatasync` entirely: a read-only transaction has no version, no on-disk in-flight
    /// stamp, and no catalog delta a crash could need.
    #[must_use]
    pub fn is_active(&self, txn: TxnId) -> bool {
        self.active.contains_key(&txn)
    }

    /// The buffer-pool **WAL rule** (`§4` / `graphus_bufpool::WalRule`): before a dirty page
    /// whose `page_lsn` is `up_to` is written home, the log must be durable through `up_to`.
    /// Because the log only ever syncs whole records, `durable_len` lands on a record boundary,
    /// so `durable_len > up_to` exactly means the record at `up_to` is fully durable.
    ///
    /// # Panics
    /// Panics if the `fdatasync` fails (`§4.9`).
    pub fn ensure_durable(&mut self, up_to: Lsn) {
        if self.sink.durable_len() <= up_to.0 {
            self.harden();
        }
    }

    /// Forces every appended record durable (an explicit group-commit flush).
    ///
    /// # Panics
    /// Panics if the `fdatasync` fails (`§4.9`).
    pub fn flush(&mut self) {
        self.harden();
    }

    /// Appends a Compensation Log Record (redo-only) during undo, recording the compensating
    /// image and the next LSN still to undo. Public for the recovery driver.
    pub fn write_clr(
        &mut self,
        txn: TxnId,
        page_id: PageId,
        compensated_lsn: Lsn,
        image: &[u8],
        undo_next: Lsn,
    ) -> Lsn {
        let mut r = LogRecord::new(RecordType::Clr, txn, page_id);
        r.prev_lsn = compensated_lsn;
        r.undo_next_lsn = undo_next;
        r.redo = image.to_vec();
        self.append(&mut r)
    }

    /// Appends an `ABORT` end-of-undo marker for `txn`. Public for the recovery driver.
    pub fn write_end(&mut self, txn: TxnId) -> Lsn {
        let mut r = LogRecord::new(RecordType::Abort, txn, PageId(0));
        self.append(&mut r)
    }

    fn append(&mut self, rec: &mut LogRecord) -> Lsn {
        let lsn = self.next_lsn();
        self.buf.clear();
        rec.encode_to(lsn, &mut self.buf);
        self.sink.append(&self.buf);
        lsn
    }

    /// Mutable access to the owned sink, for arming fault injection in tests only.
    #[cfg(test)]
    fn sink_mut_for_test(&mut self) -> &mut S {
        &mut self.sink
    }

    /// Hardens the log, treating a sync failure as unrecoverable (`§4.9`).
    fn harden(&mut self) {
        if let Err(e) = self.sink.sync() {
            panic!("WAL fdatasync failed; aborting to avoid silent data loss (fsyncgate): {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::LogRecord;
    use crate::sink::MemLogSink;

    fn decode_all(bytes: &[u8]) -> Vec<LogRecord> {
        let mut cur = HEADER_LEN as usize;
        let mut out = Vec::new();
        while cur < bytes.len() {
            let (r, n) = LogRecord::decode(&bytes[cur..]).expect("decode");
            cur += n;
            out.push(r);
        }
        out
    }

    #[test]
    fn create_then_open_validates_header() {
        let wal = WalManager::create(MemLogSink::new()).unwrap();
        assert_eq!(wal.durable_len(), HEADER_LEN);
        let sink = wal.sink().clone();
        assert!(WalManager::open(sink).is_ok());
    }

    #[test]
    fn max_recovered_txn_id_is_the_high_water_excluding_sentinels() {
        // Regression for the cross-recovery transaction-id-reuse atomicity bug: a reopened engine must
        // resume its id counter PAST every id already in the durable WAL (begin/update/commit/abort),
        // or it reuses ids and a later crash mis-classifies a pre-crash loser as committed/ended,
        // resurrecting its uncommitted effects. The fresh log has no real txns; ids appear via records;
        // the system sentinel `TxnId(u64::MAX)` and the null id `0` must be excluded.
        let mut wal = WalManager::create(MemLogSink::new()).unwrap();
        assert_eq!(
            wal.max_recovered_txn_id().unwrap(),
            0,
            "fresh log has no real txns"
        );

        wal.begin(TxnId(3));
        wal.log_update(TxnId(3), PageId(1), b"r".to_vec(), b"u".to_vec());
        wal.commit(TxnId(3)).unwrap();
        wal.begin(TxnId(7)); // an in-flight loser (no commit/abort) still bumps the high-water
        wal.log_update(TxnId(7), PageId(2), b"r".to_vec(), b"u".to_vec());
        // A system-sentinel write (catalog/checkpoint) must NOT become the high-water (it would
        // overflow the next `+= 1`).
        wal.begin(TxnId(u64::MAX));
        wal.flush();

        let sink = wal.sink().clone();
        let reopened = WalManager::open(sink).unwrap();
        assert_eq!(
            reopened.max_recovered_txn_id().unwrap(),
            7,
            "high-water is the largest real id (7), never the u64::MAX sentinel"
        );
    }

    #[test]
    fn open_rejects_a_non_wal_sink() {
        let mut sink = MemLogSink::new();
        sink.append(&[0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0]);
        sink.sync().unwrap();
        assert!(WalManager::open(sink).is_err());
    }

    #[test]
    fn lsns_are_byte_offsets_and_chain_per_txn() {
        let mut wal = WalManager::create(MemLogSink::new()).unwrap();
        let b = wal.begin(TxnId(1));
        assert_eq!(b, Lsn(HEADER_LEN)); // first record sits right after the header
        let u1 = wal.log_update(TxnId(1), PageId(5), b"r1".to_vec(), b"u1".to_vec());
        let u2 = wal.log_update(TxnId(1), PageId(6), b"r2".to_vec(), b"u2".to_vec());
        assert!(b < u1 && u1 < u2);
        wal.commit(TxnId(1)).unwrap();

        let mut bytes = Vec::new();
        wal.read_durable(Lsn(0), &mut bytes).unwrap();
        let recs = decode_all(&bytes);
        assert_eq!(recs[0].rec_type, RecordType::Begin);
        assert_eq!(recs[1].prev_lsn, b); // update 1 chains back to begin
        assert_eq!(recs[2].prev_lsn, u1); // update 2 chains back to update 1
        assert_eq!(recs[3].rec_type, RecordType::Commit);
        assert_eq!(recs[3].prev_lsn, u2);
    }

    /// `rmp` #373 byte-identity guarantee: the allocation-lean borrowed-redo update path produces a
    /// durable log byte-for-byte identical to the owned-`Vec` `log_update` path, with identical LSNs
    /// and identical in-memory undo back-chains. This is the WAL-level proof that batching/avoiding
    /// the redo `Vec` on the OLTP write path does NOT change the WAL frame format — the property the
    /// CAS-undo (`#220`/`#172`) and ARIES recovery paths depend on.
    fn drive(
        mut log: impl FnMut(&mut WalManager<MemLogSink>, TxnId, PageId, &[u8], &[u8]),
    ) -> Vec<u8> {
        let mut wal = WalManager::create(MemLogSink::new()).unwrap();
        wal.begin(TxnId(1));
        // A node-with-3-props create shape: a whole-record body redo (post-image) with a short
        // MVCC-header undo, plus narrow 8-byte chain-head field writes whose undo differs in length
        // from the redo — exercising mixed redo/undo image sizes through both paths.
        log(&mut wal, TxnId(1), PageId(5), &[0xAB; 65], &[0x11; 25]); // node record body / header undo
        log(&mut wal, TxnId(1), PageId(6), &[0x22; 46], &[0x33; 25]); // prop record body / header undo
        log(&mut wal, TxnId(1), PageId(5), &[0x44; 8], &[0x55; 20]); // chain-head field / cas-style undo
        wal.commit(TxnId(1)).unwrap();
        wal.sink().durable_bytes()
    }

    #[test]
    fn borrowed_redo_update_is_byte_identical_to_owned() {
        let owned = drive(|w, t, p, redo, undo| {
            w.log_update(t, p, redo.to_vec(), undo.to_vec());
        });
        let borrowed = drive(|w, t, p, redo, undo| {
            w.log_update_borrowed(t, p, redo, undo.to_vec());
        });
        assert_eq!(
            owned, borrowed,
            "borrowed-redo WAL frames must be byte-for-byte identical to the owned-Vec path"
        );

        // The decoded records (LSNs, prev-LSN chain, redo/undo images, CRCs) must match exactly too.
        let ro = decode_all(&owned);
        let rb = decode_all(&borrowed);
        assert_eq!(
            ro, rb,
            "decoded WAL records must be identical across both paths"
        );
    }

    #[test]
    fn commit_hardens_the_log() {
        let mut wal = WalManager::create(MemLogSink::new()).unwrap();
        wal.begin(TxnId(1));
        wal.log_update(TxnId(1), PageId(0), b"r".to_vec(), b"u".to_vec());
        let before = wal.durable_len();
        let commit_lsn = wal.commit(TxnId(1)).unwrap();
        assert!(wal.durable_len() > commit_lsn.0); // commit record is durable
        assert!(wal.durable_len() > before);
    }

    #[test]
    fn ensure_durable_flushes_only_when_needed() {
        let mut wal = WalManager::create(MemLogSink::new()).unwrap();
        wal.begin(TxnId(1));
        let u = wal.log_update(TxnId(1), PageId(0), b"r".to_vec(), b"u".to_vec());
        // The update is appended but not yet durable.
        assert!(wal.durable_len() <= u.0);
        wal.ensure_durable(u); // WAL rule: harden through the page's lsn
        assert!(wal.durable_len() > u.0);
        let d = wal.durable_len();
        wal.ensure_durable(Lsn(0)); // already durable -> no-op
        assert_eq!(wal.durable_len(), d);
    }

    /// `rmp` #528 group commit: `commit_at_no_sync` produces the **byte-for-byte identical** durable
    /// log to `commit_at` — same LSN, same `COMMIT` record — once a `flush` hardens it. Deferring the
    /// `fdatasync` must not change the wire format recovery depends on.
    #[test]
    fn commit_at_no_sync_is_byte_identical_to_commit_at_after_flush() {
        let drive = |defer: bool| -> (Vec<u8>, u64) {
            let mut wal = WalManager::create(MemLogSink::new()).unwrap();
            wal.begin(TxnId(1));
            wal.log_update(TxnId(1), PageId(0), b"r".to_vec(), b"u".to_vec());
            let lsn = if defer {
                let lsn = wal.commit_at_no_sync(TxnId(1), Timestamp(7)).unwrap();
                wal.flush();
                lsn
            } else {
                wal.commit_at(TxnId(1), Timestamp(7)).unwrap()
            };
            (wal.sink().durable_bytes(), lsn.0)
        };
        let (eager_bytes, eager_lsn) = drive(false);
        let (deferred_bytes, deferred_lsn) = drive(true);
        assert_eq!(
            eager_bytes, deferred_bytes,
            "deferring the fdatasync must not change the durable WAL bytes"
        );
        assert_eq!(
            eager_lsn, deferred_lsn,
            "the COMMIT record LSN is unchanged"
        );
    }

    /// `rmp` #528 group commit — the core coalescing proof: `K` committers that PREPARE
    /// (`commit_at_no_sync`, no sync) and then issue ONE `flush` are hardened by exactly ONE
    /// `fdatasync`, not `K`. A `CountingSink` counts every `sync`. This is the strace-free evidence
    /// that concurrent committers no longer each pay a durability sync.
    #[test]
    fn group_commit_coalesces_k_commits_into_one_fdatasync() {
        use crate::test_support::CountingSink;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        let max_read = Arc::new(AtomicU64::new(0));
        let syncs = Arc::new(AtomicU64::new(0));
        let mut wal = WalManager::create(CountingSink::new(
            MemLogSink::new(),
            max_read,
            Arc::clone(&syncs),
        ))
        .unwrap();
        // The create wrote+hardened the header (one sync); reset so we count only the batch.
        syncs.store(0, Ordering::SeqCst);

        const K: u64 = 32;
        let mut last_lsn = Lsn(0);
        for i in 1..=K {
            let txn = TxnId(i);
            wal.begin(txn);
            wal.log_update(txn, PageId(0), b"redo".to_vec(), b"undo".to_vec());
            // PREPARE: append the COMMIT record with NO fdatasync (the group-commit deferral).
            last_lsn = wal.commit_at_no_sync(txn, Timestamp(i)).unwrap();
        }
        assert_eq!(
            syncs.load(Ordering::SeqCst),
            0,
            "PREPARE must issue ZERO fdatasyncs — all {K} commit records sit un-synced in the buffer"
        );

        // HARDEN the whole batch with ONE flush.
        wal.flush();
        assert_eq!(
            syncs.load(Ordering::SeqCst),
            1,
            "the whole batch of {K} committers is hardened by exactly ONE fdatasync"
        );
        // The single sync covers every committer's LSN (durable watermark past the last COMMIT).
        assert!(
            wal.durable_len() > last_lsn.0,
            "the batch fdatasync hardens the durable watermark past every batched commit LSN"
        );

        // Every committed transaction is recoverable from the hardened log.
        let committed = wal.committed_transactions().unwrap();
        assert_eq!(
            committed.len() as u64,
            K,
            "all {K} batched commits are durable and recoverable after the single fdatasync"
        );
    }

    /// `rmp` #528 group commit — an ISOLATED single commit still hardens exactly once (no regression):
    /// `commit_at` is one append + one `fdatasync`, exactly as before the batching split.
    #[test]
    fn isolated_single_commit_still_hardens_exactly_once() {
        use crate::test_support::CountingSink;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        let max_read = Arc::new(AtomicU64::new(0));
        let syncs = Arc::new(AtomicU64::new(0));
        let mut wal = WalManager::create(CountingSink::new(
            MemLogSink::new(),
            max_read,
            Arc::clone(&syncs),
        ))
        .unwrap();
        syncs.store(0, Ordering::SeqCst);

        wal.begin(TxnId(1));
        wal.log_update(TxnId(1), PageId(0), b"r".to_vec(), b"u".to_vec());
        wal.commit_at(TxnId(1), Timestamp(1)).unwrap();
        assert_eq!(
            syncs.load(Ordering::SeqCst),
            1,
            "an isolated commit_at issues exactly one fdatasync"
        );
    }

    /// `rmp` #528 group commit — **crash mid-batch**: only committers whose `COMMIT` record was covered
    /// by a completed `fdatasync` survive; a batch PREPAREd but not yet hardened is lost WHOLE (none of
    /// its members), never partially. Modelled deterministically with [`MemLogSink::crash`] (drops the
    /// un-synced tail), the exact DST power-loss model. This is the ACID-inviolable ack-after-fsync
    /// contract: the un-hardened batch's committers were never acked, so losing them is correct, and no
    /// partial batch is ever applied.
    #[test]
    fn crash_mid_batch_recovers_only_the_hardened_prefix() {
        let mut wal = WalManager::create(MemLogSink::new()).unwrap();

        // Batch A: two committers PREPAREd then HARDENED (durable, acked).
        for i in 1..=2u64 {
            wal.begin(TxnId(i));
            wal.log_update(TxnId(i), PageId(0), b"r".to_vec(), b"u".to_vec());
            wal.commit_at_no_sync(TxnId(i), Timestamp(i)).unwrap();
        }
        wal.flush(); // ONE fdatasync hardens batch A

        // Batch B: two more committers PREPAREd but the fdatasync NEVER completes (crash).
        for i in 3..=4u64 {
            wal.begin(TxnId(i));
            wal.log_update(TxnId(i), PageId(0), b"r".to_vec(), b"u".to_vec());
            wal.commit_at_no_sync(TxnId(i), Timestamp(i)).unwrap();
        }
        // Power loss BEFORE batch B's flush: the un-synced tail is dropped whole.
        wal.sink_mut_for_test().crash();

        // Reopen the durable image and read back the committed set.
        let sink = wal.sink().clone();
        let reopened = WalManager::open(sink).unwrap();
        let committed: Vec<u64> = reopened
            .committed_transactions()
            .unwrap()
            .into_iter()
            .map(|(t, _, _)| t.0)
            .collect();
        assert_eq!(
            committed,
            vec![1, 2],
            "only the hardened batch (txns 1,2) survives; the un-synced batch (3,4) is lost WHOLE — \
             never a partial application"
        );
    }

    #[test]
    #[should_panic(expected = "fdatasync failed")]
    fn fsync_failure_panics() {
        let mut wal = WalManager::create(MemLogSink::new()).unwrap();
        wal.begin(TxnId(1));
        wal.log_update(TxnId(1), PageId(0), b"r".to_vec(), b"u".to_vec());
        wal.sink_mut_for_test().arm_sync_error();
        let _ = wal.commit(TxnId(1)); // group-commit fdatasync fails -> controlled abort
    }
}
