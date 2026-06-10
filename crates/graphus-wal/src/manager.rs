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
use crate::record::{LogRecord, RecordType};
use crate::recovery::ApplyTarget;
use crate::sink::LogSink;

/// Bytes reserved at the start of the log for its header, so that offset `0` is never a record
/// LSN and [`Lsn(0)`](graphus_core::Lsn) is unambiguously the null LSN.
pub const HEADER_LEN: u64 = 8;

const WAL_MAGIC: u32 = 0x4757_414C; // "GWAL"
const WAL_VERSION: u32 = 1;

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
        let mut hdr = Vec::new();
        sink.read_durable(0, &mut hdr)?;
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
    /// they are harmless to include (no version header references their `TxnId`). The scan stops at
    /// the first torn/short tail record, exactly like recovery, preserving committed-or-nothing.
    ///
    /// # Errors
    /// Propagates a sink read error.
    pub fn committed_transactions(&self) -> Result<Vec<(TxnId, Timestamp)>> {
        let mut log = Vec::new();
        self.read_durable(Lsn(0), &mut log)?;
        let mut out = Vec::new();
        let mut cursor = HEADER_LEN as usize;
        while cursor < log.len() {
            match LogRecord::decode(&log[cursor..]) {
                Ok((rec, n)) => {
                    cursor += n;
                    if rec.rec_type == RecordType::Commit {
                        if let Some(ts) = rec.commit_ts() {
                            out.push((rec.txn_id, ts));
                        }
                    }
                }
                Err(_) => break,
            }
        }
        Ok(out)
    }

    /// Logs the start of transaction `txn`.
    pub fn begin(&mut self, txn: TxnId) -> Lsn {
        let mut r = LogRecord::new(RecordType::Begin, txn, PageId(0));
        let lsn = self.append(&mut r);
        self.active.insert(
            txn,
            TxnState {
                last_lsn: lsn,
                undo: Vec::new(),
            },
        );
        lsn
    }

    /// Logs a page modification by `txn`: `redo` re-applies it, `undo` rolls it back. Returns the
    /// record's LSN, which the caller stamps as the page's `page_lsn`.
    pub fn log_update(&mut self, txn: TxnId, page_id: PageId, redo: Vec<u8>, undo: Vec<u8>) -> Lsn {
        let prev = self.active.get(&txn).map_or(Lsn(0), |s| s.last_lsn);
        let mut r = LogRecord::new(RecordType::Update, txn, page_id);
        r.prev_lsn = prev;
        r.redo = redo;
        r.undo = undo.clone();
        let lsn = self.append(&mut r);
        let st = self.active.entry(txn).or_insert(TxnState {
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

    /// The `prev_lsn` to thread into `txn`'s commit record (its last logged action).
    fn commit_prev_lsn(&self, txn: TxnId) -> Result<Lsn> {
        Ok(self
            .active
            .get(&txn)
            .ok_or_else(|| GraphusError::Transaction(format!("commit of inactive txn {}", txn.0)))?
            .last_lsn)
    }

    /// Appends `txn`'s prepared commit record, hardens the log (group commit, `§4.2`), and retires
    /// `txn` from the active table. Shared by [`commit`](Self::commit) and
    /// [`commit_at`](Self::commit_at).
    fn finish_commit(&mut self, txn: TxnId, r: &mut LogRecord) -> Lsn {
        let lsn = self.append(r);
        self.harden();
        self.active.remove(&txn);
        lsn
    }

    /// Rolls `txn` back: undoes its actions newest-first, writing a CLR per action and applying
    /// the compensating change to `target`, then logs `ABORT` and hardens.
    ///
    /// # Errors
    /// Returns an error if `txn` is not active or a compensating apply fails.
    ///
    /// # Panics
    /// Panics if the final `fdatasync` fails (`§4.9`).
    pub fn rollback<T: ApplyTarget>(&mut self, txn: TxnId, target: &mut T) -> Result<()> {
        let st = self.active.remove(&txn).ok_or_else(|| {
            GraphusError::Transaction(format!("rollback of inactive txn {}", txn.0))
        })?;
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
