//! WAL log-record format (`specification/04-technical-design.md` §4.1).
//!
//! The WAL is an append-only sequence of variable-length records. A record's **LSN is its
//! starting byte offset in the log** (`§4.1`: "lsn ... = file offset based"), which makes
//! `record.lsn > page.page_lsn` comparisons during redo (`§4.8`) and the back-chain of
//! `prev_lsn` pointers O(1) to seek. Offset `0` is reserved by the log header
//! ([`crate::sink`]), so [`Lsn(0)`](graphus_core::Lsn) is always the *null* LSN.
//!
//! Each record is self-describing and self-checking: a leading `total_len` lets a forward
//! scan step record-to-record, and a trailing CRC32C over the whole record detects a torn or
//! partially written tail so recovery can stop at the last intact record (physiological
//! logging, `§4.1`).

use graphus_core::{Lsn, PageId, Timestamp, TxnId};

/// Bytes of the fixed record prefix that precede the variable-length `redo`/`undo` images:
/// `total_len(4) + lsn(8) + prev_lsn(8) + txn_id(8) + type(1) + page_id(8) + undo_next_lsn(8)`.
pub const REC_FIXED_PREFIX: usize = 4 + 8 + 8 + 8 + 1 + 8 + 8;

/// The smallest possible encoded record: the fixed prefix, two empty length-prefixed images,
/// and the trailing CRC32C.
pub const MIN_RECORD_LEN: usize = REC_FIXED_PREFIX + 4 + 4 + 4;

const OFF_TOTAL_LEN: usize = 0;
const OFF_LSN: usize = 4;
const OFF_PREV_LSN: usize = 12;
const OFF_TXN_ID: usize = 20;
const OFF_TYPE: usize = 28;
const OFF_PAGE_ID: usize = 29;
const OFF_UNDO_NEXT: usize = 37;
const OFF_REDO_LEN: usize = 45;

/// The kind of a [`LogRecord`] (`§4.1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    /// A transaction began.
    Begin = 1,
    /// A page was modified (physiological redo + logical undo).
    Update = 2,
    /// A record was inserted (specialised [`Update`](RecordType::Update) for allocation).
    Insert = 3,
    /// A record was deleted.
    Delete = 4,
    /// A transaction committed (durability point for group commit, `§4.2`).
    Commit = 5,
    /// A transaction aborted (its undo is complete).
    Abort = 6,
    /// A Compensation Log Record written during undo (`§4.4`); redo-only.
    Clr = 7,
    /// Start of a fuzzy checkpoint (`§4.7`).
    CheckpointBegin = 8,
    /// End of a fuzzy checkpoint, embedding the DPT + ATT snapshot (`§4.7`).
    CheckpointEnd = 9,
    /// A full pre-image of a page (torn-write fallback, `§4.5`).
    FullPageImage = 10,
    /// A store page was allocated.
    Alloc = 11,
    /// A store page was freed.
    Free = 12,
    /// One transaction's **net signed change** to the catalogue's live-record cardinality counters
    /// (`rmp` #1066); logical, and never a page change.
    ///
    /// The other twelve kinds describe a *page*: recovery replays them by writing bytes at a
    /// [`PageId`]. This one describes an *arithmetic* change to state that lives in the catalogue,
    /// and it exists because a shared image rewritten in full by every committer cannot be made
    /// exact under concurrent commits — the image one committer samples does not contain a
    /// transaction that commits before that image lands, so the last write wins and the committed
    /// rows are lost (`rmp` #1055). A delta does not have that failure mode: it names only what its
    /// own transaction changed, so no committer's record can erase another's.
    ///
    /// This crate frames the record and stores its payload verbatim; the payload's meaning belongs
    /// to `graphus-storage`, which owns the counters (the same split as
    /// [`CheckpointEnd`](RecordType::CheckpointEnd)'s snapshot, in the other direction). The payload
    /// rides in `redo`, which is safe because [`is_page_change`](RecordType::is_page_change) excludes
    /// this kind — so recovery's redo pass never hands those bytes to a page — exactly as
    /// [`Commit`](RecordType::Commit) carries its timestamp there.
    ///
    /// It is also **not** [`is_undoable_action`](RecordType::is_undoable_action): a delta belonging
    /// to a loser is never applied in the first place (the replay admits only committed
    /// transactions), so there is nothing for the undo pass to compensate. The undo pass walks past
    /// it along `prev_lsn` like any other control record.
    CountDelta = 13,
}

impl RecordType {
    /// Whether records of this type modify a page (and so carry a redo image replayed during
    /// recovery's redo phase). `CLR`s are redo-only page changes; checkpoints and the
    /// transaction-control records are not.
    #[must_use]
    pub fn is_page_change(self) -> bool {
        matches!(
            self,
            Self::Update
                | Self::Insert
                | Self::Delete
                | Self::Clr
                | Self::FullPageImage
                | Self::Alloc
                | Self::Free
        )
    }

    /// Whether records of this type must be undone (rolled back) for a loser transaction. `CLR`s
    /// are excluded: they record undo that has *already* happened.
    #[must_use]
    pub fn is_undoable_action(self) -> bool {
        matches!(
            self,
            Self::Update | Self::Insert | Self::Delete | Self::Alloc | Self::Free
        )
    }

    /// Parses a type byte, returning `None` for an unknown value.
    #[must_use]
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            1 => Self::Begin,
            2 => Self::Update,
            3 => Self::Insert,
            4 => Self::Delete,
            5 => Self::Commit,
            6 => Self::Abort,
            7 => Self::Clr,
            8 => Self::CheckpointBegin,
            9 => Self::CheckpointEnd,
            10 => Self::FullPageImage,
            11 => Self::Alloc,
            12 => Self::Free,
            13 => Self::CountDelta,
            _ => return None,
        })
    }
}

/// A single, decoded WAL record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRecord {
    /// This record's LSN (its starting byte offset in the log).
    pub lsn: Lsn,
    /// The previous LSN of the *same* transaction (undo back-chain); [`Lsn(0)`] if none.
    pub prev_lsn: Lsn,
    /// The owning transaction; [`TxnId(0)`] for non-transactional records (checkpoints).
    pub txn_id: TxnId,
    /// The record kind.
    pub rec_type: RecordType,
    /// The page affected, where applicable; [`PageId(0)`] otherwise.
    pub page_id: PageId,
    /// For a [`Clr`](RecordType::Clr): the next LSN still to be undone; [`Lsn(0)`] otherwise.
    pub undo_next_lsn: Lsn,
    /// Redo image / logical redo: how to (idempotently) re-apply the change.
    pub redo: Vec<u8>,
    /// Undo image / logical undo: how to roll the change back.
    pub undo: Vec<u8>,
}

/// Why decoding a record at a given offset failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Not enough bytes for a complete record: a truncated (torn) tail. A forward scan treats
    /// this as the clean end of the durable log — un-acknowledged tail records may be lost.
    Incomplete,
    /// A structurally impossible record (bad length or unknown type): corruption.
    Corrupt,
    /// The trailing CRC32C did not match the record body: corruption (or a torn tail).
    BadCrc,
}

impl LogRecord {
    /// Builds a record with empty `redo`/`undo` and the given header fields. The `lsn` is
    /// assigned by [`crate::WalManager`] at append time.
    #[must_use]
    pub fn new(rec_type: RecordType, txn_id: TxnId, page_id: PageId) -> Self {
        Self {
            lsn: Lsn(0),
            prev_lsn: Lsn(0),
            txn_id,
            rec_type,
            page_id,
            undo_next_lsn: Lsn(0),
            redo: Vec::new(),
            undo: Vec::new(),
        }
    }

    /// Builds a [`Commit`](RecordType::Commit) record for `txn` carrying its MVCC `commit_ts` in the
    /// `redo` field (`04 §5.2`, `rmp` task #49).
    ///
    /// Lazy GC-time freezing leaves a committed version's on-disk `xmin`/`xmax` as the writer's
    /// in-flight `TxnId`; the only durable record of "this `TxnId` committed at this timestamp" is the
    /// commit record itself, so it must carry the timestamp. Recovery rebuilds the in-memory
    /// Active/Recent Transaction Table from these records ([`commit_ts`](Self::commit_ts)) regardless
    /// of which older commits a checkpoint truncated away. The 8 little-endian bytes live in `redo`
    /// because a `Commit` record is never a page change ([`RecordType::is_page_change`] excludes it),
    /// so recovery never replays `redo` as a page image — the field is otherwise unused for commits.
    #[must_use]
    pub fn commit(txn: TxnId, prev_lsn: Lsn, commit_ts: Timestamp) -> Self {
        let mut r = Self::new(RecordType::Commit, txn, PageId(0));
        r.prev_lsn = prev_lsn;
        r.redo = commit_ts.0.to_le_bytes().to_vec();
        r
    }

    /// The MVCC commit timestamp carried by a [`Commit`](RecordType::Commit) record (`rmp` task #49).
    ///
    /// Returns the 8-byte little-endian timestamp written by [`commit`](Self::commit). A commit
    /// record whose `redo` is empty or shorter than 8 bytes (a torn tail, or a log written before
    /// commit records carried a timestamp) decodes to [`Timestamp(0)`](graphus_core::Timestamp) — the
    /// "unknown" sentinel the recovery wiring treats conservatively. Returns `None` for a non-commit
    /// record.
    #[must_use]
    pub fn commit_ts(&self) -> Option<Timestamp> {
        if self.rec_type != RecordType::Commit {
            return None;
        }
        let ts = self.redo.get(..8).map_or(0, |b| {
            u64::from_le_bytes(b.try_into().expect("8-byte slice"))
        });
        Some(Timestamp(ts))
    }

    /// Builds a [`CountDelta`](RecordType::CountDelta) record for `txn` carrying `payload` — one
    /// transaction's net signed change to the catalogue's cardinality counters (`rmp` #1066).
    ///
    /// The payload is opaque here: this crate frames and checksums it, and `graphus-storage` decides
    /// what it means. It rides in `redo` for the same reason a commit timestamp does — a count-delta
    /// record is never a page change ([`RecordType::is_page_change`] excludes it), so recovery's redo
    /// pass never replays those bytes as a page image and the field is otherwise unused.
    #[must_use]
    pub fn count_delta(txn: TxnId, prev_lsn: Lsn, payload: Vec<u8>) -> Self {
        let mut r = Self::new(RecordType::CountDelta, txn, PageId(0));
        r.prev_lsn = prev_lsn;
        r.redo = payload;
        r
    }

    /// The opaque counter payload carried by a [`CountDelta`](RecordType::CountDelta) record
    /// (`rmp` #1066); `None` for any other record kind.
    ///
    /// An empty payload is returned as `Some(&[])` rather than `None`: "a count-delta record whose
    /// payload is empty" and "not a count-delta record" are different facts, and only the caller can
    /// say whether the first is malformed.
    #[must_use]
    pub fn count_delta_payload(&self) -> Option<&[u8]> {
        (self.rec_type == RecordType::CountDelta).then_some(&self.redo)
    }

    /// The number of bytes this record occupies when encoded.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        REC_FIXED_PREFIX + 4 + self.redo.len() + 4 + self.undo.len() + 4
    }

    /// Appends the encoded form of this record to `out`, using `lsn` as its LSN and stamping it
    /// into the record, sourcing the redo/undo images from the record's own owned `Vec`s. Returns
    /// the encoded length.
    pub fn encode_to(&mut self, lsn: Lsn, out: &mut Vec<u8>) -> usize {
        // Borrow the owned images through `encode_header_to`: identical bytes, one code path
        // (`rmp` #373). `std::mem::take` avoids aliasing `&self` while `&mut self` is borrowed for
        // the header stamp; the images are restored immediately after.
        let redo = std::mem::take(&mut self.redo);
        let undo = std::mem::take(&mut self.undo);
        let total = self.encode_header_to(lsn, &redo, &undo, out);
        self.redo = redo;
        self.undo = undo;
        total
    }

    /// The byte-exact encoder shared by [`encode_to`](Self::encode_to) (owned images) and the
    /// manager's borrowed-redo update path (`rmp` #373): writes the fixed prefix and the supplied
    /// `redo`/`undo` slices, framing each with its `u32` length and a trailing CRC32C. The wire
    /// bytes are independent of whether the images are owned or borrowed.
    pub(crate) fn encode_header_to(
        &mut self,
        lsn: Lsn,
        redo: &[u8],
        undo: &[u8],
        out: &mut Vec<u8>,
    ) -> usize {
        self.lsn = lsn;
        // The redo/undo image lengths are framed as `u32` on the wire (below). A ≥4 GiB image would
        // truncate silently, producing a corrupt, undecodable record. Such an image is never produced
        // by this engine (page images are bounded), so guard with a debug assertion that fires in
        // tests/debug builds rather than emitting silent corruption.
        debug_assert!(
            redo.len() <= u32::MAX as usize,
            "WAL redo image {} bytes exceeds the u32 frame limit",
            redo.len()
        );
        debug_assert!(
            undo.len() <= u32::MAX as usize,
            "WAL undo image {} bytes exceeds the u32 frame limit",
            undo.len()
        );
        let total = REC_FIXED_PREFIX + 4 + redo.len() + 4 + undo.len() + 4;
        let start = out.len();
        out.reserve(total);
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out.extend_from_slice(&lsn.0.to_le_bytes());
        out.extend_from_slice(&self.prev_lsn.0.to_le_bytes());
        out.extend_from_slice(&self.txn_id.0.to_le_bytes());
        out.push(self.rec_type as u8);
        out.extend_from_slice(&self.page_id.0.to_le_bytes());
        out.extend_from_slice(&self.undo_next_lsn.0.to_le_bytes());
        out.extend_from_slice(&(redo.len() as u32).to_le_bytes());
        out.extend_from_slice(redo);
        out.extend_from_slice(&(undo.len() as u32).to_le_bytes());
        out.extend_from_slice(undo);
        let crc = crc32c::crc32c(&out[start..]);
        out.extend_from_slice(&crc.to_le_bytes());
        debug_assert_eq!(out.len() - start, total);
        total
    }

    /// Decodes the record at the start of `bytes`, returning it and the number of bytes it
    /// consumed. See [`DecodeError`] for the failure taxonomy a forward scan relies on.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), DecodeError> {
        if bytes.len() < REC_FIXED_PREFIX + 8 {
            return Err(DecodeError::Incomplete);
        }
        let total = read_u32(bytes, OFF_TOTAL_LEN) as usize;
        if total < MIN_RECORD_LEN {
            return Err(DecodeError::Corrupt);
        }
        if bytes.len() < total {
            return Err(DecodeError::Incomplete);
        }
        let rec = &bytes[..total];
        let stored_crc = read_u32(rec, total - 4);
        if crc32c::crc32c(&rec[..total - 4]) != stored_crc {
            return Err(DecodeError::BadCrc);
        }
        let rec_type = RecordType::from_u8(rec[OFF_TYPE]).ok_or(DecodeError::Corrupt)?;
        let redo_len = read_u32(rec, OFF_REDO_LEN) as usize;
        let redo_start = OFF_REDO_LEN + 4;
        let undo_len_off = redo_start
            .checked_add(redo_len)
            .ok_or(DecodeError::Corrupt)?;
        // The record must hold: redo, the undo length, the undo image, and the 4-byte CRC.
        if undo_len_off + 4 + 4 > total {
            return Err(DecodeError::Corrupt);
        }
        let undo_len = read_u32(rec, undo_len_off) as usize;
        let undo_start = undo_len_off + 4;
        if undo_start + undo_len + 4 != total {
            return Err(DecodeError::Corrupt);
        }
        Ok((
            Self {
                lsn: Lsn(read_u64(rec, OFF_LSN)),
                prev_lsn: Lsn(read_u64(rec, OFF_PREV_LSN)),
                txn_id: TxnId(read_u64(rec, OFF_TXN_ID)),
                rec_type,
                page_id: PageId(read_u64(rec, OFF_PAGE_ID)),
                undo_next_lsn: Lsn(read_u64(rec, OFF_UNDO_NEXT)),
                redo: rec[redo_start..redo_start + redo_len].to_vec(),
                undo: rec[undo_start..undo_start + undo_len].to_vec(),
            },
            total,
        ))
    }
}

/// A WAL record decoded **in place**: the `redo`/`undo` images borrow the source buffer instead of
/// being copied into owned `Vec`s. Used by read-only scans (the recovery transaction-table rebuild
/// and the torn-tail probe) that inspect only header fields and at most a prefix of `redo`, avoiding
/// the two heap allocations [`LogRecord::decode`] performs per record. The validation, field layout
/// and accept/reject behaviour are byte-for-byte identical to [`LogRecord::decode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRecordRef<'a> {
    /// See [`LogRecord::lsn`].
    pub lsn: Lsn,
    /// See [`LogRecord::prev_lsn`].
    pub prev_lsn: Lsn,
    /// See [`LogRecord::txn_id`].
    pub txn_id: TxnId,
    /// See [`LogRecord::rec_type`].
    pub rec_type: RecordType,
    /// See [`LogRecord::page_id`].
    pub page_id: PageId,
    /// See [`LogRecord::undo_next_lsn`].
    pub undo_next_lsn: Lsn,
    /// Redo image, borrowed from the source buffer.
    pub redo: &'a [u8],
    /// Undo image, borrowed from the source buffer.
    pub undo: &'a [u8],
}

impl<'a> LogRecordRef<'a> {
    /// Decodes the record at the start of `bytes` without allocating, borrowing `redo`/`undo` from
    /// the input. Same validation and error taxonomy as [`LogRecord::decode`].
    pub fn decode(bytes: &'a [u8]) -> Result<(Self, usize), DecodeError> {
        if bytes.len() < REC_FIXED_PREFIX + 8 {
            return Err(DecodeError::Incomplete);
        }
        let total = read_u32(bytes, OFF_TOTAL_LEN) as usize;
        if total < MIN_RECORD_LEN {
            return Err(DecodeError::Corrupt);
        }
        if bytes.len() < total {
            return Err(DecodeError::Incomplete);
        }
        let rec = &bytes[..total];
        let stored_crc = read_u32(rec, total - 4);
        if crc32c::crc32c(&rec[..total - 4]) != stored_crc {
            return Err(DecodeError::BadCrc);
        }
        let rec_type = RecordType::from_u8(rec[OFF_TYPE]).ok_or(DecodeError::Corrupt)?;
        let redo_len = read_u32(rec, OFF_REDO_LEN) as usize;
        let redo_start = OFF_REDO_LEN + 4;
        let undo_len_off = redo_start
            .checked_add(redo_len)
            .ok_or(DecodeError::Corrupt)?;
        if undo_len_off + 4 + 4 > total {
            return Err(DecodeError::Corrupt);
        }
        let undo_len = read_u32(rec, undo_len_off) as usize;
        let undo_start = undo_len_off + 4;
        if undo_start + undo_len + 4 != total {
            return Err(DecodeError::Corrupt);
        }
        Ok((
            Self {
                lsn: Lsn(read_u64(rec, OFF_LSN)),
                prev_lsn: Lsn(read_u64(rec, OFF_PREV_LSN)),
                txn_id: TxnId(read_u64(rec, OFF_TXN_ID)),
                rec_type,
                page_id: PageId(read_u64(rec, OFF_PAGE_ID)),
                undo_next_lsn: Lsn(read_u64(rec, OFF_UNDO_NEXT)),
                redo: &rec[redo_start..redo_start + redo_len],
                undo: &rec[undo_start..undo_start + undo_len],
            },
            total,
        ))
    }

    /// The MVCC commit timestamp carried by a [`Commit`](RecordType::Commit) record; see
    /// [`LogRecord::commit_ts`]. Returns `None` for a non-commit record.
    #[must_use]
    pub fn commit_ts(&self) -> Option<Timestamp> {
        if self.rec_type != RecordType::Commit {
            return None;
        }
        let ts = self.redo.get(..8).map_or(0, |b| {
            u64::from_le_bytes(b.try_into().expect("8-byte slice"))
        });
        Some(Timestamp(ts))
    }

    /// The opaque counter payload carried by a [`CountDelta`](RecordType::CountDelta) record; see
    /// [`LogRecord::count_delta_payload`]. Returns `None` for any other record kind.
    #[must_use]
    pub fn count_delta_payload(&self) -> Option<&'a [u8]> {
        (self.rec_type == RecordType::CountDelta).then_some(self.redo)
    }
}

fn read_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().expect("4-byte slice"))
}

fn read_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().expect("8-byte slice"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> LogRecord {
        let mut r = LogRecord::new(RecordType::Update, TxnId(7), PageId(42));
        r.prev_lsn = Lsn(16);
        r.redo = b"new-image".to_vec();
        r.undo = b"old".to_vec();
        r
    }

    #[test]
    fn round_trips_through_encode_decode() {
        let mut r = sample();
        let mut buf = Vec::new();
        let n = r.encode_to(Lsn(100), &mut buf);
        assert_eq!(n, buf.len());
        assert_eq!(n, r.encoded_len());
        let (got, consumed) = LogRecord::decode(&buf).unwrap();
        assert_eq!(consumed, n);
        assert_eq!(got, r);
        assert_eq!(got.lsn, Lsn(100));
    }

    #[test]
    fn decode_reports_incomplete_for_a_truncated_tail() {
        let mut r = sample();
        let mut buf = Vec::new();
        r.encode_to(Lsn(8), &mut buf);
        buf.truncate(buf.len() - 1); // lose the last byte (a torn tail)
        assert_eq!(LogRecord::decode(&buf), Err(DecodeError::Incomplete));
    }

    #[test]
    fn decode_reports_bad_crc_on_a_flipped_body_byte() {
        let mut r = sample();
        let mut buf = Vec::new();
        r.encode_to(Lsn(8), &mut buf);
        buf[OFF_REDO_LEN + 4] ^= 0xFF; // corrupt a redo byte
        assert_eq!(LogRecord::decode(&buf), Err(DecodeError::BadCrc));
    }

    #[test]
    fn decode_reports_corrupt_for_an_impossible_length() {
        let mut r = sample();
        let mut buf = Vec::new();
        r.encode_to(Lsn(8), &mut buf);
        buf[OFF_TOTAL_LEN..OFF_TOTAL_LEN + 4].copy_from_slice(&3u32.to_le_bytes());
        assert_eq!(LogRecord::decode(&buf), Err(DecodeError::Corrupt));
    }

    #[test]
    fn forward_scan_walks_three_records() {
        let mut log = Vec::new();
        let mut lsn = 8u64;
        let mut want = Vec::new();
        for i in 0..3 {
            let mut r = LogRecord::new(RecordType::Update, TxnId(i + 1), PageId(i));
            r.redo = vec![i as u8; (i as usize) * 4];
            let n = r.encode_to(Lsn(lsn), &mut log);
            want.push(r);
            lsn += n as u64;
        }
        let mut cursor = 0usize;
        let mut got = Vec::new();
        while cursor < log.len() {
            let (r, n) = LogRecord::decode(&log[cursor..]).unwrap();
            cursor += n;
            got.push(r);
        }
        assert_eq!(got, want);
    }

    #[test]
    fn commit_record_carries_its_commit_ts_through_encode_decode() {
        // `rmp` task #49: lazy freeze relies on the commit record carrying the commit timestamp so
        // recovery can rebuild the Active/Recent Transaction Table.
        let mut r = LogRecord::commit(TxnId(9), Lsn(40), Timestamp(0x1234_5678));
        assert_eq!(r.rec_type, RecordType::Commit);
        assert_eq!(r.commit_ts(), Some(Timestamp(0x1234_5678)));
        let mut buf = Vec::new();
        r.encode_to(Lsn(64), &mut buf);
        let (got, _) = LogRecord::decode(&buf).unwrap();
        assert_eq!(got.rec_type, RecordType::Commit);
        assert_eq!(got.commit_ts(), Some(Timestamp(0x1234_5678)));
        assert_eq!(got.prev_lsn, Lsn(40));
        // A commit record is never a page change, so its `redo` is never replayed as a page image.
        assert!(!got.rec_type.is_page_change());
    }

    #[test]
    fn commit_ts_is_none_for_a_non_commit_record_and_zero_for_an_empty_redo() {
        let upd = LogRecord::new(RecordType::Update, TxnId(1), PageId(3));
        assert_eq!(upd.commit_ts(), None);
        // A commit record with no embedded timestamp (legacy / torn) reads as the 0 sentinel.
        let bare = LogRecord::new(RecordType::Commit, TxnId(1), PageId(0));
        assert_eq!(bare.commit_ts(), Some(Timestamp(0)));
    }

    use graphus_core::Timestamp;

    #[test]
    fn record_type_byte_round_trips() {
        for t in [
            RecordType::Begin,
            RecordType::Update,
            RecordType::Commit,
            RecordType::Abort,
            RecordType::Clr,
            RecordType::CheckpointBegin,
            RecordType::CheckpointEnd,
            RecordType::Free,
            RecordType::CountDelta,
        ] {
            assert_eq!(RecordType::from_u8(t as u8), Some(t));
        }
        assert_eq!(RecordType::from_u8(0), None);
        assert_eq!(RecordType::from_u8(250), None);
    }

    /// **A count-delta record round-trips, and its payload is never treated as a page image**
    /// (`rmp` #1066).
    ///
    /// The second half is the load-bearing one. The payload rides in `redo`, the same field a page
    /// change puts its after-image in, and recovery's redo pass writes `redo` straight onto
    /// `page_id` for anything [`RecordType::is_page_change`] admits. This record carries `PageId(0)`
    /// — the metadata page — so if the classification were ever widened to include it, recovery
    /// would stamp counter bytes over the catalogue.
    #[test]
    fn count_delta_record_round_trips_and_is_not_a_page_change() {
        let payload = vec![0xA5u8, 0x00, 0xFF, 0x01];
        let mut r = LogRecord::count_delta(TxnId(11), Lsn(24), payload.clone());
        assert_eq!(r.count_delta_payload(), Some(&payload[..]));
        let mut buf = Vec::new();
        r.encode_to(Lsn(96), &mut buf);
        let (got, consumed) = LogRecord::decode(&buf).expect("decode");
        assert_eq!(consumed, buf.len());
        assert_eq!(got, r);
        assert_eq!(got.count_delta_payload(), Some(&payload[..]));
        assert_eq!(got.prev_lsn, Lsn(24));
        assert_eq!(got.page_id, PageId(0));
        assert!(
            !got.rec_type.is_page_change(),
            "a count-delta payload must never be replayed as a page image: the record names \
             PageId(0), the metadata page"
        );
        assert!(
            !got.rec_type.is_undoable_action(),
            "a loser's count delta is never applied, so there is nothing to compensate; the undo \
             pass must walk past it along prev_lsn"
        );
        // The borrowed decoder — the one every recovery scan uses — reads the same payload.
        let (as_ref, _) = LogRecordRef::decode(&buf).expect("decode borrowed");
        assert_eq!(as_ref.count_delta_payload(), Some(&payload[..]));
    }

    /// **`count_delta_payload` distinguishes "not a count-delta record" from "an empty payload".**
    ///
    /// A `None` return is the caller's licence to ignore the record entirely; an empty `Some` is a
    /// record it must decide about. Collapsing the two would let a malformed (zero-length) payload
    /// be silently skipped instead of reported.
    #[test]
    fn count_delta_payload_is_none_only_for_a_different_record_kind() {
        let upd = LogRecord::new(RecordType::Update, TxnId(1), PageId(3));
        assert_eq!(upd.count_delta_payload(), None);
        let commit = LogRecord::commit(TxnId(1), Lsn(0), Timestamp(5));
        assert_eq!(commit.count_delta_payload(), None);
        let empty = LogRecord::count_delta(TxnId(1), Lsn(0), Vec::new());
        assert_eq!(empty.count_delta_payload(), Some(&[][..]));
        assert_eq!(empty.commit_ts(), None);
    }
}
