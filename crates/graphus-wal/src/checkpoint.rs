//! Fuzzy-checkpoint snapshot (`specification/04-technical-design.md` §4.7).
//!
//! A fuzzy checkpoint does not quiesce the system. The [`CheckpointEnd`](crate::RecordType)
//! record embeds this snapshot: the **Dirty Page Table** (`page_id → recovery_lsn`, the oldest
//! LSN that must be redone to reconstruct the page) and the **Active Transaction Table**
//! (`txn_id → last_lsn`). Recovery seeds analysis from it and starts redo at the smallest
//! `recovery_lsn`, instead of from the start of the log.

use graphus_core::{Lsn, PageId, TxnId};

/// The DPT + ATT captured by a fuzzy checkpoint, serialised into the `CheckpointEnd` record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckpointSnapshot {
    /// Dirty Page Table: each dirty page and the oldest LSN needed to redo it.
    pub dirty_pages: Vec<(PageId, Lsn)>,
    /// Active Transaction Table: each in-flight transaction and its last LSN.
    pub active_txns: Vec<(TxnId, Lsn)>,
}

impl CheckpointSnapshot {
    /// Serialises the snapshot to bytes (little-endian, length-prefixed arrays).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(8 + self.dirty_pages.len() * 16 + self.active_txns.len() * 16);
        out.extend_from_slice(&(self.dirty_pages.len() as u32).to_le_bytes());
        for (p, l) in &self.dirty_pages {
            out.extend_from_slice(&p.0.to_le_bytes());
            out.extend_from_slice(&l.0.to_le_bytes());
        }
        out.extend_from_slice(&(self.active_txns.len() as u32).to_le_bytes());
        for (t, l) in &self.active_txns {
            out.extend_from_slice(&t.0.to_le_bytes());
            out.extend_from_slice(&l.0.to_le_bytes());
        }
        out
    }

    /// Parses a snapshot from `bytes`, returning `None` on a malformed payload.
    ///
    /// The per-array length prefixes are **attacker-controllable** when a checkpoint record is read
    /// from an untrusted source (a backup-chain `CheckpointEnd` whose CRC32C an attacker can recompute
    /// — the CRC is unkeyed). So the pre-allocation is clamped to what the remaining bytes can
    /// actually hold (each entry is two `u64`s = 16 bytes); a crafted `n = u32::MAX` therefore cannot
    /// drive a ~68 GB allocation (storage audit F5). The loops still run `n` times, but `take_u64`
    /// returns `None` as soon as the bytes are exhausted, so a lie about the count fails cleanly.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        /// Bytes per array entry (`PageId`/`TxnId` + `Lsn`, both `u64`).
        const ENTRY_LEN: usize = 16;
        let mut cur = 0usize;
        let n_dpt = take_u32(bytes, &mut cur)? as usize;
        let mut dirty_pages =
            Vec::with_capacity(n_dpt.min(bytes.len().saturating_sub(cur) / ENTRY_LEN));
        for _ in 0..n_dpt {
            let p = take_u64(bytes, &mut cur)?;
            let l = take_u64(bytes, &mut cur)?;
            dirty_pages.push((PageId(p), Lsn(l)));
        }
        let n_att = take_u32(bytes, &mut cur)? as usize;
        let mut active_txns =
            Vec::with_capacity(n_att.min(bytes.len().saturating_sub(cur) / ENTRY_LEN));
        for _ in 0..n_att {
            let t = take_u64(bytes, &mut cur)?;
            let l = take_u64(bytes, &mut cur)?;
            active_txns.push((TxnId(t), Lsn(l)));
        }
        Some(Self {
            dirty_pages,
            active_txns,
        })
    }

    /// The LSN redo must start from: the smallest `recovery_lsn` in the DPT, or `None` if the
    /// checkpoint saw no dirty pages.
    #[must_use]
    pub fn redo_start(&self) -> Option<Lsn> {
        self.dirty_pages.iter().map(|(_, l)| *l).min()
    }
}

fn take_u32(b: &[u8], cur: &mut usize) -> Option<u32> {
    let end = cur.checked_add(4)?;
    let v = u32::from_le_bytes(b.get(*cur..end)?.try_into().ok()?);
    *cur = end;
    Some(v)
}

fn take_u64(b: &[u8], cur: &mut usize) -> Option<u64> {
    let end = cur.checked_add(8)?;
    let v = u64::from_le_bytes(b.get(*cur..end)?.try_into().ok()?);
    *cur = end;
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_round_trips() {
        let s = CheckpointSnapshot {
            dirty_pages: vec![(PageId(3), Lsn(80)), (PageId(7), Lsn(40))],
            active_txns: vec![(TxnId(9), Lsn(120))],
        };
        let bytes = s.encode();
        assert_eq!(CheckpointSnapshot::decode(&bytes), Some(s.clone()));
        assert_eq!(s.redo_start(), Some(Lsn(40)));
    }

    #[test]
    fn empty_snapshot_has_no_redo_start() {
        let s = CheckpointSnapshot::default();
        assert_eq!(CheckpointSnapshot::decode(&s.encode()), Some(s.clone()));
        assert_eq!(s.redo_start(), None);
    }

    #[test]
    fn truncated_payload_decodes_to_none() {
        let s = CheckpointSnapshot {
            dirty_pages: vec![(PageId(1), Lsn(8))],
            active_txns: vec![],
        };
        let mut bytes = s.encode();
        bytes.truncate(bytes.len() - 1);
        assert_eq!(CheckpointSnapshot::decode(&bytes), None);
    }

    #[test]
    fn a_huge_array_count_does_not_over_allocate() {
        // A crafted payload (reachable from an untrusted backup-chain CheckpointEnd) claiming
        // u32::MAX entries but carrying only a few bytes must decode to None WITHOUT pre-allocating
        // ~68 GB (storage audit F5). Were the capacity clamp removed, this test would OOM/abort
        // rather than fail.
        let mut dpt = Vec::new();
        dpt.extend_from_slice(&u32::MAX.to_le_bytes()); // n_dpt = 4.29e9
        dpt.extend_from_slice(&[0u8; 8]); // not even one full 16-byte entry follows
        assert_eq!(CheckpointSnapshot::decode(&dpt), None);

        let mut att = Vec::new();
        att.extend_from_slice(&0u32.to_le_bytes()); // n_dpt = 0 (valid, empty)
        att.extend_from_slice(&u32::MAX.to_le_bytes()); // n_att = 4.29e9 with no entries
        assert_eq!(CheckpointSnapshot::decode(&att), None);
    }
}
