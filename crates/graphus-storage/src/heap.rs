//! The `strings.store` **block-chained overflow heap** for variable-length property values
//! (`04-technical-design.md` §2.1, §2.3; `05-storage-format.md` §9; `rmp` task #43).
//!
//! `04 §2.1` lists `strings.store` as the *"variable-length large-string / large-list heap,
//! block-chained"*, and `04 §2.3` says a property record's `value_inline` holds *"the value if it
//! fits ... else `strings.store` block id"* (with the `type_tag`'s inline-vs-overflow bit set). This
//! module is that heap: it stores an arbitrary byte payload as a **chain of fixed-size blocks**, each
//! block carrying a chunk of the payload plus a pointer to the next block, and gives back the
//! physical id of the chain's **head block** — the id a [`PropRecord`](crate::record::PropRecord)
//! stores in `value_inline`.
//!
//! # Why a fixed-size-record store (the block layout decision, `rmp` task #43)
//!
//! `05 §9` froze the three fixed-record stores (`nodes`/`rels`/`props`) as arrays of fixed-size
//! records inside logical pages, addressed by a pure-arithmetic physical id, with a per-store
//! WAL-logged free list (`04 §2.7`) and crash recovery by the same three-phase ARIES machinery. The
//! overflow heap is built as a **fourth such store** ([`StoreKind::Strings`](crate::store::StoreKind))
//! so it inherits *all* of that discipline unchanged: page allocation, the intra-page redo/undo
//! patch path ([`crate::paging`]), the free list, and recovery. A heap *block* is therefore just a
//! fixed-size record:
//!
//! | Field | Bytes | Meaning |
//! | --- | --- | --- |
//! | MVCC header | 25 | the frozen `05 §7` prefix; `in_use` marks an allocated block (so the consistency scan and free list treat heap blocks exactly like any other record) |
//! | `next_block` | 8 | physical id of the next block in this chain (`0` = last block) |
//! | `len` | 2 | number of payload bytes used **in this block** (`0..=`[`BLOCK_PAYLOAD`]) |
//! | payload | [`BLOCK_PAYLOAD`] | this block's chunk of the value's bytes |
//!
//! The block payload is deliberately **small** ([`BLOCK_PAYLOAD`] = `48` bytes) so that even modest
//! strings/lists exercise the multi-block chain path; a production tuning pass (`04 §12`, gated on
//! the LDBC working set) can widen it without any format-compatibility concern, because the heap is
//! addressed only by internal physical ids that are never exposed (`04 §2.2`).
//!
//! # The three operations
//!
//! * [`alloc_chain`](super::RecordStore::alloc_chain) — splits a byte payload into
//!   [`BLOCK_PAYLOAD`]-sized chunks, allocates one block per chunk (reusing freed block ids first,
//!   `04 §2.7`), links them tail-to-head, and returns the **head** block id. An **empty** payload
//!   still allocates exactly one (empty) block, so a head id is always a valid, non-null pointer.
//! * [`read_chain`](super::RecordStore::read_chain) — walks the chain from the head, concatenating
//!   each block's `len` payload bytes, and returns the reassembled `Vec<u8>`. A cycle guard (derived
//!   from the store high-water mark) makes a corrupted chain *terminate with an error* rather than
//!   loop forever (mirrors the property/adjacency chain guards in [`crate::store`]).
//! * [`free_chain`](super::RecordStore::free_chain) — walks the chain, clears each block's `in_use`
//!   bit (a WAL-logged write) and pushes its id onto the store free list, so a freed chain's blocks
//!   are reused by the next allocation (no leak — the regression the overwrite/removal tests assert).
//!
//! All three are methods on [`RecordStore`](super::RecordStore) (they need the buffer pool, WAL and
//! catalog); this module owns only the **block codec** ([`HeapBlock`]) and the layout constants, kept
//! here and unit-tested in isolation exactly like [`crate::record`].

use crate::record::{MVCC_HEADER_SIZE, MvccHeader};

/// Bytes of payload carried by one heap block (the block record minus its header overhead).
///
/// Small by design (see the module docs): even short multi-byte values span several blocks, so the
/// chain machinery is exercised end-to-end. Widening this is a pure tuning change (`04 §12`).
pub const BLOCK_PAYLOAD: usize = 48;

/// Byte offset of `next_block` within a heap block (immediately after the MVCC header).
const OFF_NEXT_BLOCK: usize = MVCC_HEADER_SIZE; // u64
/// Byte offset of `len` (the count of payload bytes used in this block).
const OFF_LEN: usize = MVCC_HEADER_SIZE + 8; // u16
/// Byte offset of the block's payload region.
const OFF_PAYLOAD: usize = MVCC_HEADER_SIZE + 8 + 2; // [u8; BLOCK_PAYLOAD]

/// Size of one heap block record in bytes: MVCC header + `next_block` + `len` + payload
/// (`rmp` task #43; see the module-level table).
pub const STRINGS_RECORD_SIZE: usize = OFF_PAYLOAD + BLOCK_PAYLOAD;

/// One block of the [`strings.store`](self) overflow chain (`rmp` task #43).
///
/// A block holds up to [`BLOCK_PAYLOAD`] payload bytes (`len` of them used) and the physical id of
/// the next block (`0` = last). It shares the frozen 25-byte MVCC header (`05 §7`) with every other
/// record so the consistency checker and free list treat it uniformly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeapBlock {
    /// The frozen MVCC prefix; `in_use` marks an allocated block.
    pub mvcc: MvccHeader,
    /// Physical id of the next block in this chain (`0` = last block).
    pub next_block: u64,
    /// Number of payload bytes used in this block (`0..=`[`BLOCK_PAYLOAD`]).
    pub len: u16,
    /// This block's chunk of the value's bytes (only the first `len` are meaningful).
    pub payload: [u8; BLOCK_PAYLOAD],
}

impl HeapBlock {
    /// A fresh, live, in-use block carrying `chunk` (which must be at most [`BLOCK_PAYLOAD`] bytes)
    /// and pointing at `next_block`.
    ///
    /// # Panics
    /// Panics if `chunk` is longer than [`BLOCK_PAYLOAD`] (an internal invariant of the chunker).
    #[must_use]
    pub fn new(created_ts: u64, chunk: &[u8], next_block: u64) -> Self {
        assert!(
            chunk.len() <= BLOCK_PAYLOAD,
            "heap chunk {} exceeds block payload {BLOCK_PAYLOAD}",
            chunk.len()
        );
        let mut payload = [0u8; BLOCK_PAYLOAD];
        payload[..chunk.len()].copy_from_slice(chunk);
        Self {
            mvcc: MvccHeader::live(created_ts),
            // A chunk is at most BLOCK_PAYLOAD (<= u16::MAX), so this cast is lossless.
            len: chunk.len() as u16,
            next_block,
            payload,
        }
    }

    /// The meaningful payload bytes of this block (`payload[..len]`).
    ///
    /// A `len` greater than [`BLOCK_PAYLOAD`] can only arise from a corrupt record; it is clamped so
    /// a reader can never index past the fixed payload array (the consistency checker reports the
    /// corruption separately).
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        let n = (self.len as usize).min(BLOCK_PAYLOAD);
        &self.payload[..n]
    }

    /// Decodes a heap block from a [`STRINGS_RECORD_SIZE`]-byte slice.
    ///
    /// # Panics
    /// Panics if `buf` is shorter than [`STRINGS_RECORD_SIZE`].
    #[must_use]
    pub fn decode(buf: &[u8]) -> Self {
        assert!(
            buf.len() >= STRINGS_RECORD_SIZE,
            "heap block slice too short"
        );
        let mut payload = [0u8; BLOCK_PAYLOAD];
        payload.copy_from_slice(&buf[OFF_PAYLOAD..OFF_PAYLOAD + BLOCK_PAYLOAD]);
        Self {
            mvcc: MvccHeader::read(buf),
            next_block: u64::from_le_bytes(
                buf[OFF_NEXT_BLOCK..OFF_NEXT_BLOCK + 8]
                    .try_into()
                    .expect("8-byte slice"),
            ),
            len: u16::from_le_bytes(buf[OFF_LEN..OFF_LEN + 2].try_into().expect("2-byte slice")),
            payload,
        }
    }

    /// Encodes this heap block into a [`STRINGS_RECORD_SIZE`]-byte slice.
    ///
    /// # Panics
    /// Panics if `buf` is shorter than [`STRINGS_RECORD_SIZE`].
    pub fn encode(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= STRINGS_RECORD_SIZE,
            "heap block slice too short"
        );
        self.mvcc.write(buf);
        buf[OFF_NEXT_BLOCK..OFF_NEXT_BLOCK + 8].copy_from_slice(&self.next_block.to_le_bytes());
        buf[OFF_LEN..OFF_LEN + 2].copy_from_slice(&self.len.to_le_bytes());
        buf[OFF_PAYLOAD..OFF_PAYLOAD + BLOCK_PAYLOAD].copy_from_slice(&self.payload);
    }
}

/// The number of [`BLOCK_PAYLOAD`]-sized blocks a payload of `byte_len` bytes occupies — at least
/// one even for an empty payload (so a chain head id is always a valid, non-null pointer,
/// `04 §2.2`).
#[must_use]
pub fn blocks_needed(byte_len: usize) -> usize {
    if byte_len == 0 {
        1
    } else {
        byte_len.div_ceil(BLOCK_PAYLOAD)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::FLAG_IN_USE;

    #[test]
    fn record_size_matches_the_layout() {
        // 25 (MVCC) + 8 (next_block) + 2 (len) + BLOCK_PAYLOAD.
        assert_eq!(STRINGS_RECORD_SIZE, 25 + 8 + 2 + BLOCK_PAYLOAD);
        assert_eq!(STRINGS_RECORD_SIZE, 83);
    }

    #[test]
    fn block_round_trips_every_field() {
        let chunk: Vec<u8> = (0..BLOCK_PAYLOAD as u8).collect();
        let b = HeapBlock::new(7, &chunk, 42);
        let mut buf = [0u8; STRINGS_RECORD_SIZE];
        b.encode(&mut buf);
        let got = HeapBlock::decode(&buf);
        assert_eq!(got, b);
        assert_eq!(got.next_block, 42);
        assert_eq!(got.len as usize, BLOCK_PAYLOAD);
        assert_eq!(got.bytes(), chunk.as_slice());
        assert!(got.mvcc.in_use());
        assert_eq!(got.mvcc.flags, FLAG_IN_USE);
    }

    #[test]
    fn empty_chunk_block_is_in_use_with_zero_len() {
        let b = HeapBlock::new(1, &[], 0);
        assert_eq!(b.len, 0);
        assert_eq!(b.next_block, 0);
        assert!(b.bytes().is_empty());
        assert!(b.mvcc.in_use());
    }

    #[test]
    fn bytes_clamps_a_corrupt_overlong_len() {
        // A corrupt record could carry len > BLOCK_PAYLOAD; bytes() must never index past payload.
        let mut b = HeapBlock::new(1, &[1, 2, 3], 0);
        b.len = u16::MAX;
        assert_eq!(b.bytes().len(), BLOCK_PAYLOAD);
    }

    #[test]
    #[should_panic(expected = "exceeds block payload")]
    fn new_rejects_an_overlong_chunk() {
        let too_big = vec![0u8; BLOCK_PAYLOAD + 1];
        let _ = HeapBlock::new(1, &too_big, 0);
    }

    #[test]
    fn blocks_needed_rounds_up_and_is_at_least_one() {
        assert_eq!(blocks_needed(0), 1);
        assert_eq!(blocks_needed(1), 1);
        assert_eq!(blocks_needed(BLOCK_PAYLOAD), 1);
        assert_eq!(blocks_needed(BLOCK_PAYLOAD + 1), 2);
        assert_eq!(blocks_needed(BLOCK_PAYLOAD * 3), 3);
        assert_eq!(blocks_needed(BLOCK_PAYLOAD * 3 + 1), 4);
    }
}
