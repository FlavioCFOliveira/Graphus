//! Record-to-page arithmetic and the intra-page patch encoding (`05-storage-format.md` §6,
//! `04-technical-design.md` §2.1, §3.2).
//!
//! A fixed-record store lays its records out as a dense array in each page's payload — the bytes
//! after the 24-byte page header frozen in `05 §6`. Record `i` (a *physical id*) lives at
//!
//! ```text
//! page  = i / records_per_page
//! slot  = i % records_per_page
//! offset = HEADER_SIZE + slot * RECORD_SIZE
//! records_per_page = (PAGE_SIZE - HEADER_SIZE) / RECORD_SIZE
//! ```
//!
//! so addressing a record is pure arithmetic — the constant-time pointer chase index-free
//! adjacency relies on (`04 §2.1`).
//!
//! ## Intra-page patch encoding
//!
//! WAL redo and undo images are byte patches *within a single page*: a `(u16 offset, bytes)`
//! pair. [`encode_patch`] / [`apply_patch`] are the inverse of each other; the redo image is the
//! post-image of a region, the undo image its pre-image, so applying redo rolls the change
//! forward and applying undo (or a CLR carrying the undo) rolls it back (`04 §4.1`).
//!
//! ## Compare-and-set (logical undo) patch
//!
//! A *plain* pre-image undo is physical: it restores the captured bytes unconditionally. That is
//! correct only when the undone field is not concurrently shared-mutated. A graph **chain-head
//! pointer** (`first_rel` / `first_prop`) is the exception: under interleaved writers each pushes a
//! record onto the head, so a captured pre-image of the head can go *stale* (a later committed
//! writer pushes on top), and restoring it verbatim during rollback/recovery would clobber that
//! committed writer's head — destroying committed structure (`rmp` #220 / #172).
//!
//! The correct compensating undo of "push record R onto the head (head := R)" is the **logical**
//! "unlink R from the head": *if the head is still R, set it back to R's old successor; otherwise R
//! is no longer the head — a later writer already recorded R as its own old head and owns the
//! relink, so do nothing*. [`encode_cas_patch`] encodes exactly this conditional, and [`apply_patch`]
//! interprets it. Because it is expressed as a self-describing image, the **same verbatim
//! [`apply_patch`] replay path** that serves live rollback ([`crate::store`] `PoolTarget`) and crash
//! recovery ([`crate::recovery`] `DeviceTarget`) realizes the logical undo identically — no new WAL
//! record type is needed (`04 §4.1`, logical-per-record undo).
//!
//! The CAS image is distinguished from a plain patch by a leading sentinel offset
//! [`CAS_SENTINEL`] (`0xFFFF`), which can never be a real page offset (`PAGE_SIZE == 8192`), so the
//! two encodings are unambiguous and a plain patch's bytes are unchanged on the wire.

use graphus_bufpool::page::HEADER_SIZE;
use graphus_io::PAGE_SIZE;
use smallvec::SmallVec;

/// The in-flight encoding of a WAL redo/undo intra-page patch (`rmp` #373).
///
/// A patch is always tiny: a 2-byte offset prefix plus either a single fixed record body (the
/// largest is [`crate::record::REL_RECORD_SIZE`] = 102 bytes, so 104 bytes on the wire) or one
/// narrow field (an 8-byte MVCC/chain word, a 25-byte MVCC header, or a 20-byte compare-and-set
/// image). The 128-byte inline capacity therefore holds **every** patch this store emits without
/// touching the heap, so [`encode_patch`] / [`encode_cas_patch`] no longer allocate a fresh `Vec`
/// per redo/undo image on the OLTP write path. The encoded bytes are byte-for-byte identical to the
/// previous `Vec` encoding — `SmallVec` derefs to `&[u8]`, so the WAL frame format is unchanged.
pub type Patch = SmallVec<[u8; 128]>;

/// Bytes available for the record array in each page (after the frozen 24-byte header).
pub const PAGE_PAYLOAD: usize = PAGE_SIZE - HEADER_SIZE;

/// The number of fixed-size records of `record_size` bytes that fit in one page's payload.
///
/// # Panics
/// Panics if `record_size` is zero or larger than the page payload.
#[must_use]
pub const fn records_per_page(record_size: usize) -> usize {
    assert!(record_size > 0, "record size must be non-zero");
    assert!(record_size <= PAGE_PAYLOAD, "record larger than a page");
    PAGE_PAYLOAD / record_size
}

/// The `(page index, byte offset within page)` of record `id` in a store of `record_size`-byte
/// records.
///
/// Page index is the *store-relative* page number; the caller maps it to a device
/// [`PageId`](graphus_core::PageId) by adding the store's base page (see [`crate::store`]).
#[must_use]
pub fn record_location(id: u64, record_size: usize) -> (u64, usize) {
    let rpp = records_per_page(record_size) as u64;
    let page = id / rpp;
    let slot = (id % rpp) as usize;
    (page, HEADER_SIZE + slot * record_size)
}

/// The total number of record slots addressable across `page_count` pages.
#[must_use]
pub fn capacity(page_count: u64, record_size: usize) -> u64 {
    page_count * records_per_page(record_size) as u64
}

/// Encodes an intra-page patch: a 2-byte little-endian `offset` followed by `bytes`.
///
/// Used as both a redo image (post-image of `bytes` at `offset`) and an undo image (pre-image),
/// per the physiological-redo / logical-undo split (`04 §4.1`).
///
/// # Panics
/// Panics if `offset + bytes.len()` would run past [`PAGE_SIZE`].
#[must_use]
pub fn encode_patch(offset: usize, bytes: &[u8]) -> Patch {
    assert!(
        offset + bytes.len() <= PAGE_SIZE,
        "patch runs past the page"
    );
    // `SmallVec::with_capacity(n)` for `n <= 128` stays inline (no heap allocation); the bytes
    // written are identical to the previous `Vec` path, so the WAL image is byte-for-byte unchanged.
    let mut out = Patch::with_capacity(2 + bytes.len());
    out.extend_from_slice(&(offset as u16).to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

/// Sentinel offset (a value [`encode_patch`] can never emit, since it exceeds [`PAGE_SIZE`]) that
/// marks a [`encode_cas_patch`] compare-and-set image instead of a plain region patch.
pub const CAS_SENTINEL: u16 = 0xFFFF;

/// Encodes a **compare-and-set** undo image for an 8-byte chain-head field at `offset`: on apply,
/// `if page[offset..offset+8] == expect { page[offset..offset+8] = new }` — otherwise a no-op.
///
/// This is the logical undo of "push a record onto the head": `expect` is the head value this
/// writer installed (its own pushed id) and `new` is the head it found before pushing (the old
/// head). Replaying it unlinks the writer's record from the head **only if it is still the head**,
/// so a later writer's committed head is never clobbered (see module docs, `04 §4.1`).
///
/// # Panics
/// Panics if `offset + 8` would run past [`PAGE_SIZE`], or if `offset` is not addressable as a
/// non-sentinel `u16`.
#[must_use]
pub fn encode_cas_patch(offset: usize, expect: u64, new: u64) -> Patch {
    assert!(offset + 8 <= PAGE_SIZE, "cas patch runs past the page");
    assert!(
        offset <= u16::MAX as usize && offset as u16 != CAS_SENTINEL,
        "cas patch offset is not addressable"
    );
    let mut out = Patch::with_capacity(2 + 2 + 8 + 8);
    out.extend_from_slice(&CAS_SENTINEL.to_le_bytes());
    out.extend_from_slice(&(offset as u16).to_le_bytes());
    out.extend_from_slice(&expect.to_le_bytes());
    out.extend_from_slice(&new.to_le_bytes());
    out
}

/// Applies a patch produced by [`encode_patch`] (a plain region overwrite) or [`encode_cas_patch`]
/// (a conditional 8-byte compare-and-set, used for chain-head logical undo) to `page`.
///
/// # Errors
/// Returns a storage error if the patch is malformed or would write past the page.
pub fn apply_patch(page: &mut [u8], patch: &[u8]) -> graphus_core::Result<()> {
    use graphus_core::GraphusError;
    if patch.len() < 2 {
        return Err(GraphusError::Storage("patch too short".to_owned()));
    }
    let lead = u16::from_le_bytes(patch[0..2].try_into().expect("2-byte slice"));
    if lead == CAS_SENTINEL {
        // Compare-and-set image: [CAS_SENTINEL:u16][offset:u16][expect:u64][new:u64].
        if patch.len() != 2 + 2 + 8 + 8 {
            return Err(GraphusError::Storage("malformed cas patch".to_owned()));
        }
        let offset = u16::from_le_bytes(patch[2..4].try_into().expect("2-byte slice")) as usize;
        let expect = u64::from_le_bytes(patch[4..12].try_into().expect("8-byte slice"));
        let new = u64::from_le_bytes(patch[12..20].try_into().expect("8-byte slice"));
        let end = offset
            .checked_add(8)
            .ok_or_else(|| GraphusError::Storage("cas patch runs past the page".to_owned()))?;
        if end > page.len() {
            return Err(GraphusError::Storage(
                "cas patch runs past the page".to_owned(),
            ));
        }
        let current = u64::from_le_bytes(page[offset..end].try_into().expect("8-byte slice"));
        if current == expect {
            page[offset..end].copy_from_slice(&new.to_le_bytes());
        }
        // else: this record is no longer the head; the writer above it owns the relink (no-op).
        return Ok(());
    }
    let offset = lead as usize;
    let bytes = &patch[2..];
    let end = offset
        .checked_add(bytes.len())
        .ok_or_else(|| GraphusError::Storage("patch offset overflow".to_owned()))?;
    if end > page.len() {
        return Err(GraphusError::Storage("patch runs past the page".to_owned()));
    }
    page[offset..end].copy_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{NODE_RECORD_SIZE, PROP_RECORD_SIZE, REL_RECORD_SIZE};

    #[test]
    fn payload_is_page_minus_header() {
        assert_eq!(PAGE_PAYLOAD, PAGE_SIZE - 24);
        assert_eq!(PAGE_PAYLOAD, 8168);
    }

    #[test]
    fn records_per_page_matches_frozen_sizes() {
        // (8192 - 24) / size, floored.
        assert_eq!(records_per_page(NODE_RECORD_SIZE), 8168 / 65); // 125
        assert_eq!(records_per_page(REL_RECORD_SIZE), 8168 / 102); // 80
        assert_eq!(records_per_page(PROP_RECORD_SIZE), 8168 / 46); // 177
    }

    #[test]
    fn record_zero_sits_right_after_the_header() {
        let (page, off) = record_location(0, NODE_RECORD_SIZE);
        assert_eq!((page, off), (0, 24));
    }

    #[test]
    fn last_slot_of_a_page_then_first_of_the_next() {
        let rpp = records_per_page(NODE_RECORD_SIZE) as u64;
        let (p_last, off_last) = record_location(rpp - 1, NODE_RECORD_SIZE);
        assert_eq!(p_last, 0);
        assert_eq!(off_last, 24 + (rpp as usize - 1) * NODE_RECORD_SIZE);
        let (p_next, off_next) = record_location(rpp, NODE_RECORD_SIZE);
        assert_eq!((p_next, off_next), (1, 24));
    }

    #[test]
    fn patch_round_trips_into_a_page() {
        let mut page = [0u8; PAGE_SIZE];
        let patch = encode_patch(100, &[1, 2, 3, 4]);
        apply_patch(&mut page, &patch).unwrap();
        assert_eq!(&page[100..104], &[1, 2, 3, 4]);
    }

    #[test]
    fn patch_rejects_out_of_range_and_short_input() {
        let mut page = [0u8; PAGE_SIZE];
        assert!(apply_patch(&mut page, &[0]).is_err()); // too short (< 2 bytes)
        // Hand-craft a patch whose offset + len runs past the page (encode_patch would itself
        // panic on this, so build the bytes directly to exercise apply_patch's own guard).
        let mut bad = ((PAGE_SIZE - 2) as u16).to_le_bytes().to_vec();
        bad.extend_from_slice(&[9, 9, 9, 9]);
        assert!(apply_patch(&mut page, &bad).is_err());
    }

    // ----------------------- compare-and-set (logical undo) patch -----------------------

    /// Writes the 8-byte little-endian `v` at `off` into a fresh page and returns it — a tiny helper
    /// to set up a chain-head field for the CAS tests.
    fn page_with_head(off: usize, v: u64) -> [u8; PAGE_SIZE] {
        let mut page = [0u8; PAGE_SIZE];
        page[off..off + 8].copy_from_slice(&v.to_le_bytes());
        page
    }

    fn read_head(page: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(page[off..off + 8].try_into().unwrap())
    }

    #[test]
    fn cas_equal_case_resets_the_head_to_old() {
        // The head still equals what this writer installed (`expect`), so the logical undo unlinks it:
        // the field is reset to `new` (the old head this writer found before pushing).
        let off = 200usize;
        let mut page = page_with_head(off, 77); // head == 77 == expect
        let patch = encode_cas_patch(off, /*expect*/ 77, /*new*/ 42);
        apply_patch(&mut page, &patch).unwrap();
        assert_eq!(
            read_head(&page, off),
            42,
            "equal case resets to the old head"
        );
    }

    #[test]
    fn cas_unequal_case_is_a_no_op() {
        // A later committed writer pushed on top, so the head moved off `expect` (77 -> 99). The undo
        // must NOT clobber that committed head: it is a no-op, leaving 99 in place.
        let off = 200usize;
        let mut page = page_with_head(off, 99); // head == 99 != expect (77)
        let patch = encode_cas_patch(off, /*expect*/ 77, /*new*/ 42);
        apply_patch(&mut page, &patch).unwrap();
        assert_eq!(
            read_head(&page, off),
            99,
            "unequal case leaves the moved-on committed head untouched"
        );
    }

    #[test]
    fn cas_rejects_malformed_length() {
        let mut page = [0u8; PAGE_SIZE];
        // A CAS image must be exactly 2 (sentinel) + 2 (offset) + 8 (expect) + 8 (new) = 20 bytes.
        let mut short = CAS_SENTINEL.to_le_bytes().to_vec();
        short.extend_from_slice(&[0u8; 2 + 8 + 7]); // one byte short of 20
        assert!(
            apply_patch(&mut page, &short).is_err(),
            "a 19-byte CAS image is rejected"
        );
        let mut long = CAS_SENTINEL.to_le_bytes().to_vec();
        long.extend_from_slice(&[0u8; 2 + 8 + 9]); // one byte over 20
        assert!(
            apply_patch(&mut page, &long).is_err(),
            "a 21-byte CAS image is rejected"
        );
    }

    #[test]
    fn cas_runs_past_page_is_rejected() {
        let mut page = [0u8; PAGE_SIZE];
        // Hand-craft a CAS image whose offset + 8 runs past the page (encode_cas_patch would panic on
        // this, so build the bytes directly to exercise apply_patch's own bound guard).
        let mut bad = CAS_SENTINEL.to_le_bytes().to_vec();
        bad.extend_from_slice(&((PAGE_SIZE - 4) as u16).to_le_bytes()); // offset, +8 overruns
        bad.extend_from_slice(&7u64.to_le_bytes()); // expect
        bad.extend_from_slice(&9u64.to_le_bytes()); // new
        assert!(apply_patch(&mut page, &bad).is_err());
    }

    #[test]
    fn sentinel_is_unambiguous_against_a_real_offset_patch() {
        // A plain region patch at offset 0 begins with the bytes `00 00`, which is NOT the sentinel
        // `FF FF`, so it is interpreted as a region overwrite — never as a (truncated) CAS image. This
        // pins the wire-level disambiguation the chain-head logical undo relies on.
        let mut page = [0u8; PAGE_SIZE];
        let region = encode_patch(0, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_ne!(
            u16::from_le_bytes(region[0..2].try_into().unwrap()),
            CAS_SENTINEL,
            "a real offset-0 patch does not collide with the sentinel"
        );
        apply_patch(&mut page, &region).unwrap();
        assert_eq!(&page[0..8], &[1, 2, 3, 4, 5, 6, 7, 8]);

        // And a CAS image always leads with the sentinel, so apply_patch dispatches it as a CAS.
        let cas = encode_cas_patch(8, 0, 5);
        assert_eq!(
            u16::from_le_bytes(cas[0..2].try_into().unwrap()),
            CAS_SENTINEL,
            "a CAS image leads with the sentinel"
        );
    }

    #[test]
    fn cas_disambiguates_sentinel_valued_chain_heads() {
        // The CAS payload carries `expect`/`new` as full u64 words, so a chain-head field whose VALUE
        // happens to be 0xFFFF (or NULL_ID == 0, or u64::MAX) is matched/written correctly — the
        // sentinel only ever lives in the leading offset slot, never confused with a head value.
        let off = 64usize;
        for &(expect, new) in &[
            (0xFFFFu64, 0u64),     // head value == 0xFFFF (the sentinel as a number)
            (0u64, 0xFFFFu64),     // NULL_ID head reset to a 0xFFFF-valued old head
            (u64::MAX, 123u64),    // all-ones head value
            (0xFFFFu64, u64::MAX), // 0xFFFF head reset to all-ones
        ] {
            let mut page = page_with_head(off, expect); // head still == expect
            let patch = encode_cas_patch(off, expect, new);
            apply_patch(&mut page, &patch).unwrap();
            assert_eq!(
                read_head(&page, off),
                new,
                "equal-case CAS resets a {expect:#x}-valued head to {new:#x}"
            );

            // And the unequal case (head already moved to some other value) no-ops, never matching a
            // value just because it shares the 0xFFFF sentinel byte pattern in the offset slot.
            let other = expect.wrapping_add(1);
            let mut page2 = page_with_head(off, other);
            apply_patch(&mut page2, &patch).unwrap();
            assert_eq!(
                read_head(&page2, off),
                other,
                "unequal-case CAS leaves a {other:#x}-valued head untouched"
            );
        }
    }
}
