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

use graphus_bufpool::page::HEADER_SIZE;
use graphus_io::PAGE_SIZE;

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
pub fn encode_patch(offset: usize, bytes: &[u8]) -> Vec<u8> {
    assert!(
        offset + bytes.len() <= PAGE_SIZE,
        "patch runs past the page"
    );
    let mut out = Vec::with_capacity(2 + bytes.len());
    out.extend_from_slice(&(offset as u16).to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

/// Applies a patch produced by [`encode_patch`] to `page`, writing its bytes at the encoded
/// offset.
///
/// # Errors
/// Returns a storage error if the patch is malformed or would write past the page.
pub fn apply_patch(page: &mut [u8], patch: &[u8]) -> graphus_core::Result<()> {
    use graphus_core::GraphusError;
    if patch.len() < 2 {
        return Err(GraphusError::Storage("patch too short".to_owned()));
    }
    let offset = u16::from_le_bytes(patch[0..2].try_into().expect("2-byte slice")) as usize;
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
}
