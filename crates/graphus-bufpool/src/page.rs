//! Page header layout (`specification/05-storage-format.md` §6) and its CRC32C checksum.
//!
//! Every page begins with a fixed 24-byte header. Multi-byte fields are little-endian
//! (`01-needs-survey.md` FR-ST-11). The checksum covers the page body (everything after the
//! 4-byte checksum field).

use graphus_core::Lsn;
use graphus_io::{PAGE_SIZE, Page};

/// Size of the fixed page header in bytes.
pub const HEADER_SIZE: usize = 24;

const OFF_CHECKSUM: usize = 0; // u32
/// Byte offset of the 4-byte type/flags word: low byte = page type, second byte = subtype (store
/// kind for record pages, `rmp` #239), remaining bytes reserved flags. Public so the storage layer
/// can WAL-log the type/subtype stamp at offset (a redo-durable, undo == redo structural write).
pub const OFF_PAGE_TYPE: usize = 4; // u32 (low byte = type)
const OFF_PAGE_LSN: usize = 8; // u64
const OFF_PAGE_ID: usize = 16; // u64

fn read_u32(page: &Page, off: usize) -> u32 {
    u32::from_le_bytes(page[off..off + 4].try_into().expect("4-byte slice"))
}

fn read_u64(page: &Page, off: usize) -> u64 {
    u64::from_le_bytes(page[off..off + 8].try_into().expect("8-byte slice"))
}

/// Computes the CRC32C checksum over the page body (bytes `4..PAGE_SIZE`) — everything except
/// the checksum field itself.
#[must_use]
pub fn compute_checksum(page: &Page) -> u32 {
    crc32c::crc32c(&page[OFF_PAGE_TYPE..PAGE_SIZE])
}

/// Computes and stores the checksum into the page header.
pub fn write_checksum(page: &mut Page) {
    let c = compute_checksum(page);
    page[OFF_CHECKSUM..OFF_CHECKSUM + 4].copy_from_slice(&c.to_le_bytes());
}

/// Returns the checksum recorded in the header.
#[must_use]
pub fn stored_checksum(page: &Page) -> u32 {
    read_u32(page, OFF_CHECKSUM)
}

/// Verifies the page body against its stored checksum.
#[must_use]
pub fn verify_checksum(page: &Page) -> bool {
    stored_checksum(page) == compute_checksum(page)
}

/// Returns the page LSN (ARIES `pageLSN`).
#[must_use]
pub fn page_lsn(page: &Page) -> Lsn {
    Lsn(read_u64(page, OFF_PAGE_LSN))
}

/// Advances the page LSN. **Monotone: it never descends** (`rmp` #1029).
///
/// The page LSN is a claim — "this image reflects every change logged at or below this LSN" — and two
/// mechanisms are decided on it. Recovery skips every record whose `lsn <= page_lsn`, and the buffer
/// pool's WAL-before-data gate lets a page go home once the log is durable through it. Moving the
/// claim BACKWARDS makes the second gate pass for a page whose content reflects a *higher*, not-yet
/// durable LSN: the page reaches the home file ahead of its own redo record.
///
/// The out-of-order stamp that makes this necessary was expected to need two writers — the WAL record
/// is emitted and the frame latch taken as two separate steps (`SharedWal::with` releases its guard at
/// the end of the closure), so thread A can take LSN 10, thread B take LSN 12, B apply, and A apply
/// afterwards. It does not. MEASURED with an assertion in this function (`rmp` #1029): it already
/// happens on a SINGLE thread, in ordinary operation — `free_undo_chain` -> `patch_header_word`
/// stamping 2598 over 2852, and `reclaim_rel` -> `unlink_side` -> `write_node` stamping 75972 over
/// 77412. Since log LSNs are strictly increasing, that says the code logs in one order and applies in
/// another.
///
/// Taking the maximum is honest under either cause: the content DOES reflect the higher LSN, because
/// the change logged at it was applied. What the maximum does not do is fix the divergence between log
/// order and apply order — recovery replays by LSN and would rebuild a different image than the
/// runtime produced. That is `rmp` #1028's subject; this function deliberately carries no assertion,
/// so that a live ordering question does not brick every debug build (decided 2026-08-11 with the
/// measurement above in hand). InnoDB states the sister invariant as an assertion because its apply
/// order is its log order (`buf0flu.ic`: `ut_ad(block->page.get_newest_lsn() <= end_lsn)` before
/// `set_newest_lsn(end_lsn)`).
///
/// `rmp` #1062 closed that ordering question — every logged page write now appends and applies under
/// one rank-27 page latch, so the maximum never has to clamp — and supplied the middle term this note
/// asked for instead of an assertion:
/// [`ConcurrentBufferPool::page_lsn_descents`](crate::ConcurrentBufferPool::page_lsn_descents)
/// **counts** every clamped stamp, always, in every build. It is the pool, not this function, that
/// counts, because only the pool holds the write latch across the read-then-stamp pair and can
/// therefore report an exact count rather than a sample.
///
/// A page being REBUILT rather than updated in place is a different operation and must not come here —
/// see [`reset_page_lsn`].
pub fn set_page_lsn(page: &mut Page, lsn: Lsn) {
    let current = read_u64(page, OFF_PAGE_LSN);
    let advanced = current.max(lsn.0);
    page[OFF_PAGE_LSN..OFF_PAGE_LSN + 8].copy_from_slice(&advanced.to_le_bytes());
}

/// Sets the page LSN **unconditionally**, including downwards — for a page whose whole image is being
/// REPLACED rather than updated in place.
///
/// # When this is the correct operation, and why the monotone one is not
///
/// [`set_page_lsn`]'s monotonicity rests on the existing header describing the existing content. A
/// rebuild breaks that premise: the content is replaced wholesale, so the LSN that arrives with the
/// new content is the truth and the header's previous value is not evidence of anything.
///
/// Two paths do exactly this, and both would be CORRUPTED by a maximum:
///
/// * **ARIES redo onto a page that failed its checksum.** Recovery reports such a page's LSN as `0`
///   deliberately (`rmp` #592), so redo replays every record and rebuilds it from the log. A torn page
///   reads back with a large, intact-looking header LSN — measured at 13 068 958 against records at
///   LSN 749 — and taking the maximum would retain that garbage, making every subsequent record
///   `lsn <= page_lsn` and skipping the whole rebuild. The committed data is then simply gone, with
///   nothing reporting it (measured on `crash_mid_eviction_974`, `rmp` #1029).
/// * **A doublewrite restore.** `Dwb::recover_home` replaces a torn home page with its staged copy,
///   whose LSN is by construction lower than whatever the torn header happens to contain.
///
/// Naming the operation is the point: a call site that reaches for this is stating that it is
/// replacing the page, and one that reaches for [`set_page_lsn`] is stating that it is amending it.
pub fn reset_page_lsn(page: &mut Page, lsn: Lsn) {
    page[OFF_PAGE_LSN..OFF_PAGE_LSN + 8].copy_from_slice(&lsn.0.to_le_bytes());
}

/// Returns the self-referential page id recorded in the header.
#[must_use]
pub fn page_id(page: &Page) -> u64 {
    read_u64(page, OFF_PAGE_ID)
}

/// Sets the self-referential page id.
pub fn set_page_id(page: &mut Page, id: u64) {
    page[OFF_PAGE_ID..OFF_PAGE_ID + 8].copy_from_slice(&id.to_le_bytes());
}

/// Returns the page type byte.
#[must_use]
pub fn page_type(page: &Page) -> u8 {
    page[OFF_PAGE_TYPE]
}

/// Sets the page type byte (the other three bytes of the type/flags word are left intact).
pub fn set_page_type(page: &mut Page, ty: u8) {
    page[OFF_PAGE_TYPE] = ty;
}

/// Returns the page **subtype** byte: the second byte of the 4-byte type/flags word (`05 §6`'s
/// reserved flag bytes). The storage layer uses it to tag a record page with the fixed-record store
/// it belongs to, so crash recovery can attribute device pages back to their store (`rmp` #239).
#[must_use]
pub fn page_subtype(page: &Page) -> u8 {
    page[OFF_PAGE_TYPE + 1]
}

/// Sets the page subtype byte (the other three bytes of the type/flags word are left intact).
pub fn set_page_subtype(page: &mut Page, subtype: u8) {
    page[OFF_PAGE_TYPE + 1] = subtype;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **`rmp` #1029 GATE — the page LSN only ever advances.**
    ///
    /// **Non-vacuity.** With `set_page_lsn` returned to a blind `copy_from_slice` this still passes —
    /// it only exercises the forward direction — but [`a_backwards_page_lsn_is_absorbed`] reads back
    /// `10` instead of `12` and fails.
    #[test]
    fn set_page_lsn_advances_the_claim() {
        let mut page = [0u8; PAGE_SIZE];
        set_page_lsn(&mut page, Lsn(12));
        assert_eq!(page_lsn(&page), Lsn(12));
        set_page_lsn(&mut page, Lsn(20));
        assert_eq!(page_lsn(&page), Lsn(20));
    }

    /// **`rmp` #1029 GATE — a stamp that would descend is absorbed, keeping the higher claim.**
    ///
    /// The claim is what `assert_wal_covers` is decided on: lowering it lets a page whose content is at
    /// LSN 12 go home once the log is durable only through 10, which puts data ahead of its own redo
    /// record. Absorbed rather than refused, in every build — the out-of-order stamp that produces this
    /// is live today on a single thread (see [`set_page_lsn`]), and its cause is `rmp` #1028's.
    #[test]
    fn a_backwards_page_lsn_is_absorbed() {
        let mut page = [0u8; PAGE_SIZE];
        set_page_lsn(&mut page, Lsn(12));
        set_page_lsn(&mut page, Lsn(10));
        assert_eq!(
            page_lsn(&page),
            Lsn(12),
            "the claim must keep the highest LSN the content reflects"
        );
    }

    /// **`rmp` #1029 GATE — a REBUILD replaces the claim, downwards included.**
    ///
    /// This is the operation recovery performs on a page that failed its checksum and the doublewrite
    /// buffer performs on a torn home page. Making it monotone too — the obvious over-correction —
    /// retains the torn header's garbage LSN and silently skips the entire rebuild.
    #[test]
    fn reset_page_lsn_replaces_the_claim_in_both_directions() {
        let mut page = [0u8; PAGE_SIZE];
        reset_page_lsn(&mut page, Lsn(13_068_958)); // a torn page's intact-looking header
        reset_page_lsn(&mut page, Lsn(749)); // the first record redo rebuilds it from
        assert_eq!(
            page_lsn(&page),
            Lsn(749),
            "a rebuilt page's claim is the LSN that arrived with its new content, never the old \
             header's — retaining the latter skips every subsequent record and loses committed data"
        );
    }

    #[test]
    fn checksum_detects_corruption() {
        let mut page = [0u8; PAGE_SIZE];
        page[200..205].copy_from_slice(b"graph");
        write_checksum(&mut page);
        assert!(verify_checksum(&page));
        page[200] ^= 0xFF; // flip a body byte
        assert!(!verify_checksum(&page));
    }

    #[test]
    fn header_fields_round_trip() {
        let mut page = [0u8; PAGE_SIZE];
        set_page_lsn(&mut page, Lsn(0x0102_0304_0506_0708));
        set_page_id(&mut page, 42);
        set_page_type(&mut page, 3);
        assert_eq!(page_lsn(&page), Lsn(0x0102_0304_0506_0708));
        assert_eq!(page_id(&page), 42);
        assert_eq!(page_type(&page), 3);
        assert_eq!(HEADER_SIZE, 24);
    }
}
