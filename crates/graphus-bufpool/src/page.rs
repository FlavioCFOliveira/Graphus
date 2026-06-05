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
const OFF_PAGE_TYPE: usize = 4; // u32 (low byte = type)
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

/// Sets the page LSN.
pub fn set_page_lsn(page: &mut Page, lsn: Lsn) {
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

#[cfg(test)]
mod tests {
    use super::*;

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
