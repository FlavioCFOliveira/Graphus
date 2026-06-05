//! The block-device abstraction: page-granular, synchronous I/O for the storage core.

use graphus_core::PageId;
use graphus_core::constants::LOGICAL_PAGE_SIZE;
use graphus_core::error::Result;

/// The size in bytes of one storage page (equal to
/// [`graphus_core::constants::LOGICAL_PAGE_SIZE`]).
pub const PAGE_SIZE: usize = LOGICAL_PAGE_SIZE;

/// Exactly one page worth of bytes.
pub type Page = [u8; PAGE_SIZE];

/// A synchronous, page-addressable block device.
///
/// This is the single I/O surface the buffer pool and write-ahead log build on. Two
/// implementations exist: [`crate::FileBlockDevice`] (production, over a real file) and
/// [`crate::MemBlockDevice`] (in-memory, modelling the durability boundary with crash,
/// torn-write and I/O-error injection for Deterministic Simulation Testing).
///
/// Writes need not be durable until [`BlockDevice::sync_data`] or [`BlockDevice::sync_all`]
/// returns.
pub trait BlockDevice {
    /// Reads page `page` into `buf`. Errors if `page` is out of range.
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()>;

    /// Writes `buf` to page `page`. The write may be buffered until a subsequent sync.
    fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()>;

    /// Flushes file data (and the minimum metadata needed to read it back) durably.
    fn sync_data(&mut self) -> Result<()>;

    /// Flushes file data and all metadata durably.
    fn sync_all(&mut self) -> Result<()>;

    /// The number of pages the device currently holds.
    fn page_count(&self) -> u64;

    /// Grows the device by `additional` zero-filled pages.
    fn extend(&mut self, additional: u64) -> Result<()>;
}
