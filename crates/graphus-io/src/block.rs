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

    /// Writes a run of `pages` to consecutive page ids starting at `base`: `pages[i]` lands on
    /// page `base + i`. The pages are assumed to be at *contiguous* (adjacent) offsets; the caller
    /// (the buffer pool's checkpoint/flush) groups its dirty frames into contiguous runs and emits
    /// each run through this method so a device that supports it can collapse the run into a single
    /// vectored/sequential write — far fewer syscalls than one `write_page` per page (`rmp` #374).
    ///
    /// The default implementation simply loops [`write_page`](Self::write_page), so every device
    /// keeps working unchanged (and, crucially, the in-memory DST device keeps its per-page
    /// fault-injection semantics — torn writes, misdirected writes, armed I/O errors all still fire
    /// per page). A device overrides this only to coalesce the syscalls; the bytes written, the
    /// offsets, and the per-page durability contract are identical to the per-page path.
    ///
    /// # Errors
    /// Propagates the first device-write failure. On error, an unspecified prefix of the run may
    /// have reached the device's buffers (exactly as with a sequence of `write_page` calls); the
    /// caller's WAL + recovery make a partial write-back recoverable.
    fn write_pages(&mut self, base: PageId, pages: &[&Page]) -> Result<()> {
        for (i, page) in pages.iter().enumerate() {
            let id = PageId(base.0.checked_add(i as u64).ok_or_else(|| {
                graphus_core::error::GraphusError::Storage(
                    "page id overflow in write_pages run".to_owned(),
                )
            })?);
            self.write_page(id, page)?;
        }
        Ok(())
    }

    /// Flushes file data (and the minimum metadata needed to read it back) durably.
    fn sync_data(&mut self) -> Result<()>;

    /// Flushes file data and all metadata durably.
    fn sync_all(&mut self) -> Result<()>;

    /// The number of pages the device currently holds.
    fn page_count(&self) -> u64;

    /// Grows the device by `additional` zero-filled pages.
    fn extend(&mut self, additional: u64) -> Result<()>;
}
