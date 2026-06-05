//! Crash recovery wiring: replaying the WAL onto the raw device (`04-technical-design.md` §4.8).
//!
//! After an unclean shutdown the WAL holds the only durable record of committed work (no-force)
//! and possibly stolen, uncommitted pages (steal). [`recover_device`] runs the WAL's three-phase
//! ARIES recovery ([`graphus_wal::recover`]) against a [`DeviceTarget`] that applies redo/undo
//! intra-page patches directly to the [`BlockDevice`], reading each page's `page_lsn` from its
//! header to guard redo (`record.lsn > page_lsn`). After it returns, the device's pages — the
//! metadata page included — are at the last durable committed-or-nothing state, and
//! [`crate::RecordStore::open`] reloads the in-memory catalog from them.
//!
//! Recovery operates on the **raw device**, not the buffer pool, because (a) there is no
//! concurrency during recovery, (b) it must read each page's `page_lsn` to guard redo, and (c)
//! keeping the pool out avoids a self-referential WAL borrow through the pool's WAL rule.

use graphus_bufpool::page;
use graphus_core::error::Result;
use graphus_core::{Lsn, PageId};
use graphus_io::{BlockDevice, PAGE_SIZE, Page};
use graphus_wal::{ApplyTarget, LogSink, RecoveryReport, WalManager, recover};

/// An [`ApplyTarget`] that applies WAL redo/undo intra-page patches directly to a
/// [`BlockDevice`].
///
/// On `apply` it reads the page, patches it, re-stamps its `page_lsn` and the page header
/// checksum, and writes it back (the write becomes durable on the final [`DeviceTarget::sync`]).
/// `page_lsn` reads the page header so redo can skip changes already reflected on a page
/// (no-force after a partial flush).
pub struct DeviceTarget<'a, D: BlockDevice> {
    device: &'a mut D,
}

impl<'a, D: BlockDevice> DeviceTarget<'a, D> {
    /// Wraps a device as a recovery apply target.
    pub fn new(device: &'a mut D) -> Self {
        Self { device }
    }

    /// Grows the device with zero pages until `page` is addressable (no-force redo can reference a
    /// page the device was not flushed up to), returning the (possibly grown) page index.
    fn ensure(&mut self, page: PageId) -> Result<()> {
        if page.0 >= self.device.page_count() {
            let additional = page.0 - self.device.page_count() + 1;
            self.device.extend(additional)?;
        }
        Ok(())
    }

    /// Hardens every applied page durably.
    ///
    /// # Errors
    /// Returns a storage error if the device sync fails.
    pub fn sync(&mut self) -> Result<()> {
        self.device.sync_all()
    }
}

impl<D: BlockDevice> ApplyTarget for DeviceTarget<'_, D> {
    fn page_lsn(&self, page: PageId) -> Lsn {
        if page.0 >= self.device.page_count() {
            return Lsn(0);
        }
        let mut buf: Page = [0u8; PAGE_SIZE];
        // A read failure here means the page is unreadable; treat its lsn as 0 so redo replays the
        // change (idempotent: redo overwrites the region with the post-image anyway).
        if self.device.read_page(page, &mut buf).is_err() {
            return Lsn(0);
        }
        page::page_lsn(&buf)
    }

    fn apply(&mut self, page: PageId, lsn: Lsn, image: &[u8]) -> Result<()> {
        self.ensure(page)?;
        let mut buf: Page = [0u8; PAGE_SIZE];
        self.device.read_page(page, &mut buf)?;
        crate::paging::apply_patch(&mut buf, image)?;
        page::set_page_lsn(&mut buf, lsn);
        page::set_page_id(&mut buf, page.0);
        page::write_checksum(&mut buf);
        self.device.write_page(page, &buf)
    }
}

/// Runs three-phase ARIES recovery of `wal` onto `device`, leaving its pages at the last durable
/// committed-or-nothing state. Hardens the device before returning.
///
/// # Errors
/// Propagates a WAL read, apply, or device sync failure.
///
/// # Panics
/// Panics if hardening the CLRs written during undo fails (`04 §4.9`).
pub fn recover_device<S: LogSink, D: BlockDevice>(
    wal: &mut WalManager<S>,
    device: &mut D,
) -> Result<RecoveryReport> {
    let mut target = DeviceTarget::new(device);
    let report = recover(wal, &mut target)?;
    target.sync()?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_io::MemBlockDevice;
    use graphus_wal::MemLogSink;

    #[test]
    fn device_target_applies_a_patch_and_stamps_lsn() {
        let mut dev = MemBlockDevice::new(1);
        {
            let mut t = DeviceTarget::new(&mut dev);
            let patch = crate::paging::encode_patch(100, &[1, 2, 3, 4]);
            t.apply(PageId(0), Lsn(42), &patch).unwrap();
            t.sync().unwrap();
        }
        let mut buf = [0u8; PAGE_SIZE];
        dev.read_page(PageId(0), &mut buf).unwrap();
        assert_eq!(&buf[100..104], &[1, 2, 3, 4]);
        assert_eq!(page::page_lsn(&buf), Lsn(42));
        assert!(page::verify_checksum(&buf));
    }

    #[test]
    fn device_target_grows_for_an_out_of_range_page() {
        let mut dev = MemBlockDevice::new(1);
        {
            let mut t = DeviceTarget::new(&mut dev);
            let patch = crate::paging::encode_patch(0, &[9]);
            t.apply(PageId(3), Lsn(1), &patch).unwrap(); // page 3 does not exist yet
            t.sync().unwrap();
        }
        assert!(dev.page_count() >= 4);
    }

    #[test]
    fn recover_on_empty_log_is_a_noop() {
        let wal = WalManager::create(MemLogSink::new()).unwrap();
        let sink = wal.sink().clone();
        let mut wal2 = WalManager::open(sink).unwrap();
        let mut dev = MemBlockDevice::new(1);
        let report = recover_device(&mut wal2, &mut dev).unwrap();
        assert_eq!(report.redo_applied, 0);
        assert_eq!(report.losers, 0);
    }
}
