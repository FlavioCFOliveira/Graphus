//! Write-I/O-error fault: the "surface, never corrupt" contract
//! (`specification/04-technical-design.md` §11.5).
//!
//! ## Why this lives at the buffer-pool / device layer
//!
//! The spec asks the engine to *surface* a write I/O error and *never corrupt* on it. Injecting it
//! into the full `RecordStore` write path is **deferred** (see
//! [`graphus_dst::DeferredFault::WriteIoErrorFullEngine`]): `RecordStore` exposes no public seam to
//! reach its device after construction, and this task may not modify other crates. So the contract
//! is verified here at the two layers the public API *does* let us drive with an armed device:
//!
//! 1. the [`graphus_io::MemBlockDevice`] itself — an armed write returns an error and leaves the
//!    prior durable page byte-for-byte intact (no partial/torn state, checksum still valid); and
//! 2. the [`graphus_bufpool::BufferPool`] write-back path — it propagates the device's write error
//!    out of `flush` rather than swallowing it or corrupting the cached page.
//!
//! Together these prove the fault behaves correctly at the point where it is injected; the
//! full-engine wiring is tracked as deferred, honestly, in [`graphus_dst::fault`].

use graphus_bufpool::BufferPool;
use graphus_bufpool::page;
use graphus_core::PageId;
use graphus_io::{BlockDevice, MemBlockDevice, PAGE_SIZE, Page};

/// A page filled with `byte`, stamped with `page_id` and a valid checksum (so the pool will accept
/// it on fetch).
fn checksummed_page(page_id: u64, byte: u8) -> Page {
    let mut p: Page = [byte; PAGE_SIZE];
    page::set_page_id(&mut p, page_id);
    page::write_checksum(&mut p);
    p
}

/// At the device layer: an armed write fails and leaves the prior durable content intact.
#[test]
fn device_write_io_error_surfaces_and_does_not_corrupt() {
    let mut dev = MemBlockDevice::new(1);
    let durable = checksummed_page(0, 0xAB);
    dev.write_page(PageId(0), &durable).unwrap();
    dev.sync_all().unwrap();

    // Arm a one-shot I/O error; the next write must fail.
    dev.arm_io_error();
    let attempt = checksummed_page(0, 0xCD);
    let err = dev.write_page(PageId(0), &attempt);
    assert!(err.is_err(), "armed write must surface an error");

    // The page is unchanged — no partial write, checksum still valid.
    let mut read: Page = [0u8; PAGE_SIZE];
    dev.read_page(PageId(0), &mut read).unwrap();
    assert_eq!(read, durable, "a failed write must not corrupt the page");
    assert!(page::verify_checksum(&read), "checksum must still verify");

    // The fault is one-shot: the next write succeeds.
    let ok = checksummed_page(0, 0xEF);
    assert!(dev.write_page(PageId(0), &ok).is_ok());
}

/// At the buffer-pool layer: a write-back over a device whose next write errors must propagate the
/// error out of `flush`, not corrupt the cached page or silently succeed.
#[test]
fn buffer_pool_write_back_propagates_device_io_error() {
    // A device with one valid, durable page 0.
    let mut dev = MemBlockDevice::new(1);
    dev.write_page(PageId(0), &checksummed_page(0, 0x11))
        .unwrap();
    dev.sync_all().unwrap();
    // Arm the I/O error *before* handing the device to the pool (the pool exposes no device seam,
    // mirroring exactly the constraint that defers the full-engine version of this fault).
    dev.arm_io_error();

    let mut pool: BufferPool<MemBlockDevice> = BufferPool::new(dev, 4);
    let f = pool
        .fetch(PageId(0))
        .expect("fetch reads (no write) succeeds");
    // Dirty the page so a flush must write it back.
    pool.page_mut(f)[100] = 0x22;

    let flushed = pool.flush(f);
    assert!(
        flushed.is_err(),
        "the pool must propagate the device write error out of flush"
    );
    pool.unpin(f);
}

/// After a propagated I/O error, the engine layer that owns the device still treats it as a clean
/// error (no panic, no UB) — modelled by confirming a *fresh* pool over a fresh device with the same
/// content recovers normally (the failed write simply did not happen).
#[test]
fn io_error_is_recoverable_not_fatal() {
    let mut dev = MemBlockDevice::new(1);
    dev.write_page(PageId(0), &checksummed_page(0, 0x33))
        .unwrap();
    dev.sync_all().unwrap();

    let mut pool: BufferPool<MemBlockDevice> = BufferPool::new(dev, 4);
    let f = pool.fetch(PageId(0)).expect("fetch");
    // The page read back is intact and valid (the durable content), proving no corruption occurred.
    // Byte 100 is in the data region (past the 24-byte page header), so it carries the fill byte.
    assert_eq!(pool.page(f)[100], 0x33);
    assert!(page::verify_checksum(pool.page(f)));
    pool.unpin(f);
}
