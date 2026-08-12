//! **Regression gate for a fail-open in `Dwb::set_floor`** (found while auditing `rmp` #1079; the
//! defect predates it).
//!
//! ## The defect
//!
//! The doublewrite buffer's checkpoint-floor LSN (`rmp` #437) gates eviction-ring recovery: on the
//! next open, a ring slot staged below the floor is ignored, because the home page it would restore
//! is provably superseded. `RecordStore::checkpoint` therefore persists the floor **before** it
//! reclaims the WAL prefix below it — a crash between the two must leave either the old floor with
//! the log intact, or the new floor with the log gone, and never the new floor with nothing to back
//! it.
//!
//! `set_floor` assigned `self.floor` **first** and wrote the header afterwards. A failed write or
//! sync therefore left the in-memory floor ahead of the durable one — and the failure was not merely
//! transient, it was **permanent**, because `set_floor` is monotonic: the retry passes the same LSN,
//! finds it no greater than the field that was already advanced, and returns `Ok(())` having written
//! nothing at all. The checkpoint reads that `Ok` as "the floor is durable" and reclaims the WAL
//! prefix beneath it. What is left is exactly the state `rmp` #437 exists to prevent: a ring slot
//! older than a floor that was never persisted stays honoured, so a later open can restore a stale
//! committed image over a torn newer home page, with the redo records that would have rolled it
//! forward already reclaimed.
//!
//! This is the shape of every fail-open the project has met: a piece of state is adopted before the
//! step that earns it, and the guard that should have caught the second attempt reads the adoption as
//! evidence the work was done.
//!
//! ## What is asserted
//!
//! 1. A failed header write does **not** advance the in-memory floor (the mechanism).
//! 2. The retry therefore genuinely rewrites the header, and the floor is durable — read back by
//!    reopening a [`Dwb`] over the same device, which is the only claim that matters to recovery.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use graphus_core::error::Result;
use graphus_core::{Lsn, PageId};
use graphus_io::{BlockDevice, MemBlockDevice, Page};
use graphus_storage::Dwb;

/// A device whose next write can be refused, shared so the refusal can be armed while the [`Dwb`]
/// owns the device.
#[derive(Clone)]
struct ArmableDevice {
    inner: Arc<Mutex<MemBlockDevice>>,
    fail_next_write: Arc<AtomicBool>,
    refused: Arc<AtomicU64>,
}

impl ArmableDevice {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MemBlockDevice::new(0))),
            fail_next_write: Arc::new(AtomicBool::new(false)),
            refused: Arc::new(AtomicU64::new(0)),
        }
    }
    fn arm(&self) {
        self.fail_next_write.store(true, Ordering::SeqCst);
    }
    fn refusals(&self) -> u64 {
        self.refused.load(Ordering::SeqCst)
    }
    fn at(&self) -> std::sync::MutexGuard<'_, MemBlockDevice> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl BlockDevice for ArmableDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
        self.at().read_page(page, buf)
    }
    fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
        if self.fail_next_write.swap(false, Ordering::SeqCst) {
            self.refused.fetch_add(1, Ordering::SeqCst);
            return Err(graphus_core::error::GraphusError::Storage(
                "injected I/O error writing the doublewrite floor header (rmp #1079)".to_owned(),
            ));
        }
        self.at().write_page(page, buf)
    }
    fn sync_data(&mut self) -> Result<()> {
        self.at().sync_data()
    }
    fn sync_all(&mut self) -> Result<()> {
        self.at().sync_all()
    }
    fn page_count(&self) -> u64 {
        self.at().page_count()
    }
    fn extend(&mut self, additional: u64) -> Result<()> {
        self.at().extend(additional)
    }
}

#[test]
fn a_failed_floor_write_leaves_the_floor_where_it_is_durable_1079() {
    let dev = ArmableDevice::new();
    let mut dwb = Dwb::new(dev.clone()).expect("create dwb");
    assert_eq!(dwb.floor().0, 0, "a fresh doublewrite buffer floors at 0");

    // The floor write fails.
    dev.arm();
    let outcome = dwb.set_floor(Lsn(100));
    assert_eq!(
        dev.refusals(),
        1,
        "the injected fault never fired, so nothing below tests anything"
    );
    assert!(
        outcome.is_err(),
        "a refused header write must be reported, not absorbed"
    );

    // (1) THE MECHANISM. The floor names what is durable, so it must not have moved.
    assert_eq!(
        dwb.floor().0,
        0,
        "the in-memory floor advanced past a header write that failed; the monotonic guard in \
         `set_floor` then makes that permanent, because the retry finds nothing left to do"
    );

    // (2) THE CONSEQUENCE. The retry must genuinely write, and the floor must be durable — which is
    // the only form of the claim `RecordStore::checkpoint` relies on before it reclaims the WAL.
    dwb.set_floor(Lsn(100)).expect("the retry must succeed");
    assert_eq!(dwb.floor().0, 100);
    let reopened = Dwb::new(dwb.into_device()).expect("reopen dwb over the same device");
    assert_eq!(
        reopened.floor().0,
        100,
        "the floor the checkpoint was told is durable must actually be on the device"
    );
}
