//! Regression gate for `rmp` #993 — the doublewrite **staging barrier** runs with the DWB device
//! mutex released, and torn-write protection is unaffected.
//!
//! # The defect
//!
//! `rmp` #431 removed the *home write* from the DWB device mutex but left the **staging fsync**
//! inside it, because `BlockDevice::sync_data` takes `&mut self` and the device lives behind that
//! mutex. Every evictor therefore still serialised through one `fdatasync`. Measured on a 16-core
//! host with a working set twice the buffer pool: the mutex was held **96–98 % of wall time**, and
//! the time evictors spent *waiting* for it reached **11 415 ms/s at 16 readers** — 2.3 threads
//! permanently blocked. That capped evictions at ~1750/s regardless of buffer-pool size, which is
//! why detaching the doublewrite entirely took the same read workload from 34 700 to 659 590 ops/s.
//!
//! # What is asserted here
//!
//! Two properties, and the second is the one that must never bend:
//!
//! 1. **The barrier is outside the mutex.** [`graphus_core::latch::assert_no_dwb_lock_held`] fires
//!    inside the staging barrier if the DWB lock is held. That assertion is vacuous on its own — a
//!    depth counter that never increments satisfies it — so [`writes_happen_under_the_dwb_lock`] is
//!    the **positive control**: the DWB device's `write_page` asserts the depth is non-zero, which
//!    it must be, because the writes genuinely do run under the lock.
//! 2. **Torn-write protection survives.** [`a_torn_home_write_is_repaired_from_the_staged_copy`]
//!    crashes between the staging barrier and the home write — snapshotting only the *durable* DWB
//!    bytes, exactly as a power loss would — then tears the home page and proves recovery restores
//!    it from the staged copy. If the barrier did not precede the home write, the copy would still
//!    be volatile, the crash would lose it, and recovery would have nothing to repair from.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use graphus_bufpool::{PageStager, page};
use graphus_core::PageId;
use graphus_core::error::Result;
use graphus_io::{BlockDevice, PAGE_SIZE, Page, SyncHandle};
use graphus_storage::dwb::{Dwb, DwbPageStager};

fn make_page(id: u64, lsn: u64, fill: u8) -> Page {
    let mut p = [fill; PAGE_SIZE];
    page::set_page_id(&mut p, id);
    // A page BUILT from a fill byte, not amended: its header LSN is whatever the fill happens to
    // spell, so the intended value must REPLACE it rather than be maxed against it (`rmp` #1029).
    page::reset_page_lsn(&mut p, graphus_core::Lsn(lsn));
    page::write_checksum(&mut p);
    p
}

/// The durability model shared by a [`HandleDevice`] and its [`SyncHandle`]: writes land in a
/// volatile cache and only a barrier promotes them to the durable image. A "crash" is simply reading
/// the durable image and discarding the cache — precisely what a power loss leaves behind.
#[derive(Default, Debug)]
struct DeviceCore {
    durable: Vec<Page>,
    cache: std::collections::HashMap<u64, Page>,
    /// Barriers issued through the **shared handle** (i.e. with the DWB lock released).
    handle_barriers: usize,
    /// Barriers issued through the `&mut self` device method (i.e. under the lock).
    device_barriers: usize,
}

impl DeviceCore {
    fn promote(&mut self) {
        for (idx, bytes) in self.cache.drain() {
            self.durable[idx as usize] = bytes;
        }
    }
}

/// An in-memory [`BlockDevice`] that **offers a shared [`SyncHandle`]**, so the doublewrite stager
/// takes the `rmp` #993 path (barrier with the mutex released) rather than the `&mut self` fallback.
///
/// The existing DWB tests use `MemBlockDevice`, which offers no handle — they therefore exercise the
/// fallback and cannot see this change at all. That is why this file defines its own device.
#[derive(Clone)]
struct HandleDevice {
    core: Arc<Mutex<DeviceCore>>,
    /// Counts `write_page` calls that ran while the DWB lock was **not** held. Must stay zero: the
    /// writes are the half that legitimately belongs inside the lock.
    writes_outside_lock: Arc<AtomicUsize>,
    /// When set, `write_page` asserts the DWB lock IS held (the positive control). Off for the home
    /// device, which is written with no DWB lock by design.
    expect_dwb_lock: bool,
}

impl HandleDevice {
    fn new(pages: u64, expect_dwb_lock: bool) -> Self {
        Self {
            core: Arc::new(Mutex::new(DeviceCore {
                durable: vec![[0u8; PAGE_SIZE]; pages as usize],
                ..DeviceCore::default()
            })),
            writes_outside_lock: Arc::new(AtomicUsize::new(0)),
            expect_dwb_lock,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, DeviceCore> {
        self.core
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The durable image a crash right now would leave behind.
    fn crash_snapshot(&self) -> Vec<Page> {
        self.lock().durable.clone()
    }

    fn handle_barriers(&self) -> usize {
        self.lock().handle_barriers
    }

    fn device_barriers(&self) -> usize {
        self.lock().device_barriers
    }
}

/// The `&self` barrier handle over the same core.
#[derive(Debug)]
struct CoreHandle {
    core: Arc<Mutex<DeviceCore>>,
}

impl SyncHandle for CoreHandle {
    fn sync_data(&self) -> Result<()> {
        // THE TRIPWIRE, checked at the barrier itself: this is the call `rmp` #993 moved out of the
        // DWB mutex, and it must never run with that mutex held.
        assert_eq!(
            graphus_core::latch::dwb_lock_depth(),
            0,
            "rmp #993: the staging barrier ran with the DWB device mutex held"
        );
        let mut c = self
            .core
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        c.handle_barriers += 1;
        c.promote();
        Ok(())
    }

    fn sync_all(&self) -> Result<()> {
        self.sync_data()
    }
}

impl BlockDevice for HandleDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
        let c = self.lock();
        // A read sees the newest bytes (cache first), like a real page cache.
        *buf = c
            .cache
            .get(&page.0)
            .copied()
            .unwrap_or_else(|| c.durable[page.0 as usize]);
        Ok(())
    }

    fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
        if self.expect_dwb_lock {
            // POSITIVE CONTROL for the tripwire. Every `depth == 0` assertion above is satisfied by a
            // counter that never increments; this is the one assertion that proves the scope is
            // actually armed. The DWB writes genuinely run under the lock, so the depth must be > 0
            // here — and it fails loudly if `DwbLockScope` is ever dropped from the staging path.
            if graphus_core::latch::dwb_lock_depth() == 0 {
                self.writes_outside_lock.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.lock().cache.insert(page.0, *buf);
        Ok(())
    }

    fn sync_data(&mut self) -> Result<()> {
        let mut c = self.lock();
        c.device_barriers += 1;
        c.promote();
        Ok(())
    }

    fn sync_all(&mut self) -> Result<()> {
        self.sync_data()
    }

    fn sync_handle(&self) -> Option<Arc<dyn SyncHandle>> {
        Some(Arc::new(CoreHandle {
            core: Arc::clone(&self.core),
        }))
    }

    fn page_count(&self) -> u64 {
        self.lock().durable.len() as u64
    }

    fn extend(&mut self, additional: u64) -> Result<()> {
        let mut c = self.lock();
        for _ in 0..additional {
            c.durable.push([0u8; PAGE_SIZE]);
        }
        Ok(())
    }
}

/// Builds a stager over a DWB whose device offers a shared handle.
fn rig() -> (
    Arc<DwbPageStager<HandleDevice>>,
    HandleDevice,
    Arc<AtomicUsize>,
) {
    let dwb_device = HandleDevice::new(graphus_storage::dwb_device_pages(), true);
    let observer = dwb_device.clone();
    let writes_outside = Arc::clone(&dwb_device.writes_outside_lock);
    let dwb = Arc::new(Mutex::new(Dwb::new(dwb_device).expect("build dwb")));
    (Arc::new(DwbPageStager::new(dwb)), observer, writes_outside)
}

/// **The positive control.** The DWB writes must run *inside* the device mutex — so the tripwire
/// scope is genuinely armed there — while the barrier runs outside it.
///
/// Without this, every `dwb_lock_depth() == 0` assertion in this file would be satisfied by a scope
/// that never increments, and the whole gate would prove nothing.
#[test]
fn writes_happen_under_the_dwb_lock() {
    let (stager, dwb_dev, writes_outside) = rig();
    let img = make_page(7, 42, 0xAB);
    stager
        .stage_and_sync(PageId(7), &img[..], &mut || Ok(()))
        .expect("stage");

    assert_eq!(
        writes_outside.load(Ordering::Relaxed),
        0,
        "the DWB writes must run under the device mutex (the tripwire scope must be armed there); \
         a non-zero count means `DwbLockScope` is no longer covering the staging writes and every \
         `depth == 0` assertion in this file is vacuous"
    );
    assert_eq!(
        dwb_dev.handle_barriers(),
        1,
        "the staging barrier must go through the SHARED handle (outside the mutex), not the \
         `&mut self` device method"
    );
    assert_eq!(
        dwb_dev.device_barriers(),
        0,
        "no barrier may be issued through the `&mut self` device method on the handle path"
    );
}

/// **Torn-write protection across a crash taken between the staging barrier and the home write.**
///
/// The `home_write` callback snapshots only the DWB's **durable** bytes — what a power loss leaves —
/// then tears the home page. Recovery must repair it from the staged copy, which is only possible if
/// the barrier really made that copy durable *before* the home write began.
///
/// Verified non-vacuous: with the staging barrier removed from `DwbPageStager::stage_and_sync`, the
/// staged copy is still volatile at crash time, the snapshot is empty, and recovery cannot repair —
/// the assertion below fails on the torn image.
#[test]
fn a_torn_home_write_is_repaired_from_the_staged_copy() {
    let (stager, dwb_dev, _) = rig();
    const HOME_ID: u64 = 3;
    let good = make_page(HOME_ID, 500, 0x5A);

    // The home device, written with no DWB lock held (so no positive-control assertion on it).
    let mut home = HandleDevice::new(8, false);
    // A committed, intact home image to start from.
    home.write_page(PageId(HOME_ID), &make_page(HOME_ID, 100, 0x11))
        .expect("seed home");
    home.sync_all().expect("seed durable");

    let crash_dwb: Arc<Mutex<Option<Vec<Page>>>> = Arc::new(Mutex::new(None));
    {
        let crash_dwb = Arc::clone(&crash_dwb);
        let dwb_dev = dwb_dev.clone();
        let home_ref = home.clone();
        let mut home_write = move || -> Result<()> {
            // THE CRASH POINT: the staging barrier has returned, the home write is about to happen.
            // Snapshot only the DURABLE DWB bytes — the volatile cache is lost in a power loss.
            *crash_dwb
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(dwb_dev.crash_snapshot());
            // The home write TEARS: a half-written image whose checksum fails.
            let mut torn = good;
            torn[PAGE_SIZE / 2..].fill(0xFF);
            let mut h = home_ref.clone();
            h.write_page(PageId(HOME_ID), &torn)?;
            h.sync_all()?;
            Ok(())
        };
        stager
            .stage_and_sync(PageId(HOME_ID), &good[..], &mut home_write)
            .expect("stage + home write");
    }

    // The home page is genuinely torn on disk.
    let mut buf: Page = [0u8; PAGE_SIZE];
    home.read_page(PageId(HOME_ID), &mut buf)
        .expect("read home");
    assert!(
        !page::verify_checksum(&buf),
        "the modelled home write must actually have torn the page, or this gate proves nothing"
    );

    // Reopen the DWB over exactly the bytes the crash left durable, and recover.
    let snapshot = crash_dwb
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .expect("home_write ran");
    let recovered_dev = HandleDevice::new(snapshot.len() as u64, false);
    {
        let mut c = recovered_dev.lock();
        c.durable = snapshot;
    }
    let mut recovered = Dwb::new(recovered_dev).expect("reopen dwb over the crash image");
    let repaired = recovered.recover_home(&mut home).expect("recover");

    assert_eq!(
        repaired, 1,
        "recovery must repair exactly the one torn home page from its staged copy"
    );
    home.read_page(PageId(HOME_ID), &mut buf)
        .expect("re-read home");
    assert!(
        page::verify_checksum(&buf),
        "the repaired home page must pass its checksum"
    );
    assert_eq!(
        buf, good,
        "the repaired home page must be byte-identical to the image that was staged"
    );
}

/// Concurrency: many evictors stage at once, each into its own ring slot, and every staged copy is
/// durable before its home write. The barrier no longer serialises them, but the ordering each
/// evictor depends on is per-evictor and must hold for all of them.
#[test]
fn concurrent_evictors_each_see_their_own_copy_durable_before_writing_home() {
    const THREADS: u64 = 8;
    const ROUNDS: u64 = 12;
    let (stager, dwb_dev, writes_outside) = rig();
    let violations = Arc::new(AtomicUsize::new(0));

    std::thread::scope(|s| {
        for t in 0..THREADS {
            let stager = Arc::clone(&stager);
            let dwb_dev = dwb_dev.clone();
            let violations = Arc::clone(&violations);
            s.spawn(move || {
                for r in 0..ROUNDS {
                    let home_id = t * 100 + r;
                    let img = make_page(home_id, 1000 + home_id, (home_id & 0xFF) as u8);
                    let dwb_dev = dwb_dev.clone();
                    let violations = Arc::clone(&violations);
                    let mut home_write = move || -> Result<()> {
                        // At the moment this evictor is about to write home, ITS OWN staged copy must
                        // already be in the DWB's durable image. A peer's concurrent staging may or
                        // may not be there — that is irrelevant and deliberately not asserted.
                        let durable = dwb_dev.crash_snapshot();
                        let found = durable
                            .iter()
                            .any(|p| page::verify_checksum(p) && page::page_id(p) == home_id);
                        if !found {
                            violations.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(())
                    };
                    stager
                        .stage_and_sync(PageId(home_id), &img[..], &mut home_write)
                        .expect("stage");
                }
            });
        }
    });

    assert_eq!(
        violations.load(Ordering::Relaxed),
        0,
        "every evictor's staged copy must be durable before its home write begins"
    );
    assert_eq!(
        writes_outside.load(Ordering::Relaxed),
        0,
        "the DWB writes must all have run under the device mutex"
    );
    assert_eq!(
        dwb_dev.device_barriers(),
        0,
        "no staging barrier may have been issued under the mutex"
    );
    // ONE BARRIER PER EVICTION IS NOT A PROPERTY OF THIS CODE, and asserting it was a mistake this
    // gate got away with only while the machine was idle.
    //
    // `rmp` #994 amortises the barrier deliberately: an evictor whose ticket a peer's round already
    // covered returns without issuing one of its own — that is the whole point of group staging. So
    // the count of `sync_data` calls is at most the number of evictions, and equals it only when no
    // two evictors happen to be inside `wait_durable` together. Under the concurrent suite two of
    // them did, and this gate read 94 against the 96 it demanded and reported a defect that did not
    // exist (`rmp` #1044).
    //
    // What IS exact, under any interleaving, is the accounting: every eviction either LED a barrier
    // round or RODE one, and every round that was led went through the off-lock handle. That is
    // asserted here in both halves, so the gate still fails if a barrier goes missing (the eviction
    // would be neither led nor ridden) or moves back under the mutex (`device_barriers` above, and
    // the handle count below would fall short of the rounds led).
    let (led, rode) = stager.barrier_counters();
    assert_eq!(
        dwb_dev.handle_barriers() as u64,
        led,
        "every barrier round that was led must have been issued through the off-lock handle"
    );
    assert_eq!(
        led + rode,
        THREADS * ROUNDS,
        "every eviction must either lead a staging barrier or ride a peer's: {led} led + {rode} rode \
         does not account for the {} evictions performed",
        THREADS * ROUNDS
    );
}
