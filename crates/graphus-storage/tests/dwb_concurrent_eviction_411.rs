//! Regression gates for `rmp` #411 — the concurrent per-eviction doublewrite slot-reuse hole.
//!
//! ## The bug (`rmp` #411, reopening the `rmp` #407 hole under concurrency)
//!
//! The doublewrite area ([`graphus_storage::dwb::Dwb`]) holds exactly ONE batch region. Before the
//! fix, the buffer pool's eviction path
//! ([`graphus_bufpool::ConcurrentBufferPool::write_back`]) staged the evicted page into that region
//! and fsynced it, **released the DWB lock**, and only THEN wrote the page to its home location. Two
//! concurrent evictors (the production reader pool: `fetch -> load_into -> evict_held ->
//! write_back`) therefore raced on the single region:
//!
//! 1. evictor T1 stages page A — the region holds A's copy;
//! 2. evictor T2 stages page B — the region is **overwritten**, now holds B's copy;
//! 3. T1 writes A home; a power loss tears that write;
//! 4. on reopen, [`Dwb::recover_home`] reads the single region, finds only B, and A's torn home page
//!    is **unrecoverable** — ARIES redo then reads a garbage `page_lsn` from the torn page and skips
//!    its repair: latent corruption, the exact failure the doublewrite buffer exists to prevent.
//!
//! ## The fix
//!
//! [`graphus_storage::dwb::DwbPageStager::stage_and_sync`] now runs the home write (and its durable
//! `sync_data`) **inside** the DWB-lock critical section: the buffer pool passes its real home write
//! (write the page + `sync_data` the home device) as the `home_write` callback, and the stager holds
//! the shared DWB mutex across both the staging fsync AND that callback. So the region's occupant
//! stays valid and discoverable by `recover_home` until that page's home write is durably complete.
//! Only then does the lock release, freeing the region for the next evictor — the InnoDB ordering
//! invariant (`specification/05-storage-format.md` §3): a doublewrite slot must not be reused until
//! the prior occupant's home write is durable.
//!
//! Both gates drive the **real** [`DwbPageStager`] over the **real** [`Dwb`] with a `home_write`
//! callback identical in structure to [`graphus_bufpool::ConcurrentBufferPool`]'s eviction path
//! (write the page home, then `sync_data` it durable) — i.e. they exercise exactly the code the fix
//! changed.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use graphus_bufpool::{PageStager, page};
use graphus_core::PageId;
use graphus_core::error::{GraphusError, Result};
use graphus_io::{BlockDevice, MemBlockDevice, PAGE_SIZE, Page};
use graphus_storage::dwb::{Dwb, DwbPageStager};

/// Builds a valid, checksummed page that self-identifies as `id` with `page_lsn` and a body fill.
fn make_page(id: u64, lsn: u64, fill: u8) -> Page {
    let mut p = [fill; PAGE_SIZE];
    page::set_page_id(&mut p, id);
    page::set_page_lsn(&mut p, graphus_core::Lsn(lsn));
    page::write_checksum(&mut p);
    p
}

/// A minimal in-memory `BlockDevice` whose durable bytes live behind a shared `Arc<Mutex<..>>`, so
/// the test can take a **crash snapshot** of the doublewrite area at the exact instant the home
/// write tears (modelling power loss). `sync_data` drains the cache into `durable`; a snapshot of
/// `durable` is the bytes that would survive a crash. Behaviourally identical to
/// [`MemBlockDevice`] for the operations the DWB uses (`read_page`/`write_page`/`sync_data`/
/// `page_count`/`extend`).
#[derive(Clone)]
struct SharedMemDevice {
    durable: Arc<Mutex<Vec<Page>>>,
    cache: Arc<Mutex<HashMap<u64, Page>>>,
}

impl SharedMemDevice {
    fn new(pages: u64) -> Self {
        Self {
            durable: Arc::new(Mutex::new(vec![[0u8; PAGE_SIZE]; pages as usize])),
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// A copy of the **durable** pages — the bytes that would survive a crash right now.
    fn durable_snapshot(&self) -> Vec<Page> {
        self.durable.lock().unwrap().clone()
    }
}

impl BlockDevice for SharedMemDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
        if let Some(p) = self.cache.lock().unwrap().get(&page.0) {
            *buf = *p;
            return Ok(());
        }
        let durable = self.durable.lock().unwrap();
        let idx = page.0 as usize;
        if idx >= durable.len() {
            return Err(GraphusError::Storage(format!("read oob: {}", page.0)));
        }
        *buf = durable[idx];
        Ok(())
    }

    fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
        self.cache.lock().unwrap().insert(page.0, *buf);
        Ok(())
    }

    fn sync_data(&mut self) -> Result<()> {
        let mut durable = self.durable.lock().unwrap();
        for (idx, p) in self.cache.lock().unwrap().drain() {
            if (idx as usize) < durable.len() {
                durable[idx as usize] = p;
            }
        }
        Ok(())
    }

    fn sync_all(&mut self) -> Result<()> {
        self.sync_data()
    }

    fn page_count(&self) -> u64 {
        self.durable.lock().unwrap().len() as u64
    }

    fn extend(&mut self, additional: u64) -> Result<()> {
        let mut durable = self.durable.lock().unwrap();
        let new_len = durable.len() + additional as usize;
        durable.resize(new_len, [0u8; PAGE_SIZE]);
        Ok(())
    }
}

/// Mirrors [`graphus_bufpool::ConcurrentBufferPool::write_back`]'s eviction home write: write the
/// page to its home location, then `sync_data` the home device so the page is durable before the
/// stager releases the DWB region. `home` is the shared home device (behind a `Mutex` so both
/// evictor threads can write through `&mut D`).
fn write_back_home(home: &Arc<Mutex<MemBlockDevice>>, page_id: PageId, image: &Page) -> Result<()> {
    let mut dev = home.lock().unwrap();
    dev.write_page(page_id, image)?;
    dev.sync_data()
}

/// Gate 1: two concurrent evictors stage pages A and B into the single-region DWB; the
/// EARLIER-staged page's home write tears (a power loss mid home write). After recovery the
/// earlier page MUST be repaired — its DWB copy must not have been overwritten by the later evictor
/// before its home write was durable.
///
/// Fails before the `rmp` #411 fix (`repaired == 0`: B overwrote the single region between A's stage
/// and A's home write, so A's copy is gone), passes after (the region stays A's until A's home write
/// returns, so A is repairable).
///
/// The interleaving is made deterministic with two signals: the later evictor (B) is held until the
/// earlier evictor (A) has STAGED (so A is the region's occupant first), and A's torn home write is
/// held open until B has *attempted* its stage (so the buggy code's overwrite is given every chance
/// to land in the window). Under the fix, B parks on the DWB mutex and cannot overwrite the region;
/// under the bug, B's stage overwrites it.
#[test]
fn concurrent_evictors_earlier_staged_torn_home_page_is_repaired() {
    const HOME_A: u64 = 3;
    const HOME_B: u64 = 5;

    // The DWB device is shared so the test can snapshot the region's durable bytes at the crash
    // instant (the moment A's home write tears) — modelling power loss while T1's eviction is
    // mid-home-write.
    let dwb_dev = SharedMemDevice::new(0);
    let dwb = Arc::new(Mutex::new(Dwb::new(dwb_dev.clone()).expect("dwb")));
    let stager: Arc<dyn PageStager> = Arc::new(DwbPageStager::new(Arc::clone(&dwb)));

    // The home device for A. A's home write produces a torn page (CRC fails) — the power loss.
    let home_a = Arc::new(Mutex::new(MemBlockDevice::new(8)));
    home_a.lock().unwrap().arm_torn_write(PageId(HOME_A), 16);
    let home_b = Arc::new(Mutex::new(MemBlockDevice::new(8)));

    let pa = make_page(HOME_A, 100, 0xA1);
    let pb = make_page(HOME_B, 200, 0xB2);

    // Signals + the crash snapshot of the DWB region's durable bytes, taken the instant A tears.
    let a_staged = Arc::new(AtomicBool::new(false));
    // Set by B INSIDE its home-write callback — i.e. only AFTER B's `stage_batch` has returned, which
    // means B has already overwritten the single region. This is the decisive signal: if T1 observes
    // it while A's home write is still in flight, the region was reused before A was durable (the bug).
    let b_overwrote_region = Arc::new(AtomicU64::new(0));
    let crash_dwb_snapshot: Arc<Mutex<Option<Vec<Page>>>> = Arc::new(Mutex::new(None));

    // Evictor T1: stage A, then tear A's home write. The torn write IS the power loss: at that exact
    // instant we snapshot the DWB region's durable bytes — the bytes recovery would see. We hold A's
    // home write open, giving B every chance to overwrite the region (the buggy code lets it; the fix
    // blocks it on the DWB mutex), then snapshot. A bounded wait keeps the FIXED build from hanging
    // (B can never overwrite under the fix, so the wait simply times out and A is still the occupant).
    let s1 = Arc::clone(&stager);
    let home1 = Arc::clone(&home_a);
    let a_staged1 = Arc::clone(&a_staged);
    let b_overwrote1 = Arc::clone(&b_overwrote_region);
    let dwb_dev1 = dwb_dev.clone();
    let snap1 = Arc::clone(&crash_dwb_snapshot);
    let t1 = std::thread::spawn(move || {
        let mut home_write = || -> Result<()> {
            a_staged1.store(true, Ordering::SeqCst);
            // Hold A's home write open, waiting (bounded) for B to overwrite the region.
            for _ in 0..200_000 {
                if b_overwrote1.load(Ordering::SeqCst) != 0 {
                    break;
                }
                std::thread::yield_now();
            }
            // Tear A's home write (write the torn prefix, sync) — the crash.
            write_back_home(&home1, PageId(HOME_A), &pa)?;
            // CRASH INSTANT: snapshot the DWB region's durable bytes. Under the fix, the DWB lock is
            // held by THIS thread across this callback, so B cannot have overwritten the region — the
            // snapshot still holds A's copy. Under the bug, B already restaged, overwriting it.
            *snap1.lock().unwrap() = Some(dwb_dev1.durable_snapshot());
            Ok(())
        };
        s1.stage_and_sync(PageId(HOME_A), &pa[..], &mut home_write)
            .expect("stage+home A");
    });

    // Let B race only after A is the region's occupant.
    for _ in 0..1_000_000 {
        if a_staged.load(Ordering::SeqCst) {
            break;
        }
        std::thread::yield_now();
    }

    // Evictor T2: stage B (races to reuse the single region) then write B home. B signals that it has
    // overwritten the region from INSIDE its home-write callback — which runs only after `stage_batch`
    // completed (the region is now B's).
    let s2 = Arc::clone(&stager);
    let home2 = Arc::clone(&home_b);
    let b_overwrote2 = Arc::clone(&b_overwrote_region);
    let t2 = std::thread::spawn(move || {
        let mut home_write = || -> Result<()> {
            b_overwrote2.store(1, Ordering::SeqCst);
            write_back_home(&home2, PageId(HOME_B), &pb)
        };
        s2.stage_and_sync(PageId(HOME_B), &pb[..], &mut home_write)
            .expect("stage+home B");
    });

    t1.join().unwrap();
    t2.join().unwrap();
    drop(stager);

    // Precondition: page A is torn on its home device.
    let mut a_disk: Page = [0u8; PAGE_SIZE];
    home_a
        .lock()
        .unwrap()
        .read_page(PageId(HOME_A), &mut a_disk)
        .expect("read A");
    assert!(
        !page::verify_checksum(&a_disk),
        "precondition: page A's home write must be torn on disk"
    );

    // Reconstruct the post-crash world: a DWB over the region snapshot taken AT the crash instant,
    // and A's torn home device. Recovery (run before redo) must repair A from the DWB.
    let snapshot = crash_dwb_snapshot
        .lock()
        .unwrap()
        .take()
        .expect("a crash snapshot of the DWB region must have been taken");
    let mut crashed_dwb_dev = SharedMemDevice::new(0);
    crashed_dwb_dev
        .extend(snapshot.len() as u64)
        .expect("size dwb");
    *crashed_dwb_dev.durable.lock().unwrap() = snapshot;
    let mut crashed_dwb = Dwb::new(crashed_dwb_dev).expect("crashed dwb");

    let mut home_dev = Arc::try_unwrap(home_a)
        .unwrap_or_else(|_| panic!("home device still shared"))
        .into_inner()
        .unwrap();
    let repaired = crashed_dwb
        .recover_home(&mut home_dev)
        .expect("recover_home");

    // THE GATE: A must be repairable. Before the fix, B overwrote the single region before the crash
    // snapshot, so A's copy is gone and `repaired == 0`, leaving A permanently torn.
    assert_eq!(
        repaired, 1,
        "torn home page A must be repaired from the DWB — the region must still hold A's copy until \
         A's home write was durable (rmp #411). repaired={repaired}"
    );
    let mut a_fixed: Page = [0u8; PAGE_SIZE];
    home_dev
        .read_page(PageId(HOME_A), &mut a_fixed)
        .expect("reread A");
    assert!(
        page::verify_checksum(&a_fixed),
        "home page A must be intact after doublewrite repair"
    );
    assert_eq!(
        &a_fixed[..],
        &pa[..],
        "repaired A must equal its staged DWB copy"
    );
}

/// Gate 2: a deterministic two-thread interleaving proving the earlier page's DWB region copy
/// survives until its home write returns. Thread T1 enters `stage_and_sync` for page A and its home
/// write blocks until B has *attempted* to stage; thread T2 calls `stage_and_sync` for page B. The
/// fix holds the DWB lock across T1's home write, so T2 CANNOT acquire the lock (and therefore cannot
/// overwrite the region) until T1's home write has returned. We observe that ordering directly:
/// A's home write completes strictly BEFORE B's home write begins.
///
/// (loom cannot model the block device's persistent bytes across a simulated crash, so this is the
/// stated deterministic two-thread alternative the gate spec permits: a controlled signal point
/// inside the home write makes the stage->home-write->restage interleaving observable.)
#[test]
fn staging_region_is_not_reused_until_the_home_write_is_durable() {
    // The DWB device is shared so the test can READ the region's current occupant directly while A's
    // home write is in flight — the decisive observation: the region must still describe A.
    let dwb_dev = SharedMemDevice::new(0);
    let dwb = Arc::new(Mutex::new(Dwb::new(dwb_dev.clone()).expect("dwb")));
    let stager: Arc<dyn PageStager> = Arc::new(DwbPageStager::new(Arc::clone(&dwb)));
    let home = Arc::new(Mutex::new(MemBlockDevice::new(8)));

    let a_home_in_flight = Arc::new(AtomicBool::new(false));
    // Set by B from INSIDE its home-write callback — i.e. only after B's `stage_batch` has overwritten
    // the single region. If T1 observes it while A's home write is still open, the region was reused
    // before A was durable (the bug).
    let b_overwrote_region = Arc::new(AtomicU64::new(0));
    // The region's occupant home-id list, sampled by T1 mid-A-home-write.
    let region_during_a: Arc<Mutex<Option<Vec<PageId>>>> = Arc::new(Mutex::new(None));

    let pa = make_page(3, 11, 0xA1);
    let pb = make_page(5, 22, 0xB2);

    let s1 = Arc::clone(&stager);
    let home1 = Arc::clone(&home);
    let inflight = Arc::clone(&a_home_in_flight);
    let b_over1 = Arc::clone(&b_overwrote_region);
    let dwb_dev1 = dwb_dev.clone();
    let region_sample = Arc::clone(&region_during_a);
    let t1 = std::thread::spawn(move || {
        let mut home_write = || -> Result<()> {
            inflight.store(true, Ordering::SeqCst);
            // Hold A's home write open, giving B every chance to overwrite the region. Under the fix,
            // B is parked on the DWB mutex (held by this thread), so it cannot overwrite — the wait
            // simply times out. Under the bug, B overwrites and sets the flag.
            for _ in 0..200_000 {
                if b_over1.load(Ordering::SeqCst) != 0 {
                    break;
                }
                std::thread::yield_now();
            }
            // SAMPLE the region's occupant while A's home write is still in flight (before it
            // completes/returns). The region MUST still describe A: its copy may not be evicted until
            // A's home write is durable.
            let mut hdr: Page = [0u8; PAGE_SIZE];
            dwb_dev1
                .read_page(PageId(0), &mut hdr)
                .expect("read dwb header");
            *region_sample.lock().unwrap() = Some(decode_region_homes(&hdr));
            write_back_home(&home1, PageId(3), &pa)
        };
        s1.stage_and_sync(PageId(3), &pa[..], &mut home_write)
            .expect("stage A");
    });

    // Wait for T1 to enter its home write, then launch B to race for the region.
    for _ in 0..1_000_000 {
        if a_home_in_flight.load(Ordering::SeqCst) {
            break;
        }
        std::thread::yield_now();
    }

    let s2 = Arc::clone(&stager);
    let home2 = Arc::clone(&home);
    let b_over2 = Arc::clone(&b_overwrote_region);
    let t2 = std::thread::spawn(move || {
        let mut home_write = || -> Result<()> {
            b_over2.store(1, Ordering::SeqCst); // region already overwritten by our stage_batch
            write_back_home(&home2, PageId(5), &pb)
        };
        s2.stage_and_sync(PageId(5), &pb[..], &mut home_write)
            .expect("stage B");
    });

    t1.join().unwrap();
    t2.join().unwrap();
    drop(stager);

    // THE GATE: while A's home write was in flight, the region must STILL have described page A — its
    // doublewrite copy may not be evicted (overwritten by B) until A's home write is durable. Before
    // the fix, B overwrote the region during A's window, so the sample shows page B (id 5).
    let sampled = region_during_a
        .lock()
        .unwrap()
        .take()
        .expect("a region sample must have been taken during A's home write");
    assert_eq!(
        sampled,
        vec![PageId(3)],
        "while page A's home write was in flight, the DWB region must still describe A (id 3) — a \
         region holding B (id 5) means it was reused before A was durable home (rmp #411). got \
         {sampled:?}"
    );

    // A is intact and durable on the home device, and the region's final occupant is B (handed over
    // only after A's home write returned).
    let mut a_disk: Page = [0u8; PAGE_SIZE];
    home.lock()
        .unwrap()
        .read_page(PageId(3), &mut a_disk)
        .expect("read A");
    assert!(
        page::verify_checksum(&a_disk),
        "page A must be intact and durable on the home device"
    );
    let dwb = Arc::try_unwrap(dwb)
        .unwrap_or_else(|_| panic!("dwb still shared"))
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(
        dwb.staged_home_ids().expect("staged ids"),
        vec![PageId(5)],
        "the region's final occupant is B (taken only after A was durable home)"
    );
}

/// Decodes the home-id list a DWB header page describes (the region's occupants), or an empty vec if
/// the header does not decode. Mirrors [`Dwb::staged_home_ids`] for a header page read directly from
/// the device — used by Gate 2 to sample the region's occupant mid-home-write without taking the DWB
/// mutex (which the staging thread holds).
fn decode_region_homes(hdr: &Page) -> Vec<PageId> {
    use graphus_bufpool::page as bp;
    const HDR_OFF_MAGIC: usize = bp::HEADER_SIZE;
    const HDR_OFF_COUNT: usize = HDR_OFF_MAGIC + 8;
    const HDR_OFF_HOMES: usize = HDR_OFF_COUNT + 8;
    const DWB_MAGIC: u64 = 0x0000_0001_4257_4447;
    if !bp::verify_checksum(hdr) {
        return Vec::new();
    }
    let magic = u64::from_le_bytes(hdr[HDR_OFF_MAGIC..HDR_OFF_MAGIC + 8].try_into().unwrap());
    if magic != DWB_MAGIC {
        return Vec::new();
    }
    let count =
        u64::from_le_bytes(hdr[HDR_OFF_COUNT..HDR_OFF_COUNT + 8].try_into().unwrap()) as usize;
    let mut homes = Vec::with_capacity(count.min(1024));
    let mut off = HDR_OFF_HOMES;
    for _ in 0..count {
        if off + 8 > PAGE_SIZE {
            break;
        }
        homes.push(PageId(u64::from_le_bytes(
            hdr[off..off + 8].try_into().unwrap(),
        )));
        off += 8;
    }
    homes
}
