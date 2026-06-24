//! **Concurrent device-read proof** for [`ConcurrentBufferPool`] (`rmp` task #362).
//!
//! Before #362 the pool held its device behind a `Mutex<D>` and performed every cache-**miss**
//! physical read (`load_into` → `device.read_page`) while holding that mutex. So N reader/morsel
//! workers that all miss the pool at once **serialised** on one lock — read scaling collapsed to ~1×
//! the instant the working set spilled the pool, capping exactly the parallelism that off-thread
//! reads (#336) and morsel parallelism (#339) were built to deliver. #362 moves the device behind a
//! `RwLock<D>` and takes a **read** guard for the `&self` `read_page`, so concurrent misses on
//! distinct frames read in parallel.
//!
//! This test proves the property **deterministically**, independent of timing or core count, and
//! doubles as a regression guard: a `Barrier`-gated device whose `read_page` will only return once
//! **all `READERS` readers are inside `read_page` simultaneously**. With concurrent reads (the #362
//! `RwLock` read guard) the barrier trips and every reader completes promptly; with the old
//! serialising `Mutex<D>` the first reader would block on the barrier *holding the device lock* while
//! the other `READERS - 1` can never enter `read_page` — a deadlock the watchdog turns into a clear
//! failure. The device also records the **maximum number of threads ever concurrently inside
//! `read_page`**, which this test asserts equals `READERS`: positive evidence the reads overlapped.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use graphus_bufpool::ConcurrentBufferPool;
use graphus_bufpool::page;
use graphus_core::PageId;
use graphus_core::error::Result;
use graphus_io::{BlockDevice, PAGE_SIZE, Page};

/// The fixed offset at which each page carries its own id (a witness the reader verifies, so an
/// overlapping read still has to return the *correct* page — proving the win does not corrupt).
const TAG_OFF: usize = 64;

fn read_word(p: &Page, off: usize) -> u64 {
    u64::from_le_bytes(p[off..off + 8].try_into().expect("8-byte word"))
}

fn write_word(p: &mut Page, off: usize, v: u64) {
    p[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// Cross-thread observability the test keeps a handle to **after** the device is moved into the
/// pool: the rendezvous barrier plus the live / high-water in-flight counters.
struct ReadObserver {
    /// Tripped only when all `READERS` readers are concurrently inside `read_page`.
    barrier: Barrier,
    /// Live count of threads currently inside `read_page`.
    in_flight: AtomicUsize,
    /// High-water mark of `in_flight` — the max overlap ever observed.
    max_in_flight: AtomicUsize,
}

impl ReadObserver {
    fn new(readers: usize) -> Arc<Self> {
        Arc::new(Self {
            barrier: Barrier::new(readers),
            in_flight: AtomicUsize::new(0),
            max_in_flight: AtomicUsize::new(0),
        })
    }

    fn max_overlap(&self) -> usize {
        self.max_in_flight.load(Ordering::Acquire)
    }
}

/// A `Send + Sync`, read-only in-memory device of `n` checksummed pages whose `read_page`
/// **rendezvouses on a barrier**: it returns only once `READERS` threads are simultaneously inside
/// it. This is what makes the test a *proof* of concurrency rather than a timing measurement — the
/// barrier is mathematically unsatisfiable if the pool serialises the reads.
struct BarrierDevice {
    pages: Vec<Page>,
    obs: Arc<ReadObserver>,
}

impl BarrierDevice {
    fn new(n: u64, obs: Arc<ReadObserver>) -> Self {
        let mut pages = Vec::with_capacity(n as usize);
        for i in 0..n {
            let mut p: Page = [0u8; PAGE_SIZE];
            page::set_page_id(&mut p, i);
            write_word(&mut p, TAG_OFF, i);
            page::write_checksum(&mut p);
            pages.push(p);
        }
        Self { pages, obs }
    }
}

impl BlockDevice for BarrierDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
        // Enter: bump the live count and publish a new high-water mark if this is the most overlap so
        // far (a lock-free monotonic max).
        let now = self.obs.in_flight.fetch_add(1, Ordering::AcqRel) + 1;
        let mut hw = self.obs.max_in_flight.load(Ordering::Acquire);
        while now > hw {
            match self.obs.max_in_flight.compare_exchange_weak(
                hw,
                now,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => hw = observed,
            }
        }
        // Rendezvous: this returns only once ALL `READERS` threads are here at the same time. Under a
        // serialising `Mutex<D>` only one thread can ever be here, so this never returns (the watchdog
        // fails the test); under the #362 `RwLock<D>` read guard all readers arrive and it trips.
        self.obs.barrier.wait();
        buf.copy_from_slice(&self.pages[page.0 as usize]);
        self.obs.in_flight.fetch_sub(1, Ordering::AcqRel);
        Ok(())
    }
    fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
        self.pages[page.0 as usize] = *buf;
        Ok(())
    }
    fn sync_data(&mut self) -> Result<()> {
        Ok(())
    }
    fn sync_all(&mut self) -> Result<()> {
        Ok(())
    }
    fn page_count(&self) -> u64 {
        self.pages.len() as u64
    }
    fn extend(&mut self, _additional: u64) -> Result<()> {
        Ok(())
    }
}

/// `READERS` threads each fetch a **distinct, non-resident** page at the same instant, so every fetch
/// takes the cache-**miss** path and calls `device.read_page` concurrently. The barrier device proves
/// they are all inside `read_page` simultaneously (the exact #362 win); the watchdog turns the
/// old-behaviour deadlock into a clear failure; and the per-page tag check proves each overlapping
/// read still returned the correct page's bytes.
#[test]
fn concurrent_cache_miss_reads_run_in_parallel_not_serialized() {
    const READERS: usize = 8;
    // The pool holds exactly one frame per reader, so all READERS pages are resident-able at once but
    // none is resident at the start: every reader misses and loads its own page into its own victim
    // frame (distinct frames ⇒ no frame-latch contention to serialise them — only the device lock
    // could, which is precisely what #362 makes shared-read).
    const POOL_FRAMES: usize = READERS;

    let obs = ReadObserver::new(READERS);
    let dev = BarrierDevice::new(READERS as u64, Arc::clone(&obs));
    let pool = ConcurrentBufferPool::new(dev, POOL_FRAMES).shared();

    // Gate all readers so they hit `fetch` together, maximising the simultaneity of the misses.
    let start = Arc::new(Barrier::new(READERS));
    // Witness collected by each reader: the page it asked for and the tag it observed.
    let observed: Arc<std::sync::Mutex<Vec<(u64, u64)>>> =
        Arc::new(std::sync::Mutex::new(Vec::with_capacity(READERS)));
    let done = Arc::new(AtomicUsize::new(0));

    let workers: Vec<_> = (0..READERS)
        .map(|r| {
            let pool = Arc::clone(&pool);
            let start = Arc::clone(&start);
            let observed = Arc::clone(&observed);
            let done = Arc::clone(&done);
            std::thread::spawn(move || {
                let id = r as u64;
                start.wait();
                let tag = pool
                    .with_page_fetched(PageId(id), |p| read_word(p, TAG_OFF))
                    .expect("fetch of a miss must succeed (no I/O error in this device)");
                observed.lock().unwrap().push((id, tag));
                done.fetch_add(1, Ordering::AcqRel);
            })
        })
        .collect();

    // Watchdog: if the reads were serialised (a regression to `Mutex<D>`), the barrier device
    // deadlocks — the first reader waits inside `read_page` for peers that can never enter. Poll for
    // completion with a generous bound; a healthy parallel run finishes in milliseconds.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while done.load(Ordering::Acquire) < READERS {
        assert!(
            std::time::Instant::now() < deadline,
            "concurrent cache-miss reads did NOT run in parallel: only {}/{READERS} readers reached \
             `read_page` together within the watchdog window, so the barrier never tripped — the \
             device reads are serialised (the pre-#362 `Mutex<D>` behaviour). The #362 `RwLock<D>` \
             read guard must let concurrent misses read in parallel.",
            done.load(Ordering::Acquire)
        );
        std::thread::sleep(Duration::from_millis(5));
    }

    for w in workers {
        w.join().expect("reader thread must not panic");
    }

    // Positive numeric evidence: at some instant **every** reader was inside `read_page` at once.
    // (The barrier already proved this by construction — it cannot trip with fewer — but the
    // high-water mark restates it as a concrete measured count for the record.)
    assert_eq!(
        obs.max_overlap(),
        READERS,
        "max concurrent threads inside read_page was {} (expected {READERS}): the cache-miss device \
         reads did not fully overlap",
        obs.max_overlap()
    );

    // Correctness under overlap: each reader saw exactly the page it requested.
    let got = observed.lock().unwrap();
    assert_eq!(got.len(), READERS, "every reader recorded its observation");
    for (requested, tag) in got.iter() {
        assert_eq!(
            requested, tag,
            "an overlapping cache-miss read returned the WRONG page's bytes: requested {requested}, \
             observed tag {tag} — the concurrency win must not corrupt the load path"
        );
    }
}
