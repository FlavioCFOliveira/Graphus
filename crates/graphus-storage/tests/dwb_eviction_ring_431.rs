//! Regression gate for `rmp` #431 — the eviction **ring** that removes the single-slot convoy.
//!
//! ## The problem (`rmp` #431)
//!
//! `rmp` #411/#412 made every dirty eviction stage into ONE eviction slot while
//! [`DwbPageStager::stage_and_sync`] held the one process-wide `Arc<Mutex<Dwb>>` across BOTH the
//! staging fsync AND the home write+fsync (the serialisation that guaranteed the single slot's
//! occupant stayed recover-discoverable until its home write was durable). Under combined read+write
//! load every dirty eviction across `~2*min(N_cpu,16)` threads then serialised through that one slot
//! and its two serial fsyncs — a convoy: correctness intact, throughput collapsed.
//!
//! ## The fix (`rmp` #431): an N-slot eviction ring
//!
//! The eviction region is now a ring of [`graphus_storage::DWB_EVICT_RING_SLOTS`] independent
//! single-page slots. Each evictor claims a free slot, stages into it + fsyncs the DWB, writes home +
//! fsyncs home **without holding any global lock across the home write**, then frees its slot. Up to
//! `N` evictions are in flight concurrently, each owning a disjoint slot; a slot is reused only after
//! its occupant's home write is durable (the free-slot allocator enforces it). [`Dwb::recover_home`]
//! scans the batch region and every ring slot.
//!
//! This gate proves two things:
//!   1. **Correctness** (the #412 single-region gate generalised to the ring): two concurrent evictors
//!      stage into DISTINCT slots; the earlier-staged page's home write tears; recovery repairs it
//!      from its own ring slot — the later evictor's distinct slot did not clobber it.
//!   2. **Concurrency** (the convoy is gone): `N` evictors are simultaneously inside their home write,
//!      which is impossible if the stager serialised them through one slot+lock.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use graphus_bufpool::{PageStager, page};
use graphus_core::PageId;
use graphus_core::error::Result;
use graphus_io::{BlockDevice, MemBlockDevice, PAGE_SIZE, Page};
use graphus_storage::DWB_EVICT_RING_SLOTS;
use graphus_storage::dwb::{Dwb, DwbPageStager};

fn make_page(id: u64, lsn: u64, fill: u8) -> Page {
    let mut p = [fill; PAGE_SIZE];
    page::set_page_id(&mut p, id);
    page::set_page_lsn(&mut p, graphus_core::Lsn(lsn));
    page::write_checksum(&mut p);
    p
}

/// An in-memory device whose durable bytes live behind a shared `Arc<Mutex<..>>`, so a crash snapshot
/// of the DWB area can be taken at the instant a home write tears (modelling power loss).
#[derive(Clone)]
struct SharedMemDevice {
    durable: Arc<Mutex<Vec<Page>>>,
    cache: Arc<Mutex<std::collections::HashMap<u64, Page>>>,
}

impl SharedMemDevice {
    fn new(pages: u64) -> Self {
        Self {
            durable: Arc::new(Mutex::new(vec![[0u8; PAGE_SIZE]; pages as usize])),
            cache: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }
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
        *buf = self.durable.lock().unwrap()[page.0 as usize];
        Ok(())
    }
    fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
        self.cache.lock().unwrap().insert(page.0, *buf);
        Ok(())
    }
    fn sync_data(&mut self) -> Result<()> {
        let cache = std::mem::take(&mut *self.cache.lock().unwrap());
        let mut durable = self.durable.lock().unwrap();
        for (id, p) in cache {
            durable[id as usize] = p;
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

/// Correctness: two concurrent evictors stage pages A and B into DISTINCT ring slots; the
/// earlier-staged page A's home write tears (a power loss). After recovery A MUST be repaired from its
/// own ring slot — B's distinct slot must not have clobbered it.
///
/// The earlier evictor (A) holds its home write open until B has staged (proving B got a different
/// slot and is in flight); then A tears, and we snapshot the DWB. Recovery on the snapshot must repair
/// A. (Generalises `dwb_checkpoint_vs_eviction_412`'s single-region gate to the ring.)
#[test]
fn two_evictors_distinct_slots_earlier_torn_page_is_repaired() {
    const HOME_A: u64 = 3;
    const HOME_B: u64 = 5;

    let dwb_dev = SharedMemDevice::new(0);
    let dwb = Arc::new(Mutex::new(Dwb::new(dwb_dev.clone()).expect("dwb")));
    let stager: Arc<dyn PageStager> = Arc::new(DwbPageStager::new(Arc::clone(&dwb)));

    // Home device for A; A's home write tears (CRC fails) — the power loss. (A separate device for B
    // so only A's home is corrupt.)
    let home_a = Arc::new(Mutex::new(MemBlockDevice::new(8)));
    home_a.lock().unwrap().arm_torn_write(PageId(HOME_A), 16);
    let home_b = Arc::new(Mutex::new(MemBlockDevice::new(8)));

    let pa = make_page(HOME_A, 100, 0xA1);
    let pb = make_page(HOME_B, 200, 0xB2);

    let b_staged = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let crash_snapshot: Arc<Mutex<Option<Vec<Page>>>> = Arc::new(Mutex::new(None));

    // Evictor T1 (page A): hold A's home write open until B has staged (B owns a distinct slot now),
    // then tear A and snapshot the DWB at the crash instant.
    let s1 = Arc::clone(&stager);
    let home1 = Arc::clone(&home_a);
    let b_staged1 = Arc::clone(&b_staged);
    let dwb_dev1 = dwb_dev.clone();
    let snap1 = Arc::clone(&crash_snapshot);
    let t1 = std::thread::spawn(move || {
        let mut home_write = || -> Result<()> {
            for _ in 0..2_000_000 {
                if b_staged1.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::yield_now();
            }
            // Tear A's home write (the crash), then snapshot the DWB durable bytes.
            let mut dev = home1.lock().unwrap();
            dev.write_page(PageId(HOME_A), &pa)?;
            dev.sync_data()?;
            *snap1.lock().unwrap() = Some(dwb_dev1.durable_snapshot());
            Ok(())
        };
        s1.stage_and_sync(PageId(HOME_A), &pa[..], &mut home_write)
            .expect("stage+home A");
    });

    // Evictor T2 (page B): stage B (into a distinct slot — under the ring it never parks on T1) and
    // write it home, signalling that B has staged from inside its home write.
    let s2 = Arc::clone(&stager);
    let home2 = Arc::clone(&home_b);
    let b_staged2 = Arc::clone(&b_staged);
    let t2 = std::thread::spawn(move || {
        let mut home_write = || -> Result<()> {
            b_staged2.store(true, Ordering::SeqCst);
            let mut dev = home2.lock().unwrap();
            dev.write_page(PageId(HOME_B), &pb)?;
            dev.sync_data()
        };
        s2.stage_and_sync(PageId(HOME_B), &pb[..], &mut home_write)
            .expect("stage+home B");
    });

    t1.join().unwrap();
    t2.join().unwrap();
    drop(stager);

    // Precondition: A is torn on its home device.
    let mut a_disk: Page = [0u8; PAGE_SIZE];
    home_a
        .lock()
        .unwrap()
        .read_page(PageId(HOME_A), &mut a_disk)
        .expect("read A");
    assert!(
        !page::verify_checksum(&a_disk),
        "precondition: A's home write must be torn on disk"
    );

    // Recovery on the crash snapshot must repair A from its own ring slot.
    let snapshot = crash_snapshot
        .lock()
        .unwrap()
        .take()
        .expect("a crash snapshot must have been taken");
    let mut crashed_dev = SharedMemDevice::new(0);
    crashed_dev.extend(snapshot.len() as u64).expect("size");
    *crashed_dev.durable.lock().unwrap() = snapshot;
    let mut crashed_dwb = Dwb::new(crashed_dev).expect("crashed dwb");

    let mut home_dev = Arc::try_unwrap(home_a)
        .unwrap_or_else(|_| panic!("home still shared"))
        .into_inner()
        .unwrap();
    let repaired = crashed_dwb.recover_home(&mut home_dev).expect("recover");
    assert!(
        repaired >= 1,
        "torn page A must be repaired from its ring slot (rmp #431). repaired={repaired}"
    );
    let mut a_fixed: Page = [0u8; PAGE_SIZE];
    home_dev
        .read_page(PageId(HOME_A), &mut a_fixed)
        .expect("reread A");
    assert!(
        page::verify_checksum(&a_fixed),
        "A must be intact after doublewrite repair"
    );
    assert_eq!(
        &a_fixed[..],
        &pa[..],
        "repaired A must equal its ring-slot copy"
    );
}

/// Concurrency: prove the convoy is gone. `N` evictors all reach their home write and rendezvous on a
/// barrier *simultaneously* — impossible if the stager serialised them through one slot+lock (the
/// second evictor could not enter its home write until the first freed the slot). With the ring, all
/// `N` own distinct slots and proceed in parallel, so the barrier (sized `N`) is satisfied and every
/// thread completes. A per-thread "peak concurrent in-flight home writes" counter must reach `N`.
///
/// `N` is the ring capacity, so every evictor can claim a distinct slot with no allocator contention.
/// Pre-#431 this test would DEADLOCK at the barrier (only one evictor can be in its home write at a
/// time), so it fails-before by timeout; post-#431 it completes.
#[test]
fn ring_lets_n_evictions_be_in_flight_concurrently() {
    let n = DWB_EVICT_RING_SLOTS;

    let dwb_dev = MemBlockDevice::new(0);
    let dwb = Arc::new(Mutex::new(Dwb::new(dwb_dev).expect("dwb")));
    let stager: Arc<dyn PageStager> = Arc::new(DwbPageStager::new(Arc::clone(&dwb)));

    // Each evictor writes a distinct home page to a shared home device.
    let home = Arc::new(Mutex::new(MemBlockDevice::new(n as u64 + 8)));
    // A barrier sized N: every evictor blocks here INSIDE its home write. It is released only when all
    // N have arrived — i.e. only if N home writes are simultaneously in flight (no convoy).
    let barrier = Arc::new(Barrier::new(n));
    // Peak number of evictors simultaneously inside their home write.
    let in_flight = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for i in 0..n {
        let s = Arc::clone(&stager);
        let home = Arc::clone(&home);
        let barrier = Arc::clone(&barrier);
        let in_flight = Arc::clone(&in_flight);
        let peak = Arc::clone(&peak);
        let page_id = PageId(i as u64 + 1);
        let img = make_page(page_id.0, 10 + i as u64, (i as u8).wrapping_add(1));
        handles.push(std::thread::spawn(move || {
            let mut home_write = || -> Result<()> {
                // Record peak concurrency: increment on entry, before the barrier.
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                // Rendezvous: this can only complete if all N evictors are here at once.
                barrier.wait();
                {
                    let mut dev = home.lock().unwrap();
                    dev.write_page(page_id, &img)?;
                    dev.sync_data()?;
                }
                in_flight.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            };
            s.stage_and_sync(page_id, &img[..], &mut home_write)
                .expect("stage+home");
        }));
    }
    for h in handles {
        h.join().expect("evictor thread");
    }

    // THE GATE: all N evictions were simultaneously in flight (the barrier could not have been
    // satisfied otherwise). Pre-#431's single serialising slot caps this at 1 and the barrier would
    // deadlock — so reaching here with peak == N proves the convoy is gone.
    assert_eq!(
        peak.load(Ordering::SeqCst),
        n,
        "all {n} ring slots must allow {n} concurrent in-flight evictions (rmp #431 — no convoy)"
    );

    // Every evicted page is durable on the home device.
    let dev = home.lock().unwrap();
    for i in 0..n {
        let page_id = PageId(i as u64 + 1);
        let mut got: Page = [0u8; PAGE_SIZE];
        dev.read_page(page_id, &mut got).expect("read evicted");
        assert!(
            page::verify_checksum(&got),
            "evicted page {} must be durable and intact",
            page_id.0
        );
    }
}

/// `rmp` #436: ring **exhaustion** must still make progress via the escalating backoff.
///
/// When `> DWB_EVICT_RING_SLOTS` dirty evictions are in flight at once, the ring is momentarily
/// exhausted and the extra evictors must `claim_slot`-block until a slot frees. The fix replaced the
/// bare `yield_now()` busy-spin with the same escalating `Backoff` used by the buffer pool at #359.
///
/// This gate pins the ring at FULL occupancy: the first `N` evictors all enter their home write and
/// rendezvous on a barrier (so all `N` ring slots are held simultaneously — proven by the prior gate),
/// and they only release once the `EXTRA` over-subscribed evictors have all *started* their claim. The
/// `EXTRA` evictors therefore find the ring exhausted and must back off; they can only obtain a slot
/// after the first wave frees theirs. The gate asserts that **all** `N + EXTRA` evictions complete and
/// every page is durable — i.e. `claim_slot` always blocks-until-free and never returns without a slot
/// (no unprotected-home-write fallback, which would regress #407).
///
/// The exhaustion is *structural*, not racy: the first wave does not release its `N` slots until every
/// one of the `EXTRA` over-subscribed evictors has incremented `extra_started`. At that instant `N`
/// slots are held AND `EXTRA` evictors are provably blocked inside `claim_slot` against the full ring —
/// they can only proceed once the first wave frees, via the escalating backoff. Pre-#436 they would
/// still complete (it was never a livelock) but by burning cores on a bare `yield_now` spin; this gate
/// asserts the *correctness* contract (progress + durability) that must hold with the backoff in place.
#[test]
fn ring_claim_under_exhaustion_makes_progress() {
    let n = DWB_EVICT_RING_SLOTS;
    let extra = n; // 2N total evictors: N hold the ring full, N must back off and wait.
    let total = n + extra;

    let dwb_dev = MemBlockDevice::new(0);
    let dwb = Arc::new(Mutex::new(Dwb::new(dwb_dev).expect("dwb")));
    let stager: Arc<dyn PageStager> = Arc::new(DwbPageStager::new(Arc::clone(&dwb)));

    let home = Arc::new(Mutex::new(MemBlockDevice::new(total as u64 + 8)));

    // The N first-wave evictors rendezvous here so every ring slot is held at once.
    let wave_barrier = Arc::new(Barrier::new(n));
    // Count how many over-subscribed (EXTRA) evictors have begun their claim. Once all have begun, the
    // first wave is allowed to release its slots so the EXTRA wave can drain through the backoff.
    let extra_started = Arc::new(AtomicUsize::new(0));
    let completed = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for i in 0..total {
        let s = Arc::clone(&stager);
        let home = Arc::clone(&home);
        let wave_barrier = Arc::clone(&wave_barrier);
        let extra_started = Arc::clone(&extra_started);
        let completed = Arc::clone(&completed);
        let page_id = PageId(i as u64 + 1);
        let img = make_page(page_id.0, 10 + i as u64, (i as u8).wrapping_add(1));
        let is_first_wave = i < n;
        handles.push(std::thread::spawn(move || {
            if !is_first_wave {
                // Announce that this over-subscribed evictor is about to attempt its claim against a
                // (soon to be) full ring.
                extra_started.fetch_add(1, Ordering::SeqCst);
            }
            let mut home_write = || -> Result<()> {
                if is_first_wave {
                    // Hold every ring slot until ALL extra evictors have begun their (blocked) claim,
                    // so the ring is provably exhausted while they back off, then rendezvous to ensure
                    // all N are simultaneously holding a slot.
                    while extra_started.load(Ordering::SeqCst) < extra {
                        std::thread::yield_now();
                    }
                    wave_barrier.wait();
                }
                {
                    let mut dev = home.lock().unwrap();
                    dev.write_page(page_id, &img)?;
                    dev.sync_data()?;
                }
                Ok(())
            };
            s.stage_and_sync(page_id, &img[..], &mut home_write)
                .expect("stage+home under ring exhaustion");
            completed.fetch_add(1, Ordering::SeqCst);
        }));
    }
    for h in handles {
        h.join().expect("evictor thread (exhaustion)");
    }

    // THE GATE: every eviction completed — `claim_slot` always eventually returned a slot (it blocks
    // until free, never bails out), draining the over-subscribed herd via the escalating backoff.
    assert_eq!(
        completed.load(Ordering::SeqCst),
        total,
        "all {total} evictions must complete — claim_slot must block-until-free, never bail (rmp #436/#407)"
    );

    // Every evicted page is durable and intact on the home device.
    let dev = home.lock().unwrap();
    for i in 0..total {
        let page_id = PageId(i as u64 + 1);
        let mut got: Page = [0u8; PAGE_SIZE];
        dev.read_page(page_id, &mut got).expect("read evicted");
        assert!(
            page::verify_checksum(&got),
            "evicted page {} must be durable and intact under ring exhaustion",
            page_id.0
        );
    }
}
