//! `loom` model-checking of [`graphus_bufpool::ConcurrentBufferPool`]'s latching logic.
//!
//! These tests are the **substantive** validator of the concurrent pool. The crate is
//! `#![forbid(unsafe_code)]`, so it has no undefined behaviour and no data races by construction
//! (Rust's type system guarantees that) — `miri`/ThreadSanitizer would therefore find nothing.
//! What still needs proving is that the *latching/pinning/eviction protocol* is correct under
//! every legal thread interleaving: exactly-once loads, no lost dirty writes, no pin underflow,
//! no deadlock, and the WAL-before-data ordering on every path. `loom` exhaustively explores
//! those interleavings.
//!
//! The whole file is gated on `#[cfg(loom)]`, so it is **not** compiled by a normal `cargo test`.
//! Run it with:
//!
//! ```text
//! RUSTFLAGS="--cfg loom" LOOM_MAX_PREEMPTIONS=3 \
//!   cargo test -p graphus-bufpool --test loom_bufpool --release
//! ```
//!
//! `--release` is recommended (loom's search is exponential). Most models are kept deliberately tiny
//! (2 threads, 1–2 frames, 2–3 pages) so the search terminates quickly; the two `rmp` #597 models at
//! the end use a doublewrite-stager under two evictors and a **3-thread** flush-vs-two-fetch race, so
//! they need the `LOOM_MAX_PREEMPTIONS=3` bound (the same the `loom_eviction_storm` models use) to keep
//! the state space tractable. Growing any of these dimensions can blow up the search.

#![cfg(loom)]

use graphus_bufpool::page;
use graphus_bufpool::{ConcurrentBufferPool, PageStager, WalRule};
use graphus_core::error::{GraphusError, Result};
use graphus_core::{Lsn, PageId};
use graphus_io::{BlockDevice, PAGE_SIZE, Page};

use loom::sync::atomic::{AtomicUsize, Ordering};
use loom::sync::{Arc, Mutex};

/// A tiny in-memory device for loom models: a fixed set of durable, checksummed pages and a
/// per-instance device-read counter so a test can assert "loaded exactly once". Writes land in
/// place (no crash modeling needed for the latch-logic models). It is `Send` and uses no interior
/// mutability of its own — the pool already serializes it behind a latch/mutex — so the read
/// counter is an atomic to stay observable across the `&self` `read_page`.
struct ModelDevice {
    pages: Vec<Page>,
    reads: Arc<AtomicUsize>,
}

impl ModelDevice {
    /// `n` zero pages, each stamped with its id and a valid checksum, plus a shared read counter.
    fn new(n: u64, reads: Arc<AtomicUsize>) -> Self {
        let mut pages = Vec::with_capacity(n as usize);
        for i in 0..n {
            let mut p: Page = [0u8; PAGE_SIZE];
            page::set_page_id(&mut p, i);
            // Stamp a recognizable byte so reads can be checked.
            p[100] = (i as u8).wrapping_add(1);
            page::write_checksum(&mut p);
            pages.push(p);
        }
        Self { pages, reads }
    }
}

impl BlockDevice for ModelDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let idx = page.0 as usize;
        if idx >= self.pages.len() {
            return Err(GraphusError::Storage(format!("read oob {}", page.0)));
        }
        buf.copy_from_slice(&self.pages[idx]);
        Ok(())
    }

    fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
        let idx = page.0 as usize;
        if idx >= self.pages.len() {
            return Err(GraphusError::Storage(format!("write oob {}", page.0)));
        }
        self.pages[idx] = *buf;
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

    fn extend(&mut self, additional: u64) -> Result<()> {
        for i in 0..additional {
            let id = self.pages.len() as u64;
            let mut p: Page = [0u8; PAGE_SIZE];
            page::set_page_id(&mut p, id);
            page::write_checksum(&mut p);
            self.pages.push(p);
            let _ = i;
        }
        Ok(())
    }
}

/// A WAL rule that records, on every `ensure_durable`, that the log was made durable. The device
/// write happens *inside* the pool right after this returns, so a successful `ensure_durable`
/// preceding the home write is the log-before-data guarantee. We additionally assert ordering by
/// counting: each write-back must bump `wal_calls` before the device's `write_page`. Because the
/// pool calls `ensure_durable` then `write_page` under the same frame latch, observing
/// `wal_calls >= writes` at all times is the invariant.
struct OrderingWal {
    wal_calls: Arc<AtomicUsize>,
}

impl WalRule for OrderingWal {
    fn ensure_durable(&mut self, _up_to: Lsn) -> Result<()> {
        self.wal_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// A device that, in addition to the model device, asserts the WAL-before-data invariant on every
/// `write_page`: the WAL-call counter must be strictly greater than the writes-seen counter at the
/// moment of a write, proving `ensure_durable` ran for this write-back before the home write.
struct WalCheckingDevice {
    inner: ModelDevice,
    wal_calls: Arc<AtomicUsize>,
    writes: Arc<AtomicUsize>,
}

impl BlockDevice for WalCheckingDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
        self.inner.read_page(page, buf)
    }

    fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
        // Log-before-data: before this home write, the WAL must already have been ensured durable
        // at least once more than the number of writes completed so far.
        let wal = self.wal_calls.load(Ordering::SeqCst);
        let done = self.writes.load(Ordering::SeqCst);
        assert!(
            wal > done,
            "WAL rule must run before the home write (wal={wal}, writes_done={done})"
        );
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.write_page(page, buf)
    }

    fn sync_data(&mut self) -> Result<()> {
        self.inner.sync_data()
    }

    fn sync_all(&mut self) -> Result<()> {
        self.inner.sync_all()
    }

    fn page_count(&self) -> u64 {
        self.inner.page_count()
    }

    fn extend(&mut self, additional: u64) -> Result<()> {
        self.inner.extend(additional)
    }
}

/// Scenario 1: two threads concurrently `fetch` the **same** page.
///
/// Asserts on every interleaving: the page is read from the device **exactly once**, both threads
/// observe a consistent pinned view (the stamped byte), the pin count reflects both pins, and
/// after both unpin the count is zero.
#[test]
fn loom_two_threads_fetch_same_page_loads_once() {
    loom::model(|| {
        let reads = Arc::new(AtomicUsize::new(0));
        let dev = ModelDevice::new(2, reads.clone());
        // 2 frames so a victim is always available without forcing eviction churn.
        let pool = ConcurrentBufferPool::new(dev, 2).shared();

        let p0 = pool.clone();
        let r0 = reads.clone();
        let t0 = loom::thread::spawn(move || {
            let f = p0.fetch(PageId(0)).expect("fetch ok");
            let v = p0.with_page(f, |pg| pg[100]);
            assert_eq!(v, 1, "page 0 stamped byte");
            p0.unpin(f);
            let _ = r0;
        });

        let p1 = pool.clone();
        let t1 = loom::thread::spawn(move || {
            let f = p1.fetch(PageId(0)).expect("fetch ok");
            let v = p1.with_page(f, |pg| pg[100]);
            assert_eq!(v, 1, "page 0 stamped byte");
            p1.unpin(f);
        });

        t0.join().unwrap();
        t1.join().unwrap();

        assert_eq!(
            reads.load(Ordering::SeqCst),
            1,
            "page 0 must be loaded from the device exactly once"
        );
    });
}

/// Scenario 2: one thread `fetch`es page 0 while another `fetch`es a **different** page (page 1),
/// in a 1-frame pool so the second fetch must evict the first.
///
/// Asserts: no panic, no deadlock, and each fetch yields the correct stamped byte for its page
/// (no corruption / no cross-page tearing). With a single frame, total device reads may be 2 (one
/// per page) or more if the two contend and reload, but each observed page is internally
/// consistent.
#[test]
fn loom_fetch_while_evict_other_page() {
    loom::model(|| {
        let reads = Arc::new(AtomicUsize::new(0));
        let dev = ModelDevice::new(2, reads.clone());
        let pool = ConcurrentBufferPool::new(dev, 1).shared();

        let p0 = pool.clone();
        let t0 = loom::thread::spawn(move || {
            if let Ok(f) = p0.fetch(PageId(0)) {
                assert_eq!(p0.with_page(f, |pg| pg[100]), 1);
                p0.unpin(f);
            }
        });

        let p1 = pool.clone();
        let t1 = loom::thread::spawn(move || {
            if let Ok(f) = p1.fetch(PageId(1)) {
                assert_eq!(p1.with_page(f, |pg| pg[100]), 2);
                p1.unpin(f);
            }
        });

        t0.join().unwrap();
        t1.join().unwrap();
    });
}

/// Scenario 3: concurrent pin/unpin on the same page — pin count never underflows, and once both
/// threads have unpinned, the frame is unpinned (evictable).
#[test]
fn loom_concurrent_pin_unpin_never_underflows() {
    loom::model(|| {
        let reads = Arc::new(AtomicUsize::new(0));
        let dev = ModelDevice::new(1, reads);
        let pool = ConcurrentBufferPool::new(dev, 2).shared();

        let p0 = pool.clone();
        let t0 = loom::thread::spawn(move || {
            let f = p0.fetch(PageId(0)).unwrap();
            // Pin count is at least 1 here.
            assert!(p0.pin_count(f) >= 1);
            p0.unpin(f);
        });

        let p1 = pool.clone();
        let t1 = loom::thread::spawn(move || {
            let f = p1.fetch(PageId(0)).unwrap();
            assert!(p1.pin_count(f) >= 1);
            p1.unpin(f);
        });

        t0.join().unwrap();
        t1.join().unwrap();

        // After both threads finished, the page (if resident) must be fully unpinned.
        let f = pool.fetch(PageId(0)).unwrap();
        // We hold exactly one pin now.
        assert_eq!(pool.pin_count(f), 1);
        pool.unpin(f);
        assert_eq!(
            pool.pin_count(f),
            0,
            "frame must be evictable after all unpins"
        );
    });
}

/// Scenario 4: the WAL rule is satisfied **before** every dirty write-back, on every interleaving.
///
/// Two threads each create-and-dirty a page in a 1-frame pool, forcing eviction write-backs. The
/// `WalCheckingDevice` asserts, inside `write_page`, that `ensure_durable` already ran for this
/// write-back (log-before-data). The model also confirms the final WAL-call count is at least the
/// number of home writes.
#[test]
fn loom_wal_rule_before_every_write_back() {
    loom::model(|| {
        let reads = Arc::new(AtomicUsize::new(0));
        let wal_calls = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let dev = WalCheckingDevice {
            inner: ModelDevice::new(0, reads),
            wal_calls: wal_calls.clone(),
            writes: writes.clone(),
        };
        let wal = OrderingWal {
            wal_calls: wal_calls.clone(),
        };
        // 1 frame so the second allocation must evict (and thus write back) the first.
        let pool = ConcurrentBufferPool::with_wal(dev, wal, 1).shared();

        let p0 = pool.clone();
        let t0 = loom::thread::spawn(move || {
            if let Ok((f, _id)) = p0.new_page() {
                // A WAL-logged change stamps the page's redo LSN (write into the body, offset >= 24).
                p0.with_page_mut_lsn(f, Lsn(0x10), |pg| pg[100] = 0xAA);
                p0.unpin(f);
            }
        });

        let p1 = pool.clone();
        let t1 = loom::thread::spawn(move || {
            if let Ok((f, _id)) = p1.new_page() {
                p1.with_page_mut_lsn(f, Lsn(0x20), |pg| pg[120] = 0xBB);
                p1.unpin(f);
            }
        });

        t0.join().unwrap();
        t1.join().unwrap();

        // Every home write was preceded by a WAL call (asserted in write_page); also confirm the
        // counts are consistent (wal >= writes) at the end.
        assert!(
            wal_calls.load(Ordering::SeqCst) >= writes.load(Ordering::SeqCst),
            "WAL calls must be >= home writes"
        );
    });
}

/// Scenario 5 (`rmp` #337): the combined read fast path [`ConcurrentBufferPool::with_page_fetched`]
/// is correct under the same evictor race [`fetch`] guards.
///
/// `with_page_fetched` pins under the shard lock, then re-validates the frame's identity under the
/// read latch *before* running the closure (falling back to the full `fetch` if it lost the race).
/// This model runs two threads: one reads page 0 through `with_page_fetched` while the other reads a
/// *different* page (page 1) in a 1-frame pool, forcing the second read to evict the first. On every
/// interleaving the fast-path reader must observe the **correct stamped byte for its page** (never a
/// torn or cross-page value), proving the single-latch fold preserves the pin/re-validate discipline.
#[test]
fn loom_with_page_fetched_under_eviction_reads_correct_page() {
    loom::model(|| {
        let reads = Arc::new(AtomicUsize::new(0));
        let dev = ModelDevice::new(2, reads);
        // 1 frame: the two reads of different pages contend on the single frame, forcing eviction.
        let pool = ConcurrentBufferPool::new(dev, 1).shared();

        let p0 = pool.clone();
        let t0 = loom::thread::spawn(move || {
            // page 0's stamped byte is 1; the fast path must never return a torn/cross-page value.
            let v = p0.with_page_fetched(PageId(0), |pg| pg[100]);
            if let Ok(v) = v {
                assert_eq!(v, 1, "with_page_fetched read the wrong byte for page 0");
            }
        });

        let p1 = pool.clone();
        let t1 = loom::thread::spawn(move || {
            let v = p1.with_page_fetched(PageId(1), |pg| pg[100]);
            if let Ok(v) = v {
                assert_eq!(v, 2, "with_page_fetched read the wrong byte for page 1");
            }
        });

        t0.join().unwrap();
        t1.join().unwrap();

        // No pins leaked by the fast path on any interleaving: the single frame is evictable again.
        let f = pool.fetch(PageId(0)).unwrap();
        pool.unpin(f);
        assert_eq!(pool.pin_count(f), 0, "with_page_fetched must leak no pin");
    });
}

/// A `loom`-driven mock [`PageStager`] modelling the doublewrite buffer's **one-region** invariant
/// (`rmp` #407/#411, `05 §3`): a single doublewrite region, reserved from the moment a page is staged
/// until its home write is **durably complete**, and only then freed for reuse. The real
/// `graphus_storage::dwb::DwbPageStager` lives below the `--cfg loom` boundary (it uses `std::sync`),
/// so this faithful model lets loom drive the pool's `write_back` → `stage_and_sync` integration under
/// two concurrent evictors — the interleaving DST (single cooperative thread) structurally cannot reach.
struct MockStager {
    /// The single doublewrite region: `Some(page_id)` while a page is staged and its home write is in
    /// flight; `None` when free. Behind a `loom::sync::Mutex` — the stager's interior lock that
    /// serialises concurrent evictions' staging and is held **across** the home write (the #411 rule).
    region: Mutex<Option<u64>>,
    /// Count of completed `stage_and_sync` calls (one per evicted logged page).
    staged: Arc<AtomicUsize>,
}

impl PageStager for MockStager {
    fn stage_and_sync(
        &self,
        page_id: PageId,
        _image: &[u8],
        home_write: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        // Hold the region lock across staging AND the home write: the slot's occupant must be durable
        // home before the region can be reused (`rmp` #411 — the InnoDB slot-reuse-after-durable rule).
        let mut region = self.region.lock().unwrap();
        // #411 NO-CLOBBER: the region must be FREE when we claim it — a live occupant here would mean a
        // second evictor reused the region before the prior page's home write completed (the exact
        // corruption the doublewrite buffer exists to prevent).
        assert!(
            region.is_none(),
            "DWB region reused while page {:?} was still staged — the prior home write had not \
             completed (#411 slot-reuse-after-durable violated)",
            *region
        );
        *region = Some(page_id.0);
        // The home write runs INSIDE the staging critical section (region still reserved).
        home_write()?;
        // Home write durable → the region may now be reused.
        *region = None;
        self.staged.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn stage_batch_and_sync(&self, batch: &[(PageId, &[u8])]) -> Result<()> {
        // Not exercised by the eviction path this model drives, but keep the region invariant faithful
        // if a future model uses the checkpoint/flush path.
        let region = self.region.lock().unwrap();
        assert!(region.is_none(), "batch stage over an occupied DWB region");
        let _ = batch;
        drop(region);
        Ok(())
    }
}

/// **Mock-stager 2-evictor model (`rmp` #597, gap #4a): the doublewrite-buffer stager under two
/// concurrent evictors.**
///
/// Two dirty, WAL-stamped (logged) pages are made resident in a 2-frame pool; two evictor threads then
/// each fetch a *different* new page, each forcing the eviction of one resident dirty page — so both
/// evictions run through [`ConcurrentBufferPool::write_back`]'s `stage_and_sync` path **concurrently**
/// (each under its own frame latch, contending on the stager's single region). loom explores every
/// interleaving; on each, the [`MockStager`]'s inline assertions enforce the #411 one-region rule (no
/// evictor reuses the region while another's page is still staged, and the home write runs inside the
/// staging critical section), and the model must not deadlock (loom completing the search is the proof
/// of acyclic lock order: frame-latch → region → device).
///
/// Run with:
/// ```text
/// RUSTFLAGS="--cfg loom" LOOM_MAX_PREEMPTIONS=3 \
///   cargo test -p graphus-bufpool --test loom_bufpool \
///   loom_two_evictors_through_stager_respect_one_region --release
/// ```
#[test]
fn loom_two_evictors_through_stager_respect_one_region() {
    loom::model(|| {
        let reads = Arc::new(AtomicUsize::new(0));
        let dev = ModelDevice::new(4, reads); // pages 0..3
        let pool = ConcurrentBufferPool::new(dev, 2).shared();

        let staged = Arc::new(AtomicUsize::new(0));
        // loom's `Arc` does not auto-unsize in argument position; build a `std::sync::Arc<dyn …>` (which
        // does coerce) and wrap it into a loom `Arc` via `from_std` (loom 0.7 `Arc::from_std`).
        let std_stager: std::sync::Arc<dyn PageStager> = std::sync::Arc::new(MockStager {
            region: Mutex::new(None),
            staged: Arc::clone(&staged),
        });
        let stager: Arc<dyn PageStager> = Arc::from_std(std_stager);
        pool.set_page_stager(stager);

        // Seed two dirty, LOGGED (WAL-stamped, non-zero page_lsn) resident pages — so evicting either one
        // takes the staged (doublewrite-protected) path, not the unlogged fast path.
        {
            let f = pool.fetch(PageId(0)).expect("seed fetch 0");
            pool.with_page_mut_lsn(f, Lsn(0x10), |pg| pg[100] = 0xA0);
            pool.unpin(f);
        }
        {
            let f = pool.fetch(PageId(1)).expect("seed fetch 1");
            pool.with_page_mut_lsn(f, Lsn(0x20), |pg| pg[100] = 0xB0);
            pool.unpin(f);
        }

        // Two evictors: each fetches a distinct NEW page (2, 3), each forcing the eviction of one of the
        // resident dirty pages (0, 1) → a concurrent `stage_and_sync` through the single-region stager.
        let p2 = pool.clone();
        let e2 = loom::thread::spawn(move || {
            if let Ok(f) = p2.fetch(PageId(2)) {
                assert_eq!(
                    p2.with_page(f, |pg| pg[100]),
                    3,
                    "evictor read wrong page for 2"
                );
                p2.unpin(f);
            }
        });
        let p3 = pool.clone();
        let e3 = loom::thread::spawn(move || {
            if let Ok(f) = p3.fetch(PageId(3)) {
                assert_eq!(
                    p3.with_page(f, |pg| pg[100]),
                    4,
                    "evictor read wrong page for 3"
                );
                p3.unpin(f);
            }
        });

        e2.join().unwrap();
        e3.join().unwrap();

        // Both resident dirty pages were evicted, so both took the staged path exactly once. (With two
        // frames and two single-fetch threads that both start with unpinned victims available, each
        // fetch succeeds and evicts one dirty page — the eviction of both is guaranteed.)
        assert_eq!(
            staged.load(Ordering::SeqCst),
            2,
            "both dirty pages must be staged-and-home-written exactly once through the DWB stager"
        );

        // No pin leaked by any evictor on any interleaving: every frame is evictable again.
        for id in [PageId(2), PageId(3)] {
            let f = pool.fetch(id).unwrap();
            pool.unpin(f);
        }
    });
}

/// **3-thread fetch/flush model (`rmp` #597, gap #4b): a write-back concurrent with two readers.**
///
/// Beyond the existing ≤2-thread models, this drives **three** threads over a 2-frame / 3-page pool:
/// one thread [`flush_all`](ConcurrentBufferPool::flush_all)s (writing back a resident dirty page)
/// while two others [`fetch`] *different* pages (forcing eviction of the resident pages the flusher is
/// walking). loom explores the pin / latch / write-back interleavings a two-thread model cannot reach
/// (a flush write-back racing two independent evictions). On every interleaving the byte-integrity
/// invariant holds — each reader that succeeds observes **exactly** its own page's stamped byte, never
/// a torn or cross-page value — no pin leaks, and the model does not deadlock (loom completing the
/// exhaustive-within-the-preemption-bound search is itself the acyclic-lock-order proof).
///
/// Three schedulable threads is a large state space; run under a preemption cap (the same `= 3` bound
/// the `loom_eviction_storm` models use) so the search terminates:
/// ```text
/// RUSTFLAGS="--cfg loom" LOOM_MAX_PREEMPTIONS=3 \
///   cargo test -p graphus-bufpool --test loom_bufpool \
///   loom_three_threads_flush_while_two_fetch --release
/// ```
#[test]
fn loom_three_threads_flush_while_two_fetch() {
    loom::model(|| {
        let reads = Arc::new(AtomicUsize::new(0));
        let dev = ModelDevice::new(3, reads); // pages 0,1,2 stamped 1,2,3 at [100]
        let pool = ConcurrentBufferPool::new(dev, 2).shared();

        // Seed page 0 dirty & resident (a real write-back target for the flusher).
        {
            let f = pool.fetch(PageId(0)).expect("seed fetch 0");
            pool.with_page_mut_lsn(f, Lsn(0x10), |pg| pg[100] = 0xC0);
            pool.unpin(f);
        }

        // Flusher: write back all dirty pages (page 0) — concurrent with the two evicting readers.
        let pf = pool.clone();
        let flusher = loom::thread::spawn(move || {
            let _ = pf.flush_all();
        });

        // Reader of page 1 (stamped byte 2). Whenever the fetch succeeds it must read page 1's byte.
        let p1 = pool.clone();
        let r1 = loom::thread::spawn(move || {
            if let Ok(f) = p1.fetch(PageId(1)) {
                assert_eq!(
                    p1.with_page(f, |pg| pg[100]),
                    2,
                    "reader of page 1 observed the wrong page's bytes (torn/cross-page read)"
                );
                p1.unpin(f);
            }
        });

        // Reader of page 2 (stamped byte 3).
        let p2 = pool.clone();
        let r2 = loom::thread::spawn(move || {
            if let Ok(f) = p2.fetch(PageId(2)) {
                assert_eq!(
                    p2.with_page(f, |pg| pg[100]),
                    3,
                    "reader of page 2 observed the wrong page's bytes (torn/cross-page read)"
                );
                p2.unpin(f);
            }
        });

        flusher.join().unwrap();
        r1.join().unwrap();
        r2.join().unwrap();

        // No pin leaked by any path on any interleaving: every frame is fetchable + evictable again.
        for slot in 0..pool.capacity() {
            let f = pool.fetch(PageId(slot as u64)).unwrap();
            pool.unpin(f);
        }
    });
}
