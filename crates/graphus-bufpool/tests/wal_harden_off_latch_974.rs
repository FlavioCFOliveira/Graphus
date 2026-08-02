//! Regression for the **eviction write-back convoy** (`rmp` #974): the buffer pool must never issue a
//! WAL durability barrier while holding a frame latch, and WAL-before-data must survive the change.
//!
//! # The defect
//!
//! `write_back` ran entirely under the victim frame's write latch, and inside it called
//! `ensure_durable(page_lsn)` — an `fdatasync` through the WAL mutex. Because that mutex is the one
//! the store's own commit path takes, the chain *frame latch → WAL mutex → `fdatasync`* convoyed
//! every other evictor **and** every concurrent commit behind a single latch. The batch flush paths
//! were worse: they held **every** dirty frame's write latch and ran one harden per page inside that
//! region.
//!
//! Measured on a 16-core host with a working set twice the pool, the write-back path kept the pool's
//! exclusive device guard — the same lock every concurrent cache-miss read needs in shared mode —
//! occupied 87–92 % of wall time, and cache-miss reads queued behind it for 27 µs (one reader) rising
//! to 323 µs (sixteen readers).
//!
//! # What is asserted here
//!
//! Every test below drives a **real eviction storm** through the concurrent pool with a WAL rule
//! whose `ensure_durable` asserts [`graphus_core::latch::frame_latch_depth`] is zero. That assertion
//! is the test: on the pre-#974 tree it fires on the first dirty eviction, because the harden ran
//! inside the latched region by construction.
//!
//! [`wal_before_data_holds_under_the_hoist`] guards the other direction — that hoisting the barrier
//! did not weaken the ordering rule it exists to serve. The device itself checks, at the instant of
//! every home write, that the log is already durable through the bytes' `page_lsn`.

use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};

use graphus_bufpool::{ConcurrentBufferPool, WalRule, page};
use graphus_core::error::Result;
use graphus_core::{Lsn, PageId};
use graphus_io::{BlockDevice, PAGE_SIZE, Page};

/// The shared state of the test log: a monotonically minted LSN stream and the durable frontier.
struct LogCore {
    /// The next LSN to mint. Every LSN below this has been *appended*.
    ///
    /// Starts at **1**, never 0: `Lsn(0)` is the null LSN, and a dirty page carrying `page_lsn == 0`
    /// is what `guard_wal_before_data` rejects as "logged but unstamped". A real `WalManager` has
    /// the same property — its first LSN is past the log header — so minting from 1 models it.
    appended: u64,
    /// The durable frontier, in the same units. Mirrors `WalManager`: a page whose `page_lsn` is
    /// strictly below this is covered by durable log.
    durable: u64,
    /// How many times a real harden advanced the frontier.
    hardens: u64,
}

impl Default for LogCore {
    fn default() -> Self {
        Self {
            appended: 1,
            durable: 0,
            hardens: 0,
        }
    }
}

/// A test log shared by the WAL rule, the device, and the test body.
#[derive(Clone, Default)]
struct TestLog(Arc<Mutex<LogCore>>);

impl TestLog {
    fn lock(&self) -> std::sync::MutexGuard<'_, LogCore> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Appends a record and returns its LSN — what a caller stamps onto the page it is dirtying.
    fn append(&self) -> Lsn {
        let mut c = self.lock();
        let lsn = c.appended;
        c.appended += 1;
        Lsn(lsn)
    }

    fn durable(&self) -> u64 {
        self.lock().durable
    }

    fn hardens(&self) -> u64 {
        self.lock().hardens
    }
}

/// The WAL rule under test. Its `ensure_durable` stands in for the real `fdatasync`, and asserts the
/// property `rmp` #974 established: **no frame latch may be held when a durability barrier runs**.
struct LatchCheckingWal {
    log: TestLog,
    /// Counts hardens that ran with a frame latch held. The assertion below fires first, but the
    /// counter makes the failure legible from the test body too (and survives a `should_panic`).
    violations: Arc<AtomicU64>,
}

impl WalRule for LatchCheckingWal {
    fn ensure_durable(&mut self, up_to: Lsn) -> Result<()> {
        let depth = graphus_core::latch::frame_latch_depth();
        if depth != 0 {
            self.violations.fetch_add(1, AtomicOrdering::Relaxed);
        }
        assert_eq!(
            depth, 0,
            "rmp #974: the WAL harden ran with {depth} buffer-pool frame latch(es) held. This is \
             the convoy: the barrier serialises every concurrent reader and every commit behind \
             that latch. The harden must be hoisted out of the latched region."
        );
        let mut c = self.log.lock();
        // Mirror `WalManager::ensure_durable` exactly: harden only when not already covered, and a
        // harden makes the WHOLE appended log durable.
        if c.durable <= up_to.0 {
            c.durable = c.appended;
            c.hardens += 1;
        }
        Ok(())
    }

    fn tracks_lsn(&self) -> bool {
        true
    }

    /// Reporting the frontier must **also** happen outside every latched region.
    ///
    /// This is a distinct property from the harden, and a strictly weaker-looking one that is just
    /// as load-bearing. The pool's `wal` field is a mutex around the *rule object*; the production
    /// rule (`graphus_storage::SharedWal`) keeps the real `WalManager` behind its own mutex and
    /// takes it **unconditionally** here. So a `durable_len` call from inside the victim sweep would
    /// block on the WAL manager — potentially behind a commit holding it across an `fdatasync` —
    /// while the caller holds a frame latch and a shard lock. No `fdatasync` would be issued under
    /// the latch, so the harden assertion above would stay silent, yet the convoy would be back and
    /// a `shard → WAL` wait edge would exist that the pool's lock-order proof forbids.
    ///
    /// An earlier version of `rmp` #974 did exactly that, via a `try_lock` on the outer wrapper that
    /// looked non-blocking but fell straight through into a blocking acquisition. This assertion is
    /// what makes that class of mistake fail a test instead of passing review.
    fn durable_len(&mut self) -> u64 {
        let depth = graphus_core::latch::frame_latch_depth();
        if depth != 0 {
            self.violations.fetch_add(1, AtomicOrdering::Relaxed);
        }
        assert_eq!(
            depth, 0,
            "rmp #974: the WAL frontier was read with {depth} buffer-pool frame latch(es) held. \
             This acquisition is blocking for the production rule, so it convoys behind any commit \
             holding the WAL across an fdatasync — while a frame latch (and the caller's shard \
             lock) is held. The victim sweep must consult the lock-free mirror only."
        );
        self.log.lock().durable
    }
}

/// An in-memory device that asserts **WAL-before-data at the instant of every home write**: the log
/// must already be durable through the `page_lsn` carried by the bytes being written.
///
/// This is the invariant the hoist must not weaken. It is checked here, in the device, rather than
/// by inspecting an event log after the fact, so a violation is attributed to the exact write that
/// caused it.
struct WalCheckingDevice {
    pages: Vec<Page>,
    log: TestLog,
    /// Home writes observed, so a test can prove its eviction storm actually wrote pages back
    /// (a non-vacuity control: an assertion that never runs proves nothing).
    writes: Arc<AtomicU64>,
    /// Home writes that violated WAL-before-data.
    violations: Arc<AtomicU64>,
}

impl WalCheckingDevice {
    fn new(n: u64, log: TestLog, writes: Arc<AtomicU64>, violations: Arc<AtomicU64>) -> Self {
        let mut pages = Vec::with_capacity(n as usize);
        for i in 0..n {
            let mut p: Page = [0u8; PAGE_SIZE];
            page::set_page_id(&mut p, i);
            page::write_checksum(&mut p);
            pages.push(p);
        }
        Self {
            pages,
            log,
            writes,
            violations,
        }
    }

    fn check_wal_before_data(&self, page: PageId, buf: &Page) {
        self.writes.fetch_add(1, AtomicOrdering::Relaxed);
        // POSITIVE CONTROL for the tripwire itself.
        //
        // Every other assertion in this file is of the form `frame_latch_depth() == 0`, and a
        // depth counter that is never incremented satisfies all of them. That is a real risk: if
        // `Victim._latch` / `FlushBatch._latch` were dropped, or the scope were armed too late, the
        // guard would become a no-op and the whole suite would still pass — proving nothing.
        //
        // The home write, by construction, runs *inside* a latched region on all four write paths
        // (eviction, `flush`, `flush_all`, `flush_pages`), so the depth here must be non-zero. This
        // is the one assertion that proves the tripwire is armed rather than merely quiet, and it
        // would have caught the earlier version that constructed the scope only on the accepted
        // victim path.
        assert!(
            graphus_core::latch::frame_latch_depth() > 0,
            "the frame-latch tripwire is NOT armed: page {} reached its home write with depth 0, \
             but every home-write path holds a frame latch. Every `depth == 0` assertion in this \
             suite is therefore vacuous.",
            page.0
        );
        let lsn = page::page_lsn(buf);
        if lsn.0 == 0 {
            return; // an unlogged seed write: nothing in the log must precede it.
        }
        let durable = self.log.durable();
        if durable <= lsn.0 {
            self.violations.fetch_add(1, AtomicOrdering::Relaxed);
        }
        assert!(
            durable > lsn.0,
            "WAL-before-data violated: page {} was written home carrying page_lsn {} while the log \
             was durable only through {}",
            page.0,
            lsn.0,
            durable
        );
    }
}

impl BlockDevice for WalCheckingDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
        buf.copy_from_slice(&self.pages[page.0 as usize]);
        Ok(())
    }
    fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
        self.check_wal_before_data(page, buf);
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
    fn extend(&mut self, additional: u64) -> Result<()> {
        for _ in 0..additional {
            self.pages.push([0u8; PAGE_SIZE]);
        }
        Ok(())
    }
}

/// The pool under test, wired to the latch-checking WAL rule and the ordering-checking device.
type TestPool = ConcurrentBufferPool<WalCheckingDevice, LatchCheckingWal>;

/// One test rig: the pool, the shared log, the home-write counter, and the violation counter.
struct Rig {
    pool: Arc<TestPool>,
    log: TestLog,
    /// Home writes the device observed — the non-vacuity control for every test below.
    writes: Arc<AtomicU64>,
    /// Latch-held hardens plus WAL-before-data violations, from both the rule and the device.
    violations: Arc<AtomicU64>,
}

/// Builds a pool of `frames` frames over `pages` device pages, wired to a shared test log.
fn rig(frames: usize, pages: u64) -> Rig {
    let log = TestLog::default();
    let writes = Arc::new(AtomicU64::new(0));
    let violations = Arc::new(AtomicU64::new(0));
    let device = WalCheckingDevice::new(
        pages,
        log.clone(),
        Arc::clone(&writes),
        Arc::clone(&violations),
    );
    let wal = LatchCheckingWal {
        log: log.clone(),
        violations: Arc::clone(&violations),
    };
    let pool = Arc::new(ConcurrentBufferPool::with_wal(device, wal, frames));
    Rig {
        pool,
        log,
        writes,
        violations,
    }
}

/// Dirties `page` with a freshly minted, stamped LSN.
fn dirty<D: BlockDevice, W: WalRule>(
    pool: &ConcurrentBufferPool<D, W>,
    log: &TestLog,
    page: PageId,
    byte: u8,
) {
    // The LSN is minted BEFORE the pool call and the log lock is released first — the store's own
    // discipline (never hold the WAL lock across a pool call that can trigger a write-back).
    let lsn = log.append();
    let frame = pool.fetch(page).expect("fetch");
    pool.with_page_mut_lsn(frame, lsn, |p| p[128] = byte);
    pool.unpin(frame);
}

/// The core property: an **eviction** storm hardens the log without ever holding a frame latch.
///
/// Pre-#974 this fails on the first dirty eviction: `write_back` called `ensure_durable` with the
/// victim's write latch held.
#[test]
fn eviction_never_hardens_the_wal_under_a_frame_latch() {
    const FRAMES: usize = 4;
    const PAGES: u64 = 64;
    let Rig {
        pool,
        log,
        writes,
        violations,
    } = rig(FRAMES, PAGES);

    // Every page dirtied with a rising LSN, over a pool 16× too small: every fetch after the first
    // few must evict, and the victim is essentially always dirty and un-hardened.
    for round in 0..4u8 {
        for p in 0..PAGES {
            dirty(&pool, &log, PageId(p), round.wrapping_add(p as u8));
        }
    }

    // Non-vacuity: the storm must actually have driven write-backs and hardens, otherwise the
    // assertion inside the WAL rule never ran and this test proves nothing.
    assert!(
        writes.load(AtomicOrdering::Relaxed) > 0,
        "no home write occurred: the eviction storm did not exercise the write-back path"
    );
    assert!(
        log.hardens() > 0,
        "no WAL harden occurred: the write-back path never exercised the WAL rule"
    );
    assert_eq!(
        violations.load(AtomicOrdering::Relaxed),
        0,
        "a harden ran under a frame latch, or a page was written home ahead of its log record"
    );
}

/// The same property for the **batch** flush path, which held *every* dirty frame's latch and ran a
/// harden per page inside that region.
#[test]
fn batch_flush_never_hardens_the_wal_under_frame_latches() {
    const FRAMES: usize = 32;
    const PAGES: u64 = 32;
    let Rig {
        pool,
        log,
        writes,
        violations,
    } = rig(FRAMES, PAGES);

    // Fill the pool with dirty pages WITHOUT evicting (frames == pages), so the harden can only come
    // from `flush_all` itself and the test isolates the batch path.
    for p in 0..PAGES {
        dirty(&pool, &log, PageId(p), p as u8);
    }
    assert_eq!(
        pool.dirty_frames(),
        PAGES as usize,
        "every frame must be dirty before the batch flush, so the batch path is what hardens"
    );
    assert_eq!(
        writes.load(AtomicOrdering::Relaxed),
        0,
        "no eviction should have happened yet: the pool holds the whole working set"
    );

    pool.flush_all().expect("flush_all");

    assert_eq!(pool.dirty_frames(), 0, "flush_all must clean every frame");
    assert_eq!(
        writes.load(AtomicOrdering::Relaxed),
        PAGES,
        "flush_all must write every dirty page home"
    );
    assert!(log.hardens() > 0, "flush_all must have hardened the log");
    assert_eq!(
        violations.load(AtomicOrdering::Relaxed),
        0,
        "a harden ran under the batch's frame latches"
    );
}

/// The targeted batch path (`flush_pages`, the doublewrite-protected checkpoint) must hoist too.
#[test]
fn targeted_batch_flush_never_hardens_the_wal_under_frame_latches() {
    const FRAMES: usize = 16;
    const PAGES: u64 = 16;
    let Rig {
        pool,
        log,
        writes,
        violations,
    } = rig(FRAMES, PAGES);

    for p in 0..PAGES {
        dirty(&pool, &log, PageId(p), p as u8);
    }
    let selected: Vec<PageId> = (0..PAGES).step_by(2).map(PageId).collect();
    pool.flush_pages(&selected).expect("flush_pages");

    assert_eq!(
        writes.load(AtomicOrdering::Relaxed),
        selected.len() as u64,
        "flush_pages must write home exactly the selected dirty pages"
    );
    assert_eq!(
        pool.dirty_frames(),
        (PAGES as usize) - selected.len(),
        "unselected frames stay dirty"
    );
    assert!(log.hardens() > 0, "flush_pages must have hardened the log");
    assert_eq!(violations.load(AtomicOrdering::Relaxed), 0);
}

/// The single-frame `flush` path.
#[test]
fn single_frame_flush_never_hardens_the_wal_under_a_frame_latch() {
    let Rig {
        pool,
        log,
        writes,
        violations,
    } = rig(4, 8);
    let lsn = log.append();
    let frame = pool.fetch(PageId(0)).expect("fetch");
    pool.with_page_mut_lsn(frame, lsn, |p| p[128] = 0xAB);
    pool.flush(frame).expect("flush");
    pool.unpin(frame);

    assert_eq!(writes.load(AtomicOrdering::Relaxed), 1);
    assert!(log.hardens() > 0);
    assert_eq!(violations.load(AtomicOrdering::Relaxed), 0);
}

/// **WAL-before-data survives the hoist.** Moving the barrier out of the latched region must not
/// let a page reach its home location before its redo record is durable — the device asserts the
/// ordering at the instant of every home write, and the pages carry rising LSNs so a stale coverage
/// decision would be caught rather than masked by an over-hardened log.
#[test]
fn wal_before_data_holds_under_the_hoist() {
    const FRAMES: usize = 3;
    const PAGES: u64 = 48;
    let Rig {
        pool,
        log,
        writes,
        violations,
    } = rig(FRAMES, PAGES);

    // Interleave dirtying with plain reads so victims are a mix of clean and dirty, and the LSN
    // stream keeps rising between evictions — the case where a stale durability watermark would
    // wrongly conclude "already covered".
    for round in 0..6u8 {
        for p in 0..PAGES {
            if (p + u64::from(round)) % 3 == 0 {
                let frame = pool.fetch(PageId(p)).expect("fetch");
                pool.with_page(frame, |page| std::hint::black_box(page[128]));
                pool.unpin(frame);
            } else {
                dirty(&pool, &log, PageId(p), round.wrapping_add(p as u8));
            }
        }
    }
    pool.flush_all().expect("final flush");

    assert!(
        writes.load(AtomicOrdering::Relaxed) > PAGES,
        "the storm must have written far more pages home than the working set to be meaningful"
    );
    assert!(log.hardens() > 0);
    assert_eq!(
        violations.load(AtomicOrdering::Relaxed),
        0,
        "a page reached its home location before the log was durable through its page_lsn"
    );
}

/// The property must hold under **real concurrency**, which is where the convoy lived: many threads
/// evicting and hardening at once.
///
/// This also carries a genuine **read-integrity** control. Each page is owned by exactly one thread,
/// which stamps a value only it can produce and re-reads it after every round; a page that comes
/// back with another page's bytes — the `rmp` #339 failure mode, which an eviction-path change is
/// exactly the kind of thing that could reintroduce — fails the assertion with the observed value,
/// not merely a timing difference. Single ownership is what makes the expected value exact under
/// concurrency, so the control cannot be satisfied by an unchecked read.
#[test]
fn concurrent_eviction_storm_never_hardens_under_a_latch() {
    const FRAMES: usize = 8;
    const PAGES: u64 = 128;
    const THREADS: u64 = 8;
    const ROUNDS: u64 = 200;

    let Rig {
        pool,
        log,
        writes,
        violations,
    } = rig(FRAMES, PAGES);

    std::thread::scope(|s| {
        for t in 0..THREADS {
            let pool = Arc::clone(&pool);
            let log = log.clone();
            s.spawn(move || {
                // Pages are partitioned by thread, so this thread is the sole writer of every page
                // it touches and the byte it last wrote is the exact value a correct pool must
                // return. Threads still contend hard on the 8 shared frames and on the victim sweep.
                let mine: Vec<u64> = (t..PAGES).step_by(THREADS as usize).collect();
                let mut last: Vec<Option<u8>> = vec![None; mine.len()];
                for r in 0..ROUNDS {
                    let slot = (r as usize) % mine.len();
                    let p = PageId(mine[slot]);
                    if r % 3 == 0 {
                        // READ-INTEGRITY CONTROL: re-read a page this thread owns and compare
                        // against the byte it last wrote there.
                        let frame = pool.fetch(p).expect("fetch");
                        let got = pool.with_page(frame, |page| page[128]);
                        pool.unpin(frame);
                        if let Some(expected) = last[slot] {
                            assert_eq!(
                                got, expected,
                                "read integrity: page {} came back with {got:#x}, but this thread \
                                 (its only writer) last wrote {expected:#x}",
                                p.0
                            );
                        }
                    } else {
                        let byte = (r ^ t).to_le_bytes()[0];
                        dirty(&pool, &log, p, byte);
                        last[slot] = Some(byte);
                    }
                }
                // Final pass: every page this thread wrote must still read back its last value.
                for (slot, page) in mine.iter().enumerate() {
                    let Some(expected) = last[slot] else { continue };
                    let frame = pool.fetch(PageId(*page)).expect("fetch");
                    let got = pool.with_page(frame, |p| p[128]);
                    pool.unpin(frame);
                    assert_eq!(
                        got, expected,
                        "read integrity after the storm: page {page} came back with {got:#x}, \
                         expected {expected:#x}"
                    );
                }
            });
        }
    });

    pool.flush_all().expect("final flush");

    assert!(
        writes.load(AtomicOrdering::Relaxed) > 0,
        "the concurrent storm must have driven home writes"
    );
    assert!(log.hardens() > 0, "the concurrent storm must have hardened");
    assert_eq!(
        violations.load(AtomicOrdering::Relaxed),
        0,
        "under concurrency a harden ran under a frame latch, or WAL-before-data was violated"
    );
}

/// A `WalRule` whose reported frontier is **stale-low** must still make progress.
///
/// This is not a hypothetical: it is the ordinary production condition. The store's commit path
/// hardens the same log directly, without going through this pool, so the pool's lock-free mirror
/// routinely lags the truth. The rule below reproduces that by reporting a frontier that trails the
/// real one, and the eviction storm must still converge — declining a victim, hoisting, refreshing,
/// and proceeding — rather than hoisting forever or surfacing an error.
///
/// The counters make the mechanism visible: hardens must be far fewer than write-backs (one harden
/// covers the whole appended log), and no fetch may fail.
#[test]
fn a_stale_frontier_still_converges() {
    /// Reports a frontier that lags the true one by a fixed margin, and hardens for real.
    struct StaleFrontierWal {
        log: TestLog,
        hardens: Arc<AtomicU64>,
        /// The lagging snapshot the rule reports, refreshed only every third read.
        snapshot: Arc<AtomicU64>,
        reads: Arc<AtomicU64>,
    }
    impl WalRule for StaleFrontierWal {
        fn ensure_durable(&mut self, up_to: Lsn) -> Result<()> {
            assert_eq!(
                graphus_core::latch::frame_latch_depth(),
                0,
                "even the stale-frontier path must not harden under a frame latch"
            );
            let mut c = self.log.lock();
            if c.durable <= up_to.0 {
                c.durable = c.appended;
                c.hardens += 1;
            }
            drop(c);
            self.hardens.fetch_add(1, AtomicOrdering::Relaxed);
            Ok(())
        }
        fn durable_len(&mut self) -> u64 {
            // TEMPORAL staleness, the real production condition: the reported frontier is a
            // *snapshot* refreshed only every few calls, so it lags the truth by time and always
            // catches up — exactly how the pool's own mirror behaves when the store commits without
            // going through the pool. (A rule that lagged by a fixed margin forever would make some
            // pages permanently un-hardenable; the trait documents that as a broken rule, and the
            // pool's response is a bounded retry error, never a WAL-before-data violation.)
            let n = self.reads.fetch_add(1, AtomicOrdering::Relaxed);
            let truth = self.log.lock().durable;
            if n % 3 == 0 {
                self.snapshot.store(truth, AtomicOrdering::Release);
                truth
            } else {
                self.snapshot.load(AtomicOrdering::Acquire)
            }
        }
    }

    let hardens = Arc::new(AtomicU64::new(0));
    let log = TestLog::default();
    let writes = Arc::new(AtomicU64::new(0));
    let violations = Arc::new(AtomicU64::new(0));
    let device = WalCheckingDevice::new(
        64,
        log.clone(),
        Arc::clone(&writes),
        Arc::clone(&violations),
    );
    let pool = ConcurrentBufferPool::with_wal(
        device,
        StaleFrontierWal {
            log: log.clone(),
            hardens: Arc::clone(&hardens),
            snapshot: Arc::new(AtomicU64::new(0)),
            reads: Arc::new(AtomicU64::new(0)),
        },
        4,
    );

    // A 4-frame pool over 64 pages: constant eviction of dirty, rising-LSN pages.
    for round in 0..4u8 {
        for p in 0..64u64 {
            let lsn = log.append();
            let frame = pool
                .fetch(PageId(p))
                .expect("fetch must converge under a stale frontier, not hoist forever");
            pool.with_page_mut_lsn(frame, lsn, |page| page[128] = round.wrapping_add(p as u8));
            pool.unpin(frame);
        }
    }
    pool.flush_all().expect("flush must converge");

    let wrote = writes.load(AtomicOrdering::Relaxed);
    let hardened = hardens.load(AtomicOrdering::Relaxed);
    assert!(wrote > 0, "the storm must have written pages home");
    assert!(
        hardened > 0,
        "the storm must have hardened through the hoist path"
    );
    assert_eq!(
        violations.load(AtomicOrdering::Relaxed),
        0,
        "a stale frontier must never let a page reach home ahead of its log record"
    );
    // One harden makes the whole appended log durable, so hardens must be far cheaper than writes —
    // the property that makes the hoist affordable rather than merely correct.
    assert!(
        hardened < wrote,
        "hardens ({hardened}) must be fewer than home writes ({wrote}): one harden covers the \
         entire appended log, so the hoist must not degenerate into one fsync per page"
    );
}
