//! **Fast runtime repro of the `rmp` #359 concurrent-read wrong-result defect at the buffer-pool
//! level** — the multi-page *chain* read that the morsel-driven parallel scan does
//! (`incident_rels` rel-chain + `PropRecord`→`Strings` property chain, each hop a separate
//! [`ConcurrentBufferPool::with_page_fetched`]) over a pool **smaller than the working set**.
//!
//! `concurrent_eviction.rs` already exercises *independent single-page* reads under eviction. This
//! file adds the missing shape: **K threads each walking a CHAIN of pages** (each hop reads the next
//! page id out of the current page's bytes, exactly like a record/overflow chain), so a wrong-page
//! read is caught structurally (the chain pointer would lead to the wrong successor) AND a spurious
//! `fetch` error (the #339 read-integrity bug — a transient "pool full of pinned pages" surfaced
//! instead of retried, then swallowed up the read-view chain into `Value::Null`) is caught directly.
//!
//! Built to reproduce in **seconds**, with the `bufpool-probe` feature reading WHY any failure
//! happens (genuine capacity vs transient contention), so the fix cycle is not gated on the ~40 s
//! `morsel_expand` flake.
//!
//! Run:
//! ```text
//! cargo test -p graphus-bufpool --features bufpool-probe --release --test eviction_chain_repro
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use graphus_bufpool::ConcurrentBufferPool;
use graphus_bufpool::page;
use graphus_core::PageId;
use graphus_core::error::Result;
use graphus_io::{BlockDevice, PAGE_SIZE, Page};

/// Offset of each page's self-id witness (kept well past the 8-byte page header).
const TAG_OFF: usize = 64;
/// Offset of each page's "next page in the chain" pointer.
const NEXT_OFF: usize = 80;

fn read_word(p: &Page, off: usize) -> u64 {
    u64::from_le_bytes(p[off..off + 8].try_into().expect("8-byte word"))
}
fn write_word(p: &mut Page, off: usize, v: u64) {
    p[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// A `Send + Sync`, read-only device of `n` checksummed pages. Page `i` carries its own id at
/// [`TAG_OFF`] and the id of its chain successor `(i + 1) % n` at [`NEXT_OFF`] — so a reader can walk
/// a deterministic ring and verify, at every hop, that the page it got is the one its predecessor
/// pointed at. A wrong-page read corrupts the walk (a hop lands on a page whose self-id is not the
/// expected successor); the device read itself never fails, so any `with_page_fetched` `Err` is a
/// pool-internal spurious failure, not I/O.
struct ChainDevice {
    pages: Vec<Page>,
    /// A small busy-spin inside `read_page` so an evictor mid-`load_into` holds the victim's WRITE
    /// latch for a wider window — the realistic case where a `select_victim` sweep finds the few
    /// unpinned frames momentarily write-latched by peer loaders (transient contention). A real
    /// store's decode + multi-store fan-out has the same effect; the spin reproduces it
    /// deterministically with a `MemBlockDevice`-speed device.
    load_spin: u64,
}

impl ChainDevice {
    fn new(n: u64, load_spin: u64) -> Self {
        let mut pages = Vec::with_capacity(n as usize);
        for i in 0..n {
            let mut p: Page = [0u8; PAGE_SIZE];
            page::set_page_id(&mut p, i);
            write_word(&mut p, TAG_OFF, i);
            write_word(&mut p, NEXT_OFF, (i + 1) % n);
            // A second self-id copy near the tail, so a torn / wrong-frame read is caught wherever it lands.
            write_word(&mut p, PAGE_SIZE - 16, i);
            page::write_checksum(&mut p);
            pages.push(p);
        }
        Self { pages, load_spin }
    }
}

impl BlockDevice for ChainDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
        // Widen the latch-hold window (see `load_spin`): a volatile no-op spin the optimiser keeps.
        let mut acc = 0u64;
        for k in 0..self.load_spin {
            acc = std::hint::black_box(acc.wrapping_add(k));
        }
        std::hint::black_box(acc);
        buf.copy_from_slice(&self.pages[page.0 as usize]);
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

/// What a failing chain walk observed, recorded once and reported.
#[derive(Debug, Clone, Copy)]
enum Defect {
    /// A `with_page_fetched` returned `Err` even though a victim was destined to become available —
    /// the #359 spurious-fetch-error (swallowed into `Value::Null` up the read path).
    SpuriousError { page: u64 },
    /// A hop read a frame whose self-id was not the page the chain pointed at — a wrong-page read.
    WrongPage { expected: u64, observed: u64 },
}

/// The measured outcome of one chain storm: the first defect observed (if any) plus the per-pool
/// eviction-diagnostics counters.
#[derive(Debug, Clone, Copy)]
struct StormResult {
    defect: Option<Defect>,
    /// Empty sweeps classified as genuine capacity (every frame pinned). MUST be 0 when readers < frames.
    all_pinned: u64,
    /// Empty sweeps classified as transient latch contention.
    contended: u64,
    /// The deepest retry chain any single `fetch` took. Small ⇒ the backoff drains the herd fast.
    max_retry_iters: u64,
}

/// Drives `readers` threads, each walking the `n`-page ring `hops` pages at a time starting from a
/// per-thread rotation, `rounds` times, over a pool of `pool_frames` (< `n`, forcing constant
/// eviction). Returns the first [`Defect`] any thread observed (or `None`), plus the per-pool probe
/// classification of empty victim sweeps and the worst retry depth.
fn run_chain_storm(
    n: u64,
    pool_frames: usize,
    readers: usize,
    rounds: usize,
    hops: u64,
    load_spin: u64,
) -> StormResult {
    let dev = ChainDevice::new(n, load_spin);
    let pool = ConcurrentBufferPool::new(dev, pool_frames).shared();

    let stop = Arc::new(AtomicBool::new(false));
    let defect: Arc<std::sync::Mutex<Option<Defect>>> = Arc::new(std::sync::Mutex::new(None));
    // Count total successful hops so a vacuous "no defect because nothing ran" cannot pass silently.
    let total_hops = Arc::new(AtomicU64::new(0));

    std::thread::scope(|scope| {
        for r in 0..readers {
            let pool = Arc::clone(&pool);
            let stop = Arc::clone(&stop);
            let defect = Arc::clone(&defect);
            let total_hops = Arc::clone(&total_hops);
            scope.spawn(move || {
                for round in 0..rounds {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    // A per-thread, per-round starting page so the eviction interleaving differs.
                    let mut cur = ((r as u64) * 7919 + (round as u64) * 104_729) % n;
                    for _ in 0..hops {
                        let expected = cur;
                        // Each hop: fetch the current page, read its self-id witness AND its chain
                        // successor under ONE latch (the `with_page_fetched` shape the read view uses).
                        let res = pool.with_page_fetched(PageId(cur), |p| {
                            (
                                read_word(p, TAG_OFF),
                                read_word(p, PAGE_SIZE - 16),
                                read_word(p, NEXT_OFF),
                            )
                        });
                        let (tag1, tag2, next) = match res {
                            Ok(v) => v,
                            Err(_) => {
                                // The device read never fails, so this is a spurious pool-internal
                                // failure: the #359 bug. A victim is *always* destined to become
                                // available here — every peer's pin/latch is held only for the
                                // microseconds of one hop, so the pool must serve this read.
                                if !stop.swap(true, Ordering::Relaxed) {
                                    *defect.lock().unwrap() =
                                        Some(Defect::SpuriousError { page: expected });
                                }
                                return;
                            }
                        };
                        if tag1 != expected || tag2 != expected {
                            if !stop.swap(true, Ordering::Relaxed) {
                                *defect.lock().unwrap() = Some(Defect::WrongPage {
                                    expected,
                                    observed: tag1,
                                });
                            }
                            return;
                        }
                        total_hops.fetch_add(1, Ordering::Relaxed);
                        cur = next; // follow the chain to the verified successor
                    }
                }
            });
        }
    });

    // The eviction-mechanism counters are only available with the `bufpool-probe` feature; without it
    // the test still runs its (feature-independent) WrongPage / SpuriousError defect assertions, and the
    // probe-classification counters report `0` (the `all_pinned == 0` assertion is itself gated below).
    #[cfg(feature = "bufpool-probe")]
    let (all_pinned, contended, max_retry_iters) = {
        let snap = pool.probe_snapshot();
        (
            snap.victim_miss_all_pinned,
            snap.victim_miss_contended,
            snap.max_retry_iters,
        )
    };
    #[cfg(not(feature = "bufpool-probe"))]
    let (all_pinned, contended, max_retry_iters) = (0u64, 0u64, 0u64);

    let found = *defect.lock().unwrap();
    assert!(
        total_hops.load(Ordering::Relaxed) > 0,
        "the storm executed no hops — the repro is vacuous"
    );
    StormResult {
        defect: found,
        all_pinned,
        contended,
        max_retry_iters,
    }
}

/// **The #359 repro.** K readers each walk a chain over a pool far smaller than the working set,
/// under constant eviction. The pool MUST serve every hop (a victim is always destined to free) and
/// MUST never serve the wrong page's bytes. A failure here is precisely the bug the morsel
/// `morsel_expand` flake exhibits, reproduced in seconds.
///
/// `READERS` < `POOL_FRAMES` (16 readers, 24 frames) so the pool is **not** over-subscribed: a
/// genuine `AllPinned` cannot occur (at most 16 frames pinned at once, 8 always free), so any empty
/// sweep is transient contention and any error is therefore spurious.
#[test]
fn chain_reads_under_eviction_never_fail_or_cross_pages() {
    const PAGES: u64 = 4096;
    const POOL_FRAMES: usize = 24;
    const READERS: usize = 16;
    const ROUNDS: usize = 60;
    const HOPS: u64 = 256;
    // A load spin widens the evictor's write-latch hold so the few free frames are momentarily
    // latch-contended during a `select_victim` sweep — driving transient `Contended` misses with
    // READERS (16) < FRAMES (24) so a genuine `AllPinned` still cannot occur.
    const LOAD_SPIN: u64 = 4000;

    let r = run_chain_storm(PAGES, POOL_FRAMES, READERS, ROUNDS, HOPS, LOAD_SPIN);
    let (all_pinned, contended, max_iters) = (r.all_pinned, r.contended, r.max_retry_iters);

    // Report the mechanism classification regardless of pass/fail.
    eprintln!(
        "[#359 probe] empty victim sweeps: all_pinned={all_pinned} contended={contended} \
         max_retry_iters={max_iters} (readers={READERS} < frames={POOL_FRAMES}: a genuine AllPinned \
         is impossible, so any miss is transient contention)"
    );

    // With readers < frames there is ALWAYS a free frame, so a genuine capacity exhaustion is
    // impossible — the pool must never report one here. Only assertable when the `bufpool-probe`
    // feature is counting (without it `all_pinned` is a `0` placeholder, so the check would be vacuous).
    #[cfg(feature = "bufpool-probe")]
    {
        assert_eq!(
            all_pinned, 0,
            "select_victim reported genuine capacity exhaustion (all frames pinned) with only \
             {READERS} readers over {POOL_FRAMES} frames — impossible unless pins leak"
        );
        // NO-LIVELOCK PROOF (`rmp` #359): with the escalating backoff, every TRANSIENT contention
        // resolves with comfortable margin below the `MAX_FETCH_RETRIES` (16384) budget — it never
        // wedges or rides the bound. Under this deliberately pathological config (a 4000-iteration
        // load-latch hold, far harsher than a real decode) the worst observed depth is a few thousand
        // and the test always terminates promptly; the ceiling here catches a regression to a
        // bound-riding near-wedge (the live-lock the prior tight spin-retry amplified) while tolerating
        // run-to-run scheduling variance. The absolute number is not meaningful (it scales with the
        // artificial spin); what matters is it stays a *fraction* of the budget and never hangs.
        assert!(
            max_iters < 12000,
            "fetch took {max_iters} retry iterations (of a 16384 budget) to resolve a TRANSIENT \
             contention — the backoff is riding the bound instead of draining the herd (a live-lock \
             regression). Probe: contended={contended}."
        );
    }
    let _ = (all_pinned, max_iters);

    match r.defect {
        None => {}
        Some(Defect::SpuriousError { page }) => panic!(
            "SPURIOUS FETCH FAILURE (#359): with_page_fetched(page {page}) returned an error under \
             eviction even though a victim was destined to become available (the device read never \
             fails). This is the read-integrity bug: up the read-view chain it is swallowed into \
             Value::Null / a truncated chain — a WRONG query result. Probe: all_pinned={all_pinned}, \
             contended={contended}, max_retry_iters={max_iters}."
        ),
        Some(Defect::WrongPage { expected, observed }) => panic!(
            "WRONG-PAGE READ (#359): a chain hop expected page {expected} but the frame held page \
             {observed}'s bytes — the pool let an evictor reload a frame a reader had pinned. Probe: \
             all_pinned={all_pinned}, contended={contended}."
        ),
    }
}

/// A **higher-pressure** variant: readers == frames (16 == 16), so the pool is momentarily
/// over-subscribed and genuine `AllPinned` *can* occur. The contract is weaker here — a transient
/// capacity error is a legitimate, non-corrupting outcome — but the pool must STILL never serve the
/// wrong page's bytes. This catches a wrong-page regression even when the spurious-error contract is
/// relaxed (mirrors the loom `loom_reader_pin_never_lost_under_two_evictors` tolerance).
#[test]
fn chain_reads_under_max_pressure_never_cross_pages() {
    const PAGES: u64 = 4096;
    const POOL_FRAMES: usize = 16;
    const READERS: usize = 24;
    const ROUNDS: usize = 60;
    const HOPS: u64 = 256;
    const LOAD_SPIN: u64 = 4000;

    let r = run_chain_storm(PAGES, POOL_FRAMES, READERS, ROUNDS, HOPS, LOAD_SPIN);
    eprintln!(
        "[#359 probe max-pressure] empty victim sweeps: all_pinned={} contended={} max_retry_iters={}",
        r.all_pinned, r.contended, r.max_retry_iters
    );

    // The wrong-page contract is unconditional, even under over-subscription.
    if let Some(Defect::WrongPage { expected, observed }) = r.defect {
        panic!(
            "WRONG-PAGE READ under max pressure (#359): expected page {expected}, frame held \
             {observed}'s bytes. Probe: all_pinned={}, contended={}.",
            r.all_pinned, r.contended
        );
    }
    // A spurious error under genuine over-subscription (readers > frames) is tolerated (it is the
    // capacity limit, not corruption) — the strict no-spurious-error contract lives in the
    // readers < frames test above. Here we additionally assert no wrong-page bytes under max pressure.
}
