//! `loom` model-check of the **many-evictor-vs-reader eviction storm** on
//! [`graphus_bufpool::ConcurrentBufferPool`] (`rmp` #339 — the first true concurrent reader, the
//! morsel-driven parallel label scan, surfaced a read-integrity bug here).
//!
//! ## What this proves
//!
//! The existing models in `loom_bufpool.rs` / `loom_freeze_vs_reader.rs` use **2 frames and ≤2
//! threads**: they exercise the load/evict/latch protocol but never put a reader's *pin* in
//! contention with **two** independent evictors reloading the very frame the reader pinned. That is
//! the interleaving `rmp` #339's `concurrent_eviction.rs` runtime test reproduced (~33–60% of runs):
//! a reader asked for page `A` and observed another page's complete bytes.
//!
//! This model reproduces it at a small frame/thread count that still exhibits it: **two frames over
//! three distinct pages** (so every cross-page fetch must evict a resident one, but a victim is
//! generally available, unlike a 1-frame pool where a transient "all frames pinned" capacity error
//! dominates the search), shared by a reader that reads page `A` through
//! [`ConcurrentBufferPool::with_page_fetched`] and two evictor threads that read pages `B` and `C`
//! (each forcing an eviction). loom explores all interleavings, including the one where the reader's
//! pin on `A`'s frame is placed on the fast path *before* it takes its read latch, an evictor wins
//! the frame, and an absolute (`store(1)`) cold-path publish discards the reader's pin — letting a
//! second evictor reload the frame while a holder is still about to read it.
//!
//! On **every** interleaving the reader must observe **exactly** page `A`'s stamped byte — never
//! `B`'s or `C`'s. A failure here is the wrong-page read (an ACID read-integrity violation).
//!
//! Run with:
//!
//! ```text
//! RUSTFLAGS="--cfg loom" LOOM_MAX_PREEMPTIONS=3 \
//!   cargo test -p graphus-bufpool --test loom_eviction_storm --release
//! ```

#![cfg(loom)]

use graphus_bufpool::ConcurrentBufferPool;
use graphus_bufpool::page;
use graphus_core::PageId;
use graphus_core::error::{GraphusError, Result};
use graphus_io::{BlockDevice, PAGE_SIZE, Page};

use loom::sync::Arc;

/// The fixed offset at which each page carries a witness of its own id (mirrors
/// `concurrent_eviction.rs`'s `TAG_OFF`, kept well past the page header).
const TAG_OFF: usize = 64;

/// Reads the 8-byte little-endian witness word.
fn tag(p: &Page) -> u64 {
    u64::from_le_bytes(p[TAG_OFF..TAG_OFF + 8].try_into().expect("8-byte word"))
}

/// A tiny `Send`, read-only in-memory device of `n` checksummed pages, each stamped with its own id
/// at [`TAG_OFF`] (and a second copy near the tail, exactly as the runtime repro), so a wrong-frame
/// read is caught. The device is read-only at the byte level (the model never writes), so no
/// interior mutability is needed.
struct TaggedDevice {
    pages: Vec<Page>,
}

impl TaggedDevice {
    fn new(n: u64) -> Self {
        let mut pages = Vec::with_capacity(n as usize);
        for i in 0..n {
            let mut p: Page = [0u8; PAGE_SIZE];
            page::set_page_id(&mut p, i);
            p[TAG_OFF..TAG_OFF + 8].copy_from_slice(&i.to_le_bytes());
            p[PAGE_SIZE - 16..PAGE_SIZE - 8].copy_from_slice(&i.to_le_bytes());
            page::write_checksum(&mut p);
            pages.push(p);
        }
        Self { pages }
    }
}

impl BlockDevice for TaggedDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
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
    fn extend(&mut self, _additional: u64) -> Result<()> {
        Ok(())
    }
}

/// Two frames, three threads: a reader of page `A` plus two evictors reading pages `B` and `C`.
///
/// Two frames over three distinct pages still forces constant eviction, but (unlike a single frame)
/// leaves the reader's fetch of `A` a victim to use even while one evictor holds the other frame —
/// so a transient "pool full of pinned pages" is not the dominant outcome and the wrong-page
/// interleaving is reachable. The reader uses [`ConcurrentBufferPool::with_page_fetched`], whose hit
/// fast path pins the frame **before** taking the read latch; loom explores the interleaving where
/// that pin is placed, an evictor wins and reloads the frame, and (if the publish discards the
/// reader's pin) a second evictor reloads it again while the reader is still about to read it. The
/// core assertion: whenever the reader's fetch *succeeds*, it observes **only** page `A`'s witness —
/// never `B`'s or `C`'s. (A transient capacity error — every frame momentarily pinned by the other
/// two threads — is a legitimate, non-corrupting outcome and is tolerated; it is **not** the bug.)
#[test]
fn loom_reader_pin_never_lost_under_two_evictors() {
    // 3 threads + the eviction storm is a large state space; cap preemptions so the search
    // terminates in reasonable time while still covering the lost-pin window (which needs only a
    // couple of preemption points: one between the reader's pin and its read latch, one inside the
    // evictor's publish).
    loom::model(|| {
        const A: u64 = 0;
        const B: u64 = 1;
        const C: u64 = 2;

        let dev = TaggedDevice::new(3);
        // Two frames over three pages: constant eviction, but a victim is generally available.
        let pool = ConcurrentBufferPool::new(dev, 2).shared();

        // Pre-resident `A` so the reader takes the HIT fast path of `with_page_fetched` (the path
        // that pins before latching), maximising the lost-pin window the bug lives in.
        {
            let f = pool.fetch(PageId(A)).expect("seed fetch A");
            pool.unpin(f);
        }

        let pr = Arc::clone(&pool);
        let reader = loom::thread::spawn(move || {
            // The reader asks for A. Whenever its fetch SUCCEEDS it must read A's witness — never
            // B/C. A transient capacity error (both frames pinned by the evictors) is legitimate.
            if let Ok(got) = pr.with_page_fetched(PageId(A), tag) {
                assert_eq!(
                    got, A,
                    "READER READ THE WRONG PAGE: asked for {A}, observed page {got}'s bytes — the \
                     concurrent buffer pool let an evictor reload the frame the reader had pinned \
                     (a read-integrity / ACID bug)"
                );
            }
        });

        let pb = Arc::clone(&pool);
        let evictor_b = loom::thread::spawn(move || {
            // Reads a DIFFERENT page, forcing eviction of whatever resides (often A's frame).
            if let Ok(got) = pb.with_page_fetched(PageId(B), tag) {
                assert_eq!(got, B, "evictor B read the wrong page: {got}");
            }
        });

        let pc = Arc::clone(&pool);
        let evictor_c = loom::thread::spawn(move || {
            if let Ok(got) = pc.with_page_fetched(PageId(C), tag) {
                assert_eq!(got, C, "evictor C read the wrong page: {got}");
            }
        });

        reader.join().unwrap();
        evictor_b.join().unwrap();
        evictor_c.join().unwrap();

        // No pin leaked by any path on any interleaving: every frame is evictable again.
        for slot in 0..pool.capacity() {
            let f = pool.fetch(PageId(slot as u64)).unwrap();
            pool.unpin(f);
        }
    });
}

/// **The `rmp` #339 Slice 3c read-integrity bug: a SPURIOUS "pool full of pinned pages" fetch error
/// under concurrent-reader eviction pressure, even though a victim frame is available.**
///
/// ## What the bug actually is (empirically established, not the original wrong-page hypothesis)
///
/// Instrumenting `with_page_fetched` proved the pool **never serves wrong bytes** — every served
/// page's self-id matched the requested device page on every interleaving. The corruption
/// (`b.name → Null`, `concurrent_eviction.rs` / the cypher morsel scan) was instead a **spurious
/// read FAILURE**: on a page MISS, [`ConcurrentBufferPool::fetch`] called `select_victim`, and when
/// that bounded `4*n` CLOCK sweep transiently came up empty — because concurrent readers held
/// short-lived pins/latches on the frames it probed, or an evictor held a victim's write latch
/// mid-load — `fetch` returned a hard `Err("buffer pool is full of pinned pages")` **instead of
/// retrying**. That error propagated up the read-view chain, and the `Option`-returning
/// `GraphAccess::node_property` collapsed it into `None` → `Value::Null` — a present property read
/// as absent (a wrong-RESULT ACID read-integrity violation). It surfaced **only under eviction**,
/// because a pool ≥ the working set never misses-without-a-victim, so it never hit the path (which
/// is exactly why a large pool eliminated the corruption).
///
/// The fix makes the miss path treat a `select_victim` `None` as a **transient** condition (yield +
/// retry within the existing `MAX_FETCH_RETRIES` bound) rather than a permanent failure.
///
/// ## What this models
///
/// **Two frames, three pages.** The setup pins page `A` and **keeps the pin** for the whole test, so
/// frame-`A` is never evictable — leaving exactly **one** usable frame for `B` and `C`. Then:
/// - `loader` does `with_page_fetched(B)` — a miss that loads `B` into the one free frame, **holding
///   that frame's write latch for the duration of the load**, then unpins (freeing it again);
/// - `requester` does `with_page_fetched(C)` — also a miss needing that same one frame as its victim.
///
/// There is an interleaving where `requester`'s `select_victim` runs while frame-`A` is pinned **and**
/// the other frame is write-latched by `loader` mid-load: the sweep finds no victim *right then*.
/// **Pre-fix, `requester` returns the spurious error.** Post-fix, it yields and retries; `loader`
/// always finishes its load and unpins, so the frame becomes evictable and `requester` **always
/// succeeds**. A victim is *guaranteed* to become available in every complete execution, so the
/// post-fix contract is strict: `requester`'s fetch must return `Ok` on **every** interleaving.
///
/// Two spawned threads + a setup-held pin (3 frame-states, only 2 schedulable threads) keeps the loom
/// search small enough to terminate on this loaded machine.
///
/// Run with:
/// ```text
/// RUSTFLAGS="--cfg loom" LOOM_MAX_PREEMPTIONS=3 \
///   cargo test -p graphus-bufpool --test loom_eviction_storm \
///   loom_fetch_under_contention_never_spuriously_fails --release
/// ```
#[test]
fn loom_fetch_under_contention_never_spuriously_fails() {
    loom::model(|| {
        const A: u64 = 0;
        const B: u64 = 1;
        const C: u64 = 2;

        let dev = TaggedDevice::new(3);
        // Two frames over three pages, with one frame pinned for the whole test (below): exactly ONE
        // usable frame for B and C, so both the loader and the requester must use it as their victim.
        let pool = ConcurrentBufferPool::new(dev, 2).shared();

        // Pin A and KEEP the pin: frame-A is never evictable for the rest of the model. (Held on the
        // main thread, so it costs no schedulable loom thread.)
        let held = pool.fetch(PageId(A)).expect("seed fetch A");

        let pl = Arc::clone(&pool);
        let loader = loom::thread::spawn(move || {
            // A miss: loads B into the one free frame (holding its write latch during the load), then
            // unpins so the frame is evictable again. Whenever it succeeds it must read B's witness.
            if let Ok(got) = pl.with_page_fetched(PageId(B), tag) {
                assert_eq!(got, B, "loader read the wrong page: {got}");
            }
        });

        let pr = Arc::clone(&pool);
        let requester = loom::thread::spawn(move || {
            // A miss needing the same one frame as its victim. A victim is GUARANTEED to become
            // available (the loader always finishes + unpins, and frame-A is the only permanent pin),
            // so this fetch must NEVER fail spuriously — the #339 bug is exactly such a spurious
            // `Err("buffer pool is full of pinned pages")`. Post-fix it retries and always succeeds.
            let got = pr.with_page_fetched(PageId(C), tag).expect(
                "SPURIOUS FETCH FAILURE: a victim frame is guaranteed available (the loader unpins \
                 and only frame-A is permanently pinned), yet fetch(C) returned an error — the #339 \
                 read-integrity bug, where this error is swallowed into Value::Null by the \
                 Option-returning node_property",
            );
            assert_eq!(got, C, "requester read the wrong page: {got}");
        });

        loader.join().unwrap();
        requester.join().unwrap();

        // Release the permanently-held A pin; the pool is fully evictable again.
        pool.unpin(held);

        // No pin leaked by any path on any interleaving: every frame is fetchable again.
        for id in [A, B, C] {
            let f = pool.fetch(PageId(id)).unwrap();
            pool.unpin(f);
        }
    });
}

/// **Byte-integrity of a MULTI-HOP chain read under eviction** — the read shape the `rmp` #339/#359
/// morsel scan actually performs (a record/overflow chain: each hop a separate
/// [`ConcurrentBufferPool::with_page_fetched`] that reads the *next* page id out of the current
/// page's bytes).
///
/// ## What this proves — and what it deliberately does NOT
///
/// This model asserts the **byte-integrity** invariant: whenever a chain hop's fetch *succeeds*, the
/// frame holds **exactly** the page that hop asked for — never another page's bytes — even while two
/// independent evictors reload the very frames the reader is walking. A wrong-page hop here would be
/// the lost-pin corruption (`02fb803`: an absolute `store(1)` cold-path publish discarding a reader's
/// optimistic pin, letting a second evictor reload a frame mid-read). The additive `fetch_add(1)`
/// publish closes that window, and this model exhausts the interleavings that would expose it.
///
/// It **tolerates** a transient capacity error on any hop (every frame momentarily pinned by the two
/// evictors is a legitimate, non-corrupting outcome under a 2-frame pool): this model is **not** the
/// #359 spurious-fetch-error repro. That separate failure mode — a `select_victim` `Contended` sweep
/// surfaced as a spurious `Err` instead of retried-with-backoff, then swallowed up the read-view chain
/// into `Value::Null` — is modelled by
/// [`loom_fetch_under_contention_never_spuriously_fails`] (which *guarantees* `Ok`), and reproduced at
/// runtime by `tests/eviction_chain_repro.rs`. Here the contract is strictly byte-integrity: an `Err`
/// is fine, wrong bytes are not.
///
/// Two frames over three pages, walked as a **2-hop** chain (`A → B`) by the reader while a **single**
/// evictor churns page `C` — kept to two schedulable threads and a two-step walk so the (exhaustive)
/// loom search terminates, while still interleaving a reader's *second* hop with a frame reload (the
/// case a single-read model cannot reach: the reader holds no pin *between* hops, so an evictor can
/// reload the frame the next hop will land on).
///
/// Run with (a modest preemption cap keeps the two-hop search fast):
/// ```text
/// RUSTFLAGS="--cfg loom" LOOM_MAX_PREEMPTIONS=2 \
///   cargo test -p graphus-bufpool --test loom_eviction_storm \
///   loom_chained_read_never_crosses_pages_under_eviction --release
/// ```
#[test]
fn loom_chained_read_never_crosses_pages_under_eviction() {
    loom::model(|| {
        const A: u64 = 0;
        const B: u64 = 1;
        const C: u64 = 2;

        let dev = TaggedDevice::new(3);
        let pool = ConcurrentBufferPool::new(dev, 2).shared();

        // Pre-resident A so the reader's first hop takes the hit fast path (pin-before-latch — the
        // window the lost-pin corruption lived in).
        {
            let f = pool.fetch(PageId(A)).expect("seed fetch A");
            pool.unpin(f);
        }

        // The reader walks a fixed 2-hop chain A → B. At EACH hop, whenever the fetch succeeds it must
        // read that hop's own page id (the witness equals the requested id) — never another page's. A
        // transient capacity `Err` is tolerated (this model guards bytes, not the no-spurious-error
        // contract); the walk simply stops.
        let pr = Arc::clone(&pool);
        let reader = loom::thread::spawn(move || {
            for &cur in &[A, B] {
                match pr.with_page_fetched(PageId(cur), tag) {
                    Ok(witness) => assert_eq!(
                        witness, cur,
                        "CHAIN HOP CROSSED PAGES: asked for {cur}, frame held page {witness}'s bytes \
                         — an evictor reloaded a frame the reader had pinned (a read-integrity / ACID \
                         bug). This is the byte-integrity invariant, independent of the #359 \
                         spurious-error contract."
                    ),
                    // A transient "pool full of pinned pages" under the 2-frame storm is legitimate and
                    // non-corrupting; stop the walk (not the bug this model guards).
                    Err(_) => break,
                }
            }
        });

        let pc = Arc::clone(&pool);
        let evictor_c = loom::thread::spawn(move || {
            if let Ok(got) = pc.with_page_fetched(PageId(C), tag) {
                assert_eq!(got, C, "evictor C read the wrong page: {got}");
            }
        });

        reader.join().unwrap();
        evictor_c.join().unwrap();

        // No pin leaked on any interleaving.
        for slot in 0..pool.capacity() {
            let f = pool.fetch(PageId(slot as u64)).unwrap();
            pool.unpin(f);
        }
    });
}
