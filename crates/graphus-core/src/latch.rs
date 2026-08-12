//! **Lock-held tripwires**: debug-build guards proving that no durability barrier is ever issued
//! while a lock that must not span I/O is held.
//!
//! Seven are defined here:
//!
//! * the **engine-latch tripwire** ([`EngineLatchScope`], `rmp` #1038) — the server's per-engine
//!   session latches (the open-transaction table, the parked-statement queue, the plan cache);
//! * the **catalog-latch tripwire** ([`CatalogLatchScope`], `rmp` #1015) — the outermost latch of the
//!   storage stack, over the tokens, the schema counters, the metadata page chain and the DDL catalog;
//! * the **frame-latch tripwire** ([`FrameLatchScope`], `rmp` #974) — the buffer pool's per-frame
//!   latch;
//! * the **doublewrite-lock tripwire** ([`DwbLockScope`], `rmp` #993) — the mutex guarding the
//!   doublewrite buffer's device;
//! * the **maintenance-latch tripwire** ([`MaintenanceLatchScope`], `rmp` #1014) — the single latch
//!   over the GC's pending-work sets;
//! * the **allocator-latch tripwire** ([`AllocLatchScope`], `rmp` #1012) — the per-store physical-id
//!   allocation latch;
//! * the **page-order-latch tripwire** ([`PageOrderLatchScope`], `rmp` #1028/#1062) — the sharded
//!   latch that makes one logged page write — append the record, apply it to the page — atomic.
//!
//! [`FrameLatchScope`] and [`DwbLockScope`] were each *measured* to convoy behind a barrier and then
//! hoisted out. The rest state the same guarantee **before** the convoy can be built: each of those
//! latches was new, and each sits at its rank precisely on a promise about what it is not held across.
//! A promise nobody checks is a promise that lasts until the next refactor — and [`EngineLatchScope`]
//! is the case that proves it, since the promise it now checks had been written in a doc-comment and
//! broken by every call site the same comment described.
//!
//! # Why this exists
//!
//! The buffer pool's eviction write-back used to run entirely under the victim frame's write latch,
//! and inside that latch it hardened the write-ahead log — a chain of
//! *frame latch → WAL mutex → `fdatasync`*. Because the WAL mutex is shared with the store's own
//! commit path, one eviction's `fdatasync` convoyed every other evictor **and** every concurrent
//! commit behind it. `rmp` #974 hoisted that harden out from under the latch.
//!
//! "Hoisted" is easy to *say* and easy to regress: a later refactor that reintroduces an
//! `ensure_durable` call inside a latched region would silently restore the convoy, and no unit test
//! that only checks *results* would notice. This module makes the property **mechanically checked**
//! instead of visually reviewed: the buffer pool marks the regions where it holds a frame latch, and
//! the durability primitives assert that no such region is active when they run.
//!
//! # Cost
//!
//! Everything here is gated on `debug_assertions`. In a release build [`FrameLatchScope`] is a
//! zero-sized no-op, [`frame_latch_depth`] is a constant `0`, and [`assert_no_frame_latch_held`]
//! compiles away entirely — the production path pays nothing. The `cargo test` profile has
//! `debug_assertions` on by default, so the whole workspace test suite (including the DST scenarios
//! and the crash/recovery batteries) exercises the tripwire on every run.
//!
//! # Scope of each guarantee
//!
//! **Frame latch (`rmp` #974).** Covers the **write-ahead-log** barrier — the one whose mutex is
//! shared with the store's commit path. The doublewrite-staging and home-file barriers still run
//! under the victim's frame latch by construction: the frame's bytes must not change while they are
//! in flight. What `rmp` #974 removed was their hold on the pool's *device* lock, which is what
//! concurrent readers contend on. Taking them out of the frame latch as well needs the
//! PostgreSQL-style split of "content lock" from "I/O in progress" and remains a documented
//! follow-up.
//!
//! **Doublewrite lock (`rmp` #993).** Covers the doublewrite **staging** barrier. Measurement showed
//! that lock held across its own `fdatasync` — ~96 % of each hold — which capped evictions at
//! ~1750/s no matter how large the buffer pool was, because every evictor stages through it. The
//! barrier now runs with the lock released, and this tripwire is what keeps it there.
//!
//! A device that offers no shared [`graphus_io::SyncHandle`] (the in-memory DST device; the
//! encrypted device, whose sync also persists an AEAD nonce counter and so genuinely needs `&mut`)
//! keeps the barrier under the lock. Those callers therefore do **not** arm the scope — the
//! invariant is "when a `&self` barrier is available, it runs outside the lock", and arming a
//! tripwire over a path that cannot satisfy it would only produce a false alarm. See
//! `graphus_storage::dwb::DwbPageStager`.

/// The current thread's frame-latch nesting depth.
///
/// Non-zero means this thread is inside a region where it holds at least one buffer-pool frame
/// latch. Always `0` in a release build.
#[cfg(debug_assertions)]
#[must_use]
pub fn frame_latch_depth() -> u32 {
    DEPTH.with(std::cell::Cell::get)
}

/// The current thread's frame-latch nesting depth. Always `0` in a release build (the tripwire is
/// compiled out).
#[cfg(not(debug_assertions))]
#[must_use]
pub const fn frame_latch_depth() -> u32 {
    0
}

#[cfg(debug_assertions)]
thread_local! {
    static DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// An RAII marker for a region in which the current thread holds a buffer-pool frame latch.
///
/// Construct one alongside the latch guard and keep it alive for exactly as long as the guard. It is
/// re-entrant (the depth is a counter, not a flag), so nested or multiply-held latches — the batch
/// flush paths hold one per dirty frame — are counted correctly.
#[derive(Debug)]
pub struct FrameLatchScope {
    /// Makes the type both non-constructible outside [`FrameLatchScope::new`] — so the depth can
    /// never be decremented without a matching increment — and **`!Send` / `!Sync`**.
    ///
    /// The thread-affinity half is load-bearing: the depth is a `thread_local`, so a scope created
    /// on thread A and dropped on thread B would leave A's depth permanently non-zero (every later
    /// barrier on A would panic in a debug build) while saturating B's at zero. A raw pointer is the
    /// standard way to express "this value belongs to the thread that made it", and it makes the
    /// invariant a compile error rather than a convention. The guards this scope accompanies
    /// (`RwLockWriteGuard`) are already `!Send`, so nothing is lost.
    _private: std::marker::PhantomData<*const ()>,
}

impl FrameLatchScope {
    /// Enters a frame-latch region on the current thread.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        #[cfg(debug_assertions)]
        DEPTH.with(|d| d.set(d.get().saturating_add(1)));
        Self {
            _private: std::marker::PhantomData,
        }
    }
}

impl Default for FrameLatchScope {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for FrameLatchScope {
    #[inline]
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

/// The current thread's doublewrite-lock nesting depth (`rmp` #993).
///
/// Non-zero means this thread is inside a region where it holds the doublewrite buffer's device
/// mutex. Always `0` in a release build.
#[cfg(debug_assertions)]
#[must_use]
pub fn dwb_lock_depth() -> u32 {
    DWB_DEPTH.with(std::cell::Cell::get)
}

/// The current thread's doublewrite-lock nesting depth. Always `0` in a release build.
#[cfg(not(debug_assertions))]
#[must_use]
pub const fn dwb_lock_depth() -> u32 {
    0
}

#[cfg(debug_assertions)]
thread_local! {
    static DWB_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// An RAII marker for a region in which the current thread holds the doublewrite device mutex
/// (`rmp` #993).
///
/// Construct one alongside the mutex guard and keep it alive for exactly as long as the guard. Like
/// [`FrameLatchScope`] it is `!Send`/`!Sync`, because the depth is a thread-local and a scope
/// created on one thread and dropped on another would corrupt both threads' counters.
#[derive(Debug)]
pub struct DwbLockScope {
    _private: std::marker::PhantomData<*const ()>,
}

impl DwbLockScope {
    /// Enters a doublewrite-lock region on the current thread.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        #[cfg(debug_assertions)]
        DWB_DEPTH.with(|d| d.set(d.get().saturating_add(1)));
        Self {
            _private: std::marker::PhantomData,
        }
    }
}

impl Default for DwbLockScope {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for DwbLockScope {
    #[inline]
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        DWB_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

/// Panics (debug builds only) if the current thread holds the doublewrite device mutex.
///
/// Call this at every durability barrier that `rmp` #993 moved out of that mutex. `site` names the
/// barrier so a failure points straight at the offending path.
///
/// # Panics
/// Panics in a debug build if [`dwb_lock_depth`] is non-zero. Compiled out in release.
#[inline]
pub fn assert_no_dwb_lock_held(site: &str) {
    #[cfg(debug_assertions)]
    {
        let depth = dwb_lock_depth();
        assert!(
            depth == 0,
            "{site}: a durability barrier (fsync/fdatasync) was issued while holding the \
             doublewrite device mutex ({depth} deep). This is the `rmp` #993 convoy: every evictor \
             stages through that mutex, so a barrier inside it serialises all of them regardless of \
             buffer-pool size. Issue the barrier with the lock released (see `graphus_core::latch`)."
        );
    }
    let _ = site;
}

/// Panics (debug builds only) if the current thread holds a buffer-pool frame latch.
///
/// Call this at the top of every durability barrier that `rmp` #974 hoisted out from under the frame
/// latch. `site` names the barrier so a failure points straight at the offending path.
///
/// # Panics
/// Panics in a debug build if [`frame_latch_depth`] is non-zero. Compiled out in release.
#[inline]
pub fn assert_no_frame_latch_held(site: &str) {
    #[cfg(debug_assertions)]
    {
        let depth = frame_latch_depth();
        assert!(
            depth == 0,
            "{site}: a durability barrier (fsync/fdatasync) was issued while holding {depth} \
             buffer-pool frame latch(es). This is the `rmp` #974 convoy: the barrier serialises \
             every concurrent reader and every commit behind this latch. Hoist the barrier out of \
             the latched region (see `graphus_core::latch`)."
        );
    }
    let _ = site;
}

/// Whether the current thread holds a store's physical-id allocation latch — `0` or `1`, never more
/// (`rmp` #1012).
///
/// Unlike [`frame_latch_depth`] this is a flag rather than a nesting count, because rank 25 admits at
/// most one holder per thread: [`AllocLatchScope::new`] panics on a second. Always `0` in a release
/// build.
#[cfg(debug_assertions)]
#[must_use]
pub fn alloc_latch_depth() -> u32 {
    ALLOC_DEPTH.with(std::cell::Cell::get)
}

/// Whether the current thread holds a store's allocation latch. Always `0` in a release build.
#[cfg(not(debug_assertions))]
#[must_use]
pub const fn alloc_latch_depth() -> u32 {
    0
}

#[cfg(debug_assertions)]
thread_local! {
    static ALLOC_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// An RAII marker for a region in which the current thread holds a store's physical-id allocation
/// latch (`rmp` #1012).
///
/// # The rank, and the rule it encodes
///
/// Graphus orders its latches by rank, innermost last: **5** the engine's session latches, **10**
/// catalog/DDL, **20** commit sequencer and active-transaction table, **22** the maintenance latch,
/// **25** the allocation latch, **27** the page log-apply-order latch, **30** WAL, **40**
/// buffer-pool frame latch, **50** page-table shard, **60** device and doublewrite stager. An
/// acquisition out of rank order is permitted only as a `try_lock`, which creates no wait edge.
///
/// Rank 25 says two things. Below the active-transaction table (20), because allocating or freeing an
/// id happens inside a transaction that records the pop or push in that table. Above the WAL (30) and
/// everything under it, because the allocation latch is **released before any I/O**: allocating a
/// fresh id may have to map its store page, which grows the device, fetches pages, may evict, and may
/// harden the log. Holding the latch across that chain would convoy every allocator in the database
/// behind one `fdatasync` — the `rmp` #974 / #993 shape, arriving by a new route.
///
/// This tripwire enforces **both** of the rank's obligations, and they need different mechanisms:
///
/// * *not held across I/O* — [`assert_no_alloc_latch_held`], called at the points that must find the
///   latch already released (store-page growth, the WAL barrier);
/// * *at most one holder per thread* — the assertion in [`new`](Self::new). Two locks of the SAME
///   rank cannot be ordered by rank at all, so two threads acquiring a different pair in a different
///   order deadlock. A depth counter alone could not see this: it cannot tell "held" from "held
///   twice", and the interleaving that deadlocks is exactly the one it would miss.
///
/// Like the other two scopes it is `!Send`/`!Sync`, because the depth is a thread-local and a scope
/// created on one thread and dropped on another would corrupt both threads' counters. The
/// `MutexGuard` it accompanies is already `!Send`, so nothing is lost.
#[derive(Debug)]
pub struct AllocLatchScope {
    _private: std::marker::PhantomData<*const ()>,
}

impl AllocLatchScope {
    /// Enters an allocation-latch region on the current thread.
    ///
    /// # Panics
    /// Panics in a debug build if this thread **already** holds an allocation latch. Unlike
    /// [`FrameLatchScope`], this scope is deliberately **not** re-entrant — see below. Compiled out in
    /// release, where the whole tripwire is a no-op.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        // Rank 22 is a LEAF (`rmp` #1014): reaching an inner latch while holding it is a violation
        // even though 22 < 25 makes the *order* legal. Checked here because this is the acquisition,
        // and the acquisition is the only place that can see it.
        assert_no_maintenance_latch_held("AllocLatchScope::new");
        #[cfg(debug_assertions)]
        ALLOC_DEPTH.with(|d| {
            // Rank 25 admits AT MOST ONE holder per thread, and this is where that is enforced
            // (`rmp` #1012). The frame latch counts a depth because a batch flush legitimately holds
            // one latch per dirty frame; two *allocation* latches at once are a different animal —
            // they are two locks of the SAME rank, which the rank order cannot sequence, so two
            // threads taking a different pair in a different order is a textbook lock-order-inversion
            // deadlock. Nothing in the store needs it: every composite decision lives inside one
            // store's `AllocGuard`, and the six stores allocate independently.
            //
            // Without this assertion the tripwire could not tell "held" from "held twice" — the
            // counter carries no store identity and `assert_no_alloc_latch_held` only tests for zero —
            // so the one interleaving that actually deadlocks would be the one it could not see. The
            // reachable shape is `AllocGuard::claim_run`, whose closure runs WITH the latch held: a
            // closure that reached for a second store's allocator would deadlock two threads and pass
            // every test.
            assert!(
                d.get() == 0,
                "a second store allocation latch was taken while this thread already holds one. \
                 Rank 25 is not re-entrant and admits one holder per thread (`rmp` #1012): two locks \
                 of the same rank cannot be ordered by rank, so two threads acquiring a different \
                 pair in a different order deadlock. Restructure so the decision needs one store's \
                 latch, or take them strictly one after the other (see `graphus_core::latch`)."
            );
            d.set(1);
        });
        Self {
            _private: std::marker::PhantomData,
        }
    }
}

impl Default for AllocLatchScope {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for AllocLatchScope {
    #[inline]
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        ALLOC_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

/// Panics (debug builds only) if the current thread holds a store's physical-id allocation latch.
///
/// Call this at every point the allocation latch must already have been released: the durability
/// barrier, and the store-page growth path an allocation hands off to. `site` names the point so a
/// failure points straight at the offending path.
///
/// # Panics
/// Panics in a debug build if [`alloc_latch_depth`] is non-zero. Compiled out in release.
#[inline]
pub fn assert_no_alloc_latch_held(site: &str) {
    #[cfg(debug_assertions)]
    {
        let depth = alloc_latch_depth();
        assert!(
            depth == 0,
            "{site}: reached while holding {depth} store allocation latch(es). That latch is rank 25 \
             and must be released before any I/O (`rmp` #1012): held across page growth or a \
             durability barrier it convoys every allocator in the database behind one fdatasync, and \
             it takes rank-30..60 locks out of order. Drop the guard first (see `graphus_core::latch`)."
        );
    }
    let _ = site;
}

/// Whether the current thread holds a page log-apply-order latch — `0` or `1`, never more
/// (`rmp` #1028, widened to every logged page write by `rmp` #1062).
///
/// Like [`alloc_latch_depth`] this is a flag rather than a nesting count: rank 27 admits at most one
/// holder per thread. Always `0` in a release build.
#[cfg(debug_assertions)]
#[must_use]
pub fn page_order_latch_depth() -> u32 {
    PAGE_ORDER_DEPTH.with(std::cell::Cell::get)
}

/// Whether the current thread holds a page log-apply-order latch. Always `0` in a release build.
#[cfg(not(debug_assertions))]
#[must_use]
pub const fn page_order_latch_depth() -> u32 {
    0
}

#[cfg(debug_assertions)]
thread_local! {
    static PAGE_ORDER_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    /// The device page the held rank-27 latch is keyed by. Meaningful only while
    /// [`page_order_latch_depth`] is `1`; rank 27 admits one holder per thread, so one cell suffices.
    static PAGE_ORDER_PAGE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The device page whose log-apply-order latch this thread holds, or [`None`] when it holds none
/// (`rmp` #1062). Always [`None`] in a release build.
#[cfg(debug_assertions)]
#[must_use]
pub fn page_order_latch_page() -> Option<u64> {
    (page_order_latch_depth() != 0).then(|| PAGE_ORDER_PAGE.with(std::cell::Cell::get))
}

/// The device page whose log-apply-order latch this thread holds. Always [`None`] in a release build.
#[cfg(not(debug_assertions))]
#[must_use]
pub const fn page_order_latch_page() -> Option<u64> {
    None
}

/// Panics (debug builds only) unless this thread holds `page`'s log-apply-order latch (`rmp` #1062).
///
/// This is the other half of the rank-27 guarantee, and the half a doc-comment cannot keep. The latch
/// buys "log order is apply order" only while **every** logged write to a page goes through it: one
/// site that appends a record for `page` outside the section re-opens the whole defect, silently, and
/// no result-checking test would notice — both the live image and the replayed image stay internally
/// consistent, they simply stop being the same image. Called from the store's single WAL-append door
/// (`RecordStore::log_page_record`), so a new write path that forgets the section fails loudly on its
/// first append instead of shipping.
///
/// # Panics
/// Panics in a debug build if no rank-27 latch is held, or one is held for a different page.
/// Compiled out in release.
#[inline]
pub fn assert_page_order_held_for(page: u64, site: &str) {
    #[cfg(debug_assertions)]
    {
        let held = page_order_latch_page();
        assert!(
            held == Some(page),
            "{site}: a WAL record was appended against page {page} while this thread holds \
             {held:?}'s log-apply-order latch. Every logged page write must append AND apply inside \
             one rank-27 section keyed by that page (`rmp` #1062), or the order records enter the log \
             stops matching the order they take effect and ARIES rebuilds an image the live system \
             never held. Wrap the write in `RecordStore::in_page_order` (see `graphus_core::latch`)."
        );
    }
    let _ = (page, site);
}

/// An RAII marker for a region in which the current thread holds a page **log-apply-order** latch
/// (`rmp` #1028; widened from chain heads to every logged page write by `rmp` #1062).
///
/// # What it serialises, and why it is keyed by PAGE
///
/// One acquisition covers one indivisible **(append the record, apply it to the page)** pair. The
/// property it buys is that, for a given page, *log order is apply order* — the order in which
/// records enter the WAL is the order in which they take effect on that page's cached image.
///
/// The key is the **device page id**, not the record: `page_lsn` is a property of the page, ARIES
/// gates redo on it (`record.lsn > page_lsn`), and recovery replays in log order. Two writers of two
/// *different records that share a page* therefore have to be ordered exactly as much as two writers
/// of one record do, and `rmp` #1028's original per-record key did not order them. Measured
/// (`rmp` #1062, 2026-08-12): the `det_scheduler_checkpoint_inversion_1055` scenario — two writers,
/// four commits each, sixteen seeds — produced **32** page-LSN descents, and **not one of them on a
/// chain head**: the catalog image, the commit slot, the undo area and a node's label word. Those are
/// pages whose content reflected one order while the log reflected another, so a reopen rebuilt an
/// image the live system never held.
///
/// # The rank, and the rule it encodes
///
/// Rank **27**, between the allocation latch (25) and the WAL (30) — see [`AllocLatchScope`] for the
/// full order. That position is the whole design of the latch, and it is forced from both sides:
///
/// * **Below the WAL (30) and the frame latch (40)**, because a logged page write *is* the sequence
///   "append the redo record, then apply it to the page". Those two must happen in one indivisible
///   step, or the order in which changes enter the log stops matching the order in which they take
///   effect — and ARIES replays in log order, so recovery would then reach a different verdict from
///   the live system and the *replayed* one is what survives the crash. The latch is what makes that
///   one step; it must therefore be outside both locks it serialises. Doing it the other way round —
///   appending under the frame latch — is not an option: it inverts ranks 30 and 40, and the WAL
///   barrier already refuses by tripwire to run with a frame latch held ([`FrameLatchScope`]).
/// * **Above everything that does I/O**, and hence never held across a durability barrier: it is
///   taken only once the page is already resident and pinned, and released before the frame is
///   unpinned. Held across a barrier it would convoy every writer of the same shard behind one
///   `fdatasync` — the `rmp` #974 / #993 / #1012 shape arriving by a fourth route.
///
/// As with rank 25, **at most one holder per thread**: two locks of the same rank cannot be ordered
/// by rank, so two threads acquiring a different pair in a different order deadlock. Nothing needs
/// two: a write that spans two pages (a catalog image across the metadata chain, a rollback's
/// compensations) takes them strictly one after the other, precisely so that this stays true.
///
/// `!Send`/`!Sync` for the same reason as its siblings — the depth is a thread-local, and a scope
/// created on one thread and dropped on another would corrupt both threads' counters.
#[derive(Debug)]
pub struct PageOrderLatchScope {
    _private: std::marker::PhantomData<*const ()>,
}

impl PageOrderLatchScope {
    /// Enters a page log-apply-order region on the current thread.
    ///
    /// # Panics
    /// Panics in a debug build if this thread **already** holds a page-order latch (rank 27 is not
    /// re-entrant — see above). Compiled out in release.
    #[must_use]
    #[inline]
    pub fn new(page: u64) -> Self {
        // Rank 22 is a LEAF (`rmp` #1014); see `AllocLatchScope::new` for why the check belongs at the
        // acquisition rather than at the barrier.
        assert_no_maintenance_latch_held("PageOrderLatchScope::new");
        // The re-entrancy check runs BEFORE the page is recorded (`rmp` #1062, audit Q4-a). Recording
        // first would let a refused nested acquisition overwrite the OUTER section's page on its way
        // to panicking — harmless only while nothing catches the panic, and the engine's worker loop
        // does exactly that (`catch_unwind`, `rmp` #409/#414). After such a catch the outer section
        // would still be held, but `assert_page_order_held_for` would be comparing against the inner
        // page and would either wave through an append against the wrong page or reject a correct one.
        #[cfg(debug_assertions)]
        PAGE_ORDER_DEPTH.with(|d| {
            assert!(
                d.get() == 0,
                "a second page log-apply-order latch was taken while this thread already holds \
                 one. Rank 27 is not re-entrant and admits one holder per thread (`rmp` #1028): two \
                 locks of the same rank cannot be ordered by rank, so two threads acquiring a \
                 different pair in a different order deadlock. Write one page at a time (see \
                 `graphus_core::latch`)."
            );
            d.set(1);
        });
        // Recorded only once the acquisition is ACCEPTED, so the cell always names the page of the
        // section this thread actually holds.
        #[cfg(debug_assertions)]
        PAGE_ORDER_PAGE.with(|p| p.set(page));
        let _ = page;
        Self {
            _private: std::marker::PhantomData,
        }
    }
}

impl Drop for PageOrderLatchScope {
    #[inline]
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        PAGE_ORDER_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

/// Panics (debug builds only) if the current thread holds a page log-apply-order latch.
///
/// Call this at every point the latch must already have been released: the durability barrier, and
/// the page-fetch / store-growth paths that can evict (and therefore write home, and therefore
/// harden). `site` names the point so a failure points straight at the offending path.
///
/// # Panics
/// Panics in a debug build if [`page_order_latch_depth`] is non-zero. Compiled out in release.
#[inline]
pub fn assert_no_page_order_latch_held(site: &str) {
    #[cfg(debug_assertions)]
    {
        let depth = page_order_latch_depth();
        assert!(
            depth == 0,
            "{site}: reached while holding {depth} page log-apply-order latch(es). That latch is \
             rank 27 and must be released before any I/O (`rmp` #1028): held across page growth, a \
             page fetch that can evict, or a durability barrier, it convoys every writer of the \
             shard behind one fdatasync. Pin the page before taking it (see `graphus_core::latch`)."
        );
    }
    let _ = site;
}

/// Whether the current thread holds the maintenance latch — `0` or `1`, never more (`rmp` #1014).
///
/// A flag rather than a nesting count, for the same reason as [`alloc_latch_depth`]: rank 22 admits
/// at most one holder per thread. Always `0` in a release build.
#[cfg(debug_assertions)]
#[must_use]
pub fn maintenance_latch_depth() -> u32 {
    MAINTENANCE_DEPTH.with(std::cell::Cell::get)
}

/// Whether the current thread holds the maintenance latch. Always `0` in a release build.
#[cfg(not(debug_assertions))]
#[must_use]
pub const fn maintenance_latch_depth() -> u32 {
    0
}

#[cfg(debug_assertions)]
thread_local! {
    static MAINTENANCE_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// An RAII marker for a region in which the current thread holds the **maintenance latch** — the
/// single lock over the GC's pending-work sets (`rmp` #1014).
///
/// # What it guards, and why one latch is the right shape
///
/// The record stores keep a handful of in-memory sets naming work the next maintenance pass owes:
/// tombstones awaiting reclamation, undo chains awaiting release, relationship dead-link corpses
/// awaiting a splice, orphaned slots awaiting return to the free list, and a flag for unreclaimed
/// empty property cells. None of it is durable state — it is all rebuilt from the store on
/// `open` — and all of it moves at the cadence of **garbage collection**, not of OLTP: a writer
/// touches it once per tombstoned record, and the GC pass drains it once per tick.
///
/// That is why it is ONE latch and not five, and not a sharded one. The sprint's mandate is to
/// discard mechanisms that produce contention on the hot path, and this is not one of them: the
/// critical section is a `BTreeSet` insert. Splitting it would multiply the ranks that have to be
/// ordered against one another (see the "one holder per thread" rule below) and buy nothing
/// measurable. Sharding a lock that is not contended is how a lock ordering acquires a deadlock it
/// did not have.
///
/// # The rank, and the rule it encodes
///
/// Rank **22**, between the active-transaction table (20) and the allocation latch (25) — see
/// [`AllocLatchScope`] for the full order. In practice it is stronger than its rank: it is a **leaf**.
/// Nothing is acquired while it is held, and it is never held across I/O. Both obligations come from
/// the same place — the sets are drained by *snapshotting* them under the latch and then doing the
/// work with the latch released, because that work is page reads, WAL appends and slot frees. A pass
/// that iterated a set while it worked would hold a lock shared with every writer across an
/// `fdatasync`, which is the `rmp` #974 / #993 / #1012 convoy arriving by a fifth route.
///
/// As with ranks 25 and 27, **at most one holder per thread**: two locks of the same rank cannot be
/// ordered by rank, so two threads acquiring a different pair in a different order deadlock. Nothing
/// needs two — there is only one.
///
/// `!Send`/`!Sync` for the same reason as its siblings: the depth is a thread-local, and a scope
/// created on one thread and dropped on another would corrupt both threads' counters.
#[derive(Debug)]
pub struct MaintenanceLatchScope {
    _private: std::marker::PhantomData<*const ()>,
}

impl MaintenanceLatchScope {
    /// Enters a maintenance-latch region on the current thread.
    ///
    /// # Panics
    /// Panics in a debug build if this thread **already** holds the maintenance latch (rank 22 is not
    /// re-entrant — see above). Compiled out in release.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        #[cfg(debug_assertions)]
        MAINTENANCE_DEPTH.with(|d| {
            assert!(
                d.get() == 0,
                "a second maintenance latch was taken while this thread already holds one. Rank 22 \
                 is not re-entrant and admits one holder per thread (`rmp` #1014): two locks of the \
                 same rank cannot be ordered by rank, so two threads acquiring a different pair in a \
                 different order deadlock. Snapshot the set and drop the guard before doing the work \
                 (see `graphus_core::latch`)."
            );
            d.set(1);
        });
        Self {
            _private: std::marker::PhantomData,
        }
    }
}

impl Default for MaintenanceLatchScope {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for MaintenanceLatchScope {
    #[inline]
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        MAINTENANCE_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

/// Panics (debug builds only) if the current thread holds the maintenance latch.
///
/// Call this wherever the latch must already have been released: the durability barrier, the
/// store-growth and page-fetch paths that can evict, and the acquisition of any inner latch — rank 22
/// is a leaf, so *every* one of those is a violation, not merely the I/O ones. `site` names the point
/// so a failure points straight at the offending path.
///
/// # Panics
/// Panics in a debug build if [`maintenance_latch_depth`] is non-zero. Compiled out in release.
#[inline]
pub fn assert_no_maintenance_latch_held(site: &str) {
    #[cfg(debug_assertions)]
    {
        let depth = maintenance_latch_depth();
        assert!(
            depth == 0,
            "{site}: reached while holding {depth} maintenance latch(es). That latch is rank 22 and \
             is a LEAF (`rmp` #1014): nothing may be acquired while it is held, and it must never be \
             held across I/O — a pass that works while holding it convoys every writer that has a \
             record to tombstone behind one fdatasync. Snapshot the set, drop the guard, then work \
             (see `graphus_core::latch`)."
        );
    }
    let _ = site;
}

#[cfg(debug_assertions)]
thread_local! {
    static ENGINE_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Whether the current thread holds one of the engine's session latches — `0` or `1`, never more
/// (`rmp` #1038). Always `0` in a release build.
#[cfg(debug_assertions)]
#[must_use]
pub fn engine_latch_depth() -> u32 {
    ENGINE_DEPTH.with(std::cell::Cell::get)
}

/// Whether the current thread holds an engine session latch. Always `0` in a release build.
#[cfg(not(debug_assertions))]
#[must_use]
pub const fn engine_latch_depth() -> u32 {
    0
}

/// An RAII marker for a region in which the current thread holds one of the **engine's session
/// latches** (`rmp` #1038): the server's open-transaction table, its parked-statement queue, and its
/// compiled-plan cache — the state an engine worker consults to serve one client command.
///
/// # The rank, and the two rules it encodes
///
/// Rank **5** — OUTSIDE everything (see [`AllocLatchScope`] for the full order). A command handler
/// takes a session latch and then, if it needs to, descends into the storage stack: the catalog (10),
/// the active-transaction table (20), the WAL (30), the device (60). Every acquisition from rank 5 is
/// therefore *inward*, and nothing below it can reach back out — the storage layer holds no reference
/// to the engine's tables. Entering this scope while ANY inner latch is held is a rank inversion and
/// panics in a debug build, which is what makes that direction checked rather than assumed.
///
/// The two obligations of rank 5 need different mechanisms, exactly as at ranks 22/25/27:
///
/// * *at most one holder per thread* — the assertion in [`new`](Self::new). This is not a stylistic
///   preference, it is the whole point. The three latches sit at ONE rank rather than three ordered
///   ranks precisely so that nesting them is illegal: distinct ranks would legalise nesting, and
///   nesting is what produced the deadlock this scope was created to make impossible. The engine's age
///   sweep took *open → parked* while its resume and park paths took *parked → open*. With one table
///   per worker that inversion was invisible; the moment the tables are shared between workers
///   (`rmp` #1041) two workers close the cycle and the engine stops with no message at all. One rank
///   plus this assertion turns that silent two-thread hang into a loud, deterministic, single-threaded
///   panic at the second acquisition.
/// * *never held across statement execution* — [`assert_no_engine_latch_held`], called where a worker
///   begins running arbitrary work: a Cypher statement, a resumed batch, a bulk-import chunk, a
///   constraint validation that scans the data, and the blocking wait for the next command. A guard
///   that spans a statement is not a data-race hazard — it is a *throughput* hazard, and the worst
///   kind, because it is invisible to every test that only checks results: W workers still produce
///   correct answers while taking strict turns. Once the tables are shared it costs the whole of the
///   engine's parallelism (measured at 3.95 cores → 1.00 in
///   `graphus-server/tests/engine_latch_scaling_1038.rs`); while each worker owns its own it costs
///   nothing at all, which is the trap — the mistake is free until the commit that shares the state,
///   and that commit will look like the cause. In Rust it is also one character wide, since a
///   temporary guard created in argument position lives to the end of the enclosing statement —
///   which, for a call that runs a query, is the whole query.
///
/// `!Send`/`!Sync` like its siblings: the depth is a thread-local, so a scope created on one thread
/// and dropped on another would leave the first thread permanently latched and saturate the second at
/// zero. The `MutexGuard` it accompanies is already `!Send`, so nothing is lost.
#[derive(Debug)]
pub struct EngineLatchScope {
    _private: std::marker::PhantomData<*const ()>,
}

impl EngineLatchScope {
    /// Enters an engine-session-latch region on the current thread.
    ///
    /// # Panics
    /// Panics in a debug build if this thread already holds an engine session latch (rank 5 admits one
    /// holder per thread — see above), or if it holds any inner latch, which would mean rank 5 was
    /// taken second. Compiled out in release.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        #[cfg(debug_assertions)]
        {
            assert_no_frame_latch_held("EngineLatchScope::new");
            assert_no_maintenance_latch_held("EngineLatchScope::new");
            assert_no_alloc_latch_held("EngineLatchScope::new");
            assert_no_page_order_latch_held("EngineLatchScope::new");
            assert!(
                catalog_latch_depth() == 0,
                "EngineLatchScope::new: an engine session latch was taken while this thread holds the \
                 catalog latch. Rank 5 is OUTSIDE rank 10 (`rmp` #1038), so it is taken first or not \
                 at all; reaching back out for it from inside the storage stack is the one direction \
                 that closes a cycle (see `graphus_core::latch`)."
            );
            ENGINE_DEPTH.with(|d| {
                assert!(
                    d.get() == 0,
                    "a second engine session latch was taken while this thread already holds one. \
                     Rank 5 is not re-entrant and admits one holder per thread (`rmp` #1038): the \
                     open-transaction table, the parked-statement queue and the plan cache share one \
                     rank exactly so that nesting them is illegal, because two threads nesting a \
                     different pair in a different order deadlock. Take one, finish with it, release \
                     it, then take the next (see `graphus_core::latch`)."
                );
                d.set(1);
            });
        }
        Self {
            _private: std::marker::PhantomData,
        }
    }
}

impl Default for EngineLatchScope {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EngineLatchScope {
    #[inline]
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        ENGINE_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

/// Panics (debug builds only) if the current thread holds an engine session latch.
///
/// Call this wherever a worker is about to run work of unbounded duration — a statement, a resumed
/// batch, a bulk-import chunk, a data-scanning DDL validation — or to block waiting for its next
/// command. `site` names the point so a failure names the path that held on too long.
///
/// # Panics
/// Panics in a debug build if [`engine_latch_depth`] is non-zero. Compiled out in release.
#[inline]
pub fn assert_no_engine_latch_held(site: &str) {
    #[cfg(debug_assertions)]
    {
        let depth = engine_latch_depth();
        assert!(
            depth == 0,
            "{site}: reached while holding {depth} engine session latch(es). That latch is rank 5 and \
             must be released before any work of unbounded duration (`rmp` #1038): held across a \
             statement it serialises every worker of the engine onto one core while every result stays \
             correct, so no test that checks answers can see it. Copy what you need out of the table \
             under the latch, drop the guard, then execute (see `graphus_core::latch`)."
        );
    }
    let _ = site;
}

#[cfg(debug_assertions)]
thread_local! {
    static CATALOG_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Whether the current thread holds the catalog latch — `0` or `1`, never more (`rmp` #1015).
#[cfg(debug_assertions)]
#[must_use]
pub fn catalog_latch_depth() -> u32 {
    CATALOG_DEPTH.with(std::cell::Cell::get)
}

/// Whether the current thread holds the catalog latch. Always `0` in a release build.
#[cfg(not(debug_assertions))]
#[must_use]
pub const fn catalog_latch_depth() -> u32 {
    0
}

/// An RAII marker for a region in which the current thread holds the record store's **catalog latch**
/// (`rmp` #1015): the one lock over the token store, the schema generation counters, the metadata page
/// chain and the statistics/DDL catalog.
///
/// # The rank, and the rule it encodes
///
/// Rank **10** — the OUTERMOST latch in the order (see [`AllocLatchScope`] for the full list), and
/// that direction is the design rather than a leftover. A DDL mutation touches the catalog and then,
/// at commit, walks straight down through the active-transaction table (20), the allocator (25), the
/// WAL (30) and the device (60). Taking the catalog first makes every one of those acquisitions
/// *inward*, so no thread can hold an inner latch and then reach back out for the catalog — and a
/// cycle needs exactly one thread doing that.
///
/// The scope enforces it: entering while ANY inner latch is held is a rank inversion and panics in a
/// debug build. That is the mirror image of [`MaintenanceLatchScope`], which is a leaf and forbids
/// acquiring anything *under* it; between them the two ends of the order are pinned.
///
/// Unlike the maintenance latch this one MAY be held across I/O, deliberately: it sits above the WAL
/// in the order, and the operation it protects — checkpointing the catalog — *is* the I/O. What it
/// must not do is stand in the OLTP path's way, and it does not: a data transaction that changes no
/// catalog entry takes it only to read one flag.
///
/// # Why this is a latch and not a version chain
///
/// This makes concurrent DDL **safe**; it does not make the catalog **versioned**. A catalog mutation
/// still becomes visible to every transaction the moment the latch is released, and a rollback still
/// replays the transaction-scoped undo of `rmp` #734. Versioning the catalog under the same undo-chain
/// mechanism as records — so a reader sees the catalog as of its own snapshot — is `rmp` #984, and it
/// is a different change in kind: it alters what other transactions SEE, where this one only decides
/// who may touch the state at the same instant. Keeping them apart is deliberate; conflating them
/// would land a visibility change under tests that say nothing about visibility.
#[derive(Debug)]
pub struct CatalogLatchScope {
    _private: std::marker::PhantomData<*const ()>,
}

impl CatalogLatchScope {
    /// Enters a catalog-latch region on the current thread.
    ///
    /// # Panics
    /// Panics in a debug build if this thread already holds the catalog latch (rank 10 is not
    /// re-entrant), or if it holds any inner latch — rank 10 is taken first or not at all. Compiled
    /// out in release.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        #[cfg(debug_assertions)]
        {
            assert_no_frame_latch_held("CatalogLatchScope::new");
            assert_no_maintenance_latch_held("CatalogLatchScope::new");
            assert_no_alloc_latch_held("CatalogLatchScope::new");
            assert_no_page_order_latch_held("CatalogLatchScope::new");
            CATALOG_DEPTH.with(|d| {
                assert!(
                    d.get() == 0,
                    "a second catalog latch was taken while this thread already holds one. Rank 10 \
                     is not re-entrant and admits one holder per thread (`rmp` #1015): two locks of \
                     the same rank cannot be ordered by rank, so two threads acquiring a different \
                     pair in a different order deadlock. Perform the whole catalog mutation inside \
                     ONE `with_catalog` (see `graphus_core::latch`)."
                );
                d.set(1);
            });
        }
        Self {
            _private: std::marker::PhantomData,
        }
    }
}

impl Default for CatalogLatchScope {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for CatalogLatchScope {
    #[inline]
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        CATALOG_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_tracks_nesting_and_unwinds_to_zero() {
        assert_eq!(frame_latch_depth(), 0);
        {
            let _outer = FrameLatchScope::new();
            #[cfg(debug_assertions)]
            assert_eq!(frame_latch_depth(), 1);
            {
                let _inner = FrameLatchScope::new();
                #[cfg(debug_assertions)]
                assert_eq!(frame_latch_depth(), 2);
            }
            #[cfg(debug_assertions)]
            assert_eq!(frame_latch_depth(), 1);
        }
        assert_eq!(frame_latch_depth(), 0);
    }

    #[test]
    fn assert_passes_outside_a_latched_region() {
        assert_no_frame_latch_held("test barrier");
    }

    /// The tripwire must actually fire: a barrier issued inside a latched region panics in a debug
    /// build. Without this the guard could silently be a no-op and prove nothing.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "buffer-pool frame latch")]
    fn assert_fires_inside_a_latched_region() {
        let _scope = FrameLatchScope::new();
        assert_no_frame_latch_held("test barrier");
    }

    /// The allocation-latch tripwire (`rmp` #1012) must actually fire, exactly like the other two:
    /// a guard alive at a point that forbids it panics in a debug build.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "store allocation latch")]
    fn alloc_assert_fires_inside_a_latched_region() {
        let _scope = AllocLatchScope::new();
        assert_no_alloc_latch_held("test page growth");
    }

    #[test]
    fn alloc_assert_passes_outside_a_latched_region() {
        assert_eq!(alloc_latch_depth(), 0);
        assert_no_alloc_latch_held("test page growth");
    }

    /// **Positive control for the non-re-entrancy rule** (`rmp` #1012): taking a second rank-25 scope
    /// while one is alive must panic in a debug build. Without this the assertion in
    /// [`AllocLatchScope::new`] could be deleted and every test would still pass — the deadlock shape
    /// it forbids is precisely the one no test can otherwise observe.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "Rank 25 is not re-entrant")]
    fn a_second_alloc_scope_on_one_thread_is_refused() {
        let _first = AllocLatchScope::new();
        let _second = AllocLatchScope::new();
    }

    /// Sequential scopes are fine — the rule is against *simultaneous* holders, not against taking the
    /// latch twice in a row. (A rule that forbade the latter would make `set_reuse_barrier`'s
    /// six-store loop illegal, so this is what says the assertion is aimed at the right thing.)
    #[test]
    fn alloc_scopes_taken_one_after_another_are_fine() {
        for _ in 0..3 {
            let _s = AllocLatchScope::new();
        }
        assert_eq!(alloc_latch_depth(), 0);
    }

    /// The tripwires are independent counters: holding one must not trip another's assertion.
    #[test]
    fn alloc_scope_does_not_trip_the_other_tripwires() {
        let _scope = AllocLatchScope::new();
        #[cfg(debug_assertions)]
        assert_eq!(alloc_latch_depth(), 1);
        assert_no_frame_latch_held("unrelated barrier");
        assert_no_dwb_lock_held("unrelated barrier");
        assert_no_page_order_latch_held("unrelated barrier");
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "page log-apply-order latch")]
    fn page_order_assert_fires_inside_a_latched_region() {
        let _scope = PageOrderLatchScope::new(7);
        assert_no_page_order_latch_held("test durability barrier");
    }

    #[test]
    fn page_order_assert_passes_outside_a_latched_region() {
        assert_eq!(page_order_latch_depth(), 0);
        assert_no_page_order_latch_held("test durability barrier");
    }

    /// **Positive control for the non-re-entrancy rule** (`rmp` #1028), the rank-27 twin of
    /// [`a_second_alloc_scope_on_one_thread_is_refused`]: a relationship publishes its two endpoint
    /// heads one after the other, and this is what makes "one after the other" a checked property
    /// rather than a comment.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "Rank 27 is not re-entrant")]
    fn a_second_page_order_scope_on_one_thread_is_refused() {
        let _first = PageOrderLatchScope::new(7);
        let _second = PageOrderLatchScope::new(9);
    }

    /// Sequential scopes are fine — exactly the shape `create_rel` uses for its two endpoints.
    #[test]
    fn page_order_scopes_taken_one_after_another_are_fine() {
        for _ in 0..3 {
            let _s = PageOrderLatchScope::new(7);
        }
        assert_eq!(page_order_latch_depth(), 0);
    }

    #[test]
    fn page_order_scope_does_not_trip_the_other_tripwires() {
        let _scope = PageOrderLatchScope::new(7);
        #[cfg(debug_assertions)]
        assert_eq!(page_order_latch_depth(), 1);
        assert_no_frame_latch_held("unrelated barrier");
        assert_no_dwb_lock_held("unrelated barrier");
        assert_no_alloc_latch_held("unrelated barrier");
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "maintenance latch")]
    fn maintenance_assert_fires_inside_a_latched_region() {
        let _scope = MaintenanceLatchScope::new();
        assert_no_maintenance_latch_held("test durability barrier");
    }

    #[test]
    fn maintenance_assert_passes_outside_a_latched_region() {
        assert_eq!(maintenance_latch_depth(), 0);
        assert_no_maintenance_latch_held("test durability barrier");
    }

    /// **Positive control for the non-re-entrancy rule** (`rmp` #1014), the rank-22 twin of
    /// [`a_second_alloc_scope_on_one_thread_is_refused`].
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "Rank 22 is not re-entrant")]
    fn a_second_maintenance_scope_on_one_thread_is_refused() {
        let _first = MaintenanceLatchScope::new();
        let _second = MaintenanceLatchScope::new();
    }

    /// Sequential scopes are fine — a GC pass drains one set after another.
    #[test]
    fn maintenance_scopes_taken_one_after_another_are_fine() {
        for _ in 0..3 {
            let _s = MaintenanceLatchScope::new();
        }
        assert_eq!(maintenance_latch_depth(), 0);
    }

    /// **Positive control for the LEAF rule** (`rmp` #1014). Rank 22 sits *outside* rank 25, so the
    /// lock order alone permits taking the allocation latch while holding the maintenance latch — and
    /// permitting it is exactly the mistake: the allocator's holder goes on to grow the store. Without
    /// this test the `assert_no_maintenance_latch_held` call in [`AllocLatchScope::new`] could be
    /// deleted and nothing else in the suite would notice.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "AllocLatchScope::new")]
    fn taking_the_allocation_latch_under_the_maintenance_latch_is_refused() {
        let _maintenance = MaintenanceLatchScope::new();
        let _alloc = AllocLatchScope::new();
    }

    /// The leaf rule's rank-27 twin.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "PageOrderLatchScope::new")]
    fn taking_the_page_order_latch_under_the_maintenance_latch_is_refused() {
        let _maintenance = MaintenanceLatchScope::new();
        let _publish = PageOrderLatchScope::new(7);
    }

    #[test]
    fn maintenance_scope_does_not_trip_the_other_tripwires() {
        let _scope = MaintenanceLatchScope::new();
        #[cfg(debug_assertions)]
        assert_eq!(maintenance_latch_depth(), 1);
        assert_no_frame_latch_held("unrelated barrier");
        assert_no_dwb_lock_held("unrelated barrier");
        assert_no_alloc_latch_held("unrelated barrier");
        assert_no_page_order_latch_held("unrelated barrier");
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "engine session latch")]
    fn engine_assert_fires_inside_a_latched_region() {
        let _scope = EngineLatchScope::new();
        assert_no_engine_latch_held("test statement execution");
    }

    #[test]
    fn engine_assert_passes_outside_a_latched_region() {
        assert_eq!(engine_latch_depth(), 0);
        assert_no_engine_latch_held("test statement execution");
    }

    /// **Positive control for the non-re-entrancy rule** (`rmp` #1038) — the rank-5 twin of
    /// [`a_second_alloc_scope_on_one_thread_is_refused`], and the one that stands in for the ABBA the
    /// engine actually had: its age sweep took *open → parked* while its resume path took
    /// *parked → open*. Both are rank 5, so the second acquisition panics here on ONE thread instead
    /// of hanging two.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "Rank 5 is not re-entrant")]
    fn a_second_engine_scope_on_one_thread_is_refused() {
        let _first = EngineLatchScope::new();
        let _second = EngineLatchScope::new();
    }

    /// Sequential scopes are fine — the rule forbids *simultaneous* holders, not consulting one table
    /// after another. (A rule against the latter would outlaw the age sweep, which reads the parked
    /// queue and then mutates the open-transaction table.)
    #[test]
    fn engine_scopes_taken_one_after_another_are_fine() {
        for _ in 0..3 {
            let _s = EngineLatchScope::new();
        }
        assert_eq!(engine_latch_depth(), 0);
    }

    /// **Positive control for the outermost rule** (`rmp` #1038). Rank 5 sits outside rank 10, so an
    /// engine latch taken while the catalog latch is held is the one direction that closes a cycle.
    /// Without this test the `catalog_latch_depth` assertion in [`EngineLatchScope::new`] could be
    /// deleted and nothing else in the suite would notice.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "EngineLatchScope::new")]
    fn taking_an_engine_latch_under_the_catalog_latch_is_refused() {
        let _catalog = CatalogLatchScope::new();
        let _engine = EngineLatchScope::new();
    }

    /// The legal direction, and the reason the previous test is about direction rather than about the
    /// pair: rank 5 first, then rank 10, is exactly what a DDL command does.
    #[test]
    fn taking_the_catalog_latch_under_an_engine_latch_is_allowed() {
        let engine = EngineLatchScope::new();
        {
            let _catalog = CatalogLatchScope::new();
            #[cfg(debug_assertions)]
            assert_eq!(catalog_latch_depth(), 1);
        }
        drop(engine);
        assert_eq!(engine_latch_depth(), 0);
    }

    #[test]
    fn engine_scope_does_not_trip_the_other_tripwires() {
        let _scope = EngineLatchScope::new();
        #[cfg(debug_assertions)]
        assert_eq!(engine_latch_depth(), 1);
        assert_no_frame_latch_held("unrelated barrier");
        assert_no_dwb_lock_held("unrelated barrier");
        assert_no_alloc_latch_held("unrelated barrier");
        assert_no_page_order_latch_held("unrelated barrier");
        assert_no_maintenance_latch_held("unrelated barrier");
    }

    /// The depth is **per thread**: one thread's latched region must not make another thread's
    /// barrier trip the wire (the counter is a `thread_local`, not a global).
    #[test]
    fn depth_is_per_thread() {
        let _scope = FrameLatchScope::new();
        std::thread::spawn(|| {
            assert_eq!(frame_latch_depth(), 0);
            assert_no_frame_latch_held("other thread barrier");
        })
        .join()
        .expect("joined");
    }
}
