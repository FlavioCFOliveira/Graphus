//! **Lock-held tripwires**: debug-build guards proving that no durability barrier is ever issued
//! while a lock that must not span I/O is held.
//!
//! Three are defined here:
//!
//! * the **frame-latch tripwire** ([`FrameLatchScope`], `rmp` #974) — the buffer pool's per-frame
//!   latch;
//! * the **doublewrite-lock tripwire** ([`DwbLockScope`], `rmp` #993) — the mutex guarding the
//!   doublewrite buffer's device;
//! * the **allocator-latch tripwire** ([`AllocLatchScope`], `rmp` #1012) — the per-store physical-id
//!   allocation latch.
//!
//! The first two were each *measured* to convoy behind a barrier and then hoisted out. The third is
//! the same guarantee stated **before** the convoy can be built: the allocation latch is new, and it
//! sits at rank 25 of the lock order (see [`AllocLatchScope`]) precisely on the promise that it is
//! never held across I/O. A promise nobody checks is a promise that lasts until the next refactor.
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
/// Graphus orders its latches by rank, innermost last: **10** catalog/DDL, **20** commit sequencer
/// and active-transaction table, **25** the allocation latch, **30** WAL, **40** buffer-pool frame
/// latch, **50** page-table shard, **60** device and doublewrite stager. An acquisition out of rank
/// order is permitted only as a `try_lock`, which creates no wait edge.
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

    /// The three tripwires are independent counters: holding one must not trip another's assertion.
    #[test]
    fn alloc_scope_does_not_trip_the_other_tripwires() {
        let _scope = AllocLatchScope::new();
        #[cfg(debug_assertions)]
        assert_eq!(alloc_latch_depth(), 1);
        assert_no_frame_latch_held("unrelated barrier");
        assert_no_dwb_lock_held("unrelated barrier");
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
