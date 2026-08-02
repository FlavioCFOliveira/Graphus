//! **Lock-held tripwires**: debug-build guards proving that no durability barrier is ever issued
//! while a lock that must not span I/O is held.
//!
//! Two are defined here, one per lock that was measured to convoy behind a barrier:
//!
//! * the **frame-latch tripwire** ([`FrameLatchScope`], `rmp` #974) — the buffer pool's per-frame
//!   latch;
//! * the **doublewrite-lock tripwire** ([`DwbLockScope`], `rmp` #993) — the mutex guarding the
//!   doublewrite buffer's device.
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
