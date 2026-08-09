//! [`SharedCell`] — the coordinator's shared-state wrapper: `Arc<Mutex<T>>` with `RefCell`'s
//! **ergonomics** and, in a debug build, `RefCell`'s **failure mode** (`rmp` #1010, layer 2 of #975).
//!
//! # Why this type exists at all
//!
//! [`TxnCoordinator`](crate::coordinator::TxnCoordinator) shares six pieces of state — the record
//! store, the SSI tracker, the index set, the column cache, the zone map and the CSR adjacency — with
//! every statement seam it hands out. Those six used to be `Rc<RefCell<…>>`, which is what kept the
//! coordinator `!Send` even after `rmp` #1009 made all six *contents* `Send + Sync`. Replacing the
//! packaging with `Arc<Mutex<…>>` is the whole of layer 2.
//!
//! The conversion is mechanical. Its **risk is not**, and that risk is the entire reason this is a
//! named type rather than a bare `Arc<Mutex<T>>`:
//!
//! > A double borrow of a [`RefCell`](std::cell::RefCell) **panics loudly**, on the spot, with a
//! > stack trace pointing at the offending re-entrancy. The same double acquisition of a
//! > non-reentrant [`Mutex`] **hangs forever**, with no message, no trace, and no failing test —
//! > just a wedged thread.
//!
//! That exact trade has already bitten this project once. `graphus_storage::wal_rule` records that
//! the `rmp` #337 audit proved a live rollback whose working set exceeds the buffer pool's capacity
//! *deadlocks* once the WAL handle became `Arc<Mutex<…>>`, where it had *panicked* under the previous
//! `Rc<RefCell<…>>`. A silent hang is a strictly worse failure than a panic: the panic is a bug
//! report, the hang is an outage.
//!
//! # What makes it safe to convert
//!
//! In a **debug** build every acquisition goes through [`Mutex::try_lock`]. A `WouldBlock` is then
//! resolved against the recorded owning thread:
//!
//! * **the owner is this thread** — a re-entrant acquisition, and therefore a certain deadlock in
//!   release. It **panics** with a message that names the re-entrancy, exactly as the `RefCell` it
//!   replaced would have. This is the load-bearing half.
//! * **the owner is another thread** — ordinary contention, which is *correct* and must not be
//!   diagnosed as a bug. It falls through to a blocking [`Mutex::lock`].
//!
//! The owner is tracked with a per-thread token (see [`thread_token`]) rather than by panicking on
//! every `WouldBlock`, because the two situations are genuinely different and only the first is a
//! defect. Panicking on both would be indistinguishable from the first in the single-threaded world
//! this layer still lives in — but it would make the multi-writer scenario layer 2 must be able to
//! *express* (`rmp` #1010, acceptance criterion 2) fail spuriously the instant two writers overlap.
//! Tracking the owner keeps the diagnosis exact in both worlds.
//!
//! In a **release** build the acquisition is a plain [`Mutex::lock`] and the owner field does not
//! exist, so the production path pays nothing beyond the mutex itself.
//!
//! The whole workspace test suite — every unit test, every integration test, the TCK, the DST
//! batteries — compiles with `debug_assertions` on. So the tripwire is armed across the entire
//! corpus, and any latent double borrow surfaces as a loud, located panic rather than a hang nobody
//! can diagnose. This is the same "make the property mechanically checked, not visually reviewed"
//! device as [`graphus_core::latch`], and it follows its shape: dual `cfg`, an RAII guard, and a
//! positive-control test proving the panic has teeth.
//!
//! # Poisoning
//!
//! A poisoned lock is **recovered** ([`PoisonError::into_inner`]) rather than re-panicked, for the
//! same reason `graphus_storage::wal_rule::SharedWal` and the buffer pool do it: wedging every later
//! access to the store on a single prior panic elsewhere would turn one recoverable statement failure
//! into a permanently unusable database. Correctness after a panic is upheld where it actually lives
//! — MVCC undo and ARIES recovery — not by refusing to hand out the lock.
//!
//! # Deliberate non-goals
//!
//! * **No read/write split.** [`borrow`](SharedCell::borrow) and
//!   [`borrow_mut`](SharedCell::borrow_mut) both map to the same exclusive acquisition; a [`Mutex`]
//!   has no shared mode. The two names are kept so the ~360 existing call sites need no edit, and so
//!   the *intent* of each site stays readable. A consequence worth knowing: two **nested shared**
//!   borrows of the same cell, which a `RefCell` permits, are now a re-entrancy — the tripwire above
//!   is what finds them.
//! * **No cross-thread deadlock detection.** The tripwire diagnoses self-re-entrancy only. A genuine
//!   lock-order cycle between two threads is out of scope here; layer 2 keeps a single thread.

use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

#[cfg(debug_assertions)]
use std::sync::TryLockError;
#[cfg(debug_assertions)]
use std::sync::atomic::{AtomicU64, Ordering};

/// A process-unique, non-zero token for the current thread.
///
/// [`std::thread::ThreadId`] cannot be turned into an integer on stable Rust, and the owner slot has
/// to be a lock-free atomic (it is read *while another thread holds the mutex*), so the token is
/// minted here: a global counter handed out once per thread and cached thread-locally. Zero is
/// reserved for "unowned", which is why the counter starts at 1.
#[cfg(debug_assertions)]
fn thread_token() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    thread_local! {
        static TOKEN: u64 = NEXT.fetch_add(1, Ordering::Relaxed);
    }
    TOKEN.with(|t| *t)
}

/// The owner slot's value when no thread holds the cell.
#[cfg(debug_assertions)]
const UNOWNED: u64 = 0;

/// The shared payload: the value itself plus, in a debug build, the token of the thread currently
/// holding it.
struct Shared<T> {
    value: Mutex<T>,
    /// The [`thread_token`] of the current holder, or [`UNOWNED`].
    ///
    /// Written **only** while the mutex is held, and cleared *before* the mutex is released (the
    /// guard's `Drop` runs ahead of its fields'). It is read racily on the `WouldBlock` path, which is
    /// sound for the one question it is asked: "is the holder *me*?". A thread can never observe a
    /// stale copy of *its own* token, because its own writes are visible to itself in program order,
    /// and tokens are unique across threads — so a `true` answer is always a real re-entrancy and a
    /// `false` answer is always real contention.
    #[cfg(debug_assertions)]
    owner: AtomicU64,
}

/// A shared, `Send + Sync` handle to a `T`, with [`RefCell`](std::cell::RefCell)'s method names and,
/// in a debug build, its loud failure on re-entrancy. See the [module docs](self).
pub struct SharedCell<T> {
    inner: Arc<Shared<T>>,
}

impl<T> SharedCell<T> {
    /// Wraps `value` in a shared handle.
    #[must_use]
    pub fn new(value: T) -> Self {
        Self {
            inner: Arc::new(Shared {
                value: Mutex::new(value),
                #[cfg(debug_assertions)]
                owner: AtomicU64::new(UNOWNED),
            }),
        }
    }

    /// Acquires the cell for reading, mirroring [`RefCell::borrow`](std::cell::RefCell::borrow).
    ///
    /// A [`Mutex`] has no shared mode, so this is the same exclusive acquisition as
    /// [`borrow_mut`](Self::borrow_mut); the name is kept because it states the caller's intent and
    /// because it lets every existing call site compile unchanged. Binding the guard without `mut`
    /// still prevents calling a `&mut self` method through it, so the read-only discipline the name
    /// promises is preserved at the type level.
    ///
    /// # Panics
    /// In a **debug** build, panics if the current thread already holds this cell — the re-entrancy
    /// that would deadlock in release. Never panics on contention from another thread (it blocks).
    #[inline]
    pub fn borrow(&self) -> SharedGuard<'_, T> {
        self.acquire("borrow")
    }

    /// Acquires the cell for mutation, mirroring
    /// [`RefCell::borrow_mut`](std::cell::RefCell::borrow_mut).
    ///
    /// # Panics
    /// In a **debug** build, panics if the current thread already holds this cell — see
    /// [`borrow`](Self::borrow).
    #[inline]
    pub fn borrow_mut(&self) -> SharedGuard<'_, T> {
        self.acquire("borrow_mut")
    }

    /// Whether `self` and `other` are handles to the **same** cell, mirroring [`Arc::ptr_eq`].
    ///
    /// Compares the handles, never the contents: it takes no lock and so can be called while either
    /// cell is borrowed.
    #[must_use]
    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// The number of live handles to this cell, mirroring [`Arc::strong_count`].
    #[must_use]
    pub fn strong_count(&self) -> usize {
        Arc::strong_count(&self.inner)
    }

    /// Consumes the sole handle and returns the wrapped value.
    ///
    /// # Errors
    /// Returns the handle back (as `Err`) when other clones still exist, mirroring
    /// [`Arc::try_unwrap`] — the caller decides whether that is a programming error.
    pub fn into_inner(self) -> Result<T, Self> {
        Arc::try_unwrap(self.inner).map_or_else(
            |inner| Err(Self { inner }),
            |shared| {
                Ok(shared
                    .value
                    .into_inner()
                    .unwrap_or_else(PoisonError::into_inner))
            },
        )
    }

    /// The debug-build acquisition: `try_lock`, with a `WouldBlock` adjudicated against the recorded
    /// owner. See the [module docs](self) for why both arms are needed.
    #[cfg(debug_assertions)]
    #[inline]
    fn acquire(&self, site: &'static str) -> SharedGuard<'_, T> {
        let me = thread_token();
        let guard = match self.inner.value.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                assert!(
                    self.inner.owner.load(Ordering::Acquire) != me,
                    "SharedCell re-entrancy at `{site}`: this thread already holds this cell and \
                     asked for it again. Under the `Rc<RefCell<…>>` this replaced, that was a loud \
                     panic; under the non-reentrant `Mutex` it is now a silent HANG in release \
                     (`rmp` #1010, and the `rmp` #337 rollback deadlock before it). Fix the \
                     OVERLAP, not the symptom: shorten the outer borrow, or hoist the inner one out \
                     of it, so the two never nest. Note that two nested *shared* borrows count — a \
                     `Mutex` has no read mode. See `graphus_cypher::shared_cell`."
                );
                // A different thread holds it: ordinary contention, not a defect. Block.
                self.inner
                    .value
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
            }
        };
        self.inner.owner.store(me, Ordering::Release);
        SharedGuard {
            guard,
            owner: &self.inner.owner,
        }
    }

    /// The release-build acquisition: a plain blocking lock, with no owner bookkeeping.
    #[cfg(not(debug_assertions))]
    #[inline]
    fn acquire(&self, site: &'static str) -> SharedGuard<'_, T> {
        let _ = site;
        SharedGuard {
            guard: self
                .inner
                .value
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        }
    }
}

impl<T> Clone for SharedCell<T> {
    /// Clones the **handle**, never the value — exactly like [`Rc::clone`](std::rc::Rc::clone) on the
    /// `Rc<RefCell<…>>` this replaced, so every `Rc::clone(&x)` becomes `x.clone()` with identical
    /// meaning.
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for SharedCell<T> {
    /// Prints the handle, **not** the contents.
    ///
    /// Formatting the value would have to take the lock, so a `Debug`-print of a struct while one of
    /// its cells is borrowed — precisely what a panic handler or a tracing hook does — would trip the
    /// re-entrancy tripwire, or hang in release. `RefCell`'s own `Debug` sidesteps this by printing
    /// `<borrowed>`; a `Mutex` cannot detect that case cheaply, so this reports the handle instead.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedCell")
            .field("strong_count", &Arc::strong_count(&self.inner))
            .finish_non_exhaustive()
    }
}

/// The RAII guard returned by [`SharedCell::borrow`] / [`SharedCell::borrow_mut`].
///
/// Derefs to the wrapped value, so a call site written against
/// [`Ref`](std::cell::Ref)/[`RefMut`](std::cell::RefMut) compiles unchanged. Releasing it releases
/// the lock; in a debug build it also clears the owner slot first.
#[must_use = "the cell stays locked for as long as this guard lives"]
pub struct SharedGuard<'a, T> {
    guard: MutexGuard<'a, T>,
    /// The cell's owner slot, cleared on drop. Debug builds only.
    #[cfg(debug_assertions)]
    owner: &'a AtomicU64,
}

impl<T> Deref for SharedGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T> DerefMut for SharedGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

impl<T> Drop for SharedGuard<'_, T> {
    /// Clears the owner slot **before** the [`MutexGuard`] field is dropped (a type's own `Drop::drop`
    /// runs ahead of its fields'), so no thread can acquire the mutex and read a stale owner.
    #[inline]
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        self.owner.store(UNOWNED, Ordering::Release);
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for SharedGuard<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&**self, f)
    }
}

/// A shared handle to a `T` **that needs no lock at all** — the end state [`SharedCell`] was the step
/// towards (`rmp` #1033, layer 7b of #975).
///
/// `SharedCell` exists because the coordinator's members were reached through `&mut self` methods, so
/// sharing them between threads required serialising every access. Once a type's whole API takes
/// `&self` — which is what layers 1 to 7a did to [`RecordStore`](graphus_storage::RecordStore) — that
/// serialisation protects nothing: the type's own latches already order what has to be ordered, at the
/// granularity of the operation rather than of the statement. Keeping the outer `Mutex` would just
/// mean every writer waits for the whole statement of every other writer, which is precisely the
/// single-writer engine this sprint set out to retire.
///
/// The method names are [`SharedCell`]'s, deliberately: `borrow` and `borrow_mut` both hand back a
/// plain `&T`, so 432 call sites migrate by changing one field's type. `borrow_mut` keeping its name
/// while returning `&T` reads oddly on its own, and it is the honest description of what changed —
/// the call sites did not stop mutating the store, the store stopped needing exclusive access to be
/// mutated.
#[derive(Debug)]
pub struct SharedRef<T> {
    inner: Arc<T>,
}

impl<T> SharedRef<T> {
    /// Wraps `value` in a shared, lock-free handle.
    #[must_use]
    pub fn new(value: T) -> Self {
        Self {
            inner: Arc::new(value),
        }
    }

    /// Borrows the value. No lock is taken and none is needed.
    // `clippy::should_implement_trait`: the name mirrors `SharedCell`/`RefCell` on purpose — it is what
    // lets 432 call sites migrate untouched — and implementing `std::borrow::Borrow` instead would not
    // give them that, since they call the method by name.
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    #[inline]
    pub fn borrow(&self) -> &T {
        &self.inner
    }

    /// Borrows the value for mutation through its own `&self` API. Identical to
    /// [`borrow`](Self::borrow) — see the type docs for why the name is kept.
    #[must_use]
    #[inline]
    pub fn borrow_mut(&self) -> &T {
        &self.inner
    }

    /// The underlying handle, for a caller that has to hand the value to another thread.
    #[must_use]
    #[inline]
    pub fn share(&self) -> Arc<T> {
        Arc::clone(&self.inner)
    }

    /// Unwraps the value when this is the sole handle; returns `self` back when it is not.
    ///
    /// # Errors
    /// Returns the handle unchanged if another one still exists.
    pub fn into_inner(self) -> std::result::Result<T, Self> {
        Arc::try_unwrap(self.inner).map_err(|inner| Self { inner })
    }
}

impl<T> Clone for SharedRef<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_borrow_reads_and_a_borrow_mut_writes() {
        let cell = SharedCell::new(41_u32);
        assert_eq!(*cell.borrow(), 41);
        *cell.borrow_mut() += 1;
        assert_eq!(*cell.borrow(), 42);
    }

    #[test]
    fn sequential_borrows_do_not_trip_the_tripwire() {
        let cell = SharedCell::new(Vec::<u32>::new());
        for i in 0..8 {
            cell.borrow_mut().push(i);
        }
        assert_eq!(cell.borrow().len(), 8);
    }

    #[test]
    fn a_clone_shares_one_value() {
        let a = SharedCell::new(0_u32);
        let b = a.clone();
        *b.borrow_mut() = 7;
        assert_eq!(*a.borrow(), 7);
        assert!(a.ptr_eq(&b));
        assert_eq!(a.strong_count(), 2);

        let c = SharedCell::new(7_u32);
        assert!(
            !a.ptr_eq(&c),
            "distinct cells with equal values are not the same cell"
        );
    }

    /// **The teeth.** A re-entrant acquisition — the case that would hang under a bare
    /// `Arc<Mutex<…>>` — must panic in a debug build, and the message must name the re-entrancy.
    /// Without this test the tripwire could silently be a no-op and prove nothing.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "SharedCell re-entrancy at `borrow_mut`")]
    fn a_nested_borrow_mut_panics_instead_of_hanging() {
        let cell = SharedCell::new(0_u32);
        let _outer = cell.borrow_mut();
        let _inner = cell.borrow_mut();
    }

    /// Two nested **shared** borrows are fine under a `RefCell` and are a deadlock under a `Mutex`.
    /// That divergence is the single most likely way this conversion breaks a call site, so it gets
    /// its own positive control.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "a `Mutex` has no read mode")]
    fn two_nested_shared_borrows_panic_too() {
        let cell = SharedCell::new(0_u32);
        let _outer = cell.borrow();
        let _inner = cell.borrow();
    }

    /// Re-entrancy through a **clone** of the same handle is the same defect and must be caught the
    /// same way — the tripwire is a property of the cell, not of the handle it was reached through.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "SharedCell re-entrancy")]
    fn re_entrancy_through_a_clone_panics() {
        let a = SharedCell::new(0_u32);
        let b = a.clone();
        let _outer = a.borrow_mut();
        let _inner = b.borrow_mut();
    }

    /// The guard releases on drop, so a borrow taken **after** an earlier one ended is not a
    /// re-entrancy. A tripwire that fired here would be useless (it would fire everywhere).
    #[test]
    fn a_released_borrow_is_not_a_re_entrancy() {
        let cell = SharedCell::new(0_u32);
        {
            let mut g = cell.borrow_mut();
            *g = 1;
        }
        let mut g = cell.borrow_mut();
        *g = 2;
        drop(g);
        assert_eq!(*cell.borrow(), 2);
    }

    /// **The other half of the teeth**: contention from another thread is *not* a defect and must
    /// **not** panic. Thread B blocks on a cell thread A is holding, and gets it when A lets go.
    ///
    /// This is what makes a multi-writer scenario expressible (`rmp` #1010, criterion 2). A tripwire
    /// that panicked on every `WouldBlock` would pass the re-entrancy tests above and still make every
    /// real overlap a spurious failure.
    #[test]
    fn contention_from_another_thread_blocks_and_does_not_panic() {
        use std::sync::mpsc;
        use std::time::Duration;

        let cell = SharedCell::new(0_u32);
        let far = cell.clone();
        let (holding_tx, holding_rx) = mpsc::channel::<()>();

        let held = cell.borrow_mut();
        let worker = std::thread::spawn(move || {
            holding_tx.send(()).expect("main is still listening");
            // Blocks until the main thread releases; must not panic.
            *far.borrow_mut() += 1;
        });
        holding_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("worker started");
        // Give the worker time to actually reach the contended acquisition.
        std::thread::sleep(Duration::from_millis(50));
        drop(held);

        worker
            .join()
            .expect("the contended borrow blocked, it did not panic");
        assert_eq!(*cell.borrow(), 1);
    }

    /// A cell whose thread panicked while holding it stays usable: the poison is recovered, not
    /// re-raised. Wedging every later access on one prior panic would be an availability failure.
    #[test]
    fn a_poisoned_cell_is_recovered_not_re_panicked() {
        let cell = SharedCell::new(5_u32);
        let far = cell.clone();
        let poisoner = std::thread::spawn(move || {
            let _g = far.borrow_mut();
            panic!("poison this cell");
        });
        assert!(poisoner.join().is_err(), "the worker did panic");

        // The value the poisoning thread left behind is still readable and writable.
        assert_eq!(*cell.borrow(), 5);
        *cell.borrow_mut() = 6;
        assert_eq!(*cell.borrow(), 6);
    }

    /// The owner slot is cleared before the mutex is released, so a thread that takes the cell after
    /// another thread had it does not inherit that thread's identity — and a *later, legitimate*
    /// borrow on the original thread is not mis-diagnosed as re-entrancy.
    #[test]
    fn the_owner_slot_does_not_leak_across_threads() {
        let cell = SharedCell::new(0_u32);
        let far = cell.clone();
        std::thread::spawn(move || {
            *far.borrow_mut() = 1;
        })
        .join()
        .expect("worker finished");
        // Would panic if the worker's token were still recorded and matched ours; it cannot.
        assert_eq!(*cell.borrow(), 1);
    }

    #[test]
    fn into_inner_unwraps_the_sole_handle_and_refuses_a_shared_one() {
        let cell = SharedCell::new(9_u32);
        assert!(
            cell.clone().into_inner().is_err(),
            "a shared handle must not be unwrapped"
        );

        let cell = SharedCell::new(9_u32);
        assert_eq!(cell.into_inner().ok(), Some(9));
    }

    /// The whole point of layer 2: the wrapper is `Send + Sync` whenever its contents are.
    #[test]
    fn the_handle_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SharedCell<Vec<u32>>>();
    }
}
