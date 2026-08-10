//! **The engine's session latches** (`rmp` #1038): rank 5 of the lock order, with one door in.
//!
//! An engine worker keeps three pieces of state that a client command consults — the open-transaction
//! table, the queue of statements suspended on a slow consumer, and the compiled-plan cache. Until
//! `rmp` #1033 there was one worker, so they were plain locals and none of this mattered. Now the loop
//! body runs on W threads, and they are the state those threads meet.
//!
//! # Why a wrapper and not a `Mutex`
//!
//! Two reasons, and both come from a defect that was already in the tree.
//!
//! **One door.** The rank-5 rules (at most one holder per thread; never held across work of unbounded
//! duration — see [`graphus_core::latch::EngineLatchScope`]) are enforced by a thread-local depth that
//! something has to maintain. Leaving that to each call site means the rules hold until somebody adds a
//! `Mutex` and forgets, and a tripwire that a new latch can be added *beside* protects nothing. This
//! type is the only way to lock one of these tables, and locking through it arms the scope. A latch
//! that is not an [`EngineLatch`] is not at rank 5 and does not get to pretend it is.
//!
//! **The guard cannot be spelled in argument position.** In Rust a temporary lives to the end of the
//! *statement* that created it, so
//!
//! ```ignore
//! run_statement(coord, &mut open.lock().unwrap(), &mut plan_cache.lock().unwrap(), query, …);
//! ```
//!
//! holds both latches for the whole query — compile, execute, materialise, morsel, GDS. That is what
//! the engine did at every one of its execution call sites.
//!
//! Be exact about what that cost, because the honest version is the more alarming one. Measured
//! (`tests/engine_latch_scaling_1038.rs`): a lock held across a whole statement costs *nothing* while
//! each worker holds its own — 3.95 of 4 cores, indistinguishable from correct code — and collapses to
//! 1.00 core the instant the lock is shared. `EngineShared` is built inside `run_engine_loop`, so the
//! old guards were per worker and the defect was **latent**. It was not a slowdown waiting to be
//! measured; it was a deadlock and a one-core engine waiting for `rmp` #1041 to share the tables, at
//! which point the symptom would have appeared in a task that changed none of this code. A defect that
//! is invisible to results, invisible to throughput, and lethal on somebody else's commit is exactly
//! the kind that has to be made structurally unwritable rather than fixed and remembered.
//!
//! [`EngineLatchGuard`] cannot be handed to a function that takes `&mut OpenTxTable` without a named
//! binding, and if one is held when execution starts the tripwire fires — so the shape is refused
//! twice: once by shape, once by assertion.

/// A latch of **rank 5** — the engine's session state. Locking it arms the rank-5 tripwire.
///
/// See the module docs for why this exists rather than a bare `std::sync::Mutex`, and
/// [`graphus_core::latch::EngineLatchScope`] for the rank and the two rules it encodes.
#[derive(Debug)]
pub(crate) struct EngineLatch<T> {
    inner: std::sync::Mutex<T>,
}

impl<T> EngineLatch<T> {
    /// Wraps `value` in a rank-5 latch.
    pub(crate) fn new(value: T) -> Self {
        Self {
            inner: std::sync::Mutex::new(value),
        }
    }

    /// Takes the latch, arming the rank-5 tripwire for as long as the returned guard lives.
    ///
    /// # Panics
    /// Panics if the latch is poisoned — a worker panicked while holding it, so the table it guards
    /// may be half-updated and every later command would be served from state no invariant covers.
    /// The engine's own panic boundaries (`rmp` #386/#485) catch statement panics *outside* these
    /// critical sections precisely so that this stays unreachable.
    ///
    /// Also panics, in a debug build, if this thread already holds an engine session latch or holds
    /// any inner latch — see [`graphus_core::latch::EngineLatchScope::new`].
    pub(crate) fn lock(&self) -> EngineLatchGuard<'_, T> {
        // The scope is entered BEFORE the guard is acquired, so its rank checks run before this thread
        // can block: a rank inversion is then reported at the acquisition that commits the error,
        // rather than after the thread has already parked on the very lock the order was meant to keep
        // it off. It is also the only order that reports anything at all when the inversion is a
        // genuine deadlock — a thread already blocked cannot assert.
        let scope = graphus_core::latch::EngineLatchScope::new();
        EngineLatchGuard {
            guard: self.inner.lock().expect(
                "INVARIANT: an engine session latch is never held across a panic (rmp #1038)",
            ),
            _scope: scope,
        }
    }
}

/// The guard [`EngineLatch::lock`] returns: a `MutexGuard` plus the live rank-5 scope.
///
/// Field order is the release order, and it is chosen rather than inherited. Struct fields drop in
/// declaration order, so `guard` goes first — the lock is released, then the thread stops counting as
/// a holder. That is the exact reverse of [`EngineLatch::lock`]'s acquisition (scope, then lock), which
/// is the RAII discipline every other latch in the codebase follows. Neither order is *observable*
/// here, since nothing runs on this thread between the two drops; stating it is what makes a future
/// reordering of these two fields a decision rather than an accident.
#[derive(Debug)]
pub(crate) struct EngineLatchGuard<'a, T> {
    guard: std::sync::MutexGuard<'a, T>,
    _scope: graphus_core::latch::EngineLatchScope,
}

impl<T> std::ops::Deref for EngineLatchGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T> std::ops::DerefMut for EngineLatchGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

#[cfg(test)]
mod tests {
    use super::EngineLatch;

    /// The door arms the tripwire. Without this the wrapper could be added, every rank-5 rule could be
    /// stated in the docs, and nothing would check any of it — the scope would simply never be entered.
    #[cfg(debug_assertions)]
    #[test]
    fn locking_arms_the_rank_5_scope() {
        let latch = EngineLatch::new(7u32);
        assert_eq!(graphus_core::latch::engine_latch_depth(), 0);
        let guard = latch.lock();
        assert_eq!(graphus_core::latch::engine_latch_depth(), 1);
        assert_eq!(*guard, 7);
        drop(guard);
        assert_eq!(graphus_core::latch::engine_latch_depth(), 0);
    }

    /// **The ABBA, in the shape the engine actually had.** Two different rank-5 latches — stand-ins for
    /// the open-transaction table and the parked-statement queue — held at once. Before `rmp` #1038 the
    /// age sweep held them *open → parked* and the resume/park paths held them *parked → open*; with a
    /// table per worker that was harmless, and the instant `rmp` #1041 shares them two workers close
    /// the cycle and the engine stops with nothing in the log. Here it is one thread and a panic.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "Rank 5 is not re-entrant")]
    fn two_engine_latches_at_once_are_refused() {
        let open = EngineLatch::new(0u32);
        let parked = EngineLatch::new(0u32);
        let _first = open.lock();
        let _second = parked.lock();
    }

    /// The other order is refused identically — which is the point: neither order is the "right" one,
    /// because there is no order. Nesting is what is forbidden.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "Rank 5 is not re-entrant")]
    fn the_opposite_nesting_is_refused_too() {
        let open = EngineLatch::new(0u32);
        let parked = EngineLatch::new(0u32);
        let _first = parked.lock();
        let _second = open.lock();
    }

    /// One after another is exactly what the restructured call sites do, and it must stay legal.
    #[test]
    fn one_after_another_is_fine() {
        let open = EngineLatch::new(1u32);
        let parked = EngineLatch::new(2u32);
        let a = *open.lock();
        let b = *parked.lock();
        assert_eq!(a + b, 3);
        assert_eq!(graphus_core::latch::engine_latch_depth(), 0);
    }

    /// A guard released, then work, then a fresh guard: the shape every restructured site uses.
    /// `assert_no_engine_latch_held` must accept the middle of that sandwich.
    #[test]
    fn work_between_two_holds_is_unlatched() {
        let open = EngineLatch::new(5u32);
        let copied = {
            let guard = open.lock();
            *guard
        };
        graphus_core::latch::assert_no_engine_latch_held("test: work between holds");
        *open.lock() += copied;
        assert_eq!(*open.lock(), 10);
    }
}
