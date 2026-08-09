//! **The freeze frontier of a Graphus record store** (`rmp` #1014): a floor that descends freely, and
//! rises only against proof that nothing descended underneath it.
//!
//! Each record store keeps one frontier per kind. `freeze_low[kind]` is the smallest physical id that
//! may still carry an **unfrozen committed-in-flight MVCC stamp**, and the GC's freeze sweep visits
//! only `[freeze_low, high_water)` instead of the whole store. The invariant that buys the sweep its
//! cheapness is:
//!
//! > every in-use record **below** the frontier already has all committed-writer stamps frozen.
//!
//! Exactly three operations act on the cell, and each of them has exactly one correct shape:
//!
//! | operation | performed by | the only correct primitive |
//! |---|---|---|
//! | **descend** | a writer stamping an in-flight `xmin`/`xmax` at id `i` | [`FreezeFloor::descend`] — `floor = min(floor, i)` |
//! | **raise** | the freeze sweep, having scanned `[from, high_water)` | [`FreezeFloor::try_raise`] — conditional on the floor still holding `from` |
//! | **reset** | `open()`, and tests arming the cell | [`FreezeFloor::reset`] — unconditional, and **nothing else may use it** |
//!
//! # A lost descent is silent data loss, not a slow scan
//!
//! A descent names a range the frontier must keep covering. Lose one, and the ids it named are never
//! visited by any future sweep, so a committed writer's stamp stays in-flight **for ever**: the record
//! keeps a transaction id where it should hold a commit timestamp, and every later visibility decision
//! about it is taken against a transaction that no longer exists. That is the `rmp` #522
//! silent-data-loss shape — an ACID violation with no symptom at the point of failure, surfacing much
//! later as rows that appear, disappear, or refuse to be reclaimed. It is the reason the frontier's
//! algebra lives here, model-checked, instead of being three scattered accesses to an `AtomicU64`.
//!
//! # Why the raise must be a compare-exchange
//!
//! The sweep's `new_low` is not an arbitrary number: it is *the smallest id still bearing an in-flight
//! stamp in the range `[from, high_water)` that this pass actually scanned*. Its validity is therefore
//! conditional on `from` — it says nothing whatsoever about ids below `from`. A concurrent writer that
//! descends to such an id while the pass is scanning is telling the frontier about a record the pass
//! did not look at, and an unconditional store of `new_low` erases that message:
//!
//! ```text
//!   sweep:  from := load()          -> 8
//!   sweep:  scan [8, high_water)    -> nothing in flight, new_low := high_water
//!   writer: stamp record 4
//!   writer: descend(4)              -> floor = 4        (record 4 must be re-scanned)
//!   sweep:  store(high_water)       -> floor = high_water   <-- record 4 is now unreachable, for ever
//! ```
//!
//! Making the publication a compare-exchange against `from` closes it: the descent changed the floor,
//! so the exchange is refused, the lower value survives, and the next pass re-scans from there. The
//! cost of a refusal is one wasted scan; the cost of the store above is a corrupt database.
//!
//! Note what is *not* a defence. "A concurrent descent re-lowers the frontier afterwards by
//! `fetch_min`, so the order is immaterial" is true only for the descent that lands **after** the
//! store. The one that lands **before** it — the interleaving above — is exactly the one that is lost,
//! and it is the more likely of the two, because the sweep's window spans an entire scan of the store
//! while the descent is a single instruction. The order is not immaterial; it is the whole question.
//!
//! # Why a rolled-back sweep must restore by descending
//!
//! A GC pass takes a savepoint of the frontier before its sweep and restores it if the pass rolls
//! back. Restoring means "the raise never happened", and `descend(saved)` says precisely that: the
//! floor was `saved` before the raise, so `min(floor, saved)` undoes the raise exactly, while
//! remaining incapable of swallowing any descent that landed in between — a lower floor is always
//! sound, because the frontier is permitted to be conservative but never permitted to be optimistic.
//! An unconditional `store(saved)` undoes the raise just as exactly and swallows those descents, which
//! is the same defect one paragraph up wearing different clothes.
//!
//! # An obligation on the caller: stamp first, descend second
//!
//! [`descend`](FreezeFloor::descend) publishes the fact that a record needs re-scanning. It must
//! therefore be called **after** that record's stamp has been written, never before: a sweep that
//! observes the lowered floor and scans the id must find the stamp there. The reverse order leaves a
//! window in which the frontier already covers the id but the record does not yet look interesting, so
//! the pass legitimately raises past it and the stamp is stranded — a hazard no primitive in this
//! crate can close, because by the time `descend` is called the damage is already possible.
//!
//! # No dependencies, on purpose
//!
//! See this crate's `Cargo.toml`: `--cfg loom` is a global rustflag, so a structure that is to be
//! model-checked must sit in a crate with no edge to any other crate carrying a loom seam. The models
//! are in `tests/loom_freezefloor.rs`, and each positive property there is paired with a negative
//! control that requires the naive alternative to *fail*.

#![forbid(unsafe_code)]

use core::fmt;

// The atomic seam. `loom` model-checks concurrent code by *replacing* the standard atomics with
// instrumented versions that explore every interleaving the memory model permits — not merely the
// ones this CPU happens to produce. That distinction is load-bearing here: development and CI run on
// x86-64, which is TSO (loads are acquire and stores are release *in hardware*), so a frontier whose
// orderings were all `Relaxed` would pass every real-thread test on this machine and then reorder on
// aarch64, which CLAUDE.md names as a first-class target (Apple Silicon, Raspberry Pi 5).
#[cfg(loom)]
use loom::sync::atomic::{AtomicU64, Ordering};

#[cfg(not(loom))]
use std::sync::atomic::{AtomicU64, Ordering};

/// The freeze frontier of one record store kind: the smallest physical id that may still carry an
/// unfrozen committed-in-flight MVCC stamp.
///
/// The type exists to make the frontier's algebra unforgeable. Every legal transition is a method,
/// each method is the one primitive that transition may use, and the illegal transition — an
/// unconditional store performed by the sweep or by a rollback — is reachable only through
/// [`reset`](Self::reset), which says in its own documentation that it is not for either.
///
/// See the crate documentation for why each choice is the only correct one.
///
/// # Examples
///
/// The freeze sweep's shape: load the frontier, scan from there, publish the new frontier
/// conditionally.
///
/// ```
/// use graphus_freezefloor::FreezeFloor;
///
/// let floor = FreezeFloor::new(8);
///
/// // A writer stamps record 4 — an id BELOW the frontier — and covers it.
/// floor.descend(4);
/// assert_eq!(floor.get(), 4);
///
/// // A sweep that started before that descent tries to advance the frontier it loaded.
/// let stale_from = 8;
/// assert!(!floor.try_raise(stale_from, 16), "the descent must not be swallowed");
/// assert_eq!(floor.get(), 4, "the lower frontier survives; the next pass re-scans from 4");
/// ```
pub struct FreezeFloor {
    cell: AtomicU64,
}

impl FreezeFloor {
    /// Creates a frontier holding `initial`.
    ///
    /// The record stores open at `1`, the lowest id a store ever allocates, so that the first pass
    /// after `open()` is a full scan and the invariant is established rather than assumed.
    ///
    /// Not a `const fn`: under `--cfg loom` the underlying atomic is loom's instrumented one, whose
    /// constructor is not `const` and must moreover run inside a `loom::model`. A single non-`const`
    /// constructor keeps the production and the model-checked APIs identical, which is the point of
    /// the seam.
    #[must_use]
    pub fn new(initial: u64) -> Self {
        Self {
            cell: AtomicU64::new(initial),
        }
    }

    /// Reads the frontier.
    ///
    /// `Acquire`, and not for decoration: a writer stamps a record and *then*
    /// [`descend`](Self::descend)s to cover it, so a sweep that observes the lowered frontier must
    /// also observe the stamp when it scans that id. The `Release` half of `descend` and this
    /// `Acquire` are the two ends of that edge; drop either and the sweep may scan the right range and
    /// read a stale record, which is a lost stamp by a longer route.
    #[must_use]
    pub fn get(&self) -> u64 {
        self.cell.load(Ordering::Acquire)
    }

    /// Lowers the frontier to cover `candidate` — `floor = min(floor, candidate)` — and returns the
    /// value the frontier held before.
    ///
    /// This is the writer's operation, and a single `fetch_min`: two writers descending concurrently
    /// both land, whatever the interleaving, because the read and the write are one indivisible step.
    /// A load-compare-store that looks equivalent is not, and loses one of the two descents — see
    /// `naive_descent_loses_a_descent` in `tests/loom_freezefloor.rs`, which exists to keep this
    /// sentence honest.
    ///
    /// It is also the operation that restores a rolled-back sweep's savepoint, for the reason given in
    /// the crate documentation: descending to the saved value undoes the raise exactly and cannot
    /// swallow a descent that landed in the meantime.
    ///
    /// The returned previous value is incidental — production callers ignore it — and is reported
    /// because it is free and lets a caller tell "I moved the frontier" from "it was already low
    /// enough".
    ///
    /// # Contract
    ///
    /// Call this **after** writing the stamp at `candidate`, never before. See the crate
    /// documentation, "An obligation on the caller".
    pub fn descend(&self, candidate: u64) -> u64 {
        // `AcqRel`: the `Release` half publishes the stamp this call is announcing to any sweep that
        // subsequently `Acquire`-reads the frontier; the `Acquire` half makes this writer see whatever
        // the previous owner of the frontier published.
        self.cell.fetch_min(candidate, Ordering::AcqRel)
    }

    /// Advances the frontier from `from` to `to`, **if and only if** the frontier still holds `from`;
    /// reports whether it did.
    ///
    /// This is the freeze sweep's operation. `from` is the value the sweep loaded when it started, and
    /// `to` is the smallest id in `[from, high_water)` still bearing an in-flight-writer stamp after
    /// the pass (or the high-water mark, if none). Because `to` was computed from a scan that began at
    /// `from`, it is a statement about `[from, high_water)` and about nothing else — which is exactly
    /// why publishing it must be conditional on `from` still being the frontier.
    ///
    /// A refusal means a concurrent [`descend`](Self::descend) landed below `from`, naming a record
    /// this pass never looked at. The caller keeps the lower value and pays a re-scan on the next
    /// pass; it never loses a stamp. Ignoring the returned `bool` is therefore legitimate, and is what
    /// the sweep does: there is nothing to recover from, only work to redo later.
    ///
    /// # Panics
    ///
    /// Debug builds assert `to >= from`. A "raise" that lowers the frontier is not unsound — a lower
    /// frontier only ever costs a re-scan — but it means the caller computed `to` outside the range it
    /// scanned, and that is a bug worth catching before it becomes a habit. Release builds proceed.
    pub fn try_raise(&self, from: u64, to: u64) -> bool {
        debug_assert!(
            to >= from,
            "try_raise({from}, {to}) lowers the frontier: `to` must come from a scan of \
             [{from}, high_water). Use `descend` to lower it."
        );
        // `AcqRel` on success: the `Release` half publishes this pass's frozen headers before the
        // raised frontier becomes visible, so a later sweep that skips the range on the strength of
        // this frontier is guaranteed to be skipping records that really are frozen. `Acquire` on
        // failure: the refusal is caused by a descent, and the sweep that keeps the lower frontier
        // must see the stamp that descent was announcing when it re-scans.
        self.cell
            .compare_exchange(from, to, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Sets the frontier to `value` unconditionally.
    ///
    /// **This is for initialisation and for tests that arm the frontier. Nothing else.**
    ///
    /// It is emphatically **not** for the freeze sweep and **not** for a rollback's savepoint restore.
    /// Both of those clobber any [`descend`](Self::descend) that landed since the value being stored
    /// was computed, which strands a committed writer's stamp below the frontier where no future sweep
    /// will ever visit it — the `rmp` #522 silent-data-loss shape, and the entire reason this crate
    /// exists. Use [`try_raise`](Self::try_raise) for the sweep and [`descend`](Self::descend) for the
    /// restore.
    ///
    /// The hazard is not theoretical and is not left to this paragraph:
    /// `an_unconditional_raise_swallows_a_concurrent_descent` and
    /// `an_unconditional_rollback_restore_swallows_a_concurrent_descent` in
    /// `tests/loom_freezefloor.rs` call *this method* in those two roles and require that at least one
    /// interleaving loses a descent.
    pub fn reset(&self, value: u64) {
        self.cell.store(value, Ordering::Release);
    }
}

impl fmt::Debug for FreezeFloor {
    /// Written out rather than derived: the field is the loom seam, and a derived `Debug` would render
    /// loom's instrumented atomic (whose own `Debug` is not the plain integer) under `--cfg loom` and
    /// `std`'s under a production build — two different renderings of one type. Reading the cell keeps
    /// them identical.
    ///
    /// Under `--cfg loom` this performs an instrumented `Acquire` load, so formatting a `FreezeFloor`
    /// inside a model adds a scheduling point. The models here do not format one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FreezeFloor")
            .field("floor", &self.get())
            .finish()
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    /// The frontier is shared across the engine thread, the GC pass and every off-thread reader, so
    /// `Send + Sync` is part of its contract rather than an accident of its field. Checked at compile
    /// time: if the cell ever gained a non-`Sync` field, this stops compiling instead of failing
    /// somewhere in `graphus-storage`.
    const _: fn() = || {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FreezeFloor>();
    };

    #[test]
    fn a_new_floor_holds_its_initial_value() {
        assert_eq!(FreezeFloor::new(1).get(), 1);
        assert_eq!(FreezeFloor::new(u64::MAX).get(), u64::MAX);
    }

    #[test]
    fn descend_lowers_the_floor_and_reports_what_it_displaced() {
        let floor = FreezeFloor::new(10);
        assert_eq!(floor.descend(4), 10, "it displaced 10");
        assert_eq!(floor.get(), 4);
    }

    #[test]
    fn descend_never_raises_the_floor() {
        let floor = FreezeFloor::new(4);
        assert_eq!(floor.descend(9), 4, "the previous value is still reported");
        assert_eq!(
            floor.get(),
            4,
            "a descent to a higher id is a no-op: the frontier may be conservative, never optimistic"
        );
        assert_eq!(
            floor.descend(4),
            4,
            "descending to the current value is a no-op"
        );
        assert_eq!(floor.get(), 4);
    }

    #[test]
    fn the_lowest_of_several_descents_is_the_one_that_survives() {
        let floor = FreezeFloor::new(100);
        for candidate in [40, 7, 90, 12, 7] {
            floor.descend(candidate);
        }
        assert_eq!(
            floor.get(),
            7,
            "min over every candidate, order-independent"
        );
    }

    #[test]
    fn try_raise_succeeds_when_the_floor_still_holds_from() {
        let floor = FreezeFloor::new(8);
        assert!(floor.try_raise(8, 16));
        assert_eq!(floor.get(), 16);
    }

    #[test]
    fn try_raise_to_the_same_value_succeeds_and_changes_nothing() {
        // The sweep's ordinary outcome when the lowest in-flight stamp is at `from` itself.
        let floor = FreezeFloor::new(8);
        assert!(floor.try_raise(8, 8));
        assert_eq!(floor.get(), 8);
    }

    #[test]
    fn try_raise_refuses_when_a_descent_moved_the_floor_and_leaves_the_lower_value() {
        let floor = FreezeFloor::new(8);
        // A writer descends below the value the sweep loaded — an id the sweep never scanned.
        floor.descend(4);
        assert!(
            !floor.try_raise(8, 16),
            "the sweep's `new_low` says nothing about id 4, so it must not be published"
        );
        assert_eq!(
            floor.get(),
            4,
            "the refusal must leave the descent in place: the next pass re-scans from 4"
        );
    }

    #[test]
    fn try_raise_refuses_against_any_stale_from_not_merely_a_lower_one() {
        // Whoever moved the frontier owns it. Even a frontier that moved UP under the sweep (only
        // `reset` can do that, i.e. a reopen) invalidates a `from` this pass captured earlier.
        let floor = FreezeFloor::new(8);
        floor.reset(12);
        assert!(!floor.try_raise(8, 16));
        assert_eq!(floor.get(), 12);
    }

    #[test]
    fn a_rolled_back_sweep_is_restored_exactly_by_descending_to_the_savepoint() {
        let floor = FreezeFloor::new(8);
        let savepoint = floor.get();
        assert!(
            floor.try_raise(savepoint, 16),
            "the pass's sweep advances it"
        );
        floor.descend(savepoint);
        assert_eq!(
            floor.get(),
            savepoint,
            "descending to the savepoint undoes the raise exactly"
        );
    }

    #[test]
    fn restoring_a_savepoint_by_descending_cannot_swallow_a_descent() {
        let floor = FreezeFloor::new(8);
        let savepoint = floor.get();
        assert!(floor.try_raise(savepoint, 16));
        // A writer covers record 4 while the pass is unwinding.
        floor.descend(4);
        floor.descend(savepoint);
        assert_eq!(
            floor.get(),
            4,
            "the restore must not raise the frontier back over a descent it never accounted for"
        );
    }

    #[test]
    fn reset_is_unconditional_in_both_directions() {
        let floor = FreezeFloor::new(8);
        floor.reset(16);
        assert_eq!(floor.get(), 16, "reset raises without any condition");
        floor.reset(1);
        assert_eq!(
            floor.get(),
            1,
            "and lowers just the same — it is `open()`'s tool"
        );
    }

    #[test]
    fn debug_renders_the_current_frontier() {
        let floor = FreezeFloor::new(8);
        assert_eq!(format!("{floor:?}"), "FreezeFloor { floor: 8 }");
        floor.descend(3);
        assert_eq!(format!("{floor:?}"), "FreezeFloor { floor: 3 }");
    }

    #[test]
    #[should_panic(expected = "lowers the frontier")]
    fn try_raise_flags_a_to_below_from_in_debug_builds() {
        // Not unsound — a lower frontier only costs a re-scan — but it means `to` was computed
        // outside the range that was scanned, which is a caller bug.
        FreezeFloor::new(8).try_raise(8, 4);
    }
}
