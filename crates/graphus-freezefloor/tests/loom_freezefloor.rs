//! **`loom` model check of the freeze frontier** (`rmp` #1014).
//!
//! Run with:
//!
//! ```text
//! RUSTFLAGS="--cfg loom" cargo test -p graphus-freezefloor --test loom_freezefloor --release
//! ```
//!
//! # What is being modelled
//!
//! [`graphus_freezefloor::FreezeFloor`] is the production cell, driven here unchanged. What the model
//! supplies is the rest of the store: the freeze sweep's scan of `[from, high_water)` is reduced to
//! [`scan_from`], and the record a writer stamps is one [`loom::sync::atomic::AtomicU64`] rather than
//! an MVCC header on a buffer-pool page.
//!
//! That reduction keeps exactly the one property the frontier's correctness turns on: **a pass that
//! starts at `from` reads the records in `[from, high_water)` and nothing below `from`.** A stamp
//! written at an id under the frontier is therefore invisible to a pass already in flight, and the
//! only thing that can tell that pass about it is the descent — which is why losing a descent loses
//! the stamp, permanently, and why every model here measures the same thing: *is the id the writer
//! stamped still covered by the frontier when both threads have finished?*
//!
//! # Why a model checker and not a thread test
//!
//! The loss needs a descent to land inside the sweep's window — after it loaded `from`, before it
//! published `new_low`. On any given run of a real-thread test that window may simply not open, and on
//! x86-64 TSO it opens less often still. A test that passes because the interleaving did not happen
//! certifies nothing. loom enumerates the interleavings the *memory model* permits, so the answer does
//! not depend on this machine — which matters because CLAUDE.md names aarch64 (Apple Silicon,
//! Raspberry Pi 5) as a first-class target, and aarch64 is not TSO.
//!
//! # The property
//!
//! **No descent is ever lost.** In storage terms: no committed writer's stamp is stranded below the
//! frontier, where no future sweep will visit it and it stays in-flight for ever. That is the `rmp`
//! #522 silent-data-loss shape, stated as a concurrency property.
//!
//! # Non-vacuity
//!
//! Every positive model is paired with a negative control that runs the *same* scenario with exactly
//! one operation replaced by the naive alternative, and requires that at least one interleaving
//! **loses** a descent. Two of the three controls do it by calling
//! [`FreezeFloor::reset`](graphus_freezefloor::FreezeFloor::reset) — the real, unconditional store —
//! in the sweep's role and in the rollback's role, so the loud warning on that method is backed by
//! measurement rather than by prose.
//!
//! The controls are also deliberately *narrow*: each leaves every other operation correct, so a
//! counted loss can only be attributed to the one operation under test. A control that broke two
//! things at once would fire for the wrong reason and prove nothing about either.

#![cfg(loom)]

use std::sync::Arc as StdArc;
use std::sync::atomic::{AtomicUsize, Ordering as StdOrdering};

use graphus_freezefloor::FreezeFloor;
use loom::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------------------------
// The modelled store
// ---------------------------------------------------------------------------------------------

/// The frontier a GC pass finds when it starts.
const INITIAL_FLOOR: u64 = 8;

/// The store's high-water mark: the frontier a pass publishes when it found nothing in flight.
const HIGH_WATER: u64 = 16;

/// The id the writer stamps — deliberately **below** [`INITIAL_FLOOR`].
///
/// This is not a contrived value. A writer descends below the current frontier whenever it touches an
/// **existing** record rather than appending a new one: a `SET` or `REMOVE` of an existing property
/// stamps a header the frontier has long since passed over (`rmp` #967). Those are precisely the
/// descents an unconditional raise can swallow, because they name ids the in-flight pass never
/// scanned.
const STAMPED_ID: u64 = 4;

/// "No record has been stamped yet." Physical id 0 is reserved by the record stores, so it is free to
/// serve as the sentinel here too.
const NO_STAMP: u64 = 0;

/// One record store, reduced to the two words this question depends on.
struct Store {
    floor: FreezeFloor,
    /// The id whose MVCC header bears an in-flight stamp, or [`NO_STAMP`].
    stamped: AtomicU64,
}

impl Store {
    fn new() -> Self {
        Self {
            floor: FreezeFloor::new(INITIAL_FLOOR),
            stamped: AtomicU64::new(NO_STAMP),
        }
    }
}

/// The freeze sweep's scan, reduced to its one load-bearing property: a pass that starts at `from`
/// reads `[from, HIGH_WATER)` and **nothing below `from`**.
///
/// Returns the frontier the pass would publish — the smallest scanned id still bearing an
/// in-flight-writer stamp, or [`HIGH_WATER`] if the scanned range held none.
fn scan_from(store: &Store, from: u64) -> u64 {
    let stamped = store.stamped.load(Ordering::Acquire);
    if stamped != NO_STAMP && stamped >= from {
        stamped
    } else {
        HIGH_WATER
    }
}

/// Reports how many of the explored executions lost a descent, and requires that at least one did.
///
/// `control` names the naive operation under test and `certifies` names the positive model it is the
/// control for. The count is **printed** (visible under `--nocapture`) and not merely asserted on,
/// because a control that has quietly narrowed from many losing interleavings to one is on its way to
/// becoming vacuous, and the number is the only warning of that anyone will get.
fn require_losses(control: &str, certifies: &str, losses: &AtomicUsize) {
    let lost = losses.load(StdOrdering::Relaxed);
    eprintln!("[negative control] {control}: {lost} explored execution(s) lost a descent");
    assert!(
        lost > 0,
        "{control} must lose a descent on at least one interleaving. Zero losses means this \
         control has stopped controlling anything — and with it, the guarantee `{certifies}` is \
         supposed to certify."
    );
}

/// One writer: stamp the record, **then** cover it with the frontier.
///
/// The order is the production order and it is an obligation, not a convenience — see the crate
/// documentation. Reversed, the frontier would advertise an id whose record does not yet look
/// interesting, and a pass scanning it would legitimately raise past a stamp that arrives a moment
/// later.
fn stamp_and_cover(store: &Store) {
    store.stamped.store(STAMPED_ID, Ordering::Release);
    store.floor.descend(STAMPED_ID);
}

// ---------------------------------------------------------------------------------------------
// Model 1 — two concurrent descents
// ---------------------------------------------------------------------------------------------

/// The frontier two racing writers start from.
const FLOOR_BEFORE_DESCENTS: u64 = 9;
/// The lower of the two ids they stamp — the one the frontier must end up covering.
const LOWER_DESCENT: u64 = 3;
/// The higher of the two.
const HIGHER_DESCENT: u64 = 6;

/// **The writers' property.** Two writers descending concurrently both land: the frontier ends at the
/// minimum of the two candidates, under every interleaving the memory model permits.
///
/// This is what `fetch_min` buys, and it is the reason the writer's operation was already correct
/// before `rmp` #1014 — the task's subject is the other two operations. The model is here so that a
/// future "simplification" of `descend` into a load-compare-store is caught by the checker rather than
/// by a corrupt database, and so that its negative control below has something to be a control *for*.
#[test]
fn two_concurrent_descents_are_never_lost() {
    loom::model(|| {
        let floor = StdArc::new(FreezeFloor::new(FLOOR_BEFORE_DESCENTS));

        let a = {
            let floor = StdArc::clone(&floor);
            loom::thread::spawn(move || {
                floor.descend(LOWER_DESCENT);
            })
        };
        let b = {
            let floor = StdArc::clone(&floor);
            loom::thread::spawn(move || {
                floor.descend(HIGHER_DESCENT);
            })
        };
        a.join().unwrap();
        b.join().unwrap();

        assert_eq!(
            floor.get(),
            LOWER_DESCENT,
            "both descents must land: the frontier must cover the lower of the two ids, or the \
             stamp at that id is stranded below it for ever (`rmp` #522)"
        );
    });
}

/// A frontier whose descent is a load, a comparison and a **separate** store — the shape that looks
/// equivalent to `fetch_min` and is not.
///
/// Kept as the standing negative control for [`two_concurrent_descents_are_never_lost`]. Every other
/// operation is absent because this control needs none: the loss is produced by the descent alone.
struct NaiveFloor(AtomicU64);

impl NaiveFloor {
    fn new(initial: u64) -> Self {
        Self(AtomicU64::new(initial))
    }

    fn get(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    /// The window: another writer may descend between the load and the store, and this store then
    /// overwrites it. The comparison was true when it was made and stale by the time it was acted on.
    fn descend_by_read_compare_write(&self, candidate: u64) {
        let current = self.0.load(Ordering::Acquire);
        if candidate < current {
            self.0.store(candidate, Ordering::Release);
        }
    }
}

/// **NEGATIVE CONTROL.** A load-compare-store descent must lose a descent on at least one
/// interleaving.
///
/// Counted rather than asserted per execution, because most interleavings are harmless: the claim is
/// "the memory model permits the loss", which is a claim about the set of executions, not about each
/// one. The counter is a `std` atomic living outside the model, so loom does not schedule it.
#[test]
fn naive_descent_loses_a_descent() {
    let losses = StdArc::new(AtomicUsize::new(0));
    let counter = StdArc::clone(&losses);

    loom::model(move || {
        let floor = StdArc::new(NaiveFloor::new(FLOOR_BEFORE_DESCENTS));

        let a = {
            let floor = StdArc::clone(&floor);
            loom::thread::spawn(move || floor.descend_by_read_compare_write(LOWER_DESCENT))
        };
        let b = {
            let floor = StdArc::clone(&floor);
            loom::thread::spawn(move || floor.descend_by_read_compare_write(HIGHER_DESCENT))
        };
        a.join().unwrap();
        b.join().unwrap();

        if floor.get() != LOWER_DESCENT {
            counter.fetch_add(1, StdOrdering::Relaxed);
        }
    });

    require_losses(
        "a (load, compare, store) descent",
        "two_concurrent_descents_are_never_lost",
        &losses,
    );
}

// ---------------------------------------------------------------------------------------------
// Model 2 — the freeze sweep's raise against a concurrent descent
// ---------------------------------------------------------------------------------------------

/// **The sweep's property.** A freeze sweep may never swallow a descent that landed after it loaded
/// its `from`.
///
/// The sweep runs its production shape — load the frontier, scan from there, publish conditionally —
/// while a writer stamps a record at [`STAMPED_ID`], an id **below** the frontier the sweep started
/// from, and covers it.
///
/// The property is that the frontier ends at or below [`STAMPED_ID`]. Why that is the right
/// yardstick, and not something weaker: the freeze sweep visits `[freeze_low, high_water)` and nothing
/// else, so a frontier left **above** an id has forfeited it. No later pass will ever look at that
/// record again, its committed writer's stamp stays in-flight for ever, and every subsequent
/// visibility decision about it is taken against a transaction that no longer exists.
///
/// Both ways of satisfying it are explored and both are correct:
///
/// * the descent lands first — the sweep's scan then covers [`STAMPED_ID`] (it is at or above the
///   `from` the sweep loaded), so the frontier it computes is `STAMPED_ID` itself;
/// * the descent lands inside the sweep's window — the compare-exchange is refused, and the lower
///   frontier survives to be re-scanned next pass.
#[test]
fn a_raise_never_swallows_a_concurrent_descent() {
    loom::model(|| {
        let store = StdArc::new(Store::new());

        let sweep = {
            let store = StdArc::clone(&store);
            loom::thread::spawn(move || {
                let from = store.floor.get();
                let new_low = scan_from(&store, from);
                // Ignoring the answer is the production behaviour: a refusal costs a re-scan on the
                // next pass and nothing else. There is nothing to recover from.
                let _ = store.floor.try_raise(from, new_low);
            })
        };
        let writer = {
            let store = StdArc::clone(&store);
            loom::thread::spawn(move || stamp_and_cover(&store))
        };
        sweep.join().unwrap();
        writer.join().unwrap();

        assert!(
            store.floor.get() <= STAMPED_ID,
            "the frontier ended at {} — above the id {STAMPED_ID} a writer had just stamped. The \
             sweep visits only [freeze_low, high_water), so that record will never be visited again \
             and its committed stamp stays in-flight for ever (`rmp` #522).",
            store.floor.get()
        );
    });
}

/// **NEGATIVE CONTROL.** The identical scenario with the sweep publishing by
/// [`FreezeFloor::reset`] — the real, unconditional store — must swallow the descent on at least one
/// interleaving.
///
/// Nothing else is changed: the writer still descends by `fetch_min`, the scan is the same, only the
/// publication differs. So a counted loss is attributable to the unconditional store and to nothing
/// else — which is the point of a control, and the reason it does not simply break several things at
/// once and observe that something went wrong.
///
/// This is also the empirical backing for the warning on [`FreezeFloor::reset`]: the method is called
/// here in exactly the role its documentation forbids, and the loss is counted.
#[test]
fn an_unconditional_raise_swallows_a_concurrent_descent() {
    let losses = StdArc::new(AtomicUsize::new(0));
    let counter = StdArc::clone(&losses);

    loom::model(move || {
        let store = StdArc::new(Store::new());

        let sweep = {
            let store = StdArc::clone(&store);
            loom::thread::spawn(move || {
                let from = store.floor.get();
                let new_low = scan_from(&store, from);
                // The defect: `new_low` is a statement about `[from, high_water)`, published as if it
                // were a statement about the whole store.
                store.floor.reset(new_low);
            })
        };
        let writer = {
            let store = StdArc::clone(&store);
            loom::thread::spawn(move || stamp_and_cover(&store))
        };
        sweep.join().unwrap();
        writer.join().unwrap();

        if store.floor.get() > STAMPED_ID {
            counter.fetch_add(1, StdOrdering::Relaxed);
        }
    });

    require_losses(
        "an unconditional store of the sweep's `new_low`",
        "a_raise_never_swallows_a_concurrent_descent",
        &losses,
    );
}

// ---------------------------------------------------------------------------------------------
// Model 3 — the rolled-back GC pass restoring its savepoint
// ---------------------------------------------------------------------------------------------

/// **The rollback's property.** A GC pass that sweeps and then rolls back must restore its frontier
/// savepoint **by descending to it**, and doing so may never swallow a concurrent descent.
///
/// This is not [`a_raise_never_swallows_a_concurrent_descent`] with different numbers, and it is worth
/// its own model for two reasons:
///
/// 1. **The fixed operation is a different primitive.** The sweep publishes by compare-exchange; the
///    restore publishes by `fetch_min`. A model of the former certifies nothing about the latter, and
///    "restoring by descending is sufficient to undo the raise" is a claim in its own right — `floor`
///    was `saved` before the raise, so `min(floor, saved)` puts it back exactly.
/// 2. **The interleaving is genuinely new.** The pass now performs *two* publications, and the
///    writer's descent can land in three distinct places rather than two: before the raise, **between
///    the raise and the restore**, or after both. The middle one does not exist in the model above,
///    and it is precisely the one an unconditional restore loses.
#[test]
fn a_rolled_back_sweep_never_swallows_a_concurrent_descent() {
    loom::model(|| {
        let store = StdArc::new(Store::new());

        let pass = {
            let store = StdArc::clone(&store);
            loom::thread::spawn(move || {
                // The savepoint the pass takes before its sweep.
                let savepoint = store.floor.get();
                let new_low = scan_from(&store, savepoint);
                let _ = store.floor.try_raise(savepoint, new_low);
                // The pass rolls back: undo the raise by descending to the savepoint.
                store.floor.descend(savepoint);
            })
        };
        let writer = {
            let store = StdArc::clone(&store);
            loom::thread::spawn(move || stamp_and_cover(&store))
        };
        pass.join().unwrap();
        writer.join().unwrap();

        assert!(
            store.floor.get() <= STAMPED_ID,
            "the frontier ended at {} — above the id {STAMPED_ID} a writer had just stamped. A \
             rollback must put the frontier back where it was, never above a descent that landed \
             while the pass was unwinding (`rmp` #522).",
            store.floor.get()
        );
    });
}

/// **NEGATIVE CONTROL.** The identical scenario with the restore performed by
/// [`FreezeFloor::reset`] must swallow the descent on at least one interleaving.
///
/// The sweep's raise stays a correct compare-exchange, so the only broken operation is the restore and
/// a counted loss can only come from it. The losing interleaving is the middle one named above: the
/// raise succeeds, the writer then descends to [`STAMPED_ID`], and the unconditional restore lifts the
/// frontier back to the savepoint — above the id the writer had just covered.
#[test]
fn an_unconditional_rollback_restore_swallows_a_concurrent_descent() {
    let losses = StdArc::new(AtomicUsize::new(0));
    let counter = StdArc::clone(&losses);

    loom::model(move || {
        let store = StdArc::new(Store::new());

        let pass = {
            let store = StdArc::clone(&store);
            loom::thread::spawn(move || {
                let savepoint = store.floor.get();
                let new_low = scan_from(&store, savepoint);
                let _ = store.floor.try_raise(savepoint, new_low);
                // The defect: the savepoint is a statement about a frontier that no longer exists.
                store.floor.reset(savepoint);
            })
        };
        let writer = {
            let store = StdArc::clone(&store);
            loom::thread::spawn(move || stamp_and_cover(&store))
        };
        pass.join().unwrap();
        writer.join().unwrap();

        if store.floor.get() > STAMPED_ID {
            counter.fetch_add(1, StdOrdering::Relaxed);
        }
    });

    require_losses(
        "an unconditional restore of the frontier savepoint",
        "a_rolled_back_sweep_never_swallows_a_concurrent_descent",
        &losses,
    );
}
