//! Record-read accounting for the property read path (`rmp` #967, acceptance criterion 2).
//!
//! # What it proves, and why a count rather than a timing
//!
//! `rmp` #967 replaces "tombstone the old version + prepend the new one onto the `first_prop`
//! chain" with "newest version in place + the old value on the undo-delta chain". Its acceptance
//! criterion 2 is that **reading the visible property does not walk the chain when the reader sees
//! the live version**, and it demands that this be *proven by a record-read count*.
//!
//! A count is the right proof, and a timing is not, for three reasons:
//!
//! 1. **It is a structural invariant, not a performance observation.** "Serving one visible-property
//!    read performs exactly one `props.store` record read" is either true or false; it holds
//!    identically on every machine, at every optimisation level, under every load. A latency
//!    threshold is a property of the host, so it has to be re-tuned per machine and silently rots.
//! 2. **A timing cannot distinguish "no walk" from "a cheap walk".** The whole property chain of one
//!    entity occupies a handful of 8 KiB pages, and after the write ramp every one of them is
//!    resident in the buffer pool. A chain step is therefore a pinned-page read plus a 46-byte
//!    decode — tens of nanoseconds. A reader could still walk M records and merely *look* fast on a
//!    machine with a large L2, so a timing that improved would not establish that the walk is gone.
//! 3. **The available substrate counters measure the wrong layer.** `graphus-bufpool`'s
//!    `bufpool-probe` exposes `device_read_waits`, which counts *cache-miss device* reads. On the
//!    warm pool this path runs on, that counter reads zero whether the chain is walked or not. Page
//!    fetches are no better: M chain records share ~M/177 pages, so a page count is dominated by
//!    record density and residency rather than by chain length. Only a **record** read count exposes
//!    the walk.
//!
//! The invariant this makes checkable is therefore: `prop_reads` for one visible-property read is
//! **independent of M**, the number of prior overwrites of that key. Today it is `M + 1`; after #967
//! it must be `1`.
//!
//! # Where the counters are incremented
//!
//! Exactly two sites, both the sole authoritative decode for their store:
//!
//! * `props.store` — [`crate::read_view::read_prop`], the one and only place a [`PropRecord`] is
//!   decoded in the whole workspace. `RecordStore::read_prop` (the inline read path) and
//!   `StoreReadView::read_prop` (the off-thread reader-pool path) both delegate to it, so the count
//!   covers both read paths by construction and cannot drift between them.
//!   [`crate::read_view::collect_prop_chain`] — the `first_prop`/`next_prop` walk — calls it once per
//!   chain link, so `prop_reads` *is* the number of chain links visited.
//! * `undo.store` — `RecordStore::read_delta`, the one and only place an [`crate::undo::UndoDelta`]
//!   is decoded. It is instrumented now, before #967 routes reads through the delta chain, so the
//!   same proof keeps its meaning afterwards: the fix must not merely move the walk from one store
//!   to the other.
//! * `commit.store` — `RecordStore::read_commit_slot`, the one and only place a
//!   [`crate::undo::CommitSlot`] is decoded. Under the ratified design the undo chain becomes the
//!   sole visibility oracle for a property value and the cell's `created_ts` is informative only, so
//!   resolving visibility means resolving commit information through this indirection. Counting it
//!   separately is what stops the walk from being relocated a second time: a read that visits one
//!   property record but N commit slots has not become O(1), it has only moved its cost.
//!
//! Page-batched maintenance sweeps (`read_view::for_each_record_slot*`, used by GC/freeze) decode
//! only the MVCC header, never a whole record, and are not on the visible-property read path. They
//! are deliberately not counted.
//!
//! # Cost
//!
//! **Feature off (the default, and every production build): zero.** [`note_prop_read`] and
//! [`note_undo_read`] compile to empty `#[inline(always)]` bodies, so no instruction, no branch and
//! no memory traffic reaches the read path. The observation API ([`counting`], [`RecordReads`]) does
//! not exist at all in that build, which is deliberate — see below.
//!
//! **Feature on:** one thread-local `Cell` read-modify-write per record read (a TLS slot access plus
//! an add — single-digit nanoseconds, no atomic, no contention). A `Cell` rather than an
//! `AtomicU64` because the count must attribute to *the thread serving this read*: the off-thread
//! reader pool serves several reads concurrently, and a process-wide atomic would blend them into a
//! number that proves nothing about any single read.
//!
//! This is a Cargo feature rather than a dev-dependency for the reason `bufpool-probe` already
//! documents in `Cargo.toml`: a dev-dependency carrying the feature would be unified into every
//! `cargo test`/`cargo bench` resolve for the workspace, instrumenting the very hot path the
//! certification gate exists to certify. Behind a feature, the default gate compiles the production
//! shape.
//!
//! # Why the observation API vanishes when the feature is off
//!
//! [`counting`] and [`RecordReads`] are gated on the feature, so a test that asserts a record-read
//! count **fails to compile** without it. The alternative — returning `0` when uninstrumented —
//! would let `assert_eq!(reads.prop, 1)` quietly become `assert_eq!(0, 1)`, or worse, let a future
//! `assert_eq!(reads.prop, 0)` pass vacuously in the default build while proving nothing. A test
//! that cannot observe its subject must not compile rather than silently succeed.
//!
//! # Running it
//!
//! ```text
//! cargo test  -p graphus-storage --features read-probe --test prop_visible_read_record_count
//! cargo bench -p graphus-bench   --features read-probe --bench prop_overwrite
//! ```

#[cfg(feature = "read-probe")]
mod imp {
    use std::cell::Cell;

    thread_local! {
        /// `props.store` record reads performed by this thread since the last [`reset`].
        static PROP_READS: Cell<u64> = const { Cell::new(0) };
        /// `undo.store` delta reads performed by this thread since the last [`reset`].
        static UNDO_READS: Cell<u64> = const { Cell::new(0) };
        /// `commit.store` slot reads performed by this thread since the last [`reset`].
        static COMMIT_READS: Cell<u64> = const { Cell::new(0) };
    }

    /// Records one `props.store` record read on the calling thread.
    #[inline]
    pub fn note_prop_read() {
        PROP_READS.with(|c| c.set(c.get().wrapping_add(1)));
    }

    /// Records one `undo.store` delta read on the calling thread.
    #[inline]
    pub fn note_undo_read() {
        UNDO_READS.with(|c| c.set(c.get().wrapping_add(1)));
    }

    /// Records one `commit.store` slot read on the calling thread.
    #[inline]
    pub fn note_commit_slot_read() {
        COMMIT_READS.with(|c| c.set(c.get().wrapping_add(1)));
    }

    /// Zeroes every counter on the calling thread.
    pub fn reset() {
        PROP_READS.with(|c| c.set(0));
        UNDO_READS.with(|c| c.set(0));
        COMMIT_READS.with(|c| c.set(0));
    }

    /// The calling thread's counters since the last [`reset`].
    #[must_use]
    pub fn snapshot() -> super::RecordReads {
        super::RecordReads {
            prop: PROP_READS.with(Cell::get),
            undo: UNDO_READS.with(Cell::get),
            commit: COMMIT_READS.with(Cell::get),
        }
    }
}

#[cfg(not(feature = "read-probe"))]
mod imp {
    /// No-op: the `read-probe` feature is off, so the read path carries no instrumentation.
    #[inline(always)]
    pub fn note_prop_read() {}

    /// No-op: the `read-probe` feature is off, so the read path carries no instrumentation.
    #[inline(always)]
    pub fn note_undo_read() {}

    /// No-op: the `read-probe` feature is off, so the read path carries no instrumentation.
    #[inline(always)]
    pub fn note_commit_slot_read() {}
}

pub use imp::{note_commit_slot_read, note_prop_read, note_undo_read};

/// Record reads attributed to one measured region, per store (`rmp` #967 AC 2).
///
/// Only exists with the `read-probe` feature, so a count assertion cannot compile — and therefore
/// cannot pass vacuously — in an uninstrumented build.
#[cfg(feature = "read-probe")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecordReads {
    /// `props.store` record reads — the number of property-chain links visited.
    pub prop: u64,
    /// `undo.store` delta reads — the number of undo-chain links visited.
    pub undo: u64,
    /// `commit.store` slot reads — the number of commit-indirection resolutions performed.
    pub commit: u64,
}

#[cfg(feature = "read-probe")]
impl RecordReads {
    /// Total record reads across all three stores.
    #[must_use]
    pub fn total(self) -> u64 {
        self.prop + self.undo + self.commit
    }
}

/// Runs `f` with the calling thread's counters zeroed, returning its value and the record reads it
/// performed.
///
/// Nesting is **not** supported: an inner `counting` resets the outer region's tally. Measure one
/// region at a time.
///
/// # Panics
/// Propagates any panic from `f` (the counters are thread-local and are re-zeroed by the next
/// `counting`, so a panicking `f` leaves no state to corrupt).
#[cfg(feature = "read-probe")]
pub fn counting<T>(f: impl FnOnce() -> T) -> (T, RecordReads) {
    imp::reset();
    let out = f();
    (out, imp::snapshot())
}
