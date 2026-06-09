//! The timestamp oracle and the committed-vs-in-flight version-stamp convention.
//!
//! The oracle (`04 §5.2`) is the single monotonic source of logical time for the manager. It
//! issues:
//!
//! - a **begin timestamp** at transaction start, which *is* the transaction's read snapshot
//!   ([`Snapshot`](crate::snapshot::Snapshot)); and
//! - a **commit timestamp** assigned atomically at commit, *after* SSI validation succeeds.
//!
//! It also tracks the set of **active begin timestamps** so it can publish the **low-water mark**
//! (the oldest live snapshot) that drives version garbage collection (`04 §5.5`).
//!
//! ## The version-stamp convention (`04 §5.2`, `05 §7`)
//!
//! The frozen MVCC record header (`graphus_storage::record::MvccHeader`) stores `created_ts`
//! (a.k.a. `xmin`) and `expired_ts` (a.k.a. `xmax`) as raw `u64`s. A single field must therefore
//! encode **either** a committed [`Timestamp`] **or** the [`TxnId`] of a still-in-flight writer.
//! Graphus distinguishes them by the **high bit** (`04 §5.2`: "distinguished from committed
//! timestamps by a high bit"):
//!
//! - bit 63 **clear** → the value is a committed commit-[`Timestamp`];
//! - bit 63 **set** → the low 63 bits are an in-flight [`TxnId`]; the writer's commit timestamp is
//!   not yet known and must be resolved through the Active Transaction Table.
//!
//! The sentinel `0` keeps its frozen meaning ("`expired_ts == 0` ⇒ live"); the oracle therefore
//! never issues timestamp `0` (it starts at `1`), and `TxnId(0)` is reserved (never a writer).
//!
//! This module owns [`VersionStamp`], the typed view over that one `u64`, so every other module
//! reads and writes the convention through one place rather than re-deriving the bit twiddling.

use graphus_core::Timestamp;

// The version-stamp convention (committed-`Timestamp` vs in-flight-`TxnId`, discriminated by the
// high bit) is shared with `graphus-storage`'s frozen `MvccHeader`, so it lives in the
// dependency-free `graphus-core` as the single source of truth. Re-exported here so the
// historical `crate::oracle::VersionStamp` / `MAX_TIMESTAMP` paths keep resolving.
pub use graphus_core::{MAX_TIMESTAMP, VersionStamp};

/// A monotonic logical-time source that also tracks the oldest live snapshot (`04 §5.2`, `§5.5`).
///
/// Single-threaded by design: the manager owns it behind its own `&mut`. (When the manager is
/// later promoted to a shared, multi-threaded service the oracle becomes the obvious place to put
/// an atomic counter; the API here is the contract that promotion must preserve.)
#[derive(Debug)]
pub struct TimestampOracle {
    /// The last timestamp handed out; the next is `next_counter + 1`.
    next_counter: u64,
    /// Multiset of begin timestamps of currently active transactions, ascending. A `Vec` (rather
    /// than a set) because two transactions can share a begin timestamp and both must be tracked.
    active_begins: Vec<Timestamp>,
}

impl Default for TimestampOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl TimestampOracle {
    /// A fresh oracle whose first issued timestamp is `Timestamp(1)`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_counter: 0,
            active_begins: Vec::new(),
        }
    }

    fn tick(&mut self) -> Timestamp {
        self.next_counter += 1;
        assert!(
            self.next_counter <= MAX_TIMESTAMP,
            "timestamp oracle exhausted the 63-bit timestamp space"
        );
        Timestamp(self.next_counter)
    }

    /// Issues a begin timestamp and registers it as an active snapshot.
    ///
    /// The returned timestamp is the transaction's read snapshot; the caller MUST later call
    /// [`release_begin`](Self::release_begin) exactly once (on commit or abort) so the low-water
    /// mark can advance.
    pub fn begin(&mut self) -> Timestamp {
        let ts = self.tick();
        // Keep `active_begins` sorted so `low_water_mark` is `active_begins[0]`.
        let pos = self.active_begins.partition_point(|t| *t <= ts);
        self.active_begins.insert(pos, ts);
        ts
    }

    /// Issues a commit timestamp (strictly greater than every previously issued timestamp).
    pub fn commit(&mut self) -> Timestamp {
        self.tick()
    }

    /// Releases the begin timestamp of a finished transaction (commit or abort).
    ///
    /// # Panics
    /// Panics if `begin_ts` was not an active begin timestamp — a manager bookkeeping invariant.
    pub fn release_begin(&mut self, begin_ts: Timestamp) {
        let pos = self
            .active_begins
            .iter()
            .position(|t| *t == begin_ts)
            .expect("INVARIANT: released begin timestamp must be active");
        self.active_begins.remove(pos);
    }

    /// The current low-water mark (`04 §5.5`): the oldest active begin timestamp, or `None` when
    /// no transaction is active.
    ///
    /// Any version whose `expired_ts` is committed `≤` this mark is invisible to every live (and
    /// future) snapshot and is therefore eligible for garbage collection.
    #[must_use]
    pub fn low_water_mark(&self) -> Option<Timestamp> {
        self.active_begins.first().copied()
    }

    /// The number of currently active transactions (observability / GC metric, NFR-10).
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active_begins.len()
    }

    /// The most recently issued timestamp (`0` before any has been issued). Test/inspection aid.
    #[must_use]
    pub fn current(&self) -> Timestamp {
        Timestamp(self.next_counter)
    }
}

#[cfg(test)]
mod tests {
    // The `VersionStamp` round-trip/aliasing/panic tests live with the type in `graphus-core`'s
    // `version` module (the convention's single source of truth); here we test the oracle only.
    use super::*;

    #[test]
    fn timestamps_are_strictly_monotonic() {
        let mut o = TimestampOracle::new();
        let a = o.begin();
        let b = o.commit();
        let c = o.begin();
        assert_eq!(a, Timestamp(1));
        assert!(a < b && b < c);
    }

    #[test]
    fn low_water_mark_tracks_oldest_active_begin() {
        let mut o = TimestampOracle::new();
        assert_eq!(o.low_water_mark(), None);
        let t1 = o.begin();
        let t2 = o.begin();
        assert_eq!(o.low_water_mark(), Some(t1));
        o.release_begin(t1);
        // Once the oldest reader leaves, the mark advances to the next oldest.
        assert_eq!(o.low_water_mark(), Some(t2));
        o.release_begin(t2);
        assert_eq!(o.low_water_mark(), None);
        assert_eq!(o.active_count(), 0);
    }

    #[test]
    fn release_out_of_order_still_yields_correct_mark() {
        let mut o = TimestampOracle::new();
        let t1 = o.begin();
        let t2 = o.begin();
        let _t3 = o.begin();
        o.release_begin(t2); // middle reader leaves first
        assert_eq!(o.low_water_mark(), Some(t1));
        o.release_begin(t1);
        // t3 is now the oldest active.
        assert_eq!(o.low_water_mark(), Some(Timestamp(3)));
    }
}
