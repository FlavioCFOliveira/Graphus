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

use graphus_core::{GraphusError, Result, Timestamp};

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

    /// Advances the monotonic counter, returning the next timestamp, or a recoverable error when the
    /// 63-bit timestamp space is exhausted (SEC-200, CWE-190).
    ///
    /// The high bit is reserved by the version-stamp convention (`04 §5.2`) to discriminate
    /// in-flight `TxnId`s from committed `Timestamp`s, so the usable space is `1..=MAX_TIMESTAMP`.
    /// Exhaustion is astronomically unreachable in practice (2^63 timestamps), but it must degrade
    /// gracefully (a refused transaction) rather than panic the process: under the project's
    /// declared multi-threaded high-load promotion a crash-on-exhaustion would be a DoS.
    ///
    /// # Errors
    /// [`GraphusError::Transaction`] when no further timestamp can be issued.
    fn tick(&mut self) -> Result<Timestamp> {
        let next = self
            .next_counter
            .checked_add(1)
            .filter(|n| *n <= MAX_TIMESTAMP)
            .ok_or_else(|| {
                GraphusError::Transaction(
                    "timestamp oracle exhausted the 63-bit timestamp space".to_owned(),
                )
            })?;
        self.next_counter = next;
        Ok(Timestamp(next))
    }

    /// Issues a begin timestamp and registers it as an active snapshot.
    ///
    /// The returned timestamp is the transaction's read snapshot; the caller MUST later call
    /// [`release_begin`](Self::release_begin) exactly once (on commit or abort) so the low-water
    /// mark can advance.
    ///
    /// # Errors
    /// [`GraphusError::Transaction`] if the timestamp space is exhausted (see [`tick`](Self::tick)).
    pub fn begin(&mut self) -> Result<Timestamp> {
        let ts = self.tick()?;
        // Keep `active_begins` sorted so `low_water_mark` is `active_begins[0]`.
        let pos = self.active_begins.partition_point(|t| *t <= ts);
        self.active_begins.insert(pos, ts);
        Ok(ts)
    }

    /// Issues a commit timestamp (strictly greater than every previously issued timestamp).
    ///
    /// # Errors
    /// [`GraphusError::Transaction`] if the timestamp space is exhausted (see [`tick`](Self::tick)).
    pub fn commit(&mut self) -> Result<Timestamp> {
        self.tick()
    }

    /// Releases the begin timestamp of a finished transaction (commit or abort).
    ///
    /// A defensive no-op when `begin_ts` is not currently active: rather than panic on a bookkeeping
    /// inconsistency (SEC-200, CWE-248) — which under a future multi-threaded promotion would be a
    /// fragile crash vector — it returns `false` so the caller can log and continue. Returns `true`
    /// when a matching active begin timestamp was found and removed.
    pub fn release_begin(&mut self, begin_ts: Timestamp) -> bool {
        if let Some(pos) = self.active_begins.iter().position(|t| *t == begin_ts) {
            self.active_begins.remove(pos);
            true
        } else {
            false
        }
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
        let a = o.begin().unwrap();
        let b = o.commit().unwrap();
        let c = o.begin().unwrap();
        assert_eq!(a, Timestamp(1));
        assert!(a < b && b < c);
    }

    #[test]
    fn low_water_mark_tracks_oldest_active_begin() {
        let mut o = TimestampOracle::new();
        assert_eq!(o.low_water_mark(), None);
        let t1 = o.begin().unwrap();
        let t2 = o.begin().unwrap();
        assert_eq!(o.low_water_mark(), Some(t1));
        assert!(o.release_begin(t1));
        // Once the oldest reader leaves, the mark advances to the next oldest.
        assert_eq!(o.low_water_mark(), Some(t2));
        assert!(o.release_begin(t2));
        assert_eq!(o.low_water_mark(), None);
        assert_eq!(o.active_count(), 0);
    }

    #[test]
    fn release_out_of_order_still_yields_correct_mark() {
        let mut o = TimestampOracle::new();
        let t1 = o.begin().unwrap();
        let t2 = o.begin().unwrap();
        let _t3 = o.begin().unwrap();
        assert!(o.release_begin(t2)); // middle reader leaves first
        assert_eq!(o.low_water_mark(), Some(t1));
        assert!(o.release_begin(t1));
        // t3 is now the oldest active.
        assert_eq!(o.low_water_mark(), Some(Timestamp(3)));
    }

    #[test]
    fn release_of_unknown_begin_is_a_defensive_no_op() {
        // Regression: SEC-200. A bookkeeping inconsistency must not panic; release returns false.
        let mut o = TimestampOracle::new();
        let t1 = o.begin().unwrap();
        assert!(!o.release_begin(Timestamp(999)), "unknown ts is a no-op");
        assert_eq!(o.low_water_mark(), Some(t1), "active set is untouched");
    }

    #[test]
    fn tick_errors_at_exhaustion_instead_of_panicking() {
        // Regression: SEC-200/197. Drive the counter to the last legal value and confirm the next
        // issue is a recoverable error, not a panic.
        let mut o = TimestampOracle::new();
        o.next_counter = MAX_TIMESTAMP; // one below would-be-illegal
        assert!(
            o.begin().is_err(),
            "exhausted oracle must refuse, not panic"
        );
        assert!(o.commit().is_err(), "commit at exhaustion must refuse too");
    }
}
