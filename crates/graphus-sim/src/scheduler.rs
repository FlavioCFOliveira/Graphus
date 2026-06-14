//! [`SimScheduler`] — the deterministic discrete-event scheduler at the heart of the VOPR-style
//! simulator (`04-technical-design.md` §11; decision `D-dst-investment`; rmp #161).
//!
//! Everything that happens in a simulation run — a virtual client sending its next request, the
//! network delivering a delayed byte segment, a timeout firing — is a **timed event** on this one
//! scheduler. The scheduler owns the single **logical clock** (nanoseconds) and a single
//! [`SimRng`](crate::SimRng), so the *entire* run is a pure function of the seed: same seed ⇒ same
//! event order ⇒ same execution ⇒ same pass/fail (TigerBeetle's VOPR property, adapted).
//!
//! ## Ordering and why it is seed-driven
//!
//! Events are dispatched in non-decreasing **due time**. Among events due at the *same* tick the
//! order is decided by a per-event **priority drawn from the RNG at scheduling time**, then by a
//! monotonic sequence number as a final, total tie-break. So:
//!
//! - **Same seed ⇒ identical order** — the priorities are the same draws in the same places.
//! - **Different seed ⇒ different (but still valid) order** — the priorities differ, so simultaneous
//!   events interleave differently, which is exactly how the simulator explores schedules.
//!
//! The clock only moves **forward** to the due time of the event being dispatched; it never moves on
//! its own. A run is therefore a finite sequence of `next()` calls that drains the queue (plus
//! whatever new events each dispatched event schedules).

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use graphus_core::capability::Rng;

use crate::SimRng;

/// A deterministic discrete-event scheduler over events of payload type `P`.
///
/// Construct with a seed, [`schedule_after`](Self::schedule_after) work, then drain with
/// [`next`](Self::next). The same seed and the same scheduling calls always produce the same dispatch
/// order and the same clock readings.
#[derive(Debug)]
pub struct SimScheduler<P> {
    rng: SimRng,
    now: u64,
    seq: u64,
    queue: BinaryHeap<Slot<P>>,
}

/// One queued event: its due time, the RNG-drawn priority that orders simultaneous events, a total
/// tie-break sequence, and the caller's payload.
#[derive(Debug)]
struct Slot<P> {
    due: u64,
    priority: u64,
    seq: u64,
    payload: P,
}

// The heap is a *min*-heap on `(due, priority, seq)`: `Ord` is written so the "greatest" slot is the
// one that should dispatch first (earliest due, then lowest priority, then lowest seq), because
// `BinaryHeap` pops the maximum.
impl<P> Ord for Slot<P> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse the natural order of the key so smaller keys are "greater" (pop first).
        other
            .due
            .cmp(&self.due)
            .then_with(|| other.priority.cmp(&self.priority))
            .then_with(|| other.seq.cmp(&self.seq))
    }
}

impl<P> PartialOrd for Slot<P> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<P> PartialEq for Slot<P> {
    fn eq(&self, other: &Self) -> bool {
        // `seq` is unique per scheduler, so equality reduces to it (no two live slots share a seq).
        self.seq == other.seq && self.due == other.due && self.priority == other.priority
    }
}

impl<P> Eq for Slot<P> {}

impl<P> SimScheduler<P> {
    /// Creates a scheduler seeded with `seed`, its clock at 0.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            rng: SimRng::new(seed),
            now: 0,
            seq: 0,
            queue: BinaryHeap::new(),
        }
    }

    /// The current logical time in nanoseconds (the due time of the most recently dispatched event,
    /// or 0 before the first [`next`](Self::next)).
    #[must_use]
    pub fn now(&self) -> u64 {
        self.now
    }

    /// Whether the event queue is empty (the run has drained).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// The number of events still queued.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Mutable access to the scheduler's RNG, so callers make *all* their random choices from the one
    /// seeded stream (which client acts, which fault fires) — keeping the whole run reproducible.
    pub fn rng(&mut self) -> &mut SimRng {
        &mut self.rng
    }

    /// Schedules `payload` to dispatch `delay` nanoseconds from now, returning its sequence id. A
    /// `delay` of 0 makes it due at the current tick (it still orders after already-dispatched work,
    /// and among other same-tick events by its RNG-drawn priority).
    pub fn schedule_after(&mut self, delay: u64, payload: P) -> u64 {
        let due = self.now.saturating_add(delay);
        self.schedule_at(due, payload)
    }

    /// Schedules `payload` at the absolute time `due` (clamped to never be in the past), returning its
    /// sequence id.
    pub fn schedule_at(&mut self, due: u64, payload: P) -> u64 {
        let due = due.max(self.now);
        let priority = self.rng.next_u64();
        let id = self.seq;
        self.seq += 1;
        self.queue.push(Slot {
            due,
            priority,
            seq: id,
            payload,
        });
        id
    }

    /// The due time of the next event to dispatch, without removing it.
    #[must_use]
    pub fn peek_due(&self) -> Option<u64> {
        self.queue.peek().map(|s| s.due)
    }

    /// Dispatches the next event: advances the clock to its due time and returns `(time, payload)`.
    /// Returns `None` when the queue is empty.
    // Not `Iterator::next`: dispatching mutates the clock and the run can schedule new events between
    // pops, so a borrowing `&mut self` method reads more clearly than an `Iterator` impl (same choice
    // the engine's `stream::RowReceiver::next` makes).
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<(u64, P)> {
        let slot = self.queue.pop()?;
        // The clock only moves forward (`schedule_*` clamps `due >= now`, so this is monotonic).
        self.now = slot.due;
        Some((slot.due, slot.payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drains a scheduler into the dispatched `(time, payload)` sequence.
    fn drain<P>(mut s: SimScheduler<P>) -> Vec<(u64, P)> {
        let mut out = Vec::new();
        while let Some(ev) = s.next() {
            out.push(ev);
        }
        out
    }

    /// Builds a scheduler with a fixed script of (delay, label) events scheduled in a fixed order,
    /// some sharing a due time so the RNG tie-break is exercised.
    fn scripted(seed: u64) -> SimScheduler<u32> {
        let mut s = SimScheduler::new(seed);
        // Several events at the SAME due time (10) so their relative order is RNG-decided.
        s.schedule_after(10, 1);
        s.schedule_after(10, 2);
        s.schedule_after(10, 3);
        s.schedule_after(10, 4);
        s.schedule_after(5, 5);
        s.schedule_after(20, 6);
        s
    }

    #[test]
    fn same_seed_yields_identical_dispatch_order() {
        let a = drain(scripted(7));
        let b = drain(scripted(7));
        assert_eq!(a, b, "same seed ⇒ identical (time, payload) sequence");
    }

    #[test]
    fn different_seeds_reorder_simultaneous_events_non_vacuously() {
        let a = drain(scripted(1));
        let b = drain(scripted(999_983));
        assert_ne!(a, b, "different seeds must reorder the same-tick events");

        // Non-vacuity: both runs dispatch the SAME multiset of payloads — only the order differs.
        let mut pa: Vec<u32> = a.iter().map(|(_, p)| *p).collect();
        let mut pb: Vec<u32> = b.iter().map(|(_, p)| *p).collect();
        pa.sort_unstable();
        pb.sort_unstable();
        assert_eq!(pa, pb, "both runs dispatch every event exactly once");
    }

    #[test]
    fn clock_is_monotonic_and_respects_due_order() {
        let times: Vec<u64> = drain(scripted(42)).iter().map(|(t, _)| *t).collect();
        let mut sorted = times.clone();
        sorted.sort_unstable();
        assert_eq!(times, sorted, "events dispatch in non-decreasing due time");
        assert_eq!(times.first(), Some(&5), "the earliest event (due 5) is first");
        assert_eq!(times.last(), Some(&20), "the latest event (due 20) is last");
    }

    #[test]
    fn nested_scheduling_during_dispatch_is_ordered() {
        // An event that schedules a follow-up must see the follow-up dispatched at the right time.
        let mut s: SimScheduler<u32> = SimScheduler::new(3);
        s.schedule_after(10, 100);
        let mut seen = Vec::new();
        while let Some((t, p)) = s.next() {
            seen.push((t, p));
            if p == 100 {
                s.schedule_after(5, 200); // due at 15
            }
        }
        assert_eq!(seen, vec![(10, 100), (15, 200)]);
    }
}
