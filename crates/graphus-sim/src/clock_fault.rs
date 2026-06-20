//! `clock_fault` — a deterministic, seed-driven **hostile clock** layer for Deterministic Simulation
//! Testing (rmp #233; `04-technical-design.md` §11; decision `D-dst-investment`).
//!
//! [`FaultyClock`] wraps any inner [`Clock`] (in practice the simulator's [`SharedClock`], driven by
//! the [`SimScheduler`](crate::SimScheduler)) and perturbs every reading with a fault stream that is a
//! **pure function of the plan's seed and the base time read** — there is no wall clock and no OS
//! entropy on any path, so the same [`ClockFaultPlan`] reproduces an identical sequence of hostile
//! readings bit-for-bit (mirrors the `graphus-io` `FaultPlan` house style). It models the three clock
//! pathologies a production server can meet:
//!
//! * **bounded skew** — a fixed signed offset (within a configured bound) added to every read, modelling
//!   a clock that runs a constant amount fast or slow;
//! * **forward jumps** — a seeded, bounded leap forward on some reads (an NTP step, a VM resume, a
//!   suspend/resume), so "now" can suddenly be far ahead;
//! * **non-monotonic regressions** — a seeded, bounded step *backward* on some reads (an NTP slew the
//!   wrong way, a `CLOCK_REALTIME` correction), so two successive reads can go *down*.
//!
//! # The monotonicity split (the heart of the tolerance contract)
//!
//! The [`Clock`] trait returns a single `u64`, but the engine reads it for two very different purposes,
//! with different requirements:
//!
//! * **Tolerant reads** ([`FaultyClock::now_nanos`], the trait method) — used for *timestamping* and
//!   *latency*: temporal Cypher (`datetime()`), audit-record stamps, REST clock readings, slow-query
//!   latency. These paths MUST survive an arbitrary (bounded) regression: the engine already computes
//!   every duration with `saturating_sub`, so a backward read yields a clamped (never negative)
//!   duration rather than a panic. So `now_nanos` exposes the *full* fault including regressions.
//! * **Monotone reads** ([`FaultyClock::now_nanos_monotone`]) — used where a *non-decreasing* source is
//!   a correctness precondition (lease/lock expiry, keep-alive deadlines, anything that must never move
//!   backward). These reads pass through a high-water mark: a faulted reading below the previous
//!   monotone reading is **saturated** up to it, so the value never regresses. Skew and forward jumps
//!   still pass through (they do not break monotonicity); only the regression is absorbed.
//!
//! This is the deliberate, documented split the simulator asserts against: the engine survives
//! regressions on tolerant reads, and never observes a regression on monotone reads.

use std::sync::atomic::{AtomicU64, Ordering};

use graphus_core::capability::Clock;

use crate::SimRng;

/// A seed-driven schedule of clock faults for a [`FaultyClock`], armed by value (the [`FaultyClock`]
/// owns its plan).
///
/// Each fault is opt-in (a zero/`None` field is inert) and every armed fault is a pure function of the
/// plan's seed *and the base time being read*, so the same plan injects an identical hostile reading
/// for the same underlying instant every run. Built fluently from a seed, exactly like the
/// `graphus-io` disk `FaultPlan`:
///
/// ```
/// use graphus_sim::{ClockFaultPlan, FaultyClock, SharedClock};
/// use graphus_core::capability::Clock;
///
/// let base = SharedClock::new(1_000);
/// let plan = ClockFaultPlan::new(0xC0FFEE)
///     .with_skew(500)              // up to ±500 ns constant offset
///     .with_forward_jumps(250, 10_000) // 25% of reads jump up to +10_000 ns
///     .with_regressions(250, 800); // 25% of reads step back up to 800 ns
/// let clock = FaultyClock::new(base, plan);
/// let _ = clock.now_nanos(); // a hostile but bounded, deterministic reading
/// ```
#[derive(Debug, Clone, Default)]
pub struct ClockFaultPlan {
    /// The seed every stochastic choice derives from.
    seed: u64,
    /// Maximum absolute constant skew (ns). The actual signed offset is drawn once from the seed and
    /// stays fixed for the clock's lifetime (a constant-rate-error model, not per-read jitter).
    skew_bound: u64,
    /// Probability (per mille, `0..=1000`) that a given read takes a forward jump, and the maximum jump
    /// magnitude (ns).
    jump_permille: u32,
    jump_bound: u64,
    /// Probability (per mille, `0..=1000`) that a given read regresses, and the maximum regression
    /// magnitude (ns).
    regress_permille: u32,
    regress_bound: u64,
}

impl ClockFaultPlan {
    /// Creates an empty plan seeded by `seed`. With no fault armed the plan is inert and a
    /// [`FaultyClock`] over it reads exactly like its inner clock.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            ..Self::default()
        }
    }

    /// Arms a bounded constant **skew**: a fixed signed offset, drawn once from the seed within
    /// `±bound` ns, added to every reading. Models a clock that runs steadily fast or slow.
    #[must_use]
    pub fn with_skew(mut self, bound: u64) -> Self {
        self.skew_bound = bound;
        self
    }

    /// Arms bounded **forward jumps**: each read takes a seeded forward leap of up to `bound` ns with
    /// probability `permille / 1000`. Models NTP steps, VM resume, suspend/resume.
    #[must_use]
    pub fn with_forward_jumps(mut self, permille: u32, bound: u64) -> Self {
        self.jump_permille = permille.min(1000);
        self.jump_bound = bound;
        self
    }

    /// Arms bounded **non-monotonic regressions**: each read steps *backward* by up to `bound` ns with
    /// probability `permille / 1000`. Models a backward clock correction. On the monotone read path the
    /// regression is absorbed by the high-water mark (see the module docs); on the tolerant read path it
    /// is exposed in full so the engine's `saturating_sub` duration arithmetic is exercised.
    #[must_use]
    pub fn with_regressions(mut self, permille: u32, bound: u64) -> Self {
        self.regress_permille = permille.min(1000);
        self.regress_bound = bound;
        self
    }

    /// Whether the plan arms any fault at all (an all-inert plan reads through transparently).
    #[must_use]
    pub fn is_inert(&self) -> bool {
        self.skew_bound == 0
            && (self.jump_permille == 0 || self.jump_bound == 0)
            && (self.regress_permille == 0 || self.regress_bound == 0)
    }

    /// The constant skew offset (ns), drawn once from the seed: a signed value in `[-bound, +bound]`.
    /// Deterministic per seed, computed on demand so the plan stays `Copy`-cheap and stateless.
    fn skew_offset(&self) -> i64 {
        if self.skew_bound == 0 {
            return 0;
        }
        // Mix the seed with a fixed tag so the skew draw is independent of the per-read jump/regress
        // streams (which mix in a different tag).
        let mut rng = SimRng::new(self.seed ^ 0x534B_4557_0000_0001); // "SKEW"
        let span = self.skew_bound.saturating_mul(2).saturating_add(1);
        let raw = rng.below(span); // 0..=2*bound
        (raw as i64) - (self.skew_bound as i64) // -bound..=+bound
    }
}

/// A deterministic [`Clock`] that perturbs an inner clock's readings with a seed-driven
/// [`ClockFaultPlan`] (bounded skew, forward jumps, non-monotonic regressions).
///
/// `FaultyClock` is `Send + Sync` (the engine's clock slot is an `Arc<dyn Clock + Send + Sync>`): the
/// only mutable state is the monotone high-water mark, held in an [`AtomicU64`], so concurrent reads on
/// the monotone path stay correct without a lock. The per-read fault is derived afresh from the plan
/// seed mixed with the base time, so it carries no read-order state — making it a pure function of the
/// inner clock's value and replayable from the seed alone.
///
/// # Tolerance contract
///
/// The simulator drives the engine under this clock and asserts the engine's documented tolerance to a
/// hostile clock. The contract has two halves, matching the two read methods:
///
/// | Read | Used for | Fault exposed | Engine guarantee |
/// |------|----------|---------------|------------------|
/// | [`now_nanos`](Clock::now_nanos) (tolerant) | timestamps, latency, temporal Cypher, audit/REST stamps | skew + forward jumps + **regressions** | **MUST survive**: no panic; every duration is `saturating_sub` so it is never negative; a slow-query/latency observation is clamped, never garbage |
/// | [`now_nanos_monotone`](Self::now_nanos_monotone) | lease/lock expiry, keep-alive deadlines | skew + forward jumps; **regressions absorbed** to the high-water mark | **MUST stay non-decreasing**: a backward reading is saturated up, so a deadline never moves earlier than a prior observation |
///
/// **Invariants that always hold, for any seed and any armed plan:**
///
/// 1. **Bounded.** Every reading lies within `[base − skew_bound − regress_bound, base + skew_bound +
///    jump_bound]`. No fault is unbounded; a hostile clock cannot send "now" to infinity or to zero.
/// 2. **Durations never negative.** Tolerant reads feed `saturating_sub`, so any measured elapsed time
///    is `≥ 0` even across a regression.
/// 3. **Monotone reads never regress.** Successive [`now_nanos_monotone`](Self::now_nanos_monotone)
///    readings are non-decreasing, by construction of the high-water mark.
/// 4. **Determinism.** Same plan seed + same sequence of base times ⇒ identical sequence of readings.
///
/// **What the engine MUST reject / refuse to rely on:** the engine must *not* assume the trait
/// [`now_nanos`](Clock::now_nanos) is monotonic — code that needs monotonicity must go through
/// [`now_nanos_monotone`](Self::now_nanos_monotone) (or saturate its own arithmetic). A regression on a
/// tolerant read is *tolerated*, not *trusted*: it never produces a negative duration, a panic, or a
/// timeout that fires before it was armed.
#[derive(Debug)]
pub struct FaultyClock<C: Clock> {
    inner: C,
    plan: ClockFaultPlan,
    /// Cached constant skew (drawn once from the seed), so every read applies the same offset.
    skew: i64,
    /// Highest monotone reading served so far — the high-water mark that absorbs regressions on the
    /// monotone read path.
    high_water: AtomicU64,
}

impl<C: Clock> FaultyClock<C> {
    /// Wraps `inner` with the seed-driven `plan`. With an inert plan the clock reads through
    /// transparently.
    #[must_use]
    pub fn new(inner: C, plan: ClockFaultPlan) -> Self {
        let skew = plan.skew_offset();
        Self {
            inner,
            plan,
            skew,
            high_water: AtomicU64::new(0),
        }
    }

    /// The hostile (possibly regressing) reading the [`Clock`] trait serves: the inner time plus the
    /// constant skew, plus a seeded forward jump or backward regression for this particular base time.
    /// Saturates at the `u64` bounds so it can never wrap. This is the **tolerant** read.
    fn faulted(&self, base: u64) -> u64 {
        // Apply the constant skew first (saturating both directions).
        let mut t = if self.skew >= 0 {
            base.saturating_add(self.skew as u64)
        } else {
            base.saturating_sub(self.skew.unsigned_abs())
        };

        // Per-read jump / regression: derive a private RNG from the plan seed mixed with the base time,
        // so the same base instant always faults the same way (no read-order state needed) and distinct
        // instants fault independently.
        let mut rng =
            SimRng::new(self.plan.seed ^ base.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x4A55_4D50);

        if self.plan.jump_bound > 0 && rng.chance(self.plan.jump_permille) {
            let jump = rng.range_inclusive(1, self.plan.jump_bound);
            t = t.saturating_add(jump);
        }
        if self.plan.regress_bound > 0 && rng.chance(self.plan.regress_permille) {
            let back = rng.range_inclusive(1, self.plan.regress_bound);
            t = t.saturating_sub(back);
        }
        t
    }

    /// A **monotone**, non-decreasing reading for code where a backward clock would be a correctness
    /// bug (lease/lock expiry, keep-alive deadlines). Skew and forward jumps pass through; a regression
    /// below the previous monotone reading is absorbed by saturating up to the high-water mark, so the
    /// returned value never goes down.
    ///
    /// The high-water mark is advanced with a CAS loop, so concurrent monotone reads stay correct
    /// without a lock.
    #[must_use]
    pub fn now_nanos_monotone(&self) -> u64 {
        let candidate = self.faulted(self.inner.now_nanos());
        let mut prev = self.high_water.load(Ordering::Relaxed);
        loop {
            let next = candidate.max(prev);
            match self.high_water.compare_exchange_weak(
                prev,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return next,
                Err(observed) => prev = observed,
            }
        }
    }

    /// Borrows the inner (un-faulted) clock, e.g. to set a [`SharedClock`](crate::SharedClock) from the
    /// scheduler.
    pub fn inner(&self) -> &C {
        &self.inner
    }
}

impl<C: Clock> Clock for FaultyClock<C> {
    /// The **tolerant** read: serves the full hostile reading (skew + jumps + regressions). The engine
    /// must survive every value this returns (see the type-level tolerance contract).
    fn now_nanos(&self) -> u64 {
        self.faulted(self.inner.now_nanos())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SharedClock, SimClock};

    /// Reads the tolerant fault for an ascending sweep of base instants (a pure function of the plan +
    /// base, so we can sweep the inner *value* without advancing a clock).
    fn sweep(clock: &FaultyClock<SimClock>, bases: &[u64]) -> Vec<u64> {
        bases.iter().map(|&b| clock.faulted(b)).collect()
    }

    fn plan_full(seed: u64) -> ClockFaultPlan {
        ClockFaultPlan::new(seed)
            .with_skew(500)
            .with_forward_jumps(400, 10_000)
            .with_regressions(400, 800)
    }

    #[test]
    fn inert_plan_reads_through_transparently() {
        let c = FaultyClock::new(SimClock::new(12_345), ClockFaultPlan::new(7));
        assert!(ClockFaultPlan::new(7).is_inert());
        assert_eq!(
            c.now_nanos(),
            12_345,
            "an inert plan must not perturb the read"
        );
        assert_eq!(c.now_nanos_monotone(), 12_345);
    }

    #[test]
    fn same_seed_same_base_is_identical() {
        let a = FaultyClock::new(SimClock::new(0), plan_full(0xABCDEF));
        let b = FaultyClock::new(SimClock::new(0), plan_full(0xABCDEF));
        let bases: Vec<u64> = (0..64).map(|i| i * 1000).collect();
        assert_eq!(
            sweep(&a, &bases),
            sweep(&b, &bases),
            "same seed ⇒ identical fault sequence over the same bases"
        );
    }

    #[test]
    fn distinct_seeds_diverge() {
        let a = FaultyClock::new(SimClock::new(0), plan_full(1));
        let b = FaultyClock::new(SimClock::new(0), plan_full(2));
        let bases: Vec<u64> = (0..64).map(|i| i * 1000).collect();
        assert_ne!(
            sweep(&a, &bases),
            sweep(&b, &bases),
            "different seeds must produce a different fault sequence"
        );
    }

    #[test]
    fn faulted_readings_are_bounded() {
        // For every seed and base, the reading stays within
        // [base - skew - regress, base + skew + jump].
        let skew = 500u64;
        let jump = 10_000u64;
        let regress = 800u64;
        for seed in [1u64, 2, 7, 42, 99, 1234, 0xDEAD_BEEF] {
            let c = FaultyClock::new(SimClock::new(0), plan_full(seed));
            for i in 0..512u64 {
                let base = 1_000_000 + i * 137;
                let r = c.faulted(base);
                let lo = base - skew - regress;
                let hi = base + skew + jump;
                assert!(
                    (lo..=hi).contains(&r),
                    "seed {seed} base {base}: reading {r} out of [{lo}, {hi}]"
                );
            }
        }
    }

    #[test]
    fn regressions_actually_occur_on_the_tolerant_read() {
        // With a high regression probability and zero skew/jump, some reads must fall *below* the base.
        let plan = ClockFaultPlan::new(0x5EED).with_regressions(900, 1000);
        let c = FaultyClock::new(SimClock::new(0), plan);
        let regressed = (0..256u64)
            .filter(|&i| {
                let base = 1_000_000 + i * 1000;
                c.faulted(base) < base
            })
            .count();
        assert!(
            regressed > 0,
            "a high regression rate must produce backward reads"
        );
    }

    #[test]
    fn forward_jumps_actually_occur() {
        let plan = ClockFaultPlan::new(0x10).with_forward_jumps(900, 50_000);
        let c = FaultyClock::new(SimClock::new(0), plan);
        let jumped = (0..256u64)
            .filter(|&i| {
                let base = 1_000_000 + i * 1000;
                c.faulted(base) > base
            })
            .count();
        assert!(jumped > 0, "a high jump rate must produce forward leaps");
    }

    #[test]
    fn skew_is_constant_and_bounded() {
        // A skew-only plan applies the *same* signed offset to every read (constant-rate error).
        let plan = ClockFaultPlan::new(0x5151).with_skew(300);
        let c = FaultyClock::new(SimClock::new(0), plan);
        let offset = c.faulted(1_000_000) as i64 - 1_000_000;
        assert!(
            (-300..=300).contains(&offset),
            "skew offset {offset} out of bound"
        );
        for base in [2_000_000u64, 3_000_000, 5_000_000] {
            assert_eq!(
                c.faulted(base) as i64 - base as i64,
                offset,
                "skew must be a constant offset across reads"
            );
        }
    }

    #[test]
    fn monotone_read_never_regresses() {
        // Drive the monotone read over a slowly-advancing inner clock under a hostile (regressing)
        // plan. The served sequence must be non-decreasing even though the underlying faulted reads
        // dip below their predecessors. The inner is a `SharedClock` (the real production wiring) so a
        // single `FaultyClock` keeps its high-water mark across the whole sweep.
        let inner = SharedClock::new(1_000_000);
        let clock = FaultyClock::new(inner.clone(), plan_full(0xBADC0DE));
        let mut last = 0u64;
        let mut regressions_seen_on_tolerant = 0u64;
        for step in 0..1024u64 {
            // Base advances slowly (50 ns) so a regression of up to 800 ns can dip below the previous
            // monotone reading — the case the high-water mark must absorb.
            let base = 1_000_000 + step * 50;
            inner.set(base);
            // Confirm the *tolerant* read genuinely regresses sometimes (otherwise the monotone test is
            // vacuous), then confirm the *monotone* read never does.
            if step > 0 && clock.now_nanos() < base {
                regressions_seen_on_tolerant += 1;
            }
            let v = clock.now_nanos_monotone();
            assert!(v >= last, "monotone read regressed: {v} < {last}");
            last = v;
        }
        assert!(
            regressions_seen_on_tolerant > 0,
            "the plan must actually regress the tolerant read, else the monotone guard is untested"
        );
    }
}
