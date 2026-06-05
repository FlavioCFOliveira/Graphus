//! Deterministic random primitives for the simulation harness.
//!
//! Everything stochastic in a scenario — the workload, the fault schedule, the crash point —
//! is drawn from a single [`graphus_sim::SimRng`] seeded by the scenario seed, so the same seed
//! reproduces an identical run bit-for-bit (`specification/04-technical-design.md` §11.1: "fully
//! reproducible from a seed"). There is no wall clock and no OS entropy on any path.
//!
//! [`DetRng`] is a thin, allocation-free wrapper that adds the bounded-draw and weighted-choice
//! helpers the generators need on top of the project's raw [`Rng::next_u64`] source. It is
//! deliberately tiny: the determinism guarantee is only as strong as the single underlying stream,
//! so all draws funnel through one [`SimRng`].

use graphus_core::capability::Rng;
use graphus_sim::SimRng;

/// A deterministic random source for scenario generation, wrapping the project's seedable
/// [`SimRng`] with the bounded-draw helpers the workload and fault schedule need.
///
/// Cloning a `DetRng` snapshots the stream position, which lets the harness fork an independent
/// but reproducible sub-stream (e.g. to pre-plan a fault schedule without disturbing the workload
/// stream) when that is wanted; the default design keeps one stream for strict reproducibility.
#[derive(Debug, Clone)]
pub struct DetRng {
    inner: SimRng,
}

impl DetRng {
    /// Creates a deterministic source from `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            inner: SimRng::new(seed),
        }
    }

    /// The next raw 64-bit draw.
    pub fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }

    /// A uniform draw in `0..n`. Returns `0` when `n == 0` (the caller must guard empty ranges;
    /// this keeps the function total and panic-free).
    ///
    /// Uses the simple modulo reduction. The resulting modulo bias is negligible for the small
    /// `n` the harness uses (operation counts, collection indices) and, crucially, is *identical*
    /// for a given seed, which is all determinism requires.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        self.next_u64() % n
    }

    /// A uniform `usize` index in `0..len`. Returns `0` when `len == 0`.
    pub fn index(&mut self, len: usize) -> usize {
        if len == 0 {
            return 0;
        }
        (self.next_u64() % len as u64) as usize
    }

    /// A coin flip that is `true` with probability `percent`/100 (saturating at 100).
    pub fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent.min(100)
    }

    /// A uniform inclusive draw in `lo..=hi`. When `hi <= lo` it returns `lo`.
    pub fn range_inclusive(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        lo + self.below(hi - lo + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_stream() {
        let mut a = DetRng::new(7);
        let mut b = DetRng::new(7);
        let sa: Vec<u64> = (0..16).map(|_| a.next_u64()).collect();
        let sb: Vec<u64> = (0..16).map(|_| b.next_u64()).collect();
        assert_eq!(sa, sb);
    }

    #[test]
    fn below_is_bounded_and_total_on_zero() {
        let mut r = DetRng::new(1);
        for _ in 0..1000 {
            assert!(r.below(5) < 5);
        }
        assert_eq!(r.below(0), 0);
    }

    #[test]
    fn index_is_in_range_and_total_on_empty() {
        let mut r = DetRng::new(2);
        for _ in 0..1000 {
            assert!(r.index(3) < 3);
        }
        assert_eq!(r.index(0), 0);
    }

    #[test]
    fn range_inclusive_covers_both_ends_and_collapses() {
        let mut r = DetRng::new(3);
        let mut saw_lo = false;
        let mut saw_hi = false;
        for _ in 0..1000 {
            let v = r.range_inclusive(2, 4);
            assert!((2..=4).contains(&v));
            saw_lo |= v == 2;
            saw_hi |= v == 4;
        }
        assert!(saw_lo && saw_hi);
        assert_eq!(r.range_inclusive(9, 9), 9);
        assert_eq!(r.range_inclusive(9, 5), 9);
    }

    #[test]
    fn chance_extremes_are_deterministic() {
        let mut r = DetRng::new(4);
        for _ in 0..100 {
            assert!(!r.chance(0));
            assert!(r.chance(100));
            assert!(r.chance(200)); // saturates at 100
        }
    }
}
