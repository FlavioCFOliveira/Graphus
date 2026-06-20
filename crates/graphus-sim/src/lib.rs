//! `graphus-sim` — production and deterministic implementations of the
//! [`graphus_core::capability`] traits, plus the hooks for Deterministic Simulation
//! Testing (`specification/04-technical-design.md` §11; decision `D-dst-investment`).
//!
//! The deterministic implementations make the whole engine reproducible from a seed
//! so that injected faults (crashes, I/O errors, reorderings) replay exactly.
#![forbid(unsafe_code)]

pub mod clock_fault;
pub mod net;
pub mod scheduler;

pub use clock_fault::{ClockFaultPlan, FaultyClock};
pub use net::{LinkId, NetConfig, Side, SimEndpoint, SimNet};
pub use scheduler::SimScheduler;

use graphus_core::capability::{Clock, Rng};

/// A deterministic clock that advances only when explicitly ticked.
#[derive(Debug, Default, Clone)]
pub struct SimClock {
    nanos: u64,
}

impl SimClock {
    /// Creates a clock starting at `start` nanoseconds.
    #[must_use]
    pub fn new(start: u64) -> Self {
        Self { nanos: start }
    }

    /// Advances the clock by `delta` nanoseconds (saturating).
    pub fn advance(&mut self, delta: u64) {
        self.nanos = self.nanos.saturating_add(delta);
    }
}

impl Clock for SimClock {
    fn now_nanos(&self) -> u64 {
        self.nanos
    }
}

/// A deterministic clock whose time is **set externally** by the simulator's scheduler, shared by
/// handle (cheap `Arc` clone) between the simulator and the engine it drives.
///
/// Unlike [`SimClock`] (which a single owner advances), `SharedClock` is read by the engine through an
/// `Arc<dyn Clock>` while the simulator core sets it to the [`SimScheduler`](crate::SimScheduler)'s
/// current time on every step — so the engine's notion of "now" tracks logical simulation time in
/// lockstep, with no wall clock anywhere. `Send + Sync` (an atomic), as the engine's clock slot
/// requires.
#[derive(Debug, Default, Clone)]
pub struct SharedClock(std::sync::Arc<std::sync::atomic::AtomicU64>);

impl SharedClock {
    /// Creates a shared clock starting at `start` nanoseconds.
    #[must_use]
    pub fn new(start: u64) -> Self {
        Self(std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
            start,
        )))
    }

    /// Sets the current time (the simulator calls this with the scheduler's logical time each step).
    pub fn set(&self, nanos: u64) {
        self.0.store(nanos, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Clock for SharedClock {
    fn now_nanos(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// The production clock backed by the operating-system wall clock.
///
/// A future revision will switch to a monotonic source; this skeleton uses the
/// system clock so the trait is wired end to end.
#[derive(Debug, Default, Clone)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_nanos(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
    }
}

/// A deterministic `xorshift64*` pseudo-random generator (seedable, reproducible).
#[derive(Debug, Clone)]
pub struct SimRng {
    state: u64,
}

impl SimRng {
    /// Creates an RNG from a seed; a zero seed is remapped to a fixed non-zero value.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            },
        }
    }

    /// A uniform value in `0..bound` (`0` when `bound == 0`). Uses modulo reduction — the slight bias
    /// is irrelevant for fault scheduling and keeps the generator dependency-free.
    pub fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            0
        } else {
            self.next_u64() % bound
        }
    }

    /// A uniform value in the inclusive range `lo..=hi` (returns `lo` when `hi <= lo`).
    pub fn range_inclusive(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            lo
        } else {
            lo + self.below(hi - lo + 1)
        }
    }

    /// Returns `true` with probability `permille / 1000` (a seed-driven coin flip for fault
    /// injection). `permille >= 1000` is always `true`; `0` is always `false`.
    pub fn chance(&mut self, permille: u32) -> bool {
        (self.next_u64() % 1000) < u64::from(permille)
    }
}

impl Rng for SimRng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sim_clock_advances_deterministically() {
        let mut c = SimClock::new(100);
        assert_eq!(c.now_nanos(), 100);
        c.advance(50);
        assert_eq!(c.now_nanos(), 150);
    }

    #[test]
    fn sim_rng_is_reproducible_from_a_seed() {
        let mut a = SimRng::new(42);
        let mut b = SimRng::new(42);
        let seq_a: Vec<u64> = (0..8).map(|_| a.next_u64()).collect();
        let seq_b: Vec<u64> = (0..8).map(|_| b.next_u64()).collect();
        assert_eq!(seq_a, seq_b);
    }

    #[test]
    fn sim_rng_differs_by_seed() {
        let mut a = SimRng::new(1);
        let mut b = SimRng::new(2);
        assert_ne!(a.next_u64(), b.next_u64());
    }
}
