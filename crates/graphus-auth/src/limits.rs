//! Rate limiting and per-request limits for the network listeners (`04 §8.4` technical
//! requirements; `04 §9.3` backpressure/admission control).
//!
//! Two independent guards live here:
//!
//! - [`RateLimiter`] — a **token bucket** bounding request rate per client/connection. Time is
//!   **injected** via [`graphus_core::capability::Clock`], never read from the wall, so exhaustion
//!   and refill are fully deterministic in tests (project rule). The production server passes its
//!   real clock; tests pass a controllable one.
//! - [`RequestLimits`] — a validated config of `max_body_bytes` + `request_timeout`, the body-size
//!   and timeout caps the listeners enforce on every request to bound resource use (anti-pattern
//!   guard: no unbounded request body, no unbounded handler runtime).
//!
//! The limiter holds capacity as a fixed-point fractional count so a sub-1-token-per-second refill
//! rate is representable without drift; see [`RateLimiter::try_acquire`].

use std::time::Duration;

use graphus_core::capability::Clock;

use crate::error::{AuthError, Result};

/// Fixed-point scale for fractional tokens. Tokens are tracked in units of `1 / SCALE` so that
/// refill rates below one token per second accumulate exactly rather than rounding to zero.
const SCALE: u64 = 1_000_000;

/// Nanoseconds per second, for converting the injected clock's `now_nanos` into a refill amount.
const NANOS_PER_SEC: u128 = 1_000_000_000;

/// A token-bucket rate limiter with externally-injected time.
///
/// The bucket holds up to `capacity` tokens and refills at `refill_per_sec` tokens per second up to
/// that ceiling. [`RateLimiter::try_acquire`] takes one token if available. All time comes from the
/// passed-in [`Clock`], so behaviour is a pure function of the clock readings — deterministic and
/// testable with no sleeping.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// Bucket ceiling, in scaled units (`capacity * SCALE`).
    capacity_scaled: u64,
    /// Refill rate in scaled units per second (`refill_per_sec * SCALE`).
    refill_scaled_per_sec: u64,
    /// Current tokens available, in scaled units.
    available_scaled: u64,
    /// The clock reading (`now_nanos`) at which `available_scaled` was last brought up to date.
    last_refill_nanos: u64,
}

impl RateLimiter {
    /// Creates a limiter that starts **full** (`capacity` tokens) as of `clock`'s current reading.
    ///
    /// # Errors
    /// [`AuthError::InvalidLimits`] if `capacity` is zero (a bucket that can never admit a request
    /// is a configuration mistake) or `refill_per_sec` is zero (the bucket could never recover and
    /// would permanently lock out after the first burst).
    pub fn new(capacity: u32, refill_per_sec: u32, clock: &dyn Clock) -> Result<Self> {
        if capacity == 0 {
            return Err(AuthError::InvalidLimits {
                detail: "rate limiter capacity must be > 0".to_owned(),
            });
        }
        if refill_per_sec == 0 {
            return Err(AuthError::InvalidLimits {
                detail: "rate limiter refill_per_sec must be > 0".to_owned(),
            });
        }
        let capacity_scaled = u64::from(capacity) * SCALE;
        Ok(Self {
            capacity_scaled,
            refill_scaled_per_sec: u64::from(refill_per_sec) * SCALE,
            available_scaled: capacity_scaled,
            last_refill_nanos: clock.now_nanos(),
        })
    }

    /// Brings `available_scaled` up to date for the current `clock` reading, capped at capacity.
    fn refill(&mut self, clock: &dyn Clock) {
        let now = clock.now_nanos();
        // Monotonic clock: guard against a non-advancing or (defensively) regressing reading.
        let elapsed_nanos = u128::from(now.saturating_sub(self.last_refill_nanos));
        if elapsed_nanos == 0 {
            return;
        }
        // added = refill_per_sec_scaled * elapsed_nanos / 1e9, in scaled units. u128 math avoids
        // overflow for any realistic rate/elapsed product before the divide.
        let added = (u128::from(self.refill_scaled_per_sec) * elapsed_nanos) / NANOS_PER_SEC;
        let added = u64::try_from(added).unwrap_or(u64::MAX);
        self.available_scaled = self
            .available_scaled
            .saturating_add(added)
            .min(self.capacity_scaled);
        self.last_refill_nanos = now;
    }

    /// Attempts to take one token, refilling first based on `clock`. Returns `true` if a token was
    /// available (request admitted) or `false` if the bucket is empty (request should be shed).
    pub fn try_acquire(&mut self, clock: &dyn Clock) -> bool {
        self.refill(clock);
        if self.available_scaled >= SCALE {
            self.available_scaled -= SCALE;
            true
        } else {
            false
        }
    }

    /// The number of **whole** tokens currently available (after refilling to `clock`). Primarily
    /// for observability/tests.
    pub fn available_tokens(&mut self, clock: &dyn Clock) -> u32 {
        self.refill(clock);
        u32::try_from(self.available_scaled / SCALE).unwrap_or(u32::MAX)
    }
}

/// Validated per-request resource limits enforced by the listeners.
///
/// `max_body_bytes` caps an inbound request/message body; `request_timeout` caps how long a single
/// request may run before it is cancelled. Both must be positive — a zero of either would either
/// reject everything or disable the guard, neither of which is a valid production setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestLimits {
    /// Maximum accepted request/message body size, in bytes.
    pub max_body_bytes: u64,
    /// Maximum wall-clock duration a single request may run before cancellation.
    pub request_timeout: Duration,
}

impl RequestLimits {
    /// Creates and validates a request-limits config.
    ///
    /// # Errors
    /// [`AuthError::InvalidLimits`] if `max_body_bytes` is zero or `request_timeout` is zero.
    pub fn new(max_body_bytes: u64, request_timeout: Duration) -> Result<Self> {
        if max_body_bytes == 0 {
            return Err(AuthError::InvalidLimits {
                detail: "max_body_bytes must be > 0".to_owned(),
            });
        }
        if request_timeout.is_zero() {
            return Err(AuthError::InvalidLimits {
                detail: "request_timeout must be > 0".to_owned(),
            });
        }
        Ok(Self {
            max_body_bytes,
            request_timeout,
        })
    }

    /// Returns `true` if a body of `len` bytes is within the configured cap.
    #[must_use]
    pub fn permits_body(&self, len: u64) -> bool {
        len <= self.max_body_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// A deterministic, manually-advanced clock for tests (no wall time).
    #[derive(Default)]
    struct TestClock {
        nanos: Cell<u64>,
    }

    impl TestClock {
        fn advance_secs(&self, secs: u64) {
            self.nanos.set(self.nanos.get() + secs * 1_000_000_000);
        }
        fn advance_millis(&self, ms: u64) {
            self.nanos.set(self.nanos.get() + ms * 1_000_000);
        }
    }

    impl Clock for TestClock {
        fn now_nanos(&self) -> u64 {
            self.nanos.get()
        }
    }

    #[test]
    fn rejects_zero_capacity_or_refill() {
        let clock = TestClock::default();
        assert!(matches!(
            RateLimiter::new(0, 1, &clock),
            Err(AuthError::InvalidLimits { .. })
        ));
        assert!(matches!(
            RateLimiter::new(1, 0, &clock),
            Err(AuthError::InvalidLimits { .. })
        ));
    }

    #[test]
    fn bucket_exhausts_then_refuses() {
        let clock = TestClock::default();
        let mut rl = RateLimiter::new(3, 1, &clock).unwrap();
        // Starts full: three acquisitions succeed without any time passing.
        assert!(rl.try_acquire(&clock));
        assert!(rl.try_acquire(&clock));
        assert!(rl.try_acquire(&clock));
        // Fourth is refused — bucket empty, no time has elapsed to refill.
        assert!(!rl.try_acquire(&clock));
    }

    #[test]
    fn refills_over_time_up_to_capacity() {
        let clock = TestClock::default();
        let mut rl = RateLimiter::new(2, 1, &clock).unwrap();
        assert!(rl.try_acquire(&clock));
        assert!(rl.try_acquire(&clock));
        assert!(!rl.try_acquire(&clock));
        // One second later, one token has refilled (rate = 1/s).
        clock.advance_secs(1);
        assert_eq!(rl.available_tokens(&clock), 1);
        assert!(rl.try_acquire(&clock));
        assert!(!rl.try_acquire(&clock));
    }

    #[test]
    fn refill_never_exceeds_capacity() {
        let clock = TestClock::default();
        let mut rl = RateLimiter::new(2, 5, &clock).unwrap();
        // Drain, then let a long time pass — should cap at 2, not 2 + 5*100.
        assert!(rl.try_acquire(&clock));
        clock.advance_secs(100);
        assert_eq!(rl.available_tokens(&clock), 2);
    }

    #[test]
    fn fractional_refill_accumulates_without_drift() {
        let clock = TestClock::default();
        // 1 token per second; after 500ms we should have half a token (0 whole), and after another
        // 500ms exactly one whole token — proving sub-second fractions accumulate rather than floor.
        let mut rl = RateLimiter::new(1, 1, &clock).unwrap();
        assert!(rl.try_acquire(&clock));
        clock.advance_millis(500);
        assert!(!rl.try_acquire(&clock));
        clock.advance_millis(500);
        assert!(rl.try_acquire(&clock));
    }

    #[test]
    fn request_limits_validate_and_permit() {
        assert!(matches!(
            RequestLimits::new(0, Duration::from_secs(1)),
            Err(AuthError::InvalidLimits { .. })
        ));
        assert!(matches!(
            RequestLimits::new(1024, Duration::ZERO),
            Err(AuthError::InvalidLimits { .. })
        ));
        let limits = RequestLimits::new(1024, Duration::from_secs(30)).unwrap();
        assert!(limits.permits_body(1024));
        assert!(!limits.permits_body(1025));
    }
}
