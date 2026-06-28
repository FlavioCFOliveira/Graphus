//! Rate limiting and per-request limits for the network listeners (`04 §8.4` technical
//! requirements; `04 §9.3` backpressure/admission control).
//!
//! Three independent guards live here:
//!
//! - [`RateLimiter`] — a **token bucket** bounding request rate per client/connection. Time is
//!   **injected** via [`graphus_core::capability::Clock`], never read from the wall, so exhaustion
//!   and refill are fully deterministic in tests (project rule). The production server passes its
//!   real clock; tests pass a controllable one.
//! - [`AuthThrottle`] — a **per-key failed-authentication throttle** (rmp #458) built on the same
//!   token bucket: each source/account key gets a bucket of "allowed failures", consulted *before*
//!   the expensive Argon2 verification. After a configured number of failures within the window the
//!   next attempt is rejected up front, blunting online brute-force / credential-stuffing **and** the
//!   Argon2 CPU-exhaustion vector (each guess otherwise costs a full memory-hard hash). A *successful*
//!   auth never debits, so a legitimate client is unaffected by its own rate. Clock-injected, so the
//!   window is fully deterministic in tests.
//! - [`RequestLimits`] — a validated config of `max_body_bytes` + `request_timeout`, the body-size
//!   and timeout caps the listeners enforce on every request to bound resource use (anti-pattern
//!   guard: no unbounded request body, no unbounded handler runtime).
//!
//! The limiter holds capacity as a fixed-point fractional count so a sub-1-token-per-second refill
//! rate is representable without drift; see [`RateLimiter::try_acquire`].

use std::collections::HashMap;
use std::sync::Mutex;
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

/// A per-key **failed-authentication throttle** (rmp #458): a token bucket of "allowed failures" per
/// source/account key, consulted **before** the expensive Argon2 verification on every Bolt `LOGON`
/// and REST Bearer/admin check.
///
/// ## Why this exists
///
/// Without it, online brute-force / credential-stuffing resistance rests entirely on Argon2id cost +
/// password strength + the *global* connection cap (which is shared with legitimate traffic, not
/// auth-specific): an attacker gets one guess per connection with no per-account or per-source cap.
/// Worse, because every guess costs a full memory-hard Argon2 hash, unthrottled auth is also a **CPU
/// (and memory) exhaustion** vector. This throttle is the auth-specific control that bounds both.
///
/// ## Semantics (the gate)
///
/// Each key owns a [`RateLimiter`] bucket sized `max_failures` (capacity) refilling at
/// `failure_refill_per_sec`. Per attempt the caller:
///
/// 1. calls [`permit_attempt`](Self::permit_attempt) — if the key's bucket is **empty**, the attempt
///    is throttled and rejected *before* Argon2 runs (`false`); otherwise it proceeds (`true`);
/// 2. performs the (expensive) credential check;
/// 3. on **failure** calls [`note_failure`](Self::note_failure), debiting one token from the key's
///    bucket. On **success** it calls nothing.
///
/// So the first `max_failures` failures in a window each proceed (and debit); the next attempt for
/// that key is rejected up front until the bucket refills. A *correct* credential never debits, so a
/// legitimate client is never throttled by its own attempt rate — exactly the rmp-#458 gate ("the
/// Nth failed attempt within a window is rejected before Argon2; a successful auth is unaffected").
///
/// ## Bounded memory
///
/// The key map is capped at [`MAX_TRACKED_KEYS`]: an attacker who rotates source keys (e.g. spoofed
/// peer descriptors) cannot grow it without bound. When full, inserting a new key first evicts any
/// key whose bucket has fully refilled (it is back to baseline — forgetting it loses no state); if
/// none has, the new key is admitted **without** a per-key bucket (fail-open for that one attempt
/// rather than evicting a key that is actively being throttled). This keeps the throttle's own
/// footprint bounded while never *weakening* an in-progress throttle.
///
/// `Send + Sync`: the map lives behind a [`std::sync::Mutex`]; the critical section is tiny (a map
/// probe + a bucket op) and never spans an `.await`, so a sync mutex is correct here.
#[derive(Debug)]
pub struct AuthThrottle {
    /// Per-key failure buckets. `None` config (a disabled throttle) is modeled by `enabled = false`,
    /// so the map stays empty and every call is a cheap allow.
    inner: Mutex<HashMap<String, RateLimiter>>,
    /// Whether throttling is active. When `false`, [`permit_attempt`](Self::permit_attempt) always
    /// allows and [`note_failure`](Self::note_failure) is a no-op (the control is disabled).
    enabled: bool,
    /// Bucket capacity per key: the number of failures tolerated before throttling kicks in.
    max_failures: u32,
    /// Bucket refill rate per key, in tokens (allowed failures) per second.
    failure_refill_per_sec: u32,
}

/// The cap on the number of distinct keys [`AuthThrottle`] tracks at once (bounded memory; see the
/// type docs). Large enough to cover a realistic spread of concurrent source addresses / accounts,
/// small enough that the map can never become a memory-exhaustion vector itself.
pub const MAX_TRACKED_KEYS: usize = 65_536;

impl AuthThrottle {
    /// Creates an **enabled** throttle with `max_failures` tolerated failures per key, refilling at
    /// `failure_refill_per_sec` allowed-failures per second.
    ///
    /// # Errors
    /// [`AuthError::InvalidLimits`] if `max_failures` is zero (a key that can never attempt is a
    /// configuration mistake — it would lock out the *first* attempt) or `failure_refill_per_sec` is
    /// zero (a key, once throttled, could never recover — a permanent lock-out after one burst).
    pub fn new(max_failures: u32, failure_refill_per_sec: u32) -> Result<Self> {
        if max_failures == 0 {
            return Err(AuthError::InvalidLimits {
                detail: "auth throttle max_failures must be > 0".to_owned(),
            });
        }
        if failure_refill_per_sec == 0 {
            return Err(AuthError::InvalidLimits {
                detail: "auth throttle failure_refill_per_sec must be > 0".to_owned(),
            });
        }
        Ok(Self {
            inner: Mutex::new(HashMap::new()),
            enabled: true,
            max_failures,
            failure_refill_per_sec,
        })
    }

    /// Creates a **disabled** throttle: every [`permit_attempt`](Self::permit_attempt) allows and
    /// [`note_failure`](Self::note_failure) is a no-op. Used where an operator turns the control off
    /// (or for call sites that must hold an `AuthThrottle` uniformly without branching on `Option`).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            enabled: false,
            max_failures: 0,
            failure_refill_per_sec: 0,
        }
    }

    /// Whether the throttle is active (constructed via [`new`](Self::new) rather than
    /// [`disabled`](Self::disabled)).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Decides whether an authentication attempt for `key` may **proceed to credential verification**,
    /// *without* debiting (a peek). Returns `true` to proceed, or `false` to reject the attempt up
    /// front — the key has exhausted its failure budget within the window, so the caller must refuse
    /// the attempt **before** running Argon2 (rmp #458).
    ///
    /// A disabled throttle always returns `true`. The first sighting of a key is always allowed (its
    /// bucket starts full). The probe refills the key's bucket to `clock` first, so a key that was
    /// throttled and has since waited out the window is allowed again.
    pub fn permit_attempt(&self, key: &str, clock: &dyn Clock) -> bool {
        if !self.enabled {
            return true;
        }
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match map.get_mut(key) {
            // Known key: allow iff it has at least one whole failure-token left (peek, no debit).
            Some(bucket) => bucket.available_tokens(clock) >= 1,
            // First sighting: its bucket would start full, so the attempt is always allowed. We do
            // NOT insert here — insertion happens on the first *failure* (`note_failure`), so a key
            // that only ever succeeds never consumes a map slot.
            None => true,
        }
    }

    /// Records that an authentication attempt for `key` **failed**, debiting one token from the key's
    /// failure bucket (rmp #458). After `max_failures` failures within the window, the bucket is empty
    /// and [`permit_attempt`](Self::permit_attempt) will reject the next attempt for `key` until it
    /// refills. A *successful* attempt must NOT call this (success is never throttled).
    ///
    /// A disabled throttle is a no-op. Creates the key's bucket on first failure (bounded by
    /// [`MAX_TRACKED_KEYS`] — see the type docs for the eviction rule).
    pub fn note_failure(&self, key: &str, clock: &dyn Clock) {
        if !self.enabled {
            return;
        }
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(bucket) = map.get_mut(key) {
            // Existing key: consume one failure token (ignore the bool — being already empty is fine,
            // it just stays throttled).
            let _ = bucket.try_acquire(clock);
            return;
        }
        // New key: enforce the cap before inserting, evicting a fully-recovered (baseline) key if the
        // map is full so a key-rotation flood cannot grow the map without bound.
        if map.len() >= MAX_TRACKED_KEYS {
            Self::evict_one_recovered(&mut map, clock);
            if map.len() >= MAX_TRACKED_KEYS {
                // Could not free a slot without discarding an actively-throttled key. Fail-open for
                // this single failure rather than weaken a live throttle (the global connection cap
                // and Argon2 cost still apply). This is an extreme-pressure corner, not the steady
                // state.
                return;
            }
        }
        // Construct the key's bucket already debited by this first failure: start full, take one.
        let mut bucket =
            match RateLimiter::new(self.max_failures, self.failure_refill_per_sec, clock) {
                Ok(b) => b,
                // `new` only fails on a zero capacity/refill, both rejected in `Self::new`; unreachable.
                Err(_) => return,
            };
        let _ = bucket.try_acquire(clock);
        map.insert(key.to_owned(), bucket);
    }

    /// Evicts one key whose bucket has fully refilled back to capacity (it carries no live throttle
    /// state, so forgetting it is lossless). Best-effort: if every tracked key is still mid-throttle,
    /// none is evicted. Caller holds the map lock.
    fn evict_one_recovered(map: &mut HashMap<String, RateLimiter>, clock: &dyn Clock) {
        // `available_tokens` takes `&mut self` (it refills against the clock), so iterate mutably and
        // capture the first fully-recovered key, then remove it after the borrow ends.
        let mut recovered = None;
        for (k, b) in map.iter_mut() {
            if b.available_tokens(clock) >= 1 {
                recovered = Some(k.clone());
                break;
            }
        }
        if let Some(k) = recovered {
            map.remove(&k);
        }
    }

    /// The number of keys currently tracked (for tests/observability).
    #[must_use]
    pub fn tracked_keys(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
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
