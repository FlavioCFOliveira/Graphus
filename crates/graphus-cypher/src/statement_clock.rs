//! The **statement clock seam** (`rmp` task #140): the fixed "current instant" the
//! zero-argument temporal constructors (`date()`, `time()`, `datetime()`,
//! `localtime()`, `localdatetime()`) read from.
//!
//! openCypher (and the Neo4j Cypher manual) define three clock granularities for the
//! current-instant temporal functions:
//!
//! - **`statement`** — fixed for the duration of a single statement. Every `date()`,
//!   every `date.statement()`, and so on within one statement returns the **same**
//!   instant. The bare `date()` (no suffix) uses this clock by default.
//! - **`transaction`** — fixed for the duration of a transaction.
//! - **`realtime`** — the live wall clock, read afresh on every call.
//!
//! The load-bearing TCK property (`expressions/temporal/Temporal10.feature` \[12\],
//! "Should compute durations with no difference") is that two current-instant calls in
//! the same statement are *equal*, so that `duration.inSeconds(date(), date())` is
//! `'PT0S'`. That requires the instant to be captured **once** per statement and
//! threaded — never re-read from [`SystemTime::now`] scattered through evaluation.
//!
//! [`StatementClock`] holds one captured instant (epoch seconds + sub-second nanos) and
//! the default UTC offset (Graphus's configured default zone is UTC). The executor
//! captures it once when it opens a cursor (one capture per statement) and threads a
//! `&StatementClock` reference through expression evaluation alongside the function
//! registry. The `realtime_*` builders ignore the captured instant and read the live
//! clock instead.

use std::time::{SystemTime, UNIX_EPOCH};

use graphus_core::value::temporal::{Date, LocalDateTime, LocalTime, ZonedDateTime, ZonedTime};

/// Seconds in one standard (non-leap) day.
const SECONDS_PER_DAY: i64 = 86_400;
/// Nanoseconds in one second.
const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// The fixed "current instant" the zero-argument temporal constructors read from.
///
/// Captured **once** per statement via [`StatementClock::capture`] and threaded by
/// reference through expression evaluation, so that every current-instant constructor in
/// one statement observes the same instant (the TCK `PT0S` property). `Copy`, so it is
/// cheap to thread and to store on the executor context.
#[derive(Debug, Clone, Copy)]
pub struct StatementClock {
    /// Seconds since the Unix epoch (1970-01-01T00:00:00Z) at capture time.
    epoch_seconds: i64,
    /// Sub-second nanoseconds (`< 1_000_000_000`) at capture time.
    sub_nanos: u32,
    /// The default UTC offset in seconds. Graphus's configured default zone is UTC, so
    /// this is always `0` today; kept explicit so a future configurable default zone has
    /// a single seam to thread through.
    offset_seconds: i32,
}

impl StatementClock {
    /// Captures the current wall-clock instant once, for use as the statement clock.
    ///
    /// A clock that predates the Unix epoch (a `SystemTime` before 1970, only reachable
    /// on a grossly misconfigured host) is clamped to the epoch rather than panicking;
    /// the temporal constructors must never panic on a hostile system clock.
    #[must_use]
    pub fn capture() -> Self {
        let (epoch_seconds, sub_nanos) = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => (
                i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
                d.subsec_nanos(),
            ),
            // Clock before the epoch: clamp to the epoch (see method docs).
            Err(_) => (0, 0),
        };
        Self {
            epoch_seconds,
            sub_nanos,
            offset_seconds: 0,
        }
    }

    /// Builds a [`Date`] (days since the Unix epoch) from the captured instant.
    #[must_use]
    pub fn date(&self) -> Date {
        Self::date_from(self.epoch_seconds)
    }

    /// Builds a [`LocalTime`] (nanoseconds of day) from the captured instant.
    #[must_use]
    pub fn localtime(&self) -> LocalTime {
        Self::localtime_from(self.epoch_seconds, self.sub_nanos)
    }

    /// Builds a [`ZonedTime`] (local time + default UTC offset) from the captured instant.
    #[must_use]
    pub fn time(&self) -> ZonedTime {
        ZonedTime {
            time: self.localtime(),
            offset_seconds: self.offset_seconds,
        }
    }

    /// Builds a [`LocalDateTime`] (epoch seconds + sub-second nanos) from the captured instant.
    #[must_use]
    pub fn localdatetime(&self) -> LocalDateTime {
        LocalDateTime {
            epoch_seconds: self.epoch_seconds,
            nanos: self.sub_nanos,
        }
    }

    /// Builds a [`ZonedDateTime`] (local date-time + default UTC offset) from the captured
    /// instant.
    ///
    /// The zone id is left empty, which is the project's UTC convention: an empty
    /// `zone_id` with a zero offset renders its offset as `Z`
    /// (see `graphus_core::temporal_calc::format_offset`).
    #[must_use]
    pub fn datetime(&self) -> ZonedDateTime {
        ZonedDateTime {
            local: self.localdatetime(),
            offset_seconds: self.offset_seconds,
            zone_id: String::new(),
        }
    }

    /// Builds a [`Date`] from the **live** wall clock (the `.realtime` granularity).
    #[must_use]
    pub fn realtime_date() -> Date {
        Self::capture().date()
    }

    /// Builds a [`LocalTime`] from the **live** wall clock (the `.realtime` granularity).
    #[must_use]
    pub fn realtime_localtime() -> LocalTime {
        Self::capture().localtime()
    }

    /// Builds a [`ZonedTime`] from the **live** wall clock (the `.realtime` granularity).
    #[must_use]
    pub fn realtime_time() -> ZonedTime {
        Self::capture().time()
    }

    /// Builds a [`LocalDateTime`] from the **live** wall clock (the `.realtime` granularity).
    #[must_use]
    pub fn realtime_localdatetime() -> LocalDateTime {
        Self::capture().localdatetime()
    }

    /// Builds a [`ZonedDateTime`] from the **live** wall clock (the `.realtime` granularity).
    #[must_use]
    pub fn realtime_datetime() -> ZonedDateTime {
        Self::capture().datetime()
    }

    /// Days since the Unix epoch for an epoch-seconds instant (floored, so negative
    /// instants map to the correct earlier date).
    fn date_from(epoch_seconds: i64) -> Date {
        let days = epoch_seconds.div_euclid(SECONDS_PER_DAY);
        Date {
            // The realistic span of a system clock is far inside `i32` days
            // (±5.8 million years); a pathological clamp keeps this total and panic-free.
            days_since_epoch: i32::try_from(days).unwrap_or(if days < 0 {
                i32::MIN
            } else {
                i32::MAX
            }),
        }
    }

    /// Nanoseconds-of-day for an epoch-seconds + sub-second-nanos instant.
    fn localtime_from(epoch_seconds: i64, sub_nanos: u32) -> LocalTime {
        // `rem_euclid` keeps the time-of-day in `0..86_400` even for negative instants.
        let secs_of_day = epoch_seconds.rem_euclid(SECONDS_PER_DAY) as u64;
        LocalTime {
            nanos_of_day: secs_of_day * NANOS_PER_SECOND + u64::from(sub_nanos),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_from_known_instant() {
        // 2021-01-01T00:00:00Z = 1_609_459_200 s = 18_628 days since epoch.
        let date = StatementClock::date_from(1_609_459_200);
        assert_eq!(date.days_since_epoch, 18_628);
    }

    #[test]
    fn localtime_from_known_instant() {
        // 01:02:03.000000004 past midnight.
        let secs: i64 = 3600 + 2 * 60 + 3;
        let lt = StatementClock::localtime_from(secs, 4);
        assert_eq!(lt.nanos_of_day, (secs as u64) * NANOS_PER_SECOND + 4);
    }

    #[test]
    fn negative_instant_floors_date_and_wraps_time() {
        // One second before the epoch: 1969-12-31T23:59:59Z.
        let date = StatementClock::date_from(-1);
        assert_eq!(date.days_since_epoch, -1);
        let lt = StatementClock::localtime_from(-1, 0);
        // 23:59:59 of the previous day.
        assert_eq!(
            lt.nanos_of_day,
            (SECONDS_PER_DAY as u64 - 1) * NANOS_PER_SECOND
        );
    }

    #[test]
    fn captured_instant_is_stable_across_builders() {
        let clock = StatementClock::capture();
        // Two reads from the same captured clock are identical (the PT0S property).
        assert_eq!(clock.date(), clock.date());
        assert_eq!(clock.localtime(), clock.localtime());
        assert_eq!(clock.time(), clock.time());
        assert_eq!(clock.localdatetime(), clock.localdatetime());
        assert_eq!(clock.datetime(), clock.datetime());
    }

    #[test]
    fn datetime_uses_utc_default_offset_and_empty_zone() {
        let clock = StatementClock::capture();
        let dt = clock.datetime();
        assert_eq!(dt.offset_seconds, 0);
        assert!(dt.zone_id.is_empty());
        assert_eq!(clock.time().offset_seconds, 0);
    }
}
