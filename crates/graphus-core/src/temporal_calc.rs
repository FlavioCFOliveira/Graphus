//! Calendar and temporal arithmetic over the storage-shaped temporal value types.
//!
//! The structs in [`crate::value::temporal`] deliberately store *decomposed,
//! fixed-width integer components* (days since epoch, nanoseconds of day, epoch
//! seconds, duration component groups) so that the index key codec and the MVCC
//! record codec can treat them as plain integers. This module supplies all the
//! calendar intelligence on top of that representation:
//!
//! - **Civil-calendar conversions** between `(year, month, day)` triples and
//!   days-since-epoch counts, using Howard Hinnant's public-domain proleptic
//!   Gregorian algorithms (`days_from_civil` / `civil_from_days`). These are
//!   branch-light, exact over the whole supported range, and loop-free.
//! - **Validated construction** of every temporal type from calendar, ISO week,
//!   ordinal and quarter components.
//! - **Component accessors** with exactly the openCypher semantics asserted by
//!   the TCK (`Temporal5.feature`), e.g. ISO week dates (Monday = 1), truncated
//!   sub-second totals, and the three *independent* duration component groups
//!   (months / days / seconds+nanos).
//! - **ISO-8601 formatting** producing byte-for-byte the strings the openCypher
//!   TCK expects in result cells (`Temporal1/2/4/6/8.feature`): seconds are
//!   omitted when both the second and the sub-second part are zero (`12:00`),
//!   sub-seconds print in groups of three digits (`.645`, `.645876`,
//!   `.645876123`), a zero offset prints as `Z`, and durations print each
//!   component group with its own sign (`P-6M-15DT-17H-45M-3.5S`, `PT0S`).
//! - **ISO-8601 parsing** of every string shape the TCK feeds the temporal
//!   constructors (`Temporal2.feature`): calendar / week / ordinal / quarter
//!   dates in basic and extended form, times down to bare hours, offsets with
//!   second precision, bracketed IANA zone ids, and durations including
//!   fractional components and the `P<date>T<time>` form.
//! - **Arithmetic** with openCypher semantics (`Temporal8.feature`): temporal
//!   plus duration adds months first (clamping the day-of-month), then days,
//!   then the seconds group; `Date` keeps only whole days of the seconds group;
//!   `LocalTime` wraps modulo 24 h; durations combine component-wise and
//!   multiply/divide through Neo4j's *approximate* cascade (fractional months
//!   become days via the average Gregorian month, fractional days become
//!   seconds), truncating toward zero.
//!
//! Time-zone *rules* (IANA tzdb lookups) are intentionally **not** implemented
//! here: a `ZonedDateTime` carries an already-resolved offset, and resolving a
//! named zone to an offset is the responsibility of the layer that owns the
//! time-zone database. The `parse_zoned_date_time_parts` function exposes the
//! unresolved pieces so that callers can perform that resolution.
//!
//! All functions are pure, allocation is limited to the returned `String`s, and
//! no function panics on any input (invalid components and out-of-range results
//! are reported through [`TemporalError`]).

use crate::value::temporal::{
    Date, Duration, LocalDateTime, LocalTime, NANOS_PER_DAY, ZonedDateTime, ZonedTime,
};
use std::fmt::{self, Write as _};

/// Nanoseconds in one second.
pub const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// Seconds in one standard (non-leap) day.
pub const SECONDS_PER_DAY: i64 = 86_400;

/// The average Gregorian month in seconds: `365.2425 * 86400 / 12`.
///
/// This is the constant Neo4j/openCypher use when a *fractional* month has to
/// be converted into smaller units (duration parsing with fractions and
/// duration scaling). Pinned by `Temporal2.feature` scenario \[7\]:
/// `duration('P0.75M')` must render as `'P22DT19H51M49.5S'`, which is exactly
/// `0.75 * 2_629_746 s`.
pub const AVG_SECONDS_PER_MONTH: i64 = 2_629_746;

/// The average Gregorian month in nanoseconds (see [`AVG_SECONDS_PER_MONTH`]).
const AVG_NANOS_PER_MONTH: i128 = AVG_SECONDS_PER_MONTH as i128 * NANOS_PER_SECOND as i128;

/// Nanoseconds in one standard day, widened for interim arithmetic.
const NANOS_PER_DAY_I128: i128 = NANOS_PER_DAY as i128;

/// Maximum magnitude of a UTC offset in seconds (`+18:00`, as in `java.time`).
pub const MAX_OFFSET_SECONDS: i32 = 18 * 3600;

/// Largest absolute proleptic-Gregorian year constructible as a [`Date`].
///
/// `Date` stores `i32` days since 1970-01-01, which spans roughly
/// +/- 5.88 million years; this bound is checked *before* any day arithmetic so
/// that the civil conversions below never overflow.
const MAX_ABS_YEAR: i64 = 5_880_000;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by temporal construction, parsing, and arithmetic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemporalError {
    /// A calendar/time component is outside its valid range (e.g. month 13).
    InvalidComponent(&'static str),
    /// A string could not be parsed as the requested temporal type.
    Parse {
        /// The offending input string.
        input: String,
        /// A short, static description of what was wrong.
        reason: &'static str,
    },
    /// The result is not representable in the fixed-width storage types.
    Overflow,
}

impl fmt::Display for TemporalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidComponent(component) => {
                write!(f, "invalid temporal component: {component}")
            }
            Self::Parse { input, reason } => {
                write!(f, "cannot parse temporal value {input:?}: {reason}")
            }
            Self::Overflow => write!(f, "temporal value out of representable range"),
        }
    }
}

impl std::error::Error for TemporalError {}

/// Result alias for this module.
pub type TemporalResult<T> = Result<T, TemporalError>;

// ---------------------------------------------------------------------------
// Civil-calendar conversions (Howard Hinnant's algorithms, public domain)
// ---------------------------------------------------------------------------

/// Returns `true` if `year` is a leap year in the proleptic Gregorian calendar.
#[must_use]
pub fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Number of days in `month` (1-12) of `year`, or `0` if `month` is invalid.
///
/// Returning `0` for an out-of-range month keeps the function total; callers
/// that accept untrusted months must validate them first (as the constructors
/// in this module do).
#[must_use]
pub fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Number of days in quarter `quarter` (1-4) of `year`, or `0` if invalid.
#[must_use]
pub fn days_in_quarter(year: i64, quarter: u32) -> u32 {
    match quarter {
        1 => {
            if is_leap_year(year) {
                91
            } else {
                90
            }
        }
        2 => 91,
        3 | 4 => 92,
        _ => 0,
    }
}

/// Days since 1970-01-01 of the civil date `(year, month, day)`.
///
/// Proleptic Gregorian; `month` must be in `1..=12` and `day` in
/// `1..=days_in_month(year, month)` for a meaningful result (the validated
/// constructors enforce this). Exact for `|year| <= ~2.5e16`; the public
/// constructors restrict years far below that bound.
///
/// Algorithm: Howard Hinnant, "chrono-Compatible Low-Level Date Algorithms"
/// (`days_from_civil`), public domain.
#[must_use]
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = (y - era * 400) as u64; // [0, 399]
    let mp = u64::from((month + 9) % 12); // [0, 11], March = 0
    let doy = (153 * mp + 2) / 5 + u64::from(day) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe as i64 - 719_468
}

/// Civil date `(year, month, day)` of the given days-since-1970-01-01 count.
///
/// Inverse of [`days_from_civil`]; exact for `|days| <= ~9.1e18 / 400` (far
/// beyond the `i32` range a [`Date`] can hold).
///
/// Algorithm: Howard Hinnant, `civil_from_days`, public domain.
#[must_use]
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    (if month <= 2 { y + 1 } else { y }, month, day)
}

/// ISO weekday (Monday = 1 .. Sunday = 7) of a days-since-epoch count.
///
/// 1970-01-01 was a Thursday (4).
#[must_use]
fn weekday_from_epoch_days(days: i64) -> i64 {
    (days + 3).rem_euclid(7) + 1
}

/// Number of ISO 8601 weeks (52 or 53) in week-based year `week_year`.
///
/// A week-based year is long (53 weeks) iff January 1 falls on a Thursday, or
/// on a Wednesday in a leap year. Pinned by `Temporal1.feature` scenario \[1\]:
/// `{year: 1818, week: 53}` is a valid construction.
#[must_use]
pub fn weeks_in_iso_year(week_year: i64) -> u32 {
    let jan1_dow = weekday_from_epoch_days(days_from_civil(week_year, 1, 1));
    if jan1_dow == 4 || (is_leap_year(week_year) && jan1_dow == 3) {
        53
    } else {
        52
    }
}

// ---------------------------------------------------------------------------
// Shared formatting helpers
// ---------------------------------------------------------------------------

/// Formats a proleptic-Gregorian year the way the TCK result cells expect:
/// `0..=9999` zero-padded to four digits, negative years with a leading `-`,
/// and years above 9999 with an explicit `+` (the `java.time` convention).
fn format_year(year: i64) -> String {
    if year < 0 {
        format!("-{:04}", year.unsigned_abs())
    } else if year > 9999 {
        format!("+{year}")
    } else {
        format!("{year:04}")
    }
}

/// Appends the sub-second suffix (or nothing) for a nanosecond-of-second value.
///
/// The TCK prints sub-seconds in groups of three digits, trimmed to the
/// shortest group that preserves the value (`Temporal1.feature` scenario \[5\]:
/// `.123456789`, `.645876`, `.645`; scenario \[6\]: `.000000003`).
fn push_subsecond(out: &mut String, nanos: u32) {
    if nanos == 0 {
        return;
    }
    if nanos % 1_000_000 == 0 {
        let _ = write!(out, ".{:03}", nanos / 1_000_000);
    } else if nanos % 1_000 == 0 {
        let _ = write!(out, ".{:06}", nanos / 1_000);
    } else {
        let _ = write!(out, ".{nanos:09}");
    }
}

/// Renders a UTC offset in seconds as the TCK expects: `Z` for zero,
/// otherwise `+hh:mm` with a `:ss` tail only when the offset has second
/// precision (`Temporal1.feature` scenario \[13\]: `'+02:05:00'` renders as
/// `'+02:05'` but `'+02:05:59'` keeps its seconds).
#[must_use]
pub fn format_offset(offset_seconds: i32) -> String {
    if offset_seconds == 0 {
        return "Z".to_owned();
    }
    let sign = if offset_seconds < 0 { '-' } else { '+' };
    let abs = offset_seconds.unsigned_abs();
    let (h, m, s) = (abs / 3600, (abs % 3600) / 60, abs % 60);
    if s == 0 {
        format!("{sign}{h:02}:{m:02}")
    } else {
        format!("{sign}{h:02}:{m:02}:{s:02}")
    }
}

// ---------------------------------------------------------------------------
// Date
// ---------------------------------------------------------------------------

impl Date {
    /// Builds a `Date` from a days-since-epoch count, checking the `i32` range.
    fn from_epoch_days(days: i64) -> TemporalResult<Self> {
        let days_since_epoch = i32::try_from(days).map_err(|_| TemporalError::Overflow)?;
        Ok(Self { days_since_epoch })
    }

    /// The days-since-epoch count widened to `i64` for arithmetic.
    #[must_use]
    fn epoch_days(&self) -> i64 {
        i64::from(self.days_since_epoch)
    }

    /// Constructs a date from calendar components.
    ///
    /// # Errors
    /// [`TemporalError::InvalidComponent`] if `month` is not in `1..=12` or
    /// `day` is not in `1..=days_in_month(year, month)`;
    /// [`TemporalError::Overflow`] if `year` is outside the representable
    /// range.
    ///
    /// # Examples
    /// ```
    /// use graphus_core::value::temporal::Date;
    /// let d = Date::from_ymd(1984, 10, 11).unwrap();
    /// assert_eq!(d.to_iso_string(), "1984-10-11");
    /// ```
    pub fn from_ymd(year: i64, month: u32, day: u32) -> TemporalResult<Self> {
        if year.abs() > MAX_ABS_YEAR {
            return Err(TemporalError::Overflow);
        }
        if !(1..=12).contains(&month) {
            return Err(TemporalError::InvalidComponent("month"));
        }
        if day < 1 || day > days_in_month(year, month) {
            return Err(TemporalError::InvalidComponent("day"));
        }
        Self::from_epoch_days(days_from_civil(year, month, day))
    }

    /// Constructs a date from ISO 8601 week-date components.
    ///
    /// `week_year` is the ISO week-based year, `week` is in
    /// `1..=weeks_in_iso_year(week_year)`, and `day_of_week` uses the ISO
    /// numbering Monday = 1 .. Sunday = 7.
    ///
    /// # Errors
    /// [`TemporalError::InvalidComponent`] on out-of-range components;
    /// [`TemporalError::Overflow`] if the result is unrepresentable.
    pub fn from_year_week_day(week_year: i64, week: u32, day_of_week: u32) -> TemporalResult<Self> {
        if week_year.abs() > MAX_ABS_YEAR {
            return Err(TemporalError::Overflow);
        }
        if week < 1 || week > weeks_in_iso_year(week_year) {
            return Err(TemporalError::InvalidComponent("week"));
        }
        if !(1..=7).contains(&day_of_week) {
            return Err(TemporalError::InvalidComponent("dayOfWeek"));
        }
        // ISO week 1 is the week containing January 4.
        let jan4 = days_from_civil(week_year, 1, 4);
        let week1_monday = jan4 - (weekday_from_epoch_days(jan4) - 1);
        let days = week1_monday + i64::from(week - 1) * 7 + (i64::from(day_of_week) - 1);
        Self::from_epoch_days(days)
    }

    /// Constructs a date from a year and a 1-based ordinal day of that year.
    ///
    /// # Errors
    /// [`TemporalError::InvalidComponent`] if `ordinal_day` is not in
    /// `1..=365` (or `366` in leap years); [`TemporalError::Overflow`] if the
    /// year is out of range.
    pub fn from_year_ordinal(year: i64, ordinal_day: u32) -> TemporalResult<Self> {
        if year.abs() > MAX_ABS_YEAR {
            return Err(TemporalError::Overflow);
        }
        let len = if is_leap_year(year) { 366 } else { 365 };
        if ordinal_day < 1 || ordinal_day > len {
            return Err(TemporalError::InvalidComponent("ordinalDay"));
        }
        Self::from_epoch_days(days_from_civil(year, 1, 1) + i64::from(ordinal_day) - 1)
    }

    /// Constructs a date from a year, quarter (1-4) and 1-based day of quarter.
    ///
    /// # Errors
    /// [`TemporalError::InvalidComponent`] on out-of-range components;
    /// [`TemporalError::Overflow`] if the year is out of range.
    pub fn from_year_quarter_day(
        year: i64,
        quarter: u32,
        day_of_quarter: u32,
    ) -> TemporalResult<Self> {
        if year.abs() > MAX_ABS_YEAR {
            return Err(TemporalError::Overflow);
        }
        if !(1..=4).contains(&quarter) {
            return Err(TemporalError::InvalidComponent("quarter"));
        }
        if day_of_quarter < 1 || day_of_quarter > days_in_quarter(year, quarter) {
            return Err(TemporalError::InvalidComponent("dayOfQuarter"));
        }
        let first_month = (quarter - 1) * 3 + 1;
        Self::from_epoch_days(days_from_civil(year, first_month, 1) + i64::from(day_of_quarter) - 1)
    }

    /// Decomposes this date into `(year, month, day)`.
    #[must_use]
    pub fn to_ymd(&self) -> (i64, u32, u32) {
        civil_from_days(self.epoch_days())
    }

    /// The calendar year.
    #[must_use]
    pub fn year(&self) -> i64 {
        self.to_ymd().0
    }

    /// The calendar month (1-12).
    #[must_use]
    pub fn month(&self) -> i64 {
        i64::from(self.to_ymd().1)
    }

    /// The day of the month (1-31).
    #[must_use]
    pub fn day(&self) -> i64 {
        i64::from(self.to_ymd().2)
    }

    /// The quarter of the year (1-4).
    #[must_use]
    pub fn quarter(&self) -> i64 {
        (self.month() - 1) / 3 + 1
    }

    /// The ISO 8601 week of the week-based year (1-53).
    #[must_use]
    pub fn week(&self) -> i64 {
        self.iso_week_pair().1
    }

    /// The ISO 8601 week-based year (may differ from [`Self::year`] around
    /// January 1; pinned by `Temporal5.feature` scenario \[2\]: 1984-01-01 has
    /// `weekYear` 1983 and `week` 52).
    #[must_use]
    pub fn week_year(&self) -> i64 {
        self.iso_week_pair().0
    }

    /// The 1-based ordinal day of the year (1-366).
    #[must_use]
    pub fn ordinal_day(&self) -> i64 {
        self.epoch_days() - days_from_civil(self.year(), 1, 1) + 1
    }

    /// The ISO weekday: Monday = 1 .. Sunday = 7.
    #[must_use]
    pub fn week_day(&self) -> i64 {
        weekday_from_epoch_days(self.epoch_days())
    }

    /// The 1-based day within the quarter (1-92).
    #[must_use]
    pub fn day_of_quarter(&self) -> i64 {
        let (year, month, _) = self.to_ymd();
        let first_month = ((month - 1) / 3) * 3 + 1;
        self.epoch_days() - days_from_civil(year, first_month, 1) + 1
    }

    /// `(week_year, week)` per ISO 8601: the week-based year and week of the
    /// Thursday that falls in the same Monday-based week as `self`.
    fn iso_week_pair(&self) -> (i64, i64) {
        let days = self.epoch_days();
        let thursday = days + (4 - weekday_from_epoch_days(days));
        let (week_year, _, _) = civil_from_days(thursday);
        let week = (thursday - days_from_civil(week_year, 1, 1)) / 7 + 1;
        (week_year, week)
    }

    /// Formats this date as ISO 8601 (`1984-10-11`; negative years keep a
    /// leading `-`, years above 9999 a leading `+`).
    #[must_use]
    pub fn to_iso_string(&self) -> String {
        let (year, month, day) = self.to_ymd();
        format!("{}-{month:02}-{day:02}", format_year(year))
    }

    /// Adds `months` (clamping the day-of-month into the target month, e.g.
    /// January 31 plus one month is February 28/29) and then `days`.
    fn add_months_days_clamped(&self, months: i64, days: i64) -> TemporalResult<Self> {
        let (year, month, day) = self.to_ymd();
        let total_months = i128::from(year) * 12 + i128::from(month) - 1 + i128::from(months);
        let new_year =
            i64::try_from(total_months.div_euclid(12)).map_err(|_| TemporalError::Overflow)?;
        if new_year.abs() > MAX_ABS_YEAR {
            return Err(TemporalError::Overflow);
        }
        // rem_euclid(12) is in 0..=11, so the cast is lossless.
        let new_month = total_months.rem_euclid(12) as u32 + 1;
        let new_day = day.min(days_in_month(new_year, new_month));
        let base = days_from_civil(new_year, new_month, new_day);
        let total = base.checked_add(days).ok_or(TemporalError::Overflow)?;
        Self::from_epoch_days(total)
    }

    /// Adds a whole number of days.
    fn checked_add_days(&self, days: i64) -> TemporalResult<Self> {
        let total = self
            .epoch_days()
            .checked_add(days)
            .ok_or(TemporalError::Overflow)?;
        Self::from_epoch_days(total)
    }

    /// Adds a [`Duration`] with openCypher semantics: months first (clamping
    /// the day-of-month), then days, then only the *whole days* of the
    /// seconds+nanoseconds group (truncated toward zero).
    ///
    /// Pinned by `Temporal8.feature` scenario \[1\]: a duration whose seconds
    /// group exceeds one day shifts the date by that whole day.
    ///
    /// # Errors
    /// [`TemporalError::Overflow`] if the result leaves the representable range.
    pub fn add_duration(&self, d: &Duration) -> TemporalResult<Self> {
        let with_md = self.add_months_days_clamped(d.months, d.days)?;
        // |seconds| <= i64::MAX, so the whole-day count fits comfortably in i64.
        let sec_days = (seconds_group_total_nanos(d) / NANOS_PER_DAY_I128) as i64;
        with_md.checked_add_days(sec_days)
    }

    /// Subtracts a [`Duration`]; see [`Self::add_duration`].
    ///
    /// # Errors
    /// [`TemporalError::Overflow`] if the negated duration or the result is
    /// unrepresentable.
    pub fn sub_duration(&self, d: &Duration) -> TemporalResult<Self> {
        self.add_duration(&d.checked_neg()?)
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_iso_string())
    }
}

// ---------------------------------------------------------------------------
// LocalTime
// ---------------------------------------------------------------------------

impl LocalTime {
    /// Constructs a wall-clock time from components.
    ///
    /// `nanos` is the full nanosecond-of-second value (`0..=999_999_999`).
    ///
    /// # Errors
    /// [`TemporalError::InvalidComponent`] if any component is out of range
    /// (`hour < 24`, `minute < 60`, `second < 60`, `nanos < 10^9`).
    ///
    /// # Examples
    /// ```
    /// use graphus_core::value::temporal::LocalTime;
    /// let t = LocalTime::from_hms_nanos(12, 31, 14, 645_876_123).unwrap();
    /// assert_eq!(t.to_iso_string(), "12:31:14.645876123");
    /// ```
    pub fn from_hms_nanos(hour: u32, minute: u32, second: u32, nanos: u32) -> TemporalResult<Self> {
        if hour > 23 {
            return Err(TemporalError::InvalidComponent("hour"));
        }
        if minute > 59 {
            return Err(TemporalError::InvalidComponent("minute"));
        }
        if second > 59 {
            return Err(TemporalError::InvalidComponent("second"));
        }
        if nanos > 999_999_999 {
            return Err(TemporalError::InvalidComponent("nanosecond"));
        }
        let seconds_of_day = u64::from(hour) * 3600 + u64::from(minute) * 60 + u64::from(second);
        Ok(Self {
            nanos_of_day: seconds_of_day * NANOS_PER_SECOND + u64::from(nanos),
        })
    }

    /// The hour of the day (0-23).
    #[must_use]
    pub fn hour(&self) -> i64 {
        (self.nanos_of_day / (3600 * NANOS_PER_SECOND)) as i64
    }

    /// The minute of the hour (0-59).
    #[must_use]
    pub fn minute(&self) -> i64 {
        ((self.nanos_of_day / (60 * NANOS_PER_SECOND)) % 60) as i64
    }

    /// The second of the minute (0-59).
    #[must_use]
    pub fn second(&self) -> i64 {
        ((self.nanos_of_day / NANOS_PER_SECOND) % 60) as i64
    }

    /// The full nanosecond-of-second value (`0..=999_999_999`).
    fn nanos_of_second(&self) -> u32 {
        (self.nanos_of_day % NANOS_PER_SECOND) as u32
    }

    /// The truncated millisecond within the second (`123456789 ns -> 123`).
    #[must_use]
    pub fn millisecond(&self) -> i64 {
        i64::from(self.nanos_of_second() / 1_000_000)
    }

    /// The truncated microsecond within the second (`123456789 ns -> 123456`).
    #[must_use]
    pub fn microsecond(&self) -> i64 {
        i64::from(self.nanos_of_second() / 1_000)
    }

    /// The nanosecond within the second (`0..=999_999_999`).
    #[must_use]
    pub fn nanosecond(&self) -> i64 {
        i64::from(self.nanos_of_second())
    }

    /// Formats this time as ISO 8601, omitting the seconds when both the
    /// second and the sub-second part are zero (`12:00`), and printing the
    /// sub-second part in trimmed groups of three digits.
    ///
    /// Pinned by `Temporal1.feature` scenario \[5\]: `{hour: 12}` renders as
    /// `'12:00'` and `{hour: 12, minute: 31, second: 14, millisecond: 645}` as
    /// `'12:31:14.645'`.
    #[must_use]
    pub fn to_iso_string(&self) -> String {
        let mut out = String::with_capacity(18);
        let _ = write!(out, "{:02}:{:02}", self.hour(), self.minute());
        let (second, nanos) = (self.second(), self.nanos_of_second());
        if second != 0 || nanos != 0 {
            let _ = write!(out, ":{second:02}");
            push_subsecond(&mut out, nanos);
        }
        out
    }

    /// Adds the seconds+nanoseconds group of a [`Duration`], wrapping modulo
    /// 24 hours (months and days do not affect a time of day).
    ///
    /// Pinned by `Temporal8.feature` scenario \[2\].
    #[must_use]
    pub fn add_duration(&self, d: &Duration) -> Self {
        self.shift_nanos(seconds_group_total_nanos(d))
    }

    /// Subtracts the seconds+nanoseconds group of a [`Duration`], wrapping
    /// modulo 24 hours.
    #[must_use]
    pub fn sub_duration(&self, d: &Duration) -> Self {
        self.shift_nanos(-seconds_group_total_nanos(d))
    }

    /// Shifts this time by a signed nanosecond delta, wrapping modulo 24 h.
    fn shift_nanos(&self, delta: i128) -> Self {
        let total = i128::from(self.nanos_of_day) + delta;
        // rem_euclid yields a value in [0, NANOS_PER_DAY), so the cast is lossless.
        Self {
            nanos_of_day: total.rem_euclid(NANOS_PER_DAY_I128) as u64,
        }
    }
}

impl fmt::Display for LocalTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_iso_string())
    }
}

// ---------------------------------------------------------------------------
// ZonedTime
// ---------------------------------------------------------------------------

impl ZonedTime {
    /// Constructs a zoned time from a wall-clock time and a UTC offset.
    ///
    /// # Errors
    /// [`TemporalError::InvalidComponent`] if `|offset_seconds|` exceeds
    /// [`MAX_OFFSET_SECONDS`] (18 hours).
    pub fn new(time: LocalTime, offset_seconds: i32) -> TemporalResult<Self> {
        if offset_seconds.abs() > MAX_OFFSET_SECONDS {
            return Err(TemporalError::InvalidComponent("timezone offset"));
        }
        Ok(Self {
            time,
            offset_seconds,
        })
    }

    /// The hour of the day (0-23).
    #[must_use]
    pub fn hour(&self) -> i64 {
        self.time.hour()
    }

    /// The minute of the hour (0-59).
    #[must_use]
    pub fn minute(&self) -> i64 {
        self.time.minute()
    }

    /// The second of the minute (0-59).
    #[must_use]
    pub fn second(&self) -> i64 {
        self.time.second()
    }

    /// The truncated millisecond within the second.
    #[must_use]
    pub fn millisecond(&self) -> i64 {
        self.time.millisecond()
    }

    /// The truncated microsecond within the second.
    #[must_use]
    pub fn microsecond(&self) -> i64 {
        self.time.microsecond()
    }

    /// The nanosecond within the second.
    #[must_use]
    pub fn nanosecond(&self) -> i64 {
        self.time.nanosecond()
    }

    /// The offset as a string (`"+01:00"`, `"Z"`).
    #[must_use]
    pub fn offset_string(&self) -> String {
        format_offset(self.offset_seconds)
    }

    /// The offset in whole minutes (truncated toward zero).
    #[must_use]
    pub fn offset_minutes(&self) -> i64 {
        i64::from(self.offset_seconds / 60)
    }

    /// The `timezone` component: a zoned *time* has no zone id, so this is the
    /// offset string (pinned by `Temporal5.feature` scenario \[4\]).
    #[must_use]
    pub fn timezone_name(&self) -> String {
        self.offset_string()
    }

    /// Formats this time as ISO 8601 with its offset (`12:31:14.645+01:00`,
    /// `12:00Z`).
    #[must_use]
    pub fn to_iso_string(&self) -> String {
        let mut out = self.time.to_iso_string();
        out.push_str(&self.offset_string());
        out
    }

    /// Adds the seconds+nanoseconds group of a [`Duration`], wrapping modulo
    /// 24 hours; the offset is preserved (`Temporal8.feature` scenario \[3\]).
    #[must_use]
    pub fn add_duration(&self, d: &Duration) -> Self {
        Self {
            time: self.time.add_duration(d),
            offset_seconds: self.offset_seconds,
        }
    }

    /// Subtracts the seconds+nanoseconds group of a [`Duration`], wrapping
    /// modulo 24 hours; the offset is preserved.
    #[must_use]
    pub fn sub_duration(&self, d: &Duration) -> Self {
        Self {
            time: self.time.sub_duration(d),
            offset_seconds: self.offset_seconds,
        }
    }
}

impl fmt::Display for ZonedTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_iso_string())
    }
}

// ---------------------------------------------------------------------------
// LocalDateTime
// ---------------------------------------------------------------------------

impl LocalDateTime {
    /// Composes a date and a wall-clock time into a local date-time.
    ///
    /// Never overflows: an `i32` day count times 86 400 plus a second of day
    /// always fits in `i64` epoch seconds.
    #[must_use]
    pub fn from_date_time(date: Date, time: LocalTime) -> Self {
        let epoch_seconds = i64::from(date.days_since_epoch) * SECONDS_PER_DAY
            + (time.nanos_of_day / NANOS_PER_SECOND) as i64;
        Self {
            epoch_seconds,
            // nanos_of_day % 10^9 is < 10^9, so the cast is lossless.
            nanos: (time.nanos_of_day % NANOS_PER_SECOND) as u32,
        }
    }

    /// Decomposes this local date-time into its date and time of day.
    ///
    /// Uses Euclidean division so instants before 1970 decompose correctly
    /// (e.g. one second before the epoch is `1969-12-31T23:59:59`). For values
    /// produced by this module the round trip with [`Self::from_date_time`] is
    /// exact; hand-crafted `epoch_seconds` beyond the `i32`-day range of
    /// [`Date`] saturate to the nearest representable date, and a hand-crafted
    /// `nanos` field above `999_999_999` is treated as `999_999_999`.
    #[must_use]
    pub fn to_date_time(&self) -> (Date, LocalTime) {
        let days = self.epoch_seconds.div_euclid(SECONDS_PER_DAY);
        let second_of_day = self.epoch_seconds.rem_euclid(SECONDS_PER_DAY) as u64;
        let days_since_epoch =
            i32::try_from(days).unwrap_or(if days < 0 { i32::MIN } else { i32::MAX });
        let nanos = u64::from(self.nanos.min(999_999_999));
        (
            Date { days_since_epoch },
            LocalTime {
                nanos_of_day: second_of_day * NANOS_PER_SECOND + nanos,
            },
        )
    }

    /// The calendar year.
    #[must_use]
    pub fn year(&self) -> i64 {
        self.to_date_time().0.year()
    }

    /// The calendar month (1-12).
    #[must_use]
    pub fn month(&self) -> i64 {
        self.to_date_time().0.month()
    }

    /// The day of the month (1-31).
    #[must_use]
    pub fn day(&self) -> i64 {
        self.to_date_time().0.day()
    }

    /// The quarter of the year (1-4).
    #[must_use]
    pub fn quarter(&self) -> i64 {
        self.to_date_time().0.quarter()
    }

    /// The ISO 8601 week (1-53).
    #[must_use]
    pub fn week(&self) -> i64 {
        self.to_date_time().0.week()
    }

    /// The ISO 8601 week-based year.
    #[must_use]
    pub fn week_year(&self) -> i64 {
        self.to_date_time().0.week_year()
    }

    /// The 1-based ordinal day of the year.
    #[must_use]
    pub fn ordinal_day(&self) -> i64 {
        self.to_date_time().0.ordinal_day()
    }

    /// The ISO weekday: Monday = 1 .. Sunday = 7.
    #[must_use]
    pub fn week_day(&self) -> i64 {
        self.to_date_time().0.week_day()
    }

    /// The 1-based day within the quarter.
    #[must_use]
    pub fn day_of_quarter(&self) -> i64 {
        self.to_date_time().0.day_of_quarter()
    }

    /// The hour of the day (0-23).
    #[must_use]
    pub fn hour(&self) -> i64 {
        self.to_date_time().1.hour()
    }

    /// The minute of the hour (0-59).
    #[must_use]
    pub fn minute(&self) -> i64 {
        self.to_date_time().1.minute()
    }

    /// The second of the minute (0-59).
    #[must_use]
    pub fn second(&self) -> i64 {
        self.to_date_time().1.second()
    }

    /// The truncated millisecond within the second.
    #[must_use]
    pub fn millisecond(&self) -> i64 {
        self.to_date_time().1.millisecond()
    }

    /// The truncated microsecond within the second.
    #[must_use]
    pub fn microsecond(&self) -> i64 {
        self.to_date_time().1.microsecond()
    }

    /// The nanosecond within the second.
    #[must_use]
    pub fn nanosecond(&self) -> i64 {
        self.to_date_time().1.nanosecond()
    }

    /// Seconds since the Unix epoch, interpreting this local value as UTC.
    #[must_use]
    pub fn epoch_seconds(&self) -> i64 {
        self.epoch_seconds
    }

    /// Milliseconds since the Unix epoch, interpreting this local value as
    /// UTC (truncated; saturates at the `i64` boundary, which is unreachable
    /// for values produced by this module).
    #[must_use]
    pub fn epoch_millis(&self) -> i64 {
        self.epoch_seconds
            .saturating_mul(1000)
            .saturating_add(i64::from(self.nanos.min(999_999_999)) / 1_000_000)
    }

    /// Formats this local date-time as ISO 8601 (`1984-10-11T12:31:14.645`).
    #[must_use]
    pub fn to_iso_string(&self) -> String {
        let (date, time) = self.to_date_time();
        let mut out = date.to_iso_string();
        out.push('T');
        out.push_str(&time.to_iso_string());
        out
    }

    /// Adds a [`Duration`] with openCypher semantics: months first (clamping
    /// the day-of-month), then days, then the full seconds+nanoseconds group
    /// (which may carry across midnight; `Temporal8.feature` scenario \[4\]).
    ///
    /// # Errors
    /// [`TemporalError::Overflow`] if the result leaves the representable range.
    pub fn add_duration(&self, d: &Duration) -> TemporalResult<Self> {
        let (date, time) = self.to_date_time();
        let date = date.add_months_days_clamped(d.months, d.days)?;
        let total = i128::from(time.nanos_of_day) + seconds_group_total_nanos(d);
        // |total| < 2^63 * 10^9 + 2^47, and the day carry below fits in i64.
        let carry_days = total.div_euclid(NANOS_PER_DAY_I128) as i64;
        let nanos_of_day = total.rem_euclid(NANOS_PER_DAY_I128) as u64;
        let date = date.checked_add_days(carry_days)?;
        Ok(Self::from_date_time(date, LocalTime { nanos_of_day }))
    }

    /// Subtracts a [`Duration`]; see [`Self::add_duration`].
    ///
    /// # Errors
    /// [`TemporalError::Overflow`] if the negated duration or the result is
    /// unrepresentable.
    pub fn sub_duration(&self, d: &Duration) -> TemporalResult<Self> {
        self.add_duration(&d.checked_neg()?)
    }
}

impl fmt::Display for LocalDateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_iso_string())
    }
}

// ---------------------------------------------------------------------------
// ZonedDateTime
// ---------------------------------------------------------------------------

impl ZonedDateTime {
    /// Constructs a zoned date-time from a local wall-clock value, a resolved
    /// UTC offset, and an optional IANA zone id (empty string for offset-only
    /// values).
    ///
    /// This module performs no time-zone-rule resolution; the caller is
    /// responsible for supplying an offset consistent with the zone id.
    ///
    /// # Errors
    /// [`TemporalError::InvalidComponent`] if `|offset_seconds|` exceeds
    /// [`MAX_OFFSET_SECONDS`].
    pub fn from_local(
        local: LocalDateTime,
        offset_seconds: i32,
        zone_id: impl Into<String>,
    ) -> TemporalResult<Self> {
        if offset_seconds.abs() > MAX_OFFSET_SECONDS {
            return Err(TemporalError::InvalidComponent("timezone offset"));
        }
        Ok(Self {
            local,
            offset_seconds,
            zone_id: zone_id.into(),
        })
    }

    /// Constructs a zoned date-time from date and time parts plus an offset.
    ///
    /// # Errors
    /// [`TemporalError::InvalidComponent`] if the offset is out of range.
    pub fn from_parts(
        date: Date,
        time: LocalTime,
        offset_seconds: i32,
        zone_id: impl Into<String>,
    ) -> TemporalResult<Self> {
        Self::from_local(
            LocalDateTime::from_date_time(date, time),
            offset_seconds,
            zone_id,
        )
    }

    /// The calendar year of the local wall-clock value.
    #[must_use]
    pub fn year(&self) -> i64 {
        self.local.year()
    }

    /// The calendar month (1-12).
    #[must_use]
    pub fn month(&self) -> i64 {
        self.local.month()
    }

    /// The day of the month (1-31).
    #[must_use]
    pub fn day(&self) -> i64 {
        self.local.day()
    }

    /// The quarter of the year (1-4).
    #[must_use]
    pub fn quarter(&self) -> i64 {
        self.local.quarter()
    }

    /// The ISO 8601 week (1-53).
    #[must_use]
    pub fn week(&self) -> i64 {
        self.local.week()
    }

    /// The ISO 8601 week-based year.
    #[must_use]
    pub fn week_year(&self) -> i64 {
        self.local.week_year()
    }

    /// The 1-based ordinal day of the year.
    #[must_use]
    pub fn ordinal_day(&self) -> i64 {
        self.local.ordinal_day()
    }

    /// The ISO weekday: Monday = 1 .. Sunday = 7.
    #[must_use]
    pub fn week_day(&self) -> i64 {
        self.local.week_day()
    }

    /// The 1-based day within the quarter.
    #[must_use]
    pub fn day_of_quarter(&self) -> i64 {
        self.local.day_of_quarter()
    }

    /// The hour of the day (0-23).
    #[must_use]
    pub fn hour(&self) -> i64 {
        self.local.hour()
    }

    /// The minute of the hour (0-59).
    #[must_use]
    pub fn minute(&self) -> i64 {
        self.local.minute()
    }

    /// The second of the minute (0-59).
    #[must_use]
    pub fn second(&self) -> i64 {
        self.local.second()
    }

    /// The truncated millisecond within the second.
    #[must_use]
    pub fn millisecond(&self) -> i64 {
        self.local.millisecond()
    }

    /// The truncated microsecond within the second.
    #[must_use]
    pub fn microsecond(&self) -> i64 {
        self.local.microsecond()
    }

    /// The nanosecond within the second.
    #[must_use]
    pub fn nanosecond(&self) -> i64 {
        self.local.nanosecond()
    }

    /// The offset as a string (`"+01:00"`, `"Z"`).
    #[must_use]
    pub fn offset_string(&self) -> String {
        format_offset(self.offset_seconds)
    }

    /// The offset in whole minutes (truncated toward zero).
    #[must_use]
    pub fn offset_minutes(&self) -> i64 {
        i64::from(self.offset_seconds / 60)
    }

    /// The `timezone` component: the IANA zone id when present, otherwise the
    /// offset string (pinned by `Temporal5.feature` scenarios \[4\] and \[6\]).
    #[must_use]
    pub fn timezone_name(&self) -> String {
        if self.zone_id.is_empty() {
            self.offset_string()
        } else {
            self.zone_id.clone()
        }
    }

    /// Seconds since the Unix epoch of the *instant* this value denotes
    /// (local wall-clock seconds minus the offset).
    ///
    /// Pinned by `Temporal5.feature` scenario \[6\]: 1984-11-11T12:31:14+01:00
    /// has `epochSeconds` 469020674. Saturates at the `i64` boundary, which is
    /// unreachable for values produced by this module.
    #[must_use]
    pub fn epoch_seconds(&self) -> i64 {
        self.local
            .epoch_seconds
            .saturating_sub(i64::from(self.offset_seconds))
    }

    /// Milliseconds since the Unix epoch of the instant (truncated).
    #[must_use]
    pub fn epoch_millis(&self) -> i64 {
        self.epoch_seconds()
            .saturating_mul(1000)
            .saturating_add(i64::from(self.local.nanos.min(999_999_999)) / 1_000_000)
    }

    /// Formats this zoned date-time as ISO 8601 with its offset and, when a
    /// zone id is present, the bracketed zone
    /// (`1984-10-11T12:31:14.645+01:00[Europe/Stockholm]`).
    #[must_use]
    pub fn to_iso_string(&self) -> String {
        let mut out = self.local.to_iso_string();
        out.push_str(&self.offset_string());
        if !self.zone_id.is_empty() {
            out.push('[');
            out.push_str(&self.zone_id);
            out.push(']');
        }
        out
    }

    /// Adds a [`Duration`] to the local wall-clock value, preserving the
    /// offset and zone id (`Temporal8.feature` scenario \[5\]).
    ///
    /// Note: with a time-zone database, adding across a DST transition would
    /// re-resolve the offset; that refinement belongs to the layer owning the
    /// tzdb and composes on top of this wall-clock arithmetic.
    ///
    /// # Errors
    /// [`TemporalError::Overflow`] if the result leaves the representable range.
    pub fn add_duration(&self, d: &Duration) -> TemporalResult<Self> {
        Ok(Self {
            local: self.local.add_duration(d)?,
            offset_seconds: self.offset_seconds,
            zone_id: self.zone_id.clone(),
        })
    }

    /// Subtracts a [`Duration`]; see [`Self::add_duration`].
    ///
    /// # Errors
    /// [`TemporalError::Overflow`] if the negated duration or the result is
    /// unrepresentable.
    pub fn sub_duration(&self, d: &Duration) -> TemporalResult<Self> {
        self.add_duration(&d.checked_neg()?)
    }
}

impl fmt::Display for ZonedDateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_iso_string())
    }
}

// ---------------------------------------------------------------------------
// Duration
// ---------------------------------------------------------------------------

/// The seconds+nanoseconds group of a duration as a single signed nanosecond
/// total. Widened to `i128` so it can never overflow regardless of the field
/// values, and so mixed-sign `(seconds, nanos)` pairs are handled uniformly.
fn seconds_group_total_nanos(d: &Duration) -> i128 {
    i128::from(d.seconds) * i128::from(NANOS_PER_SECOND) + i128::from(d.nanos)
}

/// Truncates a finite `f64` toward zero into an `i64`, rejecting non-finite
/// values and magnitudes at or beyond `2^63` (so the cast is always exact).
fn trunc_f64_to_i64(v: f64) -> TemporalResult<i64> {
    if !v.is_finite() {
        return Err(TemporalError::Overflow);
    }
    let t = v.trunc();
    // 2^63 is exactly representable as f64; anything in (-2^63, 2^63) is safe.
    if t >= 9_223_372_036_854_775_808.0 || t <= -9_223_372_036_854_775_808.0 {
        return Err(TemporalError::Overflow);
    }
    Ok(t as i64)
}

/// Saturating narrowing for component accessors that report `i128` totals as
/// Cypher integers.
fn clamp_i128_to_i64(v: i128) -> i64 {
    i64::try_from(v).unwrap_or(if v < 0 { i64::MIN } else { i64::MAX })
}

impl Duration {
    /// Constructs a duration from its three independent component groups,
    /// normalising the seconds group so that `nanos` shares the sign of the
    /// total and `|nanos| < 10^9`.
    ///
    /// `nanos` is accepted as `i64` so callers can pass totals derived from
    /// milliseconds or microseconds without pre-normalising.
    ///
    /// # Errors
    /// [`TemporalError::Overflow`] if the normalised seconds do not fit `i64`.
    ///
    /// # Examples
    /// ```
    /// use graphus_core::value::temporal::Duration;
    /// // 2 s minus 1 ms normalises to 1.999 s.
    /// let d = Duration::from_components(0, 0, 2, -1_000_000).unwrap();
    /// assert_eq!((d.seconds, d.nanos), (1, 999_000_000));
    /// assert_eq!(d.to_iso_string(), "PT1.999S");
    /// ```
    pub fn from_components(
        months: i64,
        days: i64,
        seconds: i64,
        nanos: i64,
    ) -> TemporalResult<Self> {
        let total = i128::from(seconds) * i128::from(NANOS_PER_SECOND) + i128::from(nanos);
        Self::from_month_day_total(months, days, total)
    }

    /// Builds a duration from months, days, and a seconds-group nanosecond
    /// total, splitting the total into sign-sharing `(seconds, nanos)`.
    fn from_month_day_total(months: i64, days: i64, total_nanos: i128) -> TemporalResult<Self> {
        // i128 `/` and `%` truncate toward zero, so quotient and remainder
        // share the total's sign and |remainder| < 10^9 fits in i32.
        let seconds = i64::try_from(total_nanos / i128::from(NANOS_PER_SECOND))
            .map_err(|_| TemporalError::Overflow)?;
        let nanos = (total_nanos % i128::from(NANOS_PER_SECOND)) as i32;
        Ok(Self {
            months,
            days,
            seconds,
            nanos,
        })
    }

    /// Negates every component.
    ///
    /// # Errors
    /// [`TemporalError::Overflow`] only at the absolute `i64`/`i32` minima.
    pub fn checked_neg(&self) -> TemporalResult<Self> {
        Ok(Self {
            months: self.months.checked_neg().ok_or(TemporalError::Overflow)?,
            days: self.days.checked_neg().ok_or(TemporalError::Overflow)?,
            seconds: self.seconds.checked_neg().ok_or(TemporalError::Overflow)?,
            nanos: self.nanos.checked_neg().ok_or(TemporalError::Overflow)?,
        })
    }

    // -- Component accessors (openCypher semantics, `Temporal5.feature` [7]) --
    //
    // The three component groups are independent: month-derived components see
    // only `months`, day-derived only `days`, and time-derived only the
    // seconds+nanoseconds total. All divisions truncate toward zero.

    /// Whole years: `months / 12`.
    #[must_use]
    pub fn years(&self) -> i64 {
        self.months / 12
    }

    /// Whole quarters: `months / 3`.
    #[must_use]
    pub fn quarters(&self) -> i64 {
        self.months / 3
    }

    /// Total months (the raw months group).
    #[must_use]
    pub fn months_total(&self) -> i64 {
        self.months
    }

    /// Quarters remaining within the year: `(months % 12) / 3`.
    #[must_use]
    pub fn quarters_of_year(&self) -> i64 {
        (self.months % 12) / 3
    }

    /// Months remaining within the year: `months % 12`.
    #[must_use]
    pub fn months_of_year(&self) -> i64 {
        self.months % 12
    }

    /// Months remaining within the quarter: `months % 3`.
    #[must_use]
    pub fn months_of_quarter(&self) -> i64 {
        self.months % 3
    }

    /// Whole weeks: `days / 7`.
    #[must_use]
    pub fn weeks(&self) -> i64 {
        self.days / 7
    }

    /// Total days (the raw days group).
    #[must_use]
    pub fn days_total(&self) -> i64 {
        self.days
    }

    /// Days remaining within the week: `days % 7`.
    #[must_use]
    pub fn days_of_week(&self) -> i64 {
        self.days % 7
    }

    /// Whole hours of the seconds group.
    #[must_use]
    pub fn hours(&self) -> i64 {
        clamp_i128_to_i64(seconds_group_total_nanos(self) / (3600 * 1_000_000_000))
    }

    /// Total whole minutes of the seconds group.
    #[must_use]
    pub fn minutes(&self) -> i64 {
        clamp_i128_to_i64(seconds_group_total_nanos(self) / (60 * 1_000_000_000))
    }

    /// Minutes remaining within the hour.
    #[must_use]
    pub fn minutes_of_hour(&self) -> i64 {
        self.minutes() % 60
    }

    /// Total whole seconds of the seconds group (including the nanosecond
    /// carry, truncated toward zero).
    #[must_use]
    pub fn seconds_total(&self) -> i64 {
        clamp_i128_to_i64(seconds_group_total_nanos(self) / 1_000_000_000)
    }

    /// Seconds remaining within the minute.
    #[must_use]
    pub fn seconds_of_minute(&self) -> i64 {
        self.seconds_total() % 60
    }

    /// Total whole milliseconds of the seconds group.
    #[must_use]
    pub fn milliseconds(&self) -> i64 {
        clamp_i128_to_i64(seconds_group_total_nanos(self) / 1_000_000)
    }

    /// Milliseconds remaining within the second.
    #[must_use]
    pub fn milliseconds_of_second(&self) -> i64 {
        self.milliseconds() % 1_000
    }

    /// Total whole microseconds of the seconds group.
    #[must_use]
    pub fn microseconds(&self) -> i64 {
        clamp_i128_to_i64(seconds_group_total_nanos(self) / 1_000)
    }

    /// Microseconds remaining within the second.
    #[must_use]
    pub fn microseconds_of_second(&self) -> i64 {
        self.microseconds() % 1_000_000
    }

    /// Total nanoseconds of the seconds group (saturating at the `i64`
    /// boundary; Cypher integers are 64-bit).
    #[must_use]
    pub fn nanoseconds(&self) -> i64 {
        clamp_i128_to_i64(seconds_group_total_nanos(self))
    }

    /// Nanoseconds remaining within the second.
    #[must_use]
    pub fn nanoseconds_of_second(&self) -> i64 {
        clamp_i128_to_i64(seconds_group_total_nanos(self) % 1_000_000_000)
    }

    // -- Formatting --

    /// Formats this duration in the Neo4j/openCypher ISO-8601 style.
    ///
    /// The three component groups print independently, each component with its
    /// own sign; the seconds group prints as `H`/`M`/`S` derived from its
    /// signed nanosecond total, with the fractional second sharing the group's
    /// sign and trimmed of trailing zeros. The zero duration is `PT0S`.
    ///
    /// Pinned by `Temporal6.feature` scenario \[6\] (e.g. `'P12Y5M-14DT16H'`,
    /// `'PT-1M-0.001S'`, `'PT1.999S'`) and `Temporal8.feature` scenario \[6\]
    /// (e.g. `'P-6M-15DT-17H-45M-3.500000002S'`, `'PT0S'`).
    #[must_use]
    pub fn to_iso_string(&self) -> String {
        let total = seconds_group_total_nanos(self);
        if self.months == 0 && self.days == 0 && total == 0 {
            return "PT0S".to_owned();
        }
        let mut out = String::with_capacity(24);
        out.push('P');
        let (years, months_of_year) = (self.months / 12, self.months % 12);
        if years != 0 {
            let _ = write!(out, "{years}Y");
        }
        if months_of_year != 0 {
            let _ = write!(out, "{months_of_year}M");
        }
        if self.days != 0 {
            let _ = write!(out, "{}D", self.days);
        }
        if total != 0 {
            out.push('T');
            let sign = if total < 0 { "-" } else { "" };
            let abs = total.unsigned_abs();
            let hours = abs / (3600 * 1_000_000_000);
            let minutes = (abs / (60 * 1_000_000_000)) % 60;
            let seconds = (abs / 1_000_000_000) % 60;
            let frac = (abs % 1_000_000_000) as u32;
            if hours != 0 {
                let _ = write!(out, "{sign}{hours}H");
            }
            if minutes != 0 {
                let _ = write!(out, "{sign}{minutes}M");
            }
            if seconds != 0 || frac != 0 {
                let _ = write!(out, "{sign}{seconds}");
                if frac != 0 {
                    let digits = format!("{frac:09}");
                    let _ = write!(out, ".{}", digits.trim_end_matches('0'));
                }
                out.push('S');
            }
        }
        out
    }

    // -- Arithmetic --

    /// Adds two durations component-group-wise.
    ///
    /// Pinned by `Temporal8.feature` scenario \[6\].
    ///
    /// # Errors
    /// [`TemporalError::Overflow`] if any component group overflows.
    pub fn add(&self, other: &Self) -> TemporalResult<Self> {
        let months = self
            .months
            .checked_add(other.months)
            .ok_or(TemporalError::Overflow)?;
        let days = self
            .days
            .checked_add(other.days)
            .ok_or(TemporalError::Overflow)?;
        let total = seconds_group_total_nanos(self) + seconds_group_total_nanos(other);
        Self::from_month_day_total(months, days, total)
    }

    /// Subtracts `other` from `self` component-group-wise.
    ///
    /// # Errors
    /// [`TemporalError::Overflow`] if any component group overflows.
    pub fn sub(&self, other: &Self) -> TemporalResult<Self> {
        let months = self
            .months
            .checked_sub(other.months)
            .ok_or(TemporalError::Overflow)?;
        let days = self
            .days
            .checked_sub(other.days)
            .ok_or(TemporalError::Overflow)?;
        let total = seconds_group_total_nanos(self) - seconds_group_total_nanos(other);
        Self::from_month_day_total(months, days, total)
    }

    /// Multiplies every component by an integer factor, exactly.
    ///
    /// # Errors
    /// [`TemporalError::Overflow`] if any component group overflows.
    pub fn mul_int(&self, factor: i64) -> TemporalResult<Self> {
        let months = self
            .months
            .checked_mul(factor)
            .ok_or(TemporalError::Overflow)?;
        let days = self
            .days
            .checked_mul(factor)
            .ok_or(TemporalError::Overflow)?;
        let total = seconds_group_total_nanos(self)
            .checked_mul(i128::from(factor))
            .ok_or(TemporalError::Overflow)?;
        Self::from_month_day_total(months, days, total)
    }

    /// Multiplies every component by a floating-point factor through the
    /// approximation cascade (see [`Self::approximate`]).
    ///
    /// Pinned by `Temporal8.feature` scenario \[7\]: scaling
    /// `P12Y5M14DT16H13M10.000000001S` by `0.5` yields `P6Y2M22DT13H21M8S`
    /// (the half month becomes 15.2184375 average days, whose fraction in turn
    /// becomes seconds; the half nanosecond truncates away).
    ///
    /// # Errors
    /// [`TemporalError::Overflow`] if the factor is non-finite or a component
    /// leaves the `i64` range.
    pub fn mul_scalar(&self, factor: f64) -> TemporalResult<Self> {
        Self::approximate(
            self.months as f64 * factor,
            self.days as f64 * factor,
            self.seconds as f64 * factor,
            f64::from(self.nanos) * factor,
        )
    }

    /// Divides every component by a floating-point divisor through the
    /// approximation cascade (see [`Self::approximate`]).
    ///
    /// # Errors
    /// [`TemporalError::Overflow`] if the divisor is zero or non-finite, or a
    /// component leaves the `i64` range.
    pub fn div_scalar(&self, divisor: f64) -> TemporalResult<Self> {
        Self::approximate(
            self.months as f64 / divisor,
            self.days as f64 / divisor,
            self.seconds as f64 / divisor,
            f64::from(self.nanos) / divisor,
        )
    }

    /// Builds a duration from fractional component groups, cascading the
    /// fractions downward the way Neo4j's `DurationValue.approximate` does:
    ///
    /// 1. the whole months are kept; the fractional month becomes nanoseconds
    ///    via the average Gregorian month ([`AVG_SECONDS_PER_MONTH`]);
    /// 2. the whole days are kept; the fractional day becomes nanoseconds;
    /// 3. the pooled carry nanoseconds yield extra whole days, the remainder
    ///    joins the seconds group;
    /// 4. fractional seconds become nanoseconds; the final nanosecond total is
    ///    truncated toward zero.
    ///
    /// The carry arithmetic runs in integer nanoseconds so that benign float
    /// representation error cannot flip a `.5 s` boundary.
    ///
    /// # Errors
    /// [`TemporalError::Overflow`] if any input is non-finite or any whole
    /// component leaves the `i64` range.
    pub fn approximate(months: f64, days: f64, seconds: f64, nanos: f64) -> TemporalResult<Self> {
        let whole_months = trunc_f64_to_i64(months)?;
        // |fraction| < 1, so |month_rem_ns| < AVG_NANOS_PER_MONTH (~2.6e15):
        // exact in f64 and far inside i64.
        let month_rem_ns =
            trunc_f64_to_i64((months - whole_months as f64) * AVG_NANOS_PER_MONTH as f64)?;
        let whole_days = trunc_f64_to_i64(days)?;
        let day_rem_ns = trunc_f64_to_i64((days - whole_days as f64) * NANOS_PER_DAY as f64)?;
        let carry: i128 = i128::from(month_rem_ns) + i128::from(day_rem_ns);
        let extra_days = (carry / NANOS_PER_DAY_I128) as i64; // |carry| < 2 months
        let leftover_ns = carry % NANOS_PER_DAY_I128;
        let whole_seconds = trunc_f64_to_i64(seconds)?;
        let second_rem_ns =
            trunc_f64_to_i64((seconds - whole_seconds as f64) * NANOS_PER_SECOND as f64)?;
        let whole_nanos = trunc_f64_to_i64(nanos)?;
        let days_total = whole_days
            .checked_add(extra_days)
            .ok_or(TemporalError::Overflow)?;
        let total = i128::from(whole_seconds) * i128::from(NANOS_PER_SECOND)
            + i128::from(second_rem_ns)
            + i128::from(whole_nanos)
            + leftover_ns;
        Self::from_month_day_total(whole_months, days_total, total)
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_iso_string())
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Consumes exactly `n` ASCII digits at `*pos`, returning their value.
fn take_fixed_digits(b: &[u8], pos: &mut usize, n: usize) -> Option<u32> {
    if *pos + n > b.len() {
        return None;
    }
    let mut value = 0u32;
    for &c in &b[*pos..*pos + n] {
        if !c.is_ascii_digit() {
            return None;
        }
        value = value * 10 + u32::from(c - b'0');
    }
    *pos += n;
    Some(value)
}

/// Value of an already-validated short ASCII digit run (at most nine digits).
fn digits_value(b: &[u8]) -> u32 {
    let mut value = 0u32;
    for &c in b {
        value = value * 10 + u32::from(c - b'0');
    }
    value
}

/// Consumes an optional `.`/`,` sub-second fraction of one to nine digits,
/// returning it scaled to nanoseconds (`.142` -> `142_000_000`).
fn take_fraction_nanos(b: &[u8], pos: &mut usize) -> Result<u32, &'static str> {
    if *pos >= b.len() || (b[*pos] != b'.' && b[*pos] != b',') {
        return Ok(0);
    }
    *pos += 1;
    let start = *pos;
    while *pos < b.len() && b[*pos].is_ascii_digit() {
        *pos += 1;
    }
    let k = *pos - start;
    if k == 0 || k > 9 {
        return Err("a sub-second fraction must have one to nine digits");
    }
    Ok(digits_value(&b[start..*pos]) * 10u32.pow(9 - k as u32))
}

/// Index of the first byte that can start a UTC offset (`+`, `-`, `Z`, `z`),
/// searching from position 1 (a time string always starts with a digit).
fn find_offset_start(s: &str) -> Option<usize> {
    s.bytes()
        .enumerate()
        .skip(1)
        .find(|(_, c)| matches!(c, b'+' | b'-' | b'Z' | b'z'))
        .map(|(i, _)| i)
}

/// Returns `true` for bytes permitted inside a bracketed IANA zone id.
fn is_zone_id_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'/' | b'_' | b'-' | b'+' | b'.')
}

/// Parses an ISO 8601 date in any of the shapes the openCypher TCK feeds the
/// `date()` constructor (`Temporal2.feature` scenario \[1\]): calendar dates
/// (`2015-07-21`, `20150721`, `2015-07`, `201507`, `2015`), week dates
/// (`2015-W30-2`, `2015W302`, `2015-W30`, `2015W30`), ordinal dates
/// (`2015-202`, `2015202`), and quarter dates (`2015-Q2-60`, `2015Q260`,
/// `2015-Q2`, `2015Q2`). Omitted lower-order components default to their first
/// value. A leading `-` (or `+`) is accepted for proleptic years.
///
/// # Errors
/// [`TemporalError::Parse`] for malformed strings and
/// [`TemporalError::InvalidComponent`] for well-formed strings with
/// out-of-range components.
///
/// # Examples
/// ```
/// use graphus_core::temporal_calc::parse_date;
/// assert_eq!(parse_date("2015-W30-2").unwrap().to_iso_string(), "2015-07-21");
/// ```
pub fn parse_date(s: &str) -> TemporalResult<Date> {
    let err = |reason: &'static str| TemporalError::Parse {
        input: s.to_owned(),
        reason,
    };
    let b = s.as_bytes();
    let mut pos = 0usize;
    let (sign, signed): (i64, bool) = match b.first() {
        Some(b'+') => {
            pos = 1;
            (1, true)
        }
        Some(b'-') => {
            pos = 1;
            (-1, true)
        }
        _ => (1, false),
    };
    let year_start = pos;
    while pos < b.len() && b[pos].is_ascii_digit() && (signed || pos - year_start < 4) {
        pos += 1;
    }
    let n = pos - year_start;
    if !(4..=9).contains(&n) {
        return Err(err("expected a four-digit year"));
    }
    let year = sign * i64::from(digits_value(&b[year_start..pos]));
    if pos == b.len() {
        return Date::from_ymd(year, 1, 1);
    }
    let extended = b[pos] == b'-';
    if extended {
        pos += 1;
    }
    match b.get(pos) {
        Some(b'W') => {
            pos += 1;
            let week = take_fixed_digits(b, &mut pos, 2)
                .ok_or_else(|| err("expected a two-digit week"))?;
            if pos == b.len() {
                return Date::from_year_week_day(year, week, 1);
            }
            if extended && (pos >= b.len() || b[pos] != b'-') {
                return Err(err("expected '-' before the day of week"));
            }
            if extended {
                pos += 1;
            }
            let dow = take_fixed_digits(b, &mut pos, 1)
                .ok_or_else(|| err("expected a one-digit day of week"))?;
            if pos != b.len() {
                return Err(err("trailing characters after week date"));
            }
            Date::from_year_week_day(year, week, dow)
        }
        Some(b'Q') => {
            pos += 1;
            let quarter = take_fixed_digits(b, &mut pos, 1)
                .ok_or_else(|| err("expected a one-digit quarter"))?;
            if pos == b.len() {
                return Date::from_year_quarter_day(year, quarter, 1);
            }
            if extended && (pos >= b.len() || b[pos] != b'-') {
                return Err(err("expected '-' before the day of quarter"));
            }
            if extended {
                pos += 1;
            }
            let dq = take_fixed_digits(b, &mut pos, 2)
                .ok_or_else(|| err("expected a two-digit day of quarter"))?;
            if pos != b.len() {
                return Err(err("trailing characters after quarter date"));
            }
            Date::from_year_quarter_day(year, quarter, dq)
        }
        Some(c) if c.is_ascii_digit() => {
            let run_start = pos;
            while pos < b.len() && b[pos].is_ascii_digit() {
                pos += 1;
            }
            let k = pos - run_start;
            let run = &b[run_start..pos];
            if extended {
                match (k, pos == b.len()) {
                    // YYYY-MM
                    (2, true) => Date::from_ymd(year, digits_value(run), 1),
                    // YYYY-MM-DD
                    (2, false) => {
                        if b[pos] != b'-' {
                            return Err(err("expected '-' before the day of month"));
                        }
                        pos += 1;
                        let day = take_fixed_digits(b, &mut pos, 2)
                            .ok_or_else(|| err("expected a two-digit day"))?;
                        if pos != b.len() {
                            return Err(err("trailing characters after calendar date"));
                        }
                        Date::from_ymd(year, digits_value(run), day)
                    }
                    // YYYY-DDD
                    (3, true) => Date::from_year_ordinal(year, digits_value(run)),
                    _ => Err(err("unrecognized date format")),
                }
            } else if pos != b.len() {
                Err(err("trailing characters after date"))
            } else {
                match k {
                    // YYYYMM
                    2 => Date::from_ymd(year, digits_value(run), 1),
                    // YYYYDDD
                    3 => Date::from_year_ordinal(year, digits_value(run)),
                    // YYYYMMDD
                    4 => Date::from_ymd(year, digits_value(&run[..2]), digits_value(&run[2..])),
                    _ => Err(err("unrecognized date format")),
                }
            }
        }
        _ => Err(err("unrecognized date format")),
    }
}

/// Parses an ISO 8601 time of day in the shapes the TCK feeds `localtime()`
/// (`Temporal2.feature` scenario \[2\]): `21:40:32.142`, `214032.142`,
/// `21:40:32`, `214032`, `21:40`, `2140`, and `21`. A fraction is permitted
/// only when seconds are present.
///
/// # Errors
/// [`TemporalError::Parse`] for malformed strings and
/// [`TemporalError::InvalidComponent`] for out-of-range components.
pub fn parse_local_time(s: &str) -> TemporalResult<LocalTime> {
    let err = |reason: &'static str| TemporalError::Parse {
        input: s.to_owned(),
        reason,
    };
    let b = s.as_bytes();
    let mut pos = 0usize;
    let hour = take_fixed_digits(b, &mut pos, 2).ok_or_else(|| err("expected a two-digit hour"))?;
    let mut minute = 0u32;
    let mut second = 0u32;
    let mut nanos = 0u32;
    if pos < b.len() && b[pos] == b':' {
        pos += 1;
        minute =
            take_fixed_digits(b, &mut pos, 2).ok_or_else(|| err("expected a two-digit minute"))?;
        if pos < b.len() && b[pos] == b':' {
            pos += 1;
            second = take_fixed_digits(b, &mut pos, 2)
                .ok_or_else(|| err("expected a two-digit second"))?;
            nanos = take_fraction_nanos(b, &mut pos).map_err(err)?;
        }
    } else if pos < b.len() && b[pos].is_ascii_digit() {
        minute =
            take_fixed_digits(b, &mut pos, 2).ok_or_else(|| err("expected a two-digit minute"))?;
        if pos < b.len() && b[pos].is_ascii_digit() {
            second = take_fixed_digits(b, &mut pos, 2)
                .ok_or_else(|| err("expected a two-digit second"))?;
            nanos = take_fraction_nanos(b, &mut pos).map_err(err)?;
        }
    }
    if pos != b.len() {
        return Err(err("trailing characters after time"));
    }
    LocalTime::from_hms_nanos(hour, minute, second, nanos)
}

/// Parses a UTC offset: `Z`/`z`, or a sign followed by `hh`, `hh:mm`, `hhmm`,
/// `hh:mm:ss`, or `hhmmss` (`Temporal2.feature` scenario \[3\] uses `+0100`,
/// `Z`, `+01:00`, `-0100`, `-01:30`, `-00:00`, `-02`, `+18:00`).
///
/// # Errors
/// [`TemporalError::Parse`] for malformed or out-of-range (beyond 18 hours)
/// offsets.
pub fn parse_offset_seconds(s: &str) -> TemporalResult<i32> {
    let err = |reason: &'static str| TemporalError::Parse {
        input: s.to_owned(),
        reason,
    };
    let b = s.as_bytes();
    if b == b"Z" || b == b"z" {
        return Ok(0);
    }
    let sign: i32 = match b.first() {
        Some(b'+') => 1,
        Some(b'-') => -1,
        _ => return Err(err("expected 'Z' or a signed offset")),
    };
    let mut pos = 1usize;
    let hours =
        take_fixed_digits(b, &mut pos, 2).ok_or_else(|| err("expected two offset hour digits"))?;
    let mut minutes = 0u32;
    let mut seconds = 0u32;
    if pos < b.len() {
        if b[pos] == b':' {
            pos += 1;
        }
        minutes = take_fixed_digits(b, &mut pos, 2)
            .ok_or_else(|| err("expected two offset minute digits"))?;
        if pos < b.len() {
            if b[pos] == b':' {
                pos += 1;
            }
            seconds = take_fixed_digits(b, &mut pos, 2)
                .ok_or_else(|| err("expected two offset second digits"))?;
        }
    }
    if pos != b.len() {
        return Err(err("trailing characters after offset"));
    }
    if minutes > 59 || seconds > 59 {
        return Err(err("offset minutes/seconds out of range"));
    }
    let total = (hours * 3600 + minutes * 60 + seconds) as i32;
    if total > MAX_OFFSET_SECONDS {
        return Err(err("offset exceeds 18 hours"));
    }
    Ok(sign * total)
}

/// Parses a time with a mandatory UTC offset (`21:40:32.142+0100`, `2140-00:00`,
/// `22+18:00`); see `Temporal2.feature` scenario \[3\].
///
/// # Errors
/// [`TemporalError::Parse`] when the offset is missing or any part is
/// malformed; [`TemporalError::InvalidComponent`] for out-of-range components.
pub fn parse_zoned_time(s: &str) -> TemporalResult<ZonedTime> {
    let Some(i) = find_offset_start(s) else {
        return Err(TemporalError::Parse {
            input: s.to_owned(),
            reason: "missing UTC offset",
        });
    };
    let time = parse_local_time(&s[..i])?;
    let offset = parse_offset_seconds(&s[i..])?;
    ZonedTime::new(time, offset)
}

/// Parses a local date-time `<date>T<time>` where both sides accept every
/// shape of [`parse_date`] and [`parse_local_time`] (`Temporal2.feature`
/// scenario \[4\]: `2015-W30-2T214032.142`, `2015202T21`, ...).
///
/// # Errors
/// [`TemporalError::Parse`] / [`TemporalError::InvalidComponent`] as for the
/// underlying date and time parsers.
pub fn parse_local_date_time(s: &str) -> TemporalResult<LocalDateTime> {
    let t = s.find('T').ok_or_else(|| TemporalError::Parse {
        input: s.to_owned(),
        reason: "expected 'T' between date and time",
    })?;
    let date = parse_date(&s[..t])?;
    let time = parse_local_time(&s[t + 1..])?;
    Ok(LocalDateTime::from_date_time(date, time))
}

/// Parses a zoned date-time into its unresolved parts: the local wall-clock
/// value, the explicit UTC offset (if present), and the bracketed IANA zone id
/// (if present). This is the seam for the layer that owns the time-zone
/// database: a string such as `2015-07-21T21:40:32.142[Europe/London]` carries
/// no offset, and resolving one requires zone rules this crate does not have.
///
/// # Errors
/// [`TemporalError::Parse`] / [`TemporalError::InvalidComponent`] for
/// malformed input.
pub fn parse_zoned_date_time_parts(
    s: &str,
) -> TemporalResult<(LocalDateTime, Option<i32>, Option<String>)> {
    let err = |reason: &'static str| TemporalError::Parse {
        input: s.to_owned(),
        reason,
    };
    let (core, zone) = match s.strip_suffix(']') {
        Some(stripped) => {
            let open = stripped.find('[').ok_or_else(|| err("unbalanced ']'"))?;
            let zone = &stripped[open + 1..];
            if zone.is_empty() || !zone.bytes().all(is_zone_id_byte) {
                return Err(err("invalid time zone id"));
            }
            (&s[..open], Some(zone.to_owned()))
        }
        None => (s, None),
    };
    let t = core
        .find('T')
        .ok_or_else(|| err("expected 'T' between date and time"))?;
    let date = parse_date(&core[..t])?;
    let rest = &core[t + 1..];
    let (time_str, offset) = match find_offset_start(rest) {
        Some(i) => (&rest[..i], Some(parse_offset_seconds(&rest[i..])?)),
        None => (rest, None),
    };
    let time = parse_local_time(time_str)?;
    Ok((LocalDateTime::from_date_time(date, time), offset, zone))
}

/// Parses a zoned date-time with an **explicit** offset, optionally followed
/// by a bracketed zone id (`2015-07-21T21:40:32.142+02:00[Europe/Stockholm]`;
/// `Temporal2.feature` scenarios \[5\] and \[6\]).
///
/// Strings that carry only a named zone (no offset) require time-zone-rule
/// resolution and must go through [`parse_zoned_date_time_parts`] instead.
///
/// # Errors
/// [`TemporalError::Parse`] when the offset is absent or any part is
/// malformed; [`TemporalError::InvalidComponent`] for out-of-range components.
pub fn parse_zoned_date_time(s: &str) -> TemporalResult<ZonedDateTime> {
    let (local, offset, zone) = parse_zoned_date_time_parts(s)?;
    let Some(offset_seconds) = offset else {
        return Err(TemporalError::Parse {
            input: s.to_owned(),
            reason: "a named time zone without an explicit offset requires zone-rule resolution",
        });
    };
    ZonedDateTime::from_local(local, offset_seconds, zone.unwrap_or_default())
}

/// Parses an ISO 8601 duration in the shapes the TCK feeds `duration()`
/// (`Temporal2.feature` scenario \[7\]): the component form
/// `P[nY][nM][nW][nD][T[nH][nM][nS]]` with per-component signs, an optional
/// overall sign before `P`, an optional fraction on the **last** component
/// only, and the date-time form `P<yyyy>-<mm>-<dd>T<hh>:<mm>:<ss[.fff]>`.
///
/// Fractions cascade exactly the way Neo4j evaluates them: a fractional year
/// is twelve fractional months; a fractional month becomes nanoseconds via the
/// average Gregorian month ([`AVG_SECONDS_PER_MONTH`]); fractional months and
/// weeks contribute whole *days* before the remainder joins the seconds group
/// (`'P0.75M'` parses to 22 days 19:51:49.5, `'P2.5W'` to 17 days 12 h). The
/// cascade is computed in exact integer arithmetic.
///
/// # Errors
/// [`TemporalError::Parse`] for malformed strings and
/// [`TemporalError::Overflow`] when a component leaves the `i64` range.
///
/// # Examples
/// ```
/// use graphus_core::temporal_calc::parse_duration;
/// assert_eq!(parse_duration("P5M1.5D").unwrap().to_iso_string(), "P5M1DT12H");
/// ```
pub fn parse_duration(s: &str) -> TemporalResult<Duration> {
    let err = |reason: &'static str| TemporalError::Parse {
        input: s.to_owned(),
        reason,
    };
    let b = s.as_bytes();
    let mut pos = 0usize;
    let overall_neg = match b.first() {
        Some(b'-') => {
            pos = 1;
            true
        }
        Some(b'+') => {
            pos = 1;
            false
        }
        _ => false,
    };
    if pos >= b.len() || b[pos] != b'P' {
        return Err(err("expected 'P'"));
    }
    pos += 1;
    if pos >= b.len() {
        return Err(err("duration must have at least one component"));
    }

    // Date-time form: P<yyyy>-<mm>-<dd>T<hh>:<mm>:<ss[.fff]>.
    if b.len() >= pos + 5 && b[pos..pos + 4].iter().all(u8::is_ascii_digit) && b[pos + 4] == b'-' {
        return parse_duration_datetime_form(s, b, pos, overall_neg);
    }

    let mut months: i128 = 0;
    let mut days: i128 = 0;
    let mut seconds: i128 = 0;
    let mut date_frac_ns: i128 = 0;
    let mut time_frac_ns: i128 = 0;
    let mut in_time = false;
    let mut last_rank = 0u8;
    let mut saw_fraction = false;
    let mut any_component = false;
    let nps = i128::from(NANOS_PER_SECOND);

    while pos < b.len() {
        if !in_time && b[pos] == b'T' {
            pos += 1;
            in_time = true;
            last_rank = 0;
            if pos == b.len() {
                return Err(err("empty time part in duration"));
            }
            continue;
        }
        if saw_fraction {
            return Err(err(
                "only the smallest duration component may have a fraction",
            ));
        }
        let csign: i128 = match b[pos] {
            b'-' => {
                pos += 1;
                -1
            }
            b'+' => {
                pos += 1;
                1
            }
            _ => 1,
        };
        let start = pos;
        while pos < b.len() && b[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == start {
            return Err(err("expected digits in duration component"));
        }
        if pos - start > 18 {
            return Err(TemporalError::Overflow);
        }
        let mut value: i128 = 0;
        for &c in &b[start..pos] {
            value = value * 10 + i128::from(c - b'0');
        }
        // Optional fraction: numerator over 10^k, exact integers throughout.
        let mut frac: Option<(i128, i128)> = None;
        if pos < b.len() && (b[pos] == b'.' || b[pos] == b',') {
            pos += 1;
            let fs = pos;
            while pos < b.len() && b[pos].is_ascii_digit() {
                pos += 1;
            }
            let k = pos - fs;
            if k == 0 || k > 9 {
                return Err(err("a duration fraction must have one to nine digits"));
            }
            frac = Some((i128::from(digits_value(&b[fs..pos])), 10i128.pow(k as u32)));
            saw_fraction = true;
        }
        if pos >= b.len() {
            return Err(err("missing duration unit letter"));
        }
        let unit = b[pos];
        pos += 1;
        any_component = true;
        let rank = if in_time {
            match unit {
                b'H' => {
                    seconds += csign * value * 3600;
                    if let Some((num, den)) = frac {
                        time_frac_ns += csign * (num * 3600 * nps / den);
                    }
                    1
                }
                b'M' => {
                    seconds += csign * value * 60;
                    if let Some((num, den)) = frac {
                        time_frac_ns += csign * (num * 60 * nps / den);
                    }
                    2
                }
                b'S' => {
                    seconds += csign * value;
                    if let Some((num, den)) = frac {
                        time_frac_ns += csign * (num * nps / den);
                    }
                    3
                }
                _ => return Err(err("unexpected unit in duration time part")),
            }
        } else {
            match unit {
                b'Y' => {
                    months += csign * value * 12;
                    if let Some((num, den)) = frac {
                        let twelfths = num * 12;
                        months += csign * (twelfths / den);
                        date_frac_ns += csign * ((twelfths % den) * AVG_NANOS_PER_MONTH / den);
                    }
                    1
                }
                b'M' => {
                    months += csign * value;
                    if let Some((num, den)) = frac {
                        date_frac_ns += csign * (num * AVG_NANOS_PER_MONTH / den);
                    }
                    2
                }
                b'W' => {
                    days += csign * value * 7;
                    if let Some((num, den)) = frac {
                        date_frac_ns += csign * (num * 7 * NANOS_PER_DAY_I128 / den);
                    }
                    3
                }
                b'D' => {
                    days += csign * value;
                    if let Some((num, den)) = frac {
                        date_frac_ns += csign * (num * NANOS_PER_DAY_I128 / den);
                    }
                    4
                }
                _ => return Err(err("unexpected unit in duration date part")),
            }
        };
        if rank <= last_rank {
            return Err(err("duration components out of order"));
        }
        last_rank = rank;
    }
    if !any_component {
        return Err(err("duration must have at least one component"));
    }
    // Fractions of date units (months, weeks, days) contribute whole days
    // first; the remainder joins the seconds group (`'P0.75M'` -> 22 days +
    // 19:51:49.5).
    days += date_frac_ns / NANOS_PER_DAY_I128;
    let mut total_ns = seconds * nps + time_frac_ns + date_frac_ns % NANOS_PER_DAY_I128;
    if overall_neg {
        months = -months;
        days = -days;
        total_ns = -total_ns;
    }
    let months = i64::try_from(months).map_err(|_| TemporalError::Overflow)?;
    let days = i64::try_from(days).map_err(|_| TemporalError::Overflow)?;
    Duration::from_month_day_total(months, days, total_ns)
}

/// Parses the `P<yyyy>-<mm>-<dd>T<hh>:<mm>:<ss[.fff]>` duration form
/// (`Temporal2.feature` scenario \[7\]: `'P2012-02-02T14:37:21.545'` equals
/// `'P2012Y2M2DT14H37M21.545S'`). The fields are duration *amounts*, not a
/// calendar date, so they are not range-validated.
fn parse_duration_datetime_form(
    s: &str,
    b: &[u8],
    mut pos: usize,
    overall_neg: bool,
) -> TemporalResult<Duration> {
    let err = |reason: &'static str| TemporalError::Parse {
        input: s.to_owned(),
        reason,
    };
    let expect = |b: &[u8], pos: &mut usize, c: u8, reason: &'static str| {
        if *pos < b.len() && b[*pos] == c {
            *pos += 1;
            Ok(())
        } else {
            Err(err(reason))
        }
    };
    let years =
        take_fixed_digits(b, &mut pos, 4).ok_or_else(|| err("expected four year digits"))?;
    expect(b, &mut pos, b'-', "expected '-' after years")?;
    let months =
        take_fixed_digits(b, &mut pos, 2).ok_or_else(|| err("expected two month digits"))?;
    expect(b, &mut pos, b'-', "expected '-' after months")?;
    let days = take_fixed_digits(b, &mut pos, 2).ok_or_else(|| err("expected two day digits"))?;
    expect(b, &mut pos, b'T', "expected 'T' after days")?;
    let hours = take_fixed_digits(b, &mut pos, 2).ok_or_else(|| err("expected two hour digits"))?;
    expect(b, &mut pos, b':', "expected ':' after hours")?;
    let minutes =
        take_fixed_digits(b, &mut pos, 2).ok_or_else(|| err("expected two minute digits"))?;
    expect(b, &mut pos, b':', "expected ':' after minutes")?;
    let secs =
        take_fixed_digits(b, &mut pos, 2).ok_or_else(|| err("expected two second digits"))?;
    let nanos = take_fraction_nanos(b, &mut pos).map_err(err)?;
    if pos != b.len() {
        return Err(err("trailing characters after duration"));
    }
    let sign: i64 = if overall_neg { -1 } else { 1 };
    Duration::from_components(
        sign * (i64::from(years) * 12 + i64::from(months)),
        sign * i64::from(days),
        sign * (i64::from(hours) * 3600 + i64::from(minutes) * 60 + i64::from(secs)),
        sign * i64::from(nanos),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn date(y: i64, m: u32, d: u32) -> Date {
        Date::from_ymd(y, m, d).expect("valid test date")
    }

    fn time(h: u32, mi: u32, s: u32, n: u32) -> LocalTime {
        LocalTime::from_hms_nanos(h, mi, s, n).expect("valid test time")
    }

    fn dur(months: i64, days: i64, seconds: i64, nanos: i64) -> Duration {
        Duration::from_components(months, days, seconds, nanos).expect("valid test duration")
    }

    // -- Civil calendar ----------------------------------------------------

    #[test]
    fn civil_anchors() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(11_017), (2000, 3, 1));
    }

    #[test]
    fn civil_round_trips_across_wide_range() {
        // ~4400 years around the epoch, every 13 days, including pre-1970 and
        // every leap-cycle alignment.
        let mut days = -800_000i64;
        while days <= 800_000 {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days, "round trip for day {days}");
            assert!((1..=12).contains(&m));
            assert!(d >= 1 && d <= days_in_month(y, m));
            days += 13;
        }
        // Consecutive days are consecutive dates around the leap day.
        let feb28 = days_from_civil(2000, 2, 28);
        assert_eq!(civil_from_days(feb28 + 1), (2000, 2, 29));
        assert_eq!(civil_from_days(feb28 + 2), (2000, 3, 1));
    }

    #[test]
    fn leap_year_rules() {
        assert!(is_leap_year(2000)); // divisible by 400
        assert!(!is_leap_year(1900)); // divisible by 100 only
        assert!(is_leap_year(1984));
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(2023));
        assert!(is_leap_year(0));
        assert!(!is_leap_year(-1)); // 2 BCE proleptic
        assert!(is_leap_year(-4));
    }

    #[test]
    fn days_in_month_table() {
        assert_eq!(days_in_month(2023, 1), 31);
        assert_eq!(days_in_month(2023, 2), 28);
        assert_eq!(days_in_month(2024, 2), 29);
        assert_eq!(days_in_month(2023, 4), 30);
        assert_eq!(days_in_month(2023, 12), 31);
        assert_eq!(days_in_month(2023, 0), 0);
        assert_eq!(days_in_month(2023, 13), 0);
    }

    // -- Construction and validation ----------------------------------------

    #[test]
    fn from_ymd_validates_components() {
        assert!(Date::from_ymd(2023, 2, 28).is_ok());
        assert_eq!(
            Date::from_ymd(2023, 2, 29),
            Err(TemporalError::InvalidComponent("day"))
        );
        assert_eq!(
            Date::from_ymd(2023, 0, 1),
            Err(TemporalError::InvalidComponent("month"))
        );
        assert_eq!(
            Date::from_ymd(2023, 13, 1),
            Err(TemporalError::InvalidComponent("month"))
        );
        assert_eq!(
            Date::from_ymd(2023, 1, 0),
            Err(TemporalError::InvalidComponent("day"))
        );
        assert_eq!(
            Date::from_ymd(99_000_000, 1, 1),
            Err(TemporalError::Overflow)
        );
    }

    #[test]
    fn from_hms_nanos_validates_components() {
        assert!(LocalTime::from_hms_nanos(23, 59, 59, 999_999_999).is_ok());
        assert_eq!(
            LocalTime::from_hms_nanos(24, 0, 0, 0),
            Err(TemporalError::InvalidComponent("hour"))
        );
        assert_eq!(
            LocalTime::from_hms_nanos(0, 60, 0, 0),
            Err(TemporalError::InvalidComponent("minute"))
        );
        assert_eq!(
            LocalTime::from_hms_nanos(0, 0, 60, 0),
            Err(TemporalError::InvalidComponent("second"))
        );
        assert_eq!(
            LocalTime::from_hms_nanos(0, 0, 0, 1_000_000_000),
            Err(TemporalError::InvalidComponent("nanosecond"))
        );
    }

    #[test]
    fn offset_bounds_are_enforced() {
        assert!(ZonedTime::new(time(0, 0, 0, 0), MAX_OFFSET_SECONDS).is_ok());
        assert!(ZonedTime::new(time(0, 0, 0, 0), -MAX_OFFSET_SECONDS).is_ok());
        assert_eq!(
            ZonedTime::new(time(0, 0, 0, 0), MAX_OFFSET_SECONDS + 1),
            Err(TemporalError::InvalidComponent("timezone offset"))
        );
    }

    // -- ISO week dates (Temporal1.feature scenario [1]) ---------------------

    #[test]
    fn iso_week_date_construction_matches_tck() {
        // (week_year, week, day_of_week) -> expected calendar date string.
        let rows: &[(i64, u32, u32, &str)] = &[
            (1816, 1, 1, "1816-01-01"),
            (1816, 52, 1, "1816-12-23"),
            (1817, 1, 1, "1816-12-30"),
            (1817, 10, 1, "1817-03-03"),
            (1817, 30, 1, "1817-07-21"),
            (1817, 52, 1, "1817-12-22"),
            (1818, 1, 1, "1817-12-29"),
            (1818, 52, 1, "1818-12-21"),
            (1818, 53, 1, "1818-12-28"),
            (1819, 1, 1, "1819-01-04"),
            (1819, 52, 1, "1819-12-27"),
            (1817, 1, 2, "1816-12-31"),
            (1984, 10, 3, "1984-03-07"),
            (1984, 10, 1, "1984-03-05"),
        ];
        for &(wy, week, dow, expected) in rows {
            let d = Date::from_year_week_day(wy, week, dow).expect("valid week date");
            assert_eq!(d.to_iso_string(), expected, "{wy}-W{week}-{dow}");
        }
    }

    #[test]
    fn iso_week_validation() {
        assert_eq!(weeks_in_iso_year(1818), 53);
        assert_eq!(weeks_in_iso_year(1819), 52);
        assert_eq!(weeks_in_iso_year(2015), 53);
        assert_eq!(weeks_in_iso_year(2004), 53);
        assert_eq!(weeks_in_iso_year(2023), 52);
        assert_eq!(
            Date::from_year_week_day(1819, 53, 1),
            Err(TemporalError::InvalidComponent("week"))
        );
        assert_eq!(
            Date::from_year_week_day(2015, 1, 0),
            Err(TemporalError::InvalidComponent("dayOfWeek"))
        );
        assert_eq!(
            Date::from_year_week_day(2015, 1, 8),
            Err(TemporalError::InvalidComponent("dayOfWeek"))
        );
        assert_eq!(
            Date::from_year_week_day(2015, 0, 1),
            Err(TemporalError::InvalidComponent("week"))
        );
    }

    #[test]
    fn ordinal_and_quarter_construction_matches_tck() {
        // Temporal1.feature scenario [4].
        assert_eq!(
            Date::from_year_ordinal(1984, 202).unwrap().to_iso_string(),
            "1984-07-20"
        );
        assert_eq!(
            Date::from_year_quarter_day(1984, 3, 45)
                .unwrap()
                .to_iso_string(),
            "1984-08-14"
        );
        assert_eq!(
            Date::from_year_quarter_day(1984, 3, 1)
                .unwrap()
                .to_iso_string(),
            "1984-07-01"
        );
        assert_eq!(
            Date::from_year_ordinal(1984, 367),
            Err(TemporalError::InvalidComponent("ordinalDay"))
        );
        assert!(Date::from_year_ordinal(1984, 366).is_ok()); // leap year
        assert_eq!(
            Date::from_year_ordinal(1983, 366),
            Err(TemporalError::InvalidComponent("ordinalDay"))
        );
        assert_eq!(
            Date::from_year_quarter_day(1984, 5, 1),
            Err(TemporalError::InvalidComponent("quarter"))
        );
        assert_eq!(
            Date::from_year_quarter_day(1984, 1, 92),
            Err(TemporalError::InvalidComponent("dayOfQuarter"))
        );
        assert!(Date::from_year_quarter_day(1984, 1, 91).is_ok()); // leap Q1
    }

    // -- Component accessors (Temporal5.feature) -----------------------------

    #[test]
    fn date_accessors_match_temporal5_scenario_1() {
        let d = date(1984, 10, 11);
        assert_eq!(d.year(), 1984);
        assert_eq!(d.quarter(), 4);
        assert_eq!(d.month(), 10);
        assert_eq!(d.week(), 41);
        assert_eq!(d.week_year(), 1984);
        assert_eq!(d.day(), 11);
        assert_eq!(d.ordinal_day(), 285);
        assert_eq!(d.week_day(), 4);
        assert_eq!(d.day_of_quarter(), 11);
    }

    #[test]
    fn date_accessors_match_temporal5_scenario_2_previous_week_year() {
        let d = date(1984, 1, 1);
        assert_eq!(d.year(), 1984);
        assert_eq!(d.week_year(), 1983);
        assert_eq!(d.week(), 52);
        assert_eq!(d.week_day(), 7);
    }

    #[test]
    fn local_time_accessors_match_temporal5_scenario_3() {
        let t = time(12, 31, 14, 645_876_123);
        assert_eq!(t.hour(), 12);
        assert_eq!(t.minute(), 31);
        assert_eq!(t.second(), 14);
        assert_eq!(t.millisecond(), 645);
        assert_eq!(t.microsecond(), 645_876);
        assert_eq!(t.nanosecond(), 645_876_123);
    }

    #[test]
    fn zoned_time_accessors_match_temporal5_scenario_4() {
        let t = ZonedTime::new(time(12, 31, 14, 645_876_123), 3600).unwrap();
        assert_eq!(t.hour(), 12);
        assert_eq!(t.minute(), 31);
        assert_eq!(t.second(), 14);
        assert_eq!(t.millisecond(), 645);
        assert_eq!(t.microsecond(), 645_876);
        assert_eq!(t.nanosecond(), 645_876_123);
        assert_eq!(t.timezone_name(), "+01:00");
        assert_eq!(t.offset_string(), "+01:00");
        assert_eq!(t.offset_minutes(), 60);
        assert_eq!(t.offset_seconds, 3600);
    }

    #[test]
    fn local_date_time_accessors_match_temporal5_scenario_5() {
        let ldt = LocalDateTime::from_date_time(date(1984, 11, 11), time(12, 31, 14, 645_876_123));
        assert_eq!(ldt.year(), 1984);
        assert_eq!(ldt.quarter(), 4);
        assert_eq!(ldt.month(), 11);
        assert_eq!(ldt.week(), 45);
        assert_eq!(ldt.week_year(), 1984);
        assert_eq!(ldt.day(), 11);
        assert_eq!(ldt.ordinal_day(), 316);
        assert_eq!(ldt.week_day(), 7);
        assert_eq!(ldt.day_of_quarter(), 42);
        assert_eq!(ldt.hour(), 12);
        assert_eq!(ldt.minute(), 31);
        assert_eq!(ldt.second(), 14);
        assert_eq!(ldt.millisecond(), 645);
        assert_eq!(ldt.microsecond(), 645_876);
        assert_eq!(ldt.nanosecond(), 645_876_123);
    }

    #[test]
    fn zoned_date_time_accessors_match_temporal5_scenario_6() {
        let local =
            LocalDateTime::from_date_time(date(1984, 11, 11), time(12, 31, 14, 645_876_123));
        let zdt = ZonedDateTime::from_local(local, 3600, "Europe/Stockholm").unwrap();
        assert_eq!(zdt.year(), 1984);
        assert_eq!(zdt.quarter(), 4);
        assert_eq!(zdt.month(), 11);
        assert_eq!(zdt.week(), 45);
        assert_eq!(zdt.week_year(), 1984);
        assert_eq!(zdt.day(), 11);
        assert_eq!(zdt.ordinal_day(), 316);
        assert_eq!(zdt.week_day(), 7);
        assert_eq!(zdt.day_of_quarter(), 42);
        assert_eq!(zdt.hour(), 12);
        assert_eq!(zdt.minute(), 31);
        assert_eq!(zdt.second(), 14);
        assert_eq!(zdt.millisecond(), 645);
        assert_eq!(zdt.microsecond(), 645_876);
        assert_eq!(zdt.nanosecond(), 645_876_123);
        assert_eq!(zdt.timezone_name(), "Europe/Stockholm");
        assert_eq!(zdt.offset_string(), "+01:00");
        assert_eq!(zdt.offset_minutes(), 60);
        assert_eq!(zdt.offset_seconds, 3600);
        assert_eq!(zdt.epoch_seconds(), 469_020_674);
        assert_eq!(zdt.epoch_millis(), 469_020_674_645);
    }

    #[test]
    fn duration_accessors_match_temporal5_scenario_7() {
        // duration({years: 1, months: 4, days: 10, hours: 1, minutes: 1,
        //           seconds: 1, nanoseconds: 111111111})
        let d = dur(16, 10, 3661, 111_111_111);
        assert_eq!(d.years(), 1);
        assert_eq!(d.quarters(), 5);
        assert_eq!(d.months_total(), 16);
        assert_eq!(d.weeks(), 1);
        assert_eq!(d.days_total(), 10);
        assert_eq!(d.hours(), 1);
        assert_eq!(d.minutes(), 61);
        assert_eq!(d.seconds_total(), 3661);
        assert_eq!(d.milliseconds(), 3_661_111);
        assert_eq!(d.microseconds(), 3_661_111_111);
        assert_eq!(d.nanoseconds(), 3_661_111_111_111);
        assert_eq!(d.quarters_of_year(), 1);
        assert_eq!(d.months_of_quarter(), 1);
        assert_eq!(d.months_of_year(), 4);
        assert_eq!(d.days_of_week(), 3);
        assert_eq!(d.minutes_of_hour(), 1);
        assert_eq!(d.seconds_of_minute(), 1);
        assert_eq!(d.milliseconds_of_second(), 111);
        assert_eq!(d.microseconds_of_second(), 111_111);
        assert_eq!(d.nanoseconds_of_second(), 111_111_111);
    }

    // -- Formatting ----------------------------------------------------------

    #[test]
    fn local_time_formats_match_temporal1_scenario_5() {
        let rows: &[(LocalTime, &str)] = &[
            (time(12, 31, 14, 123_456_789), "12:31:14.123456789"),
            (time(12, 31, 14, 645_876_123), "12:31:14.645876123"),
            (time(12, 31, 14, 645_876_000), "12:31:14.645876"),
            (time(12, 31, 14, 645_000_000), "12:31:14.645"),
            (time(12, 31, 14, 3), "12:31:14.000000003"),
            (time(12, 31, 14, 0), "12:31:14"),
            (time(12, 31, 0, 0), "12:31"),
            (time(12, 0, 0, 0), "12:00"),
            (time(0, 0, 0, 0), "00:00"),
            (time(0, 0, 0, 2), "00:00:00.000000002"),
        ];
        for (t, expected) in rows {
            assert_eq!(t.to_iso_string(), *expected);
        }
    }

    #[test]
    fn zoned_time_formats_match_tck() {
        // Temporal1 scenario [6] and Temporal4 scenario [5].
        let plus1 = |t: LocalTime| ZonedTime::new(t, 3600).unwrap();
        assert_eq!(
            plus1(time(12, 31, 14, 645_876_123)).to_iso_string(),
            "12:31:14.645876123+01:00"
        );
        assert_eq!(plus1(time(12, 31, 0, 0)).to_iso_string(), "12:31+01:00");
        assert_eq!(
            ZonedTime::new(time(12, 0, 0, 0), 0)
                .unwrap()
                .to_iso_string(),
            "12:00Z"
        );
        // Temporal1 scenario [13]: second-precision offsets.
        assert_eq!(
            ZonedTime::new(time(12, 34, 56, 0), 2 * 3600 + 5 * 60)
                .unwrap()
                .to_iso_string(),
            "12:34:56+02:05"
        );
        assert_eq!(
            ZonedTime::new(time(12, 34, 56, 0), 2 * 3600 + 5 * 60 + 59)
                .unwrap()
                .to_iso_string(),
            "12:34:56+02:05:59"
        );
        assert_eq!(
            ZonedTime::new(time(12, 34, 56, 0), -(2 * 3600 + 5 * 60 + 7))
                .unwrap()
                .to_iso_string(),
            "12:34:56-02:05:07"
        );
    }

    #[test]
    fn date_and_datetime_formats_match_tck() {
        assert_eq!(date(1984, 10, 11).to_iso_string(), "1984-10-11");
        assert_eq!(date(1, 1, 1).to_iso_string(), "0001-01-01");
        assert_eq!(date(0, 1, 1).to_iso_string(), "0000-01-01");
        assert_eq!(date(-100, 12, 31).to_iso_string(), "-0100-12-31");
        assert_eq!(date(10_000, 1, 1).to_iso_string(), "+10000-01-01");
        let ldt = LocalDateTime::from_date_time(date(1984, 10, 11), time(12, 31, 14, 645_000_000));
        assert_eq!(ldt.to_iso_string(), "1984-10-11T12:31:14.645");
        let midnight = LocalDateTime::from_date_time(date(1984, 10, 11), time(0, 0, 0, 0));
        assert_eq!(midnight.to_iso_string(), "1984-10-11T00:00");
        let zdt = ZonedDateTime::from_parts(
            date(1984, 10, 11),
            time(12, 31, 14, 645_000_000),
            3600,
            "Europe/Stockholm",
        )
        .unwrap();
        assert_eq!(
            zdt.to_iso_string(),
            "1984-10-11T12:31:14.645+01:00[Europe/Stockholm]"
        );
        let utc = ZonedDateTime::from_parts(date(1912, 1, 1), time(0, 0, 0, 0), 0, "").unwrap();
        assert_eq!(utc.to_iso_string(), "1912-01-01T00:00Z");
        assert_eq!(utc.timezone_name(), "Z");
        // 1818 Stockholm local mean time: +00:53:28 = 3208 s (Temporal2
        // scenario [6]).
        let lmt = ZonedDateTime::from_parts(
            date(1818, 7, 21),
            time(21, 40, 32, 142_000_000),
            3208,
            "Europe/Stockholm",
        )
        .unwrap();
        assert_eq!(
            lmt.to_iso_string(),
            "1818-07-21T21:40:32.142+00:53:28[Europe/Stockholm]"
        );
    }

    #[test]
    fn epoch_constructions_match_temporal1_scenario_11() {
        // datetime.fromepoch(416779, 999999999)
        let d1 = LocalDateTime {
            epoch_seconds: 416_779,
            nanos: 999_999_999,
        };
        assert_eq!(d1.to_iso_string(), "1970-01-05T19:46:19.999999999");
        // datetime.fromepochmillis(237821673987)
        let d2 = LocalDateTime {
            epoch_seconds: 237_821_673,
            nanos: 987_000_000,
        };
        assert_eq!(d2.to_iso_string(), "1977-07-15T13:34:33.987");
        assert_eq!(d2.epoch_millis(), 237_821_673_987);
    }

    #[test]
    fn local_date_time_round_trips_pre_epoch() {
        let cases = [
            (date(1816, 1, 1), time(0, 0, 0, 0)),
            (date(1969, 12, 31), time(23, 59, 59, 500_000_000)),
            (date(1970, 1, 1), time(0, 0, 0, 1)),
            (date(-44, 3, 15), time(12, 0, 0, 0)),
            (date(2024, 2, 29), time(23, 59, 59, 999_999_999)),
        ];
        for (d, t) in cases {
            let ldt = LocalDateTime::from_date_time(d, t);
            let (d2, t2) = ldt.to_date_time();
            assert_eq!((d2, t2), (d, t), "round trip for {}", ldt.to_iso_string());
        }
        let before_epoch = LocalDateTime {
            epoch_seconds: -1,
            nanos: 0,
        };
        assert_eq!(before_epoch.to_iso_string(), "1969-12-31T23:59:59");
    }

    // -- Parsing (Temporal2.feature) -----------------------------------------

    #[test]
    fn parse_date_matches_temporal2_scenario_1() {
        let rows: &[(&str, &str)] = &[
            ("2015-07-21", "2015-07-21"),
            ("20150721", "2015-07-21"),
            ("2015-07", "2015-07-01"),
            ("201507", "2015-07-01"),
            ("2015-W30-2", "2015-07-21"),
            ("2015W302", "2015-07-21"),
            ("2015-W30", "2015-07-20"),
            ("2015W30", "2015-07-20"),
            ("2015-202", "2015-07-21"),
            ("2015202", "2015-07-21"),
            ("2015", "2015-01-01"),
            // Quarter dates (Neo4j-compatible extension of the TCK set).
            ("2015-Q2-60", "2015-05-30"),
            ("2015Q260", "2015-05-30"),
            ("2015-Q2", "2015-04-01"),
            ("2015Q2", "2015-04-01"),
            // Signed years.
            ("-0100-12-31", "-0100-12-31"),
            ("+10000-01-01", "+10000-01-01"),
        ];
        for (input, expected) in rows {
            let d = parse_date(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(d.to_iso_string(), *expected, "input {input:?}");
        }
    }

    #[test]
    fn parse_local_time_matches_temporal2_scenario_2() {
        let rows: &[(&str, &str)] = &[
            ("21:40:32.142", "21:40:32.142"),
            ("214032.142", "21:40:32.142"),
            ("21:40:32", "21:40:32"),
            ("214032", "21:40:32"),
            ("21:40", "21:40"),
            ("2140", "21:40"),
            ("21", "21:00"),
        ];
        for (input, expected) in rows {
            let t = parse_local_time(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(t.to_iso_string(), *expected, "input {input:?}");
        }
    }

    #[test]
    fn parse_zoned_time_matches_temporal2_scenario_3() {
        let rows: &[(&str, &str)] = &[
            ("21:40:32.142+0100", "21:40:32.142+01:00"),
            ("214032.142Z", "21:40:32.142Z"),
            ("21:40:32+01:00", "21:40:32+01:00"),
            ("214032-0100", "21:40:32-01:00"),
            ("21:40-01:30", "21:40-01:30"),
            ("2140-00:00", "21:40Z"),
            ("2140-02", "21:40-02:00"),
            ("22+18:00", "22:00+18:00"),
        ];
        for (input, expected) in rows {
            let t = parse_zoned_time(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(t.to_iso_string(), *expected, "input {input:?}");
        }
    }

    #[test]
    fn parse_local_date_time_matches_temporal2_scenario_4() {
        let rows: &[(&str, &str)] = &[
            ("2015-07-21T21:40:32.142", "2015-07-21T21:40:32.142"),
            ("2015-W30-2T214032.142", "2015-07-21T21:40:32.142"),
            ("2015-202T21:40:32", "2015-07-21T21:40:32"),
            ("2015T214032", "2015-01-01T21:40:32"),
            ("20150721T21:40", "2015-07-21T21:40"),
            ("2015-W30T2140", "2015-07-20T21:40"),
            ("2015202T21", "2015-07-21T21:00"),
        ];
        for (input, expected) in rows {
            let ldt = parse_local_date_time(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(ldt.to_iso_string(), *expected, "input {input:?}");
        }
    }

    #[test]
    fn parse_zoned_date_time_matches_temporal2_scenario_5() {
        let rows: &[(&str, &str)] = &[
            (
                "2015-07-21T21:40:32.142+0100",
                "2015-07-21T21:40:32.142+01:00",
            ),
            ("2015-W30-2T214032.142Z", "2015-07-21T21:40:32.142Z"),
            ("2015-202T21:40:32+01:00", "2015-07-21T21:40:32+01:00"),
            ("2015T214032-0100", "2015-01-01T21:40:32-01:00"),
            ("20150721T21:40-01:30", "2015-07-21T21:40-01:30"),
            ("2015-W30T2140-00:00", "2015-07-20T21:40Z"),
            ("2015-W30T2140-02", "2015-07-20T21:40-02:00"),
            ("2015202T21+18:00", "2015-07-21T21:00+18:00"),
        ];
        for (input, expected) in rows {
            let zdt = parse_zoned_date_time(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(zdt.to_iso_string(), *expected, "input {input:?}");
        }
    }

    #[test]
    fn parse_zoned_date_time_with_named_zone_matches_temporal2_scenario_6() {
        // Rows with an explicit offset resolve fully.
        let rows: &[(&str, &str)] = &[
            (
                "2015-07-21T21:40:32.142+02:00[Europe/Stockholm]",
                "2015-07-21T21:40:32.142+02:00[Europe/Stockholm]",
            ),
            (
                "2015-07-21T21:40:32.142+0845[Australia/Eucla]",
                "2015-07-21T21:40:32.142+08:45[Australia/Eucla]",
            ),
            (
                "2015-07-21T21:40:32.142-04[America/New_York]",
                "2015-07-21T21:40:32.142-04:00[America/New_York]",
            ),
        ];
        for (input, expected) in rows {
            let zdt = parse_zoned_date_time(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(zdt.to_iso_string(), *expected, "input {input:?}");
        }
        // A named zone without an offset surfaces its unresolved parts.
        let (local, offset, zone) =
            parse_zoned_date_time_parts("2015-07-21T21:40:32.142[Europe/London]").unwrap();
        assert_eq!(local.to_iso_string(), "2015-07-21T21:40:32.142");
        assert_eq!(offset, None);
        assert_eq!(zone.as_deref(), Some("Europe/London"));
        assert!(matches!(
            parse_zoned_date_time("2015-07-21T21:40:32.142[Europe/London]"),
            Err(TemporalError::Parse { .. })
        ));
    }

    #[test]
    fn parse_duration_matches_temporal2_scenario_7() {
        let rows: &[(&str, &str)] = &[
            ("P14DT16H12M", "P14DT16H12M"),
            ("P5M1.5D", "P5M1DT12H"),
            ("P0.75M", "P22DT19H51M49.5S"),
            ("PT0.75M", "PT45S"),
            ("P2.5W", "P17DT12H"),
            ("P12Y5M14DT16H12M70S", "P12Y5M14DT16H13M10S"),
            ("P2012-02-02T14:37:21.545", "P2012Y2M2DT14H37M21.545S"),
        ];
        for (input, expected) in rows {
            let d = parse_duration(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(d.to_iso_string(), *expected, "input {input:?}");
        }
    }

    #[test]
    fn parse_duration_round_trips_formatter_output() {
        // Every formatter shape must parse back to the same components
        // (Temporal6.feature scenario [6] asserts toString/parse round trips).
        let durations = [
            dur(149, 14, 58_390, 1),
            dur(149, -14, 57_600, 0),
            dur(0, 0, 660, 0),
            dur(0, 0, 2, -1_000_000),
            dur(0, 0, -2, 1_000_000),
            dur(0, 0, -2, -1_000_000),
            dur(0, 1, 0, 1_000_000),
            dur(0, 1, 0, -1_000_000),
            dur(0, 0, -60, -1_000_000),
            dur(0, 0, 0, 0),
            dur(-6, -15, -63_903, -500_000_002),
        ];
        for d in durations {
            let s = d.to_iso_string();
            let parsed = parse_duration(&s).unwrap_or_else(|e| panic!("{s}: {e}"));
            assert_eq!(parsed, d, "round trip through {s:?}");
        }
    }

    #[test]
    fn parse_rejects_malformed_and_out_of_range_input() {
        // Dates.
        assert!(parse_date("2015-13-01").is_err());
        assert!(parse_date("2015-00-10").is_err());
        assert!(parse_date("2015-02-30").is_err());
        assert!(parse_date("2015-W54-1").is_err());
        assert!(parse_date("2015-1-1").is_err());
        assert!(parse_date("215").is_err());
        assert!(parse_date("abcd").is_err());
        assert!(parse_date("2015-07-21x").is_err());
        // Times.
        assert!(parse_local_time("24:00").is_err());
        assert!(parse_local_time("12:60").is_err());
        assert!(parse_local_time("12:31:60").is_err());
        assert!(parse_local_time("1").is_err());
        assert!(parse_local_time("12:3").is_err());
        assert!(parse_local_time("12:30.5").is_err());
        assert!(parse_local_time("12:30:14.1234567890").is_err());
        // Offsets.
        assert!(parse_zoned_time("12:00+19:00").is_err());
        assert!(parse_zoned_time("12:00+01:60").is_err());
        assert!(parse_zoned_time("12:00").is_err());
        // Date-times.
        assert!(parse_local_date_time("2015-07-21").is_err());
        assert!(parse_local_date_time("2015-07-21T25:00").is_err());
        assert!(parse_zoned_date_time("2015-07-21T12:00+02:00[]").is_err());
        // Durations.
        assert!(parse_duration("P").is_err());
        assert!(parse_duration("PT").is_err());
        assert!(parse_duration("P1S").is_err());
        assert!(parse_duration("PT1Y").is_err());
        assert!(parse_duration("P1.5Y2M").is_err());
        assert!(parse_duration("P1Y1Y").is_err());
        assert!(parse_duration("PT1M1H").is_err());
        assert!(parse_duration("P1X").is_err());
        assert!(parse_duration("1Y").is_err());
        assert!(parse_duration("P1.S").is_err());
    }

    // -- Duration formatting (Temporal6.feature scenario [6]) ----------------

    #[test]
    fn duration_formats_match_temporal6_scenario_6() {
        let rows: &[(Duration, &str)] = &[
            (dur(149, 14, 58_390, 1), "P12Y5M14DT16H13M10.000000001S"),
            (dur(149, -14, 57_600, 0), "P12Y5M-14DT16H"),
            (dur(0, 0, 720 - 60, 0), "PT11M"),
            (dur(0, 0, 2, -1_000_000), "PT1.999S"),
            (dur(0, 0, -2, 1_000_000), "PT-1.999S"),
            (dur(0, 0, -2, -1_000_000), "PT-2.001S"),
            (dur(0, 1, 0, 1_000_000), "P1DT0.001S"),
            (dur(0, 1, 0, -1_000_000), "P1DT-0.001S"),
            (dur(0, 0, 60, -1_000_000), "PT59.999S"),
            (dur(0, 0, -60, 1_000_000), "PT-59.999S"),
            (dur(0, 0, -60, -1_000_000), "PT-1M-0.001S"),
            (dur(0, 0, 0, 0), "PT0S"),
            (dur(0, 0, 12, 0), "PT12S"),
        ];
        for (d, expected) in rows {
            assert_eq!(d.to_iso_string(), *expected);
        }
    }

    #[test]
    fn duration_normalisation_shares_sign_between_seconds_and_nanos() {
        let d = dur(0, 0, 2, -1_000_000);
        assert_eq!((d.seconds, d.nanos), (1, 999_000_000));
        let d = dur(0, 0, -2, 1_000_000);
        assert_eq!((d.seconds, d.nanos), (-1, -999_000_000));
        let d = dur(0, 0, 0, 2_500_000_000);
        assert_eq!((d.seconds, d.nanos), (2, 500_000_000));
        let d = dur(0, 0, 0, -2_500_000_000);
        assert_eq!((d.seconds, d.nanos), (-2, -500_000_000));
    }

    // -- Duration arithmetic (Temporal8.feature scenarios [6] and [7]) -------

    /// `duration({years: 12, months: 5, days: 14, hours: 16, minutes: 12,
    /// seconds: 70, nanoseconds: 1})` (Temporal8 scenarios \[6\]/\[7\]).
    fn d1() -> Duration {
        dur(149, 14, 58_390, 1)
    }

    /// Same map but with `nanoseconds: 2`, as used by Temporal8 scenarios
    /// \[1\]-\[5\].
    fn d1_arith() -> Duration {
        dur(149, 14, 58_390, 2)
    }

    /// `duration({months: 1, days: -14, hours: 16, minutes: -12, seconds: 70})`.
    fn d2() -> Duration {
        dur(1, -14, 56_950, 0)
    }

    /// `duration({years: 12.5, months: 5.5, days: 14.5, hours: 16.5,
    /// minutes: 12.5, seconds: 70.5, nanoseconds: 3})` after Neo4j's
    /// fractional cascade.
    fn d3() -> Duration {
        dur(155, 29, 122_293, 500_000_003)
    }

    #[test]
    fn fractional_map_components_cascade_like_neo4j() {
        // d3 above, derived through the approximate cascade.
        let d = Duration::approximate(
            12.5 * 12.0 + 5.5,
            14.5,
            16.5 * 3600.0 + 12.5 * 60.0 + 70.5,
            3.0,
        )
        .unwrap();
        assert_eq!(d, d3());
    }

    #[test]
    fn duration_add_sub_match_temporal8_scenario_6() {
        let rows: &[(Duration, Duration, &str, &str)] = &[
            (d1(), d1(), "P24Y10M28DT32H26M20.000000002S", "PT0S"),
            (
                d1(),
                d2(),
                "P12Y6MT32H2M20.000000001S",
                "P12Y4M28DT24M0.000000001S",
            ),
            (
                d1(),
                d3(),
                "P25Y4M43DT50H11M23.500000004S",
                "P-6M-15DT-17H-45M-3.500000002S",
            ),
            (
                d2(),
                d1(),
                "P12Y6MT32H2M20.000000001S",
                "P-12Y-4M-28DT-24M-0.000000001S",
            ),
            (d2(), d2(), "P2M-28DT31H38M20S", "PT0S"),
            (
                d2(),
                d3(),
                "P13Y15DT49H47M23.500000003S",
                "P-12Y-10M-43DT-18H-9M-3.500000003S",
            ),
            (
                d3(),
                d1(),
                "P25Y4M43DT50H11M23.500000004S",
                "P6M15DT17H45M3.500000002S",
            ),
            (
                d3(),
                d2(),
                "P13Y15DT49H47M23.500000003S",
                "P12Y10M43DT18H9M3.500000003S",
            ),
            (d3(), d3(), "P25Y10M58DT67H56M27.000000006S", "PT0S"),
        ];
        for (a, b, sum, diff) in rows {
            assert_eq!(a.add(b).unwrap().to_iso_string(), *sum);
            assert_eq!(a.sub(b).unwrap().to_iso_string(), *diff);
        }
    }

    #[test]
    fn duration_scaling_matches_temporal8_scenario_7() {
        let d = d1();
        assert_eq!(
            d.mul_int(1).unwrap().to_iso_string(),
            "P12Y5M14DT16H13M10.000000001S"
        );
        assert_eq!(
            d.mul_int(2).unwrap().to_iso_string(),
            "P24Y10M28DT32H26M20.000000002S"
        );
        assert_eq!(
            d.mul_scalar(1.0).unwrap().to_iso_string(),
            "P12Y5M14DT16H13M10.000000001S"
        );
        assert_eq!(
            d.mul_scalar(2.0).unwrap().to_iso_string(),
            "P24Y10M28DT32H26M20.000000002S"
        );
        assert_eq!(
            d.mul_scalar(0.5).unwrap().to_iso_string(),
            "P6Y2M22DT13H21M8S"
        );
        assert_eq!(
            d.div_scalar(1.0).unwrap().to_iso_string(),
            "P12Y5M14DT16H13M10.000000001S"
        );
        assert_eq!(
            d.div_scalar(2.0).unwrap().to_iso_string(),
            "P6Y2M22DT13H21M8S"
        );
        assert_eq!(
            d.div_scalar(0.5).unwrap().to_iso_string(),
            "P24Y10M28DT32H26M20.000000002S"
        );
        assert_eq!(d.div_scalar(0.0), Err(TemporalError::Overflow));
        assert_eq!(d.mul_scalar(f64::NAN), Err(TemporalError::Overflow));
        assert_eq!(d.mul_scalar(f64::INFINITY), Err(TemporalError::Overflow));
    }

    #[test]
    fn duration_overflow_is_reported() {
        let max = dur(i64::MAX, 0, 0, 0);
        assert_eq!(max.add(&dur(1, 0, 0, 0)), Err(TemporalError::Overflow));
        assert_eq!(max.mul_int(2), Err(TemporalError::Overflow));
        let max_secs = dur(0, 0, i64::MAX, 0);
        assert_eq!(
            max_secs.add(&dur(0, 0, 0, 1_000_000_000)),
            Err(TemporalError::Overflow)
        );
    }

    // -- Temporal +/- duration (Temporal8.feature scenarios [1]-[5]) ---------

    #[test]
    fn date_plus_minus_duration_matches_temporal8_scenario_1() {
        let x = date(1984, 10, 11);
        let rows: &[(Duration, &str, &str)] = &[
            (d1_arith(), "1997-03-25", "1972-04-27"),
            (d2(), "1984-10-28", "1984-09-25"),
            (d3(), "1997-10-11", "1971-10-12"),
        ];
        for (d, sum, diff) in rows {
            assert_eq!(x.add_duration(d).unwrap().to_iso_string(), *sum);
            assert_eq!(x.sub_duration(d).unwrap().to_iso_string(), *diff);
        }
    }

    #[test]
    fn local_time_plus_minus_duration_matches_temporal8_scenario_2() {
        let x = time(12, 31, 14, 1);
        let rows: &[(Duration, &str, &str)] = &[
            (d1_arith(), "04:44:24.000000003", "20:18:03.999999999"),
            (d2(), "04:20:24.000000001", "20:42:04.000000001"),
            (d3(), "22:29:27.500000004", "02:33:00.499999998"),
        ];
        for (d, sum, diff) in rows {
            assert_eq!(x.add_duration(d).to_iso_string(), *sum);
            assert_eq!(x.sub_duration(d).to_iso_string(), *diff);
        }
    }

    #[test]
    fn zoned_time_plus_minus_duration_matches_temporal8_scenario_3() {
        let x = ZonedTime::new(time(12, 31, 14, 1), 3600).unwrap();
        let rows: &[(Duration, &str, &str)] = &[
            (
                d1_arith(),
                "04:44:24.000000003+01:00",
                "20:18:03.999999999+01:00",
            ),
            (d2(), "04:20:24.000000001+01:00", "20:42:04.000000001+01:00"),
            (d3(), "22:29:27.500000004+01:00", "02:33:00.499999998+01:00"),
        ];
        for (d, sum, diff) in rows {
            assert_eq!(x.add_duration(d).to_iso_string(), *sum);
            assert_eq!(x.sub_duration(d).to_iso_string(), *diff);
        }
    }

    #[test]
    fn local_date_time_plus_minus_duration_matches_temporal8_scenario_4() {
        let x = LocalDateTime::from_date_time(date(1984, 10, 11), time(12, 31, 14, 1));
        let rows: &[(Duration, &str, &str)] = &[
            (
                d1_arith(),
                "1997-03-26T04:44:24.000000003",
                "1972-04-26T20:18:03.999999999",
            ),
            (
                d2(),
                "1984-10-29T04:20:24.000000001",
                "1984-09-24T20:42:04.000000001",
            ),
            (
                d3(),
                "1997-10-11T22:29:27.500000004",
                "1971-10-12T02:33:00.499999998",
            ),
        ];
        for (d, sum, diff) in rows {
            assert_eq!(x.add_duration(d).unwrap().to_iso_string(), *sum);
            assert_eq!(x.sub_duration(d).unwrap().to_iso_string(), *diff);
        }
    }

    #[test]
    fn zoned_date_time_plus_minus_duration_matches_temporal8_scenario_5() {
        let x =
            ZonedDateTime::from_parts(date(1984, 10, 11), time(12, 31, 14, 1), 3600, "").unwrap();
        let rows: &[(Duration, &str, &str)] = &[
            (
                d1_arith(),
                "1997-03-26T04:44:24.000000003+01:00",
                "1972-04-26T20:18:03.999999999+01:00",
            ),
            (
                d2(),
                "1984-10-29T04:20:24.000000001+01:00",
                "1984-09-24T20:42:04.000000001+01:00",
            ),
            (
                d3(),
                "1997-10-11T22:29:27.500000004+01:00",
                "1971-10-12T02:33:00.499999998+01:00",
            ),
        ];
        for (d, sum, diff) in rows {
            assert_eq!(x.add_duration(d).unwrap().to_iso_string(), *sum);
            assert_eq!(x.sub_duration(d).unwrap().to_iso_string(), *diff);
        }
    }

    #[test]
    fn month_arithmetic_clamps_day_of_month() {
        let one_month = dur(1, 0, 0, 0);
        assert_eq!(
            date(1984, 1, 31)
                .add_duration(&one_month)
                .unwrap()
                .to_iso_string(),
            "1984-02-29" // leap year
        );
        assert_eq!(
            date(1983, 1, 31)
                .add_duration(&one_month)
                .unwrap()
                .to_iso_string(),
            "1983-02-28"
        );
        assert_eq!(
            date(2024, 3, 31)
                .sub_duration(&one_month)
                .unwrap()
                .to_iso_string(),
            "2024-02-29"
        );
        assert_eq!(
            date(2024, 10, 31)
                .add_duration(&one_month)
                .unwrap()
                .to_iso_string(),
            "2024-11-30"
        );
        // Clamping happens after the month shift only; explicit days then add.
        let month_and_day = dur(1, 1, 0, 0);
        assert_eq!(
            date(1983, 1, 31)
                .add_duration(&month_and_day)
                .unwrap()
                .to_iso_string(),
            "1983-03-01"
        );
        // Crossing a year boundary backwards.
        assert_eq!(
            date(1984, 1, 15)
                .sub_duration(&dur(13, 0, 0, 0))
                .unwrap()
                .to_iso_string(),
            "1982-12-15"
        );
    }

    #[test]
    fn date_arithmetic_overflow_is_reported() {
        let max_date = Date {
            days_since_epoch: i32::MAX,
        };
        assert_eq!(
            max_date.add_duration(&dur(0, 1, 0, 0)),
            Err(TemporalError::Overflow)
        );
        let min_date = Date {
            days_since_epoch: i32::MIN,
        };
        assert_eq!(
            min_date.sub_duration(&dur(0, 1, 0, 0)),
            Err(TemporalError::Overflow)
        );
    }

    #[test]
    fn display_impls_delegate_to_iso_strings() {
        assert_eq!(date(1984, 10, 11).to_string(), "1984-10-11");
        assert_eq!(time(12, 0, 0, 0).to_string(), "12:00");
        assert_eq!(
            ZonedTime::new(time(12, 0, 0, 0), 0).unwrap().to_string(),
            "12:00Z"
        );
        assert_eq!(
            LocalDateTime::from_date_time(date(1912, 1, 1), time(0, 0, 0, 0)).to_string(),
            "1912-01-01T00:00"
        );
        assert_eq!(dur(0, 0, 12, 0).to_string(), "PT12S");
    }

    #[test]
    fn error_display_is_descriptive() {
        assert_eq!(
            TemporalError::InvalidComponent("month").to_string(),
            "invalid temporal component: month"
        );
        assert!(
            parse_date("nope")
                .unwrap_err()
                .to_string()
                .contains("\"nope\"")
        );
        assert_eq!(
            TemporalError::Overflow.to_string(),
            "temporal value out of representable range"
        );
    }
}
