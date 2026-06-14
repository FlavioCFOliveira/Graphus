//! The Cypher **temporal function surface** (rmp #53): constructors, component access,
//! and arithmetic over the temporal value family (`04-technical-design.md` §7.2; openCypher
//! temporal CIP).
//!
//! The calendar/clock mathematics live in [`graphus_core::temporal_calc`] (parsing, formatting,
//! civil-calendar conversions, duration arithmetic — all pinned to the TCK's expected strings).
//! This module adapts that engine to the evaluator's [`Value`] world:
//!
//! - [`construct`] implements the `date()` / `localtime()` / `time()` / `localdatetime()` /
//!   `datetime()` / `duration()` constructors over a string, a component map, or another temporal
//!   value (projection/truncation).
//! - [`component`] implements property-style component access (`d.year`, `t.hour`,
//!   `dur.minutesOfHour`, …).
//! - [`add`] / [`sub`] / [`mul`] / [`div`] implement the temporal arithmetic the binary operators
//!   delegate to (`temporal ± duration`, `duration ± duration`, `duration */ number`).
//! - [`to_iso`] renders a temporal value to its canonical ISO-8601 string (`toString`, results).
//!
//! IANA zone ids (`timezone: 'Europe/Stockholm'`, `'...[Europe/London]'`) are resolved against
//! the embedded tz database in [`crate::timezone`] (`rmp` task #60): a named zone resolves the
//! UTC offset in effect for the constructed *local* value (historical rules and DST, with the
//! gap/overlap disambiguation documented there), a zone conversion preserves the instant and
//! re-derives the local fields, and an id absent from the database is a typed
//! [`EvalError::TypeError`].
//!
//! # Current-instant forms (the statement clock seam, `rmp` task #140)
//!
//! The zero-argument "current instant" constructor forms (`date()`, `time()`, `datetime()`,
//! `localtime()`, `localdatetime()`, and their `.transaction` / `.statement` / `.realtime`
//! variants) read from the [`StatementClock`](crate::statement_clock::StatementClock) threaded in
//! by the evaluator. The `statement` (and bare, default) granularity is the instant captured once
//! when the cursor opened, so every current-instant call within one statement observes the **same**
//! instant (the TCK `PT0S` property). `duration()` has no current-instant form and still raises a
//! typed [`EvalError::UnsupportedFunction`] when called with no argument.

use graphus_core::Value;
use graphus_core::temporal_calc::{self as tc, TemporalError};
use graphus_core::value::temporal::{
    Date, Duration, LocalDateTime, LocalTime, NANOS_PER_DAY, ZonedDateTime, ZonedTime,
};

use crate::eval::EvalError;
use crate::statement_clock::StatementClock;
use crate::timezone;

/// Adapts a calendar-engine error to the evaluator's runtime error class.
fn terr(e: TemporalError) -> EvalError {
    EvalError::TypeError {
        context: e.to_string(),
    }
}

fn type_err(context: impl Into<String>) -> EvalError {
    EvalError::TypeError {
        context: context.into(),
    }
}

// =================================================================================================
// Constructors
// =================================================================================================

/// Dispatches a temporal constructor by (lower-cased) name. `None` argument is the
/// "current instant" form, read from the statement clock.
///
/// Accepts both the bare constructors (`date`, `localtime`, `time`, `localdatetime`, `datetime`,
/// `duration`) and their **clock variants** (`date.transaction`, `localtime.statement`,
/// `time.realtime`, …; `Temporal4.feature` [13]). A clock variant is the base type captured at a
/// given clock granularity: it returns the same type as its base constructor and propagates a
/// `null` argument to `null`. The optional argument of a clock variant is a timezone, which the
/// base constructor's map/string forms already accept; for the null-propagation path tested by the
/// TCK the argument never reaches the base.
///
/// In the zero-argument "current instant" form the clock granularity is chosen from the suffix:
/// `statement` (and the bare default) reads the fixed per-statement instant from `clock`;
/// `realtime` reads the live wall clock afresh. `duration()` has no current-instant form.
pub(crate) fn construct(
    name: &str,
    arg: Option<&Value>,
    clock: &StatementClock,
) -> Result<Value, EvalError> {
    // A clock variant (`<base>.transaction` / `.statement` / `.realtime`) constructs the same type
    // as its base; strip the suffix so both forms share one code path, but keep the suffix so the
    // zero-argument form can pick the clock granularity.
    let (base, suffix) = name
        .split_once('.')
        .filter(|(_, suffix)| matches!(*suffix, "transaction" | "statement" | "realtime"))
        .map_or((name, ""), |(base, suffix)| (base, suffix));
    let Some(arg) = arg else {
        return construct_current(base, suffix, clock);
    };
    if arg.is_null() {
        return Ok(Value::Null);
    }
    match base {
        "date" => construct_date(arg),
        "localtime" => construct_local_time(arg),
        "time" => construct_time(arg),
        "localdatetime" => construct_local_date_time(arg),
        "datetime" => construct_date_time(arg),
        "duration" => construct_duration(arg),
        other => Err(EvalError::UnsupportedFunction {
            name: other.to_owned(),
        }),
    }
}

/// Builds a zero-argument "current instant" temporal value from the clock.
///
/// The `suffix` selects the clock granularity:
///
/// - `""` (bare, the default) or `"statement"` → the fixed per-statement instant in `clock`.
/// - `"transaction"` → also the per-statement instant. NOTE: a true per-transaction clock would
///   require coordinator wiring; sharing the statement instant is spec-conformant for
///   single-statement transactions (the bare `date()` defaults to the statement clock anyway) and
///   is what the TCK exercises. This is intentionally not over-engineered.
/// - `"realtime"` → a freshly read live wall clock.
///
/// `duration` has no current-instant form and is rejected.
fn construct_current(base: &str, suffix: &str, clock: &StatementClock) -> Result<Value, EvalError> {
    let realtime = suffix == "realtime";
    let value = match base {
        "date" if realtime => Value::Date(StatementClock::realtime_date()),
        "date" => Value::Date(clock.date()),
        "localtime" if realtime => Value::LocalTime(StatementClock::realtime_localtime()),
        "localtime" => Value::LocalTime(clock.localtime()),
        "time" if realtime => Value::ZonedTime(StatementClock::realtime_time()),
        "time" => Value::ZonedTime(clock.time()),
        "localdatetime" if realtime => {
            Value::LocalDateTime(StatementClock::realtime_localdatetime())
        }
        "localdatetime" => Value::LocalDateTime(clock.localdatetime()),
        "datetime" if realtime => Value::ZonedDateTime(StatementClock::realtime_datetime()),
        "datetime" => Value::ZonedDateTime(clock.datetime()),
        // `duration()` (and any non-temporal base) has no current-instant form.
        other => {
            return Err(EvalError::UnsupportedFunction {
                name: format!("{other}() without arguments"),
            });
        }
    };
    Ok(value)
}

fn construct_date(arg: &Value) -> Result<Value, EvalError> {
    match arg {
        Value::String(s) => Ok(Value::Date(tc::parse_date(s).map_err(terr)?)),
        Value::Date(d) => Ok(Value::Date(*d)),
        Value::LocalDateTime(dt) => Ok(Value::Date(dt.to_date_time().0)),
        Value::ZonedDateTime(z) => Ok(Value::Date(z.local.to_date_time().0)),
        Value::Map(entries) => {
            let map = ComponentMap::new(entries)?;
            let base = base_date(&map)?;
            Ok(Value::Date(date_from_map(&map, base)?))
        }
        other => Err(type_err(format!(
            "date() requires a string, map or temporal argument, got {}",
            kind_name(other)
        ))),
    }
}

fn construct_local_time(arg: &Value) -> Result<Value, EvalError> {
    match arg {
        Value::String(s) => Ok(Value::LocalTime(tc::parse_local_time(s).map_err(terr)?)),
        Value::LocalTime(t) => Ok(Value::LocalTime(*t)),
        Value::ZonedTime(zt) => Ok(Value::LocalTime(zt.time)),
        Value::LocalDateTime(dt) => Ok(Value::LocalTime(dt.to_date_time().1)),
        Value::ZonedDateTime(z) => Ok(Value::LocalTime(z.local.to_date_time().1)),
        Value::Map(entries) => {
            let map = ComponentMap::new(entries)?;
            let base = base_time(&map)?.map(|b| b.time);
            Ok(Value::LocalTime(time_from_map(&map, base)?))
        }
        other => Err(type_err(format!(
            "localtime() requires a string, map or temporal argument, got {}",
            kind_name(other)
        ))),
    }
}

fn construct_time(arg: &Value) -> Result<Value, EvalError> {
    match arg {
        // A bare wall-clock string (no offset) defaults to UTC, like the map form without
        // `timezone`.
        Value::String(s) => match tc::parse_zoned_time(s) {
            Ok(zt) => Ok(Value::ZonedTime(zt)),
            Err(_) => {
                let t = tc::parse_local_time(s).map_err(terr)?;
                Ok(Value::ZonedTime(ZonedTime::new(t, 0).map_err(terr)?))
            }
        },
        Value::ZonedTime(zt) => Ok(Value::ZonedTime(*zt)),
        Value::LocalTime(t) => Ok(Value::ZonedTime(ZonedTime::new(*t, 0).map_err(terr)?)),
        Value::ZonedDateTime(z) => Ok(Value::ZonedTime(
            ZonedTime::new(z.local.to_date_time().1, z.offset_seconds).map_err(terr)?,
        )),
        Value::LocalDateTime(dt) => Ok(Value::ZonedTime(
            ZonedTime::new(dt.to_date_time().1, 0).map_err(terr)?,
        )),
        Value::Map(entries) => {
            let map = ComponentMap::new(entries)?;
            let tz = map.timezone()?;
            let base = base_time(&map)?;
            // With an explicit target timezone *and* a zoned base, the base wall clock is first
            // re-expressed in the target zone — the instant is preserved, modulo 24 h — and only
            // then are the component overrides applied (`Temporal3.feature` scenario [3]:
            // `time({time: t12:31+01:00, second: 42, timezone: '+05:00'})` is `16:31:42+05:00`).
            // An unzoned base keeps its wall clock under a new timezone (same scenario).
            let (default_time, offset) = match (tz, &base) {
                (Some(spec), Some(b)) if b.offset.is_some() => {
                    let from = b.offset.unwrap_or_default();
                    // A zoned *time* carries no date: a named target zone is resolved at the
                    // epoch anchor date (openCypher `Time` stores only the resolved offset; the
                    // TCK exercises named zones for times only via fixed-offset zones).
                    let instant = LocalDateTime::from_date_time(Date::default(), b.time)
                        .epoch_seconds
                        - i64::from(from);
                    let target = spec.offset_at_instant(instant)?;
                    (Some(shift_time(b.time, target - from)), target)
                }
                (Some(TzSpec::Fixed(offset)), _) => (base.as_ref().map(|b| b.time), offset),
                (Some(TzSpec::Named(zone)), _) => {
                    // No instant to anchor on: resolve the named zone at the epoch anchor date.
                    let anchor = LocalDateTime::from_date_time(
                        Date::default(),
                        base.as_ref().map(|b| b.time).unwrap_or_default(),
                    );
                    let (_, offset) = timezone::resolve_local(zone, &anchor, None)?;
                    (base.as_ref().map(|b| b.time), offset)
                }
                (None, _) => (
                    base.as_ref().map(|b| b.time),
                    base.as_ref().and_then(|b| b.offset).unwrap_or(0),
                ),
            };
            let time = time_from_map(&map, default_time)?;
            Ok(Value::ZonedTime(
                ZonedTime::new(time, offset).map_err(terr)?,
            ))
        }
        other => Err(type_err(format!(
            "time() requires a string, map or temporal argument, got {}",
            kind_name(other)
        ))),
    }
}

fn construct_local_date_time(arg: &Value) -> Result<Value, EvalError> {
    match arg {
        Value::String(s) => Ok(Value::LocalDateTime(
            tc::parse_local_date_time(s).map_err(terr)?,
        )),
        Value::LocalDateTime(dt) => Ok(Value::LocalDateTime(*dt)),
        Value::ZonedDateTime(z) => Ok(Value::LocalDateTime(z.local)),
        Value::Date(d) => Ok(Value::LocalDateTime(LocalDateTime::from_date_time(
            *d,
            LocalTime::default(),
        ))),
        Value::Map(entries) => {
            let map = ComponentMap::new(entries)?;
            Ok(Value::LocalDateTime(local_date_time_from_map(&map)?))
        }
        other => Err(type_err(format!(
            "localdatetime() requires a string, map or temporal argument, got {}",
            kind_name(other)
        ))),
    }
}

fn construct_date_time(arg: &Value) -> Result<Value, EvalError> {
    match arg {
        Value::String(s) => {
            let (local, offset, zone) = tc::parse_zoned_date_time_parts(s).map_err(terr)?;
            match (offset, zone) {
                // Offset-only: the offset *is* the zone (`Temporal2.feature` scenario [5]).
                (Some(offset), None) => Ok(Value::ZonedDateTime(
                    ZonedDateTime::from_local(local, offset, "").map_err(terr)?,
                )),
                // A named zone resolves via the zone rules; an explicit offset alongside it
                // disambiguates an overlapping local time (`Temporal2.feature` scenario [6]:
                // `'...+02:00[Europe/Stockholm]'` keeps +02:00, `'...[Europe/London]'`
                // resolves +01:00, and 1818 Stockholm resolves the historical +00:53:28).
                (offset, Some(zone)) => {
                    let zone = timezone::canonical_id(&zone)?;
                    let (local, offset) = timezone::resolve_local(zone, &local, offset)?;
                    Ok(Value::ZonedDateTime(
                        ZonedDateTime::from_local(local, offset, zone).map_err(terr)?,
                    ))
                }
                (None, None) => Err(type_err(format!(
                    "datetime() string `{s}` carries neither a UTC offset nor a time zone"
                ))),
            }
        }
        Value::ZonedDateTime(z) => Ok(Value::ZonedDateTime(z.clone())),
        Value::LocalDateTime(dt) => Ok(Value::ZonedDateTime(
            ZonedDateTime::from_local(*dt, 0, "").map_err(terr)?,
        )),
        Value::Date(d) => Ok(Value::ZonedDateTime(
            ZonedDateTime::from_local(
                LocalDateTime::from_date_time(*d, LocalTime::default()),
                0,
                "",
            )
            .map_err(terr)?,
        )),
        Value::Map(entries) => {
            let map = ComponentMap::new(entries)?;
            date_time_from_map(&map)
        }
        other => Err(type_err(format!(
            "datetime() requires a string, map or temporal argument, got {}",
            kind_name(other)
        ))),
    }
}

fn construct_duration(arg: &Value) -> Result<Value, EvalError> {
    match arg {
        Value::String(s) => Ok(Value::Duration(tc::parse_duration(s).map_err(terr)?)),
        Value::Duration(d) => Ok(Value::Duration(*d)),
        Value::Map(entries) => {
            let mut months = 0.0f64;
            let mut days = 0.0f64;
            let mut seconds = 0.0f64;
            let mut nanos = 0.0f64;
            for (key, value) in entries {
                if value.is_null() {
                    continue;
                }
                let n = duration_component_number(key, value)?;
                match key.to_ascii_lowercase().as_str() {
                    "years" => months += n * 12.0,
                    "quarters" => months += n * 3.0,
                    "months" => months += n,
                    "weeks" => days += n * 7.0,
                    "days" => days += n,
                    "hours" => seconds += n * 3600.0,
                    "minutes" => seconds += n * 60.0,
                    "seconds" => seconds += n,
                    "milliseconds" => nanos += n * 1_000_000.0,
                    "microseconds" => nanos += n * 1_000.0,
                    "nanoseconds" => nanos += n,
                    other => {
                        return Err(type_err(format!("unknown duration() component `{other}`")));
                    }
                }
            }
            Ok(Value::Duration(
                Duration::approximate(months, days, seconds, nanos).map_err(terr)?,
            ))
        }
        other => Err(type_err(format!(
            "duration() requires a string, map or duration argument, got {}",
            kind_name(other)
        ))),
    }
}

fn duration_component_number(key: &str, value: &Value) -> Result<f64, EvalError> {
    match value {
        Value::Integer(i) => Ok(*i as f64),
        Value::Float(f) => Ok(*f),
        other => Err(type_err(format!(
            "duration() component `{key}` must be a number, got {}",
            kind_name(other)
        ))),
    }
}

// =================================================================================================
// Component maps (`date({year: 1984, month: 10, day: 11})`, …)
// =================================================================================================

/// A constructor-supplied `timezone` component: a fixed UTC offset (`'+01:00'`, `'Z'`) or a
/// named IANA zone (`'Europe/Stockholm'`, canonicalised case).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TzSpec {
    Fixed(i32),
    Named(&'static str),
}

impl TzSpec {
    /// Parses a `timezone` string: anything that is not a fixed offset must name a zone in the
    /// embedded IANA database; an unknown id is a typed runtime error.
    fn parse(tz: &str) -> Result<Self, EvalError> {
        match tc::parse_offset_seconds(tz) {
            Ok(offset) => Ok(Self::Fixed(offset)),
            Err(_) => Ok(Self::Named(timezone::canonical_id(tz)?)),
        }
    }

    /// The offset for converting an existing instant *into* this zone (total: every instant has
    /// exactly one offset; no gap/overlap can arise).
    fn offset_at_instant(self, unix_seconds: i64) -> Result<i32, EvalError> {
        match self {
            Self::Fixed(offset) => Ok(offset),
            Self::Named(zone) => timezone::offset_at_instant(zone, unix_seconds),
        }
    }
}

/// A lower-cased view over a constructor's component map, with typed integer extraction.
struct ComponentMap<'v> {
    entries: Vec<(String, &'v Value)>,
}

impl<'v> ComponentMap<'v> {
    fn new(entries: &'v [(String, Value)]) -> Result<Self, EvalError> {
        Ok(Self {
            entries: entries
                .iter()
                .map(|(k, v)| (k.to_ascii_lowercase(), v))
                .collect(),
        })
    }

    fn get(&self, key: &str) -> Option<&'v Value> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| *v)
    }

    fn has(&self, key: &str) -> bool {
        self.get(key).is_some_and(|v| !v.is_null())
    }

    /// An integer component, or `default` when absent/null. Non-integers are a runtime type error.
    fn int_or(&self, key: &str, default: i64) -> Result<i64, EvalError> {
        match self.get(key) {
            None | Some(Value::Null) => Ok(default),
            Some(Value::Integer(i)) => Ok(*i),
            Some(other) => Err(type_err(format!(
                "temporal component `{key}` must be an integer, got {}",
                kind_name(other)
            ))),
        }
    }

    /// The parsed `timezone` entry, if present: a fixed offset or a named IANA zone (an unknown
    /// id is a typed runtime error).
    fn timezone(&self) -> Result<Option<TzSpec>, EvalError> {
        match self.get("timezone") {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(tz)) => TzSpec::parse(tz).map(Some),
            Some(other) => Err(type_err(format!(
                "temporal component `timezone` must be a string, got {}",
                kind_name(other)
            ))),
        }
    }
}

/// The date carried by a `date:` / `datetime:` base entry, if any.
fn base_date(map: &ComponentMap<'_>) -> Result<Option<Date>, EvalError> {
    for key in ["date", "datetime"] {
        match map.get(key) {
            None | Some(Value::Null) => {}
            Some(Value::Date(d)) => return Ok(Some(*d)),
            Some(Value::LocalDateTime(dt)) => return Ok(Some(dt.to_date_time().0)),
            Some(Value::ZonedDateTime(z)) => return Ok(Some(z.local.to_date_time().0)),
            Some(other) => {
                return Err(type_err(format!(
                    "temporal component `{key}` must carry a date, got {}",
                    kind_name(other)
                )));
            }
        }
    }
    Ok(None)
}

/// The time carried by a `time:` / `datetime:` base entry, with its offset and IANA zone id
/// when zoned, and which entry it came from: a `datetime:` base also carries the date, so a
/// zone conversion moves the whole local date-time, while a `time:` base converts the
/// time-of-day modulo 24 h (`Temporal3.feature` scenarios \[3\], \[9\] and \[11\]).
struct TimeBase {
    time: LocalTime,
    offset: Option<i32>,
    /// The IANA zone id of a named-zone `DateTime` base (inherited by the result when the map
    /// has no `timezone` entry of its own).
    zone: Option<String>,
    /// Whether the base came from the `datetime` entry (full-date conversion granularity).
    from_datetime: bool,
}

/// The time carried by a `time:` / `datetime:` base entry, if any.
fn base_time(map: &ComponentMap<'_>) -> Result<Option<TimeBase>, EvalError> {
    for key in ["time", "datetime"] {
        let from_datetime = key == "datetime";
        match map.get(key) {
            None | Some(Value::Null) => {}
            Some(Value::LocalTime(t)) => {
                return Ok(Some(TimeBase {
                    time: *t,
                    offset: None,
                    zone: None,
                    from_datetime,
                }));
            }
            Some(Value::ZonedTime(zt)) => {
                return Ok(Some(TimeBase {
                    time: zt.time,
                    offset: Some(zt.offset_seconds),
                    zone: None,
                    from_datetime,
                }));
            }
            Some(Value::LocalDateTime(dt)) => {
                return Ok(Some(TimeBase {
                    time: dt.to_date_time().1,
                    offset: None,
                    zone: None,
                    from_datetime,
                }));
            }
            Some(Value::ZonedDateTime(z)) => {
                return Ok(Some(TimeBase {
                    time: z.local.to_date_time().1,
                    offset: Some(z.offset_seconds),
                    zone: (!z.zone_id.is_empty()).then(|| z.zone_id.clone()),
                    from_datetime,
                }));
            }
            Some(other) => {
                return Err(type_err(format!(
                    "temporal component `{key}` must carry a time, got {}",
                    kind_name(other)
                )));
            }
        }
    }
    Ok(None)
}

/// Shifts a time-of-day by a whole number of seconds, wrapping modulo 24 h (zone conversion of
/// a time value: the date, if any, is owned by the caller).
fn shift_time(t: LocalTime, delta_seconds: i32) -> LocalTime {
    let delta = i64::from(delta_seconds) * 1_000_000_000;
    let nanos = (t.nanos_of_day as i64 + delta).rem_euclid(NANOS_PER_DAY as i64);
    LocalTime {
        nanos_of_day: nanos as u64,
    }
}

/// Builds a date from the map's components over an optional base date (normally
/// `base_date(map)`; the zone-conversion paths substitute the converted date).
///
/// Each calendar form — week, ordinal-day, quarter, year-month-day — has its own component
/// family; with a base date the unspecified components of the *selected* calendar default to
/// the base's value in that calendar (`Temporal3.feature` scenario \[1\]:
/// `date({date: 1984-11-11, week: 1})` keeps the base's week-year and week-day, giving
/// `1984-01-08`; `{date: ..., quarter: 3}` keeps the day-of-quarter). Without a base, `year`
/// is mandatory and the remaining components default to their first value.
fn date_from_map(map: &ComponentMap<'_>, base: Option<Date>) -> Result<Date, EvalError> {
    let year = match (map.get("year"), base) {
        (Some(Value::Integer(y)), _) => Some(*y),
        (None | Some(Value::Null), Some(_)) => None,
        _ => return Err(type_err("date() from a map requires a `year` component")),
    };
    if map.has("week") || (base.is_some() && map.has("dayofweek")) {
        let (by, bw, bd) = match base {
            Some(b) => (b.week_year(), b.week(), b.week_day()),
            None => (0, 1, 1),
        };
        let week = map.int_or("week", bw)?;
        let dow = map.int_or("dayofweek", bd)?;
        return Date::from_year_week_day(year.unwrap_or(by), clamp_u32(week)?, clamp_u32(dow)?)
            .map_err(terr);
    }
    if map.has("ordinalday") {
        let (by, bo) = match base {
            Some(b) => (b.year(), b.ordinal_day()),
            None => (0, 1),
        };
        let ordinal = map.int_or("ordinalday", bo)?;
        return Date::from_year_ordinal(year.unwrap_or(by), clamp_u32(ordinal)?).map_err(terr);
    }
    if map.has("quarter") || (base.is_some() && map.has("dayofquarter")) {
        let (by, bq, bd) = match base {
            Some(b) => (b.year(), b.quarter(), b.day_of_quarter()),
            None => (0, 1, 1),
        };
        let quarter = map.int_or("quarter", bq)?;
        let doq = map.int_or("dayofquarter", bd)?;
        return Date::from_year_quarter_day(
            year.unwrap_or(by),
            clamp_u32(quarter)?,
            clamp_u32(doq)?,
        )
        .map_err(terr);
    }
    let (by, bm, bd) = match base {
        Some(b) => {
            let (y, m, d) = b.to_ymd();
            (y, i64::from(m), i64::from(d))
        }
        None => (0, 1, 1),
    };
    let month = map.int_or("month", bm)?;
    let day = map.int_or("day", bd)?;
    Date::from_ymd(year.unwrap_or(by), clamp_u32(month)?, clamp_u32(day)?).map_err(terr)
}

/// Builds a time-of-day from the map's components over an optional base time (normally the
/// `base_time(map)` wall clock; the zone-conversion paths substitute the converted time).
fn time_from_map(map: &ComponentMap<'_>, base: Option<LocalTime>) -> Result<LocalTime, EvalError> {
    let (bh, bm, bs, bn) = match base {
        Some(t) => (t.hour(), t.minute(), t.second(), t.nanosecond()),
        None => (0, 0, 0, 0),
    };
    let hour = map.int_or("hour", bh)?;
    let minute = map.int_or("minute", bm)?;
    let second = map.int_or("second", bs)?;
    let nanos = if map.has("millisecond") || map.has("microsecond") || map.has("nanosecond") {
        // Sub-second fields are additive: ms·10⁶ + µs·10³ + ns (each defaulting to 0); the total
        // must stay within one second.
        let ms = map.int_or("millisecond", 0)?;
        let us = map.int_or("microsecond", 0)?;
        let ns = map.int_or("nanosecond", 0)?;
        let total = ms
            .checked_mul(1_000_000)
            .and_then(|v| v.checked_add(us.checked_mul(1_000)?))
            .and_then(|v| v.checked_add(ns))
            .ok_or_else(|| type_err("sub-second components overflow"))?;
        if !(0..1_000_000_000).contains(&total) {
            return Err(type_err(
                "sub-second components must combine to less than one second",
            ));
        }
        total
    } else {
        bn
    };
    LocalTime::from_hms_nanos(
        clamp_u32(hour)?,
        clamp_u32(minute)?,
        clamp_u32(second)?,
        clamp_u32(nanos)?,
    )
    .map_err(terr)
}

fn local_date_time_from_map(map: &ComponentMap<'_>) -> Result<LocalDateTime, EvalError> {
    let date = date_from_map(map, base_date(map)?)?;
    let time = time_from_map(map, base_time(map)?.map(|b| b.time))?;
    Ok(LocalDateTime::from_date_time(date, time))
}

fn date_time_from_map(map: &ComponentMap<'_>) -> Result<Value, EvalError> {
    let tz = map.timezone()?;
    // Epoch forms: `datetime({epochSeconds: s [, nanosecond: n]})` / `{epochMillis: ms}`. The
    // epoch fixes the instant; a timezone only re-renders it (no gap/overlap can arise).
    if map.has("epochseconds") || map.has("epochmillis") {
        let (secs, base_nanos) = if map.has("epochseconds") {
            (map.int_or("epochseconds", 0)?, 0i64)
        } else {
            let ms = map.int_or("epochmillis", 0)?;
            (ms.div_euclid(1000), ms.rem_euclid(1000) * 1_000_000)
        };
        let extra_nanos = map.int_or("nanosecond", 0)?;
        let total_nanos = base_nanos + extra_nanos;
        let local = LocalDateTime {
            epoch_seconds: secs + total_nanos.div_euclid(1_000_000_000),
            nanos: u32::try_from(total_nanos.rem_euclid(1_000_000_000))
                .expect("rem_euclid(1e9) fits u32"),
        };
        let (offset, zone_id) = match tz {
            None => (0, ""),
            Some(TzSpec::Fixed(offset)) => (offset, ""),
            Some(TzSpec::Named(zone)) => (
                timezone::offset_at_instant(zone, local.epoch_seconds)?,
                zone,
            ),
        };
        // The local fields shift by the resolved offset.
        let shifted = LocalDateTime {
            epoch_seconds: local.epoch_seconds + i64::from(offset),
            nanos: local.nanos,
        };
        return Ok(Value::ZonedDateTime(
            ZonedDateTime::from_local(shifted, offset, zone_id).map_err(terr)?,
        ));
    }

    let base = base_time(map)?;
    let base_offset = base.as_ref().and_then(|b| b.offset);

    // 1. Conversion: an explicit target timezone re-expresses a *zoned* base in the target zone
    //    (the instant is preserved) before the component overrides apply (`Temporal3.feature`
    //    scenarios [9]/[11]: `datetime({datetime: d12:00+01:00, timezone: '+05:00'})` is
    //    `16:00+05:00`). A `datetime:` base converts the whole local date-time; a `time:` base
    //    converts the time-of-day modulo 24 h. An unzoned base keeps its wall clock.
    let mut default_date = base_date(map)?;
    let mut default_time = base.as_ref().map(|b| b.time);
    let mut converted_offset: Option<i32> = None;
    if let (Some(spec), Some(b), Some(from)) = (tz, &base, base_offset) {
        if b.from_datetime {
            let date = default_date
                .ok_or_else(|| type_err("temporal component `datetime` must carry a date"))?;
            let local = LocalDateTime::from_date_time(date, b.time);
            let instant = local.epoch_seconds - i64::from(from);
            let target = spec.offset_at_instant(instant)?;
            let converted = LocalDateTime {
                epoch_seconds: instant + i64::from(target),
                nanos: local.nanos,
            };
            let (d, t) = converted.to_date_time();
            default_date = Some(d);
            default_time = Some(t);
            converted_offset = Some(target);
        } else {
            // The date is owned by the date components; only the time-of-day converts. The
            // source offset is re-resolved against the base's own zone at the *assembled*
            // local — a zoned `time:` base reused under a different date can sit on the other
            // side of a DST transition than where its offset was originally resolved
            // (`Temporal3.feature` scenario [10]: a Stockholm October time re-anchored to late
            // March 1984 carries +02:00, not its stored +01:00). The target offset is then
            // resolved at the instant the (assembled date, base time, source offset) denote.
            let date = date_from_map(map, default_date)?;
            let local = LocalDateTime::from_date_time(date, b.time);
            let from = match &b.zone {
                Some(zone) => timezone::resolve_local(zone, &local, Some(from))?.1,
                None => from,
            };
            let instant = local.epoch_seconds - i64::from(from);
            let target = spec.offset_at_instant(instant)?;
            default_time = Some(shift_time(b.time, target - from));
            converted_offset = Some(target);
        }
    }

    // 2. Component overrides over the (possibly converted) base.
    let date = date_from_map(map, default_date)?;
    let time = time_from_map(map, default_time)?;
    let local = LocalDateTime::from_date_time(date, time);

    // 3. Final offset and zone id: the explicit timezone wins; otherwise the zone (or fixed
    //    offset) is inherited from the zoned base; otherwise UTC. A named zone re-resolves the
    //    offset from the *final* local value — overrides can move it across a DST transition
    //    (`Temporal3.feature` scenario [10]: a Stockholm base moved from October to late March
    //    1984 flips +01:00 to +02:00) — preferring the converted/inherited offset when the local
    //    time is ambiguous.
    let (local, offset, zone_id): (LocalDateTime, i32, String) = match tz {
        Some(TzSpec::Fixed(offset)) => (local, offset, String::new()),
        Some(TzSpec::Named(zone)) => {
            let (local, offset) = timezone::resolve_local(zone, &local, converted_offset)?;
            (local, offset, zone.to_owned())
        }
        None => match base.as_ref() {
            Some(TimeBase {
                zone: Some(zone), ..
            }) => {
                let (local, offset) = timezone::resolve_local(zone, &local, base_offset)?;
                (local, offset, zone.clone())
            }
            Some(TimeBase {
                offset: Some(offset),
                ..
            }) => (local, *offset, String::new()),
            _ => (local, 0, String::new()),
        },
    };
    Ok(Value::ZonedDateTime(
        ZonedDateTime::from_local(local, offset, zone_id).map_err(terr)?,
    ))
}

fn clamp_u32(v: i64) -> Result<u32, EvalError> {
    u32::try_from(v).map_err(|_| type_err(format!("temporal component out of range: {v}")))
}

// =================================================================================================
// Component access (`d.year`, `t.hour`, `dur.minutesOfHour`, …)
// =================================================================================================

/// Property-style component access on a temporal value. `None` means "not a temporal base" (the
/// caller falls through to its own semantics); a temporal base with an unknown component yields
/// `Some(Value::Null)` (Cypher's missing-property rule).
pub(crate) fn component(base: &Value, key: &str) -> Option<Value> {
    let k = key.to_ascii_lowercase();
    Some(match base {
        Value::Date(d) => date_component(d, &k),
        Value::LocalTime(t) => time_component(
            t.hour(),
            t.minute(),
            t.second(),
            t.millisecond(),
            t.microsecond(),
            t.nanosecond(),
            &k,
        ),
        Value::ZonedTime(zt) => match k.as_str() {
            "offset" => Value::String(zt.offset_string()),
            "offsetminutes" => Value::Integer(zt.offset_minutes()),
            "offsetseconds" => Value::Integer(i64::from(zt.offset_seconds)),
            "timezone" => Value::String(zt.timezone_name()),
            _ => time_component(
                zt.hour(),
                zt.minute(),
                zt.second(),
                zt.millisecond(),
                zt.microsecond(),
                zt.nanosecond(),
                &k,
            ),
        },
        Value::LocalDateTime(dt) => match k.as_str() {
            "epochseconds" => Value::Integer(dt.epoch_seconds()),
            "epochmillis" => Value::Integer(dt.epoch_millis()),
            _ => {
                let (date, time) = dt.to_date_time();
                let from_date = date_component(&date, &k);
                if from_date != Value::Null {
                    from_date
                } else {
                    time_component(
                        time.hour(),
                        time.minute(),
                        time.second(),
                        time.millisecond(),
                        time.microsecond(),
                        time.nanosecond(),
                        &k,
                    )
                }
            }
        },
        Value::ZonedDateTime(z) => match k.as_str() {
            "offset" => Value::String(z.offset_string()),
            "offsetminutes" => Value::Integer(z.offset_minutes()),
            "offsetseconds" => Value::Integer(i64::from(z.offset_seconds)),
            "timezone" => Value::String(z.timezone_name()),
            "epochseconds" => Value::Integer(z.epoch_seconds()),
            "epochmillis" => Value::Integer(z.epoch_millis()),
            _ => {
                let (date, time) = z.local.to_date_time();
                let from_date = date_component(&date, &k);
                if from_date != Value::Null {
                    from_date
                } else {
                    time_component(
                        time.hour(),
                        time.minute(),
                        time.second(),
                        time.millisecond(),
                        time.microsecond(),
                        time.nanosecond(),
                        &k,
                    )
                }
            }
        },
        Value::Duration(d) => duration_component(d, &k),
        _ => return None,
    })
}

fn date_component(d: &Date, key: &str) -> Value {
    match key {
        "year" => Value::Integer(d.year()),
        "month" => Value::Integer(d.month()),
        "day" => Value::Integer(d.day()),
        "quarter" => Value::Integer(d.quarter()),
        "week" => Value::Integer(d.week()),
        "weekyear" => Value::Integer(d.week_year()),
        "ordinalday" => Value::Integer(d.ordinal_day()),
        "weekday" | "dayofweek" => Value::Integer(d.week_day()),
        "dayofquarter" => Value::Integer(d.day_of_quarter()),
        _ => Value::Null,
    }
}

fn time_component(
    hour: i64,
    minute: i64,
    second: i64,
    millisecond: i64,
    microsecond: i64,
    nanosecond: i64,
    key: &str,
) -> Value {
    match key {
        "hour" => Value::Integer(hour),
        "minute" => Value::Integer(minute),
        "second" => Value::Integer(second),
        "millisecond" => Value::Integer(millisecond),
        "microsecond" => Value::Integer(microsecond),
        "nanosecond" => Value::Integer(nanosecond),
        _ => Value::Null,
    }
}

fn duration_component(d: &Duration, key: &str) -> Value {
    match key {
        "years" => Value::Integer(d.years()),
        "quarters" => Value::Integer(d.quarters()),
        "months" => Value::Integer(d.months_total()),
        "quartersofyear" => Value::Integer(d.quarters_of_year()),
        "monthsofyear" => Value::Integer(d.months_of_year()),
        "monthsofquarter" => Value::Integer(d.months_of_quarter()),
        "weeks" => Value::Integer(d.weeks()),
        "days" => Value::Integer(d.days_total()),
        "daysofweek" => Value::Integer(d.days_of_week()),
        "hours" => Value::Integer(d.hours()),
        "minutes" => Value::Integer(d.minutes()),
        "minutesofhour" => Value::Integer(d.minutes_of_hour()),
        "seconds" => Value::Integer(d.seconds_total()),
        "secondsofminute" => Value::Integer(d.seconds_of_minute()),
        "milliseconds" => Value::Integer(d.milliseconds()),
        "millisecondsofsecond" => Value::Integer(d.milliseconds_of_second()),
        "microseconds" => Value::Integer(d.microseconds()),
        "microsecondsofsecond" => Value::Integer(d.microseconds_of_second()),
        "nanoseconds" => Value::Integer(d.nanoseconds()),
        "nanosecondsofsecond" => Value::Integer(d.nanoseconds_of_second()),
        _ => Value::Null,
    }
}

// =================================================================================================
// Arithmetic
// =================================================================================================

/// Temporal `+`: `temporal + duration` (commutative) and `duration + duration`. `None` means
/// "not a temporal pair" (the caller falls through to numeric/string/list semantics).
pub(crate) fn add(a: &Value, b: &Value) -> Option<Result<Value, EvalError>> {
    match (a, b) {
        (Value::Duration(x), Value::Duration(y)) => {
            Some(x.add(y).map(Value::Duration).map_err(terr))
        }
        (Value::Duration(d), other) if is_point_temporal(other) => add_to_temporal(other, d),
        (other, Value::Duration(d)) if is_point_temporal(other) => add_to_temporal(other, d),
        _ => None,
    }
}

/// Temporal `-`: `temporal - duration` and `duration - duration`.
pub(crate) fn sub(a: &Value, b: &Value) -> Option<Result<Value, EvalError>> {
    match (a, b) {
        (Value::Duration(x), Value::Duration(y)) => {
            Some(x.sub(y).map(Value::Duration).map_err(terr))
        }
        (other, Value::Duration(d)) if is_point_temporal(other) => sub_from_temporal(other, d),
        _ => None,
    }
}

/// Temporal `*`: `duration * number` (commutative).
pub(crate) fn mul(a: &Value, b: &Value) -> Option<Result<Value, EvalError>> {
    match (a, b) {
        (Value::Duration(d), Value::Integer(n)) | (Value::Integer(n), Value::Duration(d)) => {
            Some(d.mul_int(*n).map(Value::Duration).map_err(terr))
        }
        (Value::Duration(d), Value::Float(f)) | (Value::Float(f), Value::Duration(d)) => {
            Some(d.mul_scalar(*f).map(Value::Duration).map_err(terr))
        }
        _ => None,
    }
}

/// Temporal `/`: `duration / number`.
pub(crate) fn div(a: &Value, b: &Value) -> Option<Result<Value, EvalError>> {
    match (a, b) {
        (Value::Duration(d), Value::Integer(n)) => {
            Some(d.div_scalar(*n as f64).map(Value::Duration).map_err(terr))
        }
        (Value::Duration(d), Value::Float(f)) => {
            Some(d.div_scalar(*f).map(Value::Duration).map_err(terr))
        }
        _ => None,
    }
}

fn is_point_temporal(v: &Value) -> bool {
    matches!(
        v,
        Value::Date(_)
            | Value::LocalTime(_)
            | Value::ZonedTime(_)
            | Value::LocalDateTime(_)
            | Value::ZonedDateTime(_)
    )
}

fn add_to_temporal(t: &Value, d: &Duration) -> Option<Result<Value, EvalError>> {
    Some(match t {
        Value::Date(x) => x.add_duration(d).map(Value::Date).map_err(terr),
        Value::LocalTime(x) => Ok(Value::LocalTime(x.add_duration(d))),
        Value::ZonedTime(x) => Ok(Value::ZonedTime(x.add_duration(d))),
        Value::LocalDateTime(x) => x.add_duration(d).map(Value::LocalDateTime).map_err(terr),
        Value::ZonedDateTime(x) => x.add_duration(d).map(Value::ZonedDateTime).map_err(terr),
        _ => return None,
    })
}

fn sub_from_temporal(t: &Value, d: &Duration) -> Option<Result<Value, EvalError>> {
    Some(match t {
        Value::Date(x) => x.sub_duration(d).map(Value::Date).map_err(terr),
        Value::LocalTime(x) => Ok(Value::LocalTime(x.sub_duration(d))),
        Value::ZonedTime(x) => Ok(Value::ZonedTime(x.sub_duration(d))),
        Value::LocalDateTime(x) => x.sub_duration(d).map(Value::LocalDateTime).map_err(terr),
        Value::ZonedDateTime(x) => x.sub_duration(d).map(Value::ZonedDateTime).map_err(terr),
        _ => return None,
    })
}

// =================================================================================================
// duration.between / duration.inMonths / duration.inDays / duration.inSeconds
// =================================================================================================

/// The date+time decomposition of a point temporal, with its offset when zoned. `LocalTime` /
/// `ZonedTime` carry no date (their `Date` is the epoch anchor and `dated` is false).
struct PointParts {
    date: Date,
    time: LocalTime,
    offset: Option<i32>,
    /// The IANA zone id of a named-zone `DateTime` (drives zone-aware difference/truncation).
    zone: Option<String>,
    dated: bool,
}

fn point_parts(v: &Value) -> Option<PointParts> {
    Some(match v {
        Value::Date(d) => PointParts {
            date: *d,
            time: LocalTime::default(),
            offset: None,
            zone: None,
            dated: true,
        },
        Value::LocalDateTime(dt) => {
            let (date, time) = dt.to_date_time();
            PointParts {
                date,
                time,
                offset: None,
                zone: None,
                dated: true,
            }
        }
        Value::ZonedDateTime(z) => {
            let (date, time) = z.local.to_date_time();
            PointParts {
                date,
                time,
                offset: Some(z.offset_seconds),
                zone: (!z.zone_id.is_empty()).then(|| z.zone_id.clone()),
                dated: true,
            }
        }
        Value::LocalTime(t) => PointParts {
            date: Date::default(),
            time: *t,
            offset: None,
            zone: None,
            dated: false,
        },
        Value::ZonedTime(zt) => PointParts {
            date: Date::default(),
            time: zt.time,
            offset: Some(zt.offset_seconds),
            zone: None,
            dated: false,
        },
        _ => return None,
    })
}

/// `duration.between/inMonths/inDays/inSeconds(a, b)`: the difference from `a` to `b`, decomposed
/// per openCypher — `between` yields months+days+seconds, the `in*` forms truncate to a single
/// component group. When both ends are zoned, `b` is re-expressed in `a`'s offset first (the
/// instant is what is being measured).
pub(crate) fn duration_between(kind: &str, a: &Value, b: &Value) -> Result<Value, EvalError> {
    if a.is_null() || b.is_null() {
        return Ok(Value::Null);
    }
    let mut pa =
        point_parts(a).ok_or_else(|| type_err(format!("{kind}() requires temporal arguments")))?;
    let mut pb =
        point_parts(b).ok_or_else(|| type_err(format!("{kind}() requires temporal arguments")))?;
    // Named-zone resolution of a local operand (`Temporal10.feature` scenario [8]): when exactly
    // one operand carries an offset and that operand is anchored to a named IANA zone, the other
    // operand is interpreted in that zone — borrowing the zoned operand's local date when it has
    // none — so the difference measures instants across DST transitions (e.g. Stockholm
    // 2017-10-29T00:00 to a local 04:00 the same day is 5 hours, not 4).
    if pa.offset.is_some() != pb.offset.is_some() {
        let (anchor_zone, anchor_date, other) = if pa.offset.is_some() {
            (pa.zone.clone(), pa.date, &mut pb)
        } else {
            (pb.zone.clone(), pb.date, &mut pa)
        };
        if let Some(zone) = anchor_zone {
            if !other.dated {
                other.date = anchor_date;
            }
            let local = LocalDateTime::from_date_time(other.date, other.time);
            let (adjusted, offset) = timezone::resolve_local(&zone, &local, None)?;
            let (date, time) = adjusted.to_date_time();
            other.date = date;
            other.time = time;
            other.offset = Some(offset);
        }
    }
    let dated = pa.dated && pb.dated;
    // A time-only operand reduces the difference to the time-of-day axis: the other operand's
    // date does not contribute (`Temporal10.feature` scenario [2]: `date × localtime('16:30')`
    // is PT16H30M, `localtime('14:30') × localdatetime(...T21:45:22.142)` is PT7H15M22.142S).
    // Both operands are re-anchored to the same date *before* the offset re-expression, which
    // may legitimately carry the wall clock across midnight (java.time's OffsetTime semantics).
    if !dated {
        pa.date = Date::default();
        pb.date = Date::default();
    }
    // Re-express b at a's offset so the difference measures instants, not wall clocks.
    if let (Some(oa), Some(ob)) = (pa.offset, pb.offset) {
        let shift = i64::from(oa) - i64::from(ob);
        let ldt = LocalDateTime::from_date_time(pb.date, pb.time);
        let shifted = LocalDateTime {
            epoch_seconds: ldt.epoch_seconds + shift,
            nanos: ldt.nanos,
        };
        let (date, time) = shifted.to_date_time();
        pb.date = date;
        pb.time = time;
    }

    let la = LocalDateTime::from_date_time(pa.date, pa.time);
    let lb = LocalDateTime::from_date_time(pb.date, pb.time);
    let total_nanos = instant_nanos(&lb) - instant_nanos(&la);

    let result = match kind {
        "duration.inseconds" => Duration {
            months: 0,
            days: 0,
            seconds: (total_nanos.div_euclid(1_000_000_000)) as i64,
            nanos: (total_nanos.rem_euclid(1_000_000_000)) as i32,
        },
        "duration.indays" => {
            if !dated {
                Duration::default()
            } else {
                Duration {
                    months: 0,
                    days: whole_days_between(&la, &lb),
                    seconds: 0,
                    nanos: 0,
                }
            }
        }
        "duration.inmonths" => {
            if !dated {
                Duration::default()
            } else {
                Duration {
                    months: whole_months_between(&la, &lb)?,
                    days: 0,
                    seconds: 0,
                    nanos: 0,
                }
            }
        }
        // duration.between: months, then days, then the sub-day remainder.
        _ => {
            if !dated {
                Duration {
                    months: 0,
                    days: 0,
                    seconds: (total_nanos.div_euclid(1_000_000_000)) as i64,
                    nanos: (total_nanos.rem_euclid(1_000_000_000)) as i32,
                }
            } else {
                let months = whole_months_between(&la, &lb)?;
                let after_months = add_months(&la, months)?;
                let days = whole_days_between(&after_months, &lb);
                let after_days = LocalDateTime {
                    epoch_seconds: after_months.epoch_seconds + days * tc::SECONDS_PER_DAY,
                    nanos: after_months.nanos,
                };
                let rest = instant_nanos(&lb) - instant_nanos(&after_days);
                Duration {
                    months,
                    days,
                    seconds: (rest.div_euclid(1_000_000_000)) as i64,
                    nanos: (rest.rem_euclid(1_000_000_000)) as i32,
                }
            }
        }
    };
    Ok(Value::Duration(result))
}

// =================================================================================================
// datetime.fromepoch / datetime.fromepochmillis
// =================================================================================================

/// `datetime.fromepoch(seconds, nanoseconds)`: the UTC instant `seconds` after
/// the Unix epoch, with a sub-second `nanoseconds` field added on top
/// (`Temporal1.feature` scenario \[11\]). Either argument being `null`
/// propagates to `null`.
pub(crate) fn from_epoch_seconds(secs: &Value, nanos: &Value) -> Result<Value, EvalError> {
    if secs.is_null() || nanos.is_null() {
        return Ok(Value::Null);
    }
    let secs = epoch_int(secs, "datetime.fromepoch")?;
    let nanos = epoch_int(nanos, "datetime.fromepoch")?;
    utc_from_epoch(secs, nanos)
}

/// `datetime.fromepochmillis(milliseconds)`: the UTC instant `milliseconds`
/// after the Unix epoch (`Temporal1.feature` scenario \[11\]). A `null`
/// argument propagates to `null`.
pub(crate) fn from_epoch_millis(millis: &Value) -> Result<Value, EvalError> {
    if millis.is_null() {
        return Ok(Value::Null);
    }
    let millis = epoch_int(millis, "datetime.fromepochmillis")?;
    // Split into whole seconds and a non-negative sub-second nanosecond field so
    // instants before the epoch decompose correctly (Euclidean division).
    let secs = millis.div_euclid(1000);
    let nanos = millis.rem_euclid(1000) * 1_000_000;
    utc_from_epoch(secs, nanos)
}

/// Builds a UTC `DateTime` (offset `Z`, no named zone) from an epoch-second
/// count and a nanosecond addend, carrying whole seconds out of the nanosecond
/// field so the stored `nanos` stays in `0 ..= 999_999_999`.
fn utc_from_epoch(secs: i64, nanos: i64) -> Result<Value, EvalError> {
    let epoch_seconds = secs
        .checked_add(nanos.div_euclid(1_000_000_000))
        .ok_or_else(|| type_err("datetime epoch seconds overflow"))?;
    let nanos = u32::try_from(nanos.rem_euclid(1_000_000_000)).expect("rem_euclid(1e9) fits u32");
    let local = LocalDateTime {
        epoch_seconds,
        nanos,
    };
    Ok(Value::ZonedDateTime(
        ZonedDateTime::from_local(local, 0, "").map_err(terr)?,
    ))
}

/// Extracts an integer epoch component, rejecting non-integers as a typed error.
fn epoch_int(value: &Value, func: &str) -> Result<i64, EvalError> {
    match value {
        Value::Integer(i) => Ok(*i),
        other => Err(type_err(format!(
            "{func}() requires integer arguments, got {}",
            kind_name(other)
        ))),
    }
}

fn instant_nanos(dt: &LocalDateTime) -> i128 {
    i128::from(dt.epoch_seconds) * 1_000_000_000 + i128::from(dt.nanos)
}

/// Whole (sign-carrying) days from `a` to `b`: truncating division of the nanosecond difference —
/// an incomplete final day does not count, in either direction.
fn whole_days_between(a: &LocalDateTime, b: &LocalDateTime) -> i64 {
    let diff = instant_nanos(b) - instant_nanos(a);
    let day = i128::from(tc::SECONDS_PER_DAY) * 1_000_000_000;
    (diff / day) as i64
}

/// Whole (sign-carrying) calendar months from `a` to `b`.
fn whole_months_between(a: &LocalDateTime, b: &LocalDateTime) -> Result<i64, EvalError> {
    let (ya, ma, _) = a.to_date_time().0.to_ymd();
    let (yb, mb, _) = b.to_date_time().0.to_ymd();
    let mut months = (yb - ya) * 12 + (i64::from(mb) - i64::from(ma));
    let forward = instant_nanos(a) <= instant_nanos(b);
    // Adjust for an incomplete final month.
    let candidate = add_months(a, months)?;
    if forward && instant_nanos(&candidate) > instant_nanos(b) {
        months -= 1;
    } else if !forward && instant_nanos(&candidate) < instant_nanos(b) {
        months += 1;
    }
    Ok(months)
}

fn add_months(a: &LocalDateTime, months: i64) -> Result<LocalDateTime, EvalError> {
    a.add_duration(&Duration {
        months,
        days: 0,
        seconds: 0,
        nanos: 0,
    })
    .map_err(terr)
}

// =================================================================================================
// <type>.truncate(unit, temporal [, overrides])
// =================================================================================================

/// `date.truncate` / `time.truncate` / `localtime.truncate` / `datetime.truncate` /
/// `localdatetime.truncate`: truncate `value` down to the start of `unit`, then apply the optional
/// component overrides, and project into the function's result class.
pub(crate) fn truncate(
    func: &str,
    unit: &Value,
    value: &Value,
    overrides: Option<&Value>,
) -> Result<Value, EvalError> {
    if unit.is_null() || value.is_null() {
        return Ok(Value::Null);
    }
    let Value::String(unit) = unit else {
        return Err(type_err(format!(
            "{func}() requires a string truncation unit"
        )));
    };
    let parts = point_parts(value)
        .ok_or_else(|| type_err(format!("{func}() requires a temporal argument")))?;
    let (date, time) = truncate_parts(&unit.to_ascii_lowercase(), parts.date, parts.time)
        .ok_or_else(|| type_err(format!("unknown truncation unit `{unit}`")))?;

    // Optional component overrides (`{day: 2}`-style map).
    let (date, time, override_tz) = match overrides {
        None | Some(Value::Null) => (date, time, None),
        Some(Value::Map(entries)) => {
            let map = ComponentMap::new(entries)?;
            // The date overrides reuse the component-map calendars over the truncated date
            // (`Temporal9.feature` scenario [1]: truncating to 'week' with `{dayOfWeek: 2}`
            // lands on the Tuesday of that week).
            let new_date = date_from_map(&map, Some(date))?;
            let hour = map.int_or("hour", time.hour())?;
            let minute = map.int_or("minute", time.minute())?;
            let second = map.int_or("second", time.second())?;
            let nanos = if map.has("millisecond") || map.has("microsecond") || map.has("nanosecond")
            {
                // Positional-field overrides over the *truncated* value: `millisecond` is the
                // millisecond-of-second, `microsecond` the microsecond-of-millisecond and
                // `nanosecond` the nanosecond-of-microsecond (`Temporal9.feature` scenario [2]:
                // truncating to 'millisecond' keeps `.645`, and `{nanosecond: 2}` then yields
                // `.645000002`). This differs from the constructors, where the sub-second
                // components are cumulative.
                let ms = map.int_or("millisecond", time.millisecond())?;
                let us = map.int_or(
                    "microsecond",
                    time.microsecond() - time.millisecond() * 1_000,
                )?;
                let ns =
                    map.int_or("nanosecond", time.nanosecond() - time.microsecond() * 1_000)?;
                ms * 1_000_000 + us * 1_000 + ns
            } else {
                time.nanosecond()
            };
            let new_time = LocalTime::from_hms_nanos(
                clamp_u32(hour)?,
                clamp_u32(minute)?,
                clamp_u32(second)?,
                clamp_u32(nanos)?,
            )
            .map_err(terr)?;
            (new_date, new_time, map.timezone()?)
        }
        Some(other) => {
            return Err(type_err(format!(
                "{func}() overrides must be a map, got {}",
                kind_name(other)
            )));
        }
    };

    Ok(match func {
        "date.truncate" => Value::Date(date),
        "localtime.truncate" => Value::LocalTime(time),
        "time.truncate" => {
            // Truncation never converts: a timezone override replaces the offset on the
            // truncated wall clock (`Temporal9.feature` scenario [5]). A named zone resolves at
            // the truncated local value (the input's date when it carried one).
            let offset = match override_tz {
                Some(TzSpec::Fixed(offset)) => offset,
                Some(TzSpec::Named(zone)) => {
                    let local = LocalDateTime::from_date_time(parts.date, time);
                    timezone::resolve_local(zone, &local, None)?.1
                }
                None => parts.offset.unwrap_or(0),
            };
            Value::ZonedTime(ZonedTime::new(time, offset).map_err(terr)?)
        }
        "localdatetime.truncate" => Value::LocalDateTime(LocalDateTime::from_date_time(date, time)),
        _ => {
            // datetime.truncate: a timezone override replaces the zone on the truncated wall
            // clock (no instant conversion — `Temporal9.feature` scenario [2]: truncating a
            // `-01:00` value to 'hour' with `{timezone: 'Europe/Stockholm'}` keeps 12:00 and
            // resolves +01:00). Without an override, a named-zone input keeps its zone with the
            // offset re-resolved at the truncated local value (the truncated date can sit on
            // the other side of a DST transition).
            let local = LocalDateTime::from_date_time(date, time);
            let (local, offset, zone_id): (LocalDateTime, i32, String) = match override_tz {
                Some(TzSpec::Fixed(offset)) => (local, offset, String::new()),
                Some(TzSpec::Named(zone)) => {
                    let (local, offset) = timezone::resolve_local(zone, &local, None)?;
                    (local, offset, zone.to_owned())
                }
                None => match parts.zone {
                    Some(zone) => {
                        let (local, offset) = timezone::resolve_local(&zone, &local, parts.offset)?;
                        (local, offset, zone)
                    }
                    None => (local, parts.offset.unwrap_or(0), String::new()),
                },
            };
            Value::ZonedDateTime(ZonedDateTime::from_local(local, offset, zone_id).map_err(terr)?)
        }
    })
}

/// Truncates `(date, time)` to the start of `unit`; `None` for an unknown unit.
fn truncate_parts(unit: &str, date: Date, time: LocalTime) -> Option<(Date, LocalTime)> {
    let (y, m, _) = date.to_ymd();
    let midnight = LocalTime::default();
    let date_of = |year: i64, month: u32, day: u32| Date::from_ymd(year, month, day).ok();
    Some(match unit {
        "millennium" => (date_of(y.div_euclid(1000) * 1000, 1, 1)?, midnight),
        "century" => (date_of(y.div_euclid(100) * 100, 1, 1)?, midnight),
        "decade" => (date_of(y.div_euclid(10) * 10, 1, 1)?, midnight),
        "year" => (date_of(y, 1, 1)?, midnight),
        "weekyear" => (
            Date::from_year_week_day(date.week_year(), 1, 1).ok()?,
            midnight,
        ),
        "quarter" => (date_of(y, (m - 1) / 3 * 3 + 1, 1)?, midnight),
        "month" => (date_of(y, m, 1)?, midnight),
        "week" => {
            // Back to Monday of this ISO week.
            let dow = date.week_day(); // Monday = 1
            let monday = Date {
                days_since_epoch: date.days_since_epoch - (dow - 1),
            };
            (monday, midnight)
        }
        "day" => (date, midnight),
        "hour" => (
            date,
            LocalTime::from_hms_nanos(time.hour() as u32, 0, 0, 0).ok()?,
        ),
        "minute" => (
            date,
            LocalTime::from_hms_nanos(time.hour() as u32, time.minute() as u32, 0, 0).ok()?,
        ),
        "second" => (
            date,
            LocalTime::from_hms_nanos(
                time.hour() as u32,
                time.minute() as u32,
                time.second() as u32,
                0,
            )
            .ok()?,
        ),
        "millisecond" => (
            date,
            LocalTime::from_hms_nanos(
                time.hour() as u32,
                time.minute() as u32,
                time.second() as u32,
                (time.millisecond() * 1_000_000) as u32,
            )
            .ok()?,
        ),
        "microsecond" => (
            date,
            LocalTime::from_hms_nanos(
                time.hour() as u32,
                time.minute() as u32,
                time.second() as u32,
                (time.microsecond() * 1_000) as u32,
            )
            .ok()?,
        ),
        _ => return None,
    })
}

// =================================================================================================
// Rendering
// =================================================================================================

/// The canonical ISO-8601 string of a temporal value (`toString`, result rendering), or `None`
/// for a non-temporal value.
pub(crate) fn to_iso(v: &Value) -> Option<String> {
    Some(match v {
        Value::Date(d) => d.to_iso_string(),
        Value::LocalTime(t) => t.to_iso_string(),
        Value::ZonedTime(t) => t.to_iso_string(),
        Value::LocalDateTime(dt) => dt.to_iso_string(),
        Value::ZonedDateTime(z) => z.to_iso_string(),
        Value::Duration(d) => d.to_iso_string(),
        _ => return None,
    })
}

/// A short human kind name for error messages.
fn kind_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "Null",
        Value::Boolean(_) => "Boolean",
        Value::Integer(_) => "Integer",
        Value::Float(_) => "Float",
        Value::String(_) => "String",
        Value::Bytes(_) => "Bytes",
        Value::List(_) => "List",
        Value::Map(_) => "Map",
        Value::Date(_) => "Date",
        Value::LocalTime(_) => "LocalTime",
        Value::ZonedTime(_) => "Time",
        Value::LocalDateTime(_) => "LocalDateTime",
        Value::ZonedDateTime(_) => "DateTime",
        Value::Duration(_) => "Duration",
        Value::Point(_) => "Point",
    }
}

#[cfg(test)]
mod tests {
    //! Regression pins for IANA zone resolution (`rmp` task #60) and the adjacent
    //! component-map fixes, asserted on the canonical ISO renderings the TCK compares against.

    use super::*;

    /// A captured statement clock for the constructor tests. The argument-bearing constructors
    /// never read it; the zero-argument current-instant tests only need a single shared capture.
    fn test_clock() -> StatementClock {
        StatementClock::capture()
    }

    /// Builds a `Value::Map` from `(key, value)` pairs.
    fn map(entries: &[(&str, Value)]) -> Value {
        Value::Map(
            entries
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        )
    }

    fn iso(v: &Value) -> String {
        to_iso(v).expect("temporal value renders")
    }

    fn dt(arg: Value) -> Value {
        construct("datetime", Some(&arg), &test_clock()).expect("datetime() constructs")
    }

    #[test]
    fn named_zone_resolves_dst_summer_and_winter_offsets() {
        // Temporal1 [10]: the same zone and year, opposite sides of the Swedish DST window.
        let winter = dt(map(&[
            ("year", Value::Integer(1984)),
            ("month", Value::Integer(10)),
            ("day", Value::Integer(11)),
            ("hour", Value::Integer(12)),
            ("timezone", Value::String("Europe/Stockholm".into())),
        ]));
        assert_eq!(iso(&winter), "1984-10-11T12:00+01:00[Europe/Stockholm]");
        let summer = dt(map(&[
            ("year", Value::Integer(1984)),
            ("ordinalDay", Value::Integer(202)),
            ("timezone", Value::String("Europe/Stockholm".into())),
        ]));
        assert_eq!(iso(&summer), "1984-07-20T00:00+02:00[Europe/Stockholm]");
    }

    #[test]
    fn named_zone_string_resolves_historical_offset() {
        // Temporal2 [6]: 1818 Stockholm is the pre-standard-time local mean time, which differs
        // from every offset the zone has used since 1879.
        let parsed = dt(Value::String(
            "1818-07-21T21:40:32.142[Europe/Stockholm]".into(),
        ));
        assert_eq!(
            iso(&parsed),
            "1818-07-21T21:40:32.142+00:53:28[Europe/Stockholm]"
        );
        // An explicit offset is kept when consistent with the zone.
        let strict = dt(Value::String(
            "2015-07-21T21:40:32.142+02:00[Europe/Stockholm]".into(),
        ));
        assert_eq!(
            iso(&strict),
            "2015-07-21T21:40:32.142+02:00[Europe/Stockholm]"
        );
    }

    #[test]
    fn zone_conversion_preserves_the_instant() {
        // Temporal3 [11]: `{datetime: d, timezone: tz}` re-expresses the instant in the target
        // zone before overrides apply.
        let base = dt(map(&[
            ("year", Value::Integer(1984)),
            ("month", Value::Integer(10)),
            ("day", Value::Integer(11)),
            ("hour", Value::Integer(12)),
            ("timezone", Value::String("Europe/Stockholm".into())),
        ]));
        let converted = dt(map(&[
            ("datetime", base.clone()),
            ("timezone", Value::String("Pacific/Honolulu".into())),
        ]));
        assert_eq!(iso(&converted), "1984-10-11T01:00-10:00[Pacific/Honolulu]");
        let (Value::ZonedDateTime(b), Value::ZonedDateTime(c)) = (&base, &converted) else {
            panic!("zoned datetimes expected");
        };
        assert_eq!(b.epoch_seconds(), c.epoch_seconds());
        // Overrides over an *inherited* named zone re-resolve the offset for the new local
        // value (Temporal3 [10]/[11]: moving a Stockholm local across the DST boundary flips
        // the offset).
        let moved = dt(map(&[
            ("datetime", base),
            ("month", Value::Integer(3)),
            ("day", Value::Integer(28)),
        ]));
        assert_eq!(iso(&moved), "1984-03-28T12:00+02:00[Europe/Stockholm]");
    }

    #[test]
    fn dst_gap_construction_moves_the_local_time_later() {
        // Stockholm springs forward 2017-03-26 02:00 → 03:00: the skipped 02:30 is adjusted
        // later by the gap, per java.time.ZonedDateTime.ofLocal (Neo4j's reference behaviour).
        let gap = dt(map(&[
            ("year", Value::Integer(2017)),
            ("month", Value::Integer(3)),
            ("day", Value::Integer(26)),
            ("hour", Value::Integer(2)),
            ("minute", Value::Integer(30)),
            ("timezone", Value::String("Europe/Stockholm".into())),
        ]));
        assert_eq!(iso(&gap), "2017-03-26T03:30+02:00[Europe/Stockholm]");
    }

    #[test]
    fn unknown_zone_id_is_a_typed_error() {
        let err = construct(
            "datetime",
            Some(&map(&[
                ("year", Value::Integer(2017)),
                ("timezone", Value::String("Mars/Olympus_Mons".into())),
            ])),
            &test_clock(),
        )
        .expect_err("unknown zone must not resolve");
        assert!(matches!(err, EvalError::TypeError { .. }), "{err:?}");
        let err = construct(
            "datetime",
            Some(&Value::String("2017-01-01T12:00[Mars/Olympus_Mons]".into())),
            &test_clock(),
        )
        .expect_err("unknown zone must not parse");
        assert!(matches!(err, EvalError::TypeError { .. }), "{err:?}");
    }

    #[test]
    fn duration_in_seconds_resolves_a_local_operand_in_the_named_zone() {
        // Temporal10 [8]: midnight is still +02:00, the local 04:00 the same day is already
        // +01:00 after the fall-back, so the distance is 5 hours, not 4.
        let a = dt(map(&[
            ("year", Value::Integer(2017)),
            ("month", Value::Integer(10)),
            ("day", Value::Integer(29)),
            ("hour", Value::Integer(0)),
            ("timezone", Value::String("Europe/Stockholm".into())),
        ]));
        let b = construct(
            "localdatetime",
            Some(&map(&[
                ("year", Value::Integer(2017)),
                ("month", Value::Integer(10)),
                ("day", Value::Integer(29)),
                ("hour", Value::Integer(4)),
            ])),
            &test_clock(),
        )
        .expect("localdatetime() constructs");
        let d = duration_between("duration.inseconds", &a, &b).expect("computes");
        assert_eq!(iso(&d), "PT5H");
    }

    #[test]
    fn truncation_with_a_named_zone_override_resolves_the_truncated_local() {
        // Temporal9 [2]: truncation never converts; the named-zone override resolves the
        // offset at the truncated wall clock.
        let input = dt(map(&[
            ("year", Value::Integer(1984)),
            ("month", Value::Integer(10)),
            ("day", Value::Integer(11)),
            ("hour", Value::Integer(12)),
            ("minute", Value::Integer(31)),
            ("timezone", Value::String("-01:00".into())),
        ]));
        let truncated = truncate(
            "datetime.truncate",
            &Value::String("hour".into()),
            &input,
            Some(&map(&[(
                "timezone",
                Value::String("Europe/Stockholm".into()),
            )])),
        )
        .expect("truncates");
        assert_eq!(iso(&truncated), "1984-10-11T12:00+01:00[Europe/Stockholm]");
    }

    #[test]
    fn truncation_sub_second_overrides_are_positional_fields() {
        // Temporal9 [2] (pre-existing bug fixed in this cycle): truncating to 'millisecond'
        // keeps `.645`; `{nanosecond: 2}` then sets the nanosecond-of-microsecond field.
        let input = dt(map(&[
            ("year", Value::Integer(1984)),
            ("month", Value::Integer(10)),
            ("day", Value::Integer(11)),
            ("hour", Value::Integer(12)),
            ("minute", Value::Integer(31)),
            ("second", Value::Integer(14)),
            ("nanosecond", Value::Integer(645_876_123)),
            ("timezone", Value::String("+01:00".into())),
        ]));
        let truncated = truncate(
            "datetime.truncate",
            &Value::String("millisecond".into()),
            &input,
            Some(&map(&[("nanosecond", Value::Integer(2))])),
        )
        .expect("truncates");
        assert_eq!(iso(&truncated), "1984-10-11T12:31:14.645000002+01:00");
    }

    #[test]
    fn week_overrides_apply_over_a_base_date() {
        // Temporal1 [1] / Temporal3 [1] (pre-existing bug fixed in this cycle): week-calendar
        // components over a `date:` base default to the base's week-year/week/week-day.
        let base = construct(
            "date",
            Some(&Value::String("1816-12-30".into())),
            &test_clock(),
        )
        .expect("date() constructs");
        let picked = construct(
            "date",
            Some(&map(&[
                ("date", base),
                ("week", Value::Integer(2)),
                ("dayOfWeek", Value::Integer(3)),
            ])),
            &test_clock(),
        )
        .expect("date() selects");
        assert_eq!(iso(&picked), "1817-01-08");
    }

    #[test]
    fn duration_between_with_a_time_only_operand_uses_the_time_axis() {
        // Temporal10 [2] (pre-existing bug fixed in this cycle): `date × localtime` measures
        // time-of-day only — the date contributes nothing.
        let a = construct(
            "date",
            Some(&Value::String("1984-10-11".into())),
            &test_clock(),
        )
        .expect("date() constructs");
        let b = construct(
            "localtime",
            Some(&Value::String("16:30".into())),
            &test_clock(),
        )
        .expect("localtime() constructs");
        let d = duration_between("duration.between", &a, &b).expect("computes");
        assert_eq!(iso(&d), "PT16H30M");
    }

    /// `Temporal4.feature` [13]: every constructor and clock variant propagates a `null` argument
    /// to `null` (rather than raising). The base names plus the 15 clock variants.
    #[test]
    fn clock_variants_and_bases_propagate_null() {
        const NAMES: &[&str] = &[
            "date",
            "date.transaction",
            "date.statement",
            "date.realtime",
            "localtime",
            "localtime.transaction",
            "localtime.statement",
            "localtime.realtime",
            "time",
            "time.transaction",
            "time.statement",
            "time.realtime",
            "localdatetime",
            "localdatetime.transaction",
            "localdatetime.statement",
            "localdatetime.realtime",
            "datetime",
            "datetime.transaction",
            "datetime.statement",
            "datetime.realtime",
            "duration",
        ];
        for name in NAMES {
            let out = construct(name, Some(&Value::Null), &test_clock())
                .unwrap_or_else(|e| panic!("{name}(null) should be null, got error: {e:?}"));
            assert_eq!(out, Value::Null, "{name}(null) must be null");
        }
    }

    /// A clock variant constructs the same value type as its base constructor when given a
    /// projection argument (the optional value/timezone form), confirming the suffix strip routes
    /// to the right base.
    #[test]
    fn clock_variants_route_to_their_base_type() {
        let from_str = |name: &str, s: &str| {
            construct(name, Some(&Value::String(s.to_owned())), &test_clock())
                .unwrap_or_else(|e| panic!("{name} constructs: {e:?}"))
        };
        assert!(matches!(
            from_str("date.transaction", "1984-10-11"),
            Value::Date(_)
        ));
        assert!(matches!(
            from_str("localtime.statement", "12:00"),
            Value::LocalTime(_)
        ));
        assert!(matches!(
            from_str("time.realtime", "12:00"),
            Value::ZonedTime(_)
        ));
        assert!(matches!(
            from_str("localdatetime.realtime", "1912-01-01T00:00"),
            Value::LocalDateTime(_)
        ));
        assert!(matches!(
            from_str("datetime.transaction", "1912-01-01T00:00Z"),
            Value::ZonedDateTime(_)
        ));
    }

    /// The zero-argument "current instant" form now constructs the base type from the statement
    /// clock seam (`rmp` task #140) — for the bare constructor and every clock variant. Each base
    /// is checked across all granularities (bare / `.statement` / `.transaction` / `.realtime`).
    #[test]
    fn clock_variants_zero_arg_constructs_current_instant() {
        let clock = test_clock();
        // The expected variant kind is asserted by matching the base name against the built value.
        let expected_kind_ok = |base: &str, v: &Value| match base {
            "date" => matches!(v, Value::Date(_)),
            "localtime" => matches!(v, Value::LocalTime(_)),
            "time" => matches!(v, Value::ZonedTime(_)),
            "localdatetime" => matches!(v, Value::LocalDateTime(_)),
            "datetime" => matches!(v, Value::ZonedDateTime(_)),
            other => panic!("unexpected base {other}"),
        };
        for base in ["date", "localtime", "time", "localdatetime", "datetime"] {
            for suffix in ["", ".statement", ".transaction", ".realtime"] {
                let name = format!("{base}{suffix}");
                let v = construct(&name, None, &clock)
                    .unwrap_or_else(|e| panic!("{name}() should construct, got error: {e:?}"));
                assert!(
                    expected_kind_ok(base, &v),
                    "{name}() built the wrong value kind: {v:?}"
                );
            }
        }
    }

    /// The statement clock is fixed: two `date()` reads from the *same* clock are equal — the
    /// unit-level form of the TCK `duration.inSeconds(date(), date()) == 'PT0S'` property
    /// (`Temporal10.feature` [12]).
    #[test]
    fn same_clock_yields_equal_current_instants() {
        let clock = test_clock();
        for base in ["date", "localtime", "time", "localdatetime", "datetime"] {
            let a = construct(base, None, &clock).expect("constructs");
            let b = construct(base, None, &clock).expect("constructs");
            assert_eq!(a, b, "{base}() twice from one clock must be equal");
        }
        // And across the `.statement` spelling, which shares the same instant.
        assert_eq!(
            construct("date", None, &clock).expect("constructs"),
            construct("date.statement", None, &clock).expect("constructs"),
            "date() and date.statement() must share the statement instant"
        );
    }

    /// `duration()` has no zero-argument current-instant form and is still rejected.
    #[test]
    fn duration_zero_arg_is_unsupported() {
        let clock = test_clock();
        assert!(matches!(
            construct("duration", None, &clock),
            Err(EvalError::UnsupportedFunction { .. })
        ));
    }

    #[test]
    fn datetime_from_epoch_builds_a_utc_instant() {
        // Temporal1 [11]: `datetime.fromepoch(seconds, nanoseconds)` is the UTC instant the
        // epoch second count denotes, with the nanosecond field added on top.
        let d = from_epoch_seconds(&Value::Integer(416_779), &Value::Integer(999_999_999))
            .expect("fromepoch constructs");
        assert_eq!(iso(&d), "1970-01-05T19:46:19.999999999Z");
    }

    #[test]
    fn datetime_from_epoch_millis_builds_a_utc_instant() {
        // Temporal1 [11]: `datetime.fromepochmillis(milliseconds)` is the UTC instant the
        // epoch millisecond count denotes.
        let d = from_epoch_millis(&Value::Integer(237_821_673_987))
            .expect("fromepochmillis constructs");
        assert_eq!(iso(&d), "1977-07-15T13:34:33.987Z");
    }

    #[test]
    fn datetime_from_epoch_before_the_epoch_keeps_a_non_negative_nanos_field() {
        // A negative epoch instant decomposes with Euclidean carry: one nanosecond before the
        // epoch is `1969-12-31T23:59:59.999999999Z`, not a negative nanosecond field.
        let d = from_epoch_seconds(&Value::Integer(0), &Value::Integer(-1))
            .expect("fromepoch constructs");
        assert_eq!(iso(&d), "1969-12-31T23:59:59.999999999Z");
    }

    #[test]
    fn datetime_from_epoch_propagates_null_and_rejects_non_integers() {
        assert_eq!(
            from_epoch_seconds(&Value::Null, &Value::Integer(0)).expect("null propagates"),
            Value::Null
        );
        assert_eq!(
            from_epoch_millis(&Value::Null).expect("null propagates"),
            Value::Null
        );
        assert!(matches!(
            from_epoch_seconds(&Value::Float(1.5), &Value::Integer(0)),
            Err(EvalError::TypeError { .. })
        ));
    }

    #[test]
    fn duration_between_equal_instants_is_zero() {
        // Temporal10 [12]: `duration.inSeconds(x, x)` for any temporal `x` is the zero duration.
        for value in [
            construct(
                "localtime",
                Some(&Value::String("12:34:54.7".into())),
                &test_clock(),
            )
            .unwrap(),
            construct(
                "date",
                Some(&Value::String("1984-10-11".into())),
                &test_clock(),
            )
            .unwrap(),
            construct(
                "localdatetime",
                Some(&Value::String("1984-10-11T12:00".into())),
                &test_clock(),
            )
            .unwrap(),
            construct(
                "datetime",
                Some(&Value::String("1984-10-11T12:00Z".into())),
                &test_clock(),
            )
            .unwrap(),
        ] {
            let d = duration_between("duration.inseconds", &value, &value).expect("computes");
            assert_eq!(
                iso(&d),
                "PT0S",
                "duration between equal instants must be zero"
            );
        }
    }

    #[test]
    fn duration_between_splits_a_sub_second_remainder_with_floor_semantics() {
        // Temporal10 [1]: a backward difference of -23h59m59.9s reports `seconds = -86400` and
        // `nanosecondsOfSecond = 100000000` (floor decomposition), while the ISO string keeps
        // the trunc-toward-zero form `PT-23H-59M-59.9S`.
        let a = construct(
            "localdatetime",
            Some(&Value::String("2018-01-02T10:00:00.1".into())),
            &test_clock(),
        )
        .unwrap();
        let b = construct(
            "localdatetime",
            Some(&Value::String("2018-01-01T10:00:00.2".into())),
            &test_clock(),
        )
        .unwrap();
        let d = duration_between("duration.between", &a, &b).expect("computes");
        assert_eq!(iso(&d), "PT-23H-59M-59.9S");
        let Value::Duration(dur) = d else {
            panic!("duration.between yields a Duration")
        };
        assert_eq!(dur.seconds_total(), -86_400);
        assert_eq!(dur.nanoseconds_of_second(), 100_000_000);
    }

    #[test]
    fn datetime_from_date_and_zoned_time_reresolves_the_source_zone_at_the_final_date() {
        // Temporal3 [10]: a Stockholm October time reused under a late-March date carries
        // +02:00 (summer), not its stored +01:00, when converted to another zone.
        let other_date = construct(
            "localdatetime",
            Some(&map(&[
                ("year", Value::Integer(1984)),
                ("week", Value::Integer(10)),
                ("dayOfWeek", Value::Integer(3)),
                ("hour", Value::Integer(12)),
            ])),
            &test_clock(),
        )
        .unwrap();
        let other_time = dt(map(&[
            ("year", Value::Integer(1984)),
            ("month", Value::Integer(10)),
            ("day", Value::Integer(11)),
            ("hour", Value::Integer(12)),
            ("timezone", Value::String("Europe/Stockholm".into())),
        ]));
        let result = construct(
            "datetime",
            Some(&map(&[
                ("date", other_date),
                ("time", other_time),
                ("day", Value::Integer(28)),
                ("second", Value::Integer(42)),
                ("timezone", Value::String("Pacific/Honolulu".into())),
            ])),
            &test_clock(),
        )
        .expect("datetime() selects");
        assert_eq!(iso(&result), "1984-03-28T00:00:42-10:00[Pacific/Honolulu]");
    }
}
