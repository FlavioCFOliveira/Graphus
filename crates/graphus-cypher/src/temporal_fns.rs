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
//! # Named deferrals
//!
//! - The zero-argument "current instant" constructor forms need the transaction clock; they raise
//!   a typed [`EvalError::UnsupportedFunction`].
//! - IANA zone-id **resolution** (`timezone: 'Europe/Stockholm'` without an explicit offset)
//!   needs a tz database; such inputs raise a typed error rather than guessing an offset.

use graphus_core::Value;
use graphus_core::temporal_calc::{self as tc, TemporalError};
use graphus_core::value::temporal::{
    Date, Duration, LocalDateTime, LocalTime, ZonedDateTime, ZonedTime,
};

use crate::eval::EvalError;

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
/// "current instant" form (a named deferral — needs the transaction clock).
pub(crate) fn construct(name: &str, arg: Option<&Value>) -> Result<Value, EvalError> {
    let Some(arg) = arg else {
        return Err(EvalError::UnsupportedFunction {
            name: format!("{name}() without arguments (requires the transaction clock)"),
        });
    };
    if arg.is_null() {
        return Ok(Value::Null);
    }
    match name {
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

fn construct_date(arg: &Value) -> Result<Value, EvalError> {
    match arg {
        Value::String(s) => Ok(Value::Date(tc::parse_date(s).map_err(terr)?)),
        Value::Date(d) => Ok(Value::Date(*d)),
        Value::LocalDateTime(dt) => Ok(Value::Date(dt.to_date_time().0)),
        Value::ZonedDateTime(z) => Ok(Value::Date(z.local.to_date_time().0)),
        Value::Map(entries) => {
            let map = ComponentMap::new(entries)?;
            Ok(Value::Date(date_from_map(&map)?))
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
            Ok(Value::LocalTime(time_from_map(&map)?))
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
        Value::LocalTime(t) => Ok(Value::ZonedTime(
            ZonedTime::new(*t, 0).map_err(terr)?,
        )),
        Value::ZonedDateTime(z) => Ok(Value::ZonedTime(
            ZonedTime::new(z.local.to_date_time().1, z.offset_seconds).map_err(terr)?,
        )),
        Value::LocalDateTime(dt) => Ok(Value::ZonedTime(
            ZonedTime::new(dt.to_date_time().1, 0).map_err(terr)?,
        )),
        Value::Map(entries) => {
            let map = ComponentMap::new(entries)?;
            let time = time_from_map(&map)?;
            let offset = map.offset_seconds()?.unwrap_or(0);
            Ok(Value::ZonedTime(ZonedTime::new(time, offset).map_err(terr)?))
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
            let Some(offset) = offset else {
                return Err(zone_resolution_error(zone.as_deref().unwrap_or("?")));
            };
            Ok(Value::ZonedDateTime(
                ZonedDateTime::from_local(local, offset, zone.unwrap_or_default())
                    .map_err(terr)?,
            ))
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
                        return Err(type_err(format!(
                            "unknown duration() component `{other}`"
                        )));
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

/// The typed error for an IANA zone id that cannot be resolved without a tz database.
fn zone_resolution_error(zone: &str) -> EvalError {
    EvalError::UnsupportedFunction {
        name: format!("IANA time-zone resolution for `{zone}` (requires a tz database)"),
    }
}

// =================================================================================================
// Component maps (`date({year: 1984, month: 10, day: 11})`, …)
// =================================================================================================

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
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| *v)
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

    /// The resolved UTC offset from a `timezone` entry, if present. An IANA name (anything that
    /// does not parse as an offset) is a typed deferral.
    fn offset_seconds(&self) -> Result<Option<i32>, EvalError> {
        match self.get("timezone") {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(tz)) => match tc::parse_offset_seconds(tz) {
                Ok(off) => Ok(Some(off)),
                Err(_) => Err(zone_resolution_error(tz)),
            },
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

/// The time carried by a `time:` / `datetime:` base entry, if any (with its offset when zoned).
fn base_time(map: &ComponentMap<'_>) -> Result<Option<(LocalTime, Option<i32>)>, EvalError> {
    for key in ["time", "datetime"] {
        match map.get(key) {
            None | Some(Value::Null) => {}
            Some(Value::LocalTime(t)) => return Ok(Some((*t, None))),
            Some(Value::ZonedTime(zt)) => return Ok(Some((zt.time, Some(zt.offset_seconds)))),
            Some(Value::LocalDateTime(dt)) => return Ok(Some((dt.to_date_time().1, None))),
            Some(Value::ZonedDateTime(z)) => {
                return Ok(Some((z.local.to_date_time().1, Some(z.offset_seconds))));
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

fn date_from_map(map: &ComponentMap<'_>) -> Result<Date, EvalError> {
    if let Some(base) = base_date(map)? {
        // Truncation-with-overrides form: `date({date: d, day: 28})`.
        let (y, m, d) = base.to_ymd();
        let year = map.int_or("year", y)?;
        let month = map.int_or("month", i64::from(m))?;
        let day = map.int_or("day", i64::from(d))?;
        return Date::from_ymd(year, clamp_u32(month)?, clamp_u32(day)?).map_err(terr);
    }
    let year = match map.get("year") {
        Some(Value::Integer(y)) => *y,
        _ => return Err(type_err("date() from a map requires a `year` component")),
    };
    if map.has("week") {
        let week = map.int_or("week", 1)?;
        let dow = map.int_or("dayofweek", 1)?;
        return Date::from_year_week_day(year, clamp_u32(week)?, clamp_u32(dow)?).map_err(terr);
    }
    if map.has("ordinalday") {
        let ordinal = map.int_or("ordinalday", 1)?;
        return Date::from_year_ordinal(year, clamp_u32(ordinal)?).map_err(terr);
    }
    if map.has("quarter") {
        let quarter = map.int_or("quarter", 1)?;
        let doq = map.int_or("dayofquarter", 1)?;
        return Date::from_year_quarter_day(year, clamp_u32(quarter)?, clamp_u32(doq)?)
            .map_err(terr);
    }
    let month = map.int_or("month", 1)?;
    let day = map.int_or("day", 1)?;
    Date::from_ymd(year, clamp_u32(month)?, clamp_u32(day)?).map_err(terr)
}

fn time_from_map(map: &ComponentMap<'_>) -> Result<LocalTime, EvalError> {
    let base = base_time(map)?.map(|(t, _)| t);
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
    let date = date_from_map(map)?;
    let time = time_from_map(map)?;
    Ok(LocalDateTime::from_date_time(date, time))
}

fn date_time_from_map(map: &ComponentMap<'_>) -> Result<Value, EvalError> {
    // Epoch forms: `datetime({epochSeconds: s [, nanosecond: n]})` / `{epochMillis: ms}`.
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
        let offset = map.offset_seconds()?.unwrap_or(0);
        // The epoch fixes the instant; the local fields shift by the offset.
        let shifted = LocalDateTime {
            epoch_seconds: local.epoch_seconds + i64::from(offset),
            nanos: local.nanos,
        };
        return Ok(Value::ZonedDateTime(
            ZonedDateTime::from_local(shifted, offset, "").map_err(terr)?,
        ));
    }
    // Inherit the offset of a zoned base (`{datetime: zdt}` / `{time: zt}`) unless overridden.
    let base_offset = base_time(map)?.and_then(|(_, off)| off);
    let local = local_date_time_from_map(map)?;
    let offset = match map.offset_seconds()? {
        Some(off) => off,
        None => base_offset.unwrap_or(0),
    };
    Ok(Value::ZonedDateTime(
        ZonedDateTime::from_local(local, offset, "").map_err(terr)?,
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
        Value::LocalTime(t) => time_component(t.hour(), t.minute(), t.second(), t.millisecond(), t.microsecond(), t.nanosecond(), &k),
        Value::ZonedTime(zt) => match k.as_str() {
            "offset" => Value::String(zt.offset_string()),
            "offsetminutes" => Value::Integer(zt.offset_minutes()),
            "offsetseconds" => Value::Integer(i64::from(zt.offset_seconds)),
            "timezone" => Value::String(zt.timezone_name()),
            _ => time_component(zt.hour(), zt.minute(), zt.second(), zt.millisecond(), zt.microsecond(), zt.nanosecond(), &k),
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
                    time_component(time.hour(), time.minute(), time.second(), time.millisecond(), time.microsecond(), time.nanosecond(), &k)
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
                    time_component(time.hour(), time.minute(), time.second(), time.millisecond(), time.microsecond(), time.nanosecond(), &k)
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
    dated: bool,
}

fn point_parts(v: &Value) -> Option<PointParts> {
    Some(match v {
        Value::Date(d) => PointParts {
            date: *d,
            time: LocalTime::default(),
            offset: None,
            dated: true,
        },
        Value::LocalDateTime(dt) => {
            let (date, time) = dt.to_date_time();
            PointParts {
                date,
                time,
                offset: None,
                dated: true,
            }
        }
        Value::ZonedDateTime(z) => {
            let (date, time) = z.local.to_date_time();
            PointParts {
                date,
                time,
                offset: Some(z.offset_seconds),
                dated: true,
            }
        }
        Value::LocalTime(t) => PointParts {
            date: Date::default(),
            time: *t,
            offset: None,
            dated: false,
        },
        Value::ZonedTime(zt) => PointParts {
            date: Date::default(),
            time: zt.time,
            offset: Some(zt.offset_seconds),
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
    let pa = point_parts(a)
        .ok_or_else(|| type_err(format!("{kind}() requires temporal arguments")))?;
    let mut pb = point_parts(b)
        .ok_or_else(|| type_err(format!("{kind}() requires temporal arguments")))?;
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

    let dated = pa.dated && pb.dated;
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
    let (date, time, override_offset) = match overrides {
        None | Some(Value::Null) => (date, time, None),
        Some(Value::Map(entries)) => {
            let map = ComponentMap::new(entries)?;
            let (y, m, d) = date.to_ymd();
            let year = map.int_or("year", y)?;
            let month = map.int_or("month", i64::from(m))?;
            let day = map.int_or("day", i64::from(d))?;
            let new_date =
                Date::from_ymd(year, clamp_u32(month)?, clamp_u32(day)?).map_err(terr)?;
            let hour = map.int_or("hour", time.hour())?;
            let minute = map.int_or("minute", time.minute())?;
            let second = map.int_or("second", time.second())?;
            let nanos = if map.has("millisecond") || map.has("microsecond") || map.has("nanosecond")
            {
                map.int_or("millisecond", 0)? * 1_000_000
                    + map.int_or("microsecond", 0)? * 1_000
                    + map.int_or("nanosecond", 0)?
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
            (new_date, new_time, map.offset_seconds()?)
        }
        Some(other) => {
            return Err(type_err(format!(
                "{func}() overrides must be a map, got {}",
                kind_name(other)
            )));
        }
    };

    let offset = override_offset.or(parts.offset).unwrap_or(0);
    Ok(match func {
        "date.truncate" => Value::Date(date),
        "localtime.truncate" => Value::LocalTime(time),
        "time.truncate" => Value::ZonedTime(ZonedTime::new(time, offset).map_err(terr)?),
        "localdatetime.truncate" => {
            Value::LocalDateTime(LocalDateTime::from_date_time(date, time))
        }
        _ => Value::ZonedDateTime(
            ZonedDateTime::from_local(LocalDateTime::from_date_time(date, time), offset, "")
                .map_err(terr)?,
        ),
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
        "weekyear" => (Date::from_year_week_day(date.week_year(), 1, 1).ok()?, midnight),
        "quarter" => (date_of(y, (m - 1) / 3 * 3 + 1, 1)?, midnight),
        "month" => (date_of(y, m, 1)?, midnight),
        "week" => {
            // Back to Monday of this ISO week.
            let dow = date.week_day(); // Monday = 1
            let monday = Date {
                days_since_epoch: date.days_since_epoch - (dow as i32 - 1),
            };
            (monday, midnight)
        }
        "day" => (date, midnight),
        "hour" => (date, LocalTime::from_hms_nanos(time.hour() as u32, 0, 0, 0).ok()?),
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
    }
}
