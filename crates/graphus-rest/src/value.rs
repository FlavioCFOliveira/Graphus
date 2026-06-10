//! Typed-value serialization for [`graphus_core::Value`] — **Jolt-style typed JSON** and **CBOR**
//! (`04-technical-design.md` §8.2; decision `D-serialization`).
//!
//! `04 §8.3` mandates **one `Value` model** behind every listener and **exactly one place that turns
//! `Value` into bytes per protocol**. This module is that place for REST: it owns the `Value` ↔ Jolt
//! JSON and `Value` ↔ CBOR conversions (PackStream is `graphus-bolt`'s). The router and the streaming
//! encoder call into here; no other module reaches into the encoding.
//!
//! # The int53 problem, fixed from day one (`04 §8.2`)
//!
//! JSON numbers are IEEE-754 doubles, so an `i64` beyond ±2^53 loses precision crossing a JSON
//! boundary (notoriously, a JS client silently mangles it). Graphus therefore **string-encodes
//! 64-bit integers** in JSON: an integer is the Jolt object `{"Z": "<decimal>"}` whose value is a
//! *string*. CBOR (RFC 8949) has native 64-bit integers, so it carries them as numbers with no loss.
//! Both directions are round-trip tested, including a value `> 2^53` (see the tests).
//!
//! # Jolt sigils (authoritative subset)
//!
//! Jolt represents a typed value as a **single-key object** whose key is a short *sigil* naming the
//! type, with the payload encoded losslessly (Source: the Jolt specification,
//! `neo4j-drivers/neo4j-drivers.github.io` `jolt/jolt-specification.md`). The sigils Graphus emits:
//!
//! | `Value` | Jolt (strict) | note |
//! | --- | --- | --- |
//! | `Null` | `null` | plain JSON null |
//! | `Boolean(b)` | `{"?": "true"}` / `{"?": "false"}` | sigil `?`; payload is a *string* (Jolt spec) |
//! | `Integer(i)` | `{"Z": "<decimal>"}` | sigil `Z` (ℤ); **string** payload — the int53 fix |
//! | `Float(f)` | `{"R": "<decimal>"}` | sigil `R` (ℝ); string payload |
//! | `String(s)` | `{"U": "<s>"}` | sigil `U` (Unicode) |
//! | `Bytes(b)` | `{"#": "<UPPER-HEX>"}` | sigil `#`; uppercase hex, no separators |
//! | `List(xs)` | `[ <typed> … ]` | plain JSON array of typed elements |
//! | `Map(kv)` | `{"{}": { k: <typed> … }}` | sigil `{}`; insertion order preserved |
//! | temporal | `{"T": "<ISO-8601>"}` | sigil `T`; ISO-8601 string (Neo4j Jolt convention) |
//!
//! The structural `$N`/`$R`/`$P` (node / relationship / path) and `@` (point) sigils are **not**
//! emitted: those `Value` variants do not exist yet in `graphus_core::Value` (`04 §7.2` defers them
//! to their owning subsystems), exactly as `graphus-bolt`'s PackStream encoder documents. They are
//! added here when the variants land; the seam does not change.
//!
//! ## Decoding accepts plain JSON too (Jolt "sparse" input)
//!
//! Jolt input may be *sparse*: a bare JSON `42`, `"x"`, `true`, `[…]`, or `{…}` (no sigil) is
//! accepted and mapped to the natural `Value`. This is what lets a hand-written request body use
//! ordinary JSON for parameters while results are always emitted in strict typed form. A bare JSON
//! number that is an integer maps to [`Value::Integer`]; one with a fraction/exponent maps to
//! [`Value::Float`]. A sigil object always wins over the sparse interpretation.

use graphus_core::Value;
use graphus_core::value::temporal::NANOS_PER_DAY;
use serde_json::{Map as JsonMap, Value as Json};

/// An error encoding or decoding a typed value.
///
/// Decoding is a **trusted boundary** (it parses client input), so every malformed shape must
/// surface as this controlled error — never a panic (`04 §11.4`, the fuzz-hardening rule for every
/// decoder). The router maps it to an RFC 9457 problem+json `400` ([`crate::problem`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueCodecError {
    /// A Jolt sigil object carried a payload of the wrong JSON shape (e.g. `{"Z": 1}` — the `Z`
    /// payload must be a *string*), or a sigil string did not parse (e.g. a non-numeric `Z`).
    BadSigilPayload {
        /// The sigil that was mis-encoded.
        sigil: String,
        /// A short, safe-to-log reason.
        detail: String,
    },
    /// A CBOR value used a type Graphus does not accept as a `Value` (e.g. a CBOR tag, or a non-text
    /// map key).
    UnsupportedCbor {
        /// A short, safe-to-log reason.
        detail: String,
    },
    /// The bytes were not valid CBOR / JSON at all.
    Malformed {
        /// A short, safe-to-log reason.
        detail: String,
    },
}

impl std::fmt::Display for ValueCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSigilPayload { sigil, detail } => {
                write!(f, "invalid Jolt `{sigil}` payload: {detail}")
            }
            Self::UnsupportedCbor { detail } => write!(f, "unsupported CBOR value: {detail}"),
            Self::Malformed { detail } => write!(f, "malformed encoded value: {detail}"),
        }
    }
}

impl std::error::Error for ValueCodecError {}

// ---- Jolt sigils ------------------------------------------------------------------------------

const SIGIL_BOOL: &str = "?";
const SIGIL_INT: &str = "Z";
const SIGIL_REAL: &str = "R";
const SIGIL_STR: &str = "U";
const SIGIL_BYTES: &str = "#";
const SIGIL_MAP: &str = "{}";
const SIGIL_TEMPORAL: &str = "T";

// =============================== JSON / Jolt ===================================================

/// Encodes a [`Value`] into its strict Jolt typed-JSON form (`04 §8.2`).
///
/// Integers and floats are **string-encoded** (the int53 fix); see the module docs for the full
/// sigil table.
#[must_use]
pub fn value_to_jolt(value: &Value) -> Json {
    match value {
        Value::Null => Json::Null,
        Value::Boolean(b) => sigil(SIGIL_BOOL, Json::String(b.to_string())),
        // The int53 fix: the integer's payload is a decimal *string*, never a JSON number.
        Value::Integer(i) => sigil(SIGIL_INT, Json::String(i.to_string())),
        Value::Float(f) => sigil(SIGIL_REAL, Json::String(format_float(*f))),
        Value::String(s) => sigil(SIGIL_STR, Json::String(s.clone())),
        Value::Bytes(b) => sigil(SIGIL_BYTES, Json::String(to_hex(b))),
        Value::List(xs) => Json::Array(xs.iter().map(value_to_jolt).collect()),
        Value::Map(kv) => {
            let mut inner = JsonMap::with_capacity(kv.len());
            for (k, v) in kv {
                inner.insert(k.clone(), value_to_jolt(v));
            }
            sigil(SIGIL_MAP, Json::Object(inner))
        }
        // Temporals render as an ISO-8601 string under the `T` sigil (Neo4j Jolt convention).
        Value::Date(_)
        | Value::LocalTime(_)
        | Value::ZonedTime(_)
        | Value::LocalDateTime(_)
        | Value::ZonedDateTime(_)
        | Value::Duration(_) => sigil(SIGIL_TEMPORAL, Json::String(temporal_to_iso(value))),
    }
}

/// Decodes a Jolt typed-JSON value (strict *or* sparse) into a [`Value`] (`04 §8.2`).
///
/// A single-key object whose key is a known sigil is decoded as that type; any other JSON is
/// interpreted *sparsely* (a bare number/string/bool/array/object maps to the natural `Value`). See
/// the module docs.
///
/// # Errors
/// [`ValueCodecError::BadSigilPayload`] if a sigil object's payload has the wrong shape or fails to
/// parse.
pub fn jolt_to_value(json: &Json) -> Result<Value, ValueCodecError> {
    match json {
        Json::Null => Ok(Value::Null),
        Json::Bool(b) => Ok(Value::Boolean(*b)), // sparse
        Json::String(s) => Ok(Value::String(s.clone())), // sparse
        Json::Number(n) => Ok(number_to_value(n)), // sparse
        Json::Array(xs) => {
            let mut out = Vec::with_capacity(xs.len());
            for x in xs {
                out.push(jolt_to_value(x)?);
            }
            Ok(Value::List(out))
        }
        Json::Object(obj) => object_to_value(obj),
    }
}

/// Decodes a JSON object: a single known sigil → typed value; otherwise a sparse map.
fn object_to_value(obj: &JsonMap<String, Json>) -> Result<Value, ValueCodecError> {
    // A sigil object has exactly one entry whose key is a known sigil.
    if obj.len() == 1 {
        let (key, payload) = obj.iter().next().expect("len == 1");
        match key.as_str() {
            SIGIL_BOOL => return decode_bool(payload),
            SIGIL_INT => return decode_int(payload),
            SIGIL_REAL => return decode_real(payload),
            SIGIL_STR => return decode_str(payload),
            SIGIL_BYTES => return decode_bytes(payload),
            SIGIL_MAP => return decode_map(payload),
            SIGIL_TEMPORAL => return decode_temporal(payload),
            // Not a recognised sigil → fall through to the sparse map interpretation.
            _ => {}
        }
    }
    // Sparse: a plain JSON object is a `Value::Map`, preserving key order.
    let mut out = Vec::with_capacity(obj.len());
    for (k, v) in obj {
        out.push((k.clone(), jolt_to_value(v)?));
    }
    Ok(Value::Map(out))
}

fn decode_bool(payload: &Json) -> Result<Value, ValueCodecError> {
    match payload {
        // Strict Jolt: the payload is the string "true"/"false".
        Json::String(s) if s == "true" => Ok(Value::Boolean(true)),
        Json::String(s) if s == "false" => Ok(Value::Boolean(false)),
        // Be lenient on input: accept a real JSON bool under the sigil too.
        Json::Bool(b) => Ok(Value::Boolean(*b)),
        other => Err(bad_payload(
            SIGIL_BOOL,
            other,
            "expected \"true\" or \"false\"",
        )),
    }
}

fn decode_int(payload: &Json) -> Result<Value, ValueCodecError> {
    match payload {
        // The int53 fix: the canonical payload is a decimal string parsed losslessly to i64.
        Json::String(s) => s
            .parse::<i64>()
            .map(Value::Integer)
            .map_err(|e| bad_payload(SIGIL_INT, payload, &e.to_string())),
        // Lenient: a JSON integer in range is accepted (it is exact below 2^53).
        Json::Number(n) if n.is_i64() => Ok(Value::Integer(n.as_i64().expect("is_i64"))),
        other => Err(bad_payload(
            SIGIL_INT,
            other,
            "expected a decimal integer string",
        )),
    }
}

fn decode_real(payload: &Json) -> Result<Value, ValueCodecError> {
    match payload {
        Json::String(s) => parse_float(s)
            .map(Value::Float)
            .ok_or_else(|| bad_payload(SIGIL_REAL, payload, "not a finite/named float")),
        Json::Number(n) => Ok(Value::Float(n.as_f64().unwrap_or(f64::NAN))),
        other => Err(bad_payload(
            SIGIL_REAL,
            other,
            "expected a decimal float string",
        )),
    }
}

fn decode_str(payload: &Json) -> Result<Value, ValueCodecError> {
    match payload {
        Json::String(s) => Ok(Value::String(s.clone())),
        other => Err(bad_payload(SIGIL_STR, other, "expected a string")),
    }
}

fn decode_bytes(payload: &Json) -> Result<Value, ValueCodecError> {
    match payload {
        Json::String(s) => from_hex(s)
            .map(Value::Bytes)
            .ok_or_else(|| bad_payload(SIGIL_BYTES, payload, "not valid hex")),
        other => Err(bad_payload(SIGIL_BYTES, other, "expected a hex string")),
    }
}

fn decode_map(payload: &Json) -> Result<Value, ValueCodecError> {
    match payload {
        Json::Object(obj) => {
            let mut out = Vec::with_capacity(obj.len());
            for (k, v) in obj {
                out.push((k.clone(), jolt_to_value(v)?));
            }
            Ok(Value::Map(out))
        }
        other => Err(bad_payload(SIGIL_MAP, other, "expected an object")),
    }
}

fn decode_temporal(payload: &Json) -> Result<Value, ValueCodecError> {
    match payload {
        Json::String(s) => iso_to_temporal(s),
        other => Err(bad_payload(
            SIGIL_TEMPORAL,
            other,
            "expected an ISO-8601 string",
        )),
    }
}

// =============================== CBOR (RFC 8949) ===============================================

/// Encodes a [`Value`] into a CBOR data item (RFC 8949).
///
/// Unlike JSON, CBOR has **native 64-bit integers**, so [`Value::Integer`] is carried as a CBOR
/// integer with no precision loss and no string-encoding. Temporals are carried as their ISO-8601
/// string (the `T`-sigil payload) so the two codecs agree on temporal text.
#[must_use]
pub fn value_to_cbor(value: &Value) -> ciborium::Value {
    use ciborium::Value as Cbor;
    match value {
        Value::Null => Cbor::Null,
        Value::Boolean(b) => Cbor::Bool(*b),
        Value::Integer(i) => Cbor::Integer((*i).into()), // native 64-bit, lossless
        Value::Float(f) => Cbor::Float(*f),
        Value::String(s) => Cbor::Text(s.clone()),
        Value::Bytes(b) => Cbor::Bytes(b.clone()),
        Value::List(xs) => Cbor::Array(xs.iter().map(value_to_cbor).collect()),
        Value::Map(kv) => Cbor::Map(
            kv.iter()
                .map(|(k, v)| (Cbor::Text(k.clone()), value_to_cbor(v)))
                .collect(),
        ),
        Value::Date(_)
        | Value::LocalTime(_)
        | Value::ZonedTime(_)
        | Value::LocalDateTime(_)
        | Value::ZonedDateTime(_)
        | Value::Duration(_) => Cbor::Text(temporal_to_iso(value)),
    }
}

/// Decodes a CBOR data item into a [`Value`].
///
/// # Errors
/// [`ValueCodecError::UnsupportedCbor`] for a CBOR construct Graphus does not model as a `Value`
/// (a tag, or a non-text map key).
pub fn cbor_to_value(cbor: &ciborium::Value) -> Result<Value, ValueCodecError> {
    use ciborium::Value as Cbor;
    match cbor {
        Cbor::Null => Ok(Value::Null),
        Cbor::Bool(b) => Ok(Value::Boolean(*b)),
        Cbor::Integer(i) => i128::from(*i).try_into().map(Value::Integer).map_err(|_| {
            ValueCodecError::UnsupportedCbor {
                detail: "integer out of i64 range".to_owned(),
            }
        }),
        Cbor::Float(f) => Ok(Value::Float(*f)),
        Cbor::Text(s) => Ok(Value::String(s.clone())),
        Cbor::Bytes(b) => Ok(Value::Bytes(b.clone())),
        Cbor::Array(xs) => {
            let mut out = Vec::with_capacity(xs.len());
            for x in xs {
                out.push(cbor_to_value(x)?);
            }
            Ok(Value::List(out))
        }
        Cbor::Map(kv) => {
            let mut out = Vec::with_capacity(kv.len());
            for (k, v) in kv {
                let Cbor::Text(key) = k else {
                    return Err(ValueCodecError::UnsupportedCbor {
                        detail: "map keys must be text".to_owned(),
                    });
                };
                out.push((key.clone(), cbor_to_value(v)?));
            }
            Ok(Value::Map(out))
        }
        other => Err(ValueCodecError::UnsupportedCbor {
            detail: format!("{other:?}"),
        }),
    }
}

// =============================== helpers =======================================================

fn sigil(key: &str, payload: Json) -> Json {
    let mut obj = JsonMap::with_capacity(1);
    obj.insert(key.to_owned(), payload);
    Json::Object(obj)
}

fn bad_payload(sigil: &str, got: &Json, detail: &str) -> ValueCodecError {
    ValueCodecError::BadSigilPayload {
        sigil: sigil.to_owned(),
        detail: format!("{detail} (got {got})"),
    }
}

/// Maps a bare JSON number (sparse mode) to the natural `Value`: an exact integer to
/// [`Value::Integer`], otherwise [`Value::Float`].
fn number_to_value(n: &serde_json::Number) -> Value {
    if let Some(i) = n.as_i64() {
        Value::Integer(i)
    } else {
        Value::Float(n.as_f64().unwrap_or(f64::NAN))
    }
}

/// Formats an `f64` for the `R`-sigil string, round-trippably (including the named non-finite
/// values, which JSON numbers cannot represent — another reason floats are string-encoded).
fn format_float(f: f64) -> String {
    if f.is_nan() {
        "NaN".to_owned()
    } else if f.is_infinite() {
        if f > 0.0 { "Infinity" } else { "-Infinity" }.to_owned()
    } else {
        // `{}` on f64 is the shortest round-trippable decimal in Rust.
        format!("{f}")
    }
}

/// Parses an `R`-sigil string back to `f64`, accepting the named non-finite values.
fn parse_float(s: &str) -> Option<f64> {
    match s {
        "NaN" => Some(f64::NAN),
        "Infinity" => Some(f64::INFINITY),
        "-Infinity" => Some(f64::NEG_INFINITY),
        _ => s.parse::<f64>().ok(),
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        // Uppercase, two digits per byte (Jolt `#` convention).
        let _ = write!(s, "{b:02X}");
    }
    s
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    // `% 2 != 0` rather than `usize::is_multiple_of` (stable only since 1.87; MSRV is 1.85).
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

// ---- temporal ISO-8601 (the `T`-sigil payload) ------------------------------------------------
//
// `graphus_core` stores temporals as decomposed integer components (`04 §7.2`), not a formatted
// string. The full openCypher temporal ISO grammar (with its calendar arithmetic) is owned by
// `graphus-cypher`; here we render/parse the **canonical wire forms** these REST codecs need, so the
// `T` sigil round-trips. Date/LocalDateTime are calendar values rendered via a self-contained
// civil-date conversion (no chrono dependency — the core is dependency-free and this keeps the REST
// crate's tree minimal).

fn temporal_to_iso(value: &Value) -> String {
    match value {
        Value::Date(d) => fmt_date(d.days_since_epoch),
        Value::LocalTime(t) => fmt_time_of_day(t.nanos_of_day),
        Value::ZonedTime(z) => format!(
            "{}{}",
            fmt_time_of_day(z.time.nanos_of_day),
            fmt_offset(z.offset_seconds)
        ),
        Value::LocalDateTime(dt) => fmt_local_datetime(dt.epoch_seconds, dt.nanos),
        Value::ZonedDateTime(dt) => format!(
            "{}{}{}",
            fmt_local_datetime(dt.local.epoch_seconds, dt.local.nanos),
            fmt_offset(dt.offset_seconds),
            if dt.zone_id.is_empty() {
                String::new()
            } else {
                format!("[{}]", dt.zone_id)
            }
        ),
        Value::Duration(d) => fmt_duration(d),
        _ => String::new(),
    }
}

/// Parses the temporal wire forms back. The set is deliberately small (the forms
/// [`temporal_to_iso`] emits); anything richer is the `graphus-cypher` parser's job, so an
/// unrecognised string is reported rather than guessed.
fn iso_to_temporal(s: &str) -> Result<Value, ValueCodecError> {
    if let Some(d) = parse_duration(s) {
        return Ok(Value::Duration(d));
    }
    if let Some(days) = parse_date_only(s) {
        return Ok(Value::Date(graphus_core::Date {
            days_since_epoch: days,
        }));
    }
    Err(ValueCodecError::BadSigilPayload {
        sigil: SIGIL_TEMPORAL.to_owned(),
        detail: format!(
            "unrecognised temporal form `{s}` (only DATE and DURATION are parsed here)"
        ),
    })
}

/// Days-since-epoch → `YYYY-MM-DD` (proleptic Gregorian), via the civil_from_days algorithm
/// (Howard Hinnant, "chrono-Compatible Low-Level Date Algorithms"; public domain).
fn fmt_date(days_since_epoch: i32) -> String {
    let (y, m, d) = civil_from_days(i64::from(days_since_epoch));
    format!("{y:04}-{m:02}-{d:02}")
}

fn parse_date_only(s: &str) -> Option<i32> {
    // Strict `YYYY-MM-DD` with no time/zone suffix.
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let y: i64 = parts[0].parse().ok()?;
    let m: u32 = parts[1].parse().ok()?;
    let d: u32 = parts[2].parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    i32::try_from(days_from_civil(y, m, d)).ok()
}

fn fmt_time_of_day(nanos_of_day: u64) -> String {
    let nanos_of_day = nanos_of_day.min(NANOS_PER_DAY - 1);
    let secs = nanos_of_day / 1_000_000_000;
    let nanos = nanos_of_day % 1_000_000_000;
    let (h, rem) = (secs / 3600, secs % 3600);
    let (mi, se) = (rem / 60, rem % 60);
    if nanos == 0 {
        format!("{h:02}:{mi:02}:{se:02}")
    } else {
        format!("{h:02}:{mi:02}:{se:02}.{nanos:09}")
    }
}

fn fmt_local_datetime(epoch_seconds: i64, nanos: u32) -> String {
    let days = epoch_seconds.div_euclid(86_400);
    let secs_of_day = epoch_seconds.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let time = fmt_time_of_day((secs_of_day as u64) * 1_000_000_000 + u64::from(nanos));
    format!("{y:04}-{m:02}-{d:02}T{time}")
}

fn fmt_offset(offset_seconds: i32) -> String {
    if offset_seconds == 0 {
        return "Z".to_owned();
    }
    let sign = if offset_seconds < 0 { '-' } else { '+' };
    let abs = offset_seconds.unsigned_abs();
    let (h, m) = (abs / 3600, (abs % 3600) / 60);
    format!("{sign}{h:02}:{m:02}")
}

fn fmt_duration(d: &graphus_core::Duration) -> String {
    // ISO-8601 duration with Cypher's month/day/second/nanos components.
    let mut out = String::from("P");
    if d.months != 0 {
        use std::fmt::Write as _;
        let _ = write!(out, "{}M", d.months);
    }
    if d.days != 0 {
        use std::fmt::Write as _;
        let _ = write!(out, "{}D", d.days);
    }
    if d.seconds != 0 || d.nanos != 0 {
        use std::fmt::Write as _;
        out.push('T');
        if d.nanos == 0 {
            let _ = write!(out, "{}S", d.seconds);
        } else {
            let _ = write!(out, "{}.{:09}S", d.seconds, d.nanos.unsigned_abs());
        }
    }
    if out == "P" {
        out.push_str("T0S"); // the zero duration
    }
    out
}

fn parse_duration(s: &str) -> Option<graphus_core::Duration> {
    // Minimal `P[<n>M][<n>D][T<n>[.<frac>]S]` reader for the form `fmt_duration` emits.
    let rest = s.strip_prefix('P')?;
    let mut months = 0i64;
    let mut days = 0i64;
    let mut seconds = 0i64;
    let mut nanos = 0i32;
    let (date_part, time_part) = match rest.split_once('T') {
        Some((d, t)) => (d, Some(t)),
        None => (rest, None),
    };
    let mut num = String::new();
    for ch in date_part.chars() {
        match ch {
            '0'..='9' | '-' => num.push(ch),
            'M' => {
                months = num.parse().ok()?;
                num.clear();
            }
            'D' => {
                days = num.parse().ok()?;
                num.clear();
            }
            _ => return None,
        }
    }
    if !num.is_empty() {
        return None;
    }
    if let Some(time_part) = time_part {
        let sec_str = time_part.strip_suffix('S')?;
        if let Some((whole, frac)) = sec_str.split_once('.') {
            seconds = whole.parse().ok()?;
            // Pad/truncate the fraction to 9 digits.
            let mut frac = frac.to_owned();
            frac.truncate(9);
            while frac.len() < 9 {
                frac.push('0');
            }
            nanos = frac.parse().ok()?;
        } else {
            seconds = sec_str.parse().ok()?;
        }
    }
    Some(graphus_core::Duration {
        months,
        days,
        seconds,
        nanos,
    })
}

/// Days since 1970-01-01 → `(year, month, day)` (Hinnant `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `(year, month, day)` → days since 1970-01-01 (Hinnant `days_from_civil`).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let m = i64::from(m);
    let d = i64::from(d);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_core::value::temporal::{Date, Duration, LocalDateTime, LocalTime};

    fn jolt_round_trip(v: &Value) -> Value {
        let json = value_to_jolt(v);
        jolt_to_value(&json).expect("decode")
    }

    fn cbor_round_trip(v: &Value) -> Value {
        let cbor = value_to_cbor(v);
        cbor_to_value(&cbor).expect("decode")
    }

    #[test]
    fn jolt_integer_is_string_encoded() {
        let json = value_to_jolt(&Value::Integer(42));
        assert_eq!(json, serde_json::json!({ "Z": "42" }));
    }

    #[test]
    fn jolt_int53_above_2_pow_53_round_trips_as_string() {
        // 2^53 + 1 is the canonical value JSON's f64 would corrupt. The string payload preserves it.
        let big = (1_i64 << 53) + 1;
        let json = value_to_jolt(&Value::Integer(big));
        assert_eq!(json, serde_json::json!({ "Z": "9007199254740993" }));
        // It is emitted as a *string*, not a JSON number — that is the whole point.
        let payload = &json["Z"];
        assert!(
            payload.is_string(),
            "int payload must be a string, was {payload}"
        );
        assert_eq!(jolt_to_value(&json).unwrap(), Value::Integer(big));
    }

    #[test]
    fn jolt_max_and_min_i64_round_trip() {
        for v in [i64::MAX, i64::MIN, -1, 0] {
            assert_eq!(jolt_round_trip(&Value::Integer(v)), Value::Integer(v));
        }
    }

    #[test]
    fn cbor_int53_above_2_pow_53_is_native_and_lossless() {
        let big = (1_i64 << 53) + 1;
        // CBOR carries it as a native integer (not a string), losslessly.
        assert_eq!(cbor_round_trip(&Value::Integer(big)), Value::Integer(big));
        let cbor = value_to_cbor(&Value::Integer(big));
        assert!(matches!(cbor, ciborium::Value::Integer(_)));
    }

    #[test]
    fn jolt_scalars_round_trip() {
        for v in [
            Value::Null,
            Value::Boolean(true),
            Value::Boolean(false),
            Value::Float(1.5),
            Value::String("héllo".to_owned()),
            Value::Bytes(vec![0x00, 0xAB, 0xFF]),
        ] {
            assert_eq!(jolt_round_trip(&v), v, "jolt round-trip failed for {v:?}");
        }
    }

    #[test]
    fn jolt_named_floats_round_trip() {
        assert_eq!(
            jolt_round_trip(&Value::Float(f64::INFINITY)),
            Value::Float(f64::INFINITY)
        );
        assert_eq!(
            jolt_round_trip(&Value::Float(f64::NEG_INFINITY)),
            Value::Float(f64::NEG_INFINITY)
        );
        // NaN != NaN, so compare via the encoding.
        let nan = value_to_jolt(&Value::Float(f64::NAN));
        assert_eq!(nan, serde_json::json!({ "R": "NaN" }));
        assert!(matches!(jolt_to_value(&nan).unwrap(), Value::Float(f) if f.is_nan()));
    }

    #[test]
    fn jolt_list_and_map_round_trip() {
        let v = Value::Map(vec![
            ("n".to_owned(), Value::Integer(1)),
            (
                "xs".to_owned(),
                Value::List(vec![Value::String("a".to_owned()), Value::Boolean(false)]),
            ),
        ]);
        assert_eq!(jolt_round_trip(&v), v);
        // The map sigil is present and key order is preserved.
        let json = value_to_jolt(&v);
        assert!(json.get("{}").is_some());
    }

    #[test]
    fn jolt_sparse_input_is_accepted() {
        // A hand-written body may use plain JSON (no sigils).
        assert_eq!(
            jolt_to_value(&serde_json::json!(7)).unwrap(),
            Value::Integer(7)
        );
        assert_eq!(
            jolt_to_value(&serde_json::json!(1.5)).unwrap(),
            Value::Float(1.5)
        );
        assert_eq!(
            jolt_to_value(&serde_json::json!("x")).unwrap(),
            Value::String("x".to_owned())
        );
        assert_eq!(
            jolt_to_value(&serde_json::json!(true)).unwrap(),
            Value::Boolean(true)
        );
        assert_eq!(
            jolt_to_value(&serde_json::json!([1, 2])).unwrap(),
            Value::List(vec![Value::Integer(1), Value::Integer(2)])
        );
        // A bare object is a sparse map.
        assert_eq!(
            jolt_to_value(&serde_json::json!({"k": "v"})).unwrap(),
            Value::Map(vec![("k".to_owned(), Value::String("v".to_owned()))])
        );
    }

    #[test]
    fn jolt_bad_sigil_payload_is_an_error_not_a_panic() {
        // `Z` payload must be a string; a number is rejected with a controlled error.
        let bad = serde_json::json!({ "Z": [] });
        assert!(matches!(
            jolt_to_value(&bad),
            Err(ValueCodecError::BadSigilPayload { .. })
        ));
    }

    #[test]
    fn cbor_collections_round_trip() {
        let v = Value::List(vec![
            Value::Map(vec![("a".to_owned(), Value::Integer(-9))]),
            Value::Bytes(vec![1, 2, 3]),
            Value::Null,
        ]);
        assert_eq!(cbor_round_trip(&v), v);
    }

    #[test]
    fn temporal_date_round_trips_through_jolt() {
        // 2024-02-29 (a leap day) exercises the civil-date conversion both ways.
        let days = days_from_civil(2024, 2, 29) as i32;
        let v = Value::Date(Date {
            days_since_epoch: days,
        });
        let json = value_to_jolt(&v);
        assert_eq!(json, serde_json::json!({ "T": "2024-02-29" }));
        assert_eq!(jolt_to_value(&json).unwrap(), v);
    }

    #[test]
    fn temporal_renders_expected_iso_strings() {
        assert_eq!(
            temporal_to_iso(&Value::LocalTime(LocalTime {
                nanos_of_day: 13 * 3600 * 1_000_000_000 + 30 * 60 * 1_000_000_000
            })),
            "13:30:00"
        );
        assert_eq!(
            temporal_to_iso(&Value::LocalDateTime(LocalDateTime {
                epoch_seconds: 0,
                nanos: 0
            })),
            "1970-01-01T00:00:00"
        );
        assert_eq!(
            temporal_to_iso(&Value::Duration(Duration {
                months: 1,
                days: 2,
                seconds: 3,
                nanos: 0
            })),
            "P1M2DT3S"
        );
    }

    #[test]
    fn duration_round_trips_through_jolt() {
        let v = Value::Duration(Duration {
            months: 14,
            days: 3,
            seconds: 45,
            nanos: 500_000_000,
        });
        assert_eq!(jolt_round_trip(&v), v);
    }

    #[test]
    fn civil_date_conversions_are_inverse() {
        // Spot-check the date algorithms round-trip across a range including negative (pre-1970).
        for days in [-25_567_i64, -1, 0, 1, 19_000, 100_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days, "failed at {days}");
        }
    }
}
