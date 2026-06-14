//! Self-describing **byte serialization** of overflow property values (`String`, `List` and the
//! six temporal classes) for the `strings.store` heap (`04-technical-design.md` §2.3;
//! `05-storage-format.md` §7.2; `rmp` task #43).
//!
//! [`crate::propenc`] (task #38) encodes the three **inline scalar** value classes
//! (`Boolean`/`Integer`/`Float`) into the property record's `(type_tag, value_inline)` pair. This
//! module is its variable-length counterpart: it turns a `String`, a `List` or a temporal value
//! (`Date`/`LocalTime`/`ZonedTime`/`LocalDateTime`/`ZonedDateTime`/`Duration`) into a flat
//! `Vec<u8>` that the [`heap`](crate::heap) stores as a block chain, and reads those bytes back into
//! a [`Value`]. The *store-side* glue — deciding inline vs overflow, allocating/freeing the chain,
//! and stamping the `type_tag`'s overflow bit + the head block id into `value_inline` — lives in
//! [`RecordStore`](crate::store::RecordStore); this module owns only the **pure byte format**, kept
//! here and unit-tested in isolation exactly like [`crate::propenc`] and [`crate::labels`].
//!
//! # `type_tag` layout (`04 §2.3` inline-vs-overflow bit)
//!
//! A property record's `type_tag: u8` carries the value class in its low bits and an
//! **inline-vs-overflow** flag in its top bit ([`OVERFLOW_BIT`], `0x80`, `04 §2.3`):
//!
//! * overflow bit **clear** → the value lives inline in `value_inline` ([`crate::propenc`]);
//! * overflow bit **set** → `value_inline` is the **head block id** of the value's heap chain
//!   ([`crate::heap`]), and the low bits name the class ([`TAG_STRING`] / [`TAG_LIST`]).
//!
//! The class tags continue [`crate::propenc`]'s space (`1`=bool, `2`=int, `3`=float) with
//! [`TAG_STRING`] = `4`, [`TAG_LIST`] = `5`, and the temporal classes [`TAG_DATE`] = `6` through
//! [`TAG_DURATION`] = `11`, then [`TAG_POINT`] = `12` and [`TAG_DATE_WIDE`] = `13`, so the inline
//! and overflow tag spaces never collide.
//!
//! # Backward compatibility — the `Date` widening (`rmp` task #141)
//!
//! `Date` was widened from `i32` to `i64` days-since-epoch (openCypher years
//! `-999_999_999 ..= +999_999_999`). Because the property heap is **durable on disk** and part of
//! the ACID-certified core, the widening is done with a **new self-describing tag** rather than an
//! in-place page migration:
//!
//! * the encoder *always* emits [`TAG_DATE_WIDE`] (13) with an 8-byte `i64 LE` body;
//! * the decoder reads [`TAG_DATE_WIDE`] as 8 bytes **and** still reads the legacy [`TAG_DATE`]
//!   (6) as its original 4-byte `i32 LE` body, sign-extending into the `i64` field.
//!
//! The tag carries the width, so legacy 4-byte images written before #141 remain readable
//! **byte-for-byte** with no rewrite — there is no migration step that could leave a page torn or a
//! value half-converted, and no on-disk byte already in the wild changes meaning. New writes simply
//! use the wider tag. The same rule applies to a `Date` **inside a persisted list**: the list's
//! shared element tag is [`TAG_DATE_WIDE`] for new lists and [`TAG_DATE`] for legacy ones, decoded
//! by the same per-element dispatch.
//!
//! # String format
//!
//! A `String` serializes to its **UTF-8 bytes**, nothing more — the chain's reassembled length is
//! the string length, and decode is [`String::from_utf8`]. Empty strings, multi-byte/Unicode, and
//! arbitrarily long strings all round-trip.
//!
//! # Temporal formats
//!
//! Each temporal value serializes its **decomposed integer components** fixed-width little-endian
//! (the file-wide endianness), in the field order of its `graphus_core::value::temporal` struct.
//! Signed fields are two's-complement; the only variable-width field is the `ZonedDateTime` zone
//! id, which is length-prefixed (`len: u32 LE ++ UTF-8 bytes`, the same framing as list string
//! elements):
//!
//! ```text
//!   TAG_DATE_WIDE       (13) days_since_epoch: i64 LE                              (8 bytes)
//!   TAG_DATE            (6)  days_since_epoch: i32 LE  [legacy, decode-only]       (4 bytes)
//!   TAG_LOCAL_TIME      (7)  nanos_of_day: u64 LE                                  (8 bytes)
//!   TAG_ZONED_TIME      (8)  nanos_of_day: u64 LE ++ offset_seconds: i32 LE        (12 bytes)
//!   TAG_LOCAL_DATE_TIME (9)  epoch_seconds: i64 LE ++ nanos: u32 LE                (12 bytes)
//!   TAG_ZONED_DATE_TIME (10) epoch_seconds: i64 LE ++ nanos: u32 LE ++
//!                            offset_seconds: i32 LE ++ zone_len: u32 LE ++
//!                            zone_id UTF-8 bytes                                   (16 + 4 + n bytes)
//!   TAG_DURATION        (11) months: i64 LE ++ days: i64 LE ++ seconds: i64 LE ++
//!                            nanos: i32 LE                                         (28 bytes)
//! ```
//!
//! # Spatial format (`rmp` task #73)
//!
//! A spatial `Point` serializes as its one-byte **CRS discriminant** (`graphus_core::Crs::as_byte`)
//! followed by the CRS-determined number of **little-endian `f64` coordinates** (2 for a 2D CRS, 3
//! for a 3D CRS). The CRS byte fixes the coordinate count, so the body is self-delimiting:
//!
//! ```text
//!   TAG_POINT           (12) crs: u8 ++ coord: f64 LE × {2 | 3}             (9 or 17 bytes)
//! ```
//!
//! Every component round-trips **bit-exactly**; component-range invariants (e.g. `nanos_of_day <
//! NANOS_PER_DAY`) are owned by `graphus-core`'s constructors, not re-validated by this codec —
//! exactly as the float codec round-trips every bit pattern. Decode still rejects *structural*
//! corruption (truncation, trailing bytes, invalid UTF-8 zone ids) as [`ValueDecodeError`].
//!
//! # List format (homogeneous, `05 §7.2`)
//!
//! Persisted lists are **homogeneous** in their *element class* (`05 §7.2`: *"lists must be
//! homogeneous when persisted"*). A list serializes as:
//!
//! ```text
//!   elem_tag: u8        // the shared element class (TAG_BOOL/INT/FLOAT/STRING or a temporal
//!                       // tag), or TAG_LIST_EMPTY
//!   count:    u32 LE    // number of elements
//!   element*            // `count` elements, encoded by class:
//!                       //   bool     -> 1 byte (0/1)
//!                       //   int      -> 8 bytes i64 LE (two's-complement)
//!                       //   float    -> 8 bytes f64 LE (to_bits)
//!                       //   string   -> len:u32 LE ++ UTF-8 bytes
//!                       //   temporal -> the class's top-level body (see "Temporal formats")
//! ```
//!
//! The supported element classes are the **inline scalars plus strings plus the six temporal
//! classes** — i.e. exactly the value classes Cypher most commonly stores in a property list
//! (`['x','y']`, `[1,2,3]`, `[date1, date2]`). A list whose elements are themselves lists, maps,
//! `Bytes`, or a *mix* of classes is rejected with [`ValueEncodeError`] (a clear, documented
//! deferral — never a silently-wrong or partial write); those richer element classes are a
//! follow-up that extends this format, not a redesign of it.

use graphus_core::Value;
use graphus_core::value::spatial::{Crs, Point};
use graphus_core::value::temporal::{
    Date, Duration, LocalDateTime, LocalTime, ZonedDateTime, ZonedTime,
};

use crate::propenc::{TAG_BOOL, TAG_FLOAT, TAG_INT};

/// Top bit of a property `type_tag`: set ⇒ `value_inline` is a `strings.store` head block id rather
/// than an inline value (`04 §2.3` *"inline-vs-overflow bit"*).
pub const OVERFLOW_BIT: u8 = 0b1000_0000;

/// `type_tag` low-bits class for a `String` (continues [`crate::propenc`]'s tag space).
pub const TAG_STRING: u8 = 4;
/// `type_tag` low-bits class for a `List`.
pub const TAG_LIST: u8 = 5;
/// `type_tag` low-bits class for a **legacy** narrow `Date` (body:
/// `days_since_epoch: i32 LE`, 4 bytes). **Decode-only**: kept so values written before the
/// `i64` widening (`rmp` task #141) remain byte-for-byte readable; the encoder never emits it.
/// New `Date` values use [`TAG_DATE_WIDE`].
pub const TAG_DATE: u8 = 6;
/// `type_tag` low-bits class for a `LocalTime` (body: `nanos_of_day: u64 LE`).
pub const TAG_LOCAL_TIME: u8 = 7;
/// `type_tag` low-bits class for a `ZonedTime` (body: `nanos_of_day: u64 LE ++
/// offset_seconds: i32 LE`).
pub const TAG_ZONED_TIME: u8 = 8;
/// `type_tag` low-bits class for a `LocalDateTime` (body: `epoch_seconds: i64 LE ++ nanos: u32 LE`).
pub const TAG_LOCAL_DATE_TIME: u8 = 9;
/// `type_tag` low-bits class for a `ZonedDateTime` (body: `epoch_seconds: i64 LE ++ nanos: u32 LE
/// ++ offset_seconds: i32 LE ++ zone_len: u32 LE ++ zone_id UTF-8 bytes`).
pub const TAG_ZONED_DATE_TIME: u8 = 10;
/// `type_tag` low-bits class for a `Duration` (body: `months: i64 LE ++ days: i64 LE ++
/// seconds: i64 LE ++ nanos: i32 LE`).
pub const TAG_DURATION: u8 = 11;
/// `type_tag` low-bits class for a spatial `Point` (`rmp` task #73; body: `crs: u8 (CRS
/// discriminant) ++ coord: f64 LE × CRS-dimensionality`). The CRS byte fixes the coordinate count
/// (2 or 3), so the body is self-delimiting.
pub const TAG_POINT: u8 = 12;
/// `type_tag` low-bits class for a **wide** `Date` (body: `days_since_epoch: i64 LE`, 8 bytes;
/// `rmp` task #141). This is the tag the encoder *always* emits for a `Date`; it carries the full
/// `i64` range (openCypher years `-999_999_999 ..= +999_999_999`). The legacy [`TAG_DATE`] (4-byte
/// `i32`) remains decode-only for backward compatibility — the tag is self-describing of its width,
/// so old and new images coexist with no in-place page migration.
pub const TAG_DATE_WIDE: u8 = 13;

/// `elem_tag` sentinel inside a serialized **empty** list (it has no element class to record).
const TAG_LIST_EMPTY: u8 = 0;

/// The reason a [`Value`] could not be serialized to overflow bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValueEncodeError {
    /// The value is not a `String`, a `List` or a temporal value — this codec serializes only the
    /// overflow classes (inline scalars go through [`crate::propenc`]; `Null` is never persisted;
    /// `Map`/`Bytes` property values are a separate follow-up).
    NotOverflowClass {
        /// The Cypher value-class name that this codec does not serialize.
        class: &'static str,
    },
    /// A list element is not a supported, homogeneous scalar/string/temporal. Carries the offending
    /// element's class and the list's established element class (`05 §7.2`: persisted lists are
    /// homogeneous).
    UnsupportedListElement {
        /// The class of the offending element.
        element: &'static str,
        /// The list's established element class (the first element's class).
        established: &'static str,
    },
}

impl std::fmt::Display for ValueEncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotOverflowClass { class } => write!(
                f,
                "property value of class {class} cannot be serialized to the strings/overflow heap: \
                 only String, homogeneous scalar/string/temporal List, and temporal values use the \
                 overflow heap (inline scalars use the inline codec; Map/Bytes property values are \
                 a follow-up)"
            ),
            Self::UnsupportedListElement {
                element,
                established,
            } => write!(
                f,
                "list element of class {element} cannot be persisted: a stored list must be \
                 homogeneous over the supported scalar/string/temporal element classes (this \
                 list's element class is {established}); nested lists, maps and bytes elements are \
                 a follow-up"
            ),
        }
    }
}

impl std::error::Error for ValueEncodeError {}

impl From<ValueEncodeError> for graphus_core::error::GraphusError {
    /// A serialization limit is a **runtime** error: the query is well-formed, but the value it
    /// tries to persist is outside this build's stored-property subtype (`05 §7.2`).
    fn from(e: ValueEncodeError) -> Self {
        graphus_core::error::GraphusError::Runtime(e.to_string())
    }
}

/// The reason overflow bytes could not be decoded back into a [`Value`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValueDecodeError {
    /// The `type_tag`'s class is not an overflow class this build understands (not [`TAG_STRING`],
    /// [`TAG_LIST`] nor a temporal class tag). Such a tag can only come from a newer/foreign build.
    UnknownClass {
        /// The unrecognised class (the `type_tag` with its overflow bit masked off).
        class: u8,
    },
    /// The serialized bytes are truncated, malformed, or not valid UTF-8 (a corrupt chain).
    Malformed {
        /// A short description of what was malformed.
        what: &'static str,
    },
}

impl std::fmt::Display for ValueDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownClass { class } => write!(
                f,
                "overflow property class {class} is not a String, List or temporal class this \
                 build understands"
            ),
            Self::Malformed { what } => {
                write!(f, "overflow property bytes are malformed: {what}")
            }
        }
    }
}

impl std::error::Error for ValueDecodeError {}

impl From<ValueDecodeError> for graphus_core::error::GraphusError {
    fn from(e: ValueDecodeError) -> Self {
        graphus_core::error::GraphusError::Storage(e.to_string())
    }
}

/// The static Cypher class name of `value`, for diagnostics.
fn class_name(value: &Value) -> &'static str {
    match value {
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
        Value::ZonedTime(_) => "ZonedTime",
        Value::LocalDateTime(_) => "LocalDateTime",
        Value::ZonedDateTime(_) => "ZonedDateTime",
        Value::Duration(_) => "Duration",
        Value::Point(_) => "Point",
    }
}

/// Serializes an overflow [`Value`] (`String`, `List` or a temporal value) to its self-describing
/// byte image and returns it together with the `type_tag` **class byte** (without the overflow bit;
/// the store sets that bit when it stamps the head block id into `value_inline`).
///
/// # Errors
/// - [`ValueEncodeError::NotOverflowClass`] if `value` is not a `String`/`List`/temporal value.
/// - [`ValueEncodeError::UnsupportedListElement`] if a list element is not a supported homogeneous
///   scalar/string/temporal (`05 §7.2`).
pub fn encode(value: &Value) -> Result<(u8, Vec<u8>), ValueEncodeError> {
    match value {
        Value::String(s) => Ok((TAG_STRING, s.as_bytes().to_vec())),
        Value::List(items) => Ok((TAG_LIST, encode_list(items)?)),
        Value::Point(p) => Ok((TAG_POINT, encode_point_body(p))),
        other => match temporal_tag(other) {
            Some(tag) => {
                // The largest fixed-width temporal body (Duration) is 28 bytes; a ZonedDateTime's
                // zone id grows the Vec once at most.
                let mut out = Vec::with_capacity(28);
                encode_temporal_body(other, &mut out);
                Ok((tag, out))
            }
            None => Err(ValueEncodeError::NotOverflowClass {
                class: class_name(other),
            }),
        },
    }
}

/// The overflow class tag of a temporal [`Value`], or `None` for any other class.
fn temporal_tag(v: &Value) -> Option<u8> {
    match v {
        // Always emit the wide tag for new writes; the legacy `TAG_DATE` is decode-only (#141).
        Value::Date(_) => Some(TAG_DATE_WIDE),
        Value::LocalTime(_) => Some(TAG_LOCAL_TIME),
        Value::ZonedTime(_) => Some(TAG_ZONED_TIME),
        Value::LocalDateTime(_) => Some(TAG_LOCAL_DATE_TIME),
        Value::ZonedDateTime(_) => Some(TAG_ZONED_DATE_TIME),
        Value::Duration(_) => Some(TAG_DURATION),
        _ => None,
    }
}

/// Appends the little-endian component body of a temporal value to `out` (the module-doc "Temporal
/// formats" layouts). Shared verbatim between the top-level image and the list-element encoding.
/// Callers guarantee a temporal class (a class [`temporal_tag`] accepted); anything else appends
/// nothing.
fn encode_temporal_body(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Date(d) => out.extend_from_slice(&d.days_since_epoch.to_le_bytes()),
        Value::LocalTime(t) => out.extend_from_slice(&t.nanos_of_day.to_le_bytes()),
        Value::ZonedTime(zt) => {
            out.extend_from_slice(&zt.time.nanos_of_day.to_le_bytes());
            out.extend_from_slice(&zt.offset_seconds.to_le_bytes());
        }
        Value::LocalDateTime(dt) => {
            out.extend_from_slice(&dt.epoch_seconds.to_le_bytes());
            out.extend_from_slice(&dt.nanos.to_le_bytes());
        }
        Value::ZonedDateTime(zdt) => {
            out.extend_from_slice(&zdt.local.epoch_seconds.to_le_bytes());
            out.extend_from_slice(&zdt.local.nanos.to_le_bytes());
            out.extend_from_slice(&zdt.offset_seconds.to_le_bytes());
            // Length-prefixed like a list string element. IANA zone ids are short ASCII (< 100
            // bytes); the `unwrap_or(u32::MAX)` mirrors the file-wide length-framing convention.
            let zone = zdt.zone_id.as_bytes();
            out.extend_from_slice(&(u32::try_from(zone.len()).unwrap_or(u32::MAX)).to_le_bytes());
            out.extend_from_slice(zone);
        }
        Value::Duration(d) => {
            out.extend_from_slice(&d.months.to_le_bytes());
            out.extend_from_slice(&d.days.to_le_bytes());
            out.extend_from_slice(&d.seconds.to_le_bytes());
            out.extend_from_slice(&d.nanos.to_le_bytes());
        }
        // Unreachable: callers always pass a class `temporal_tag` accepted.
        _ => {}
    }
}

/// Serializes a spatial [`Point`] to its byte body (`rmp` task #73): the one-byte CRS discriminant
/// ([`Crs::as_byte`]) followed by the **significant** coordinates ([`Point::dimensions`]) as little-
/// endian `f64`s. The CRS byte fixes the coordinate count, so the body is self-delimiting.
fn encode_point_body(p: &Point) -> Vec<u8> {
    // 1 CRS byte + up to 3 × 8 coordinate bytes.
    let mut out = Vec::with_capacity(1 + p.dimensions() * 8);
    out.push(p.crs.as_byte());
    for &c in p.coords() {
        out.extend_from_slice(&c.to_le_bytes());
    }
    out
}

/// Serializes a homogeneous list of supported scalar/string/temporal elements (`05 §7.2`).
fn encode_list(items: &[Value]) -> Result<Vec<u8>, ValueEncodeError> {
    let Some(first) = items.first() else {
        // Empty list: just the sentinel element tag and a zero count.
        let mut out = Vec::with_capacity(5);
        out.push(TAG_LIST_EMPTY);
        out.extend_from_slice(&0u32.to_le_bytes());
        return Ok(out);
    };
    let elem_tag = list_elem_tag(first)?;
    let established = class_name(first);

    let mut out = Vec::new();
    out.push(elem_tag);
    // The element count fits in u32 for any list this build can build (Cypher lists are in-memory
    // Vecs); a list longer than u32::MAX elements is not representable on these targets.
    out.extend_from_slice(&(u32::try_from(items.len()).unwrap_or(u32::MAX)).to_le_bytes());
    for item in items {
        if list_elem_tag(item)? != elem_tag {
            return Err(ValueEncodeError::UnsupportedListElement {
                element: class_name(item),
                established,
            });
        }
        encode_list_element(item, &mut out);
    }
    Ok(out)
}

/// The element tag for a supported scalar/string/temporal list element, or an error for an
/// unsupported class.
fn list_elem_tag(v: &Value) -> Result<u8, ValueEncodeError> {
    match v {
        Value::Boolean(_) => Ok(TAG_BOOL),
        Value::Integer(_) => Ok(TAG_INT),
        Value::Float(_) => Ok(TAG_FLOAT),
        Value::String(_) => Ok(TAG_STRING),
        other => temporal_tag(other).ok_or(ValueEncodeError::UnsupportedListElement {
            element: class_name(other),
            established: class_name(other),
        }),
    }
}

/// Appends one supported scalar/string/temporal element to `out` (caller guarantees a supported
/// class).
fn encode_list_element(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Boolean(b) => out.push(u8::from(*b)),
        // i64 -> u64 via `as` is a lossless two's-complement reinterpretation (MSRV 1.85 predates
        // `i64::cast_unsigned`), the exact inverse of the decode-side `as i64`.
        #[allow(clippy::cast_sign_loss)]
        Value::Integer(i) => out.extend_from_slice(&(*i as u64).to_le_bytes()),
        Value::Float(f) => out.extend_from_slice(&f.to_bits().to_le_bytes()),
        Value::String(s) => {
            let bytes = s.as_bytes();
            out.extend_from_slice(&(u32::try_from(bytes.len()).unwrap_or(u32::MAX)).to_le_bytes());
            out.extend_from_slice(bytes);
        }
        // Temporal elements share the top-level body format; any other class appends nothing
        // (unreachable: callers always pass a class `list_elem_tag` accepted).
        other => encode_temporal_body(other, out),
    }
}

/// Deserializes overflow bytes back into a [`Value`], dispatching on the `type_tag`'s **class**
/// (`class_tag` is the `type_tag` with its [`OVERFLOW_BIT`] already masked off by the caller).
///
/// # Errors
/// - [`ValueDecodeError::UnknownClass`] if `class_tag` is not [`TAG_STRING`]/[`TAG_LIST`]/a
///   temporal class tag.
/// - [`ValueDecodeError::Malformed`] if the bytes are truncated, carry trailing garbage, contain
///   invalid UTF-8, or are otherwise inconsistent (a corrupt chain).
pub fn decode(class_tag: u8, bytes: &[u8]) -> Result<Value, ValueDecodeError> {
    match class_tag {
        TAG_STRING => {
            let s = String::from_utf8(bytes.to_vec()).map_err(|_| ValueDecodeError::Malformed {
                what: "invalid UTF-8 string",
            })?;
            Ok(Value::String(s))
        }
        TAG_LIST => decode_list(bytes),
        TAG_POINT => {
            let mut cur = Cursor::new(bytes);
            let v = decode_point_body(&mut cur)?;
            if !cur.is_empty() {
                return Err(ValueDecodeError::Malformed {
                    what: "trailing bytes after the point value",
                });
            }
            Ok(v)
        }
        tag @ (TAG_DATE | TAG_DATE_WIDE | TAG_LOCAL_TIME | TAG_ZONED_TIME | TAG_LOCAL_DATE_TIME
        | TAG_ZONED_DATE_TIME | TAG_DURATION) => {
            let mut cur = Cursor::new(bytes);
            let v = decode_temporal_body(tag, &mut cur)?;
            if !cur.is_empty() {
                return Err(ValueDecodeError::Malformed {
                    what: "trailing bytes after the temporal value",
                });
            }
            Ok(v)
        }
        other => Err(ValueDecodeError::UnknownClass { class: other }),
    }
}

/// Decodes one temporal body of class `class_tag` from `cur` (the exact inverse of
/// [`encode_temporal_body`]). Shared between the top-level image and the list-element decoding;
/// the *top-level* caller additionally asserts the cursor is exhausted.
fn decode_temporal_body(class_tag: u8, cur: &mut Cursor<'_>) -> Result<Value, ValueDecodeError> {
    match class_tag {
        // Wide (current) form: 8-byte i64 body.
        TAG_DATE_WIDE => Ok(Value::Date(Date {
            days_since_epoch: cur.i64()?,
        })),
        // Legacy (decode-only) form: 4-byte i32 body, sign-extended into the i64 field (#141).
        TAG_DATE => Ok(Value::Date(Date {
            days_since_epoch: i64::from(cur.i32()?),
        })),
        TAG_LOCAL_TIME => Ok(Value::LocalTime(LocalTime {
            nanos_of_day: cur.u64()?,
        })),
        TAG_ZONED_TIME => {
            let nanos_of_day = cur.u64()?;
            let offset_seconds = cur.i32()?;
            Ok(Value::ZonedTime(ZonedTime {
                time: LocalTime { nanos_of_day },
                offset_seconds,
            }))
        }
        TAG_LOCAL_DATE_TIME => {
            let epoch_seconds = cur.i64()?;
            let nanos = cur.u32()?;
            Ok(Value::LocalDateTime(LocalDateTime {
                epoch_seconds,
                nanos,
            }))
        }
        TAG_ZONED_DATE_TIME => {
            let epoch_seconds = cur.i64()?;
            let nanos = cur.u32()?;
            let offset_seconds = cur.i32()?;
            let zone_len = cur.u32()? as usize;
            let raw = cur.take(zone_len)?;
            let zone_id =
                String::from_utf8(raw.to_vec()).map_err(|_| ValueDecodeError::Malformed {
                    what: "invalid UTF-8 zone id",
                })?;
            Ok(Value::ZonedDateTime(ZonedDateTime {
                local: LocalDateTime {
                    epoch_seconds,
                    nanos,
                },
                offset_seconds,
                zone_id,
            }))
        }
        TAG_DURATION => {
            let months = cur.i64()?;
            let days = cur.i64()?;
            let seconds = cur.i64()?;
            let nanos = cur.i32()?;
            Ok(Value::Duration(Duration {
                months,
                days,
                seconds,
                nanos,
            }))
        }
        // Unreachable: both callers dispatch only the six temporal tags here.
        _ => Err(ValueDecodeError::Malformed {
            what: "unknown temporal class tag",
        }),
    }
}

/// Decodes a spatial [`Point`] body produced by [`encode_point_body`] (`rmp` task #73): a one-byte
/// CRS discriminant then the CRS-determined number of little-endian `f64` coordinates. An unknown
/// CRS byte or a truncated coordinate is [`ValueDecodeError::Malformed`] (never a panic).
fn decode_point_body(cur: &mut Cursor<'_>) -> Result<Value, ValueDecodeError> {
    let crs_byte = cur.u8()?;
    let crs = Crs::from_byte(crs_byte).ok_or(ValueDecodeError::Malformed {
        what: "unknown spatial CRS discriminant",
    })?;
    let mut coords = [0.0_f64; 3];
    for slot in coords.iter_mut().take(crs.dimensions()) {
        *slot = f64::from_bits(cur.u64()?);
    }
    let point = Point::from_crs_coords(crs, &coords[..crs.dimensions()]).ok_or(
        ValueDecodeError::Malformed {
            what: "spatial coordinate count does not match the CRS",
        },
    )?;
    Ok(Value::Point(point))
}

/// Deserializes a homogeneous list image produced by [`encode_list`].
fn decode_list(bytes: &[u8]) -> Result<Value, ValueDecodeError> {
    let mut cur = Cursor::new(bytes);
    let elem_tag = cur.u8()?;
    let count = cur.u32()? as usize;
    if elem_tag == TAG_LIST_EMPTY {
        if count != 0 {
            return Err(ValueDecodeError::Malformed {
                what: "empty-list tag with a non-zero count",
            });
        }
        return Ok(Value::List(Vec::new()));
    }
    // Cap the pre-allocation by the input length: `count` is an untrusted on-disk u32, and the
    // smallest list element is a single byte, so a real list of `count` elements occupies at least
    // `count` bytes — capacity never legitimately exceeds `bytes.len()`. Without the cap, a corrupt
    // `count = 0xFFFF_FFFF` forces a multi-GiB allocation (OOM) before the per-element decode (which
    // fails fast on truncation) ever runs.
    let mut items = Vec::with_capacity(count.min(bytes.len()));
    for _ in 0..count {
        items.push(decode_list_element(elem_tag, &mut cur)?);
    }
    if !cur.is_empty() {
        return Err(ValueDecodeError::Malformed {
            what: "trailing bytes after the list elements",
        });
    }
    Ok(Value::List(items))
}

/// Decodes one scalar/string/temporal element of class `elem_tag` from `cur`.
fn decode_list_element(elem_tag: u8, cur: &mut Cursor<'_>) -> Result<Value, ValueDecodeError> {
    match elem_tag {
        TAG_BOOL => Ok(Value::Boolean(cur.u8()? != 0)),
        TAG_INT => {
            // u64 -> i64 via `as`: the inverse reinterpretation of the encode-side `as u64`.
            #[allow(clippy::cast_possible_wrap)]
            Ok(Value::Integer(cur.u64()? as i64))
        }
        TAG_FLOAT => Ok(Value::Float(f64::from_bits(cur.u64()?))),
        TAG_STRING => {
            let len = cur.u32()? as usize;
            let raw = cur.take(len)?;
            let s = String::from_utf8(raw.to_vec()).map_err(|_| ValueDecodeError::Malformed {
                what: "invalid UTF-8 list element",
            })?;
            Ok(Value::String(s))
        }
        TAG_DATE | TAG_DATE_WIDE | TAG_LOCAL_TIME | TAG_ZONED_TIME | TAG_LOCAL_DATE_TIME
        | TAG_ZONED_DATE_TIME | TAG_DURATION => decode_temporal_body(elem_tag, cur),
        _ => Err(ValueDecodeError::Malformed {
            what: "unknown list element tag",
        }),
    }
}

/// A minimal forward byte cursor with bounds-checked reads (a malformed/truncated image is reported,
/// never a panic).
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ValueDecodeError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or(ValueDecodeError::Malformed {
                what: "truncated overflow bytes",
            })?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, ValueDecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, ValueDecodeError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4-byte slice"),
        ))
    }

    fn u64(&mut self) -> Result<u64, ValueDecodeError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("8-byte slice"),
        ))
    }

    fn i32(&mut self) -> Result<i32, ValueDecodeError> {
        Ok(i32::from_le_bytes(
            self.take(4)?.try_into().expect("4-byte slice"),
        ))
    }

    fn i64(&mut self) -> Result<i64, ValueDecodeError> {
        Ok(i64::from_le_bytes(
            self.take(8)?.try_into().expect("8-byte slice"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(v: &Value) -> Value {
        let (class, bytes) = encode(v).expect("encode");
        decode(class, &bytes).expect("decode")
    }

    /// All class tags, inline and overflow, in tag order.
    const ALL_TAGS: [u8; 12] = [
        TAG_BOOL,
        TAG_INT,
        TAG_FLOAT,
        TAG_STRING,
        TAG_LIST,
        TAG_DATE,
        TAG_LOCAL_TIME,
        TAG_ZONED_TIME,
        TAG_LOCAL_DATE_TIME,
        TAG_ZONED_DATE_TIME,
        TAG_DURATION,
        TAG_POINT,
    ];

    #[test]
    fn overflow_bit_is_the_top_bit_and_disjoint_from_class_tags() {
        assert_eq!(OVERFLOW_BIT, 0x80);
        for (i, &tag) in ALL_TAGS.iter().enumerate() {
            // Every class tag fits the low 7 bits, so `class | OVERFLOW_BIT` is unambiguous.
            assert_eq!(tag & OVERFLOW_BIT, 0);
            // No two classes share a tag (the tag space is one dense sequence).
            for &other in &ALL_TAGS[i + 1..] {
                assert_ne!(tag, other);
            }
        }
    }

    /// The tag values are an **on-disk format**: they go through the WAL and onto pages, so they
    /// must never be renumbered. This test freezes them.
    #[test]
    fn class_tag_values_are_frozen() {
        assert_eq!(
            ALL_TAGS,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            "class tags are persisted bytes and must never be renumbered"
        );
    }

    /// Regression (storage audit, finding 4 / SEV 2): a corrupt list image whose `count` field is a
    /// huge untrusted value must not drive a multi-gigabyte pre-allocation (OOM). `decode_list` caps
    /// `Vec::with_capacity` at the input length, then fails fast when the (absent) element bytes are
    /// read. The decode must return an error — not abort the process on an allocation.
    #[test]
    fn decode_list_with_forged_count_does_not_oom() {
        // Body layout produced by `encode_list`: elem_tag (u8), count (u32 LE), then elements.
        // Here: TAG_INT elements, count = u32::MAX, but zero element bytes follow.
        let mut body = Vec::new();
        body.push(TAG_INT);
        body.extend_from_slice(&u32::MAX.to_le_bytes());
        // No element bytes: the first `decode_list_element` read is truncated.
        let res = decode(TAG_LIST, &body);
        assert!(
            matches!(res, Err(ValueDecodeError::Malformed { .. })),
            "a forged list count must yield a Malformed error, got {res:?}"
        );
    }

    #[test]
    fn strings_round_trip_empty_short_unicode_and_long() {
        for s in ["", "Ada", "héllo, 世界 🌍", &"x".repeat(10_000)] {
            let v = Value::String(s.to_owned());
            assert_eq!(round_trip(&v), v);
        }
    }

    #[test]
    fn string_class_tag_is_string() {
        let (class, _) = encode(&Value::String("hi".to_owned())).unwrap();
        assert_eq!(class, TAG_STRING);
    }

    #[test]
    fn list_of_ints_round_trips() {
        let v = Value::List(vec![
            Value::Integer(1),
            Value::Integer(-2),
            Value::Integer(i64::MIN),
        ]);
        assert_eq!(round_trip(&v), v);
    }

    #[test]
    fn list_of_strings_round_trips_including_unicode_and_empty_elements() {
        let v = Value::List(vec![
            Value::String("x".to_owned()),
            Value::String(String::new()),
            Value::String("世界".to_owned()),
        ]);
        assert_eq!(round_trip(&v), v);
    }

    #[test]
    fn list_of_bools_and_floats_round_trip() {
        let bools = Value::List(vec![Value::Boolean(true), Value::Boolean(false)]);
        assert_eq!(round_trip(&bools), bools);
        let floats = Value::List(vec![
            Value::Float(1.5),
            Value::Float(-0.0),
            Value::Float(f64::INFINITY),
        ]);
        assert_eq!(round_trip(&floats), floats);
    }

    #[test]
    fn empty_list_round_trips() {
        let v = Value::List(Vec::new());
        assert_eq!(round_trip(&v), v);
    }

    #[test]
    fn non_overflow_classes_are_rejected() {
        assert_eq!(
            encode(&Value::Integer(1)),
            Err(ValueEncodeError::NotOverflowClass { class: "Integer" })
        );
        assert_eq!(
            encode(&Value::Null),
            Err(ValueEncodeError::NotOverflowClass { class: "Null" })
        );
        assert_eq!(
            encode(&Value::Map(vec![("k".to_owned(), Value::Integer(1))])),
            Err(ValueEncodeError::NotOverflowClass { class: "Map" })
        );
    }

    #[test]
    fn a_heterogeneous_list_is_rejected() {
        let v = Value::List(vec![Value::Integer(1), Value::String("x".to_owned())]);
        assert_eq!(
            encode(&v),
            Err(ValueEncodeError::UnsupportedListElement {
                element: "String",
                established: "Integer",
            })
        );
    }

    #[test]
    fn a_nested_list_element_is_rejected() {
        let v = Value::List(vec![Value::List(vec![Value::Integer(1)])]);
        assert!(matches!(
            encode(&v),
            Err(ValueEncodeError::UnsupportedListElement {
                element: "List",
                ..
            })
        ));
    }

    #[test]
    fn decode_rejects_an_unknown_class() {
        assert_eq!(
            decode(99, &[]),
            Err(ValueDecodeError::UnknownClass { class: 99 })
        );
    }

    #[test]
    fn decode_rejects_truncated_and_invalid_utf8() {
        // Truncated list (claims one int element but carries no bytes).
        let mut bad = vec![TAG_INT];
        bad.extend_from_slice(&1u32.to_le_bytes());
        assert!(matches!(
            decode(TAG_LIST, &bad),
            Err(ValueDecodeError::Malformed { .. })
        ));
        // Invalid UTF-8 string.
        assert!(matches!(
            decode(TAG_STRING, &[0xFF, 0xFE]),
            Err(ValueDecodeError::Malformed { .. })
        ));
    }

    // =============================================================================================
    // Temporal classes (TAG_DATE .. TAG_DURATION)
    // =============================================================================================

    #[test]
    fn dates_round_trip_including_negative_and_extreme_days() {
        // Include the openCypher year bounds (`±999_999_999` years ≈ `±3.66e11` days), which
        // exceed the former `i32` range, plus the `i64` extremes (#141).
        const MAX_OC_DAYS: i64 = 365_241_780_471; // days(+999_999_999-12-31)
        for days in [
            0,
            1,
            -1,
            20_000,
            -20_000,
            i64::from(i32::MIN),
            i64::from(i32::MAX),
            MAX_OC_DAYS,
            -MAX_OC_DAYS,
            i64::MIN,
            i64::MAX,
        ] {
            let v = Value::Date(Date {
                days_since_epoch: days,
            });
            assert_eq!(round_trip(&v), v);
        }
        // New writes always use the wide tag (#141).
        let (class, _) = encode(&Value::Date(Date::default())).unwrap();
        assert_eq!(class, TAG_DATE_WIDE);
    }

    /// BACKWARD COMPATIBILITY (#141): a `Date` written *before* the `i64` widening was stored as a
    /// legacy [`TAG_DATE`] (6) image with a **4-byte i32 LE** body. The decoder must still read
    /// those bytes byte-for-byte and reconstruct the identical `Date` (with sign-extension), proving
    /// no in-place page migration is needed and old data stays readable.
    #[test]
    fn legacy_narrow_date_image_still_decodes() {
        // These are the *exact* bytes the pre-#141 encoder produced for these `i32` days values:
        // `TAG_DATE` (6) class + `i32::to_le_bytes()`.
        for days in [0_i32, 1, -1, 20_000, -20_000, i32::MIN, i32::MAX] {
            let legacy_body = days.to_le_bytes();
            let decoded = decode(TAG_DATE, &legacy_body).unwrap();
            assert_eq!(
                decoded,
                Value::Date(Date {
                    days_since_epoch: i64::from(days),
                }),
                "legacy 4-byte Date image for days={days} must round-trip"
            );
        }
        // A legacy Date *inside a persisted list* (shared element tag = TAG_DATE, 4-byte bodies).
        // Hand-build the legacy list image: elem_tag(6) ++ count(2) ++ two 4-byte i32 bodies.
        let mut legacy_list = Vec::new();
        legacy_list.push(TAG_DATE);
        legacy_list.extend_from_slice(&2u32.to_le_bytes());
        legacy_list.extend_from_slice(&(-719_528_i32).to_le_bytes()); // 0001-01-01
        legacy_list.extend_from_slice(&20_000_i32.to_le_bytes());
        let decoded = decode(TAG_LIST, &legacy_list).unwrap();
        assert_eq!(
            decoded,
            Value::List(vec![
                Value::Date(Date {
                    days_since_epoch: -719_528,
                }),
                Value::Date(Date {
                    days_since_epoch: 20_000,
                }),
            ])
        );
    }

    #[test]
    fn local_times_round_trip_including_midnight_and_last_nano() {
        use graphus_core::value::temporal::NANOS_PER_DAY;
        for nanos in [0, 1, NANOS_PER_DAY - 1, 12 * 3_600_000_000_000] {
            let v = Value::LocalTime(LocalTime {
                nanos_of_day: nanos,
            });
            assert_eq!(round_trip(&v), v);
        }
        let (class, _) = encode(&Value::LocalTime(LocalTime::default())).unwrap();
        assert_eq!(class, TAG_LOCAL_TIME);
    }

    #[test]
    fn zoned_times_round_trip_including_negative_and_extreme_offsets() {
        for (nanos, offset) in [
            (0, 0),
            (1, 3600),
            (86_399_999_999_999, -3600),
            (42, 64_800),  // +18:00, the ISO-8601 extreme
            (42, -64_800), // -18:00
            (7, i32::MIN), // bit-exactness even beyond semantic ranges
            (7, i32::MAX),
        ] {
            let v = Value::ZonedTime(ZonedTime {
                time: LocalTime {
                    nanos_of_day: nanos,
                },
                offset_seconds: offset,
            });
            assert_eq!(round_trip(&v), v);
        }
        let (class, _) = encode(&Value::ZonedTime(ZonedTime::default())).unwrap();
        assert_eq!(class, TAG_ZONED_TIME);
    }

    #[test]
    fn local_date_times_round_trip_including_negative_seconds_and_max_nanos() {
        for (secs, nanos) in [
            (0, 0),
            (1_700_000_000, 123_456_789),
            (-1, 999_999_999), // pre-epoch with the largest sub-second field
            (i64::MIN, 0),
            (i64::MAX, 999_999_999),
        ] {
            let v = Value::LocalDateTime(LocalDateTime {
                epoch_seconds: secs,
                nanos,
            });
            assert_eq!(round_trip(&v), v);
        }
        let (class, _) = encode(&Value::LocalDateTime(LocalDateTime::default())).unwrap();
        assert_eq!(class, TAG_LOCAL_DATE_TIME);
    }

    #[test]
    fn zoned_date_times_round_trip_with_empty_and_non_empty_zone_ids() {
        for (secs, nanos, offset, zone) in [
            (0, 0, 0, ""),                                   // offset-only (empty zone id)
            (1_700_000_000, 1, 3600, "Europe/Lisbon"),       // a real IANA id
            (-86_400, 999_999_999, -64_800, "Pacific/Niue"), // pre-epoch, extreme negative offset
            (i64::MIN, 0, i32::MIN, "Etc/GMT+12"),
            (i64::MAX, 999_999_999, i32::MAX, "Antarctica/DumontDUrville"),
        ] {
            let v = Value::ZonedDateTime(ZonedDateTime {
                local: LocalDateTime {
                    epoch_seconds: secs,
                    nanos,
                },
                offset_seconds: offset,
                zone_id: zone.to_owned(),
            });
            assert_eq!(round_trip(&v), v);
        }
        let (class, _) = encode(&Value::ZonedDateTime(ZonedDateTime::default())).unwrap();
        assert_eq!(class, TAG_ZONED_DATE_TIME);
    }

    #[test]
    fn durations_round_trip_including_negative_and_extreme_components() {
        for (months, days, seconds, nanos) in [
            (0, 0, 0, 0),
            (1, 2, 3, 4),
            (-1, -2, -3, -4), // all-negative (Cypher duration groups carry their own signs)
            (i64::MIN, i64::MAX, i64::MIN, i32::MIN),
            (i64::MAX, i64::MIN, i64::MAX, i32::MAX),
        ] {
            let v = Value::Duration(Duration {
                months,
                days,
                seconds,
                nanos,
            });
            assert_eq!(round_trip(&v), v);
        }
        let (class, _) = encode(&Value::Duration(Duration::default())).unwrap();
        assert_eq!(class, TAG_DURATION);
    }

    // =============================================================================================
    // Spatial points (TAG_POINT)
    // =============================================================================================

    #[test]
    fn points_round_trip_for_every_crs_2d_and_3d() {
        use graphus_core::value::spatial::{Crs, Point};
        let points = [
            Value::Point(Point::new_2d(Crs::Cartesian, 1.5, -2.5)),
            Value::Point(Point::new_3d(Crs::Cartesian3D, 1.0, 2.0, 3.0)),
            Value::Point(Point::new_2d(Crs::Wgs84, -8.61, 41.15)), // Porto, lon/lat
            Value::Point(Point::new_3d(Crs::Wgs84_3D, 12.5, -7.25, 100.0)),
            // Bit-exact extremes round-trip (incl. signed zeros and the named non-finite values).
            Value::Point(Point::new_2d(Crs::Cartesian, -0.0, 0.0)),
            Value::Point(Point::new_3d(
                Crs::Cartesian3D,
                f64::INFINITY,
                f64::NEG_INFINITY,
                f64::MAX,
            )),
        ];
        for v in &points {
            assert_eq!(round_trip(v), *v);
        }
        let (class, _) = encode(&Value::Point(Point::new_2d(Crs::Cartesian, 0.0, 0.0))).unwrap();
        assert_eq!(class, TAG_POINT);
    }

    #[test]
    fn point_byte_layout_is_frozen() {
        use graphus_core::value::spatial::{Crs, Point};
        // 2D Cartesian: crs byte 0 then x=1.0, y=2.0 little-endian.
        let (tag, bytes) = encode(&Value::Point(Point::new_2d(Crs::Cartesian, 1.0, 2.0))).unwrap();
        let mut expected = vec![0u8]; // Crs::Cartesian discriminant
        expected.extend_from_slice(&1.0_f64.to_le_bytes());
        expected.extend_from_slice(&2.0_f64.to_le_bytes());
        assert_eq!((tag, bytes.as_slice()), (TAG_POINT, expected.as_slice()));
        assert_eq!(bytes.len(), 1 + 2 * 8);

        // 3D WGS-84: crs byte 3 then three coordinates.
        let (tag, bytes) =
            encode(&Value::Point(Point::new_3d(Crs::Wgs84_3D, 4.0, 5.0, 6.0))).unwrap();
        assert_eq!(tag, TAG_POINT);
        assert_eq!(bytes[0], 3); // Crs::Wgs84_3D discriminant
        assert_eq!(bytes.len(), 1 + 3 * 8);
    }

    #[test]
    fn decode_rejects_unknown_crs_and_truncated_coordinates() {
        use graphus_core::value::spatial::{Crs, Point};
        // Unknown CRS byte.
        assert_eq!(
            decode(TAG_POINT, &[99, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(ValueDecodeError::Malformed {
                what: "unknown spatial CRS discriminant",
            })
        );
        // Truncate a valid image by one byte.
        let (class, bytes) =
            encode(&Value::Point(Point::new_2d(Crs::Cartesian, 1.0, 2.0))).unwrap();
        assert!(matches!(
            decode(class, &bytes[..bytes.len() - 1]),
            Err(ValueDecodeError::Malformed { .. })
        ));
        // Trailing byte after a complete image.
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(
            decode(class, &extra),
            Err(ValueDecodeError::Malformed {
                what: "trailing bytes after the point value",
            })
        );
    }

    /// The temporal byte layouts are an **on-disk format** (they go to pages and through the WAL):
    /// freeze them byte-for-byte so a refactor can never silently change the encoding.
    #[test]
    fn temporal_byte_layouts_are_frozen() {
        // `Date` now encodes as the wide tag (#141): an 8-byte i64 LE body. `-2` is `0xFFFF…FFFE`.
        let (tag, bytes) = encode(&Value::Date(Date {
            days_since_epoch: -2,
        }))
        .unwrap();
        assert_eq!(
            (tag, bytes.as_slice()),
            (
                TAG_DATE_WIDE,
                &[0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF][..]
            )
        );

        let (tag, bytes) = encode(&Value::LocalTime(LocalTime {
            nanos_of_day: 0x0102_0304_0506_0708,
        }))
        .unwrap();
        assert_eq!(
            (tag, bytes.as_slice()),
            (
                TAG_LOCAL_TIME,
                &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01][..]
            )
        );

        let (tag, bytes) = encode(&Value::ZonedTime(ZonedTime {
            time: LocalTime { nanos_of_day: 1 },
            offset_seconds: -1,
        }))
        .unwrap();
        assert_eq!(
            (tag, bytes.as_slice()),
            (
                TAG_ZONED_TIME,
                &[1, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF][..]
            )
        );

        let (tag, bytes) = encode(&Value::LocalDateTime(LocalDateTime {
            epoch_seconds: -1,
            nanos: 5,
        }))
        .unwrap();
        assert_eq!(
            (tag, bytes.as_slice()),
            (
                TAG_LOCAL_DATE_TIME,
                &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 5, 0, 0, 0][..]
            )
        );

        let (tag, bytes) = encode(&Value::ZonedDateTime(ZonedDateTime {
            local: LocalDateTime {
                epoch_seconds: 2,
                nanos: 3,
            },
            offset_seconds: 4,
            zone_id: "UTC".to_owned(),
        }))
        .unwrap();
        assert_eq!(
            (tag, bytes.as_slice()),
            (
                TAG_ZONED_DATE_TIME,
                &[
                    2, 0, 0, 0, 0, 0, 0, 0, // epoch_seconds: i64 LE
                    3, 0, 0, 0, // nanos: u32 LE
                    4, 0, 0, 0, // offset_seconds: i32 LE
                    3, 0, 0, 0, // zone_len: u32 LE
                    b'U', b'T', b'C', // zone_id UTF-8
                ][..]
            )
        );

        let (tag, bytes) = encode(&Value::Duration(Duration {
            months: 1,
            days: 2,
            seconds: 3,
            nanos: -1,
        }))
        .unwrap();
        assert_eq!(
            (tag, bytes.as_slice()),
            (
                TAG_DURATION,
                &[
                    1, 0, 0, 0, 0, 0, 0, 0, // months: i64 LE
                    2, 0, 0, 0, 0, 0, 0, 0, // days: i64 LE
                    3, 0, 0, 0, 0, 0, 0, 0, // seconds: i64 LE
                    0xFF, 0xFF, 0xFF, 0xFF, // nanos: i32 LE
                ][..]
            )
        );
    }

    #[test]
    fn lists_of_each_temporal_class_round_trip() {
        let lists = [
            Value::List(vec![
                Value::Date(Date {
                    days_since_epoch: -1,
                }),
                Value::Date(Date {
                    days_since_epoch: 20_000,
                }),
            ]),
            Value::List(vec![
                Value::LocalTime(LocalTime { nanos_of_day: 0 }),
                Value::LocalTime(LocalTime {
                    nanos_of_day: 86_399_999_999_999,
                }),
            ]),
            Value::List(vec![
                Value::ZonedTime(ZonedTime {
                    time: LocalTime { nanos_of_day: 42 },
                    offset_seconds: -3600,
                }),
                Value::ZonedTime(ZonedTime::default()),
            ]),
            Value::List(vec![
                Value::LocalDateTime(LocalDateTime {
                    epoch_seconds: -1,
                    nanos: 999_999_999,
                }),
                Value::LocalDateTime(LocalDateTime::default()),
            ]),
            Value::List(vec![
                // Mixed zone-id lengths inside one list (empty and non-empty) exercise the
                // per-element variable-width framing.
                Value::ZonedDateTime(ZonedDateTime {
                    local: LocalDateTime {
                        epoch_seconds: 7,
                        nanos: 8,
                    },
                    offset_seconds: 3600,
                    zone_id: "Europe/Lisbon".to_owned(),
                }),
                Value::ZonedDateTime(ZonedDateTime {
                    local: LocalDateTime::default(),
                    offset_seconds: 0,
                    zone_id: String::new(),
                }),
            ]),
            Value::List(vec![
                Value::Duration(Duration {
                    months: -1,
                    days: 2,
                    seconds: -3,
                    nanos: 4,
                }),
                Value::Duration(Duration::default()),
            ]),
        ];
        for v in lists {
            assert_eq!(round_trip(&v), v);
        }
    }

    #[test]
    fn a_temporally_heterogeneous_list_is_rejected() {
        // Two different temporal classes do not form a homogeneous list.
        let v = Value::List(vec![
            Value::Date(Date::default()),
            Value::LocalTime(LocalTime::default()),
        ]);
        assert_eq!(
            encode(&v),
            Err(ValueEncodeError::UnsupportedListElement {
                element: "LocalTime",
                established: "Date",
            })
        );
        // Nor does a temporal mixed with a scalar.
        let v = Value::List(vec![
            Value::Integer(1),
            Value::Duration(Duration::default()),
        ]);
        assert_eq!(
            encode(&v),
            Err(ValueEncodeError::UnsupportedListElement {
                element: "Duration",
                established: "Integer",
            })
        );
    }

    #[test]
    fn decode_rejects_truncated_temporal_bodies() {
        // Truncating any temporal image by one byte is Malformed, never a panic or a wrong value.
        let values = [
            Value::Date(Date {
                days_since_epoch: 1,
            }),
            Value::LocalTime(LocalTime { nanos_of_day: 1 }),
            Value::ZonedTime(ZonedTime::default()),
            Value::LocalDateTime(LocalDateTime::default()),
            Value::ZonedDateTime(ZonedDateTime {
                local: LocalDateTime::default(),
                offset_seconds: 0,
                zone_id: "UTC".to_owned(),
            }),
            Value::Duration(Duration::default()),
        ];
        for v in values {
            let (class, bytes) = encode(&v).unwrap();
            assert!(matches!(
                decode(class, &bytes[..bytes.len() - 1]),
                Err(ValueDecodeError::Malformed { .. })
            ));
        }
    }

    #[test]
    fn decode_rejects_trailing_bytes_after_a_temporal_value() {
        let (class, mut bytes) = encode(&Value::Date(Date {
            days_since_epoch: 1,
        }))
        .unwrap();
        bytes.push(0);
        assert_eq!(
            decode(class, &bytes),
            Err(ValueDecodeError::Malformed {
                what: "trailing bytes after the temporal value",
            })
        );
    }

    #[test]
    fn decode_rejects_an_invalid_utf8_zone_id() {
        let (class, mut bytes) = encode(&Value::ZonedDateTime(ZonedDateTime {
            local: LocalDateTime::default(),
            offset_seconds: 0,
            zone_id: "ab".to_owned(),
        }))
        .unwrap();
        // Corrupt the two zone-id bytes (the image tail) into invalid UTF-8.
        let n = bytes.len();
        bytes[n - 2] = 0xFF;
        bytes[n - 1] = 0xFE;
        assert_eq!(
            decode(class, &bytes),
            Err(ValueDecodeError::Malformed {
                what: "invalid UTF-8 zone id",
            })
        );
    }
}
