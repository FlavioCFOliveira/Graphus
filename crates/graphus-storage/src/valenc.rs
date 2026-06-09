//! Self-describing **byte serialization** of overflow property values (`String` and `List`) for the
//! `strings.store` heap (`04-technical-design.md` §2.3; `05-storage-format.md` §7.2; `rmp` task #43).
//!
//! [`crate::propenc`] (task #38) encodes the three **inline scalar** value classes
//! (`Boolean`/`Integer`/`Float`) into the property record's `(type_tag, value_inline)` pair. This
//! module is its variable-length counterpart: it turns a `String` or a `List` into a flat
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
//! [`TAG_STRING`] = `4` and [`TAG_LIST`] = `5`, so the inline and overflow tag spaces never collide.
//!
//! # String format
//!
//! A `String` serializes to its **UTF-8 bytes**, nothing more — the chain's reassembled length is
//! the string length, and decode is [`String::from_utf8`]. Empty strings, multi-byte/Unicode, and
//! arbitrarily long strings all round-trip.
//!
//! # List format (homogeneous, `05 §7.2`)
//!
//! Persisted lists are **homogeneous** in their *element class* (`05 §7.2`: *"lists must be
//! homogeneous when persisted"*). A list serializes as:
//!
//! ```text
//!   elem_tag: u8        // the shared element class (TAG_BOOL/INT/FLOAT/STRING), or TAG_LIST_EMPTY
//!   count:    u32 LE    // number of elements
//!   element*            // `count` elements, encoded by class:
//!                       //   bool  -> 1 byte (0/1)
//!                       //   int   -> 8 bytes i64 LE (two's-complement)
//!                       //   float -> 8 bytes f64 LE (to_bits)
//!                       //   string-> len:u32 LE ++ UTF-8 bytes
//! ```
//!
//! The supported element classes are the **inline scalars plus strings** — i.e. exactly the value
//! classes Cypher most commonly stores in a property list (`['x','y']`, `[1,2,3]`). A list whose
//! elements are themselves lists, maps, `Bytes`, temporals, or a *mix* of classes is rejected with
//! [`ValueEncodeError`] (a clear, documented deferral — never a silently-wrong or partial write);
//! those richer element classes are a follow-up that extends this format, not a redesign of it.

use graphus_core::Value;

use crate::propenc::{TAG_BOOL, TAG_FLOAT, TAG_INT};

/// Top bit of a property `type_tag`: set ⇒ `value_inline` is a `strings.store` head block id rather
/// than an inline value (`04 §2.3` *"inline-vs-overflow bit"*).
pub const OVERFLOW_BIT: u8 = 0b1000_0000;

/// `type_tag` low-bits class for a `String` (continues [`crate::propenc`]'s tag space).
pub const TAG_STRING: u8 = 4;
/// `type_tag` low-bits class for a `List`.
pub const TAG_LIST: u8 = 5;

/// `elem_tag` sentinel inside a serialized **empty** list (it has no element class to record).
const TAG_LIST_EMPTY: u8 = 0;

/// The reason a [`Value`] could not be serialized to overflow bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValueEncodeError {
    /// The value is neither a `String` nor a `List` — this codec serializes only the two
    /// variable-length overflow classes (inline scalars go through [`crate::propenc`]; `Null` is
    /// never persisted; `Map`/`Bytes`/temporal property values are a separate follow-up).
    NotOverflowClass {
        /// The Cypher value-class name that this codec does not serialize.
        class: &'static str,
    },
    /// A list element is not a supported, homogeneous scalar/string. Carries the offending element's
    /// class and the list's established element class (`05 §7.2`: persisted lists are homogeneous).
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
                 only String and homogeneous scalar/string List values use the overflow heap \
                 (inline scalars use the inline codec; Map/Bytes/temporal property values are a \
                 follow-up)"
            ),
            Self::UnsupportedListElement {
                element,
                established,
            } => write!(
                f,
                "list element of class {element} cannot be persisted: a stored list must be \
                 homogeneous over the supported scalar/string element classes (this list's element \
                 class is {established}); nested lists, maps, bytes and temporal elements are a \
                 follow-up"
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
    /// The `type_tag`'s class is not an overflow class this build understands (not [`TAG_STRING`]
    /// nor [`TAG_LIST`]). Such a tag can only come from a newer/foreign build.
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
                "overflow property class {class} is not a String or List class this build \
                 understands"
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
    }
}

/// Serializes an overflow [`Value`] (`String` or `List`) to its self-describing byte image and
/// returns it together with the `type_tag` **class byte** (without the overflow bit; the store sets
/// that bit when it stamps the head block id into `value_inline`).
///
/// # Errors
/// - [`ValueEncodeError::NotOverflowClass`] if `value` is not a `String`/`List`.
/// - [`ValueEncodeError::UnsupportedListElement`] if a list element is not a supported homogeneous
///   scalar/string (`05 §7.2`).
pub fn encode(value: &Value) -> Result<(u8, Vec<u8>), ValueEncodeError> {
    match value {
        Value::String(s) => Ok((TAG_STRING, s.as_bytes().to_vec())),
        Value::List(items) => Ok((TAG_LIST, encode_list(items)?)),
        other => Err(ValueEncodeError::NotOverflowClass {
            class: class_name(other),
        }),
    }
}

/// Serializes a homogeneous list of supported scalar/string elements (`05 §7.2`).
fn encode_list(items: &[Value]) -> Result<Vec<u8>, ValueEncodeError> {
    let Some(first) = items.first() else {
        // Empty list: just the sentinel element tag and a zero count.
        let mut out = Vec::with_capacity(5);
        out.push(TAG_LIST_EMPTY);
        out.extend_from_slice(&0u32.to_le_bytes());
        return Ok(out);
    };
    let elem_tag = scalar_elem_tag(first)?;
    let established = class_name(first);

    let mut out = Vec::new();
    out.push(elem_tag);
    // The element count fits in u32 for any list this build can build (Cypher lists are in-memory
    // Vecs); a list longer than u32::MAX elements is not representable on these targets.
    out.extend_from_slice(&(u32::try_from(items.len()).unwrap_or(u32::MAX)).to_le_bytes());
    for item in items {
        if scalar_elem_tag(item)? != elem_tag {
            return Err(ValueEncodeError::UnsupportedListElement {
                element: class_name(item),
                established,
            });
        }
        encode_scalar_element(item, &mut out);
    }
    Ok(out)
}

/// The element tag for a supported scalar/string list element, or an error for an unsupported class.
fn scalar_elem_tag(v: &Value) -> Result<u8, ValueEncodeError> {
    match v {
        Value::Boolean(_) => Ok(TAG_BOOL),
        Value::Integer(_) => Ok(TAG_INT),
        Value::Float(_) => Ok(TAG_FLOAT),
        Value::String(_) => Ok(TAG_STRING),
        other => Err(ValueEncodeError::UnsupportedListElement {
            element: class_name(other),
            established: class_name(other),
        }),
    }
}

/// Appends one supported scalar/string element to `out` (caller guarantees a supported class).
fn encode_scalar_element(v: &Value, out: &mut Vec<u8>) {
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
        // Unreachable: callers always pass a class `scalar_elem_tag` accepted.
        _ => {}
    }
}

/// Deserializes overflow bytes back into a [`Value`], dispatching on the `type_tag`'s **class**
/// (`class_tag` is the `type_tag` with its [`OVERFLOW_BIT`] already masked off by the caller).
///
/// # Errors
/// - [`ValueDecodeError::UnknownClass`] if `class_tag` is not [`TAG_STRING`]/[`TAG_LIST`].
/// - [`ValueDecodeError::Malformed`] if the bytes are truncated, invalid UTF-8, or otherwise
///   inconsistent (a corrupt chain).
pub fn decode(class_tag: u8, bytes: &[u8]) -> Result<Value, ValueDecodeError> {
    match class_tag {
        TAG_STRING => {
            let s = String::from_utf8(bytes.to_vec()).map_err(|_| ValueDecodeError::Malformed {
                what: "invalid UTF-8 string",
            })?;
            Ok(Value::String(s))
        }
        TAG_LIST => decode_list(bytes),
        other => Err(ValueDecodeError::UnknownClass { class: other }),
    }
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
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        items.push(decode_scalar_element(elem_tag, &mut cur)?);
    }
    if !cur.is_empty() {
        return Err(ValueDecodeError::Malformed {
            what: "trailing bytes after the list elements",
        });
    }
    Ok(Value::List(items))
}

/// Decodes one scalar/string element of class `elem_tag` from `cur`.
fn decode_scalar_element(elem_tag: u8, cur: &mut Cursor<'_>) -> Result<Value, ValueDecodeError> {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(v: &Value) -> Value {
        let (class, bytes) = encode(v).expect("encode");
        decode(class, &bytes).expect("decode")
    }

    #[test]
    fn overflow_bit_is_the_top_bit_and_disjoint_from_class_tags() {
        assert_eq!(OVERFLOW_BIT, 0x80);
        // Every class tag fits the low 7 bits, so `class | OVERFLOW_BIT` is unambiguous.
        for tag in [TAG_BOOL, TAG_INT, TAG_FLOAT, TAG_STRING, TAG_LIST] {
            assert_eq!(tag & OVERFLOW_BIT, 0);
        }
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
}
