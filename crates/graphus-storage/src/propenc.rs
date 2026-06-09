//! Inline scalar **property value** codec for the `(type_tag, value_inline)` pair of a
//! [`PropRecord`](crate::record::PropRecord) (`04-technical-design.md` §2.3).
//!
//! A property record stores its value as a `type_tag: u8` discriminant plus a `value_inline: u64`
//! payload (`04 §2.3`: *"`type_tag` discriminates the value class and the inline-vs-overflow bit;
//! `value_inline` holds the value if it fits (e.g. an `i64`/`f64`/`bool`/short string) or else a
//! `strings.store` block id"*). This module is the codec for the value classes that fit **entirely
//! in those 64 bits**: `Boolean`, `Integer` and `Float`.
//!
//! # The achievable subset (`rmp` task #38)
//!
//! Only the three inline scalar classes are encodable here. Every other [`Value`] class — `String`,
//! `Bytes`, `List`, `Map` and the temporal classes — needs the `strings.store` overflow heap to
//! hold its bytes, and that heap is a **separate follow-up (#39)**. Encoding such a value returns
//! [`PropEncodeError::NonInline`] (a clear, documented error — never a panic and never a silently
//! wrong inline payload), so a caller (e.g. the Cypher `RecordStoreGraph` write path) can surface it
//! as a runtime error rather than corrupt the store. `Null` is not a stored value at all (Cypher
//! does not persist null properties), so it is also rejected here; write callers drop nulls before
//! reaching the codec.
//!
//! # Stability
//!
//! The tag values are an internal encoding of this crate, **not** a frozen on-disk format yet: the
//! frozen `05 §7` layout fixes only the *byte offsets* of `type_tag`/`value_inline`, not their
//! meaning. When the overflow heap lands (#39) this tag space is extended (overflow classes get
//! their own tags); the three inline tags here are chosen to stay stable across that extension.

use graphus_core::Value;

/// `type_tag` for a boolean: `value_inline` is `0` (false) or `1` (true).
pub const TAG_BOOL: u8 = 1;
/// `type_tag` for a 64-bit signed integer: `value_inline` is the `i64`'s two's-complement bit
/// pattern (a lossless `i64 <-> u64` reinterpretation).
pub const TAG_INT: u8 = 2;
/// `type_tag` for an IEEE-754 64-bit float: `value_inline` is [`f64::to_bits`] (every bit pattern,
/// including `NaN` and `-0.0`, round-trips exactly).
pub const TAG_FLOAT: u8 = 3;

/// The reason a [`Value`] could not be encoded into the inline `(type_tag, value_inline)` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PropEncodeError {
    /// The value is not one of the inline scalar classes (`Boolean`/`Integer`/`Float`). String,
    /// bytes, list, map and temporal values require the `strings.store` overflow heap, which is a
    /// follow-up (#39). Carries the offending class name for a precise diagnostic.
    NonInline {
        /// The Cypher value-class name that cannot be stored inline (e.g. `"String"`, `"List"`).
        class: &'static str,
    },
    /// `Null` is never persisted as a property value (Cypher semantics); a write caller must drop
    /// null-valued keys before encoding.
    Null,
}

impl std::fmt::Display for PropEncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonInline { class } => write!(
                f,
                "property value of type {class} cannot be stored inline yet: the strings/overflow \
                 heap for non-scalar property values is a follow-up (graphus #39); only Integer, \
                 Float and Boolean property values are supported in this build"
            ),
            Self::Null => write!(f, "a null property value is not persisted"),
        }
    }
}

impl std::error::Error for PropEncodeError {}

impl From<PropEncodeError> for graphus_core::error::GraphusError {
    /// A property-encoding limit is surfaced as a **runtime** error: the query is well-formed, but
    /// the value it tries to persist exceeds this build's storage capability.
    fn from(e: PropEncodeError) -> Self {
        graphus_core::error::GraphusError::Runtime(e.to_string())
    }
}

/// The static Cypher class name of `value`, for diagnostics in [`PropEncodeError::NonInline`].
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

/// Encodes an inline scalar [`Value`] into its `(type_tag, value_inline)` pair.
///
/// Supports exactly `Boolean`, `Integer` (i64) and `Float` (f64). Every other class — including the
/// temporal classes and all variable-length classes — returns [`PropEncodeError::NonInline`]; `Null`
/// returns [`PropEncodeError::Null`].
///
/// # Errors
/// - [`PropEncodeError::NonInline`] for any class that does not fit in 64 inline bits (deferred to
///   #39's overflow heap).
/// - [`PropEncodeError::Null`] for [`Value::Null`].
pub fn encode_inline(value: &Value) -> Result<(u8, u64), PropEncodeError> {
    match value {
        Value::Boolean(b) => Ok((TAG_BOOL, u64::from(*b))),
        // i64 -> u64 via `as` is a lossless two's-complement reinterpretation (same width), the
        // exact inverse of the `as i64` on decode. (`i64::cast_unsigned` would be clearer but needs
        // Rust 1.87 > the workspace MSRV of 1.85.)
        #[allow(clippy::cast_sign_loss)]
        Value::Integer(i) => Ok((TAG_INT, *i as u64)),
        // Every f64 bit pattern (incl. NaN payloads and the two zeros) round-trips through `to_bits`.
        Value::Float(fl) => Ok((TAG_FLOAT, fl.to_bits())),
        Value::Null => Err(PropEncodeError::Null),
        other => Err(PropEncodeError::NonInline {
            class: class_name(other),
        }),
    }
}

/// Decodes a `(type_tag, value_inline)` pair back into a [`Value`].
///
/// The exact inverse of [`encode_inline`] for the three inline tags ([`TAG_BOOL`], [`TAG_INT`],
/// [`TAG_FLOAT`]).
///
/// # Errors
/// Returns [`PropDecodeError::UnknownTag`] for any tag this build does not understand (e.g. a future
/// overflow-class tag written by #39's heap). A boolean payload other than `0`/`1` is normalised to
/// `true` for any non-zero value (defensive; [`encode_inline`] only ever writes `0`/`1`).
pub fn decode_inline(type_tag: u8, value_inline: u64) -> Result<Value, PropDecodeError> {
    match type_tag {
        TAG_BOOL => Ok(Value::Boolean(value_inline != 0)),
        // u64 -> i64 via `as`: the inverse reinterpretation of the `as u64` on encode (same width,
        // lossless). `u64::cast_signed` would be clearer but needs Rust 1.87 > the MSRV of 1.85.
        TAG_INT =>
        {
            #[allow(clippy::cast_possible_wrap)]
            Ok(Value::Integer(value_inline as i64))
        }
        TAG_FLOAT => Ok(Value::Float(f64::from_bits(value_inline))),
        other => Err(PropDecodeError::UnknownTag { tag: other }),
    }
}

/// The reason a `(type_tag, value_inline)` pair could not be decoded by this build.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PropDecodeError {
    /// The `type_tag` is not one of this build's inline scalar tags. Such a tag can only arise from
    /// a value written by a newer overflow-heap build (#39); this build cannot interpret it.
    UnknownTag {
        /// The unrecognised tag byte.
        tag: u8,
    },
}

impl std::fmt::Display for PropDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownTag { tag } => write!(
                f,
                "property type tag {tag} is not an inline scalar tag this build understands \
                 (non-scalar/overflow property values are a follow-up, graphus #39)"
            ),
        }
    }
}

impl std::error::Error for PropDecodeError {}

impl From<PropDecodeError> for graphus_core::error::GraphusError {
    fn from(e: PropDecodeError) -> Self {
        graphus_core::error::GraphusError::Runtime(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(v: Value) -> Value {
        let (tag, inline) = encode_inline(&v).expect("encode inline");
        decode_inline(tag, inline).expect("decode inline")
    }

    #[test]
    fn booleans_round_trip() {
        assert_eq!(round_trip(Value::Boolean(true)), Value::Boolean(true));
        assert_eq!(round_trip(Value::Boolean(false)), Value::Boolean(false));
        assert_eq!(
            encode_inline(&Value::Boolean(false)).unwrap(),
            (TAG_BOOL, 0)
        );
        assert_eq!(encode_inline(&Value::Boolean(true)).unwrap(), (TAG_BOOL, 1));
    }

    #[test]
    fn integers_round_trip_including_negatives_and_extremes() {
        for i in [0_i64, 1, -1, 42, -42, i64::MIN, i64::MAX] {
            assert_eq!(round_trip(Value::Integer(i)), Value::Integer(i));
        }
        // -1 is all-ones in two's complement.
        assert_eq!(
            encode_inline(&Value::Integer(-1)).unwrap(),
            (TAG_INT, u64::MAX)
        );
    }

    #[test]
    fn floats_round_trip_including_negative_zero_and_nan() {
        for f in [0.0_f64, -0.0, 1.5, -1.5, f64::MIN, f64::MAX, f64::INFINITY] {
            assert_eq!(round_trip(Value::Float(f)), Value::Float(f));
        }
        // -0.0 keeps its sign bit (bit-distinct from +0.0).
        assert_ne!(
            encode_inline(&Value::Float(-0.0)).unwrap(),
            encode_inline(&Value::Float(0.0)).unwrap()
        );
        // NaN round-trips to a NaN (compare via bits, since NaN != NaN).
        let (tag, inline) = encode_inline(&Value::Float(f64::NAN)).unwrap();
        let Value::Float(back) = decode_inline(tag, inline).unwrap() else {
            panic!("expected float");
        };
        assert!(back.is_nan());
    }

    #[test]
    fn null_is_rejected() {
        assert_eq!(encode_inline(&Value::Null), Err(PropEncodeError::Null));
    }

    #[test]
    fn non_inline_classes_are_rejected_with_their_class_name() {
        assert_eq!(
            encode_inline(&Value::String("hi".to_owned())),
            Err(PropEncodeError::NonInline { class: "String" })
        );
        assert_eq!(
            encode_inline(&Value::List(vec![Value::Integer(1)])),
            Err(PropEncodeError::NonInline { class: "List" })
        );
        assert_eq!(
            encode_inline(&Value::Map(vec![("k".to_owned(), Value::Integer(1))])),
            Err(PropEncodeError::NonInline { class: "Map" })
        );
        assert_eq!(
            encode_inline(&Value::Bytes(vec![1, 2, 3])),
            Err(PropEncodeError::NonInline { class: "Bytes" })
        );
        assert_eq!(
            encode_inline(&Value::Duration(graphus_core::Duration::default())),
            Err(PropEncodeError::NonInline { class: "Duration" })
        );
    }

    #[test]
    fn unknown_decode_tag_is_an_error_not_a_wrong_value() {
        assert_eq!(
            decode_inline(0, 0),
            Err(PropDecodeError::UnknownTag { tag: 0 })
        );
        assert_eq!(
            decode_inline(99, 12345),
            Err(PropDecodeError::UnknownTag { tag: 99 })
        );
    }
}
