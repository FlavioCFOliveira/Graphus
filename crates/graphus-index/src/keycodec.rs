//! Order-preserving key encoding (`04-technical-design.md` §6.2, §7.6).
//!
//! A B+-tree compares keys as raw byte strings (memcmp / lexicographic order). For the tree's
//! byte order to coincide with **Cypher value order**, every value must be serialised so that
//!
//! ```text
//! encode(a) <= encode(b)   (lexicographically, as byte slices)
//!     iff   a <= b         (in Cypher's defined total order)
//! ```
//!
//! This module is the single place that encoding lives, and it is the most heavily
//! property-tested module in the crate (`tests/keycodec_order.rs`): for random pairs across every
//! supported type — including negatives, signed zeros, NaN, empty and long strings, and composite
//! keys — it asserts `encode` order matches `Cypher` order both ways.
//!
//! # Encoding scheme (one byte per type, then the order-preserving payload)
//!
//! Every encoded value begins with a **type tag** byte (see [`tag`]). Because the tags are
//! assigned in ascending Cypher value-class order, two values of *different* classes already order
//! correctly on the tag alone; within a class the payload preserves order. The Cypher value-class
//! order Graphus indexes use (ascending) is the one specified for `ORDER BY` (`04 §7.6`):
//!
//! `BOOLEAN < INTEGER ≈ FLOAT < STRING < temporal < …`
//!
//! Numbers (`INTEGER` and `FLOAT`) are *numerically* comparable to each other in Cypher
//! (`1 = 1.0`, `1 < 1.5`), so both are mapped onto **one** order-preserving numeric domain under a
//! single shared tag ([`tag::NUMBER`]); their original type is recoverable from a discriminator
//! byte that sorts *after* the magnitude, so it never disturbs cross-type ordering. See
//! [`encode_number`].
//!
//! ## Per-type payloads
//!
//! - **`bool`** — one byte: `0x00` for `false`, `0x01` for `true` (`false < true`).
//! - **`i64`** — big-endian with the sign bit flipped, so two's-complement negatives sort before
//!   positives ([`encode_i64_bits`]). Classic order-preserving integer trick.
//! - **`f64`** — IEEE-754 "total order" bit-twiddle ([`encode_f64_bits`]): negatives reversed,
//!   positives passed through, which yields `-inf < … < -0 < +0 < … < +inf < NaN`. Cypher places
//!   `NaN` as the largest float in ordering, which this matches.
//! - **`String`** — raw UTF-8 bytes. UTF-8 has the rare and valuable property that *bytewise*
//!   order equals *code-point* order, so this is the correct collation for Cypher's codepoint
//!   string ordering (`04 §7.6`); a length terminator is added only for composite framing (below).
//! - **temporal** — encoded from their fixed-width integer components in most-significant-first
//!   order using the same `i64`/`i32` sign-flip, so chronological order is byte order. The v1
//!   temporal value types are not yet present in [`graphus_core::Value`] (they arrive with the
//!   Cypher engine, `04 §7.2`); the building blocks ([`encode_i64_bits`], [`encode_i32_bits`]) are
//!   provided and unit-tested here so the temporal index keys drop in unchanged when the value
//!   variants land. This is called out as a documented seam rather than faked.
//!
//! ## Composite keys (multi-field)
//!
//! A composite key is the concatenation of its fields' encodings. For lexicographic order over the
//! concatenation to equal tuple order, **no field's encoding may be a prefix of another's**
//! (otherwise `("a",…)` could mis-sort against `("ab",…)`). Fixed-width payloads (bool, number,
//! temporals) are self-delimiting. Variable-width payloads (strings, byte strings) are made
//! prefix-free with an **escape-and-terminate** framing ([`push_var`]): every `0x00` byte in the
//! payload is escaped to `0x00 0xFF`, and the field ends with the terminator `0x00 0x00`. Because
//! the terminator (`0x00 …`) sorts *before* any escaped data byte (`0x00 0xFF`) and before any
//! non-zero leading byte, a shorter string always sorts before a longer one sharing its prefix,
//! which is exactly Cypher string order. See [`encode_composite`].

use graphus_core::Value;

/// Type tags, assigned in ascending Cypher value-class order so cross-class ordering falls out of
/// the tag byte alone (`04 §7.6`).
pub mod tag {
    /// `Value::Boolean`.
    pub const BOOL: u8 = 0x10;
    /// `Value::Integer` and `Value::Float` (one shared numeric domain, see [`super::encode_number`]).
    pub const NUMBER: u8 = 0x20;
    /// `Value::String` (UTF-8, bytewise = codepoint order).
    pub const STRING: u8 = 0x30;
    /// `Value::Bytes` (raw bytes, bytewise order).
    pub const BYTES: u8 = 0x38;
    /// Temporal value classes (reserved; see module docs — value variants land with the engine).
    pub const TEMPORAL: u8 = 0x40;
}

/// Numeric sub-tags, appended *after* the order-preserving magnitude so they never perturb the
/// cross-value numeric order; they only disambiguate the original Cypher type when two values share
/// the same magnitude (e.g. `1` vs `1.0`, which Cypher treats as equal, ordered here by tie-break).
mod numtag {
    /// An `i64` whose value was representable exactly in the numeric domain.
    pub const INTEGER: u8 = 0x00;
    /// An `f64`.
    pub const FLOAT: u8 = 0x01;
}

/// An error returned when a value cannot participate in an index key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyEncodeError {
    /// The value type is not indexable (e.g. `Null`, `List`, `Map`, or a structural value).
    ///
    /// `Null` is never stored in an index key: in Cypher a `NULL` property is treated as *absent*
    /// for indexing, so the index layer skips it rather than encoding it.
    Unindexable(&'static str),
}

impl std::fmt::Display for KeyEncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unindexable(t) => write!(f, "value of type {t} cannot be used in an index key"),
        }
    }
}

impl std::error::Error for KeyEncodeError {}

/// Encodes an `i64`'s bits in order-preserving big-endian form (sign bit flipped).
///
/// Flipping the sign bit maps the two's-complement order onto unsigned big-endian order, so
/// `i64::MIN` encodes to all-zeros and `i64::MAX` to all-ones, with `0` in the middle.
#[must_use]
pub fn encode_i64_bits(v: i64) -> [u8; 8] {
    // XOR with the sign mask flips the top bit; for negatives this moves them below positives.
    (v as u64 ^ 0x8000_0000_0000_0000).to_be_bytes()
}

/// Encodes an `i32`'s bits in order-preserving big-endian form (sign bit flipped). Used for the
/// fixed-width temporal components (e.g. `DATE` = days-since-epoch `i32`, `04 §2.3`).
#[must_use]
pub fn encode_i32_bits(v: i32) -> [u8; 4] {
    (v as u32 ^ 0x8000_0000).to_be_bytes()
}

/// Encodes an `f64` in IEEE-754 **total order** (`04 §7.6`).
///
/// The transform: if the sign bit is set (negative, incl. `-0.0`), flip *all* bits; otherwise flip
/// only the sign bit. This produces a monotonic unsigned key with
/// `-inf < … < -0.0 < +0.0 < … < +inf < NaN`. Cypher orders **all** `NaN` (regardless of sign or
/// payload) as the single largest float, so every `NaN` is first **canonicalised** to the standard
/// positive quiet-`NaN` bit pattern (`0x7FF8_0000_0000_0000`); without this a sign-set ("negative")
/// `NaN` would mis-sort as a tiny value. Note `-0.0` and `+0.0` encode distinctly (`-0.0` just below
/// `+0.0`) in *ordering*; for equality/grouping Cypher treats them as equal, which is the consumer's
/// concern (`04 §7.6` distinguishes ordering from equality).
#[must_use]
pub fn encode_f64_bits(v: f64) -> [u8; 8] {
    // Canonicalise every NaN to one bit pattern so all NaN sort identically (and as the maximum).
    let bits = if v.is_nan() {
        0x7FF8_0000_0000_0000
    } else {
        v.to_bits()
    };
    let mask = if bits & 0x8000_0000_0000_0000 != 0 {
        // Negative (sign bit set): flip every bit, so more-negative magnitudes sort lower.
        0xFFFF_FFFF_FFFF_FFFF
    } else {
        // Non-negative: flip only the sign bit so it sorts above all negatives.
        0x8000_0000_0000_0000
    };
    (bits ^ mask).to_be_bytes()
}

/// Encodes an `i64` Cypher `INTEGER` into the shared numeric domain.
fn encode_integer(into: &mut Vec<u8>, v: i64) {
    // An integer participates in float comparisons, so encode it on the *float* magnitude line:
    // `1` and `1.0` must produce the same magnitude bytes. `i64 as f64` is the value Cypher uses
    // for the mixed comparison; the exact original integer is not needed for *ordering*, only for
    // the tie-break tag. (Index keys carry no value back to the planner — they map to record ids —
    // so lossy magnitude here is correct for ordering and is documented.)
    into.extend_from_slice(&encode_f64_bits(v as f64));
    into.push(numtag::INTEGER);
}

/// Encodes an `f64` Cypher `FLOAT` into the shared numeric domain.
fn encode_float(into: &mut Vec<u8>, v: f64) {
    into.extend_from_slice(&encode_f64_bits(v));
    into.push(numtag::FLOAT);
}

/// Encodes a number (integer or float) into `into` on the single shared order-preserving numeric
/// domain (`04 §6.2`: numbers compare numerically across `INTEGER`/`FLOAT`).
pub fn encode_number(into: &mut Vec<u8>, v: &Value) -> Result<(), KeyEncodeError> {
    match v {
        Value::Integer(i) => encode_integer(into, *i),
        Value::Float(f) => encode_float(into, *f),
        _ => return Err(KeyEncodeError::Unindexable("non-number")),
    }
    Ok(())
}

/// Appends a variable-width payload (string / bytes) with prefix-free escape-and-terminate framing
/// (`04 §6.2`, see module docs): every `0x00` is escaped to `0x00 0xFF`, then a `0x00 0x00`
/// terminator closes the field so no field can be a prefix of another.
pub fn push_var(into: &mut Vec<u8>, payload: &[u8]) {
    for &b in payload {
        if b == 0x00 {
            into.push(0x00);
            into.push(0xFF);
        } else {
            into.push(b);
        }
    }
    into.push(0x00);
    into.push(0x00);
}

/// Encodes a single Cypher [`Value`] as an order-preserving key field into `into`.
///
/// The leading [`tag`] byte makes cross-type order fall out of the tag, and the per-type payload
/// preserves order within a type. Variable-width values (`String`, `Bytes`) use [`push_var`]
/// framing so the encoding composes safely inside a composite key.
///
/// # Errors
/// Returns [`KeyEncodeError::Unindexable`] for `Null`, `List`, `Map`, or structural values, which
/// are not valid index-key components (`Null` is treated as *absent* by the index layer).
pub fn encode_value(into: &mut Vec<u8>, v: &Value) -> Result<(), KeyEncodeError> {
    match v {
        Value::Boolean(b) => {
            into.push(tag::BOOL);
            into.push(u8::from(*b));
        }
        Value::Integer(_) | Value::Float(_) => {
            into.push(tag::NUMBER);
            encode_number(into, v)?;
        }
        Value::String(s) => {
            into.push(tag::STRING);
            push_var(into, s.as_bytes());
        }
        Value::Bytes(b) => {
            into.push(tag::BYTES);
            push_var(into, b);
        }
        Value::Null => return Err(KeyEncodeError::Unindexable("Null")),
        Value::List(_) => return Err(KeyEncodeError::Unindexable("List")),
        Value::Map(_) => return Err(KeyEncodeError::Unindexable("Map")),
    }
    Ok(())
}

/// Encodes a single value to a fresh `Vec` (convenience over [`encode_value`]).
///
/// # Errors
/// See [`encode_value`].
pub fn encode_single(v: &Value) -> Result<Vec<u8>, KeyEncodeError> {
    let mut out = Vec::with_capacity(16);
    encode_value(&mut out, v)?;
    Ok(out)
}

/// Encodes a composite key — the in-order concatenation of its fields' encodings (`04 §6.2`).
///
/// Each field is framed prefix-free (fixed-width payloads are self-delimiting; variable-width ones
/// use [`push_var`]), so lexicographic order over the concatenation equals tuple (lexicographic)
/// order over the fields, including leading-prefix range semantics.
///
/// # Errors
/// Propagates [`encode_value`] for any unindexable field.
pub fn encode_composite(fields: &[Value]) -> Result<Vec<u8>, KeyEncodeError> {
    let mut out = Vec::with_capacity(16 * fields.len());
    for f in fields {
        encode_value(&mut out, f)?;
    }
    Ok(out)
}

/// Prefixes an already-encoded key with a big-endian `u32` token id, the leading field of the
/// token-keyed index kinds (`04 §6.2`: `(token, value)` / `(reltype, value)` / `(token, id)`).
///
/// Big-endian keeps token order = byte order, so per-token ranges are contiguous and scannable.
#[must_use]
pub fn with_token_prefix(token: u32, encoded_tail: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + encoded_tail.len());
    out.extend_from_slice(&token.to_be_bytes());
    out.extend_from_slice(encoded_tail);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(v: &Value) -> Vec<u8> {
        encode_single(v).unwrap()
    }

    #[test]
    fn i64_sign_flip_orders_negatives_below_positives() {
        assert!(encode_i64_bits(i64::MIN) < encode_i64_bits(-1));
        assert!(encode_i64_bits(-1) < encode_i64_bits(0));
        assert!(encode_i64_bits(0) < encode_i64_bits(1));
        assert!(encode_i64_bits(1) < encode_i64_bits(i64::MAX));
    }

    #[test]
    fn i32_sign_flip_orders() {
        assert!(encode_i32_bits(i32::MIN) < encode_i32_bits(0));
        assert!(encode_i32_bits(0) < encode_i32_bits(i32::MAX));
    }

    #[test]
    fn f64_total_order_places_specials_correctly() {
        let neg_inf = encode_f64_bits(f64::NEG_INFINITY);
        let neg_one = encode_f64_bits(-1.0);
        let neg_zero = encode_f64_bits(-0.0);
        let pos_zero = encode_f64_bits(0.0);
        let pos_one = encode_f64_bits(1.0);
        let pos_inf = encode_f64_bits(f64::INFINITY);
        let nan = encode_f64_bits(f64::NAN);
        assert!(neg_inf < neg_one);
        assert!(neg_one < neg_zero);
        assert!(neg_zero < pos_zero); // -0.0 just below +0.0 in *ordering*
        assert!(pos_zero < pos_one);
        assert!(pos_one < pos_inf);
        assert!(pos_inf < nan); // NaN is the largest float in Cypher ordering
    }

    #[test]
    fn all_nan_bit_patterns_canonicalise_to_the_same_largest_key() {
        let pos_nan = encode_f64_bits(f64::NAN);
        // A sign-set ("negative") NaN and a NaN with a different payload must encode identically.
        let neg_nan = encode_f64_bits(f64::from_bits(0xFFF8_0000_0000_0001));
        let other_nan = encode_f64_bits(f64::from_bits(0x7FFA_BCDE_F012_3456));
        assert_eq!(pos_nan, neg_nan);
        assert_eq!(pos_nan, other_nan);
        // And it is the maximum (above +inf).
        assert!(encode_f64_bits(f64::INFINITY) < pos_nan);
    }

    #[test]
    fn numbers_compare_across_integer_and_float() {
        assert!(enc(&Value::Integer(1)) < enc(&Value::Float(1.5)));
        assert!(enc(&Value::Float(0.5)) < enc(&Value::Integer(1)));
        assert!(enc(&Value::Integer(-3)) < enc(&Value::Integer(2)));
        // 1 and 1.0 share a magnitude; the sub-tag breaks the tie deterministically.
        let one_i = enc(&Value::Integer(1));
        let one_f = enc(&Value::Float(1.0));
        assert_ne!(one_i, one_f);
        assert!(one_i < one_f); // INTEGER sub-tag (0x00) sorts before FLOAT (0x01)
    }

    #[test]
    fn cross_type_tag_order_is_bool_then_number_then_string() {
        assert!(enc(&Value::Boolean(true)) < enc(&Value::Integer(i64::MIN)));
        assert!(enc(&Value::Integer(i64::MAX)) < enc(&Value::String("".to_owned())));
        assert!(enc(&Value::String("zzz".to_owned())) < enc(&Value::Bytes(vec![0])));
    }

    #[test]
    fn bool_orders_false_below_true() {
        assert!(enc(&Value::Boolean(false)) < enc(&Value::Boolean(true)));
    }

    #[test]
    fn strings_order_by_codepoint_and_prefix() {
        assert!(enc(&Value::String("".to_owned())) < enc(&Value::String("a".to_owned())));
        assert!(enc(&Value::String("a".to_owned())) < enc(&Value::String("ab".to_owned())));
        assert!(enc(&Value::String("ab".to_owned())) < enc(&Value::String("b".to_owned())));
        // Multi-byte codepoints still order correctly (UTF-8 bytewise = codepoint order).
        assert!(enc(&Value::String("a".to_owned())) < enc(&Value::String("é".to_owned())));
    }

    #[test]
    fn var_framing_is_prefix_free_for_embedded_nulls() {
        // "a\0b" must not be confused with "a" then a new field starting with "b".
        let s1 = enc(&Value::String("a\u{0}b".to_owned()));
        let s2 = enc(&Value::String("a".to_owned()));
        assert!(s2 < s1); // "a" is a strict prefix => sorts first
        // Round-trip-ish: the escaped 0x00 0xFF must appear, not a bare 0x00 inside the payload.
        assert!(s1.windows(2).any(|w| w == [0x00, 0xFF]));
    }

    #[test]
    fn composite_orders_lexicographically_by_field() {
        let k1 = encode_composite(&[Value::Integer(1), Value::String("a".to_owned())]).unwrap();
        let k2 = encode_composite(&[Value::Integer(1), Value::String("b".to_owned())]).unwrap();
        let k3 = encode_composite(&[Value::Integer(2), Value::String("a".to_owned())]).unwrap();
        assert!(k1 < k2); // same leading field, second field orders
        assert!(k2 < k3); // leading field dominates
    }

    #[test]
    fn composite_leading_prefix_is_contiguous() {
        // All keys with leading field 1 sort before all with leading field 2 — the property a
        // composite/leading-prefix seek relies on.
        let a = encode_composite(&[Value::Integer(1), Value::String("zzzz".to_owned())]).unwrap();
        let b = encode_composite(&[Value::Integer(2), Value::String("".to_owned())]).unwrap();
        assert!(a < b);
    }

    #[test]
    fn token_prefix_orders_by_token_first() {
        let lo = with_token_prefix(1, &enc(&Value::Integer(i64::MAX)));
        let hi = with_token_prefix(2, &enc(&Value::Integer(i64::MIN)));
        assert!(lo < hi); // token 1 (any value) < token 2 (any value)
    }

    #[test]
    fn unindexable_values_error() {
        assert!(encode_single(&Value::Null).is_err());
        assert!(encode_single(&Value::List(vec![])).is_err());
        assert!(encode_single(&Value::Map(vec![])).is_err());
    }
}
