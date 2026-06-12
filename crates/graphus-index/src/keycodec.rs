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
//! correctly on the tag alone; within a class the payload preserves order. The ascending order is
//! the openCypher global orderability (CIP2016-06-14 §Orderability, the TCK-enforced source),
//! restricted to the index-encodable classes:
//!
//! `{temporals} < STRING < BOOLEAN < NUMBER`
//!
//! and within the temporal block, the CIP sub-order (ascending):
//!
//! `ZonedDateTime < LocalDateTime < Date < ZonedTime < LocalTime < Duration`
//!
//! Note the openCypher quirk that **`STRING < BOOLEAN < NUMBER`** (numbers are the *largest*
//! scalars, not the smallest) — this is exactly what the CIP specifies and what the Cypher TCK
//! enforces, so the tag bytes are laid out to match. (A previous revision of this module encoded
//! `BOOLEAN < NUMBER < STRING`, which was a confirmed cross-type ordering bug against the CIP; the
//! tags were reassigned to fix it.)
//!
//! The full global order also places `MAP < NODE < RELATIONSHIP < LIST < PATH` *below* the temporal
//! block and `NULL` *above* everything, but those classes are not index-encodable (see
//! [`KeyEncodeError::Unindexable`]) — `NULL` properties are treated as absent for indexing, and the
//! composite/structural classes are not stored in B+-tree keys — so they need no tag.
//!
//! `BYTES` is **not** an openCypher value class (it is a Graphus/PackStream extension); it is given
//! a tag immediately after `STRING` purely as an implementation-defined, internally-consistent
//! placement and never participates in TCK ordering.
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
//! - **temporal** — each temporal class has its own tag (ordered per the CIP sub-order above) and
//!   is encoded from its fixed-width integer components in most-significant-first order using the
//!   same `i64`/`i32`/`u64` sign-flip / big-endian tricks, so that *within* a class chronological
//!   order is byte order. The instant-defining quantities lead (so equal instants with different
//!   offsets still sort together) and the offset / zone id break ties consistently with
//!   `graphus-cypher`'s `ordering` module. See [`encode_temporal`].
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

/// Type tags, assigned in **ascending** openCypher orderability so cross-class ordering falls out
/// of the tag byte alone (CIP2016-06-14 §Orderability). The encodable order is
/// `{temporals} < STRING < BOOLEAN < NUMBER`, and within the temporal block
/// `ZonedDateTime < LocalDateTime < Date < ZonedTime < LocalTime < Duration`.
///
/// The numeric values only need to be *monotonic* in that order; the specific bytes are chosen with
/// gaps so future, currently-unindexable classes can be slotted in without a re-encoding.
pub mod tag {
    // --- Spatial point (below the temporal block per the CIP global order). ---
    /// `Value::Point` (openCypher `Point`). The full openCypher orderability places
    /// `LIST < PATH < POINT < {temporals}`, so the point tag sorts **below** every temporal tag
    /// (`rmp` task #73). Within the class the payload (SRID then coordinates) preserves
    /// [`graphus_core::Point::total_cmp`] order.
    pub const POINT: u8 = 0x08;

    // --- Temporal block (lowest among encodable values), in CIP sub-order. ---
    /// `Value::ZonedDateTime` (openCypher `DateTime`) — lowest temporal.
    pub const ZONED_DATE_TIME: u8 = 0x10;
    /// `Value::LocalDateTime` (openCypher `LocalDateTime`).
    pub const LOCAL_DATE_TIME: u8 = 0x11;
    /// `Value::Date` (openCypher `Date`).
    pub const DATE: u8 = 0x12;
    /// `Value::ZonedTime` (openCypher `Time`).
    pub const ZONED_TIME: u8 = 0x13;
    /// `Value::LocalTime` (openCypher `LocalTime`).
    pub const LOCAL_TIME: u8 = 0x14;
    /// `Value::Duration` — highest temporal.
    pub const DURATION: u8 = 0x15;

    // --- String, then the Bytes extension (implementation-defined placement). ---
    /// `Value::String` (UTF-8, bytewise = codepoint order); above all temporals per the CIP.
    pub const STRING: u8 = 0x20;
    /// `Value::Bytes` (raw bytes, bytewise order). Not an openCypher class; placed just after
    /// `STRING` as an internally-consistent extension that never enters TCK ordering.
    pub const BYTES: u8 = 0x28;

    /// `Value::Boolean`; above `STRING` per the openCypher quirk `STRING < BOOLEAN`.
    pub const BOOL: u8 = 0x30;

    /// `Value::Integer` and `Value::Float` (one shared numeric domain, see [`super::encode_number`]);
    /// the **largest** scalar class per the openCypher quirk `BOOLEAN < NUMBER`.
    pub const NUMBER: u8 = 0x40;
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

/// Encodes a `u64` in order-preserving big-endian form. Used for the always-non-negative temporal
/// components (e.g. nanoseconds-since-midnight, `0 ..= NANOS_PER_DAY - 1`), where big-endian alone
/// already preserves order — no sign flip is needed.
#[must_use]
pub fn encode_u64_bits(v: u64) -> [u8; 8] {
    v.to_be_bytes()
}

/// Encodes a `u32` in order-preserving big-endian form. Used for the sub-second nanosecond
/// component (`0 ..= 999_999_999`).
#[must_use]
pub fn encode_u32_bits(v: u32) -> [u8; 4] {
    v.to_be_bytes()
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

/// The approximate number of days in a month used **only** for *ordering* durations
/// (`365.2425 / 12 ≈ 30.436875` days). Cypher durations have no exact length (a month is not a
/// fixed number of days), so the global order compares them by this normalised approximation
/// (openCypher temporal CIP); equality remains strictly component-wise (handled in
/// `graphus-cypher`'s `equivalence`/`equality`). The factor is expressed in nanoseconds.
const AVG_NANOS_PER_MONTH: i128 = 30_436_875 * 1_000_000;

/// The approximate length of a [`Value::Duration`] in nanoseconds, used as its ordering key.
///
/// Uses `i128` so the multiplications cannot overflow for any `i64` component.
#[must_use]
fn duration_order_nanos(d: &graphus_core::Duration) -> i128 {
    i128::from(d.months) * AVG_NANOS_PER_MONTH
        + i128::from(d.days) * i128::from(graphus_core::value::temporal::NANOS_PER_DAY)
        + i128::from(d.seconds) * 1_000_000_000
        + i128::from(d.nanos)
}

/// Encodes an `i128`'s bits in order-preserving big-endian form (sign bit flipped), the 128-bit
/// analogue of [`encode_i64_bits`]. Used for the approximate duration length, which needs 128 bits
/// to hold `i64` months × nanoseconds-per-month without overflow.
#[must_use]
fn encode_i128_bits(v: i128) -> [u8; 16] {
    (v as u128 ^ (1u128 << 127)).to_be_bytes()
}

/// Encodes a temporal [`Value`] (its tag is pushed by [`encode_value`]; this pushes the payload).
///
/// Each class lays out its **instant-defining components most-significant-first** so that within a
/// class chronological order is byte order, followed by any tie-break (offset) and finally the
/// IANA zone id for `ZonedDateTime`. The layouts match `graphus-cypher`'s `ordering` module exactly
/// (cross-checked by a test there). See the openCypher temporal CIP and `04 §7.2`.
///
/// # Errors
/// Returns [`KeyEncodeError::Unindexable`] if `v` is not a temporal value.
pub fn encode_temporal(into: &mut Vec<u8>, v: &Value) -> Result<(), KeyEncodeError> {
    match v {
        Value::Date(d) => into.extend_from_slice(&encode_i32_bits(d.days_since_epoch)),
        Value::LocalTime(t) => into.extend_from_slice(&encode_u64_bits(t.nanos_of_day)),
        Value::ZonedTime(zt) => {
            // Order by the UTC instant the time denotes (local nanos minus the offset), then by
            // offset to break ties between equal instants. `nanos_of_day < NANOS_PER_DAY` (< 2^47)
            // and `|offset| <= 18h` (< 2^37), so the instant fits comfortably in `i64`.
            let instant = (zt.time.nanos_of_day as i64)
                .wrapping_sub(i64::from(zt.offset_seconds) * 1_000_000_000);
            into.extend_from_slice(&encode_i64_bits(instant));
            into.extend_from_slice(&encode_i32_bits(zt.offset_seconds));
        }
        Value::LocalDateTime(dt) => {
            into.extend_from_slice(&encode_i64_bits(dt.epoch_seconds));
            into.extend_from_slice(&encode_u32_bits(dt.nanos));
        }
        Value::ZonedDateTime(zdt) => {
            // The UTC instant is `local - offset`; saturating because the offset is at most ±18h
            // and only an astronomically extreme `epoch_seconds` near `i64::MIN/MAX` could overflow.
            let utc_seconds = zdt
                .local
                .epoch_seconds
                .saturating_sub(i64::from(zdt.offset_seconds));
            into.extend_from_slice(&encode_i64_bits(utc_seconds));
            into.extend_from_slice(&encode_u32_bits(zdt.local.nanos));
            into.extend_from_slice(&encode_i32_bits(zdt.offset_seconds));
            push_var(into, zdt.zone_id.as_bytes());
        }
        Value::Duration(d) => into.extend_from_slice(&encode_i128_bits(duration_order_nanos(d))),
        _ => return Err(KeyEncodeError::Unindexable("non-temporal")),
    }
    Ok(())
}

/// Encodes a spatial [`Value::Point`] order-preservingly (its tag is pushed by [`encode_value`];
/// this pushes the payload), consistent with [`graphus_core::Point::total_cmp`] (`rmp` task #73).
///
/// A point orders first by CRS (by **SRID**), then lexicographically by coordinate. The payload is
/// therefore the SRID as an order-preserving big-endian `i64` ([`encode_i64_bits`]), followed by the
/// **significant** coordinates ([`graphus_core::Point::dimensions`]) each as the total-order `f64`
/// key ([`encode_f64_bits`]). The SRID byte-count is fixed (8) and each CRS has a fixed coordinate
/// count, so the encoding is self-delimiting per CRS; across CRSs the leading SRID already separates
/// the (necessarily different) dimensionalities, so no length terminator is needed.
///
/// # Errors
/// Returns [`KeyEncodeError::Unindexable`] if `v` is not a point.
pub fn encode_point(into: &mut Vec<u8>, v: &Value) -> Result<(), KeyEncodeError> {
    let Value::Point(p) = v else {
        return Err(KeyEncodeError::Unindexable("non-point"));
    };
    into.extend_from_slice(&encode_i64_bits(p.crs.srid()));
    for &c in p.coords() {
        into.extend_from_slice(&encode_f64_bits(c));
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
/// The leading [`tag`] byte makes cross-type order fall out of the tag (in the ascending
/// openCypher orderability `{temporals} < STRING < BOOLEAN < NUMBER`, CIP2016-06-14 §Orderability),
/// and the per-type payload preserves order within a type. Variable-width values (`String`,
/// `Bytes`, and a `ZonedDateTime`'s zone id) use [`push_var`] framing so the encoding composes
/// safely inside a composite key. Temporal values are encoded by [`encode_temporal`].
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
        Value::ZonedDateTime(_) => {
            into.push(tag::ZONED_DATE_TIME);
            encode_temporal(into, v)?;
        }
        Value::LocalDateTime(_) => {
            into.push(tag::LOCAL_DATE_TIME);
            encode_temporal(into, v)?;
        }
        Value::Date(_) => {
            into.push(tag::DATE);
            encode_temporal(into, v)?;
        }
        Value::ZonedTime(_) => {
            into.push(tag::ZONED_TIME);
            encode_temporal(into, v)?;
        }
        Value::LocalTime(_) => {
            into.push(tag::LOCAL_TIME);
            encode_temporal(into, v)?;
        }
        Value::Duration(_) => {
            into.push(tag::DURATION);
            encode_temporal(into, v)?;
        }
        Value::Point(_) => {
            into.push(tag::POINT);
            encode_point(into, v)?;
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
    fn cross_type_tag_order_matches_opencypher_cip() {
        // REGRESSION TEST for the confirmed cross-type ordering bug. The authoritative ascending
        // order over the index-encodable classes is, verbatim from CIP2016-06-14 §Orderability:
        //     {temporals} < STRING < BOOLEAN < NUMBER
        // (note the openCypher quirk: STRING < BOOLEAN < NUMBER — numbers are the *largest*
        // scalars). A previous revision encoded BOOLEAN < NUMBER < STRING, which this test pins
        // against so the bug cannot recur.
        let temporal = Value::Date(graphus_core::Date {
            days_since_epoch: i32::MAX,
        });
        let string = Value::String("zzzzzzzzzz".to_owned());
        let boolean = Value::Boolean(false); // the *smallest* boolean
        let number_min = Value::Integer(i64::MIN); // the *smallest* number

        // Any temporal sorts below any string.
        assert!(enc(&temporal) < enc(&string));
        // The largest string sorts below the smallest boolean.
        assert!(enc(&string) < enc(&boolean));
        // The largest boolean sorts below the smallest number.
        assert!(enc(&Value::Boolean(true)) < enc(&number_min));
        // Full chain, smallest representatives upward.
        assert!(enc(&temporal) < enc(&string));
        assert!(enc(&string) < enc(&boolean));
        assert!(enc(&boolean) < enc(&number_min));

        // Bytes is a non-CIP extension placed just above STRING (implementation-defined).
        assert!(enc(&string) < enc(&Value::Bytes(vec![0])));
        assert!(enc(&Value::Bytes(vec![0xFF])) < enc(&boolean));
    }

    #[test]
    fn temporal_classes_order_per_cip_sub_order() {
        // CIP temporal block (ascending):
        //   ZonedDateTime < LocalDateTime < Date < ZonedTime < LocalTime < Duration
        // Use values whose payloads are *largest* so only the tag can be deciding the order.
        let zdt = Value::ZonedDateTime(graphus_core::ZonedDateTime {
            local: graphus_core::LocalDateTime {
                epoch_seconds: i64::MAX,
                nanos: 999_999_999,
            },
            offset_seconds: 0,
            zone_id: "Z".repeat(8),
        });
        let ldt = Value::LocalDateTime(graphus_core::LocalDateTime {
            epoch_seconds: i64::MIN,
            nanos: 0,
        });
        let date = Value::Date(graphus_core::Date {
            days_since_epoch: i32::MIN,
        });
        let zt = Value::ZonedTime(graphus_core::ZonedTime {
            time: graphus_core::LocalTime { nanos_of_day: 0 },
            offset_seconds: -64_800,
        });
        let lt = Value::LocalTime(graphus_core::LocalTime { nanos_of_day: 0 });
        let dur = Value::Duration(graphus_core::Duration {
            months: i64::MIN,
            days: i64::MIN,
            seconds: i64::MIN,
            nanos: i32::MIN,
        });
        assert!(enc(&zdt) < enc(&ldt));
        assert!(enc(&ldt) < enc(&date));
        assert!(enc(&date) < enc(&zt));
        assert!(enc(&zt) < enc(&lt));
        assert!(enc(&lt) < enc(&dur));
    }

    #[test]
    fn point_key_order_matches_point_cmp() {
        use graphus_core::value::spatial::{Crs, Point};
        use std::cmp::Ordering;

        // The encoded byte order must equal `Point::cmp` for every pair (the index/Cypher-order
        // agreement contract, `rmp` task #73). A deterministic spread covering both 2D/3D CRSs,
        // signed zeros, NaN and the named non-finite coordinates.
        let pool = [
            Point::new_2d(Crs::Wgs84, -8.61, 41.15), // SRID 4326 (smallest)
            Point::new_2d(Crs::Wgs84, -8.61, 41.16),
            Point::new_3d(Crs::Wgs84_3D, 0.0, 0.0, -10.0), // SRID 4979
            Point::new_3d(Crs::Wgs84_3D, 0.0, 0.0, 10.0),
            Point::new_2d(Crs::Cartesian, -0.0, 0.0), // SRID 7203
            Point::new_2d(Crs::Cartesian, 0.0, 0.0),
            Point::new_2d(Crs::Cartesian, f64::INFINITY, 0.0),
            Point::new_2d(Crs::Cartesian, f64::NAN, 0.0),
            Point::new_3d(Crs::Cartesian3D, 1.0, 2.0, 3.0), // SRID 9157 (largest)
        ];
        for a in &pool {
            for b in &pool {
                let key_cmp = enc(&Value::Point(*a)).cmp(&enc(&Value::Point(*b)));
                let point_cmp = a.total_cmp(b);
                assert_eq!(
                    key_cmp, point_cmp,
                    "key order disagrees with Point::cmp for {a:?} vs {b:?}"
                );
            }
        }

        // The whole point class sorts BELOW every temporal (the CIP global order
        // `LIST < PATH < POINT < {temporals}`): a point's tag (0x08) precedes the lowest temporal
        // tag (ZONED_DATE_TIME = 0x10).
        let point = Value::Point(Point::new_3d(
            Crs::Cartesian3D,
            f64::MAX,
            f64::MAX,
            f64::MAX,
        ));
        let lowest_temporal = Value::ZonedDateTime(graphus_core::ZonedDateTime {
            local: graphus_core::LocalDateTime {
                epoch_seconds: i64::MIN,
                nanos: 0,
            },
            offset_seconds: 0,
            zone_id: String::new(),
        });
        assert!(enc(&point) < enc(&lowest_temporal));
        // And a point cannot be encoded equal to a different point class member.
        assert_eq!(
            Value::Point(Point::new_2d(Crs::Cartesian, 1.0, 2.0)).eq(&Value::Point(Point::new_2d(
                Crs::Cartesian,
                1.0,
                2.0
            ))),
            enc(&Value::Point(Point::new_2d(Crs::Cartesian, 1.0, 2.0)))
                .cmp(&enc(&Value::Point(Point::new_2d(Crs::Cartesian, 1.0, 2.0))))
                == Ordering::Equal
        );
    }

    #[test]
    fn temporal_within_class_is_chronological() {
        // Date: earlier days sort first.
        assert!(
            enc(&Value::Date(graphus_core::Date {
                days_since_epoch: -1
            })) < enc(&Value::Date(graphus_core::Date {
                days_since_epoch: 0
            }))
        );
        // LocalTime: earlier nanos-of-day sort first.
        assert!(
            enc(&Value::LocalTime(graphus_core::LocalTime {
                nanos_of_day: 0
            })) < enc(&Value::LocalTime(graphus_core::LocalTime {
                nanos_of_day: 1
            }))
        );
        // LocalDateTime: earlier instant sorts first; nanos break the second-tie.
        assert!(
            enc(&Value::LocalDateTime(graphus_core::LocalDateTime {
                epoch_seconds: 0,
                nanos: 0
            })) < enc(&Value::LocalDateTime(graphus_core::LocalDateTime {
                epoch_seconds: 0,
                nanos: 1
            }))
        );
        // ZonedTime: ordered by the UTC instant the time denotes. 01:00+01:00 == 00:00 UTC, which
        // equals 00:00+00:00; the later wall-clock with the same instant ties on instant and is
        // separated only by the offset tie-break, so a *strictly earlier* instant sorts first.
        let earlier = Value::ZonedTime(graphus_core::ZonedTime {
            time: graphus_core::LocalTime { nanos_of_day: 0 },
            offset_seconds: 0,
        }); // 00:00 UTC
        let later = Value::ZonedTime(graphus_core::ZonedTime {
            time: graphus_core::LocalTime {
                nanos_of_day: 3600 * 1_000_000_000,
            },
            offset_seconds: 0,
        }); // 01:00 UTC
        assert!(enc(&earlier) < enc(&later));
        // ZonedDateTime: ordered by UTC instant (local - offset). 12:00+01:00 is the same instant
        // as 11:00+00:00, and an earlier instant sorts first.
        let zdt_earlier = Value::ZonedDateTime(graphus_core::ZonedDateTime {
            local: graphus_core::LocalDateTime {
                epoch_seconds: 0,
                nanos: 0,
            },
            offset_seconds: 0,
            zone_id: String::new(),
        });
        let zdt_later = Value::ZonedDateTime(graphus_core::ZonedDateTime {
            local: graphus_core::LocalDateTime {
                epoch_seconds: 10,
                nanos: 0,
            },
            offset_seconds: 0,
            zone_id: String::new(),
        });
        assert!(enc(&zdt_earlier) < enc(&zdt_later));
        // Duration: ordered by approximate normalised length.
        assert!(
            enc(&Value::Duration(graphus_core::Duration {
                months: 0,
                days: 0,
                seconds: 1,
                nanos: 0
            })) < enc(&Value::Duration(graphus_core::Duration {
                months: 1,
                days: 0,
                seconds: 0,
                nanos: 0
            }))
        );
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
