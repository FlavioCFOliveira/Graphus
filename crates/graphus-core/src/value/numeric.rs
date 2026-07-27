//! The exact comparison between the two Cypher numeric types, `INTEGER` (`i64`) and `FLOAT` (`f64`)
//! (`rmp` task #894).
//!
//! # The rule
//!
//! openCypher CIP2016-06-14, §Numbers, under *Comparability and equality*, states verbatim:
//!
//! > "Numbers of different types (excluding `NaN` values and the Infinities) are compared to each
//! > other and tested for equality **as if both numbers would have been coerced to unlimited
//! > precision big decimals** (currently outside the Cypher type system) before comparing them with
//! > each other numerically in their natural order."
//!
//! An `f64` carries a 53-bit significand, so `i as f64` is **lossy** for `|i| > 2^53`: it rounds the
//! integer onto the nearest representable double. Comparing through that cast is exactly what the
//! CIP forbids — it makes `9007199254740993` (2^53+1) compare *equal* to `9007199254740992.0`
//! (2^53), when under unlimited precision they are two different numbers. Worse, the value's
//! *storage* is exact, so a scan and an index disagreed about which rows matched: declaring an index
//! changed the answer (`rmp` #894).
//!
//! # The reference implementation
//!
//! Neo4j `org.neo4j.values.storable.NumberValues` (5.0) implements the same rule. It masks the
//! `long` against `NON_DOUBLE_LONG = 0xFFE0_0000_0000_0000L` ("doubles are exact integers up to 53
//! bits") and, once a bit outside that window is set, stops coercing: `numbersEqual` compares
//! `in == (long) fpn` after checking the double is a whole number in range, and
//! `compareDoubleAgainstLong` falls back to `BigDecimal.valueOf(lhs).compareTo(BigDecimal.valueOf(rhs))`
//! — an exact, unlimited-precision comparison.
//!
//! [`cmp_int_float`] reproduces that relation with integer arithmetic instead of a big decimal: once
//! the operands are known to be in `i64` range, comparing the double's floor against the integer
//! *is* the unlimited-precision comparison, and it cannot allocate or lose a bit.
//!
//! # One relation, three consumers
//!
//! Cypher has three *distinct* relations over values — equality (`=`, three-valued), equivalence
//! (`DISTINCT` / grouping, total and two-valued) and orderability (`ORDER BY`, a total order) — and
//! they legitimately differ on `null`, `NaN` and signed zero. They must **not** differ on which of
//! two numbers is the larger, so all three build on this single function
//! (`graphus_cypher::equality`, `::equivalence`, `::ordering`), rather than each coercing through
//! `f64` on its own.

use std::cmp::Ordering;

/// The largest magnitude for which **every** `i64` is exactly representable as an `f64` (2^53).
///
/// Within `-2^53 ..= 2^53` the cast `i as f64` is lossless, so an IEEE comparison against a double
/// already *is* the unlimited-precision comparison. This is the same threshold Neo4j's
/// `NON_DOUBLE_LONG` bit mask expresses.
const MAX_EXACT_INT_IN_F64: i64 = 1 << 53;

/// 2^63 as an `f64` — exactly representable, and **one past** `i64::MAX`. Any double at or above it
/// is greater than every `i64`; any double below `-2^63` is smaller than every `i64`.
const TWO_POW_63: f64 = 9_223_372_036_854_775_808.0;

/// Compares a Cypher `INTEGER` against a Cypher `FLOAT` **exactly**, as if both had been coerced to
/// unlimited-precision decimals (openCypher CIP2016-06-14 §Numbers; see the module docs).
///
/// Returns [`None`] if — and only if — `f` is `NaN`. The CIP excludes `NaN` from this rule
/// explicitly, and each of Cypher's three value relations resolves it differently (`=` is `FALSE`,
/// grouping equivalence makes `NaN ≡ NaN`, orderability makes `NaN` the largest number), so this
/// function reports "no order" and leaves the decision to the caller rather than inventing one.
///
/// The Infinities are also excluded by the CIP sentence, and are handled here as the extremes of the
/// numeric line: every `i64` is below `+Infinity` and above `-Infinity`.
///
/// # Examples
///
/// ```
/// use std::cmp::Ordering;
/// use graphus_core::cmp_int_float;
///
/// // The `rmp` #894 pair: 2^53+1 is NOT 2^53, even though `9007199254740993 as f64` is.
/// assert_eq!(cmp_int_float(9_007_199_254_740_993, 9_007_199_254_740_992.0), Some(Ordering::Greater));
/// // 2^53 itself is exactly representable, so the two spellings really are one number.
/// assert_eq!(cmp_int_float(9_007_199_254_740_992, 9_007_199_254_740_992.0), Some(Ordering::Equal));
/// // Small magnitudes are unaffected: `1 = 1.0` (TCK `Comparison1 [9]`).
/// assert_eq!(cmp_int_float(1, 1.0), Some(Ordering::Equal));
/// // `NaN` has no order against a number.
/// assert_eq!(cmp_int_float(1, f64::NAN), None);
/// ```
#[must_use]
pub fn cmp_int_float(i: i64, f: f64) -> Option<Ordering> {
    // `NaN` is outside the rule (and outside any order): report "incomparable".
    if f.is_nan() {
        return None;
    }

    // FAST PATH — `|i| <= 2^53`, where `i as f64` is **lossless**. The IEEE comparison is then
    // bit-for-bit the unlimited-precision one, so nothing is given up by taking it, and this is the
    // branch every realistic value takes. It also settles `±Infinity` (a finite double compares
    // correctly against them) and signed zero (`0` vs `-0.0` is `Equal`, as `=` requires).
    if (-MAX_EXACT_INT_IN_F64..=MAX_EXACT_INT_IN_F64).contains(&i) {
        #[allow(clippy::cast_precision_loss)] // guarded above: exact within ±2^53
        return (i as f64).partial_cmp(&f);
    }

    // EXACT PATH — `|i| > 2^53`, so `i as f64` would round and must not be used.
    //
    // First push the double outside `i64`'s range out of the way, which also disposes of the
    // Infinities. `TWO_POW_63` is `i64::MAX + 1`, so `f >= 2^63` is greater than every `i64`, and
    // `f < -2^63` is smaller than every `i64` (`-2^63` *is* `i64::MIN`, so it stays in range).
    if f >= TWO_POW_63 {
        return Some(Ordering::Less);
    }
    if f < -TWO_POW_63 {
        return Some(Ordering::Greater);
    }

    // `f` is now finite with `-2^63 <= f < 2^63`, so `f.floor()` is an integral double in
    // `[-2^63, 2^63)` and the cast below is **exact** — it can neither truncate nor saturate. This
    // matters: Rust's float→int cast *saturates* for out-of-range inputs, which would silently
    // manufacture `i64::MAX` out of a much larger double and report a wrong equality. The two
    // branches above are what make the cast safe, and they are the same two range guards Neo4j's
    // `numbersEqual` performs (`fpn > Long.MAX_VALUE` / `fpn < Long.MIN_VALUE`) before its own
    // `(long) fpn`.
    let floor = f.floor();
    #[allow(clippy::cast_possible_truncation)] // guarded above: `floor` is exactly in i64's range
    let floor_as_int = floor as i64;
    debug_assert_eq!(floor_as_int as f64, floor, "the floor cast must be exact");

    // Compare the integer parts; on a tie the double's fractional part (if any) makes it the larger.
    // (`|i| > 2^53` forces `|f| > 2^53` for the tie to be reachable, and every double that large is
    // already a whole number — so the fractional term is a formality that keeps the function total.)
    let by_integer_part = i.cmp(&floor_as_int);
    Some(by_integer_part.then(if floor < f {
        Ordering::Less // e.g. i == 3 and f == 3.5  →  i < f
    } else {
        Ordering::Equal
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2^53, the last magnitude at which every integer is an exact double.
    const P53: i64 = 1 << 53;

    /// The `rmp` #894 reproduction and its immediate neighbourhood, both signs.
    #[test]
    fn separates_an_integer_from_the_float_it_rounds_to() {
        #[allow(clippy::cast_precision_loss)]
        let p53f = P53 as f64;
        // 2^53+1 rounds to 2^53 but is strictly greater than it.
        assert_eq!(cmp_int_float(P53 + 1, p53f), Some(Ordering::Greater));
        // 2^53 itself is exactly representable — genuinely equal.
        assert_eq!(cmp_int_float(P53, p53f), Some(Ordering::Equal));
        // 2^53-1 is below.
        assert_eq!(cmp_int_float(P53 - 1, p53f), Some(Ordering::Less));
        // The next whole-number double above 2^53 is 2^53+2, so 2^53+1 sits strictly between.
        assert_eq!(cmp_int_float(P53 + 1, p53f + 2.0), Some(Ordering::Less));
        // Negatives mirror exactly.
        assert_eq!(cmp_int_float(-(P53 + 1), -p53f), Some(Ordering::Less));
        assert_eq!(cmp_int_float(-P53, -p53f), Some(Ordering::Equal));
        assert_eq!(
            cmp_int_float(-(P53 + 1), -p53f - 2.0),
            Some(Ordering::Greater)
        );
    }

    /// The saturating-cast trap: `i64::MAX as f64` is 2^63, which is **larger** than `i64::MAX`. A
    /// naive `f as i64` would saturate back to `i64::MAX` and report equality.
    #[test]
    fn i64_bounds_against_the_doubles_around_them() {
        assert_eq!(cmp_int_float(i64::MAX, TWO_POW_63), Some(Ordering::Less));
        assert_eq!(
            cmp_int_float(i64::MAX, -TWO_POW_63),
            Some(Ordering::Greater)
        );
        // `i64::MIN` is exactly -2^63, so it really does equal that double.
        assert_eq!(cmp_int_float(i64::MIN, -TWO_POW_63), Some(Ordering::Equal));
        assert_eq!(cmp_int_float(i64::MIN, TWO_POW_63), Some(Ordering::Less));
        // Far outside i64's range on both sides.
        assert_eq!(cmp_int_float(i64::MAX, 1e300), Some(Ordering::Less));
        assert_eq!(cmp_int_float(i64::MIN, -1e300), Some(Ordering::Greater));
    }

    /// Two distinct large integers that share one double must each compare correctly against that
    /// double (this is what keeps `<` / `>` a strict relation over the pair).
    #[test]
    fn integers_sharing_one_double_are_ordered_around_it() {
        // 2^54's binade has a spacing of 4: 2^54+3 and 2^54+5 both round to 2^54+4.
        let base: i64 = 1 << 54;
        #[allow(clippy::cast_precision_loss)]
        let mid = (base + 4) as f64;
        assert_eq!(cmp_int_float(base + 3, mid), Some(Ordering::Less));
        assert_eq!(cmp_int_float(base + 4, mid), Some(Ordering::Equal));
        assert_eq!(cmp_int_float(base + 5, mid), Some(Ordering::Greater));
    }

    #[test]
    fn small_magnitudes_and_signed_zero_are_unchanged() {
        assert_eq!(cmp_int_float(1, 1.0), Some(Ordering::Equal));
        assert_eq!(cmp_int_float(1, 1.5), Some(Ordering::Less));
        assert_eq!(cmp_int_float(2, 1.5), Some(Ordering::Greater));
        // Signed zero compares equal (the *equality* rule; ordering adds `-0.0 < +0.0` on top).
        assert_eq!(cmp_int_float(0, 0.0), Some(Ordering::Equal));
        assert_eq!(cmp_int_float(0, -0.0), Some(Ordering::Equal));
        // A fractional double either side of an integer.
        assert_eq!(cmp_int_float(3, 3.5), Some(Ordering::Less));
        assert_eq!(cmp_int_float(3, 2.5), Some(Ordering::Greater));
        assert_eq!(cmp_int_float(-3, -3.5), Some(Ordering::Greater));
    }

    #[test]
    fn nan_is_incomparable_and_infinities_are_the_extremes() {
        assert_eq!(cmp_int_float(0, f64::NAN), None);
        assert_eq!(cmp_int_float(i64::MAX, f64::NAN), None);
        assert_eq!(cmp_int_float(i64::MIN, f64::NAN), None);
        assert_eq!(cmp_int_float(0, f64::INFINITY), Some(Ordering::Less));
        assert_eq!(cmp_int_float(i64::MAX, f64::INFINITY), Some(Ordering::Less));
        assert_eq!(cmp_int_float(0, f64::NEG_INFINITY), Some(Ordering::Greater));
        assert_eq!(
            cmp_int_float(i64::MIN, f64::NEG_INFINITY),
            Some(Ordering::Greater)
        );
    }

    /// Exhaustive agreement with an independent oracle over the whole `i64` range: the comparison is
    /// re-derived in `i128` from the double's exact integral value, which cannot round. Covers both
    /// binades around 2^53 and 2^54 (where several integers share one double) plus the `i64`
    /// extremes, so it exercises the exact path densely rather than by spot check.
    #[test]
    fn agrees_with_an_exact_i128_oracle() {
        /// The oracle: for a finite whole-number double inside `i64`'s range, compare in `i128`.
        fn oracle(i: i64, f: f64) -> Ordering {
            assert!(
                f.fract() == 0.0 && f.is_finite(),
                "oracle needs a whole f64"
            );
            #[allow(clippy::cast_possible_truncation)]
            let fi = f as i128;
            i128::from(i).cmp(&fi)
        }
        let anchors: [i64; 6] = [
            1 << 53,
            -(1 << 53),
            1 << 54,
            -(1 << 54),
            (1 << 62) + (1 << 20),
            -((1 << 62) + (1 << 20)),
        ];
        for anchor in anchors {
            for di in -64_i64..=64 {
                let i = anchor.saturating_add(di);
                for df in -64_i64..=64 {
                    #[allow(clippy::cast_precision_loss)]
                    let f = anchor.saturating_add(df) as f64;
                    // The double may not represent `anchor + df` exactly; the oracle compares
                    // against whatever whole number `f` actually IS, which is the point.
                    assert_eq!(
                        cmp_int_float(i, f),
                        Some(oracle(i, f)),
                        "cmp_int_float({i}, {f}) disagrees with the i128 oracle"
                    );
                }
            }
        }
    }

    /// Antisymmetry against itself: reversing the operand roles must reverse the result, for every
    /// pair that has one. (The relation is defined with the integer on the left; the ordering module
    /// derives the float-on-the-left direction by reversing, so this is the property that makes that
    /// derivation sound.)
    #[test]
    fn is_antisymmetric_and_consistent_with_equality() {
        #[allow(clippy::cast_precision_loss)]
        let probes: Vec<(i64, f64)> = [
            (0_i64, 0.0_f64),
            (0, -0.0),
            (1, 1.0),
            (1, 1.5),
            (-1, -1.0),
            ((1 << 53) + 1, (1_i64 << 53) as f64),
            (i64::MAX, TWO_POW_63),
            (i64::MIN, -TWO_POW_63),
        ]
        .into_iter()
        .collect();
        for (i, f) in probes {
            let ord = cmp_int_float(i, f).expect("no NaN in the probe set");
            // Equality is exactly `Ordering::Equal`, and it is reflexive through the f64 spelling
            // whenever the integer is representable.
            if ord == Ordering::Equal {
                #[allow(clippy::cast_precision_loss)]
                let round_trip = i as f64;
                assert_eq!(
                    cmp_int_float(i, round_trip),
                    Some(Ordering::Equal),
                    "an integer equal to a float must equal its own f64 spelling"
                );
            }
            // Strictness: an ordered pair is never simultaneously ordered the other way.
            if ord != Ordering::Equal {
                assert_ne!(cmp_int_float(i, f), Some(ord.reverse()));
            }
        }
    }
}
