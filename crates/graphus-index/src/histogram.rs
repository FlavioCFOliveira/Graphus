//! Equi-depth property histograms over order-preserving encoded values (`04-technical-design.md`
//! §6, cardinality-estimation track; rmp task #81 stage 1).
//!
//! A [`PropertyHistogram`] is a compact summary of the distribution of one indexed property's
//! values, used by the query planner for **cardinality estimation** (how many rows an equality or
//! range predicate will select). It is the input to selectivity-based plan costing, so its only job
//! is to answer "roughly how many rows match this predicate?" cheaply and stably.
//!
//! # The order-preserving-bytes invariant
//!
//! Every value fed to this module is the output of [`crate::keycodec`], the crate's
//! **order-preserving** encoder: for any two Cypher values `a`, `b`,
//!
//! ```text
//! encode(a) <= encode(b)  (lexicographically, as byte slices)
//!     iff   a <= b        (in Cypher's defined total order)
//! ```
//!
//! Because of this, the histogram never needs to *decode* anything: it compares encoded values with
//! plain lexicographic [`Ord`] on `&[u8]`, which is exactly Cypher value order. The histogram is
//! therefore **type-agnostic and decode-free** — it works identically for integers, strings,
//! temporals, and mixed-type columns, and it can be built and queried entirely in encoded-byte
//! space. This is the whole reason the planner can reuse a single histogram shape for every column.
//!
//! # Equi-depth bucketing
//!
//! The histogram partitions the sorted values into [`Bucket`]s of approximately **equal row count**
//! (the "depth"), rather than equal value-width (which would be an *equi-width* histogram). Equi-depth
//! adapts to skew: a region of the value space with many rows gets more (narrower) buckets, so the
//! per-bucket uniformity assumption holds better where it matters. The classic reference is
//! Piatetsky-Shapiro & Connell, *Accurate Estimation of the Number of Tuples Satisfying a Condition*
//! (SIGMOD 1984), which introduced equi-depth (then called "equi-height") histograms for exactly
//! this purpose.
//!
//! Two hard rules shape the buckets:
//!
//! 1. **A value is never split across buckets.** All copies of one distinct value live in a single
//!    bucket. This keeps [`PropertyHistogram::estimate_eq`] well-defined (a value belongs to exactly
//!    one bucket) and is what makes a bucket boundary always fall on a real value boundary.
//! 2. **The upper bound of a bucket is a value that actually occurs** in the data (the largest value
//!    in that bucket). Range estimation relies on these being real, comparable boundaries.
//!
//! Because rule 1 forbids splitting a value, a single very frequent value can make its bucket
//! heavier than the equi-depth target; that is intentional and correct (the alternative — splitting —
//! would corrupt equality estimation).
//!
//! # Error model (what the estimates guarantee)
//!
//! Let `D = total / buckets.len()` be the equi-depth target depth (rows per bucket). The textbook
//! equi-depth error bounds, which this implementation realises, are:
//!
//! - **Equality** ([`PropertyHistogram::estimate_eq`]): the estimate is `bucket.count / bucket.distinct`
//!   (uniform-within-bucket assumption). The error is bounded by the **within-bucket frequency skew**:
//!   if every distinct value in the bucket had the same frequency the estimate would be exact, so the
//!   absolute error per value is at most the spread between the most- and least-frequent value in its
//!   bucket. Equi-depth keeps buckets shallow (`~D` rows) precisely to keep this spread small.
//! - **Range** ([`PropertyHistogram::estimate_range`]): buckets that fall entirely inside the query
//!   interval contribute their exact `count`; the (at most two) boundary buckets that the interval
//!   only partially covers each contribute **half** their count — the standard "continuous-value
//!   assumption" heuristic. The error is therefore at most **half a bucket depth per open end**, i.e.
//!   bounded by `D` total (`~D/2` per boundary bucket). Shrinking `D` (more buckets) shrinks this
//!   bound linearly. This is the textbook equi-depth range bound.
//!
//! These are *distribution-independent* worst cases on the structural error; the actual error is
//! usually far smaller. The unit tests assert these bounds numerically.

/// A persisted, order-preserving summary of one property's value distribution (see module docs).
///
/// Built from the sorted encoded values of an index by [`PropertyHistogram::from_sorted_encoded`]
/// (or [`crate::kinds::PropertyIndex::build_histogram`]), and queried by [`Self::estimate_eq`] /
/// [`Self::estimate_range`]. Cloneable and serialisable ([`Self::encode`] / [`Self::decode`]) for
/// persistence in the statistics catalogue (a later stage).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyHistogram {
    /// The number of indexed (non-null) rows that fed the histogram, counting duplicates. This is
    /// the sum of every bucket's `count` and the denominator for selectivity.
    total: u64,
    /// The number of *distinct* encoded values across the whole histogram (the sum of every bucket's
    /// `distinct`, since a value belongs to exactly one bucket).
    distinct: u64,
    /// The smallest encoded value present — the inclusive lower edge of the first bucket. Stored
    /// explicitly so the first bucket's range `[min, buckets[0].upper]` is fully determined and both
    /// equality and range estimation handle the below-minimum case exactly (rather than approximating
    /// the minimum as the empty byte string). Empty for the empty histogram.
    min: Vec<u8>,
    /// The buckets in ascending value order. Each holds `~total/target_buckets` rows; bucket `i`'s
    /// value range is `(buckets[i-1].upper, buckets[i].upper]` (half-open below, inclusive upper) for
    /// `i > 0`, and the first bucket's range is the closed `[min, buckets[0].upper]`.
    buckets: Vec<Bucket>,
}

/// One equi-depth bucket: a contiguous slice of the sorted value space and its row/distinct counts.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Bucket {
    /// The inclusive encoded **upper bound** of this bucket — the largest value it contains, an
    /// actual value present in the data (never a synthetic boundary).
    upper: Vec<u8>,
    /// The number of rows (values including duplicates) in this bucket — the equi-depth "depth".
    count: u64,
    /// The number of distinct values in this bucket (`>= 1` for any bucket that exists).
    distinct: u64,
}

/// How a query interval overlaps a single bucket's value range, used to decide that bucket's
/// contribution to a range estimate (see [`PropertyHistogram::classify_bucket`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BucketOverlap {
    /// The interval contains the bucket's whole range — contribute the full `count`.
    Full,
    /// The interval intersects the bucket but does not contain it — contribute half the `count`.
    Partial,
    /// The interval and the bucket are disjoint — contribute nothing.
    None,
}

/// An error returned when [`PropertyHistogram::decode`] is given malformed bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistogramDecodeError {
    /// The input ended before a fixed-width field or a declared-length payload was fully read. Holds
    /// a short static description of which field was being read.
    Truncated(&'static str),
    /// A length prefix or bucket count was larger than the bytes that remain, so the record cannot be
    /// consistent (e.g. a bucket-bound length that overruns the buffer, or a declared bucket count
    /// the body does not satisfy).
    InconsistentLength,
    /// Trailing bytes remained after a complete, well-formed record was decoded. The format is
    /// length-exact, so extra bytes signal a corrupted or mis-framed record.
    TrailingBytes,
}

impl std::fmt::Display for HistogramDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated(field) => write!(f, "histogram bytes truncated while reading {field}"),
            Self::InconsistentLength => {
                write!(f, "histogram length prefix is inconsistent with the buffer")
            }
            Self::TrailingBytes => write!(f, "histogram bytes have unexpected trailing data"),
        }
    }
}

impl std::error::Error for HistogramDecodeError {}

/// The self-describing format magic, bumped if the layout ever changes incompatibly.
const HISTOGRAM_FORMAT_VERSION: u8 = 1;

impl PropertyHistogram {
    /// Builds an equi-depth histogram from **all** encoded values of a property, including duplicates,
    /// in **ascending byte order**.
    ///
    /// `values` must already be sorted ascending (the caller — an index scan — produces them in key
    /// order, so this is free); a `debug_assert!` checks it in debug builds. Each bucket targets
    /// `~total / target_buckets` rows, but a bucket boundary always falls on a value boundary: all
    /// copies of one value land in the same bucket (see the module-level bucketing rules). A
    /// `target_buckets` of `0` is treated as `1`. Empty input yields the empty histogram
    /// (`total == 0`, `distinct == 0`, no buckets).
    #[must_use]
    pub fn from_sorted_encoded(values: &[Vec<u8>], target_buckets: usize) -> Self {
        debug_assert!(
            values.windows(2).all(|w| w[0] <= w[1]),
            "from_sorted_encoded requires ascending byte order",
        );

        let total = values.len() as u64;
        if total == 0 {
            return Self {
                total: 0,
                distinct: 0,
                min: Vec::new(),
                buckets: Vec::new(),
            };
        }
        // Sorted ascending, so the first element is the global minimum (the first bucket's lower edge).
        let min = values[0].clone();

        // At least one bucket; `target` is the equi-depth depth, rounded *up* so we never produce
        // more than `target_buckets` buckets from the row count alone (ceil division).
        let target_buckets = target_buckets.max(1) as u64;
        let target = total.div_ceil(target_buckets).max(1);

        let mut buckets: Vec<Bucket> = Vec::new();
        // The bucket currently being filled, as (count, distinct, last_value). `last_value` is the
        // running upper bound; we only commit it into a `Bucket` when the bucket closes.
        let mut cur_count: u64 = 0;
        let mut cur_distinct: u64 = 0;
        let mut cur_upper: &[u8] = &[];

        let mut i = 0;
        while i < values.len() {
            // Consume the whole run of one distinct value — it can never be split across buckets.
            let v = &values[i];
            let mut run = 0u64;
            while i < values.len() && values[i] == *v {
                run += 1;
                i += 1;
            }

            // If adding this run would overshoot the target *and* the current bucket is non-empty,
            // close the current bucket first so the new run starts a fresh one. This keeps each
            // bucket near the target depth without ever splitting a value's run.
            if cur_count > 0 && cur_count + run > target {
                buckets.push(Bucket {
                    upper: cur_upper.to_vec(),
                    count: cur_count,
                    distinct: cur_distinct,
                });
                cur_count = 0;
                cur_distinct = 0;
            }

            cur_count += run;
            cur_distinct += 1;
            cur_upper = v;
        }

        // Flush the final (always non-empty here, since total > 0) bucket.
        buckets.push(Bucket {
            upper: cur_upper.to_vec(),
            count: cur_count,
            distinct: cur_distinct,
        });

        let distinct = buckets.iter().map(|b| b.distinct).sum();
        Self {
            total,
            distinct,
            min,
            buckets,
        }
    }

    /// The number of indexed (non-null) rows summarised, counting duplicates.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.total
    }

    /// The number of distinct encoded values summarised.
    #[must_use]
    pub fn distinct(&self) -> u64 {
        self.distinct
    }

    /// Whether the histogram summarises no rows (no buckets).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// Bucket `i`'s **lower edge** as a `(value, inclusive)` pair:
    ///
    /// - bucket `0` is closed at the dataset minimum: `(min, true)` — its range is `[min, upper_0]`;
    /// - bucket `i > 0` is half-open below at the previous bucket's `upper`: `(buckets[i-1].upper,
    ///   false)` — its range is `(buckets[i-1].upper, upper_i]`.
    ///
    /// The half-open-below rule for later buckets reflects that all copies of one value share a single
    /// bucket: a value equal to a previous bucket's `upper` belongs to *that* bucket, not this one.
    fn lower_edge(&self, i: usize) -> (&[u8], bool) {
        if i == 0 {
            (self.min.as_slice(), true)
        } else {
            (self.buckets[i - 1].upper.as_slice(), false)
        }
    }

    /// Whether `encoded` lies in bucket `i`'s range (`[min, upper_0]` for bucket 0, otherwise
    /// `(prev_upper, upper_i]`).
    fn bucket_contains(&self, i: usize, encoded: &[u8]) -> bool {
        let (edge, inclusive) = self.lower_edge(i);
        let above_lower = if inclusive {
            encoded >= edge
        } else {
            encoded > edge
        };
        above_lower && encoded <= self.buckets[i].upper.as_slice()
    }

    /// Estimates the number of rows whose value equals `encoded`.
    ///
    /// Locates the unique bucket whose range contains `encoded` and applies the uniform-within-bucket
    /// assumption: `bucket.count / bucket.distinct`. Returns `0.0` if `encoded` is outside the whole
    /// value range (below `min` or above the largest `upper`) or the histogram is empty. See the
    /// module-level error model for the bound this carries.
    #[must_use]
    pub fn estimate_eq(&self, encoded: &[u8]) -> f64 {
        // The buckets partition `[min, max]` in ascending order, so the first bucket whose `upper` is
        // `>= encoded` is the only one that can contain `encoded`; `bucket_contains` then confirms it
        // is also at/above that bucket's lower edge (which, for bucket 0, rejects values below `min`).
        for i in 0..self.buckets.len() {
            if encoded <= self.buckets[i].upper.as_slice() {
                if self.bucket_contains(i, encoded) && self.buckets[i].distinct > 0 {
                    return self.buckets[i].count as f64 / self.buckets[i].distinct as f64;
                }
                return 0.0;
            }
        }
        0.0
    }

    /// Estimates the number of rows whose value lies in the interval bounded by `lo`/`hi`.
    ///
    /// Each bound is optional (`None` = unbounded on that side) and carries an inclusivity flag.
    /// Buckets whose entire range falls inside the interval contribute their exact `count`; the
    /// at-most-two boundary buckets the interval only partially covers each contribute **half** their
    /// count (the continuous-value heuristic — see the module-level error model, where the bound is
    /// `~half a bucket depth per open end`). The result is clamped to `[0.0, total]`. An empty
    /// histogram, or an interval that overlaps nothing, yields `0.0`.
    #[must_use]
    pub fn estimate_range(
        &self,
        lo: Option<&[u8]>,
        lo_inclusive: bool,
        hi: Option<&[u8]>,
        hi_inclusive: bool,
    ) -> f64 {
        let mut estimate = 0.0f64;
        for i in 0..self.buckets.len() {
            match self.classify_bucket(i, lo, lo_inclusive, hi, hi_inclusive) {
                BucketOverlap::Full => estimate += self.buckets[i].count as f64,
                BucketOverlap::Partial => estimate += self.buckets[i].count as f64 / 2.0,
                BucketOverlap::None => {}
            }
        }
        estimate.clamp(0.0, self.total as f64)
    }

    /// Classifies how the query interval overlaps bucket `i`'s value range.
    ///
    /// The query interval is `{ v : lo_cmp(v) and hi_cmp(v) }` with the bound inclusivity applied. A
    /// bucket is [`Full`] when the interval contains the bucket's whole range, [`Partial`] when it
    /// intersects it without containing it, and [`None`] when they are disjoint. The contribution rule
    /// (full count vs half count vs nothing) follows directly.
    ///
    /// [`Full`]: BucketOverlap::Full
    /// [`Partial`]: BucketOverlap::Partial
    /// [`None`]: BucketOverlap::None
    fn classify_bucket(
        &self,
        i: usize,
        lo: Option<&[u8]>,
        lo_inclusive: bool,
        hi: Option<&[u8]>,
        hi_inclusive: bool,
    ) -> BucketOverlap {
        let bucket_upper = self.buckets[i].upper.as_slice();
        let (edge, edge_inclusive) = self.lower_edge(i);

        // Full coverage: the query contains the bucket's whole range. The query's lower bound must
        // reach at or below the bucket's lowest possible value, and its upper bound at or above the
        // bucket's `upper`.
        //
        // The bucket's lowest possible value is `edge` itself when the edge is inclusive (bucket 0),
        // else the smallest value strictly above `edge` (later buckets). So the query lower bound
        // `covers the start` when:
        //   - unbounded below: always;
        //   - inclusive edge (bucket 0): `lo <= min` (i.e. `lo <= edge`);
        //   - exclusive edge (later):    `lo <= edge` — any query lower bound at or below the exclusive
        //     edge sits below every value the bucket holds (all `> edge`), so it covers the start.
        let lo_covers_start = match lo {
            None => true,
            Some(l) => l <= edge,
        };
        let hi_covers_end = match hi {
            None => true,
            Some(h) => {
                if hi_inclusive {
                    h >= bucket_upper
                } else {
                    h > bucket_upper
                }
            }
        };
        if lo_covers_start && hi_covers_end {
            return BucketOverlap::Full;
        }

        // Any overlap at all? The interval touches the bucket iff its lower bound reaches at or below
        // the bucket's `upper`, and its upper bound reaches a value the bucket actually holds (at or
        // above `edge` for an inclusive edge, strictly above `edge` for an exclusive edge).
        let lo_within = match lo {
            None => true,
            Some(l) => {
                if lo_inclusive {
                    l <= bucket_upper
                } else {
                    l < bucket_upper
                }
            }
        };
        let hi_within = match hi {
            None => true,
            Some(h) => {
                if hi_inclusive {
                    // An inclusive upper at the exclusive edge still cannot reach a value `> edge`.
                    if edge_inclusive { h >= edge } else { h > edge }
                } else {
                    // An exclusive upper at or below the lowest bucket value cannot reach it.
                    h > edge
                }
            }
        };
        if lo_within && hi_within {
            BucketOverlap::Partial
        } else {
            BucketOverlap::None
        }
    }

    /// Serialises the histogram into a deterministic, self-describing, length-prefixed,
    /// little-endian byte string suitable for persistence.
    ///
    /// Layout:
    ///
    /// ```text
    /// version: u8                     // HISTOGRAM_FORMAT_VERSION
    /// total:   u64 LE
    /// distinct:u64 LE
    /// min_len: u32 LE
    /// min:     [u8; min_len]          // smallest encoded value (empty when total == 0)
    /// nbuckets:u32 LE
    /// repeated nbuckets times:
    ///     upper_len: u32 LE
    ///     upper:     [u8; upper_len]
    ///     count:     u64 LE
    ///     distinct:  u64 LE
    /// ```
    ///
    /// The format is length-exact: [`Self::decode`] consumes the whole buffer and rejects any
    /// trailing bytes, so it round-trips deterministically (`decode(encode(h)) == h`).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(1 + 8 + 8 + 4 + self.min.len() + 4 + self.buckets.len() * 24);
        out.push(HISTOGRAM_FORMAT_VERSION);
        out.extend_from_slice(&self.total.to_le_bytes());
        out.extend_from_slice(&self.distinct.to_le_bytes());
        out.extend_from_slice(&(self.min.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.min);
        // The bucket count fits in u32 for any realistic statistic; cast is checked by the round-trip.
        out.extend_from_slice(&(self.buckets.len() as u32).to_le_bytes());
        for b in &self.buckets {
            out.extend_from_slice(&(b.upper.len() as u32).to_le_bytes());
            out.extend_from_slice(&b.upper);
            out.extend_from_slice(&b.count.to_le_bytes());
            out.extend_from_slice(&b.distinct.to_le_bytes());
        }
        out
    }

    /// Deserialises a histogram produced by [`Self::encode`].
    ///
    /// # Errors
    /// Returns [`HistogramDecodeError`] if the input is truncated, declares a length that overruns the
    /// buffer, or carries trailing bytes after a complete record.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistogramDecodeError> {
        let mut cur = Cursor::new(bytes);
        let version = cur.u8("version")?;
        if version != HISTOGRAM_FORMAT_VERSION {
            // A future revision would bump the magic; an unknown version is an inconsistent record.
            return Err(HistogramDecodeError::InconsistentLength);
        }
        let total = cur.u64("total")?;
        let distinct = cur.u64("distinct")?;
        let min_len = cur.u32("min length")? as usize;
        let min = cur.bytes(min_len, "min value")?.to_vec();
        let nbuckets = cur.u32("bucket count")? as usize;

        let mut buckets = Vec::with_capacity(nbuckets.min(1024));
        let mut bucket_distinct_sum: u64 = 0;
        let mut bucket_count_sum: u64 = 0;
        for _ in 0..nbuckets {
            let upper_len = cur.u32("bucket upper length")? as usize;
            let upper = cur.bytes(upper_len, "bucket upper")?.to_vec();
            let count = cur.u64("bucket count")?;
            let bdistinct = cur.u64("bucket distinct")?;
            bucket_count_sum = bucket_count_sum.saturating_add(count);
            bucket_distinct_sum = bucket_distinct_sum.saturating_add(bdistinct);
            buckets.push(Bucket {
                upper,
                count,
                distinct: bdistinct,
            });
        }

        if !cur.is_at_end() {
            return Err(HistogramDecodeError::TrailingBytes);
        }
        // Cross-check the header totals against the bucket bodies: a record whose declared totals do
        // not match the buckets it carries is inconsistent (corruption or a framing error). Also check
        // the empty/non-empty structural invariant ties `min` to the buckets.
        if bucket_count_sum != total || bucket_distinct_sum != distinct {
            return Err(HistogramDecodeError::InconsistentLength);
        }
        match buckets.first() {
            // Non-empty: `min` must be a real value at or below the first bucket's upper.
            Some(first) if min <= first.upper && total > 0 => {}
            // Empty: no buckets, no rows, and `min` must be empty.
            None if total == 0 && distinct == 0 && min.is_empty() => {}
            _ => return Err(HistogramDecodeError::InconsistentLength),
        }

        Ok(Self {
            total,
            distinct,
            min,
            buckets,
        })
    }
}

/// A minimal forward-only byte cursor for [`PropertyHistogram::decode`], with bounds-checked reads
/// that map underruns to [`HistogramDecodeError`].
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn is_at_end(&self) -> bool {
        self.pos == self.buf.len()
    }

    fn bytes(&mut self, n: usize, field: &'static str) -> Result<&'a [u8], HistogramDecodeError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(HistogramDecodeError::InconsistentLength)?;
        if end > self.buf.len() {
            // A field longer than the remaining buffer is both a truncation and a length
            // inconsistency; we report truncation for a fixed-width read and inconsistency when the
            // overrun is driven by a declared length (handled at the call site for `bytes`).
            return Err(HistogramDecodeError::InconsistentLength);
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        let _ = field;
        Ok(out)
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, HistogramDecodeError> {
        let s = self.fixed::<1>(field)?;
        Ok(s[0])
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, HistogramDecodeError> {
        Ok(u32::from_le_bytes(self.fixed::<4>(field)?))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, HistogramDecodeError> {
        Ok(u64::from_le_bytes(self.fixed::<8>(field)?))
    }

    /// Reads a fixed-width field, mapping an underrun to [`HistogramDecodeError::Truncated`].
    fn fixed<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], HistogramDecodeError> {
        let end = self
            .pos
            .checked_add(N)
            .ok_or(HistogramDecodeError::InconsistentLength)?;
        if end > self.buf.len() {
            return Err(HistogramDecodeError::Truncated(field));
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&self.buf[self.pos..end]);
        self.pos = end;
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keycodec::encode_single;
    use graphus_core::Value;

    /// Encodes a single value to its order-preserving bytes (test helper).
    fn enc(v: &Value) -> Vec<u8> {
        encode_single(v).unwrap()
    }

    /// Encodes a sorted run of integers (each once) into encoded byte order.
    fn enc_ints(range: std::ops::Range<i64>) -> Vec<Vec<u8>> {
        range.map(|i| enc(&Value::Integer(i))).collect()
    }

    /// A brute-force oracle: the exact number of rows equal to `target` in `rows`.
    fn oracle_eq(rows: &[Vec<u8>], target: &[u8]) -> u64 {
        rows.iter().filter(|v| v.as_slice() == target).count() as u64
    }

    /// A brute-force oracle: the exact number of rows in `[lo, hi)` (half-open) in `rows`.
    fn oracle_range_half_open(rows: &[Vec<u8>], lo: &[u8], hi: &[u8]) -> u64 {
        rows.iter()
            .filter(|v| v.as_slice() >= lo && v.as_slice() < hi)
            .count() as u64
    }

    #[test]
    fn empty_input_is_empty_histogram() {
        let h = PropertyHistogram::from_sorted_encoded(&[], 16);
        assert!(h.is_empty());
        assert_eq!(h.total(), 0);
        assert_eq!(h.distinct(), 0);
        assert_eq!(h.estimate_eq(&enc(&Value::Integer(5))), 0.0);
        assert_eq!(
            h.estimate_range(None, true, None, true),
            0.0,
            "range over empty histogram is 0"
        );
    }

    #[test]
    fn target_buckets_zero_is_treated_as_one() {
        let rows = enc_ints(0..100);
        let h = PropertyHistogram::from_sorted_encoded(&rows, 0);
        assert_eq!(h.total(), 100);
        assert_eq!(h.distinct(), 100);
        // One bucket holds everything.
        assert_eq!(h.estimate_range(None, true, None, true), 100.0);
    }

    #[test]
    fn totals_and_distinct_are_exact() {
        // 0..1000 each once, plus 500 appearing 9 extra times (10 total).
        let mut rows = enc_ints(0..1000);
        for _ in 0..9 {
            rows.push(enc(&Value::Integer(500)));
        }
        rows.sort();
        let h = PropertyHistogram::from_sorted_encoded(&rows, 32);
        assert_eq!(
            h.total(),
            1009,
            "1000 distinct rows + 9 duplicate copies of 500"
        );
        assert_eq!(h.distinct(), 1000, "still 1000 distinct values");
    }

    #[test]
    fn uniform_distribution_equality_within_bound() {
        // 0..1000, one row each. Every equality estimate should be ~1.
        let rows = enc_ints(0..1000);
        let target_buckets = 32usize;
        let h = PropertyHistogram::from_sorted_encoded(&rows, target_buckets);

        // The equi-depth depth.
        let depth = (h.total() as f64) / (target_buckets as f64);
        // With a perfectly uniform distribution and value-aligned buckets, count/distinct == 1 for
        // every bucket (each value appears once), so the estimate is exactly 1 — well inside the
        // within-bucket-skew bound (which is 0 here).
        for i in (0..1000).step_by(37) {
            let est = h.estimate_eq(&enc(&Value::Integer(i)));
            assert!(
                (est - 1.0).abs() < 1e-9,
                "uniform eq estimate for {i} was {est}, expected 1.0 (depth={depth})"
            );
        }
    }

    #[test]
    fn uniform_distribution_range_within_half_bucket_depth() {
        let rows = enc_ints(0..1000);
        let target_buckets = 32usize;
        let h = PropertyHistogram::from_sorted_encoded(&rows, target_buckets);
        let depth = (h.total() as f64) / (target_buckets as f64);

        // Sub-range [200, 700): true count is 500.
        let lo = enc(&Value::Integer(200));
        let hi = enc(&Value::Integer(700));
        let true_count = oracle_range_half_open(&rows, &lo, &hi) as f64;
        let est = h.estimate_range(Some(&lo), true, Some(&hi), false);

        // Documented bound: error <= ~half a bucket depth per open end => <= one full depth.
        let bound = depth; // two boundary buckets, ~depth/2 each
        assert!(
            (est - true_count).abs() <= bound + 1e-9,
            "range estimate {est} vs true {true_count} exceeded equi-depth bound {bound}"
        );
    }

    #[test]
    fn skewed_distribution_concentrates_and_estimates_frequent_values() {
        // A Zipfian-ish shape: value 0 is very frequent, then a long tail of singletons.
        let mut rows: Vec<Vec<u8>> = Vec::new();
        for _ in 0..500 {
            rows.push(enc(&Value::Integer(0)));
        }
        for i in 1..501 {
            rows.push(enc(&Value::Integer(i)));
        }
        rows.sort();
        let total = rows.len() as u64; // 1000
        let target_buckets = 20usize;
        let h = PropertyHistogram::from_sorted_encoded(&rows, target_buckets);
        assert_eq!(h.total(), total);
        assert_eq!(h.distinct(), 501);

        // The frequent value (0) has true frequency 500. Its bucket holds it (possibly with a few
        // neighbours); count/distinct should be close to 500 and certainly far above 1.
        let est0 = h.estimate_eq(&enc(&Value::Integer(0)));
        assert!(
            est0 > 100.0,
            "frequent value estimate {est0} should reflect its heavy bucket"
        );

        // A tail singleton estimates near 1 (its bucket is all singletons).
        let est_tail = h.estimate_eq(&enc(&Value::Integer(400)));
        assert!(
            (est_tail - 1.0).abs() <= 2.0,
            "tail singleton estimate {est_tail} should be ~1"
        );
    }

    #[test]
    fn equality_outside_range_is_zero() {
        let rows = enc_ints(10..20);
        let h = PropertyHistogram::from_sorted_encoded(&rows, 4);
        // Above the max.
        assert_eq!(h.estimate_eq(&enc(&Value::Integer(100))), 0.0);
        // A value larger than every recorded value but of a *higher* type also sorts above.
        assert_eq!(h.estimate_eq(&enc(&Value::Integer(i64::MAX))), 0.0);
        // Below the minimum (exact, thanks to the stored `min`): value 5 < min (10) => 0.
        assert_eq!(h.estimate_eq(&enc(&Value::Integer(5))), 0.0);
        assert_eq!(h.estimate_eq(&enc(&Value::Integer(i64::MIN))), 0.0);
        // The minimum itself is in range and estimates to its frequency (1).
        assert!((h.estimate_eq(&enc(&Value::Integer(10))) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn range_below_minimum_is_zero() {
        // A range entirely below the dataset minimum contributes nothing (the boundary heuristic must
        // not leak half of the first bucket for a non-overlapping interval).
        let rows = enc_ints(100..200);
        let h = PropertyHistogram::from_sorted_encoded(&rows, 8);
        let lo = enc(&Value::Integer(0));
        let hi = enc(&Value::Integer(50));
        assert_eq!(h.estimate_range(Some(&lo), true, Some(&hi), true), 0.0);
        // A range entirely above the maximum is likewise zero.
        let lo2 = enc(&Value::Integer(500));
        assert_eq!(h.estimate_range(Some(&lo2), true, None, true), 0.0);
    }

    #[test]
    fn equal_values_are_never_split_across_buckets() {
        // 1000 copies of one value, surrounded by singletons, with many target buckets. All 1000
        // copies must land in a single bucket — verified by the equality estimate being exactly the
        // full frequency (count/distinct with distinct==1 in that bucket).
        let mut rows: Vec<Vec<u8>> = Vec::new();
        rows.push(enc(&Value::Integer(-1)));
        for _ in 0..1000 {
            rows.push(enc(&Value::Integer(0)));
        }
        rows.push(enc(&Value::Integer(1)));
        rows.sort();
        let h = PropertyHistogram::from_sorted_encoded(&rows, 50);

        let est = h.estimate_eq(&enc(&Value::Integer(0)));
        assert!(
            (est - 1000.0).abs() < 1e-9,
            "all 1000 copies of value 0 must share one bucket (est={est})"
        );
    }

    #[test]
    fn range_clamps_to_total_and_handles_unbounded() {
        let rows = enc_ints(0..100);
        let h = PropertyHistogram::from_sorted_encoded(&rows, 8);
        // Fully unbounded covers everything.
        assert_eq!(h.estimate_range(None, true, None, true), 100.0);
        // Unbounded-below up to a high inclusive bound is everything.
        let hi = enc(&Value::Integer(1000));
        assert_eq!(h.estimate_range(None, true, Some(&hi), true), 100.0);
        // Unbounded-above from a low bound is everything.
        let lo = enc(&Value::Integer(-1000));
        assert_eq!(h.estimate_range(Some(&lo), true, None, true), 100.0);
    }

    #[test]
    fn range_half_open_vs_oracle_many_windows() {
        let rows = enc_ints(0..1000);
        let target_buckets = 40usize;
        let h = PropertyHistogram::from_sorted_encoded(&rows, target_buckets);
        let depth = (h.total() as f64) / (target_buckets as f64);
        let bound = depth + 1e-9; // <= one full depth (two open ends)

        for &(a, b) in &[(0i64, 1000i64), (100, 200), (333, 777), (0, 1), (999, 1000)] {
            let lo = enc(&Value::Integer(a));
            let hi = enc(&Value::Integer(b));
            let truth = oracle_range_half_open(&rows, &lo, &hi) as f64;
            let est = h.estimate_range(Some(&lo), true, Some(&hi), false);
            assert!(
                (est - truth).abs() <= bound,
                "window [{a},{b}) est={est} truth={truth} bound={bound}"
            );
        }
    }

    #[test]
    fn codec_roundtrip_empty_single_and_many_buckets() {
        // Empty.
        let empty = PropertyHistogram::from_sorted_encoded(&[], 8);
        assert_eq!(PropertyHistogram::decode(&empty.encode()).unwrap(), empty);

        // Single bucket (few values, one bucket target).
        let single = PropertyHistogram::from_sorted_encoded(&enc_ints(0..5), 1);
        assert_eq!(single.buckets.len(), 1);
        assert_eq!(PropertyHistogram::decode(&single.encode()).unwrap(), single);

        // Many buckets, mixed types so bucket uppers have differing lengths.
        let mut rows: Vec<Vec<u8>> = Vec::new();
        rows.extend(enc_ints(0..200));
        for s in ["alpha", "beta", "gamma", "delta"] {
            rows.push(enc(&Value::String(s.to_owned())));
        }
        rows.push(enc(&Value::Boolean(true)));
        rows.sort();
        let many = PropertyHistogram::from_sorted_encoded(&rows, 16);
        assert!(many.buckets.len() > 1);
        let bytes = many.encode();
        assert_eq!(PropertyHistogram::decode(&bytes).unwrap(), many);
    }

    #[test]
    fn decode_rejects_truncated_input() {
        let h = PropertyHistogram::from_sorted_encoded(&enc_ints(0..50), 8);
        let bytes = h.encode();
        // Truncate at several points; every prefix shorter than the full record must error.
        for cut in 0..bytes.len() {
            assert!(
                PropertyHistogram::decode(&bytes[..cut]).is_err(),
                "truncated decode at {cut} bytes unexpectedly succeeded"
            );
        }
        // The full record decodes.
        assert!(PropertyHistogram::decode(&bytes).is_ok());
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let h = PropertyHistogram::from_sorted_encoded(&enc_ints(0..10), 4);
        let mut bytes = h.encode();
        bytes.push(0xAB); // one byte too many
        assert_eq!(
            PropertyHistogram::decode(&bytes),
            Err(HistogramDecodeError::TrailingBytes)
        );
    }

    #[test]
    fn decode_rejects_inconsistent_header_totals() {
        let h = PropertyHistogram::from_sorted_encoded(&enc_ints(0..10), 4);
        let mut bytes = h.encode();
        // Corrupt the `total` field (bytes 1..9) so it disagrees with the bucket bodies.
        bytes[1] = bytes[1].wrapping_add(1);
        assert_eq!(
            PropertyHistogram::decode(&bytes),
            Err(HistogramDecodeError::InconsistentLength)
        );
    }

    #[test]
    fn decode_rejects_min_above_first_bucket_upper() {
        // Corrupt the stored `min` to a value greater than the first bucket's upper, which violates
        // the structural invariant `min <= buckets[0].upper`.
        let h = PropertyHistogram::from_sorted_encoded(&enc_ints(0..40), 4);
        let mut bytes = h.encode();
        // Header layout: version(1) total(8) distinct(8) min_len(4) min(min_len) ...
        let min_len = u32::from_le_bytes(bytes[17..21].try_into().unwrap()) as usize;
        assert!(
            min_len > 0,
            "first byte of the stored min must exist to corrupt"
        );
        // Bump the first byte of `min` to the max so it sorts above the first bucket's upper.
        bytes[21] = 0xFF;
        assert_eq!(
            PropertyHistogram::decode(&bytes),
            Err(HistogramDecodeError::InconsistentLength)
        );
    }

    #[test]
    fn mixed_type_ordering_respects_encoded_order() {
        // A string and a number: in Cypher (and the keycodec) STRING < NUMBER, so the string's
        // bucket(s) precede the number's. The histogram must place them per encoded order.
        let s = enc(&Value::String("hello".to_owned()));
        let n = enc(&Value::Integer(42));
        assert!(s < n, "precondition: keycodec orders STRING below NUMBER");
        let mut rows = vec![s.clone(), n.clone()];
        rows.sort();
        let h = PropertyHistogram::from_sorted_encoded(&rows, 2);
        // Each present value estimates to 1.
        assert!((h.estimate_eq(&s) - 1.0).abs() < 1e-9);
        assert!((h.estimate_eq(&n) - 1.0).abs() < 1e-9);
        // A range covering only the string side excludes the number.
        let just_below_n = enc(&Value::Integer(0)); // still a NUMBER, > any string
        let est = h.estimate_range(None, true, Some(&s), true);
        // Inclusive of the string value only: ~1 (one boundary bucket at most).
        assert!(
            est <= 1.0 + 1e-9,
            "range up to the string must not include the number (est={est})"
        );
        let _ = just_below_n;
    }

    #[test]
    fn eq_oracle_agreement_on_uniform_data() {
        // On strictly-once data the equality estimate equals the oracle exactly (== 1) for present
        // values and 0 for absent in-range gaps handled via distinct buckets.
        let rows = enc_ints(0..256);
        let h = PropertyHistogram::from_sorted_encoded(&rows, 16);
        for i in (0..256).step_by(11) {
            let target = enc(&Value::Integer(i));
            let est = h.estimate_eq(&target);
            let truth = oracle_eq(&rows, &target) as f64;
            assert!(
                (est - truth).abs() < 1e-9,
                "eq estimate {est} != oracle {truth} for {i}"
            );
        }
    }
}
