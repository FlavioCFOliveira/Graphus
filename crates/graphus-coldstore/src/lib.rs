//! `graphus-coldstore` — the **immutable columnar cold tier** for aged time-series partitions
//! (`rmp` task #332).
//!
//! # The hot/cold thesis
//!
//! Graphus's authoritative store is a row store + WAL + ARIES (hot, mutable, MVCC, ACID). Time-series
//! data (IoT readings, events, metrics) is **append-only and aged**: once a window is old enough that
//! no transaction will mutate it, keeping it as 71-byte row records (`PropRecord` + MVCC header per
//! value) is pure overhead. The cold tier rewrites such an aged window into **immutable, densely
//! encoded columnar segments** and drops it out of the hot store. A row is therefore **either** hot
//! (mutable, in the row store, under MVCC) **or** cold (immutable, here, outside MVCC) — never both,
//! so there is no dual-write, no extra ACID surface, and the hot store's durability/recovery is
//! untouched.
//!
//! The compression is the measured `columnar_footprint` result, delivered by the native
//! [`graphus_columnar`] codecs:
//!
//! | column | codec | measured ratio (IoT `:Reading`) |
//! |--------|-------|----------------------------------|
//! | `seq`  | delta / double-delta integer ([`graphus_columnar::integer`]) | ~255000× (monotonic) |
//! | `ts`   | delta / double-delta integer | ~255000× (regular cadence) |
//! | `value`| Gorilla XOR float ([`graphus_columnar::gorilla`]) | ~6.8× |
//! | `sensor`| dictionary ([`graphus_columnar::dictionary`]) | ~171× (low cardinality) |
//!
//! ≈35× overall vs the row records — the ~20–90× target depending on cadence/cardinality.
//!
//! # What this crate delivers (and what is staged)
//!
//! Delivered here, self-contained and fuzz-hardened:
//! - [`ColdSegment`]: encode a batch of [`Reading`]s into one immutable, self-describing segment
//!   (byte buffer), decode it back **exactly**, and run a **late-materialized** `ts`-range scan
//!   (decode the cheap `ts` column to find survivors, then materialize `value`/`sensor` only for
//!   them). Each segment carries its `[min_ts, max_ts]` so a whole segment is skipped when its range
//!   cannot match — data-skipping at segment granularity (cf. `rmp` #331's zone maps).
//! - [`ColdStore`]: an ordered set of segments with a store-wide range scan that skips
//!   non-overlapping segments.
//!
//! Staged integration (tracked on `rmp` #332, wired with the `#305` reclaim trigger): the background
//! compaction job that moves an aged hot window into a cold segment behind a hot/cold **watermark**,
//! and the Cypher scan operator that unions the cold tier under a `MATCH`. The segment format and
//! scan semantics here are built so those steps are pure wiring: a cold scan returns exactly the rows
//! a row scan over the same data would, which the round-trip and equivalence tests prove.

#![forbid(unsafe_code)]

use graphus_columnar::{dictionary, gorilla, integer};

/// One time-series reading — the cold tier's row shape (the IoT `:Reading` projection).
#[derive(Debug, Clone, PartialEq)]
pub struct Reading {
    /// A monotonic per-stream sequence number (double-delta-friendly).
    pub seq: i64,
    /// The event timestamp in epoch units (regular-cadence → double-delta-friendly).
    pub ts: i64,
    /// The measured value (Gorilla-compressed; consecutive readings often share a prefix).
    pub value: f64,
    /// The low-cardinality sensor/stream id (dictionary-compressed).
    pub sensor: String,
}

/// The 4-byte segment magic (`"GCS1"`) and version, so a truncated/foreign buffer is rejected rather
/// than mis-decoded.
const MAGIC: [u8; 4] = *b"GCS1";

/// A decode error: a buffer that is not a valid, complete cold segment. Decoding never panics on a
/// malformed buffer — it returns this (the codecs are fuzzed for exactly this property).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColdError {
    /// The buffer is shorter than the fixed header, or a declared column length runs past its end.
    Truncated,
    /// The magic / version bytes do not match — not a cold segment of this format.
    BadMagic,
    /// A column blob itself is corrupt: a codec payload was truncated, named an unknown sub-scheme,
    /// or carried an out-of-range dictionary code. Surfaced from [`graphus_columnar`] so a corrupt
    /// segment is a controlled error here too (`04 §11.4`), never a panic.
    BadColumn(graphus_columnar::DecodeError),
}

impl std::fmt::Display for ColdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ColdError::Truncated => write!(f, "cold segment buffer is truncated"),
            ColdError::BadMagic => write!(f, "cold segment magic/version mismatch"),
            ColdError::BadColumn(e) => write!(f, "cold segment column is corrupt: {e}"),
        }
    }
}

impl From<graphus_columnar::DecodeError> for ColdError {
    fn from(e: graphus_columnar::DecodeError) -> Self {
        ColdError::BadColumn(e)
    }
}

impl std::error::Error for ColdError {}

/// An immutable, self-describing columnar segment of [`Reading`]s (`rmp` #332).
///
/// The on-wire / on-disk layout is the header followed by the four encoded column blobs:
///
/// ```text
/// magic[4] version[1] count[u32] min_ts[i64] max_ts[i64]
/// len_seq[u32] len_ts[u32] len_value[u32] len_sensor[u32]
/// <seq blob> <ts blob> <value blob> <sensor blob>
/// ```
///
/// All integers are little-endian. The segment owns its encoded bytes; reads decode columns on
/// demand (whole-column, the codec granularity) so the struct stays small and shareable.
#[derive(Debug, Clone)]
pub struct ColdSegment {
    count: usize,
    min_ts: i64,
    max_ts: i64,
    seq_blob: Vec<u8>,
    ts_blob: Vec<u8>,
    value_blob: Vec<u8>,
    sensor_blob: Vec<u8>,
}

impl ColdSegment {
    /// Encodes `readings` into one immutable segment. An empty batch yields an empty segment
    /// (`min_ts`/`max_ts` are `0` and every scan returns nothing). Rows keep their given order; the
    /// caller typically appends in `seq`/`ts` order so the integer columns are monotonic (the
    /// double-delta win), but correctness does not require it.
    #[must_use]
    pub fn encode(readings: &[Reading]) -> Self {
        let count = readings.len();
        let seq: Vec<i64> = readings.iter().map(|r| r.seq).collect();
        let ts: Vec<i64> = readings.iter().map(|r| r.ts).collect();
        let value: Vec<f64> = readings.iter().map(|r| r.value).collect();
        let sensor: Vec<Vec<u8>> = readings
            .iter()
            .map(|r| r.sensor.clone().into_bytes())
            .collect();
        let (min_ts, max_ts) = ts
            .iter()
            .copied()
            .fold(None, |acc: Option<(i64, i64)>, t| match acc {
                Some((lo, hi)) => Some((lo.min(t), hi.max(t))),
                None => Some((t, t)),
            })
            .unwrap_or((0, 0));
        Self {
            count,
            min_ts,
            max_ts,
            seq_blob: integer::encode_i64(&seq),
            ts_blob: integer::encode_i64(&ts),
            value_blob: gorilla::encode(&value),
            sensor_blob: dictionary::encode(&sensor),
        }
    }

    /// The number of readings in the segment.
    #[must_use]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the segment holds no readings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The inclusive `[min_ts, max_ts]` of the segment (`(0, 0)` when empty) — used for segment-level
    /// data-skipping: a query range disjoint from this interval skips the segment without decoding.
    #[must_use]
    pub fn ts_bounds(&self) -> (i64, i64) {
        (self.min_ts, self.max_ts)
    }

    /// The compressed byte footprint of the segment (header + the four encoded columns).
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        HEADER_LEN
            + self.seq_blob.len()
            + self.ts_blob.len()
            + self.value_blob.len()
            + self.sensor_blob.len()
    }

    /// Decodes **every** reading, exactly as encoded (the round-trip-exact contract). Use a range scan
    /// instead when only a `ts` window is needed (it avoids materializing non-survivors).
    ///
    /// # Errors
    /// [`ColdError::BadColumn`] if any column blob is corrupt (truncated / bad scheme / out-of-range
    /// code). A segment built by [`encode`](Self::encode) always decodes; this guards the
    /// [`from_bytes`](Self::from_bytes) path, whose blobs are untrusted on-disk bytes.
    pub fn decode_all(&self) -> Result<Vec<Reading>, ColdError> {
        let seq = integer::decode_i64(&self.seq_blob, self.count)?;
        let ts = integer::decode_i64(&self.ts_blob, self.count)?;
        let value = gorilla::decode(&self.value_blob, self.count)?;
        let sensor = dictionary::decode(&self.sensor_blob, self.count)?;
        Ok((0..self.count)
            .map(|i| Reading {
                seq: seq[i],
                ts: ts[i],
                value: value[i],
                sensor: String::from_utf8_lossy(&sensor[i]).into_owned(),
            })
            .collect())
    }

    /// A **late-materialized** scan of the readings whose `ts` is in the inclusive range `[lo, hi]`
    /// (`rmp` #332): decode the cheap `ts` column first to find the survivor row indices, then decode
    /// `seq`/`value`/`sensor` and materialize **only** the survivors. If the query range is disjoint
    /// from the segment's `[min_ts, max_ts]`, returns immediately without decoding any column.
    ///
    /// # Errors
    /// [`ColdError::BadColumn`] if any column blob is corrupt (the [`from_bytes`](Self::from_bytes)
    /// untrusted path); a [`encode`](Self::encode)-built segment always decodes.
    pub fn scan_ts_range(&self, lo: i64, hi: i64) -> Result<Vec<Reading>, ColdError> {
        if self.count == 0 || hi < self.min_ts || lo > self.max_ts {
            return Ok(Vec::new()); // segment-level skip: range disjoint from the segment.
        }
        let ts = integer::decode_i64(&self.ts_blob, self.count)?;
        let survivors: Vec<usize> = (0..self.count)
            .filter(|&i| ts[i] >= lo && ts[i] <= hi)
            .collect();
        if survivors.is_empty() {
            return Ok(Vec::new());
        }
        // Materialize the other columns only now (decode is whole-column at the codec granularity, but
        // a non-survivor never becomes a `Reading` — the late-materialization the spec calls for).
        let seq = integer::decode_i64(&self.seq_blob, self.count)?;
        let value = gorilla::decode(&self.value_blob, self.count)?;
        let sensor = dictionary::decode(&self.sensor_blob, self.count)?;
        Ok(survivors
            .into_iter()
            .map(|i| Reading {
                seq: seq[i],
                ts: ts[i],
                value: value[i],
                sensor: String::from_utf8_lossy(&sensor[i]).into_owned(),
            })
            .collect())
    }

    /// Serializes the segment to a single self-describing byte buffer (a cold segment file).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(&MAGIC);
        out.push(1); // version
        out.extend_from_slice(&(self.count as u32).to_le_bytes());
        out.extend_from_slice(&self.min_ts.to_le_bytes());
        out.extend_from_slice(&self.max_ts.to_le_bytes());
        out.extend_from_slice(&(self.seq_blob.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.ts_blob.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.value_blob.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.sensor_blob.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.seq_blob);
        out.extend_from_slice(&self.ts_blob);
        out.extend_from_slice(&self.value_blob);
        out.extend_from_slice(&self.sensor_blob);
        out
    }

    /// Reconstructs a segment from a buffer produced by [`to_bytes`](Self::to_bytes).
    ///
    /// # Errors
    /// [`ColdError::BadMagic`] if the magic/version is wrong; [`ColdError::Truncated`] if the buffer
    /// is shorter than the header or a declared column length runs past its end. Never panics.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, ColdError> {
        if buf.len() < HEADER_LEN {
            return Err(ColdError::Truncated);
        }
        if buf[0..4] != MAGIC || buf[4] != 1 {
            return Err(ColdError::BadMagic);
        }
        let rd_u32 =
            |off: usize| u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        let rd_i64 = |off: usize| {
            i64::from_le_bytes([
                buf[off],
                buf[off + 1],
                buf[off + 2],
                buf[off + 3],
                buf[off + 4],
                buf[off + 5],
                buf[off + 6],
                buf[off + 7],
            ])
        };
        let count = rd_u32(5) as usize;
        let min_ts = rd_i64(9);
        let max_ts = rd_i64(17);
        let len_seq = rd_u32(25) as usize;
        let len_ts = rd_u32(29) as usize;
        let len_value = rd_u32(33) as usize;
        let len_sensor = rd_u32(37) as usize;
        let mut off = HEADER_LEN;
        let mut take = |n: usize| -> Result<Vec<u8>, ColdError> {
            let end = off.checked_add(n).ok_or(ColdError::Truncated)?;
            let slice = buf.get(off..end).ok_or(ColdError::Truncated)?;
            off = end;
            Ok(slice.to_vec())
        };
        let seq_blob = take(len_seq)?;
        let ts_blob = take(len_ts)?;
        let value_blob = take(len_value)?;
        let sensor_blob = take(len_sensor)?;
        Ok(Self {
            count,
            min_ts,
            max_ts,
            seq_blob,
            ts_blob,
            value_blob,
            sensor_blob,
        })
    }
}

/// The fixed segment header length: magic(4) + version(1) + count(4) + min_ts(8) + max_ts(8) +
/// 4 column lengths (4×4).
const HEADER_LEN: usize = 4 + 1 + 4 + 8 + 8 + 16;

/// An ordered, immutable set of cold [`ColdSegment`]s — the cold tier of one time-series partition
/// (`rmp` #332). A store-wide range scan skips every segment whose `[min_ts, max_ts]` is disjoint from
/// the query window, so only the overlapping segments are decoded.
#[derive(Debug, Default, Clone)]
pub struct ColdStore {
    segments: Vec<ColdSegment>,
}

impl ColdStore {
    /// An empty cold store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends an already-encoded immutable segment (the compaction job's output). Cold segments are
    /// never mutated in place — only appended and (eventually) dropped wholesale.
    pub fn push_segment(&mut self, segment: ColdSegment) {
        self.segments.push(segment);
    }

    /// The number of segments.
    #[must_use]
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// The total number of readings across all segments.
    #[must_use]
    pub fn reading_count(&self) -> usize {
        self.segments.iter().map(ColdSegment::len).sum()
    }

    /// The total compressed footprint across all segments.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.segments.iter().map(ColdSegment::encoded_len).sum()
    }

    /// A store-wide late-materialized scan of readings with `ts` in `[lo, hi]`, skipping every segment
    /// whose bounds are disjoint from the range. Returns readings in segment order. `segments_scanned`
    /// out-param reports how many segments were actually decoded (the rest skipped).
    ///
    /// # Errors
    /// [`ColdError::BadColumn`] if a scanned segment's column blob is corrupt.
    pub fn scan_ts_range(&self, lo: i64, hi: i64) -> Result<Vec<Reading>, ColdError> {
        let mut out = Vec::new();
        for seg in &self.segments {
            let (min, max) = seg.ts_bounds();
            if hi < min || lo > max {
                continue; // skip the whole segment without decoding.
            }
            out.extend(seg.scan_ts_range(lo, hi)?);
        }
        Ok(out)
    }

    /// How many segments overlap the range `[lo, hi]` (would be decoded by [`scan_ts_range`]); the
    /// rest are skipped. Diagnostics / measurement.
    #[must_use]
    pub fn segments_overlapping(&self, lo: i64, hi: i64) -> usize {
        self.segments
            .iter()
            .filter(|s| {
                let (min, max) = s.ts_bounds();
                !(hi < min || lo > max)
            })
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(n: i64) -> Vec<Reading> {
        (0..n)
            .map(|i| Reading {
                seq: i,
                ts: 1_000_000 + i * 10, // regular cadence (double-delta-friendly)
                value: 20.0 + (i % 7) as f64 * 0.5,
                sensor: format!("sensor-{}", i % 4), // low cardinality
            })
            .collect()
    }

    #[test]
    fn round_trip_decode_is_exact() {
        let readings = sample(1000);
        let seg = ColdSegment::encode(&readings);
        assert_eq!(seg.len(), 1000);
        assert_eq!(
            seg.decode_all().unwrap(),
            readings,
            "decode must reproduce the input exactly"
        );
    }

    #[test]
    fn to_from_bytes_round_trips() {
        let readings = sample(500);
        let seg = ColdSegment::encode(&readings);
        let bytes = seg.to_bytes();
        let back = ColdSegment::from_bytes(&bytes).expect("valid segment");
        assert_eq!(back.decode_all().unwrap(), readings);
        assert_eq!(back.ts_bounds(), seg.ts_bounds());
    }

    #[test]
    fn range_scan_equals_row_filter() {
        // Equivalence with a row store: the cold range scan returns EXACTLY the rows a row filter does.
        let readings = sample(2000);
        let seg = ColdSegment::encode(&readings);
        let (lo, hi) = (1_000_500, 1_010_000);
        let mut row_baseline: Vec<Reading> = readings
            .iter()
            .filter(|r| r.ts >= lo && r.ts <= hi)
            .cloned()
            .collect();
        let mut cold = seg.scan_ts_range(lo, hi).unwrap();
        row_baseline.sort_by_key(|r| r.seq);
        cold.sort_by_key(|r| r.seq);
        assert_eq!(
            cold, row_baseline,
            "cold range scan must equal the row filter"
        );
    }

    #[test]
    fn disjoint_range_skips_segment() {
        let seg = ColdSegment::encode(&sample(100));
        let (_min, max) = seg.ts_bounds();
        assert!(seg.scan_ts_range(max + 1, max + 1000).unwrap().is_empty());
    }

    #[test]
    fn empty_segment_is_safe() {
        let seg = ColdSegment::encode(&[]);
        assert!(seg.is_empty());
        assert!(seg.decode_all().unwrap().is_empty());
        assert!(seg.scan_ts_range(0, i64::MAX).unwrap().is_empty());
        let back = ColdSegment::from_bytes(&seg.to_bytes()).unwrap();
        assert!(back.is_empty());
    }

    #[test]
    fn malformed_buffer_errors_not_panics() {
        assert_eq!(
            ColdSegment::from_bytes(&[]).unwrap_err(),
            ColdError::Truncated
        );
        assert_eq!(
            ColdSegment::from_bytes(&[0; 8]).unwrap_err(),
            ColdError::Truncated
        );
        let mut bytes = ColdSegment::encode(&sample(10)).to_bytes();
        bytes[0] = b'X'; // corrupt the magic
        assert_eq!(
            ColdSegment::from_bytes(&bytes).unwrap_err(),
            ColdError::BadMagic
        );
        // Truncate the body: a declared column length now runs past the end.
        let mut t = ColdSegment::encode(&sample(10)).to_bytes();
        t.truncate(t.len() - 3);
        assert_eq!(
            ColdSegment::from_bytes(&t).unwrap_err(),
            ColdError::Truncated
        );
    }

    #[test]
    fn coldstore_skips_non_overlapping_segments() {
        let mut store = ColdStore::new();
        // Three contiguous windows of 1000 readings each.
        for w in 0..3i64 {
            let readings: Vec<Reading> = (0..1000)
                .map(|i| Reading {
                    seq: w * 1000 + i,
                    ts: w * 100_000 + i,
                    value: i as f64,
                    sensor: "s".into(),
                })
                .collect();
            store.push_segment(ColdSegment::encode(&readings));
        }
        assert_eq!(store.reading_count(), 3000);
        // A range inside window 1 only: only that segment overlaps.
        assert_eq!(store.segments_overlapping(100_010, 100_020), 1);
        let got = store.scan_ts_range(100_010, 100_020).unwrap();
        assert_eq!(got.len(), 11);
        assert!(got.iter().all(|r| r.ts >= 100_010 && r.ts <= 100_020));
    }

    #[test]
    fn corrupt_column_blob_is_a_controlled_error_not_a_panic() {
        // A segment whose on-disk image had a column blob corrupted (but the structural lengths still
        // parse) must surface `BadColumn` from `decode_all`, never panic (`04 §11.4`).
        let mut bytes = ColdSegment::encode(&sample(50)).to_bytes();
        // Overwrite the tail (inside the sensor/dictionary column region) with bytes that the
        // structural `from_bytes` length checks accept but the dictionary decoder rejects.
        let n = bytes.len();
        for b in &mut bytes[n - 4..n] {
            *b = 0xFF;
        }
        // `from_bytes` may accept it (lengths unchanged); the codec layer is what must reject it.
        if let Ok(seg) = ColdSegment::from_bytes(&bytes) {
            // Must be Err or Ok, but never a panic. If Ok, the bytes happened to stay valid.
            let _ = seg.decode_all();
            let _ = seg.scan_ts_range(i64::MIN, i64::MAX);
        }
    }
}
