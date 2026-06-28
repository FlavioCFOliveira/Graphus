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

/// The 4-byte segment magic (`"GCS2"`) and version, so a truncated/foreign buffer is rejected rather
/// than mis-decoded.
///
/// Bumped `GCS1` → `GCS2` for the format v2 change (`rmp` #420): a trailing CRC32C integrity field
/// now covers the whole segment, so any v1 buffer (no trailer) is rejected by the magic rather than
/// silently mis-validated. The crate is still staged/unwired (no v1 segment was ever persisted), so
/// no migration path is required.
const MAGIC: [u8; 4] = *b"GCS2";

/// The format version carried in the header (v2: whole-segment trailing CRC32C, `rmp` #420).
const VERSION: u8 = 2;

/// The trailing integrity field length: a little-endian CRC32C (Castagnoli) over the whole segment
/// body (everything before the trailer). The same `crc32c` crate the `.gcol` (`rmp` #405),
/// `graphus-bufpool` page, and `graphus-wal` frame checksums use, so the integrity discipline is
/// uniform across the storage layer.
const CRC_LEN: usize = 4;

/// A decode error: a buffer that is not a valid, complete cold segment. Decoding never panics on a
/// malformed buffer — it returns this (the codecs are fuzzed for exactly this property).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColdError {
    /// The buffer is shorter than the fixed header (incl. the trailing CRC32C), or a declared column
    /// length runs past its end.
    Truncated,
    /// The magic / version bytes do not match — not a cold segment of this format.
    BadMagic,
    /// The trailing CRC32C does not match a fresh checksum of the body — the segment is corrupt
    /// (bit-rot / torn write / tamper), or the declared `count` cannot fit the segment bytes. The
    /// integrity field is verified **before** any length/bound/`count` field is trusted, so a bit
    /// flip — including one inside the `min_ts`/`max_ts` skip bounds — is a controlled error, never
    /// silently-wrong data (`04 §11.4`).
    Corrupt,
    /// A column blob itself is corrupt: a codec payload was truncated, named an unknown sub-scheme,
    /// or carried an out-of-range dictionary code. Surfaced from [`graphus_columnar`] so a corrupt
    /// segment is a controlled error here too (`04 §11.4`), never a panic.
    BadColumn(graphus_columnar::DecodeError),
    /// The segment's `count` or one of its column-blob lengths exceeds the **`u32`** field the
    /// on-disk header frames it in (`rmp` #441). The header fields are little-endian `u32`s; an
    /// unchecked `as u32` cast of a `usize` above [`u32::MAX`] would *wrap* (mod 2³²) and the trailing
    /// CRC32C would then be computed over — and match — the **wrapped** header, so a >4 GiB segment
    /// would round-trip to a *different*, structurally-valid-looking segment: silently-wrong data that
    /// passes every integrity check. [`encode`](ColdSegment::encode) and
    /// [`to_bytes`](ColdSegment::to_bytes) return this instead of casting, so a segment too large to
    /// represent is a controlled error, never a silent truncation.
    TooLarge,
}

impl std::fmt::Display for ColdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ColdError::Truncated => write!(f, "cold segment buffer is truncated"),
            ColdError::BadMagic => write!(f, "cold segment magic/version mismatch"),
            ColdError::Corrupt => {
                write!(
                    f,
                    "cold segment integrity check failed (CRC32C mismatch or bad count)"
                )
            }
            ColdError::BadColumn(e) => write!(f, "cold segment column is corrupt: {e}"),
            ColdError::TooLarge => write!(
                f,
                "cold segment count or column length exceeds the u32 header field (segment too large to represent)"
            ),
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
/// crc32c[u32]   // format v2 (rmp #420): CRC32C over every preceding byte
/// ```
///
/// All integers are little-endian. The trailing CRC32C (format v2) covers the entire segment — header
/// **and** every column blob — so a single bit flip anywhere (including inside the `min_ts`/`max_ts`
/// skip bounds or the `count`) is detected on decode and surfaced as [`ColdError::Corrupt`], never
/// served as silently-wrong data. The segment owns its encoded bytes; reads decode columns on demand
/// (whole-column, the codec granularity) so the struct stays small and shareable.
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
    ///
    /// # Errors
    /// [`ColdError::TooLarge`] if the batch has more than [`u32::MAX`] readings or any encoded column
    /// blob exceeds [`u32::MAX`] bytes — the limits of the segment header's `u32` count/length fields.
    /// Rejecting here (rather than truncating the count via an `as u32` cast in
    /// [`to_bytes`](Self::to_bytes)) is what prevents a >4 GiB segment from silently round-tripping to
    /// a *different*, CRC-valid segment (`rmp` #441). The cold tier's compaction batches are far below
    /// this bound, so this never fires in practice — it is a structural safety net.
    pub fn encode(readings: &[Reading]) -> Result<Self, ColdError> {
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
        let seg = Self {
            count,
            min_ts,
            max_ts,
            seq_blob: integer::encode_i64(&seq),
            ts_blob: integer::encode_i64(&ts),
            value_blob: gorilla::encode(&value),
            sensor_blob: dictionary::encode(&sensor),
        };
        // Verify every field fits the `u32` header *before* the segment is handed out, so a too-large
        // segment can never be constructed (and therefore never silently truncated by `to_bytes`).
        seg.check_u32_framing()?;
        Ok(seg)
    }

    /// Asserts that `count` and every column-blob length fit the segment header's `u32` fields, so a
    /// later little-endian `u32` serialization (in [`to_bytes`](Self::to_bytes)) is exact rather than
    /// a silent mod-2³² wrap. Returns [`ColdError::TooLarge`] otherwise (`rmp` #441).
    fn check_u32_framing(&self) -> Result<(), ColdError> {
        let fits = |n: usize| u32::try_from(n).is_ok();
        if fits(self.count)
            && fits(self.seq_blob.len())
            && fits(self.ts_blob.len())
            && fits(self.value_blob.len())
            && fits(self.sensor_blob.len())
        {
            Ok(())
        } else {
            Err(ColdError::TooLarge)
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

    /// The compressed byte footprint of the segment (header + the four encoded columns + the trailing
    /// CRC32C integrity field).
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        HEADER_LEN
            + self.seq_blob.len()
            + self.ts_blob.len()
            + self.value_blob.len()
            + self.sensor_blob.len()
            + CRC_LEN
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
    ///
    /// # Errors
    /// [`ColdError::TooLarge`] if `count` or any column-blob length exceeds [`u32::MAX`] (the header's
    /// `u32` fields). Without this guard an `as u32` cast would silently *wrap* a >4 GiB value mod 2³²
    /// and the trailing CRC32C — computed over the wrapped header — would still match, so the buffer
    /// would decode to a structurally-valid-but-WRONG segment (`rmp` #441). A segment built by
    /// [`encode`](Self::encode) or read by [`from_bytes`](Self::from_bytes) already satisfies the
    /// bound, so for those this is infallible in practice; the check makes the truncation impossible
    /// by construction.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ColdError> {
        // Validate the `u32` framing FIRST, so the casts below are guaranteed exact (no mod-2³² wrap).
        self.check_u32_framing()?;
        // Each `try_from` is now infallible (just proven), but use it rather than `as` so a future
        // refactor that drops the check above still cannot silently truncate. `expect` is unreachable.
        let to_u32 = |n: usize| -> u32 { u32::try_from(n).expect("u32 framing checked above") };
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&to_u32(self.count).to_le_bytes());
        out.extend_from_slice(&self.min_ts.to_le_bytes());
        out.extend_from_slice(&self.max_ts.to_le_bytes());
        out.extend_from_slice(&to_u32(self.seq_blob.len()).to_le_bytes());
        out.extend_from_slice(&to_u32(self.ts_blob.len()).to_le_bytes());
        out.extend_from_slice(&to_u32(self.value_blob.len()).to_le_bytes());
        out.extend_from_slice(&to_u32(self.sensor_blob.len()).to_le_bytes());
        out.extend_from_slice(&self.seq_blob);
        out.extend_from_slice(&self.ts_blob);
        out.extend_from_slice(&self.value_blob);
        out.extend_from_slice(&self.sensor_blob);
        // Trailing CRC32C over every preceding byte (format v2, `rmp` #420): the last thing written,
        // the first thing verified on decode.
        let crc = crc32c::crc32c(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        Ok(out)
    }

    /// Reconstructs a segment from a buffer produced by [`to_bytes`](Self::to_bytes).
    ///
    /// # Errors
    /// [`ColdError::Corrupt`] if the trailing CRC32C does not match (verified **first**, before any
    /// header field is trusted) or the declared `count` cannot fit the segment bytes;
    /// [`ColdError::BadMagic`] if the magic/version is wrong; [`ColdError::Truncated`] if the buffer
    /// is shorter than the header (incl. the CRC trailer) or a declared column length runs past its
    /// end. Never panics, and never returns a structurally-valid-but-corrupt segment.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, ColdError> {
        // Step 1 — integrity FIRST. Verify the trailing CRC32C over the body before trusting any
        // length/bound/`count` field, so a bit flip anywhere (header, skip bounds, or payload) is a
        // controlled `Corrupt` error and never a silently-wrong decode (`04 §11.4`, `rmp` #420).
        if buf.len() < HEADER_LEN + CRC_LEN {
            return Err(ColdError::Truncated);
        }
        let (body, trailer) = buf.split_at(buf.len() - CRC_LEN);
        let stored = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
        if crc32c::crc32c(body) != stored {
            return Err(ColdError::Corrupt);
        }
        // Step 2 — only now is `body` trusted-intact: parse it. `buf` is rebound to the verified body
        // so no field read below can reach into (or past) the CRC trailer.
        let buf = body;
        if buf[0..4] != MAGIC || buf[4] != VERSION {
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
        // Step 3 — validate `count` against the payload before handing it to the column decoders.
        // `count` is load-bearing: each decoder is asked to materialize exactly `count` elements, and
        // a FOR-width-0 / single-value-dictionary column decodes `count` elements from a payload that
        // does NOT grow with `count` (graphus-columnar bitpack: a width-0 stream is empty). Two layers
        // bound the resulting allocation, so a forged `count` is neither an OOM-abort nor silently
        // wrong:
        //   1. The columnar layer caps every width-0 `unpack` at `u32::MAX` elements and errors above
        //      it (`rmp` #438), so no single column decode can be driven unbounded by an absurd count.
        //   2. This structural cap: a segment can never describe more rows than its body has bytes, so
        //      `count > buf.len()` is impossible for a genuine segment. It bounds the peak decode
        //      footprint to O(body bytes) — `count <= buf.len() <= u32::MAX`, and each materialized
        //      column is `count` elements — keeping a forged-but-CRC-valid `count` proportional to the
        //      on-disk size rather than a multi-gigabyte amplification.
        // (The CRC already proved the bytes intact; this guards a count that is intact-but-absurd,
        // e.g. a forged or mis-built segment. `count` itself was read from a `u32` field, so it is
        // already `<= u32::MAX`.)
        if count > buf.len() {
            return Err(ColdError::Corrupt);
        }
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
        let seg = ColdSegment::encode(&readings).expect("encode");
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
        let seg = ColdSegment::encode(&readings).expect("encode");
        let bytes = seg.to_bytes().expect("to_bytes");
        let back = ColdSegment::from_bytes(&bytes).expect("valid segment");
        assert_eq!(back.decode_all().unwrap(), readings);
        assert_eq!(back.ts_bounds(), seg.ts_bounds());
    }

    #[test]
    fn range_scan_equals_row_filter() {
        // Equivalence with a row store: the cold range scan returns EXACTLY the rows a row filter does.
        let readings = sample(2000);
        let seg = ColdSegment::encode(&readings).expect("encode");
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
        let seg = ColdSegment::encode(&sample(100)).expect("encode");
        let (_min, max) = seg.ts_bounds();
        assert!(seg.scan_ts_range(max + 1, max + 1000).unwrap().is_empty());
    }

    #[test]
    fn empty_segment_is_safe() {
        let seg = ColdSegment::encode(&[]).expect("encode");
        assert!(seg.is_empty());
        assert!(seg.decode_all().unwrap().is_empty());
        assert!(seg.scan_ts_range(0, i64::MAX).unwrap().is_empty());
        let back = ColdSegment::from_bytes(&seg.to_bytes().expect("to_bytes")).unwrap();
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
        // A buffer too short to even hold the header + CRC trailer is `Truncated`.
        assert_eq!(
            ColdSegment::from_bytes(&[0; HEADER_LEN]).unwrap_err(),
            ColdError::Truncated
        );
        // Corrupting the magic also breaks the CRC, which is checked FIRST → `Corrupt` (a foreign
        // buffer that happens to carry a matching CRC would still be caught by the magic check).
        let mut bytes = ColdSegment::encode(&sample(10))
            .expect("encode")
            .to_bytes()
            .expect("to_bytes");
        bytes[0] = b'X';
        assert_eq!(
            ColdSegment::from_bytes(&bytes).unwrap_err(),
            ColdError::Corrupt
        );
        // A foreign-but-self-consistent buffer (valid CRC, wrong magic) is rejected as `BadMagic`.
        let mut foreign = ColdSegment::encode(&sample(10))
            .expect("encode")
            .to_bytes()
            .expect("to_bytes");
        let body_len = foreign.len() - CRC_LEN;
        foreign[0] = b'X';
        let crc = crc32c::crc32c(&foreign[..body_len]);
        foreign[body_len..].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            ColdSegment::from_bytes(&foreign).unwrap_err(),
            ColdError::BadMagic
        );
    }

    #[test]
    fn coldstore_single_byte_flip_is_detected() {
        // Flip every single byte of a well-formed segment, one at a time, and assert decode never
        // serves silently-wrong data and never panics. The CRC32C trailer must catch every flip —
        // including ones inside the `min_ts`/`max_ts` skip bounds (header offsets 9..25), the `count`
        // (offsets 5..9) and the column payloads. (`rmp` #420)
        let readings = sample(200);
        let original = ColdSegment::encode(&readings)
            .expect("encode")
            .to_bytes()
            .expect("to_bytes");
        for i in 0..original.len() {
            for flip in [0x01u8, 0x80u8, 0xFFu8] {
                let mut corrupted = original.clone();
                corrupted[i] ^= flip;
                if corrupted == original {
                    continue; // 0x00 ^ x can't happen here, but be defensive.
                }
                match ColdSegment::from_bytes(&corrupted) {
                    // The overwhelmingly common outcome: integrity caught the flip. `TooLarge` is an
                    // encode/serialize-side error and never arises on the `from_bytes` read path
                    // (its `count`/lengths come from `u32` fields), but the match must be exhaustive.
                    Err(
                        ColdError::Corrupt
                        | ColdError::BadMagic
                        | ColdError::Truncated
                        | ColdError::TooLarge,
                    ) => {}
                    Err(ColdError::BadColumn(_)) => {}
                    Ok(seg) => {
                        // from_bytes accepted it ONLY if the flip produced a byte-identical buffer,
                        // which CRC makes impossible — so any Ok must round-trip to the SAME data.
                        // (Never silently-wrong.) Decoding must also never panic.
                        let decoded = seg.decode_all();
                        assert!(
                            decoded.is_err() || decoded.unwrap() == readings,
                            "byte {i} flip {flip:#04x}: segment decoded to DIFFERENT data — \
                             silently-wrong read escaped the integrity check"
                        );
                        let _ = seg.scan_ts_range(i64::MIN, i64::MAX);
                    }
                }
            }
        }
    }

    #[test]
    fn coldstore_truncation_is_detected() {
        // Truncating the blob at any offset must be a controlled Err (the CRC trailer is lost or no
        // longer matches the shortened body), never a panic and never a wrong decode. (`rmp` #420)
        let original = ColdSegment::encode(&sample(300))
            .expect("encode")
            .to_bytes()
            .expect("to_bytes");
        for cut in [
            0,
            1,
            HEADER_LEN - 1,
            HEADER_LEN,
            HEADER_LEN + 1,
            original.len() / 2,
            original.len() - CRC_LEN - 1,
            original.len() - CRC_LEN,
            original.len() - 1,
        ] {
            if cut >= original.len() {
                continue;
            }
            let truncated = &original[..cut];
            let err = ColdSegment::from_bytes(truncated)
                .expect_err("a truncated cold segment must be rejected");
            assert!(
                matches!(err, ColdError::Truncated | ColdError::Corrupt),
                "truncation at {cut} gave {err:?}, expected Truncated or Corrupt"
            );
        }
    }

    #[test]
    fn coldstore_header_count_overflow_is_detected() {
        // Forge a `count` far larger than the segment can possibly hold, then re-stamp a VALID CRC
        // over the forged body (so the CRC passes and the `count` guard is what must reject it). The
        // `count > buf.len()` guard caps the decode footprint to the segment's actual size; the
        // columnar layer additionally caps any width-0 column decode at `u32::MAX` (`rmp` #438), so
        // an intact-but-absurd count is neither an OOM-abort nor silently-wrong. (`rmp` #420 / #441)
        let mut bytes = ColdSegment::encode(&sample(8))
            .expect("encode")
            .to_bytes()
            .expect("to_bytes");
        let body_len = bytes.len() - CRC_LEN;
        // Overwrite count (offset 5, u32 LE) with a value that cannot fit the bytes.
        bytes[5..9].copy_from_slice(&u32::MAX.to_le_bytes());
        let crc = crc32c::crc32c(&bytes[..body_len]);
        bytes[body_len..].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            ColdSegment::from_bytes(&bytes).unwrap_err(),
            ColdError::Corrupt,
            "an intact-but-absurd count (count > body bytes) must be rejected up front"
        );

        // A count equal to the body length is the boundary: still structurally impossible to fill
        // with this tiny segment, but the guard only rejects strictly-greater-than. Confirm the
        // realistic forge (count just past the body) is caught, and that a genuine segment passes.
        let good = ColdSegment::encode(&sample(8))
            .expect("encode")
            .to_bytes()
            .expect("to_bytes");
        assert!(ColdSegment::from_bytes(&good).is_ok());
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
            store.push_segment(ColdSegment::encode(&readings).expect("encode"));
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
        let mut bytes = ColdSegment::encode(&sample(50))
            .expect("encode")
            .to_bytes()
            .expect("to_bytes");
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

    /// A segment whose `count` (or any column length) exceeds the header's `u32` field must be
    /// rejected by `to_bytes` (and `encode`) with [`ColdError::TooLarge`], NOT serialized with an
    /// `as u32` cast that silently wraps mod 2³² (which the trailing CRC would then bless, producing a
    /// structurally-valid-but-WRONG segment) (`rmp` #441). `count == u32::MAX` readings cannot be
    /// materialized in memory, so the guard is exercised on a hand-built segment with an out-of-range
    /// `count` field — the exact value `to_bytes` would otherwise truncate. This is a `tests`-module
    /// (white-box) construction; the public `encode` path enforces the same invariant via
    /// `check_u32_framing` on every batch it builds.
    #[test]
    fn to_bytes_rejects_count_above_u32_max() {
        // A genuine tiny (empty-column) segment, then force `count` just past `u32::MAX`.
        let mut seg = ColdSegment::encode(&[]).expect("encode");
        seg.count = u32::MAX as usize + 1;
        assert_eq!(
            seg.to_bytes().unwrap_err(),
            ColdError::TooLarge,
            "a count above u32::MAX must be rejected, not truncated by an `as u32` cast"
        );
        // The exact boundary: `u32::MAX` is representable and must still serialize; one more must not.
        seg.count = u32::MAX as usize;
        assert!(
            seg.to_bytes().is_ok(),
            "count == u32::MAX is the largest representable count and must serialize"
        );
        // A column-blob length above u32::MAX is likewise rejected (the other `as u32` cast sites).
        // Build a >4 GiB blob lazily — `vec![0u8; 4 GiB+1]` is large but allocatable; gate it behind a
        // size the CI box can hold. We instead assert the framing check directly to avoid a 4 GiB
        // allocation: a blob length above u32::MAX makes `check_u32_framing` fail.
        let mut tiny = ColdSegment::encode(&sample(4)).expect("encode");
        tiny.count = u32::MAX as usize; // representable
        assert!(tiny.check_u32_framing().is_ok());
        tiny.count = u32::MAX as usize + 7;
        assert_eq!(tiny.check_u32_framing().unwrap_err(), ColdError::TooLarge);
    }

    /// The width-0 amplification bound (`rmp` #441): a forged-but-CRC-valid segment whose `count`
    /// equals its body length and whose integer columns are width-0 (a constant column ⇒ empty
    /// payload) must decode with a PEAK allocation proportional to the segment's on-disk size — never
    /// an unbounded multi-gigabyte amplification, and never a panic/OOM-abort. Two layers enforce
    /// this: the columnar layer caps every width-0 `unpack` at `u32::MAX` (`rmp` #438), and
    /// `from_bytes`' `count <= buf.len()` structural cap keeps `count` proportional to the bytes.
    ///
    /// The forged `count` is LARGER than the segment's real row count, so a column whose payload *does*
    /// grow with the row count (the Gorilla float / the dictionary codes) runs out of bytes and errors
    /// cleanly — the **correct** controlled outcome (a forged over-count is not a valid segment). The
    /// property under test is that the width-0 *integer* path (the amplification vector) allocates a
    /// bounded `vec![0i64; count]` (≤ `buf.len()` elements) and that the whole `decode_all` is a
    /// controlled `Result`, never an abort.
    #[test]
    fn width_zero_count_equal_body_len_is_bounded() {
        // A CONSTANT segment: every seq/ts identical ⇒ each integer column is FOR width-0 (empty
        // payload) — the densest "count ≫ payload" amplification shape.
        let constant: Vec<Reading> = (0..64)
            .map(|_| Reading {
                seq: 7,
                ts: 1_000,
                value: 3.5,
                sensor: "s".to_string(),
            })
            .collect();
        let mut bytes = ColdSegment::encode(&constant)
            .expect("encode")
            .to_bytes()
            .expect("to_bytes");
        let body_len = bytes.len() - CRC_LEN;
        // Forge count = body_len (the loosest value the `count > buf.len()` guard still ACCEPTS, since
        // it rejects only strictly-greater). `body_len <= buf.len()`, so this is admitted.
        let forged_count = u32::try_from(body_len).expect("tiny segment fits u32");
        bytes[5..9].copy_from_slice(&forged_count.to_le_bytes());
        let crc = crc32c::crc32c(&bytes[..body_len]);
        bytes[body_len..].copy_from_slice(&crc.to_le_bytes());

        // Accepted (count == body_len passes the `>` guard). The integer columns are width-0, so they
        // allocate `vec![0i64; body_len]` — BOUNDED by the body length, the whole point of the cap.
        let seg = ColdSegment::from_bytes(&bytes).expect("count == body_len is admitted");
        assert_eq!(seg.len(), body_len);

        // Decoding the whole segment is a CONTROLLED outcome (a forged over-count makes the
        // count-dependent Gorilla/dictionary payloads come up short → clean `Err`), never a panic or
        // OOM-abort. Either result is acceptable; what matters is no abort and a bounded allocation.
        match seg.decode_all() {
            Ok(rows) => {
                assert_eq!(rows.len(), body_len);
                assert!(rows.iter().all(|r| r.seq == 7 && r.ts == 1_000));
            }
            Err(ColdError::BadColumn(_)) => {} // expected: count-dependent column ran short, cleanly.
            Err(other) => panic!("unexpected decode error for a forged over-count: {other:?}"),
        }
        // The amplification vector in isolation: the width-0 `seq` column decodes to a BOUNDED
        // `vec![0i64; body_len]` (≤ the segment size), proving the `count <= buf.len()` cap holds the
        // peak allocation proportional to the on-disk bytes rather than to a forged absurd count.
        let seq = integer::decode_i64(&seg.seq_blob, seg.count)
            .expect("width-0 integer column decodes to bounded `count` zeros");
        assert_eq!(seq.len(), body_len);
        assert!(
            seq.iter().all(|&v| v == 7),
            "constant width-0 column is all `min`"
        );

        // A range scan over the forged segment is likewise a controlled outcome, never an abort.
        let _ = seg.scan_ts_range(i64::MIN, i64::MAX);
    }
}
