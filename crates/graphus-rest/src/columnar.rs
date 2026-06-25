//! The **analytical columnar result channel** for REST (rmp #334) — a compact, self-describing,
//! *column-wise* encoding of a query result, complementary to (and explicitly distinct from) the
//! row-wise JSON/CBOR/NDJSON paths and the inviolable Bolt/PackStream OLTP path.
//!
//! # Why a native columnar body instead of Arrow
//!
//! The buffered JSON/CBOR paths serialise a result **row-wise**: a `Vec<Json>` of per-row arrays,
//! one boxed `serde_json::Value` per cell ([`crate::router`]'s `run_one`). On a *large analytical*
//! result that is `O(rows × cols)` allocations and a wire body dominated by repeated keys/sigils.
//! An analytical client (dashboards, exports, bulk reads) wants the result **transposed into
//! columns** so each column compresses with a type-appropriate codec.
//!
//! The obvious off-the-shelf answer is Arrow IPC, but pulling `arrow`/`arrow-ipc` drags a very large
//! dependency tree into a graph-database server that already runs on a Raspberry Pi and that
//! deliberately **hand-rolls its codecs** (`graphus-storage::{propenc,valenc}`, the native `.gcol`
//! bulk format, `graphus-columnar`). So this channel reuses the already-built, proptest-validated
//! [`graphus_columnar`] codecs to encode each column natively. The media type is
//! [`GCOL_RESULT_MEDIA_TYPE`] (`application/x-graphus-columnar`); the body format is "**gcol-result**"
//! (see [the wire format](#the-gcol-result-wire-format)).
//!
//! This module owns **no** HTTP, auth, or transaction logic: the router authenticates, authorises,
//! opens the transaction, and pulls rows exactly as for every other result format, then hands the
//! collected rows here to be encoded. It is a leaf, like [`crate::value`].
//!
//! # When to use it (and where it loses)
//!
//! This is an **analytical / export** channel for *large* result sets. The columnar body carries a
//! fixed per-column framing overhead (a present/absent bitmap, a codec tag, a length prefix) plus a
//! small JSON header; on a *small* OLTP result that fixed cost makes it **larger** than JSON — so
//! small transactional results should keep using JSON/NDJSON. The crate documents and the tests
//! measure exactly this trade-off.
//!
//! # The gcol-result wire format
//!
//! All multi-byte integers are little-endian. The body is:
//!
//! ```text
//! magic        : 8 bytes  = b"GCOLRES1"
//! header_len   : u32      = byte length of the JSON header that follows
//! header       : header_len bytes of UTF-8 JSON (see GcolHeader)
//! columns      : for each field, in field order:
//!     present_len : u32       = byte length of the present/absent bitmap
//!     present     : present_len bytes — a bit-packed bool column (1 bit/row, MSB→LSB within a byte
//!                   per graphus_columnar::bitpack); bit i = 1 ⇔ row i's cell is present (non-null)
//!     payload_len : u32       = byte length of the codec payload
//!     payload     : payload_len bytes — the column's PRESENT (non-null) values, encoded with the
//!                   codec named in the header for this column
//! ```
//!
//! The JSON header (`GcolHeader`) is self-describing: the format version, the `fields` (column
//! names, in order), the `row_count`, the per-column codec tag, and the result `summary` (the same
//! `{ type, stats }` object the JSON path emits). A decoder reads the header, then walks each
//! column's bitmap pulling one decoded value per present bit and emitting `null` per absent bit.
//!
//! # Codec selection (lossless)
//!
//! Each column is classified by the value type of its **present** cells; `null` cells are recorded
//! in the bitmap and contribute nothing to the payload:
//!
//! | every present cell is | codec tag | encoder |
//! | --- | --- | --- |
//! | [`Value::Integer`] | `"i64"` | [`graphus_columnar::integer`] (FOR / delta / double-delta) |
//! | [`Value::Float`] | `"f64"` | [`graphus_columnar::gorilla`] (Gorilla XOR) |
//! | [`Value::Boolean`] | `"bool"` | [`graphus_columnar::encode_bool`] (1 bit/value) |
//! | [`Value::String`] | `"str"` | [`graphus_columnar::dictionary`] over the UTF-8 bytes |
//! | anything else / mixed / structural | `"json"` | strict-Jolt per cell, then [`dictionary`] over the JSON bytes |
//!
//! The `"json"` fallback is what makes the channel **lossless for every result**: a heterogeneous,
//! structural ([`RestValue::Node`]/`Relationship`/`Path`/`List`), `Bytes`, temporal, `Point`, or
//! `Map` column round-trips through the exact strict-Jolt codec the JSON path uses
//! ([`crate::restvalue::restvalue_to_jolt`] / [`crate::value::jolt_to_value`]), dictionary-compressed
//! so a low-cardinality structural column (e.g. a repeated label set) still shrinks. The typed
//! codecs are applied **only** when every present cell already has the matching scalar type, so a
//! typed codec never has to coerce or approximate a value.

use graphus_columnar::{dictionary, encode_bool, gorilla, integer};
use graphus_core::Value;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

use crate::engine::Row;
use crate::restvalue::{RestValue, restvalue_to_jolt};
use crate::value::{self, ValueCodecError};

/// The media type of the analytical columnar result body (rmp #334).
///
/// A client opts into the columnar channel with `Accept: application/x-graphus-columnar` (or by
/// posting to `POST /db/{db}/query/columnar`); the response carries this `Content-Type`.
pub const GCOL_RESULT_MEDIA_TYPE: &str = "application/x-graphus-columnar";

/// The 8-byte magic that prefixes every gcol-result body (`b"GCOLRES1"`).
const MAGIC: &[u8; 8] = b"GCOLRES1";

/// The gcol-result format version recorded in the header (bumped on any incompatible change).
const FORMAT_VERSION: u32 = 1;

/// Per-column codec tags, as they appear in the JSON header (`GcolColumn::codec`).
mod codec_tag {
    /// Integer column → [`graphus_columnar::integer`].
    pub const I64: &str = "i64";
    /// Float column → [`graphus_columnar::gorilla`].
    pub const F64: &str = "f64";
    /// Boolean column → [`graphus_columnar::encode_bool`].
    pub const BOOL: &str = "bool";
    /// String column → [`graphus_columnar::dictionary`] over UTF-8 bytes.
    pub const STR: &str = "str";
    /// Fallback column → strict-Jolt per cell, [`graphus_columnar::dictionary`] over the JSON bytes.
    pub const JSON: &str = "json";
}

/// An error encoding or (more importantly) **decoding** a gcol-result body.
///
/// Decoding is a trusted boundary, so a malformed body must surface as this controlled error rather
/// than a panic (`04 §11.4`, the fuzz-hardening rule for every decoder): every length read is
/// bounds-checked and every header field validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GcolError {
    /// The body did not start with the `GCOLRES1` magic prefix, or was shorter than the fixed prefix.
    BadMagic,
    /// The header declared a format version this build does not understand.
    UnsupportedVersion(u32),
    /// A length prefix pointed past the end of the body (truncated/corrupt input).
    Truncated {
        /// What was being read when the body ran out.
        what: &'static str,
    },
    /// The JSON header itself was not valid UTF-8 / JSON, or was missing a required field.
    BadHeader {
        /// A short, safe-to-log reason.
        detail: String,
    },
    /// A column named a codec tag this build does not implement.
    UnknownCodec {
        /// The offending tag.
        tag: String,
    },
    /// A cell value failed to decode through the strict-Jolt codec (the `"json"` fallback path).
    BadValue(ValueCodecError),
    /// A columnar codec payload (integer / float / dictionary / bitmap) was truncated, named an
    /// unknown sub-scheme, or carried an out-of-range dictionary code — a corrupt column blob.
    BadColumn(graphus_columnar::DecodeError),
}

impl std::fmt::Display for GcolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "not a gcol-result body (bad magic)"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported gcol-result version {v}"),
            Self::Truncated { what } => {
                write!(f, "truncated gcol-result body while reading {what}")
            }
            Self::BadHeader { detail } => write!(f, "malformed gcol-result header: {detail}"),
            Self::UnknownCodec { tag } => write!(f, "unknown gcol-result column codec `{tag}`"),
            Self::BadValue(e) => write!(f, "malformed gcol-result cell value: {e}"),
            Self::BadColumn(e) => write!(f, "malformed gcol-result column payload: {e}"),
        }
    }
}

impl std::error::Error for GcolError {}

impl From<ValueCodecError> for GcolError {
    fn from(e: ValueCodecError) -> Self {
        Self::BadValue(e)
    }
}

impl From<graphus_columnar::DecodeError> for GcolError {
    fn from(e: graphus_columnar::DecodeError) -> Self {
        Self::BadColumn(e)
    }
}

/// The self-describing JSON header of a gcol-result body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GcolHeader {
    /// The gcol-result format version (currently `1`).
    pub version: u32,
    /// The result column names, in order (the `fields` of the result envelope).
    pub fields: Vec<String>,
    /// The number of rows encoded (the length every column decodes back to).
    pub row_count: u64,
    /// The per-column codec descriptors, in `fields` order.
    pub columns: Vec<GcolColumn>,
    /// The result summary (`{ type, stats }`), the same object the JSON path emits via
    /// `encode_summary` — carried so the columnar channel surfaces side-effect counters too.
    pub summary: Json,
}

/// One column's descriptor in the [`GcolHeader`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GcolColumn {
    /// The column name (mirrors the matching entry in [`GcolHeader::fields`]).
    pub name: String,
    /// The codec tag (`"i64"`/`"f64"`/`"bool"`/`"str"`/`"json"`); see the module docs.
    pub codec: String,
    /// The count of **present** (non-null) cells — the number of values the payload decodes to.
    pub present_count: u64,
}

// =============================== encoding ======================================================

/// Encodes a whole result (`fields` + `rows` + `summary`) into a gcol-result body (rmp #334).
///
/// The rows are transposed into columns and each column is encoded with the type-appropriate
/// [`graphus_columnar`] codec plus a present/absent bitmap (see the module docs). `summary_json` is
/// the already-encoded `{ type, stats }` object (produced by the router's `encode_summary`, so the
/// columnar channel reuses the exact same summary rendering as the JSON path).
///
/// This buffers the rows to transpose them — a columnar layout is inherently per-column, so the
/// result must be materialised before it can be encoded. That is acceptable precisely because this
/// is the *analytical* channel; the OLTP paths keep their row-at-a-time streaming.
#[must_use]
pub fn encode_result(fields: &[String], rows: &[Row], summary_json: &Json) -> Vec<u8> {
    let row_count = rows.len();
    let col_count = fields.len();

    // Transpose: gather each column's cells (borrowed) once, so each column is encoded independently.
    // A row shorter than `fields` (should not happen — the engine yields full rows) is treated as
    // trailing nulls; a longer row's extra cells are ignored. This keeps the encoder total.
    let mut columns: Vec<Vec<&RestValue>> = vec![Vec::with_capacity(row_count); col_count];
    for row in rows {
        for (c, col) in columns.iter_mut().enumerate() {
            // `RestValue` has no cheap "null" sentinel to borrow, so a missing cell is recorded as
            // `None` below via the present bitmap; here we only push cells that exist.
            if let Some(cell) = row.get(c) {
                col.push(cell);
            } else {
                col.push(&RestValue::Value(Value::Null));
            }
        }
    }

    let mut header_columns = Vec::with_capacity(col_count);
    let mut column_blobs = Vec::with_capacity(col_count);
    for (c, cells) in columns.iter().enumerate() {
        let (codec, present_count, present_bitmap, payload) = encode_column(cells);
        header_columns.push(GcolColumn {
            name: fields.get(c).cloned().unwrap_or_default(),
            codec: codec.to_owned(),
            present_count: present_count as u64,
        });
        column_blobs.push((present_bitmap, payload));
    }

    let header = GcolHeader {
        version: FORMAT_VERSION,
        fields: fields.to_vec(),
        row_count: row_count as u64,
        columns: header_columns,
        summary: summary_json.clone(),
    };
    // The header is small (names + tags + counts) and we control it, so a serialisation failure is an
    // internal invariant; fall back to an empty object so the body stays well-formed rather than
    // panicking.
    let header_bytes = serde_json::to_vec(&header).unwrap_or_else(|_| b"{}".to_vec());

    // Assemble the body. Pre-size to avoid reallocation churn on a large result.
    let payload_total: usize = column_blobs
        .iter()
        .map(|(b, p)| b.len() + p.len() + 8)
        .sum();
    let mut out = Vec::with_capacity(MAGIC.len() + 4 + header_bytes.len() + payload_total);
    out.extend_from_slice(MAGIC);
    put_u32(&mut out, header_bytes.len() as u32);
    out.extend_from_slice(&header_bytes);
    for (present_bitmap, payload) in &column_blobs {
        put_u32(&mut out, present_bitmap.len() as u32);
        out.extend_from_slice(present_bitmap);
        put_u32(&mut out, payload.len() as u32);
        out.extend_from_slice(payload);
    }
    out
}

/// Classifies one column and encodes it, returning `(codec_tag, present_count, present_bitmap,
/// payload)`. A `null` cell is recorded as absent in the bitmap and contributes nothing to the
/// payload; the typed codecs run only over the present values.
fn encode_column(cells: &[&RestValue]) -> (&'static str, usize, Vec<u8>, Vec<u8>) {
    // The present/absent bitmap: bit i = 1 ⇔ cell i is a present (non-null) value.
    let present_bits: Vec<bool> = cells.iter().map(|c| !is_null(c)).collect();
    let present_bitmap = encode_bool(&present_bits);
    let present_count = present_bits.iter().filter(|&&b| b).count();

    // Decide the codec from the present cells' value types (a column of all-nulls is `"json"` with an
    // empty payload — trivially round-trips).
    let kind = classify(cells);
    let payload = match kind {
        ColumnKind::I64 => {
            let vals: Vec<i64> = present_scalars(cells, |v| match v {
                Value::Integer(i) => Some(*i),
                _ => None,
            });
            integer::encode_i64(&vals)
        }
        ColumnKind::F64 => {
            let vals: Vec<f64> = present_scalars(cells, |v| match v {
                Value::Float(f) => Some(*f),
                _ => None,
            });
            gorilla::encode(&vals)
        }
        ColumnKind::Bool => {
            let vals: Vec<bool> = present_scalars(cells, |v| match v {
                Value::Boolean(b) => Some(*b),
                _ => None,
            });
            encode_bool(&vals)
        }
        ColumnKind::Str => {
            let vals: Vec<Vec<u8>> = present_scalars(cells, |v| match v {
                Value::String(s) => Some(s.clone().into_bytes()),
                _ => None,
            });
            dictionary::encode(&vals)
        }
        ColumnKind::Json => {
            // The lossless fallback: each present cell → its strict-Jolt JSON → compact bytes, then a
            // dictionary over those bytes (so a low-cardinality structural/heterogeneous column still
            // compresses). High-cardinality columns simply store each rendering once.
            let vals: Vec<Vec<u8>> = cells
                .iter()
                .filter(|c| !is_null(c))
                .map(|c| {
                    serde_json::to_vec(&restvalue_to_jolt(c)).unwrap_or_else(|_| b"null".to_vec())
                })
                .collect();
            dictionary::encode(&vals)
        }
    };
    (kind.tag(), present_count, present_bitmap, payload)
}

/// The codec a column resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ColumnKind {
    I64,
    F64,
    Bool,
    Str,
    Json,
}

impl ColumnKind {
    fn tag(self) -> &'static str {
        match self {
            Self::I64 => codec_tag::I64,
            Self::F64 => codec_tag::F64,
            Self::Bool => codec_tag::BOOL,
            Self::Str => codec_tag::STR,
            Self::Json => codec_tag::JSON,
        }
    }
}

/// Picks the column codec from the value types of the **present** (non-null) cells.
///
/// A typed codec is chosen only when *every* present cell is a [`RestValue::Value`] of exactly that
/// scalar type, so the codec never has to coerce. Any structural cell, any mixed-type column, or any
/// non-scalar (`Bytes`/temporal/`Map`/`Point`/`List`) makes the whole column `"json"` (the lossless
/// fallback). An all-null or empty column is `"json"` too (an empty dictionary payload).
fn classify(cells: &[&RestValue]) -> ColumnKind {
    let mut kind: Option<ColumnKind> = None;
    for cell in cells {
        let RestValue::Value(v) = cell else {
            return ColumnKind::Json; // a structural cell → fallback for the whole column
        };
        let this = match v {
            Value::Null => continue, // nulls do not constrain the codec (recorded in the bitmap)
            Value::Integer(_) => ColumnKind::I64,
            Value::Float(_) => ColumnKind::F64,
            Value::Boolean(_) => ColumnKind::Bool,
            Value::String(_) => ColumnKind::Str,
            // Everything else (bytes, temporals, map, point, list) is not a typed-codec scalar.
            _ => return ColumnKind::Json,
        };
        match kind {
            None => kind = Some(this),
            Some(prev) if prev == this => {}
            Some(_) => return ColumnKind::Json, // mixed scalar types → fallback
        }
    }
    kind.unwrap_or(ColumnKind::Json)
}

/// Collects the present (non-null) cells' scalar payloads via `extract`, in row order.
fn present_scalars<T>(cells: &[&RestValue], extract: impl Fn(&Value) -> Option<T>) -> Vec<T> {
    cells
        .iter()
        .filter_map(|c| match c {
            RestValue::Value(v) => extract(v),
            _ => None,
        })
        .collect()
}

/// Whether a cell is a SQL-style `null` (a [`Value::Null`]); only these are "absent" in the bitmap.
fn is_null(cell: &RestValue) -> bool {
    matches!(cell, RestValue::Value(Value::Null))
}

// =============================== decoding ======================================================

/// A decoded gcol-result: the header (fields, codecs, summary) plus the reconstructed rows, as the
/// **same strict-Jolt JSON cells** the row-wise JSON path emits.
///
/// Each cell is a [`serde_json::Value`] in the exact strict-Jolt shape a JSON client receives in a
/// `StatementResult`'s `data` rows: a typed column's cells re-render through
/// [`crate::value::value_to_jolt`] (e.g. `{"Z":"42"}`), the `"json"` fallback yields the stored Jolt
/// object **verbatim** (so a structural node/relationship/path cell is byte-identical to the row-wise
/// rendering), and a `null` cell is JSON `null`. This makes [`decode_result`] the exact round-trip
/// companion to [`encode_result`]: the decoded rows equal the JSON path's `data` rows cell-for-cell,
/// for *every* result (scalar, structural, mixed). Tests rely on that total equality.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedResult {
    /// The decoded header.
    pub header: GcolHeader,
    /// The reconstructed rows, each a `Vec<Json>` of strict-Jolt cells in `fields` order.
    pub rows: Vec<Vec<Json>>,
}

/// Decodes a gcol-result body produced by [`encode_result`].
///
/// # Errors
///
/// [`GcolError`] for any malformed input: a bad/short magic, an unsupported version, a length prefix
/// past the end of the body, a malformed JSON header, an unknown column codec, a string column that
/// is not valid UTF-8, or a fallback cell that is not valid JSON. Never panics on adversarial input
/// (`04 §11.4`).
pub fn decode_result(bytes: &[u8]) -> Result<DecodedResult, GcolError> {
    // A body too short to even contain the magic is simply "not a gcol-result body" (BadMagic),
    // which is more accurate than a mid-parse "truncated" for an unrelated short input.
    if bytes.len() < MAGIC.len() || &bytes[..MAGIC.len()] != MAGIC {
        return Err(GcolError::BadMagic);
    }
    let mut r = Reader::new(bytes);
    let _ = r.take(MAGIC.len(), "magic")?; // advance past the verified magic
    let header_len = r.u32("header length")? as usize;
    let header_bytes = r.take(header_len, "header")?;
    let header: GcolHeader =
        serde_json::from_slice(header_bytes).map_err(|e| GcolError::BadHeader {
            detail: e.to_string(),
        })?;
    if header.version != FORMAT_VERSION {
        return Err(GcolError::UnsupportedVersion(header.version));
    }
    let row_count = header.row_count as usize;

    // Decode each column into a full `Vec<Json>` of strict-Jolt cells (nulls reinstated from the
    // bitmap as JSON `null`).
    let mut decoded_columns: Vec<Vec<Json>> = Vec::with_capacity(header.columns.len());
    for col in &header.columns {
        let present_len = r.u32("present bitmap length")? as usize;
        let present_bytes = r.take(present_len, "present bitmap")?;
        // Guard against a forged header whose `row_count` exceeds what the present bitmap can hold:
        // `decode_bool` would otherwise read past the bitmap and panic. A bitmap of `present_len`
        // bytes carries at most `present_len * 8` bits; a larger `row_count` is corrupt input
        // (`04 §11.4` — a malformed body is a controlled error, never a panic).
        if row_count > present_len.saturating_mul(8) {
            return Err(GcolError::BadHeader {
                detail: format!(
                    "row_count {row_count} exceeds the {present_len}-byte present bitmap capacity"
                ),
            });
        }
        let present = graphus_columnar::decode_bool(present_bytes, row_count)?;
        let present_count = present.iter().filter(|&&b| b).count();

        let payload_len = r.u32("payload length")? as usize;
        let payload = r.take(payload_len, "payload")?;

        let cells = decode_column(&col.codec, payload, present_count)?;
        decoded_columns.push(reinstate_nulls(&present, cells)?);
    }

    // Pivot the columns back into rows.
    let mut rows = Vec::with_capacity(row_count);
    for row_idx in 0..row_count {
        let mut row = Vec::with_capacity(decoded_columns.len());
        for col in &decoded_columns {
            // Each column has exactly `row_count` entries by construction.
            row.push(col[row_idx].clone());
        }
        rows.push(row);
    }

    Ok(DecodedResult { header, rows })
}

/// Decodes one column's payload (`present_count` present values) for `codec`, into the strict-Jolt
/// JSON cells the row-wise path emits. A typed column re-renders its scalar [`Value`]s through
/// [`crate::value::value_to_jolt`]; the `"json"` fallback returns each stored Jolt object verbatim
/// (so structural cells are byte-identical to the row-wise rendering).
fn decode_column(
    codec: &str,
    payload: &[u8],
    present_count: usize,
) -> Result<Vec<Json>, GcolError> {
    let cells = match codec {
        codec_tag::I64 => integer::decode_i64(payload, present_count)?
            .into_iter()
            .map(|i| value::value_to_jolt(&Value::Integer(i)))
            .collect(),
        codec_tag::F64 => gorilla::decode(payload, present_count)?
            .into_iter()
            .map(|f| value::value_to_jolt(&Value::Float(f)))
            .collect(),
        codec_tag::BOOL => graphus_columnar::decode_bool(payload, present_count)?
            .into_iter()
            .map(|b| value::value_to_jolt(&Value::Boolean(b)))
            .collect(),
        codec_tag::STR => {
            let raw = dictionary::decode(payload, present_count)?;
            let mut out = Vec::with_capacity(raw.len());
            for bytes in raw {
                let s = String::from_utf8(bytes).map_err(|e| {
                    GcolError::BadValue(ValueCodecError::Malformed {
                        detail: format!("string column held invalid UTF-8: {e}"),
                    })
                })?;
                out.push(value::value_to_jolt(&Value::String(s)));
            }
            out
        }
        codec_tag::JSON => {
            let raw = dictionary::decode(payload, present_count)?;
            let mut out = Vec::with_capacity(raw.len());
            for bytes in raw {
                // The stored bytes ARE the strict-Jolt cell rendering; return them verbatim so a
                // structural/heterogeneous cell round-trips byte-identically to the JSON path.
                let json: Json = serde_json::from_slice(&bytes).map_err(|e| {
                    GcolError::BadValue(ValueCodecError::Malformed {
                        detail: format!("json column held invalid JSON: {e}"),
                    })
                })?;
                out.push(json);
            }
            out
        }
        other => {
            return Err(GcolError::UnknownCodec {
                tag: other.to_owned(),
            });
        }
    };
    Ok(cells)
}

/// Re-expands a column's `present_count` decoded cells into a full `row_count`-length column,
/// inserting JSON `null` for every absent bit (in row order).
fn reinstate_nulls(present: &[bool], cells: Vec<Json>) -> Result<Vec<Json>, GcolError> {
    let mut out = Vec::with_capacity(present.len());
    let mut it = cells.into_iter();
    for &is_present in present {
        if is_present {
            // The codec produced exactly `present_count` cells, one per present bit; a short iterator
            // means the body's bitmap and payload disagree (corruption).
            let Some(v) = it.next() else {
                return Err(GcolError::Truncated {
                    what: "column values (bitmap/payload disagree)",
                });
            };
            out.push(v);
        } else {
            out.push(Json::Null);
        }
    }
    Ok(out)
}

// =============================== little-endian + bounds-checked reader =========================

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// A bounds-checked cursor over the gcol-result body. Every read returns a [`GcolError::Truncated`]
/// rather than panicking when the body is too short (the fuzz-hardening rule, `04 §11.4`).
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Returns the next `n` bytes, advancing the cursor, or [`GcolError::Truncated`] if fewer remain.
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], GcolError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(GcolError::Truncated { what })?;
        if end > self.bytes.len() {
            return Err(GcolError::Truncated { what });
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Reads a little-endian `u32`.
    fn u32(&mut self, what: &'static str) -> Result<u32, GcolError> {
        let b = self.take(4, what)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}

#[cfg(test)]
mod tests;
