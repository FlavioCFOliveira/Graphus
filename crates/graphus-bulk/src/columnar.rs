//! Lossless **columnar** (`.gcol`) transcoding for the offline bulk dump/import path (FR-BK; `rmp`
//! task #327).
//!
//! This module pivots the importer's row-oriented CSV (see [`dump`](crate::dump) /
//! [`import`](crate::import)) into a compact, self-describing **column-oriented** binary blob, using
//! the round-trip-exact codecs of the [`graphus_columnar`] crate (dictionary / frame-of-reference /
//! Gorilla XOR / bit-packed booleans). It is a pure byte→byte transform: it never touches the
//! authoritative [`RecordStore`](graphus_storage::RecordStore) write path or any ACID/MVCC code, so
//! it adds **zero** risk to durability. The CLI and tests wire it in by transcoding *through* the
//! existing CSV dumper/importer:
//!
//! ```text
//! dump:    store --dump_nodes--> CSV bytes --csv_to_gcol--> .gcol on disk
//! import:  .gcol on disk --gcol_to_csv--> CSV bytes --BulkImporter--> store
//! ```
//!
//! # Why pivot through CSV (rather than columnarise the store directly)
//!
//! The CSV the dumper emits is already the canonical, type-annotated, round-trippable serialisation
//! of the graph; [`dump`](crate::dump) even computes the typed column schema in its pass-1 scan. By
//! transcoding that CSV we reuse **all** of the proven dump/import logic (label sets, newest-wins
//! property collapse, array/`;` handling, formula-injection neutralisation, duplicate-`:ID` policy)
//! and keep the columnar path a *leaf* with no store coupling — the safest possible place to add a
//! new on-disk format.
//!
//! # The lossless contract
//!
//! For **any CSV the dumper produces**, [`gcol_to_csv`]`(`[`csv_to_gcol`]`(csv)) == csv`
//! byte-for-byte. Two mechanisms guarantee it:
//!
//! 1. **Faithful CSV re-serialisation.** `csv_to_gcol` parses the input with the `csv` crate into
//!    its logical fields (raw bytes, via [`csv::ByteRecord`]); `gcol_to_csv` re-serialises those
//!    exact fields with a [`csv::Writer`] configured identically to the dumper's
//!    ([`csv::WriterBuilder::new`] defaults: `"` quoting, `QuoteStyle::Necessary`, `\n` terminator)
//!    plus the recorded delimiter. The `csv` writer is a deterministic function of (logical fields,
//!    config), and the dumper *is* that same writer, so the bytes match exactly.
//! 2. **"Re-render identical or fall back to raw bytes."** A numeric codec
//!    ([`integer`](graphus_columnar::integer) / [`gorilla`](graphus_columnar::gorilla)) is used for a
//!    column **only if** every non-empty cell parses *and* re-renders byte-identically to its
//!    original text; otherwise the column falls back to a
//!    [`dictionary`](graphus_columnar::dictionary) of the raw cell bytes (trivially lossless). So a
//!    typed codec never changes a cell's bytes — it only ever *shrinks* a column whose text is in the
//!    codec's canonical form.
//!
//! A per-row **present/absent bitmap** ([`encode_bool`](graphus_columnar::encode_bool)) distinguishes
//! an *empty* CSV cell (absent — no value stored) from a stored value, so empties round-trip exactly
//! regardless of the column's codec.

use graphus_columnar::{decode_bool, dictionary, encode_bool, gorilla, integer};

use crate::header::{ColumnRole, PropertyType, ScalarType};

/// The 4-byte magic that prefixes every `.gcol` blob (`b"GCOL"`).
const MAGIC: [u8; 4] = *b"GCOL";
/// The on-disk format version. Bumping it is how a future incompatible layout is detected on read.
///
/// - **v1** — magic + version + delimiter + counts + sections, no integrity check.
/// - **v2** (`rmp` #405) — identical layout, plus a trailing little-endian **CRC32C** over every
///   preceding byte, verified *first* on read so bit-rot / truncation is detected instead of
///   decoding to wrong-but-plausible data. A well-formed v1 column section is byte-identical inside
///   a v2 blob (only the version byte and the 4-byte trailer differ).
const VERSION: u8 = 2;

/// The width of the trailing CRC32C integrity field appended by [`encode_blob`] (v2+).
const CRC_LEN: usize = 4;

/// The per-column codec tag stored in the blob so [`gcol_to_csv`] dispatches the right decoder. The
/// numeric values mirror [`graphus_columnar::CodecKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Codec {
    /// [`graphus_columnar::integer`] `i64` column (the cells are canonical decimal integers).
    Integer = 1,
    /// [`graphus_columnar::gorilla`] `f64` column (the cells re-render byte-identically as floats).
    Float = 2,
    /// [`graphus_columnar::dictionary`] of raw cell bytes (the universal lossless fallback).
    Dictionary = 3,
}

impl Codec {
    /// Decodes a codec tag byte, or `None` for an unknown tag (a corrupt / future blob).
    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Integer),
            2 => Some(Self::Float),
            3 => Some(Self::Dictionary),
            _ => None,
        }
    }
}

/// An error transcoding to/from the `.gcol` format. The CSV-parse and codec layers are themselves
/// total (the codecs are round-trip-exact), so these surface only a malformed/truncated blob or an
/// unreadable input CSV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColumnarError {
    /// The input could not be parsed as CSV (only possible for [`csv_to_gcol`]).
    Csv(String),
    /// The `.gcol` blob is truncated, has a bad magic/version, or an unknown codec tag.
    Malformed(String),
}

impl std::fmt::Display for ColumnarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Csv(m) => write!(f, "columnar: CSV parse: {m}"),
            Self::Malformed(m) => write!(f, "columnar: malformed .gcol: {m}"),
        }
    }
}

impl std::error::Error for ColumnarError {}

impl From<ColumnarError> for graphus_core::GraphusError {
    fn from(e: ColumnarError) -> Self {
        graphus_core::GraphusError::Storage(format!("bulk columnar: {e}"))
    }
}

// =================================================================================================
// Little-endian framing helpers (length-prefixed sections keep the blob self-describing).
// =================================================================================================

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

/// A forward cursor over a `.gcol` blob with bounds-checked reads (a truncated blob errors rather
/// than panicking).
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ColumnarError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| ColumnarError::Malformed("length overflow".to_owned()))?;
        if end > self.bytes.len() {
            return Err(ColumnarError::Malformed(format!(
                "unexpected end of blob (wanted {n} bytes at offset {})",
                self.pos
            )));
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn take_u8(&mut self) -> Result<u8, ColumnarError> {
        Ok(self.take(1)?[0])
    }

    fn take_u32(&mut self) -> Result<u32, ColumnarError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a `u32`-length-prefixed byte section.
    fn take_section(&mut self) -> Result<&'a [u8], ColumnarError> {
        let len = self.take_u32()? as usize;
        self.take(len)
    }
}

/// Validates the trailing CRC32C integrity field (`rmp` #405) and returns the body slice (everything
/// before the trailer) for parsing. Errors if the blob is shorter than the trailer or the stored
/// checksum does not match a fresh CRC32C of the body — so bit-rot / truncation is a controlled
/// error, never a wrong-but-plausible decode (`04 §11.4`).
fn verify_crc(gcol: &[u8]) -> Result<&[u8], ColumnarError> {
    if gcol.len() < CRC_LEN {
        return Err(ColumnarError::Malformed(format!(
            "blob shorter than the {CRC_LEN}-byte CRC32C trailer (len {})",
            gcol.len()
        )));
    }
    let (body, trailer) = gcol.split_at(gcol.len() - CRC_LEN);
    let stored = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let actual = crc32c::crc32c(body);
    if stored != actual {
        return Err(ColumnarError::Malformed(format!(
            "CRC32C mismatch: stored {stored:#010x}, computed {actual:#010x} (blob is corrupt or truncated)"
        )));
    }
    Ok(body)
}

// =================================================================================================
// The scalar type a column declares, decoded from its header cell (drives codec selection).
// =================================================================================================

/// The codec-relevant shape of a column, read from its header cell. Only single (non-array) `int` /
/// `float` columns are eligible for a numeric codec; everything else (strings, IDs, labels, types,
/// booleans, temporals, *and any array column*) goes to the dictionary, whose raw-bytes storage is
/// lossless for arbitrary cell text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ColumnShape {
    /// A single-valued `:int` column — try [`integer`](graphus_columnar::integer).
    IntScalar,
    /// A single-valued `:float` column — try [`gorilla`](graphus_columnar::gorilla).
    FloatScalar,
    /// Anything else — store the raw cell bytes via [`dictionary`](graphus_columnar::dictionary).
    Other,
}

/// Classifies a header cell into its [`ColumnShape`].
///
/// Reserved columns (`:ID`, `:LABEL`, `:START_ID`, `:END_ID`, `:TYPE`) and array / non-numeric
/// property columns are [`ColumnShape::Other`]; only a bare single `:int` / `:float` property column
/// is numeric-codec eligible.
fn shape_of_header(cell: &str) -> ColumnShape {
    // Reuse the importer's exact header grammar so the classification matches how the cell will be
    // parsed back. A header that does not parse (it should always parse — the dumper wrote it) is
    // treated conservatively as `Other`.
    match crate::header::parse_header_cell_public(cell) {
        Ok(ColumnRole::Property {
            ty: PropertyType::Scalar(ScalarType::Integer),
            ..
        }) => ColumnShape::IntScalar,
        Ok(ColumnRole::Property {
            ty: PropertyType::Scalar(ScalarType::Float),
            ..
        }) => ColumnShape::FloatScalar,
        _ => ColumnShape::Other,
    }
}

// =================================================================================================
// csv_to_gcol
// =================================================================================================

/// Transcodes CSV bytes (the importer's node/relationship format) into a self-describing columnar
/// `.gcol` blob, choosing a per-column codec from the header `:type` and the column's actual cell
/// shape.
///
/// `delimiter` is the CSV field separator (matching the dumper / importer, e.g. `b','`). The header
/// row and column order are preserved exactly; the value bytes round-trip exactly (see the
/// module-level lossless contract).
///
/// An **empty input** (no header row) encodes as a header-less blob that [`gcol_to_csv`] turns back
/// into empty bytes.
///
/// # Errors
///
/// Returns [`ColumnarError::Csv`] if `csv_bytes` is not valid CSV under `delimiter`.
pub fn csv_to_gcol(csv_bytes: &[u8], delimiter: u8) -> Result<Vec<u8>, ColumnarError> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .delimiter(delimiter)
        .flexible(true)
        .from_reader(csv_bytes);

    // Read the header row (column names verbatim).
    let mut header = csv::ByteRecord::new();
    if !reader
        .read_byte_record(&mut header)
        .map_err(|e| ColumnarError::Csv(e.to_string()))?
    {
        // Empty input: a zero-column, zero-row blob.
        return Ok(encode_blob(delimiter, &[], &[]));
    }
    let header_cells: Vec<Vec<u8>> = header.iter().map(<[u8]>::to_vec).collect();
    let ncols = header_cells.len();

    // Collect the columns: one `Vec<Vec<u8>>` per column, one entry per data row (raw field bytes).
    // The dumper emits rectangular records (every row has `ncols` fields); a short row (shouldn't
    // happen from the dumper) is padded with empty cells so the column matrix stays rectangular and
    // the round-trip stays well-defined.
    let mut columns: Vec<Vec<Vec<u8>>> = vec![Vec::new(); ncols];
    let mut record = csv::ByteRecord::new();
    loop {
        let more = reader
            .read_byte_record(&mut record)
            .map_err(|e| ColumnarError::Csv(e.to_string()))?;
        if !more {
            break;
        }
        for (c, col) in columns.iter_mut().enumerate() {
            col.push(record.get(c).unwrap_or(b"").to_vec());
        }
    }

    Ok(encode_blob(delimiter, &header_cells, &columns))
}

/// Serialises the header + already-pivoted columns into the `.gcol` byte layout.
fn encode_blob(delimiter: u8, header_cells: &[Vec<u8>], columns: &[Vec<Vec<u8>>]) -> Vec<u8> {
    let ncols = header_cells.len();
    let nrows = columns.first().map_or(0, Vec::len);

    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(delimiter);
    put_u32(&mut out, ncols as u32);
    put_u32(&mut out, nrows as u32);

    // Header section: each column name, length-prefixed.
    for name in header_cells {
        put_bytes(&mut out, name);
    }

    // Column section.
    for (c, name) in header_cells.iter().enumerate() {
        let column = &columns[c];
        encode_column(&mut out, name, column);
    }

    // Integrity trailer (`rmp` #405): CRC32C over every byte written so far, little-endian. Verified
    // first on read, so a single flipped bit or a truncation is *detected* rather than silently
    // decoded into wrong-but-plausible data.
    let crc = crc32c::crc32c(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    out
}

/// Encodes one column: the present/absent bitmap, the chosen codec tag, and the codec payload over
/// the non-empty cells only.
fn encode_column(out: &mut Vec<u8>, header_cell: &[u8], cells: &[Vec<u8>]) {
    // Present bitmap: `true` for a non-empty cell. Empty cells carry no stored value.
    let present: Vec<bool> = cells.iter().map(|c| !c.is_empty()).collect();
    let bitmap = encode_bool(&present);

    // The non-empty cell bytes, in row order, are what the codec stores.
    let values: Vec<&[u8]> = cells
        .iter()
        .filter(|c| !c.is_empty())
        .map(Vec::as_slice)
        .collect();

    // Decide the codec from the header type *and* whether the typed codec is lossless for this data.
    let header_str = std::str::from_utf8(header_cell).unwrap_or("");
    let (codec, payload) = match shape_of_header(header_str) {
        ColumnShape::IntScalar => try_integer_codec(&values)
            .map(|p| (Codec::Integer, p))
            .unwrap_or_else(|| (Codec::Dictionary, dictionary_payload(&values))),
        ColumnShape::FloatScalar => try_float_codec(&values)
            .map(|p| (Codec::Float, p))
            .unwrap_or_else(|| (Codec::Dictionary, dictionary_payload(&values))),
        ColumnShape::Other => (Codec::Dictionary, dictionary_payload(&values)),
    };

    put_bytes(out, &bitmap);
    out.push(codec as u8);
    put_bytes(out, &payload);
}

/// Builds the dictionary payload (the universal lossless fallback) over the present cell bytes.
fn dictionary_payload(values: &[&[u8]]) -> Vec<u8> {
    let owned: Vec<Vec<u8>> = values.iter().map(|v| v.to_vec()).collect();
    dictionary::encode(&owned)
}

/// Tries the integer codec for a column: every present cell must parse to `i64` **and** re-render
/// (via `itoa`) byte-identically to its original text. Returns the codec payload, or `None` to fall
/// back to the dictionary (so a cell like `007`, `+1`, ` 1`, or `1.0` — which would not re-render
/// identically — is never silently rewritten).
fn try_integer_codec(values: &[&[u8]]) -> Option<Vec<u8>> {
    let mut parsed = Vec::with_capacity(values.len());
    let mut buf = itoa::Buffer::new();
    for &cell in values {
        let text = std::str::from_utf8(cell).ok()?;
        let n: i64 = text.parse().ok()?;
        // Canonical-form check: the codec stores the *number*, so it round-trips to `itoa(n)`. Only
        // use it when that is byte-identical to what was written.
        if buf.format(n).as_bytes() != cell {
            return None;
        }
        parsed.push(n);
    }
    Some(integer::encode_i64(&parsed))
}

/// Tries the Gorilla `f64` codec for a column: every present cell must parse to `f64` **and**
/// re-render (via Rust's default `f64` `Display`, which is what the dumper uses) byte-identically to
/// its original text. Returns the payload, or `None` to fall back to the dictionary (so e.g. `1.50`,
/// `1e3`, `NaN`, or `.5` — not the dumper's canonical rendering — stays raw and lossless).
fn try_float_codec(values: &[&[u8]]) -> Option<Vec<u8>> {
    let mut parsed = Vec::with_capacity(values.len());
    for &cell in values {
        let text = std::str::from_utf8(cell).ok()?;
        let f: f64 = text.parse().ok()?;
        // The dumper renders floats with `f64::to_string()` (Rust's shortest round-trip `Display`).
        // Use the codec only when the cell already equals that canonical rendering, so the codec
        // (which stores the bit pattern and re-renders on decode) cannot change the bytes.
        if f.to_string().as_bytes() != cell {
            return None;
        }
        parsed.push(f);
    }
    Some(gorilla::encode(&parsed))
}

// =================================================================================================
// gcol_to_csv
// =================================================================================================

/// Transcodes a `.gcol` blob back into the **byte-identical** CSV the dumper produced (the exact
/// inverse of [`csv_to_gcol`]).
///
/// # Errors
///
/// Returns [`ColumnarError::Malformed`] if `gcol` is truncated, has a bad magic / version, or names
/// an unknown codec.
pub fn gcol_to_csv(gcol: &[u8]) -> Result<Vec<u8>, ColumnarError> {
    // Verify the CRC32C integrity trailer FIRST (`rmp` #405): a blob whose body does not match its
    // trailing checksum is bit-rotted / truncated and must be rejected before any length field is
    // trusted. The trailer is the last `CRC_LEN` bytes; the checksum covers everything before it.
    let body = verify_crc(gcol)?;

    let mut cur = Cursor::new(body);

    let magic = cur.take(4)?;
    if magic != MAGIC {
        return Err(ColumnarError::Malformed(format!(
            "bad magic {magic:?} (expected {MAGIC:?})"
        )));
    }
    let version = cur.take_u8()?;
    if version != VERSION {
        return Err(ColumnarError::Malformed(format!(
            "unsupported version {version} (this build writes/reads v{VERSION})"
        )));
    }
    let delimiter = cur.take_u8()?;
    let ncols = cur.take_u32()? as usize;
    let nrows = cur.take_u32()? as usize;

    // Header section.
    let mut header_cells: Vec<Vec<u8>> = Vec::with_capacity(ncols);
    for _ in 0..ncols {
        header_cells.push(cur.take_section()?.to_vec());
    }

    // Empty input round-trips to empty bytes (no header was written).
    if ncols == 0 {
        return Ok(Vec::new());
    }

    // Column section → reconstruct each column's `nrows` cells.
    let mut columns: Vec<Vec<Vec<u8>>> = Vec::with_capacity(ncols);
    for _ in 0..ncols {
        columns.push(decode_column(&mut cur, nrows)?);
    }

    // Re-serialise with the *same* writer configuration the dumper uses (all `WriterBuilder`
    // defaults) plus the recorded delimiter, so the output is byte-identical to the dumper's CSV.
    let mut writer = csv::WriterBuilder::new()
        .delimiter(delimiter)
        .from_writer(Vec::new());

    // Header row.
    writer
        .write_record(&header_cells)
        .map_err(|e| ColumnarError::Malformed(format!("re-serialising header: {e}")))?;
    // Data rows (column-major → row-major).
    let mut row: Vec<&[u8]> = Vec::with_capacity(ncols);
    for r in 0..nrows {
        row.clear();
        for col in &columns {
            row.push(col[r].as_slice());
        }
        writer
            .write_record(&row)
            .map_err(|e| ColumnarError::Malformed(format!("re-serialising row {r}: {e}")))?;
    }
    writer
        .flush()
        .map_err(|e| ColumnarError::Malformed(format!("flushing CSV: {e}")))?;
    writer
        .into_inner()
        .map_err(|e| ColumnarError::Malformed(format!("finishing CSV writer: {e}")))
}

/// Decodes one column from the cursor back into its `nrows` raw cell-byte values.
fn decode_column(cur: &mut Cursor<'_>, nrows: usize) -> Result<Vec<Vec<u8>>, ColumnarError> {
    let bitmap = cur.take_section()?;
    let present = decode_bool(bitmap, nrows).map_err(codec_err)?;
    let codec = Codec::from_tag(cur.take_u8()?)
        .ok_or_else(|| ColumnarError::Malformed("unknown codec tag".to_owned()))?;
    let payload = cur.take_section()?;
    let n_present = present.iter().filter(|&&p| p).count();

    // Decode the present values into raw cell bytes. Every codec is now fallible: a truncated /
    // adversarial payload surfaces as a controlled `Malformed`, never a panic (`04 §11.4`, rmp #402).
    let values: Vec<Vec<u8>> = match codec {
        Codec::Integer => {
            let nums = integer::decode_i64(payload, n_present).map_err(codec_err)?;
            let mut buf = itoa::Buffer::new();
            nums.iter()
                .map(|n| buf.format(*n).as_bytes().to_vec())
                .collect()
        }
        Codec::Float => gorilla::decode(payload, n_present)
            .map_err(codec_err)?
            .iter()
            .map(|f| f.to_string().into_bytes())
            .collect(),
        Codec::Dictionary => dictionary::decode(payload, n_present).map_err(codec_err)?,
    };

    // Re-expand to `nrows` cells using the bitmap: a present row pulls the next decoded value, an
    // absent row is an empty cell. `values` has exactly `n_present` entries by construction, so the
    // `next` cursor can never run past it.
    let mut out = Vec::with_capacity(nrows);
    let mut next = 0usize;
    for &p in &present {
        if p {
            out.push(values[next].clone());
            next += 1;
        } else {
            out.push(Vec::new());
        }
    }
    Ok(out)
}

/// Maps a [`graphus_columnar::DecodeError`] (a malformed codec payload) into the transcoder's
/// [`ColumnarError::Malformed`], so a corrupt `.gcol` is a controlled error rather than a panic.
fn codec_err(e: graphus_columnar::DecodeError) -> ColumnarError {
    ColumnarError::Malformed(format!("codec payload: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The round-trip property the whole module exists to guarantee.
    fn assert_lossless(csv: &str, delimiter: u8) {
        let gcol = csv_to_gcol(csv.as_bytes(), delimiter).expect("encode");
        let back = gcol_to_csv(&gcol).expect("decode");
        assert_eq!(
            back,
            csv.as_bytes(),
            "round-trip must be byte-identical\n  in:  {csv:?}\n  out: {:?}",
            String::from_utf8_lossy(&back)
        );
    }

    #[test]
    fn empty_input_round_trips() {
        assert_lossless("", b',');
    }

    #[test]
    fn header_only_round_trips() {
        assert_lossless(":ID,:LABEL,name:string\n", b',');
    }

    #[test]
    fn typed_columns_round_trip() {
        let csv = ":ID,:LABEL,name:string,age:int,score:float,active:boolean\n\
                   1,Person,Alice,30,1.5,true\n\
                   2,Person;Admin,Bob,25,2.5,false\n";
        assert_lossless(csv, b',');
    }

    #[test]
    fn empty_cells_round_trip() {
        // Mixed present/absent in every column kind.
        let csv = ":ID,:LABEL,name:string,age:int,score:float\n\
                   1,,Alice,,1.5\n\
                   2,Person,,25,\n\
                   3,,Carol,30,3.5\n";
        assert_lossless(csv, b',');
    }

    #[test]
    fn integer_falls_back_to_dictionary_on_noncanonical_text() {
        // `007` and `+1` parse to i64 but do NOT re-render identically — the column must fall back to
        // the dictionary and round-trip the original bytes exactly.
        let csv = "id:ID,code:int\n\
                   a,007\n\
                   b,+1\n\
                   c,42\n";
        assert_lossless(csv, b',');
        // Verify the fallback actually triggered (codec tag is Dictionary for the `code` column).
        let gcol = csv_to_gcol(csv.as_bytes(), b',').unwrap();
        assert_eq!(column_codec(&gcol, 1), Codec::Dictionary);
    }

    #[test]
    fn float_falls_back_to_dictionary_on_noncanonical_text() {
        // `1.50` and `1e3` are not Rust's canonical `f64` Display → dictionary fallback.
        let csv = "id:ID,v:float\n\
                   a,1.50\n\
                   b,1e3\n\
                   c,2.5\n";
        assert_lossless(csv, b',');
        let gcol = csv_to_gcol(csv.as_bytes(), b',').unwrap();
        assert_eq!(column_codec(&gcol, 1), Codec::Dictionary);
    }

    #[test]
    fn canonical_integers_use_the_integer_codec() {
        let csv = "id:ID,seq:int\n\
                   a,1\n\
                   b,2\n\
                   c,3\n";
        assert_lossless(csv, b',');
        let gcol = csv_to_gcol(csv.as_bytes(), b',').unwrap();
        assert_eq!(column_codec(&gcol, 1), Codec::Integer);
    }

    #[test]
    fn canonical_floats_use_the_gorilla_codec() {
        let csv = "id:ID,v:float\n\
                   a,1.5\n\
                   b,1.5\n\
                   c,1.5\n";
        assert_lossless(csv, b',');
        let gcol = csv_to_gcol(csv.as_bytes(), b',').unwrap();
        assert_eq!(column_codec(&gcol, 1), Codec::Float);
    }

    #[test]
    fn quoted_and_special_cells_round_trip() {
        // Fields needing CSV quoting (commas, quotes, newlines) must survive byte-identically.
        let csv = "id:ID,note:string\n\
                   1,\"a,b\"\n\
                   2,\"he said \"\"hi\"\"\"\n\
                   3,\"line1\nline2\"\n";
        assert_lossless(csv, b',');
    }

    #[test]
    fn custom_delimiter_round_trips() {
        let csv = "id:ID;name:string;age:int\n1;Alice;30\n2;Bob;25\n";
        assert_lossless(csv, b';');
    }

    #[test]
    fn arrays_round_trip_via_dictionary() {
        let csv = "id:ID,tags:string[],scores:int[]\n\
                   n1,a;b;c,1;2;3\n\
                   n2,,\n";
        assert_lossless(csv, b',');
    }

    #[test]
    fn negative_and_extreme_integers_round_trip() {
        let csv = format!("id:ID,n:int\na,{}\nb,0\nc,{}\nd,-1\n", i64::MIN, i64::MAX);
        assert_lossless(&csv, b',');
        let gcol = csv_to_gcol(csv.as_bytes(), b',').unwrap();
        assert_eq!(column_codec(&gcol, 1), Codec::Integer);
    }

    #[test]
    fn malformed_blob_errors_cleanly() {
        assert!(matches!(
            gcol_to_csv(b"NOPE").unwrap_err(),
            ColumnarError::Malformed(_)
        ));
        assert!(matches!(
            gcol_to_csv(&[]).unwrap_err(),
            ColumnarError::Malformed(_)
        ));
    }

    /// A valid `.gcol` carries a CRC32C trailer; flipping ANY single byte must be detected as
    /// `Malformed` rather than decoded into wrong data (`rmp` #405).
    #[test]
    fn gcol_single_byte_flip_is_detected() {
        let csv = ":ID,:LABEL,name:string,age:int,score:float\n\
                   1,Person,Alice,30,1.5\n\
                   2,Person;Admin,Bob,25,2.5\n";
        let good = csv_to_gcol(csv.as_bytes(), b',').unwrap();
        // The good blob decodes byte-identically.
        assert_eq!(gcol_to_csv(&good).unwrap(), csv.as_bytes());
        // Flipping any single byte (including a CRC-trailer byte) must be caught.
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0x01;
            assert!(
                matches!(gcol_to_csv(&bad), Err(ColumnarError::Malformed(_))),
                "flip at byte {i} must be detected as Malformed"
            );
        }
    }

    /// Truncating a valid blob — at the trailer boundary or mid-section — must be a controlled error,
    /// never a panic or a partial decode (`rmp` #405).
    #[test]
    fn gcol_truncation_is_detected() {
        let csv = "id:ID,seq:int\na,1\nb,2\nc,3\n";
        let good = csv_to_gcol(csv.as_bytes(), b',').unwrap();
        // Drop the last byte (truncated CRC trailer) — CRC can no longer match.
        assert!(matches!(
            gcol_to_csv(&good[..good.len() - 1]),
            Err(ColumnarError::Malformed(_))
        ));
        // Truncate on a section boundary (just past the header) — both the CRC trailer is gone and
        // the body is short; either way it is rejected, not panicked.
        for cut in [0, 5, 9, good.len() / 2] {
            assert!(
                matches!(gcol_to_csv(&good[..cut]), Err(ColumnarError::Malformed(_))),
                "truncation to {cut} bytes must be Malformed"
            );
        }
    }

    /// A blob whose codec payload is internally corrupt (but the CRC happens to be recomputed over
    /// it) must still surface as a controlled `Malformed`, never a panic — this exercises the
    /// fallible `graphus-columnar` decoders through the transcoder (`rmp` #402).
    #[test]
    fn corrupt_codec_payload_is_a_controlled_error() {
        // Build a valid blob, then corrupt a column's payload bytes *and* fix the CRC so the codec
        // layer (not the CRC layer) is what rejects it.
        let csv = "id:ID,seq:int\na,1\nb,2\nc,3\n";
        let good = csv_to_gcol(csv.as_bytes(), b',').unwrap();
        let body_len = good.len() - CRC_LEN;
        // Replace the integer codec tag byte's payload region with a forged short payload by simply
        // zeroing the body interior; recompute the CRC so only the decoder can object.
        let mut tampered = good.clone();
        for b in &mut tampered[10..body_len] {
            *b = 0xFF;
        }
        let crc = crc32c::crc32c(&tampered[..body_len]);
        tampered[body_len..].copy_from_slice(&crc.to_le_bytes());
        // Must be Err (Malformed), and crucially must not panic/abort.
        assert!(matches!(
            gcol_to_csv(&tampered),
            Err(ColumnarError::Malformed(_))
        ));
    }

    /// Reads the codec tag of column `target` out of a blob (test introspection only).
    fn column_codec(gcol: &[u8], target: usize) -> Codec {
        let mut cur = Cursor::new(gcol);
        cur.take(4).unwrap(); // magic
        cur.take_u8().unwrap(); // version
        cur.take_u8().unwrap(); // delimiter
        let ncols = cur.take_u32().unwrap() as usize;
        cur.take_u32().unwrap(); // nrows
        for _ in 0..ncols {
            cur.take_section().unwrap(); // header cell
        }
        for c in 0..ncols {
            cur.take_section().unwrap(); // bitmap
            let codec = Codec::from_tag(cur.take_u8().unwrap()).unwrap();
            cur.take_section().unwrap(); // payload
            if c == target {
                return codec;
            }
        }
        panic!("column {target} out of range");
    }
}
