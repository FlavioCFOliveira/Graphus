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
    /// The blob is well-formed and CRC-valid, but decoding it would exceed the caller's transcode
    /// memory budget ([`gcol_to_csv_limited`]) — i.e. its declared row count, or the working set its
    /// columns would materialise, is larger than the budget permits. A **CRC-valid** blob can still
    /// be a decompression bomb (a small compressed column decoding to gigabytes: e.g. a single
    /// dictionary entry referenced by billions of present rows), so this is the bound that keeps peak
    /// decode memory independent of the *decoded* size, not just the uploaded size (`rmp` #595). Never
    /// returned by the unbudgeted [`gcol_to_csv`].
    TooLarge(String),
}

impl std::fmt::Display for ColumnarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Csv(m) => write!(f, "columnar: CSV parse: {m}"),
            Self::Malformed(m) => write!(f, "columnar: malformed .gcol: {m}"),
            Self::TooLarge(m) => write!(f, "columnar: .gcol exceeds decode memory budget: {m}"),
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

    /// The number of bytes left between the cursor and the end of the blob. Used to clamp / reject a
    /// forged element count *before* a `Vec::with_capacity`, so an attacker-controlled count cannot
    /// drive a multi-gigabyte pre-allocation (`rmp` #439, `04 §11.4`).
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
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

/// The heap cost, in bytes, this transcoder charges its decode budget for **every** reconstructed
/// cell — one owned `Vec<u8>` header (24 bytes on a 64-bit target) lives in `columns` per row per
/// column regardless of whether that cell carries any value bytes. Charging it (rather than counting
/// only value bytes) is what stops a *tall-but-empty* or *wide-but-empty* blob — whose sections are
/// tiny but whose `nrows × ncols` pointer array is gigantic — from slipping a multi-gigabyte
/// allocation past a value-bytes-only limit (`rmp` #595).
const PER_CELL_OVERHEAD: usize = std::mem::size_of::<Vec<u8>>();

/// The heap cost, in bytes, this transcoder charges its decode budget for **every** column, on top of
/// its cells: the two `ncols`-length outer pointer arrays a decode always builds — `header_cells`
/// (`Vec<Vec<u8>>`) and `columns` (`Vec<Vec<Vec<u8>>>`), each one `Vec<u8>`-header (24 bytes) per
/// column. Charging it (via the `max_cols` ceiling) is what stops a *wide* blob — whose per-column
/// sections are tiny but whose `ncols`-length pointer arrays are gigantic — from slipping a
/// multi-gigabyte outer-array allocation past the per-cell limit, the sibling of the `nrows`
/// row-ceiling for the *tall* case (`rmp` #595, Finding E-3).
const PER_COL_OVERHEAD: usize = 2 * std::mem::size_of::<Vec<u8>>();

/// Charges `cost` bytes against the remaining decode budget, failing with [`ColumnarError::TooLarge`]
/// the instant the running total would cross it — so an adversarial blob is rejected **before** the
/// offending allocation completes, not after it has already exhausted memory.
fn charge(remaining: &mut usize, cost: usize) -> Result<(), ColumnarError> {
    if cost > *remaining {
        return Err(ColumnarError::TooLarge(format!(
            "decoding would need at least {cost} more bytes than the remaining transcode budget \
             allows; the blob is a decompression bomb or larger than this endpoint permits"
        )));
    }
    *remaining -= cost;
    Ok(())
}

/// Transcodes a `.gcol` blob back into the **byte-identical** CSV the dumper produced (the exact
/// inverse of [`csv_to_gcol`]), with **no memory budget** — for trusted, offline callers (the
/// `graphus-bulk` CLI decoding its own just-written files, round-trip tests). Network paths that
/// transcode an attacker-influenced upload MUST use [`gcol_to_csv_limited`] instead, so a CRC-valid
/// decompression bomb cannot drive an unbounded allocation.
///
/// # Errors
///
/// Returns [`ColumnarError::Malformed`] if `gcol` is truncated, has a bad magic / version, or names
/// an unknown codec.
pub fn gcol_to_csv(gcol: &[u8]) -> Result<Vec<u8>, ColumnarError> {
    gcol_to_csv_limited(gcol, usize::MAX)
}

/// Transcodes a `.gcol` blob back into CSV like [`gcol_to_csv`], but bounds the **peak decode working
/// set** to `max_decoded_bytes` so the transcode's memory is a function of the *budget*, never of the
/// (potentially adversarial) decoded size (`rmp` #595, `04 §11.4`).
///
/// The CRC32C integrity trailer is still verified **first and in full** (unchanged from
/// [`gcol_to_csv`]) — a corrupt / truncated blob is rejected before any budgeting runs, so this never
/// weakens integrity checking. The budget then guards the two allocations a CRC-valid blob can still
/// blow up:
///
/// 1. The declared `nrows` is capped so a single column's `nrows`-length intermediates (the
///    present/absent bitmap, the unpacked code stream, and the returned per-cell pointer array)
///    cannot exceed the budget on their own.
/// 2. Every reconstructed cell — including the fixed [`PER_CELL_OVERHEAD`] and, for dictionary
///    columns, the *pre-summed* size of the entries their row codes reference — is charged against a
///    running budget, so a small compressed column that decodes to gigabytes (a single dictionary
///    entry cited by billions of present rows) is rejected via [`ColumnarError::TooLarge`] the moment
///    the running total crosses the limit, before that allocation completes.
///
/// # Errors
///
/// [`ColumnarError::Malformed`] for a corrupt / truncated / unknown-codec blob (as [`gcol_to_csv`]),
/// or [`ColumnarError::TooLarge`] if a CRC-valid blob's decoded working set would exceed
/// `max_decoded_bytes`.
pub fn gcol_to_csv_limited(
    gcol: &[u8],
    max_decoded_bytes: usize,
) -> Result<Vec<u8>, ColumnarError> {
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

    // Cap `nrows` against the budget BEFORE decoding any column. Each column materialises `nrows`
    // owned cells (an `nrows`-entry `Vec<u8>` array), and its decode allocates `nrows`-sized
    // intermediates (the present/absent bitmap `Vec<bool>`, and — for an all-present column — an
    // `nrows`-entry unpacked code stream). A CRC-valid header can declare up to `u32::MAX` rows
    // (`decode_bool` would then need `nrows/8` bitmap bytes, so ~536 MB of bitmap already buys
    // ~4.29 billion rows), so without this ceiling a single column's `nrows`-length arrays alone
    // could dwarf the budget before any per-cell accounting runs. `max_decoded_bytes / PER_CELL_
    // OVERHEAD` is the largest row count whose per-cell pointer array can possibly fit the budget
    // (`rmp` #595). The unbudgeted [`gcol_to_csv`] passes `usize::MAX`, so `max_rows` is effectively
    // unbounded for trusted callers.
    let max_rows = (max_decoded_bytes / PER_CELL_OVERHEAD).max(1);
    if nrows > max_rows {
        return Err(ColumnarError::TooLarge(format!(
            "row count {nrows} exceeds the {max_rows}-row ceiling this transcode budget permits \
             (raise the budget or split the upload)"
        )));
    }

    // Clamp `ncols` against the remaining body length BEFORE any `Vec::with_capacity(ncols)`: each of
    // the `ncols` header cells consumes at least its 4-byte length prefix (and each column section a
    // further bitmap + tag + payload), so the blob cannot describe more columns than it has bytes
    // left. A forged `ncols` (e.g. `0xFFFF_FFFF`, ~103 GB of capacity) that passes the CRC is still
    // structurally impossible, so reject it here rather than pre-allocate gigabytes and then fail in
    // the read loop (`rmp` #439, mirrors `dictionary::read_dict_header` and `coldstore`'s `count`
    // guard). The CRC has already proved the bytes intact; this guards an intact-but-absurd count.
    if ncols > cur.remaining() {
        return Err(ColumnarError::Malformed(format!(
            "column count {ncols} exceeds the {} remaining body bytes (truncated or forged header)",
            cur.remaining()
        )));
    }

    // Cap `ncols` against the budget BEFORE the two `Vec::with_capacity(ncols)` outer arrays below.
    // `ncols > cur.remaining()` above only bounds the count by the *upload* size (each column needs
    // ≥1 body byte), NOT by the decode budget — so a wide-but-shallow blob (e.g. a 1 GiB upload whose
    // body is ~`ncols` minimal column sections) would reserve `ncols × PER_COL_OVERHEAD` for
    // `header_cells` + `columns` (24 B each × 2 ≈ 48 B/column ⇒ tens of GiB of pointer array),
    // sidestepping the per-cell charge and OOM-/abort-ing the host on a single `malloc`. This is the
    // *wide*-blob sibling of the `max_rows` *tall*-blob ceiling (`rmp` #595, Finding E-3). The
    // unbudgeted [`gcol_to_csv`] passes `usize::MAX`, so `max_cols` is effectively unbounded there and
    // a forged `ncols` still falls to the `Malformed` guard above (trusted-path behaviour unchanged).
    let max_cols = (max_decoded_bytes / PER_COL_OVERHEAD).max(1);
    if ncols > max_cols {
        return Err(ColumnarError::TooLarge(format!(
            "column count {ncols} exceeds the {max_cols}-column ceiling this transcode budget permits \
             (raise the budget or split the upload)"
        )));
    }

    // Header section. Capacity is clamped to `ncols`, now proven `<=` the bytes that remain AND
    // `<= max_cols`, so it can be neither an upload- nor a budget-driven over-allocation.
    let mut header_cells: Vec<Vec<u8>> = Vec::with_capacity(ncols);
    for _ in 0..ncols {
        header_cells.push(cur.take_section()?.to_vec());
    }

    // Empty input round-trips to empty bytes (no header was written).
    if ncols == 0 {
        return Ok(Vec::new());
    }

    // Column section → reconstruct each column's `nrows` cells. `ncols` is already bounded above by
    // the body length, so this capacity cannot be an attacker-driven over-allocation either. A
    // running `budget` (shared across all columns) is charged as each cell is materialised, so the
    // whole `columns` working set stays `<= max_decoded_bytes` and an entry-reuse decompression bomb
    // is rejected mid-decode rather than after it OOMs (`rmp` #595).
    let mut budget = max_decoded_bytes;
    // Charge the two `ncols`-length outer pointer arrays (`header_cells`, already built above, and
    // `columns`, about to be) against the shared budget up front — the `nrows` row array is likewise
    // charged per column inside `decode_column`, so accounting the *column* arrays here keeps total
    // decode memory `<= max_decoded_bytes` rather than a multiple of it. `ncols <= max_cols` makes
    // this charge always fit; it is exactly that ceiling's basis (`rmp` #595).
    charge(&mut budget, ncols.saturating_mul(PER_COL_OVERHEAD))?;
    let mut columns: Vec<Vec<Vec<u8>>> = Vec::with_capacity(ncols);
    for _ in 0..ncols {
        columns.push(decode_column(&mut cur, nrows, &mut budget)?);
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

/// Decodes one column from the cursor back into its `nrows` raw cell-byte values, charging every
/// materialised cell against the shared `budget` so the running working set stays within the caller's
/// [`gcol_to_csv_limited`] limit (`rmp` #595). `nrows` is already capped against the budget by the
/// caller, so the `nrows`-length intermediates (`present`, the unpacked code stream, `out`) are each
/// bounded before this runs; the per-cell charging below then bounds the value bytes on top of that.
fn decode_column(
    cur: &mut Cursor<'_>,
    nrows: usize,
    budget: &mut usize,
) -> Result<Vec<Vec<u8>>, ColumnarError> {
    let bitmap = cur.take_section()?;
    let present = decode_bool(bitmap, nrows).map_err(codec_err)?;
    let codec = Codec::from_tag(cur.take_u8()?)
        .ok_or_else(|| ColumnarError::Malformed("unknown codec tag".to_owned()))?;
    let payload = cur.take_section()?;
    let n_present = present.iter().filter(|&&p| p).count();

    // Charge the fixed pointer-array cost for this column's `nrows` owned cells up front (present or
    // empty, every row is a `Vec<u8>` in the returned column). `nrows <= max_decoded_bytes /
    // PER_CELL_OVERHEAD` is guaranteed by the caller, so this single charge can never overflow.
    charge(budget, nrows.saturating_mul(PER_CELL_OVERHEAD))?;

    // Decode the present values into raw cell bytes, charging each value's length as it is produced so
    // the loop aborts the instant the running total crosses the budget — before the offending
    // allocation grows unbounded. Every codec is fallible: a truncated / adversarial payload surfaces
    // as a controlled `Malformed`, never a panic (`04 §11.4`, rmp #402).
    let mut values: Vec<Vec<u8>> = Vec::with_capacity(n_present);
    match codec {
        Codec::Integer => {
            let nums = integer::decode_i64(payload, n_present).map_err(codec_err)?;
            let mut buf = itoa::Buffer::new();
            for n in &nums {
                let cell = buf.format(*n).as_bytes().to_vec();
                charge(budget, cell.len())?;
                values.push(cell);
            }
        }
        Codec::Float => {
            let floats = gorilla::decode(payload, n_present).map_err(codec_err)?;
            for f in &floats {
                let cell = f.to_string().into_bytes();
                charge(budget, cell.len())?;
                values.push(cell);
            }
        }
        Codec::Dictionary => {
            // Bound the dictionary's OWN pointer array (built inside `decode_codes` →
            // `read_dict_header`) against the shared budget BEFORE it is allocated. A dictionary
            // payload declares `num` distinct entries and reconstructs them into a `num`-entry
            // `Vec<Vec<u8>>` (24 B/entry); `read_dict_header` clamps that reservation to the entries
            // the payload can physically hold (each entry costs a ≥4-byte length prefix, so
            // `<= payload/4`) but NOT to the budget — so a *wide*-dictionary column (num ≈ payload/4
            // distinct entries) would reserve O(payload) of pointer array, sidestepping the per-cell
            // charge below and OOM-/abort-ing the host on a single upload-sized `malloc` (`rmp` #595,
            // Finding E-3). Charge that reservation here — the declared count is the leading LE `u32`
            // of the payload (mirrors `dictionary::encode`'s framing) — so an over-wide dictionary is
            // `TooLarge` before it allocates. A payload too short to even hold the count decodes to a
            // controlled `Malformed` in `decode_codes` as before.
            if let Some(head) = payload.get(0..4) {
                let declared = u32::from_le_bytes(head.try_into().expect("4 bytes")) as usize;
                let dict_entries = declared.min(payload.len() / 4);
                charge(budget, dict_entries.saturating_mul(PER_CELL_OVERHEAD))?;
            }
            // Decode to raw codes + dictionary WITHOUT materialising one owned value per row
            // (`decode_codes` is itself bomb-safe: the code stream is bounded by `n_present <= nrows`
            // and the dictionary reservation is now budget-charged just above). Then charge each row's
            // referenced entry length as it is cloned, so a single small dictionary entry cited by a
            // huge number of present rows (the classic decompression bomb — a CRC-valid blob whose
            // decoded size is orders of magnitude larger than the compressed input) is rejected via
            // `TooLarge` the moment the running total crosses the budget, never after it OOMs.
            let (codes, dict) = dictionary::decode_codes(payload, n_present).map_err(codec_err)?;
            for &c in &codes {
                // `decode_codes` already validated every code `< dict.len()`, so this cannot panic.
                let entry = &dict[c as usize];
                charge(budget, entry.len())?;
                values.push(entry.clone());
            }
        }
    }

    // Re-expand to `nrows` cells using the bitmap: a present row **moves** in the next decoded value
    // (no clone — `values` is consumed here, so only one copy of the cell bytes is ever resident), an
    // absent row is an empty cell. `values` has exactly `n_present` entries by construction, so the
    // iterator can never run dry before the present rows are filled.
    let mut out = Vec::with_capacity(nrows);
    let mut it = values.into_iter();
    for &p in &present {
        if p {
            out.push(
                it.next()
                    .expect("n_present present rows ⇒ n_present decoded values"),
            );
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

    /// A blob whose `ncols` header is forged to `u32::MAX` (with a VALID CRC, so the CRC layer cannot
    /// reject it) must be a controlled `Malformed` and return PROMPTLY — never a ~103 GB
    /// `Vec::with_capacity(ncols)` over-allocation (`rmp` #439, `04 §11.4`). The clamp is `ncols <=`
    /// the remaining body bytes: a tiny body cannot describe `u32::MAX` columns.
    #[test]
    fn forged_ncols_is_rejected_promptly_without_oversized_alloc() {
        // Build a minimal-but-well-framed body, then overwrite `ncols` (offset 6, u32 LE) with
        // u32::MAX and re-stamp a fresh CRC32C so only the `ncols` guard can object.
        // Layout: magic[4] version[1] delimiter[1] ncols[4] nrows[4] ... (see `encode_blob`).
        let mut blob = csv_to_gcol(b":ID\n1\n", b',').unwrap();
        let body_len = blob.len() - CRC_LEN;
        blob[6..10].copy_from_slice(&u32::MAX.to_le_bytes()); // forge ncols
        let crc = crc32c::crc32c(&blob[..body_len]);
        blob[body_len..].copy_from_slice(&crc.to_le_bytes()); // valid CRC over the forged body

        let start = std::time::Instant::now();
        let result = gcol_to_csv(&blob);
        let elapsed = start.elapsed();
        assert!(
            matches!(result, Err(ColumnarError::Malformed(_))),
            "a forged u32::MAX ncols must be rejected as Malformed, got {result:?}"
        );
        // Promptly: the guard fires before any per-column allocation. A multi-GB pre-allocation would
        // take far longer (or OOM-abort); a structural reject is sub-millisecond. Generous bound to
        // stay robust on a loaded CI box while still failing a real ~103 GB allocation attempt.
        assert!(
            elapsed.as_secs() < 5,
            "rejecting a forged ncols must be prompt (no oversized alloc), took {elapsed:?}"
        );
    }

    /// Builds a **single dictionary column** `.gcol` blob directly (bypassing `csv_to_gcol`, so a
    /// decompression bomb can be constructed cheaply — one stored entry, not one per row), with a
    /// correct CRC32C trailer so it passes integrity verification and reaches the decode budget.
    /// Mirrors `encode_blob` + `dictionary::encode`'s on-disk layout for one all-`Other` (dictionary)
    /// column of `present.len()` rows whose every present row references the single `entry`.
    fn build_single_dict_column_blob(
        header: &[u8],
        present: &[bool],
        entry: &[u8],
        delimiter: u8,
    ) -> Vec<u8> {
        // Dictionary payload: [num_entries=1][entry_len][entry][code_width=0]; width 0 (one distinct
        // value) means an EMPTY code stream, so this stays tiny no matter how many rows cite it.
        let mut payload = Vec::new();
        put_u32(&mut payload, 1);
        put_u32(&mut payload, entry.len() as u32);
        payload.extend_from_slice(entry);
        payload.push(0);

        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(delimiter);
        put_u32(&mut out, 1); // ncols
        put_u32(&mut out, present.len() as u32); // nrows
        put_bytes(&mut out, header); // header cell
        put_bytes(&mut out, &encode_bool(present)); // column bitmap section
        out.push(Codec::Dictionary as u8); // codec tag
        put_bytes(&mut out, &payload); // column payload section
        let crc = crc32c::crc32c(&out); // valid trailer over the whole body
        out.extend_from_slice(&crc.to_le_bytes());
        out
    }

    /// `rmp` #595 (Finding E-3): a **CRC-valid** `.gcol` in which one small dictionary entry is
    /// referenced by many present rows decodes to orders of magnitude more than its compressed size.
    /// [`gcol_to_csv_limited`] must reject it as [`ColumnarError::TooLarge`] (NOT `Malformed` — the
    /// blob is structurally valid) the moment the running decode exceeds the budget, having allocated
    /// only up-to-budget bytes, never the full decoded size.
    #[test]
    fn dictionary_entry_reuse_bomb_is_rejected_within_budget() {
        let n = 2_000usize;
        let entry = vec![b'x'; 100_000]; // 100 KB entry, cited by every one of the n rows
        let present = vec![true; n];
        let blob = build_single_dict_column_blob(b"v:string", &present, &entry, b',');
        // Compressed blob is tiny (one 100 KB entry + an n/8 bitmap); decoded is n × 100 KB ≈ 200 MB.
        assert!(
            blob.len() < 200 * 1024,
            "the bomb's COMPRESSED size must stay tiny: {} bytes",
            blob.len()
        );

        let budget = 4 * 1024 * 1024; // 4 MiB — two orders of magnitude below the ~200 MB decode
        let start = std::time::Instant::now();
        let result = gcol_to_csv_limited(&blob, budget);
        let elapsed = start.elapsed();
        assert!(
            matches!(result, Err(ColumnarError::TooLarge(_))),
            "an entry-reuse bomb (valid CRC/structure) must be TooLarge, got {result:?}"
        );
        // Prompt/bounded: had it materialised the full 200 MB (or more, at billions of rows) it would
        // take far longer or OOM-abort. The running budget caps the allocation at ~4 MiB.
        assert!(
            elapsed.as_secs() < 5,
            "bomb rejection must be prompt/bounded, took {elapsed:?}"
        );

        // The SAME structure at a small row count decodes fine under the same budget — proof the
        // blob shape is genuinely valid (rejected purely on size, not because it is malformed).
        let ok = build_single_dict_column_blob(b"v:string", &[true, true, true], b"xxxx", b',');
        assert!(gcol_to_csv_limited(&ok, budget).is_ok());
    }

    /// `rmp` #595: a blob declaring far more rows than the budget's per-cell pointer array can hold is
    /// rejected at the row-count ceiling BEFORE any column is decoded — the guard against a *tall*
    /// blob whose `nrows`-length intermediates (bitmap, code stream, cell array) alone exhaust memory.
    #[test]
    fn oversized_row_count_is_rejected_at_the_budget_row_cap() {
        let n = 5_000_000usize; // 5M rows → ~625 KB bitmap, cheap to build
        let present = vec![true; n];
        let blob = build_single_dict_column_blob(b"v:string", &present, b"z", b',');

        let budget = 1024 * 1024; // 1 MiB ⇒ max_rows ≈ 43_690, far below 5M
        let start = std::time::Instant::now();
        let result = gcol_to_csv_limited(&blob, budget);
        let elapsed = start.elapsed();
        assert!(
            matches!(result, Err(ColumnarError::TooLarge(_))),
            "a row count above the budget's row ceiling must be TooLarge, got {result:?}"
        );
        assert!(
            elapsed.as_secs() < 5,
            "row-cap rejection must be prompt (before any decode), took {elapsed:?}"
        );
    }

    /// `rmp` #595: on VALID data, the budgeted transcode is byte-identical to the unbudgeted one — the
    /// bound must not alter correct output, only reject oversized/adversarial input.
    #[test]
    fn budgeted_transcode_matches_unbudgeted_on_valid_data() {
        let csv = ":ID,:LABEL,name:string,age:int,score:float,active:boolean\n\
                   1,Person,Alice,30,1.5,true\n\
                   2,Person;Admin,Bob,25,2.5,false\n\
                   3,,Carol,,3.5,\n";
        let blob = csv_to_gcol(csv.as_bytes(), b',').unwrap();
        let unbudgeted = gcol_to_csv(&blob).unwrap();
        let budgeted = gcol_to_csv_limited(&blob, 16 * 1024 * 1024).unwrap();
        assert_eq!(
            budgeted, unbudgeted,
            "a generous budget must not change the decoded output"
        );
        assert_eq!(
            budgeted,
            csv.as_bytes(),
            "and it must be byte-identical to the source CSV"
        );
    }

    /// `rmp` #595: the budget MUST NOT weaken CRC integrity — a partial/corrupt upload is still
    /// rejected (never partially applied), exactly as on the unbudgeted path. Any single-byte flip
    /// stays `Malformed`, even with an effectively-unbounded budget.
    #[test]
    fn budgeted_transcode_still_enforces_crc_integrity() {
        let csv = "id:ID,seq:int\na,1\nb,2\nc,3\n";
        let good = csv_to_gcol(csv.as_bytes(), b',').unwrap();
        assert_eq!(
            gcol_to_csv_limited(&good, usize::MAX).unwrap(),
            csv.as_bytes()
        );
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0x01;
            assert!(
                matches!(
                    gcol_to_csv_limited(&bad, usize::MAX),
                    Err(ColumnarError::Malformed(_))
                ),
                "flip at byte {i} must be Malformed under the budgeted path too"
            );
        }
    }

    /// Builds a CRC-valid `.gcol` of `ncols` **empty** (0-row) dictionary columns — cheap to
    /// construct (each column is a fixed ~19 bytes) yet, without the `max_cols` ceiling, would drive
    /// two `Vec::with_capacity(ncols)` outer pointer arrays (`header_cells` + `columns`, 24 B each)
    /// that scale with the upload, not the decode budget. Used to prove the *wide*-blob budget cap.
    fn build_wide_empty_blob(ncols: usize) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(b','); // delimiter
        put_u32(&mut out, ncols as u32);
        put_u32(&mut out, 0); // nrows = 0
        for _ in 0..ncols {
            put_bytes(&mut out, b"c"); // header cell
        }
        let empty_bitmap = encode_bool(&[]);
        let mut empty_dict_payload = Vec::new();
        put_u32(&mut empty_dict_payload, 0); // 0 dictionary entries
        empty_dict_payload.push(0); // code width 0
        for _ in 0..ncols {
            put_bytes(&mut out, &empty_bitmap);
            out.push(Codec::Dictionary as u8);
            put_bytes(&mut out, &empty_dict_payload);
        }
        let crc = crc32c::crc32c(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        out
    }

    /// Builds a CRC-valid single-column `.gcol` whose dictionary header declares `num_entries` empty
    /// entries over **0 rows** — the compressed blob is a few MB (one 4-byte length prefix per entry)
    /// but `read_dict_header` would reconstruct a `num_entries`-slot `Vec<Vec<u8>>` (24 B each). Used
    /// to prove the *wide-dictionary* pointer-array reservation is now budget-charged.
    fn build_wide_dict_blob(num_entries: usize) -> Vec<u8> {
        let mut payload = Vec::new();
        put_u32(&mut payload, num_entries as u32);
        for _ in 0..num_entries {
            put_u32(&mut payload, 0); // each entry: length 0 (empty)
        }
        payload.push(0); // code width 0 (no code bytes: 0 rows)

        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(b',');
        put_u32(&mut out, 1); // ncols = 1
        put_u32(&mut out, 0); // nrows = 0
        put_bytes(&mut out, b"v:string"); // header cell
        put_bytes(&mut out, &encode_bool(&[])); // 0-row bitmap
        out.push(Codec::Dictionary as u8);
        put_bytes(&mut out, &payload);
        let crc = crc32c::crc32c(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        out
    }

    /// `rmp` #595 (Finding E-3, security re-audit F1): a CRC-valid but very *wide* blob (huge `ncols`,
    /// tiny per-column sections) whose two `ncols`-length outer pointer arrays would exceed the budget
    /// must be rejected at the `max_cols` ceiling — [`ColumnarError::TooLarge`], promptly, BEFORE any
    /// `Vec::with_capacity(ncols)` runs — not allowed to reserve `ncols × 48 B` off-budget (which at
    /// the production `.gcol` cap is a multi-GiB single `malloc` → process abort).
    #[test]
    fn oversized_column_count_is_rejected_at_the_budget_column_cap() {
        let ncols = 50_000usize; // 50k cols × 48 B ≈ 2.4 MB pointer array, ~950 KB compressed blob
        let blob = build_wide_empty_blob(ncols);
        let budget = 4096; // ⇒ max_cols ≈ 4096/48 ≈ 85, far below 50k
        let start = std::time::Instant::now();
        let result = gcol_to_csv_limited(&blob, budget);
        let elapsed = start.elapsed();
        assert!(
            matches!(result, Err(ColumnarError::TooLarge(_))),
            "a column count above the budget's column ceiling must be TooLarge, got {result:?}"
        );
        assert!(
            elapsed.as_secs() < 5,
            "column-cap rejection must be prompt (before any outer-array alloc), took {elapsed:?}"
        );
    }

    /// `rmp` #595 (security re-audit F1): a CRC-valid single column whose dictionary header declares
    /// far more entries than the budget's pointer array can hold must be rejected as
    /// [`ColumnarError::TooLarge`] BEFORE `read_dict_header` reserves the `Vec<Vec<u8>>` — the fix
    /// charges the declared entry count against the shared budget up front, so an off-budget
    /// upload-sized dictionary reservation (the auditor's measured +365 MB RSS bypass) cannot happen.
    #[test]
    fn wide_dictionary_header_is_rejected_within_budget() {
        let blob = build_wide_dict_blob(1_000_000); // 1M empty entries ⇒ ~24 MB would-be pointer array
        assert!(
            blob.len() < 8 * 1024 * 1024,
            "the COMPRESSED wide-dict blob must stay small: {} bytes",
            blob.len()
        );
        let budget = 4096; // two+ orders of magnitude below the ~24 MB reservation
        let start = std::time::Instant::now();
        let result = gcol_to_csv_limited(&blob, budget);
        let elapsed = start.elapsed();
        assert!(
            matches!(result, Err(ColumnarError::TooLarge(_))),
            "a wide dictionary header must be TooLarge, got {result:?}"
        );
        assert!(
            elapsed.as_secs() < 5,
            "wide-dictionary rejection must be prompt (before the dict alloc), took {elapsed:?}"
        );
    }

    /// `rmp` #595 (security re-audit F1): the two new *wide* ceilings must not reject genuinely wide
    /// but small blobs — a 100-column header-only blob and a 1000-entry dictionary both decode fine
    /// under a generous budget, proving the caps reject purely on size, never on valid shape.
    #[test]
    fn wide_but_valid_blob_and_dictionary_decode_under_budget() {
        let wide = build_wide_empty_blob(100);
        let csv =
            gcol_to_csv_limited(&wide, 16 * 1024 * 1024).expect("100 empty columns are valid");
        assert_eq!(
            csv.iter().filter(|&&b| b == b',').count(),
            99,
            "100 header cells ⇒ 99 delimiters, got: {csv:?}"
        );
        let dict = build_wide_dict_blob(1000);
        assert!(
            gcol_to_csv_limited(&dict, 16 * 1024 * 1024).is_ok(),
            "a 1000-entry dictionary is valid and well under budget"
        );
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
