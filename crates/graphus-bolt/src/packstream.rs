//! PackStream **v1** codec — the single place that turns a [`graphus_core::Value`] into Bolt wire
//! bytes and back (`04-technical-design.md` §8.1; `06-bolt-and-error-shapes.md` §1, §3.1).
//!
//! PackStream is the binary serialization Bolt rides on. It is **big-endian** throughout and uses
//! the **smallest marker that fits** a value (`04 §8.1`; verified against the Neo4j PackStream
//! specification, 2026-06). This module implements every marker class §8.1 names:
//!
//! - `null`, `boolean`, `integer` (1/2/4/8-byte int markers plus the `-16..=127` tiny range),
//!   `float64`, UTF-8 `string` (tiny / 8 / 16 / 32), `bytes` (8 / 16 / 32), `list`
//!   (tiny / 8 / 16 / 32) and `dictionary` (tiny / 8 / 16 / 32);
//! - the **structure** primitive ([`Structure`]) — a tag byte plus up to 15 fields — on which the
//!   tagged composite types (`Node`, `Relationship`, `Path`, the temporals) and **every Bolt
//!   message** ([`crate::message`]) are built.
//!
//! ## Two layers
//!
//! - [`Packer`] / [`Unpacker`] are the low-level cursor primitives: they read and write individual
//!   PackStream items (markers, ints, strings, list/map/struct *headers*). Messages
//!   ([`crate::message`]) drive these directly because a message is a structure whose field count
//!   and tag are known statically.
//! - [`pack_value`] / [`unpack_value`] are the high-level [`Value`] (de)serializers built on top,
//!   used for `RUN` parameters and `RECORD` values.
//!
//! ## The `Value` ↔ PackStream mapping
//!
//! `04 §7.2` states the `Value` enum maps one-to-one onto PackStream. The scalar, string, bytes,
//! list, map and temporal variants map directly. The **structural** classes (`Node`,
//! `Relationship`, `Path`, `Point`) are still **deferred in `graphus_core::Value`** (the enum
//! comments mark them as added with their owning subsystems), so this codec cannot yet *decode* a
//! wire `Node` into a `Value` variant that does not exist. The structure *encoders* are nonetheless
//! provided ([`Structure`] + the [`tag`] bytes) because the Bolt server emits them for `RECORD`
//! values from the entity ids/labels/properties the executor exposes (`04 §8.3`); see
//! [`crate::message`] and the executor seam ([`crate::executor`]) for where that happens, and the
//! `Value::Node`-deferred note there.
//!
//! ## Temporal encoding (Bolt 5.0+)
//!
//! The temporal structures use the **Bolt 5.0+** definitions (we pin 5.4, `06 §1`): `DateTime`
//! (tag `0x49`) and `DateTimeZoneId` (tag `0x69`) carry **UTC** epoch seconds (not local seconds —
//! that was the pre-5.0 layout). [`Date`] is *days* since the epoch, [`LocalTime`] / `Time` are
//! nanoseconds-of-day, and [`Duration`] is `(months, days, seconds, nanos)`.

use graphus_core::Value;
use graphus_core::value::temporal::{
    Date, Duration, LocalDateTime, LocalTime, ZonedDateTime, ZonedTime,
};

use crate::error::{BoltError, BoltResult};

// ---- Marker bytes (PackStream v1, big-endian) ------------------------------------------------
//
// Source: Neo4j PackStream specification (verified 2026-06); the byte values are the contract
// `04 §8.1` references. Grouped by class so the codec reads as a direct transcription of the spec.

pub(crate) const NULL: u8 = 0xC0;
pub(crate) const FALSE: u8 = 0xC2;
pub(crate) const TRUE: u8 = 0xC3;

pub(crate) const FLOAT_64: u8 = 0xC1;

pub(crate) const INT_8: u8 = 0xC8;
pub(crate) const INT_16: u8 = 0xC9;
pub(crate) const INT_32: u8 = 0xCA;
pub(crate) const INT_64: u8 = 0xCB;

/// Tiny ints occupy `0xF0..=0xFF` (`-16..=-1`) and `0x00..=0x7F` (`0..=127`): a single byte is the
/// value itself, read as `i8`. Inclusive value range `-16..=127`.
pub(crate) const TINY_INT_MIN: i64 = -16;
pub(crate) const TINY_INT_MAX: i64 = 127;

pub(crate) const TINY_STRING_BASE: u8 = 0x80; // 0x80..=0x8F: 0..=15 bytes
pub(crate) const STRING_8: u8 = 0xD0;
pub(crate) const STRING_16: u8 = 0xD1;
pub(crate) const STRING_32: u8 = 0xD2;

pub(crate) const BYTES_8: u8 = 0xCC;
pub(crate) const BYTES_16: u8 = 0xCD;
pub(crate) const BYTES_32: u8 = 0xCE;

pub(crate) const TINY_LIST_BASE: u8 = 0x90; // 0x90..=0x9F
pub(crate) const LIST_8: u8 = 0xD4;
pub(crate) const LIST_16: u8 = 0xD5;
pub(crate) const LIST_32: u8 = 0xD6;

pub(crate) const TINY_MAP_BASE: u8 = 0xA0; // 0xA0..=0xAF
pub(crate) const MAP_8: u8 = 0xD8;
pub(crate) const MAP_16: u8 = 0xD9;
pub(crate) const MAP_32: u8 = 0xDA;

pub(crate) const TINY_STRUCT_BASE: u8 = 0xB0; // 0xB0..=0xBF: 0..=15 fields

/// The largest collection (string/bytes/list/map) length PackStream's 32-bit size field can carry,
/// and the most fields a structure (tiny-struct only) may hold.
const MAX_U32_LEN: usize = u32::MAX as usize;
/// A structure has at most 15 fields (the tiny-struct nibble); Bolt never exceeds this.
pub(crate) const MAX_STRUCT_FIELDS: usize = 15;

// ---- Structure tag bytes (Bolt 5.x; `04 §8.1`, verified 2026-06) -----------------------------

/// PackStream structure tag bytes for the tagged composite [`Value`] classes and the Bolt graph
/// types (`04 §8.1`). Message tags live in [`crate::message`].
pub mod tag {
    /// `Node` — fields: id, labels, properties, element_id (element_id added in 5.0).
    pub const NODE: u8 = 0x4E;
    /// `Relationship` — id, start, end, type, properties, element_id, start_element_id,
    /// end_element_id.
    pub const RELATIONSHIP: u8 = 0x52;
    /// `UnboundRelationship` — id, type, properties, element_id.
    pub const UNBOUND_RELATIONSHIP: u8 = 0x72;
    /// `Path` — nodes, rels, indices.
    pub const PATH: u8 = 0x50;

    /// `Date` — days since the Unix epoch.
    pub const DATE: u8 = 0x44;
    /// `Time` — nanoseconds-of-day, tz offset seconds.
    pub const TIME: u8 = 0x54;
    /// `LocalTime` — nanoseconds-of-day.
    pub const LOCAL_TIME: u8 = 0x74;
    /// `DateTime` (5.0+) — UTC epoch seconds, nanoseconds, tz offset seconds.
    pub const DATE_TIME: u8 = 0x49;
    /// `DateTimeZoneId` (5.0+) — UTC epoch seconds, nanoseconds, IANA zone id.
    pub const DATE_TIME_ZONE_ID: u8 = 0x69;
    /// `LocalDateTime` — epoch seconds, nanoseconds.
    pub const LOCAL_DATE_TIME: u8 = 0x64;
    /// `Duration` — months, days, seconds, nanoseconds.
    pub const DURATION: u8 = 0x45;
}

// ---- A decoded structure ---------------------------------------------------------------------

/// A decoded PackStream structure: a tag byte plus its fields as [`Value`]s.
///
/// This is the shape every Bolt message and every tagged value (`Node`, temporals, …) takes on the
/// wire. [`crate::message`] decodes a message by reading a structure header and matching on the
/// tag; for tagged *values* the fields land here as `Value`s.
#[derive(Debug, Clone, PartialEq)]
pub struct Structure {
    /// The signature/tag byte (e.g. [`tag::NODE`] or a message opcode).
    pub tag: u8,
    /// The structure's fields, in order.
    pub fields: Vec<Value>,
}

impl Structure {
    /// Constructs a structure from a tag and its fields.
    #[must_use]
    pub fn new(tag: u8, fields: Vec<Value>) -> Self {
        Self { tag, fields }
    }
}

// ---- Packer: writes PackStream items into a growing buffer -----------------------------------

/// A cursor that appends PackStream-encoded items to an owned byte buffer.
///
/// All writes are infallible (a `Vec` grows) except [`Packer::write_struct_header`], which rejects
/// a field count above 15 (PackStream has no non-tiny structure marker; Bolt never needs one).
#[derive(Debug, Default)]
pub struct Packer {
    buf: Vec<u8>,
}

impl Packer {
    /// A new empty packer.
    #[must_use]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// A new packer with `cap` bytes reserved.
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    /// Consumes the packer, returning the encoded bytes.
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }

    /// Borrows the encoded bytes so far.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Writes the `null` marker.
    pub fn write_null(&mut self) {
        self.buf.push(NULL);
    }

    /// Writes a boolean (`true` → `0xC3`, `false` → `0xC2`).
    pub fn write_bool(&mut self, b: bool) {
        self.buf.push(if b { TRUE } else { FALSE });
    }

    /// Writes a signed integer using the smallest of the tiny / 8 / 16 / 32 / 64-bit markers.
    pub fn write_int(&mut self, n: i64) {
        if (TINY_INT_MIN..=TINY_INT_MAX).contains(&n) {
            // Tiny int: the byte is the value as i8 (negatives land in 0xF0..=0xFF).
            #[expect(clippy::cast_possible_truncation, reason = "range-checked to fit i8")]
            self.buf.push(n as i8 as u8);
        } else if let Ok(v) = i8::try_from(n) {
            self.buf.push(INT_8);
            self.buf.push(v as u8);
        } else if let Ok(v) = i16::try_from(n) {
            self.buf.push(INT_16);
            self.buf.extend_from_slice(&v.to_be_bytes());
        } else if let Ok(v) = i32::try_from(n) {
            self.buf.push(INT_32);
            self.buf.extend_from_slice(&v.to_be_bytes());
        } else {
            self.buf.push(INT_64);
            self.buf.extend_from_slice(&n.to_be_bytes());
        }
    }

    /// Writes an IEEE-754 float64 (`0xC1` + 8 big-endian bytes).
    pub fn write_float(&mut self, f: f64) {
        self.buf.push(FLOAT_64);
        self.buf.extend_from_slice(&f.to_be_bytes());
    }

    /// Writes a UTF-8 string with the smallest tiny / 8 / 16 / 32 marker.
    pub fn write_string(&mut self, s: &str) {
        self.write_collection_header(TINY_STRING_BASE, STRING_8, STRING_16, STRING_32, s.len());
        self.buf.extend_from_slice(s.as_bytes());
    }

    /// Writes a byte string with the smallest 8 / 16 / 32 marker (bytes have no tiny form).
    pub fn write_bytes(&mut self, b: &[u8]) {
        let len = b.len();
        if let Ok(n) = u8::try_from(len) {
            self.buf.push(BYTES_8);
            self.buf.push(n);
        } else if let Ok(n) = u16::try_from(len) {
            self.buf.push(BYTES_16);
            self.buf.extend_from_slice(&n.to_be_bytes());
        } else {
            // PackStream caps bytes at u32; values longer never occur from a `Value::Bytes` that
            // round-trips, but truncating the length silently would corrupt the stream, so clamp at
            // the codec's documented limit by writing the 32-bit header.
            #[expect(clippy::cast_possible_truncation, reason = "documented u32 length cap")]
            let n = len.min(MAX_U32_LEN) as u32;
            self.buf.push(BYTES_32);
            self.buf.extend_from_slice(&n.to_be_bytes());
        }
        self.buf.extend_from_slice(b);
    }

    /// Writes a **list header** (marker + element count); the caller then writes that many items.
    pub fn write_list_header(&mut self, count: usize) {
        self.write_collection_header(TINY_LIST_BASE, LIST_8, LIST_16, LIST_32, count);
    }

    /// Writes a **map/dictionary header** (marker + entry count); the caller then writes that many
    /// `key, value` pairs (key first, as a string).
    pub fn write_map_header(&mut self, count: usize) {
        self.write_collection_header(TINY_MAP_BASE, MAP_8, MAP_16, MAP_32, count);
    }

    /// Writes a **structure header** (tiny-struct marker carrying the field count + the tag byte).
    ///
    /// # Errors
    /// [`BoltError::Encode`] if `field_count` exceeds 15 (PackStream has no larger structure
    /// marker; no Bolt structure needs more).
    pub fn write_struct_header(&mut self, tag: u8, field_count: usize) -> BoltResult<()> {
        if field_count > MAX_STRUCT_FIELDS {
            return Err(BoltError::Encode(format!(
                "structure has {field_count} fields, PackStream allows at most {MAX_STRUCT_FIELDS}"
            )));
        }
        #[expect(clippy::cast_possible_truncation, reason = "checked <= 15 above")]
        self.buf.push(TINY_STRUCT_BASE + field_count as u8);
        self.buf.push(tag);
        Ok(())
    }

    /// Shared length-header writer for the string / list / map families, which share the
    /// tiny(0..=15) / 8 / 16 / 32 marker shape and differ only in their base marker bytes.
    fn write_collection_header(&mut self, tiny_base: u8, m8: u8, m16: u8, m32: u8, len: usize) {
        if len <= 15 {
            #[expect(clippy::cast_possible_truncation, reason = "checked <= 15 above")]
            self.buf.push(tiny_base + len as u8);
        } else if let Ok(n) = u8::try_from(len) {
            self.buf.push(m8);
            self.buf.push(n);
        } else if let Ok(n) = u16::try_from(len) {
            self.buf.push(m16);
            self.buf.extend_from_slice(&n.to_be_bytes());
        } else {
            #[expect(clippy::cast_possible_truncation, reason = "documented u32 length cap")]
            let n = len.min(MAX_U32_LEN) as u32;
            self.buf.push(m32);
            self.buf.extend_from_slice(&n.to_be_bytes());
        }
    }
}

// ---- Unpacker: reads PackStream items from a byte slice ---------------------------------------

/// A header read for one of the variable-length collection classes (string / list / map): its
/// element/byte count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CollectionLen(usize);

/// A cursor that reads PackStream items out of a borrowed byte slice.
///
/// Every read is bounds- and marker-checked: a malformed or truncated stream yields a
/// [`BoltError::Decode`] rather than a panic (`#![forbid(unsafe_code)]`; the codec is a trusted
/// boundary and never trusts its input).
#[derive(Debug)]
pub struct Unpacker<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Unpacker<'a> {
    /// A new unpacker over `buf`, positioned at the start.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Whether the whole input has been consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Reads one raw byte, advancing the cursor.
    fn read_u8(&mut self) -> BoltResult<u8> {
        let b = *self
            .buf
            .get(self.pos)
            .ok_or_else(|| BoltError::Decode("unexpected end of PackStream input".to_owned()))?;
        self.pos += 1;
        Ok(b)
    }

    /// Reads `n` raw bytes as a borrowed slice, advancing the cursor.
    fn read_slice(&mut self, n: usize) -> BoltResult<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(|| {
            BoltError::Decode("PackStream length overflows the address space".to_owned())
        })?;
        let s = self
            .buf
            .get(self.pos..end)
            .ok_or_else(|| BoltError::Decode("PackStream item truncated".to_owned()))?;
        self.pos = end;
        Ok(s)
    }

    /// Reads a fixed-width big-endian unsigned size field of `width` bytes (1/2/4) into a `usize`.
    fn read_be_len(&mut self, width: usize) -> BoltResult<usize> {
        let bytes = self.read_slice(width)?;
        let mut acc: usize = 0;
        for &b in bytes {
            acc = (acc << 8) | usize::from(b);
        }
        Ok(acc)
    }

    /// Peeks at the next marker byte without consuming it.
    #[must_use]
    pub fn peek_marker(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    /// Reads a signed integer (tiny / 8 / 16 / 32 / 64-bit).
    ///
    /// # Errors
    /// [`BoltError::Decode`] if the next marker is not an integer marker or the stream is truncated.
    pub fn read_int(&mut self) -> BoltResult<i64> {
        let m = self.read_u8()?;
        match m {
            INT_8 => Ok(i64::from(self.read_u8()? as i8)),
            INT_16 => {
                let s = self.read_slice(2)?;
                Ok(i64::from(i16::from_be_bytes([s[0], s[1]])))
            }
            INT_32 => {
                let s = self.read_slice(4)?;
                Ok(i64::from(i32::from_be_bytes([s[0], s[1], s[2], s[3]])))
            }
            INT_64 => {
                let s = self.read_slice(8)?;
                let mut a = [0u8; 8];
                a.copy_from_slice(s);
                Ok(i64::from_be_bytes(a))
            }
            // Tiny int: the marker *is* the value (read as i8 so 0xF0..=0xFF are -16..=-1).
            _ if is_tiny_int(m) => Ok(i64::from(m as i8)),
            other => Err(BoltError::Decode(format!(
                "expected an integer marker, found {other:#04x}"
            ))),
        }
    }

    /// Reads a UTF-8 string.
    ///
    /// # Errors
    /// [`BoltError::Decode`] if the marker is not a string marker, the stream is truncated, or the
    /// bytes are not valid UTF-8.
    pub fn read_string(&mut self) -> BoltResult<String> {
        let len = self.read_string_header()?.0;
        let bytes = self.read_slice(len)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| BoltError::Decode("PackStream string is not valid UTF-8".to_owned()))
    }

    /// Reads a string *header*, returning its byte length (the caller reads the bytes).
    fn read_string_header(&mut self) -> BoltResult<CollectionLen> {
        let m = self.read_u8()?;
        match m {
            _ if (TINY_STRING_BASE..=TINY_STRING_BASE + 0x0F).contains(&m) => {
                Ok(CollectionLen(usize::from(m - TINY_STRING_BASE)))
            }
            STRING_8 => Ok(CollectionLen(self.read_be_len(1)?)),
            STRING_16 => Ok(CollectionLen(self.read_be_len(2)?)),
            STRING_32 => Ok(CollectionLen(self.read_be_len(4)?)),
            other => Err(BoltError::Decode(format!(
                "expected a string marker, found {other:#04x}"
            ))),
        }
    }

    /// Reads a **list header**, returning the element count.
    ///
    /// # Errors
    /// [`BoltError::Decode`] if the marker is not a list marker.
    pub fn read_list_header(&mut self) -> BoltResult<usize> {
        let m = self.read_u8()?;
        match m {
            _ if (TINY_LIST_BASE..=TINY_LIST_BASE + 0x0F).contains(&m) => {
                Ok(usize::from(m - TINY_LIST_BASE))
            }
            LIST_8 => self.read_be_len(1),
            LIST_16 => self.read_be_len(2),
            LIST_32 => self.read_be_len(4),
            other => Err(BoltError::Decode(format!(
                "expected a list marker, found {other:#04x}"
            ))),
        }
    }

    /// Reads a **map header**, returning the entry count (the caller reads that many `key, value`
    /// pairs).
    ///
    /// # Errors
    /// [`BoltError::Decode`] if the marker is not a map marker.
    pub fn read_map_header(&mut self) -> BoltResult<usize> {
        let m = self.read_u8()?;
        match m {
            _ if (TINY_MAP_BASE..=TINY_MAP_BASE + 0x0F).contains(&m) => {
                Ok(usize::from(m - TINY_MAP_BASE))
            }
            MAP_8 => self.read_be_len(1),
            MAP_16 => self.read_be_len(2),
            MAP_32 => self.read_be_len(4),
            other => Err(BoltError::Decode(format!(
                "expected a map marker, found {other:#04x}"
            ))),
        }
    }

    /// Reads a **structure header**, returning `(tag, field_count)`. The caller reads the fields.
    ///
    /// # Errors
    /// [`BoltError::Decode`] if the marker is not a tiny-struct marker or the tag is missing.
    pub fn read_struct_header(&mut self) -> BoltResult<(u8, usize)> {
        let m = self.read_u8()?;
        if (TINY_STRUCT_BASE..=TINY_STRUCT_BASE + 0x0F).contains(&m) {
            let field_count = usize::from(m - TINY_STRUCT_BASE);
            let tag = self.read_u8()?;
            Ok((tag, field_count))
        } else {
            Err(BoltError::Decode(format!(
                "expected a structure marker, found {m:#04x}"
            )))
        }
    }
}

/// Whether `m` is a tiny-int marker byte (`0x00..=0x7F` non-negative, `0xF0..=0xFF` negative).
#[inline]
fn is_tiny_int(m: u8) -> bool {
    m <= 0x7F || m >= 0xF0
}

// ---- High-level Value (de)serialization -------------------------------------------------------

/// Encodes a [`Value`] as PackStream into `packer`.
///
/// Every variant `graphus_core::Value` currently has is handled. The structural classes (`Node`,
/// `Relationship`, `Path`, `Point`) are **not** `Value` variants yet (`04 §7.2` defers them), so
/// they cannot reach this function; the server constructs those structures directly from executor
/// data via [`Packer::write_struct_header`] (see [`crate::message`]).
pub fn pack_value(packer: &mut Packer, value: &Value) {
    match value {
        Value::Null => packer.write_null(),
        Value::Boolean(b) => packer.write_bool(*b),
        Value::Integer(n) => packer.write_int(*n),
        Value::Float(f) => packer.write_float(*f),
        Value::String(s) => packer.write_string(s),
        Value::Bytes(b) => packer.write_bytes(b),
        Value::List(items) => {
            packer.write_list_header(items.len());
            for item in items {
                pack_value(packer, item);
            }
        }
        Value::Map(entries) => {
            packer.write_map_header(entries.len());
            for (k, v) in entries {
                packer.write_string(k);
                pack_value(packer, v);
            }
        }
        Value::Date(d) => pack_date(packer, *d),
        Value::LocalTime(t) => pack_local_time(packer, *t),
        Value::ZonedTime(t) => pack_time(packer, *t),
        Value::LocalDateTime(dt) => pack_local_date_time(packer, *dt),
        Value::ZonedDateTime(dt) => pack_zoned_date_time(packer, dt),
        Value::Duration(d) => pack_duration(packer, *d),
        // This match is intentionally **exhaustive** over `graphus_core::Value`. When a new variant
        // is added there (the deferred structural `Node`/`Relationship`/`Path`/`Point`, `04 §7.2`),
        // this becomes a compile error here — forcing its PackStream encoding to be written rather
        // than silently dropped. That compile-time enforcement is stronger than a runtime guard.
    }
}

/// Decodes one [`Value`] from `unpacker`.
///
/// # Errors
/// [`BoltError::Decode`] on a truncated stream, an unknown marker, or a structure tag whose target
/// `Value` variant does not yet exist (`Node`/`Relationship`/`Path`/`Point` are deferred in
/// `graphus_core::Value`, `04 §7.2`) — decoding such a wire structure into a `Value` is not yet
/// possible and is reported rather than guessed.
pub fn unpack_value(unpacker: &mut Unpacker<'_>) -> BoltResult<Value> {
    let marker = unpacker
        .peek_marker()
        .ok_or_else(|| BoltError::Decode("unexpected end of PackStream input".to_owned()))?;

    match marker {
        NULL => {
            let _ = unpacker.read_u8()?;
            Ok(Value::Null)
        }
        TRUE => {
            let _ = unpacker.read_u8()?;
            Ok(Value::Boolean(true))
        }
        FALSE => {
            let _ = unpacker.read_u8()?;
            Ok(Value::Boolean(false))
        }
        FLOAT_64 => {
            let _ = unpacker.read_u8()?;
            let s = unpacker.read_slice(8)?;
            let mut a = [0u8; 8];
            a.copy_from_slice(s);
            Ok(Value::Float(f64::from_be_bytes(a)))
        }
        INT_8 | INT_16 | INT_32 | INT_64 => Ok(Value::Integer(unpacker.read_int()?)),
        _ if is_tiny_int(marker) => Ok(Value::Integer(unpacker.read_int()?)),
        BYTES_8 | BYTES_16 | BYTES_32 => unpack_bytes(unpacker),
        _ if is_string_marker(marker) => Ok(Value::String(unpacker.read_string()?)),
        _ if is_list_marker(marker) => {
            let n = unpacker.read_list_header()?;
            let mut items = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                items.push(unpack_value(unpacker)?);
            }
            Ok(Value::List(items))
        }
        _ if is_map_marker(marker) => {
            let n = unpacker.read_map_header()?;
            let mut entries = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                let k = unpacker.read_string()?;
                let v = unpack_value(unpacker)?;
                entries.push((k, v));
            }
            Ok(Value::Map(entries))
        }
        _ if is_struct_marker(marker) => unpack_structured_value(unpacker),
        other => Err(BoltError::Decode(format!(
            "unknown PackStream marker {other:#04x}"
        ))),
    }
}

/// Decodes a tagged structure into the matching temporal [`Value`]. The graph structural tags
/// (`Node`/`Relationship`/`Path`) have no `Value` variant yet and are rejected with a clear error.
fn unpack_structured_value(unpacker: &mut Unpacker<'_>) -> BoltResult<Value> {
    let (t, field_count) = unpacker.read_struct_header()?;
    match t {
        tag::DATE => {
            expect_fields(t, field_count, 1)?;
            let days = unpacker.read_int()?;
            let days = i32::try_from(days)
                .map_err(|_| BoltError::Decode("Date.days out of i32 range".to_owned()))?;
            Ok(Value::Date(Date {
                days_since_epoch: days,
            }))
        }
        tag::LOCAL_TIME => {
            expect_fields(t, field_count, 1)?;
            let nanos = read_u64_field(unpacker, "LocalTime.nanoseconds")?;
            Ok(Value::LocalTime(LocalTime {
                nanos_of_day: nanos,
            }))
        }
        tag::TIME => {
            expect_fields(t, field_count, 2)?;
            let nanos = read_u64_field(unpacker, "Time.nanoseconds")?;
            let offset = read_i32_field(unpacker, "Time.tz_offset_seconds")?;
            Ok(Value::ZonedTime(ZonedTime {
                time: LocalTime {
                    nanos_of_day: nanos,
                },
                offset_seconds: offset,
            }))
        }
        tag::LOCAL_DATE_TIME => {
            expect_fields(t, field_count, 2)?;
            let secs = unpacker.read_int()?;
            let nanos = read_u32_field(unpacker, "LocalDateTime.nanoseconds")?;
            Ok(Value::LocalDateTime(LocalDateTime {
                epoch_seconds: secs,
                nanos,
            }))
        }
        tag::DATE_TIME => {
            expect_fields(t, field_count, 3)?;
            // Bolt 5.0+ DateTime carries UTC epoch seconds; reconstruct the stored local instant by
            // re-applying the offset so the round-trip preserves `ZonedDateTime.local`.
            let utc_secs = unpacker.read_int()?;
            let nanos = read_u32_field(unpacker, "DateTime.nanoseconds")?;
            let offset = read_i32_field(unpacker, "DateTime.tz_offset_seconds")?;
            Ok(Value::ZonedDateTime(zoned_from_utc(
                utc_secs,
                nanos,
                offset,
                String::new(),
            )))
        }
        tag::DATE_TIME_ZONE_ID => {
            expect_fields(t, field_count, 3)?;
            let utc_secs = unpacker.read_int()?;
            let nanos = read_u32_field(unpacker, "DateTimeZoneId.nanoseconds")?;
            let zone_id = unpacker.read_string()?;
            // A zone-id DateTime carries no numeric offset on the wire; the offset is whatever the
            // zone resolves to. We preserve the UTC instant and the zone id, leaving the resolved
            // offset at 0 (offset resolution from an IANA id is the engine's job, not the codec's).
            Ok(Value::ZonedDateTime(zoned_from_utc(
                utc_secs, nanos, 0, zone_id,
            )))
        }
        tag::DURATION => {
            expect_fields(t, field_count, 4)?;
            let months = unpacker.read_int()?;
            let days = unpacker.read_int()?;
            let seconds = unpacker.read_int()?;
            let nanos = read_i32_field(unpacker, "Duration.nanoseconds")?;
            Ok(Value::Duration(Duration {
                months,
                days,
                seconds,
                nanos,
            }))
        }
        tag::NODE | tag::RELATIONSHIP | tag::UNBOUND_RELATIONSHIP | tag::PATH => {
            Err(BoltError::Decode(format!(
                "structure tag {t:#04x} (graph entity) has no `graphus_core::Value` variant yet \
                 (deferred per 04 §7.2); cannot decode into a Value"
            )))
        }
        other => Err(BoltError::Decode(format!(
            "unknown PackStream structure tag {other:#04x}"
        ))),
    }
}

/// Reconstructs a [`ZonedDateTime`] (whose `local` field stores the *local* instant) from the
/// Bolt-5.0+ UTC epoch seconds by re-applying the offset (`local = utc + offset`).
fn zoned_from_utc(
    utc_secs: i64,
    nanos: u32,
    offset_seconds: i32,
    zone_id: String,
) -> ZonedDateTime {
    let local_secs = utc_secs.saturating_add(i64::from(offset_seconds));
    ZonedDateTime {
        local: LocalDateTime {
            epoch_seconds: local_secs,
            nanos,
        },
        offset_seconds,
        zone_id,
    }
}

fn unpack_bytes(unpacker: &mut Unpacker<'_>) -> BoltResult<Value> {
    let m = unpacker.read_u8()?;
    let len = match m {
        BYTES_8 => unpacker.read_be_len(1)?,
        BYTES_16 => unpacker.read_be_len(2)?,
        BYTES_32 => unpacker.read_be_len(4)?,
        other => {
            return Err(BoltError::Decode(format!(
                "expected a bytes marker, found {other:#04x}"
            )));
        }
    };
    Ok(Value::Bytes(unpacker.read_slice(len)?.to_vec()))
}

// ---- Temporal encoders ------------------------------------------------------------------------

fn pack_date(packer: &mut Packer, d: Date) {
    // Infallible: 1 field <= 15. `expect` documents the invariant per the API guidelines.
    packer
        .write_struct_header(tag::DATE, 1)
        .expect("INVARIANT: Date has 1 field");
    packer.write_int(i64::from(d.days_since_epoch));
}

fn pack_local_time(packer: &mut Packer, t: LocalTime) {
    packer
        .write_struct_header(tag::LOCAL_TIME, 1)
        .expect("INVARIANT: LocalTime has 1 field");
    packer.write_int(i64_from_u64_saturating(t.nanos_of_day));
}

fn pack_time(packer: &mut Packer, t: ZonedTime) {
    packer
        .write_struct_header(tag::TIME, 2)
        .expect("INVARIANT: Time has 2 fields");
    packer.write_int(i64_from_u64_saturating(t.time.nanos_of_day));
    packer.write_int(i64::from(t.offset_seconds));
}

fn pack_local_date_time(packer: &mut Packer, dt: LocalDateTime) {
    packer
        .write_struct_header(tag::LOCAL_DATE_TIME, 2)
        .expect("INVARIANT: LocalDateTime has 2 fields");
    packer.write_int(dt.epoch_seconds);
    packer.write_int(i64::from(dt.nanos));
}

fn pack_zoned_date_time(packer: &mut Packer, dt: &ZonedDateTime) {
    // Bolt 5.0+: emit UTC epoch seconds (`utc = local - offset`). A non-empty IANA zone id selects
    // the `DateTimeZoneId` form (tag 0x69); otherwise the offset form `DateTime` (tag 0x49).
    let utc_secs = dt
        .local
        .epoch_seconds
        .saturating_sub(i64::from(dt.offset_seconds));
    if dt.zone_id.is_empty() {
        packer
            .write_struct_header(tag::DATE_TIME, 3)
            .expect("INVARIANT: DateTime has 3 fields");
        packer.write_int(utc_secs);
        packer.write_int(i64::from(dt.local.nanos));
        packer.write_int(i64::from(dt.offset_seconds));
    } else {
        packer
            .write_struct_header(tag::DATE_TIME_ZONE_ID, 3)
            .expect("INVARIANT: DateTimeZoneId has 3 fields");
        packer.write_int(utc_secs);
        packer.write_int(i64::from(dt.local.nanos));
        packer.write_string(&dt.zone_id);
    }
}

fn pack_duration(packer: &mut Packer, d: Duration) {
    packer
        .write_struct_header(tag::DURATION, 4)
        .expect("INVARIANT: Duration has 4 fields");
    packer.write_int(d.months);
    packer.write_int(d.days);
    packer.write_int(d.seconds);
    packer.write_int(i64::from(d.nanos));
}

// ---- Small typed-field readers ---------------------------------------------------------------

fn expect_fields(tag: u8, got: usize, want: usize) -> BoltResult<()> {
    if got == want {
        Ok(())
    } else {
        Err(BoltError::Decode(format!(
            "structure {tag:#04x} expected {want} fields, found {got}"
        )))
    }
}

fn read_u64_field(unpacker: &mut Unpacker<'_>, what: &str) -> BoltResult<u64> {
    let n = unpacker.read_int()?;
    u64::try_from(n).map_err(|_| BoltError::Decode(format!("{what} is negative")))
}

fn read_u32_field(unpacker: &mut Unpacker<'_>, what: &str) -> BoltResult<u32> {
    let n = unpacker.read_int()?;
    u32::try_from(n).map_err(|_| BoltError::Decode(format!("{what} out of u32 range")))
}

fn read_i32_field(unpacker: &mut Unpacker<'_>, what: &str) -> BoltResult<i32> {
    let n = unpacker.read_int()?;
    i32::try_from(n).map_err(|_| BoltError::Decode(format!("{what} out of i32 range")))
}

/// Saturating `u64 -> i64` for nanosecond-of-day fields (always `< NANOS_PER_DAY`, well within
/// `i64`, but a defensive clamp keeps a corrupt value from wrapping negative on the wire).
fn i64_from_u64_saturating(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

fn is_string_marker(m: u8) -> bool {
    (TINY_STRING_BASE..=TINY_STRING_BASE + 0x0F).contains(&m)
        || matches!(m, STRING_8 | STRING_16 | STRING_32)
}

fn is_list_marker(m: u8) -> bool {
    (TINY_LIST_BASE..=TINY_LIST_BASE + 0x0F).contains(&m) || matches!(m, LIST_8 | LIST_16 | LIST_32)
}

fn is_map_marker(m: u8) -> bool {
    (TINY_MAP_BASE..=TINY_MAP_BASE + 0x0F).contains(&m) || matches!(m, MAP_8 | MAP_16 | MAP_32)
}

fn is_struct_marker(m: u8) -> bool {
    (TINY_STRUCT_BASE..=TINY_STRUCT_BASE + 0x0F).contains(&m)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trips a single `Value` through `pack_value`/`unpack_value`.
    fn round_trip(v: &Value) -> Value {
        let mut p = Packer::new();
        pack_value(&mut p, v);
        let bytes = p.into_inner();
        let mut u = Unpacker::new(&bytes);
        let out = unpack_value(&mut u).expect("decode");
        assert!(u.is_empty(), "decode left {} trailing bytes", u.remaining());
        out
    }

    #[test]
    fn null_and_bool_markers() {
        let mut p = Packer::new();
        p.write_null();
        p.write_bool(true);
        p.write_bool(false);
        assert_eq!(p.as_bytes(), &[NULL, TRUE, FALSE]);
    }

    #[test]
    fn integer_marker_boundaries() {
        // The exact marker chosen at each boundary is part of the wire contract.
        let cases: &[(i64, &[u8])] = &[
            (0, &[0x00]),
            (127, &[0x7F]),
            (-16, &[0xF0]),
            (-1, &[0xFF]),
            // 128 does not fit i8 (max 127), so it steps up to INT_16.
            (128, &[INT_16, 0x00, 0x80]),
            (-17, &[INT_8, 0xEF]),
            (-128, &[INT_8, 0x80]),
            (200, &[INT_16, 0x00, 0xC8]),
            (-200, &[INT_16, 0xFF, 0x38]),
            (32_767, &[INT_16, 0x7F, 0xFF]),
            (32_768, &[INT_32, 0x00, 0x00, 0x80, 0x00]),
            (
                2_147_483_648,
                &[INT_64, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00],
            ),
        ];
        for (n, expected) in cases {
            let mut p = Packer::new();
            p.write_int(*n);
            assert_eq!(p.as_bytes(), *expected, "encoding of {n}");
            assert_eq!(round_trip(&Value::Integer(*n)), Value::Integer(*n));
        }
    }

    #[test]
    fn integer_extremes_round_trip() {
        for n in [i64::MIN, i64::MAX, i64::MIN + 1, i64::MAX - 1] {
            assert_eq!(round_trip(&Value::Integer(n)), Value::Integer(n));
        }
    }

    #[test]
    fn float_round_trips_including_specials() {
        for f in [
            0.0_f64,
            -0.0,
            1.5,
            -2.25,
            f64::MIN,
            f64::MAX,
            f64::INFINITY,
            f64::NEG_INFINITY,
        ] {
            let out = round_trip(&Value::Float(f));
            match out {
                Value::Float(g) => assert_eq!(g.to_bits(), f.to_bits()),
                other => panic!("expected float, got {other:?}"),
            }
        }
        // NaN survives as a NaN bit pattern (PartialEq would say NaN != NaN, so compare bits).
        let out = round_trip(&Value::Float(f64::NAN));
        match out {
            Value::Float(g) => assert!(g.is_nan()),
            other => panic!("expected NaN float, got {other:?}"),
        }
    }

    #[test]
    fn string_marker_boundaries() {
        // tiny (<=15), 8-bit (16..=255), 16-bit (>=256).
        for len in [0usize, 1, 15, 16, 255, 256, 70_000] {
            let s = "a".repeat(len);
            assert_eq!(round_trip(&Value::String(s.clone())), Value::String(s));
        }
        // Marker selection at the tiny/8 boundary.
        let mut p = Packer::new();
        p.write_string("");
        assert_eq!(p.as_bytes(), &[TINY_STRING_BASE]);
        let mut p = Packer::new();
        p.write_string(&"x".repeat(16));
        assert_eq!(p.as_bytes()[0], STRING_8);
        assert_eq!(p.as_bytes()[1], 16);
    }

    #[test]
    fn unicode_string_round_trips() {
        let s = "héllo — 日本語 — 🦀".to_owned();
        assert_eq!(round_trip(&Value::String(s.clone())), Value::String(s));
    }

    #[test]
    fn bytes_marker_boundaries() {
        for len in [0usize, 1, 255, 256, 70_000] {
            let b = vec![0xABu8; len];
            assert_eq!(round_trip(&Value::Bytes(b.clone())), Value::Bytes(b));
        }
        let mut p = Packer::new();
        p.write_bytes(&[1, 2, 3]);
        assert_eq!(p.as_bytes(), &[BYTES_8, 3, 1, 2, 3]);
    }

    #[test]
    fn nested_list_and_map_round_trip() {
        let v = Value::List(vec![
            Value::Integer(1),
            Value::String("two".to_owned()),
            Value::List(vec![Value::Boolean(true), Value::Null]),
            Value::Map(vec![
                ("k".to_owned(), Value::Float(3.5)),
                ("nested".to_owned(), Value::List(vec![Value::Integer(-1)])),
            ]),
        ]);
        assert_eq!(round_trip(&v), v);
    }

    #[test]
    fn map_preserves_insertion_order() {
        let v = Value::Map(vec![
            ("z".to_owned(), Value::Integer(1)),
            ("a".to_owned(), Value::Integer(2)),
            ("m".to_owned(), Value::Integer(3)),
        ]);
        assert_eq!(round_trip(&v), v);
    }

    #[test]
    fn large_list_uses_16bit_marker() {
        let v = Value::List(vec![Value::Integer(0); 300]);
        let mut p = Packer::new();
        pack_value(&mut p, &v);
        assert_eq!(p.as_bytes()[0], LIST_16);
        assert_eq!(round_trip(&v), v);
    }

    #[test]
    fn all_temporal_values_round_trip() {
        let cases = [
            Value::Date(Date {
                days_since_epoch: -19_000,
            }),
            Value::Date(Date {
                days_since_epoch: 20_000,
            }),
            Value::LocalTime(LocalTime {
                nanos_of_day: 12_345_678_900,
            }),
            Value::ZonedTime(ZonedTime {
                time: LocalTime { nanos_of_day: 1 },
                offset_seconds: -3600,
            }),
            Value::LocalDateTime(LocalDateTime {
                epoch_seconds: 1_700_000_000,
                nanos: 123_456_789,
            }),
            Value::LocalDateTime(LocalDateTime {
                epoch_seconds: -1,
                nanos: 0,
            }),
            Value::ZonedDateTime(ZonedDateTime {
                local: LocalDateTime {
                    epoch_seconds: 1_700_000_000,
                    nanos: 500,
                },
                offset_seconds: 7200,
                zone_id: String::new(),
            }),
            Value::ZonedDateTime(ZonedDateTime {
                local: LocalDateTime {
                    epoch_seconds: 1_700_000_000,
                    nanos: 500,
                },
                offset_seconds: 0,
                zone_id: "Europe/Lisbon".to_owned(),
            }),
            Value::Duration(Duration {
                months: 14,
                days: -3,
                seconds: 90,
                nanos: 250,
            }),
        ];
        for v in cases {
            assert_eq!(round_trip(&v), v, "temporal round-trip for {v:?}");
        }
    }

    #[test]
    fn zoned_date_time_emits_utc_seconds_and_offset_tag() {
        // local = 2000s, offset = +500s  ⇒  utc = 1500s, tag DATE_TIME.
        let v = ZonedDateTime {
            local: LocalDateTime {
                epoch_seconds: 2000,
                nanos: 0,
            },
            offset_seconds: 500,
            zone_id: String::new(),
        };
        let mut p = Packer::new();
        pack_zoned_date_time(&mut p, &v);
        let bytes = p.into_inner();
        assert_eq!(bytes[0], TINY_STRUCT_BASE + 3);
        assert_eq!(bytes[1], tag::DATE_TIME);
        // Round-trip restores the local instant.
        let mut u = Unpacker::new(&bytes);
        assert_eq!(unpack_value(&mut u).unwrap(), Value::ZonedDateTime(v));
    }

    #[test]
    fn decode_rejects_deferred_graph_structure() {
        // A wire Node (tag 0x4E, 4 fields) cannot become a Value yet — must error, not guess.
        let mut p = Packer::new();
        p.write_struct_header(tag::NODE, 4).unwrap();
        p.write_int(1); // id
        p.write_list_header(0); // labels
        p.write_map_header(0); // properties
        p.write_string("e1"); // element_id
        let bytes = p.into_inner();
        let mut u = Unpacker::new(&bytes);
        let err = unpack_value(&mut u).unwrap_err();
        assert!(matches!(err, BoltError::Decode(_)));
    }

    #[test]
    fn decode_errors_on_truncation_and_bad_marker() {
        // Truncated int.
        let mut u = Unpacker::new(&[INT_32, 0x00, 0x01]);
        assert!(u.read_int().is_err());
        // Unknown marker.
        let mut u = Unpacker::new(&[0xC4]); // C4..C7 are reserved/unused in v1.
        assert!(unpack_value(&mut u).is_err());
        // Non-UTF-8 string body.
        let mut p = Packer::new();
        p.write_struct_header(tag::DATE, 1).unwrap(); // header so we exercise read paths
        let _ = p; // not used further; the UTF-8 case below is direct.
        let mut u = Unpacker::new(&[TINY_STRING_BASE + 1, 0xFF]);
        assert!(u.read_string().is_err());
    }

    #[test]
    fn struct_header_rejects_too_many_fields() {
        let mut p = Packer::new();
        assert!(matches!(
            p.write_struct_header(0x4E, 16),
            Err(BoltError::Encode(_))
        ));
    }
}
