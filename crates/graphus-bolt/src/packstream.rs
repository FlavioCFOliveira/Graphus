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
//! list, map, temporal and **spatial** (`Point2D`/`Point3D`, `rmp` task #73) variants map directly.
//! The **structural** classes (`Node`, `Relationship`, `Path`) are still **deferred in
//! `graphus_core::Value`** (the enum comments mark them as added with their owning subsystems), so
//! this codec cannot yet *decode* a wire `Node` into a `Value` variant that does not exist. The
//! structure *encoders* are nonetheless
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
use graphus_core::value::spatial::{Crs, Point};
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

/// The largest collection (string/bytes/list/map) length PackStream's 32-bit size field can carry.
///
/// # Spec maximum vs this lenient cap (`rmp` #397 — NOT yet ratified)
///
/// The PackStream specification states the maximum collection length is **`i32::MAX`**
/// (`2_147_483_647`): the `*_32` size header is read as a *signed* 32-bit big-endian integer, so a
/// strictly conformant decoder rejects any length above `i32::MAX`. Graphus deliberately uses the
/// **wider `u32::MAX`** here — a *lenient* choice that accepts the full unsigned 32-bit range. This is
/// safe by construction: a wire length never sizes an allocation directly (every collection
/// pre-allocates at most [`MAX_PREALLOC`] and grows as real elements are decoded, and each element
/// consumes ≥1 input byte), so an over-large header cannot exhaust memory — it simply fails at
/// end-of-input. Tightening this cap to `i32::MAX` is a behavioural change (it would start *rejecting*
/// inputs the decoder currently accepts), so it is **pending a ratified decision** and is intentionally
/// not changed here; the `collection_length_cap_current_behavior` test pins the present behaviour.
const MAX_U32_LEN: usize = u32::MAX as usize;
/// A structure has at most 15 fields (the tiny-struct nibble); Bolt never exceeds this.
pub(crate) const MAX_STRUCT_FIELDS: usize = 15;

/// Upper bound on the number of elements **pre-allocated** from a wire-supplied collection length,
/// before a single element has been read.
///
/// A PackStream `LIST_32`/`MAP_32`/`BYTES_32` header carries a 32-bit count, and a hostile or
/// compromised peer (or a MITM on a plaintext `bolt://` link) can set it to `0xFFFF_FFFF` while
/// sending only a few bytes of body. Sizing a `Vec` directly from that header would request
/// `count * size_of::<T>()` bytes — hundreds of GiB — and abort the process via
/// `alloc::handle_alloc_error` (CWE-789 / CWE-770). We therefore **never** trust the wire header to
/// size an allocation: we pre-reserve at most this many slots and let the `Vec` grow as *real*
/// elements are decoded. Every decode loop is bounded by the actual input length (each item consumes
/// ≥1 byte and the unpacker errors at end-of-input), so a genuinely large collection still decodes
/// correctly — it just reallocates instead of pre-sizing. This is the single source of truth for the
/// policy; use [`prealloc_cap`] at every wire-driven `Vec::with_capacity` call site.
pub(crate) const MAX_PREALLOC: usize = 1024;

/// Clamps a wire-supplied collection length to a safe pre-allocation capacity ([`MAX_PREALLOC`]).
///
/// This is the **only** sanctioned way to turn an untrusted PackStream length into a
/// `Vec::with_capacity` argument. Capping the pre-sizing changes no successful-decode behaviour (the
/// `Vec` grows as elements are read); it only removes the unbounded-allocation footgun. See
/// [`MAX_PREALLOC`] for the threat model.
#[inline]
#[must_use]
pub(crate) fn prealloc_cap(wire_len: usize) -> usize {
    wire_len.min(MAX_PREALLOC)
}

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

    /// `Point2D` — srid, x, y (Cartesian/WGS-84 2D spatial point).
    pub const POINT_2D: u8 = 0x58;
    /// `Point3D` — srid, x, y, z (Cartesian/WGS-84 3D spatial point).
    pub const POINT_3D: u8 = 0x59;
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

    /// PERF (C4/C5): clears the buffer while retaining its allocated capacity, so a single `Packer`
    /// can encode many messages back-to-back without re-allocating between them.
    pub fn reset(&mut self) {
        self.buf.clear();
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
    /// Current nesting depth of the in-progress decode (lists/maps/structures). Guarded against
    /// [`MAX_DECODE_DEPTH`] so a maliciously deep payload cannot overflow the stack (DoS hardening).
    depth: usize,
}

/// Maximum nesting depth accepted when decoding a PackStream value (lists, maps, and structures).
///
/// Decoding is recursive, so an adversary-supplied, deeply nested payload (e.g. tens of thousands of
/// nested empty lists) could otherwise exhaust the call stack and abort the process — a trivial
/// denial-of-service from network bytes.
///
/// The bound is chosen from measurement, not folklore: a debug build of [`unpack_value`] consumes
/// roughly 2 KiB of stack per recursive frame, so ~1000 frames already overflow the default 2 MiB
/// thread stack a Bolt session runs on. `256` levels therefore cost at most ~0.5 MiB even in the
/// worst (debug) profile — safe with wide margin on a 1 MiB stack — while remaining orders of
/// magnitude beyond any legitimate Bolt payload (real-world property/list nesting is single-digit).
/// A well-formed message is never rejected; only a hostile one is.
pub const MAX_DECODE_DEPTH: usize = 256;

impl<'a> Unpacker<'a> {
    /// A new unpacker over `buf`, positioned at the start.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            depth: 0,
        }
    }

    /// Enters one level of recursive decoding, rejecting the input once [`MAX_DECODE_DEPTH`] is
    /// exceeded. Pair every successful call with [`Unpacker::leave_nested`].
    ///
    /// # Errors
    /// [`BoltError::Decode`] when the nesting depth would exceed [`MAX_DECODE_DEPTH`].
    fn enter_nested(&mut self) -> BoltResult<()> {
        self.depth += 1;
        if self.depth > MAX_DECODE_DEPTH {
            return Err(BoltError::Decode(format!(
                "PackStream nesting depth exceeds the maximum of {MAX_DECODE_DEPTH}"
            )));
        }
        Ok(())
    }

    /// Leaves one level of recursive decoding previously entered via [`Unpacker::enter_nested`].
    fn leave_nested(&mut self) {
        self.depth -= 1;
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
    ///
    /// # Allocation-safety contract
    /// The returned length is taken **verbatim from untrusted wire bytes** and is therefore
    /// unbounded (up to `u32::MAX` for a 4-byte field). It MUST NOT be used to size an allocation
    /// directly. Every caller either (a) feeds it to [`Unpacker::read_slice`], which bounds it
    /// against the remaining input before any allocation, or (b) routes it through
    /// [`prealloc_cap`] before `Vec::with_capacity`. Decode loops driven by this length are bounded
    /// by the real input (each element consumes ≥1 byte and the unpacker errors at end-of-input),
    /// so the value can safely drive a `for` loop even though it must never drive a reservation.
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
            // INVARIANT: PackStream has no wide-struct marker — the field count is the low nibble of
            // the tiny-struct byte, so it is bounded to `0..=15` (== [`MAX_STRUCT_FIELDS`]). Callers
            // (e.g. `message::read_fields`) rely on this to pre-allocate without a [`prealloc_cap`]
            // clamp. If a future Bolt revision adds a wide-struct marker, this bound must be
            // re-derived and those call sites re-audited.
            let field_count = usize::from(m - TINY_STRUCT_BASE);
            debug_assert!(field_count <= MAX_STRUCT_FIELDS);
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
        // A spatial point maps onto the Bolt `Point2D` (0x58) or `Point3D` (0x59) structure by
        // dimensionality, carrying the CRS's SRID and its coordinates (`rmp` task #73).
        Value::Point(p) => match p.z() {
            None => pack_point_2d(packer, p.crs.srid(), p.x(), p.y()),
            Some(z) => pack_point_3d(packer, p.crs.srid(), p.x(), p.y(), z),
        },
        // This match is intentionally **exhaustive** over `graphus_core::Value`. When a new variant
        // is added there (the deferred structural `Node`/`Relationship`/`Path`, `04 §7.2`), this
        // becomes a compile error here — forcing its PackStream encoding to be written rather than
        // silently dropped. That compile-time enforcement is stronger than a runtime guard.
    }
}

// ---- Structural (graph) result values --------------------------------------------------------
//
// `graphus_core::Value` has no `Node`/`Relationship`/`Path`/`Point` variant yet (`04 §7.2` defers
// them). But a RECORD value *may* be a graph entity, and a stock Neo4j driver expects the proper
// Bolt structures — not a flattened id. So a result cell is carried as a [`BoltValue`]: either a
// property [`Value`] (packed by [`pack_value`]) or a graph entity packed here from the ids / labels
// / type / endpoints / properties the executor resolved (`04 §8.3`). This keeps the structural
// classes out of the shared core type while still emitting spec-correct wire bytes.

/// A node as a Bolt `Node` structure (tag `0x4E`).
#[derive(Debug, Clone, PartialEq)]
pub struct BoltNode {
    /// The node id.
    pub id: i64,
    /// The node's labels.
    pub labels: Vec<String>,
    /// The node's properties (ordered `(key, value)`).
    pub properties: Vec<(String, Value)>,
}

/// A relationship as a Bolt `Relationship` structure (tag `0x52`).
#[derive(Debug, Clone, PartialEq)]
pub struct BoltRelationship {
    /// The relationship id.
    pub id: i64,
    /// The start (source) node id.
    pub start: i64,
    /// The end (target) node id.
    pub end: i64,
    /// The relationship type name.
    pub rel_type: String,
    /// The relationship's properties (ordered `(key, value)`).
    pub properties: Vec<(String, Value)>,
}

/// A path as a Bolt `Path` structure (tag `0x50`): the distinct nodes and **unbound**
/// relationships on the path plus the alternating, signed, 1-based index sequence (see
/// [`pack_path`]). The `nodes`/`rels` are the path's distinct entities in first-appearance order;
/// `indices` is `[rel, node, rel, node, …]`.
#[derive(Debug, Clone, PartialEq)]
pub struct BoltPath {
    /// The distinct nodes on the path, in first-appearance order (start node first).
    pub nodes: Vec<BoltNode>,
    /// The distinct relationships on the path, in first-appearance order (packed as
    /// `UnboundRelationship`s — id, type, properties — since the node sequence supplies endpoints).
    pub rels: Vec<BoltRelationship>,
    /// The alternating, signed, 1-based index sequence (`2 * hops` entries).
    pub indices: Vec<i64>,
}

/// A **result-row cell** for a RECORD: a property value or a graph entity (`04 §8.3`).
///
/// Scalars/temporals/lists/maps stay [`BoltValue::Value`] and pack exactly as before; the structural
/// variants pack the Bolt 5.x graph structures. A [`BoltValue::List`] is a *structural* list (one
/// that contains an entity); a pure-property list stays inside a `Value::List`.
#[derive(Debug, Clone, PartialEq)]
pub enum BoltValue {
    /// A property value (scalar/string/bytes/list/map/temporal/null).
    Value(Value),
    /// A node (tag `0x4E`).
    Node(BoltNode),
    /// A relationship (tag `0x52`).
    Relationship(BoltRelationship),
    /// A path (tag `0x50`).
    Path(BoltPath),
    /// A structural list whose elements are packed each as a [`BoltValue`].
    List(Vec<BoltValue>),
}

impl From<Value> for BoltValue {
    fn from(v: Value) -> Self {
        BoltValue::Value(v)
    }
}

/// The Bolt 5.x `element_id` (and `start_element_id`/`end_element_id`) string for an entity.
///
/// Bolt 5.0 added a string `element_id` alongside the legacy integer id. Graphus is single-instance,
/// so its stable string element id is simply the **decimal of the integer id** — a documented
/// convention (`04 §8.3`): a stock driver reads it as an opaque string and round-trips it unchanged.
fn element_id(id: i64) -> String {
    id.to_string()
}

/// Packs a [`BoltValue`] result-row cell into `packer`: a property [`Value`] via [`pack_value`], or
/// the matching Bolt graph structure.
pub fn pack_bolt_value(packer: &mut Packer, value: &BoltValue) {
    match value {
        BoltValue::Value(v) => pack_value(packer, v),
        BoltValue::Node(n) => pack_node(packer, n),
        BoltValue::Relationship(r) => pack_relationship(packer, r),
        BoltValue::Path(p) => pack_path(packer, p),
        BoltValue::List(items) => {
            packer.write_list_header(items.len());
            for item in items {
                pack_bolt_value(packer, item);
            }
        }
    }
}

/// Packs a Bolt 5.x `Node` structure (tag `0x4E`): `id`, `labels`, `properties`, `element_id`
/// (Source: the Neo4j Bolt specification, Node since 5.0 carries the trailing string `element_id`).
pub fn pack_node(packer: &mut Packer, node: &BoltNode) {
    // 4 fields <= 15; infallible. The `expect` documents the invariant per the API guidelines.
    packer
        .write_struct_header(tag::NODE, 4)
        .expect("INVARIANT: Node has 4 fields");
    packer.write_int(node.id);
    packer.write_list_header(node.labels.len());
    for label in &node.labels {
        packer.write_string(label);
    }
    pack_properties(packer, &node.properties);
    packer.write_string(&element_id(node.id));
}

/// Packs a Bolt 5.x `Relationship` structure (tag `0x52`): `id`, `start`, `end`, `type`,
/// `properties`, `element_id`, `start_element_id`, `end_element_id` (the three element-id strings
/// added in 5.0).
pub fn pack_relationship(packer: &mut Packer, rel: &BoltRelationship) {
    packer
        .write_struct_header(tag::RELATIONSHIP, 8)
        .expect("INVARIANT: Relationship has 8 fields");
    packer.write_int(rel.id);
    packer.write_int(rel.start);
    packer.write_int(rel.end);
    packer.write_string(&rel.rel_type);
    pack_properties(packer, &rel.properties);
    packer.write_string(&element_id(rel.id));
    packer.write_string(&element_id(rel.start));
    packer.write_string(&element_id(rel.end));
}

/// Packs a Bolt 5.x `UnboundRelationship` structure (tag `0x72`): `id`, `type`, `properties`,
/// `element_id`. Used inside a `Path`'s `rels` list, where endpoints come from the node sequence.
fn pack_unbound_relationship(packer: &mut Packer, rel: &BoltRelationship) {
    packer
        .write_struct_header(tag::UNBOUND_RELATIONSHIP, 4)
        .expect("INVARIANT: UnboundRelationship has 4 fields");
    packer.write_int(rel.id);
    packer.write_string(&rel.rel_type);
    pack_properties(packer, &rel.properties);
    packer.write_string(&element_id(rel.id));
}

/// Packs a Bolt `Path` structure (tag `0x50`): `nodes`, `rels` (as `UnboundRelationship`s),
/// `indices`.
///
/// The `indices` list alternates `[rel, node, rel, node, …]`: a node index is 0-based into `nodes`,
/// a relationship index is **1-based** into `rels` and **signed** by traversal direction (positive =
/// forward, negative = backward). This is the exact Bolt encoding the driver re-walks to rebuild the
/// path (Source: the Neo4j Bolt/PackStream specification).
pub fn pack_path(packer: &mut Packer, path: &BoltPath) {
    packer
        .write_struct_header(tag::PATH, 3)
        .expect("INVARIANT: Path has 3 fields");
    packer.write_list_header(path.nodes.len());
    for node in &path.nodes {
        pack_node(packer, node);
    }
    packer.write_list_header(path.rels.len());
    for rel in &path.rels {
        pack_unbound_relationship(packer, rel);
    }
    packer.write_list_header(path.indices.len());
    for &idx in &path.indices {
        packer.write_int(idx);
    }
}

/// Packs an ordered `(key, value)` property list as a PackStream map.
fn pack_properties(packer: &mut Packer, properties: &[(String, Value)]) {
    packer.write_map_header(properties.len());
    for (key, value) in properties {
        packer.write_string(key);
        pack_value(packer, value);
    }
}

// ---- Spatial point encoders (tags 0x58 / 0x59) -----------------------------------------------
//
// A `Value::Point` (task #73) maps onto one of these structures by dimensionality (`pack_value`):
// a 2D CRS packs as `Point2D` (0x58), a 3D CRS as `Point3D` (0x59), each carrying the CRS's SRID
// and its coordinates. The inverse decode lives in `unpack_structured_value`.

/// Packs a Bolt `Point2D` structure (tag `0x58`): `srid` (int), `x` (float), `y` (float).
pub fn pack_point_2d(packer: &mut Packer, srid: i64, x: f64, y: f64) {
    packer
        .write_struct_header(tag::POINT_2D, 3)
        .expect("INVARIANT: Point2D has 3 fields");
    packer.write_int(srid);
    packer.write_float(x);
    packer.write_float(y);
}

/// Packs a Bolt `Point3D` structure (tag `0x59`): `srid` (int), `x`, `y`, `z` (floats).
pub fn pack_point_3d(packer: &mut Packer, srid: i64, x: f64, y: f64, z: f64) {
    packer
        .write_struct_header(tag::POINT_3D, 4)
        .expect("INVARIANT: Point3D has 4 fields");
    packer.write_int(srid);
    packer.write_float(x);
    packer.write_float(y);
    packer.write_float(z);
}

/// Inserts `(key, value)` into a decoded dictionary with PackStream "last seen value wins"
/// semantics (`04 §7.1`): if `key` is already present, its value is replaced in place; otherwise the
/// pair is appended (preserving first-seen ordering for distinct keys).
fn map_insert_last_wins(entries: &mut Vec<(String, Value)>, key: String, value: Value) {
    if let Some(slot) = entries.iter_mut().find(|(k, _)| *k == key) {
        slot.1 = value;
    } else {
        entries.push((key, value));
    }
}

/// Decodes one [`Value`] from `unpacker`.
///
/// # Errors
/// [`BoltError::Decode`] on a truncated stream, an unknown marker, or a structure tag whose target
/// `Value` variant does not yet exist (`Node`/`Relationship`/`Path` are deferred in
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
            unpacker.enter_nested()?;
            let mut items = Vec::with_capacity(prealloc_cap(n));
            for _ in 0..n {
                items.push(unpack_value(unpacker)?);
            }
            unpacker.leave_nested();
            Ok(Value::List(items))
        }
        _ if is_map_marker(marker) => {
            let n = unpacker.read_map_header()?;
            unpacker.enter_nested()?;
            let mut entries: Vec<(String, Value)> = Vec::with_capacity(prealloc_cap(n));
            for _ in 0..n {
                let k = unpacker.read_string()?;
                let v = unpack_value(unpacker)?;
                // PackStream dictionaries are "last seen value wins" for duplicate keys (`04 §7.1`):
                // overwrite an existing entry rather than retaining a duplicate pair.
                map_insert_last_wins(&mut entries, k, v);
            }
            unpacker.leave_nested();
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
            // PackStream INTEGER carries the full i64; `Date` is i64 days-since-epoch (#141), so the
            // value is taken as-is with no narrowing.
            let days = unpacker.read_int()?;
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
            Ok(Value::zoned_date_time(zoned_from_utc(
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
            Ok(Value::zoned_date_time(zoned_from_utc(
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
        tag::POINT_2D => {
            expect_fields(t, field_count, 3)?;
            let srid = unpacker.read_int()?;
            let x = read_float_field(unpacker, "Point2D.x")?;
            let y = read_float_field(unpacker, "Point2D.y")?;
            decode_point(srid, &[x, y])
        }
        tag::POINT_3D => {
            expect_fields(t, field_count, 4)?;
            let srid = unpacker.read_int()?;
            let x = read_float_field(unpacker, "Point3D.x")?;
            let y = read_float_field(unpacker, "Point3D.y")?;
            let z = read_float_field(unpacker, "Point3D.z")?;
            decode_point(srid, &[x, y, z])
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

/// Decodes one **result-row cell** ([`BoltValue`]) from `unpacker`: a property [`Value`] (via
/// [`unpack_value`]) or a graph structure (`Node`/`Relationship`/`Path`).
///
/// Unlike [`unpack_value`] (which rejects the deferred graph tags — they have no `Value` variant),
/// this decodes those tags into the corresponding [`BoltValue`] structural variant. It is the
/// inverse of [`pack_bolt_value`] and is what a client/test uses to read RECORD cells that may carry
/// entities.
///
/// # Errors
/// [`BoltError::Decode`] on a truncated/malformed stream or an unknown structure tag.
pub fn unpack_bolt_value(unpacker: &mut Unpacker<'_>) -> BoltResult<BoltValue> {
    let marker = unpacker
        .peek_marker()
        .ok_or_else(|| BoltError::Decode("unexpected end of PackStream input".to_owned()))?;

    if is_struct_marker(marker) {
        // Peek the tag without consuming the header, so a temporal/unknown tag can fall through to
        // `unpack_value`'s richer handling. The struct marker is 1 byte; the tag is the next.
        let tag = unpacker
            .buf
            .get(unpacker.pos + 1)
            .copied()
            .ok_or_else(|| BoltError::Decode("structure header truncated".to_owned()))?;
        match tag {
            tag::NODE => return Ok(BoltValue::Node(unpack_node(unpacker)?)),
            tag::RELATIONSHIP => {
                return Ok(BoltValue::Relationship(unpack_relationship(unpacker)?));
            }
            tag::PATH => return Ok(BoltValue::Path(unpack_path(unpacker)?)),
            // A temporal (or any other) structure: defer to the Value decoder.
            _ => return Ok(BoltValue::Value(unpack_value(unpacker)?)),
        }
    }

    // A list may be structural (contain an entity), so decode element-wise as BoltValues.
    if is_list_marker(marker) {
        let n = unpacker.read_list_header()?;
        unpacker.enter_nested()?;
        let mut items = Vec::with_capacity(prealloc_cap(n));
        for _ in 0..n {
            items.push(unpack_bolt_value(unpacker)?);
        }
        unpacker.leave_nested();
        return Ok(BoltValue::List(items));
    }

    Ok(BoltValue::Value(unpack_value(unpacker)?))
}

/// Decodes the property map of a graph structure as `(key, value)` pairs.
fn unpack_properties(unpacker: &mut Unpacker<'_>) -> BoltResult<Vec<(String, Value)>> {
    let n = unpacker.read_map_header()?;
    unpacker.enter_nested()?;
    let mut props: Vec<(String, Value)> = Vec::with_capacity(prealloc_cap(n));
    for _ in 0..n {
        let k = unpacker.read_string()?;
        let v = unpack_value(unpacker)?;
        // "Last seen value wins" for duplicate keys, exactly as a top-level dictionary (`04 §7.1`).
        map_insert_last_wins(&mut props, k, v);
    }
    unpacker.leave_nested();
    Ok(props)
}

/// Decodes a Bolt 5.x `Node` (tag `0x4E`, 4 fields: id, labels, properties, element_id).
fn unpack_node(unpacker: &mut Unpacker<'_>) -> BoltResult<BoltNode> {
    let (t, field_count) = unpacker.read_struct_header()?;
    expect_fields(t, field_count, 4)?;
    let id = unpacker.read_int()?;
    let label_count = unpacker.read_list_header()?;
    // Pre-allocation is capped (a node carries very few labels in practice, so 64 is a deliberately
    // tighter bound than [`MAX_PREALLOC`]); the `Vec` still grows if a node legitimately has more.
    // The wire `label_count` is NEVER trusted to size the allocation — see [`prealloc_cap`].
    let mut labels = Vec::with_capacity(label_count.min(64));
    for _ in 0..label_count {
        labels.push(unpacker.read_string()?);
    }
    let properties = unpack_properties(unpacker)?;
    let _element_id = unpacker.read_string()?; // round-tripped, not modelled separately
    Ok(BoltNode {
        id,
        labels,
        properties,
    })
}

/// Decodes a Bolt 5.x `Relationship` (tag `0x52`, 8 fields).
fn unpack_relationship(unpacker: &mut Unpacker<'_>) -> BoltResult<BoltRelationship> {
    let (t, field_count) = unpacker.read_struct_header()?;
    expect_fields(t, field_count, 8)?;
    let id = unpacker.read_int()?;
    let start = unpacker.read_int()?;
    let end = unpacker.read_int()?;
    let rel_type = unpacker.read_string()?;
    let properties = unpack_properties(unpacker)?;
    let _element_id = unpacker.read_string()?;
    let _start_element_id = unpacker.read_string()?;
    let _end_element_id = unpacker.read_string()?;
    Ok(BoltRelationship {
        id,
        start,
        end,
        rel_type,
        properties,
    })
}

/// Decodes a Bolt 5.x `UnboundRelationship` (tag `0x72`, 4 fields). The path's node sequence
/// supplies endpoints, so they are left at 0 here.
fn unpack_unbound_relationship(unpacker: &mut Unpacker<'_>) -> BoltResult<BoltRelationship> {
    let (t, field_count) = unpacker.read_struct_header()?;
    expect_fields(t, field_count, 4)?;
    let id = unpacker.read_int()?;
    let rel_type = unpacker.read_string()?;
    let properties = unpack_properties(unpacker)?;
    let _element_id = unpacker.read_string()?;
    Ok(BoltRelationship {
        id,
        start: 0,
        end: 0,
        rel_type,
        properties,
    })
}

/// Decodes a Bolt `Path` (tag `0x50`, 3 fields: nodes, rels, indices).
fn unpack_path(unpacker: &mut Unpacker<'_>) -> BoltResult<BoltPath> {
    let (t, field_count) = unpacker.read_struct_header()?;
    expect_fields(t, field_count, 3)?;
    let node_count = unpacker.read_list_header()?;
    let mut nodes = Vec::with_capacity(prealloc_cap(node_count));
    for _ in 0..node_count {
        nodes.push(unpack_node(unpacker)?);
    }
    let rel_count = unpacker.read_list_header()?;
    let mut rels = Vec::with_capacity(prealloc_cap(rel_count));
    for _ in 0..rel_count {
        rels.push(unpack_unbound_relationship(unpacker)?);
    }
    let idx_count = unpacker.read_list_header()?;
    let mut indices = Vec::with_capacity(prealloc_cap(idx_count));
    for _ in 0..idx_count {
        indices.push(unpacker.read_int()?);
    }
    Ok(BoltPath {
        nodes,
        rels,
        indices,
    })
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
    packer.write_int(d.days_since_epoch);
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

/// Builds a [`Value::Point`] from a wire SRID and coordinate slice (`rmp` task #73). An unknown SRID
/// or a coordinate count that does not match the CRS dimensionality is a controlled
/// [`BoltError::Decode`].
fn decode_point(srid: i64, coords: &[f64]) -> BoltResult<Value> {
    let crs = Crs::from_srid(srid)
        .ok_or_else(|| BoltError::Decode(format!("unknown spatial SRID {srid}")))?;
    Point::from_crs_coords(crs, coords)
        .map(Value::Point)
        .ok_or_else(|| {
            BoltError::Decode(format!(
                "SRID {srid} ({}) expects {} coordinates, found {}",
                crs.name(),
                crs.dimensions(),
                coords.len()
            ))
        })
}

/// Reads a PackStream `float64` coordinate field (a `Point2D`/`Point3D` `x`/`y`/`z`). Decoding a
/// non-float (the wrong wire shape) is a controlled [`BoltError::Decode`], never a panic.
fn read_float_field(unpacker: &mut Unpacker<'_>, what: &str) -> BoltResult<f64> {
    match unpack_value(unpacker)? {
        Value::Float(f) => Ok(f),
        // A Bolt sender may legitimately pack a whole-number coordinate as an integer; accept it.
        Value::Integer(i) => Ok(i as f64),
        other => Err(BoltError::Decode(format!(
            "{what} must be a float, found {other:?}"
        ))),
    }
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

    /// Decodes a single `Value` from a hand-built byte slice, asserting the whole slice is consumed.
    fn decode(bytes: &[u8]) -> Value {
        let mut u = Unpacker::new(bytes);
        let out = unpack_value(&mut u).expect("decode");
        assert!(u.is_empty(), "decode left {} trailing bytes", u.remaining());
        out
    }

    /// `rmp` #397: the PackStream spec says minimal-width encoding is *recommended*, not *mandated*, so
    /// a conformant decoder MUST accept **non-minimal** encodings — the official Neo4j driver
    /// ecosystem is permitted to emit them. The decoder is marker-width-driven, so it already does;
    /// this test pins that property so a future "reject non-minimal markers" optimisation cannot
    /// silently break wire interop. Each hand-built non-minimal byte sequence must decode to exactly
    /// the value its minimal form encodes.
    #[test]
    fn non_minimal_encodings_are_accepted() {
        // INT_16 carrying 1 (minimal form is the tiny int 0x01).
        assert_eq!(decode(&[INT_16, 0x00, 0x01]), Value::Integer(1));
        // INT_32 carrying 1.
        assert_eq!(decode(&[INT_32, 0x00, 0x00, 0x00, 0x01]), Value::Integer(1));
        // INT_64 carrying 1.
        assert_eq!(
            decode(&[INT_64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]),
            Value::Integer(1)
        );
        // INT_8 carrying 1 (minimal form is the tiny int 0x01).
        assert_eq!(decode(&[INT_8, 0x01]), Value::Integer(1));
        // STRING_8 carrying the 1-byte string "a" (minimal form is TINY_STRING_BASE + 1, 'a').
        assert_eq!(
            decode(&[STRING_8, 0x01, b'a']),
            Value::String("a".to_owned())
        );
        // STRING_16 carrying "a".
        assert_eq!(
            decode(&[STRING_16, 0x00, 0x01, b'a']),
            Value::String("a".to_owned())
        );
        // LIST_8 carrying an empty list (minimal form is the tiny list 0x90).
        assert_eq!(decode(&[LIST_8, 0x00]), Value::List(Vec::new()));
        // MAP_8 carrying an empty map (minimal form is the tiny map 0xA0).
        assert_eq!(decode(&[MAP_8, 0x00]), Value::Map(vec![]));
        // And the minimal forms decode to the same values — proving equivalence, not just acceptance.
        assert_eq!(decode(&[0x01]), Value::Integer(1));
        assert_eq!(
            decode(&[TINY_STRING_BASE + 1, b'a']),
            Value::String("a".to_owned())
        );
        assert_eq!(decode(&[TINY_LIST_BASE]), Value::List(Vec::new()));
    }

    /// `rmp` #397: documents the **current** collection-length cap behaviour. The PackStream spec's
    /// maximum is `i32::MAX`, but Graphus deliberately uses the wider unsigned [`MAX_U32_LEN`]
    /// (`u32::MAX`) as a lenient choice (see its doc comment). This test pins that current value so any
    /// change to the cap — in either direction — is a conscious, reviewed decision (the tightening to
    /// `i32::MAX` is not yet ratified). The cap governs only the maximum *expressible* header length; a
    /// header never sizes an allocation directly ([`MAX_PREALLOC`] / [`prealloc_cap`]).
    #[test]
    fn collection_length_cap_current_behavior() {
        // The cap is the full unsigned 32-bit range, NOT the spec's i32::MAX — the current lenient
        // choice. (If this assertion ever needs changing, the cap was changed; that requires a
        // ratified decision per `rmp` #397.)
        assert_eq!(MAX_U32_LEN, u32::MAX as usize);
        assert!(
            MAX_U32_LEN > i32::MAX as usize,
            "the current cap is intentionally wider than the spec's i32::MAX maximum"
        );
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
            Value::zoned_date_time(ZonedDateTime {
                local: LocalDateTime {
                    epoch_seconds: 1_700_000_000,
                    nanos: 500,
                },
                offset_seconds: 7200,
                zone_id: String::new(),
            }),
            Value::zoned_date_time(ZonedDateTime {
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
        assert_eq!(unpack_value(&mut u).unwrap(), Value::zoned_date_time(v));
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
    fn deeply_nested_list_is_rejected_not_overflowed() {
        // Regression (DoS hardening): a payload of deeply nested single-element lists must be
        // rejected with a Decode error rather than recursing until the stack overflows/aborts.
        // Build `MAX_DECODE_DEPTH + 1` nested TINY_LISTs of one element, then a Null at the bottom.
        let mut bytes = vec![TINY_LIST_BASE + 1; MAX_DECODE_DEPTH + 1];
        bytes.push(NULL);
        let mut u = Unpacker::new(&bytes);
        let err = unpack_value(&mut u).expect_err("over-deep nesting must be rejected");
        assert!(
            matches!(err, BoltError::Decode(ref m) if m.contains("nesting depth")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn deeply_nested_map_is_rejected_not_overflowed() {
        // The same guard must apply to nested dictionaries: each level is a single-entry TINY_MAP
        // (`0xA1`) whose key is the empty string (`0x80`).
        let mut bytes = Vec::new();
        for _ in 0..=MAX_DECODE_DEPTH {
            bytes.push(TINY_MAP_BASE + 1); // map of 1 entry
            bytes.push(TINY_STRING_BASE); // empty-string key
        }
        bytes.push(NULL); // innermost value
        let mut u = Unpacker::new(&bytes);
        let err = unpack_value(&mut u).expect_err("over-deep map nesting must be rejected");
        assert!(
            matches!(err, BoltError::Decode(ref m) if m.contains("nesting depth")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn nesting_at_the_depth_limit_is_accepted() {
        // A payload nested exactly to the limit must still decode: the bound is the maximum
        // accepted depth, not one below it.
        let mut bytes = vec![TINY_LIST_BASE + 1; MAX_DECODE_DEPTH];
        bytes.push(NULL);
        let mut u = Unpacker::new(&bytes);
        assert!(
            unpack_value(&mut u).is_ok(),
            "nesting exactly at the limit must be accepted"
        );
    }

    #[test]
    fn duplicate_map_keys_keep_last_value() {
        // Regression: PackStream dictionaries are "last seen value wins" (`04 §7.1`). A map encoding
        // the same key twice must decode to a single entry carrying the LAST value.
        let mut p = Packer::new();
        p.write_map_header(2);
        p.write_string("k");
        p.write_int(1);
        p.write_string("k");
        p.write_int(2);
        let bytes = p.into_inner();
        let mut u = Unpacker::new(&bytes);
        let v = unpack_value(&mut u).expect("decode map");
        assert_eq!(
            v,
            Value::Map(vec![("k".to_owned(), Value::Integer(2))]),
            "duplicate key must collapse to the last-seen value"
        );
    }

    #[test]
    fn duplicate_property_keys_keep_last_value() {
        // The same "last wins" rule must hold for a graph entity's property map (`unpack_properties`).
        // Encode a Node whose property map repeats `p`; the surviving value must be the last one.
        let mut p = Packer::new();
        p.write_struct_header(tag::NODE, 4).unwrap();
        p.write_int(7); // id
        p.write_list_header(0); // labels
        p.write_map_header(2); // properties: duplicate key `p`
        p.write_string("p");
        p.write_int(10);
        p.write_string("p");
        p.write_int(20);
        p.write_string("e7"); // element_id
        let bytes = p.into_inner();
        let mut u = Unpacker::new(&bytes);
        let node = unpack_node(&mut u).expect("decode node");
        assert_eq!(
            node.properties,
            vec![("p".to_owned(), Value::Integer(20))],
            "duplicate property key must collapse to the last-seen value"
        );
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

    // ---- structural (graph) value tests -------------------------------------------------------

    /// Round-trips a [`BoltValue`] through `pack_bolt_value`/`unpack_bolt_value`.
    fn bolt_round_trip(v: &BoltValue) -> BoltValue {
        let mut p = Packer::new();
        pack_bolt_value(&mut p, v);
        let bytes = p.into_inner();
        let mut u = Unpacker::new(&bytes);
        let out = unpack_bolt_value(&mut u).expect("decode bolt value");
        assert!(u.is_empty(), "decode left {} trailing bytes", u.remaining());
        out
    }

    #[test]
    fn node_structure_exact_layout_and_round_trip() {
        let node = BoltNode {
            id: 7,
            labels: vec!["Person".to_owned(), "Admin".to_owned()],
            properties: vec![("name".to_owned(), Value::String("Ada".to_owned()))],
        };
        let mut p = Packer::new();
        pack_node(&mut p, &node);
        let bytes = p.into_inner();
        // Tiny-struct marker carrying 4 fields, then the Node tag.
        assert_eq!(bytes[0], TINY_STRUCT_BASE + 4);
        assert_eq!(bytes[1], tag::NODE);
        // Field 0: id (tiny int 7).
        assert_eq!(bytes[2], 0x07);
        // Field 1: labels — a 2-element tiny list.
        assert_eq!(bytes[3], TINY_LIST_BASE + 2);
        // Round-trip preserves id/labels/properties (element_id is round-tripped, not modelled).
        let mut u = Unpacker::new(&bytes);
        assert_eq!(unpack_node(&mut u).unwrap(), node);
        // The element_id field is the stringified id (single-instance convention).
        let mut u2 = Unpacker::new(&bytes);
        let _ = u2.read_struct_header().unwrap();
        let _id = u2.read_int().unwrap();
        // Skip the labels list to reach the trailing element_id field.
        let n = u2.read_list_header().unwrap();
        for _ in 0..n {
            let _ = u2.read_string().unwrap();
        }
        let _props = unpack_properties(&mut u2).unwrap();
        assert_eq!(u2.read_string().unwrap(), "7");
    }

    #[test]
    fn relationship_structure_has_eight_fields_and_element_ids() {
        let rel = BoltRelationship {
            id: 3,
            start: 1,
            end: 2,
            rel_type: "KNOWS".to_owned(),
            properties: vec![("since".to_owned(), Value::Integer(2010))],
        };
        let mut p = Packer::new();
        pack_relationship(&mut p, &rel);
        let bytes = p.into_inner();
        assert_eq!(bytes[0], TINY_STRUCT_BASE + 8);
        assert_eq!(bytes[1], tag::RELATIONSHIP);
        // Walk the structure to confirm the three element-id strings: "3", "1", "2".
        let mut u = Unpacker::new(&bytes);
        let (_t, fc) = u.read_struct_header().unwrap();
        assert_eq!(fc, 8);
        assert_eq!(u.read_int().unwrap(), 3); // id
        assert_eq!(u.read_int().unwrap(), 1); // start
        assert_eq!(u.read_int().unwrap(), 2); // end
        assert_eq!(u.read_string().unwrap(), "KNOWS"); // type
        let _props = unpack_properties(&mut u).unwrap();
        assert_eq!(u.read_string().unwrap(), "3"); // element_id
        assert_eq!(u.read_string().unwrap(), "1"); // start_element_id
        assert_eq!(u.read_string().unwrap(), "2"); // end_element_id
        // And it round-trips through the high-level decoder.
        assert_eq!(
            bolt_round_trip(&BoltValue::Relationship(rel.clone())),
            BoltValue::Relationship(rel)
        );
    }

    #[test]
    fn path_structure_packs_nodes_unbound_rels_and_indices() {
        let n0 = BoltNode {
            id: 10,
            labels: vec!["P".to_owned()],
            properties: vec![],
        };
        let n1 = BoltNode {
            id: 11,
            labels: vec!["P".to_owned()],
            properties: vec![],
        };
        let r0 = BoltRelationship {
            id: 100,
            start: 10,
            end: 11,
            rel_type: "R".to_owned(),
            properties: vec![],
        };
        let path = BoltPath {
            nodes: vec![n0, n1],
            rels: vec![r0],
            indices: vec![1, 1], // forward rel #1, arrive at node index 1
        };
        let mut p = Packer::new();
        pack_path(&mut p, &path);
        let bytes = p.into_inner();
        assert_eq!(bytes[0], TINY_STRUCT_BASE + 3);
        assert_eq!(bytes[1], tag::PATH);
        // Inner rels must be UnboundRelationship (tag 0x72), not full Relationship.
        let mut u = Unpacker::new(&bytes);
        let (_t, fc) = u.read_struct_header().unwrap();
        assert_eq!(fc, 3);
        let node_count = u.read_list_header().unwrap();
        assert_eq!(node_count, 2);
        for _ in 0..node_count {
            let _ = unpack_node(&mut u).unwrap();
        }
        let rel_count = u.read_list_header().unwrap();
        assert_eq!(rel_count, 1);
        let (rel_tag, rel_fc) = u.read_struct_header().unwrap();
        assert_eq!(rel_tag, tag::UNBOUND_RELATIONSHIP);
        assert_eq!(rel_fc, 4);
        // Round-trip: the inner rels are UnboundRelationships, so endpoints come back as 0 (the
        // node sequence supplies them on the driver side) — id/type/properties/indices are exact.
        let mut expected = path.clone();
        expected.rels[0].start = 0;
        expected.rels[0].end = 0;
        assert_eq!(
            bolt_round_trip(&BoltValue::Path(path)),
            BoltValue::Path(expected)
        );
    }

    #[test]
    fn structural_list_round_trips_with_an_entity() {
        let node = BoltNode {
            id: 1,
            labels: vec!["L".to_owned()],
            properties: vec![],
        };
        let list = BoltValue::List(vec![
            BoltValue::Value(Value::Integer(42)),
            BoltValue::Node(node),
        ]);
        assert_eq!(bolt_round_trip(&list), list);
    }

    #[test]
    fn scalar_bolt_value_round_trips() {
        let v = BoltValue::Value(Value::String("hi".to_owned()));
        assert_eq!(bolt_round_trip(&v), v);
    }

    #[test]
    fn point_2d_and_3d_exact_layout() {
        let mut p = Packer::new();
        pack_point_2d(&mut p, 7203, 1.5, -2.5);
        let bytes = p.into_inner();
        assert_eq!(bytes[0], TINY_STRUCT_BASE + 3);
        assert_eq!(bytes[1], tag::POINT_2D);
        let mut u = Unpacker::new(&bytes);
        let (_t, fc) = u.read_struct_header().unwrap();
        assert_eq!(fc, 3);
        assert_eq!(u.read_int().unwrap(), 7203);

        let mut p = Packer::new();
        pack_point_3d(&mut p, 9157, 1.0, 2.0, 3.0);
        let bytes = p.into_inner();
        assert_eq!(bytes[0], TINY_STRUCT_BASE + 4);
        assert_eq!(bytes[1], tag::POINT_3D);
        let mut u = Unpacker::new(&bytes);
        let (_t, fc) = u.read_struct_header().unwrap();
        assert_eq!(fc, 4);
        assert_eq!(u.read_int().unwrap(), 9157);
    }

    #[test]
    fn value_point_round_trips_through_pack_and_unpack() {
        use graphus_core::value::spatial::{Crs, Point};

        // 2D Cartesian: packs as a Point2D (0x58) struct and round-trips bit-exactly.
        let p2 = Value::Point(Point::new_2d(Crs::Cartesian, 1.5, -2.5));
        let mut p = Packer::new();
        pack_value(&mut p, &p2);
        let bytes = p.into_inner();
        assert_eq!(bytes[0], TINY_STRUCT_BASE + 3);
        assert_eq!(bytes[1], tag::POINT_2D, "2D point packs as Point2D (0x58)");
        assert_eq!(round_trip(&p2), p2);

        // 3D WGS-84: packs as a Point3D (0x59) struct and round-trips.
        let p3 = Value::Point(Point::new_3d(Crs::Wgs84_3D, 12.5, -7.25, 100.0));
        let mut p = Packer::new();
        pack_value(&mut p, &p3);
        let bytes = p.into_inner();
        assert_eq!(bytes[0], TINY_STRUCT_BASE + 4);
        assert_eq!(bytes[1], tag::POINT_3D, "3D point packs as Point3D (0x59)");
        assert_eq!(round_trip(&p3), p3);

        // Every CRS round-trips with its SRID preserved.
        for p in [
            Value::Point(Point::new_2d(Crs::Wgs84, -8.61, 41.15)),
            Value::Point(Point::new_3d(Crs::Cartesian3D, 1.0, 2.0, 3.0)),
        ] {
            assert_eq!(round_trip(&p), p);
        }

        // An unknown SRID is a controlled decode error, not a panic.
        let mut bad = Packer::new();
        pack_point_2d(&mut bad, 9999, 1.0, 2.0);
        let bytes = bad.into_inner();
        let mut u = Unpacker::new(&bytes);
        assert!(unpack_value(&mut u).is_err());
    }

    #[test]
    fn unpack_bolt_value_still_decodes_temporals_and_scalars() {
        // A temporal structure goes through the Value path inside a BoltValue.
        let v = Value::Date(Date {
            days_since_epoch: 20_000,
        });
        let mut p = Packer::new();
        pack_value(&mut p, &v);
        let bytes = p.into_inner();
        let mut u = Unpacker::new(&bytes);
        assert_eq!(unpack_bolt_value(&mut u).unwrap(), BoltValue::Value(v));
    }
}
