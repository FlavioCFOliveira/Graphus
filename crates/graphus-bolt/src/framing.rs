//! Bolt **chunked message framing** (`04-technical-design.md` §8.1).
//!
//! A Bolt *message* (a single PackStream structure, [`crate::message`]) is transmitted as one or
//! more **chunks**. Each chunk is a **2-byte big-endian length** header followed by exactly that
//! many payload bytes; a message is terminated by a **zero-length chunk** (`00 00`). The maximum
//! payload per chunk is `65 535` bytes (the largest 16-bit length), so a long message is split
//! across several chunks (`04 §8.1`).
//!
//! A bare `00 00` with no preceding non-empty chunk is a **NOOP** — a keep-alive that carries no
//! message (`04 §8.1`). [`Dechunker`] surfaces it as [`Frame::Noop`] so the server can ignore it.
//!
//! This module is pure byte↔byte framing: it neither parses nor builds PackStream. [`chunk_message`]
//! takes an already-serialized message payload and frames it; [`Dechunker`] reassembles a payload
//! from a byte stream. The framing and the codec compose in [`crate::message`].

use crate::error::{BoltError, BoltResult};

/// The maximum number of payload bytes in a single chunk (the largest 16-bit big-endian length).
pub const MAX_CHUNK_PAYLOAD: usize = u16::MAX as usize;

/// The default cap on the size (in bytes) of a single **reassembled** message payload.
///
/// A Bolt message may legitimately span many chunks (`04 §8.1`), but it is reassembled into one
/// contiguous buffer before decoding. Without a bound, a malicious peer can stream an unbounded run
/// of non-empty chunks (never sending the `00 00` terminator) and force the server to buffer until
/// it runs out of memory — a trivial denial-of-service. This default (64 MiB) is far larger than any
/// legitimate Bolt message yet bounds the worst case. Use [`Dechunker::with_max_message_size`] to
/// tune it per deployment.
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024;

/// The two-byte end-of-message / NOOP marker (`00 00`).
pub const END_MARKER: [u8; 2] = [0x00, 0x00];

/// Frames an already-serialized message `payload` into Bolt chunks, terminated by `00 00`.
///
/// A payload longer than [`MAX_CHUNK_PAYLOAD`] is split across multiple chunks. An **empty**
/// payload is framed as a single `00 00` (an empty message); callers that want a NOOP keep-alive
/// should emit [`END_MARKER`] directly rather than calling this with an empty payload, since the
/// two are byte-identical and only context distinguishes them.
///
/// The bytes are appended to `out` (so a caller can frame several messages back-to-back into one
/// buffer).
pub fn chunk_message_into(out: &mut Vec<u8>, payload: &[u8]) {
    for piece in payload.chunks(MAX_CHUNK_PAYLOAD) {
        // `piece.len() <= MAX_CHUNK_PAYLOAD == u16::MAX`, so the cast cannot truncate.
        debug_assert!(piece.len() <= MAX_CHUNK_PAYLOAD);
        #[expect(clippy::cast_possible_truncation, reason = "chunk size <= u16::MAX")]
        let len = piece.len() as u16;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(piece);
    }
    out.extend_from_slice(&END_MARKER);
}

/// Frames an already-serialized message `payload` into a fresh `Vec` of Bolt chunks.
///
/// See [`chunk_message_into`] for the layout.
#[must_use]
pub fn chunk_message(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    chunk_message_into(&mut out, payload);
    out
}

/// One result of reading from a chunk stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// A fully reassembled message payload (the concatenation of its chunks).
    Message(Vec<u8>),
    /// A NOOP keep-alive (a bare `00 00` with no preceding payload).
    Noop,
}

/// Reassembles message payloads from a Bolt chunk byte stream.
///
/// Feed it bytes with [`Dechunker::push`]; pull completed [`Frame`]s with [`Dechunker::next_frame`].
/// It buffers a partial chunk across `push` calls, so a transport may deliver bytes in arbitrary
/// slices (the realistic case over a socket). A chunk header announcing more bytes than have
/// arrived simply waits for the rest.
///
/// The distinction between an empty message and a NOOP is positional, exactly as on the wire: a
/// `00 00` that terminates one-or-more non-empty chunks ends a [`Frame::Message`]; a `00 00` seen
/// with no buffered payload is a [`Frame::Noop`].
#[derive(Debug)]
pub struct Dechunker {
    /// Bytes received but not yet parsed into chunks.
    inbox: Vec<u8>,
    /// PERF (C2): read offset into `inbox`. Consumed chunks advance this cursor instead of being
    /// drained from the front (an O(remaining) memmove per chunk). The buffer is compacted lazily —
    /// only once everything is consumed or the cursor crosses a threshold — so steady-state framing
    /// is amortised O(1) per chunk. The *logical* buffer is always `inbox[read_cursor..]`.
    read_cursor: usize,
    /// Payload assembled for the in-progress message (non-empty chunks seen since the last
    /// end-marker).
    assembling: Vec<u8>,
    /// Whether at least one chunk (even an explicit empty one mid-message is impossible, so this is
    /// set by any non-end chunk) has contributed to the current message, distinguishing an
    /// end-of-message from a NOOP.
    in_message: bool,
    /// Hard cap on the size of a single reassembled message; exceeding it is a fatal framing error
    /// (DoS hardening — see [`DEFAULT_MAX_MESSAGE_SIZE`]).
    max_message_size: usize,
}

impl Default for Dechunker {
    fn default() -> Self {
        Self {
            inbox: Vec::new(),
            read_cursor: 0,
            assembling: Vec::new(),
            in_message: false,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
        }
    }
}

impl Dechunker {
    /// A new, empty dechunker with the [`DEFAULT_MAX_MESSAGE_SIZE`] reassembly cap.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A new, empty dechunker with a custom reassembled-message size cap (DoS hardening).
    #[must_use]
    pub fn with_max_message_size(max_message_size: usize) -> Self {
        Self {
            max_message_size,
            ..Self::default()
        }
    }

    /// Appends received bytes to the internal buffer.
    pub fn push(&mut self, bytes: &[u8]) {
        // PERF (C2): reclaim already-consumed front bytes before growing, so the backing `Vec` does
        // not accumulate dead prefix across many `push` calls.
        self.compact();
        self.inbox.extend_from_slice(bytes);
    }

    /// Drops consumed front bytes (`inbox[..read_cursor]`) and resets the cursor. Called when the
    /// buffer is fully drained, when the cursor grows large, or before appending more input.
    fn compact(&mut self) {
        if self.read_cursor == 0 {
            return;
        }
        if self.read_cursor >= self.inbox.len() {
            self.inbox.clear();
        } else {
            self.inbox.drain(..self.read_cursor);
        }
        self.read_cursor = 0;
    }

    /// Returns the next complete [`Frame`], or `Ok(None)` if more bytes are needed.
    ///
    /// Drives the chunk parser forward over the buffered bytes: it consumes whole chunks, appends
    /// their payloads to the in-progress message, and on an end-marker returns the assembled
    /// [`Frame::Message`] (or a [`Frame::Noop`] if nothing was assembled).
    ///
    /// # Errors
    /// [`BoltError::Decode`] when a reassembled message would exceed the configured
    /// [`max_message_size`](Dechunker::with_max_message_size): the framing is aborted so the caller
    /// can close the connection rather than buffer unboundedly (DoS hardening).
    pub fn next_frame(&mut self) -> BoltResult<Option<Frame>> {
        loop {
            // PERF (C2): the logical buffer is `inbox[read_cursor..]`; consumed chunks advance the
            // cursor rather than draining the front. Compact lazily once it grows large so the dead
            // prefix never accumulates unboundedly between `push` calls (e.g. a stream of many small
            // messages without intervening pushes).
            if self.read_cursor > 8 * 1024 && self.read_cursor > self.inbox.len() / 2 {
                self.compact();
            }
            let avail = self.inbox.len() - self.read_cursor;
            // Need at least a 2-byte length header to proceed.
            if avail < 2 {
                return Ok(None);
            }
            let base = self.read_cursor;
            let len = usize::from(u16::from_be_bytes([self.inbox[base], self.inbox[base + 1]]));

            if len == 0 {
                // End-of-message / NOOP marker.
                self.read_cursor += 2;
                if self.in_message {
                    let payload = std::mem::take(&mut self.assembling);
                    self.in_message = false;
                    self.compact_if_drained();
                    return Ok(Some(Frame::Message(payload)));
                }
                self.compact_if_drained();
                return Ok(Some(Frame::Noop));
            }

            // Reject before buffering: the chunk's payload would push the reassembled message past
            // the cap. Checked against the already-assembled size (saturating, so it cannot wrap),
            // so an unbounded run of non-terminated chunks is stopped at the limit rather than
            // exhausting memory.
            if self.assembling.len().saturating_add(len) > self.max_message_size {
                return Err(BoltError::Decode(format!(
                    "reassembled Bolt message exceeds the maximum size of {} bytes",
                    self.max_message_size
                )));
            }

            // A data chunk: wait until the full header+payload has arrived.
            let total = 2 + len;
            if avail < total {
                return Ok(None);
            }
            self.assembling
                .extend_from_slice(&self.inbox[base + 2..base + total]);
            self.in_message = true;
            self.read_cursor += total;
            // Loop: there may be more chunks (or the terminating marker) already buffered.
        }
    }

    /// Compacts the inbox when the cursor has consumed everything buffered. This keeps the common
    /// "buffer fully drained between reads" case allocation-stable (cursor reset to 0, no memmove).
    fn compact_if_drained(&mut self) {
        if self.read_cursor >= self.inbox.len() {
            self.inbox.clear();
            self.read_cursor = 0;
        }
    }

    /// Whether any buffered bytes remain unparsed (a partial chunk awaiting more input).
    #[must_use]
    pub fn has_buffered(&self) -> bool {
        // PERF (C2): unparsed bytes are `inbox[read_cursor..]`, not the whole `inbox`.
        self.read_cursor < self.inbox.len() || !self.assembling.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pushes `bytes` and drains every currently-available frame.
    fn frames(bytes: &[u8]) -> Vec<Frame> {
        let mut d = Dechunker::new();
        d.push(bytes);
        let mut out = Vec::new();
        while let Some(f) = d.next_frame().expect("framing") {
            out.push(f);
        }
        out
    }

    #[test]
    fn single_chunk_message_round_trips() {
        let payload = b"hello bolt".to_vec();
        let framed = chunk_message(&payload);
        // 00 0A <10 bytes> 00 00
        assert_eq!(&framed[..2], &[0x00, 0x0A]);
        assert_eq!(&framed[framed.len() - 2..], &END_MARKER);
        assert_eq!(frames(&framed), vec![Frame::Message(payload)]);
    }

    #[test]
    fn empty_message_is_a_single_end_marker() {
        let framed = chunk_message(&[]);
        assert_eq!(framed, END_MARKER);
        // With no buffered payload, a bare 00 00 reads as a NOOP (positional, per the wire).
        assert_eq!(frames(&framed), vec![Frame::Noop]);
    }

    #[test]
    fn noop_keepalive_is_recognized() {
        assert_eq!(frames(&END_MARKER), vec![Frame::Noop]);
        // Several NOOPs in a row.
        let mut b = Vec::new();
        b.extend_from_slice(&END_MARKER);
        b.extend_from_slice(&END_MARKER);
        assert_eq!(frames(&b), vec![Frame::Noop, Frame::Noop]);
    }

    #[test]
    fn message_spanning_multiple_chunks_reassembles() {
        // A payload larger than one chunk must split and reassemble byte-for-byte.
        let payload: Vec<u8> = (0..(MAX_CHUNK_PAYLOAD + 1234))
            .map(|i| (i % 251) as u8)
            .collect();
        let framed = chunk_message(&payload);
        // First chunk is a full MAX_CHUNK_PAYLOAD.
        assert_eq!(&framed[..2], &(MAX_CHUNK_PAYLOAD as u16).to_be_bytes());
        let got = frames(&framed);
        assert_eq!(got, vec![Frame::Message(payload)]);
    }

    #[test]
    fn manually_split_chunks_reassemble_into_one_message() {
        // Two non-empty chunks then the end marker = one message (the classic "split across chunks").
        let mut wire = Vec::new();
        wire.extend_from_slice(&[0x00, 0x03]);
        wire.extend_from_slice(b"abc");
        wire.extend_from_slice(&[0x00, 0x02]);
        wire.extend_from_slice(b"de");
        wire.extend_from_slice(&END_MARKER);
        assert_eq!(frames(&wire), vec![Frame::Message(b"abcde".to_vec())]);
    }

    #[test]
    fn bytes_delivered_one_at_a_time_still_reassemble() {
        // The realistic socket case: the transport hands us one byte per push.
        let payload = b"streamed".to_vec();
        let framed = chunk_message(&payload);
        let mut d = Dechunker::new();
        let mut got = None;
        for b in &framed {
            d.push(&[*b]);
            if let Some(f) = d.next_frame().expect("framing") {
                got = Some(f);
            }
        }
        assert_eq!(got, Some(Frame::Message(payload)));
        assert!(!d.has_buffered());
    }

    #[test]
    fn two_messages_back_to_back() {
        let mut wire = Vec::new();
        chunk_message_into(&mut wire, b"one");
        chunk_message_into(&mut wire, b"two");
        assert_eq!(
            frames(&wire),
            vec![
                Frame::Message(b"one".to_vec()),
                Frame::Message(b"two".to_vec()),
            ]
        );
    }

    #[test]
    fn oversized_reassembled_message_is_rejected() {
        // Regression (DoS hardening): a peer streams non-empty chunks without ever sending the
        // `00 00` terminator. The reassembly cap must abort with an error instead of buffering
        // unboundedly. Use a tiny cap so the test is cheap and deterministic.
        let mut d = Dechunker::with_max_message_size(8);
        // First chunk of 5 bytes is fine (5 <= 8).
        let mut wire = Vec::new();
        wire.extend_from_slice(&[0x00, 0x05]);
        wire.extend_from_slice(b"abcde");
        d.push(&wire);
        assert_eq!(d.next_frame().unwrap(), None); // consumed, awaiting more

        // A second 5-byte chunk would make 10 bytes (> 8): rejected, and the rejection is decided
        // from the header alone (no need to deliver the payload first).
        d.push(&[0x00, 0x05]);
        let err = d
            .next_frame()
            .expect_err("oversized message must be rejected");
        assert!(
            matches!(err, BoltError::Decode(ref m) if m.contains("maximum size")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn message_at_the_size_cap_is_accepted() {
        // A message exactly at the cap must still be accepted (the bound is inclusive).
        let mut d = Dechunker::with_max_message_size(5);
        let mut wire = Vec::new();
        wire.extend_from_slice(&[0x00, 0x05]);
        wire.extend_from_slice(b"abcde");
        wire.extend_from_slice(&END_MARKER);
        d.push(&wire);
        assert_eq!(
            d.next_frame().unwrap(),
            Some(Frame::Message(b"abcde".to_vec()))
        );
    }

    #[test]
    fn many_messages_one_push_drive_cursor_then_compact() {
        // PERF (C2) regression: a single large push of many small messages must reassemble each one
        // byte-identically while the read cursor advances (and lazily compacts) instead of draining
        // the front. Build enough payload that the cursor crosses the 8 KiB compaction threshold.
        let mut wire = Vec::new();
        let mut expected = Vec::new();
        for i in 0..2000u32 {
            let payload = format!("msg-{i}").into_bytes();
            chunk_message_into(&mut wire, &payload);
            expected.push(Frame::Message(payload));
        }
        let mut d = Dechunker::new();
        d.push(&wire);
        let mut got = Vec::new();
        while let Some(f) = d.next_frame().expect("framing") {
            got.push(f);
        }
        assert_eq!(got, expected);
        assert!(!d.has_buffered(), "buffer must be fully drained");
    }

    #[test]
    fn cursor_survives_interleaved_push_and_consume() {
        // A frame is consumed (advancing the cursor), then more bytes are pushed: `push` must compact
        // the consumed prefix so the second frame still reassembles correctly.
        let mut d = Dechunker::new();
        let mut first = Vec::new();
        chunk_message_into(&mut first, b"first");
        d.push(&first);
        assert_eq!(
            d.next_frame().unwrap(),
            Some(Frame::Message(b"first".to_vec()))
        );
        let mut second = Vec::new();
        chunk_message_into(&mut second, b"second");
        d.push(&second);
        assert_eq!(
            d.next_frame().unwrap(),
            Some(Frame::Message(b"second".to_vec()))
        );
        assert!(!d.has_buffered());
    }

    #[test]
    fn partial_header_waits_for_more_bytes() {
        let mut d = Dechunker::new();
        d.push(&[0x00]); // only half a length header
        assert_eq!(d.next_frame().unwrap(), None);
        d.push(&[0x03]);
        assert_eq!(d.next_frame().unwrap(), None); // header complete, payload missing
        d.push(b"abc");
        assert_eq!(d.next_frame().unwrap(), None); // payload in, end marker missing
        d.push(&END_MARKER);
        assert_eq!(
            d.next_frame().unwrap(),
            Some(Frame::Message(b"abc".to_vec()))
        );
    }
}
