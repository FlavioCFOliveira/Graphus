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

use crate::error::BoltResult;

/// The maximum number of payload bytes in a single chunk (the largest 16-bit big-endian length).
pub const MAX_CHUNK_PAYLOAD: usize = u16::MAX as usize;

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
#[derive(Debug, Default)]
pub struct Dechunker {
    /// Bytes received but not yet parsed into chunks.
    inbox: Vec<u8>,
    /// Payload assembled for the in-progress message (non-empty chunks seen since the last
    /// end-marker).
    assembling: Vec<u8>,
    /// Whether at least one chunk (even an explicit empty one mid-message is impossible, so this is
    /// set by any non-end chunk) has contributed to the current message, distinguishing an
    /// end-of-message from a NOOP.
    in_message: bool,
}

impl Dechunker {
    /// A new, empty dechunker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends received bytes to the internal buffer.
    pub fn push(&mut self, bytes: &[u8]) {
        self.inbox.extend_from_slice(bytes);
    }

    /// Returns the next complete [`Frame`], or `Ok(None)` if more bytes are needed.
    ///
    /// Drives the chunk parser forward over the buffered bytes: it consumes whole chunks, appends
    /// their payloads to the in-progress message, and on an end-marker returns the assembled
    /// [`Frame::Message`] (or a [`Frame::Noop`] if nothing was assembled).
    ///
    /// # Errors
    /// This never errors today (all 16-bit lengths are valid); it returns [`BoltResult`] so the
    /// signature is stable if a future framing extension (e.g. oversized-message limits) adds a
    /// validity check.
    pub fn next_frame(&mut self) -> BoltResult<Option<Frame>> {
        loop {
            // Need at least a 2-byte length header to proceed.
            if self.inbox.len() < 2 {
                return Ok(None);
            }
            let len = usize::from(u16::from_be_bytes([self.inbox[0], self.inbox[1]]));

            if len == 0 {
                // End-of-message / NOOP marker.
                self.inbox.drain(..2);
                if self.in_message {
                    let payload = std::mem::take(&mut self.assembling);
                    self.in_message = false;
                    return Ok(Some(Frame::Message(payload)));
                }
                return Ok(Some(Frame::Noop));
            }

            // A data chunk: wait until the full header+payload has arrived.
            let total = 2 + len;
            if self.inbox.len() < total {
                return Ok(None);
            }
            self.assembling.extend_from_slice(&self.inbox[2..total]);
            self.in_message = true;
            self.inbox.drain(..total);
            // Loop: there may be more chunks (or the terminating marker) already buffered.
        }
    }

    /// Whether any buffered bytes remain unparsed (a partial chunk awaiting more input).
    #[must_use]
    pub fn has_buffered(&self) -> bool {
        !self.inbox.is_empty() || !self.assembling.is_empty()
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
