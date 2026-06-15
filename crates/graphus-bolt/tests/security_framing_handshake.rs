//! Security regression battery for the **chunk framing** (`Dechunker`) and the **handshake** parsers
//! — the two byte-level entry points a peer hits before any PackStream message is decoded.
//!
//! Threat model: a peer streams adversarial chunk headers / handshake bytes. The framer must bound
//! the reassembled message size (no unbounded buffering = OOM), and the handshake parsers must reject
//! malformed input with errors, never panic or read out of bounds.

use graphus_bolt::framing::{Dechunker, Frame};
use graphus_bolt::handshake::{MANIFEST_V1_REQUEST, parse_client_handshake, parse_manifest_choice};

// ---- framing: reassembly size cap (CWE-400 / CWE-770) -----------------------------------------

#[test]
fn unbounded_chunk_stream_is_capped_not_buffered_to_oom() {
    // A peer that never sends the 00 00 terminator and keeps streaming non-empty chunks would force
    // unbounded reassembly buffering. With a small cap, the framer aborts with a Decode error well
    // before exhausting memory. We use a tiny 1 KiB cap and feed > 1 KiB of chunk payload.
    let mut d = Dechunker::with_max_message_size(1024);
    // One chunk header (len = 600) + 600 payload bytes, twice → 1200 bytes assembled, no terminator.
    let mut stream = Vec::new();
    for _ in 0..2 {
        stream.extend_from_slice(&600u16.to_be_bytes());
        stream.extend(std::iter::repeat_n(0x41, 600));
    }
    d.push(&stream);
    let err = d
        .next_frame()
        .expect_err("reassembly past the cap must be a framing error, not unbounded buffering");
    assert!(format!("{err}").contains("maximum size"));
}

#[test]
fn giant_chunk_header_is_rejected_before_buffering() {
    // A single chunk announcing 65535 bytes but only 4 present: the framer must wait (Ok(None)) for
    // the rest rather than allocate based on the header — and with a cap below the header it rejects.
    let mut d = Dechunker::with_max_message_size(1024);
    let mut stream = Vec::new();
    stream.extend_from_slice(&65535u16.to_be_bytes());
    stream.extend_from_slice(&[0x41, 0x42, 0x43, 0x44]);
    d.push(&stream);
    // 65535 > 1024 cap → rejected immediately (before waiting for the missing payload).
    assert!(d.next_frame().is_err());
}

#[test]
fn partial_header_waits_for_more_bytes() {
    // Only one byte of the 2-byte chunk header is present: must return Ok(None), not panic/index OOB.
    let mut d = Dechunker::new();
    d.push(&[0x00]);
    assert_eq!(d.next_frame().unwrap(), None);
}

#[test]
fn bare_terminator_is_a_noop_not_a_panic() {
    // 00 00 with no preceding payload is a NOOP keep-alive, not an empty message.
    let mut d = Dechunker::new();
    d.push(&[0x00, 0x00]);
    assert_eq!(d.next_frame().unwrap(), Some(Frame::Noop));
}

#[test]
fn byte_dribbled_chunk_reassembles_correctly() {
    // A realistic hostile-ish transport delivers bytes one at a time. The framer must reassemble the
    // message correctly regardless of slicing — no state confusion across `push` calls.
    let mut d = Dechunker::new();
    // Chunk: len=3, "abc", then terminator 00 00.
    let wire = [0x00, 0x03, b'a', b'b', b'c', 0x00, 0x00];
    let mut frame = None;
    for b in wire {
        d.push(&[b]);
        if let Some(f) = d.next_frame().unwrap() {
            frame = Some(f);
        }
    }
    assert_eq!(frame, Some(Frame::Message(b"abc".to_vec())));
}

// ---- handshake: length / magic / bounds (CWE-125 resistance) ----------------------------------

#[test]
fn handshake_wrong_length_errors() {
    assert!(parse_client_handshake(&[]).is_err());
    assert!(parse_client_handshake(&[0x60, 0x60, 0xB0, 0x17]).is_err()); // magic only, no proposals
    assert!(parse_client_handshake(&[0u8; 19]).is_err()); // one byte short
    assert!(parse_client_handshake(&[0u8; 21]).is_err()); // one byte long
}

#[test]
fn handshake_bad_magic_errors() {
    let mut bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
    bytes.extend_from_slice(&[0u8; 16]);
    assert!(parse_client_handshake(&bytes).is_err());
}

#[test]
fn handshake_correct_length_and_magic_parses() {
    let mut bytes = vec![0x60, 0x60, 0xB0, 0x17];
    bytes.extend_from_slice(&[0x00, 0x00, 0x04, 0x05]); // propose 5.4
    bytes.extend_from_slice(&[0u8; 12]); // three empty slots
    assert!(parse_client_handshake(&bytes).is_ok());
}

// ---- manifest choice: varint bounds (CWE-190 / CWE-400) ---------------------------------------

#[test]
fn manifest_choice_too_short_errors() {
    // Fewer than 4 version bytes → clean Handshake error, never an index panic.
    assert!(parse_manifest_choice(&[0x00, 0x00]).is_err());
    assert!(parse_manifest_choice(&[]).is_err());
}

#[test]
fn manifest_choice_truncated_varint_errors() {
    // 4 version bytes then a varint whose continuation bit is set but no further byte follows.
    let bytes = [0x00, 0x00, 0x04, 0x05, 0x80];
    assert!(parse_manifest_choice(&bytes).is_err());
}

#[test]
fn manifest_choice_overlong_varint_overflow_errors() {
    // A capabilities varint with eleven continuation bytes overflows u64; the reader must reject it
    // rather than silently shifting bits off the top (CWE-190).
    let mut bytes = vec![0x00, 0x00, 0x04, 0x05];
    bytes.extend(std::iter::repeat_n(0x80, 11)); // never-terminating / overlong
    assert!(parse_manifest_choice(&bytes).is_err());
}

#[test]
fn manifest_request_marker_is_recognised() {
    // Sanity: the marker constant round-trips through the wire form used by detection.
    assert_eq!(MANIFEST_V1_REQUEST, [0x00, 0x00, 0x01, 0xFF]);
}
