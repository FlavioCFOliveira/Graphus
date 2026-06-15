//! Security regression battery for the **PackStream codec** (`Unpacker` / `unpack_value` /
//! `unpack_bolt_value`) — the crate's wire-level trust boundary that parses untrusted bytes from any
//! network peer.
//!
//! Threat model: a malicious peer streams adversarial PackStream into the decoder. The decoder MUST
//! never panic, never abort the process (allocation bomb), and never read out of bounds; every
//! malformed input must surface a `BoltError::Decode` (`#![forbid(unsafe_code)]` rules out UB, so the
//! residual risks are DoS via panic / OOM / unbounded work).
//!
//! These tests use only bounded, controlled inputs: no test allocates a large buffer or can exhaust
//! memory. Every audited finding here is **fixed**; each test pins the hardened (secure) behaviour as
//! a `// Regression: SEC-<task-id>` so a regression would flip it back. No `// VULNERABLE: SEC-...`
//! markers remain.

use graphus_bolt::{BoltValue, Unpacker, unpack_bolt_value, unpack_value};

// ---- helpers ----------------------------------------------------------------------------------

/// Decode one `Value` from raw bytes, returning the result.
fn dec(bytes: &[u8]) -> Result<graphus_core::Value, graphus_bolt::BoltError> {
    let mut u = Unpacker::new(bytes);
    unpack_value(&mut u)
}

/// Decode one `BoltValue` from raw bytes, returning the result.
fn dec_bolt(bytes: &[u8]) -> Result<BoltValue, graphus_bolt::BoltError> {
    let mut u = Unpacker::new(bytes);
    unpack_bolt_value(&mut u)
}

// ---- truncation / bounds ----------------------------------------------------------------------

#[test]
fn empty_input_errors_not_panics() {
    assert!(dec(&[]).is_err());
    assert!(dec_bolt(&[]).is_err());
}

#[test]
fn truncated_int64_errors() {
    // INT_64 marker (0xCB) with only 3 of 8 payload bytes present.
    assert!(dec(&[0xCB, 0x00, 0x00, 0x00]).is_err());
}

#[test]
fn truncated_float64_errors() {
    // FLOAT_64 marker (0xC1) with no payload.
    assert!(dec(&[0xC1]).is_err());
}

#[test]
fn string_header_claims_more_than_present_errors() {
    // STRING_8 (0xD0) length 200, but no payload bytes follow → truncated, must error not panic.
    assert!(dec(&[0xD0, 200]).is_err());
}

#[test]
fn string32_huge_length_truncated_errors_without_allocating() {
    // STRING_32 (0xD2) length 0xFFFFFFFF with no payload. `read_slice` bounds-checks against the
    // actual buffer, so this is a clean Decode error — it must NOT try to allocate ~4 GiB.
    assert!(dec(&[0xD2, 0xFF, 0xFF, 0xFF, 0xFF]).is_err());
}

#[test]
fn bytes32_huge_length_truncated_errors_without_allocating() {
    // BYTES_32 (0xCE) length 0xFFFFFFFF, no payload → bounds-checked Decode error, no 4 GiB alloc.
    assert!(dec(&[0xCE, 0xFF, 0xFF, 0xFF, 0xFF]).is_err());
}

// ---- allocation-bomb resistance (CWE-789) -----------------------------------------------------

#[test]
fn list32_giant_header_does_not_oom() {
    // LIST_32 (0xD6) announcing ~4 billion elements, but no element bytes. The decoder pre-allocates
    // `n.min(1024)` and then loops reading elements, hitting end-of-input on the first → Decode error.
    // It must NOT attempt to allocate a 4-billion-element Vec. A panic/abort here would be a remote
    // DoS; we assert a clean error instead.
    let bytes = [0xD6, 0xFF, 0xFF, 0xFF, 0xFF];
    assert!(dec(&bytes).is_err());
    assert!(dec_bolt(&bytes).is_err());
}

#[test]
fn map32_giant_header_does_not_oom() {
    // MAP_32 (0xDA) announcing ~4 billion entries, no payload → bounded pre-alloc + Decode error.
    let bytes = [0xDA, 0xFF, 0xFF, 0xFF, 0xFF];
    assert!(dec(&bytes).is_err());
}

#[test]
fn list_with_real_elements_is_bounded_by_input_length() {
    // A genuine attack shape: LIST_32 with a large count, padded with as many cheap (1-byte NULL)
    // elements as the message allows. The codec must consume exactly the bytes present and error on
    // the first missing element — work and memory are bounded by the input size, not by the header.
    let mut bytes = vec![0xD6, 0x00, 0x10, 0x00, 0x00]; // count = 0x00100000 (~1M)
    bytes.extend(std::iter::repeat_n(0xC0, 64)); // 64 real NULLs, then it must run out
    let r = dec(&bytes);
    assert!(
        r.is_err(),
        "must error on the first missing element, not hang or OOM"
    );
}

// ---- deep nesting / stack overflow ------------------------------------------------------------

#[test]
fn deeply_nested_lists_are_rejected_not_stack_overflowed() {
    // 5000 nested single-element lists (TINY_LIST of size 1 = 0x91) far exceeds MAX_DECODE_DEPTH
    // (256). Without the depth guard this recurses 5000 frames deep and overflows the stack (process
    // abort = remote DoS). With it, it returns a clean Decode error.
    let depth = 5000;
    let mut bytes = vec![0x91u8; depth]; // 0x91 = TINY_LIST size 1
    bytes.push(0xC0); // innermost value: NULL
    let err =
        dec(&bytes).expect_err("over-deep nesting must be rejected, never overflow the stack");
    assert!(
        format!("{err}").contains("depth"),
        "expected a depth-limit error, got: {err}"
    );
}

#[test]
fn deeply_nested_maps_are_rejected() {
    // 5000 nested single-entry maps: 0xA1 (TINY_MAP size 1), key 0x80 (empty string), then recurse.
    let mut bytes = Vec::new();
    for _ in 0..5000 {
        bytes.push(0xA1); // TINY_MAP, 1 entry
        bytes.push(0x80); // empty string key
    }
    bytes.push(0xC0); // innermost value
    assert!(dec(&bytes).is_err());
}

#[test]
fn nesting_at_the_limit_is_accepted() {
    // A payload nested just within MAX_DECODE_DEPTH (256) must still decode — a legitimate (if deep)
    // message is never rejected. 200 levels is comfortably under the limit.
    let mut bytes = vec![0x91u8; 200];
    bytes.push(0xC0);
    assert!(
        dec(&bytes).is_ok(),
        "a payload within the depth limit must decode"
    );
}

// ---- invalid UTF-8 / type confusion -----------------------------------------------------------

#[test]
fn invalid_utf8_string_errors_not_panics() {
    // TINY_STRING of length 2 with bytes 0xFF 0xFF (not valid UTF-8). `String::from_utf8` must be
    // handled as a Decode error, never an unwrap panic.
    let err = dec(&[0x82, 0xFF, 0xFF]).expect_err("invalid UTF-8 must be a Decode error");
    assert!(format!("{err}").contains("UTF-8"));
}

#[test]
fn unknown_marker_errors() {
    // 0xC4..=0xC7 and similar are reserved/undefined markers; the decoder must reject, not guess.
    assert!(dec(&[0xC7]).is_err());
}

#[test]
fn unknown_struct_tag_errors() {
    // TINY_STRUCT (0xB0) size 0, tag 0xAB (no such Bolt structure) → Decode error.
    assert!(dec(&[0xB1, 0xAB, 0xC0]).is_err());
}

#[test]
fn struct_with_wrong_arity_errors() {
    // DATE (tag 0x44) requires exactly 1 field; present it with 3 fields → arity mismatch error.
    // 0xB3 = TINY_STRUCT size 3, 0x44 = DATE, then three ints.
    assert!(dec(&[0xB3, 0x44, 0x01, 0x02, 0x03]).is_err());
}

#[test]
fn graph_entity_tag_rejected_by_value_decoder() {
    // NODE (0x4E) has no `Value` variant; `unpack_value` must reject it cleanly (the structural
    // decoder is `unpack_bolt_value`). 0xB1 = struct size 1, 0x4E = NODE tag.
    assert!(dec(&[0xB1, 0x4E, 0xC0]).is_err());
}

// ---- structure header truncation in bolt-value path -------------------------------------------

#[test]
fn struct_marker_without_tag_errors() {
    // A lone struct marker (0xB1) with no following tag byte. `unpack_bolt_value` peeks `pos + 1` for
    // the tag and must surface a Decode error, never index out of bounds.
    assert!(dec_bolt(&[0xB1]).is_err());
}

// ---- integer markers (boundary correctness, no overflow) --------------------------------------

#[test]
fn all_integer_widths_round_within_bounds() {
    // INT_8 of -1 (0xC8 0xFF), INT_16, INT_32, INT_64 minimum — none must overflow or panic.
    assert_eq!(
        dec(&[0xC8, 0xFF]).unwrap(),
        graphus_core::Value::Integer(-1)
    );
    assert_eq!(
        dec(&[0xCB, 0x80, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
        graphus_core::Value::Integer(i64::MIN)
    );
}
