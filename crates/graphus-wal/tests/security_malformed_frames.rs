//! Red-team security tests for `graphus-wal` frame decoding against a tampered/corrupted/truncated
//! log.
//!
//! Threat model: every byte fed to `LogRecord::decode` / `LogRecordRef::decode` /
//! `CheckpointSnapshot::decode` may have been written by an attacker with filesystem access. The
//! WAL CRC32C is **unkeyed**, so a tampered frame can carry a self-consistent CRC. The decoder must
//! never panic, read out of bounds, or pre-allocate based on an untrusted length/count field.
//!
//! These tests assert the SECURE post-conditions that already hold (regression guard), and would
//! catch a future change that reintroduces an OOB/OOM/panic on adversarial input. Everything runs
//! on in-memory byte buffers; nothing touches the filesystem or the running system.

use graphus_core::{PageId, TxnId};
use graphus_wal::record::{LogRecordRef, MIN_RECORD_LEN};
use graphus_wal::{CheckpointSnapshot, DecodeError, LogRecord, RecordType};

// Header field offsets (mirror the private `const`s in record.rs; layout is part of the on-disk
// format and asserted stable by the round-trip tests in that module).
const OFF_TOTAL_LEN: usize = 0;
const OFF_REDO_LEN: usize = 45;

/// Encodes a minimal valid record we can then corrupt field by field.
fn valid_frame() -> Vec<u8> {
    let mut r = LogRecord::new(RecordType::Update, TxnId(7), PageId(42));
    r.redo = b"redo".to_vec();
    r.undo = b"undo".to_vec();
    let mut out = Vec::new();
    r.encode_to(graphus_core::Lsn(1), &mut out);
    out
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

#[test]
fn empty_and_tiny_buffers_never_panic() {
    for len in 0..MIN_RECORD_LEN {
        let buf = vec![0u8; len];
        // Must return an error, never panic / index OOB.
        assert!(LogRecord::decode(&buf).is_err(), "len {len} should be undecodable");
        assert!(LogRecordRef::decode(&buf).is_err(), "ref len {len} should be undecodable");
    }
}

#[test]
fn lying_total_len_below_minimum_is_rejected() {
    let mut f = valid_frame();
    // total_len = 3 (< MIN_RECORD_LEN). Must hit the `total < MIN_RECORD_LEN` guard, not slice OOB.
    put_u32(&mut f, OFF_TOTAL_LEN, 3);
    assert!(matches!(LogRecord::decode(&f), Err(DecodeError::Corrupt)));
}

#[test]
fn lying_total_len_beyond_buffer_is_incomplete_not_oob() {
    let mut f = valid_frame();
    // total_len = u32::MAX: the `bytes.len() < total` guard must fire BEFORE any `rec[total-4]`
    // slice is attempted (which would otherwise be a wild OOB index).
    put_u32(&mut f, OFF_TOTAL_LEN, u32::MAX);
    assert!(matches!(LogRecord::decode(&f), Err(DecodeError::Incomplete)));
}

#[test]
fn gigantic_redo_len_does_not_overflow_or_oob() {
    let mut f = valid_frame();
    // redo_len = u32::MAX with an honest (small) total_len. The decoder must reject via the
    // `undo_len_off + 4 + 4 > total` bound check, NOT panic on `rec[redo_start..redo_start+redo_len]`
    // and NOT allocate ~4 GiB. (checked_add on redo_start+redo_len + the explicit bound guard.)
    put_u32(&mut f, OFF_REDO_LEN, u32::MAX);
    // Fix the CRC so the corruption is "authenticated" (unkeyed CRC = attacker can recompute it):
    let total = f.len();
    let crc = crc32c::crc32c(&f[..total - 4]);
    put_u32(&mut f, total - 4, crc);
    assert!(matches!(LogRecord::decode(&f), Err(DecodeError::Corrupt)));
    assert!(matches!(LogRecordRef::decode(&f), Err(DecodeError::Corrupt)));
}

#[test]
fn bit_flip_anywhere_is_caught_by_crc() {
    let base = valid_frame();
    for i in 0..base.len() - 4 {
        // Flip a payload/header byte but leave the stored CRC intact: must be BadCrc, never accepted.
        let mut f = base.clone();
        f[i] ^= 0xFF;
        match LogRecord::decode(&f) {
            Err(DecodeError::BadCrc | DecodeError::Corrupt | DecodeError::Incomplete) => {}
            Ok(_) => panic!("a single-byte tamper at offset {i} was accepted as valid"),
        }
    }
}

#[test]
fn truncated_tail_is_incomplete_never_oob() {
    let base = valid_frame();
    for cut in 1..base.len() {
        let f = &base[..base.len() - cut];
        // Any prefix must decode to an error (Incomplete/Corrupt), never panic.
        assert!(LogRecord::decode(f).is_err());
        assert!(LogRecordRef::decode(f).is_err());
    }
}

#[test]
fn checkpoint_huge_count_does_not_over_allocate() {
    // n_dpt = u32::MAX with no entries: must decode to None WITHOUT a ~68 GB pre-allocation.
    // `take_u64` returns None on the first iteration, so the lie fails cleanly (capacity is clamped
    // to remaining_bytes / 16).
    let mut dpt = Vec::new();
    dpt.extend_from_slice(&u32::MAX.to_le_bytes());
    dpt.extend_from_slice(&[0u8; 8]); // not even one full 16-byte entry
    assert_eq!(CheckpointSnapshot::decode(&dpt), None);
}
