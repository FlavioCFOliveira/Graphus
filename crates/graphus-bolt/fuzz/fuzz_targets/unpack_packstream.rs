//! Fuzz target: the PackStream decoder (`Unpacker` + `unpack_value`) must never **panic** on
//! arbitrary bytes — it must always return `Ok(Value)` or a structured `BoltError::Decode`.
//!
//! PackStream is the Bolt wire serialization (`04 §8`): every byte a Bolt client sends is decoded
//! here, so it is a primary attack surface, and the zero-panic rule (`CLAUDE.md`) applies. Malformed
//! length headers, truncated payloads, oversized declared sizes, and nested-structure depth are
//! exactly the cases libFuzzer is good at finding. A panic/overflow/abort is a reportable crash.
//!
//! Run: `cargo +nightly fuzz run unpack_packstream --fuzz-dir crates/graphus-bolt/fuzz`.
#![no_main]

use libfuzzer_sys::fuzz_target;

use graphus_bolt::{Unpacker, unpack_value};

fuzz_target!(|data: &[u8]| {
    // Decode a single top-level PackStream value from the fuzz bytes. The decoder must tolerate any
    // byte sequence: a valid value, a clean decode error, or a truncated-input error — but never a
    // panic. We loop to drain multiple values so trailing bytes are exercised too, stopping on the
    // first error or end of input.
    let mut unpacker = Unpacker::new(data);
    // Bound the loop so a pathological input that the decoder reports as a zero-length value can not
    // spin forever in the fuzz harness; the decoder's own progress is what we are testing.
    for _ in 0..1024 {
        match unpack_value(&mut unpacker) {
            Ok(_value) => {}
            Err(_e) => break,
        }
    }
});
