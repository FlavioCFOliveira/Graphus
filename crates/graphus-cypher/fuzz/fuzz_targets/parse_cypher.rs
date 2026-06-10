//! Fuzz target: the full Cypher front end (`tokenize` → `parse`) must never **panic** on arbitrary
//! input — it must always return `Ok(Query)` or a structured `Err` (`SyntaxError`/`GraphusError`).
//!
//! A parser is the server's most exposed attack surface (every byte a client sends reaches it), and
//! the project's hard rule is **zero panics in production** (`CLAUDE.md`). libFuzzer drives the
//! coverage-guided search; any panic, overflow, or assertion failure is a reportable crash.
//!
//! Run: `cargo +nightly fuzz run parse_cypher --fuzz-dir crates/graphus-cypher/fuzz`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The parser's input is text; interpret the fuzz bytes as UTF-8 (lossily so every input is
    // exercised, including invalid byte sequences mapped to U+FFFD — the server itself decodes the
    // wire bytes to a `&str` before parsing, so this matches the real entry condition).
    let src = String::from_utf8_lossy(data);
    // Whatever the result, it must be a value or a structured error — never a panic/abort.
    let _ = graphus_cypher::parse(&src);
});
