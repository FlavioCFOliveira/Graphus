//! Fuzz target: the Cypher lexer (`tokenize`) in isolation must never panic on arbitrary input.
//!
//! Separating the lexer from the parser lets the coverage-guided search concentrate on the
//! tokenizer's own edge cases (numeric-literal overflow, unterminated strings/escapes, exotic
//! identifiers, span arithmetic) without the parser's grammar masking them.
//!
//! Run: `cargo +nightly fuzz run tokenize_cypher --fuzz-dir crates/graphus-cypher/fuzz`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let src = String::from_utf8_lossy(data);
    let _ = graphus_cypher::tokenize(&src);
});
