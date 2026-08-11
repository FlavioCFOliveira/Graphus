//! **The verification profile may be fast; it may not be quiet** (`rmp` #1043).
//!
//! The gates run under an OPTIMISED profile (`[profile.gate]`: `opt-level = 1`), because measured on
//! this workspace the same 452 test binaries and 6347 tests take 2139,7 s unoptimised and 333,3 s
//! optimised — the cost was never compilation (a warm `--no-run` returns in 0,58 s), it was executing
//! unoptimised code. That change is only safe under one condition, and this file is that condition
//! asserted rather than trusted.
//!
//! # The trap this closes
//!
//! `--release` is the obvious way to make a Rust test suite fast, and it is the wrong one here: it
//! turns off `debug_assertions` and `overflow-checks`, so every `debug_assert!` in the engine and
//! every arithmetic overflow check disappears. The suite would then run FASTER and prove LESS, and
//! nothing in the output would say so — a green run in which whole classes of assertion were compiled
//! away is indistinguishable from a green run in which they held. That is the same failure mode as a
//! gate nobody executes (`rmp` #960): the signal reads "pass" either way.
//!
//! So `[profile.gate]` sets `debug-assertions = true` and `overflow-checks = true` EXPLICITLY, rather
//! than relying on inheriting them, and these two tests prove they survived — from inside the compiled
//! binary, which is the only place that can answer. Reading `Cargo.toml` proves the intent; this
//! proves the artefact.
//!
//! # Why this also fails under `--release`, deliberately
//!
//! These tests fail when the suite is run with `cargo test --release`, and that is the intended
//! behaviour, not an oversight. `--release` is not a verification profile for this project: anyone
//! reaching for it to speed the gates up is trading assertions for seconds without being told. Failing
//! loudly, with the reason in the message, is how they are told. The supported fast path is
//! `--profile gate`, which is faster than `--release` to BUILD and keeps every assertion.

/// `debug_assert!` must still be compiled in.
///
/// The engine's invariants are stated with `debug_assert!` in the hot paths where a release build
/// cannot afford them — latch ordering, slot bookkeeping, delta-chain shape. Under a profile with
/// `debug-assertions = false` every one of those statements is erased at compile time, and the tests
/// that exist to trip them pass by construction.
// `clippy::assertions_on_constants` is right in general and wrong here: the whole point is that the
// constant is decided by the profile this binary was compiled under, so asserting it is asserting a
// property of the artefact. Rewriting it into a runtime shape to satisfy the lint would obscure that.
#[allow(clippy::assertions_on_constants)]
#[test]
fn debug_assertions_are_compiled_into_the_verification_binary() {
    assert!(
        cfg!(debug_assertions),
        "this binary was built WITHOUT debug assertions, so every `debug_assert!` in the engine was \
         erased at compile time and the suite is proving less than it appears to. The verification \
         profile is `--profile gate` (optimised AND fully asserted); `--release` is not a \
         verification profile and must not be used to run the gates (`rmp` #1043)."
    );
}

/// Arithmetic overflow must still panic rather than wrap.
///
/// Wrapping arithmetic is how an id allocator hands out a live slot twice and how a counter that must
/// never pass zero silently becomes `u64::MAX` — a defect this project has already met
/// (`saturating_sub` is not `fetch_sub`). `overflow-checks` is what turns that into a panic at the
/// point of the mistake instead of a wrong answer a hundred layers away.
///
/// The operands go through `black_box` so the expression cannot be folded at compile time: a literal
/// `255u8 + 1` is a compile ERROR, and a constant the optimiser can see through would be evaluated
/// before the check this test is about ever applies.
#[test]
fn overflow_checks_are_compiled_into_the_verification_binary() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {})); // the panic below is the expected outcome, not a report
    let overflowed = std::panic::catch_unwind(|| {
        let a: u8 = std::hint::black_box(255);
        let b: u8 = std::hint::black_box(1);
        a + b
    });
    std::panic::set_hook(previous);

    assert!(
        overflowed.is_err(),
        "255u8 + 1 wrapped instead of panicking, so this binary was built WITHOUT overflow checks: \
         an id allocator handing out a live slot twice, or a counter wrapping past zero, would now \
         produce a wrong answer instead of a panic at the point of the mistake. The verification \
         profile is `--profile gate` (optimised AND fully asserted); `--release` is not a \
         verification profile and must not be used to run the gates (`rmp` #1043)."
    );
}
