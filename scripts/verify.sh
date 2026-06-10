#!/usr/bin/env bash
# verify.sh — run the FAST gates of the Graphus standing verification suite in sequence (`rmp` #27).
#
# This runs the gates that finish in seconds-to-minutes and belong on every push:
#   1. workspace build + clippy + fmt check
#   2. anomaly checker (Elle/DSG serializability)
#   3. proptest invariants (codec round-trips + order-preserving key codec)
#   4. the criterion regression gate (vs the committed baseline)
#   5. the LDBC-SNB macro harness (tiny scale)
#
# The SLOW gates are deliberately NOT run here (they are documented in VERIFICATION.md and run on a
# nightly/manual job): the loom model-check, the miri UB gate, the full Criterion suites, and any
# fuzz campaign. Pass `--with-miri` to additionally run the (slower) miri gate; pass `--with-loom`
# to add the loom model-check.
#
# Usage:
#   scripts/verify.sh                 # fast gates only
#   scripts/verify.sh --with-miri     # fast gates + miri UB gate (needs nightly + miri)
#   scripts/verify.sh --with-loom     # fast gates + loom model-check (slow)
#
# Exits non-zero on the first failing gate.
set -euo pipefail

cd "$(dirname "$0")/.."

WITH_MIRI=0
WITH_LOOM=0
for arg in "$@"; do
    case "$arg" in
        --with-miri) WITH_MIRI=1 ;;
        --with-loom) WITH_LOOM=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$1"; }

step "1/5  build + clippy + fmt (workspace)"
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check

step "2/5  anomaly gate — Elle/DSG serializability checker"
cargo test -p graphus-cypher --test elle

step "3/5  proptest invariants — codec round-trips + order-preserving key codec"
cargo test -p graphus-storage --test proptest_codecs
cargo test -p graphus-cypher --test proptest_keycodec

step "4/5  criterion regression gate — vs committed baseline (release)"
cargo run -q -p graphus-bench --release --bin bench_gate

step "5/5  LDBC-SNB macro harness — tiny scale (release)"
cargo run -q -p graphus-bench --release --bin ldbc_snb

if [ "$WITH_LOOM" = "1" ]; then
    step "loom model-check — buffer-pool latch protocol (slow)"
    RUSTFLAGS="--cfg loom" LOOM_MAX_PREEMPTIONS=3 \
        cargo test -p graphus-bufpool --test loom_bufpool --release
fi

if [ "$WITH_MIRI" = "1" ]; then
    step "miri UB gate — pure-logic crates (slow; nightly + miri required)"
    cargo +nightly miri test -p graphus-core
    cargo +nightly miri test -p graphus-wal --lib
    cargo +nightly miri test -p graphus-bolt --lib
    cargo +nightly miri test -p graphus-index --lib
    cargo +nightly miri test -p graphus-storage --lib -- \
        record:: valenc:: propenc:: labels:: heap:: paging:: tokens:: idalloc:: meta::
fi

printf '\n\033[1;32mAll requested gates passed.\033[0m\n'
