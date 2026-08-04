#!/usr/bin/env bash
# verify.sh — run the FAST gates of the Graphus standing verification suite in sequence (`rmp` #27).
#
# This runs the gates that finish in seconds-to-minutes and belong on every push:
#   1. workspace build + clippy + fmt check
#   2. anomaly checker (Elle/DSG serializability)
#   3. the read-polarity census (superset / decision / conservative storage reads)
#   4. the property visible-read record-count gate (`rmp` #967 AC2; needs --features read-probe)
#   5. proptest invariants (codec round-trips + order-preserving key codec)
#   6. the criterion regression gate (vs the committed baseline)
#   7. the LDBC-SNB macro harness (tiny scale)
#   8. the examples suite, in BOTH modes (self-boot + attached to a running instance)
#   9. the official Neo4j driver interop suite (real drivers over Bolt; needs node/npm, python3, go + network)
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

step "1/9  build + clippy + fmt (workspace)"
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check

step "2/9  anomaly gate — Elle/DSG serializability checker"
cargo test -p graphus-cypher --test elle

# A read of the record store returns raw physical state; which answer the caller owes back is one of
# three (superset / decision / conservative, `04 §5.3`). Confusing them produced three CRITICAL
# defects, each of them behind a docstring that asserted the wrong polarity and was believed. This
# gate reads source text, costs milliseconds, and fails when a polarity-sensitive read appears or
# moves without being classified (`rmp` #905; VERIFICATION.md gate 10).
step "3/9  read-polarity census — superset / decision / conservative storage reads"
cargo test -p graphus-cypher --test read_polarity_census
cargo test -p graphus-storage --test scan_polarity_barrier

# Acceptance criterion 2 of `rmp` #967 — "reading the visible property does not walk the chain" —
# proven by a RECORD-READ COUNT rather than a timing, because a timing is a property of the host's
# cache and the count is a property of the algorithm. The instrumentation is a cargo FEATURE that is
# off by default (it sits on the hottest read in the engine and must not perturb the benchmark or the
# production build), and the test file is `#![cfg(feature = "read-probe")]`, so a plain
# `cargo test -p graphus-storage` compiles it away and asserts nothing.
#
# That is precisely the shape of `rmp` #960 (gate 11 below): a suite behind an opt-in feature that no
# automated gate ever enabled, so the defect it existed to catch survived on `main` with every other
# gate green. `04-technical-design.md` §11.6 was ratified by #967 itself to stop that recurring, and a
# headline acceptance criterion asserted by nothing any gate runs is the same defect again. Hence the
# explicit `--features read-probe` invocation here.
step "4/9  property visible-read record count — `rmp` #967 AC2 (needs --features read-probe)"
cargo test -p graphus-storage --features read-probe --test prop_visible_read_record_count

step "5/9  proptest invariants — codec round-trips + order-preserving key codec"
cargo test -p graphus-storage --test proptest_codecs
cargo test -p graphus-cypher --test proptest_keycodec

step "6/9  criterion regression gate — vs committed baseline (release)"
cargo run -q -p graphus-bench --release --bin bench_gate

step "7/9  LDBC-SNB macro harness — tiny scale (release)"
cargo run -q -p graphus-bench --release --bin ldbc_snb

# The examples are the project's instrument for exposing regressions and resource inefficiencies in a
# REAL, end-to-end server. They only work as an instrument if they are actually run — every one of the
# evidence defects this gate now guards against (a failing example sitting unnoticed on `main`, reports
# publishing fabricated zeros, a baseline gate comparing 0.0 to 0.0) survived precisely because nothing
# executed the suite. It runs BOTH modes: self-boot, and attached to an already-running instance.
step "8/9  examples suite — E2E, both modes (self-boot + attach to a running instance)"
scripts/examples-gate.sh

# The official-driver interop suite is the ONLY test that proves the four inviolable wire claims (Bolt,
# PackStream, and the Cypher and transaction semantics a real client depends on) against a real,
# unmodified Neo4j driver rather than against Graphus's own view of them. It lives behind the opt-in
# `neo4j-interop` cargo feature so that a plain `cargo test` stays hermetic — it needs `node`/`npm` and
# the network to install the driver.
#
# That opt-in is exactly how `rmp` #960 hid. The suite has existed since 2026-06-15 and no automated
# gate has ever enabled the feature, so when #865 introduced the defect on 2026-07-26,
# `official_neo4j_driver_full_crud_nodes_and_edges` began failing on `main` while every gate that does
# run stayed green — the regression was invisible to all of them. The suite is therefore a GATE here,
# not an optional extra.
#
# The suite now spans THREE official driver ecosystems (`rmp` #907): the JavaScript driver via
# `node`/`npm`, the Python driver via a `python3` venv created in the test's own temporary directory,
# and the Go driver via a `go` module built there. Each is provisioned hermetically per test and
# removed with the temporary directory, so nothing is installed on the machine — but the three
# toolchains themselves must be present.
#
# It is a HARD failure when any of them is missing, never a skip. A gate that quietly skips is
# indistinguishable from a gate that passes, which is the failure mode being closed; the prerequisites
# are documented in VERIFICATION.md and in the suite's own module docs. Checking them HERE also means a
# missing toolchain is reported at the gate, with a clear message, instead of deep inside a test helper.
step "9/9  official Neo4j driver interop — real drivers over Bolt (needs node/npm, python3, go + network)"
missing_interop_tools=""
for tool in node npm python3 go; do
    command -v "$tool" >/dev/null 2>&1 || missing_interop_tools="$missing_interop_tools $tool"
done
if [ -n "$missing_interop_tools" ]; then
    echo "FAIL: the interop gate needs these on PATH (see VERIFICATION.md):$missing_interop_tools" >&2
    echo "      They are a prerequisite of scripts/verify.sh, not an optional extra: this suite is" >&2
    echo "      the only proof that the official driver ecosystem can talk to Graphus." >&2
    exit 1
fi
# Serial: the tests each boot a server and share one npm prefix, one pip cache and one Go module
# cache, so they must not race on them.
cargo test -p graphus-server --features neo4j-interop --test neo4j_driver_interop -- --test-threads=1

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
