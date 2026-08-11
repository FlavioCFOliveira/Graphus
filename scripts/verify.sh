#!/usr/bin/env bash
# verify.sh — run the FAST gates of the Graphus standing verification suite in sequence (`rmp` #27).
#
# EVERY workspace gate below runs under `--profile gate` (`rmp` #1043), the optimised-and-fully-
# asserted profile defined in the root `Cargo.toml`. Measured: the whole suite takes 2139,7 s at
# `opt-level = 0` and 333,3 s here, and the profile keeps `debug_assertions` and `overflow-checks` ON
# so nothing is traded away for that — `graphus-core/tests/verification_profile_keeps_its_assertions.rs`
# proves it from inside the compiled binary and FAILS under `--release`, which is not a verification
# profile. Using one profile for every step also means one artefact graph instead of three, so clippy
# reuses what the tests built (measured: 25,4 s).
#
# The performance gates below (the criterion regression gate, LDBC, the examples suite, the release
# symbol check) stay on `--release` deliberately: their committed baselines were measured there, and
# comparing against a different profile would invalidate the comparison rather than speed it up.
#
# This runs the gates that finish in seconds-to-minutes and belong on every push:
#   1. workspace build + clippy + fmt check
#   2. anomaly checker (Elle/DSG serializability)
#   3. the read-polarity census (superset / decision / conservative storage reads)
#   4. the property visible-read record-count gate (`rmp` #967 AC2; needs --features read-probe)
#   5. the deterministic writer-scheduler suites (`rmp` #973; needs --features det-sched)
#   6. proptest invariants (codec round-trips + order-preserving key codec)
#   7. the criterion regression gate (vs the committed baseline)
#   8. the LDBC-SNB macro harness (tiny scale)
#   9. the examples suite, in BOTH modes (self-boot + attached to a running instance)
#  10. the official Neo4j driver interop suite (real drivers over Bolt; needs node/npm, python3, go + network)
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

# Each step reports what it cost. A runner whose per-step cost is invisible cannot be optimised and
# cannot be defended: the table in VERIFICATION.md carried figures nobody had remeasured since they
# were written, and "~2-4 min" for a gate is not a measurement. Now every run produces one.
GATE_T0=$(date +%s)
STEP_NAME=""
STEP_T0=0
close_step() {
    if [ -n "$STEP_NAME" ]; then
        printf '\033[2m    ↳ %s: %ds\033[0m\n' "$STEP_NAME" "$(($(date +%s) - STEP_T0))"
    fi
}
step() {
    close_step
    STEP_NAME="$1"
    STEP_T0=$(date +%s)
    printf '\n\033[1;34m==> %s\033[0m\n' "$1"
}

step "1/10 build + clippy + fmt (workspace)"
cargo build --workspace --profile gate
cargo clippy --workspace --all-targets --profile gate -- -D warnings
cargo fmt --all --check

step "2/10 anomaly gate — Elle/DSG serializability checker"
cargo test --profile gate -p graphus-cypher --test elle

# A read of the record store returns raw physical state; which answer the caller owes back is one of
# three (superset / decision / conservative, `04 §5.3`). Confusing them produced three CRITICAL
# defects, each of them behind a docstring that asserted the wrong polarity and was believed. This
# gate reads source text, costs milliseconds, and fails when a polarity-sensitive read appears or
# moves without being classified (`rmp` #905; VERIFICATION.md gate 10).
step "3/10 read-polarity census — superset / decision / conservative storage reads"
cargo test --profile gate -p graphus-cypher --test read_polarity_census
cargo test --profile gate -p graphus-storage --test scan_polarity_barrier

# Acceptance criterion 2 of `rmp` #967 — "reading the visible property does not walk the chain" —
# proven by a RECORD-READ COUNT rather than a timing, because a timing is a property of the host's
# cache and the count is a property of the algorithm. The instrumentation is a cargo FEATURE that is
# off by default (it sits on the hottest read in the engine and must not perturb the benchmark or the
# production build), and the test file is `#![cfg(feature = "read-probe")]`, so a plain
# `cargo test -p graphus-storage` compiles it away and asserts nothing.
#
# That is precisely the shape of `rmp` #960 (gate 10 below): a suite behind an opt-in feature that no
# automated gate ever enabled, so the defect it existed to catch survived on `main` with every other
# gate green. `04-technical-design.md` §11.6 was ratified by #967 itself to stop that recurring, and a
# headline acceptance criterion asserted by nothing any gate runs is the same defect again. Hence the
# explicit `--features read-probe` invocation here.
step '4/10 property visible-read record count — rmp #967 AC2 (needs --features read-probe)'
cargo test --profile gate -p graphus-storage --features read-probe --test prop_visible_read_record_count

step '4b/10 catalog counters in RELEASE — rmp #1052 (debug_assertions OFF is where it is silent)'
# The counters this suite certifies are guarded in the store by a `debug_assert!`, which the gate
# profile compiles IN — so a regression there fails on the assertion, and the suite's real claim (the
# NUMBER is right) is never the thing that failed. In a release build the same code takes its
# saturating rail in silence and writes a wrong cardinality into the durable catalog, which `rmp` #866
# then serves as the answer to `count()`. That is the failure that ships, so it gets its own run with
# the assertions compiled out: here the only thing standing between a regression and a green gate is
# the asserted value. Measured against each reverted half of the `rmp` #1052 fix, this run fails.
cargo test --release -p graphus-storage --test catalog_counts_multi_writer_1052

# `rmp` #973 puts the DST's thread interleaving under a seeded scheduler, so a concurrency defect
# reproduces from a seed the way a crash already does. Its suites are behind the opt-in `det-sched`
# cargo feature and declare `required-features`, so `cargo test --workspace` does not even COMPILE
# them — which is deliberate (the hook sits on `with_page_fetched`, the hottest read in the engine,
# and must not instrument the very paths the gates above certify).
#
# That is also, precisely, how `rmp` #960 hid: a suite behind an opt-in feature that no automated
# gate ever enabled, so the defect it existed to catch survived on `main` with every other gate
# green. A headline acceptance criterion asserted only by a suite nothing runs is that defect again.
# Hence the explicit `--features det-sched` invocation here, covering EVERY suite and the
# scheduler's own unit tests.
#
# The clippy run below is part of the same argument. The workspace lint gate enables no optional
# feature, so these test targets are not merely unlinted — they are not compiled at all by it, and
# two of them had accumulated `-D warnings` failures that no gate could see. A suite nothing lints
# rots exactly the way a suite nothing runs does.
step '5/10 deterministic writer scheduler — rmp #973/#1034 (needs --features det-sched)'
cargo clippy --profile gate -p graphus-dst --features det-sched --all-targets -- -D warnings
cargo test --profile gate -p graphus-dst --features det-sched --lib detsched::
cargo test --profile gate -p graphus-dst --features det-sched --test det_scheduler_gc_reader_811
cargo test --profile gate -p graphus-dst --features det-sched --test det_scheduler_elle_oracle
cargo test --profile gate -p graphus-dst --features det-sched --test det_scheduler_multi_writer_1034
cargo test --profile gate -p graphus-dst --features det-sched --test det_scheduler_double_rollback_1051
cargo test --profile gate -p graphus-dst --features det-sched --test det_scheduler_catalog_counts_1052
cargo test --profile gate -p graphus-dst --features det-sched --test det_scheduler_unpublished_delta_1053

# `rmp` #973 acceptance criterion 3 — the production cost is ZERO — asserted mechanically rather
# than argued. The release build below reproduces the container image's `-p graphus-server` package
# selection (`Dockerfile`, which additionally cross-compiles with `--target "$RUST_TARGET"`; the
# target does not change which features the resolve reaches, which is the only thing this check is
# about). That selection is what makes the check meaningful: `det-sched` is enabled by no dependency
# declaration anywhere, so a `-p graphus-server` resolve cannot reach it, and every scheduler symbol
# must therefore be absent from the shipped binary.
#
# The patterns are anchored on `graphus_core::sched::` and not on `sched` — matching loosely finds
# eight `tokio::runtime::blocking::schedule::BlockingSchedule` symbols and would make this gate
# report a violation that does not exist. A gate that cries wolf is retired by the next person who
# sees it, so it is anchored here on purpose.
step '5b/10 deterministic scheduler costs production NOTHING — rmp #973 AC3'
cargo build --release --locked -p graphus-server
for pattern in 'graphus_core::sched::' 'detsched' 'YieldSite'; do
    found=$(nm -C target/release/graphus-server | grep -c -- "$pattern" || true)
    if [ "$found" -ne 0 ]; then
        echo "FAIL: $found symbol(s) matching '$pattern' in the release server binary;" >&2
        echo "      the det-sched seam must compile to nothing outside the DST." >&2
        exit 1
    fi
done
echo "    no scheduler symbol reaches the release binary (3 patterns, 0 matches)"

step "6/10 proptest invariants — codec round-trips + order-preserving key codec"
cargo test --profile gate -p graphus-storage --test proptest_codecs
cargo test --profile gate -p graphus-cypher --test proptest_keycodec

step "7/10 criterion regression gate — vs committed baseline (release)"
cargo run -q -p graphus-bench --release --bin bench_gate

step "8/10 LDBC-SNB macro harness — tiny scale (release)"
cargo run -q -p graphus-bench --release --bin ldbc_snb

# The examples are the project's instrument for exposing regressions and resource inefficiencies in a
# REAL, end-to-end server. They only work as an instrument if they are actually run — every one of the
# evidence defects this gate now guards against (a failing example sitting unnoticed on `main`, reports
# publishing fabricated zeros, a baseline gate comparing 0.0 to 0.0) survived precisely because nothing
# executed the suite. It runs BOTH modes: self-boot, and attached to an already-running instance.
step "9/10 examples suite — E2E, both modes (self-boot + attach to a running instance)"
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
step "10/10 official Neo4j driver interop — real drivers over Bolt (needs node/npm, python3, go + network)"
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
cargo test --profile gate -p graphus-server --features neo4j-interop --test neo4j_driver_interop -- --test-threads=1

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

close_step
printf '\n\033[1;32mAll requested gates passed in %ds.\033[0m\n' "$(($(date +%s) - GATE_T0))"
