#!/usr/bin/env bash
# tsan-soak.sh — the non-deterministic, soak-only THREADED concurrency lane (`rmp` #460).
#
# Runs the **real-OS-thread** owners of the parallel-race class under ThreadSanitizer. This class —
# the off-thread reader pool (#336), intra-query morsel fan-out (#339), the ConcurrentBufferPool
# contended sweep / #359 livelock, concurrent evictors, and the doublewrite ring (#411/#412) — is
# STRUCTURALLY INVISIBLE to the deterministic simulator (DST/VOPR), which runs the engine on one
# cooperative OS thread with each statement executed atomically (see
# `specification/07-dst-simulator.md` §5.1). Its correctness is owned by the loom suites and by these
# real-OS-thread tests, NOT by DST.
#
# This lane is the NAMED OWNER of the true-parallel races. It is deliberately:
#   * NON-DETERMINISTIC — the OS scheduler decides the thread interleaving, so a run is NOT a pure
#     function of any seed; and
#   * SOAK-ONLY — it is NOT part of the byte-identical deterministic seed-replay gate
#     (`vopr --seed B --seeds K`). Feeding an OS-scheduled, ThreadSanitizer-instrumented run into the
#     determinism gate would be a category error: the gate's contract is single-threaded and
#     bit-for-bit reproducible.
#
# ThreadSanitizer needs the NIGHTLY toolchain (the `-Z sanitizer=thread` flag and an instrumented std
# via `-Z build-std`). On a stable-only machine this script prints how to obtain nightly and exits 0
# (a non-fatal skip), so it never breaks a stable CI leg; the data-race detection runs on the nightly
# soak job.
#
# Usage:
#   scripts/tsan-soak.sh            # run the threaded tests under ThreadSanitizer (needs nightly)
#   TSAN_ITERATIONS=20 scripts/tsan-soak.sh   # repeat each test N times to shake out rare interleavings
#
# This script never feeds the deterministic gate; CI wires it as its own (nightly) job.

set -euo pipefail

cd "$(dirname "$0")/.."

# The host target triple (ThreadSanitizer requires an explicit target so `-Z build-std` instruments
# the standard library for the same triple).
TARGET="$(rustc -vV | sed -n 's|host: ||p')"
ITER="${TSAN_ITERATIONS:-1}"

# ---- The named real-OS-thread owners (rmp #460) ----------------------------------------------------
# Each entry is "<crate> <integration-test-name>". These are the tests whose correctness rests on real
# thread parallelism (not the deterministic simulator). The loom suites are a separate lane (run with
# `RUSTFLAGS="--cfg loom"`), not under ThreadSanitizer.
THREADED_TESTS=(
    "graphus-server concurrent_read_scaling"
    "graphus-server concurrent_reader_serializability"
    "graphus-server panic_isolation"
    "graphus-server blocking_thread_budget"
    "graphus-server connection_stress"
    "graphus-server slow_consumer_no_head_of_line_block"
    "graphus-storage dwb_concurrent_eviction_411"
    "graphus-dst real_thread_supernode_stress"
)

# ---- Nightly + ThreadSanitizer availability check --------------------------------------------------
if ! cargo +nightly --version >/dev/null 2>&1; then
    echo "tsan-soak: the nightly toolchain is not installed; skipping the ThreadSanitizer lane."
    echo "  Install it with:  rustup toolchain install nightly --component rust-src"
    echo "  (This lane is the named owner of the parallel-race class; it must run on the nightly soak.)"
    exit 0
fi

# ThreadSanitizer flags: instrument the crates AND the standard library for the host triple. The
# `--cfg tsan` lets a test opt into TSan-aware behaviour if it ever needs to (none currently do).
export RUSTFLAGS="-Z sanitizer=thread --cfg tsan"
export RUSTDOCFLAGS="-Z sanitizer=thread"
# A second-chance TSan report format that is easier to read in CI logs; halt on the first race so the
# job fails fast and loudly (a data race is never acceptable).
export TSAN_OPTIONS="halt_on_error=1 second_deadlock_stack=1"

echo "tsan-soak: running the threaded concurrency lane under ThreadSanitizer (target=$TARGET, iterations=$ITER)."
echo "tsan-soak: this lane is NON-DETERMINISTIC and SOAK-ONLY; it does NOT feed the deterministic seed-replay gate."

fail=0
for entry in "${THREADED_TESTS[@]}"; do
    # shellcheck disable=SC2086
    set -- $entry
    crate="$1"
    test_name="$2"
    for i in $(seq 1 "$ITER"); do
        echo "==> [$crate :: $test_name] iteration $i/$ITER under ThreadSanitizer"
        # `-Z build-std` instruments std for the same target; `--release` keeps the soak tractable.
        # `--include-ignored` runs the measurement tests that are `#[ignore]`d by default (the scaling
        # tests), since the soak WANTS those heavy concurrent paths exercised.
        if ! cargo +nightly test \
            -Z build-std \
            --target "$TARGET" \
            --release \
            -p "$crate" \
            --test "$test_name" \
            -- --include-ignored --test-threads=1; then
            echo "tsan-soak: FAILURE in [$crate :: $test_name] (a data race or a test failure under TSan)."
            fail=1
        fi
    done
done

if [ "$fail" -ne 0 ]; then
    echo "tsan-soak: at least one threaded test failed under ThreadSanitizer."
    exit 1
fi

echo "tsan-soak: all threaded concurrency tests passed under ThreadSanitizer."
