#!/usr/bin/env bash
#
# Graphus durability & crash-recovery under load — the DETERMINISTIC CORE, driven by the project's DST
# (Deterministic Simulation Testing) simulator. Fully HERMETIC: no server, no Bolt driver, no Node, no
# network. Per CLAUDE.md, crash/recovery scenarios MUST be driven through the DST simulator, so this
# example REUSES the `graphus-dst` VOPR safety oracle end to end rather than reinventing it.
#
# This script doubles as an executable E2E test. It:
#   1. runs the DETERMINISTIC OLTP DURABILITY SWEEP (`durability_demo`): for each seed, a concurrent
#      overlapping-transaction workload (write-heavy create/relate/property/delete) runs under disk +
#      clock faults and a SEEDED MID-WORKLOAD CRASH, the engine is rebuilt via ARIES recovery, and the
#      FOUR ACID-durability properties (serializability / durability / atomicity / reference-model
#      equivalence) are asserted on the RECOVERED engine against the committed-only shadow LPG. It
#      proves ZERO violations and full determinism (same seed => identical recovered state), and
#      surfaces a focused seed's acked-vs-in-flight CRASH PARTITION (the empirical committed-or-nothing
#      proof). It emits the standardized, schema-versioned report.json + report.md.
#   2. cross-checks the same sweep through the `graphus-dst vopr safety` CLI (the project's PR safety
#      gate), asserting it agrees: all seeds SAFE + deterministic.
#   3. proves the ONE-COMMAND REPLAY round-trip (`durability_replay`): the real engine has NO failing
#      seed, so a SYNTHETIC failure is planted via the DST replay machinery's FailurePredicate path,
#      captured into a ReplayArtifact on disk, and replayed to the IDENTICAL failure byte-for-byte.
#
# The sibling real-server SIGKILL run + the live CPU/RAM/storage evidence (rmp #274-276) layer a real
# `graphus-server` crash on top of this same deterministic scenario; this script is its hermetic core.
#
# Usage:
#   examples/durability-crash-recovery/run.sh                         # CI-fast: 30 seeds
#   GRAPHUS_BIN_DIR=target/release examples/durability-crash-recovery/run.sh
#   DUR_PROFILE=full   examples/durability-crash-recovery/run.sh      # 100 seeds (evidence scale)
#   DUR_SEEDS=250      examples/durability-crash-recovery/run.sh      # custom seed count
#   DUR_FOCUS=7        examples/durability-crash-recovery/run.sh      # which seed's crash partition to detail
#
# Requirements: a Unix host (Linux/macOS), bash, and a checkout that builds. No openssl/node/npm/network.

set -euo pipefail

# --------------------------------------------------------------------------------------------------
# Pretty output helpers (house style)
# --------------------------------------------------------------------------------------------------
if [ -t 1 ]; then
  BOLD=$'\e[1m'; GREEN=$'\e[32m'; RED=$'\e[31m'; BLUE=$'\e[34m'; DIM=$'\e[2m'; RESET=$'\e[0m'
else
  BOLD=''; GREEN=''; RED=''; BLUE=''; DIM=''; RESET=''
fi

CHECKS=0
FAILURES=0

section() { printf '\n%s== %s ==%s\n' "$BOLD$BLUE" "$1" "$RESET"; }
info()    { printf '%s· %s%s\n' "$DIM" "$1" "$RESET"; }

# assert <description> <expected> <actual>
assert() {
  CHECKS=$((CHECKS + 1))
  if [ "$2" = "$3" ]; then
    printf '  %s✓%s %s %s(= %s)%s\n' "$GREEN" "$RESET" "$1" "$DIM" "$3" "$RESET"
  else
    FAILURES=$((FAILURES + 1))
    printf '  %s✗ %s%s — expected %s[%s]%s, got %s[%s]%s\n' \
      "$RED" "$1" "$RESET" "$BOLD" "$2" "$RESET" "$BOLD" "$3" "$RESET"
  fi
}

# --------------------------------------------------------------------------------------------------
# Locate (or build) the binaries
# --------------------------------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${GRAPHUS_BIN_DIR:-$REPO_ROOT/target/release}"
DEMO="$BIN_DIR/durability_demo"
REPLAY="$BIN_DIR/durability_replay"
DST="$BIN_DIR/graphus-dst"

PROFILE="${DUR_PROFILE:-fast}"
case "$PROFILE" in
  fast) DEFAULT_SEEDS=30 ;;
  full) DEFAULT_SEEDS=100 ;;
  *)    DEFAULT_SEEDS=30 ;;
esac
SEEDS="${DUR_SEEDS:-$DEFAULT_SEEDS}"
FOCUS="${DUR_FOCUS:-7}"

build_bin() { # <crate> <bin> <path-var-name>
  local crate="$1" bin="$2"
  section "Building $bin (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p "$crate" --bin "$bin" )
}

[ -x "$DEMO" ]   || build_bin graphus-durability-demo durability_demo
[ -x "$REPLAY" ] || build_bin graphus-durability-demo durability_replay
[ -x "$DST" ]    || build_bin graphus-dst graphus-dst
for b in "$DEMO" "$REPLAY" "$DST"; do
  [ -x "$b" ] || { echo "${RED}fatal: binary not found at $b${RESET}" >&2; exit 2; }
done

# --------------------------------------------------------------------------------------------------
# Workspace: a private temp dir for the reproducer artifact, removed on exit
# --------------------------------------------------------------------------------------------------
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/graphus-durability-XXXXXX")"
ARTIFACT="$WORKDIR/planted-repro.json"
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT INT TERM
mkdir -p "$EVIDENCE_DIR"

# --------------------------------------------------------------------------------------------------
# Step 1 — the deterministic OLTP durability sweep (workload + crash + ARIES recovery + 4-prop oracle)
# --------------------------------------------------------------------------------------------------
section "Step 1 — deterministic OLTP durability + crash-recovery sweep ($SEEDS seeds, $PROFILE profile)"
info "each seed: concurrent overlapping transactions under disk/clock faults + a mid-workload crash,"
info "rebuilt via ARIES recovery, then the 4 ACID-durability properties asserted on the recovered engine"
SWEEP_CODE=0
SWEEP_OUT="$("$DEMO" --seed 1 --seeds "$SEEDS" --focus "$FOCUS" --evidence-dir "$EVIDENCE_DIR")" || SWEEP_CODE=$?
printf '%s\n' "$SWEEP_OUT" | sed 's/^/  /'

assert "durability sweep completed with exit 0 (zero violations, deterministic)" "0" "$SWEEP_CODE"
assert "sweep reports a DURABLE verdict" "yes" \
  "$(printf '%s' "$SWEEP_OUT" | grep -q 'RESULT: DURABLE' && echo yes || echo no)"
assert "every seed was non-vacuous (acked + in-flight coexisted at a crash)" "yes" \
  "$(printf '%s' "$SWEEP_OUT" | grep -qE "non-vacuous=$SEEDS/$SEEDS" && echo yes || echo no)"
assert "focused seed's committed-or-nothing contract HOLDS" "yes" \
  "$(printf '%s' "$SWEEP_OUT" | grep -q 'committed-or-nothing.*HOLDS' && echo yes || echo no)"
assert "evidence report.json was produced" "yes" \
  "$([ -f "$EVIDENCE_DIR/report.json" ] && echo yes || echo no)"
assert "evidence report.md was produced" "yes" \
  "$([ -f "$EVIDENCE_DIR/report.md" ] && echo yes || echo no)"

# --------------------------------------------------------------------------------------------------
# Step 2 — cross-check through the graphus-dst VOPR safety CLI (the PR safety gate)
# --------------------------------------------------------------------------------------------------
section "Step 2 — cross-check via the graphus-dst VOPR safety gate"
info "the same scenario, run through the project's PR safety gate, must agree: all SAFE + deterministic"
DST_CODE=0
DST_OUT="$("$DST" vopr safety --seed 1 --seeds "$SEEDS")" || DST_CODE=$?
printf '%s\n' "$DST_OUT" | tail -n 3 | sed 's/^/  /'
assert "vopr safety gate exits 0" "0" "$DST_CODE"
assert "vopr safety gate reports all SAFE + deterministic" "yes" \
  "$(printf '%s' "$DST_OUT" | grep -qE "$SEEDS seed\(s\) checked, all SAFE" && echo yes || echo no)"

# --------------------------------------------------------------------------------------------------
# Step 3 — the one-command replay round-trip (planted synthetic failure)
# --------------------------------------------------------------------------------------------------
section "Step 3 — one-command replay round-trip (planted synthetic failure)"
info "the real engine has NO failing seed, so the failure is PLANTED via the DST replay machinery;"
info "the captured artifact must replay to the IDENTICAL failure byte-for-byte"

CAP_CODE=0
CAP_OUT="$("$REPLAY" --capture "$ARTIFACT" --seed "$FOCUS")" || CAP_CODE=$?
printf '%s\n' "$CAP_OUT" | sed 's/^/  /'
assert "planted reproducer captured (exit 0)" "0" "$CAP_CODE"
assert "reproducer artifact written to disk" "yes" "$([ -s "$ARTIFACT" ] && echo yes || echo no)"

# Capture the recorded hashes so we can prove the replay reproduced them byte-for-byte.
CAP_TRACE="$(printf '%s' "$CAP_OUT" | sed -n 's/.*expected_trace_hash=\([0-9a-f]*\).*/\1/p' | head -n1)"
CAP_STATE="$(printf '%s' "$CAP_OUT" | sed -n 's/.*expected_state_hash=\([0-9a-f]*\).*/\1/p' | head -n1)"

REP_CODE=0
REP_OUT="$("$REPLAY" --replay "$ARTIFACT")" || REP_CODE=$?
printf '%s\n' "$REP_OUT" | sed 's/^/  /'
assert "replay reproduced the failure (exit 0)" "0" "$REP_CODE"
assert "replay reports REPRODUCED (identical)" "yes" \
  "$(printf '%s' "$REP_OUT" | grep -q 'REPRODUCED (identical)' && echo yes || echo no)"

REP_TRACE="$(printf '%s' "$REP_OUT" | sed -n 's/.*trace_hash=\([0-9a-f]*\).*/\1/p' | head -n1)"
REP_STATE="$(printf '%s' "$REP_OUT" | sed -n 's/.*state_hash=\([0-9a-f]*\).*/\1/p' | head -n1)"
assert "replayed trace_hash equals the captured one (byte-identical)" "$CAP_TRACE" "$REP_TRACE"
assert "replayed state_hash equals the captured one (byte-identical)" "$CAP_STATE" "$REP_STATE"

# --------------------------------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------------------------------
section "Result"
printf '%s checks run, %s failures.\n' "$CHECKS" "$FAILURES"
if [ -f "$EVIDENCE_DIR/report.json" ]; then
  info "standardized evidence: $EVIDENCE_DIR/{report.json, report.md}"
fi
if [ "$FAILURES" -eq 0 ]; then
  printf '%s%sDURABILITY-CRASH-RECOVERY DEMONSTRATION PASSED%s — across %s deterministic seeds, Graphus\n' "$BOLD" "$GREEN" "$RESET" "$SEEDS"
  printf 'ran a concurrent OLTP workload under faults + a mid-workload crash, recovered via ARIES, and\n'
  printf 'upheld all four ACID-durability properties on the recovered engine (every acknowledged commit\n'
  printf 'survived; no in-flight effect did), fully deterministically. The planted-failure reproducer\n'
  printf 'replayed to the IDENTICAL failure byte-for-byte.\n'
  exit 0
else
  printf '%s%sDURABILITY-CRASH-RECOVERY DEMONSTRATION FAILED%s — %s assertion(s) did not hold.\n' "$BOLD" "$RED" "$RESET" "$FAILURES"
  exit 1
fi
