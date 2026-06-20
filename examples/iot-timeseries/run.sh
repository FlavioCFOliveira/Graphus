#!/usr/bin/env bash
#
# Graphus IoT / time-series event-graph demonstration — sustained ingest + retention churn and a
# storage-RECLAMATION proof (the on-disk footprint plateaus under churn instead of growing without
# bound).
#
# This script doubles as an executable E2E test. It:
#   1. proves the deterministic, seeded time-series generator (`iot_gen`) is BYTE-IDENTICAL per seed
#      by generating `stream.cypher` twice and diffing (rmp #294);
#   2. runs the sustained ingest + retention churn workload + the storage-reclamation proof
#      (`iot_churn`) against the REAL engine, asserting (a) the live `:Reading` count reaches and
#      holds a STEADY STATE around the retention window (rmp #295), and (b) the on-disk footprint
#      reaches a PLATEAU — bounded despite total-ingested >> window — reporting the page high-water
#      mark (rmp #296);
#   3. runs a short `--no-gc` CONTRAST slice showing the linear-growth curve the GC pass flattens
#      (informational);
#   4. (optional) drives the same ingest+retention churn over a real Bolt-over-UDS WIRE with
#      `graphus-cli` against a booted server, asserting the steady-state live count over the wire.
#
# Steps 1–3 are HERMETIC and always run (the `iot_churn` driver runs the real engine in-process —
# see README.md → "Transport" for why the reclamation proof needs the in-process GC seam). Step 4 is
# OPT-IN via RUN_WIRE (default ON; set RUN_WIRE=0 to skip).
#
# Usage:
#   examples/iot-timeseries/run.sh                       # builds binaries if needed, then runs
#   GRAPHUS_BIN_DIR=target/release  examples/iot-timeseries/run.sh
#   IOT_PROFILE=large               examples/iot-timeseries/run.sh   # evidence-scale churn
#   RUN_WIRE=0                      examples/iot-timeseries/run.sh   # skip the Bolt-over-UDS wire demo
#
# Requirements: a Unix host (Linux/macOS), bash, and a checkout that builds. No network/openssl/node.

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

GEN="$BIN_DIR/iot_gen"
CHURN="$BIN_DIR/iot_churn"
EVIDENCE_BIN="$BIN_DIR/iot_evidence"
CMP_BIN="$BIN_DIR/iot_baseline_cmp"
SERVER="$BIN_DIR/graphus-server"
CLI="$BIN_DIR/graphus-cli"

PROFILE="${IOT_PROFILE:-fast}"
RUN_WIRE="${RUN_WIRE:-1}"
# Long-running steady-state knob: override the number of churn ticks the evidence run drives. The
# default is the profile's own (short, CI-fast) tick count; set IOT_TICKS for a longer steady-state
# demonstration (the plateau holds for as many ticks as you ask — the footprint stays flat). It is
# applied to the EVIDENCE run only, so the deterministic structural metrics the baseline gate holds
# (page high-water, plateau footprint) are unaffected by the tick count, only how long the plateau is
# observed. Leave unset for the committed-baseline-comparable default.
IOT_TICKS="${IOT_TICKS:-}"

# The hermetic generator + churn driver + evidence emitter + baseline gate all live in the one crate;
# the churn driver + evidence emitter need the `churn` feature (real engine).
if [ ! -x "$GEN" ] || [ ! -x "$CHURN" ] || [ ! -x "$EVIDENCE_BIN" ] || [ ! -x "$CMP_BIN" ]; then
  section "Building the iot-timeseries generator + churn driver + evidence binaries (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p graphus-iot-gen --features churn --bins )
fi
for b in "$GEN" "$CHURN" "$EVIDENCE_BIN" "$CMP_BIN"; do
  [ -x "$b" ] || { echo "${RED}fatal: required binary not found at $b${RESET}" >&2; exit 2; }
done

# --------------------------------------------------------------------------------------------------
# Workspace: a private temp dir for generated artifacts, removed on exit. The evidence/ dir is
# git-ignored; baseline.json lives at a non-ignored path.
# --------------------------------------------------------------------------------------------------
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/graphus-iot-XXXXXX")"
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
BASELINE="$SCRIPT_DIR/baseline.json"
SAMPLES_JSON="$WORKDIR/samples.json"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT INT TERM
mkdir -p "$EVIDENCE_DIR"

# kv <summary-line> <key> — pull a `key=value` token out of a generator/driver summary line.
kv() { printf '%s' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -n1; }
# jnum <json> <key> — pull a flat numeric "key":N field out of the samples JSON (no jq dependency).
jnum() { printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\\([0-9][0-9]*\\).*/\\1/p" | head -n1; }

# ==================================================================================================
# Step 1 — deterministic generator (byte-identical per seed)  [rmp #294]
# ==================================================================================================
section "Step 1 — deterministic time-series churn generator ($PROFILE profile)"
GEN_OUT="$("$GEN" --profile "$PROFILE" --out-dir "$WORKDIR/gen1")"
printf '%s\n' "$GEN_OUT" | sed 's/^/  /'
assert "stream.cypher generated" "yes" "$([ -s "$WORKDIR/gen1/stream.cypher" ] && echo yes || echo no)"

"$GEN" --profile "$PROFILE" --out-dir "$WORKDIR/gen2" >/dev/null
if diff -q "$WORKDIR/gen1/stream.cypher" "$WORKDIR/gen2/stream.cypher" >/dev/null; then
  assert "generator is byte-identical per seed" "yes" "yes"
else
  assert "generator is byte-identical per seed" "yes" "no"
fi

GEN_WINDOW="$(kv "$GEN_OUT" window)"
GEN_TOTAL="$(kv "$GEN_OUT" total_readings)"

# ==================================================================================================
# Step 2 — sustained ingest + churn + storage-reclamation proof (REAL engine)  [rmp #295 + #296]
# ==================================================================================================
section "Step 2 — sustained ingest + retention churn + reclamation proof (real engine)"
CHURN_OUT="$("$CHURN" --profile "$PROFILE" --json "$SAMPLES_JSON" 2>&1)" || true
printf '%s\n' "$CHURN_OUT" | grep -v '^GRAPHUS_IOT_SAMPLES' | sed 's/^/  /'

assert "workload reached steady state AND footprint plateaued" "yes" \
  "$(printf '%s' "$CHURN_OUT" | grep -q 'GRAPHUS_IOT_CHURN_OK' && echo yes || echo no)"

# Harvest the machine-readable structural results for the README/evidence + a couple of direct asserts.
SAMPLES="$(cat "$SAMPLES_JSON" 2>/dev/null || echo '{}')"
PAGE_HW="$(jnum "$SAMPLES" page_high_water)"
STEADY_MIN="$(jnum "$SAMPLES" steady_min_bytes)"
STEADY_MAX="$(jnum "$SAMPLES" steady_max_bytes)"
TOTAL_INGESTED="$(jnum "$SAMPLES" total_ingested)"
info "page_high_water=$PAGE_HW  steady_footprint=[$STEADY_MIN, $STEADY_MAX]B  total_ingested=$TOTAL_INGESTED  window=$GEN_WINDOW"

# Independent structural check on the captured samples: the post-warmup footprint band is bounded
# (max within 1.5x of min) and we ingested >> the window (>= 3x). These mirror the driver's own
# assertions but re-prove them from the committed-shape JSON the evidence tooling consumes.
if [ -n "$STEADY_MIN" ] && [ -n "$STEADY_MAX" ] && [ "${STEADY_MIN:-0}" -gt 0 ]; then
  BOUNDED="$(awk -v a="$STEADY_MAX" -v b="$STEADY_MIN" 'BEGIN{print (a <= 1.5*b) ? "yes":"no"}')"
  assert "footprint plateau: post-warmup max within 1.5x of min" "yes" "$BOUNDED"
fi
if [ -n "$TOTAL_INGESTED" ] && [ -n "$GEN_WINDOW" ] && [ "${GEN_WINDOW:-0}" -gt 0 ]; then
  ENOUGH="$(awk -v t="$TOTAL_INGESTED" -v w="$GEN_WINDOW" 'BEGIN{print (t >= 3*w) ? "yes":"no"}')"
  assert "total ingested is >= 3x the retention window" "yes" "$ENOUGH"
fi

# ==================================================================================================
# Step 3 — the no-GC contrast (informational): the linear-growth curve GC flattens
# ==================================================================================================
section "Step 3 — no-GC contrast (informational): footprint grows without a GC pass"
# A short slice keeps the growing-scan cost bounded; this path makes no assertion (it is the honest
# motivation for why the GC maintenance pass is required).
NOGC_OUT="$("$CHURN" --profile "$PROFILE" --no-gc --ticks 12 2>&1)" || true
printf '%s\n' "$NOGC_OUT" | grep -E 'no-GC contrast|footprint grew' | sed 's/^/  /'

# ==================================================================================================
# Step 4 — (optional) Bolt-over-UDS wire demonstration of ingest + retention
# ==================================================================================================
if [ "$RUN_WIRE" = "1" ]; then
  if [ ! -x "$SERVER" ] || [ ! -x "$CLI" ]; then
    section "Building graphus-server and graphus-cli (release) for the wire demo"
    ( cd "$REPO_ROOT" && cargo build --release -p graphus-server -p graphus-cli )
  fi
  if [ -x "$SERVER" ] && [ -x "$CLI" ]; then
    section "Step 4 — Bolt-over-UDS wire demo (ingest + retention via graphus-cli)"
    # churn_cli.sh owns its OWN server process + lifecycle (its own trap); this script never holds a
    # background server PID, so there is no bare-`wait` hazard here.
    WIRE_OUT="$("$SCRIPT_DIR/data/churn_cli.sh" "$SERVER" "$CLI" 12 20 60 4 2>&1)" || true
    printf '%s\n' "$WIRE_OUT" | grep -vE '^GRAPHUS_IOT_WIRE_OK' | sed 's/^/  /'
    assert "wire ingest+retention reached steady state over UDS" "yes" \
      "$(printf '%s' "$WIRE_OUT" | grep -q 'GRAPHUS_IOT_WIRE_OK' && echo yes || echo no)"
  else
    section "Step 4 — wire demo SKIPPED (server/cli binaries unavailable)"
  fi
else
  section "Step 4 — Bolt-over-UDS wire demo SKIPPED (RUN_WIRE=0)"
fi

# ==================================================================================================
# Step 5 — standardized evidence (footprint plateau + RSS series + throughput + time) + baseline gate
#          [rmp #297 / #298 / #300]
# ==================================================================================================
section "Step 5 — collect performance evidence (footprint plateau + RSS + throughput + time)"
# Drive the SAME in-process churn run as Step 2 through the evidence emitter, which additionally
# samples RSS over the loop and folds the footprint time series + page high-water + plateau_ratio +
# RSS series + throughput + end-to-end time into a schema-versioned report.json + report.md.
rm -f "$EVIDENCE_DIR/report.json" "$EVIDENCE_DIR/report.md"
EVIDENCE_ARGS=( --evidence-dir "$EVIDENCE_DIR" --profile "$PROFILE" )
# The long-running steady-state knob (#298): more ticks => the plateau is observed for longer. It does
# NOT change the deterministic structural metrics the baseline gates, only how long the flat footprint
# is demonstrated, so it is forwarded to the evidence run unconditionally.
[ -n "$IOT_TICKS" ] && EVIDENCE_ARGS+=( --ticks "$IOT_TICKS" )
EVIDENCE_OUT="$("$EVIDENCE_BIN" "${EVIDENCE_ARGS[@]}" 2>&1)" || true
printf '%s\n' "$EVIDENCE_OUT" | sed 's/^/  /'
assert "evidence report.json was produced" "yes" \
  "$([ -f "$EVIDENCE_DIR/report.json" ] && echo yes || echo no)"
assert "evidence report.md was produced" "yes" \
  "$([ -f "$EVIDENCE_DIR/report.md" ] && echo yes || echo no)"

# Regression gate (fast profile, default tick count only — the committed baseline is that run).
# Compares ONLY the stable STRUCTURAL metrics (plateau footprint store_bytes/pages, plateau_ratio via
# write_amplification, per-element space_amplification) against baseline.json; the machine-variant
# RSS / throughput / CPU / wall-time families are given an effectively-infinite tolerance (see
# iot_baseline_cmp). A custom --ticks run is not baseline-comparable (longer series, same plateau), so
# the gate is skipped then.
if [ "$PROFILE" = "fast" ] && [ -z "$IOT_TICKS" ] && [ -f "$BASELINE" ] && [ -f "$EVIDENCE_DIR/report.json" ]; then
  section "regression gate vs committed baseline"
  CMP_OUT="$("$CMP_BIN" "$BASELINE" "$EVIDENCE_DIR/report.json" 2>&1)" || true
  printf '%s\n' "$CMP_OUT" | sed 's/^/  /'
  assert "fresh run is within baseline thresholds (structural plateau metrics)" "yes" \
    "$(printf '%s' "$CMP_OUT" | grep -q 'GRAPHUS_BASELINE_OK' && echo yes || echo no)"
elif [ ! -f "$BASELINE" ]; then
  info "no committed baseline.json yet — skipping the regression gate (generate one with this script)."
else
  info "regression gate skipped (non-fast profile or custom --ticks: not baseline-comparable)."
fi

# ==================================================================================================
# Summary
# ==================================================================================================
section "Result"
printf '%s checks run, %s failures.\n' "$CHECKS" "$FAILURES"
if [ -f "$EVIDENCE_DIR/report.json" ]; then
  info "standardized evidence: $EVIDENCE_DIR/{report.json, report.md}"
fi
if [ "$FAILURES" -eq 0 ]; then
  printf '%s%sIOT-TIMESERIES DEMONSTRATION PASSED%s — the seeded generator is byte-identical, the\n' "$BOLD" "$GREEN" "$RESET"
  printf 'sustained ingest+retention churn reached a steady state (live count ~ window), and the\n'
  printf 'on-disk footprint PLATEAUED under churn (page high-water %s) while ingesting %s readings\n' "${PAGE_HW:-?}" "${TOTAL_INGESTED:-?}"
  printf '(>> the window of %s) — reclaimed space demonstrably reused, not unbounded growth.\n' "${GEN_WINDOW:-?}"
  exit 0
else
  printf '%s%sIOT-TIMESERIES DEMONSTRATION FAILED%s — %s assertion(s) did not hold.\n' "$BOLD" "$RED" "$RESET" "$FAILURES"
  exit 1
fi
