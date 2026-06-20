#!/usr/bin/env bash
#
# Graphus high-throughput bulk ingest & ETL demonstration — fully OFFLINE (no server, no Bolt driver,
# no network).
#
# This script doubles as an executable E2E test. It:
#   1. generates a DETERMINISTIC, SEEDED LDBC-SNB-like social-network dataset as loader-ready CSV
#      (per-label node files + per-type relationship files + manifest.json) via the `bulk_gen` binary,
#      and proves the generator is BYTE-IDENTICAL per seed by regenerating and diffing;
#   2. imports the dataset into a fresh store with the REAL `graphus-bulk import` binary, asserting the
#      reported node/relationship counts equal the manifest;
#   3. proves a LOSSLESS `import -> dump -> re-import` round-trip (`bulk_roundtrip`): the whole graph is
#      dumped back to CSV, re-imported into a second fresh store, and the two stores are proven
#      identical by an id-independent CONTENT HASH (same labels, types, property values, connectivity);
#   4. measures the on-disk STORAGE footprint + write/space amplification (`bulk_storage` -> storage.json);
#   5. emits the standardized, schema-versioned report.json + report.md (ingest THROUGHPUT — elements/sec
#      and MB/sec — peak RAM, CPU time, end-to-end time, plus the store footprint + amplification) via
#      the dev-only `bulk_evidence` harness binary, and gates a fresh fast-profile run against the
#      committed baseline.json (STRUCTURAL metrics only) via `bulk_baseline_cmp`.
#
# Everything is HERMETIC and always runs — there is no server to boot and no opt-in driver path.
#
# Usage:
#   examples/bulk-etl/run.sh                       # builds binaries if needed, then runs
#   GRAPHUS_BIN_DIR=target/release  examples/bulk-etl/run.sh
#   BULK_PROFILE=large              examples/bulk-etl/run.sh   # evidence-scale dataset
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

BULK="$BIN_DIR/graphus-bulk"
GEN="$BIN_DIR/bulk_gen"
ROUNDTRIP="$BIN_DIR/bulk_roundtrip"
STORAGE="$BIN_DIR/bulk_storage"
EVIDENCE_BIN="$BIN_DIR/bulk_evidence"
CMP_BIN="$BIN_DIR/bulk_baseline_cmp"

PROFILE="${BULK_PROFILE:-fast}"

# The offline importer is its own release binary; the generator + drivers are the dev-only crate's.
if [ ! -x "$BULK" ]; then
  section "Building the offline graphus-bulk importer (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p graphus-bulk --bin graphus-bulk )
fi
[ -x "$BULK" ] || { echo "${RED}fatal: graphus-bulk binary not found at $BULK${RESET}" >&2; exit 2; }

if [ ! -x "$GEN" ] || [ ! -x "$ROUNDTRIP" ] || [ ! -x "$STORAGE" ] || [ ! -x "$EVIDENCE_BIN" ] || [ ! -x "$CMP_BIN" ]; then
  section "Building the dev-only bulk-etl generator + drivers (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p graphus-bulk-gen --bins )
fi
for b in "$GEN" "$ROUNDTRIP" "$STORAGE" "$EVIDENCE_BIN" "$CMP_BIN"; do
  [ -x "$b" ] || { echo "${RED}fatal: required binary not found at $b${RESET}" >&2; exit 2; }
done

# --------------------------------------------------------------------------------------------------
# Workspace + evidence paths. The temp workspace is removed on exit (success or failure). The
# evidence/ dir is git-ignored; baseline.json lives at a non-ignored path.
# --------------------------------------------------------------------------------------------------
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/graphus-bulk-etl-XXXXXX")"
DATA_DIR="$WORKDIR/data"
STORAGE_JSON="$WORKDIR/storage.json"
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
BASELINE="$SCRIPT_DIR/baseline.json"

cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT INT TERM

mkdir -p "$EVIDENCE_DIR"

# kv <summary-line> <key> — pull a `key=value` token out of a generator/driver summary line.
kv() { printf '%s' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -n1; }

# --------------------------------------------------------------------------------------------------
# Step 1 — generate the deterministic dataset + prove it is byte-identical per seed
# --------------------------------------------------------------------------------------------------
section "Step 1 — generate the deterministic social-network dataset ($PROFILE profile)"
GEN_OUT="$("$GEN" --profile "$PROFILE" --out-dir "$DATA_DIR")"
printf '%s\n' "$GEN_OUT" | sed 's/^/  /'
NODE_COUNT="$(kv "$GEN_OUT" nodes)"
REL_COUNT="$(kv "$GEN_OUT" relationships)"
assert "manifest.json generated" "yes" "$([ -s "$DATA_DIR/manifest.json" ] && echo yes || echo no)"

# Determinism check: regenerate into a second dir and diff every emitted file (the #264 AC).
DATA_DIR2="$WORKDIR/data2"
"$GEN" --profile "$PROFILE" --out-dir "$DATA_DIR2" > /dev/null
if diff -rq "$DATA_DIR" "$DATA_DIR2" > /dev/null; then
  assert "generator is byte-identical per seed" "yes" "yes"
else
  assert "generator is byte-identical per seed" "yes" "no"
fi

# --------------------------------------------------------------------------------------------------
# Step 2 — prove the lossless import -> dump -> re-import round-trip on the REAL graphus-bulk binary
# --------------------------------------------------------------------------------------------------
section "Step 2 — lossless import -> dump -> re-import round-trip (real graphus-bulk)"
ROUNDTRIP_OUT="$("$ROUNDTRIP" --bulk-bin "$BULK" --data-dir "$DATA_DIR" 2>&1)" || true
printf '%s\n' "$ROUNDTRIP_OUT" | sed 's/^/  /'
assert "round-trip is lossless (content hash preserved)" "yes" \
  "$(printf '%s' "$ROUNDTRIP_OUT" | grep -q 'GRAPHUS_BULK_ROUNDTRIP_OK' && echo yes || echo no)"
RT_LINE="$(printf '%s' "$ROUNDTRIP_OUT" | sed -n 's/^GRAPHUS_BULK_ROUNDTRIP_OK //p' | head -n1)"
CONTENT_HASH="$(kv "$RT_LINE" content_hash)"
assert "round-trip reports the original node count" "$NODE_COUNT" "$(kv "$RT_LINE" nodes)"
assert "round-trip reports the original relationship count" "$REL_COUNT" "$(kv "$RT_LINE" relationships)"

# --------------------------------------------------------------------------------------------------
# Step 3 — measure the on-disk storage footprint + amplification
# --------------------------------------------------------------------------------------------------
section "Step 3 — on-disk storage footprint + write/space amplification"
STORAGE_OUT="$("$STORAGE" --bulk-bin "$BULK" --data-dir "$DATA_DIR" --out "$STORAGE_JSON" 2>&1)" || true
printf '%s\n' "$STORAGE_OUT" | sed 's/^/  /'
assert "storage.json was produced" "yes" "$([ -s "$STORAGE_JSON" ] && echo yes || echo no)"

# --------------------------------------------------------------------------------------------------
# Step 4 — emit the standardized evidence (throughput + RAM + CPU + time + storage) and gate it
# --------------------------------------------------------------------------------------------------
section "Step 4 — collect performance evidence (ingest throughput + RAM / CPU / time + storage)"
# Refresh only the report files (NOT storage.json — that lives under WORKDIR; the dir is git-ignored).
rm -f "$EVIDENCE_DIR/report.json" "$EVIDENCE_DIR/report.md"
EVIDENCE_ARGS=(
  --evidence-dir "$EVIDENCE_DIR"
  --data-dir "$DATA_DIR"
  --storage "$STORAGE_JSON"
  --bulk-bin "$BULK"
  --scenario "bulk-etl"
  --param "profile=$PROFILE"
  --param "connection=offline"
)
[ -n "${CONTENT_HASH:-}" ] && EVIDENCE_ARGS+=( --content-hash "$CONTENT_HASH" )
EVIDENCE_OUT="$("$EVIDENCE_BIN" "${EVIDENCE_ARGS[@]}" 2>&1)" || true
printf '%s\n' "$EVIDENCE_OUT" | sed 's/^/  /'
assert "evidence report.json was produced" "yes" \
  "$([ -f "$EVIDENCE_DIR/report.json" ] && echo yes || echo no)"
assert "evidence report.md was produced" "yes" \
  "$([ -f "$EVIDENCE_DIR/report.md" ] && echo yes || echo no)"

# Regression gate (fast profile only — the committed baseline is a fast-profile run). Compares only
# the STABLE STRUCTURAL metrics (dataset size, imported_elements, store footprint within 15%) against
# the committed baseline; ingest throughput / CPU / RAM / wall-time are machine-variant and NOT gated.
if [ "$PROFILE" = "fast" ] && [ -f "$BASELINE" ] && [ -f "$EVIDENCE_DIR/report.json" ]; then
  section "regression gate vs committed baseline"
  CMP_OUT="$("$CMP_BIN" "$BASELINE" "$EVIDENCE_DIR/report.json" 2>&1)" || true
  printf '%s\n' "$CMP_OUT" | sed 's/^/  /'
  assert "fresh run is within baseline thresholds (structural metrics)" "yes" \
    "$(printf '%s' "$CMP_OUT" | grep -q 'GRAPHUS_BASELINE_OK' && echo yes || echo no)"
fi

# --------------------------------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------------------------------
section "Result"
printf '%s checks run, %s failures.\n' "$CHECKS" "$FAILURES"
if [ -f "$EVIDENCE_DIR/report.json" ]; then
  info "standardized evidence: $EVIDENCE_DIR/{report.json, report.md}"
fi
if [ "$FAILURES" -eq 0 ]; then
  printf '%s%sBULK-ETL DEMONSTRATION PASSED%s — Graphus generated a byte-identical seeded social\n' "$BOLD" "$GREEN" "$RESET"
  printf '%s\n' "network, bulk-imported it with the real graphus-bulk binary, proved a LOSSLESS"
  printf '%s\n' "import -> dump -> re-import round-trip by content hash, characterised the on-disk store"
  printf '%s\n' "footprint + amplification, and produced standardized ingest-throughput / RAM / CPU / time evidence."
  exit 0
else
  printf '%s%sBULK-ETL DEMONSTRATION FAILED%s — %s assertion(s) did not hold.\n' "$BOLD" "$RED" "$RESET" "$FAILURES"
  exit 1
fi
