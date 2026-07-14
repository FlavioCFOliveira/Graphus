#!/usr/bin/env bash
#
# Graphus high-throughput bulk ingest & ETL demonstration.
#
# This script doubles as an executable E2E test. Its OFFLINE core (always run, hermetic — no server,
# no network) proves the loader path end to end and CHARACTERISES BOTH HALVES OF A BULK LOAD:
#   1. generates a DETERMINISTIC, SEEDED LDBC-SNB-like social-network dataset as loader-ready CSV
#      (per-label node files + per-type relationship files + manifest.json) via the `bulk_gen` binary,
#      and proves the generator is BYTE-IDENTICAL per seed by regenerating and diffing;
#   2. proves a LOSSLESS `import -> dump -> re-import` round-trip (`bulk_roundtrip`) on the REAL
#      `graphus-bulk` binary: the whole graph is dumped back to CSV, re-imported into a second fresh
#      store, and the two stores are proven identical by an id-independent CONTENT HASH;
#   3. runs ONE metered import (`bulk_evidence`) and measures EVERYTHING over that one store image —
#      ingest throughput + CPU + peak RAM, the on-disk footprint (store bytes, the WAL RESIDUAL, the
#      per-element durable costs, write/space amplification), and THE COST OF REOPENING IT (WAL
#      recovery + RecordStore::open — `rmp` #576/#579), which is the half of a bulk load nobody was
#      measuring;
#   4. ASSERTS those storage vectors (a load that writes nothing, logs nothing, or loses data on
#      reopen fails here) and gates a fresh default-profile run against the committed baseline.
#
# It THEN drives the SAME generated CSVs into a RUNNING server over the ratified network bulk-import
# (Mode A) path (`specification/08-network-bulk-import.md`), in REALISTIC BATCHES: an empty database is
# taken over exclusively, the node CSVs are streamed in `--batch-rows` chunks
# (`POST /admin/db/{db}/bulk-import?phase=nodes`), then the relationship CSVs (`?phase=relationships`),
# then the session is ended (`?end=true`) and the database brought online (`START DATABASE`). Each chunk
# is one request/response, so each one is a REAL per-batch INGEST LATENCY sample — the latency an
# offline one-shot import structurally does not have. It asserts the server's own final ingest tally AND
# the queried row counts equal the manifest, and collects SERVER-SIDE evidence from the target's
# Prometheus `/metrics` (before/after deltas) into a wire report.json via the shared `measure_target`.
#
# The wire step runs against a self-booted local plaintext-loopback REST server by default, or ATTACHES
# to an already-running instance (local OR remote) when a GRAPHUS_TARGET_* endpoint is set
# (the shared external-target seam in `_harness/harness.sh`).
#
# THE PROFILE LADDER — one production-shaped graph at four sizes. The SHAPE is what makes the example
# representative; the SIZE is a knob. The default is production-shaped at a MODERATE size, so that the
# storage and durability vectors are meaningful while the whole examples suite stays inside its gate
# budget (`scripts/examples-gate.sh`). A bigger rung is opt-in, and the README states exactly which
# profile produced which number — a fast run never claims production scale.
#
#   BULK_PROFILE=fast     ~800 nodes /   ~4k rels  — a smoke run. NOT an evidence scale.
#   BULK_PROFILE=default  ~24k nodes / ~140k rels  — THE DEFAULT (~30s; the baseline's profile).
#   BULK_PROFILE=large    ~98k nodes / ~560k rels  — opt-in: real evaluation scale.
#   BULK_PROFILE=huge    ~390k nodes / ~2.2M rels  — opt-in: the memory/WAL ceiling of a big import.
#
# Usage:
#   examples/bulk-etl/run.sh                       # offline core + local self-boot wire step
#   GRAPHUS_BIN_DIR=target/release  examples/bulk-etl/run.sh
#   BULK_PROFILE=large              examples/bulk-etl/run.sh   # evaluation-scale dataset
#   BULK_BATCH_ROWS=5000            examples/bulk-etl/run.sh   # wire batch size (default 1000 rows)
#   RUN_WIRE=0                      examples/bulk-etl/run.sh   # offline core only (no server)
#   GRAPHUS_TARGET_REST=https://host:7474 GRAPHUS_TARGET_USER=graphus \
#     GRAPHUS_TARGET_PASSWORD=graphus-local GRAPHUS_TARGET_TLS_INSECURE=1 \
#     examples/bulk-etl/run.sh                     # stream into an already-running instance
#
# Requirements: a Unix host (Linux/macOS), bash, curl, awk. The offline core needs no network; the wire
# step needs a REST-reachable server (self-booted locally, or the GRAPHUS_TARGET_REST target).

set -euo pipefail

# --------------------------------------------------------------------------------------------------
# Shared external-target seam (GRAPHUS_TARGET_* detection, isolated-DB create/drop, /metrics scrape).
# Sourced FIRST; the pretty-printers + assert counters below are then (re)defined so the harness's
# target helpers (which call `info`/`section` by name) use these definitions and the offline core's
# CHECKS/FAILURES tally is preserved (the harness's own assert/section/info are shadowed on purpose).
# --------------------------------------------------------------------------------------------------
# shellcheck source=../_harness/harness.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../_harness" && pwd)/harness.sh"
export HARNESS_SCENARIO="bulk-etl"   # names the isolated wire DB: ex_bulk-etl_<epoch>_<pid>

# --------------------------------------------------------------------------------------------------
# Pretty output helpers (house style) — defined AFTER the source so they win over the harness copies.
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

# assert_gt <description> <actual> <lower-bound-exclusive> — an integer/float lower-bound assertion,
# for the vectors whose EXACT value is machine-variant but whose being > 0 (or under a ceiling) is a
# real invariant. Uses awk so it works for both integers and floats, locale-independently (LC_ALL=C).
assert_gt() {
  CHECKS=$((CHECKS + 1))
  if LC_ALL=C awk -v a="$2" -v b="$3" 'BEGIN { exit !(a > b) }' 2>/dev/null; then
    printf '  %s✓%s %s %s(%s > %s)%s\n' "$GREEN" "$RESET" "$1" "$DIM" "$2" "$3" "$RESET"
  else
    FAILURES=$((FAILURES + 1))
    printf '  %s✗ %s%s — expected %s> %s%s, got %s[%s]%s\n' \
      "$RED" "$1" "$RESET" "$BOLD" "$3" "$RESET" "$BOLD" "$2" "$RESET"
  fi
}

# assert_lt <description> <actual> <upper-bound-exclusive> — the ceiling counterpart of assert_gt.
assert_lt() {
  CHECKS=$((CHECKS + 1))
  if LC_ALL=C awk -v a="$2" -v b="$3" 'BEGIN { exit !(a < b) }' 2>/dev/null; then
    printf '  %s✓%s %s %s(%s < %s)%s\n' "$GREEN" "$RESET" "$1" "$DIM" "$2" "$3" "$RESET"
  else
    FAILURES=$((FAILURES + 1))
    printf '  %s✗ %s%s — expected %s< %s%s, got %s[%s]%s\n' \
      "$RED" "$1" "$RESET" "$BOLD" "$3" "$RESET" "$BOLD" "$2" "$RESET"
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
REOPEN_BIN="$BIN_DIR/bulk_reopen"
EVIDENCE_BIN="$BIN_DIR/bulk_evidence"
CMP_BIN="$BIN_DIR/bulk_baseline_cmp"
SERVER="$BIN_DIR/graphus-server"

# The DEFAULT profile is production-SHAPED at a MODERATE size (see the ladder above). `rmp` #716: it
# used to be `fast` — a 47-MILLISECOND workload, which cannot stress anything an ETL actually stresses.
PROFILE="${BULK_PROFILE:-default}"
# Rows per network bulk-import request. A realistic ETL batch size, and the unit each per-batch INGEST
# LATENCY sample is measured over. 1000 rows over the default profile yields ~165 timed requests, which
# is enough samples for an honest p50 and p99 (measure_target omits a percentile the sample size cannot
# support — a "p999" over 165 samples is just the maximum wearing a percentile's name).
BATCH_ROWS="${BULK_BATCH_ROWS:-1000}"
# The offline import/round-trip/footprint/reopen/baseline core is the always-run hermetic body. The
# network bulk-import (Mode A) WIRE step streams the SAME generated CSVs into a running server and is
# OPT-IN via RUN_WIRE (default ON; set RUN_WIRE=0 to skip it on a host with no server/network).
RUN_WIRE="${RUN_WIRE:-1}"

# The offline importer is its own release binary; the generator + drivers are the dev-only crate's.
# harness_build rebuilds unconditionally (cargo is incremental) so the evidence always describes the
# CURRENT sources — a build-only-if-absent guard silently runs a STALE binary after any source edit.
harness_build "the offline graphus-bulk importer (release)" --release -p graphus-bulk --bin graphus-bulk
harness_build "the dev-only bulk-etl generator + drivers (release)" --release -p graphus-bulk-gen --bins
# The dev-only measure_target evidence binary, built UNCONDITIONALLY (a build-only-if-absent guard
# silently ran a STALE measure_target after a source edit — the evidence then described code no longer
# under test, rmp #577).
harness_build "the dev-only measure_target evidence binary (release)" \
  --release -p graphus-examples-harness --bin measure_target
for b in "$BULK" "$GEN" "$ROUNDTRIP" "$REOPEN_BIN" "$EVIDENCE_BIN" "$CMP_BIN"; do
  [ -x "$b" ] || { echo "${RED}fatal: required binary not found at $b${RESET}" >&2; exit 2; }
done

# --------------------------------------------------------------------------------------------------
# Workspace + evidence paths. The temp workspace is removed on exit (success or failure). The
# evidence/ dir is git-ignored; baseline.json lives at a non-ignored path. The offline evidence lands
# at evidence/report.json; the WIRE evidence lands under evidence/wire/ so the two never clobber.
# --------------------------------------------------------------------------------------------------
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/graphus-bulk-etl-XXXXXX")"
DATA_DIR="$WORKDIR/data"
CHUNK_DIR="$WORKDIR/chunks"
STORAGE_JSON="$WORKDIR/storage.json"
# The store the metered import builds. KEPT (not thrown away) so the #681 server-openability probe can
# examine the real thing without paying for a THIRD import of the same dataset.
OFFLINE_STORE="$WORKDIR/offline-store"
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
WIRE_EVIDENCE_DIR="$EVIDENCE_DIR/wire"
BASELINE="$SCRIPT_DIR/baseline.json"
METRICS_BEFORE="$WORKDIR/metrics_before.prom"
METRICS_AFTER="$WORKDIR/metrics_after.prom"
LATENCY_SAMPLES="$WORKDIR/wire_latency_secs.txt"

SERVER_PID=""
cleanup() {
  # Drop the isolated wire DB the harness created (no-op if none / operator-owned GRAPHUS_TARGET_DB).
  # Done BEFORE stopping a self-booted local server so the DROP (issued over REST) still reaches it.
  harness_target_drop_db >/dev/null 2>&1 || true
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

mkdir -p "$EVIDENCE_DIR"

# kv <summary-line> <key> — pull a `key=value` token out of a generator/driver summary line.
kv() { printf '%s' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -n1; }
# json_num <file> <key> — pull a top-level numeric field out of a flat JSON object (integer or float).
json_num() { sed -n "s/.*\"$2\": *\([0-9][0-9.]*\).*/\1/p" "$1" | head -n1; }

# --------------------------------------------------------------------------------------------------
# Step 1 — generate the deterministic dataset + prove it is byte-identical per seed
# --------------------------------------------------------------------------------------------------
section "Step 1 — generate the deterministic social-network dataset ($PROFILE profile)"
GEN_OUT="$("$GEN" --profile "$PROFILE" --out-dir "$DATA_DIR")"
printf '%s\n' "$GEN_OUT" | sed 's/^/  /'
NODE_COUNT="$(kv "$GEN_OUT" nodes)"
REL_COUNT="$(kv "$GEN_OUT" relationships)"
PROP_COUNT="$(kv "$GEN_OUT" properties)"
LOGICAL_BYTES="$(kv "$GEN_OUT" logical_csv_bytes)"
assert "manifest.json generated" "yes" "$([ -s "$DATA_DIR/manifest.json" ] && echo yes || echo no)"

# Determinism check: regenerate into a second dir and diff every emitted file (the #264 AC).
DATA_DIR2="$WORKDIR/data2"
"$GEN" --profile "$PROFILE" --out-dir "$DATA_DIR2" > /dev/null
if diff -rq "$DATA_DIR" "$DATA_DIR2" > /dev/null; then
  assert "generator is byte-identical per seed" "yes" "yes"
else
  assert "generator is byte-identical per seed" "yes" "no"
fi
rm -rf "$DATA_DIR2"   # the copy has served its purpose; a big profile should not carry it around

# --------------------------------------------------------------------------------------------------
# Step 2 — prove the lossless import -> dump -> re-import round-trip on the REAL graphus-bulk binary
# --------------------------------------------------------------------------------------------------
section "Step 2 — lossless import -> dump -> re-import round-trip (real graphus-bulk)"
ROUNDTRIP_OUT="$("$ROUNDTRIP" --bulk-bin "$BULK" --data-dir "$DATA_DIR" 2>&1)" || true
printf '%s\n' "$ROUNDTRIP_OUT" | sed 's/^/  /'
assert "round-trip is lossless (content hash preserved)" "yes" \
  "$(grep -q 'GRAPHUS_BULK_ROUNDTRIP_OK' <<<"$ROUNDTRIP_OUT" && echo yes || echo no)"
RT_LINE="$(printf '%s' "$ROUNDTRIP_OUT" | sed -n 's/^GRAPHUS_BULK_ROUNDTRIP_OK //p' | head -n1)"
CONTENT_HASH="$(kv "$RT_LINE" content_hash)"
assert "round-trip reports the original node count" "$NODE_COUNT" "$(kv "$RT_LINE" nodes)"
assert "round-trip reports the original relationship count" "$REL_COUNT" "$(kv "$RT_LINE" relationships)"

# --------------------------------------------------------------------------------------------------
# Step 3 — ONE metered import: throughput + CPU + RAM, the on-disk footprint, and the REOPEN cost
#
# `rmp` #716. This used to be TWO drivers importing the same dataset into two different stores — one to
# time it, one to measure it — so the per-element costs it published were, strictly, a footprint of one
# store amortised over the element count of another. Now a single import is metered for everything, and
# every figure below describes the SAME store image. That store is also KEPT, so the #681 probe and the
# reopen measurement examine the real thing rather than a re-import of it.
# --------------------------------------------------------------------------------------------------
section "Step 3 — one metered import: ingest (CPU/RAM/throughput) + footprint + THE REOPEN COST"
rm -f "$EVIDENCE_DIR/report.json" "$EVIDENCE_DIR/report.md"
EVIDENCE_ARGS=(
  --evidence-dir "$EVIDENCE_DIR"
  --data-dir "$DATA_DIR"
  --storage-out "$STORAGE_JSON"
  --keep-store "$OFFLINE_STORE"
  --bulk-bin "$BULK"
  --reopen-bin "$REOPEN_BIN"
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
assert "storage.json was produced" "yes" "$([ -s "$STORAGE_JSON" ] && echo yes || echo no)"

# --------------------------------------------------------------------------------------------------
# Step 4 — ASSERT the storage vectors that make an ETL judgeable
#
# The exact values are gated against the committed baseline (Step 5, 15% band). What is asserted HERE
# are the INVARIANTS — the things that must hold on any host, and whose violation is a real defect
# rather than a slower machine:
#
#   * the durable store is non-empty and each element costs real bytes (a load that stored nothing);
#   * the load was WAL-LOGGED (a bulk load that leaves NO redo log is a durability defect, not a fast
#     one) — and the WAL RESIDUAL it leaves behind is reported, because that residual IS the reopen
#     cost;
#   * amplification is finite and under a generous ceiling (a blow-up, not a drift);
#   * the REOPEN returns the WHOLE graph. `bulk_reopen` fails outright if the reopened store holds the
#     wrong node/relationship count, so a reopen that came back fast because it came back EMPTY can
#     never be reported here as a good number.
# --------------------------------------------------------------------------------------------------
section "Step 4 — assert the storage + reopen vectors (bytes/element, WAL residual, amplification)"
S_STORE_BYTES="$(json_num "$STORAGE_JSON" store_bytes)"
S_WAL_BYTES="$(json_num "$STORAGE_JSON" wal_bytes)"
S_BPN="$(json_num "$STORAGE_JSON" bytes_per_node)"
S_BPE="$(json_num "$STORAGE_JSON" bytes_per_edge)"
S_WAMP="$(json_num "$STORAGE_JSON" write_amplification)"
S_SAMP="$(json_num "$STORAGE_JSON" store_space_amplification)"
S_W2S="$(json_num "$STORAGE_JSON" wal_to_store_ratio)"
S_REOPEN="$(json_num "$STORAGE_JSON" reopen_secs)"
S_REOPEN_RSS="$(json_num "$STORAGE_JSON" reopen_peak_rss_bytes)"

info "durable store      : $S_STORE_BYTES B  ($S_BPN B/node, $S_BPE B/relationship)"
info "WAL residual       : $S_WAL_BYTES B  (${S_W2S}x the durable store it just wrote)"
info "amplification      : store ${S_SAMP}x, store+WAL ${S_WAMP}x, over $LOGICAL_BYTES B of logical CSV"
info "REOPEN of that store: ${S_REOPEN}s, peak RSS $S_REOPEN_RSS B  (WAL recovery + RecordStore::open)"

assert_gt "the load produced a non-empty durable store" "$S_STORE_BYTES" 0
assert_gt "a stored node costs real durable bytes" "$S_BPN" 0
assert_gt "a stored relationship costs real durable bytes" "$S_BPE" 0
# A bulk load with NO redo log would not be fast, it would be UNRECOVERABLE. Zero WAL bytes here is a
# durability defect, and this assertion is the one that would catch it.
assert_gt "the load was WAL-logged (a redo log exists to recover from)" "$S_WAL_BYTES" 0
assert_gt "write amplification is a real, measured ratio" "$S_WAMP" 1
# A generous ceiling: it does not gate drift (the baseline's 15% band does), it catches a BLOW-UP.
assert_lt "write amplification has not blown up" "$S_WAMP" 200
# The reopen must actually cost something to measure (a 0.0 would mean it was never timed), and must
# not have degenerated into the ~33s of `rmp` #576 at this scale.
assert_gt "the store reopen was measured" "$S_REOPEN" 0
assert_lt "the store reopen did not degenerate (rmp #576 ceiling)" "$S_REOPEN" 60
assert_gt "the reopen process's peak RSS was measured" "$S_REOPEN_RSS" 0

# --------------------------------------------------------------------------------------------------
# Step 5 — regression gate vs the committed baseline
#
# Default profile only: the committed baseline is a DEFAULT-profile run, and a baseline can only be
# compared against the workload it was captured from. Compares the STABLE STRUCTURAL metrics (dataset
# size, imported_elements, store footprint + per-element costs + amplification within 15%); ingest
# throughput / CPU / RAM / wall-time / reopen seconds are machine-variant and are NOT gated.
# --------------------------------------------------------------------------------------------------
if [ "$PROFILE" = "default" ] && [ -f "$BASELINE" ] && [ -f "$EVIDENCE_DIR/report.json" ]; then
  section "Step 5 — regression gate vs committed baseline"
  CMP_OUT="$("$CMP_BIN" "$BASELINE" "$EVIDENCE_DIR/report.json" 2>&1)" || true
  printf '%s\n' "$CMP_OUT" | sed 's/^/  /'
  assert "fresh run is within baseline thresholds (structural metrics)" "yes" \
    "$(grep -q 'GRAPHUS_BASELINE_OK' <<<"$CMP_OUT" && echo yes || echo no)"
else
  section "Step 5 — baseline gate SKIPPED (profile=$PROFILE; the committed baseline is a 'default'-profile run)"
  info "a baseline can only gate the workload it was captured from — comparing a $PROFILE run against"
  info "a default-profile baseline would compare two different graphs and call the difference a regression."
fi

# ==================================================================================================
# Step 6 — network bulk-import (Mode A) over the wire, IN REALISTIC BATCHES, + per-batch INGEST LATENCY
#
# The realistic offline->online workflow: after characterising the OFFLINE load above, an operator
# brings the SAME data online by streaming the generator's CSVs into a RUNNING server over the ratified
# network bulk-import Mode A happy path.
#
# `rmp` #716 — the CSVs are streamed in `--batch-rows` CHUNKS, not as ten whole files. Two reasons, both
# substantive:
#   * it is what an ETL pipeline actually does (bounded batches, not one 77 MiB body), and
#   * every chunk is ONE request/response, so every chunk is a REAL per-batch INGEST LATENCY sample.
#     The offline import structurally HAS no such boundary — which is why its own report omits latency
#     rather than inventing a zero. Here the boundary exists, so the latency is measured, and
#     `measure_target` publishes only the percentiles the sample size can honestly support.
#
# Each chunk carries the file's header + a slice of its rows, which is exactly the shape the endpoint
# documents ("resend the header plus every row not yet reflected"): `08-network-bulk-import.md` §4.2 —
# node and relationship files are separate request bodies against the same session.
#
# It runs against a self-booted local plaintext-loopback REST server by default, or ATTACHES to an
# already-running instance (local OR remote) when a GRAPHUS_TARGET_* endpoint is set.
# ==================================================================================================

# The generator's node + relationship CSV file names, in load order (must match bulk_gen). ALL node
# files must land before ANY relationship file, so the two phases are streamed in two passes.
WIRE_NODE_FILES=(persons.csv forums.csv posts.csv comments.csv)
WIRE_REL_FILES=(knows.csv has_member.csv container_of.csv has_creator.csv reply_of.csv likes.csv)

# wire_json_int <json> <key> — extract a top-level integer field from a plain-JSON stats object.
wire_json_int() { printf '%s' "$1" | sed -n "s/.*\"$2\":\([0-9][0-9]*\).*/\1/p" | head -n1; }
# wire_jolt_int <tx-commit-json> — extract the first strict-Jolt integer cell {"Z":"N"} scalar.
wire_jolt_int() { printf '%s' "$1" | sed -n 's/.*"Z":"\([0-9][0-9]*\)".*/\1/p' | head -n1; }

# chunk_csv <src.csv> <out-prefix> <rows-per-chunk> — split a CSV into chunk files of <rows> data rows
# each, every chunk carrying the source file's HEADER row. Echoes the chunk paths, one per line.
# Pure awk: no CSV field parsing is needed (we are slicing whole records), and the generator never
# emits an embedded newline, so a line IS a record.
chunk_csv() {
  local src="$1" prefix="$2" rows="$3"
  awk -v n="$rows" -v out="$prefix" '
    NR == 1 { hdr = $0; next }
    {
      if (idx % n == 0) {
        if (f != "") close(f)
        c++
        f = sprintf("%s.%05d.csv", out, c)
        print hdr > f
      }
      print > f
      idx++
    }
    END { if (f != "") close(f) }
  ' "$src"
  ls -1 "$prefix".*.csv 2>/dev/null | sort
}

# wire_post_chunks <db> <phase> <chunk-file>... — POST every chunk to the bulk-import endpoint from ONE
# curl process (so the connection is REUSED across the batches, exactly as a real ETL client pools it),
# writing `<http_code> <time_total>` per request to stdout, in order.
#
# It drives curl from a CONFIG FILE rather than a command line, for three substantive reasons:
#
#  1. `--next` starts each request with a CLEAN option slate. EVERY per-transfer option must therefore
#     be repeated in EVERY block — including `-k`. A `-k` supplied once up front (as `_harness_curl`
#     does) applies to the FIRST request only, which is precisely how a self-signed TLS target accepts
#     batch 1 and then rejects every batch after it. This cost a real debugging cycle: the plaintext
#     local path passed while attach mode silently ingested exactly one batch.
#  2. argv would hit ARG_MAX at the bigger profiles (the `huge` rung is ~2,600 batches; macOS caps a
#     command line at 256 KiB). A config file has no such ceiling, so the same code path works at every
#     rung of the ladder.
#  3. The Bearer token stays OUT of the process argv, where `ps` would expose it to any local user. The
#     config file is created 0600.
#
# `%{time_total}` is C-locale formatted by curl regardless of the caller's locale, so the samples file
# is safe to hand to measure_target's `parse::<f64>` under any LC_NUMERIC (e.g. a pt-PT comma locale).
wire_post_chunks() {
  local db="$1" phase="$2"; shift 2
  local base token conf first=1 chunk
  base="$(_harness_target_rest_base)"
  token="$(harness_target_login)" || return 1
  conf="$WORKDIR/curl-$phase.conf"
  : > "$conf"
  chmod 600 "$conf" 2>/dev/null || true
  for chunk in "$@"; do
    [ "$first" = 1 ] || printf -- '--next\n' >> "$conf"
    first=0
    if _harness_target_insecure; then printf -- '--insecure\n' >> "$conf"; fi
    {
      printf -- '--silent\n--show-error\n--output /dev/null\n'
      printf -- '--write-out "%%{http_code} %%{time_total}\\n"\n'
      printf -- '--request POST\n'
      printf -- '--url "%s"\n' "$base/admin/db/$db/bulk-import?phase=$phase"
      printf -- '--header "Authorization: Bearer %s"\n' "$token"
      printf -- '--header "Content-Type: text/csv"\n'
      printf -- '--data-binary "@%s"\n' "$chunk"
    } >> "$conf"
  done
  # Print whatever curl produced EVEN IF a transfer failed. A non-zero exit must not discard the
  # per-request results — the caller needs them to report WHICH batch failed, and a `|| RESULTS=""`
  # that throws them all away turns "batch 7 was rejected" into "nothing happened".
  curl -K "$conf" 2>/dev/null || true
}

# wire_diagnose <db> <phase> <chunk-file> — re-issue ONE failing batch with the response body captured,
# so a rejection is reported with the server's own error message instead of a bare status code. Called
# only on failure; an example nobody can debug from its own output is an example that will be ignored.
wire_diagnose() {
  local db="$1" phase="$2" chunk="$3" base token
  base="$(_harness_target_rest_base)"
  token="$(harness_target_login)" || return 0
  info "server's response to the first failing batch ($phase, $(basename "$chunk")):"
  _harness_curl -sS -w '\n  HTTP %{http_code}\n' \
    -X POST "$base/admin/db/$db/bulk-import?phase=$phase" \
    -H "Authorization: Bearer $token" -H 'Content-Type: text/csv' \
    --data-binary "@$chunk" 2>&1 | head -5 | sed 's/^/    /'
}

if [ "$RUN_WIRE" != "1" ]; then
  section "Step 6 — network bulk-import wire step SKIPPED (RUN_WIRE=0)"
else
  WIRE_MODE="$(harness_target_mode)"   # external iff GRAPHUS_TARGET_{BOLT,REST,UDS} set at entry
  WIRE_OK=1
  WIRE_DB=""

  if [ "$WIRE_MODE" = external ]; then
    section "Step 6 — attach to the running instance for the network bulk-import wire step"
    if [ -z "${GRAPHUS_TARGET_REST:-}${GRAPHUS_TARGET_METRICS:-}" ]; then
      info "external target has no REST/_METRICS endpoint — the network bulk-import path is REST-only; skipping the wire step"
      WIRE_OK=0
    else
      info "attaching to ${GRAPHUS_TARGET_REST:-$GRAPHUS_TARGET_METRICS} (network bulk-import Mode A)"
    fi
  else
    section "Step 6 — boot a local plaintext-loopback REST server for the network bulk-import wire step"
    harness_build "graphus-server (release)" --release -p graphus-server || true
    if [ ! -x "$SERVER" ]; then
      info "graphus-server binary unavailable — skipping the wire step"
      WIRE_OK=0
    else
      # A free loopback TCP port for the plaintext REST listener (the bulk-import upload path).
      free_port() {
        if command -v python3 >/dev/null 2>&1; then
          python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'
        else echo 47575; fi
      }
      REST_PORT="$(free_port)"
      REST_ADDR="127.0.0.1:$REST_PORT"
      CONFIG="$WORKDIR/graphus.toml"
      SOCKET="$WORKDIR/graphus.sock"
      SERVER_LOG="$WORKDIR/server.log"
      ADMIN_USER="etl"; ADMIN_PW="bulk-etl-demo-pw-1"
      cat > "$CONFIG" <<EOF
# Generated by examples/bulk-etl/run.sh — a UDS + plaintext-loopback-REST wire configuration.
store_path = "$WORKDIR/server-data"
default_database = "graphus"
buffer_pool_pages = 2048
uds_path = "$SOCKET"
rest_addr = "$REST_ADDR"
jwt_secret = "graphus-bulk-etl-demo-wire-secret-32chars-plus+"
# Plaintext loopback REST (dev/test only) so the network bulk-import upload needs no TLS/cert.
allow_insecure_network = true

[auth]
admin_user = "$ADMIN_USER"
admin_password = "$ADMIN_PW"
admin_uid = $(id -u)
EOF
      "$SERVER" "$CONFIG" >>"$SERVER_LOG" 2>&1 &
      SERVER_PID=$!
      BOUND=no
      for _ in $(seq 1 150); do
        [ -S "$SOCKET" ] && { BOUND=yes; break; }
        kill -0 "$SERVER_PID" 2>/dev/null || break
        sleep 0.1
      done
      assert "local server bound (ready for the wire load)" "yes" "$BOUND"
      if [ "$BOUND" != yes ]; then
        info "server did not come up; last log lines:"; tail -n 15 "$SERVER_LOG" >&2 || true
        WIRE_OK=0
      else
        # Point the shared external-target seam at our local server so ONE code path drives both modes.
        export GRAPHUS_TARGET_REST="http://$REST_ADDR"
        export GRAPHUS_TARGET_USER="$ADMIN_USER"
        export GRAPHUS_TARGET_PASSWORD="$ADMIN_PW"
        export GRAPHUS_TARGET_SYSTEM_DB="graphus"
        unset HARNESS_TARGET_TOKEN 2>/dev/null || true
        info "REST on $REST_ADDR (server pid $SERVER_PID)"
      fi
    fi
  fi

  # Prime the admin Bearer in THIS shell (so every later $(harness_target_login) subshell reuses it).
  if [ "$WIRE_OK" = 1 ]; then
    harness_target_login >/dev/null 2>&1 || { info "could not authenticate against the target"; WIRE_OK=0; }
  fi

  # Isolated target database (created here; dropped by the exit trap via the PID-keyed state file).
  if [ "$WIRE_OK" = 1 ]; then
    WIRE_DB="$(harness_target_ensure_db)" || WIRE_DB=""
    if [ -z "$WIRE_DB" ]; then
      info "could not resolve an isolated target database"; WIRE_OK=0
    fi
    assert "isolated wire database resolved" "yes" "$([ -n "$WIRE_DB" ] && echo yes || echo no)"
  fi

  if [ "$WIRE_OK" = 1 ]; then
    section "Step 6 — stream the CSVs into '$WIRE_DB' in $BATCH_ROWS-row batches (Mode A)"
    rm -rf "$WIRE_EVIDENCE_DIR"; mkdir -p "$WIRE_EVIDENCE_DIR" "$CHUNK_DIR"
    : > "$LATENCY_SAMPLES"

    # 1. Scrape /metrics BEFORE the wire workload (whole-server; the delta is attributed to WIRE_DB).
    harness_scrape_metrics "$METRICS_BEFORE" || info "metrics-before scrape failed (non-fatal)"
    assert "/metrics scraped before the wire load" "yes" "$([ -s "$METRICS_BEFORE" ] && echo yes || echo no)"

    # 2. Slice every CSV into <BATCH_ROWS>-row chunks (each carrying the file's header row).
    NODE_CHUNKS=(); REL_CHUNKS=()
    for f in "${WIRE_NODE_FILES[@]}"; do
      while IFS= read -r c; do NODE_CHUNKS+=("$c"); done < <(chunk_csv "$DATA_DIR/$f" "$CHUNK_DIR/${f%.csv}" "$BATCH_ROWS")
    done
    for f in "${WIRE_REL_FILES[@]}"; do
      while IFS= read -r c; do REL_CHUNKS+=("$c"); done < <(chunk_csv "$DATA_DIR/$f" "$CHUNK_DIR/${f%.csv}" "$BATCH_ROWS")
    done
    TOTAL_BATCHES=$(( ${#NODE_CHUNKS[@]} + ${#REL_CHUNKS[@]} ))
    info "sliced into $TOTAL_BATCHES batches of <= $BATCH_ROWS rows (${#NODE_CHUNKS[@]} node + ${#REL_CHUNKS[@]} relationship)"
    assert_gt "the dataset sliced into multiple ingest batches" "$TOTAL_BATCHES" 1

    # 3. Stream node batches, then relationship batches. Every request is timed; a non-200 fails.
    #    ALL nodes land before ANY relationship (two passes), as the importer requires.
    WIRE_STREAM_OK=yes
    WIRE_START="$(_harness_now_ms)"
    for phase in nodes relationships; do
      # `${arr[@]+"${arr[@]}"}` — bash 3.2 (which is what macOS still ships, and macOS is a Tier-1
      # target) treats a plain `"${arr[@]}"` on an EMPTY array as an unbound variable under `set -u`.
      if [ "$phase" = nodes ]; then
        CHUNKS=(${NODE_CHUNKS[@]+"${NODE_CHUNKS[@]}"})
      else
        CHUNKS=(${REL_CHUNKS[@]+"${REL_CHUNKS[@]}"})
      fi
      [ "${#CHUNKS[@]}" -gt 0 ] || continue
      RESULTS="$(wire_post_chunks "$WIRE_DB" "$phase" "${CHUNKS[@]}")"
      # One `<http_code> <time_total>` line per request, in order.
      LINES="$(printf '%s\n' "$RESULTS" | grep -c '^[0-9]' || true)"
      if [ "$LINES" != "${#CHUNKS[@]}" ]; then
        info "phase=$phase: expected ${#CHUNKS[@]} responses, got $LINES — the upload did not complete"
        WIRE_STREAM_OK=no
      fi
      BAD="$(printf '%s\n' "$RESULTS" | awk '$1 != 200 && $1 != "" { c++ } END { print c + 0 }')"
      if [ "$BAD" != 0 ]; then
        info "phase=$phase: $BAD batch(es) did NOT return HTTP 200"
        printf '%s\n' "$RESULTS" | awk '$1 != 200 && $1 != ""' | head -3 | sed 's/^/    /'
        WIRE_STREAM_OK=no
        # Report the FIRST failing batch with the server's own message, not just its status code.
        FIRST_BAD_IDX="$(printf '%s\n' "$RESULTS" | awk '$1 != 200 && $1 != "" { print NR; exit }')"
        if [ -n "${FIRST_BAD_IDX:-}" ]; then
          wire_diagnose "$WIRE_DB" "$phase" "${CHUNKS[$((FIRST_BAD_IDX - 1))]}" || true
        fi
      fi
      # Append this phase's per-request wall times (seconds) to the latency sample file.
      printf '%s\n' "$RESULTS" | awk '$1 == 200 { print $2 }' >> "$LATENCY_SAMPLES"
    done
    WIRE_END="$(_harness_now_ms)"
    assert "every ingest batch was accepted (HTTP 200)" "yes" "$WIRE_STREAM_OK"

    # `grep -c` PRINTS "0" and EXITS 1 when it matches nothing, so a `|| echo 0` fallback appends a
    # SECOND zero and the count reads "0\n0". `|| true` keeps the printed count and swallows the exit.
    SAMPLE_COUNT="$(grep -c '[0-9]' "$LATENCY_SAMPLES" 2>/dev/null || true)"
    assert "per-batch ingest latency was sampled once per batch" "$TOTAL_BATCHES" "${SAMPLE_COUNT:-0}"

    # 4. End the session; the server reports its cumulative ingest tally.
    END_BODY="$(_harness_curl -sS -X POST \
                 "$(_harness_target_rest_base)/admin/db/$WIRE_DB/bulk-import?end=true" \
                 -H "Authorization: Bearer $(harness_target_login)" 2>/dev/null || true)"
    info "end=true stats: $END_BODY"
    END_NODES="$(wire_json_int "$END_BODY" nodes)"
    END_RELS="$(wire_json_int "$END_BODY" relationships)"
    END_PROPS="$(wire_json_int "$END_BODY" properties)"
    assert "server ingest tally: node count == manifest" "$NODE_COUNT" "${END_NODES:-none}"
    assert "server ingest tally: relationship count == manifest" "$REL_COUNT" "${END_RELS:-none}"
    assert "server ingest tally: property count == manifest" "$PROP_COUNT" "${END_PROPS:-none}"

    # 5. Bring the loaded database online (Mode A leaves it Offline).
    START_RESP="$(harness_target_query "$(_harness_target_system_db)" "START DATABASE $WIRE_DB" || true)"
    assert "START DATABASE brought the loaded DB online" "yes" \
      "$(grep -q '"results"' <<<"$START_RESP" && echo yes || echo no)"

    # 6. Query the online database: row counts must equal the manifest.
    CN="$(wire_jolt_int "$(harness_target_query "$WIRE_DB" "MATCH (n) RETURN count(n) AS c" || true)")"
    CR="$(wire_jolt_int "$(harness_target_query "$WIRE_DB" "MATCH ()-[r]->() RETURN count(r) AS c" || true)")"
    assert "queried node count == manifest" "$NODE_COUNT" "${CN:-none}"
    assert "queried relationship count == manifest" "$REL_COUNT" "${CR:-none}"

    # 7. Best-effort, VERSION-TOLERANT online DDL over the ACTUALLY-loaded network data + evidence.
    #    Only DDL that is meaningful over bulk-imported nodes is applied: the CSV `:ID` is the physical
    #    join key and is NOT stored as a queryable property (verified — `keys(n)` carries no `id`), so
    #    the id-anchored constraint palette (NODE KEY / UNIQUE on `.id`) is documented but not applied
    #    here. What IS exercised: a RANGE index on a real timeline property + property-type constraints
    #    (satisfied by construction). An OLDER server may reject some DDL — each statement is therefore
    #    best-effort and NON-FATAL; the count of accepted statements is reported.
    section "Step 6 — version-tolerant online DDL over the network-loaded data + schema evidence"
    SCHEMA_STMTS=(
      "CREATE INDEX FOR (n:Post) ON (n.createdAt)"
      "CREATE CONSTRAINT bulk_etl_post_length_int FOR (n:Post) REQUIRE n.length IS :: INTEGER"
      "CREATE CONSTRAINT bulk_etl_has_creator_weight_int FOR ()-[r:HAS_CREATOR]-() REQUIRE r.weight IS :: INTEGER"
    )
    SCHEMA_TOTAL=${#SCHEMA_STMTS[@]}
    SCHEMA_OK=0
    for stmt in "${SCHEMA_STMTS[@]}"; do
      R="$(harness_target_query "$WIRE_DB" "$stmt" 2>/dev/null || true)"
      if grep -q '"results"' <<<"$R"; then
        SCHEMA_OK=$((SCHEMA_OK + 1))
      else
        info "online DDL not accepted by this server (version-tolerant, non-fatal): $stmt"
      fi
    done
    info "online schema DDL applied: $SCHEMA_OK/$SCHEMA_TOTAL statement(s) accepted"
    # The online DDL over the bulk-loaded data must SUCCEED on a current server. Swallowing a rejection
    # into a "version gap" was a green tick that could never go red: a real defect in CREATE INDEX /
    # constraint enforcement over bulk-imported nodes read as "older target", not a failure (rmp #743).
    # Version-tolerance is retained ONLY behind an explicit GRAPHUS_TARGET_LEGACY=1 opt-out for attaching
    # to a server that genuinely predates a DDL form.
    if [ "${GRAPHUS_TARGET_LEGACY:-0}" = 1 ]; then
      info "GRAPHUS_TARGET_LEGACY=1 — online DDL treated as best-effort (older target); not gated"
    else
      assert "online DDL over the loaded data was fully accepted ($SCHEMA_OK/$SCHEMA_TOTAL)" \
        "$SCHEMA_TOTAL" "$SCHEMA_OK"
    fi
    harness_target_query "$WIRE_DB" "SHOW CONSTRAINTS" > "$WIRE_EVIDENCE_DIR/schema_constraints.json" 2>/dev/null || true
    harness_target_query "$WIRE_DB" "SHOW INDEXES"     > "$WIRE_EVIDENCE_DIR/schema_indexes.json"     2>/dev/null || true
    assert "schema evidence captured (SHOW CONSTRAINTS/INDEXES over the loaded data)" "yes" \
      "$([ -s "$WIRE_EVIDENCE_DIR/schema_constraints.json" ] && echo yes || echo no)"

    # 8. Scrape /metrics AFTER + emit the wire evidence report (server-side deltas + REAL per-batch
    #    ingest latency percentiles) via measure_target.
    section "Step 6 — server-side /metrics + per-batch ingest latency for the wire load"
    harness_scrape_metrics "$METRICS_AFTER" || info "metrics-after scrape failed (non-fatal)"
    assert "/metrics scraped after the wire load" "yes" "$([ -s "$METRICS_AFTER" ] && echo yes || echo no)"

    WIRE_ELEMENTS=$(( ${NODE_COUNT:-0} + ${REL_COUNT:-0} ))
    # Wire-load wall time in seconds, formatted with a '.' decimal via pure integer math so it is
    # LOCALE-PROOF (an awk/printf float would use the locale decimal separator — e.g. a comma under a
    # pt-PT/de locale — which measure_target's `parse::<f64>` rejects as an "invalid float literal").
    WIRE_MS=$(( WIRE_END - WIRE_START ))
    [ "$WIRE_MS" -le 0 ] && WIRE_MS=1
    WIRE_SECS="$(( WIRE_MS / 1000 )).$(printf '%03d' "$(( WIRE_MS % 1000 ))")"
    info "wire load: $WIRE_ELEMENTS elements in ${WIRE_SECS}s across $TOTAL_BATCHES batches"

    # Built (fresh) by harness_build above — no build-only-if-absent guard that could run a stale binary.
    MEASURE_BIN="$BIN_DIR/measure_target"

    if [ -x "$MEASURE_BIN" ] && [ -s "$METRICS_BEFORE" ] && [ -s "$METRICS_AFTER" ]; then
      "$MEASURE_BIN" \
        --evidence-dir "$WIRE_EVIDENCE_DIR" \
        --scenario "bulk-etl-wire" \
        --description "network bulk-import (Mode A): stream the generated LDBC-SNB-like CSVs into a running server in realistic batches; per-batch ingest latency client-side, server-side evidence from /metrics" \
        --database "$WIRE_DB" \
        --metrics-before "$METRICS_BEFORE" --metrics-after "$METRICS_AFTER" \
        --nodes "$NODE_COUNT" --rels "$REL_COUNT" \
        --workload-ops "$WIRE_ELEMENTS" --workload-secs "$WIRE_SECS" \
        --latency-samples-secs "$LATENCY_SAMPLES" \
        --param "connection=rest-bulk-import-mode-a" \
        --param "profile=$PROFILE" \
        --param "wire_mode=$WIRE_MODE" \
        --param "target=$(_harness_target_rest_base)" \
        --param "scenario_db=$WIRE_DB" \
        --param "batch_rows=$BATCH_ROWS" \
        --param "ingest_batches=$TOTAL_BATCHES" \
        --param "node_count=$NODE_COUNT" \
        --param "relationship_count=$REL_COUNT" \
        --param "property_count=$PROP_COUNT" \
        --param "server_ingest_nodes=${END_NODES:-0}" \
        --param "server_ingest_relationships=${END_RELS:-0}" \
        --param "server_ingest_properties=${END_PROPS:-0}" \
        --param "online_ddl_accepted=$SCHEMA_OK/$SCHEMA_TOTAL" \
        --note "The network bulk-import Mode A path streamed the SAME dataset the offline importer consumes, in $TOTAL_BATCHES batches of up to $BATCH_ROWS rows; the server's own ingest tally and the queried row counts both equal the generator manifest ($NODE_COUNT nodes, $REL_COUNT relationships, $PROP_COUNT properties)." \
        --note "throughput.operations counts ELEMENTS (nodes + relationships) and ops_per_sec is the element rate over the whole wire window, while the LATENCY percentiles are per BATCH (one timed HTTP request each) — the two count different things on purpose, and each says which in its name." \
        --note "CSV :ID is the physical-id join key and is NOT persisted as a queryable node property, so the id-anchored constraint palette (NODE KEY / UNIQUE on .id) is declared by an operator only after id is materialised; the wire step exercises the DDL that is meaningful directly over bulk-imported data (a RANGE index on a real timeline property + property-type constraints)." \
        --assert \
        && info "wire evidence written to $WIRE_EVIDENCE_DIR" \
        || { info "measure_target reported an invariant violation or error"; FAILURES=$((FAILURES + 1)); }
      assert "wire report.json produced (measurement_mode=external)" "yes" \
        "$([ -f "$WIRE_EVIDENCE_DIR/report.json" ] && grep -q '"measurement_mode": *"external"' "$WIRE_EVIDENCE_DIR/report.json" && echo yes || echo no)"
      assert "wire report.json carries server_metrics deltas" "yes" \
        "$([ -f "$WIRE_EVIDENCE_DIR/report.json" ] && grep -q '"server_metrics"' "$WIRE_EVIDENCE_DIR/report.json" && echo yes || echo no)"
      # The whole point of batching the upload: a REAL, MEASURED ingest latency where a request
      # boundary exists. A report that came back without one has silently lost the measurement.
      assert "wire report.json carries a MEASURED per-batch ingest latency (p50)" "yes" \
        "$([ -f "$WIRE_EVIDENCE_DIR/report.json" ] && grep -q '"p50_latency_ms"' "$WIRE_EVIDENCE_DIR/report.json" && echo yes || echo no)"
    else
      info "measure_target unavailable or metrics missing — wire server-side evidence not collected"
      FAILURES=$((FAILURES + 1))
    fi
  fi
fi

# ==================================================================================================
# Step 7 — is the OFFLINE-produced store directly server-openable? (rmp #681)
#
# An honest, first-class probe (not a silent sidestep), run against the REAL store the metered import
# in Step 3 produced — no extra import. The offline `graphus-bulk import` writes a flat
# `<dir>/graph.store` + `graph.wal` pair, whereas a `graphus-server` resolves its store as
# `<store_path>/databases/<name>/graphus.store` (+ catalog/meta). We check for that layout so the
# incompatibility is SURFACED as a finding rather than assumed. Informational (it is a known,
# documented gap, not a regression this run introduced).
# ==================================================================================================
section "Step 7 — offline store server-openability probe (rmp #681, informational)"
if [ -e "$OFFLINE_STORE/graph.store" ]; then
  HAS_SERVER_LAYOUT=no
  [ -d "$OFFLINE_STORE/databases" ] && HAS_SERVER_LAYOUT=yes
  info "offline import wrote: $(ls -1 "$OFFLINE_STORE" 2>/dev/null | tr '\n' ' ')"
  info "FINDING (rmp #681, STILL OPEN): the offline store is a flat graph.store + graph.wal pair; a"
  info "graphus-server expects <store_path>/databases/<name>/graphus.store (+ catalog)."
  info "server-openable directly: $HAS_SERVER_LAYOUT."
  info "The online demo therefore reaches the SAME data through the network bulk-import path (Step 6),"
  info "not by pointing a server at the offline store — the incompatibility is surfaced, not sidestepped."
  assert "the #681 probe examined the real offline store" "yes" "yes"
else
  info "no offline store to probe (Step 3 did not keep one) — skipping the #681 finding this run"
fi

# --------------------------------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------------------------------
section "Result"
printf '%s checks run, %s failures.\n' "$CHECKS" "$FAILURES"
if [ -f "$EVIDENCE_DIR/report.json" ]; then
  info "offline evidence:      $EVIDENCE_DIR/{report.json, report.md}"
fi
if [ -f "$WIRE_EVIDENCE_DIR/report.json" ]; then
  info "wire (server) evidence: $WIRE_EVIDENCE_DIR/{report.json, report.md, schema_*.json}"
fi
if [ "$FAILURES" -eq 0 ]; then
  printf '%s%sBULK-ETL DEMONSTRATION PASSED%s — Graphus generated a byte-identical seeded social network\n' "$BOLD" "$GREEN" "$RESET"
  printf '%s\n' "($PROFILE profile: $NODE_COUNT nodes, $REL_COUNT relationships), bulk-imported it with the real graphus-bulk"
  printf '%s\n' "binary, proved a LOSSLESS import -> dump -> re-import round-trip by content hash, measured the"
  printf '%s\n' "on-disk footprint + WAL residual + amplification AND THE COST OF REOPENING the loaded store,"
  printf '%s\n' "streamed the SAME data into a running server in realistic batches over the network bulk-import"
  printf '%s\n' "(Mode A) path with a REAL per-batch ingest latency, and collected server-side /metrics evidence."
  exit 0
else
  printf '%s%sBULK-ETL DEMONSTRATION FAILED%s — %s assertion(s) did not hold.\n' "$BOLD" "$RED" "$RESET" "$FAILURES"
  exit 1
fi
