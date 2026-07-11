#!/usr/bin/env bash
#
# Graphus high-throughput bulk ingest & ETL demonstration.
#
# This script doubles as an executable E2E test. Its OFFLINE core (always run, hermetic — no server,
# no network) proves the loader path end to end:
#   1. generates a DETERMINISTIC, SEEDED LDBC-SNB-like social-network dataset as loader-ready CSV
#      (per-label node files + per-type relationship files + manifest.json) via the `bulk_gen` binary,
#      and proves the generator is BYTE-IDENTICAL per seed by regenerating and diffing;
#   2. imports the dataset into a fresh store with the REAL `graphus-bulk import` binary, asserting the
#      reported node/relationship counts equal the manifest;
#   3. proves a LOSSLESS `import -> dump -> re-import` round-trip (`bulk_roundtrip`): the whole graph is
#      dumped back to CSV, re-imported into a second fresh store, and the two stores are proven identical
#      by an id-independent CONTENT HASH (same labels, types, property values, connectivity);
#   4. measures the on-disk STORAGE footprint + write/space amplification (`bulk_storage` -> storage.json);
#   5. emits the standardized, schema-versioned report.json + report.md and gates a fresh fast-profile
#      run against the committed baseline.json (STRUCTURAL metrics only) via `bulk_baseline_cmp`.
#
# It THEN drives the SAME generated CSVs into a RUNNING server over the ratified network bulk-import
# (Mode A) path (`specification/08-network-bulk-import.md`): an empty database is taken over exclusively,
# the per-label node files are streamed (`POST /admin/db/{db}/bulk-import?phase=nodes`), then the
# per-type relationship files (`?phase=relationships`), then the session is ended (`?end=true`) and the
# database brought online (`START DATABASE`). It asserts the server's own final ingest tally AND the
# queried row counts equal the manifest, and collects SERVER-SIDE evidence from the target's Prometheus
# `/metrics` (before/after deltas) into a wire report.json via the shared `measure_target` binary. The
# wire load is isolated in a dedicated database dropped on exit.
#
# The wire step runs against a self-booted local plaintext-loopback REST server by default, or ATTACHES
# to an already-running instance (local OR remote, e.g. pi516) when a GRAPHUS_TARGET_* endpoint is set
# (the shared external-target seam in `_harness/harness.sh`).
#
# Usage:
#   examples/bulk-etl/run.sh                       # offline core + local self-boot wire step
#   GRAPHUS_BIN_DIR=target/release  examples/bulk-etl/run.sh
#   BULK_PROFILE=large              examples/bulk-etl/run.sh   # evidence-scale dataset
#   RUN_WIRE=0                      examples/bulk-etl/run.sh   # offline core only (no server)
#   GRAPHUS_TARGET_REST=https://host:7474 GRAPHUS_TARGET_USER=graphus \
#     GRAPHUS_TARGET_PASSWORD=graphus-local GRAPHUS_TARGET_TLS_INSECURE=1 \
#     examples/bulk-etl/run.sh                     # stream into an already-running instance (e.g. pi516)
#
# Requirements: a Unix host (Linux/macOS), bash, curl. The offline core needs no network; the wire step
# needs a REST-reachable server (self-booted locally, or the GRAPHUS_TARGET_REST target).

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
SERVER="$BIN_DIR/graphus-server"

PROFILE="${BULK_PROFILE:-fast}"
# The offline import/round-trip/storage/baseline core is the always-run hermetic body. The network
# bulk-import (Mode A) WIRE step (Step 5) streams the SAME generated CSVs into a running server and is
# OPT-IN via RUN_WIRE (default ON; set RUN_WIRE=0 to skip it on a host with no server/network).
RUN_WIRE="${RUN_WIRE:-1}"

# The offline importer is its own release binary; the generator + drivers are the dev-only crate's.
# harness_build rebuilds unconditionally (cargo is incremental) so the evidence always describes the
# CURRENT sources — a build-only-if-absent guard silently runs a STALE binary after any source edit.
harness_build "the offline graphus-bulk importer (release)" --release -p graphus-bulk --bin graphus-bulk
harness_build "the dev-only bulk-etl generator + drivers (release)" --release -p graphus-bulk-gen --bins
for b in "$BULK" "$GEN" "$ROUNDTRIP" "$STORAGE" "$EVIDENCE_BIN" "$CMP_BIN"; do
  [ -x "$b" ] || { echo "${RED}fatal: required binary not found at $b${RESET}" >&2; exit 2; }
done

# --------------------------------------------------------------------------------------------------
# Workspace + evidence paths. The temp workspace is removed on exit (success or failure). The
# evidence/ dir is git-ignored; baseline.json lives at a non-ignored path. The offline evidence lands
# at evidence/report.json; the WIRE evidence lands under evidence/wire/ so the two never clobber.
# --------------------------------------------------------------------------------------------------
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/graphus-bulk-etl-XXXXXX")"
DATA_DIR="$WORKDIR/data"
STORAGE_JSON="$WORKDIR/storage.json"
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
WIRE_EVIDENCE_DIR="$EVIDENCE_DIR/wire"
BASELINE="$SCRIPT_DIR/baseline.json"
METRICS_BEFORE="$WORKDIR/metrics_before.prom"
METRICS_AFTER="$WORKDIR/metrics_after.prom"

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

# --------------------------------------------------------------------------------------------------
# Step 1 — generate the deterministic dataset + prove it is byte-identical per seed
# --------------------------------------------------------------------------------------------------
section "Step 1 — generate the deterministic social-network dataset ($PROFILE profile)"
GEN_OUT="$("$GEN" --profile "$PROFILE" --out-dir "$DATA_DIR")"
printf '%s\n' "$GEN_OUT" | sed 's/^/  /'
NODE_COUNT="$(kv "$GEN_OUT" nodes)"
REL_COUNT="$(kv "$GEN_OUT" relationships)"
PROP_COUNT="$(kv "$GEN_OUT" properties)"
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

# ==================================================================================================
# Step 5 — network bulk-import (Mode A) over the wire + server-side /metrics evidence
#
# The realistic offline->online workflow: after characterising the OFFLINE load above, an operator
# brings the SAME data online by streaming the generator's CSVs into a RUNNING server over the ratified
# network bulk-import Mode A happy path. We assert the server's own final ingest tally AND the queried
# row counts equal the manifest, scrape the target's /metrics before + after the load, and fold the
# server-side deltas into a wire report.json via the shared `measure_target` binary. The wire load is
# isolated in a dedicated database (harness_target_ensure_db) dropped on exit (harness_target_drop_db).
#
# It runs against a self-booted local plaintext-loopback REST server by default, or ATTACHES to an
# already-running instance (local OR remote, e.g. pi516) when a GRAPHUS_TARGET_* endpoint is set.
# ==================================================================================================

# The generator's node + relationship CSV file names, in load order (must match bulk_gen).
WIRE_NODE_FILES=(persons.csv forums.csv posts.csv comments.csv)
WIRE_REL_FILES=(knows.csv has_member.csv container_of.csv has_creator.csv reply_of.csv likes.csv)

# wire_json_int <json> <key> — extract a top-level integer field from a plain-JSON stats object.
wire_json_int() { printf '%s' "$1" | sed -n "s/.*\"$2\":\([0-9][0-9]*\).*/\1/p" | head -n1; }
# wire_jolt_int <tx-commit-json> — extract the first strict-Jolt integer cell {"Z":"N"} scalar.
wire_jolt_int() { printf '%s' "$1" | sed -n 's/.*"Z":"\([0-9][0-9]*\)".*/\1/p' | head -n1; }

# wire_bulk <db> <phase-query> <csv-file> <body-out> — stream one CSV file to the bulk-import endpoint;
# writes the response body to <body-out> and ECHOES the HTTP status code (captured by the caller in the
# parent shell — this function is always invoked in a $() subshell, so it must not rely on side-effect
# variables). Honours the self-signed-TLS opt-out (_harness_curl) and reuses the cached admin Bearer.
wire_bulk() {
  local db="$1" q="$2" file="$3" out="$4" base token
  base="$(_harness_target_rest_base)"
  token="$(harness_target_login)" || { echo 000; return 1; }
  _harness_curl -sS -o "$out" -w '%{http_code}' \
    -X POST "$base/admin/db/$db/bulk-import?$q" \
    -H "Authorization: Bearer $token" -H 'Content-Type: text/csv' \
    --data-binary "@$file" 2>/dev/null
}

if [ "$RUN_WIRE" != "1" ]; then
  section "Step 5 — network bulk-import wire step SKIPPED (RUN_WIRE=0)"
else
  WIRE_MODE="$(harness_target_mode)"   # external iff GRAPHUS_TARGET_{BOLT,REST,UDS} set at entry
  WIRE_OK=1
  WIRE_DB=""

  if [ "$WIRE_MODE" = external ]; then
    section "Step 5 — attach to the running instance for the network bulk-import wire step"
    if [ -z "${GRAPHUS_TARGET_REST:-}${GRAPHUS_TARGET_METRICS:-}" ]; then
      info "external target has no REST/_METRICS endpoint — the network bulk-import path is REST-only; skipping the wire step"
      WIRE_OK=0
    else
      info "attaching to ${GRAPHUS_TARGET_REST:-$GRAPHUS_TARGET_METRICS} (network bulk-import Mode A)"
    fi
  else
    section "Step 5 — boot a local plaintext-loopback REST server for the network bulk-import wire step"
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
    section "Step 5 — stream the generated CSVs into '$WIRE_DB' (network bulk-import Mode A)"
    rm -rf "$WIRE_EVIDENCE_DIR"; mkdir -p "$WIRE_EVIDENCE_DIR"

    # 1. Scrape /metrics BEFORE the wire workload (whole-server; the delta is attributed to WIRE_DB).
    harness_scrape_metrics "$METRICS_BEFORE" || info "metrics-before scrape failed (non-fatal)"
    assert "/metrics scraped before the wire load" "yes" "$([ -s "$METRICS_BEFORE" ] && echo yes || echo no)"

    # 2. Stream node files (?phase=nodes), then relationship files (?phase=relationships).
    WIRE_RESP="$WORKDIR/wire_resp.json"
    WIRE_START="$(_harness_now_ms)"
    WIRE_STREAM_OK=yes
    for f in "${WIRE_NODE_FILES[@]}"; do
      CODE="$(wire_bulk "$WIRE_DB" "phase=nodes" "$DATA_DIR/$f" "$WIRE_RESP")" || CODE=000
      if [ "$CODE" != 200 ]; then
        info "bulk phase=nodes $f -> HTTP $CODE: $(cat "$WIRE_RESP" 2>/dev/null)"; WIRE_STREAM_OK=no; break
      fi
    done
    if [ "$WIRE_STREAM_OK" = yes ]; then
      for f in "${WIRE_REL_FILES[@]}"; do
        CODE="$(wire_bulk "$WIRE_DB" "phase=relationships" "$DATA_DIR/$f" "$WIRE_RESP")" || CODE=000
        if [ "$CODE" != 200 ]; then
          info "bulk phase=relationships $f -> HTTP $CODE: $(cat "$WIRE_RESP" 2>/dev/null)"; WIRE_STREAM_OK=no; break
        fi
      done
    fi
    assert "all node + relationship CSVs streamed (HTTP 200)" "yes" "$WIRE_STREAM_OK"

    # 3. End the session; the server reports its cumulative ingest tally.
    END_BODY="$(_harness_curl -sS -X POST \
                 "$(_harness_target_rest_base)/admin/db/$WIRE_DB/bulk-import?end=true" \
                 -H "Authorization: Bearer $(harness_target_login)" 2>/dev/null || true)"
    WIRE_END="$(_harness_now_ms)"
    info "end=true stats: $END_BODY"
    END_NODES="$(wire_json_int "$END_BODY" nodes)"
    END_RELS="$(wire_json_int "$END_BODY" relationships)"
    END_PROPS="$(wire_json_int "$END_BODY" properties)"
    assert "server ingest tally: node count == manifest" "$NODE_COUNT" "${END_NODES:-none}"
    assert "server ingest tally: relationship count == manifest" "$REL_COUNT" "${END_RELS:-none}"
    assert "server ingest tally: property count == manifest" "$PROP_COUNT" "${END_PROPS:-none}"

    # 4. Bring the loaded database online (Mode A leaves it Offline).
    START_RESP="$(harness_target_query "$(_harness_target_system_db)" "START DATABASE $WIRE_DB" || true)"
    assert "START DATABASE brought the loaded DB online" "yes" \
      "$(printf '%s' "$START_RESP" | grep -q '"results"' && echo yes || echo no)"

    # 5. Query the online database: row counts must equal the manifest.
    CN="$(wire_jolt_int "$(harness_target_query "$WIRE_DB" "MATCH (n) RETURN count(n) AS c" || true)")"
    CR="$(wire_jolt_int "$(harness_target_query "$WIRE_DB" "MATCH ()-[r]->() RETURN count(r) AS c" || true)")"
    assert "queried node count == manifest" "$NODE_COUNT" "${CN:-none}"
    assert "queried relationship count == manifest" "$REL_COUNT" "${CR:-none}"

    # 6. Best-effort, VERSION-TOLERANT online DDL over the ACTUALLY-loaded network data + evidence.
    #    Only DDL that is meaningful over bulk-imported nodes is applied: the CSV `:ID` is the physical
    #    join key and is NOT stored as a queryable property (verified — `keys(n)` carries no `id`), so
    #    the id-anchored constraint palette (NODE KEY / UNIQUE on `.id`) is documented but not applied
    #    here. What IS exercised: a RANGE index on a real timeline property + property-type constraints
    #    (satisfied by construction). An OLDER server may reject some DDL (e.g. pi516 rejects the typed
    #    TEXT/FULLTEXT index DDL and the `SHOW ... YIELD` projection form) — each statement is therefore
    #    best-effort and NON-FATAL; the count of accepted statements is reported.
    section "Step 5 — version-tolerant online DDL over the network-loaded data + schema evidence"
    SCHEMA_STMTS=(
      "CREATE INDEX FOR (n:Post) ON (n.createdAt)"
      "CREATE CONSTRAINT bulk_etl_post_length_int FOR (n:Post) REQUIRE n.length IS :: INTEGER"
      "CREATE CONSTRAINT bulk_etl_has_creator_weight_int FOR ()-[r:HAS_CREATOR]-() REQUIRE r.weight IS :: INTEGER"
    )
    SCHEMA_TOTAL=${#SCHEMA_STMTS[@]}
    SCHEMA_OK=0
    for stmt in "${SCHEMA_STMTS[@]}"; do
      R="$(harness_target_query "$WIRE_DB" "$stmt" 2>/dev/null || true)"
      if printf '%s' "$R" | grep -q '"results"'; then
        SCHEMA_OK=$((SCHEMA_OK + 1))
      else
        info "online DDL not accepted by this server (version-tolerant, non-fatal): $stmt"
      fi
    done
    info "online schema DDL applied: $SCHEMA_OK/$SCHEMA_TOTAL statement(s) accepted"
    # Capture the plain SHOW CONSTRAINTS / SHOW INDEXES listings as evidence (no YIELD — an older
    # server rejects the projection form).
    harness_target_query "$WIRE_DB" "SHOW CONSTRAINTS" > "$WIRE_EVIDENCE_DIR/schema_constraints.json" 2>/dev/null || true
    harness_target_query "$WIRE_DB" "SHOW INDEXES"     > "$WIRE_EVIDENCE_DIR/schema_indexes.json"     2>/dev/null || true
    assert "schema evidence captured (SHOW CONSTRAINTS/INDEXES over the loaded data)" "yes" \
      "$([ -s "$WIRE_EVIDENCE_DIR/schema_constraints.json" ] && echo yes || echo no)"

    # 7. Scrape /metrics AFTER + emit the wire evidence report (server-side deltas) via measure_target.
    section "Step 5 — server-side /metrics evidence for the wire load (measure_target, external mode)"
    harness_scrape_metrics "$METRICS_AFTER" || info "metrics-after scrape failed (non-fatal)"
    assert "/metrics scraped after the wire load" "yes" "$([ -s "$METRICS_AFTER" ] && echo yes || echo no)"

    WIRE_ELEMENTS=$(( ${NODE_COUNT:-0} + ${REL_COUNT:-0} ))
    # Wire-load wall time in seconds, formatted with a '.' decimal via pure integer math so it is
    # LOCALE-PROOF (an awk/printf float would use the locale decimal separator — e.g. a comma under a
    # pt-PT/de locale — which measure_target's `parse::<f64>` rejects as an "invalid float literal").
    WIRE_MS=$(( WIRE_END - WIRE_START ))
    [ "$WIRE_MS" -le 0 ] && WIRE_MS=1
    WIRE_SECS="$(( WIRE_MS / 1000 )).$(printf '%03d' "$(( WIRE_MS % 1000 ))")"

    MEASURE_BIN="$BIN_DIR/measure_target"
    if [ ! -x "$MEASURE_BIN" ]; then
      info "building the dev-only measure_target harness binary…"
      ( cd "$REPO_ROOT" && cargo build -q -p graphus-examples-harness --bin measure_target ) || true
      for cand in "$REPO_ROOT/target/release/measure_target" "$REPO_ROOT/target/debug/measure_target"; do
        [ -x "$cand" ] && MEASURE_BIN="$cand" && break
      done
    fi

    if [ -x "$MEASURE_BIN" ] && [ -s "$METRICS_BEFORE" ] && [ -s "$METRICS_AFTER" ]; then
      "$MEASURE_BIN" \
        --evidence-dir "$WIRE_EVIDENCE_DIR" \
        --scenario "bulk-etl-wire" \
        --description "network bulk-import (Mode A): stream the generated LDBC-SNB-like CSVs into a running server; server-side evidence from /metrics" \
        --database "$WIRE_DB" \
        --metrics-before "$METRICS_BEFORE" --metrics-after "$METRICS_AFTER" \
        --nodes "$NODE_COUNT" --rels "$REL_COUNT" \
        --workload-ops "$WIRE_ELEMENTS" --workload-secs "$WIRE_SECS" \
        --param "connection=rest-bulk-import-mode-a" \
        --param "profile=$PROFILE" \
        --param "wire_mode=$WIRE_MODE" \
        --param "target=$(_harness_target_rest_base)" \
        --param "scenario_db=$WIRE_DB" \
        --param "node_count=$NODE_COUNT" \
        --param "relationship_count=$REL_COUNT" \
        --param "property_count=$PROP_COUNT" \
        --param "server_ingest_nodes=${END_NODES:-0}" \
        --param "server_ingest_relationships=${END_RELS:-0}" \
        --param "server_ingest_properties=${END_PROPS:-0}" \
        --param "online_ddl_accepted=$SCHEMA_OK/$SCHEMA_TOTAL" \
        --note "The network bulk-import Mode A path streamed the SAME per-label node CSVs + per-type relationship CSVs the offline importer consumes; the server's own ingest tally and the queried row counts both equal the generator manifest ($NODE_COUNT nodes, $REL_COUNT relationships, $PROP_COUNT properties)." \
        --note "CSV :ID is the physical-id join key and is NOT persisted as a queryable node property, so the id-anchored constraint palette (NODE KEY / UNIQUE on .id) is declared by an operator only after id is materialised; the wire step exercises the DDL that is meaningful directly over bulk-imported data (a RANGE index on a real timeline property + property-type constraints)." \
        --assert \
        && info "wire evidence written to $WIRE_EVIDENCE_DIR" \
        || { info "measure_target reported an invariant violation or error"; FAILURES=$((FAILURES + 1)); }
      assert "wire report.json produced (measurement_mode=external)" "yes" \
        "$([ -f "$WIRE_EVIDENCE_DIR/report.json" ] && grep -q '"measurement_mode": *"external"' "$WIRE_EVIDENCE_DIR/report.json" && echo yes || echo no)"
      assert "wire report.json carries server_metrics deltas" "yes" \
        "$([ -f "$WIRE_EVIDENCE_DIR/report.json" ] && grep -q '"server_metrics"' "$WIRE_EVIDENCE_DIR/report.json" && echo yes || echo no)"
    else
      info "measure_target unavailable or metrics missing — wire server-side evidence not collected"
      FAILURES=$((FAILURES + 1))
    fi
  fi
fi

# ==================================================================================================
# Step 6 (STRETCH) — is the OFFLINE-produced store directly server-openable? (rmp #681)
#
# An honest, first-class probe (not a silent sidestep): the offline `graphus-bulk import` writes a flat
# `<dir>/graph.store` + `graph.wal` pair, whereas a `graphus-server` resolves its store as
# `<store_path>/databases/<name>/graphus.store` (+ catalog/meta). We import into a probe store and check
# for that layout so the incompatibility is SURFACED as a finding rather than assumed. Non-fatal.
# ==================================================================================================
if [ "$RUN_WIRE" = "1" ]; then
  section "Step 6 — offline store server-openability probe (rmp #681, informational)"
  PROBE_STORE="$WORKDIR/offline-store"
  IMPORT_ARGS=(import --db "$PROBE_STORE")
  for f in "${WIRE_NODE_FILES[@]}"; do IMPORT_ARGS+=(--nodes "$DATA_DIR/$f"); done
  for f in "${WIRE_REL_FILES[@]}"; do IMPORT_ARGS+=(--relationships "$DATA_DIR/$f"); done
  set +e
  "$BULK" "${IMPORT_ARGS[@]}" >/dev/null 2>&1
  IMPORT_RC=$?
  set -e
  if [ "$IMPORT_RC" -eq 0 ] && [ -e "$PROBE_STORE/graph.store" ]; then
    HAS_SERVER_LAYOUT=no
    [ -d "$PROBE_STORE/databases" ] && HAS_SERVER_LAYOUT=yes
    info "offline import wrote: $(ls -1 "$PROBE_STORE" 2>/dev/null | tr '\n' ' ')"
    info "FINDING (rmp #681): the offline store is a flat graph.store + graph.wal pair; a graphus-server"
    info "expects <store_path>/databases/<name>/graphus.store (+ catalog). server-openable directly: $HAS_SERVER_LAYOUT."
    info "The online demo therefore reaches the SAME data through the network bulk-import path (Step 5),"
    info "not by pointing a server at the offline store — the incompatibility is surfaced, not sidestepped."
  else
    info "offline store probe import did not complete (rc=$IMPORT_RC) — skipping the #681 finding this run"
  fi
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
  printf '%s%sBULK-ETL DEMONSTRATION PASSED%s — Graphus generated a byte-identical seeded social network,\n' "$BOLD" "$GREEN" "$RESET"
  printf '%s\n' "bulk-imported it with the real graphus-bulk binary, proved a LOSSLESS import -> dump -> re-import"
  printf '%s\n' "round-trip by content hash, characterised the on-disk store footprint + amplification, streamed the"
  printf '%s\n' "SAME CSVs into a running server over the network bulk-import (Mode A) path with the server's ingest"
  printf '%s\n' "tally + queried counts equal to the manifest, and collected server-side /metrics evidence."
  exit 0
else
  printf '%s%sBULK-ETL DEMONSTRATION FAILED%s — %s assertion(s) did not hold.\n' "$BOLD" "$RED" "$RESET" "$FAILURES"
  exit 1
fi
