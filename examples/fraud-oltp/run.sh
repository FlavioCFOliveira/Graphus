#!/usr/bin/env bash
#
# Graphus fraud-detection OLTP demonstration — driven by the OFFICIAL Neo4j driver over Bolt+TLS,
# with an extreme-concurrency SSI driver on the REAL mule supernodes and a deterministic in-process
# SSI repro.
#
# It runs in TWO modes (auto-detected via the shared external-target seam in `_harness/harness.sh`):
#
#   LOCAL (default)   — self-boots a real `graphus-server` (Bolt-over-TCP + TLS + REST/`/metrics`),
#                       loads + detects + runs concurrency against it, meters the co-located process
#                       (CPU/RSS + on-disk store/WAL via `measure_server`), folds in the `/metrics`
#                       before/after delta (`inject_server_metrics`), and gates the run against the
#                       committed `baseline.json`.
#   EXTERNAL (attach) — when ANY of GRAPHUS_TARGET_{BOLT,REST,UDS} is set, attaches to an
#                       ALREADY-RUNNING instance (local OR remote). It carves out a
#                       dedicated, isolated database (session `{database}` routing), runs the same
#                       load + detect + concurrency there, scrapes the target's `/metrics` before +
#                       after, emits an EXTERNAL-mode report via `measure_target` (server-side
#                       committed/aborted/abort_rate/force-detached deltas + client throughput/latency
#                       — process CPU/RSS + storage are N/A remotely and no baseline is gated), and
#                       DROPS the isolated database on exit (never touching the target's own data).
#
# What it proves, either way:
#   1. a DETERMINISTIC, SEEDED fraud graph with a known, enumerable set of planted fraud structures
#      (transaction rings + mule fan-in/fan-out chains + shared-device/IP collusion clusters);
#   2. detection finds EXACTLY the planted fraud (0 FP / 0 FN) — rings, mules, velocity, AND the
#      shared-device/shared-IP collusion clusters (the generated device/ip fields);
#   3. a blended point-lookup OLTP mix (account-by-id, recent-transfers);
#   4. constraint enforcement (negative tests, gated on what the target's version supports);
#   5. a PRODUCTION-SHAPED OLTP CLIENT under extreme contention on the REAL mule supernodes: every
#      unit of business work is a DOUBLE-ENTRY ledger transfer driven as a MANAGED transaction through
#      the official driver (`executeWrite`), so an SSI abort is RETRIED with bounded exponential
#      backoff until it commits. It reports BOTH layers of truth — the ENGINE's abort rate (the
#      contention evidence) AND the application-visible outcome (transfers committed, retries per
#      commit, retry-inclusive p50/p99/p999, retry-budget exhaustion) — and asserts that the LEDGER
#      RECONCILES (total balance conserved; no transfer lost, none applied twice), that the
#      application makes PROGRESS, and that a serialization abort is CLASSIFIED RETRYABLE by the real
#      driver (a regression of rmp #612 FAILS the run);
#   6. the deterministic in-process SSI-contention repro (`dst_contention`).
#
# Steps 2-5 need Node + npm + network (for `npm install neo4j-driver`); they are OPT-IN via RUN_DRIVER
# (default ON when `node`/`npm` are present). The generator (step 1) and the DST repro (step 6) are
# HERMETIC and always run.
#
# Usage:
#   examples/fraud-oltp/run.sh                                         # local self-boot
#   FRAUD_PROFILE=large  examples/fraud-oltp/run.sh                    # evidence-scale dataset
#   FRAUD_RETRY=0        examples/fraud-oltp/run.sh                    # pure-contention isolation
#                                                                      #   (single-shot txns, no retry)
#   RUN_DRIVER=0         examples/fraud-oltp/run.sh                    # skip the official-driver steps
#   GRAPHUS_TARGET_BOLT=bolt+ssc://host:7687 GRAPHUS_TARGET_REST=https://host:7474 \
#     GRAPHUS_TARGET_USER=graphus GRAPHUS_TARGET_PASSWORD=graphus-local \
#     GRAPHUS_TARGET_TLS_INSECURE=1  examples/fraud-oltp/run.sh        # attach to a running instance
#
# Requirements: a Unix host, bash, curl. LOCAL mode also needs openssl (the self-signed cert). The
# official-driver steps also need node (v18+), npm, and network/cache for `npm install neo4j-driver`.

set -euo pipefail

# --------------------------------------------------------------------------------------------------
# Shared external-target seam (GRAPHUS_TARGET_* detection, isolated-DB create/drop, /metrics scrape).
# We source it FIRST, then (re)define this script's own pretty-printers + assert counters below so the
# familiar `CHECKS`/`FAILURES` summary is preserved; the harness's target helpers call `info`/`section`
# by name at call time, so they transparently use these definitions.
# --------------------------------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../_harness/harness.sh
source "$(cd "$SCRIPT_DIR/../_harness" && pwd)/harness.sh"
export HARNESS_SCENARIO="fraud-oltp"   # names the isolated DB: ex_fraud-oltp_<epoch>_<pid>

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

MODE="$(harness_target_mode)"   # external iff GRAPHUS_TARGET_{BOLT,REST,UDS} is set, else local

# --------------------------------------------------------------------------------------------------
# Locate (or build) the binaries
# --------------------------------------------------------------------------------------------------
BIN_DIR="${GRAPHUS_BIN_DIR:-$REPO_ROOT/target/release}"
SERVER="$BIN_DIR/graphus-server"
GEN="$BIN_DIR/gen"
DST="$BIN_DIR/dst_contention"

PROFILE="${FRAUD_PROFILE:-fast}"
DST_SEED="${FRAUD_DST_SEED:-42}"

# The server binary is only needed to self-boot in LOCAL mode.
if [ "$MODE" = local ]; then
  harness_build "graphus-server (release)" --release -p graphus-server
  [ -x "$SERVER" ] || { echo "${RED}fatal: server binary not found at $SERVER${RESET}" >&2; exit 2; }
fi

harness_build "the deterministic fraud generator (release)" --release -p graphus-fraud-gen --bin gen
[ -x "$GEN" ] || { echo "${RED}fatal: gen binary not found at $GEN${RESET}" >&2; exit 2; }

harness_build "the deterministic DST contention repro (release)" \
  --release -p graphus-fraud-gen --features dst-repro --bin dst_contention
[ -x "$DST" ] || { echo "${RED}fatal: dst_contention binary not found at $DST${RESET}" >&2; exit 2; }

# --------------------------------------------------------------------------------------------------
# Workspace + teardown
# --------------------------------------------------------------------------------------------------
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/graphus-fraud-XXXXXX")"
CONFIG="$WORKDIR/graphus.toml"
SERVER_LOG="$WORKDIR/server.log"
CERT="$WORKDIR/cert.pem"
KEY="$WORKDIR/key.pem"
DATA_DIR="$WORKDIR/dataset"
ADMIN_USER="neo4j"
ADMIN_PW="fraud-oltp-demo-pw-32bytes-minimum!"
JWT_SECRET="fraud-oltp-demo-jwt-secret-32bytes-ok!"

EVIDENCE_DIR="$SCRIPT_DIR/evidence"
STORE_FILE="$WORKDIR/data/graphus.store"
WAL_DIR="$WORKDIR/data/graphus.wal"
BASELINE="$SCRIPT_DIR/baseline.json"
PEAK_RSS_BYTES=0
SERVER_START_EPOCH=0
METRICS_BEFORE="$WORKDIR/metrics_before.prom"
METRICS_AFTER="$WORKDIR/metrics_after.prom"

SERVER_PID=""
TARGET_DB=""
cleanup() {
  # LOCAL: stop the self-booted server.
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  # EXTERNAL: drop ONLY a database the harness created. Against an operator-pinned GRAPHUS_TARGET_DB we
  # do NOT blanket-delete :Account/:Customer — that would destroy the operator's own data, and this
  # trap also fires when detect.js REFUSED to run (a non-empty operator DB), i.e. on exactly the nodes
  # we declined to touch. The operator owns that DB's lifecycle (harness contract); detect.js only ever
  # loaded into it if it was empty of our labels, so leaving it is safe and re-runs want a fresh
  # scratch DB anyway (rmp #742).
  if [ "$MODE" = external ] && [ -z "${GRAPHUS_TARGET_DB:-}" ]; then
    harness_target_drop_db >/dev/null 2>&1 || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

# server_rss_bytes <pid> — current resident set size in bytes (Linux /proc, macOS ps).
server_rss_bytes() {
  local pid="$1" bytes=0
  if [ -r "/proc/$pid/statm" ]; then
    local pages page_sz
    pages="$(awk '{print $2}' "/proc/$pid/statm" 2>/dev/null || echo 0)"
    page_sz="$(getconf PAGE_SIZE 2>/dev/null || echo 4096)"
    bytes=$(( ${pages:-0} * ${page_sz:-4096} ))
  elif command -v ps >/dev/null 2>&1; then
    local kib
    kib="$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ' || echo 0)"
    bytes=$(( ${kib:-0} * 1024 ))
  fi
  echo "${bytes:-0}"
}
sample_peak_rss() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    local rss; rss="$(server_rss_bytes "$SERVER_PID")"
    if [ "${rss:-0}" -gt "$PEAK_RSS_BYTES" ]; then PEAK_RSS_BYTES="$rss"; fi
  fi
}

# json_field <json-blob> <key> — extract a flat scalar field without a jq dependency.
json_field() {
  printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\\{0,1\\}\\([^,\"}]*\\).*/\\1/p" | head -n1
}

# local_scrape_metrics <rest_base> <user> <pass> <outfile> — LOCAL-mode /metrics scrape (the harness
# scrape helpers key off GRAPHUS_TARGET_*, which are unset in local mode). Non-fatal.
local_scrape_metrics() {
  local base="$1" user="$2" pass="$3" out="$4" token
  token="$(curl -sS -k -m 10 -X POST "$base/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$user\",\"password\":\"$pass\"}" 2>/dev/null \
    | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  [ -z "$token" ] && { info "local_scrape_metrics: no admin token from $base/auth/login"; return 1; }
  curl -sS -k -m 10 -o "$out" -H "Authorization: Bearer $token" "$base/metrics" 2>/dev/null || return 1
  [ -s "$out" ]
}

# --------------------------------------------------------------------------------------------------
# Step 1 — generate the deterministic fraud graph + ground truth
# --------------------------------------------------------------------------------------------------
section "Step 1 — generate the deterministic fraud graph ($PROFILE profile)"
mkdir -p "$DATA_DIR"
GEN_OUT="$("$GEN" --profile "$PROFILE" --out-dir "$DATA_DIR")"
info "$GEN_OUT"
GRAPH_CYPHER="$DATA_DIR/graph.cypher"
GROUND_TRUTH="$DATA_DIR/ground_truth.json"

kv() { printf '%s' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -n1; }
GEN_ACCOUNTS="$(kv "$GEN_OUT" accounts)"
GEN_CUSTOMERS="$(kv "$GEN_OUT" customers)"
GEN_TRANSFERS="$(kv "$GEN_OUT" transfers)"
NODE_COUNT=$(( ${GEN_ACCOUNTS:-0} + ${GEN_CUSTOMERS:-0} ))
REL_COUNT=$(( ${GEN_TRANSFERS:-0} + ${GEN_ACCOUNTS:-0} ))
# The logical dataset = the bytes the generator ACTUALLY emitted: the honest denominator for the
# amplification ratios (it was an invented `nodes*256 + rels*128` formula — rmp #699).
LOGICAL_GRAPH_BYTES="$(wc -c < "$GRAPH_CYPHER" | tr -d ' ')"
assert "graph.cypher generated"      "yes" "$([ -s "$GRAPH_CYPHER" ] && echo yes || echo no)"
assert "ground_truth.json generated" "yes" "$([ -s "$GROUND_TRUTH" ] && echo yes || echo no)"

GEN_OUT2_DIR="$WORKDIR/dataset2"
"$GEN" --profile "$PROFILE" --out-dir "$GEN_OUT2_DIR" > /dev/null
if diff -q "$GRAPH_CYPHER" "$GEN_OUT2_DIR/graph.cypher" > /dev/null \
   && diff -q "$GROUND_TRUTH" "$GEN_OUT2_DIR/ground_truth.json" > /dev/null; then
  assert "generator is byte-identical per seed" "yes" "yes"
else
  assert "generator is byte-identical per seed" "yes" "no"
fi

# --------------------------------------------------------------------------------------------------
# Step 2 — decide whether to run the official-driver steps
# --------------------------------------------------------------------------------------------------
RUN_DRIVER="${RUN_DRIVER:-auto}"
if [ "$RUN_DRIVER" = "auto" ]; then
  if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then RUN_DRIVER=1; else RUN_DRIVER=0; fi
fi

if [ "$RUN_DRIVER" = "1" ]; then
  # ------------------------------------------------------------------------------------------------
  # Attach or self-boot, then install the official driver once (shared Node project under WORKDIR).
  # ------------------------------------------------------------------------------------------------
  if [ "$MODE" = external ]; then
    section "Step 2 — attach to the running Graphus instance"
    BOLT_URI="${GRAPHUS_TARGET_BOLT:?external mode requires GRAPHUS_TARGET_BOLT (bolt://host:port)}"
    [ -n "${GRAPHUS_TARGET_REST:-}${GRAPHUS_TARGET_METRICS:-}" ] || {
      echo "${RED}fatal: external mode needs GRAPHUS_TARGET_REST (or _METRICS) for DB isolation + /metrics${RESET}" >&2; exit 2; }
    TARGET_DB="$(harness_target_ensure_db)" || { echo "${RED}fatal: could not resolve an isolated target database${RESET}" >&2; exit 1; }
    info "attaching to $BOLT_URI, isolated database '$TARGET_DB'"
    DRIVER_URI="$BOLT_URI"
    DRIVER_DB="$TARGET_DB"
  else
    command -v openssl >/dev/null 2>&1 || { echo "${RED}fatal: openssl required for the TLS cert${RESET}" >&2; exit 2; }
    section "Step 2 — boot graphus-server (Bolt-over-TCP + TLS + REST/metrics)"
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" \
      -days 2 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
    BOLT_PORT="$(( (RANDOM % 20000) + 40000 ))"
    REST_PORT="$(( (RANDOM % 20000) + 20000 ))"
    # NOTE (rmp #689): rest_addr is now BOUND (was ""), so /metrics is exposed and scraped into the
    # report; the admin Bearer from /auth/login satisfies the fail-closed /metrics gate.
    cat > "$CONFIG" <<EOF
# Generated by examples/fraud-oltp/run.sh — a Bolt-TCP+TLS + REST/metrics demo configuration.
store_path = "$WORKDIR/data"
buffer_pool_pages = 4096
bolt_tcp_addr = "127.0.0.1:$BOLT_PORT"
rest_addr = "127.0.0.1:$REST_PORT"
uds_path = ""
jwt_secret = "$JWT_SECRET"

[tls]
cert_path = "$CERT"
key_path = "$KEY"

[auth]
admin_user = "$ADMIN_USER"
admin_password = "$ADMIN_PW"
EOF
    "$SERVER" "$CONFIG" >>"$SERVER_LOG" 2>&1 &
    SERVER_PID=$!
    SERVER_START_EPOCH="$(date +%s)"
    ready=0
    for _ in $(seq 1 100); do
      if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "${RED}server exited during startup; last log lines:${RESET}" >&2; tail -n 20 "$SERVER_LOG" >&2; exit 1
      fi
      if (exec 3<>"/dev/tcp/127.0.0.1/$BOLT_PORT") 2>/dev/null; then
        exec 3>&- 3<&- 2>/dev/null || true; ready=1; break
      fi
      sleep 0.1
    done
    [ "$ready" = "1" ] || { echo "${RED}server did not open Bolt-TCP port $BOLT_PORT${RESET}" >&2; tail -n 20 "$SERVER_LOG" >&2; exit 1; }
    info "server pid $SERVER_PID on bolt+ssc://127.0.0.1:$BOLT_PORT + REST https://127.0.0.1:$REST_PORT"
    DRIVER_URI="bolt+ssc://127.0.0.1:$BOLT_PORT"
    DRIVER_DB=""   # the local default database
    # A network listener requires TLS (config validation), so the local REST/metrics surface is HTTPS
    # with the self-signed cert; local_scrape_metrics uses `curl -k` to trust it.
    REST_BASE="https://127.0.0.1:$REST_PORT"
  fi

  NODE_PROJ="$WORKDIR/node"
  mkdir -p "$NODE_PROJ"
  cat > "$NODE_PROJ/package.json" <<'EOF'
{
  "name": "graphus-fraud-oltp",
  "version": "1.0.0",
  "private": true,
  "description": "Drives Graphus fraud detection over Bolt+TLS with the official Neo4j driver.",
  "dependencies": { "neo4j-driver": "^6.1.0" }
}
EOF
  cp "$SCRIPT_DIR/data/detect.js" "$NODE_PROJ/detect.js"
  cp "$SCRIPT_DIR/data/concurrency.js" "$NODE_PROJ/concurrency.js"
  info "installing neo4j-driver (npm)…"
  ( cd "$NODE_PROJ" && npm install --no-audit --no-fund --loglevel=error ) >>"$SERVER_LOG" 2>&1 \
    || { echo "${RED}npm install neo4j-driver failed; see $SERVER_LOG${RESET}" >&2; exit 1; }

  # For external creds default to the target's; for local use the config's admin creds.
  if [ "$MODE" = external ]; then
    DRIVER_USER="${GRAPHUS_TARGET_USER:-graphus}"; DRIVER_PW="${GRAPHUS_TARGET_PASSWORD:-graphus-local}"
  else
    DRIVER_USER="$ADMIN_USER"; DRIVER_PW="$ADMIN_PW"
  fi

  # ---- Scrape /metrics BEFORE the workload (both modes). ------------------------------------------
  if [ "$MODE" = external ]; then
    harness_scrape_metrics "$METRICS_BEFORE" || info "metrics-before scrape failed (non-fatal)"
  else
    local_scrape_metrics "$REST_BASE" "$ADMIN_USER" "$ADMIN_PW" "$METRICS_BEFORE" || info "metrics-before scrape failed (non-fatal)"
  fi

  WORKLOAD_START_EPOCH="$(date +%s)"
  WORKLOAD_START_MS="$(_harness_now_ms)"

  # ------------------------------------------------------------------------------------------------
  # Step 3 — load + detect fraud + OLTP mix (OFFICIAL neo4j-driver)
  # ------------------------------------------------------------------------------------------------
  section "Step 3 — load + detect fraud + OLTP mix (OFFICIAL neo4j-driver)"
  DETECT_START_MS="$(_harness_now_ms)"
  # Signal DB ownership to detect.js: we OWN the DB (safe to blanket-teardown its label classes) unless
  # the operator pinned their own GRAPHUS_TARGET_DB in external mode — then detect.js refuses to touch a
  # non-empty operator DB instead of clobbering it (rmp #742).
  if [ "$MODE" = external ] && [ -n "${GRAPHUS_TARGET_DB:-}" ]; then DB_OWNED=0; else DB_OWNED=1; fi
  DETECT_OUT="$(cd "$NODE_PROJ" && GRAPHUS_DB_OWNED="$DB_OWNED" node detect.js "$DRIVER_URI" "$DRIVER_DB" "$DRIVER_USER" "$DRIVER_PW" "$GRAPH_CYPHER" "$GROUND_TRUTH" 2>&1)" || true
  DETECT_MS=$(( $(_harness_now_ms) - DETECT_START_MS ))
  printf '%s\n' "$DETECT_OUT" | sed 's/^/  /'
  assert "detection found EXACTLY the planted fraud (rings + mules + collusion)" "yes" \
    "$(grep -q 'GRAPHUS_FRAUD_OK' <<<"$DETECT_OUT" && echo yes || echo no)"
  sample_peak_rss

  DETECT_STATS="$(printf '%s' "$DETECT_OUT" | sed -n 's/^GRAPHUS_STATS //p' | head -n1)"
  DETECT_OPS="$(json_field "$DETECT_STATS" operations)"
  DETECT_SECS="$(json_field "$DETECT_STATS" workload_secs)"
  DETECT_P50="$(json_field "$DETECT_STATS" p50_ms)"
  DETECT_P99="$(json_field "$DETECT_STATS" p99_ms)"
  DETECT_P999="$(json_field "$DETECT_STATS" p999_ms)"
  DETECT_PL_P99="$(json_field "$DETECT_STATS" point_lookup_p99_ms)"
  TXCURVE="$(printf '%s' "$DETECT_OUT" | sed -n 's/^GRAPHUS_TXCURVE //p' | head -n1)"

  SCHEMA_EVIDENCE_FILE="$WORKDIR/schema.txt"
  printf '%s\n' "$DETECT_OUT" | sed -n '/GRAPHUS_SCHEMA_BEGIN/,/GRAPHUS_SCHEMA_END/p' > "$SCHEMA_EVIDENCE_FILE"
  SCHEMA_STATS="$(printf '%s' "$DETECT_OUT" | sed -n 's/^GRAPHUS_SCHEMA //p' | head -n1)"
  SCHEMA_CREATED="$(json_field "$SCHEMA_STATS" created)"
  assert "schema evidence (SHOW INDEXES/CONSTRAINTS) captured" "yes" \
    "$([ -s "$SCHEMA_EVIDENCE_FILE" ] && echo yes || echo no)"
  # At least the essential node constraints (NODE KEY + UNIQUE) must be creatable on ANY target.
  assert "target created the essential node constraints" "yes" \
    "$([ "${SCHEMA_CREATED:-0}" -ge 2 ] 2>/dev/null && echo yes || echo no)"

  # ------------------------------------------------------------------------------------------------
  # Step 4 — the PRODUCTION-SHAPED OLTP client under extreme contention on the REAL mule supernodes
  #
  # The DEFAULT (FRAUD_RETRY=1) drives every transfer as a MANAGED transaction through the official
  # driver's executeWrite(), so a serialization failure is RETRIED with bounded exponential backoff
  # until it commits — what every real Neo4j-driver application does, and the only configuration that
  # exercises the driver's retry CLASSIFIER (the path rmp #612 silently broke). FRAUD_RETRY=0 keeps the
  # pure-contention isolation (single-shot transactions, raw engine abort rate).
  # ------------------------------------------------------------------------------------------------
  RETRY_MODE="${FRAUD_RETRY:-1}"
  if [ "$RETRY_MODE" = "0" ]; then
    section "Step 4 — OLTP contention on the REAL mule supernodes (NO-RETRY isolation)"
  else
    section "Step 4 — PRODUCTION OLTP client (managed/retried txns) under extreme contention"
  fi
  CONC_START_MS="$(_harness_now_ms)"
  CONC_OUT="$(cd "$NODE_PROJ" && FRAUD_RETRY="$RETRY_MODE" node concurrency.js "$DRIVER_URI" "$DRIVER_DB" "$DRIVER_USER" "$DRIVER_PW" "$GROUND_TRUTH" 12 30 2 2>&1)" || true
  CONC_MS=$(( $(_harness_now_ms) - CONC_START_MS ))
  printf '%s\n' "$CONC_OUT" | sed 's/^/  /'
  assert "OLTP: ledger reconciles, application progressed, driver retry classified (rmp #612)" "yes" \
    "$(grep -q 'GRAPHUS_CONCURRENCY_OK' <<<"$CONC_OUT" && echo yes || echo no)"
  sample_peak_rss

  CONC_STATS="$(printf '%s' "$CONC_OUT" | sed -n 's/^GRAPHUS_STATS //p' | head -n1)"
  # ENGINE layer — the contention evidence (transaction attempts the engine actually saw).
  CONC_MODE="$(json_field "$CONC_STATS" mode)"
  CONC_ATTEMPTS="$(json_field "$CONC_STATS" engine_attempts)"
  CONC_ENGINE_ABORTS="$(json_field "$CONC_STATS" engine_aborts)"
  CONC_ABORT_RATE="$(json_field "$CONC_STATS" engine_abort_rate)"
  # APPLICATION layer — the outcome a real OLTP client sees.
  CONC_BUSINESS="$(json_field "$CONC_STATS" business_txns)"
  CONC_COMMITTED="$(json_field "$CONC_STATS" committed)"
  CONC_COMMIT_RATE="$(json_field "$CONC_STATS" commit_rate)"
  CONC_EXHAUSTED="$(json_field "$CONC_STATS" retry_budget_exhausted)"
  CONC_RETRIES_PER_COMMIT="$(json_field "$CONC_STATS" retries_per_commit)"
  CONC_MAX_RETRIES="$(json_field "$CONC_STATS" max_retries)"
  # Retry-INCLUSIVE per-business-transfer latency + the phase window they were committed in.
  CONC_P50="$(json_field "$CONC_STATS" p50_ms)"
  CONC_P99="$(json_field "$CONC_STATS" p99_ms)"
  CONC_P999="$(json_field "$CONC_STATS" p999_ms)"
  CONC_PHASE_SECS="$(json_field "$CONC_STATS" phase_secs)"

  # Millisecond resolution: total_millis must be the workload's real wall-time, not a whole-second
  # rounding of it (rmp #699).
  WORKLOAD_MS=$(( $(_harness_now_ms) - WORKLOAD_START_MS ))
  WORKLOAD_SECS=$(( $(date +%s) - WORKLOAD_START_EPOCH ))
  [ "$WORKLOAD_SECS" -lt 1 ] && WORKLOAD_SECS=1

  # ---- Scrape /metrics AFTER the workload (both modes). -------------------------------------------
  if [ "$MODE" = external ]; then
    harness_scrape_metrics "$METRICS_AFTER" || info "metrics-after scrape failed (non-fatal)"
  else
    local_scrape_metrics "$REST_BASE" "$ADMIN_USER" "$ADMIN_PW" "$METRICS_AFTER" || info "metrics-after scrape failed (non-fatal)"
  fi

  # ------------------------------------------------------------------------------------------------
  # Step 5 — collect standardized performance evidence (+ server-side /metrics deltas)
  # ------------------------------------------------------------------------------------------------
  section "Step 5 — collect performance evidence"
  rm -rf "$EVIDENCE_DIR"

  # is_num <value> — a value measure_server can parse as a number (a `null` percentile means the run
  # recorded NO sample, and per schema v3 an unmeasured metric must be ABSENT, never a 0).
  is_num() { case "${1:-}" in '' | null | NaN) return 1 ;; *) return 0 ;; esac; }

  # The RETRY-INCLUSIVE latency of a business transfer — the tail IS the story under contention.
  LATENCY_PARAMS=()
  is_num "$CONC_P50" && LATENCY_PARAMS+=(--p50-ms "$CONC_P50")
  is_num "$CONC_P99" && LATENCY_PARAMS+=(--p99-ms "$CONC_P99")
  is_num "$CONC_P999" && LATENCY_PARAMS+=(--p999-ms "$CONC_P999")

  COMMON_PARAMS=(
    --scenario "fraud-oltp"
    --description "Fraud-detection OLTP over Bolt/TLS via the official Neo4j driver: load a seeded fraud graph, detect EXACTLY the planted fraud (rings + mules + shared-device/IP collusion), run a point-lookup OLTP mix, and drive a PRODUCTION-shaped OLTP client (managed/retried double-entry ledger transfers) under extreme SSI contention on the REAL mule supernodes."
    --nodes "$NODE_COUNT" --rels "$REL_COUNT"
    --total-millis "${WORKLOAD_MS:-0}"
    # ---------------------------------------------------------------------------------------------
    # THROUGHPUT — ONE coherent workload: the OLTP contention phase (rmp #715).
    #
    # `operations` is the business work DONE (double-entry transfers COMMITTED), `ops_per_sec` is the
    # rate they committed at, p50/p99/p999 are their RETRY-INCLUSIVE latency, and `abort_rate` is the
    # ENGINE's abort rate over the VERY SAME transactions. Every field now describes one set of
    # transactions.
    #
    # It used to describe TWO disjoint sets: `operations`/`ops_per_sec`/latency came from the SERIAL
    # detect phase (914 load+detection+lookup queries, which never abort), while `abort_rate` came
    # from the 270 transactions of the CONCURRENCY phase, which appear nowhere in `operations`. A
    # reader seeing `operations: 914, abort_rate: 0.878` could only conclude "802 of my 914 operations
    # failed" — false in both directions. The detect-phase figures are kept, explicitly named, below.
    # ---------------------------------------------------------------------------------------------
    --workload-ops "${CONC_COMMITTED:-0}" --workload-secs "${CONC_PHASE_SECS:-0}"
    "${LATENCY_PARAMS[@]}"
    --abort-rate "${CONC_ABORT_RATE:-0}"
    --phase "load+detect+oltp-mix=${DETECT_MS:-0}"
    --phase "oltp-contention=${CONC_MS:-0}"
    --param "profile=$PROFILE"
    --param "connection=bolt-tcp-tls"
    --param "driver=official neo4j-driver"
    # APPLICATION layer — what a real OLTP client actually experiences.
    --param "oltp_mode=${CONC_MODE:-unknown}"
    --param "oltp_business_transfers=${CONC_BUSINESS:-0}"
    --param "oltp_committed=${CONC_COMMITTED:-0}"
    --param "oltp_commit_rate=${CONC_COMMIT_RATE:-0}"
    --param "oltp_retry_budget_exhausted=${CONC_EXHAUSTED:-0}"
    --param "oltp_retries_per_commit=${CONC_RETRIES_PER_COMMIT:-0}"
    --param "oltp_max_retries=${CONC_MAX_RETRIES:-0}"
    # ENGINE layer — the contention evidence, kept in full.
    --param "engine_txn_attempts=${CONC_ATTEMPTS:-0}"
    --param "engine_txn_aborts=${CONC_ENGINE_ABORTS:-0}"
    --param "engine_abort_rate=${CONC_ABORT_RATE:-0}"
    # The SERIAL load+detect+lookup phase — named for what it is, no longer masquerading as the headline.
    --param "detect_operations=${DETECT_OPS:-0}"
    --param "detect_p50_ms=${DETECT_P50:-0}"
    --param "detect_p99_ms=${DETECT_P99:-0}"
    --param "detect_p999_ms=${DETECT_P999:-0}"
    --param "point_lookup_p99_ms=${DETECT_PL_P99:-0}"
    --note "TWO LAYERS OF TRUTH, never conflated (rmp #715). ENGINE: ${CONC_ENGINE_ABORTS:-0} of ${CONC_ATTEMPTS:-0} transaction attempts were aborted by SSI (throughput.abort_rate = ${CONC_ABORT_RATE:-0}) — real, hard contention on the mule supernodes. APPLICATION: ${CONC_COMMITTED:-0} of ${CONC_BUSINESS:-0} business transfers COMMITTED (commit rate ${CONC_COMMIT_RATE:-0}), at ${CONC_RETRIES_PER_COMMIT:-0} retries per commit, ${CONC_EXHAUSTED:-0} exhausted their retry budget. A high engine abort rate WITH a full application commit rate is a HEALTHY system under contention: the application-visible cost of contention is LATENCY (see the retry-inclusive p99/p999), not lost work."
    --note "throughput.* describes the OLTP contention phase ONLY — one coherent set of transactions. The serial load+detect+lookup phase is reported separately as the detect_* params (it never aborts). These two used to be spliced into one section, so 'operations' and 'abort_rate' described disjoint transaction sets."
    --note "The write path is driven as a MANAGED transaction through the OFFICIAL neo4j-driver (executeWrite), so an SSI abort is classified by the driver's real retry logic and retried with bounded exponential backoff. This is the path rmp #612 broke (a '…Transaction.Terminated' poison title makes drivers treat a serialization failure as NON-retryable); the example FAILS if a serialization abort is ever classified non-retryable, so #612 cannot regress unnoticed."
    --note "storage.bytes_per_node / bytes_per_relationship are deliberately ABSENT (rmp #711): --nodes/--rels are the GENERATOR's seeded counts, while the contention phase CREATEs extra CONC- TRANSFER relationships in the same store. Dividing the measured store image by the seed counts would be real arithmetic over a graph the store no longer holds — a figure wrong in a way no reader could see. Absent is the honest state; --per-element-costs is therefore not passed."
    --note "per-TRANSFER insert latency vs cumulative edge count (rmp #683 scan-based REL KEY): $TXCURVE"
  )

  if [ "$MODE" = external ]; then
    MEASURE_BIN="$BIN_DIR/measure_target"
    harness_build "the dev-only measure_target harness binary" --release -p graphus-examples-harness --bin measure_target
    MEASURE_BIN="$BIN_DIR/measure_target"
    if [ -x "$MEASURE_BIN" ]; then
      "$MEASURE_BIN" \
        --evidence-dir "$EVIDENCE_DIR" \
        --database "$TARGET_DB" \
        --metrics-before "$METRICS_BEFORE" --metrics-after "$METRICS_AFTER" \
        "${COMMON_PARAMS[@]}" \
        --param "target=$BOLT_URI" \
        --assert \
        && info "external evidence written to $EVIDENCE_DIR" \
        || { info "measure_target reported an invariant violation or error"; FAILURES=$((FAILURES + 1)); }
      assert "external report.json produced (measurement_mode=external)" "yes" \
        "$([ -f "$EVIDENCE_DIR/report.json" ] && grep -q '"measurement_mode": *"external"' "$EVIDENCE_DIR/report.json" && echo yes || echo no)"
      assert "report.json carries server_metrics deltas" "yes" \
        "$([ -f "$EVIDENCE_DIR/report.json" ] && grep -q '"server_metrics"' "$EVIDENCE_DIR/report.json" && echo yes || echo no)"
    else
      info "measure_target unavailable; skipping evidence collection (non-fatal)"
    fi
  else
    sample_peak_rss
    SERVER_UPTIME_SECS=$(( $(date +%s) - SERVER_START_EPOCH ))
    [ "$SERVER_UPTIME_SECS" -lt 1 ] && SERVER_UPTIME_SECS=1
    MEASURE_BIN="$BIN_DIR/measure_server"
    harness_build "the dev-only measure_server harness binary (debug)" --release -p graphus-examples-harness --bin measure_server
    MEASURE_BIN="$BIN_DIR/measure_server"
    if [ -x "$MEASURE_BIN" ] && [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
      "$MEASURE_BIN" \
        --evidence-dir "$EVIDENCE_DIR" \
        --pid "$SERVER_PID" --uptime-secs "$SERVER_UPTIME_SECS" \
        --store "$STORE_FILE" --wal "$WAL_DIR" \
        --peak-rss-bytes "$PEAK_RSS_BYTES" \
        --logical-bytes-written "$LOGICAL_GRAPH_BYTES" \
        --logical-graph-bytes "$LOGICAL_GRAPH_BYTES" \
        "${COMMON_PARAMS[@]}" \
        && info "evidence written to $EVIDENCE_DIR" \
        || info "evidence collection failed (non-fatal); see output above"
      # Fold in the server-side /metrics before/after delta (rmp #689) so the LOCAL report carries the
      # same server_metrics section external mode gets from measure_target.
      INJECT_BIN="$BIN_DIR/inject_server_metrics"
      harness_build "the inject_server_metrics helper (debug)" --release -p graphus-fraud-gen --bin inject_server_metrics
      INJECT_BIN="$BIN_DIR/inject_server_metrics"
      if [ -x "$INJECT_BIN" ] && [ -s "$METRICS_BEFORE" ] && [ -s "$METRICS_AFTER" ] && [ -f "$EVIDENCE_DIR/report.json" ]; then
        "$INJECT_BIN" "$EVIDENCE_DIR" "$METRICS_BEFORE" "$METRICS_AFTER" "graphus" \
          && info "server_metrics folded into $EVIDENCE_DIR/report.json" \
          || info "inject_server_metrics failed (non-fatal)"
      fi
      assert "evidence report.json was produced" "yes" \
        "$([ -f "$EVIDENCE_DIR/report.json" ] && echo yes || echo no)"
      assert "report.json carries server_metrics deltas" "yes" \
        "$([ -f "$EVIDENCE_DIR/report.json" ] && grep -q '"server_metrics"' "$EVIDENCE_DIR/report.json" && echo yes || echo no)"
      # Evidence honesty (rmp #699): total_millis is the workload's wall-time, ops/sec is the detection
      # ops over the window they were ISSUED in (not the whole load+detect+concurrency window), and
      # both amplification ratios are real (write_amplification was a 0.0 placeholder).
      assert "report evidence is honest (real total_millis, ops/sec, amplification)" "yes" \
        "$(python3 -c "
import json,sys
try: d = json.load(open('$EVIDENCE_DIR/report.json'))
except Exception: print('no'); sys.exit()
t, tp, st = d['total_millis'], d['throughput'], d['storage']
ok = (t >= 1.0
      and tp['ops_per_sec'] > 0.0
      and tp['p50_latency_ms'] > 0.0 and tp['p99_latency_ms'] > 0.0 and tp['p999_latency_ms'] > 0.0
      and st['store_bytes'] > 0 and (st.get('wal_bytes',0) > 0 or st.get('wal_retained_bytes',0) > 0)
      and st['write_amplification'] > 0.0 and st['space_amplification'] > 0.0)
print('yes' if ok else 'no')" 2>/dev/null || echo no)"

      # Baseline regression gate (LOCAL, fast profile, DEFAULT retry mode only).
      #
      # The committed baseline is a `fast`-profile run of the DEFAULT (retrying) client, so it can only
      # be compared against another one. The FRAUD_RETRY=0 isolation is a genuinely DIFFERENT workload —
      # it commits ~26 of 270 transfers instead of all 270 (so it writes a fraction of the durable
      # bytes) and its engine abort rate is ~0.90 instead of ~0.05. Diffing those two against each other
      # would be real arithmetic over mismatched inputs: a red gate that means nothing, which is the
      # same family of lie as a green gate that cannot fire. So it is SKIPPED, and says so.
      if [ "$PROFILE" = "fast" ] && [ "$RETRY_MODE" != "0" ] \
         && [ -f "$BASELINE" ] && [ -f "$EVIDENCE_DIR/report.json" ]; then
        section "Step 5b — regression gate vs committed baseline"
        CMP_BIN="$BIN_DIR/baseline_cmp"
        harness_build "the baseline_cmp gate (debug)" --release -p graphus-fraud-gen --bin baseline_cmp
        CMP_BIN="$BIN_DIR/baseline_cmp"
        CMP_OUT="$("$CMP_BIN" "$BASELINE" "$EVIDENCE_DIR/report.json" 2>&1)" || true
        printf '%s\n' "$CMP_OUT" | sed 's/^/  /'
        assert "fresh run is within baseline thresholds (structural metrics)" "yes" \
          "$(grep -q 'GRAPHUS_BASELINE_OK' <<<"$CMP_OUT" && echo yes || echo no)"
      elif [ "$PROFILE" = "fast" ] && [ "$RETRY_MODE" = "0" ]; then
        section "Step 5b — regression gate vs committed baseline: SKIPPED"
        info "FRAUD_RETRY=0 is the pure-contention ISOLATION, a different workload from the committed"
        info "baseline (which is a run of the DEFAULT retrying client): it commits a fraction of the"
        info "transfers, so it writes a fraction of the durable bytes and aborts ~18x more per attempt."
        info "Gating it against that baseline would compare two different things. Re-run without"
        info "FRAUD_RETRY=0 for the baseline-gated run."
      fi
    else
      info "measure_server unavailable or server not alive; skipping evidence collection (non-fatal)"
    fi
  fi

  # Persist the schema evidence listing into the evidence dir (both modes).
  if [ -s "$SCHEMA_EVIDENCE_FILE" ]; then
    mkdir -p "$EVIDENCE_DIR"
    cp "$SCHEMA_EVIDENCE_FILE" "$EVIDENCE_DIR/schema.txt"
    info "schema evidence written to $EVIDENCE_DIR/schema.txt"
  fi

  # LOCAL: stop the server before the hermetic DST step. EXTERNAL: the cleanup trap drops the DB.
  if [ "$MODE" = local ] && [ -n "$SERVER_PID" ]; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
  fi
else
  section "Steps 2-5 — official-driver path SKIPPED (RUN_DRIVER=0 or node/npm absent)"
  info "the hermetic generator + DST repro below still run and assert the same fraud structures"
fi

# --------------------------------------------------------------------------------------------------
# Step 6 — deterministic in-process SSI-contention repro (hermetic; always runs)
# --------------------------------------------------------------------------------------------------
section "Step 6 — deterministic SSI-contention repro (seed=$DST_SEED)"
DST_OUT1="$("$DST" --seed "$DST_SEED" --rounds 40 --clients 4 --hot 3 2>&1)" || true
printf '%s\n' "$DST_OUT1" | sed 's/^/  /'
assert "DST contention repro passed its SSI invariants" "yes" \
  "$(grep -q 'GRAPHUS_DST_CONTENTION_OK' <<<"$DST_OUT1" && echo yes || echo no)"

DST_OUT2="$("$DST" --seed "$DST_SEED" --rounds 40 --clients 4 --hot 3 2>&1)" || true
assert "DST repro is byte-identical for a fixed seed" "yes" \
  "$([ "$DST_OUT1" = "$DST_OUT2" ] && echo yes || echo no)"

# --------------------------------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------------------------------
section "Result"
printf '%s checks run, %s failures.  (mode: %s)\n' "$CHECKS" "$FAILURES" "$MODE"
if [ "$RUN_DRIVER" = "1" ] && [ -f "$EVIDENCE_DIR/report.json" ]; then
  printf 'evidence: %s {report.json, report.md, schema.txt}\n' "$EVIDENCE_DIR"
fi
if [ "$FAILURES" -eq 0 ]; then
  if [ "$RUN_DRIVER" = "1" ]; then
    printf '%s%sFRAUD-OLTP DEMONSTRATION PASSED%s (%s mode) — Graphus loaded a seeded fraud graph over\n' "$BOLD" "$GREEN" "$RESET" "$MODE"
    printf 'Bolt/TLS via the official Neo4j driver, detected EXACTLY the planted fraud (rings + mules +\n'
    printf 'shared-device/IP collusion), ran a point-lookup OLTP mix, and sustained a PRODUCTION-shaped\n'
    printf 'OLTP client under extreme SSI contention on the REAL mule supernodes: the engine aborted\n'
    printf '%s of %s transaction attempts, yet %s of %s business transfers COMMITTED (%s retries per\n' \
      "${CONC_ENGINE_ABORTS:-?}" "${CONC_ATTEMPTS:-?}" "${CONC_COMMITTED:-?}" "${CONC_BUSINESS:-?}" "${CONC_RETRIES_PER_COMMIT:-?}"
    printf 'commit) — the ledger RECONCILES, the driver CLASSIFIED every SSI abort as retryable\n'
    printf '(rmp #612 cannot regress unnoticed), the SSI contention reproduced deterministically, and\n'
    printf 'standardized performance + server-side /metrics evidence was emitted.\n'
  else
    printf '%s%sFRAUD-OLTP DEMONSTRATION PASSED%s — the hermetic generator produced a byte-identical\n' "$BOLD" "$GREEN" "$RESET"
    printf 'seeded fraud graph + ground truth and the deterministic SSI-contention repro held its\n'
    printf 'invariants. (Official-driver load/detect/concurrency + evidence were skipped: RUN_DRIVER=0\n'
    printf 'or node/npm absent. Run with node/npm present for the full Bolt/TLS demonstration.)\n'
  fi
  exit 0
else
  printf '%s%sFRAUD-OLTP DEMONSTRATION FAILED%s — %s assertion(s) did not hold.\n' "$BOLD" "$RED" "$RESET" "$FAILURES"
  exit 1
fi
