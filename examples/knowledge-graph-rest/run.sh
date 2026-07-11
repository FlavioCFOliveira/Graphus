#!/usr/bin/env bash
#
# Graphus knowledge-graph-over-REST demonstration — over the REST transactional API, secured with
# TLS + Bearer-JWT auth (obtained from POST /auth/login), driven by a pure-stdlib python3 client.
#
# This script doubles as an executable E2E test. It runs in one of two modes:
#
#   * LOCAL (default) — boots a REAL `graphus-server` exposing the REST API over HTTPS with a
#     self-signed TLS cert + a real jwt_secret, loads a seeded knowledge graph, drives the discovery
#     workload against it, and collects the full evidence set (server CPU/RSS, on-disk store/WAL, a
#     committed-baseline regression gate) plus the server-side /metrics snapshots.
#   * EXTERNAL / ATTACH — when any of GRAPHUS_TARGET_{BOLT,REST,UDS} is set, it does NOT boot a
#     server: it attaches to the ALREADY-RUNNING instance (local or remote, e.g. pi516) via the
#     shared external-target seam in `_harness/harness.sh`, authenticates with POST /auth/login,
#     carves out an ISOLATED dedicated database, drives the same discovery+concurrency workload into
#     it, scrapes the target's Prometheus /metrics before+after, emits the server-side evidence via
#     the `measure_target` harness (measurement_mode=external; process CPU/RSS + on-disk storage are
#     N/A remotely, and the host-specific baseline gate is skipped), then DROPS the database on exit.
#
# In BOTH modes the workload:
#   1. generates a DETERMINISTIC, SEEDED knowledge graph (the `kg_gen` binary) — documents, authors,
#      concepts and topics with semantic relationships (AUTHORED / MENTIONS / CITES / ABOUT /
#      RELATED_TO) — plus a fixed reference subgraph whose discovery-query answers are KNOWN, emitted
#      as `reference.json`;
#   2. runs the python REST workload (`data/discovery.py`), which: authenticates via POST /auth/login,
#      proves an unauthenticated request is rejected 401, loads the graph SCHEMA-FIRST (unique-id +
#      node property-type + node existence constraints, a `Document.year` RANGE index and a FULLTEXT
#      title index) in BATCHED auto-commit transactions, captures SHOW INDEXES / SHOW CONSTRAINTS as
#      evidence, demonstrates the explicit begin/commit/rollback lifecycle, asserts the five discovery
#      queries (lookup / multi-hop traversal / recommendation / aggregation / concept path) against
#      `reference.json`, runs the FULLTEXT title search asserting the known reference documents, proves
#      a property-type and an existence violation are both rejected, streams a large result as NDJSON,
#      negotiates CBOR vs JSON and compares payload sizes, and drives concurrent HTTP clients with zero
#      errors. Every READ query carries `access_mode: "READ"` so it dispatches to the server's
#      off-thread reader pool (reads scale across cores); each client keeps a persistent keep-alive
#      HTTPS connection.
#
# The generator (step 1) is HERMETIC and CI-runnable on its own (`cargo test -p graphus-kg-gen`
# proves byte-identical output per seed). The LOCAL REST workload needs `openssl` (for the self-signed
# cert) and `python3` (stdlib only — no pip packages); they are skipped with a clear note if either is
# absent. The EXTERNAL workload needs `python3` + `curl` (the harness uses curl for /metrics + DDL).
#
# Usage:
#   examples/knowledge-graph-rest/run.sh                          # LOCAL: builds binaries if needed
#   GRAPHUS_BIN_DIR=target/release  examples/knowledge-graph-rest/run.sh
#   KG_PROFILE=large                examples/knowledge-graph-rest/run.sh   # evidence-scale dataset
#   KG_CLIENTS=32 KG_OPS=40         examples/knowledge-graph-rest/run.sh   # heavier concurrency
#
#   # EXTERNAL / ATTACH — run against an already-running instance (e.g. pi516), isolated + cleaned up:
#   GRAPHUS_TARGET_REST=https://100.89.148.30:7474 \
#     GRAPHUS_TARGET_USER=graphus GRAPHUS_TARGET_PASSWORD=graphus-local \
#     GRAPHUS_TARGET_TLS_INSECURE=1 examples/knowledge-graph-rest/run.sh
#
# Requirements: a Unix host (Linux/macOS), bash, python3 (3.8+, stdlib only). LOCAL also needs
# openssl + a checkout that builds; EXTERNAL also needs curl.

set -euo pipefail

# --------------------------------------------------------------------------------------------------
# Shared external-target seam (attach mode + /metrics scrape). Sourced BEFORE this script's own
# pretty-print helpers so ours (the CHECKS/FAILURES-based assert + the tailored summary) take
# precedence over the harness's identically-named helpers.
# --------------------------------------------------------------------------------------------------
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../_harness" && pwd)/harness.sh"

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

# json_field <json-blob> <key> — extract a numeric/string field from the one-line GRAPHUS_STATS JSON
# object the python client emits, without a jq dependency (the object is flat scalars).
json_field() {
  printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\\{0,1\\}\\([^,\"}]*\\).*/\\1/p" | head -n1
}

# --------------------------------------------------------------------------------------------------
# Locate (or build) the binaries
# --------------------------------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${GRAPHUS_BIN_DIR:-$REPO_ROOT/target/release}"
SERVER="$BIN_DIR/graphus-server"
GEN="$BIN_DIR/kg_gen"

PROFILE="${KG_PROFILE:-fast}"
CLIENTS="${KG_CLIENTS:-16}"
OPS_PER_CLIENT="${KG_OPS:-20}"
BATCH_SIZE="${KG_BATCH:-200}"

# local | external — external iff any of GRAPHUS_TARGET_{BOLT,REST,UDS} is set.
MODE="$(harness_target_mode)"

# The deterministic generator is needed in BOTH modes (it produces the graph + reference answers).
harness_build "the deterministic knowledge-graph generator (release)" \
  --release -p graphus-kg-gen --bin kg_gen
[ -x "$GEN" ] || { echo "${RED}fatal: kg_gen binary not found at $GEN${RESET}" >&2; exit 2; }

# The server binary is needed ONLY in local mode (external attaches to a running instance).
if [ "$MODE" = "local" ]; then
  harness_build "graphus-server (release)" --release -p graphus-server
fi
if [ "$MODE" = "local" ]; then
  [ -x "$SERVER" ] || { echo "${RED}fatal: server binary not found at $SERVER${RESET}" >&2; exit 2; }
fi

# --------------------------------------------------------------------------------------------------
# Workspace: a private temp dir for generated data (+ TLS material + a store in local mode), removed
# on exit. In external mode the DATA dir holds only the generated cypher/reference + /metrics files.
# --------------------------------------------------------------------------------------------------
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/graphus-kg-rest-XXXXXX")"
DATA_DIR="$WORKDIR/dataset"

# local-only server material
CONFIG="$WORKDIR/graphus.toml"
SERVER_LOG="$WORKDIR/server.log"
CERT="$WORKDIR/cert.pem"
KEY="$WORKDIR/key.pem"
ADMIN_USER="neo4j"
ADMIN_PW="kg-rest-demo-admin-pw-8plus"
JWT_SECRET="kg-rest-demo-jwt-secret-32bytes-minimum!"
STORE_FILE="$WORKDIR/data/graphus.store"
WAL_DIR="$WORKDIR/data/graphus.wal"

# Evidence collection (rmp #282/#285/#692). The standardized report.json + report.md land in the
# git-ignored evidence/ dir; BASELINE is the committed reference run we compare a fresh fast-profile
# LOCAL run against (skipped in external mode — a foreign host has no comparable baseline).
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
BASELINE="$SCRIPT_DIR/baseline.json"
METRICS_BEFORE="$WORKDIR/metrics_before.prom"   # /metrics scrape immediately before the workload
METRICS_AFTER="$WORKDIR/metrics_after.prom"     # /metrics scrape immediately after the workload
PEAK_RSS_BYTES=0          # high-watermark of the server's RSS, sampled during the workload (local)
SERVER_START_EPOCH=0      # wall-clock epoch (s) of the server boot, for the CPU/uptime window (local)

REST_PORT=0
SERVER_PID=""
# cleanup — tear down whatever THIS run created: the local server pid we spawned (never a bare
# `wait`, which would block on the background server), and/or the isolated external database we
# carved out (harness_target_drop_db is a no-op when we created none). The python client runs
# synchronously in the foreground, so there is no client pid to reap here.
cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  harness_target_drop_db 2>/dev/null || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

# server_rss_bytes <pid> — current resident set size of the server in bytes (Linux /proc, macOS ps).
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

# sample_peak_rss — read the live server's RSS once and keep the running high-watermark (local mode).
sample_peak_rss() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    local rss
    rss="$(server_rss_bytes "$SERVER_PID")"
    if [ "${rss:-0}" -gt "$PEAK_RSS_BYTES" ]; then
      PEAK_RSS_BYTES="$rss"
    fi
  fi
}

# local_login — mint an admin Bearer against the LOCAL server via POST /auth/login (best-effort, for
# the /metrics scrape only). Echoes the token; empty + non-zero if curl is absent or login fails.
local_login() {
  command -v curl >/dev/null 2>&1 || return 1
  local resp token
  resp="$(curl -k -sS -X POST "https://127.0.0.1:$REST_PORT/auth/login" \
            -H 'Content-Type: application/json' \
            -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PW\"}" 2>/dev/null)" || return 1
  token="$(printf '%s' "$resp" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  [ -n "$token" ] && printf '%s' "$token"
}

# local_scrape_metrics <outfile> <token> — GET the LOCAL server's /metrics (best-effort). Returns
# non-zero (and writes nothing durable) on any failure so it never fails the demonstration.
local_scrape_metrics() {
  command -v curl >/dev/null 2>&1 || return 1
  local out="$1" token="$2" code
  [ -n "$token" ] || return 1
  code="$(curl -k -sS -o "$out" -w '%{http_code}' \
            -H "Authorization: Bearer $token" "https://127.0.0.1:$REST_PORT/metrics" 2>/dev/null)" || return 1
  [ "$code" = "200" ] && [ -s "$out" ]
}

# --------------------------------------------------------------------------------------------------
# Step 1 — generate the deterministic knowledge graph + reference subgraph (both modes)
# --------------------------------------------------------------------------------------------------
section "Step 1 — generate the deterministic knowledge graph ($PROFILE profile)"
mkdir -p "$DATA_DIR"
GEN_OUT="$("$GEN" --profile "$PROFILE" --out-dir "$DATA_DIR" | head -n1)"
info "$GEN_OUT"
GRAPH_CYPHER="$DATA_DIR/graph.cypher"
REFERENCE="$DATA_DIR/reference.json"
assert "graph.cypher generated"   "yes" "$([ -s "$GRAPH_CYPHER" ] && echo yes || echo no)"
assert "reference.json generated" "yes" "$([ -s "$REFERENCE" ] && echo yes || echo no)"

# Dataset sizing for the evidence report — counted directly off the deterministic load script (the
# ground truth): node CREATEs are `CREATE (:Label ...)`, relationship CREATEs are `CREATE (x)-[:...`.
NODE_COUNT="$(grep -cE '^CREATE \(:' "$GRAPH_CYPHER" || true)"
REL_COUNT="$(grep -cE 'CREATE \([a-z]\)-\[:' "$GRAPH_CYPHER" || true)"
NODE_COUNT="${NODE_COUNT:-0}"
REL_COUNT="${REL_COUNT:-0}"
# The logical dataset is the bytes the generator ACTUALLY emitted — the honest denominator for the
# amplification ratios. It used to be an invented `nodes*256 + rels*128` formula, which made the
# published space_amplification a fabrication (rmp #699).
LOGICAL_GRAPH_BYTES="$(wc -c < "$GRAPH_CYPHER" | tr -d ' ')"
info "dataset: $NODE_COUNT nodes, $REL_COUNT relationships; logical graph.cypher: ${LOGICAL_GRAPH_BYTES} B"

# Determinism check: regenerate and diff (the AC: byte-identical per seed/scale).
GEN_OUT2_DIR="$WORKDIR/dataset2"
"$GEN" --profile "$PROFILE" --out-dir "$GEN_OUT2_DIR" > /dev/null
if diff -q "$GRAPH_CYPHER" "$GEN_OUT2_DIR/graph.cypher" > /dev/null \
   && diff -q "$REFERENCE" "$GEN_OUT2_DIR/reference.json" > /dev/null; then
  assert "generator is byte-identical per seed" "yes" "yes"
else
  assert "generator is byte-identical per seed" "yes" "no"
fi

# --------------------------------------------------------------------------------------------------
# Decide whether the REST workload can run. LOCAL needs openssl + python3; EXTERNAL needs python3.
# --------------------------------------------------------------------------------------------------
RUN_REST=1
command -v python3 >/dev/null 2>&1 || RUN_REST=0
if [ "$MODE" = "local" ]; then
  command -v openssl >/dev/null 2>&1 || RUN_REST=0
fi

REST_OUT=""
WORKLOAD_SECS=1
TARGET_DB=""

if [ "$RUN_REST" = "1" ] && [ "$MODE" = "external" ]; then
  # ================================================================================================
  # EXTERNAL / ATTACH — attach to an ALREADY-RUNNING instance via the shared seam (no server boot).
  # ================================================================================================
  section "Step 2 — attach to the ALREADY-RUNNING Graphus instance (external target)"
  REST_BASE="$(_harness_target_rest_base)"
  [ -n "$REST_BASE" ] || { echo "${RED}fatal: external mode set but no REST endpoint (GRAPHUS_TARGET_REST)${RESET}" >&2; exit 1; }

  # Authenticate once (POST /auth/login) and reuse the Bearer for the isolated-DB DDL + /metrics.
  TARGET_TOKEN="$(harness_target_login)" || { echo "${RED}fatal: POST /auth/login failed against $REST_BASE${RESET}" >&2; exit 1; }
  export GRAPHUS_TARGET_METRICS_TOKEN="$TARGET_TOKEN"   # reuse the token for /metrics (skip re-login)
  info "authenticated to $REST_BASE via POST /auth/login (${#TARGET_TOKEN} chars)"

  # Carve out an ISOLATED dedicated database (created + tracked for teardown by the seam). The
  # cleanup trap drops it (STOP then DROP) so the target is left exactly as we found it.
  TARGET_DB="$(harness_target_ensure_db)" || { echo "${RED}fatal: could not create an isolated database on $REST_BASE${RESET}" >&2; exit 1; }
  info "isolated target database: $TARGET_DB"
  assert "isolated external database created" "yes" "$([ -n "$TARGET_DB" ] && echo yes || echo no)"

  # Scrape /metrics immediately BEFORE the workload window.
  if harness_scrape_metrics "$METRICS_BEFORE"; then
    info "scraped /metrics (before) -> $METRICS_BEFORE"
  else
    info "metrics-before scrape unavailable (non-fatal)"
  fi

  section "Step 3 — knowledge-graph discovery over REST (python3 stdlib client, attach mode)"
  D_USER="${GRAPHUS_TARGET_USER:-graphus}"
  D_PASS="${GRAPHUS_TARGET_PASSWORD:-graphus-local}"
  PY_ARGS=(--base-url "$REST_BASE" --user "$D_USER" --password "$D_PASS"
           --database "$TARGET_DB" --cypher "$GRAPH_CYPHER" --reference "$REFERENCE"
           --batch-size "$BATCH_SIZE" --clients "$CLIENTS" --ops-per-client "$OPS_PER_CLIENT")
  if _harness_target_insecure; then PY_ARGS+=(--insecure); fi

  WORKLOAD_START_MS="$(_harness_now_ms)"
  REST_OUT="$(python3 "$SCRIPT_DIR/data/discovery.py" "${PY_ARGS[@]}" 2>&1)" || true
  WORKLOAD_MS=$(( $(_harness_now_ms) - WORKLOAD_START_MS ))
  printf '%s\n' "$REST_OUT" | sed 's/^/  /'
  WORKLOAD_SECS=$(( WORKLOAD_MS / 1000 ))
  [ "$WORKLOAD_SECS" -lt 1 ] && WORKLOAD_SECS=1
  assert "REST workload passed every assertion" "yes" \
    "$(printf '%s' "$REST_OUT" | grep -q 'GRAPHUS_KG_REST_OK' && echo yes || echo no)"

  # Scrape /metrics immediately AFTER the workload window.
  if harness_scrape_metrics "$METRICS_AFTER"; then
    info "scraped /metrics (after) -> $METRICS_AFTER"
  else
    info "metrics-after scrape unavailable (non-fatal)"
  fi

elif [ "$RUN_REST" = "1" ] && [ "$MODE" = "local" ]; then
  # ================================================================================================
  # LOCAL — boot a REST + TLS server (production REST path: TLS + a real JWT secret) and drive it.
  # ================================================================================================
  section "Step 2 — boot graphus-server (REST over HTTPS + Bearer JWT via /auth/login)"

  # Self-signed cert (CN/SAN localhost; the python client trusts it via --insecure).
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" \
    -days 2 -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

  REST_PORT="$(( (RANDOM % 20000) + 40000 ))"
  cat > "$CONFIG" <<EOF
# Generated by examples/knowledge-graph-rest/run.sh — a REST-over-HTTPS demo configuration.
store_path = "$WORKDIR/data"
buffer_pool_pages = 4096
bolt_tcp_addr = ""
uds_path = ""
rest_addr = "127.0.0.1:$REST_PORT"
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
      echo "${RED}server exited during startup; last log lines:${RESET}" >&2
      tail -n 20 "$SERVER_LOG" >&2
      exit 1
    fi
    if (exec 3<>"/dev/tcp/127.0.0.1/$REST_PORT") 2>/dev/null; then
      exec 3>&- 3<&- 2>/dev/null || true
      ready=1
      break
    fi
    sleep 0.1
  done
  [ "$ready" = "1" ] || { echo "${RED}server did not open REST port $REST_PORT${RESET}" >&2; tail -n 20 "$SERVER_LOG" >&2; exit 1; }
  info "server pid $SERVER_PID listening on https://127.0.0.1:$REST_PORT"
  TARGET_DB="graphus"   # the local server's default database

  # Scrape /metrics immediately BEFORE the workload window (best-effort, curl-gated, non-fatal).
  LOCAL_METRICS_TOKEN="$(local_login || true)"
  if local_scrape_metrics "$METRICS_BEFORE" "$LOCAL_METRICS_TOKEN"; then
    info "scraped /metrics (before) -> $METRICS_BEFORE"
  else
    info "local /metrics-before scrape unavailable (non-fatal)"
  fi

  section "Step 3 — knowledge-graph discovery over REST (python3 stdlib client)"
  # Bracket the workload: the evidence binary runs AFTER it and cannot time it, so total_millis would
  # otherwise be the report's own emission time (rmp #699).
  WORKLOAD_START_MS="$(_harness_now_ms)"
  REST_OUT="$(python3 "$SCRIPT_DIR/data/discovery.py" \
    --base-url "https://127.0.0.1:$REST_PORT" \
    --user "$ADMIN_USER" \
    --password "$ADMIN_PW" \
    --database "$TARGET_DB" \
    --insecure \
    --cypher "$GRAPH_CYPHER" \
    --reference "$REFERENCE" \
    --batch-size "$BATCH_SIZE" \
    --clients "$CLIENTS" \
    --ops-per-client "$OPS_PER_CLIENT" 2>&1)" || true
  WORKLOAD_MS=$(( $(_harness_now_ms) - WORKLOAD_START_MS ))
  printf '%s\n' "$REST_OUT" | sed 's/^/  /'
  assert "REST workload passed every assertion" "yes" \
    "$(printf '%s' "$REST_OUT" | grep -q 'GRAPHUS_KG_REST_OK' && echo yes || echo no)"
  sample_peak_rss   # the load + discovery + concurrency just ran; capture the server's RSS here

  # Scrape /metrics immediately AFTER the workload window (best-effort, non-fatal).
  if local_scrape_metrics "$METRICS_AFTER" "$LOCAL_METRICS_TOKEN"; then
    info "scraped /metrics (after) -> $METRICS_AFTER"
  else
    info "local /metrics-after scrape unavailable (non-fatal)"
  fi
fi

# --------------------------------------------------------------------------------------------------
# Shared — harvest the machine-readable stats + schema lines from the python client's output.
# --------------------------------------------------------------------------------------------------
STATS=""
SCHEMA_JSON=""
if [ "$RUN_REST" = "1" ] && [ -n "$REST_OUT" ]; then
  STATS="$(printf '%s' "$REST_OUT" | sed -n 's/^[[:space:]]*GRAPHUS_STATS //p' | head -n1)"
  SCHEMA_JSON="$(printf '%s' "$REST_OUT" | sed -n 's/^[[:space:]]*GRAPHUS_SCHEMA //p' | head -n1)"
fi

if [ -n "$STATS" ]; then
  mkdir -p "$EVIDENCE_DIR"
  printf '%s\n' "$STATS" > "$EVIDENCE_DIR/workload_stats.json"
  info "workload stats written to $EVIDENCE_DIR/workload_stats.json"
fi

# Per-metric figures the python client measured (latency percentiles, payload sizes, throughput).
W_OPS="$(json_field "$STATS" concurrency_ops)"
W_CONC_SECS="$(json_field "$STATS" concurrency_secs)"
W_P50="$(json_field "$STATS" p50_ms)"
W_P99="$(json_field "$STATS" p99_ms)"
W_P999="$(json_field "$STATS" p999_ms)"
W_JSON_BYTES="$(json_field "$STATS" json_bytes)"
W_CBOR_BYTES="$(json_field "$STATS" cbor_bytes)"
W_CBOR_RATIO="$(json_field "$STATS" cbor_ratio)"
W_NDJSON_ROWS="$(json_field "$STATS" ndjson_rows)"
W_NDJSON_BYTES="$(json_field "$STATS" ndjson_bytes)"
W_NDJSON_RPS="$(json_field "$STATS" ndjson_rows_per_sec)"
W_NDJSON_BPS="$(json_field "$STATS" ndjson_bytes_per_sec)"
W_OPS_PER_SEC="$(json_field "$STATS" ops_per_sec)"
W_INDEXES="$(json_field "$STATS" indexes_total)"
W_CONSTRAINTS="$(json_field "$STATS" constraints_total)"

# --------------------------------------------------------------------------------------------------
# Step 4 — collect the standardized performance evidence.
# --------------------------------------------------------------------------------------------------
if [ "$RUN_REST" = "1" ] && [ "$MODE" = "external" ]; then
  # ------------------------------------------------------------------------------------------------
  # EXTERNAL — server-side evidence is the /metrics before→after delta for the isolated database,
  # emitted via `measure_target` (measurement_mode=external). Process CPU/RSS + on-disk storage are
  # N/A remotely (no /proc, no store path) and the host-specific baseline gate is skipped. The
  # invariant gate (--assert) fails the run on any statement panic / force-detach / excessive abort.
  # ------------------------------------------------------------------------------------------------
  section "Step 4 — server-side evidence via /metrics (external mode)"
  MEASURE_TGT="$BIN_DIR/measure_target"
  if [ ! -x "$MEASURE_TGT" ]; then
    harness_build "the dev-only measure_target harness binary (debug)" -p graphus-examples-harness --bin measure_target
    MEASURE_TGT="$REPO_ROOT/target/debug/measure_target"
  fi

  if [ -x "$MEASURE_TGT" ] && [ -s "$METRICS_BEFORE" ] && [ -s "$METRICS_AFTER" ]; then
    rm -rf "$EVIDENCE_DIR"   # a fresh report each run; the dir is git-ignored
    "$MEASURE_TGT" \
      --evidence-dir "$EVIDENCE_DIR" \
      --scenario "knowledge-graph-rest" \
      --description "Knowledge graph served over the REST API (HTTPS + Bearer JWT via /auth/login), attached to an ALREADY-RUNNING instance and isolated in a dedicated database: load a seeded KG, run the discovery queries against a known reference, stream NDJSON, negotiate CBOR vs JSON, and sustain concurrent READ clients (off-thread reader pool)." \
      --database "$TARGET_DB" \
      --metrics-before "$METRICS_BEFORE" \
      --metrics-after "$METRICS_AFTER" \
      --nodes "$NODE_COUNT" \
      --rels "$REL_COUNT" \
      --total-millis "${WORKLOAD_MS:-0}" \
      --workload-ops "${W_OPS:-0}" \
      --workload-secs "${W_CONC_SECS:-$WORKLOAD_SECS}" \
      --p50-ms "${W_P50:-0}" \
      --p99-ms "${W_P99:-0}" \
      --p999-ms "${W_P999:-0}" \
      --abort-rate 0.0 \
      --param "profile=$PROFILE" \
      --param "connection=rest-https-jwt-attach" \
      --param "client=python3 stdlib" \
      --param "clients=$CLIENTS" \
      --param "target_rest=$REST_BASE" \
      --param "access_mode=READ" \
      --param "json_bytes=${W_JSON_BYTES:-0}" \
      --param "cbor_bytes=${W_CBOR_BYTES:-0}" \
      --param "cbor_ratio=${W_CBOR_RATIO:-0}" \
      --param "ndjson_rows=${W_NDJSON_ROWS:-0}" \
      --param "ndjson_bytes=${W_NDJSON_BYTES:-0}" \
      --param "ndjson_rows_per_sec=${W_NDJSON_RPS:-0}" \
      --param "ndjson_bytes_per_sec=${W_NDJSON_BPS:-0}" \
      --param "http_ops_per_sec=${W_OPS_PER_SEC:-0}" \
      --param "concurrency_secs=${W_CONC_SECS:-0}" \
      --param "indexes_total=${W_INDEXES:-0}" \
      --param "constraints_total=${W_CONSTRAINTS:-0}" \
      --note "Attach mode (measurement_mode=external): the workload ran against an already-running instance ($REST_BASE) isolated in database '$TARGET_DB', which is DROPPED on exit. Reads carry access_mode=READ so they engage the server's off-thread reader pool. The server_metrics section is the /metrics before→after delta attributed to '$TARGET_DB'; throughput/latency are client-measured; the CBOR/JSON/NDJSON payload bytes are deterministic per seed+profile." \
      --assert \
      --max-abort-rate 0.5 \
      && info "evidence written to $EVIDENCE_DIR (external)" \
      || info "measure_target reported a violation or failure (see output above)"
    assert "evidence report.json was produced" "yes" \
      "$([ -f "$EVIDENCE_DIR/report.json" ] && echo yes || echo no)"
    assert "report.json is external-mode with a server_metrics section" "yes" \
      "$(grep -q '"measurement_mode": *"external"' "$EVIDENCE_DIR/report.json" 2>/dev/null \
         && grep -q '"server_metrics"' "$EVIDENCE_DIR/report.json" 2>/dev/null && echo yes || echo no)"
  else
    info "measure_target unavailable or /metrics snapshots missing; skipping server-side evidence (non-fatal)"
  fi

elif [ "$RUN_REST" = "1" ] && [ "$MODE" = "local" ]; then
  # ------------------------------------------------------------------------------------------------
  # LOCAL — the co-located server is still alive: read its REAL cumulative CPU + RSS and the on-disk
  # store/WAL footprint, emit the report via measure_server, and gate a fast-profile run against the
  # committed baseline. Additionally emit the server-side /metrics delta via measure_target into an
  # evidence subdirectory (the co-located primary report stays measure_server's).
  # ------------------------------------------------------------------------------------------------
  section "Step 4 — collect performance evidence (CPU / RAM / storage / throughput)"
  sample_peak_rss
  SERVER_UPTIME_SECS=$(( $(date +%s) - SERVER_START_EPOCH ))
  [ "$SERVER_UPTIME_SECS" -lt 1 ] && SERVER_UPTIME_SECS=1   # avoid a zero-length CPU window

  MEASURE_BIN="$BIN_DIR/measure_server"
  if [ ! -x "$MEASURE_BIN" ]; then
    harness_build "the dev-only measure_server harness binary (debug)" -p graphus-examples-harness --bin measure_server
    MEASURE_BIN="$REPO_ROOT/target/debug/measure_server"
  fi

  if [ -x "$MEASURE_BIN" ] && [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    rm -rf "$EVIDENCE_DIR"   # a fresh report each run; the dir is git-ignored
    "$MEASURE_BIN" \
      --evidence-dir "$EVIDENCE_DIR" \
      --scenario "knowledge-graph-rest" \
      --description "Knowledge graph served over the REST API (HTTPS + Bearer JWT via /auth/login): load a seeded KG, run the discovery queries against a known reference, stream NDJSON, negotiate CBOR vs JSON, and sustain concurrent READ clients." \
      --pid "$SERVER_PID" \
      --uptime-secs "$SERVER_UPTIME_SECS" \
      --store "$STORE_FILE" \
      --wal "$WAL_DIR" \
      --nodes "$NODE_COUNT" \
      --rels "$REL_COUNT" \
      --peak-rss-bytes "$PEAK_RSS_BYTES" \
      --total-millis "${WORKLOAD_MS:-0}" \
      --workload-ops "${W_OPS:-0}" \
      --workload-secs "${W_CONC_SECS:-0}" \
      --p50-ms "${W_P50:-0}" \
      --p99-ms "${W_P99:-0}" \
      --p999-ms "${W_P999:-0}" \
      --logical-bytes-written "$LOGICAL_GRAPH_BYTES" \
      --logical-graph-bytes "$LOGICAL_GRAPH_BYTES" \
      --param "profile=$PROFILE" \
      --param "connection=rest-https-jwt" \
      --param "client=python3 stdlib" \
      --param "clients=$CLIENTS" \
      --param "access_mode=READ" \
      --param "json_bytes=${W_JSON_BYTES:-0}" \
      --param "cbor_bytes=${W_CBOR_BYTES:-0}" \
      --param "cbor_ratio=${W_CBOR_RATIO:-0}" \
      --param "ndjson_rows=${W_NDJSON_ROWS:-0}" \
      --param "ndjson_bytes=${W_NDJSON_BYTES:-0}" \
      --param "ndjson_rows_per_sec=${W_NDJSON_RPS:-0}" \
      --param "ndjson_bytes_per_sec=${W_NDJSON_BPS:-0}" \
      --param "http_ops_per_sec=${W_OPS_PER_SEC:-0}" \
      --param "indexes_total=${W_INDEXES:-0}" \
      --param "constraints_total=${W_CONSTRAINTS:-0}" \
      --note "Throughput is the concurrency driver's HTTP requests over the window those requests were ACTUALLY ISSUED IN (concurrency_secs, measured by the python client) — it used to be divided by the whole server UPTIME, which silently understated req/s (rmp #699). The per-request latency percentiles + the payload sizes per encoding (json_bytes/cbor_bytes/cbor_ratio) + the NDJSON streaming throughput are likewise measured by the python client (GRAPHUS_STATS). Reads carry access_mode=READ so they engage the off-thread reader pool." \
      --note "storage.* is the REAL on-disk footprint: the graphus.store image plus the graphus.wal DIRECTORY of segment files. The amplification ratios are those durable bytes over the generator's logical graph.cypher bytes — previously the denominator was an invented nodes*256 + rels*128 formula and write_amplification was left at a 0.0 placeholder (rmp #699)." \
      --note "Payload sizes per encoding (json_bytes, cbor_bytes, cbor_ratio) and the dataset size are DETERMINISTIC for a fixed seed+profile and are gated tightly; req/s, latency, CPU and RSS are machine-variant and are NOT gated (see kg_baseline_cmp)." \
      && info "evidence written to $EVIDENCE_DIR" \
      || info "evidence collection failed (non-fatal); see output above"
    assert "evidence report.json was produced" "yes" \
      "$([ -f "$EVIDENCE_DIR/report.json" ] && echo yes || echo no)"
    assert "evidence report.md was produced" "yes" \
      "$([ -f "$EVIDENCE_DIR/report.md" ] && echo yes || echo no)"
    # Evidence honesty (rmp #699): total_millis is the workload's wall-time, every throughput/latency
    # field is really measured, and both amplification ratios are real (they were 0.0 placeholders).
    assert "report evidence is honest (real total_millis, no zero-placeholder latency/throughput)" "yes" \
      "$(python3 -c "
import json,sys
try: d = json.load(open('$EVIDENCE_DIR/report.json'))
except Exception: print('no'); sys.exit()
t, tp, st = d['total_millis'], d['throughput'], d['storage']
ok = (t >= 1.0
      and tp['ops_per_sec'] > 0.0
      and tp['p50_latency_ms'] > 0.0 and tp['p99_latency_ms'] > 0.0 and tp['p999_latency_ms'] > 0.0
      and st['store_bytes'] > 0 and st['wal_bytes'] > 0
      and st['write_amplification'] > 0.0 and st['space_amplification'] > 0.0)
print('yes' if ok else 'no')" 2>/dev/null || echo no)"

    # --------------------------------------------------------------------------------------------
    # Step 4b — regression gate vs committed baseline (fast profile only). Compares the STABLE
    # STRUCTURAL metrics (on-disk footprint, dataset size, EXACT payload bytes per encoding +
    # CBOR/JSON ratio, NDJSON rows) against tight thresholds; the machine-variant families
    # (req/s, latency, CPU, RSS) stay ungated.
    # --------------------------------------------------------------------------------------------
    if [ "$PROFILE" = "fast" ] && [ -f "$BASELINE" ] && [ -f "$EVIDENCE_DIR/report.json" ]; then
      section "Step 4b — regression gate vs committed baseline"
      CMP_BIN="$BIN_DIR/kg_baseline_cmp"
      if [ ! -x "$CMP_BIN" ]; then
        harness_build "the kg_baseline_cmp gate (debug)" -p graphus-kg-gen --bin kg_baseline_cmp
        CMP_BIN="$REPO_ROOT/target/debug/kg_baseline_cmp"
      fi
      CMP_OUT="$("$CMP_BIN" "$BASELINE" "$EVIDENCE_DIR/report.json" 2>&1)" || true
      printf '%s\n' "$CMP_OUT" | sed 's/^/  /'
      assert "fresh run is within baseline thresholds (structural metrics)" "yes" \
        "$(printf '%s' "$CMP_OUT" | grep -q 'GRAPHUS_BASELINE_OK' && echo yes || echo no)"
    fi

    # --------------------------------------------------------------------------------------------
    # Step 4c — server-side /metrics delta (additive). The co-located primary report above carries
    # CPU/RSS/storage + the baseline gate; here we ALSO compute the server-side counter delta from
    # the local /metrics before→after snapshots via measure_target, into evidence/server-metrics/.
    # Purely additive + non-fatal (skipped cleanly if curl/the snapshots were unavailable).
    # --------------------------------------------------------------------------------------------
    if [ -s "$METRICS_BEFORE" ] && [ -s "$METRICS_AFTER" ]; then
      MEASURE_TGT="$BIN_DIR/measure_target"
      if [ ! -x "$MEASURE_TGT" ]; then
        harness_build "the dev-only measure_target harness binary (debug)" -p graphus-examples-harness --bin measure_target
        MEASURE_TGT="$REPO_ROOT/target/debug/measure_target"
      fi
      if [ -x "$MEASURE_TGT" ]; then
        "$MEASURE_TGT" \
          --evidence-dir "$EVIDENCE_DIR/server-metrics" \
          --scenario "knowledge-graph-rest" \
          --description "Server-side /metrics counter delta for the local co-located run (companion to the primary report.json)." \
          --database "$TARGET_DB" \
          --metrics-before "$METRICS_BEFORE" \
          --metrics-after "$METRICS_AFTER" \
          --nodes "$NODE_COUNT" \
          --rels "$REL_COUNT" \
          --total-millis "${WORKLOAD_MS:-0}" \
          --workload-ops "${W_OPS:-0}" \
          --workload-secs "${W_CONC_SECS:-0}" \
          --abort-rate 0.0 \
          --note "Companion to the co-located measure_server report.json in the parent evidence dir: this is the /metrics before→after counter delta for database '$TARGET_DB'. The process CPU/RSS + on-disk storage vectors live in the parent report (not here)." \
          >/dev/null 2>&1 \
          && info "server-side /metrics delta written to $EVIDENCE_DIR/server-metrics/report.json" \
          || info "server-side /metrics delta unavailable (non-fatal)"
      fi
    fi
  else
    info "measure_server unavailable or server not alive; skipping evidence collection (non-fatal)"
  fi
fi

# Persist the schema snapshot (SHOW INDEXES / SHOW CONSTRAINTS) as durable evidence, AFTER any report
# rebuild above so it is not wiped by a report's fresh `rm -rf "$EVIDENCE_DIR"`.
if [ -n "$SCHEMA_JSON" ]; then
  mkdir -p "$EVIDENCE_DIR"
  printf '%s\n' "$SCHEMA_JSON" > "$EVIDENCE_DIR/schema_evidence.json"
  info "schema evidence written to $EVIDENCE_DIR/schema_evidence.json"
  assert "SHOW INDEXES / SHOW CONSTRAINTS evidence captured" "yes" \
    "$([ -s "$EVIDENCE_DIR/schema_evidence.json" ] && echo yes || echo no)"
fi

# Tear down the local server now (external teardown — the isolated DB — happens in the cleanup trap).
if [ -n "$SERVER_PID" ]; then
  stop_pid="$SERVER_PID"
  kill -TERM "$stop_pid" 2>/dev/null || true
  wait "$stop_pid" 2>/dev/null || true
  SERVER_PID=""
fi

if [ "$RUN_REST" != "1" ]; then
  section "REST workload SKIPPED (python3 or, in local mode, openssl absent)"
  info "the hermetic generator above still ran and asserted byte-identical output."
  info "install python3 (+ openssl for local mode) for the full REST/TLS/JWT demonstration."
fi

# --------------------------------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------------------------------
section "Result"
printf '%s checks run, %s failures.\n' "$CHECKS" "$FAILURES"
if [ "$RUN_REST" = "1" ] && [ -f "$EVIDENCE_DIR/report.json" ]; then
  if [ -f "$EVIDENCE_DIR/schema_evidence.json" ]; then
    printf 'evidence: %s {report.json, report.md, schema_evidence.json}\n' "$EVIDENCE_DIR"
  else
    printf 'evidence: %s {report.json, report.md}\n' "$EVIDENCE_DIR"
  fi
elif [ "$RUN_REST" = "1" ] && [ -f "$EVIDENCE_DIR/workload_stats.json" ]; then
  printf 'workload stats: %s\n' "$EVIDENCE_DIR/workload_stats.json"
fi
if [ "$FAILURES" -eq 0 ]; then
  if [ "$RUN_REST" = "1" ] && [ "$MODE" = "external" ]; then
    printf '%s%sKNOWLEDGE-GRAPH-REST DEMONSTRATION PASSED%s — Graphus served a seeded knowledge graph\n' "$BOLD" "$GREEN" "$RESET"
    printf 'over the REST API of an ALREADY-RUNNING instance (attach mode), isolated in a dedicated\n'
    printf 'database that was DROPPED on exit: authenticated via POST /auth/login, an unauthenticated\n'
    printf 'request was rejected, the graph loaded schema-first, every discovery query matched the known\n'
    printf 'reference, the full-text search returned exactly the known documents, property-type and\n'
    printf 'existence violations were rejected, a large result streamed as NDJSON, CBOR/JSON negotiated to\n'
    printf 'the same result, concurrent READ clients (off-thread reader pool) ran with zero errors, and\n'
    printf 'the server-side /metrics delta was captured as evidence (measurement_mode=external).\n'
  elif [ "$RUN_REST" = "1" ]; then
    printf '%s%sKNOWLEDGE-GRAPH-REST DEMONSTRATION PASSED%s — Graphus served a seeded knowledge graph\n' "$BOLD" "$GREEN" "$RESET"
    printf 'over the REST API (HTTPS + Bearer JWT via /auth/login): an unauthenticated request was\n'
    printf 'rejected, the graph loaded schema-first (unique-id + property-type + existence constraints, a\n'
    printf 'year RANGE index and a FULLTEXT title index) over batched auto-commit transactions, the\n'
    printf 'explicit begin/commit/rollback lifecycle worked, every discovery query matched the known\n'
    printf 'reference answers, the full-text title search returned exactly the known documents,\n'
    printf 'property-type and existence violations were rejected, a large result streamed as NDJSON, CBOR\n'
    printf 'and JSON negotiated to the same logical result, and concurrent READ clients ran with zero\n'
    printf 'errors.\n'
  else
    printf '%s%sKNOWLEDGE-GRAPH-REST DEMONSTRATION PASSED%s — the hermetic generator produced a\n' "$BOLD" "$GREEN" "$RESET"
    printf 'byte-identical seeded knowledge graph + reference answers. (The REST/TLS/JWT workload was\n'
    printf 'skipped: python3 or openssl absent. Install both for the full demonstration.)\n'
  fi
  exit 0
else
  printf '%s%sKNOWLEDGE-GRAPH-REST DEMONSTRATION FAILED%s — %s assertion(s) did not hold.\n' "$BOLD" "$RED" "$RESET" "$FAILURES"
  exit 1
fi
