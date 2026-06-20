#!/usr/bin/env bash
#
# Graphus knowledge-graph-over-REST demonstration — over the REST transactional API, secured with
# TLS + Bearer-JWT auth, driven by a pure-stdlib python3 client.
#
# This script doubles as an executable E2E test. It:
#   1. generates a DETERMINISTIC, SEEDED knowledge graph (the `kg_gen` binary) — documents, authors,
#      concepts and topics with semantic relationships (AUTHORED / MENTIONS / CITES / ABOUT /
#      RELATED_TO) — plus a fixed reference subgraph whose discovery-query answers are KNOWN, emitted
#      as `reference.json`;
#   2. boots the REAL `graphus-server` exposing the REST API over HTTPS with a self-signed TLS cert
#      and a real `jwt_secret` (production REST requires both TLS and a non-default JWT secret);
#   3. runs the python REST workload (`data/discovery.py`), which: mints a Bearer JWT out of band,
#      proves an unauthenticated request is rejected 401, loads the graph in BATCHED auto-commit
#      transactions, demonstrates the explicit begin/commit/rollback lifecycle, asserts the five
#      discovery queries (lookup / multi-hop traversal / recommendation / aggregation / concept
#      path) against `reference.json`, streams a large result as NDJSON, negotiates CBOR vs JSON and
#      compares payload sizes, and drives concurrent HTTP clients with zero errors.
#
# The generator (step 1) is HERMETIC and CI-runnable on its own (`cargo test -p graphus-kg-gen`
# proves byte-identical output per seed). Steps 2 + 3 need `openssl` (for the self-signed cert) and
# `python3` (stdlib only — no pip packages). They are skipped with a clear note if either is absent.
#
# Usage:
#   examples/knowledge-graph-rest/run.sh                          # builds binaries if needed, runs
#   GRAPHUS_BIN_DIR=target/release  examples/knowledge-graph-rest/run.sh
#   KG_PROFILE=large                examples/knowledge-graph-rest/run.sh   # evidence-scale dataset
#   KG_CLIENTS=32 KG_OPS=40         examples/knowledge-graph-rest/run.sh   # heavier concurrency
#
# Requirements: a Unix host (Linux/macOS), bash, openssl, python3 (3.8+, stdlib only), and a checkout
# that builds.

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
SERVER="$BIN_DIR/graphus-server"
GEN="$BIN_DIR/kg_gen"

PROFILE="${KG_PROFILE:-fast}"
CLIENTS="${KG_CLIENTS:-16}"
OPS_PER_CLIENT="${KG_OPS:-20}"
BATCH_SIZE="${KG_BATCH:-200}"

if [ ! -x "$SERVER" ]; then
  section "Building graphus-server (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p graphus-server )
fi
[ -x "$SERVER" ] || { echo "${RED}fatal: server binary not found at $SERVER${RESET}" >&2; exit 2; }

if [ ! -x "$GEN" ]; then
  section "Building the deterministic knowledge-graph generator (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p graphus-kg-gen --bin kg_gen )
fi
[ -x "$GEN" ] || { echo "${RED}fatal: kg_gen binary not found at $GEN${RESET}" >&2; exit 2; }

# --------------------------------------------------------------------------------------------------
# Workspace: a private temp store + TLS material + generated data, removed on exit
# --------------------------------------------------------------------------------------------------
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/graphus-kg-rest-XXXXXX")"
CONFIG="$WORKDIR/graphus.toml"
SERVER_LOG="$WORKDIR/server.log"
CERT="$WORKDIR/cert.pem"
KEY="$WORKDIR/key.pem"
DATA_DIR="$WORKDIR/dataset"
ADMIN_USER="neo4j"
ADMIN_PW="kg-rest-demo-admin-pw-8plus"
JWT_SECRET="kg-rest-demo-jwt-secret-32bytes-minimum!"

# Evidence collection (rmp #282/#285). The standardized report.json + report.md land in the
# git-ignored evidence/ dir; the durable store/WAL paths follow the server's single-db layout
# (<store_path>/graphus.store, <store_path>/graphus.wal/). BASELINE is the committed reference run we
# compare a fresh fast-profile run against.
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
STORE_FILE="$WORKDIR/data/graphus.store"
WAL_DIR="$WORKDIR/data/graphus.wal"
BASELINE="$SCRIPT_DIR/baseline.json"
PEAK_RSS_BYTES=0          # high-watermark of the server's RSS, sampled during the workload
SERVER_START_EPOCH=0      # wall-clock epoch (s) of the server boot, for the CPU/uptime window

SERVER_PID=""
# cleanup — kill ONLY the server pid we spawned and `wait` ONLY on it (never a bare `wait`, which
# would block on the background server itself; that hazard bit the durability example). The python
# client is run synchronously in the foreground via command-substitution, so it has already exited
# by the time we reach teardown — there is no client pid to reap here.
cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
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

# sample_peak_rss — read the live server's RSS once and keep the running high-watermark.
sample_peak_rss() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    local rss
    rss="$(server_rss_bytes "$SERVER_PID")"
    if [ "${rss:-0}" -gt "$PEAK_RSS_BYTES" ]; then
      PEAK_RSS_BYTES="$rss"
    fi
  fi
}

# json_field <json-blob> <key> — extract a numeric/string field from the one-line GRAPHUS_STATS JSON
# object the python client emits, without a jq dependency (the object is flat scalars).
json_field() {
  printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\\{0,1\\}\\([^,\"}]*\\).*/\\1/p" | head -n1
}

# --------------------------------------------------------------------------------------------------
# Step 1 — generate the deterministic knowledge graph + reference subgraph
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
# These are byte-stable for a fixed seed+profile (the schema DDL is excluded by the anchored pattern).
NODE_COUNT="$(grep -cE '^CREATE \(:' "$GRAPH_CYPHER" || true)"
REL_COUNT="$(grep -cE 'CREATE \([a-z]\)-\[:' "$GRAPH_CYPHER" || true)"
NODE_COUNT="${NODE_COUNT:-0}"
REL_COUNT="${REL_COUNT:-0}"
# Coarse logical-bytes estimate for the space-amplification ratio (~256 B/node + ~128 B/rel covers
# the fixed-record node/rel payloads and their small property values) — a meaningful-but-honest
# proxy, documented in the README, not precise accounting (same convention as fraud-oltp).
LOGICAL_GRAPH_BYTES=$(( NODE_COUNT * 256 + REL_COUNT * 128 ))
info "dataset: $NODE_COUNT nodes, $REL_COUNT relationships"

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
# Step 2 — decide whether to run the REST workload (needs openssl + python3)
# --------------------------------------------------------------------------------------------------
RUN_REST=1
command -v openssl >/dev/null 2>&1 || RUN_REST=0
command -v python3 >/dev/null 2>&1 || RUN_REST=0

if [ "$RUN_REST" = "1" ]; then
  # ------------------------------------------------------------------------------------------------
  # Boot a REST + TLS server (production REST path: TLS + a real JWT secret).
  # ------------------------------------------------------------------------------------------------
  section "Step 2 — boot graphus-server (REST over HTTPS + Bearer JWT)"

  # Self-signed cert (CN/SAN localhost; the python client trusts it via an unverified SSL context).
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
  # Wait until the REST port is accepting connections (or the process dies).
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

  # ------------------------------------------------------------------------------------------------
  # Step 3 — the REST discovery workload (python3, stdlib only)
  # ------------------------------------------------------------------------------------------------
  section "Step 3 — knowledge-graph discovery over REST (python3 stdlib client)"
  REST_OUT="$(python3 "$SCRIPT_DIR/data/discovery.py" \
    --port "$REST_PORT" \
    --secret "$JWT_SECRET" \
    --user "$ADMIN_USER" \
    --cypher "$GRAPH_CYPHER" \
    --reference "$REFERENCE" \
    --batch-size "$BATCH_SIZE" \
    --clients "$CLIENTS" \
    --ops-per-client "$OPS_PER_CLIENT" 2>&1)" || true
  printf '%s\n' "$REST_OUT" | sed 's/^/  /'
  assert "REST workload passed every assertion" "yes" \
    "$(printf '%s' "$REST_OUT" | grep -q 'GRAPHUS_KG_REST_OK' && echo yes || echo no)"
  sample_peak_rss   # the load + discovery + concurrency just ran; capture the server's RSS here

  # Harvest the machine-readable stats line for the evidence wiring (rmp #282-285).
  STATS="$(printf '%s' "$REST_OUT" | sed -n 's/^[[:space:]]*GRAPHUS_STATS //p' | head -n1)"
  if [ -n "$STATS" ]; then
    mkdir -p "$EVIDENCE_DIR"
    printf '%s\n' "$STATS" > "$EVIDENCE_DIR/workload_stats.json"
    info "workload stats written to $EVIDENCE_DIR/workload_stats.json"
    assert "machine-readable workload stats captured" "yes" \
      "$([ -s "$EVIDENCE_DIR/workload_stats.json" ] && echo yes || echo no)"
  fi

  # Pull the per-metric figures the python client measured (latency percentiles, payload sizes,
  # streaming throughput) out of the stats line for the standardized report.
  W_OPS="$(json_field "$STATS" concurrency_ops)"
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

  # ------------------------------------------------------------------------------------------------
  # Step 4 — collect standardized performance evidence (CPU / RAM / storage / throughput) (rmp #282)
  # ------------------------------------------------------------------------------------------------
  # The server is still alive, so we read its REAL cumulative CPU + RSS and the on-disk store/WAL
  # footprint the workload produced, then emit the schema-versioned report.json + report.md via the
  # dev-only measure_server harness binary. The HTTP-request/latency/streaming/payload figures the
  # python client measured ride in as throughput inputs + workload params. This is purely ADDITIVE:
  # it changes no assertion above, and a metering failure must not fail the demonstration.
  section "Step 4 — collect performance evidence (CPU / RAM / storage / throughput)"
  sample_peak_rss
  SERVER_UPTIME_SECS=$(( $(date +%s) - SERVER_START_EPOCH ))
  [ "$SERVER_UPTIME_SECS" -lt 1 ] && SERVER_UPTIME_SECS=1   # avoid a zero-length CPU window

  MEASURE_BIN="$BIN_DIR/measure_server"
  if [ ! -x "$MEASURE_BIN" ]; then
    info "building the dev-only measure_server harness binary (debug)…"
    ( cd "$REPO_ROOT" && cargo build -q -p graphus-examples-harness --bin measure_server ) || true
    MEASURE_BIN="$REPO_ROOT/target/debug/measure_server"
  fi

  if [ -x "$MEASURE_BIN" ] && [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    rm -rf "$EVIDENCE_DIR"   # a fresh report each run; the dir is git-ignored
    "$MEASURE_BIN" \
      --evidence-dir "$EVIDENCE_DIR" \
      --scenario "knowledge-graph-rest" \
      --description "Knowledge graph served over the REST API (HTTPS + Bearer JWT): load a seeded KG, run the discovery queries against a known reference, stream NDJSON, negotiate CBOR vs JSON, and sustain concurrent clients." \
      --pid "$SERVER_PID" \
      --uptime-secs "$SERVER_UPTIME_SECS" \
      --store "$STORE_FILE" \
      --wal "$WAL_DIR" \
      --nodes "$NODE_COUNT" \
      --rels "$REL_COUNT" \
      --peak-rss-bytes "$PEAK_RSS_BYTES" \
      --workload-ops "${W_OPS:-0}" \
      --workload-secs "$SERVER_UPTIME_SECS" \
      --p50-ms "${W_P50:-0}" \
      --p99-ms "${W_P99:-0}" \
      --p999-ms "${W_P999:-0}" \
      --logical-graph-bytes "$LOGICAL_GRAPH_BYTES" \
      --param "profile=$PROFILE" \
      --param "connection=rest-https-jwt" \
      --param "client=python3 stdlib" \
      --param "clients=$CLIENTS" \
      --param "json_bytes=${W_JSON_BYTES:-0}" \
      --param "cbor_bytes=${W_CBOR_BYTES:-0}" \
      --param "cbor_ratio=${W_CBOR_RATIO:-0}" \
      --param "ndjson_rows=${W_NDJSON_ROWS:-0}" \
      --param "ndjson_bytes=${W_NDJSON_BYTES:-0}" \
      --param "ndjson_rows_per_sec=${W_NDJSON_RPS:-0}" \
      --param "ndjson_bytes_per_sec=${W_NDJSON_BPS:-0}" \
      --param "http_ops_per_sec=${W_OPS_PER_SEC:-0}" \
      --note "Throughput is the concurrency driver's HTTP requests over the server uptime window (a coarse proxy); the per-request latency percentiles + the payload sizes per encoding (json_bytes/cbor_bytes/cbor_ratio) + the NDJSON streaming throughput are measured by the python client (GRAPHUS_STATS) and ride in as throughput inputs + workload params." \
      --note "Payload sizes per encoding (json_bytes, cbor_bytes, cbor_ratio) and the dataset size are DETERMINISTIC for a fixed seed+profile and are gated tightly; req/s, latency, CPU and RSS are machine-variant and are NOT gated (see kg_baseline_cmp)." \
      && info "evidence written to $EVIDENCE_DIR" \
      || info "evidence collection failed (non-fatal); see output above"
    assert "evidence report.json was produced" "yes" \
      "$([ -f "$EVIDENCE_DIR/report.json" ] && echo yes || echo no)"
    assert "evidence report.md was produced" "yes" \
      "$([ -f "$EVIDENCE_DIR/report.md" ] && echo yes || echo no)"

    # ----------------------------------------------------------------------------------------------
    # Step 4b — regression gate vs committed baseline (fast profile only — the committed baseline is
    # a fast-profile run). We compare the STABLE STRUCTURAL metrics (on-disk footprint, dataset size,
    # EXACT payload bytes per encoding + CBOR/JSON ratio, NDJSON rows) against tight thresholds, and
    # leave the machine-variant families (req/s, latency, CPU, RSS) ungated. Delegated to the
    # kg-gen `kg_baseline_cmp` helper (named distinctly from fraud-oltp's `baseline_cmp` to avoid a
    # target/<profile> binary-name collision — both leaf crates ship a comparator).
    # ----------------------------------------------------------------------------------------------
    if [ "$PROFILE" = "fast" ] && [ -f "$BASELINE" ] && [ -f "$EVIDENCE_DIR/report.json" ]; then
      section "Step 4b — regression gate vs committed baseline"
      CMP_BIN="$BIN_DIR/kg_baseline_cmp"
      if [ ! -x "$CMP_BIN" ]; then
        ( cd "$REPO_ROOT" && cargo build -q -p graphus-kg-gen --bin kg_baseline_cmp ) || true
        CMP_BIN="$REPO_ROOT/target/debug/kg_baseline_cmp"
      fi
      CMP_OUT="$("$CMP_BIN" "$BASELINE" "$EVIDENCE_DIR/report.json" 2>&1)" || true
      printf '%s\n' "$CMP_OUT" | sed 's/^/  /'
      assert "fresh run is within baseline thresholds (structural metrics)" "yes" \
        "$(printf '%s' "$CMP_OUT" | grep -q 'GRAPHUS_BASELINE_OK' && echo yes || echo no)"
    fi
  else
    info "measure_server unavailable or server not alive; skipping evidence collection (non-fatal)"
  fi

  stop_pid="$SERVER_PID"
  kill -TERM "$stop_pid" 2>/dev/null || true
  wait "$stop_pid" 2>/dev/null || true
  SERVER_PID=""
else
  section "Steps 2–3 — REST workload SKIPPED (openssl or python3 absent)"
  info "the hermetic generator above still ran and asserted byte-identical output."
  info "install openssl + python3 for the full REST/TLS/JWT demonstration."
fi

# --------------------------------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------------------------------
section "Result"
printf '%s checks run, %s failures.\n' "$CHECKS" "$FAILURES"
if [ "$RUN_REST" = "1" ] && [ -f "$EVIDENCE_DIR/report.json" ]; then
  printf 'evidence: %s {report.json, report.md}\n' "$EVIDENCE_DIR"
elif [ "$RUN_REST" = "1" ] && [ -f "$EVIDENCE_DIR/workload_stats.json" ]; then
  printf 'workload stats: %s\n' "$EVIDENCE_DIR/workload_stats.json"
fi
if [ "$FAILURES" -eq 0 ]; then
  if [ "$RUN_REST" = "1" ]; then
    printf '%s%sKNOWLEDGE-GRAPH-REST DEMONSTRATION PASSED%s — Graphus served a seeded knowledge graph\n' "$BOLD" "$GREEN" "$RESET"
    printf 'over the REST API (HTTPS + Bearer JWT): an unauthenticated request was rejected, the graph\n'
    printf 'loaded over batched auto-commit transactions, the explicit begin/commit/rollback lifecycle\n'
    printf 'worked, every discovery query matched the known reference answers, a large result streamed\n'
    printf 'as NDJSON, CBOR and JSON negotiated to the same logical result, and concurrent clients ran\n'
    printf 'with zero errors.\n'
  else
    printf '%s%sKNOWLEDGE-GRAPH-REST DEMONSTRATION PASSED%s — the hermetic generator produced a\n' "$BOLD" "$GREEN" "$RESET"
    printf 'byte-identical seeded knowledge graph + reference answers. (The REST/TLS/JWT workload was\n'
    printf 'skipped: openssl or python3 absent. Install both for the full demonstration.)\n'
  fi
  exit 0
else
  printf '%s%sKNOWLEDGE-GRAPH-REST DEMONSTRATION FAILED%s — %s assertion(s) did not hold.\n' "$BOLD" "$RED" "$RESET" "$FAILURES"
  exit 1
fi
