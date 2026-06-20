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

EVIDENCE_DIR="$SCRIPT_DIR/evidence"

SERVER_PID=""
cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

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

  # Harvest the machine-readable stats line for the evidence wiring (rmp #282-285).
  STATS="$(printf '%s' "$REST_OUT" | sed -n 's/^[[:space:]]*GRAPHUS_STATS //p' | head -n1)"
  if [ -n "$STATS" ]; then
    mkdir -p "$EVIDENCE_DIR"
    printf '%s\n' "$STATS" > "$EVIDENCE_DIR/workload_stats.json"
    info "workload stats written to $EVIDENCE_DIR/workload_stats.json"
    assert "machine-readable workload stats captured" "yes" \
      "$([ -s "$EVIDENCE_DIR/workload_stats.json" ] && echo yes || echo no)"
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
if [ "$RUN_REST" = "1" ] && [ -f "$EVIDENCE_DIR/workload_stats.json" ]; then
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
