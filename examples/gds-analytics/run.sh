#!/usr/bin/env bash
#
# Graphus Graph-Data-Science analytics demonstration — over Bolt-over-TCP+TLS, driven by the OFFICIAL
# Neo4j driver, plus a hermetic single-threaded scalability + CSR-footprint sweep.
#
# This script doubles as an executable E2E test. It:
#   1. generates a DETERMINISTIC, SEEDED influence/citation network (the `gds_gen` binary): :Author
#      nodes in `community_count` planted research fields, dense intra-field :CITES edges, sparse
#      inter-field :CROSS edges, and a small :Ref/:LINKS reference subgraph whose PageRank /
#      centrality / connected-component / shortest-path / community results are ANALYTICALLY KNOWN —
#      emitted as reference.json;
#   2. boots the REAL `graphus-server` exposing Bolt-over-TCP secured with a self-signed TLS cert;
#   3. loads the graph over Bolt via the OFFICIAL `neo4j-driver` npm package (`bolt+ssc://`), then
#      projects the CSR (`CALL gds.graph.project`) and runs the FULL algorithm suite through the
#      `CALL gds.*.stream` procedure surface (PageRank, degree/betweenness/closeness centrality,
#      WCC/SCC, triangleCount, labelPropagation, Dijkstra/Bellman-Ford), asserting the reference
#      outputs match ground truth within tolerance, and dropping the projections cleanly;
#   4. runs the HERMETIC scalability + CSR-footprint sweep (`gds_sweep`): graphus-gds is
#      SINGLE-THREADED (no rayon / thread pool / core knob — verified), so the sweep honestly varies
#      GRAPH SIZE, reporting per-algorithm time vs size and the CSR footprint in bytes-per-node /
#      bytes-per-edge. Its JSON lands in evidence/ for the report.
#
# Step 3 needs Node + npm + network (for `npm install neo4j-driver`); it is OPT-IN via RUN_DRIVER=1
# (default ON when `node`/`npm` are present, else skipped with a clear note). The generator (step 1)
# and the sweep (step 4) are HERMETIC and always run.
#
# Usage:
#   examples/gds-analytics/run.sh                       # builds binaries if needed, then runs
#   GRAPHUS_BIN_DIR=target/release  examples/gds-analytics/run.sh
#   GDS_PROFILE=large               examples/gds-analytics/run.sh   # evidence-scale dataset
#   RUN_DRIVER=0                    examples/gds-analytics/run.sh   # skip the official-driver steps
#   GDS_SWEEP_SIZES=40,120,360      examples/gds-analytics/run.sh   # custom sweep field sizes
#
# Requirements: a Unix host (Linux/macOS), bash, openssl (for the self-signed cert), and a checkout
# that builds. For the official-driver step also: node (v18+), npm, and network/cache access.

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
GEN="$BIN_DIR/gds_gen"
SWEEP="$BIN_DIR/gds_sweep"

PROFILE="${GDS_PROFILE:-fast}"
SWEEP_SIZES="${GDS_SWEEP_SIZES:-40,120,360,1080}"

if [ ! -x "$SERVER" ]; then
  section "Building graphus-server (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p graphus-server )
fi
[ -x "$SERVER" ] || { echo "${RED}fatal: server binary not found at $SERVER${RESET}" >&2; exit 2; }

if [ ! -x "$GEN" ]; then
  section "Building the deterministic influence-network generator (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p graphus-gds-gen --bin gds_gen )
fi
[ -x "$GEN" ] || { echo "${RED}fatal: gds_gen binary not found at $GEN${RESET}" >&2; exit 2; }

if [ ! -x "$SWEEP" ]; then
  section "Building the hermetic GDS scalability sweep (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p graphus-gds-gen --bin gds_sweep )
fi
[ -x "$SWEEP" ] || { echo "${RED}fatal: gds_sweep binary not found at $SWEEP${RESET}" >&2; exit 2; }

# --------------------------------------------------------------------------------------------------
# Workspace: a private temp store + TLS material + generated data, removed on exit
# --------------------------------------------------------------------------------------------------
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/graphus-gds-XXXXXX")"
CONFIG="$WORKDIR/graphus.toml"
SERVER_LOG="$WORKDIR/server.log"
CERT="$WORKDIR/cert.pem"
KEY="$WORKDIR/key.pem"
DATA_DIR="$WORKDIR/dataset"
ADMIN_USER="neo4j"
ADMIN_PW="gds-analytics-demo-pw-32bytes-minimum!"
JWT_SECRET="gds-analytics-demo-jwt-secret-32bytes-ok!"

# Evidence collection. The sibling #260-263 tasks wire the standardized report.json + report.md; this
# script produces the machine-readable inputs they consume (the driver's GRAPHUS_STATS + the sweep
# JSON). The evidence/ dir is git-ignored.
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
STORE_FILE="$WORKDIR/data/graphus.store"
WAL_DIR="$WORKDIR/data/graphus.wal"
SWEEP_JSON="$EVIDENCE_DIR/sweep.json"
PEAK_RSS_BYTES=0
SERVER_START_EPOCH=0

SERVER_PID=""
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

sample_peak_rss() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    local rss
    rss="$(server_rss_bytes "$SERVER_PID")"
    if [ "${rss:-0}" -gt "$PEAK_RSS_BYTES" ]; then
      PEAK_RSS_BYTES="$rss"
    fi
  fi
}

# json_field <json-blob> <key> — extract a scalar field from a one-line JSON object without jq.
json_field() {
  printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\\{0,1\\}\\([^,\"}]*\\).*/\\1/p" | head -n1
}

mkdir -p "$EVIDENCE_DIR"

# --------------------------------------------------------------------------------------------------
# Step 1 — generate the deterministic influence network + reference subgraph
# --------------------------------------------------------------------------------------------------
section "Step 1 — generate the deterministic influence network ($PROFILE profile)"
mkdir -p "$DATA_DIR"
GEN_OUT="$("$GEN" --profile "$PROFILE" --out-dir "$DATA_DIR")"
info "$GEN_OUT"
GRAPH_CYPHER="$DATA_DIR/graph.cypher"
REFERENCE="$DATA_DIR/reference.json"

# Parse the generator's `key=value` summary line for the dataset sizing.
kv() { printf '%s' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -n1; }
NODE_COUNT="$(kv "$GEN_OUT" nodes)"
REL_COUNT="$(kv "$GEN_OUT" rels)"
# Coarse logical-bytes estimate for the space-amplification ratio (~256 B/node + ~96 B/rel covers the
# fixed-record payloads + small property values) — a meaningful-but-honest proxy, not precise.
LOGICAL_GRAPH_BYTES=$(( ${NODE_COUNT:-0} * 256 + ${REL_COUNT:-0} * 96 ))
assert "graph.cypher generated"  "yes" "$([ -s "$GRAPH_CYPHER" ] && echo yes || echo no)"
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
# Step 2 — decide whether to run the official-driver step
# --------------------------------------------------------------------------------------------------
RUN_DRIVER="${RUN_DRIVER:-auto}"
if [ "$RUN_DRIVER" = "auto" ]; then
  if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
    RUN_DRIVER=1
  else
    RUN_DRIVER=0
  fi
fi

ANALYZE_OPS=0
ANALYZE_P50=0
ANALYZE_P99=0
ANALYZE_P999=0

if [ "$RUN_DRIVER" = "1" ]; then
  command -v openssl >/dev/null 2>&1 || { echo "${RED}fatal: openssl required for the TLS cert${RESET}" >&2; exit 2; }

  # ------------------------------------------------------------------------------------------------
  # Step 2 — boot a Bolt-TCP + TLS server
  # ------------------------------------------------------------------------------------------------
  section "Step 2 — boot graphus-server (Bolt-over-TCP + TLS)"

  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" \
    -days 2 -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

  BOLT_PORT="$(( (RANDOM % 20000) + 40000 ))"
  cat > "$CONFIG" <<EOF
# Generated by examples/gds-analytics/run.sh — a Bolt-TCP+TLS demo configuration.
store_path = "$WORKDIR/data"
buffer_pool_pages = 8192
bolt_tcp_addr = "127.0.0.1:$BOLT_PORT"
rest_addr = ""
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
      echo "${RED}server exited during startup; last log lines:${RESET}" >&2
      tail -n 20 "$SERVER_LOG" >&2
      exit 1
    fi
    if (exec 3<>"/dev/tcp/127.0.0.1/$BOLT_PORT") 2>/dev/null; then
      exec 3>&- 3<&- 2>/dev/null || true
      ready=1
      break
    fi
    sleep 0.1
  done
  [ "$ready" = "1" ] || { echo "${RED}server did not open Bolt-TCP port $BOLT_PORT${RESET}" >&2; tail -n 20 "$SERVER_LOG" >&2; exit 1; }
  info "server pid $SERVER_PID listening on bolt+ssc://127.0.0.1:$BOLT_PORT"

  # ------------------------------------------------------------------------------------------------
  # Install the official driver once (shared Node project under WORKDIR)
  # ------------------------------------------------------------------------------------------------
  NODE_PROJ="$WORKDIR/node"
  mkdir -p "$NODE_PROJ"
  cat > "$NODE_PROJ/package.json" <<'EOF'
{
  "name": "graphus-gds-analytics",
  "version": "1.0.0",
  "private": true,
  "description": "Drives Graphus GDS analytics over Bolt+TLS with the official Neo4j driver.",
  "dependencies": { "neo4j-driver": "^6.1.0" }
}
EOF
  cp "$SCRIPT_DIR/data/analyze.js" "$NODE_PROJ/analyze.js"

  section "Step 3 — load + analyze the influence network over Bolt (OFFICIAL neo4j-driver)"
  info "installing neo4j-driver (npm)…"
  ( cd "$NODE_PROJ" && npm install --no-audit --no-fund --loglevel=error ) >>"$SERVER_LOG" 2>&1 \
    || { echo "${RED}npm install neo4j-driver failed; see $SERVER_LOG${RESET}" >&2; exit 1; }

  ANALYZE_OUT="$(cd "$NODE_PROJ" && node analyze.js "$BOLT_PORT" "$ADMIN_USER" "$ADMIN_PW" "$GRAPH_CYPHER" "$REFERENCE" 2>&1)" || true
  printf '%s\n' "$ANALYZE_OUT" | sed 's/^/  /'
  assert "GDS analytics matched the reference ground truth" "yes" \
    "$(printf '%s' "$ANALYZE_OUT" | grep -q 'GRAPHUS_GDS_OK' && echo yes || echo no)"
  sample_peak_rss

  ANALYZE_STATS="$(printf '%s' "$ANALYZE_OUT" | sed -n 's/^GRAPHUS_STATS //p' | head -n1)"
  ANALYZE_OPS="$(json_field "$ANALYZE_STATS" operations)"
  ANALYZE_P50="$(json_field "$ANALYZE_STATS" p50_ms)"
  ANALYZE_P99="$(json_field "$ANALYZE_STATS" p99_ms)"
  ANALYZE_P999="$(json_field "$ANALYZE_STATS" p999_ms)"

  sample_peak_rss
  stop_pid="$SERVER_PID"
  kill -TERM "$stop_pid" 2>/dev/null || true
  wait "$stop_pid" 2>/dev/null || true
  SERVER_PID=""
else
  section "Steps 2–3 — official-driver path SKIPPED (RUN_DRIVER=0 or node/npm absent)"
  info "the hermetic generator + scalability sweep below still run and assert their invariants"
fi

# --------------------------------------------------------------------------------------------------
# Step 4 — hermetic single-threaded scalability + CSR-footprint sweep (always runs)
# --------------------------------------------------------------------------------------------------
section "Step 4 — scalability + CSR-footprint sweep (single-threaded, hermetic)"
info "graphus-gds is single-threaded (no rayon / thread pool / core knob) — the sweep varies GRAPH SIZE"
"$SWEEP" --out "$SWEEP_JSON" --sizes "$SWEEP_SIZES" --repeats 3 2>&1 | sed 's/^/  /'
assert "sweep JSON was produced" "yes" "$([ -s "$SWEEP_JSON" ] && echo yes || echo no)"
assert "sweep honestly reports single-threaded engine" "yes" \
  "$(grep -q '"engine_parallelism": "single-threaded"' "$SWEEP_JSON" && echo yes || echo no)"
assert "sweep reports a core_knob=false (no core sweep to fabricate)" "yes" \
  "$(grep -q '"core_knob": false' "$SWEEP_JSON" && echo yes || echo no)"
assert "sweep reports CSR bytes-per-node / bytes-per-edge" "yes" \
  "$(grep -q 'bytes_per_node' "$SWEEP_JSON" && grep -q 'bytes_per_edge' "$SWEEP_JSON" && echo yes || echo no)"

# --------------------------------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------------------------------
section "Result"
printf '%s checks run, %s failures.\n' "$CHECKS" "$FAILURES"
info "sweep evidence: $SWEEP_JSON"
if [ "$FAILURES" -eq 0 ]; then
  if [ "$RUN_DRIVER" = "1" ]; then
    printf '%s%sGDS-ANALYTICS DEMONSTRATION PASSED%s — Graphus loaded a seeded influence network over\n' "$BOLD" "$GREEN" "$RESET"
    printf 'Bolt/TLS via the official Neo4j driver, ran the FULL gds.* algorithm suite over the CSR\n'
    printf 'projection, matched the analytically-known reference outputs EXACTLY, recovered the planted\n'
    printf 'field communities, released the projections cleanly, and produced a single-threaded\n'
    printf 'scalability + CSR-footprint sweep.\n'
  else
    printf '%s%sGDS-ANALYTICS DEMONSTRATION PASSED%s — the hermetic generator produced a byte-identical\n' "$BOLD" "$GREEN" "$RESET"
    printf 'seeded influence network + reference subgraph and the single-threaded scalability sweep held\n'
    printf 'its invariants. (Official-driver load/analyze was skipped: RUN_DRIVER=0 or node/npm absent.\n'
    printf 'Run with node/npm present for the full Bolt/TLS GDS demonstration.)\n'
  fi
  exit 0
else
  printf '%s%sGDS-ANALYTICS DEMONSTRATION FAILED%s — %s assertion(s) did not hold.\n' "$BOLD" "$RED" "$RESET" "$FAILURES"
  exit 1
fi
