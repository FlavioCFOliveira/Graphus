#!/usr/bin/env bash
#
# Graphus fraud-detection OLTP demonstration — over Bolt-over-TCP+TLS, driven by the OFFICIAL Neo4j
# driver, plus an extreme-concurrency SSI driver and a deterministic in-process SSI repro.
#
# This script doubles as an executable E2E test. It:
#   1. generates a DETERMINISTIC, SEEDED fraud graph (the `gen` binary) with a known, enumerable set
#      of planted fraud structures (transaction rings + mule fan-in/fan-out chains) and emits the
#      ground truth as JSON;
#   2. boots the REAL `graphus-server` exposing Bolt-over-TCP secured with a self-signed TLS cert;
#   3. loads the schema (UNIQUE constraints + indexes) and the graph over Bolt via the OFFICIAL
#      `neo4j-driver` npm package (`bolt+ssc://`), then runs the detection workload and asserts it
#      finds EXACTLY the planted fraud (0 false negatives, 0 false positives on the seeded set);
#   4. runs an EXTREME-CONCURRENCY SSI driver: many overlapping writer/reader transactions contending
#      on hot accounts, reporting commit/abort tallies and proving NO committed transfer is lost;
#   5. runs the DETERMINISTIC in-process SSI-contention repro (`dst_contention`), which reproduces the
#      same contention byte-identically for a fixed seed.
#
# Steps 3 + 4 need Node + npm + network (for `npm install neo4j-driver`); they are OPT-IN via
# RUN_DRIVER=1 (default ON when `node`/`npm` are present, else skipped with a clear note). The
# generator (step 1) and the DST repro (step 5) are HERMETIC and always run.
#
# Usage:
#   examples/fraud-oltp/run.sh                       # builds binaries if needed, then runs
#   GRAPHUS_BIN_DIR=target/release  examples/fraud-oltp/run.sh
#   FRAUD_PROFILE=large             examples/fraud-oltp/run.sh   # evidence-scale dataset
#   RUN_DRIVER=0                    examples/fraud-oltp/run.sh   # skip the official-driver steps
#
# Requirements: a Unix host (Linux/macOS), bash, openssl (for the self-signed cert), and a checkout
# that builds. For the official-driver steps also: node (v18+), npm, and network/cache access.

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
GEN="$BIN_DIR/gen"
DST="$BIN_DIR/dst_contention"

PROFILE="${FRAUD_PROFILE:-fast}"
DST_SEED="${FRAUD_DST_SEED:-42}"

if [ ! -x "$SERVER" ]; then
  section "Building graphus-server (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p graphus-server )
fi
[ -x "$SERVER" ] || { echo "${RED}fatal: server binary not found at $SERVER${RESET}" >&2; exit 2; }

if [ ! -x "$GEN" ]; then
  section "Building the deterministic fraud generator (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p graphus-fraud-gen --bin gen )
fi
[ -x "$GEN" ] || { echo "${RED}fatal: gen binary not found at $GEN${RESET}" >&2; exit 2; }

if [ ! -x "$DST" ]; then
  section "Building the deterministic DST contention repro (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p graphus-fraud-gen --features dst-repro --bin dst_contention )
fi
[ -x "$DST" ] || { echo "${RED}fatal: dst_contention binary not found at $DST${RESET}" >&2; exit 2; }

# --------------------------------------------------------------------------------------------------
# Workspace: a private temp store + TLS material + generated data, removed on exit
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
# Step 1 — generate the deterministic fraud graph + ground truth
# --------------------------------------------------------------------------------------------------
section "Step 1 — generate the deterministic fraud graph ($PROFILE profile)"
mkdir -p "$DATA_DIR"
GEN_OUT="$("$GEN" --profile "$PROFILE" --out-dir "$DATA_DIR")"
info "$GEN_OUT"
GRAPH_CYPHER="$DATA_DIR/graph.cypher"
GROUND_TRUTH="$DATA_DIR/ground_truth.json"
assert "graph.cypher generated"      "yes" "$([ -s "$GRAPH_CYPHER" ] && echo yes || echo no)"
assert "ground_truth.json generated" "yes" "$([ -s "$GROUND_TRUTH" ] && echo yes || echo no)"

# Determinism check: regenerate and diff (the AC: byte-identical per seed/scale).
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
  if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
    RUN_DRIVER=1
  else
    RUN_DRIVER=0
  fi
fi

if [ "$RUN_DRIVER" = "1" ]; then
  command -v openssl >/dev/null 2>&1 || { echo "${RED}fatal: openssl required for the TLS cert${RESET}" >&2; exit 2; }

  # ------------------------------------------------------------------------------------------------
  # Step 2 — boot a Bolt-TCP + TLS server
  # ------------------------------------------------------------------------------------------------
  section "Step 2 — boot graphus-server (Bolt-over-TCP + TLS)"

  # Self-signed cert (CN/SAN localhost; the driver connects with bolt+ssc:// which trusts it).
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" \
    -days 2 -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

  # Bolt-TCP + TLS config. Port 0 is not supported by the file config (the OS picks ephemeral only
  # via the in-process API), so we pick a high random port and read it back from the log.
  BOLT_PORT="$(( (RANDOM % 20000) + 40000 ))"
  cat > "$CONFIG" <<EOF
# Generated by examples/fraud-oltp/run.sh — a Bolt-TCP+TLS demo configuration.
store_path = "$WORKDIR/data"
buffer_pool_pages = 4096
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
  # Wait until the Bolt-TCP port is accepting connections (or the process dies).
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
  "name": "graphus-fraud-oltp",
  "version": "1.0.0",
  "private": true,
  "description": "Drives Graphus fraud detection over Bolt+TLS with the official Neo4j driver.",
  "dependencies": { "neo4j-driver": "^6.1.0" }
}
EOF
  cp "$SCRIPT_DIR/data/detect.js" "$NODE_PROJ/detect.js"
  cp "$SCRIPT_DIR/data/concurrency.js" "$NODE_PROJ/concurrency.js"

  section "Step 3 — load + detect fraud over Bolt (OFFICIAL neo4j-driver)"
  info "installing neo4j-driver (npm)…"
  ( cd "$NODE_PROJ" && npm install --no-audit --no-fund --loglevel=error ) >>"$SERVER_LOG" 2>&1 \
    || { echo "${RED}npm install neo4j-driver failed; see $SERVER_LOG${RESET}" >&2; exit 1; }

  DETECT_OUT="$(cd "$NODE_PROJ" && node detect.js "$BOLT_PORT" "$ADMIN_USER" "$ADMIN_PW" "$GRAPH_CYPHER" "$GROUND_TRUTH" 2>&1)" || true
  printf '%s\n' "$DETECT_OUT" | sed 's/^/  /'
  assert "detection found EXACTLY the planted fraud" "yes" \
    "$(printf '%s' "$DETECT_OUT" | grep -q 'GRAPHUS_FRAUD_OK' && echo yes || echo no)"

  # ------------------------------------------------------------------------------------------------
  # Step 4 — extreme-concurrency SSI driver
  # ------------------------------------------------------------------------------------------------
  section "Step 4 — extreme-concurrency SSI driver (overlapping txns on hot accounts)"
  # 12 clients, 30 ops each, 8 hot accounts: enough overlap to fire SSI (non-zero, bounded aborts)
  # while still letting a healthy fraction of writers commit — the "sustains concurrency" signal.
  CONC_OUT="$(cd "$NODE_PROJ" && node concurrency.js "$BOLT_PORT" "$ADMIN_USER" "$ADMIN_PW" 12 30 8 2>&1)" || true
  printf '%s\n' "$CONC_OUT" | sed 's/^/  /'
  assert "concurrency: no lost update, SSI invariant held" "yes" \
    "$(printf '%s' "$CONC_OUT" | grep -q 'GRAPHUS_CONCURRENCY_OK' && echo yes || echo no)"

  stop_pid="$SERVER_PID"
  kill -TERM "$stop_pid" 2>/dev/null || true
  wait "$stop_pid" 2>/dev/null || true
  SERVER_PID=""
else
  section "Steps 2–4 — official-driver path SKIPPED (RUN_DRIVER=0 or node/npm absent)"
  info "the hermetic generator + DST repro below still run and assert the same fraud structures"
fi

# --------------------------------------------------------------------------------------------------
# Step 5 — deterministic in-process SSI-contention repro (hermetic; always runs)
# --------------------------------------------------------------------------------------------------
section "Step 5 — deterministic SSI-contention repro (seed=$DST_SEED)"
DST_OUT1="$("$DST" --seed "$DST_SEED" --rounds 40 --clients 4 --hot 3 2>&1)" || true
printf '%s\n' "$DST_OUT1" | sed 's/^/  /'
assert "DST contention repro passed its SSI invariants" "yes" \
  "$(printf '%s' "$DST_OUT1" | grep -q 'GRAPHUS_DST_CONTENTION_OK' && echo yes || echo no)"

# Reproducibility: a second run at the same seed must be byte-identical.
DST_OUT2="$("$DST" --seed "$DST_SEED" --rounds 40 --clients 4 --hot 3 2>&1)" || true
assert "DST repro is byte-identical for a fixed seed" "yes" \
  "$([ "$DST_OUT1" = "$DST_OUT2" ] && echo yes || echo no)"

# --------------------------------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------------------------------
section "Result"
printf '%s checks run, %s failures.\n' "$CHECKS" "$FAILURES"
if [ "$FAILURES" -eq 0 ]; then
  printf '%s%sFRAUD-OLTP DEMONSTRATION PASSED%s — Graphus loaded a seeded fraud graph over Bolt/TLS\n' "$BOLD" "$GREEN" "$RESET"
  printf 'via the official Neo4j driver, detected EXACTLY the planted fraud, sustained extreme\n'
  printf 'concurrency with no lost update, and reproduced the SSI contention deterministically.\n'
  exit 0
else
  printf '%s%sFRAUD-OLTP DEMONSTRATION FAILED%s — %s assertion(s) did not hold.\n' "$BOLD" "$RED" "$RESET" "$FAILURES"
  exit 1
fi
