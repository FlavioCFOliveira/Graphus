#!/usr/bin/env bash
#
# Graphus product-recommendations demonstration — a READ-HEAVY concurrency evaluation.
#
# The scenario: a product-recommendation service over a social + purchase graph (a multigraph LPG):
#   (:User {id,name,country,signup})
#   (:Product {id,name,category,price})
#   (:User)-[:FRIEND {since}]-(:User)          an undirected configuration-model multigraph
#   (:User)-[:PURCHASED {ts,qty}]->(:Product)  a popularity-skewed purchase history
# Recommendations are drawn from a customer's DIRECT friends, their 2nd- and 3rd-level friends, and
# from customers with a SIMILAR CONSUMPTION PROFILE (collaborative filtering / co-purchase).
#
# This script doubles as an executable E2E test. It:
#   1. GENERATES the graph deterministically (`reco_gen`) as neo4j-admin-import-flavoured CSV and
#      proves it is byte-identical per seed;
#   2. boots a REAL `graphus-server` exposing Bolt-over-UDS (the read driver) + plaintext-loopback
#      REST (the bulk-import upload path), on a private temp store;
#   3. LOADS the graph over the wire via the ratified network bulk-import Mode A (`reco_load`):
#      CREATE DATABASE -> streaming CSV upload -> START DATABASE -> CREATE INDEX -> asserts the graph
#      shape and that every recommendation query returns a well-formed result;
#   4. drives the read-heavy CONCURRENCY LADDER (`reco_bench`): many simultaneous UDS-Bolt
#      connections issuing the recommendation read battery (with a few concurrent writes), sweeping
#      the connection count to find the saturation knee, while sampling the SERVER's CPU (total +
#      per-thread), RSS and IO from /proc — exposing where reads scale across cores vs hit the
#      single-engine-thread ceiling;
#   5. emits standardized evidence (report.json + report.md) and, at the fast profile, gates the
#      stable STRUCTURAL metrics against the committed baseline (`reco_baseline_cmp`).
#
# Usage:
#   examples/product-recommendations/run.sh                         # builds binaries if needed, runs
#   GRAPHUS_BIN_DIR=target/release  examples/product-recommendations/run.sh
#   RECO_PROFILE=large              examples/product-recommendations/run.sh   # evidence-scale run
#   RECO_READER_THREADS=4           examples/product-recommendations/run.sh   # pin the reader pool
#
# Requirements: a Linux host (the /proc server sampling is Linux-specific; the run still works on
# macOS but the CPU/RSS/IO server evidence is skipped there), bash, and a checkout that builds. No
# network / openssl / node.

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

# kv <summary-line> <key> — pull a `key=value` token out of a generator/driver summary line.
kv() { printf '%s' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -n1; }

# --------------------------------------------------------------------------------------------------
# Locate (or build) the binaries
# --------------------------------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${GRAPHUS_BIN_DIR:-$REPO_ROOT/target/release}"

GEN="$BIN_DIR/reco_gen"
LOAD="$BIN_DIR/reco_load"
BENCH="$BIN_DIR/reco_bench"
CMP_BIN="$BIN_DIR/reco_baseline_cmp"
SERVER="$BIN_DIR/graphus-server"

PROFILE="${RECO_PROFILE:-fast}"

# Ladder + op-budget per profile. `fast` is small and CI-quick; `large` is an evidence-scale sweep.
case "$PROFILE" in
  fast)  LADDER="1,2,4,8";           OPS_PER_RUNG=1500;  WRITE_EVERY_MS=0;  POOL_PAGES=8192 ;;
  large) LADDER="1,2,4,8,16,32,64";  OPS_PER_RUNG=20000; WRITE_EVERY_MS=50; POOL_PAGES=49152 ;;
  *) echo "${RED}fatal: unknown RECO_PROFILE '$PROFILE' (use fast|large)${RESET}" >&2; exit 2 ;;
esac

if [ ! -x "$GEN" ] || [ ! -x "$LOAD" ] || [ ! -x "$BENCH" ] || [ ! -x "$CMP_BIN" ]; then
  section "Building the product-recommendations binaries (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p graphus-reco-gen --bins )
fi
if [ ! -x "$SERVER" ]; then
  section "Building graphus-server (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p graphus-server )
fi
for b in "$GEN" "$LOAD" "$BENCH" "$CMP_BIN" "$SERVER"; do
  [ -x "$b" ] || { echo "${RED}fatal: required binary not found at $b${RESET}" >&2; exit 2; }
done

# --------------------------------------------------------------------------------------------------
# Workspace: a private temp dir removed on exit. The evidence/ dir is git-ignored; baseline.json lives
# at a non-ignored path.
# --------------------------------------------------------------------------------------------------
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/graphus-reco-XXXXXX")"
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
BASELINE="$SCRIPT_DIR/baseline.json"
GENDIR="$WORKDIR/gen"
SOCKET="$WORKDIR/graphus.sock"
CONFIG="$WORKDIR/graphus.toml"
SERVER_LOG="$WORKDIR/server.log"
DATA_DIR="$WORKDIR/data"
mkdir -p "$EVIDENCE_DIR"

SERVER_PID=""
cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

# A free TCP port for the plaintext-loopback REST listener (the bulk-import upload path).
free_port() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
  else
    echo 47474
  fi
}
REST_PORT="$(free_port)"
REST_ADDR="127.0.0.1:$REST_PORT"

ADMIN_USER="reco"
ADMIN_PW="reco-admin-pw-1"
DEFAULT_DB="graphus"
TARGET_DB="recodb"

# ==================================================================================================
# Step 1 — deterministic generator (byte-identical per seed)
# ==================================================================================================
section "Step 1 — deterministic recommendation-graph generator ($PROFILE profile)"
GEN_OUT="$("$GEN" --profile "$PROFILE" --out-dir "$DATA_DIR")"
printf '%s\n' "$GEN_OUT" | sed 's/^/  /'
assert "users.csv generated" "yes" "$([ -s "$DATA_DIR/users.csv" ] && echo yes || echo no)"
assert "products.csv generated" "yes" "$([ -s "$DATA_DIR/products.csv" ] && echo yes || echo no)"
assert "friends.csv generated" "yes" "$([ -s "$DATA_DIR/friends.csv" ] && echo yes || echo no)"
assert "purchased.csv generated" "yes" "$([ -s "$DATA_DIR/purchased.csv" ] && echo yes || echo no)"

"$GEN" --profile "$PROFILE" --out-dir "$GENDIR" >/dev/null
if diff -q "$DATA_DIR/users.csv" "$GENDIR/users.csv" >/dev/null \
   && diff -q "$DATA_DIR/purchased.csv" "$GENDIR/purchased.csv" >/dev/null; then
  assert "generator is byte-identical per seed" "yes" "yes"
else
  assert "generator is byte-identical per seed" "yes" "no"
fi
rm -rf "$GENDIR"

GEN_USERS="$(kv "$GEN_OUT" users)"
GEN_PRODUCTS="$(kv "$GEN_OUT" products)"
GEN_FRIENDS="$(kv "$GEN_OUT" friend_edges)"
GEN_PURCHASED="$(kv "$GEN_OUT" purchased_edges)"
info "graph: $GEN_USERS users, $GEN_PRODUCTS products, $GEN_FRIENDS FRIEND, $GEN_PURCHASED PURCHASED"

# ==================================================================================================
# Step 2 — boot a real server (UDS-Bolt for reads + plaintext-loopback REST for the bulk upload)
# ==================================================================================================
section "Step 2 — boot graphus-server (Bolt-over-UDS + plaintext-loopback REST)"
cat > "$CONFIG" <<EOF
# Generated by examples/product-recommendations/run.sh — a UDS+REST dev configuration.
store_path = "$WORKDIR/store"
default_database = "$DEFAULT_DB"
buffer_pool_pages = $POOL_PAGES
uds_path = "$SOCKET"
rest_addr = "$REST_ADDR"
jwt_secret = "graphus-product-recommendations-example-uds-rest-secret-32+"
# Plaintext loopback REST (dev/test only) so the network bulk-import upload needs no TLS/cert.
allow_insecure_network = true

[auth]
admin_user = "$ADMIN_USER"
admin_password = "$ADMIN_PW"
admin_uid = $(id -u)
EOF

# Let the operator pin the reader pool (0 = auto) to observe its effect on read scaling.
if [ -n "${RECO_READER_THREADS:-}" ]; then
  printf '\n[admission]\nreader_threads = %s\n' "$RECO_READER_THREADS" >> "$CONFIG"
  info "reader pool pinned to $RECO_READER_THREADS thread(s)"
fi

"$SERVER" "$CONFIG" >>"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
BOUND=no
for _ in $(seq 1 150); do
  if [ -S "$SOCKET" ]; then BOUND=yes; break; fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then break; fi
  sleep 0.1
done
assert "server bound the UDS socket" "yes" "$BOUND"
if [ "$BOUND" != "yes" ]; then
  echo "${RED}server did not come up; last log lines:${RESET}" >&2
  tail -n 20 "$SERVER_LOG" >&2 || true
  exit 1
fi
info "REST on $REST_ADDR, UDS on $SOCKET, server pid $SERVER_PID"

# ==================================================================================================
# Step 3 — load the graph over the wire (network bulk-import Mode A) + schema + correctness asserts
# ==================================================================================================
section "Step 3 — network bulk-import (Mode A) + schema + correctness asserts"
LOAD_OUT="$("$LOAD" \
  --rest "$REST_ADDR" --default-db "$DEFAULT_DB" --db "$TARGET_DB" \
  --data-dir "$DATA_DIR" --user "$ADMIN_USER" --password "$ADMIN_PW" \
  --expect-users "$GEN_USERS" --expect-products "$GEN_PRODUCTS" \
  --expect-friends "$GEN_FRIENDS" --expect-purchased "$GEN_PURCHASED" 2>&1)" || true
# Show the loader's diagnostics (delete the machine-readable sentinel line, indent the rest). Use
# `sed` (not `grep -v`, which exits 1 on no-match and would trip `set -o pipefail`/`set -e` when the
# loader prints only the sentinel).
printf '%s\n' "$LOAD_OUT" | sed '/^GRAPHUS_RECO_LOAD_OK/d; s/^/  /'
assert "graph loaded + indexed + every recommendation query well-formed" "yes" \
  "$(printf '%s' "$LOAD_OUT" | grep -q 'GRAPHUS_RECO_LOAD_OK' && echo yes || echo no)"
if ! printf '%s' "$LOAD_OUT" | grep -q 'GRAPHUS_RECO_LOAD_OK'; then
  echo "${RED}load failed; aborting the concurrency ladder.${RESET}" >&2
  exit 1
fi

# ==================================================================================================
# Step 4 — the read-heavy CONCURRENCY LADDER + server resource sampling + evidence
# ==================================================================================================
section "Step 4 — concurrent read ladder (many simultaneous UDS-Bolt connections)"
rm -f "$EVIDENCE_DIR/report.json" "$EVIDENCE_DIR/report.md"
BENCH_OUT="$("$BENCH" \
  --socket "$SOCKET" --user "$ADMIN_USER" --password "$ADMIN_PW" --db "$TARGET_DB" \
  --server-pid "$SERVER_PID" --ladder "$LADDER" --ops-per-rung "$OPS_PER_RUNG" \
  --users "$GEN_USERS" --products "$GEN_PRODUCTS" \
  --friends "$GEN_FRIENDS" --purchased "$GEN_PURCHASED" \
  --scenario "product-recommendations" --evidence-dir "$EVIDENCE_DIR" \
  --write-every-ms "$WRITE_EVERY_MS" 2>&1)" || true
printf '%s\n' "$BENCH_OUT" | sed 's/^/  /'
assert "evidence report.json was produced" "yes" \
  "$([ -f "$EVIDENCE_DIR/report.json" ] && echo yes || echo no)"
assert "evidence report.md was produced" "yes" \
  "$([ -f "$EVIDENCE_DIR/report.md" ] && echo yes || echo no)"

# ==================================================================================================
# Step 5 — regression gate vs the committed baseline (fast profile only; structural metrics)
# ==================================================================================================
if [ "$PROFILE" = "fast" ] && [ -f "$BASELINE" ] && [ -f "$EVIDENCE_DIR/report.json" ]; then
  section "regression gate vs committed baseline (structural metrics)"
  CMP_OUT="$("$CMP_BIN" "$BASELINE" "$EVIDENCE_DIR/report.json" 2>&1)" || true
  printf '%s\n' "$CMP_OUT" | sed 's/^/  /'
  assert "fresh run is within baseline thresholds (structural metrics)" "yes" \
    "$(printf '%s' "$CMP_OUT" | grep -q 'GRAPHUS_BASELINE_OK' && echo yes || echo no)"
elif [ ! -f "$BASELINE" ]; then
  info "no committed baseline.json yet — skipping the regression gate."
else
  info "regression gate skipped (non-fast profile: not baseline-comparable)."
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
  printf '%s%sPRODUCT-RECOMMENDATIONS DEMONSTRATION PASSED%s — the seeded generator is byte-identical,\n' "$BOLD" "$GREEN" "$RESET"
  printf 'the %s-user / %s-product graph (%s FRIEND, %s PURCHASED) was network-bulk-loaded over the wire,\n' "${GEN_USERS:-?}" "${GEN_PRODUCTS:-?}" "${GEN_FRIENDS:-?}" "${GEN_PURCHASED:-?}"
  printf 'every recommendation query returned a well-formed result, and the concurrent read ladder\n'
  printf 'produced standardized evidence of the server read-path behaviour under load.\n'
  exit 0
else
  printf '%s%sPRODUCT-RECOMMENDATIONS DEMONSTRATION FAILED%s — %s assertion(s) did not hold.\n' "$BOLD" "$RED" "$RESET" "$FAILURES"
  exit 1
fi
