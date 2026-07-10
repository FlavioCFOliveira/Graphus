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
# It runs in TWO modes (auto-detected via the shared external-target seam in `_harness/harness.sh`):
#
#   LOCAL (default)   — self-boots a REAL `graphus-server` exposing Bolt-over-UDS (the read driver) +
#                       plaintext-loopback REST (the bulk-import upload path), loads the graph via the
#                       ratified network bulk-import Mode A (`reco_load --rest`), declares the full
#                       modern read-path SCHEMA (VECTOR/HNSW + TEXT + NODE KEY + UNIQUE + property-type),
#                       drives the concurrency ladder over UDS while sampling the SERVER's per-thread
#                       CPU/RSS/IO from /proc (the single-engine-thread vs reader-pool knee diagnosis),
#                       emits standardized evidence, and gates the STRUCTURAL metrics against the
#                       committed baseline.
#   EXTERNAL (attach) — when ANY of GRAPHUS_TARGET_{BOLT,REST,UDS} is set, attaches to an
#                       ALREADY-RUNNING instance (local OR remote, e.g. pi516) over Bolt-over-TCP + TLS.
#                       It carves out a dedicated, isolated database, loads the graph over Bolt with a
#                       VERSION-TOLERANT minimal schema (`reco_load --bolt`; an older server may not
#                       support the modern VECTOR/property-type DDL), scrapes the target's `/metrics`
#                       before + after the ladder, drives the SAME read ladder over Bolt-TCP+TLS
#                       (`reco_bench --bolt`, /proc sampling OFF — the server-side channel is /metrics),
#                       emits an EXTERNAL-mode report via `measure_target` (server-side committed/aborted
#                       deltas + client throughput/latency; process CPU/RSS + storage are N/A remotely
#                       and no baseline is gated), and DROPS the isolated database on exit.
#
# Usage:
#   examples/product-recommendations/run.sh                         # local self-boot, fast profile
#   RECO_PROFILE=large              examples/product-recommendations/run.sh   # evidence-scale local run
#   RECO_READER_THREADS=4           examples/product-recommendations/run.sh   # pin the reader pool (local)
#   GRAPHUS_TARGET_BOLT=bolt+ssc://host:7687 GRAPHUS_TARGET_REST=https://host:7474 \
#     GRAPHUS_TARGET_USER=graphus GRAPHUS_TARGET_PASSWORD=graphus-local \
#     GRAPHUS_TARGET_TLS_INSECURE=1  examples/product-recommendations/run.sh  # attach to a running instance
#
# External-mode knobs (all optional): RECO_EXTERNAL_LADDER (default 1,2,4,8,16), RECO_EXTERNAL_OPS
# (default 2000), RECO_WRITERS (default 0), RECO_WRITE_EVERY_MS (default 0), RECO_TARGET_RPS (default 0
# = closed-loop), RECO_MIN_OPS_PER_CLIENT (default 150), RECO_AUTO_EXTEND (default 1).
#
# Requirements: a Unix host, bash, curl. LOCAL mode's /proc server sampling is Linux-specific (the run
# still works on macOS but the CPU/RSS/IO server evidence is skipped there). No node / openssl needed.

set -euo pipefail

# --------------------------------------------------------------------------------------------------
# Shared external-target seam (GRAPHUS_TARGET_* detection, isolated-DB create/drop, /metrics scrape).
# Sourced FIRST; the pretty-printers + assert counters below are then (re)defined so the harness's
# target helpers (which call `info`/`section` by name) transparently use these definitions.
# --------------------------------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../_harness/harness.sh
source "$(cd "$SCRIPT_DIR/../_harness" && pwd)/harness.sh"
export HARNESS_SCENARIO="product-recommendations"   # names the isolated DB: ex_product-recommendations_<epoch>_<pid>

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

MODE="$(harness_target_mode)"   # external iff GRAPHUS_TARGET_{BOLT,REST,UDS} is set, else local

# --------------------------------------------------------------------------------------------------
# Locate (or build) the binaries
# --------------------------------------------------------------------------------------------------
BIN_DIR="${GRAPHUS_BIN_DIR:-$REPO_ROOT/target/release}"

GEN="$BIN_DIR/reco_gen"
LOAD="$BIN_DIR/reco_load"
BENCH="$BIN_DIR/reco_bench"
CMP_BIN="$BIN_DIR/reco_baseline_cmp"
SERVER="$BIN_DIR/graphus-server"

PROFILE="${RECO_PROFILE:-fast}"

# Ladder + op-budget per profile (LOCAL). `fast` is small and CI-quick; `large` is an evidence sweep.
case "$PROFILE" in
  fast)  LADDER="1,2,4,8";           OPS_PER_RUNG=1500;  WRITE_EVERY_MS=0;  POOL_PAGES=8192 ;;
  large) LADDER="1,2,4,8,16,32,64";  OPS_PER_RUNG=20000; WRITE_EVERY_MS=50; POOL_PAGES=49152 ;;
  *) echo "${RED}fatal: unknown RECO_PROFILE '$PROFILE' (use fast|large)${RESET}" >&2; exit 2 ;;
esac

# External-mode ladder / op budget (independent of the local profile; brackets a multi-core knee and
# auto-extends past the tested top rung until throughput plateaus).
EXT_LADDER="${RECO_EXTERNAL_LADDER:-1,2,4,8,16}"
EXT_OPS="${RECO_EXTERNAL_OPS:-2000}"
EXT_WRITERS="${RECO_WRITERS:-0}"
EXT_WRITE_EVERY_MS="${RECO_WRITE_EVERY_MS:-0}"
EXT_TARGET_RPS="${RECO_TARGET_RPS:-0}"
MIN_OPS_PER_CLIENT="${RECO_MIN_OPS_PER_CLIENT:-150}"
AUTO_EXTEND="${RECO_AUTO_EXTEND:-1}"

# The generator profile: LOCAL uses the ladder profile ($PROFILE); EXTERNAL defaults to the small
# `tiny` graph so the whole graph loads quickly over Bolt UNWIND writes even against a small/remote or
# OLDER server (whose planner may not index-seek on an UNWIND-row-valued anchor). Override with
# RECO_EXTERNAL_PROFILE (e.g. `fast`) against a current server for the full-size graph.
if [ "$MODE" = external ]; then
  GEN_PROFILE="${RECO_EXTERNAL_PROFILE:-tiny}"
else
  GEN_PROFILE="$PROFILE"
fi

if [ ! -x "$GEN" ] || [ ! -x "$LOAD" ] || [ ! -x "$BENCH" ] || [ ! -x "$CMP_BIN" ]; then
  section "Building the product-recommendations binaries (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p graphus-reco-gen --bins )
fi
# The server binary is only needed to self-boot in LOCAL mode.
if [ "$MODE" = local ] && [ ! -x "$SERVER" ]; then
  section "Building graphus-server (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p graphus-server )
fi
for b in "$GEN" "$LOAD" "$BENCH" "$CMP_BIN"; do
  [ -x "$b" ] || { echo "${RED}fatal: required binary not found at $b${RESET}" >&2; exit 2; }
done
if [ "$MODE" = local ]; then
  [ -x "$SERVER" ] || { echo "${RED}fatal: server binary not found at $SERVER${RESET}" >&2; exit 2; }
fi

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
METRICS_BEFORE="$WORKDIR/metrics_before.prom"
METRICS_AFTER="$WORKDIR/metrics_after.prom"
mkdir -p "$EVIDENCE_DIR"

SERVER_PID=""
TARGET_DB=""
cleanup() {
  # LOCAL: stop the self-booted server.
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  # EXTERNAL: drop the isolated DB we created (no-op for an operator-owned GRAPHUS_TARGET_DB).
  if [ "$MODE" = external ]; then
    harness_target_drop_db >/dev/null 2>&1 || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

ADMIN_USER="reco"
ADMIN_PW="reco-admin-pw-1"
DEFAULT_DB="graphus"
LOCAL_TARGET_DB="recodb"

# ==================================================================================================
# Step 1 — deterministic generator (byte-identical per seed) — both modes
# ==================================================================================================
section "Step 1 — deterministic recommendation-graph generator ($GEN_PROFILE profile)"
GEN_OUT="$("$GEN" --profile "$GEN_PROFILE" --out-dir "$DATA_DIR")"
printf '%s\n' "$GEN_OUT" | sed 's/^/  /'
assert "users.csv generated" "yes" "$([ -s "$DATA_DIR/users.csv" ] && echo yes || echo no)"
assert "products.csv generated" "yes" "$([ -s "$DATA_DIR/products.csv" ] && echo yes || echo no)"
assert "friends.csv generated" "yes" "$([ -s "$DATA_DIR/friends.csv" ] && echo yes || echo no)"
assert "purchased.csv generated" "yes" "$([ -s "$DATA_DIR/purchased.csv" ] && echo yes || echo no)"

"$GEN" --profile "$GEN_PROFILE" --out-dir "$GENDIR" >/dev/null
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
NODE_COUNT=$(( ${GEN_USERS:-0} + ${GEN_PRODUCTS:-0} ))
REL_COUNT=$(( ${GEN_FRIENDS:-0} + ${GEN_PURCHASED:-0} ))
info "graph: $GEN_USERS users, $GEN_PRODUCTS products, $GEN_FRIENDS FRIEND, $GEN_PURCHASED PURCHASED"

# ==================================================================================================
# Step 2 — attach to a running instance (external) OR boot a local server (local)
# ==================================================================================================
if [ "$MODE" = external ]; then
  section "Step 2 — attach to the running Graphus instance (Bolt-over-TCP + TLS)"
  BOLT_URI="${GRAPHUS_TARGET_BOLT:?external mode requires GRAPHUS_TARGET_BOLT (bolt://host:port)}"
  [ -n "${GRAPHUS_TARGET_REST:-}${GRAPHUS_TARGET_METRICS:-}" ] || {
    echo "${RED}fatal: external mode needs GRAPHUS_TARGET_REST (or _METRICS) for DB isolation + /metrics${RESET}" >&2; exit 2; }
  TARGET_DB="$(harness_target_ensure_db)" || { echo "${RED}fatal: could not resolve an isolated target database${RESET}" >&2; exit 1; }
  DRIVER_USER="${GRAPHUS_TARGET_USER:-graphus}"
  DRIVER_PW="${GRAPHUS_TARGET_PASSWORD:-graphus-local}"
  info "attaching to $BOLT_URI, isolated database '$TARGET_DB'"
  assert "isolated target database resolved" "yes" "$([ -n "$TARGET_DB" ] && echo yes || echo no)"
else
  section "Step 2 — boot graphus-server (Bolt-over-UDS + plaintext-loopback REST)"
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
  TARGET_DB="$LOCAL_TARGET_DB"
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
fi

# ==================================================================================================
# Step 3 — load the graph + schema + correctness asserts
# ==================================================================================================
# The loader streams progress live (indented, sentinels stripped) via `tee` while its full output is
# captured to LOAD_LOG for sentinel parsing — a Bolt attach load of ~30k edges into a small/remote box
# runs against the single-writer edge-create path and can take a couple of minutes, so live progress
# beats a silent wait.
LOAD_LOG="$WORKDIR/load.log"
STRIP_SENTINELS='/^GRAPHUS_RECO_LOAD_OK/d; /^GRAPHUS_RECO_SCHEMA /d; /GRAPHUS_RECO_SCHEMA_BEGIN/,/GRAPHUS_RECO_SCHEMA_END/d; s/^/  /'
if [ "$MODE" = external ]; then
  section "Step 3 — load the graph over Bolt (version-tolerant UNWIND) + correctness asserts"
  info "loading over Bolt (index-backed UNWIND batches); on a small/remote box this can take a couple of minutes…"
  set +e
  "$LOAD" \
    --bolt "$BOLT_URI" --db "$TARGET_DB" \
    --data-dir "$DATA_DIR" --user "$DRIVER_USER" --password "$DRIVER_PW" \
    --expect-users "$GEN_USERS" --expect-products "$GEN_PRODUCTS" \
    --expect-friends "$GEN_FRIENDS" --expect-purchased "$GEN_PURCHASED" 2>&1 \
    | tee "$LOAD_LOG" | sed "$STRIP_SENTINELS"
  set -e
else
  section "Step 3 — network bulk-import (Mode A) + schema + correctness asserts"
  set +e
  "$LOAD" \
    --rest "$REST_ADDR" --default-db "$DEFAULT_DB" --db "$TARGET_DB" \
    --data-dir "$DATA_DIR" --user "$ADMIN_USER" --password "$ADMIN_PW" \
    --expect-users "$GEN_USERS" --expect-products "$GEN_PRODUCTS" \
    --expect-friends "$GEN_FRIENDS" --expect-purchased "$GEN_PURCHASED" 2>&1 \
    | tee "$LOAD_LOG" | sed "$STRIP_SENTINELS"
  set -e
fi
LOAD_OUT="$(cat "$LOAD_LOG")"
assert "graph loaded + every recommendation query well-formed" "yes" \
  "$(printf '%s' "$LOAD_OUT" | grep -q 'GRAPHUS_RECO_LOAD_OK' && echo yes || echo no)"
if ! printf '%s' "$LOAD_OUT" | grep -q 'GRAPHUS_RECO_LOAD_OK'; then
  echo "${RED}load failed; aborting the concurrency ladder.${RESET}" >&2
  exit 1
fi

# LOCAL: harvest the modern schema evidence (the SHOW INDEXES / SHOW CONSTRAINTS dump between the
# GRAPHUS_RECO_SCHEMA_BEGIN/_END sentinels). The Bolt attach path declares only a version-tolerant
# minimal schema, so this block is local-only.
if [ "$MODE" = local ]; then
  SCHEMA_EVIDENCE_FILE="$WORKDIR/schema.txt"
  printf '%s\n' "$LOAD_OUT" \
    | sed -n '/GRAPHUS_RECO_SCHEMA_BEGIN/,/GRAPHUS_RECO_SCHEMA_END/p' > "$SCHEMA_EVIDENCE_FILE"
  RECO_SCHEMA_STATS="$(printf '%s' "$LOAD_OUT" | sed -n 's/^GRAPHUS_RECO_SCHEMA //p' | head -n1)"
  SCHEMA_INDEXES="$(kv "$RECO_SCHEMA_STATS" indexes)"
  SCHEMA_CONSTRAINTS="$(kv "$RECO_SCHEMA_STATS" constraints)"
  assert "schema evidence (SHOW INDEXES/CONSTRAINTS) captured" "yes" \
    "$([ -s "$SCHEMA_EVIDENCE_FILE" ] && echo yes || echo no)"
  assert "SHOW INDEXES lists the TEXT + VECTOR index kinds" "yes" \
    "$([ "${SCHEMA_INDEXES:-0}" -ge 4 ] 2>/dev/null && echo yes || echo no)"
  assert "SHOW CONSTRAINTS lists the NODE KEY + UNIQUE + property-type kinds" "yes" \
    "$([ "${SCHEMA_CONSTRAINTS:-0}" -ge 3 ] 2>/dev/null && echo yes || echo no)"
fi

# ==================================================================================================
# Step 4 — the read-heavy CONCURRENCY LADDER + evidence
# ==================================================================================================
if [ "$MODE" = external ]; then
  section "Step 4 — concurrent read ladder over Bolt-TCP+TLS (attach) + /metrics evidence"
  rm -f "$EVIDENCE_DIR/report.json" "$EVIDENCE_DIR/report.md"

  # Scrape /metrics BEFORE the ladder (after the load, so only the ladder's work is in the window).
  harness_scrape_metrics "$METRICS_BEFORE" || info "metrics-before scrape failed (non-fatal)"
  assert "/metrics scraped before the ladder" "yes" "$([ -s "$METRICS_BEFORE" ] && echo yes || echo no)"

  AUTO_FLAG=()
  [ "$AUTO_EXTEND" = "1" ] && AUTO_FLAG=(--auto-extend)
  # Stream the per-rung progress live (indented) via `tee` while capturing the full output (including
  # the machine-readable sentinels) to BENCH_LOG for parsing below.
  BENCH_LOG="$WORKDIR/bench.log"
  set +e
  "$BENCH" \
    --bolt "$BOLT_URI" --user "$DRIVER_USER" --password "$DRIVER_PW" --db "$TARGET_DB" \
    --ladder "$EXT_LADDER" --ops-per-rung "$EXT_OPS" \
    --min-ops-per-client "$MIN_OPS_PER_CLIENT" \
    --write-every-ms "$EXT_WRITE_EVERY_MS" --writers "$EXT_WRITERS" \
    --target-rps "$EXT_TARGET_RPS" "${AUTO_FLAG[@]}" \
    --users "$GEN_USERS" --products "$GEN_PRODUCTS" \
    --friends "$GEN_FRIENDS" --purchased "$GEN_PURCHASED" \
    --scenario "product-recommendations" 2>&1 \
    | tee "$BENCH_LOG" | sed 's/^/  /'
  set -e
  BENCH_OUT="$(cat "$BENCH_LOG")"

  # Scrape /metrics AFTER the ladder.
  harness_scrape_metrics "$METRICS_AFTER" || info "metrics-after scrape failed (non-fatal)"
  assert "/metrics scraped after the ladder" "yes" "$([ -s "$METRICS_AFTER" ] && echo yes || echo no)"

  # Harvest the client-side stats sentinels the driver printed for measure_target.
  BENCH_STATS="$(printf '%s' "$BENCH_OUT" | sed -n 's/^GRAPHUS_RECO_BENCH_STATS //p' | head -n1)"
  assert "client-side stats sentinel produced" "yes" "$([ -n "$BENCH_STATS" ] && echo yes || echo no)"
  BEST_CLIENTS="$(kv "$BENCH_STATS" best_clients)"
  BEST_OPS_PER_SEC="$(kv "$BENCH_STATS" best_ops_per_sec)"
  BEST_OPS="$(kv "$BENCH_STATS" best_ops)"
  BEST_SECS="$(kv "$BENCH_STATS" best_secs)"
  P50_MS="$(kv "$BENCH_STATS" p50_ms)"
  P99_MS="$(kv "$BENCH_STATS" p99_ms)"
  P999_MS="$(kv "$BENCH_STATS" p999_ms)"
  ABORT_RATE="$(kv "$BENCH_STATS" abort_rate)"

  # Forward the full per-rung scaling curve + the client-side scaling verdict as report notes.
  RUNG_NOTES=()
  while IFS= read -r line; do
    [ -n "$line" ] && RUNG_NOTES+=(--note "$line")
  done < <(printf '%s\n' "$BENCH_OUT" | grep '^GRAPHUS_RECO_BENCH_RUNG ' || true)
  VERDICT_LINE="$(printf '%s\n' "$BENCH_OUT" | grep 'CLIENT-SIDE VERDICT' | head -n1 || true)"
  [ -n "$VERDICT_LINE" ] && RUNG_NOTES+=(--note "$VERDICT_LINE")

  # Emit the EXTERNAL-mode evidence report via measure_target (server-side /metrics delta + the
  # client-measured throughput/latency; process CPU/RSS + storage are N/A remotely).
  MEASURE_BIN="$BIN_DIR/measure_target"
  if [ ! -x "$MEASURE_BIN" ]; then
    info "building the dev-only measure_target harness binary…"
    ( cd "$REPO_ROOT" && cargo build -q -p graphus-examples-harness --bin measure_target ) || true
    MEASURE_BIN="$REPO_ROOT/target/debug/measure_target"
  fi
  if [ -x "$MEASURE_BIN" ] && [ -s "$METRICS_BEFORE" ] && [ -s "$METRICS_AFTER" ] && [ -n "$BENCH_STATS" ]; then
    "$MEASURE_BIN" \
      --evidence-dir "$EVIDENCE_DIR" \
      --scenario "product-recommendations" \
      --description "read-heavy product recommendations: concurrent read scaling over Bolt-TCP+TLS (attach mode)" \
      --database "$TARGET_DB" \
      --metrics-before "$METRICS_BEFORE" --metrics-after "$METRICS_AFTER" \
      --nodes "$NODE_COUNT" --rels "$REL_COUNT" \
      --workload-ops "${BEST_OPS:-0}" --workload-secs "${BEST_SECS:-1}" \
      --p50-ms "${P50_MS:-0}" --p99-ms "${P99_MS:-0}" --p999-ms "${P999_MS:-0}" \
      --abort-rate "${ABORT_RATE:-0}" \
      --param "connection=bolt-tcp-tls" \
      --param "target=$BOLT_URI" \
      --param "scenario_db=$TARGET_DB" \
      --param "ladder=$EXT_LADDER" \
      --param "ops_per_rung=$EXT_OPS" \
      --param "min_ops_per_client=$MIN_OPS_PER_CLIENT" \
      --param "writers=$EXT_WRITERS" \
      --param "target_rps=$EXT_TARGET_RPS" \
      --param "best_clients=${BEST_CLIENTS:-?}" \
      --param "best_ops_per_sec=${BEST_OPS_PER_SEC:-?}" \
      --param "user_count=$GEN_USERS" --param "product_count=$GEN_PRODUCTS" \
      --param "friend_count=$GEN_FRIENDS" --param "purchased_count=$GEN_PURCHASED" \
      --param "node_count=$NODE_COUNT" --param "relationship_count=$REL_COUNT" \
      "${RUNG_NOTES[@]}" \
      --note "Client throughput/latency are measured by reco_bench over Bolt-TCP+TLS; the server-side channel is the /metrics before/after delta (no /proc — remote/attached instance)." \
      --assert \
      && info "external evidence written to $EVIDENCE_DIR" \
      || { info "measure_target reported an invariant violation or error"; FAILURES=$((FAILURES + 1)); }
    assert "external report.json produced (measurement_mode=external)" "yes" \
      "$([ -f "$EVIDENCE_DIR/report.json" ] && grep -q '"measurement_mode": *"external"' "$EVIDENCE_DIR/report.json" && echo yes || echo no)"
    assert "report.json carries server_metrics deltas" "yes" \
      "$([ -f "$EVIDENCE_DIR/report.json" ] && grep -q '"server_metrics"' "$EVIDENCE_DIR/report.json" && echo yes || echo no)"
  else
    info "measure_target unavailable or metrics missing; skipping evidence collection (non-fatal)"
    FAILURES=$((FAILURES + 1))
  fi
else
  section "Step 4 — concurrent read ladder (many simultaneous UDS-Bolt connections)"
  rm -f "$EVIDENCE_DIR/report.json" "$EVIDENCE_DIR/report.md"
  BENCH_OUT="$("$BENCH" \
    --socket "$SOCKET" --user "$ADMIN_USER" --password "$ADMIN_PW" --db "$TARGET_DB" \
    --server-pid "$SERVER_PID" --ladder "$LADDER" --ops-per-rung "$OPS_PER_RUNG" \
    --min-ops-per-client "$MIN_OPS_PER_CLIENT" \
    --users "$GEN_USERS" --products "$GEN_PRODUCTS" \
    --friends "$GEN_FRIENDS" --purchased "$GEN_PURCHASED" \
    --scenario "product-recommendations" --evidence-dir "$EVIDENCE_DIR" \
    --write-every-ms "$WRITE_EVERY_MS" 2>&1)" || true
  printf '%s\n' "$BENCH_OUT" | sed 's/^/  /'
  assert "evidence report.json was produced" "yes" \
    "$([ -f "$EVIDENCE_DIR/report.json" ] && echo yes || echo no)"
  assert "evidence report.md was produced" "yes" \
    "$([ -f "$EVIDENCE_DIR/report.md" ] && echo yes || echo no)"

  # Persist the modern schema evidence into the evidence dir alongside the concurrency report.
  if [ -s "${SCHEMA_EVIDENCE_FILE:-/nonexistent}" ]; then
    cp "$SCHEMA_EVIDENCE_FILE" "$EVIDENCE_DIR/schema.txt"
    assert "schema evidence (SHOW INDEXES/CONSTRAINTS) written to evidence dir" "yes" \
      "$([ -f "$EVIDENCE_DIR/schema.txt" ] && echo yes || echo no)"
    info "schema evidence written to $EVIDENCE_DIR/schema.txt"
  fi
fi

# ==================================================================================================
# Step 5 — regression gate vs the committed baseline (LOCAL fast profile only; structural metrics)
# ==================================================================================================
if [ "$MODE" = local ] && [ "$PROFILE" = "fast" ] && [ -f "$BASELINE" ] && [ -f "$EVIDENCE_DIR/report.json" ]; then
  section "regression gate vs committed baseline (structural metrics)"
  CMP_OUT="$("$CMP_BIN" "$BASELINE" "$EVIDENCE_DIR/report.json" 2>&1)" || true
  printf '%s\n' "$CMP_OUT" | sed 's/^/  /'
  assert "fresh run is within baseline thresholds (structural metrics)" "yes" \
    "$(printf '%s' "$CMP_OUT" | grep -q 'GRAPHUS_BASELINE_OK' && echo yes || echo no)"
elif [ "$MODE" = external ]; then
  info "regression gate skipped (external attach: the host-independent invariant gate ran in measure_target --assert)."
elif [ ! -f "$BASELINE" ]; then
  info "no committed baseline.json yet — skipping the regression gate."
else
  info "regression gate skipped (non-fast profile: not baseline-comparable)."
fi

# ==================================================================================================
# Summary
# ==================================================================================================
section "Result"
printf '%s checks run, %s failures.  (mode: %s)\n' "$CHECKS" "$FAILURES" "$MODE"
if [ -f "$EVIDENCE_DIR/report.json" ]; then
  info "standardized evidence: $EVIDENCE_DIR/{report.json, report.md}"
fi
if [ "$FAILURES" -eq 0 ]; then
  if [ "$MODE" = external ]; then
    printf '%s%sPRODUCT-RECOMMENDATIONS DEMONSTRATION PASSED%s (external attach) — the seeded generator is\n' "$BOLD" "$GREEN" "$RESET"
    printf 'byte-identical, the %s-user / %s-product graph (%s FRIEND, %s PURCHASED) was loaded over\n' "${GEN_USERS:-?}" "${GEN_PRODUCTS:-?}" "${GEN_FRIENDS:-?}" "${GEN_PURCHASED:-?}"
    printf 'Bolt-TCP+TLS into an isolated database, the concurrent read ladder ran against the live\n'
    printf 'instance, and the /metrics before/after delta + client throughput/latency were folded into\n'
    printf 'an external-mode evidence report (the isolated database was dropped on exit).\n'
  else
    printf '%s%sPRODUCT-RECOMMENDATIONS DEMONSTRATION PASSED%s — the seeded generator is byte-identical,\n' "$BOLD" "$GREEN" "$RESET"
    printf 'the %s-user / %s-product graph (%s FRIEND, %s PURCHASED) was network-bulk-loaded over the wire,\n' "${GEN_USERS:-?}" "${GEN_PRODUCTS:-?}" "${GEN_FRIENDS:-?}" "${GEN_PURCHASED:-?}"
    printf 'every recommendation query returned a well-formed result, and the concurrent read ladder\n'
    printf 'produced standardized evidence of the server read-path behaviour under load.\n'
  fi
  exit 0
else
  printf '%s%sPRODUCT-RECOMMENDATIONS DEMONSTRATION FAILED%s — %s assertion(s) did not hold.\n' "$BOLD" "$RED" "$RESET" "$FAILURES"
  exit 1
fi
