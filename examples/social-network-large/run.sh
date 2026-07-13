#!/usr/bin/env bash
#
# Graphus large-scale social-graph demonstration — OVER-THE-WIRE concurrent read scaling.
#
# The model (a multigraph LPG): a social network of (:USER {id, name, registered}) befriended by an
# UNDIRECTED multigraph (:USER)-[:FRIEND {since}]-(:USER), a corpus of (:ARTICLE {id, name,
# registered}) carrying realistic Portuguese headlines, and directed (:USER)-[:LIKE {date}]->(:ARTICLE)
# edges. The FRIEND degree is a configuration model — uniform by default, or a power law (Zipf) that
# produces SUPERNODES via SOCIAL_DEGREE_DIST=zipf.
#
# THE HEADLINE (rmp #691): the 8-query read battery (direct friends, friend-of-friend, mutual friends,
# top-liked articles, degree, headline TEXT search, recent-LIKE range, FULLTEXT headline search) is
# driven OVER THE WIRE by a concurrency ladder of C Bolt clients while the CO-LOCATED SERVER PROCESS is
# sampled from /proc — so the report shows whether reads SCALE ACROSS CORES (the off-thread reader pool)
# or hit a single-thread ceiling. This corrects the previous in-process battery, whose ~1-core figure
# was a DRIVER artifact (it bypassed the server's reader pool entirely).
#
# It runs in TWO modes (auto-detected via the shared external-target seam in `_harness/harness.sh`):
#
#   LOCAL (default)   — self-boots a REAL `graphus-server` exposing Bolt-over-UDS (the read ladder) +
#                       plaintext-loopback REST (the network bulk-import upload path), loads the graph
#                       via REST bulk-import (Mode A) into an isolated database, declares a
#                       version-tolerant read-path schema, drives the concurrency ladder over UDS while
#                       sampling the SERVER's per-thread CPU/RSS from /proc, emits standardized evidence
#                       (report.json with the server-PID scaling curve + real p50/p99 per rung), and
#                       gates the STRUCTURAL counts against the committed baseline.
#   EXTERNAL (attach) — when ANY of GRAPHUS_TARGET_{BOLT,REST,UDS} is set, attaches to an
#                       ALREADY-RUNNING instance (local OR remote) over Bolt-over-TCP + TLS.
#                       It carves out a dedicated, isolated database, loads a SMALL graph over Bolt with
#                       a version-tolerant schema (an older server may lack the modern FULLTEXT/TEXT
#                       DDL — the driver's capability preflight drops any family the target cannot
#                       serve), scrapes the target's `/metrics` before + after the ladder, drives the
#                       SAME read ladder over Bolt-TCP+TLS (/proc sampling OFF — the server-side channel
#                       is /metrics), emits an EXTERNAL-mode report via `measure_target`, and DROPS the
#                       isolated database on exit.
#
# THE DEFAULT RUN IS A READ/WRITE MIX (rmp #714). A production graph workload is never a read-only
# ladder against a FROZEN graph: reads are served WHILE writes commit underneath them, and Graphus's
# entire concurrency story — MVCC snapshot-isolation auto-commit reads that neither abort writers nor
# are aborted by them, the off-thread reader pool (#336/#543), SSI for writers (#171), the GC pin a
# long reader holds (#551) — exists precisely to make that mix work. So every rung of the ladder is
# driven TWICE, back to back, against the same graph:
#
#   arm `readonly` (CONTROL)   — writers OFF. Runs FIRST, warming the buffer pool for the treatment,
#                                which makes the measured cost of the mix a conservative LOWER bound.
#   arm `mixed`    (TREATMENT) — writers ON. THIS is the default and the headline.
#
# The delta between the two arms is THE COST OF THE MIX, and the run ASSERTS the concurrency
# invariants: I1 reads never abort (an auto-commit read runs at Snapshot Isolation); I2 writers commit
# (managed retry, no livelock); I3 readers are not starved; I4 an SSI abort stays retryable (the #612
# detector); I5 a slow reader does not stall the writers (the GC pin, #551); I6 no read ever fails with
# an INTERNAL server error (Neo.DatabaseError.*). SOCIAL_WRITERS=0 restores the pure read-only ladder,
# which stays a legitimate isolation experiment.
#
# I6 CURRENTLY FAILS, and it is meant to: switching the mix on immediately exposed a real server bug,
# filed as rmp #721 — an off-thread reader intermittently cannot locate a record ("Prop/Rel store page
# N not allocated") while a writer GROWS the store, because its location oracle is a snapshot while the
# record content it navigates is live. The writers-off control arm of the very same ladder is clean at
# every rung, which is exactly why a read-only ladder could never have found it.
#
# Usage:
#   examples/social-network-large/run.sh                          # local self-boot, fast profile, MIX ON
#   SOCIAL_WRITERS=0                examples/social-network-large/run.sh   # read-only baseline (the off switch)
#   SOCIAL_PROFILE=large            examples/social-network-large/run.sh   # evidence-scale local run
#   SOCIAL_DEGREE_DIST=zipf         examples/social-network-large/run.sh   # power-law (supernode) FRIEND graph
#   SOCIAL_READER_THREADS=4         examples/social-network-large/run.sh   # pin the reader pool (local)
#   GRAPHUS_TARGET_BOLT=bolt+ssc://host:7687 GRAPHUS_TARGET_REST=https://host:7474 \
#     GRAPHUS_TARGET_USER=graphus GRAPHUS_TARGET_PASSWORD=graphus-local \
#     GRAPHUS_TARGET_TLS_INSECURE=1  examples/social-network-large/run.sh  # attach to a running instance
#
# Mix knobs (both modes, all optional): SOCIAL_WRITERS (default 2), SOCIAL_WRITE_EVERY_MS (default 20),
# SOCIAL_HOT_WRITE_FRACTION (default 0.25 — the share of writes that read-modify-write a TRENDING
# article; this is the shape that lets SSI fire, but MEASURED at the default rate the engine abort rate
# is ~0, so the retry path is armed-but-idle — raise the writers / lower the pacing to exercise it), SOCIAL_HOT_KEYS (default
# 4), SOCIAL_MIX_BASELINE (default 1 — run the readonly CONTROL arm so the cost of the mix is
# measurable), SOCIAL_RETRY_BUDGET_MS (default 15000), SOCIAL_PROBE_SECS (default 3 — the
# slow-reader/GC-pin probe).
#
# Requirements: a Unix host, bash, curl. LOCAL mode's /proc server sampling is Linux-specific (the run
# still works on macOS but the CPU/RSS server evidence is skipped there). No node / openssl needed.

set -euo pipefail

# --------------------------------------------------------------------------------------------------
# Shared external-target seam (GRAPHUS_TARGET_* detection, isolated-DB create/drop, /metrics scrape).
# --------------------------------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../_harness/harness.sh
source "$(cd "$SCRIPT_DIR/../_harness" && pwd)/harness.sh"
export HARNESS_SCENARIO="social-network-large"

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
# Locate (or build) the binaries. The wire client bins build WITHOUT the engine (--features wire) for a
# light, fast client build; the engine is only needed by graphus-server (self-boot, local mode).
# --------------------------------------------------------------------------------------------------
BIN_DIR="${GRAPHUS_BIN_DIR:-$REPO_ROOT/target/release}"
GEN="$BIN_DIR/social_gen"
LOAD="$BIN_DIR/social_wire_load"
BENCH="$BIN_DIR/social_bench"
CMP_BIN="$BIN_DIR/social_baseline_cmp"
SERVER="$BIN_DIR/graphus-server"

PROFILE="${SOCIAL_PROFILE:-fast}"
case "$PROFILE" in
  fast)  LADDER="1,2,4,8";           OPS_PER_RUNG=1500;  POOL_PAGES=8192 ;;
  large) LADDER="1,2,4,8,16,32";     OPS_PER_RUNG=20000; POOL_PAGES=49152 ;;
  huge)  LADDER="1,2,4,8,16,32,64";  OPS_PER_RUNG=40000; POOL_PAGES=131072 ;;
  *) echo "${RED}fatal: unknown SOCIAL_PROFILE '$PROFILE' (use fast|large|huge)${RESET}" >&2; exit 2 ;;
esac
# The profile's ladder is a default, not a cage: the knee diagnosis tells the reader to extend the
# ladder when the top rung is still the best rung, so the ladder (and the per-rung op budget) must be
# overridable to actually follow that advice. SOCIAL_LADDER=1 also isolates per-family latency from
# queueing, which is the only way to tell a slow QUERY apart from a contended one.
LADDER="${SOCIAL_LADDER:-$LADDER}"
OPS_PER_RUNG="${SOCIAL_OPS_PER_RUNG:-$OPS_PER_RUNG}"

# External-mode ladder / op budget (independent of the local profile).
EXT_LADDER="${SOCIAL_EXTERNAL_LADDER:-1,2,4,8}"
EXT_OPS="${SOCIAL_EXTERNAL_OPS:-2000}"
MIN_OPS_PER_CLIENT="${SOCIAL_MIN_OPS_PER_CLIENT:-150}"
AUTO_EXTEND="${SOCIAL_AUTO_EXTEND:-0}"

# --- The read/write MIX — ON BY DEFAULT, in BOTH modes (rmp #714) ---------------------------------
# A modest, production-shaped write rate running underneath the read ladder — a trickle, not a storm.
# SOCIAL_WRITERS=0 is the documented OFF switch that restores the pure read-only ladder.
WRITERS="${SOCIAL_WRITERS:-2}"
WRITE_EVERY_MS="${SOCIAL_WRITE_EVERY_MS:-20}"
HOT_WRITE_FRACTION="${SOCIAL_HOT_WRITE_FRACTION:-0.25}"
HOT_KEYS="${SOCIAL_HOT_KEYS:-4}"
MIX_BASELINE="${SOCIAL_MIX_BASELINE:-1}"
RETRY_BUDGET_MS="${SOCIAL_RETRY_BUDGET_MS:-15000}"
PROBE_SECS="${SOCIAL_PROBE_SECS:-3}"
# The mix flags are IDENTICAL in both modes: the same driver, the same workload shape, whether the
# target is self-booted or attached.
MIX_FLAGS=(
  --writers "$WRITERS"
  --write-every-ms "$WRITE_EVERY_MS"
  --hot-write-fraction "$HOT_WRITE_FRACTION"
  --hot-keys "$HOT_KEYS"
  --mix-baseline "$MIX_BASELINE"
  --retry-budget-ms "$RETRY_BUDGET_MS"
  --probe-secs "$PROBE_SECS"
)
if [ "$WRITERS" -gt 0 ]; then
  info_mix="read/write MIX ON — ${WRITERS} writer(s), one business unit every ${WRITE_EVERY_MS}ms, \
${HOT_WRITE_FRACTION} of them a read-modify-write of ${HOT_KEYS} trending article(s)"
else
  info_mix="read/write mix OFF (SOCIAL_WRITERS=0) — a pure read ladder against a FROZEN graph"
fi

# Build the shared generator argument list (identical for social_gen, social_wire_load, social_bench so
# all three reconstruct the SAME deterministic graph). LOCAL uses the ladder profile; EXTERNAL uses a
# SMALL override set so the whole graph loads quickly over Bolt UNWIND writes even against a small /
# remote / OLDER server (whose planner may SCAN on an UNWIND-row-valued edge anchor).
GEN_ARGS=(--profile "$PROFILE")
if [ "$MODE" = external ]; then
  GEN_ARGS=(
    --profile "${SOCIAL_EXTERNAL_PROFILE:-fast}"
    --users "${SOCIAL_EXTERNAL_USERS:-400}"
    --articles "${SOCIAL_EXTERNAL_ARTICLES:-40}"
    --friend-min "${SOCIAL_EXTERNAL_FRIEND_MIN:-2}"
    --friend-max "${SOCIAL_EXTERNAL_FRIEND_MAX:-8}"
    --avg-likes "${SOCIAL_EXTERNAL_AVG_LIKES:-3}"
  )
fi
# Optional power-law (Zipf) FRIEND-degree mode (supernodes). Applies to both modes.
if [ "${SOCIAL_DEGREE_DIST:-uniform}" = "zipf" ]; then
  GEN_ARGS+=(--degree-dist zipf --zipf-exponent "${SOCIAL_ZIPF_EXPONENT:-2}")
  # A power law wants a low floor + a high ceiling to grow a hub tail (unless already overridden).
  case " ${GEN_ARGS[*]} " in *" --friend-min "*) : ;; *) GEN_ARGS+=(--friend-min 1) ;; esac
  case " ${GEN_ARGS[*]} " in *" --friend-max "*) : ;; *) GEN_ARGS+=(--friend-max 500) ;; esac
fi

# I7 (rmp #744): forward the SAME generation config to social_bench so it can reconstruct the FRIEND
# ground truth and verify a sampled fraction of read replies (degree / friends / mutual) — a server
# serving wrong counts would otherwise pass a run whose reads were pulled and discarded. Translate the
# loader's --profile to the bench's --gen-profile and pass the FRIEND-degree band/dist through; the
# realised --users/--articles the bench already receives are the resolve() overrides. If the config does
# not reconstruct the loaded edge count, the bench declines the oracle and I7 is honestly N/A.
BENCH_ORACLE_ARGS=(--verify-fraction "${SOCIAL_VERIFY_FRACTION:-0.05}")
_ga_i=0
while [ "$_ga_i" -lt "${#GEN_ARGS[@]}" ]; do
  case "${GEN_ARGS[$_ga_i]}" in
    --profile)
      BENCH_ORACLE_ARGS+=(--gen-profile "${GEN_ARGS[$((_ga_i + 1))]}"); _ga_i=$((_ga_i + 2)) ;;
    --friend-min|--friend-max|--avg-likes|--degree-dist|--zipf-exponent)
      BENCH_ORACLE_ARGS+=("${GEN_ARGS[$_ga_i]}" "${GEN_ARGS[$((_ga_i + 1))]}"); _ga_i=$((_ga_i + 2)) ;;
    --users|--articles)
      _ga_i=$((_ga_i + 2)) ;;  # the bench already receives the realised counts explicitly
    *)
      _ga_i=$((_ga_i + 1)) ;;
  esac
done

harness_build "the social-network wire client binaries (release, --features wire, no engine)" \
  --release -p graphus-social-gen --no-default-features --features wire \
  --bin social_gen --bin social_wire_load --bin social_bench --bin social_baseline_cmp
if [ "$MODE" = local ]; then
  harness_build "graphus-server (release)" --release -p graphus-server
fi
for b in "$GEN" "$LOAD" "$BENCH" "$CMP_BIN"; do
  [ -x "$b" ] || { echo "${RED}fatal: required binary not found at $b${RESET}" >&2; exit 2; }
done
[ "$MODE" = local ] && { [ -x "$SERVER" ] || { echo "${RED}fatal: server binary not found at $SERVER${RESET}" >&2; exit 2; }; }

# --------------------------------------------------------------------------------------------------
# Workspace
# --------------------------------------------------------------------------------------------------
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/graphus-social-XXXXXX")"
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
BASELINE="$SCRIPT_DIR/baseline.json"
DATA_DIR="$WORKDIR/gen"
GENDIR2="$WORKDIR/gen2"
SOCKET="$WORKDIR/graphus.sock"
CONFIG="$WORKDIR/graphus.toml"
SERVER_LOG="$WORKDIR/server.log"
STORE_DIR="$WORKDIR/store"
METRICS_BEFORE="$WORKDIR/metrics_before.prom"
METRICS_AFTER="$WORKDIR/metrics_after.prom"
mkdir -p "$EVIDENCE_DIR"

SERVER_PID=""
TARGET_DB=""
cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [ "$MODE" = external ]; then
    harness_target_drop_db >/dev/null 2>&1 || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

ADMIN_USER="social"
ADMIN_PW="social-large-demo-pw-1"
DEFAULT_DB="graphus"
LOCAL_TARGET_DB="socialdb"

# ==================================================================================================
# Step 1 — deterministic generator (byte-identical per seed) — both modes
# ==================================================================================================
section "Step 1 — deterministic social-graph generator (${GEN_ARGS[*]})"
GEN_OUT="$("$GEN" "${GEN_ARGS[@]}" --format csv --out-dir "$DATA_DIR")"
printf '%s\n' "$GEN_OUT" | sed 's/^/  /'
for f in users.csv articles.csv friends.csv likes.csv; do
  assert "$f generated" "yes" "$([ -s "$DATA_DIR/$f" ] && echo yes || echo no)"
done
"$GEN" "${GEN_ARGS[@]}" --format csv --out-dir "$GENDIR2" >/dev/null
if diff -q "$DATA_DIR/users.csv" "$GENDIR2/users.csv" >/dev/null \
   && diff -q "$DATA_DIR/friends.csv" "$GENDIR2/friends.csv" >/dev/null; then
  assert "generator is byte-identical per seed" "yes" "yes"
else
  assert "generator is byte-identical per seed" "yes" "no"
fi
rm -rf "$GENDIR2"

SEED="$(kv "$GEN_OUT" seed)"
GEN_USERS="$(kv "$GEN_OUT" users)"
GEN_ARTICLES="$(kv "$GEN_OUT" articles)"
GEN_FRIENDS="$(kv "$GEN_OUT" friend_edges)"
GEN_LIKES="$(kv "$GEN_OUT" like_edges)"
DEG_DIST="$(kv "$GEN_OUT" degree_dist)"
DEG_MIN="$(kv "$GEN_OUT" degree_min)"
DEG_MAX="$(kv "$GEN_OUT" degree_max)"
DEG_HIST="$(kv "$GEN_OUT" degree_hist)"
NODE_COUNT=$(( ${GEN_USERS:-0} + ${GEN_ARTICLES:-0} ))
REL_COUNT=$(( ${GEN_FRIENDS:-0} + ${GEN_LIKES:-0} ))
info "graph: $GEN_USERS USER, $GEN_ARTICLES ARTICLE, $GEN_FRIENDS FRIEND, $GEN_LIKES LIKE  (degree_dist=$DEG_DIST)"
info "realised FRIEND-degree band [$DEG_MIN, $DEG_MAX], log2 histogram: $DEG_HIST"
if [ "$DEG_DIST" = "uniform" ]; then
  info "(set SOCIAL_DEGREE_DIST=zipf for a power-law FRIEND graph with supernodes)"
else
  # A power-law run must have grown a supernode tail — max degree well above the band midpoint.
  assert "power-law grew a supernode (max degree >= 32)" "yes" \
    "$([ "${DEG_MAX:-0}" -ge 32 ] 2>/dev/null && echo yes || echo no)"
fi

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
  free_port() {
    if command -v python3 >/dev/null 2>&1; then
      python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
    else
      echo 47475
    fi
  }
  REST_PORT="$(free_port)"
  REST_ADDR="127.0.0.1:$REST_PORT"
  TARGET_DB="$LOCAL_TARGET_DB"
  cat > "$CONFIG" <<EOF
# Generated by examples/social-network-large/run.sh — a UDS+REST dev configuration.
store_path = "$STORE_DIR"
default_database = "$DEFAULT_DB"
buffer_pool_pages = $POOL_PAGES
uds_path = "$SOCKET"
rest_addr = "$REST_ADDR"
jwt_secret = "graphus-social-network-large-example-uds-rest-secret-32+"
# Plaintext loopback REST (dev/test only) so the network bulk-import upload needs no TLS/cert.
allow_insecure_network = true

[auth]
admin_user = "$ADMIN_USER"
admin_password = "$ADMIN_PW"
admin_uid = $(id -u)
EOF
  if [ -n "${SOCIAL_READER_THREADS:-}" ]; then
    printf '\n[admission]\nreader_threads = %s\n' "$SOCIAL_READER_THREADS" >> "$CONFIG"
    info "reader pool pinned to $SOCIAL_READER_THREADS thread(s)"
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
# Step 3 — load the graph over the wire + version-tolerant schema + round-tripped-count asserts
# ==================================================================================================
LOAD_LOG="$WORKDIR/load.log"
if [ "$MODE" = external ]; then
  section "Step 3 — load the graph over Bolt (version-tolerant UNWIND) + round-tripped counts"
  info "loading over Bolt into '$TARGET_DB'; on a small/remote box this can take a while…"
  set +e
  "$LOAD" --bolt "$BOLT_URI" --db "$TARGET_DB" --data-dir "$DATA_DIR" \
    --user "$DRIVER_USER" --password "$DRIVER_PW" "${GEN_ARGS[@]}" 2>&1 | tee "$LOAD_LOG" | sed 's/^/  /'
  set -e
else
  section "Step 3 — network bulk-import (Mode A) + version-tolerant schema + round-tripped counts"
  set +e
  "$LOAD" --rest "$REST_ADDR" --default-db "$DEFAULT_DB" --db "$TARGET_DB" --data-dir "$DATA_DIR" \
    --user "$ADMIN_USER" --password "$ADMIN_PW" "${GEN_ARGS[@]}" 2>&1 | tee "$LOAD_LOG" | sed 's/^/  /'
  set -e
fi
assert "graph loaded + every battery family well-formed (round-tripped counts asserted)" "yes" \
  "$(grep -q 'GRAPHUS_SOCIAL_LOAD_OK' "$LOAD_LOG" && echo yes || echo no)"
if ! grep -q 'GRAPHUS_SOCIAL_LOAD_OK' "$LOAD_LOG"; then
  echo "${RED}load failed; aborting the concurrency ladder.${RESET}" >&2
  exit 1
fi

# ==================================================================================================
# Step 4 — the over-the-wire concurrent read LADDER + evidence
# ==================================================================================================
if [ "$MODE" = external ]; then
  section "Step 4 — concurrent read/write MIX ladder over Bolt-TCP+TLS (attach) + /metrics evidence"
  info "$info_mix"
  rm -f "$EVIDENCE_DIR/report.json" "$EVIDENCE_DIR/report.md"
  harness_scrape_metrics "$METRICS_BEFORE" || info "metrics-before scrape failed (non-fatal)"
  assert "/metrics scraped before the ladder" "yes" "$([ -s "$METRICS_BEFORE" ] && echo yes || echo no)"

  AUTO_FLAG=(); [ "$AUTO_EXTEND" = "1" ] && AUTO_FLAG=(--auto-extend)
  BENCH_LOG="$WORKDIR/bench.log"
  # Bracket the ladder so total_millis is the RUN's wall-time (rmp #699): measure_target runs AFTER it
  # and cannot time it, so an unbracketed report timed only its own emission (this attach path was
  # still missing the bracket, so its total_millis was the emitter's microseconds, not the workload's).
  LADDER_START_MS="$(_harness_now_ms)"
  set +e
  "$BENCH" --bolt "$BOLT_URI" --user "$DRIVER_USER" --password "$DRIVER_PW" --db "$TARGET_DB" \
    --ladder "$EXT_LADDER" --ops-per-rung "$EXT_OPS" --min-ops-per-client "$MIN_OPS_PER_CLIENT" \
    "${MIX_FLAGS[@]}" "${AUTO_FLAG[@]}" "${BENCH_ORACLE_ARGS[@]}" \
    --users "$GEN_USERS" --articles "$GEN_ARTICLES" --friends "$GEN_FRIENDS" --likes "$GEN_LIKES" \
    --seed "$SEED" --scenario "social-network-large" 2>&1 | tee "$BENCH_LOG" | sed 's/^/  /'
  BENCH_STATUS="${PIPESTATUS[0]}"
  set -e
  LADDER_MS=$(( $(_harness_now_ms) - LADDER_START_MS ))
  # The driver exits non-zero when a concurrency INVARIANT was violated (I1..I5) or the reader error
  # rate breached its threshold. That is the whole point of asserting them, so it must fail the run.
  assert "every concurrency invariant held (I1..I7, incl. read-result correctness)" "0" "$BENCH_STATUS"

  harness_scrape_metrics "$METRICS_AFTER" || info "metrics-after scrape failed (non-fatal)"
  assert "/metrics scraped after the ladder" "yes" "$([ -s "$METRICS_AFTER" ] && echo yes || echo no)"

  BENCH_STATS="$(sed -n 's/^GRAPHUS_SOCIAL_BENCH_STATS //p' "$BENCH_LOG" | head -n1)"
  assert "client-side stats sentinel produced" "yes" "$([ -n "$BENCH_STATS" ] && echo yes || echo no)"
  BEST_CLIENTS="$(kv "$BENCH_STATS" best_clients)"
  BEST_OPS_PER_SEC="$(kv "$BENCH_STATS" best_ops_per_sec)"
  BEST_OPS="$(kv "$BENCH_STATS" best_ops)"
  BEST_SECS="$(kv "$BENCH_STATS" best_secs)"
  P50_MS="$(kv "$BENCH_STATS" p50_ms)"
  P99_MS="$(kv "$BENCH_STATS" p99_ms)"
  P999_MS="$(kv "$BENCH_STATS" p999_ms)"
  # The READ vector's abort rate — a MEASURED 0.0 (an auto-commit read runs at Snapshot Isolation and
  # cannot abort: invariant I1). It is NOT the writers' rate, and the two are never merged (rmp #714).
  ABORT_RATE="$(kv "$BENCH_STATS" abort_rate)"
  HEADLINE_ARM="$(kv "$BENCH_STATS" arm)"
  INVARIANTS_OK="$(kv "$BENCH_STATS" invariants_ok)"

  # --- The WRITE vector, kept STRUCTURALLY APART from the read vector above (rmp #714/#715) --------
  # ENGINE layer (what contention the engine actually saw) and APPLICATION layer (what the business
  # units achieved). `na` means NOT MEASURED — the driver never renders an unmeasured figure as 0.
  W_ATTEMPTS="$(kv "$BENCH_STATS" write_attempts)"
  W_ABORTS="$(kv "$BENCH_STATS" write_aborts)"
  W_ENGINE_ABORT_RATE="$(kv "$BENCH_STATS" engine_abort_rate)"
  W_UNITS="$(kv "$BENCH_STATS" write_units)"
  W_COMMITTED="$(kv "$BENCH_STATS" write_committed)"
  W_COMMIT_RATE="$(kv "$BENCH_STATS" write_commit_rate)"
  W_RETRIES_PER_COMMIT="$(kv "$BENCH_STATS" write_retries_per_commit)"
  W_MAX_RETRIES="$(kv "$BENCH_STATS" write_max_retries)"
  W_EXHAUSTED="$(kv "$BENCH_STATS" write_exhausted)"
  W_OTHER_ERRORS="$(kv "$BENCH_STATS" write_other_errors)"
  W_P50_MS="$(kv "$BENCH_STATS" write_p50_ms)"
  W_P99_MS="$(kv "$BENCH_STATS" write_p99_ms)"
  W_P999_MS="$(kv "$BENCH_STATS" write_p999_ms)"
  W_OPS_PER_SEC="$(kv "$BENCH_STATS" write_ops_per_sec)"
  # THE COST OF THE MIX: the mixed arm's best rung against its own writers-off control rung.
  CONTROL_BEST_OPS="$(kv "$BENCH_STATS" control_best_ops_per_sec)"
  MIX_COST_PCT="$(kv "$BENCH_STATS" mix_cost_read_ops_pct)"

  # Only forward a write/mix param when it was actually MEASURED. `na` = absent, and an absent vector
  # must stay ABSENT from the report rather than be zero-filled (report schema v3, rmp #711).
  MIX_PARAMS=()
  add_measured_param() {   # add_measured_param <key> <value>
    [ -n "$2" ] && [ "$2" != "na" ] && MIX_PARAMS+=(--param "$1=$2")
    return 0
  }
  add_measured_param "headline_arm"             "$HEADLINE_ARM"
  add_measured_param "writer_mode"              "$([ "$WRITERS" -gt 0 ] && echo managed-retry || echo none)"
  add_measured_param "write_every_ms"           "$WRITE_EVERY_MS"
  add_measured_param "hot_write_fraction"       "$HOT_WRITE_FRACTION"
  add_measured_param "hot_keys"                 "$HOT_KEYS"
  add_measured_param "write_retry_budget_ms"    "$RETRY_BUDGET_MS"
  add_measured_param "engine_txn_attempts"      "$W_ATTEMPTS"
  add_measured_param "engine_txn_aborts"        "$W_ABORTS"
  add_measured_param "engine_abort_rate"        "$W_ENGINE_ABORT_RATE"
  add_measured_param "write_units"              "$W_UNITS"
  add_measured_param "write_committed"          "$W_COMMITTED"
  add_measured_param "write_commit_rate"        "$W_COMMIT_RATE"
  add_measured_param "write_retries_per_commit" "$W_RETRIES_PER_COMMIT"
  add_measured_param "write_max_retries"        "$W_MAX_RETRIES"
  add_measured_param "write_retry_budget_exhausted" "$W_EXHAUSTED"
  add_measured_param "write_other_errors"       "$W_OTHER_ERRORS"
  add_measured_param "write_p50_ms"             "$W_P50_MS"
  add_measured_param "write_p99_ms"             "$W_P99_MS"
  add_measured_param "write_p999_ms"            "$W_P999_MS"
  add_measured_param "write_ops_per_sec"        "$W_OPS_PER_SEC"
  add_measured_param "control_best_ops_per_sec" "$CONTROL_BEST_OPS"
  add_measured_param "mixed_best_ops_per_sec"   "$BEST_OPS_PER_SEC"
  add_measured_param "mix_cost_read_ops_pct"    "$MIX_COST_PCT"
  add_measured_param "concurrency_invariants_ok" "$INVARIANTS_OK"

  RUNG_NOTES=()
  while IFS= read -r line; do
    [ -n "$line" ] && RUNG_NOTES+=(--note "$line")
  done < <(grep '^GRAPHUS_SOCIAL_BENCH_RUNG ' "$BENCH_LOG" || true)
  while IFS= read -r line; do
    [ -n "$line" ] && RUNG_NOTES+=(--note "INVARIANT $line")
  done < <(grep -E '^(PASS|FAIL) I[0-9]' "$BENCH_LOG" || true)
  VERDICT_LINE="$(grep 'CLIENT-SIDE VERDICT' "$BENCH_LOG" | head -n1 || true)"
  [ -n "$VERDICT_LINE" ] && RUNG_NOTES+=(--note "$VERDICT_LINE")

  MEASURE_BIN="$BIN_DIR/measure_target"
  if [ ! -x "$MEASURE_BIN" ]; then
    info "building the dev-only measure_target harness binary…"
    ( cd "$REPO_ROOT" && cargo build -q -p graphus-examples-harness --bin measure_target ) || true
    MEASURE_BIN="$REPO_ROOT/target/debug/measure_target"
  fi
  if [ -x "$MEASURE_BIN" ] && [ -s "$METRICS_BEFORE" ] && [ -s "$METRICS_AFTER" ] && [ -n "$BENCH_STATS" ]; then
    "$MEASURE_BIN" \
      --evidence-dir "$EVIDENCE_DIR" --scenario "social-network-large" \
      --description "large social network: concurrent read scaling under a production-shaped read/write MIX over Bolt-TCP+TLS (attach mode)" \
      --database "$TARGET_DB" \
      --metrics-before "$METRICS_BEFORE" --metrics-after "$METRICS_AFTER" \
      --nodes "$NODE_COUNT" --rels "$REL_COUNT" \
      --total-millis "$LADDER_MS" \
      --workload-ops "${BEST_OPS:-0}" --workload-secs "${BEST_SECS:-1}" \
      --p50-ms "${P50_MS:-0}" --p99-ms "${P99_MS:-0}" --p999-ms "${P999_MS:-0}" \
      --abort-rate "${ABORT_RATE:-0}" \
      --param "connection=bolt-tcp-tls" --param "target=$BOLT_URI" --param "scenario_db=$TARGET_DB" \
      --param "ladder=$EXT_LADDER" --param "ops_per_rung=$EXT_OPS" \
      --param "min_ops_per_client=$MIN_OPS_PER_CLIENT" --param "writers=$WRITERS" \
      --param "degree_dist=$DEG_DIST" --param "degree_hist=$DEG_HIST" \
      --param "best_clients=${BEST_CLIENTS:-?}" --param "best_ops_per_sec=${BEST_OPS_PER_SEC:-?}" \
      --param "user_count=$GEN_USERS" --param "article_count=$GEN_ARTICLES" \
      --param "friend_count=$GEN_FRIENDS" --param "like_count=$GEN_LIKES" \
      --param "node_count=$NODE_COUNT" --param "relationship_count=$REL_COUNT" \
      "${MIX_PARAMS[@]}" \
      "${RUNG_NOTES[@]}" \
      --note "Client throughput/latency are measured by social_bench over Bolt-TCP+TLS; the server-side channel is the /metrics before/after delta (no /proc — remote/attached instance)." \
      --note "TWO LAYERS OF TRUTH, never conflated (rmp #714/#715). READ: throughput.* is ONE coherent set — the reads of the best '${HEADLINE_ARM:-?}' rung (C=${BEST_CLIENTS:-?}) at ${BEST_OPS_PER_SEC:-?} ops/s, and throughput.abort_rate=${ABORT_RATE:-?} is the READ abort rate. It is a MEASURED zero, not a placeholder: a standalone auto-commit read runs at SNAPSHOT ISOLATION (rmp #543/#545), so it can neither abort a writer nor be aborted by one (invariant I1). WRITE: the writers' evidence lives in metadata.workload, split into the ENGINE layer (engine_txn_attempts/engine_txn_aborts/engine_abort_rate) and the APPLICATION layer (write_units/write_committed/write_commit_rate). A high engine abort rate WITH a full application commit rate is a HEALTHY system under contention: the cost is LATENCY (write_p99_ms, which is retry-inclusive), not lost work." \
      --note "THE COST OF THE MIX: the mixed arm's best rung ran at ${BEST_OPS_PER_SEC:-?} ops/s against its writers-off CONTROL rung's ${CONTROL_BEST_OPS:-na} ops/s (delta ${MIX_COST_PCT:-na}%). The control arm runs FIRST at every rung, warming the buffer pool for the treatment, so this cost is a conservative LOWER bound. A read-only ladder against a frozen graph structurally cannot produce this figure." \
      --assert \
      && info "external evidence written to $EVIDENCE_DIR" \
      || { info "measure_target reported an invariant violation or error"; FAILURES=$((FAILURES + 1)); }
    assert "external report.json produced (measurement_mode=external)" "yes" \
      "$([ -f "$EVIDENCE_DIR/report.json" ] && grep -q '"measurement_mode": *"external"' "$EVIDENCE_DIR/report.json" && echo yes || echo no)"
    assert "report.json carries server_metrics deltas" "yes" \
      "$([ -f "$EVIDENCE_DIR/report.json" ] && grep -q '"server_metrics"' "$EVIDENCE_DIR/report.json" && echo yes || echo no)"
    if [ "$WRITERS" -gt 0 ]; then
      assert "the attach run drove readers AND writers against the same graph" "yes" \
        "$([ -n "$W_COMMITTED" ] && [ "$W_COMMITTED" != "na" ] && [ "${W_COMMITTED:-0}" -gt 0 ] && echo yes || echo no)"
      assert "the report separates the READ and WRITE vectors" "yes" \
        "$([ -f "$EVIDENCE_DIR/report.json" ] && grep -q '"engine_abort_rate"' "$EVIDENCE_DIR/report.json" \
           && grep -q '"write_commit_rate"' "$EVIDENCE_DIR/report.json" && echo yes || echo no)"
      assert "the report carries the COST OF THE MIX vs the read-only baseline" "yes" \
        "$([ -f "$EVIDENCE_DIR/report.json" ] && grep -q '"mix_cost_read_ops_pct"' "$EVIDENCE_DIR/report.json" && echo yes || echo no)"
    fi
  else
    info "measure_target unavailable or metrics missing; skipping evidence collection (non-fatal)"
    FAILURES=$((FAILURES + 1))
  fi
else
  section "Step 4 — concurrent read/write MIX ladder (many simultaneous UDS-Bolt connections, server-PID sampled)"
  info "$info_mix"
  rm -f "$EVIDENCE_DIR/report.json" "$EVIDENCE_DIR/report.md"
  # The logical size of the graph (the generator's CSV bytes) anchors the space-amplification ratio:
  # how many durable bytes (store + WAL) the engine holds per logical byte of graph.
  LOGICAL_BYTES=0
  for f in users.csv articles.csv friends.csv likes.csv; do
    LOGICAL_BYTES=$((LOGICAL_BYTES + $(wc -c < "$DATA_DIR/$f")))
  done
  set +e
  BENCH_OUT="$("$BENCH" --socket "$SOCKET" --user "$ADMIN_USER" --password "$ADMIN_PW" --db "$TARGET_DB" \
    --server-pid "$SERVER_PID" --store-path "$STORE_DIR" --logical-bytes "$LOGICAL_BYTES" \
    --ladder "$LADDER" --ops-per-rung "$OPS_PER_RUNG" --min-ops-per-client "$MIN_OPS_PER_CLIENT" \
    "${MIX_FLAGS[@]}" "${BENCH_ORACLE_ARGS[@]}" \
    --users "$GEN_USERS" --articles "$GEN_ARTICLES" --friends "$GEN_FRIENDS" --likes "$GEN_LIKES" \
    --seed "$SEED" --scenario "social-network-large" --evidence-dir "$EVIDENCE_DIR" 2>&1)"
  BENCH_STATUS=$?
  set -e
  printf '%s\n' "$BENCH_OUT" | sed 's/^/  /'
  # The driver exits non-zero when a concurrency INVARIANT was violated (I1..I5) or the reader error
  # rate breached its threshold. Swallowing that status (as this did) makes the assertions decorative.
  assert "every concurrency invariant held (I1..I7, incl. read-result correctness)" "0" "$BENCH_STATUS"
  assert "evidence report.json was produced" "yes" \
    "$([ -f "$EVIDENCE_DIR/report.json" ] && echo yes || echo no)"
  assert "evidence report.md was produced" "yes" \
    "$([ -f "$EVIDENCE_DIR/report.md" ] && echo yes || echo no)"

  # --- The MIX is the point of the default run (rmp #714) ------------------------------------------
  if [ "$WRITERS" -gt 0 ]; then
    BENCH_STATS="$(printf '%s' "$BENCH_OUT" | sed -n 's/^GRAPHUS_SOCIAL_BENCH_STATS //p' | head -n1)"
    W_COMMITTED="$(kv "$BENCH_STATS" write_committed)"
    W_COMMIT_RATE="$(kv "$BENCH_STATS" write_commit_rate)"
    W_ENGINE_ABORT_RATE="$(kv "$BENCH_STATS" engine_abort_rate)"
    MIX_COST_PCT="$(kv "$BENCH_STATS" mix_cost_read_ops_pct)"
    assert "the default run drove readers AND writers against the same graph" "yes" \
      "$([ -n "$W_COMMITTED" ] && [ "$W_COMMITTED" != "na" ] && [ "${W_COMMITTED:-0}" -gt 0 ] && echo yes || echo no)"
    assert "every business unit COMMITTED (managed retry; no livelock)" "1.000000" "${W_COMMIT_RATE:-na}"
    assert "the report separates the READ and WRITE vectors" "yes" \
      "$([ -f "$EVIDENCE_DIR/report.json" ] && grep -q '"engine_abort_rate"' "$EVIDENCE_DIR/report.json" \
         && grep -q '"write_commit_rate"' "$EVIDENCE_DIR/report.json" && echo yes || echo no)"
    assert "the report carries the COST OF THE MIX vs the read-only baseline" "yes" \
      "$([ -f "$EVIDENCE_DIR/report.json" ] && grep -q '"mix_cost_read_ops_pct"' "$EVIDENCE_DIR/report.json" && echo yes || echo no)"
    info "cost of the mix at the best rung: ${MIX_COST_PCT:-na}% read throughput vs the writers-off control"
    info "engine abort rate ${W_ENGINE_ABORT_RATE:-na} (SSI contention) with an application commit rate of ${W_COMMIT_RATE:-na}"
  fi
fi

# ==================================================================================================
# Step 5 — regression gate vs the committed baseline (LOCAL fast profile only; structural counts)
# ==================================================================================================
if [ "$MODE" = local ] && [ "$PROFILE" = "fast" ] && [ "$WRITERS" -eq 0 ]; then
  # The committed baseline was captured from the DEFAULT run, which is the MIX. SOCIAL_WRITERS=0 is a
  # different workload (a read-only ladder against a frozen graph), so diffing it against the mixed
  # baseline would be a red gate that means nothing — the same family of lie as a green gate that
  # cannot fire. Skip it, and say why.
  section "regression gate vs committed baseline (structural counts)"
  info "SKIPPED: SOCIAL_WRITERS=0 is the read-only ISOLATION experiment, not the default workload the"
  info "baseline was captured from (the mix). Comparing them would gate one workload against another."
elif [ "$MODE" = local ] && [ "$PROFILE" = "fast" ] && [ "${SOCIAL_DEGREE_DIST:-uniform}" = "uniform" ] \
   && [ -f "$BASELINE" ] && [ -f "$EVIDENCE_DIR/report.json" ]; then
  section "regression gate vs committed baseline (structural counts)"
  CMP_OUT="$("$CMP_BIN" "$BASELINE" "$EVIDENCE_DIR/report.json" 2>&1)" || true
  printf '%s\n' "$CMP_OUT" | sed 's/^/  /'
  assert "fresh run is within baseline thresholds (structural counts)" "yes" \
    "$(printf '%s' "$CMP_OUT" | grep -q 'GRAPHUS_BASELINE_OK' && echo yes || echo no)"
elif [ "$MODE" = external ]; then
  info "regression gate skipped (external attach: the host-independent invariant gate ran in measure_target --assert)."
elif [ "${SOCIAL_DEGREE_DIST:-uniform}" != "uniform" ]; then
  info "regression gate skipped (power-law graph: not baseline-comparable to the committed uniform baseline)."
elif [ ! -f "$BASELINE" ]; then
  info "no committed baseline.json yet — skipping the regression gate."
else
  info "regression gate skipped (non-fast profile: not baseline-comparable)."
fi

# ==================================================================================================
# Summary
# ==================================================================================================
section "Result"
printf '%s checks run, %s failures.  (mode: %s, degree_dist: %s)\n' "$CHECKS" "$FAILURES" "$MODE" "$DEG_DIST"
if [ -f "$EVIDENCE_DIR/report.json" ]; then
  info "standardized evidence: $EVIDENCE_DIR/{report.json, report.md}"
fi
if [ "$FAILURES" -eq 0 ]; then
  if [ "$MODE" = external ]; then
    printf '%s%sSOCIAL-NETWORK-LARGE DEMONSTRATION PASSED%s (external attach) — the seeded generator is\n' "$BOLD" "$GREEN" "$RESET"
    printf 'byte-identical, the %s-USER / %s-ARTICLE graph (%s FRIEND, %s LIKE) was loaded over Bolt-TCP+TLS\n' "${GEN_USERS:-?}" "${GEN_ARTICLES:-?}" "${GEN_FRIENDS:-?}" "${GEN_LIKES:-?}"
    printf 'into an isolated database, the concurrent read ladder ran against the live instance over the\n'
    printf 'wire, and the /metrics before/after delta + client throughput/latency were folded into an\n'
    printf 'external-mode evidence report (the isolated database was dropped on exit).\n'
  else
    printf '%s%sSOCIAL-NETWORK-LARGE DEMONSTRATION PASSED%s — the seeded generator is byte-identical, the\n' "$BOLD" "$GREEN" "$RESET"
    printf '%s-USER / %s-ARTICLE graph (%s FRIEND, %s LIKE) was network-bulk-loaded over the wire, every\n' "${GEN_USERS:-?}" "${GEN_ARTICLES:-?}" "${GEN_FRIENDS:-?}" "${GEN_LIKES:-?}"
    printf 'battery family returned a well-formed result, and the concurrent read ladder produced\n'
    printf 'standardized evidence of the SERVER read-path core-scaling under load (server-PID sampled).\n'
  fi
  exit 0
else
  printf '%s%sSOCIAL-NETWORK-LARGE DEMONSTRATION FAILED%s — %s assertion(s) did not hold.\n' "$BOLD" "$RED" "$RESET" "$FAILURES"
  exit 1
fi
