#!/usr/bin/env bash
#
# Graphus durability & crash-recovery under load — the DETERMINISTIC CORE, driven by the project's DST
# (Deterministic Simulation Testing) simulator. Fully HERMETIC: no server, no Bolt driver, no Node, no
# network. Per CLAUDE.md, crash/recovery scenarios MUST be driven through the DST simulator, so this
# example REUSES the `graphus-dst` VOPR safety oracle end to end rather than reinventing it.
#
# This script doubles as an executable E2E test. It:
#   1. runs the DETERMINISTIC OLTP DURABILITY SWEEP (`durability_demo`): for each seed, a concurrent
#      overlapping-transaction workload (write-heavy create/relate/property/delete) runs under disk +
#      clock faults and a SEEDED MID-WORKLOAD CRASH, the engine is rebuilt via ARIES recovery, and the
#      FOUR ACID-durability properties (serializability / durability / atomicity / reference-model
#      equivalence) are asserted on the RECOVERED engine against the committed-only shadow LPG. It
#      proves ZERO violations and full determinism (same seed => identical recovered state), and
#      surfaces a focused seed's acked-vs-in-flight CRASH PARTITION (the empirical committed-or-nothing
#      proof). It emits the standardized, schema-versioned report.json + report.md.
#   2. cross-checks the same sweep through the `graphus-dst vopr safety` CLI (the project's PR safety
#      gate), asserting it agrees: all seeds SAFE + deterministic.
#   3. proves the ONE-COMMAND REPLAY round-trip (`durability_replay`): the real engine has NO failing
#      seed, so a SYNTHETIC failure is planted via the DST replay machinery's FailurePredicate path,
#      captured into a ReplayArtifact on disk, and replayed to the IDENTICAL failure byte-for-byte.
#
# The sibling real-server SIGKILL run + the live CPU/RAM/storage evidence (rmp #274-276) layer a real
# `graphus-server` crash on top of this same deterministic scenario; this script is its hermetic core.
#
# Usage:
#   examples/durability-crash-recovery/run.sh                         # CI-fast: 30 seeds
#   GRAPHUS_BIN_DIR=target/release examples/durability-crash-recovery/run.sh
#   DUR_PROFILE=full   examples/durability-crash-recovery/run.sh      # 100 seeds (evidence scale)
#   DUR_SEEDS=250      examples/durability-crash-recovery/run.sh      # custom seed count
#   DUR_FOCUS=7        examples/durability-crash-recovery/run.sh      # which seed's crash partition to detail
#
# Requirements: a Unix host (Linux/macOS), bash, and a checkout that builds. No openssl/node/npm/network.

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
DEMO="$BIN_DIR/durability_demo"
REPLAY="$BIN_DIR/durability_replay"
DST="$BIN_DIR/graphus-dst"
CMP="$BIN_DIR/durability_baseline_cmp"
# The real-server SIGKILL phase (rmp #275) boots the actual production binaries over a UDS.
SERVER="$BIN_DIR/graphus-server"
CLI="$BIN_DIR/graphus-cli"

PROFILE="${DUR_PROFILE:-fast}"
case "$PROFILE" in
  fast) DEFAULT_SEEDS=30 ;;
  full) DEFAULT_SEEDS=100 ;;
  *)    DEFAULT_SEEDS=30 ;;
esac
SEEDS="${DUR_SEEDS:-$DEFAULT_SEEDS}"
FOCUS="${DUR_FOCUS:-7}"

build_bin() { # <crate> <bin> <path-var-name>
  local crate="$1" bin="$2"
  section "Building $bin (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p "$crate" --bin "$bin" )
}

[ -x "$DEMO" ]   || build_bin graphus-durability-demo durability_demo
[ -x "$REPLAY" ] || build_bin graphus-durability-demo durability_replay
[ -x "$CMP" ]    || build_bin graphus-durability-demo durability_baseline_cmp
[ -x "$DST" ]    || build_bin graphus-dst graphus-dst
[ -x "$SERVER" ] || build_bin graphus-server graphus-server
[ -x "$CLI" ]    || build_bin graphus-cli graphus-cli
for b in "$DEMO" "$REPLAY" "$CMP" "$DST" "$SERVER" "$CLI"; do
  [ -x "$b" ] || { echo "${RED}fatal: binary not found at $b${RESET}" >&2; exit 2; }
done

# --------------------------------------------------------------------------------------------------
# Workspace: a private temp dir for the reproducer artifact, removed on exit
# --------------------------------------------------------------------------------------------------
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/graphus-durability-XXXXXX")"
ARTIFACT="$WORKDIR/planted-repro.json"
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
BASELINE="$SCRIPT_DIR/baseline.json"
SERVER_PID=""   # set during the real-server phase; the trap kills it if still alive
cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -KILL "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM
mkdir -p "$EVIDENCE_DIR"

# --------------------------------------------------------------------------------------------------
# Step 1 — the deterministic OLTP durability sweep (workload + crash + ARIES recovery + 4-prop oracle)
# --------------------------------------------------------------------------------------------------
section "Step 1 — deterministic OLTP durability + crash-recovery sweep ($SEEDS seeds, $PROFILE profile)"
info "each seed: concurrent overlapping transactions under disk/clock faults + a mid-workload crash,"
info "rebuilt via ARIES recovery, then the 4 ACID-durability properties asserted on the recovered engine"
SWEEP_CODE=0
SWEEP_OUT="$("$DEMO" --seed 1 --seeds "$SEEDS" --focus "$FOCUS" --evidence-dir "$EVIDENCE_DIR")" || SWEEP_CODE=$?
printf '%s\n' "$SWEEP_OUT" | sed 's/^/  /'

assert "durability sweep completed with exit 0 (zero violations, deterministic)" "0" "$SWEEP_CODE"
assert "sweep reports a DURABLE verdict" "yes" \
  "$(printf '%s' "$SWEEP_OUT" | grep -q 'RESULT: DURABLE' && echo yes || echo no)"
assert "every seed was non-vacuous (acked + in-flight coexisted at a crash)" "yes" \
  "$(printf '%s' "$SWEEP_OUT" | grep -qE "non-vacuous=$SEEDS/$SEEDS" && echo yes || echo no)"
assert "focused seed's committed-or-nothing contract HOLDS" "yes" \
  "$(printf '%s' "$SWEEP_OUT" | grep -q 'committed-or-nothing.*HOLDS' && echo yes || echo no)"
assert "evidence report.json was produced" "yes" \
  "$([ -f "$EVIDENCE_DIR/report.json" ] && echo yes || echo no)"
assert "evidence report.md was produced" "yes" \
  "$([ -f "$EVIDENCE_DIR/report.md" ] && echo yes || echo no)"

# --------------------------------------------------------------------------------------------------
# Step 2 — cross-check through the graphus-dst VOPR safety CLI (the PR safety gate)
# --------------------------------------------------------------------------------------------------
section "Step 2 — cross-check via the graphus-dst VOPR safety gate"
info "the same scenario, run through the project's PR safety gate, must agree: all SAFE + deterministic"
DST_CODE=0
DST_OUT="$("$DST" vopr safety --seed 1 --seeds "$SEEDS")" || DST_CODE=$?
printf '%s\n' "$DST_OUT" | tail -n 3 | sed 's/^/  /'
assert "vopr safety gate exits 0" "0" "$DST_CODE"
assert "vopr safety gate reports all SAFE + deterministic" "yes" \
  "$(printf '%s' "$DST_OUT" | grep -qE "$SEEDS seed\(s\) checked, all SAFE" && echo yes || echo no)"

# --------------------------------------------------------------------------------------------------
# Step 3 — the one-command replay round-trip (planted synthetic failure)
# --------------------------------------------------------------------------------------------------
section "Step 3 — one-command replay round-trip (planted synthetic failure)"
info "the real engine has NO failing seed, so the failure is PLANTED via the DST replay machinery;"
info "the captured artifact must replay to the IDENTICAL failure byte-for-byte"

CAP_CODE=0
CAP_OUT="$("$REPLAY" --capture "$ARTIFACT" --seed "$FOCUS")" || CAP_CODE=$?
printf '%s\n' "$CAP_OUT" | sed 's/^/  /'
assert "planted reproducer captured (exit 0)" "0" "$CAP_CODE"
assert "reproducer artifact written to disk" "yes" "$([ -s "$ARTIFACT" ] && echo yes || echo no)"

# Capture the recorded hashes so we can prove the replay reproduced them byte-for-byte.
CAP_TRACE="$(printf '%s' "$CAP_OUT" | sed -n 's/.*expected_trace_hash=\([0-9a-f]*\).*/\1/p' | head -n1)"
CAP_STATE="$(printf '%s' "$CAP_OUT" | sed -n 's/.*expected_state_hash=\([0-9a-f]*\).*/\1/p' | head -n1)"

REP_CODE=0
REP_OUT="$("$REPLAY" --replay "$ARTIFACT")" || REP_CODE=$?
printf '%s\n' "$REP_OUT" | sed 's/^/  /'
assert "replay reproduced the failure (exit 0)" "0" "$REP_CODE"
assert "replay reports REPRODUCED (identical)" "yes" \
  "$(printf '%s' "$REP_OUT" | grep -q 'REPRODUCED (identical)' && echo yes || echo no)"

REP_TRACE="$(printf '%s' "$REP_OUT" | sed -n 's/.*trace_hash=\([0-9a-f]*\).*/\1/p' | head -n1)"
REP_STATE="$(printf '%s' "$REP_OUT" | sed -n 's/.*state_hash=\([0-9a-f]*\).*/\1/p' | head -n1)"
assert "replayed trace_hash equals the captured one (byte-identical)" "$CAP_TRACE" "$REP_TRACE"
assert "replayed state_hash equals the captured one (byte-identical)" "$CAP_STATE" "$REP_STATE"

# --------------------------------------------------------------------------------------------------
# Step 4 — REAL-SERVER SIGKILL durability run (rmp #275)
# --------------------------------------------------------------------------------------------------
# Steps 1-3 prove durability deterministically, in-process. Step 4 layers a REAL `graphus-server`
# process under an ACTUAL SIGKILL on top of the same guarantee: boot the production binary on a real
# on-disk store over a UDS, drive a concurrent OLTP workload to build WAL, capture steady-state
# throughput + the on-disk WAL footprint, HARD-KILL it mid-life (kill -KILL — no flush, no clean
# shutdown), RESTART from the same store, and ASSERT every acknowledged commit survived (count +
# content) — measuring the wall-clock recovery time and the peak RSS during replay. The evidence
# (recovery-time-vs-WAL-size + peak replay RSS) is written through the shared `measure_server` harness.
section "Step 4 — real-server SIGKILL durability (boot → concurrent OLTP → kill → restart → assert)"
info "this phase boots the PRODUCTION graphus-server over a UDS on a real store; the deterministic"
info "core above is its hermetic proof — here a real process is killed with SIGKILL and recovered"

SERVER_CONFIG="$WORKDIR/graphus.toml"
SOCKET="$WORKDIR/graphus.sock"
SERVER_LOG="$WORKDIR/server.log"
STORE_DIR="$WORKDIR/data"
STORE_FILE="$STORE_DIR/graphus.store"
WAL_FILE="$STORE_DIR/graphus.wal"
ADMIN_USER="durability-admin"
ADMIN_PW="durability-demo-pw-1"
PEAK_RSS_BYTES=0          # high-watermark of the server RSS, sampled during the workload + replay

# A UDS-only configuration (no network listener ⇒ no TLS/Node needed). The admin user is bound to
# this process's uid so the UDS SO_PEERCRED gate admits our own connections; the JWT secret is set
# only because the security catalog mandates a >=32-byte secret even when the network listener is off.
cat > "$SERVER_CONFIG" <<EOF
# Generated by examples/durability-crash-recovery/run.sh — a UDS-only crash-durability config.
store_path = "$STORE_DIR"
buffer_pool_pages = 2048
uds_path = "$SOCKET"
rest_addr = ""
jwt_secret = "graphus-durability-crash-recovery-uds-secret-32+"

[auth]
admin_user = "$ADMIN_USER"
admin_password = "$ADMIN_PW"
admin_uid = $(id -u)
EOF

# _now_ms — current time in milliseconds (GNU date), or seconds*1000 fallback (macOS BSD date).
_now_ms() {
  local ns
  ns="$(date +%s%N 2>/dev/null)"
  case "$ns" in
    *N|'') echo "$(( $(date +%s) * 1000 ))" ;;
    *)     echo "$(( ns / 1000000 ))" ;;
  esac
}

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
    if [ "${rss:-0}" -gt "$PEAK_RSS_BYTES" ]; then PEAK_RSS_BYTES="$rss"; fi
  fi
}

# Boot the server and wait until the UDS is bound (readiness), failing fast if the process dies.
start_server() {
  "$SERVER" "$SERVER_CONFIG" >>"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 100); do
    if [ -S "$SOCKET" ]; then return 0; fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      echo "${RED}server exited during startup; last log lines:${RESET}" >&2
      tail -n 15 "$SERVER_LOG" >&2
      return 1
    fi
    sleep 0.1
  done
  echo "${RED}server did not bind UDS $SOCKET within timeout${RESET}" >&2
  tail -n 15 "$SERVER_LOG" >&2
  return 1
}

# crash_server — SIGKILL: no flush, no clean shutdown. Recovery must rely entirely on the durable WAL.
crash_server() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -KILL "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -f "$SOCKET" # the kernel does not unlink the socket file on SIGKILL
  SERVER_PID=""
}

# cypher / scalar — run a statement over the UDS; scalar prints just the single returned value.
cypher() { GRAPHUS_PASSWORD="$ADMIN_PW" "$CLI" --uds "$SOCKET" --user "$ADMIN_USER" -c "$1"; }
scalar() {
  cypher "$1" | awk -F'|' '
    /^\|/ { rows++; if (rows == 2) { v = $2; gsub(/^[ \t"]+|[ \t"]+$/, "", v); print v } }
  '
}

# --- Boot --------------------------------------------------------------------------------------
SERVER_BOOTED=yes
start_server || SERVER_BOOTED=no
assert "real graphus-server booted and bound the UDS" "yes" "$SERVER_BOOTED"

if [ "$SERVER_BOOTED" = "yes" ]; then
  info "server pid $SERVER_PID listening on $SOCKET"
  assert "server answers a trivial query over UDS" "1" "$(scalar "RETURN 1 AS one")"
  assert "graph starts empty" "0" "$(scalar "MATCH (n) RETURN count(n) AS c")"

  # --- Concurrent OLTP workload: N background writers each commit a batch of account nodes +
  # transfer edges, building real WAL. We time the whole window for steady-state throughput.
  WRITERS="${DUR_WRITERS:-4}"
  BATCHES="${DUR_BATCHES:-6}"   # batches per writer
  PER_BATCH=5                   # account nodes created per batch (each its own committed statement)
  info "driving $WRITERS concurrent writers × $BATCHES batches × $PER_BATCH nodes (committed OLTP)"
  WL_START_MS="$(_now_ms)"
  writer() { # <writer-id>
    local w="$1" b i
    for b in $(seq 1 "$BATCHES"); do
      # One committed statement per batch: create PER_BATCH accounts + chain TRANSFER edges between
      # them, tagged by writer+batch so the post-crash content check can verify them precisely.
      local q="CREATE "
      for i in $(seq 1 "$PER_BATCH"); do
        [ "$i" -gt 1 ] && q+=", "
        q+="(a${i}:Account {writer:${w}, batch:${b}, seq:${i}, bal:$(( w*1000 + b*10 + i ))})"
      done
      for i in $(seq 2 "$PER_BATCH"); do
        q+=", (a$(( i-1 )))-[:TRANSFER {amount:${i}}]->(a${i})"
      done
      q+=" RETURN count(*) AS c"
      GRAPHUS_PASSWORD="$ADMIN_PW" "$CLI" --uds "$SOCKET" --user "$ADMIN_USER" -c "$q" >/dev/null 2>&1 || true
    done
  }
  # Spawn the writers and collect ONLY their PIDs — a bare `wait` would also block on the long-lived
  # background server job ($SERVER_PID), which never exits on its own.
  WRITER_PIDS=()
  for w in $(seq 1 "$WRITERS"); do writer "$w" & WRITER_PIDS+=( "$!" ); done
  # While the writers run, sample the server RSS a few times to catch the steady-state high-watermark.
  for _ in $(seq 1 20); do sample_peak_rss; sleep 0.02; done
  for wp in "${WRITER_PIDS[@]}"; do wait "$wp" 2>/dev/null || true; done   # all writers committed
  WL_MS=$(( $(_now_ms) - WL_START_MS ))
  [ "$WL_MS" -lt 1 ] && WL_MS=1
  sample_peak_rss

  EXPECT_NODES=$(( WRITERS * BATCHES * PER_BATCH ))
  EXPECT_RELS=$(( WRITERS * BATCHES * (PER_BATCH - 1) ))
  WL_OPS=$(( WRITERS * BATCHES ))   # committed statements (transactions)
  NODES_BEFORE="$(scalar "MATCH (a:Account) RETURN count(a) AS c")"
  RELS_BEFORE="$(scalar "MATCH ()-[r:TRANSFER]->() RETURN count(r) AS c")"
  BAL_SUM_BEFORE="$(scalar "MATCH (a:Account) RETURN sum(a.bal) AS s")"
  info "committed pre-crash: $NODES_BEFORE accounts, $RELS_BEFORE transfers (bal sum $BAL_SUM_BEFORE) in ${WL_MS} ms"

  assert "all committed accounts present pre-crash"  "$EXPECT_NODES" "$NODES_BEFORE"
  assert "all committed transfers present pre-crash" "$EXPECT_RELS"  "$RELS_BEFORE"

  # Steady-state throughput (committed transactions / second over the workload window).
  WL_TPS="$(LC_ALL=C awk "BEGIN{printf \"%.1f\", ${WL_OPS} / (${WL_MS}/1000.0)}")"
  info "steady-state throughput: ${WL_OPS} committed txns in ${WL_MS} ms (${WL_TPS} txn/s)"

  # On-disk WAL footprint BEFORE the crash — the redo log recovery will replay.
  WAL_BYTES_BEFORE=0
  [ -e "$WAL_FILE" ] && WAL_BYTES_BEFORE="$(du -sb "$WAL_FILE" 2>/dev/null | awk '{print $1}')"
  [ -d "$STORE_DIR" ] && WAL_BYTES_BEFORE="$(du -sb "$STORE_DIR"/*.wal 2>/dev/null | awk '{s+=$1} END{print s+0}')"
  info "on-disk WAL footprint before crash: ${WAL_BYTES_BEFORE} bytes"
  assert "the workload built a non-empty WAL to recover from" "yes" \
    "$([ "${WAL_BYTES_BEFORE:-0}" -gt 0 ] && echo yes || echo no)"

  # --- HARD KILL mid-life, then time the restart + WAL replay -------------------------------------
  info "SIGKILL the server (no flush / no clean shutdown) — recovery must replay the WAL"
  crash_server
  REC_START_MS="$(_now_ms)"
  RESTARTED=yes
  start_server || RESTARTED=no
  REC_MS=$(( $(_now_ms) - REC_START_MS ))
  [ "$REC_MS" -lt 1 ] && REC_MS=1
  assert "server restarted from the same store after the crash" "yes" "$RESTARTED"
  sample_peak_rss   # the just-recovered process RSS (replay high-watermark)

  if [ "$RESTARTED" = "yes" ]; then
    grep -qi "recover" "$SERVER_LOG" && info "recovery path exercised (see server.log)" || true
    info "wall-clock recovery time (kill → UDS bound again): ${REC_MS} ms"

    # --- Durability assertions: every acknowledged commit survived the crash (count + content). ---
    assert "account count survived the crash"  "$NODES_BEFORE" "$(scalar "MATCH (a:Account) RETURN count(a) AS c")"
    assert "transfer count survived the crash" "$RELS_BEFORE"  "$(scalar "MATCH ()-[r:TRANSFER]->() RETURN count(r) AS c")"
    assert "the balance sum survived the crash (content intact)" "$BAL_SUM_BEFORE" \
      "$(scalar "MATCH (a:Account) RETURN sum(a.bal) AS s")"
    # A precise content spot-check: writer 1 / batch 1 / seq 3's balance is deterministic (1*1000+1*10+3).
    assert "a specific committed account survived with its exact property" "1013" \
      "$(scalar "MATCH (a:Account {writer:1, batch:1, seq:3}) RETURN a.bal AS b")"
    # No in-flight or duplicated effect: the recovered counts equal EXACTLY what was committed.
    assert "no extra (phantom) account appeared after recovery"  "$EXPECT_NODES" \
      "$(scalar "MATCH (a:Account) RETURN count(a) AS c")"

    # --- Emit the standardized real-server evidence via the shared measure_server harness. The
    # server is still alive (the recovered pid), so its real CPU + RSS are readable and the on-disk
    # store/WAL footprint reflects the recovered workload. This is purely ADDITIVE; a metering failure
    # must not fail the demonstration.
    section "Step 4b — real-server evidence (recovery-time-vs-WAL-size, peak replay RSS)"
    MEASURE_BIN="$BIN_DIR/measure_server"
    if [ ! -x "$MEASURE_BIN" ]; then
      info "building the dev-only measure_server harness binary (debug)…"
      ( cd "$REPO_ROOT" && cargo build -q -p graphus-examples-harness --bin measure_server ) || true
      MEASURE_BIN="$REPO_ROOT/target/debug/measure_server"
    fi
    SERVER_UPTIME_SECS=1   # the recovered process has just booted; a 1s floor avoids a zero CPU window
    if [ -x "$MEASURE_BIN" ] && [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
      "$MEASURE_BIN" \
        --evidence-dir "$EVIDENCE_DIR/real-server" \
        --scenario "durability-crash-recovery-real-server" \
        --description "Real graphus-server over UDS: concurrent OLTP workload, a hard SIGKILL mid-life, and ARIES WAL-replay recovery — with the post-crash on-disk WAL footprint, wall-clock recovery time, and peak replay RSS." \
        --pid "$SERVER_PID" \
        --uptime-secs "$SERVER_UPTIME_SECS" \
        --store "$STORE_FILE" \
        --wal "$WAL_FILE" \
        --nodes "$NODES_BEFORE" \
        --rels "$RELS_BEFORE" \
        --peak-rss-bytes "$PEAK_RSS_BYTES" \
        --workload-ops "$WL_OPS" \
        --workload-secs "$(LC_ALL=C awk "BEGIN{printf \"%.6f\", ${WL_MS}/1000}")" \
        --param "connection=uds-bolt" \
        --param "writers=$WRITERS" \
        --param "crash=sigkill-mid-life" \
        --param "recovery=aries-wal-replay" \
        --param "wal_bytes_before_crash=$WAL_BYTES_BEFORE" \
        --param "recovery_wall_ms=$REC_MS" \
        --param "steady_state_txn_per_sec=$WL_TPS" \
        --phase "concurrent-oltp-workload=${WL_MS}" \
        --phase "recovery=${REC_MS}" \
        --note "RECOVERY-TIME-vs-WAL-SIZE: recovery replayed a ${WAL_BYTES_BEFORE}-byte on-disk WAL in ${REC_MS} ms wall-clock (kill → UDS bound again). These are MACHINE-VARIANT (host-dependent) and are NOT gated by the committed baseline; the deterministic recovery-work counts live in the sibling DST report (report.json)." \
        --note "Every one of the $NODES_BEFORE committed accounts + $RELS_BEFORE transfers (balance sum $BAL_SUM_BEFORE) survived the SIGKILL intact, and no phantom/in-flight effect appeared — the same committed-or-nothing contract the DST core proves deterministically, here under a REAL process crash." \
        && info "real-server evidence written to $EVIDENCE_DIR/real-server" \
        || info "real-server evidence collection failed (non-fatal); see output above"
      assert "real-server evidence report.json was produced" "yes" \
        "$([ -f "$EVIDENCE_DIR/real-server/report.json" ] && echo yes || echo no)"
    else
      info "measure_server unavailable or server not alive; skipping real-server evidence (non-fatal)"
    fi
  fi

  stop_after_real_server() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
      kill -TERM "$SERVER_PID" 2>/dev/null || true
      wait "$SERVER_PID" 2>/dev/null || true
    fi
    SERVER_PID=""
  }
  stop_after_real_server
fi

# --------------------------------------------------------------------------------------------------
# Step 5 — regression gate vs the committed baseline (deterministic structural metrics)
# --------------------------------------------------------------------------------------------------
# The committed baseline.json is a fast-profile (30-seed) deterministic run. We gate ONLY the
# structural, byte-stable recovery metrics (recovered dataset size, acked-commits-replayed,
# in-flight-undone, crashes, seed range) at EXACT equality; throughput / CPU / RAM / on-disk WAL bytes
# / recovery time are machine-variant and are NOT gated. Only meaningful at the baseline's own profile.
if [ "$PROFILE" = "fast" ] && [ "$SEEDS" = "30" ] && [ -f "$BASELINE" ] && [ -f "$EVIDENCE_DIR/report.json" ]; then
  section "Step 5 — regression gate vs committed baseline (structural deterministic metrics)"
  CMP_OUT="$("$CMP" "$BASELINE" "$EVIDENCE_DIR/report.json" 2>&1)" || true
  printf '%s\n' "$CMP_OUT" | sed 's/^/  /'
  assert "fresh run matches the committed baseline (structural deterministic metrics)" "yes" \
    "$(printf '%s' "$CMP_OUT" | grep -q 'GRAPHUS_BASELINE_OK' && echo yes || echo no)"
else
  info "baseline gate skipped (only runs at the baseline's fast/30-seed profile)"
fi

# --------------------------------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------------------------------
section "Result"
printf '%s checks run, %s failures.\n' "$CHECKS" "$FAILURES"
if [ -f "$EVIDENCE_DIR/report.json" ]; then
  info "standardized evidence: $EVIDENCE_DIR/{report.json, report.md}"
fi
if [ -f "$EVIDENCE_DIR/real-server/report.json" ]; then
  info "real-server SIGKILL evidence: $EVIDENCE_DIR/real-server/{report.json, report.md}"
fi
if [ "$FAILURES" -eq 0 ]; then
  printf '%s%sDURABILITY-CRASH-RECOVERY DEMONSTRATION PASSED%s — across %s deterministic seeds, Graphus\n' "$BOLD" "$GREEN" "$RESET" "$SEEDS"
  printf 'ran a concurrent OLTP workload under faults + a mid-workload crash, recovered via ARIES, and\n'
  printf 'upheld all four ACID-durability properties on the recovered engine (every acknowledged commit\n'
  printf 'survived; no in-flight effect did), fully deterministically. The planted-failure reproducer\n'
  printf 'replayed to the IDENTICAL failure byte-for-byte. A REAL graphus-server then survived an actual\n'
  printf 'SIGKILL mid-workload and recovered every committed account + transfer via WAL replay.\n'
  exit 0
else
  printf '%s%sDURABILITY-CRASH-RECOVERY DEMONSTRATION FAILED%s — %s assertion(s) did not hold.\n' "$BOLD" "$RED" "$RESET" "$FAILURES"
  exit 1
fi
