#!/usr/bin/env bash
#
# Graphus durability & crash recovery — the project's DURABILITY PROOF, end to end.
#
# It proves the two inviolable durability guarantees three ways, from the most controlled to the most
# brutal:
#
#   1. DETERMINISTIC CORE (`durability_demo`, DST) — a concurrent OLTP workload under disk/clock faults
#      and a seeded mid-workload crash, rebuilt via ARIES, with the four ACID-durability properties
#      asserted on the RECOVERED engine against a committed-only shadow LPG, for every seed.
#   2. THE FULL FAULT CATALOGUE (`durability_faults`, DST) — the SAME engine driven through EVERY fault
#      the simulator can physically inject: crash(no-force), crash(steal) [ARIES UNDO of stolen,
#      uncommitted pages], torn WAL tail, torn DATA page [doublewrite repair before redo], write
#      reordering [a non-atomic sync], and a write I/O error [surface, never corrupt]. The headline
#      sweep only exercises the easiest ARIES case; this exercises the hard ones.
#   3. A REAL SERVER, KILLED MID-WORKLOAD (`graphus-server` + `durability_oltp`) — the production binary
#      on a real on-disk store, with concurrent writers committing AND one writer holding an EXPLICIT,
#      never-committed transaction OPEN, is `SIGKILL`ed while they run. After the restart every
#      ACKNOWLEDGED commit must be present, complete and correct; NO in-flight effect may survive; no
#      transaction may be half-applied. The redo log the crash left behind is measured, and proven
#      LOAD-BEARING by a negative control (the same store, minus its WAL, cannot reproduce the data).
#
# THE HEADLINE EVIDENCE (evidence/report.json) IS THE REAL SERVER'S (rmp #712). This is the project's
# durability example, so the report a reader opens must answer "what did durability COST here?" — the
# redo log the crash left behind, the store image it was replayed into, the WAL residual afterwards,
# the bytes forced to durable media, and the wall-clock + peak RSS of the replay. Those exist only on
# the REAL server's on-disk store. The deterministic DST sweep — which runs the engine on an in-memory
# device and therefore HAS no on-disk footprint — emits its (baseline-gated, structurally
# reproducible) report alongside it, at evidence/dst-core/report.json. It used to be the headline, so
# the durability example's headline report stated no durability cost at all.
#
# THE CRASH WINDOW IS DETERMINISTIC (rmp #712). The `SIGKILL` is sequenced BEHIND three independent
# facts, checked in this order and immediately before the kill: (a) the server's own
# `graphus_active_transactions` gauge shows an open transaction; (b) the in-flight writer's HOLD
# BEACON has advanced since the ready marker — it completed another in-transaction round-trip after
# every other pre-kill step finished, so it is still holding *now*; (c) it never sends COMMIT on any
# code path. The driver then REFUSES to publish a ledger in which the server died without a writer
# attesting an open transaction at the kill, so a raced observation is a loud failure, never a quietly
# weakened proof.
#
# LOCAL-ONLY BY CONSTRUCTION. This is the documented exception in `examples/CLAUDE.md`: the example must
# OWN the server's lifecycle to `SIGKILL` it and to reopen its store exclusively. It therefore cannot
# attach to an already-running (let alone shared/remote) instance — killing someone else's server is not
# a demonstration, and durability is a property of a store you control. Setting GRAPHUS_TARGET_* is
# refused with a clear message rather than silently degrading the proof.
#
# Usage:
#   examples/durability-crash-recovery/run.sh                        # CI-fast: 30 seeds
#   DUR_PROFILE=full   examples/durability-crash-recovery/run.sh     # 100 seeds (evidence scale)
#   DUR_SEEDS=250      examples/durability-crash-recovery/run.sh     # custom seed count
#   DUR_FOCUS=7        examples/durability-crash-recovery/run.sh     # which seed's crash partition to detail
#   DUR_FAULT_SEEDS=40 examples/durability-crash-recovery/run.sh     # seeds per fault kind (step 2)
#   DUR_WRITERS=6 DUR_BATCH_NODES=8 examples/durability-crash-recovery/run.sh   # heavier real-server OLTP
#   GRAPHUS_BIN_DIR=target/release examples/durability-crash-recovery/run.sh    # use prebuilt binaries
#
# Requirements: a Unix host (Linux/macOS), bash, curl, and openssl (the real-server step binds REST so
# its Prometheus /metrics can be scraped; a network listener requires TLS, hence the self-signed cert).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Shared harness: pretty output + assert counters, the harness_build seam, the external-target contract.
source "$REPO_ROOT/examples/_harness/harness.sh"

RED="$HARNESS_RED"; RESET="$HARNESS_RESET"

# --------------------------------------------------------------------------------------------------
# LOCAL-ONLY guard (examples/CLAUDE.md — the documented crash-recovery exception)
# --------------------------------------------------------------------------------------------------
if [ "$(harness_target_mode)" = "external" ]; then
  cat >&2 <<EOF
${RED}fatal: durability-crash-recovery is LOCAL-ONLY and cannot run against an external target.${RESET}

This example SIGKILLs the server it measures and then reopens its store exclusively to prove ARIES
recovery. Doing that to an already-running (possibly shared or remote) instance would kill someone
else's database, and durability can only be demonstrated on a store whose lifecycle you own.

Unset GRAPHUS_TARGET_BOLT / GRAPHUS_TARGET_REST / GRAPHUS_TARGET_UDS and run it locally. Every other
example supports the external-target seam; this one is the documented exception (examples/CLAUDE.md:
"Durability/crash-recovery examples that must inject a crash and own the server lifecycle are the
documented local-only exception").
EOF
  exit 2
fi

command -v curl    >/dev/null 2>&1 || { echo "${RED}fatal: curl is required (the /metrics scrape)${RESET}" >&2; exit 2; }
command -v openssl >/dev/null 2>&1 || { echo "${RED}fatal: openssl is required (the REST listener's TLS cert)${RESET}" >&2; exit 2; }

# --------------------------------------------------------------------------------------------------
# Binaries — built through the shared harness_build seam (NEVER an "if the file exists" guard: that
# silently runs a STALE binary after any source edit, so the evidence would describe code that is no
# longer the code under test).
# --------------------------------------------------------------------------------------------------
BIN_DIR="${GRAPHUS_BIN_DIR:-$REPO_ROOT/target/release}"
harness_build "the durability example + server binaries (release)" \
  --release -p graphus-durability-demo -p graphus-dst -p graphus-server -p graphus-cli \
  -p graphus-examples-harness

DEMO="$BIN_DIR/durability_demo"
FAULTS="$BIN_DIR/durability_faults"
OLTP="$BIN_DIR/durability_oltp"
REPLAY="$BIN_DIR/durability_replay"
CMP="$BIN_DIR/durability_baseline_cmp"
DST="$BIN_DIR/graphus-dst"
SERVER="$BIN_DIR/graphus-server"
CLI="$BIN_DIR/graphus-cli"
MEASURE="$BIN_DIR/measure_server"
for b in "$DEMO" "$FAULTS" "$OLTP" "$REPLAY" "$CMP" "$DST" "$SERVER" "$CLI" "$MEASURE"; do
  [ -x "$b" ] || { echo "${RED}fatal: binary not found at $b${RESET}" >&2; exit 2; }
done

PROFILE="${DUR_PROFILE:-fast}"
case "$PROFILE" in
  full) DEFAULT_SEEDS=100 ;;
  *)    DEFAULT_SEEDS=30 ;;
esac
SEEDS="${DUR_SEEDS:-$DEFAULT_SEEDS}"
FOCUS="${DUR_FOCUS:-7}"
FAULT_SEEDS="${DUR_FAULT_SEEDS:-25}"

# --------------------------------------------------------------------------------------------------
# Workspace
# --------------------------------------------------------------------------------------------------
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/graphus-durability-XXXXXX")"
ARTIFACT="$WORKDIR/planted-repro.json"
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
# The HEADLINE report (evidence/report.json) is the REAL SERVER's — see the header. The deterministic
# DST sweep, which has no on-disk store to measure, reports alongside it (rmp #712).
DST_EVIDENCE_DIR="$EVIDENCE_DIR/dst-core"
DST_REPORT="$DST_EVIDENCE_DIR/report.json"
BASELINE="$SCRIPT_DIR/baseline.json"
SERVER_PID=""
CONTROL_PID=""
WORKLOAD_PID=""
cleanup() {
  for pid in "$SERVER_PID" "$CONTROL_PID" "$WORKLOAD_PID"; do
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill -KILL "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM
mkdir -p "$EVIDENCE_DIR" "$DST_EVIDENCE_DIR"
# A stale headline report from a previous run must never be mistaken for this one's: the real-server
# step writes it, and if that step never gets there, there must be NO report rather than an old one.
rm -f "$EVIDENCE_DIR/report.json" "$EVIDENCE_DIR/report.md"
# The real-server report used to live in its own subdirectory; it IS the headline report now (rmp
# #712). Remove the old location so the suite's evidence audit never reads a stale report from it.
rm -rf "$EVIDENCE_DIR/real-server"

# --------------------------------------------------------------------------------------------------
# Step 1 — the deterministic OLTP durability sweep (workload + crash + ARIES recovery + 4-prop oracle)
# --------------------------------------------------------------------------------------------------
section "Step 1 — deterministic OLTP durability + crash-recovery sweep ($SEEDS seeds, $PROFILE profile)"
info "each seed: concurrent overlapping transactions under disk/clock faults + a mid-workload crash,"
info "rebuilt via ARIES recovery, then the 4 ACID-durability properties asserted on the recovered engine"
SWEEP_CODE=0
SWEEP_OUT="$("$DEMO" --seed 1 --seeds "$SEEDS" --focus "$FOCUS" --evidence-dir "$DST_EVIDENCE_DIR")" || SWEEP_CODE=$?
printf '%s\n' "$SWEEP_OUT" | sed 's/^/  /'

assert "durability sweep completed with exit 0 (zero violations, deterministic)" "0" "$SWEEP_CODE"
assert "sweep reports a DURABLE verdict" "yes" \
  "$(printf '%s' "$SWEEP_OUT" | grep -q 'RESULT: DURABLE' && echo yes || echo no)"
assert "every seed was non-vacuous (acked + in-flight coexisted at a crash)" "yes" \
  "$(printf '%s' "$SWEEP_OUT" | grep -qE "non-vacuous=$SEEDS/$SEEDS" && echo yes || echo no)"
assert "focused seed's committed-or-nothing contract HOLDS (nodes)" "yes" \
  "$(printf '%s' "$SWEEP_OUT" | grep -q 'committed-or-nothing.*HOLDS' && echo yes || echo no)"
assert "focused seed's relationship durability HOLDS (recovered edges == committed edges)" "yes" \
  "$(printf '%s' "$SWEEP_OUT" | grep -q 'relationships:.*HOLDS' && echo yes || echo no)"
# The dataset's relationship count must be REAL, not the hard-coded 0 it used to report (rmp #698).
REPORTED_RELS="$(grep -o '"relationships": *[0-9]*' "$DST_REPORT" | grep -o '[0-9]*$' || echo 0)"
assert "evidence reports a NON-ZERO recovered relationship count (no hard-coded 0)" "yes" \
  "$([ "${REPORTED_RELS:-0}" -gt 0 ] && echo yes || echo no)"
# `total_millis` must be the measured WORKLOAD wall-time, not the report-builder's own microseconds.
TOTAL_MS="$(grep -o '"total_millis": *[0-9.]*' "$DST_REPORT" | grep -o '[0-9.]*$' || echo 0)"
assert "evidence total_millis is the measured sweep wall-time (>= 1 ms, not a report-build artefact)" "yes" \
  "$(LC_ALL=C awk "BEGIN{exit !(${TOTAL_MS:-0} >= 1.0)}" && echo yes || echo no)"
assert "DST-core evidence report.json + report.md were produced" "yes" \
  "$([ -f "$DST_REPORT" ] && [ -f "$DST_EVIDENCE_DIR/report.md" ] && echo yes || echo no)"

# --------------------------------------------------------------------------------------------------
# Step 2 — THE FULL FAULT CATALOGUE (rmp #698): every fault the engine can be subjected to
# --------------------------------------------------------------------------------------------------
section "Step 2 — the FULL fault catalogue ($FAULT_SEEDS seeds x 6 fault kinds, through the real engine)"
info "steal/UNDO, torn WAL tail, torn DATA page (doublewrite repair before redo), write reordering,"
info "write I/O error (surface-never-corrupt), plain crash — each must recover SAFE + deterministically"
FAULT_CODE=0
FAULT_OUT="$("$FAULTS" --seed 1 --seeds "$FAULT_SEEDS")" || FAULT_CODE=$?
printf '%s\n' "$FAULT_OUT" | sed 's/^/  /'

assert "fault catalogue completed with exit 0" "0" "$FAULT_CODE"
assert "every fault kind recovered SAFE" "yes" \
  "$(printf '%s' "$FAULT_OUT" | grep -q 'RESULT: ALL FAULTS SAFE' && echo yes || echo no)"
for kind in 'crash(no-force)' 'crash(steal)' 'torn-wal-tail' 'torn-data-page' 'write-reordering' 'write-io-error(full-engine)'; do
  assert "fault '$kind' ran and is SAFE" "yes" \
    "$(printf '%s\n' "$FAULT_OUT" | grep -F "fault=$kind" | grep -q 'verdict=SAFE' && echo yes || echo no)"
done
# Non-vacuity: the hard faults must actually have done their hard work, or "SAFE" would be vacuous.
STEAL_LOSERS="$(printf '%s\n' "$FAULT_OUT" | grep -F 'fault=crash(steal)' | sed -n 's/.*recovery_losers=\([0-9]*\).*/\1/p')"
assert "the steal crash gave ARIES UNDO real work (uncommitted pages stolen home)" "yes" \
  "$([ "${STEAL_LOSERS:-0}" -gt 0 ] && echo yes || echo no)"
TORN_TAILS="$(printf '%s\n' "$FAULT_OUT" | grep -F 'fault=torn-wal-tail' | sed -n 's/.*torn_tails=\([0-9]*\).*/\1/p')"
assert "the torn-WAL-tail fault really left recovery a truncated tail" "yes" \
  "$([ "${TORN_TAILS:-0}" -gt 0 ] && echo yes || echo no)"
assert "the ONE deferred fault is declared with its reason (fsync-EIO), not hidden" "yes" \
  "$(printf '%s' "$FAULT_OUT" | grep -q 'fsync-eio: controlled-PANIC' && echo yes || echo no)"

# --------------------------------------------------------------------------------------------------
# Step 3 — cross-check through the graphus-dst VOPR safety CLI (the PR safety gate)
# --------------------------------------------------------------------------------------------------
section "Step 3 — cross-check via the graphus-dst VOPR safety gate"
info "the same scenario, run through the project's PR safety gate, must agree: all SAFE + deterministic"
DST_CODE=0
DST_OUT="$("$DST" vopr safety --seed 1 --seeds "$SEEDS")" || DST_CODE=$?
printf '%s\n' "$DST_OUT" | tail -n 3 | sed 's/^/  /'
assert "vopr safety gate exits 0" "0" "$DST_CODE"
assert "vopr safety gate reports all SAFE + deterministic" "yes" \
  "$(printf '%s' "$DST_OUT" | grep -qE "$SEEDS seed\(s\) checked, all SAFE" && echo yes || echo no)"

# --------------------------------------------------------------------------------------------------
# Step 4 — the one-command replay round-trip (planted synthetic failure)
# --------------------------------------------------------------------------------------------------
section "Step 4 — one-command replay round-trip (planted synthetic failure)"
info "the real engine has NO failing seed, so the failure is PLANTED via the DST replay machinery;"
info "the captured artifact must replay to the IDENTICAL failure byte-for-byte"
CAP_CODE=0
CAP_OUT="$("$REPLAY" --capture "$ARTIFACT" --seed "$FOCUS")" || CAP_CODE=$?
printf '%s\n' "$CAP_OUT" | sed 's/^/  /'
assert "planted reproducer captured (exit 0)" "0" "$CAP_CODE"
assert "reproducer artifact written to disk" "yes" "$([ -s "$ARTIFACT" ] && echo yes || echo no)"
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
# Step 5 — REAL SERVER, KILLED MID-WORKLOAD (rmp #698)
# --------------------------------------------------------------------------------------------------
section "Step 5 — real graphus-server, SIGKILLed MID-WORKLOAD (writers committing + 1 OPEN transaction)"
info "the production binary on a real on-disk store: concurrent writers commit while ONE writer holds an"
info "EXPLICIT, never-committed transaction open. The kill lands while they run — not after they finish."

STORE_DIR="$WORKDIR/data"
SOCKET="$WORKDIR/graphus.sock"
SERVER_LOG="$WORKDIR/server.log"
SERVER_CONFIG="$WORKDIR/graphus.toml"
CERT="$WORKDIR/cert.pem"
KEY="$WORKDIR/key.pem"
LEDGER="$WORKDIR/ledger.txt"
READY="$WORKDIR/ready"
# The in-flight writer refreshes this after EVERY successful in-transaction probe (rmp #712). Reading
# it immediately before the SIGKILL turns "a transaction was open a moment ago" into "a transaction is
# being held RIGHT NOW", which is the fact the example's strongest assertion needs.
HOLD="$WORKDIR/hold"
WORKLOAD_LOG="$WORKDIR/workload.log"
METRICS_BEFORE="$WORKDIR/metrics_before.prom"
METRICS_AFTER="$WORKDIR/metrics_after.prom"
ADMIN_USER="durability-admin"
ADMIN_PW="durability-demo-pw-1"
WRITERS="${DUR_WRITERS:-4}"
BATCH_NODES="${DUR_BATCH_NODES:-5}"
PHANTOM_NODES="${DUR_PHANTOM_NODES:-6}"
MIN_ACKED="${DUR_MIN_ACKED:-40}"
PEAK_RSS_BYTES=0
# The peak RSS observed while the server is REPLAYING its WAL (sampled every 100 ms across the restart,
# from the SIGKILL to the UDS being bound again) — the memory cost of recovery itself, as distinct from
# the workload's peak. Stays 0 only if recovery completed inside a single sample, in which case it is
# OMITTED from the evidence rather than reported as a zero (rmp #711).
RECOVERY_PEAK_RSS=0
SAMPLE_RECOVERY_RSS=no
RECOVERY_PANICS=""

REST_PORT="$(( (RANDOM % 20000) + 20000 ))"
REST_BASE="https://127.0.0.1:$REST_PORT"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" \
  -days 1 -subj "/CN=localhost" -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1

# UDS (the workload) + REST/TLS (so the Prometheus /metrics endpoint can be scraped — a network
# listener requires TLS by config validation, hence the self-signed cert).
cat > "$SERVER_CONFIG" <<EOF
# Generated by examples/durability-crash-recovery/run.sh — UDS workload + REST /metrics.
store_path = "$STORE_DIR"
buffer_pool_pages = 2048
uds_path = "$SOCKET"
rest_addr = "127.0.0.1:$REST_PORT"
jwt_secret = "graphus-durability-crash-recovery-uds-secret-32+"

[tls]
cert_path = "$CERT"
key_path = "$KEY"

[auth]
admin_user = "$ADMIN_USER"
admin_password = "$ADMIN_PW"
admin_uid = $(id -u)
EOF

_now_ms() {
  local ns
  ns="$(date +%s%N 2>/dev/null)"
  case "$ns" in
    *N|'') echo "$(( $(date +%s) * 1000 ))" ;;
    *)     echo "$(( ns / 1000000 ))" ;;
  esac
}
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
start_server() { # <config> <socket> <log> -> sets SERVER_PID
  "$SERVER" "$1" >>"$3" 2>&1 &
  SERVER_PID=$!
  local _ rss
  for _ in $(seq 1 150); do
    # While the server is coming up after the CRASH it is replaying its WAL. Sampling its RSS here —
    # before the readiness check, so at least one sample is always taken — measures the memory cost of
    # RECOVERY itself, not of the workload that preceded it.
    if [ "$SAMPLE_RECOVERY_RSS" = "yes" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
      rss="$(server_rss_bytes "$SERVER_PID")"
      if [ "${rss:-0}" -gt "$RECOVERY_PEAK_RSS" ]; then RECOVERY_PEAK_RSS="$rss"; fi
      if [ "${rss:-0}" -gt "$PEAK_RSS_BYTES" ]; then PEAK_RSS_BYTES="$rss"; fi
    fi
    [ -S "$2" ] && return 0
    kill -0 "$SERVER_PID" 2>/dev/null || { echo "${RED}server exited during startup:${RESET}" >&2; tail -n 15 "$3" >&2; return 1; }
    sleep 0.1
  done
  echo "${RED}server did not bind UDS $2 within timeout${RESET}" >&2; tail -n 15 "$3" >&2; return 1
}
crash_server() {   # SIGKILL: no flush, no clean shutdown — recovery must rely entirely on the durable WAL.
  kill -KILL "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
  rm -f "$SOCKET"
  SERVER_PID=""
}
stop_server() {    # SIGTERM: the graceful path.
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -f "$SOCKET"
  SERVER_PID=""
}
scalar() { GRAPHUS_PASSWORD="$ADMIN_PW" "$CLI" --uds "$SOCKET" --user "$ADMIN_USER" -c "$1" | awk -F'|' '
  /^\|/ { rows++; if (rows == 2) { v = $2; gsub(/^[ \t"]+|[ \t"]+$/, "", v); print v } }'; }
scrape_metrics() { # <outfile>
  local token
  token="$(curl -sS -k -m 10 -X POST "$REST_BASE/auth/login" -H 'Content-Type: application/json' \
            -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PW\"}" 2>/dev/null \
          | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  [ -z "$token" ] && return 1
  curl -sS -k -m 10 -o "$1" -H "Authorization: Bearer $token" "$REST_BASE/metrics" 2>/dev/null || return 1
  [ -s "$1" ]
}
metric() { # <file> <name> -> value ("" if absent)
  awk -v n="$2" '$1 == n { print $2; exit }' "$1" 2>/dev/null
}

# ---- Boot ----------------------------------------------------------------------------------------
BOOTED=yes
start_server "$SERVER_CONFIG" "$SOCKET" "$SERVER_LOG" || BOOTED=no
assert "real graphus-server booted (UDS + REST/metrics)" "yes" "$BOOTED"
[ "$BOOTED" = "yes" ] || { harness_summary "" || true; exit 1; }
info "server pid $SERVER_PID on $SOCKET + $REST_BASE"
assert "graph starts empty" "0" "$(scalar 'MATCH (n) RETURN count(n) AS c')"

# ---- Drive the workload; crash it MID-FLIGHT -----------------------------------------------------
info "$WRITERS committing writers x $BATCH_NODES nodes/commit + 1 writer holding an OPEN transaction"
WL_START_MS="$(_now_ms)"
"$OLTP" --workload --uds "$SOCKET" --user "$ADMIN_USER" --password "$ADMIN_PW" \
  --writers "$WRITERS" --batch-nodes "$BATCH_NODES" --phantom-nodes "$PHANTOM_NODES" \
  --min-acked "$MIN_ACKED" --max-secs 90 --ready-file "$READY" --hold-file "$HOLD" \
  --ledger "$LEDGER" \
  >"$WORKLOAD_LOG" 2>&1 &
WORKLOAD_PID=$!

# The in-flight writer's hold beacon: `probes=<n>`, rewritten atomically after every successful
# in-transaction round-trip. Reading it is how the script knows the never-committed transaction is
# still being HELD, rather than assuming it (rmp #712).
hold_probes() { sed -n 's/^probes=//p' "$HOLD" 2>/dev/null | tail -n1; }

# Wait for the mid-workload state: an OPEN, never-committed transaction AND commits being acknowledged.
READY_OK=no
for _ in $(seq 1 900); do
  [ -f "$READY" ] && { READY_OK=yes; break; }
  kill -0 "$WORKLOAD_PID" 2>/dev/null || break
  sample_peak_rss
  sleep 0.1
done
assert "the workload reached the MID-WORKLOAD state (open txn + >= $MIN_ACKED acked commits)" "yes" "$READY_OK"
if [ "$READY_OK" != "yes" ]; then
  echo "${RED}workload never reached the crash state; log:${RESET}" >&2; cat "$WORKLOAD_LOG" >&2
  harness_summary "" || true; exit 1
fi
info "ready marker: $(cat "$READY")"
HOLD_AT_READY="$(hold_probes)"

# The redo log the crash is about to leave behind, measured BEFORE the kill. Classified by PATH: the WAL
# is a DIRECTORY of `seg.<lsn>` files, so a leaf-name classifier reports wal=0 and hides it entirely.
# This is the figure the headline evidence reports as `storage.wal_bytes`: recovery CONSUMES it, so it
# exists at exactly one instant — now — and it is the whole point of the example (rmp #712).
FP_BEFORE="$("$OLTP" --footprint --store-dir "$STORE_DIR")"
WAL_BEFORE="$(printf '%s\n' "$FP_BEFORE" | sed -n 's/^store\.wal_bytes=//p')"
DATA_BEFORE="$(printf '%s\n' "$FP_BEFORE" | sed -n 's/^store\.data_bytes=//p')"
DWB_BEFORE="$(printf '%s\n' "$FP_BEFORE" | sed -n 's/^store\.dwb_bytes=//p')"
STORE_PATH="$(printf '%s\n' "$FP_BEFORE" | sed -n 's/^store\.data_path=//p')"
WAL_PATH="$(printf '%s\n' "$FP_BEFORE" | sed -n 's/^store\.wal_path=//p')"
info "on-disk at the crash: WAL ${WAL_BEFORE} B (redo log) | data image ${DATA_BEFORE} B | doublewrite ${DWB_BEFORE} B"
info "  data: $STORE_PATH"
info "  wal : $WAL_PATH (a DIRECTORY of seg.<lsn> segments)"
# A crash worth recovering from: the workload must have built a real, UN-checkpointed redo log.
assert "the crash leaves a NON-TRIVIAL redo log to replay (>= 64 KiB of WAL)" "yes" \
  "$([ "${WAL_BEFORE:-0}" -ge 65536 ] && echo yes || echo no)"

# ---- THE CRASH WINDOW, made deterministic (rmp #712) ----------------------------------------------
# The kill must be GUARANTEED to land on an open, never-committed transaction. It used to be merely
# LIKELY: the ready marker said a transaction had been opened, the script then did more work, and the
# kill landed whenever it landed. Three facts now gate the trigger, and the LAST one is checked with
# nothing between it and the SIGKILL.
#
# FACT 1 (server-side) — the server's OWN bookkeeping says a transaction is open right now. This is the
# falsifying direction that matters: `graphus_active_transactions` reaching 0 here would DISPROVE the
# claim outright. (It counts every open transaction, so the auto-commit writers contribute too; it
# corroborates the client-side proof rather than replacing it.)
ACTIVE_TXNS=""
if scrape_metrics "$METRICS_BEFORE"; then
  ACTIVE_TXNS="$(metric "$METRICS_BEFORE" graphus_active_transactions)"
  info "server-side at the crash window: graphus_active_transactions=$ACTIVE_TXNS"
fi
assert "the SERVER itself reports >= 1 OPEN transaction at the crash window" "yes" \
  "$([ -n "$ACTIVE_TXNS" ] && [ "${ACTIVE_TXNS%%.*}" -ge 1 ] && echo yes || echo no)"

# FACT 2 (client-side, FRESH) — the in-flight writer's hold beacon has ADVANCED since the ready marker.
# It only advances on an in-transaction round-trip the server ANSWERED, so a higher count proves the
# never-committed transaction was alive and held AFTER every other pre-kill step above had finished.
# This is the check that replaces the old assumption, and nothing may be inserted between it and the
# kill below.
HOLD_BEFORE_KILL="$(hold_probes)"
info "in-flight writer: ${HOLD_AT_READY:-0} -> ${HOLD_BEFORE_KILL:-0} in-transaction probes held (it is still holding, now)"
assert "the never-committed transaction is STILL being held at the instant of the kill (beacon advanced)" "yes" \
  "$([ -n "$HOLD_BEFORE_KILL" ] && [ "${HOLD_BEFORE_KILL:-0}" -gt "${HOLD_AT_READY:-0}" ] && echo yes || echo no)"

# FACT 3 (by construction) — `hold_open_transaction` contains no COMMIT on any path, so the held
# transaction cannot have committed. The driver enforces this end to end: it REFUSES to publish a
# ledger in which the server died without the writer attesting an open transaction at the kill.

sample_peak_rss
info "SIGKILL the server — no flush, no clean shutdown, an OPEN transaction and statements in flight"
crash_server
REC_START_MS="$(_now_ms)"

# The workload's clients die with the server; collect the ledger of exactly what was ACKNOWLEDGED.
WL_CODE=0
wait "$WORKLOAD_PID" || WL_CODE=$?
WORKLOAD_PID=""
WL_MS=$(( $(_now_ms) - WL_START_MS ))
[ "$WL_MS" -lt 1 ] && WL_MS=1
sed 's/^/  /' "$WORKLOAD_LOG"
assert "the workload driver exited cleanly with its ledger" "0" "$WL_CODE"

ledger() { sed -n "s/^$1=//p" "$LEDGER"; }
ACKED_BATCHES="$(ledger acked_batches)"
ACKED_NODES="$(ledger acked_nodes)"
ACKED_RELS="$(ledger acked_rels)"
UNDET="$(ledger undetermined_batches)"
PHANTOM_OPEN="$(ledger phantom_txn_open_at_kill)"
PHANTOM_IN_TXN="$(ledger phantom_visible_in_txn)"
PHANTOM_PROBES="$(ledger phantom_hold_probes)"
PHANTOM_ERR="$(ledger phantom_txn_error)"
P50="$(ledger commit_p50_ms)"; P99="$(ledger commit_p99_ms)"; P999="$(ledger commit_p999_ms)"
TPS="$(ledger acked_commits_per_sec)"

# THE proof that the kill was mid-workload: a writer was inside an OPEN transaction, held across real
# in-transaction round-trips, its writes were live INSIDE that transaction, and it never sent COMMIT.
# It observed the kill FIRST-HAND — its own connection died under it — which is why this is a recorded
# fact and not an inference (rmp #712).
assert "a writer really was inside an OPEN, never-committed transaction at SIGKILL" "yes" "$PHANTOM_OPEN"
if [ "$PHANTOM_OPEN" != "yes" ]; then
  echo "${RED}the in-flight writer did not witness the kill with its transaction open.${RESET}" >&2
  echo "  hold probes: ${PHANTOM_PROBES:-0}" >&2
  echo "  it ended with: ${PHANTOM_ERR:-<none>}" >&2
fi
assert "it HELD that transaction across real in-transaction round-trips (>= 1 answered probe)" "yes" \
  "$([ "${PHANTOM_PROBES:-0}" -ge 1 ] && echo yes || echo no)"
assert "it died with a dead SOCKET, i.e. it observed the SIGKILL first-hand (not a server refusal)" "yes" \
  "$(printf '%s' "$PHANTOM_ERR" | grep -qi 'refused' && echo no || echo yes)"
assert "that transaction's writes were live INSIDE it (so their absence later is a real UNDO)" \
  "$PHANTOM_NODES" "$PHANTOM_IN_TXN"
assert "acknowledged commits were still flowing at the kill" "yes" \
  "$([ "${ACKED_BATCHES:-0}" -ge "$MIN_ACKED" ] && echo yes || echo no)"
info "at the kill: $ACKED_BATCHES acked commit(s) ($ACKED_NODES accounts + $ACKED_RELS transfers), $UNDET undetermined (statement in flight), $PHANTOM_IN_TXN uncommitted :Phantom rows held across $PHANTOM_PROBES probes"

# ---- NEGATIVE CONTROL: is that redo log actually LOAD-BEARING? ------------------------------------
# The crashed store is copied and its WAL segments removed, then a server is opened on the copy. If the
# committed data were already in the data image, the copy would come back whole and the "recovery" we
# are about to time would be a no-op. It must NOT: without its redo log the acknowledged data must be
# missing (or the store must refuse to open at all).
section "Step 5a — negative control: the same store WITHOUT its WAL cannot reproduce the committed data"
CONTROL_DIR="$WORKDIR/control"
cp -a "$STORE_DIR" "$CONTROL_DIR"
find "$CONTROL_DIR" -type d -name '*.wal' -exec sh -c 'rm -f "$1"/*' _ {} \; 2>/dev/null || true
CONTROL_WAL_AFTER="$("$OLTP" --footprint --store-dir "$CONTROL_DIR" | sed -n 's/^store\.wal_bytes=//p')"
info "control store: WAL ${WAL_BEFORE} B -> ${CONTROL_WAL_AFTER} B (redo log removed)"

CONTROL_SOCK="$WORKDIR/control.sock"
CONTROL_CONFIG="$WORKDIR/control.toml"
CONTROL_LOG="$WORKDIR/control.log"
cat > "$CONTROL_CONFIG" <<EOF
store_path = "$CONTROL_DIR"
buffer_pool_pages = 2048
uds_path = "$CONTROL_SOCK"
rest_addr = ""
jwt_secret = "graphus-durability-crash-recovery-uds-secret-32+"

[auth]
admin_user = "$ADMIN_USER"
admin_password = "$ADMIN_PW"
admin_uid = $(id -u)
EOF
CONTROL_ACCOUNTS=""
CONTROL_BOOTED=no
"$SERVER" "$CONTROL_CONFIG" >>"$CONTROL_LOG" 2>&1 &
CONTROL_PID=$!
for _ in $(seq 1 100); do
  [ -S "$CONTROL_SOCK" ] && { CONTROL_BOOTED=yes; break; }
  kill -0 "$CONTROL_PID" 2>/dev/null || break
  sleep 0.1
done
if [ "$CONTROL_BOOTED" = "yes" ]; then
  CONTROL_ACCOUNTS="$(GRAPHUS_PASSWORD="$ADMIN_PW" "$CLI" --uds "$CONTROL_SOCK" --user "$ADMIN_USER" \
    -c 'MATCH (a:Account) RETURN count(a) AS c' 2>/dev/null | awk -F'|' '/^\|/ { rows++; if (rows == 2) { v=$2; gsub(/^[ \t"]+|[ \t"]+$/,"",v); print v } }')"
  info "WITHOUT its WAL the store came back with ${CONTROL_ACCOUNTS:-?} accounts (the acknowledged set is $ACKED_NODES)"
else
  info "WITHOUT its WAL the store could not be opened at all — the redo log is essential"
  tail -n 3 "$CONTROL_LOG" | sed 's/^/    /' || true
fi
if [ -n "$CONTROL_PID" ] && kill -0 "$CONTROL_PID" 2>/dev/null; then
  kill -KILL "$CONTROL_PID" 2>/dev/null || true; wait "$CONTROL_PID" 2>/dev/null || true
fi
CONTROL_PID=""
REDO_LOAD_BEARING=no
if [ "$CONTROL_BOOTED" != "yes" ]; then
  REDO_LOAD_BEARING=yes
elif [ -n "$CONTROL_ACCOUNTS" ] && [ "$CONTROL_ACCOUNTS" -lt "$ACKED_NODES" ]; then
  REDO_LOAD_BEARING=yes
fi
assert "the redo log is LOAD-BEARING (without the WAL the acknowledged data is NOT there)" "yes" "$REDO_LOAD_BEARING"

# ---- Restart: ARIES recovery from the durable WAL --------------------------------------------------
section "Step 5b — restart from the crashed store (ARIES: doublewrite repair -> redo -> undo)"
RESTARTED=yes
SAMPLE_RECOVERY_RSS=yes   # sample the REPLAYING server's RSS across the restart (the cost of recovery)
start_server "$SERVER_CONFIG" "$SOCKET" "$SERVER_LOG" || RESTARTED=no
SAMPLE_RECOVERY_RSS=no
REC_MS=$(( $(_now_ms) - REC_START_MS ))
[ "$REC_MS" -lt 1 ] && REC_MS=1
assert "server restarted from the same store after the SIGKILL" "yes" "$RESTARTED"
[ "$RESTARTED" = "yes" ] || { harness_summary "" || true; exit 1; }
sample_peak_rss
info "wall-clock recovery: kill -> UDS bound again in ${REC_MS} ms (replaying ${WAL_BEFORE} B of WAL)"
info "peak RSS observed WHILE replaying: ${RECOVERY_PEAK_RSS} B (sampled every 100 ms across the restart)"

# ---- The durability contract, verified against the ledger -----------------------------------------
VERIFY_CODE=0
VERIFY_OUT="$("$OLTP" --verify --uds "$SOCKET" --user "$ADMIN_USER" --password "$ADMIN_PW" --ledger "$LEDGER")" || VERIFY_CODE=$?
printf '%s\n' "$VERIFY_OUT" | sed 's/^/  /'
v() { printf '%s\n' "$VERIFY_OUT" | sed -n "s/^$1=//p"; }

assert "post-crash verification exits 0" "0" "$VERIFY_CODE"
assert "NO in-flight effect survived (0 :Phantom rows from the open transaction)" "0" "$(v verify.phantom_after_recovery)"
assert "EVERY acknowledged commit survived, complete and correct" "$ACKED_BATCHES/$ACKED_BATCHES" "$(v verify.acked_batches_intact)"
assert "no transaction was half-applied (atomicity, acked AND undetermined alike)" "0" "$(v verify.partial_batches)"
assert "no fabricated commit appeared (every recovered batch is in the ledger)" "0" "$(v verify.batches_outside_ledger)"
assert "no recovered row came back with a wrong value" "0" "$(v verify.corrupt_batches)"
assert "the verifier's overall verdict is DURABLE" "yes" \
  "$(printf '%s' "$VERIFY_OUT" | grep -q 'VERDICT: DURABLE' && echo yes || echo no)"
ACCOUNTS_AFTER="$(v verify.accounts_present)"
TRANSFERS_AFTER="$(v verify.transfers_present)"
info "recovered: $ACCOUNTS_AFTER accounts + $TRANSFERS_AFTER transfers (acknowledged $ACKED_NODES + $ACKED_RELS, plus $(v verify.undetermined_present) undetermined batch(es) whose ack was lost with the socket)"

# ---- /metrics: the engine recovered without a single recovery panic --------------------------------
METRICS_OK=no
scrape_metrics "$METRICS_AFTER" && METRICS_OK=yes
assert "the recovered server's /metrics is scrapeable" "yes" "$METRICS_OK"
if [ "$METRICS_OK" = "yes" ]; then
  RECOVERY_PANICS="$(metric "$METRICS_AFTER" graphus_engine_recovery_panics_total)"
  STATEMENT_PANICS="$(metric "$METRICS_AFTER" graphus_statement_panics_total)"
  FORCE_DETACHED="$(metric "$METRICS_AFTER" graphus_engine_force_detached_total)"
  COMMITTED_AFTER="$(metric "$METRICS_AFTER" graphus_transactions_committed_total)"
  info "server-side after recovery: recovery_panics=$RECOVERY_PANICS statement_panics=$STATEMENT_PANICS force_detached=$FORCE_DETACHED transactions_committed=$COMMITTED_AFTER"
  assert "graphus_engine_recovery_panics_total == 0 (no engine recovery boundary was breached)" "0" "$RECOVERY_PANICS"
  assert "graphus_statement_panics_total == 0 (no statement panicked on the recovered engine)" "0" "$STATEMENT_PANICS"
  assert "graphus_engine_force_detached_total == 0 (no wedged engine was abandoned)" "0" "$FORCE_DETACHED"
fi

# ---- THE HEADLINE EVIDENCE: what durability actually COST (measured; nothing fabricated) -----------
# This is the durability example, so its headline report must answer "what did durability cost here?"
# from the report alone (rmp #712). Every figure below is measured on the REAL store this run crashed
# and recovered:
#
#   storage.wal_bytes    = the redo log the crash left behind — the WAL bytes that carried the
#                          ACKNOWLEDGED commits to durable media, measured by PATH at the instant of the
#                          kill. Recovery CONSUMES it, so this is the only instant at which it exists;
#                          it is passed to the harness explicitly (--wal-bytes) rather than re-walked
#                          afterwards, which would silently report the post-recovery residual instead.
#   storage.store_bytes  = the data image AFTER replay — the durable graph the redo log was replayed
#                          into (walked at emission time, which is exactly when that is true).
#   storage.bytes_fsynced= the same WAL bytes: every one of them was forced to durable media before its
#                          commit was acknowledged. It is the honest PROXY the harness documents (the
#                          server exposes no fsync-byte counter), and the note says so.
#   memory.peak_rss      = the server's peak RSS across both lifetimes; the REPLAY's own peak is
#                          reported separately, sampled while the WAL was being replayed.
#
# The WAL residual after recovery is reported too — it is what a checkpoint reclaimed the redo log down
# to, and it is a different quantity from the redo log itself, so it gets its own name.
section "Step 5c — the durability vector: what the crash + recovery actually cost on disk"
FP_AFTER="$("$OLTP" --footprint --store-dir "$STORE_DIR")"
WAL_AFTER="$(printf '%s\n' "$FP_AFTER" | sed -n 's/^store\.wal_bytes=//p')"
DATA_AFTER="$(printf '%s\n' "$FP_AFTER" | sed -n 's/^store\.data_bytes=//p')"
info "redo log at the crash : ${WAL_BEFORE} B  (replayed in ${REC_MS} ms)"
info "store image after replay: ${DATA_AFTER} B  (was ${DATA_BEFORE} B at the crash)"
info "WAL residual afterwards : ${WAL_AFTER} B"

LAT_ARGS=()
[ -n "$P50"  ] && LAT_ARGS+=( --p50-ms  "$P50" )
[ -n "$P99"  ] && LAT_ARGS+=( --p99-ms  "$P99" )
[ -n "$P999" ] && LAT_ARGS+=( --p999-ms "$P999" )
# A recovery that finished inside a single 100 ms sample yields NO replay-RSS sample. That is "not
# measured", so it is OMITTED — never reported as a server that replayed a WAL in zero bytes of memory.
RSS_ARGS=()
[ "${RECOVERY_PEAK_RSS:-0}" -gt 0 ] && RSS_ARGS+=( --param "recovery_peak_rss_bytes=$RECOVERY_PEAK_RSS" )
SERVER_UPTIME_SECS="$(LC_ALL=C awk "BEGIN{printf \"%.3f\", ${REC_MS}/1000 + 1}")"
if "$MEASURE" \
    --evidence-dir "$EVIDENCE_DIR" \
    --scenario "durability-crash-recovery" \
    --description "Real graphus-server over UDS: a concurrent OLTP workload with one writer inside an OPEN, never-committed transaction, a hard SIGKILL MID-WORKLOAD, and ARIES WAL-replay recovery. The durability vector is the REAL one: the redo log the crash left behind, the store image it was replayed into, the WAL residual afterwards, the bytes forced to durable media, and the wall-clock + peak RSS of the replay." \
    --pid "$SERVER_PID" \
    --uptime-secs "$SERVER_UPTIME_SECS" \
    --store "$STORE_PATH" \
    --wal "$WAL_PATH" \
    --wal-bytes "$WAL_BEFORE" \
    --bytes-fsynced "$WAL_BEFORE" \
    --nodes "$ACCOUNTS_AFTER" \
    --rels "$TRANSFERS_AFTER" \
    --per-element-costs \
    --peak-rss-bytes "$PEAK_RSS_BYTES" \
    --workload-ops "$ACKED_BATCHES" \
    --workload-secs "$(LC_ALL=C awk "BEGIN{printf \"%.6f\", ${WL_MS}/1000}")" \
    "${LAT_ARGS[@]}" \
    "${RSS_ARGS[@]}" \
    --param "connection=uds-bolt" \
    --param "writers=$WRITERS" \
    --param "crash=sigkill-mid-workload (a writer inside an OPEN, never-committed transaction)" \
    --param "recovery=aries-wal-replay (doublewrite repair -> redo -> undo)" \
    --param "wal_bytes_at_crash=$WAL_BEFORE" \
    --param "wal_bytes_after_recovery=$WAL_AFTER" \
    --param "store_bytes_at_crash=$DATA_BEFORE" \
    --param "doublewrite_bytes=$DWB_BEFORE" \
    --param "recovery_wall_ms=$REC_MS" \
    --param "acked_commits=$ACKED_BATCHES" \
    --param "undetermined_commits=$UNDET" \
    --param "inflight_rows_discarded=$PHANTOM_IN_TXN" \
    --param "inflight_txn_hold_probes=$PHANTOM_PROBES" \
    --param "active_transactions_at_crash=${ACTIVE_TXNS:-unscraped}" \
    --param "acked_commits_per_sec=${TPS:-unmeasured}" \
    --phase "concurrent-oltp-workload=${WL_MS}" \
    --phase "recovery=${REC_MS}" \
    --note "WHAT DURABILITY COST: to make ${ACKED_BATCHES} acknowledged commits durable the server wrote ${WAL_BEFORE} bytes of redo log (storage.wal_bytes — measured by PATH, because the WAL is a DIRECTORY of seg.<lsn> files and a leaf-name classifier reports 0 and hides it). ARIES replayed that log in ${REC_MS} ms into a ${DATA_AFTER}-byte store image (storage.store_bytes, walked AFTER replay); a checkpoint then reclaimed the log down to a ${WAL_AFTER}-byte residual. The doublewrite buffer is a further ${DWB_BEFORE} bytes of FIXED torn-page-repair overhead that does not scale with the graph." \
    --note "storage.wal_bytes is the redo log AT THE CRASH, not at report time. Recovery consumes it, so it exists at exactly one instant: it is measured then (by the same path-classified walker) and passed to the harness explicitly. Re-walking the WAL directory after recovery would report the ${WAL_AFTER}-byte residual instead — a real number describing the wrong thing, and one that would tell the reader a crashed store's redo log cost almost nothing." \
    --note "storage.bytes_fsynced is a PROXY, and a deliberately conservative one: the server exposes no fsync-byte counter, so the figure reported is the redo log that carried the acknowledged commits — every byte of which was forced to durable media before its commit was acknowledged. It is not a syscall-level measurement and is not claimed to be one." \
    --note "RECOVERY COST: ${REC_MS} ms wall-clock from SIGKILL to the UDS being bound again, at a peak replay RSS of ${RECOVERY_PEAK_RSS:-unsampled} bytes (sampled every 100 ms across the restart; omitted entirely if recovery finished inside one sample). memory.peak_rss_bytes is the high-water mark across BOTH server lifetimes (workload + replay). Both are MACHINE-VARIANT and are NOT gated by the committed baseline; the deterministic recovery-work counts live in the sibling DST report (evidence/dst-core/report.json)." \
    --note "MID-WORKLOAD CRASH (deterministic, rmp #712): at the SIGKILL, ${ACKED_BATCHES} commits had been acknowledged, ${UNDET} statement(s) were in flight (their ack never arrived — undetermined by construction), and one writer was inside an OPEN, never-committed transaction holding ${PHANTOM_IN_TXN} uncommitted rows, which it had held across ${PHANTOM_PROBES} answered in-transaction round-trips. The kill was sequenced behind that writer's fresh hold beacon AND the server's own graphus_active_transactions=${ACTIVE_TXNS:-unscraped} gauge. After recovery: every acknowledged commit was present, complete and correct; ZERO uncommitted rows survived; no transaction was half-applied. graphus_engine_recovery_panics_total = ${RECOVERY_PANICS:-unscraped}." \
    --note "REDO IS LOAD-BEARING (negative control): the same crashed store, copied and stripped of its WAL segments, could not reproduce the acknowledged data — so the recovery timed here is real redo work, not a no-op reopen of an already-checkpointed image." \
    ; then
  info "headline durability evidence written to $EVIDENCE_DIR"
else
  info "headline evidence collection FAILED; see output above"
fi
assert "the headline evidence report.json was produced" "yes" \
  "$([ -f "$EVIDENCE_DIR/report.json" ] && echo yes || echo no)"

# The gate this example lacked: its headline report must actually CARRY the durability vector. It used
# to emit `storage: {}` — every on-disk figure absent — while proving durability with 54 assertions
# (and, before schema v3, it emitted them as ZEROS, telling the reader durability cost nothing). These
# assertions CAN fire, which is the whole point (rmp #711: "a gate that cannot fire is the same lie
# wearing a green tick").
report_metric() { # <json> <section> <key> -> the numeric value, or "" if absent
  python3 -c "
import json,sys
r = json.load(open(sys.argv[1]))
v = (r.get(sys.argv[2]) or {}).get(sys.argv[3])
print('' if v is None else v)
" "$1" "$2" "$3" 2>/dev/null
}
if [ -f "$EVIDENCE_DIR/report.json" ] && command -v python3 >/dev/null 2>&1; then
  R_WAL="$(report_metric "$EVIDENCE_DIR/report.json" storage wal_bytes)"
  R_STORE="$(report_metric "$EVIDENCE_DIR/report.json" storage store_bytes)"
  R_FSYNC="$(report_metric "$EVIDENCE_DIR/report.json" storage bytes_fsynced)"
  R_RSS="$(report_metric "$EVIDENCE_DIR/report.json" memory peak_rss_bytes)"
  info "headline storage vector: wal_bytes=$R_WAL store_bytes=$R_STORE bytes_fsynced=$R_FSYNC peak_rss=$R_RSS"
  assert "the headline report carries the REDO LOG the crash left behind (storage.wal_bytes == measured)" \
    "$WAL_BEFORE" "$R_WAL"
  assert "the headline report carries the store image after replay (storage.store_bytes > 0)" "yes" \
    "$([ -n "$R_STORE" ] && [ "${R_STORE%%.*}" -gt 0 ] && echo yes || echo no)"
  assert "the headline report carries the bytes forced to durable media (storage.bytes_fsynced > 0)" "yes" \
    "$([ -n "$R_FSYNC" ] && [ "${R_FSYNC%%.*}" -gt 0 ] && echo yes || echo no)"
  assert "the headline report carries the replay's memory cost (memory.peak_rss_bytes > 0)" "yes" \
    "$([ -n "$R_RSS" ] && [ "${R_RSS%%.*}" -gt 0 ] && echo yes || echo no)"
fi

# ---- Graceful-restart companion: the clean path must be just as intact -----------------------------
section "Step 5d — graceful-restart companion (SIGTERM -> clean shutdown -> reopen)"
info "a crash is the hard path; the clean path must not lose anything either"
stop_server
GRACEFUL=yes
start_server "$SERVER_CONFIG" "$SOCKET" "$SERVER_LOG" || GRACEFUL=no
assert "server restarted after a GRACEFUL (SIGTERM) shutdown" "yes" "$GRACEFUL"
if [ "$GRACEFUL" = "yes" ]; then
  assert "the graph is unchanged across the clean restart (accounts)" \
    "$ACCOUNTS_AFTER" "$(scalar 'MATCH (a:Account) RETURN count(a) AS c')"
  assert "the graph is unchanged across the clean restart (transfers)" \
    "$TRANSFERS_AFTER" "$(scalar 'MATCH ()-[t:TRANSFER]->() RETURN count(t) AS c')"
  assert "still no in-flight effect after the clean restart" "0" \
    "$(scalar 'MATCH (p:Phantom) RETURN count(p) AS c')"
fi
stop_server

# --------------------------------------------------------------------------------------------------
# Step 6 — regression gate vs the committed baseline (deterministic structural metrics)
# --------------------------------------------------------------------------------------------------
# The baseline gates the DST core's STRUCTURAL, deterministic recovery metrics (a pure function of the
# seed range). The real-server run's figures — WAL bytes, recovery time, RSS — are machine-variant and
# are deliberately NOT gated; they are reported, not compared.
if [ "$PROFILE" = "fast" ] && [ "$SEEDS" = "30" ] && [ -f "$BASELINE" ] && [ -f "$DST_REPORT" ]; then
  section "Step 6 — regression gate vs committed baseline (structural deterministic metrics)"
  CMP_OUT="$("$CMP" "$BASELINE" "$DST_REPORT" 2>&1)" || true
  printf '%s\n' "$CMP_OUT" | sed 's/^/  /'
  assert "fresh run matches the committed baseline (structural deterministic metrics)" "yes" \
    "$(printf '%s' "$CMP_OUT" | grep -q 'GRAPHUS_BASELINE_OK' && echo yes || echo no)"
else
  info "baseline gate skipped (only runs at the baseline's fast/30-seed profile)"
fi

# --------------------------------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------------------------------
if [ -f "$EVIDENCE_DIR/report.json" ]; then
  info "HEADLINE evidence (real server, crashed + recovered): $EVIDENCE_DIR/{report.json, report.md}"
fi
if [ -f "$DST_REPORT" ]; then
  info "DST-core evidence (deterministic sweep, in-memory)  : $DST_EVIDENCE_DIR/{report.json, report.md}"
fi
if harness_summary "DURABILITY-CRASH-RECOVERY DEMONSTRATION PASSED"; then
  printf 'Across %s deterministic seeds Graphus ran a concurrent OLTP workload under faults + a crash,\n' "$SEEDS"
  printf 'recovered via ARIES, and upheld all four ACID-durability properties on the recovered engine.\n'
  printf 'EVERY fault the engine can be subjected to — steal/UNDO, torn WAL tail, torn data page\n'
  printf '(doublewrite-repaired), write reordering, write I/O error — recovered SAFE. A REAL server was\n'
  printf 'then SIGKILLed MID-WORKLOAD, with a writer inside an OPEN transaction: every acknowledged\n'
  printf 'commit survived intact, and NOT ONE uncommitted row did.\n'
  exit 0
fi
exit 1
