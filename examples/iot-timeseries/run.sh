#!/usr/bin/env bash
#
# Graphus IoT / time-series event-graph demonstration — sustained ingest + sliding-window retention
# churn, driven over a REAL WIRE against a REAL `graphus-server`, and measured on disk.
#
# WHAT IT PROVES, AND WHAT IT REFUSES TO HIDE (rmp #694, #713):
#
#   1. THE STORE PLATEAUS.  Under a relentless delete-old/insert-new churn the durable data image stops
#      growing — the engine physically reclaims the tombstoned versions and new inserts reuse the freed
#      space — while the server's own graphus_maintenance_versions_reclaimed_total CLIMBS. Both halves
#      are load-bearing: a flat store alone also describes a workload that wrote nothing, and a climbing
#      counter alone does not rule out unbounded growth.
#
#   2. THE DATABASE ON DISK DOES NOT.  The same run measures the TOTAL durable footprint (store + WAL)
#      and finds it does NOT plateau: the WAL sawtooths between ~2 MB and ~70 MB to protect a 229 KB
#      graph, because WAL disk is freed only in whole 64 MiB SEGMENT units (rmp #706). The store's flat
#      plateau is a true statement about a COMPONENT; published on its own it would create a false
#      impression about the DATABASE. So this example reports both, gates both, and says so out loud.
#
# The write amplification is a FIRST-CLASS, GATED signal here — not a number buried in a report nobody
# opens. `iot_wire_evidence --assert` FAILS the run if the WAL footprint comes back zero while writes
# were committed (the exact rot that made this example publish `wal_bytes: 0` for months), if write
# amplification exceeds its ceiling, if the total footprint exceeds its ceiling, or if a run long enough
# to seal a WAL segment never actually gets any WAL disk back.
#
# TWO INSTRUMENTS, AND WHICH ONE IS THE EVIDENCE:
#
#   evidence/         PRIMARY — the FILE-BACKED, over-the-wire run against a REAL server (a real
#                     FileBlockDevice, a real segmented WAL on disk). This is what the server did.
#   evidence-mirror/  CONTROL — a deterministic in-process mirror of the same churn over an IN-MEMORY
#                     device and WAL. It has no store file, no WAL file and no fsync, so it can say
#                     nothing about durable bytes — but it gives a byte-reproducible footprint curve
#                     that pins the reclamation logic itself. A valuable instrument; NOT the headline.
#
# It runs in TWO modes (auto-detected via the shared external-target seam in `_harness/harness.sh`):
#
#   LOCAL (default)   — self-boots a real `graphus-server` (Bolt-over-UDS + plaintext-loopback REST),
#                       carves out an isolated database, drives the churn over the wire, issues
#                       CHECKPOINT DATABASE, and measures the REAL on-disk footprint (path-classified:
#                       data image / doublewrite / WAL / catalog), the REAL cumulative WAL volume, the
#                       server's CPU/RSS and kernel write_bytes from /proc, plus the /metrics deltas.
#   EXTERNAL (attach) — when ANY of GRAPHUS_TARGET_{BOLT,REST,UDS} is set, attaches to an ALREADY-RUNNING
#                       instance over Bolt, carves out an isolated database, drives the SAME churn, and
#                       collects server-side evidence from /metrics. The store files and /proc are on
#                       another host, so those vectors are ABSENT from the report — never zero-filled.
#
# Usage:
#   examples/iot-timeseries/run.sh                          # local self-boot; wire = `reclaim` profile
#   IOT_WIRE_PROFILE=fast  examples/iot-timeseries/run.sh   # a SHORTER wire run — see the warning it prints
#   IOT_WIRE_PROFILE=soak  examples/iot-timeseries/run.sh   # long, SUSTAINED wire run (300 ticks)
#   IOT_PROFILE=large      examples/iot-timeseries/run.sh   # scale up the in-memory CONTROL mirror
#   RUN_WIRE=0             examples/iot-timeseries/run.sh   # control mirror ONLY (no primary evidence)
#   GRAPHUS_TARGET_BOLT=bolt://127.0.0.1:7687 GRAPHUS_TARGET_REST=http://127.0.0.1:7474 \
#     GRAPHUS_TARGET_USER=u GRAPHUS_TARGET_PASSWORD=p  examples/iot-timeseries/run.sh   # attach
#
# Requirements: a Unix host (Linux/macOS), bash, curl. The /proc server sampling is Linux-specific (the
# run still works on macOS; those two fields are then simply absent). No node / openssl needed.

set -euo pipefail

# --------------------------------------------------------------------------------------------------
# Shared harness: build seam, external-target detection, isolated-DB create/drop, /metrics scrape.
# --------------------------------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../_harness/harness.sh
source "$(cd "$SCRIPT_DIR/../_harness" && pwd)/harness.sh"
export HARNESS_SCENARIO="iot-timeseries"

# --------------------------------------------------------------------------------------------------
# Pretty output helpers (house style)
# --------------------------------------------------------------------------------------------------
if [ -t 1 ]; then
  BOLD=$'\e[1m'; GREEN=$'\e[32m'; RED=$'\e[31m'; BLUE=$'\e[34m'; YELLOW=$'\e[33m'; DIM=$'\e[2m'; RESET=$'\e[0m'
else
  BOLD=''; GREEN=''; RED=''; BLUE=''; YELLOW=''; DIM=''; RESET=''
fi
CHECKS=0
FAILURES=0
section() { printf '\n%s== %s ==%s\n' "$BOLD$BLUE" "$1" "$RESET"; }
info()    { printf '%s· %s%s\n' "$DIM" "$1" "$RESET"; }
warn()    { printf '%s! %s%s\n' "$YELLOW" "$1" "$RESET"; }
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
# kv <summary-line> <key> — pull a `key=value` token out of a generator summary line.
kv() { printf '%s' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -n1; }
# jnum <json> <key> — pull a flat numeric "key":N field out of a JSON blob (no jq dependency).
jnum() { printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\\([0-9][0-9]*\\).*/\\1/p" | head -n1; }
# prom <file> <metric> — read a Prometheus counter's value out of a scraped /metrics text file.
prom() { awk -v m="$2" '$1 == m { print $2; exit }' "$1" 2>/dev/null; }

MODE="$(harness_target_mode)"   # external iff GRAPHUS_TARGET_{BOLT,REST,UDS} is set at entry

# --------------------------------------------------------------------------------------------------
# Profiles + knobs
#
# The WIRE run defaults to the `reclaim` profile, and that default is load-bearing (rmp #713). One
# reading costs ~21.5 KB of WAL, so the older `fast` profile's 3,000 readings produced ~59 MB of WAL —
# stopping just BELOW the 64 MiB segment seal threshold. Its WAL therefore climbed monotonically and not
# one byte was ever reclaimed: it could neither observe reclamation nor prove its absence benign. An
# example whose headline is "reclamation holds the footprint flat" must not be sized so that the
# reclamation it claims never runs. `reclaim` (140 ticks, 7,000 readings, ~150 MB of WAL, ~9.5 s) seals
# and frees TWO segments, and still fits a CI budget (rmp #704).
# --------------------------------------------------------------------------------------------------
PROFILE="${IOT_PROFILE:-fast}"                     # the in-memory CONTROL mirror's profile
WIRE_PROFILE="${IOT_WIRE_PROFILE:-reclaim}"        # the FILE-BACKED wire run's profile (the PRIMARY)
RUN_WIRE="${RUN_WIRE:-1}"
IOT_TICKS="${IOT_TICKS:-}"                         # override the mirror's tick count
WIRE_CLIENTS="${IOT_WIRE_CLIENTS:-2}"              # concurrent ingest connections (sensor-sharded)
WIRE_CHECKPOINT_EVERY="${IOT_CHECKPOINT_EVERY:-5}" # 0 => rely on the background cadence alone

# Ceilings the wire gate holds the (known-bad) durability cost under. They are UPPER BOUNDS just above
# today's measured values, not targets: a bound cannot be satisfied by regressing, and it does not have
# to be relaxed to accept a fix. Measured on the `reclaim` profile: write amplification ~799x, peak
# durable footprint ~347x the data image.
MAX_WRITE_AMP="${IOT_MAX_WRITE_AMP:-1000}"
MAX_FOOTPRINT_RATIO="${IOT_MAX_FOOTPRINT_RATIO:-450}"

# --------------------------------------------------------------------------------------------------
# Locate (or BUILD) the binaries.
#
# harness_build builds UNCONDITIONALLY (cargo is incremental, so it is a no-op when nothing changed).
# The tempting `[ ! -x "$BIN" ]` guard this script used to have silently ran a STALE binary after any
# source edit — so the evidence described code that was no longer the code under test. For a suite whose
# entire purpose is trustworthy evidence about the CURRENT server, that is the worst failure mode there
# is. GRAPHUS_BIN_DIR remains the escape hatch for prebuilt binaries.
# --------------------------------------------------------------------------------------------------
BIN_DIR="${GRAPHUS_BIN_DIR:-$REPO_ROOT/target/release}"
GEN="$BIN_DIR/iot_gen"
CHURN="$BIN_DIR/iot_churn"
EVIDENCE_BIN="$BIN_DIR/iot_evidence"
CMP_BIN="$BIN_DIR/iot_baseline_cmp"
WIRE_BIN="$BIN_DIR/iot_wire"
WIRE_EVIDENCE_BIN="$BIN_DIR/iot_wire_evidence"
SERVER="$BIN_DIR/graphus-server"

harness_build "the iot-timeseries generator + in-process churn mirror + evidence + baseline gate (release)" \
  --release -p graphus-iot-gen --features churn \
  --bin iot_gen --bin iot_churn --bin iot_evidence --bin iot_baseline_cmp
if [ "$RUN_WIRE" = "1" ]; then
  harness_build "the iot-timeseries WIRE driver + wire-evidence gate (release, client-only, no engine)" \
    --release -p graphus-iot-gen --no-default-features --features wire \
    --bin iot_wire --bin iot_wire_evidence
  if [ "$MODE" = local ]; then
    harness_build "graphus-server (release)" --release -p graphus-server
  fi
fi
for b in "$GEN" "$CHURN" "$EVIDENCE_BIN" "$CMP_BIN"; do
  [ -x "$b" ] || { echo "${RED}fatal: required binary not found at $b${RESET}" >&2; exit 2; }
done

# --------------------------------------------------------------------------------------------------
# Workspace. `evidence/` is the PRIMARY report (the real server, over the wire); `evidence-mirror/` is
# the deterministic in-memory CONTROL. Both are wiped up front so a stale report from an earlier run can
# never be mistaken for this one's evidence.
# --------------------------------------------------------------------------------------------------
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/graphus-iot-XXXXXX")"
EVIDENCE_DIR="$SCRIPT_DIR/evidence"                 # PRIMARY: the real server
MIRROR_EVIDENCE_DIR="$SCRIPT_DIR/evidence-mirror"   # CONTROL: the deterministic in-memory mirror
BASELINE="$SCRIPT_DIR/baseline.json"                # gates the PRIMARY
MIRROR_BASELINE="$SCRIPT_DIR/baseline-mirror.json"  # gates the CONTROL
SAMPLES_JSON="$WORKDIR/samples.json"
WIRE_SAMPLES="$WORKDIR/wire_samples.json"
METRICS_BEFORE="$WORKDIR/metrics_before.prom"
METRICS_AFTER="$WORKDIR/metrics_after.prom"
STORE_DIR="$WORKDIR/server-data"
SERVER_LOG="$WORKDIR/server.log"
rm -rf "$EVIDENCE_DIR" "$MIRROR_EVIDENCE_DIR"
mkdir -p "$EVIDENCE_DIR" "$MIRROR_EVIDENCE_DIR"

SERVER_PID=""
cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  harness_target_drop_db >/dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

# ==================================================================================================
# Step 1 — deterministic generator (byte-identical per seed)
# ==================================================================================================
section "Step 1 — deterministic time-series churn generator"
GEN_OUT="$("$GEN" --profile "$PROFILE" --out-dir "$WORKDIR/gen1")"
printf '%s\n' "$GEN_OUT" | sed 's/^/  /'
assert "stream.cypher generated" "yes" "$([ -s "$WORKDIR/gen1/stream.cypher" ] && echo yes || echo no)"

"$GEN" --profile "$PROFILE" --out-dir "$WORKDIR/gen2" >/dev/null
if diff -q "$WORKDIR/gen1/stream.cypher" "$WORKDIR/gen2/stream.cypher" >/dev/null; then
  assert "generator is byte-identical per seed" "yes" "yes"
else
  assert "generator is byte-identical per seed" "yes" "no"
fi

GEN_WINDOW="$(kv "$GEN_OUT" window)"

# ==================================================================================================
# Step 2 — THE HEADLINE (PRIMARY EVIDENCE): file-backed, over-the-wire churn against a REAL server.
#
# This is what a reader of this example must see: what the SERVER did, on a real disk. Everything below
# — the durable bytes, the WAL volume, the write amplification, the total footprint — is measured here
# and nowhere else. The in-memory mirror (step 3) cannot produce any of it.
# ==================================================================================================
WIRE_OK=1
WIRE_DB=""
if [ "$RUN_WIRE" != "1" ]; then
  section "Step 2 — file-backed wire run SKIPPED (RUN_WIRE=0)"
  warn "RUN_WIRE=0 skips the example's PRIMARY evidence: no real server, no durable bytes, no WAL,"
  warn "no write amplification. Only the in-memory CONTROL mirror will run. Do not quote this as"
  warn "storage evidence — evidence/ will not be written."
  WIRE_OK=0
elif [ ! -x "$WIRE_BIN" ] || [ ! -x "$WIRE_EVIDENCE_BIN" ]; then
  section "Step 2 — file-backed wire run SKIPPED (wire binaries unavailable)"
  WIRE_OK=0
  FAILURES=$((FAILURES + 1))
else
  if [ "$MODE" = external ]; then
    section "Step 2 — attach to the running Graphus instance (the store lives on the target)"
    if [ -z "${GRAPHUS_TARGET_REST:-}${GRAPHUS_TARGET_METRICS:-}" ]; then
      echo "${RED}fatal: external mode needs GRAPHUS_TARGET_REST (or _METRICS) for DB isolation + /metrics${RESET}" >&2
      exit 2
    fi
    WIRE_USER="${GRAPHUS_TARGET_USER:-graphus}"
    WIRE_PW="${GRAPHUS_TARGET_PASSWORD:-graphus-local}"
    # Either Bolt transport attaches: TCP(+TLS) for a remote instance, or UDS for an already-running
    # instance on THIS host (the harness contract carries both). Bolt-TCP is preferred when both are
    # given. Note the server MANDATES TLS on Bolt-TCP, so a plaintext local instance is reached over UDS.
    if [ -n "${GRAPHUS_TARGET_BOLT:-}" ]; then
      WIRE_TRANSPORT=(--bolt "$GRAPHUS_TARGET_BOLT")
      info "attaching over Bolt-TCP: $GRAPHUS_TARGET_BOLT"
    elif [ -n "${GRAPHUS_TARGET_UDS:-}" ]; then
      WIRE_TRANSPORT=(--socket "$GRAPHUS_TARGET_UDS")
      info "attaching over Bolt-over-UDS: $GRAPHUS_TARGET_UDS"
    else
      echo "${RED}fatal: external mode needs GRAPHUS_TARGET_BOLT (bolt://host:port) or GRAPHUS_TARGET_UDS (a socket path)${RESET}" >&2
      exit 2
    fi
    # The store files and /proc belong to the TARGET, and we do not presume to know where they are — even
    # when the target happens to be on this host. Those vectors are therefore ABSENT from the attach-mode
    # report, never zero-filled; the server-side evidence is /metrics.
    WIRE_LOCAL_FLAGS=()
  else
    section "Step 2 — boot graphus-server (Bolt-over-UDS + plaintext-loopback REST) for the file-backed run"
    [ -x "$SERVER" ] || { echo "${RED}fatal: server binary not found at $SERVER${RESET}" >&2; exit 2; }
    free_port() {
      if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'
      else echo 47675; fi
    }
    REST_PORT="$(free_port)"
    REST_ADDR="127.0.0.1:$REST_PORT"
    SOCKET="$WORKDIR/graphus.sock"
    CONFIG="$WORKDIR/graphus.toml"
    WIRE_USER="iot"
    WIRE_PW="iot-timeseries-demo-pw-1"
    cat > "$CONFIG" <<EOF
# Generated by examples/iot-timeseries/run.sh — a UDS + plaintext-loopback-REST dev configuration.
store_path = "$STORE_DIR"
default_database = "graphus"
buffer_pool_pages = 2048
uds_path = "$SOCKET"
rest_addr = "$REST_ADDR"
jwt_secret = "graphus-iot-timeseries-example-uds-rest-secret-32+"
# Plaintext loopback REST (dev/test only) so the /metrics scrape + DB isolation need no TLS/cert.
allow_insecure_network = true

[auth]
admin_user = "$WIRE_USER"
admin_password = "$WIRE_PW"
admin_uid = $(id -u)
EOF
    "$SERVER" "$CONFIG" >>"$SERVER_LOG" 2>&1 &
    SERVER_PID=$!
    BOUND=no
    for _ in $(seq 1 150); do
      [ -S "$SOCKET" ] && { BOUND=yes; break; }
      kill -0 "$SERVER_PID" 2>/dev/null || break
      sleep 0.1
    done
    assert "server bound the UDS socket" "yes" "$BOUND"
    if [ "$BOUND" != yes ]; then
      echo "${RED}server did not come up; last log lines:${RESET}" >&2
      tail -n 20 "$SERVER_LOG" >&2 || true
      exit 1
    fi
    info "REST on $REST_ADDR, UDS on $SOCKET, server pid $SERVER_PID"
    # Point the shared external-target seam at OUR server, so ONE code path (login, isolated DB,
    # /metrics scrape) drives both modes.
    export GRAPHUS_TARGET_REST="http://$REST_ADDR"
    export GRAPHUS_TARGET_USER="$WIRE_USER"
    export GRAPHUS_TARGET_PASSWORD="$WIRE_PW"
    export GRAPHUS_TARGET_SYSTEM_DB="graphus"
    unset HARNESS_TARGET_TOKEN 2>/dev/null || true
    WIRE_TRANSPORT=(--socket "$SOCKET")
  fi

  # Authenticate once in THIS shell so every later $(harness_target_login) subshell reuses the token.
  harness_target_login >/dev/null 2>&1 || { info "could not authenticate against the target"; WIRE_OK=0; }

  # An isolated database, created here and dropped by the exit trap (via the PID-keyed state file).
  if [ "$WIRE_OK" = 1 ]; then
    WIRE_DB="$(harness_target_ensure_db)" || WIRE_DB=""
    assert "isolated wire database resolved" "yes" "$([ -n "$WIRE_DB" ] && echo yes || echo no)"
    [ -n "$WIRE_DB" ] || WIRE_OK=0
  fi

  # In LOCAL mode we can now name the database's on-disk directory + the server pid: the storage and
  # /proc evidence. A non-default database lives at <store_path>/databases/<name>.
  if [ "$WIRE_OK" = 1 ] && [ "$MODE" = local ]; then
    WIRE_LOCAL_FLAGS=(--db-store-path "$STORE_DIR/databases/$WIRE_DB" --server-pid "$SERVER_PID")
  fi
fi

if [ "$WIRE_OK" = 1 ]; then
  section "Step 2a — file-backed ingest + retention churn over the wire into '$WIRE_DB' ($WIRE_PROFILE profile)"
  if [ "$WIRE_PROFILE" = "fast" ]; then
    warn "the 'fast' wire profile writes ~59 MB of WAL — just BELOW the 64 MiB segment seal threshold —"
    warn "so it can never observe WAL reclamation. Its WAL climbs monotonically and nothing comes back."
    warn "That is a real (and reportable) observation, but only the default 'reclaim' profile shows the"
    warn "full seal-and-free cycle. The gate will say which of the two this run measured."
  fi

  # 1. Scrape /metrics BEFORE the workload. The reclamation counters' delta over this window is the
  #    server-side half of the store-plateau claim.
  harness_scrape_metrics "$METRICS_BEFORE" || info "metrics-before scrape failed (non-fatal)"
  assert "/metrics scraped before the churn" "yes" "$([ -s "$METRICS_BEFORE" ] && echo yes || echo no)"

  # 2. Drive the churn: concurrent sensor-sharded ingest + windowed retention DELETE + the real
  #    CHECKPOINT DATABASE operator trigger, sampling the REAL on-disk footprint every tick.
  set +e
  "$WIRE_BIN" "${WIRE_TRANSPORT[@]}" --user "$WIRE_USER" --password "$WIRE_PW" --db "$WIRE_DB" \
    --profile "$WIRE_PROFILE" --ingest-clients "$WIRE_CLIENTS" \
    --checkpoint-every "$WIRE_CHECKPOINT_EVERY" \
    --samples "$WIRE_SAMPLES" --scenario "iot-timeseries" \
    "${WIRE_LOCAL_FLAGS[@]}" 2>&1 | tee "$WORKDIR/wire.log" | sed 's/^/  /'
  set -e
  assert "file-backed churn completed over the wire (all wire checks passed)" "yes" \
    "$(grep -q 'GRAPHUS_IOT_WIRE_OK' "$WORKDIR/wire.log" && echo yes || echo no)"

  # 3. Scrape /metrics AFTER the workload.
  harness_scrape_metrics "$METRICS_AFTER" || info "metrics-after scrape failed (non-fatal)"
  assert "/metrics scraped after the churn" "yes" "$([ -s "$METRICS_AFTER" ] && echo yes || echo no)"

  # 4. The reclamation counters MUST have climbed. This is the half of the claim the store-file length
  #    cannot make on its own: a flat store also describes a workload that never wrote anything.
  #
  #    Note what these counters do NOT say: they count MVCC versions freed inside the STORE, not WAL
  #    segments. They climb happily while zero bytes of WAL disk come back — so a green counter beside a
  #    growing WAL is not a paradox, it is the #706 defect. The WAL's own reclamation is measured
  #    separately, by watching the on-disk WAL actually shrink.
  if [ -s "$METRICS_BEFORE" ] && [ -s "$METRICS_AFTER" ]; then
    R_BEFORE="$(prom "$METRICS_BEFORE" graphus_maintenance_versions_reclaimed_total)"
    R_AFTER="$(prom "$METRICS_AFTER" graphus_maintenance_versions_reclaimed_total)"
    C_BEFORE="$(prom "$METRICS_BEFORE" graphus_maintenance_checkpoints_total)"
    C_AFTER="$(prom "$METRICS_AFTER" graphus_maintenance_checkpoints_total)"
    R_DELTA=$(( ${R_AFTER:-0} - ${R_BEFORE:-0} ))
    C_DELTA=$(( ${C_AFTER:-0} - ${C_BEFORE:-0} ))
    info "store reclamation over the workload window: versions_reclaimed +$R_DELTA, checkpoints +$C_DELTA"
    assert "graphus_maintenance_versions_reclaimed_total CLIMBED" "yes" \
      "$([ "$R_DELTA" -gt 0 ] && echo yes || echo no)"
    assert "graphus_maintenance_checkpoints_total CLIMBED (the CHECKPOINT DATABASE trigger is counted)" "yes" \
      "$([ "$C_DELTA" -gt 0 ] && echo yes || echo no)"
  fi

  # 5. Fold samples + /metrics into the PRIMARY evidence report, and GATE the invariants — including the
  #    durability cost, which is the point of this example and is no longer allowed to rot to zero.
  section "Step 2b — PRIMARY evidence report + invariant gate (store plateaus; durability cost measured + bounded)"
  set +e
  "$WIRE_EVIDENCE_BIN" --samples "$WIRE_SAMPLES" --evidence-dir "$EVIDENCE_DIR" \
    --metrics-before "$METRICS_BEFORE" --metrics-after "$METRICS_AFTER" \
    --plateau-factor 1.10 --min-ingest-to-window 3.0 \
    --max-write-amplification "$MAX_WRITE_AMP" --max-footprint-ratio "$MAX_FOOTPRINT_RATIO" \
    --assert 2>&1 | tee "$WORKDIR/wire_ev.log" | sed 's/^/  /'
  set -e
  assert "PRIMARY evidence report + invariant gate passed" "yes" \
    "$(grep -q 'GRAPHUS_IOT_WIRE_EVIDENCE_OK' "$WORKDIR/wire_ev.log" && echo yes || echo no)"
  assert "PRIMARY report.json produced" "yes" \
    "$([ -f "$EVIDENCE_DIR/report.json" ] && echo yes || echo no)"
  assert "PRIMARY report.json carries the server_metrics deltas" "yes" \
    "$([ -f "$EVIDENCE_DIR/report.json" ] && grep -q '"server_metrics"' "$EVIDENCE_DIR/report.json" && echo yes || echo no)"

  # 6. THE DURABILITY COST, stated in the run's own output — not left for someone to find in a JSON.
  if [ -f "$EVIDENCE_DIR/report.json" ] && [ "$MODE" = local ]; then
    WIRE_JSON="$(cat "$EVIDENCE_DIR/report.json")"
    W_STORE="$(jnum "$WIRE_JSON" store_bytes)"
    W_WAL="$(jnum "$WIRE_JSON" wal_bytes)"
    W_FSYNC="$(jnum "$WIRE_JSON" bytes_fsynced)"

    section "Step 2c — WHAT DURABILITY COST (the finding this example exists to surface)"
    printf '  %sstore (data image, PLATEAUED)%s     %s B\n' "$BOLD" "$RESET" "${W_STORE:-?}"
    printf '  %sWAL residual on disk%s              %s B\n' "$BOLD" "$RESET" "${W_WAL:-?}"
    printf '  %sWAL written (cumulative, fsynced)%s %s B\n' "$BOLD" "$RESET" "${W_FSYNC:-?}"
    # The gate emits one dedicated, greppable FINDING line so the durability cost is impossible to miss.
    sed -n 's/^ *iot_wire_evidence: FINDING /  /p' "$WORKDIR/wire_ev.log" \
      | tr '|' '\n' | sed 's/^ *//;s/^/  /' || true

    # THE ANTI-ROT ASSERTIONS (rmp #713). This example published wal_bytes=0 / bytes_fsynced=0 /
    # write_amplification=0 for months while asserting a green plateau, because the WAL is a DIRECTORY
    # and a leaf-name classifier scored every segment as store. A commit is not durable until its redo
    # record is fsynced — so on a file-backed run that committed thousands of writes, a zero here is
    # impossible, and it now FAILS the example rather than passing as a "measurement".
    assert "wal_bytes is REAL and non-zero (writes were committed, so a WAL MUST exist)" "yes" \
      "$([ "${W_WAL:-0}" -gt 0 ] && echo yes || echo no)"
    assert "bytes_fsynced is REAL and non-zero (the cumulative durable-sync volume)" "yes" \
      "$([ "${W_FSYNC:-0}" -gt 0 ] && echo yes || echo no)"
    assert "write_amplification is MEASURED (present in the report, not omitted)" "yes" \
      "$(printf '%s' "$WIRE_JSON" | grep -q '"write_amplification"' && echo yes || echo no)"
    assert "the report states the TOTAL durable footprint, not just the store" "yes" \
      "$(printf '%s' "$WIRE_JSON" | grep -q 'durable_footprint_peak_bytes' && echo yes || echo no)"
  elif [ "$MODE" = external ]; then
    info "attach mode: the store + /proc live on the target, so those vectors are ABSENT (not zeroed);"
    info "the server-side evidence for this run is the /metrics delta in the report."
  fi

  # 7. The committed-baseline regression gate over the PRIMARY report (local runs only — an external run
  #    cannot measure the storage vectors, so it is never a baseline candidate).
  if [ "$MODE" = local ] && [ -f "$EVIDENCE_DIR/report.json" ]; then
    if [ "$WIRE_PROFILE" = "reclaim" ] && [ -f "$BASELINE" ]; then
      section "Step 2d — regression gate: PRIMARY report vs the committed baseline"
      CMP_OUT="$("$CMP_BIN" "$BASELINE" "$EVIDENCE_DIR/report.json" 2>&1)" || true
      printf '%s\n' "$CMP_OUT" | sed 's/^/  /'
      assert "fresh PRIMARY run is within baseline thresholds" "yes" \
        "$(printf '%s' "$CMP_OUT" | grep -q 'GRAPHUS_BASELINE_OK' && echo yes || echo no)"
    elif [ ! -f "$BASELINE" ]; then
      info "no committed baseline.json yet — skipping the PRIMARY regression gate."
    else
      info "PRIMARY baseline gate skipped: the baseline is captured on the 'reclaim' profile, and this"
      info "run used '$WIRE_PROFILE' (a different workload is not baseline-comparable)."
    fi
  fi
fi

# ==================================================================================================
# Step 3 — the CONTROL: the deterministic in-memory mirror.
#
# The same churn, run inline against the REAL engine but over an IN-MEMORY device and WAL. It has no
# store file, no WAL file and no fsync, so it can measure NONE of the durable bytes above — and it does
# not pretend to: those fields are simply absent from its report. What it gives instead is a
# byte-reproducible footprint curve, which pins the reclamation logic itself against a committed
# baseline. A genuine instrument; the CONTROL, not the headline.
# ==================================================================================================
section "Step 3 — CONTROL: deterministic in-memory mirror of the same churn ($PROFILE profile)"
info "in-memory device + WAL: no store file, no WAL file, no fsync. It measures the reclamation LOGIC"
info "byte-reproducibly; it CANNOT measure durable bytes. Step 2 is the storage evidence."
CHURN_OUT="$("$CHURN" --profile "$PROFILE" --json "$SAMPLES_JSON" 2>&1)" || true
printf '%s\n' "$CHURN_OUT" | grep -v '^GRAPHUS_IOT_SAMPLES' | sed 's/^/  /'

assert "mirror reached steady state AND its footprint plateaued" "yes" \
  "$(printf '%s' "$CHURN_OUT" | grep -q 'GRAPHUS_IOT_CHURN_OK' && echo yes || echo no)"

SAMPLES="$(cat "$SAMPLES_JSON" 2>/dev/null || echo '{}')"
PAGE_HW="$(jnum "$SAMPLES" page_high_water)"
STEADY_MIN="$(jnum "$SAMPLES" steady_min_bytes)"
STEADY_MAX="$(jnum "$SAMPLES" steady_max_bytes)"
TOTAL_INGESTED="$(jnum "$SAMPLES" total_ingested)"
info "page_high_water=$PAGE_HW  steady_footprint=[$STEADY_MIN, $STEADY_MAX]B  total_ingested=$TOTAL_INGESTED  window=$GEN_WINDOW"

# Independent structural checks on the committed-shape JSON the evidence tooling consumes.
if [ -n "$STEADY_MIN" ] && [ -n "$STEADY_MAX" ] && [ "${STEADY_MIN:-0}" -gt 0 ]; then
  BOUNDED="$(awk -v a="$STEADY_MAX" -v b="$STEADY_MIN" 'BEGIN{print (a <= 1.5*b) ? "yes":"no"}')"
  assert "mirror footprint plateau: post-warmup max within 1.5x of min" "yes" "$BOUNDED"
fi
if [ -n "$TOTAL_INGESTED" ] && [ -n "$GEN_WINDOW" ] && [ "${GEN_WINDOW:-0}" -gt 0 ]; then
  ENOUGH="$(awk -v t="$TOTAL_INGESTED" -v w="$GEN_WINDOW" 'BEGIN{print (t >= 3*w) ? "yes":"no"}')"
  assert "mirror ingested >= 3x the retention window" "yes" "$ENOUGH"
fi

section "Step 3a — CONTROL evidence report + its own committed baseline"
EVIDENCE_ARGS=( --evidence-dir "$MIRROR_EVIDENCE_DIR" --profile "$PROFILE" )
[ -n "$IOT_TICKS" ] && EVIDENCE_ARGS+=( --ticks "$IOT_TICKS" )
EVIDENCE_OUT="$("$EVIDENCE_BIN" "${EVIDENCE_ARGS[@]}" 2>&1)" || true
printf '%s\n' "$EVIDENCE_OUT" | sed 's/^/  /'
assert "CONTROL report.json was produced" "yes" \
  "$([ -f "$MIRROR_EVIDENCE_DIR/report.json" ] && echo yes || echo no)"
assert "CONTROL report.md was produced" "yes" \
  "$([ -f "$MIRROR_EVIDENCE_DIR/report.md" ] && echo yes || echo no)"

# The mirror's value IS its byte-reproducibility, so its gate is tight on the structural plateau metrics
# and effectively infinite on the machine-variant families (RSS / throughput / latency / CPU / wall-time).
# A custom --ticks run is not baseline-comparable (longer series, same plateau), so the gate is skipped.
if [ "$PROFILE" = "fast" ] && [ -z "$IOT_TICKS" ] && [ -f "$MIRROR_BASELINE" ] && [ -f "$MIRROR_EVIDENCE_DIR/report.json" ]; then
  CMP_OUT="$("$CMP_BIN" "$MIRROR_BASELINE" "$MIRROR_EVIDENCE_DIR/report.json" 2>&1)" || true
  printf '%s\n' "$CMP_OUT" | sed 's/^/  /'
  assert "fresh CONTROL run is within baseline thresholds" "yes" \
    "$(printf '%s' "$CMP_OUT" | grep -q 'GRAPHUS_BASELINE_OK' && echo yes || echo no)"
elif [ ! -f "$MIRROR_BASELINE" ]; then
  info "no committed baseline-mirror.json yet — skipping the CONTROL regression gate."
else
  info "CONTROL regression gate skipped (non-fast profile or custom --ticks: not baseline-comparable)."
fi

# ==================================================================================================
# Step 4 — the no-GC contrast (informational): the linear-growth curve reclamation flattens
# ==================================================================================================
section "Step 4 — no-GC contrast (informational): the footprint grows without a reclamation pass"
NOGC_OUT="$("$CHURN" --profile "$PROFILE" --no-gc --ticks 12 2>&1)" || true
printf '%s\n' "$NOGC_OUT" | grep -E 'no-GC contrast|footprint grew' | sed 's/^/  /'

# ==================================================================================================
# Summary
# ==================================================================================================
section "Result"
printf '%s checks run, %s failures.  (mode: %s, wire profile: %s, mirror profile: %s)\n' \
  "$CHECKS" "$FAILURES" "$MODE" "$WIRE_PROFILE" "$PROFILE"
[ -f "$EVIDENCE_DIR/report.json" ] && info "PRIMARY evidence (the real server): $EVIDENCE_DIR/{report.json, report.md}"
[ -f "$MIRROR_EVIDENCE_DIR/report.json" ] && info "CONTROL evidence (in-memory mirror): $MIRROR_EVIDENCE_DIR/{report.json, report.md}"
if [ "$FAILURES" -eq 0 ]; then
  printf '%s%sIOT-TIMESERIES DEMONSTRATION PASSED%s — the seeded generator is byte-identical; the\n' "$BOLD" "$GREEN" "$RESET"
  printf 'sustained ingest+retention churn reached a steady state (live count ~ window of %s).\n' "${GEN_WINDOW:-?}"
  if [ "$WIRE_OK" = 1 ] && [ "$MODE" = local ]; then
    printf 'Driven over a REAL WIRE against a REAL SERVER with a real store file and a real segmented\n'
    printf 'WAL: the on-disk STORE PLATEAUED while the server’s own reclamation counters CLIMBED —\n'
    printf 'reclaimed space is demonstrably reused, not leaked. And the durability that cost is now\n'
    printf 'MEASURED and BOUNDED rather than omitted: see "WHAT DURABILITY COST" above, and the\n'
    printf 'FINDING note in the report — the store plateaus, but the DATABASE ON DISK DOES NOT,\n'
    printf 'because WAL disk is freed only in whole 64 MiB segments (rmp #706).\n'
  elif [ "$WIRE_OK" = 1 ]; then
    printf 'Driven over the wire against an ATTACHED instance: the store and /proc live on the target,\n'
    printf 'so the storage vectors are absent by construction; the server-side evidence is /metrics.\n'
  else
    printf 'Only the in-memory CONTROL mirror ran — its footprint PLATEAUED (page high-water %s), but\n' "${PAGE_HW:-?}"
    printf 'NO durable-byte evidence was collected. This is not a storage result.\n'
  fi
  exit 0
else
  printf '%s%sIOT-TIMESERIES DEMONSTRATION FAILED%s — %s assertion(s) did not hold.\n' "$BOLD" "$RED" "$RESET" "$FAILURES"
  exit 1
fi
