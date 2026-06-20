#!/usr/bin/env bash
#
# Graphus examples — shared shell helper library.
#
# Every example's `run.sh` sources this file to inherit a common, portable (Linux + macOS) toolkit:
#   * pretty output + assertion helpers (mirrors the house style of social-network-uds/run.sh),
#   * an evidence-directory + metrics-file scaffold (the shell-side seam for `rmp #246/#247`),
#   * phase timing,
#   * a generalized server boot / teardown helper.
#
# It is NOT itself executable; source it:
#
#   source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../_harness" && pwd)/harness.sh"
#
# Heavy metering (peak RSS, CPU, storage sizing) is deliberately STUBBED here with clear
# TODO(rmp #246/#247) markers: the helpers create the evidence dir and a metrics file so the seam is
# real and the smoke example produces output, but the actual numbers are filled in by those tasks
# (and, for the Rust path, by the `graphus-examples-harness` crate).

# --------------------------------------------------------------------------------------------------
# Pretty output helpers (identical palette to social-network-uds/run.sh)
# --------------------------------------------------------------------------------------------------
if [ -t 1 ]; then
  HARNESS_BOLD=$'\e[1m'; HARNESS_GREEN=$'\e[32m'; HARNESS_RED=$'\e[31m'
  HARNESS_BLUE=$'\e[34m'; HARNESS_DIM=$'\e[2m'; HARNESS_RESET=$'\e[0m'
else
  HARNESS_BOLD=''; HARNESS_GREEN=''; HARNESS_RED=''
  HARNESS_BLUE=''; HARNESS_DIM=''; HARNESS_RESET=''
fi

HARNESS_CHECKS=0
HARNESS_FAILURES=0

# section <title> — a bold blue banner.
section() { printf '\n%s== %s ==%s\n' "$HARNESS_BOLD$HARNESS_BLUE" "$1" "$HARNESS_RESET"; }

# info <message> — a dim status line.
info() { printf '%s· %s%s\n' "$HARNESS_DIM" "$1" "$HARNESS_RESET"; }

# assert <description> <expected> <actual> — increments the global check/failure counters.
assert() {
  HARNESS_CHECKS=$((HARNESS_CHECKS + 1))
  if [ "$2" = "$3" ]; then
    printf '  %s✓%s %s %s(= %s)%s\n' \
      "$HARNESS_GREEN" "$HARNESS_RESET" "$1" "$HARNESS_DIM" "$3" "$HARNESS_RESET"
  else
    HARNESS_FAILURES=$((HARNESS_FAILURES + 1))
    printf '  %s✗ %s%s — expected %s[%s]%s, got %s[%s]%s\n' \
      "$HARNESS_RED" "$1" "$HARNESS_RESET" \
      "$HARNESS_BOLD" "$2" "$HARNESS_RESET" "$HARNESS_BOLD" "$3" "$HARNESS_RESET"
  fi
}

# harness_summary <pass-message> — prints the check tally and returns non-zero on any failure.
# Call at the end of an example's run.sh: `harness_summary "DEMO PASSED" || exit 1`.
harness_summary() {
  section "Result"
  printf '%s checks run, %s failures.\n' "$HARNESS_CHECKS" "$HARNESS_FAILURES"
  if [ "$HARNESS_FAILURES" -eq 0 ]; then
    printf '%s%s%s%s\n' "$HARNESS_BOLD" "$HARNESS_GREEN" "${1:-PASSED}" "$HARNESS_RESET"
    return 0
  fi
  printf '%s%sFAILED%s — %s assertion(s) did not hold.\n' \
    "$HARNESS_BOLD" "$HARNESS_RED" "$HARNESS_RESET" "$HARNESS_FAILURES"
  return 1
}

# --------------------------------------------------------------------------------------------------
# Evidence directory + metrics file (shell-side seam)
# --------------------------------------------------------------------------------------------------
# evidence_init <evidence-dir> — creates the (git-ignored) evidence dir and starts a metrics file.
# Sets the global HARNESS_EVIDENCE_DIR and HARNESS_METRICS_FILE for the other evidence_* helpers.
evidence_init() {
  HARNESS_EVIDENCE_DIR="$1"
  mkdir -p "$HARNESS_EVIDENCE_DIR"
  HARNESS_METRICS_FILE="$HARNESS_EVIDENCE_DIR/metrics.txt"
  {
    printf '# Graphus example evidence (shell-collected)\n'
    printf '# host: %s\n' "$(uname -srm 2>/dev/null || echo unknown)"
    printf '# started_unix: %s\n' "$(date +%s)"
    printf '# TODO(rmp #246): peak RSS + CPU metering   TODO(rmp #247): storage sizing\n'
  } > "$HARNESS_METRICS_FILE"
  info "evidence dir: $HARNESS_EVIDENCE_DIR"
}

# evidence_metric <key> <value> — appends a `key=value` line to the metrics file.
evidence_metric() {
  printf '%s=%s\n' "$1" "$2" >> "$HARNESS_METRICS_FILE"
}

# timed_phase <name> -- <command...> — runs the command, records its wall-clock ms as a metric.
# Portable timing via the shell's SECONDS plus a millisecond fallback when `date +%N` is available
# (GNU date / Linux); on macOS without %N it degrades gracefully to whole-second resolution.
timed_phase() {
  local name="$1"; shift
  [ "$1" = "--" ] && shift
  local start end
  start="$(_harness_now_ms)"
  "$@"
  local status=$?
  end="$(_harness_now_ms)"
  evidence_metric "phase.${name}.millis" "$((end - start))"
  info "phase '$name' took $((end - start)) ms"
  return $status
}

# _harness_now_ms — current time in milliseconds (GNU date), or seconds*1000 fallback (macOS BSD).
_harness_now_ms() {
  local ns
  ns="$(date +%s%N 2>/dev/null)"
  case "$ns" in
    *N|'') echo "$(( $(date +%s) * 1000 ))" ;; # %N unsupported → second resolution
    *)     echo "$(( ns / 1000000 ))" ;;
  esac
}

# evidence_capture_rss <pid> — STUB (TODO rmp #246). Records a peak-RSS placeholder so the seam and
# metrics file are real today; the actual /proc + getrusage sampling lands with the metering task.
evidence_capture_rss() {
  local pid="$1"
  local rss=0
  if [ -r "/proc/$pid/status" ]; then
    # Linux best-effort current RSS (kB → bytes). Peak tracking is the rmp #246 job.
    rss="$(awk '/^VmRSS:/ {print $2 * 1024}' "/proc/$pid/status" 2>/dev/null || echo 0)"
  fi
  evidence_metric "memory.rss_bytes_sample" "${rss:-0}"
  evidence_metric "memory.peak_rss_bytes" "0  # TODO(rmp #246)"
}

# evidence_capture_storage <store-dir> <wal-dir> — STUB (TODO rmp #247). Records on-disk sizes if the
# paths exist; otherwise zeros. Full attribution (bytes fsynced, etc.) is the metering task's job.
evidence_capture_storage() {
  local store="$1" wal="$2"
  local store_bytes=0 wal_bytes=0
  [ -e "$store" ] && store_bytes="$(du -sb "$store" 2>/dev/null | awk '{print $1}' || echo 0)"
  [ -e "$wal" ]   && wal_bytes="$(du -sb "$wal" 2>/dev/null | awk '{print $1}' || echo 0)"
  evidence_metric "storage.store_bytes" "${store_bytes:-0}"
  evidence_metric "storage.wal_bytes" "${wal_bytes:-0}"
}

# --------------------------------------------------------------------------------------------------
# Binary location + server lifecycle (generalized from social-network-uds/run.sh)
# --------------------------------------------------------------------------------------------------
# harness_locate_binaries <repo-root> — sets HARNESS_SERVER and HARNESS_CLI, building if absent.
# Honours GRAPHUS_BIN_DIR for pre-built binaries.
harness_locate_binaries() {
  local repo_root="$1"
  local bin_dir="${GRAPHUS_BIN_DIR:-$repo_root/target/release}"
  HARNESS_SERVER="$bin_dir/graphus-server"
  HARNESS_CLI="$bin_dir/graphus-cli"
  if [ ! -x "$HARNESS_SERVER" ] || [ ! -x "$HARNESS_CLI" ]; then
    section "Building graphus-server and graphus-cli (release)"
    ( cd "$repo_root" && cargo build --release -p graphus-server -p graphus-cli )
  fi
  [ -x "$HARNESS_SERVER" ] || { echo "fatal: server not found at $HARNESS_SERVER" >&2; return 2; }
  [ -x "$HARNESS_CLI" ]    || { echo "fatal: cli not found at $HARNESS_CLI" >&2; return 2; }
}

# harness_start_server <config> <socket> <log> — boots the server, waits for the UDS, sets
# HARNESS_SERVER_PID. Fails fast (returns 1) if the process dies during startup.
harness_start_server() {
  local config="$1" socket="$2" log="$3"
  "$HARNESS_SERVER" "$config" >>"$log" 2>&1 &
  HARNESS_SERVER_PID=$!
  local _
  for _ in $(seq 1 100); do
    [ -S "$socket" ] && return 0
    if ! kill -0 "$HARNESS_SERVER_PID" 2>/dev/null; then
      echo "server exited during startup; last log lines:" >&2
      tail -n 15 "$log" >&2
      return 1
    fi
    sleep 0.1
  done
  echo "server did not bind UDS $socket within timeout" >&2
  tail -n 15 "$log" >&2
  return 1
}

# harness_stop_server — graceful SIGTERM shutdown; clears HARNESS_SERVER_PID.
harness_stop_server() {
  if [ -n "${HARNESS_SERVER_PID:-}" ] && kill -0 "$HARNESS_SERVER_PID" 2>/dev/null; then
    kill -TERM "$HARNESS_SERVER_PID" 2>/dev/null || true
    wait "$HARNESS_SERVER_PID" 2>/dev/null || true
  fi
  HARNESS_SERVER_PID=""
}
