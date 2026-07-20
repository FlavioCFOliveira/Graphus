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
# Building the example's binaries (shell-side seam)
# --------------------------------------------------------------------------------------------------
# harness_build <label> <cargo args...> — builds the binaries an example drives.
#
# It builds UNCONDITIONALLY, because cargo is incremental (a no-op when nothing changed). The
# tempting alternative — build only when the binary file is ABSENT — silently runs a STALE binary
# after any source edit, so the example's evidence describes code that is no longer the code under
# test. For a suite whose entire purpose is to produce trustworthy evidence about the CURRENT server,
# that is the worst failure mode there is, so it is not an option.
#
# The one exception is an explicit GRAPHUS_BIN_DIR: the caller is then deliberately pointing at
# binaries they built themselves (CI artifacts, a host without cargo). We trust those — the callers of
# this helper still verify the binaries exist and fail loudly if they do not.
harness_build() {
  local label="$1"
  shift
  if [ -n "${GRAPHUS_BIN_DIR:-}" ]; then
    info "using prebuilt binaries from GRAPHUS_BIN_DIR ($label not rebuilt)"
    return 0
  fi
  section "Building $label"
  ( cd "${REPO_ROOT:?harness_build needs REPO_ROOT}" && cargo build "$@" )
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

# evidence_capture_storage <store-dir> <wal-dir> — records on-disk sizes if the paths exist.
#
# A `du -sb` of the WAL directory is the on-disk RETAINED footprint at this instant, NOT the durable
# write VOLUME — and it is bimodal by construction (it depends on where this snapshot lands relative to
# the last checkpoint; rmp #805 observed a 17x spread). So it is emitted under storage.wal_retained_bytes,
# never storage.wal_bytes. The gated storage.wal_bytes is the WAL bytes WRITTEN
# (graphus_wal_bytes_written_total), a monotonic counter this shell stub cannot read — an example that
# needs it scrapes /metrics (see examples/product-recommendations). Full attribution (bytes fsynced,
# etc.) is the metering task's job.
evidence_capture_storage() {
  local store="$1" wal="$2"
  local store_bytes wal_retained_bytes
  if [ -e "$store" ]; then
    store_bytes="$(du -sb "$store" 2>/dev/null | awk '{print $1}' || echo 0)"
    evidence_metric "storage.store_bytes" "${store_bytes:-0}"
  fi
  if [ -e "$wal" ]; then
    wal_retained_bytes="$(du -sb "$wal" 2>/dev/null | awk '{print $1}' || echo 0)"
    evidence_metric "storage.wal_retained_bytes" "${wal_retained_bytes:-0}"
  fi
}

# --------------------------------------------------------------------------------------------------
# External target attach — run an example against an ALREADY-RUNNING Graphus instance
# --------------------------------------------------------------------------------------------------
# By default an example self-boots a local server (harness_start_server). Setting ANY of
# GRAPHUS_TARGET_BOLT / GRAPHUS_TARGET_REST / GRAPHUS_TARGET_UDS switches the harness into "external"
# mode: harness_start_server becomes a no-op and the example instead attaches to the running instance
# over its REST endpoint. This lets the same example run unchanged against a local dev server or a
# remote box (e.g. a shared/staging instance) WITHOUT clobbering its data — the harness carves out a
# dedicated, isolated database and drops it again on cleanup.
#
# Every helper below is a safe no-op / non-fatal in local mode (no GRAPHUS_TARGET_* set), so the
# smoke example and all existing examples behave identically.
#
# Environment (all optional; setting BOLT, REST or UDS is what enables external mode):
#   GRAPHUS_TARGET_BOLT          bolt://host:port      — Bolt/TCP endpoint            (marks external)
#   GRAPHUS_TARGET_REST          https://host:7474     — REST base URL                (marks external)
#   GRAPHUS_TARGET_UDS           /path/to/graphus.sock — Bolt-over-UDS path           (marks external)
#   GRAPHUS_TARGET_USER          login username                              (default: graphus)
#   GRAPHUS_TARGET_PASSWORD      login password                             (default: graphus-local)
#   GRAPHUS_TARGET_DB            existing DB to use; when SET the harness NEVER creates or drops a DB
#                                (the operator owns it). When unset, an isolated DB is created/dropped.
#   GRAPHUS_TARGET_SYSTEM_DB     DB through which CREATE/STOP/DROP/SHOW DATABASE are issued
#                                (default: graphus — Graphus's default DB; set to `system` for a
#                                 Neo4j-compatible target).
#   GRAPHUS_TARGET_METRICS       metrics/REST base URL for /metrics             (default: the REST base)
#   GRAPHUS_TARGET_METRICS_TOKEN pre-issued Bearer for /metrics             (default: the login token)
#   GRAPHUS_TARGET_TLS_INSECURE  1/true/yes → curl -k (accept a self-signed TLS cert on the target)
#
# REST contract (validated against a live instance):
#   * POST <base>/auth/login          {"username","password"}        -> {"token":"<JWT>", ...}
#   * POST <base>/db/<db>/tx/commit    {"statements":[{"statement":"<CYPHER>"}]}   (Bearer auth)
#   * GET  <base>/metrics             (Bearer auth; an admin Bearer satisfies the fail-closed gate)
#   DB DDL (CREATE/STOP/DROP/SHOW DATABASE) is routed through GRAPHUS_TARGET_SYSTEM_DB.
#   A database must be STOPped (offline) before it can be DROPped.

# harness_target_mode — echoes `external` iff any of GRAPHUS_TARGET_{BOLT,REST,UDS} is set, else `local`.
harness_target_mode() {
  if [ -n "${GRAPHUS_TARGET_BOLT:-}" ] || [ -n "${GRAPHUS_TARGET_REST:-}" ] || [ -n "${GRAPHUS_TARGET_UDS:-}" ]; then
    printf 'external\n'
  else
    printf 'local\n'
  fi
}

# _harness_target_insecure — true when self-signed TLS should be accepted (curl -k).
_harness_target_insecure() {
  case "${GRAPHUS_TARGET_TLS_INSECURE:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *)                         return 1 ;;
  esac
}

# _harness_curl <curl-args...> — shared curl wrapper that honours the self-signed-TLS opt-out.
_harness_curl() {
  if _harness_target_insecure; then
    curl -k "$@"
  else
    curl "$@"
  fi
}

# _harness_target_rest_base — base URL for REST (login + tx/commit): REST, else METRICS. Trailing / stripped.
_harness_target_rest_base() {
  local b="${GRAPHUS_TARGET_REST:-${GRAPHUS_TARGET_METRICS:-}}"
  printf '%s' "${b%/}"
}

# _harness_target_metrics_base — base URL for /metrics: METRICS, else REST. Trailing / stripped.
_harness_target_metrics_base() {
  local b="${GRAPHUS_TARGET_METRICS:-${GRAPHUS_TARGET_REST:-}}"
  printf '%s' "${b%/}"
}

# _harness_target_system_db — DB through which DATABASE DDL is routed (default: graphus).
_harness_target_system_db() {
  printf '%s' "${GRAPHUS_TARGET_SYSTEM_DB:-graphus}"
}

# _harness_json_escape <string> — minimal JSON string escaping (backslash + double-quote) for
# single-line statements/values. Adequate for the harness's own DDL and simple values.
_harness_json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '%s' "$s"
}

# harness_target_login — obtain (and cache) an admin Bearer via POST <base>/auth/login using
# GRAPHUS_TARGET_USER/PASSWORD. Echoes the token; caches it in HARNESS_TARGET_TOKEN so a later call in
# the SAME shell (or an inherited subshell) reuses it. Non-fatal + clear message if REST is absent.
harness_target_login() {
  if [ -n "${HARNESS_TARGET_TOKEN:-}" ]; then
    printf '%s\n' "$HARNESS_TARGET_TOKEN"
    return 0
  fi
  local base; base="$(_harness_target_rest_base)"
  if [ -z "$base" ]; then
    info "harness_target_login: no REST endpoint (set GRAPHUS_TARGET_REST) — cannot obtain a Bearer" >&2
    return 1
  fi
  local user pass resp token
  user="$(_harness_json_escape "${GRAPHUS_TARGET_USER:-graphus}")"
  pass="$(_harness_json_escape "${GRAPHUS_TARGET_PASSWORD:-graphus-local}")"
  resp="$(_harness_curl -sS -X POST "$base/auth/login" \
            -H 'Content-Type: application/json' \
            -d "{\"username\":\"$user\",\"password\":\"$pass\"}" 2>/dev/null)" || {
    info "harness_target_login: request to $base/auth/login failed" >&2
    return 1
  }
  token="$(printf '%s' "$resp" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  if [ -z "$token" ]; then
    info "harness_target_login: no token in response from $base/auth/login: $resp" >&2
    return 1
  fi
  HARNESS_TARGET_TOKEN="$token"
  printf '%s\n' "$token"
}

# harness_target_query <db> <cypher> — POST a single statement to <base>/db/<db>/tx/commit with the
# admin Bearer and echo the raw JSON response. Single-line statements only (minimal JSON escaping).
# Non-fatal (returns non-zero) if REST is absent or login fails.
harness_target_query() {
  local db="$1" cypher="$2"
  local base; base="$(_harness_target_rest_base)"
  if [ -z "$base" ]; then
    info "harness_target_query: no REST endpoint (set GRAPHUS_TARGET_REST) — skipping" >&2
    return 1
  fi
  local token; token="$(harness_target_login)" || return 1
  local esc; esc="$(_harness_json_escape "$cypher")"
  _harness_curl -sS -X POST "$base/db/$db/tx/commit" \
    -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' \
    -d "{\"statements\":[{\"statement\":\"$esc\"}]}" 2>/dev/null
}

# _harness_target_state_file — deterministic path (keyed on the shell PID, stable across $()-subshells)
# recording a harness-created DB name so a trap-invoked harness_target_drop_db can find it.
_harness_target_state_file() {
  local d="${TMPDIR:-/tmp}"; d="${d%/}"
  printf '%s/graphus-harness-created-db.%s' "$d" "$$"
}

# _harness_target_gen_db_name — a unique, valid ([a-z][a-z0-9_-]{0,62}) DB name of the form
# ex_<scenario>_<epoch>_<pid>, sanitized and truncated to 63 chars (the scenario part is trimmed so the
# unique epoch+pid suffix always survives). Scenario = $HARNESS_SCENARIO or the example folder name.
_harness_target_gen_db_name() {
  local scen src epoch pid suffix maxscen
  src="${BASH_SOURCE[$((${#BASH_SOURCE[@]} - 1))]}"
  scen="${HARNESS_SCENARIO:-}"
  if [ -z "$scen" ] && [ -n "$src" ]; then
    scen="$(basename "$(dirname "$src")" 2>/dev/null)"
  fi
  [ -z "$scen" ] && scen="example"
  scen="$(printf '%s' "$scen" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_-]//g')"
  [ -z "$scen" ] && scen="example"
  epoch="$(date +%s)"; pid="$$"
  suffix="_${epoch}_${pid}"
  maxscen=$((63 - 3 - ${#suffix}))
  [ "$maxscen" -lt 1 ] && maxscen=1
  scen="${scen:0:$maxscen}"
  printf 'ex_%s%s' "$scen" "$suffix"
}

# harness_target_ensure_db — resolve the database an example should use against an external target.
#   * If GRAPHUS_TARGET_DB is set: echo it as-is (operator-owned; never created/dropped).
#   * Otherwise: CREATE a unique isolated DB (routed via the system DB), remember it in
#     HARNESS_TARGET_CREATED_DB (+ a PID-keyed state file for trap teardown), and echo its name.
# Fails fast with a clear message if the CREATE is unauthorized/rejected.
harness_target_ensure_db() {
  if [ -n "${GRAPHUS_TARGET_DB:-}" ]; then
    printf '%s\n' "$GRAPHUS_TARGET_DB"
    return 0
  fi
  local base; base="$(_harness_target_rest_base)"
  if [ -z "$base" ]; then
    info "harness_target_ensure_db: no REST endpoint (set GRAPHUS_TARGET_REST) — cannot create an isolated DB" >&2
    return 1
  fi
  local sysdb name resp
  sysdb="$(_harness_target_system_db)"
  name="$(_harness_target_gen_db_name)"
  resp="$(harness_target_query "$sysdb" "CREATE DATABASE $name IF NOT EXISTS")" || {
    info "harness_target_ensure_db: CREATE DATABASE request to $base failed" >&2
    return 1
  }
  case "$resp" in
    *'"results"'*) : ;; # a results envelope means the statement executed successfully
    *)
      local detail
      detail="$(printf '%s' "$resp" | sed -n 's/.*"detail"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
      echo "fatal: CREATE DATABASE $name was rejected by $base (unauthorized or invalid): ${detail:-$resp}" >&2
      return 1 ;;
  esac
  HARNESS_TARGET_CREATED_DB="$name"
  printf '%s\n' "$name" > "$(_harness_target_state_file)" 2>/dev/null || true
  info "created isolated target DB '$name' on $base (DDL via '$sysdb')" >&2
  printf '%s\n' "$name"
}

# harness_target_drop_db — teardown for a harness-created DB. Only acts on a DB WE created (tracked in
# HARNESS_TARGET_CREATED_DB or the PID-keyed state file); otherwise a no-op. Issues STOP then
# DROP IF EXISTS (a DB must be offline before it can be dropped). Safe to call from a trap.
harness_target_drop_db() {
  local name statef sysdb
  name="${HARNESS_TARGET_CREATED_DB:-}"
  statef="$(_harness_target_state_file)"
  if [ -z "$name" ] && [ -f "$statef" ]; then
    name="$(cat "$statef" 2>/dev/null)"
  fi
  [ -z "$name" ] && return 0 # nothing the harness created — leave the target untouched
  sysdb="$(_harness_target_system_db)"
  info "dropping isolated target DB '$name' (STOP then DROP)" >&2
  harness_target_query "$sysdb" "STOP DATABASE $name" >/dev/null 2>&1 || true
  harness_target_query "$sysdb" "DROP DATABASE $name IF EXISTS" >/dev/null 2>&1 || true
  rm -f "$statef" 2>/dev/null || true
  HARNESS_TARGET_CREATED_DB=""
}

# harness_scrape_metrics <outfile> — GET the target's /metrics (Prometheus text) into <outfile> using
# GRAPHUS_TARGET_METRICS_TOKEN, or an admin Bearer from harness_target_login. A missing/unreachable
# endpoint is NON-FATAL: nothing is written and a note is printed (returns non-zero).
harness_scrape_metrics() {
  local out="$1"
  local mbase; mbase="$(_harness_target_metrics_base)"
  if [ -z "$mbase" ]; then
    info "harness_scrape_metrics: no metrics/REST endpoint (set GRAPHUS_TARGET_REST or GRAPHUS_TARGET_METRICS) — nothing to scrape" >&2
    return 1
  fi
  local url="$mbase/metrics"
  local token="${GRAPHUS_TARGET_METRICS_TOKEN:-}"
  if [ -z "$token" ]; then
    token="$(harness_target_login)" || {
      info "harness_scrape_metrics: could not obtain a Bearer for $url" >&2
      return 1
    }
  fi
  local tmp status
  tmp="$(mktemp 2>/dev/null || printf '%s/graphus-metrics.%s' "${TMPDIR:-/tmp}" "$$")"
  status="$(_harness_curl -sS -o "$tmp" -w '%{http_code}' \
             -H "Authorization: Bearer $token" "$url" 2>/dev/null)"
  if [ "$status" != "200" ]; then
    info "harness_scrape_metrics: $url returned HTTP ${status:-000} — no metrics written" >&2
    rm -f "$tmp" 2>/dev/null || true
    return 1
  fi
  if [ ! -s "$tmp" ]; then
    info "harness_scrape_metrics: $url returned an empty body — no metrics written" >&2
    rm -f "$tmp" 2>/dev/null || true
    return 1
  fi
  mv "$tmp" "$out" 2>/dev/null || { cp "$tmp" "$out" && rm -f "$tmp" 2>/dev/null; }
  info "scraped metrics: $url -> $out" >&2
  return 0
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
  # External-target mode: attach to the ALREADY-RUNNING instance instead of booting a local server.
  if [ "$(harness_target_mode)" = external ]; then
    info "external target detected (GRAPHUS_TARGET_*) — attaching to the running instance, not booting a local server"
    HARNESS_SERVER_PID=""
    return 0
  fi
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
