#!/usr/bin/env bash
#
# Run the WHOLE examples suite and report one verdict.
#
# The examples are the project's instrument for exposing regressions, fragilities, and resource
# inefficiencies in the server. That only works if they are actually RUN — so this runner exists to
# make "do all the examples still pass?" a single command rather than a manual ritual.
#
# Two modes, mirroring the examples themselves:
#
#   LOCAL (default)   — each example self-boots the server it needs.
#   EXTERNAL (attach) — set GRAPHUS_TARGET_{REST,BOLT} and every attach-capable example runs against
#                       an ALREADY-RUNNING instance (local or remote), each isolating itself in its
#                       own run-scoped database. The durability examples are SKIPPED in this mode:
#                       they must own the server lifecycle to inject a crash, so they are local-only
#                       by construction (see examples/CLAUDE.md).
#
# Usage:
#   examples/run-all.sh                     # every example, local self-boot
#   examples/run-all.sh social-network-large fraud-oltp     # only the named ones
#   GRAPHUS_TARGET_REST=… GRAPHUS_TARGET_BOLT=… examples/run-all.sh   # attach to a running instance
#
# Exit status is non-zero if ANY example fails, so this is usable as a gate.

set -uo pipefail   # NOT -e: a failing example must be recorded, not abort the sweep.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_harness/harness.sh"

if [ -t 1 ]; then
  BOLD=$'\e[1m'; GREEN=$'\e[32m'; RED=$'\e[31m'; YELLOW=$'\e[33m'; DIM=$'\e[2m'; RESET=$'\e[0m'
else
  BOLD=''; GREEN=''; RED=''; YELLOW=''; DIM=''; RESET=''
fi

MODE="$(harness_target_mode)"

# Examples that MUST own the server lifecycle (they inject a crash / kill the process), so they can
# never target a shared or remote instance. Documented exception in examples/CLAUDE.md.
LOCAL_ONLY="durability-crash-recovery social-network-uds"

ALL=(
  smoke-evidence
  clients-go
  social-network-uds
  durability-crash-recovery
  bulk-etl
  iot-timeseries
  knowledge-graph-rest
  social-network-large
  product-recommendations
  fraud-oltp
  gds-analytics
  security-multitenant
)

if [ "$#" -gt 0 ]; then
  TARGETS=("$@")
else
  TARGETS=("${ALL[@]}")
fi

printf '%s== Graphus examples suite (%s mode) ==%s\n' "$BOLD" "$MODE" "$RESET"
printf '%s%s examples to run%s\n' "$DIM" "${#TARGETS[@]}" "$RESET"

PASSED=(); FAILED=(); SKIPPED=()
declare -A SECS

for ex in "${TARGETS[@]}"; do
  run="$SCRIPT_DIR/$ex/run.sh"
  if [ ! -x "$run" ]; then
    printf '\n%s▸ %-28s%s %sNO run.sh — skipped%s\n' "$BOLD" "$ex" "$RESET" "$YELLOW" "$RESET"
    SKIPPED+=("$ex (no run.sh)")
    continue
  fi
  if [ "$MODE" = external ] && [[ " $LOCAL_ONLY " == *" $ex "* ]]; then
    printf '\n%s▸ %-28s%s %sskipped — local-only by construction (owns the server lifecycle to inject a crash)%s\n' \
      "$BOLD" "$ex" "$RESET" "$YELLOW" "$RESET"
    SKIPPED+=("$ex (local-only)")
    continue
  fi

  printf '\n%s▸ %-28s%s running…\n' "$BOLD" "$ex" "$RESET"
  t0=$(date +%s)
  log="$(mktemp "${TMPDIR:-/tmp}/graphus-suite-$ex-XXXXXX.log")"
  if "$run" > "$log" 2>&1; then
    t1=$(date +%s); SECS[$ex]=$((t1 - t0))
    checks="$(grep -Eo '^[0-9]+ checks run, [0-9]+ failures' "$log" | tail -1)"
    printf '  %s✓ PASSED%s  %s  %s(%ss)%s\n' "$GREEN" "$RESET" "${checks:-}" "$DIM" "${SECS[$ex]}" "$RESET"
    PASSED+=("$ex")
    rm -f "$log"
  else
    t1=$(date +%s); SECS[$ex]=$((t1 - t0))
    printf '  %s✗ FAILED%s %s(%ss)%s — last lines:\n' "$RED" "$RESET" "$DIM" "${SECS[$ex]}" "$RESET"
    tail -12 "$log" | sed 's/^/      /'
    printf '  %sfull log: %s%s\n' "$DIM" "$log" "$RESET"
    FAILED+=("$ex")
  fi
done

printf '\n%s== Suite result ==%s\n' "$BOLD" "$RESET"
printf '  %s%s passed%s' "$GREEN" "${#PASSED[@]}" "$RESET"
[ "${#FAILED[@]}"  -gt 0 ] && printf ', %s%s FAILED%s' "$RED" "${#FAILED[@]}" "$RESET"
[ "${#SKIPPED[@]}" -gt 0 ] && printf ', %s%s skipped%s' "$YELLOW" "${#SKIPPED[@]}" "$RESET"
printf '\n'
for s in "${SKIPPED[@]}"; do printf '    %s· %s%s\n' "$DIM" "$s" "$RESET"; done
if [ "${#FAILED[@]}" -gt 0 ]; then
  printf '  %sfailed:%s %s\n' "$RED" "$RESET" "${FAILED[*]}"
  exit 1
fi
printf '%s%sALL EXAMPLES PASSED%s\n' "$BOLD" "$GREEN" "$RESET"
