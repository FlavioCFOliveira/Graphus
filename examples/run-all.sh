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

# ------------------------------------------------------------------------------------------------
# Evidence-honesty audit (rmp #711) — the suite's own guard against a zero placeholder.
#
# "Measure it or omit it, never a zero placeholder" is a rule about EVERY report the suite emits, so
# it is checked HERE, once, over every report the sweep just produced — rather than being restated in
# twelve run.sh files, where the thirteenth would forget it. Schema 3 makes an unmeasured metric
# ABSENT, so any metric still present as an exact 0 / 0.0 is, by construction, either a genuinely
# measured zero (only `throughput.abort_rate` and the server-metrics counters can be) or a resurrected
# placeholder. The scan fails the suite on the latter — this is precisely how `bytes_per_node` sat at
# 0.0 in all 11 reports, documented as "durable bytes per stored node", with a green gate over it.
# ------------------------------------------------------------------------------------------------
audit_zero_placeholders() {
  command -v python3 >/dev/null 2>&1 || { printf '  %s(python3 absent — evidence audit skipped)%s\n' "$DIM" "$RESET"; return 0; }
  python3 - "$SCRIPT_DIR" "${PASSED[@]}" <<'PY'
import glob, json, os, sys

root, examples = sys.argv[1], sys.argv[2:]
# Metrics whose measured value may LEGITIMATELY be zero. Everything else in the four vector sections
# cannot be: a live process holds RSS, a stored graph occupies bytes, a completed operation takes
# time, and a real footprint does not amplify by a factor of zero.
LEGITIMATELY_ZERO = {("throughput", "abort_rate")}


def cpu_zero_is_measured(cpu, key):
    """A CPU figure of 0.0 that is a REAL measurement, not a placeholder (`rmp #715`).

    The OS reports process CPU in USER_HZ clock ticks (10 ms on Linux), so a short-lived child can
    genuinely consume ZERO WHOLE TICKS of system (or user) time: bulk-etl's `graphus-bulk import`
    lives ~48 ms and truthfully reports `system_secs: 0.0` beside `user_secs: 0.02` and
    `mean_core_utilisation: 0.41`. That zero is quantisation, not fabrication — the same family as a
    measured `abort_rate` of 0.0.

    So a zero in ONE of user/system is accepted only when the OTHER is non-zero, which proves the CPU
    vector really was sampled. A section where BOTH are zero is still a placeholder and still fails —
    the audit keeps its teeth.
    """
    if key not in ("user_secs", "system_secs"):
        return False
    other = "system_secs" if key == "user_secs" else "user_secs"
    return bool(cpu.get(other))


bad, seen = [], 0

for ex in examples:
    # EVERY report the example emitted — an example may write several (a wire report beside the
    # in-process one, a real-server report beside the DST one). All of them are evidence.
    for path in sorted(glob.glob(os.path.join(root, ex, "evidence*", "**", "report.json"),
                                 recursive=True)):
        seen += 1
        rel = os.path.relpath(path, root)
        with open(path) as fh:
            report = json.load(fh)
        if report.get("version", 0) < 3:
            bad.append(f"{rel}: schema v{report.get('version')} — pre-#711 (zero placeholders)")
            continue
        for section in ("cpu", "memory", "storage", "throughput"):
            contents = report.get(section) or {}
            for key, value in contents.items():
                if (section, key) in LEGITIMATELY_ZERO:
                    continue
                if section == "cpu" and cpu_zero_is_measured(contents, key):
                    continue
                if isinstance(value, (int, float)) and not isinstance(value, bool) and value == 0:
                    bad.append(f"{rel}: {section}.{key} = {value} — a zero placeholder for an "
                               f"unmeasured metric (schema 3 OMITS what it did not measure)")

print(f"  audited {seen} report.json file(s) for zero placeholders")
for b in bad:
    print(f"  ZERO PLACEHOLDER: {b}")
sys.exit(1 if bad else 0)
PY
}

printf '\n%s== Evidence-honesty audit ==%s\n' "$BOLD" "$RESET"
if [ "${#PASSED[@]}" -gt 0 ] && ! audit_zero_placeholders; then
  printf '  %s✗ a report emits a 0 for a metric it did not measure%s\n' "$RED" "$RESET"
  FAILED+=("evidence-honesty audit")
else
  printf '  %s✓ every emitted metric is measured (unmeasured vectors are ABSENT, not zero)%s\n' "$GREEN" "$RESET"
fi

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
