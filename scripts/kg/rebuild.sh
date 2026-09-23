#!/usr/bin/env bash
# Rebuild the `graphus` knowledge graph from scratch and prove it.
#
#   rustdoc (3 targets) -> extract.py -> populate.py -> audit.py
#
# The graph is rebuilt, never patched: it is always exactly one extractor run of
# the current HEAD. Exits non-zero if any fidelity criterion fails.
#
# The graph is reached only through a live `rmp graph serve` for the roadmap
# (populate.py and audit.py send every statement with `rmp graph client`). If a
# server already answers, it is reused and left running; otherwise this script
# starts one just before populate and stops it (SIGTERM, then waits for its
# exit) when the script ends, on success and on failure alike. Both ends use
# the socket path rmp derives from the roadmap (no --socket).
#
# Usage: scripts/kg/rebuild.sh [roadmap]        (default roadmap: graphus)
set -euo pipefail

ROADMAP="${1:-graphus}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="${KG_WORK:-$(mktemp -d)}"
cd "$REPO"

# --- graph server lifecycle --------------------------------------------------
SERVE_PID=""   # set only when THIS script started the server

stop_server() {
  local rc=$?
  if [ -n "$SERVE_PID" ]; then
    echo "==> stopping graph server (pid $SERVE_PID)"
    kill -TERM "$SERVE_PID" 2>/dev/null || true
    local src=0
    wait "$SERVE_PID" || src=$?
    SERVE_PID=""
    if [ "$src" -ne 0 ]; then
      # serve exits 0 after a clean drain + checkpoint; anything else is a fault.
      echo "FATAL: rmp graph serve exited rc=$src on shutdown (log: $WORK/serve.log)" >&2
      [ "$rc" -ne 0 ] || rc=1
    fi
  fi
  exit "$rc"
}
trap stop_server EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start_server() {
  if rmp graph client -r "$ROADMAP" --query "RETURN 1" >/dev/null 2>&1; then
    echo "==> graph server already answering for $ROADMAP: reusing it (left running)"
    return 0
  fi
  local log="$WORK/serve.log"
  echo "==> starting graph server for $ROADMAP (log: $log)"
  rmp graph serve -r "$ROADMAP" >"$log" 2>&1 &
  SERVE_PID=$!
  # serve prints {"socket": "<path>"} once it is bound and accepting.
  for _ in $(seq 1 240); do                     # at most 60 s
    grep -q '"socket"' "$log" && break
    if ! kill -0 "$SERVE_PID" 2>/dev/null; then
      local src=0
      wait "$SERVE_PID" || src=$?
      SERVE_PID=""
      echo "FATAL: rmp graph serve exited rc=$src before binding its socket:" >&2
      cat "$log" >&2
      exit 1
    fi
    sleep 0.25
  done
  if ! grep -q '"socket"' "$log"; then
    echo "FATAL: rmp graph serve printed no socket line within 60 s:" >&2
    cat "$log" >&2
    exit 1
  fi
  if ! rmp graph client -r "$ROADMAP" --query "RETURN 1" >/dev/null; then
    echo "FATAL: rmp graph serve is bound but does not answer RETURN 1" >&2
    exit 1
  fi
}

# The Tier-1 target matrix (specification decision `D-target-matrix`).
# 7 crates cannot cross-document: aws-lc-sys (rustls's C backend) needs a target
# C toolchain that is not installed. Those crates are simply absent from the
# non-native targets, and Crate.doc_targets records that honestly -- the graph
# says "not checked here", never "does not exist here".
TARGETS=(
  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-gnu
  aarch64-apple-darwin
)
NATIVE=x86_64-unknown-linux-gnu

echo "==> rustdoc JSON (work dir: $WORK)"
DOC_ARGS=()
for T in "${TARGETS[@]}"; do
  echo "    target $T"
  if [ "$T" = "$NATIVE" ]; then
    # The native target documents as a workspace in one pass.
    CARGO_TARGET_DIR="$WORK/rd-$T" \
    RUSTDOCFLAGS='-Zunstable-options --output-format json' \
      cargo +nightly doc --workspace --no-deps --lib --target "$T" >/dev/null 2>&1
  else
    # Cross targets: per crate, because `cargo doc --workspace` aborts the whole
    # run on the first crate that cannot build, losing the 28 that can.
    for c in crates/*/; do
      CARGO_TARGET_DIR="$WORK/rd-$T" \
      RUSTDOCFLAGS='-Zunstable-options --output-format json' \
        cargo +nightly doc -p "$(basename "$c")" --lib --no-deps --target "$T" \
        >/dev/null 2>&1 || true
    done
  fi
  n=$(find "$WORK/rd-$T/$T/doc" -maxdepth 1 -name '*.json' 2>/dev/null | wc -l)
  echo "        $n crates documented"
  [ "$n" -gt 0 ] || { echo "FATAL: no rustdoc JSON for $T"; exit 1; }
  DOC_ARGS+=(--rustdoc-dir "$T=$WORK/rd-$T/$T/doc")
done

echo "==> extract"
python3 scripts/kg/extract.py "${DOC_ARGS[@]}" > "$WORK/kg.json"

start_server

echo "==> populate ($ROADMAP)"
python3 scripts/kg/populate.py "$WORK/kg.json" --roadmap "$ROADMAP"

echo "==> audit"
python3 scripts/kg/audit.py --roadmap "$ROADMAP"
