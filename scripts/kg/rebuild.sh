#!/usr/bin/env bash
# Rebuild the `graphus` knowledge graph from scratch and prove it.
#
#   rustdoc (3 targets) -> extract.py -> populate.py -> audit.py
#
# The graph is rebuilt, never patched: it is always exactly one extractor run of
# the current HEAD. Exits non-zero if any fidelity criterion fails.
#
# Usage: scripts/kg/rebuild.sh [roadmap]        (default roadmap: graphus)
set -euo pipefail

ROADMAP="${1:-graphus}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="${KG_WORK:-$(mktemp -d)}"
cd "$REPO"

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

echo "==> populate ($ROADMAP)"
python3 scripts/kg/populate.py "$WORK/kg.json" --roadmap "$ROADMAP"

echo "==> audit"
python3 scripts/kg/audit.py --roadmap "$ROADMAP"
