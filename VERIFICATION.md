# Graphus standing verification suite and performance gates

This document catalogs Graphus's standing verification arsenal — the gates that prove the server is
ACID-correct, serializable, free of undefined behaviour, free of parser/decoder panics, and free of
performance regressions — and gives the **exact** invocation, expected outcome, and rough runtime for
each (`rmp` task #27).

A single convenience runner, [`scripts/verify.sh`](scripts/verify.sh), runs the fast gates in
sequence (and, with flags, the slow ones). The table below is the authority on what each gate is and
how CI should schedule it.

## Gate summary

| # | Gate | Crate / file | CI cadence | Typical runtime |
| - | ---- | ------------ | ---------- | --------------- |
| 1 | Anomaly checker (Elle/DSG serializability) | `graphus-cypher/tests/elle.rs` | every push | < 1 s |
| 2 | loom model-check (lock-free latch protocol) | `graphus-bufpool/tests/loom_bufpool.rs` | nightly / on-change | seconds (bounded) |
| 3 | miri UB gate (pure-logic crates) | `graphus-core`, `graphus-wal`, `graphus-bolt`, `graphus-index`, `graphus-storage` | nightly / on-change | ~3 min total |
| 4 | proptest invariants (codecs, key order) | `graphus-storage/tests/proptest_codecs.rs`, `graphus-cypher/tests/proptest_keycodec.rs` | every push | < 1 s |
| 5 | cargo-fuzz targets (parser, packstream) | `graphus-cypher/fuzz`, `graphus-bolt/fuzz` | manual / scheduled campaign | build < 2 min; campaign = as long as you let it |
| 6 | Criterion regression gate | `graphus-bench` (`bin/bench_gate`, `baseline.toml`) | every push (release) | ~1–2 s |
| 7 | Criterion micro-benchmark suites | `graphus-bench/benches/*`, `graphus-io/benches/loopback` | manual / perf job | minutes |
| 8 | LDBC-SNB macro harness | `graphus-bench` (`bin/ldbc_snb`, `src/ldbc/`) | nightly / perf job | seconds (tiny) |

---

## 1. Anomaly checker — Elle/DSG serializability (AC: "anomaly checks pass at the default level")

Drives randomized **concurrent** Cypher transactions through the `TxnCoordinator` and feeds each
committed transaction's read/write history to `graphus-txn`'s Direct-Serialization-Graph
`HistoryChecker` (the Adya/Berenson anomaly oracle). An execution is serializable iff its DSG is
acyclic. The suite has teeth: the same write-skew workload under the SNAPSHOT opt-in is caught as a
cycle, proving the check is not vacuous.

```sh
cargo test -p graphus-cypher --test elle
```

**Expected:** `test result: ok. 2 passed`
(`serializable_concurrent_histories_have_no_anomaly` over 12 seeds × 40 rounds, and
`checker_catches_write_skew_permitted_under_snapshot_isolation`).

The deterministic-simulation crate `graphus-dst` and `graphus-storage/tests/{crash_recovery,
consistency}.rs` are the complementary durability/ACID checks (run as ordinary `cargo test`).

---

## 2. loom — lock-free latch protocol model-check (AC: "loom green")

`graphus-bufpool` is `#![forbid(unsafe_code)]`, so it has no data races by construction; what still
needs proving is that the buffer pool's **latch/pin/eviction protocol** is correct under every legal
thread interleaving (exactly-once loads, no pin underflow, no lost dirty write, WAL-before-data on
every path). loom explores those interleavings exhaustively over deliberately tiny models (2 threads,
1–2 frames).

```sh
RUSTFLAGS="--cfg loom" LOOM_MAX_PREEMPTIONS=3 \
    cargo test -p graphus-bufpool --test loom_bufpool --release
```

**Expected:** `test result: ok. 4 passed`
(`loom_two_threads_fetch_same_page_loads_once`, `loom_fetch_while_evict_other_page`,
`loom_concurrent_pin_unpin_never_underflows`, `loom_wal_rule_before_every_write_back`).

**Bound:** `LOOM_MAX_PREEMPTIONS=3` caps the preemption-point search depth to keep CI time bounded;
the models are small enough that the run still completes in well under a second. Raise or drop the
bound to trade search depth for time. `--release` is recommended (loom's search is exponential).

> Note: the gate requires `graphus-io` to compile under `--cfg loom`. Because Tokio's `net`/runtime
> modules are themselves `#![cfg(not(loom))]`, `graphus-io` gates its Tokio-backed half
> (`net`/`fsync`/`backend`) on `not(loom)` — the loom build sees only the synchronous `BlockDevice`
> half the buffer pool needs.

---

## 3. miri — undefined-behaviour gate (AC: "miri green")

miri interprets the program against the Rust abstract machine and flags undefined behaviour
(out-of-bounds, use-after-free, invalid values, data races, misaligned access, provenance bugs). It
is scoped to the **pure-logic** crates and their **codec/logic** tests — the ones with no real
syscalls, no mmap/io_uring, and no filesystem I/O. `graphus-io` (mmap/uring/real sockets) is **not**
run under miri (and is the only crate with an actual `unsafe` block — the io_uring FFI in
`uring.rs`).

Run each scoped command (all GREEN):

```sh
cargo +nightly miri test -p graphus-core
cargo +nightly miri test -p graphus-wal --lib
cargo +nightly miri test -p graphus-bolt --lib
cargo +nightly miri test -p graphus-index --lib
cargo +nightly miri test -p graphus-storage --lib -- \
    record:: valenc:: propenc:: labels:: heap:: paging:: tokens:: idalloc:: meta::
```

**Expected:**

| Command | Result |
| ------- | ------ |
| `graphus-core` | `10 passed; 0 failed` |
| `graphus-wal --lib` | `23 passed; 0 failed; 1 ignored` |
| `graphus-bolt --lib` | `54 passed; 0 failed` |
| `graphus-index --lib` | `42 passed; 0 failed; 1 ignored` |
| `graphus-storage` (codecs) | `63 passed; 0 failed` |

The `--lib` scope keeps the gate fast by running each crate's unit tests (the UB-relevant codec/logic
surface) and skipping the **integration** test binaries that drive the full paging/recovery substrate
— e.g. `graphus-wal/tests/aries_recovery.rs` and `graphus-index/tests/btree_props.rs` — which are
correct under miri but take minutes (heavy page churn under the interpreter). Run those natively;
under miri the same codecs they exercise are already covered by the `--lib` unit tests above.
`graphus-core` has no integration tests, so it needs no `--lib`.

This covers the UB-relevant logic directly: the shared `Value`/version model (`graphus-core`); the
WAL append/recovery/undo logic over the in-memory sink (`graphus-wal`); the **PackStream wire codec**,
message framing, handshake negotiation (`graphus-bolt`); the B+-tree node/key-codec logic
(`graphus-index`); and the on-disk **record/property/label/heap/paging codecs** (`graphus-storage`).

**Setup:** `rustup +nightly component add miri` (the nightly toolchain is the project's miri channel;
`cargo +nightly miri --version` confirms).

**Justified exclusions (minimal; never to hide UB):**

- `graphus-wal::sink::tests::file_sink_round_trips_and_survives_reopen` — `#[cfg_attr(miri, ignore)]`:
  uses real `open`/`remove_file`, which miri's filesystem **isolation** aborts. It exercises the
  production `FileLogSink`; the WAL *logic* is validated over the in-memory `MemLogSink` (which runs
  under miri).
- `graphus-index::btree::tests::many_inserts_grow_the_tree_height` — `#[cfg_attr(miri, ignore)]`: 1000
  inserts × page splits is impractically slow under the interpreter; the split/grow logic is covered
  by the smaller tests (which run under miri) and the native `tests/btree_props.rs` proptest.
- `graphus-bolt`'s `server::tests` module — `#[cfg(all(test, not(miri)))]`: these end-to-end session
  tests call `Authenticator::set_password`, a deliberately CPU-expensive password KDF that takes
  minutes under the interpreter. The wire codec they drive (framing/message/handshake/packstream) is
  covered by those modules' own miri-green unit tests.
- `graphus-storage` non-codec tests (`store::`, `check::`, `recovery::`, `backup::`, `wal_rule::`) are
  out of the miri command's scope by test-name filter: they drive the full store over the paging
  substrate (slow under miri) and exercise the same codecs the scoped tests already cover.

The whole miri gate runs in ~3 minutes total. If `rustup component add miri` ever fails (offline CI),
the gate is nightly-gated: the commands above are the exact green invocations to run where nightly +
miri are available.

---

## 4. proptest — invariant property tests (TR)

Randomized, **shrinking** property tests for the most safety-critical pure functions. Complement the
example-based unit tests; a regression surfaces the minimal counterexample.

```sh
cargo test -p graphus-storage --test proptest_codecs
cargo test -p graphus-cypher --test proptest_keycodec
```

**Expected:** `proptest_codecs` → `5 passed`; `proptest_keycodec` → `3 passed`.

Invariants:

- **Codec round-trips** (`proptest_codecs`): `decode_inline(encode_inline(v)) == v` for inline scalars
  (bit-exact, incl. `NaN`/`-0.0`); `valenc::decode(valenc::encode(v)) == v` for `String` and
  homogeneous scalar `List`s; and the inline codec *rejects* non-inline classes rather than
  mis-encoding them.
- **Order-preserving key codec** (`proptest_keycodec`):
  `cmp_values(a, b) == encode_single(a).cmp(encode_single(b))` for every index-encodable value (the
  proof a memcmp B+-tree returns Cypher-ordered rows); the byte order is a total order
  (reflexive + antisymmetric); and composite keys are prefix-free (a tuple's encoding equals the
  concatenation of its fields' encodings, and byte order equals tuple order). This is the proptest
  formulation of the existing deterministic 100k-iteration cross-check in
  `graphus-cypher/tests/ordering_vs_keycodec.rs`.

---

## 5. cargo-fuzz — parser and decoder fuzz targets (TR)

Coverage-guided fuzzing of the server's two most exposed byte-decoding surfaces, enforcing the
zero-panic rule (`CLAUDE.md`): any input must yield a value or a structured error, never a
panic/overflow/abort.

**Setup:** `cargo install cargo-fuzz` (installs `cargo-fuzz` 0.13+; needs the nightly toolchain).

**Build the targets** (this is the CI gate — the targets must always compile):

```sh
cargo +nightly fuzz build --fuzz-dir crates/graphus-cypher/fuzz
cargo +nightly fuzz build --fuzz-dir crates/graphus-bolt/fuzz
```

**Run a campaign** (manual / scheduled — run as long as you like):

```sh
# Cypher front end:
cargo +nightly fuzz run parse_cypher    --fuzz-dir crates/graphus-cypher/fuzz
cargo +nightly fuzz run tokenize_cypher --fuzz-dir crates/graphus-cypher/fuzz
# Bolt PackStream decoder:
cargo +nightly fuzz run unpack_packstream --fuzz-dir crates/graphus-bolt/fuzz
# A bounded smoke run (CI-friendly):
cargo +nightly fuzz run parse_cypher --fuzz-dir crates/graphus-cypher/fuzz -- -max_total_time=30
```

**Expected:** all targets build. A campaign reports `Done N runs` with no crash artifacts written to
`fuzz/artifacts/`. (A representative smoke run of `parse_cypher` executed ~800k inputs at ~38k
exec/s with zero crashes.)

The `fuzz/` directories are **separate, non-workspace packages** (each has its own `[workspace]`
table) because `libfuzzer-sys` is nightly-only; they do not affect the stable workspace build.

---

## 6. Criterion regression gate (AC: "benchmarks gate regressions")

A lightweight CI gate that measures representative slices of the hot paths, takes the **median**
(robust to outliers), and fails if any metric regresses past a tolerance vs the committed baseline
(`crates/graphus-bench/baseline.toml`). It is self-contained (no Criterion dependency) and fast.

```sh
# Gate against the committed baseline (ALWAYS release — the baseline is a release measurement):
cargo run -p graphus-bench --release --bin bench_gate

# Re-seed the baseline after an intentional perf change, on a quiet release build:
cargo run -p graphus-bench --release --bin bench_gate -- --update

# Loosen the threshold for a noisy runner:
cargo run -p graphus-bench --release --bin bench_gate -- --tolerance 0.30
```

**Metrics gated:** `commit_short_txn_ns` (median latency of a 4-op write-transaction commit) and
`scan_1k_nodes_ns` (median latency of a full 1000-node store scan) — the write serialization point
and the lock-free read leaf, distilled to one number each.

**Tolerance:** default **20 %** (a metric may be up to 20 % slower than baseline before failing). This
absorbs run-to-run jitter while still catching a real regression (typically ≥ 1.5–2×).

**Expected:** `RESULT: all metrics within tolerance — gate PASSES.` (exit 0). A genuine regression
prints `FAIL` for the offending metric and `RESULT: REGRESSION DETECTED — gate FAILS.` (exit 1) — e.g.
running the gate from a **debug** build (~10× slower) makes every metric "regress", which is the
intended failure shape; that is why the gate must be run in `--release`.

The committed baseline numbers are recorded from a release build on the machine class in
`crates/graphus-bench/RESULTS.md` §1.

---

## 7. Criterion micro-benchmark suites (the measurement instrument)

The full statistical benchmarks the regression gate is distilled from. Run on a perf job, not every
push.

```sh
cargo bench -p graphus-bench --bench commit_path   # write/commit serialization point (SPIKE #8)
cargo bench -p graphus-bench --bench read_path      # lock-free traversal + scan
cargo bench -p graphus-io   --bench loopback        # epoll/kqueue network loopback baseline
```

See `crates/graphus-bench/RESULTS.md` for recorded numbers, methodology, and the SPIKE #8 decision.

---

## 8. LDBC-SNB macro harness (AC: "LDBC SNB runs")

A scaled, **inspired** Social-Network-Benchmark workload: generate a synthetic social graph
(`Person`/`KNOWS`, `Forum`/`Post`/`Comment` with `HAS_CREATOR`/`REPLY_OF`/`CONTAINER_OF`) and run
representative SNB-style read/write operations through the **real** engine pipeline, reporting
throughput + latency percentiles. It is **not** the official LDBC driver — see
`crates/graphus-bench/LDBC.md` for the provenance, the schema, the query→official-SNB mapping, and the
deferred official queries (those needing Cypher the young engine does not yet support).

```sh
cargo run -p graphus-bench --bin ldbc_snb              # tiny scale (seconds)
cargo run -p graphus-bench --release --bin ldbc_snb -- --medium
cargo test -p graphus-bench --lib ldbc                  # as a self-checking test
```

**Expected:** the harness runs to completion and prints a report ending in
`N/N operations supported and measured`. At the tiny scale it builds a 174-node / 670-relationship
graph and measures all 8 SNB-flavoured operations (point lookup, 1-hop and 2-hop expand, author
expand, aggregate, filtered scan, degree, insert). Per-operation latencies are currently in the
millisecond range because id-keyed `MATCH` is a full label scan (no property index yet — see
`LDBC.md`); the numbers are stable run-to-run (deterministic generator) and this harness is the
instrument that will show the speed-up once an index seek is wired into planning.

---

## Quick start

```sh
# Fast gates only (build/clippy/fmt, anomaly, proptest, regression gate, LDBC) — every push:
scripts/verify.sh

# Add the slow gates as needed:
scripts/verify.sh --with-loom     # + loom model-check
scripts/verify.sh --with-miri     # + miri UB gate (nightly + miri)
```
