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
| 9 | Examples suite — E2E, both modes | `examples/run-all.sh` via `scripts/examples-gate.sh` | every push | ~2–4 min |
| 10 | Read-polarity census (superset / decision / conservative) | `graphus-cypher/tests/read_polarity_census.rs`, `graphus-storage/tests/scan_polarity_barrier.rs` | every push | < 1 s |
| 11 | Official Neo4j driver interop (real driver over Bolt) | `graphus-server/tests/neo4j_driver_interop.rs` (feature `neo4j-interop`) | every push | ~1–3 min |
| 12 | Property visible-read record count (`rmp` #967 AC2) | `graphus-storage/tests/prop_visible_read_record_count.rs` (feature `read-probe`) | every push | < 1 s |
| 13 | Deterministic writer scheduler (`rmp` #973) | `graphus-dst/tests/det_scheduler_gc_reader_811.rs`, `graphus-dst/tests/det_scheduler_elle_oracle.rs`, `graphus-dst/src/detsched.rs` (feature `det-sched`) | every push | ~5 s |

> **What "every push" means today.** It is the *intended* cadence, and it is what `scripts/verify.sh`
> runs — but nothing invokes that script automatically: `.github/workflows/` holds only the on-demand
> Docker Hub publish job, so every "every push" gate above is in practice **run by a human executing
> `scripts/verify.sh`**. This is worth stating plainly rather than leaving the column to imply
> enforcement that does not exist, because a gate nobody runs is exactly how `rmp` #960 survived (see
> gate 11). Restoring a CI workflow that invokes `scripts/verify.sh` is the open item.

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

**Expected:** `test result: ok. 7 passed`
(`loom_two_threads_fetch_same_page_loads_once`, `loom_fetch_while_evict_other_page`,
`loom_concurrent_pin_unpin_never_underflows`, `loom_wal_rule_before_every_write_back`,
`loom_with_page_fetched_under_eviction_reads_correct_page`,
`loom_two_evictors_through_stager_respect_one_region`, `loom_three_threads_flush_while_two_fetch`).

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
cargo +nightly miri test -p graphus-core --lib
cargo +nightly miri test -p graphus-wal --lib
cargo +nightly miri test -p graphus-bolt --lib
cargo +nightly miri test -p graphus-index --lib
cargo +nightly miri test -p graphus-storage --lib -- \
    record:: valenc:: propenc:: labels:: heap:: paging:: tokens:: idalloc:: meta::
```

**Expected:**

| Command | Result |
| ------- | ------ |
| `graphus-core --lib` | `66 passed; 0 failed` |
| `graphus-wal --lib` | `49 passed; 0 failed; 7 ignored` |
| `graphus-bolt --lib` | `91 passed; 0 failed; 6 ignored` |
| `graphus-index --lib` | `0 failed` — B-tree/codec unit tests under miri; the heavy histogram-estimation and 1000-insert tests are miri-excluded (below), exact count re-measurement tracked (roadmap #610) |
| `graphus-storage` (codecs) | `0 failed` — the record/value/property/label/heap/paging/token/id codec unit tests under miri, exact count re-measurement tracked (roadmap #610) |

The `graphus-core`, `graphus-wal`, and `graphus-bolt` counts were re-measured for this release
(`graphus-bolt`'s miri time dropped from impractical to ~17 s once its heavyweight `graphus-auth →
rustls → aws-lc-sys` build dependency was feature-gated out and its complexity/native-stack tests were
excluded — see below). The `graphus-index`/`graphus-storage` codec suites run under miri once the
heavy non-codec tests below are excluded; finishing their trim and re-recording exact counts is a
tracked follow-up.

The `--lib` scope keeps the gate fast by running each crate's unit tests (the UB-relevant codec/logic
surface) and skipping the **integration** test binaries that drive the full paging/recovery substrate
— e.g. `graphus-wal/tests/aries_recovery.rs` and `graphus-index/tests/btree_props.rs` — which are
correct under miri but take minutes (heavy page churn under the interpreter). Run those natively;
under miri the same codecs they exercise are already covered by the `--lib` unit tests above.
`graphus-core` now has integration tests too, so it is scoped with `--lib` for the same reason.

This covers the UB-relevant logic directly: the shared `Value`/version model (`graphus-core`); the
WAL append/recovery/undo logic over the in-memory sink (`graphus-wal`); the **PackStream wire codec**,
message framing, handshake negotiation (`graphus-bolt`); the B+-tree node/key-codec logic
(`graphus-index`); and the on-disk **record/property/label/heap/paging codecs** (`graphus-storage`).

**Setup:** `rustup +nightly component add miri` (the nightly toolchain is the project's miri channel;
`cargo +nightly miri --version` confirms).

**Justified exclusions (minimal; never to hide UB):**

- **`graphus-wal`** — several tests that do real filesystem I/O (the production `FileLogSink`'s
  `open`/`remove_file`/`remove_dir_all`) are `#[cfg_attr(miri, ignore)]`: miri's filesystem
  **isolation** aborts real syscalls. The WAL *logic* is validated over the in-memory `MemLogSink`
  (which runs under miri). A multi-MiB retained-WAL recovery test is likewise excluded as too slow —
  the same recovery logic runs under miri on tiny windows.
- **`graphus-index`** — `btree::tests::many_inserts_grow_the_tree_height` (1000 inserts × page splits)
  and the histogram equi-depth-**estimation** tests (~1000-row datasets) are `#[cfg_attr(miri, ignore)]`:
  impractically slow under the interpreter, and they test numeric estimation, not codec UB. The B-tree
  split/grow logic is covered by the smaller miri-run tests and the native `tests/btree_props.rs`
  proptest; the histogram *byte codec* is covered by `codec_roundtrip_*` / `decode_rejects_*` (which
  run under miri).
- **`graphus-bolt`** — the `server::tests` module is `#[cfg(all(test, not(miri)))]` (its end-to-end
  sessions call the deliberately CPU-expensive Argon2 password KDF). Six codec tests are additionally
  `#[cfg_attr(miri, ignore)]`: a 200k-key map decode with a "linear not quadratic time" **timing**
  assertion, a 70 KB string, a ~66 KB multi-chunk frame, a 2000-message compaction run, and two
  max-depth (`nest ≈ 1000`) **native-stack**-safety tests — all too slow under miri and testing
  timing / perf / native-stack behaviour, not byte-codec UB. The wire codec
  (framing/message/handshake/packstream) is covered by those modules' small miri-run tests; the string
  test was **split** so the small-marker cases still run under miri.
- `graphus-storage` non-codec tests (`store::`, `check::`, `recovery::`, `backup::`, `wal_rule::`) are
  out of the miri command's scope by test-name filter: they drive the full store over the paging
  substrate (slow under miri) and exercise the same codecs the scoped tests already cover.

Runtime is dominated by the interpreter (miri is ~100–1000× slower than native) and is
machine-dependent; the exclusions above keep the codec-only gate practical (`graphus-bolt` ≈ 17 s and
`graphus-core` ≈ 90 s on the reference machine). If `rustup component add miri` ever fails (offline CI),
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

**Expected:** `proptest_codecs` → `9 passed`; `proptest_keycodec` → `3 passed`.

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
(`Person`/`KNOWS`, `Forum`/`Post`/`Comment` with `HAS_CREATOR`/`REPLY_OF`/`CONTAINER_OF`, plus
`Tag`/`Place`/`Organisation` dimensions) and run representative SNB-style read/write operations
through the **real** engine pipeline, reporting
throughput + latency percentiles. It is **not** the official LDBC driver — see
`crates/graphus-bench/LDBC.md` for the provenance, the schema, the query→official-SNB mapping, and the
deferred official queries (those needing Cypher the young engine does not yet support).

```sh
cargo run -p graphus-bench --bin ldbc_snb              # tiny scale (seconds)
cargo run -p graphus-bench --release --bin ldbc_snb -- --medium
cargo test -p graphus-bench --lib ldbc                  # as a self-checking test
```

**Expected:** the harness runs to completion and prints a report ending in
`N/N operations supported and measured`. At the tiny scale it builds a **191-node / 898-relationship**
graph (60 persons, 6 forums, 36 posts, 72 comments, 8 tags, 5 places, 4 orgs; 454 `KNOWS`), builds
**3 property indexes** (`Person.id`, `Forum.id`, `Post.id`), and measures **all 34 SNB-flavoured
operations** across the Interactive Short (`IS1`–`IS7`), Interactive Complex (`IC*`), Business
Intelligence (`BI*`), degree, and insert/update families; the remaining official queries are deferred
where they need Cypher the engine does not yet express (see `LDBC.md`). With the property indexes in
place, id-keyed point lookups run in the low hundreds of microseconds (e.g. `IS1-profile` ≈ 250 µs
p50) and the heaviest multi-hop / aggregation queries in the low single-digit milliseconds; the
numbers are stable run-to-run (deterministic generator) and every operation is checked against the
generator's ground-truth by `cargo test -p graphus-bench`.

---

## 9. Examples suite — end-to-end, in both modes (AC: "every example still passes, against a self-booted AND an already-running instance")

The twelve examples under `examples/` are not documentation: each one boots a **real
`graphus-server`**, drives it over its public surface (a Neo4j driver / Bolt / REST / UDS), asserts
every step, and collects evidence across all of Graphus's performance vectors. They are the project's
instrument for exposing regressions, fragilities and resource inefficiencies in a real end-to-end
server — which is exactly why they are a **gate** and not a demo.

They earned that status the hard way. For as long as nothing ran them, they rotted in place: a failing
example sat on `main` unnoticed; reports published fabricated zeros (`bytes_per_node: 0.0` —
"this graph costs nothing to store" — with a baseline gate comparing 0.0 against 0.0 and passing); and
a durability example that only *sometimes* injected the crash it claimed to inject still went green.
Every one of those defects was found the moment the suite was actually executed. An example that is
never run cannot expose anything.

```sh
scripts/examples-gate.sh            # both modes — this is what verify.sh runs
scripts/examples-gate.sh --local    # self-boot mode only
scripts/examples-gate.sh --attach   # attach mode only (boots the target instance itself)
```

The gate runs the suite **twice**, because the examples make two distinct promises and each can rot
on its own:

- **LOCAL** — every example self-boots its own server and measures it directly (`/proc` CPU and RSS,
  on-disk store and WAL bytes). This is the only mode that can produce the process and storage
  vectors, so it is also the only mode a committed baseline may be captured from.
- **ATTACH** — the gate boots ONE instance exactly as the container image does (self-signed TLS,
  Bolt-TCP + REST + UDS, an admin identity) and points every attach-capable example at it via the
  `GRAPHUS_TARGET_*` seam; each example isolates itself in a run-scoped database. This proves the
  "runnable against an already-running Graphus, local **or remote**" promise on every run instead of
  asserting it in a README. The two durability examples are local-only by construction — they SIGKILL
  the server to prove crash recovery, so they cannot target a shared instance.

**Expected:** every example passes in both modes; the suite's own **evidence-honesty audit** passes
(no report emits a zero for a metric it did not measure); and the attach target survives the whole
suite with **no panic and no force-detach** — a server that dies under the examples is a server
finding, not a test artefact, and no per-example verdict can see it.

**Runtime:** ~2–4 minutes for both modes at the examples' default profiles. The larger profiles
(`SOCIAL_PROFILE=large`, `FRAUD_PROFILE=large`, …) are for real evaluation, not for the gate.

---

## 10. Read-polarity census — the rule for any new constraint or validation path (`rmp` #905)

**What it is.** Every read of the record store returns raw physical state. Which *answer* the caller
owes back is one of three (`04-technical-design.md` §5.3, and `graphus_storage::scan_polarity`):

- **superset** — index population. The consumer re-checks each candidate against its own snapshot, and
  a re-check can remove a candidate but never resurrect one, so a hole is unrecoverable.
- **decision** — constraint validation. The verdict is written into the catalogue and nothing
  re-checks it, so it must be exactly what the deciding snapshot sees.
- **conservative** — a pruning structure (the zone map). It excludes an id range *before* any re-check
  runs and nothing repairs it, so it may never narrow on unproven state — and the re-check that turns
  its candidates into rows must run at the reader's snapshot, on a seam that owns one (`rmp` #958).

Reading raw is **correct** for the first and **wrong** for the second. That single confusion produced
three CRITICAL defects (`rmp` #771, #902, #904), and in each of them a docstring asserted the wrong
polarity and was believed.

**Invocation:**

```sh
cargo test -p graphus-cypher --test read_polarity_census
cargo test -p graphus-storage --test scan_polarity_barrier
```

**Expected:** green. Both files run in well under a second and read source text, so they cost nothing
to keep on every push.

**The checklist, for a reviewer or an author adding a constraint, a validation path, an index refill
or any data-skipping structure:**

1. **Name the polarity before writing the read.** Which of the three does this code owe? If the
   answer is "it does not matter", the code is a decision path and the answer is *decision*.
2. **A decision path takes a `Snapshot`.** Resolve values through `RecordStore::decision_scan_*`.
   Handing it a raw chain does not compile — `DecidedProperties` has no other constructor — and
   walking a raw chain inline is caught by gate 10.
3. **A population or pruning path gates labels on `RecordStore::node_label_superset`,** never on
   `node_labels`. The live word is a *subset* while an uncommitted `REMOVE n:L` is open.
4. **If you must read raw somewhere new, classify it in the census** — in
   `read_polarity_census.rs`'s module docs — **with the reason it is correct there.** An entry with
   no justification is not an entry. The census also records the two shapes that sit outside the
   three: the write path (which reads the image it has just written) and a memoization with a total
   fallback (where a hole costs a decode, not a row).
5. **Do not trust a docstring about polarity that you have not checked against the code.** That is
   not a figure of speech: it is what happened three times.

**When gate 10 fails**, the new code is not necessarily wrong. It means a polarity-sensitive read
appeared or moved and nobody classified it. Classify it, then either fix the read or extend the
census table with its justification.

---

## 11. Official Neo4j driver interop — the wire claims, proved by a real client (`rmp` #960)

Three of the project's four inviolable claims are claims about **interoperability**: that any Bolt
client, "including the official Neo4j driver ecosystem", can talk to Graphus exactly as the
specification mandates. Every other test in this repository checks Graphus against Graphus's own
reading of those specifications. This suite is the only one that checks it against an **unmodified,
official `neo4j-driver`**, driven from Node.js over a real socket: connect, authenticate, run
parameterised reads and writes, explicit and managed transactions, and read the results back.

```sh
cargo test -p graphus-server --features neo4j-interop --test neo4j_driver_interop -- --test-threads=1
```

**Prerequisite: `node` and `npm` on `PATH`, plus network access** (the harness runs
`npm install neo4j-driver`). This is why the suite sits behind the opt-in `neo4j-interop` cargo
feature: a plain `cargo test` must stay hermetic. `--test-threads=1` is required — each test boots a
server and they share one npm prefix.

**Why it is a gate and not an optional extra.** The opt-in feature is exactly how `rmp` #960 stayed
hidden. The suite has existed since 2026-06-15 (`rmp` #226/#230) and no automated gate has ever enabled
it. So when #865 introduced the defect on 2026-07-26,
`official_neo4j_driver_full_crud_nodes_and_edges` began failing on `main` — reporting
`after CREATE edges, count=0, expected 200` — and every gate that *does* run stayed green, start to
finish. The defect it was catching was a silent wrong answer: a `MATCH` predicate combining a
driving-row variable with a query parameter matched nothing, which broke the `UNWIND … MATCH … CREATE`
idiom every driver uses to write relationships in bulk. A test that nothing runs cannot fail, and a
claim nothing tests is not a claim.

`scripts/verify.sh` therefore runs it as step 8, and **fails hard** when `node`/`npm` are absent rather
than skipping. A gate that quietly skips is indistinguishable from a gate that passes — the very
property that let this regression survive. The consequence is deliberate: `scripts/verify.sh` cannot
complete on a machine with no network access, because it cannot honestly claim conformance it did not
measure.

**When gate 11 fails**, treat it as a conformance defect first, not a harness defect. The driver is the
reference implementation of the protocol; if it disagrees with Graphus, Graphus is the one that has to
change.

---

## 12. Property visible-read record count — the `rmp` #967 headline claim, measured

`rmp` #967 moved a property overwrite to "newest version written in place, old value on the entity's
undo chain". Its headline acceptance criterion is that **reading the visible property no longer walks
the version chain** when the reader sees the live version — the whole point of the redesign, and the
reason the pre-#967 read cost grew with the number of overwrites.

That claim is proved by a **record-read count**, not a timing. The count is a property of the
algorithm; a timing is a property of the host, because after the writes the whole chain is resident in
the buffer pool and a big enough cache walks thousands of records fast enough to pass any threshold
loose enough not to be flaky. The suite measures the reads at two chain lengths (M = 1000 and
M = 8000) and asserts the whole `(prop, undo, commit)` triple is **identical** — comparing the triple
rather than its total is what stops the walk from being merely *relocated* into the undo chain or the
commit indirection.

```sh
cargo test -p graphus-storage --features read-probe --test prop_visible_read_record_count
```

**Expected:** `test result: ok. 3 passed`
(`visible_read_record_count_is_identical_at_m1000_and_m8000` — the criterion;
`a_visible_read_costs_exactly_one_record_in_each_store` — the exact constant `1/1/1`;
`distinct_keys_still_cost_one_record_read_each` — the direction in which growth is still correct).

**`--features read-probe` is mandatory, and this is why it is a gate.** The instrumentation is a cargo
feature that is **off by default**: it sits on the hottest read in the engine, and defaulting it on (or
carrying it as a dev-dependency, which cargo would unify into every workspace test and bench resolve)
would perturb the very benchmark #967 exists to measure. The test file is therefore
`#![cfg(feature = "read-probe")]`, so a plain `cargo test -p graphus-storage` **compiles it away** and
asserts nothing.

That is the exact shape of `rmp` #960 (gate 11): a suite behind an opt-in feature that no automated
gate ever enabled, so the defect it existed to catch sat on `main` while every gate that did run
stayed green. `04-technical-design.md` §11.6 was ratified by #967 itself to stop that recurring — and a
headline acceptance criterion asserted by nothing any gate executes is that same defect, one release
later. `scripts/verify.sh` runs it as step 4.

**When gate 12 fails**, the property read has started walking the chain again — most likely because a
read path was moved off `decision_scan_*` onto a fold over the cells' own MVCC stamps, or because a
new indirection was introduced between the cell and its value. Check which of the three counters grew:
`prop` means the `props.store` chain, `undo` the delta chain, `commit` the slot indirection.

---

## 13. Deterministic writer scheduler (`rmp` #973)

Puts the **interleaving of real OS threads** under a seeded scheduler, so a concurrency defect
reproduces from a seed the way a crash already does. A single execution token is handed from thread
to thread at declared yield points — page-latch acquisition and release, thread spawn/exit, the two
halves of commit publication, snapshot acquisition, each GC phase — and the successor is drawn from a
`SimRng`. The global order of operations is therefore a pure function of the seed.

The scheduling history is materialised as fixed-width 24-byte little-endian records, so two runs are
compared **byte for byte** (`Vec<u8> == Vec<u8>`) rather than through a digest that can only say
"different".

**What the suites assert**

| Suite | Claim |
| ----- | ----- |
| `graphus-dst/src/detsched.rs` unit tests | the mechanism itself: replay, exploration, fixed-width records, and that an unreleasable park is reported as a **deadlock** rather than hanging |
| `tests/det_scheduler_gc_reader_811.rs` | over the **real two-thread engine**: the same seed replays byte-identically; different seeds explore; and the `rmp` #811 severance window (an off-thread reader mid-chain-walk while GC reclaims the tombstone above it) is now entered **by construction** rather than by luck |
| `tests/det_scheduler_elle_oracle.rs` | the isolation oracle still rules on the histories produced — on a genuinely two-threaded scheduled history, and on the existing VOPR safety run with a scheduler installed over it |

`graphus-storage`'s own `offthread_reader_never_loses_live_property_across_gc_811` remains the
probabilistic owner of the same window: it hammers 20 000 cycles hoping the OS scheduler cooperates,
and it cannot say whether the window was ever entered. The scheduled suite enters it in 24 cycles and
**proves** it did, by finding the GC phase-D step between two of the reader's record-read steps in
the history.

**Cost in production: zero.** The seam (`graphus_core::sched`) is gated on the `det-sched` cargo
feature, off by default and enabled by no dependency declaration anywhere in the workspace. With it
off, `yield_at` is an empty `#[inline(always)] const fn`, `acquire` reduces to its blocking closure,
the release guards are zero-sized types with empty `Drop` bodies, and `spawn` is
`std::thread::spawn`. Verified mechanically:

```sh
cargo build --release --locked -p graphus-server
nm -C target/release/graphus-server | grep -c 'graphus_core.*sched'   # must print 0
```

Deliberately **not** `debug_assertions` (the gate `graphus_core::latch` uses). That tripwire wants to
be armed across the whole suite because it is a correctness tripwire costing a thread-local
increment; a scheduler hook is hot-path instrumentation sitting on `with_page_fetched`, and arming it
in every `cargo test --workspace` would instrument the very paths the other gates certify.

It is also mutually exclusive with `--cfg loom` and with ThreadSanitizer, enforced by `compile_error!`:
both of those lanes own the thread interleaving themselves, and TSan running under a scheduler that
totally orders every step would report **zero** races — a vacuously clean soak.

**Run it:**

```sh
cargo test -p graphus-dst --features det-sched --lib detsched::
cargo test -p graphus-dst --features det-sched --test det_scheduler_gc_reader_811
cargo test -p graphus-dst --features det-sched --test det_scheduler_elle_oracle
```

`scripts/verify.sh` runs all three as step 5. The suites declare `required-features = ["det-sched"]`,
so `cargo test --workspace` does not even compile them — which is deliberate, and which is exactly
why the gate invokes them explicitly: a suite behind an opt-in feature that no gate enables is the
`rmp` #960 defect class.

**When gate 13 fails**, read the message before the diff. A *byte divergence at step N* names the
first step where two runs of one seed disagreed — look for a new source of nondeterminism on the
scheduled path (an address in a decision, a `HashMap` iteration, a wall-clock read). A *DEADLOCK*
or *STALLED* report means a yield point was placed inside a latched region, or an unscheduled thread
holds a resource a scheduled thread needs; the message prints who is runnable and who is parked on
what.

---

## Quick start

```sh
# Fast gates only (build/clippy/fmt, anomaly, read-polarity census, visible-read record count,
# deterministic writer scheduler, proptest, regression gate, LDBC, examples, official-driver
# interop) — every push:
scripts/verify.sh

# Add the slow gates as needed:
scripts/verify.sh --with-loom     # + loom model-check
scripts/verify.sh --with-miri     # + miri UB gate (nightly + miri)
```
