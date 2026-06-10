# JVM `tck-api` cross-check — deferred

## Status: deferred (settled decision)

The openCypher project ships a JVM (Scala) `tck-api` that parses the feature corpus into an in-memory
object model and exposes a small interface an implementation hooks into (see `tck/README.adoc`
§"Installation instructions"). Cross-validating Graphus's interpretation of the corpus against that
reference parser would be a second, independent source of truth for *how the feature files are meant
to be read* (outline expansion, the expected-value mini-language, the error-step grammar, the
side-effect metrics).

**This cross-check is deliberately not run in this environment, and that is a settled decision — do
not attempt to run any JVM here.**

### Why

- There is **no JVM in this environment**: `which java` and `which javac` both return nothing.
- Pulling a JVM + the Scala `tck-api` + its Maven dependency tree into a Rust workspace's test path
  would add a heavy, cross-ecosystem toolchain dependency that violates the harness's self-contained,
  no-JVM design (`crates/graphus-tck/Cargo.toml` documents the choice of the pure-Rust `gherkin`
  parser precisely to avoid a Cucumber/JVM runtime).

### What is used instead — the embedded feature-file expectations are the ground truth

Every `.feature` file embeds, *in the file itself*, the complete expectation for each scenario: the
initial graph, the query, and either the expected result table (or `empty`), the expected error
`(TYPE, PHASE, DETAIL)` triple, or the expected side-effect counters. The harness
(`crates/graphus-tck/src/`) reads those embedded expectations directly and treats them as the ground
truth, which is exactly what a Cucumber-based integration of the same corpus would do. The corpus is
**pinned** (`tck/PINNED.txt`), so the expectations are frozen and reproducible.

Crucially, the harness does **not** re-implement Cypher value semantics to decide a match — it calls
the *engine's own* `graphus_cypher::equivalent` for scalar/list/map equivalence and compares
structural elements (nodes / relationships / paths) by labels-as-set + properties-as-map + path
shape. So a "pass" means *the engine agrees with the embedded expectation under the engine's own
value model*, not under a re-implementation that could drift.

### How to add the JVM oracle later (if a JVM becomes available)

The JVM `tck-api` would serve as a **parser oracle**, not a result oracle (Graphus is the
implementation under test; only its *reading* of the corpus is being double-checked). A faithful
integration would:

1. Add a JVM build step (outside `cargo`, e.g. a `justfile` / CI job) that runs the Scala `tck-api`
   over the pinned `tck/features/**` and emits, per scenario, a machine-readable normal form:
   the expanded steps, the parsed expected-result values, the error triple, and the side-effect
   counters (JSON, one record per concrete scenario after outline expansion).
2. Add a Rust test (feature-gated, e.g. `#[cfg(feature = "jvm-oracle")]`) that loads that JSON and
   asserts it agrees, scenario-for-scenario, with this harness's own parse
   (`graphus_tck::feature::load_feature` + `graphus_tck::value::parse_expected`). Any divergence is a
   bug in *our* corpus reading, to be fixed here.
3. Keep the JSON artefact pinned alongside `tck/PINNED.txt` so the oracle is reproducible without the
   JVM on every run — the JVM is needed only to *regenerate* the artefact when the pinned corpus is
   bumped.

This keeps the day-to-day `cargo test` path pure-Rust and JVM-free while still allowing a periodic,
out-of-band cross-check of the harness's corpus interpretation.
