# Knowledge Graph Model — graphus

The contract between the `knowledge-authority` skill and the `graphus` knowledge
graph (`rmp graph -r graphus`). It declares every label, edge type, property and
enumerated vocabulary the graph may contain, and the criteria that **prove** the
graph reflects the code.

**Bootstrapped 2026-07-16 at commit `f360da4`.** This model replaces the one
retired on 2026-07-16, when the previous graph (876 nodes / 1232 edges) was
emptied for making claims that were not true.

Everything below describes the **live graph**, not an intention. Counts are exact
and are re-checked by `scripts/kg/audit.py`, which is green at 17/17.

## 1. Cardinal principles

Each is a countermeasure to a defect that was *proven* — in the retired graph, or
in this model's own first draft.

1. **Derived, never authored.** Every fact comes from the compiler
   (`rustdoc --output-format json`), `cargo metadata`, or `git`. The graph is
   **rebuilt, not patched**: a partial patch is how a graph starts lying.
2. **Authoritative sources only — and never trust a scan a parser can replace.**
   *Proven necessary:* a naive grep of the decision register reported 35
   decisions; 3 were substrings of unrelated words (`SSD-vs-rotational` yields
   `D-vs-rotational`). The register now carries a machine-readable fence (§8).
3. **rmp owns task state; the graph never mirrors it.** No node carries a task's
   `status`, `severity` or `title`. A commit references a task only by
   `rmp_task` (integer). *The retired graph froze `status:'OPEN'` at import time
   and then lied about five completed tasks.*
4. **Enumerated vocabularies.** Every categorical property has a closed enum (§5).
   Off-enum or null is a defect. *The retired graph held 14 values for
   `Finding.status` — including 16 nulls and both `open` and `OPEN` — so
   `MATCH (f {status:'open'})` returned a wrong answer.*
5. **Identity is never overloaded with foreign-key semantics.** Each label has one
   identity property (§3). Where a property denormalizes a 1-hop lookup
   (`Symbol.crate`, `Symbol.file`, `Test.crate`), it is declared here as a
   denormalization and criterion **C16** asserts it agrees with the edge. Two
   mechanisms may encode one fact only if something checks they still agree.
6. **One fact, one direction.** No inverse-duplicate edge types.
7. **One node per real thing.** *Enforced, not hoped:* 268 rustdoc `module` items
   whose span is `1:1` ARE their file and are dropped — modelling them would put
   `File` and `Symbol` nodes on one thing. **C15** asserts `Symbol` and `Test`
   never share a location.
8. **Explicit scope boundary (§6).** What is excluded is written down, so absence
   is never mistaken for drift.
9. **Provenance that can fail.** Every element carries `gitCommit` + `gitDate`,
   and a singleton `Build` node records the rebuild. **C12** asserts they all
   equal `HEAD` — which catches a *partial* rebuild. (A "not newer than HEAD"
   check could never fail and would be vacuous.)
10. **No criterion is trusted until it has been seen to fail.** See §7.

## 2. Fidelity claim

**Absolute fidelity is claimed for the whole graph, and it is proven mechanically.**
There is no curated tier: every node and edge is derived. The semantic layer that
would normally require judgement (which decision affects which code, which spec
governs which file) is instead derived from what the code **actually cites** —
`CITED_IN` and `CITES` are facts about the source text, not opinions.

## 3. Labels — exact counts at `f360da4`

| Label | Identity | Properties | Count | Source of truth |
|---|---|---|---|---|
| `Symbol` | `key` = `{file}:{line}:{col}` | `name`, `kind`, `crate`, `file`, `line`, `col`, `targets`, `owner`? | 5264 | `rustdoc` JSON |
| `Test` | `key` = `{crate}::{target}::{module_path}::{name}` | `name`, `crate`, `target`, `module_path`, `file`, `line`, `kind`, `harness`, `cfg`? | 5159 | source scan |
| `File` | `path` | `kind` | 660 | `git ls-files '*.rs'` |
| `Commit` | `hash` (40 chars) | `date`, `summary`, `rmp_task`? | 575 | `git log` |
| `ExternalCrate` | `name` | — | 52 | `cargo metadata` |
| `Crate` | `name` | `path`, `description`, `version`, `publish_false`, `doc_targets` | 35 | `cargo metadata` |
| `Decision` | `key` (`D-*`) | `status`, `chosen`, `ratified_on`? | 31 | register fence (§8) |
| `Example` | `path` | `name`, `has_baseline`, `has_readme` | 12 | `examples/*/run.sh` |
| `Doc` | `path` | `title` | 11 | `git ls-files 'docs/**.md'` |
| `Spec` | `path` | `title` | 10 | `git ls-files 'specification/*.md'` |
| `Release` | `tag` | `date` | 9 | `git tag` |
| `Build` | `gitCommit` | `gitDate`, `targets` | 1 | the rebuild itself |

**Total: 11,819 nodes.**

`Symbol.key` is `file:line:col`. Uniqueness is **proven** (0 collisions over 5264)
— but only after the derive filter (§8); in the first draft, uniqueness was an
*artifact* of the bug, because each `#[derive(...)]` argument landed on its own
column. It is **location-based and therefore unstable**: inserting a line rekeys
every symbol below it. That is acceptable only because the graph is rebuilt, never
diffed. Attaching durable per-symbol facts (coverage, findings) would require a
stable key first.

`Symbol.targets` records which of the three `D-target-matrix` Tier-1 targets the
symbol was **observed** under. `Crate.doc_targets` records which targets that crate
could be **checked** on. The pair is what lets the graph distinguish *"absent on
macOS"* from *"never checked on macOS"* — 7 crates (`auth`, `cli`, `dst`,
`durability-demo`, `reco-gen`, `rest`, `server`) cannot cross-document because
`aws-lc-sys` (rustls's C backend) needs a target C toolchain that is not installed.
**Verified invariant:** 0 symbols are macOS-only across the 28 checkable crates —
every platform difference in this repo sits inside a function body or on a private
item, so the public API is platform-invariant.

## 4. Edge types — exact counts

One direction each. Identity is `(from, to)` plus any property marked `{…}`.

| Edge | From → To | Count | Meaning |
|---|---|---|---|
| `DEFINES` | `File` → `Symbol` \| `Test` | 10423 | the file is the item's syntactic home |
| `TOUCHES` | `Commit` → `File` | 3307 | the commit changed the file |
| `CONTAINS` | `Crate` → `File` | 660 | crate ownership (longest-path match) |
| `DEPENDS_ON {kind, target}` | `Crate` → `Crate` \| `ExternalCrate` | 292 | a cargo dependency |
| `CITED_IN` | `Decision` → `File` | 58 | the source names the decision key |
| `CITES` | `File` → `Spec` | 50 | the source names the spec path |
| `DRIVEN_BY` | `Example` → `Crate` | 34 | `run.sh` invokes `-p <crate>` |
| `AT_COMMIT` | `Release` → `Commit` | 9 | the tag's commit |

**Total: 14,833 edges.**

`DEPENDS_ON` carries `kind` **in its identity** because the relation is genuinely
multi-valued: `graphus-rest → graphus-auth` exists as *both* `normal` and `dev`
(16 such pairs). It carries `target` because 11 dependencies are cfg-gated
(`loom`, macOS `libc`, Linux `rustix`); asserting them unconditionally would be
false for every real build.

`DEFINES` is deliberately overloaded across `Symbol` and `Test`: the semantics
(*"F is the item's syntactic home"*) do not change with the target, `labels(x)`
discriminates, and splitting it would turn *"what does this file define"* into a
union query. Its safety rests on **C15** (disjointness), which is asserted, not
assumed.

## 5. Enumerated vocabularies (closed)

A value outside these sets, or null, is a defect. Asserted by **C8**.

| Property | Allowed values |
|---|---|
| `File.kind` | `src` · `test` · `bench` · `bin` · `build` · `fuzz` |
| `Symbol.kind` | `function` · `struct` · `enum` · `trait` · `constant` · `type_alias` · `module` · `macro` · `union` · `static` |
| `Test.kind` | `unit` · `integration` · `bench` · `bin` |
| `Test.harness` | `test` · `tokio_test` · `proptest` |
| `Decision.status` | `ratified` · `open` |
| `DEPENDS_ON.kind` | `normal` · `dev` · `build` |

`fuzz` is in `File.kind` because the repo has 3 fuzz files; an enum that cannot
classify its own inputs fails at bootstrap. `macro`/`union`/`static` and
`DEPENDS_ON.kind = build` are currently **unpopulated** (0 items) — they are
declared because rustdoc/cargo can emit them, and populating one must not require
a model change.

`Commit.rmp_task` is an **integer or absent**, never a string; it is set only when
the summary matches `rmp #(\d+)`. *The retired graph stored `'release'` and
`'docs'` here.* 250 of 575 commits carry one.

## 6. Scope boundary — deliberate exclusions

**Not** gaps. The audit does not look for these, and their absence is never drift.

- **Private items.** Only the public API surface is modelled (`rustdoc` without
  `--document-private-items`). A private helper is found by reading the file —
  the documented fallback.
- **`impl` blocks, struct fields, enum variants, `use` re-exports, associated
  types.** Too fine-grained; they churn on every edit for little query value.
  `Symbol.owner` carries the impl's self-type where rustdoc resolves it, so the
  useful part survives without the nodes.
- **"Which tests cover X".** *The graph cannot answer this and does not pretend
  to.* There is no test→subject edge: `Test`'s only edge is `File DEFINES Test`,
  so the best available traversal is *"tests in the same crate"*, which for
  `graphus-storage` returns hundreds of ~5159. An honest answer needs per-test
  coverage (`cargo llvm-cov`); it is deliberately deferred, not silently missing.
- **Call graph.** No `Symbol → Symbol` edges. Impact analysis therefore resolves
  to **file** granularity via `TOUCHES` co-change, and to **crate** granularity
  via `DEPENDS_ON`. It cannot answer "which functions break if I change this one".
- **Symbol → Symbol containment** (module membership, type→method). Not modelled;
  `Symbol.owner`/`Symbol.crate` are the flat substitute.
- **rmp tasks and sprints as nodes.** rmp is the authority (principle 3).
- **Bin, test and bench target symbols.** `rustdoc --lib` covers library surfaces
  only, so 51 bins (~29k LOC) contribute `File` and `Test` nodes but no `Symbol`.
  367 of 660 `File` nodes therefore have no `DEFINES`→`Symbol` edge; that means
  *"not examined for symbols"*, not *"defines nothing"*.
- **The four inviolable requirements** (ACID / Cypher TCK / Bolt / PackStream) are
  not modelled. The graph cannot answer *"does this change touch something a
  compliance requirement rests on"*. Named here so the absence is explicit.
- **Line counts and sizes.** Volatile, no query value, guaranteed to go stale.

## 7. Auditing this graph — 17 criteria, all green, all proven able to fail

`scripts/kg/audit.py` (exit 0 = all hold). Every criterion computes a symmetric
difference against an authoritative source and reports how many elements it
examined; **a criterion that examines 0 elements FAILS as vacuous.**

| # | Criterion | Anchored to |
|---|---|---|
| C1 | `File` ⟷ `git ls-files '*.rs'` | git |
| C2 | `Crate` ⟷ `cargo metadata` | cargo |
| C3 | **every `Symbol` is declared in the source text at its `file:line`** | **the file bytes** |
| C4 | identity present + unique, for **every** label | graph |
| C5 | `DEPENDS_ON` ⟷ `cargo metadata`, incl. `kind`/`target` | cargo |
| C6 | `Commit` ⟷ `git log`, dates match | git |
| C7 | `Release` → the tag's real commit | git |
| C8 | every enumerated property in-enum, non-null | §5 |
| C9 | `Commit.rmp_task` integer-or-absent | graph |
| C10 | no label outside §3 | §3 |
| C11 | no edge type outside §4 | §4 |
| C12 | provenance == `Build` commit == `HEAD` (catches a partial rebuild) | git |
| C13 | every `Spec`/`Doc`/`Example` path exists on disk | filesystem |
| C14 | `Decision` ⟷ the register's canonical fence | §8 |
| C15 | `Symbol` and `Test` never share a location | graph |
| C16 | `Symbol.crate` agrees with `CONTAINS`/`DEFINES` (FK ⟷ edge) | graph |
| C17 | `Test` count ⟷ the source `#[test]`/`#[tokio::test]` census | **the file bytes** |

**C3 and C17 are the non-circular core.** A criterion that re-runs the extractor
and compares it to the graph can only prove the graph matches the extractor — it
goes green on a graph built from a *wrong* extractor. Proven: an early extractor
emitted 61 foreign symbols from dependency blanket-impls, and an
extractor-vs-graph check passes on every one of them. C3 anchors to the file bytes
instead, and rejects both that class and the derive-span class.

**Non-vacuity — verified 2026-07-16, not assumed.** Each criterion was made to
fail by deliberate corruption, then the graph was restored by rebuild:

| Mutation | Criterion that fired |
|---|---|
| moved `BufferPool`'s line to 1 | C3 — *no `struct` at pool.rs:1* |
| set `File.kind = 'SRC'` | C8 — *File.kind='SRC' x1* |
| set one `gitCommit = 'deadbeef'` | C12 — *stale=1* |
| deleted a `File` node | C1 — *in repo only (1)* |

## 8. Extractors

`scripts/kg/` — the graph is rebuilt from scratch by:

| Script | Role |
|---|---|
| `rebuild.sh` | the whole pipeline: rustdoc × 3 targets → extract → populate → audit |
| `extract.py` | nodes/edges as JSON, from rustdoc + `cargo metadata` + `git` (~7 s) |
| `populate.py` | wipe + batched `rmp graph create` (~57 s) |
| `audit.py` | the 17 criteria (~7 s) |

Symbol extraction needs nightly rustdoc:
`RUSTDOCFLAGS='-Zunstable-options --output-format json' cargo +nightly doc --workspace --no-deps --lib`
(~22 s per target).

**Three extractor invariants, each proven necessary against this repo:**

1. **Foreign spans.** rustdoc's index carries items from *dependencies* (blanket
   impls). Spans must be filtered to paths starting with `crates/`. Unfiltered,
   the symbol count inflates by 61 with another project's code.
2. **Derive-synthesized functions.** A function whose span *equals its parent
   impl's span* is generated by `#[derive(...)]`, and its span points **inside the
   attribute** — `limits.rs:45:10` is the `Debug` token in `#[derive(Debug, Clone)]`,
   where no function is written. 2403 such items (30% of the raw set) must be
   dropped, or the graph asserts 2403 declarations that do not exist.
3. **Edge properties must be Cypher literals.** `rmp graph` does **not** resolve
   an `UNWIND` row variable inside a *relationship* property map — it writes
   `null` and reports success. (Node property maps resolve correctly.) With every
   `kind` nulled, `MERGE` then collapsed `normal` and `dev` into one edge and 292
   real dependencies silently became 276. `populate.py` groups by property value
   and emits literals.

The decision register (`specification/02-decision-register.md`) carries a
canonical, machine-readable index fenced by
`<!-- BEGIN decision-index -->` / `<!-- END decision-index -->`, one row per
decision:

```
| `D-cypher-line` | ratified | 2026-06-05 | openCypher 2024.x line, … |
```

parsed by ``^\| `(D-[a-z0-9-]+)` \| (ratified|open) \| (\d{4}-\d{2}-\d{2}|—) \| (.+) \|$``.
The fence exists because **no text-scan rule was reproducible**: grep yields 35
(3 false), a backtick-or-table-row rule yields 28 and drops 4 real decisions
(`D-wire-protocol`, `D-bolt-compat`, `D-vopr`, `D-graph-algos`). Parsing the fence
is the only rule that reproduces its own count.

## 9. Materialization status

**Populated:** every label and every edge type in §3 and §4 — the whole model.
**Declared but empty:** `Symbol.kind` ∈ {`macro`, `union`, `static`},
`DEPENDS_ON.kind = build` (0 in the repo today; see §5).
**Deliberately absent:** everything in §6.

## 10. Known content issues (reported, not silently fixed)

Surfaced during the bootstrap and left for the owner to rule on:

1. **`D-bulk-import-non-atomic` is not in the register.** `02-decision-register.md`
   cites it as *"the already-ratified"* decision, but it is registered only in
   `08-network-bulk-import.md`. The parser therefore treats it as a
   cross-reference and the graph has 31 `Decision` nodes, not 32.
2. **Status-vocabulary clash.** The register's sprint-19 note describes
   `D-read-parallelism` / `D-perf-deferrals` as KG nodes with `status: deferred`
   — a third value this model's enum does not admit. Both are indexed `ratified`
   (the decision *was* ratified; the ratified *choice* is "DEFER…").
3. **`01-needs-survey.md:11`** says "(all 24 ratified 2026-06-05)", true of the
   baseline but misleading now that 31 are registered.
