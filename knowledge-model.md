# Knowledge Graph Model — graphus

The canonical description of the shape of the Graphus knowledge graph. The graph
itself lives in the `rmp` roadmap **`graphus`** and is queried exclusively through
`rmp graph` (`create` / `query` / `search` / `update` / `delete`).

This file is the **contract**: it states what the graph promises to contain and how
each fact is identified, so that any claim in the graph can be checked against the
repository. Without this contract the graph is unauditable — a divergence cannot be
told apart from a deliberate modelling choice.

- Roadmap name: `graphus`
- Last audited: 2026-07-16 against commit `b8fdc7b`
- Size at that audit: 874 nodes, 1229 edges, 30 labels, 52 edge types

## What this graph is — and what it is not

This is a **project-knowledge graph**, not a source-code index. It maps the
project's *reasoning and history*: requirements, domains, subsystems, decisions,
findings, releases, examples and the commits that carry them.

It deliberately does **not** model files, functions or types as nodes. There is no
`File` or `Symbol` tier and none is planned. "Where is X implemented?" is answered
by the `crate` / `path` properties on `Component`, `Example`, `Test`, `Feature` and
`Spec` — not by a per-file node. Every one of those properties is a repo-relative
path that MUST exist in the working tree; that is the graph's fidelity contract to
the code, and it is machine-checkable (see "Auditing this graph").

## Identity — the rule that prevents duplicates

Every node MUST carry a stable identity property. `MERGE` matches the **whole**
pattern, so only the identity property may appear in a `MERGE` map; everything else
is set by a follow-up `rmp graph update`.

| Label | Identity | Notes |
|---|---|---|
| `Commit` | `hash` | **7-char** abbreviated git hash, and it MUST resolve in this repo |
| `Release` | `tag` | git tag name, e.g. `v0.0.9` |
| `Sprint` | `id` | rmp sprint id |
| `Task` | `id` | rmp task id |
| every other label | `key` | lowercase kebab-case slug, unique within the label |

Never introduce a second identity property for a label (`sha`, `id`, `name`-as-key
have all been used in the past and were removed in the 2026-07-16 audit). A node
whose identity is unreachable by the canonical query is a fact the graph cannot
answer with.

## Labels

Counts are from the 2026-07-16 audit and will drift; the identity and required
properties are the contract.

### Core project model

| Label | n | Required | Common optional |
|---|---|---|---|
| `Project` | 1 | `name` | `architecture`, `language`, `kind` |
| `Requirement` | 8 | `key`, `name`, `tier`, `desc` | — |
| `Domain` | 15 | `key`, `name` | — |
| `Component` | 106 | `key`, `name` | `crate`, `path`, `rmp_task`, `commit`, `date`, `summary`, `prod_ready`, `certified_on` |
| `Feature` | 16 | `key`, `name` | `crate`, `path`, `commit`, `rmp_task`, `status`, `kind` |
| `Decision` | 35 | `key`, `name`, `status` | `chosen`, `rec`, `rationale`, `date`, `rmp_task`, `spec_doc` |
| `Phase` | 4 | `key`, `name`, `order` | — |
| `Spec` | 10 | `key`, `name`, `path` | `kind` |
| `Source` | 16 | `key`, `name`, `url` | — |

`Requirement.tier` is `inviolable` (ACID, Cypher TCK, Bolt, PackStream) or `core`.
`Decision.status` is `open` | `ratified` | `implemented`. `Decision.key` MUST match a
`D-*` id in `specification/02-decision-register.md`.

### History and delivery

| Label | n | Required | Common optional |
|---|---|---|---|
| `Commit` | 357 | `hash`, `date` | `summary`, `rmp_task`, `sprint`, `branch` |
| `Release` | 9 | `tag`, `version`, `commit`, `date` | `tck`, `kind`, `channel`, `url` |
| `Sprint` | 25 | `id`, `date`, `status` | `title`, `outcome`, `head_commit` |
| `Task` | 7 | `id`, `kind`, `status`, `title` | — |
| `Change` | 16 | `key`, `name`, `commit`, `date`, `detail` | `tasks` |
| `Milestone`, `DbState`, `Documentation`, `Rule`, `BuildPipeline` | 1 each | `key`, `name`, `date` | — |

`Commit.date` MUST equal `git show -s --format=%cs <hash>`. `Release.commit` MUST
equal `git rev-list -1 <tag>` (7-char) and `Release.version` is the tag without the
leading `v`.

### Quality: findings, bugs, tests, audits

| Label | n | Required | Common optional |
|---|---|---|---|
| `Finding` | 205 | `key` | `severity`, `status`, `date`, `rmp_task`, `component`, `fixed_commit`, `fixed_date` |
| `Bug` | 4 | `key` | `severity`, `status`, `symptom`, `root_cause`, `fix`, `commit`, `rmp_task` |
| `Test` | 9 | `key`, `name`, `path` | `count`, `covers`, `kind` |
| `Example` | 13 | `key`, `name`, `folder`, `iface` | `role`, `modes`, `status`, `commit` |

Audit labels — one per audit campaign, all identified by `key` and dated: `PerfAudit` (3),
`ReliabilityAudit` (3), `ProductionConfidenceAudit` (2), `SecurityAudit`,
`ConcurrencyAudit`, `CertificationAudit`, `Audit` (1 each). The proliferation is
historical: they are kept distinct because each carries campaign-specific properties
(`vectors`, `crates_covered`, `go_no_go`, …). Treat them as one conceptual tier —
"an audit that FOUND findings".

`Example.folder` MUST be an existing directory under `examples/`. Every directory
under `examples/` MUST have exactly one `Example` node — except `examples/run-all.sh`,
which is the suite runner and is modelled as `Component {key:'examples-run-all'}`.

## Edges

Canonical direction matters: each fact is stored **once**, in one direction. Do not
add an inverse edge type.

| Edge | Direction | n |
|---|---|---|
| `HAS_REQUIREMENT` | `Project` → `Requirement` | 8 |
| `HAS_DOMAIN` | `Project` → `Domain` | 21 |
| `INCLUDES` | `Domain` → `Component` | 51 |
| `DEPENDS_ON` | `Component` → `Component`, `Example` → `Example` | 63 |
| `AFFECTS` | `Decision`/`Finding`/`Bug` → `Domain`/`Component`/`Spec`/`Project` | 116 |
| `INTRODUCED_IN` | `Component`/`Example`/`Feature`/`Spec` → `Commit` | 85 |
| `UPDATED_IN` | any → `Commit` | 356 |
| `CHANGED_IN` / `CHANGES` | any ↔ `Commit` | 5 / 12 |
| `RATIFIED_IN` | `Decision` → `Commit` | 29 |
| `DOCUMENTED_IN` | `Domain`→`Source`, `Component`/`Finding`→`Spec` | 34 |
| `COVERS` | `Spec` → `Domain` | 32 |
| `HAS_SPEC` | `Domain` → `Spec` | 7 |
| `FOUND` | audit label → `Finding` | 114 |
| `REAUDIT_FOUND` | audit label → `Finding` | 5 |
| `SURFACED` | `Example`/`Task`/`Feature`/`Commit`/`Component` → `Finding` | 18 |
| `FIXED_BY` | `Finding`/`Bug`/`Task` → `Commit` (or `Component`) | 85 |
| `REMEDIATES` | `Commit` → `Finding` | 16 |
| `EXERCISES` | `Example` → `Domain`/`Component` | 67 |
| `VERIFIES` | `Example`/`Test` → `Component` | 7 |
| `VERIFIED_BY` | `Requirement`→`Domain`, `Component`/`Finding`→`Commit` | 6 |
| `TESTED_BY` | → `Test` | 2 |
| `GUARDS` | `Test`/`Component` → target | 11 |
| `TAGGED_AT` | `Release` → `Commit` | 9 |
| `PRECEDES` | `Phase`→`Phase`, `Release`→`Release` | 18 |
| `PLANNED_IN` | `Example`/`Task` → `Sprint` | 8 |

Long-tail edges used once or twice (`SHIPS`, `DELIVERS`, `GATES`, `EXTENDS`,
`DEFERS_TO`, `ROOT_CAUSE_OF`, `BLOCKED_BY`, `PREREQUISITE_FOR`, `TRANSPORT_FOR`,
`IMPLEMENTED_BY`, `IMPLEMENTS`, `REALIZES`, `USES`, `HAS_BINARY`, `INTRODUCES`,
`LED_TO`, `OBSERVED_ON`, `CONFIRMS`, `ASSESSES`, `AUDITS`, `FOLLOWS`,
`ADVANCED_IN`, `CERTIFIED_BY`, `DRIVES_INLINE`, `RATIFIED_DURING`) express
one-off relations. Prefer an existing edge over minting a new one.

## Conventions

- **`rmp_task`** — the single property naming an rmp task, on every label. Digits
  only, comma-separated for several (`'706,719'`). Never `#706`. Never `task` or
  `rmp`. Every id MUST exist in the `graphus` roadmap.
- **Provenance** — `gitCommit` (full hash) + `gitDate` (ISO date) record when a fact
  was last confirmed. Historically absent; back-filled from the 2026-07-16 audit
  onward on every node and edge that is written. Nodes also carry a domain-specific
  `date` / `commit` describing the fact itself — these are different things and both
  are kept.
- **Hashes** — abbreviated to 7 chars everywhere except `gitCommit`, which is full.
- **Writing** — `rmp graph create` rejects `SET`, including `MERGE … ON CREATE SET`.
  Upsert is always two calls: `create` with a MERGE on identity only, then `update`
  for the rest. The validator also rejects Cypher clause keywords as substrings of
  string literals; prefer `SET a.x = b.y` property references, `STARTS WITH` prefixes,
  or `WHERE id(n)=…` over long literals.

## Auditing this graph

Fidelity is verifiable, not aspirational. These properties MUST hold, and each is
checkable by a script (see the audit recipe in the `knowledge-authority` skill):

1. Every `Commit.hash` resolves in git, and `Commit.date` equals the git commit date.
2. Every `Release` matches its git tag: `commit` = `git rev-list -1 <tag>`, `version` =
   tag without `v`. Every git tag has exactly one `Release`.
3. Every `path` / `folder` / `file` property points at an existing entry in the working
   tree; every `crate` names a directory under `crates/`.
4. Every `Spec.path` exists, and every file under `specification/` has exactly one `Spec`.
5. Every directory under `examples/` has exactly one `Example`, whose `folder` exists.
6. Every `Decision.key` matching `D-*` appears in `specification/02-decision-register.md`,
   and vice versa.
7. Every `rmp_task` id exists in the `graphus` roadmap. Check ids **one at a time** —
   `rmp task get` with several ids returns only the first and still exits 0.
8. No node lacks its identity property; no identity is duplicated within a label.
9. No duplicate `(a)-[type]->(b)` edges.

Known, accepted gaps, as measured on 2026-07-16:

- **No file/symbol tier** — by design, see above.
- **103 orphan nodes** (12% — mostly historical `Commit` and `Sprint` nodes that were
  recorded without a relation). They are reachable by key, not by traversal.
- **Provenance is partial** — 486 of 874 nodes carry `gitCommit`/`gitDate`. The audit
  stamped everything it touched; nodes it did not need to change were left unstamped
  rather than given a false "last confirmed" date.
- **`Component` does not map 1:1 to crates** — it models logical subsystems
  (`cypher-executor`, `storage-engine`), so `DEPENDS_ON` between components is a
  design-level claim and is *not* checkable against `Cargo.toml`. Only the `crate` /
  `path` properties are checkable. 24 of the 35 crates are not named by any `crate`
  property.
