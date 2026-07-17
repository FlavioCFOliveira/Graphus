# Indexes

How to declare, name, list and drop **node-property indexes** in Graphus. A node-property
index accelerates lookups of nodes by a `(label, property)` pair; it is Graphus's `RANGE`
index, matching Neo4j 5.x semantics and status codes.

Index DDL is written in Cypher and sent over any interface (REST or Bolt). It is **not
transactional**: index statements run in *auto-commit* only and are rejected inside an
explicit transaction (see [transactions.md](transactions.md)). Declaring or dropping an index
requires the **`SCHEMA`** privilege on the target database — `ADMIN` contains it, so an
administrator can always do it, and `GRANT SCHEMA ON GRAPH <db>` delegates DDL without full
admin rights (see [security.md](security.md)).

Building an index is **non-blocking**: `CREATE INDEX` returns promptly and the build runs in
the background, so it never stalls concurrent queries. Over an already-populated store the
index reports `POPULATING` in `SHOW INDEXES`, with its real progress in `populationPercent`,
before it becomes `ONLINE` — see [The `POPULATING` window](#the-populating-window) for how long
that takes, what it costs, and how to tell a normal build from a stalled one.

---

## Creating an index

### Named (openCypher 9 form)

Give the index a name to make it easy to find and drop:

```cypher
CREATE INDEX ix_person FOR (p:Person) ON (p.name)
```

The name is an **identifier**, not a string. To use a name that is not a bare word (for
example one containing `-`), wrap it in backticks:

```cypher
CREATE INDEX `my-idx` FOR (p:Person) ON (p.email)
```

> A single-quoted string is **not** a valid index name: `CREATE INDEX 'ix' FOR …` is a syntax
> error (`Neo.ClientError.Statement.SyntaxError`). Names are identifiers or backtick-quoted.

### Anonymous — a deterministic auto-name

The name is optional. Both the openCypher-9 form and the legacy form may omit it, in which
case the index receives a deterministic, stable **auto-name** of the shape
`index_<label>_<property>`:

```cypher
CREATE INDEX FOR (p:Person) ON (p.age)   -- named  index_Person_age
CREATE INDEX ON :Company(founded)        -- legacy; named  index_Company_founded
```

Any character in the label or property that is not `A–Z`, `a–z`, `0–9` or `_` is mapped to
`_` when building the auto-name. The auto-name is a pure function of `(label, property)`, so
it is identical across restarts and rebuilds. If two different targets would sanitize to the
same base name, or the base collides with an explicit name, Graphus appends a deterministic
suffix so the resulting name is still unique and stable.

### Node vs relationship, single vs composite

A `RANGE` index covers **one** property or a **composite** ordered tuple of two or more, over either
**nodes** or **relationships** (the undirected `()-[r:T]-()` pattern; a directed arrow is a syntax
error). All four combinations are supported:

```cypher
CREATE INDEX FOR (n:Person)      ON (n.name)           -- single-property node   → index_Person_name
CREATE INDEX FOR (n:Person)      ON (n.first, n.last)  -- composite node         → index_Person_first_last
CREATE INDEX FOR ()-[r:KNOWS]-() ON (r.since)          -- single-property rel    → rel_index_KNOWS_since
CREATE INDEX FOR ()-[r:KNOWS]-() ON (r.a, r.b)         -- composite relationship → rel_index_KNOWS_a_b
```

A composite index accelerates a `MATCH` that supplies an equality on **every** covered key —
`MATCH (n:Person {first: 'Ada', last: 'Lovelace'})` or `MATCH ()-[r:KNOWS {a: 1, b: 2}]-()` — as **one**
seek over the full ordered tuple, and serves a predicate on only its **leading** key as a leading-prefix
seek. The key **order is significant**: `(a, b)` and `(b, a)` are distinct indexes. Relationship
auto-names carry a `rel_index_` prefix so a relationship index's auto-name never collides with a node
index's over the same identifiers.

### Idempotent create — `IF NOT EXISTS`

`IF NOT EXISTS` makes the create a no-op when an equivalent index (or the same name) already
exists — it reports **0** indexes added and sets no `contains-updates`:

```cypher
CREATE INDEX ix_person IF NOT EXISTS FOR (p:Person) ON (p.name)
```

Without `IF NOT EXISTS`, re-declaring is an error (with **no** side effect):

| Situation | Status code |
| --------- | ----------- |
| An index already covers the same `(label, property)` — even under a different name | `Neo.ClientError.Schema.EquivalentSchemaRuleAlreadyExists` |
| The requested **name** is already used by another index or constraint | `Neo.ClientError.Schema.IndexWithNameAlreadyExists` |

### `OPTIONS` clause

A `CREATE INDEX` may carry a trailing Neo4j `OPTIONS { … }` map naming a backing-index provider and
its configuration. Graphus has a **single built-in index provider** and synchronous builds, so the
clause is **accepted for Neo4j-DDL compatibility and not applied** — the created index is identical
with or without it. The clause is still fully validated: `indexProvider` must be a quoted string,
`indexConfig` must be a map, and any *other* top-level key is a clear syntax error; unknown
`indexConfig` keys are accepted and ignored.

```cypher
CREATE INDEX ix_person FOR (p:Person) ON (p.name)
  OPTIONS { indexProvider: 'range-1.0', indexConfig: { } }
```

The same `OPTIONS` clause is accepted on `CREATE RANGE INDEX`, `CREATE TEXT INDEX`,
`CREATE POINT INDEX` (whose `indexConfig` may carry the spatial `spatial.cartesian.min|max` /
`spatial.wgs-84.min|max` bounds), and `CREATE FULLTEXT INDEX` (see below).

---

## Dropping an index

### By name

```cypher
DROP INDEX ix_person
DROP INDEX ix_person IF EXISTS   -- no-op (0 removed) if it does not exist
```

The unified `DROP INDEX <name>` form does **not** spell the index kind, so it drops an index of
**any** kind by name — node-property / relationship-property / composite `RANGE`, `FULLTEXT` **and**
`POINT` — since names are globally unique across every catalog. (The kind-specific
`DROP POINT INDEX <name>` / `DROP FULLTEXT INDEX <name>` forms still work too, and both accept
`IF EXISTS`.)

Dropping a name that does not exist **without** `IF EXISTS` is an error:
`Neo.ClientError.Schema.IndexDropFailed`.

### By target

The by-target form still works and is idempotent (a no-op success if the target is not
indexed):

```cypher
DROP INDEX FOR (n:Person) ON (n.name)   -- openCypher 9 form
DROP INDEX ON :Person(name)             -- legacy form
```

---

## Listing indexes — `SHOW INDEXES`

`SHOW INDEXES` is a **unified** Neo4j-5.x listing of *every* index kind — node-property and
relationship-property `RANGE`, composite `RANGE`, `TEXT`, `FULLTEXT`, `POINT`, and the two always-on
token `LOOKUP` indexes (`node_label_lookup_index` / `rel_type_lookup_index`) that Neo4j always lists.
A bare listing returns the **12 default columns**, in Neo4j order:

| Column              | Type            | Value |
| ------------------- | --------------- | ----- |
| `id`                | integer         | a stable-within-a-listing id (the two token LOOKUPs are `1` / `2`) |
| `name`              | string          | the index name (explicit or auto-generated) |
| `state`             | string          | `ONLINE` (ready) or `POPULATING` (build in progress) |
| `populationPercent` | float           | `100.0` when online; a build's real progress (`0.0`–`100.0`) while `POPULATING` — see [The `POPULATING` window](#the-populating-window) |
| `type`              | string          | `RANGE`, `TEXT`, `FULLTEXT`, `POINT` or `LOOKUP` |
| `entityType`        | string          | `NODE` or `RELATIONSHIP` |
| `labelsOrTypes`     | list of string  | the covered label(s)/type, e.g. `["Person"]` (empty for `LOOKUP`) |
| `properties`        | list of string  | the covered property tuple, e.g. `["name"]` or `["first","last"]` |
| `indexProvider`     | string          | `range-1.0` / `text-1.0` / `token-lookup-1.0` / `fulltext-1.0` / `point-1.0` / `vector-2.0` |
| `owningConstraint`  | string or null  | the uniqueness/key constraint this index backs, else `null` |
| `lastRead`          | null            | index-usage statistics are untracked |
| `readCount`         | null            | index-usage statistics are untracked |

```cypher
SHOW INDEXES
SHOW INDEX     -- the singular is accepted too, and behaves identically
```

Neo4j accepts both `INDEX` and `INDEXES`; the singular is a full synonym everywhere the plural is
(including the filtered forms and the `YIELD` / `WHERE` / `RETURN` tail).

### Type filters

`SHOW <type> INDEXES` restricts the listing to one index kind, matching Neo4j's filtered forms:

```cypher
SHOW ALL INDEXES        -- every kind (same as SHOW INDEXES)
SHOW RANGE INDEXES      -- node / relationship / composite range indexes
SHOW TEXT INDEXES       -- text (trigram) indexes
SHOW POINT INDEXES      -- spatial (point) indexes
SHOW FULLTEXT INDEXES   -- full-text indexes
SHOW LOOKUP INDEXES     -- the two always-on token lookup indexes
SHOW VECTOR INDEXES     -- vector (HNSW) indexes
```

> `SHOW FULLTEXT INDEXES` and `SHOW POINT INDEXES` now return the **same unified 12-column shape**
> filtered to that kind. The full-text analyzer surfaces under the `options` column (via `YIELD *`),
> not as a bespoke column.

### `YIELD` / `WHERE` / `RETURN`

A `YIELD` / `WHERE` / `RETURN` tail projects, filters and re-orders the listing like any Neo4j
`SHOW` command. `YIELD *` exposes three further columns — `options` (a map; the full-text analyzer
config lives here), `failureMessage` (empty), and `createStatement` (a round-trippable
`CREATE … INDEX` DDL):

```cypher
SHOW INDEXES YIELD name, type, state WHERE type = 'RANGE' RETURN name, state
SHOW INDEXES YIELD *
```

### The `POPULATING` window

`CREATE INDEX` returns as soon as the index is declared; the build then runs in the background,
indexing a snapshot of the covered entities in bounded chunks so it never stalls concurrent queries.
Until it finishes, the index reports `POPULATING` and is **withheld from the planner** — queries keep
running, on a full scan, and keep returning exactly the right answers.

`populationPercent` reports that build's real progress. It is the fraction of the build's snapshot
indexed so far, on Neo4j's own rule (`completed / total * 100`, or `0.0` when there is nothing to
index), so a build halfway through a million nodes reports ≈`50.0`:

```cypher
SHOW INDEXES YIELD name, state, populationPercent WHERE state = 'POPULATING'
```

A `POPULATING` index with `populationPercent` at `0.0` and **no** build running is a different
condition: it is an index the engine has demoted because a storage fault made the derived indexes
untrustworthy (a *fail-closed* wipe). Queries stay correct — every read path drops to the exact store
scan — and the index is reported `POPULATING` deliberately, rather than claiming a readiness it does
not have. The `graphus_index_fail_closed_total` counter below records each occurrence.

**How long the window lasts.** Measured on a node-property `RANGE` build: **~70–74k nodes/s**, linear
in the number of covered nodes.

| Nodes covered | Build window (measured) |
| ------------- | ----------------------- |
| 10⁴           | 79–135 ms               |
| 10⁵           | 1.29–1.40 s             |
| 10⁶           | 13.8–14.7 s             |
| 10⁷           | ~2.3 min (extrapolated) |

**What the window costs today: nothing.** It would be reasonable to expect a latency cliff here — the
index is withheld while `POPULATING`, so point lookups fall back to a label scan until it is promoted.
Measurement says otherwise. Across promotion the latency is **flat**:

| Index state             | Operator          | dbHits   | Latency   |
| ----------------------- | ----------------- | -------- | --------- |
| no index (control)      | `NodeLabelScanEq` | 100001   | 23.6 ms   |
| `POPULATING`            | `NodeLabelScanEq` | 100001   | 23–32 ms  |
| `ONLINE`                | `NodeIndexSeek`   | 100001   | 23–24 ms  |

The promoted index really is planned (`PROFILE` shows `NodeIndexSeek`), but it reads the whole label
anyway, so promotion currently buys nothing and the window costs nothing to wait through. The cliff is
therefore **latent, not present**: it will appear only once the promoted index stops scanning the full
label, and until then `populationPercent` is an operability signal rather than a latency warning.

**Telling a window from a stall.** A build stopped for good by a storage fault is *parked*: its index
stays `POPULATING` indefinitely — still correct, still unaccelerated — until the store reads cleanly
again, at which point the build is resurrected automatically. `SHOW INDEXES` cannot distinguish that
from a healthy build at the same percentage in a single snapshot, and it deliberately does not try:
`POPULATING` is the conformant state for an interrupted build that will be repopulated, and a
`FAILED` state would be a lie (it is terminal in Neo4j, and drivers' `awaitIndexes()` throws on it).
The distinction is published in the metrics instead:

| Metric                                   | Type    | Meaning |
| ---------------------------------------- | ------- | ------- |
| `graphus_index_builds_pending`            | gauge   | builds in flight now — rises and returns to zero over a normal window |
| `graphus_index_build_entities_remaining`  | gauge   | entities still to index; falls as a healthy build progresses |
| `graphus_index_builds_parked`             | gauge   | **builds stalled right now** — alert on this |
| `graphus_index_builds_poisoned_total`     | counter | cumulative builds ever poisoned |
| `graphus_index_fail_closed_total`         | counter | cumulative fail-closed index wipes |

`pending > 0` with `entities_remaining` falling is a normal window. `parked > 0` is a stall that will
not clear on its own until the underlying storage fault does — the counters cannot tell you this,
because they only ever say that something happened once. Each parked build is also logged at `ERROR`.

---

## Text (trigram) index DDL

A `TEXT` index is a **distinct native string index** — *not* a synonym of `RANGE` — that accelerates
the `CONTAINS`, `ENDS WITH` and `STARTS WITH` predicates a forward-ordered B-tree cannot serve (a
substring or suffix is not a contiguous key range). It covers **one node label and one string
property**, is built **synchronously** (it is `ONLINE` as soon as `CREATE` returns), and supports the
same idempotency / `OPTIONS` modifiers as the node-property index. A `RANGE` and a `TEXT` index may
coexist on the same `(label, property)` (different kinds); when a `TEXT` index is present it also
serves `STARTS WITH` (preferred over the range prefix seek).

```cypher
-- TEXT: the name is optional (auto-named text_index_<label>_<property>); IF NOT EXISTS / OPTIONS.
CREATE TEXT INDEX ix_name IF NOT EXISTS FOR (p:Person) ON (p.name)
CREATE TEXT INDEX FOR (p:Person) ON (p.bio)              -- anonymous → text_index_Person_bio
DROP TEXT INDEX ix_name IF EXISTS
```

With the index in place, a substring / suffix / prefix filter is index-served (a candidate seek plus
an exact re-check) instead of a full label scan:

```cypher
MATCH (p:Person) WHERE p.name CONTAINS 'obe'  RETURN p
MATCH (p:Person) WHERE p.name ENDS WITH 'son' RETURN p
```

Internally the index stores the set of character **trigrams** (three-character windows, with
head/tail sentinels so short strings, prefixes and suffixes work) of each value and intersects the
needle's trigrams to produce a candidate superset; the exact predicate re-check makes the result
identical to a scan. Matching is on raw Unicode scalar values (case-sensitive, no normalization),
exactly like Cypher's `CONTAINS` / `STARTS WITH` / `ENDS WITH`. Relationship `TEXT` indexes are a
follow-up.

---

## Point and full-text index DDL

`POINT` (spatial) and `FULLTEXT` indexes are their own kinds, created and dropped with the Neo4j
`POINT` / `FULLTEXT` keywords. Both support the same idempotency and `OPTIONS` modifiers as the
node-property index:

```cypher
-- POINT: the name is optional (auto-named point_index_<label>_<property>); IF NOT EXISTS / OPTIONS.
CREATE POINT INDEX by_loc IF NOT EXISTS FOR (c:City) ON (c.location)
CREATE POINT INDEX FOR (c:City) ON (c.location)          -- anonymous → point_index_City_location
CREATE POINT INDEX by_loc FOR (c:City) ON (c.location)
  OPTIONS { indexConfig: { `spatial.cartesian.min`: [-100.0, -100.0],
                           `spatial.cartesian.max`: [ 100.0,  100.0] } }
DROP POINT INDEX by_loc IF EXISTS

-- POINT over RELATIONSHIPS (undirected `()-[r:T]-()` pattern, single type). Anonymous rel point
-- indexes auto-name point_index_rel_<type>_<property>.
CREATE POINT INDEX rel_at FOR ()-[r:VISITED]-() ON (r.at)
CREATE POINT INDEX FOR ()-[r:VISITED]-() ON (r.at)       -- anonymous → point_index_rel_VISITED_at
DROP POINT INDEX rel_at IF EXISTS

-- FULLTEXT: named; ON EACH [ … ]; IF NOT EXISTS; analyzer via the bare or indexConfig OPTIONS form.
CREATE FULLTEXT INDEX ft IF NOT EXISTS FOR (a:Article) ON EACH [a.title, a.body]
  OPTIONS { analyzer: 'keyword' }
CREATE FULLTEXT INDEX ft FOR (a:Article) ON EACH [a.title]
  OPTIONS { indexConfig: { `fulltext.analyzer`: 'standard',
                           `fulltext.eventually_consistent`: true } }
DROP FULLTEXT INDEX ft IF EXISTS

-- FULLTEXT over MULTIPLE labels (Neo4j `A|B` syntax): a node carrying ANY covered label is indexed.
CREATE FULLTEXT INDEX posts FOR (n:Article|Blog) ON EACH [n.title, n.body]

-- FULLTEXT over RELATIONSHIPS (undirected `()-[r:T]-()` pattern), single or multiple types.
CREATE FULLTEXT INDEX rel_notes FOR ()-[r:KNOWS]-() ON EACH [r.note]
CREATE FULLTEXT INDEX rel_reviews FOR ()-[r:RATED|REVIEWED]-() ON EACH [r.body]
  OPTIONS { analyzer: 'standard' }
DROP FULLTEXT INDEX rel_notes IF EXISTS
```

For full-text, `fulltext.analyzer` maps to the analyzer (`standard` / `keyword`);
`fulltext.eventually_consistent` is accepted and ignored (Graphus builds are synchronous). A `TEXT`,
`POINT` or `FULLTEXT` index is also droppable by the unified `DROP INDEX <name>` form.

### Node vs relationship, single vs multi-label full-text

Full-text indexes come in two flavours (Neo4j-compatible):

- **Node** — `FOR (n:Label…)`, queried by `db.index.fulltext.queryNodes(name, query)`.
- **Relationship** — `FOR ()-[r:Type…]-()` (only the *undirected* pattern; a directed arrow is a
  syntax error), queried by `db.index.fulltext.queryRelationships(name, query)`.

Either flavour may cover **one or more** labels/types with the `A|B` syntax; a node/relationship
carrying **any** covered label/type is indexed. `SHOW INDEXES` reports `entityType` = `NODE` or
`RELATIONSHIP` and lists every covered label/type under `labelsOrTypes`.

Both procedures return `(entity, score)` rows — `queryNodes` a structural **node** and a relevance
`score`, `queryRelationships` a structural **relationship** and a `score` — ordered by descending score
then ascending id, with each candidate re-checked for MVCC visibility, its current label/type and RBAC:

```cypher
CALL db.index.fulltext.queryNodes('posts', 'graph databases') YIELD node, score
  RETURN node, score
CALL db.index.fulltext.queryRelationships('rel_notes', 'graph') YIELD relationship, score
  RETURN relationship, score
```

Passing a **node** index name to `queryRelationships` (or a relationship index name to `queryNodes`)
is a clear error, not silently-empty results.

### Node vs relationship point index

Point (spatial) indexes likewise come in two flavours (Neo4j-compatible):

- **Node** — `FOR (n:Label) ON (n.prop)`.
- **Relationship** — `FOR ()-[r:Type]-() ON (r.prop)` (only the *undirected* pattern; a directed arrow
  is a syntax error). A point index covers **exactly one** label/type and **one** point property.

Both accelerate an **upper-bounded Cartesian proximity** predicate — `distance(x.prop, <const point>)
<= <const r>` (or `<`; the namespaced `point.distance(…)` spelling and the symmetric argument order are
equivalent). The grid returns a candidate superset and the exact `distance` predicate is always
re-checked above the seek, so the index never changes the answer — only the speed:

```cypher
-- node proximity (served by a node point index when one covers (:City, location)):
MATCH (c:City) WHERE distance(c.location, point({x: 0, y: 0})) <= 5 RETURN c

-- relationship proximity (served by a relationship point index over ()-[r:VISITED]-() on r.at):
MATCH ()-[r:VISITED]-() WHERE distance(r.at, point({x: 0, y: 0})) <= 5 RETURN r
```

A **geographic** (WGS-84) centre is measured in metres while the grid buckets degrees, so the planner
declines the seek for a geographic centre and keeps the exact predicate on a scan (still correct). A
`point.withinBBox(…)` predicate is not an upper-bounded distance and likewise stays a scan + filter.
Without a matching point index either query falls back to a scan + filter — always correct, just not
index-accelerated. `SHOW INDEXES` reports `entityType` = `NODE` or `RELATIONSHIP` for point indexes and
lists the covered label/type under `labelsOrTypes`.

---

## Vector (HNSW) index DDL

A `VECTOR` index is an approximate-nearest-neighbour (ANN) index over a dense `f32` embedding property,
built on an HNSW graph. It covers **one node label or relationship type** and **exactly one** embedding
property, and — unlike every other kind — its `CREATE` **requires** an `OPTIONS { indexConfig: { … } }`
clause carrying the embedding shape:

```cypher
-- node vector index (backtick-quote the dotted config keys, Neo4j-style):
CREATE VECTOR INDEX doc_emb IF NOT EXISTS FOR (d:Doc) ON (d.embedding)
  OPTIONS { indexConfig: {
    `vector.dimensions`:           1536,      -- REQUIRED integer, 1..=4096
    `vector.similarity_function`:  'cosine',  -- REQUIRED 'cosine' | 'euclidean' (case-insensitive)
    `vector.hnsw.m`:               16,         -- optional, default 16
    `vector.hnsw.ef_construction`: 100         -- optional, default 100
  } }

-- relationship vector index (undirected only), defaults for the two HNSW parameters:
CREATE VECTOR INDEX rel_emb FOR ()-[r:SIMILAR]-() ON (r.vec)
  OPTIONS { indexConfig: { `vector.dimensions`: 3, `vector.similarity_function`: 'euclidean' } }

DROP VECTOR INDEX doc_emb IF EXISTS
DROP INDEX doc_emb                 -- the unified by-name drop resolves the vector catalog too
```

The `indexConfig` keys:

| Key                            | Required | Type    | Default | Validation |
| ------------------------------ | -------- | ------- | ------- | ---------- |
| `vector.dimensions`            | yes      | integer | —       | must be `1..=4096` |
| `vector.similarity_function`   | yes      | string  | —       | `'cosine'` or `'euclidean'`, case-insensitive |
| `vector.hnsw.m`                | no       | integer | `16`    | must be a positive integer |
| `vector.hnsw.ef_construction`  | no       | integer | `100`   | must be a positive integer |

A missing `OPTIONS`/`indexConfig`, a missing required key, an out-of-range dimension, an unknown
similarity or a non-positive HNSW parameter is a clear, side-effect-free error. An unrecognised
`indexConfig` key is **accepted and ignored** (Neo4j leniency); an unrecognised **top-level** `OPTIONS`
key is rejected. The name is optional (auto-named deterministically when omitted), and `IF NOT EXISTS` /
`IF EXISTS` behave as for the other kinds. `SHOW INDEXES` lists a vector index with `type` `VECTOR`,
`indexProvider` `vector-2.0`, its covered label/type under `labelsOrTypes`, and its `indexConfig` under
the `options` column (via `YIELD *`); its `createStatement` round-trips back to the same DDL. A `VECTOR`
index is its own kind — it never backs a constraint (`owningConstraint` is always `null`).

---

## Names are unique and durable

- **Unique across the whole schema.** An index name may not collide with the name of any
  other index (node-property, composite, relationship-property, text, full-text, point, or vector)
  *or* any constraint. A collision is rejected with
  `Neo.ClientError.Schema.IndexWithNameAlreadyExists`.
- **Durable.** A name is persisted and survives a restart, crash recovery, and backup/restore.
- **Backfilled on upgrade.** An anonymous index created before named indexes existed is given
  its stable auto-name (`index_<label>_<property>`) the first time the store is opened, so it,
  too, is listed with a name and droppable by that name.

---

## Index statistics and the planner

The cost-based planner estimates how many rows a predicate will match. Graphus keeps **two kinds** of
statistic, and they are maintained differently — the distinction matters when you tune:

| Statistic | Scope | Maintenance |
| --------- | ----- | ----------- |
| Per-label / per-relationship-type **counts** | the whole graph | **Live.** Every write keeps them current, so they never go stale and never need a resample. |
| Per-`(label, property)` **selectivity histogram** (equi-depth, 64 buckets) | each declared single-property **node** index | **Sampled.** A point-in-time image, recomputed by a full scan on demand. It drifts as the data changes. |

An equi-depth histogram cannot be maintained incrementally without resampling, so it is deliberately
recompute-only — this is the same trade-off `ANALYZE` / `UPDATE STATISTICS` makes in a relational
engine. Graphus recomputes it in two places:

- **at `CREATE INDEX`**, so a declared index is *born* with real statistics and no operator action is
  needed for a freshly-built index;
- **on demand**, via `db.resampleIndex(indexName)` / `db.resampleOutdatedIndexes()` — Graphus's
  `ANALYZE`. (Neo4j has no `ANALYZE` keyword; these procedures *are* it.)

```cypher
CALL db.resampleIndex('index_Person_age')  -- refresh one index after a bulk load
CALL db.resampleOutdatedIndexes()          -- refresh every declared node-property index
```

**A resample is not part of your transaction, and `ROLLBACK` does not undo it.** The procedure
*requests* the recompute and returns; the engine runs it immediately afterwards in its own
transaction. This matches Neo4j, where `db.resampleIndex` schedules a background re-sampling job that
ignores the calling transaction entirely — resampling is not a transactional graph mutation. So the
call returns "accepted and will run", not "already done", and the outcome is the **same** whether you
call it auto-commit or inside `BEGIN … ROLLBACK`, with or without other transactions in flight.

Statistics are metadata, not data: this costs you nothing in correctness. A histogram that is stale,
absent, or refreshed when you expected it not to be can only make a plan less well informed — it can
never change a query's rows.

**When to resample.** After a bulk load, or after a change large enough to shift the distribution the
histogram describes — the classic case being data that arrives sorted or clustered, so the shape after
the load looks nothing like the shape at `CREATE INDEX`. A stale histogram is never *wrong*, only
imprecise: it can only cost you a less well-informed plan, never a wrong answer.

**Cost.** A resample is a full scan of the label, per `(label, property)`. That is why it is explicit
rather than automatic, and why `db.resampleOutdatedIndexes()` on a large graph with many indexed
properties is not free. Measured on the reference host, seeding a histogram adds **~5%** to the
`CREATE INDEX` DDL (which already scans the store to populate the index itself) — 569 ms vs 541 ms at
50 000 nodes.

**Scope.** Only single-property **node** indexes carry a histogram — it is what the estimator is keyed
by. Resampling a relationship, composite, full-text, point, text, or vector index by name is an
accepted no-op: those index kinds keep no sampled statistic. Naming an index that does not exist at
all is an error.

> Unlike Neo4j — which samples in the background and selects only indexes whose update count exceeds a
> threshold — `db.resampleOutdatedIndexes()` recomputes **every** declared node-property index
> synchronously. Graphus tracks no per-index update counter, so it cannot single out the genuinely
> drifted ones; recomputing all of them is a superset of that selection (never wrong, but more
> expensive), and it is complete by the time the call returns.

---

## Try it — REST

Log in for a Bearer token, then send the DDL to the auto-commit endpoint (see
[rest-api.md](rest-api.md)). Index DDL uses `access_mode: "WRITE"` and its summary `type` is
`s` (schema/admin).

```sh
TOKEN=$(curl -sk -X POST https://localhost:7474/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"graphus","password":"graphus-local"}' | jq -r .token)

# Create a named index.
curl -sk -X POST https://localhost:7474/db/graphus/tx/commit \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"CREATE INDEX ix_person FOR (p:Person) ON (p.name)"}]}'
# -> summary.stats: { "contains-updates": true, "indexes-added": 1 }, "type": "s"

# List indexes.
curl -sk -X POST https://localhost:7474/db/graphus/tx/commit \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"SHOW INDEXES"}],"access_mode":"READ"}'
# fields: ["id","name","state","populationPercent","type","entityType",
#          "labelsOrTypes","properties","indexProvider","owningConstraint","lastRead","readCount"]
# row:    [3,"ix_person","ONLINE",100.0,"RANGE","NODE",["Person"],["name"],"range-1.0",null,null,null]
# (the two always-on token LOOKUP indexes are listed first, ids 1 and 2)

# Idempotent re-create: no-op, 0 added.
curl -sk -X POST https://localhost:7474/db/graphus/tx/commit \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"CREATE INDEX ix_person IF NOT EXISTS FOR (p:Person) ON (p.name)"}]}'
# -> summary.stats: {} (nothing changed)

# Drop it by name.
curl -sk -X POST https://localhost:7474/db/graphus/tx/commit \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"DROP INDEX ix_person"}]}'
# -> summary.stats: { "contains-updates": true, "indexes-removed": 1 }
```

Result cells above are shown decoded; on the wire they are strict-Jolt typed JSON (a string
is `{"U":"Person"}`, a list is a JSON array) — see [rest-api.md](rest-api.md#41-value-encoding-jolt-typed-json).

## Try it — Bolt

Over any Neo4j driver (Bolt over TCP or UDS — see [bolt.md](bolt.md)) the same statements run
as ordinary auto-commit Cypher. The trailing `SUCCESS` summary carries the `indexes-added` /
`indexes-removed` counters:

```python
from neo4j import GraphDatabase
driver = GraphDatabase.driver("bolt+ssc://localhost:7687",
                              auth=("graphus", "graphus-local"))
with driver.session(database="graphus") as s:
    s.run("CREATE INDEX ix_person FOR (p:Person) ON (p.name)").consume()
    for r in s.run("SHOW INDEXES"):
        print(r["name"], r["type"], r["entityType"],
              r["labelsOrTypes"], r["properties"], r["state"])
        # node_label_lookup_index LOOKUP NODE [] [] ONLINE
        # rel_type_lookup_index   LOOKUP RELATIONSHIP [] [] ONLINE
        # ix_person               RANGE  NODE ['Person'] ['name'] ONLINE
    s.run("DROP INDEX ix_person IF EXISTS").consume()
driver.close()
```

---

See also: [rest-api.md](rest-api.md) · [bolt.md](bolt.md) · [transactions.md](transactions.md)
· [security.md](security.md).
