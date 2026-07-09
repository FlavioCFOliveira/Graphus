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
index may briefly report `POPULATING` in `SHOW INDEXES` before it becomes `ONLINE`.

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

---

## Dropping an index

### By name

```cypher
DROP INDEX ix_person
DROP INDEX ix_person IF EXISTS   -- no-op (0 removed) if it does not exist
```

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
relationship-property `RANGE`, composite `RANGE`, `FULLTEXT`, `POINT`, and the two always-on token
`LOOKUP` indexes (`node_label_lookup_index` / `rel_type_lookup_index`) that Neo4j always lists. A
bare listing returns the **12 default columns**, in Neo4j order:

| Column              | Type            | Value |
| ------------------- | --------------- | ----- |
| `id`                | integer         | a stable-within-a-listing id (the two token LOOKUPs are `1` / `2`) |
| `name`              | string          | the index name (explicit or auto-generated) |
| `state`             | string          | `ONLINE` (ready) or `POPULATING` (build in progress) |
| `populationPercent` | float           | `100.0` when online, else `0.0` |
| `type`              | string          | `RANGE`, `FULLTEXT`, `POINT` or `LOOKUP` |
| `entityType`        | string          | `NODE` or `RELATIONSHIP` |
| `labelsOrTypes`     | list of string  | the covered label(s)/type, e.g. `["Person"]` (empty for `LOOKUP`) |
| `properties`        | list of string  | the covered property tuple, e.g. `["name"]` or `["first","last"]` |
| `indexProvider`     | string          | `range-1.0` / `token-lookup-1.0` / `fulltext-1.0` / `point-1.0` |
| `owningConstraint`  | string or null  | the uniqueness/key constraint this index backs, else `null` |
| `lastRead`          | null            | index-usage statistics are untracked |
| `readCount`         | null            | index-usage statistics are untracked |

```cypher
SHOW INDEXES
```

### Type filters

`SHOW <type> INDEXES` restricts the listing to one index kind, matching Neo4j's filtered forms:

```cypher
SHOW ALL INDEXES        -- every kind (same as SHOW INDEXES)
SHOW RANGE INDEXES      -- node / relationship / composite range indexes
SHOW POINT INDEXES      -- spatial (point) indexes
SHOW FULLTEXT INDEXES   -- full-text indexes
SHOW LOOKUP INDEXES     -- the two always-on token lookup indexes
SHOW TEXT INDEXES       -- text indexes (none in Graphus: TEXT is a synonym of RANGE)
SHOW VECTOR INDEXES     -- vector indexes (none yet; a later release)
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

---

## Names are unique and durable

- **Unique across the whole schema.** An index name may not collide with the name of any
  other index (node-property, full-text, or point) *or* any constraint. A collision is
  rejected with `Neo.ClientError.Schema.IndexWithNameAlreadyExists`.
- **Durable.** A name is persisted and survives a restart, crash recovery, and backup/restore.
- **Backfilled on upgrade.** An anonymous index created before named indexes existed is given
  its stable auto-name (`index_<label>_<property>`) the first time the store is opened, so it,
  too, is listed with a name and droppable by that name.

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
