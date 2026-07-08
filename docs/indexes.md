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
index may briefly report `populating` in `SHOW INDEXES` before it becomes `online`.

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

`SHOW INDEXES` returns one row per node-property index, with the Neo4j column shape the driver
ecosystem expects:

| Column          | Type          | Value |
| --------------- | ------------- | ----- |
| `name`          | string        | the index name (explicit or auto-generated) |
| `type`          | string        | `RANGE` (the node-property index kind) |
| `entityType`    | string        | `NODE` |
| `labelsOrTypes` | list of string | the single label, e.g. `["Person"]` |
| `properties`    | list of string | the single property, e.g. `["name"]` |
| `state`         | string        | `online` (ready) or `populating` (build in progress) |

```cypher
SHOW INDEXES
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
# fields: ["name","type","entityType","labelsOrTypes","properties","state"]
# row:    ["ix_person","RANGE","NODE",["Person"],["name"],"online"]

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
        # ix_person RANGE NODE ['Person'] ['name'] online
    s.run("DROP INDEX ix_person IF EXISTS").consume()
driver.close()
```

---

See also: [rest-api.md](rest-api.md) · [bolt.md](bolt.md) · [transactions.md](transactions.md)
· [security.md](security.md).
