# Cypher language support

The Cypher surface Graphus implements, with runnable examples and Neo4j 5.x conformance notes.

Graphus speaks **Cypher** — the openCypher query language, aligned with **Neo4j 5.x**. Two of the
project's four inviolable guarantees govern this surface: **100% openCypher TCK** (every query
behaves exactly as the specification mandates) and **100% Bolt / PackStream** (every value crosses
the wire byte-for-byte as the driver ecosystem expects). This page is the practical reference for
the language features available today — the functions, expressions, subqueries, patterns, clauses,
and administrative statements — plus an honest list of what is **not yet supported**.

Every example below was executed against a live server and shows its **real** result. Where a form
is accepted for compatibility but behaves as a documented equivalence (for example a `TEXT` index),
or is deliberately declined (for example a `LOOKUP` index), that is called out precisely.

Related guides: [indexes.md](indexes.md) (node-property index DDL in depth),
[transactions.md](transactions.md) (isolation and the auto-commit model),
[security.md](security.md) (users, roles, privileges), [rest-api.md](rest-api.md) and
[bolt.md](bolt.md) (the interfaces).

---

## Running the examples

The examples are plain Cypher; send them over any interface. Over REST, log in for a Bearer token
and post to the auto-commit endpoint:

```sh
TOKEN=$(curl -sk -X POST https://localhost:7474/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"graphus","password":"graphus-local"}' | jq -r .token)

curl -sk -X POST https://localhost:7474/db/graphus/tx/commit \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"RETURN sin(0) AS s, pi() AS p"}]}'
```

Result cells come back as **strict-Jolt typed JSON** — an integer is `{"Z":"1"}`, a float is
`{"R":"1.5"}`, a string is `{"U":"Ada"}`, a boolean is `{"?":"true"}`, a list is a JSON array, and a
map is `{"{}":{…}}` (see [rest-api.md](rest-api.md#41-value-encoding-jolt-typed-json)). For
readability, the results shown on this page are **decoded** to their plain values.

Over a Neo4j driver (Bolt over TCP or UDS — see [bolt.md](bolt.md)) the same statements run as
ordinary Cypher and values arrive already decoded by the driver.

---

## Functions

Function names are **case-insensitive** (`toInteger`, `TOINTEGER`, and `tointeger` are the same
function). `CALL dbms.components()` reports the running server; `SHOW FUNCTIONS` lists the full
built-in library (see [Administration](#administration)).

### Mathematical functions

The full Neo4j 5.x trigonometric and logarithmic family is available.

| Group | Functions |
| ----- | --------- |
| Trigonometric | `sin`, `cos`, `tan`, `cot`, `asin`, `acos`, `atan`, `atan2(y, x)` |
| Angle & constants | `degrees(radians)`, `radians(degrees)`, `pi()`, `e()`, `haversin` |
| Exponential / log | `exp`, `log` (natural), `log10` |
| Predicate | `isNaN(number)` |

```cypher
RETURN sin(1.0) AS sin, cos(1.0) AS cos, cot(1.0) AS cot, atan2(1.0, 1.0) AS atan2
-- sin 0.8414709848078965 | cos 0.5403023058681398 | cot 0.6420926159343306 | atan2 0.7853981633974483

RETURN pi() AS pi, e() AS e, degrees(pi()) AS deg, radians(180.0) AS rad, log10(1000.0) AS log10
-- pi 3.141592653589793 | e 2.718281828459045 | deg 180.0 | rad 3.141592653589793 | log10 3.0

RETURN isNaN(0.0/0.0) AS from_div_zero, isNaN(1.0) AS finite
-- from_div_zero true | finite false
```

### Numeric rounding — `round(value [, precision [, mode]])`

`round` accepts an optional decimal `precision` and an optional rounding `mode`. The default mode is
`HALF_UP` (so `round(2.5)` is `3`), matching Neo4j 5.x.

```cypher
RETURN round(3.14159, 2) AS r2, round(2.5) AS half_up
-- r2 3.14 | half_up 3.0

RETURN round(2.5, 0, 'HALF_DOWN') AS down, round(2.5, 0, 'CEILING') AS ceil
-- down 2.0 | ceil 3.0
```

Rounding modes accepted: `UP`, `DOWN`, `CEILING`, `FLOOR`, `HALF_UP`, `HALF_DOWN`, `HALF_EVEN`.

### Scalar and identity functions

| Function | Result |
| -------- | ------ |
| `elementId(n \| r)` | the **string** element id (matches the Bolt/REST wire element id) |
| `id(n \| r)` | the **integer** id (Neo4j-legacy) |
| `timestamp()` | milliseconds since the Unix epoch (constant within a statement) |
| `randomUUID()` | a random UUID string |
| `isEmpty(list \| map \| string)` | `true` when the value has no elements |
| `valueType(v)` | the string name of the most precise Cypher type of `v` |
| `nullIf(a, b)` | `null` when `a = b`, else `a` |
| `char_length(s)` / `character_length(s)` | Unicode character count — aliases of `size()` |
| `exists(n.prop)` | `true` when the property is present (function form) |

```cypher
RETURN timestamp() AS ts, randomUUID() AS uuid, isEmpty([]) AS empty, isEmpty([1]) AS notEmpty
-- ts 1783584623214 | uuid 4153e7a9-… | empty true | notEmpty false

RETURN valueType(1) AS i, valueType(1.0) AS f, valueType([1,2]) AS l, valueType(null) AS n
-- i "INTEGER NOT NULL" | f "FLOAT NOT NULL" | l "LIST<INTEGER NOT NULL> NOT NULL" | n "null"

RETURN nullIf(1, 1) AS same, nullIf(1, 2) AS diff, char_length('héllo') AS len
-- same null | diff 1 | len 5
```

`elementId` and `exists(n.prop)` need a bound entity:

```cypher
CREATE (n:Person {name:'Ann'})
RETURN elementId(n) AS eid, exists(n.name) AS hasName, exists(n.missing) AS hasMissing
-- eid "19" (a string) | hasName true | hasMissing false
```

### Type-conversion functions

The strict converters (`toInteger`, `toFloat`, `toString`, `toBoolean`) raise on a non-convertible
value; the **`*OrNull`** variants return `null` instead of failing, and the **list** variants apply
the matching `*OrNull` element-wise.

| Scalar | `*OrNull` | List |
| ------ | --------- | ---- |
| `toInteger` | `toIntegerOrNull` | `toIntegerList` |
| `toFloat` | `toFloatOrNull` | `toFloatList` |
| `toString` | `toStringOrNull` | `toStringList` |
| `toBoolean` | `toBooleanOrNull` | `toBooleanList` |

```cypher
RETURN toIntegerOrNull('12') AS ok, toIntegerOrNull('x') AS bad, toFloatOrNull('1.5') AS f
-- ok 12 | bad null | f 1.5

RETURN toIntegerList(['1','2','x']) AS il, toBooleanList(['true','x']) AS bl
-- il [1, 2, null] | bl [true, null]
```

### String functions

`btrim`, `normalize`, plus the established set (`trim`, `ltrim`, `rtrim`, `left`, `right`,
`substring`, `replace`, `split`, `toLower`, `toUpper`, `reverse`).

- **`btrim(input [, trimChars])`** — trims both ends; with a second argument, trims those characters
  instead of whitespace.
- **`normalize(input [, form])`** — Unicode normalization; `form` is one of `NFC` (default), `NFD`,
  `NFKC`, `NFKD`.

```cypher
RETURN btrim('  hi  ') AS b1, btrim('xxhixx', 'x') AS b2
-- b1 "hi" | b2 "hi"

RETURN size(normalize('café', 'NFC')) AS nfc, size(normalize('café', 'NFD')) AS nfd
-- nfc 4 | nfd 5   (NFD decomposes the accented e into two code points)
```

### Spatial — `point.withinBBox`

`point.withinBBox(point, lowerLeft, upperRight)` tests bounding-box containment (alongside `point`,
`point.distance`, `distance`).

```cypher
RETURN point.withinBBox(point({x:1, y:1}), point({x:0, y:0}), point({x:2, y:2})) AS inside,
       point.withinBBox(point({x:5, y:5}), point({x:0, y:0}), point({x:2, y:2})) AS outside
-- inside true | outside false
```

### Aggregation — `stdev` / `stdevp` corrected

`stdev` (sample standard deviation) and `stdevp` (population standard deviation) now compute the true
statistic. (A prior defect returned the last input value; that is fixed.)

```cypher
UNWIND [1, 2, 3, 4, 5] AS x RETURN stdev(x) AS sample, stdevp(x) AS population
-- sample 1.5811388300841898 | population 1.4142135623730951
```

The other aggregates are unchanged: `count`, `sum`, `avg`, `min`, `max`, `collect`,
`percentileCont`, `percentileDisc`.

### List folding — `reduce`

`reduce(accumulator = initial, variable IN list | expression)` folds a list to a single value.

```cypher
RETURN reduce(acc = 0, x IN [1, 2, 3, 4] | acc + x) AS total
-- total 10

RETURN reduce(s = '', x IN ['a', 'b', 'c'] | s + x) AS joined
-- joined "abc"
```

---

## Expressions

### Map projection

Project an entity or map into a new map. Four selector forms may be combined inside `{ … }`:

| Selector | Meaning |
| -------- | ------- |
| `.key` | include property `key` |
| `.*` | include **all** properties |
| `alias: expr` | a computed entry |
| `var` | include variable `var` under its own name |

```cypher
CREATE (n:Person {name:'Ann', age:30, city:'Lisbon'})
WITH n
RETURN n{.name, .age}                      AS picked,   -- {name:'Ann', age:30}
       n{.*}                               AS everything,-- {name:'Ann', age:30, city:'Lisbon'}
       n{.name, upper: toUpper(n.city)}    AS computed  -- {name:'Ann', upper:'LISBON'}

WITH 42 AS extra
MATCH (n:Person {name:'Ann'})
RETURN n{.name, extra} AS projected        -- {name:'Ann', extra:42}
```

### Type predicates — `IS ::` / `IS TYPED` / `IS NORMALIZED`

`expr IS :: <TYPE>` (spelled `IS TYPED <TYPE>` equivalently) tests a value's type; negate with
`IS NOT ::` / `IS NOT TYPED`. Type names include `INTEGER`, `FLOAT`, `STRING`, `BOOLEAN`, `LIST<…>`,
`NULL`, and `ANY`, each optionally suffixed with `NOT NULL`.

```cypher
RETURN 1 IS :: INTEGER          AS a,   -- true
       1 IS :: FLOAT            AS b,   -- false
       1 IS NOT :: STRING       AS c,   -- true
       [1,2] IS :: LIST<INTEGER> AS d,  -- true
       1 IS TYPED ANY           AS e    -- true
```

By default a type accepts `null`; `NOT NULL` tightens it:

```cypher
RETURN null IS :: INTEGER          AS nullable,  -- true
       null IS :: INTEGER NOT NULL AS strict     -- false
```

`expr IS [NOT] [<form>] NORMALIZED` tests Unicode normalization (`form` defaults to `NFC`):

```cypher
RETURN 'café' IS NORMALIZED AS a, 'café' IS NFD NORMALIZED AS b
-- depends on how the string is encoded; the NFC-composed form is `IS NORMALIZED` true, `IS NFD NORMALIZED` false
```

---

## Subqueries

### `CALL { … }` subqueries

A `CALL { … }` block runs a nested query per incoming row. It supports the importing `WITH` (to
correlate with outer variables), an inner `UNION`, and the transactional-batching form
`IN TRANSACTIONS`.

```cypher
-- Uncorrelated
CALL { RETURN 1 AS x } RETURN x                         -- 1

-- Correlated: import `n` with `WITH n`
UNWIND [1, 2, 3] AS n
CALL { WITH n RETURN n * 10 AS ten }
RETURN n, ten                                           -- (1,10) (2,20) (3,30)

-- Inner UNION
CALL { RETURN 1 AS x UNION RETURN 2 AS x } RETURN x ORDER BY x   -- 1, 2
```

**`CALL { … } IN TRANSACTIONS [OF n ROWS]`** runs the subquery in row-batches:

```cypher
UNWIND [1, 2, 3] AS x
CALL { WITH x CREATE (:Batch {v:x}) } IN TRANSACTIONS OF 2 ROWS
```

> **Conformance note.** `IN TRANSACTIONS` is accepted and executes the batched work, but the batches
> are **not** committed as independent transactions — the whole statement commits atomically within
> the enclosing auto-commit transaction. Use it for its batching ergonomics, not (yet) for
> incremental durability of very large writes.

### `COUNT { … }` and `COLLECT { … }` expression subqueries

Use a subquery directly as an expression:

```cypher
MATCH (n:Person {name:'Ann'})
RETURN COUNT { MATCH (m:Person) } AS people,
       COLLECT { MATCH (m:Person) RETURN m.name } AS names
-- people <n> | names ['Ann', …]
```

---

## Patterns

### Label / relationship-type expressions

Boolean label expressions are accepted in node patterns, relationship patterns, and `WHERE`:

| Operator | Meaning | Example |
| -------- | ------- | ------- |
| `&` | conjunction (all labels) | `(n:A&B)` |
| `\|` | disjunction (any label) | `(n:A\|B)` |
| `!` | negation | `(n:!A)` |
| `%` | wildcard — any label at all | `(n:%)` |

```cypher
CREATE (:A:B {t:'ab'}), (:A {t:'a'}), (:B {t:'b'}), (:C {t:'c'})

MATCH (n:A&B)  RETURN n.t                         -- 'ab' only
MATCH (n:A|B)  RETURN n.t ORDER BY n.t            -- 'a', 'ab', 'b'
MATCH (n) WHERE n:A&!B RETURN n.t                 -- 'a'   (label expression in WHERE)
```

On relationships the same operators apply to types:

```cypher
MATCH (a)-[r:KNOWS|LIKES]->(b) RETURN type(r)
```

### Quantified path patterns (QPP)

A parenthesised path with a quantifier repeats a path segment. Quantifiers are `{n,m}`, `{n}`,
`{n,}`, `{,m}` (all inclusive). Variables inside the quantified group become **group variables**
(lists), and matching uses **trail** semantics (no relationship is traversed twice within a match).

```cypher
CREATE (a:N {id:'a'})-[:R]->(:N {id:'b'})-[:R]->(:N {id:'c'})-[:R]->(:N {id:'d'})

MATCH (a:N {id:'a'}) ((x)-[r:R]->(y)){1,3} (z:N)
RETURN z.id ORDER BY z.id                         -- 'b', 'c', 'd'

MATCH (a:N {id:'a'}) ((x)-[r:R]->(y)){1,3} (z:N {id:'d'})
RETURN [n IN x | n.id] AS trail, size(r) AS hops  -- trail ['a','b','c'] | hops 3
```

> **Conformance note.** The quantified group's interior may be a **single relationship** `(x)-[r]->(y)`
> or a **multi-relationship path** `(x)-[r1]->(m)-[r2]->(y)` (every interior variable becomes a group
> variable — one entry per iteration — under global **trail** semantics: no relationship repeats
> across hops or iterations). A **nested** quantified interior (a QPP inside a QPP) is still rejected
> at compile time with a clear message (see [Not yet supported](#not-yet-supported--deferred)).

---

## Clauses

### `USE <database>` selector

Prefix a query with `USE <db>` to target a database explicitly. It must name a database the caller is
authorised for; on this single-database deployment that is `graphus`.

```cypher
USE graphus MATCH (n:Person) RETURN n.name
```

---

## Administration

Administrative statements run in auto-commit (they are not part of a user transaction) and require
the appropriate privilege (see [security.md](security.md)).

### `SHOW` catalogues and `TERMINATE TRANSACTIONS`

| Statement | Columns |
| --------- | ------- |
| `SHOW FUNCTIONS` | `name`, `category`, `description`, `signature`, `isBuiltIn`, `aggregating` |
| `SHOW PROCEDURES` | `name`, `description`, `signature`, `mode`, `worksOnSystem` |
| `SHOW TRANSACTIONS` | `transactionId`, `database`, `currentQuery`, `username`, `mode`, `status`, `startTime`, `elapsedTimeMillis`, `protocol`, `clientAddress` |
| `SHOW SETTINGS` | `name`, `value`, `isDynamic`, `isExplicitlySet` |

```cypher
SHOW FUNCTIONS       -- one row per built-in function
SHOW PROCEDURES      -- one row per registered procedure
SHOW TRANSACTIONS    -- currently running transactions
SHOW SETTINGS        -- effective configuration keys
```

`TERMINATE TRANSACTIONS '<id>'` asks the server to kill a running transaction; it returns
`transactionId`, `database`, `username`, and a `message` (`"Transaction not found"` for an unknown
id).

```cypher
TERMINATE TRANSACTIONS 'graphus-transaction-42'
```

> **Note.** `SHOW …` statements do **not** accept a trailing `YIELD` / `WHERE` / `RETURN` clause;
> run the bare statement and post-process the rows. `CALL <procedure>() YIELD …` **is** supported
> (see below).

### Constraint DDL

Constraints support `IF NOT EXISTS`, `OR REPLACE`, and both node and relationship targets. Creating
one reports `constraints-added: 1`. The four kinds — uniqueness, existence (`NOT NULL`), key, and
property type — apply to both nodes (`FOR (n:Label)`) and relationships (`FOR ()-[r:TYPE]-()`).

The constraint **name is optional**: when omitted (`CREATE CONSTRAINT FOR (n:L) REQUIRE …`), a
deterministic Neo4j-style name (`constraint_<hex>`, derived from the schema) is generated, so a
repeated unnamed `CREATE … IF NOT EXISTS` stays idempotent. A trailing `OPTIONS { … }` map (Neo4j's
backing-index provider / config) is accepted for DDL compatibility; Graphus has a single built-in
index provider, so the options have no effect.

```cypher
CREATE CONSTRAINT uq_email    IF NOT EXISTS FOR (p:Person)      REQUIRE p.email IS UNIQUE
CREATE CONSTRAINT uq_name     IF NOT EXISTS FOR (p:Person)      REQUIRE (p.first, p.last) IS UNIQUE
CREATE CONSTRAINT nk_person   IF NOT EXISTS FOR (p:Person)      REQUIRE (p.first, p.last) IS NODE KEY
CREATE CONSTRAINT ex_name     IF NOT EXISTS FOR (p:Person)      REQUIRE p.name IS NOT NULL
CREATE CONSTRAINT ty_age      IF NOT EXISTS FOR (p:Person)      REQUIRE p.age IS :: INTEGER
CREATE CONSTRAINT rk_rated    IF NOT EXISTS FOR ()-[r:RATED]-() REQUIRE (r.a, r.b) IS RELATIONSHIP KEY
CREATE CONSTRAINT rex_since   IF NOT EXISTS FOR ()-[r:RATED]-() REQUIRE r.since IS NOT NULL
CREATE OR REPLACE CONSTRAINT uq_email FOR (p:Person) REQUIRE p.email IS UNIQUE
```

Uniqueness constraints may cover a **single property or a composite tuple** (`REQUIRE (a, b) IS
UNIQUE`), for both nodes and relationships. Like Neo4j, uniqueness is *null-relaxed*: an entity with
a null (or absent) value in any covered property is not checked, so it never collides — only fully
present tuples must be unique. (A key constraint additionally requires every covered property to be
present.)

#### Property type constraints — allowed types

A property type constraint (`REQUIRE n.p IS :: <TYPE>`, equivalently `IS TYPED <TYPE>` or `:: <TYPE>`)
accepts the full Neo4j-5.x closed set of property types:

- **Scalars** — `BOOLEAN`, `STRING`, `INTEGER`, `FLOAT`, `DATE`, `LOCAL TIME`, `ZONED TIME`,
  `LOCAL DATETIME`, `ZONED DATETIME`, `DURATION`, `POINT` (openCypher synonyms `BOOL`, `VARCHAR`,
  `INT`, `SIGNED INTEGER` are accepted).
- **Lists** — `LIST<X NOT NULL>` where `X` is one of the scalars above (e.g. `LIST<STRING NOT NULL>`).
- **Closed unions** — any `|`-separated union of the above, e.g. `INTEGER | STRING` or
  `STRING | LIST<STRING NOT NULL>`.

A type constraint checks only *present, non-null* values (it does **not** imply existence). The
non-property types `NODE`, `RELATIONSHIP`, `PATH`, `MAP`, `ANY`, `NOTHING`, and `NULL` are rejected.
`VECTOR<…>` property-type constraints are tracked separately (rmp #647).

```cypher
CREATE CONSTRAINT ty_born  FOR (p:Person)      REQUIRE p.bornOn IS :: DATE
CREATE CONSTRAINT ty_loc   FOR (p:Place)       REQUIRE p.location IS :: POINT
CREATE CONSTRAINT ty_code  FOR (p:Product)     REQUIRE p.code IS :: INTEGER | STRING
CREATE CONSTRAINT ty_tags  FOR (p:Product)     REQUIRE p.tags IS :: LIST<STRING NOT NULL>
CREATE CONSTRAINT ty_rwhen FOR ()-[r:RATED]-() REQUIRE r.when IS :: ZONED DATETIME
```

#### `SHOW CONSTRAINTS`

`SHOW CONSTRAINTS` lists every declared constraint with the Neo4j-5.x column set. The **default**
columns are `id`, `name`, `type`, `entityType`, `labelsOrTypes`, `properties`, `ownedIndex`,
`propertyType`; `YIELD *` additionally returns `options` and `createStatement`. The `type` value is one
of `NODE_PROPERTY_UNIQUENESS`, `RELATIONSHIP_PROPERTY_UNIQUENESS`, `NODE_PROPERTY_EXISTENCE`,
`RELATIONSHIP_PROPERTY_EXISTENCE`, `NODE_KEY`, `RELATIONSHIP_KEY`, `NODE_PROPERTY_TYPE`,
`RELATIONSHIP_PROPERTY_TYPE`. `labelsOrTypes` and `properties` are lists; `ownedIndex` names the backing
index for a uniqueness/key constraint (else `null`); `propertyType` carries a type constraint's declared
type (else `null`); `createStatement` is a re-runnable `CREATE CONSTRAINT` DDL; `options` is `{}`
(Graphus has a single built-in index provider).

Type filters and a `YIELD … [WHERE …] [RETURN …] [ORDER BY …] [SKIP …] [LIMIT …]` (or a terse
`WHERE …`) sub-clause are supported:

```cypher
SHOW CONSTRAINTS
SHOW UNIQUE CONSTRAINTS
SHOW NODE KEY CONSTRAINTS
SHOW RELATIONSHIP PROPERTY EXISTENCE CONSTRAINTS
SHOW PROPERTY TYPE CONSTRAINTS
SHOW CONSTRAINTS YIELD name, type WHERE type = 'NODE_KEY' RETURN name ORDER BY name
SHOW CONSTRAINTS WHERE entityType = 'RELATIONSHIP'
```

(`SHOW INDEXES` gains an `owningConstraint` column naming the constraint that owns a backing index.)

### Typed index DDL

In addition to the plain `CREATE INDEX` (see [indexes.md](indexes.md)), the typed keywords are
accepted:

| Keyword | Behaviour |
| ------- | --------- |
| `RANGE` | A full synonym of the node-property index. Nameable, droppable, and listed as `type` `RANGE`. |
| `TEXT` | Maps to the **same** node-property (`RANGE`) B-tree, which serves `=` and `STARTS WITH` string predicates. A documented equivalence — it is created and then reported as `RANGE` in `SHOW INDEXES`, not a distinct store. |
| `LOOKUP` | `CREATE`/`DROP LOOKUP INDEX` is **declined** by design: Graphus maintains node-label and relationship-type lookup indexes **implicitly** (always-on), so no explicit `LOOKUP` index is needed. They *are* listed, though — the two token lookups (`node_label_lookup_index` / `rel_type_lookup_index`) always appear in `SHOW INDEXES` and in `SHOW LOOKUP INDEXES`. |

```cypher
CREATE RANGE INDEX ix_age  IF NOT EXISTS FOR (p:Person) ON (p.age)
CREATE TEXT  INDEX ix_name IF NOT EXISTS FOR (p:Person) ON (p.name)   -- appears as RANGE in SHOW INDEXES
```

`SHOW INDEXES` is a single unified, Neo4j-conformant listing of **every** index kind (node/relationship
`RANGE`, composite `RANGE`, `FULLTEXT`, `POINT`, and the two token `LOOKUP` indexes), with the full
Neo4j column set, `UPPER-CASE` state, per-type filters (`SHOW RANGE|TEXT|POINT|LOOKUP|FULLTEXT|VECTOR|ALL
INDEXES`), and a `YIELD` / `WHERE` / `RETURN` tail — see [indexes.md](indexes.md#listing-indexes--show-indexes).

### Security DDL

Users and roles are managed with the following forms (grammar as implemented; note that
`SET PASSWORD` precedes `IF NOT EXISTS`, and there is no `CHANGE … REQUIRED` clause):

```cypher
CREATE USER alice SET PASSWORD 'S3cret-pw!' IF NOT EXISTS
ALTER  USER alice SET PASSWORD 'N3w-pw!'
ALTER  USER alice SET STATUS SUSPENDED        -- or SET STATUS ACTIVE
RENAME USER alice TO alicia

CREATE ROLE analyst IF NOT EXISTS
RENAME ROLE analyst TO reporting
```

`GRANT` / `REVOKE` of privileges to roles is covered in [security.md](security.md). Changing a user's
password forces its existing sessions to re-authenticate.

### `dbms.*` / `db.*` procedures

Call procedures with `CALL … [YIELD …]`.

| Procedure | Purpose |
| --------- | ------- |
| `dbms.components()` | product name, version list, and edition (`Graphus`, `["0.0.x"]`, `community`) |
| `db.awaitIndexes(timeoutSeconds)` | block until every index is `online` or the timeout elapses — the timeout argument is **required** |
| `db.resampleIndex(indexName)` | schedule a re-sampling of one index's statistics |
| `db.labels()`, `db.propertyKeys()`, `db.relationshipTypes()` | catalogue introspection |

```cypher
CALL dbms.components() YIELD name, versions, edition RETURN name, versions, edition
-- 'Graphus' | ['0.0.9'] | 'community'

CALL db.awaitIndexes(300)          -- block up to 300 s for pending builds
CALL db.resampleIndex('ix_age')
```

### Graph Data Science (GDS) execution modes

Project a named in-memory graph, then run an algorithm in one of four **execution modes**. Signatures
take the graph name plus a configuration map (`gds.graph.project` takes four arguments —
`name, nodeFilter, relFilter, config`).

| Mode | Suffix | Effect |
| ---- | ------ | ------ |
| Stream | `.stream` | yields one row per node/result |
| Stats | `.stats` | yields a single summary row (no writes) |
| Mutate | `.mutate` | writes the result into the **in-memory** projected graph |
| Write | `.write` | writes the result back to the **stored** graph as a property |

```cypher
CALL gds.graph.project('g', 'Person', 'KNOWS', {})

CALL gds.pageRank.stream('g', {}) YIELD nodeId, score RETURN count(*)
CALL gds.pageRank.stats('g', {})                       -- ranIterations, didConverge, centralityDistribution, …
CALL gds.pageRank.mutate('g', {mutateProperty:'prm'})  -- nodePropertiesWritten
CALL gds.pageRank.write('g', {writeProperty:'pr'})     -- writes `pr` on each Person; summary.stats reports properties-set

CALL gds.wcc.write('g', {writeProperty:'component'})
CALL gds.triangleCount.stats('g', {})
```

Algorithms available include `pageRank`, `wcc`, `scc`, `labelPropagation`, `triangleCount`,
`betweenness`, `closeness`, `degree` (with their `.stream` / `.stats` / `.mutate` / `.write` modes as
registered), plus the streaming path algorithms `gds.dijkstra.stream` and `gds.bellmanFord.stream`.
Manage projected graphs with `gds.graph.list()`, `gds.graph.exists(name)`, and
`gds.graph.drop(name)`.

---

## Not yet supported / deferred

These are recognised as out of scope today and are declined (most with an explanatory compile-time
message). They are documented here so expectations are exact.

| Area | Status |
| ---- | ------ |
| **Vector index** — `CREATE VECTOR INDEX …` | Not supported (syntax error). |
| **Vector similarity functions** — `vector.similarity.*`, `gds.similarity.*` | Not supported (unknown function). |
| **QPP — nested interior** | Deferred. A quantified group inside another quantified group is rejected at compile time. Single- **and** multi-relationship interiors (`(x)-[r1]->(m)-[r2]->(y)`) **are** supported. |
| **GDS path-algorithm write** — `gds.dijkstra.write`, `gds.bellmanFord.write` | Deferred. The path algorithms are **stream-only** today (`gds.dijkstra.stream` works). Node-property algorithms support `.stats`/`.mutate`/`.write`. |
| **Database aliases** — `CREATE ALIAS … FOR DATABASE …` | Not supported (syntax error). |
| **`ALTER USER … SET HOME DATABASE`** and `CHANGE [NOT] REQUIRED` | Not supported — `SET PASSWORD` and `SET STATUS` are (see below). |
| **Relationship property index — range / composite seek** | An **equality** relationship predicate now uses the index as a **planner seek**: a standalone `MATCH ()-[r:T {p: v}]-()` (or `MATCH ()-[r:T]-() WHERE r.p = v`) seeks the relationship-property index instead of scanning every `:T` relationship and filtering (`rmp` #659). A **range** (`r.p > v`) or **composite** (`{a: …, b: …}`) relationship predicate still scans + filters — those relationship seeks are deferred (composite is `rmp` #666). A variable-length (`-[r:T*]-`), multi-type (`-[r:T1|T2]-`) or `OPTIONAL MATCH` pattern also stays a scan by design. |
| **`LOOKUP` index DDL** | Declined by design — label/type lookup indexes are implicit and always-on (see above). |

---

See also: [indexes.md](indexes.md) · [transactions.md](transactions.md) · [security.md](security.md)
· [rest-api.md](rest-api.md) · [bolt.md](bolt.md).
