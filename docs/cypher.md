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

## Query prefixes — `EXPLAIN` and `PROFILE`

Prefix any statement with `EXPLAIN` or `PROFILE` to get its **execution plan** back in the result
summary. This is how you confirm that a query is served by the index you declared, rather than silently
falling back to a full scan — the two return exactly the same rows, so the plan is the only way to tell
them apart.

| Prefix | Runs the query? | Records returned | Summary key | Counters |
|--------|-----------------|------------------|-------------|----------|
| `EXPLAIN` | **No** — planned only | none (the column names are still reported) | `plan` | estimates only |
| `PROFILE` | **Yes** | the query's real rows | `profile` | **measured** `rows` + `dbHits` per operator |

`EXPLAIN` has **no side effects**: `EXPLAIN CREATE (:Person)` creates nothing, and makes no store access
at all. `PROFILE` executes normally — including writes — and additionally reports what each operator did.
Only one prefix may be used, and it must be the first token of the statement. Neither is a reserved word:
`RETURN 1 AS explain`, `MATCH (n:Profile)` and `n.explain` keep working exactly as before.

### The plan shape (Neo4j 5.x, verbatim)

Each plan node is a map with `operatorType`, `args`, `identifiers` and — for a non-leaf — `children`;
a `PROFILE` adds the top-level `rows` and `dbHits` of that operator. The official Neo4j drivers parse it
as `summary().plan` / `summary().profile`. Over REST the same document appears under the summary's
`plan` / `profile` key.

`EXPLAIN` (the index is used — `NodeIndexSeek`):

```
{
  operatorType: "Projection",
  args: { Details: "Projection(p.email AS email)", EstimatedRows: 30, planner: "COST", runtime: "VOLCANO" },
  identifiers: ["email"],
  children: [
    { operatorType: "NodeIndexSeek",
      args: { Details: "NodeIndexSeek(p:Person email = 'u7@x.io' via idx#1)" },
      identifiers: ["p"] }
  ]
}
```

`PROFILE` of `MATCH (p:Person) WHERE p.age > 90 RETURN p.age AS age` over 100 people (real output):

```
Projection      rows=9    dbHits=9      Details: Projection(p.age AS age)
  Filter        rows=9    dbHits=100    Details: Filter((p.age > 90))
    TokenLookupScan rows=100 dbHits=100 Details: TokenLookupScan(p:Person via idx#0)
```

Read it bottom-up: the scan read 100 node records and emitted 100 rows; the filter read one `age`
property per candidate (100 reads) and kept 9; the projection read `age` once per surviving row.

### What `dbHits` means — and what it does not

A `dbHit` is **one record obtained from the storage engine** by that operator: one node/relationship
record, one property, one index entry. It is *measured*, never estimated — Graphus reports no counter it
did not count. A fused scan-and-filter operator (`NodeLabelScanEq`) reports the records it **examined**,
not just the ones it matched, so a full-scan fallback cannot masquerade as cheap.

Graphus deliberately does **not** report `pageCacheHits`, `pageCacheMisses` or `time`: it does not
measure them, and a fabricated counter is worse than an absent one. Drivers treat all three as optional.

### The candidates an access path examined

`dbHits` charges an operator for what it **matched**. Every index access path in Graphus is a *candidate
list plus a re-verification* — the index is a derived, MVCC-unaware structure, so it answers with a
**superset** of the matching ids and the engine re-reads each candidate to test visibility and re-apply
the predicate — so `dbHits` alone cannot tell a seek that examined a million candidates to return ten
rows from one that examined ten. A `PROFILE` therefore also reports, inside each operator's `args`:

| Key | Meaning |
| --- | ------- |
| `CandidatesExamined` | Candidate records this operator decoded and re-verified. |
| `CandidatesRejectedByVisibility` | Of those, how many the MVCC visibility re-check dropped. |
| `CandidatesRejectedByFilter` | Of those, how many the operator's own predicate re-check dropped (label, value, range, relationship type, traversal direction). PostgreSQL calls the same thing *"Rows Removed by Filter"*. |
| `ReadMarkers` / `PredicateMarkers` | Serializability (SIREAD) markers this operator emitted, counted where they are emitted. |

The three candidate counters are disjoint: `examined - rejectedByVisibility - rejectedByFilter` is the
number of candidates that **survived the re-verification**. That is not the same as the operator's row
count — a node id named by both a stale and a live index entry is examined twice, survives twice and
yields one row after de-duplication, and a self-loop matched undirected is one survivor reported on
both of its sides.

`ReadMarkers` is the one to watch. A **range** seek registers a conservative whole-store predicate
footprint — one marker per live node, however few rows it returns — while an **equality** seek registers
a precise one. Over a 40-node label, measured:

```
MATCH (n:Person {name: 'p7'})          NodeIndexSeek       rows=1   dbHits=1   examined=1   ReadMarkers=2
MATCH (n:Person) WHERE n.age >= 38     NodeIndexRangeSeek  rows=2   dbHits=2   examined=2   ReadMarkers=44
MATCH (n:Person) WHERE n.age >= 0      NodeIndexRangeSeek  rows=40  dbHits=40  examined=40  ReadMarkers=120
MATCH (n:Person)                       TokenLookupScan     rows=40  dbHits=40  examined=40  ReadMarkers=80
```

Two rows costing a 44-marker pass over the whole store is a real cost that `rows` and `dbHits` could not
show. These counters are emitted **only when non-zero**, the same rule the `stats` map follows. On the
store-backed engine every server statement runs on, absence therefore means a *measured* zero. (The
in-memory reference backend used by the engine's own test suites measures no candidates at all and
emits none of these keys anywhere; that absence means "not measured". Nothing is fabricated either
way.) Both differ from `pageCacheHits` / `time` above, which are never measured on any backend and so
are never reported.

`PROFILE` runs the statement **serially** (intra-query morsel parallelism is disabled for it) so that
every storage access is attributable to an operator; a profiled query may therefore be slower than the
same query run normally. An unprofiled statement pays nothing at all — no instrumentation is built.

### Known limitation: an auto-commit read does not use the index it plans

A plain auto-commit read is dispatched to the off-thread reader pool, whose seam does not currently serve
property-index seeks: it declines them and the executor falls back — correctly, but expensively — to a
scan. So `PROFILE MATCH (p:Person {email: $e}) RETURN p` reports `NodeIndexSeek` (the planner *did*
choose the index) while its `dbHits` are those of a full scan. Inside an explicit transaction the same
seek costs 2 `dbHits` against 201 for the scan. The rows are identical either way — which is why this
went unnoticed until `PROFILE` made it visible.

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

A terminated transaction **cannot commit on any interface** — Bolt, Bolt-over-UDS, or REST. Its
client is refused at the next thing it does with the transaction (a statement, a keep-alive, or the
commit) with the non-retryable error *"the transaction has been terminated by an administrator
(TERMINATE TRANSACTIONS)"*, and the transaction is rolled back; a rollback still succeeds. See
[transactions.md](transactions.md#administrative-termination).

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
| `RANGE` | A full synonym of the node-property index. Nameable, droppable, and listed as `type` `RANGE`. Serves `=`, range (`<`/`>`/…) and — since a bounded prefix seek — `STARTS WITH`. |
| `TEXT` | A **distinct native trigram string index** (not a synonym of `RANGE`) that accelerates `CONTAINS`, `ENDS WITH` and `STARTS WITH` on a single node string property — the substring/suffix predicates a forward-ordered B-tree cannot serve. Nameable (or auto-named), droppable, and listed as `type` `TEXT`. A `RANGE` and a `TEXT` index may coexist on the same `(label, property)`; when a `TEXT` index is present it is preferred for `STARTS WITH` too. Node property only (relationship `TEXT` is a follow-up). |
| `LOOKUP` | `CREATE`/`DROP LOOKUP INDEX` is **declined** by design: Graphus maintains node-label and relationship-type lookup indexes **implicitly** (always-on), so no explicit `LOOKUP` index is needed. They *are* listed, though — the two token lookups (`node_label_lookup_index` / `rel_type_lookup_index`) always appear in `SHOW INDEXES` and in `SHOW LOOKUP INDEXES`. |

```cypher
CREATE RANGE INDEX ix_age  IF NOT EXISTS FOR (p:Person) ON (p.age)
CREATE TEXT  INDEX ix_name IF NOT EXISTS FOR (p:Person) ON (p.name)   -- serves CONTAINS/ENDS WITH/STARTS WITH
CREATE TEXT  INDEX         FOR (p:Person) ON (p.bio)                  -- anonymous → text_index_Person_bio
DROP   TEXT  INDEX ix_name IF EXISTS
```

A `RANGE` index may cover **one** property or a **composite** ordered tuple of two or more, over **nodes**
(`FOR (n:L) ON (n.a, n.b)`) or **relationships** (`FOR ()-[r:T]-() ON (r.a, r.b)`, undirected only). A
`MATCH` whose inline map / `WHERE` supplies an equality on every covered key seeks the composite in **one**
seek (over the full ordered tuple) instead of a single-key seek + residual filter; a predicate on only the
leading key uses the composite as a leading-prefix seek. The key order is significant — `(a, b)` and
`(b, a)` are distinct indexes.

```cypher
CREATE INDEX ix_pn  FOR (p:Person)      ON (p.first, p.last)   -- composite node index
CREATE INDEX ix_ks  FOR ()-[r:KNOWS]-() ON (r.since)           -- single-property relationship index
CREATE INDEX ix_kab FOR ()-[r:KNOWS]-() ON (r.a, r.b)          -- composite relationship index (rmp #666)
MATCH (p:Person {first: 'Ada', last: 'Lovelace'}) RETURN p     -- one composite node seek
MATCH ()-[r:KNOWS {a: 1, b: 2}]-() RETURN r                    -- one composite relationship seek
```

With that index in place, a substring or suffix filter is index-served instead of a full label scan:

```cypher
MATCH (p:Person) WHERE p.name CONTAINS 'obe'   RETURN p   -- index-served (was scan + filter)
MATCH (p:Person) WHERE p.name ENDS WITH 'son'  RETURN p   -- index-served (was scan + filter)
```

Every `CREATE INDEX` (plain / `RANGE` / `TEXT` / `POINT` / `FULLTEXT`) accepts a trailing Neo4j
`OPTIONS { indexProvider: '…', indexConfig { … } }` map. Graphus has one built-in provider and
synchronous builds, so the clause is validated and accepted but not applied (except the full-text
`fulltext.analyzer`, which maps to the analyzer, and the `VECTOR` index config, which **is** applied —
see below). `POINT`, `FULLTEXT` and `VECTOR` `CREATE`/`DROP` also support `IF NOT EXISTS` / `IF EXISTS`,
an anonymous (auto-named) index, and dropping any kind by the unified `DROP INDEX <name>` — see
[indexes.md](indexes.md).

Point (spatial) indexes cover **nodes** (`FOR (n:L) ON (n.p)`) or **relationships**
(`FOR ()-[r:T]-() ON (r.p)`, undirected only), and serve an upper-bounded Cartesian proximity filter as
a planner seek instead of a scan:

```cypher
CREATE POINT INDEX by_loc FOR (c:City) ON (c.location)
CREATE POINT INDEX rel_at FOR ()-[r:VISITED]-() ON (r.at)
MATCH (c:City)         WHERE distance(c.location, point({x:0, y:0})) <= 5 RETURN c   -- node seek
MATCH ()-[r:VISITED]-() WHERE distance(r.at,       point({x:0, y:0})) <= 5 RETURN r   -- rel  seek
```

The exact `distance` predicate is always re-checked above the seek (the grid returns a superset), a
geographic (WGS-84) centre or a `point.withinBBox(…)` predicate falls back to a scan, and without a
matching point index the query stays a scan + filter — always correct, never index-required.

Full-text indexes cover **nodes** (`FOR (n:A|B)`) or **relationships** (`FOR ()-[r:T|U]-()`), each over
one or more labels/types (Neo4j's `A|B` syntax — a node/relationship of **any** covered label/type is
indexed) and searched by the two full-text procedures, which return the matching entity as a structural
value plus a relevance `score`:

```cypher
CALL db.index.fulltext.queryNodes('posts', 'graph databases') YIELD node, score
  RETURN node, score
CALL db.index.fulltext.queryRelationships('rel_notes', 'graph') YIELD relationship, score
  RETURN relationship, score
```

Both re-check each candidate for MVCC visibility, its current label/type and RBAC; an unknown index
name — or a node index name given to `queryRelationships` (and vice versa) — is a clear error, not
silently-empty results. See [indexes.md](indexes.md#node-vs-relationship-single-vs-multi-label-full-text).

Vector (HNSW) indexes are approximate-nearest-neighbour indexes over a dense `f32` embedding property.
They cover **nodes** (`FOR (n:L) ON (n.p)`) or **relationships** (`FOR ()-[r:T]-() ON (r.p)`, undirected
only), and require an `OPTIONS { indexConfig: { … } }` clause carrying the embedding shape:

```cypher
CREATE VECTOR INDEX doc_emb IF NOT EXISTS FOR (d:Doc) ON (d.embedding)
  OPTIONS { indexConfig: {
    `vector.dimensions`:          1536,        -- REQUIRED integer, 1..=4096
    `vector.similarity_function`: 'cosine',    -- REQUIRED 'cosine' | 'euclidean' (case-insensitive)
    `vector.hnsw.m`:              16,           -- optional, default 16
    `vector.hnsw.ef_construction`: 100          -- optional, default 100
  } }

CREATE VECTOR INDEX rel_emb FOR ()-[r:SIMILAR]-() ON (r.vec)
  OPTIONS { indexConfig: { `vector.dimensions`: 3, `vector.similarity_function`: 'euclidean' } }
DROP VECTOR INDEX doc_emb IF EXISTS
```

`vector.dimensions` and `vector.similarity_function` are **mandatory** (the `OPTIONS { indexConfig: … }`
clause is therefore required); a missing or out-of-range dimension (must be `1..=4096`), an unknown
similarity, a non-positive HNSW parameter, or a missing required key is a clear, side-effect-free error.
An unrecognised `indexConfig` key is accepted and ignored (Neo4j leniency); an unrecognised **top-level**
`OPTIONS` key is rejected. The name is optional (auto-named when omitted). A `VECTOR` index is a distinct
kind — it never backs a constraint — and is listed under `SHOW INDEXES` with `type` `VECTOR`,
`indexProvider` `vector-2.0` and its `indexConfig` in `options`.

A declared vector index is queried with the Neo4j-compatible **k-NN procedures**, and two **similarity
functions** compute the same normalized score directly in an expression:

```cypher
-- k nearest :Doc nodes to a query embedding, most-similar first (score in (0, 1])
CALL db.index.vector.queryNodes('doc_emb', 5, [0.1, 0.2, …]) YIELD node, score
RETURN node.title, score

-- the relationship analogue
CALL db.index.vector.queryRelationships('rel_emb', 5, [0.1, 0.2, …]) YIELD relationship, score
RETURN relationship, score

-- the raw similarity of two vectors (no index needed)
RETURN vector.similarity.cosine([1.0, 0.0], [0.0, 1.0]) AS s      -- 0.5  ((1 + cos) / 2)
RETURN vector.similarity.euclidean([0.0], [2.0]) AS s             -- 0.2  (1 / (1 + d²))
```

`db.index.vector.queryNodes(indexName :: STRING, numberOfNearestNeighbours :: INTEGER, query :: ANY)
:: (node :: NODE, score :: FLOAT)` resolves the named **node** vector index, runs the HNSW k-NN with the
index's similarity metric, and yields the visible nodes with their score in descending order.
`db.index.vector.queryRelationships(…) :: (relationship :: RELATIONSHIP, score :: FLOAT)` is the
relationship analogue. `query` is a `LIST<FLOAT | INTEGER>` of the index's dimension. Each hit is
**re-checked against the caller's transaction snapshot** — a deleted, re-labelled/re-typed or
re-embedded entity, or one the caller lacks read privileges for, is dropped — so results honour MVCC and
RBAC. An unknown index, an index of the **wrong kind** (a relationship vector index through `queryNodes`
or vice-versa), a non-list / non-finite / wrong-dimension query vector, or a non-positive `k` is a clear
error. These procedures run **inline** (a read; `SHOW PROCEDURES` reports `mode` `READ`).

`vector.similarity.cosine(a :: LIST<FLOAT>, b :: LIST<FLOAT>) :: FLOAT` and
`vector.similarity.euclidean(a, b) :: FLOAT` return the **same normalized score in `(0, 1]`** the index
uses — cosine `(1 + cos) / 2` (`1.0` for identical, `0.5` for orthogonal vectors), euclidean
`1 / (1 + ‖a − b‖²)`. A `null` operand yields `null`; a dimension mismatch or a non-finite element is a
runtime error. INTEGER elements widen to FLOAT.

`SHOW INDEXES` is a single unified, Neo4j-conformant listing of **every** index kind (node/relationship
`RANGE`, composite `RANGE`, `TEXT`, `FULLTEXT`, `POINT`, `VECTOR`, and the two token `LOOKUP` indexes),
with the full Neo4j column set, `UPPER-CASE` state, per-type filters
(`SHOW RANGE|TEXT|POINT|LOOKUP|FULLTEXT|VECTOR|ALL INDEX[ES]`), and a `YIELD` / `WHERE` / `RETURN` tail.
The singular `SHOW INDEX` / `SHOW <filter> INDEX` is accepted as a full synonym of the plural — see
[indexes.md](indexes.md#listing-indexes--show-indexes).

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
| `db.awaitIndexes(timeOutSeconds = 300)` | block until every index is `online` or the timeout elapses — the timeout is **optional** (defaults to 300) |
| `db.awaitIndex(indexName, timeOutSeconds = 300)` | await one named index; a no-op for a real index, an **error** if no index of that name exists |
| `db.resampleIndex(indexName)` | request a recompute of the named index's selectivity histogram — an **error** if no index of that name exists; a no-op for an index kind that keeps no histogram. Not part of the calling transaction (as in Neo4j); see [indexes.md](indexes.md#index-statistics-and-the-planner) |
| `db.resampleOutdatedIndexes()` | request a recompute of **every** declared node-property index's selectivity histogram |
| `db.index.fulltext.queryNodes(indexName, queryString [, options])` | full-text node search; optional `options` map honours `skip` / `limit` |
| `db.index.fulltext.queryRelationships(indexName, queryString [, options])` | full-text relationship search; same optional `options` map |
| `db.index.fulltext.listAvailableAnalyzers()` | list the supported full-text analyzers (`standard`, `keyword`) with their stop-words |
| `db.index.fulltext.awaitEventuallyConsistentIndexRefresh()` | no-op (Graphus full-text is maintained synchronously, not eventually-consistent) |
| `db.labels()`, `db.propertyKeys()`, `db.relationshipTypes()` | catalogue introspection |

```cypher
CALL dbms.components() YIELD name, versions, edition RETURN name, versions, edition
-- 'Graphus' | ['0.0.9'] | 'community'

CALL db.awaitIndexes()             -- block up to the default 300 s for pending builds
CALL db.awaitIndexes(60)           -- ... or an explicit timeout
CALL db.awaitIndex('ix_age')       -- await a single named index (errors if it does not exist)

CALL db.resampleIndex('ix_age')    -- refresh one index's selectivity histogram
CALL db.resampleOutdatedIndexes()  -- ... or every declared node-property index

CALL db.index.fulltext.listAvailableAnalyzers() YIELD analyzer, description, stopwords

-- Paginate a full-text search with the options map (skip/limit apply after relevance ordering):
CALL db.index.fulltext.queryNodes('posts', 'graph databases', {skip: 10, limit: 5})
  YIELD node, score RETURN node, score
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
| **GDS node-similarity functions** — `gds.similarity.*` | Not supported (unknown function). The `vector.similarity.cosine` / `vector.similarity.euclidean` functions **are** supported, as is the whole `VECTOR` index surface (DDL + `db.index.vector.query*`) — see [Indexes](#indexes). |
| **QPP — nested interior** | Deferred. A quantified group inside another quantified group is rejected at compile time. Single- **and** multi-relationship interiors (`(x)-[r1]->(m)-[r2]->(y)`) **are** supported. |
| **GDS path-algorithm write** — `gds.dijkstra.write`, `gds.bellmanFord.write` | Deferred. The path algorithms are **stream-only** today (`gds.dijkstra.stream` works). Node-property algorithms support `.stats`/`.mutate`/`.write`. |
| **Database aliases** — `CREATE ALIAS … FOR DATABASE …` | Not supported (syntax error). |
| **`ALTER USER … SET HOME DATABASE`** and `CHANGE [NOT] REQUIRED` | Not supported — `SET PASSWORD` and `SET STATUS` are (see below). |
| **Relationship property index — range seek** | An **equality** relationship predicate uses the index as a **planner seek**: a standalone `MATCH ()-[r:T {p: v}]-()` (or `MATCH ()-[r:T]-() WHERE r.p = v`) seeks the single-property relationship index (`rmp` #659), and a **composite** predicate `MATCH ()-[r:T {a: …, b: …}]-()` seeks a composite relationship index over the full ordered tuple in **one** `RelCompositeIndexSeek` (`rmp` #666). A **range** (`r.p > v`) relationship predicate still scans + filters — that relationship seek is deferred. A variable-length (`-[r:T*]-`), multi-type (`-[r:T1|T2]-`) or `OPTIONAL MATCH` pattern also stays a scan by design. |
| **`LOOKUP` index DDL** | Declined by design — label/type lookup indexes are implicit and always-on (see above). |

---

See also: [indexes.md](indexes.md) · [transactions.md](transactions.md) · [security.md](security.md)
· [rest-api.md](rest-api.md) · [bolt.md](bolt.md).
