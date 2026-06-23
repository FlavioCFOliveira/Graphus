//! The openCypher TCK conformance run: discover every vendored scenario, run it through the real
//! Graphus engine, print a summary, and assert a no-regression ratchet (`CLAUDE.md`: measure to
//! decide; the TCK is an inviolable target).
//!
//! This is **one** integration test (`tck_conformance`) so the corpus is parsed and walked once. It
//! prints a single machine-greppable line —
//! `TCK: <passed>/<total> (<pct>%) — baseline <BASELINE>` — plus a per-category breakdown and
//! triage samples, then asserts `passed >= BASELINE`. Raising the ratchet after an engine
//! improvement is a one-line edit to [`BASELINE`].
//!
//! Run it verbosely to see the report:
//!
//! ```text
//! cargo test -p graphus-tck --test tck -- --nocapture
//! ```

use std::path::{Path, PathBuf};

use graphus_tck::feature::load_feature;
use graphus_tck::report::Report;
use graphus_tck::runner::run_scenario;

/// The no-regression ratchet: the exact number of scenarios passing today.
///
/// Measured empirically by this very test (run once with the printed `passed` count, then pinned
/// here). A future engine improvement that raises the pass count should bump this so the gain is
/// locked in; a regression that drops below it fails the build.
///
/// Current ratchet: **3496 / 3901 scenarios pass (89.62 %)**, with 0 panics and 0 scenarios
/// skipped as unsupported. This rose from 3479 (+17 from the spatial point type (#73)): a new
/// `expressions/spatial/Spatial1.feature` exercises `point()` construction (both CRSs, 2D/3D), the
/// accessors (`.x`/`.y`/`.z`/`.longitude`/`.latitude`/`.height`/`.crs`/`.srid`), `distance()` /
/// `point.distance()` (Cartesian Euclidean and the cross-CRS-is-null rule), point equality
/// (same-CRS true, cross-CRS false), point orderability (`ORDER BY` by CRS/srid then coordinates),
/// and a point property round-tripping through a node — all through the real engine. **Provenance
/// note (`rmp` task #73):** the pinned upstream openCypher corpus has **no** `expressions/spatial`
/// directory (spatial was never standardised into the public TCK feature set; see `tck/PINNED.txt`
/// and the feature file's header), so these 17 are **Graphus-authored** scenarios that mirror the
/// openCypher spatial CIP / Neo4j spatial semantics, run through the same harness as the vendored
/// corpus. They are transparently labelled as such; the gain is genuine, engine-verified spatial
/// coverage, not a borrowed upstream count. Measured: zero regressions (failures held at 405).
/// Prior rise: 3413 → 3479 (+66 from executor path & aggregation functions
/// (#63)): `collect()`/`collect(DISTINCT …)` now folds at the `RowValue` level so structural
/// elements survive; `nodes(path)`/`relationships(path)` and `length(path)` project a path's
/// element sequence; and a named path (`MATCH p = …`, `[p = (a)-->(b) | p]`) binds the structural
/// `Path` value end-to-end (executor [`NamedPath`] operator + the expression-side pattern walk),
/// which also lifted variable-length patterns inside expressions, structural list/path equality,
/// ordering and grouping, and `DELETE` over paths/lists. The same cycle fixed a synthetic-name
/// collision in the composite-aggregate rewrite — every aggregate column reused `#agg0`, so a
/// multi-aggregate projection (`RETURN sum(x), min(x), max(x)`) read every column back as the last
/// one; the synthetic names are now disambiguated per column (the bulk of the gain). Measured: zero
/// regressions, the before/after failing-scenario set diff is strictly shrinking. Prior rise:
/// 3324 → 3413 (+89 from scalar function gaps (#62)): `rand()`,
/// `sqrt()`, `toBoolean()`/`toBooleanOrNull()` joined the function registry and the evaluator
/// (+64 `expressions/quantifier`, +7 `expressions/typeConversion`, +1
/// `expressions/mathematical`), and the same cycle fixed the pre-existing aggregation-grouping
/// over-restriction those scenarios then surfaced — any non-aggregated projection item is now a
/// grouping key, while an aggregate-containing item may compose, outside its aggregates, only
/// constants and projected *simple* keys (`AmbiguousAggregationExpression` otherwise) — plus
/// compile-time `SKIP`/`LIMIT` constancy (`NonConstantExpression` for row-dependent counts,
/// `NegativeIntegerArgument` for negated literals) and `count(rand())` →
/// `NonConstantExpression` (+8 `clauses/return-skip-limit`, +3 `clauses/with-orderBy`,
/// +3 `clauses/match`, +2 `clauses/return`, +1 `clauses/with`; measured: zero regressions, the
/// before/after failing-scenario set diff is strictly shrinking). Prior rises: 3130 → 3324
/// (#60, IANA time-zone resolution); 2996 → 3130 (#61, compile-time expression type checking
/// via [`graphus_cypher::static_type`]); 2944 → 2996 (#57, `CALL` procedures); 2614 → 2944
/// (#56, TCK-faithful error classification); 1782 → 2614 (#53, temporal types); 1192 → 1782
/// (#54, quantifiers/comprehensions/EXISTS); 1112 → 1192 (#55, verbatim column names).
/// Remaining failures are honest gaps: property-access typing that needs `WITH`-projection
/// type-flow (`WITH 1 AS x … x.p`), float-parameter `SKIP`/`LIMIT`, the transaction-clock
/// constructors (`datetime()`, `date.statement()`, …), the full-query
/// `EXISTS { ... RETURN ... }` form, structural (node/relationship/path) values inside list
/// literals (`toBoolean(n)` via `[true, n]` cannot raise its `TypeError`), and ORDER BY keys
/// that *evaluate* aggregates (`ORDER BY sum(…)` matching a projected aggregate).
///
/// 3515 → 3540 (#125, feature-level `Background:` blocks): the corpus's sole `Background:` user,
/// `clauses/match/Match5.feature`, had its graph-seeding `Given`/`having executed:` steps silently
/// dropped — gherkin parses a `Background:` into `feature.background`, separate from each scenario's
/// own steps, and the harness only read `feature.scenarios`. Every Match5 scenario therefore ran
/// against an empty graph, so all 26 variable-length patterns returned 0 rows. Prepending the
/// background steps to every scenario (Gherkin semantics) fixed Match5 3/29 → 28/29 (+25; the lone
/// remaining failure is the unsupported double-arrow `<-[*]->` pattern, an honest parser gap). The
/// variable-length expand engine itself was already correct — proven by `tests/var_length.rs`.
///
/// 3540 → 3562 (#126, pattern predicates): a relationship pattern written directly as a boolean
/// expression (`MATCH (n) WHERE (n)-[]->() RETURN n`) now parses, desugaring to the existing
/// `EXISTS { pattern }` existential (openCypher `PatternPredicate = RelationshipsPattern`). The
/// parser disambiguates a node-pattern-shaped `(…)` followed by a relationship connector from an
/// ordinary parenthesized expression; semantics enforce the two openCypher restrictions — a pattern
/// predicate may not introduce fresh variables (`UndefinedVariable`) and may only appear in a
/// predicate position, never a projection / `SET` RHS / function argument (`UnexpectedSyntax`).
/// Wins: `expressions/pattern/Pattern1` 17/39 → 38/39 (+21; the lone gap is the bare-node
/// `WHERE (n)` self-pattern type check), `expressions/list/List6` +1 (`size()` on a pattern
/// predicate now rejected), and `clauses/match-where/MatchWhere4` / `clauses/with-where/WithWhere4`
/// +1 each (disjunctive multi-part predicates including patterns). Measured: zero regressions.
///
/// 3562 → 3589 (#127, multi-block scenarios): a TCK scenario is an ordered sequence of
/// `(When query → Then expectation → [And side effects])` blocks executed against the *same* graph
/// (`tck/README.adoc`); a `When executing control query:` reads back the committed effect of the
/// preceding block. The harness had collapsed the plan to a *single* `(query, expectation,
/// side_effects)`, so for a two-block scenario (`CREATE …` then a control `MATCH … RETURN …`) only
/// the last query survived — the CREATE never ran and the control query read an empty graph
/// (`row count mismatch: expected 1, got 0`). The runner now collects an ordered `Vec<QueryBlock>`,
/// runs each against the shared coordinator (committed between blocks like a real session), and
/// measures each block's side effects as the delta around *that block alone*. Wins:
/// `expressions/temporal/Temporal4` 6/39 → 24/39 (+18), `clauses/create/Create2` 20/24 → 24/24
/// (+4), `clauses/create/Create5` 0/5 → 4/5 (+4), `clauses/merge/Merge6` 2/6 → 3/6 (+1). Measured:
/// zero regressions (the net +27 equals the sum of the affected-feature gains exactly). The harness
/// fix proved temporal *storage* already works: Temporal4 [1]–[12] (date/time/datetime/duration
/// scalars **and arrays** round-tripping through a node property) all pass.
///
/// 3608 → 3623 (#129, temporal clock constructors): scenario Temporal4 [13] (`Should propagate
/// null`, 15 example rows) now passes — Temporal4 is 39/39. The clock variants
/// `date.transaction` / `date.statement` / `date.realtime` (and the `localtime` / `time` /
/// `localdatetime` / `datetime` equivalents) are registered and route to their base constructor:
/// they return the base type, propagate a `null` argument to `null` (the path the TCK exercises),
/// and accept the optional timezone argument. Their zero-argument "current instant" form remains a
/// documented named deferral (it needs a clock seam), shared with the bare constructors — that gap
/// is the *honest* remaining failure in Temporal10 [12] (`date()` / `time()` / … with no argument),
/// deliberately left failing rather than masked. Measured: zero regressions (the net +15 equals
/// Temporal4 [13]'s 15 example rows exactly).
///
/// 3589 → 3608 (#128, WITH … WHERE dual scope): the trailing `WHERE` of a `WITH` (and its `ORDER BY`)
/// is evaluated in the **dual scope** — the projected aliases UNION the pre-projection input
/// variables — per the openCypher grammar (`WITH items [ORDER BY] [SKIP] [LIMIT] [WHERE]`, where the
/// `WHERE` nests inside the projection body) and the canonical `WithWhere7` before/after/both test.
/// Graphus had reset the scope to the projected names *before* the `WHERE`, rejecting a `WHERE` that
/// references a dropped variable (`WITH c WHERE r IS NULL` → `variable r is not defined`). Both the
/// semantic binder (dual scope) and the planner were fixed: for a non-aggregating projection the
/// planner now carries the referenced input variables across the projection, filters above the
/// augmented projection, then narrows the row back to the declared output columns. Wins:
/// `useCases/triadicSelection/TriadicSelection1` +14 (the triadic anti-join / friend-of-a-friend
/// queries), `clauses/with-where/WithWhere1` +3, `WithWhere7` +2. Measured: zero regressions (the
/// net +19 equals the sum of the affected-feature gains exactly).
///
/// 3623 → 3656 (#130, comparability vs orderability for `<`/`>`/`<=`/`>=`): the inequality operators
/// now use the openCypher **comparability** *partial* relation (`graphus_cypher::compare_values`,
/// CIP2016-06-14 §Comparability) instead of the total **orderability** (`cmp_values`, which
/// `ORDER BY`/`min`/`max`/`DISTINCT`/indexes keep — left untouched). A cross-type comparison
/// (string vs number, a `map` operand, mismatched temporal classes / point CRS, a `null` reached
/// inside a list) now yields `NULL`; `NaN`-vs-number yields `FALSE` while `NaN`-vs-non-number yields
/// `NULL`. Two further pre-existing bugs found and fixed in the same cycle: (a) **chained
/// comparisons** `a < b < c` were parsed left-associatively as `(a < b) < c` (a boolean compared to
/// `c`) instead of desugaring to the conjunction `a < b AND b < c`; (b) **large-integer equality**
/// compared two `INTEGER`s through `f64`, so distinct 19-digit ids collapsed to equal. Wins:
/// `expressions/comparison` 47→72 (Comparison1 [12]/[13], Comparison2 [1]–[6], Comparison3 [1]–[9]
/// ranges, Comparison4 chains), plus clause-level cross-type/range queries. Measured per-category,
/// zero regressions: clauses 1113→1117, expressions 2486→2515, useCases 24→24; `with-orderBy`
/// 277/292 and `return-orderby` 24/35 both *unchanged* (the orderability path is preserved). The
/// net +33 equals the sum of the affected-feature gains exactly.
///
/// 3656 → 3667 (#131, `percentileDisc`/`percentileCont` aggregations): the two percentile aggregates
/// are now computed in the executor's group accumulator following Neo4j's exact algorithm —
/// `percentileDisc` is nearest-rank (`floatIdx = p*count`, returning a real set member with its
/// source numeric subtype), `percentileCont` is linear interpolation (`floatIdx = p*(count-1)`,
/// always a `Float`). The percentile argument (`args[1]`) is captured and range-validated on the
/// first contributing row; a value outside `[0,1]` raises the new `EvalError::NumberOutOfRange`,
/// which classifies to the TCK `ArgumentError: NumberOutOfRange`. Wins: `expressions/aggregation`
/// Aggregation6 [1]/[2] (values) and [3]/[4]/[5] (bad-argument errors), +11. Measured, zero
/// regressions: the net +11 equals the Aggregation6 percentile-scenario count exactly.
///
/// 3667 → 3715 (#132, graph-element accessors + static property access): `labels()`/`type()` now
/// propagate null (`labels(null) = null`), raise a runtime `TypeError` (`InvalidArgumentValue`) on a
/// non-null non-matching argument, and are rejected at compile time on a statically-provable wrong
/// type — a node into `type()`, a path into `labels()` — via a new `SType::Path`/`VarKind::Path`.
/// List indexing (`list[i]`) and dynamic property access (`n['name']`) now operate at the
/// `RowValue` level, so a structural list preserves its node/relationship references (the "accept
/// type Any" path: `labels(list[0])`, `(list[1]).prop`). An aliased projection carries its provable
/// static type forward, so `WITH 123 AS x RETURN x.num` is a compile-time mismatch. A *leading*
/// `OPTIONAL MATCH` over the empty unit row now preserves its one all-`NULL` driving row instead of
/// collapsing to zero. The harness also honours `(ignoring element order for lists)` by matching a
/// list cell as a bag. Wins: `expressions/graph` 34→60 (Graph3/4/6/7/9), plus the leading-optional
/// fix unblocking further `clauses`/`expressions` scenarios. Measured, zero regressions (full
/// failure-set diff: 0 newly-failing scenarios; the net +48 is purely additive).
///
/// 3715 → 3736 (#133, scalar type-conversion alignment): `toInteger`/`toFloat`/`toString`/
/// `toBoolean` now evaluate their argument at the `RowValue` level, so a node/relationship/path/
/// list/map argument raises a runtime `TypeError` (`InvalidArgumentValue`) instead of silently
/// collapsing to `null` — `expressions/typeConversion` TypeConversion2 [8], TypeConversion3 [6],
/// TypeConversion4 [10] (the "Fail … on invalid types" outlines). `toInteger` of a numeric string
/// now truncates the float form (`'1.7'` → 1, `'2.9'` → 2) so the "handling Any type" and
/// "list of strings" scenarios pass, and integer-shaped strings keep full `i64` precision.
/// `toFloat(true)` is now correctly invalid (a boolean is convertible for `toInteger`/`toBoolean`
/// but not `toFloat`). The `…OrNull` companions yield `null` rather than raising. Wins:
/// `expressions/typeConversion` to 47/47 (100%), +21. Measured, zero regressions (full
/// failure-set diff: the net +21 is purely additive).
///
/// 3736 → 3760 (#134, DELETE semantics): `clauses/delete` to 41/41 (100%, +22), with the +24 net
/// fully additive. Five fixes: (1) `RecordGraph::incident_rels` now filters MVCC-tombstoned
/// relationships, so a deleted relationship is no longer reported as incident (fixed every
/// relationship `-relationships` count and the spurious `DeleteConnectedNode` after delete);
/// (2) a new structural `RowValue::Map` (mirroring `RowValue::List`) preserves graph elements
/// through map construction and `m.key`/`m['key']` access, so `DELETE` reaches the node/rel/path a
/// map holds (`Delete5` [3]-[6]); (3) `DELETE` is now two-phase — gather all targets (dedup by id),
/// delete every relationship, then every node — so two overlapping paths delete cleanly without
/// `DETACH` (`Delete5` [7]); (4) the openCypher delete-after-read **Eager** barrier wraps a
/// `DELETE`'s graph-reading input, so `MATCH (a)-[r]-(b) DELETE r,a,b RETURN count(*)` observes the
/// full pre-delete row set (`Delete4` [1][2]); (5) the compile-time `DELETE`-non-entity split:
/// arithmetic (`DELETE 1 + 1`) is `InvalidArgumentType` while a label/type predicate
/// (`DELETE n:Person`/`r:T`) is `InvalidDelete` (`Delete5` [9], `Delete1`/`Delete2`). Measured,
/// zero regressions (full failure-set diff: 0 newly-failing scenarios; the net +24 is purely
/// additive).
///
/// 3830 → 3847 (#137, MERGE semantics): `clauses/merge/{Merge1,Merge5,Merge6,Merge7}` all to 100%,
/// closing 16 scenarios, plus one additive knock-on (`clauses/match/Match8` [2], which combines
/// MATCH/MERGE/OPTIONAL MATCH). Six fixes: (1) **path binding** — `MERGE p = …` now wraps the merge
/// in the same `NamedPath` operator a `MATCH p = …` uses, over the create-parts' anchor/step
/// variables (`Merge1` [13], `Merge5` [10]); (2) **deleted-entity visibility** — a `MERGE` whose
/// input reads the graph gets the same delete-after-read `Eager` barrier `DELETE` has, so a prior
/// same-query delete is fully settled before the match scan, never matching a tombstoned entity
/// (`Merge1` [14], `Merge5` [20]); (3) **unspecified direction** — an undirected `MERGE` relationship
/// is now accepted (the `RequiresDirectedRelationship` check is `CREATE`-only), matches both
/// orientations, and creates left-to-right when absent (`Merge5` [11]-[13]); (4) **null property** —
/// a `MERGE` inline map with a null value raises the runtime `SemanticError: MergeReadOwnWrites` via
/// the new `ExecError::MergeNullProperty` (`Merge1` [17], `Merge5` [29]); (5) **parameter predicate**
/// — a parameter used as a `MERGE` node/relationship predicate is the compile-time
/// `SyntaxError: InvalidParameterUse`, raised by semantic analysis before parameter binding
/// (`Merge1` [16], `Merge5` [27]); (6) **multi-match fan-out** — `MERGE` now binds **all** matches
/// (one row each) when several exist and creates only on zero matches, deduping a self-loop reported
/// twice by the undirected expansion (`Merge5` [3][18][19]); plus `SET r = a` / `SET r += map` now
/// copy onto a **relationship** (new rel-property seam methods + entity-source eval), fixing
/// `Merge6` [6][7] and `Merge7` [4][5]. Measured, zero regressions (full failure-set diff: 0
/// newly-failing scenarios; the net +17 is purely additive).
///
/// 3847 → 3866 (#138, numeric-literal limits + operator precedence): three independent fixes across
/// the lexer/parser/evaluator, closing 19 scenarios. (1) **Integer literal range check at compile
/// time** — integer literals are now resolved to `i64` *in the parser*, range-checked against
/// `i64::MIN..=i64::MAX`; an out-of-range literal is a compile-time `SyntaxError` (`IntegerOverflow`)
/// instead of a runtime `ArithmeticError`, and a `-` directly in front of an integer literal is
/// folded so `i64::MIN` (`-9223372036854775808`) is representable. Closes
/// `expressions/literals/Literals2` [8][9][10] (decimal), `Literals3` [8][16][17] (hex), `Literals4`
/// [8][9][10] (octal). The AST `Literal::Integer` now carries an `i64`, not the lexer magnitude.
/// (2) **Float overflow** — a float literal whose magnitude exceeds `f64` (e.g. `1.34E999`, which
/// `f64::from_str` maps to infinity) is now a compile-time `SyntaxError` (`Literals5` [27]).
/// (3) **Exponentiation is left-associative** — `^` now folds left (`4 ^ (3*2) ^ 3 == (4 ^ 6) ^ 3`),
/// per the openCypher M23 EBNF and `expressions/precedence/Precedence2` [2][3]; unary minus still
/// binds tighter than `^`, preserving [4]. (4) **String predicate on a non-string operand yields
/// `null`** (openCypher/Neo4j), not a `TypeError` — closing `Precedence4` [4] and additively
/// `expressions/string/{String8,String9,String10}` [8] (STARTS WITH/ENDS WITH/CONTAINS non-string
/// operands). Measured, zero regressions (full failure-set diff: 0 newly-failing scenarios; the net
/// +19 is purely additive).
///
/// `rmp` #123: **+5 EXISTS full-query scenarios** — `expressions/existentialSubqueries/`
/// `ExistentialSubquery2` [1][2] and `ExistentialSubquery3` [1][2][3] now pass (the full-query form
/// `EXISTS { MATCH ... RETURN ... }`, correlated and read-only, with aggregation and nesting);
/// `ExistentialSubquery2` [3] remains a compile-time `InvalidClauseComposition` rejection (a writing
/// clause inside `EXISTS`). Measured, zero regressions (failure-set diff: exactly the 5 scenarios
/// removed from the FAIL list, nothing added).
///
/// rmp #142 (null in SET/REMOVE): a `SET`/`REMOVE` whose target is a null entity (an `OPTIONAL MATCH`
/// that bound nothing) is now a silent no-op instead of a `TypeError`, lifting 3874 → 3881. Fixes the
/// 7 "Ignore null" scenarios `clauses/set/{Set1[8],Set3[8],Set4[5],Set5[1]}` and
/// `clauses/remove/{Remove1[5][6],Remove2[5]}`. Measured, zero regressions (failure-set diff: exactly
/// those 7 scenarios removed, nothing added).
///
/// rmp #143 (8 error type/phase/detail fixes), lifting 3881 → 3895. New compile-time validations:
/// mixing `UNION`/`UNION ALL` (`union/Union3` [1][2] → `InvalidClauseComposition`); `RETURN *` over
/// an empty scope (`return/Return7` [2] → new `NoVariablesInScope` detail), which also legalised
/// `WITH *` over an empty scope and fixed `create/Create3` [2] as a bonus; an unaliased aggregate in
/// `WITH` (`with/With4` [5] → `NoExpressionAlias`); aggregation inside a list comprehension
/// (`list/List12` [7] → `InvalidAggregation`); `size()` on a path (`list/List6` [5] →
/// `InvalidArgumentType`); a bare node pattern as a `WHERE` predicate (`pattern/Pattern1` [11] →
/// `InvalidArgumentType`); a parameter as a `MATCH` inline predicate (`match/Match1` [6],
/// `match/Match2` [8] → `InvalidParameterUse`). One runtime fix: `range()` step `0`
/// (`list/List11` [4], 4 outline rows → `ArgumentError`/`NumberOutOfRange`). Measured, zero
/// regressions (failure-set identity diff: 0 newly-failing scenarios). `create/Create3` [3] remains a
/// residual failure — a pre-existing `WITH *` over-empty-scope cardinality bug, now surfaced honestly
/// instead of masked by the former erroneous rejection.
///
/// rmp #145 (five graphus-cypher fixes), lifting 3895 → 3907. First, access to an entity deleted
/// earlier in the same query: `id`/`type` survive, but a property/label read raises `EntityNotFound`/
/// `DeletedEntityAccess` (`return/Return2` [14]/[15]/[16]/[17]) — a new `entity_deleted_by_txn` seam
/// plus `rel_data_including_deleted`. Second, `ORDER BY` across distinct value types now follows the
/// full CIP total order at the `RowValue` level (structural Node/Rel/Path interleaved with the property
/// classes; `return/ReturnOrderBy1` [11]/[12]). Third, a label predicate on a relationship checks its
/// type (`expressions/graph/Graph5` [2]). Fourth, `null`/`true`/`false` accepted as map/property key
/// names, preserving source spelling so `null` and `NULL` stay distinct (`expressions/map/Map1` [5],
/// `Map2` [5]). Fifth, the two-stage `MATCH () CREATE () WITH * MATCH () CREATE ()` now gives the
/// correct +10 via paired `Eager` barriers (a write-bearing `Apply` left plus a graph-reading `CREATE`
/// input), fixing the `create/Create3` [3] residual above. Measured, zero regressions (failure-set
/// identity diff: 0 newly-failing scenarios). Sixth, the statement clock seam (`rmp` task #140)
/// wired the zero-argument current-instant temporal constructors (`date()`, `time()`, `datetime()`,
/// `localtime()`, `localdatetime()`), flipping `expressions/temporal/Temporal10` [12] "Should
/// compute durations with no difference" to pass (+5 scenarios, zero regressions). Seventh, the
/// `Date` `i32`→`i64` widening (`rmp` task #141) lets dates span the full openCypher year range
/// `±999_999_999`, and `parse_local_date_time` now defaults a date-only string to midnight; this
/// flips `expressions/temporal/Temporal10` [9] "Should handle large durations" and [10] "...in
/// seconds" to pass (+2 scenarios, zero regressions) — reaching **100%** of the harnessed suite.
const BASELINE: usize = 3914;

/// Recursively collects every `*.feature` file under `root`, returning `(absolute_path,
/// path_relative_to_root)` pairs sorted for a stable run order.
fn discover_features(root: &Path) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    collect(root, root, &mut out);
    out.sort_by(|a, b| a.1.cmp(&b.1));
    out
}

/// Depth-first directory walk gathering feature files.
fn collect(dir: &Path, root: &Path, out: &mut Vec<(PathBuf, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, root, out);
        } else if path.extension().is_some_and(|e| e == "feature") {
            if let Ok(rel) = path.strip_prefix(root) {
                out.push((path.clone(), rel.to_string_lossy().replace('\\', "/")));
            }
        }
    }
}

#[test]
fn tck_conformance() {
    // `rmp` task #339: optionally run the whole TCK under the morsel-parallelism knob, so conformance is
    // proven identical with morsel intra-query parallelism enabled (`GRAPHUS_MORSEL_PARALLELISM=16`) and
    // with it off (unset / `=1`). The morsel tier only engages above 50k label-rows, which no TCK
    // scenario reaches, so the result is identical either way — this hook makes that explicit and
    // testable end-to-end through the production seam.
    if let Some(n) = std::env::var("GRAPHUS_MORSEL_PARALLELISM")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
    {
        graphus_cypher::morsel::set_morsel_threads(n);
    }

    let root = graphus_tck::tck_root();
    let features_dir = root.join("features");
    let graphs_dir = root.join("graphs");

    assert!(
        features_dir.is_dir(),
        "TCK features directory not found at {} — is the corpus vendored?",
        features_dir.display()
    );

    let mut features = discover_features(&features_dir);
    assert!(
        !features.is_empty(),
        "no .feature files discovered under {}",
        features_dir.display()
    );

    // Optional triage filter: `TCK_ONLY=expressions/mathematical` restricts the run to features
    // whose relative path contains the substring. It does not affect the committed run (the env var
    // is unset there) but makes drilling into one category fast during development.
    if let Ok(filter) = std::env::var("TCK_ONLY") {
        if !filter.is_empty() {
            features.retain(|(_, rel)| rel.contains(&filter));
            eprintln!("TCK_ONLY={filter}: {} feature(s) selected", features.len());
        }
    }

    let mut report = Report::new();
    let mut feature_parse_failures = 0usize;

    // Optional full dump: `TCK_DUMP=/path/to/file` writes every failure/error/unsupported outcome
    // (uncapped) for offline triage. Unset in the committed run.
    let mut dump = String::new();
    let dump_path = std::env::var("TCK_DUMP").ok().filter(|p| !p.is_empty());

    for (path, rel) in &features {
        let scenarios = match load_feature(path, rel) {
            Ok(s) => s,
            Err(e) => {
                // A feature file that does not parse is itself a harness/corpus problem, not an
                // engine result; count it but do not abort the run.
                eprintln!("WARN: could not parse feature {rel}: {e}");
                feature_parse_failures += 1;
                continue;
            }
        };
        for scenario in &scenarios {
            let outcome = run_scenario(scenario, &graphs_dir);
            if dump_path.is_some() {
                use std::fmt::Write as _;
                // Flatten any multi-line reason to a single TSV line so the dump stays grep-able.
                let line = |tag: &str, reason: &str| {
                    format!(
                        "{tag}\t{rel}\t{}\t{}\n",
                        scenario.name,
                        reason.replace('\n', " ⏎ ")
                    )
                };
                match &outcome {
                    graphus_tck::runner::Outcome::Passed => {}
                    graphus_tck::runner::Outcome::Failed(r) => {
                        let _ = dump.write_str(&line("FAIL", r));
                    }
                    graphus_tck::runner::Outcome::Errored(r) => {
                        let _ = dump.write_str(&line("ERR", r));
                    }
                    graphus_tck::runner::Outcome::Unsupported(r) => {
                        let _ = dump.write_str(&line("UNSUP", r));
                    }
                }
            }
            report.record(scenario.category(), &scenario.name, &outcome);
        }
    }

    if let Some(path) = &dump_path {
        std::fs::write(path, &dump).expect("write TCK_DUMP file");
        eprintln!("TCK_DUMP written to {path}");
    }

    // Print the full report (visible with `-- --nocapture`).
    println!("{}", report.render(BASELINE));
    println!(
        "TCK: {}/{} ({:.2}%) — baseline {BASELINE}",
        report.overall.passed,
        report.total(),
        report.pass_rate()
    );
    if feature_parse_failures > 0 {
        println!("WARN: {feature_parse_failures} feature file(s) failed to parse");
    }

    // The ratchet: never regress below the measured baseline.
    assert!(
        report.overall.passed >= BASELINE,
        "TCK regression: {} scenarios passed, but the baseline is {BASELINE}. \
         Investigate the drop (a real regression) before lowering the baseline.",
        report.overall.passed
    );
}
