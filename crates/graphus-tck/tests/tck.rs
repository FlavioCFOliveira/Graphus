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
/// scalars **and arrays** round-tripping through a node property) all pass. The 15 remaining
/// Temporal4 failures are one *honest engine gap*: scenario [13] uses the transaction-clock
/// constructors `date.transaction` / `date.statement` / `date.realtime` (and the `localtime` /
/// `time` / `localdatetime` / `datetime` equivalents), which the function registry does not yet
/// know (`unknown function …` at compile time) — input for a follow-up engine task, deliberately
/// left failing rather than masked.
const BASELINE: usize = 3589;

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
