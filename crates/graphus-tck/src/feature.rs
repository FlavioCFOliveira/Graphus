//! The Gherkin model: parse a `.feature` file, expand `Scenario Outline` / `Examples`, and classify
//! each step into the TCK step vocabulary (`tck/README.adoc` §"Format of a TCK scenario").
//!
//! # Outline expansion is ours to do
//!
//! The `gherkin` crate parses an `Examples:` table but does **not** substitute its rows into the
//! steps. The TCK relies heavily on `Scenario Outline` (e.g. one outline with a 7-row `Examples`
//! becomes 7 concrete scenarios), so `expand_scenario` performs the substitution: for each
//! `Examples` row it replaces every `<column>` placeholder in each step's text, docstring and table
//! cells with that row's value, producing one [`Scenario`] per row. A scenario with no examples runs
//! once verbatim.
//!
//! # Step classification
//!
//! The corpus uses a small, fixed set of step phrasings (confirmed by scanning all 220 files). Each
//! is mapped to one [`StepKind`]; an unrecognised phrasing becomes [`StepKind::Unsupported`] carrying
//! the raw text, so the runner can mark the scenario `Unsupported` and the report can list exactly
//! which forms appeared (never silently dropped).

use std::path::Path;

use gherkin::{GherkinEnv, StepType};

use crate::value::{ExpectedValue, parse_expected};

/// A fully-expanded TCK scenario: a flat list of classified [`Step`]s with the originating feature
/// path and scenario name (for diagnostics and the per-category breakdown).
#[derive(Debug, Clone)]
pub struct Scenario {
    /// The feature file this scenario came from, relative to `tck/features` (drives the category
    /// breakdown — the first path component, e.g. `clauses` / `expressions` / `useCases`).
    pub feature_rel: String,
    /// The scenario name (after outline expansion, the outline name is reused for every row).
    pub name: String,
    /// The classified steps, in order.
    pub steps: Vec<Step>,
}

impl Scenario {
    /// The top-level corpus category: the first path component of [`Self::feature_rel`]
    /// (`clauses` / `expressions` / `useCases`), or `"<root>"` if the path has none.
    #[must_use]
    pub fn category(&self) -> &str {
        self.feature_rel
            .split(['/', '\\'])
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("<root>")
    }
}

/// One classified TCK step.
#[derive(Debug, Clone)]
pub struct Step {
    /// What the step asks the harness to do.
    pub kind: StepKind,
    /// The raw step text (`Given …` value, without the keyword), kept for diagnostics.
    pub raw: String,
}

/// A two-column TCK data table (parameters, side effects) as `(key, value)` rows, header dropped.
pub type KvRows = Vec<(String, String)>;

/// A `there exists a procedure …` step: the raw signature text (everything after the phrase, e.g.
/// `test.my.proc(in :: INTEGER?) :: (out :: STRING?)`) plus the fixture table — its header (the
/// input names followed by the output names) and its raw-cell data rows. Structured parsing into a
/// procedure registration lives in [`crate::procedures`].
#[derive(Debug, Clone, Default)]
pub struct ProcedureStep {
    /// The raw signature text, trailing colon stripped.
    pub signature: String,
    /// The fixture-table header (input names then output names); empty for a no-field signature.
    pub header: Vec<String>,
    /// The fixture-table data rows (raw TCK mini-language cells).
    pub rows: Vec<Vec<String>>,
}

/// A result table: the header (column names) and the data rows (each a vector of raw cell strings).
#[derive(Debug, Clone, Default)]
pub struct ResultTable {
    /// The column names from the header row.
    pub header: Vec<String>,
    /// The data rows (each cell is the raw expected-value text, parsed lazily by [`crate::compare`]).
    pub rows: Vec<Vec<String>>,
}

/// The classified meaning of a TCK step.
#[derive(Debug, Clone)]
pub enum StepKind {
    /// `Given an empty graph` — start from an empty graph (the default).
    EmptyGraph,
    /// `Given any graph` — any initial graph is acceptable; the harness uses an empty one.
    AnyGraph,
    /// `Given the <name> graph` — seed from a TCK named graph (`binary-tree-1` / `-2` / `yago`).
    NamedGraph(String),
    /// `And having executed:` / `And after having executed:` — an initialisation query (docstring)
    /// run and committed before the query under test.
    InitQuery(String),
    /// `And parameters are:` — the parameter table for the query under test.
    Parameters(KvRows),
    /// `And there exists a procedure <signature>:` — registers a scenario-local fixture procedure
    /// (`tck/features/clauses/call/**`). Carries the raw signature text and the fixture data table
    /// (header = input names then output names; rows in the TCK value mini-language), parsed into
    /// an engine registration by [`crate::procedures`].
    Procedure(ProcedureStep),
    /// `When executing query:` — the query under test (docstring, or inline after the colon).
    Query(String),
    /// `Then the result should be, in any order:` — an unordered (bag) result-set assertion.
    ResultUnordered(ResultTable),
    /// `Then the result should be, in order:` — an ordered (positional) result-set assertion.
    ResultOrdered(ResultTable),
    /// `Then the result should be empty` — zero rows expected.
    ResultEmpty,
    /// `Then a <TYPE> should be raised at <PHASE>: <DETAIL>` — an error assertion.
    Error {
        /// The TCK error type name (e.g. `SyntaxError`, `TypeError`).
        error_type: String,
        /// The TCK phase (`compile time` / `runtime` / `any time`).
        phase: String,
        /// The fine-grained detail (e.g. `UndefinedVariable`).
        detail: String,
    },
    /// `And the side effects should be:` — the expected side-effect counters.
    SideEffects(KvRows),
    /// `And no side effects` — all side-effect counters are zero.
    NoSideEffects,
    /// A step form the harness does not implement (carries the raw text for the report).
    Unsupported(String),
}

/// Parses and outline-expands every scenario in a `.feature` file at `path`.
///
/// `feature_rel` is the path **relative to `tck/features`**, recorded on each [`Scenario`] for the
/// category breakdown.
///
/// # Errors
///
/// Returns the `gherkin` parse error message if the file is not a well-formed feature file.
pub fn load_feature(path: &Path, feature_rel: &str) -> Result<Vec<Scenario>, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    load_feature_str(&text, feature_rel)
}

/// Parses and outline-expands every scenario in feature-file `text` (used by tests and by
/// [`load_feature`]).
///
/// # Errors
///
/// Returns the `gherkin` parse error message if `text` is not a well-formed feature file.
pub fn load_feature_str(text: &str, feature_rel: &str) -> Result<Vec<Scenario>, String> {
    let sanitized = sanitize_table_escapes(text);
    let feature = gherkin::Feature::parse(&sanitized, GherkinEnv::default())
        .map_err(|e| format!("parse {feature_rel}: {e}"))?;

    let mut out = Vec::new();
    // A feature-level `Background:` block runs before **every** scenario (Cucumber/Gherkin
    // semantics); the openCypher TCK uses it to seed the graph (`Given an empty graph` + one or more
    // `And having executed:` CREATE steps). Its steps are parsed by gherkin into `feature.background`
    // — *separate* from each scenario's own steps — so they must be prepended to every scenario, or
    // the setup is silently lost and every query runs against an empty graph.
    let feature_bg: &[gherkin::Step] = feature
        .background
        .as_ref()
        .map_or(&[], |bg| bg.steps.as_slice());

    // Scenarios may live directly on the feature or be grouped under rules; walk both so none are
    // missed (the gherkin model exposes rule-grouped scenarios separately).
    for sc in &feature.scenarios {
        out.extend(expand_scenario(sc, feature_bg, feature_rel));
    }
    for rule in &feature.rules {
        // A `Rule:` may carry its own `Background:` that runs *after* the feature background for the
        // scenarios under that rule (Gherkin semantics). Concatenate feature-then-rule background.
        let mut rule_bg: Vec<gherkin::Step> = feature_bg.to_vec();
        if let Some(bg) = rule.background.as_ref() {
            rule_bg.extend(bg.steps.iter().cloned());
        }
        for sc in &rule.scenarios {
            out.extend(expand_scenario(sc, &rule_bg, feature_rel));
        }
    }
    Ok(out)
}

/// Normalises data-table cell backslash escapes so the `gherkin` 0.16 parser accepts the full
/// openCypher TCK corpus without touching the vendored `.feature` files.
///
/// # Why this exists
///
/// The official Gherkin data-table grammar treats a backslash inside a cell as an escape lead-in:
/// `\\` → `\`, `\|` → `|`, `\n` → newline, and — per the reference Cucumber implementations — **any
/// other** `\x` passes through verbatim as a literal backslash followed by `x`. The `gherkin` 0.16
/// PEG (`src/parser.rs`, rule `escaped_cell_char`) only implements the first three and has no
/// fall-through: a `\` that is not part of `\\`/`\|`/`\n` matches no alternative, the cell repetition
/// stops early, and the row's closing `|` is never found — surfacing as a misleading
/// `"unknown keyword"` error on the *next* line.
///
/// Two cells in `expressions/literals/Literals6.feature` hit this (`| '\'' |` and the escaped-char
/// cell), which capped TCK conformance by dropping all 13 of that file's scenarios. A corpus-wide
/// scan confirms these are the only two affected cells today, but this normalisation is written for
/// the whole corpus so any future vendored cell behaves identically.
///
/// # The transformation (and why it is faithful)
///
/// On data-table rows only (a line whose first non-whitespace byte is `|`, and which is **not**
/// inside a `"""`/```` ``` ```` docstring — docstrings are captured verbatim by gherkin and must not
/// be altered), every backslash that is **not** the lead byte of a `\\`, `\|`, or `\n` escape is
/// doubled to `\\`. gherkin then unescapes that `\\` back to a single `\`, reproducing exactly the
/// spec's "unknown escape passes through as a literal backslash" behaviour. Recognised escapes
/// (`\\`, `\|`, `\n`) are left untouched, so gherkin's own unescaping is preserved bit-for-bit; the
/// transformation is therefore a no-op for every cell that already parses.
///
/// The cell string the harness ultimately compares (`crate::value::parse_expected`, which itself
/// decodes the TCK mini-language escapes such as `\'`) receives precisely the spec-correct
/// table-unescaped text — verified by round-tripping both affected cells through `sanitize` followed
/// by gherkin's unescaping (see the unit tests below).
fn sanitize_table_escapes(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 16);
    // Track docstring state so table-shaped lines inside a `"""` / ``` block are left verbatim.
    let mut in_docstring = false;
    let mut fence: &str = "";

    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if in_docstring {
            if trimmed.starts_with(fence) {
                in_docstring = false;
            }
            out.push_str(line);
            continue;
        }
        if trimmed.starts_with("\"\"\"") {
            in_docstring = true;
            fence = "\"\"\"";
            out.push_str(line);
            continue;
        }
        if trimmed.starts_with("```") {
            in_docstring = true;
            fence = "```";
            out.push_str(line);
            continue;
        }
        if trimmed.starts_with('|') {
            sanitize_table_line(line, &mut out);
        } else {
            out.push_str(line);
        }
    }
    out
}

/// Appends `line` (a data-table row) to `out`, doubling every backslash that does not lead a
/// gherkin-recognised `\\`, `\|`, or `\n` escape (see [`sanitize_table_escapes`]).
fn sanitize_table_line(line: &str, out: &mut String) {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            match bytes.get(i + 1) {
                // A recognised escape: copy both bytes unchanged.
                Some(b'\\') | Some(b'|') | Some(b'n') => {
                    out.push('\\');
                    out.push(bytes[i + 1] as char);
                    i += 2;
                    continue;
                }
                // Unknown escape (or trailing backslash): double it so gherkin unescapes it back to
                // a single literal backslash.
                _ => {
                    out.push_str("\\\\");
                    i += 1;
                    continue;
                }
            }
        }
        // A run of non-backslash bytes: copy it verbatim. `\` (0x5C) is ASCII and can never appear
        // as a UTF-8 lead or continuation byte, so a `b'\\'` match only ever lands on a char
        // boundary — `&line[start..i]` is therefore always a valid slice and multi-byte characters
        // stay intact.
        let start = i;
        i += 1;
        while i < bytes.len() && bytes[i] != b'\\' {
            i += 1;
        }
        out.push_str(&line[start..i]);
    }
}

/// Expands one `gherkin::Scenario` into one-or-more concrete [`Scenario`]s.
///
/// With no `Examples`, the scenario is classified once verbatim. With one or more `Examples` blocks,
/// each data row produces one concrete scenario whose steps have had every `<column>` placeholder
/// substituted by that row's value (`tck/README.adoc`: the outline is expanded per Examples row).
fn expand_scenario(
    sc: &gherkin::Scenario,
    background: &[gherkin::Step],
    feature_rel: &str,
) -> Vec<Scenario> {
    // Background steps run first, then the scenario's own steps (Gherkin semantics).
    let all_steps = || background.iter().chain(sc.steps.iter());

    let substitutions = examples_rows(sc);
    if substitutions.is_empty() {
        return vec![Scenario {
            feature_rel: feature_rel.to_owned(),
            name: sc.name.clone(),
            steps: all_steps().map(classify_step).collect(),
        }];
    }

    substitutions
        .into_iter()
        .map(|row| {
            let steps = all_steps()
                .map(|st| classify_step(&substitute_step(st, &row)))
                .collect();
            Scenario {
                feature_rel: feature_rel.to_owned(),
                name: sc.name.clone(),
                steps,
            }
        })
        .collect()
}

/// All `Examples` data rows as `(column → value)` maps, across every `Examples` block of `sc`.
///
/// Each block's first table row is its header; subsequent rows are data. Multiple blocks (rare in
/// the corpus) are simply concatenated — each produces its own concrete scenarios.
fn examples_rows(sc: &gherkin::Scenario) -> Vec<Vec<(String, String)>> {
    let mut rows = Vec::new();
    for ex in &sc.examples {
        let Some(table) = ex.table.as_ref() else {
            continue;
        };
        let Some((header, data)) = table.rows.split_first() else {
            continue;
        };
        for data_row in data {
            let mapping: Vec<(String, String)> = header
                .iter()
                .cloned()
                .zip(data_row.iter().cloned())
                .collect();
            rows.push(mapping);
        }
    }
    rows
}

/// A `gherkin::Step` with every `<col>` placeholder substituted from one Examples row (in `value`,
/// `docstring`, and every table cell).
fn substitute_step(step: &gherkin::Step, row: &[(String, String)]) -> gherkin::Step {
    let mut next = step.clone();
    next.value = substitute(&next.value, row);
    if let Some(doc) = next.docstring.as_mut() {
        *doc = substitute(doc, row);
    }
    if let Some(table) = next.table.as_mut() {
        for r in &mut table.rows {
            for cell in r.iter_mut() {
                *cell = substitute(cell, row);
            }
        }
    }
    next
}

/// Replaces every `<column>` occurrence in `text` with its Examples-row value.
fn substitute(text: &str, row: &[(String, String)]) -> String {
    let mut out = text.to_owned();
    for (col, val) in row {
        let needle = format!("<{col}>");
        if out.contains(&needle) {
            out = out.replace(&needle, val);
        }
    }
    out
}

/// Maps one parsed `gherkin::Step` onto its [`StepKind`].
///
/// The match is on the normalised step text (the keyword is dropped by gherkin into
/// [`gherkin::Step::value`]); the `ty` ([`StepType`]) only disambiguates a couple of borderline
/// phrasings. Anything unrecognised becomes [`StepKind::Unsupported`] with the raw text.
fn classify_step(step: &gherkin::Step) -> Step {
    let value = step.value.trim();
    let docstring = step.docstring.as_deref().map(str::trim);
    let kind = classify(value, docstring, step.table.as_ref(), step.ty);
    Step {
        kind,
        raw: value.to_owned(),
    }
}

/// The classification core, separated so it is unit-testable without a `gherkin::Step`.
fn classify(
    value: &str,
    docstring: Option<&str>,
    table: Option<&gherkin::Table>,
    ty: StepType,
) -> StepKind {
    // ---- Given (initial graph) ------------------------------------------------------------------
    if value == "an empty graph" {
        return StepKind::EmptyGraph;
    }
    if value == "any graph" {
        return StepKind::AnyGraph;
    }
    if let Some(name) = value
        .strip_prefix("the ")
        .and_then(|s| s.strip_suffix(" graph"))
    {
        return StepKind::NamedGraph(name.to_owned());
    }

    // ---- initialisation query (docstring) -------------------------------------------------------
    if value == "having executed:" || value == "after having executed:" {
        return docstring.map_or_else(
            || StepKind::Unsupported("having executed: <missing docstring>".to_owned()),
            |q| StepKind::InitQuery(q.to_owned()),
        );
    }

    // ---- parameters -----------------------------------------------------------------------------
    if value == "parameters are:" || value == "parameter values are:" {
        return table.map_or_else(
            || StepKind::Unsupported("parameters are: <missing table>".to_owned()),
            |t| StepKind::Parameters(kv_rows(t)),
        );
    }

    // ---- fixture procedures (`tck/features/clauses/call/**`) -------------------------------------
    if let Some(sig) = value.strip_prefix("there exists a procedure ") {
        return StepKind::Procedure(procedure_step(sig, table));
    }

    // ---- query under test -----------------------------------------------------------------------
    // The query is normally a docstring (`When executing query:` + `"""…"""`); the README also shows
    // a one-line inline form (`When executing query: <query>`), so accept that fallback too.
    if value == "executing query:" || value == "executing control query:" {
        return docstring.map_or_else(
            || StepKind::Unsupported("executing query: <missing docstring>".to_owned()),
            |q| StepKind::Query(q.to_owned()),
        );
    }
    if let Some(inline) = value.strip_prefix("executing query:") {
        let inline = inline.trim();
        if !inline.is_empty() {
            return StepKind::Query(inline.to_owned());
        }
    }

    // ---- result-set assertions ------------------------------------------------------------------
    if value == "the result should be empty" {
        return StepKind::ResultEmpty;
    }
    // The "(ignoring element order for lists)" variants relax list-element order; we treat them as
    // their base ordered/unordered kind for the row-level comparison (a documented, conservative
    // approximation — see `compare`).
    if value.starts_with("the result should be, in order") {
        return table.map_or(StepKind::ResultEmpty, |t| {
            StepKind::ResultOrdered(result_table(t))
        });
    }
    if value.starts_with("the result should be, in any order")
        || value.starts_with("the result should be (ignoring element order for lists)")
    {
        return table.map_or(StepKind::ResultEmpty, |t| {
            StepKind::ResultUnordered(result_table(t))
        });
    }

    // ---- error assertions -----------------------------------------------------------------------
    if let Some(err) = parse_error_step(value) {
        return err;
    }

    // ---- side effects ---------------------------------------------------------------------------
    if value == "no side effects" {
        return StepKind::NoSideEffects;
    }
    if value == "the side effects should be:" {
        return table.map_or(StepKind::NoSideEffects, |t| {
            StepKind::SideEffects(kv_rows(t))
        });
    }

    let _ = ty;
    StepKind::Unsupported(value.to_owned())
}

/// Parses a `a <TYPE> should be raised at <PHASE>: <DETAIL>` step (the only error phrasing the TCK
/// uses), returning `None` for any other text.
fn parse_error_step(value: &str) -> Option<StepKind> {
    let rest = value
        .strip_prefix("a ")
        .or_else(|| value.strip_prefix("an "))?;
    let (error_type, rest) = rest.split_once(" should be raised at ")?;
    let (phase, detail) = match rest.split_once(':') {
        Some((p, d)) => (p.trim(), d.trim()),
        // Some steps omit the detail (rare); keep an empty detail.
        None => (rest.trim(), ""),
    };
    Some(StepKind::Error {
        error_type: error_type.trim().to_owned(),
        phase: phase.to_owned(),
        detail: detail.to_owned(),
    })
}

/// A two-column TCK key/value table as `(key, value)` pairs.
///
/// TCK parameter and side-effect tables have **no header row** — every row is data (e.g.
/// `| +nodes | 1 |`, `| param | 0 |`), confirmed across the corpus. So unlike a result table, no row
/// is dropped here.
fn kv_rows(table: &gherkin::Table) -> KvRows {
    table
        .rows
        .iter()
        .filter_map(|r| match r.as_slice() {
            [k, v, ..] => Some((k.trim().to_owned(), v.trim().to_owned())),
            _ => None,
        })
        .collect()
}

/// Builds a [`ProcedureStep`] from the raw signature text and the fixture table.
///
/// The signature keeps its raw text (trailing `:` and whitespace stripped; structured parsing is
/// [`crate::procedures`]'s job). The table's first row is the header (input then output names); a
/// void signature (`() :: ()`) is written in the corpus with a single empty table line, which
/// gherkin yields as one empty-cell row — normalised here to an empty header and no rows.
fn procedure_step(signature: &str, table: Option<&gherkin::Table>) -> ProcedureStep {
    let signature = signature.trim().trim_end_matches(':').trim().to_owned();
    let (header, rows) = match table {
        Some(t) => {
            let mut iter = t.rows.iter();
            let header: Vec<String> = iter
                .next()
                .map(|h| {
                    h.iter()
                        .map(|c| c.trim().to_owned())
                        .filter(|c| !c.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            let rows = iter
                .map(|r| r.iter().map(|c| c.trim().to_owned()).collect())
                .collect();
            (header, rows)
        }
        None => (Vec::new(), Vec::new()),
    };
    ProcedureStep {
        signature,
        header,
        rows,
    }
}

/// A result table: header row + data rows of raw cell strings.
fn result_table(table: &gherkin::Table) -> ResultTable {
    let mut iter = table.rows.iter();
    let header = iter
        .next()
        .map(|h| h.iter().map(|c| c.trim().to_owned()).collect())
        .unwrap_or_default();
    let rows = iter
        .map(|r| r.iter().map(|c| c.trim().to_owned()).collect())
        .collect();
    ResultTable { header, rows }
}

/// Parses every cell of a [`ResultTable`] row into [`ExpectedValue`]s, in column order.
///
/// # Errors
///
/// Returns a per-cell error describing the column and the parse failure if any cell is not a
/// well-formed expected value (`tck/README.adoc` mini-language).
pub fn parse_row(header: &[String], row: &[String]) -> Result<Vec<ExpectedValue>, String> {
    row.iter()
        .enumerate()
        .map(|(i, cell)| {
            parse_expected(cell).map_err(|e| {
                let col = header.get(i).map(String::as_str).unwrap_or("?");
                format!("column `{col}` cell {cell:?}: {e}")
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(text: &str) -> Vec<Scenario> {
        load_feature_str(text, "clauses/test/T.feature").expect("parse feature")
    }

    #[test]
    fn classifies_a_simple_scenario() {
        let f = "Feature: F\n\n  Scenario: S\n\
                 \x20   Given an empty graph\n\
                 \x20   And having executed:\n      \"\"\"\n      CREATE ()\n      \"\"\"\n\
                 \x20   When executing query:\n      \"\"\"\n      MATCH (n) RETURN n\n      \"\"\"\n\
                 \x20   Then the result should be, in any order:\n      | n  |\n      | () |\n\
                 \x20   And no side effects\n";
        let scs = one(f);
        assert_eq!(scs.len(), 1);
        let kinds: Vec<_> = scs[0].steps.iter().map(|s| &s.kind).collect();
        assert!(matches!(kinds[0], StepKind::EmptyGraph));
        assert!(matches!(kinds[1], StepKind::InitQuery(q) if q == "CREATE ()"));
        assert!(matches!(kinds[2], StepKind::Query(q) if q.contains("MATCH (n) RETURN n")));
        assert!(matches!(kinds[3], StepKind::ResultUnordered(t) if t.header == ["n"]));
        assert!(matches!(kinds[4], StepKind::NoSideEffects));
        assert_eq!(scs[0].category(), "clauses");
    }

    #[test]
    fn classifies_an_error_scenario() {
        let f = "Feature: F\n\n  Scenario: S\n\
                 \x20   Given any graph\n\
                 \x20   When executing query:\n      \"\"\"\n      MATCH () RETURN foo\n      \"\"\"\n\
                 \x20   Then a SyntaxError should be raised at compile time: UndefinedVariable\n";
        let scs = one(f);
        let StepKind::Error {
            error_type,
            phase,
            detail,
        } = &scs[0].steps[2].kind
        else {
            panic!("expected an Error step, got {:?}", scs[0].steps[2].kind);
        };
        assert_eq!(error_type, "SyntaxError");
        assert_eq!(phase, "compile time");
        assert_eq!(detail, "UndefinedVariable");
    }

    #[test]
    fn expands_an_outline_into_one_scenario_per_row() {
        let f = "Feature: F\n\n  Scenario Outline: S\n\
                 \x20   Given any graph\n\
                 \x20   When executing query:\n      \"\"\"\n      RETURN <expr> AS r\n      \"\"\"\n\
                 \x20   Then the result should be, in any order:\n      | r     |\n      | <res> |\n\
                 \x20   Examples:\n      | expr | res |\n      | 1+1  | 2   |\n      | 2*3  | 6   |\n";
        let scs = one(f);
        assert_eq!(scs.len(), 2, "two Examples rows -> two scenarios");
        // Row 0: RETURN 1+1 AS r, expecting 2.
        assert!(matches!(&scs[0].steps[1].kind, StepKind::Query(q) if q.contains("1+1")));
        assert!(
            matches!(&scs[0].steps[2].kind, StepKind::ResultUnordered(t) if t.rows[0][0] == "2")
        );
        // Row 1: RETURN 2*3 AS r, expecting 6.
        assert!(matches!(&scs[1].steps[1].kind, StepKind::Query(q) if q.contains("2*3")));
        assert!(
            matches!(&scs[1].steps[2].kind, StepKind::ResultUnordered(t) if t.rows[0][0] == "6")
        );
    }

    /// A feature-level `Background:` block must be prepended to **every** scenario's steps — its
    /// `Given`/`And having executed:` seed steps run before the scenario's own steps. Regression for
    /// `rmp` #125: the background was parsed by gherkin into `feature.background` and silently dropped,
    /// so every scenario ran against an empty graph (e.g. `clauses/match/Match5.feature` — the corpus's
    /// sole `Background:` user — returned 0 rows for all 26 variable-length scenarios).
    #[test]
    fn background_steps_are_prepended_to_every_scenario() {
        let f = "Feature: F\n\n  Background:\n\
                 \x20   Given an empty graph\n\
                 \x20   And having executed:\n      \"\"\"\n      CREATE (:A)\n      \"\"\"\n\n\
                 \x20 Scenario: S1\n\
                 \x20   When executing query:\n      \"\"\"\n      MATCH (n) RETURN n\n      \"\"\"\n\
                 \x20   Then the result should be, in any order:\n      | n    |\n      | (:A) |\n\
                 \x20   And no side effects\n\n\
                 \x20 Scenario: S2\n\
                 \x20   When executing query:\n      \"\"\"\n      MATCH (n) RETURN count(*) AS c\n      \"\"\"\n\
                 \x20   Then the result should be, in any order:\n      | c |\n      | 1 |\n\
                 \x20   And no side effects\n";
        let scs = one(f);
        assert_eq!(scs.len(), 2, "two scenarios under one background");
        for sc in &scs {
            // Each scenario starts with the two background steps, then its own When/Then/AndNoSideEffects.
            assert!(
                matches!(sc.steps[0].kind, StepKind::EmptyGraph),
                "background `Given an empty graph` must lead, got {:?}",
                sc.steps[0].kind
            );
            assert!(
                matches!(&sc.steps[1].kind, StepKind::InitQuery(q) if q == "CREATE (:A)"),
                "background `having executed:` must follow, got {:?}",
                sc.steps[1].kind
            );
            assert!(
                matches!(&sc.steps[2].kind, StepKind::Query(_)),
                "the scenario's own `When` follows the background, got {:?}",
                sc.steps[2].kind
            );
        }
    }

    /// A `Scenario Outline` under a `Background:` gets the background prepended to **each** expanded
    /// row's scenario (the background runs once per concrete scenario).
    #[test]
    fn background_is_prepended_to_each_outline_row() {
        let f = "Feature: F\n\n  Background:\n\
                 \x20   Given an empty graph\n\n\
                 \x20 Scenario Outline: S\n\
                 \x20   When executing query:\n      \"\"\"\n      RETURN <expr> AS r\n      \"\"\"\n\
                 \x20   Then the result should be, in any order:\n      | r     |\n      | <res> |\n\
                 \x20   Examples:\n      | expr | res |\n      | 1+1  | 2   |\n      | 2*3  | 6   |\n";
        let scs = one(f);
        assert_eq!(scs.len(), 2, "two Examples rows -> two scenarios");
        for sc in &scs {
            assert!(
                matches!(sc.steps[0].kind, StepKind::EmptyGraph),
                "every outline row must carry the background first"
            );
        }
    }

    #[test]
    fn parameters_and_side_effects_tables() {
        let f = "Feature: F\n\n  Scenario: S\n\
                 \x20   Given an empty graph\n\
                 \x20   And parameters are:\n      | param | 0 |\n\
                 \x20   When executing query:\n      \"\"\"\n      CREATE ({p: $param})\n      \"\"\"\n\
                 \x20   Then the result should be empty\n\
                 \x20   And the side effects should be:\n      | +nodes | 1 |\n      | +properties | 1 |\n";
        let scs = one(f);
        assert!(
            matches!(&scs[0].steps[1].kind, StepKind::Parameters(p) if p == &[("param".to_owned(), "0".to_owned())])
        );
        assert!(matches!(&scs[0].steps[3].kind, StepKind::ResultEmpty));
        let StepKind::SideEffects(se) = &scs[0].steps[4].kind else {
            panic!("expected side effects");
        };
        assert_eq!(
            se,
            &[
                ("+nodes".to_owned(), "1".to_owned()),
                ("+properties".to_owned(), "1".to_owned())
            ]
        );
    }

    #[test]
    fn named_graph_is_recognised() {
        let f = "Feature: F\n\n  Scenario: S\n\
                 \x20   Given the binary-tree-1 graph\n\
                 \x20   When executing query:\n      \"\"\"\n      MATCH (n) RETURN count(n) AS c\n      \"\"\"\n\
                 \x20   Then the result should be, in any order:\n      | c  |\n      | 13 |\n";
        let scs = one(f);
        assert!(matches!(&scs[0].steps[0].kind, StepKind::NamedGraph(n) if n == "binary-tree-1"));
    }

    #[test]
    fn procedure_step_is_classified_with_signature_and_table() {
        let f = "Feature: F\n\n  Scenario: S\n\
                 \x20   Given an empty graph\n\
                 \x20   And there exists a procedure test.my.proc() :: (x :: INTEGER?):\n      | x |\n      | 1 |\n\
                 \x20   When executing query:\n      \"\"\"\n      RETURN 1 AS n\n      \"\"\"\n\
                 \x20   Then the result should be, in any order:\n      | n |\n      | 1 |\n";
        let scs = one(f);
        let StepKind::Procedure(p) = &scs[0].steps[1].kind else {
            panic!("expected a Procedure step, got {:?}", scs[0].steps[1].kind);
        };
        assert_eq!(p.signature, "test.my.proc() :: (x :: INTEGER?)");
        assert_eq!(p.header, ["x"]);
        assert_eq!(p.rows, [["1"]]);
    }

    /// Mirrors gherkin 0.16's data-table cell unescaping (`\\`→`\`, `\|`→`|`, `\n`→newline; every
    /// other byte verbatim) so a test can assert what the parser hands the harness.
    fn gherkin_cell_unescape(cell: &str) -> String {
        let b = cell.as_bytes();
        let mut out = String::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'\\' {
                match b.get(i + 1) {
                    Some(b'\\') => {
                        out.push('\\');
                        i += 2;
                        continue;
                    }
                    Some(b'|') => {
                        out.push('|');
                        i += 2;
                        continue;
                    }
                    Some(b'n') => {
                        out.push('\n');
                        i += 2;
                        continue;
                    }
                    _ => {}
                }
            }
            // Copy one whole UTF-8 char.
            let ch = cell[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
        out
    }

    #[test]
    fn sanitizer_is_a_noop_for_cells_without_unknown_escapes() {
        // A plain table and one using only recognised escapes must be returned byte-for-byte.
        let plain = "Feature: F\n  Scenario: S\n    Given an empty graph\n    Then the result should be, in any order:\n      | a | b |\n      | 1 | x |\n";
        assert_eq!(sanitize_table_escapes(plain), plain);
        let recognised = "      | a\\\\b | c\\|d |\n"; // cell text: a\\b , c\|d
        assert_eq!(sanitize_table_escapes(recognised), recognised);
    }

    #[test]
    fn sanitizer_rescues_unknown_escapes_to_a_literal_backslash() {
        // `\'` is not a gherkin escape; doubling the backslash makes gherkin unescape it back to a
        // single literal `\`, matching the spec's pass-through behaviour.
        let raw = "      | '\\''    |\n";
        let san = sanitize_table_escapes(raw);
        assert_eq!(san, "      | '\\\\''    |\n");
        // After gherkin's own unescaping, the cell content equals the original `'\''` — exactly what
        // `crate::value::parse_expected` expects to decode.
        assert_eq!(gherkin_cell_unescape("'\\\\''"), "'\\''");
    }

    #[test]
    fn sanitizer_leaves_docstrings_verbatim() {
        // A `\'` inside a query docstring must NOT be doubled (docstrings are captured verbatim by
        // gherkin and carry the query's own backslashes).
        let f = "Feature: F\n  Scenario: S\n    When executing query:\n      \"\"\"\n      RETURN '\\'' AS x\n      \"\"\"\n";
        let san = sanitize_table_escapes(f);
        assert!(
            san.contains("RETURN '\\'' AS x"),
            "docstring backslash must be preserved, got:\n{san}"
        );
        // And it does not accidentally double the docstring's backslash.
        assert!(!san.contains("RETURN '\\\\'' AS x"));
    }

    #[test]
    fn literals6_escaped_quote_cells_parse_and_carry_the_right_expected_value() {
        // The two cells that broke gherkin 0.16: a single escaped quote, and the escaped-characters
        // cell. Both must now parse, and the expected value must round-trip to `'`-decoded text.
        let f = "Feature: F\n  Scenario: S\n    Given any graph\n\
                 \x20   When executing query:\n      \"\"\"\n      RETURN '\\'' AS literal\n      \"\"\"\n\
                 \x20   Then the result should be, in any order:\n      | literal |\n      | '\\''    |\n\
                 \x20   And no side effects\n";
        let scs = one(f);
        assert_eq!(scs.len(), 1, "the escaped-quote scenario must parse");
        let StepKind::ResultUnordered(t) = &scs[0].steps[2].kind else {
            panic!("expected a result table, got {:?}", scs[0].steps[2].kind);
        };
        // The raw cell handed to the value parser is `'\''` (gherkin unescaped the doubled backslash).
        assert_eq!(t.rows[0][0], "'\\''");
        let parsed = crate::value::parse_expected(&t.rows[0][0]).expect("value parses");
        assert_eq!(parsed, crate::value::ExpectedValue::String("'".to_owned()));
    }

    #[test]
    fn unknown_step_form_is_unsupported_not_dropped() {
        let f = "Feature: F\n\n  Scenario: S\n\
                 \x20   Given an empty graph\n\
                 \x20   And some entirely novel step phrasing\n\
                 \x20   When executing query:\n      \"\"\"\n      RETURN 1 AS n\n      \"\"\"\n\
                 \x20   Then the result should be, in any order:\n      | n |\n      | 1 |\n";
        let scs = one(f);
        assert!(
            matches!(&scs[0].steps[1].kind, StepKind::Unsupported(t) if t.contains("novel")),
            "an unrecognised step keeps its raw text as Unsupported"
        );
    }
}
