//! Pattern-form `EXISTS { … }` / `COUNT { … }` and pattern-comprehension semantics (`rmp` task #869).
//!
//! The **pattern** form of `EXISTS { pattern }` / `COUNT { pattern }` is evaluated by the expression
//! interpreter (`eval::eval_exists_subquery` → `pattern_element_rows` → `match_chain`), while the
//! semantically identical **full-query** form (`EXISTS { MATCH pattern RETURN 1 }`) is compiled and
//! run by the real planner + executor. `EXISTS { pattern }` *is* `EXISTS { MATCH pattern }`
//! (openCypher), so the two spellings must agree on every input — and both must agree with the
//! by-hand expectation derived from the corpus below.
//!
//! Every test here is therefore a **differential oracle with an absolute anchor**: it asserts
//! `pattern-form == full-query-form` *and* `pattern-form == hand-computed value`, so "both wrong the
//! same way" cannot pass.
//!
//! # The two defects these tests pin (`rmp` #869)
//!
//! * **D1 — relationship isomorphism across comma-separated pattern parts.** One `MATCH` clause
//!   binds each relationship at most once across its *whole* pattern (`04 §2.4`). The interpreter
//!   used to restart the "already used" accumulator at every comma, so `(x)-[r1:T]->(), (x)-[r2:T]->()`
//!   matched a node with a *single* incident relationship by binding it to both `r1` and `r2`.
//! * **D2 — an undirected hop binding a self-loop twice.** `GraphAccess::expand` reports a self-loop
//!   once per matching side by contract; the executor deduplicates by relationship id, the
//!   interpreter did not, so `COUNT { (x)-[r:T]-(y) }` counted a lone self-loop as two matches.

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::MemGraph;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::semantics::analyze;

// =================================================================================================
// Corpus
// =================================================================================================

/// A corpus deliberately rich in the structures relationship isomorphism turns on.
///
/// Nodes (`n` is the identifying property; `a`..`e` carry `:P`, `f` carries `:R`):
///
/// | node | labels | notes                    |
/// |------|--------|--------------------------|
/// | `a`  | `P`    | two **parallel** `T` edges to `b` |
/// | `b`  | `P`    |                          |
/// | `c`  | `P`,`Q`| closes a 3-cycle back to `a` |
/// | `d`  | `P`    | a `T` **self-loop**, and nothing else |
/// | `e`  | `P`    | one `T` edge to `f`      |
/// | `f`  | `R`    | sink                     |
///
/// Relationships: `R1 = (a)-[:T]->(b)`, `R2 = (a)-[:T]->(b)` (parallel), `R3 = (b)-[:T]->(c)`,
/// `R4 = (c)-[:T]->(a)`, `R5 = (d)-[:T]->(d)` (self-loop), `R6 = (e)-[:T]->(f)`,
/// `R7 = (a)-[:U]->(c)`, `R8 = (c)-[:U]->(a)` (a 2-cycle on `U`).
fn corpus() -> MemGraph {
    let mut g = MemGraph::new();
    let a = g.add_node(
        ["P"],
        [("n", Value::String("a".into())), ("k", Value::Integer(1))],
    );
    let b = g.add_node(
        ["P"],
        [("n", Value::String("b".into())), ("k", Value::Integer(2))],
    );
    let c = g.add_node(
        ["P", "Q"],
        [("n", Value::String("c".into())), ("k", Value::Integer(3))],
    );
    let d = g.add_node(["P"], [("n", Value::String("d".into()))]); // no `k`
    let e = g.add_node(
        ["P"],
        [("n", Value::String("e".into())), ("k", Value::Null)],
    );
    let f = g.add_node(
        ["R"],
        [("n", Value::String("f".into())), ("k", Value::Integer(9))],
    );

    g.add_rel("T", a, b, [("w", Value::Integer(1))]); // R1
    g.add_rel("T", a, b, [("w", Value::Integer(2))]); // R2 (parallel with R1)
    g.add_rel("T", b, c, [("w", Value::Integer(3))]); // R3
    g.add_rel("T", c, a, [("w", Value::Integer(4))]); // R4 (closes the 3-cycle)
    g.add_rel("T", d, d, [("w", Value::Integer(5))]); // R5 (self-loop)
    g.add_rel("T", e, f, [("w", Value::Null)]); // R6
    g.add_rel("U", a, c, [("w", Value::Integer(6))]); // R7
    g.add_rel("U", c, a, [("w", Value::Integer(7))]); // R8 (2-cycle on U)
    g
}

// =================================================================================================
// Harness
// =================================================================================================

fn compile(src: &str) -> PhysicalPlan {
    let toks = tokenize(src).unwrap_or_else(|e| panic!("lex `{src}`: {e:?}"));
    let ast = parse_tokens(&toks, src).unwrap_or_else(|e| panic!("parse `{src}`: {e:?}"));
    let validated = analyze(&ast).unwrap_or_else(|e| panic!("analyze `{src}`: {e:?}"));
    plan_physical(&lower(&validated), &IndexCatalog::empty()).with_prefix(ast.prefix())
}

/// Runs `src` against a fresh [`corpus`] and returns the `(n, c)` projection of every row, where `c`
/// is absent for the boolean shapes. Rows come back sorted so the assertions are order-independent.
fn run(src: &str, columns: &[&str]) -> Vec<Vec<Value>> {
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new())
        .unwrap_or_else(|e| panic!("bind `{src}`: {e:?}"));
    let mut g = corpus();
    let mut cursor =
        execute(&plan, &bound, &mut g).unwrap_or_else(|e| panic!("open `{src}`: {e:?}"));
    let all = cursor
        .collect_all()
        .unwrap_or_else(|e| panic!("exec `{src}`: {e:?}"));
    let mut out: Vec<Vec<Value>> = all
        .iter()
        .map(|r| columns.iter().map(|c| r.value(c)).collect())
        .collect();
    out.sort_by_key(|r| format!("{r:?}"));
    out
}

/// The `x.n` of every `:P` node for which `EXISTS { body }` holds — the *pattern* spelling.
fn exists_pattern(body: &str) -> Vec<String> {
    names(&format!(
        "MATCH (x:P) WHERE EXISTS {{ {body} }} RETURN x.n AS n"
    ))
}

/// The same, spelled as the *full-query* form the planner + executor run.
fn exists_full_query(body: &str) -> Vec<String> {
    names(&format!(
        "MATCH (x:P) WHERE EXISTS {{ MATCH {body} RETURN 1 }} RETURN x.n AS n"
    ))
}

fn names(src: &str) -> Vec<String> {
    run(src, &["n"])
        .into_iter()
        .map(|r| match &r[0] {
            Value::String(s) => s.to_string(),
            other => panic!("expected a string name, got {other:?}"),
        })
        .collect()
}

/// `(x.n, COUNT { body })` per `:P` node — the *pattern* spelling.
fn count_pattern(body: &str) -> Vec<(String, i64)> {
    name_counts(&format!(
        "MATCH (x:P) RETURN x.n AS n, COUNT {{ {body} }} AS c"
    ))
}

/// The same, spelled as the *full-query* form the planner + executor run.
fn count_full_query(body: &str) -> Vec<(String, i64)> {
    name_counts(&format!(
        "MATCH (x:P) RETURN x.n AS n, COUNT {{ MATCH {body} RETURN 1 }} AS c"
    ))
}

fn name_counts(src: &str) -> Vec<(String, i64)> {
    run(src, &["n", "c"])
        .into_iter()
        .map(|r| match (&r[0], &r[1]) {
            (Value::String(s), Value::Integer(i)) => (s.to_string(), *i),
            other => panic!("expected (string, integer), got {other:?}"),
        })
        .collect()
}

fn owned(expected: &[&str]) -> Vec<String> {
    expected.iter().map(|s| (*s).to_owned()).collect()
}

fn owned_counts(expected: &[(&str, i64)]) -> Vec<(String, i64)> {
    expected
        .iter()
        .map(|(n, c)| ((*n).to_owned(), *c))
        .collect()
}

/// Asserts the differential oracle for `EXISTS`: the pattern spelling, the full-query spelling and
/// the hand-computed expectation must all agree.
#[track_caller]
fn check_exists(body: &str, expected: &[&str]) {
    let pattern = exists_pattern(body);
    let full = exists_full_query(body);
    assert_eq!(
        pattern, full,
        "EXISTS `{body}`: the pattern form and the full-query form disagree"
    );
    assert_eq!(
        pattern,
        owned(expected),
        "EXISTS `{body}`: wrong answer (hand-computed expectation)"
    );
}

/// Asserts the differential oracle for `COUNT` — see [`check_exists`].
#[track_caller]
fn check_count(body: &str, expected: &[(&str, i64)]) {
    let pattern = count_pattern(body);
    let full = count_full_query(body);
    assert_eq!(
        pattern, full,
        "COUNT `{body}`: the pattern form and the full-query form disagree"
    );
    assert_eq!(
        pattern,
        owned_counts(expected),
        "COUNT `{body}`: wrong answer (hand-computed expectation)"
    );
}

// =================================================================================================
// D1 — relationship isomorphism spans the comma-separated parts of one pattern
// =================================================================================================

/// Two parts anchored on the same node: `r1` and `r2` are distinct variables of one `MATCH`
/// pattern, so they may never bind the same relationship (`04 §2.4`).
///
/// Only `a` has two outgoing `T` relationships (the parallel `R1`/`R2`); it therefore admits the two
/// ordered pairs `(R1,R2)` and `(R2,R1)`. Every other `:P` node has exactly one outgoing `T`
/// relationship — including `d`, whose only edge is its self-loop — so none of them matches at all.
#[test]
fn d1_two_parts_on_one_anchor_may_not_reuse_a_relationship() {
    check_count(
        "(x)-[r1:T]->(), (x)-[r2:T]->()",
        &[("a", 2), ("b", 0), ("c", 0), ("d", 0), ("e", 0)],
    );
    check_exists("(x)-[r1:T]->(), (x)-[r2:T]->()", &["a"]);
}

/// Three parts anchored on the same node, undirected so the anchors have three incident
/// relationships to choose from: `a` sees `{R1, R2, R4}` and `b` sees `{R1, R2, R3}`, giving the
/// `3! = 6` ordered triples of *distinct* relationships each. `c` has two incident `T`
/// relationships, `d` has one (its self-loop) and `e` has one, so none of them can fill three
/// distinct slots.
#[test]
fn d1_three_parts_on_one_anchor_need_three_distinct_relationships() {
    check_count(
        "(x)-[r1:T]-(), (x)-[r2:T]-(), (x)-[r3:T]-()",
        &[("a", 6), ("b", 6), ("c", 0), ("d", 0), ("e", 0)],
    );
    check_exists("(x)-[r1:T]-(), (x)-[r2:T]-(), (x)-[r3:T]-()", &["a", "b"]);
}

/// A two-part cycle `x -r1-> m -r2-> x` needs **two** relationships. On `T` no `:P` node has one:
/// `d`'s self-loop would close the cycle only by binding `R5` to both `r1` and `r2`, which
/// isomorphism forbids. On `U` the genuine 2-cycle `R7`/`R8` matches from both of its endpoints —
/// the positive control that proves the empty `T` answer is not "matches nothing at all".
#[test]
fn d1_two_part_cycle_needs_two_distinct_relationships() {
    check_exists("(x)-[r1:T]->(m), (m)-[r2:T]->(x)", &[]);
    check_exists("(x)-[r1:U]->(m), (m)-[r2:U]->(x)", &["a", "c"]);
}

/// The "already used" set is **per candidate match**, not shared across the candidates of a part.
///
/// Directed first: from `a`, part 1 produces two partial matches (`R1` and `R2`, both to `b`), and
/// part 2 must be free to take `R3` in *each* of them. `d` is the D1 anchor — `(d)-R5->(d)` then
/// needs a second, distinct outgoing relationship of `d`, and there is none.
///
/// Undirected is the sharper discriminator, because there the parts compete for the *same*
/// relationships. From `a`: `R1→b` leaves `{R2, R3}`, `R2→b` leaves `{R1, R3}` and `R4→c` leaves
/// `{R3}` — five matches. One accumulator shared across the part's candidates would subtract the
/// union `{R1, R2, R4}` from all three continuations and yield three.
#[test]
fn d1_used_set_is_per_candidate_match_not_shared() {
    check_count(
        "(x)-[r1:T]->(m), (m)-[r2:T]->(z)",
        &[("a", 2), ("b", 1), ("c", 2), ("d", 0), ("e", 0)],
    );
    check_count(
        "(x)-[r1:T]-(m), (m)-[r2:T]-(z)",
        &[("a", 5), ("b", 5), ("c", 4), ("d", 0), ("e", 0)],
    );
}

/// A named path on the first part must still bind, and must not disturb the threading of the used
/// set into the second part — the counts are exactly those of
/// [`d1_used_set_is_per_candidate_match_not_shared`].
#[test]
fn d1_named_path_on_a_part_still_binds_and_threads() {
    check_count(
        "p = (x)-[r1:T]->(m), (m)-[r2:T]->(z)",
        &[("a", 2), ("b", 1), ("c", 2), ("d", 0), ("e", 0)],
    );
    check_exists(
        "p = (x)-[r1:T]->(m), (m)-[r2:T]->(z) WHERE length(p) = 1",
        &["a", "b", "c"],
    );
}

/// Isomorphism is scoped to the subquery's **own** pattern: a relationship variable bound by an
/// enclosing clause is an identity constraint on the hop, never a forbidden relationship. A fresh
/// accumulator per `EXISTS { … }` is what keeps that legal, exactly as `lower_pattern_parts` gives
/// the planner a fresh accumulator per `MATCH`.
///
/// `d`'s self-loop is the sharpest case: the only relationship the subquery could take is the one
/// the outer clause already bound.
#[test]
fn cross_clause_relationship_reuse_stays_legal() {
    let one = run(
        "MATCH (x:P {n: 'd'})-[r:T]->(y) WHERE EXISTS { (x)-[r]->(y) } RETURN count(*) AS c",
        &["c"],
    );
    assert_eq!(
        one,
        vec![vec![Value::Integer(1)]],
        "an outer relationship variable must remain re-usable inside EXISTS"
    );
    let all = run(
        "MATCH (x:P)-[r:T]->(y) WHERE EXISTS { (x)-[r]->(y) } RETURN count(*) AS c",
        &["c"],
    );
    assert_eq!(
        all,
        vec![vec![Value::Integer(6)]],
        "every (x)-[r]->(y) of the corpus satisfies EXISTS {{ (x)-[r]->(y) }}"
    );
}

// =================================================================================================
// D2 — an undirected hop binds a self-loop once
// =================================================================================================

/// `GraphAccess::expand` reports a self-loop once per matching side; an undirected hop must bind it
/// **once**. `d`'s only relationship is its self-loop, so `d` contributes exactly one match.
///
/// The other anchors are the non-degenerate control: `a` and `b` each have three incident `T`
/// relationships, `c` two, `e` one.
#[test]
fn d2_undirected_hop_binds_a_self_loop_once() {
    check_count(
        "(x)-[r:T]-(y)",
        &[("a", 3), ("b", 3), ("c", 2), ("d", 1), ("e", 1)],
    );
}

/// The same, with a named path: recording the traversed hop must not resurrect the duplicate.
#[test]
fn d2_named_path_over_a_self_loop_is_bound_once() {
    check_count(
        "p = (x)-[:T]-(y)",
        &[("a", 3), ("b", 3), ("c", 2), ("d", 1), ("e", 1)],
    );
    check_exists(
        "p = (x)-[:T]-(y) WHERE length(p) = 1",
        &["a", "b", "c", "d", "e"],
    );
}

/// The variable-length walker has the same duplicate-incident exposure at every depth.
///
/// At `*1..1` the answer is the single-hop one. At `*1..2`: from `a`, three length-1 trails plus
/// five length-2 trails (`R1→{R2,R3}`, `R2→{R1,R3}`, `R4→{R3}`); symmetric from `b`; from `c`,
/// two plus four; from `d`, only the self-loop itself (its continuation would have to re-use `R5`);
/// from `e`, only `R6`.
#[test]
fn d2_var_length_hop_binds_a_self_loop_once() {
    check_count(
        "(x)-[:T*1..1]-(y)",
        &[("a", 3), ("b", 3), ("c", 2), ("d", 1), ("e", 1)],
    );
    check_count(
        "(x)-[:T*1..2]-(y)",
        &[("a", 8), ("b", 8), ("c", 6), ("d", 1), ("e", 1)],
    );
}

/// Pattern comprehensions share `pattern_element_rows`, so they shared the defect: `[(d)-[r:T]-(y) | y]`
/// used to yield two elements for `d`'s single self-loop. The differential anchor is the full-query
/// `COUNT`, which the planner answers.
#[test]
fn d2_pattern_comprehension_binds_a_self_loop_once() {
    let comprehension = name_counts("MATCH (x:P) RETURN x.n AS n, size([(x)-[r:T]-(y) | y]) AS c");
    let planner = count_full_query("(x)-[r:T]-(y)");
    assert_eq!(
        comprehension, planner,
        "a pattern comprehension must enumerate the same matches as the planner"
    );
    assert_eq!(
        comprehension,
        owned_counts(&[("a", 3), ("b", 3), ("c", 2), ("d", 1), ("e", 1)]),
        "wrong answer (hand-computed expectation)"
    );
}

// =================================================================================================
// Boundaries
// =================================================================================================

/// The empty cases: an unsatisfiable predicate, and a part count no anchor can fill.
#[test]
fn empty_results_stay_empty() {
    check_exists("(x)-[r:T]->(y) WHERE y.n = 'zzz'", &[]);
    check_count(
        "(x)-[r:T]->(y) WHERE y.n = 'zzz'",
        &[("a", 0), ("b", 0), ("c", 0), ("d", 0), ("e", 0)],
    );
    check_exists("(x)-[r1:T]->(), (x)-[r2:T]->(), (x)-[r3:T]->()", &[]);
    check_count(
        "(x)-[r1:T]->(), (x)-[r2:T]->(), (x)-[r3:T]->()",
        &[("a", 0), ("b", 0), ("c", 0), ("d", 0), ("e", 0)],
    );
}

// =================================================================================================
// Whole-corpus sweep: the two spellings must never disagree
// =================================================================================================

/// The inner bodies exercised in both spellings — the shapes relationship isomorphism, 3VL, named
/// paths and variable length turn on. This is the regression net around the two fixes: any future
/// change that makes the interpreter and the planner drift apart on any of them fails here.
///
/// The bare pattern-predicate spelling (`WHERE size((y)-[:T]->()) > 0`) is deliberately **not** in
/// this list: semantic analysis rejects it in *both* spellings (`PatternPredicateInExpression`), so
/// comparing them would compare two identical compile errors and prove nothing. The pattern
/// **comprehension** below is the legal spelling of that shape, and it is the corpus entry that
/// drives `eval_pattern_comprehension` from inside a subquery predicate.
const BODIES: &[&str] = &[
    "(x)-[:T]->()",
    "(x)-[r:T]->(y)",
    "(x)-[r]->(y)",
    "(x)<-[r:T]-(y)",
    "(x)-[r:T]-(y)",
    "(x)-[r:T|U]->(y)",
    "(x)-[:T]->(:P)",
    "(x)-[:T]->({n: 'b'})",
    "(x)-[:T {w: 1}]->()",
    "(x)-[r:T]->(y) WHERE y.n = 'b'",
    "(x)-[r:T]->(y) WHERE y.k > 1",
    "(x)-[r:T]->(y) WHERE y.k IS NULL",
    "(x)-[r:T]->(y) WHERE r.w IS NULL",
    "(x)-[r:T]->(y)-[r2:T]->(z)",
    "(x)-[r]-(y)-[r2]-(x)",
    "(x)-[r:T]->(y), (y)-[r2:T]->(z)",
    "(x)-[r1:T]->(m), (m)-[r2:T]->(z)",
    "(x)-[r1:T]-(m), (m)-[r2:T]-(z)",
    "(x)-[r1:T]->(m), (m)-[r2:T]->(x)",
    "(x)-[r1:T]->(), (x)-[r2:T]->()",
    "(x)-[r1:T]->(), (x)-[r2:T]->(), (x)-[r3:T]->()",
    "(x)-[r1:T]-(), (x)-[r2:T]-()",
    "(x)-[r1:T]-(), (x)-[r2:T]-(), (x)-[r3:T]-()",
    "(x)-[r1]->(m), (m)-[r2]->(x)",
    "(x)-[r1:U]->(m), (m)-[r2:U]->(x)",
    "(x)-[:T*1..2]->(y)",
    "(x)-[:T*1..2]-(y)",
    "(x)-[:T*]->(y)",
    "(x)-[:T*]-(y)",
    "(x)-[:T*0..1]->(y)",
    "(x)-[:T*0..1]-(y)",
    "p = (x)-[:T]->(y)",
    "p = (x)-[:T]-(y)",
    "p = (x)-[:T]->(y) WHERE length(p) = 1",
    "p = (x)-[r1:T]->(m), (m)-[r2:T]->(z)",
    "(x:P)-[:T]->()",
    "(x:Q)-[:T]->()",
    "(:P)-[:U]->()",
    "(y)-[:T]->(x)",
    "(x)",
    "(x:P)",
    "(x {n: 'a'})",
    "(y:Q)",
    "(x)-[r:T]->(y) WHERE EXISTS { (y)-[:T]->() }",
    "(x)-[r:T]->(y) WHERE y.k IN [1, 2]",
    "(x)-[r:T]->(y) WHERE NOT y.n = 'b'",
    "(x)-[r:T]->(y) WHERE y.n STARTS WITH 'b'",
    // A pattern comprehension inside the subquery's predicate — the only corpus entries that reach
    // `eval_pattern_comprehension` (and its `RelScope::standalone()` call site) from within an
    // `EXISTS`/`COUNT` body. Note what these can and cannot prove: a comprehension is an
    // *expression*, so BOTH spellings evaluate it through the interpreter, and this sweep therefore
    // cannot discriminate a wrong comprehension cardinality — that is pinned by
    // `d2_pattern_comprehension_binds_a_self_loop_once`, whose oracle is the planner. What these do
    // prove is that the nested call site stays reachable and consistent with the surrounding
    // subquery machinery in both spellings.
    "(x)-[r:T]->(y) WHERE size([(y)-[:T]->(z) | z]) > 0",
    "(x)-[r:T]-(y) WHERE size([(y)-[r2:T]-(z) | z]) = 1",
];

#[test]
fn pattern_form_agrees_with_full_query_form_across_the_corpus() {
    let mut disagreements = Vec::new();
    let mut checked = 0usize;
    for body in BODIES {
        let pattern = exists_pattern(body);
        let full = exists_full_query(body);
        checked += 1;
        if pattern != full {
            disagreements.push(format!(
                "[EXISTS] `{body}`\n   pattern-form: {pattern:?}\n   full-form:    {full:?}"
            ));
        }
        let pattern = count_pattern(body);
        let full = count_full_query(body);
        checked += 1;
        if pattern != full {
            disagreements.push(format!(
                "[COUNT] `{body}`\n   pattern-form: {pattern:?}\n   full-form:    {full:?}"
            ));
        }
    }
    assert!(
        disagreements.is_empty(),
        "{} of {checked} comparisons disagree:\n{}",
        disagreements.len(),
        disagreements.join("\n")
    );
}
