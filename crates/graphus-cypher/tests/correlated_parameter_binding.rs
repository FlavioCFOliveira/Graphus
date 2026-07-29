//! **A predicate that mixes a driving-row variable with a `$param` must bind that parameter**
//! (`rmp` task #960).
//!
//! # The defect
//!
//! [`BoundParameters`](graphus_cypher::binding::BoundParameters) carries exactly the parameter names
//! that `binding::walk_physical` records while walking the physical plan, and `eval` resolves an
//! unrecorded `$p` to `Null`. So an expression field that escapes that walk is not a missing
//! diagnostic — it is a **silent wrong answer**.
//!
//! `rmp` #865 introduced [`PhysicalOp::ValueHashJoin`], which is planned by CONSUMING the `Filter`
//! that held an equality between two branches and moving that equality onto the operator as
//! `left_key` / `right_key`. The binder's join arm matched `{ left, right, .. }`, so the two keys fell
//! through the `..`. Any `$param` that appeared only inside the equality was then never bound, the
//! key evaluated to `Null`, `Null` matches nothing, and the query returned **zero rows** with no error:
//!
//! ```text
//! UNWIND range(0, 99) AS i MATCH (b:Person {id: (i + 1) % $n}) RETURN count(*)   -- 0, expected 100
//! UNWIND range(0, 99) AS i MATCH (b:Person) WHERE b.id = (i + 1) % $n RETURN ...  -- 0, expected 100
//! ```
//!
//! Writing `100` instead of `$n` returned 100, which is exactly why it went unnoticed: only the
//! *combination* of a parameter and a driving-row variable inside one predicate is wrong.
//!
//! The blast radius is the whole official-driver ecosystem: `UNWIND $rows AS r MATCH (a {id: r.a})
//! MATCH (b {id: r.b}) CREATE (a)-[:R]->(b)` is *the* idiom every driver uses to write edges in bulk,
//! and parameters are the only way a driver sends values. With the read prefix yielding nothing, the
//! `CREATE` ran zero times and the relationships were silently never written.
//!
//! # Why these tests cannot pass vacuously
//!
//! Two independent traps had to be measured out rather than assumed away.
//!
//! 1. **The operator must actually be in the plan.** `ValueHashJoin` is only chosen with live
//!    statistics and no usable index; with either absent the planner emits `NestedLoopJoin` + `Filter`,
//!    whose parameters were always recorded correctly. A bag comparison that never reaches the
//!    operator is two identical plans agreeing with themselves. Every scenario below therefore asserts
//!    the operator it is about is **present in the plan it just ran** (see [`assert_has_operator`]).
//! 2. **The expected bag must be non-empty.** Comparing "param" against "literal" is worthless if both
//!    are empty, so each comparison also pins the exact expected rows.
//!
//! # The index dimension
//!
//! `CREATE INDEX` must never change an answer, and in this project it repeatedly has. Every scenario
//! runs in all four planning modes — statistics on/off crossed with the index present/absent — and
//! requires one single bag from all of them.

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters, referenced_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::{GraphAccess, MemGraph};
use graphus_cypher::lexer::{TokenKind, tokenize};
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalOp, PhysicalPlan, plan_physical, plan_physical_with_stats};
use graphus_cypher::semantics::analyze;

/// How many `:Person` nodes the corpus holds, and the modulus the queries wrap on.
const N: i64 = 100;

const NO_PROPS: [(&str, Value); 0] = [];

/// `N` `:Person` nodes with `id` 0..N-1 — enough rows that the cost-based planner prefers a hash join
/// to a nested loop, which is the whole point (see the module docs).
fn corpus() -> MemGraph {
    let mut g = MemGraph::new();
    for i in 0..N {
        g.add_node(["Person"], [("id", Value::Integer(i))]);
    }
    g
}

fn indexed() -> IndexCatalog {
    IndexCatalog::builder()
        .with_label_property("Person", "id")
        .build()
}

/// The four planning modes a query must give one single answer in: statistics on/off crossed with the
/// `:Person(id)` index present/absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Mode {
    stats: bool,
    index: bool,
}

impl Mode {
    const ALL: [Self; 4] = [
        Self {
            stats: false,
            index: false,
        },
        Self {
            stats: false,
            index: true,
        },
        Self {
            stats: true,
            index: false,
        },
        Self {
            stats: true,
            index: true,
        },
    ];

    /// The mode in which `rmp` #960 bites: the cost-based planner picks a `ValueHashJoin` only when it
    /// has statistics AND no index makes a seek cheaper.
    const VALUE_HASH_JOIN: Self = Self {
        stats: true,
        index: false,
    };
}

fn compile(src: &str, g: &MemGraph, mode: Mode) -> PhysicalPlan {
    let toks = tokenize(src).unwrap_or_else(|e| panic!("lex `{src}`: {e:?}"));
    let ast = parse_tokens(&toks, src).unwrap_or_else(|e| panic!("parse `{src}`: {e:?}"));
    let v = analyze(&ast).unwrap_or_else(|e| panic!("analyze `{src}`: {e:?}"));
    let catalog = if mode.index {
        indexed()
    } else {
        IndexCatalog::empty()
    };
    let logical = lower(&v);
    if mode.stats {
        plan_physical_with_stats(&logical, &catalog, g.statistics())
    } else {
        plan_physical(&logical, &catalog)
    }
}

/// Whether `plan` contains an operator whose `operator_type()` is `name`.
fn has_operator(plan: &PhysicalPlan, name: &str) -> bool {
    fn walk(op: &PhysicalOp, name: &str) -> bool {
        op.operator_type() == name || op.children().into_iter().any(|c| walk(c, name))
    }
    walk(&plan.root, name)
}

/// Asserts the plan for `src` in `mode` really contains `name`.
///
/// This is the non-vacuity control for the whole file: without it a planner change that stopped
/// choosing the operator would leave every assertion below trivially true, and the regression would be
/// free to come back.
fn assert_has_operator(src: &str, g: &MemGraph, mode: Mode, name: &str) {
    let plan = compile(src, g, mode);
    assert!(
        has_operator(&plan, name),
        "{mode:?}: expected a `{name}` in the plan for `{src}`, got:\n{}",
        plan.root
    );
}

/// Runs `src` with `params` in `mode` and returns its rows as a sorted bag of `col`-joined strings.
fn bag(
    src: &str,
    g: &mut MemGraph,
    params: &Parameters,
    mode: Mode,
    columns: &[&str],
) -> Vec<String> {
    let plan = compile(src, g, mode);
    let bound =
        bind_parameters(&plan, params).unwrap_or_else(|e| panic!("{mode:?}: bind `{src}`: {e:?}"));
    let mut rows: Vec<String> = execute(&plan, &bound, g)
        .unwrap_or_else(|e| panic!("{mode:?}: open `{src}`: {e:?}"))
        .collect_all()
        .unwrap_or_else(|e| panic!("{mode:?}: run `{src}`: {e:?}"))
        .iter()
        .map(|r| {
            columns
                .iter()
                .map(|c| format!("{:?}", r.value(c)))
                .collect::<Vec<_>>()
                .join("|")
        })
        .collect();
    rows.sort();
    rows
}

/// Every `$name` written in `src`, read straight off the lexer.
///
/// An **independent** oracle for what a query references: it comes from the token stream, not from the
/// plan and not from a hand-maintained list, so it cannot drift with either. That independence is the
/// point — the defects this file guards were both cases of the plan-side walker's view of "which
/// parameters exist" silently disagreeing with the query the user wrote.
fn params_in_source(src: &str) -> std::collections::BTreeSet<String> {
    tokenize(src)
        .unwrap_or_else(|e| panic!("lex `{src}`: {e:?}"))
        .iter()
        .filter_map(|t| match &t.kind {
            TokenKind::Parameter(name) => Some(name.clone()),
            _ => None,
        })
        .collect()
}

/// The bag `UNWIND range(0, 99) AS i MATCH (b:Person {id: (i + 1) % 100})` must produce: every `i`
/// paired with `(i + 1) % 100`. Pinned literally so an empty or truncated result cannot pass.
fn expected_pairs() -> Vec<String> {
    let mut rows: Vec<String> = (0..N)
        .map(|i| format!("Integer({i})|Integer({})", (i + 1) % N))
        .collect();
    rows.sort();
    rows
}

// =================================================================================================
// The headline: a parameter inside a predicate that also reads the driving row
// =================================================================================================

/// The property-map spelling: `MATCH (b:Person {id: (i + 1) % $n})`.
///
/// Pre-fix this returned ZERO rows in the `stats + no index` mode while the literal spelling returned
/// all 100 — the reported defect.
#[test]
fn parameterised_property_map_predicate_matches_the_same_bag_as_the_literal() {
    let mut g = corpus();
    let param =
        "UNWIND range(0, 99) AS i MATCH (b:Person {id: (i + 1) % $n}) RETURN i, b.id AS bid";
    let literal =
        "UNWIND range(0, 99) AS i MATCH (b:Person {id: (i + 1) % 100}) RETURN i, b.id AS bid";
    let params = Parameters::new().with("n", Value::Integer(N));
    let cols = ["i", "bid"];

    // The operator this task is about must really be planned, or everything below is vacuous.
    assert_has_operator(param, &g, Mode::VALUE_HASH_JOIN, "ValueHashJoin");

    for mode in Mode::ALL {
        let got = bag(param, &mut g, &params, mode, &cols);
        assert_eq!(
            got,
            expected_pairs(),
            "{mode:?}: the parameterised property map lost rows"
        );
        assert_eq!(
            got,
            bag(literal, &mut g, &Parameters::new(), mode, &cols),
            "{mode:?}: `$n` and the literal `100` disagree"
        );
    }
}

/// The `WHERE` spelling of the same predicate. It lowers differently but reaches the same operator,
/// and failed identically.
#[test]
fn parameterised_where_predicate_matches_the_same_bag_as_the_literal() {
    let mut g = corpus();
    let param =
        "UNWIND range(0, 99) AS i MATCH (b:Person) WHERE b.id = (i + 1) % $n RETURN i, b.id AS bid";
    let literal = "UNWIND range(0, 99) AS i MATCH (b:Person) WHERE b.id = (i + 1) % 100 RETURN i, b.id AS bid";
    let params = Parameters::new().with("n", Value::Integer(N));
    let cols = ["i", "bid"];

    assert_has_operator(param, &g, Mode::VALUE_HASH_JOIN, "ValueHashJoin");

    for mode in Mode::ALL {
        let got = bag(param, &mut g, &params, mode, &cols);
        assert_eq!(
            got,
            expected_pairs(),
            "{mode:?}: the parameterised WHERE predicate lost rows"
        );
        assert_eq!(
            got,
            bag(literal, &mut g, &Parameters::new(), mode, &cols),
            "{mode:?}: `$n` and the literal `100` disagree"
        );
    }
}

/// `CREATE INDEX` must not change the answer.
///
/// The two spellings above already cross the index dimension; this states the property directly, on
/// the parameterised form, so a future regression names itself.
#[test]
fn declaring_an_index_does_not_change_the_parameterised_answer() {
    let mut g = corpus();
    let cols = ["i", "bid"];
    let params = Parameters::new().with("n", Value::Integer(N));
    for src in [
        "UNWIND range(0, 99) AS i MATCH (b:Person {id: (i + 1) % $n}) RETURN i, b.id AS bid",
        "UNWIND range(0, 99) AS i MATCH (b:Person) WHERE b.id = (i + 1) % $n RETURN i, b.id AS bid",
    ] {
        let bags: Vec<Vec<String>> = Mode::ALL
            .iter()
            .map(|&m| bag(src, &mut g, &params, m, &cols))
            .collect();
        assert_eq!(bags[0], expected_pairs(), "`{src}` is wrong with no stats");
        for (mode, got) in Mode::ALL.iter().zip(&bags) {
            assert_eq!(
                got, &bags[0],
                "{mode:?} disagrees with the reference plan for `{src}`"
            );
        }
    }
}

/// The **seam contract**, pinned where it is the sole control: a plan containing a `ValueHashJoin`
/// must DECLARE the `$param`s written in its join keys.
///
/// The end-to-end tests above are the user-visible symptom; this is the mechanism. It is stated
/// separately because a planner change could make those tests stop reaching the operator, and this one
/// would still fail if the keys stopped being walked.
#[test]
fn a_value_hash_join_declares_the_parameters_in_its_keys() {
    let g = corpus();
    let src = "UNWIND range(0, 99) AS i MATCH (b:Person) WHERE b.id = (i + 1) % $n RETURN i";
    let plan = compile(src, &g, Mode::VALUE_HASH_JOIN);
    assert!(
        has_operator(&plan, "ValueHashJoin"),
        "fixture no longer plans a ValueHashJoin; the assertion below would be vacuous:\n{}",
        plan.root
    );
    assert!(
        referenced_parameters(&plan).contains("n"),
        "the join key's `$n` was not declared, so it would bind to Null and match nothing"
    );
}

/// **Both** key expressions must be walked, not just the one the headline queries happen to use.
///
/// `value_hash_join_alternative` assigns the equality's two sides by which branch each reads, and in
/// every query above the `$param` lands in `left_key` alone — so deleting the `right_key` walk left the
/// whole rest of this file green. This query puts a distinct parameter on each side, which is the only
/// thing that pins the second line of the fix.
#[test]
fn a_value_hash_join_declares_the_parameters_in_both_of_its_keys() {
    let g = corpus();
    let src = "MATCH (a:Person), (b:Person) WHERE a.id + $l = b.id + $r RETURN count(*) AS c";
    let plan = compile(src, &g, Mode::VALUE_HASH_JOIN);
    assert!(
        has_operator(&plan, "ValueHashJoin"),
        "fixture no longer plans a ValueHashJoin; the assertions below would be vacuous:\n{}",
        plan.root
    );
    let declared = referenced_parameters(&plan);
    assert!(
        declared.contains("l"),
        "the LEFT key's `$l` was not declared"
    );
    assert!(
        declared.contains("r"),
        "the RIGHT key's `$r` was not declared"
    );
}

// =================================================================================================
// The same defect class one level down: a pattern comprehension's own pattern
// =================================================================================================

/// A `$param` inside a **pattern comprehension's** inline property map must bind.
///
/// Found while auditing the class for `rmp` #960 and fixed with it. `binding::params_in_expr` walked
/// only the comprehension's `WHERE` and its projection, never its pattern element, so
/// `[(a)-[:KNOWS]->(b:Person {city: $c}) | b.name]` left `$c` unbound and yielded an EMPTY LIST for
/// every row. Independent of the planner — it reproduces with no statistics and no index.
#[test]
fn a_pattern_comprehension_declares_the_parameters_in_its_pattern() {
    let mut g = MemGraph::new();
    let a = g.add_node(["Person"], [("name", Value::String("a".to_owned()))]);
    let b = g.add_node(
        ["Person"],
        [
            ("name", Value::String("b".to_owned())),
            ("city", Value::String("Lisbon".to_owned())),
        ],
    );
    let c = g.add_node(
        ["Person"],
        [
            ("name", Value::String("c".to_owned())),
            ("city", Value::String("Porto".to_owned())),
        ],
    );
    g.add_rel("KNOWS", a, b, NO_PROPS);
    g.add_rel("KNOWS", a, c, NO_PROPS);

    let param = "MATCH (a:Person) WHERE a.name = 'a' \
                 RETURN [(a)-[:KNOWS]->(x:Person {city: $c}) | x.name] AS r";
    let literal = "MATCH (a:Person) WHERE a.name = 'a' \
                   RETURN [(a)-[:KNOWS]->(x:Person {city: 'Lisbon'}) | x.name] AS r";
    let params = Parameters::new().with("c", Value::String("Lisbon".to_owned()));

    for mode in Mode::ALL {
        let plan = compile(param, &g, mode);
        assert!(
            referenced_parameters(&plan).contains("c"),
            "{mode:?}: the comprehension's `$c` was not declared"
        );
        let got = bag(param, &mut g, &params, mode, &["r"]);
        // Pinned literally: an empty list is exactly the pre-fix answer, so `got == literal` alone
        // would pass if the literal spelling ever broke too.
        assert_eq!(
            got,
            vec![r#"List([String("b")])"#.to_owned()],
            "{mode:?}: the parameterised comprehension pattern lost its match"
        );
        assert_eq!(
            got,
            bag(literal, &mut g, &Parameters::new(), mode, &["r"]),
            "{mode:?}: `$c` and the literal disagree"
        );
    }
}

// =================================================================================================
// The class-level guard
// =================================================================================================

/// **Every `$param` written in a query must be declared by the plan compiled from it, in every
/// planning mode.**
///
/// This is the invariant both defects broke, stated once over a corpus that reaches the operators a
/// rewrite can hide an expression on. It is the cheap guard against the next instance: any future pass
/// that moves an expression out of a `Filter` and onto an operator field without teaching
/// `binding::walk_physical` about it fails here, whichever operator it invents.
///
/// The expectation is **derived from the source text, not hand-written**: [`params_in_source`] reads
/// the `$name`s straight off the lexer, so a query added to the corpus cannot be accompanied by a
/// stale or incomplete list of the parameters it is supposed to declare. The corpus itself stays
/// curated, because the invariant is a subset relation in one direction only: a pass that legitimately
/// *eliminates* an expression (folding a conjunct away) may drop a parameter with it, and that is not
/// a defect.
#[test]
fn every_parameter_written_in_a_query_is_declared_by_its_plan() {
    let mut g = corpus();
    let d = g.add_node(["Dept"], [("code", Value::String("x".to_owned()))]);
    let p = g.add_node(["Person"], [("id", Value::Integer(1000))]);
    g.add_rel("WORKS_IN", p, d, [("since", Value::Integer(2020))]);

    let queries: &[&str] = &[
        // The reported defect, both spellings.
        "UNWIND range(0, 99) AS i MATCH (b:Person {id: (i + 1) % $n}) RETURN count(*) AS c",
        "UNWIND range(0, 99) AS i MATCH (b:Person) WHERE b.id = (i + 1) % $n RETURN count(*) AS c",
        // Value joins between two branches on a business key — the shape `ValueHashJoin` exists for,
        // including one with a parameter on EACH side so both key expressions are covered.
        "MATCH (a:Person), (b:Person) WHERE a.id = b.id + $off RETURN count(*) AS c",
        "MATCH (a:Person), (b:Person) WHERE a.id + $l = b.id + $r RETURN count(*) AS c",
        // Pattern comprehension: inline node map, inline relationship map.
        "MATCH (a:Person) RETURN [(a)-[:WORKS_IN]->(x:Dept {code: $code}) | x.code] AS r",
        "MATCH (a:Person) RETURN [(a)-[r:WORKS_IN {since: $yr}]->(x) | x.code] AS r",
        // Positions earlier fixes of this same class added, kept under guard.
        "MATCH (a:Person)-[r:WORKS_IN*1..2 {since: $yr}]->(b) RETURN count(*) AS c",
        "MATCH (a:Person) OPTIONAL MATCH (a)-[:WORKS_IN]->(b) WHERE b.code = $code RETURN count(*) AS c",
        "MATCH (a:Person) WHERE EXISTS { (a)-[:WORKS_IN]->(d:Dept {code: $code}) } RETURN count(*) AS c",
        // Ordinary positions.
        "MATCH (n:Person) RETURN n.id SKIP $s LIMIT $l",
        "MATCH (n:Person) WHERE n.id IN $ids RETURN count(*) AS c",
        "MATCH (n:Person) SET n.tag = $t RETURN count(*) AS c",
        "CREATE (n:Person {id: $newid}) RETURN n.id",
        "MERGE (n:Person {id: $mid}) ON CREATE SET n.k = $ck ON MATCH SET n.k = $mk RETURN n.id",
        "UNWIND $rows AS row MATCH (a:Person {id: row.a}) RETURN count(*) AS c",
    ];

    for src in queries {
        let written = params_in_source(src);
        assert!(
            !written.is_empty(),
            "`{src}` writes no `$param`, so it guards nothing"
        );
        for mode in Mode::ALL {
            let declared = referenced_parameters(&compile(src, &g, mode));
            for name in &written {
                assert!(
                    declared.contains(name),
                    "{mode:?}: `${name}` is written in `{src}` but the plan does not declare it — \
                     it would bind to Null and silently change the answer. Declared: {declared:?}"
                );
            }
        }
    }
}
