//! The executor's **per-row hot path** — the cost of pulling rows through the Volcano operator tree.
//!
//! This benchmark exists to hold one specific line: instrumentation added for diagnostics
//! (`EXPLAIN` / `PROFILE`, `rmp` task #752) must cost **nothing** on the ordinary path. A statement with
//! no query prefix must build no profiling shim, wrap no seam, and take the same per-row work it always
//! did — so this measures exactly that path, with no prefix, and is the number to compare across a
//! change that touches `Cursor::next` / `Operator::next` / `build_operator`.
//!
//! Two shapes, chosen because they exercise the row path differently:
//!
//! * `scan_project` — a label scan straight into a projection: the leanest possible per-row path
//!   (one operator pull + one expression evaluation per row).
//! * `scan_filter_project` — adds a `Filter` between them: a second operator pull and a predicate
//!   evaluation per row, so the per-operator overhead is doubled.
//!
//! Both are deliberately *seam-light* (a `MemGraph` scan is a `Vec` walk), because what is being measured
//! is the **executor's** per-row work — the operator pulls, the `Ctx` construction, the expression
//! evaluation — not the storage engine underneath it. A traversal shape was tried and rejected: its cost
//! is dominated by `MemGraph`'s O(E) incidence walk, which would drown the signal.
//!
//! `Throughput::Elements` is the number of **rows the query returns**, so Criterion reports rows/sec.
//!
//! Run with `cargo bench -p graphus-cypher --bench executor_row_path`.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
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

/// The benchmark graph: `n` `:Person` nodes with an `age` and a `name`.
fn graph(n: i64) -> MemGraph {
    let mut g = MemGraph::new();
    for i in 0..n {
        g.add_node(
            ["Person"],
            [
                ("age", Value::Integer(i % 90)),
                ("name", Value::String(format!("p{i}"))),
            ],
        );
    }
    g
}

fn compile(src: &str) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

/// Pulls every row of `plan` over `graph` and returns how many there were.
fn drain(plan: &PhysicalPlan, graph: &mut MemGraph) -> usize {
    let params = bind_parameters(plan, &Parameters::new()).expect("bind");
    let mut cursor = execute(plan, &params, graph).expect("open");
    let mut n = 0;
    while let Some(row) = cursor.next().expect("row") {
        black_box(&row);
        n += 1;
    }
    n
}

fn bench_row_path(c: &mut Criterion) {
    const N: i64 = 50_000;
    let mut g = graph(N);

    let mut group = c.benchmark_group("executor_row_path");

    // 1. scan → project: the leanest per-row path.
    let plan = compile("MATCH (n:Person) RETURN n.name AS name");
    let rows = drain(&plan, &mut g);
    assert_eq!(rows, N as usize);
    group.throughput(Throughput::Elements(rows as u64));
    group.bench_function("scan_project", |b| {
        b.iter(|| black_box(drain(black_box(&plan), black_box(&mut g))));
    });

    // 2. scan → filter → project: one more operator pull + a predicate per row.
    let plan = compile("MATCH (n:Person) WHERE n.age >= 0 RETURN n.name AS name");
    let rows = drain(&plan, &mut g);
    assert_eq!(rows, N as usize);
    group.throughput(Throughput::Elements(rows as u64));
    group.bench_function("scan_filter_project", |b| {
        b.iter(|| black_box(drain(black_box(&plan), black_box(&mut g))));
    });

    group.finish();
}

criterion_group!(benches, bench_row_path);
criterion_main!(benches);
