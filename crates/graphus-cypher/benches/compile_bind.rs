//! Per-statement engine-thread cost breakdown (`rmp` task #531 assessment).
//!
//! Every statement the single engine thread processes pays, before the off-thread dispatch gate:
//! a plan-cache **key build + lookup**, and then either a **deep plan clone** (cache hit) or a full
//! **compile** (cache miss), followed by **parameter binding**. This benchmark quantifies each so we
//! can decide what is worth moving off the engine thread. It is an assessment aid, not a permanent
//! regression gate.
//!
//! Run: `cargo bench -p graphus-cypher --bench compile_bind`

use std::collections::HashMap;
use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical_with_stats};
use graphus_cypher::plan_cache::{FeatureFlags, PlanCacheKey, SchemaVersion};
use graphus_cypher::semantics::analyze;

/// Compiles `src` through the full front-end pipeline the server's `compile` uses (minus extensions).
fn compile(src: &str) -> PhysicalPlan {
    let tokens = tokenize(src).expect("tokenizes");
    let ast = parse_tokens(&tokens, src).expect("parses");
    let validated = analyze(&ast).expect("analyzes");
    let logical = lower(&validated);
    plan_physical_with_stats(&logical, &IndexCatalog::empty(), None)
}

/// A minimal `PlanCacheKey` mirroring `EnginePlanCache::key` (verbatim query text keyed).
fn key(src: &str) -> PlanCacheKey {
    PlanCacheKey {
        normalized_query_text: src.to_owned(),
        schema_version: SchemaVersion::INITIAL,
        feature_flags: FeatureFlags::empty(),
    }
}

/// Representative statements spanning the plan-complexity range the engine sees.
fn corpus() -> Vec<(&'static str, &'static str, Parameters)> {
    vec![
        (
            "simple_scan",
            "MATCH (n:Person) RETURN n",
            Parameters::new(),
        ),
        (
            "param_filter",
            "MATCH (n:Person) WHERE n.age > $age RETURN n.name",
            Parameters::new().with("age", Value::Integer(30)),
        ),
        (
            "two_hop",
            "MATCH (a:Person)-[:KNOWS]->(b:Person)-[:KNOWS]->(c:Person) \
             WHERE a.name = $name RETURN c.name LIMIT $lim",
            Parameters::new()
                .with("name", Value::String("Ada".to_owned()))
                .with("lim", Value::Integer(10)),
        ),
        (
            "aggregate_order",
            "MATCH (n:Person) WHERE n.age > $age \
             RETURN n.city AS city, count(*) AS c ORDER BY c DESC LIMIT $lim",
            Parameters::new()
                .with("age", Value::Integer(21))
                .with("lim", Value::Integer(25)),
        ),
    ]
}

fn bench(c: &mut Criterion) {
    let corpus = corpus();

    // (1) Cache-MISS cost: the full compile pipeline that runs on the engine thread on a miss.
    let mut g = c.benchmark_group("compile_miss");
    for (name, src, _) in &corpus {
        g.bench_with_input(BenchmarkId::from_parameter(name), src, |b, src| {
            b.iter(|| black_box(compile(black_box(src))));
        });
    }
    g.finish();

    // (2) Cache-HIT deep-clone cost (the BEFORE for `rmp` #531): what the engine paid to hand a cached
    // plan out — a full operator-tree clone, once at cache handout and once more inside the executor.
    let mut g = c.benchmark_group("plan_clone");
    for (name, src, _) in &corpus {
        let plan = compile(src);
        g.bench_with_input(BenchmarkId::from_parameter(name), &plan, |b, plan| {
            b.iter(|| black_box(black_box(plan).clone()));
        });
    }
    g.finish();

    // (2b) Cache-HIT `Arc::clone` cost (the AFTER for `rmp` #531): the shared-plan handout the engine
    // pays now, per clone eliminated (both the cache handout and the executor's internal clone).
    let mut g = c.benchmark_group("plan_arc_clone");
    for (name, src, _) in &corpus {
        let plan = std::sync::Arc::new(compile(src));
        g.bench_with_input(BenchmarkId::from_parameter(name), &plan, |b, plan| {
            b.iter(|| black_box(std::sync::Arc::clone(black_box(plan))));
        });
    }
    g.finish();

    // (3) Parameter binding cost (runs on the engine thread on every statement, hit or miss).
    let mut g = c.benchmark_group("bind_parameters");
    for (name, src, params) in &corpus {
        let plan = compile(src);
        g.bench_with_input(
            BenchmarkId::from_parameter(name),
            &(plan, params),
            |b, (plan, params)| {
                b.iter(|| black_box(bind_parameters(black_box(plan), black_box(params))).unwrap());
            },
        );
    }
    g.finish();

    // (4) Key build + HashMap probe: the per-statement lookup cost (String alloc for the key + hash
    // over the whole query text + a HashMap get), paid on every statement, hit or miss.
    let mut g = c.benchmark_group("key_build_and_probe");
    for (name, src, _) in &corpus {
        // A one-entry map standing in for the populated plan cache on the hit path.
        let mut map: HashMap<PlanCacheKey, u32> = HashMap::with_capacity(4);
        map.insert(key(src), 1);
        g.bench_with_input(BenchmarkId::from_parameter(name), src, |b, src| {
            b.iter(|| {
                let k = key(black_box(src));
                black_box(map.get(&k))
            });
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
