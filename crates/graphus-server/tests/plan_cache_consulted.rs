//! `rmp` task #322 (F6): proves the server RUN path consults the engine's compiled-plan cache.
//!
//! Before this work the engine re-ran the *entire* compile pipeline
//! (tokenize→parse→analyze→lower→physical-plan, a measured ~7–9 µs) on **every** `Run`, so a looped
//! identical query recompiled every iteration. These tests drive the **real engine** (via the inline
//! [`LocalEngine`], the same `dispatch_command`→`handle_run` path production uses) and assert:
//!
//! 1. a repeated identical query text reuses a cached plan (a cache **hit**, not a recompile);
//! 2. a schema change (index / constraint DDL) **invalidates** the cache, so the next identical query
//!    recompiles (a miss) — a cached plan is never reused across a planner-visible catalog change.

use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{IndexCommand, LocalEngine};
use graphus_sim::SharedClock;
use graphus_wal::MemLogSink;
use std::sync::Arc;

type Eng = LocalEngine<MemBlockDevice, MemLogSink>;

fn engine() -> Eng {
    let clock = SharedClock::new(0);
    LocalEngine::in_memory(Arc::new(clock) as Arc<dyn Clock + Send + Sync>, 256)
        .expect("build in-memory engine")
}

/// Runs one auto-commit read statement to completion (draining its rows so the auto-commit finalises).
fn run_read(eng: &mut Eng, stmt: &str) {
    let ticket = eng
        .begin_auto_commit(AccessMode::Read)
        .expect("begin auto-commit read");
    let mut reply = eng.run(ticket, stmt, vec![], true, None).expect("run");
    while reply.rows.next().expect("drain rows").is_some() {}
}

#[test]
fn repeated_query_text_hits_the_plan_cache() {
    let mut eng = engine();
    let q = "MATCH (n:Person) WHERE n.age = 30 RETURN n.name ORDER BY n.name LIMIT 10";

    // First execution: a cold cache → exactly one miss, no hits, one cached plan.
    run_read(&mut eng, q);
    let after_first = eng.plan_cache_stats();
    assert_eq!(after_first.misses, 1, "first compile is a miss");
    assert_eq!(after_first.hits, 0, "first compile cannot be a hit");
    assert_eq!(after_first.len, 1, "the compiled plan is cached");

    // Re-run the SAME text many times: every one must be a cache hit (no recompile). Misses stay at 1.
    const REPEATS: u64 = 50;
    for _ in 0..REPEATS {
        run_read(&mut eng, q);
    }
    let after_loop = eng.plan_cache_stats();
    assert_eq!(
        after_loop.misses, 1,
        "no further misses — every repeat reused the cached plan (got {} misses)",
        after_loop.misses
    );
    assert_eq!(
        after_loop.hits, REPEATS,
        "every repeated Run is a cache hit"
    );
    assert_eq!(after_loop.len, 1, "still exactly one cached plan");
}

#[test]
fn distinct_query_texts_are_cached_separately() {
    let mut eng = engine();
    // Two texts differing only in a literal are DIFFERENT exact-text keys (exact-text keying is the
    // low-risk policy — literal-collapsing normalisation is a separate task). Each is its own plan.
    run_read(&mut eng, "MATCH (n:Person) WHERE n.age = 30 RETURN n");
    run_read(&mut eng, "MATCH (n:Person) WHERE n.age = 41 RETURN n");
    let s = eng.plan_cache_stats();
    assert_eq!(s.misses, 2, "two distinct texts → two misses");
    assert_eq!(s.hits, 0);
    assert_eq!(s.len, 2, "two plans cached");

    // Re-running each is a hit.
    run_read(&mut eng, "MATCH (n:Person) WHERE n.age = 30 RETURN n");
    run_read(&mut eng, "MATCH (n:Person) WHERE n.age = 41 RETURN n");
    let s = eng.plan_cache_stats();
    assert_eq!(s.misses, 2, "still two misses");
    assert_eq!(s.hits, 2, "each repeat is a hit");
}

#[test]
fn index_ddl_invalidates_the_plan_cache() {
    let mut eng = engine();
    let q = "MATCH (n:Person) WHERE n.age = 30 RETURN n.name";

    // Warm the cache, then confirm a repeat is a hit.
    run_read(&mut eng, q);
    run_read(&mut eng, q);
    let before = eng.plan_cache_stats();
    assert_eq!(before.misses, 1);
    assert_eq!(before.hits, 1, "the repeat hit before any schema change");

    // A schema change: create a node-property index. The inline engine drives the build to completion
    // before returning, so the catalog now exposes the new index — every plan compiled under the old
    // schema is stale and must be invalidated.
    eng.index_ddl(IndexCommand::CreateNodePropertyIndex {
        label: "Person".to_owned(),
        property: "age".to_owned(),
    })
    .expect("create index");

    // The very same query text must now MISS (recompile against the new schema), not reuse the stale
    // plan. (Counters are cumulative: misses 1→2.)
    run_read(&mut eng, q);
    let after = eng.plan_cache_stats();
    assert_eq!(
        after.misses, 2,
        "the schema change invalidated the cache: the next identical query recompiled"
    );

    // And after invalidation the new plan is itself cached: a further repeat hits again.
    run_read(&mut eng, q);
    let after2 = eng.plan_cache_stats();
    assert_eq!(after2.misses, 2, "no extra miss");
    assert_eq!(
        after2.hits,
        before.hits + 1,
        "the post-invalidation plan is now cached and reused"
    );
}

#[test]
fn drop_index_also_invalidates() {
    let mut eng = engine();
    eng.index_ddl(IndexCommand::CreateNodePropertyIndex {
        label: "Person".to_owned(),
        property: "age".to_owned(),
    })
    .expect("create index");

    let q = "MATCH (n:Person) WHERE n.age = 30 RETURN n";
    run_read(&mut eng, q);
    run_read(&mut eng, q);
    let before = eng.plan_cache_stats();
    let hits_before = before.hits;

    // Dropping the index changes the planner-visible catalog → invalidate.
    eng.index_ddl(IndexCommand::DropNodePropertyIndex {
        label: "Person".to_owned(),
        property: "age".to_owned(),
    })
    .expect("drop index");

    let misses_before = eng.plan_cache_stats().misses;
    run_read(&mut eng, q);
    let after = eng.plan_cache_stats();
    assert_eq!(
        after.misses,
        misses_before + 1,
        "dropping the index invalidated the cached plan"
    );
    assert_eq!(
        after.hits, hits_before,
        "the post-drop run was a miss, not a hit"
    );
}
