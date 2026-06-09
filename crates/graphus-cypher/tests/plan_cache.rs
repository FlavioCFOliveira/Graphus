//! Integration tests for the Cypher **plan cache** and **literal auto-parameterisation**
//! (`graphus_cypher::plan_cache`, `04-technical-design.md` §7.5).
//!
//! These exercise the cache through a realistic *compile-on-miss* loop: a compile counter proves a
//! repeated normalised query compiles exactly once; literal-only variants share a plan
//! (auto-parameterisation); a `schema_version` bump forces a recompile; and the LRU evicts at
//! capacity. A golden test pins the semantics-preserving property of auto-parameterisation.

use graphus_core::Value;
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::lower::lower;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::plan_cache::{
    FeatureFlags, NormalizedQuery, PlanCache, PlanCacheKey, SchemaVersion, normalize_query,
};
use graphus_cypher::{analyze, parse};

/// A test harness wrapping a [`PlanCache`] with a compile counter, so a test can assert a query was
/// compiled exactly once across repeated lookups.
struct Engine {
    cache: PlanCache<PhysicalPlan>,
    catalog: IndexCatalog,
    schema_version: SchemaVersion,
    flags: FeatureFlags,
    compiles: usize,
}

impl Engine {
    fn new(capacity: usize) -> Self {
        Self {
            cache: PlanCache::new(capacity),
            catalog: IndexCatalog::empty(),
            schema_version: SchemaVersion::INITIAL,
            flags: FeatureFlags::empty(),
            compiles: 0,
        }
    }

    /// Normalises `src` (lifting literals to auto-params), then caches the compiled plan, compiling
    /// on a miss. Returns the normalised query so a caller can inspect the lifted auto-params.
    fn compile_returning(&mut self, src: &str) -> NormalizedQuery {
        let query = parse(src).expect("parses");
        let normalized = normalize_query(src, &query);
        let key = PlanCacheKey::new(&normalized, self.schema_version, self.flags.clone());
        if self.cache.get(&key).is_none() {
            // Compile: front-end + physical planning. (Re-parse for analysis; in production the
            // normalised auto-params travel alongside the plan to binding.)
            let validated = analyze(&query).expect("analyses");
            let plan = plan_physical(&lower(&validated), &self.catalog);
            self.compiles += 1;
            self.cache.insert(key, plan);
        }
        normalized
    }

    /// [`compile_returning`](Self::compile_returning), discarding the normalised query (the common
    /// case: a test only cares about the compile counter / cache state).
    fn get_or_compile(&mut self, src: &str) {
        let _ = self.compile_returning(src);
    }

    /// Bumps the schema version (a DDL/index/constraint change, `04 §6.6`/§7.5).
    fn bump_schema(&mut self) {
        self.schema_version = self.schema_version.next();
    }
}

#[test]
fn identical_query_compiles_once_then_hits_cache() {
    let mut engine = Engine::new(8);
    engine.get_or_compile("MATCH (n:Person) WHERE n.age = 30 RETURN n");
    engine.get_or_compile("MATCH (n:Person) WHERE n.age = 30 RETURN n");
    engine.get_or_compile("MATCH (n:Person) WHERE n.age = 30 RETURN n");
    assert_eq!(engine.compiles, 1, "the query must compile exactly once");
    assert_eq!(engine.cache.stats().hits, 2);
    assert_eq!(engine.cache.stats().misses, 1);
}

#[test]
fn literal_only_variants_share_a_plan() {
    let mut engine = Engine::new(8);
    // Same structure, different integer literal -> one plan (auto-parameterisation).
    let a = engine.compile_returning("MATCH (n:Person) WHERE n.age = 30 RETURN n");
    let b = engine.compile_returning("MATCH (n:Person) WHERE n.age = 41 RETURN n");
    assert_eq!(
        engine.compiles, 1,
        "literal-only variants reuse the same plan"
    );
    // … and the distinct literal values travel in the auto-param sidecar.
    assert_eq!(a.auto_params()[0].1, Value::Integer(30));
    assert_eq!(b.auto_params()[0].1, Value::Integer(41));
    assert_eq!(a.key_text(), b.key_text());
}

#[test]
fn different_structure_compiles_separately() {
    let mut engine = Engine::new(8);
    engine.get_or_compile("MATCH (n:Person) WHERE n.age = 30 RETURN n");
    engine.get_or_compile("MATCH (n:Company) WHERE n.size = 30 RETURN n");
    assert_eq!(engine.compiles, 2, "different structure -> different plans");
}

#[test]
fn whitespace_only_difference_shares_a_plan() {
    let mut engine = Engine::new(8);
    engine.get_or_compile("MATCH (n) RETURN n");
    engine.get_or_compile("MATCH    (n)\n   RETURN\tn");
    assert_eq!(engine.compiles, 1, "whitespace is canonicalised away");
}

#[test]
fn schema_version_bump_invalidates_and_recompiles() {
    let mut engine = Engine::new(8);
    engine.get_or_compile("MATCH (n) RETURN n");
    assert_eq!(engine.compiles, 1);
    // A DDL change bumps the schema version; the key changes, so the next lookup misses.
    engine.bump_schema();
    engine.get_or_compile("MATCH (n) RETURN n");
    assert_eq!(engine.compiles, 2, "a schema bump forces a recompile");
}

#[test]
fn eager_invalidation_evicts_stale_plans() {
    let mut engine = Engine::new(8);
    engine.get_or_compile("MATCH (a) RETURN a");
    engine.get_or_compile("MATCH (b) RETURN b");
    assert_eq!(engine.cache.len(), 2);
    engine.bump_schema();
    let evicted = engine.cache.invalidate_schema_change(engine.schema_version);
    assert_eq!(
        evicted, 2,
        "both plans were compiled against the old schema"
    );
    assert_eq!(engine.cache.len(), 0);
}

#[test]
fn lru_evicts_at_capacity() {
    let mut engine = Engine::new(2);
    engine.get_or_compile("MATCH (a) RETURN a");
    engine.get_or_compile("MATCH (b) RETURN b");
    // Touch `a` so `b` is the LRU victim.
    engine.get_or_compile("MATCH (a) RETURN a");
    engine.get_or_compile("MATCH (c) RETURN c"); // evicts `b`
    assert_eq!(engine.cache.len(), 2);
    // `b` was evicted -> looking it up again recompiles.
    let before = engine.compiles;
    engine.get_or_compile("MATCH (b) RETURN b");
    assert_eq!(engine.compiles, before + 1, "the evicted plan recompiles");
}

#[test]
fn feature_flags_are_part_of_the_key() {
    let n = normalize_query("MATCH (n) RETURN n", &parse("MATCH (n) RETURN n").unwrap());
    let k_no_flags = PlanCacheKey::new(&n, SchemaVersion(0), FeatureFlags::empty());
    let k_flags = PlanCacheKey::new(
        &n,
        SchemaVersion(0),
        FeatureFlags::from_iter_names(["experimental-quantified-paths"]),
    );
    assert_ne!(
        k_no_flags, k_flags,
        "different feature flags -> different keys"
    );
}

// =================================================================================================
// Auto-parameterisation semantics (golden)
// =================================================================================================

#[test]
fn auto_parameterisation_preserves_semantics_golden() {
    // GOLDEN: lifting scalar literals to auto-parameters is observably identity-preserving — the
    // auto-param VALUES are exactly the literals they replaced, in source order, and the key text is
    // literal-free. Re-supplying those auto-params at execution reproduces the original query's
    // values bit-for-bit. (`04 §7.5`: a TCK-safe transformation that must not change observable
    // semantics.)
    let src = "MATCH (n:Person) WHERE n.age >= 18 AND n.name = 'Ada' AND n.active = true \
               RETURN n SKIP 2 LIMIT 10";
    let query = parse(src).expect("parses");
    let n = normalize_query(src, &query);

    // (1) Every scalar literal was lifted, in source order, to its exact value.
    let values: Vec<Value> = n.auto_params().iter().map(|(_, v)| v.clone()).collect();
    assert_eq!(
        values,
        vec![
            Value::Integer(18),
            Value::String("Ada".to_owned()),
            Value::Boolean(true),
            Value::Integer(2),
            Value::Integer(10),
        ],
        "auto-param values must equal the source literals, in order"
    );

    // (2) The key text is literal-free (no `18`, `'Ada'`, `true`, `2`, `10` survive as literals).
    let key = n.key_text();
    assert!(!key.contains("18"), "{key}");
    assert!(!key.contains("'Ada'"), "{key}");
    assert!(!key.contains("true"), "{key}");
    // The structural keywords/identifiers remain.
    assert!(key.contains("MATCH"), "{key}");
    assert!(key.contains("n.age"), "{key}");

    // (3) Re-normalising a literal-only variant yields the SAME key but its own values — proof the
    // transformation isolates the only thing that differs (the values) from the plan-shaping text.
    let src2 = "MATCH (n:Person) WHERE n.age >= 65 AND n.name = 'Bob' AND n.active = false \
                RETURN n SKIP 0 LIMIT 5";
    let n2 = normalize_query(src2, &parse(src2).unwrap());
    assert_eq!(
        n.key_text(),
        n2.key_text(),
        "structure-identical -> same key"
    );
    assert_ne!(n.auto_params(), n2.auto_params(), "values differ");
}

#[test]
fn auto_param_names_cannot_collide_with_user_params() {
    // A query mixing a user `$p` and a liftable literal: the auto-param name is space-prefixed and
    // distinct from the user name, so both coexist.
    let src = "MATCH (n) WHERE n.a = $p AND n.b = 7 RETURN n";
    let query = parse(src).expect("parses");
    let n = normalize_query(src, &query);
    assert_eq!(
        n.auto_params().len(),
        1,
        "only the literal `7` is lifted, not the user $p"
    );
    assert_eq!(n.auto_params()[0].1, Value::Integer(7));
    // The user parameter survives verbatim in the key text; the auto-param name is reserved.
    assert!(n.key_text().contains("$p"), "{}", n.key_text());
    assert!(
        n.auto_params()[0].0.starts_with("  AUTO_"),
        "reserved prefix"
    );
}
