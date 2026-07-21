//! Hermetic cargo exercise of the `examples/social-network-large` **search schema** (`rmp` #677).
//!
//! Where `graphus-social-gen`'s `tests/load_fast.rs` proves the large-graph bulk *load + traversal*
//! semantics, this test proves the production-realistic **search schema** the example now declares
//! actually works end-to-end, hermetically (no Bolt, no server, no network): it declares the schema
//! through the REAL engine via the admin-DDL command path (`parse_admin_statement` →
//! `LocalEngine::{index_ddl, constraint_ddl}` — the exact seam the Bolt/REST admin surfaces submit
//! after parsing `CREATE … INDEX` / `CREATE CONSTRAINT`), loads a small seeded social graph
//! (`graphus-social-gen`, the SAME generator the example bulk-loads) **schema-first**, and asserts:
//!
//! - the new index & constraint kinds are declared and `Online` (`SHOW INDEXES` / `SHOW CONSTRAINTS`):
//!   a **TEXT** index and a **FULLTEXT** index over `ARTICLE.name`, a relationship **RANGE** index on
//!   `LIKE.date`, a **composite** node `RANGE` index on `ARTICLE(registered, id)`, the two always-on
//!   **LOOKUP** token indexes (`node_label_lookup_index` / `rel_type_lookup_index`), the two node id
//!   **UNIQUENESS** constraints (`USER.id` / `ARTICLE.id` — which back the id point-seek), and a node
//!   **existence** constraint (`ARTICLE.name IS NOT NULL`);
//! - the **empirical planner utilisation** of the relationship `RANGE` index (asserted honestly on the
//!   real public planner): Graphus serves an *equality* predicate on a relationship property from it (a
//!   `RelIndexSeek`) **and** a `>=` range predicate (a `RelIndexRangeSeek`, `rmp` #680) — so the
//!   example's `LIKE.date` recent-half range query is an index seek, not a scan + residual filter;
//! - the **headline search paths**: a `TEXT` `CONTAINS` search and a `FULLTEXT`
//!   `db.index.fulltext.queryNodes` search over `ARTICLE.name` return **exactly** the same known
//!   article set (the term is a single-token subject word), derived from the generator — including the
//!   *empirically-verified* analyzer behaviour that the standard analyzer lowercases and tokenizes the
//!   Portuguese headlines per word but does **not** stem;
//! - **constraint enforcement**: an `ARTICLE` written with a missing `name` (existence) is rejected
//!   with the constraint-violation error class, and the rejected write leaves the counts unchanged.
//!
//! Determining the substrate empirically (`rmp` #677 asked): `LocalEngine::run` does **not** accept DDL
//! strings (admin DDL is intercepted before the Cypher pipeline), but `LocalEngine` fully supports admin
//! DDL through its typed `index_ddl` / `constraint_ddl` methods **and** runs the built-in full-text
//! procedure `db.index.fulltext.queryNodes` through its normal query path — so the whole exercise runs
//! in-process against the real coordinator, no booted server required. This is the string-form
//! counterpart of the typed coordinator seam the example's `load::run_load` applies through
//! `TxnCoordinator`: both declare the identical schema (same object names), so a drift between the two
//! would fail here.

use std::sync::Arc;

use graphus_core::Value;
use graphus_cypher::{
    CONSTRAINT_VIOLATION_PREFIX, IndexCatalog, MaterializedValue, PhysicalPlan, analyze, lower,
    parse_tokens, plan_physical, tokenize,
};
use graphus_io::MemBlockDevice;
use graphus_server::admin::{AdminParse, parse_admin_statement};
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{
    ConstraintCommand, ConstraintTypeFilter, IndexCommand, IndexDdlReply, IndexTypeFilter,
    LocalEngine,
};
use graphus_sim::SharedClock;
use graphus_social_gen::{DegreeDist, EPOCH_S, GenConfig, Generator};
use graphus_wal::MemLogSink;

type Eng = LocalEngine<MemBlockDevice, MemLogSink>;

/// The seeded generator config for the hermetic load — a small graph, but with enough articles that a
/// headline subject word appears in several (so `CONTAINS` / FULLTEXT match a non-trivial set) and
/// enough `LIKE` edges that a `date` equality seek finds a seeded row.
fn cfg() -> GenConfig {
    GenConfig {
        seed: 0x50C1_A150_5EA5_C4EE,
        users: 60,
        articles: 90,
        friend_min: 3,
        friend_max: 6,
        avg_likes_per_user: 3,
        degree_dist: DegreeDist::Uniform,
    }
}

/// The **exact** search schema the example's `load::run_load` declares through the typed coordinator
/// seam, here written as the equivalent admin-DDL **strings** (carrying the SAME object names) the
/// Bolt/REST admin surface parses. `IF NOT EXISTS` is omitted so each is a plain create over the empty
/// store.
const SCHEMA_DDL: &[&str] = &[
    // The id UNIQUENESS constraints (the most-appropriate schema for the unique-key `id` column): each
    // enforces the globally-unique identity AND, via its backing index, serves the friendship / like
    // point-lookup anchor seek.
    "CREATE CONSTRAINT user_id_unique FOR (u:USER) REQUIRE u.id IS UNIQUE",
    "CREATE CONSTRAINT article_id_unique FOR (a:ARTICLE) REQUIRE a.id IS UNIQUE",
    // The search schema over ARTICLE headlines + the LIKE timeline.
    "CREATE TEXT INDEX article_name_text FOR (a:ARTICLE) ON (a.name)",
    "CREATE FULLTEXT INDEX article_headline_fulltext FOR (a:ARTICLE) ON EACH [a.name]",
    "CREATE INDEX like_date_range FOR ()-[l:LIKE]-() ON (l.date)",
    "CREATE INDEX article_catalog_composite FOR (a:ARTICLE) ON (a.registered, a.id)",
    // The node existence constraint: every ARTICLE carries a searchable headline.
    "CREATE CONSTRAINT article_name_exists FOR (a:ARTICLE) REQUIRE a.name IS NOT NULL",
];

/// Builds an in-memory engine with a fixed clock — the deterministic, hermetic substrate.
fn engine() -> Eng {
    LocalEngine::in_memory(Arc::new(SharedClock::new(0)), 1024).expect("in-memory engine")
}

/// Runs `f` on a dedicated 128 MiB-stack thread. The engine's recursive front-end (parser → analyzer →
/// physical planner) and its recursive cursor tree can nest more deeply than the default 2 MiB test
/// thread stack allows while loading the seeded graph — so, exactly like the example's own
/// `load::LOAD_STACK_BYTES` isolation (and the openCypher TCK harness's per-scenario stack), each test
/// body runs on a generously-sized thread. Any panic (a failed assertion) is re-raised on the caller so
/// the test still fails.
fn on_big_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .name("social-schema-test".to_owned())
        .stack_size(128 * 1024 * 1024)
        .spawn(f)
        .expect("spawn 128 MiB-stack test thread")
        .join()
        .unwrap_or_else(|p| std::panic::resume_unwind(p))
}

#[test]
fn schema_first_load_declares_new_index_and_constraint_kinds() {
    on_big_stack(schema_first_load_declares_new_index_and_constraint_kinds_impl);
}

#[test]
fn rel_range_index_serves_equality_and_range_predicates() {
    on_big_stack(rel_range_index_serves_equality_and_range_predicates_impl);
}

#[test]
fn text_and_fulltext_return_the_same_headline_article_set() {
    on_big_stack(text_and_fulltext_return_the_same_headline_article_set_impl);
}

#[test]
fn schema_enforces_existence_constraint_with_negative_writes() {
    on_big_stack(schema_enforces_existence_constraint_with_negative_writes_impl);
}

/// Streams the whole seeded graph as its Cypher `CREATE` / `MATCH … CREATE` statements, in the
/// generator's deterministic order (USER nodes, ARTICLE nodes, FRIEND edges, LIKE edges).
fn data_statements(generator: &Generator) -> Vec<String> {
    let mut data = Vec::new();
    generator.stream_user_node_batches(|s| data.push(s));
    generator.stream_article_node_batches(|s| data.push(s));
    generator.stream_friend_edge_batches(|s| data.push(s));
    generator.stream_like_edge_batches(|s| data.push(s));
    data
}

/// Loads the seeded social graph **schema-first** through the real engine: every `CREATE … INDEX` /
/// `CREATE CONSTRAINT` runs through the admin-DDL command path (as the Bolt/REST admin seams do), then
/// the data `CREATE`s load inside a single write transaction — so the FULLTEXT / TEXT / composite /
/// relationship indexes are populated incrementally as each write lands, and every write is
/// constraint-checked. Asserts the load succeeds — i.e. **every seed value conforms to the constraint**
/// (`rmp` #677 acceptance: each `ARTICLE` carries a `name`).
fn load_schema_first() -> Eng {
    let generator = Generator::new(cfg());
    let mut eng = engine();

    // 1. Apply the schema DDL through the admin path (each an auto-commit control command).
    for stmt in SCHEMA_DDL {
        match parse_admin_statement(stmt) {
            AdminParse::Index(cmd) => {
                eng.index_ddl(cmd)
                    .unwrap_or_else(|e| panic!("index DDL failed: {stmt}\n  {e}"));
            }
            AdminParse::Constraint(cmd) => {
                eng.constraint_ddl(cmd)
                    .unwrap_or_else(|e| panic!("constraint DDL failed: {stmt}\n  {e}"));
            }
            other => panic!("schema statement did not parse as admin DDL: {stmt}\n  got {other:?}"),
        }
    }

    // 2. Load the data with the schema active — every write is constraint-checked and index-maintained
    //    (so the FULLTEXT index is populated + promoted to Online as each ARTICLE CREATE lands).
    let ticket = eng.begin(AccessMode::Write).expect("begin load txn");
    for stmt in data_statements(&generator) {
        let mut reply = eng
            .run(ticket, &stmt, Vec::new(), false, None)
            .unwrap_or_else(|e| {
                panic!("load statement failed (data does not conform?): {stmt}\n  {e}")
            });
        while let Ok(Some(_)) = reply.rows.next() {}
    }
    eng.commit(ticket).expect("commit load txn");

    eng
}

/// `SHOW INDEXES` (full column set), as an [`IndexDdlReply`].
fn show_indexes(eng: &mut Eng) -> IndexDdlReply {
    eng.index_ddl(IndexCommand::ShowIndexes {
        filter: IndexTypeFilter::All,
        tail: None,
    })
    .expect("show indexes")
}

/// `SHOW CONSTRAINTS` (full column set), as an [`IndexDdlReply`].
fn show_constraints(eng: &mut Eng) -> IndexDdlReply {
    eng.constraint_ddl(ConstraintCommand::Show {
        filter: ConstraintTypeFilter::All,
        tail: None,
    })
    .expect("show constraints")
}

/// The 0-based column index of `name` in an [`IndexDdlReply`]'s field list.
fn col(reply: &IndexDdlReply, name: &str) -> usize {
    reply
        .fields
        .iter()
        .position(|f| f == name)
        .unwrap_or_else(|| panic!("a `{name}` column in {:?}", reply.fields))
}

/// Finds the single row whose `name` column equals `name`, or panics.
fn row_by_name<'a>(reply: &'a IndexDdlReply, name: &str) -> &'a [Value] {
    let name_c = col(reply, "name");
    reply
        .rows
        .iter()
        .find(|r| matches!(&r[name_c], Value::String(n) if n == name))
        .unwrap_or_else(|| panic!("a row named `{name}`"))
        .as_slice()
}

/// Compiles `src` into a physical plan against `catalog` (the real public planner pipeline — the
/// closest hermetic equivalent of `EXPLAIN`, since Graphus exposes no `EXPLAIN` query keyword).
fn plan(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    let logical = lower(&validated);
    plan_physical(&logical, catalog)
}

/// Runs an auto-commit write that MUST be rejected by a constraint, returning the violation message.
fn expect_rejected(eng: &mut Eng, stmt: &str) -> String {
    let ticket = eng
        .begin_auto_commit(AccessMode::Write)
        .expect("begin auto-commit");
    match eng.run(ticket, stmt, Vec::new(), true, None) {
        Err(e) => e.to_string(),
        Ok(mut reply) => loop {
            match reply.rows.next() {
                Ok(Some(_)) => {}
                Ok(None) => panic!("statement was ACCEPTED but must be rejected: {stmt}"),
                Err(e) => break e.to_string(),
            }
        },
    }
}

/// Collects the single integer column of a read query into a sorted, de-duplicated set (e.g. the
/// `ARTICLE` `id`s the TEXT / FULLTEXT search returns — now `u64` values on the wire as `i64`).
fn collect_ints(eng: &mut Eng, query: &str) -> Vec<i64> {
    let ticket = eng.begin(AccessMode::Read).expect("begin read txn");
    let mut reply = eng
        .run(ticket, query, Vec::new(), false, None)
        .expect("query runs");
    let mut out = Vec::new();
    while let Ok(Some(row)) = reply.rows.next() {
        if let Some(MaterializedValue::Value(Value::Integer(v))) = row.first() {
            out.push(*v);
        }
    }
    eng.commit(ticket).expect("commit read txn");
    out.sort_unstable();
    out.dedup();
    out
}

/// A single scalar integer (e.g. a `count(…)`).
fn scalar_int(eng: &mut Eng, query: &str) -> i64 {
    let ticket = eng.begin(AccessMode::Read).expect("begin read txn");
    let mut reply = eng
        .run(ticket, query, Vec::new(), false, None)
        .expect("query runs");
    let mut n = 0i64;
    while let Ok(Some(row)) = reply.rows.next() {
        if let Some(MaterializedValue::Value(Value::Integer(v))) = row.first() {
            n = *v;
        }
    }
    eng.commit(ticket).expect("commit read txn");
    n
}

/// The single-word, ASCII-only headline **subject** words the search asserts on — mirrors the
/// example's `load::dominant_headline_term`. Each is unique to its subject and appears nowhere else in
/// the headline fragment pools, so for any of them "articles whose `name` CONTAINS the word", "articles
/// the FULLTEXT index returns for the lower-cased token", and "articles with that subject" all denote
/// the same set.
const ASCII_SUBJECTS: &[&str] = &[
    "Governo",
    "Universidade",
    "Banco",
    "Empresa",
    "Investigadores",
    "Autarquia",
    "Mercado",
    "Sector",
];

/// Picks the most frequent [`ASCII_SUBJECTS`] headline term for [`cfg`] and returns `(term, sorted set
/// of ARTICLE ids whose headline contains it)` — the ground truth read straight from the deterministic
/// generator (the set the engine's TEXT / FULLTEXT searches must both return). The ids are the `u64`
/// [`Generator::article_id`] values as `i64` (all in `[0, 2^63)`), the form they come back on the wire.
fn dominant_headline_term() -> (String, Vec<i64>) {
    let c = cfg();
    let mut best: (String, Vec<i64>) = (ASCII_SUBJECTS[0].to_owned(), Vec::new());
    for &word in ASCII_SUBJECTS {
        let ids: Vec<i64> = (0..c.articles)
            .filter(|&i| Generator::article_name(c.seed, i).contains(word))
            .map(|i| Generator::article_id(i) as i64)
            .collect();
        if ids.len() > best.1.len() {
            best = (word.to_owned(), ids);
        }
    }
    best.1.sort_unstable();
    best
}

/// Extracts the `date: <n>` integer from a generated `LIKE`-edge statement — a real, seeded like
/// timestamp the relationship-index equality seek can be tied back to.
fn sample_like_date() -> i64 {
    let generator = Generator::new(cfg());
    let mut date: Option<i64> = None;
    generator.stream_like_edge_batches(|stmt| {
        if date.is_none()
            && let Some(pos) = stmt.find("date: ")
        {
            let rest = &stmt[pos + "date: ".len()..];
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            date = digits.parse().ok();
        }
    });
    date.expect("at least one LIKE edge with a date")
}

fn schema_first_load_declares_new_index_and_constraint_kinds_impl() {
    let mut eng = load_schema_first();

    // ---- SHOW INDEXES: the TEXT + FULLTEXT + relationship-RANGE + composite indexes and the two
    //      always-on LOOKUP token indexes, all Online (the id anchors are uniqueness constraints, whose
    //      backing indexes are not listed here — see SHOW CONSTRAINTS below). ----
    let idx = show_indexes(&mut eng);
    let (type_c, entity_c, labels_c, props_c, state_c) = (
        col(&idx, "type"),
        col(&idx, "entityType"),
        col(&idx, "labelsOrTypes"),
        col(&idx, "properties"),
        col(&idx, "state"),
    );

    // The two ALWAYS-ON token LOOKUP indexes Neo4j always lists (ids 1/2) — a NODE and a RELATIONSHIP
    // one, covering no specific label/type.
    let node_lookup = row_by_name(&idx, "node_label_lookup_index");
    assert_eq!(node_lookup[type_c], Value::String("LOOKUP".to_owned()));
    assert_eq!(node_lookup[entity_c], Value::String("NODE".to_owned()));
    assert_eq!(node_lookup[state_c], Value::String("ONLINE".to_owned()));
    let rel_lookup = row_by_name(&idx, "rel_type_lookup_index");
    assert_eq!(rel_lookup[type_c], Value::String("LOOKUP".to_owned()));
    assert_eq!(
        rel_lookup[entity_c],
        Value::String("RELATIONSHIP".to_owned())
    );
    assert_eq!(rel_lookup[state_c], Value::String("ONLINE".to_owned()));

    // TEXT (trigram) index on ARTICLE.name.
    let text = row_by_name(&idx, "article_name_text");
    assert_eq!(
        text[type_c],
        Value::String("TEXT".to_owned()),
        "TEXT is a distinct native string index, not a RANGE synonym"
    );
    assert_eq!(text[entity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        text[labels_c],
        Value::List(vec![Value::String("ARTICLE".to_owned())])
    );
    assert_eq!(
        text[props_c],
        Value::List(vec![Value::String("name".to_owned())])
    );
    assert_eq!(text[state_c], Value::String("ONLINE".to_owned()));

    // FULLTEXT (analyzer-tokenized) index on ARTICLE.name.
    let ft = row_by_name(&idx, "article_headline_fulltext");
    assert_eq!(
        ft[type_c],
        Value::String("FULLTEXT".to_owned()),
        "FULLTEXT is a distinct analyzer-tokenized index, not a RANGE/TEXT synonym"
    );
    assert_eq!(ft[entity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        ft[labels_c],
        Value::List(vec![Value::String("ARTICLE".to_owned())])
    );
    assert_eq!(
        ft[props_c],
        Value::List(vec![Value::String("name".to_owned())])
    );
    assert_eq!(
        ft[state_c],
        Value::String("ONLINE".to_owned()),
        "the FULLTEXT index must be Online after the schema-first load"
    );

    // Relationship RANGE index on LIKE.date — the headline relationship optimisation.
    let rel_range = row_by_name(&idx, "like_date_range");
    assert_eq!(rel_range[type_c], Value::String("RANGE".to_owned()));
    assert_eq!(
        rel_range[entity_c],
        Value::String("RELATIONSHIP".to_owned()),
        "the LIKE.date index is a RELATIONSHIP index"
    );
    assert_eq!(
        rel_range[labels_c],
        Value::List(vec![Value::String("LIKE".to_owned())])
    );
    assert_eq!(
        rel_range[props_c],
        Value::List(vec![Value::String("date".to_owned())])
    );
    assert_eq!(rel_range[state_c], Value::String("ONLINE".to_owned()));

    // Composite RANGE index on ARTICLE(registered, id) — the ordered two-property tuple.
    let composite = row_by_name(&idx, "article_catalog_composite");
    assert_eq!(composite[type_c], Value::String("RANGE".to_owned()));
    assert_eq!(composite[entity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        composite[props_c],
        Value::List(vec![
            Value::String("registered".to_owned()),
            Value::String("id".to_owned()),
        ]),
        "the composite index covers (registered, id) in declared order"
    );
    assert_eq!(composite[state_c], Value::String("ONLINE".to_owned()));

    // The two node id read-path anchors are now UNIQUENESS constraints, not standalone RANGE indexes.
    // A constraint's backing index is NOT listed by `SHOW INDEXES` (it surfaces under `SHOW
    // CONSTRAINTS`), so neither `user_id_range` nor `article_id_range` appears here.
    for absent in ["user_id_range", "article_id_range"] {
        assert!(
            !idx.rows
                .iter()
                .any(|r| matches!(&r[col(&idx, "name")], Value::String(n) if n == absent)),
            "{absent} must NOT be listed — the id anchors are uniqueness-constraint backings now"
        );
    }

    // ---- SHOW CONSTRAINTS: the two id UNIQUENESS constraints + the node existence constraint on
    //      ARTICLE.name. ----
    let cons = show_constraints(&mut eng);
    let (ctype_c, centity_c, cprops_c) = (
        col(&cons, "type"),
        col(&cons, "entityType"),
        col(&cons, "properties"),
    );

    // USER.id / ARTICLE.id uniqueness — the unique-key enforcement that also backs the id point-seek.
    for (name, label) in [("user_id_unique", "USER"), ("article_id_unique", "ARTICLE")] {
        let uniq = row_by_name(&cons, name);
        assert_eq!(
            uniq[ctype_c],
            Value::String("NODE_PROPERTY_UNIQUENESS".to_owned()),
            "{label}.id is a node uniqueness constraint"
        );
        assert_eq!(uniq[centity_c], Value::String("NODE".to_owned()), "{name}");
        assert_eq!(
            uniq[cprops_c],
            Value::List(vec![Value::String("id".to_owned())]),
            "{name} covers exactly the id property"
        );
    }

    let exists = row_by_name(&cons, "article_name_exists");
    assert_eq!(
        exists[ctype_c],
        Value::String("NODE_PROPERTY_EXISTENCE".to_owned())
    );
    assert_eq!(exists[centity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        exists[cprops_c],
        Value::List(vec![Value::String("name".to_owned())])
    );
}

fn rel_range_index_serves_equality_and_range_predicates_impl() {
    // The relationship RANGE index serves an EQUALITY predicate on a relationship property (a
    // `RelIndexSeek`, `rmp` #659) AND — since `rmp` #680 — a `>=` RANGE predicate (a
    // `RelIndexRangeSeek`), which is what the example's `LIKE.date` recent-half query needs.
    // Asserted on the real public planner against a catalog modelling exactly `like_date_range`, then
    // tied back to the engine: the index is really Online and an equality seek returns the seeded row.
    let mut eng = load_schema_first();

    let catalog = IndexCatalog::builder()
        .with_rel_property("LIKE", "date")
        .build();

    // An equality predicate IS served by the relationship RANGE index.
    let eq_plan = plan(
        "MATCH ()-[l:LIKE]->() WHERE l.date = 1712345678 RETURN l.date",
        &catalog,
    );
    let eq_render = eq_plan.to_string();
    assert!(
        eq_render.contains("RelIndexSeek"),
        "an equality predicate must lower to a RelIndexSeek:\n{eq_render}"
    );
    assert_eq!(
        eq_plan.index_dependencies().count(),
        1,
        "the equality plan depends on exactly the relationship index:\n{eq_render}"
    );

    // ...and a `>=` RANGE predicate is served too (`rmp` #680), by the distinct `RelIndexRangeSeek`
    // operator — which REPLACES the `ExpandAll` scan subtree (both endpoints come from the
    // relationship's own record). This is what makes the example's `LIKE.date` recent-half range query
    // an index seek rather than a full relationship scan.
    let ge_plan = plan(
        "MATCH ()-[l:LIKE]->() WHERE l.date >= 1712345678 RETURN l.date",
        &catalog,
    );
    let ge_render = ge_plan.to_string();
    assert!(
        ge_render.contains("RelIndexRangeSeek"),
        "a `>=` predicate must lower to a RelIndexRangeSeek:\n{ge_render}"
    );
    assert!(
        !ge_render.contains("ExpandAll"),
        "the seek replaces the ExpandAll scan subtree:\n{ge_render}"
    );
    assert_eq!(
        ge_plan.index_dependencies().count(),
        1,
        "the `>=` plan depends on exactly the relationship index:\n{ge_render}"
    );

    // Tie back to the engine: the relationship RANGE index really is Online, and — because a
    // schema-first-created index is maintained incrementally — an EQUALITY seek on a real seeded like
    // date returns at least the seeded row.
    {
        let idx = show_indexes(&mut eng);
        let state_c = col(&idx, "state");
        assert_eq!(
            row_by_name(&idx, "like_date_range")[state_c],
            Value::String("ONLINE".to_owned())
        );
    }
    let date = sample_like_date();
    let served = scalar_int(
        &mut eng,
        &format!("MATCH ()-[l:LIKE]->() WHERE l.date = {date} RETURN count(l) AS c"),
    );
    assert!(
        served >= 1,
        "the equality seek on a seeded like date must return at least the seeded like edge"
    );

    // And the `>=` range predicate — now index-served (`rmp` #680) — is still exactly correct: a range
    // from the epoch floor captures every LIKE (all generated dates are >= EPOCH_S). This is the
    // end-to-end witness that the range SEEK returns the same rows the scan + filter used to.
    let all_likes = scalar_int(&mut eng, "MATCH ()-[l:LIKE]->() RETURN count(l) AS c");
    let from_epoch = scalar_int(
        &mut eng,
        &format!("MATCH ()-[l:LIKE]->() WHERE l.date >= {EPOCH_S} RETURN count(l) AS c"),
    );
    assert_eq!(
        from_epoch, all_likes,
        "the `>= EPOCH_S` range (index seek) returns every LIKE edge — all dates are >= EPOCH_S"
    );
    assert!(all_likes > 0, "the seeded graph has LIKE edges");
}

fn text_and_fulltext_return_the_same_headline_article_set_impl() {
    let mut eng = load_schema_first();

    // The known ground truth: the ARTICLE ids whose headline contains the dominant single-token subject
    // word, read straight from the generator.
    let (term, expected_ids) = dominant_headline_term();
    assert!(
        expected_ids.len() > 1,
        "the headline term '{term}' must match multiple articles to exercise a set search (matched {})",
        expected_ids.len()
    );

    // TEXT `CONTAINS` over the TEXT-indexed ARTICLE.name returns exactly the expected articles.
    let via_text = collect_ints(
        &mut eng,
        &format!("MATCH (a:ARTICLE) WHERE a.name CONTAINS '{term}' RETURN a.id AS id"),
    );
    assert_eq!(
        via_text, expected_ids,
        "TEXT CONTAINS '{term}' must return exactly the generator's headline article set"
    );

    // FULLTEXT `queryNodes` over the FULLTEXT index returns the SAME set. EMPIRICAL analyzer finding:
    // the standard analyzer lowercases + tokenizes the Portuguese headline per word but does NOT stem,
    // so the whole-word subject token (lower-cased) matches exactly the articles whose headline uses
    // that subject — identical to the CONTAINS set.
    let term_lc = term.to_lowercase();
    let via_fulltext = collect_ints(
        &mut eng,
        &format!(
            "CALL db.index.fulltext.queryNodes('article_headline_fulltext', '{term_lc}') \
             YIELD node RETURN node.id AS id"
        ),
    );
    assert_eq!(
        via_fulltext, expected_ids,
        "FULLTEXT queryNodes('{term_lc}') must return the same article set as TEXT CONTAINS \
         (lowercased, tokenized, not stemmed)"
    );

    // A stop-word-only / absent term matches nothing (the analyzer drops English stop-words; a term no
    // headline contains simply has no matches).
    let none = collect_ints(
        &mut eng,
        "CALL db.index.fulltext.queryNodes('article_headline_fulltext', 'zzzznotaword') \
         YIELD node RETURN node.id AS id",
    );
    assert!(
        none.is_empty(),
        "a term no headline contains matches nothing"
    );
}

fn schema_enforces_existence_constraint_with_negative_writes_impl() {
    let mut eng = load_schema_first();
    let article_count = cfg().articles as i64;

    // Node existence: an ARTICLE without a `name` is rejected. (The id `1` is a fresh, non-colliding
    // integer — every seeded ARTICLE id is `>= 2^62` — so uniqueness passes and existence is the
    // violation under test.)
    let missing = expect_rejected(
        &mut eng,
        "CREATE (:ARTICLE {id: 1, registered: 1712345678})",
    );
    assert!(
        missing.contains(CONSTRAINT_VIOLATION_PREFIX),
        "a missing/null ARTICLE.name must be a constraint violation, got: {missing}"
    );

    // An explicit null `name` is likewise rejected.
    let explicit_null = expect_rejected(
        &mut eng,
        "CREATE (:ARTICLE {id: 2, name: null, registered: 1712345678})",
    );
    assert!(
        explicit_null.contains(CONSTRAINT_VIOLATION_PREFIX),
        "an explicit null ARTICLE.name must be a constraint violation, got: {explicit_null}"
    );

    // The rejected writes rolled back — the ARTICLE count is unchanged from the load.
    let count = scalar_int(&mut eng, "MATCH (a:ARTICLE) RETURN count(a) AS c");
    assert_eq!(
        count, article_count,
        "the rejected writes created nothing (ARTICLE count unchanged)"
    );
}
