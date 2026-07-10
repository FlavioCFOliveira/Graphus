//! Hermetic cargo exercise of the `examples/bulk-etl` **online schema-hardening** (`rmp` #678).
//!
//! The `examples/bulk-etl` demonstration is fully OFFLINE: `graphus-bulk` builds a fresh store through
//! the low-level record API and neither builds secondary indexes nor enforces constraints. What
//! follows a bulk load in production is **online schema-hardening** — an operator declares, via DDL on
//! the live server, the constraints and indexes the freshly-loaded data is now ready to carry. The
//! generator (`graphus-bulk-gen`) documents that exact production schema in its manifest under
//! `Manifest::implied_schema`, and generates the dataset so every rule is **satisfied by construction**.
//!
//! This test proves that documented schema actually works end-to-end, hermetically (no Bolt, no server,
//! no network): it applies the manifest's `implied_schema` DDL **verbatim** through the REAL engine via
//! the admin-DDL command path (`parse_admin_statement` → `LocalEngine::{index_ddl, constraint_ddl}` —
//! the exact seam the Bolt/REST admin surfaces submit after parsing `CREATE … INDEX` /
//! `CREATE CONSTRAINT`), loads a representative slice of the SAME seeded social graph **schema-first**
//! (so every index is maintained and every write constraint-checked as it lands), and asserts:
//!
//! - the new index & constraint kinds are declared and `Online` (`SHOW INDEXES` / `SHOW CONSTRAINTS`):
//!   a **TEXT** and a **FULLTEXT** index over `Post.content`, a **composite** node `RANGE` index on
//!   `Post(createdAt, id)`, the two always-on **LOOKUP** token indexes, a **NODE KEY** on `Person.id`,
//!   a composite **UNIQUE** on `Post(id, createdAt)`, `UNIQUE` on `Forum.id` / `Comment.id`, a node
//!   **property-type** (`Post.length IS :: INTEGER`), a relationship **existence**
//!   (`LIKES.creationDate IS NOT NULL`) and a relationship **property-type**
//!   (`HAS_CREATOR.weight IS :: INTEGER`) — with the correct type strings, entities and properties;
//! - **enforcement**: a composite-`UNIQUE` duplicate `Post` tuple, a `NODE KEY` duplicate `Person.id`,
//!   and a `LIKES` relationship missing `creationDate` (existence) are each rejected with the
//!   constraint-violation error class, and the rejected writes leave the counts unchanged;
//! - the **index query paths** return correct results and are utilised by the real planner: a `TEXT`
//!   `CONTAINS` substring search over `Post.content` returns exactly the generator's post set (and
//!   lowers to a `NodeTextIndexSeek`); a `FULLTEXT` `db.index.fulltext.queryNodes` search returns the
//!   full post population for the shared `content` token, exactly one post for a unique number token,
//!   and nothing for an absent term; and a composite equality seek on `Post(createdAt, id)` returns the
//!   right post (and lowers to a `NodeCompositeIndexSeek`).
//!
//! Determining the substrate empirically (`rmp` #678 asked): `LocalEngine::run` does **not** accept DDL
//! strings (admin DDL is intercepted before the Cypher pipeline), but `LocalEngine` fully supports admin
//! DDL through its typed `index_ddl` / `constraint_ddl` methods **and** runs the built-in full-text
//! procedure `db.index.fulltext.queryNodes` through its normal query path — so the whole exercise runs
//! in-process against the real coordinator, no booted server required. Because the offline importer does
//! NOT persist the CSV `:ID` column as a queryable node property (it is consumed as the physical-id join
//! key only), the id-anchored production schema is exercised here by loading the model over the query
//! path with `id` carried as a property — exactly as an online client (and the live wire demo in
//! `run.sh`) does after a bulk load.

use std::collections::BTreeMap;
use std::sync::Arc;

use graphus_bulk_gen::{Dataset, GenConfig, generate};
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
use graphus_wal::MemLogSink;

type Eng = LocalEngine<MemBlockDevice, MemLogSink>;

/// A small, representative slice of the LDBC-SNB-like model — every node label, every relationship
/// type, arrays, integer/string properties — kept modest so the full schema-first Cypher load stays a
/// sub-second in-process test while remaining a faithful subset of the example's `fast` profile.
///
/// `posts_per_forum * forums = 32` posts, numbered `po0..po31`, so a `content` substring search matches
/// a non-trivial subset (e.g. `content-1` ⇒ `po1, po10..po19`) and a whole-number FULLTEXT token
/// matches exactly one.
fn cfg() -> GenConfig {
    GenConfig {
        seed: 0x50C1_A1B0_17E7_0678,
        persons: 40,
        forums: 8,
        posts_per_forum: 4,
        comments_per_post: 2,
        knows_per_person: 4,
        members_per_forum: 6,
        likes_per_person: 3,
    }
}

/// Builds an in-memory engine with a fixed clock — the deterministic, hermetic substrate.
fn engine() -> Eng {
    LocalEngine::in_memory(Arc::new(SharedClock::new(0)), 1024).expect("in-memory engine")
}

/// Runs `f` on a dedicated 128 MiB-stack thread. The engine's recursive front-end (parser → analyzer →
/// physical planner) and its recursive cursor tree can nest more deeply than the default 2 MiB test
/// thread stack allows while loading the seeded graph — so, like the example's own load isolation and
/// the openCypher TCK harness, each test body runs on a generously-sized thread. Any panic (a failed
/// assertion) is re-raised on the caller so the test still fails.
fn on_big_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .name("bulk-etl-schema-test".to_owned())
        .stack_size(128 * 1024 * 1024)
        .spawn(f)
        .expect("spawn 128 MiB-stack test thread")
        .join()
        .unwrap_or_else(|p| std::panic::resume_unwind(p))
}

// =================================================================================================
// CSV → Cypher: parse the generator's `neo4j-admin import`-flavoured CSV into schema-checked writes.
//
// The offline importer consumes this CSV directly; here we replay the SAME rows over the query path so
// the nodes carry an `id` property (the CSV `:ID` join key), which the id-anchored production schema
// requires but the offline importer does not persist. The generator's CSV is simple — no quoting, `;`
// -separated arrays, one property per relationship — so a compact hand parser is faithful and exact.
// =================================================================================================

/// A parsed CSV column role (from the typed header cell).
enum Col {
    /// `<name>:ID` — the external id, replayed as a string property `id`.
    Id,
    /// `:LABEL` — the node label (taken from the file, ignored per-row here).
    Ignore,
    /// A `<key>:int` integer property.
    IntProp(String),
    /// A `<key>:string` string property.
    StrProp(String),
    /// A `<key>:string[]` list-of-string property (`;`-separated cell).
    StrListProp(String),
}

/// Parses a CSV header line into its column roles (`:START_ID` / `:END_ID` / `:TYPE` are treated as
/// [`Col::Ignore`] since relationships are built by looking their endpoints up by external id).
fn parse_header(header: &str) -> Vec<Col> {
    header
        .split(',')
        .map(|c| match c.trim() {
            ":LABEL" | ":START_ID" | ":END_ID" | ":TYPE" => Col::Ignore,
            typed => {
                let (name, ty) = typed.split_once(':').expect("a typed `name:type` column");
                match ty {
                    "ID" => Col::Id,
                    "int" => Col::IntProp(name.to_owned()),
                    "string" => Col::StrProp(name.to_owned()),
                    "string[]" => Col::StrListProp(name.to_owned()),
                    other => panic!("unhandled CSV column type: {other}"),
                }
            }
        })
        .collect()
}

/// Renders a string as a single-quoted Cypher literal, escaping `\` and `'` (defensive — the
/// generator emits neither).
fn cy_str(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
}

/// The node label of an external id, from its per-label prefix (`po` Post before `p` Person, `f`
/// Forum, `c` Comment). The generator guarantees these prefixes.
fn label_for_extid(id: &str) -> &'static str {
    if let Some(rest) = id.strip_prefix("po") {
        debug_assert!(rest.chars().all(|c| c.is_ascii_digit()));
        "Post"
    } else if id.starts_with('p') {
        "Person"
    } else if id.starts_with('f') {
        "Forum"
    } else if id.starts_with('c') {
        "Comment"
    } else {
        panic!("unknown external-id prefix: {id}")
    }
}

/// Builds the `{...}` property map body for one CSV row given its column roles, and returns the id
/// cell separately (so a relationship row can match its endpoints).
fn row_props(cols: &[Col], row: &str) -> (Option<String>, String) {
    let cells: Vec<&str> = row.split(',').collect();
    let mut props: Vec<String> = Vec::new();
    let mut id: Option<String> = None;
    for (col, cell) in cols.iter().zip(&cells) {
        let cell = *cell;
        match col {
            Col::Ignore => {}
            Col::Id => {
                id = Some(cell.to_owned());
                props.push(format!("id: {}", cy_str(cell)));
            }
            Col::IntProp(k) => props.push(format!("{k}: {cell}")),
            Col::StrProp(k) => props.push(format!("{k}: {}", cy_str(cell))),
            Col::StrListProp(k) => {
                let list = if cell.is_empty() {
                    "[]".to_owned()
                } else {
                    let items: Vec<String> = cell.split(';').map(cy_str).collect();
                    format!("[{}]", items.join(", "))
                };
                props.push(format!("{k}: {list}"));
            }
        }
    }
    (id, format!("{{{}}}", props.join(", ")))
}

/// The Cypher `CREATE` / `MATCH … CREATE` statements that load the seeded graph, schema-first order:
/// all node CREATEs (batched per label), then one relationship `MATCH … CREATE` per edge (endpoints
/// resolved to their label + external id).
fn data_statements(dataset: &Dataset) -> Vec<String> {
    let mut out = Vec::new();

    // Nodes, batched per label (≤ 40 fragments per statement) for a brisk load.
    for nf in &dataset.node_files {
        let mut lines = nf.csv.lines();
        let cols = parse_header(lines.next().expect("node header"));
        let mut frags: Vec<String> = Vec::new();
        for row in lines.filter(|l| !l.is_empty()) {
            let (_, body) = row_props(&cols, row);
            frags.push(format!("(:{} {body})", nf.label));
        }
        for chunk in frags.chunks(40) {
            out.push(format!("CREATE {}", chunk.join(", ")));
        }
    }

    // Relationships, one per statement: match both endpoints by (label, id), then create the typed edge.
    for rf in &dataset.rel_files {
        let mut lines = rf.csv.lines();
        let header = lines.next().expect("rel header");
        let cols = parse_header(header);
        for row in lines.filter(|l| !l.is_empty()) {
            let cells: Vec<&str> = row.split(',').collect();
            let start = cells[0];
            let end = cells[1];
            let (_, body) = row_props(&cols, row);
            out.push(format!(
                "MATCH (a:{sl} {{id: {sid}}}), (b:{el} {{id: {eid}}}) \
                 CREATE (a)-[:{ty} {body}]->(b)",
                sl = label_for_extid(start),
                sid = cy_str(start),
                el = label_for_extid(end),
                eid = cy_str(end),
                ty = rf.rel_type,
            ));
        }
    }

    out
}

/// Loads the seeded graph **schema-first** through the real engine: the manifest's `implied_schema`
/// DDL runs through the admin-DDL command path (as the Bolt/REST admin seams do), then the data CREATEs
/// load inside a single write transaction — so each index is maintained + promoted Online as the writes
/// land and every write is constraint-checked. Asserts the load succeeds (every seed value conforms).
fn load_schema_first() -> (Eng, Dataset) {
    let dataset = generate(cfg(), "hermetic");
    let mut eng = engine();

    // 1. Apply the documented production schema, verbatim, through the admin path.
    assert_eq!(
        dataset.manifest.implied_schema.len(),
        10,
        "the manifest documents the full ten-statement palette"
    );
    for stmt in &dataset.manifest.implied_schema {
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

    // 2. Load the data with the schema active — every write is constraint-checked and index-maintained.
    let ticket = eng.begin(AccessMode::Write).expect("begin load txn");
    for stmt in data_statements(&dataset) {
        let mut reply = eng
            .run(ticket, &stmt, Vec::new(), false, None)
            .unwrap_or_else(|e| {
                panic!("load statement failed (data does not conform?): {stmt}\n  {e}")
            });
        while let Ok(Some(_)) = reply.rows.next() {}
    }
    eng.commit(ticket).expect("commit load txn");

    (eng, dataset)
}

// =================================================================================================
// Ground truth read straight from the deterministic generator.
// =================================================================================================

/// `(post external id, content, createdAt)` for every generated post, in id order.
fn posts(dataset: &Dataset) -> Vec<(String, String, i64)> {
    let pf = dataset
        .node_files
        .iter()
        .find(|n| n.label == "Post")
        .expect("a posts file");
    let mut lines = pf.csv.lines();
    let cols = parse_header(lines.next().expect("post header"));
    // Column order: id, content, length, createdAt, language.
    lines
        .filter(|l| !l.is_empty())
        .map(|row| {
            let cells: Vec<&str> = row.split(',').collect();
            let mut id = String::new();
            let mut content = String::new();
            let mut created = 0i64;
            for (col, cell) in cols.iter().zip(&cells) {
                match col {
                    Col::Id => id = (*cell).to_owned(),
                    Col::StrProp(k) if k == "content" => content = (*cell).to_owned(),
                    Col::IntProp(k) if k == "createdAt" => {
                        created = cell.parse().expect("createdAt int")
                    }
                    _ => {}
                }
            }
            (id, content, created)
        })
        .collect()
}

// =================================================================================================
// SHOW helpers (full column sets), column/row accessors, planner + read helpers.
// =================================================================================================

fn show_indexes(eng: &mut Eng) -> IndexDdlReply {
    eng.index_ddl(IndexCommand::ShowIndexes {
        filter: IndexTypeFilter::All,
        tail: None,
    })
    .expect("show indexes")
}

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
        .unwrap_or_else(|| panic!("a row named `{name}` in {:?}", reply.rows))
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

/// Collects the single string column of a read query into a sorted, de-duplicated set.
fn collect_strings(eng: &mut Eng, query: &str) -> Vec<String> {
    let ticket = eng.begin(AccessMode::Read).expect("begin read txn");
    let mut reply = eng
        .run(ticket, query, Vec::new(), false, None)
        .expect("query runs");
    let mut out = Vec::new();
    while let Ok(Some(row)) = reply.rows.next() {
        if let Some(MaterializedValue::Value(Value::String(s))) = row.first() {
            out.push(s.clone());
        }
    }
    eng.commit(ticket).expect("commit read txn");
    out.sort();
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

// =================================================================================================
// Tests (each on a big stack).
// =================================================================================================

#[test]
fn schema_first_load_declares_new_index_and_constraint_kinds() {
    on_big_stack(schema_first_load_declares_new_index_and_constraint_kinds_impl);
}

#[test]
fn schema_enforces_constraints_with_negative_writes() {
    on_big_stack(schema_enforces_constraints_with_negative_writes_impl);
}

#[test]
fn index_query_paths_return_correct_results_and_are_utilised() {
    on_big_stack(index_query_paths_return_correct_results_and_are_utilised_impl);
}

fn schema_first_load_declares_new_index_and_constraint_kinds_impl() {
    let (mut eng, _dataset) = load_schema_first();

    // ---- SHOW INDEXES: the TEXT + FULLTEXT + composite RANGE + the two always-on LOOKUP indexes. ----
    let idx = show_indexes(&mut eng);
    let (type_c, entity_c, labels_c, props_c, state_c) = (
        col(&idx, "type"),
        col(&idx, "entityType"),
        col(&idx, "labelsOrTypes"),
        col(&idx, "properties"),
        col(&idx, "state"),
    );

    // The two always-on token LOOKUP indexes Neo4j always lists — a NODE and a RELATIONSHIP one.
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

    // TEXT (trigram) index on Post.content.
    let text = row_by_name(&idx, "post_content_text");
    assert_eq!(
        text[type_c],
        Value::String("TEXT".to_owned()),
        "TEXT is a distinct native string index, not a RANGE synonym"
    );
    assert_eq!(text[entity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        text[labels_c],
        Value::List(vec![Value::String("Post".to_owned())])
    );
    assert_eq!(
        text[props_c],
        Value::List(vec![Value::String("content".to_owned())])
    );
    assert_eq!(text[state_c], Value::String("ONLINE".to_owned()));

    // FULLTEXT (analyzer-tokenized) index on Post.content.
    let ft = row_by_name(&idx, "post_content_fulltext");
    assert_eq!(
        ft[type_c],
        Value::String("FULLTEXT".to_owned()),
        "FULLTEXT is a distinct analyzer-tokenized index, not a RANGE/TEXT synonym"
    );
    assert_eq!(ft[entity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        ft[props_c],
        Value::List(vec![Value::String("content".to_owned())])
    );
    assert_eq!(
        ft[state_c],
        Value::String("ONLINE".to_owned()),
        "the FULLTEXT index must be Online after the schema-first load"
    );

    // Composite RANGE index on Post(createdAt, id) — the ordered two-property tuple.
    let composite = row_by_name(&idx, "post_catalog_composite");
    assert_eq!(composite[type_c], Value::String("RANGE".to_owned()));
    assert_eq!(composite[entity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        composite[props_c],
        Value::List(vec![
            Value::String("createdAt".to_owned()),
            Value::String("id".to_owned()),
        ]),
        "the composite index covers (createdAt, id) in declared order"
    );
    assert_eq!(composite[state_c], Value::String("ONLINE".to_owned()));

    // ---- SHOW CONSTRAINTS: the NODE KEY, composite UNIQUE, two UNIQUEs, node + rel property-type,
    //      and the rel existence — full column set. ----
    let cons = show_constraints(&mut eng);
    let (ctype_c, centity_c, clabels_c, cprops_c, cptype_c) = (
        col(&cons, "type"),
        col(&cons, "entityType"),
        col(&cons, "labelsOrTypes"),
        col(&cons, "properties"),
        col(&cons, "propertyType"),
    );

    // NODE KEY on Person.id (the upgrade from the documented UNIQUE).
    let key = row_by_name(&cons, "person_id_key");
    assert_eq!(key[ctype_c], Value::String("NODE_KEY".to_owned()));
    assert_eq!(key[centity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        key[clabels_c],
        Value::List(vec![Value::String("Person".to_owned())])
    );
    assert_eq!(
        key[cprops_c],
        Value::List(vec![Value::String("id".to_owned())])
    );

    // Composite UNIQUE on Post(id, createdAt) — the tuple, in declared order.
    let post_uniq = row_by_name(&cons, "post_id_created_unique");
    assert_eq!(
        post_uniq[ctype_c],
        Value::String("NODE_PROPERTY_UNIQUENESS".to_owned())
    );
    assert_eq!(
        post_uniq[cprops_c],
        Value::List(vec![
            Value::String("id".to_owned()),
            Value::String("createdAt".to_owned()),
        ]),
        "the composite uniqueness covers (id, createdAt) in declared order"
    );

    // Forum.id / Comment.id kept as single-property UNIQUE.
    for name in ["forum_id_unique", "comment_id_unique"] {
        let r = row_by_name(&cons, name);
        assert_eq!(
            r[ctype_c],
            Value::String("NODE_PROPERTY_UNIQUENESS".to_owned()),
            "{name}"
        );
        assert_eq!(
            r[cprops_c],
            Value::List(vec![Value::String("id".to_owned())]),
            "{name}"
        );
    }

    // Node property-type: Post.length IS :: INTEGER.
    let post_len = row_by_name(&cons, "post_length_integer");
    assert_eq!(
        post_len[ctype_c],
        Value::String("NODE_PROPERTY_TYPE".to_owned())
    );
    assert_eq!(
        post_len[cptype_c],
        Value::String("INTEGER".to_owned()),
        "the declared node property type is INTEGER"
    );

    // Relationship existence: LIKES.creationDate IS NOT NULL.
    let rel_exists = row_by_name(&cons, "likes_created_exists");
    assert_eq!(
        rel_exists[ctype_c],
        Value::String("RELATIONSHIP_PROPERTY_EXISTENCE".to_owned())
    );
    assert_eq!(
        rel_exists[centity_c],
        Value::String("RELATIONSHIP".to_owned())
    );
    assert_eq!(
        rel_exists[clabels_c],
        Value::List(vec![Value::String("LIKES".to_owned())])
    );

    // Relationship property-type: HAS_CREATOR.weight IS :: INTEGER.
    let rel_type = row_by_name(&cons, "has_creator_weight_integer");
    assert_eq!(
        rel_type[ctype_c],
        Value::String("RELATIONSHIP_PROPERTY_TYPE".to_owned())
    );
    assert_eq!(
        rel_type[centity_c],
        Value::String("RELATIONSHIP".to_owned())
    );
    assert_eq!(
        rel_type[cptype_c],
        Value::String("INTEGER".to_owned()),
        "the declared relationship property type is INTEGER (weight is an i64)"
    );
}

fn schema_enforces_constraints_with_negative_writes_impl() {
    let (mut eng, dataset) = load_schema_first();
    let all_posts = posts(&dataset);
    let post_count = all_posts.len() as i64;
    let (po0_id, _, po0_created) = &all_posts[0];
    assert_eq!(po0_id, "po0");

    // Composite UNIQUE: a second Post with the SAME (id, createdAt) tuple is rejected. (A different
    // createdAt would be a distinct, permitted tuple — this proves the composite key, not a bare id.)
    let dup_tuple = expect_rejected(
        &mut eng,
        &format!(
            "CREATE (:Post {{id: 'po0', content: 'dup', length: 1, createdAt: {po0_created}, language: 'en'}})"
        ),
    );
    assert!(
        dup_tuple.contains(CONSTRAINT_VIOLATION_PREFIX),
        "a duplicate composite (id, createdAt) tuple must be a constraint violation, got: {dup_tuple}"
    );

    // NODE KEY (uniqueness half): a duplicate Person.id is rejected.
    let dup_person = expect_rejected(
        &mut eng,
        "CREATE (:Person {id: 'p0', firstName: 'Dup', lastName: 'Dup', gender: 'female', \
         age: 30, locationIP: '0.0.0.0', browserUsed: 'Firefox', tags: ['rust']})",
    );
    assert!(
        dup_person.contains(CONSTRAINT_VIOLATION_PREFIX),
        "a duplicate Person.id (NODE KEY) must be a constraint violation, got: {dup_person}"
    );

    // Relationship existence: a LIKES edge without `creationDate` is rejected.
    let missing_date = expect_rejected(
        &mut eng,
        "MATCH (a:Person {id: 'p0'}), (b:Post {id: 'po0'}) CREATE (a)-[:LIKES]->(b)",
    );
    assert!(
        missing_date.contains(CONSTRAINT_VIOLATION_PREFIX),
        "a LIKES edge missing creationDate (existence) must be a constraint violation, got: {missing_date}"
    );

    // Relationship property-type: a non-integer HAS_CREATOR.weight is rejected.
    let wrong_weight = expect_rejected(
        &mut eng,
        "MATCH (a:Post {id: 'po0'}), (b:Person {id: 'p0'}) \
         CREATE (a)-[:HAS_CREATOR {weight: 'heavy'}]->(b)",
    );
    assert!(
        wrong_weight.contains(CONSTRAINT_VIOLATION_PREFIX),
        "a non-integer HAS_CREATOR.weight must be a constraint violation, got: {wrong_weight}"
    );

    // The rejected writes rolled back — the Post count is unchanged from the load.
    let count = scalar_int(&mut eng, "MATCH (p:Post) RETURN count(p) AS c");
    assert_eq!(
        count, post_count,
        "the rejected writes created nothing (Post count unchanged)"
    );
}

fn index_query_paths_return_correct_results_and_are_utilised_impl() {
    let (mut eng, dataset) = load_schema_first();
    let all_posts = posts(&dataset);

    // ---- TEXT CONTAINS: a substring search returns exactly the generator's matching post set. ----
    let substr = "content-1";
    let mut expected_contains: Vec<String> = all_posts
        .iter()
        .filter(|(_, content, _)| content.contains(substr))
        .map(|(id, _, _)| id.clone())
        .collect();
    expected_contains.sort();
    expected_contains.dedup();
    assert!(
        expected_contains.len() > 1,
        "the substring '{substr}' must match multiple posts to exercise a set search (matched {})",
        expected_contains.len()
    );
    let via_text = collect_strings(
        &mut eng,
        &format!("MATCH (p:Post) WHERE p.content CONTAINS '{substr}' RETURN p.id AS id"),
    );
    assert_eq!(
        via_text, expected_contains,
        "TEXT CONTAINS '{substr}' must return exactly the generator's matching post set"
    );

    // The TEXT index is utilised by the real planner (a `NodeTextIndexSeek`, not a scan + filter).
    let text_catalog = IndexCatalog::builder()
        .with_label_text("Post", "content")
        .build();
    let text_plan = plan(
        "MATCH (p:Post) WHERE p.content CONTAINS 'content-1' RETURN p.id",
        &text_catalog,
    );
    let text_render = text_plan.to_string();
    assert!(
        text_render.contains("NodeTextIndexSeek"),
        "a CONTAINS predicate must lower to a NodeTextIndexSeek:\n{text_render}"
    );

    // ---- FULLTEXT queryNodes: the shared `content` token returns the whole post population. ----
    let mut all_post_ids: Vec<String> = all_posts.iter().map(|(id, _, _)| id.clone()).collect();
    all_post_ids.sort();
    all_post_ids.dedup();
    let via_ft_all = collect_strings(
        &mut eng,
        "CALL db.index.fulltext.queryNodes('post_content_fulltext', 'content') \
         YIELD node RETURN node.id AS id",
    );
    assert_eq!(
        via_ft_all, all_post_ids,
        "FULLTEXT queryNodes('content') returns every indexed post (the shared 'content' token)"
    );

    // A unique whole-number token returns exactly the one post it names (the analyzer splits
    // `post-content-7` into [post, content, 7], so the token `7` names only `po7`).
    let ft_seven = collect_strings(
        &mut eng,
        "CALL db.index.fulltext.queryNodes('post_content_fulltext', '7') \
         YIELD node RETURN node.id AS id",
    );
    assert_eq!(
        ft_seven,
        vec!["po7".to_owned()],
        "FULLTEXT queryNodes('7') returns exactly po7 (its unique number token)"
    );

    // An absent term matches nothing.
    let ft_none = collect_strings(
        &mut eng,
        "CALL db.index.fulltext.queryNodes('post_content_fulltext', 'zzznotaword') \
         YIELD node RETURN node.id AS id",
    );
    assert!(
        ft_none.is_empty(),
        "a term no post content contains matches nothing"
    );

    // ---- Composite seek: an equality on (createdAt, id) returns the right post. ----
    // Pick a real seeded post and seek it by its full composite tuple.
    let (target_id, _, target_created) = &all_posts[7];
    assert_eq!(target_id, "po7");
    let via_composite = collect_strings(
        &mut eng,
        &format!(
            "MATCH (p:Post) WHERE p.createdAt = {target_created} AND p.id = '{target_id}' RETURN p.id AS id"
        ),
    );
    assert_eq!(
        via_composite,
        vec![target_id.clone()],
        "a composite (createdAt, id) equality seek returns exactly the named post"
    );

    // Correctness cross-check on the leading key alone: every post sharing a createdAt is returned.
    let mut by_created: BTreeMap<i64, Vec<String>> = BTreeMap::new();
    for (id, _, created) in &all_posts {
        by_created.entry(*created).or_default().push(id.clone());
    }
    let mut leading_expected = by_created[target_created].clone();
    leading_expected.sort();
    let via_leading = collect_strings(
        &mut eng,
        &format!("MATCH (p:Post) WHERE p.createdAt = {target_created} RETURN p.id AS id"),
    );
    assert_eq!(
        via_leading, leading_expected,
        "a leading-key createdAt equality returns exactly the posts with that timestamp"
    );

    // The composite index is utilised by the real planner (a `NodeCompositeIndexSeek`).
    let composite_catalog = IndexCatalog::builder()
        .with_label_composite("Post", ["createdAt", "id"])
        .build();
    let composite_plan = plan(
        "MATCH (p:Post) WHERE p.createdAt = 1500000000 AND p.id = 'po7' RETURN p.id",
        &composite_catalog,
    );
    let composite_render = composite_plan.to_string();
    assert!(
        composite_render.contains("NodeCompositeIndexSeek"),
        "an equality on both composite keys must lower to a NodeCompositeIndexSeek:\n{composite_render}"
    );
}
