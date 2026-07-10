//! Hermetic cargo exercise of the `examples/product-recommendations` **schema** (`rmp` #676).
//!
//! Where the example's `reco_bench` proves the *read-concurrency* behaviour over a bulk-loaded graph,
//! this test proves the production-realistic **recommendation-retrieval schema** the example now
//! declares actually works end-to-end, hermetically (no Bolt, no server, no network): it plants a small
//! deterministic set of `Product`s (with the generator's **category-clustered embeddings**) and a few
//! `User`s, then drives the shared [`graphus_reco_gen::schema::schema_ddl`] block — the exact DDL the
//! wire loader submits — through the REAL engine via the admin-DDL command path (`parse_admin_statement`
//! → `LocalEngine::{index_ddl, constraint_ddl}`), **data-first** (as the example does: bulk-load, then
//! declare the schema, so the synchronous `VECTOR`/`TEXT`/constraint builds scan the existing data), and
//! asserts:
//!
//! - the new index & constraint kinds are declared and `Online` (`SHOW INDEXES` / `SHOW CONSTRAINTS`):
//!   a **`VECTOR`** (HNSW) index on `Product.embedding` (entity `NODE`, cosine), a **`TEXT`** (trigram)
//!   index on `Product.name`, and the identity/type constraints — a **`NODE KEY`** on `User.id`, a node
//!   **`UNIQUE`** on `Product.id`, and a node **property-type** (`Product.price IS :: INTEGER`);
//! - the **vector k-NN "similar products" seek** (`db.index.vector.queryNodes`): a query at a product's
//!   own embedding returns that exact product nearest (cosine self-similarity `1.0`), and a query at a
//!   category **centroid** returns exactly that category's products — the wide-margin cluster separation
//!   the recommendation feature depends on, asserted against the known ground truth;
//! - the **`TEXT` `CONTAINS` search**: a fragment of a product's name returns exactly the products whose
//!   name contains it (derived deterministically from the generator);
//! - **constraint enforcement**: a duplicate `Product.id` (UNIQUE), a duplicate `User.id` (NODE KEY),
//!   and a non-integer `Product.price` (property-type) are each rejected with the constraint-violation
//!   error class, and the rejected writes leave the counts unchanged.
//!
//! Determining the substrate empirically (`rmp` #676 asked): `LocalEngine::run` does **not** accept DDL
//! strings (admin DDL is intercepted before the Cypher pipeline), but `LocalEngine` fully supports admin
//! DDL through its typed `index_ddl` / `constraint_ddl` methods and serves the vector procedure
//! `db.index.vector.queryNodes` + `CONTAINS` through its normal query path — so the whole exercise runs
//! in-process against the real coordinator, no booted server required. This is the string-form
//! counterpart of the DDL the `reco_load` wire loader submits: both drive the identical
//! [`graphus_reco_gen::schema::schema_ddl`], so a drift between the two would fail here.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;

use graphus_core::Value;
use graphus_cypher::{CONSTRAINT_VIOLATION_PREFIX, MaterializedValue};
use graphus_io::MemBlockDevice;
use graphus_reco_gen::{EMBED_DIM, Generator};
use graphus_server::admin::{AdminParse, parse_admin_statement};
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{
    ConstraintCommand, ConstraintTypeFilter, IndexCommand, IndexDdlReply, IndexTypeFilter,
    LocalEngine,
};
use graphus_sim::SharedClock;
use graphus_wal::MemLogSink;

type Eng = LocalEngine<MemBlockDevice, MemLogSink>;

/// The seed for the planted catalogue (fixed ⇒ deterministic ground truth).
const SEED: u64 = 0x5EED_5EC0_0000_0676;
/// How many `Product`s to plant. Enough that several categories are well-populated (≈ 6 per category
/// across [`EMBED_DIM`] categories) so the largest-cluster k-NN assertion is meaningful, yet small
/// enough to keep the in-process Cypher-`CREATE` load quick under a default `cargo test`.
const PRODUCTS: u64 = 60;
/// A few `User`s so the `NODE KEY` on `User.id` has data (and a duplicate can be rejected).
const USERS: u64 = 5;

/// Builds an in-memory engine with a fixed clock — the deterministic, hermetic substrate.
fn engine() -> Eng {
    LocalEngine::in_memory(Arc::new(SharedClock::new(0)), 1024).expect("in-memory engine")
}

/// Whether `stmt` is a schema-DDL statement (any `CREATE CONSTRAINT` or any `CREATE … INDEX` form,
/// including `CREATE VECTOR INDEX` / `CREATE TEXT INDEX`).
fn is_schema_ddl(stmt: &str) -> bool {
    stmt.starts_with("CREATE CONSTRAINT")
        || (stmt.starts_with("CREATE") && stmt.contains(" INDEX "))
}

/// Formats an `f32` slice as a Cypher list literal (`[1.023, 0.007, …]`); `{x:?}` keeps a decimal point
/// so each element lexes as a `Float`.
fn cypher_f32_list(v: &[f32]) -> String {
    let elems: Vec<String> = v.iter().map(|x| format!("{x:?}")).collect();
    format!("[{}]", elems.join(", "))
}

/// The map `category index → planted product indices`, in ascending index order.
fn category_clusters() -> BTreeMap<usize, Vec<u64>> {
    let mut clusters: BTreeMap<usize, Vec<u64>> = BTreeMap::new();
    for i in 0..PRODUCTS {
        clusters
            .entry(Generator::product_category_index(SEED, i))
            .or_default()
            .push(i);
    }
    clusters
}

/// Loads the planted catalogue **data-first, then the schema** (the example's order), through the real
/// engine: `USERS` users + `PRODUCTS` products (each carrying its generator category-clustered
/// embedding) load inside one write transaction, then every [`graphus_reco_gen::schema::schema_ddl`]
/// statement runs through the admin-DDL command path (as the Bolt/REST admin seams do) so the
/// synchronous `VECTOR` / `TEXT` / constraint builds scan the just-loaded data. Asserts the load and the
/// schema declaration both succeed — i.e. **every planted value conforms to every constraint**.
fn load_data_then_schema() -> Eng {
    let mut eng = engine();

    // 1. Load the catalogue (data-first, as the bulk-import example does).
    let ticket = eng.begin(AccessMode::Write).expect("begin load txn");
    for u in 0..USERS {
        let id = Generator::user_id(u);
        let stmt = format!("CREATE (:User {{id: '{id}'}})");
        let mut reply = eng
            .run(ticket, &stmt, Vec::new(), false, None)
            .unwrap_or_else(|e| panic!("user load failed: {stmt}\n  {e}"));
        while let Ok(Some(_)) = reply.rows.next() {}
    }
    for i in 0..PRODUCTS {
        let id = Generator::product_id(i);
        let name = Generator::product_name(SEED, i);
        let category = Generator::category_name(Generator::product_category_index(SEED, i));
        // A deterministic integer price (cents) — the exact value is irrelevant to the schema, only
        // that it is an INTEGER (the property-type constraint's contract).
        let price = 199 + i as i64;
        let embedding = cypher_f32_list(&Generator::product_embedding(SEED, i));
        // Names come from a comma-free pool, but escape a stray apostrophe defensively for the literal.
        let name = name.replace('\'', "\\'");
        let stmt = format!(
            "CREATE (:Product {{id: '{id}', name: '{name}', category: '{category}', \
             price: {price}, embedding: {embedding}}})"
        );
        let mut reply = eng
            .run(ticket, &stmt, Vec::new(), false, None)
            .unwrap_or_else(|e| panic!("product load failed: {stmt}\n  {e}"));
        while let Ok(Some(_)) = reply.rows.next() {}
    }
    eng.commit(ticket).expect("commit load txn");

    // 2. Declare the schema over the loaded data (each an auto-commit control command).
    let ddl = graphus_reco_gen::schema::schema_ddl();
    assert_eq!(
        ddl.len(),
        5,
        "the schema DDL is the five expected statements"
    );
    assert!(ddl.iter().all(|s| is_schema_ddl(s)), "all DDL: {ddl:?}");
    for stmt in &ddl {
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

/// Runs the vector k-NN procedure and returns `(product id, score)` rows in the procedure's order
/// (nearest first).
fn knn(eng: &mut Eng, query: &[f32], k: usize) -> Vec<(String, f64)> {
    let src = format!(
        "CALL db.index.vector.queryNodes('{}', {k}, {}) YIELD node, score \
         RETURN node.id AS id, score",
        graphus_reco_gen::schema::PRODUCT_EMBEDDING_VECTOR,
        cypher_f32_list(query),
    );
    let ticket = eng.begin(AccessMode::Read).expect("begin read txn");
    let mut reply = eng
        .run(ticket, &src, Vec::new(), false, None)
        .expect("k-NN query runs");
    let mut out = Vec::new();
    while let Ok(Some(row)) = reply.rows.next() {
        let id = match row.first() {
            Some(MaterializedValue::Value(Value::String(s))) => s.clone(),
            other => panic!("node.id must be a string, got {other:?}"),
        };
        let score = match row.get(1) {
            Some(MaterializedValue::Value(Value::Float(f))) => *f,
            other => panic!("score must be a float, got {other:?}"),
        };
        out.push((id, score));
    }
    eng.commit(ticket).expect("commit read txn");
    out
}

/// Collects the single string `id` column of a read query into a sorted, de-duplicated set.
fn collect_ids(eng: &mut Eng, query: &str) -> Vec<String> {
    let ticket = eng.begin(AccessMode::Read).expect("begin read txn");
    let mut reply = eng
        .run(ticket, query, Vec::new(), false, None)
        .expect("query runs");
    let mut ids = Vec::new();
    while let Ok(Some(row)) = reply.rows.next() {
        if let Some(MaterializedValue::Value(Value::String(s))) = row.first() {
            ids.push(s.clone());
        }
    }
    eng.commit(ticket).expect("commit read txn");
    ids.sort();
    ids.dedup();
    ids
}

/// A single scalar integer (e.g. a `count(…)`).
fn scalar_int(eng: &mut Eng, query: &str) -> i64 {
    let ticket = eng.begin(AccessMode::Read).expect("begin read txn");
    let mut reply = eng
        .run(ticket, query, Vec::new(), false, None)
        .expect("query runs");
    let got = match reply.rows.next() {
        Ok(Some(row)) => match row.first() {
            Some(MaterializedValue::Value(Value::Integer(n))) => *n,
            other => panic!("expected an integer scalar, got {other:?}"),
        },
        other => panic!("expected one row for `{query}`, got {other:?}"),
    };
    eng.commit(ticket).expect("commit read txn");
    got
}

#[test]
fn schema_declares_the_vector_text_and_constraint_kinds() {
    let mut eng = load_data_then_schema();

    // ---- SHOW INDEXES: the new VECTOR + TEXT indexes and the constraint-backed identity indexes. ----
    let idx = show_indexes(&mut eng);
    let (type_c, entity_c, labels_c, props_c, state_c) = (
        col(&idx, "type"),
        col(&idx, "entityType"),
        col(&idx, "labelsOrTypes"),
        col(&idx, "properties"),
        col(&idx, "state"),
    );

    // VECTOR (HNSW) node index on Product.embedding — the headline recommendation-retrieval feature.
    let vector = row_by_name(&idx, "product_embedding");
    assert_eq!(
        vector[type_c],
        Value::String("VECTOR".to_owned()),
        "VECTOR is a distinct ANN index, not a RANGE synonym"
    );
    assert_eq!(
        vector[entity_c],
        Value::String("NODE".to_owned()),
        "the product_embedding index is a NODE index"
    );
    assert_eq!(
        vector[labels_c],
        Value::List(vec![Value::String("Product".to_owned())])
    );
    assert_eq!(
        vector[props_c],
        Value::List(vec![Value::String("embedding".to_owned())])
    );
    assert_eq!(
        vector[state_c],
        Value::String("ONLINE".to_owned()),
        "the synchronously-built VECTOR index must be Online after the data-first schema declaration"
    );

    // TEXT (trigram) node index on Product.name.
    let text = row_by_name(&idx, "product_name_text");
    assert_eq!(
        text[type_c],
        Value::String("TEXT".to_owned()),
        "TEXT is a distinct native string index, not a RANGE synonym"
    );
    assert_eq!(text[entity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        text[props_c],
        Value::List(vec![Value::String("name".to_owned())])
    );
    assert_eq!(text[state_c], Value::String("ONLINE".to_owned()));

    // The identity constraints (User.id NODE KEY, Product.id UNIQUE) back the `(:User {id})` /
    // `(:Product {id})` anchor seeks through the in-memory index set, but — like every constraint
    // backing in Graphus — they are surfaced under `SHOW CONSTRAINTS`, not `SHOW INDEXES` (which lists
    // only the durable *index* declarations: the two always-on LOOKUP indexes plus the TEXT + VECTOR
    // indexes here). So `SHOW INDEXES` lists exactly those four, and no constraint-backing row.
    assert_eq!(
        idx.rows.len(),
        4,
        "SHOW INDEXES lists exactly: 2 LOOKUP + TEXT + VECTOR (constraint backings are not listed): {:?}",
        idx.rows
    );

    // ---- SHOW CONSTRAINTS: the NODE KEY, the node UNIQUE, and the property-type constraint. ----
    let cons = show_constraints(&mut eng);
    let (ctype_c, centity_c, cprops_c, cptype_c) = (
        col(&cons, "type"),
        col(&cons, "entityType"),
        col(&cons, "properties"),
        col(&cons, "propertyType"),
    );

    let key = row_by_name(&cons, "user_id_key");
    assert_eq!(key[ctype_c], Value::String("NODE_KEY".to_owned()));
    assert_eq!(key[centity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        key[cprops_c],
        Value::List(vec![Value::String("id".to_owned())])
    );

    let uniq = row_by_name(&cons, "product_id_unique");
    assert_eq!(
        uniq[ctype_c],
        Value::String("NODE_PROPERTY_UNIQUENESS".to_owned())
    );
    assert_eq!(uniq[centity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        uniq[cprops_c],
        Value::List(vec![Value::String("id".to_owned())])
    );

    let price_type = row_by_name(&cons, "product_price_integer");
    assert_eq!(
        price_type[ctype_c],
        Value::String("NODE_PROPERTY_TYPE".to_owned())
    );
    assert_eq!(price_type[centity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        price_type[cprops_c],
        Value::List(vec![Value::String("price".to_owned())])
    );
    assert_eq!(
        price_type[cptype_c],
        Value::String("INTEGER".to_owned()),
        "price is an integer number of cents, never a FLOAT"
    );
}

#[test]
fn vector_knn_returns_the_similar_products() {
    let mut eng = load_data_then_schema();
    let clusters = category_clusters();

    // The VECTOR index is really Online.
    {
        let idx = show_indexes(&mut eng);
        let state_c = col(&idx, "state");
        assert_eq!(
            row_by_name(&idx, "product_embedding")[state_c],
            Value::String("ONLINE".to_owned())
        );
    }

    // 1. Exact self-match: a query at a specific product's own embedding returns that product nearest,
    //    with a cosine self-similarity of 1.0 — the "find products like THIS one" retrieval.
    let probe = 0u64;
    let probe_id = Generator::product_id(probe);
    let hits = knn(&mut eng, &Generator::product_embedding(SEED, probe), 3);
    assert!(!hits.is_empty(), "the k-NN seek returned no products");
    assert_eq!(
        hits[0].0, probe_id,
        "a query at product {probe}'s own embedding must return it nearest: {hits:?}"
    );
    assert!(
        (hits[0].1 - 1.0).abs() < 1e-6,
        "the cosine self-similarity of the exact match is 1.0, got {}",
        hits[0].1
    );
    // Scores are descending (nearest first).
    for w in hits.windows(2) {
        assert!(
            w[0].1 >= w[1].1,
            "k-NN scores must be descending (nearest first): {hits:?}"
        );
    }

    // 2. Cluster separation: a query at the LARGEST category's centroid returns EXACTLY that category's
    //    products (k = the cluster size) — the wide-margin separation the "similar products" feature
    //    depends on. With one orthogonal axis per category, cross-category cosine (~0.02) is far below
    //    within-category (~0.99), so the k nearest are precisely the cluster.
    let (cat, members) = clusters
        .iter()
        .max_by_key(|(_, ids)| ids.len())
        .expect("at least one non-empty category");
    assert!(
        members.len() >= 3,
        "the largest category should have several products for a meaningful set assertion (had {})",
        members.len()
    );
    let mut expected: Vec<String> = members.iter().map(|&i| Generator::product_id(i)).collect();
    expected.sort();

    let centroid_hits = knn(&mut eng, &Generator::category_centroid(*cat), members.len());
    let mut got: Vec<String> = centroid_hits.iter().map(|(id, _)| id.clone()).collect();
    got.sort();
    got.dedup();
    assert_eq!(
        got, expected,
        "the k nearest to category {cat}'s centroid must be exactly that category's products"
    );
    // Every returned product really is of the queried category (belt-and-braces on the id→category map).
    let expected_category = Generator::category_name(*cat);
    for (id, _) in &centroid_hits {
        let i = (0..PRODUCTS)
            .find(|&i| &Generator::product_id(i) == id)
            .expect("a hit maps back to a planted product");
        assert_eq!(
            Generator::category_name(Generator::product_category_index(SEED, i)),
            expected_category,
            "a centroid hit ({id}) is not of the queried category"
        );
    }
}

#[test]
fn text_contains_returns_exactly_the_matching_products() {
    let mut eng = load_data_then_schema();

    // The TEXT index is really Online.
    {
        let idx = show_indexes(&mut eng);
        let state_c = col(&idx, "state");
        assert_eq!(
            row_by_name(&idx, "product_name_text")[state_c],
            Value::String("ONLINE".to_owned())
        );
    }

    // Product 0's name is `<noun> <adjective> [brand]`; its leading noun is a stable, comma-free
    // fragment guaranteed present. Compute the EXPECTED match set deterministically from the generator,
    // then assert the TEXT-index CONTAINS returns exactly it (not just a superset).
    let name0 = Generator::product_name(SEED, 0);
    let fragment = name0.split(' ').next().expect("a leading word").to_owned();
    let mut expected: Vec<String> = (0..PRODUCTS)
        .filter(|&i| Generator::product_name(SEED, i).contains(&fragment))
        .map(Generator::product_id)
        .collect();
    expected.sort();
    expected.dedup();
    assert!(
        expected.contains(&Generator::product_id(0)),
        "the fragment must at least match product 0"
    );

    let got = collect_ids(
        &mut eng,
        &format!("MATCH (p:Product) WHERE p.name CONTAINS '{fragment}' RETURN p.id AS id"),
    );
    assert_eq!(
        got, expected,
        "CONTAINS '{fragment}' over the TEXT-indexed product name must return exactly the matching products"
    );
}

#[test]
fn schema_enforces_constraints_with_negative_writes() {
    let mut eng = load_data_then_schema();

    // UNIQUE (Product.id): a duplicate product id is rejected.
    let existing_pid = Generator::product_id(0);
    let dup_product = expect_rejected(
        &mut eng,
        &format!(
            "CREATE (:Product {{id: '{existing_pid}', name: 'dup', category: 'x', price: 100, \
             embedding: {}}})",
            zeros_embedding()
        ),
    );
    assert!(
        dup_product.contains(CONSTRAINT_VIOLATION_PREFIX),
        "a duplicate Product.id must be a constraint violation, got: {dup_product}"
    );

    // NODE KEY (User.id, uniqueness half): a duplicate user id is rejected.
    let existing_uid = Generator::user_id(0);
    let dup_user = expect_rejected(
        &mut eng,
        &format!("CREATE (:User {{id: '{existing_uid}'}})"),
    );
    assert!(
        dup_user.contains(CONSTRAINT_VIOLATION_PREFIX),
        "a duplicate User.id must be a NODE KEY violation, got: {dup_user}"
    );

    // Property-type (Product.price IS :: INTEGER): a float price is rejected. A fresh, unique id keeps
    // the write's only defect the float price.
    let wrong_type = expect_rejected(
        &mut eng,
        &format!(
            "CREATE (:Product {{id: 'reco-neg-price-test', name: 'p', category: 'x', price: 9.99, \
             embedding: {}}})",
            zeros_embedding()
        ),
    );
    assert!(
        wrong_type.contains(CONSTRAINT_VIOLATION_PREFIX),
        "a non-integer Product.price must be a property-type violation, got: {wrong_type}"
    );

    // The rejected writes all rolled back — the counts are unchanged from the load.
    assert_eq!(
        scalar_int(&mut eng, "MATCH (p:Product) RETURN count(p) AS c"),
        PRODUCTS as i64,
        "the rejected products created nothing"
    );
    assert_eq!(
        scalar_int(&mut eng, "MATCH (u:User) RETURN count(u) AS c"),
        USERS as i64,
        "the rejected duplicate user created nothing"
    );
}

/// An all-zeros embedding of the right dimension for a negative-write literal (its value is irrelevant —
/// the write is rejected before the embedding is indexed, but it must be well-formed to reach the check).
fn zeros_embedding() -> String {
    let mut s = String::from("[");
    for d in 0..EMBED_DIM {
        if d > 0 {
            let _ = write!(s, ", ");
        }
        let _ = write!(s, "0.0");
    }
    s.push(']');
    s
}
