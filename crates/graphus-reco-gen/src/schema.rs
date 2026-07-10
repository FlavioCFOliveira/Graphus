//! The production-realistic **read-path schema** the `examples/product-recommendations` demonstration
//! declares once the graph is bulk-loaded — expressed as a single shared DDL block so the wire loader
//! (`reco_load`) and the hermetic server mirror
//! (`crates/graphus-server/tests/product_recommendations_schema.rs`) drive **byte-identical**
//! statements. A drift between the two would fail the mirror.
//!
//! The block declares, in application order:
//!
//! 1. a **`NODE KEY`** on `User.id` — present + unique customer identity; its backing 1-property
//!    composite index's leading key serves the `(:User {id: $id})` anchor **seek** every recommendation
//!    query starts from;
//! 2. a **`UNIQUE`** constraint on `Product.id` — unique catalogue identity; its single-property backing
//!    index serves the `(:Product {id: $id})` anchor seek (the write-path purchase + the k-NN node
//!    lookups) and rejects a duplicate product;
//! 3. a **property-type** constraint `Product.price IS :: INTEGER` — `price` is an integer number of
//!    cents, never a float (matching the generator's contract), enforced at write time;
//! 4. a **`TEXT`** (trigram) index on `Product.name` — accelerates `p.name CONTAINS '…'` catalogue
//!    search (the "find a product by a fragment of its name" query);
//! 5. a **`VECTOR`** (HNSW) index on `Product.embedding` (cosine, [`EMBED_DIM`] dimensions) — the modern
//!    recommendation-retrieval feature: `db.index.vector.queryNodes` finds the products nearest a query
//!    vector (a category centroid ⇒ that category's "similar products").
//!
//! Every statement is verified against the `graphus-server` admin matcher: the hermetic mirror parses
//! this exact block off `graphus_server::admin::parse_admin_statement` and drives it through the real
//! engine's typed `index_ddl` / `constraint_ddl` seam.

use crate::EMBED_DIM;

/// The `NODE KEY` constraint name on `User.id` (present + unique).
pub const USER_ID_KEY: &str = "user_id_key";
/// The `UNIQUE` constraint name on `Product.id`.
pub const PRODUCT_ID_UNIQUE: &str = "product_id_unique";
/// The property-type constraint name on `Product.price` (`IS :: INTEGER`).
pub const PRODUCT_PRICE_INTEGER: &str = "product_price_integer";
/// The `TEXT` index name on `Product.name` — accelerates `CONTAINS` catalogue search.
pub const PRODUCT_NAME_TEXT: &str = "product_name_text";
/// The `VECTOR` (HNSW) index name on `Product.embedding` — the `db.index.vector.queryNodes` handle.
pub const PRODUCT_EMBEDDING_VECTOR: &str = "product_embedding";

/// The cosine similarity function the vector index uses (the ANN metric for "similar products").
pub const VECTOR_SIMILARITY: &str = "cosine";

/// The schema DDL statements in application order (see the [module docs](self)). Each is a complete,
/// self-contained admin statement (no trailing `;`), ready to submit over `POST /db/{db}/tx/commit` or
/// to parse through `parse_admin_statement`. The `VECTOR` index's `vector.dimensions` is bound to
/// [`EMBED_DIM`], so the DDL and the generated embeddings can never disagree.
#[must_use]
pub fn schema_ddl() -> Vec<String> {
    vec![
        format!("CREATE CONSTRAINT {USER_ID_KEY} FOR (u:User) REQUIRE u.id IS NODE KEY"),
        format!("CREATE CONSTRAINT {PRODUCT_ID_UNIQUE} FOR (p:Product) REQUIRE p.id IS UNIQUE"),
        format!(
            "CREATE CONSTRAINT {PRODUCT_PRICE_INTEGER} FOR (p:Product) REQUIRE p.price IS :: INTEGER"
        ),
        format!("CREATE TEXT INDEX {PRODUCT_NAME_TEXT} FOR (p:Product) ON (p.name)"),
        format!(
            "CREATE VECTOR INDEX {PRODUCT_EMBEDDING_VECTOR} FOR (p:Product) ON (p.embedding) \
             OPTIONS {{ indexConfig: {{ `vector.dimensions`: {EMBED_DIM}, \
             `vector.similarity_function`: '{VECTOR_SIMILARITY}' }} }}"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_ddl_is_the_five_expected_statements() {
        let ddl = schema_ddl();
        assert_eq!(ddl.len(), 5, "five schema statements");
        assert!(ddl[0].starts_with("CREATE CONSTRAINT") && ddl[0].contains("IS NODE KEY"));
        assert!(ddl[1].contains("IS UNIQUE"));
        assert!(ddl[2].contains("IS :: INTEGER"));
        assert!(ddl[3].starts_with("CREATE TEXT INDEX"));
        assert!(ddl[4].starts_with("CREATE VECTOR INDEX"));
    }

    #[test]
    fn vector_ddl_binds_the_embedding_dimension() {
        let vector = &schema_ddl()[4];
        assert!(
            vector.contains(&format!("`vector.dimensions`: {EMBED_DIM}")),
            "the VECTOR DDL must bind vector.dimensions to EMBED_DIM: {vector}"
        );
        assert!(
            vector.contains("`vector.similarity_function`: 'cosine'"),
            "cosine similarity: {vector}"
        );
    }
}
