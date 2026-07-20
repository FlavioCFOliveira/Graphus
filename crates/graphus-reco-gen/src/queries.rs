//! The canonical **product-recommendation read battery** — the parameterised Cypher the example's
//! wire clients run. Defined once here so `reco_load`'s correctness asserts and `reco_bench`'s
//! concurrent load exercise byte-identical query text (which also lets the server's compiled-plan
//! cache reuse a single `Arc`-shared plan per family across every connection and every operation —
//! parameters vary, the text does not).
//!
//! # The workload it models
//!
//! A realistic read-heavy recommendation service: a large majority of **read** operations mixing
//! cheap **point reads** (a customer, their purchases, their friend count) with progressively heavier
//! **recommendation traversals**:
//!
//! - `r1_friends`  — products bought by a customer's **direct friends** that they have not bought,
//!   ranked by how many friends bought them (1-hop social + purchase join + anti-join + aggregation).
//! - `r2_fof`      — the same, one hop further out: **friend-of-friend** (2nd-level) reach.
//! - `r3_fof3`     — **3rd-level** reach (a deep 3-hop traversal — the heaviest read).
//! - `r4_similar`  — **customers with a similar consumption profile** (collaborative filtering /
//!   co-purchase): find users who bought many of the same products, then recommend what *they* bought
//!   that the seed customer has not — the classic "customers like you also bought" query.
//!
//! Every query anchors on `(:User {id: $id})`, so with a `:User(id)` index present the anchor is an
//! index **seek** (not a scan) regardless of graph size; `$id` varies per operation.
//!
//! The battery is **read-only**. The scenario's few, low-rate **writes** use [`WRITE_PURCHASE`],
//! kept separate so the read mix stays purely read-only and the writer's rate is controlled
//! independently.

/// What per-op parameters a family binds, how it must be **dispatched** so it genuinely hits its
/// declared index at runtime (`rmp` #746/#755), and how its result is verified.
///
/// The dispatch distinction is the crux of this task. An auto-commit read is sent to the **off-thread
/// reader pool**, whose seam declines every index seek and falls back to a full scan (`rmp` #755): the
/// *plan* still reports the seek operator, but the *execution* reads the whole store. A read inside an
/// **explicit transaction** runs inline on the engine thread and really seeks the index. So each family
/// declares the path that actually indexes it — verified empirically with `PROFILE` (`rmp` #752).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FamilyKind {
    /// Anchored on `(:User {id: $id})` — the traversal + point-read families. Runs **auto-commit**
    /// (their cost is the traversal, not the anchor seek; the anchor-seek decline is `rmp` #755's own
    /// fix, out of scope here). Binds `$id`.
    UserAnchored,
    /// The VECTOR (HNSW) k-NN **"similar products"** ANN retrieval — the primary retrieval path of a
    /// real recommendation service: `CALL db.index.vector.queryNodes($indexName, $k, $queryVector)`.
    /// `db.index.vector.queryNodes` is registered **not** reader-safe, so it runs **inline** on the
    /// engine thread even as an auto-commit read and hits the live HNSW regardless of dispatch (`rmp`
    /// #746, measured 25 dbHits vs a 700-node scan). Binds `$indexName`, `$k`, and `$queryVector` — a
    /// real `LIST<FLOAT>` Bolt parameter, **never** a string-formatted literal.
    VectorAnn,
    /// The TEXT (trigram) catalogue search `MATCH (p:Product) WHERE p.name CONTAINS $fragment`. A plain
    /// read with no procedure ⇒ auto-commit dispatches off-thread, where the reader pool **declines**
    /// the `NodeTextIndexSeek` and full-scans (`rmp` #755, measured 601 dbHits). It MUST run in an
    /// **explicit read transaction** to seek the index (measured 3 dbHits) — which is also the realistic
    /// production shape (`session.executeRead`). Binds `$fragment`.
    TextContains,
}

/// One query family in the read battery.
#[derive(Debug, Clone, Copy)]
pub struct QuerySpec {
    /// Stable family id, e.g. `"s_user"` / `"r1_friends"` (a metrics/report key).
    pub name: &'static str,
    /// The parameterised Cypher. A [`FamilyKind::UserAnchored`] family binds `$id`; the index-backed
    /// families bind their own parameters (see [`FamilyKind`]).
    pub cypher: &'static str,
    /// Relative selection weight in the read mix (larger = more frequent).
    pub weight: u32,
    /// Whether this is an **advanced** traversal (`true`) or a simple **point read** (`false`) — used
    /// only to group the per-family latencies in the report.
    pub advanced: bool,
    /// The parameter shape + dispatch + verification contract for this family (`rmp` #746).
    pub kind: FamilyKind,
}

/// The read battery, in a fixed order. Weights model a read-heavy service: ~45% cheap point reads,
/// ~55% recommendation traversals (with the heaviest 3-hop / collaborative-filtering families the
/// least frequent, as in a real service).
pub const READ_BATTERY: &[QuerySpec] = &[
    // --- Point reads (simple) ---------------------------------------------------------------------
    QuerySpec {
        name: "s_user",
        cypher: "MATCH (u:User {id: $id}) RETURN u.name AS name, u.country AS country",
        weight: 18,
        advanced: false,
        kind: FamilyKind::UserAnchored,
    },
    QuerySpec {
        name: "s_purchases",
        cypher: "MATCH (:User {id: $id})-[:PURCHASED]->(p:Product) \
                 RETURN p.id AS id, p.name AS name LIMIT 50",
        weight: 14,
        advanced: false,
        kind: FamilyKind::UserAnchored,
    },
    QuerySpec {
        name: "s_degree",
        cypher: "MATCH (u:User {id: $id})-[:FRIEND]-(f:User) RETURN count(f) AS degree",
        weight: 9,
        advanced: false,
        kind: FamilyKind::UserAnchored,
    },
    // --- Recommendation traversals (advanced) -----------------------------------------------------
    // Direct friends' purchases the customer has not bought, ranked by how many friends bought them.
    QuerySpec {
        name: "r1_friends",
        cypher: "MATCH (me:User {id: $id})-[:FRIEND]-(f:User)-[:PURCHASED]->(p:Product) \
                 WHERE NOT (me)-[:PURCHASED]->(p) \
                 RETURN p.id AS product, count(DISTINCT f) AS friends \
                 ORDER BY friends DESC, product ASC LIMIT 10",
        weight: 18,
        advanced: true,
        kind: FamilyKind::UserAnchored,
    },
    // Friend-of-friend (2nd level) reach: purchases of 2-hop friends (excluding self + direct friends).
    QuerySpec {
        name: "r2_fof",
        cypher: "MATCH (me:User {id: $id})-[:FRIEND]-(:User)-[:FRIEND]-(fof:User) \
                 WHERE fof.id <> $id AND NOT (me)-[:FRIEND]-(fof) \
                 MATCH (fof)-[:PURCHASED]->(p:Product) \
                 WHERE NOT (me)-[:PURCHASED]->(p) \
                 RETURN p.id AS product, count(DISTINCT fof) AS reach \
                 ORDER BY reach DESC, product ASC LIMIT 10",
        weight: 10,
        advanced: true,
        kind: FamilyKind::UserAnchored,
    },
    // Third-level reach: purchases of 3-hop friends (the heaviest social traversal).
    QuerySpec {
        name: "r3_fof3",
        cypher: "MATCH (me:User {id: $id})-[:FRIEND]-(:User)-[:FRIEND]-(:User)-[:FRIEND]-(f3:User) \
                 WHERE f3.id <> $id \
                 MATCH (f3)-[:PURCHASED]->(p:Product) \
                 WHERE NOT (me)-[:PURCHASED]->(p) \
                 RETURN p.id AS product, count(DISTINCT f3) AS reach \
                 ORDER BY reach DESC, product ASC LIMIT 10",
        weight: 8,
        advanced: true,
        kind: FamilyKind::UserAnchored,
    },
    // Similar consumption profile (collaborative filtering / co-purchase): users who bought many of
    // the same products, then what *they* bought that the seed customer has not.
    QuerySpec {
        name: "r4_similar",
        cypher: "MATCH (me:User {id: $id})-[:PURCHASED]->(p:Product)<-[:PURCHASED]-(other:User) \
                 WHERE other.id <> $id \
                 WITH me, other, count(DISTINCT p) AS shared \
                 ORDER BY shared DESC LIMIT 50 \
                 MATCH (other)-[:PURCHASED]->(rec:Product) \
                 WHERE NOT (me)-[:PURCHASED]->(rec) \
                 RETURN rec.id AS product, count(DISTINCT other) AS supporters, sum(shared) AS affinity \
                 ORDER BY supporters DESC, affinity DESC, product ASC LIMIT 10",
        weight: 13,
        advanced: true,
        kind: FamilyKind::UserAnchored,
    },
    // --- Index-backed retrieval (the declared VECTOR + TEXT indexes, exercised UNDER LOAD, rmp #746) ---
    // The VECTOR (HNSW) "similar products" ANN retrieval — the primary retrieval path of a real
    // recommendation service. The query vector is a category CENTROID passed as a real LIST<FLOAT>
    // parameter ($queryVector), so the k nearest neighbours are that category's products (ground truth).
    // db.index.vector.queryNodes is not reader-safe ⇒ runs inline ⇒ hits the live HNSW even auto-commit.
    QuerySpec {
        name: "p_ann",
        cypher: "CALL db.index.vector.queryNodes($indexName, $k, $queryVector) YIELD node, score \
                 RETURN node.id AS id, node.category AS category, score",
        weight: 15,
        advanced: true,
        kind: FamilyKind::VectorAnn,
    },
    // The TEXT (trigram) catalogue search — "find a product by a fragment of its name". A plain read, so
    // it MUST run in an explicit read transaction to seek the NodeTextIndexSeek (auto-commit is declined
    // to a full scan by the off-thread reader pool — rmp #755). Binds $fragment.
    QuerySpec {
        name: "p_search",
        cypher: "MATCH (p:Product) WHERE p.name CONTAINS $fragment RETURN p.id AS id",
        weight: 8,
        advanced: false,
        kind: FamilyKind::TextContains,
    },
];

/// The scenario's single **write** shape (the "few writes"): record a new purchase between an
/// existing customer and product. Both anchors are `:User(id)` / `:Product(id)` index seeks, so a
/// single write is a cheap 2-seek + create — it participates in MVCC/SSI against the concurrent
/// readers without scanning. Parameters: `$uid`, `$pid`, `$ts`.
pub const WRITE_PURCHASE: &str = "MATCH (u:User {id: $uid}), (p:Product {id: $pid}) \
                                  CREATE (u)-[:PURCHASED {ts: $ts, qty: 1}]->(p)";

/// The scenario's **hot** write shape (`rmp` #714): a **read-modify-write** of a *trending* product's
/// view counter — `hot = coalesce(hot, 0) + 1` — over a deliberately **small** set of products.
///
/// This is the shape that lets SSI (and therefore the driver's retry path) fire at all.
/// [`WRITE_PURCHASE`] always lands on a random `(user, product)` pair, so concurrent writers
/// essentially never touch the same key. Two concurrent read-modify-writes of the *same* node, by
/// contrast, are exactly the rw-antidependency cycle SSI exists to break.
///
/// **Measured, do not over-claim:** at the production-shaped default (2 writers, one unit every 20 ms)
/// the writers still rarely overlap on the same trending product, and the engine abort rate comes out
/// at a measured **~0**. The retry path is therefore *armed but idle* on a default run — see
/// [`crate::mix::WriteKind`] and invariant I4, which report that plainly instead of implying SSI was
/// stressed. Raise `--writers` / lower `--write-every-ms` / lower `--hot-keys` to exercise it.
///
/// Parameter: `$id` (a `:Product(id)`, an index seek — so the conflict is on the *node version*, not
/// on a scan).
pub const WRITE_PRODUCT_HOT: &str =
    "MATCH (p:Product {id: $id}) SET p.hot = coalesce(p.hot, 0) + 1";

/// The total selection weight of the read battery (sum of every family's `weight`).
#[must_use]
pub fn total_weight() -> u32 {
    READ_BATTERY.iter().map(|q| q.weight).sum()
}

/// Selects a read-battery family by a weighted draw. `draw` is any value; it is reduced modulo the
/// total weight, then mapped onto the cumulative-weight ranges in [`READ_BATTERY`] order. Always
/// returns a family (the battery is non-empty).
#[must_use]
pub fn pick(draw: u64) -> &'static QuerySpec {
    let total = u64::from(total_weight().max(1));
    let mut point = draw % total;
    for spec in READ_BATTERY {
        let w = u64::from(spec.weight);
        if point < w {
            return spec;
        }
        point -= w;
    }
    // Unreachable for a non-empty battery with total > 0; fall back to the first family.
    &READ_BATTERY[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn battery_is_nonempty_and_weighted() {
        assert!(!READ_BATTERY.is_empty());
        assert!(total_weight() > 0);
        // Family names are unique (they are report keys).
        for (i, a) in READ_BATTERY.iter().enumerate() {
            for b in &READ_BATTERY[i + 1..] {
                assert_ne!(a.name, b.name, "duplicate family name {}", a.name);
            }
        }
    }

    #[test]
    fn every_read_query_is_read_only_and_binds_its_kind_params() {
        for q in READ_BATTERY {
            // The whole read battery must be strictly read-only.
            for verb in ["CREATE", "MERGE", "DELETE", "SET ", "REMOVE"] {
                assert!(
                    !q.cypher.contains(verb),
                    "{} is not read-only (contains {verb})",
                    q.name
                );
            }
            // Each family binds exactly the parameters its kind promises.
            match q.kind {
                FamilyKind::UserAnchored => {
                    assert!(q.cypher.contains("$id"), "{} must bind $id", q.name);
                }
                FamilyKind::VectorAnn => {
                    assert!(
                        q.cypher.contains("$indexName")
                            && q.cypher.contains("$k")
                            && q.cypher.contains("$queryVector"),
                        "{} must bind the ANN params",
                        q.name
                    );
                    assert!(
                        q.cypher.contains("db.index.vector.queryNodes"),
                        "{} must call the vector index procedure",
                        q.name
                    );
                }
                FamilyKind::TextContains => {
                    assert!(
                        q.cypher.contains("$fragment") && q.cypher.contains("CONTAINS"),
                        "{} must be a CONTAINS search binding $fragment",
                        q.name
                    );
                }
            }
        }
    }

    #[test]
    fn exactly_one_ann_and_one_text_family_exist() {
        let ann = READ_BATTERY
            .iter()
            .filter(|q| q.kind == FamilyKind::VectorAnn)
            .count();
        let text = READ_BATTERY
            .iter()
            .filter(|q| q.kind == FamilyKind::TextContains)
            .count();
        assert_eq!(ann, 1, "exactly one VECTOR ANN family");
        assert_eq!(text, 1, "exactly one TEXT search family");
    }

    #[test]
    fn pick_covers_every_family_and_respects_order() {
        // Sweeping the whole cumulative range yields each family in turn, contiguous by weight.
        let total = total_weight();
        let mut expected = READ_BATTERY.iter();
        let mut cur = expected.next().unwrap();
        let mut seen_in_cur = 0u32;
        for d in 0..total {
            let got = pick(u64::from(d));
            if seen_in_cur == cur.weight {
                cur = expected.next().unwrap();
                seen_in_cur = 0;
            }
            assert_eq!(got.name, cur.name, "draw {d} mapped to the wrong family");
            seen_in_cur += 1;
        }
    }

    #[test]
    fn write_shape_is_a_single_purchase_create() {
        assert!(WRITE_PURCHASE.contains("CREATE (u)-[:PURCHASED"));
        assert!(WRITE_PURCHASE.contains("$uid") && WRITE_PURCHASE.contains("$pid"));
    }

    /// The hot write must be a genuine READ-MODIFY-WRITE of a single indexed node: that is the only
    /// shape that produces the rw-antidependency SSI aborts on (rmp #714). A blind `SET p.hot = 1`
    /// would not read the old value and would not conflict.
    #[test]
    fn hot_write_is_an_indexed_read_modify_write() {
        assert!(WRITE_PRODUCT_HOT.contains("(p:Product {id: $id})"));
        assert!(WRITE_PRODUCT_HOT.contains("coalesce(p.hot, 0) + 1"));
        assert!(WRITE_PRODUCT_HOT.contains("SET p.hot"));
    }
}
