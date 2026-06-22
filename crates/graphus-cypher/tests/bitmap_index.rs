//! End-to-end tests for the **complementary low-cardinality Roaring-bitmap index** (`rmp` task #328):
//! the bitmap index is a derived, in-memory, **membership-exact** candidate source for equality and
//! multi-predicate-AND predicates over low-cardinality columns (booleans, enum-like strings, status
//! flags). It must return **exactly** the set of node ids that the authoritative row path matches for
//! the same predicate — under a fresh index and after every kind of mutation (overwrite, removal,
//! insertion, label loss), proving the per-write re-index keeps it membership-exact (a bitmap is a
//! candidate SOURCE, so a missing member would make a query miss a row — a subset is never correct).
//!
//! The overriding correctness property every test asserts is **equivalence**: the bitmap candidate
//! id-set equals the id-set the row path (`MATCH (n:Label) WHERE n.p = v RETURN id(n)`) returns over
//! the same committed graph. The multi-predicate test asserts the bitmap **intersection** equals the
//! conjunction the row path matches. The harness mirrors `tests/columnar_analytical.rs`.

use std::collections::BTreeSet;

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

// =================================================================================================
// Harness
// =================================================================================================

fn fresh_store() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 64, 1).expect("create store")
}

fn fresh_coord() -> Coord {
    TxnCoordinator::new(fresh_store())
}

fn compile(src: &str) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

fn run_plan(coord: &Coord, txn: graphus_core::TxnId, plan: &PhysicalPlan) -> Vec<Row> {
    let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let rows = {
        let mut cursor = execute(plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    assert!(
        !graph.has_error(),
        "statement captured an error: {:?}",
        graph.take_error()
    );
    rows
}

fn run_write(coord: &mut Coord, src: &str) {
    let plan = compile(src);
    let txn = coord.begin_serializable();
    let _rows = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("write commits");
}

/// The **row-path** truth: the sorted set of physical node ids the engine matches for `query`
/// (which must `RETURN id(n) AS id`), run in its own committed read transaction.
fn row_path_ids(coord: &mut Coord, query: &str) -> BTreeSet<u64> {
    let plan = compile(query);
    let txn = coord.begin_serializable();
    let rows = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("read commits");
    rows.iter()
        .map(|r| match r.value("id") {
            Value::Integer(i) => i as u64,
            other => panic!("id(n) must be an Integer, got {other:?}"),
        })
        .collect()
}

fn as_set(ids: Vec<u64>) -> BTreeSet<u64> {
    ids.into_iter().collect()
}

// =================================================================================================
// Single-predicate equivalence — fresh index
// =================================================================================================

/// Over a freshly-captured boolean column, the bitmap candidate set equals the row path's matching
/// set for each value, and the index actually captured the column (the bitmap seek returns `Some`).
#[test]
fn fresh_boolean_bitmap_equals_row_path() {
    let mut coord = fresh_coord();
    // 60 active, 40 inactive, plus a non-User node that must never appear.
    for i in 0..60 {
        run_write(
            &mut coord,
            &format!("CREATE (:User {{id: {i}, active: true}})"),
        );
    }
    for i in 60..100 {
        run_write(
            &mut coord,
            &format!("CREATE (:User {{id: {i}, active: false}})"),
        );
    }
    run_write(&mut coord, "CREATE (:Robot {active: true})");

    coord
        .declare_bitmap_index("User", "active")
        .expect("declare");

    for v in [true, false] {
        let bitmap = coord
            .bitmap_seek_eq("User", "active", &Value::Boolean(v))
            .expect("column declared");
        let row = row_path_ids(
            &mut coord,
            &format!("MATCH (n:User) WHERE n.active = {v} RETURN id(n) AS id"),
        );
        assert_eq!(
            as_set(bitmap),
            row,
            "bitmap(active={v}) must equal row path"
        );
    }
}

/// An enum-like (low-cardinality) string column: the bitmap matches the row path per value.
#[test]
fn fresh_enum_string_bitmap_equals_row_path() {
    let mut coord = fresh_coord();
    let tiers = ["free", "pro", "enterprise"];
    for i in 0..120 {
        let tier = tiers[(i % 3) as usize];
        run_write(
            &mut coord,
            &format!("CREATE (:Acct {{id: {i}, tier: '{tier}'}})"),
        );
    }
    coord.declare_bitmap_index("Acct", "tier").expect("declare");

    for tier in tiers {
        let bitmap = coord
            .bitmap_seek_eq("Acct", "tier", &Value::String(tier.into()))
            .expect("declared");
        let row = row_path_ids(
            &mut coord,
            &format!("MATCH (n:Acct) WHERE n.tier = '{tier}' RETURN id(n) AS id"),
        );
        assert_eq!(as_set(bitmap), row, "bitmap(tier={tier}) must equal row");
    }
}

// =================================================================================================
// Membership-exactness under mutation (the candidate-source guarantee)
// =================================================================================================

/// After an **overwrite** (`SET n.active = ...`) the per-write re-index moves the node between
/// value-bitmaps, so the bitmap still equals the row path — no stale membership.
#[test]
fn overwrite_keeps_bitmap_membership_exact() {
    let mut coord = fresh_coord();
    for i in 0..50 {
        run_write(
            &mut coord,
            &format!("CREATE (:User {{id: {i}, active: true}})"),
        );
    }
    coord
        .declare_bitmap_index("User", "active")
        .expect("declare");
    // Flip half of them to inactive AFTER the index was built.
    run_write(
        &mut coord,
        "MATCH (n:User) WHERE n.id < 25 SET n.active = false",
    );

    for v in [true, false] {
        let bitmap = coord
            .bitmap_seek_eq("User", "active", &Value::Boolean(v))
            .expect("declared");
        let row = row_path_ids(
            &mut coord,
            &format!("MATCH (n:User) WHERE n.active = {v} RETURN id(n) AS id"),
        );
        assert_eq!(
            as_set(bitmap),
            row,
            "after overwrite, bitmap(active={v}) must equal row"
        );
    }
}

/// After a **removal** (`REMOVE n.active`) the node leaves every value-bitmap; after an **insertion**
/// a new node joins the right one. Both keep the bitmap equal to the row path.
#[test]
fn remove_and_insert_keep_bitmap_membership_exact() {
    let mut coord = fresh_coord();
    for i in 0..40 {
        run_write(
            &mut coord,
            &format!("CREATE (:User {{id: {i}, active: true}})"),
        );
    }
    coord
        .declare_bitmap_index("User", "active")
        .expect("declare");
    run_write(&mut coord, "MATCH (n:User) WHERE n.id < 10 REMOVE n.active");
    run_write(&mut coord, "CREATE (:User {id: 100, active: true})");
    run_write(&mut coord, "CREATE (:User {id: 101, active: false})");

    for v in [true, false] {
        let bitmap = coord
            .bitmap_seek_eq("User", "active", &Value::Boolean(v))
            .expect("declared");
        let row = row_path_ids(
            &mut coord,
            &format!("MATCH (n:User) WHERE n.active = {v} RETURN id(n) AS id"),
        );
        assert_eq!(
            as_set(bitmap),
            row,
            "after remove+insert, bitmap(active={v}) must equal row"
        );
    }
}

/// After a node **loses the covered label** it must drop out of the bitmap (the row path's
/// `MATCH (n:User)` no longer matches it either).
#[test]
fn label_loss_drops_node_from_bitmap() {
    let mut coord = fresh_coord();
    for i in 0..30 {
        run_write(
            &mut coord,
            &format!("CREATE (:User {{id: {i}, active: true}})"),
        );
    }
    coord
        .declare_bitmap_index("User", "active")
        .expect("declare");
    run_write(&mut coord, "MATCH (n:User) WHERE n.id < 5 REMOVE n:User");

    let bitmap = coord
        .bitmap_seek_eq("User", "active", &Value::Boolean(true))
        .expect("declared");
    let row = row_path_ids(
        &mut coord,
        "MATCH (n:User) WHERE n.active = true RETURN id(n) AS id",
    );
    assert_eq!(
        as_set(bitmap),
        row,
        "label loss must drop the node from the bitmap"
    );
}

// =================================================================================================
// Multi-predicate AND (bitmap intersection)
// =================================================================================================

/// A conjunction `n.active = true AND n.tier = 'pro'` answered by intersecting the two value-bitmaps
/// equals the row path's matching set.
#[test]
fn multi_predicate_and_equals_row_path() {
    let mut coord = fresh_coord();
    let tiers = ["free", "pro", "enterprise"];
    for i in 0..150 {
        let active = i % 2 == 0;
        let tier = tiers[(i % 3) as usize];
        run_write(
            &mut coord,
            &format!("CREATE (:User {{id: {i}, active: {active}, tier: '{tier}'}})"),
        );
    }
    coord
        .declare_bitmap_index("User", "active")
        .expect("declare active");
    coord
        .declare_bitmap_index("User", "tier")
        .expect("declare tier");

    for (active, tier) in [(true, "pro"), (false, "free"), (true, "enterprise")] {
        let bitmap = coord
            .bitmap_conjunction(
                "User",
                &[
                    ("active", &Value::Boolean(active)),
                    ("tier", &Value::String(tier.into())),
                ],
            )
            .expect("both columns declared");
        let row = row_path_ids(
            &mut coord,
            &format!(
                "MATCH (n:User) WHERE n.active = {active} AND n.tier = '{tier}' RETURN id(n) AS id"
            ),
        );
        assert_eq!(
            as_set(bitmap),
            row,
            "bitmap AND(active={active}, tier={tier}) must equal row path"
        );
    }
}

/// A conjunction declines (returns `None`) when a column has no bitmap index, so the caller falls
/// back to its ordinary seek+filter path.
#[test]
fn conjunction_declines_when_a_column_is_not_bitmap_indexed() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:User {active: true, tier: 'pro'})");
    coord
        .declare_bitmap_index("User", "active")
        .expect("declare");
    // `tier` is NOT bitmap-indexed ⇒ the conjunction must decline.
    let got = coord.bitmap_conjunction(
        "User",
        &[
            ("active", &Value::Boolean(true)),
            ("tier", &Value::String("pro".into())),
        ],
    );
    assert!(
        got.is_none(),
        "conjunction must decline when a column lacks a bitmap index"
    );
}

// =================================================================================================
// Measurement (ignored by default) — postings footprint and AND speed vs B-tree+filter
// =================================================================================================

/// Reports the bitmap posting footprint and multi-predicate-AND wall-time. Not a correctness gate.
#[test]
#[ignore = "measurement, not a correctness gate; run with --release --ignored --nocapture"]
fn measure_bitmap_footprint_and_and_speed() {
    const N: i64 = 50_000;
    let mut coord = fresh_coord();
    // Batched seed (bounded per-txn footprint): a 2-value `active` + 3-value `tier` low-card column.
    const BATCH: i64 = 2_000;
    let mut lo = 0;
    while lo < N {
        let hi = (lo + BATCH).min(N);
        // One UNWIND per batch; values derive from i so both columns are low-cardinality.
        let stmt = format!(
            "UNWIND range({lo}, {}) AS i CREATE (:User {{id: i, active: (i % 2 = 0), tier: ['free','pro','enterprise'][i % 3]}})",
            hi - 1
        );
        run_write(&mut coord, &stmt);
        lo = hi;
    }
    coord
        .declare_bitmap_index("User", "active")
        .expect("declare active");
    coord
        .declare_bitmap_index("User", "tier")
        .expect("declare tier");

    let bytes_active = coord.bitmap_serialized_bytes("User", "active").unwrap_or(0);
    let bytes_tier = coord.bitmap_serialized_bytes("User", "tier").unwrap_or(0);
    // A B+-tree PropertyIndex posting is ~ key(token 4B + encoded value + id 8B) + payload 8B; for a
    // boolean that is ~ 4 + 1 + 8 + 8 = ~21 bytes/row. Report the per-row comparison.
    let btree_active_est = (N as u64) * 21;

    // AND wall-time: bitmap intersection vs (single bitmap seek for the rarer column + per-row filter
    // of the other predicate, emulating the B-tree seek+Filter plan).
    let t0 = std::time::Instant::now();
    let mut and_total = 0usize;
    for _ in 0..100 {
        let ids = coord
            .bitmap_conjunction(
                "User",
                &[
                    ("active", &Value::Boolean(true)),
                    ("tier", &Value::String("pro".into())),
                ],
            )
            .expect("declared");
        and_total = ids.len();
    }
    let bitmap_and = t0.elapsed() / 100;

    let t1 = std::time::Instant::now();
    let mut filter_total = 0usize;
    for _ in 0..100 {
        // Emulate seek-one + filter-other: seek `tier='pro'`, then keep those also `active=true`.
        let tier_ids = coord
            .bitmap_seek_eq("User", "tier", &Value::String("pro".into()))
            .expect("declared");
        let active_set: BTreeSet<u64> = coord
            .bitmap_seek_eq("User", "active", &Value::Boolean(true))
            .expect("declared")
            .into_iter()
            .collect();
        filter_total = tier_ids
            .into_iter()
            .filter(|id| active_set.contains(id))
            .count();
    }
    let seek_filter = t1.elapsed() / 100;

    assert_eq!(and_total, filter_total, "both AND strategies must agree");
    eprintln!("\n=== rmp #328 measurement (N={N} Users; active=2-value, tier=3-value) ===");
    eprintln!(
        "bitmap postings: active={bytes_active} B, tier={bytes_tier} B  (≈{:.3} bits/row for `active`)",
        (bytes_active as f64 * 8.0) / N as f64
    );
    eprintln!(
        "B+-tree postings (est.) for `active`: ~{btree_active_est} B  -> bitmap is ~{:.0}x smaller",
        btree_active_est as f64 / (bytes_active.max(1) as f64)
    );
    eprintln!(
        "multi-predicate AND  : bitmap-intersection {bitmap_and:?}  | seek+filter {seek_filter:?}  | matches {and_total}"
    );
    eprintln!(
        "AND speedup (bitmap vs seek+filter): {:.2}x\n",
        seek_filter.as_secs_f64() / bitmap_and.as_secs_f64().max(f64::MIN_POSITIVE)
    );
}
