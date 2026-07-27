//! **Index-backed property lookup** (`rmp` task #879): a node index access path carries the key
//! value it already read into the row, so a later `n.p` is answered without a second store read.
//!
//! # What is under test, and what it must never change
//!
//! The optimisation is invisible: the same query returns the same bag, with **identical** values, and
//! registers the same serializability footprint. The only observable difference is the number of
//! property-store reads, which `PROFILE` reports as `dbHits`. So every test here is one of exactly
//! two kinds, and each is labelled:
//!
//! * **Evidence** — it fails against the pre-change engine. The measured before/after `dbHits` are
//!   recorded in the test body, so a regression names the number it lost.
//! * **Guard** — it passes either way. It exists to pin a decline (a shape the cache must NOT serve)
//!   or an invariant a future change could break. It is never presented as proof the feature works.
//!
//! # The one thing that is carried
//!
//! The **value the store returned**, never a value decoded from the index key. `graphus-index` has no
//! key decoder at all, and the encoding is not injective: `keycodec::encode_integer` puts every `i64`
//! on the `f64` magnitude line (so `Integer(2^54+3)` and `Integer(2^54+5)` share one key),
//! `encode_f64_bits` canonicalises every `NaN` sign and payload, and a `Duration` collapses onto one
//! approximate nanosecond total. `rmp` #894 settled that these differences are *observable*. The
//! type-corpus test below asserts **bit identity**, not `==`, precisely so a future "decode the key
//! instead" shortcut fails here.

use std::collections::BTreeMap;

use graphus_core::Value;
use graphus_core::value::spatial::{Crs, Point};
use graphus_core::value::temporal::{Date, Duration, LocalDateTime, LocalTime, ZonedTime};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::plan_description::{PlanDescription, PlanNode};
use graphus_cypher::runtime::{Row, RowValue};
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

// =================================================================================================
// Harness
// =================================================================================================

fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("wal");
    TxnCoordinator::new(RecordStore::create(device, wal, 64, 1).expect("store"))
}

fn compile_with(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), catalog).with_prefix(ast.prefix())
}

/// Runs `src` in its own committed transaction, returning the rows.
fn run(coord: &mut Coord, src: &str, catalog: &IndexCatalog) -> Vec<Row> {
    let plan = compile_with(src, catalog);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let txn = coord.begin_serializable();
    let rows = {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open");
        let rows = cursor.collect_all().expect("collect");
        assert!(
            graph.take_error().is_none(),
            "{src:?} captured a storage error"
        );
        rows
    };
    coord.commit(txn).expect("commit");
    rows
}

/// Runs a write statement and commits it.
fn write(coord: &mut Coord, src: &str) {
    run(coord, src, &IndexCatalog::empty());
}

/// Runs `src` (which must carry the `PROFILE` prefix) and returns `(rows, plan description)`.
fn profile(coord: &mut Coord, src: &str, catalog: &IndexCatalog) -> (Vec<Row>, PlanDescription) {
    let plan = compile_with(src, catalog);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let txn = coord.begin_serializable();
    let out = {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open");
        let rows = cursor.collect_all().expect("collect");
        let d = PlanDescription::profile(cursor.profile().expect("a PROFILEd statement measures"));
        assert!(
            graph.take_error().is_none(),
            "{src:?} captured a storage error"
        );
        (rows, d)
    };
    coord.commit(txn).expect("commit");
    out
}

/// The measured `dbHits` of every operator of a profiled plan, summed.
fn total_db_hits(p: &PlanDescription) -> u64 {
    fn walk(n: &PlanNode) -> u64 {
        n.db_hits.unwrap_or(0) + n.children.iter().map(walk).sum::<u64>()
    }
    walk(p.root())
}

/// The measured `dbHits` of the first operator of `kind`, which must exist.
fn db_hits_of(p: &PlanDescription, kind: &str) -> u64 {
    fn find<'a>(n: &'a PlanNode, kind: &str) -> Option<&'a PlanNode> {
        if n.operator_type == kind {
            return Some(n);
        }
        n.children.iter().find_map(|c| find(c, kind))
    }
    find(p.root(), kind)
        .unwrap_or_else(|| panic!("no {kind} operator in the profiled plan"))
        .db_hits
        .unwrap_or(0)
}

/// The rendered `Details` of the first operator of `kind`.
fn details_of(p: &PlanDescription, kind: &str) -> String {
    fn find<'a>(n: &'a PlanNode, kind: &str) -> Option<&'a PlanNode> {
        if n.operator_type == kind {
            return Some(n);
        }
        n.children.iter().find_map(|c| find(c, kind))
    }
    let node = find(p.root(), kind).unwrap_or_else(|| panic!("no {kind} operator in the plan"));
    match node.args.iter().find(|(k, _)| k == "Details") {
        Some((_, Value::String(s))) => s.clone(),
        other => panic!("no Details on {kind}: {other:?}"),
    }
}

/// **Bit-exact** value identity — deliberately NOT `PartialEq`.
///
/// `Value`'s derived equality compares floats with IEEE `==`, under which `NaN != NaN` and
/// `-0.0 == 0.0`. Both are exactly the distinctions this feature could destroy: a `-0.0` served as
/// `0.0` would pass `==` and be wrong, and a `NaN` served as any `NaN` would pass nothing at all.
/// Comparing `f64::to_bits` decides both, and recursing through `List`/`Map` keeps a nested float
/// from escaping the check.
fn identical(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Float(x), Value::Float(y)) => x.to_bits() == y.to_bits(),
        (Value::List(x), Value::List(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| identical(p, q))
        }
        (Value::Map(x), Value::Map(y)) => {
            x.len() == y.len()
                && x.iter()
                    .zip(y)
                    .all(|((kx, vx), (ky, vy))| kx == ky && identical(vx, vy))
        }
        (Value::Point(x), Value::Point(y)) => {
            x.crs == y.crs
                && x.coords().len() == y.coords().len()
                && x.coords()
                    .iter()
                    .zip(y.coords().iter())
                    .all(|(p, q)| p.to_bits() == q.to_bits())
        }
        _ => a == b,
    }
}

/// Renders the rows as a sorted multiset of `column -> value` maps, so two plans' bags can be
/// compared regardless of emission order, with [`identical`] deciding each value.
fn bag(rows: &[Row]) -> Vec<BTreeMap<String, Value>> {
    let mut out: Vec<BTreeMap<String, Value>> = rows
        .iter()
        .map(|r| {
            r.columns()
                .iter()
                .cloned()
                .zip(r.values().iter().map(|v| match v {
                    RowValue::Value(v) => v.clone(),
                    other => panic!("expected a property value column, got {other:?}"),
                }))
                .collect()
        })
        .collect();
    // A deterministic total order for the comparison; `Debug` distinguishes `-0.0` from `0.0` and
    // orders `NaN` consistently, which `cmp_values` would not.
    out.sort_by_key(|m| format!("{m:?}"));
    out
}

/// Asserts the seek plan and the store-reading (no-index) plan return the **identical** bag.
fn assert_same_bag(coord: &mut Coord, src: &str, catalog: &IndexCatalog) -> Vec<Row> {
    let seek_rows = run(coord, src, catalog);
    let scan_rows = run(coord, src, &IndexCatalog::empty());
    let (a, b) = (bag(&seek_rows), bag(&scan_rows));
    assert_eq!(a.len(), b.len(), "{src}: row counts differ");
    for (x, y) in a.iter().zip(b.iter()) {
        assert_eq!(x.keys().collect::<Vec<_>>(), y.keys().collect::<Vec<_>>());
        for (k, xv) in x {
            let yv = &y[k];
            assert!(
                identical(xv, yv),
                "{src}: column {k:?} is not BIT-IDENTICAL between the index plan and the store \
                 plan: index={xv:?} store={yv:?}"
            );
        }
    }
    seek_rows
}

/// 20 `:Person` nodes with `name` / `age` / `city`, plus the three indexes the tests use.
fn people_with_indexes(coord: &mut Coord) -> IndexCatalog {
    for i in 0..20 {
        write(
            coord,
            &format!(
                "CREATE (:Person {{name: 'p{i}', age: {i}, city: 'c{}'}})",
                i % 3
            ),
        );
    }
    coord
        .create_node_property_index("Person", "name")
        .expect("name index");
    coord
        .create_node_property_index("Person", "age")
        .expect("age index");
    coord
        .begin_online_node_composite_index_named(
            None,
            "Person",
            &["city".to_owned(), "age".to_owned()],
            false,
        )
        .expect("composite index");
    while coord.has_pending_index_builds() {
        coord.advance_index_builds(1000);
    }
    coord.catalog()
}

// =================================================================================================
// AC 1 — the measured before/after: strictly fewer property-store reads, on an observable counter
// =================================================================================================

/// **EVIDENCE.** A seek plus a projection of the indexed property reads the store **once**, not twice.
///
/// Measured against unmodified `main` (commit `bab4645`) and against this change, on the same data
/// and the same query:
///
/// | operator        | before | after |
/// |-----------------|--------|-------|
/// | `NodeIndexSeek` | 1      | 1     |
/// | `Projection`    | **1**  | **0** |
/// | total `dbHits`  | **2**  | **1** |
///
/// The `Projection` line is the whole feature: it is the second read of a value the seek's own
/// candidate re-check had already fetched. The plan says so too — `cache[n.name]` is rendered on the
/// seek — and the two agree, which is the `rmp` #755 lesson applied here.
#[test]
fn seek_plus_projection_reads_the_store_once_879() {
    let mut coord = fresh_coord();
    let catalog = people_with_indexes(&mut coord);

    let (rows, plan) = profile(
        &mut coord,
        "PROFILE MATCH (n:Person {name: 'p7'}) RETURN n.name AS name",
        &catalog,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("name"), Value::String("p7".to_owned()));

    assert_eq!(
        db_hits_of(&plan, "Projection"),
        0,
        "the projection must not read the store for a property the seek already read (was 1)"
    );
    assert_eq!(
        total_db_hits(&plan),
        1,
        "the whole statement costs one store access (was 2)"
    );
    assert!(
        details_of(&plan, "NodeIndexSeek").contains("cache[n.name]"),
        "the plan must say the property is available from the index: {}",
        details_of(&plan, "NodeIndexSeek")
    );
}

/// **EVIDENCE.** Two references to the same indexed property still cost one read.
///
/// before: total 3 (`Projection` 2 + seek 1) → after: total **1** (`Projection` **0**).
#[test]
fn repeated_references_cost_one_read_879() {
    let mut coord = fresh_coord();
    let catalog = people_with_indexes(&mut coord);

    let (rows, plan) = profile(
        &mut coord,
        "PROFILE MATCH (n:Person {name: 'p7'}) RETURN n.name AS a, n.name AS b",
        &catalog,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("a"), Value::String("p7".to_owned()));
    assert_eq!(rows[0].value("b"), Value::String("p7".to_owned()));
    assert_eq!(db_hits_of(&plan, "Projection"), 0, "was 2");
    assert_eq!(total_db_hits(&plan), 1, "was 3");
}

/// **EVIDENCE.** A **range** seek carries its key value too (`AC 4`).
///
/// `age >= 15` over 20 people matches 5. before: total 10 (`Projection` 5 + seek 5) → after: **5**.
#[test]
fn range_seek_plus_projection_reads_the_store_once_per_row_879() {
    let mut coord = fresh_coord();
    let catalog = people_with_indexes(&mut coord);

    let (rows, plan) = profile(
        &mut coord,
        "PROFILE MATCH (n:Person) WHERE n.age >= 15 RETURN n.age AS age",
        &catalog,
    );
    assert_eq!(rows.len(), 5);
    assert!(plan.contains_operator("NodeIndexRangeSeek"));
    assert_eq!(db_hits_of(&plan, "Projection"), 0, "was 5");
    assert_eq!(total_db_hits(&plan), 5, "was 10");
    assert!(details_of(&plan, "NodeIndexRangeSeek").contains("cache[n.age]"));
}

/// **EVIDENCE.** An **ordered** range seek stops reading the property twice for the sort key as well.
///
/// `order_ids_if_requested` used to re-read every candidate's property purely to build the sort key,
/// on top of the re-check that had just read it and the projection that would read it again.
/// before: total 15 (seek 10 — 5 re-check + 5 sort-key reads — plus `Projection` 5) → after: **5**.
#[test]
fn ordered_range_seek_sorts_on_the_carried_value_879() {
    let mut coord = fresh_coord();
    let catalog = people_with_indexes(&mut coord);

    let (rows, plan) = profile(
        &mut coord,
        "PROFILE MATCH (n:Person) WHERE n.age >= 15 RETURN n.age AS age ORDER BY n.age",
        &catalog,
    );
    assert_eq!(
        rows.iter().map(|r| r.value("age")).collect::<Vec<_>>(),
        (15..20).map(Value::Integer).collect::<Vec<_>>(),
        "the provided order must be unchanged"
    );
    assert!(details_of(&plan, "NodeIndexRangeSeek").contains("ordered asc"));
    assert_eq!(db_hits_of(&plan, "NodeIndexRangeSeek"), 5, "was 10");
    assert_eq!(total_db_hits(&plan), 5, "was 15");
}

/// **EVIDENCE.** The existence access path (`IS NOT NULL`, a `NodeIndexScan` over the whole index)
/// serves both its residual `Filter` and the projection from the row.
///
/// before: total 60 over 20 rows (scan 20 + `Filter` 20 + `Projection` 20) → after: **20**.
#[test]
fn existence_index_scan_serves_the_filter_and_the_projection_879() {
    let mut coord = fresh_coord();
    let catalog = people_with_indexes(&mut coord);

    let (rows, plan) = profile(
        &mut coord,
        "PROFILE MATCH (n:Person) WHERE n.name IS NOT NULL RETURN n.name AS name",
        &catalog,
    );
    assert_eq!(rows.len(), 20);
    assert!(plan.contains_operator("NodeIndexScan"));
    assert_eq!(db_hits_of(&plan, "Filter"), 0, "was 20");
    assert_eq!(db_hits_of(&plan, "Projection"), 0, "was 20");
    assert_eq!(total_db_hits(&plan), 20, "was 60");
}

/// **EVIDENCE.** A **composite** seek makes every covered key available (`AC 4`).
///
/// before: total 3 (`Projection` 2 + seek 1) → after: **1**, and the plan renders both keys.
#[test]
fn composite_seek_carries_every_covered_key_879() {
    let mut coord = fresh_coord();
    let catalog = people_with_indexes(&mut coord);

    let (rows, plan) = profile(
        &mut coord,
        "PROFILE MATCH (n:Person {city: 'c1', age: 4}) RETURN n.city AS c, n.age AS a",
        &catalog,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("c"), Value::String("c1".to_owned()));
    assert_eq!(rows[0].value("a"), Value::Integer(4));
    assert!(plan.contains_operator("NodeCompositeIndexSeek"));
    assert_eq!(db_hits_of(&plan, "Projection"), 0, "was 2");
    assert_eq!(total_db_hits(&plan), 1, "was 3");
    assert!(
        details_of(&plan, "NodeCompositeIndexSeek").contains("cache[n.city, n.age]"),
        "{}",
        details_of(&plan, "NodeCompositeIndexSeek")
    );
}

/// **EVIDENCE.** Referencing only a **subset** of a composite key is served just as well — the seam
/// reads the whole tuple to re-check it, so there is nothing cheaper to do (`TRAP 3`).
///
/// The `dbHits` figures annotated below are DERIVED, not measured on the pre-change tree: one
/// `node_property` call costs one `dbHit` (`crate::profile`), and before this change the projection
/// had no other way to obtain the value. The assertion itself is still evidence — a projection that
/// reads the store cannot report zero.
#[test]
fn composite_seek_serves_a_subset_of_its_keys_879() {
    let mut coord = fresh_coord();
    let catalog = people_with_indexes(&mut coord);

    let (rows, plan) = profile(
        &mut coord,
        "PROFILE MATCH (n:Person {city: 'c1', age: 4}) RETURN n.age AS a",
        &catalog,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("a"), Value::Integer(4));
    assert_eq!(db_hits_of(&plan, "Projection"), 0, "was 1");
    assert_eq!(total_db_hits(&plan), 1, "was 2");
}

/// **GUARD.** A query that never reads the indexed property must not carry it: the plan renders no
/// `cache[...]` and the `dbHits` are unchanged, so a plan that projects whole nodes pays nothing for
/// a feature it does not use.
#[test]
fn a_plan_that_never_reads_the_property_carries_nothing_879() {
    let mut coord = fresh_coord();
    let catalog = people_with_indexes(&mut coord);

    let (rows, plan) = profile(
        &mut coord,
        "PROFILE MATCH (n:Person {name: 'p7'}) RETURN n",
        &catalog,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(total_db_hits(&plan), 1, "unchanged before and after");
    assert!(
        !details_of(&plan, "NodeIndexSeek").contains("cache["),
        "the plan must not claim a cache it was never asked for: {}",
        details_of(&plan, "NodeIndexSeek")
    );
}

// =================================================================================================
// AC 2 — bag equality across a property-type corpus, with BIT-IDENTICAL values
// =================================================================================================

/// The corpus: one node per value, covering every indexable Cypher type and every case where the
/// index key is known to be a lossy projection of the value.
fn type_corpus() -> Vec<Value> {
    vec![
        // Numbers, including the `rmp` #894 pairs the key codec folds together.
        Value::Integer(0),
        Value::Integer(-1),
        Value::Integer(i64::MIN),
        Value::Integer(i64::MAX),
        Value::Integer(9_007_199_254_740_992),  // 2^53
        Value::Integer(9_007_199_254_740_993),  // 2^53+1 — shares 2^53's key
        Value::Integer(18_014_398_509_481_987), // 2^54+3 ─┬ one key, two numbers
        Value::Integer(18_014_398_509_481_989), // 2^54+5 ─┘
        Value::Float(0.0),
        Value::Float(-0.0), // the signed zero the key codec DOES separate but `==` does not
        Value::Float(f64::NAN), // canonicalised in the key; must survive verbatim in the value
        Value::Float(-f64::NAN), // a NaN with the sign bit set — a different bit pattern
        Value::Float(f64::INFINITY),
        Value::Float(f64::NEG_INFINITY),
        Value::Float(9_007_199_254_740_992.0),
        Value::Float(-1.5),
        // Text needing collation / escaping (`push_var` escapes every interior `0x00`).
        Value::String(String::new()),
        Value::String("a".to_owned()),
        Value::String("A".to_owned()),
        Value::String("ä".to_owned()),
        Value::String("Å".to_owned()),
        Value::String("straße".to_owned()),
        Value::String("STRASSE".to_owned()),
        Value::String("\u{0}embedded".to_owned()),
        Value::String("é\u{301}".to_owned()), // NFD: two code points, one grapheme
        Value::String("\u{e9}".to_owned()),   // NFC: the same grapheme, one code point
        // A homogeneous `List`: storable, but NOT index-encodable, so every access path over it
        // declines to the exact scan. It is in the corpus precisely to keep that decline covered —
        // and it is the value whose silent loss from the existence scan this task uncovered
        // (`tests/index_wiring.rs::a_list_valued_property_does_not_disappear_from_the_existence_scan_879`).
        //
        // `Value::Bytes` is deliberately ABSENT: `graphus-storage`'s property codec refuses it
        // ("Map/Bytes property values are a follow-up") and the write fails closed with a captured
        // error, so it is not a storable property class at all and there is nothing here to compare.
        Value::List(vec![Value::Integer(1), Value::Integer(2)]),
        Value::Boolean(true),
        Value::Boolean(false),
        // Spatial, both CRSs and both dimensions.
        Value::Point(Point::new_2d(Crs::Cartesian, 3.0, 4.0)),
        Value::Point(Point::new_3d(Crs::Cartesian3D, 3.0, 4.0, 5.0)),
        Value::Point(Point::new_2d(Crs::Wgs84, -8.61, 41.15)),
        Value::Point(Point::new_3d(Crs::Wgs84_3D, -8.61, 41.15, 100.0)),
        Value::Point(Point::new_2d(Crs::Cartesian, -0.0, 0.0)), // signed zero inside a point
        // Every temporal type.
        Value::Date(Date {
            days_since_epoch: 19_000,
        }),
        Value::Date(Date {
            days_since_epoch: -1,
        }),
        Value::LocalTime(LocalTime {
            nanos_of_day: 86_399_999_999_999,
        }),
        Value::ZonedTime(ZonedTime {
            time: LocalTime {
                nanos_of_day: 3_600_000_000_000,
            },
            offset_seconds: -3600,
        }),
        Value::LocalDateTime(LocalDateTime {
            epoch_seconds: 1_700_000_000,
            nanos: 123_456_789,
        }),
        Value::zoned_date_time(graphus_core::value::temporal::ZonedDateTime {
            local: LocalDateTime {
                epoch_seconds: 1_700_000_000,
                nanos: 1,
            },
            offset_seconds: 0,
            zone_id: "Europe/Lisbon".to_owned(),
        }),
        // Two durations whose key collapses onto the same approximate nanosecond total but which are
        // different values — the `Duration` half of the "the key is not the value" argument.
        Value::Duration(Duration {
            months: 1,
            days: 0,
            seconds: 0,
            nanos: 0,
        }),
        Value::Duration(Duration {
            months: 0,
            days: 30,
            seconds: 37_800,
            nanos: 0,
        }),
    ]
}

/// **EVIDENCE.** Over the whole type corpus, the index-served plan returns the **bit-identical**
/// value the store-reading plan returns, for both the existence scan (every row) and a per-value
/// equality seek.
///
/// This is the test a "decode the index key" implementation cannot pass. Verified non-vacuous three
/// ways: the index plan must really plan the index operator (asserted), the corpus must really reach
/// the store (row counts asserted), and the comparison is [`identical`], not `==`, so `-0.0`/`0.0`
/// and the two `NaN` bit patterns are distinguished.
#[test]
fn the_carried_value_is_bit_identical_to_the_store_over_the_type_corpus_879() {
    let corpus = type_corpus();
    let mut coord = fresh_coord();
    // Seed one node per value through the seam (a Cypher literal cannot spell every type).
    let txn = coord.begin_serializable();
    {
        let mut graph = coord.statement(txn).expect("statement");
        use graphus_cypher::graph_access::GraphAccess;
        for (i, v) in corpus.iter().enumerate() {
            #[allow(clippy::cast_possible_wrap)]
            let id = Value::Integer(i as i64);
            graph.create_node(
                &["T".to_owned()],
                &[("id".to_owned(), id), ("v".to_owned(), v.clone())],
            );
        }
    }
    coord.commit(txn).expect("commit");
    coord
        .create_node_property_index("T", "v")
        .expect("index on v");
    let catalog = coord.catalog();

    // (a) The existence scan: every row, every type, at once.
    let src = "MATCH (n:T) WHERE n.v IS NOT NULL RETURN n.id AS id, n.v AS v";
    assert!(
        compile_with(src, &catalog)
            .to_string()
            .contains("NodeIndexScan"),
        "the corpus comparison must actually run the index path"
    );
    let rows = assert_same_bag(&mut coord, src, &catalog);
    assert_eq!(
        rows.len(),
        corpus.len(),
        "every corpus value must produce a row (else the comparison is vacuous)"
    );
    // And the value that came back is bit-identical to what was written, per id.
    for row in &rows {
        let Value::Integer(i) = row.value("id") else {
            panic!("id must be an integer")
        };
        #[allow(clippy::cast_sign_loss)]
        let expected = &corpus[i as usize];
        let got = row.value("v");
        assert!(
            identical(&got, expected),
            "id {i}: the index-served value is not the value that was stored: \
             got={got:?} stored={expected:?}"
        );
    }

    // (b) A per-value equality seek, so the equality access path is covered value by value. `NaN`
    // equals nothing (not even itself) so it matches no row — asserted, rather than skipped.
    for (i, v) in corpus.iter().enumerate() {
        let params = {
            let mut p = Parameters::new();
            p.insert("v".to_owned(), v.clone());
            p
        };
        let src = "MATCH (n:T {v: $v}) RETURN n.id AS id, n.v AS v";
        let seek = run_with_params(&mut coord, src, &catalog, &params);
        let scan = run_with_params(&mut coord, src, &IndexCatalog::empty(), &params);
        assert_eq!(
            bag(&seek).len(),
            bag(&scan).len(),
            "corpus[{i}] = {v:?}: the seek and the scan return different row counts"
        );
        for (x, y) in bag(&seek).iter().zip(bag(&scan).iter()) {
            for (k, xv) in x {
                assert!(
                    identical(xv, &y[k]),
                    "corpus[{i}] = {v:?}: column {k:?} differs: seek={xv:?} scan={:?}",
                    y[k]
                );
            }
        }
        if matches!(v, Value::Float(f) if f.is_nan()) {
            assert!(
                seek.is_empty(),
                "NaN equals nothing, so a NaN seek must match no row"
            );
        } else {
            assert!(
                !seek.is_empty(),
                "corpus[{i}] = {v:?}: the seek found nothing — the comparison would be vacuous"
            );
        }
    }
}

/// Runs `src` with `params` bound.
fn run_with_params(
    coord: &mut Coord,
    src: &str,
    catalog: &IndexCatalog,
    params: &Parameters,
) -> Vec<Row> {
    let plan = compile_with(src, catalog);
    let bound = bind_parameters(&plan, params).expect("bind");
    let txn = coord.begin_serializable();
    let rows = {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open");
        let rows = cursor.collect_all().expect("collect");
        assert!(graph.take_error().is_none(), "{src:?} captured an error");
        rows
    };
    coord.commit(txn).expect("commit");
    rows
}

// =================================================================================================
// AC 3 — the fallback is proven, not assumed
// =================================================================================================

/// **EVIDENCE.** A `Populating` index must not short-circuit anything: the seam declines, the
/// executor takes the exact scan, and the later `n.name` **really reads the store**.
///
/// The plan is compiled against a catalogue in which the index is `Online` — the situation a cached
/// plan reaches when the index is rebuilt underneath it — so the operator carries `cache[n.name]`
/// while the run cannot honour it. This is the one case in which the rendered marker is a plan-time
/// intent the run did not fulfil, and the assertion below is exactly what makes it detectable:
/// `PROFILE` shows the projection paying a `dbHit` per row.
#[test]
fn a_populating_index_falls_back_to_the_store_read_879() {
    // A donor coordinator with the index fully built, purely to obtain the catalogue the planner
    // would have used.
    let mut donor = fresh_coord();
    for i in 0..6 {
        write(&mut donor, &format!("CREATE (:Person {{name: 'p{i}'}})"));
    }
    donor
        .create_node_property_index("Person", "name")
        .expect("donor index");
    let catalog = donor.catalog();

    // The coordinator under test: the same schema, but the build is STARTED and never driven, so the
    // index stays `Populating` and every seek against it declines (`rmp` #733).
    let mut coord = fresh_coord();
    for i in 0..6 {
        write(&mut coord, &format!("CREATE (:Person {{name: 'p{i}'}})"));
    }
    coord
        .begin_online_node_property_index("Person", "name")
        .expect("begin build");
    assert!(
        coord.has_pending_index_builds(),
        "the index must be left Populating for this test to mean anything"
    );

    let (rows, plan) = profile(
        &mut coord,
        "PROFILE MATCH (n:Person {name: 'p3'}) RETURN n.name AS name",
        &catalog,
    );
    // The answer is right regardless — that is the point of failing closed.
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("name"), Value::String("p3".to_owned()));
    assert!(
        details_of(&plan, "NodeIndexSeek").contains("cache[n.name]"),
        "the plan was compiled against an Online index, so it asks for the cache"
    );
    assert_eq!(
        db_hits_of(&plan, "Projection"),
        1,
        "the seam declined, so the projection MUST have read the store — this is the fallback"
    );
    assert!(
        total_db_hits(&plan) >= 6,
        "the declined seek falls back to the exact scan over all 6 nodes: {}",
        total_db_hits(&plan)
    );
}

/// **EVIDENCE.** The carried value is the version **this snapshot** sees, never the newest one.
///
/// A reader opens its snapshot, a concurrent writer commits a new value, and the index then holds
/// entries for *both*. The reader's seek must find the node under the value it can see, carry that
/// value, and find nothing at all under the value it cannot. Both are compared against the
/// store-reading plan, which is the reference.
#[test]
fn a_version_outside_the_snapshot_is_never_served_879() {
    let mut coord = fresh_coord();
    write(&mut coord, "CREATE (:Person {name: 'old', tag: 1})");
    coord
        .create_node_property_index("Person", "name")
        .expect("index");
    let catalog = coord.catalog();

    // The reader's snapshot is taken BEFORE the writer commits.
    let reader = coord.begin_serializable();

    write(&mut coord, "MATCH (n:Person) SET n.name = 'new'");

    // Through the reader's snapshot: `old` is what it sees.
    let seek_old = compile_with(
        "MATCH (n:Person {name: 'old'}) RETURN n.name AS name",
        &catalog,
    );
    let scan_old = compile_with(
        "MATCH (n:Person {name: 'old'}) RETURN n.name AS name",
        &IndexCatalog::empty(),
    );
    let seek_new = compile_with(
        "MATCH (n:Person {name: 'new'}) RETURN n.name AS name",
        &catalog,
    );
    // Non-vacuity: the plan under test really is the caching index seek.
    assert!(
        seek_old.to_string().contains("NodeIndexSeek")
            && seek_old.to_string().contains("cache[n.name]"),
        "the snapshot test must exercise the caching seek:\n{seek_old}"
    );

    let (old_seek_rows, old_scan_rows, new_seek_rows) = {
        let mut graph = coord.statement(reader).expect("statement");
        let mut drain = |plan: &PhysicalPlan| -> Vec<Row> {
            let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
            let mut cursor = execute(plan, &bound, &mut graph).expect("open");
            cursor.collect_all().expect("collect")
        };
        (drain(&seek_old), drain(&scan_old), drain(&seek_new))
    };
    // The reader may or may not survive commit under SSI; the rows above are what is under test.
    let _ = coord.commit(reader);

    assert_eq!(old_seek_rows.len(), 1, "the reader still sees `old`");
    assert_eq!(
        old_seek_rows[0].value("name"),
        Value::String("old".to_owned()),
        "the carried value must be the version the SNAPSHOT sees, not the committed newest"
    );
    assert_eq!(
        bag(&old_seek_rows),
        bag(&old_scan_rows),
        "seek vs store plan"
    );
    assert!(
        new_seek_rows.is_empty(),
        "the reader must not see the value a later transaction committed"
    );
}

// =================================================================================================
// TRAP 3 — every decline, pinned
// =================================================================================================

/// **EVIDENCE.** A `SET` between the seek and the projection makes the carried value stale, so the
/// whole plan declines to cache.
///
/// **Measured, not argued.** With the gate removed from `mark_index_backed_properties`, the plan
/// renders `NodeIndexSeek(n:Person name = 'x' via idx#1 cache[n.name])` and
/// `MATCH (n:Person {name: 'x'}) SET n.name = 'y' RETURN n.name` returns `String("x")` — the value
/// the seek carried — while the store holds `String("y")`. With the gate it returns `'y'` and the
/// plan carries no `cache[...]` at all.
#[test]
fn a_write_anywhere_in_the_plan_disables_the_cache_879() {
    let mut coord = fresh_coord();
    let catalog = people_with_indexes(&mut coord);

    let plan = compile_with(
        "MATCH (n:Person {name: 'p3'}) SET n.name = 'renamed' RETURN n.name AS name",
        &catalog,
    );
    assert!(
        plan.to_string().contains("NodeIndexSeek"),
        "the seek must still be planned (else the decline is vacuous):\n{plan}"
    );
    assert!(
        !plan.to_string().contains("cache["),
        "a mutating plan must not cache any property:\n{plan}"
    );

    let rows = run(
        &mut coord,
        "MATCH (n:Person {name: 'p3'}) SET n.name = 'renamed' RETURN n.name AS name",
        &catalog,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].value("name"),
        Value::String("renamed".to_owned()),
        "the projection must observe the SET, not the value the seek read"
    );
}

/// **EVIDENCE.** A `SET` that reaches the seek's node through a **different variable** is the case a
/// per-variable gate would miss; the whole-plan gate covers it.
#[test]
fn a_write_through_an_alias_disables_the_cache_879() {
    let mut coord = fresh_coord();
    let catalog = people_with_indexes(&mut coord);
    let src = "MATCH (n:Person {name: 'p4'}) MATCH (m:Person) WHERE id(m) = id(n) \
               SET m.name = 'aliased' RETURN n.name AS name";
    let plan = compile_with(src, &catalog);
    assert!(
        !plan.to_string().contains("cache["),
        "an aliased write must disable the cache too:\n{plan}"
    );
    let rows = run(&mut coord, src, &catalog);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("name"), Value::String("aliased".to_owned()));
}

/// **EVIDENCE.** A `CALL` disables the cache: a procedure is opaque and may write.
#[test]
fn a_procedure_call_disables_the_cache_879() {
    let mut coord = fresh_coord();
    let catalog = people_with_indexes(&mut coord);
    let plan = compile_with(
        "MATCH (n:Person {name: 'p3'}) CALL db.labels() YIELD label RETURN n.name AS name, label",
        &catalog,
    );
    assert!(
        plan.to_string().contains("NodeIndexSeek"),
        "the seek must still be planned (else the decline is vacuous):\n{plan}"
    );
    assert!(
        !plan.to_string().contains("cache["),
        "a plan containing a procedure call must not cache:\n{plan}"
    );
}

/// **GUARD.** An `OPTIONAL MATCH` null row reads `null`, not a value cached for a different row.
///
/// The null row binds `n` to `null`, so the per-row node-identity check in
/// `Row::cached_property` misses and the store path (which yields `null` for a null base) runs.
#[test]
fn an_optional_match_null_row_reads_null_879() {
    let mut coord = fresh_coord();
    let catalog = people_with_indexes(&mut coord);
    let src = "MATCH (a:Person {name: 'p1'}) \
               OPTIONAL MATCH (n:Person {name: 'nobody'}) \
               RETURN a.name AS a, n.name AS n";
    let rows = assert_same_bag(&mut coord, src, &catalog);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("a"), Value::String("p1".to_owned()));
    assert_eq!(
        rows[0].value("n"),
        Value::Null,
        "the null row must read null"
    );
}

/// **GUARD.** A variable re-bound to a **different** node after the seek is not served from the
/// cache: the row's binding no longer names the node the value came from.
#[test]
fn a_rebound_variable_is_not_served_from_the_cache_879() {
    let mut coord = fresh_coord();
    let catalog = people_with_indexes(&mut coord);
    // `n` is seeked as p1, then re-bound (via the projection) to p2; `n.name` must read p2's name.
    let src = "MATCH (n:Person {name: 'p1'}) MATCH (other:Person {name: 'p2'}) \
               WITH other AS n RETURN n.name AS name";
    let rows = assert_same_bag(&mut coord, src, &catalog);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].value("name"),
        Value::String("p2".to_owned()),
        "the re-bound variable must resolve to the NEW node's property"
    );
}

/// **GUARD.** An alias across a `WITH` boundary reads the store (the projection builds fresh rows,
/// which carry no memo) and still returns the right value.
#[test]
fn an_alias_across_a_with_boundary_still_answers_correctly_879() {
    let mut coord = fresh_coord();
    let catalog = people_with_indexes(&mut coord);
    let src = "MATCH (n:Person {name: 'p5'}) WITH n AS m RETURN m.name AS name";
    let rows = assert_same_bag(&mut coord, src, &catalog);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("name"), Value::String("p5".to_owned()));
}

/// **GUARD.** The memo survives an expansion's fan-out — the driving variable is still bound to the
/// same node in every produced row — and the answer is unchanged.
#[test]
fn the_memo_survives_an_expand_fan_out_879() {
    let mut coord = fresh_coord();
    let catalog = people_with_indexes(&mut coord);
    write(
        &mut coord,
        "MATCH (a:Person {name: 'p0'}), (b:Person) WHERE b.name <> 'p0' CREATE (a)-[:KNOWS]->(b)",
    );
    let src = "MATCH (a:Person {name: 'p0'})-[:KNOWS]->(b) RETURN a.name AS a, b.name AS b";
    let rows = assert_same_bag(&mut coord, src, &catalog);
    assert_eq!(rows.len(), 19);
    assert!(
        rows.iter()
            .all(|r| r.value("a") == Value::String("p0".to_owned()))
    );
}

/// **GUARD.** A second predicate on the indexed property is evaluated against the carried value and
/// still filters correctly — the value the residual sees must be the store's, not the seek argument
/// (which is only Cypher-*equal* to it: `n.age = 4` also matches a node storing `4.0`).
#[test]
fn a_residual_predicate_on_the_cached_property_still_filters_879() {
    let mut coord = fresh_coord();
    let catalog = people_with_indexes(&mut coord);
    for (src, expected) in [
        (
            "MATCH (n:Person) WHERE n.age >= 15 AND n.age <> 17 RETURN n.age AS age",
            4,
        ),
        (
            "MATCH (n:Person) WHERE n.age >= 15 AND n.age % 2 = 0 RETURN n.age AS age",
            2,
        ),
    ] {
        let rows = assert_same_bag(&mut coord, src, &catalog);
        assert_eq!(rows.len(), expected, "{src}");
    }
}

// =================================================================================================
// TRAP 4 — the plan and the counter agree
// =================================================================================================

/// **EVIDENCE.** The plan text and `PROFILE`'s `dbHits` tell the same story in both directions: an
/// operator rendering `cache[n.name]` shows a consumer with **zero** `dbHits`, and the same query
/// with no index renders no marker and shows a consumer paying one `dbHit` per row.
#[test]
fn the_plan_marker_and_the_measured_db_hits_agree_879() {
    let mut coord = fresh_coord();
    let catalog = people_with_indexes(&mut coord);
    let src = "PROFILE MATCH (n:Person {name: 'p9'}) RETURN n.name AS name";

    let (with_rows, with_plan) = profile(&mut coord, src, &catalog);
    let (without_rows, without_plan) = profile(&mut coord, src, &IndexCatalog::empty());

    assert_eq!(bag(&with_rows), bag(&without_rows), "same bag either way");

    assert!(details_of(&with_plan, "NodeIndexSeek").contains("cache[n.name]"));
    assert_eq!(
        db_hits_of(&with_plan, "Projection"),
        0,
        "the marker claims the property is available; the counter must corroborate"
    );

    assert!(without_plan.contains_operator("NodeLabelScanEq"));
    assert!(
        !details_of(&without_plan, "NodeLabelScanEq").contains("cache["),
        "no index, no marker"
    );
    assert_eq!(
        db_hits_of(&without_plan, "Projection"),
        1,
        "with no marker the consumer must be seen reading the store"
    );
}

// =================================================================================================
// The SSI read footprint is unchanged (TRAP 2)
// =================================================================================================

/// **EVIDENCE.** Serving a projected property from the row must not shrink the transaction's
/// serializability footprint — the superset rule of `rmp` #866, whose single admissible exception
/// (a Snapshot-isolated reader whose markers are dropped unmerged) does not apply here.
///
/// The claim is exact and is tested exactly: the marker set registered by
/// `index_seek_eq(.., Carry)` **alone** must equal the one registered by
/// `index_seek_eq(.., Discard)` **followed by a `node_property` read per matching id** — which is
/// what the plan did before this change. It holds because a property read's only marker is the
/// per-node SIREAD `node_exists` registers, and the seek's own candidate re-check
/// (`filter_label_candidates`) has already registered it for every candidate it examined; the
/// eliminated read therefore contributed nothing new.
///
/// Non-vacuity: the two runs are asserted to find the same rows and the marker set is asserted
/// non-empty, so an implementation that registered nothing at all could not pass.
#[test]
fn carrying_the_value_does_not_narrow_the_ssi_read_footprint_879() {
    use graphus_cypher::graph_access::{GraphAccess, KeyValues};

    let mut coord = fresh_coord();
    let _catalog = people_with_indexes(&mut coord);

    // (a) The carrying run: one seek, nothing else.
    let txn_a = coord.begin_serializable();
    let (hits_a, markers_a) = {
        let graph = coord.statement(txn_a).expect("statement");
        let hits = graph
            .index_seek_eq(
                "Person",
                "name",
                &Value::String("p7".to_owned()),
                KeyValues::Carry,
            )
            .expect("an Online index must serve the seek");
        let buf = graph
            .take_read_buffer()
            .expect("a coordinated statement holds a SIREAD buffer");
        (hits, buf.into_sorted_markers())
    };
    let _ = coord.commit(txn_a);

    // (b) The reference run: the same seek WITHOUT carrying, then the property read the plan used to
    //     perform for each matching row.
    let txn_b = coord.begin_serializable();
    let (hits_b, markers_b) = {
        let graph = coord.statement(txn_b).expect("statement");
        let hits = graph
            .index_seek_eq(
                "Person",
                "name",
                &Value::String("p7".to_owned()),
                KeyValues::Discard,
            )
            .expect("an Online index must serve the seek");
        for id in &hits.matched {
            let _ = graph.node_property(*id, "name");
        }
        let buf = graph
            .take_read_buffer()
            .expect("a coordinated statement holds a SIREAD buffer");
        (hits, buf.into_sorted_markers())
    };
    let _ = coord.commit(txn_b);

    assert_eq!(
        hits_a.matched, hits_b.matched,
        "the two runs must find the same rows (else the footprint comparison is vacuous)"
    );
    assert!(
        !hits_a.matched.is_empty(),
        "the seek must match something (else the footprint comparison is vacuous)"
    );
    assert_eq!(
        hits_a.key_values.len(),
        hits_a.matched.len(),
        "the carrying run must actually carry (else it is not the path under test)"
    );
    assert!(
        hits_b.key_values.is_empty(),
        "the reference run carries nothing"
    );

    assert!(
        !markers_a.1.is_empty(),
        "the seek must register per-record SIREAD markers — assertion vacuous otherwise"
    );
    assert_eq!(
        markers_a.1, markers_b.1,
        "per-record SIREAD markers must be IDENTICAL with and without the eliminated read"
    );
    assert_eq!(
        markers_a.2, markers_b.2,
        "predicate SIREAD markers must be IDENTICAL with and without the eliminated read"
    );
}

// =================================================================================================
// Row-level invariants
// =================================================================================================

/// **GUARD.** The memo is invisible to row identity, so `DISTINCT` cannot observe it: a row that
/// arrived through a seek and one that arrived through a scan must collapse together.
#[test]
fn the_memo_is_invisible_to_row_identity_879() {
    let mut coord = fresh_coord();
    let catalog = people_with_indexes(&mut coord);
    // The union's left branch is served by the index seek, the right by the label scan; `DISTINCT`
    // must fold the two identical rows into one.
    let src = "MATCH (n:Person {name: 'p2'}) RETURN DISTINCT n.name AS name \
               UNION MATCH (m:Person) WHERE m.name = 'p2' RETURN DISTINCT m.name AS name";
    let rows = run(&mut coord, src, &catalog);
    assert_eq!(
        rows.len(),
        1,
        "UNION must fold the seek row and the scan row into one: {rows:?}"
    );
    assert_eq!(rows[0].value("name"), Value::String("p2".to_owned()));
}

/// **GUARD.** `Row::cached_property` refuses to answer once the variable is re-bound in place, which
/// is the mechanism every re-binding decline above relies on. Pinned directly so a refactor that
/// dropped the node-identity check fails here, loudly, and not only through a query that happens to
/// exercise it.
#[test]
fn row_cached_property_requires_the_same_node_879() {
    use graphus_cypher::graph_access::NodeId;
    use graphus_cypher::runtime::{NodeRef, cached_property_key};

    let key = cached_property_key("n", "name");
    let mut row = Row::from_pairs([("n".to_owned(), RowValue::Node(NodeRef { id: NodeId(7) }))]);
    row.cache_property(key, NodeId(7), Value::String("seven".to_owned()));
    assert_eq!(
        row.cached_property("n", "name"),
        Some(&Value::String("seven".to_owned()))
    );
    // A different property, a different variable: both miss.
    assert_eq!(row.cached_property("n", "age"), None);
    assert_eq!(row.cached_property("m", "name"), None);
    // Re-bind `n` to another node: the memo must stop answering.
    row.set("n", RowValue::Node(NodeRef { id: NodeId(8) }));
    assert_eq!(
        row.cached_property("n", "name"),
        None,
        "a memo must never answer for a node the row no longer binds"
    );
    // Re-bind to null (the `OPTIONAL MATCH` shape): still a miss.
    row.set("n", RowValue::NULL);
    assert_eq!(row.cached_property("n", "name"), None);
}
