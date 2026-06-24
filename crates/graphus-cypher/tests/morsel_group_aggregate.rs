//! Equivalence + determinism guard for the **morsel-driven parallel GROUPED aggregation** tier (`rmp`
//! task #360 — the non-empty-`GROUP BY` counterpart of the keyless Slice-3a tier, and the actual LDBC-BI
//! bottleneck: `MATCH (n:Label) RETURN n.<key>, <agg>(n.<p>)`).
//!
//! The tier partitions the label's candidate-id vector into contiguous morsels, builds a LOCAL group
//! table per morsel **concurrently** on the dedicated pool, then merges the partials **deterministically**
//! on the engine thread (groups emitted in serial first-seen order). The whole point is that this is
//! **byte-identical** — rows, values AND order — to the serial `aggregate_rows` over the same scan.
//!
//! These guards drive the **real executor + coordinator** end-to-end (so they engage the real tier above
//! the cardinality gate), with the morsel knob set around each phase, and assert:
//!
//! 1. **parallel == serial, byte-identical** (rows + values + order) for the full mergeable-aggregate set
//!    (`count(*)` / `count(n.p)` / `sum(n.p)` / `min(n.p)` / `max(n.p)` / `collect(n.p)` /
//!    `collect(DISTINCT n.p)`), each run with the knob OFF (serial) then ON (parallel) and `assert_eq`d;
//! 2. **determinism across worker counts** — the same query at knob 1 / 2 / 8 yields the identical
//!    row sequence (output order must not depend on worker scheduling);
//! 3. **float-`sum` group bit-identity** — a `sum` over a FLOAT column declines the parallel path (float
//!    `+` is non-associative) and falls back to serial, so the result is still bit-identical to knob = 1;
//! 4. **i64-saturation regression** — a `sum` whose column saturates `i64` (the
//!    `[i64::MAX, i64::MAX, -i64::MAX, -i64::MAX]` case, where `saturating_add` is order-dependent) is
//!    bit-identical to serial: the saturation gate makes the parallel tier decline so serial folds it
//!    exactly.
//!
//! The integer/string columns keep the parallel `sum` on its provably-associative no-overflow path; the
//! float / saturation columns prove the *decline* path is correct.

use graphus_core::Value;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::runtime::RowValue;
use graphus_cypher::semantics::analyze;

/// A column value rendered to a stable, comparable form (so two result row-sequences can be `assert_eq`d
/// byte-for-byte regardless of the underlying `RowValue` boxing). The `Debug` of `RowValue` is fully
/// structural (lists recurse), so it is the comparison form.
fn render_rv(rv: &RowValue) -> String {
    format!("{rv:?}")
}

/// Renders one result row to an ordered `(column-name, rendered-value)` vector — the unit of byte-for-byte
/// comparison between the serial and parallel runs. Uses the parallel `columns()` / `values()` slices.
fn render_row(row: &graphus_cypher::runtime::Row) -> Vec<(String, String)> {
    row.columns()
        .iter()
        .zip(row.values())
        .map(|(name, rv)| (name.clone(), render_rv(rv)))
        .collect()
}

/// Runs `src` over the coordinator in a fresh committed read transaction, returning the rendered row
/// sequence (order preserved). Mirrors `tests/morsel_rows.rs::run_rows`.
fn run_rows(
    coord: &mut TxnCoordinator<MemBlockDevice, MemLogSink>,
    src: &str,
) -> Vec<Vec<(String, String)>> {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let plan = plan_physical(
        &lower(&analyze(&ast).expect("analyze")),
        &IndexCatalog::empty(),
    );
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");

    let txn = coord.begin_serializable();
    let rendered = {
        let mut graph = coord.statement(txn).expect("statement");
        let rows = {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect")
        };
        assert!(
            !graph.has_error(),
            "statement captured an error: {:?}",
            graph.take_error()
        );
        rows.iter().map(render_row).collect()
    };
    coord.commit(txn).expect("read commits");
    rendered
}

/// Bulk-seeds `n` committed `:Person` nodes with a `country` (one of `cardinality` distinct values, so
/// the GROUP BY produces `cardinality` groups) and an integer `age` (small, so the parallel `sum` stays on
/// its provably-associative no-overflow path), then wraps the store in a `TxnCoordinator` whose durable
/// statistics report `nodes_with_label("Person") == n` (so the tier's cardinality gate engages above
/// `MORSEL_MIN_ROWS = 50_000`). The country assignment is `id % cardinality` so the first occurrence of
/// each country is at a small, distinct candidate index — the first-seen order is `Country0, Country1, …`.
fn coord_with_grouped_people(
    n: i64,
    cardinality: i64,
) -> TxnCoordinator<MemBlockDevice, MemLogSink> {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    // A deliberately small pool (64 frames) so the concurrent morsel scan over a much larger node store
    // exercises the concurrent eviction path, not just resident-page reads (the workload that surfaced the
    // `rmp` #337 lost-pin race — running the grouped end-to-end over a small pool guards it stays correct).
    let mut s = RecordStore::create(device, wal, 64, 1).expect("create store");
    let txn = graphus_core::TxnId(1);
    s.begin(txn);
    let l_person = s.intern_token(Namespace::Label, "Person").unwrap();
    let k_country = s.intern_token(Namespace::PropKey, "country").unwrap();
    let k_age = s.intern_token(Namespace::PropKey, "age").unwrap();
    for i in 0..n {
        let (id, _) = s.create_node(txn).unwrap();
        s.add_label(txn, id, l_person).unwrap();
        let country = format!("Country{}", i % cardinality);
        s.set_node_property_value(txn, id, k_country, &Value::String(country))
            .unwrap();
        // age in [0, 100): small magnitude, so per-group integer sums never approach the i64 rail.
        s.set_node_property_value(txn, id, k_age, &Value::Integer(i % 100))
            .unwrap();
    }
    s.commit(txn).unwrap();
    TxnCoordinator::new(s)
}

/// The headline equivalence guard (`rmp` #360 AC test a): for every mergeable grouped aggregate, the
/// parallel result bag (rows + values + ORDER) is byte-identical to the serial `aggregate_rows` on the
/// same input. Each query is run with the knob OFF (serial) then ON (parallel) and `assert_eq`d.
///
/// The queries have NO `ORDER BY`, so the serial first-seen group order is the observable order — the
/// parallel merge MUST reproduce it exactly (the determinism AC), not merely produce the same set.
#[test]
fn grouped_parallel_matches_serial_byte_identical() {
    // 80k > MORSEL_MIN_ROWS (50k), 8 countries ⇒ 8 groups, ~10k rows each.
    let mut coord = coord_with_grouped_people(80_000, 8);

    let queries = [
        "MATCH (n:Person) RETURN n.country AS c, count(*) AS k",
        "MATCH (n:Person) RETURN n.country AS c, count(n.age) AS k",
        "MATCH (n:Person) RETURN n.country AS c, sum(n.age) AS s",
        "MATCH (n:Person) RETURN n.country AS c, min(n.age) AS lo",
        "MATCH (n:Person) RETURN n.country AS c, max(n.age) AS hi",
        "MATCH (n:Person) RETURN n.country AS c, count(*) AS k, sum(n.age) AS s, min(n.age) AS lo, max(n.age) AS hi",
        "MATCH (n:Person) RETURN n.country AS c, collect(DISTINCT n.age) AS ages",
    ];

    for q in queries {
        graphus_cypher::morsel::set_morsel_threads(1);
        let serial = run_rows(&mut coord, q);

        graphus_cypher::morsel::set_morsel_threads(8);
        let parallel = run_rows(&mut coord, q);

        assert_eq!(
            serial, parallel,
            "`{q}`: the parallel grouped result (rows + values + order) must equal serial"
        );
        // Sanity: 8 groups, in first-seen order Country0..Country7.
        assert_eq!(serial.len(), 8, "`{q}`: must produce one row per country");
        assert_eq!(
            serial[0][0],
            ("c".to_owned(), "Value(String(\"Country0\"))".to_owned()),
            "`{q}`: the first group is the first-seen country (Country0)"
        );
    }

    graphus_cypher::morsel::set_morsel_threads(1);
}

/// `collect(n.p)` is order-sensitive (the list preserves scan-encounter order); the parallel merge
/// concatenates morsels in ascending-`lo` order, which must reproduce the serial encounter order
/// byte-for-byte. Driven separately with a SMALL distinct-value column so the collected lists are
/// inspectable, but still over a large scan so the tier engages (`rmp` #360 AC test a, collect arm).
#[test]
fn grouped_collect_order_matches_serial() {
    // Many rows per group; `age = id % 100` makes each group's collected list a long, ordered sequence.
    let mut coord = coord_with_grouped_people(60_000, 3);
    let q = "MATCH (n:Person) RETURN n.country AS c, collect(n.age) AS ages";

    graphus_cypher::morsel::set_morsel_threads(1);
    let serial = run_rows(&mut coord, q);

    graphus_cypher::morsel::set_morsel_threads(8);
    let parallel = run_rows(&mut coord, q);

    assert_eq!(
        serial, parallel,
        "`collect` over a grouped scan must preserve serial encounter order under parallelism"
    );
    graphus_cypher::morsel::set_morsel_threads(1);

    // The collected lists are non-trivial (each group has tens of thousands of elements).
    assert_eq!(serial.len(), 3, "3 countries ⇒ 3 groups");
}

/// Determinism across worker counts (`rmp` #360 AC test b): the same grouped query at knob 1 / 2 / 8 must
/// yield the IDENTICAL row sequence — output order cannot depend on worker scheduling.
#[test]
fn grouped_output_order_is_worker_count_independent() {
    let mut coord = coord_with_grouped_people(70_000, 16);
    let q = "MATCH (n:Person) RETURN n.country AS c, count(*) AS k, sum(n.age) AS s";

    graphus_cypher::morsel::set_morsel_threads(1);
    let serial = run_rows(&mut coord, q);

    for knob in [2usize, 8, 16] {
        graphus_cypher::morsel::set_morsel_threads(knob);
        let parallel = run_rows(&mut coord, q);
        assert_eq!(
            serial, parallel,
            "knob={knob}: grouped output (order included) must be identical to serial (knob=1)"
        );
    }

    graphus_cypher::morsel::set_morsel_threads(1);
    assert_eq!(serial.len(), 16, "16 countries ⇒ 16 groups");
}

/// Float-`sum` group bit-identity (`rmp` #360 AC test c): a `sum` over a FLOAT column declines the
/// parallel path (float `+` is non-associative — a parallel reduction tree could round differently than
/// the serial left fold) and falls back to serial, so the result is bit-identical to knob = 1.
///
/// Seeds a float `score` column so `sum(n.score)` exercises the decline path; the result must equal the
/// serial fold exactly (the gate makes the parallel tier return `None`, so serial folds the column).
#[test]
fn grouped_float_sum_matches_serial_via_decline() {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut s = RecordStore::create(device, wal, 64, 1).expect("create store");
    let txn = graphus_core::TxnId(1);
    s.begin(txn);
    let l = s.intern_token(Namespace::Label, "Person").unwrap();
    let k_country = s.intern_token(Namespace::PropKey, "country").unwrap();
    let k_score = s.intern_token(Namespace::PropKey, "score").unwrap();
    let n: i64 = 60_000;
    for i in 0..n {
        let (id, _) = s.create_node(txn).unwrap();
        s.add_label(txn, id, l).unwrap();
        s.set_node_property_value(txn, id, k_country, &Value::String(format!("C{}", i % 4)))
            .unwrap();
        // A float column with non-representable-sum fractions so the order of additions matters.
        s.set_node_property_value(txn, id, k_score, &Value::Float((i as f64) * 0.1))
            .unwrap();
    }
    s.commit(txn).unwrap();
    let mut coord = TxnCoordinator::new(s);

    let q = "MATCH (n:Person) RETURN n.country AS c, sum(n.score) AS total";

    graphus_cypher::morsel::set_morsel_threads(1);
    let serial = run_rows(&mut coord, q);

    graphus_cypher::morsel::set_morsel_threads(8);
    let parallel = run_rows(&mut coord, q);

    assert_eq!(
        serial, parallel,
        "float `sum` grouped: the parallel path must decline and match the serial f64 fold bit-for-bit"
    );
    graphus_cypher::morsel::set_morsel_threads(1);
    assert_eq!(serial.len(), 4, "4 groups");
}

/// i64-saturation regression (`rmp` #360, finding C): a `sum` whose column saturates `i64` is
/// bit-identical to serial. `saturating_add` is NOT associative once any partition subtree clamps to the
/// rail (`[i64::MAX, i64::MAX, -i64::MAX, -i64::MAX]` folds to `MIN+1` serially but `-1` under a 2+2
/// split), so the parallel tier's saturation gate makes it decline and serial folds the column exactly.
///
/// One group holds the four rail values (so a parallel reduction would saturate a sub-sum); the other
/// groups hold small values (which never saturate). The whole result must equal the serial fold.
#[test]
fn grouped_sum_saturation_matches_serial() {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut s = RecordStore::create(device, wal, 64, 1).expect("create store");
    let txn = graphus_core::TxnId(1);
    s.begin(txn);
    let l = s.intern_token(Namespace::Label, "Person").unwrap();
    let k_country = s.intern_token(Namespace::PropKey, "country").unwrap();
    let k_v = s.intern_token(Namespace::PropKey, "v").unwrap();

    // The four i64-rail values, all in group "RAIL" (so a parallel sub-sum could saturate). To make the
    // tier engage (cardinality gate ≥ 50k) we pad with many small-valued rows in other groups.
    let rail = [i64::MAX, i64::MAX, -i64::MAX, -i64::MAX];
    for &val in &rail {
        let (id, _) = s.create_node(txn).unwrap();
        s.add_label(txn, id, l).unwrap();
        s.set_node_property_value(txn, id, k_country, &Value::String("RAIL".to_owned()))
            .unwrap();
        s.set_node_property_value(txn, id, k_v, &Value::Integer(val))
            .unwrap();
    }
    let pad: i64 = 60_000;
    for i in 0..pad {
        let (id, _) = s.create_node(txn).unwrap();
        s.add_label(txn, id, l).unwrap();
        s.set_node_property_value(txn, id, k_country, &Value::String(format!("G{}", i % 4)))
            .unwrap();
        s.set_node_property_value(txn, id, k_v, &Value::Integer(i % 7))
            .unwrap();
    }
    s.commit(txn).unwrap();
    let mut coord = TxnCoordinator::new(s);

    let q = "MATCH (n:Person) RETURN n.country AS c, sum(n.v) AS s";

    graphus_cypher::morsel::set_morsel_threads(1);
    let serial = run_rows(&mut coord, q);

    graphus_cypher::morsel::set_morsel_threads(8);
    let parallel = run_rows(&mut coord, q);

    assert_eq!(
        serial, parallel,
        "saturating `sum` grouped: the parallel tier must decline (saturation gate) so the result equals \
         the serial incremental-saturation fold bit-for-bit"
    );

    // The serial RAIL group sum is the incremental-saturation result (MIN+1), NOT the true total (0): the
    // assertion above guarantees the parallel result matches it exactly.
    let rail_row = serial
        .iter()
        .find(|r| r[0] == ("c".to_owned(), "Value(String(\"RAIL\"))".to_owned()))
        .expect("RAIL group present");
    let expected_rail: i64 = rail.iter().fold(0i64, |a, &v| a.saturating_add(v));
    assert_eq!(
        rail_row[1],
        ("s".to_owned(), format!("Value(Integer({expected_rail}))")),
        "the RAIL group's sum is the serial incremental-saturation value"
    );

    graphus_cypher::morsel::set_morsel_threads(1);
}
