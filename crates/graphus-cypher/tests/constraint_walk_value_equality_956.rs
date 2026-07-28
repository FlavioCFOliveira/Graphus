//! **The uniqueness walk decides by Cypher value equality, whatever bucket a value hashes into**
//! (`rmp` task #956).
//!
//! `rmp` task #956 replaced the walk's linear duplicate search with a hash-bucketed set. A hash is the
//! wrong relation for Cypher values, so the set uses it only to choose a bucket and still confirms
//! every candidate with `crate::equality::equals`. Two obligations follow, and each has teeth only if a
//! test drives real values through the walk:
//!
//! * **Equal values must share a bucket.** `1 = 1.0` is `TRUE` across `INTEGER`/`FLOAT`. Had the set
//!   keyed on Rust's `Hash`/`Eq`, or on any digest that separated the two spellings, the walk would
//!   file the second value where the probe never looks and **accept a constraint the data violates** —
//!   a silent ACID defect that publishes a false schema guarantee.
//! * **A shared bucket must not become an equality.** Above 2^53 the comparison is exact
//!   (`rmp` task #894), so `9007199254740993 = 9007199254740992.0` is `FALSE`; the digest projects
//!   integers through `f64` and therefore puts those two in the *same* bucket. The walk must still tell
//!   them apart and accept. The same holds for `NaN`, which all hashes to one bucket while
//!   `NaN = NaN` is `FALSE`.
//!
//! Before this task the create-time walk had no cross-type, `NaN`, temporal, point or list coverage at
//! all: every existing cross-type constraint test declares the constraint over an empty store or a
//! single row, so the decision was made by the write-time index seek and never by this walk. These
//! gates close that hole, and they are written so that they judge the **walk** — every value is
//! committed *before* the constraint is declared.

use graphus_core::{Point, TxnId, Value};
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
use graphus_cypher::{CONSTRAINT_VIOLATION_PREFIX, ConstraintKind};
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

// =================================================================================================
// Harness (mirrors tests/constraint_ddl_transaction_903.rs)
// =================================================================================================

fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: Store = RecordStore::create(device, wal, 256, 1).expect("create store");
    TxnCoordinator::new(store)
}

fn compile(src: &str) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

/// Runs `src` with `params` in its own transaction and commits it.
fn run_write(coord: &mut Coord, src: &str, params: Parameters) {
    let txn: TxnId = coord.begin_serializable();
    let plan = compile(src);
    let bound = bind_parameters(&plan, &params).expect("bind");
    {
        let mut graph = coord.statement(txn).expect("statement");
        {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            let _rows: Vec<Row> = cursor.collect_all().expect("collect");
        }
        let err = graph.take_error();
        assert!(
            err.is_none(),
            "seed statement {src:?} must not raise a runtime error, got: {err:?}"
        );
    }
    coord.commit(txn).expect("seed commits");
}

/// What the validation walk decided about the already-committed data.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Decision {
    /// The constraint holds over the committed graph.
    Accepted,
    /// The committed graph contains a duplicate, so the constraint was refused.
    Refused,
}

/// Turns a `create_constraint*` outcome into a [`Decision`], insisting that a refusal really is a
/// constraint violation and not some unrelated error dressed up as one.
fn classify(outcome: graphus_core::error::Result<()>) -> Decision {
    match outcome {
        Ok(()) => Decision::Accepted,
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains(CONSTRAINT_VIOLATION_PREFIX),
                "a refusal must be a constraint violation, got: {msg}"
            );
            Decision::Refused
        }
    }
}

/// Commits one `:P` node per element of `values` carrying it as property `v`, then declares
/// `p.v IS UNIQUE` and reports what the **walk** decided.
fn node_unique(values: &[Value]) -> Decision {
    let mut coord = fresh_coord();
    let mut params = Parameters::new();
    params.insert("vals".to_owned(), Value::List(values.to_vec()));
    run_write(&mut coord, "UNWIND $vals AS x CREATE (:P {v: x})", params);
    classify(coord.create_constraint("u_v", "P", "v", ConstraintKind::Unique))
}

/// The composite twin of [`node_unique`]: one `:P` node per `(a, b)` pair, then
/// `(p.a, p.b) IS NODE KEY`.
fn node_key(tuples: &[(Value, Value)]) -> Decision {
    let mut coord = fresh_coord();
    let mut params = Parameters::new();
    params.insert(
        "vals".to_owned(),
        Value::List(
            tuples
                .iter()
                .map(|(a, b)| Value::List(vec![a.clone(), b.clone()]))
                .collect(),
        ),
    );
    run_write(
        &mut coord,
        "UNWIND $vals AS x CREATE (:P {a: x[0], b: x[1]})",
        params,
    );
    classify(coord.create_constraint_general(
        "k_ab",
        "P",
        &["a", "b"],
        ConstraintKind::NodeKey,
        None,
    ))
}

/// The relationship twin of [`node_unique`]: one `:LINK` relationship per element, then
/// `r.v IS UNIQUE`.
fn rel_unique(values: &[Value]) -> Decision {
    let mut coord = fresh_coord();
    let mut params = Parameters::new();
    params.insert("vals".to_owned(), Value::List(values.to_vec()));
    run_write(
        &mut coord,
        "UNWIND $vals AS x CREATE (:A)-[:LINK {v: x}]->(:B)",
        params,
    );
    classify(coord.create_constraint_general(
        "ru_v",
        "LINK",
        &["v"],
        ConstraintKind::RelUnique,
        None,
    ))
}

/// The composite relationship twin: one `:LINK` per `(a, b)` pair, then `(r.a, r.b) IS REL KEY`.
fn rel_key(tuples: &[(Value, Value)]) -> Decision {
    let mut coord = fresh_coord();
    let mut params = Parameters::new();
    params.insert(
        "vals".to_owned(),
        Value::List(
            tuples
                .iter()
                .map(|(a, b)| Value::List(vec![a.clone(), b.clone()]))
                .collect(),
        ),
    );
    run_write(
        &mut coord,
        "UNWIND $vals AS x CREATE (:A)-[:LINK {a: x[0], b: x[1]}]->(:B)",
        params,
    );
    classify(coord.create_constraint_general(
        "rk_ab",
        "LINK",
        &["a", "b"],
        ConstraintKind::RelKey,
        None,
    ))
}

fn i(n: i64) -> Value {
    Value::Integer(n)
}
fn f(x: f64) -> Value {
    Value::Float(x)
}
fn s(x: &str) -> Value {
    Value::String(x.to_owned())
}

// =================================================================================================
// Non-vacuity: the harness reaches the walk at all
// =================================================================================================

/// The premise every gate below rests on: this harness commits the data *first*, so the decision is
/// the walk's. A duplicate must be refused and distinct values accepted — if both came back the same,
/// every assertion in this file would be meaningless.
#[test]
fn the_harness_judges_the_walk_and_can_report_both_answers() {
    assert_eq!(
        node_unique(&[s("a"), s("a")]),
        Decision::Refused,
        "two committed 'a's violate uniqueness"
    );
    assert_eq!(
        node_unique(&[s("a"), s("b")]),
        Decision::Accepted,
        "two distinct committed values satisfy uniqueness"
    );
}

// =================================================================================================
// Equal values must land in the same bucket
// =================================================================================================

/// `1 = 1.0` is `TRUE` in Cypher, so an `INTEGER` and the `FLOAT` spelling of the same number are a
/// duplicate and the constraint must be refused.
///
/// This is the gate that fails if the duplicate set is ever keyed on a relation finer than Cypher
/// equality — a `HashSet<Value>`, or any digest that separates `Integer(1)` from `Float(1.0)`. The
/// failure mode is the dangerous direction: the walk would ACCEPT, publishing a uniqueness guarantee
/// over data that already breaks it.
#[test]
fn an_integer_and_the_equal_float_are_one_value_to_the_walk() {
    assert_eq!(
        node_unique(&[i(1), f(1.0)]),
        Decision::Refused,
        "1 and 1.0 are the same number in Cypher, so they duplicate"
    );
    assert_eq!(
        node_unique(&[f(2.0), i(2)]),
        Decision::Refused,
        "the relation is symmetric: insertion order must not change the verdict"
    );
    assert_eq!(
        node_unique(&[i(1), f(1.5)]),
        Decision::Accepted,
        "non-vacuity: a float that is NOT the integer must still be accepted"
    );
}

/// Signed zeros are equal in Cypher (`-0.0 = +0.0` is `TRUE`) and the digest normalises them, so a
/// `0`, a `0.0` and a `-0.0` are all one value.
#[test]
fn signed_zeros_and_the_integer_zero_are_one_value_to_the_walk() {
    assert_eq!(node_unique(&[f(-0.0), f(0.0)]), Decision::Refused);
    assert_eq!(node_unique(&[i(0), f(-0.0)]), Decision::Refused);
}

/// The exactly-representable boundary of `rmp` task #894: 2^53 *is* the same number in both
/// spellings, so it duplicates.
#[test]
fn the_exactly_representable_boundary_still_duplicates() {
    assert_eq!(
        node_unique(&[i(9_007_199_254_740_992), f(9_007_199_254_740_992.0)]),
        Decision::Refused,
        "2^53 is exactly representable, so the integer and the float are one number"
    );
}

/// Equal temporals, points and lists duplicate — the digest hashes each class consistently with the
/// equality used to confirm it.
#[test]
fn equal_temporals_points_and_lists_duplicate() {
    let date = Value::Date(graphus_core::Date {
        days_since_epoch: 18_262,
    });
    assert_eq!(
        node_unique(&[date.clone(), date.clone()]),
        Decision::Refused,
        "two equal dates duplicate"
    );
    assert_eq!(
        node_unique(&[
            date,
            Value::Date(graphus_core::Date {
                days_since_epoch: 18_263
            })
        ]),
        Decision::Accepted,
        "non-vacuity: distinct dates do not"
    );

    let p = Value::Point(Point::new_2d(graphus_core::Crs::Cartesian, 1.0, 2.0));
    assert_eq!(
        node_unique(&[p.clone(), p.clone()]),
        Decision::Refused,
        "two equal points duplicate"
    );
    assert_eq!(
        node_unique(&[
            p,
            Value::Point(Point::new_2d(graphus_core::Crs::Cartesian, 1.0, 2.5)),
        ]),
        Decision::Accepted,
        "non-vacuity: distinct points do not"
    );

    // A stored list must be homogeneous over one element class, so the cross-type case is expressed
    // between two lists rather than inside one.
    let list = Value::List(vec![i(1), i(2)]);
    assert_eq!(
        node_unique(&[list.clone(), Value::List(vec![i(1), i(2)])]),
        Decision::Refused,
        "two equal lists duplicate — the digest recurses in order, as list equality does"
    );
    assert_eq!(
        node_unique(&[list.clone(), Value::List(vec![f(1.0), f(2.0)])]),
        Decision::Refused,
        "and cross-type equality applies ELEMENT-WISE: [1, 2] = [1.0, 2.0]"
    );
    assert_eq!(
        node_unique(&[list, Value::List(vec![i(1), i(3)])]),
        Decision::Accepted,
        "non-vacuity: lists differing in an element do not"
    );
}

// =================================================================================================
// A shared bucket must not become an equality
// =================================================================================================

/// The `rmp` task #894 pair. `9007199254740993 as f64` **is** `9007199254740992.0`, so the digest —
/// which projects integers through `f64` — files both under one key. Cypher equality compares them
/// exactly and reports `FALSE`, so the walk must ACCEPT: the bucket is a hint, never the verdict.
///
/// Reverting the confirmation step to a bare digest comparison turns this into a refusal, which is why
/// this gate exists rather than only its mirror above.
#[test]
fn two_numbers_sharing_a_bucket_above_2_53_are_still_distinct() {
    assert_eq!(
        node_unique(&[i(9_007_199_254_740_993), f(9_007_199_254_740_992.0)]),
        Decision::Accepted,
        "2^53+1 is not 2^53 even though it rounds to it: the constraint holds"
    );
    assert_eq!(
        node_unique(&[i(9_007_199_254_740_993), i(9_007_199_254_740_994)]),
        Decision::Accepted,
        "two distinct integers above 2^53 that round to one double must stay distinct"
    );
}

/// `NaN = NaN` is `FALSE` (openCypher CIP §Equality), while every `NaN` hashes to one canonical
/// bucket. Two `NaN`s therefore collide and must still be accepted.
#[test]
fn two_nans_share_a_bucket_and_are_still_not_duplicates() {
    assert_eq!(
        node_unique(&[f(f64::NAN), f(f64::NAN)]),
        Decision::Accepted,
        "NaN never equals anything, including another NaN, so no duplicate exists"
    );
}

// =================================================================================================
// The same relation on the composite and relationship paths
// =================================================================================================

/// Composite `NODE KEY` compares tuples, and it must do so with the same cross-type equality: the
/// tuple `(1, 'x')` duplicates `(1.0, 'x')`.
#[test]
fn node_key_tuples_use_the_same_cross_type_equality() {
    assert_eq!(
        node_key(&[(i(1), s("x")), (f(1.0), s("x"))]),
        Decision::Refused,
        "(1, 'x') and (1.0, 'x') are the same key"
    );
    assert_eq!(
        node_key(&[(i(1), s("x")), (i(1), s("y"))]),
        Decision::Accepted,
        "non-vacuity: tuples differing in the second component are distinct keys"
    );
    assert_eq!(
        node_key(&[
            (i(9_007_199_254_740_993), s("x")),
            (f(9_007_199_254_740_992.0), s("x")),
        ]),
        Decision::Accepted,
        "and a tuple whose first component only SHARES A BUCKET is a distinct key"
    );
}

/// The relationship walk is a separate function with its own duplicate set, so it gets its own gates —
/// a shared helper is no substitute for driving both paths.
#[test]
fn the_relationship_walk_uses_the_same_relation() {
    assert_eq!(
        rel_unique(&[i(1), f(1.0)]),
        Decision::Refused,
        "1 and 1.0 duplicate on a relationship property too"
    );
    assert_eq!(
        rel_unique(&[i(1), f(2.0)]),
        Decision::Accepted,
        "non-vacuity: distinct relationship values are accepted"
    );
    assert_eq!(
        rel_unique(&[i(9_007_199_254_740_993), f(9_007_199_254_740_992.0)]),
        Decision::Accepted,
        "and the bucket collision is resolved exactly on the relationship path"
    );
}

/// Composite `REL KEY` over pre-existing data — the arm the survey for this task found had **no**
/// create-time duplicate coverage at all: every prior test declared the rel-composite constraint
/// before any matching relationship existed, so the tuple comparison was never exercised by the walk.
#[test]
fn rel_key_tuples_are_compared_by_the_walk() {
    assert_eq!(
        rel_key(&[(i(1), s("x")), (i(1), s("x"))]),
        Decision::Refused,
        "a committed duplicate REL KEY tuple must refuse the constraint"
    );
    assert_eq!(
        rel_key(&[(i(1), s("x")), (f(1.0), s("x"))]),
        Decision::Refused,
        "and cross-type equality applies to the tuple's components"
    );
    assert_eq!(
        rel_key(&[(i(1), s("x")), (i(2), s("x"))]),
        Decision::Accepted,
        "non-vacuity: distinct tuples are accepted"
    );
}

// =================================================================================================
// The bucketing must not lose a distant duplicate
// =================================================================================================

/// A duplicate separated from its twin by many thousands of other values must still be found. A linear
/// scan finds it trivially; a bucketed set finds it only if the two really hash alike and the bucket
/// is probed. The pair is deliberately cross-type, so this is also the large-scale form of the
/// `1 = 1.0` gate.
#[test]
fn a_duplicate_at_the_far_end_of_a_long_walk_is_still_found() {
    const N: i64 = 5_000;
    let mut values: Vec<Value> = (0..N).map(i).collect();
    // The float spelling of the very first value, appended last: maximal distance between the twins.
    values.push(f(0.0));
    assert_eq!(
        node_unique(&values),
        Decision::Refused,
        "the duplicate of the FIRST value, committed last, must still be found"
    );

    let distinct: Vec<Value> = (0..=N).map(i).collect();
    assert_eq!(
        node_unique(&distinct),
        Decision::Accepted,
        "non-vacuity: the same walk over {N} distinct values accepts, so the refusal above is the \
         duplicate and not the size"
    );
}
