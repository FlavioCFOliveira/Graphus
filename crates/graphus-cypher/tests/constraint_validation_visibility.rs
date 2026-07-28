//! Creation-time constraint validation must judge the **committed** graph, not raw physical state
//! (`rmp` task #902).
//!
//! `CREATE CONSTRAINT` validates existing data before it declares the rule. That walk used to read
//! the store physically — `scan_node_ids()` / `scan_rel_ids()` (which include MVCC tombstones the GC
//! has not reclaimed yet) and the chain-head property version (with no `expired_ts` check) — so it
//! judged the constraint against values that **no query can observe**:
//!
//! * a property removed and committed still counted toward uniqueness, so a `IS UNIQUE` constraint
//!   was refused over a duplicate that does not exist;
//! * the same removed value satisfied `IS NOT NULL`, so an existence constraint was accepted over a
//!   node that lacks the property;
//! * a deleted node/relationship still counted until the next GC pass — and GC has no automatic
//!   trigger (`rmp` #305), so the refusal was permanent in practice.
//!
//! The polarity here is the opposite of an index *population* (`rmp` #765/#766/#771): a candidate
//! index may be a superset because the seek re-checks visibility, while a constraint decision is
//! final and is never re-checked. These tests pin the committed-state semantics, in both directions
//! (a real committed duplicate is still refused), for nodes and for relationships.
//!
//! They also pin the **fail-closed guard**: while another transaction holds uncommitted writes the
//! DDL refuses with a retryable [`GraphusError::Transaction`] rather than deciding on data that may
//! be rolled back or may still commit (see `TxnCoordinator::create_constraint_general`).

use graphus_core::{GraphusError, TxnId, Value};
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
// Harness (mirrors tests/constraint_coordinator.rs)
// =================================================================================================

fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: Store = RecordStore::create(device, wal, 64, 1).expect("create store");
    TxnCoordinator::new(store)
}

fn compile(src: &str) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

/// Runs `src` inside `txn` and returns the rows, asserting no runtime error was captured. The
/// transaction is left **open** — the caller decides whether to commit or to keep it uncommitted.
fn run_in(coord: &Coord, txn: TxnId, src: &str) -> Vec<Row> {
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let rows: Vec<Row> = {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    assert!(
        graph.take_error().is_none(),
        "statement {src:?} must not raise a runtime error"
    );
    rows
}

/// Runs a write statement in its own transaction and **commits** it.
fn run_write(coord: &mut Coord, src: &str) {
    let txn = coord.begin_serializable();
    let _rows = run_in(coord, txn, src);
    coord.commit(txn).expect("write commits");
}

/// Runs a write statement in a fresh transaction and leaves that transaction **open**, so its writes
/// stay uncommitted. Returns the open transaction id (the caller must resolve it).
fn begin_uncommitted_write(coord: &mut Coord, src: &str) -> TxnId {
    let txn = coord.begin_serializable();
    let _rows = run_in(coord, txn, src);
    txn
}

/// The values a `MATCH` projects, as a sorted vector of their rendered form — the committed image the
/// constraint decision must agree with.
fn matched(coord: &mut Coord, src: &str, column: &str) -> Vec<String> {
    let txn = coord.begin_serializable();
    let rows = run_in(coord, txn, src);
    coord.commit(txn).expect("read commits");
    let mut out: Vec<String> = rows
        .iter()
        .map(|r| match r.value(column) {
            Value::String(s) => s.clone(),
            other => format!("{other:?}"),
        })
        .collect();
    out.sort();
    out
}

fn assert_constraint_violation(e: &GraphusError) {
    let msg = e.to_string();
    assert!(
        msg.contains(CONSTRAINT_VIOLATION_PREFIX),
        "expected a constraint-violation error, got: {msg}"
    );
}

// =================================================================================================
// Nodes: a committed property removal is not part of the state
// =================================================================================================

/// The headline `rmp` #902 reproduction. `a.email` is removed and committed, then `b` takes the same
/// value: exactly one node holds `'x'`, so `IS UNIQUE` must be **accepted**.
///
/// Pre-fix this was refused, naming a duplicate on `'x'` that no `MATCH` can find: the validation
/// walk read the chain-head property version without checking `expired_ts`, so the tombstoned `'x'`
/// on `a` still counted.
#[test]
fn unique_accepts_when_the_duplicate_value_was_removed_and_committed() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {email: 'x', tag: 'a'})");
    run_write(&mut coord, "MATCH (n:P {tag: 'a'}) REMOVE n.email");
    run_write(&mut coord, "CREATE (:P {email: 'x', tag: 'b'})");

    // The committed image: exactly one node carries `email`, so there is no duplicate to find.
    assert_eq!(
        matched(
            &mut coord,
            "MATCH (n:P) WHERE n.email IS NOT NULL RETURN n.email AS e",
            "e"
        ),
        vec!["x".to_owned()],
        "precondition: only one node holds an email"
    );

    coord
        .create_constraint("uniq_email", "P", "email", ConstraintKind::Unique)
        .expect("IS UNIQUE must be accepted: the removed value is not part of the committed state");
}

/// The mirror case. `a.email` was removed and committed, so `a` **lacks** the property and
/// `IS NOT NULL` must be **refused**. Pre-fix the tombstoned value satisfied the check and the
/// constraint was accepted over a node that violates it — a schema object that lies.
#[test]
fn not_null_refuses_when_the_property_was_removed_and_committed() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {email: 'x', tag: 'a'})");
    run_write(&mut coord, "MATCH (n:P {tag: 'a'}) REMOVE n.email");

    assert!(
        matched(
            &mut coord,
            "MATCH (n:P) WHERE n.email IS NOT NULL RETURN n.email AS e",
            "e"
        )
        .is_empty(),
        "precondition: no node holds an email any more"
    );

    let err = coord
        .create_constraint("email_exists", "P", "email", ConstraintKind::Existence)
        .expect_err("IS NOT NULL must be refused: the node no longer has the property");
    assert_constraint_violation(&err);
}

/// The overwrite path pins the other half of the resolution rule: `SET` tombstones the old version
/// and PREPENDS the new one, so the newest version must win. This one already held before `rmp` #902
/// (chain-head-wins and newest-wins agree when the newest version is live) — it is here so the
/// `expired_ts` guard cannot be "fixed" by walking past the newest version to an older live one.
#[test]
fn unique_accepts_when_the_duplicate_value_was_overwritten_and_committed() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {email: 'x', tag: 'a'})");
    run_write(&mut coord, "CREATE (:P {email: 'y', tag: 'b'})");
    run_write(&mut coord, "MATCH (n:P {tag: 'b'}) SET n.email = 'z'");

    coord
        .create_constraint("uniq_email", "P", "email", ConstraintKind::Unique)
        .expect("IS UNIQUE must be accepted: 'y' was overwritten, the live values are 'x' and 'z'");
}

// =================================================================================================
// Nodes: an uncollected MVCC tombstone is not part of the state
// =================================================================================================

/// A deleted node keeps its slot until GC reclaims it, and GC has no automatic trigger (`rmp` #305),
/// so `scan_node_ids()` returns it indefinitely. Its committed deletion must not refuse a constraint
/// the live data satisfies — and the acceptance must not have to wait for a GC pass.
#[test]
fn unique_accepts_over_an_uncollected_node_tombstone() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {email: 'x', tag: 'a'})");
    run_write(&mut coord, "MATCH (n:P {tag: 'a'}) DELETE n");
    run_write(&mut coord, "CREATE (:P {email: 'x', tag: 'b'})");

    assert_eq!(
        matched(&mut coord, "MATCH (n:P) RETURN n.email AS e", "e"),
        vec!["x".to_owned()],
        "precondition: exactly one live node carries the label"
    );

    coord
        .create_constraint("uniq_email", "P", "email", ConstraintKind::Unique)
        .expect("IS UNIQUE must be accepted over an uncollected tombstone, without waiting for GC");
}

/// The existence twin: a deleted node must not be checked for the property at all. Pre-fix the
/// tombstone was scanned, and (had its property also been removed) it would have refused a valid
/// `IS NOT NULL`.
#[test]
fn not_null_accepts_over_an_uncollected_node_tombstone_that_lacks_the_property() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {tag: 'a'})"); // no `email` at all
    run_write(&mut coord, "MATCH (n:P {tag: 'a'}) DELETE n");
    run_write(&mut coord, "CREATE (:P {email: 'x', tag: 'b'})");

    coord
        .create_constraint("email_exists", "P", "email", ConstraintKind::Existence)
        .expect("IS NOT NULL must ignore a deleted node: every LIVE node has the property");
}

// =================================================================================================
// Nodes: the fix must not weaken validation
// =================================================================================================

/// Non-vacuity of the fix itself: a genuine committed duplicate is still refused. Without this, a fix
/// that simply stopped looking would pass every test above.
#[test]
fn unique_still_refuses_a_real_committed_duplicate() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {email: 'x', tag: 'a'})");
    run_write(&mut coord, "CREATE (:P {email: 'x', tag: 'b'})");

    let err = coord
        .create_constraint("uniq_email", "P", "email", ConstraintKind::Unique)
        .expect_err("two live nodes share 'x': the constraint must be refused");
    assert_constraint_violation(&err);
}

/// The composite twin (`NODE KEY`): a removed component must not complete a tuple. After the removal
/// `a` has no `email`, so its tuple is incomplete and the KEY's existence half must refuse.
#[test]
fn node_key_refuses_when_a_covered_property_was_removed_and_committed() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {email: 'x', kind: 'k', tag: 'a'})");
    run_write(&mut coord, "MATCH (n:P {tag: 'a'}) REMOVE n.email");

    let err = coord
        .create_constraint_general("pk", "P", &["email", "kind"], ConstraintKind::NodeKey, None)
        .expect_err("NODE KEY must be refused: the live node lacks a covered property");
    assert_constraint_violation(&err);
}

// =================================================================================================
// Relationships: the same two defects, through the relationship twin
// =================================================================================================

/// The relationship twin of the headline reproduction (`rel_value_for_key` had the same missing
/// `expired_ts` guard).
#[test]
fn rel_unique_accepts_when_the_duplicate_value_was_removed_and_committed() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:P {tag: 'a'})-[:R {sku: 'x', tag: 'r1'}]->(:P {tag: 'b'})",
    );
    run_write(&mut coord, "MATCH ()-[r:R {tag: 'r1'}]->() REMOVE r.sku");
    run_write(
        &mut coord,
        "CREATE (:P {tag: 'c'})-[:R {sku: 'x', tag: 'r2'}]->(:P {tag: 'd'})",
    );

    coord
        .create_constraint_general(
            "rel_uniq_sku",
            "R",
            &["sku"],
            ConstraintKind::RelUnique,
            None,
        )
        .expect("relationship IS UNIQUE must be accepted: the removed value is not live");
}

/// The relationship existence mirror: a removed property must refuse `IS NOT NULL`.
#[test]
fn rel_not_null_refuses_when_the_property_was_removed_and_committed() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:P {tag: 'a'})-[:R {sku: 'x', tag: 'r1'}]->(:P {tag: 'b'})",
    );
    run_write(&mut coord, "MATCH ()-[r:R {tag: 'r1'}]->() REMOVE r.sku");

    let err = coord
        .create_constraint_general(
            "rel_sku_exists",
            "R",
            &["sku"],
            ConstraintKind::RelExistence,
            None,
        )
        .expect_err("relationship IS NOT NULL must be refused: the property was removed");
    assert_constraint_violation(&err);
}

/// A deleted relationship keeps its slot until GC; it must not refuse a valid constraint.
#[test]
fn rel_unique_accepts_over_an_uncollected_rel_tombstone() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:P {tag: 'a'})-[:R {sku: 'x', tag: 'r1'}]->(:P {tag: 'b'})",
    );
    run_write(&mut coord, "MATCH ()-[r:R {tag: 'r1'}]->() DELETE r");
    run_write(
        &mut coord,
        "CREATE (:P {tag: 'c'})-[:R {sku: 'x', tag: 'r2'}]->(:P {tag: 'd'})",
    );

    coord
        .create_constraint_general(
            "rel_uniq_sku",
            "R",
            &["sku"],
            ConstraintKind::RelUnique,
            None,
        )
        .expect("relationship IS UNIQUE must be accepted over an uncollected tombstone");
}

/// Non-vacuity for the relationship path: a real committed duplicate is still refused.
#[test]
fn rel_unique_still_refuses_a_real_committed_duplicate() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:P {tag: 'a'})-[:R {sku: 'x', tag: 'r1'}]->(:P {tag: 'b'})",
    );
    run_write(
        &mut coord,
        "CREATE (:P {tag: 'c'})-[:R {sku: 'x', tag: 'r2'}]->(:P {tag: 'd'})",
    );

    let err = coord
        .create_constraint_general(
            "rel_uniq_sku",
            "R",
            &["sku"],
            ConstraintKind::RelUnique,
            None,
        )
        .expect_err("two live relationships share 'x': the constraint must be refused");
    assert_constraint_violation(&err);
}

// =================================================================================================
// The fail-closed guard: never decide on uncommitted data
// =================================================================================================

/// The coupling hazard the visibility fix creates, and the guard that closes it (`rmp` #902).
///
/// Two committed nodes hold `'a'` and `'b'` — no duplicate. A concurrent transaction `W` holds an
/// **uncommitted** `SET b.email = 'a'`. Judging the committed image alone would ACCEPT the
/// constraint, and `W` would then commit two `'a'`s under a live `IS UNIQUE` — a committed duplicate
/// no SSI edge can undo, because the DDL takes no predicate marker (that is `rmp` task #903).
///
/// So the DDL must refuse, with a **retryable** transaction error rather than a constraint violation:
/// nothing in the data is wrong, the answer is merely not decidable yet.
#[test]
fn create_constraint_refuses_while_another_transaction_holds_uncommitted_writes() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {email: 'a', tag: 'a'})");
    run_write(&mut coord, "CREATE (:P {email: 'b', tag: 'b'})");

    let w = begin_uncommitted_write(&mut coord, "MATCH (n:P {tag: 'b'}) SET n.email = 'a'");

    let err = coord
        .create_constraint("uniq_email", "P", "email", ConstraintKind::Unique)
        .expect_err("the DDL must not decide while a writer holds uncommitted state");
    assert!(
        matches!(err, GraphusError::Transaction(_)),
        "the refusal must be a retryable transaction error, got: {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("uniq_email") && msg.contains("retry"),
        "the refusal must name the constraint and invite a retry, got: {msg}"
    );
    assert!(
        !msg.contains(CONSTRAINT_VIOLATION_PREFIX),
        "an undecidable DDL is not a constraint violation, got: {msg}"
    );

    // Zero side effects: the constraint was not declared.
    assert!(
        !coord
            .list_constraints()
            .iter()
            .any(|c| c.name == "uniq_email"),
        "a refused DDL must leave the catalog unchanged"
    );

    // Once the writer commits, the duplicate is committed data and the DDL refuses it as a genuine
    // violation — the very outcome the guard exists to preserve.
    coord.commit(w).expect("W commits");
    let err = coord
        .create_constraint("uniq_email", "P", "email", ConstraintKind::Unique)
        .expect_err("two committed nodes now hold 'a'");
    assert_constraint_violation(&err);
}

/// The other half of the same hazard: once the concurrent writer **rolls back**, the DDL is decidable
/// again and must be accepted. This pins the guard as a retry-and-succeed condition, not a dead end.
#[test]
fn create_constraint_succeeds_once_the_concurrent_writer_resolves() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {email: 'a', tag: 'a'})");
    run_write(&mut coord, "CREATE (:P {email: 'b', tag: 'b'})");

    let w = begin_uncommitted_write(&mut coord, "MATCH (n:P {tag: 'b'}) SET n.email = 'a'");
    assert!(
        coord
            .create_constraint("uniq_email", "P", "email", ConstraintKind::Unique)
            .is_err(),
        "refused while W is open"
    );
    coord.rollback(w).expect("W rolls back");

    coord
        .create_constraint("uniq_email", "P", "email", ConstraintKind::Unique)
        .expect("after the writer rolled back the committed image has no duplicate");
}

/// A concurrent **read-only** transaction must NOT refuse the DDL: it holds no uncommitted state, so
/// the committed image is fully decidable. This keeps the guard proportionate — a server with open
/// read sessions can still declare a constraint.
///
/// This pins a deliberate scope decision, NOT a safety claim. An open transaction whose snapshot
/// predates a row committed before the declaration can still write a duplicate that its own snapshot
/// hides, and no guard on *uncommitted* state can see that coming; it needs the DDL to hold an SSI
/// predicate marker (`rmp` task #903). See `refuse_constraint_ddl_while_writers_open`.
#[test]
fn create_constraint_is_not_blocked_by_a_concurrent_reader() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {email: 'a', tag: 'a'})");
    run_write(&mut coord, "CREATE (:P {email: 'b', tag: 'b'})");

    let reader = coord.begin_serializable();
    let _rows = run_in(&coord, reader, "MATCH (n:P) RETURN n.email AS e");

    coord
        .create_constraint("uniq_email", "P", "email", ConstraintKind::Unique)
        .expect("a read-only transaction holds no uncommitted state and must not refuse the DDL");

    coord.commit(reader).expect("reader commits");
}

/// An `IF NOT EXISTS` that resolves to an existing equivalent constraint validates nothing, so the
/// guard must not refuse it: this is the idempotent application-startup idiom, and making it fail
/// whenever the database happens to be busy would make every boot load-dependent for a call that
/// changes nothing.
#[test]
fn if_not_exists_is_still_an_idempotent_no_op_while_a_writer_is_open() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {email: 'a', tag: 'a'})");
    coord
        .create_constraint("uniq_email", "P", "email", ConstraintKind::Unique)
        .expect("declare the constraint on a quiet database");

    let w = begin_uncommitted_write(&mut coord, "CREATE (:P {email: 'b', tag: 'b'})");

    let mutated = coord
        .create_constraint_ddl(
            "uniq_email",
            "P",
            &["email"],
            ConstraintKind::Unique,
            None,
            true,  // if_not_exists
            false, // or_replace
        )
        .expect("an equivalent constraint already exists: a no-op, whatever else is in flight");
    assert!(!mutated, "an IF NOT EXISTS no-op must report no mutation");

    coord.rollback(w).expect("W rolls back");
}

/// A **permanent** conflict must be reported as one. Masking it behind the retryable transaction error
/// would make a driver retry (`Neo.TransientError` is retryable by contract) a call that can never
/// succeed, and then surface an entirely different error once the writer happened to close.
#[test]
fn a_name_conflict_is_reported_as_permanent_even_while_a_writer_is_open() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {email: 'a', tag: 'a'})");
    coord
        .create_constraint("uniq_email", "P", "email", ConstraintKind::Unique)
        .expect("declare the constraint on a quiet database");

    let w = begin_uncommitted_write(&mut coord, "CREATE (:P {email: 'b', tag: 'b'})");

    // A different schema under an already-used name: a permanent name conflict.
    let err = coord
        .create_constraint_ddl(
            "uniq_email",
            "P",
            &["nickname"],
            ConstraintKind::Unique,
            None,
            false,
            false,
        )
        .expect_err("the name is taken");
    assert!(
        !matches!(err, GraphusError::Transaction(_)),
        "a name conflict is permanent and must not be classified as retryable, got: {err:?}"
    );

    coord.rollback(w).expect("W rolls back");
}

/// `OR REPLACE` drops before it creates, so the guard must fire **before** the drop: a refusal must
/// never leave the operator with the old constraint gone and the new one not declared, for a condition
/// a retry would have cleared.
#[test]
fn or_replace_refused_by_the_guard_keeps_the_existing_constraint() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {email: 'a', tag: 'a'})");
    coord
        .create_constraint("uniq_email", "P", "email", ConstraintKind::Unique)
        .expect("declare the constraint on a quiet database");

    let w = begin_uncommitted_write(&mut coord, "CREATE (:P {email: 'b', tag: 'b'})");

    let err = coord
        .create_constraint_ddl(
            "uniq_email",
            "P",
            &["email"],
            ConstraintKind::Unique,
            None,
            false,
            true, // or_replace
        )
        .expect_err("a replace revalidates, so it must be refused while a writer is open");
    assert!(
        matches!(err, GraphusError::Transaction(_)),
        "the refusal must be the retryable transaction error, got: {err:?}"
    );
    assert!(
        coord
            .list_constraints()
            .iter()
            .any(|c| c.name == "uniq_email"),
        "the existing constraint must survive a refused OR REPLACE"
    );

    coord.rollback(w).expect("W rolls back");
}
