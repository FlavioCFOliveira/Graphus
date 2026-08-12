//! `CREATE CONSTRAINT` runs as a **first-class transaction** (`rmp` task #903).
//!
//! Every schema DDL used to open its transaction straight on the store — `next_txn_id += 1` then
//! `RecordStore::begin` — which is adequate for a command that decides nothing about data. It is not
//! adequate for `CREATE CONSTRAINT`, the one schema command that reads the whole graph and publishes a
//! durable assertion about it: a bare transaction is registered in **neither** the SSI tracker **nor**
//! the coordinator's active set, so it formed no rw-edge with anything, pinned no GC watermark, and
//! read raw physical state instead of a snapshot.
//!
//! The DDL now goes through `begin_serializable` / `commit` / `rollback` like any user transaction.
//! These tests pin the observable consequences of that:
//!
//! * it is **registered in the SSI tracker**, without which every predicate SIREAD marker it announces
//!   would be silently inert (`SsiTracker::are_concurrent` returns `false` for an unregistered
//!   transaction, so no edge can ever form);
//! * it is **in the active set for the whole walk** — `TxnCoordinator::commit` rejects an id that is
//!   not in `active` with `"commit of inactive txn"`, so a `CREATE CONSTRAINT` that returns `Ok` is
//!   itself the proof that its transaction was a live member of the active set from `begin` to
//!   `commit`;
//! * it **leaks nothing** on either the success or the failure path — the active-set slot and the SSI
//!   entry are both released, so nothing is left pinning the GC watermark (`rmp` #415's drop-guard
//!   discipline);
//! * it is **never spuriously aborted**: it announces no predicate write and takes no physical write
//!   marker, so `detect_pivot_abort`'s read-only exemption applies, and an open reader — however old —
//!   cannot make a schema change fail.
//!
//! The end-to-end anomaly this registration closes (a transaction whose snapshot predates the
//! constraint committing a duplicate the constraint forbids) is guarded deterministically by the DST
//! scenario `graphus_dst::isolation::tests::constraint_declared_while_an_older_reader_is_open_903`.

use graphus_core::{TxnId, Value};
use graphus_cypher::CancellationToken;
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
// Harness (mirrors tests/constraint_validation_visibility.rs)
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

/// Runs `src` inside `txn`, leaving the transaction open.
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

/// Runs a write statement in its own transaction and commits it.
fn run_write(coord: &mut Coord, src: &str) {
    let txn = coord.begin_serializable();
    let _rows = run_in(coord, txn, src);
    coord.commit(txn).expect("write commits");
}

// =================================================================================================
// Registration in the SSI tracker
// =================================================================================================

/// The DDL's transaction must enter the SSI tracker. `SsiTracker::register` is the only way into
/// `txns`, and a committed entry is retained until GC prunes it, so a successful `CREATE CONSTRAINT`
/// must leave exactly one more tracked transaction than before.
///
/// This is the property the whole task rests on: an unregistered transaction's `record_predicate_read`
/// leaves a reverse-index entry no `forget` can clean, and `are_concurrent` short-circuits to `false`
/// for it — so every marker the validation walk announces would form no edge at all.
#[test]
fn a_successful_constraint_ddl_registers_its_transaction_in_the_ssi_tracker() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {email: 'a'})");

    let tracked_before = coord.ssi_tracked_len();
    coord
        .create_constraint("u_email", "P", "email", ConstraintKind::Unique)
        .expect("the constraint holds over the committed graph");

    assert_eq!(
        coord.ssi_tracked_len(),
        tracked_before + 1,
        "the constraint DDL must be registered in the SSI tracker, and retained after it commits — \
         without that registration its predicate markers form no rw-edge with anything"
    );
}

/// A **refused** DDL must leave the tracker exactly as it found it: the abort path calls
/// `SsiTracker::forget`, which purges the transaction's entry and scrubs its rw-edges from every
/// survivor. A tracker that kept growing on every rejected `CREATE CONSTRAINT` would accumulate
/// unreachable conflict records for the life of the process.
#[test]
fn a_refused_constraint_ddl_leaves_the_ssi_tracker_unchanged() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {email: 'dup'})");
    run_write(&mut coord, "CREATE (:P {email: 'dup'})");

    let tracked_before = coord.ssi_tracked_len();
    let refused = coord.create_constraint("u_email", "P", "email", ConstraintKind::Unique);
    let err = refused.expect_err("a committed duplicate must refuse the constraint");
    assert!(
        err.to_string().contains(CONSTRAINT_VIOLATION_PREFIX),
        "expected a constraint-violation error, got: {err}"
    );

    assert_eq!(
        coord.ssi_tracked_len(),
        tracked_before,
        "a rolled-back constraint DDL must be forgotten by the SSI tracker"
    );
}

// =================================================================================================
// Membership in the active set, and the absence of a leak
// =================================================================================================

/// A successful `CREATE CONSTRAINT` proves its own active-set membership: the DDL commits through
/// `TxnCoordinator::commit`, which looks the transaction up in `active` and returns
/// `"commit of inactive txn"` when it is absent. `Ok(())` is therefore only reachable if the
/// transaction was a live member of the active set from `begin` through the whole validation walk. The
/// count returning to its prior value then pins the other half: no slot is left behind.
#[test]
fn a_successful_constraint_ddl_is_active_throughout_and_leaks_nothing() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {email: 'a'})");
    run_write(&mut coord, "CREATE (:P {email: 'b'})");
    assert_eq!(
        coord.active_count(),
        0,
        "no transaction is open at the start"
    );

    coord
        .create_constraint("u_email", "P", "email", ConstraintKind::Unique)
        .expect("commit through the coordinator succeeds only for an ACTIVE transaction");

    assert_eq!(
        coord.active_count(),
        0,
        "the DDL's active-set slot must be released on commit"
    );
    assert_eq!(
        coord.oldest_active_snapshot(),
        None,
        "a released DDL transaction must stop pinning the GC watermark"
    );
}

/// The failure path must release just as completely. A constraint violation rolls the DDL back
/// through `TxnCoordinator::rollback`, whose cleanup runs under a drop guard (`rmp` #415), so a
/// refused schema change cannot pin the GC watermark forever.
#[test]
fn a_refused_constraint_ddl_leaks_no_active_transaction() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {email: 'dup'})");
    run_write(&mut coord, "CREATE (:P {email: 'dup'})");

    let _ = coord
        .create_constraint("u_email", "P", "email", ConstraintKind::Unique)
        .expect_err("a committed duplicate must refuse the constraint");

    assert_eq!(
        coord.active_count(),
        0,
        "a refused constraint DDL must leave no open transaction"
    );
    assert_eq!(
        coord.oldest_active_snapshot(),
        None,
        "a refused DDL must not pin the GC watermark"
    );
}

/// The same, for a **relationship** constraint: it takes the sibling validation walk, which announces
/// the `RelType` / `RelEquality` marker family instead, and must retire its transaction identically.
#[test]
fn a_refused_relationship_constraint_ddl_leaks_no_active_transaction() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:A)-[:LINK {tag: 'dup'}]->(:B), (:A)-[:LINK {tag: 'dup'}]->(:B)",
    );

    // Committed transactions stay in the tracker until GC prunes them, so the oracle is the DELTA the
    // refused DDL contributes, not an absolute count.
    let tracked_before = coord.ssi_tracked_len();
    let _ = coord
        .create_constraint("u_tag", "LINK", "tag", ConstraintKind::RelUnique)
        .expect_err("a committed duplicate relationship value must refuse the constraint");

    assert_eq!(
        coord.active_count(),
        0,
        "a refused relationship-constraint DDL must leave no open transaction"
    );
    assert_eq!(
        coord.ssi_tracked_len(),
        tracked_before,
        "and must be forgotten by the SSI tracker"
    );
}

// =================================================================================================
// The DDL is never spuriously aborted
// =================================================================================================

/// A schema change must not become load-dependent now that it participates in SSI. The DDL announces
/// no predicate **write** and takes no physical write marker, so `detect_pivot_abort`'s read-only
/// exemption (`writes.is_empty() && !out_conflict`) applies to it, and an already-committed
/// transaction is never `are_concurrent` with a transaction that began after it. An open **reader** —
/// which the `rmp` #902 guard deliberately does not refuse — must therefore not affect the DDL at all.
#[test]
fn an_open_reader_neither_refuses_nor_aborts_the_constraint_ddl() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {email: 'a'})");
    run_write(&mut coord, "CREATE (:P {email: 'b'})");

    // An old reader that has actually read the covered label, so it holds real SIREAD markers over
    // exactly the predicate the DDL is about to read.
    let reader = coord.begin_serializable();
    let seen = run_in(&coord, reader, "MATCH (n:P) RETURN n.email AS e");
    assert_eq!(
        seen.len(),
        2,
        "non-vacuity: the reader must really have read both nodes of the covered label"
    );

    coord
        .create_constraint("u_email", "P", "email", ConstraintKind::Unique)
        .expect("an open reader must not make a schema change fail");

    // And the reader itself is untouched: it wrote nothing, so it cannot be a pivot either.
    coord.commit(reader).expect("the open reader still commits");
}

/// The DDL must see, and judge, exactly the committed graph — including a value a concurrent reader's
/// older snapshot would hide. This pins that the walk reads through its **own** snapshot (taken at its
/// `begin`, so it is the newest one) rather than through anything the caller happens to hold.
#[test]
fn the_ddl_judges_the_newest_committed_state_not_an_older_readers_view() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {email: 'a', tag: 'first'})");

    // An older reader whose snapshot predates the duplicate below.
    let reader = coord.begin_serializable();
    let before = run_in(&coord, reader, "MATCH (n:P) RETURN n.email AS e");
    assert_eq!(before.len(), 1, "the reader's snapshot holds one node");

    // A second, committed 'a' — invisible to `reader`, visible to any transaction begun after it.
    run_write(&mut coord, "CREATE (:P {email: 'a', tag: 'second'})");

    let refused = coord.create_constraint("u_email", "P", "email", ConstraintKind::Unique);
    let err = refused.expect_err(
        "the DDL must judge the newest committed state, in which 'a' is duplicated — reading through \
         the older reader's snapshot would have accepted a false constraint",
    );
    assert!(
        err.to_string().contains(CONSTRAINT_VIOLATION_PREFIX),
        "expected a constraint-violation error, got: {err}"
    );

    let _ = coord.rollback(reader);
}

// =================================================================================================
// Cancellation: `TERMINATE TRANSACTIONS` against a running validation walk
// =================================================================================================

/// A cancelled DDL must abort, and abort **cleanly**. The walk polls the token once per entity, so an
/// operator's `TERMINATE TRANSACTIONS` stops a `CREATE CONSTRAINT` over a large label instead of being
/// noticed only once the walk has already finished — which is exactly when it no longer matters.
///
/// The oracle is the same shape as `a_refused_constraint_ddl_has_no_side_effects`, deliberately: a
/// terminated DDL must be indistinguishable from a refused one in its after-effects.
#[test]
fn a_cancelled_constraint_ddl_aborts_with_no_side_effects() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {email: 'a'})");
    run_write(&mut coord, "CREATE (:P {email: 'b'})");

    let cancel = CancellationToken::new();
    cancel.cancel();
    let err = coord
        .create_constraint_general_cancellable(
            "u_email",
            "P",
            &["email"],
            ConstraintKind::Unique,
            None,
            &cancel,
        )
        .expect_err("a cancelled DDL must not declare the constraint");
    assert!(
        err.to_string().contains("cancelled"),
        "the error must name the cancellation, got: {err}"
    );

    assert!(
        coord.list_constraints().is_empty(),
        "a cancelled constraint must not be recorded in the catalog"
    );
    assert_eq!(
        coord.active_count(),
        0,
        "a cancelled DDL must leave no open transaction"
    );
    assert_eq!(
        coord.oldest_active_snapshot(),
        None,
        "a cancelled DDL must not pin the GC watermark"
    );

    // The graph is untouched, and still readable.
    let txn = coord.begin_serializable();
    let rows = run_in(&coord, txn, "MATCH (n:P) RETURN n.email AS e");
    coord.commit(txn).expect("read commits");
    assert_eq!(rows.len(), 2, "both nodes survive a cancelled DDL");
}

/// The control that makes the test above non-vacuous: the *same* call with a token that was never
/// cancelled declares the constraint. Without this, "the constraint was not created" would be equally
/// consistent with the call being broken.
#[test]
fn the_same_ddl_succeeds_with_an_uncancelled_token() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {email: 'a'})");
    run_write(&mut coord, "CREATE (:P {email: 'b'})");

    coord
        .create_constraint_general_cancellable(
            "u_email",
            "P",
            &["email"],
            ConstraintKind::Unique,
            None,
            &CancellationToken::new(),
        )
        .expect("an uncancelled token must not affect the outcome");

    assert_eq!(
        coord.list_constraints().len(),
        1,
        "the identical call declares the constraint when the token is clear"
    );
    assert_eq!(coord.active_count(), 0, "and leaks no transaction");
}

/// Cancellation reaches the **relationship** walk too. It is a separate loop over a separate scan, so
/// a node-only poll would leave every relationship constraint uninterruptible.
#[test]
fn a_cancelled_relationship_constraint_ddl_aborts_with_no_side_effects() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:A)-[:LINK {tag: 'x'}]->(:B)");
    run_write(&mut coord, "CREATE (:A)-[:LINK {tag: 'y'}]->(:B)");

    let cancel = CancellationToken::new();
    cancel.cancel();
    let err = coord
        .create_constraint_general_cancellable(
            "u_tag",
            "LINK",
            &["tag"],
            ConstraintKind::RelUnique,
            None,
            &cancel,
        )
        .expect_err("a cancelled relationship DDL must not declare the constraint");
    assert!(
        err.to_string().contains("cancelled"),
        "the error must name the cancellation, got: {err}"
    );

    assert!(coord.list_constraints().is_empty());
    assert_eq!(coord.active_count(), 0);
    assert_eq!(
        coord.ssi_tracked_len(),
        2,
        "only the two setup writes remain"
    );
}

/// The `IF NOT EXISTS` / `OR REPLACE` entry point honours cancellation as well — it is the route every
/// client statement actually takes, so a poll reachable only through the lower-level call would leave
/// the production path uninterruptible.
#[test]
fn the_idempotent_ddl_entry_point_honours_cancellation() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {email: 'a'})");

    let cancel = CancellationToken::new();
    cancel.cancel();
    let err = coord
        .create_constraint_ddl_cancellable(
            "u_email",
            "P",
            &["email"],
            ConstraintKind::Unique,
            None,
            /* if_not_exists */ false,
            /* or_replace */ false,
            &cancel,
        )
        .expect_err("a cancelled DDL must not declare the constraint");
    assert!(err.to_string().contains("cancelled"), "got: {err}");
    assert!(coord.list_constraints().is_empty());
    assert_eq!(coord.active_count(), 0);
}

/// An `OR REPLACE` cancelled during the re-create must not leave the operator with the old constraint
/// dropped and no new one: the drop and the create are ordered so that a cancellation lands where a
/// failed re-create already landed, and the pre-flight check runs before anything is dropped.
#[test]
fn a_cancelled_or_replace_does_not_drop_the_existing_constraint() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {email: 'a'})");
    coord
        .create_constraint("u_email", "P", "email", ConstraintKind::Unique)
        .expect("declare the original constraint");
    assert_eq!(coord.list_constraints().len(), 1);

    let cancel = CancellationToken::new();
    cancel.cancel();
    let err = coord
        .create_constraint_ddl_cancellable(
            "u_email",
            "P",
            &["email"],
            ConstraintKind::Unique,
            None,
            /* if_not_exists */ false,
            /* or_replace */ true,
            &cancel,
        )
        .expect_err("a cancelled OR REPLACE must not report success");
    assert!(err.to_string().contains("cancelled"), "got: {err}");

    assert_eq!(
        coord.list_constraints().len(),
        1,
        "the pre-flight cancellation check runs before the drop, so the existing constraint survives"
    );
    assert_eq!(coord.active_count(), 0, "and no transaction is leaked");
}

// =================================================================================================
// The interned tokens still roll back with a refused DDL
// =================================================================================================

/// Routing the DDL through the coordinator's `rollback` must undo exactly what the old direct
/// `store.rollback` did: a refused create leaves no durable catalog entry, and the graph is untouched.
#[test]
fn a_refused_constraint_ddl_has_no_side_effects() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {email: 'dup'})");
    run_write(&mut coord, "CREATE (:P {email: 'dup'})");

    let _ = coord
        .create_constraint("u_email", "P", "email", ConstraintKind::Unique)
        .expect_err("a committed duplicate must refuse the constraint");

    assert!(
        coord.list_constraints().is_empty(),
        "a refused constraint must not be recorded in the catalog"
    );

    // The graph is still readable and unchanged.
    let txn = coord.begin_serializable();
    let rows = run_in(&coord, txn, "MATCH (n:P) RETURN n.email AS e");
    coord.commit(txn).expect("read commits");
    assert_eq!(rows.len(), 2, "both nodes survive a refused DDL");
    for row in &rows {
        assert_eq!(
            row.value("e"),
            Value::String("dup".to_owned()),
            "the nodes' values are untouched"
        );
    }
}
