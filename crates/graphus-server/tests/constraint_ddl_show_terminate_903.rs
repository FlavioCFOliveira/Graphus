//! **`CREATE CONSTRAINT` is visible to `SHOW TRANSACTIONS` and stoppable by `TERMINATE TRANSACTIONS`**
//! (`rmp` task #903).
//!
//! The validating `CREATE CONSTRAINT` DDL used to be invisible: the engine ran it as a bare store
//! transaction that appeared in no operator surface at all. Two things make that unacceptable rather
//! than merely untidy.
//!
//! * **Audit.** The validation walk reads every entity carrying the covered token, including the
//!   property values it compares. Schema work that reads user data was the one class of database
//!   activity an administrator could not observe while it happened.
//! * **Availability.** The walk is O(entities carrying the token) — and, for a uniqueness constraint,
//!   quadratic in the number of covered values — so a `CREATE CONSTRAINT` on a large label is a
//!   realistic runaway an operator needs to be able to kill.
//!
//! These gates drive the **real threaded engine** with a shared
//! [`TransactionRegistry`](graphus_server::txn_registry::TransactionRegistry) — the same instance a
//! running server shares between both connectivity seams and every engine — and assert the two
//! operator-facing properties end to end.
//!
//! # Why the oracle is all-or-nothing rather than "the DDL was aborted"
//!
//! Terminating an in-flight statement is inherently a race with that statement finishing: an operator
//! who types `TERMINATE TRANSACTIONS` a microsecond before the walk completes gets a transaction that
//! committed. A test that demanded an abort would be asserting that it won the race, and would flake
//! on a fast machine. What must hold *unconditionally* is the invariant: the DDL either completed and
//! declared the constraint, or it was stopped and left **nothing** behind — never a half-applied
//! schema. That is what these tests assert, together with the two facts that are not racy at all: the
//! entry was listed while the DDL ran, and terminating it reported `"Terminated"` rather than
//! `"Transaction not found"`.
//!
//! The complementary deterministic gates live where no race is possible, and together they cover the
//! whole chain without any of them depending on winning a race: `terminate` cancels the entry's token
//! (`txn_registry`'s unit tests), a cancelled token aborts the walk and leaves nothing behind
//! (`graphus-cypher`'s `constraint_ddl_transaction_903.rs`, driven by a pre-cancelled token with no
//! threads at all), and the engine relabels the resulting error with the registry's own wording (the
//! `Err` arm below).
//!
//! Measured on the development host, the seeded walk is slow enough that the `Err` arm is the one that
//! fires — three consecutive runs all reported
//! `"the transaction has been terminated by an administrator (TERMINATE TRANSACTIONS)"`. The oracle
//! still admits the `Ok` arm on purpose: a machine fast enough to finish first must not turn a correct
//! outcome into a red build.

use std::sync::Arc;
use std::time::{Duration, Instant};

use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::{
    AccessMode, ConstraintCommand, ConstraintCreateKind, ConstraintEntity, ConstraintTypeFilter,
    CreateConstraint,
};
use graphus_server::engine::{Engine, EngineHandle, spawn_engine_with_timeout};
use graphus_server::txn_registry::TransactionRegistry;
use graphus_sim::SharedClock;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

/// How long a poller waits for the DDL's registry entry to appear. Generous: the assertion it guards
/// is "the entry was listed", and a machine slow enough to need more than this is one where the DDL is
/// slower still.
const APPEAR_TIMEOUT: Duration = Duration::from_secs(30);

/// Nodes seeded under the covered label. Sized so the uniqueness walk — which compares every value
/// against every value already seen — runs long enough that a concurrent operator reliably observes
/// it, while keeping the whole gate well inside a normal test budget.
const SEEDED_NODES: usize = 20_000;

/// Spawns a threaded engine sharing `transactions`, exactly as the server does.
fn engine_sharing(transactions: &Arc<TransactionRegistry>) -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine_with_timeout::<MemBlockDevice, MemLogSink, _>(
        Arc::from("test"),
        || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            let store = RecordStore::create(device, wal, 16_384, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        4096,
        256,
        2,
        metrics,
        clock,
        // No statement timeout: the only thing that may stop the DDL in these gates is the operator.
        None,
        None,
        None,
        Arc::clone(transactions),
    )
    .expect("spawn threaded engine")
}

/// Seeds `n` `:P` nodes carrying a distinct `email`, in one committed auto-commit statement.
fn seed_people(handle: &EngineHandle, n: usize) {
    let ticket = handle
        .begin_auto_commit_blocking(AccessMode::Write)
        .expect("begin seed");
    let reply = handle
        .run_blocking(
            ticket,
            "UNWIND range(1, $n) AS i CREATE (:P {email: 'user' + toString(i)})".to_owned(),
            vec![("n".to_owned(), graphus_core::Value::Integer(n as i64))],
            true,
            None,
        )
        .expect("seed runs");
    let mut rows = reply.rows;
    while rows.next().expect("drain seed").is_some() {}
}

/// Drops the engine's handles and joins its thread (the harness `statement_timeout.rs` uses).
fn shutdown(engine: Engine, handle: EngineHandle) {
    let Engine {
        handle: inner,
        join,
    } = engine;
    drop(handle);
    drop(inner);
    join.join().expect("engine thread joins cleanly");
}

/// A `CREATE CONSTRAINT … IS UNIQUE` over `(:P.email)`.
fn create_unique(name: &str) -> ConstraintCommand {
    ConstraintCommand::Create(CreateConstraint {
        name: name.to_owned(),
        entity: ConstraintEntity::Node {
            label: "P".to_owned(),
        },
        properties: vec!["email".to_owned()],
        kind: ConstraintCreateKind::Unique,
        if_not_exists: false,
        or_replace: false,
    })
}

/// The declared constraints, as seen through a `SHOW CONSTRAINTS`.
fn constraint_count(handle: &EngineHandle) -> usize {
    handle
        .constraint_ddl_blocking(
            ConstraintCommand::Show {
                filter: ConstraintTypeFilter::All,
                tail: None,
            },
            None,
        )
        .expect("show constraints")
        .rows
        .len()
}

/// Blocks until `transactions` lists an entry whose `protocol` is `"internal"`, returning its id, or
/// [`None`] if none appears within [`APPEAR_TIMEOUT`].
fn await_internal_entry(transactions: &Arc<TransactionRegistry>) -> Option<String> {
    let deadline = Instant::now() + APPEAR_TIMEOUT;
    while Instant::now() < deadline {
        if let Some(row) = transactions
            .snapshot()
            .into_iter()
            .find(|s| s.protocol == "internal")
        {
            return Some(row.id);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    None
}

/// A running `CREATE CONSTRAINT` appears in `SHOW TRANSACTIONS` as an `"internal"` WRITE transaction
/// carrying the rendered statement, and disappears once it resolves.
#[test]
fn a_running_constraint_ddl_is_listed_and_then_deregistered() {
    let transactions = Arc::new(TransactionRegistry::new());
    let engine = engine_sharing(&transactions);
    let handle = engine.handle.clone();
    seed_people(&handle, SEEDED_NODES);
    assert!(
        transactions.is_empty(),
        "non-vacuity: seeding must leave the registry empty, so anything observed below is the DDL"
    );

    let observer = {
        let transactions = Arc::clone(&transactions);
        std::thread::spawn(move || {
            let deadline = Instant::now() + APPEAR_TIMEOUT;
            while Instant::now() < deadline {
                if let Some(row) = transactions
                    .snapshot()
                    .into_iter()
                    .find(|s| s.protocol == "internal")
                {
                    return Some(row);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            None
        })
    };

    handle
        .constraint_ddl_blocking(create_unique("u_email"), Some("alice".to_owned()))
        .expect("the seeded values are distinct, so the constraint holds");

    let seen = observer
        .join()
        .expect("observer thread")
        .expect("the running CREATE CONSTRAINT must be listed in SHOW TRANSACTIONS");

    assert_eq!(seen.database, "test");
    assert_eq!(seen.mode, "WRITE");
    assert_eq!(
        seen.username.as_deref(),
        Some("alice"),
        "the operator must be able to see who asked for the schema change"
    );
    assert_eq!(
        seen.client_address, None,
        "an internal transaction has no peer address"
    );
    assert!(
        seen.current_query
            .as_deref()
            .is_some_and(|q| q.contains("CREATE CONSTRAINT") && q.contains("u_email")),
        "the rendered statement must be readable in the currentQuery column, got {:?}",
        seen.current_query
    );

    assert!(
        transactions.is_empty(),
        "the entry must be deregistered once the DDL resolves"
    );
    assert_eq!(
        constraint_count(&handle),
        1,
        "and the constraint is declared"
    );

    shutdown(engine, handle);
}

/// `TERMINATE TRANSACTIONS` against a running `CREATE CONSTRAINT` reaches it, and whatever the race
/// outcome the schema is never half-applied.
#[test]
fn terminating_a_running_constraint_ddl_leaves_no_half_applied_schema() {
    let transactions = Arc::new(TransactionRegistry::new());
    let engine = engine_sharing(&transactions);
    let handle = engine.handle.clone();
    seed_people(&handle, SEEDED_NODES);

    let terminator = {
        let transactions = Arc::clone(&transactions);
        std::thread::spawn(move || {
            let id = await_internal_entry(&transactions)?;
            Some(transactions.terminate(&[id]))
        })
    };

    let outcome =
        handle.constraint_ddl_blocking(create_unique("u_email"), Some("alice".to_owned()));

    let terminated = terminator
        .join()
        .expect("terminator thread")
        .expect("the running CREATE CONSTRAINT must be addressable by TERMINATE TRANSACTIONS");
    assert_eq!(terminated.len(), 1);
    assert_eq!(
        terminated[0].message, "Terminated",
        "the DDL's id must resolve to a live transaction, not to \"Transaction not found\""
    );
    assert_eq!(terminated[0].database.as_deref(), Some("test"));
    assert_eq!(terminated[0].username.as_deref(), Some("alice"));

    // The invariant, whichever side of the race won.
    match outcome {
        Ok(_) => assert_eq!(
            constraint_count(&handle),
            1,
            "the DDL reached its uninterruptible tail and committed, so the constraint must be there"
        ),
        Err(e) => {
            assert!(
                e.to_string().contains("terminated"),
                "a stopped DDL must report the termination, got: {e}"
            );
            assert_eq!(
                constraint_count(&handle),
                0,
                "a terminated DDL must leave NOTHING behind — not a catalogue entry, not a rule"
            );
            // And the schema is still declarable afterwards, from the clean slate just asserted.
            // Guarded by this arm rather than run unconditionally: on the `Ok` arm the equivalent
            // constraint already exists, and re-declaring it is correctly an error.
            handle
                .constraint_ddl_blocking(create_unique("u_email_retry"), None)
                .expect("a terminated DDL must leave the schema in a state a retry can build on");
        }
    }

    assert!(
        transactions.is_empty(),
        "the entry must be deregistered on the terminated path too"
    );

    // The engine keeps serving: a terminated DDL is not a wedged engine.
    let ticket = handle
        .begin_auto_commit_blocking(AccessMode::Read)
        .expect("begin after termination");
    let reply = handle
        .run_blocking(
            ticket,
            "MATCH (p:P) RETURN count(p) AS c".to_owned(),
            vec![],
            true,
            None,
        )
        .expect("the engine still serves after a terminated DDL");
    let mut rows = reply.rows;
    while rows.next().expect("drain").is_some() {}

    shutdown(engine, handle);
}
