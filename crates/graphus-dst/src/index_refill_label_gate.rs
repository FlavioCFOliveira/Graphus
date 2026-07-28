//! An index refill must gate node membership on the **live-OR-retained** label superset, never on the
//! raw live label word (`rmp` task #904) — the property-tree half of the `rmp` #771 / #765 / #766
//! defect family.
//!
//! # The defect
//!
//! Labels live in a `u64` inside the node record and are mutated **in place** (`05 §9`), so the live
//! word carries an uncommitted writer's changes. `IndexSet::clear` empties the node-property,
//! composite, full-text, spatial, text and vector trees, and `rebuild_index`'s per-node helpers then
//! decided *which* of those a node belongs to from `RecordStore::node_labels` — that raw live word.
//!
//! So this four-step interleaving lost a committed row permanently:
//!
//! 1. a committed `(:Person {email})` with an index (or an `IS UNIQUE` constraint) on
//!    `:Person(email)`;
//! 2. transaction A runs `REMOVE n:Person` and stays **open**;
//! 3. any DDL that reaches `rebuild_index` — here an unrelated `CREATE POINT INDEX` on a different
//!    relationship type — wipes the trees and refills them; the live word says the node is not a
//!    `:Person`, so it is indexed nowhere;
//! 4. A **rolls back**. WAL undo restores the record's label bit; nothing restores the index entry.
//!
//! `MATCH (n:Person {email: …})` then returned zero rows for the rest of the process's life, because a
//! seek's re-check can REMOVE a candidate but never RESURRECT one. And the same emptied tree is what
//! `unique_conflict` reads as an exact candidate source, treating `Some([])` as "no duplicate" — so a
//! live `IS UNIQUE` constraint **admitted a second node with the same value**.
//!
//! `rmp` #771 closed exactly this on the `labels` tree, by exempting it from `clear`. That exemption
//! left the *gate* — the live word — feeding every tree `clear` still wipes.
//!
//! # What is asserted, and why the oracle cannot be a tautology
//!
//! Every scenario reports two numbers taken at ONE snapshot: the answer to the label-and-property
//! query (which the planner routes through the index) and the answer to an ALL-NODES scan of the same
//! property with no label and no index in it. The second never touches a derived structure, so the two
//! agreeing is a real check. The uniqueness scenario reports whether the duplicate `CREATE` was
//! admitted, plus a fault-free control arm proving the constraint refuses that same duplicate when no
//! rebuild is in the way — without the control, "the constraint refused" could mean the fixture never
//! declared one.
//!
//! Two traps had to be measured out of these scenarios rather than assumed away, both of which would
//! have made them pass over the unfixed engine: the read arm must seed enough nodes that the
//! **cost-based** planner prefers a seek to a label scan (see [`FILLER_PERSONS`]), and it must confirm
//! the index is `ONLINE` when the seek runs (see [`SeekReport::index_online`]). A scenario that skips
//! either is comparing a scan with itself.
//!
//! # Why the DST, and what a single-threaded DST can reach here
//!
//! The defect needs one transaction to be **open** across another command, which is exactly what a
//! ticket-valued single-threaded engine gives for free: `LocalEngine` drives the real coordinator,
//! storage and WAL inline, so A's `REMOVE` sits uncommitted on the page while the DDL and the reads
//! run on the same thread. No fault injection and no scheduler are needed — the interleaving IS the
//! fault. Everything here therefore runs on the production command path (`run` / `index_ddl` /
//! `constraint_ddl`), not against a hand-built store.
//!
//! The one thing it cannot reach is an interleaving *inside* a single synchronous engine command; the
//! rebuild is one such command, and nothing needs to observe its midpoint.

use std::sync::Arc;

use graphus_core::Value;
use graphus_cypher::{MaterializedValue, SpatialEntity};
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{
    ConstraintCommand, ConstraintCreateKind, ConstraintEntity, CreateConstraint, IndexCommand,
    IndexTypeFilter, LocalEngine, TxTicket,
};
use graphus_sim::SharedClock;
use graphus_wal::MemLogSink;

type Eng = LocalEngine<MemBlockDevice, MemLogSink>;

/// Buffer-pool frames. Small: these scenarios hold a handful of nodes and one relationship type, and a
/// tight pool keeps the run deterministic and fast.
const POOL_PAGES: usize = 64;
/// The label the open writer removes, and the one every index and constraint below covers.
const LABEL: &str = "Person";
/// The indexed property, and the value the duplicate collides on.
const EMAIL: &str = "a@x.io";
/// The uniqueness constraint's name.
const UNIQUE_NAME: &str = "person_email";
/// The standalone `(:Person, email)` index's name, as `SHOW INDEXES` lists it.
const INDEX_NAME: &str = "person_email_idx";
/// How many *other* `:Person` nodes the seek scenarios seed alongside the target.
///
/// Not decoration: the engine plans through the **cost-based** optimiser with live statistics, and over
/// a one-node store a label scan is genuinely cheaper than a seek, so the query never reached the index
/// at all and the comparison below was two scans agreeing. Measured: at 1 seeded node the pre-fix run
/// reports `sought == scanned == 1` (vacuous); at 41 it reports `sought = 0, scanned = 1` — the defect.
const FILLER_PERSONS: usize = 40;

fn engine() -> Eng {
    LocalEngine::in_memory(Arc::new(SharedClock::new(0)), POOL_PAGES).expect("engine")
}

/// Runs `stmt` in `ticket` to completion, reporting whether the write path **admitted** it. `false`
/// means the statement was rejected — a constraint violation, raised either by `run` itself or while
/// draining the stream.
fn try_run(eng: &mut Eng, ticket: TxTicket, stmt: &str) -> bool {
    let Ok(mut reply) = eng.run(ticket, stmt, Vec::new(), false, None) else {
        return false;
    };
    loop {
        match reply.rows.next() {
            Ok(Some(_)) => {}
            Ok(None) => return true,
            Err(_) => return false,
        }
    }
}

/// Runs `stmt` in `ticket` and asserts it was admitted.
fn run_ok(eng: &mut Eng, ticket: TxTicket, stmt: &str) {
    assert!(try_run(eng, ticket, stmt), "{stmt} must succeed here");
}

/// Runs `stmt` in its own auto-committed transaction, reporting whether it was admitted. A rejected
/// statement is rolled back, so the store is left exactly as it was found.
fn try_write_own_txn(eng: &mut Eng, stmt: &str) -> bool {
    let t = eng.begin(AccessMode::Write).expect("begin writer");
    if try_run(eng, t, stmt) {
        eng.commit(t).expect("write commits");
        true
    } else {
        let _ = eng.rollback(t);
        false
    }
}

/// The single integer a one-column `RETURN count(...)` query yields, read inside `ticket`.
fn count_in(eng: &mut Eng, ticket: TxTicket, stmt: &str) -> i64 {
    let mut reply = eng
        .run(ticket, stmt, Vec::new(), false, None)
        .expect("counts");
    let mut c = 0;
    while let Ok(Some(row)) = reply.rows.next() {
        if let Some(MaterializedValue::Value(Value::Integer(n))) = row.first() {
            c = *n;
        }
    }
    c
}

/// Seeds one committed `(:Person {email: 'a@x.io'})` — the target — plus [`FILLER_PERSONS`] other
/// `:Person` nodes with distinct emails, all in one committed transaction.
fn seed(eng: &mut Eng) {
    let t = eng.begin(AccessMode::Write).expect("begin seeder");
    for i in 0..FILLER_PERSONS {
        run_ok(
            eng,
            t,
            &format!("CREATE (:{LABEL} {{email: 'filler{i}@x.io'}})"),
        );
    }
    run_ok(eng, t, &format!("CREATE (:{LABEL} {{email: '{EMAIL}'}})"));
    eng.commit(t).expect("the seed commits");
}

/// Opens a transaction that removes `:Person` from the **target** node and **leaves it open**.
///
/// Only the target, so the filler nodes keep the label throughout: the label word every other node
/// presents is untouched, which makes the ground-truth scan and the label count below describe exactly
/// one moving part.
fn open_writer_removing_the_label(eng: &mut Eng) -> TxTicket {
    let a = eng.begin(AccessMode::Write).expect("begin writer A");
    run_ok(
        eng,
        a,
        &format!("MATCH (n:{LABEL}) WHERE n.email = '{EMAIL}' REMOVE n:{LABEL}"),
    );
    a
}

/// The DDL that drives a full `IndexSet::clear` + `rebuild_index` on the production route, declaring
/// something entirely unrelated: a point index on a relationship type nobody has used.
///
/// A relationship POINT index is chosen deliberately. It is synchronous (so the rebuild has finished
/// when the call returns, with no build to drain), it names neither `:Person` nor `email`, and it
/// reaches `rebuild_index` through `handle_index_ddl` exactly as a client `CREATE POINT INDEX` does.
/// `CREATE CONSTRAINT` is NOT usable as the vehicle: since `rmp` #902 a constraint DDL is fail-closed
/// while any transaction holds uncommitted writes, which is precisely the state these scenarios set up.
fn unrelated_index_ddl(eng: &mut Eng) {
    eng.index_ddl(IndexCommand::CreatePointIndex {
        name: "widget_at".to_owned(),
        entity: SpatialEntity::Relationship,
        label: "WIDGET".to_owned(),
        property: "at".to_owned(),
        if_not_exists: false,
    })
    .expect("the unrelated point index DDL succeeds");
}

/// The `state` column `SHOW INDEXES` reports for the index named `name`, or `None` if it is not
/// listed. Read by name and by column name, never by position.
///
/// This is the non-vacuity instrument for the seek scenarios: an index that is not `ONLINE` is
/// withheld from every read seam (`rmp` #733), so a query over it would silently fall back to the
/// always-correct store scan and the comparison below would be a statement about two scans.
fn index_state(eng: &mut Eng, name: &str) -> Option<String> {
    let reply = eng
        .index_ddl(IndexCommand::ShowIndexes {
            filter: IndexTypeFilter::All,
            tail: None,
        })
        .expect("SHOW INDEXES renders");
    let col = |c: &str| reply.fields.iter().position(|f| f == c).expect("column");
    let (name_c, state_c) = (col("name"), col("state"));
    reply
        .rows
        .iter()
        .find(|r| r[name_c] == Value::String(name.to_owned()))
        .and_then(|r| match &r[state_c] {
            Value::String(s) => Some(s.clone()),
            _ => None,
        })
}

/// Declares a standalone `CREATE INDEX person_email_idx FOR (n:Person) ON (n.email)` and lets the
/// engine drain the non-blocking build (which `LocalEngine::dispatch` does after every command), so the
/// index is `ONLINE` before anything else happens.
fn declare_property_index(eng: &mut Eng) {
    eng.index_ddl(IndexCommand::CreateNodePropertyIndex {
        name: Some(INDEX_NAME.to_owned()),
        label: LABEL.to_owned(),
        properties: vec!["email".to_owned()],
        if_not_exists: false,
    })
    .expect("the property index is declared");
}

/// Declares `CREATE CONSTRAINT … FOR (n:Person) REQUIRE n.email IS UNIQUE`.
fn declare_unique(eng: &mut Eng) {
    eng.constraint_ddl(ConstraintCommand::Create(CreateConstraint {
        name: UNIQUE_NAME.to_owned(),
        entity: ConstraintEntity::Node {
            label: LABEL.to_owned(),
        },
        properties: vec!["email".to_owned()],
        kind: ConstraintCreateKind::Unique,
        if_not_exists: false,
        or_replace: false,
    }))
    .expect("the uniqueness constraint is declared");
}

/// What one run of [`run_seek_across_a_rolled_back_relabel`] observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeekReport {
    /// Rows returned by `MATCH (n:Person) WHERE n.email = …`, the query the planner routes through
    /// the property index. Must equal [`scanned`](Self::scanned).
    pub sought: i64,
    /// Rows returned by `MATCH (n) WHERE n.email = …` — an all-nodes scan with no label predicate and
    /// no index in it. The independent ground truth.
    pub scanned: i64,
    /// NON-VACUITY: the rolled-back writer really did leave the node carrying `:Person`, so there is a
    /// row for the seek to lose. `false` means the fixture, not the engine, decided the outcome.
    pub label_restored: bool,
    /// NON-VACUITY: the `(:Person, email)` index was `ONLINE` when the seek ran, so the read really was
    /// served from the tree the rebuild refilled. A non-`ONLINE` index is withheld from every read seam
    /// (`rmp` #733) and the query would silently become a second store scan.
    pub index_online: bool,
}

impl SeekReport {
    /// The invariant: the index-routed answer equals the scan, over a row that demonstrably exists.
    #[must_use]
    pub fn index_lost_nothing(&self) -> bool {
        self.sought == self.scanned && self.scanned == 1
    }
}

/// What one run of [`run_unique_across_a_rolled_back_relabel`] observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UniqueReport {
    /// NON-VACUITY control: with no rebuild in the way, the declared `IS UNIQUE` refuses a duplicate.
    /// `false` means the constraint was never in force and the assertion below proves nothing.
    pub control_refuses_duplicate: bool,
    /// Whether the duplicate `CREATE` was **admitted** after the rebuild-and-rollback. Must be `false`.
    pub duplicate_admitted: bool,
    /// How many `(:Person {email: 'a@x.io'})` nodes a fresh reader sees at the end. Must be `1`.
    pub survivors: i64,
}

impl UniqueReport {
    /// The invariant: the constraint stayed in force, and exactly one holder of the value survives.
    #[must_use]
    pub fn uniqueness_held(&self) -> bool {
        !self.duplicate_admitted && self.survivors == 1
    }
}

/// The read half of `rmp` #904: an unrelated index DDL run while a writer holds an uncommitted
/// `REMOVE n:Person`, followed by that writer's rollback, must leave the indexed row findable.
#[must_use]
pub fn run_seek_across_a_rolled_back_relabel() -> SeekReport {
    let mut eng = engine();
    seed(&mut eng);
    declare_property_index(&mut eng);

    let a = open_writer_removing_the_label(&mut eng);
    unrelated_index_ddl(&mut eng);
    eng.rollback(a).expect("A rolls back");

    let index_online = index_state(&mut eng, INDEX_NAME).as_deref() == Some("ONLINE");

    // One reader, all three queries, so the answers describe the same snapshot.
    let reader = eng.begin(AccessMode::Read).expect("begin reader");
    let sought = count_in(
        &mut eng,
        reader,
        &format!("MATCH (n:{LABEL}) WHERE n.email = '{EMAIL}' RETURN count(n) AS c"),
    );
    let scanned = count_in(
        &mut eng,
        reader,
        &format!("MATCH (n) WHERE n.email = '{EMAIL}' RETURN count(n) AS c"),
    );
    let label_restored = count_in(
        &mut eng,
        reader,
        &format!("MATCH (n) WHERE '{LABEL}' IN labels(n) RETURN count(n) AS c"),
    ) == FILLER_PERSONS as i64 + 1;
    eng.commit(reader).expect("the reader commits");

    SeekReport {
        sought,
        scanned,
        label_restored,
        index_online,
    }
}

/// The enforcement half of `rmp` #904, and the serious one: the same interleaving must not let a live
/// `IS UNIQUE` constraint admit a duplicate.
#[must_use]
pub fn run_unique_across_a_rolled_back_relabel() -> UniqueReport {
    let mut eng = engine();
    seed(&mut eng);
    declare_unique(&mut eng);

    let duplicate = format!("CREATE (:{LABEL} {{email: '{EMAIL}'}})");

    // Control arm FIRST, on a clean store: the constraint must refuse this exact statement with no
    // rebuild involved. A refusal rolls its transaction back, so the store is unchanged afterwards.
    let control_refuses_duplicate = !try_write_own_txn(&mut eng, &duplicate);

    let a = open_writer_removing_the_label(&mut eng);
    unrelated_index_ddl(&mut eng);
    eng.rollback(a).expect("A rolls back");

    let duplicate_admitted = try_write_own_txn(&mut eng, &duplicate);

    let reader = eng.begin(AccessMode::Read).expect("begin reader");
    let survivors = count_in(
        &mut eng,
        reader,
        &format!("MATCH (n) WHERE n.email = '{EMAIL}' RETURN count(n) AS c"),
    );
    eng.commit(reader).expect("the reader commits");

    UniqueReport {
        control_refuses_duplicate,
        duplicate_admitted,
        survivors,
    }
}

/// The opposite direction, which the widened gate must not break: when the writer **commits**, the
/// label is genuinely gone and the superset must not resurrect the row.
///
/// Reported as a [`SeekReport`] whose expected answer is `0 == 0`, so it reads like its twin;
/// [`index_lost_nothing`](SeekReport::index_lost_nothing) deliberately does not apply.
#[must_use]
pub fn run_seek_across_a_committed_relabel() -> SeekReport {
    let mut eng = engine();
    seed(&mut eng);
    declare_property_index(&mut eng);

    let a = open_writer_removing_the_label(&mut eng);
    unrelated_index_ddl(&mut eng);
    eng.commit(a).expect("A commits the REMOVE");

    let index_online = index_state(&mut eng, INDEX_NAME).as_deref() == Some("ONLINE");

    let reader = eng.begin(AccessMode::Read).expect("begin reader");
    let sought = count_in(
        &mut eng,
        reader,
        &format!("MATCH (n:{LABEL}) WHERE n.email = '{EMAIL}' RETURN count(n) AS c"),
    );
    let scanned = count_in(
        &mut eng,
        reader,
        &format!("MATCH (n) WHERE n.email = '{EMAIL}' RETURN count(n) AS c"),
    );
    let label_restored = count_in(
        &mut eng,
        reader,
        &format!("MATCH (n) WHERE '{LABEL}' IN labels(n) RETURN count(n) AS c"),
    ) == FILLER_PERSONS as i64 + 1;
    eng.commit(reader).expect("the reader commits");

    SeekReport {
        sought,
        scanned,
        label_restored,
        index_online,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rebuild_during_an_uncommitted_relabel_does_not_lose_the_indexed_row_904() {
        let r = run_seek_across_a_rolled_back_relabel();
        assert!(
            r.label_restored,
            "non-vacuity: the rolled-back REMOVE must leave the node carrying :{LABEL}, otherwise \
             every assertion below is a statement about a node that legitimately has no label — {r:?}",
        );
        assert_eq!(
            r.scanned, 1,
            "ground truth broken: the all-nodes scan must still find the committed row — {r:?}",
        );
        assert_eq!(
            r.sought, r.scanned,
            "`rmp` #904: the rebuild dropped the node from the (:{LABEL}, email) tree because the LIVE \
             label word showed an uncommitted REMOVE, and the rollback could not restore the entry — \
             {r:?}",
        );
    }

    #[test]
    fn a_rebuild_during_an_uncommitted_relabel_cannot_admit_a_unique_duplicate_904() {
        let r = run_unique_across_a_rolled_back_relabel();
        assert!(
            r.control_refuses_duplicate,
            "non-vacuity: the declared IS UNIQUE must refuse this duplicate with no rebuild in the \
             way, otherwise the constraint was never in force — {r:?}",
        );
        assert!(
            !r.duplicate_admitted,
            "`rmp` #904: the rebuild emptied the backing index, `unique_conflict` read Some([]) as \
             `no duplicate`, and a live IS UNIQUE constraint admitted a second holder — {r:?}",
        );
        assert_eq!(
            r.survivors, 1,
            "a committed duplicate survived under a declared IS UNIQUE — {r:?}",
        );
        assert!(r.uniqueness_held(), "the invariant, restated whole — {r:?}");
    }

    /// The widened gate is a candidate SUPERSET, and a superset is only safe because every consumer
    /// re-checks label membership at the reader's snapshot. This is the trap that fails if that ever
    /// stops being true: a genuinely committed `REMOVE` must make the row disappear.
    #[test]
    fn the_widened_gate_does_not_resurrect_a_committed_removal_904() {
        let r = run_seek_across_a_committed_relabel();
        assert!(
            !r.label_restored,
            "non-vacuity: the COMMITTED REMOVE must leave the node without :{LABEL} — {r:?}",
        );
        assert_eq!(
            r.scanned, 1,
            "ground truth broken: the node itself still exists, only its label is gone — {r:?}",
        );
        assert_eq!(
            r.sought, 0,
            "the widened refill resurrected a row whose label was genuinely removed — {r:?}",
        );
    }

    #[test]
    fn reproduction_is_deterministic_904() {
        assert_eq!(
            run_seek_across_a_rolled_back_relabel(),
            run_seek_across_a_rolled_back_relabel(),
        );
        assert_eq!(
            run_unique_across_a_rolled_back_relabel(),
            run_unique_across_a_rolled_back_relabel(),
        );
        assert_eq!(
            run_seek_across_a_committed_relabel(),
            run_seek_across_a_committed_relabel(),
        );
    }
}
