//! **`rmp` #1051 — an SSI victim that is not the committer is CONDEMNED, never undone by the
//! committer.**
//!
//! # What broke
//!
//! `SsiTracker::detect_pivot_abort` has two shapes. In **Case A** the committing transaction is
//! itself the pivot and the victim is itself. In **Case B** the committer is the *outbound* end of
//! `Tin --rw--> Tpivot --rw--> Tout`, and the victim is `Tpivot` — a **different, still-running**
//! transaction. `TxnCoordinator::commit` / `commit_prepare` used to answer Case B by calling
//! `abort(victim)` on the spot, from the committing worker's own thread.
//!
//! With one engine worker that is invisible: the victim is parked between statements, so nothing else
//! is inside it. With `engine_workers = 8` the victim is a transaction another worker is *running*,
//! and the abort raced it. Measured on `graphus-server`'s `multi_writer_certification_1034` gate 2:
//! two workers entered `RecordStore::rollback_logical` for one transaction, the first detached and
//! freed its deltas and its commit slot, the second walked a chain those deltas had already left, and
//! the store's fail-closed head-prefix tripwire refused — which by the `rmp` #955 contract leaves the
//! transaction OPEN with its uncommitted writes physically present. 476 of 480 requests were then
//! answered "engine degraded … pending a controlled restart". One transaction losing a race took the
//! whole database out of service.
//!
//! The engine already states the rule this violated, for its own age sweep: it declines a sibling
//! worker's transaction because "what would go wrong here is claiming a transaction whose owner may
//! be executing a statement in it right now" (`graphus-server/src/engine/mod.rs`, `maybe_reap_aged`).
//!
//! # What it does now
//!
//! A foreign victim is **condemned** ([`graphus_txn::SsiTracker::doom`]) and aborts *itself*, at its
//! own commit, on its own worker. That is PostgreSQL's model: a backend that must kill a pivot sets
//! `SXACT_FLAG_DOOMED` on it and never runs another backend's rollback
//! (`src/backend/storage/lmgr/predicate.c`).
//!
//! # What this file asserts, and why each assertion has teeth
//!
//! One deterministic three-transaction structure, and three assertions on it:
//!
//! 1. **The safe member commits.** `Tout` commits — the forward-progress property Case B exists for.
//!    Were the structure not built, or built the wrong way round, `Tout` would abort under Case A and
//!    this fails.
//! 2. **The victim is still usable.** `Tpivot` can still open a statement and read. **This is the
//!    assertion that fails before the fix**: `abort(victim)` had removed it from the active set, so
//!    `statement` answered `statement in inactive txn`.
//! 3. **The victim aborts itself, with the right error.** `Tpivot`'s own commit fails with the
//!    *serialization failure*, not with `commit of inactive txn`. The distinction is the whole point:
//!    both are `GraphusError::Transaction` and both are retriable at the Bolt seam, so only the text
//!    separates "this transaction condemned itself at its commit" from "somebody else destroyed it
//!    while it was running".
//!
//! # A note on why the condemnation is belt-and-braces
//!
//! Once `Tout` has committed, `Tpivot` also satisfies **Case A** at its own commit: it has both
//! conflicts, and its outbound partner has now committed, so `detect_pivot_abort` would name it even
//! with an empty doomed set. The doom is what makes the guarantee independent of that coincidence —
//! and assertion 3 holds under either route, which is exactly what makes the fix safe rather than
//! merely different.

use graphus_core::{GraphusError, TxnId, Value};
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::graph_access::GraphAccess;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

/// The property every node in this scenario carries.
const KEY: &str = "v";

fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: RecordStore<MemBlockDevice, MemLogSink> =
        RecordStore::create(device, wal, 64, 1).expect("create store");
    TxnCoordinator::new(store)
}

/// Creates and commits two unlabelled nodes, returning their ids.
///
/// Unlabelled and read by id, deliberately. Every read here is a **single-record** SIREAD marker
/// taken through [`GraphAccess::node_property`], never a label scan — a scan with no index reads
/// every node in the store and would smear each transaction's footprint across both nodes, which is
/// precisely what this scenario must not do: the three-transaction structure is built out of exactly
/// four markers, and one stray edge would turn Case B into Case A without the test noticing.
fn seed(coord: &Coord) -> (u64, u64) {
    let t = coord.begin_serializable();
    let ids = {
        let mut seam = coord.statement(t).expect("seed statement");
        let p = seam.create_node(&[], &[(KEY.to_owned(), Value::Integer(0))]);
        let q = seam.create_node(&[], &[(KEY.to_owned(), Value::Integer(0))]);
        assert!(seam.take_error().is_none(), "the seed captured an error");
        (p.0, q.0)
    };
    coord.commit(t).expect("seed commits");
    ids
}

/// Reads `node`'s property under `txn`, registering the SIREAD marker that makes `txn` a reader of
/// it.
fn read(coord: &Coord, txn: TxnId, node: u64) {
    let seam = coord
        .statement(txn)
        .unwrap_or_else(|e| panic!("transaction {} must still be usable: {e}", txn.0));
    let _ = seam.node_property(graphus_cypher::graph_access::NodeId(node), KEY);
    assert!(seam.take_error().is_none(), "a read captured an error");
}

/// Writes `node`'s property under `txn`, registering the write marker.
fn write(coord: &Coord, txn: TxnId, node: u64, v: i64) {
    let mut seam = coord
        .statement(txn)
        .unwrap_or_else(|e| panic!("transaction {} must still be usable: {e}", txn.0));
    seam.set_node_property(
        graphus_cypher::graph_access::NodeId(node),
        KEY,
        Value::Integer(v),
    );
    assert!(seam.take_error().is_none(), "a write captured an error");
}

/// Builds `Tin --rw--> Tpivot --rw--> Tout` and returns `(t_in, t_pivot, t_out)`.
///
/// The two rw-antidependencies, and nothing else:
///
/// * `Tpivot` reads `q`, which `Tout` writes  ⇒ `Tpivot --rw--> Tout`;
/// * `Tin` reads `p`, which `Tpivot` writes   ⇒ `Tin --rw--> Tpivot`.
///
/// `Tout` therefore has an inbound conflict and **no** outbound one, which is what keeps it out of
/// Case A and puts its commit squarely in Case B with `Tpivot` as the victim.
fn dangerous_structure(coord: &Coord, p: u64, q: u64) -> (TxnId, TxnId, TxnId) {
    let t_in = coord.begin_serializable();
    let t_pivot = coord.begin_serializable();
    let t_out = coord.begin_serializable();

    write(coord, t_out, q, 1);
    read(coord, t_pivot, q); // Tpivot --rw--> Tout
    write(coord, t_pivot, p, 1);
    read(coord, t_in, p); // Tin --rw--> Tpivot

    (t_in, t_pivot, t_out)
}

/// **The Case-B victim is condemned, not undone by the transaction that chose it.**
#[test]
fn a_foreign_ssi_victim_stays_open_and_aborts_itself_at_its_own_commit() {
    let coord = fresh_coord();
    let (p, q) = seed(&coord);
    let (t_in, t_pivot, t_out) = dangerous_structure(&coord, p, q);

    // 1. The safe member commits. If the structure had made `Tout` the pivot instead, Case A would
    //    have aborted it here and everything below would be asserting about the wrong shape.
    coord
        .commit(t_out)
        .expect("the outbound end of the structure is the safe member and must commit");

    // 2. THE ASSERTION THAT FAILS BEFORE THE FIX. `Tout`'s commit chose `Tpivot` as the victim. It
    //    must have CONDEMNED it, not run its undo — so `Tpivot` is still a live transaction with a
    //    usable statement seam. `abort(victim)` from `Tout`'s thread made this
    //    `statement in inactive txn`, and at `engine_workers > 1` it was also a second thread inside
    //    `Tpivot`'s rollback.
    let seam = coord.statement(t_pivot);
    assert!(
        seam.is_ok(),
        "the SSI victim was destroyed by the transaction that chose it: {:?}. A transaction is \
         undone by its own worker and by no other (`rmp` #1051)",
        seam.err()
    );
    drop(seam);
    read(&coord, t_pivot, q);

    // 3. The guarantee is still enforced, by the victim on itself, with the error that says so.
    let verdict = coord.commit(t_pivot);
    let Err(GraphusError::Transaction(msg)) = &verdict else {
        panic!(
            "the condemned pivot must abort at its own commit with a RETRIABLE transaction error, \
             got {verdict:?}"
        );
    };
    assert!(
        msg.contains("serialization failure"),
        "the condemned pivot must fail as a serialization failure it decided on itself, not as a \
         casualty of somebody else's thread; got: {msg}"
    );
    assert!(
        !msg.contains("inactive"),
        "`commit of inactive txn` means the victim was destroyed by another transaction before it \
         reached its own commit — the `rmp` #1051 defect; got: {msg}"
    );

    let _ = coord.commit(t_in);
}

/// **Non-vacuity: without the structure, nothing aborts.**
///
/// The same three transactions and the same reads and writes, on **disjoint** nodes, so no rw-edge
/// forms. All three commit. Without this, the gate above could be passing because the fixture aborts
/// everything it touches — and it would keep passing if `detect_pivot_abort` were replaced by
/// `Some(txn)`.
#[test]
fn the_same_fixture_without_a_dangerous_structure_commits_every_transaction() {
    let coord = fresh_coord();
    let (p, q) = seed(&coord);
    let (r, s) = seed(&coord);

    let t_in = coord.begin_serializable();
    let t_pivot = coord.begin_serializable();
    let t_out = coord.begin_serializable();

    // Same shapes, four different nodes: nobody reads what anybody else writes.
    write(&coord, t_out, q, 1);
    read(&coord, t_pivot, r);
    write(&coord, t_pivot, p, 1);
    read(&coord, t_in, s);

    coord.commit(t_out).expect("t_out commits");
    coord.commit(t_pivot).expect("t_pivot commits");
    coord.commit(t_in).expect("t_in commits");
}
