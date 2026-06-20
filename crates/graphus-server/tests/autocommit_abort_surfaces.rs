//! Regression (rmp #238, seed-4 VOPR `EdgeMultisetMismatch` divergence): an **auto-commit** write
//! whose post-stream COMMIT is rejected by SSI must report the failure to the consumer — never a
//! silent success over rolled-back writes.
//!
//! The bug: `handle_run` streamed the statement's rows and signalled success, then ran the
//! auto-commit COMMIT *afterwards* and **swallowed** a commit error (it only bumped an abort metric).
//! A consumer that drained the rows saw no error, so a transaction the engine had rolled back was
//! acknowledged as committed — an atomicity/durability violation (`04 §1.3` step 6). The VOPR strong
//! reference-model oracle caught it as an edge the model recorded but the engine did not persist.
//!
//! The fix runs the auto-commit COMMIT while the egress channel is still open and, on a commit
//! failure, sends the error as the stream's terminal item. This test drives the exact shape — an SSI
//! write-skew where the auto-commit transaction is the pivot that aborts at commit — through the
//! **real engine** and asserts the consumer observes the terminal error (so `ok` is false), and that
//! the rolled-back write left no trace.

use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::LocalEngine;
use graphus_server::engine::command::AccessMode;
use graphus_sim::SharedClock;
use graphus_wal::MemLogSink;
use std::sync::Arc;

type Eng = LocalEngine<MemBlockDevice, MemLogSink>;

fn engine() -> Eng {
    let clock = SharedClock::new(0);
    LocalEngine::in_memory(Arc::new(clock) as Arc<dyn Clock + Send + Sync>, 256)
        .expect("build in-memory engine")
}

/// Drains an auto-commit statement, returning `(ok, row_count)`. `ok` is false iff the stream's
/// terminal item is an error — which, after the fix, a rolled-back auto-commit produces.
fn auto_commit(eng: &mut Eng, mode: AccessMode, stmt: &str) -> (bool, usize) {
    let ticket = eng.begin_auto_commit(mode).expect("begin auto-commit");
    match eng.run(ticket, stmt, vec![], true, None) {
        Ok(mut reply) => {
            let mut rows = 0;
            loop {
                match reply.rows.next() {
                    Ok(Some(_)) => rows += 1,
                    Ok(None) => return (true, rows),
                    Err(_) => return (false, rows),
                }
            }
        }
        Err(_) => (false, 0),
    }
}

/// Runs one statement inside an already-open explicit transaction, draining its rows.
fn run_in(eng: &mut Eng, ticket: graphus_server::engine::TxTicket, stmt: &str) {
    let mut reply = eng.run(ticket, stmt, vec![], false, None).expect("run in txn");
    while reply.rows.next().expect("drain").is_some() {}
}

#[test]
fn autocommit_commit_abort_is_reported_not_silently_swallowed() {
    let mut eng = engine();

    // Seed two nodes `(:A {v:1})`, `(:B {v:1})` in a committed auto-commit.
    let (ok, _) = auto_commit(&mut eng, AccessMode::Write, "CREATE (:A {v: 1}), (:B {v: 1})");
    assert!(ok, "seed must commit");

    // Open an explicit SERIALIZABLE writer that reads label A (full scan, predicate SIREAD) and
    // writes it — and leave it open so it overlaps the auto-commit below.
    let t1 = eng.begin(AccessMode::Write).expect("begin explicit writer");
    run_in(&mut eng, t1, "MATCH (a:A) SET a.v = 0");

    // Auto-commit the symmetric write-skew partner: read label B, write it. It overlaps t1, so the
    // two form the SSI dangerous structure. When its stream drains, the engine runs the auto-commit
    // COMMIT, and the pivot (the auto-commit, whose outbound rw-partner t1 is still concurrent)
    // aborts itself with a retriable serialization failure.
    let (ok, _) = auto_commit(&mut eng, AccessMode::Write, "MATCH (b:B) SET b.v = 0");
    assert!(
        !ok,
        "the auto-commit whose COMMIT was SSI-aborted MUST surface the failure to the consumer, \
         not report a silent success over its rolled-back write (rmp #238 atomicity regression)"
    );

    // Commit t1 (it is the surviving safe member).
    let _ = eng.commit(t1);

    // The rolled-back auto-commit left no trace: B's value is still 1 (only t1's A.v=0 survives).
    let probe = eng.begin_auto_commit(AccessMode::Read).expect("begin read");
    let mut reply = eng
        .run(probe, "MATCH (b:B) RETURN b.v AS v", vec![], true, None)
        .expect("probe runs");
    let mut bvals = Vec::new();
    while let Some(row) = reply.rows.next().expect("drain probe") {
        bvals.push(format!("{row:?}"));
    }
    assert_eq!(bvals.len(), 1, "exactly one :B node");
    assert!(
        bvals[0].contains('1'),
        "the SSI-aborted auto-commit's write to B was rolled back (B.v stays 1): {bvals:?}"
    );

    let _ = eng.shutdown();
}
