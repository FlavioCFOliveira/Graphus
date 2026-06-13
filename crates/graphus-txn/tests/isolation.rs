//! Integration tests for the public `graphus-txn` API: isolation-level behaviour, the canonical
//! SSI write-skew (SERIALIZABLE vs SI), lost-update/dirty-write prevention, non-blocking reads,
//! deadlock detection, and version GC. These exercise the manager's contract end to end
//! (`specification/04-technical-design.md` §5).

use graphus_core::GraphusError;
use graphus_txn::{IsolationLevel, MemVersionedStore, NoDurability, TxnManager, VersionedStore};

/// Keys used by the write-skew scenario (think: two on-call doctors `x` and `y`).
const X: u64 = 100;
const Y: u64 = 200;

fn manager() -> TxnManager<MemVersionedStore, NoDurability> {
    TxnManager::new(MemVersionedStore::new())
}

/// Seeds both keys with an initial committed value, returning the manager ready for the scenario.
fn seeded() -> TxnManager<MemVersionedStore, NoDurability> {
    let mut m = manager();
    let t = m.begin_serializable();
    m.write(t, X, b"on".to_vec()).unwrap();
    m.write(t, Y, b"on".to_vec()).unwrap();
    m.commit(t).unwrap();
    m
}

/// The canonical write-skew: two concurrent transactions each read **both** keys and write the
/// *other* key based on what they read. A serial schedule can never let both proceed, so under
/// SERIALIZABLE exactly one MUST abort with a serialization failure.
#[test]
fn write_skew_aborts_one_under_serializable() {
    let mut m = seeded();

    let t1 = m.begin(IsolationLevel::Serializable);
    let t2 = m.begin(IsolationLevel::Serializable);

    // Both read the shared set {x, y}.
    assert_eq!(m.read(t1, X).unwrap(), Some(b"on".to_vec()));
    assert_eq!(m.read(t1, Y).unwrap(), Some(b"on".to_vec()));
    assert_eq!(m.read(t2, X).unwrap(), Some(b"on".to_vec()));
    assert_eq!(m.read(t2, Y).unwrap(), Some(b"on".to_vec()));

    // Each writes the key the *other* depends on (disjoint write sets -> no write-write conflict;
    // pure write-skew, which only SSI catches).
    m.write(t1, Y, b"off".to_vec()).unwrap();
    m.write(t2, X, b"off".to_vec()).unwrap();

    // First committer succeeds or is chosen as the pivot; the surviving one then commits. Exactly
    // one of the two must fail with a serialization error.
    let r1 = m.commit(t1);
    let r2 = m.commit(t2);

    let failures = [&r1, &r2].iter().filter(|r| r.is_err()).count();
    assert_eq!(
        failures, 1,
        "exactly one of the write-skew pair must abort under SERIALIZABLE; r1={r1:?} r2={r2:?}"
    );
    // The failure is a (retriable) transaction/serialization error.
    let err = [r1, r2].into_iter().find_map(Result::err).unwrap();
    assert!(matches!(err, GraphusError::Transaction(_)));
}

/// The same scenario under Snapshot Isolation: write-skew is *allowed*, so BOTH commit. This proves
/// SI is a real, weaker opt-in and that SERIALIZABLE (above) genuinely prevents the anomaly.
#[test]
fn write_skew_both_commit_under_snapshot_isolation() {
    let mut m = seeded();

    let t1 = m.begin(IsolationLevel::Snapshot);
    let t2 = m.begin(IsolationLevel::Snapshot);

    assert_eq!(m.read(t1, X).unwrap(), Some(b"on".to_vec()));
    assert_eq!(m.read(t1, Y).unwrap(), Some(b"on".to_vec()));
    assert_eq!(m.read(t2, X).unwrap(), Some(b"on".to_vec()));
    assert_eq!(m.read(t2, Y).unwrap(), Some(b"on".to_vec()));

    m.write(t1, Y, b"off".to_vec()).unwrap();
    m.write(t2, X, b"off".to_vec()).unwrap();

    // Under SI both succeed (the anomaly is permitted).
    assert!(m.commit(t1).is_ok(), "SI must allow write-skew");
    assert!(m.commit(t2).is_ok(), "SI must allow write-skew");

    // Both writes landed.
    let t3 = m.begin_serializable();
    assert_eq!(m.read(t3, X).unwrap(), Some(b"off".to_vec()));
    assert_eq!(m.read(t3, Y).unwrap(), Some(b"off".to_vec()));
}

/// Lost-update / dirty-write prevention: two concurrent transactions writing the *same* key. The
/// write-write conflict (first-updater-wins) prevents the second from silently overwriting.
#[test]
fn lost_update_is_prevented_by_write_write_conflict() {
    let mut m = seeded();
    let t1 = m.begin_serializable();
    let t2 = m.begin_serializable();

    m.write(t1, X, b"t1".to_vec()).unwrap();
    // T2's write to the same key conflicts (retriable) — it cannot blind-overwrite.
    let conflict = m.write(t2, X, b"t2".to_vec());
    assert!(matches!(conflict, Err(GraphusError::Transaction(_))));

    m.commit(t1).unwrap();
    // T2 must retry; here we roll it back. The surviving value is T1's.
    m.rollback(t2).ok();
    let t3 = m.begin_serializable();
    assert_eq!(m.read(t3, X).unwrap(), Some(b"t1".to_vec()));
}

/// Reads never block writers (NFR-4): a long-running reader holds an open snapshot while a writer
/// freely writes and commits the very key the reader is reading. Asserted via the API: the reader's
/// read returns without error/blocking, the writer's write/commit succeed, and the reader keeps
/// seeing its snapshot. (Single-threaded logic: "never blocks" is shown by reads taking no lock —
/// the writer is granted the write lock even while the reader's snapshot is open.)
#[test]
fn reads_never_block_writers() {
    let mut m = seeded();

    let reader = m.begin_serializable();
    assert_eq!(m.read(reader, X).unwrap(), Some(b"on".to_vec()));

    // While the reader's snapshot is open, a writer writes and commits the same key with no wait.
    let writer = m.begin_serializable();
    m.write(writer, X, b"new".to_vec()).unwrap(); // not blocked by the open reader
    assert!(m.commit(writer).is_ok());

    // The reader still sees its snapshot and is itself unaffected; it can keep reading.
    assert_eq!(m.read(reader, X).unwrap(), Some(b"on".to_vec()));
    assert_eq!(m.read(reader, Y).unwrap(), Some(b"on".to_vec()));
    // A read-only transaction is never an SSI abort victim -> commits cleanly.
    assert!(m.commit(reader).is_ok());
}

/// Deadlock detection aborts the youngest on a write-write wait cycle. T1 holds A then wants B; T2
/// holds B then wants A — a 2-cycle. The younger (T2) is aborted with a retriable error.
#[test]
fn deadlock_aborts_the_youngest() {
    let mut m = seeded();
    let t1 = m.begin_serializable();
    let t2 = m.begin_serializable();

    m.write(t1, X, b"a".to_vec()).unwrap(); // T1 holds X
    m.write(t2, Y, b"b".to_vec()).unwrap(); // T2 holds Y

    // T1 now wants Y (held by T2): with the single-threaded model this is reported as a conflict
    // rather than a real park, but the wait-for edge is recorded.
    let _ = m.write(t1, Y, b"a2".to_vec());
    // T2 wants X (held by T1): this closes the cycle, so the detector fires and aborts the youngest.
    let r = m.write(t2, X, b"b2".to_vec());
    assert!(
        matches!(r, Err(GraphusError::Transaction(_))),
        "the deadlock victim must get a retriable error; got {r:?}"
    );

    // T1 (the older, surviving transaction) can still commit.
    assert!(m.commit(t1).is_ok());
}

/// GC reclaims dead versions past the low-water mark but holds them back for a long-running reader
/// (`04 §5.5`).
#[test]
fn gc_reclaims_past_low_water_and_holds_for_long_reader() {
    let mut m = seeded();
    // seeded() wrote X and Y in one txn -> 2 versions live.
    assert_eq!(m.store().version_count(), 2);

    // A long reader pins the watermark at its begin timestamp.
    let reader = m.begin_serializable();
    assert_eq!(m.read(reader, X).unwrap(), Some(b"on".to_vec()));

    // Two successive updaters of X create dead versions behind the live head.
    let u1 = m.begin_serializable();
    m.write(u1, X, b"v2".to_vec()).unwrap();
    m.commit(u1).unwrap();
    let u2 = m.begin_serializable();
    m.write(u2, X, b"v3".to_vec()).unwrap();
    m.commit(u2).unwrap();
    assert_eq!(m.store().version_count(), 4); // X: 3 versions, Y: 1

    // GC while the reader is open must NOT reclaim the version the reader still needs.
    let report = m.run_gc();
    assert!(
        report.low_water.is_some(),
        "the open reader pins a watermark"
    );
    assert_eq!(
        m.store().version_count(),
        4,
        "nothing reclaimed for the live reader"
    );

    // Reader still sees its snapshot.
    assert_eq!(m.read(reader, X).unwrap(), Some(b"on".to_vec()));
    m.commit(reader).unwrap();

    // With no active readers, GC reclaims the dead X versions, leaving the two live heads.
    let report2 = m.run_gc();
    assert_eq!(report2.low_water, None);
    assert!(report2.versions_reclaimed >= 2);
    assert_eq!(m.store().version_count(), 2);
}

/// A read-only transaction at SERIALIZABLE never aborts even amid concurrent writes (the read-only
/// optimization, `04 §5.4`).
#[test]
fn read_only_serializable_transaction_commits() {
    let mut m = seeded();
    let reader = m.begin_serializable();
    assert_eq!(m.read(reader, X).unwrap(), Some(b"on".to_vec()));

    let writer = m.begin_serializable();
    m.write(writer, X, b"changed".to_vec()).unwrap();
    m.commit(writer).unwrap();

    // The pure reader commits cleanly despite the concurrent overwrite of a key it read.
    assert!(m.commit(reader).is_ok());
}
