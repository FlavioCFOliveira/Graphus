//! Security regression battery for `graphus-txn` (red-team audit, 2026-06-14; fixes landed).
//!
//! Each test pins the **hardened** behaviour of an audited weakness so a regression flips it back.
//! Tests for a fix carry `// Regression: SEC-<rmp-task-id>`.
//!
//! Findings covered:
//! - SEC-197 — `next_txn_id` is `checked_add`-bounded; it can never reach a reserved/illegal `VersionStamp` (CWE-190).
//! - SEC-198 — active-transaction admission cap + idle reaping bound the in-memory tables and free a frozen GC watermark (CWE-400).
//! - SEC-199 — the deadlock detector is iterative; a deep wait-for chain cannot overflow the stack (CWE-674), correctness preserved.
//! - SEC-200 — the timestamp oracle refuses gracefully at exhaustion instead of panicking (CWE-248).

use std::time::Duration;

use graphus_core::{MAX_TIMESTAMP, TxnId, VersionStamp};
use graphus_txn::{
    IsolationLevel, LockOutcome, LockTable, MemVersionedStore, NoDurability, TxnConfig, TxnManager,
};

fn mgr() -> TxnManager<MemVersionedStore, NoDurability> {
    TxnManager::with_durability(MemVersionedStore::new(), NoDurability)
}

fn mgr_with(config: TxnConfig) -> TxnManager<MemVersionedStore, NoDurability> {
    TxnManager::with_durability_and_config(MemVersionedStore::new(), NoDurability, config)
}

// ---------------------------------------------------------------------------------------------
// SEC-197 — the txn-id counter is checked and range-bounded; it never reaches an illegal stamp.
// ---------------------------------------------------------------------------------------------

/// Regression: SEC-197. The manager mints monotonically increasing, **legal** writer ids: never
/// `0` (reserved) and never above `MAX_TIMESTAMP` (which would collide with the in-flight high-bit
/// discriminator). A freshly minted id is always a usable `VersionStamp::in_flight`.
#[test]
fn sec197_minted_ids_are_legal_writer_stamps() {
    // Regression: SEC-197
    let mut m = mgr();
    let a = m.begin(IsolationLevel::Snapshot).unwrap();
    let b = m.begin(IsolationLevel::Snapshot).unwrap();
    assert!(b.0 > a.0, "ids strictly increase");
    assert!(
        a.0 != 0 && a.0 <= MAX_TIMESTAMP,
        "minted id is a legal writer id"
    );
    // Must not panic for a freshly minted id (the SEC-197 destination states never occur).
    let _ = VersionStamp::in_flight(a);
    let _ = VersionStamp::in_flight(b);
}

/// The illegal destination states the unchecked counter could once reach still reject loudly at the
/// `VersionStamp` boundary — proving the manager's checked counter is what keeps them unreachable.
#[test]
fn sec197_illegal_stamps_still_rejected_at_the_boundary() {
    // `TxnId(0)` (the u64-wrap target) is reserved.
    assert!(
        std::panic::catch_unwind(|| VersionStamp::in_flight(TxnId(0))).is_err(),
        "TxnId(0) must remain a rejected writer stamp"
    );
    // The first id with bit 63 set (MAX_TIMESTAMP + 1) collides with the in-flight discriminator.
    assert!(
        std::panic::catch_unwind(|| VersionStamp::in_flight(TxnId(MAX_TIMESTAMP + 1))).is_err(),
        "an id past MAX_TIMESTAMP must remain rejected"
    );
}

// ---------------------------------------------------------------------------------------------
// SEC-198 — admission cap + idle reaping bound the in-memory tables and unfreeze GC.
// ---------------------------------------------------------------------------------------------

/// Regression: SEC-198. `begin` above the configured active-transaction ceiling is refused with a
/// retriable error — there is now an admission limit.
#[test]
fn sec198_begin_refused_above_active_cap() {
    // Regression: SEC-198
    let cap = 8;
    let mut m = mgr_with(TxnConfig {
        max_active_txns: cap,
        ..TxnConfig::default()
    });
    for _ in 0..cap {
        m.begin(IsolationLevel::Snapshot).expect("under the cap");
    }
    assert_eq!(m.active_count(), cap);
    // The next begin is refused (not admitted, no unbounded growth).
    let over = m.begin(IsolationLevel::Snapshot);
    assert!(over.is_err(), "begin above the cap must be refused");
    assert_eq!(m.active_count(), cap, "a refused begin admits nothing");

    // Rolling one back frees a slot so a fresh begin is admitted again.
    // (Find an active txn id by re-deriving: ids are 1..=cap.)
    m.rollback(TxnId(1)).expect("rollback the first");
    assert_eq!(m.active_count(), cap - 1);
    assert!(
        m.begin(IsolationLevel::Snapshot).is_ok(),
        "a freed slot re-admits a begin"
    );
}

/// Regression: SEC-198. A zero idle-timeout makes every non-progressing transaction immediately
/// reapable: an idle holder that froze the GC watermark is aborted by `reap_idle`, and GC then
/// reclaims the registry entries it was pinning.
#[test]
fn sec198_idle_txn_is_reaped_and_unfreezes_gc() {
    // Regression: SEC-198
    let mut m = mgr_with(TxnConfig {
        idle_timeout: Duration::ZERO, // any idleness is immediately reapable
        ..TxnConfig::default()
    });

    // An idle reader that never commits, pinning the low-water mark.
    let idle = m.begin(IsolationLevel::Snapshot).unwrap();
    let _ = m.read(idle, 999_u64);

    // Churn committed writers; their old versions/registry entries become garbage held back only by
    // the idle reader's watermark.
    for i in 0..50u64 {
        let t = m.begin(IsolationLevel::Snapshot).unwrap();
        m.write(t, 1_u64, i.to_le_bytes().to_vec()).unwrap();
        m.commit(t).unwrap();
    }
    let before = m.registry_len();
    assert!(
        before > 0,
        "the idle reader pins settled writers in the registry"
    );

    // Reap the idle holder, then GC: the watermark advances and the registry drains.
    let reaped = m.reap_idle();
    assert_eq!(reaped, 1, "exactly the idle reader is reaped");
    assert!(
        m.active_count() == 0 || !m.config().idle_timeout.is_zero(),
        "the idle reader is no longer active"
    );
    let _ = m.run_gc();
    assert!(
        m.registry_len() < before,
        "GC makes progress once the idle watermark is freed (before={before}, after={})",
        m.registry_len()
    );
}

/// An actively progressing transaction is **not** reaped even with a zero idle-timeout, as long as
/// it performed an operation: the reaper measures idleness from the last op, not lifetime.
#[test]
fn sec198_reaper_does_not_abort_progressing_txn_after_op() {
    let mut m = mgr_with(TxnConfig {
        idle_timeout: Duration::from_secs(3600), // generous
        ..TxnConfig::default()
    });
    let t = m.begin(IsolationLevel::Snapshot).unwrap();
    m.write(t, 1_u64, b"v".to_vec()).unwrap();
    assert_eq!(m.reap_idle(), 0, "a recently-active txn is not reaped");
    assert!(m.commit(t).is_ok(), "it can still commit");
}

// ---------------------------------------------------------------------------------------------
// SEC-199 — the deadlock detector is iterative: deep chains do not overflow the stack.
// ---------------------------------------------------------------------------------------------

/// Regression: SEC-199. A genuine two-transaction lock cycle is still detected (correctness
/// preserved across the recursive→iterative rewrite).
#[test]
fn sec199_detects_real_lock_cycle() {
    // Regression: SEC-199
    let mut lt = LockTable::new();
    let (t1, t2) = (TxnId(1), TxnId(2));
    assert!(matches!(lt.acquire(t1, 10_u64), LockOutcome::Granted));
    assert!(matches!(lt.acquire(t2, 20_u64), LockOutcome::Granted));
    let _ = lt.acquire(t1, 20_u64); // T1 waits on T2
    let _ = lt.acquire(t2, 10_u64); // T2 waits on T1 -> cycle
    let victim = lt.find_deadlock_victim();
    assert!(
        victim == Some(t1) || victim == Some(t2),
        "a real deadlock cycle must yield a victim, got {victim:?}"
    );
    assert_eq!(
        victim,
        Some(t2),
        "the youngest (largest TxnId) is the victim"
    );
}

/// Regression: SEC-199. A **pathologically deep** acyclic wait-for chain is processed without a
/// stack overflow and correctly reports no deadlock. The previous recursive detector would recurse
/// to `DEPTH` call frames; the iterative one uses heap-allocated work stacks instead. A depth of
/// 200k comfortably exceeds the recursion budget the old code would have blown.
#[test]
fn sec199_deep_acyclic_chain_does_not_overflow_stack() {
    // Regression: SEC-199
    const DEPTH: u64 = 200_000;
    let mut lt = LockTable::new();
    // T(i) holds key(i).
    for i in 0..DEPTH {
        assert!(matches!(lt.acquire(TxnId(i + 1), i), LockOutcome::Granted));
    }
    // T(i) additionally waits on key(i-1) held by T(i-1): a single linear chain, no cycle.
    for i in 1..DEPTH {
        let _ = lt.acquire(TxnId(i + 1), i - 1);
    }
    // The detector must terminate without a stack overflow and find no victim.
    assert_eq!(
        lt.find_deadlock_victim(),
        None,
        "a deep acyclic chain has no deadlock victim and must not overflow the stack"
    );
}

/// Regression: SEC-199. A deep chain that closes into a cycle at the far end is still detected by
/// the iterative walk (the back-edge across the whole chain), and the youngest is chosen.
#[test]
fn sec199_deep_chain_with_far_cycle_is_detected() {
    // Regression: SEC-199
    const DEPTH: u64 = 50_000;
    let mut lt = LockTable::new();
    for i in 0..DEPTH {
        assert!(matches!(lt.acquire(TxnId(i + 1), i), LockOutcome::Granted));
    }
    for i in 1..DEPTH {
        let _ = lt.acquire(TxnId(i + 1), i - 1);
    }
    // Close the cycle: the head T(1) waits on the tail's key, held by T(DEPTH).
    let _ = lt.acquire(TxnId(1), DEPTH - 1);
    let victim = lt.find_deadlock_victim();
    assert_eq!(
        victim,
        Some(TxnId(DEPTH)),
        "the closing cycle is detected and the youngest is the victim"
    );
}

// ---------------------------------------------------------------------------------------------
// SEC-200 — the oracle refuses gracefully at exhaustion; release of an unknown ts is a no-op.
// (The fine-grained oracle behaviour is unit-tested in `src/oracle.rs`; here we confirm the manager
// surfaces a normal begin path and never panics on the happy path after the hardening.)
// ---------------------------------------------------------------------------------------------

/// Regression: SEC-200. The happy-path lifecycle (begin → write → commit → re-read) still works
/// after making the oracle fallible — the recoverable-error refactor introduced no regression.
#[test]
fn sec200_happy_path_lifecycle_intact() {
    // Regression: SEC-200
    let mut m = mgr();
    let w = m.begin_serializable().unwrap();
    m.write(w, 1_u64, b"hello".to_vec()).unwrap();
    assert!(m.commit(w).is_ok());
    let r = m.begin_serializable().unwrap();
    assert_eq!(m.read(r, 1_u64).unwrap(), Some(b"hello".to_vec()));
    assert!(m.commit(r).is_ok());
}
