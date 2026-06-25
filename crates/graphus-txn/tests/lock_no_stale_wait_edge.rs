//! Regression for `rmp` #387: a fast-failed write must not leave a **stale wait-for edge** behind.
//!
//! When a write hits a key held by another transaction and the conflict is *not* a deadlock, the
//! waiter fails fast with a retriable write-write error but **stays active** (it keeps the locks it
//! already holds). [`LockTable::acquire`] records the wait-for edge `waiter → holder` *before* the
//! manager decides to fail the wait; if that edge is left behind it is stale (the transaction is no
//! longer waiting on anyone). A later *legitimate* wait can then close a **phantom cycle** through the
//! stale edge and abort an innocent transaction.
//!
//! The fix drops the waiter's pending wait edge on the fast-fail path while preserving its real held
//! locks. This test drives the documented 5-step interleaving through the real [`TxnManager`] and
//! asserts the innocent transaction is never spuriously aborted.

use graphus_core::GraphusError;
use graphus_txn::{MemVersionedStore, NoDurability, TxnManager};

fn manager() -> TxnManager<MemVersionedStore, NoDurability> {
    TxnManager::new(MemVersionedStore::new())
}

/// The CONFIRMED repro from `rmp` #387, step by step:
///
/// 1. T1 write(key1)            → Ok  (T1 holds key1)
/// 2. T2 write(key1)            → Err (fast-fail, no deadlock). PRE-FIX: stale edge T2→T1 lingers.
/// 3. T2 write(key2)            → Ok  (T2 holds key2; still active)
/// 4. T1 write(key2)            → Wait{T2}, edge T1→T2. PRE-FIX the stale T2→T1 fabricates the cycle
///    T1→T2→T1 and the detector aborts the youngest, T2.
/// 5. T2 write(key3)            → POST-FIX Ok (T2 is still active). PRE-FIX Err("write in inactive
///    txn 2") because step 4 spuriously aborted T2.
///
/// The acceptance property: after T1's second write, **T2 remains ACTIVE** (no spurious abort),
/// proven by T2's subsequent write succeeding.
#[test]
fn fast_failed_write_does_not_leave_stale_wait_edge() {
    const KEY1: u64 = 1;
    const KEY2: u64 = 2;
    const KEY3: u64 = 3;

    let mut m = manager();
    let t1 = m.begin_serializable().unwrap();
    let t2 = m.begin_serializable().unwrap();

    // 1. T1 takes key1.
    m.write(t1, KEY1, b"t1-key1".to_vec()).unwrap();

    // 2. T2 writes key1 → fast-fail write-write conflict (no deadlock). T2 stays active.
    let err = m.write(t2, KEY1, b"t2-key1".to_vec()).unwrap_err();
    assert!(
        matches!(&err, GraphusError::Transaction(msg) if msg.contains("write-write conflict")),
        "expected a retriable write-write conflict, got {err:?}"
    );

    // 3. T2 writes key2 → Ok (proves T2 is still active after the fast-fail).
    m.write(t2, KEY2, b"t2-key2".to_vec()).unwrap();

    // 4. T1 writes key2 → it must WAIT on T2 (T2 holds key2). With the stale edge removed there is no
    //    cycle, so T1 simply fails fast on the write-write conflict and **T2 is untouched**. With the
    //    bug, the stale T2→T1 edge closes the phantom cycle T1→T2→T1 and the detector aborts T2.
    let t1_second = m.write(t1, KEY2, b"t1-key2".to_vec());
    assert!(
        matches!(&t1_second, Err(GraphusError::Transaction(msg)) if msg.contains("write-write conflict")),
        "T1's wait on key2 should fail fast as a write-write conflict (no phantom deadlock), got {t1_second:?}"
    );

    // 5. T2 writes key3 → MUST succeed: T2 was never aborted. Pre-fix this returned
    //    "write in inactive txn 2".
    let t2_third = m.write(t2, KEY3, b"t2-key3".to_vec());
    assert!(
        t2_third.is_ok(),
        "T2 must remain ACTIVE after T1's second write (no spurious abort); got {t2_third:?}"
    );

    // And T2 can still commit — it was a legitimate, uninterrupted transaction.
    m.commit(t2).unwrap();
}
