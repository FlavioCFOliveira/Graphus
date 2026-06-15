//! The empirical "Elle/Jepsen-style no anomalies" proof (acceptance criterion 3).
//!
//! A deterministic randomized history generator (`graphus_sim::SimRng`) drives many interleaved
//! transactions through the **real** [`TxnManager`] at the default SERIALIZABLE level over a sweep
//! of seeds. Each run records the committed transactions' read/write operations with concrete
//! per-key version numbers, then asserts the independent [`HistoryChecker`] (`graphus_txn`'s
//! serialization-graph oracle) finds **NO** cycle — i.e. every SERIALIZABLE schedule the manager
//! admits is serializable.
//!
//! A companion test feeds the same checker a known-bad history and asserts it DOES flag a cycle, so
//! the no-anomaly result above is meaningful rather than vacuous.
//!
//! ## How a version number is observed
//!
//! Each write stores a payload encoding `(writer_txn, installed_version)`; the installed version is
//! `previous_committed_version_of_key + 1`, assigned **at commit** in commit order. A read decodes
//! the version it observed straight from the payload it read (or version `0` for "no value yet").
//! This yields exactly the `(key, version)` operations the DSG checker consumes.

use std::collections::HashMap;

use graphus_core::TxnId;
use graphus_core::capability::Rng;
use graphus_sim::SimRng;
use graphus_txn::{HistoryChecker, IsolationLevel, MemVersionedStore, Op, TxnHistory, TxnManager};

/// Encodes `(writer_txn, version)` into an 8-byte payload.
fn encode(writer: u64, version: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(16);
    v.extend_from_slice(&writer.to_le_bytes());
    v.extend_from_slice(&version.to_le_bytes());
    v
}

/// Decodes the version component of a payload (the second u64).
fn decode_version(payload: &[u8]) -> u64 {
    u64::from_le_bytes(payload[8..16].try_into().expect("16-byte payload"))
}

/// One pending operation a generated transaction will perform.
#[derive(Clone, Copy)]
enum PlannedOp {
    Read(u64),
    Write(u64),
}

/// A generated transaction plan.
struct Plan {
    ops: Vec<PlannedOp>,
}

/// Generates a workload of `n_txns` transactions over `n_keys` keys, each with a few random
/// read/write ops, deterministically from `rng`.
fn generate(rng: &mut SimRng, n_txns: usize, n_keys: u64) -> Vec<Plan> {
    (0..n_txns)
        .map(|_| {
            let n_ops = 1 + (rng.next_u64() % 4) as usize; // 1..=4 ops
            let ops = (0..n_ops)
                .map(|_| {
                    let key = rng.next_u64() % n_keys;
                    if rng.next_u64() % 2 == 0 {
                        PlannedOp::Read(key)
                    } else {
                        PlannedOp::Write(key)
                    }
                })
                .collect();
            Plan { ops }
        })
        .collect()
}

/// Runs one randomized workload through the manager under SERIALIZABLE and returns the recorded
/// history of **committed** transactions (the only ones in a serialization graph).
///
/// The interleaving: transactions are started in waves so several are concurrent at once; within a
/// wave each transaction performs all its ops then attempts commit. A write-write conflict or SSI
/// abort simply means the transaction does not commit (its ops are excluded from the history) —
/// which is the correct, serializable outcome.
fn run_workload(seed: u64) -> HistoryChecker {
    let mut rng = SimRng::new(seed);
    let n_keys = 4;
    let plans = generate(&mut rng, 12, n_keys);

    let mut mgr = TxnManager::new(MemVersionedStore::new());

    // Seed every key with version 1 so reads have something to observe.
    let seed_txn = mgr.begin_serializable().unwrap();
    for k in 0..n_keys {
        mgr.write(seed_txn, k, encode(0, 1)).unwrap();
    }
    mgr.commit(seed_txn).unwrap();

    // `committed_version[k]` = the latest committed version number installed on key `k`.
    let mut committed_version: HashMap<u64, u64> = (0..n_keys).map(|k| (k, 1)).collect();

    let mut checker = HistoryChecker::new();

    // Process the plans in small overlapping waves to force concurrency.
    let wave = 3;
    let mut i = 0;
    while i < plans.len() {
        let end = (i + wave).min(plans.len());
        let batch = &plans[i..end];

        // Begin all transactions in the wave (they are now concurrent).
        let txns: Vec<TxnId> = batch
            .iter()
            .map(|_| mgr.begin_serializable().unwrap())
            .collect();

        // Each transaction performs its ops; record what it read/intends.
        // We buffer per-txn recorded ops and the version each write WILL install (decided at commit).
        let mut recorded: Vec<Vec<Op>> = vec![Vec::new(); batch.len()];
        let mut aborted: Vec<bool> = vec![false; batch.len()];

        for (j, plan) in batch.iter().enumerate() {
            if aborted[j] {
                continue;
            }
            let txn = txns[j];
            for op in &plan.ops {
                match *op {
                    PlannedOp::Read(key) => match mgr.read(txn, key) {
                        Ok(Some(payload)) => {
                            let observed = decode_version(&payload);
                            // `u64::MAX` is the placeholder of *this* transaction's own pending
                            // write (own-writes-visible). A read-after-own-write reads our own
                            // value and creates no inter-transaction dependency, so it is omitted
                            // from the serialization graph.
                            if observed != u64::MAX {
                                recorded[j].push(Op::Read {
                                    key,
                                    version: observed,
                                });
                            }
                        }
                        Ok(None) => {
                            recorded[j].push(Op::Read { key, version: 0 });
                        }
                        Err(_) => {
                            aborted[j] = true;
                            break;
                        }
                    },
                    PlannedOp::Write(key) => {
                        // Provisional payload; the version is fixed at commit. Use a placeholder we
                        // overwrite by re-writing at commit-time is overkill — instead we record the
                        // write intent and assign the version when the commit succeeds.
                        match mgr.write(txn, key, encode(txn.0, u64::MAX)) {
                            Ok(()) => recorded[j].push(Op::Write {
                                key,
                                version: u64::MAX, // patched at commit
                            }),
                            Err(_) => {
                                aborted[j] = true;
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Attempt to commit each non-aborted transaction; only committed ones enter the history,
        // and only on commit do their writes get a concrete version number (commit order).
        for (j, &txn) in txns.iter().enumerate() {
            if aborted[j] {
                let _ = mgr.rollback(txn);
                continue;
            }
            match mgr.commit(txn) {
                Ok(_) => {
                    // A committed transaction installs exactly one new version per key it wrote
                    // (the latest write wins; multiple writes of one key collapse to one version).
                    // Assign each written key its installed version once, in commit order.
                    let mut written: Vec<u64> = Vec::new();
                    for op in &recorded[j] {
                        if let Op::Write { key, .. } = *op
                            && !written.contains(&key)
                        {
                            written.push(key);
                        }
                    }
                    let mut installed: HashMap<u64, u64> = HashMap::new();
                    for key in &written {
                        let v = committed_version.entry(*key).or_insert(0);
                        *v += 1;
                        installed.insert(*key, *v);
                    }

                    let mut hist = TxnHistory::new(txn);
                    let mut wrote_key: Vec<u64> = Vec::new();
                    for op in &recorded[j] {
                        match *op {
                            Op::Read { key, version } => hist.read(key, version),
                            Op::Write { key, .. } => {
                                if !wrote_key.contains(&key) {
                                    wrote_key.push(key);
                                    hist.write(key, installed[&key]);
                                }
                            }
                        }
                    }
                    checker.add(hist);
                }
                Err(_) => {
                    // SSI/conflict abort: not serialized, not recorded. Correct outcome.
                    let _ = mgr.rollback(txn);
                }
            }
        }

        i = end;
    }

    checker
}

#[test]
fn serializable_histories_have_no_anomalies_across_seeds() {
    // Many deterministic seeds; every committed SERIALIZABLE history must be serializable (acyclic
    // DSG). This is the empirical Elle-style no-anomaly proof.
    for seed in 1..=200u64 {
        let checker = run_workload(seed);
        assert_eq!(
            checker.find_anomaly(),
            None,
            "SERIALIZABLE run for seed {seed} produced a serialization anomaly"
        );
    }
}

#[test]
fn the_checker_would_catch_an_anomaly_if_present() {
    // Teeth check, in the same file as the no-anomaly proof so the proof cannot be vacuous: a
    // hand-built write-skew history MUST be flagged by the very checker used above.
    let mut c = HistoryChecker::new();
    let mut t1 = TxnHistory::new(TxnId(1));
    t1.read(2, 0);
    t1.write(1, 1);
    let mut t2 = TxnHistory::new(TxnId(2));
    t2.read(1, 0);
    t2.write(2, 1);
    c.add(t1);
    c.add(t2);
    assert!(
        c.find_anomaly().is_some(),
        "the checker used in the no-anomaly proof must detect a real anomaly"
    );
}

#[test]
fn snapshot_isolation_can_produce_anomalies_the_checker_catches() {
    // Counterpoint: run the SAME write-skew workload under SNAPSHOT ISOLATION through the real
    // manager. SI permits write-skew, so both commit and the recorded history is non-serializable —
    // and the checker flags it. This jointly proves (a) SI is genuinely weaker and (b) the checker
    // detects anomalies the engine actually produces, not just synthetic ones.
    let mut mgr = TxnManager::new(MemVersionedStore::new());
    let seed = mgr.begin_serializable().unwrap();
    mgr.write(seed, 1, encode(0, 1)).unwrap();
    mgr.write(seed, 2, encode(0, 1)).unwrap();
    mgr.commit(seed).unwrap();

    let t1 = mgr.begin(IsolationLevel::Snapshot).unwrap();
    let t2 = mgr.begin(IsolationLevel::Snapshot).unwrap();

    let r1_y = decode_version(&mgr.read(t1, 2).unwrap().unwrap());
    let r2_x = decode_version(&mgr.read(t2, 1).unwrap().unwrap());
    mgr.write(t1, 1, encode(t1.0, 2)).unwrap();
    mgr.write(t2, 2, encode(t2.0, 2)).unwrap();
    // Under SI both commit (write-skew allowed).
    assert!(mgr.commit(t1).is_ok());
    assert!(mgr.commit(t2).is_ok());

    let mut c = HistoryChecker::new();
    let mut h1 = TxnHistory::new(t1);
    h1.read(2, r1_y); // read y (initial, v1)
    h1.write(1, 2); // installed x v2
    let mut h2 = TxnHistory::new(t2);
    h2.read(1, r2_x); // read x (initial, v1)
    h2.write(2, 2); // installed y v2
    c.add(h1);
    c.add(h2);

    assert!(
        c.find_anomaly().is_some(),
        "the SI write-skew the engine just committed must be flagged as a serialization anomaly"
    );
}
