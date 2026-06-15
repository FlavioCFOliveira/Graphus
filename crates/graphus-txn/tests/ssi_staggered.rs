//! Staggered-lifetime SSI cross-check (`rmp` #111, storage audit F9).
//!
//! `elle_no_anomalies.rs` already drives the real [`TxnManager`] and cross-checks committed histories
//! against the DSG oracle — but it commits transactions in **synchronized waves**, so no transaction
//! ever outlives its wave. That cannot exercise the structure the audit flagged: a 3-transaction
//! pivot whose middle commits *before* the closing endpoint, where the second anti-dependency edge
//! forms only **after** the pivot has already committed (so `detect_pivot_abort`'s Case A cannot see
//! the out-edge at the pivot's commit, and Case B excludes the already-committed pivot at the
//! endpoint's commit).
//!
//! This harness interleaves transactions with **overlapping lifetimes**: at each step it randomly
//! begins a new transaction, advances a random in-flight one by one operation, or commits a random
//! in-flight one — so a transaction routinely commits while others remain open, and new transactions
//! begin after others have committed. Every committed transaction's read/write history is recorded
//! with concrete per-key version numbers (derived from the post-hoc commit order, robust to the
//! commit-time version assignment) and fed to the independent [`HistoryChecker`]. The acceptance
//! property: **every history the manager admits under SERIALIZABLE is serializable** (acyclic DSG).
//!
//! ## Version observation (robust)
//!
//! A write stores the **writer transaction id** in its payload. After the run, the committed writers
//! of each key, in commit order, define that key's version sequence (the seed is version 1). A read
//! decodes the writer of the value it observed and is mapped to that writer's version on the key; a
//! read of a transaction's own pending write creates no inter-transaction edge and is dropped. This
//! sidesteps the fact that a version number is only known at commit, not at write time.

use std::collections::HashMap;

use graphus_core::TxnId;
use graphus_core::capability::Rng;
use graphus_sim::SimRng;
use graphus_txn::{HistoryChecker, MemVersionedStore, NoDurability, TxnHistory, TxnManager};

/// The writer-id payload (8 bytes LE). `0` is the seed writer.
fn writer_payload(writer: u64) -> Vec<u8> {
    writer.to_le_bytes().to_vec()
}

fn decode_writer(payload: &[u8]) -> u64 {
    u64::from_le_bytes(payload[..8].try_into().expect("8-byte payload"))
}

/// A committed transaction's recorded history: `(id, reads as (key, observed_writer), keys written)`.
type CommittedTxn = (TxnId, Vec<(u64, u64)>, Vec<u64>);

#[derive(Clone, Copy)]
enum PlannedOp {
    Read(u64),
    Write(u64),
}

/// An in-flight transaction's planned ops and the inter-transaction operations recorded so far.
struct InFlight {
    id: TxnId,
    plan: Vec<PlannedOp>,
    cursor: usize,
    /// `(key, observed_writer)` for each read of another transaction's committed value.
    reads: Vec<(u64, u64)>,
    /// Keys this transaction wrote (deduplicated).
    writes: Vec<u64>,
}

fn generate(rng: &mut SimRng, n_txns: usize, n_keys: u64) -> Vec<Vec<PlannedOp>> {
    (0..n_txns)
        .map(|_| {
            let n_ops = 2 + (rng.next_u64() % 3) as usize; // 2..=4 ops
            (0..n_ops)
                .map(|_| {
                    let key = rng.next_u64() % n_keys;
                    if rng.next_u64() % 2 == 0 {
                        PlannedOp::Read(key)
                    } else {
                        PlannedOp::Write(key)
                    }
                })
                .collect()
        })
        .collect()
}

/// Drives one staggered workload through the real manager under SERIALIZABLE and returns any DSG
/// cycle the committed histories contain (`None` ⇒ serializable).
fn run_staggered(seed: u64) -> Option<Vec<TxnId>> {
    let mut rng = SimRng::new(seed);
    let n_keys = 3u64;
    let cap = 4usize; // max concurrent in-flight transactions
    let plans = generate(&mut rng, 24, n_keys);

    let mut mgr = TxnManager::new(MemVersionedStore::new());

    // Seed every key (writer 0 ⇒ version 1).
    let seed_txn = mgr.begin_serializable().unwrap();
    for k in 0..n_keys {
        mgr.write(seed_txn, k, writer_payload(0)).unwrap();
    }
    mgr.commit(seed_txn).unwrap();

    // Per-key writers in commit order (seed first). version(key, writer) = index + 1.
    let mut key_writers: HashMap<u64, Vec<u64>> = (0..n_keys).map(|k| (k, vec![0u64])).collect();
    // Recorded committed transactions: (id, reads, writes).
    let mut committed: Vec<CommittedTxn> = Vec::new();

    let mut active: Vec<InFlight> = Vec::new();
    let mut next_plan = 0usize;
    let mut guard = 0u64;

    let commit_one = |mgr: &mut TxnManager<MemVersionedStore, NoDurability>,
                      t: InFlight,
                      key_writers: &mut HashMap<u64, Vec<u64>>,
                      committed: &mut Vec<CommittedTxn>| {
        if mgr.commit(t.id).is_ok() {
            for &k in &t.writes {
                key_writers.get_mut(&k).expect("seeded key").push(t.id.0);
            }
            committed.push((t.id, t.reads, t.writes));
        }
        // On Err the transaction (or a poisoned victim) aborted — correctly not recorded.
    };

    while (next_plan < plans.len() || !active.is_empty()) && guard < 1_000_000 {
        guard += 1;
        let can_begin = next_plan < plans.len() && active.len() < cap;
        let action = rng.next_u64() % 3;

        if active.is_empty() || (action == 0 && can_begin) {
            let id = mgr.begin_serializable().unwrap();
            active.push(InFlight {
                id,
                plan: plans[next_plan].clone(),
                cursor: 0,
                reads: Vec::new(),
                writes: Vec::new(),
            });
            next_plan += 1;
            continue;
        }

        let idx = (rng.next_u64() as usize) % active.len();
        let has_more = active[idx].cursor < active[idx].plan.len();

        if action == 1 && has_more {
            // Advance this transaction by one operation.
            let op = active[idx].plan[active[idx].cursor];
            active[idx].cursor += 1;
            let id = active[idx].id;
            match op {
                PlannedOp::Read(key) => match mgr.read(id, key) {
                    Ok(Some(payload)) => {
                        let writer = decode_writer(&payload);
                        if writer != id.0 {
                            active[idx].reads.push((key, writer));
                        }
                    }
                    Ok(None) => active[idx].reads.push((key, 0)),
                    Err(_) => {
                        let _ = mgr.rollback(id);
                        active.remove(idx);
                    }
                },
                PlannedOp::Write(key) => match mgr.write(id, key, writer_payload(id.0)) {
                    Ok(()) => {
                        if !active[idx].writes.contains(&key) {
                            active[idx].writes.push(key);
                        }
                    }
                    Err(_) => {
                        let _ = mgr.rollback(id);
                        active.remove(idx);
                    }
                },
            }
        } else {
            // Commit this transaction now (a transaction may commit before finishing its plan).
            let t = active.remove(idx);
            commit_one(&mut mgr, t, &mut key_writers, &mut committed);
        }
    }

    // Commit any stragglers.
    for t in std::mem::take(&mut active) {
        commit_one(&mut mgr, t, &mut key_writers, &mut committed);
    }

    // Map (key, writer) -> version (1-based; seed = 1).
    let mut version_of: HashMap<(u64, u64), u64> = HashMap::new();
    for (k, writers) in &key_writers {
        for (i, w) in writers.iter().enumerate() {
            version_of.insert((*k, *w), i as u64 + 1);
        }
    }

    let mut checker = HistoryChecker::new();
    // The seed transaction writes version 1 of every key, so reads of v1 form wr-edges from it.
    let mut seed_hist = TxnHistory::new(seed_txn);
    for k in 0..n_keys {
        seed_hist.write(k, 1);
    }
    checker.add(seed_hist);

    for (id, reads, writes) in &committed {
        let mut h = TxnHistory::new(*id);
        for (k, writer) in reads {
            let v = *version_of.get(&(*k, *writer)).unwrap_or(&0);
            h.read(*k, v);
        }
        for k in writes {
            let v = *version_of
                .get(&(*k, id.0))
                .expect("a committed writer has a version");
            h.write(*k, v);
        }
        checker.add(h);
    }

    checker.find_anomaly()
}

/// Deterministic regression for the **first-committer-wins** lost update (the seed-9 class): two
/// concurrent transactions read a key; one writes it and commits; the other then writes the same key
/// based on its stale snapshot. Under SI the second writer must abort (it would overwrite a version
/// it cannot see). Before the fix the lock-based first-updater-wins released at the first committer's
/// commit and let the second writer through — a ww/rw cycle.
#[test]
fn first_committer_wins_rejects_a_lost_update() {
    let mut mgr = TxnManager::new(MemVersionedStore::new());
    let s = mgr.begin_serializable().unwrap();
    mgr.write(s, 0, vec![1]).unwrap();
    mgr.commit(s).unwrap();

    let t1 = mgr.begin_serializable().unwrap();
    let t2 = mgr.begin_serializable().unwrap(); // concurrent: snapshot precedes t1's commit
    mgr.read(t2, 0).unwrap(); // t2 reads the seed value
    mgr.write(t1, 0, vec![2]).unwrap();
    mgr.commit(t1).unwrap(); // t1 commits a new version of key 0

    // t2 now tries to write key 0 over the version it cannot see -> first-committer-wins conflict.
    assert!(
        mgr.write(t2, 0, vec![3]).is_err(),
        "first-committer-wins must reject a write over a concurrently-committed version"
    );
}

/// Deterministic regression for the **committed-pivot** dangerous structure (the seed-102 class):
/// `T12 --rw--> T9 --rw--> T6` where the pivot T9 commits *before* either anti-dependency edge forms.
/// Neither commit-time case can abort the already-committed pivot, so the eager `add_edge` break must
/// doom the still-active endpoint (T12) that closes the structure.
#[test]
fn committed_pivot_structure_aborts_the_closing_endpoint() {
    let mut mgr = TxnManager::new(MemVersionedStore::new());
    let s = mgr.begin_serializable().unwrap();
    mgr.write(s, 0, vec![1]).unwrap(); // key 0 v1
    mgr.write(s, 2, vec![1]).unwrap(); // key 2 v1
    mgr.commit(s).unwrap();

    let t6 = mgr.begin_serializable().unwrap();
    let t9 = mgr.begin_serializable().unwrap();
    let t12 = mgr.begin_serializable().unwrap();

    // T9 (the pivot) reads key 0 and writes key 2, then commits — at this point it has NEITHER
    // anti-dependency edge yet, so no commit-time check can flag it.
    mgr.read(t9, 0).unwrap();
    mgr.write(t9, 2, vec![2]).unwrap();
    mgr.commit(t9).unwrap();

    // The two edges form only now, around the already-committed T9:
    mgr.write(t6, 0, vec![2]).unwrap(); // T9 --rw--> T6 (T9 read key0 v1, T6 overwrites)
    mgr.read(t12, 2).unwrap(); // T12 --rw--> T9 (T12 reads key2 v1, T9 overwrote) ⇒ T9 is a committed pivot

    assert!(mgr.commit(t6).is_ok(), "the out-endpoint commits");
    assert!(
        mgr.commit(t12).is_err(),
        "the active endpoint closing a committed-pivot structure must abort to preserve serializability"
    );
}

#[test]
fn serializable_staggered_histories_have_no_anomalies() {
    // Many deterministic seeds with overlapping transaction lifetimes — the cross-commit pivot
    // structures the wave-synchronized elle harness cannot reach. Every committed SERIALIZABLE
    // history must be serializable; any cycle is an SSI defect (storage audit F9).
    for seed in 1..=1000u64 {
        if let Some(cycle) = run_staggered(seed) {
            panic!(
                "SERIALIZABLE staggered run for seed {seed} committed a non-serializable history; \
                 DSG cycle over {cycle:?} — the SSI detector admitted an anomaly"
            );
        }
    }
}

// =================================================================================================
// Canonical multi-hop rw-antidependency cycle harness (rmp #224, residual finding #153).
//
// The staggered fuzz above proves the detector admits no anomalous *random* history; this harness
// adds the missing **direct, deterministic** construction the finding asked for: canonical n-cycles
// of read-write antidependencies (T0 -rw-> T1 -rw-> ... -rw-> T_{n-1} -rw-> T0) for n = 3 and n = 4,
// asserting the SSI layer breaks every cycle with at least one abort — the concrete safety property
// behind the 100%-ACID serializability pillar. Plus negative cases that must NOT abort, chosen to
// contain no dangerous structure at all (a lone antidependency and fully independent transactions),
// so they hold even though SSI is intentionally conservative and may abort acyclic *pivots*.
// =================================================================================================

/// Builds a pure rw-antidependency `n`-cycle over `n` concurrent SERIALIZABLE transactions and
/// asserts the manager aborts at least one of them. Construction: a committed seed installs v1 on
/// keys `0..n`; then transaction `i` reads key `i` (observing the seed version) and writes key
/// `(i+1) % n`. Because `i -> (i+1) % n` is a permutation, there is **no** write-write conflict — the
/// only conflicts are the rw-antidependencies `T_{(i+1)%n} -rw-> T_i` (the reader of key `(i+1)%n`
/// is dominated by `T_i`'s overwrite), which close an `n`-cycle in the dependency-serialization
/// graph. A serializable engine MUST refuse to commit the whole cycle.
fn canonical_rw_cycle_forces_abort(n: u64) {
    assert!(n >= 2);
    let mut mgr = TxnManager::new(MemVersionedStore::new());

    let seed = mgr.begin_serializable().unwrap();
    for k in 0..n {
        mgr.write(seed, k, writer_payload(0)).unwrap();
    }
    mgr.commit(seed).unwrap();

    // All `n` transactions begin concurrently (overlapping lifetimes — none commits before the
    // cycle is fully wired).
    let txns: Vec<TxnId> = (0..n).map(|_| mgr.begin_serializable().unwrap()).collect();

    // Read footprints first: each Ti reads key i, observing the seed's v1.
    for (i, &t) in txns.iter().enumerate() {
        mgr.read(t, i as u64).unwrap();
    }
    // Then the writes that turn those reads into antidependencies: Ti overwrites key (i+1) % n,
    // which T_{(i+1)%n} just read. No two transactions target the same key (permutation), so every
    // write succeeds (no first-committer-wins ww-abort) and the structure is purely rw.
    for (i, &t) in txns.iter().enumerate() {
        mgr.write(t, (i as u64 + 1) % n, writer_payload(i as u64 + 1))
            .unwrap();
    }

    // Commit in index order. At least one commit must fail to break the cycle.
    let aborts = txns.iter().filter(|&&t| mgr.commit(t).is_err()).count();
    assert!(
        aborts >= 1,
        "n={n}: a {n}-transaction rw-antidependency cycle must force >=1 abort to stay \
         serializable, but every transaction committed"
    );
}

#[test]
fn three_transaction_rw_cycle_breaks() {
    canonical_rw_cycle_forces_abort(3);
}

#[test]
fn four_transaction_rw_cycle_breaks() {
    canonical_rw_cycle_forces_abort(4);
}

#[test]
fn independent_transactions_never_abort() {
    // No conflicts at all: each transaction reads and writes a private key. There is no dangerous
    // structure, so a correct (non-over-aborting) SSI layer commits all of them. Guards against a
    // detector that spuriously aborts disjoint work.
    let mut mgr = TxnManager::new(MemVersionedStore::new());
    let n: u64 = 6;

    let seed = mgr.begin_serializable().unwrap();
    for k in 0..n {
        mgr.write(seed, k, writer_payload(0)).unwrap();
    }
    mgr.commit(seed).unwrap();

    let txns: Vec<TxnId> = (0..n).map(|_| mgr.begin_serializable().unwrap()).collect();
    for (i, &t) in txns.iter().enumerate() {
        mgr.read(t, i as u64).unwrap();
        mgr.write(t, i as u64, writer_payload(i as u64 + 1))
            .unwrap();
    }
    for (i, &t) in txns.iter().enumerate() {
        assert!(
            mgr.commit(t).is_ok(),
            "independent transaction {i} must commit (no conflict, no false abort)"
        );
    }
}

#[test]
fn lone_antidependency_does_not_abort() {
    // A single rw-antidependency edge (T0 -rw-> T1) with NO second edge: there is no pivot (T0 has
    // only an out-edge, T1 only an in-edge), hence no dangerous structure. Both must commit — a lone
    // antidependency is not a serializability violation.
    let mut mgr = TxnManager::new(MemVersionedStore::new());

    let seed = mgr.begin_serializable().unwrap();
    mgr.write(seed, 0, writer_payload(0)).unwrap(); // key A
    mgr.write(seed, 1, writer_payload(0)).unwrap(); // key C (T1's private read)
    mgr.commit(seed).unwrap();

    let t0 = mgr.begin_serializable().unwrap();
    let t1 = mgr.begin_serializable().unwrap();

    mgr.read(t0, 0).unwrap(); // T0 reads key A (seed v1)
    mgr.write(t0, 2, writer_payload(1)).unwrap(); // T0 writes key D (private, unread)
    mgr.read(t1, 1).unwrap(); // T1 reads key C (private, no in-edge to T1)
    mgr.write(t1, 0, writer_payload(2)).unwrap(); // T1 overwrites key A ⇒ T0 -rw-> T1 (the only edge)

    assert!(mgr.commit(t0).is_ok(), "the antidependency tail commits");
    assert!(
        mgr.commit(t1).is_ok(),
        "a lone antidependency (no pivot) must not abort the head"
    );
}
