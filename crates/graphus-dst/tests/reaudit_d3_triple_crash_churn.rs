//! Re-audit D3 (sprint-42 #485): **triple-crash** idempotency + **richer loser disposition** soak for
//! the #468/#301 corpse class — deeper than the committed `double_crash_recovery` soak.
//!
//! ## What it adds over the existing soaks
//!
//! `selfloop_churn_recovery` / `property_churn_recovery` do ONE crash; `double_crash_recovery` does
//! TWO and always leaves exactly one loser in flight at the crash. This soak strengthens the regime
//! along two axes the committed soaks do not exercise together:
//!
//!   1. **Three** crash + ARIES recovery cycles back-to-back. The 3rd cycle replays the WAL prefix the
//!      *second* recovery left behind (base records + R1 CLRs + R2 END records), so it certifies the
//!      ARIES repeating-history fixed point survives more than one re-entry — a crash during recovery
//!      during recovery. A non-idempotent redo/undo (an effect applied twice, or a CLR mis-resumed)
//!      would diverge here.
//!   2. **Independent loser disposition.** Each of `2..=4` interleaved losers is *independently* either
//!      rolled back LIVE (before the crash) or left IN-FLIGHT at the crash (so ARIES undo must unwind
//!      several interleaved losers in strict global descending-LSN order on a shared, densely-packed
//!      record page). At least one loser is forced in-flight so the crash always has undo work.
//!
//! The committed-survivor shape (self-loops AND properties on a shared node, threaded BELOW the loser
//! churn) is the worst-case #468/#301 corpse layout. After EACH recovery it asserts the checker's full
//! integrity bundle AND byte-identical observable state across all three recoveries (idempotency).
//!
//! Uses only public `RecordStore` + `recover_device` + `checker`/`model` API (no `src` edits).

use graphus_core::{PageId, TxnId};
use graphus_dst::checker::{self, CheckFailure};
use graphus_dst::model::{Model, PropTriple};
use graphus_dst::rng::DetRng;
use graphus_io::{BlockDevice, MemBlockDevice};
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

const POOL_CAPACITY: usize = 16;
const REL_TYPE: &str = "E";
const INLINE_TAG: u8 = 2;
const SEEDS: u64 = 12_000;

fn next_txn(next: &mut u64) -> TxnId {
    let id = TxnId(*next);
    *next += 1;
    id
}

/// The shared node's observable state for the idempotency comparison: sorted incident rel ids and
/// sorted property `(key, type_tag, value)` multiset.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Observed {
    incident: Vec<u64>,
    props: Vec<(u32, u8, u64)>,
}

fn observe(store: &Store, node: u64) -> Result<Observed, CheckFailure> {
    let mut incident = store
        .incident_rels(node)
        .map_err(|e| CheckFailure::StoreError {
            context: "incident_rels".into(),
            message: e.to_string(),
        })?;
    incident.sort_unstable();
    let mut props: Vec<(u32, u8, u64)> = store
        .node_properties(node)
        .map_err(|e| CheckFailure::StoreError {
            context: "node_properties".into(),
            message: e.to_string(),
        })?
        .into_iter()
        .map(|(_, p)| (p.key, p.type_tag, p.value_inline))
        .collect();
    props.sort_unstable();
    Ok(Observed { incident, props })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TripleCrashReport {
    seed: u64,
    result: Result<(), CheckFailure>,
    /// Whether `first_rel` pointed at a corpse after R1 (proves the #468 hard shape was reached).
    rel_corpse_head_after_r1: bool,
    /// Whether `first_prop` pointed at a corpse after R1 (#301).
    prop_corpse_head_after_r1: bool,
    /// How many losers were left in flight at the crash (>=1 always).
    inflight_losers: usize,
}

// Reopen the store on the **post-recovery** WAL (the one ARIES wrote its CLRs + ABORT end-records
// into), exactly as the production `LocalEngine::crash_restart` does — NOT on a throwaway clone of the
// pre-recovery sink. `MemLogSink` derives `Clone` over its `Vec` buffers (a deep copy), so recovering
// on `sink.clone()` and reopening on `sink` (as the committed `double_crash_recovery` harness does)
// would leave the recovery CLRs only in the discarded clone — the next cycle would replay the *base*
// log again, never "base + CLRs". Carrying the SAME `wal` forward makes each subsequent cycle genuinely
// replay the prior recovery's CLRs (the #239 CLR-durability path), so the idempotency assertion has the
// teeth its doc claims.
fn crash_no_force(store: Store) -> Store {
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    // Reopen on the post-recovery `wal` (carries the just-written CLRs + ABORT markers durably).
    RecordStore::open(device, wal, POOL_CAPACITY).expect("open store")
}

fn crash_steal(mut store: Store) -> Store {
    store.flush().expect("flush (steal)");
    let pages = store.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    for p in &pages {
        let bytes = store.read_device_page(*p).expect("read device page");
        device.write_page(PageId(p.0), &bytes).expect("stage page");
    }
    device.sync_all().expect("persist disk image");
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut wal = WalManager::open(sink).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    // Reopen on the post-recovery `wal` (carries CLRs forward), like `LocalEngine::crash_restart`.
    RecordStore::open(device, wal, POOL_CAPACITY).expect("open store")
}

fn corpse_heads(store: &Store, shared: u64) -> (bool, bool) {
    let rel_head = store.node(shared).expect("node").first_rel;
    let rel_corpse = rel_head != 0 && !store.rel(rel_head).expect("rel").mvcc.in_use();
    let prop_head = store.node(shared).expect("node").first_prop;
    let prop_corpse = prop_head != 0 && !store.property(prop_head).expect("prop").mvcc.in_use();
    (rel_corpse, prop_corpse)
}

fn run_triple_crash(seed: u64) -> TripleCrashReport {
    let mut rng = DetRng::new(seed);

    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut store = RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");

    let mut next = 1u64;
    let setup = next_txn(&mut next);
    store.begin(setup);
    let rel_type = store
        .intern_token(Namespace::RelType, REL_TYPE)
        .expect("intern reltype");
    let mut keys = Vec::new();
    for k in 0..3u32 {
        keys.push(
            store
                .intern_token(Namespace::PropKey, &format!("k{k}"))
                .expect("intern propkey"),
        );
    }
    store.commit(setup).expect("commit setup");

    let mut model = Model::new();

    // Committed nodes + shared node.
    let node_count = rng.range_inclusive(1, 3) as usize;
    let tnodes = next_txn(&mut next);
    store.begin(tnodes);
    let mut nodes = Vec::with_capacity(node_count);
    for _ in 0..node_count {
        let (id, _) = store.create_node(tnodes).expect("create_node");
        nodes.push(id);
    }
    store.commit(tnodes).expect("commit nodes");
    for &n in &nodes {
        model.add_node(n);
    }
    let shared = nodes[0];

    // Committed survivors: 1..=5 self-loops AND 1..=5 properties on the shared node.
    let surv_rels = rng.range_inclusive(1, 5);
    let surv_props = rng.range_inclusive(1, 5);
    let tsurv = next_txn(&mut next);
    store.begin(tsurv);
    let mut committed_rels = Vec::new();
    for _ in 0..surv_rels {
        let (id, _) = store
            .create_rel(tsurv, rel_type, shared, shared)
            .expect("create survivor self-loop");
        committed_rels.push((id, shared, shared));
    }
    let mut committed_props = Vec::new();
    for i in 0..surv_props {
        let key = keys[rng.index(keys.len())];
        let value = 0x1000 + i;
        store
            .add_node_property(tsurv, shared, key, INLINE_TAG, value)
            .expect("add survivor property");
        committed_props.push((key, value));
    }
    store.commit(tsurv).expect("commit survivors");
    for &(id, a, b) in &committed_rels {
        model.add_rel(id, a, b);
    }
    for &(key, value) in &committed_props {
        model.add_node_prop(
            shared,
            PropTriple {
                key,
                type_tag: INLINE_TAG,
                value_inline: value,
            },
        );
    }

    // 2..=4 interleaved losers churning self-loops AND properties on the shared node.
    let losers = rng.range_inclusive(2, 4) as usize;
    let mut tids = Vec::with_capacity(losers);
    for _ in 0..losers {
        let t = next_txn(&mut next);
        store.begin(t);
        tids.push(t);
    }
    let mut rem: Vec<u64> = (0..losers).map(|_| rng.range_inclusive(1, 5)).collect();
    let mut remaining: u64 = rem.iter().sum();
    while remaining > 0 {
        let mut pick = rng.index(losers);
        while rem[pick] == 0 {
            pick = (pick + 1) % losers;
        }
        let tid = tids[pick];
        if rng.chance(50) {
            let _ = store
                .create_rel(tid, rel_type, shared, shared)
                .expect("create loser self-loop");
        } else {
            let key = keys[rng.index(keys.len())];
            let _ = store
                .add_node_property(tid, shared, key, INLINE_TAG, 0x9000 + remaining)
                .expect("add loser property");
        }
        rem[pick] -= 1;
        remaining -= 1;
    }

    // INDEPENDENT loser disposition: each loser is rolled back LIVE or left in flight. Force at least
    // one in flight so the crash always has undo work (and the corpse layout is reached).
    let mut dispositions: Vec<bool> = (0..losers).map(|_| rng.chance(50)).collect(); // true ⇒ live-rollback
    if dispositions.iter().all(|&d| d) {
        let forced = rng.index(losers);
        dispositions[forced] = false; // at least one in flight
    }
    let mut inflight_losers = 0usize;
    for (i, &t) in tids.iter().enumerate() {
        if dispositions[i] {
            store.rollback(t).expect("live rollback loser");
        } else {
            inflight_losers += 1;
        }
    }
    // Optionally open one more bare in-flight transaction (an extra crash loser with no work yet).
    if rng.chance(40) {
        let t = next_txn(&mut next);
        store.begin(t);
    }
    store.with_wal(WalManager::flush);

    // --- Crash #1 (steal or no-force) + ARIES recovery. ---
    let store1 = if rng.chance(40) {
        crash_steal(store)
    } else {
        crash_no_force(store)
    };
    let (rel_corpse_head_after_r1, prop_corpse_head_after_r1) = corpse_heads(&store1, shared);
    let after_r1 = observe(&store1, shared);

    // --- Crash #2: replay the prefix R1 left (base + R1 CLRs). ---
    let store2 = crash_no_force(store1);
    let after_r2 = observe(&store2, shared);

    // --- Crash #3: replay the prefix R2 left (base + R1 CLRs + R2 ENDs). ---
    let mut store3 = crash_no_force(store2);

    let result = (|| {
        // Full integrity bundle after the THIRD recovery.
        checker::verify(&mut store3, &model)?;
        let a = after_r1?;
        let b = after_r2?;
        let c = observe(&store3, shared)?;
        if a != b {
            return Err(CheckFailure::StoreError {
                context: "triple-crash idempotency R1!=R2".into(),
                message: format!("R1 {a:?} != R2 {b:?}"),
            });
        }
        if b != c {
            return Err(CheckFailure::StoreError {
                context: "triple-crash idempotency R2!=R3".into(),
                message: format!("R2 {b:?} != R3 {c:?}"),
            });
        }
        Ok(())
    })();

    TripleCrashReport {
        seed,
        result,
        rel_corpse_head_after_r1,
        prop_corpse_head_after_r1,
        inflight_losers,
    }
}

#[test]
fn triple_crash_recovery_is_idempotent_across_seeds() {
    let mut passed = 0u64;
    let mut rel_corpse = 0u64;
    let mut prop_corpse = 0u64;
    let mut multi_inflight = 0u64;
    let mut first_failure: Option<TripleCrashReport> = None;

    for seed in 1..=SEEDS {
        let r = run_triple_crash(seed);
        if r.result.is_ok() {
            passed += 1;
        } else if first_failure.is_none() {
            first_failure = Some(r.clone());
        }
        if r.rel_corpse_head_after_r1 {
            rel_corpse += 1;
        }
        if r.prop_corpse_head_after_r1 {
            prop_corpse += 1;
        }
        if r.inflight_losers >= 2 {
            multi_inflight += 1;
        }
        // Determinism of the whole scenario.
        assert_eq!(
            r,
            run_triple_crash(seed),
            "seed {seed}: triple-crash scenario is not deterministic"
        );
    }

    if let Some(f) = &first_failure {
        panic!(
            "triple-crash recovery DIVERGED — reproduce with seed {}: {:?}",
            f.seed, f.result
        );
    }
    assert_eq!(passed, SEEDS, "every seed must survive three crashes");
    // Non-vacuity: the soak must reach the #468 (rel) and #301 (prop) corpse-head states AND the
    // multi-loser in-flight undo regime, or it is not exercising the hard shape.
    assert!(rel_corpse > 0, "no seed reached a rel corpse head — soak vacuous");
    assert!(prop_corpse > 0, "no seed reached a prop corpse head — soak vacuous");
    assert!(
        multi_inflight > 0,
        "no seed left >=2 losers in flight at the crash — multi-loser undo not exercised"
    );
    eprintln!(
        "triple_crash soak: {SEEDS} seeds PASS (idempotent across 3 recoveries); \
         rel-corpse-head {rel_corpse}, prop-corpse-head {prop_corpse}, >=2-inflight {multi_inflight}"
    );
}
