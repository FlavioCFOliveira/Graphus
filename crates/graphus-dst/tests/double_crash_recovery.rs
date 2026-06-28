//! Crash-during-recovery (double-crash) idempotency soak for the hostile incidence + property churn
//! family (`rmp` #471 probe 2: "multi-crash — crash during recovery").
//!
//! ARIES recovery itself writes hardened, redo-only **CLRs** during undo (`graphus-wal`
//! `recovery.rs`, `04 §4.9`). A power loss that strikes *after* recovery has written some CLRs but
//! *before* the next checkpoint truncates the WAL must be safe: the next recovery replays the same
//! durable prefix — now carrying those CLRs — and ARIES repeating-history must converge to the exact
//! same committed state (a CLR "records an undo that already happened; resume at the next LSN to
//! undo"). If the second pass diverged, a crash during recovery would corrupt or lose committed data.
//!
//! This soak builds the worst-case post-recovery shape the `rmp` #468/#301 corpse class lives on —
//! committed self-loops AND committed properties on a shared node, threaded *below* interleaved loser
//! churn (2..=3 losers, all but one rolled back live, the last in flight at the crash) — then runs
//! **two** crash + ARIES recovery cycles back to back. The second cycle replays the WAL prefix the
//! first recovery left behind (base records + CLRs). It asserts:
//!
//!   1. the checker's full integrity bundle holds after the *second* recovery (no committed self-loop
//!      or property lost, every chain a well-formed forward thread); and
//!   2. **idempotency**: the shared node's incidence set and property multiset are byte-identical
//!      after the first and second recoveries (recovery is a fixed point).

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

fn next_txn(next: &mut u64) -> TxnId {
    let id = TxnId(*next);
    *next += 1;
    id
}

/// The shared node's observable state used for the idempotency comparison: its sorted incident rel
/// ids and its sorted property `(key, type_tag, value)` multiset.
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

/// One double-crash run report.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DoubleCrashReport {
    seed: u64,
    /// `Ok` if the second recovery preserved every invariant AND matched the first recovery.
    result: Result<(), CheckFailure>,
    /// Whether the shared node's `first_rel` pointed at a corpse after the FIRST recovery (the #468
    /// vulnerable state — proves the double-crash is exercising the hard shape, not a trivial one).
    rel_corpse_head_after_r1: bool,
    /// Whether the shared node's `first_prop` pointed at a corpse after the first recovery (#301).
    prop_corpse_head_after_r1: bool,
}

fn run_double_crash(seed: u64) -> DoubleCrashReport {
    let mut rng = DetRng::new(seed);
    let steal_first = rng.chance(40);

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

    // Committed nodes + shared.
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

    // Committed survivors: self-loops AND properties on the shared node, threaded below loser churn.
    let surv_rels = rng.range_inclusive(1, 4);
    let surv_props = rng.range_inclusive(1, 4);
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

    // 2..=3 interleaved losers churning BOTH self-loops and properties on the shared node.
    let losers = rng.range_inclusive(2, 3) as usize;
    let mut tids = Vec::with_capacity(losers);
    for _ in 0..losers {
        let t = next_txn(&mut next);
        store.begin(t);
        tids.push(t);
    }
    let mut rem: Vec<u64> = (0..losers).map(|_| rng.range_inclusive(1, 4)).collect();
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
    let in_flight = rng.index(losers);
    for (i, &t) in tids.iter().enumerate() {
        if i != in_flight {
            store.rollback(t).expect("live rollback loser");
        }
    }
    if rng.chance(50) {
        let t = next_txn(&mut next);
        store.begin(t);
    }
    store.with_wal(WalManager::flush);

    // --- Crash #1 + ARIES recovery. ---
    let store1 = if steal_first {
        crash_steal(store)
    } else {
        crash_no_force(store)
    };

    let rel_head = store1.node(shared).expect("node").first_rel;
    let rel_corpse_head_after_r1 =
        rel_head != 0 && !store1.rel(rel_head).expect("rel").mvcc.in_use();
    let prop_head = store1.node(shared).expect("node").first_prop;
    let prop_corpse_head_after_r1 =
        prop_head != 0 && !store1.property(prop_head).expect("prop").mvcc.in_use();

    // Snapshot the recovered observable state after R1 (before the second crash consumes the store).
    let after_r1 = observe(&store1, shared);

    // --- Crash #2: replay the WAL prefix the FIRST recovery left behind (base + CLRs) onto a fresh
    //     device. This is the crash-during/after-recovery, before-checkpoint case. ---
    let mut store2 = crash_no_force(store1);

    let result = (|| {
        checker::verify(&mut store2, &model)?;
        let a = after_r1?;
        let b = observe(&store2, shared)?;
        if a != b {
            return Err(CheckFailure::StoreError {
                context: "double-crash idempotency".into(),
                message: format!("R1 {a:?} != R2 {b:?}"),
            });
        }
        Ok(())
    })();

    DoubleCrashReport {
        seed,
        result,
        rel_corpse_head_after_r1,
        prop_corpse_head_after_r1,
    }
}

fn crash_no_force(store: Store) -> Store {
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
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
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, POOL_CAPACITY).expect("open store")
}

const SEEDS: u64 = 6_000;

#[test]
fn double_crash_recovery_is_idempotent_across_seeds() {
    let mut passed = 0u64;
    let mut rel_corpse = 0u64;
    let mut prop_corpse = 0u64;
    let mut first_failure: Option<DoubleCrashReport> = None;

    for seed in 1..=SEEDS {
        let r = run_double_crash(seed);
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
        assert_eq!(
            r,
            run_double_crash(seed),
            "seed {seed}: double-crash scenario is not deterministic"
        );
    }

    if let Some(f) = &first_failure {
        panic!(
            "crash-during-recovery DIVERGED — reproduce with seed {}: {:?}",
            f.seed, f.result
        );
    }
    assert_eq!(passed, SEEDS, "every seed must survive a double crash");
    // Non-vacuity: the double crash must reach the #468 (rel) and #301 (prop) corpse-head states.
    assert!(
        rel_corpse > 0,
        "no seed reached a rel corpse head after R1 — double-crash soak is vacuous"
    );
    assert!(
        prop_corpse > 0,
        "no seed reached a prop corpse head after R1 — double-crash soak is vacuous"
    );
    eprintln!(
        "double_crash soak: {SEEDS} seeds PASS (idempotent); rel-corpse-head {rel_corpse}, \
         prop-corpse-head {prop_corpse}"
    );
}
