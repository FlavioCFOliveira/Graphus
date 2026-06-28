//! Large-seed crash-recovery sweep for **interleaved property-chain churn** — the property-chain
//! sibling of the self-loop incidence-chain soak (`rmp` #468 / seed 11731) that audits whether the
//! `rmp` #468 high-water floor closes the **same** dead-link-corpse class on the `first_prop` chain
//! (`rmp` #172 / #301).
//!
//! ## Why this exists (the #301 question)
//!
//! `add_node_property` prepends a new property onto a node's `first_prop` head with the *identical*
//! mechanism the incidence chain uses for relationships: a header-only creation undo for the prop
//! record plus a compare-and-set logical undo for the owner's `first_prop` head (`store.rs`
//! `write_chain_head`, `rmp` #172). When two sessions interleave property creations on the same
//! committed node, one is rolled back **live**, and the other is left **in flight** at a crash, ARIES
//! recovery can legitimately leave the node's `first_prop` pointing at a `!in_use` **dead-link
//! corpse** whose `next_prop` body still threads down to the committed properties below it. The hot
//! read path [`RecordStore::node_properties`] (→ `read_view::collect_prop_chain`) must thread through
//! that corpse run, bounded by the cycle guard `Prop.high_water + 1`.
//!
//! That is structurally the SAME bug `rmp` #468 fixed for the rel chain: if ARIES redo materialises a
//! loser's prop record on an already-mapped (committed-catalog) densely-packed Prop page *above* the
//! durable Prop high-water, `reconstruct_orphan_store_pages` (orphan pages only) cannot reach it, so
//! `Prop.high_water` stays *below* the corpse run, the guard `Prop.high_water + 1` is too small to
//! thread the run to the committed head, and committed properties below the run become unreadable
//! ("property chain ... malformed (cycle?)") = **committed-data loss**. The #468 fix
//! `floor_high_water_over_mapped_corpses` iterates **every** store (Node/Rel/Prop/Strings), so it is
//! expected to floor the Prop store too — this soak proves that empirically and pins the regression.
//!
//! The shape (mirrors `selfloop_churn`): commit survivors below loser churn, interleave 2..=3 loser
//! property creations on a shared node, roll some losers back live, leave one in flight, crash
//! (no-force or steal), run ARIES recovery + reopen, then assert every DST integrity invariant via
//! [`checker::verify`] — including the node property multiset, which exercises the corpse-threading
//! property read walk. [`head_pointed_at_corpse`](PropChurnReport::head_pointed_at_corpse) records
//! when a run actually reaches the vulnerable post-recovery state, so the sweep asserts non-vacuity.

use graphus_core::{PageId, TxnId};
use graphus_dst::checker::{self, CheckFailure};
use graphus_dst::model::{Model, PropTriple};
use graphus_dst::rng::DetRng;
use graphus_io::{BlockDevice, MemBlockDevice};
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// A small buffer-pool capacity, to exercise eviction and the WAL rule during the run.
const POOL_CAPACITY: usize = 16;
/// Inline integer-like value tag: stored purely inline (no overflow heap chain), so the soak isolates
/// the property *record* chain corpse-recovery path the #468/#301 class lives on.
const INLINE_TAG: u8 = 2;

/// The outcome of one property-churn crash-recovery run.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PropChurnReport {
    seed: u64,
    result: std::result::Result<(), CheckFailure>,
    /// How many committed properties (survivors) the run created on the shared node and must preserve.
    committed_props: usize,
    /// Recovery's loser count (transactions rolled back by recovery — at least the in-flight loser).
    recovery_losers: usize,
    /// Number of interleaved loser transactions (2 or 3).
    losers: usize,
    /// Whether the recovered shared node's `first_prop` legitimately pointed at a `!in_use` dead-link
    /// corpse (`rmp` #172) — the exact post-recovery state the #468/#301 class mishandles.
    head_pointed_at_corpse: bool,
    /// Whether the crash stole (flushed) dirty pages home before recovery.
    steal: bool,
}

impl PropChurnReport {
    fn passed(&self) -> bool {
        self.result.is_ok()
    }
}

fn next_txn(next: &mut u64) -> TxnId {
    let id = TxnId(*next);
    *next += 1;
    id
}

/// Runs one deterministic property-churn crash-recovery scenario for `seed`.
fn run_prop_churn_crash(seed: u64) -> PropChurnReport {
    let mut rng = DetRng::new(seed);
    let steal = rng.chance(40);

    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut store = RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");

    let mut next = 1u64;
    // Intern a handful of property keys up front (committed standalone), so the churn only touches the
    // Prop store + node first_prop chain.
    let setup = next_txn(&mut next);
    store.begin(setup);
    let mut keys = Vec::new();
    for k in 0..4u32 {
        let key = store
            .intern_token(Namespace::PropKey, &format!("k{k}"))
            .expect("intern propkey");
        keys.push(key);
    }
    store.commit(setup).expect("commit setup");

    let mut model = Model::new();

    // --- Committed nodes; pick a shared node whose property chain the losers churn. ---
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

    // --- Committed survivor properties on the shared node: committed data threaded BELOW the loser
    //     churn that a crash must never lose. ---
    let survivors = rng.range_inclusive(1, 5);
    let tsurv = next_txn(&mut next);
    store.begin(tsurv);
    let mut committed = Vec::new();
    for i in 0..survivors {
        let key = keys[rng.index(keys.len())];
        // Unique value per survivor so the multiset comparison in the checker is meaningful.
        let value = 0x1000 + i;
        store
            .add_node_property(tsurv, shared, key, INLINE_TAG, value)
            .expect("add survivor property");
        committed.push((key, value));
    }
    store.commit(tsurv).expect("commit survivors");
    for &(key, value) in &committed {
        model.add_node_prop(
            shared,
            PropTriple {
                key,
                type_tag: INLINE_TAG,
                value_inline: value,
            },
        );
    }

    // --- 2..=3 interleaved loser transactions churning properties on the shared node. All but one are
    //     rolled back LIVE; the last is left in flight at the crash (the seed-11731 family, extended to
    //     3+ losers per the #471 hostile-concurrency probe). ---
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
        // Pick a loser that still has budget (seeded), interleaving the prepends across all losers.
        let mut pick = rng.index(losers);
        while rem[pick] == 0 {
            pick = (pick + 1) % losers;
        }
        let key = keys[rng.index(keys.len())];
        let value = 0x9000 + remaining; // loser values: never acknowledged ⇒ never modelled.
        store
            .add_node_property(tids[pick], shared, key, INLINE_TAG, value)
            .expect("add loser property");
        rem[pick] -= 1;
        remaining -= 1;
    }

    // Roll all losers back LIVE except the last, which stays in flight at the crash. A seeded shuffle
    // of which stays in flight broadens the interleaving family.
    let in_flight = rng.index(losers);
    for (i, &t) in tids.iter().enumerate() {
        if i != in_flight {
            store.rollback(t).expect("live rollback loser");
        }
    }

    // Sometimes a freshly-begun, empty transaction at the crash boundary (mirrors seed-11731's txn7).
    if rng.chance(50) {
        let t = next_txn(&mut next);
        store.begin(t);
    }

    // Harden the loser tail so the crash WAL carries the in-flight loser's prepends: recovery redoes
    // them as corpses then undoes the loser — the state where `first_prop` can end on a corpse.
    store.with_wal(WalManager::flush);

    let (mut store, recovery_losers) = if steal {
        crash_steal(store)
    } else {
        crash_no_force(store)
    };

    // The vulnerable post-recovery state: the shared node's `first_prop` legitimately pointing at a
    // `!in_use` dead-link corpse (`rmp` #172), so the property read walk MUST thread through the
    // corpse run to reach the committed survivor properties below it.
    let head = store.node(shared).expect("node").first_prop;
    let head_pointed_at_corpse = head != 0 && !store.property(head).expect("prop").mvcc.in_use();

    let result = checker::verify(&mut store, &model);

    PropChurnReport {
        seed,
        result,
        committed_props: committed.len(),
        recovery_losers,
        losers,
        head_pointed_at_corpse,
        steal,
    }
}

/// No-force crash: rebuild onto a fresh empty device from the durable WAL prefix, then reopen.
fn crash_no_force(store: Store) -> (Store, usize) {
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    let report = recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    let store = RecordStore::open(device, wal, POOL_CAPACITY).expect("open store");
    (store, report.losers)
}

/// Steal crash: flush dirty pages home, snapshot that on-disk image, then recover so undo rolls back
/// any stolen uncommitted (loser) pages.
fn crash_steal(mut store: Store) -> (Store, usize) {
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
    let report = recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    let store = RecordStore::open(device, wal, POOL_CAPACITY).expect("open store");
    (store, report.losers)
}

/// The number of seeds swept. Large enough that the broad family of interleavings, loser counts, and
/// crash modes is exercised and the vulnerable corpse-head state is reached for many seeds.
const SEEDS: u64 = 10_000;

#[test]
fn property_churn_crash_recovery_holds_across_ten_thousand_seeds() {
    let mut passed = 0u64;
    let mut hit_corpse_head = 0u64;
    let mut hit_losers = 0u64;
    let mut hit_three = 0u64;
    let mut hit_steal = 0u64;
    let mut first_failure: Option<PropChurnReport> = None;

    for seed in 1..=SEEDS {
        let r = run_prop_churn_crash(seed);
        if r.passed() {
            passed += 1;
        } else if first_failure.is_none() {
            first_failure = Some(r.clone());
        }
        if r.head_pointed_at_corpse {
            hit_corpse_head += 1;
        }
        if r.recovery_losers > 0 {
            hit_losers += 1;
        }
        if r.losers >= 3 {
            hit_three += 1;
        }
        if r.steal {
            hit_steal += 1;
        }
        // Determinism: the same seed must reproduce byte-for-byte.
        assert_eq!(
            r,
            run_prop_churn_crash(seed),
            "seed {seed}: property-churn scenario is not deterministic"
        );
    }

    if let Some(f) = &first_failure {
        panic!(
            "property-churn crash recovery LOST committed data — reproduce with seed {}: {:?} \
             (committed_props={}, recovery_losers={}, losers={}, head_corpse={}, steal={})",
            f.seed,
            f.result,
            f.committed_props,
            f.recovery_losers,
            f.losers,
            f.head_pointed_at_corpse,
            f.steal,
        );
    }
    assert_eq!(
        passed, SEEDS,
        "every seed must preserve committed properties"
    );

    // Non-vacuity: the soak must actually reach the vulnerable post-recovery state (a corpse head
    // with committed properties below it), produce recovery losers, exercise 3-loser interleavings,
    // and exercise the steal crash mode — otherwise it proves nothing about #468/#301.
    assert!(
        hit_corpse_head > 0,
        "no seed reached a property corpse head — soak not exercising the #468/#301 condition"
    );
    assert!(
        hit_losers > 0,
        "no seed produced a recovery loser — vacuous"
    );
    assert!(
        hit_three > 0,
        "no seed exercised a 3-loser interleave — vacuous"
    );
    assert!(
        hit_steal > 0,
        "no seed exercised the steal crash mode — vacuous"
    );

    eprintln!(
        "property_churn soak: {SEEDS} seeds PASS; corpse-head reached {hit_corpse_head}, \
         recovery-losers {hit_losers}, 3-loser {hit_three}, steal {hit_steal}"
    );
}
