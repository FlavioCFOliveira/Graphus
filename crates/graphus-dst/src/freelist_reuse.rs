//! Focused deterministic reproducer for **free-list double-allocation after a live rollback**
//! (`rmp` #578).
//!
//! Under high concurrent write load (many statement-interleaved SSI transactions), Graphus's
//! property (`first_prop`) and incidence (`first_rel`) chains were observed to become **cyclic** —
//! the server-side walk guards fire with `"… chain of node N is malformed (cycle?)"` and committed
//! data threaded below the cycle becomes unreadable (an ACID durability breach). The storage audit
//! root-caused it to a **physical-id double-allocation**:
//!
//! 1. GC frees a physical id `P` and commits, so the last *durably committed* free list is `[P]`.
//! 2. An open transaction `A` pops `P` (via `alloc_id`), links it into a node's chain, and stays
//!    **open**.
//! 3. A *different* transaction `B` **live-rolls-back**; `reload_catalog` restores the free list to
//!    the committed image `[P]` — re-listing `P` even though `A` still holds it `in_use`.
//! 4. A later transaction `C` pops `P` **again**. `A` and `C` now both own slot `P`, so `C` writes
//!    `P.next_prop = P` / `P.start_next = P` — a self-cycle, persisted to a durable page.
//!
//! Because `alloc_id` is store-generic, **both** the relationship and property chains corrupt; this
//! module reproduces the defect deterministically against BOTH stores, at only three transactions
//! (`A`, `B`, `C`) — no concurrency primitives, just the statement-interleaving the generic
//! [`crate::harness`] deliberately never performs (the same reason [`crate::selfloop_churn`] exists).
//!
//! The reproduction drives [`graphus_storage::RecordStore`] directly:
//!
//! 1. commit a node `H` plus a handful of committed **survivors** (relationships or properties)
//!    threaded *below* the churn — committed data a corruption must never lose;
//! 2. add one **victim** entity, delete it, and [`RecordStore::gc`] past the delete so `reclaim_*`
//!    frees its id `P` and commits — the last committed free list is now `[P]`;
//! 3. open `A`, allocate on `H` (popping `P`), and leave `A` **open**;
//! 4. open `B`, do one write, and **live-roll-back** `B`;
//! 5. assert — **while `A` still holds `P`** — that the storage consistency checker finds NO free-list
//!    fault ([`graphus_storage::FreeListFault::StillInUse`]). This alone catches the defect *before*
//!    any cycle forms (pre-fix it fires; post-fix it does not);
//! 6. open `C`, allocate on `H` again, assert it did NOT re-pop `P`, commit `A` and `C`, and assert
//!    the recovered graph equals the reference [`Model`] via [`crate::checker::verify`] — no
//!    `"malformed (cycle?)"`.
//!
//! The fix ([`RecordStore::rollback`], `rmp` #578) restores the *pre-rollback in-memory* free list
//! (which already reflects `A`'s pop) minus the aborting transaction's own pushes — the free-list twin
//! of the `rmp` #220/#172 monotonic high-water floor. A separate crash-recovery variant confirms the
//! fix is durability-neutral: `RecordStore::open` rebuilds the free list from the durable catalog, so
//! recovery is byte-identical and unaffected (there are no surviving concurrent open transactions
//! after a crash — the same reasoning as the #220 high-water floor, which is likewise live-rollback
//! only).

use graphus_core::{PageId, TxnId};
use graphus_io::{BlockDevice, MemBlockDevice};
use graphus_storage::check::check_store;
use graphus_storage::recovery::recover_device;
use graphus_storage::{FreeListFault, Namespace, RecordStore, Violation};
use graphus_wal::{LogSink, MemLogSink, WalManager};

use crate::checker::{self, CheckFailure};
use crate::model::{Model, PropTriple};
use crate::rng::DetRng;

/// The store type the reproducer drives: the record store over the in-memory DST device + log.
type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// The single reltype token used for every relationship in the relationship variant.
const REL_TYPE: &str = "E";
/// A small buffer-pool capacity, so eviction + the WAL rule are exercised during the run.
const POOL_CAPACITY: usize = 16;
/// Inline scalar `type_tag` (an integer property, mirroring the storage tests). Kept constant so the
/// model's [`PropTriple`]s compare byte-for-byte with what the store persists.
const INLINE_TAG: u8 = 1;

/// Which store the freed-then-reused physical id lives in. `alloc_id` is store-generic, so the
/// double-allocation corrupts either chain; the reproducer exercises both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The property store: the reused slot lands in a node's singly-linked `first_prop` chain, and a
    /// double-allocation makes `P.next_prop = P` (a self-cycle).
    Prop,
    /// The relationship store: the reused slot lands in a node's doubly-linked incidence chain, and a
    /// double-allocation makes the incidence link point at itself (a self-cycle).
    Rel,
}

/// The outcome of one free-list-reuse-after-rollback reproduction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreelistReuseReport {
    /// The scenario seed (the reproducer).
    pub seed: u64,
    /// Which store the reused slot lived in.
    pub target: Target,
    /// How many committed survivor entities were threaded below the churn.
    pub survivors: usize,
    /// The physical id GC freed and `A` re-allocated (the reused slot `P`).
    pub reused_id: u64,
    /// The physical id `C` allocated. Post-fix this MUST differ from `reused_id` (no double-alloc);
    /// pre-fix it equals it (the defect).
    pub c_allocated_id: u64,
    /// Whether `A` actually popped the GC-freed slot `P` — i.e. the reproducer reached its
    /// precondition (a non-vacuity signal; a sweep asserts it holds every seed).
    pub reached_precondition: bool,
    /// Whether the double-allocation was averted (`C` did not re-pop `P`). Post-fix MUST be `true`.
    pub double_alloc_averted: bool,
    /// The first free-list fault the storage consistency checker reports at the CRITICAL point —
    /// after `B`'s live rollback, while `A` still holds `P`, before `C` allocates. Post-fix MUST be
    /// `None`; pre-fix this is `Some(FreeListFault::StillInUse)` (a live record sitting on the free
    /// list).
    pub freelist_fault: Option<FreeListFault>,
    /// The DST invariant-checker result after `A` and `C` commit. Post-fix MUST be `Ok`; pre-fix this
    /// is a `StoreError` carrying `"malformed (cycle?)"` (the cyclic chain the double-alloc created).
    pub result: std::result::Result<(), CheckFailure>,
}

impl FreelistReuseReport {
    /// Whether the run upheld every property: the reproducer reached its precondition, the
    /// double-allocation was averted, the storage checker found no free-list fault, and the recovered
    /// graph equalled the model.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.reached_precondition
            && self.double_alloc_averted
            && self.freelist_fault.is_none()
            && self.result.is_ok()
    }
}

/// The outcome of one crash-recovery variant: the reproduction's committed state, crashed and
/// recovered, must still equal the model (proving the `rmp` #578 fix is durability-neutral).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreelistReuseCrashReport {
    /// The scenario seed.
    pub seed: u64,
    /// Which store the reused slot lived in.
    pub target: Target,
    /// Whether the crash stole (flushed) dirty pages home before recovery.
    pub steal: bool,
    /// Whether `A` actually popped the GC-freed slot `P` (non-vacuity).
    pub reached_precondition: bool,
    /// Whether the double-allocation was averted before the crash.
    pub double_alloc_averted: bool,
    /// `Ok(())` if the recovered graph equalled the model, else the first failure.
    pub result: std::result::Result<(), CheckFailure>,
}

impl FreelistReuseCrashReport {
    /// Whether the recovered graph upheld every invariant.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.reached_precondition && self.double_alloc_averted && self.result.is_ok()
    }
}

/// Allocates a fresh monotonically-increasing [`TxnId`] from `next`.
fn next_txn(next: &mut u64) -> TxnId {
    let id = TxnId(*next);
    *next += 1;
    id
}

/// The intermediate result of driving the reproduction up to (and including) committing `A` and `C`
/// and mirroring their effects into the model — shared by the live-assertion and crash-recovery
/// entry points.
struct ScenarioOutcome {
    store: Store,
    model: Model,
    target: Target,
    survivors: usize,
    reused_id: u64,
    c_allocated_id: u64,
    reached_precondition: bool,
    double_alloc_averted: bool,
    freelist_fault: Option<FreeListFault>,
}

/// Allocates one entity on `H` under `txn` in the chosen store, returning its physical id.
///
/// For [`Target::Prop`] this appends an inline property `(key, INLINE_TAG, value)`; for
/// [`Target::Rel`] it creates a self-loop on `H` (the `key`/`value` are ignored). Both go through
/// `alloc_id`, which pops the free list first — the operation whose double-pop this module reproduces.
fn alloc_on_h(
    store: &mut Store,
    txn: TxnId,
    target: Target,
    rel_type: u32,
    h: u64,
    key: u32,
    value: u64,
) -> u64 {
    match target {
        Target::Prop => store
            .add_node_property(txn, h, key, INLINE_TAG, value)
            .expect("alloc property on H"),
        Target::Rel => {
            store
                .create_rel(txn, rel_type, h, h)
                .expect("alloc relationship on H")
                .0
        }
    }
}

/// The first free-list fault the storage consistency checker finds over `store`, or `None` if the
/// free list is sane. Reads only; safe to call mid-transaction (it reports the *current* record and
/// free-list state, which is exactly the latent contradiction — a freed id whose record is still
/// `in_use` — we need to catch before any cycle materialises).
fn first_freelist_fault(store: &mut Store) -> Option<FreeListFault> {
    let report = check_store(store, &[]).expect("consistency check runs");
    report.violations.iter().find_map(|v| match v {
        Violation::FreeList { detail, .. } => Some(*detail),
        _ => None,
    })
}

/// Drives the deterministic reproduction for `seed` up to and including committing `A` and `C`.
fn drive_scenario(seed: u64) -> ScenarioOutcome {
    let mut rng = DetRng::new(seed);
    let target = if rng.chance(50) {
        Target::Prop
    } else {
        Target::Rel
    };
    let survivors = rng.range_inclusive(0, 3) as usize;

    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut store = RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");
    let mut model = Model::new();
    let mut next = 1u64;

    // A reltype token for the relationship variant (interning it under the property variant too keeps
    // the id streams identical across targets — harmless, it is simply never referenced there).
    let t_tok = next_txn(&mut next);
    store.begin(t_tok);
    let rel_type = store
        .intern_token(Namespace::RelType, REL_TYPE)
        .expect("intern reltype");
    store.commit(t_tok).expect("commit token");

    // --- Committed node H. ---
    let t_h = next_txn(&mut next);
    store.begin(t_h);
    let (h, _) = store.create_node(t_h).expect("create H");
    store.commit(t_h).expect("commit H");
    model.add_node(h);

    // --- Committed survivors threaded BELOW the churn (committed data a corruption must not lose). ---
    let t_surv = next_txn(&mut next);
    store.begin(t_surv);
    for i in 0..survivors {
        match target {
            Target::Prop => {
                let key = 100 + i as u32;
                let value = 0x1000_0000u64 + i as u64;
                store
                    .add_node_property(t_surv, h, key, INLINE_TAG, value)
                    .expect("survivor property");
                model.add_node_prop(
                    h,
                    PropTriple {
                        key,
                        type_tag: INLINE_TAG,
                        value_inline: value,
                    },
                );
            }
            Target::Rel => {
                let (rid, _) = store
                    .create_rel(t_surv, rel_type, h, h)
                    .expect("survivor relationship");
                model.add_rel(rid, h, h);
            }
        }
    }
    store.commit(t_surv).expect("commit survivors");

    // --- Victim: one more entity we delete + GC to free a physical id P (the head of H's chain). ---
    let t_v = next_txn(&mut next);
    store.begin(t_v);
    let victim_id = match target {
        Target::Prop => store
            .add_node_property(t_v, h, 200, INLINE_TAG, 0x2000_0000)
            .expect("victim property"),
        Target::Rel => {
            store
                .create_rel(t_v, rel_type, h, h)
                .expect("victim relationship")
                .0
        }
    };
    store.commit(t_v).expect("commit victim");

    // Delete the victim (MVCC tombstone), commit.
    let t_del = next_txn(&mut next);
    store.begin(t_del);
    match target {
        Target::Prop => {
            store
                .remove_node_property_value(t_del, h, 200)
                .expect("remove victim property");
        }
        Target::Rel => {
            store
                .delete_rel(t_del, victim_id)
                .expect("delete victim relationship");
        }
    }
    store.commit(t_del).expect("commit delete");

    // GC past the delete: reclaim_* frees id P == victim_id and splices it out of H's chain. Commit
    // persists the free list, so the last DURABLY COMMITTED free list for this store is now `[P]`.
    let t_gc = next_txn(&mut next);
    let watermark = store.snapshot_ts();
    store.begin(t_gc);
    store.gc(t_gc, watermark).expect("gc");
    store.commit(t_gc).expect("commit gc");

    // --- Txn A: allocate on H, popping the freed P; leave A OPEN. ---
    let a = next_txn(&mut next);
    store.begin(a);
    let reused_id = alloc_on_h(&mut store, a, target, rel_type, h, 300, 0x3000_0000);
    let reached_precondition = reused_id == victim_id;

    // --- Txn B: one write, then a LIVE rollback. `reload_catalog` here is what re-lists the durably
    //     committed `[P]` — even though A holds P `in_use` (the bug), or, post-fix, is corrected by the
    //     pre-rollback free-list restore. ---
    let b = next_txn(&mut next);
    store.begin(b);
    let _ = store.create_node(b).expect("B throwaway write");
    store.rollback(b).expect("live rollback B");

    // --- CRITICAL assertion point: while A still holds P, the storage checker must find NO free-list
    //     fault. Pre-fix P is on the free list AND `in_use` -> FreeListFault::StillInUse. ---
    let freelist_fault = first_freelist_fault(&mut store);

    // --- Txn C: allocate on H again. Pre-fix `alloc_id` pops P a SECOND time (the double-alloc that
    //     self-cycles the chain); post-fix the free list is empty so a fresh id is handed out. ---
    let c = next_txn(&mut next);
    store.begin(c);
    let c_allocated_id = alloc_on_h(&mut store, c, target, rel_type, h, 400, 0x4000_0000);
    let double_alloc_averted = c_allocated_id != reused_id;

    // Commit A and C — both are acknowledged, so both belong in the model.
    store.commit(a).expect("commit A");
    store.commit(c).expect("commit C");
    match target {
        Target::Prop => {
            model.add_node_prop(
                h,
                PropTriple {
                    key: 300,
                    type_tag: INLINE_TAG,
                    value_inline: 0x3000_0000,
                },
            );
            model.add_node_prop(
                h,
                PropTriple {
                    key: 400,
                    type_tag: INLINE_TAG,
                    value_inline: 0x4000_0000,
                },
            );
        }
        Target::Rel => {
            model.add_rel(reused_id, h, h);
            model.add_rel(c_allocated_id, h, h);
        }
    }

    ScenarioOutcome {
        store,
        model,
        target,
        survivors,
        reused_id,
        c_allocated_id,
        reached_precondition,
        double_alloc_averted,
        freelist_fault,
    }
}

/// Runs one deterministic free-list-reuse-after-rollback reproduction for `seed` and checks the
/// recovered graph against the reference model.
#[must_use]
pub fn run_freelist_reuse_after_rollback(seed: u64) -> FreelistReuseReport {
    let mut outcome = drive_scenario(seed);
    // Write the committed pages home before the checker's page-checksum pass: a committed-but-unflushed
    // page carries a stale checksum field until write-back, so verifying it warm would false-positive
    // (the cold-open contract, `#426`; the same reason the harness flushes after its post-recovery GC).
    outcome.store.flush().expect("flush before verify");
    let result = checker::verify(&mut outcome.store, &outcome.model);
    FreelistReuseReport {
        seed,
        target: outcome.target,
        survivors: outcome.survivors,
        reused_id: outcome.reused_id,
        c_allocated_id: outcome.c_allocated_id,
        reached_precondition: outcome.reached_precondition,
        double_alloc_averted: outcome.double_alloc_averted,
        freelist_fault: outcome.freelist_fault,
        result,
    }
}

/// Runs the same reproduction, then **crashes** (no-force or steal, seeded) and recovers, asserting
/// the committed graph is reconstructed exactly — proving the `rmp` #578 live-rollback fix does not
/// perturb crash recovery (which rebuilds the free list from the durable catalog independently).
#[must_use]
pub fn run_freelist_reuse_crash(seed: u64) -> FreelistReuseCrashReport {
    let outcome = drive_scenario(seed);
    // Crash kind derived from the seed directly (independent of the scenario's own rng consumption),
    // so the report is a pure function of the seed.
    let steal = seed & 1 == 0;
    let target = outcome.target;
    let reached_precondition = outcome.reached_precondition;
    let double_alloc_averted = outcome.double_alloc_averted;
    let model = outcome.model;

    let store = outcome.store;
    // Harden the committed tail so the crash WAL carries A's and C's committed records.
    store.with_wal(WalManager::flush);
    let (mut store, _losers) = if steal {
        crash_steal(store)
    } else {
        crash_no_force(store)
    };

    let result = checker::verify(&mut store, &model);
    FreelistReuseCrashReport {
        seed,
        target,
        steal,
        reached_precondition,
        double_alloc_averted,
        result,
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
/// any stolen uncommitted pages.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_is_deterministic_and_passes() {
        // Seed 1 exercises the property variant (rng.chance(50) is true for it); seed 2 the rel one.
        for seed in [1u64, 2] {
            let a = run_freelist_reuse_after_rollback(seed);
            let b = run_freelist_reuse_after_rollback(seed);
            assert_eq!(a, b, "seed {seed}: reproduction is not deterministic");
            assert!(
                a.reached_precondition,
                "seed {seed}: A must re-allocate the GC-freed slot P (vacuous otherwise): {a:?}"
            );
            assert!(
                a.passed(),
                "seed {seed} must pass post-fix (no double-alloc, no free-list fault, no cycle): {a:?}"
            );
        }
    }

    #[test]
    fn small_sweep_is_non_vacuous_and_holds() {
        // Proves the reproduction actually reaches its precondition (A re-allocates the freed slot) for
        // every seed and exercises BOTH stores, while asserting the invariants hold. Pre-fix (fix
        // reverted) each seed instead surfaces `FreeListFault::StillInUse` and a `"malformed (cycle?)"`
        // — the teeth are verified empirically by reverting the fix; the large sweep lives in
        // `tests/freelist_reuse_recovery.rs`.
        let mut saw_prop = false;
        let mut saw_rel = false;
        for seed in 1..=400u64 {
            let r = run_freelist_reuse_after_rollback(seed);
            assert!(
                r.reached_precondition,
                "seed {seed}: A must re-allocate the GC-freed slot P (non-vacuity): {r:?}"
            );
            assert!(
                r.freelist_fault.is_none(),
                "seed {seed}: storage checker reported a free-list fault while A held P: {:?}",
                r.freelist_fault
            );
            assert!(
                r.double_alloc_averted,
                "seed {seed}: C re-popped P (double-allocation not averted): {r:?}"
            );
            assert!(
                r.passed(),
                "seed {seed} violated an invariant: {:?}",
                r.result
            );
            match r.target {
                Target::Prop => saw_prop = true,
                Target::Rel => saw_rel = true,
            }
        }
        assert!(saw_prop, "the sweep never exercised the property store");
        assert!(saw_rel, "the sweep never exercised the relationship store");
    }

    #[test]
    fn crash_recovery_is_deterministic_and_holds() {
        // The fix is live-rollback-only, so crash recovery (which rebuilds the free list from the
        // durable catalog) must be byte-identical and continue to reconstruct the committed graph.
        for seed in 1..=200u64 {
            let a = run_freelist_reuse_crash(seed);
            let b = run_freelist_reuse_crash(seed);
            assert_eq!(a, b, "seed {seed}: crash recovery is not deterministic");
            assert!(
                a.reached_precondition,
                "seed {seed}: reproduction did not reach its precondition (vacuous): {a:?}"
            );
            assert!(
                a.passed(),
                "seed {seed}: recovered graph did not equal the model: {:?}",
                a.result
            );
        }
    }
}
