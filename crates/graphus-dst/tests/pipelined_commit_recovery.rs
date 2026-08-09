//! Deterministic crash-recovery sweep for **commit pipelining** (`rmp` #532): a committed write
//! driven through the *pipelined* group-commit harden path
//! ([`RecordStore::commit_prepare`] → [`RecordStore::begin_harden_wal`] → run the offloaded
//! `fdatasync` → [`RecordStore::complete_harden_wal`]) must recover to **exactly** the committed
//! state — bit-identically to the inline [`RecordStore::harden_wal`] path — and a batch that was
//! PREPAREd but crashed **before** its harden must be lost **whole** (never partially applied).
//!
//! ## Why this is the right DST scenario
//!
//! Pipelining splits the group-commit harden in two: `begin_harden` writes a batch's records to the
//! log and returns a deferred `fdatasync` (offloaded to a dedicated thread), then `complete_harden`
//! advances the durable watermark once that `fdatasync` has run — with the engine PREPAREing the next
//! batch in between (depth-1: at most one batch written-but-un-synced). The design's inviolable claim
//! is that this leaves the **same category** of on-disk crash state as inline group commit, so crash
//! recovery is unchanged. This sweep proves that over the DST oracle, exercising the exact production
//! store methods on the deterministic [`MemLogSink`] (whose default `begin_harden` hardens inline — the
//! DST/replay path, bit-identical to `flush`), across both crash modes and many interleavings.
//!
//! What this pins:
//!  1. A write **fully** driven through the pipeline (PREPARE → begin_harden → run job →
//!     complete_harden) is committed-durable and **survives** the crash, in both crash modes.
//!  2. A **write loser** left in flight at the crash (its data records hardened into the crash WAL but
//!     never committed) is **undone** by recovery — never partially applied.
//!
//! (The complementary "an un-hardened PREPARE is lost WHOLE" property is pinned at the pure-WAL level
//! by `graphus_wal`'s `crash_mid_batch_recovers_only_the_hardened_prefix` and
//! `pipelined_harden_is_byte_identical_to_flush`; it cannot be modelled through the RecordStore
//! **steal** path here, because the steal `flush` legitimately hardens the WAL through every dirty
//! page's LSN — including a pending PREPARE — to honour WAL-before-data.)
//!
//! The recover / reopen / [`checker::verify`]-against-[`Model`] shape mirrors the other recovery soaks.

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
const INLINE_TAG: u8 = 2;

/// Commits `txn` through the **pipelined** group-commit path — the production `rmp` #532 sequence:
/// PREPARE (append `COMMIT`, no `fdatasync`) → `begin_harden` (write the batch to the log, return the
/// deferred fsync) → run the offloaded `fdatasync` → `complete_harden` (advance the durable
/// watermark). Over `MemLogSink` the `begin_harden` hardens inline and the job is a no-op, so this is
/// byte-identical to the inline `commit`, exactly as it is for DST replay.
fn pipelined_commit(store: &mut Store, txn: TxnId) {
    let _lsn = store.commit_prepare(txn).expect("commit_prepare");
    let job = store.begin_harden_wal();
    let target = job.target_len();
    job.run().expect("offloaded fdatasync");
    store.complete_harden_wal(target);
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PipelineRecoveryReport {
    seed: u64,
    result: std::result::Result<(), CheckFailure>,
    committed_writes: usize,
    /// Whether an in-flight WRITE loser was left at the crash (must be undone by recovery).
    write_loser_at_crash: bool,
    recovery_losers: usize,
    steal: bool,
}

fn next_txn(next: &mut u64) -> TxnId {
    let id = TxnId(*next);
    *next += 1;
    id
}

fn run_pipeline_recovery(seed: u64) -> PipelineRecoveryReport {
    let mut rng = DetRng::new(seed);
    let steal = rng.chance(50);

    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut store = RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");

    let mut next = 1u64;
    let mut model = Model::new();

    // --- Committed base graph via the pipelined path. ---
    let setup = next_txn(&mut next);
    store.begin(setup);
    let link = store
        .intern_token(Namespace::RelType, "LINK")
        .expect("intern rel type");
    let key = store
        .intern_token(Namespace::PropKey, "v")
        .expect("intern prop key");
    let node_count = rng.range_inclusive(2, 5) as usize;
    let mut nodes = Vec::with_capacity(node_count);
    for _ in 0..node_count {
        let (id, _) = store.create_node(setup).expect("create_node");
        nodes.push(id);
    }
    pipelined_commit(&mut store, setup);
    for &n in &nodes {
        model.add_node(n);
    }

    // --- A run of committed write transactions, each hardened through the pipeline. This is the
    //     committed data a crash must never lose. ---
    let mut committed_writes = 1usize; // the setup
    let write_txns = rng.range_inclusive(2, 6) as usize;
    for _ in 0..write_txns {
        let t = next_txn(&mut next);
        store.begin(t);
        let ops = rng.range_inclusive(1, 4);
        for _ in 0..ops {
            if rng.chance(50) {
                let s = nodes[rng.index(nodes.len())];
                let e = nodes[rng.index(nodes.len())]; // equal ⇒ self-loop
                let (rid, _) = store.create_rel(t, link, s, e).expect("create_rel");
                model.add_rel(rid, s, e);
            } else {
                let n = nodes[rng.index(nodes.len())];
                let value = 0x1000 + rng.range_inclusive(0, 0xFF);
                store
                    .add_node_property(t, n, key, INLINE_TAG, value)
                    .expect("add_node_property");
                model.add_node_prop(
                    n,
                    PropTriple {
                        key,
                        type_tag: INLINE_TAG,
                        value_inline: value,
                    },
                );
            }
        }
        pipelined_commit(&mut store, t);
        committed_writes += 1;
    }

    // --- Optionally an in-flight WRITE loser: left uncommitted at the crash (recovery undoes it). It
    //     appends data records (no `COMMIT`), which are hardened into the crash WAL below so recovery
    //     redoes then undoes them — the loser's uncommitted change must NOT survive. ---
    let write_loser_at_crash = rng.chance(70);
    if write_loser_at_crash {
        let loser_in_flight = next_txn(&mut next);
        store.begin(loser_in_flight);
        let n = nodes[rng.index(nodes.len())];
        let _ = store
            .add_node_property(loser_in_flight, n, key, INLINE_TAG, 0xDEAD)
            .expect("loser prop");
        // NOT added to the model, and NOT committed: recovery must undo it whole.
    }
    // Harden the tail so any in-flight loser's records are in the crash WAL (recovery redoes+undoes).
    store.with_wal(WalManager::flush);

    let (store, recovery_losers) = if steal {
        crash_steal(store)
    } else {
        crash_no_force(store)
    };

    let result = checker::verify(&store, &model);

    PipelineRecoveryReport {
        seed,
        result,
        committed_writes,
        write_loser_at_crash,
        recovery_losers,
        steal,
    }
}

/// No-force crash: rebuild onto a fresh empty device from the durable WAL prefix (dropping the
/// un-synced tail), then reopen.
fn crash_no_force(store: Store) -> (Store, usize) {
    // `durable_bytes()` is exactly the fdatasync'd prefix; an un-hardened PREPARE is not in it (the
    // power-loss model — its `COMMIT` record never became durable), so recovery never sees it.
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
fn crash_steal(store: Store) -> (Store, usize) {
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

const SEEDS: u64 = 2_000;

#[test]
fn pipelined_commits_recover_committed_or_nothing_across_many_seeds() {
    let mut steal_seen = false;
    let mut no_force_seen = false;
    let mut write_loser_seen = false;

    for seed in 1..=SEEDS {
        let report = run_pipeline_recovery(seed);

        assert!(
            report.result.is_ok(),
            "seed {seed} [{}]: pipelined-commit recovery lost/created committed state or broke \
             integrity: {:?}\ncommitted_writes={} write_loser={} recovery_losers={}",
            if report.steal { "steal" } else { "no-force" },
            report.result,
            report.committed_writes,
            report.write_loser_at_crash,
            report.recovery_losers,
        );

        // Determinism: the same seed reproduces the identical report (byte-identical replay).
        let again = run_pipeline_recovery(seed);
        assert_eq!(report, again, "seed {seed} is not deterministic");

        steal_seen |= report.steal;
        no_force_seen |= !report.steal;
        write_loser_seen |= report.write_loser_at_crash;
    }

    assert!(steal_seen, "sweep never exercised the steal crash mode");
    assert!(
        no_force_seen,
        "sweep never exercised the no-force crash mode"
    );
    assert!(
        write_loser_seen,
        "sweep never left an in-flight write loser at the crash"
    );
}
