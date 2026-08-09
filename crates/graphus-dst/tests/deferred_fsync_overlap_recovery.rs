//! Deterministic crash-recovery sweep for the **deferred-fsync overlap window** of commit pipelining
//! (`rmp` #554 — the DST-fidelity counterpart of #532).
//!
//! ## The fidelity gap this closes
//!
//! The production commit path [`pipelined_group_commit`] is a **depth-1 pipeline**: `begin_harden` writes
//! batch *K*'s records to the WAL file — advancing the *write* frontier — and returns a deferred
//! `fdatasync` offloaded to a dedicated thread; the engine then PREPAREs the next batch WHILE that
//! `fdatasync` is in flight; only afterwards does it wait for the sync, advance `durable_len`, and ack.
//! So there is a real crash window where **`durable_len < written_len`**: a batch's records are *written
//! to the WAL but not yet `fdatasync`'d*.
//!
//! The sibling sweep `pipelined_commit_recovery` drives each commit through the pipeline API, but over the
//! **default** [`MemLogSink`] `begin_harden` hardens *inline* (returns an `already_durable` no-op job), so
//! the un-synced overlap state **never exists in the sink at crash time** — DST could not represent it.
//! `MemLogSink::with_deferred_harden()` (`rmp` #554) fixes exactly that: it models the write frontier
//! (`written`) as a region between the durable `tail` and the not-yet-written `pending`, excluded from
//! `durable_len`/`durable_bytes` and dropped whole by `crash()`.
//!
//! ## What this pins
//!
//! Driving a genuinely pipelined sequence in deferred mode and crashing IN the overlap window, across many
//! seeds and both crash modes, this asserts **committed-or-nothing**:
//!
//!  1. A batch whose deferred harden **completed** (`complete_harden` ran → durable) **survives** the
//!     crash, whole.
//!  2. A batch left **written-but-un-synced** at a power-loss (**no-force**) crash — its records in the
//!     WAL file but its `fdatasync` never completed — is **lost WHOLE** (never partially applied). The
//!     durable image (`durable_bytes()`) excludes it, exactly as a power loss drops the un-`fdatasync`'d
//!     tail.
//!  3. Under a **steal** crash, a dirty home page can only be written after the WAL-before-data rule
//!     (`ensure_durable` → inline `sync`) hardens the written-but-un-synced range through that page's LSN;
//!     so the batch's records — and its `COMMIT` — become durable and the batch legitimately **survives**.
//!     This proves WAL-before-data holds in the deferred window (the Defect-B guarantee, now at the DST /
//!     store level).
//!
//! Two overlap shapes are covered explicitly (the task's required cases): *K durable but K+1
//! written-but-un-synced* (a crash between the two — depths 1 and 2), and *neither durable* (a crash with
//! both K and K+1 in the written frontier).
//!
//! The production engine loop is strictly **depth-1** (it `complete_harden`s K before `begin_harden`ing
//! K+1), so `written` never holds two batches there today; `KDurableDepth1` models that path exactly. The
//! depth-2 modes (`NeitherDepth2`/`KDurableDepth2`) deliberately stress the sink primitive *beyond* the
//! current depth-1 loop — a defensible superset that future-proofs a deeper pipeline and exercises the
//! monotonic prefix-promotion of `complete_harden` — while producing neither false confidence nor false
//! failures (all seeds recover committed-or-nothing).
//!
//! The oracle is the same `checker::verify`-against-[`Model`] shape as the other recovery soaks: the model
//! contains **only** the batches that are durable at the crash, so if `durable_bytes()` wrongly kept the
//! un-synced tail the recovered store would contain an uncommitted batch's mutation on a model node and
//! the checker would report the mismatch. The dedicated `..._is_a_genuine_oracle` test makes that teeth
//! explicit: recovering from the (incorrect) image that *includes* the un-synced tail MUST diverge from
//! the model, proving the sweep genuinely detects a leaked overlap tail.
//!
//! [`pipelined_group_commit`]: (see `graphus-server`'s engine)

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

/// The overlap sequencing at the crash. All three end with batch **K+1** written-but-un-synced; A and C
/// additionally make batch **K** durable (via `complete_harden`) before the crash, B makes neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverlapMode {
    /// begin_harden K → complete K (durable) → begin_harden K+1 → crash. (depth-1: K durable, K+1 un-synced)
    KDurableDepth1,
    /// begin_harden K → begin_harden K+1 → crash. (depth-2: neither durable)
    NeitherDepth2,
    /// begin_harden K → begin_harden K+1 → complete K (prefix-promote) → crash. (depth-2: K durable, K+1 un-synced)
    KDurableDepth2,
}

/// A mutation applied by an overlap batch, recorded so it can be conditionally added to the model
/// depending on whether that batch ends up durable at the crash.
#[derive(Debug, Clone, Copy)]
enum Op {
    Rel { rid: u64, start: u64, end: u64 },
    Prop { node: u64, triple: PropTriple },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OverlapReport {
    seed: u64,
    steal: bool,
    mode: OverlapMode,
    /// Whether batch K was made durable (`complete_harden`) before the crash.
    k_completed: bool,
    /// Whether batch K ends up in the committed model (durable at crash).
    k_in_model: bool,
    /// Whether batch K+1 ends up in the committed model (durable at crash — only under steal).
    kp1_in_model: bool,
    /// The size of the written-but-un-synced frontier at the crash (`buffered_len - durable_len`),
    /// measured **before** the crash. Must be `> 0` — proof the overlap window was genuinely present.
    window_len: u64,
    recovery_losers: usize,
    result: std::result::Result<(), CheckFailure>,
}

fn next_txn(next: &mut u64) -> TxnId {
    let id = TxnId(*next);
    *next += 1;
    id
}

/// Commits `txn` through a **fully-completed** pipelined harden: PREPARE → begin_harden (write frontier)
/// → run the offloaded (no-op) `fdatasync` → complete_harden (advance the durable watermark). Over the
/// deferred `MemLogSink` this promotes the batch's `written` frontier into the durable `tail`, so the
/// batch is committed-durable. Used to build the committed base the crash must never lose.
fn pipelined_commit_full(store: &mut Store, txn: TxnId) {
    let _lsn = store.commit_prepare(txn).expect("commit_prepare");
    let job = store.begin_harden_wal();
    let target = job.target_len();
    job.run().expect("offloaded fdatasync");
    store.complete_harden_wal(target);
}

/// Applies a random 1..=3-op write transaction to the store (rels and/or props on existing model nodes)
/// and PREPAREs it (appends its `COMMIT`, no `fdatasync`). Returns the ops so the caller can conditionally
/// reflect them in the model. Does NOT harden — the caller drives begin_harden/complete to shape the
/// overlap window.
fn prepare_overlap_txn(
    store: &mut Store,
    rng: &mut DetRng,
    nodes: &[u64],
    link: u32,
    key: u32,
    txn: TxnId,
) -> Vec<Op> {
    store.begin(txn);
    let mut ops = Vec::new();
    let n_ops = rng.range_inclusive(1, 3);
    for _ in 0..n_ops {
        if rng.chance(50) {
            let start = nodes[rng.index(nodes.len())];
            let end = nodes[rng.index(nodes.len())]; // equal ⇒ self-loop
            let (rid, _) = store.create_rel(txn, link, start, end).expect("create_rel");
            ops.push(Op::Rel { rid, start, end });
        } else {
            let node = nodes[rng.index(nodes.len())];
            let value = 0x2000 + rng.range_inclusive(0, 0xFF);
            store
                .add_node_property(txn, node, key, INLINE_TAG, value)
                .expect("add_node_property");
            ops.push(Op::Prop {
                node,
                triple: PropTriple {
                    key,
                    type_tag: INLINE_TAG,
                    value_inline: value,
                },
            });
        }
    }
    let _lsn = store
        .commit_prepare(txn)
        .expect("commit_prepare overlap batch");
    ops
}

/// Reflects a batch's ops into the model — called only when the batch is durable at the crash.
fn apply_ops_to_model(model: &mut Model, ops: &[Op]) {
    for &op in ops {
        match op {
            Op::Rel { rid, start, end } => model.add_rel(rid, start, end),
            Op::Prop { node, triple } => model.add_node_prop(node, triple),
        }
    }
}

fn run_deferred_overlap_recovery(seed: u64) -> OverlapReport {
    let mut rng = DetRng::new(seed);
    let steal = rng.chance(50);
    let mode = match rng.range_inclusive(0, 2) {
        0 => OverlapMode::KDurableDepth1,
        1 => OverlapMode::NeitherDepth2,
        _ => OverlapMode::KDurableDepth2,
    };
    let k_completed = matches!(
        mode,
        OverlapMode::KDurableDepth1 | OverlapMode::KDurableDepth2
    );

    // A batch is durable at the crash if its `complete_harden` ran (K in A/C) OR a steal crash forced the
    // written range durable via WAL-before-data (both K and K+1).
    let k_in_model = k_completed || steal;
    let kp1_in_model = steal;

    let device = MemBlockDevice::new(0);
    // DEFERRED-harden sink: `begin_harden` writes the batch to the WAL write frontier WITHOUT syncing, so
    // the crash can happen with `durable_len < written_len` — the fidelity this test adds (`rmp` #554).
    let wal = WalManager::create(MemLogSink::with_deferred_harden()).expect("create wal");
    let mut store = RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");

    let mut next = 1u64;
    let mut model = Model::new();

    // --- Committed base graph (fully hardened → durable). ---
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
    pipelined_commit_full(&mut store, setup);
    for &n in &nodes {
        model.add_node(n);
    }

    // --- A run of committed writes, each fully hardened through the pipeline (durable). ---
    let write_txns = rng.range_inclusive(1, 4) as usize;
    for _ in 0..write_txns {
        let t = next_txn(&mut next);
        let ops = prepare_overlap_txn(&mut store, &mut rng, &nodes, link, key, t);
        pipelined_commit_full(&mut store, t);
        apply_ops_to_model(&mut model, &ops);
    }

    // --- The OVERLAP window: batch K then batch K+1, both PREPAREd and begin_harden'd (written to the WAL
    //     write frontier) but at least K+1 left with its deferred `fdatasync` INCOMPLETE at the crash. ---
    let txn_k = next_txn(&mut next);
    let txn_kp1 = next_txn(&mut next);

    let k_ops;
    let kp1_ops;
    match mode {
        OverlapMode::KDurableDepth1 => {
            // begin_harden K → complete K → begin_harden K+1 → crash.
            k_ops = prepare_overlap_txn(&mut store, &mut rng, &nodes, link, key, txn_k);
            let job_k = store.begin_harden_wal();
            let target_k = job_k.target_len();
            job_k.run().expect("offloaded fdatasync K");
            store.complete_harden_wal(target_k); // K durable
            kp1_ops = prepare_overlap_txn(&mut store, &mut rng, &nodes, link, key, txn_kp1);
            let _job_kp1 = store.begin_harden_wal(); // K+1 written, un-synced (job dropped: crash interrupts)
        }
        OverlapMode::NeitherDepth2 => {
            // begin_harden K → begin_harden K+1 → crash (neither completed).
            k_ops = prepare_overlap_txn(&mut store, &mut rng, &nodes, link, key, txn_k);
            let _job_k = store.begin_harden_wal();
            kp1_ops = prepare_overlap_txn(&mut store, &mut rng, &nodes, link, key, txn_kp1);
            let _job_kp1 = store.begin_harden_wal();
        }
        OverlapMode::KDurableDepth2 => {
            // begin_harden K → begin_harden K+1 → complete K (prefix-promote) → crash.
            k_ops = prepare_overlap_txn(&mut store, &mut rng, &nodes, link, key, txn_k);
            let job_k = store.begin_harden_wal();
            let target_k = job_k.target_len();
            kp1_ops = prepare_overlap_txn(&mut store, &mut rng, &nodes, link, key, txn_kp1);
            let _job_kp1 = store.begin_harden_wal();
            job_k.run().expect("offloaded fdatasync K");
            store.complete_harden_wal(target_k); // K durable via prefix promotion; K+1 stays un-synced
        }
    }

    // The overlap window is genuinely present in the sink: records written but not yet durable.
    let window_len = store.with_wal(|w| w.sink().buffered_len() - w.sink().durable_len());

    // Reflect into the model only the batches that are durable at the crash.
    if k_in_model {
        apply_ops_to_model(&mut model, &k_ops);
    }
    if kp1_in_model {
        apply_ops_to_model(&mut model, &kp1_ops);
    }

    let (mut store, recovery_losers) = if steal {
        crash_steal_deferred(store)
    } else {
        crash_no_force_deferred(store)
    };

    let result = checker::verify(&mut store, &model);

    OverlapReport {
        seed,
        steal,
        mode,
        k_completed,
        k_in_model,
        kp1_in_model,
        window_len,
        recovery_losers,
        result,
    }
}

/// Power-loss (**no-force**) crash: take the durable prefix (`durable_bytes()` EXCLUDES the
/// written-but-un-synced frontier — the un-`fdatasync`'d overlap tail is dropped), rebuild onto a fresh
/// empty device from that prefix, and reopen. No pre-crash `flush` — flushing would harden the written
/// frontier and destroy the very overlap window under test.
fn crash_no_force_deferred(store: Store) -> (Store, usize) {
    let log = store.with_wal(|w| w.sink().durable_bytes());
    let mut sink = MemLogSink::new(); // the recovered log is an ordinary (inline) sink
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    let report = recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    let store = RecordStore::open(device, wal, POOL_CAPACITY).expect("open store");
    (store, report.losers)
}

/// **Steal** crash: flush dirty pages home. Each home write enforces WAL-before-data — an eviction whose
/// page LSN is in the written-but-un-synced window hardens that range inline (`ensure_durable` → `sync`),
/// so the overlap batches' records (and `COMMIT`s) become durable. Snapshot the on-disk image + the (now
/// complete) durable log, then recover.
fn crash_steal_deferred(store: Store) -> (Store, usize) {
    store.flush().expect("flush (steal)");
    let pages = store.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    for p in &pages {
        let bytes = store.read_device_page(*p).expect("read device page");
        device.write_page(PageId(p.0), &bytes).expect("stage page");
    }
    device.sync_all().expect("persist disk image");

    let log = store.with_wal(|w| w.sink().durable_bytes());
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
fn deferred_fsync_overlap_recovers_committed_or_nothing_across_many_seeds() {
    let mut steal_seen = false;
    let mut no_force_seen = false;
    let mut mode_seen = [false; 3];
    let mut k_durable_kp1_unsynced_seen = false; // the "K durable, K+1 written-but-un-synced" case (no-force)
    let mut neither_durable_seen = false; // the "neither durable" case (no-force)

    for seed in 1..=SEEDS {
        let report = run_deferred_overlap_recovery(seed);

        assert!(
            report.result.is_ok(),
            "seed {seed} [{}] mode {:?}: deferred-fsync overlap recovery violated committed-or-nothing: \
             {:?}\nk_completed={} k_in_model={} kp1_in_model={} window_len={} recovery_losers={}",
            if report.steal { "steal" } else { "no-force" },
            report.mode,
            report.result,
            report.k_completed,
            report.k_in_model,
            report.kp1_in_model,
            report.window_len,
            report.recovery_losers,
        );

        // The overlap window was genuinely present — the exact fidelity DST lacked before #554.
        assert!(
            report.window_len > 0,
            "seed {seed}: the written-but-un-synced overlap window was empty (fidelity not exercised)"
        );

        // Determinism: the same seed reproduces the identical report (byte-identical replay).
        let again = run_deferred_overlap_recovery(seed);
        assert_eq!(report, again, "seed {seed} is not deterministic");

        steal_seen |= report.steal;
        no_force_seen |= !report.steal;
        let mode_idx = match report.mode {
            OverlapMode::KDurableDepth1 => 0,
            OverlapMode::NeitherDepth2 => 1,
            OverlapMode::KDurableDepth2 => 2,
        };
        mode_seen[mode_idx] = true;
        if !report.steal {
            if report.k_in_model && !report.kp1_in_model {
                k_durable_kp1_unsynced_seen = true;
            }
            if !report.k_in_model && !report.kp1_in_model {
                neither_durable_seen = true;
            }
        }
    }

    assert!(steal_seen, "sweep never exercised the steal crash mode");
    assert!(
        no_force_seen,
        "sweep never exercised the no-force crash mode"
    );
    assert!(
        mode_seen.iter().all(|&s| s),
        "sweep did not exercise all three overlap modes: {mode_seen:?}"
    );
    assert!(
        k_durable_kp1_unsynced_seen,
        "sweep never crashed with K durable but K+1 written-but-un-synced (no-force)"
    );
    assert!(
        neither_durable_seen,
        "sweep never crashed with neither batch durable (no-force)"
    );
}

/// The sweep is a **genuine oracle** for the dropped overlap tail: recovery from `durable_bytes()` (which
/// EXCLUDES the written-but-un-synced tail) matches the committed-or-nothing model, but recovery from the
/// **incorrect** image that *includes* that tail (`durable_bytes()` ++ `unsynced_written_bytes()`) MUST
/// diverge from the model. This proves the sweep would FAIL if `durable_bytes()` wrongly kept the tail.
#[test]
fn deferred_fsync_overlap_dropped_tail_is_a_genuine_oracle() {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::with_deferred_harden()).expect("create wal");
    let mut store = RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");

    // Two durable base nodes.
    let setup = TxnId(1);
    store.begin(setup);
    let key = store
        .intern_token(Namespace::PropKey, "v")
        .expect("intern prop key");
    let (n0, _) = store.create_node(setup).expect("create_node");
    let (n1, _) = store.create_node(setup).expect("create_node");
    pipelined_commit_full(&mut store, setup);

    let mut model = Model::new();
    model.add_node(n0);
    model.add_node(n1);

    // An overlap batch K+1 with a VISIBLE mutation on a model node (a property on n0), written to the WAL
    // write frontier but left with its deferred `fdatasync` INCOMPLETE — the un-synced overlap tail.
    let sentinel = 0xBEEF;
    let txn = TxnId(2);
    store.begin(txn);
    store
        .add_node_property(txn, n0, key, INLINE_TAG, sentinel)
        .expect("add_node_property");
    let _lsn = store.commit_prepare(txn).expect("commit_prepare");
    let _job = store.begin_harden_wal(); // written, NOT completed (job dropped)

    // Snapshot both the CORRECT durable image (excludes the tail) and the un-synced tail bytes.
    let correct_image = store.with_wal(|w| w.sink().durable_bytes());
    let unsynced_tail = store.with_wal(|w| w.sink().unsynced_written_bytes());
    assert!(
        !unsynced_tail.is_empty(),
        "the overlap tail must be non-empty for this oracle to have teeth"
    );

    // (1) Correct recovery — from `durable_bytes()`, which DROPS the tail — matches the model (no prop).
    {
        let mut recovered = recover_from_image(&correct_image);
        assert!(
            checker::verify(&mut recovered, &model).is_ok(),
            "correct recovery (tail dropped) must match the committed-or-nothing model"
        );
        // n0 has NO property — the un-synced batch was lost whole.
        let props = recovered
            .superset_scan_node_properties(n0)
            .expect("superset_scan_node_properties");
        assert!(
            props.is_empty(),
            "the written-but-un-synced property must NOT survive a power-loss crash"
        );
    }

    // (2) BUGGY recovery — from an image that WRONGLY includes the un-synced tail — MUST diverge from the
    //     model (n0 gains the uncommitted sentinel property → PropMismatch). This is the teeth: were
    //     `durable_bytes()` to keep the overlap tail, the sweep's committed-or-nothing check would fire.
    {
        let mut buggy_image = correct_image.clone();
        buggy_image.extend_from_slice(&unsynced_tail);
        let mut recovered = recover_from_image(&buggy_image);
        let verdict = checker::verify(&mut recovered, &model);
        assert!(
            matches!(verdict, Err(CheckFailure::PropMismatch { node, .. }) if node == n0),
            "recovery from an image that KEPT the un-synced overlap tail must be caught by the checker \
             (expected PropMismatch on n0), got {verdict:?}"
        );
    }
}

/// Rebuilds a store by recovering `image` (a full durable WAL byte stream) onto a fresh empty device.
fn recover_from_image(image: &[u8]) -> Store {
    let mut sink = MemLogSink::new();
    sink.append(image);
    sink.sync().expect("sync image");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    let _ = recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, POOL_CAPACITY).expect("open store")
}
