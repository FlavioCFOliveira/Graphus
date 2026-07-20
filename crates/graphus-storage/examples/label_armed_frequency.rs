//! `label_armed_frequency` — measures, on the real [`RecordStore`], how often the
//! [`LabelHistory`] is in the **armed** state (`rmp` #808 Part 1.1). The armed window is what exposes
//! the multi-core read-scaling residual, so this grounds whether a structural fix is worth the risk.
//!
//! # The mechanism (verified by the numbers below)
//!
//! The history arms only on a label change to an **already-committed** node (`SET`/`REMOVE` label in
//! a transaction *later* than the one that created the node). A node labelled in the same transaction
//! that created it retains no version — the store's `track_label_history` skips it — so a pure
//! insert/create workload never arms the gate. The window closes at the next GC prune, whose
//! watermark collapses the settled version into the base and drains the map.
//!
//! Run:
//! ```text
//! cargo run -p graphus-storage --release --example label_armed_frequency
//! ```

use std::time::Instant;

use graphus_core::TxnId;
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 4096, 1).expect("create store")
}

/// A monotonic transaction-id source for the probe.
struct Txns(u64);
impl Txns {
    fn next(&mut self) -> TxnId {
        self.0 += 1;
        TxnId(self.0)
    }
}

fn main() {
    println!("== rmp #808 Part 1.1: how often is LabelHistory armed? ==\n");

    scenario_insert_only();
    scenario_relabel_churn();
    scenario_window_duration();
}

/// Scenario 1 — a create/label-on-create workload NEVER arms the gate.
fn scenario_insert_only() {
    let mut s = fresh();
    let mut txns = Txns(0);
    let label = {
        let t = txns.next();
        s.begin(t);
        let l = s.intern_token(Namespace::Label, "Person").unwrap();
        s.commit(t).unwrap();
        l
    };

    let mut armed_samples = 0u64;
    let n = 5_000;
    for _ in 0..n {
        let t = txns.next();
        s.begin(t);
        let (id, _) = s.create_node(t).unwrap();
        // Label the node IN THE SAME txn that created it: no version retained.
        s.add_label(t, id, label).unwrap();
        s.commit(t).unwrap();
        if s.label_history().any() {
            armed_samples += 1;
        }
    }
    println!("Scenario 1 — insert + label-on-create ({n} txns):");
    println!(
        "  armed after {armed_samples}/{n} commits  =>  {:.1}% of the workload armed\n",
        100.0 * armed_samples as f64 / n as f64
    );
}

/// Scenario 2 — post-commit relabel churn, swept across GC cadence. Armed-fraction is sampled once
/// per operation over the whole stream.
fn scenario_relabel_churn() {
    println!("Scenario 2 — post-commit relabel churn (1000 committed nodes, 20000 ops):");
    println!("  a relabel arms the gate; a GC pass drains it. Armed-fraction vs GC cadence:\n");
    println!(
        "   {:>16}   {:>14}   {:>14}",
        "GC cadence", "armed fraction", "armed windows"
    );

    for &gc_every in &[1usize, 8, 64, 512, usize::MAX] {
        let (frac, windows) = run_relabel_churn(1000, 20_000, gc_every);
        let cadence = if gc_every == usize::MAX {
            "never".to_string()
        } else {
            format!("every {gc_every} ops")
        };
        println!("   {cadence:>16}   {:>13.1}%   {windows:>14}", frac * 100.0);
    }
    println!();
}

/// Builds `pool` committed nodes, then runs `ops` operations: each op relabels a random committed
/// node (toggling a label, in a fresh committed txn) and, every `gc_every` ops, runs a GC prune.
/// Samples `any()` once per op. Returns (armed fraction, number of distinct armed windows).
fn run_relabel_churn(pool: u64, ops: u64, gc_every: usize) -> (f64, u64) {
    let mut s = fresh();
    let mut txns = Txns(0);

    let label_a = {
        let t = txns.next();
        s.begin(t);
        let a = s.intern_token(Namespace::Label, "A").unwrap();
        s.intern_token(Namespace::Label, "B").unwrap();
        s.commit(t).unwrap();
        a
    };

    // Create the committed pool (labelled on create => not armed).
    let mut ids = Vec::with_capacity(pool as usize);
    {
        let t = txns.next();
        s.begin(t);
        for _ in 0..pool {
            let (id, _) = s.create_node(t).unwrap();
            s.add_label(t, id, label_a).unwrap();
            ids.push(id);
        }
        s.commit(t).unwrap();
    }
    assert!(!s.label_history().any(), "pool build must not arm");

    // A cheap deterministic PRNG (xorshift) so the run is reproducible.
    let mut rng: u64 = 0x9e37_79b9_7f4a_7c15;
    let next_rand = |rng: &mut u64| {
        *rng ^= *rng << 13;
        *rng ^= *rng >> 7;
        *rng ^= *rng << 17;
        *rng
    };

    let mut armed_samples = 0u64;
    let mut windows = 0u64;
    let mut was_armed = false;
    for op in 0..ops {
        // Relabel a random committed node: toggle a label bit in a NEW committed txn (arms the gate).
        let node = ids[(next_rand(&mut rng) as usize) % ids.len()];
        let t = txns.next();
        s.begin(t);
        // Toggle: remove A if present else add A (either is a real committed-node relabel).
        if s.node_has_label(node, label_a).unwrap() {
            s.remove_label(t, node, label_a).unwrap();
        } else {
            s.add_label(t, node, label_a).unwrap();
        }
        s.commit(t).unwrap();

        if gc_every != usize::MAX && (op as usize + 1) % gc_every == 0 {
            let wm = s.snapshot_ts();
            let t = txns.next();
            s.begin(t);
            s.gc(t, wm).unwrap();
            s.commit(t).unwrap();
        }

        let armed = s.label_history().any();
        if armed {
            armed_samples += 1;
        }
        if armed && !was_armed {
            windows += 1;
        }
        was_armed = armed;
    }
    (armed_samples as f64 / ops as f64, windows)
}

/// Scenario 3 — the wall-time an armed window lasts, from the relabel commit to the GC that drains
/// it, for a range of how much unrelated work sits between them.
fn scenario_window_duration() {
    println!("Scenario 3 — armed-window wall-time (relabel commit -> draining GC):");
    for &gap_ops in &[0u64, 100, 1000, 10_000] {
        let ns = measure_window(1000, gap_ops);
        println!(
            "   {gap_ops:>6} unrelated ops between relabel and GC  =>  armed for {:>10.1} µs",
            ns / 1000.0
        );
    }
    println!(
        "\n  (The window is bounded by GC cadence, not by the fix. The residual only bites while a\n   \
         window is open AND multiple reader threads scan concurrently.)"
    );
}

/// Arms the gate with one committed relabel, does `gap_ops` unrelated committed creates, then runs a
/// draining GC. Returns the wall-time (ns) the gate stayed armed.
fn measure_window(pool: u64, gap_ops: u64) -> f64 {
    let mut s = fresh();
    let mut txns = Txns(0);
    let label_a = {
        let t = txns.next();
        s.begin(t);
        let a = s.intern_token(Namespace::Label, "A").unwrap();
        s.commit(t).unwrap();
        a
    };
    let mut ids = Vec::new();
    {
        let t = txns.next();
        s.begin(t);
        for _ in 0..pool {
            let (id, _) = s.create_node(t).unwrap();
            ids.push(id);
        }
        s.commit(t).unwrap();
    }

    // Arm: relabel a committed node.
    let t = txns.next();
    s.begin(t);
    s.add_label(t, ids[0], label_a).unwrap();
    s.commit(t).unwrap();
    assert!(s.label_history().any());
    let start = Instant::now();

    // Unrelated committed work while the window stays open.
    for _ in 0..gap_ops {
        let t = txns.next();
        s.begin(t);
        s.create_node(t).unwrap();
        s.commit(t).unwrap();
    }

    // Draining GC.
    let wm = s.snapshot_ts();
    let t = txns.next();
    s.begin(t);
    s.gc(t, wm).unwrap();
    s.commit(t).unwrap();
    let elapsed = start.elapsed().as_nanos() as f64;
    assert!(!s.label_history().any(), "GC must drain the window");
    elapsed
}
