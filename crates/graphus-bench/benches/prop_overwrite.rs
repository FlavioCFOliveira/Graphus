//! Property-write cost as a function of chain length (`rmp` #967, acceptance criteria 1 and 2).
//!
//! # The subject
//!
//! **The mechanism #967 retired.** Writing a property used not to replace the version:
//! `RecordStore::set_node_property_value` (`graphus-storage/src/store.rs`) first called
//! `tombstone_props_for_key`, which walked the entity's **whole** `first_prop` chain stamping `xmax`
//! on the live version of that key, and then prepended a fresh version onto the head of the same
//! chain. The chain therefore grew by one record per write and every write walked everything written
//! before it, so M writes to one entity cost `Θ(M²)` in total and `Θ(M)` each. The read followed:
//! `decision_scan_node_properties` read every record in the chain (`read_view::collect_prop_chain`)
//! and only then folded visibility.
//!
//! Note where that cost actually came from: `tombstone_props_for_key` walked the whole chain
//! *regardless of the key filter*. That is why this harness measures two key shapes, and why only
//! one of them was a defect — see "The positive control" below.
//!
//! **The mechanism in place now** (`D-property-removal`, `D-property-visibility`): the newest value
//! is written **in place** into the key's own cell, and the value it displaced descends onto the
//! *owning entity's* undo chain as a `SetProperty` delta. The property chain holds exactly one cell
//! per key and does not grow with overwrites, so a same-key overwrite is `O(1)`; the read resolves
//! the visible value from the in-place image and stops at the first delta its snapshot already
//! reflects (`read_view::decide_properties`), so a reader that sees the live version touches one
//! record per store no matter how long the history is.
//!
//! This harness is what decides between those two statements empirically, and it is kept after the
//! migration for the same reason it was written before it: it is the instrument that would detect
//! the walk coming back.
//!
//! # The four arms
//!
//! Two dimensions, crossed, because the design review established that they are not equivalent.
//!
//! **Transaction shape** — how the M writes are distributed over transactions:
//!
//! * `txn/op` — one transaction per write. This is the production shape:
//!   `graphus-server/src/engine/bulk_load.rs:409-455` (`checkpoint_sentinel`) rewrites the same four
//!   keys on one sentinel node once per import batch, in the batch's own transaction, so a long
//!   import walks a chain that grows for the whole import.
//! * `1 txn` — all M writes inside a single transaction. Isolates the chain walk from every
//!   per-commit cost, and is the shape a large `SET` in one statement produces.
//!
//! **Key shape** — which key each write targets:
//!
//! * `same key` — every write overwrites one key. **The subject.** After #967 the entity holds
//!   exactly one live version of that key, so the per-write cost must become constant.
//! * `distinct keys` — every write targets a fresh key. **The positive control.**
//!
//! ## The positive control, and why the harness would be worthless without it
//!
//! With M distinct keys the entity genuinely holds M live properties. No representation can make
//! "touch an entity with M properties" cheaper than `O(M)` in general, so this arm is *expected* to
//! keep growing after #967. It exists to prove the instrument can still detect growth: a benchmark
//! that reports "flat" both before and after has not demonstrated an improvement, it has
//! demonstrated that it stopped measuring. A valid #967 result is `same key` flat **and**
//! `distinct keys` still growing, in the same run, from the same harness.
//!
//! Before #967 both arms grew, because the chain walk ignored the key filter; that was the expected
//! BEFORE reading and was not itself the finding. After #967 the `distinct keys` arm still grows —
//! see "The measured result" below, where it is the reason the flat SUBJECT arm means anything.
//!
//! # What each column means
//!
//! | column | meaning |
//! |---|---|
//! | `set µs/op` | mean over the ramp of **`set_node_property_value` alone** — the call #967 changes. `begin`/`commit` are outside the timer. The headline number. |
//! | `txn µs/op` | mean over the ramp of the whole transaction cost, amortised per write (`1 txn`: the single `begin`+`commit` spread over M). The gap to `set µs/op` is commit-side cost, which #967 does not touch; reporting both stops the headline number absorbing it. |
//! | `d1`, `d10` | mean per-op `set` cost of the **first** and **last** tenth of the ramp. |
//! | `d10/d1` | growth *within a single run*. The first tenth walks a mean chain of `M/20`, the last tenth `19M/20`, so for a cost that is purely linear in chain length this ratio tends to **19**, approaching it from below as M grows and the fixed per-write cost dilutes. `≈1` means the walk is gone. |
//! | `read µs` | mean latency of one visible-property read at the final chain length. |
//! | `cells` | live `props.store` cells after the ramp — a non-vacuity control, asserted `== 1` for `same key` and `== M` for `distinct keys`. |
//! | `deltas` | undo-chain length after the ramp — the other half of the control, asserted `>= M`: the M old values must still be retained somewhere. |
//! | `prop/undo/commit` | record reads in `props.store` / `undo.store` / `commit.store` to serve **one** visible-property read (`--features read-probe`). |
//!
//! Two independent readings of the same claim, so neither has to be taken on faith:
//!
//! * **Across rows.** With per-op cost linear in chain length, the *mean* per-op cost over a ramp
//!   from 0 to M is `c·M/2`, so `set µs/op` **doubles whenever M doubles**.
//! * **Within one row.** `d10/d1` says the same thing without comparing runs: the last tenth of the
//!   ramp walks 19× the chain the first tenth walked, so a cost linear in chain length drives this
//!   ratio towards 19. Measured on `d94cfe4` it climbs 6.5 → 9.6 → 12.8 → 15.2 as M goes
//!   1000 → 8000, which is that limit being approached as the ~2.6 µs fixed per-write cost becomes a
//!   smaller share of the total. Fitting `cost = f + c·chain` to the deciles gives `f ≈ 2.6 µs` and
//!   `c ≈ 23.5 ns` per chain step, consistently at every M — that two-parameter model reproduces all
//!   four measured `set µs/op` values to within 4%.
//!
//! For acceptance criterion 2 the non-vacuous form is that the `prop`/`undo`/`commit` triple is
//! **identical at M = 1000 and M = 8000** — not merely that it is small.
//!
//! # The measured result (`rmp` #967 acceptance criterion 1)
//!
//! Both readings taken on the same host, same harness, same arms — AMD Ryzen 9 5900HX (8 cores /
//! 16 threads), Linux 6.8.0-136-generic, `rustc 1.96.0`, idle machine, `--release`. BEFORE is the
//! `tombstone_props_for_key` path at `d94cfe4`; AFTER is the in-place + undo-delta path.
//!
//! **The subject — `same key`, `txn/op` (the `checkpoint_sentinel` shape), `set µs/op`:**
//!
//! | M | BEFORE | AFTER |
//! |---:|---:|---:|
//! | 1000 | 15.1 | **2.96** |
//! | 2000 | 27.1 | **2.97** |
//! | 4000 | 50.9 | **2.95** |
//! | 8000 | 97.8 | **2.95** |
//!
//! `vs prev` is `x1.00, x0.99, x1.00` and `d10/d1` is `0.9, 1.0, 1.0, 1.0`: flat across rows **and**
//! flat within each row, which are the two independent readings above agreeing. Run-to-run spread is
//! 0.5–6.7% over 5 repeats, so the residual variation is noise, not a trend. At M = 8000 the write is
//! **33× cheaper**; the visible read is **296 µs → 0.2 µs** at the same chain length, and `cells == 1`
//! confirms the entity really does hold a single live version rather than the harness having stopped
//! counting.
//!
//! **The positive control — `distinct keys`, `txn/op`, `set µs/op`:** 16.78 → 29.53 → 55.03 → 106.40,
//! i.e. `vs prev` of `x1.76, x1.86, x1.93` with `d10/d1` climbing 5.6 → 13.2. It still grows, and
//! grows *quadratically*, from the same run that reports the subject arm flat. That is what licenses
//! the claim: the instrument did not go blind, the subject's cost went away.
//!
//! # What this benchmark does NOT measure — read this before quoting a number
//!
//! * **No disk.** The store runs on `MemBlockDevice` + `MemLogSink` (the DST substrate every
//!   `graphus-bench` fixture uses), so `commit`'s `fdatasync` is modelled in memory and `txn µs/op`
//!   is not a durability figure. Deliberate: #967 changes CPU work on a chain walk, and real
//!   `fdatasync` noise (milliseconds) would bury a microsecond effect. Durability cost is
//!   `commit_path_fsync`'s subject.
//! * **The whole working set is resident.** M = 8000 property records occupy ~46 of the 4096 pool
//!   frames, so every chain step is a pinned-page read with no I/O. The measured per-step cost is a
//!   *lower bound*: pure CPU and L2/L3 traffic. The same walk on a cold or contended pool is
//!   strictly worse, so a fix validated here is not thereby validated for a pool-spilling working set.
//! * **Inline values only.** The written value is `Value::Integer`, which lives in the property
//!   record's `value_inline` field. A `String` would allocate an overflow chain in `strings.store`
//!   per write, adding cost that grows with nothing and dilutes the signal. The real
//!   `checkpoint_sentinel` counters are integers too.
//! * **`Instant::now()` is inside the loop.** Two clock reads per op, ~40 ns together — <0.5% at the
//!   reported per-op costs, but a visible fraction of `d1` at small M, so `d10/d1` is if anything an
//!   *under*-estimate of the true growth.
//! * **Single-threaded.** The storage write API takes `&mut self` (`04 §11.1`), so there is no
//!   contention here. #967's interaction with the reader pool is a separate question.
//!
//! # Running it
//!
//! ```text
//! cargo bench -p graphus-bench --bench prop_overwrite
//! ```
//!
//! To additionally report the record-read triple for acceptance criterion 2:
//!
//! ```text
//! cargo bench -p graphus-bench --bench prop_overwrite --features read-probe
//! ```
//!
//! With `read-probe` on, the read path carries a thread-local counter bump per record read, so the
//! `read µs` column is instrumented and must not be quoted as a clean timing — the harness says so in
//! its own output. Every other column is unaffected (the counter is on the read path only). Take
//! timings from the plain run and counts from the probe run.
//!
//! Environment overrides (all optional):
//!
//! - `PROP_OVERWRITE_M` — comma-separated chain lengths (default `1000,2000,4000,8000`)
//! - `PROP_OVERWRITE_REPEATS` — independent runs per cell (default `5`)
//! - `PROP_OVERWRITE_READS` — timed reads per run (default `200`)
//!
//! Report alongside hardware (`lscpu`), kernel (`uname -r`) and toolchain (`rustc --version`), and
//! run it on an idle host: the effect under test is tens of microseconds and a busy machine moves it.

use std::hint::black_box;
use std::time::Instant;

use graphus_core::{TxnId, Value};
use graphus_storage::Namespace;
use graphus_txn::Snapshot;

#[path = "common.rs"]
mod common;
use common::{BenchStore, fresh_store};

/// The key overwritten over and over in the `same key` arm — the `checkpoint_sentinel` counter.
const SAME_KEY: &str = "batch_seq";

/// Chain lengths measured unless `PROP_OVERWRITE_M` overrides them.
const DEFAULT_M: [u64; 4] = [1000, 2000, 4000, 8000];

/// Independent runs per cell unless `PROP_OVERWRITE_REPEATS` overrides it. Each run builds a fresh
/// store, so runs are independent samples rather than repetitions inside one warmed state.
const DEFAULT_REPEATS: u64 = 5;

/// Timed visible-property reads per run unless `PROP_OVERWRITE_READS` overrides it.
const DEFAULT_READS: u64 = 200;

/// How many equal-width windows the ramp is split into for the within-run growth profile.
const DECILES: usize = 10;

/// How the M writes are distributed over transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TxnShape {
    /// One transaction per write — the `bulk_load::checkpoint_sentinel` production shape.
    PerOp,
    /// All M writes inside one transaction.
    Single,
}

/// Which key each of the M writes targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyShape {
    /// Every write overwrites one key — the subject; must become O(1) under #967.
    Same,
    /// Every write targets a fresh key — the positive control; legitimately stays O(K).
    Distinct,
}

/// One arm of the benchmark.
#[derive(Debug, Clone, Copy)]
struct Arm {
    txn: TxnShape,
    keys: KeyShape,
}

impl Arm {
    fn label(self) -> &'static str {
        match (self.keys, self.txn) {
            (KeyShape::Same, TxnShape::PerOp) => {
                "same key, txn/op       [SUBJECT — the bulk_load checkpoint-sentinel shape]"
            }
            (KeyShape::Same, TxnShape::Single) => "same key, 1 txn        [SUBJECT]",
            (KeyShape::Distinct, TxnShape::PerOp) => {
                "distinct keys, txn/op  [POSITIVE CONTROL — must keep growing after #967]"
            }
            (KeyShape::Distinct, TxnShape::Single) => {
                "distinct keys, 1 txn   [POSITIVE CONTROL — must keep growing after #967]"
            }
        }
    }
}

/// One independent run of one arm at one chain length.
#[derive(Debug, Clone, Copy)]
struct Run {
    /// Mean µs per `set_node_property_value` call over the whole ramp.
    set_us: f64,
    /// Mean µs of total transaction cost per write over the whole ramp.
    txn_us: f64,
    /// Mean µs per `set` in the first tenth of the ramp.
    d1_us: f64,
    /// Mean µs per `set` in the last tenth of the ramp.
    d10_us: f64,
    /// Mean µs to serve one visible-property read at the final chain length.
    read_us: f64,
    /// Live `props.store` cells after the ramp (the non-vacuity control: `1` for `same key` after
    /// `rmp` #967, `M` for `distinct keys`).
    chain: u64,
    /// Undo-delta chain length after the ramp — the second half of the non-vacuity control: the
    /// accumulated old values have to be SOMEWHERE, and after #967 that is the chain.
    history: u64,
    /// Record reads to serve one visible-property read: `(prop, undo, commit)`. `None` without
    /// the `read-probe` feature.
    reads: Option<(u64, u64, u64)>,
}

/// Builds a store holding one node, performs `m` property writes on it according to `arm`, then
/// measures a visible-property read at the resulting chain length.
///
/// Only the `set`/`begin`/`commit` calls are timed; store creation, node creation and token
/// interning are outside every timer.
///
/// # Panics
/// Panics on any store error (a benchmark fixture — a failure is a programming error, not a
/// condition to handle), and on the chain-length non-vacuity check.
fn run_one(m: u64, reads: u64, arm: Arm) -> Run {
    assert!(m >= DECILES as u64, "M must be at least {DECILES}");

    let mut store: BenchStore = fresh_store();

    // Intern every key up front, outside the timers: token interning is not the subject, and in the
    // `Distinct` arm it would otherwise grow the measured cost for a reason unrelated to #967.
    let keys: Vec<u32> = match arm.keys {
        KeyShape::Same => vec![
            store
                .intern_token(Namespace::PropKey, SAME_KEY)
                .expect("intern propkey"),
        ],
        KeyShape::Distinct => (0..m)
            .map(|i| {
                store
                    .intern_token(Namespace::PropKey, &format!("k{i}"))
                    .expect("intern propkey")
            })
            .collect(),
    };
    let key_at = |i: u64| match arm.keys {
        KeyShape::Same => keys[0],
        KeyShape::Distinct => keys[i as usize],
    };

    let mut next_txn: u64 = 1;

    // Setup, untimed: one node, committed, with no properties yet.
    let t = TxnId(next_txn);
    next_txn += 1;
    store.begin(t);
    let (node, _eid) = store.create_node(t).expect("create node");
    store.commit(t).expect("commit node");

    // The ramp. `set_ns` times only the call #967 replaces; `txn_ns` times the transaction machinery
    // as well, so the commit-side share stays visible instead of hiding inside the headline number.
    let mut set_ns: u64 = 0;
    let mut txn_ns: u64 = 0;
    let mut window_ns = [0u64; DECILES];
    let mut window_ops = [0u64; DECILES];

    match arm.txn {
        TxnShape::PerOp => {
            for i in 0..m {
                let t = TxnId(next_txn);
                next_txn += 1;
                let t_txn = Instant::now();
                store.begin(t);
                let t_set = Instant::now();
                store
                    .set_node_property_value(t, node, key_at(i), &Value::Integer(i as i64))
                    .expect("set property");
                let d_set = t_set.elapsed().as_nanos() as u64;
                store.commit(t).expect("commit write");
                let d_txn = t_txn.elapsed().as_nanos() as u64;

                set_ns += d_set;
                txn_ns += d_txn;
                let w = ((i * DECILES as u64) / m) as usize;
                window_ns[w] += d_set;
                window_ops[w] += 1;
            }
        }
        TxnShape::Single => {
            let t = TxnId(next_txn);
            next_txn += 1;
            let t_txn = Instant::now();
            store.begin(t);
            for i in 0..m {
                let t_set = Instant::now();
                store
                    .set_node_property_value(t, node, key_at(i), &Value::Integer(i as i64))
                    .expect("set property");
                let d_set = t_set.elapsed().as_nanos() as u64;
                set_ns += d_set;
                let w = ((i * DECILES as u64) / m) as usize;
                window_ns[w] += d_set;
                window_ops[w] += 1;
            }
            // The single commit settles all M version stamps at once; it is part of the write cost
            // and is amortised into `txn µs/op` rather than dropped.
            store.commit(t).expect("commit ramp");
            txn_ns = t_txn.elapsed().as_nanos() as u64;
        }
    }

    // Non-vacuity, in BOTH halves. `rmp` #967 changed where the accumulated versions live, so the
    // control had to change with it — and it is now stronger, because it pins the representation
    // rather than only a count:
    //
    // * `cells` — in the `Same` arm the write path rewrites ONE cell in place, so the entity holds
    //   exactly 1; in the `Distinct` arm each write adds a cell for a fresh key, so it holds M. If
    //   the `Same` arm ever reports M again the in-place write has regressed, and the flat timings
    //   below would be measuring something else.
    // * `history` — the M old values must still be retrievable by an older snapshot, so the undo
    //   chain must have grown to at least M. Without this half, a change that simply stopped
    //   recording old values would make the subject arms flat AND leave `cells == 1`, and the
    //   benchmark would report a triumphant false win for a correctness regression.
    let superset = store
        .superset_scan_node_properties(node)
        .expect("superset scan");
    let chain = superset.len() as u64;
    let history = superset.history_len() as u64;
    let expected_cells = match arm.keys {
        KeyShape::Same => 1,
        KeyShape::Distinct => m,
    };
    assert_eq!(
        chain, expected_cells,
        "the entity should hold {expected_cells} property cells after {m} writes, found {chain} — \
         the benchmark is not measuring what it claims"
    );
    assert!(
        history >= m,
        "the undo chain should hold at least {m} deltas (one old value per write), found \
         {history} — the old values are not being retained, so the timings below are not the cost \
         of a correct write"
    );

    // The read arm: the visible value of the last key written, through the same decision-polarity
    // path the query engine uses (`decision_scan_node_properties` → `visible_version`).
    let read_key = key_at(m - 1);
    let snap = Snapshot::new(TxnId(next_txn), store.snapshot_ts());
    let visible_read = |s: &BenchStore| {
        let decided = s
            .decision_scan_node_properties(node, snap)
            .expect("decision scan");
        assert!(
            decided.visible_version(read_key).is_some(),
            "the written key must be visible — the read arm is measuring an empty result"
        );
        decided
    };

    // Warm the pool and branch predictors so the first timed read is not an outlier.
    for _ in 0..3 {
        black_box(visible_read(&store));
    }
    let t_read = Instant::now();
    for _ in 0..reads {
        black_box(visible_read(&store));
    }
    let read_ns = t_read.elapsed().as_nanos() as u64;

    // Acceptance criterion 2: the record reads ONE visible-property read performs, per store. In the
    // `Same` arm this must become `(1, ..., ...)` and, crucially, must be IDENTICAL at every M.
    #[cfg(feature = "read-probe")]
    let reads_triple = {
        let (_decided, c) = graphus_storage::read_probe::counting(|| visible_read(&store));
        Some((c.prop, c.undo, c.commit))
    };
    #[cfg(not(feature = "read-probe"))]
    let reads_triple = None;

    let mean_us = |ns: u64, n: u64| ns as f64 / n as f64 / 1000.0;
    Run {
        set_us: mean_us(set_ns, m),
        txn_us: mean_us(txn_ns, m),
        d1_us: mean_us(window_ns[0], window_ops[0]),
        d10_us: mean_us(window_ns[DECILES - 1], window_ops[DECILES - 1]),
        read_us: mean_us(read_ns, reads),
        chain,
        history,
        reads: reads_triple,
    }
}

/// Median of `xs` (mean of the two middle values for an even count). `xs` is sorted in place.
fn median(xs: &mut [f64]) -> f64 {
    xs.sort_by(f64::total_cmp);
    let n = xs.len();
    if n % 2 == 1 {
        xs[n / 2]
    } else {
        (xs[n / 2 - 1] + xs[n / 2]) / 2.0
    }
}

/// Reads a comma-separated `u64` list from the environment, falling back to `default`.
fn env_list(var: &str, default: &[u64]) -> Vec<u64> {
    match std::env::var(var) {
        Ok(s) => s
            .split(',')
            .map(|p| {
                p.trim()
                    .parse::<u64>()
                    .unwrap_or_else(|_| panic!("{var}: `{p}` is not a number"))
            })
            .collect(),
        Err(_) => default.to_vec(),
    }
}

/// Reads a single `u64` from the environment, falling back to `default`.
fn env_u64(var: &str, default: u64) -> u64 {
    std::env::var(var).map_or(default, |s| {
        s.trim()
            .parse()
            .unwrap_or_else(|_| panic!("{var}: `{s}` is not a number"))
    })
}

/// Runs one arm over every chain length and prints its table.
fn run_arm(arm: Arm, ms: &[u64], repeats: u64, reads: u64) {
    println!("── {}", arm.label());
    println!(
        "{:>6}  {:>10}  {:>10}  {:>9}  {:>9}  {:>7}  {:>8}  {:>9}  {:>7}  {:>8}  {:>18}",
        "M",
        "set us/op",
        "txn us/op",
        "d1 us/op",
        "d10 us/op",
        "d10/d1",
        "vs prev",
        "read us",
        "cells",
        "deltas",
        "prop/undo/commit",
    );
    println!("{}", "-".repeat(128));

    let mut prev_set: Option<f64> = None;
    for &m in ms {
        let runs: Vec<Run> = (0..repeats).map(|_| run_one(m, reads, arm)).collect();

        let mut set: Vec<f64> = runs.iter().map(|r| r.set_us).collect();
        let mut txn: Vec<f64> = runs.iter().map(|r| r.txn_us).collect();
        let mut d1: Vec<f64> = runs.iter().map(|r| r.d1_us).collect();
        let mut d10: Vec<f64> = runs.iter().map(|r| r.d10_us).collect();
        let mut rd: Vec<f64> = runs.iter().map(|r| r.read_us).collect();

        let set_lo = set.iter().copied().fold(f64::INFINITY, f64::min);
        let set_hi = set.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let set_med = median(&mut set);
        let d1_med = median(&mut d1);
        let d10_med = median(&mut d10);

        // Every run of a cell is deterministic in its record reads, so disagreement between runs
        // would mean the counter is observing something other than the read it brackets.
        if let Some(first) = runs[0].reads {
            assert!(
                runs.iter().all(|r| r.reads == Some(first)),
                "record-read counts differ between identical runs at M={m}: {:?}",
                runs.iter().map(|r| r.reads).collect::<Vec<_>>()
            );
        }
        let triple = runs[0]
            .reads
            .map_or_else(|| "-".to_string(), |(p, u, c)| format!("{p}/{u}/{c}"));
        let vs_prev = prev_set.map_or_else(|| "-".to_string(), |p| format!("x{:.2}", set_med / p));

        println!(
            "{:>6}  {:>10.2}  {:>10.2}  {:>9.3}  {:>9.2}  {:>7.1}  {:>8}  {:>9.1}  {:>7}  {:>8}  {:>18}",
            m,
            set_med,
            median(&mut txn),
            d1_med,
            d10_med,
            d10_med / d1_med,
            vs_prev,
            median(&mut rd),
            runs[0].chain,
            runs[0].history,
            triple,
        );
        println!(
            "        (set us/op over {repeats} runs: min {set_lo:.2}, max {set_hi:.2}, spread {:.1}%)",
            (set_hi - set_lo) / set_med * 100.0
        );
        prev_set = Some(set_med);
    }
    println!();
}

fn main() {
    let ms = env_list("PROP_OVERWRITE_M", &DEFAULT_M);
    let repeats = env_u64("PROP_OVERWRITE_REPEATS", DEFAULT_REPEATS);
    let reads = env_u64("PROP_OVERWRITE_READS", DEFAULT_READS);
    assert!(
        repeats > 0 && reads > 0,
        "repeats and reads must be positive"
    );

    println!("property write cost vs chain length (rmp #967 AC 1 / AC 2)");
    println!("  M          = {ms:?}");
    println!("  repeats    = {repeats} (fresh store each)");
    println!("  reads/run  = {reads}");
    println!(
        "  substrate  = MemBlockDevice + MemLogSink, pool {} frames",
        common::POOL_CAPACITY
    );
    if cfg!(feature = "read-probe") {
        println!(
            "  read-probe = ON — `read us` is INSTRUMENTED (a thread-local counter bump per record\n\
             \x20              read) and must not be quoted as a clean timing. Take timings from a\n\
             \x20              plain run; take `prop/undo/commit` from this one."
        );
    } else {
        println!(
            "  read-probe = off — `prop/undo/commit` unavailable; rerun with --features read-probe"
        );
    }
    println!();

    for arm in [
        Arm {
            keys: KeyShape::Same,
            txn: TxnShape::PerOp,
        },
        Arm {
            keys: KeyShape::Same,
            txn: TxnShape::Single,
        },
        Arm {
            keys: KeyShape::Distinct,
            txn: TxnShape::PerOp,
        },
        Arm {
            keys: KeyShape::Distinct,
            txn: TxnShape::Single,
        },
    ] {
        run_arm(arm, &ms, repeats, reads);
    }

    println!(
        "Reading this table:\n\
         \x20 * Growth is quadratic iff `set us/op` roughly DOUBLES per doubling of M (`vs prev` ~x2)\n\
         \x20   and `d10/d1` climbs towards 19 (the last tenth walks 19x the chain the first does;\n\
         \x20   it approaches that limit from below as the fixed per-write cost dilutes).\n\
         \x20 * #967 must drive `vs prev` to ~1 and `d10/d1` to ~1 in the two SUBJECT arms.\n\
         \x20 * The POSITIVE CONTROL arms must KEEP growing — an entity with K live properties is\n\
         \x20   legitimately O(K). If they go flat too, the harness stopped measuring and no claim\n\
         \x20   about the subject arms can be supported by it.\n\
         \x20 * For AC 2 the non-vacuous form is `prop/undo/commit` IDENTICAL at M=1000 and M=8000,\n\
         \x20   not merely small."
    );
}
