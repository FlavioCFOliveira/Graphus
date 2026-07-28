//! **`CREATE CONSTRAINT … IS UNIQUE` validates in linear time, and pins the GC watermark for exactly
//! that long** (`rmp` task #956).
//!
//! The validation walk decides a uniqueness constraint by comparing each covered value against the
//! values it has already inspected. It used to keep those in a `Vec` and search it with a linear scan
//! per entity, so the walk was O(entities²) in comparisons and O(entities) in memory.
//!
//! # Why the exponent is an availability property, not just a latency one
//!
//! Since `rmp` task #903 the walk runs inside a registered transaction that holds a snapshot from
//! `begin` to `commit`. While that transaction is in the active set it is the minimum of
//! [`TxnCoordinator::oldest_active_snapshot`], so it **pins the GC watermark** and no version newer
//! than its snapshot can be reclaimed. The walk's duration is therefore exactly the window in which a
//! live database cannot reclaim storage — and a quadratic walk suspends reclamation for a quadratic
//! time. That is what makes the exponent, rather than any single wall-clock number, the property worth
//! gating, and it is why `rmp` #903's terminability was load-bearing rather than theoretical.
//!
//! # Measured
//!
//! The headline figures come from [`time_unique`] below driven at the task's acceptance sizes, on the
//! development host (Linux 6.8, release profile) — the same seed-then-validate path the gates use, only
//! at 10⁴/10⁵/10⁶ instead of the smaller corpora these tests can afford to run on every build:
//!
//! | nodes     | before `rmp` #956 | after   |
//! |-----------|-------------------|---------|
//! | 10 000    | 0.381 s           | 0.110 s |
//! | 100 000   | 42.94 s           | 1.159 s |
//! | 1 000 000 | not run           | 12.06 s |
//!
//! Fitted exponent over the 10k→100k decade: **2.05 before, 1.02 after**; over 100k→1M, **1.03**. The
//! 10⁶ row was not run against the old walk — at the measured exponent it would have taken about an
//! hour.
//!
//! The gates themselves run at [`SMALL`]/[`LARGE`] and are reproduced by
//! `cargo test -p graphus-cypher --test constraint_validation_scaling_956 -- --nocapture
//! --test-threads=1`.
//!
//! # Why these gates compare against themselves
//!
//! They assert a *ratio* between two corpus sizes, never an absolute time, so they measure the
//! algorithm and not the host — the house style of `construction_scales_sub_quadratically`
//! (`graphus-cypher`'s coordinator) and `it_is_linear_rather_than_quadratic` (`value_hash_join.rs`).
//!
//! The [`CEILING`] was chosen from measurement, not taste. Both regimes were run at these exact sizes,
//! in both profiles, by reverting only `SeenTuples::contains_equal` to the per-entity linear scan:
//!
//! | gate       | profile | pre-#956 | after `rmp` #956 |
//! |------------|---------|----------|------------------|
//! | uniqueness | debug   | 30.05x   | 8.22x            |
//! | uniqueness | release | 33.36x   | 9.01x            |
//! | node key   | debug   | 28.14x   | 8.15x            |
//! | node key   | release | 30.59x   | 8.70x            |
//!
//! The ceiling therefore sits 1.8x above the slowest passing measurement and 1.8x below the fastest
//! failing one — the geometric mean of 9.01 and 28.14 is 15.9.
//!
//! An earlier draft of this file used a **4x** size step, where the two regimes measure only 4.0–4.35x
//! and 8.61–11.23x: the quadratic implementation **passed** a 16x ceiling there, so the gate was
//! vacuous. The 8x step is what separates them, because the linear term grows with the step while the
//! quadratic term grows with its square. A future edit that shrinks these corpora must re-derive the
//! ceiling the same way, by reverting the fix and measuring.

use std::time::{Duration, Instant};

use graphus_core::{TxnId, Value};
use graphus_cypher::ConstraintKind;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

/// The smaller corpus. Large enough that the per-node floor (one store read plus one property-chain
/// resolution) dominates start-up noise.
const SMALL: usize = 2_000;
/// The larger corpus, [`GROWTH`]x the smaller.
const LARGE: usize = 16_000;
/// The size ratio between the two corpora.
const GROWTH: f64 = 8.0;
/// The ratio a linear walk must stay under. Sits at the geometric mean of the two measured regimes
/// (8.2-9.0x linear, 28-33x for the per-entity linear scan this replaced), so it clears a pass and a
/// failure by ~1.8x either way — see the module docs for the full measurement table.
const CEILING: f64 = 16.0;

fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: Store = RecordStore::create(device, wal, 16_384, 1).expect("create store");
    TxnCoordinator::new(store)
}

fn compile(src: &str) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

/// Runs a seeding statement in its own transaction and commits it.
fn seed_with(coord: &mut Coord, src: &str, n: usize) {
    let txn: TxnId = coord.begin_serializable();
    let plan = compile(src);
    let mut params = Parameters::new();
    params.insert(
        "n".to_owned(),
        Value::Integer(i64::try_from(n).expect("corpus size fits an i64")),
    );
    let bound = bind_parameters(&plan, &params).expect("bind");
    {
        let mut graph = coord.statement(txn).expect("statement");
        {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            let _rows: Vec<Row> = cursor.collect_all().expect("collect");
        }
        assert!(graph.take_error().is_none(), "the seed must be clean");
    }
    coord.commit(txn).expect("seed commits");
}

/// Seeds `n` `:P` nodes carrying a distinct `email`, then times `CREATE CONSTRAINT … IS UNIQUE`.
///
/// The measured span is the whole DDL call, which is precisely the window in which its transaction
/// sits in the active set and pins the GC watermark — the two facts asserted around it.
fn time_unique(n: usize) -> Duration {
    let mut coord = fresh_coord();
    seed_with(
        &mut coord,
        "UNWIND range(1, $n) AS i CREATE (:P {email: 'user' + toString(i)})",
        n,
    );
    assert_eq!(
        coord.oldest_active_snapshot(),
        None,
        "premise: nothing pins the watermark before the DDL, so the window measured is the DDL's"
    );

    // No `black_box` is needed to keep the call: the DDL mutates `coord`'s store and catalogue, so it
    // is not a candidate for elimination.
    let started = Instant::now();
    coord
        .create_constraint("u_email", "P", "email", ConstraintKind::Unique)
        .expect("the seeded values are distinct, so the constraint holds");
    let elapsed = started.elapsed();

    assert_eq!(
        coord.oldest_active_snapshot(),
        None,
        "and the DDL releases the watermark when it resolves, so the pin lasted exactly the span timed"
    );
    elapsed
}

/// Seeds `n` `:K` nodes carrying a distinct `(a, b)` tuple, then times `… IS NODE KEY` over it.
fn time_node_key(n: usize) -> Duration {
    let mut coord = fresh_coord();
    seed_with(
        &mut coord,
        "UNWIND range(1, $n) AS i CREATE (:K {a: 'user' + toString(i), b: i % 7})",
        n,
    );
    let started = Instant::now();
    coord
        .create_constraint_general("k_ab", "K", &["a", "b"], ConstraintKind::NodeKey, None)
        .expect("the seeded tuples are distinct, so the key holds");
    started.elapsed()
}

/// The minimum of `samples` runs of `f` at size `n` — the noise estimator the house uses for this
/// shape. A minimum rejects scheduler interference, which can only ever make a run slower.
fn min_of(samples: usize, n: usize, f: fn(usize) -> Duration) -> Duration {
    (0..samples)
        .map(|_| f(n))
        .min()
        .expect("at least one sample")
}

/// Reports the measured growth ratio of `f` between [`SMALL`] and [`LARGE`], having warmed it up so the
/// ratio reflects steady state rather than first-touch allocation.
///
/// The large corpus is sampled fewer times than the small one on purpose: its run is an order of
/// magnitude longer, so a scheduler hiccup is a proportionally smaller share of it, and each extra
/// sample costs a whole re-seed.
fn growth_ratio(f: fn(usize) -> Duration) -> (Duration, Duration, f64) {
    let _ = f(SMALL); // warm-up, discarded
    let t_small = min_of(3, SMALL, f);
    let t_large = min_of(2, LARGE, f);
    let ratio = t_large.as_secs_f64() / t_small.as_secs_f64().max(f64::MIN_POSITIVE);
    (t_small, t_large, ratio)
}

/// Growing the covered node count by [`GROWTH`] must grow the validation walk by about [`GROWTH`], not
/// by `GROWTH²`.
#[test]
fn uniqueness_validation_scales_linearly_not_quadratically() {
    let (t_small, t_large, ratio) = growth_ratio(time_unique);
    let exponent = ratio.ln() / GROWTH.ln();
    println!(
        "uniqueness validation: t({SMALL})={t_small:?} t({LARGE})={t_large:?} \
         ratio={ratio:.2}x exponent={exponent:.2}"
    );

    assert!(
        ratio < CEILING,
        "the uniqueness walk regressed toward quadratic: {GROWTH}x more nodes took {ratio:.1}x \
         longer. A linear sweep measures 8.2-9.0x here; the pre-#956 per-entity linear scan measured \
         30.1-33.4x. t({SMALL})={t_small:?} t({LARGE})={t_large:?}",
    );
}

/// The composite / `NODE KEY` path compares whole tuples and had its own copy of the linear scan, so it
/// gets its own gate: fixing only the single-property arm would leave `IS NODE KEY` quadratic.
#[test]
fn node_key_validation_scales_linearly_not_quadratically() {
    let (t_small, t_large, ratio) = growth_ratio(time_node_key);
    println!(
        "NODE KEY validation: t({SMALL})={t_small:?} t({LARGE})={t_large:?} ratio={ratio:.2}x"
    );

    assert!(
        ratio < CEILING,
        "the NODE KEY walk regressed toward quadratic: {GROWTH}x more nodes took {ratio:.1}x longer. \
         A linear sweep measures 8.2-8.7x here; the pre-#956 per-entity linear scan measured 28.1-30.6x. \
         t({SMALL})={t_small:?} t({LARGE})={t_large:?}",
    );
}

/// The GC watermark consequence, stated as the fact the scaling gates rest on: the DDL pins the
/// watermark for the duration of its walk and for nothing longer, so shortening the walk shortens the
/// pin by the same factor.
///
/// That the DDL pins and releases at all is `rmp` task #903's property; what is added here is that a
/// walk over a substantial corpus leaves the watermark released and the collector able to run — the
/// state a quadratic walk deferred for a quadratic time.
#[test]
fn the_ddl_releases_the_gc_watermark_as_soon_as_its_walk_ends() {
    let mut coord = fresh_coord();
    seed_with(
        &mut coord,
        "UNWIND range(1, $n) AS i CREATE (:P {email: 'user' + toString(i)})",
        SMALL,
    );

    let started = Instant::now();
    coord
        .create_constraint("u_email", "P", "email", ConstraintKind::Unique)
        .expect("the seeded values are distinct");
    let pinned_for = started.elapsed();
    println!("watermark pinned for {pinned_for:?} over {SMALL} nodes");

    assert_eq!(
        coord.oldest_active_snapshot(),
        None,
        "the DDL must not outlive its own walk as a watermark holder"
    );
    // And the released watermark really does let the collector run: a pass after the DDL must succeed
    // rather than be blocked by a lingering snapshot.
    coord
        .gc()
        .expect("a GC pass runs once the DDL has released the watermark");
}
