//! Equivalence + determinism + engagement guard for the **frontier-seeded morsel-parallel
//! grouped-aggregation** tier (`rmp` task #575 — the product-recommendation `r3_fof3` class:
//! `MATCH (me:User {id:$id})-[:FRIEND]-()-[:FRIEND]-()-[:FRIEND]-(f3) WHERE f3.id<>$id
//!  MATCH (f3)-[:PURCHASED]->(p:Product) WHERE NOT (me)-[:PURCHASED]->(p)
//!  RETURN p.id, count(DISTINCT f3) ORDER BY reach DESC, product ASC LIMIT 10`).
//!
//! This tier materializes the multi-hop first `MATCH` **serially** (so its rows, visibility,
//! relationship-isomorphism, and SIREAD markers are byte-identical to serial), then partitions the
//! **distinct** frontier anchors (the `f3` node-ids) into contiguous morsels, each expanding the final
//! `(f3)-[:PURCHASED]->(p)` hop + applying the residual filters (`p:Product` and the **anti-join**
//! `NOT (me)-[:PURCHASED]->(p)`, evaluated per-row through the same graph seam serial uses) + folding the
//! grouped `count(DISTINCT f3)` into a LOCAL group table, then merging the partials via the #360 merge
//! (reused verbatim). It covers exactly the shape the #558 grouped-over-expand tier declines (its final
//! expand must be anchored on a bare label scan, and it rejects the anti-join pattern predicate).
//!
//! The inviolable obligation is that the parallel path is **byte-identical to serial** — rows, values AND
//! order — for the same MVCC snapshot, and worker-count-independent. This guard asserts it end-to-end
//! through the real executor + coordinator: the `r3_fof3` / `r2_fof` / `r1_friends` queries run with the
//! morsel knob at 1 (serial), 4, and 16 return the exact same result, and the tier is proven to actually
//! engage (the `parallel_scan_hits` counter increments at knob>1 but not at knob=1).

use graphus_core::{TxnId, Value};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// Bulk-seeds a committed recommendation-shaped graph: `n_users` `:User` nodes (integer `id`), a circulant
/// band plus a scattered long-range `FRIEND` graph so a single seed's 3-hop friend frontier is large and
/// spans the whole id range, `n_products` `:Product` nodes, and `PURCHASED` edges from each user to a spread
/// of products so a product's `count(DISTINCT f3)` reach-set is assembled from friends across **many**
/// morsels (the cross-morsel merge the tier must get right). Deterministic.
fn seed_reco(n_users: i64, n_products: i64, friend_deg: i64, purchase_deg: i64) -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut s = RecordStore::create(device, wal, 256, 1).expect("create store");
    let txn = TxnId(1);
    s.begin(txn);
    let l_user = s.intern_token(Namespace::Label, "User").unwrap();
    let l_product = s.intern_token(Namespace::Label, "Product").unwrap();
    let k_id = s.intern_token(Namespace::PropKey, "id").unwrap();
    let t_friend = s.intern_token(Namespace::RelType, "FRIEND").unwrap();
    let t_purchased = s.intern_token(Namespace::RelType, "PURCHASED").unwrap();

    // Products first (ids stable, exist before edges).
    let mut products = Vec::with_capacity(n_products as usize);
    for p in 0..n_products {
        let (id, _) = s.create_node(txn).unwrap();
        s.add_label(txn, id, l_product).unwrap();
        s.set_node_property_value(txn, id, k_id, &Value::Integer(p))
            .unwrap();
        products.push(id);
    }
    // Users.
    let mut users = Vec::with_capacity(n_users as usize);
    for u in 0..n_users {
        let (id, _) = s.create_node(txn).unwrap();
        s.add_label(txn, id, l_user).unwrap();
        s.set_node_property_value(txn, id, k_id, &Value::Integer(u))
            .unwrap();
        users.push(id);
    }
    // FRIEND edges (directed once — the query's `-[:FRIEND]-` matches either direction): a circulant band
    // plus a scattered long-range edge, so the 3-hop reach fans out across the whole id space.
    for u in 0..n_users {
        for d in 1..=friend_deg {
            let v = (u + d).rem_euclid(n_users);
            if v != u {
                s.create_rel(txn, t_friend, users[u as usize], users[v as usize])
                    .unwrap();
            }
        }
        let far = (u.wrapping_mul(2_654_435_761) ^ 0x9E37).rem_euclid(n_users);
        if far != u {
            s.create_rel(txn, t_friend, users[u as usize], users[far as usize])
                .unwrap();
        }
    }
    // PURCHASED edges: each user buys a deterministic spread of products (across the whole product range).
    for u in 0..n_users {
        for k in 0..purchase_deg {
            let p = (u.wrapping_mul(31).wrapping_add(k.wrapping_mul(97))).rem_euclid(n_products);
            s.create_rel(txn, t_purchased, users[u as usize], products[p as usize])
                .unwrap();
        }
    }
    s.commit(txn).unwrap();
    s
}

/// Runs `src` (with `$id` bound to `id`) over the coordinator in a fresh committed read transaction,
/// returning the FULL ordered row sequence rendered to a stable `Vec<(column, Debug-of-value)>`.
fn run_rows(
    coord: &mut TxnCoordinator<MemBlockDevice, MemLogSink>,
    src: &str,
    id: i64,
) -> Vec<Vec<(String, String)>> {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let plan = plan_physical(
        &lower(&analyze(&ast).expect("analyze")),
        &IndexCatalog::empty(),
    );
    let mut params = Parameters::new();
    params.insert("id".to_owned(), Value::Integer(id));
    let bound = bind_parameters(&plan, &params).expect("bind");

    let txn = coord.begin_serializable();
    let rendered = {
        let mut graph = coord.statement(txn).expect("statement");
        let rows = {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect")
        };
        assert!(
            !graph.has_error(),
            "statement captured an error: {:?}",
            graph.take_error()
        );
        rows.iter().map(render_row).collect()
    };
    coord.commit(txn).expect("read commits");
    rendered
}

fn render_row(row: &Row) -> Vec<(String, String)> {
    row.columns()
        .iter()
        .zip(row.values())
        .map(|(c, v)| (c.clone(), format!("{v:?}")))
        .collect()
}

/// The reco anti-join family — every query anchors on a single `(:User {id:$id})` seed, traverses a
/// friend chain, joins `PURCHASED`, anti-joins the seed's own purchases, and aggregates
/// `count(DISTINCT <friend>)` grouped by product with an `ORDER BY … LIMIT` on top.
fn reco_family() -> Vec<&'static str> {
    vec![
        // r1_friends — direct friends' purchases (1 hop). The final expand is anchored on the *direct*
        // friend expand's output (not a bare label scan), so this is the frontier tier's shape too.
        "MATCH (me:User {id: $id})-[:FRIEND]-(f:User)-[:PURCHASED]->(p:Product) \
         WHERE NOT (me)-[:PURCHASED]->(p) \
         RETURN p.id AS product, count(DISTINCT f) AS reach \
         ORDER BY reach DESC, product ASC LIMIT 10",
        // r2_fof — friend-of-friend (2 hops).
        "MATCH (me:User {id: $id})-[:FRIEND]-(:User)-[:FRIEND]-(f2:User) \
         WHERE f2.id <> $id \
         MATCH (f2)-[:PURCHASED]->(p:Product) \
         WHERE NOT (me)-[:PURCHASED]->(p) \
         RETURN p.id AS product, count(DISTINCT f2) AS reach \
         ORDER BY reach DESC, product ASC LIMIT 10",
        // r3_fof3 — third-level reach (3 hops) — the heaviest, the exact task-#575 target.
        "MATCH (me:User {id: $id})-[:FRIEND]-(:User)-[:FRIEND]-(:User)-[:FRIEND]-(f3:User) \
         WHERE f3.id <> $id \
         MATCH (f3)-[:PURCHASED]->(p:Product) \
         WHERE NOT (me)-[:PURCHASED]->(p) \
         RETURN p.id AS product, count(DISTINCT f3) AS reach \
         ORDER BY reach DESC, product ASC LIMIT 10",
    ]
}

/// The headline end-to-end guard: every reco query is byte-identical between the serial (knob=1) and
/// parallel (knob=4, knob=16) executor, AND the parallel tier actually engages (proven via the coordinator
/// `parallel_scan_hits` counter — a fully-declined tier would pass serial==serial vacuously).
#[test]
fn frontier_fof_end_to_end_matches_serial_and_engages() {
    let store = seed_reco(1_000, 120, 14, 6);
    let mut coord = TxnCoordinator::new(store);
    let seed_id = 0;

    for q in reco_family() {
        // Serial baseline (knob=1: the frontier tier is OFF — `morsel_threads <= 1`).
        graphus_cypher::morsel::set_morsel_threads(1);
        let hits_before_serial = coord.parallel_scan_hits();
        let serial = run_rows(&mut coord, q, seed_id);
        assert_eq!(
            coord.parallel_scan_hits(),
            hits_before_serial,
            "`{q}`: serial (knob=1) must NOT engage the parallel tier"
        );
        assert!(
            !serial.is_empty(),
            "`{q}`: expected a non-empty reco result (else the equivalence is vacuous)"
        );

        // Parallel at two worker counts — each must be byte-identical to serial AND engage the tier.
        for knob in [4usize, 16] {
            graphus_cypher::morsel::set_morsel_threads(knob);
            let hits_before = coord.parallel_scan_hits();
            let parallel = run_rows(&mut coord, q, seed_id);
            assert!(
                coord.parallel_scan_hits() > hits_before,
                "`{q}`: the frontier tier must engage at knob={knob}"
            );
            assert_eq!(
                serial, parallel,
                "`{q}`: morsel(knob={knob}) result (order included) must equal serial"
            );
        }
    }

    graphus_cypher::morsel::set_morsel_threads(1);
}

/// A DECLINE guard: a query whose residual filter is a **non-deterministic function call** (not a pure
/// per-row expr, not a structural pattern predicate) must fall back to serial (no engagement) — proving the
/// tier's residual gate is not over-permissive. Its result must still be identical serial-vs-parallel.
#[test]
fn frontier_fof_declines_impure_residual() {
    let store = seed_reco(600, 80, 12, 5);
    let mut coord = TxnCoordinator::new(store);
    let seed_id = 0;
    // A `toString(...)` residual is a function call — the frontier tier's residual gate rejects it.
    let q = "MATCH (me:User {id: $id})-[:FRIEND]-(:User)-[:FRIEND]-(f2:User) \
             MATCH (f2)-[:PURCHASED]->(p:Product) \
             WHERE toString(p.id) <> '' AND NOT (me)-[:PURCHASED]->(p) \
             RETURN p.id AS product, count(DISTINCT f2) AS reach \
             ORDER BY reach DESC, product ASC LIMIT 10";

    graphus_cypher::morsel::set_morsel_threads(1);
    let serial = run_rows(&mut coord, q, seed_id);

    graphus_cypher::morsel::set_morsel_threads(16);
    let hits_before = coord.parallel_scan_hits();
    let parallel = run_rows(&mut coord, q, seed_id);
    assert_eq!(
        coord.parallel_scan_hits(),
        hits_before,
        "an impure (function-call) residual must DECLINE the frontier tier (fall back to serial)"
    );
    assert_eq!(serial, parallel, "declined query must still be identical");

    graphus_cypher::morsel::set_morsel_threads(1);
}

// =================================================================================================
// (2) Measurement bench: wall-clock + read-phase mean cores of the `r3_fof3` query (`rmp` #575).
// =================================================================================================

/// Measures the wall-clock + READ-PHASE mean cores of the exact `r3_fof3` reco query at the morsel knob in
/// `GRAPHUS_BENCH_MORSEL` (one knob per process). `mean cores = (User + Sys) / Wall` over the read loop,
/// isolated from the serial preload via `/proc/self/stat` utime+stime. Prove the frontier tier turns a
/// single deep single-seed traversal from 1 core (knob=1) to many cores (knob=16), with a wall-time drop.
///
/// Run (Linux, release, one knob per process):
/// ```text
/// GRAPHUS_BENCH_MORSEL=1  cargo test -p graphus-cypher --release --test morsel_frontier_fof \
///     measure_r3_fof3_cores -- --ignored --nocapture
/// GRAPHUS_BENCH_MORSEL=16 cargo test -p graphus-cypher --release --test morsel_frontier_fof \
///     measure_r3_fof3_cores -- --ignored --nocapture
/// ```
/// `GRAPHUS_BENCH_USERS` / `GRAPHUS_BENCH_FRIEND_DEG` / `GRAPHUS_BENCH_PRODUCTS` / `GRAPHUS_BENCH_ITERS`
/// size the graph (defaults chosen so the 3-hop frontier is large enough to fan across cores without a
/// huge dataset). Do NOT set the size so high the box OOMs.
#[test]
#[ignore = "measurement bench — run explicitly with --ignored --nocapture under release (one knob per process)"]
fn measure_r3_fof3_cores() {
    use std::time::Instant;

    let knob: usize = std::env::var("GRAPHUS_BENCH_MORSEL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let users: i64 = std::env::var("GRAPHUS_BENCH_USERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(40_000);
    let friend_deg: i64 = std::env::var("GRAPHUS_BENCH_FRIEND_DEG")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let products: i64 = std::env::var("GRAPHUS_BENCH_PRODUCTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4_000);
    let purchase_deg: i64 = std::env::var("GRAPHUS_BENCH_PURCHASE_DEG")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(25);
    let iters: usize = std::env::var("GRAPHUS_BENCH_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);

    graphus_cypher::morsel::set_morsel_threads(knob);

    // Preload (NOT measured for cores: the serial bulk insert + commit on the engine thread).
    let preload_start = Instant::now();
    let store = seed_reco(users, products, friend_deg, purchase_deg);
    let mut coord = TxnCoordinator::new(store);
    let preload = preload_start.elapsed();

    // The exact `r3_fof3` query (the measured bottleneck): 3-hop friend chain from ONE seed, join PURCHASED,
    // anti-join the seed's purchases, grouped `count(DISTINCT f3)`, then ORDER BY reach DESC, product ASC.
    let q = "MATCH (me:User {id: $id})-[:FRIEND]-(:User)-[:FRIEND]-(:User)-[:FRIEND]-(f3:User) \
             WHERE f3.id <> $id \
             MATCH (f3)-[:PURCHASED]->(p:Product) \
             WHERE NOT (me)-[:PURCHASED]->(p) \
             RETURN p.id AS product, count(DISTINCT f3) AS reach \
             ORDER BY reach DESC, product ASC LIMIT 10";

    // Warm one run (fault pages into the buffer pool), then time the read loop — the phase whose mean-cores
    // is the AC. CPU time is read in ISOLATION via `/proc/self/stat` so the serial preload does not dilute it.
    let warm = run_rows(&mut coord, q, 0);
    let top = format!("{warm:?}");

    let (cpu0, wall0) = (proc_cpu_secs(), Instant::now());
    let mut last = String::new();
    for _ in 0..iters {
        let r = run_rows(&mut coord, q, 0);
        last = format!("{r:?}");
    }
    let elapsed = wall0.elapsed();
    let cpu = proc_cpu_secs() - cpu0;
    assert_eq!(
        last, top,
        "the reco result must be stable under knob={knob}"
    );

    let read_cores = cpu / elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
    println!(
        "r3_fof3 knob={knob} users={users} friend_deg={friend_deg} products={products} \
         purchase_deg={purchase_deg}: preload {:.2}s | read {iters} iters in {:?} ({:.1} ms/iter) \
         | READ-PHASE mean cores = {read_cores:.2} (cpu {cpu:.2}s / wall {:.2}s) | rows={}",
        preload.as_secs_f64(),
        elapsed,
        elapsed.as_secs_f64() * 1000.0 / iters as f64,
        elapsed.as_secs_f64(),
        warm.len(),
    );

    graphus_cypher::morsel::set_morsel_threads(1);
}

/// This process's total CPU time (user + system) in seconds, from `/proc/self/stat` (Linux). Isolates the
/// READ phase's mean-core utilisation from the serial preload. Returns 0.0 off Linux (wall time only).
#[cfg(target_os = "linux")]
fn proc_cpu_secs() -> f64 {
    let ticks_per_sec = 100.0; // _SC_CLK_TCK is 100 on every mainstream Linux; good enough for a bench.
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let after = stat.rsplit_once(')').map(|(_, t)| t).unwrap_or("");
    let fields: Vec<&str> = after.split_whitespace().collect();
    let utime: f64 = fields.get(11).and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let stime: f64 = fields.get(12).and_then(|s| s.parse().ok()).unwrap_or(0.0);
    (utime + stime) / ticks_per_sec
}

#[cfg(not(target_os = "linux"))]
fn proc_cpu_secs() -> f64 {
    0.0
}
