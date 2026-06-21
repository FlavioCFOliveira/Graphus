//! `social_load` — the large-graph **load + traversal** workload for `examples/social-network`,
//! driving the REAL Graphus engine over an on-disk store.
//!
//! # What it proves
//!
//! 1. **A large social graph loads through the production BULK path (`O(E)`).** The deterministic
//!    [`Generator`](graphus_social_gen::Generator) is streamed as `neo4j-admin import`-flavoured CSV
//!    (chunk by chunk, peak memory one chunk) into `graphus-bulk`'s
//!    [`BulkImporter`](graphus_bulk::BulkImporter): a node pass (USER then ARTICLE) and a relationship
//!    pass (FRIEND then LIKE). The importer resolves each relationship endpoint through an internal
//!    external-id→internal-id hash map — O(1) per endpoint, **O(E) total** — so the ingest scales
//!    independently of `N` (per-edge Cypher `CREATE`, by contrast, is O(E·N) because the planner can
//!    only index-seek one of the two anchors; see [`graphus_social_gen::load`]). The realised graph
//!    shape is then read **back from the engine** and asserted against the generator's prediction —
//!    `|USER|`, `|ARTICLE|`, `|FRIEND|`, `|LIKE|` must match exactly.
//!
//! 2. **Cypher is the traversal/read path, and index-backed point lookups keep it fast.** After the
//!    bulk import, a [`TxnCoordinator`](graphus_cypher::coordinator::TxnCoordinator) is built over the
//!    same store (no reopen), the `:USER(id)`/`:ARTICLE(id)` indexes are built online over the loaded
//!    data, and every read statement is compiled against the live catalog, so each `MATCH (:USER {id:
//!    …})` point lookup is an index *seek*. The bulk-import throughput (nodes/s, rels/s) and the
//!    on-disk footprint with its logical-vs-physical amplification are reported as evidence.
//!
//! 3. **The traversal queries work and are fast.** A read-query battery exercises the core social
//!    operations — direct friends, friend-of-friend (2-hop), mutual friends, top-N most-liked
//!    articles (aggregation + ORDER BY + LIMIT), and a user's degree — each with its measured
//!    latency and result shape. The probes that must be non-empty at the `fast` profile are asserted
//!    so a regression that silently breaks traversal fails the run.
//!
//! 4. **The durable footprint is real bytes on disk.** The store is a [`FileBlockDevice`] page file
//!    plus a [`FileLogSink`] WAL directory; after the load is flushed + synced the binary reports the
//!    actual on-disk size of both — the genuine storage cost of the graph.
//!
//! The engine-driving logic lives in [`graphus_social_gen::load`] (shared with the later
//! `social_evidence` binary and the hermetic `tests/load_fast.rs` cargo test); this binary owns the
//! CLI, the human-readable report, and the pass/fail assertions. See that module's docs for why the
//! workload drives the engine inline + on-disk, the empirical index/planner findings, and the sizing
//! rationale.
//!
//! Usage:
//!   cargo run -p graphus-social-gen --features engine --bin social_load -- --profile fast
//!   cargo run -p graphus-social-gen --features engine --bin social_load -- --profile large --dir <path>
//!   cargo run -p graphus-social-gen --features engine --bin social_load -- --profile fast --json <path>

use std::path::PathBuf;
use std::process::ExitCode;

use graphus_social_gen::GenConfig;
use graphus_social_gen::Generator;
use graphus_social_gen::load::{LoadOpts, outcome_json, resolve_dir, run_load_isolated};

fn main() -> ExitCode {
    let mut profile = String::from("fast");
    let mut dir: Option<PathBuf> = None;
    let mut json_path: Option<PathBuf> = None;
    let mut index_ids = true;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--profile" => match args.next() {
                Some(v) => profile = v,
                None => return fail("--profile requires a value"),
            },
            "--dir" => match args.next() {
                Some(v) => dir = Some(PathBuf::from(v)),
                None => return fail("--dir requires a path"),
            },
            "--json" => match args.next() {
                Some(v) => json_path = Some(PathBuf::from(v)),
                None => return fail("--json requires a path"),
            },
            // Escape hatch for a scan-only contrast at a TINY profile (never use at large/huge).
            "--no-index" => index_ids = false,
            "-h" | "--help" => {
                eprintln!(
                    "usage: social_load --profile <fast|large|huge> [--dir <path>] [--no-index] \
                     [--json <path>]"
                );
                return ExitCode::SUCCESS;
            }
            other => return fail(&format!("unexpected argument '{other}'")),
        }
    }

    let Some(cfg) = GenConfig::profile(&profile) else {
        return fail(&format!(
            "unknown profile '{profile}' (want fast|large|huge)"
        ));
    };

    // The generator's *predicted* shape — what the engine must read back after the load.
    let predicted = Generator::new(cfg.clone()).summary();

    let load_dir = match resolve_dir(dir) {
        Ok(d) => d,
        Err(e) => return fail(&format!("cannot prepare load directory: {e}")),
    };

    println!(
        "social_load: profile={profile} seed={} users={} articles={} friend_min={} friend_max={} avg_likes_per_user={}",
        cfg.seed, cfg.users, cfg.articles, cfg.friend_min, cfg.friend_max, cfg.avg_likes_per_user,
    );
    println!("  store dir: {}", load_dir.display());

    let out = run_load_isolated(&cfg, &load_dir, LoadOpts { index_ids });

    // ---------------------------------------------------------------------------------------------
    // Report: load phases (throughput), durable footprint, then the read-query battery.
    // ---------------------------------------------------------------------------------------------
    println!(
        "  loaded: users={} articles={} friend_edges={} like_edges={} total_elements={}",
        out.user_count,
        out.article_count,
        out.friend_count,
        out.like_count,
        out.total_elements(),
    );
    println!("  bulk-import phases (production O(E) path):");
    println!("  phase            items        ms     items/s");
    let phase_line = |name: &str, p: &graphus_social_gen::load::PhaseTiming| {
        println!(
            "  {name:<14} {:>8}  {:>8}  {:>10.0}",
            p.items,
            p.millis,
            p.per_sec()
        );
    };
    phase_line("nodes", &out.nodes_phase);
    phase_line("relationships", &out.rels_phase);
    println!(
        "  importer rates:  nodes={:.0}/s  rels={:.0}/s  properties_set={}",
        out.import_nodes_per_sec, out.import_rels_per_sec, out.import_properties,
    );
    println!(
        "  index_build      (USER,ARTICLE)  {:>8} ms",
        out.index_build_millis
    );
    println!(
        "  footprint: device={}B wal={}B total={}B  logical_csv={}B  (indexed={})",
        out.device_bytes,
        out.wal_bytes,
        out.footprint_bytes(),
        out.logical_csv_bytes,
        out.indexed,
    );
    println!(
        "  amplification: space(total)={:.3}x  space(store-only)={:.3}x",
        out.space_amplification(),
        out.store_space_amplification(),
    );

    println!("  read-query battery:");
    println!("    name         latency_us   rows   scalar");
    for q in &out.queries {
        println!(
            "    {:<11}  {:>9}  {:>5}   {}",
            q.name,
            q.latency_us,
            q.rows,
            q.scalar.map_or_else(|| "-".to_owned(), |n| n.to_string()),
        );
    }

    if let Some(path) = &json_path {
        if let Err(e) = std::fs::write(path, outcome_json(&out)) {
            return fail(&format!("cannot write --json {}: {e}", path.display()));
        }
        println!("  wrote machine-readable outcome to {}", path.display());
    } else {
        println!("GRAPHUS_SOCIAL_SAMPLES {}", outcome_json(&out));
    }

    // ---------------------------------------------------------------------------------------------
    // Assertions: the graph shape read back from the engine must match the generator's prediction,
    // and the traversal probes must be well-formed (non-empty where the model guarantees it).
    // ---------------------------------------------------------------------------------------------
    let mut failures = 0u32;

    let mut check = |cond: bool, msg: String| {
        if cond {
            println!("  ✓ {msg}");
        } else {
            eprintln!("FAIL: {msg}");
            failures += 1;
        }
    };

    check(
        out.user_count == cfg.users,
        format!("|USER| == {} (got {})", cfg.users, out.user_count),
    );
    check(
        out.article_count == cfg.articles,
        format!("|ARTICLE| == {} (got {})", cfg.articles, out.article_count),
    );
    check(
        out.friend_count == predicted.friend_edges,
        format!(
            "|FRIEND| == generator.friend_edges {} (got {})",
            predicted.friend_edges, out.friend_count
        ),
    );
    check(
        out.like_count == predicted.like_edges,
        format!(
            "|LIKE| == generator.like_edges {} (got {})",
            predicted.like_edges, out.like_count
        ),
    );
    // The bulk relationship pass must have ingested exactly the realised FRIEND + LIKE edge totals.
    check(
        out.rels_phase.items == predicted.friend_edges + predicted.like_edges,
        format!(
            "relationship phase item count {} matches realised friend_edges + like_edges {}",
            out.rels_phase.items,
            predicted.friend_edges + predicted.like_edges
        ),
    );

    // The traversal probes: at the `fast` profile the model guarantees a connected, well-fanned-out
    // graph, so direct-friends, friend-of-friend and degree must be non-empty; top-liked must return
    // the requested rows; mutual-friends may legitimately be zero for an arbitrary pair, so we only
    // assert it returned a (scalar) row.
    let probe = |name: &str| out.query(name).expect("probe present");
    let friends = probe("friends");
    let fof = probe("fof");
    let mutual = probe("mutual");
    let top = probe("top_liked");
    let degree = probe("degree");

    check(
        friends.scalar.unwrap_or(0) > 0,
        format!(
            "direct friends non-empty (got {})",
            friends.scalar.unwrap_or(0)
        ),
    );
    check(
        fof.scalar.unwrap_or(0) > 0,
        format!(
            "friend-of-friend non-empty (got {})",
            fof.scalar.unwrap_or(0)
        ),
    );
    check(
        mutual.rows == 1,
        format!(
            "mutual-friends returned a scalar row (got {} rows)",
            mutual.rows
        ),
    );
    check(
        top.rows >= 1,
        format!(
            "top-liked returned at least one article (got {} rows)",
            top.rows
        ),
    );
    check(
        degree.scalar.unwrap_or(0) > 0,
        format!("degree non-empty (got {})", degree.scalar.unwrap_or(0)),
    );

    println!();
    if failures == 0 {
        println!(
            "GRAPHUS_SOCIAL_OK — loaded a {}-user / {}-article social graph ({} FRIEND, {} LIKE) into the real engine over an on-disk store; shape read back from the engine and the traversal battery (friends, friend-of-friend, mutual, top-liked, degree) all verified; durable footprint {} bytes on disk.",
            out.user_count,
            out.article_count,
            out.friend_count,
            out.like_count,
            out.footprint_bytes(),
        );
        ExitCode::SUCCESS
    } else {
        eprintln!("social_load: {failures} assertion(s) failed");
        ExitCode::FAILURE
    }
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("social_load: error: {msg}");
    ExitCode::FAILURE
}
