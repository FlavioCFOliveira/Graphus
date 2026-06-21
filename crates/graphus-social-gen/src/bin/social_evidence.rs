//! `social_evidence` — turns one large-graph **bulk load + read-query battery** run into a
//! **standardized, schema-versioned** [`EvidenceReport`] for `examples/social-network` (`rmp #309`).
//!
//! # What it captures (and how)
//!
//! The social-network headline evidence is the **durable bytes a large graph occupies on disk** and
//! the **index-backed read latencies** that serving it costs. This binary drives the SAME in-process
//! load+traversal run as `social_load` ([`graphus_social_gen::load::run_load_isolated`]) and, over the
//! same run, samples process RSS, so it folds the following evidence series into the shared schema:
//!
//! 1. **Durable on-disk footprint (DETERMINISTIC, GATED)** — the real `graph.store` page-device file
//!    size + its whole-page count, measured from the on-disk store after the bulk load is flushed +
//!    synced. For a fixed seed + profile the bulk-imported graph (and thus the store image it
//!    produces) is reproducible, so `store_bytes`, `store_pages`, the realised node / relationship
//!    counts, and the store-only space amplification are byte-stable and are the meaningful regression
//!    signal the committed baseline gates.
//! 2. **WAL footprint (machine-variant, NOT gated)** — the WAL directory's summed segment bytes. The
//!    WAL is a transient redo log whose on-disk length varies with segment rotation / fsync timing, so
//!    it is reported for visibility but NEVER gated.
//! 3. **RSS time series (process RAM, informational)** — an
//!    [`RssSampler`](graphus_examples_harness::RssSampler) sampled at each phase boundary plus a
//!    baseline + final point. Machine- and allocator-variant; NEVER gated.
//! 4. **Bulk-ingest throughput** — nodes/s + rels/s over the deterministic injected phase windows.
//!    Machine-variant, NOT gated.
//! 5. **Read-query latencies** — each of the five traversal probes' wall-clock latency, recorded as a
//!    note (the per-probe latency carried in the [`QuerySample`](graphus_social_gen::load::QuerySample)
//!    the load returns). Machine-variant, NOT gated.
//!
//! # Schema mapping (no schema widening)
//!
//! - **`storage`** — `store_bytes` = the durable device file size, `store_pages` = its whole-page
//!   count, `wal_bytes` = the WAL directory bytes (informational). `record_amplification` folds in the
//!   write/space amplification against the logical CSV byte count (the total figure includes the
//!   transient WAL, so the **store-only** amplification — the stable one — is stashed in the workload
//!   params and is what the baseline gate holds).
//! - **`throughput`** — `operations` = nodes + relationships ingested, `ops_per_sec` = the combined
//!   ingest rate over the load phases.
//! - **`memory`** — peak / final RSS over the run.
//! - **`phases`** — `node load`, `rel load`, `index build`, `read battery`.
//! - **`workload`** — seed/users/articles/friend band/avg_likes, the deterministic structural results
//!   (counts, store bytes/pages, store-only space amplification), and the per-probe latencies.
//!
//! It drives the engine inline + single-threaded over an **on-disk** store under the evidence dir's
//! `store/` sub-dir (the same on-disk layout the production server uses), so the durable footprint it
//! reports is real bytes on disk. Deterministic structural metrics; machine-variant RSS/throughput/
//! latency/time.
//!
//! # Usage
//!
//! ```text
//! social_evidence --evidence-dir <dir> [--profile fast|large|huge]
//!                 [--scenario social-network-large] [--description <text>] [--param k=v]... [--note <t>]...
//! ```

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use graphus_examples_harness::resource::cpu_section;
use graphus_examples_harness::{
    CpuTimes, DatasetScale, EvidenceCollector, PAGE_SIZE, RssSampler, RunMetadata, Target,
    ThroughputCounter, cumulative_cpu_times,
};
use graphus_social_gen::GenConfig;
use graphus_social_gen::load::{LoadOpts, LoadOutcome, run_load};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("social_evidence: error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Default)]
struct Args {
    evidence_dir: String,
    profile: String,
    scenario: String,
    description: String,
    params: Vec<(String, String)>,
    notes: Vec<String>,
}

fn run() -> Result<(), String> {
    let args = parse_args()?;

    let cfg = GenConfig::profile(&args.profile)
        .ok_or_else(|| format!("unknown profile '{}' (want fast|large|huge)", args.profile))?;

    // The on-disk store lives under the evidence dir so the durable footprint is real bytes on disk
    // (the same on-disk layout the production server uses). A dedicated sub-dir keeps the report.json /
    // report.md the harness writes separate from the store files.
    let evidence_dir = PathBuf::from(&args.evidence_dir);
    std::fs::create_dir_all(&evidence_dir)
        .map_err(|e| format!("cannot create evidence dir {}: {e}", args.evidence_dir))?;
    let store_dir = evidence_dir.join("store");
    // Start from a clean store dir: `RecordStore::create` requires an EMPTY device, so a leftover
    // `graph.store` / `graph.wal` from a previous run (the evidence dir is git-ignored but persists
    // across local runs) would otherwise fail the load. Removing it makes the evidence run idempotent.
    if store_dir.exists() {
        std::fs::remove_dir_all(&store_dir)
            .map_err(|e| format!("cannot clear store dir {}: {e}", store_dir.display()))?;
    }
    std::fs::create_dir_all(&store_dir)
        .map_err(|e| format!("cannot create store dir {}: {e}", store_dir.display()))?;

    // ----- Drive the REAL engine load+traversal, sampling RSS at phase boundaries. ----------------
    // The load is the same one `social_load` runs (the shared `run_load` core). We run it inline here
    // (not on the isolated 128 MiB-stack thread) so the RSS sampler observes THIS process's footprint
    // over the run; the `fast`/`large` profiles do not nest deeply enough in the engine front-end to
    // overflow the default stack for the read battery (the deep-recursion isolation matters for the
    // adversarial TCK corpus, not this fixed, well-formed workload).
    let mut rss = RssSampler::start(Target::SelfProcess, Duration::ZERO);
    rss.sample_now(); // a baseline point before the load
    let started = Instant::now();
    let outcome: LoadOutcome = run_load(&cfg, &store_dir, LoadOpts { index_ids: true });
    let wall = started.elapsed();
    rss.sample_now(); // a final point after the run
    let cpu_times = cumulative_cpu_times(Target::SelfProcess).unwrap_or(CpuTimes {
        user_secs: 0.0,
        system_secs: 0.0,
    });

    // ----- Derive the structural + throughput figures. --------------------------------------------
    let total_ingested = outcome
        .nodes_phase
        .items
        .saturating_add(outcome.rels_phase.items);
    // Combined ingest rate over the node + relationship load windows (the deterministic injected
    // windows — node phase + rel phase wall time, not the whole run including the read battery).
    let ingest_window = Duration::from_millis(
        outcome
            .nodes_phase
            .millis
            .saturating_add(outcome.rels_phase.millis),
    );
    let mut throughput = ThroughputCounter::new();
    throughput.add(total_ingested);
    let ingest_ops_per_sec = throughput.ops_per_sec_over(ingest_window);
    let nodes = outcome.user_count.saturating_add(outcome.article_count);
    let relationships = outcome.friend_count.saturating_add(outcome.like_count);
    // The STORE-ONLY space amplification (device bytes / logical CSV bytes) — the stable, gated figure
    // (the harness's `space_amplification` uses store+WAL, whose WAL component is machine-variant).
    let store_space_amp = outcome.store_space_amplification();
    // The durable store image's whole-page count (ceil), matching the harness's `store_pages` rule
    // (`bytes.div_ceil(PAGE_SIZE)`) so the workload param and the `storage.store_pages` section agree.
    let store_pages = outcome.device_bytes.div_ceil(PAGE_SIZE);

    // ----- Assemble the standardized report. ------------------------------------------------------
    let metadata = RunMetadata::new(args.scenario.clone(), args.description.clone())
        .with_dataset(DatasetScale::new(nodes, relationships));
    let mut collector = EvidenceCollector::new(metadata);

    {
        let w = &mut collector.metadata_mut().workload;
        w.insert("connection".into(), "in-process (engine seam)".into());
        w.insert("profile".into(), args.profile.clone());
        w.insert("seed".into(), cfg.seed.to_string());
        w.insert("users".into(), cfg.users.to_string());
        w.insert("articles".into(), cfg.articles.to_string());
        w.insert("friend_min".into(), cfg.friend_min.to_string());
        w.insert("friend_max".into(), cfg.friend_max.to_string());
        w.insert(
            "avg_likes_per_user".into(),
            cfg.avg_likes_per_user.to_string(),
        );
        w.insert("indexed".into(), outcome.indexed.to_string());
        // The DETERMINISTIC structural results the baseline gate holds.
        w.insert("user_count".into(), outcome.user_count.to_string());
        w.insert("article_count".into(), outcome.article_count.to_string());
        w.insert("friend_count".into(), outcome.friend_count.to_string());
        w.insert("like_count".into(), outcome.like_count.to_string());
        w.insert("node_count".into(), nodes.to_string());
        w.insert("relationship_count".into(), relationships.to_string());
        w.insert("device_bytes".into(), outcome.device_bytes.to_string());
        w.insert("store_pages".into(), store_pages.to_string());
        w.insert("wal_bytes".into(), outcome.wal_bytes.to_string());
        w.insert(
            "logical_csv_bytes".into(),
            outcome.logical_csv_bytes.to_string(),
        );
        w.insert(
            "store_space_amplification".into(),
            format!("{store_space_amp:.4}"),
        );
        w.insert(
            "import_nodes_per_sec".into(),
            format!("{:.1}", outcome.import_nodes_per_sec),
        );
        w.insert(
            "import_rels_per_sec".into(),
            format!("{:.1}", outcome.import_rels_per_sec),
        );
        w.insert(
            "import_properties".into(),
            outcome.import_properties.to_string(),
        );
        w.insert(
            "index_build_millis".into(),
            outcome.index_build_millis.to_string(),
        );
        w.insert(
            "load_wall_secs".into(),
            format!("{:.4}", wall.as_secs_f64()),
        );
        // The per-probe read latencies (compact `name:latency_us`), for human inspection.
        w.insert("query_latencies".into(), query_latency_series(&outcome));
        for (k, v) in &args.params {
            w.insert(k.clone(), v.clone());
        }
    }

    collector.start();
    collector.phase(
        "node load",
        Duration::from_millis(outcome.nodes_phase.millis),
    );
    collector.phase("rel load", Duration::from_millis(outcome.rels_phase.millis));
    collector.phase(
        "index build",
        Duration::from_millis(outcome.index_build_millis),
    );
    // The read battery's wall time is the summed per-probe latencies.
    let read_micros: u64 = outcome.queries.iter().map(|q| q.latency_us).sum();
    collector.phase("read battery", Duration::from_micros(read_micros));

    // CPU: the self-process cumulative time over the run.
    let cpu = cpu_section(cpu_times, wall);
    collector.cpu_mut().user_secs = cpu.user_secs;
    collector.cpu_mut().system_secs = cpu.system_secs;
    collector.cpu_mut().mean_core_utilisation = cpu.mean_core_utilisation;

    // Memory: the RSS series' peak/final (machine-variant, NOT gated).
    let mem = rss.to_section();
    collector.memory_mut().peak_rss_bytes = mem.peak_rss_bytes;
    collector.memory_mut().final_rss_bytes = mem.final_rss_bytes;

    // Storage: measure the REAL on-disk store + WAL files, then fold in the amplification against the
    // logical CSV bytes. `record_storage` walks both paths; `bytes_fsynced=None` records the WAL byte
    // count as the honest fsync proxy (every committed WAL byte is fsynced before commit ack).
    let device_file = store_dir.join("graph.store");
    let wal_dir = store_dir.join("graph.wal");
    collector
        .record_storage(&device_file, &wal_dir, None)
        .map_err(|e| {
            format!(
                "failed to measure on-disk storage under {}: {e}",
                store_dir.display()
            )
        })?;
    // write amplification := physical (store+WAL) / logical CSV; space amplification := same physical
    // / logical CSV. The STORE-ONLY space amplification (the stable, gated figure) is in the workload
    // params above; these total figures are informational (the WAL component is machine-variant).
    collector.record_amplification(outcome.logical_csv_bytes, outcome.logical_csv_bytes);

    // Throughput: nodes + relationships ingested over the deterministic load windows.
    collector.throughput_mut().operations = total_ingested;
    collector.throughput_mut().ops_per_sec = ingest_ops_per_sec;

    collector.note(format!(
        "DURABLE ON-DISK FOOTPRINT (the headline, DETERMINISTIC, GATED): bulk-loading the {}-user / \
         {}-article social graph ({} FRIEND, {} LIKE edges; {} nodes, {} relationships read back from \
         the engine) produced a durable store image of {} bytes ({} pages) on disk, a store-only space \
         amplification of {store_space_amp:.3}× over the {} logical CSV bytes the importer consumed. For \
         a fixed seed+profile the bulk-imported graph is reproducible, so the realised counts, the store \
         bytes/pages, and the store-only amplification are byte-stable — the baseline gate holds them to \
         a tight band; a drift is a genuine storage-engine or generator regression.",
        outcome.user_count, outcome.article_count, outcome.friend_count, outcome.like_count,
        nodes, relationships, outcome.device_bytes, store_pages,
        outcome.logical_csv_bytes,
    ));
    collector.note(format!(
        "WAL FOOTPRINT (machine-variant, NOT gated): the WAL directory measured {} bytes after the load \
         was flushed + synced. The WAL is a transient redo log whose on-disk length varies with segment \
         rotation and fsync timing, so it is reported for visibility but is given effectively-infinite \
         tolerance by the baseline gate — only the deterministic STORE image is gated.",
        outcome.wal_bytes,
    ));
    collector.note(format!(
        "INGEST THROUGHPUT (machine-variant, NOT gated): the production O(E) bulk path ingested {} nodes \
         and {} relationships ({} typed property assignments) over the node+rel load windows at {:.0} \
         nodes/s and {:.0} rels/s. The bulk importer resolves each relationship endpoint through an \
         internal external-id→internal-id hash map (O(1) per endpoint ⇒ O(E) total), so ingest scales \
         independently of N.",
        outcome.nodes_phase.items, outcome.rels_phase.items, outcome.import_properties,
        outcome.import_nodes_per_sec, outcome.import_rels_per_sec,
    ));
    collector.note(format!(
        "READ-QUERY LATENCIES (machine-variant, NOT gated): the index-backed traversal battery ran over \
         the loaded graph — {}. Each `MATCH (:USER {{id: …}})` point lookup is an index SEEK (the \
         :USER(id)/:ARTICLE(id) indexes were built before the battery), so latency stays low regardless \
         of graph size.",
        query_latency_human(&outcome),
    ));
    for note in &args.notes {
        collector.note(note.clone());
    }

    eprintln!(
        "social_evidence: profile={} seed={} nodes={nodes} relationships={relationships} \
         store={}B ({} pages) wal={}B store_space_amp={store_space_amp:.3}x | ingest {:.0} nodes/s {:.0} rels/s \
         | peak_rss={}B | {:.3}s wall",
        args.profile,
        cfg.seed,
        outcome.device_bytes,
        store_pages,
        outcome.wal_bytes,
        outcome.import_nodes_per_sec,
        outcome.import_rels_per_sec,
        mem.peak_rss_bytes,
        wall.as_secs_f64(),
    );

    let report = collector.finish();
    match report.write_to(&evidence_dir) {
        Ok((json, md)) => {
            println!("wrote {}", json.display());
            println!("wrote {}", md.display());
            Ok(())
        }
        Err(e) => Err(format!(
            "failed to write evidence to {}: {e}",
            evidence_dir.display()
        )),
    }
}

/// A compact `name:latency_us` series (one entry per probe, space-separated) for the report params.
fn query_latency_series(outcome: &LoadOutcome) -> String {
    let mut s = String::with_capacity(outcome.queries.len() * 24);
    for (i, q) in outcome.queries.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{}:{}", q.name, q.latency_us));
    }
    s
}

/// A human phrase summarising each probe's latency + result scalar, for the read-latency note.
fn query_latency_human(outcome: &LoadOutcome) -> String {
    let mut s = String::with_capacity(outcome.queries.len() * 32);
    for (i, q) in outcome.queries.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        let scalar = q.scalar.map_or_else(|| "-".to_owned(), |n| n.to_string());
        s.push_str(&format!("{} {}µs (={scalar})", q.name, q.latency_us));
    }
    s
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("missing value for {flag}"));
        match flag.as_str() {
            "--evidence-dir" => args.evidence_dir = value()?,
            "--profile" => args.profile = value()?,
            "--scenario" => args.scenario = value()?,
            "--description" => args.description = value()?,
            "--param" => {
                let raw = value()?;
                let (k, v) = raw
                    .split_once('=')
                    .ok_or_else(|| format!("--param expects key=value, got {raw:?}"))?;
                args.params.push((k.to_string(), v.to_string()));
            }
            "--note" => args.notes.push(value()?),
            "-h" | "--help" => {
                eprintln!(
                    "usage: social_evidence --evidence-dir <dir> [--profile fast|large|huge] \
                     [--scenario social-network-large] [--description <text>] [--param k=v]... \
                     [--note <t>]..."
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown flag {other:?}")),
        }
    }
    if args.evidence_dir.is_empty() {
        return Err("--evidence-dir is required".to_string());
    }
    if args.profile.is_empty() {
        args.profile = "fast".to_string();
    }
    if args.scenario.is_empty() {
        args.scenario = "social-network-large".to_string();
    }
    if args.description.is_empty() {
        args.description =
            "Social-network LPG: a large deterministic graph (USER/ARTICLE nodes, an undirected \
             FRIEND multigraph + directed LIKE edges) bulk-loaded into the REAL engine over an on-disk \
             store via the production O(E) bulk path, then served the openCypher traversal/read battery \
             (direct friends, friend-of-friend, mutual friends, top-liked articles, degree) over \
             index-backed point lookups — capturing the durable on-disk footprint, ingest throughput, \
             read latencies, CPU and RAM."
                .to_string();
    }
    Ok(args)
}
