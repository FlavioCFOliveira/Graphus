//! `social_falkor_bench` — run the social-network-large read battery against a **FalkorDB** instance
//! (the RedisGraph successor: a Cypher property graph served over the Redis RESP protocol via the
//! `GRAPH.QUERY` command), so its performance can be compared apples-to-apples with the Graphus and
//! Neo4j Bolt runs.
//!
//! FalkorDB speaks RESP, not Bolt, so the Bolt bench tools (`social_bench`) cannot target it. This
//! binary reuses the EXACT same graph generator, read-battery families, and Zipf anchor-skew sampler as
//! `social_bench` (from the shared `graphus_social_gen` crate) and swaps only the transport: a minimal
//! RESP client issuing `GRAPH.QUERY <graph> "CYPHER <params> <cypher>"`. The parameterised form lets
//! FalkorDB cache one plan per family, mirroring the `$u0`/`$u1` parameter maps the Bolt runs used.
//!
//! Two modes:
//!   --load <data-dir>   create the id indexes and load the graph from the SAME CSVs the Bolt runs used
//!                       (byte-identical edge set), via `UNWIND` batches; then exit.
//!   (default)           run the concurrency ladder read battery and print per-rung + per-family stats.
//!
//! Anchors, family mix (friends:4 degree:4 fof:2 mutual:2 top_liked:1), and the Zipf degree-rank skew
//! are reconstructed from the generator, identical to `social_bench` (`rmp` #746), so the queried
//! anchor distribution matches the earlier runs.

use std::io::{self, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Barrier, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use graphus_social_gen::{DegreeDist, GenConfig, Generator, SplitMix64, ZipfRanks, battery};

// ============================================================================================
// Minimal RESP client (RESP2) — just enough to issue GRAPH.QUERY and consume the full reply.
// ============================================================================================

/// One RESP connection to FalkorDB. Owns a raw write handle plus a buffered read handle over a clone of
/// the same socket, so a reply is drained in full before the next command is written (RESP is strictly
/// request/response on one connection).
struct FalkorConn {
    write: TcpStream,
    read: BufReader<TcpStream>,
}

impl FalkorConn {
    fn connect(host: &str, port: u16, timeout: Duration) -> io::Result<Self> {
        let stream = TcpStream::connect((host, port))?;
        stream.set_nodelay(true).ok();
        stream.set_read_timeout(Some(timeout)).ok();
        stream.set_write_timeout(Some(timeout)).ok();
        let read = BufReader::new(stream.try_clone()?);
        Ok(Self {
            write: stream,
            read,
        })
    }

    /// Encode `args` as a RESP array of bulk strings and write it.
    fn send(&mut self, args: &[&str]) -> io::Result<()> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
        for a in args {
            buf.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
            buf.extend_from_slice(a.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
        self.write.write_all(&buf)?;
        self.write.flush()
    }

    /// Read one CRLF-terminated line (without the trailing CRLF).
    fn read_line(&mut self) -> io::Result<String> {
        let mut out = Vec::with_capacity(32);
        let mut byte = [0u8; 1];
        loop {
            self.read.read_exact(&mut byte)?;
            if byte[0] == b'\r' {
                self.read.read_exact(&mut byte)?; // consume '\n'
                break;
            }
            out.push(byte[0]);
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    /// Consume exactly one RESP value, recursively. Returns `Err` iff the value is a top-level RESP
    /// error (`-...`), carrying its message. All other types are drained and yield `Ok(())`.
    fn consume(&mut self) -> io::Result<Result<(), String>> {
        let mut tag = [0u8; 1];
        self.read.read_exact(&mut tag)?;
        match tag[0] {
            b'+' | b':' | b',' | b'#' | b'(' => {
                self.read_line()?;
                Ok(Ok(()))
            }
            b'-' => {
                let msg = self.read_line()?;
                Ok(Err(msg))
            }
            b'$' | b'=' => {
                // Bulk string: length line, then len bytes + CRLF (or -1 = null).
                let len: i64 = self.read_line()?.trim().parse().unwrap_or(-1);
                if len >= 0 {
                    let mut body = vec![0u8; len as usize + 2];
                    self.read.read_exact(&mut body)?;
                }
                Ok(Ok(()))
            }
            b'_' => {
                self.read_line()?; // RESP3 null
                Ok(Ok(()))
            }
            b'*' | b'~' | b'>' => {
                let n: i64 = self.read_line()?.trim().parse().unwrap_or(-1);
                let mut first_err: Option<String> = None;
                for _ in 0..n.max(0) {
                    if let Err(e) = self.consume()? {
                        first_err.get_or_insert(e);
                    }
                }
                Ok(match first_err {
                    Some(e) => Err(e),
                    None => Ok(()),
                })
            }
            b'%' => {
                let n: i64 = self.read_line()?.trim().parse().unwrap_or(-1);
                let mut first_err: Option<String> = None;
                for _ in 0..(n.max(0) * 2) {
                    if let Err(e) = self.consume()? {
                        first_err.get_or_insert(e);
                    }
                }
                Ok(match first_err {
                    Some(e) => Err(e),
                    None => Ok(()),
                })
            }
            other => Ok(Err(format!("unexpected RESP tag 0x{other:02x}"))),
        }
    }

    /// Issue `GRAPH.QUERY <graph> <query> TIMEOUT <ms>` and consume the full reply. `Err` on a RESP
    /// error. FalkorDB's deprecated legacy `TIMEOUT` config defaults to 1000ms and aborts any read
    /// exceeding it; the Graphus and Neo4j Bolt runs had no such cap and ran the heavy `top_liked`
    /// aggregation (~4-37s) to completion, so a generous per-query ceiling removes that config
    /// artifact and keeps the comparison about the ENGINE, not the default timeout.
    fn graph_query(
        &mut self,
        graph: &str,
        query: &str,
        timeout_ms: &str,
    ) -> io::Result<Result<(), String>> {
        self.send(&["GRAPH.QUERY", graph, query, "TIMEOUT", timeout_ms])?;
        self.consume()
    }
}

/// The generous per-query ceiling (ms) passed to every `GRAPH.QUERY`, above the heaviest family's cost
/// yet below the TCP read timeout, so a slow query completes rather than being severed by either bound.
const QUERY_TIMEOUT_MS: &str = "120000";

// ============================================================================================
// CLI
// ============================================================================================

struct Args {
    host: String,
    port: u16,
    graph: String,
    profile: String,
    users: u64,
    articles: u64,
    friend_min: u64,
    friend_max: u64,
    avg_likes: u64,
    zipf_exponent: u32,
    seed: u64,
    ladder: Vec<u64>,
    ops_per_rung: u64,
    min_ops_per_client: u64,
    anchor_skew: u32,
    load_dir: Option<String>,
    timeout: Duration,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        host: "127.0.0.1".into(),
        port: 6379,
        graph: "social".into(),
        profile: "fast".into(),
        users: 1_000_000,
        articles: 30_000,
        friend_min: 20,
        friend_max: 50,
        avg_likes: 10,
        zipf_exponent: 2,
        seed: 5_819_109_560_120_336_109,
        ladder: vec![1, 2, 4, 8, 16, 32],
        ops_per_rung: 300,
        min_ops_per_client: 150,
        anchor_skew: 2,
        load_dir: None,
        timeout: Duration::from_secs(180),
    };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let mut val = || it.next().ok_or_else(|| format!("missing value for {k}"));
        match k.as_str() {
            "--host" => a.host = val()?,
            "--port" => a.port = val()?.parse().map_err(|e| format!("--port: {e}"))?,
            "--graph" => a.graph = val()?,
            "--profile" => a.profile = val()?,
            "--users" => a.users = val()?.parse().map_err(|e| format!("--users: {e}"))?,
            "--articles" => a.articles = val()?.parse().map_err(|e| format!("--articles: {e}"))?,
            "--friend-min" => {
                a.friend_min = val()?.parse().map_err(|e| format!("--friend-min: {e}"))?
            }
            "--friend-max" => {
                a.friend_max = val()?.parse().map_err(|e| format!("--friend-max: {e}"))?
            }
            "--avg-likes" => {
                a.avg_likes = val()?.parse().map_err(|e| format!("--avg-likes: {e}"))?
            }
            "--degree-dist" => {
                let _ = val()?; // accepted for CLI parity; power-law is implied by --zipf-exponent
            }
            "--zipf-exponent" => {
                a.zipf_exponent = val()?
                    .parse()
                    .map_err(|e| format!("--zipf-exponent: {e}"))?
            }
            "--seed" => a.seed = val()?.parse().map_err(|e| format!("--seed: {e}"))?,
            "--ladder" => {
                a.ladder = val()?
                    .split(',')
                    .map(|s| s.trim().parse::<u64>())
                    .collect::<Result<_, _>>()
                    .map_err(|e| format!("--ladder: {e}"))?;
            }
            "--ops-per-rung" => {
                a.ops_per_rung = val()?.parse().map_err(|e| format!("--ops-per-rung: {e}"))?
            }
            "--min-ops-per-client" => {
                a.min_ops_per_client = val()?
                    .parse()
                    .map_err(|e| format!("--min-ops-per-client: {e}"))?
            }
            "--anchor-skew" => {
                a.anchor_skew = val()?.parse().map_err(|e| format!("--anchor-skew: {e}"))?
            }
            "--load" => a.load_dir = Some(val()?),
            "--read-timeout-ms" => {
                a.timeout = Duration::from_millis(
                    val()?
                        .parse()
                        .map_err(|e| format!("--read-timeout-ms: {e}"))?,
                )
            }
            "--gen-profile" | "--scenario" | "--writers" | "--verify-fraction" => {
                let _ = val()?; // accepted for CLI parity with social_bench; not used here
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(a)
}

fn gen_config(a: &Args) -> Result<GenConfig, String> {
    GenConfig::resolve(
        &a.profile,
        Some(a.users),
        Some(a.articles),
        Some(a.friend_min),
        Some(a.friend_max),
        Some(a.avg_likes),
        Some(a.seed),
        Some(DegreeDist::PowerLaw {
            exponent: a.zipf_exponent,
        }),
    )
}

// ============================================================================================
// Anchor sampler — verbatim reuse of social_bench's logic (rmp #746).
// ============================================================================================

/// Degree-rank permutation (rank 0 = the highest-degree user) + the Zipf rank sampler, or `None` when
/// the skew is off. Identical to `social_bench::build_anchor_ranks`.
fn build_anchor_ranks(skew: u32, degree: &[u64]) -> Option<(Vec<u64>, ZipfRanks)> {
    if skew == 0 {
        return None;
    }
    let mut perm: Vec<u64> = (0..degree.len() as u64).collect();
    perm.sort_by(|&x, &y| degree[y as usize].cmp(&degree[x as usize]).then(x.cmp(&y)));
    let zipf = ZipfRanks::new(perm.len(), skew);
    Some((perm, zipf))
}

/// Weighted family "bag": each family index repeated by its weight (cheap point reads more frequent than
/// heavy scans). Identical to `social_bench::weighted_bag`.
fn weighted_bag() -> Vec<usize> {
    let mut bag = Vec::new();
    for (i, fam) in battery::ALL.iter().enumerate() {
        let w = match fam.name {
            "friends" | "degree" => 4,
            "fof" | "mutual" => 2,
            "top_liked" => 1,
            _ => 1,
        };
        for _ in 0..w {
            bag.push(i);
        }
    }
    bag
}

/// Draw one anchor user index: Zipf-skewed toward the supernode tail when engaged, else uniform.
/// Identical to `social_bench::BenchCtx::draw_anchor`.
fn draw_anchor(
    anchor_ranks: &Option<(Vec<u64>, ZipfRanks)>,
    users: u64,
    rng: &mut SplitMix64,
) -> u64 {
    match anchor_ranks {
        Some((perm, zipf)) if !perm.is_empty() => {
            let rank = zipf.sample(rng.next_u64());
            perm[rank.min(perm.len() - 1)]
        }
        _ => rng.next_u64() % users.max(1),
    }
}

/// Build the FalkorDB `GRAPH.QUERY` query string for a family + anchors, using the `CYPHER k=v` prefix
/// so FalkorDB caches one plan per family (mirrors the Bolt `$u0`/`$u1` parameter maps).
fn build_query(fam: &battery::Family, u0: u64, u1: u64) -> String {
    match fam.params {
        battery::Params::None => fam.cypher.to_string(),
        battery::Params::User => format!("CYPHER u0={u0} {}", fam.cypher),
        battery::Params::UserPair => format!("CYPHER u0={u0} u1={u1} {}", fam.cypher),
    }
}

// ============================================================================================
// Percentiles
// ============================================================================================

fn pct(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

// ============================================================================================
// Loader (from the SAME CSVs the Bolt runs used, so the edge set is byte-identical)
// ============================================================================================

fn csv_ids(path: &str, id_col: usize) -> Result<Vec<i64>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 || line.is_empty() {
            continue; // header
        }
        let col = line
            .split(',')
            .nth(id_col)
            .ok_or_else(|| format!("{path}:{i}: too few columns"))?;
        out.push(
            col.trim()
                .parse::<i64>()
                .map_err(|e| format!("{path}:{i}: {e}"))?,
        );
    }
    Ok(out)
}

fn csv_pairs(path: &str) -> Result<Vec<(i64, i64)>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 || line.is_empty() {
            continue;
        }
        let mut f = line.split(',');
        let a = f.next().ok_or_else(|| format!("{path}:{i}: no START_ID"))?;
        let b = f.next().ok_or_else(|| format!("{path}:{i}: no END_ID"))?;
        out.push((
            a.trim()
                .parse::<i64>()
                .map_err(|e| format!("{path}:{i} START: {e}"))?,
            b.trim()
                .parse::<i64>()
                .map_err(|e| format!("{path}:{i} END: {e}"))?,
        ));
    }
    Ok(out)
}

fn load(a: &Args, dir: &str) -> Result<(), String> {
    let mut c =
        FalkorConn::connect(&a.host, a.port, a.timeout).map_err(|e| format!("connect: {e}"))?;
    let g = &a.graph;
    println!(
        "social_falkor_bench: loading into FalkorDB graph '{g}' at {}:{}",
        a.host, a.port
    );

    // Indexes so the {id: $u0} anchors seek instead of scanning.
    for label in ["USER", "ARTICLE"] {
        let q = format!("CREATE INDEX FOR (n:{label}) ON (n.id)");
        match c
            .graph_query(g, &q, QUERY_TIMEOUT_MS)
            .map_err(|e| format!("index {label}: {e}"))?
        {
            Ok(()) => println!("  index on :{label}(id) created"),
            Err(e) => println!("  index on :{label}(id) note: {e}"),
        }
    }

    // Nodes (id is the 3rd column of ":ID,:LABEL,id:long").
    let users = csv_ids(&format!("{dir}/users.csv"), 2)?;
    let articles = csv_ids(&format!("{dir}/articles.csv"), 2)?;
    load_nodes(&mut c, g, "USER", &users)?;
    println!("  loaded {} USER nodes", users.len());
    load_nodes(&mut c, g, "ARTICLE", &articles)?;
    println!("  loaded {} ARTICLE nodes", articles.len());

    // Edges.
    let friends = csv_pairs(&format!("{dir}/friends.csv"))?;
    let likes = csv_pairs(&format!("{dir}/likes.csv"))?;
    load_edges(&mut c, g, "USER", "USER", "FRIEND", &friends)?;
    println!("  loaded {} FRIEND edges", friends.len());
    load_edges(&mut c, g, "USER", "ARTICLE", "LIKE", &likes)?;
    println!("  loaded {} LIKE edges", likes.len());

    println!(
        "SOCIAL_FALKOR_LOAD_OK users={} articles={} friends={} likes={}",
        users.len(),
        articles.len(),
        friends.len(),
        likes.len()
    );
    Ok(())
}

fn load_nodes(c: &mut FalkorConn, g: &str, label: &str, ids: &[i64]) -> Result<(), String> {
    const B: usize = 5000;
    for chunk in ids.chunks(B) {
        let mut list = String::with_capacity(chunk.len() * 8);
        list.push('[');
        for (i, id) in chunk.iter().enumerate() {
            if i > 0 {
                list.push(',');
            }
            list.push_str(&id.to_string());
        }
        list.push(']');
        let q = format!("UNWIND {list} AS id CREATE (:{label} {{id: id}})");
        c.graph_query(g, &q, QUERY_TIMEOUT_MS)
            .map_err(|e| format!("load {label} nodes: {e}"))?
            .map_err(|e| format!("load {label} nodes: {e}"))?;
    }
    Ok(())
}

fn load_edges(
    c: &mut FalkorConn,
    g: &str,
    la: &str,
    lb: &str,
    rel: &str,
    pairs: &[(i64, i64)],
) -> Result<(), String> {
    const B: usize = 1000;
    for chunk in pairs.chunks(B) {
        let mut list = String::with_capacity(chunk.len() * 18);
        list.push('[');
        for (i, (x, y)) in chunk.iter().enumerate() {
            if i > 0 {
                list.push(',');
            }
            list.push('[');
            list.push_str(&x.to_string());
            list.push(',');
            list.push_str(&y.to_string());
            list.push(']');
        }
        list.push(']');
        let q = format!(
            "UNWIND {list} AS p MATCH (a:{la} {{id: p[0]}}), (b:{lb} {{id: p[1]}}) CREATE (a)-[:{rel}]->(b)"
        );
        c.graph_query(g, &q, QUERY_TIMEOUT_MS)
            .map_err(|e| format!("load {rel} edges: {e}"))?
            .map_err(|e| format!("load {rel} edges: {e}"))?;
    }
    Ok(())
}

// ============================================================================================
// Bench
// ============================================================================================

struct Ctx {
    host: String,
    port: u16,
    graph: String,
    users: u64,
    timeout: Duration,
    bag: Vec<usize>,
    anchor_ranks: Option<(Vec<u64>, ZipfRanks)>,
}

struct WorkerOut {
    /// (family_index, latency_ms) for every op this worker completed.
    lat: Vec<(usize, f64)>,
    errors: u64,
    connect_error: bool,
}

fn run_worker(
    ctx: &Ctx,
    issued: &AtomicU64,
    barrier: &Barrier,
    origin: &OnceLock<Instant>,
    seed: u64,
    budget: u64,
) -> WorkerOut {
    let mut out = WorkerOut {
        lat: Vec::new(),
        errors: 0,
        connect_error: false,
    };
    let mut conn = match FalkorConn::connect(&ctx.host, ctx.port, ctx.timeout) {
        Ok(c) => c,
        Err(_) => {
            out.connect_error = true;
            barrier.wait();
            return out;
        }
    };
    barrier.wait();
    let _ = *origin.get_or_init(Instant::now);
    let mut rng = SplitMix64::new(seed);
    loop {
        let ticket = issued.fetch_add(1, Ordering::Relaxed);
        if ticket >= budget {
            break;
        }
        let fam_ix = ctx.bag[(rng.next_u64() as usize) % ctx.bag.len()];
        let fam = &battery::ALL[fam_ix];
        let u0_idx = draw_anchor(&ctx.anchor_ranks, ctx.users, &mut rng);
        let u1_idx = draw_anchor(&ctx.anchor_ranks, ctx.users, &mut rng);
        let u0 = Generator::user_id(u0_idx);
        let u1 = Generator::user_id(u1_idx);
        let query = build_query(fam, u0, u1);
        let start = Instant::now();
        match conn.graph_query(&ctx.graph, &query, QUERY_TIMEOUT_MS) {
            Ok(Ok(())) => {
                let ms = start.elapsed().as_secs_f64() * 1000.0;
                out.lat.push((fam_ix, ms));
            }
            _ => out.errors += 1,
        }
    }
    out
}

struct RungResult {
    clients: u64,
    ops: u64,
    secs: f64,
    ops_per_sec: f64,
    p50: f64,
    p99: f64,
    errors: u64,
    per_family: Vec<(usize, f64)>, // (family_index, latency_ms) — only populated at the top rung
}

fn run_rung(ctx: &Ctx, clients: u64, budget: u64, collect_family: bool) -> RungResult {
    let issued = AtomicU64::new(0);
    let barrier = Barrier::new(clients as usize);
    let origin = OnceLock::new();
    let start = Instant::now();
    let outs = thread::scope(|s| {
        let handles: Vec<_> = (0..clients)
            .map(|i| {
                let ctx = &ctx;
                let issued = &issued;
                let barrier = &barrier;
                let origin = &origin;
                s.spawn(move || {
                    run_worker(
                        ctx,
                        issued,
                        barrier,
                        origin,
                        0x5EED ^ (i.wrapping_mul(0x9E3779B97F4A7C15)),
                        budget,
                    )
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    let secs = origin
        .get()
        .map_or_else(|| start.elapsed(), |o| o.elapsed())
        .as_secs_f64();

    let mut all: Vec<f64> = Vec::new();
    let mut errors = 0u64;
    let mut per_family: Vec<(usize, f64)> = Vec::new();
    for o in &outs {
        errors += o.errors;
        if o.connect_error {
            errors += 1;
        }
        for &(fx, ms) in &o.lat {
            all.push(ms);
            if collect_family {
                per_family.push((fx, ms));
            }
        }
    }
    all.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let ops = all.len() as u64;
    RungResult {
        clients,
        ops,
        secs,
        ops_per_sec: if secs > 0.0 { ops as f64 / secs } else { 0.0 },
        p50: pct(&all, 50.0),
        p99: pct(&all, 99.0),
        errors,
        per_family,
    }
}

fn preflight(ctx: &Ctx) -> Result<(), String> {
    let mut c = FalkorConn::connect(&ctx.host, ctx.port, ctx.timeout)
        .map_err(|e| format!("preflight connect: {e}"))?;
    let u0 = Generator::user_id(0);
    let u1 = Generator::user_id(1);
    for fam in battery::ALL {
        let q = build_query(fam, u0, u1);
        match c
            .graph_query(&ctx.graph, &q, QUERY_TIMEOUT_MS)
            .map_err(|e| format!("preflight {}: {e}", fam.name))?
        {
            Ok(()) => {}
            Err(e) => return Err(format!("preflight family '{}' rejected: {e}", fam.name)),
        }
    }
    Ok(())
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("social_falkor_bench: {e}");
            std::process::exit(2);
        }
    };

    if let Some(dir) = args.load_dir.clone() {
        match load(&args, &dir) {
            Ok(()) => return,
            Err(e) => {
                eprintln!("social_falkor_bench: load failed: {e}");
                std::process::exit(1);
            }
        }
    }

    // Bench mode: reconstruct the generator to derive the FRIEND-degree oracle for the Zipf anchor skew.
    let cfg = match gen_config(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("social_falkor_bench: {e}");
            std::process::exit(2);
        }
    };
    let generator = Generator::new(cfg);
    let (degree, _neighbours) = generator.friend_adjacency();
    let anchor_ranks = build_anchor_ranks(args.anchor_skew, &degree);

    let ctx = Ctx {
        host: args.host.clone(),
        port: args.port,
        graph: args.graph.clone(),
        users: args.users,
        timeout: args.timeout,
        bag: weighted_bag(),
        anchor_ranks,
    };

    println!(
        "social_falkor_bench: target=falkor://{}:{} graph={} ladder={:?} ops/rung={} min_ops/client={} users={} articles={} anchor_skew={} families={:?}",
        args.host,
        args.port,
        args.graph,
        args.ladder,
        args.ops_per_rung,
        args.min_ops_per_client,
        args.users,
        args.articles,
        args.anchor_skew,
        battery::ALL.iter().map(|f| f.name).collect::<Vec<_>>(),
    );

    if let Err(e) = preflight(&ctx) {
        eprintln!("social_falkor_bench: {e}");
        std::process::exit(1);
    }

    let mut rungs: Vec<RungResult> = Vec::new();
    let top = *args.ladder.iter().max().unwrap_or(&1);
    for &clients in &args.ladder {
        let budget = args.ops_per_rung.max(clients * args.min_ops_per_client);
        let r = run_rung(&ctx, clients, budget, clients == top);
        println!(
            "  rung clients={:>4} : {:>8.2} ops/s | p50={:>9.3}ms p99={:>10.3}ms | ok={} err={} secs={:.1}",
            r.clients, r.ops_per_sec, r.p50, r.p99, r.ops, r.errors, r.secs
        );
        rungs.push(r);
    }

    // Ladder table + best rung.
    println!("\n=== social_falkor_bench: concurrency ladder (5 families) ===");
    println!(" clients |      ops/s |    p50 ms |     p99 ms |   ok | err");
    println!("---------------------------------------------------------------");
    for r in &rungs {
        println!(
            " {:>7} | {:>10.2} | {:>9.3} | {:>10.3} | {:>4} | {:>3}",
            r.clients, r.ops_per_sec, r.p50, r.p99, r.ops, r.errors
        );
    }
    let best = rungs
        .iter()
        .max_by(|x, y| x.ops_per_sec.partial_cmp(&y.ops_per_sec).unwrap());
    if let Some(b) = best {
        println!(
            "\nPeak throughput {:.2} ops/s at clients={} (p50={:.3}ms p99={:.3}ms).",
            b.ops_per_sec, b.clients, b.p50, b.p99
        );
    }

    // Per-family latency at the top rung.
    if let Some(topr) = rungs.iter().find(|r| r.clients == top) {
        println!("\n=== per-family latency @ top rung (clients={top}) ===");
        println!("        family |   ok |    p50 ms |     p99 ms |     max ms");
        println!("---------------------------------------------------------------");
        for (fx, fam) in battery::ALL.iter().enumerate() {
            let mut v: Vec<f64> = topr
                .per_family
                .iter()
                .filter(|(i, _)| *i == fx)
                .map(|(_, ms)| *ms)
                .collect();
            v.sort_by(|x, y| x.partial_cmp(y).unwrap());
            let mx = v.last().copied().unwrap_or(0.0);
            println!(
                " {:>13} | {:>4} | {:>9.3} | {:>10.3} | {:>10.3}",
                fam.name,
                v.len(),
                pct(&v, 50.0),
                pct(&v, 99.0),
                mx
            );
        }
    }

    let total_err: u64 = rungs.iter().map(|r| r.errors).sum();
    if let Some(b) = best {
        println!(
            "\nSOCIAL_FALKOR_BENCH_STATS best_clients={} best_ops_per_sec={:.3} p50_ms={:.4} p99_ms={:.4} total_errors={}",
            b.clients, b.ops_per_sec, b.p50, b.p99, total_err
        );
    }
    println!("social_falkor_bench: OK");
}
