//! `social_gen` — the deterministic social-network graph generator binary for
//! `examples/social-network`.
//!
//! Writes one artifact into `--out-dir` for the chosen `--profile`, in the format selected by
//! `--format`:
//! - `--format cypher` (default) — `graph.cypher`, the `USER` + `ARTICLE` nodes, then the `FRIEND`
//!   (undirected multigraph) and `LIKE` edges, all batched and `;`-terminated.
//! - `--format csv` — the `neo4j-admin import`-flavoured CSV file set the production
//!   `graphus-bulk`/network bulk-import path (`specification/08-network-bulk-import.md`) consumes:
//!   `users.csv`, `articles.csv` (node files, `:ID`/`:LABEL` header), `friends.csv`, `likes.csv`
//!   (relationship files, `:START_ID`/`:END_ID`/`:TYPE` header) — the same [`Generator::stream_user_csv`]
//!   family `graphus-social-gen`'s own in-process loader (`load.rs`) already streams to a temp
//!   directory before handing the files to [`graphus_bulk::BulkImporter`]. Written straight to disk,
//!   one chunk at a time (peak memory is one CSV chunk, not the whole file), so this scales to the
//!   `huge` profile's hundreds of millions of relationship rows.
//!
//! `--users`/`--articles`/`--friend-min`/`--friend-max`/`--avg-likes`/`--seed` override individual
//! fields of the profile resolved by `--profile`, so a caller can request a **custom scale** while
//! keeping a named profile's density/shape characteristics (e.g. `--profile huge --users 30000` keeps
//! `huge`'s 200–2000 friend-degree band and 30,000-article/30-avg-like density but bounds the total
//! row count for a disk- or time-constrained run) — used by the `rmp` #521 pi516 network bulk-import
//! validation to pick the largest dataset the target host's (unknown) free disk can safely absorb
//! without guessing at a whole new profile.
//!
//! Output is a pure function of the resolved [`GenConfig`] (each profile pins its own seed, and an
//! override is applied deterministically), so re-running with the same flags yields byte-identical
//! files — the determinism the example's performance claims are pinned to. Hermetic: serde only, no
//! engine, no network, CI-runnable.
//!
//! Usage:
//!   cargo run -p graphus-social-gen --bin social_gen -- --profile fast  --out-dir <dir>
//!   cargo run -p graphus-social-gen --bin social_gen -- --profile large --out-dir <dir>
//!   cargo run -p graphus-social-gen --bin social_gen -- --profile huge  --out-dir <dir> --format csv
//!   cargo run -p graphus-social-gen --bin social_gen -- --profile huge  --out-dir <dir> --format csv --users 30000

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use graphus_social_gen::{DegreeDist, GenConfig, Generator};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Cypher,
    Csv,
}

fn main() -> ExitCode {
    let mut profile = String::from("fast");
    let mut out_dir = PathBuf::from(".");
    let mut format = Format::Cypher;
    let mut users: Option<u64> = None;
    let mut articles: Option<u64> = None;
    let mut friend_min: Option<u64> = None;
    let mut friend_max: Option<u64> = None;
    let mut avg_likes: Option<u64> = None;
    let mut seed: Option<u64> = None;
    let mut degree_dist: Option<String> = None;
    let mut zipf_exponent: Option<u64> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile" => match args.next() {
                Some(v) => profile = v,
                None => return fail("--profile requires a value (fast|large|huge)"),
            },
            "--out-dir" => match args.next() {
                Some(v) => out_dir = PathBuf::from(v),
                None => return fail("--out-dir requires a value"),
            },
            "--format" => match args.next().as_deref() {
                Some("cypher") => format = Format::Cypher,
                Some("csv") => format = Format::Csv,
                Some(other) => {
                    return fail(&format!("unknown format '{other}' (expected cypher|csv)"));
                }
                None => return fail("--format requires a value (cypher|csv)"),
            },
            "--users" => match parse_u64_arg(&mut args, "--users") {
                Ok(v) => users = Some(v),
                Err(e) => return fail(&e),
            },
            "--articles" => match parse_u64_arg(&mut args, "--articles") {
                Ok(v) => articles = Some(v),
                Err(e) => return fail(&e),
            },
            "--friend-min" => match parse_u64_arg(&mut args, "--friend-min") {
                Ok(v) => friend_min = Some(v),
                Err(e) => return fail(&e),
            },
            "--friend-max" => match parse_u64_arg(&mut args, "--friend-max") {
                Ok(v) => friend_max = Some(v),
                Err(e) => return fail(&e),
            },
            "--avg-likes" => match parse_u64_arg(&mut args, "--avg-likes") {
                Ok(v) => avg_likes = Some(v),
                Err(e) => return fail(&e),
            },
            "--seed" => match parse_u64_arg(&mut args, "--seed") {
                Ok(v) => seed = Some(v),
                Err(e) => return fail(&e),
            },
            "--degree-dist" => match args.next().as_deref() {
                Some("uniform") => degree_dist = Some("uniform".to_owned()),
                Some("zipf" | "powerlaw" | "power-law") => {
                    degree_dist = Some("powerlaw".to_owned())
                }
                Some(other) => {
                    return fail(&format!(
                        "unknown --degree-dist '{other}' (expected uniform|zipf)"
                    ));
                }
                None => return fail("--degree-dist requires a value (uniform|zipf)"),
            },
            "--zipf-exponent" => match parse_u64_arg(&mut args, "--zipf-exponent") {
                Ok(v) => zipf_exponent = Some(v),
                Err(e) => return fail(&e),
            },
            "-h" | "--help" => {
                eprintln!(
                    "usage: social_gen --profile <fast|large|huge> --out-dir <dir> [--format cypher|csv]\n\
                     \x20      [--users N] [--articles N] [--friend-min N] [--friend-max N] [--avg-likes N] [--seed N]\n\
                     \x20      [--degree-dist uniform|zipf] [--zipf-exponent N (1..=6, default 2)]\n\
                     --format cypher (default) writes graph.cypher.\n\
                     --format csv writes users.csv, articles.csv, friends.csv, likes.csv (the\n\
                     neo4j-admin import / network bulk-import CSV shape).\n\
                     --degree-dist zipf draws each user's FRIEND degree from a power law P(k) ∝ k^-exp,\n\
                     producing SUPERNODES (a heavy hub tail); pair with --friend-min 1 for realism.\n\
                     The override flags replace individual fields of the resolved --profile config,\n\
                     for a custom scale that keeps a named profile's density/shape."
                );
                return ExitCode::SUCCESS;
            }
            other => return fail(&format!("unexpected argument '{other}'")),
        }
    }

    // Degree distribution: `uniform` (default) or a power law (`zipf`) with `--zipf-exponent` (default
    // 2 — the classic social-graph slope). The power-law draw produces SUPERNODES; pair it with a low
    // `--friend-min` (e.g. 1) and a high `--friend-max` for the most realistic hub structure. The
    // `--zipf-exponent`-without-`zipf` guard is a CLI concern; the rest of the resolution + validation
    // is the shared `GenConfig::resolve` (also used by the over-the-wire loader + ladder driver).
    let resolved_dist = match degree_dist.as_deref() {
        None | Some("uniform") => {
            if zipf_exponent.is_some() {
                return fail("--zipf-exponent requires --degree-dist zipf");
            }
            Some(DegreeDist::Uniform)
        }
        Some("powerlaw") => Some(DegreeDist::PowerLaw {
            exponent: zipf_exponent.unwrap_or(2) as u32,
        }),
        Some(other) => return fail(&format!("unknown degree distribution '{other}'")),
    };

    let cfg: GenConfig = match GenConfig::resolve(
        &profile,
        users,
        articles,
        friend_min,
        friend_max,
        avg_likes,
        seed,
        resolved_dist,
    ) {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };

    let generator = Generator::new(cfg);

    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        return fail(&format!("cannot create out-dir {}: {e}", out_dir.display()));
    }

    match format {
        Format::Cypher => {
            let graph_path = out_dir.join("graph.cypher");
            if let Err(e) = std::fs::write(&graph_path, generator.emit_all()) {
                return fail(&format!("cannot write {}: {e}", graph_path.display()));
            }
            println!("{}", generator.summary_line());
            println!("wrote {}", graph_path.display());
        }
        Format::Csv => {
            let written = [
                stream_to_file(&out_dir, "users.csv", |sink| {
                    generator.stream_user_csv(sink)
                }),
                stream_to_file(&out_dir, "articles.csv", |sink| {
                    generator.stream_article_csv(sink);
                }),
                stream_to_file(&out_dir, "friends.csv", |sink| {
                    generator.stream_friend_csv(sink);
                }),
                stream_to_file(&out_dir, "likes.csv", |sink| {
                    generator.stream_like_csv(sink);
                }),
            ];
            for w in &written {
                if let Err(e) = w {
                    return fail(e);
                }
            }
            println!("{}", generator.summary_line());
            for name in ["users.csv", "articles.csv", "friends.csv", "likes.csv"] {
                println!("wrote {}", out_dir.join(name).display());
            }
        }
    }

    ExitCode::SUCCESS
}

/// Streams one CSV artifact to `dir/name` via `stream`, one chunk at a time (never materializing the
/// whole file in memory) — mirrors `graphus_social_gen::load::write_csv_to_temp`'s shape, duplicated
/// here rather than reused because that helper is private to the `load` module's in-process loader.
fn stream_to_file(
    dir: &std::path::Path,
    name: &str,
    stream: impl FnOnce(&mut dyn FnMut(Vec<u8>)),
) -> Result<(), String> {
    let path = dir.join(name);
    let file = std::fs::File::create(&path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    let mut writer = std::io::BufWriter::new(file);
    let mut err: Option<std::io::Error> = None;
    {
        let mut sink = |chunk: Vec<u8>| {
            if err.is_some() {
                return;
            }
            if let Err(e) = writer.write_all(&chunk) {
                err = Some(e);
            }
        };
        stream(&mut sink);
    }
    if let Some(e) = err {
        return Err(format!("cannot write {}: {e}", path.display()));
    }
    writer
        .flush()
        .map_err(|e| format!("cannot flush {}: {e}", path.display()))
}

fn parse_u64_arg(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<u64, String> {
    match args.next() {
        Some(v) => v
            .parse::<u64>()
            .map_err(|_| format!("{flag} requires a non-negative integer value, got '{v}'")),
        None => Err(format!("{flag} requires a value")),
    }
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("social_gen: error: {msg}");
    ExitCode::FAILURE
}
