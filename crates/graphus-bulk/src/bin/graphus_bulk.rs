//! `graphus-bulk` — command-line offline CSV bulk importer / whole-graph dumper (FR-BK; `rmp` tasks
//! #22 and #327).
//!
//! ```text
//! graphus-bulk import --db <dir> [--nodes <file>]... [--relationships <file>]... [--delimiter <c>] [--batch <n>] [--format csv|gcol]
//! graphus-bulk dump   --db <dir> --nodes-out <file> --relationships-out <file> [--format csv|gcol]
//! ```
//!
//! `import` builds a **fresh** store in `<dir>` (it must not already contain a store) from the given
//! node and relationship files, then prints the measured throughput. `dump` opens an existing store
//! in `<dir>` and writes its nodes and relationships to the two output files in the same format the
//! importer reads (so the pair round-trips).
//!
//! `--format` selects the on-disk file format (default `csv`):
//! - `csv` — the row-oriented `neo4j-admin import`-flavoured CSV (the existing path, unchanged).
//! - `gcol` — the compact, lossless **columnar** format (`rmp` #327): the dumper transcodes its CSV
//!   through [`csv_to_gcol`](graphus_bulk::csv_to_gcol); the importer transcodes the `.gcol` blob back
//!   with [`gcol_to_csv`](graphus_bulk::gcol_to_csv) before feeding the existing `BulkImporter`. The
//!   `.gcol` round-trips to byte-identical CSV, so a graph is preserved exactly across either format.
//!
//! A `<dir>` holds `graph.store` (the block device, a file) and `graph.wal` (the write-ahead log, a
//! segmented directory of an `anchor` + `seg.<base>` files — `rmp` #116), matching the server's
//! on-disk layout.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use graphus_bulk::{
    BulkImporter, DEFAULT_BATCH_SIZE, InputFormatHint, auto_pool_pages_for_input,
    auto_pool_pages_for_store, csv_to_gcol, dump_nodes, dump_relationships, gcol_to_csv,
};
use graphus_core::GraphusError;
use graphus_io::{FileBlockDevice, PAGE_SIZE};
use graphus_storage::RecordStore;
use graphus_storage::recovery::recover_device;
use graphus_wal::{FileLogSink, WalManager};

/// The on-disk file format for a bulk dump/import (the `--format` flag). CSV is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    /// Row-oriented `neo4j-admin import`-flavoured CSV (the original path).
    Csv,
    /// Lossless columnar `.gcol` (`rmp` #327): CSV transcoded through the `graphus-columnar` codecs.
    Gcol,
}

impl Format {
    /// Parses the `--format` value (`csv` | `gcol`), case-insensitively.
    fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "csv" => Ok(Self::Csv),
            "gcol" => Ok(Self::Gcol),
            other => Err(format!("--format must be `csv` or `gcol`, got `{other}`")),
        }
    }
}

/// Environment override for the buffer-pool size (in 8 KiB pages): `0`, empty, or unset ⇒ auto-size.
/// Distinct from the server's `GRAPHUS_BUFFER_POOL_PAGES` because this is a separate offline tool.
const BUFFER_POOL_ENV: &str = "GRAPHUS_BULK_BUFFER_POOL_PAGES";

/// The smallest explicit `--buffer-pool-pages` an operator may pin (mirrors the server's
/// `MIN_BUFFER_POOL_PAGES`); `0` = auto. Below this a pool cannot hold the handful of pages one
/// `create_rel` pins at once, so it is rejected up front with a clear message rather than failing
/// cryptically deep in the load.
const MIN_EXPLICIT_POOL_PAGES: usize = 64;

/// Where a resolved buffer-pool size came from, for the human-readable report line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PoolSource {
    /// Sized automatically from the input/store size and the host RAM (`rmp` #718).
    Auto,
    /// Pinned by the operator via `--buffer-pool-pages` or the env override.
    Explicit,
}

/// Reads and validates the `GRAPHUS_BULK_BUFFER_POOL_PAGES` env override, if set. `Ok(None)` when
/// unset; `Ok(Some(0))` means "explicitly auto".
fn read_env_pool_pages() -> Result<Option<usize>, String> {
    match std::env::var(BUFFER_POOL_ENV) {
        Ok(s) => {
            let t = s.trim();
            if t.is_empty() {
                return Ok(None);
            }
            let v = t.parse::<usize>().map_err(|_| {
                format!("{BUFFER_POOL_ENV} must be a non-negative integer (0 = auto), got {s:?}")
            })?;
            Ok(Some(v))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(format!("{BUFFER_POOL_ENV} is not valid UTF-8"))
        }
    }
}

/// Resolves the buffer-pool page count. Precedence: an explicit `--buffer-pool-pages` (the `flag`)
/// beats the `GRAPHUS_BULK_BUFFER_POOL_PAGES` env, which beats the `auto` closure. A `0` at either
/// explicit layer means "auto". An explicit non-zero value below [`MIN_EXPLICIT_POOL_PAGES`] is
/// rejected. The `auto` closure is only evaluated when no explicit value is pinned (so the RAM/size
/// probe is skipped when the operator has already decided).
fn resolve_pool_pages(
    flag: Option<usize>,
    auto: impl FnOnce() -> usize,
) -> Result<(usize, PoolSource), String> {
    let explicit = match flag {
        Some(v) => Some(v),
        None => read_env_pool_pages()?,
    };
    match explicit {
        None | Some(0) => Ok((auto(), PoolSource::Auto)),
        Some(n) if n < MIN_EXPLICIT_POOL_PAGES => Err(format!(
            "--buffer-pool-pages must be 0 (auto) or >= {MIN_EXPLICIT_POOL_PAGES}, got {n}"
        )),
        Some(n) => Ok((n, PoolSource::Explicit)),
    }
}

/// Sums the on-disk byte size of every input file, best-effort: a file whose metadata cannot be read
/// contributes 0 (and surfaces its own error when the importer reads it). Used only to size the
/// buffer pool, so a slightly-off total merely nudges the pool — it never affects correctness.
fn total_input_bytes(nodes: &[PathBuf], rels: &[PathBuf]) -> u64 {
    nodes
        .iter()
        .chain(rels.iter())
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum()
}

/// A human-readable "N pages (M MiB)" for the report line.
fn pool_pages_human(pool_pages: usize) -> String {
    let mib = (pool_pages as f64 * PAGE_SIZE as f64) / (1024.0 * 1024.0);
    format!("{pool_pages} pages ({mib:.1} MiB)")
}

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("graphus-bulk: error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Parses the subcommand and dispatches. Returns a human-readable error string on failure.
fn run(args: Vec<String>) -> Result<(), String> {
    let mut args = args.into_iter();
    let Some(subcommand) = args.next() else {
        return Err(usage());
    };
    let rest: Vec<String> = args.collect();
    match subcommand.as_str() {
        "import" => cmd_import(rest),
        "dump" => cmd_dump(rest),
        "-h" | "--help" | "help" => {
            println!("{}", usage());
            Ok(())
        }
        other => Err(format!("unknown subcommand `{other}`\n\n{}", usage())),
    }
}

/// The usage text.
fn usage() -> String {
    "graphus-bulk — offline bulk import / whole-graph dump (CSV or columnar `.gcol`)\n\n\
     USAGE:\n  \
       graphus-bulk import --db <dir> [--nodes <file>]... [--relationships <file>]... \
     [--delimiter <c>] [--batch <n>] [--format csv|gcol] [--buffer-pool-pages <n>]\n  \
       graphus-bulk dump   --db <dir> --nodes-out <file> --relationships-out <file> \
     [--format csv|gcol] [--buffer-pool-pages <n>]\n\n\
     --format selects the file format (default csv); `gcol` is the lossless columnar format.\n\n\
     --buffer-pool-pages <n> pins the in-RAM buffer pool to n 8-KiB pages; 0 (the default) auto-\n  \
       sizes it to the store the load builds, bounded by host RAM (rmp #718 — a fixed small pool made\n  \
       large imports quadratic). Env override: GRAPHUS_BULK_BUFFER_POOL_PAGES (0 = auto).\n\n\
     DURABILITY — IMPORTANT:\n  \
       `import` is NON-ATOMIC. It commits in batches (--batch, default per build), so a crash or\n  \
       error mid-import leaves a PARTIALLY loaded store containing all batches committed before the\n  \
       failure. Import is not a transaction; there is no automatic rollback of a partial load.\n  \
       On a failed/partial import, DELETE the --db directory and re-run the import from scratch.\n  \
       A fully successful import is durable: the store, WAL, and their directory entries are fsynced\n  \
       before `import` reports success.\n"
        .to_owned()
}

/// `import`: build a fresh store and load the node/relationship CSV files into it.
///
/// # Durability contract (NON-ATOMIC — ratified, `rmp` #403)
///
/// Import is **not** a single transaction. It commits in batches (`--batch`), so a crash or an error
/// part-way through leaves a **partially loaded** store: every batch committed before the failure is
/// durable, the torn batch and everything after it is absent. There is **no automatic rollback**. The
/// ratified operator procedure on a failed/partial load is to **delete the `--db` directory and
/// re-run the import** (the importer refuses to load into a non-empty store, so a stale partial load
/// must be removed first). A fully successful import is durable end-to-end: the store contents are
/// flushed and the `--db` directory entries are `fsync`ed before success is reported (`rmp` #404).
fn cmd_import(args: Vec<String>) -> Result<(), String> {
    let mut db: Option<PathBuf> = None;
    let mut nodes: Vec<PathBuf> = Vec::new();
    let mut rels: Vec<PathBuf> = Vec::new();
    let mut delimiter = b',';
    let mut batch = DEFAULT_BATCH_SIZE;
    let mut format = Format::Csv;
    let mut buffer_pool_flag: Option<usize> = None;

    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--db" => db = Some(PathBuf::from(next_value(&mut it, "--db")?)),
            "--nodes" => nodes.push(PathBuf::from(next_value(&mut it, "--nodes")?)),
            "--relationships" => rels.push(PathBuf::from(next_value(&mut it, "--relationships")?)),
            "--delimiter" => delimiter = parse_delimiter(&next_value(&mut it, "--delimiter")?)?,
            "--format" => format = Format::parse(&next_value(&mut it, "--format")?)?,
            "--batch" => {
                batch = next_value(&mut it, "--batch")?
                    .parse()
                    .map_err(|_| "--batch expects a positive integer".to_owned())?;
            }
            "--buffer-pool-pages" => {
                buffer_pool_flag = Some(
                    next_value(&mut it, "--buffer-pool-pages")?
                        .parse()
                        .map_err(|_| {
                            "--buffer-pool-pages expects a non-negative integer (0 = auto)"
                                .to_owned()
                        })?,
                );
            }
            other => return Err(format!("unexpected argument `{other}`\n\n{}", usage())),
        }
    }
    let db = db.ok_or_else(|| "import requires --db <dir>".to_owned())?;
    if nodes.is_empty() {
        return Err("import requires at least one --nodes <file>".to_owned());
    }

    // Size the buffer pool to the store this load will build (`rmp` #718): the relationship phase is
    // random-access over the whole store, so a fixed small pool thrashes once the store outgrows it,
    // turning the import quadratic. `resolve_pool_pages` honours an explicit `--buffer-pool-pages` /
    // env override, else auto-sizes from the total input bytes + host RAM.
    let input_bytes = total_input_bytes(&nodes, &rels);
    let fmt_hint = match format {
        Format::Csv => InputFormatHint::Csv,
        Format::Gcol => InputFormatHint::Gcol,
    };
    let mem = graphus_sysres::memory();
    let (pool_pages, pool_source) = resolve_pool_pages(buffer_pool_flag, || {
        auto_pool_pages_for_input(input_bytes, fmt_hint, mem)
    })?;
    println!(
        "buffer pool: {}{}",
        pool_pages_human(pool_pages),
        match pool_source {
            PoolSource::Auto => format!(
                " — auto-sized (rmp #718) for a ~{:.1} MiB {} load",
                input_bytes as f64 / (1024.0 * 1024.0),
                match format {
                    Format::Csv => "CSV",
                    Format::Gcol => "gcol",
                }
            ),
            PoolSource::Explicit => " — operator override".to_owned(),
        }
    );

    let store = create_fresh_store(&db, pool_pages).map_err(|e| e.to_string())?;
    let mut importer = BulkImporter::new(store, batch, delimiter);

    // Load all files. Any failure here may have left a PARTIAL (some batches committed) load on disk
    // — import is non-atomic by ratified contract (`rmp` #403) — so the operator-facing error spells
    // out the recovery procedure (delete `--db`, re-run) instead of leaving a cryptic mid-load error.
    let load_result = (|| -> Result<(), String> {
        for path in &nodes {
            let csv = read_as_csv(path, format)?;
            importer
                .import_nodes(csv.as_slice())
                .map_err(|e| format!("importing nodes from {}: {e}", path.display()))?;
        }
        for path in &rels {
            let csv = read_as_csv(path, format)?;
            importer
                .import_relationships(csv.as_slice())
                .map_err(|e| format!("importing relationships from {}: {e}", path.display()))?;
        }
        Ok(())
    })();
    if let Err(e) = load_result {
        return Err(format!(
            "{e}\n\
             import FAILED — the load is non-atomic, so `{}` may now hold a PARTIAL store (the batches\n\
             committed before this error are on disk). Delete that directory and re-run the import:\n  \
               rm -rf {}\n",
            db.display(),
            db.display()
        ));
    }

    let (mut store, stats) = importer.finish();
    store.flush().map_err(|e| format!("flushing store: {e}"))?;

    // Durability (`rmp` #404): the store + WAL files were created and written inside `--db`, but the
    // *directory entries* naming them are not guaranteed durable until the directory itself is
    // `fsync`ed (POSIX: an `fsync` of a file does not harden the entry that names it). Without this,
    // a crash right after a successful import could leave `--db` with no entry for `graph.store` /
    // `graph.wal` even though their contents reached disk. `store.flush()` above already made the
    // file contents durable; harden the directory entries now so the imported store is self-contained.
    graphus_io::sync_dir(&db)
        .map_err(|e| format!("hardening db directory {}: {e}", db.display()))?;

    println!(
        "imported {} nodes, {} relationships, {} properties",
        stats.nodes, stats.relationships, stats.properties
    );
    println!(
        "throughput: {:.0} nodes/s ({:.3}s), {:.0} rels/s ({:.3}s)",
        stats.nodes_per_sec(),
        stats.node_seconds,
        stats.rels_per_sec(),
        stats.rel_seconds,
    );
    Ok(())
}

/// `dump`: open an existing store and serialise it to the two output files (CSV or `.gcol`).
fn cmd_dump(args: Vec<String>) -> Result<(), String> {
    let mut db: Option<PathBuf> = None;
    let mut nodes_out: Option<PathBuf> = None;
    let mut rels_out: Option<PathBuf> = None;
    let mut format = Format::Csv;
    let mut buffer_pool_flag: Option<usize> = None;

    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--db" => db = Some(PathBuf::from(next_value(&mut it, "--db")?)),
            "--nodes-out" => nodes_out = Some(PathBuf::from(next_value(&mut it, "--nodes-out")?)),
            "--relationships-out" => {
                rels_out = Some(PathBuf::from(next_value(&mut it, "--relationships-out")?));
            }
            "--format" => format = Format::parse(&next_value(&mut it, "--format")?)?,
            "--buffer-pool-pages" => {
                buffer_pool_flag = Some(
                    next_value(&mut it, "--buffer-pool-pages")?
                        .parse()
                        .map_err(|_| {
                            "--buffer-pool-pages expects a non-negative integer (0 = auto)"
                                .to_owned()
                        })?,
                );
            }
            other => return Err(format!("unexpected argument `{other}`\n\n{}", usage())),
        }
    }
    let db = db.ok_or_else(|| "dump requires --db <dir>".to_owned())?;
    let nodes_out = nodes_out.ok_or_else(|| "dump requires --nodes-out <file>".to_owned())?;
    let rels_out = rels_out.ok_or_else(|| "dump requires --relationships-out <file>".to_owned())?;

    // Size the read pool to the existing store (`rmp` #718): the store file's byte size is known
    // exactly, so no estimate is needed. Honours the same `--buffer-pool-pages` / env override.
    let (device_file, _) = db_files(&db);
    let store_bytes = std::fs::metadata(&device_file)
        .map(|m| m.len())
        .unwrap_or(0);
    let mem = graphus_sysres::memory();
    let (pool_pages, _) = resolve_pool_pages(buffer_pool_flag, || {
        auto_pool_pages_for_store(store_bytes, mem)
    })?;

    let mut store = open_store(&db, pool_pages).map_err(|e| e.to_string())?;

    // Dump each entity kind to an in-memory CSV buffer (the canonical serialisation), then write it
    // out in the requested format. The CSV path writes the buffer verbatim; the gcol path transcodes
    // it through the columnar codecs.
    let mut node_csv = Vec::new();
    dump_nodes(&mut store, &mut node_csv).map_err(|e| format!("dumping nodes: {e}"))?;
    write_dump(&nodes_out, &node_csv, format)?;

    let mut rel_csv = Vec::new();
    dump_relationships(&mut store, &mut rel_csv)
        .map_err(|e| format!("dumping relationships: {e}"))?;
    write_dump(&rels_out, &rel_csv, format)?;

    println!(
        "dumped graph ({}) to {} and {}",
        match format {
            Format::Csv => "csv",
            Format::Gcol => "gcol",
        },
        nodes_out.display(),
        rels_out.display()
    );
    Ok(())
}

/// The CSV delimiter the dumper emits and the importer reads (`csv::WriterBuilder::new()` default,
/// matching [`dump`](graphus_bulk::dump_nodes)).
const DUMP_DELIMITER: u8 = b',';

/// Reads a dump file as CSV bytes, transcoding from `.gcol` when `format` is [`Format::Gcol`].
fn read_as_csv(path: &Path, format: Format) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("opening {}: {e}", path.display()))?;
    match format {
        Format::Csv => Ok(bytes),
        Format::Gcol => {
            gcol_to_csv(&bytes).map_err(|e| format!("decoding columnar {}: {e}", path.display()))
        }
    }
}

/// Writes a dump file, transcoding the in-memory CSV to `.gcol` when `format` is [`Format::Gcol`].
///
/// The write is **atomic and durable** (`rmp` #406): the bytes are written to a fresh sibling temp
/// file, `fsync`ed, then `rename(2)`d over `path` with a directory `fsync`. A crash at any point
/// therefore leaves `path` as either the old whole image or the new whole image — a partial/torn
/// write can never destroy a pre-existing dump (the failure mode of an in-place `std::fs::write`).
fn write_dump(path: &Path, csv: &[u8], format: Format) -> Result<(), String> {
    use std::io::Write;

    let bytes = match format {
        Format::Csv => csv.to_vec(),
        Format::Gcol => csv_to_gcol(csv, DUMP_DELIMITER)
            .map_err(|e| format!("encoding columnar {}: {e}", path.display()))?,
    };
    graphus_io::atomic_replace_file(path, |tmp| {
        let mut f = std::fs::File::create(tmp).map_err(|e| {
            GraphusError::Storage(format!("creating temp dump {}: {e}", tmp.display()))
        })?;
        f.write_all(&bytes).map_err(|e| {
            GraphusError::Storage(format!("writing temp dump {}: {e}", tmp.display()))
        })?;
        // Make the content durable before the rename, so the renamed entry never names torn bytes.
        f.sync_all()
            .map_err(|e| GraphusError::Storage(format!("syncing temp dump {}: {e}", tmp.display())))
    })
    .map_err(|e| format!("writing {}: {e}", path.display()))
}

/// The on-disk file pair inside a `--db` directory.
fn db_files(db: &Path) -> (PathBuf, PathBuf) {
    (db.join("graph.store"), db.join("graph.wal"))
}

/// Creates a **fresh** store in `db` (the directory is created if missing); errors if a store already
/// exists there (the bulk importer loads into an empty DB).
fn create_fresh_store(
    db: &Path,
    pool_pages: usize,
) -> Result<RecordStore<FileBlockDevice, FileLogSink>, GraphusError> {
    std::fs::create_dir_all(db)
        .map_err(|e| GraphusError::Storage(format!("creating db dir {}: {e}", db.display())))?;
    let (device_file, wal_file) = db_files(db);
    if device_file.metadata().map(|m| m.len() > 0).unwrap_or(false) {
        return Err(GraphusError::Storage(format!(
            "{} already contains a store; bulk import requires an empty DB",
            db.display()
        )));
    }
    let device = FileBlockDevice::open(&device_file)?;
    let wal = WalManager::create(
        FileLogSink::open(&wal_file)
            .map_err(|e| GraphusError::Storage(format!("creating WAL: {e}")))?,
    )
    .map_err(|e| GraphusError::Storage(format!("creating WAL manager: {e}")))?;
    let store = RecordStore::create(device, wal, pool_pages, 1)?;
    // Harden the directory so the freshly-created `graph.store` / `graph.wal` entries are durable
    // even before any data is written (`rmp` #404); the final `sync_dir` in `cmd_import` re-hardens
    // after the import completes.
    graphus_io::sync_dir(db)
        .map_err(|e| GraphusError::Storage(format!("hardening db dir {}: {e}", db.display())))?;
    Ok(store)
}

/// Opens an existing store in `db` (recovering the WAL onto the device first), for the dumper. The
/// `pool_pages` frame count is sized by the caller ([`auto_pool_pages_for_store`]).
fn open_store(
    db: &Path,
    pool_pages: usize,
) -> Result<RecordStore<FileBlockDevice, FileLogSink>, GraphusError> {
    let (device_file, wal_file) = db_files(db);
    if !device_file.metadata().map(|m| m.len() > 0).unwrap_or(false) {
        return Err(GraphusError::Storage(format!(
            "no store found in {}",
            db.display()
        )));
    }
    let mut device = FileBlockDevice::open(&device_file)?;
    let mut wal = WalManager::open(
        FileLogSink::open(&wal_file)
            .map_err(|e| GraphusError::Storage(format!("opening WAL: {e}")))?,
    )
    .map_err(|e| GraphusError::Storage(format!("opening WAL manager: {e}")))?;
    recover_device(&mut wal, &mut device)?;
    let wal = WalManager::open(
        FileLogSink::open(&wal_file)
            .map_err(|e| GraphusError::Storage(format!("reopening WAL: {e}")))?,
    )
    .map_err(|e| GraphusError::Storage(format!("reopening WAL manager: {e}")))?;
    RecordStore::open(device, wal, pool_pages)
}

/// Consumes the next CLI value after a flag, erroring if it is missing.
fn next_value(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} requires a value"))
}

/// Parses a one-character delimiter argument into its byte.
fn parse_delimiter(s: &str) -> Result<u8, String> {
    let mut chars = s.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) if c.is_ascii() => Ok(c as u8),
        _ => Err(format!(
            "--delimiter must be a single ASCII character, got `{s}`"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-cleaning unique temp directory for a test.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let p = std::env::temp_dir()
                .join(format!("graphus-bulk-{tag}-{nanos}-{}", std::process::id()));
            std::fs::create_dir_all(&p).expect("mkdir");
            Self(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn write_file(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).expect("seed file");
    }

    /// #406: a successful `dump` write is atomic and durable, and a *failed* `write_dump` leaves any
    /// pre-existing target byte-for-byte intact (the in-place `std::fs::write` truncate-then-write
    /// hazard is gone — `atomic_replace_file` aborts on the temp without touching `target`).
    #[test]
    fn write_dump_is_atomic_and_preserves_target_on_failure() {
        let dir = TempDir::new("dump");
        let target = dir.0.join("nodes.csv");

        // A successful write lands the new content.
        write_dump(&target, b":ID\n1\n", Format::Csv).expect("first dump");
        assert_eq!(std::fs::read(&target).unwrap(), b":ID\n1\n");

        // Seed a known PRIOR dump, then force a failing write_dump by making the parent directory
        // read-only so the temp-sibling create fails. The prior target must survive untouched.
        write_file(&target, b"PRIOR-DUMP-CONTENTS");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&dir.0).unwrap().permissions();
            perm.set_mode(0o500); // r-x: cannot create the temp sibling
            std::fs::set_permissions(&dir.0, perm).unwrap();

            let res = write_dump(&target, b":ID\n2\n", Format::Csv);

            // Restore write permission so the prior content can be read back / cleaned up.
            let mut perm = std::fs::metadata(&dir.0).unwrap().permissions();
            perm.set_mode(0o700);
            std::fs::set_permissions(&dir.0, perm).unwrap();

            assert!(
                res.is_err(),
                "the dump must fail when the temp cannot be created"
            );
            assert_eq!(
                std::fs::read(&target).unwrap(),
                b"PRIOR-DUMP-CONTENTS",
                "a failed dump must leave the pre-existing target byte-for-byte intact"
            );
        }
    }

    /// #404: `create_fresh_store` + a full `cmd_import` produce a `--db` directory whose entries are
    /// durable — verified by (a) `sync_dir` succeeding on the directory (the exact call `cmd_import`
    /// makes) and (b) the store reopening cleanly afterwards (entries + contents are consistent).
    #[test]
    fn cmd_import_fsyncs_the_db_dir_and_reopens() {
        let dir = TempDir::new("import");
        let nodes = dir.0.join("nodes.csv");
        write_file(
            &nodes,
            b":ID,:LABEL,name:string\n1,Person,Alice\n2,Person,Bob\n",
        );
        let db = dir.0.join("db");

        cmd_import(vec![
            "--db".into(),
            db.to_string_lossy().into_owned(),
            "--nodes".into(),
            nodes.to_string_lossy().into_owned(),
            "--batch".into(),
            "1".into(),
        ])
        .expect("import");

        // The directory `cmd_import` hardened must be a real, fsync-able directory.
        graphus_io::sync_dir(&db).expect("db dir must be fsync-able (it was hardened on import)");

        // And the imported store reopens cleanly — proving the directory entries and file contents
        // that `sync_dir` made durable are present and consistent.
        let store = open_store(&db, 256).expect("reopen imported store");
        assert_eq!(store.scan_node_ids().expect("scan").len(), 2);
    }

    /// #718: an explicit `--buffer-pool-pages` below the minimum is rejected up front (not left to
    /// fail cryptically deep in the load), while `0` and a valid value are accepted.
    #[test]
    fn resolve_pool_pages_precedence_and_validation() {
        // 0 (explicit auto) → the auto closure is used.
        let (pages, src) = resolve_pool_pages(Some(0), || 4242).expect("auto");
        assert_eq!((pages, src), (4242, PoolSource::Auto));
        // A valid explicit value wins verbatim.
        let (pages, src) = resolve_pool_pages(Some(8192), || 4242).expect("explicit");
        assert_eq!((pages, src), (8192, PoolSource::Explicit));
        // No flag and no env → auto (env is not set in the test process).
        let (pages, src) = resolve_pool_pages(None, || 777).expect("no-flag auto");
        assert_eq!((pages, src), (777, PoolSource::Auto));
        // A non-zero value below the minimum is rejected.
        let err = resolve_pool_pages(Some(MIN_EXPLICIT_POOL_PAGES - 1), || 1).unwrap_err();
        assert!(err.contains("--buffer-pool-pages"), "clear error: {err}");
    }

    /// #718: a full `cmd_import` with `--buffer-pool-pages 0` (auto) still produces a store that
    /// reopens with the right node/relationship counts — the adaptive pool changes only the RAM
    /// working set, never the durable result or the recovery contract.
    #[test]
    fn cmd_import_auto_pool_reopens_with_correct_counts() {
        let dir = TempDir::new("autopool");
        let nodes = dir.0.join("nodes.csv");
        write_file(
            &nodes,
            b":ID,:LABEL,name:string\n1,Person,Alice\n2,Person,Bob\n3,Person,Cara\n",
        );
        let rels = dir.0.join("rels.csv");
        write_file(
            &rels,
            b":START_ID,:END_ID,:TYPE\n1,2,KNOWS\n2,3,KNOWS\n1,3,KNOWS\n",
        );
        let db = dir.0.join("db");

        cmd_import(vec![
            "--db".into(),
            db.to_string_lossy().into_owned(),
            "--nodes".into(),
            nodes.to_string_lossy().into_owned(),
            "--relationships".into(),
            rels.to_string_lossy().into_owned(),
            "--buffer-pool-pages".into(),
            "0".into(), // auto
            "--batch".into(),
            "2".into(),
        ])
        .expect("auto-pool import");

        let store = open_store(&db, 256).expect("reopen");
        assert_eq!(store.scan_node_ids().expect("scan nodes").len(), 3);
        assert_eq!(store.scan_rel_ids().expect("scan rels").len(), 3);
    }

    /// #403: the operator-facing `--help`/usage text documents the NON-ATOMIC import contract and the
    /// delete-and-retry recovery procedure.
    #[test]
    fn usage_documents_the_non_atomic_import_contract() {
        let u = usage();
        assert!(
            u.contains("NON-ATOMIC"),
            "usage must call out non-atomic import"
        );
        assert!(
            u.to_lowercase().contains("delete") && u.contains("--db"),
            "usage must tell the operator to delete --db and re-run on a partial load"
        );
    }
}
