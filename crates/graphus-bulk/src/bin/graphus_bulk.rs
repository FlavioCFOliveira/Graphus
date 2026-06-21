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
    BulkImporter, DEFAULT_BATCH_SIZE, csv_to_gcol, dump_nodes, dump_relationships, gcol_to_csv,
};
use graphus_core::GraphusError;
use graphus_io::FileBlockDevice;
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

/// Buffer-pool frames for the bulk session. A bulk load is sequential-write heavy; a modest pool is
/// plenty (pages are written through the WAL and flushed at commit).
const POOL_PAGES: usize = 256;

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
     [--delimiter <c>] [--batch <n>] [--format csv|gcol]\n  \
       graphus-bulk dump   --db <dir> --nodes-out <file> --relationships-out <file> \
     [--format csv|gcol]\n\n\
     --format selects the file format (default csv); `gcol` is the lossless columnar format.\n"
        .to_owned()
}

/// `import`: build a fresh store and load the node/relationship CSV files into it.
fn cmd_import(args: Vec<String>) -> Result<(), String> {
    let mut db: Option<PathBuf> = None;
    let mut nodes: Vec<PathBuf> = Vec::new();
    let mut rels: Vec<PathBuf> = Vec::new();
    let mut delimiter = b',';
    let mut batch = DEFAULT_BATCH_SIZE;
    let mut format = Format::Csv;

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
            other => return Err(format!("unexpected argument `{other}`\n\n{}", usage())),
        }
    }
    let db = db.ok_or_else(|| "import requires --db <dir>".to_owned())?;
    if nodes.is_empty() {
        return Err("import requires at least one --nodes <file>".to_owned());
    }

    let store = create_fresh_store(&db).map_err(|e| e.to_string())?;
    let mut importer = BulkImporter::new(store, batch, delimiter);

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

    let (mut store, stats) = importer.finish();
    store.flush().map_err(|e| format!("flushing store: {e}"))?;

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

    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--db" => db = Some(PathBuf::from(next_value(&mut it, "--db")?)),
            "--nodes-out" => nodes_out = Some(PathBuf::from(next_value(&mut it, "--nodes-out")?)),
            "--relationships-out" => {
                rels_out = Some(PathBuf::from(next_value(&mut it, "--relationships-out")?));
            }
            "--format" => format = Format::parse(&next_value(&mut it, "--format")?)?,
            other => return Err(format!("unexpected argument `{other}`\n\n{}", usage())),
        }
    }
    let db = db.ok_or_else(|| "dump requires --db <dir>".to_owned())?;
    let nodes_out = nodes_out.ok_or_else(|| "dump requires --nodes-out <file>".to_owned())?;
    let rels_out = rels_out.ok_or_else(|| "dump requires --relationships-out <file>".to_owned())?;

    let mut store = open_store(&db).map_err(|e| e.to_string())?;

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
fn write_dump(path: &Path, csv: &[u8], format: Format) -> Result<(), String> {
    let bytes = match format {
        Format::Csv => csv.to_vec(),
        Format::Gcol => csv_to_gcol(csv, DUMP_DELIMITER)
            .map_err(|e| format!("encoding columnar {}: {e}", path.display()))?,
    };
    std::fs::write(path, &bytes).map_err(|e| format!("creating {}: {e}", path.display()))
}

/// The on-disk file pair inside a `--db` directory.
fn db_files(db: &Path) -> (PathBuf, PathBuf) {
    (db.join("graph.store"), db.join("graph.wal"))
}

/// Creates a **fresh** store in `db` (the directory is created if missing); errors if a store already
/// exists there (the bulk importer loads into an empty DB).
fn create_fresh_store(
    db: &Path,
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
    RecordStore::create(device, wal, POOL_PAGES, 1)
}

/// Opens an existing store in `db` (recovering the WAL onto the device first), for the dumper.
fn open_store(db: &Path) -> Result<RecordStore<FileBlockDevice, FileLogSink>, GraphusError> {
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
    RecordStore::open(device, wal, POOL_PAGES)
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
