//! End-to-end tests for the `LOAD CSV` source clause over the **real** persistent record store
//! (`04-technical-design.md` §7.4; FR-BK; `rmp` task #22).
//!
//! `LOAD CSV [WITH HEADERS] FROM <url> AS <var> [FIELDTERMINATOR <c>]` is a driving source clause:
//! each CSV record becomes one row bound to `<var>` (a `List` of fields, or a `Map{header -> value}`
//! with headers), feeding the downstream clauses. These tests run the full pipeline
//! (`parse → analyze → plan → execute`) against a [`RecordStoreGraph`] wrapping a real
//! [`graphus_storage::RecordStore`], proving that:
//!
//! - the header-less form ingests a temp CSV: `LOAD CSV FROM '<file>' AS row CREATE (:N {v: row[0]})`
//!   really persists nodes whose property is the CSV field;
//! - the `WITH HEADERS` form binds a `Map{header -> value}` and ingests typed-by-position properties;
//! - a custom `FIELDTERMINATOR` is honored;
//! - the ingestion is transactional (runs inside the statement transaction, committed by the seam);
//! - error cases — a missing file and a non-`file` URL scheme — surface a runtime error and roll back
//!   rather than corrupting the store.

use graphus_core::{TxnId, Value};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::{ExecError, execute};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::record_graph::RecordStoreGraph;
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

use graphus_cypher::loadcsv::{CsvImportPolicy, set_global_import_policy};
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

// =================================================================================================
// Harness
// =================================================================================================

/// The per-test-binary import root: a dedicated temp subdirectory `LOAD CSV` is confined to
/// (`SEC-189`). Created and installed as the process-global import policy on first use, so every
/// `LOAD CSV` in this binary reads only files written under this root by [`write_temp_csv`].
fn import_root() -> &'static PathBuf {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        let root = std::env::temp_dir().join(format!("graphus-loadcsv-import-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("create import root");
        // Install the confined policy once for this test binary. `set` may already be set by a
        // concurrent test thread — that is fine, the root is identical.
        let canonical = std::fs::canonicalize(&root).unwrap_or_else(|_| root.clone());
        let _ = set_global_import_policy(CsvImportPolicy::with_import_root(canonical.clone()));
        canonical
    })
}

/// A fresh, empty record store over an in-memory DST device + log.
fn fresh_store() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 64, 1).expect("create store")
}

/// Compiles `src` to a physical plan against the empty index catalog.
fn compile(src: &str) -> graphus_cypher::physical::PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

/// Runs `src` over `store` in one transaction, asserting no deferred storage error, committing, and
/// returning `(rows, store)`.
fn run_commit(src: &str, store: Store, txn: u64) -> (Vec<Row>, Store) {
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = RecordStoreGraph::begin(store, TxnId(txn));
    let rows = {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect rows")
    };
    assert!(
        !graph.has_error(),
        "unexpected captured error: {:?}",
        graph.take_error()
    );
    let store = graph.commit().expect("commit");
    (rows, store)
}

/// Runs `src` over `store` expecting the cursor itself to fail at runtime (a `LOAD CSV` runtime
/// error such as a missing file / bad scheme), rolling back. Returns the error.
fn run_expect_exec_error(src: &str, store: Store, txn: u64) -> ExecError {
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = RecordStoreGraph::begin(store, TxnId(txn));
    let err = {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor
            .collect_all()
            .expect_err("expected a runtime LOAD CSV error")
    };
    // The statement rolls back: nothing the failed LOAD CSV pipeline created is committed.
    graph.rollback().expect("rollback");
    err
}

/// Writes `contents` to a uniquely-named file **inside the import root** (`SEC-189` confinement) and
/// returns its path *relative to that root* — i.e. the bare filename. Queries reference it relative
/// to the import directory, exactly as a confined `LOAD CSV` must. The file is left for the OS temp
/// reaper; the test reads it back through `LOAD CSV`.
fn write_temp_csv(contents: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = format!("graphus-loadcsv-{}-{n}.csv", std::process::id());
    let path = import_root().join(&name);
    let mut f = std::fs::File::create(&path).expect("create temp csv");
    f.write_all(contents.as_bytes()).expect("write temp csv");
    f.flush().expect("flush temp csv");
    PathBuf::from(name)
}

/// Cypher single-quoted string literal for a filesystem path, escaping `\` and `'` so a Windows path
/// or a quote in the path survives the lexer.
fn cypher_str(path: &std::path::Path) -> String {
    let s = path.to_string_lossy();
    let escaped = s.replace('\\', "\\\\").replace('\'', "\\'");
    format!("'{escaped}'")
}

/// Sorts a column of integer values ascending (CSV ingestion order is file order, but a re-read
/// `MATCH (n)` returns store order; sorting makes the assertion order-independent).
fn sorted_ints(rows: &[Row], col: &str) -> Vec<i64> {
    let mut v: Vec<i64> = rows
        .iter()
        .map(|r| match r.value(col) {
            Value::Integer(i) => i,
            other => panic!("expected an integer in column `{col}`, got {other:?}"),
        })
        .collect();
    v.sort_unstable();
    v
}

fn sorted_strings(rows: &[Row], col: &str) -> Vec<String> {
    let mut v: Vec<String> = rows
        .iter()
        .map(|r| match r.value(col) {
            Value::String(s) => s,
            other => panic!("expected a string in column `{col}`, got {other:?}"),
        })
        .collect();
    v.sort();
    v
}

// =================================================================================================
// LOAD CSV without headers — a List per record
// =================================================================================================

#[test]
fn load_csv_no_headers_ingests_list_rows_into_the_store() {
    let csv = write_temp_csv("alice,30\nbob,25\ncarol,41\n");
    let store = fresh_store();

    // Each record is a List `row`; `row[0]` is the name, `toInteger(row[1])` the age.
    let src = format!(
        "LOAD CSV FROM {} AS row CREATE (:Person {{name: row[0], age: toInteger(row[1])}})",
        cypher_str(&csv)
    );
    // `LOAD CSV ... CREATE` has a `Create` plan root (the `CREATE` clause wraps the `LoadCsv` source
    // as its input), so it is a write with no `RETURN` and yields **zero** rows (openCypher write
    // cardinality, rmp #97) — the ingest of one node per record is a summary-only side effect.
    let (created, store) = run_commit(&src, store, 1);
    assert_eq!(created.len(), 0, "a write without RETURN echoes no rows");

    // The three rows were really persisted: read them back in a new transaction.
    let (rows, store) = run_commit("MATCH (p:Person) RETURN p.name AS name", store, 2);
    assert_eq!(rows.len(), 3, "three records ingested");
    assert_eq!(sorted_strings(&rows, "name"), ["alice", "bob", "carol"]);

    let (rows, _store) = run_commit("MATCH (p:Person) RETURN p.age AS age", store, 3);
    assert_eq!(sorted_ints(&rows, "age"), [25, 30, 41]);
}

#[test]
fn load_csv_streams_a_large_file_without_slurping() {
    // 5_000 records: proves the streaming reader ingests a multi-thousand-row file inside one
    // transaction (the catalog scales past 1000 pages — task #51 — so this commits fine).
    let mut contents = String::new();
    for i in 0..5_000 {
        contents.push_str(&format!("node{i},{i}\n"));
    }
    let csv = write_temp_csv(&contents);
    let store = fresh_store();

    let src = format!(
        "LOAD CSV FROM {} AS row CREATE (:Item {{k: toInteger(row[1])}})",
        cypher_str(&csv)
    );
    // A write without `RETURN` echoes no rows (rmp #97); the 5_000-record ingest is a side effect,
    // verified below by counting the persisted nodes.
    let (created, store) = run_commit(&src, store, 1);
    assert_eq!(created.len(), 0, "a write without RETURN echoes no rows");

    let (rows, _store) = run_commit("MATCH (n:Item) RETURN count(n) AS c", store, 2);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].value("c"),
        Value::Integer(5_000),
        "all records ingested in one transaction"
    );
}

// =================================================================================================
// LOAD CSV WITH HEADERS — a Map per record
// =================================================================================================

#[test]
fn load_csv_with_headers_ingests_map_rows() {
    let csv = write_temp_csv("name,age\nalice,30\nbob,25\n");
    let store = fresh_store();

    // `row` is a Map{header -> value}; `row.name` / `row.age` access by header.
    let src = format!(
        "LOAD CSV WITH HEADERS FROM {} AS row \
         CREATE (:Person {{name: row.name, age: toInteger(row.age)}})",
        cypher_str(&csv)
    );
    let (_created, store) = run_commit(&src, store, 1);

    let (rows, store) = run_commit("MATCH (p:Person) RETURN p.name AS name", store, 2);
    assert_eq!(sorted_strings(&rows, "name"), ["alice", "bob"]);
    let (rows, _store) = run_commit("MATCH (p:Person) RETURN p.age AS age", store, 3);
    assert_eq!(sorted_ints(&rows, "age"), [25, 30]);
}

#[test]
fn load_csv_with_headers_short_record_maps_missing_field_to_null() {
    // The second record has only the name column; `age` must come back as null.
    let csv = write_temp_csv("name,age\nalice,30\nbob\n");
    let store = fresh_store();

    let src = format!(
        "LOAD CSV WITH HEADERS FROM {} AS row RETURN row.name AS name, row.age AS age",
        cypher_str(&csv)
    );
    let (rows, _store) = run_commit(&src, store, 1);
    assert_eq!(rows.len(), 2);
    // Rows preserve file order for a leading LOAD CSV (a single driving row, streamed in order).
    assert_eq!(rows[0].value("name"), Value::String("alice".to_owned()));
    assert_eq!(rows[0].value("age"), Value::String("30".to_owned()));
    assert_eq!(rows[1].value("name"), Value::String("bob".to_owned()));
    assert_eq!(rows[1].value("age"), Value::Null, "missing field → null");
}

// =================================================================================================
// FIELDTERMINATOR
// =================================================================================================

#[test]
fn load_csv_honors_a_custom_field_terminator() {
    let csv = write_temp_csv("alice;30\nbob;25\n");
    let store = fresh_store();

    let src = format!(
        "LOAD CSV FROM {} AS row FIELDTERMINATOR ';' \
         CREATE (:Person {{name: row[0], age: toInteger(row[1])}})",
        cypher_str(&csv)
    );
    let (_created, store) = run_commit(&src, store, 1);

    let (rows, _store) = run_commit("MATCH (p:Person) RETURN p.name AS name", store, 2);
    assert_eq!(sorted_strings(&rows, "name"), ["alice", "bob"]);
}

#[test]
fn load_csv_with_headers_and_tab_terminator() {
    let csv = write_temp_csv("name\tage\nalice\t30\n");
    let store = fresh_store();

    let src = format!(
        "LOAD CSV WITH HEADERS FROM {} AS row FIELDTERMINATOR '\\t' RETURN row.name AS name",
        cypher_str(&csv)
    );
    let (rows, _store) = run_commit(&src, store, 1);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("name"), Value::String("alice".to_owned()));
}

// =================================================================================================
// file:// URL form
// =================================================================================================

#[test]
fn load_csv_accepts_a_file_url() {
    let csv = write_temp_csv("x\n1\n2\n");
    let store = fresh_store();
    // A `file://` URL of the same absolute path (temp_dir is absolute on every supported OS).
    let url = format!("file://{}", csv.to_string_lossy());
    let escaped = url.replace('\\', "\\\\").replace('\'', "\\'");
    let src = format!("LOAD CSV WITH HEADERS FROM '{escaped}' AS row RETURN toInteger(row.x) AS v");
    let (rows, _store) = run_commit(&src, store, 1);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].value("v"), Value::Integer(1));
    assert_eq!(rows[1].value("v"), Value::Integer(2));
}

// =================================================================================================
// Error classification
// =================================================================================================

#[test]
fn load_csv_missing_file_is_a_runtime_error_and_rolls_back() {
    let store = fresh_store();
    // A file that does not exist *inside the import root*. Confinement canonicalises the path, which
    // requires the file to exist, so a missing file surfaces as an unresolvable path (a runtime
    // `LoadCsv` error that rolls the statement back).
    let missing_name = format!("graphus-loadcsv-absent-{}.csv", std::process::id());
    let _ = std::fs::remove_file(import_root().join(&missing_name));

    let src = format!("LOAD CSV FROM '{missing_name}' AS row CREATE (:N {{v: row[0]}})");
    let err = run_expect_exec_error(&src, store, 1);
    match err {
        ExecError::LoadCsv { reason } => {
            assert!(
                reason.contains("cannot resolve") || reason.contains("cannot open"),
                "missing-file error should mention the file could not be resolved/opened, got: {reason}"
            );
        }
        other => panic!("expected ExecError::LoadCsv, got {other:?}"),
    }
}

#[test]
fn load_csv_rejects_a_non_file_scheme() {
    let store = fresh_store();
    let src = "LOAD CSV FROM 'https://example.com/data.csv' AS row RETURN row";
    let err = run_expect_exec_error(src, store, 1);
    match err {
        ExecError::LoadCsv { reason } => {
            assert!(
                reason.contains("local files only"),
                "scheme rejection should explain the file-only policy, got: {reason}"
            );
        }
        other => panic!("expected ExecError::LoadCsv, got {other:?}"),
    }
}

#[test]
fn load_csv_rejects_an_absolute_path_outside_the_import_root() {
    // Regression: SEC-189 — even with an import root configured, an absolute path pointing at a
    // file OUTSIDE the root is rejected (the file is re-anchored under the root, where it does not
    // exist / does not resolve inside the root).
    let _ = import_root(); // ensure the confined policy is installed
    let store = fresh_store();
    // A real secret file far outside the import root.
    let secret =
        std::env::temp_dir().join(format!("graphus-loadcsv-secret-{}.txt", std::process::id()));
    std::fs::write(&secret, "TOP-SECRET\n").expect("write secret");
    let src = format!(
        "LOAD CSV FROM '{}' AS row RETURN row",
        secret.to_string_lossy().replace('\\', "\\\\").replace('\'', "\\'")
    );
    let err = run_expect_exec_error(&src, store, 1);
    let _ = std::fs::remove_file(&secret);
    match err {
        ExecError::LoadCsv { .. } => {} // rejected, as required
        other => panic!("expected ExecError::LoadCsv rejection, got {other:?}"),
    }
}

#[test]
fn load_csv_non_string_url_literal_is_a_compile_time_error() {
    // A statically non-string URL literal is rejected at semantic analysis (compile time), before
    // any execution — the openCypher `LoadCSV` grammar requires a string URL.
    let src = "LOAD CSV FROM 42 AS row RETURN row";
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let err = analyze(&ast).expect_err("a non-string URL literal must fail semantic analysis");
    // It is the dedicated InvalidLoadCsvUrl detail.
    assert_eq!(
        err.kind.detail(),
        graphus_cypher::errors::SemanticDetail::InvalidLoadCsvUrl
    );
}
