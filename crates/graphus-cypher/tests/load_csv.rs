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

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

// =================================================================================================
// Harness
// =================================================================================================

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

/// Writes `contents` to a uniquely-named temp file (PID + counter, the workspace convention — no
/// `tempfile` dep) and returns its path. The file is left for the OS temp reaper; the test reads it
/// back through `LOAD CSV`.
fn write_temp_csv(contents: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("graphus-loadcsv-{}-{n}.csv", std::process::id()));
    let mut f = std::fs::File::create(&path).expect("create temp csv");
    f.write_all(contents.as_bytes()).expect("write temp csv");
    f.flush().expect("flush temp csv");
    path
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
    // `LOAD CSV ... CREATE` has the `LoadCsv` *source* op as its plan root (not a bare `CREATE`), so
    // it streams one row per record — each carrying the bound `row` List and the created node. This
    // is the same shape as `UNWIND xs AS x CREATE (...)` (a source-rooted write).
    let (created, store) = run_commit(&src, store, 1);
    assert_eq!(created.len(), 3, "one row per ingested CSV record");

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
    let (created, store) = run_commit(&src, store, 1);
    assert_eq!(
        created.len(),
        5_000,
        "all records ingested in one transaction"
    );

    let (rows, _store) = run_commit("MATCH (n:Item) RETURN count(n) AS c", store, 2);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("c"), Value::Integer(5_000));
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
    let missing =
        std::env::temp_dir().join(format!("graphus-loadcsv-absent-{}.csv", std::process::id()));
    // Make sure it really does not exist.
    let _ = std::fs::remove_file(&missing);

    let src = format!(
        "LOAD CSV FROM {} AS row CREATE (:N {{v: row[0]}})",
        cypher_str(&missing)
    );
    let err = run_expect_exec_error(&src, store, 1);
    match err {
        ExecError::LoadCsv { reason } => {
            assert!(
                reason.contains("cannot open"),
                "missing-file error should mention opening the file, got: {reason}"
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
