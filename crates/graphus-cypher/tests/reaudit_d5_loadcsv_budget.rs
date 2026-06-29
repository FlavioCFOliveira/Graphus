//! Sprint-42 re-audit (`rmp` task #485 / #489), domain **D5**: regression lock for the per-value
//! materialised-size budget (`SEC-191` / #481) on `LOAD CSV` without headers, which built one row as a
//! `Value::List` of every field via an unbudgeted `.collect()` (loadcsv.rs ~290). A hostile CSV with a
//! single record of millions of fields (`a,a,a,…` on one line) therefore materialised millions of
//! `Value` slots in one row value — the same CWE-770/789 class as `split`/`keys`.
//!
//! Reachability is GATED by the import-path policy (`SEC-189`, `CsvImportPolicy` confines `LOAD CSV` to a
//! configured root, non-`file` schemes refused), so an attacker must place the file under that root (or
//! the server is configured permissively) — a higher bar than the parameter-driven bypasses. The fix
//! (closing #489) bounds the field count against `max_list_elements()` before collecting the record into
//! a `Value::List`.

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::MemGraph;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::loadcsv::{CsvImportPolicy, set_global_import_policy};
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_cypher::value_size::BudgetOverride;

/// Serialises the process-global budget override across this binary's tests.
static CAP_LOCK: Mutex<()> = Mutex::new(());

/// The per-test-binary import root, created and installed as the confined `LOAD CSV` policy on first use.
fn import_root() -> &'static PathBuf {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        let root = std::env::temp_dir().join(format!("graphus-d5-loadcsv-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("create import root");
        let canonical = std::fs::canonicalize(&root).unwrap_or_else(|_| root.clone());
        let _ = set_global_import_policy(CsvImportPolicy::with_import_root(canonical.clone()));
        canonical
    })
}

/// Writes `contents` to a uniquely-named file under the import root and returns its BARE FILENAME.
fn write_temp_csv(contents: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let name = format!("d5-{}.csv", SEQ.fetch_add(1, Ordering::Relaxed));
    let path = import_root().join(&name);
    let mut f = std::fs::File::create(&path).expect("create temp csv");
    f.write_all(contents.as_bytes()).expect("write temp csv");
    f.flush().expect("flush temp csv");
    PathBuf::from(name)
}

/// Drives the full compile→execute→drain pipeline over an empty `MemGraph`, returning the rows or
/// `Err(message)`. Never panics on a query outcome, so a clean rejection surfaces as `Err`.
fn run_rows(src: &str) -> Result<Vec<Row>, String> {
    let _ = import_root(); // ensure the confined import policy is installed before any LOAD CSV runs.
    let toks = tokenize(src).map_err(|e| format!("lex: {e:?}"))?;
    let ast = parse_tokens(&toks, src).map_err(|e| format!("parse: {e:?}"))?;
    let validated = analyze(&ast).map_err(|e| format!("semantic: {e:?}"))?;
    let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).map_err(|e| format!("bind: {e:?}"))?;
    let mut graph = MemGraph::new();
    let mut cursor = execute(&plan, &bound, &mut graph).map_err(|e| format!("exec: {e}"))?;
    let rows = cursor.collect_all().map_err(|e| format!("{e}"))?;
    Ok(rows)
}

/// A single record of `fields` one-character fields (`a,a,…,a`) on one line — the hostile wide row.
fn wide_csv(fields: usize) -> String {
    let mut s = vec!["a"; fields].join(",");
    s.push('\n');
    s
}

fn src_for(path: &std::path::Path) -> String {
    format!(
        "LOAD CSV FROM '{}' AS row RETURN row AS r",
        path.to_string_lossy()
    )
}

fn is_value_budget_rejection(outcome: &Result<Vec<Row>, String>) -> bool {
    match outcome {
        Ok(_) => false,
        Err(msg) => {
            let m = msg.to_lowercase();
            (m.contains("limit") || m.contains("budget") || m.contains("exceed"))
                && !m.contains("cancel")
        }
    }
}

#[test]
fn loadcsv_wide_row_rejects_over_budget() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _b = BudgetOverride::new(4096);
    // One CSV record with 2000 fields; the header-less form binds `row` to a Value::List of 2000
    // Value::String. The field-count guard must reject it before collecting.
    let path = write_temp_csv(&wide_csv(2000));
    let outcome = run_rows(&src_for(&path));
    assert!(
        is_value_budget_rejection(&outcome),
        "a header-less LOAD CSV record whose field list exceeds the budget must reject with a typed \
         ResourceLimit (the field count is bounded against max_list_elements before collecting). Got: {outcome:?}"
    );
}

#[test]
fn loadcsv_narrow_row_is_unaffected() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // At the real default budget, an ordinary small CSV record is untouched (control: the guard must not
    // reject honest rows).
    let path = write_temp_csv(&wide_csv(3));
    let rows = run_rows(&src_for(&path)).expect("a narrow CSV row must load normally");
    assert_eq!(rows.len(), 1);
}
