//! Security regression battery for `graphus-bulk` (red-team audit, 2026-06-14; fixes landed).
//!
//! Each test pins the **hardened** behaviour of an audited weakness so a regression flips it back.
//! Tests for a fix carry `// Regression: SEC-<rmp-task-id>`.
//!
//! Findings covered:
//! - SEC-194  CSV formula injection on export — string cells with a formula-trigger prefix are
//!   neutralised with a leading `'` (CWE-1236)
//! - SEC-195  Unbounded array from a single cell -> OOM, now capped (CWE-789/400)
//! - SEC-196  Duplicate non-empty `:ID` is rejected (strict, default) instead of silently
//!   overwriting the id map (CWE-694)

use graphus_bulk::{BulkImporter, DEFAULT_BATCH_SIZE, DuplicatePolicy, dump_nodes};
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

/// A fresh in-memory store for a test.
fn fresh_store() -> RecordStore<MemBlockDevice, MemLogSink> {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("wal create");
    RecordStore::create(device, wal, 256, 1).expect("store create")
}

/// Imports a single-node CSV and returns the full node dump as a string.
fn import_node_and_dump(nodes_csv: &str) -> String {
    let store = fresh_store();
    let mut importer = BulkImporter::new(store, DEFAULT_BATCH_SIZE, b',');
    importer
        .import_nodes(nodes_csv.as_bytes())
        .expect("import nodes");
    let (mut store, _stats) = importer.finish();
    let mut out = Vec::new();
    dump_nodes(&mut store, &mut out).expect("dump nodes");
    String::from_utf8(out).expect("utf8 dump")
}

// ---------------------------------------------------------------------------------------------
// SEC-194 — CSV formula injection on export (CWE-1236).
// ---------------------------------------------------------------------------------------------

/// Regression: SEC-194. A property value beginning with `=` is exported **neutralised**: the dumped
/// cell is prefixed with a single quote (`'`) so a spreadsheet reads it as literal text, never a
/// formula. The dangerous `=cmd…` is never emitted as the first character of the cell.
#[test]
fn sec194_formula_injection_neutralised_on_export() {
    // Regression: SEC-194
    let payload = "=cmd|'/c calc'!A1";
    let nodes = format!("id:ID,:LABEL,name:string\nn1,Person,{payload}\n");
    let dump = import_node_and_dump(&nodes);

    let data_line = dump
        .lines()
        .find(|l| l.contains("Person"))
        .expect("data row present");

    // Hardened behaviour: the cell is neutralised with a leading `'`, and the raw `=cmd` formula is
    // no longer present (the only occurrence of the payload is the quoted form).
    assert!(
        data_line.contains(&format!("'{payload}")),
        "expected the formula neutralised with a leading single-quote, got: {data_line:?}"
    );
    assert!(
        !data_line.contains(",=cmd"),
        "the raw, unquoted formula must not appear as a cell value: {data_line:?}"
    );
}

/// Regression: SEC-194. All formula-trigger prefixes (`=`, `+`, `-`, `@`, TAB) are neutralised with a
/// leading `'` on export. `-` is the subtle one: a *string* `-2+3` is a formula even though a
/// *numeric* `-2` is harmless — and indeed the numeric column below is left untouched.
#[test]
fn sec194_all_formula_prefixes_neutralised_on_export() {
    // Regression: SEC-194
    for payload in ["=1+1", "+1+1", "-2+3", "@SUM(A1)", "\t=1+1"] {
        let nodes = format!("id:ID,:LABEL,note:string\nn1,L,{payload}\n");
        let dump = import_node_and_dump(&nodes);
        // The neutralised value is the original prefixed with `'`. The CSV writer may wrap a
        // leading-tab cell in quotes, so assert on the quoted-payload substring.
        let neutralised = format!("'{payload}");
        assert!(
            dump.contains(&neutralised),
            "payload {payload:?} must be neutralised as {neutralised:?}: {dump:?}"
        );
    }

    // A *numeric* negative is NOT a string and must stay a bare number (no spurious `'`): a numeric
    // `-2` is inert in a spreadsheet.
    let numeric = "id:ID,:LABEL,bal:int\nn1,L,-2\n";
    let dump = import_node_and_dump(numeric);
    let data_line = dump
        .lines()
        .find(|l| l.contains(",L,") || l.contains(",L\t") || l.ends_with(",-2"))
        .unwrap_or_else(|| {
            dump.lines()
                .find(|l| l.contains("-2"))
                .expect("numeric row")
        });
    assert!(
        data_line.contains("-2") && !data_line.contains("'-2"),
        "a numeric -2 must not be quoted (it is inert): {data_line:?}"
    );
}

/// Regression: SEC-194. The neutralising `'` is a spreadsheet rendering convention, not part of the
/// datum. A dump → import round-trip must preserve the **logical** value: re-importing the dumped
/// CSV yields a node whose `name` is the original `=1+1`, byte-for-byte (the importer reads the cell
/// verbatim; the `'` is only meaningful to a spreadsheet's display layer).
#[test]
fn sec194_neutralisation_round_trips_logical_value() {
    // Regression: SEC-194
    use graphus_core::Value;

    let payload = "=1+1";
    let nodes = format!("id:ID,:LABEL,name:string\nn1,L,{payload}\n");

    // Import → dump.
    let store = fresh_store();
    let mut imp1 = BulkImporter::new(store, DEFAULT_BATCH_SIZE, b',');
    imp1.import_nodes(nodes.as_bytes()).expect("import 1");
    let (mut store1, _) = imp1.finish();
    let mut dump = Vec::new();
    dump_nodes(&mut store1, &mut dump).expect("dump");

    // Re-import the dump into a fresh store.
    let store2 = fresh_store();
    let mut imp2 = BulkImporter::new(store2, DEFAULT_BATCH_SIZE, b',');
    imp2.import_nodes(dump.as_slice()).expect("re-import");
    let (mut store2, _) = imp2.finish();

    // The single re-imported node carries name == the original payload (no leading `'`).
    let ids = store2.scan_node_ids().expect("scan");
    assert_eq!(ids.len(), 1, "exactly one node round-trips");
    let props = store2.node_property_values(ids[0]).expect("props");
    let name = props
        .iter()
        .find_map(|(_, _tok, v)| match v {
            Value::String(s) => Some(s.clone()),
            _ => None,
        })
        .expect("name property present");
    assert_eq!(
        name, payload,
        "the logical value must survive the round trip unchanged (the ' is display-only)"
    );
}

// ---------------------------------------------------------------------------------------------
// SEC-195 — Unbounded array materialised from a single cell (CWE-789/400).
// ---------------------------------------------------------------------------------------------

/// Regression: SEC-195 — a single `type[]` cell with N `;` separators must not materialise an
/// unbounded `Value::List`. The importer now enforces `ParseLimits::max_array_elems`
/// ([`DEFAULT_MAX_ARRAY_ELEMS`] = 65_536), so a cell above the cap is rejected before any large
/// allocation, while a cell within the cap still imports cleanly.
#[test]
fn sec195_single_cell_array_is_capped() {
    // Regression: SEC-195
    // Above the cap (65_536): must be rejected without materialising the giant list.
    const N: usize = 200_000;
    let mut cell = String::with_capacity(N * 2);
    for i in 0..N {
        if i > 0 {
            cell.push(';');
        }
        cell.push('1');
    }
    let csv = format!("id:ID,:LABEL,nums:int[]\nn1,L,{cell}\n");

    let store = fresh_store();
    let mut importer = BulkImporter::new(store, DEFAULT_BATCH_SIZE, b',');
    let result = importer.import_nodes(csv.as_bytes());
    assert!(
        result.is_err(),
        "a single-cell array above the element cap must be rejected; got {result:?}"
    );

    // Within the cap: a modest array still imports successfully.
    let small: String = (0..1000)
        .map(|i| {
            if i == 0 {
                "1".to_owned()
            } else {
                ";1".to_owned()
            }
        })
        .collect();
    let csv_ok = format!("id:ID,:LABEL,nums:int[]\nn2,L,{small}\n");
    let store_ok = fresh_store();
    let mut importer_ok = BulkImporter::new(store_ok, DEFAULT_BATCH_SIZE, b',');
    assert!(
        importer_ok.import_nodes(csv_ok.as_bytes()).is_ok(),
        "a modest array within the element cap must still import"
    );
}

// ---------------------------------------------------------------------------------------------
// SEC-196 — Duplicate `:ID` silently overwrites the join map (CWE-694).
// ---------------------------------------------------------------------------------------------

/// Regression: SEC-196. Two node rows sharing the same non-empty `:ID` are rejected with an error
/// under the strict (default) policy: a relationship pass can no longer be silently mis-joined onto
/// the wrong node. The error names the offending external id.
#[test]
fn sec196_duplicate_external_id_is_rejected_strict_default() {
    // Regression: SEC-196
    let nodes = "id:ID,:LABEL,name:string\nx,A,first\nx,B,second\n";
    let store = fresh_store();
    let mut importer = BulkImporter::new(store, DEFAULT_BATCH_SIZE, b',');
    let result = importer.import_nodes(nodes.as_bytes());

    let err = result.expect_err("duplicate :ID must be a hard error under the strict default");
    let msg = err.to_string();
    assert!(
        msg.contains("duplicate :ID") && msg.contains("\"x\""),
        "the error must identify the duplicate external id, got: {msg:?}"
    );
}

/// Regression: SEC-196. Under the opt-in `SkipDuplicate` policy the import succeeds: the duplicate's
/// node is still created (it is a real node), the first id binding is kept, and the skip is counted.
#[test]
fn sec196_duplicate_external_id_skip_policy_counts_and_keeps_first() {
    // Regression: SEC-196
    let nodes = "id:ID,:LABEL,name:string\nx,A,first\nx,B,second\n";
    let store = fresh_store();
    let mut importer = BulkImporter::new(store, DEFAULT_BATCH_SIZE, b',')
        .with_duplicate_policy(DuplicatePolicy::SkipDuplicate);
    importer
        .import_nodes(nodes.as_bytes())
        .expect("skip policy tolerates the duplicate");
    let (_store, stats) = importer.finish();

    assert_eq!(stats.nodes, 2, "both rows still create a physical node");
    assert_eq!(
        stats.skipped_duplicate_ids, 1,
        "the duplicate id remap is skipped and counted"
    );
}

/// Regression: SEC-196. Multiple *anonymous* nodes (empty `:ID`) are NOT a duplicate-id error: the
/// empty key is the anonymous-node convention and no relationship can reference it.
#[test]
fn sec196_empty_ids_are_not_treated_as_duplicates() {
    // Regression: SEC-196
    let nodes = "id:ID,:LABEL,name:string\n,L,first\n,L,second\n";
    let store = fresh_store();
    let mut importer = BulkImporter::new(store, DEFAULT_BATCH_SIZE, b',');
    importer
        .import_nodes(nodes.as_bytes())
        .expect("anonymous nodes (empty :ID) must import cleanly");
    let (_store, stats) = importer.finish();
    assert_eq!(stats.nodes, 2, "both anonymous nodes load");
    assert_eq!(
        stats.skipped_duplicate_ids, 0,
        "no skip: empty ids are exempt"
    );
}

// ---------------------------------------------------------------------------------------------
// Robustness checks that should hold regardless of the fixes (no panic / no crash on bad input).
// These are pure hardening assertions: malformed input must surface as `Err`, never a panic.
// ---------------------------------------------------------------------------------------------

/// An unterminated quote / ragged row must not panic the importer.
#[test]
fn malformed_csv_does_not_panic() {
    let csv = "id:ID,:LABEL,name:string\nn1,L,\"unterminated\nn2,L,ok\n";
    let store = fresh_store();
    let mut importer = BulkImporter::new(store, DEFAULT_BATCH_SIZE, b',');
    // Either Ok (csv crate is lenient) or Err is fine — the contract is "no panic".
    let _ = importer.import_nodes(csv.as_bytes());
}

/// A non-numeric cell for an `:int` column is a graceful `Err`, never a panic.
#[test]
fn bad_typed_cell_is_graceful_error() {
    let csv = "id:ID,:LABEL,age:int\nn1,L,not-a-number\n";
    let store = fresh_store();
    let mut importer = BulkImporter::new(store, DEFAULT_BATCH_SIZE, b',');
    let result = importer.import_nodes(csv.as_bytes());
    assert!(result.is_err(), "a bad :int cell must be a graceful error");
}

/// An empty file imports cleanly (no header, nothing to do).
#[test]
fn empty_file_is_ok() {
    let store = fresh_store();
    let mut importer = BulkImporter::new(store, DEFAULT_BATCH_SIZE, b',');
    assert!(importer.import_nodes(b"".as_slice()).is_ok());
}
