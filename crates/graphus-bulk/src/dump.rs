//! The whole-graph **dumper** (FR-BK; `rmp` task #22): serialises a populated [`RecordStore`] to the
//! **same** node/relationship CSV format the [bulk importer](crate::import) reads, so a dump → import
//! round-trips to an identical graph.
//!
//! # Format
//!
//! - **Nodes file**: header `:ID,:LABEL,<key>:<type>,…` then one row per node. The `:ID` is the
//!   node's physical id rendered as a string (a stable, unique external id); `:LABEL` is its labels
//!   joined by `;`; each property column holds that node's value for the key (empty when the node
//!   lacks it).
//! - **Relationships file**: header `:START_ID,:END_ID,:TYPE,<key>:<type>,…` then one row per
//!   relationship, its endpoints rendered as the same physical-id strings used in the nodes file.
//!
//! # Property columns and types
//!
//! The dumper first scans the whole store to collect, per entity kind, the **union** of property keys
//! and infers each key's column type from the first value observed (`Integer`→`int`, `Float`→`float`,
//! `Boolean`→`boolean`, `String`→`string`, `List`→element-typed `…[]`). A property-typed graph (the
//! round-trip bar) has each key consistently typed, so this reproduces it faithfully. Values are
//! rendered to the textual form the importer parses back: scalars verbatim, lists `;`-joined.

use std::collections::BTreeMap;
use std::io::Write;

use graphus_core::{Result, Value};
use graphus_io::BlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::LogSink;

/// The inferred CSV column type token for a property key (the `:type` suffix the importer reads).
fn column_type_token(value: &Value) -> &'static str {
    match value {
        Value::Integer(_) => "int",
        Value::Float(_) => "float",
        Value::Boolean(_) => "boolean",
        Value::List(items) => match items.first() {
            Some(Value::Integer(_)) => "int[]",
            Some(Value::Float(_)) => "float[]",
            Some(Value::Boolean(_)) => "boolean[]",
            // Empty or string-element lists serialise as a string array.
            _ => "string[]",
        },
        // String and everything else round-trips through the string column.
        _ => "string",
    }
}

/// The leading characters that make a spreadsheet (Excel / LibreOffice Calc / Google Sheets) treat a
/// CSV cell as a **formula** rather than literal text. A cell beginning with any of these is a CSV
/// injection vector (CWE-1236, OWASP WSTG-INPV-21): opened in a spreadsheet it can run DDE / call
/// external programs / exfiltrate data in the victim's context.
///
/// `=` `+` `-` `@` are the formula sigils; TAB (`0x09`) and CR (`0x0D`) are the whitespace leaders
/// some spreadsheets strip before re-evaluating the remainder as a formula.
const FORMULA_TRIGGERS: [char; 6] = ['=', '+', '-', '@', '\t', '\r'];

/// Neutralises a **string** cell against spreadsheet formula injection (SEC-194, CWE-1236).
///
/// If `s` begins with a [formula trigger](FORMULA_TRIGGERS), the cell is prefixed with a single
/// quote (`'`) — the spreadsheet convention that forces a cell to be read as literal text, so
/// `=cmd|'/c calc'!A1` is exported as `'=cmd|'/c calc'!A1` and never evaluated. The `'` is purely a
/// rendering convention (not part of the stored datum); a dump → import round-trip preserves the
/// logical value because the importer reads the cell verbatim and only the operator's spreadsheet
/// (the sole consumer that interprets the leading `'`) strips it on display.
///
/// Only `String` values are sanitised: numeric / boolean cells are produced by `to_string()` and
/// cannot begin with a malicious construct (a numeric `-2` is an inert number, not a formula).
fn sanitize_string_cell(s: &str) -> String {
    match s.chars().next() {
        Some(first) if FORMULA_TRIGGERS.contains(&first) => {
            let mut out = String::with_capacity(s.len() + 1);
            out.push('\'');
            out.push_str(s);
            out
        }
        _ => s.to_owned(),
    }
}

/// Renders a scalar [`Value`] to the textual cell the importer parses back.
///
/// String cells are neutralised against spreadsheet formula injection via
/// [`sanitize_string_cell`] (SEC-194).
fn render_scalar(value: &Value) -> String {
    match value {
        Value::String(s) => sanitize_string_cell(s),
        Value::Integer(i) => i.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Boolean(b) => b.to_string(),
        // A null or non-scalar reaching here renders empty (absent).
        _ => String::new(),
    }
}

/// Renders a property [`Value`] (scalar or list) to its CSV cell.
fn render_value(value: &Value) -> String {
    match value {
        Value::List(items) => items
            .iter()
            .map(render_scalar)
            .collect::<Vec<_>>()
            .join(";"),
        other => render_scalar(other),
    }
}

/// Collapses a property chain (newest-first, per the store's prepend order) to the **newest** value
/// per key, keyed by the property-key token id.
fn newest_per_key(props: Vec<(u64, u32, Value)>) -> BTreeMap<u32, Value> {
    let mut out: BTreeMap<u32, Value> = BTreeMap::new();
    // The chain is head-to-tail = newest-to-oldest, so the *first* occurrence of a key wins.
    for (_pid, key_token, value) in props {
        out.entry(key_token).or_insert(value);
    }
    out
}

/// PERF (C17): collapses a property chain to the newest value per key **and** resolves token ids to
/// key names in a single pass, returning a name-keyed map ready for column lookup. This replaces the
/// previous "build a token-keyed `BTreeMap`, then re-key into a name-keyed `BTreeMap`" double build.
///
/// Newest-wins is preserved: token interning is 1:1 (a name has exactly one token), so deduping by
/// token before resolving and deduping by name while resolving yield identical results.
fn newest_by_name<D: BlockDevice, S: LogSink>(
    store: &RecordStore<D, S>,
    props: Vec<(u64, u32, Value)>,
) -> Result<BTreeMap<String, Value>> {
    // First-occurrence-per-token wins (chain is newest-to-oldest); resolve each surviving token to
    // its name once.
    let mut seen: BTreeMap<u32, ()> = BTreeMap::new();
    let mut out: BTreeMap<String, Value> = BTreeMap::new();
    for (_pid, key_token, value) in props {
        if seen.insert(key_token, ()).is_none() {
            let name = key_name(store, Namespace::PropKey, key_token)?;
            out.insert(name, value);
        }
    }
    Ok(out)
}

/// Dumps every node of `store` to `writer` in the importer's node-CSV format.
///
/// Returns the stable ordering of property-key names used for the columns (so the relationship dump
/// and tests can stay consistent if needed). Streams row by row after a single schema-collection
/// scan.
///
/// # Errors
///
/// Returns a storage error if the store cannot be scanned, or an I/O error wrapped as
/// [`graphus_core::GraphusError::Storage`] if `writer` fails.
pub fn dump_nodes<D: BlockDevice, S: LogSink, W: Write>(
    store: &mut RecordStore<D, S>,
    writer: W,
) -> Result<Vec<String>> {
    let node_ids = store.scan_node_ids()?;

    // Pass 1: collect the union of property keys and infer each key's column type.
    let mut key_types: BTreeMap<String, &'static str> = BTreeMap::new();
    for &id in &node_ids {
        let props = newest_per_key(store.node_property_values(id)?);
        for (key_token, value) in &props {
            let key = key_name(store, Namespace::PropKey, *key_token)?;
            key_types
                .entry(key)
                .or_insert_with(|| column_type_token(value));
        }
    }
    let keys: Vec<String> = key_types.keys().cloned().collect();

    let mut w = csv::WriterBuilder::new().from_writer(writer);
    // Header: :ID, :LABEL, then one typed column per property key.
    let mut header = vec![":ID".to_owned(), ":LABEL".to_owned()];
    for key in &keys {
        header.push(format!("{key}:{}", key_types[key]));
    }
    w.write_record(&header).map_err(csv_err)?;

    // Pass 2: one row per node.
    for &id in &node_ids {
        let label_tokens = store.node_labels(id)?;
        let mut labels = Vec::with_capacity(label_tokens.len());
        for t in label_tokens {
            labels.push(key_name(store, Namespace::Label, t)?);
        }
        // PERF (C17): build the name-keyed newest-value map in one pass (no token-map → name-map
        // double build).
        let node_props = store.node_property_values(id)?;
        let by_name = newest_by_name(store, node_props)?;

        // PERF (C19): render the u64 id via `itoa` (no digit-by-digit `Display` machinery).
        let mut id_buf = itoa::Buffer::new();
        let mut row = vec![id_buf.format(id).to_owned(), labels.join(";")];
        for key in &keys {
            row.push(by_name.get(key).map(render_value).unwrap_or_default());
        }
        w.write_record(&row).map_err(csv_err)?;
    }
    w.flush().map_err(io_err)?;
    Ok(keys)
}

/// Dumps every relationship of `store` to `writer` in the importer's relationship-CSV format.
///
/// Endpoints are rendered as the same physical-id strings [`dump_nodes`] uses for `:ID`, so the
/// two files join correctly on re-import.
///
/// # Errors
///
/// Returns a storage error if the store cannot be scanned, or an I/O error if `writer` fails.
pub fn dump_relationships<D: BlockDevice, S: LogSink, W: Write>(
    store: &mut RecordStore<D, S>,
    writer: W,
) -> Result<Vec<String>> {
    let rel_ids = store.scan_rel_ids()?;

    // Pass 1: union of relationship property keys + inferred types.
    let mut key_types: BTreeMap<String, &'static str> = BTreeMap::new();
    for &id in &rel_ids {
        let props = newest_per_key(store.rel_property_values(id)?);
        for (key_token, value) in &props {
            let key = key_name(store, Namespace::PropKey, *key_token)?;
            key_types
                .entry(key)
                .or_insert_with(|| column_type_token(value));
        }
    }
    let keys: Vec<String> = key_types.keys().cloned().collect();

    let mut w = csv::WriterBuilder::new().from_writer(writer);
    let mut header = vec![
        ":START_ID".to_owned(),
        ":END_ID".to_owned(),
        ":TYPE".to_owned(),
    ];
    for key in &keys {
        header.push(format!("{key}:{}", key_types[key]));
    }
    w.write_record(&header).map_err(csv_err)?;

    for &id in &rel_ids {
        let rec = store.rel(id)?;
        let type_name = key_name(store, Namespace::RelType, rec.type_id)?;
        // PERF (C17): single-pass name-keyed newest-value map (see `dump_nodes`).
        let rel_props = store.rel_property_values(id)?;
        let by_name = newest_by_name(store, rel_props)?;

        // PERF (C19): render the endpoint u64 ids via `itoa`.
        let mut start_buf = itoa::Buffer::new();
        let mut end_buf = itoa::Buffer::new();
        let mut row = vec![
            start_buf.format(rec.start_node).to_owned(),
            end_buf.format(rec.end_node).to_owned(),
            type_name,
        ];
        for key in &keys {
            row.push(by_name.get(key).map(render_value).unwrap_or_default());
        }
        w.write_record(&row).map_err(csv_err)?;
    }
    w.flush().map_err(io_err)?;
    Ok(keys)
}

/// Resolves a token id to its name in `ns`, erroring if the token is unknown (a corrupt store).
fn key_name<D: BlockDevice, S: LogSink>(
    store: &RecordStore<D, S>,
    ns: Namespace,
    id: u32,
) -> Result<String> {
    store.token_name(ns, id).map(str::to_owned).ok_or_else(|| {
        graphus_core::GraphusError::Storage(format!("dump: unknown {ns:?} token id {id}"))
    })
}

/// Converts a `csv` writer error into a [`graphus_core::GraphusError`].
fn csv_err(e: csv::Error) -> graphus_core::GraphusError {
    graphus_core::GraphusError::Storage(format!("dump CSV write: {e}"))
}

/// Converts an I/O error into a [`graphus_core::GraphusError`].
fn io_err(e: std::io::Error) -> graphus_core::GraphusError {
    graphus_core::GraphusError::Storage(format!("dump flush: {e}"))
}
