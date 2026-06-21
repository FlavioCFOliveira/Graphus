//! Unit tests for the gcol-result columnar codec (rmp #334): per-codec round-trips, null handling,
//! the lossless structural/mixed fallback, the size win on low-cardinality wide data, and
//! fuzz-hardening of the decoder (truncation / bad magic / bad header / unknown codec).

use super::*;
use crate::restvalue::RestNode;
use serde_json::json;

/// A row of plain [`Value`] cells, lifted into the [`Row`]'s [`RestValue`] cells.
fn row(values: Vec<Value>) -> Row {
    values.into_iter().map(RestValue::Value).collect()
}

/// The default read summary the router would attach (matches `encode_summary`'s shape).
fn summary() -> Json {
    json!({ "type": "r", "stats": {} })
}

/// Encodes `(fields, rows)` then decodes, asserting each decoded strict-Jolt cell equals the
/// original cell's own `restvalue_to_jolt` rendering — i.e. the columnar body reproduces the
/// row-wise JSON `data` rows cell-for-cell. Returns the encoded body so the caller can also assert
/// on size / codec choice.
fn round_trip(fields: &[&str], rows: &[Row]) -> Vec<u8> {
    let fields: Vec<String> = fields.iter().map(|s| (*s).to_owned()).collect();
    let body = encode_result(&fields, rows, &summary());
    let decoded = decode_result(&body).expect("decode");
    assert_eq!(decoded.header.fields, fields);
    assert_eq!(decoded.header.row_count as usize, rows.len());

    // The decoder yields the same strict-Jolt cells a JSON client receives: each decoded cell equals
    // the original cell's own `restvalue_to_jolt` rendering — exactly, for scalars AND structural
    // cells. (NaN's `{"R":"NaN"}` string form makes even a NaN cell compare equal here, so no
    // float-bit special-casing is needed.)
    for (r, original) in rows.iter().enumerate() {
        for (c, cell) in original.iter().enumerate() {
            let expected = restvalue_to_jolt(cell);
            assert_eq!(
                decoded.rows[r][c], expected,
                "cell ({r},{c}) mismatch: codec={}",
                decoded.header.columns[c].codec
            );
        }
    }
    body
}

/// The codec tag chosen for column `c` of an encoded body.
fn codec_of(body: &[u8], c: usize) -> String {
    decode_result(body).unwrap().header.columns[c].codec.clone()
}

#[test]
fn integer_column_round_trips_and_uses_i64_codec() {
    let rows: Vec<Row> = (0..256).map(|i| row(vec![Value::Integer(i)])).collect();
    let body = round_trip(&["n"], &rows);
    assert_eq!(codec_of(&body, 0), "i64");
}

#[test]
fn float_column_round_trips_and_uses_f64_codec() {
    // Slowly-varying sensor readings — the Gorilla case. Specials round-trip too.
    let mut rows: Vec<Row> = (0..200)
        .map(|i| row(vec![Value::Float(21.0 + (i as f64) * 0.01)]))
        .collect();
    rows.push(row(vec![Value::Float(f64::NAN)]));
    rows.push(row(vec![Value::Float(f64::INFINITY)]));
    let body = round_trip(&["temp"], &rows);
    assert_eq!(codec_of(&body, 0), "f64");
    // The special floats round-trip bit-exactly through Gorilla and render as their named Jolt forms.
    let decoded = decode_result(&body).unwrap();
    assert_eq!(decoded.rows[200][0], json!({ "R": "NaN" }));
    assert_eq!(decoded.rows[201][0], json!({ "R": "Infinity" }));
}

#[test]
fn boolean_column_round_trips_and_uses_bool_codec() {
    let rows: Vec<Row> = (0..100)
        .map(|i| row(vec![Value::Boolean(i % 3 == 0)]))
        .collect();
    let body = round_trip(&["flag"], &rows);
    assert_eq!(codec_of(&body, 0), "bool");
}

#[test]
fn string_column_round_trips_and_uses_str_codec() {
    let cats = ["gold", "silver", "bronze"];
    let rows: Vec<Row> = (0..300)
        .map(|i| row(vec![Value::String(cats[i % 3].to_owned())]))
        .collect();
    let body = round_trip(&["tier"], &rows);
    assert_eq!(codec_of(&body, 0), "str");
}

#[test]
fn nulls_are_preserved_via_the_present_bitmap() {
    // A column with interleaved nulls: the typed codec runs over the present integers only, and the
    // nulls are reinstated in their exact positions on decode.
    let rows: Vec<Row> = (0..50)
        .map(|i| {
            if i % 5 == 0 {
                row(vec![Value::Null])
            } else {
                row(vec![Value::Integer(i)])
            }
        })
        .collect();
    let body = round_trip(&["maybe"], &rows);
    // The present cells are still integers, so the column stays the i64 codec.
    assert_eq!(codec_of(&body, 0), "i64");
    let decoded = decode_result(&body).unwrap();
    assert_eq!(decoded.rows[0][0], Json::Null);
    assert_eq!(decoded.rows[5][0], Json::Null);
    assert_eq!(decoded.rows[1][0], json!({ "Z": "1" }));
}

#[test]
fn all_null_column_round_trips_as_empty_json_payload() {
    let rows: Vec<Row> = (0..10).map(|_| row(vec![Value::Null])).collect();
    let body = round_trip(&["empty"], &rows);
    // No present cell constrains a typed codec ⇒ the fallback, with a present_count of 0.
    assert_eq!(codec_of(&body, 0), "json");
    let decoded = decode_result(&body).unwrap();
    assert_eq!(decoded.header.columns[0].present_count, 0);
    assert!(decoded.rows.iter().all(|r| r[0] == Json::Null));
}

#[test]
fn mixed_scalar_types_fall_back_to_json_losslessly() {
    // A column mixing integers and strings cannot use a typed codec; the `"json"` fallback keeps it
    // exact (each cell via strict-Jolt).
    let rows = vec![
        row(vec![Value::Integer(1)]),
        row(vec![Value::String("two".to_owned())]),
        row(vec![Value::Integer(3)]),
        row(vec![Value::Boolean(true)]),
    ];
    let body = round_trip(&["mixed"], &rows);
    assert_eq!(codec_of(&body, 0), "json");
}

#[test]
fn bytes_temporal_map_columns_fall_back_to_json() {
    // Non-scalar property values are not typed-codec scalars; each makes its column `"json"`.
    let rows = vec![
        row(vec![
            Value::Bytes(vec![0xDE, 0xAD]),
            Value::Map(vec![("k".to_owned(), Value::Integer(1))]),
            Value::Date(graphus_core::Date {
                days_since_epoch: 20_000,
            }),
        ]),
        row(vec![
            Value::Bytes(vec![0xBE, 0xEF]),
            Value::Map(vec![("k".to_owned(), Value::Integer(2))]),
            Value::Date(graphus_core::Date {
                days_since_epoch: 20_001,
            }),
        ]),
    ];
    let body = round_trip(&["b", "m", "d"], &rows);
    assert_eq!(codec_of(&body, 0), "json");
    assert_eq!(codec_of(&body, 1), "json");
    assert_eq!(codec_of(&body, 2), "json");
}

#[test]
fn structural_node_column_round_trips_via_json_fallback() {
    // A structural cell (a node) round-trips through the `"json"` fallback as the EXACT strict-Jolt
    // node object the row-wise JSON path emits — byte-identical, not a re-interpretation.
    let node = |id: i64| {
        RestValue::Node(RestNode {
            id,
            labels: vec!["Person".to_owned()],
            properties: vec![("name".to_owned(), Value::String(format!("n{id}")))],
        })
    };
    let rows = vec![
        vec![node(1), RestValue::Value(Value::Integer(10))],
        vec![node(2), RestValue::Value(Value::Integer(20))],
    ];
    let body = round_trip(&["person", "age"], &rows);
    assert_eq!(codec_of(&body, 0), "json"); // structural → fallback
    assert_eq!(codec_of(&body, 1), "i64"); // scalar → typed

    // The structural cell decodes to the exact node object (the same one `round_trip` already
    // asserted equal to `restvalue_to_jolt`); spot-check its top-level shape.
    let decoded = decode_result(&body).unwrap();
    assert_eq!(decoded.rows[0][0]["id"], json!(1));
    assert_eq!(decoded.rows[0][0]["labels"], json!(["Person"]));
    assert_eq!(
        decoded.rows[0][0]["properties"]["name"],
        json!({ "U": "n1" })
    );
    // The scalar column re-renders as the int53 string form.
    assert_eq!(decoded.rows[0][1], json!({ "Z": "10" }));
}

#[test]
fn empty_result_round_trips() {
    // Zero rows, several columns: every column has an empty bitmap + empty payload.
    let body = round_trip(&["a", "b", "c"], &[]);
    let decoded = decode_result(&body).unwrap();
    assert_eq!(decoded.header.row_count, 0);
    assert!(decoded.rows.is_empty());
}

#[test]
fn zero_columns_round_trips() {
    // A result with rows but no fields (a degenerate but valid shape).
    let rows = vec![row(vec![]), row(vec![])];
    let body = round_trip(&[], &rows);
    let decoded = decode_result(&body).unwrap();
    assert_eq!(decoded.header.row_count, 2);
    assert!(decoded.rows.iter().all(Vec::is_empty));
}

#[test]
fn summary_is_carried_in_the_header() {
    let fields = vec!["x".to_owned()];
    let s = json!({ "type": "rw", "stats": { "nodes-created": { "Z": "3" } } });
    let body = encode_result(&fields, &[row(vec![Value::Integer(1)])], &s);
    let decoded = decode_result(&body).unwrap();
    assert_eq!(decoded.header.summary, s);
}

#[test]
fn columnar_beats_json_on_low_cardinality_wide_result() {
    // A large analytical result: many rows, several low-cardinality columns. This is the case the
    // channel exists for; the columnar body must be materially smaller than the row-wise JSON body.
    let tiers = ["gold", "silver", "bronze", "none"];
    let regions = ["EU", "US", "APAC"];
    let n = 20_000;
    let fields = ["id", "tier", "region", "active", "score"];
    let rows: Vec<Row> = (0..n)
        .map(|i| {
            row(vec![
                Value::Integer(i as i64),
                Value::String(tiers[i % tiers.len()].to_owned()),
                Value::String(regions[i % regions.len()].to_owned()),
                Value::Boolean(i % 2 == 0),
                Value::Float(40.0 + ((i % 100) as f64) * 0.5),
            ])
        })
        .collect();

    let field_strings: Vec<String> = fields.iter().map(|s| (*s).to_owned()).collect();
    let columnar = encode_result(&field_strings, &rows, &summary());

    // The row-wise JSON body the existing path would produce: a StatementResult-shaped object.
    let json_body = json_rowwise_body(&fields, &rows);
    let json_len = serde_json::to_vec(&json_body).unwrap().len();

    // Round-trips correctly.
    let decoded = decode_result(&columnar).unwrap();
    assert_eq!(decoded.rows.len(), n);

    // The measured win (printed so `cargo test -- --nocapture` shows it).
    println!(
        "[gcol-result] low-cardinality wide result: {n} rows x {} cols | columnar = {} B | json = {} B | ratio = {:.2}x smaller",
        fields.len(),
        columnar.len(),
        json_len,
        json_len as f64 / columnar.len() as f64,
    );
    assert!(
        columnar.len() * 2 < json_len,
        "columnar ({}) must be < half the JSON body ({})",
        columnar.len(),
        json_len
    );
}

#[test]
fn columnar_loses_on_a_tiny_result_as_documented() {
    // Honesty check: on a tiny OLTP-shaped result the fixed framing + JSON header make the columnar
    // body LARGER than JSON. This is the documented reason small results stay on JSON/NDJSON.
    let rows = vec![row(vec![Value::Integer(1), Value::String("ok".to_owned())])];
    let fields = ["n", "status"];
    let field_strings: Vec<String> = fields.iter().map(|s| (*s).to_owned()).collect();
    let columnar = encode_result(&field_strings, &rows, &summary());
    let json_len = serde_json::to_vec(&json_rowwise_body(&fields, &rows))
        .unwrap()
        .len();
    println!(
        "[gcol-result] tiny result (1 row x 2 cols): columnar = {} B | json = {} B (columnar larger, as documented)",
        columnar.len(),
        json_len
    );
    assert!(
        columnar.len() > json_len,
        "the fixed columnar overhead is expected to exceed JSON on a 1-row result"
    );
}

/// Builds the row-wise JSON body the existing buffered REST path would emit for `(fields, rows)`: the
/// `StatementResult` shape `{ fields, data: [[jolt-cell, …], …], summary }`. Used only to measure
/// columnar-vs-JSON size on the same result, with the exact same per-cell Jolt encoding.
fn json_rowwise_body(fields: &[&str], rows: &[Row]) -> Json {
    let data: Vec<Json> = rows
        .iter()
        .map(|r| Json::Array(r.iter().map(restvalue_to_jolt).collect()))
        .collect();
    json!({
        "fields": fields,
        "data": data,
        "summary": summary(),
    })
}

// ---- decoder fuzz-hardening (`04 §11.4`) ------------------------------------------------------

#[test]
fn decode_rejects_bad_magic() {
    assert_eq!(decode_result(b"not-gcol").unwrap_err(), GcolError::BadMagic);
    assert_eq!(decode_result(b"").unwrap_err(), GcolError::BadMagic);
    assert_eq!(decode_result(b"GCO").unwrap_err(), GcolError::BadMagic);
}

#[test]
fn decode_rejects_truncated_body() {
    let body = encode_result(
        &["n".to_owned()],
        &[row(vec![Value::Integer(1)])],
        &summary(),
    );
    // Truncating anywhere past the magic must be a controlled Truncated/BadHeader error, never a
    // panic. Walk several cut points.
    for cut in MAGIC.len()..body.len() {
        let err = decode_result(&body[..cut]).unwrap_err();
        assert!(
            matches!(
                err,
                GcolError::Truncated { .. } | GcolError::BadHeader { .. }
            ),
            "cut at {cut} gave {err:?}"
        );
    }
}

#[test]
fn decode_rejects_unsupported_version() {
    // Hand-craft a header with a future version.
    let header = GcolHeader {
        version: 999,
        fields: vec![],
        row_count: 0,
        columns: vec![],
        summary: summary(),
    };
    let header_bytes = serde_json::to_vec(&header).unwrap();
    let mut body = Vec::new();
    body.extend_from_slice(MAGIC);
    body.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    body.extend_from_slice(&header_bytes);
    assert_eq!(
        decode_result(&body).unwrap_err(),
        GcolError::UnsupportedVersion(999)
    );
}

#[test]
fn decode_rejects_unknown_codec() {
    let header = GcolHeader {
        version: FORMAT_VERSION,
        fields: vec!["x".to_owned()],
        row_count: 1,
        columns: vec![GcolColumn {
            name: "x".to_owned(),
            codec: "martian".to_owned(),
            present_count: 1,
        }],
        summary: summary(),
    };
    let header_bytes = serde_json::to_vec(&header).unwrap();
    let mut body = Vec::new();
    body.extend_from_slice(MAGIC);
    body.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    body.extend_from_slice(&header_bytes);
    // One column: a 1-row present bitmap (1 byte) + an empty payload.
    let bitmap = encode_bool(&[true]);
    body.extend_from_slice(&(bitmap.len() as u32).to_le_bytes());
    body.extend_from_slice(&bitmap);
    body.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(
        decode_result(&body).unwrap_err(),
        GcolError::UnknownCodec {
            tag: "martian".to_owned()
        }
    );
}

#[test]
fn decode_rejects_malformed_header_json() {
    let mut body = Vec::new();
    body.extend_from_slice(MAGIC);
    let garbage = b"{ not json";
    body.extend_from_slice(&(garbage.len() as u32).to_le_bytes());
    body.extend_from_slice(garbage);
    assert!(matches!(
        decode_result(&body).unwrap_err(),
        GcolError::BadHeader { .. }
    ));
}

#[test]
fn decode_rejects_forged_row_count_past_bitmap_capacity() {
    // A forged header claiming a huge row_count against a tiny present bitmap must be a controlled
    // error, NOT an out-of-bounds panic in the bit unpacker (`04 §11.4`). One column, a 1-byte
    // bitmap (8 bits) but a row_count of 10_000.
    let header = GcolHeader {
        version: FORMAT_VERSION,
        fields: vec!["x".to_owned()],
        row_count: 10_000,
        columns: vec![GcolColumn {
            name: "x".to_owned(),
            codec: "i64".to_owned(),
            present_count: 0,
        }],
        summary: summary(),
    };
    let header_bytes = serde_json::to_vec(&header).unwrap();
    let mut body = Vec::new();
    body.extend_from_slice(MAGIC);
    body.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    body.extend_from_slice(&header_bytes);
    // A 1-byte present bitmap (can describe at most 8 rows, not 10_000) + an empty payload.
    body.extend_from_slice(&1u32.to_le_bytes());
    body.push(0u8);
    body.extend_from_slice(&0u32.to_le_bytes());
    assert!(matches!(
        decode_result(&body).unwrap_err(),
        GcolError::BadHeader { .. }
    ));
}
