//! Result rendering for the Graphus shell: a [`Value`] formatted in a readable, Cypher-ish form and
//! an aligned ASCII result table.
//!
//! # Value rendering
//!
//! [`render_value`] formats a [`Value`] the way the Cypher shell ecosystem does:
//!
//! - `Null` → `null`; booleans → `true`/`false`; integers/floats → their numeric form.
//! - Strings are **quoted** (`"abc"`) so an empty string and a `null` are visually distinct.
//! - Lists → `[a, b, c]`; maps → `{k: v, …}` (insertion order, as stored).
//! - Bytes → a `0x…`-prefixed lowercase hex string.
//! - Temporal values → an ISO-8601-ish textual form.
//!
//! `Node`/`Relationship`/`Path`/`Point` are **not** modelled in [`graphus_core::Value`] yet (deferred
//! with their owning subsystems, `04 §7.2`), so they cannot appear in a result row and need no
//! rendering branch; when they land, a branch is added here.
//!
//! # Table rendering
//!
//! [`render_table`] draws a header row of column names, a `+--+--+` separator, then one row per
//! record. Columns are left-aligned and padded to the widest cell. A cell wider than
//! [`MAX_CELL_WIDTH`] is truncated with a trailing `…` (so a pathological value cannot blow the
//! terminal width); the full value is always available programmatically on the [`QueryResult`].

use std::fmt::Write as _;

use graphus_core::Value;
use graphus_core::value::temporal::NANOS_PER_DAY;

use crate::client::QueryResult;

/// The maximum rendered width of a single table cell before it is truncated with an ellipsis.
///
/// Chosen so a runaway value (a long string, a deep list) cannot stretch a row past a typical
/// terminal; the untruncated value remains accessible on the parsed [`QueryResult`].
pub const MAX_CELL_WIDTH: usize = 72;

/// Renders a single [`Value`] to a readable, Cypher-ish string (no width limit applied here).
#[must_use]
pub fn render_value(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

/// Renders a whole query result as an aligned ASCII table (header, separator, rows, footer count).
///
/// An empty result (no rows) still prints the header and a `(0 rows)` footer, so the column shape is
/// visible. A result with no columns at all (e.g. a write-only statement) prints just the row count.
#[must_use]
pub fn render_table(result: &QueryResult) -> String {
    if result.fields.is_empty() {
        return format!("{}\n", row_count_footer(result.row_count()));
    }

    // Render every cell up front so column widths can be computed from the truncated display text.
    let header: Vec<String> = result.fields.clone();
    let rows: Vec<Vec<String>> = result
        .records
        .iter()
        .map(|rec| {
            (0..header.len())
                .map(|i| truncate(&render_value(rec.get(i).unwrap_or(&Value::Null))))
                .collect()
        })
        .collect();

    // Column width = the widest of the (truncated) header and cells, measured in Unicode scalar
    // values (a pragmatic width proxy; full grapheme/East-Asian-width handling is out of scope and
    // documented as such).
    let widths: Vec<usize> = header
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let cell_max = rows.iter().map(|r| display_width(&r[i])).max().unwrap_or(0);
            display_width(h).max(cell_max)
        })
        .collect();

    let mut out = String::new();
    push_separator(&mut out, &widths);
    push_row(&mut out, &header, &widths);
    push_separator(&mut out, &widths);
    for row in &rows {
        push_row(&mut out, row, &widths);
    }
    push_separator(&mut out, &widths);
    let _ = writeln!(out, "{}", row_count_footer(result.row_count()));
    out
}

/// The `(N row[s])` footer line.
fn row_count_footer(n: usize) -> String {
    if n == 1 {
        "(1 row)".to_owned()
    } else {
        format!("({n} rows)")
    }
}

/// Writes a `+----+----+` separator line sized to `widths`.
fn push_separator(out: &mut String, widths: &[usize]) {
    out.push('+');
    for w in widths {
        // One space of padding on each side of every cell (`| cell |`).
        for _ in 0..(w + 2) {
            out.push('-');
        }
        out.push('+');
    }
    out.push('\n');
}

/// Writes one `| a | b |` data/header row, left-aligning and padding each cell to its column width.
fn push_row(out: &mut String, cells: &[String], widths: &[usize]) {
    out.push('|');
    for (i, w) in widths.iter().enumerate() {
        let cell = cells.get(i).map(String::as_str).unwrap_or("");
        let pad = w.saturating_sub(display_width(cell));
        out.push(' ');
        out.push_str(cell);
        for _ in 0..pad {
            out.push(' ');
        }
        out.push(' ');
        out.push('|');
    }
    out.push('\n');
}

/// Truncates `s` to [`MAX_CELL_WIDTH`] scalar values, appending `…` when it was cut.
fn truncate(s: &str) -> String {
    if display_width(s) <= MAX_CELL_WIDTH {
        return s.to_owned();
    }
    // Keep room for the one-char ellipsis. Count by `char` so we never split a UTF-8 sequence.
    let kept: String = s.chars().take(MAX_CELL_WIDTH.saturating_sub(1)).collect();
    format!("{kept}…")
}

/// A pragmatic display width: the number of Unicode scalar values.
///
/// This treats every `char` as width 1, which is exact for ASCII (the overwhelmingly common case in
/// identifiers and small results) and a close approximation otherwise. Full grapheme-cluster /
/// East-Asian-width accounting is intentionally out of scope.
fn display_width(s: &str) -> usize {
    s.chars().count()
}

/// Appends the Cypher-ish rendering of `value` to `out`.
fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Boolean(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Integer(n) => {
            let _ = write!(out, "{n}");
        }
        Value::Float(x) => write_float(out, *x),
        Value::String(s) => write_quoted(out, s),
        Value::Bytes(bytes) => {
            out.push_str("0x");
            for b in bytes {
                let _ = write!(out, "{b:02x}");
            }
        }
        Value::List(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Map(entries) => {
            out.push('{');
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(k);
                out.push_str(": ");
                write_value(out, v);
            }
            out.push('}');
        }
        Value::Date(d) => write_date(out, d.days_since_epoch),
        Value::LocalTime(t) => write_time_of_day(out, t.nanos_of_day),
        Value::ZonedTime(t) => {
            write_time_of_day(out, t.time.nanos_of_day);
            write_offset(out, t.offset_seconds);
        }
        Value::LocalDateTime(dt) => write_local_datetime(out, dt.epoch_seconds, dt.nanos),
        Value::ZonedDateTime(dt) => {
            write_local_datetime(out, dt.local.epoch_seconds, dt.local.nanos);
            write_offset(out, dt.offset_seconds);
            if !dt.zone_id.is_empty() {
                let _ = write!(out, "[{}]", dt.zone_id);
            }
        }
        Value::Duration(d) => {
            let _ = write!(
                out,
                "Duration(months={}, days={}, seconds={}, nanos={})",
                d.months, d.days, d.seconds, d.nanos
            );
        }
    }
}

/// Writes a string in Cypher double-quoted form, escaping `\` and `"` and the common control chars.
fn write_quoted(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out.push('"');
}

/// Writes a float, preserving a trailing `.0` for whole numbers (so `1.0` is not shown as `1`).
fn write_float(out: &mut String, x: f64) {
    if x.is_nan() {
        out.push_str("NaN");
    } else if x.is_infinite() {
        out.push_str(if x > 0.0 { "Infinity" } else { "-Infinity" });
    } else if x == x.trunc() && x.abs() < 1e16 {
        let _ = write!(out, "{x:.1}");
    } else {
        let _ = write!(out, "{x}");
    }
}

/// Writes a calendar date as `YYYY-MM-DD` from days since the Unix epoch (proleptic Gregorian).
fn write_date(out: &mut String, days_since_epoch: i32) {
    let (y, m, d) = civil_from_days(i64::from(days_since_epoch));
    let _ = write!(out, "{y:04}-{m:02}-{d:02}");
}

/// Writes a wall-clock time `HH:MM:SS[.fraction]` from nanoseconds-of-day.
fn write_time_of_day(out: &mut String, nanos_of_day: u64) {
    let nanos_of_day = nanos_of_day % NANOS_PER_DAY;
    let total_secs = nanos_of_day / 1_000_000_000;
    let nanos = nanos_of_day % 1_000_000_000;
    let (h, min, s) = (total_secs / 3600, (total_secs % 3600) / 60, total_secs % 60);
    let _ = write!(out, "{h:02}:{min:02}:{s:02}");
    write_fraction(out, nanos);
}

/// Writes a no-zone date-time `YYYY-MM-DDTHH:MM:SS[.fraction]` from epoch seconds + sub-second nanos.
fn write_local_datetime(out: &mut String, epoch_seconds: i64, nanos: u32) {
    let days = epoch_seconds.div_euclid(NANOS_PER_DAY as i64 / 1_000_000_000);
    let secs_of_day = epoch_seconds.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(days);
    let (h, min, s) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    let _ = write!(out, "{y:04}-{mo:02}-{d:02}T{h:02}:{min:02}:{s:02}");
    write_fraction(out, u64::from(nanos));
}

/// Appends `.fraction` (trimmed of trailing zeros) for a sub-second nanosecond count, if non-zero.
fn write_fraction(out: &mut String, nanos: u64) {
    if nanos == 0 {
        return;
    }
    let frac = format!("{nanos:09}");
    let trimmed = frac.trim_end_matches('0');
    out.push('.');
    out.push_str(trimmed);
}

/// Appends a UTC offset as `Z` (zero) or `±HH:MM`.
fn write_offset(out: &mut String, offset_seconds: i32) {
    if offset_seconds == 0 {
        out.push('Z');
        return;
    }
    let sign = if offset_seconds < 0 { '-' } else { '+' };
    let abs = offset_seconds.unsigned_abs();
    let (h, m) = (abs / 3600, (abs % 3600) / 60);
    let _ = write!(out, "{sign}{h:02}:{m:02}");
}

/// Converts a day count since the Unix epoch to a proleptic-Gregorian `(year, month, day)`.
///
/// Uses Howard Hinnant's well-known `civil_from_days` algorithm (public-domain), which is exact for
/// the full `i64` day range and avoids pulling in a date-time crate just to render dates.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_core::value::temporal::{Date, Duration, LocalDateTime, LocalTime};
    use std::time::Duration as StdDuration;

    fn result(fields: &[&str], records: Vec<Vec<Value>>) -> QueryResult {
        QueryResult {
            fields: fields.iter().map(|s| (*s).to_owned()).collect(),
            records,
            summary: vec![],
            elapsed: StdDuration::from_millis(0),
        }
    }

    #[test]
    fn scalars_render_cypher_ish() {
        assert_eq!(render_value(&Value::Null), "null");
        assert_eq!(render_value(&Value::Boolean(true)), "true");
        assert_eq!(render_value(&Value::Integer(-42)), "-42");
        assert_eq!(render_value(&Value::Float(1.0)), "1.0");
        assert_eq!(render_value(&Value::Float(2.5)), "2.5");
        assert_eq!(render_value(&Value::String("ab".to_owned())), "\"ab\"");
        // An empty string is visibly distinct from null.
        assert_eq!(render_value(&Value::String(String::new())), "\"\"");
    }

    #[test]
    fn strings_escape_quotes_and_controls() {
        assert_eq!(
            render_value(&Value::String("a\"b\\c\n".to_owned())),
            "\"a\\\"b\\\\c\\n\""
        );
    }

    #[test]
    fn collections_and_bytes_render() {
        let list = Value::List(vec![Value::Integer(1), Value::String("x".to_owned())]);
        assert_eq!(render_value(&list), "[1, \"x\"]");
        let map = Value::Map(vec![
            ("a".to_owned(), Value::Integer(1)),
            ("b".to_owned(), Value::Null),
        ]);
        assert_eq!(render_value(&map), "{a: 1, b: null}");
        assert_eq!(render_value(&Value::Bytes(vec![0x0a, 0xff])), "0x0aff");
    }

    #[test]
    fn temporal_values_render_iso_ish() {
        // 2021-01-01 is 18628 days after the epoch.
        assert_eq!(
            render_value(&Value::Date(Date {
                days_since_epoch: 18_628,
            })),
            "2021-01-01"
        );
        // 13:02:03 (no fraction).
        let secs = (13 * 3600 + 2 * 60 + 3) as u64 * 1_000_000_000;
        assert_eq!(
            render_value(&Value::LocalTime(LocalTime { nanos_of_day: secs })),
            "13:02:03"
        );
        assert_eq!(
            render_value(&Value::LocalDateTime(LocalDateTime {
                epoch_seconds: 0,
                nanos: 0,
            })),
            "1970-01-01T00:00:00"
        );
        assert_eq!(
            render_value(&Value::Duration(Duration {
                months: 1,
                days: 2,
                seconds: 3,
                nanos: 0,
            })),
            "Duration(months=1, days=2, seconds=3, nanos=0)"
        );
    }

    #[test]
    fn dates_before_the_epoch_render_correctly() {
        // -1 day is 1969-12-31; this exercises the negative `civil_from_days` branch.
        assert_eq!(
            render_value(&Value::Date(Date {
                days_since_epoch: -1,
            })),
            "1969-12-31"
        );
        // A negative epoch-seconds date-time, one second before the epoch, with a fractional part.
        assert_eq!(
            render_value(&Value::LocalDateTime(LocalDateTime {
                epoch_seconds: -1,
                nanos: 500_000_000,
            })),
            "1969-12-31T23:59:59.5"
        );
    }

    #[test]
    fn sub_second_fractions_trim_trailing_zeros() {
        // 1ms past midnight renders as `.001`, not `.001000000`.
        assert_eq!(
            render_value(&Value::LocalTime(LocalTime {
                nanos_of_day: 1_000_000,
            })),
            "00:00:00.001"
        );
    }

    #[test]
    fn table_is_aligned_with_header_and_footer() {
        let r = result(
            &["name", "age"],
            vec![
                vec![Value::String("Ada".to_owned()), Value::Integer(36)],
                vec![Value::String("Bo".to_owned()), Value::Integer(7)],
            ],
        );
        let table = render_table(&r);
        let lines: Vec<&str> = table.lines().collect();
        // border, header, border, 2 rows, border, footer = 7 lines.
        assert_eq!(lines.len(), 7, "table shape:\n{table}");
        assert_eq!(lines[1], "| name  | age |");
        assert_eq!(lines[3], "| \"Ada\" | 36  |");
        assert_eq!(lines[6], "(2 rows)");
        // Every border/row line is the same width (alignment invariant).
        let w = lines[0].chars().count();
        for l in &lines[..6] {
            assert_eq!(l.chars().count(), w, "ragged line: {l:?}");
        }
    }

    #[test]
    fn empty_result_shows_header_and_zero_rows() {
        let r = result(&["x"], vec![]);
        let table = render_table(&r);
        assert!(table.contains("| x |"), "header present:\n{table}");
        assert!(table.trim_end().ends_with("(0 rows)"));
    }

    #[test]
    fn columnless_result_shows_only_a_count() {
        let r = result(&[], vec![]);
        assert_eq!(render_table(&r).trim_end(), "(0 rows)");
    }

    #[test]
    fn wide_cells_are_truncated_with_an_ellipsis() {
        let long = "x".repeat(MAX_CELL_WIDTH * 2);
        let r = result(&["c"], vec![vec![Value::String(long)]]);
        let table = render_table(&r);
        assert!(table.contains('…'), "ellipsis present:\n{table}");
        // No data line exceeds the cap plus the framing (`| ` + ` |` + quotes).
        for line in table.lines() {
            assert!(
                line.chars().count() <= MAX_CELL_WIDTH + 8,
                "line too wide: {line:?}"
            );
        }
    }

    #[test]
    fn single_row_uses_singular_footer() {
        let r = result(&["x"], vec![vec![Value::Integer(1)]]);
        assert!(render_table(&r).contains("(1 row)"));
    }
}
