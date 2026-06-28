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
        // A point renders as a Cypher-ish `point({srid, x, y[, z]})` (`rmp` task #73).
        Value::Point(p) => {
            let _ = write!(out, "point({{srid: {}, x: ", p.crs.srid());
            write_float(out, p.x());
            out.push_str(", y: ");
            write_float(out, p.y());
            if let Some(z) = p.z() {
                out.push_str(", z: ");
                write_float(out, z);
            }
            out.push_str("})");
        }
    }
}

/// Writes a string in Cypher double-quoted form, escaping `\` and `"` and **every** control character.
///
/// The common control chars get their short C-style escapes (`\n`, `\r`, `\t`); any other control
/// character — crucially `\x1b` (ESC) and the rest of the C0/C1 ranges, NUL, BEL, DEL — is emitted as
/// a `\u{XXXX}` escape rather than verbatim. This is a security control: a stored string value can
/// carry raw terminal escape sequences (colour codes, cursor moves, even clear-screen), and rendering
/// them verbatim would let untrusted graph data drive the operator's terminal (escape injection).
/// Escaping all control bytes keeps a rendered value inert text.
fn write_quoted(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Any remaining control character (ESC, NUL, BEL, the C0/C1 ranges, DEL, …) is rendered as
            // an inert `\u{XXXX}` escape so it cannot drive the terminal. Non-control chars pass through.
            c if c.is_control() => {
                let _ = write!(out, "\\u{{{:04x}}}", c as u32);
            }
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

/// A bounded sentinel rendered for a temporal value whose day count is so extreme that the civil-date
/// conversion would overflow `i64` (reachable only for a day count within `719_468` of `i64::MAX`,
/// which the storage codec can round-trip). Rendering this inert string is preferable to wrapping
/// (release) or panicking (debug).
const DATE_OUT_OF_RANGE: &str = "Date(out-of-range)";

/// Writes a calendar date as `YYYY-MM-DD` from days since the Unix epoch (proleptic Gregorian).
///
/// A day count within `719_468` of `i64::MAX` (which the storage codec can round-trip) would overflow
/// the civil-date conversion's positive shift; that case renders the bounded [`DATE_OUT_OF_RANGE`]
/// sentinel instead of wrapping or panicking.
fn write_date(out: &mut String, days_since_epoch: i64) {
    match civil_from_days(days_since_epoch) {
        Some((y, m, d)) => {
            let _ = write!(out, "{y:04}-{m:02}-{d:02}");
        }
        None => out.push_str(DATE_OUT_OF_RANGE),
    }
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
///
/// As with [`write_date`], a date component so extreme that the civil-date conversion would overflow
/// renders the bounded [`DATE_OUT_OF_RANGE`] sentinel rather than wrapping or panicking. (Dividing
/// `epoch_seconds` by 86 400 keeps `days` well inside the safe range for any in-range `i64` seconds,
/// so this branch is defensive; it matches `write_date`'s contract exactly.)
fn write_local_datetime(out: &mut String, epoch_seconds: i64, nanos: u32) {
    let days = epoch_seconds.div_euclid(NANOS_PER_DAY as i64 / 1_000_000_000);
    let secs_of_day = epoch_seconds.rem_euclid(86_400);
    let Some((y, mo, d)) = civil_from_days(days) else {
        out.push_str(DATE_OUT_OF_RANGE);
        return;
    };
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

/// Converts a day count since the Unix epoch to a proleptic-Gregorian `(year, month, day)`, or `None`
/// when the conversion would overflow `i64`.
///
/// Uses Howard Hinnant's well-known `civil_from_days` algorithm (public-domain). The algorithm first
/// shifts the day count by `+719_468` to anchor the era arithmetic; because the shift is positive it
/// can only overflow at the **top** of the range — for a `z` within `719_468` of `i64::MAX` (the low
/// end, including `i64::MIN`, never overflows the shift). Such high day counts are reachable because
/// the storage codec round-trips the full `i64` `Date` range. Rather than wrap (release) or panic
/// (debug), the overflowing shift returns `None`; the caller renders a bounded sentinel. For every
/// non-overflowing `z` the remaining arithmetic stays within Hinnant's proven bounds, so the result is
/// exact across the representable range.
fn civil_from_days(z: i64) -> Option<(i64, u32, u32)> {
    let z = z.checked_add(719_468)?;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    Some((if m <= 2 { y + 1 } else { y }, m, d))
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

    // `rmp` #464 (F-CLI-1): a stored string can carry raw terminal control bytes (ESC, BEL, NUL, …).
    // Rendering them verbatim is escape injection — untrusted graph data driving the operator's
    // terminal. Every control character must be emitted ESCAPED (`\u{XXXX}`), never raw.
    #[test]
    fn control_bytes_are_escaped_not_emitted_raw() {
        // A classic ANSI escape sequence: ESC [ 3 1 m (set red) embedded in a value.
        let injected = Value::String("\u{1b}[31mRED\u{1b}[0m".to_owned());
        let rendered = render_value(&injected);
        // The raw ESC byte must NOT survive into the output...
        assert!(
            !rendered.contains('\u{1b}'),
            "raw ESC must not be emitted: {rendered:?}"
        );
        // ...it must appear as the inert `\u{001b}` escape instead.
        assert!(
            rendered.contains("\\u{001b}"),
            "ESC must be escaped as \\u{{001b}}: {rendered:?}"
        );
        assert_eq!(rendered, "\"\\u{001b}[31mRED\\u{001b}[0m\"");

        // A spread of other C0/C1/DEL control bytes, plus the explicitly-handled short escapes.
        let controls = Value::String("\u{0}\u{7}\u{8}\u{1f}\u{7f}\u{9b}\t\n\r".to_owned());
        let r = render_value(&controls);
        assert_eq!(
            r,
            // NUL, BEL, BS, US, DEL, CSI escaped as \u{..}; TAB/LF/CR keep their short escapes.
            "\"\\u{0000}\\u{0007}\\u{0008}\\u{001f}\\u{007f}\\u{009b}\\t\\n\\r\""
        );
        // No actual control byte leaks through (the strongest invariant: the rendered text is inert).
        assert!(
            !r.chars().any(|c| c.is_control()),
            "no raw control char may survive escaping: {r:?}"
        );
        // Ordinary characters (incl. non-ASCII printable) still pass through verbatim.
        assert_eq!(
            render_value(&Value::String("héllo café".to_owned())),
            "\"héllo café\""
        );
    }

    // `rmp` #464 (F-CLI-2): a `Date` at `i64::MIN`/`MAX` (the storage codec round-trips the full
    // range) must render a BOUNDED string with NO panic and NO silent wrap. The civil-date conversion
    // shifts the day count by `+719_468`; that shift overflows only at the very top of the `i64` range
    // (`> i64::MAX - 719_468`), so `i64::MAX` renders the bounded `Date(out-of-range)` sentinel via the
    // `checked_add` guard. `i64::MIN + 719_468` does NOT overflow, so the algorithm stays valid there
    // and yields a (correct, astronomically negative) date — which is itself a bounded, panic-free
    // string. Both ends therefore satisfy the gate: bounded, no panic, no wrap. This test runs in the
    // debug profile where overflow checks are ON, so a wrapping bug at either extreme would panic here.
    #[test]
    fn extreme_dates_render_bounded_string_without_panic() {
        let max = render_value(&Value::Date(Date {
            days_since_epoch: i64::MAX,
        }));
        let min = render_value(&Value::Date(Date {
            days_since_epoch: i64::MIN,
        }));
        // The high extreme overflows the `+719_468` shift -> bounded sentinel (the bug's locus).
        assert_eq!(
            max, "Date(out-of-range)",
            "i64::MAX overflows the civil shift and must render the bounded sentinel"
        );
        // The low extreme does NOT overflow; it renders a real (extreme) date, bounded and panic-free.
        assert_ne!(
            min, "Date(out-of-range)",
            "i64::MIN does not overflow the shift; it renders a valid extreme date: {min}"
        );
        // Both outputs are BOUNDED and carry no raw control bytes (the gate's invariant for either end).
        for s in [&max, &min] {
            assert!(s.len() < 64, "rendered date must be bounded: {s:?}");
            assert!(
                !s.chars().any(|c| c.is_control()),
                "rendered date must be inert text: {s:?}"
            );
        }
        // The largest non-overflowing day count renders a real date, not the sentinel (the sentinel is
        // reserved strictly for the overflowing shift, never for a merely "large" but valid date).
        let safe = render_value(&Value::Date(Date {
            days_since_epoch: i64::MAX - 719_468,
        }));
        assert_ne!(
            safe, "Date(out-of-range)",
            "the largest non-overflowing date must render normally: {safe}"
        );
    }
}
