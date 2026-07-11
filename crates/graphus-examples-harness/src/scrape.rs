//! Prometheus text-exposition scraping for example evidence (`rmp #684`).
//!
//! Every `examples/*` run boots (or targets) a Graphus server that exposes a Prometheus
//! `/metrics` endpoint. This module turns that endpoint's **text exposition** into a typed
//! [`MetricsSnapshot`] so an example can capture **server-side** evidence — committed/aborted
//! transactions, the retained-SSI gauge, slow queries, the reliability panic/force-detach counters,
//! and the query-duration histogram — both for a *local* server it booted and for a *remote*
//! instance where `/proc` and the store files are inaccessible. It is the single biggest evidence
//! gap the reliability/perf audits flagged.
//!
//! ## Why hand-rolled (no dependency)
//!
//! This is a dev-only leaf crate whose `Cargo.toml` mandates a lean dependency surface. The
//! Prometheus text format is small and stable, so we parse it directly rather than pulling in
//! `prometheus-parse` (and its transitive graph). The parser is deliberately **lenient**: any line
//! it does not understand is ignored, so a future metric never breaks an example.
//!
//! ## What is captured
//!
//! - **Scalars** — plain counters/gauges `name value` are keyed by their full metric name.
//! - **Per-database series** — a `name{database="X",…} value` line is routed into a per-database
//!   scalar table keyed by the `database` label (Graphus's `graphus_db_*` family, `rmp #463`).
//! - **Histograms** — a `name_bucket{le="…"} v` / `name_sum` / `name_count` trio (Graphus's
//!   `graphus_query_duration_seconds`, and the per-db `graphus_db_query_duration_seconds`) is folded
//!   into a [`Histogram`] with cumulative buckets, a sum, and a count. Histogram membership is
//!   detected from `# TYPE … histogram` comments **and** structurally (any `_bucket` line carrying
//!   an `le` label), so a snapshot parses correctly even if the `# TYPE` header is absent.
//!
//! The parse is total (it never fails) and side-effect-free; see [`parse`].

use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------------------------
// Public data model
// ---------------------------------------------------------------------------------------------

/// One cumulative histogram bucket: an upper bound (`le`) and the cumulative observation count at or
/// below it. The `+Inf` bucket is stored with [`f64::INFINITY`] as its `le`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bucket {
    /// Inclusive upper bound of the bucket (`le` label). `+Inf` is stored as [`f64::INFINITY`].
    pub le: f64,
    /// Cumulative observation count at or below `le` (Prometheus buckets are cumulative).
    pub cumulative: f64,
}

/// A parsed Prometheus histogram: cumulative buckets (sorted ascending by `le`), the running `_sum`,
/// and the total `_count`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Histogram {
    /// Cumulative buckets, sorted ascending by `le` with the `+Inf` bucket last.
    pub buckets: Vec<Bucket>,
    /// Sum of all observed values (`name_sum`), in the metric's native unit (seconds for durations).
    pub sum: f64,
    /// Total number of observations (`name_count`); equal to the `+Inf` bucket's cumulative count.
    pub count: f64,
}

impl Histogram {
    /// The cumulative count recorded for the exact upper bound `le`, if that bucket exists.
    ///
    /// Bounds are matched by value; because `before`/`after` snapshots come from the same server they
    /// share identical bucket boundaries (including `+Inf`, where `INFINITY == INFINITY`).
    #[must_use]
    pub fn cumulative_at(&self, le: f64) -> Option<f64> {
        self.buckets
            .iter()
            .find(|b| b.le == le)
            .map(|b| b.cumulative)
    }

    /// The per-window histogram obtained by subtracting an earlier `before` snapshot from this one.
    ///
    /// Prometheus counters only increase, so every cumulative bucket delta (and the `sum`/`count`
    /// deltas) is clamped at `0`. A missing `before` (the first observation of this histogram) is
    /// treated as an all-zero baseline, so the delta is simply this histogram.
    #[must_use]
    pub fn delta(&self, before: Option<&Histogram>) -> Histogram {
        let buckets = self
            .buckets
            .iter()
            .map(|b| {
                let prior = before.and_then(|h| h.cumulative_at(b.le)).unwrap_or(0.0);
                Bucket {
                    le: b.le,
                    cumulative: (b.cumulative - prior).max(0.0),
                }
            })
            .collect();
        let sum = (self.sum - before.map_or(0.0, |h| h.sum)).max(0.0);
        let count = (self.count - before.map_or(0.0, |h| h.count)).max(0.0);
        Histogram {
            buckets,
            sum,
            count,
        }
    }

    /// Estimates the `q`-quantile (`0.0..=1.0`) of the distribution using Prometheus's
    /// `histogram_quantile` linear-interpolation rule over the cumulative buckets.
    ///
    /// Returns `0.0` for an empty or all-zero histogram. When the quantile falls in the `+Inf`
    /// bucket, the largest finite bound is returned (as Prometheus does), since the true value is
    /// unknown above it. The result is in the histogram's native unit (seconds for durations).
    #[must_use]
    pub fn quantile(&self, q: f64) -> f64 {
        let n = self.buckets.len();
        if n == 0 {
            return 0.0;
        }
        // Total observations = cumulative count of the last (highest, i.e. +Inf) bucket.
        let total = self.buckets[n - 1].cumulative;
        if total <= 0.0 {
            return 0.0;
        }
        let rank = q * total;
        // First finite bucket (indices 0..n-1, excluding the +Inf terminator) whose cumulative count
        // reaches `rank`. If none do, `b` stays at the terminator index.
        let mut b = n - 1;
        for (i, bucket) in self.buckets[..n - 1].iter().enumerate() {
            if bucket.cumulative >= rank {
                b = i;
                break;
            }
        }
        if b == n - 1 {
            // The quantile is in the +Inf bucket: report the largest finite bound.
            return if n >= 2 { self.buckets[n - 2].le } else { 0.0 };
        }
        let bucket_end = self.buckets[b].le;
        let (bucket_start, prev_cum) = if b > 0 {
            (self.buckets[b - 1].le, self.buckets[b - 1].cumulative)
        } else {
            (0.0, 0.0)
        };
        let count = self.buckets[b].cumulative - prev_cum;
        if count <= 0.0 {
            return bucket_end;
        }
        bucket_start + (bucket_end - bucket_start) * ((rank - prev_cum) / count)
    }
}

/// A typed snapshot of a Prometheus `/metrics` scrape.
///
/// Built by [`parse`]. Scalar series are keyed by full metric name; per-database series are
/// additionally bucketed by their `database` label; histograms are keyed by their base name (the
/// metric without the `_bucket`/`_sum`/`_count` suffix). Query with [`scalar`](Self::scalar),
/// [`db_scalar`](Self::db_scalar), [`histogram`](Self::histogram), and
/// [`db_histogram`](Self::db_histogram).
#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    /// Global (unlabelled) counters/gauges: metric name → value.
    scalars: BTreeMap<String, f64>,
    /// Global histograms: base metric name → [`Histogram`].
    histograms: BTreeMap<String, Histogram>,
    /// Per-database scalars: database → (metric name → value).
    db_scalars: BTreeMap<String, BTreeMap<String, f64>>,
    /// Per-database histograms: database → (base metric name → [`Histogram`]).
    db_histograms: BTreeMap<String, BTreeMap<String, Histogram>>,
}

impl MetricsSnapshot {
    /// The value of a global (unlabelled) scalar series, if present.
    #[must_use]
    pub fn scalar(&self, name: &str) -> Option<f64> {
        self.scalars.get(name).copied()
    }

    /// The value of a per-database scalar series (`name{database=db}`), if present.
    #[must_use]
    pub fn db_scalar(&self, database: &str, name: &str) -> Option<f64> {
        self.db_scalars.get(database)?.get(name).copied()
    }

    /// A global histogram by its base name (e.g. `graphus_query_duration_seconds`), if present.
    #[must_use]
    pub fn histogram(&self, base: &str) -> Option<&Histogram> {
        self.histograms.get(base)
    }

    /// A per-database histogram (`base{database=db}`), if present.
    #[must_use]
    pub fn db_histogram(&self, database: &str, base: &str) -> Option<&Histogram> {
        self.db_histograms.get(database)?.get(base)
    }

    /// `true` if any per-database series (scalar or histogram) was seen for `database`.
    #[must_use]
    pub fn has_database(&self, database: &str) -> bool {
        self.db_scalars.contains_key(database) || self.db_histograms.contains_key(database)
    }

    /// Every database name that carries at least one per-database series, in sorted order.
    #[must_use]
    pub fn databases(&self) -> Vec<&str> {
        self.db_scalars
            .keys()
            .chain(self.db_histograms.keys())
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Folds one parsed series into the snapshot, routing it to the right table by classification.
    fn ingest(&mut self, series: RawSeries, histogram_bases: &BTreeSet<String>) {
        let database = series.label("database").map(str::to_string);
        match classify(&series.name, histogram_bases) {
            (_, Part::Scalar) => {
                let table = match &database {
                    Some(db) => self.db_scalars.entry(db.clone()).or_default(),
                    None => &mut self.scalars,
                };
                table.insert(series.name, series.value);
            }
            (base, Part::Bucket) => {
                if let Some(le) = series.label("le").and_then(parse_f64) {
                    self.histogram_mut(&database, &base).buckets.push(Bucket {
                        le,
                        cumulative: series.value,
                    });
                }
            }
            (base, Part::Sum) => self.histogram_mut(&database, &base).sum = series.value,
            (base, Part::Count) => self.histogram_mut(&database, &base).count = series.value,
        }
    }

    /// Mutable access to the (global or per-database) histogram for `base`, creating it if absent.
    fn histogram_mut(&mut self, database: &Option<String>, base: &str) -> &mut Histogram {
        match database {
            Some(db) => self
                .db_histograms
                .entry(db.clone())
                .or_default()
                .entry(base.to_string())
                .or_default(),
            None => self.histograms.entry(base.to_string()).or_default(),
        }
    }

    /// Sorts every histogram's buckets ascending by `le` (with `+Inf` last) so quantile/delta logic
    /// can assume order regardless of the exposition line order.
    fn finalize(&mut self) {
        let sort = |h: &mut Histogram| h.buckets.sort_by(|a, b| a.le.total_cmp(&b.le));
        self.histograms.values_mut().for_each(sort);
        for per_db in self.db_histograms.values_mut() {
            per_db.values_mut().for_each(sort);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------------------------

/// Parses a Prometheus text-exposition body into a [`MetricsSnapshot`].
///
/// The parse is **total** (never fails) and **lenient**: comment lines other than `# TYPE …
/// histogram` are ignored, and any data line that does not parse (malformed value, missing name) is
/// skipped rather than aborting the scrape. An empty input yields an empty snapshot.
///
/// # Examples
///
/// ```
/// use graphus_examples_harness::scrape;
///
/// let snap = scrape::parse(
///     "# TYPE graphus_transactions_committed_total counter\n\
///      graphus_transactions_committed_total 42\n\
///      graphus_db_slow_queries_total{database=\"graphus\"} 3\n",
/// );
/// assert_eq!(snap.scalar("graphus_transactions_committed_total"), Some(42.0));
/// assert_eq!(snap.db_scalar("graphus", "graphus_db_slow_queries_total"), Some(3.0));
/// ```
#[must_use]
pub fn parse(text: &str) -> MetricsSnapshot {
    let mut histogram_bases: BTreeSet<String> = BTreeSet::new();
    let mut raw: Vec<RawSeries> = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix('#') {
            // The only comment we act on is `# TYPE <name> histogram`, which declares a histogram
            // base name authoritatively. Everything else (HELP, other TYPEs) is ignored.
            let mut it = comment.split_whitespace();
            if it.next() == Some("TYPE") {
                if let (Some(name), Some(kind)) = (it.next(), it.next()) {
                    if kind == "histogram" {
                        histogram_bases.insert(name.to_string());
                    }
                }
            }
            continue;
        }
        if let Some(series) = parse_line(line) {
            // Structural fallback: any `_bucket` line with an `le` label proves its base is a
            // histogram, even without a `# TYPE` header.
            if series.label("le").is_some() {
                if let Some(base) = series.name.strip_suffix("_bucket") {
                    histogram_bases.insert(base.to_string());
                }
            }
            raw.push(series);
        }
    }

    let mut snapshot = MetricsSnapshot::default();
    for series in raw {
        snapshot.ingest(series, &histogram_bases);
    }
    snapshot.finalize();
    snapshot
}

/// A single parsed exposition line: metric name, its label set, and the numeric value.
struct RawSeries {
    name: String,
    labels: Vec<(String, String)>,
    value: f64,
}

impl RawSeries {
    /// The value of label `key`, if the series carries it.
    fn label(&self, key: &str) -> Option<&str> {
        self.labels
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Which part of a (possibly histogram) metric a series line represents.
enum Part {
    /// A plain counter/gauge value.
    Scalar,
    /// A histogram `_bucket` line (carries an `le` label).
    Bucket,
    /// A histogram `_sum` line.
    Sum,
    /// A histogram `_count` line.
    Count,
}

/// Classifies a metric name into `(base_name, part)`.
///
/// A `_bucket`/`_sum`/`_count` suffix maps to the corresponding histogram part **only** when the
/// stripped base is a known histogram (from a `# TYPE` header or an observed `_bucket` line);
/// otherwise the name is a scalar in its own right (e.g. a counter literally ending in `_count`).
fn classify(name: &str, histogram_bases: &BTreeSet<String>) -> (String, Part) {
    for (suffix, part) in [
        ("_bucket", Part::Bucket),
        ("_sum", Part::Sum),
        ("_count", Part::Count),
    ] {
        if let Some(base) = name.strip_suffix(suffix) {
            if histogram_bases.contains(base) {
                return (base.to_string(), part);
            }
        }
    }
    (name.to_string(), Part::Scalar)
}

/// Parses one non-comment exposition line into a [`RawSeries`], or `None` if it is malformed.
fn parse_line(line: &str) -> Option<RawSeries> {
    // The metric name runs up to the first `{` (labels) or ASCII whitespace (value).
    let name_end = line.find(['{', ' ', '\t'])?;
    let name = line[..name_end].to_string();
    if name.is_empty() {
        return None;
    }
    let rest = &line[name_end..];
    let (labels, remainder) = if rest.starts_with('{') {
        let (inner, after) = split_label_block(rest)?;
        (parse_labels(inner), after)
    } else {
        (Vec::new(), rest)
    };
    // The value is the first whitespace-delimited token of the remainder; any trailing timestamp is
    // ignored. `+Inf`/`-Inf`/`NaN` parse via `f64::from_str`.
    let value = remainder.split_whitespace().next()?.parse::<f64>().ok()?;
    Some(RawSeries {
        name,
        labels,
        value,
    })
}

/// Given `rest` starting at `{`, returns `(inner_labels, remainder_after_close)` by scanning for the
/// matching `}` **outside** any quoted string, so a `}` inside a label value cannot end the block
/// early. Returns `None` if the block is unterminated.
fn split_label_block(rest: &str) -> Option<(&str, &str)> {
    let bytes = rest.as_bytes();
    let mut i = 1; // skip the opening '{'
    let mut in_quote = false;
    let mut escaped = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_quote {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_quote = false;
            }
        } else if c == b'"' {
            in_quote = true;
        } else if c == b'}' {
            // `{`, `}`, `"` and `\` are ASCII, so these byte indices are char boundaries.
            return Some((&rest[1..i], &rest[i + 1..]));
        }
        i += 1;
    }
    None
}

/// Parses the inside of a `{...}` label block into `key → value` pairs, honouring quoted values and
/// the `\\`, `\"`, `\n` escape sequences the exposition format permits.
fn parse_labels(inner: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = inner.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Skip separators (comma / whitespace) between labels.
        while i < bytes.len() && matches!(bytes[i], b',' | b' ' | b'\t') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        // Key: up to '='.
        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let key = inner[key_start..i].trim().to_string();
        i += 1; // skip '='
        // Value: a double-quoted string.
        if i >= bytes.len() || bytes[i] != b'"' {
            break;
        }
        i += 1; // skip opening quote
        let value_start = i;
        let mut escaped = false;
        let mut has_escape = false;
        while i < bytes.len() {
            let c = bytes[i];
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
                has_escape = true;
            } else if c == b'"' {
                break;
            }
            i += 1;
        }
        // `"` and `\` are ASCII, so `value_start..i` is a char boundary slice.
        let raw = &inner[value_start..i];
        let value = if has_escape {
            unescape(raw)
        } else {
            raw.to_string()
        };
        i += 1; // skip closing quote
        if !key.is_empty() {
            out.push((key, value));
        }
    }
    out
}

/// Decodes the exposition escape sequences (`\\`, `\"`, `\n`) in a label value; other backslash
/// sequences are passed through verbatim.
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Parses a Prometheus numeric token (`123`, `0.0005`, `+Inf`, `NaN`), returning `None` on failure.
fn parse_f64(s: &str) -> Option<f64> {
    s.trim().parse::<f64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A verbatim `/metrics` scrape captured from a live Graphus instance. Embedding the real
    /// output — including the global and per-database `query_duration` histograms — proves the parser
    /// against genuine server exposition rather than a hand-tuned fixture.
    const LIVE_SAMPLE: &str = r#"# HELP graphus_transactions_committed_total Transactions committed successfully.
# TYPE graphus_transactions_committed_total counter
graphus_transactions_committed_total 191
# HELP graphus_transactions_aborted_total Transactions aborted or rolled back.
# TYPE graphus_transactions_aborted_total counter
graphus_transactions_aborted_total 1425
# HELP graphus_active_transactions Currently-open transactions.
# TYPE graphus_active_transactions gauge
graphus_active_transactions 0
# HELP graphus_slow_queries_total Queries exceeding the slow-query threshold.
# TYPE graphus_slow_queries_total counter
graphus_slow_queries_total 0
# HELP graphus_statement_panics_total Statements whose execution panicked and was caught at the engine panic boundary (rmp #386).
# TYPE graphus_statement_panics_total counter
graphus_statement_panics_total 0
# HELP graphus_ssi_tracked_transactions Retained SSI conflict records across all engines; grows while a long-lived active reader pins the GC watermark (rmp #591).
# TYPE graphus_ssi_tracked_transactions gauge
graphus_ssi_tracked_transactions 190
# HELP graphus_engine_recovery_panics_total Statement-recovery double-panics caught at the engine recovery boundary (rmp #409).
# TYPE graphus_engine_recovery_panics_total counter
graphus_engine_recovery_panics_total 0
# HELP graphus_engine_force_detached_total Wedged engines force-detached while stopping; each left a zombie holding its store-open lock (rmp #598).
# TYPE graphus_engine_force_detached_total counter
graphus_engine_force_detached_total 0
# HELP graphus_engine_force_detached_active Force-detached zombies still believed to hold their store-open lock, blocking START DATABASE for that store (rmp #598).
# TYPE graphus_engine_force_detached_active gauge
graphus_engine_force_detached_active 0
# HELP graphus_query_duration_seconds Query execution latency in seconds.
# TYPE graphus_query_duration_seconds histogram
graphus_query_duration_seconds_bucket{le="0.0005"} 33
graphus_query_duration_seconds_bucket{le="0.001"} 41
graphus_query_duration_seconds_bucket{le="0.0025"} 47
graphus_query_duration_seconds_bucket{le="0.005"} 47
graphus_query_duration_seconds_bucket{le="0.01"} 47
graphus_query_duration_seconds_bucket{le="0.025"} 47
graphus_query_duration_seconds_bucket{le="0.05"} 47
graphus_query_duration_seconds_bucket{le="0.1"} 47
graphus_query_duration_seconds_bucket{le="0.25"} 47
graphus_query_duration_seconds_bucket{le="0.5"} 47
graphus_query_duration_seconds_bucket{le="1"} 47
graphus_query_duration_seconds_bucket{le="2.5"} 47
graphus_query_duration_seconds_bucket{le="+Inf"} 47
graphus_query_duration_seconds_sum 0.022482
graphus_query_duration_seconds_count 47
# HELP graphus_db_transactions_committed_total Transactions committed successfully, per database (rmp #463).
# TYPE graphus_db_transactions_committed_total counter
graphus_db_transactions_committed_total{database="ex_probe_tmp"} 1
graphus_db_transactions_committed_total{database="graphus"} 190
# HELP graphus_db_transactions_aborted_total Transactions aborted or rolled back, per database (rmp #463).
# TYPE graphus_db_transactions_aborted_total counter
graphus_db_transactions_aborted_total{database="ex_probe_tmp"} 0
graphus_db_transactions_aborted_total{database="graphus"} 1425
# HELP graphus_db_active_transactions Currently-open transactions, per database (rmp #463).
# TYPE graphus_db_active_transactions gauge
graphus_db_active_transactions{database="ex_probe_tmp"} 0
graphus_db_active_transactions{database="graphus"} 0
# HELP graphus_db_slow_queries_total Queries exceeding the slow-query threshold, per database (rmp #463).
# TYPE graphus_db_slow_queries_total counter
graphus_db_slow_queries_total{database="ex_probe_tmp"} 0
graphus_db_slow_queries_total{database="graphus"} 0
# HELP graphus_db_query_duration_seconds Query execution latency in seconds, per database (rmp #463).
# TYPE graphus_db_query_duration_seconds histogram
graphus_db_query_duration_seconds_bucket{database="ex_probe_tmp",le="0.0005"} 1
graphus_db_query_duration_seconds_bucket{database="ex_probe_tmp",le="0.001"} 1
graphus_db_query_duration_seconds_bucket{database="ex_probe_tmp",le="0.0025"} 1
graphus_db_query_duration_seconds_bucket{database="ex_probe_tmp",le="0.005"} 1
graphus_db_query_duration_seconds_bucket{database="ex_probe_tmp",le="0.01"} 1
graphus_db_query_duration_seconds_bucket{database="ex_probe_tmp",le="0.025"} 1
graphus_db_query_duration_seconds_bucket{database="ex_probe_tmp",le="0.05"} 1
graphus_db_query_duration_seconds_bucket{database="ex_probe_tmp",le="0.1"} 1
graphus_db_query_duration_seconds_bucket{database="ex_probe_tmp",le="0.25"} 1
graphus_db_query_duration_seconds_bucket{database="ex_probe_tmp",le="0.5"} 1
graphus_db_query_duration_seconds_bucket{database="ex_probe_tmp",le="1"} 1
graphus_db_query_duration_seconds_bucket{database="ex_probe_tmp",le="2.5"} 1
graphus_db_query_duration_seconds_bucket{database="ex_probe_tmp",le="+Inf"} 1
graphus_db_query_duration_seconds_sum{database="ex_probe_tmp"} 0.000019
graphus_db_query_duration_seconds_count{database="ex_probe_tmp"} 1
graphus_db_query_duration_seconds_bucket{database="graphus",le="0.0005"} 32
graphus_db_query_duration_seconds_bucket{database="graphus",le="0.001"} 40
graphus_db_query_duration_seconds_bucket{database="graphus",le="0.0025"} 46
graphus_db_query_duration_seconds_bucket{database="graphus",le="0.005"} 46
graphus_db_query_duration_seconds_bucket{database="graphus",le="0.01"} 46
graphus_db_query_duration_seconds_bucket{database="graphus",le="0.025"} 46
graphus_db_query_duration_seconds_bucket{database="graphus",le="0.05"} 46
graphus_db_query_duration_seconds_bucket{database="graphus",le="0.1"} 46
graphus_db_query_duration_seconds_bucket{database="graphus",le="0.25"} 46
graphus_db_query_duration_seconds_bucket{database="graphus",le="0.5"} 46
graphus_db_query_duration_seconds_bucket{database="graphus",le="1"} 46
graphus_db_query_duration_seconds_bucket{database="graphus",le="2.5"} 46
graphus_db_query_duration_seconds_bucket{database="graphus",le="+Inf"} 46
graphus_db_query_duration_seconds_sum{database="graphus"} 0.022463
graphus_db_query_duration_seconds_count{database="graphus"} 46
"#;

    #[test]
    fn parses_live_sample_scalars_and_gauges() {
        let snap = parse(LIVE_SAMPLE);

        // Plain counters and gauges are keyed by full name.
        assert_eq!(
            snap.scalar("graphus_transactions_committed_total"),
            Some(191.0)
        );
        assert_eq!(
            snap.scalar("graphus_transactions_aborted_total"),
            Some(1425.0)
        );
        assert_eq!(snap.scalar("graphus_slow_queries_total"), Some(0.0));
        assert_eq!(snap.scalar("graphus_ssi_tracked_transactions"), Some(190.0));
        // Reliability counters that MUST stay at zero on a healthy server.
        assert_eq!(snap.scalar("graphus_statement_panics_total"), Some(0.0));
        assert_eq!(
            snap.scalar("graphus_engine_recovery_panics_total"),
            Some(0.0)
        );
        assert_eq!(
            snap.scalar("graphus_engine_force_detached_total"),
            Some(0.0)
        );
        assert_eq!(
            snap.scalar("graphus_engine_force_detached_active"),
            Some(0.0)
        );
        // An unknown series is simply absent (lenient parse).
        assert_eq!(snap.scalar("graphus_nonexistent_total"), None);
    }

    #[test]
    fn parses_live_sample_global_histogram() {
        let snap = parse(LIVE_SAMPLE);
        let hist = snap
            .histogram("graphus_query_duration_seconds")
            .expect("global query-duration histogram present");

        // The specific figures from the real scrape.
        assert_eq!(hist.count, 47.0);
        assert!((hist.sum - 0.022482).abs() < 1e-12, "sum was {}", hist.sum);
        // A specific bucket line, and the +Inf terminator.
        assert_eq!(hist.cumulative_at(0.0005), Some(33.0));
        assert_eq!(hist.cumulative_at(0.001), Some(41.0));
        assert_eq!(hist.cumulative_at(f64::INFINITY), Some(47.0));
        // Buckets are sorted ascending with +Inf last.
        assert_eq!(hist.buckets.first().unwrap().le, 0.0005);
        assert!(hist.buckets.last().unwrap().le.is_infinite());
    }

    #[test]
    fn parses_live_sample_per_database_series() {
        let snap = parse(LIVE_SAMPLE);

        // Per-database scalars keyed by the `database` label.
        assert_eq!(
            snap.db_scalar("graphus", "graphus_db_transactions_committed_total"),
            Some(190.0)
        );
        assert_eq!(
            snap.db_scalar("ex_probe_tmp", "graphus_db_transactions_committed_total"),
            Some(1.0)
        );
        assert_eq!(
            snap.db_scalar("graphus", "graphus_db_transactions_aborted_total"),
            Some(1425.0)
        );

        // Per-database histograms.
        let db_hist = snap
            .db_histogram("graphus", "graphus_db_query_duration_seconds")
            .expect("per-db histogram for graphus");
        assert_eq!(db_hist.count, 46.0);
        assert_eq!(db_hist.cumulative_at(0.0005), Some(32.0));
        assert_eq!(db_hist.cumulative_at(f64::INFINITY), Some(46.0));

        // Database enumeration + membership.
        assert!(snap.has_database("graphus"));
        assert!(snap.has_database("ex_probe_tmp"));
        assert!(!snap.has_database("no_such_db"));
        assert_eq!(snap.databases(), vec!["ex_probe_tmp", "graphus"]);
    }

    #[test]
    fn quantile_uses_prometheus_interpolation() {
        // 10 observations, all in (0.001, 0.01].
        let hist = Histogram {
            buckets: vec![
                Bucket {
                    le: 0.001,
                    cumulative: 0.0,
                },
                Bucket {
                    le: 0.01,
                    cumulative: 10.0,
                },
                Bucket {
                    le: f64::INFINITY,
                    cumulative: 10.0,
                },
            ],
            sum: 0.05,
            count: 10.0,
        };
        // p50: rank 5 lands in the (0.001, 0.01] bucket: 0.001 + 0.009 * (5/10) = 0.0055.
        assert!((hist.quantile(0.50) - 0.0055).abs() < 1e-12);
        // p99: rank 9.9: 0.001 + 0.009 * (9.9/10) = 0.00991.
        assert!((hist.quantile(0.99) - 0.00991).abs() < 1e-12);
        // Empty / all-zero histogram is a safe zero.
        assert_eq!(Histogram::default().quantile(0.5), 0.0);
    }

    #[test]
    fn histogram_delta_subtracts_baseline() {
        let before = Histogram {
            buckets: vec![
                Bucket {
                    le: 0.001,
                    cumulative: 5.0,
                },
                Bucket {
                    le: f64::INFINITY,
                    cumulative: 8.0,
                },
            ],
            sum: 0.01,
            count: 8.0,
        };
        let after = Histogram {
            buckets: vec![
                Bucket {
                    le: 0.001,
                    cumulative: 7.0,
                },
                Bucket {
                    le: f64::INFINITY,
                    cumulative: 20.0,
                },
            ],
            sum: 0.05,
            count: 20.0,
        };
        let delta = after.delta(Some(&before));
        assert_eq!(delta.count, 12.0);
        assert!((delta.sum - 0.04).abs() < 1e-12);
        assert_eq!(delta.cumulative_at(0.001), Some(2.0));
        assert_eq!(delta.cumulative_at(f64::INFINITY), Some(12.0));
        // A missing baseline means the delta is the whole histogram.
        assert_eq!(after.delta(None).count, 20.0);
    }

    #[test]
    fn ignores_unparseable_and_comment_lines() {
        let snap = parse(
            "# a bare comment\n\
             garbage line with no value\n\
             graphus_ok_total not_a_number\n\
             graphus_ok_total 12\n\
             \n\
             graphus_labelled{database=\"graphus\",extra=\"x\"} 7\n",
        );
        // The malformed-value line is ignored; the valid one wins.
        assert_eq!(snap.scalar("graphus_ok_total"), Some(12.0));
        // A multi-label per-db line still routes by its `database` label.
        assert_eq!(snap.db_scalar("graphus", "graphus_labelled"), Some(7.0));
    }

    #[test]
    fn counter_ending_in_count_is_not_a_histogram() {
        // `_count` only means "histogram count" when its base is a known histogram; a standalone
        // counter that happens to end in `_count` stays a scalar.
        let snap = parse("graphus_widget_count 9\n");
        assert_eq!(snap.scalar("graphus_widget_count"), Some(9.0));
        assert!(snap.histogram("graphus_widget").is_none());
    }
}
