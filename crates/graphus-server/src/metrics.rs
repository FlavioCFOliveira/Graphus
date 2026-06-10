//! A minimal, dependency-free **Prometheus text-exposition** metrics registry (`04 §9` / NFR-10).
//!
//! The deliverable allows either the `metrics` + `metrics-exporter-prometheus` crates or a
//! hand-rolled exposition. We hand-roll a small one: it keeps the dependency surface tight (a
//! project value — see `CLAUDE.md`'s production-grade, minimal-deps stance) and the metric set is
//! small and fixed, so a registry of a few atomics plus a fixed-bucket latency histogram is simpler
//! and cheaper than pulling the exporter's transitive tree.
//!
//! Every counter/gauge is a single [`AtomicU64`] updated with `Relaxed` ordering: these are
//! independent observability counters with no happens-before relationship to protect, so `Relaxed`
//! is the correct (and cheapest) ordering (`04 §10.1` atomic-ordering discipline — use the weakest
//! ordering that is correct). The histogram is a fixed set of cumulative bucket counters, also
//! `Relaxed`, matching Prometheus' `_bucket{le=…}` cumulative semantics.
//!
//! The registry is shared as `Arc<Metrics>` across every connection task and the engine; it is
//! `Send + Sync` and never locks on the hot path.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Upper bounds (`le`, in seconds) of the query-latency histogram buckets. Cumulative: a sample is
/// counted in every bucket whose bound it is `<=`. The implicit `+Inf` bucket equals the total
/// count. Chosen to span sub-millisecond to multi-second queries.
const LATENCY_BUCKETS_SECS: [f64; 12] = [
    0.000_5, 0.001, 0.002_5, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
];

/// A fixed-bucket cumulative histogram for query latency, plus the running sum and count Prometheus
/// needs for `_sum`/`_count` (and quantile/`rate` math).
#[derive(Debug)]
struct LatencyHistogram {
    /// Cumulative counts, parallel to [`LATENCY_BUCKETS_SECS`]; `buckets[i]` is the number of
    /// samples `<= LATENCY_BUCKETS_SECS[i]`.
    buckets: [AtomicU64; LATENCY_BUCKETS_SECS.len()],
    /// Total number of observations (the implicit `+Inf` bucket and the `_count`).
    count: AtomicU64,
    /// Sum of all observed values in **microseconds** (kept as an integer to stay lock-free and
    /// exact; rendered back to seconds for `_sum`). Microsecond resolution is ample for query
    /// latency and avoids float atomics.
    sum_micros: AtomicU64,
}

impl LatencyHistogram {
    const fn new() -> Self {
        // `AtomicU64` is not `Copy`, so the array cannot be built with `[AtomicU64::new(0); N]`;
        // list each element. Twelve entries, matching `LATENCY_BUCKETS_SECS`.
        Self {
            buckets: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            count: AtomicU64::new(0),
            sum_micros: AtomicU64::new(0),
        }
    }

    fn observe(&self, d: Duration) {
        let secs = d.as_secs_f64();
        let micros = u64::try_from(d.as_micros()).unwrap_or(u64::MAX);
        self.sum_micros.fetch_add(micros, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        for (i, &bound) in LATENCY_BUCKETS_SECS.iter().enumerate() {
            if secs <= bound {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// The Graphus server metrics, exposed at `/metrics` in Prometheus text format.
///
/// Construct one per server, share it as `Arc<Metrics>`. All methods are lock-free.
#[derive(Debug)]
pub struct Metrics {
    // ---- transaction outcomes (`04 §9` / NFR-10) ----
    /// Transactions committed successfully.
    commits: AtomicU64,
    /// Transactions aborted/rolled back (explicit rollback, error, or SSI victim).
    aborts: AtomicU64,
    /// Currently-open transactions (a gauge, mirrors the engine's coordinator).
    active_txns: AtomicU64,

    // ---- admission control (`04 §9.3`) ----
    /// Queries fast-rejected because the admission semaphore was saturated ("server busy").
    admission_rejections: AtomicU64,
    /// Cumulative number of admission permits acquired (a query that ran).
    admission_admitted: AtomicU64,
    /// Current number of in-flight admitted queries (a gauge).
    admission_in_flight: AtomicU64,

    // ---- connections ----
    /// Connections accepted, per interface.
    bolt_uds_conns: AtomicU64,
    bolt_tcp_conns: AtomicU64,
    rest_requests: AtomicU64,
    /// Connections rejected for failed authentication, summed across interfaces.
    auth_failures: AtomicU64,

    // ---- query latency ----
    latency: LatencyHistogram,
    /// Queries whose latency exceeded the slow-query threshold (also written to the slow-query log).
    slow_queries: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    /// A fresh registry with all counters at zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            commits: AtomicU64::new(0),
            aborts: AtomicU64::new(0),
            active_txns: AtomicU64::new(0),
            admission_rejections: AtomicU64::new(0),
            admission_admitted: AtomicU64::new(0),
            admission_in_flight: AtomicU64::new(0),
            bolt_uds_conns: AtomicU64::new(0),
            bolt_tcp_conns: AtomicU64::new(0),
            rest_requests: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
            latency: LatencyHistogram::new(),
            slow_queries: AtomicU64::new(0),
        }
    }

    /// Records a committed transaction.
    pub fn record_commit(&self) {
        self.commits.fetch_add(1, Ordering::Relaxed);
    }

    /// Records an aborted/rolled-back transaction.
    pub fn record_abort(&self) {
        self.aborts.fetch_add(1, Ordering::Relaxed);
    }

    /// Sets the current open-transaction gauge (the engine publishes its coordinator's count).
    pub fn set_active_txns(&self, n: u64) {
        self.active_txns.store(n, Ordering::Relaxed);
    }

    /// Records an admission fast-reject ("server busy").
    pub fn record_admission_rejection(&self) {
        self.admission_rejections.fetch_add(1, Ordering::Relaxed);
    }

    /// Records that a query acquired an admission permit and began executing.
    pub fn record_admission_acquired(&self) {
        self.admission_admitted.fetch_add(1, Ordering::Relaxed);
        self.admission_in_flight.fetch_add(1, Ordering::Relaxed);
    }

    /// Records that an admitted query finished (releasing its permit).
    pub fn record_admission_released(&self) {
        // Saturating: never wrap below zero even under a logic error.
        let prev = self.admission_in_flight.load(Ordering::Relaxed);
        if prev > 0 {
            self.admission_in_flight.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Records an accepted Bolt-over-UDS connection.
    pub fn record_bolt_uds_conn(&self) {
        self.bolt_uds_conns.fetch_add(1, Ordering::Relaxed);
    }

    /// Records an accepted Bolt-over-TCP connection.
    pub fn record_bolt_tcp_conn(&self) {
        self.bolt_tcp_conns.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a served REST request.
    pub fn record_rest_request(&self) {
        self.rest_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a failed authentication on any interface.
    pub fn record_auth_failure(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Observes a query's execution latency into the histogram.
    pub fn observe_query_latency(&self, d: Duration) {
        self.latency.observe(d);
    }

    /// Records a slow query (over the configured threshold).
    pub fn record_slow_query(&self) {
        self.slow_queries.fetch_add(1, Ordering::Relaxed);
    }

    /// Renders the full registry in Prometheus text-exposition format (v0.0.4).
    ///
    /// The output is a stable, self-describing snapshot: each metric carries its `# HELP` and
    /// `# TYPE` lines followed by the sample line(s). The histogram emits one `_bucket{le=…}` line
    /// per bound plus the cumulative `+Inf` bucket, and the `_sum`/`_count` aggregates.
    #[must_use]
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(2048);

        counter(
            &mut out,
            "graphus_transactions_committed_total",
            "Transactions committed successfully.",
            self.commits.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "graphus_transactions_aborted_total",
            "Transactions aborted or rolled back.",
            self.aborts.load(Ordering::Relaxed),
        );
        gauge(
            &mut out,
            "graphus_active_transactions",
            "Currently-open transactions.",
            self.active_txns.load(Ordering::Relaxed),
        );

        counter(
            &mut out,
            "graphus_admission_rejections_total",
            "Queries fast-rejected by admission control (server busy).",
            self.admission_rejections.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "graphus_admission_admitted_total",
            "Queries admitted for execution.",
            self.admission_admitted.load(Ordering::Relaxed),
        );
        gauge(
            &mut out,
            "graphus_admission_in_flight",
            "Queries currently holding an admission permit.",
            self.admission_in_flight.load(Ordering::Relaxed),
        );

        counter(
            &mut out,
            "graphus_connections_bolt_uds_total",
            "Accepted Bolt-over-UDS connections.",
            self.bolt_uds_conns.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "graphus_connections_bolt_tcp_total",
            "Accepted Bolt-over-TCP connections.",
            self.bolt_tcp_conns.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "graphus_rest_requests_total",
            "Served REST requests.",
            self.rest_requests.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "graphus_auth_failures_total",
            "Authentication failures across all interfaces.",
            self.auth_failures.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "graphus_slow_queries_total",
            "Queries exceeding the slow-query threshold.",
            self.slow_queries.load(Ordering::Relaxed),
        );

        // The latency histogram.
        out.push_str("# HELP graphus_query_duration_seconds Query execution latency in seconds.\n");
        out.push_str("# TYPE graphus_query_duration_seconds histogram\n");
        for (i, &bound) in LATENCY_BUCKETS_SECS.iter().enumerate() {
            let v = self.latency.buckets[i].load(Ordering::Relaxed);
            out.push_str(&format!(
                "graphus_query_duration_seconds_bucket{{le=\"{bound}\"}} {v}\n"
            ));
        }
        let count = self.latency.count.load(Ordering::Relaxed);
        out.push_str(&format!(
            "graphus_query_duration_seconds_bucket{{le=\"+Inf\"}} {count}\n"
        ));
        let sum_secs = self.latency.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        out.push_str(&format!("graphus_query_duration_seconds_sum {sum_secs}\n"));
        out.push_str(&format!("graphus_query_duration_seconds_count {count}\n"));

        out
    }
}

/// Appends a Prometheus counter (`# HELP`/`# TYPE counter` + value).
fn counter(out: &mut String, name: &str, help: &str, value: u64) {
    out.push_str(&format!(
        "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
    ));
}

/// Appends a Prometheus gauge (`# HELP`/`# TYPE gauge` + value).
fn gauge(out: &mut String, name: &str, help: &str, value: u64) {
    out.push_str(&format!(
        "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}\n"
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_render_their_values() {
        let m = Metrics::new();
        m.record_commit();
        m.record_commit();
        m.record_abort();
        m.set_active_txns(3);
        let text = m.render_prometheus();
        assert!(text.contains("graphus_transactions_committed_total 2"));
        assert!(text.contains("graphus_transactions_aborted_total 1"));
        assert!(text.contains("graphus_active_transactions 3"));
        // Self-describing: HELP + TYPE present.
        assert!(text.contains("# TYPE graphus_transactions_committed_total counter"));
        assert!(text.contains("# TYPE graphus_active_transactions gauge"));
    }

    #[test]
    fn admission_in_flight_is_a_balanced_gauge() {
        let m = Metrics::new();
        m.record_admission_acquired();
        m.record_admission_acquired();
        m.record_admission_released();
        let text = m.render_prometheus();
        assert!(text.contains("graphus_admission_in_flight 1"));
        assert!(text.contains("graphus_admission_admitted_total 2"));
    }

    #[test]
    fn in_flight_never_underflows() {
        let m = Metrics::new();
        // Releasing without acquiring must not wrap to u64::MAX.
        m.record_admission_released();
        let text = m.render_prometheus();
        assert!(text.contains("graphus_admission_in_flight 0"));
    }

    #[test]
    fn histogram_is_cumulative_and_consistent() {
        let m = Metrics::new();
        m.observe_query_latency(Duration::from_micros(800)); // <= 0.001 and up
        m.observe_query_latency(Duration::from_millis(3)); // <= 0.005 and up
        m.observe_query_latency(Duration::from_secs(10)); // only +Inf
        let text = m.render_prometheus();
        // 800us is in the 0.001 bucket (and every larger one) but not in 0.0005.
        assert!(text.contains("graphus_query_duration_seconds_bucket{le=\"0.0005\"} 0"));
        assert!(text.contains("graphus_query_duration_seconds_bucket{le=\"0.001\"} 1"));
        // 0.005 bucket has the 800us + 3ms samples = 2.
        assert!(text.contains("graphus_query_duration_seconds_bucket{le=\"0.005\"} 2"));
        // +Inf == count == 3.
        assert!(text.contains("graphus_query_duration_seconds_bucket{le=\"+Inf\"} 3"));
        assert!(text.contains("graphus_query_duration_seconds_count 3"));
    }

    #[test]
    fn histogram_buckets_are_monotonic_nondecreasing() {
        let m = Metrics::new();
        for us in [100u64, 700, 1500, 4000, 9000, 40_000, 200_000, 800_000] {
            m.observe_query_latency(Duration::from_micros(us));
        }
        let mut last = 0u64;
        for b in &m.latency.buckets {
            let v = b.load(Ordering::Relaxed);
            assert!(v >= last, "cumulative buckets must be non-decreasing");
            last = v;
        }
        assert_eq!(m.latency.count.load(Ordering::Relaxed), 8);
    }
}
