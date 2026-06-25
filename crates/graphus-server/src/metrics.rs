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

/// A cache-line-isolated wrapper around an [`AtomicU64`], used for the **multi-writer** counters
/// (the accept loops and the whole Tokio worker pool update these concurrently). Without padding,
/// several of these adjacent counters would share one 64-byte cache line, and a `fetch_add` on any
/// of them by one core invalidates that line on every other core touching the line — *false
/// sharing*: a coherence ping-pong that has nothing to do with the program's logic. `#[repr(align(64))]`
/// places each counter on its own line so concurrent updates to *different* counters never contend.
///
/// 64 bytes is the cache-line size on every architecture Graphus targets (x86-64, Apple Silicon and
/// other aarch64 use 64-byte lines for coherence; the larger 128-byte sectoring on some Apple cores
/// only over-aligns, which is harmless). This is the hand-rolled equivalent of
/// `crossbeam_utils::CachePadded`; we keep it in-crate to avoid pulling a new dependency for one
/// 12-byte struct (`CLAUDE.md`'s minimal-dependency stance, mirrored by this module's hand-rolled
/// Prometheus exposition).
///
/// **Only genuinely multi-writer counters are padded.** Engine-thread-only counters (`commits`,
/// `aborts`, `active_txns`, the latency histogram, `slow_queries`, the `maintenance_*` family) are
/// written by the *single* engine thread, so they cannot false-share *with each other*; they stay
/// unpadded to keep the struct small. Isolating the hot multi-writer counters onto their own lines
/// also protects those unpadded single-writer fields, since a reader hammering an admission counter
/// no longer evicts a line that also holds an engine-only counter.
#[derive(Debug)]
#[repr(align(64))]
struct CachePad(AtomicU64);

impl CachePad {
    const fn new(v: u64) -> Self {
        Self(AtomicU64::new(v))
    }

    #[inline]
    fn fetch_add(&self, v: u64, ord: Ordering) -> u64 {
        self.0.fetch_add(v, ord)
    }

    #[inline]
    fn fetch_sub(&self, v: u64, ord: Ordering) -> u64 {
        self.0.fetch_sub(v, ord)
    }

    #[inline]
    fn load(&self, ord: Ordering) -> u64 {
        self.0.load(ord)
    }
}

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
    // ---- transaction outcomes (`04 §9` / NFR-10) — ENGINE-THREAD-ONLY, unpadded ----
    // These (and the latency histogram, slow_queries and the maintenance_* family below) are written
    // exclusively by the single engine thread that owns the `TxnCoordinator`, so they cannot
    // false-share with each other and need no padding; keeping them unpadded keeps the struct small.
    /// Transactions committed successfully.
    commits: AtomicU64,
    /// Transactions aborted/rolled back (explicit rollback, error, or SSI victim).
    aborts: AtomicU64,
    /// Currently-open transactions (a gauge, mirrors the engine's coordinator).
    active_txns: AtomicU64,

    // ---- admission control (`04 §9.3`) — MULTI-WRITER (Tokio worker pool), cache-padded ----
    /// Queries fast-rejected because the admission semaphore was saturated ("server busy").
    admission_rejections: CachePad,
    /// Cumulative number of admission permits acquired (a query that ran).
    admission_admitted: CachePad,
    /// Current number of in-flight admitted queries (a gauge). Incremented on admit and decremented
    /// from `AdmissionPermit::drop`, both on arbitrary worker threads — the hottest contended field.
    admission_in_flight: CachePad,

    // ---- connections — MULTI-WRITER (accept loops + connection tasks), cache-padded ----
    /// Connections accepted, per interface.
    bolt_uds_conns: CachePad,
    bolt_tcp_conns: CachePad,
    rest_requests: CachePad,
    /// Connections rejected for failed authentication, summed across interfaces.
    auth_failures: CachePad,
    /// Connections **load-shed** at accept time because the connection-admission semaphore was
    /// saturated (`max_connections` reached) — the connection was closed before any protocol bytes
    /// (rmp #118).
    conn_shed: CachePad,
    /// Network connections dropped because their TLS handshake did not complete within
    /// `handshake_timeout_ms` (a slow-loris guard — rmp #118).
    handshake_timeouts: CachePad,

    // ---- query latency ----
    latency: LatencyHistogram,
    /// Queries whose latency exceeded the slow-query threshold (also written to the slow-query log).
    slow_queries: AtomicU64,

    // ---- storage maintenance (`rmp` #305) ----
    /// Maintenance checkpoints run (operator-triggered `CHECKPOINT DATABASE` + the background cadence):
    /// each reclaims RAM (the in-memory WAL tail), disk (sealed WAL segments) and version slots.
    maintenance_checkpoints: AtomicU64,
    /// Cumulative MVCC version slots reclaimed by maintenance GC passes.
    maintenance_versions_reclaimed: AtomicU64,
    /// Cumulative committed MVCC stamps frozen (settled to `Committed(ts)`) by maintenance GC passes.
    maintenance_stamps_frozen: AtomicU64,

    // ---- reliability (`rmp` #386) ----
    /// Statements whose synchronous execution **panicked** and was caught at the engine's
    /// per-statement panic boundary (the transaction was rolled back and the engine kept alive). A
    /// non-zero value is an operator signal of a latent executor/UDF bug to investigate; it is *not*
    /// engine death. A multi-writer-safe `CachePad` (the engine thread is the sole writer today, but a
    /// reader-pool worker's caught panic is accounted through the same counter at retirement).
    statement_panics: CachePad,
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
            admission_rejections: CachePad::new(0),
            admission_admitted: CachePad::new(0),
            admission_in_flight: CachePad::new(0),
            bolt_uds_conns: CachePad::new(0),
            bolt_tcp_conns: CachePad::new(0),
            rest_requests: CachePad::new(0),
            auth_failures: CachePad::new(0),
            conn_shed: CachePad::new(0),
            handshake_timeouts: CachePad::new(0),
            latency: LatencyHistogram::new(),
            slow_queries: AtomicU64::new(0),
            maintenance_checkpoints: AtomicU64::new(0),
            maintenance_versions_reclaimed: AtomicU64::new(0),
            maintenance_stamps_frozen: AtomicU64::new(0),
            statement_panics: CachePad::new(0),
        }
    }

    /// Records one completed maintenance checkpoint (`rmp` #305): the number of MVCC version slots its
    /// GC pass `reclaimed` and the number of committed stamps it `frozen`.
    pub fn record_maintenance_checkpoint(&self, reclaimed: u64, frozen: u64) {
        self.maintenance_checkpoints.fetch_add(1, Ordering::Relaxed);
        self.maintenance_versions_reclaimed
            .fetch_add(reclaimed, Ordering::Relaxed);
        self.maintenance_stamps_frozen
            .fetch_add(frozen, Ordering::Relaxed);
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

    /// The current open-transaction gauge (`rmp` #386 regression visibility): after every reader
    /// retirement the engine republishes its coordinator's `active_count`, so a return to zero proves
    /// no reader transaction leaked (e.g. a panicked read whose txn/ticket was rolled back).
    #[must_use]
    pub fn active_txns(&self) -> u64 {
        self.active_txns.load(Ordering::Relaxed)
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

    /// Records a connection load-shed at accept time (the `max_connections` cap was reached — rmp
    /// #118). The connection was closed before any protocol bytes were read.
    pub fn record_conn_shed(&self) {
        self.conn_shed.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a network connection dropped because its TLS handshake exceeded the handshake timeout
    /// (rmp #118).
    pub fn record_handshake_timeout(&self) {
        self.handshake_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    /// Observes a query's execution latency into the histogram.
    pub fn observe_query_latency(&self, d: Duration) {
        self.latency.observe(d);
    }

    /// Records a slow query (over the configured threshold).
    pub fn record_slow_query(&self) {
        self.slow_queries.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one statement panic caught at the engine's per-statement panic boundary (`rmp` #386):
    /// the transaction was rolled back and the engine kept serving. Used by the regression test to
    /// assert the boundary fired, and exported for operator visibility.
    pub fn record_statement_panic(&self) {
        self.statement_panics.fetch_add(1, Ordering::Relaxed);
    }

    /// The number of statement panics caught so far (`rmp` #386) — observability / tests.
    #[must_use]
    pub fn statement_panics(&self) -> u64 {
        self.statement_panics.load(Ordering::Relaxed)
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
            "graphus_connections_shed_total",
            "Connections load-shed at accept time (max_connections reached).",
            self.conn_shed.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "graphus_handshake_timeouts_total",
            "Network connections dropped because their TLS handshake timed out.",
            self.handshake_timeouts.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "graphus_slow_queries_total",
            "Queries exceeding the slow-query threshold.",
            self.slow_queries.load(Ordering::Relaxed),
        );

        counter(
            &mut out,
            "graphus_maintenance_checkpoints_total",
            "Maintenance checkpoints run (operator CHECKPOINT DATABASE + the background cadence).",
            self.maintenance_checkpoints.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "graphus_maintenance_versions_reclaimed_total",
            "MVCC version slots reclaimed by maintenance GC passes.",
            self.maintenance_versions_reclaimed.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "graphus_maintenance_stamps_frozen_total",
            "Committed MVCC stamps frozen by maintenance GC passes.",
            self.maintenance_stamps_frozen.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "graphus_statement_panics_total",
            "Statements whose execution panicked and was caught at the engine panic boundary (rmp #386).",
            self.statement_panics.load(Ordering::Relaxed),
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
    fn connection_admission_counters_render() {
        let m = Metrics::new();
        m.record_conn_shed();
        m.record_conn_shed();
        m.record_handshake_timeout();
        let text = m.render_prometheus();
        assert!(text.contains("graphus_connections_shed_total 2"));
        assert!(text.contains("graphus_handshake_timeouts_total 1"));
        assert!(text.contains("# TYPE graphus_connections_shed_total counter"));
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

#[cfg(test)]
mod padding_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// `CachePad` occupies a full cache line (so distinct multi-writer counters never share one) and
    /// is 64-byte aligned.
    #[test]
    fn cachepad_is_one_cache_line() {
        assert_eq!(std::mem::align_of::<CachePad>(), 64);
        assert_eq!(std::mem::size_of::<CachePad>(), 64);
    }

    /// The padded multi-writer counters each land on a distinct cache line (no two share an address
    /// range within 64 bytes). This is the property that eliminates false sharing.
    #[test]
    fn multi_writer_counters_are_on_distinct_cache_lines() {
        let m = Metrics::new();
        let line = |p: *const CachePad| (p as usize) / 64;
        let addrs = [
            line(&m.admission_rejections),
            line(&m.admission_admitted),
            line(&m.admission_in_flight),
            line(&m.bolt_uds_conns),
            line(&m.bolt_tcp_conns),
            line(&m.rest_requests),
            line(&m.auth_failures),
            line(&m.conn_shed),
            line(&m.handshake_timeouts),
        ];
        for i in 0..addrs.len() {
            for j in (i + 1)..addrs.len() {
                assert_ne!(
                    addrs[i], addrs[j],
                    "padded counters {i} and {j} share a cache line"
                );
            }
        }
    }

    /// Padding must not change counter SEMANTICS: increments accumulate exactly and the gauge is
    /// balanced under concurrent multi-thread updates (the very workload the padding targets).
    #[test]
    fn padded_counters_are_semantically_unchanged_under_concurrency() {
        const THREADS: u64 = 8;
        const PER_THREAD: u64 = 50_000;
        let m = Arc::new(Metrics::new());
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let m = Arc::clone(&m);
            handles.push(std::thread::spawn(move || {
                for _ in 0..PER_THREAD {
                    m.record_bolt_uds_conn();
                    m.record_admission_acquired();
                    m.record_admission_released();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let text = m.render_prometheus();
        let total = THREADS * PER_THREAD;
        assert!(text.contains(&format!("graphus_connections_bolt_uds_total {total}")));
        assert!(text.contains(&format!("graphus_admission_admitted_total {total}")));
        // Every acquire was released, so the in-flight gauge nets to zero.
        assert!(text.contains("graphus_admission_in_flight 0"));
    }

    /// A connection-storm micro-bench: `THREADS` workers each hammer the multi-writer counters, the
    /// exact contention pattern a connection storm creates. Run with
    /// `cargo test -p graphus-server --release -- --ignored --nocapture metrics_storm` and compare
    /// the reported ops/s before vs after cache-padding (the unpadded baseline false-shares these
    /// counters across one or two lines; the padded build does not). `#[ignore]` so it never runs in
    /// the normal suite.
    #[test]
    #[ignore = "perf micro-benchmark; run explicitly with --ignored --nocapture"]
    fn metrics_storm() {
        use std::time::Instant;
        const THREADS: usize = 8;
        const ITERS: u64 = 5_000_000;

        // Padded (production) layout.
        let padded = Arc::new(Metrics::new());
        let start = Instant::now();
        let mut hs = Vec::new();
        for _ in 0..THREADS {
            let m = Arc::clone(&padded);
            hs.push(std::thread::spawn(move || {
                for _ in 0..ITERS {
                    m.record_admission_acquired();
                    m.record_bolt_uds_conn();
                    m.record_admission_released();
                }
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
        let padded_elapsed = start.elapsed();

        // Unpadded baseline: the same counters packed adjacently in one struct (pre-#380 layout).
        #[derive(Default)]
        struct Packed {
            a: AtomicU64,
            b: AtomicU64,
            c: AtomicU64,
        }
        let packed = Arc::new(Packed::default());
        let start = Instant::now();
        let mut hs = Vec::new();
        for _ in 0..THREADS {
            let m = Arc::clone(&packed);
            hs.push(std::thread::spawn(move || {
                for _ in 0..ITERS {
                    m.a.fetch_add(1, Ordering::Relaxed);
                    m.b.fetch_add(1, Ordering::Relaxed);
                    m.c.fetch_sub(1, Ordering::Relaxed);
                    m.c.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
        let packed_elapsed = start.elapsed();

        let ops = (THREADS as u64 * ITERS * 3) as f64;
        let padded_ops_s = ops / padded_elapsed.as_secs_f64();
        let packed_ops_s = ops / packed_elapsed.as_secs_f64();
        println!("metrics_storm: threads={THREADS} iters={ITERS}");
        println!(
            "  PADDED  (production): {padded_elapsed:?}  -> {:.1} M ops/s",
            padded_ops_s / 1e6
        );
        println!(
            "  PACKED  (baseline)  : {packed_elapsed:?}  -> {:.1} M ops/s",
            packed_ops_s / 1e6
        );
        println!(
            "  speedup (padded/packed): {:.2}x",
            padded_ops_s / packed_ops_s
        );
    }
}

#[cfg(test)]
mod size_probe {
    use super::Metrics;

    /// The padded layout costs extra bytes per *process* (one `Arc<Metrics>`): each multi-writer
    /// counter occupies its own 64-byte line. That is a trivially small, one-off price for eliminating
    /// the false-sharing ping-pong on the hottest counters; this test pins the layout so the trade-off
    /// stays visible and any accidental padding of the engine-only counters (which would bloat the
    /// struct without benefit) is caught.
    #[test]
    fn metrics_struct_layout_is_cache_line_aligned() {
        assert_eq!(
            std::mem::align_of::<Metrics>(),
            64,
            "Metrics inherits 64-byte alignment from its padded multi-writer counters"
        );
        // 10 padded counters * 64B = 640B (the 9 original + `statement_panics`, `rmp` #386 — written by
        // both the engine thread and reader-pool workers, so genuinely multi-writer), plus the unpadded
        // engine-only fields packed into the remaining lines: 832B total on this target.
        assert_eq!(std::mem::size_of::<Metrics>(), 832);
    }
}
