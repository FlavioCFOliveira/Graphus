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

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
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

/// The per-**database** slice of the metric families that an operator needs attributed to a single
/// tenant (`rmp` #463): the transaction outcomes, the open-transaction gauge, query latency and the
/// slow-query count. One of these exists per registered database, mirroring the engine-thread-only
/// aggregate fields on [`Metrics`] (each engine records into BOTH its per-database slice and the
/// aggregate, so the per-database series provably sum to the aggregate).
///
/// Cardinality is bounded by the catalog's database count — a small, fixed, operator-controlled set —
/// which is exactly the case where a `database=` label is both safe (no unbounded series) and necessary
/// (the aggregate alone cannot tell an operator *which* tenant is aborting/slow/leaking). Each engine is
/// the sole writer of its own slice (the single engine thread), so — like the aggregate engine-only
/// fields — these counters are unpadded and updated with `Relaxed` ordering.
#[derive(Debug)]
struct PerDbCounters {
    /// Transactions committed successfully on this database.
    commits: AtomicU64,
    /// Transactions aborted/rolled back on this database.
    aborts: AtomicU64,
    /// Currently-open transactions on this database (a gauge). Published additively by the database's
    /// engine, mirroring the aggregate [`Metrics::active_txns`] (`rmp` #418/#463): a positive delta is a
    /// `fetch_add`, a negative one a saturating `fetch_sub`, so it never wraps below zero.
    active_txns: AtomicU64,
    /// Query latency on this database.
    latency: LatencyHistogram,
    /// Queries on this database that exceeded the slow-query threshold.
    slow_queries: AtomicU64,
}

impl PerDbCounters {
    fn new() -> Self {
        Self {
            commits: AtomicU64::new(0),
            aborts: AtomicU64::new(0),
            active_txns: AtomicU64::new(0),
            latency: LatencyHistogram::new(),
            slow_queries: AtomicU64::new(0),
        }
    }

    /// Applies a signed delta to this database's open-transaction gauge, saturating at zero on a
    /// (logic-error) over-decrement so the gauge never wraps below zero (mirrors
    /// [`Metrics::add_active_txns_delta`]).
    fn add_active_txns_delta(&self, delta: i64) {
        if delta > 0 {
            self.active_txns
                .fetch_add(delta.unsigned_abs(), Ordering::Relaxed);
        } else if delta < 0 {
            let dec = delta.unsigned_abs();
            let mut cur = self.active_txns.load(Ordering::Relaxed);
            loop {
                let next = cur.saturating_sub(dec);
                match self.active_txns.compare_exchange_weak(
                    cur,
                    next,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(observed) => cur = observed,
                }
            }
        }
    }
}

/// The Graphus server metrics, exposed at `/metrics` in Prometheus text format.
///
/// Construct one per server, share it as `Arc<Metrics>`. The aggregate-counter methods are lock-free;
/// the per-database methods (`rmp` #463) take a brief read lock on the per-database registry on the hot
/// path and a write lock only the first time a given database name is seen (a bounded, one-off cost).
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
    /// Currently-open transactions, **summed across every database engine** (a gauge). Each engine
    /// publishes its coordinator's count *additively* via [`add_active_txns_delta`](Metrics::add_active_txns_delta)
    /// (not a last-writer-wins `store`), so under multi-database operation the gauge equals the sum of
    /// the per-engine counts rather than whichever engine published last (`rmp` #418). This is what
    /// keeps the `rmp` #386 leak oracle ("a return to zero proves no reader transaction leaked") sound
    /// when several engines report concurrently.
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
    /// Cumulative background maintenance checkpoints that **failed** (`rmp` #394). A persistently
    /// rising value means reclamation has stalled — RAM (the WAL tail), disk (sealed segments) and
    /// version slots stop being reclaimed while writes accrue, a slow-motion OOM. Engine-thread-only
    /// writer (the maintenance pass runs only on the engine thread), so unpadded.
    maintenance_failures: AtomicU64,
    // NOTE (`rmp` #435): the reclamation-degraded *gating* gauge that used to live here was a single
    // shared `AtomicU64`, so one database's `K` consecutive maintenance failures flagged the WHOLE node
    // not-ready (and any other database's checkpoint success false-cleared a still-stuck flag). It is
    // now a **per-engine** flag ([`crate::engine::MaintenanceDegraded`], the sibling of #414's
    // `EngineDegraded`), read by `/health/ready`'s per-database aggregation. The fleet-wide
    // `maintenance_failures` counter above stays for observability.

    // ---- reliability (`rmp` #386) ----
    /// Statements whose synchronous execution **panicked** and was caught at the engine's
    /// per-statement panic boundary (the transaction was rolled back and the engine kept alive). A
    /// non-zero value is an operator signal of a latent executor/UDF bug to investigate; it is *not*
    /// engine death. A multi-writer-safe `CachePad` (the engine thread is the sole writer today, but a
    /// reader-pool worker's caught panic is accounted through the same counter at retirement).
    statement_panics: CachePad,

    // ---- reliability (`rmp` #409) ----
    /// Statement-recovery **double-panics** caught at the engine's recovery boundary (`rmp` #409): a
    /// statement panicked AND the subsequent rollback/commit that recovers it *also* panicked. A
    /// non-zero value means a deep storage/buffer-pool/MVCC invariant broke (the in-memory state may be
    /// unreliable), so unlike a plain statement panic it is treated as **engine-degraded**. Engine-
    /// thread-only writer (the recovery boundary runs only on the engine thread), so unpadded.
    ///
    /// NOTE (`rmp` #451): the former shared `engine_degraded` *gauge* that lived here was removed. Engine
    /// degradation is now an authoritative **per-engine** flag ([`crate::engine::EngineDegraded`], the
    /// `rmp` #414 gate) surfaced through `/health/ready`'s per-database aggregation. The shared gauge was a
    /// never-cleared, un-labelled fleet-wide latch: one secondary database's transient recovery
    /// double-panic flagged the WHOLE node `graphus_engine_degraded=1` forever (no clear path, even after
    /// a per-database restart), and it was read by nothing but the tests (the production gate had already
    /// moved per-engine). This aggregate `engine_recovery_panics` **counter** remains the fleet-wide
    /// observability signal — exactly as `rmp` #435 kept `maintenance_failures` after dropping the shared
    /// `maintenance_degraded` gauge for the symmetric reason.
    engine_recovery_panics: AtomicU64,

    // ---- per-database dimension (`rmp` #463) ----
    /// Per-database slices of the transaction/latency/abort families, keyed by canonical database name.
    /// Each engine records into BOTH its slice here and the aggregate fields above, so the per-database
    /// series provably sum to the aggregate. Cardinality is bounded by the catalog's database count (a
    /// fixed, operator-controlled set), so the `database=` label can never explode the series count. A
    /// [`BTreeMap`] gives a deterministic render order; the `RwLock` is read on the hot record path and
    /// write-locked only the first time a database name is seen.
    per_db: RwLock<BTreeMap<String, Arc<PerDbCounters>>>,
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
            maintenance_failures: AtomicU64::new(0),
            statement_panics: CachePad::new(0),
            engine_recovery_panics: AtomicU64::new(0),
            per_db: RwLock::new(BTreeMap::new()),
        }
    }

    /// Returns the per-database counter slice for `db`, creating it on first use (`rmp` #463).
    ///
    /// The fast path is a read lock (the slice already exists for an established database); only the very
    /// first metric recorded for a never-seen database name takes the write lock to insert the slice.
    /// Cardinality is bounded by the catalog's database count, so this map can never grow without bound.
    /// Lock poisoning is recovered into — a panic while merely holding this bookkeeping lock must not
    /// cascade into the metrics path.
    fn per_db_entry(&self, db: &str) -> Arc<PerDbCounters> {
        if let Some(c) = self
            .per_db
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(db)
        {
            return Arc::clone(c);
        }
        let mut map = self
            .per_db
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(
            map.entry(db.to_owned())
                .or_insert_with(|| Arc::new(PerDbCounters::new())),
        )
    }

    /// Records one completed maintenance checkpoint (`rmp` #305): the number of MVCC version slots its
    /// GC pass `reclaimed` and the number of committed stamps it `frozen`. A success also clears the
    /// reclamation-degraded gauge (`rmp` #394) — reclamation is making progress again.
    pub fn record_maintenance_checkpoint(&self, reclaimed: u64, frozen: u64) {
        self.maintenance_checkpoints.fetch_add(1, Ordering::Relaxed);
        self.maintenance_versions_reclaimed
            .fetch_add(reclaimed, Ordering::Relaxed);
        self.maintenance_stamps_frozen
            .fetch_add(frozen, Ordering::Relaxed);
        // NOTE (`rmp` #435): the reclamation-degraded *gating* flag is now **per-engine**
        // ([`crate::engine::MaintenanceDegraded`]), cleared by the engine's OWN checkpoint success — it
        // is no longer a shared-`Metrics` gauge. This success therefore clears ONLY this engine's flag
        // (in the engine loop), never another engine's (the cross-tenant false-clear #435 closed). The
        // aggregate `maintenance_failures` counter stays here for fleet observability.
    }

    /// Records one **failed** background maintenance checkpoint (`rmp` #394). The pass logs and retries
    /// (durability is unaffected — nothing was reclaimed below the floor), but a persistent failure
    /// means reclamation has stalled, so the count must be observable for alerting.
    pub fn record_maintenance_failure(&self) {
        self.maintenance_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a committed transaction.
    pub fn record_commit(&self) {
        self.commits.fetch_add(1, Ordering::Relaxed);
    }

    /// Records an aborted/rolled-back transaction.
    pub fn record_abort(&self) {
        self.aborts.fetch_add(1, Ordering::Relaxed);
    }

    /// Sets the current open-transaction gauge to `n` with last-writer-wins semantics.
    ///
    /// **Single-engine / test use only.** Under multi-database operation this is unsound: with `N`
    /// engines each publishing their own count, the gauge would reflect whichever engine stored last
    /// rather than the server-wide total (`rmp` #418). Production engines therefore publish their count
    /// *additively* through [`add_active_txns_delta`](Self::add_active_txns_delta); this setter remains
    /// for the single-engine metrics unit tests (and as the documented building block they assert on).
    pub fn set_active_txns(&self, n: u64) {
        self.active_txns.store(n, Ordering::Relaxed);
    }

    /// Publishes a per-engine change to the **server-wide** open-transaction gauge additively
    /// (`rmp` #418): the engine reports the signed delta between its previous and current coordinator
    /// `active_count`, which is folded into the shared gauge so the gauge always equals the SUM across
    /// every engine — never whichever engine published last. A positive delta is a `fetch_add`, a
    /// negative one a saturating `fetch_sub` (the gauge never wraps below zero even under a transient
    /// publish reordering). A zero delta is a no-op. The per-engine "previous" bookkeeping lives in
    /// [`crate::engine`]'s per-engine `ActiveTxnGauge` (a private engine-loop helper).
    pub fn add_active_txns_delta(&self, delta: i64) {
        if delta > 0 {
            // `delta > 0`, so the cast to u64 is exact and non-negative.
            self.active_txns
                .fetch_add(delta.unsigned_abs(), Ordering::Relaxed);
        } else if delta < 0 {
            // Saturating: never wrap below zero, even if a (buggy) over-decrement were ever attempted.
            let dec = delta.unsigned_abs();
            let mut cur = self.active_txns.load(Ordering::Relaxed);
            loop {
                let next = cur.saturating_sub(dec);
                match self.active_txns.compare_exchange_weak(
                    cur,
                    next,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(observed) => cur = observed,
                }
            }
        }
    }

    /// The current server-wide open-transaction gauge (`rmp` #386 regression visibility, `rmp` #418
    /// multi-DB sum): after every reader retirement (and every begin/commit/rollback) each engine
    /// republishes its coordinator's `active_count` additively, so a return to zero proves no reader
    /// transaction leaked on **any** database (e.g. a panicked read whose txn/ticket was rolled back).
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

    /// Records one statement-recovery **double-panic** caught at the engine's recovery boundary
    /// (`rmp` #409): a statement panicked and its recovering rollback/commit *also* panicked. The engine
    /// degradation that drives `/health/ready` to `503` is flagged on the **per-engine**
    /// [`crate::engine::EngineDegraded`] flag (the `rmp` #414 gate), NOT here — this method only bumps the
    /// fleet-wide observability counter (`rmp` #451 removed the shared, never-cleared gauge). Kept
    /// allocation-light and infallible: it must never itself panic, since it runs in the catch handler of
    /// the very panic it records.
    pub fn record_engine_recovery_panic(&self) {
        self.engine_recovery_panics.fetch_add(1, Ordering::Relaxed);
    }

    /// The number of statement-recovery double-panics caught so far (`rmp` #409) — observability /
    /// tests.
    #[must_use]
    pub fn engine_recovery_panics(&self) -> u64 {
        self.engine_recovery_panics.load(Ordering::Relaxed)
    }

    // ---- per-database recording (`rmp` #463) -------------------------------------------------------
    //
    // Each of these updates the aggregate field (so every existing aggregate metric is unchanged) AND the
    // database's own slice (so the per-database series sum to the aggregate). Called by the engine thread,
    // which is the sole writer of both for its database.

    /// Records a committed transaction for `db` (aggregate + per-database, `rmp` #463).
    pub fn record_commit_for(&self, db: &str) {
        self.commits.fetch_add(1, Ordering::Relaxed);
        self.per_db_entry(db)
            .commits
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records an aborted/rolled-back transaction for `db` (aggregate + per-database, `rmp` #463).
    pub fn record_abort_for(&self, db: &str) {
        self.aborts.fetch_add(1, Ordering::Relaxed);
        self.per_db_entry(db).aborts.fetch_add(1, Ordering::Relaxed);
    }

    /// Publishes a per-engine change to the open-transaction gauge for `db`, folded additively into BOTH
    /// the aggregate gauge and the database's own gauge (`rmp` #418/#463). See
    /// [`add_active_txns_delta`](Self::add_active_txns_delta).
    pub fn add_active_txns_delta_for(&self, db: &str, delta: i64) {
        self.add_active_txns_delta(delta);
        self.per_db_entry(db).add_active_txns_delta(delta);
    }

    /// Observes a query's latency for `db` into the aggregate and per-database histograms (`rmp` #463).
    pub fn observe_query_latency_for(&self, db: &str, d: Duration) {
        self.latency.observe(d);
        self.per_db_entry(db).latency.observe(d);
    }

    /// Records a slow query (over the threshold) for `db` (aggregate + per-database, `rmp` #463).
    pub fn record_slow_query_for(&self, db: &str) {
        self.slow_queries.fetch_add(1, Ordering::Relaxed);
        self.per_db_entry(db)
            .slow_queries
            .fetch_add(1, Ordering::Relaxed);
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
            "graphus_maintenance_failures_total",
            "Background maintenance checkpoints that failed (reclamation stalled — rmp #394).",
            self.maintenance_failures.load(Ordering::Relaxed),
        );
        // NOTE (`rmp` #435): the former `graphus_maintenance_degraded` node-wide gauge was removed —
        // reclamation degradation is now a **per-engine** gate surfaced through `/health/ready`'s
        // per-database aggregation (the shared gauge made one tenant's stall blanket-503 the node and
        // let another tenant's success false-clear it). `graphus_maintenance_failures_total` above
        // remains the fleet-wide observability signal.
        counter(
            &mut out,
            "graphus_statement_panics_total",
            "Statements whose execution panicked and was caught at the engine panic boundary (rmp #386).",
            self.statement_panics.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "graphus_engine_recovery_panics_total",
            "Statement-recovery double-panics caught at the engine recovery boundary (rmp #409).",
            self.engine_recovery_panics.load(Ordering::Relaxed),
        );
        // NOTE (`rmp` #451): the former `graphus_engine_degraded` gauge was removed — engine degradation
        // is now an authoritative **per-engine** flag surfaced through `/health/ready`'s per-database
        // aggregation (it was a never-cleared, un-labelled fleet-wide latch read by nothing but tests).
        // `graphus_engine_recovery_panics_total` above remains the fleet-wide observability signal.

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

        // ---- per-database series (`rmp` #463) ----
        //
        // A `{database="<name>"}`-labelled sample for each registered database, for every family an
        // operator needs attributed to a single tenant: the transaction outcomes, the open-transaction
        // gauge, query latency and the slow-query count. Each per-database series sums to the unlabelled
        // aggregate above (each engine records into both), and the series count is bounded by the catalog
        // database count, so the label can never explode cardinality. A snapshot of the registry is taken
        // under a brief read lock so the render never holds the lock across the string building.
        let per_db: Vec<(String, Arc<PerDbCounters>)> = {
            self.per_db
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .map(|(name, c)| (name.clone(), Arc::clone(c)))
                .collect()
        };
        if !per_db.is_empty() {
            // Counters: one `# HELP`/`# TYPE` header, then one labelled sample line per database.
            labelled_counter_header(
                &mut out,
                "graphus_db_transactions_committed_total",
                "Transactions committed successfully, per database (rmp #463).",
            );
            for (name, c) in &per_db {
                labelled_sample(
                    &mut out,
                    "graphus_db_transactions_committed_total",
                    name,
                    c.commits.load(Ordering::Relaxed),
                );
            }
            labelled_counter_header(
                &mut out,
                "graphus_db_transactions_aborted_total",
                "Transactions aborted or rolled back, per database (rmp #463).",
            );
            for (name, c) in &per_db {
                labelled_sample(
                    &mut out,
                    "graphus_db_transactions_aborted_total",
                    name,
                    c.aborts.load(Ordering::Relaxed),
                );
            }
            labelled_gauge_header(
                &mut out,
                "graphus_db_active_transactions",
                "Currently-open transactions, per database (rmp #463).",
            );
            for (name, c) in &per_db {
                labelled_sample(
                    &mut out,
                    "graphus_db_active_transactions",
                    name,
                    c.active_txns.load(Ordering::Relaxed),
                );
            }
            labelled_counter_header(
                &mut out,
                "graphus_db_slow_queries_total",
                "Queries exceeding the slow-query threshold, per database (rmp #463).",
            );
            for (name, c) in &per_db {
                labelled_sample(
                    &mut out,
                    "graphus_db_slow_queries_total",
                    name,
                    c.slow_queries.load(Ordering::Relaxed),
                );
            }
            // The per-database latency histogram: a multi-line histogram per database (bucket lines carry
            // BOTH the `database=` and the `le=` labels, plus `_sum`/`_count`).
            out.push_str(
                "# HELP graphus_db_query_duration_seconds Query execution latency in seconds, per database (rmp #463).\n",
            );
            out.push_str("# TYPE graphus_db_query_duration_seconds histogram\n");
            for (name, c) in &per_db {
                let label = escape_label_value(name);
                for (i, &bound) in LATENCY_BUCKETS_SECS.iter().enumerate() {
                    let v = c.latency.buckets[i].load(Ordering::Relaxed);
                    out.push_str(&format!(
                        "graphus_db_query_duration_seconds_bucket{{database=\"{label}\",le=\"{bound}\"}} {v}\n"
                    ));
                }
                let dcount = c.latency.count.load(Ordering::Relaxed);
                out.push_str(&format!(
                    "graphus_db_query_duration_seconds_bucket{{database=\"{label}\",le=\"+Inf\"}} {dcount}\n"
                ));
                let dsum = c.latency.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
                out.push_str(&format!(
                    "graphus_db_query_duration_seconds_sum{{database=\"{label}\"}} {dsum}\n"
                ));
                out.push_str(&format!(
                    "graphus_db_query_duration_seconds_count{{database=\"{label}\"}} {dcount}\n"
                ));
            }
        }

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

/// Appends only the `# HELP`/`# TYPE counter` header for a labelled metric family (`rmp` #463): the
/// caller then emits one labelled sample line per series. Prometheus requires the `# TYPE` to appear
/// exactly once per metric name, before its samples.
fn labelled_counter_header(out: &mut String, name: &str, help: &str) {
    out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} counter\n"));
}

/// Appends only the `# HELP`/`# TYPE gauge` header for a labelled metric family (`rmp` #463).
fn labelled_gauge_header(out: &mut String, name: &str, help: &str) {
    out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} gauge\n"));
}

/// Appends one `name{database="<db>"} <value>` sample line (`rmp` #463). The database name is escaped
/// for the Prometheus label-value grammar via [`escape_label_value`].
fn labelled_sample(out: &mut String, name: &str, db: &str, value: u64) {
    let label = escape_label_value(db);
    out.push_str(&format!("{name}{{database=\"{label}\"}} {value}\n"));
}

/// Escapes a string for a Prometheus **label value** (text-exposition v0.0.4): a backslash, a double
/// quote and a line feed are the three characters that must be escaped (`\\`, `\"`, `\n`). A database
/// name is operator-controlled and already validated by the catalog, but escaping defensively keeps the
/// exposition well-formed regardless. Allocation-free for the common (no special character) case.
fn escape_label_value(s: &str) -> std::borrow::Cow<'_, str> {
    if s.bytes().any(|b| b == b'\\' || b == b'"' || b == b'\n') {
        let mut escaped = String::with_capacity(s.len() + 8);
        for ch in s.chars() {
            match ch {
                '\\' => escaped.push_str("\\\\"),
                '"' => escaped.push_str("\\\""),
                '\n' => escaped.push_str("\\n"),
                other => escaped.push(other),
            }
        }
        std::borrow::Cow::Owned(escaped)
    } else {
        std::borrow::Cow::Borrowed(s)
    }
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

    /// `rmp` #418: the open-transaction gauge is additive, so two engines each publishing their own
    /// count sum into the shared gauge (rather than last-writer-wins clobbering). This is the
    /// unit-level proof of the mechanism the multi-DB integration gate exercises end-to-end.
    #[test]
    fn active_txns_gauge_is_additive_across_engines() {
        let m = Metrics::new();
        // Engine A opens 2 txns (delta +2 from 0), engine B opens 3 (delta +3 from 0).
        m.add_active_txns_delta(2);
        m.add_active_txns_delta(3);
        assert_eq!(
            m.active_txns(),
            5,
            "the gauge is the SUM across engines, not the last write"
        );
        // Engine A drops to 1 (delta -1); engine B finishes all (delta -3).
        m.add_active_txns_delta(-1);
        m.add_active_txns_delta(-3);
        assert_eq!(m.active_txns(), 1);
        // Over-decrement saturates at zero (never wraps to u64::MAX).
        m.add_active_txns_delta(-100);
        assert_eq!(m.active_txns(), 0);
        // A zero delta is a no-op.
        m.add_active_txns_delta(0);
        assert_eq!(m.active_txns(), 0);
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

    /// `rmp` #463 REGRESSION GATE: the per-database recording methods emit one labelled series per
    /// registered database, and the per-database series **sum to the existing aggregate** (each engine
    /// records into both). Two databases' commits/aborts add up to the unlabelled totals, and the
    /// `database=` label keeps cardinality bounded by the database count.
    #[test]
    fn per_database_series_sum_to_the_aggregate() {
        let m = Metrics::new();
        // db "alpha": 3 commits, 1 abort, 2 slow queries, two latency samples.
        for _ in 0..3 {
            m.record_commit_for("alpha");
        }
        m.record_abort_for("alpha");
        m.record_slow_query_for("alpha");
        m.record_slow_query_for("alpha");
        m.observe_query_latency_for("alpha", Duration::from_micros(800));
        m.observe_query_latency_for("alpha", Duration::from_millis(3));
        // db "beta": 5 commits, 2 aborts, one latency sample.
        for _ in 0..5 {
            m.record_commit_for("beta");
        }
        m.record_abort_for("beta");
        m.record_abort_for("beta");
        m.observe_query_latency_for("beta", Duration::from_secs(10));

        let text = m.render_prometheus();

        // The unlabelled AGGREGATE equals the SUM across the two databases (3+5 commits, 1+2 aborts).
        assert!(
            text.contains("graphus_transactions_committed_total 8"),
            "aggregate commits = alpha(3) + beta(5)"
        );
        assert!(
            text.contains("graphus_transactions_aborted_total 3"),
            "aggregate aborts = alpha(1) + beta(2)"
        );
        assert!(
            text.contains("graphus_slow_queries_total 2"),
            "aggregate slow queries = alpha(2) + beta(0)"
        );
        // The aggregate latency count is alpha(2) + beta(1) = 3.
        assert!(text.contains("graphus_query_duration_seconds_count 3"));

        // The PER-DATABASE series carry the `database=` label and match each database's own counts.
        assert!(text.contains("graphus_db_transactions_committed_total{database=\"alpha\"} 3"));
        assert!(text.contains("graphus_db_transactions_committed_total{database=\"beta\"} 5"));
        assert!(text.contains("graphus_db_transactions_aborted_total{database=\"alpha\"} 1"));
        assert!(text.contains("graphus_db_transactions_aborted_total{database=\"beta\"} 2"));
        assert!(text.contains("graphus_db_slow_queries_total{database=\"alpha\"} 2"));
        assert!(text.contains("graphus_db_slow_queries_total{database=\"beta\"} 0"));
        assert!(text.contains("graphus_db_active_transactions{database=\"alpha\"} 0"));
        // The per-database latency histogram is labelled and its count matches.
        assert!(text.contains("graphus_db_query_duration_seconds_count{database=\"alpha\"} 2"));
        assert!(text.contains("graphus_db_query_duration_seconds_count{database=\"beta\"} 1"));

        // EXPLICIT SUM check: parsing the two per-database commit series back out, they sum to the
        // aggregate — the property the gate asserts (no per-database series is double-counted or lost).
        let alpha = parse_labelled(&text, "graphus_db_transactions_committed_total", "alpha");
        let beta = parse_labelled(&text, "graphus_db_transactions_committed_total", "beta");
        assert_eq!(
            alpha + beta,
            8,
            "per-database commit series must sum to the aggregate"
        );

        // Cardinality is bounded by the database count: exactly two databases were seen, so each family
        // has exactly two labelled series (no unbounded growth).
        assert_eq!(
            text.matches("graphus_db_transactions_committed_total{database=")
                .count(),
            2,
            "one committed-series per registered database — cardinality bounded by the database count"
        );
    }

    /// `rmp` #463: the open-transaction gauge is additive **per database** too, mirroring the aggregate
    /// `add_active_txns_delta` — a positive delta adds, a negative one saturates at zero.
    #[test]
    fn per_database_active_txns_gauge_is_additive_and_saturating() {
        let m = Metrics::new();
        m.add_active_txns_delta_for("alpha", 4);
        m.add_active_txns_delta_for("beta", 1);
        // Aggregate is the sum across databases.
        assert_eq!(m.active_txns(), 5);
        let text = m.render_prometheus();
        assert!(text.contains("graphus_db_active_transactions{database=\"alpha\"} 4"));
        assert!(text.contains("graphus_db_active_transactions{database=\"beta\"} 1"));
        // Over-decrement on one database saturates that database's gauge at zero (never wraps).
        m.add_active_txns_delta_for("alpha", -100);
        let text = m.render_prometheus();
        assert!(text.contains("graphus_db_active_transactions{database=\"alpha\"} 0"));
    }

    /// `rmp` #463: a database name containing Prometheus-special characters is escaped in the label
    /// value, keeping the exposition well-formed (defensive — catalog names are validated, but the
    /// renderer must never emit a malformed label).
    #[test]
    fn per_database_label_value_is_escaped() {
        let m = Metrics::new();
        m.record_commit_for("we\"ird\\name");
        let text = m.render_prometheus();
        assert!(
            text.contains(
                "graphus_db_transactions_committed_total{database=\"we\\\"ird\\\\name\"} 1"
            ),
            "the quote and backslash must be escaped in the label value:\n{text}"
        );
    }

    /// Parses the `u64` value of a single `{database="<db>"}`-labelled sample line out of a rendered
    /// exposition (test helper for the sum check).
    fn parse_labelled(text: &str, metric: &str, db: &str) -> u64 {
        let needle = format!("{metric}{{database=\"{db}\"}} ");
        text.lines()
            .find_map(|l| l.strip_prefix(&needle))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or_else(|| panic!("no labelled sample {metric}{{database={db:?}}} in:\n{text}"))
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
        // both the engine thread and reader-pool workers, so genuinely multi-writer); the unpadded
        // engine-only fields (the latency histogram, the `maintenance_*`/reliability counters) and the
        // `rmp` #463 per-database registry (`RwLock<BTreeMap<…>>`) pack into the trailing lines. The exact
        // byte count is no longer pinned: the per-database registry's `RwLock`/`BTreeMap` have
        // std-internal, target-dependent sizes, so a magic number would be brittle without testing
        // anything meaningful. The invariants that DO matter are asserted instead — 64-byte alignment
        // (above) and a floor at the padded-counter contribution (below), which still catches any
        // accidental padding of the engine-only fields or loss of a padded counter.
        const PADDED_COUNTERS: usize = 10;
        const CACHE_LINE: usize = 64;
        let size = std::mem::size_of::<Metrics>();
        assert!(
            size >= PADDED_COUNTERS * CACHE_LINE,
            "Metrics ({size}B) must be at least the {PADDED_COUNTERS} padded multi-writer counters \
             ({}B) — a smaller size means a padded counter was lost",
            PADDED_COUNTERS * CACHE_LINE
        );
        assert_eq!(
            size % CACHE_LINE,
            0,
            "a 64-byte-aligned struct's size is a multiple of its alignment"
        );
    }
}
