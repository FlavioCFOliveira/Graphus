//! Server configuration (`04-technical-design.md` §9): listen addresses, the store path, TLS
//! material, admission limits, timeouts and the slow-query threshold.
//!
//! [`ServerConfig`] is loaded from an optional TOML file and then **overlaid with environment
//! variables** (`GRAPHUS_*`), so an operator can ship a base file and tune a deployment without
//! editing it. Every field has a sensible default, so an empty config (no file, no env) yields a
//! runnable server bound to loopback.
//!
//! The config is plain data: it performs no I/O beyond reading the file/env, and it is validated by
//! [`ServerConfig::validate`] before the server starts so a misconfiguration fails fast with a clear
//! message rather than at first use.

use std::path::PathBuf;
use std::time::Duration;

use graphus_io::PAGE_SIZE;
use serde::Deserialize;

use crate::audit::AuditConfig;
use crate::hardware::HardwareResources;

/// How a fallible config step failed.
#[derive(Debug)]
pub enum ConfigError {
    /// The config file could not be read.
    Read {
        /// The path that failed.
        path: PathBuf,
        /// The underlying I/O error rendering.
        source: String,
    },
    /// The config file (or an env override) could not be parsed.
    Parse(String),
    /// A field failed validation (e.g. a zero limit, or TLS half-configured).
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(f, "reading config file {}: {source}", path.display())
            }
            Self::Parse(m) => write!(f, "parsing config: {m}"),
            Self::Invalid(m) => write!(f, "invalid config: {m}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// TLS material for a network listener: PEM-encoded certificate chain + private key file paths.
///
/// Both must be present for a listener to terminate TLS; the server reads and validates them
/// through [`graphus_auth::tls_server_config`] at startup (`04 §8.4`).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    /// Path to the PEM certificate chain.
    pub cert_path: Option<PathBuf>,
    /// Path to the PEM private key.
    pub key_path: Option<PathBuf>,
}

impl TlsConfig {
    /// Whether both cert and key are configured (a listener can terminate TLS).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.cert_path.is_some() && self.key_path.is_some()
    }

    /// `Err` if exactly one of cert/key is set (a half-configured TLS is a misconfiguration).
    fn validate(&self, who: &str) -> Result<(), ConfigError> {
        match (&self.cert_path, &self.key_path) {
            (Some(_), Some(_)) | (None, None) => Ok(()),
            _ => Err(ConfigError::Invalid(format!(
                "{who}: TLS requires both cert_path and key_path, or neither"
            ))),
        }
    }
}

/// Encryption-at-rest configuration (rmp #85, parent #69, decision `D-security-scope`).
///
/// When [`key_path`](Self::key_path) is set, the record store is created/opened as an **encrypted**
/// device (AES-256-GCM page encryption at the `BlockDevice` seam — see `graphus-crypto`). When it is
/// **unset**, the store path is byte-identical to today (a plaintext `FileBlockDevice`). The key
/// applies to **all databases** under the data root (per-database keys are out of scope for this
/// sub-task). WAL and backup encryption, and key rotation, are sub-task #86 — only the record-store
/// device is encrypted here.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct EncryptionConfig {
    /// Path to the master-key file (raw 32 bytes, or 64 hex characters). When set, the record store
    /// is encrypted; when unset, the store is plaintext. Overridable via `GRAPHUS_ENCRYPTION_KEY_PATH`.
    pub key_path: Option<PathBuf>,
}

impl EncryptionConfig {
    /// Whether encryption at rest is enabled (a key path is configured).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.key_path.is_some()
    }

    /// `Err` if a key path is set but the file does not exist (a misconfiguration that must fail
    /// fast at startup, not at first store open).
    fn validate(&self) -> Result<(), ConfigError> {
        if let Some(path) = &self.key_path {
            if !path.is_file() {
                return Err(ConfigError::Invalid(format!(
                    "encryption.key_path {} does not exist or is not a file (the master key file \
                     must be present when encryption is enabled)",
                    path.display()
                )));
            }
        }
        Ok(())
    }
}

/// Blocking-thread slack reserved on top of [`AdmissionConfig::max_connections`] when sizing the
/// Tokio runtime's blocking pool (rmp #363).
///
/// Bolt sessions consume one blocking thread *each* for their whole lifetime, but the same pool also
/// serves bursty short-lived blocking work that is **not** capped by `max_connections`: REST
/// per-request `spawn_blocking` (rmp #20), the engine command-channel bridge (`engine/handle.rs`) and
/// catalog persistence (`dbcatalog.rs`). This headroom keeps that work from contending with a fully
/// subscribed connection pool. It is deliberately small: Tokio creates blocking threads lazily and
/// reaps idle ones after ~10 s, so an unused reservation costs nothing.
const RESERVED_HEADROOM: usize = 64;

/// Admission control + load-shedding limits (`04 §9.3`).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct AdmissionConfig {
    /// Maximum number of queries executing (or queued for execution) concurrently. Excess work is
    /// fast-rejected with a retriable "server busy" error. Must be > 0.
    pub max_concurrent_queries: usize,
    /// Bounded capacity of the engine's command channel (the submission queue). Must be > 0.
    pub engine_queue_capacity: usize,
    /// Bounded capacity of a result row stream's channel (egress backpressure). Must be > 0.
    pub result_buffer_capacity: usize,
    /// Maximum number of **concurrently-open connections** across all listeners (UDS + Bolt-TCP +
    /// REST), enforced at *accept time* before any protocol bytes are read. This is the first line of
    /// defence against resource exhaustion under hostile load: it caps file descriptors and per-
    /// connection tasks *ahead* of [`max_concurrent_queries`](Self::max_concurrent_queries), which only
    /// engages once a connection is established and submitting work. A connection accepted beyond this
    /// limit is immediately closed (load-shed) and counted in `graphus_connections_shed_total`. Must
    /// be > 0. (rmp #118)
    ///
    /// **Invariant (rmp #363):** the Tokio runtime's `max_blocking_threads` is *always derived* from
    /// this value via [`blocking_thread_budget`](Self::blocking_thread_budget), never set
    /// independently. Each accepted Bolt session occupies one blocking thread for its whole lifetime
    /// (`spawn_blocking`), so the blocking pool must accommodate `max_connections` of them *plus*
    /// headroom for REST per-request, engine-bridge and catalog-persistence blocking work. Deriving
    /// the budget here makes a silent under-sizing (e.g. Tokio's 512 default starving the 513th
    /// session) impossible: raise `max_connections` and the blocking budget grows with it.
    pub max_connections: usize,
    /// Maximum number of **concurrently-open connections from a single source IP** on the *network*
    /// listeners (Bolt-over-TCP + REST), enforced at *accept time* as an **inner** bound that composes
    /// **with** the global [`max_connections`](Self::max_connections) cap (`rmp` #478, D1/R1). The global
    /// cap protects the process's total file-descriptor/task budget; this caps how much of that budget any
    /// *one* source IP may hold, so a single abusive client — or a distributed connect-then-reconnect
    /// flood concentrated on a few sources — cannot keep the global budget saturated and shed legitimate
    /// clients arriving from *other* IPs. The live per-IP count is decremented when the connection closes
    /// (an RAII guard, so it never leaks on any exit path — success, timeout, error, or panic). A
    /// connection that would exceed an IP's cap is closed at accept time, *before* any TLS/protocol work,
    /// and counted in `graphus_connections_per_ip_rejected_total`.
    ///
    /// **UDS is exempt.** A Unix-domain socket has no peer IP: it is a single, kernel-protected, local
    /// trust domain already gated by `SO_PEERCRED` (`04 §8.4`), so the per-IP cap never applies to it (a
    /// flood there is bounded by the global cap and the peer-cred gate, not by a per-IP count).
    ///
    /// `0` **disables** the per-IP cap (only the global `max_connections` applies) — the correct setting
    /// for a deployment where all clients legitimately share one source IP (behind a NAT, a load balancer,
    /// or a reverse proxy), where a per-IP cap would otherwise shed real clients. Defaults to `256`: a
    /// meaningful fraction of the default `max_connections` (1024) so one IP cannot dominate the budget,
    /// yet far above what any normal single-host client opens. When set larger than `max_connections` it
    /// simply never binds (the global cap is tighter) — a valid "effectively unlimited per IP" setting.
    pub max_connections_per_ip: usize,
    /// Number of **off-thread reader worker threads** (`rmp` task #336): read-only auto-commit
    /// statements run on this pool concurrently with the single writer (the engine thread), so multiple
    /// `MATCH`es scale past one core. `0` (the default) selects an automatic size of
    /// `min(available_parallelism(), 16)`; any value `> 0` pins the pool to exactly that many workers
    /// (e.g. `1` keeps reads effectively serial for A/B comparison; a large value over-subscribes,
    /// useful only when reads are I/O-bound). The reader work queue is bounded at
    /// `reader_threads * 8` (floored at 16) — sized to the pool, independent of
    /// [`engine_queue_capacity`](Self::engine_queue_capacity) (which bounds the *command* channel); a
    /// full reader queue falls back to the inline engine-thread path (still correct, just serial).
    pub reader_threads: usize,
    /// Number of **morsel worker threads** for intra-query parallelism (`rmp` task #339): a single
    /// large analytical aggregation (`MATCH (n:Label) RETURN <exact-agg>(n.p)`) splits its label scan
    /// into contiguous morsels read concurrently on a dedicated pool, so one heavy query scales past one
    /// core (distinct from [`reader_threads`](Self::reader_threads), which parallelizes *separate*
    /// read-only statements). `0` (the default) selects an automatic size of
    /// `min(available_parallelism(), 16)`; `1` keeps every query **fully serial** (the morsel tier
    /// early-returns — the determinism / single-core / Raspberry-Pi path); any value `> 1` pins the
    /// morsel pool to exactly that many workers. The pool is dedicated (never the global `rayon` pool, so
    /// it never contends with GDS or the off-thread reader pool).
    pub morsel_parallelism: usize,
    /// Maximum number of **concurrently-open explicit REST transactions** across all databases
    /// (`rmp` #448, CWE-770). A REST explicit transaction is stateless and URL-named: it outlives its
    /// connection and is otherwise bounded only by the inactivity TTL
    /// ([`TimingConfig::transaction_idle_timeout_ms`](TimingConfig::transaction_idle_timeout_ms)), so
    /// within that window one authenticated principal can `POST /db/{db}/tx` in a loop and accumulate
    /// open transactions without limit — each pinning the MVCC GC watermark and growing RAM/version slots
    /// on a **shared** engine (a slow-motion OOM affecting co-tenants, since the registry spans every
    /// database). This caps the live count: a `BEGIN` past it is `429`-rejected (retriable), exactly as
    /// [`max_connections`](Self::max_connections) bounds connections. Bolt is already bounded (one tx per
    /// connection, capped by `max_connections`); this is the REST-specific equivalent. Must be > 0;
    /// defaults to [`graphus_rest::registry::DEFAULT_MAX_OPEN_TRANSACTIONS`].
    pub max_open_transactions: usize,
    /// Whether to build the **opt-in type-bucketed CSR adjacency accelerator** (`rmp` task #324,
    /// "Win 2"). `false` (the default) builds **no** CSR — zero extra RAM, and a type-selective
    /// `expand` behaves exactly as the Win-1 single-pass chain walk. When `true`, each per-database
    /// engine builds a flat CSR adjacency (`~8 bytes per incident edge endpoint`) from the store on
    /// open and consults it for typed expands, so the engine reads **only** matching-type candidate
    /// relationships instead of walking past every non-matching incidence-chain link. The CSR is a
    /// candidate accelerator only (every candidate is re-read and MVCC-re-checked) and is marked stale
    /// on any relationship mutation (falling back to the chain walk until the next open), so enabling
    /// it never changes query results — only the read cost of typed traversals on a stable graph. Keep
    /// it off unless type-selective expand is a measured bottleneck and the per-edge RAM is acceptable.
    pub csr_adjacency: bool,
    /// Maximum number of **concurrent password verifications** (Argon2id KDFs) in flight across every
    /// authentication interface at once (`rmp` #824, CWE-770). The per-account login throttle (`rmp`
    /// #458/#823) bounds repeated failures for **one** username, but an attacker who sends a fresh,
    /// never-seen username on every request is never throttled, and since the `rmp` #812 constant-work
    /// fix an unknown user pays a **full** Argon2id (~19 MiB, tens of ms) — so a *distinct*-username
    /// flood forces unbounded **concurrent** memory-hard hashing on the shared blocking pool
    /// ([`blocking_thread_budget`](Self::blocking_thread_budget)), a pre-authentication availability
    /// collapse from ~120-byte requests. This global bound sheds a verification past the cap
    /// (`/auth/login` → `503`, Bolt `LOGON` → a transient `FAILURE`) **before** the KDF runs.
    ///
    /// `0` (the default) selects an automatic size of `max(4, 2 × available_parallelism())` — a small
    /// multiple of the detected CPU count that bounds both the CPU saturation and the transient memory
    /// (cap × ~19 MiB) while never starving legitimate logins at low concurrency. Any value `> 0` pins
    /// the cap exactly (`1` serialises verification — useful only for A/B tests). See
    /// [`password_verification_cap`](Self::password_verification_cap).
    pub max_concurrent_password_verifications: usize,
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            max_concurrent_queries: 256,
            engine_queue_capacity: 1024,
            result_buffer_capacity: 256,
            max_connections: 1024,
            // A meaningful fraction of `max_connections` so one IP cannot dominate the global budget,
            // yet well above any normal single-host client's footprint (`rmp` #478). `0` disables it
            // (the NAT/load-balancer/reverse-proxy setting where all clients share one source IP).
            max_connections_per_ip: 256,
            reader_threads: 0,
            morsel_parallelism: 0,
            max_open_transactions: graphus_rest::registry::DEFAULT_MAX_OPEN_TRANSACTIONS,
            csr_adjacency: false,
            max_concurrent_password_verifications: 0,
        }
    }
}

impl AdmissionConfig {
    /// The effective off-thread reader pool size (`rmp` task #336): the configured
    /// [`reader_threads`](Self::reader_threads), or — when that is `0` (auto) — `min(N, 16)` where `N`
    /// is the available hardware parallelism (falling back to 1 if it cannot be queried). Capped at 16
    /// so the pool never over-subscribes a many-core host past the point shared-buffer-pool contention
    /// dominates (the measured Slice-1 knee); pin a larger value explicitly for an I/O-bound read mix.
    #[must_use]
    pub fn reader_threads(&self) -> usize {
        if self.reader_threads > 0 {
            self.reader_threads
        } else {
            std::thread::available_parallelism()
                .map(std::num::NonZeroUsize::get)
                .unwrap_or(1)
                .min(16)
        }
    }

    /// The effective morsel worker-pool size (`rmp` task #339): the configured
    /// [`morsel_parallelism`](Self::morsel_parallelism), or — when that is `0` (auto) — `min(N, 16)`
    /// where `N` is the available hardware parallelism (falling back to 1 if it cannot be queried).
    /// Capped at 16 so the dedicated morsel pool never over-subscribes a many-core host past the point
    /// shared-buffer-pool contention dominates (the measured `rmp` #337 Slice-1 knee). `1` keeps every
    /// query fully serial (the morsel tier early-returns).
    #[must_use]
    pub fn morsel_parallelism(&self) -> usize {
        if self.morsel_parallelism > 0 {
            self.morsel_parallelism
        } else {
            std::thread::available_parallelism()
                .map(std::num::NonZeroUsize::get)
                .unwrap_or(1)
                .min(16)
        }
    }

    /// The effective **global concurrent-password-verification cap** (rmp #824): the configured
    /// [`max_concurrent_password_verifications`](Self::max_concurrent_password_verifications), or — when
    /// that is `0` (auto) — `max(4, 2 × N)` where `N` is the available hardware parallelism (falling
    /// back to 1 if it cannot be queried).
    ///
    /// The `2 ×` multiple lets a brief legitimate login burst overlap (a memory-hard verify is
    /// momentarily memory-bandwidth-bound, not purely CPU-bound) while keeping the concurrent Argon2
    /// work — and hence its transient memory (cap × ~19 MiB) and its share of the shared blocking pool —
    /// a small, bounded multiple of the CPU count rather than header-driven-unbounded. The `4` floor
    /// keeps a 1–2 core host (a Raspberry Pi) from starving a handful of concurrent legitimate logins.
    /// A flood beyond the cap is shed with a retriable busy response *before* the KDF, so it costs the
    /// server almost nothing.
    #[must_use]
    pub fn password_verification_cap(&self) -> usize {
        if self.max_concurrent_password_verifications > 0 {
            self.max_concurrent_password_verifications
        } else {
            let cpus = std::thread::available_parallelism()
                .map(std::num::NonZeroUsize::get)
                .unwrap_or(1);
            (2 * cpus).max(4)
        }
    }

    /// The Tokio runtime's `max_blocking_threads` budget (rmp #363), *derived* from
    /// [`max_connections`](Self::max_connections) so the two can never silently disagree.
    ///
    /// Returns `max_connections + `[`RESERVED_HEADROOM`]: every accepted Bolt session holds one
    /// blocking thread for its lifetime (`spawn_blocking`), so the pool must seat `max_connections`
    /// of them, and the headroom covers the short-lived REST / engine-bridge / catalog-persistence
    /// blocking work that shares the same pool but is not capped by `max_connections`. Without this
    /// derivation the pool would fall back to Tokio's 512 default and the 513th session would queue
    /// forever once `max_connections > 512`.
    ///
    /// The sum is saturating: a pathologically large `max_connections` clamps to `usize::MAX` rather
    /// than wrapping (it is validated `> 0` elsewhere, and Tokio caps the actual thread count by lazy
    /// creation regardless of the configured ceiling).
    #[must_use]
    pub fn blocking_thread_budget(&self) -> usize {
        self.max_connections.saturating_add(RESERVED_HEADROOM)
    }
}

/// Timeouts and the slow-query threshold (`04 §9`, NFR-10).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct TimingConfig {
    /// Queries slower than this are written to the slow-query log. In milliseconds.
    pub slow_query_threshold_ms: u64,
    /// Hard deadline for draining in-flight work on graceful shutdown before stragglers are forcibly
    /// rolled back (`04 §9.4`). In milliseconds.
    pub shutdown_drain_deadline_ms: u64,
    /// Maximum time a newly-accepted network connection may take to complete its **TLS handshake**
    /// before the server drops it (`04 §8.4`; rmp #118). A stalled handshake otherwise pins an accept-
    /// side task and an open socket indefinitely, a classic slow-loris resource-exhaustion vector. In
    /// milliseconds; must be > 0.
    ///
    /// It **also** serves as the Bolt **pre-authentication read deadline** (rmp #469, F-NET-1): after
    /// the transport handshake, the same bound caps how long the still-unauthenticated client may take
    /// over the Bolt handshake / `HELLO` / `LOGON` before it is reaped, so a connected-but-silent client
    /// can never pin a connection slot + blocking thread + socket indefinitely. This pre-auth use
    /// applies on **both** transports — including UDS, which has no TLS handshake but whose
    /// peer-cred-admitted local client could otherwise stall the Bolt handshake. Once a session
    /// authenticates, the (separate) [`idle_timeout_ms`](Self::idle_timeout_ms) governs it instead.
    pub handshake_timeout_ms: u64,
    /// Maximum time an **authenticated** connection may sit **idle** (no inbound bytes) before the
    /// server reaps it, as a read deadline applied to the per-connection session (`04 §9`; rmp #118).
    /// `0` **disables** idle reaping (the default, so existing long-lived idle authenticated sessions —
    /// e.g. a driver's pooled connections — are unaffected, matching Neo4j); any value `> 0` enables
    /// it. Applies to the Bolt sessions (UDS + TCP) via the read bridge; the REST listener's hyper
    /// stack manages its own connection lifetimes.
    ///
    /// This governs the connection **only after it authenticates**: the *pre*-authentication phase is
    /// always bounded by [`handshake_timeout_ms`](Self::handshake_timeout_ms) (rmp #469, F-NET-1)
    /// regardless of this value, so disabling idle reaping never re-opens the unauthenticated
    /// slow-loris hole.
    pub idle_timeout_ms: u64,
    /// Maximum time the REST listener will wait for a client to send the **complete HTTP request
    /// headers** before it drops the connection (SEC-181; rmp #181). The TLS-handshake deadline
    /// ([`handshake_timeout_ms`](Self::handshake_timeout_ms)) only covers the handshake; afterwards a
    /// client could otherwise dribble request headers byte-by-byte indefinitely (a classic slow-loris
    /// HTTP vector that, with `max_connections` slow connections, makes REST unavailable). Wired to
    /// hyper's `http1().header_read_timeout(...)`. In milliseconds; `0` **disables** the guard. Has no
    /// effect on the Bolt listeners (which have their own handshake/idle deadlines).
    pub header_read_timeout_ms: u64,
    /// Maximum time an **open REST explicit transaction** may sit idle (no `run`/`commit` touching it)
    /// before the server's inactivity sweep rolls it back (`04 §8.2`; rmp #389). A client that begins
    /// a transaction and never returns otherwise leaks it permanently — pinning the MVCC GC watermark
    /// and growing RAM and version slots without bound. A periodic background task rolls back every
    /// transaction idle past this timeout. Measured on the **monotonic** clock (rmp #395), so an NTP
    /// step cannot expire a fresh transaction or perpetually reprieve a stale one. In milliseconds;
    /// must be `> 0`. Each `run`/`commit` refreshes the deadline, so only a genuinely abandoned
    /// transaction is reaped.
    pub transaction_idle_timeout_ms: u64,
    /// Maximum wall-clock time a **single Cypher statement** may execute on its database engine thread
    /// before it is cooperatively aborted with a cancellation error (`04 §7.7`; rmp #476). Without this
    /// bound an ordinary statement runs with **no CPU budget**: a patient client can submit a
    /// cartesian-product or deep variable-length-expansion "bomb" that pins the per-database engine
    /// thread (and, via morsel parallelism, several cores) indefinitely, starving every co-tenant on the
    /// same database — a CPU-exhaustion denial of service. The executor already polls a cancellation
    /// token at dense safe points (between rows, inside the variable-length DFS / shortest-path BFS, and
    /// inside each morsel worker); this timeout drives that token from a per-statement deadline.
    ///
    /// Deliberately **generous** so it never false-cancels a legitimate statement: at 2 minutes it is
    /// ~240× the [`slow_query_threshold_ms`](Self::slow_query_threshold_ms) and far beyond any
    /// interactive/OLTP query, while comfortably accommodating a large analytical aggregation or a bulk
    /// `MATCH … SET` over millions of rows. Its purpose is to make the server **bounded by default** (a
    /// runaway query is reclaimed in finite time) rather than to police normal latency. In milliseconds;
    /// `0` **disables** the per-statement timeout (opt-out, unbounded — matching the prior behaviour).
    /// Operators serving a pure-OLTP workload can lower it dramatically; batch-analytics deployments can
    /// raise or disable it. GDS procedures carry their own independent (inner) deadline, so this acts as
    /// an outer bound on the non-GDS portion of a statement.
    pub statement_timeout_ms: u64,
    /// Maximum wall-clock **lifetime** an open transaction may reach (now − begin) before the engine's
    /// background sweep aborts it with a clean, retriable rollback (`rmp` #477). Where
    /// [`transaction_idle_timeout_ms`](Self::transaction_idle_timeout_ms) bounds *inactivity* (refreshed
    /// on every operation) and [`statement_timeout_ms`](Self::statement_timeout_ms) bounds a *single
    /// statement*, this bounds the transaction's *total age* — the one window a client can hold open
    /// indefinitely by periodically touching a read transaction so the inactivity sweep never fires (or
    /// simply by leaving a single long-lived `BEGIN` open). Such a holder pins the MVCC GC low-water
    /// mark forever, so dead versions can never be reclaimed and the store and RAM grow without bound
    /// with other transactions' write rate — the classic "idle-in-transaction blocks vacuum"
    /// denial of service (CWE-400). Reaping the over-age holder frees the watermark so reclamation
    /// resumes. Applies on **both** Bolt and REST (it lives in the per-database engine, not a protocol
    /// layer). Measured on the **monotonic** clock (`rmp` #395), so an NTP step cannot expire a fresh
    /// transaction or perpetually reprieve a stale one.
    ///
    /// Deliberately **generous** so it never aborts a legitimate long-running transaction: at 1 hour it
    /// comfortably accommodates a long analytical session or a multi-statement bulk load (far beyond the
    /// 2-minute single-statement budget and 1-minute idle window), yet finite so an abandoned or
    /// deliberately-held transaction is reclaimed in bounded time. In milliseconds; `0` **disables** the
    /// cap (opt-out, unbounded lifetime — matching the prior behaviour). The auto-commit statements that
    /// back a simple `RUN` are transient single-statement units already bounded by
    /// [`statement_timeout_ms`](Self::statement_timeout_ms); this cap targets explicit
    /// `BEGIN … COMMIT` transactions, which are the only ones a client can hold open across statements.
    pub max_transaction_age_ms: u64,
    /// Maximum wall-clock time an **off-thread reader** may spend blocked on a **full result-egress
    /// channel with no progress** (no row accepted by the consumer) before the read is aborted with a
    /// clean, retriable error (`rmp` #591, sprint-52 finding C-F1). This is an **egress-stall ceiling**
    /// that is deliberately **independent of** [`statement_timeout_ms`](Self::statement_timeout_ms):
    ///
    /// An auto-commit read that runs on the reader pool (`rmp` #336/#543) streams its rows into a bounded
    /// channel. If the consumer stops draining (a TCP zero-window / slow-loris on the result stream), the
    /// reader backs off waiting for room. The per-statement timeout bounds that wait **only when it is
    /// configured** — with `statement_timeout_ms = 0` (a legitimate choice for long-running analytics),
    /// nothing else bounds an off-thread reader blocked on egress, so it would spin/park **forever**,
    /// pinning its MVCC snapshot (the GC watermark — nothing it read is ever reclaimed, so RAM and disk
    /// grow without bound) and holding a finite reader-pool slot (a few such stalls exhaust the pool and
    /// kill read service). A full consumer *disconnect* already unblocks the reader; a *zero-window
    /// stall* never disconnects, which is the gap this ceiling closes.
    ///
    /// The ceiling measures **time since the last row was accepted** (it resets on every successful send),
    /// so it never false-aborts a consumer that keeps draining — even slowly, even for hours: it targets a
    /// genuine *stall*, not a legitimately slow but progressing reader. Its total duration is bounded by
    /// [`statement_timeout_ms`](Self::statement_timeout_ms) (when set) as before.
    ///
    /// Deliberately **generous** so a real client's transient hiccup (a GC pause, a momentary network
    /// stall) never trips it: at 30 s it is far beyond any interactive client's inter-row latency (which
    /// is sub-second), yet finite so a genuinely wedged consumer releases the reader — and its GC pin —
    /// promptly. In milliseconds; `0` **disables** the ceiling (opt-out — an off-thread reader can then be
    /// pinned indefinitely by a stalled consumer when `statement_timeout_ms` is also `0`, exactly the
    /// pre-fix behaviour, so only disable it deliberately). Applies only to the **off-thread reader**
    /// (auto-commit reads); inline statements suspend-and-yield the engine thread instead of blocking, and
    /// the deterministic [`crate::engine::LocalEngine`] uses an unbounded egress, so neither is affected.
    pub egress_stall_timeout_ms: u64,
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            slow_query_threshold_ms: 500,
            shutdown_drain_deadline_ms: 10_000,
            handshake_timeout_ms: 10_000,
            idle_timeout_ms: 0,
            // A secure default: a well-behaved client sends its headers within seconds; 15s tolerates
            // slow networks while bounding a slow-loris drip (SEC-181).
            header_read_timeout_ms: 15_000,
            // 60s: comfortably covers an interactive client's think-time between statements in an open
            // transaction, while ensuring an abandoned one is reclaimed promptly (rmp #389). Each
            // touch refreshes the deadline, so only a genuinely idle transaction is reaped.
            transaction_idle_timeout_ms: 60_000,
            // 2 minutes (rmp #476): bounded-by-default per-statement CPU budget. Generous enough never to
            // false-cancel a legitimate analytical / bulk statement (~240× the slow-query threshold, far
            // beyond any interactive/OLTP query), yet finite so a cartesian / variable-length bomb is
            // reclaimed instead of pinning the engine thread forever. `0` disables it.
            statement_timeout_ms: 120_000,
            // 1 hour (rmp #477): bounded-by-default per-transaction lifetime. Generous enough never to
            // abort a legitimate long analytical session or multi-statement bulk load (far beyond the
            // 2-minute single-statement budget and the 1-minute idle window), yet finite so an
            // idle-in-transaction holder pinning the GC watermark — the classic "idle-in-transaction
            // blocks vacuum" DoS — is reclaimed in bounded time. `0` disables it.
            max_transaction_age_ms: 60 * 60 * 1000,
            // 30s (rmp #591, sprint-52 C-F1): the off-thread reader egress-stall ceiling. Bounds how long
            // a reader-pool read blocks on a full result-egress channel with NO progress (a non-draining /
            // zero-window consumer) before it is aborted and releases its GC-watermark pin + pool slot —
            // independently of `statement_timeout_ms`, so a stalled consumer cannot pin a reader forever
            // even when the per-statement timeout is disabled for long analytics. Resets on every accepted
            // row, so it never false-aborts a slow-but-progressing consumer. `0` disables it.
            egress_stall_timeout_ms: 30_000,
        }
    }
}

impl TimingConfig {
    /// The slow-query threshold as a [`Duration`].
    #[must_use]
    pub fn slow_query_threshold(&self) -> Duration {
        Duration::from_millis(self.slow_query_threshold_ms)
    }

    /// The shutdown drain deadline as a [`Duration`].
    #[must_use]
    pub fn shutdown_drain_deadline(&self) -> Duration {
        Duration::from_millis(self.shutdown_drain_deadline_ms)
    }

    /// The TLS-handshake timeout as a [`Duration`] (rmp #118).
    #[must_use]
    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_millis(self.handshake_timeout_ms)
    }

    /// The idle/read timeout as a [`Duration`], or `None` when idle reaping is disabled
    /// (`idle_timeout_ms == 0`) — rmp #118.
    #[must_use]
    pub fn idle_timeout(&self) -> Option<Duration> {
        if self.idle_timeout_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(self.idle_timeout_ms))
        }
    }

    /// The REST request-header read timeout as a [`Duration`], or `None` when disabled
    /// (`header_read_timeout_ms == 0`) — SEC-181 (rmp #181).
    #[must_use]
    pub fn header_read_timeout(&self) -> Option<Duration> {
        if self.header_read_timeout_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(self.header_read_timeout_ms))
        }
    }

    /// The per-statement execution timeout as a [`Duration`], or `None` when disabled
    /// (`statement_timeout_ms == 0`) — rmp #476. Drives the per-statement cancellation deadline that
    /// bounds a runaway query's CPU on the database engine thread.
    #[must_use]
    pub fn statement_timeout(&self) -> Option<Duration> {
        if self.statement_timeout_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(self.statement_timeout_ms))
        }
    }

    /// The maximum transaction-age (total-lifetime) cap as a [`Duration`], or `None` when disabled
    /// (`max_transaction_age_ms == 0`) — `rmp` #477. Drives the engine's background sweep that aborts a
    /// transaction whose lifetime exceeds the cap, freeing the GC watermark it would otherwise pin
    /// (the idle-in-transaction DoS).
    #[must_use]
    pub fn max_transaction_age(&self) -> Option<Duration> {
        if self.max_transaction_age_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(self.max_transaction_age_ms))
        }
    }

    /// The off-thread reader egress-stall ceiling as a [`Duration`], or `None` when disabled
    /// (`egress_stall_timeout_ms == 0`) — `rmp` #591 (sprint-52 C-F1). Bounds how long a reader-pool read
    /// may block on a full result-egress channel with no progress before it is aborted, releasing its
    /// GC-watermark pin and pool slot independently of the per-statement timeout.
    #[must_use]
    pub fn egress_stall_timeout(&self) -> Option<Duration> {
        if self.egress_stall_timeout_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(self.egress_stall_timeout_ms))
        }
    }

    /// The REST transaction inactivity timeout as a [`Duration`] (rmp #389). An open explicit
    /// transaction idle past this is rolled back by the server's inactivity sweep.
    #[must_use]
    pub fn transaction_idle_timeout(&self) -> Duration {
        Duration::from_millis(self.transaction_idle_timeout_ms)
    }
}

/// Network bulk-import endpoint configuration (`08-network-bulk-import.md` §8; `rmp` #518): the
/// resource limits guarding `POST /admin/db/{db}/bulk-import` — a deliberately oversized-body-
/// tolerant route (exempt from [`graphus_rest::router::MAX_REQUEST_BODY_BYTES`]) that therefore
/// needs its own, purpose-built ceiling instead.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct BulkImportConfig {
    /// Maximum total bytes a single bulk-import session may upload, enforced **as bytes are
    /// consumed** from the request body (never after the fact — `08` §8): a session whose running
    /// total crosses this ceiling is aborted mid-stream without ever materializing the excess in
    /// memory. Must be `> 0`. Default: 8 GiB — a sensible ceiling for one streamed session; raise it
    /// for a deployment that routinely loads larger datasets.
    pub max_bytes_per_session: u64,
    /// The minimum free space (bytes) that must remain on the **target database's** filesystem,
    /// checked before the upload is accepted (the `08` §8 disk-space preflight) and re-checked
    /// periodically as bytes are consumed (the ongoing check). An upload that would leave free space
    /// below this reserve is refused up front, or aborted mid-stream, rather than running the device
    /// out of space. `0` **disables** the check (not recommended in production). Default: 1 GiB.
    pub min_free_disk_bytes: u64,
    /// Maximum bytes a single **`.gcol`** (columnar) upload may reach on this call, a ceiling applied
    /// *in addition to* [`max_bytes_per_session`](Self::max_bytes_per_session) and **only** to the
    /// `.gcol` format (`rmp` #595, Finding E-3). Unlike the row-streamed CSV path (whose peak memory
    /// is one batch regardless of file size), `.gcol`'s CRC-32C-at-the-end framing forces the whole
    /// blob to be buffered before it can be decoded, so this cap bounds that single in-RAM buffer to a
    /// host-safe size. It does **not** cap the CSV path. Must be `> 0`. Default: 1 GiB.
    pub max_gcol_upload_bytes: u64,
    /// Maximum **decoded** working set a single `.gcol` transcode may materialise before the row bytes
    /// are handed to the batch loop (`rmp` #595, Finding E-3). A CRC-valid `.gcol` can be a
    /// decompression bomb — a small compressed column (e.g. one dictionary entry cited by billions of
    /// present rows) decoding to gigabytes — so bounding only the *upload* is insufficient; this caps
    /// the *decoded* size directly. A transcode whose declared rows or materialised column bytes would
    /// exceed this is rejected (`400`) rather than allowed to exhaust memory, keeping peak decode RAM a
    /// function of this budget, not of the (possibly adversarial) *amplification* of the decoded size.
    /// The budget bounds **all** the transcode's amplifying allocations — the per-cell value bytes, the
    /// `nrows`-length row array (row ceiling), the two `ncols`-length column pointer arrays (column
    /// ceiling), and each dictionary's own entry pointer array — so a small compressed blob cannot
    /// decode to an unbounded working set. Legitimate loads larger than this should use the streaming
    /// CSV path or the offline importer, or raise this on a larger-RAM host. Must be `> 0`.
    /// Default: 1 GiB. Worst-case additional peak RAM for a `.gcol` ingest is therefore
    /// `O(max_gcol_upload_bytes) + O(max_gcol_decoded_bytes)` — the buffered blob (and, for a
    /// pathological all-distinct dictionary column, one payload-sized copy of its entry bytes) sit in
    /// the upload-bounded term, while every amplifying structure sits in this decode-bounded term.
    pub max_gcol_decoded_bytes: u64,
    /// Maximum wall-clock duration a bulk-import session may stay open, from the first request byte
    /// to the last (`08` §8's per-session timeout — guards an abandoned or deliberately slow-loris'd
    /// upload). Measured on the real (wall-clock) timer, the same as
    /// [`TimingConfig::handshake_timeout_ms`] and
    /// [`TimingConfig::header_read_timeout_ms`] (network-level connection guards, not domain logic
    /// gated on the injected [`graphus_core::capability::Clock`]). In milliseconds; must be `> 0`.
    /// Default: 2 hours — generous enough for a multi-hundred-GB transfer over a modest link, yet
    /// finite so an abandoned session is reclaimed.
    pub session_timeout_ms: u64,
    /// **Mode B** (`08` §5.3/§7.2, `rmp` #520): rows per Mode B commit/transaction — the SSI-footprint
    /// / retry-blast-radius knob (`08` §7.2.1). A larger in-flight batch holds a larger SIREAD/write-
    /// lock footprint open for longer, raising both the probability of a pivot abort against
    /// concurrent traffic that happens to probe/scan the exact rows/predicates the batch is populating
    /// (the dominant, correct source of Mode B contention — `08` §7.2.1) and the wasted work of a
    /// whole-batch retry when one occurs; too small a batch fails to amortize the fixed per-commit cost
    /// (WAL group commit, SSI/index-maintenance bookkeeping), defeating the point of batching.
    /// **Measured** (`rmp` #520, `crates/graphus-dst/src/mode_b_batch_size_measurement.rs`, a
    /// deterministic `LocalEngine` sweep driving a REAL Mode B batch — `begin`/
    /// `bulk_import_mode_b_chunk`/`commit` — against a fixed-probability concurrent reader that probes
    /// each about-to-be-created row's own unique property value, reproducing a genuine, per-chunk
    /// SSI pivot-abort mechanism traced against the actual `graphus_txn::ssi::SsiTracker`, not a
    /// guessed one — see that module's doc comment for the empirically-derived mechanism, which turned
    /// out to be node-property-equality-driven rather than the originally-assumed relationship-type
    /// predicate): batch size → abort rate — 100 → 0%, 500 → 0%, 2,000 → 5%, 5,000 → 25%, 10,000 → 10%
    /// (20 trials/candidate; the 5,000/10,000 gap reflects genuine run-to-run noise at this trial count,
    /// not a real non-monotonicity — both are well above the 2,000 candidate). `2,000` keeps the
    /// measured abort rate low (~5%, comfortably under the ~20-25% ceiling this default is chosen
    /// against) while still amortizing per-commit overhead ~2,000× over the row-at-a-time floor, and is
    /// a full order of magnitude below Mode A's contention-free `DEFAULT_BATCH_SIZE = 10,000` (`08`
    /// §7.2.1: "Mode B batch size is expected to differ from Mode A's default"). Must be `> 0`.
    pub mode_b_batch_rows: u64,
    /// **Mode B**: rows per engine-thread dispatch within one open batch — the `08` §7.2.6 fairness/
    /// yielding granularity ("the batch driver must yield the engine thread at small sub-batch...
    /// granularity, never submit an entire...batch as one uninterruptible engine command"). Chosen as
    /// a small, low-double-digit row count: each row's `GraphAccess::create_node`/`create_rel` call is
    /// itself sub-millisecond (a handful of B-tree/bitmap writes), so a chunk of a few dozen rows keeps
    /// any single [`EngineCommand`](crate::engine::EngineCommand) dispatch's uninterruptible engine-
    /// thread occupancy in the tens-of-microseconds range — far below the latency an ordinary
    /// concurrent client would notice — while still amortizing the fixed per-dispatch channel
    /// round-trip cost (a `std::sync::mpsc` send + reply) over more than one row. Verified
    /// mechanistically (chunk size genuinely bounds one dispatch) by the
    /// `network_bulk_ingest_mode_b` DST scenario, and against **real wall-clock latency** under
    /// genuine concurrent tokio tasks by
    /// `crates/graphus-server/tests/bulk_import_mode_b_fairness.rs` (DST has no real clock — see that
    /// scenario's module docs for the split). Must be `> 0` and `<= mode_b_batch_rows`.
    pub mode_b_chunk_rows: u64,
    /// **Mode B**: the bounded automatic retry count for a batch that aborts on an SSI pivot (`08`
    /// §7.2.3: "The server automatically retries an aborted batch, bounded by a configurable retry
    /// count... If a batch keeps aborting past the retry bound... the session surfaces a retriable
    /// error to the client rather than looping forever"). `0` is a valid value (no automatic retry —
    /// every abort surfaces immediately, e.g. for a client that prefers to control its own retry
    /// policy). Default: `5` — generous enough to ride out a handful of pivot aborts against transient
    /// concurrent contention (per the measurement above, most batch sizes in the sane range abort well
    /// under 5 times in a row even under sustained contention) without looping indefinitely against a
    /// persistently hot relationship type.
    pub mode_b_max_batch_retries: u32,
    /// **Mode B**: the base backoff (milliseconds) between automatic batch retries, doubling per
    /// attempt up to a fixed ceiling (exponential backoff with a cap — `crate::bulk_import_mode_b`).
    /// Must be `> 0`: a zero base with exponential doubling stays zero forever, defeating backoff's own
    /// purpose (immediately hammering a hot contended predicate on every retry, worsening the exact
    /// abort storm `08` §7.2.1 describes). Default: `20` ms — brief enough not to meaningfully slow a
    /// multi-batch import's overall throughput, long enough to let a transient conflicting transaction
    /// clear before the retry re-contends.
    pub mode_b_retry_backoff_ms: u64,
    /// **Mode B**: server-wide cap on concurrently open Mode B sessions, across all databases (`08`
    /// §8: "a server-wide cap on concurrently open Mode B sessions..., since Mode B has no exclusivity
    /// mechanism to naturally bound concurrency... purely to bound aggregate resource consumption").
    /// Must be `> 0`. Default: `8` — bounds the aggregate in-flight-batch/id-map/SSI-footprint memory a
    /// multi-tenant server exposes to this capability, while comfortably covering the realistic
    /// "several concurrent imports against different label sets/databases" scenario `08` §5.3
    /// describes as supported.
    pub mode_b_max_concurrent_sessions: usize,
    /// **Mode B**: idle-session reap window (milliseconds) — a Mode B session with no chunk/end
    /// activity for longer than this is opportunistically reclaimed on the next registry access (`08`
    /// §8's abandoned/slow-loris session guard, applied to Mode B's own session registry rather than
    /// the streaming-call-level guards [`session_timeout_ms`](Self::session_timeout_ms) already
    /// provides for Mode A / the per-call streaming path). Must be `> 0`. Default: 30 minutes —
    /// generous for a legitimate pause between batches (e.g. an operator-side ETL step between files),
    /// yet finite so an abandoned session's `id_map`/stats memory and its held session slot are
    /// eventually reclaimed.
    pub mode_b_session_idle_timeout_ms: u64,
}

impl Default for BulkImportConfig {
    fn default() -> Self {
        Self {
            max_bytes_per_session: 8 * 1024 * 1024 * 1024,
            min_free_disk_bytes: 1024 * 1024 * 1024,
            max_gcol_upload_bytes: 1024 * 1024 * 1024,
            max_gcol_decoded_bytes: 1024 * 1024 * 1024,
            session_timeout_ms: 2 * 60 * 60 * 1000,
            mode_b_batch_rows: 2_000,
            mode_b_chunk_rows: 25,
            mode_b_max_batch_retries: 5,
            mode_b_retry_backoff_ms: 20,
            mode_b_max_concurrent_sessions: 8,
            mode_b_session_idle_timeout_ms: 30 * 60 * 1000,
        }
    }
}

impl BulkImportConfig {
    /// The per-session upload timeout as a [`Duration`].
    #[must_use]
    pub fn session_timeout(&self) -> Duration {
        Duration::from_millis(self.session_timeout_ms)
    }

    /// The Mode B base retry backoff as a [`Duration`].
    #[must_use]
    pub fn mode_b_retry_backoff(&self) -> Duration {
        Duration::from_millis(self.mode_b_retry_backoff_ms)
    }

    /// The Mode B idle-session reap window as a [`Duration`].
    #[must_use]
    pub fn mode_b_session_idle_timeout(&self) -> Duration {
        Duration::from_millis(self.mode_b_session_idle_timeout_ms)
    }
}

/// One additional (non-admin) bootstrap user: a name and a password.
///
/// Bootstrap users are granted database **read + write** (but **not** admin), so a deployment can
/// ship an application identity that runs queries yet cannot drive the administrative surface
/// (`CREATE DATABASE …`, `/admin/*` — rmp #84). Deny-by-default RBAC means anything beyond
/// read/write must be granted explicitly afterwards.
#[derive(Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct UserBootstrap {
    /// The username (must be non-empty and distinct from the admin user).
    pub name: String,
    /// The user's password (for Bolt `LOGON` / minting REST Bearer tokens). Empty disables
    /// password auth for this user.
    pub password: String,
}

// SEC-183 (CWE-532/209): `password` is a secret; a derived `Debug` would spill it into any
// `tracing::debug!(?cfg)` or panic payload. Redact it (preserving whether one is set) while keeping
// the non-secret `name` visible for diagnostics.
impl std::fmt::Debug for UserBootstrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserBootstrap")
            .field("name", &self.name)
            .field("password", &redacted(&self.password))
            .finish()
    }
}

/// Renders a secret for `Debug`: `"<unset>"` when empty (so an empty/disabled secret is still
/// distinguishable from a set one) and `"<redacted>"` otherwise. Never reveals the value (SEC-183).
fn redacted(secret: &str) -> &'static str {
    if secret.is_empty() {
        "<unset>"
    } else {
        "<redacted>"
    }
}

/// The initial RBAC bootstrap: the admin user every fresh deployment needs so a server is usable
/// out of the box (`04 §8.4`), plus optional non-admin users. In production an operator manages
/// users via the admin API afterwards; this just seeds the initial identities.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct AuthBootstrap {
    /// The initial admin username.
    pub admin_user: String,
    /// The initial admin password (for Bolt `LOGON` and to mint REST Bearer tokens). Empty disables
    /// password auth for the admin (e.g. a UDS-only deployment relying on peer-cred).
    pub admin_password: String,
    /// An OS uid bound to the admin user for UDS `SO_PEERCRED` auth, if set (`04 §8.4`).
    pub admin_uid: Option<u32>,
    /// Additional non-admin bootstrap users, each granted database read + write only (see
    /// [`UserBootstrap`]). Empty by default.
    pub users: Vec<UserBootstrap>,
}

// SEC-183 (CWE-532/209): redact `admin_password`; `users` redact themselves via their own `Debug`.
impl std::fmt::Debug for AuthBootstrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthBootstrap")
            .field("admin_user", &self.admin_user)
            .field("admin_password", &redacted(&self.admin_password))
            .field("admin_uid", &self.admin_uid)
            .field("users", &self.users)
            .finish()
    }
}

impl Default for AuthBootstrap {
    fn default() -> Self {
        Self {
            admin_user: "admin".to_owned(),
            admin_password: String::new(),
            admin_uid: None,
            users: Vec::new(),
        }
    }
}

/// The complete server configuration (`04 §9`).
///
/// `Debug` is implemented manually to **redact every secret** (`jwt_secret`, `metrics_scrape_token`,
/// and — transitively — the bootstrap passwords): a stray `tracing::debug!(?config)` or a panic
/// carrying the config must never spill credentials into the logs or an error message (SEC-183,
/// CWE-532/209).
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// Directory holding the record-store device file and the WAL file. Created if absent.
    ///
    /// With multi-database support (decision `D-multi-db`, rmp #83) this directory is the
    /// **default database's** directory and the data root: additional databases live under
    /// `<store_path>/databases/<name>/` and the durable catalog at `<store_path>/databases.toml`
    /// (see [`crate::dbcatalog`]).
    pub store_path: PathBuf,
    /// The **default database's** name (decision `D-multi-db`, rmp #83). It lives directly in
    /// [`store_path`](Self::store_path) (the backward-compatible single-db layout), always exists,
    /// is always online while the server runs, and can never be dropped. Must satisfy the
    /// database-name rule (`[a-z][a-z0-9_-]{0,62}`, compared case-insensitively, stored
    /// lowercase — see [`crate::dbcatalog::normalize_db_name`]); checked by
    /// [`validate`](Self::validate).
    pub default_database: String,
    /// Buffer-pool capacity in **pages** (`04 §3`), per database (each open database owns a pool of
    /// this size). At [`graphus_io::PAGE_SIZE`] = 8 KiB a page, so e.g. `4096` ⇒ 32 MiB.
    ///
    /// **`0` means auto** (`04 §9.5`, decision `D-hw-autotune`): at startup the server sizes the
    /// pool from detected RAM —
    /// `clamp( ⌊`[`AUTO_BUFFER_POOL_RAM_FRACTION`]`× available_RAM ÷ PAGE_SIZE⌋,`
    /// [`AUTO_BUFFER_POOL_FLOOR_PAGES`]`,`[`AUTO_BUFFER_POOL_CEIL_PAGES`]`)` — via
    /// [`apply_hardware_defaults`](Self::apply_hardware_defaults). Any **explicit** value here (from
    /// the TOML file or `GRAPHUS_BUFFER_POOL_PAGES`) is used verbatim and **overrides** the
    /// auto-size: operator config always wins over hardware detection. An explicit value must be
    /// `>=` [`MIN_BUFFER_POOL_PAGES`] (a smaller pool is rejected by [`validate`](Self::validate)
    /// rather than risking a degenerate pool — `rmp` #302).
    pub buffer_pool_pages: usize,

    /// TCP address for the Bolt-over-TCP listener, or `None` to disable it. TLS required when set.
    pub bolt_tcp_addr: Option<String>,
    /// The Bolt address (`host:port`) advertised to **routing** (`neo4j://`) drivers in the `ROUTE`
    /// reply (rmp #95), or `None` to fall back to [`bolt_tcp_addr`](Self::bolt_tcp_addr). Set this to
    /// the server's externally-reachable address when clients connect through a different name/port
    /// than the bind address (e.g. behind a load balancer or NAT) — the bind address (often
    /// `0.0.0.0:7687`) is not usable as a reconnection target. Graphus is a single instance, so all
    /// three routing roles (read/write/route) advertise this one address.
    pub advertised_bolt_address: Option<String>,
    /// The `server` **agent string** advertised in the Bolt `HELLO` `SUCCESS` (rmp #614), or `None`
    /// to keep the honest default
    /// [`graphus_bolt::server::DEFAULT_SERVER_AGENT`] (`Graphus/<version>`, 100% Bolt-conform).
    ///
    /// **Opt-in Neo4j compatibility.** Some strict/legacy Bolt clients (the 1.x-era Neo4j drivers and
    /// third-party tooling derived from them) verify this string and reject any product that is not
    /// the *case-sensitive* literal `Neo4j`. Set this to interoperate with them. Accepted forms
    /// (resolved by [`resolved_bolt_server_agent`](Self::resolved_bolt_server_agent)):
    /// - the shortcut **`neo4j-compat`** (case-insensitive) → expands to the vetted
    ///   [`graphus_bolt::server::NEO4J_COMPAT_SERVER_AGENT`] (`Neo4j/5.13.0`);
    /// - any other non-empty string → used **verbatim** (full operator control, e.g.
    ///   `Neo4j/5.13.0-graphus-<ver>` to keep the Graphus marker while still parsing as Neo4j);
    /// - empty/blank or unset → the `Graphus/<version>` default.
    ///
    /// Overridable via `GRAPHUS_BOLT_SERVER_AGENT`. Announcing `Neo4j/...` does not change Graphus's
    /// Bolt/PackStream conformance nor unlock capabilities (drivers gate features on the *negotiated
    /// Bolt version*, not this string); see [`NEO4J_COMPAT_SERVER_AGENT`](graphus_bolt::server::NEO4J_COMPAT_SERVER_AGENT)
    /// for why the announced Neo4j version must not exceed the negotiated Bolt window.
    pub bolt_server_agent: Option<String>,
    /// The **highest Bolt 5.x minor** the Bolt listeners advertise and accept (rmp #906), or `None`
    /// (the default) to use the compiled maximum [`graphus_bolt::handshake::MAX_MINOR`] — i.e. the
    /// full `5.0..=5.4` window, which is exactly the behaviour before this option existed.
    ///
    /// Set it to pin an unmodified stock driver to an exact older minor: the server simply never
    /// offers anything above the cap, so a driver that would otherwise choose 5.4 negotiates the
    /// capped version instead. Two real uses: certifying an older protocol version end to end against
    /// the official driver ecosystem, and working around a driver defect that only appears at a newer
    /// minor.
    ///
    /// The cap governs **both** handshake forms — the legacy 4-slot reply and the Manifest-v1
    /// exchange — so the two can never advertise different windows. A value outside
    /// `MIN_MINOR..=MAX_MINOR` is rejected by [`validate`](Self::validate) with a clear message; it
    /// can only ever *narrow* the window, never widen it past what Graphus implements.
    ///
    /// Overridable via `GRAPHUS_BOLT_MAX_PROTOCOL_MINOR`.
    pub bolt_max_protocol_minor: Option<u8>,
    /// TCP address for the REST listener, or `None` to disable it. TLS required when set.
    pub rest_addr: Option<String>,
    /// Filesystem path for the Bolt-over-UDS listener, or `None` to disable it.
    pub uds_path: Option<PathBuf>,

    /// TLS material shared by the network listeners (`04 §8.4`).
    pub tls: TlsConfig,
    /// Admission control + load shedding (`04 §9.3`).
    pub admission: AdmissionConfig,
    /// Timeouts + slow-query threshold (`04 §9`).
    pub timing: TimingConfig,

    /// The HS256 JWT signing secret for REST Bearer auth. **Must** be overridden in production (a
    /// generated default is rejected by [`validate`](Self::validate) when any network listener is on,
    /// to prevent shipping a known secret).
    pub jwt_secret: String,

    /// The initial RBAC bootstrap (the first admin user).
    pub auth: AuthBootstrap,

    /// Encryption at rest (rmp #85). Unset ⇒ plaintext store (byte-identical to today).
    pub encryption: EncryptionConfig,

    /// Security audit logging (rmp #70). **Disabled by default**; when enabled, every
    /// security-relevant event (auth outcomes, authorization denials, admin/schema/security/data
    /// changes) is written to a crash-safe, append-only JSONL log at `<store_path>/audit.log` (or
    /// the configured override). Security-critical deployments enable it — see [`AuditConfig`].
    pub audit: AuditConfig,

    /// Network bulk-import endpoint resource limits (`08-network-bulk-import.md` §8; `rmp` #518):
    /// the byte quota, disk-space reserve and session timeout guarding
    /// `POST /admin/db/{db}/bulk-import`.
    pub bulk_import: BulkImportConfig,

    /// **Escape hatch (default `false`):** allow a network listener (Bolt-TCP / REST) to run
    /// **without TLS**. Off by default so production is TLS-mandatory (`04 §8.4`); intended for
    /// loopback test harnesses and trusted-network/dev setups. The name is deliberately alarming so
    /// it is never set in production by accident.
    pub allow_insecure_network: bool,

    /// Optional **bearer token** that authenticates Prometheus scrapes of `/metrics` (rmp #149).
    ///
    /// `/metrics` is **fail-closed** by default: when this is `None`, a scrape must present a valid
    /// **admin Bearer token** (the same gate as `/admin/*`). When set to `Some(token)`, a scraper may
    /// alternatively present `Authorization: Bearer <token>` (compared in constant time) — the
    /// conventional shared-secret a Prometheus server holds, so it need not be a full admin. The
    /// liveness/readiness probes (`/health/live`, `/health/ready`) stay open regardless.
    ///
    /// Overridable via `GRAPHUS_METRICS_SCRAPE_TOKEN`. An **explicitly empty** value is a
    /// misconfiguration (a blank shared secret authenticates nobody safely) and is rejected by
    /// [`validate`](Self::validate); leave it unset to require an admin Bearer instead.
    pub metrics_scrape_token: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            store_path: PathBuf::from("graphus-data"),
            default_database: crate::dbcatalog::DEFAULT_DATABASE_NAME.to_owned(),
            // `0` = auto: sized from detected RAM at startup by `apply_hardware_defaults`
            // (`04 §9.5`), floored at `AUTO_BUFFER_POOL_FLOOR_PAGES` (= the historical fixed 32 MiB
            // default) so auto is never worse than before, and capped at `AUTO_BUFFER_POOL_CEIL_PAGES`.
            buffer_pool_pages: 0,
            bolt_tcp_addr: None,
            advertised_bolt_address: None,
            bolt_server_agent: None,
            bolt_max_protocol_minor: None,
            rest_addr: Some("127.0.0.1:7474".to_owned()),
            uds_path: Some(PathBuf::from("graphus.sock")),
            tls: TlsConfig::default(),
            admission: AdmissionConfig::default(),
            timing: TimingConfig::default(),
            jwt_secret: DEFAULT_INSECURE_JWT_SECRET.to_owned(),
            auth: AuthBootstrap::default(),
            encryption: EncryptionConfig::default(),
            audit: AuditConfig::default(),
            bulk_import: BulkImportConfig::default(),
            allow_insecure_network: false,
            metrics_scrape_token: None,
        }
    }
}

/// One effective configuration setting for `SHOW SETTINGS` (`rmp` #637): a canonical dotted name
/// and its rendered value (`None` = unset / null). Secrets are pre-redacted by
/// [`ServerConfig::effective_settings`] so a caller can never accidentally spill them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingRow {
    /// The canonical, dotted setting name — the Rust field path, e.g. `admission.reader_threads`.
    pub name: &'static str,
    /// The rendered value, or `None` when the setting is unset (an `Option` field that is `None`).
    pub value: Option<String>,
}

impl ServerConfig {
    /// The server's effective (post-hardware-auto-tune, validated) configuration as a flat, ordered
    /// list of `(name, value)` rows, for the read-only `SHOW SETTINGS` introspection (`rmp` #637).
    ///
    /// Names are the canonical dotted field paths (e.g. `admission.reader_threads`,
    /// `timing.statement_timeout_ms`). The values are the **resolved** ones — the auto-tuned
    /// `buffer_pool_pages` / `admission.reader_threads` / `admission.morsel_parallelism` are reported
    /// as their concrete effective numbers (a `0` sentinel here would mean auto was left unresolved,
    /// which never happens after startup).
    ///
    /// **Secrets are redacted here** (SEC-183, CWE-532/209): `jwt_secret`, `metrics_scrape_token`,
    /// and `auth.admin_password` render as `"<redacted>"` when set (never their value); individual
    /// bootstrap user passwords are never listed (only their count).
    #[must_use]
    pub fn effective_settings(&self) -> Vec<SettingRow> {
        /// A set value.
        fn set(name: &'static str, value: impl Into<String>) -> SettingRow {
            SettingRow {
                name,
                value: Some(value.into()),
            }
        }
        /// An optional-path value (`None` ⇒ unset).
        fn path(name: &'static str, p: &Option<PathBuf>) -> SettingRow {
            SettingRow {
                name,
                value: p.as_ref().map(|p| p.display().to_string()),
            }
        }
        /// An optional-string value (`None` ⇒ unset).
        fn opt(name: &'static str, s: &Option<String>) -> SettingRow {
            SettingRow {
                name,
                value: s.clone(),
            }
        }
        /// A secret: `"<redacted>"` when non-empty, `None` when empty/disabled.
        fn secret(name: &'static str, s: &str) -> SettingRow {
            SettingRow {
                name,
                value: if s.is_empty() {
                    None
                } else {
                    Some("<redacted>".to_owned())
                },
            }
        }

        let a = &self.admission;
        let t = &self.timing;
        let b = &self.bulk_import;
        vec![
            // Top-level / storage.
            set("store_path", self.store_path.display().to_string()),
            set("default_database", self.default_database.clone()),
            set("buffer_pool_pages", self.buffer_pool_pages.to_string()),
            set(
                "allow_insecure_network",
                self.allow_insecure_network.to_string(),
            ),
            // Listeners.
            opt("bolt_tcp_addr", &self.bolt_tcp_addr),
            opt("advertised_bolt_address", &self.advertised_bolt_address),
            opt("bolt_server_agent", &self.bolt_server_agent),
            SettingRow {
                name: "bolt_max_protocol_minor",
                value: self.bolt_max_protocol_minor.map(|m| m.to_string()),
            },
            opt("rest_addr", &self.rest_addr),
            path("uds_path", &self.uds_path),
            // TLS + encryption.
            path("tls.cert_path", &self.tls.cert_path),
            path("tls.key_path", &self.tls.key_path),
            path("encryption.key_path", &self.encryption.key_path),
            // Admission control.
            set(
                "admission.max_concurrent_queries",
                a.max_concurrent_queries.to_string(),
            ),
            set(
                "admission.engine_queue_capacity",
                a.engine_queue_capacity.to_string(),
            ),
            set(
                "admission.result_buffer_capacity",
                a.result_buffer_capacity.to_string(),
            ),
            set("admission.max_connections", a.max_connections.to_string()),
            set(
                "admission.max_connections_per_ip",
                a.max_connections_per_ip.to_string(),
            ),
            set("admission.reader_threads", a.reader_threads.to_string()),
            set(
                "admission.morsel_parallelism",
                a.morsel_parallelism.to_string(),
            ),
            set(
                "admission.max_open_transactions",
                a.max_open_transactions.to_string(),
            ),
            set("admission.csr_adjacency", a.csr_adjacency.to_string()),
            // Timing.
            set(
                "timing.slow_query_threshold_ms",
                t.slow_query_threshold_ms.to_string(),
            ),
            set(
                "timing.shutdown_drain_deadline_ms",
                t.shutdown_drain_deadline_ms.to_string(),
            ),
            set(
                "timing.handshake_timeout_ms",
                t.handshake_timeout_ms.to_string(),
            ),
            set("timing.idle_timeout_ms", t.idle_timeout_ms.to_string()),
            set(
                "timing.header_read_timeout_ms",
                t.header_read_timeout_ms.to_string(),
            ),
            set(
                "timing.transaction_idle_timeout_ms",
                t.transaction_idle_timeout_ms.to_string(),
            ),
            set(
                "timing.statement_timeout_ms",
                t.statement_timeout_ms.to_string(),
            ),
            set(
                "timing.max_transaction_age_ms",
                t.max_transaction_age_ms.to_string(),
            ),
            set(
                "timing.egress_stall_timeout_ms",
                t.egress_stall_timeout_ms.to_string(),
            ),
            // Auth bootstrap (passwords redacted; individual users not listed).
            set("auth.admin_user", self.auth.admin_user.clone()),
            secret("auth.admin_password", &self.auth.admin_password),
            SettingRow {
                name: "auth.admin_uid",
                value: self.auth.admin_uid.map(|u| u.to_string()),
            },
            set("auth.bootstrap_users", self.auth.users.len().to_string()),
            // Audit.
            set("audit.enabled", self.audit.enabled.to_string()),
            path("audit.path", &self.audit.path),
            set(
                "audit.fsync_security_events",
                self.audit.fsync_security_events.to_string(),
            ),
            set(
                "audit.audit_data_changes",
                self.audit.audit_data_changes.to_string(),
            ),
            set(
                "audit.fsync_data_changes",
                self.audit.fsync_data_changes.to_string(),
            ),
            set(
                "audit.rotate_max_bytes",
                self.audit.rotate_max_bytes.to_string(),
            ),
            set("audit.retain_files", self.audit.retain_files.to_string()),
            // Bulk import.
            set(
                "bulk_import.max_bytes_per_session",
                b.max_bytes_per_session.to_string(),
            ),
            set(
                "bulk_import.min_free_disk_bytes",
                b.min_free_disk_bytes.to_string(),
            ),
            set(
                "bulk_import.max_gcol_upload_bytes",
                b.max_gcol_upload_bytes.to_string(),
            ),
            set(
                "bulk_import.max_gcol_decoded_bytes",
                b.max_gcol_decoded_bytes.to_string(),
            ),
            set(
                "bulk_import.session_timeout_ms",
                b.session_timeout_ms.to_string(),
            ),
            set(
                "bulk_import.mode_b_batch_rows",
                b.mode_b_batch_rows.to_string(),
            ),
            set(
                "bulk_import.mode_b_chunk_rows",
                b.mode_b_chunk_rows.to_string(),
            ),
            set(
                "bulk_import.mode_b_max_batch_retries",
                b.mode_b_max_batch_retries.to_string(),
            ),
            set(
                "bulk_import.mode_b_retry_backoff_ms",
                b.mode_b_retry_backoff_ms.to_string(),
            ),
            set(
                "bulk_import.mode_b_max_concurrent_sessions",
                b.mode_b_max_concurrent_sessions.to_string(),
            ),
            set(
                "bulk_import.mode_b_session_idle_timeout_ms",
                b.mode_b_session_idle_timeout_ms.to_string(),
            ),
            // Secrets (redacted).
            secret("jwt_secret", &self.jwt_secret),
            SettingRow {
                name: "metrics_scrape_token",
                value: self
                    .metrics_scrape_token
                    .as_deref()
                    .map(|_| "<redacted>".to_owned()),
            },
        ]
    }
}

// SEC-183 (CWE-532/209): redact `jwt_secret` and `metrics_scrape_token`; `auth` redacts its own
// passwords via [`AuthBootstrap`]'s `Debug`. Every other field is non-secret and rendered verbatim
// so the config stays diagnosable.
impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("store_path", &self.store_path)
            .field("default_database", &self.default_database)
            .field("buffer_pool_pages", &self.buffer_pool_pages)
            .field("bolt_tcp_addr", &self.bolt_tcp_addr)
            .field("advertised_bolt_address", &self.advertised_bolt_address)
            .field("bolt_server_agent", &self.bolt_server_agent)
            .field("bolt_max_protocol_minor", &self.bolt_max_protocol_minor)
            .field("rest_addr", &self.rest_addr)
            .field("uds_path", &self.uds_path)
            .field("tls", &self.tls)
            .field("admission", &self.admission)
            .field("timing", &self.timing)
            .field("jwt_secret", &redacted(&self.jwt_secret))
            .field("auth", &self.auth)
            .field("encryption", &self.encryption)
            .field("audit", &self.audit)
            .field("allow_insecure_network", &self.allow_insecure_network)
            .field(
                "metrics_scrape_token",
                &self.metrics_scrape_token.as_deref().map(|t| redacted(t)),
            )
            .finish()
    }
}

/// The placeholder JWT secret in [`ServerConfig::default`]. Refused for a TLS/Bearer listener by
/// [`ServerConfig::validate`] so a real deployment cannot accidentally ship it.
pub const DEFAULT_INSECURE_JWT_SECRET: &str = "INSECURE-DEFAULT-CHANGE-ME";

/// The smallest **explicit** [`buffer_pool_pages`](ServerConfig::buffer_pool_pages) a config may set
/// (`rmp` #302, #617). A pool below this risks a degenerate eviction path, so an operator value under
/// it is a fail-fast [`validate`](ServerConfig::validate) error rather than a runtime hazard. The
/// **auto** path never goes below [`AUTO_BUFFER_POOL_FLOOR_PAGES`] (which is far above this), so a
/// hardware-sized pool is always comfortably valid; this bound only guards a hand-set value. A single
/// query pins only a handful of pages (a B-tree path plus a little working set), so 64 pages
/// (= 512 KiB at 8 KiB/page) is a safe, generous floor.
pub const MIN_BUFFER_POOL_PAGES: usize = 64;

/// Auto buffer-pool **floor** in pages (`04 §9.5`): 4096 pages = 32 MiB at 8 KiB/page. This equals
/// the historical fixed `buffer_pool_pages` default, so hardware auto-sizing is **never worse than
/// the prior status quo** — even a tiny host or a failed RAM probe gets at least today's pool.
pub const AUTO_BUFFER_POOL_FLOOR_PAGES: usize = 4096;

/// Auto buffer-pool **ceiling** in pages (`04 §9.5`): 262 144 pages = 2 GiB at 8 KiB/page. Bounds
/// worst-case pool RSS on a big-RAM host (the pool is *per-database*, and RAM is shared with the WAL,
/// indexes, result buffers and the OS), so auto-sizing can never run away. An operator who wants a
/// larger pool sets an explicit value, which is used verbatim and is not capped here.
pub const AUTO_BUFFER_POOL_CEIL_PAGES: usize = 262_144;

/// Fraction of **available** RAM the auto path devotes to the (per-database) buffer pool: 1/8
/// (12.5%). Deliberately conservative because the pool is per-database and coexists with the WAL,
/// index trees, result buffers and the OS page cache, so a fraction this size leaves ample headroom
/// even with several databases open, while still dwarfing the historical fixed 32 MiB on any real
/// host. Expressed as a numerator/denominator pair so the arithmetic stays in integer `u64`.
pub const AUTO_BUFFER_POOL_RAM_NUM: u64 = 1;
/// Denominator of [`AUTO_BUFFER_POOL_RAM_NUM`] — see it for the rationale.
pub const AUTO_BUFFER_POOL_RAM_DEN: u64 = 8;

/// Human-readable form of [`AUTO_BUFFER_POOL_RAM_NUM`]/[`AUTO_BUFFER_POOL_RAM_DEN`] for docs.
pub const AUTO_BUFFER_POOL_RAM_FRACTION: &str = "1/8";

/// Upper bound on the auto **CPU** pool sizes (`reader_threads`, `morsel_parallelism`) — `04 §9.5`.
/// Matches the long-standing accessor behaviour: past this many workers, shared buffer-pool
/// contention dominates (the measured `rmp` #337 Slice-1 knee), so auto never over-subscribes a
/// many-core host. Pin a larger value explicitly for an I/O-bound read mix.
pub const AUTO_CPU_POOL_CAP: usize = 16;

/// Computes the auto buffer-pool size (pages) for a detected hardware snapshot: a conservative
/// fraction of available RAM, clamped to `[`[`AUTO_BUFFER_POOL_FLOOR_PAGES`]`,`
/// [`AUTO_BUFFER_POOL_CEIL_PAGES`]`]`. When RAM is unknown (probe failed) it returns the floor, so
/// the server still gets at least the historical default pool. Pure; the clamp keeps the result a
/// valid `usize` on every target (the ceiling fits well within 32-bit `usize`).
#[must_use]
pub fn auto_buffer_pool_pages(hw: &HardwareResources) -> usize {
    let Some(ram_bytes) = hw.sizing_memory_bytes() else {
        return AUTO_BUFFER_POOL_FLOOR_PAGES;
    };
    // budget = ram * NUM / DEN, then pages = budget / PAGE_SIZE — all in u64 to avoid overflow, then
    // clamped in u64 before the cast so the narrowing can never truncate a large intermediate.
    let budget = ram_bytes / AUTO_BUFFER_POOL_RAM_DEN * AUTO_BUFFER_POOL_RAM_NUM;
    let pages = budget / PAGE_SIZE as u64;
    pages.clamp(
        AUTO_BUFFER_POOL_FLOOR_PAGES as u64,
        AUTO_BUFFER_POOL_CEIL_PAGES as u64,
    ) as usize
}

impl ServerConfig {
    /// Loads the config from an optional TOML file and overlays `GRAPHUS_*` environment variables.
    ///
    /// With `path == None` and no env vars set, returns [`ServerConfig::default`]. The result is
    /// **not** validated here — call [`validate`](Self::validate) before starting the server.
    ///
    /// # Errors
    /// [`ConfigError::Read`] if the file exists but cannot be read, or [`ConfigError::Parse`] if the
    /// file or an env override is malformed.
    pub fn load(path: Option<&std::path::Path>) -> Result<Self, ConfigError> {
        let mut cfg = match path {
            Some(p) => {
                let text = std::fs::read_to_string(p).map_err(|e| ConfigError::Read {
                    path: p.to_path_buf(),
                    source: e.to_string(),
                })?;
                toml::from_str(&text).map_err(|e| ConfigError::Parse(e.to_string()))?
            }
            None => Self::default(),
        };
        cfg.apply_env()?;
        cfg.normalize();
        Ok(cfg)
    }

    /// Fills every resource-sizing parameter still at its `0 = auto` sentinel from a detected
    /// [`HardwareResources`] snapshot (`04 §9.5`, decision `D-hw-autotune`).
    ///
    /// **Override precedence.** A field an operator set explicitly — a non-zero value from the TOML
    /// file or a `GRAPHUS_*` env var, already applied by [`load`](Self::load) — is left untouched, so
    /// **operator config always wins over hardware detection**. Only a field left at `0` (auto) is
    /// resolved here.
    ///
    /// Resolves:
    /// - [`buffer_pool_pages`](Self::buffer_pool_pages) → [`auto_buffer_pool_pages`] (a conservative
    ///   fraction of available RAM, clamped to the floor/ceiling).
    /// - [`admission.reader_threads`](AdmissionConfig::reader_threads) and
    ///   [`admission.morsel_parallelism`](AdmissionConfig::morsel_parallelism) →
    ///   `min(logical_cpus, `[`AUTO_CPU_POOL_CAP`]`)`. (These already resolved `0` lazily in their
    ///   accessors; filling the stored field here unifies the source on the one detected CPU count
    ///   and makes the resolved value concrete for the startup log. `morsel_parallelism == 1` — the
    ///   "fully serial" opt-out — is a non-sentinel value and is preserved.)
    ///
    /// This is **pure** given `hw` (all probing I/O happens in [`HardwareResources::detect`] before
    /// this is called), so it is exhaustively unit-testable with synthetic hardware. Idempotent: a
    /// second call is a no-op because every auto field is now concrete.
    ///
    /// Call it **once at startup, after [`load`](Self::load) and before [`validate`](Self::validate)**
    /// (see [`crate::server::Server::start`]); [`validate`] then only ever sees resolved values.
    pub fn apply_hardware_defaults(&mut self, hw: &HardwareResources) {
        if self.buffer_pool_pages == 0 {
            self.buffer_pool_pages = auto_buffer_pool_pages(hw);
        }
        let cpu_pool = hw.logical_cpus.clamp(1, AUTO_CPU_POOL_CAP);
        if self.admission.reader_threads == 0 {
            self.admission.reader_threads = cpu_pool;
        }
        if self.admission.morsel_parallelism == 0 {
            self.admission.morsel_parallelism = cpu_pool;
        }
    }

    /// Normalises listener addresses so an **empty string** disables that listener (`Some("")` →
    /// `None`), uniformly for file- and env-provided values. Lets an operator disable a listener by
    /// blanking it in the file (`rest_addr = ""`) exactly as an empty env var does.
    fn normalize(&mut self) {
        if self
            .bolt_tcp_addr
            .as_deref()
            .is_some_and(|s| s.trim().is_empty())
        {
            self.bolt_tcp_addr = None;
        }
        if self
            .advertised_bolt_address
            .as_deref()
            .is_some_and(|s| s.trim().is_empty())
        {
            self.advertised_bolt_address = None;
        }
        // The advertised Bolt agent: a blank value means "keep the default", exactly like a blanked
        // listener address disables its listener; a set value is trimmed so the stored/announced form
        // is canonical (leading/trailing whitespace in an agent string would defeat the strict Neo4j
        // parser it may be trying to satisfy — see `resolved_bolt_server_agent`).
        if let Some(agent) = self.bolt_server_agent.as_deref() {
            let trimmed = agent.trim();
            self.bolt_server_agent = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            };
        }
        if self
            .rest_addr
            .as_deref()
            .is_some_and(|s| s.trim().is_empty())
        {
            self.rest_addr = None;
        }
        if self
            .uds_path
            .as_deref()
            .is_some_and(|p| p.as_os_str().is_empty())
        {
            self.uds_path = None;
        }
        // Database names are case-insensitive and stored lowercase (`crate::dbcatalog`); normalise
        // the configured default here so the rest of the server only ever sees the canonical form.
        self.default_database = self.default_database.trim().to_ascii_lowercase();
    }

    /// Overlays the recognised `GRAPHUS_*` environment variables onto `self`.
    ///
    /// Only a focused, deployment-relevant subset is overridable by env (the file is the place for
    /// the full surface): the listen addresses, store path, TLS paths, the JWT secret, and the two
    /// most-tuned admission/timing knobs. An unset var leaves the field unchanged.
    fn apply_env(&mut self) -> Result<(), ConfigError> {
        use std::env::var;

        if let Ok(v) = var("GRAPHUS_STORE_PATH") {
            self.store_path = PathBuf::from(v);
        }
        if let Ok(v) = var("GRAPHUS_DEFAULT_DATABASE") {
            self.default_database = v;
        }
        if let Ok(v) = var("GRAPHUS_BOLT_TCP_ADDR") {
            self.bolt_tcp_addr = empty_to_none(v);
        }
        if let Ok(v) = var("GRAPHUS_ADVERTISED_BOLT_ADDRESS") {
            self.advertised_bolt_address = empty_to_none(v);
        }
        if let Ok(v) = var("GRAPHUS_BOLT_SERVER_AGENT") {
            self.bolt_server_agent = empty_to_none(v);
        }
        if let Ok(v) = var("GRAPHUS_BOLT_MAX_PROTOCOL_MINOR") {
            // An EMPTY value means "unset" (use the compiled maximum), mirroring how a blanked
            // listener address disables its listener. A non-empty value must parse as a `u8`; whether
            // it names a minor Graphus implements is `validate`'s call, so the range error carries the
            // same clear, actionable message from the file and the env alike.
            self.bolt_max_protocol_minor = match empty_to_none(v) {
                None => None,
                Some(v) => Some(v.trim().parse().map_err(|_| {
                    ConfigError::Parse(format!(
                        "GRAPHUS_BOLT_MAX_PROTOCOL_MINOR is not a Bolt 5.x minor \
                         ({MIN_BOLT_PROTOCOL_MINOR}..={MAX_BOLT_PROTOCOL_MINOR}): {v:?}"
                    ))
                })?),
            };
        }
        if let Ok(v) = var("GRAPHUS_REST_ADDR") {
            self.rest_addr = empty_to_none(v);
        }
        if let Ok(v) = var("GRAPHUS_UDS_PATH") {
            self.uds_path = empty_to_none(v).map(PathBuf::from);
        }
        if let Ok(v) = var("GRAPHUS_TLS_CERT_PATH") {
            self.tls.cert_path = empty_to_none(v).map(PathBuf::from);
        }
        if let Ok(v) = var("GRAPHUS_TLS_KEY_PATH") {
            self.tls.key_path = empty_to_none(v).map(PathBuf::from);
        }
        if let Ok(v) = var("GRAPHUS_JWT_SECRET") {
            self.jwt_secret = v;
        }
        if let Ok(v) = var("GRAPHUS_ENCRYPTION_KEY_PATH") {
            self.encryption.key_path = empty_to_none(v).map(PathBuf::from);
        }
        if let Ok(v) = var("GRAPHUS_METRICS_SCRAPE_TOKEN") {
            // Unlike a listener address, an empty value here is NOT "disable": it is an explicit blank
            // secret, which `validate` rejects. Carry it verbatim so the validator can catch it.
            self.metrics_scrape_token = Some(v);
        }
        if let Ok(v) = var("GRAPHUS_BUFFER_POOL_PAGES") {
            // `0` = auto (size from detected RAM at startup); any value `> 0` pins the pool and
            // overrides auto-detection (`04 §9.5`). Non-zero values below `MIN_BUFFER_POOL_PAGES`
            // are accepted here and rejected by `validate` with a clear message.
            self.buffer_pool_pages = v.parse().map_err(|_| {
                ConfigError::Parse(format!(
                    "GRAPHUS_BUFFER_POOL_PAGES is not a non-negative integer (0 = auto): {v:?}"
                ))
            })?;
        }
        if let Ok(v) = var("GRAPHUS_MAX_CONCURRENT_QUERIES") {
            self.admission.max_concurrent_queries = v.parse().map_err(|_| {
                ConfigError::Parse(format!(
                    "GRAPHUS_MAX_CONCURRENT_QUERIES is not a positive integer: {v:?}"
                ))
            })?;
        }
        if let Ok(v) = var("GRAPHUS_MAX_CONNECTIONS") {
            self.admission.max_connections = v.parse().map_err(|_| {
                ConfigError::Parse(format!(
                    "GRAPHUS_MAX_CONNECTIONS is not a positive integer: {v:?}"
                ))
            })?;
        }
        if let Ok(v) = var("GRAPHUS_MAX_CONNECTIONS_PER_IP") {
            // `0` is valid here (it disables the per-IP cap), so accept any non-negative integer.
            self.admission.max_connections_per_ip = v.parse().map_err(|_| {
                ConfigError::Parse(format!(
                    "GRAPHUS_MAX_CONNECTIONS_PER_IP is not a non-negative integer (0 = disabled): {v:?}"
                ))
            })?;
        }
        if let Ok(v) = var("GRAPHUS_MAX_OPEN_TRANSACTIONS") {
            self.admission.max_open_transactions = v.parse().map_err(|_| {
                ConfigError::Parse(format!(
                    "GRAPHUS_MAX_OPEN_TRANSACTIONS is not a positive integer: {v:?}"
                ))
            })?;
        }
        if let Ok(v) = var("GRAPHUS_READER_THREADS") {
            self.admission.reader_threads = v.parse().map_err(|_| {
                ConfigError::Parse(format!(
                    "GRAPHUS_READER_THREADS is not a non-negative integer (0 = auto): {v:?}"
                ))
            })?;
        }
        if let Ok(v) = var("GRAPHUS_MORSEL_PARALLELISM") {
            self.admission.morsel_parallelism = v.parse().map_err(|_| {
                ConfigError::Parse(format!(
                    "GRAPHUS_MORSEL_PARALLELISM is not a non-negative integer (0 = auto): {v:?}"
                ))
            })?;
        }
        if let Ok(v) = var("GRAPHUS_CSR_ADJACENCY") {
            // Accept the common truthy / falsy spellings; the knob is opt-in so anything unrecognised
            // is a hard error rather than a silent default (a misspelled "ture" must not leave the
            // accelerator off without warning).
            self.admission.csr_adjacency = match v.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => true,
                "0" | "false" | "no" | "off" => false,
                _ => {
                    return Err(ConfigError::Parse(format!(
                        "GRAPHUS_CSR_ADJACENCY is not a boolean (true/false/1/0/yes/no/on/off): {v:?}"
                    )));
                }
            };
        }
        if let Ok(v) = var("GRAPHUS_SLOW_QUERY_THRESHOLD_MS") {
            self.timing.slow_query_threshold_ms = v.parse().map_err(|_| {
                ConfigError::Parse(format!(
                    "GRAPHUS_SLOW_QUERY_THRESHOLD_MS is not an integer: {v:?}"
                ))
            })?;
        }
        if let Ok(v) = var("GRAPHUS_HANDSHAKE_TIMEOUT_MS") {
            self.timing.handshake_timeout_ms = v.parse().map_err(|_| {
                ConfigError::Parse(format!(
                    "GRAPHUS_HANDSHAKE_TIMEOUT_MS is not an integer: {v:?}"
                ))
            })?;
        }
        if let Ok(v) = var("GRAPHUS_IDLE_TIMEOUT_MS") {
            self.timing.idle_timeout_ms = v.parse().map_err(|_| {
                ConfigError::Parse(format!("GRAPHUS_IDLE_TIMEOUT_MS is not an integer: {v:?}"))
            })?;
        }
        if let Ok(v) = var("GRAPHUS_HEADER_READ_TIMEOUT_MS") {
            self.timing.header_read_timeout_ms = v.parse().map_err(|_| {
                ConfigError::Parse(format!(
                    "GRAPHUS_HEADER_READ_TIMEOUT_MS is not an integer: {v:?}"
                ))
            })?;
        }
        if let Ok(v) = var("GRAPHUS_STATEMENT_TIMEOUT_MS") {
            self.timing.statement_timeout_ms = v.parse().map_err(|_| {
                ConfigError::Parse(format!(
                    "GRAPHUS_STATEMENT_TIMEOUT_MS is not an integer: {v:?}"
                ))
            })?;
        }
        if let Ok(v) = var("GRAPHUS_MAX_TRANSACTION_AGE_MS") {
            self.timing.max_transaction_age_ms = v.parse().map_err(|_| {
                ConfigError::Parse(format!(
                    "GRAPHUS_MAX_TRANSACTION_AGE_MS is not an integer: {v:?}"
                ))
            })?;
        }
        if let Ok(v) = var("GRAPHUS_EGRESS_STALL_TIMEOUT_MS") {
            self.timing.egress_stall_timeout_ms = v.parse().map_err(|_| {
                ConfigError::Parse(format!(
                    "GRAPHUS_EGRESS_STALL_TIMEOUT_MS is not an integer: {v:?}"
                ))
            })?;
        }
        Ok(())
    }

    /// Validates the config, returning a clear message on the first problem.
    ///
    /// Enforces: at least one listener enabled; admission limits non-zero; buffer pool non-zero;
    /// TLS fully-or-not configured; TLS present whenever a network listener is enabled (UDS is
    /// kernel-protected and needs none); and that the insecure default JWT secret is not used when a
    /// network listener that relies on it (REST Bearer) is enabled.
    ///
    /// # Errors
    /// [`ConfigError::Invalid`] describing the first failed invariant.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.bolt_tcp_addr.is_none() && self.rest_addr.is_none() && self.uds_path.is_none() {
            return Err(ConfigError::Invalid(
                "no listeners enabled: set at least one of bolt_tcp_addr, rest_addr, uds_path"
                    .to_owned(),
            ));
        }
        // `0` = auto: resolved from detected RAM at startup by `apply_hardware_defaults`, *before*
        // the store is opened (`04 §9.5`), so it is valid here — production never reaches store-open
        // with an unresolved `0`. Any *explicit* value must be at least `MIN_BUFFER_POOL_PAGES` so a
        // hand-set tiny pool fails fast with a clear message instead of degenerating at runtime
        // (`rmp` #302).
        if self.buffer_pool_pages != 0 && self.buffer_pool_pages < MIN_BUFFER_POOL_PAGES {
            return Err(ConfigError::Invalid(format!(
                "buffer_pool_pages must be >= {MIN_BUFFER_POOL_PAGES} (or 0 = auto-size from detected \
                 RAM at startup)"
            )));
        }
        if let Err(e) = crate::dbcatalog::normalize_db_name(&self.default_database) {
            return Err(ConfigError::Invalid(format!("default_database: {e}")));
        }
        // The Bolt version cap (rmp #906) may only NARROW the window Graphus implements. Rejecting an
        // out-of-range value here — rather than silently clamping it — means an operator who asks for
        // a minor Graphus does not speak learns at startup instead of discovering the wrong version
        // negotiated at runtime.
        if let Some(minor) = self.bolt_max_protocol_minor
            && !(MIN_BOLT_PROTOCOL_MINOR..=MAX_BOLT_PROTOCOL_MINOR).contains(&minor)
        {
            return Err(ConfigError::Invalid(format!(
                "bolt_max_protocol_minor must be between {MIN_BOLT_PROTOCOL_MINOR} and \
                 {MAX_BOLT_PROTOCOL_MINOR} (the Bolt 5.x minors Graphus implements), got {minor}; \
                 leave it unset to advertise the full 5.{MIN_BOLT_PROTOCOL_MINOR}–5.\
                 {MAX_BOLT_PROTOCOL_MINOR} window"
            )));
        }
        if self.admission.max_concurrent_queries == 0 {
            return Err(ConfigError::Invalid(
                "admission.max_concurrent_queries must be > 0".to_owned(),
            ));
        }
        if self.admission.engine_queue_capacity == 0 {
            return Err(ConfigError::Invalid(
                "admission.engine_queue_capacity must be > 0".to_owned(),
            ));
        }
        if self.admission.result_buffer_capacity == 0 {
            return Err(ConfigError::Invalid(
                "admission.result_buffer_capacity must be > 0".to_owned(),
            ));
        }
        if self.admission.max_connections == 0 {
            return Err(ConfigError::Invalid(
                "admission.max_connections must be > 0".to_owned(),
            ));
        }
        if self.admission.max_open_transactions == 0 {
            return Err(ConfigError::Invalid(
                "admission.max_open_transactions must be > 0 (a zero cap would reject every REST \
                 BEGIN)"
                    .to_owned(),
            ));
        }
        if self.timing.handshake_timeout_ms == 0 {
            return Err(ConfigError::Invalid(
                "timing.handshake_timeout_ms must be > 0 (a zero handshake deadline would reject \
                 every TLS connection)"
                    .to_owned(),
            ));
        }
        if self.timing.transaction_idle_timeout_ms == 0 {
            return Err(ConfigError::Invalid(
                "timing.transaction_idle_timeout_ms must be > 0 (a zero idle timeout would reap \
                 every REST transaction the instant it is opened)"
                    .to_owned(),
            ));
        }
        if self.bulk_import.max_bytes_per_session == 0 {
            return Err(ConfigError::Invalid(
                "bulk_import.max_bytes_per_session must be > 0 (a zero quota would reject every \
                 bulk-import upload)"
                    .to_owned(),
            ));
        }
        if self.bulk_import.max_gcol_upload_bytes == 0 {
            return Err(ConfigError::Invalid(
                "bulk_import.max_gcol_upload_bytes must be > 0 (a zero cap would reject every \
                 .gcol upload)"
                    .to_owned(),
            ));
        }
        if self.bulk_import.max_gcol_decoded_bytes == 0 {
            return Err(ConfigError::Invalid(
                "bulk_import.max_gcol_decoded_bytes must be > 0 (a zero budget would reject every \
                 .gcol upload before it could decode a single row)"
                    .to_owned(),
            ));
        }
        if self.bulk_import.session_timeout_ms == 0 {
            return Err(ConfigError::Invalid(
                "bulk_import.session_timeout_ms must be > 0 (a zero session timeout would abort \
                 every bulk-import upload immediately)"
                    .to_owned(),
            ));
        }
        if self.bulk_import.mode_b_batch_rows == 0 {
            return Err(ConfigError::Invalid(
                "bulk_import.mode_b_batch_rows must be > 0 (a zero batch size can never commit a \
                 Mode B row)"
                    .to_owned(),
            ));
        }
        if self.bulk_import.mode_b_chunk_rows == 0 {
            return Err(ConfigError::Invalid(
                "bulk_import.mode_b_chunk_rows must be > 0 (a zero chunk size can never dispatch a \
                 Mode B row)"
                    .to_owned(),
            ));
        }
        if self.bulk_import.mode_b_chunk_rows > self.bulk_import.mode_b_batch_rows {
            return Err(ConfigError::Invalid(format!(
                "bulk_import.mode_b_chunk_rows ({}) must be <= bulk_import.mode_b_batch_rows ({}): \
                 a chunk larger than its own batch cannot be dispatched within it",
                self.bulk_import.mode_b_chunk_rows, self.bulk_import.mode_b_batch_rows
            )));
        }
        if self.bulk_import.mode_b_retry_backoff_ms == 0 {
            return Err(ConfigError::Invalid(
                "bulk_import.mode_b_retry_backoff_ms must be > 0 (a zero base backoff never grows \
                 under exponential doubling, defeating its own purpose)"
                    .to_owned(),
            ));
        }
        if self.bulk_import.mode_b_max_concurrent_sessions == 0 {
            return Err(ConfigError::Invalid(
                "bulk_import.mode_b_max_concurrent_sessions must be > 0 (a zero cap would reject \
                 every Mode B session)"
                    .to_owned(),
            ));
        }
        if self.bulk_import.mode_b_session_idle_timeout_ms == 0 {
            return Err(ConfigError::Invalid(
                "bulk_import.mode_b_session_idle_timeout_ms must be > 0 (a zero idle timeout would \
                 reap every Mode B session the instant it is opened)"
                    .to_owned(),
            ));
        }

        for user in &self.auth.users {
            if user.name.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "auth.users: a bootstrap user name must be non-empty".to_owned(),
                ));
            }
            if user.name == self.auth.admin_user {
                return Err(ConfigError::Invalid(format!(
                    "auth.users: {:?} collides with the admin user",
                    user.name
                )));
            }
        }

        self.tls.validate("tls")?;
        self.encryption.validate()?;
        self.audit.validate().map_err(ConfigError::Invalid)?;

        let network_listener = self.bolt_tcp_addr.is_some() || self.rest_addr.is_some();
        if network_listener && !self.tls.is_enabled() && !self.allow_insecure_network {
            return Err(ConfigError::Invalid(
                "a network listener (bolt_tcp_addr/rest_addr) requires TLS: set tls.cert_path and \
                 tls.key_path (only UDS is exempt — it is a kernel-protected local channel). Set \
                 allow_insecure_network = true to override (test/dev only)."
                    .to_owned(),
            ));
        }
        if self.rest_addr.is_some() && self.jwt_secret == DEFAULT_INSECURE_JWT_SECRET {
            return Err(ConfigError::Invalid(
                "rest_addr is enabled but jwt_secret is the insecure default: set a real secret via \
                 the config file or GRAPHUS_JWT_SECRET"
                    .to_owned(),
            ));
        }
        if self
            .metrics_scrape_token
            .as_deref()
            .is_some_and(|t| t.trim().is_empty())
        {
            return Err(ConfigError::Invalid(
                "metrics_scrape_token is set but empty: a blank scrape secret authenticates nobody \
                 safely. Leave it unset to require an admin Bearer for /metrics, or set a real \
                 token."
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// The path to the **default database's** record-store device file within
    /// [`store_path`](Self::store_path) (additional databases live under `databases/<name>/` —
    /// see [`crate::dbcatalog`]).
    #[must_use]
    pub fn device_file(&self) -> PathBuf {
        self.store_path.join(crate::dbcatalog::STORE_FILE_NAME)
    }

    /// The path to the **default database's** WAL file within [`store_path`](Self::store_path).
    #[must_use]
    pub fn wal_file(&self) -> PathBuf {
        self.store_path.join(crate::dbcatalog::WAL_FILE_NAME)
    }

    /// The Bolt address advertised to routing (`neo4j://`) drivers in the `ROUTE` reply (rmp #95).
    ///
    /// Resolves to [`advertised_bolt_address`](Self::advertised_bolt_address) when set, else to the
    /// configured [`bolt_tcp_addr`](Self::bolt_tcp_addr) (the address Bolt-TCP binds to). `None` when
    /// neither is set — a UDS-only deployment has no TCP address to advertise, and the Bolt session
    /// then advertises its documented `localhost:7687` fallback so a routing table is still
    /// well-formed.
    #[must_use]
    pub fn resolved_advertised_bolt_address(&self) -> Option<String> {
        self.advertised_bolt_address
            .clone()
            .or_else(|| self.bolt_tcp_addr.clone())
    }

    /// The `server` agent string to announce in the Bolt `HELLO` `SUCCESS`, resolved from
    /// [`bolt_server_agent`](Self::bolt_server_agent) (rmp #614):
    /// - `None` → the honest default `Graphus/<version>`
    ///   ([`DEFAULT_SERVER_AGENT`](graphus_bolt::server::DEFAULT_SERVER_AGENT));
    /// - the case-insensitive shortcut [`NEO4J_COMPAT_AGENT_SHORTCUT`] (`"neo4j-compat"`) → the vetted
    ///   `Neo4j/5.13.0` ([`NEO4J_COMPAT_SERVER_AGENT`](graphus_bolt::server::NEO4J_COMPAT_SERVER_AGENT));
    /// - any other value → returned **verbatim** (the operator owns the exact string).
    ///
    /// [`normalize`](Self::normalize) already trims and maps blank → `None`; this resolver **also**
    /// trims and treats blank as unset, so it stays correct even if called on a not-yet-normalized
    /// config (defence in depth — a stray leading/trailing space must never reach the wire and defeat
    /// the strict Neo4j parser).
    #[must_use]
    pub fn resolved_bolt_server_agent(&self) -> String {
        use graphus_bolt::server::{DEFAULT_SERVER_AGENT, NEO4J_COMPAT_SERVER_AGENT};
        match self.bolt_server_agent.as_deref().map(str::trim) {
            None | Some("") => DEFAULT_SERVER_AGENT.to_owned(),
            Some(s) if s.eq_ignore_ascii_case(NEO4J_COMPAT_AGENT_SHORTCUT) => {
                NEO4J_COMPAT_SERVER_AGENT.to_owned()
            }
            Some(s) => s.to_owned(),
        }
    }

    /// The highest Bolt 5.x minor the listeners advertise and accept, resolved from
    /// [`bolt_max_protocol_minor`](Self::bolt_max_protocol_minor) (rmp #906): the configured cap when
    /// set, else the compiled [`MAX_BOLT_PROTOCOL_MINOR`] — so an unconfigured server negotiates the
    /// full window exactly as it did before the option existed.
    ///
    /// [`validate`](Self::validate) has already refused an out-of-range cap; the handshake layer
    /// clamps again as defence in depth, so the value returned here can never widen the window.
    #[must_use]
    pub fn resolved_bolt_max_protocol_minor(&self) -> u8 {
        self.bolt_max_protocol_minor
            .unwrap_or(MAX_BOLT_PROTOCOL_MINOR)
    }
}

/// The lowest Bolt 5.x minor Graphus implements — the floor of the
/// [`bolt_max_protocol_minor`](ServerConfig::bolt_max_protocol_minor) range (re-exported from
/// `graphus-bolt`, so the config validator and the protocol core can never drift apart).
pub const MIN_BOLT_PROTOCOL_MINOR: u8 = graphus_bolt::handshake::MIN_MINOR;

/// The highest Bolt 5.x minor Graphus implements — the ceiling of the
/// [`bolt_max_protocol_minor`](ServerConfig::bolt_max_protocol_minor) range **and** its resolved
/// default (re-exported from `graphus-bolt`; see [`MIN_BOLT_PROTOCOL_MINOR`]).
pub const MAX_BOLT_PROTOCOL_MINOR: u8 = graphus_bolt::handshake::MAX_MINOR;

/// Maps an empty string to `None` so `GRAPHUS_REST_ADDR=` explicitly *disables* a listener (rather
/// than binding to the empty address).
fn empty_to_none(v: String) -> Option<String> {
    if v.trim().is_empty() { None } else { Some(v) }
}

/// The case-insensitive shortcut token for [`bolt_server_agent`](ServerConfig::bolt_server_agent)
/// that expands to the vetted Neo4j-compatibility agent string
/// [`NEO4J_COMPAT_SERVER_AGENT`](graphus_bolt::server::NEO4J_COMPAT_SERVER_AGENT) (`Neo4j/5.13.0`),
/// so an operator need not hard-code (and risk mistyping) the exact string.
pub const NEO4J_COMPAT_AGENT_SHORTCUT: &str = "neo4j-compat";

/// Does `agent` *claim* the Neo4j product but in a shape a strict/legacy Neo4j driver would reject —
/// defeating the very compatibility it is meant to buy?
///
/// Such a driver does two things the modern ones don't: it parses the string with an **anchored**
/// regex `([^/]+)/(\d+)\.(\d+)(?:\.)?(\d*)(\.|-|\+)?([0-9A-Za-z-.]*)?` (it must consume the *whole*
/// string), and it then checks the product with a **case-sensitive** `.equals("Neo4j")`. A string can
/// fail either gate:
/// - **wrong case** — `neo4j/5.13.0`, `NEO4J/5.13.0`: parse fine but fail the case-sensitive product
///   check. This is the *most plausible* operator typo — they believe they enabled compat and would
///   otherwise get no signal.
/// - **malformed version** — `Neo4j/5`, `Neo4j/5.`, `Neo4j/5.13 beta`, `Neo4j/5.26.0 (Graphus/0.0.8)`:
///   the anchored regex needs at least `<major>.<minor>` and forbids spaces/parens/extra `/`.
///
/// This flags exactly those cases while keeping **zero false positives** (every safe form —
/// `Neo4j/5.13.0`, `Neo4j/5.13.0-graphus-<ver>`, and any non-Neo4j product like `Graphus/…` — is left
/// alone). It drives a **startup warning only**, never a rejection: the operator's explicit string is
/// still announced verbatim.
#[must_use]
pub fn bolt_agent_claims_neo4j_but_unparseable(agent: &str) -> bool {
    // Split product/version on the first `/`; without one, it is not claiming the Neo4j shape.
    let Some((product, version)) = agent.split_once('/') else {
        return false;
    };
    // Only agents that *attempt* the Neo4j product are this heuristic's business.
    if !product.eq_ignore_ascii_case("Neo4j") {
        return false;
    }
    // Attempting Neo4j: reject if the product is not the case-sensitive literal, or the version does
    // not match the strict anchored shape.
    product != "Neo4j" || !neo4j_version_is_strict_parseable(version)
}

/// Whether `version` matches the version tail of the strict/legacy Neo4j driver's anchored regex
/// `(\d+)\.(\d+)(?:\.)?(\d*)(\.|-|\+)?([0-9A-Za-z-.]*)?`: it must begin with `<major>.<minor>`
/// (digits, `.`, digits) and the whole remainder may contain only the suffix alphabet
/// `[0-9A-Za-z]` plus the separators `.`, `-`, `+` (never a space, `(`, `)` or `/`).
fn neo4j_version_is_strict_parseable(version: &str) -> bool {
    // <major>: one or more leading digits.
    let major_len = version.chars().take_while(char::is_ascii_digit).count();
    if major_len == 0 {
        return false;
    }
    // A literal `.` must follow the major.
    let Some(after_major) = version[major_len..].strip_prefix('.') else {
        return false;
    };
    // <minor>: one or more digits.
    let minor_len = after_major.chars().take_while(char::is_ascii_digit).count();
    if minor_len == 0 {
        return false;
    }
    // The rest (optional patch/suffix) may only use the regex's allowed alphabet.
    after_major[minor_len..]
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_runnable_and_valid() {
        // The default has a REST listener; to validate it we must supply TLS + a real secret, which
        // mirrors what a real deployment does. The *shape* of the default (a UDS + REST) is the
        // point here; validation correctly rejects the insecure secret.
        let cfg = ServerConfig::default();
        assert!(cfg.uds_path.is_some());
        assert!(cfg.rest_addr.is_some());
        // Insecure default secret + REST → rejected.
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn uds_only_needs_no_tls_and_no_secret() {
        let cfg = ServerConfig {
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: Some(PathBuf::from("x.sock")),
            ..ServerConfig::default()
        };
        assert!(cfg.validate().is_ok(), "UDS-only is valid without TLS");
    }

    #[test]
    fn network_listener_requires_tls() {
        let cfg = ServerConfig {
            rest_addr: None,
            uds_path: None,
            bolt_tcp_addr: Some("127.0.0.1:7687".to_owned()),
            jwt_secret: "a-real-secret-value-32-bytes-long!!".to_owned(),
            ..ServerConfig::default()
        };
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn half_configured_tls_is_rejected() {
        let cfg = ServerConfig {
            tls: TlsConfig {
                cert_path: Some(PathBuf::from("c.pem")),
                key_path: None,
            },
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: Some(PathBuf::from("x.sock")),
            ..ServerConfig::default()
        };
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn no_listeners_is_rejected() {
        let cfg = ServerConfig {
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: None,
            ..ServerConfig::default()
        };
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn zero_admission_limit_is_rejected() {
        let cfg = ServerConfig {
            admission: AdmissionConfig {
                max_concurrent_queries: 0,
                ..AdmissionConfig::default()
            },
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: Some(PathBuf::from("x.sock")),
            ..ServerConfig::default()
        };
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn bulk_import_mode_b_defaults_and_accessors() {
        let cfg = BulkImportConfig::default();
        assert_eq!(cfg.mode_b_batch_rows, 2_000);
        assert_eq!(cfg.mode_b_chunk_rows, 25);
        assert_eq!(cfg.mode_b_max_batch_retries, 5);
        assert_eq!(cfg.mode_b_retry_backoff_ms, 20);
        assert_eq!(cfg.mode_b_max_concurrent_sessions, 8);
        assert_eq!(cfg.mode_b_session_idle_timeout_ms, 30 * 60 * 1000);
        assert_eq!(cfg.mode_b_retry_backoff(), Duration::from_millis(20));
        assert_eq!(
            cfg.mode_b_session_idle_timeout(),
            Duration::from_millis(30 * 60 * 1000)
        );
        // The defaults themselves must validate cleanly.
        let server = ServerConfig {
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: Some(PathBuf::from("x.sock")),
            ..ServerConfig::default()
        };
        assert!(server.validate().is_ok());
    }

    #[test]
    fn zero_mode_b_batch_rows_is_rejected() {
        let cfg = ServerConfig {
            bulk_import: BulkImportConfig {
                mode_b_batch_rows: 0,
                ..BulkImportConfig::default()
            },
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: Some(PathBuf::from("x.sock")),
            ..ServerConfig::default()
        };
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn zero_mode_b_chunk_rows_is_rejected() {
        let cfg = ServerConfig {
            bulk_import: BulkImportConfig {
                mode_b_chunk_rows: 0,
                ..BulkImportConfig::default()
            },
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: Some(PathBuf::from("x.sock")),
            ..ServerConfig::default()
        };
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn mode_b_chunk_rows_exceeding_batch_rows_is_rejected() {
        let cfg = ServerConfig {
            bulk_import: BulkImportConfig {
                mode_b_batch_rows: 10,
                mode_b_chunk_rows: 11,
                ..BulkImportConfig::default()
            },
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: Some(PathBuf::from("x.sock")),
            ..ServerConfig::default()
        };
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn mode_b_chunk_rows_equal_to_batch_rows_is_accepted() {
        let cfg = ServerConfig {
            bulk_import: BulkImportConfig {
                mode_b_batch_rows: 10,
                mode_b_chunk_rows: 10,
                ..BulkImportConfig::default()
            },
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: Some(PathBuf::from("x.sock")),
            ..ServerConfig::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn zero_mode_b_retry_backoff_is_rejected() {
        let cfg = ServerConfig {
            bulk_import: BulkImportConfig {
                mode_b_retry_backoff_ms: 0,
                ..BulkImportConfig::default()
            },
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: Some(PathBuf::from("x.sock")),
            ..ServerConfig::default()
        };
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn zero_mode_b_max_concurrent_sessions_is_rejected() {
        let cfg = ServerConfig {
            bulk_import: BulkImportConfig {
                mode_b_max_concurrent_sessions: 0,
                ..BulkImportConfig::default()
            },
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: Some(PathBuf::from("x.sock")),
            ..ServerConfig::default()
        };
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn zero_mode_b_session_idle_timeout_is_rejected() {
        let cfg = ServerConfig {
            bulk_import: BulkImportConfig {
                mode_b_session_idle_timeout_ms: 0,
                ..BulkImportConfig::default()
            },
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: Some(PathBuf::from("x.sock")),
            ..ServerConfig::default()
        };
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));
    }

    // `mode_b_max_batch_retries` has no zero-rejection rule: `0` is documented as a valid "no
    // automatic retry" value (`08` §7.2.3), so there is no invalid value to test here beyond the
    // type's own range — covered implicitly by the defaults test above.

    #[test]
    fn connection_admission_defaults_and_validation() {
        // Sensible defaults (rmp #118).
        let cfg = AdmissionConfig::default();
        assert_eq!(cfg.max_connections, 1024);
        // The per-source-IP cap (rmp #478) defaults to a fraction of `max_connections` — enabled by
        // default, but well above any single-host client's footprint.
        assert_eq!(cfg.max_connections_per_ip, 256);
        let t = TimingConfig::default();
        assert_eq!(t.handshake_timeout_ms, 10_000);
        assert_eq!(t.idle_timeout_ms, 0, "idle reaping is off by default");
        assert_eq!(t.handshake_timeout(), Duration::from_millis(10_000));
        assert_eq!(t.idle_timeout(), None, "0 ⇒ disabled");
        assert_eq!(
            TimingConfig {
                idle_timeout_ms: 250,
                ..TimingConfig::default()
            }
            .idle_timeout(),
            Some(Duration::from_millis(250))
        );

        // The per-statement timeout (rmp #476) is bounded-by-default and `0` disables it.
        assert_eq!(
            t.statement_timeout(),
            Some(Duration::from_millis(120_000)),
            "statement timeout is finite (bounded) by default"
        );
        assert_eq!(
            TimingConfig {
                statement_timeout_ms: 0,
                ..TimingConfig::default()
            }
            .statement_timeout(),
            None,
            "0 ⇒ disabled (opt-out, unbounded)"
        );

        // The max transaction-age cap (rmp #477) is bounded-by-default (1 hour) and `0` disables it.
        assert_eq!(
            t.max_transaction_age_ms, 3_600_000,
            "max transaction age is finite (1 hour) by default"
        );
        assert_eq!(
            t.max_transaction_age(),
            Some(Duration::from_millis(3_600_000)),
            "max transaction age is finite (bounded) by default"
        );
        assert_eq!(
            TimingConfig {
                max_transaction_age_ms: 0,
                ..TimingConfig::default()
            }
            .max_transaction_age(),
            None,
            "0 ⇒ disabled (opt-out, unbounded lifetime)"
        );

        // The off-thread reader egress-stall ceiling (rmp #591, C-F1) is bounded-by-default (30s) and
        // `0` disables it — the always-on guard against a stalled consumer pinning a reader's GC watermark.
        assert_eq!(
            t.egress_stall_timeout_ms, 30_000,
            "egress-stall ceiling is finite (30s) by default"
        );
        assert_eq!(
            t.egress_stall_timeout(),
            Some(Duration::from_millis(30_000)),
            "egress-stall ceiling is finite (bounded) by default"
        );
        assert_eq!(
            TimingConfig {
                egress_stall_timeout_ms: 0,
                ..TimingConfig::default()
            }
            .egress_stall_timeout(),
            None,
            "0 ⇒ disabled (opt-out; a stalled consumer can then pin a reader when the statement timeout \
             is also disabled)"
        );

        // A zero connection cap is rejected.
        let cfg = ServerConfig {
            admission: AdmissionConfig {
                max_connections: 0,
                ..AdmissionConfig::default()
            },
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: Some(PathBuf::from("x.sock")),
            ..ServerConfig::default()
        };
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));

        // A zero handshake timeout is rejected (it would refuse every TLS connection).
        let cfg = ServerConfig {
            timing: TimingConfig {
                handshake_timeout_ms: 0,
                ..TimingConfig::default()
            },
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: Some(PathBuf::from("x.sock")),
            ..ServerConfig::default()
        };
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn blocking_thread_budget_is_derived_from_max_connections() {
        // rmp #363: the Tokio blocking-thread budget is always `max_connections + RESERVED_HEADROOM`,
        // so the two can never silently disagree (the 512-default-starves-the-513th-session bug).
        let default = AdmissionConfig::default();
        assert_eq!(default.max_connections, 1024);
        assert_eq!(
            default.blocking_thread_budget(),
            1024 + RESERVED_HEADROOM,
            "budget must be max_connections + the documented headroom"
        );

        // The default already clears Tokio's 512-thread default with room to spare, and a larger cap
        // (the sample config sets 4096) scales the budget with it — never capping silently at 512.
        for max_connections in [1_usize, 512, 513, 1024, 2000, 4096] {
            let admission = AdmissionConfig {
                max_connections,
                ..AdmissionConfig::default()
            };
            let budget = admission.blocking_thread_budget();
            assert!(
                budget >= max_connections + RESERVED_HEADROOM,
                "budget {budget} must seat every one of {max_connections} sessions plus headroom"
            );
            assert!(
                budget > max_connections,
                "budget {budget} must exceed max_connections {max_connections} (strict headroom)"
            );
        }

        // The default config builds a runtime whose blocking budget clears Tokio's 512 floor: a
        // server at the default cap can admit every session it accepts.
        assert!(
            AdmissionConfig::default().blocking_thread_budget() > 512,
            "default blocking budget must exceed Tokio's 512 default so the 513th session never \
             queues forever"
        );
    }

    #[test]
    fn blocking_thread_budget_saturates_on_overflow() {
        // A pathological `max_connections` near usize::MAX must clamp, not wrap (wrapping would
        // produce a tiny budget and silently reintroduce starvation).
        let admission = AdmissionConfig {
            max_connections: usize::MAX,
            ..AdmissionConfig::default()
        };
        assert_eq!(admission.blocking_thread_budget(), usize::MAX);
    }

    #[test]
    fn parses_a_toml_file() {
        let toml = r#"
            store_path = "/var/lib/graphus"
            buffer_pool_pages = 8192
            rest_addr = "0.0.0.0:7474"
            uds_path = "/run/graphus.sock"
            jwt_secret = "file-provided-secret-value-here!"

            [tls]
            cert_path = "/etc/graphus/cert.pem"
            key_path = "/etc/graphus/key.pem"

            [admission]
            max_concurrent_queries = 512
            max_connections = 4096

            [timing]
            slow_query_threshold_ms = 250
            handshake_timeout_ms = 3000
            idle_timeout_ms = 30000
        "#;
        let cfg: ServerConfig = toml::from_str(toml).expect("parse");
        assert_eq!(cfg.store_path, PathBuf::from("/var/lib/graphus"));
        assert_eq!(cfg.buffer_pool_pages, 8192);
        assert_eq!(cfg.admission.max_concurrent_queries, 512);
        assert_eq!(cfg.admission.max_connections, 4096);
        assert_eq!(cfg.timing.slow_query_threshold_ms, 250);
        assert_eq!(cfg.timing.handshake_timeout_ms, 3000);
        assert_eq!(cfg.timing.idle_timeout_ms, 30_000);
        assert!(cfg.tls.is_enabled());
        assert!(cfg.validate().is_ok());
    }

    /// The opt-in CSR-adjacency knob (`rmp` task #324, "Win 2") defaults **off**, and a TOML file that
    /// omits it parses with the accelerator disabled — the zero-RAM default the task mandates.
    #[test]
    fn csr_adjacency_defaults_off_and_opts_in_via_toml() {
        // Default.
        assert!(
            !AdmissionConfig::default().csr_adjacency,
            "CSR adjacency must default OFF (zero extra RAM)"
        );
        // A TOML that does not mention it stays off.
        let off: ServerConfig = toml::from_str(
            r#"
            store_path = "/x"
            uds_path = "/run/g.sock"
            [admission]
            max_concurrent_queries = 8
            "#,
        )
        .expect("parse");
        assert!(!off.admission.csr_adjacency, "omitted ⇒ off");
        // Opting in via TOML.
        let on: ServerConfig = toml::from_str(
            r#"
            store_path = "/x"
            uds_path = "/run/g.sock"
            [admission]
            csr_adjacency = true
            "#,
        )
        .expect("parse");
        assert!(on.admission.csr_adjacency, "csr_adjacency = true ⇒ on");
    }

    #[test]
    fn per_ip_cap_parses_from_toml_and_zero_is_valid() {
        // The per-source-IP cap (rmp #478) is operator-tunable via the `[admission]` table, and `0`
        // (disabled — the NAT/load-balancer/reverse-proxy setting) is a valid configuration.
        let mut cfg: ServerConfig = toml::from_str(
            r#"
            store_path = "/x"
            uds_path = "/run/g.sock"
            rest_addr = ""
            [admission]
            max_connections = 4096
            max_connections_per_ip = 512
            "#,
        )
        .expect("parse");
        // `normalize()` turns the blanked `rest_addr` into `None` (UDS-only), exactly as `load()` does;
        // `toml::from_str` alone does not run it.
        cfg.normalize();
        assert_eq!(cfg.admission.max_connections_per_ip, 512);
        assert!(cfg.validate().is_ok());

        // A zero per-IP cap (disabled) is accepted by validation — unlike `max_connections`, which
        // must be > 0, a zero per-IP cap simply means "global cap only".
        let cfg = ServerConfig {
            admission: AdmissionConfig {
                max_connections_per_ip: 0,
                ..AdmissionConfig::default()
            },
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: Some(PathBuf::from("x.sock")),
            ..ServerConfig::default()
        };
        assert!(
            cfg.validate().is_ok(),
            "a zero per-IP cap is valid (disables the per-IP bound)"
        );
    }

    #[test]
    fn empty_env_value_disables_listener() {
        assert_eq!(empty_to_none(String::new()), None);
        assert_eq!(empty_to_none("  ".to_owned()), None);
        assert_eq!(empty_to_none("x".to_owned()), Some("x".to_owned()));
    }

    #[test]
    fn normalize_blanks_disable_listeners() {
        // An empty string in the file (not just env) disables a listener.
        let mut cfg = ServerConfig {
            rest_addr: Some(String::new()),
            bolt_tcp_addr: Some("  ".to_owned()),
            uds_path: Some(PathBuf::new()),
            ..ServerConfig::default()
        };
        cfg.normalize();
        assert_eq!(cfg.rest_addr, None, "blank rest_addr disabled");
        assert_eq!(cfg.bolt_tcp_addr, None, "whitespace bolt_tcp_addr disabled");
        assert_eq!(cfg.uds_path, None, "empty uds_path disabled");
    }

    #[test]
    fn unknown_field_is_rejected() {
        // `deny_unknown_fields` catches typos in operator config.
        let toml = "store_pathh = \"/oops\"\n";
        assert!(toml::from_str::<ServerConfig>(toml).is_err());
    }

    #[test]
    fn default_database_defaults_and_is_validated() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.default_database, "graphus");

        // An invalid default-database name is rejected with a clear message.
        let cfg = ServerConfig {
            default_database: "no/slash".to_owned(),
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: Some(PathBuf::from("x.sock")),
            ..ServerConfig::default()
        };
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn bootstrap_users_are_parsed_and_validated() {
        // A TOML file can seed non-admin users (read+write only — rmp #84 privilege boundary).
        let toml = r#"
            uds_path = "/run/graphus.sock"
            rest_addr = ""
            [[auth.users]]
            name = "app"
            password = "s3cret"
        "#;
        let mut cfg: ServerConfig = toml::from_str(toml).expect("parse");
        cfg.normalize();
        assert_eq!(cfg.auth.users.len(), 1);
        assert_eq!(cfg.auth.users[0].name, "app");
        assert!(cfg.validate().is_ok());

        // A bootstrap user colliding with the admin name is rejected.
        let cfg = ServerConfig {
            auth: AuthBootstrap {
                users: vec![UserBootstrap {
                    name: "admin".to_owned(),
                    password: "x".to_owned(),
                }],
                ..AuthBootstrap::default()
            },
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: Some(PathBuf::from("x.sock")),
            ..ServerConfig::default()
        };
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));

        // An empty bootstrap user name is rejected.
        let cfg = ServerConfig {
            auth: AuthBootstrap {
                users: vec![UserBootstrap::default()],
                ..AuthBootstrap::default()
            },
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: Some(PathBuf::from("x.sock")),
            ..ServerConfig::default()
        };
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn encryption_defaults_to_disabled() {
        let cfg = ServerConfig::default();
        assert!(!cfg.encryption.is_enabled(), "encryption is off by default");
        assert!(cfg.encryption.key_path.is_none());
    }

    #[test]
    fn encryption_key_path_must_exist_when_set() {
        // A set-but-missing key file is a misconfiguration that fails validation fast.
        let cfg = ServerConfig {
            encryption: EncryptionConfig {
                key_path: Some(PathBuf::from("/nonexistent/graphus/master.key")),
            },
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: Some(PathBuf::from("x.sock")),
            ..ServerConfig::default()
        };
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn encryption_with_an_existing_key_file_validates() {
        // Write a temp 32-byte key file; the config should validate.
        let mut path = std::env::temp_dir();
        path.push(format!(
            "graphus-cfg-key-{}-{}.key",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&path, [0x11u8; 32]).expect("write key file");
        let cfg = ServerConfig {
            encryption: EncryptionConfig {
                key_path: Some(path.clone()),
            },
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: Some(PathBuf::from("x.sock")),
            ..ServerConfig::default()
        };
        assert!(cfg.validate().is_ok(), "an existing key file validates");
        assert!(cfg.encryption.is_enabled());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn advertised_bolt_address_resolves_and_defaults() {
        // Explicit advertised address wins.
        let cfg = ServerConfig {
            advertised_bolt_address: Some("public.example:7687".to_owned()),
            bolt_server_agent: None,
            bolt_tcp_addr: Some("0.0.0.0:7687".to_owned()),
            ..ServerConfig::default()
        };
        assert_eq!(
            cfg.resolved_advertised_bolt_address().as_deref(),
            Some("public.example:7687")
        );

        // Unset advertised address falls back to the Bolt-TCP bind address.
        let cfg = ServerConfig {
            advertised_bolt_address: None,
            bolt_server_agent: None,
            bolt_tcp_addr: Some("10.0.0.5:7687".to_owned()),
            ..ServerConfig::default()
        };
        assert_eq!(
            cfg.resolved_advertised_bolt_address().as_deref(),
            Some("10.0.0.5:7687")
        );

        // Neither set (UDS-only): None — the Bolt session uses its documented localhost fallback.
        let cfg = ServerConfig {
            advertised_bolt_address: None,
            bolt_server_agent: None,
            bolt_tcp_addr: None,
            ..ServerConfig::default()
        };
        assert_eq!(cfg.resolved_advertised_bolt_address(), None);
    }

    #[test]
    fn normalize_blanks_disable_advertised_bolt_address() {
        let mut cfg = ServerConfig {
            advertised_bolt_address: Some("   ".to_owned()),
            bolt_server_agent: None,
            ..ServerConfig::default()
        };
        cfg.normalize();
        assert_eq!(cfg.advertised_bolt_address, None);
    }

    #[test]
    fn bolt_server_agent_resolves_default_shortcut_and_verbatim() {
        use graphus_bolt::server::{DEFAULT_SERVER_AGENT, NEO4J_COMPAT_SERVER_AGENT};

        // Unset → the honest `Graphus/<version>` default (rmp #614; the user-chosen opt-in policy).
        let cfg = ServerConfig {
            bolt_server_agent: None,
            ..ServerConfig::default()
        };
        assert_eq!(cfg.resolved_bolt_server_agent(), DEFAULT_SERVER_AGENT);
        assert!(cfg.resolved_bolt_server_agent().starts_with("Graphus/"));

        // The shortcut expands to the vetted Neo4j-compat string — case-insensitively, so
        // `neo4j-compat` / `Neo4j-Compat` / `NEO4J-COMPAT` all work.
        for token in ["neo4j-compat", "Neo4j-Compat", "NEO4J-COMPAT"] {
            let cfg = ServerConfig {
                bolt_server_agent: Some(token.to_owned()),
                ..ServerConfig::default()
            };
            assert_eq!(
                cfg.resolved_bolt_server_agent(),
                NEO4J_COMPAT_SERVER_AGENT,
                "shortcut {token:?} must expand to {NEO4J_COMPAT_SERVER_AGENT}"
            );
        }
        // The vetted constant is exactly the Neo4j-5.13.0 floor of the Bolt-5.4 window.
        assert_eq!(NEO4J_COMPAT_SERVER_AGENT, "Neo4j/5.13.0");

        // Any other value is announced verbatim — full operator control (e.g. keep the Graphus marker
        // in a strict-parseable form).
        let cfg = ServerConfig {
            bolt_server_agent: Some("Neo4j/5.13.0-graphus-0.0.8".to_owned()),
            ..ServerConfig::default()
        };
        assert_eq!(
            cfg.resolved_bolt_server_agent(),
            "Neo4j/5.13.0-graphus-0.0.8"
        );
    }

    #[test]
    fn normalize_trims_and_blanks_bolt_server_agent() {
        // Blank → None → resolves back to the default.
        let mut cfg = ServerConfig {
            bolt_server_agent: Some("   ".to_owned()),
            ..ServerConfig::default()
        };
        cfg.normalize();
        assert_eq!(cfg.bolt_server_agent, None);

        // A set value is trimmed to its canonical form (surrounding whitespace would defeat the
        // strict Neo4j parser it may be meant to satisfy).
        let mut cfg = ServerConfig {
            bolt_server_agent: Some("  Neo4j/5.13.0  ".to_owned()),
            ..ServerConfig::default()
        };
        cfg.normalize();
        assert_eq!(cfg.bolt_server_agent.as_deref(), Some("Neo4j/5.13.0"));
    }

    #[test]
    fn bolt_max_protocol_minor_defaults_to_the_compiled_maximum_and_only_narrows() {
        // rmp #906. Unset → the compiled maximum, so an unconfigured server advertises the full
        // window exactly as it did before the option existed.
        let cfg = ServerConfig::default();
        assert_eq!(cfg.bolt_max_protocol_minor, None, "unset by default");
        assert_eq!(
            cfg.resolved_bolt_max_protocol_minor(),
            MAX_BOLT_PROTOCOL_MINOR
        );
        assert_eq!(
            MAX_BOLT_PROTOCOL_MINOR,
            graphus_bolt::handshake::MAX_MINOR,
            "the config ceiling must track the protocol core's, never drift from it"
        );

        // Every in-range cap resolves verbatim and validates.
        for minor in MIN_BOLT_PROTOCOL_MINOR..=MAX_BOLT_PROTOCOL_MINOR {
            let cfg = ServerConfig {
                bolt_max_protocol_minor: Some(minor),
                rest_addr: None,
                bolt_tcp_addr: None,
                uds_path: Some(PathBuf::from("x.sock")),
                ..ServerConfig::default()
            };
            assert_eq!(cfg.resolved_bolt_max_protocol_minor(), minor);
            assert!(cfg.validate().is_ok(), "5.{minor} must be a valid cap");
        }

        // It is a first-class TOML key (the struct is `deny_unknown_fields`, so this also proves the
        // documented spelling is the one the parser accepts).
        let cfg: ServerConfig =
            toml::from_str("bolt_max_protocol_minor = 0\n").expect("parse the cap from TOML");
        assert_eq!(cfg.bolt_max_protocol_minor, Some(0));
        assert_eq!(cfg.resolved_bolt_max_protocol_minor(), 0);
    }

    #[test]
    fn an_out_of_range_bolt_max_protocol_minor_is_rejected_at_validation() {
        // A minor Graphus does not implement is a fail-fast startup error, not a silent clamp: an
        // operator asking for 5.9 must learn at boot, not discover 5.4 negotiated at runtime.
        for minor in [MAX_BOLT_PROTOCOL_MINOR + 1, 9, 200] {
            let cfg = ServerConfig {
                bolt_max_protocol_minor: Some(minor),
                rest_addr: None,
                bolt_tcp_addr: None,
                uds_path: Some(PathBuf::from("x.sock")),
                ..ServerConfig::default()
            };
            match cfg.validate() {
                Err(ConfigError::Invalid(msg)) => assert!(
                    msg.contains("bolt_max_protocol_minor"),
                    "the error must name the setting: {msg}"
                ),
                other => panic!("5.{minor} must be rejected, got {other:?}"),
            }
        }
    }

    #[test]
    fn bolt_max_protocol_minor_is_reported_and_debug_printed() {
        // `SHOW SETTINGS` must surface the cap (it changes what every driver negotiates), and it is
        // not a secret, so `Debug` prints it verbatim.
        let cfg = ServerConfig {
            bolt_max_protocol_minor: Some(0),
            ..ServerConfig::default()
        };
        let row = cfg
            .effective_settings()
            .into_iter()
            .find(|r| r.name == "bolt_max_protocol_minor")
            .expect("the cap must appear in SHOW SETTINGS");
        assert_eq!(row.value.as_deref(), Some("0"));
        assert!(format!("{cfg:?}").contains("bolt_max_protocol_minor: Some(0)"));

        // Unset renders as null (not as the resolved default) — the row reports the *setting*.
        let cfg = ServerConfig::default();
        let row = cfg
            .effective_settings()
            .into_iter()
            .find(|r| r.name == "bolt_max_protocol_minor")
            .expect("the cap must appear in SHOW SETTINGS");
        assert_eq!(row.value, None);
    }

    #[test]
    fn neo4j_agent_footgun_detection() {
        // Malformed version: space + parentheses + second `/` break the strict anchored parser.
        assert!(bolt_agent_claims_neo4j_but_unparseable(
            "Neo4j/5.26.0 (Graphus/0.0.8)"
        ));
        assert!(bolt_agent_claims_neo4j_but_unparseable("Neo4j/")); // no version at all
        assert!(bolt_agent_claims_neo4j_but_unparseable("Neo4j/5.13 beta"));
        assert!(bolt_agent_claims_neo4j_but_unparseable("Neo4j/5")); // no minor
        assert!(bolt_agent_claims_neo4j_but_unparseable("Neo4j/5.")); // empty minor
        assert!(bolt_agent_claims_neo4j_but_unparseable("Neo4j/x.y")); // non-numeric

        // Wrong case: parses, but fails the driver's case-sensitive `.equals("Neo4j")` genuineness
        // check — the most plausible operator typo, and now warned.
        assert!(bolt_agent_claims_neo4j_but_unparseable("neo4j/5.13.0"));
        assert!(bolt_agent_claims_neo4j_but_unparseable("NEO4J/5.13.0"));

        // Safe compatible forms are NOT flagged (zero false positives).
        assert!(!bolt_agent_claims_neo4j_but_unparseable("Neo4j/5.13.0"));
        assert!(!bolt_agent_claims_neo4j_but_unparseable("Neo4j/5.13")); // major.minor only is legal
        assert!(!bolt_agent_claims_neo4j_but_unparseable(
            "Neo4j/5.13.0-graphus-0.0.8"
        ));
        // Non-Neo4j products are none of this heuristic's business (the honest default included).
        assert!(!bolt_agent_claims_neo4j_but_unparseable("Graphus/0.0.8"));
        assert!(!bolt_agent_claims_neo4j_but_unparseable("MyGraph/1.0.0"));
        assert!(!bolt_agent_claims_neo4j_but_unparseable("no-slash-at-all"));
    }

    #[test]
    fn audit_config_validates() {
        // An enabled audit with an explicitly-empty path is rejected (likely a typo).
        let cfg = ServerConfig {
            audit: AuditConfig {
                enabled: true,
                path: Some(PathBuf::new()),
                ..AuditConfig::default()
            },
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: Some(PathBuf::from("x.sock")),
            ..ServerConfig::default()
        };
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));

        // Rotation enabled but zero retained files is rejected.
        let cfg = ServerConfig {
            audit: AuditConfig {
                enabled: true,
                rotate_max_bytes: 1024,
                retain_files: 0,
                ..AuditConfig::default()
            },
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: Some(PathBuf::from("x.sock")),
            ..ServerConfig::default()
        };
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));

        // A sane enabled audit validates (UDS-only so no TLS/secret needed).
        let cfg = ServerConfig {
            audit: AuditConfig {
                enabled: true,
                ..AuditConfig::default()
            },
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: Some(PathBuf::from("x.sock")),
            ..ServerConfig::default()
        };
        assert!(cfg.validate().is_ok(), "a sane enabled audit validates");
        assert!(
            !ServerConfig::default().audit.enabled,
            "audit is off by default"
        );
    }

    #[test]
    fn normalize_lowercases_the_default_database() {
        // Names are case-insensitive and stored lowercase (`crate::dbcatalog`).
        let mut cfg = ServerConfig {
            default_database: "  MyGraph ".to_owned(),
            ..ServerConfig::default()
        };
        cfg.normalize();
        assert_eq!(cfg.default_database, "mygraph");
        assert!(
            crate::dbcatalog::normalize_db_name(&cfg.default_database).is_ok(),
            "the normalised form passes the name rule"
        );
    }

    // ---- Hardware-aware startup auto-tuning (`04 §9.5`, decision `D-hw-autotune`, rmp #617) ----
    //
    // These are deterministic simulations of the resolution: they feed `apply_hardware_defaults` /
    // `auto_buffer_pool_pages` **synthetic** `HardwareResources` (no probing I/O) and assert the exact
    // clamp arithmetic, the floor/ceiling, and — critically — that any operator-set value survives
    // resolution (file/env override hardware). Because the resolution is pure, this table-driven form
    // exercises every branch reproducibly (the DST/VOPR simulator targets storage-fault/concurrency
    // scenarios, which this pure config policy has none of).

    const GIB: u64 = 1024 * 1024 * 1024;

    /// A synthetic hardware snapshot for the tuning tests.
    fn hw(cpus: usize, available: Option<u64>, total: Option<u64>) -> HardwareResources {
        let mut h = HardwareResources::unknown();
        h.logical_cpus = cpus;
        h.memory.available_bytes = available;
        h.memory.total_bytes = total;
        h
    }

    #[test]
    fn auto_pool_uses_one_eighth_of_available_ram() {
        // 8 GiB available → 1 GiB budget → 1 GiB / 8 KiB = 131072 pages (inside [floor, ceil]).
        let pages = auto_buffer_pool_pages(&hw(4, Some(8 * GIB), Some(16 * GIB)));
        assert_eq!(pages, (8 * GIB / 8 / PAGE_SIZE as u64) as usize);
        assert_eq!(pages, 131_072);
    }

    #[test]
    fn auto_pool_prefers_available_over_total() {
        // Available (2 GiB) far below total (64 GiB): the budget must track available.
        let pages = auto_buffer_pool_pages(&hw(4, Some(2 * GIB), Some(64 * GIB)));
        assert_eq!(pages, (2 * GIB / 8 / PAGE_SIZE as u64) as usize); // 32768
    }

    #[test]
    fn auto_pool_falls_back_to_total_when_available_unknown() {
        let pages = auto_buffer_pool_pages(&hw(4, None, Some(8 * GIB)));
        assert_eq!(pages, 131_072);
    }

    #[test]
    fn auto_pool_floors_on_tiny_ram() {
        // 128 MiB available → 16 MiB budget → 2048 pages < floor → floored to the historical default.
        let pages =
            auto_buffer_pool_pages(&hw(1, Some(128 * 1024 * 1024), Some(256 * 1024 * 1024)));
        assert_eq!(pages, AUTO_BUFFER_POOL_FLOOR_PAGES);
    }

    #[test]
    fn auto_pool_floors_when_ram_is_unknown() {
        assert_eq!(
            auto_buffer_pool_pages(&hw(1, None, None)),
            AUTO_BUFFER_POOL_FLOOR_PAGES,
            "a failed RAM probe still yields at least the historical default pool"
        );
    }

    #[test]
    fn auto_pool_caps_on_huge_ram() {
        // 64 GiB available → 8 GiB budget → far above ceil → capped, so the per-database pool can
        // never run away on a big-RAM host.
        assert_eq!(
            auto_buffer_pool_pages(&hw(64, Some(64 * GIB), Some(64 * GIB))),
            AUTO_BUFFER_POOL_CEIL_PAGES
        );
    }

    #[test]
    fn apply_hardware_defaults_fills_only_auto_sentinels() {
        let mut cfg = ServerConfig::default(); // pool/reader/morsel all at the `0` auto sentinel
        cfg.apply_hardware_defaults(&hw(8, Some(8 * GIB), Some(8 * GIB)));
        assert_eq!(cfg.buffer_pool_pages, 131_072);
        assert_eq!(cfg.admission.reader_threads, 8);
        assert_eq!(cfg.admission.morsel_parallelism, 8);
    }

    #[test]
    fn operator_values_override_hardware_detection() {
        // Every knob set explicitly; auto-tuning must leave them all untouched (config wins).
        let mut cfg = ServerConfig {
            buffer_pool_pages: 12_345,
            admission: AdmissionConfig {
                reader_threads: 3,
                morsel_parallelism: 1, // the "fully serial" opt-out — a non-sentinel value
                ..AdmissionConfig::default()
            },
            ..ServerConfig::default()
        };
        cfg.apply_hardware_defaults(&hw(64, Some(64 * GIB), Some(64 * GIB)));
        assert_eq!(cfg.buffer_pool_pages, 12_345, "explicit pool preserved");
        assert_eq!(
            cfg.admission.reader_threads, 3,
            "explicit reader pool preserved"
        );
        assert_eq!(
            cfg.admission.morsel_parallelism, 1,
            "the serial opt-out (1) is a real value, not the auto sentinel, so it is preserved"
        );
    }

    #[test]
    fn auto_cpu_pools_are_capped_and_floored() {
        let mut cfg = ServerConfig::default();
        cfg.apply_hardware_defaults(&hw(64, None, None));
        assert_eq!(
            cfg.admission.reader_threads, AUTO_CPU_POOL_CAP,
            "64 cores → capped"
        );
        assert_eq!(cfg.admission.morsel_parallelism, AUTO_CPU_POOL_CAP);

        let mut cfg = ServerConfig::default();
        cfg.apply_hardware_defaults(&hw(0, None, None));
        assert_eq!(
            cfg.admission.reader_threads, 1,
            "0 reported cores → floored to 1"
        );
    }

    #[test]
    fn apply_hardware_defaults_is_idempotent() {
        let mut cfg = ServerConfig::default();
        let snapshot = hw(8, Some(8 * GIB), Some(8 * GIB));
        cfg.apply_hardware_defaults(&snapshot);
        let once = cfg.clone();
        cfg.apply_hardware_defaults(&snapshot);
        assert_eq!(
            cfg, once,
            "a second resolution is a no-op — every auto field is now concrete"
        );
    }

    #[test]
    fn validate_accepts_zero_pool_as_auto_but_rejects_tiny_explicit() {
        // UDS-only base so no TLS/JWT concerns interfere with the pool assertions.
        let base = ServerConfig {
            rest_addr: None,
            bolt_tcp_addr: None,
            uds_path: Some(PathBuf::from("x.sock")),
            ..ServerConfig::default()
        };

        let mut cfg = base.clone();
        cfg.buffer_pool_pages = 0;
        assert!(
            cfg.validate().is_ok(),
            "0 = auto must validate (resolved at startup)"
        );

        // A non-zero value below the minimum fails fast with a clean error — never a runtime panic
        // (`rmp` #302). {1,2,3,4} are the exact sizes that panicked the legacy RefCell pool.
        for tiny in [1usize, 2, 3, 4, MIN_BUFFER_POOL_PAGES - 1] {
            let mut cfg = base.clone();
            cfg.buffer_pool_pages = tiny;
            assert!(
                matches!(cfg.validate(), Err(ConfigError::Invalid(_))),
                "buffer_pool_pages = {tiny} (< {MIN_BUFFER_POOL_PAGES}) must be rejected"
            );
        }

        let mut cfg = base;
        cfg.buffer_pool_pages = MIN_BUFFER_POOL_PAGES;
        assert!(cfg.validate().is_ok(), "exactly the minimum pool validates");
    }

    #[test]
    fn toml_explicit_pool_overrides_auto_zero_stays_auto() {
        // An explicit value in the file survives hardware resolution (override precedence).
        let mut cfg: ServerConfig = toml::from_str("buffer_pool_pages = 5000\n").unwrap();
        cfg.apply_hardware_defaults(&hw(16, Some(64 * GIB), Some(64 * GIB)));
        assert_eq!(
            cfg.buffer_pool_pages, 5000,
            "file value wins over auto-detection"
        );

        // `0` in the file means auto → resolved from the detected hardware.
        let mut cfg: ServerConfig = toml::from_str("buffer_pool_pages = 0\n").unwrap();
        cfg.apply_hardware_defaults(&hw(16, Some(8 * GIB), Some(8 * GIB)));
        assert_eq!(
            cfg.buffer_pool_pages, 131_072,
            "0 in the file auto-sizes from RAM"
        );
    }
}
