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

use serde::Deserialize;

use crate::audit::AuditConfig;

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
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            max_concurrent_queries: 256,
            engine_queue_capacity: 1024,
            result_buffer_capacity: 256,
            max_connections: 1024,
            reader_threads: 0,
            morsel_parallelism: 0,
            max_open_transactions: graphus_rest::registry::DEFAULT_MAX_OPEN_TRANSACTIONS,
            csr_adjacency: false,
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
    /// milliseconds; must be > 0. UDS is exempt (no TLS — it is admitted by peer-cred at accept time).
    pub handshake_timeout_ms: u64,
    /// Maximum time a connection may sit **idle** (no inbound bytes) before the server reaps it, as a
    /// read deadline applied to the per-connection session (`04 §9`; rmp #118). `0` **disables** idle
    /// reaping (the default, so existing long-lived idle sessions are unaffected); any value `> 0`
    /// enables it. Applies to the Bolt sessions (UDS + TCP) via the read bridge; the REST listener's
    /// hyper stack manages its own connection lifetimes.
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

    /// The REST transaction inactivity timeout as a [`Duration`] (rmp #389). An open explicit
    /// transaction idle past this is rolled back by the server's inactivity sweep.
    #[must_use]
    pub fn transaction_idle_timeout(&self) -> Duration {
        Duration::from_millis(self.transaction_idle_timeout_ms)
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
    /// Buffer-pool capacity in pages (`04 §3`).
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
            buffer_pool_pages: 4096,
            bolt_tcp_addr: None,
            advertised_bolt_address: None,
            rest_addr: Some("127.0.0.1:7474".to_owned()),
            uds_path: Some(PathBuf::from("graphus.sock")),
            tls: TlsConfig::default(),
            admission: AdmissionConfig::default(),
            timing: TimingConfig::default(),
            jwt_secret: DEFAULT_INSECURE_JWT_SECRET.to_owned(),
            auth: AuthBootstrap::default(),
            encryption: EncryptionConfig::default(),
            audit: AuditConfig::default(),
            allow_insecure_network: false,
            metrics_scrape_token: None,
        }
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
        if self.buffer_pool_pages == 0 {
            return Err(ConfigError::Invalid(
                "buffer_pool_pages must be > 0".to_owned(),
            ));
        }
        if let Err(e) = crate::dbcatalog::normalize_db_name(&self.default_database) {
            return Err(ConfigError::Invalid(format!("default_database: {e}")));
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
}

/// Maps an empty string to `None` so `GRAPHUS_REST_ADDR=` explicitly *disables* a listener (rather
/// than binding to the empty address).
fn empty_to_none(v: String) -> Option<String> {
    if v.trim().is_empty() { None } else { Some(v) }
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
    fn connection_admission_defaults_and_validation() {
        // Sensible defaults (rmp #118).
        let cfg = AdmissionConfig::default();
        assert_eq!(cfg.max_connections, 1024);
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
            bolt_tcp_addr: None,
            ..ServerConfig::default()
        };
        assert_eq!(cfg.resolved_advertised_bolt_address(), None);
    }

    #[test]
    fn normalize_blanks_disable_advertised_bolt_address() {
        let mut cfg = ServerConfig {
            advertised_bolt_address: Some("   ".to_owned()),
            ..ServerConfig::default()
        };
        cfg.normalize();
        assert_eq!(cfg.advertised_bolt_address, None);
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
}
