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
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            max_concurrent_queries: 256,
            engine_queue_capacity: 1024,
            result_buffer_capacity: 256,
        }
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
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            slow_query_threshold_ms: 500,
            shutdown_drain_deadline_ms: 10_000,
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
}

/// One additional (non-admin) bootstrap user: a name and a password.
///
/// Bootstrap users are granted database **read + write** (but **not** admin), so a deployment can
/// ship an application identity that runs queries yet cannot drive the administrative surface
/// (`CREATE DATABASE …`, `/admin/*` — rmp #84). Deny-by-default RBAC means anything beyond
/// read/write must be granted explicitly afterwards.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct UserBootstrap {
    /// The username (must be non-empty and distinct from the admin user).
    pub name: String,
    /// The user's password (for Bolt `LOGON` / minting REST Bearer tokens). Empty disables
    /// password auth for this user.
    pub password: String,
}

/// The initial RBAC bootstrap: the admin user every fresh deployment needs so a server is usable
/// out of the box (`04 §8.4`), plus optional non-admin users. In production an operator manages
/// users via the admin API afterwards; this just seeds the initial identities.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
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
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
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
    /// Number of dedicated `fsync` threads in the durability offload pool (`04 §9.1`).
    pub fsync_threads: usize,

    /// TCP address for the Bolt-over-TCP listener, or `None` to disable it. TLS required when set.
    pub bolt_tcp_addr: Option<String>,
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

    /// **Escape hatch (default `false`):** allow a network listener (Bolt-TCP / REST) to run
    /// **without TLS**. Off by default so production is TLS-mandatory (`04 §8.4`); intended for
    /// loopback test harnesses and trusted-network/dev setups. The name is deliberately alarming so
    /// it is never set in production by accident.
    pub allow_insecure_network: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            store_path: PathBuf::from("graphus-data"),
            default_database: crate::dbcatalog::DEFAULT_DATABASE_NAME.to_owned(),
            buffer_pool_pages: 4096,
            fsync_threads: 2,
            bolt_tcp_addr: None,
            rest_addr: Some("127.0.0.1:7474".to_owned()),
            uds_path: Some(PathBuf::from("graphus.sock")),
            tls: TlsConfig::default(),
            admission: AdmissionConfig::default(),
            timing: TimingConfig::default(),
            jwt_secret: DEFAULT_INSECURE_JWT_SECRET.to_owned(),
            auth: AuthBootstrap::default(),
            encryption: EncryptionConfig::default(),
            allow_insecure_network: false,
        }
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
        if let Ok(v) = var("GRAPHUS_MAX_CONCURRENT_QUERIES") {
            self.admission.max_concurrent_queries = v.parse().map_err(|_| {
                ConfigError::Parse(format!(
                    "GRAPHUS_MAX_CONCURRENT_QUERIES is not a positive integer: {v:?}"
                ))
            })?;
        }
        if let Ok(v) = var("GRAPHUS_SLOW_QUERY_THRESHOLD_MS") {
            self.timing.slow_query_threshold_ms = v.parse().map_err(|_| {
                ConfigError::Parse(format!(
                    "GRAPHUS_SLOW_QUERY_THRESHOLD_MS is not an integer: {v:?}"
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

            [timing]
            slow_query_threshold_ms = 250
        "#;
        let cfg: ServerConfig = toml::from_str(toml).expect("parse");
        assert_eq!(cfg.store_path, PathBuf::from("/var/lib/graphus"));
        assert_eq!(cfg.buffer_pool_pages, 8192);
        assert_eq!(cfg.admission.max_concurrent_queries, 512);
        assert_eq!(cfg.timing.slow_query_threshold_ms, 250);
        assert!(cfg.tls.is_enabled());
        assert!(cfg.validate().is_ok());
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
