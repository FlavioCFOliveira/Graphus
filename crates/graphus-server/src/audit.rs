//! The **security audit log** (rmp #70, parent #69, decision `D-security-scope`): an append-only,
//! crash-safe, line-delimited-JSON record of every security-relevant event the server processes —
//! authentication outcomes, authorization denials, and administrative / schema / security / data
//! changes — across all three connection types (UDS-Bolt, TCP-Bolt, REST).
//!
//! ## Why audit logging is its own subsystem
//!
//! An auditor or a SIEM needs an **independent, tamper-evident, durable** trail of *who did what,
//! when, and whether it was allowed*, separate from the operational store. A compliance review (or a
//! breach investigation) reads the audit log, not the graph. So the log is:
//!
//! - **Append-only + line-delimited JSON (JSONL).** Each line is exactly one self-contained, compact
//!   JSON object followed by `\n`. One object per line is what makes a torn final line (from a crash
//!   mid-append) *detectable* — see [`AuditLog::open`].
//! - **Crash-safe — with a precisely-stated durability contract.** *Security-relevant* events
//!   (auth outcomes, authorization denials, and admin/schema/security changes) are `fsync`'d
//!   *before the recording call returns*, so the event is durable before the client learns the
//!   operation's outcome (when [`AuditConfig::fsync_security_events`] is on, the default).
//!   *Data-change* events ([`AuditClass::DataChange`]) are, by default, **batched** (left in the OS
//!   page cache, hardened on the next security event or on [`AuditLog::flush`]); they are durable
//!   *before the ack only* when [`AuditConfig::fsync_data_changes`] is enabled. With batching, a
//!   crash between the engine's commit and the next sync can lose the data-change *audit line* — the
//!   committed mutation itself is never lost, because **the graph WAL is the authoritative durable
//!   record of the write**; the audit line is a secondary, forensic trail. An operator who needs the
//!   audit line to be durable-before-ack for every audited write sets `fsync_data_changes = true`
//!   (at a throughput cost). On reopen a torn final line is detected and truncated, so the log never
//!   accumulates partial garbage (the recovery is the core of this module — [`AuditLog::open`]).
//! - **Non-dropping.** The write path is synchronous, serialized behind a [`std::sync::Mutex`]:
//!   there is no bounded queue to overflow, so there is structurally no *silent* drop. An I/O error
//!   (e.g. a full disk) is surfaced **loudly** via `tracing` and counted, but never panics and never
//!   silently swallows an event — we will not fail a client's authentication purely because the
//!   audit disk filled, yet the failure is loud and observable (see [`AuditLog::record`]).
//! - **Secret-free.** A password, credential or query literal is **never** written. The redaction
//!   rules live in [`redact_admin_detail`] (admin commands) and the seams' data-change category
//!   derivation; a unit test asserts a password never reaches the redacted output.
//!
//! ## On-wire shape
//!
//! Each line is an on-disk record: a monotonically increasing `seq`, an RFC 3339 UTC `ts`, and the
//! event fields (`class`, `outcome`, `source`, `actor`, `database`, `peer`, `detail`). The `seq`
//! counter is independent of the file — it continues monotonically across rotations and is recovered
//! on reopen as `max valid seq + 1` over **both the active file and the retained rotated files**, so
//! a restart (even one immediately following a rotation that left the active file empty) never
//! reuses or skips a number.
//!
//! ## Threading
//!
//! [`AuditLog`] is `Send + Sync` and shared as `Arc<AuditLog>`. It is **not** on the cypher engine
//! thread — it is reached from the synchronous connectivity seams (which run on blocking-thread
//! contexts), so a `std::sync::Mutex` is correct and is **never** held across an `.await` (every
//! caller is a synchronous seam method). When audit is disabled ([`AuditConfig::enabled`] is
//! `false`) the log is still constructed (so the `Arc<AuditLog>` threading stays uniform) but every
//! [`record`](AuditLog::record) is a cheap early return that writes nothing.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use serde::{Deserialize, Serialize, Serializer};

// ------------------------------------------------------------------------------------------------
// Event model
// ------------------------------------------------------------------------------------------------

/// The class of an audited event — the *category* an auditor filters on (rmp #70).
///
/// The on-disk (and `tracing`) tag is the stable, lowercase-with-underscores string from
/// [`AuditClass::as_str`]; that is what serializes on the wire and what a SIEM rule greps for. The
/// variant names are Rust-side conveniences only — the tags are the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditClass {
    /// A successful authentication (`LOGON` / Bearer validation).
    AuthSuccess,
    /// A failed authentication attempt.
    AuthFailure,
    /// An authorization check denied an operation (the principal lacked the privilege).
    AuthzDenied,
    /// An authorization check granted an operation (reserved for explicit allow-auditing; not
    /// emitted by default to keep volume down — denials are the security-relevant signal).
    AuthzGranted,
    /// An administrative change (database lifecycle: create/drop/start/stop database).
    AdminChange,
    /// A schema change (index DDL).
    SchemaChange,
    /// A security-model change (users, roles, grants/revokes).
    SecurityChange,
    /// A data change (a write query), audited only when [`AuditConfig::audit_data_changes`] is on.
    DataChange,
}

impl AuditClass {
    /// The stable on-wire tag (`"auth_success"`, `"authz_denied"`, `"security_change"`, …).
    ///
    /// This string is the contract: it is what serializes onto the JSON line, what `tracing`
    /// records, and what audit tooling matches. It must never change for an existing class.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AuthSuccess => "auth_success",
            Self::AuthFailure => "auth_failure",
            Self::AuthzDenied => "authz_denied",
            Self::AuthzGranted => "authz_granted",
            Self::AdminChange => "admin_change",
            Self::SchemaChange => "schema_change",
            Self::SecurityChange => "security_change",
            Self::DataChange => "data_change",
        }
    }

    /// Whether this class is **security-relevant** and therefore `fsync`'d before the call returns
    /// (auth outcomes, authorization denials, and admin/schema/security changes). Data changes are
    /// batch-synced (durable on the next security event or on [`AuditLog::flush`]) for volume.
    #[must_use]
    fn is_security_relevant(&self) -> bool {
        match self {
            Self::AuthSuccess
            | Self::AuthFailure
            | Self::AuthzDenied
            | Self::AuthzGranted
            | Self::AdminChange
            | Self::SchemaChange
            | Self::SecurityChange => true,
            Self::DataChange => false,
        }
    }
}

impl Serialize for AuditClass {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Which connection a [`AuditEvent`] arrived on (rmp #70) — so an auditor can tell a local UDS
/// action from a networked one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditSource {
    /// A Bolt connection over a Unix domain socket (local, peer-cred gated).
    BoltUds,
    /// A Bolt connection over TCP (TLS-wrapped, networked).
    BoltTcp,
    /// A REST request (TLS-wrapped, networked).
    Rest,
    /// A server-internal action (reserved; e.g. a future background task).
    Internal,
}

impl AuditSource {
    /// The stable on-wire tag (`"bolt_uds"`, `"bolt_tcp"`, `"rest"`, `"internal"`).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BoltUds => "bolt_uds",
            Self::BoltTcp => "bolt_tcp",
            Self::Rest => "rest",
            Self::Internal => "internal",
        }
    }
}

impl Serialize for AuditSource {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Whether an audited operation succeeded or failed (rmp #70).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    /// The operation completed successfully.
    Success,
    /// The operation failed (a rejected auth, a denied authorization, a failed mutation).
    Failure,
}

impl AuditOutcome {
    /// The stable on-wire tag (`"success"` / `"failure"`).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

impl Serialize for AuditOutcome {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// An in-memory audit event, **before** the log assigns its sequence number and timestamp.
///
/// Build one with [`AuditEvent::new`] and the chainable setters, then hand it to
/// [`AuditLog::record`]. The [`detail`](Self::detail) field is a SHORT, **already-redacted** human
/// description (e.g. `"LOGON basic"`, `"CREATE USER carol"`, `"write query (CREATE)"`); it MUST
/// never contain a secret (see the module-level redaction note and [`redact_admin_detail`]).
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// The event class (also drives the `fsync` policy — a security-relevant class is synced before
    /// the recording call returns).
    pub class: AuditClass,
    /// Whether the operation succeeded or failed.
    pub outcome: AuditOutcome,
    /// Which connection the event arrived on.
    pub source: AuditSource,
    /// The acting principal's name, if known (`None` is a real JSON `null` on the line; a human
    /// mirror renders it as `"anonymous"`). Never a credential — only the username.
    pub actor: Option<String>,
    /// The target database, if known/applicable.
    pub database: Option<String>,
    /// Peer information where cheaply available (e.g. a UDS `uid=NNN` or a TCP peer address);
    /// `None` otherwise.
    pub peer: Option<String>,
    /// A short, already-redacted human description of the event. NEVER contains a secret.
    pub detail: String,
}

impl AuditEvent {
    /// A fresh event of `class`/`outcome`/`source` with all optional fields unset and an empty
    /// `detail`. Fill in the rest with the chainable setters.
    #[must_use]
    pub fn new(class: AuditClass, outcome: AuditOutcome, source: AuditSource) -> Self {
        Self {
            class,
            outcome,
            source,
            actor: None,
            database: None,
            peer: None,
            detail: String::new(),
        }
    }

    /// Sets the acting principal (the username; never a credential).
    #[must_use]
    pub fn actor(mut self, actor: Option<&str>) -> Self {
        self.actor = actor.map(str::to_owned);
        self
    }

    /// Sets the target database.
    #[must_use]
    pub fn database(mut self, database: Option<&str>) -> Self {
        self.database = database.map(str::to_owned);
        self
    }

    /// Sets the peer descriptor (e.g. `"uid=1000"`).
    #[must_use]
    pub fn peer(mut self, peer: Option<String>) -> Self {
        self.peer = peer;
        self
    }

    /// Sets the short, already-redacted human `detail`.
    #[must_use]
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }
}

/// The on-disk record: an [`AuditEvent`] stamped with its assigned `seq` and `ts`.
///
/// The field order is stable (`seq`, `ts`, `class`, `outcome`, `source`, `actor`, `database`,
/// `peer`, `detail`) so the JSONL is predictable for eyeballing and `grep`/`jq`. It borrows the
/// event so [`AuditLog::record`] serializes without an extra clone.
#[derive(Debug, Serialize)]
struct AuditRecord<'a> {
    /// The monotonic sequence number (1-based; continues across rotations and restarts).
    seq: u64,
    /// The event timestamp in RFC 3339 UTC, millisecond precision (`YYYY-MM-DDTHH:MM:SS.mmmZ`).
    ts: String,
    /// The event class.
    class: AuditClass,
    /// The operation outcome.
    outcome: AuditOutcome,
    /// The connection the event arrived on.
    source: AuditSource,
    /// The acting principal (real JSON `null` when absent).
    actor: &'a Option<String>,
    /// The target database (real JSON `null` when absent).
    database: &'a Option<String>,
    /// Peer information (real JSON `null` when absent).
    peer: &'a Option<String>,
    /// The redacted human description.
    detail: &'a str,
}

// ------------------------------------------------------------------------------------------------
// Configuration
// ------------------------------------------------------------------------------------------------

/// The default size threshold (64 MiB) at which the active audit file rotates.
const DEFAULT_ROTATE_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// The default number of rotated files to retain (`audit.log.1` … `audit.log.5`).
const DEFAULT_RETAIN_FILES: u32 = 5;
/// The default audit log file name within the store directory.
const AUDIT_FILE_NAME: &str = "audit.log";

/// Audit-logging configuration (rmp #70). A sub-struct of
/// [`ServerConfig`](crate::config::ServerConfig); audit is **opt-in** (off by default) so the hot
/// path is a cheap early return for deployments that do not enable it.
///
/// Security-critical deployments MUST enable it ([`enabled`](Self::enabled) = `true`); the durable,
/// `fsync`'d trail is then the compliance / forensic record.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    /// Whether audit logging is enabled. **Default `false`** (opt-in). When off, nothing is written
    /// and [`AuditLog::record`] is a cheap early return. Security-critical deployments enable it.
    pub enabled: bool,
    /// The audit log file path. When `None` (and enabled), it defaults to `<store_path>/audit.log`
    /// (resolved by [`AuditLog::open`]; this field stores only the operator's explicit override).
    pub path: Option<PathBuf>,
    /// Whether security-relevant events (auth, authz-denied, admin/schema/security changes) are
    /// `fsync`'d **before the call returns** (so the event is durable before the client learns the
    /// outcome). **Default `true`.** Data-change events are batch-synced regardless.
    pub fsync_security_events: bool,
    /// Whether `DataChange` events (write queries) are audited. **Default `false`** — data-change
    /// volume can be very high, and the security-relevant signal is the auth/authz/admin trail; an
    /// operator opts into data auditing explicitly when the deployment requires it.
    pub audit_data_changes: bool,
    /// Whether `DataChange` events are `fsync`'d **before the recording call returns** (like a
    /// security event), rather than batched. **Default `false`** to preserve write throughput.
    ///
    /// With the default (`false`) a data-change audit line is left in the OS page cache and hardened
    /// only on the next security event or on [`AuditLog::flush`]; a crash in that window can lose the
    /// audit *line* (never the committed write — the graph WAL is authoritative). Set this to `true`
    /// when the deployment requires every audited write's record to be durable before its ack, at a
    /// per-write `fsync` cost. Has no effect unless [`audit_data_changes`](Self::audit_data_changes)
    /// is also on (a data-change event that is not recorded cannot be synced).
    pub fsync_data_changes: bool,
    /// The active file rotates when an append would take it to/over this many bytes. **Default 64
    /// MiB.** `0` disables size-based rotation (a single growing file).
    pub rotate_max_bytes: u64,
    /// How many rotated files to retain (`audit.log.1` … `audit.log.N`). **Default 5.** Must be
    /// `>= 1` when rotation is enabled (`rotate_max_bytes > 0`); validated by [`Self::validate`].
    pub retain_files: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: None,
            fsync_security_events: true,
            audit_data_changes: false,
            fsync_data_changes: false,
            rotate_max_bytes: DEFAULT_ROTATE_MAX_BYTES,
            retain_files: DEFAULT_RETAIN_FILES,
        }
    }
}

impl AuditConfig {
    /// Validates the audit configuration, returning a clear message on the first problem.
    ///
    /// Rejects: an enabled audit with an explicitly **empty** path (`Some("")` — a likely typo that
    /// would otherwise resolve to an unintended location); and `rotate_max_bytes > 0` with
    /// `retain_files == 0` (rotation enabled but nothing retained, which would discard every rotated
    /// file).
    ///
    /// # Errors
    /// A human-readable message describing the first failed invariant.
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled {
            if let Some(path) = &self.path {
                if path.as_os_str().is_empty() {
                    return Err(
                        "audit.path is set to an empty string; unset it to default to \
                         <store_path>/audit.log, or give a real path"
                            .to_owned(),
                    );
                }
            }
        }
        if self.rotate_max_bytes > 0 && self.retain_files == 0 {
            return Err(
                "audit.retain_files must be >= 1 when audit.rotate_max_bytes > 0 (rotation is \
                 enabled but no rotated files would be kept)"
                    .to_owned(),
            );
        }
        Ok(())
    }
}

// ------------------------------------------------------------------------------------------------
// The sink
// ------------------------------------------------------------------------------------------------

/// The mutable interior of an [`AuditLog`], serialized behind a [`std::sync::Mutex`].
struct Inner {
    /// The active append handle (opened with `create(true).append(true)`).
    file: std::fs::File,
    /// The active file's path (the rotation target; `<dir>/audit.log`).
    path: PathBuf,
    /// The active file's current size in bytes (kept in sync so rotation is a cheap comparison, no
    /// `metadata` syscall per append).
    bytes: u64,
    /// Whether a `DataChange` event has been written but not yet `fsync`'d (drives the batched sync
    /// on the next security event and on [`AuditLog::flush`]).
    pending_unsynced: bool,
}

/// The append-only, crash-safe, rotating JSONL audit sink + the in-memory sequence counter
/// (rmp #70). Shared as `Arc<AuditLog>`; `Send + Sync`.
///
/// See the module docs for the design (append-only JSONL, torn-tail repair on reopen, the
/// non-dropping synchronous write model, the `fsync`-on-security-event policy, and rotation).
pub struct AuditLog {
    /// Whether audit is enabled. When `false`, [`record`](Self::record) returns immediately and the
    /// file is never touched (so a disabled log provably writes nothing).
    enabled: bool,
    /// The mutable file state behind the serialization lock.
    inner: Mutex<Inner>,
    /// The next sequence number to assign minus one (so `fetch_add(1) + 1` yields it). Recovered on
    /// open as `max valid seq seen`; continues monotonically across rotations + restarts.
    seq: AtomicU64,
    /// A count of write/fsync I/O errors (the loud, non-dropping failure signal — see
    /// [`Self::record`]). Surfaced for tests + future metrics.
    write_errors: AtomicU64,
    /// `rotate_max_bytes`: rotate when an append would reach/exceed it (`0` disables rotation).
    rotate_max_bytes: u64,
    /// `retain_files`: how many rotated files to keep.
    retain_files: u32,
    /// `fsync_security_events`: whether security-relevant events are synced before returning.
    fsync_security_events: bool,
    /// `audit_data_changes`: whether `DataChange` events are recorded (the seams consult this so a
    /// disabled data-change category never even builds the event).
    audit_data_changes: bool,
    /// `fsync_data_changes`: whether `DataChange` events are `fsync`'d before returning (durable
    /// before the audited op's ack) rather than batched. See [`AuditConfig::fsync_data_changes`].
    fsync_data_changes: bool,
}

impl AuditLog {
    /// Opens (or creates) the audit log under `store_path`, recovering the sequence counter and
    /// repairing a torn final line, and returns it as a shared `Arc<AuditLog>`.
    ///
    /// The path is `config.path` if set, else `<store_path>/audit.log`; parent directories are
    /// created. When `config.enabled` is `false`, the returned log is a no-op (it carries the
    /// `enabled = false` flag and never opens/touches the file) — the threading stays uniform
    /// (`Arc<AuditLog>` everywhere, never `Option`).
    ///
    /// ## Crash-safety recovery (the core mechanism)
    ///
    /// Before appending, `open` scans the existing file to:
    ///
    /// 1. **Recover `seq`.** It splits the content on `\n` and reads the `seq` of every line that
    ///    parses as JSON carrying a `seq`. A trailing partial line (bytes after the last `\n` with
    ///    no terminating newline, or a final line that fails to parse) is a TORN line from a crash
    ///    mid-append — it is **not** counted. The next `seq` is `max valid seq + 1`, or `1` for a
    ///    new/empty file. The max is taken over the active file **and** the retained rotated files
    ///    ([`max_rotated_seq`]) so a rotation that just emptied the active file cannot make a restart
    ///    reuse a number already in `audit.log.1` (#425).
    /// 2. **Repair a torn tail.** If the file does **not** end with `\n`, the last write was torn
    ///    mid-append; `open` truncates the file back to the offset just past the last complete line
    ///    (the last `\n`, or `0` if there is none) with `set_len`, discarding the torn bytes. The
    ///    next append therefore starts cleanly on a fresh line and the log never accumulates partial
    ///    garbage. This is the durability guarantee that makes a `fsync`'d security event meaningful
    ///    across a crash.
    ///
    /// # Errors
    /// [`std::io::Error`] if the parent directory cannot be created or the file cannot be opened /
    /// scanned / truncated.
    pub fn open(config: &AuditConfig, store_path: &Path) -> std::io::Result<std::sync::Arc<Self>> {
        use std::sync::Arc;

        // Resolve the knobs regardless of enabled so a re-enable keeps the same shape.
        let rotate_max_bytes = config.rotate_max_bytes;
        let retain_files = config.retain_files;
        let fsync_security_events = config.fsync_security_events;
        let audit_data_changes = config.audit_data_changes;
        let fsync_data_changes = config.fsync_data_changes;

        if !config.enabled {
            // A disabled log never opens the audit file and never writes: every `record` call
            // short-circuits on the `enabled` flag before touching `Inner`. The struct still needs an
            // `Inner` with *some* file handle, so we back it with the OS null device (present on every
            // supported platform — all are Unix per `CLAUDE.md`). That handle is inert: no write ever
            // reaches it. This keeps the `Arc<AuditLog>` threading uniform (no `Option`) regardless of
            // whether audit is on, so the hot path is a single bool check.
            let null = std::fs::OpenOptions::new()
                .write(true)
                .open(null_device())
                .or_else(|_| {
                    // Fallback: if the null device is unavailable, a disabled log still must not
                    // fail startup — create a throwaway under the system temp dir that we never use.
                    let mut p = std::env::temp_dir();
                    p.push(format!(
                        "graphus-audit-disabled-{}.sink",
                        std::process::id()
                    ));
                    std::fs::OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(p)
                })?;
            return Ok(Arc::new(Self {
                enabled: false,
                inner: Mutex::new(Inner {
                    file: null,
                    path: PathBuf::new(),
                    bytes: 0,
                    pending_unsynced: false,
                }),
                seq: AtomicU64::new(0),
                write_errors: AtomicU64::new(0),
                rotate_max_bytes,
                retain_files,
                fsync_security_events,
                audit_data_changes,
                fsync_data_changes,
            }));
        }

        let path = resolve_path(config, store_path);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        // Scan the existing content (if any) to recover the next seq and the offset of the last
        // complete line, then repair a torn tail before opening the append handle.
        //
        // #425: the next seq must be the max over the ACTIVE file AND the rotated files. A rotation
        // followed immediately by a restart (before any line lands in the fresh `audit.log`) leaves
        // the active file empty, so its max seq is 0 — but the highest-numbered seq lives in
        // `audit.log.1`. Recovering only from the active file would reuse seq numbers already
        // present in a rotated file, breaking the monotonic never-reuse guarantee. We therefore take
        // the overall max across the active file and the retained rotated files.
        let (active_seq, complete_len, total_len) = scan_existing(&path)?;
        let next_seq_base = active_seq.max(max_rotated_seq(&path, retain_files));
        if total_len > complete_len {
            // The file did not end on a complete line: truncate the torn tail away.
            let f = std::fs::OpenOptions::new().write(true).open(&path)?;
            f.set_len(complete_len)?;
            f.sync_all()?;
        }

        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let bytes = complete_len;

        Ok(Arc::new(Self {
            enabled: true,
            inner: Mutex::new(Inner {
                file,
                path,
                bytes,
                pending_unsynced: false,
            }),
            seq: AtomicU64::new(next_seq_base),
            write_errors: AtomicU64::new(0),
            rotate_max_bytes,
            retain_files,
            fsync_security_events,
            audit_data_changes,
            fsync_data_changes,
        }))
    }

    /// Whether audit is enabled (so callers can skip building an event when nothing would be logged).
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Whether `DataChange` events should be recorded (audit enabled AND `audit_data_changes` on).
    /// The seams consult this before building a data-change event, so the disabled-by-default case
    /// costs nothing on the hot path.
    #[must_use]
    pub fn data_changes_enabled(&self) -> bool {
        self.enabled && self.audit_data_changes
    }

    /// The count of write/fsync I/O errors observed so far (the loud, non-dropping failure signal).
    #[must_use]
    pub fn write_errors(&self) -> u64 {
        self.write_errors.load(Ordering::Relaxed)
    }

    /// Records one audit event — **the single entry point** (rmp #70).
    ///
    /// The model is *synchronous and non-dropping*: there is no queue to overflow, so a security
    /// event is never silently dropped. Steps:
    ///
    /// 1. If disabled, return immediately (nothing written).
    /// 2. Assign the next `seq` and build the RFC 3339 UTC `ts`.
    /// 3. Serialize the on-disk record to a **compact** JSON line (`serde_json` produces no embedded
    ///    newlines) and append `\n`, so the line stays exactly one JSON object.
    /// 4. Under the mutex: rotate first if the append would cross `rotate_max_bytes`, then
    ///    `write_all` the line and update the byte counter.
    /// 5. `fsync` policy: a security-relevant class (auth / authz-denied / admin / schema / security)
    ///    is `sync_data`'d **before returning** (when `fsync_security_events` is on), so the event is
    ///    durable before the client learns the operation's result. A `DataChange` is, by default,
    ///    left unsynced (batched; flushed by the next security event or [`flush`](Self::flush)) — but
    ///    is `sync_data`'d before returning when [`AuditConfig::fsync_data_changes`] is enabled, so
    ///    the data-change line is durable before the audited write's ack at a per-write `fsync` cost.
    ///
    /// Every event is **also** mirrored to `tracing` (`target: "graphus::audit"`) at `info` (normal)
    /// or `warn` (failure / denial), so an operator shipping logs to a SIEM receives the trail even
    /// without the file.
    ///
    /// On an I/O error the event is **not** dropped silently: it is logged loudly via
    /// `tracing::error!` and counted in [`write_errors`](Self::write_errors); the call still returns
    /// (we will not fail a client's authentication purely because the audit disk is full — but the
    /// failure is loud and observable). This trade-off is deliberate (module docs).
    pub fn record(&self, event: AuditEvent) {
        if !self.enabled {
            return;
        }

        // Assign the sequence number (monotonic, 1-based) and timestamp first, outside the file
        // lock — they do not touch the file and the atomic is the only ordering concern.
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let ts = rfc3339_utc(SystemTime::now());

        // Mirror to tracing unconditionally, so the trail reaches a SIEM even if the file write
        // fails below. Failures/denials are warnings; everything else is info.
        self.mirror_to_tracing(seq, &ts, &event);

        let record = AuditRecord {
            seq,
            ts,
            class: event.class,
            outcome: event.outcome,
            source: event.source,
            actor: &event.actor,
            database: &event.database,
            peer: &event.peer,
            detail: &event.detail,
        };

        // Compact JSON (no embedded newlines) + a single trailing newline = one JSONL line.
        let mut line = match serde_json::to_string(&record) {
            Ok(s) => s,
            Err(e) => {
                // Serialization cannot realistically fail for these plain types; if it ever does,
                // surface it loudly and count it rather than dropping silently.
                self.write_errors.fetch_add(1, Ordering::Relaxed);
                tracing::error!(target: "graphus::audit", seq, error = %e, "failed to serialize audit record");
                return;
            }
        };
        debug_assert!(
            !line.contains('\n'),
            "compact serde_json must not embed newlines"
        );
        line.push('\n');

        let security_relevant = event.class.is_security_relevant();
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Rotation check FIRST (before the write), so the threshold bounds the active file.
        let line_len = line.len() as u64;
        if self.rotate_max_bytes > 0
            && guard.bytes > 0
            && guard.bytes + line_len > self.rotate_max_bytes
        {
            if let Err(e) = rotate(&mut guard, self.retain_files) {
                self.write_errors.fetch_add(1, Ordering::Relaxed);
                tracing::error!(target: "graphus::audit", seq, error = %e, "audit log rotation failed");
                // Continue: a failed rotation must not drop the event; we still attempt the write to
                // the (un-rotated) active file below.
            }
        }

        if let Err(e) = write_line(&mut guard, line.as_bytes()) {
            self.write_errors.fetch_add(1, Ordering::Relaxed);
            tracing::error!(target: "graphus::audit", seq, error = %e, "failed to write audit record (event NOT dropped: also mirrored to tracing)");
            return;
        }
        guard.bytes += line_len;

        if security_relevant {
            if self.fsync_security_events {
                if let Err(e) = guard.file.sync_data() {
                    self.write_errors.fetch_add(1, Ordering::Relaxed);
                    tracing::error!(target: "graphus::audit", seq, error = %e, "failed to fsync security audit record");
                } else {
                    guard.pending_unsynced = false;
                }
            }
            // If fsync is off, this security event is left in the OS page cache like a data change.
        } else if self.fsync_data_changes {
            // Opt-in: harden the data-change line before returning, so it is durable before the
            // audited write's ack (the WAL is authoritative for the write itself; this makes the
            // audit *line* durable-before-ack too). Same loud-not-dropping error policy as above.
            if let Err(e) = guard.file.sync_data() {
                self.write_errors.fetch_add(1, Ordering::Relaxed);
                tracing::error!(target: "graphus::audit", seq, error = %e, "failed to fsync data-change audit record");
            } else {
                guard.pending_unsynced = false;
            }
        } else {
            // A DataChange: batched. Mark dirty so the next security event / flush hardens it.
            guard.pending_unsynced = true;
        }
    }

    /// Flushes any batched (unsynced) data-change events to disk (`sync_data`). Best-effort: an
    /// error is logged + counted, never panics. Called on graceful shutdown so the last batch of
    /// `DataChange` events is durable before exit (rmp #70).
    ///
    /// # Errors
    /// [`std::io::Error`] if the final sync fails (the caller logs it; shutdown proceeds).
    pub fn flush(&self) -> std::io::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.pending_unsynced {
            guard.file.sync_data()?;
            guard.pending_unsynced = false;
        }
        Ok(())
    }

    /// Mirrors an event to `tracing` (`target: "graphus::audit"`): `warn` for a failure/denial,
    /// `info` otherwise. This is the SIEM-friendly stream that exists even without the file.
    fn mirror_to_tracing(&self, seq: u64, ts: &str, event: &AuditEvent) {
        let class = event.class.as_str();
        let outcome = event.outcome.as_str();
        let source = event.source.as_str();
        let actor = event.actor.as_deref().unwrap_or("anonymous");
        let database = event.database.as_deref().unwrap_or("-");
        let detail = event.detail.as_str();
        let warn = matches!(event.outcome, AuditOutcome::Failure)
            || matches!(event.class, AuditClass::AuthzDenied);
        if warn {
            tracing::warn!(target: "graphus::audit", seq, ts, class, outcome, source, actor, database, detail, "audit");
        } else {
            tracing::info!(target: "graphus::audit", seq, ts, class, outcome, source, actor, database, detail, "audit");
        }
    }
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog")
            .field("enabled", &self.enabled)
            .field("seq", &self.seq.load(Ordering::Relaxed))
            .field("write_errors", &self.write_errors.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// Writes a full line to the active file (the seam over `Write::write_all`, kept tiny so the lock
/// section in [`AuditLog::record`] stays auditable).
fn write_line(inner: &mut Inner, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    inner.file.write_all(bytes)
}

/// Rotates the active audit file (rmp #70): shifts `audit.log.{N-1}` → `audit.log.{N}` for `N` from
/// `retain` down to `1` (dropping the oldest beyond `retain`), renames the live `audit.log` →
/// `audit.log.1`, then opens a fresh empty `audit.log`, resets the byte counter, and `fsync`s the
/// parent directory so the renames are durable.
///
/// Sequence numbers are independent of the file, so they continue monotonically across a rotation.
///
/// # Errors
/// [`std::io::Error`] on a rename / open / directory-sync failure.
fn rotate(inner: &mut Inner, retain: u32) -> std::io::Result<()> {
    let base = &inner.path;
    let dir = base.parent().unwrap_or_else(|| Path::new("."));
    let file_name = base.file_name().map_or_else(
        || std::ffi::OsString::from(AUDIT_FILE_NAME),
        |n| n.to_os_string(),
    );

    // Shift the existing rotated files up by one, dropping the oldest beyond `retain`.
    // audit.log.{retain-1} -> audit.log.{retain}, …, audit.log.1 -> audit.log.2.
    for n in (1..retain).rev() {
        let from = numbered(dir, &file_name, n);
        let to = numbered(dir, &file_name, n + 1);
        if from.exists() {
            std::fs::rename(&from, &to)?;
        }
    }
    // Live file -> audit.log.1.
    if base.exists() {
        let first = numbered(dir, &file_name, 1);
        std::fs::rename(base, &first)?;
    }

    // Open a fresh, empty active file.
    let fresh = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .truncate(false)
        .open(base)?;
    inner.file = fresh;
    inner.bytes = 0;
    inner.pending_unsynced = false;

    // Harden the renames by syncing the directory entry (best-effort on platforms that allow it).
    if let Ok(dir_handle) = std::fs::File::open(dir) {
        let _ = dir_handle.sync_all();
    }
    Ok(())
}

/// Builds the path of the `n`-th rotated file: `<dir>/<file_name>.<n>` (e.g. `audit.log.1`).
fn numbered(dir: &Path, file_name: &std::ffi::OsStr, n: u32) -> PathBuf {
    let mut name = file_name.to_os_string();
    name.push(format!(".{n}"));
    dir.join(name)
}

/// Resolves the active audit log path: the configured override if set, else `<store_path>/audit.log`.
fn resolve_path(config: &AuditConfig, store_path: &Path) -> PathBuf {
    match &config.path {
        Some(p) if !p.as_os_str().is_empty() => p.clone(),
        _ => store_path.join(AUDIT_FILE_NAME),
    }
}

/// Scans an existing audit file, returning `(next_seq_base, complete_len, total_len)`:
///
/// - `next_seq_base` — the maximum valid `seq` found (so `record` assigns `+ 1`), or `0` for an
///   empty/new file.
/// - `complete_len` — the byte offset just past the last `\n` (the end of the last *complete* line;
///   `0` if there is no newline).
/// - `total_len` — the file's total length, so the caller can detect a torn tail
///   (`total_len > complete_len`).
///
/// A trailing partial line (no terminating `\n`) or a final line that fails to parse as JSON / lacks
/// a `seq` is treated as a torn write and excluded from `next_seq_base`.
///
/// # Errors
/// [`std::io::Error`] if the file exists but cannot be read.
fn scan_existing(path: &Path) -> std::io::Result<(u64, u64, u64)> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0, 0)),
        Err(e) => return Err(e),
    };
    let total_len = bytes.len() as u64;

    // The end of the last complete line is the offset just past the final newline (0 if none).
    let complete_len = match bytes.iter().rposition(|&b| b == b'\n') {
        Some(pos) => (pos + 1) as u64,
        None => 0,
    };

    // Recover the max seq from the complete lines only (everything up to `complete_len`). A line
    // that does not parse / lacks a numeric `seq` is ignored (defensive; a clean writer never emits
    // one before `complete_len`).
    let mut max_seq = 0u64;
    let complete = &bytes[..complete_len as usize];
    for line in complete.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(line) {
            if let Some(seq) = value.get("seq").and_then(serde_json::Value::as_u64) {
                max_seq = max_seq.max(seq);
            }
        }
    }
    Ok((max_seq, complete_len, total_len))
}

/// Scans the rotated files (`<active>.1` … `<active>.N`, where `N` is `retain` capped to a small
/// bound) and returns the maximum valid `seq` found across them, or `0` if none exist (#425).
///
/// On reopen the next seq is `max(active-file max, this) + 1`, so a rotation immediately followed by
/// a restart — which leaves the fresh active file empty while the highest seq sits in `audit.log.1`
/// — never reuses a number. Each rotated file is scanned with the same complete-line logic as the
/// active file ([`scan_existing`]); a missing rotated file contributes `0`. We scan at most
/// [`MAX_ROTATED_SCAN`] files: the seq is monotonic across rotations, so the newest rotated file
/// (`.1`) always holds the largest seq, but we scan a few for robustness against an out-of-order or
/// partially-written rotation (e.g. a crash mid-`rotate`). `retain == 0` (rotation disabled) scans
/// nothing.
fn max_rotated_seq(active_path: &Path, retain: u32) -> u64 {
    /// How many of the newest rotated files to scan. The newest (`.1`) carries the largest seq;
    /// scanning a handful guards against a torn/out-of-order rotation without reading every file.
    const MAX_ROTATED_SCAN: u32 = 4;

    if retain == 0 {
        return 0;
    }
    let dir = active_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = active_path.file_name().map_or_else(
        || std::ffi::OsString::from(AUDIT_FILE_NAME),
        |n| n.to_os_string(),
    );
    let scan_count = retain.min(MAX_ROTATED_SCAN);
    let mut max_seq = 0u64;
    for n in 1..=scan_count {
        let rotated = numbered(dir, &file_name, n);
        // A missing/unreadable rotated file contributes nothing; we must not fail open over it
        // (the active-file scan is the primary recovery, and reuse-avoidance is best-effort-max).
        if let Ok((seq, _, _)) = scan_existing(&rotated) {
            max_seq = max_seq.max(seq);
        }
    }
    max_seq
}

/// The OS null device path for the disabled-log inert handle (`/dev/null` on Unix).
fn null_device() -> &'static str {
    // Graphus targets Linux/macOS/Raspberry Pi OS (CLAUDE.md), all Unix.
    "/dev/null"
}

// ------------------------------------------------------------------------------------------------
// RFC 3339 UTC timestamp (no external time dependency)
// ------------------------------------------------------------------------------------------------

/// Formats `t` as an RFC 3339 UTC timestamp with millisecond precision
/// (`YYYY-MM-DDTHH:MM:SS.mmmZ`), using only `std` — the workspace deliberately avoids a time crate
/// for this one string.
///
/// The civil-date conversion is Howard Hinnant's well-known `civil_from_days` algorithm.
///
/// reference: Howard Hinnant, "chrono-Compatible Low-Level Date Algorithms"
/// (<https://howardhinnant.github.io/date_algorithms.html>) — `civil_from_days`, valid for the full
/// proleptic Gregorian calendar. A pre-epoch instant (clock set before 1970) is clamped to the
/// epoch rather than producing a negative timestamp.
#[must_use]
pub fn rfc3339_utc(t: SystemTime) -> String {
    let dur = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default(); // pre-epoch ⇒ clamp to 1970-01-01T00:00:00.000Z
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();

    let days = (secs / 86_400) as i64;
    let secs_of_day = secs % 86_400;
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;

    let (year, month, day) = civil_from_days(days);

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Converts a day count since the Unix epoch (1970-01-01) to a civil `(year, month, day)`.
///
/// reference: Howard Hinnant, `civil_from_days`
/// (<https://howardhinnant.github.io/date_algorithms.html>). The era arithmetic treats the calendar
/// as starting in March so leap days fall at the end of the era, making the month/day extraction
/// branch-free.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    // Shift the epoch from 1970-01-01 to 0000-03-01 (the algorithm's reference point).
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

// ------------------------------------------------------------------------------------------------
// Redaction
// ------------------------------------------------------------------------------------------------

/// Classifies an [`AdminCommand`](crate::admin::AdminCommand) into its audit class (rmp #70):
/// user/role/grant/revoke commands are a [`AuditClass::SecurityChange`]; database lifecycle commands
/// are an [`AuditClass::AdminChange`]. The read-only `SHOW *` commands are not mutations and never
/// emit a change event (the seam audits only their authz-denial path), so they map to `AdminChange`
/// here purely as a default — [`is_mutating_admin`] gates whether a change event is emitted at all.
#[must_use]
pub fn classify_admin(cmd: &crate::admin::AdminCommand) -> AuditClass {
    use crate::admin::AdminCommand as A;
    match cmd {
        A::CreateUser { .. }
        | A::DropUser { .. }
        | A::CreateRole { .. }
        | A::DropRole { .. }
        | A::GrantRole { .. }
        | A::RevokeRole { .. }
        | A::GrantPrivilege { .. }
        | A::RevokePrivilege { .. }
        | A::ShowUsers
        | A::ShowRoles
        | A::ShowPrivileges => AuditClass::SecurityChange,
        A::CreateDatabase { .. }
        | A::DropDatabase { .. }
        | A::StartDatabase { .. }
        | A::StopDatabase { .. }
        | A::ShowDatabases
        | A::ShowDatabase { .. }
        | A::BackupDatabase { .. }
        | A::RestoreDatabase { .. }
        | A::CheckpointDatabase { .. } => AuditClass::AdminChange,
    }
}

/// Whether an [`AdminCommand`](crate::admin::AdminCommand) **mutates** state (so a change event is
/// worth auditing). The read-only `SHOW *` commands return `false` — only their authorization-denial
/// path is audited, never a (non-existent) change.
#[must_use]
pub fn is_mutating_admin(cmd: &crate::admin::AdminCommand) -> bool {
    use crate::admin::AdminCommand as A;
    matches!(
        cmd,
        A::CreateDatabase { .. }
            | A::DropDatabase { .. }
            | A::StartDatabase { .. }
            | A::StopDatabase { .. }
            | A::CreateUser { .. }
            | A::DropUser { .. }
            | A::CreateRole { .. }
            | A::DropRole { .. }
            | A::GrantRole { .. }
            | A::RevokeRole { .. }
            | A::GrantPrivilege { .. }
            | A::RevokePrivilege { .. }
            | A::BackupDatabase { .. }
            | A::RestoreDatabase { .. }
            | A::CheckpointDatabase { .. }
    )
}

/// The target database an [`AdminCommand`](crate::admin::AdminCommand) acts on, for the audit
/// `database` field, where one applies (the database-lifecycle commands). Security commands are
/// server-wide (no single database), so they return `None`.
#[must_use]
pub fn admin_target_database(cmd: &crate::admin::AdminCommand) -> Option<String> {
    use crate::admin::AdminCommand as A;
    match cmd {
        A::CreateDatabase { name, .. }
        | A::DropDatabase { name, .. }
        | A::StartDatabase { name }
        | A::StopDatabase { name }
        | A::ShowDatabase { name }
        | A::BackupDatabase { name, .. }
        | A::RestoreDatabase { name, .. }
        | A::CheckpointDatabase { name } => Some(name.clone()),
        _ => None,
    }
}

/// Produces the audited `detail` for an [`AdminCommand`](crate::admin::AdminCommand) — a concise,
/// **secret-free** description (rmp #70). A password is **never** included: a
/// [`CreateUser`](crate::admin::AdminCommand::CreateUser) with a password renders as
/// `"CREATE USER <name> SET PASSWORD <redacted>"`, never the value. GRANT/REVOKE include the
/// action + scope + role/user (none of which is a secret). This is the only place an admin command's
/// description is built for the log, so the redaction is centralized and testable.
#[must_use]
pub fn redact_admin_detail(cmd: &crate::admin::AdminCommand) -> String {
    use crate::admin::AdminCommand as A;
    match cmd {
        A::CreateDatabase { name, .. } => format!("CREATE DATABASE {name}"),
        A::DropDatabase { name, .. } => format!("DROP DATABASE {name}"),
        A::StartDatabase { name } => format!("START DATABASE {name}"),
        A::StopDatabase { name } => format!("STOP DATABASE {name}"),
        A::ShowDatabases => "SHOW DATABASES".to_owned(),
        A::ShowDatabase { name } => format!("SHOW DATABASE {name}"),
        A::CreateUser { name, password, .. } => {
            // NEVER the password value — only that one was set.
            if password.is_some() {
                format!("CREATE USER {name} SET PASSWORD <redacted>")
            } else {
                format!("CREATE USER {name}")
            }
        }
        A::DropUser { name, .. } => format!("DROP USER {name}"),
        A::CreateRole { name, .. } => format!("CREATE ROLE {name}"),
        A::DropRole { name, .. } => format!("DROP ROLE {name}"),
        A::GrantRole { role, user } => format!("GRANT ROLE {role} TO {user}"),
        A::RevokeRole { role, user } => format!("REVOKE ROLE {role} FROM {user}"),
        A::GrantPrivilege {
            action,
            scope,
            role,
        } => format!(
            "GRANT {} ON {} TO {role}",
            priv_action_str(*action),
            priv_scope_str(scope)
        ),
        A::RevokePrivilege {
            action,
            scope,
            role,
        } => format!(
            "REVOKE {} ON {} FROM {role}",
            priv_action_str(*action),
            priv_scope_str(scope)
        ),
        A::ShowUsers => "SHOW USERS".to_owned(),
        A::ShowRoles => "SHOW ROLES".to_owned(),
        A::ShowPrivileges => "SHOW PRIVILEGES".to_owned(),
        A::BackupDatabase { name, path } => format!("BACKUP DATABASE {name} TO {path}"),
        A::RestoreDatabase { name, path, point } => {
            use crate::admin::RestorePoint as R;
            let at = match point {
                R::Latest => String::new(),
                R::Lsn(n) => format!(" AT LSN {n}"),
                R::Timestamp(t) => format!(" AT TIMESTAMP {t}"),
            };
            format!("RESTORE DATABASE {name} FROM {path}{at}")
        }
        A::CheckpointDatabase { name } => format!("CHECKPOINT DATABASE {name}"),
    }
}

/// The uppercase keyword for a [`PrivAction`](crate::admin::PrivAction) (for the redacted detail).
fn priv_action_str(action: crate::admin::PrivAction) -> &'static str {
    use crate::admin::PrivAction as P;
    match action {
        P::Traverse => "TRAVERSE",
        P::Read => "READ",
        P::Write => "WRITE",
        P::Schema => "SCHEMA",
        P::Admin => "ADMIN",
    }
}

/// A concise textual scope for a [`PrivScope`](crate::admin::PrivScope) (for the redacted detail);
/// a name is not a secret.
fn priv_scope_str(scope: &crate::admin::PrivScope) -> String {
    use crate::admin::PrivScope as S;
    match scope {
        S::Database => "DATABASE".to_owned(),
        S::Graph { db } => format!("GRAPH {db}"),
        S::Label { db, label } => format!("LABEL {db}.{label}"),
        S::RelType { db, rel_type } => format!("RELATIONSHIP {db}.{rel_type}"),
        S::Property {
            db,
            label,
            property,
        } => format!("PROPERTY {db}.{label}.{property}"),
    }
}

/// Builds the audited `detail` for an index-DDL command (rmp #70/#91) — concise and secret-free
/// (index DDL carries no secret). E.g. `"CREATE INDEX ON :Person(name)"`.
#[must_use]
pub fn redact_index_detail(cmd: &crate::engine::IndexCommand) -> String {
    use crate::engine::IndexCommand as I;
    match cmd {
        I::CreateNodePropertyIndex { label, property } => {
            format!("CREATE INDEX ON :{label}({property})")
        }
        I::DropNodePropertyIndex { label, property } => {
            format!("DROP INDEX ON :{label}({property})")
        }
        I::ShowIndexes => "SHOW INDEXES".to_owned(),
        // Full-text index DDL (`rmp` task #72) carries no secret either: the index name, label,
        // property keys and analyzer are all schema identifiers.
        I::CreateFulltextIndex {
            name,
            label,
            properties,
            analyzer,
        } => format!(
            "CREATE FULLTEXT INDEX {name} FOR (:{label}) ON EACH [{}] (analyzer={analyzer})",
            properties.join(", ")
        ),
        I::DropFulltextIndex { name } => format!("DROP FULLTEXT INDEX {name}"),
        I::ShowFulltextIndexes => "SHOW FULLTEXT INDEXES".to_owned(),
        // Spatial (point) index DDL (`rmp` task #98) carries no secret either: the index name, label
        // and property key are all schema identifiers.
        I::CreatePointIndex {
            name,
            label,
            property,
        } => format!("CREATE POINT INDEX {name} FOR (:{label}) ON ({property})"),
        I::DropPointIndex { name } => format!("DROP POINT INDEX {name}"),
        I::ShowPointIndexes => "SHOW POINT INDEXES".to_owned(),
    }
}

/// Builds the audited `detail` for a constraint-DDL command (rmp #70/#99) — concise and secret-free
/// (constraint DDL carries no secret: the name, label and property are all schema identifiers). E.g.
/// `"CREATE CONSTRAINT c1 FOR (:Person) REQUIRE email IS UNIQUE"`.
#[must_use]
pub fn redact_constraint_detail(cmd: &crate::engine::ConstraintCommand) -> String {
    use crate::engine::ConstraintCommand as C;
    match cmd {
        C::CreateUnique {
            name,
            label,
            property,
        } => format!("CREATE CONSTRAINT {name} FOR (:{label}) REQUIRE {property} IS UNIQUE"),
        C::CreateExistence {
            name,
            label,
            property,
        } => format!("CREATE CONSTRAINT {name} FOR (:{label}) REQUIRE {property} IS NOT NULL"),
        C::CreateNodeKey {
            name,
            label,
            properties,
        } => format!(
            "CREATE CONSTRAINT {name} FOR (:{label}) REQUIRE ({}) IS NODE KEY",
            properties.join(", ")
        ),
        C::CreatePropertyType {
            name,
            label,
            property,
            declared_type,
        } => format!(
            "CREATE CONSTRAINT {name} FOR (:{label}) REQUIRE {property} IS :: {}",
            graphus_cypher::constraint::type_descriptor_name(declared_type)
        ),
        C::Drop { name } => format!("DROP CONSTRAINT {name}"),
        C::Show => "SHOW CONSTRAINTS".to_owned(),
    }
}

/// Builds the audited `detail` for a **data-change** (write) query (rmp #70): a category word only,
/// **never** the query text, parameters or literals (they may carry sensitive data).
///
/// The category is the leading clause keyword (e.g. `CREATE`/`MERGE`/`DELETE`/`SET`/`REMOVE`),
/// preferring the engine's `query_type` when the seam has it, else the first keyword of the query.
/// The result is like `"write query (CREATE)"` or, if no category can be derived, `"write query"`.
#[must_use]
pub fn data_change_detail(query: &str, query_type: Option<&str>) -> String {
    // Prefer an explicit category, else derive the leading clause keyword cheaply.
    let category = query_type
        .map(str::to_ascii_uppercase)
        .filter(|s| !s.is_empty())
        .or_else(|| leading_keyword(query));
    match category {
        Some(cat) => format!("write query ({cat})"),
        None => "write query".to_owned(),
    }
}

/// Extracts the leading clause keyword of a query (uppercased) for the data-change category, or
/// `None` if the query is empty/blank. Only the *keyword* is taken — never any literal/parameter.
fn leading_keyword(query: &str) -> Option<String> {
    let word: String = query
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect();
    if word.is_empty() {
        None
    } else {
        Some(word.to_ascii_uppercase())
    }
}

// ------------------------------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::{AdminCommand, PrivAction, PrivScope};
    use std::io::Write;

    /// A unique temp directory removed on drop (mirrors the `security.rs`/`config.rs` test helper).
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> Self {
            let mut path = std::env::temp_dir();
            let nanos = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            path.push(format!(
                "graphus-audit-{tag}-{nanos}-{}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// An enabled config with the default knobs (rotation large so it never fires in these tests
    /// unless overridden).
    fn enabled_config() -> AuditConfig {
        AuditConfig {
            enabled: true,
            ..AuditConfig::default()
        }
    }

    /// Reads the audit log under `dir` and parses each non-empty line as JSON.
    fn read_lines(dir: &Path) -> Vec<serde_json::Value> {
        let text = std::fs::read_to_string(dir.join(AUDIT_FILE_NAME)).unwrap_or_default();
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("parse audit line"))
            .collect()
    }

    fn an_event(class: AuditClass) -> AuditEvent {
        AuditEvent::new(class, AuditOutcome::Success, AuditSource::BoltUds)
            .actor(Some("alice"))
            .detail("test event")
    }

    #[test]
    fn rfc3339_known_values() {
        // The epoch.
        assert_eq!(
            rfc3339_utc(std::time::UNIX_EPOCH),
            "1970-01-01T00:00:00.000Z"
        );
        // A known modern instant: 2021-01-01T00:00:00Z is 1_609_459_200 seconds since the epoch.
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_609_459_200);
        assert_eq!(rfc3339_utc(t), "2021-01-01T00:00:00.000Z");
        // Millisecond precision is carried.
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_609_459_200_123);
        assert_eq!(rfc3339_utc(t), "2021-01-01T00:00:00.123Z");
        // A leap-year boundary: 2020-02-29T12:34:56Z = 1_582_979_696s.
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_582_979_696);
        assert_eq!(rfc3339_utc(t), "2020-02-29T12:34:56.000Z");
    }

    #[test]
    fn class_tags_are_stable() {
        assert_eq!(AuditClass::AuthSuccess.as_str(), "auth_success");
        assert_eq!(AuditClass::AuthFailure.as_str(), "auth_failure");
        assert_eq!(AuditClass::AuthzDenied.as_str(), "authz_denied");
        assert_eq!(AuditClass::AuthzGranted.as_str(), "authz_granted");
        assert_eq!(AuditClass::AdminChange.as_str(), "admin_change");
        assert_eq!(AuditClass::SchemaChange.as_str(), "schema_change");
        assert_eq!(AuditClass::SecurityChange.as_str(), "security_change");
        assert_eq!(AuditClass::DataChange.as_str(), "data_change");
        // Sources + outcomes too.
        assert_eq!(AuditSource::BoltUds.as_str(), "bolt_uds");
        assert_eq!(AuditSource::BoltTcp.as_str(), "bolt_tcp");
        assert_eq!(AuditSource::Rest.as_str(), "rest");
        assert_eq!(AuditSource::Internal.as_str(), "internal");
        assert_eq!(AuditOutcome::Success.as_str(), "success");
        assert_eq!(AuditOutcome::Failure.as_str(), "failure");
    }

    #[test]
    fn passwords_are_never_in_redacted_output() {
        let cmd = AdminCommand::CreateUser {
            name: "carol".to_owned(),
            password: Some("sup3r-s3cret".to_owned()),
            if_not_exists: false,
        };
        let detail = redact_admin_detail(&cmd);
        assert!(
            !detail.contains("sup3r-s3cret"),
            "the password must never appear: {detail}"
        );
        assert!(
            detail.contains("<redacted>"),
            "a set password is marked redacted: {detail}"
        );
        assert!(detail.contains("CREATE USER carol"), "{detail}");
    }

    #[test]
    fn redacted_admin_details_are_concise_and_secret_free() {
        assert_eq!(
            redact_admin_detail(&AdminCommand::CreateUser {
                name: "u".to_owned(),
                password: None,
                if_not_exists: true,
            }),
            "CREATE USER u"
        );
        assert_eq!(
            redact_admin_detail(&AdminCommand::CreateDatabase {
                name: "sales".to_owned(),
                if_not_exists: false,
            }),
            "CREATE DATABASE sales"
        );
        assert_eq!(
            redact_admin_detail(&AdminCommand::GrantPrivilege {
                action: PrivAction::Read,
                scope: PrivScope::Label {
                    db: "sales".to_owned(),
                    label: "Person".to_owned(),
                },
                role: "reader".to_owned(),
            }),
            "GRANT READ ON LABEL sales.Person TO reader"
        );
    }

    #[test]
    fn data_change_detail_never_includes_query_text() {
        let d = data_change_detail("CREATE (n:Person {name:'secret-value'})", None);
        assert_eq!(d, "write query (CREATE)");
        assert!(!d.contains("secret-value"));
        // An explicit query_type wins over the leading keyword.
        assert_eq!(
            data_change_detail("MATCH (n) SET n.x = 1", Some("w")),
            "write query (W)"
        );
        // Blank query, no type ⇒ the bare category.
        assert_eq!(data_change_detail("   ", None), "write query");
    }

    #[test]
    fn disabled_log_writes_nothing() {
        let dir = TempDir::new("disabled");
        let config = AuditConfig {
            enabled: false,
            ..AuditConfig::default()
        };
        let log = AuditLog::open(&config, &dir.path).expect("open disabled");
        assert!(!log.enabled());
        for _ in 0..5 {
            log.record(an_event(AuditClass::AuthSuccess));
        }
        log.flush().expect("flush disabled is ok");
        let audit_path = dir.path.join(AUDIT_FILE_NAME);
        assert!(
            !audit_path.exists(),
            "a disabled audit log must not create the file"
        );
    }

    #[test]
    fn events_get_monotonic_increasing_sequence_and_survive_reopen() {
        let dir = TempDir::new("monotonic");
        let config = enabled_config();
        {
            let log = AuditLog::open(&config, &dir.path).expect("open");
            log.record(an_event(AuditClass::AuthSuccess));
            log.record(an_event(AuditClass::SecurityChange));
            log.record(an_event(AuditClass::AdminChange));
            log.flush().expect("flush");
        } // drop closes the handle

        // Reopen: the recovered counter continues from 3 → the 4th event is seq 4.
        let log = AuditLog::open(&config, &dir.path).expect("reopen");
        log.record(an_event(AuditClass::SchemaChange));
        log.flush().expect("flush");

        let lines = read_lines(&dir.path);
        assert_eq!(lines.len(), 4, "all four events present: {lines:?}");
        let seqs: Vec<u64> = lines
            .iter()
            .map(|l| l.get("seq").and_then(serde_json::Value::as_u64).unwrap())
            .collect();
        assert_eq!(seqs, vec![1, 2, 3, 4], "monotonic, no gap across reopen");
        for l in &lines {
            assert!(
                l.get("ts").and_then(serde_json::Value::as_str).is_some(),
                "every line carries a ts: {l:?}"
            );
        }
    }

    #[test]
    fn actor_none_is_json_null_not_anonymous() {
        let dir = TempDir::new("null-actor");
        let log = AuditLog::open(&enabled_config(), &dir.path).expect("open");
        log.record(AuditEvent::new(
            AuditClass::AuthFailure,
            AuditOutcome::Failure,
            AuditSource::BoltTcp,
        ));
        log.flush().expect("flush");
        let lines = read_lines(&dir.path);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].get("actor").map(serde_json::Value::is_null) == Some(true),
            "absent actor is JSON null: {:?}",
            lines[0]
        );
    }

    #[test]
    fn torn_final_line_is_repaired_on_reopen() {
        let dir = TempDir::new("torn");
        let config = enabled_config();
        {
            let log = AuditLog::open(&config, &dir.path).expect("open");
            log.record(an_event(AuditClass::AuthSuccess));
            log.record(an_event(AuditClass::SecurityChange));
            log.flush().expect("flush");
        }
        // Simulate a crash mid-append: a partial line WITHOUT a trailing newline.
        let audit_path = dir.path.join(AUDIT_FILE_NAME);
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&audit_path)
                .expect("reopen for torn write");
            f.write_all(b"{\"seq\":99,\"ts\":\"2099-01-01T00:00:00.000Z\",\"clas")
                .expect("write torn partial");
            f.flush().expect("flush torn");
        }
        let raw = std::fs::read_to_string(&audit_path).expect("read torn");
        assert!(
            raw.contains("\"seq\":99"),
            "the torn bytes are present pre-reopen"
        );

        // Reopen via AuditLog::open: the torn tail is detected and truncated.
        let log = AuditLog::open(&config, &dir.path).expect("reopen repairs torn tail");
        let repaired = std::fs::read_to_string(&audit_path).expect("read repaired");
        assert!(
            !repaired.contains("\"seq\":99"),
            "the torn bytes were truncated: {repaired}"
        );
        assert!(
            repaired.ends_with('\n'),
            "the file ends on a clean newline after repair"
        );

        // The next event appends cleanly and continues from seq 3 (the bogus 99 is ignored).
        log.record(an_event(AuditClass::AdminChange));
        log.flush().expect("flush");
        let lines = read_lines(&dir.path);
        assert_eq!(lines.len(), 3, "two valid + the new one: {lines:?}");
        let seqs: Vec<u64> = lines
            .iter()
            .map(|l| l.get("seq").and_then(serde_json::Value::as_u64).unwrap())
            .collect();
        assert_eq!(seqs, vec![1, 2, 3], "torn seq 99 ignored; continues from 3");
    }

    #[test]
    fn rotation_keeps_configured_number_of_files() {
        let dir = TempDir::new("rotation");
        let config = AuditConfig {
            enabled: true,
            rotate_max_bytes: 200, // tiny, so a few events force several rotations
            retain_files: 2,
            ..AuditConfig::default()
        };
        let log = AuditLog::open(&config, &dir.path).expect("open");
        // Each record line is well over 100 bytes, so ~10 events force >= 3 rotations.
        for _ in 0..10 {
            log.record(
                AuditEvent::new(
                    AuditClass::SecurityChange,
                    AuditOutcome::Success,
                    AuditSource::Rest,
                )
                .actor(Some("alice"))
                .database(Some("graphus"))
                .detail("CREATE USER somebody SET PASSWORD <redacted>"),
            );
        }
        log.flush().expect("flush");

        let active = dir.path.join(AUDIT_FILE_NAME);
        let r1 = dir.path.join("audit.log.1");
        let r2 = dir.path.join("audit.log.2");
        let r3 = dir.path.join("audit.log.3");
        assert!(active.exists(), "the active file exists");
        assert!(r1.exists(), "audit.log.1 retained");
        assert!(r2.exists(), "audit.log.2 retained");
        assert!(
            !r3.exists(),
            "audit.log.3 must NOT exist (retain_files = 2)"
        );
    }

    #[test]
    fn data_change_is_batched_then_flushed() {
        let dir = TempDir::new("batched");
        let config = AuditConfig {
            enabled: true,
            audit_data_changes: true,
            ..AuditConfig::default()
        };
        let log = AuditLog::open(&config, &dir.path).expect("open");
        assert!(log.data_changes_enabled());
        log.record(
            AuditEvent::new(
                AuditClass::DataChange,
                AuditOutcome::Success,
                AuditSource::BoltUds,
            )
            .actor(Some("alice"))
            .detail("write query (CREATE)"),
        );
        // It is written to the page cache and parseable even before an explicit flush.
        let lines = read_lines(&dir.path);
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0].get("class").and_then(serde_json::Value::as_str),
            Some("data_change")
        );
        // With the default (fsync_data_changes = false) the line is left batched (unsynced) until
        // the next security event / flush — pinning the precise durability contract for #424.
        assert!(
            log.inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pending_unsynced,
            "default policy leaves a data-change line batched (unsynced) before flush"
        );
        log.flush().expect("flush hardens the batch");
    }

    /// #424: with `fsync_data_changes = true`, a `DataChange` record is `fsync`'d **before
    /// `record` returns** (durable before the audited op's ack), exactly like a security event —
    /// so it leaves no pending-unsynced state and survives a crash with no further flush. The
    /// `pending_unsynced` flag is the in-process witness of the `sync_data` call (set on a batched
    /// write, cleared by a successful sync); asserting it is `false` immediately after `record`
    /// proves the hardening happened synchronously, before the call returned.
    #[test]
    fn data_change_is_fsynced_before_ack_when_opted_in() {
        let dir = TempDir::new("fsync-dc");
        let config = AuditConfig {
            enabled: true,
            audit_data_changes: true,
            fsync_data_changes: true,
            ..AuditConfig::default()
        };
        let log = AuditLog::open(&config, &dir.path).expect("open");
        log.record(
            AuditEvent::new(
                AuditClass::DataChange,
                AuditOutcome::Success,
                AuditSource::BoltUds,
            )
            .actor(Some("alice"))
            .detail("write query (CREATE)"),
        );
        // The hardening happened inside `record` (before it returned): nothing is left batched.
        assert!(
            !log.inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pending_unsynced,
            "fsync_data_changes=true hardens the data-change line before record() returns"
        );
        // And the line survives a reopen with no explicit flush in between (durable-before-ack).
        drop(log);
        let lines = read_lines(&dir.path);
        assert_eq!(lines.len(), 1, "the data-change line is on disk: {lines:?}");
        assert_eq!(
            lines[0].get("class").and_then(serde_json::Value::as_str),
            Some("data_change")
        );
    }

    /// #425: a rotation immediately followed by a restart must NOT reuse seq numbers. We write
    /// enough to force at least one rotation (so the highest seq lives in `audit.log.1`), then
    /// simulate the worst case: the active file is empty at restart (a rotation that produced a
    /// fresh `audit.log` before any line was written). On reopen, the next seq must be strictly
    /// greater than the max seq present in any rotated file — no reuse.
    #[test]
    fn seq_is_not_reused_after_rotation_then_restart() {
        let dir = TempDir::new("rotate-restart");
        let config = AuditConfig {
            enabled: true,
            // Large threshold: no automatic rotation here. We model the precise #425 worst case by
            // hand: a rotation that moved every written line into `audit.log.1` and then a restart
            // before any line landed in the fresh (empty) active file.
            rotate_max_bytes: 0,
            retain_files: 3,
            ..AuditConfig::default()
        };
        let max_written;
        {
            let log = AuditLog::open(&config, &dir.path).expect("open");
            for _ in 0..6 {
                log.record(an_event(AuditClass::SecurityChange));
            }
            log.flush().expect("flush");
            max_written = log.seq.load(Ordering::Relaxed);
        }
        assert_eq!(max_written, 6, "six events written, seqs 1..=6");

        // Model "rotation then restart before any write": move the active file (holding the highest
        // seqs) to audit.log.1 and leave the active file ABSENT (a fresh-rotated, unwritten state).
        let active = dir.path.join(AUDIT_FILE_NAME);
        let r1 = dir.path.join("audit.log.1");
        std::fs::rename(&active, &r1).expect("rotate active -> .1");
        assert!(!active.exists(), "the fresh active file does not exist yet");

        // Active-only recovery would see max seq 0 here (the bug): the highest seq lives in .1.
        let active_max = scan_existing(&active).unwrap().0;
        assert_eq!(
            active_max, 0,
            "active-only recovery gives 0 (would REUSE seq 1)"
        );
        let rotated_max = max_rotated_seq(&active, config.retain_files);
        assert_eq!(rotated_max, 6, "the rotated file carries the highest seq");

        // Reopen: with the #425 fix the next seq is recovered from the rotated files too.
        let log = AuditLog::open(&config, &dir.path).expect("reopen");
        log.record(an_event(AuditClass::AdminChange));
        let next = log.seq.load(Ordering::Relaxed);
        assert!(
            next > rotated_max,
            "next seq {next} must exceed the max rotated seq {rotated_max} (no reuse); \
             active-only recovery would have produced {} (REUSE of an existing seq)",
            active_max + 1
        );
        assert_eq!(
            next,
            max_written + 1,
            "continues monotonically past every written seq"
        );
    }

    /// #424: the durability *contract* itself, pinned as an assertion — security events are
    /// security-relevant (synced before ack by default), data changes are not (batched by default).
    #[test]
    fn durability_contract_is_pinned() {
        // Security-relevant classes are fsync'd-before-ack (when fsync_security_events is on).
        assert!(AuditClass::AuthSuccess.is_security_relevant());
        assert!(AuditClass::AuthFailure.is_security_relevant());
        assert!(AuditClass::AuthzDenied.is_security_relevant());
        assert!(AuditClass::AdminChange.is_security_relevant());
        assert!(AuditClass::SchemaChange.is_security_relevant());
        assert!(AuditClass::SecurityChange.is_security_relevant());
        // A data change is NOT security-relevant: batched unless fsync_data_changes opts in.
        assert!(!AuditClass::DataChange.is_security_relevant());
        // The defaults encode the contract: security synced, data changes batched.
        let d = AuditConfig::default();
        assert!(
            d.fsync_security_events,
            "security events sync-before-ack by default"
        );
        assert!(!d.fsync_data_changes, "data changes are batched by default");
    }
}
