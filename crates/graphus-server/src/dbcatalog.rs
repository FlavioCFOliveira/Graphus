//! The crash-safe **database catalog** + per-database engine runtime (decision `D-multi-db`,
//! rmp #83 — the foundation half of multi-database support; the Cypher/Bolt/REST admin surface is
//! rmp #84).
//!
//! Graphus serves multiple named databases from one server process. Each database is a fully
//! independent [`graphus_storage::RecordStore`] (its own device file, WAL, token dictionaries and
//! element-id sequence) driven by its own dedicated engine thread (see [`crate::engine`]) — storage
//! isolation is structural, not advisory. This module adds the three pieces storage does not have:
//! **naming**, **durable lifecycle state**, and **engine selection**.
//!
//! ## On-disk layout (backward compatible)
//!
//! ```text
//! <store_path>/                      ← the DEFAULT database (the unchanged single-db layout)
//! ├── graphus.store
//! ├── graphus.wal/                   ← the segmented WAL directory (anchor + seg.<base>, rmp #116)
//! ├── databases.toml                 ← the durable catalog (ABSENT ⇒ no additional databases)
//! └── databases/
//!     └── <name>/                    ← one directory per additional database
//!         ├── graphus.store
//!         └── graphus.wal/
//! ```
//!
//! The default database lives **directly in `store_path`**, exactly where a pre-multi-db deployment
//! put it, so an existing single-database store opens completely unchanged, with zero migration.
//!
//! The default database is **implicit — never stored in `databases.toml`**. Storing it would create
//! a reconciliation problem: the file could disagree with the config's `default_database` about the
//! name, or claim the default is `offline` when the server must always serve it. Deriving it from
//! config keeps a single source of truth, and makes the absent-catalog case (a fresh or pre-multi-db
//! deployment) literally identical to "the default database only".
//!
//! ## Crash-safe persistence (the catalog itself is ACID)
//!
//! Every catalog mutation rewrites `databases.toml` with the classic atomic-replace protocol:
//!
//! 1. write the full new contents to `databases.toml.tmp`;
//! 2. `fsync` the temp file (the bytes are durable *before* they become visible);
//! 3. atomically `rename` it onto `databases.toml` (POSIX rename is all-or-nothing);
//! 4. `fsync` the parent directory (the rename's directory entry is durable).
//!
//! A crash at any point leaves either the complete old file or the complete new file — never a
//! torn one. On load, a leftover `.tmp` is a crashed step-1/2 whose rename never happened; the real
//! file (or its absence) is authoritative, so the stale temp is removed. A **malformed** catalog
//! file fails the load **closed** with a clear error: the server refuses to start rather than
//! silently resetting state that names real data directories.
//!
//! A persist **failure** is resolved by *resync, not blind rollback*: the atomic replace can fail
//! on either side of its `rename` — before it (the old file is still published) or after it (the
//! new file is already visible, and may survive a crash even though the parent-directory `fsync`
//! failed). The in-memory entries are therefore reloaded from whatever file is actually published
//! (`persist_or_resync`); only if that reload also fails does memory fall back to the caller's
//! pre-mutation snapshot, logged at error level.
//!
//! ## Lifecycle state model: desired vs. actual
//!
//! `databases.toml` records each additional database's **desired** state (`online` / `offline` —
//! the operator's durable intent). The in-process registry holds the **actual** state (which
//! engines are running). The two reconcile as follows:
//!
//! - **Boot**: the default database starts first and its failure fails startup (unchanged
//!   single-db behaviour). Every catalog database whose desired state is `online` is then started;
//!   a failure is logged and recorded in memory as *failed* — it does **not** flip the durable
//!   desired state and does **not** prevent the server (or the other databases) from starting, so
//!   one corrupt secondary database can never take down the rest.
//! - **`create`**: provision the directory → persist the catalog entry (`online`) → start the
//!   engine. A crash after provisioning leaves an *orphan directory without a catalog entry* —
//!   inert, and reclaimed (cleared) by a later `create` of the same name. A crash after the persist
//!   leaves an `online` entry whose store files do not exist yet — the next boot simply creates the
//!   fresh store when it starts that database. If the engine fails to start, the entry is rolled
//!   back (and the directory removed) so a failed `create` leaves no trace.
//! - **`start`**: persist desired `online` first, then start the engine. A spawn failure is
//!   reported and recorded as *failed* in memory; the durable intent stays `online`, so the boot
//!   policy retries it — exactly the semantics of a database that failed at boot.
//! - **`stop`**: drain + harden + join the engine first, then persist desired `offline`. If the
//!   persist fails the error is reported and memory resyncs to the published file (normally still
//!   `online`), so a retried `stop` skips the drain (the engine is already down) and re-attempts
//!   the persist. A stop that never became durable behaves as if it never happened: the database
//!   comes back at the next boot.
//! - **`drop`**: only allowed when stopped. The catalog entry is removed (persisted) **first**,
//!   then the directory is deleted. A crash in between leaves an orphan directory — inert, and
//!   cleared by a future `create` of the same name (so dropped data can never resurrect).
//!
//! ## Registry locking design
//!
//! - **Mutations** (`create`/`start`/`stop`/`drop`/boot/shutdown) are serialized behind one
//!   [`tokio::sync::Mutex`]. An async-aware mutex is required because `stop`/`shutdown` await the
//!   engine's drain while holding the guard — sound on a Tokio mutex, an anti-pattern on a std one.
//! - **Handle lookup** (the per-request hot path the rmp-#84 routing will hit) goes through a
//!   [`std::sync::RwLock`]`<HashMap>`: readers take a brief read lock, clone the (cheap, three
//!   pointer-sized fields) [`EngineHandle`], and release — never across an `.await`. Writers touch
//!   it only inside admin-locked sections, so the lock order is always admin → handles.
//!
//! ## Database names
//!
//! Names are compared case-insensitively and stored lowercase. The accepted (normalized) form is
//! `[a-z][a-z0-9_-]{0,62}` — 1 to 63 characters, starting with a lowercase ASCII letter, then
//! lowercase letters, digits, `_` or `-`. The conservative charset makes a name always safe to use
//! verbatim as a directory name (no separators, no `.`/`..`, no empty string, nothing the
//! filesystem could interpret).

use std::collections::{BTreeMap, HashMap};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};

use graphus_core::GraphusError;
use graphus_crypto::{EncryptedFileDevice, EncryptedFileLogSink, Keyring};
use graphus_cypher::TxnCoordinator;
use graphus_io::FileBlockDevice;
use graphus_storage::check::verify_on_open;
use graphus_storage::recovery::recover_device_with_dwb;
use graphus_storage::{Dwb, RecordStore};
use graphus_wal::{FileLogSink, WalManager};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::config::ServerConfig;
use crate::engine::{Engine, EngineHandle, spawn_engine};
use crate::metrics::Metrics;
use crate::store_device::{MasterKey, StoreDevice, WalSink};

/// The default database's name when the config does not override it.
pub const DEFAULT_DATABASE_NAME: &str = "graphus";

/// The record-store device file name inside a database directory (shared with
/// [`crate::config::ServerConfig::device_file`] so the two can never drift).
pub const STORE_FILE_NAME: &str = "graphus.store";

/// The WAL file name inside a database directory (shared with
/// [`crate::config::ServerConfig::wal_file`]).
pub const WAL_FILE_NAME: &str = "graphus.wal";

/// The doublewrite-buffer file name inside a database directory (`rmp` #384). A persistent,
/// fixed-size area (`graphus_storage::dwb_device_pages` pages) holding a durable copy of each batch of dirty home
/// pages *before* they are written home, so a torn home page can be repaired from it on the next
/// open ([`recover_device_with_dwb`]). Lives beside `graphus.store` and `graphus.wal`.
pub const DWB_FILE_NAME: &str = "graphus.dwb";

/// The durable catalog file name, directly under the data root.
pub const CATALOG_FILE_NAME: &str = "databases.toml";

/// The temp file the atomic-replace protocol writes before the rename (see the module docs).
const CATALOG_TMP_NAME: &str = "databases.toml.tmp";

/// The directory (under the data root) holding the additional databases' directories.
const DATABASES_DIR_NAME: &str = "databases";

/// The catalog file format version this build reads and writes. A file with any other version
/// fails the load closed (a future format change must bump this and ship explicit migration).
const CATALOG_FORMAT_VERSION: u32 = 1;

/// The maximum (normalized) database-name length, in bytes.
pub const MAX_DB_NAME_LEN: usize = 63;

// ------------------------------------------------------------------------------------------------
// Errors
// ------------------------------------------------------------------------------------------------

/// How a catalog operation failed.
#[derive(Debug)]
pub enum CatalogError {
    /// The database name does not satisfy the name rule (see the module docs).
    InvalidName(String),
    /// A filesystem operation on the catalog or a database directory failed.
    Io {
        /// The path the operation touched.
        path: PathBuf,
        /// What was being done + the underlying I/O error rendering.
        source: String,
    },
    /// The catalog file exists but is malformed. The load **fails closed**: the server refuses to
    /// start rather than silently resetting a catalog that names real data directories.
    Corrupt {
        /// The catalog file path.
        path: PathBuf,
        /// Why it could not be accepted.
        reason: String,
    },
    /// Serializing the catalog for persistence failed (an internal invariant violation).
    Encode(String),
    /// `create` of a name that already exists (including the default database's name).
    AlreadyExists(String),
    /// The named database is not in the catalog.
    UnknownDatabase(String),
    /// The operation is not allowed on the default database (it always exists, is always online
    /// while the server runs, and is managed by the server lifecycle — not the admin API).
    DefaultDatabase {
        /// The default database's name.
        name: String,
        /// The rejected operation (`"create"`, `"start"`, `"stop"`, `"drop"`).
        operation: &'static str,
    },
    /// `drop` of a database that is not stopped (drop requires desired + actual state offline).
    NotOffline(String),
    /// A backup capture or a restore failed (`rmp` task #149): a storage/crypto fault, a malformed
    /// or wrong-key backup file, or a target-state precondition (e.g. restore requires the database
    /// stopped). The message is the operator-facing reason.
    Backup(String),
    /// Starting or stopping the database's engine failed (e.g. an integrity-check failure).
    Engine(GraphusError),
}

impl std::fmt::Display for CatalogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidName(name) => write!(
                f,
                "invalid database name {name:?}: a name is 1-{MAX_DB_NAME_LEN} characters matching \
                 [a-z][a-z0-9_-]* (compared case-insensitively, stored lowercase)"
            ),
            Self::Io { path, source } => {
                write!(f, "catalog I/O error at {}: {source}", path.display())
            }
            Self::Corrupt { path, reason } => write!(
                f,
                "catalog file {} is malformed: {reason}. Refusing to start — repair or remove the \
                 file explicitly; the server never resets a corrupt catalog",
                path.display()
            ),
            Self::Encode(m) => write!(f, "encoding catalog: {m}"),
            Self::AlreadyExists(name) => write!(f, "database {name:?} already exists"),
            Self::UnknownDatabase(name) => write!(f, "database {name:?} does not exist"),
            Self::DefaultDatabase { name, operation } => {
                write!(f, "cannot {operation} the default database {name:?}")
            }
            Self::NotOffline(name) => write!(
                f,
                "database {name:?} must be stopped (offline) before it can be dropped"
            ),
            Self::Backup(m) => write!(f, "backup/restore failed: {m}"),
            Self::Engine(e) => write!(f, "database engine error: {e}"),
        }
    }
}

impl std::error::Error for CatalogError {}

// ------------------------------------------------------------------------------------------------
// Names
// ------------------------------------------------------------------------------------------------

/// Normalizes (trims + lowercases) and validates a database name, returning the canonical stored
/// form.
///
/// The accepted normalized form is `[a-z][a-z0-9_-]{0,62}` (see the module docs for why the
/// charset is deliberately conservative: a valid name is always safe verbatim as a directory
/// name — no path separators, no `.`/`..`, never empty). Comparison is case-insensitive: callers
/// pass any case, the catalog stores and matches lowercase.
///
/// # Errors
/// [`CatalogError::InvalidName`] when the name does not satisfy the rule.
pub fn normalize_db_name(raw: &str) -> Result<String, CatalogError> {
    let name = raw.trim().to_ascii_lowercase();
    let bytes = name.as_bytes();
    let valid = match bytes {
        [] => false,
        [first, rest @ ..] => {
            bytes.len() <= MAX_DB_NAME_LEN
                && first.is_ascii_lowercase()
                && rest.iter().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-'
                })
        }
    };
    if valid {
        Ok(name)
    } else {
        Err(CatalogError::InvalidName(raw.to_owned()))
    }
}

// ------------------------------------------------------------------------------------------------
// Durable catalog file
// ------------------------------------------------------------------------------------------------

/// A database's lifecycle state. In the durable catalog it is the **desired** state (the
/// operator's intent); in [`DbInfo`] it also describes the **actual** state (whether the engine is
/// running right now).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DbState {
    /// The database serves queries (desired: start it at boot).
    Online,
    /// The database is stopped (desired: leave it stopped at boot).
    Offline,
}

/// The serialized shape of `databases.toml`. Unknown fields are rejected (a format change must
/// bump [`CATALOG_FORMAT_VERSION`], never silently extend version 1).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogFile {
    /// The format version; must equal [`CATALOG_FORMAT_VERSION`].
    version: u32,
    /// The additional (non-default) databases. The default database is implicit (module docs).
    #[serde(default)]
    databases: Vec<CatalogEntry>,
}

/// One additional database in the durable catalog.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogEntry {
    /// The (lowercase) database name.
    name: String,
    /// The desired lifecycle state.
    state: DbState,
}

/// Builds a [`CatalogError::Io`] with a uniform "what failed: why" rendering.
fn io_error(path: &Path, what: &str, e: &std::io::Error) -> CatalogError {
    CatalogError::Io {
        path: path.to_path_buf(),
        source: format!("{what}: {e}"),
    }
}

/// Persists `entries` to `<root>/databases.toml` with the atomic-replace protocol (module docs):
/// write temp → `fsync` temp → `rename` → `fsync` parent dir. Blocking; run it off the runtime.
///
/// # Errors
/// [`CatalogError::Io`] on any filesystem failure, [`CatalogError::Encode`] if serialization
/// fails (an internal invariant violation — the entries were validated on the way in).
fn persist_entries(root: &Path, entries: &BTreeMap<String, DbState>) -> Result<(), CatalogError> {
    std::fs::create_dir_all(root).map_err(|e| io_error(root, "creating data root", &e))?;

    let file = CatalogFile {
        version: CATALOG_FORMAT_VERSION,
        databases: entries
            .iter()
            .map(|(name, state)| CatalogEntry {
                name: name.clone(),
                state: *state,
            })
            .collect(),
    };
    let text = toml::to_string(&file).map_err(|e| CatalogError::Encode(e.to_string()))?;

    let tmp = root.join(CATALOG_TMP_NAME);
    let dst = root.join(CATALOG_FILE_NAME);
    {
        // `File::create` truncates, so a stale temp from an earlier crash is harmlessly reused.
        let mut f =
            std::fs::File::create(&tmp).map_err(|e| io_error(&tmp, "creating catalog temp", &e))?;
        f.write_all(text.as_bytes())
            .map_err(|e| io_error(&tmp, "writing catalog temp", &e))?;
        // Harden the bytes BEFORE the rename makes them visible; otherwise a crash could publish
        // a file whose contents were never written back.
        f.sync_all()
            .map_err(|e| io_error(&tmp, "syncing catalog temp", &e))?;
    }
    // POSIX rename is atomic: readers see the complete old file or the complete new file.
    std::fs::rename(&tmp, &dst).map_err(|e| io_error(&dst, "publishing catalog", &e))?;
    // Harden the rename's directory entry, or a crash could roll the publish back.
    let dir = std::fs::File::open(root).map_err(|e| io_error(root, "opening data root", &e))?;
    dir.sync_all()
        .map_err(|e| io_error(root, "syncing data root directory", &e))?;
    Ok(())
}

/// Loads the durable catalog from `<root>/databases.toml`, removing a stale temp file first.
///
/// An absent file means "no additional databases" (a fresh or pre-multi-db deployment). A present
/// but malformed file **fails closed** ([`CatalogError::Corrupt`]) — the catalog names real data
/// directories, so it is never silently reset. Every entry's name is re-validated (it must already
/// be in canonical lowercase form: the catalog is always written normalized, so divergence means
/// tampering or corruption), duplicates are rejected, and the default database must not appear
/// (it is implicit — a conflicting entry means the config and the catalog disagree).
///
/// # Errors
/// [`CatalogError::Io`] if the file exists but cannot be read; [`CatalogError::Corrupt`] on any
/// malformed content.
fn load_entries(
    root: &Path,
    default_name: &str,
) -> Result<BTreeMap<String, DbState>, CatalogError> {
    // A stale temp is a crashed mutation whose rename never happened; the real file (or its
    // absence) is authoritative. Removal is best-effort: a leftover temp is inert (the next
    // persist truncates it), so failing to remove it must not fail the load.
    let tmp = root.join(CATALOG_TMP_NAME);
    match std::fs::remove_file(&tmp) {
        Ok(()) => tracing::warn!(
            path = %tmp.display(),
            "removed stale catalog temp file (a catalog write crashed before publishing)"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(
            path = %tmp.display(),
            error = %e,
            "could not remove stale catalog temp file (inert; will be reused by the next persist)"
        ),
    }

    let path = root.join(CATALOG_FILE_NAME);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        // No catalog ⇒ no additional databases (fresh or pre-multi-db deployment).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(io_error(&path, "reading catalog", &e)),
    };

    let corrupt = |reason: String| CatalogError::Corrupt {
        path: path.clone(),
        reason,
    };
    let parsed: CatalogFile = toml::from_str(&text).map_err(|e| corrupt(e.to_string()))?;
    if parsed.version != CATALOG_FORMAT_VERSION {
        return Err(corrupt(format!(
            "unsupported catalog version {} (this build supports {CATALOG_FORMAT_VERSION})",
            parsed.version
        )));
    }

    let mut entries = BTreeMap::new();
    for entry in parsed.databases {
        let name = normalize_db_name(&entry.name)
            .map_err(|e| corrupt(format!("invalid database entry: {e}")))?;
        if name != entry.name {
            return Err(corrupt(format!(
                "database name {:?} is not in canonical (lowercase) form",
                entry.name
            )));
        }
        if name == default_name {
            return Err(corrupt(format!(
                "the catalog lists the default database {name:?}; the default is implicit (the \
                 config and the catalog disagree)"
            )));
        }
        if entries.insert(name.clone(), entry.state).is_some() {
            return Err(corrupt(format!("duplicate database entry {name:?}")));
        }
    }
    Ok(entries)
}

// ------------------------------------------------------------------------------------------------
// Engine spawning (one store + one engine thread per database)
// ------------------------------------------------------------------------------------------------

/// The engine-spawn knobs the catalog captures from [`ServerConfig`] at construction, so runtime
/// `create`/`start` spawn engines with exactly the same sizing as the default database.
#[derive(Clone)]
pub struct EngineParams {
    /// Buffer-pool capacity in pages, per database (`04 §3`).
    pub buffer_pool_pages: usize,
    /// Bounded capacity of each engine's command channel (`04 §9.3`).
    pub engine_queue_capacity: usize,
    /// Bounded capacity of each result row stream (`04 §9.3`).
    pub result_buffer_capacity: usize,
    /// Per-database admission limit (each database gets its own semaphore of this many permits,
    /// applied via [`EngineHandle::with_admission_limit`]).
    pub max_concurrent_queries: usize,
    /// The effective off-thread reader pool size (`rmp` task #336): how many reader worker threads each
    /// database's engine spawns to run read-only auto-commit statements concurrently with its writer.
    /// Resolved from [`AdmissionConfig::reader_threads`](crate::config::AdmissionConfig::reader_threads)
    /// (already auto-sized when `0`).
    pub reader_threads: usize,
    /// The encryption-at-rest master key (rmp #85), or `None` for the plaintext store path. When
    /// set, every database's store is an encrypted device (a per-store salted subkey is derived at
    /// create/open). When `None`, the store path is byte-identical to before encryption existed.
    pub master_key: Option<MasterKey>,
    /// The wall-clock source threaded into the engine for query-latency observation (`04 §11`).
    /// Production defaults to a [`crate::server::SystemClock`]-backed clock in [`Self::from_config`];
    /// the deterministic [`crate::engine::LocalEngine`] does not go through this path (it builds its
    /// engine inline with a `SimClock`), so this field exists solely so the threaded (production)
    /// engine is itself clock-injectable and never reaches for `Instant::now()` directly.
    pub clock: std::sync::Arc<dyn graphus_core::capability::Clock + Send + Sync>,
    /// Hard deadline for one engine's graceful drain on stop/shutdown (`rmp` #450): how long
    /// [`DatabaseCatalog::stop_engine`] waits for that engine's `Shutdown` (drain → flush → fdatasync)
    /// to complete before it **force-detaches** the (presumed wedged) engine and proceeds. Bounds the
    /// blast radius of a single wedged engine thread: without it, a hung storage/buffer-pool syscall
    /// makes `shutdown_all` never return while it holds the admin lock — blocking every *other* tenant's
    /// admin op until the process is externally `SIGKILL`ed. Sourced from
    /// [`TimingConfig::shutdown_drain_deadline`](crate::config::TimingConfig::shutdown_drain_deadline).
    pub engine_shutdown_timeout: std::time::Duration,
}

impl std::fmt::Debug for EngineParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The `clock` is a `dyn Clock` trait object (not `Debug`); render it as an opaque marker so
        // `EngineParams` keeps a useful `Debug` for diagnostics without constraining the trait.
        f.debug_struct("EngineParams")
            .field("buffer_pool_pages", &self.buffer_pool_pages)
            .field("engine_queue_capacity", &self.engine_queue_capacity)
            .field("result_buffer_capacity", &self.result_buffer_capacity)
            .field("max_concurrent_queries", &self.max_concurrent_queries)
            .field(
                "master_key",
                &self.master_key.as_ref().map(|_| "<redacted>"),
            )
            .field("clock", &"<dyn Clock>")
            .field("engine_shutdown_timeout", &self.engine_shutdown_timeout)
            .finish()
    }
}

impl EngineParams {
    /// Extracts the engine-spawn knobs from the server config, loading the encryption master key if
    /// one is configured.
    ///
    /// # Errors
    /// [`GraphusError`] (mapped to [`CatalogError::Engine`] by the caller) if encryption is enabled
    /// but the key file cannot be read or contains invalid key material.
    pub fn from_config(config: &ServerConfig) -> Result<Self, GraphusError> {
        let master_key = match &config.encryption.key_path {
            Some(path) => Some(MasterKey::load_from_file(path)?),
            None => None,
        };
        // The morsel-parallelism knob (`rmp` task #339) is a process-global read by the Cypher
        // executor's morsel tier (mirroring how the `rmp` #352 tier reads `rayon::current_num_threads`).
        // Set it once here from the resolved config — it applies to every database's engine (one
        // process-wide dedicated morsel pool), and the call is idempotent across per-database
        // `EngineSettings::from_config` invocations.
        graphus_cypher::morsel::set_morsel_threads(config.admission.morsel_parallelism());
        // The SHARED analytics pool (`rmp` task #376) is the single bounded compute-thread budget the
        // morsel tier AND GDS centrality both draw from (GDS no longer uses the global `rayon` pool). Size
        // it to the resolved reader-pool width (`min(N, 16)` by default, operator-tunable) — the same
        // core-bounded compute width as the reader/morsel pools — so the morsel + GDS peak runnable-thread
        // sum is `≈` core count, not `2 × N`. Independent of the morsel *enablement* knob above: pinning
        // morsel to serial must not shrink the pool GDS shares. Idempotent across per-database opens.
        graphus_cypher::morsel::set_analytics_pool_threads(config.admission.reader_threads());
        // The opt-in CSR-adjacency knob (`rmp` task #324, "Win 2") is likewise a process-global read by
        // the Cypher read path (mirroring `set_morsel_threads`). Set it once here from the resolved
        // config (default `false`); it decides whether each per-database coordinator builds a CSR on
        // open. Idempotent across per-database `from_config` invocations.
        graphus_cypher::read_source::set_csr_adjacency(config.admission.csr_adjacency);
        Ok(Self {
            buffer_pool_pages: config.buffer_pool_pages,
            engine_queue_capacity: config.admission.engine_queue_capacity,
            result_buffer_capacity: config.admission.result_buffer_capacity,
            max_concurrent_queries: config.admission.max_concurrent_queries,
            reader_threads: config.admission.reader_threads(),
            master_key,
            clock: std::sync::Arc::new(crate::server::SystemClock),
            engine_shutdown_timeout: config.timing.shutdown_drain_deadline(),
        })
    }
}

/// Opens an existing store (recovering its WAL first) or creates a fresh one, then **verifies it**
/// (`04 §4.6`/§4.8) — refusing to serve a corrupt store. Runs on the engine thread.
///
/// A store is "existing" when its device file is a non-empty whole number of pages; otherwise a
/// fresh store is created. Recovery replays the durable WAL onto the device (ARIES redo+undo,
/// `04 §4.8`) before the catalog is read back. This is the open path for **every** database — the
/// default and the additional ones differ only in the directory the paths point into.
fn open_or_create_coordinator(
    device_file: &Path,
    wal_file: &Path,
    pool_pages: usize,
    master_key: Option<&MasterKey>,
) -> Result<TxnCoordinator<StoreDevice, WalSink>, GraphusError> {
    let device_existing = device_file.metadata().map(|m| m.len() > 0).unwrap_or(false);

    let mut store = if device_existing {
        // Existing store: recover the WAL onto the device, then reopen. Both the device and the WAL
        // are (when a key is configured) encrypted; recovery and reopen run over the `BlockDevice`
        // and `LogSink` seams — transparently decrypted. The WAL subkey is derived from the SAME
        // master key + the store's salt (read from the device header), so the WAL and store share
        // one salt source (rmp #88).
        let keyring = wal_keyring_for_existing(device_file, master_key)?;
        let mut device = open_store_device(device_file, master_key)?;
        let mut wal = WalManager::open(open_wal_sink(wal_file, keyring.as_ref())?)
            .map_err(|e| GraphusError::Storage(format!("opening WAL manager: {e}")))?;
        // Doublewrite torn-page repair MUST run BEFORE ARIES redo (`rmp` #384, `04 §4.5`,
        // `recovery.rs` §recover_device_with_dwb): redo gates each change on the home page's own
        // `page_lsn`, so a torn home page (garbage header → garbage `page_lsn`) would have its redo
        // skipped and the corrupt page served. `recover_device_with_dwb` first restores every torn
        // home page from its intact DWB copy, then runs the normal recovery.
        let mut dwb = open_or_create_dwb(device_file, master_key)?;
        recover_device_with_dwb(&mut wal, &mut device, &mut dwb)?;
        // Reopen the WAL fresh for serving (recovery consumed the recovery view).
        let wal = WalManager::open(open_wal_sink(wal_file, keyring.as_ref())?)
            .map_err(|e| GraphusError::Storage(format!("reopening WAL manager: {e}")))?;
        let mut store = RecordStore::open(device, wal, pool_pages)?;
        // Attach the (now-recovered) DWB so every subsequent checkpoint/flush home write is
        // doublewrite-protected for the rest of this store's lifetime.
        store.attach_dwb(dwb);
        store
    } else {
        // Fresh store on an empty device + a freshly-created WAL. Both share one freshly-generated
        // per-store salt: the device persists it in its header; the WAL subkey is derived from it.
        let salt = master_key.map(|_| graphus_crypto::random_salt());
        let device = create_store_device(device_file, master_key, salt)?;
        let keyring = salt.map(|s| {
            master_key
                .expect("INVARIANT: a salt is generated only when a master key is configured")
                .keyring_for(&s)
        });
        let wal = WalManager::create(create_wal_sink(wal_file, keyring.as_ref())?)
            .map_err(|e| GraphusError::Storage(format!("creating WAL manager: {e}")))?;
        // Seed element ids from 1 (`04 §2.2`).
        let mut store = RecordStore::create(device, wal, pool_pages, 1)?;
        // Create and attach the persistent doublewrite buffer (`rmp` #384) so every checkpoint/flush
        // from now on is torn-write protected. `RecordStore::create`'s own initial flush already ran
        // (unprotected) above — correct, the fresh store holds no committed data yet.
        store.attach_dwb(open_or_create_dwb(device_file, master_key)?);
        // Durable-create barrier (`04 §4.9`, storage audit F1). `RecordStore::create` flushes the
        // device and `WalManager::create` hardens the WAL header, so both files' **content** is now
        // durable — but their **directory entries** are not. On ext4/XFS/btrfs/APFS an `fdatasync`
        // of a file's content does NOT harden the parent directory entry that names it, so a power
        // loss after a later `COMMIT` (which hardens the WAL content and returns success to the
        // client) could leave `store.blk` and/or `wal.log` unfindable on reboot. `open_or_create`
        // would then see an empty/absent device and create a FRESH EMPTY store, silently discarding
        // acknowledged-committed data. Hardening the directory now (both files live in the same dir,
        // so one `fsync` covers the plaintext and the encrypted paths alike) makes the entries
        // durable before the engine serves its first commit. Mirrors the create-side barrier in
        // [`provision_fresh_dir`] and the durable-rename idiom in [`crate::key_rotation`].
        fsync_parent_dir(device_file)?;
        store
    };

    // The inviolable integrity gate (`04 §4.6`/§4.8): refuse to serve a corrupt store.
    //
    // `rmp` #423 — why the index/base divergence slice is empty (`&[]`): every Graphus secondary index
    // (the node-property candidate index, the bitmap, full-text and spatial indexes) is **in-memory and
    // rebuilt from the store on each open** by `TxnCoordinator::new` below — none is durably persisted
    // independently of the store. So at open time there is no separately-durable index image that could
    // have diverged from the store base; `verify_on_open`'s index/base divergence check has nothing to
    // compare and is correctly a no-op here (the store-integrity half of `verify_on_open` still runs in
    // full). The divergence check exists for a *future* wire-durable index path; passing `&[]` is not a
    // skipped check but a faithful statement that "indexes are rebuilt, not verified, on the server open
    // path", so divergence is structurally impossible today. The
    // `secondary_indexes_are_rebuilt_not_verified_on_open` test pins this contract.
    verify_on_open(&mut store, &[])?;

    Ok(TxnCoordinator::new(store))
}

/// Derives the WAL keyring for an **existing** store by reading the per-store salt from the device
/// header (the WAL and store share one salt source, rmp #88). Returns `None` for the plaintext path.
///
/// # Errors
/// [`GraphusError`] if the device header cannot be read (the salt is needed to derive the WAL
/// subkey). A wrong key is caught later by the WAL KCV at [`open_wal_sink`].
fn wal_keyring_for_existing(
    device_file: &Path,
    master_key: Option<&MasterKey>,
) -> Result<Option<Keyring>, GraphusError> {
    match master_key {
        None => Ok(None),
        Some(key) => {
            let header = EncryptedFileDevice::read_file_header(device_file)?;
            Ok(Some(key.keyring_for(&header.salt)))
        }
    }
}

/// Creates a **fresh** record-store device for `device_file`: an encrypted file device when a master
/// key is configured (the given per-store `salt` is persisted in the header), or a plaintext file
/// device otherwise (byte-identical to before encryption existed).
fn create_store_device(
    device_file: &Path,
    master_key: Option<&MasterKey>,
    salt: Option<[u8; graphus_crypto::SALT_LEN]>,
) -> Result<StoreDevice, GraphusError> {
    match master_key {
        None => Ok(StoreDevice::Plain(FileBlockDevice::open(device_file)?)),
        Some(key) => {
            // Use the shared per-store salt (also the WAL subkey's salt source), derive the subkey,
            // and create the encrypted device (writing the header: magic, salt, KCV).
            let salt =
                salt.expect("INVARIANT: a salt is provided whenever a master key is configured");
            let keyring = key.keyring_for(&salt);
            Ok(StoreDevice::Encrypted(Box::new(
                EncryptedFileDevice::create_file(device_file, &keyring, salt)?,
            )))
        }
    }
}

/// Opens an **existing** record-store device for `device_file`: an encrypted file device when a
/// master key is configured (the per-store salt is read from the header, the subkey re-derived, and
/// the KCV verified — a wrong/missing key fails closed here), or a plaintext file device otherwise.
fn open_store_device(
    device_file: &Path,
    master_key: Option<&MasterKey>,
) -> Result<StoreDevice, GraphusError> {
    match master_key {
        None => Ok(StoreDevice::Plain(FileBlockDevice::open(device_file)?)),
        Some(key) => {
            // Probe the header to recover this store's salt, then derive the keyring and open
            // (the KCV check inside `open_file` fails closed on a wrong key, before any page read).
            let header = EncryptedFileDevice::read_file_header(device_file)?;
            let keyring = key.keyring_for(&header.salt);
            Ok(StoreDevice::Encrypted(Box::new(
                EncryptedFileDevice::open_file(device_file, &keyring)?,
            )))
        }
    }
}

/// The doublewrite-buffer file path beside a database's store device (`rmp` #384).
fn dwb_file_for(device_file: &Path) -> std::path::PathBuf {
    device_file.with_file_name(DWB_FILE_NAME)
}

/// Opens (or, on first use / a pre-#384 upgrade, creates) the persistent doublewrite buffer beside
/// `device_file`, returning a sized [`Dwb`] ready to protect home writes and run torn-page repair
/// (`rmp` #384, `05 §3`).
///
/// The DWB device is a [`StoreDevice`] — the **same** [`graphus_io::BlockDevice`] type as the store
/// device — so an encrypted store's DWB area is itself AES-256-GCM encrypted and **never** persists a
/// page image in plaintext. The DWB carries its **own** independent per-file salt (read from / written
/// to its header), so its derived store subkey is independent of the main store's: the two files do
/// not share a GCM nonce budget. The DWB content is transient page images only — no catalog, no
/// committed state — so creating it fresh when it is missing is always safe (a fresh DWB describes no
/// batch, so [`Dwb::recover_home`] finds nothing to repair).
///
/// # Errors
/// [`GraphusError`] if the DWB file cannot be opened/created or sized, or (encrypted path) if its
/// header cannot be read or its key check fails.
fn open_or_create_dwb(
    device_file: &Path,
    master_key: Option<&MasterKey>,
) -> Result<Dwb<StoreDevice>, GraphusError> {
    let dwb_file = dwb_file_for(device_file);
    let existing = dwb_file.metadata().map(|m| m.len() > 0).unwrap_or(false);
    let device = if existing {
        // Reuse the persisted DWB (it may hold a batch a crash left mid-flight — its recovery pass
        // runs in `recover_device_with_dwb` before redo). The encrypted path re-derives the subkey
        // from the DWB header's own salt and fails closed on a wrong key.
        open_store_device(&dwb_file, master_key)?
    } else {
        // First open (or a store created before #384 wired the DWB): create a fresh DWB file. It
        // describes no batch, so recovery has nothing to repair from it — safe.
        let salt = master_key.map(|_| graphus_crypto::random_salt());
        let dev = create_store_device(&dwb_file, master_key, salt)?;
        // Harden the new DWB file's directory entry so a crash cannot leave it unfindable (mirrors
        // the store/WAL durable-create barrier; same directory, so this also covers the store/WAL).
        fsync_parent_dir(&dwb_file)?;
        dev
    };
    // `Dwb::new` extends the device to `dwb_device_pages()` pages if a freshly created file is
    // shorter; the header + data slots are written on the first `stage_batch`.
    Dwb::new(device)
}

/// Creates a **fresh** WAL sink for `wal_file`: an encrypted file sink when a `keyring` is given
/// (writing the sink header: magic, version, WAL KCV), or a plaintext file sink otherwise
/// (byte-identical to before WAL encryption existed). The keyring's WAL subkey was derived from the
/// store's salt by the caller, so the WAL and store share one salt source (rmp #88).
fn create_wal_sink(wal_file: &Path, keyring: Option<&Keyring>) -> Result<WalSink, GraphusError> {
    let backing = FileLogSink::open(wal_file)
        .map_err(|e| GraphusError::Storage(format!("creating WAL: {e}")))?;
    match keyring {
        None => Ok(WalSink::Plain(backing)),
        Some(kr) => Ok(WalSink::Encrypted(Box::new(EncryptedFileLogSink::create(
            backing, kr,
        )?))),
    }
}

/// Opens an **existing** WAL sink for `wal_file`: an encrypted file sink when a `keyring` is given
/// (the sink header's magic + WAL KCV are validated — a wrong/missing key fails closed here, before
/// any frame is decrypted, and a torn tail frame is dropped), or a plaintext file sink otherwise.
fn open_wal_sink(wal_file: &Path, keyring: Option<&Keyring>) -> Result<WalSink, GraphusError> {
    let backing = FileLogSink::open(wal_file)
        .map_err(|e| GraphusError::Storage(format!("opening WAL: {e}")))?;
    match keyring {
        None => Ok(WalSink::Plain(backing)),
        Some(kr) => Ok(WalSink::Encrypted(Box::new(EncryptedFileLogSink::open(
            backing, kr,
        )?))),
    }
}

/// Spawns one database's engine thread for the store in `dir`, constructing the `!Send`
/// coordinator **on that thread** (see [`spawn_engine`]). Creates the directory if absent;
/// opening-or-creating + WAL recovery + `verify_on_open` happen on the engine thread via
/// [`open_or_create_coordinator`]. Blocking (waits for the engine's startup result); run it off
/// the runtime.
fn spawn_db_engine(
    db_name: &str,
    dir: &Path,
    params: &EngineParams,
    metrics: Arc<Metrics>,
) -> Result<Engine, GraphusError> {
    std::fs::create_dir_all(dir).map_err(|e| {
        GraphusError::Storage(format!("creating database dir {}: {e}", dir.display()))
    })?;
    let device_file = dir.join(STORE_FILE_NAME);
    let wal_file = dir.join(WAL_FILE_NAME);
    let pool_pages = params.buffer_pool_pages;
    // Crash-safe key-rotation recovery (rmp #89): complete or discard any pending master-key
    // rotation for this database BEFORE its store is opened. It is a pure filesystem operation
    // (rename/cleanup of `.rot-new` temps under a commit marker — no key needed) and a cheap no-op
    // when no rotation is pending. Only meaningful for the encrypted path: a plaintext store cannot
    // be key-rotated, so it never has rotation artifacts. Idempotent and crash-safe (see
    // [`crate::key_rotation`]). Runs on this blocking (off-runtime) thread, ahead of the engine.
    if params.master_key.is_some() {
        crate::key_rotation::recover_pending_rotation(dir, &device_file, &wal_file)?;
    }
    // The master key (if any) is cloned into the build closure (an `Arc` bump) so the `!Send`
    // coordinator can be built on the engine thread from `Send` ingredients (paths + the key).
    let master_key = params.master_key.clone();
    let build = move || {
        open_or_create_coordinator(&device_file, &wal_file, pool_pages, master_key.as_ref())
    };
    spawn_engine(
        Arc::from(db_name),
        build,
        params.engine_queue_capacity,
        params.result_buffer_capacity,
        params.reader_threads,
        metrics,
        std::sync::Arc::clone(&params.clock),
    )
}

/// Writes `bytes` to `dest` **atomically and durably** (`rmp` task #149 operator backup write): a
/// fresh sibling temp is filled + `fsync`ed, then `rename(2)`d over `dest` and the directory
/// `fsync`ed — so a crash leaves `dest` as the old whole file or the new whole file, never a torn
/// mixture. Maps the storage error to a [`CatalogError::Backup`].
fn write_file_atomic(dest: &Path, bytes: &[u8]) -> Result<(), CatalogError> {
    use std::io::Write as _;
    graphus_io::atomic_replace_file(dest, |tmp| {
        let mut f = std::fs::File::create(tmp)
            .map_err(|e| GraphusError::Storage(format!("creating backup temp: {e}")))?;
        f.write_all(bytes)
            .map_err(|e| GraphusError::Storage(format!("writing backup: {e}")))?;
        f.sync_all()
            .map_err(|e| GraphusError::Storage(format!("syncing backup: {e}")))
    })
    .map_err(|e| CatalogError::Backup(e.to_string()))
}

/// Restores `device_file` from the backup chain artifact at `src` to `target` (`rmp` task #149).
/// Reads + (optionally) unseals + decodes the artifact, then lays it down atomically with the
/// catalog's device-opening scheme so an encrypted database is restored as a valid encrypted store
/// (a fresh per-store salt). Pure blocking filesystem/crypto work — run off the runtime.
fn restore_db_file(
    src: &Path,
    device_file: &Path,
    target: graphus_storage::RestoreTarget,
    master_key: Option<&MasterKey>,
    pool_pages: usize,
) -> Result<(), CatalogError> {
    use graphus_storage::{ChainArtifact, Plain, restore_chain_file_atomic};

    let to_backup_err = |e: GraphusError| CatalogError::Backup(e.to_string());

    // 1. Read the backup file.
    let raw = std::fs::read(src)
        .map_err(|e| CatalogError::Backup(format!("reading backup file {}: {e}", src.display())))?;
    // 2. Unseal under the master key when the database is encrypted (fail-closed on wrong key/tamper).
    let plaintext = match master_key {
        Some(key) => key.open_artifact(&raw).map_err(to_backup_err)?,
        None => raw,
    };
    // 3. Decode the chain artifact (file framing) — the chain's own integrity is re-proved next.
    let artifact = ChainArtifact::decode(&plaintext).map_err(to_backup_err)?;
    let codec = Plain;

    // 4. Lay it down atomically with the right device type. The page images are plaintext above the
    //    device seam, so re-encrypting under a fresh salt is correct for an encrypted database.
    //
    //    The chain restore leaves the device at a consistent committed state needing **no** WAL
    //    replay, but the next `START DATABASE` opens the *existing* WAL file and would replay its
    //    (now stale) records onto the restored device — and for an encrypted store the old WAL's
    //    subkey no longer matches the restored device's fresh salt. So after the device is restored
    //    we reset the WAL to a fresh empty log consistent with the restored device (step 5).
    let wal_file = device_file.with_file_name(WAL_FILE_NAME);
    match master_key {
        None => {
            restore_chain_file_atomic(
                &artifact.manifest,
                &artifact.links,
                target,
                &codec,
                device_file,
                |tmp| FileBlockDevice::open(tmp),
                pool_pages,
            )
            .map_err(to_backup_err)?;
            // 5. Fresh empty plaintext WAL (recovery replays nothing on the next open).
            reset_wal(&wal_file, None).map_err(to_backup_err)?;
            // 6. Drop the prior generation's doublewrite buffer (`rmp` #417): a stale DWB could
            //    clobber a (genuinely or coincidentally) torn page of the freshly restored device on
            //    the next open. Removing it makes the next `START DATABASE` create a fresh empty DWB.
            reset_dwb(device_file).map_err(to_backup_err)?;
        }
        Some(key) => {
            let salt = graphus_crypto::random_salt();
            let keyring = key.keyring_for(&salt);
            restore_chain_file_atomic(
                &artifact.manifest,
                &artifact.links,
                target,
                &codec,
                device_file,
                |tmp| {
                    Ok(StoreDevice::Encrypted(Box::new(
                        EncryptedFileDevice::create_file(tmp, &keyring, salt)?,
                    )))
                },
                pool_pages,
            )
            .map_err(to_backup_err)?;
            // 5. Fresh empty WAL whose subkey is derived from the restored device's new salt
            //    (`wal_keyring_for_existing` reads that salt back from the device header on open).
            let wal_keyring =
                wal_keyring_for_existing(device_file, master_key).map_err(to_backup_err)?;
            reset_wal(&wal_file, wal_keyring.as_ref()).map_err(to_backup_err)?;
            // 6. Drop the prior generation's doublewrite buffer (`rmp` #417). For an encrypted store
            //    the stale DWB's subkey no longer matches the restored device's fresh salt anyway;
            //    removing it makes the next open create a fresh DWB with its own salt.
            reset_dwb(device_file).map_err(to_backup_err)?;
        }
    }
    Ok(())
}

/// Drops the doublewrite buffer beside `device_file` on restore (`rmp` #417), so no prior-generation
/// doublewrite copy can survive to clobber a torn page of the freshly restored device on the next
/// open. The DWB holds only transient page images (no committed state), so deleting it is always
/// safe: the next [`open_or_create_dwb`] recreates a fresh empty DWB (which describes no batch, so
/// [`recover_device_with_dwb`] finds nothing to repair). This mirrors [`reset_wal`]: the device was
/// restored atomically *before* this runs, so a crash between the device rename and this reset is
/// healed by re-running the idempotent (offline) restore.
fn reset_dwb(device_file: &Path) -> Result<(), GraphusError> {
    let dwb_file = dwb_file_for(device_file);
    match std::fs::remove_file(&dwb_file) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(GraphusError::Storage(format!(
                "removing the doublewrite buffer {} on restore: {e}",
                dwb_file.display()
            )));
        }
    }
    // Harden the directory entry so the deletion is durable (a crash cannot resurrect the stale DWB).
    fsync_parent_dir(&dwb_file)?;
    Ok(())
}

/// Resets the WAL at `wal_dir` to a **fresh empty WAL** consistent with a just-restored device
/// (`rmp` task #149): a plaintext WAL when `keyring` is `None`, or an encrypted WAL whose subkey is
/// derived from the restored device's salt otherwise. The next open then recovers nothing (the chain
/// restore already left the device at a consistent committed state), and an encrypted store's WAL
/// subkey matches its device again.
///
/// The Graphus WAL is a **directory** of segment files ([`FileLogSink`]), so it is reset by removing
/// the directory and recreating a fresh empty WAL in its place — not by an atomic file rename. The
/// device was restored atomically *before* this runs; should the process crash between the device
/// rename and this reset, the next open would see the restored device beside a stale WAL — the
/// operator simply re-runs the (idempotent) restore, which re-lays the device and resets the WAL
/// again. (Restore is an offline operator action, not a hot path, so this is the right trade-off.)
fn reset_wal(wal_dir: &Path, keyring: Option<&Keyring>) -> Result<(), GraphusError> {
    // Remove any existing WAL directory (segments + anchor). A missing directory is fine.
    match std::fs::remove_dir_all(wal_dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(GraphusError::Storage(format!(
                "removing the WAL directory {} on restore: {e}",
                wal_dir.display()
            )));
        }
    }
    // Create + harden a fresh empty WAL (writes the header durably into a fresh segment).
    let _wal = WalManager::create(create_wal_sink(wal_dir, keyring)?)
        .map_err(|e| GraphusError::Storage(format!("creating fresh WAL on restore: {e}")))?;
    Ok(())
}

// ------------------------------------------------------------------------------------------------
// The catalog
// ------------------------------------------------------------------------------------------------

/// One database's listing entry: name, desired + actual state, and whether it is the default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbInfo {
    /// The (lowercase) database name.
    pub name: String,
    /// The **actual** state: `Online` iff the engine is running right now.
    pub state: DbState,
    /// The durable **desired** state (always `Online` for the default database). `desired ==
    /// Online` with `state == Offline` means the engine failed to start (see [`DbInfo::error`]).
    pub desired: DbState,
    /// Whether this is the (implicit, undroppable) default database.
    pub is_default: bool,
    /// The startup error, when the engine failed to start (boot policy / a failed `start`).
    pub error: Option<String>,
}

/// One running database engine: the admission-limited client handle plus the engine thread's join
/// handle (needed for a clean stop).
struct RunningEngine {
    /// The handle handed to consumers (already carrying the per-database admission limit).
    handle: EngineHandle,
    /// The engine thread, joined when the database stops.
    join: std::thread::JoinHandle<()>,
}

/// The mutable catalog state, owned by the admin mutex (module docs: locking design).
struct AdminState {
    /// Durable desired state of every **additional** database. A `BTreeMap` so the persisted file
    /// has a deterministic order (stable diffs, reproducible tests).
    entries: BTreeMap<String, DbState>,
    /// Running engines (including the default database), keyed by name.
    running: HashMap<String, RunningEngine>,
    /// Databases whose desired state is `online` but whose engine failed to start, with the error
    /// (in-memory only — the boot policy never flips durable desired state).
    failed: BTreeMap<String, String>,
}

/// The durable catalog of named databases + the in-process registry of their running engines
/// (see the module docs for the on-disk layout, crash-safety protocol, lifecycle state model and
/// locking design).
pub struct DatabaseCatalog {
    /// The data root (`store_path`): the default database's directory and the catalog's home.
    root: PathBuf,
    /// The (normalized) default database name, from config.
    default_name: String,
    /// Engine-spawn sizing, captured from config so every database is sized identically.
    params: EngineParams,
    /// The shared metrics registry every engine reports into (a per-database split is future
    /// observability work; one registry keeps today's dashboards unchanged).
    metrics: Arc<Metrics>,
    /// Serializes all catalog mutations; async-aware because `stop`/`shutdown` await the engine's
    /// drain under the guard.
    admin: Mutex<AdminState>,
    /// The concurrent lookup view: name → admission-limited [`EngineHandle`] for **running**
    /// databases. Written only inside admin-locked sections; read lock-briefly by lookups.
    handles: RwLock<HashMap<String, EngineHandle>>,
    /// Count of **non-default** databases whose desired state is `online` but whose engine **failed to
    /// open/start** (`rmp` #430). Maintained alongside the admin-locked `failed` map, but as a
    /// lock-free atomic so `/health/ready` can read it without taking the async admin mutex. A non-zero
    /// value flips a degraded readiness signal so an orchestrator can tell that a configured database is
    /// not serving — previously such a failure was logged but readiness stayed unconditionally green
    /// (`server.rs` `readiness.set(true)`), hiding a catalog whose secondary databases all failed to
    /// open. The default database's open failure remains fatal (fails startup), so it is never counted
    /// here. Tracked as a *set size* (recomputed from the admin-locked `failed` map under the lock) so
    /// it can never drift from the authoritative map.
    failed_open_count: std::sync::atomic::AtomicUsize,
    /// Test-only persist fault seam: how many upcoming `persist_state` calls fail *before
    /// touching the filesystem* (the durable file is untouched — exactly a pre-`rename` I/O
    /// failure). The field, like the seam, does not exist in production builds.
    #[cfg(test)]
    persist_faults: std::sync::atomic::AtomicU32,
}

impl DatabaseCatalog {
    /// Loads the catalog for `config` (the usual server path): the data root is
    /// [`ServerConfig::store_path`], the default name [`ServerConfig::default_database`], and the
    /// engine sizing is captured from the config. No engine is started yet — call
    /// [`start_default`](Self::start_default) and
    /// [`start_catalog_databases`](Self::start_catalog_databases).
    ///
    /// # Errors
    /// [`CatalogError`] if the default name is invalid or the durable catalog cannot be loaded
    /// (a malformed file fails closed — module docs).
    pub fn load(config: &ServerConfig, metrics: Arc<Metrics>) -> Result<Self, CatalogError> {
        let params = EngineParams::from_config(config).map_err(CatalogError::Engine)?;
        Self::open(
            config.store_path.clone(),
            &config.default_database,
            params,
            metrics,
        )
    }

    /// Opens the catalog at `root` with an explicit default name and engine sizing (the test
    /// seam; [`load`](Self::load) is the config-driven wrapper).
    ///
    /// # Errors
    /// As [`load`](Self::load).
    pub fn open(
        root: PathBuf,
        default_database: &str,
        params: EngineParams,
        metrics: Arc<Metrics>,
    ) -> Result<Self, CatalogError> {
        let default_name = normalize_db_name(default_database)?;
        let entries = load_entries(&root, &default_name)?;
        Ok(Self {
            root,
            default_name,
            params,
            metrics,
            admin: Mutex::new(AdminState {
                entries,
                running: HashMap::new(),
                failed: BTreeMap::new(),
            }),
            handles: RwLock::new(HashMap::new()),
            failed_open_count: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            persist_faults: std::sync::atomic::AtomicU32::new(0),
        })
    }

    /// The (normalized) default database's name.
    #[must_use]
    pub fn default_database(&self) -> &str {
        &self.default_name
    }

    /// The directory holding an **additional** database's store: `<root>/databases/<name>`.
    /// (The default database lives directly in the root — module docs.)
    fn db_dir(&self, name: &str) -> PathBuf {
        self.root.join(DATABASES_DIR_NAME).join(name)
    }

    /// Looks up the running engine handle for `name` (case-insensitive). `None` when the database
    /// does not exist or is not online. Cheap and concurrent: a brief read lock + a handle clone,
    /// never held across an `.await` (module docs: locking design).
    #[must_use]
    pub fn handle(&self, name: &str) -> Option<EngineHandle> {
        let Ok(name) = normalize_db_name(name) else {
            return None;
        };
        self.read_handles().get(&name).cloned()
    }

    /// The default database's engine handle, when it is running (it always is while the server
    /// serves; `None` only before startup or during/after shutdown).
    #[must_use]
    pub fn default_handle(&self) -> Option<EngineHandle> {
        self.read_handles().get(&self.default_name).cloned()
    }

    /// The names of every **running** database whose engine is currently flagged **degraded** by a
    /// recovery double-panic (`rmp` #409/#414), in name order. Used by `/health/ready` to aggregate
    /// degradation **per database**: one degraded secondary database is surfaced (so an orchestrator
    /// can tell which database is unhealthy) without marking the whole node not-ready when other
    /// databases are healthy. A brief read lock on the handle map + per-handle atomic loads; never held
    /// across an `.await`.
    #[must_use]
    pub fn degraded_databases(&self) -> Vec<String> {
        let mut degraded: Vec<String> = self
            .read_handles()
            .iter()
            .filter(|(_, h)| h.is_degraded())
            .map(|(name, _)| name.clone())
            .collect();
        degraded.sort_unstable();
        degraded
    }

    /// Whether the **default** database's engine is degraded (`rmp` #414). The default database is the
    /// one the listeners structurally depend on, so its degradation is treated as a node-level
    /// not-ready (mirroring the pre-`rmp`-#414 whole-node behaviour); a *secondary* database's
    /// degradation is reported separately by [`degraded_databases`](Self::degraded_databases) without
    /// taking the node down.
    #[must_use]
    pub fn default_database_degraded(&self) -> bool {
        self.read_handles()
            .get(&self.default_name)
            .is_some_and(EngineHandle::is_degraded)
    }

    /// The names of every **running** database whose engine has its reclamation flagged **degraded**
    /// (`rmp` #394/#435): its background maintenance checkpoint has failed `K` times consecutively
    /// (RAM/disk/version slots stop being reclaimed while writes accrue — a slow-motion OOM), in name
    /// order. Used by `/health/ready` to aggregate reclamation degradation **per database**: one stalled
    /// secondary database is surfaced (so an orchestrator can tell which database is unhealthy) without
    /// marking the whole node not-ready when other databases are reclaiming fine. This closes the
    /// residual cross-tenant breach #414 left: the gating flag was a single shared-`Metrics` gauge, so
    /// one database's stall blanket-503'd the node and another database's checkpoint success
    /// false-cleared it; the flag is now per-engine. A brief read lock on the handle map + per-handle
    /// atomic loads; never held across an `.await`.
    #[must_use]
    pub fn maintenance_degraded_databases(&self) -> Vec<String> {
        let mut degraded: Vec<String> = self
            .read_handles()
            .iter()
            .filter(|(_, h)| h.is_maintenance_degraded())
            .map(|(name, _)| name.clone())
            .collect();
        degraded.sort_unstable();
        degraded
    }

    /// Whether the **default** database's engine has its reclamation flagged degraded (`rmp`
    /// #394/#435). The default database is the one the listeners structurally depend on, so its
    /// reclamation stall is treated as a node-level not-ready (mirroring the pre-`rmp`-#435 whole-node
    /// behaviour); a *secondary* database's stall is reported separately by
    /// [`maintenance_degraded_databases`](Self::maintenance_degraded_databases) without taking the node
    /// down.
    #[must_use]
    pub fn default_database_maintenance_degraded(&self) -> bool {
        self.read_handles()
            .get(&self.default_name)
            .is_some_and(EngineHandle::is_maintenance_degraded)
    }

    /// The number of **non-default** databases that are configured `online` but whose engine failed to
    /// open/start (`rmp` #430). Lock-free (an atomic load), so `/health/ready` can consult it without
    /// the async admin mutex. `> 0` means at least one configured database is not serving — a degraded
    /// signal an orchestrator can act on (the node still serves the default + every healthy database).
    #[must_use]
    pub fn failed_open_database_count(&self) -> usize {
        self.failed_open_count
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Recomputes [`failed_open_count`](Self::failed_open_count) from the authoritative admin-locked
    /// `failed` map (`rmp` #430). Called whenever the map changes under the admin lock, so the lock-free
    /// readiness signal can never drift from the map. The default database is never in `failed` (its
    /// open failure is fatal), so the map's size is exactly the non-default failed-open count.
    fn sync_failed_count(&self, state: &AdminState) {
        self.failed_open_count
            .store(state.failed.len(), std::sync::atomic::Ordering::Release);
    }

    /// Lists every database: the default first, then the additional ones in name order, each with
    /// desired + actual state and the startup error when the engine failed (boot policy).
    pub async fn list(&self) -> Vec<DbInfo> {
        let state = self.admin.lock().await;
        let mut out = Vec::with_capacity(state.entries.len() + 1);
        out.push(DbInfo {
            name: self.default_name.clone(),
            state: if state.running.contains_key(&self.default_name) {
                DbState::Online
            } else {
                DbState::Offline
            },
            desired: DbState::Online,
            is_default: true,
            error: None,
        });
        for (name, desired) in &state.entries {
            out.push(DbInfo {
                name: name.clone(),
                state: if state.running.contains_key(name) {
                    DbState::Online
                } else {
                    DbState::Offline
                },
                desired: *desired,
                is_default: false,
                error: state.failed.get(name).cloned(),
            });
        }
        out
    }

    /// Starts the **default** database (directly in the data root — the unchanged single-db open
    /// path) and returns its admission-limited handle. Idempotent: returns the existing handle if
    /// already running. The server calls this first at boot; a failure here fails startup
    /// (preserving single-db behaviour: a corrupt default store refuses to serve).
    ///
    /// # Errors
    /// [`GraphusError`] if the store cannot be opened/recovered/verified or the thread cannot be
    /// spawned.
    pub async fn start_default(&self) -> Result<EngineHandle, GraphusError> {
        let mut state = self.admin.lock().await;
        if let Some(running) = state.running.get(&self.default_name) {
            return Ok(running.handle.clone());
        }
        let engine = self.spawn_in(&self.default_name, self.root.clone()).await?;
        let name = self.default_name.clone();
        Ok(self.register(&mut state, &name, engine))
    }

    /// Starts every catalog database whose **desired** state is `online` (the boot
    /// reconciliation). A database that fails to open is logged and recorded as *failed* in
    /// memory — its durable desired state is **not** flipped, and the failure never prevents the
    /// server or the other databases from starting (module docs: lifecycle state model). Call
    /// after [`start_default`](Self::start_default).
    pub async fn start_catalog_databases(&self) {
        let mut state = self.admin.lock().await;
        let to_start: Vec<String> = state
            .entries
            .iter()
            .filter(|(name, desired)| {
                **desired == DbState::Online && !state.running.contains_key(*name)
            })
            .map(|(name, _)| name.clone())
            .collect();
        for name in to_start {
            match self.spawn_in(&name, self.db_dir(&name)).await {
                Ok(engine) => {
                    let _ = self.register(&mut state, &name, engine);
                    tracing::info!(db = %name, "database online");
                }
                Err(e) => {
                    tracing::error!(
                        db = %name,
                        error = %e,
                        "database failed to start; it stays offline (desired state unchanged) and \
                         the server continues",
                    );
                    state.failed.insert(name, e.to_string());
                }
            }
        }
        // Surface any boot-time open failures into the lock-free readiness signal (`rmp` #430).
        self.sync_failed_count(&state);
    }

    /// Creates a new database named `name` (case-insensitive; stored lowercase). Created
    /// databases start **online**. Durability ordering (module docs): provision the directory →
    /// persist the catalog entry → start the engine — success is reported only after the entry is
    /// durable. If the engine fails to start, the entry and directory are rolled back so a failed
    /// `create` leaves no trace.
    ///
    /// Any pre-existing directory under `databases/<name>` is an **inert orphan** (a crashed
    /// `create` before its persist, or a crashed `drop` after its persist) and is cleared first —
    /// this is what guarantees dropped data can never resurrect through a re-`create`.
    ///
    /// # Errors
    /// [`CatalogError::InvalidName`], [`CatalogError::AlreadyExists`] (including the default's
    /// name via [`CatalogError::DefaultDatabase`]), [`CatalogError::Io`] on provisioning/persist
    /// failure, or [`CatalogError::Engine`] if the fresh store cannot be started.
    pub async fn create(&self, name: &str) -> Result<EngineHandle, CatalogError> {
        let name = normalize_db_name(name)?;
        if name == self.default_name {
            return Err(CatalogError::DefaultDatabase {
                name,
                operation: "create",
            });
        }
        let mut state = self.admin.lock().await;
        if state.entries.contains_key(&name) || state.running.contains_key(&name) {
            return Err(CatalogError::AlreadyExists(name));
        }

        // 1) Provision a fresh directory (clearing an inert orphan — see the rustdoc above).
        let dir = self.db_dir(&name);
        run_blocking({
            let dir = dir.clone();
            move || provision_fresh_dir(&dir)
        })
        .await?;

        // 2) Persist the entry (state online) BEFORE starting the engine, so success is never
        //    reported for a database that would not survive a restart. On failure memory resyncs
        //    to the published file (normally: no entry — the create never happened).
        let fallback = state.entries.clone();
        state.entries.insert(name.clone(), DbState::Online);
        self.persist_or_resync(&mut state, fallback).await?;

        // 3) Start the engine (creates the fresh store + WAL in the provisioned directory).
        match self.spawn_in(&name, dir.clone()).await {
            Ok(engine) => Ok(self.register(&mut state, &name, engine)),
            Err(e) => {
                // Roll the entry back: a failed create must leave no trace. If the rollback
                // persist itself fails, memory resyncs to the published file (normally the entry
                // stays, desired online) and the boot policy will retry/report it — documented,
                // recoverable.
                let fallback = state.entries.clone();
                state.entries.remove(&name);
                if let Err(p) = self.persist_or_resync(&mut state, fallback).await {
                    tracing::error!(
                        db = %name,
                        error = %p,
                        "could not roll back the catalog entry of a failed create; the boot \
                         policy will retry/report whatever the published catalog still claims",
                    );
                } else if let Err(rm) = run_blocking(move || remove_dir(&dir)).await {
                    // The directory is an inert orphan now; a future create clears it.
                    tracing::warn!(db = %name, error = %rm, "could not remove a failed create's directory");
                }
                Err(CatalogError::Engine(e))
            }
        }
    }

    /// Starts the database `name`. Idempotent: starting a running database returns its handle.
    /// Desired-state-first ordering (module docs): the durable state is set `online` **before**
    /// the engine spawn, so a spawn failure leaves the operator's intent recorded and the boot
    /// policy retries it — exactly the semantics of a database that failed at boot.
    ///
    /// `start` of the default database returns its handle when running (it is managed by the
    /// server lifecycle) and is rejected otherwise.
    ///
    /// # Errors
    /// [`CatalogError::UnknownDatabase`], [`CatalogError::Io`] on persist failure, or
    /// [`CatalogError::Engine`] when the store cannot be opened/recovered/verified.
    pub async fn start(&self, name: &str) -> Result<EngineHandle, CatalogError> {
        let name = normalize_db_name(name)?;
        let mut state = self.admin.lock().await;
        if name == self.default_name {
            return match state.running.get(&name) {
                Some(running) => Ok(running.handle.clone()),
                None => Err(CatalogError::DefaultDatabase {
                    name,
                    operation: "start",
                }),
            };
        }
        if !state.entries.contains_key(&name) {
            return Err(CatalogError::UnknownDatabase(name));
        }
        if let Some(running) = state.running.get(&name) {
            return Ok(running.handle.clone());
        }

        // Record the durable intent first (no-op when already online, e.g. a boot-failed retry).
        if state.entries.get(&name) != Some(&DbState::Online) {
            // On failure memory resyncs to the published file (normally back to offline).
            let fallback = state.entries.clone();
            state.entries.insert(name.clone(), DbState::Online);
            self.persist_or_resync(&mut state, fallback).await?;
        }

        match self.spawn_in(&name, self.db_dir(&name)).await {
            Ok(engine) => Ok(self.register(&mut state, &name, engine)),
            Err(e) => {
                state.failed.insert(name, e.to_string());
                self.sync_failed_count(&state);
                Err(CatalogError::Engine(e))
            }
        }
    }

    /// Stops the database `name`: drains + hardens + joins its engine, then persists desired
    /// `offline`. Idempotent: stopping an already-stopped database is `Ok` (and reconciles a
    /// boot-failed database's desired state to `offline`, cancelling the boot retry). Engine-first
    /// ordering (module docs): if the persist fails after the engine stopped, the error is
    /// reported and memory resyncs to the published file — normally still `online`, so the
    /// database comes back at the next boot (a stop that did not become durable behaves as if it
    /// never happened), and a **retried `stop` re-attempts the persist**: the engine is already
    /// down, so the retry skips the drain and just persists `offline`.
    ///
    /// The default database cannot be stopped (the server's listeners depend on it; it is managed
    /// by the server lifecycle).
    ///
    /// # Errors
    /// [`CatalogError::UnknownDatabase`], [`CatalogError::DefaultDatabase`], or
    /// [`CatalogError::Io`] on persist failure.
    pub async fn stop(&self, name: &str) -> Result<(), CatalogError> {
        let name = normalize_db_name(name)?;
        if name == self.default_name {
            return Err(CatalogError::DefaultDatabase {
                name,
                operation: "stop",
            });
        }
        let mut state = self.admin.lock().await;
        let Some(desired) = state.entries.get(&name).copied() else {
            return Err(CatalogError::UnknownDatabase(name));
        };

        let was_running = match state.running.remove(&name) {
            Some(engine) => {
                self.stop_engine(&name, engine).await;
                true
            }
            None => false,
        };
        state.failed.remove(&name);
        self.sync_failed_count(&state);

        if desired == DbState::Offline && !was_running {
            // Fully idempotent: already stopped and already durable.
            return Ok(());
        }
        // On failure memory resyncs to the published file. Normally the rename never happened, so
        // the entry returns to `online` — the durable truth — and a retried `stop` (engine
        // already down ⇒ `!was_running`, desired `online`) skips the drain above and re-attempts
        // this persist. Leaving memory at `offline` here would make the retry hit the idempotency
        // check above and report success without ever persisting — the "stopped" database would
        // then resurrect at the next boot (regression-tested below).
        let fallback = state.entries.clone();
        state.entries.insert(name.clone(), DbState::Offline);
        self.persist_or_resync(&mut state, fallback).await
    }

    /// Drops the database `name`: removes its catalog entry (persisted **first**), then deletes
    /// its directory. Only allowed when the database is stopped (desired + actual offline) — stop
    /// it first. The default database can never be dropped.
    ///
    /// Persist-first ordering (module docs): a crash between the persist and the directory
    /// deletion leaves an orphan directory — inert (no catalog entry names it) and cleared by any
    /// future `create` of the same name, so dropped data can never resurrect.
    ///
    /// # Errors
    /// [`CatalogError::UnknownDatabase`], [`CatalogError::DefaultDatabase`],
    /// [`CatalogError::NotOffline`] when not stopped, or [`CatalogError::Io`] on persist/delete
    /// failure (after a failed delete the entry is already gone; the directory is an inert
    /// orphan).
    pub async fn drop_database(&self, name: &str) -> Result<(), CatalogError> {
        let name = normalize_db_name(name)?;
        if name == self.default_name {
            return Err(CatalogError::DefaultDatabase {
                name,
                operation: "drop",
            });
        }
        let mut state = self.admin.lock().await;
        let Some(desired) = state.entries.get(&name).copied() else {
            return Err(CatalogError::UnknownDatabase(name));
        };
        if desired == DbState::Online || state.running.contains_key(&name) {
            return Err(CatalogError::NotOffline(name));
        }

        // Persist the removal first; only then delete the data (module docs). On failure memory
        // resyncs to the published file: normally the entry survives and the drop can simply be
        // retried; if the rename did land, the entry is gone and the directory is an inert
        // orphan. Either way no data is deleted before the removal is durable.
        let fallback = state.entries.clone();
        state.entries.remove(&name);
        self.persist_or_resync(&mut state, fallback).await?;
        state.failed.remove(&name);
        self.sync_failed_count(&state);

        let dir = self.db_dir(&name);
        run_blocking(move || remove_dir(&dir)).await
    }

    /// The store directory of database `name`: the data root for the default database, or
    /// `<root>/databases/<name>` for an additional one (mirrors [`spawn_in`](Self::spawn_in)'s
    /// targets). `name` must already be normalized.
    fn dir_of(&self, name: &str) -> PathBuf {
        if name == self.default_name {
            self.root.clone()
        } else {
            self.db_dir(name)
        }
    }

    /// Captures an **online backup chain artifact** of database `name` and writes it atomically to
    /// `dest` (`rmp` task #149). The database must be **online**: the capture goes through its running
    /// engine ([`EngineHandle::backup`]), which quiesces and frames the store between commands without
    /// stopping it. The artifact supports point-in-time restore (`Latest` / a chosen LSN / a chosen
    /// commit timestamp) via [`restore`](Self::restore).
    ///
    /// When the database is **encrypted**, the artifact is sealed under the master key before it
    /// touches disk (rmp #89), so a backup file never leaks plaintext page images at rest. An
    /// unencrypted database writes the plaintext artifact (protect the file with filesystem
    /// permissions). The write is atomic (temp + `rename` + directory `fsync`).
    ///
    /// # Errors
    /// [`CatalogError::UnknownDatabase`] if the database is offline/unknown, [`CatalogError::Backup`]
    /// if the capture, the seal, or the file write fails.
    pub async fn backup(&self, name: &str, dest: &Path) -> Result<(), CatalogError> {
        let name = normalize_db_name(name)?;
        let handle = self
            .handle(&name)
            .ok_or_else(|| CatalogError::UnknownDatabase(name.clone()))?;
        // 1. Capture the plaintext chain artifact through the engine (online).
        let plaintext = handle
            .backup()
            .await
            .map_err(|e| CatalogError::Backup(e.to_string()))?;
        // 2. Seal under the master key when the database is encrypted.
        let bytes = match &self.params.master_key {
            Some(key) => key
                .seal_artifact(&plaintext)
                .map_err(|e| CatalogError::Backup(e.to_string()))?,
            None => plaintext,
        };
        // 3. Write atomically off the runtime (the directory `fsync` must not run on a worker).
        let dest = dest.to_path_buf();
        run_blocking(move || write_file_atomic(&dest, &bytes)).await
    }

    /// Drives a **maintenance checkpoint** of the online database `name` (`rmp` #305): a reader-safe GC
    /// pass plus a sharp checkpoint that reclaims RAM (the in-memory WAL tail), disk (sealed WAL
    /// segments below the floor) and version slots — the resource leaks that previously had no
    /// production trigger (`rmp` #305 / #313 / #315). The database must be **online**: the maintenance
    /// runs through its running engine ([`EngineHandle::checkpoint`]), between commands, without
    /// stopping it. Returns the GC pass summary.
    ///
    /// # Errors
    /// [`CatalogError::UnknownDatabase`] if the database is offline/unknown, [`CatalogError::Backup`]
    /// if the GC pass, flush, or WAL reclaim fails.
    pub async fn checkpoint(
        &self,
        name: &str,
    ) -> Result<crate::engine::CheckpointReply, CatalogError> {
        let name = normalize_db_name(name)?;
        let handle = self
            .handle(&name)
            .ok_or_else(|| CatalogError::UnknownDatabase(name.clone()))?;
        handle
            .checkpoint()
            .await
            .map_err(|e| CatalogError::Backup(e.to_string()))
    }

    /// **Restores** database `name` from the backup chain artifact at `src`, to `target`
    /// (`rmp` task #149): the whole committed chain (`RestoreTarget::Latest`), a chosen WAL
    /// `RestoreTarget::Lsn`, or a chosen `RestoreTarget::Timestamp` (PITR).
    ///
    /// The database **must be stopped** (offline) first — the restore atomically replaces the store
    /// file under it, which is only sound when no engine holds the device. The default database can
    /// never be stopped, so it cannot be restored in place while the server runs; stop the server and
    /// restore offline, or restore into a fresh named database. On success the database stays stopped;
    /// the operator restarts it (`START DATABASE`) to bring the restored data online.
    ///
    /// The artifact is unsealed under the master key when the database is encrypted, decoded, its
    /// chain re-proved (`verify_chain`, inside the file-atomic restore), and laid down with the
    /// catalog's own device-opening scheme so an encrypted database is restored as a valid encrypted
    /// store.
    ///
    /// # Errors
    /// [`CatalogError::UnknownDatabase`], [`CatalogError::DefaultDatabase`] (default cannot be
    /// restored in place), [`CatalogError::NotOffline`] (stop it first), or [`CatalogError::Backup`]
    /// if the file is missing/malformed/wrong-key or the restore fails (the target is left untouched
    /// on any error — the restore is atomic).
    pub async fn restore(
        &self,
        name: &str,
        src: &Path,
        target: graphus_storage::RestoreTarget,
    ) -> Result<(), CatalogError> {
        let name = normalize_db_name(name)?;
        if name == self.default_name {
            return Err(CatalogError::DefaultDatabase {
                name,
                operation: "restore",
            });
        }
        // The database must exist and be stopped (no running engine holding the device).
        {
            let state = self.admin.lock().await;
            if !state.entries.contains_key(&name) {
                return Err(CatalogError::UnknownDatabase(name));
            }
            if state.running.contains_key(&name) {
                return Err(CatalogError::NotOffline(name));
            }
        }
        let device_file = self.dir_of(&name).join(STORE_FILE_NAME);
        let src = src.to_path_buf();
        let master_key = self.params.master_key.clone();
        let pool_pages = self.params.buffer_pool_pages;
        run_blocking(move || {
            restore_db_file(&src, &device_file, target, master_key.as_ref(), pool_pages)
        })
        .await
    }

    /// Stops **every** running engine for process shutdown (`04 §9.4`): additional databases
    /// first, the default last (listeners may still be draining against it). Durable desired
    /// states are **not** touched — a database online at shutdown comes back online at the next
    /// boot ([`stop`](Self::stop) is the operator intent; this is process teardown). Errors are
    /// logged, never propagated: shutdown must always complete.
    pub async fn shutdown_all(&self) {
        let mut state = self.admin.lock().await;
        let mut names: Vec<String> = state.running.keys().cloned().collect();
        names.sort_unstable();
        if let Some(pos) = names.iter().position(|n| *n == self.default_name) {
            let default = names.remove(pos);
            names.push(default);
        }
        for name in names {
            if let Some(engine) = state.running.remove(&name) {
                tracing::info!(db = %name, "graceful shutdown: draining and hardening the store");
                self.stop_engine(&name, engine).await;
                tracing::info!(db = %name, "store hardened and marked clean");
            }
        }
    }

    // ---- internals ------------------------------------------------------------------------------

    /// Spawns one database's engine off the runtime (the open path blocks on WAL recovery +
    /// `verify_on_open`).
    async fn spawn_in(&self, db_name: &str, dir: PathBuf) -> Result<Engine, GraphusError> {
        let params = self.params.clone();
        let metrics = Arc::clone(&self.metrics);
        let db_name = db_name.to_owned();
        tokio::task::spawn_blocking(move || spawn_db_engine(&db_name, &dir, &params, metrics))
            .await
            .map_err(|e| GraphusError::Storage(format!("engine spawn task join: {e}")))?
    }

    /// Registers a freshly-spawned engine under `name` (admin lock held by the caller): applies
    /// the per-database admission limit, tracks the join handle, publishes the lookup handle, and
    /// clears any stale failure record.
    fn register(&self, state: &mut AdminState, name: &str, engine: Engine) -> EngineHandle {
        let handle = engine
            .handle
            .with_admission_limit(self.params.max_concurrent_queries);
        state.running.insert(
            name.to_owned(),
            RunningEngine {
                handle: handle.clone(),
                join: engine.join,
            },
        );
        state.failed.remove(name);
        self.sync_failed_count(state);
        self.write_handles().insert(name.to_owned(), handle.clone());
        handle
    }

    /// Stops one engine (admin lock held by the caller): unpublishes the lookup handle **first**
    /// (no new consumer obtains a handle to a draining engine), drains + hardens via the engine's
    /// `Shutdown` command, then joins its thread off the runtime. Errors are logged — at this
    /// point the engine is going away regardless.
    ///
    /// ## Bounded drain (`rmp` #450)
    ///
    /// Both the `Shutdown` round-trip **and** the subsequent thread `join` are wrapped in a
    /// [`tokio::time::timeout`] of [`EngineParams::engine_shutdown_timeout`]. A *wedged* engine thread
    /// (a hung storage syscall, a buffer-pool livelock) would otherwise make `shutdown().await` —
    /// `recv_async` on the reply — block forever, and because `shutdown_all` holds the admin lock for the
    /// whole teardown, every **other** tenant's `CREATE/DROP/START/STOP DATABASE` would block until the
    /// process is externally `SIGKILL`ed. On elapse we **force-detach**: log the wedged engine, abandon
    /// its (detached) thread, and return so teardown proceeds to the next database. Durability is **not**
    /// compromised — every acked commit is already in the WAL by the group-commit rule, so a forcibly
    /// abandoned engine recovers cleanly on next open; only the *graceful* clean-checkpoint optimisation
    /// is skipped for that one wedged database. The healthy engines still drain within their own
    /// deadlines.
    async fn stop_engine(&self, name: &str, engine: RunningEngine) {
        self.write_handles().remove(name);
        let deadline = self.params.engine_shutdown_timeout;
        match tokio::time::timeout(deadline, engine.handle.shutdown()).await {
            // Drain round-trip completed within the deadline (cleanly or with a flush error).
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::error!(db = %name, error = %e, "error hardening the store on stop");
            }
            // The engine did not even acknowledge `Shutdown` within the deadline: it is wedged. Do NOT
            // wait on the join (it would block just as long). Force-detach and proceed — the admin lock
            // is released for the next database / other tenants' admin ops.
            Err(_elapsed) => {
                tracing::error!(
                    db = %name,
                    timeout_ms = deadline.as_millis() as u64,
                    "engine did not drain within the shutdown deadline; force-detaching the wedged \
                     engine and proceeding (durability is preserved — acked commits are already in the \
                     WAL; the store recovers cleanly on next open)",
                );
                // Drop the join handle WITHOUT joining: the OS thread is detached and torn down with the
                // process. Joining a wedged thread is the very hang this fix exists to prevent.
                drop(engine.join);
                return;
            }
        }
        // The drain completed; join the (now-exiting) thread, but still bounded so a thread that
        // acknowledged `Shutdown` yet wedged during its final flush cannot hang teardown either.
        let join = engine.join;
        match tokio::time::timeout(deadline, tokio::task::spawn_blocking(move || join.join())).await
        {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(_panic))) => tracing::error!(db = %name, "engine thread panicked"),
            Ok(Err(e)) => tracing::error!(db = %name, error = %e, "joining engine thread"),
            Err(_elapsed) => tracing::error!(
                db = %name,
                timeout_ms = deadline.as_millis() as u64,
                "engine thread did not exit within the shutdown deadline after draining; detaching it",
            ),
        }
    }

    /// Persists a snapshot of `entries` off the runtime (the fsync-bearing atomic replace must
    /// not run on a Tokio worker — `04 §9.1`).
    async fn persist_state(&self, entries: &BTreeMap<String, DbState>) -> Result<(), CatalogError> {
        // Test-only fault seam (`inject_persist_faults`); compiled out of production builds.
        #[cfg(test)]
        self.maybe_inject_persist_fault()?;
        let root = self.root.clone();
        let err_path = self.root.join(CATALOG_FILE_NAME);
        let snapshot = entries.clone();
        tokio::task::spawn_blocking(move || persist_entries(&root, &snapshot))
            .await
            .map_err(|e| CatalogError::Io {
                path: err_path,
                source: format!("persist task join: {e}"),
            })?
    }

    /// Persists `state.entries` via [`Self::persist_state`]; on a persist **failure**, resyncs
    /// the in-memory entries from the file actually published on disk instead of blindly rolling
    /// back. The atomic-replace protocol can fail on either side of its `rename`: before it (the
    /// old file is still published) or after it (the new file is already visible — and may
    /// survive a crash even though its parent-directory `fsync` failed). A blind rollback would
    /// diverge from disk in the second case, so memory follows whatever the filesystem says.
    /// Best effort: when the reload itself also fails, memory falls back to `fallback` (the
    /// caller's pre-mutation snapshot — the old rollback behaviour) and the possible divergence
    /// is logged at error level. The original persist error is returned either way.
    async fn persist_or_resync(
        &self,
        state: &mut AdminState,
        fallback: BTreeMap<String, DbState>,
    ) -> Result<(), CatalogError> {
        let Err(persist_err) = self.persist_state(&state.entries).await else {
            return Ok(());
        };
        match self.reload_entries().await {
            Ok(published) => state.entries = published,
            Err(reload_err) => {
                tracing::error!(
                    error = %persist_err,
                    reload_error = %reload_err,
                    "catalog persist failed AND the published catalog could not be reloaded; \
                     falling back to the pre-mutation in-memory state (may diverge from disk \
                     until the next successful persist or reboot)",
                );
                state.entries = fallback;
            }
        }
        Err(persist_err)
    }

    /// Reloads the published catalog file off the runtime (the resync half of
    /// [`Self::persist_or_resync`]).
    async fn reload_entries(&self) -> Result<BTreeMap<String, DbState>, CatalogError> {
        let root = self.root.clone();
        let default_name = self.default_name.clone();
        tokio::task::spawn_blocking(move || load_entries(&root, &default_name))
            .await
            .map_err(|e| CatalogError::Encode(format!("catalog reload task join: {e}")))?
    }

    /// Test-only: arms the persist fault seam — the next `n` [`Self::persist_state`] calls fail
    /// *before touching the filesystem* (before the temp write and the rename), exactly like a
    /// pre-`rename` I/O error on the catalog file. The seam (this method, its consumer and the
    /// backing field) is `#[cfg(test)]`: production builds compile without it, byte-identical.
    #[cfg(test)]
    fn inject_persist_faults(&self, n: u32) {
        self.persist_faults
            .store(n, std::sync::atomic::Ordering::SeqCst);
    }

    /// Test-only: consumes one armed persist fault, if any (see
    /// [`Self::inject_persist_faults`]).
    #[cfg(test)]
    fn maybe_inject_persist_fault(&self) -> Result<(), CatalogError> {
        use std::sync::atomic::Ordering;
        if self
            .persist_faults
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(CatalogError::Io {
                path: self.root.join(CATALOG_FILE_NAME),
                source: "injected persist fault (test seam; fails before the write/rename)"
                    .to_owned(),
            });
        }
        Ok(())
    }

    /// The handles map's read guard, recovering from poisoning (the map holds only cheap handle
    /// clones, so the data is always valid; recovering beats cascading a panic into shutdown).
    fn read_handles(&self) -> std::sync::RwLockReadGuard<'_, HashMap<String, EngineHandle>> {
        self.handles.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// The handles map's write guard (same poisoning recovery as [`Self::read_handles`]).
    fn write_handles(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, EngineHandle>> {
        self.handles.write().unwrap_or_else(PoisonError::into_inner)
    }
}

impl std::fmt::Debug for DatabaseCatalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabaseCatalog")
            .field("root", &self.root)
            .field("default_database", &self.default_name)
            .finish_non_exhaustive()
    }
}

/// Clears any pre-existing directory at `dir` (an inert orphan — see [`DatabaseCatalog::create`])
/// and creates it fresh, then **hardens the result with directory `fsync`s** before returning.
///
/// The `fsync` barrier is what stops dropped data from resurrecting. POSIX `fsync` gives **no
/// cross-directory (or directory-vs-file) ordering guarantee**: a `drop`'s `remove_dir_all` only
/// dirties the page cache, so without a barrier a subsequent `create` of the same name could make
/// its `online` catalog entry durable (the catalog persist fsyncs the data root) while the
/// *unlinks* of the old store files were still volatile. A crash can then replay the directory
/// tree without the unlinks (e.g. a btrfs tree-log replay), and the next boot would find the OLD
/// dropped store files under a name the catalog claims online — [`open_or_create_coordinator`]
/// would see a non-empty device and serve the dropped data. Syncing the freshly created database
/// directory (its empty entry list) **and** its parent (`<root>/databases/` — the entry for the
/// directory itself) makes "the directory exists and is empty" durable *before* the catalog can
/// claim the name online. (`<root>`'s own entry for `databases/` is hardened by the catalog
/// persist that immediately follows in `create`, which fsyncs the data root.)
fn provision_fresh_dir(dir: &Path) -> Result<(), CatalogError> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_error(dir, "clearing orphan database directory", &e)),
    }
    // Create the parent explicitly first, so both fsync targets below exist even on the very
    // first `create` (when `<root>/databases/` is not there yet).
    let parent = dir.parent().ok_or_else(|| CatalogError::Io {
        path: dir.to_path_buf(),
        source: "database directory has no parent".to_owned(),
    })?;
    std::fs::create_dir_all(parent)
        .map_err(|e| io_error(parent, "creating databases directory", &e))?;
    std::fs::create_dir_all(dir).map_err(|e| io_error(dir, "creating database directory", &e))?;
    // The durability barrier (see above): the fresh directory's (empty) entry list first, then
    // the parent's entry for the directory itself.
    fsync_dir(dir)?;
    fsync_dir(parent)
}

/// Removes a database directory; an already-absent directory is fine (idempotent). After a
/// successful removal the parent directory (`<root>/databases/`) is `fsync`ed, hardening the
/// unlink: `fsync` has no cross-directory ordering, so without this barrier the removal could
/// still be sitting in the page cache when a later mutation makes catalog state durable that
/// assumes it happened — the belt-and-braces closing, from the drop side, of the same
/// resurrection window [`provision_fresh_dir`] closes from the create side.
fn remove_dir(dir: &Path) -> Result<(), CatalogError> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io_error(dir, "removing database directory", &e)),
    }
    match dir.parent() {
        // The parent necessarily exists: a child of it was just removed.
        Some(parent) => fsync_dir(parent),
        None => Ok(()),
    }
}

/// `fsync`s the directory that contains `file`, hardening the (just-created) directory entry that
/// names it — the engine-thread counterpart of [`fsync_dir`] that maps to a [`GraphusError`] and is
/// keyed off a file path. Used by [`open_or_create_coordinator`]'s durable-create barrier so a fresh
/// store + WAL are findable after a crash (storage audit F1, `04 §4.9`).
///
/// # Errors
/// Returns a storage error if `file` has no parent directory or the directory `fsync` fails.
fn fsync_parent_dir(file: &Path) -> Result<(), GraphusError> {
    let dir = file.parent().ok_or_else(|| {
        GraphusError::Storage(format!(
            "file {} has no parent directory to fsync",
            file.display()
        ))
    })?;
    let f = std::fs::File::open(dir).map_err(|e| {
        GraphusError::Storage(format!("opening directory {} to fsync: {e}", dir.display()))
    })?;
    f.sync_all()
        .map_err(|e| GraphusError::Storage(format!("syncing directory {}: {e}", dir.display())))
}

/// Opens `dir` and `fsync`s it, hardening its directory entries (creations and unlinks) — the
/// standard POSIX way to make directory-level changes durable.
fn fsync_dir(dir: &Path) -> Result<(), CatalogError> {
    let f =
        std::fs::File::open(dir).map_err(|e| io_error(dir, "opening directory to fsync", &e))?;
    f.sync_all()
        .map_err(|e| io_error(dir, "syncing directory", &e))
}

/// Runs a blocking catalog filesystem step off the runtime, mapping a task-join failure to a
/// catalog error.
async fn run_blocking<F>(f: F) -> Result<(), CatalogError>
where
    F: FnOnce() -> Result<(), CatalogError> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| CatalogError::Encode(format!("catalog task join: {e}")))?
}

// ------------------------------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique temp data root for one test (auto-removed on drop).
    struct TempRoot {
        path: PathBuf,
    }

    impl TempRoot {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock after epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "graphus-dbcatalog-{tag}-{nanos}-{}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create temp root");
            Self { path }
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn test_params() -> EngineParams {
        EngineParams {
            buffer_pool_pages: 256,
            engine_queue_capacity: 64,
            result_buffer_capacity: 32,
            max_concurrent_queries: 16,
            reader_threads: 2,
            master_key: None,
            clock: std::sync::Arc::new(crate::server::SystemClock),
            engine_shutdown_timeout: std::time::Duration::from_secs(10),
        }
    }

    fn open_catalog(root: &TempRoot) -> DatabaseCatalog {
        DatabaseCatalog::open(
            root.path.clone(),
            DEFAULT_DATABASE_NAME,
            test_params(),
            Arc::new(Metrics::new()),
        )
        .expect("open catalog")
    }

    // ---- name validation matrix -----------------------------------------------------------------

    #[test]
    fn name_validation_matrix() {
        // Accepted (and normalized to lowercase).
        for (raw, normalized) in [
            ("a", "a"),
            ("graph", "graph"),
            ("abc-def_1", "abc-def_1"),
            ("Analytics", "analytics"),
            ("  padded  ", "padded"),
            ("z9", "z9"),
        ] {
            assert_eq!(
                normalize_db_name(raw).expect("valid name"),
                normalized,
                "{raw:?} should normalize to {normalized:?}"
            );
        }
        // Exactly the maximum length is accepted; one more is rejected.
        let max = format!("a{}", "b".repeat(MAX_DB_NAME_LEN - 1));
        assert_eq!(normalize_db_name(&max).expect("max-length name"), max);
        let too_long = format!("a{}", "b".repeat(MAX_DB_NAME_LEN));
        assert!(matches!(
            normalize_db_name(&too_long),
            Err(CatalogError::InvalidName(_))
        ));
        // Rejected: empty, bad first char, separators, traversal, spaces, non-ASCII.
        for raw in [
            "",
            " ",
            "1abc",
            "-abc",
            "_abc",
            "a/b",
            "a\\b",
            "a.b",
            ".",
            "..",
            "a b",
            "ção",
            "UPPER CASE",
            "a:b",
        ] {
            assert!(
                matches!(normalize_db_name(raw), Err(CatalogError::InvalidName(_))),
                "{raw:?} should be rejected"
            );
        }
    }

    // ---- durable file round-trip + crash-safety contract ------------------------------------------

    #[test]
    fn catalog_round_trips_through_the_file() {
        let root = TempRoot::new("roundtrip");
        let mut entries = BTreeMap::new();
        entries.insert("alpha".to_owned(), DbState::Online);
        entries.insert("beta".to_owned(), DbState::Offline);
        persist_entries(&root.path, &entries).expect("persist");

        let loaded = load_entries(&root.path, DEFAULT_DATABASE_NAME).expect("load");
        assert_eq!(loaded, entries);
        // No temp file is left behind by a successful persist.
        assert!(!root.path.join(CATALOG_TMP_NAME).exists());
    }

    #[test]
    fn absent_catalog_means_no_additional_databases() {
        let root = TempRoot::new("absent");
        let loaded = load_entries(&root.path, DEFAULT_DATABASE_NAME).expect("load");
        assert!(loaded.is_empty());
        // Loading never creates the file (backward compat: an old store dir stays untouched).
        assert!(!root.path.join(CATALOG_FILE_NAME).exists());
    }

    // ---- durable-create barrier (storage audit F1) ------------------------------------------------

    /// The directory-`fsync` barrier hardens a real directory and refuses a parentless path. The
    /// `fsync` itself (directory entries made durable) is, like [`provision_fresh_dir`]'s barrier,
    /// asserted by code review — proving it would require crash simulation — but the happy and error
    /// control-flow paths are exercised here so a regression in the call surface is caught.
    #[test]
    fn fsync_parent_dir_hardens_a_directory_and_rejects_a_parentless_path() {
        let root = TempRoot::new("fsync-parent");
        let file = root.path.join("some.file");
        std::fs::write(&file, b"x").expect("write file");
        fsync_parent_dir(&file).expect("fsync the parent of an existing file");
        // The filesystem root has no parent directory to harden.
        assert!(matches!(
            fsync_parent_dir(Path::new("/")),
            Err(GraphusError::Storage(_))
        ));
    }

    /// A freshly-created store + WAL round-trips through a drop and reopen for BOTH the plaintext and
    /// the encrypted path — proving the durable-create barrier (the `fsync_parent_dir` added to the
    /// fresh-create branch) does not break create/recover/`verify_on_open`, and that both files are
    /// created in, and findable from, their directory. This is the functional guard for F1; the
    /// power-loss durability the barrier provides is covered by code review (see the barrier comment).
    #[test]
    fn fresh_create_round_trips_through_reopen_plaintext_and_encrypted() {
        for tag in ["create-plain", "create-enc"] {
            let root = TempRoot::new(tag);
            let dir = root.path.join("db");
            std::fs::create_dir_all(&dir).expect("create db dir");
            let device_file = dir.join(STORE_FILE_NAME);
            let wal_file = dir.join(WAL_FILE_NAME);

            // Only the encrypted variant configures a master key (a valid 32-byte key file).
            let master_key = if tag == "create-enc" {
                let key_file = root.path.join("key.bin");
                std::fs::write(&key_file, [0x42u8; graphus_crypto::KEY_LEN]).expect("write key");
                Some(MasterKey::load_from_file(&key_file).expect("load master key"))
            } else {
                None
            };

            // Fresh create: exercises the durable-create barrier (fsync of the containing dir).
            {
                let coord =
                    open_or_create_coordinator(&device_file, &wal_file, 64, master_key.as_ref())
                        .expect("fresh create");
                drop(coord); // close the files so they can be reopened below
            }
            // Both files exist and are findable from the directory.
            assert!(device_file.exists(), "{tag}: store file should exist");
            assert!(wal_file.exists(), "{tag}: WAL file should exist");

            // Reopen via the existing-store path (WAL recovery + verify_on_open) — must succeed.
            let reopened =
                open_or_create_coordinator(&device_file, &wal_file, 64, master_key.as_ref())
                    .unwrap_or_else(|e| panic!("{tag}: reopen failed: {e}"));
            drop(reopened);
        }
    }

    /// `rmp` #384 — the doublewrite buffer is wired into the **production** open/checkpoint path: a
    /// torn home data page injected after a checkpoint (which stages every home page into the
    /// persistent DWB) is **repaired** on reopen via [`open_or_create_coordinator`]
    /// (`recover_device_with_dwb` runs before ARIES redo), and the post-recovery consistency checker
    /// ([`verify_on_open`], invoked inside the open path) passes.
    ///
    /// Before this wiring the production open used the non-DWB `recover_device` and checkpoint never
    /// staged into a DWB, so a torn home page failed `verify_on_open` and the reopen errored. The
    /// final assertion (reopen succeeds with the checker green) therefore fails before the wiring and
    /// passes after.
    ///
    /// The tear is modelled exactly as a mid-flush power loss: the DWB batch is staged-and-synced,
    /// the home write tears, and the crash happens **before** the batch is cleared — so the DWB still
    /// holds the intact copy when recovery runs. We drive `flush_protected` directly (which stages
    /// without clearing) to reproduce that window, then corrupt a home record page on disk.
    #[test]
    fn torn_home_page_is_repaired_on_production_reopen_via_doublewrite() {
        use graphus_core::TxnId;
        use graphus_io::PAGE_SIZE;

        let root = TempRoot::new("dwb-torn-repair");
        let dir = root.path.join("db");
        std::fs::create_dir_all(&dir).expect("create db dir");
        let device_file = dir.join(STORE_FILE_NAME);
        let wal_file = dir.join(WAL_FILE_NAME);
        let dwb_file = dir.join(DWB_FILE_NAME);

        // 1. Fresh create via the production path, then write enough nodes to allocate several record
        //    pages and commit, so there is a real home record page to tear.
        {
            let coord = open_or_create_coordinator(&device_file, &wal_file, 64, None)
                .expect("fresh create");
            coord.with_store_mut(|s| {
                let txn = TxnId(1);
                s.begin(txn);
                for _ in 0..400 {
                    s.create_node(txn).expect("create node");
                }
                s.commit(txn).expect("commit");
                // Stage every home page into the persistent DWB and write them home — WITHOUT
                // clearing the batch (models the crash window: staged+synced, home torn, no clear).
                let mut dwb = open_or_create_dwb(&device_file, None).expect("open dwb");
                s.flush_protected(&mut dwb).expect("flush_protected");
            });
            drop(coord);
        }
        assert!(dwb_file.exists(), "the persistent DWB file must exist");

        // 2. Find a non-metadata home page with a valid checksum and TEAR it on disk (corrupt a body
        //    byte so its CRC32C fails) — exactly a torn home write. Its intact copy is in the DWB.
        let mut bytes = std::fs::read(&device_file).expect("read store file");
        let page_count = bytes.len() / PAGE_SIZE;
        let mut torn_page = None;
        for p in 1..page_count {
            let off = p * PAGE_SIZE;
            let page: &[u8; PAGE_SIZE] = bytes[off..off + PAGE_SIZE].try_into().expect("page");
            if graphus_storage::page::verify_checksum(page)
                && graphus_storage::page::page_id(page) != 0
            {
                // Corrupt a mid-page body byte (well past the 24-byte header) so the checksum fails
                // but the page is still self-identifying (a realistic torn write).
                bytes[off + 1000] ^= 0xFF;
                torn_page = Some(p);
                break;
            }
        }
        let torn_page = torn_page.expect("a non-metadata home page to tear");
        std::fs::write(&device_file, &bytes).expect("write torn store file");

        // Precondition: the torn page now fails its checksum on disk.
        {
            let disk = std::fs::read(&device_file).expect("reread");
            let off = torn_page * PAGE_SIZE;
            let page: &[u8; PAGE_SIZE] = disk[off..off + PAGE_SIZE].try_into().expect("page");
            assert!(
                !graphus_storage::page::verify_checksum(page),
                "the injected tear must corrupt home page {torn_page}"
            );
        }

        // 3. Reopen via the PRODUCTION path. `recover_device_with_dwb` repairs the torn page from the
        //    DWB before redo, and the open path's `verify_on_open` (the consistency checker) passes.
        let reopened = open_or_create_coordinator(&device_file, &wal_file, 64, None)
            .expect("production reopen must repair the torn page and pass the consistency checker");
        drop(reopened);

        // 4. The repaired home page is intact on disk after recovery.
        let disk = std::fs::read(&device_file).expect("reread after recovery");
        let off = torn_page * PAGE_SIZE;
        let page: &[u8; PAGE_SIZE] = disk[off..off + PAGE_SIZE].try_into().expect("page");
        assert!(
            graphus_storage::page::verify_checksum(page),
            "home page {torn_page} must be intact after doublewrite repair"
        );
    }

    /// `rmp` #407 — the doublewrite buffer also protects the buffer pool's **eviction/steal**
    /// home-write path (not just checkpoint). A dirty home data page written home by the **evictor**
    /// (pool smaller than the working set, NO checkpoint) is staged into the persistent DWB by the
    /// installed [`graphus_storage::DwbPageStager`] before its home write; if that home write tears,
    /// the production reopen ([`recover_device_with_dwb`] before redo) repairs it from the DWB copy
    /// and `verify_on_open` passes.
    ///
    /// Before #407 the evictor wrote dirty home pages **directly**, with no DWB staging, so a torn
    /// eviction write had no intact copy — the reopen's consistency checker would reject the corrupt
    /// page. This test forces eviction (a tiny pool, auto-checkpoint disabled so the DWB's last batch
    /// is an *eviction* batch, never cleared by a checkpoint), tears exactly the home page the DWB's
    /// surviving batch protects, and asserts the production reopen repairs it. It fails before the
    /// eviction-path stager wiring and passes after.
    #[test]
    fn torn_evicted_home_page_is_repaired_on_production_reopen_via_doublewrite() {
        use graphus_core::TxnId;
        use graphus_io::PAGE_SIZE;

        let root = TempRoot::new("dwb-evict-torn-repair");
        let dir = root.path.join("db");
        std::fs::create_dir_all(&dir).expect("create db dir");
        let device_file = dir.join(STORE_FILE_NAME);
        let wal_file = dir.join(WAL_FILE_NAME);
        let dwb_file = dir.join(DWB_FILE_NAME);

        // 1. Fresh create via the production path with a TINY buffer pool, so a working set larger than
        //    the pool forces the evictor to steal (and write home) dirty pages. Disable auto-checkpoint
        //    so the DWB's surviving batch is an EVICTION batch — never cleared by a checkpoint's
        //    flush_protected. The committed work is durable in the WAL regardless.
        let pool_pages = 6;
        {
            let coord = open_or_create_coordinator(&device_file, &wal_file, pool_pages, None)
                .expect("fresh create");
            coord.with_store_mut(|s| {
                s.set_checkpoint_interval_bytes(0); // no auto-checkpoint: keep the eviction DWB batch
                let txn = TxnId(1);
                s.begin(txn);
                // Far more nodes than the tiny pool can hold resident → many record pages allocated
                // and evicted (each eviction stages its dirty home page into the DWB, then writes it
                // home). The LAST eviction's batch is what survives in the single-slot DWB.
                for _ in 0..2000 {
                    s.create_node(txn).expect("create node");
                }
                s.commit(txn).expect("commit");
            });
            drop(coord);
        }
        assert!(dwb_file.exists(), "the persistent DWB file must exist");

        // 2. Discover which home page the DWB's surviving (eviction) batch protects, and tear EXACTLY
        //    that page on disk — a torn eviction write whose intact copy is the DWB batch. Reading the
        //    DWB through a fresh `Dwb` over the same file decodes its current batch's home ids.
        let staged = {
            let dwb = open_or_create_dwb(&device_file, None).expect("open dwb");
            // The eviction path stages into the DWB's EVICTION region (disjoint from the checkpoint
            // batch region, `rmp` #412), so read the eviction region's occupant, not the batch region.
            dwb.evicted_home_ids().expect("decode dwb eviction batch")
        };
        assert!(
            !staged.is_empty(),
            "the DWB eviction region must hold an eviction batch (no checkpoint cleared it) — got \
             none, so no eviction staged into the DWB"
        );

        let mut bytes = std::fs::read(&device_file).expect("read store file");
        let page_count = (bytes.len() / PAGE_SIZE) as u64;
        // Pick a staged home page that is in range, non-metadata, and currently intact on disk (its
        // home write completed), then tear a mid-body byte so its CRC32C fails — a torn home write.
        let mut torn_page = None;
        for home in &staged {
            let p = home.0;
            if p == 0 || p >= page_count {
                continue;
            }
            let off = (p as usize) * PAGE_SIZE;
            let page: &[u8; PAGE_SIZE] = bytes[off..off + PAGE_SIZE].try_into().expect("page");
            if graphus_storage::page::verify_checksum(page)
                && graphus_storage::page::page_id(page) == p
            {
                bytes[off + 1000] ^= 0xFF;
                torn_page = Some(p as usize);
                break;
            }
        }
        let torn_page = torn_page.expect("a staged, intact, non-metadata home page to tear");
        std::fs::write(&device_file, &bytes).expect("write torn store file");

        // Precondition: the torn page now fails its checksum on disk.
        {
            let disk = std::fs::read(&device_file).expect("reread");
            let off = torn_page * PAGE_SIZE;
            let page: &[u8; PAGE_SIZE] = disk[off..off + PAGE_SIZE].try_into().expect("page");
            assert!(
                !graphus_storage::page::verify_checksum(page),
                "the injected tear must corrupt evicted home page {torn_page}"
            );
        }

        // 3. Reopen via the PRODUCTION path. `recover_device_with_dwb` repairs the torn evicted page
        //    from the DWB before redo, and the open path's `verify_on_open` (consistency checker)
        //    passes. Before the eviction-path stager wiring the evicted page had no DWB copy, so this
        //    reopen would error.
        let reopened = open_or_create_coordinator(&device_file, &wal_file, pool_pages, None).expect(
            "production reopen must repair the torn EVICTED home page and pass the consistency checker",
        );
        drop(reopened);

        // 4. The repaired home page is intact on disk after recovery.
        let disk = std::fs::read(&device_file).expect("reread after recovery");
        let off = torn_page * PAGE_SIZE;
        let page: &[u8; PAGE_SIZE] = disk[off..off + PAGE_SIZE].try_into().expect("page");
        assert!(
            graphus_storage::page::verify_checksum(page),
            "evicted home page {torn_page} must be intact after doublewrite repair"
        );
    }

    /// `rmp` #417 — a restore must drop the prior generation's doublewrite buffer, so no stale
    /// doublewrite copy can clobber a (genuinely or coincidentally) torn page of the freshly restored
    /// device on the next open.
    ///
    /// We build a DWB file holding a real durable batch (a staged copy of a home page), then run
    /// [`reset_dwb`] (the companion to [`reset_wal`] the restore path calls). After it, the DWB file
    /// must be gone — so it carries NO header/ring-slot describing any batch — and the next
    /// [`open_or_create_dwb`] must recreate a fresh, empty DWB that [`Dwb::recover_home`] finds nothing
    /// to repair from. This proves `restore_db_file`'s DWB reset clears every DWB header.
    ///
    /// Fails before the fix (no `reset_dwb`: the stale DWB file survives the restore, still describing
    /// its old batch); passes after (the file is removed, so a fresh empty DWB is created on open).
    #[test]
    fn restore_resets_the_dwb() {
        use graphus_core::{Lsn, PageId};
        use graphus_io::{BlockDevice, PAGE_SIZE, Page};

        let root = TempRoot::new("dwb-restore-reset");
        let dir = root.path.join("db");
        std::fs::create_dir_all(&dir).expect("create db dir");
        let device_file = dir.join(STORE_FILE_NAME);
        let dwb_file = dir.join(DWB_FILE_NAME);

        // 1. Create a DWB beside the (notional) device and stage a real durable batch into it, so it
        //    holds a copy describing a committed home page — the "prior generation" doublewrite copy.
        let staged_home = PageId(2);
        {
            let mut dwb = open_or_create_dwb(&device_file, None).expect("open dwb");
            let mut image: Page = [0xAB; PAGE_SIZE];
            graphus_storage::page::set_page_id(&mut image, staged_home.0);
            graphus_storage::page::set_page_lsn(&mut image, Lsn(50));
            graphus_storage::page::write_checksum(&mut image);
            dwb.stage_batch(&[(staged_home, &image)]).expect("stage");
            assert_eq!(
                dwb.staged_home_ids().expect("ids"),
                vec![staged_home],
                "precondition: the DWB must describe the staged batch before reset"
            );
        }
        assert!(dwb_file.exists(), "the DWB file must exist before reset");

        // 2. The restore path's DWB reset (`rmp` #417).
        reset_dwb(&device_file).expect("reset_dwb");

        // 3. THE GATE: no stale DWB copy survives — the file is gone, so it describes no batch in ANY
        //    region (batch or ring). A fresh open recreates an empty DWB with nothing to repair.
        assert!(
            !dwb_file.exists(),
            "rmp #417: the prior-generation DWB must be removed by the restore reset"
        );
        let fresh = open_or_create_dwb(&device_file, None).expect("recreate dwb after reset");
        assert!(
            fresh.staged_home_ids().expect("ids").is_empty(),
            "the recreated DWB's batch region must describe no batch"
        );
        assert!(
            fresh.evicted_home_ids().expect("ring ids").is_empty(),
            "the recreated DWB's eviction ring must describe no batch"
        );

        // And a fresh DWB repairs nothing on a clean home device (no stale copy to apply).
        let mut dwb = fresh;
        let mut home = graphus_io::MemBlockDevice::new(4);
        let mut intact: Page = [0u8; PAGE_SIZE];
        graphus_storage::page::set_page_id(&mut intact, staged_home.0);
        graphus_storage::page::write_checksum(&mut intact);
        home.write_page(staged_home, &intact).expect("write home");
        home.sync_data().expect("sync");
        assert_eq!(
            dwb.recover_home(&mut home).expect("recover"),
            0,
            "a DWB recreated after the restore reset must hold no stale copy to apply"
        );
    }

    #[test]
    fn stale_tmp_is_removed_and_the_valid_file_wins() {
        let root = TempRoot::new("staletmp");
        let mut entries = BTreeMap::new();
        entries.insert("alpha".to_owned(), DbState::Online);
        persist_entries(&root.path, &entries).expect("persist");
        // Simulate a crash mid-write of a later mutation: a garbage temp next to the valid file.
        std::fs::write(root.path.join(CATALOG_TMP_NAME), b"%% garbage %%").expect("plant tmp");

        let loaded = load_entries(&root.path, DEFAULT_DATABASE_NAME).expect("load");
        assert_eq!(loaded, entries, "the published file is authoritative");
        assert!(
            !root.path.join(CATALOG_TMP_NAME).exists(),
            "the stale temp is cleaned up"
        );
    }

    #[test]
    fn malformed_catalog_fails_closed() {
        let cases: &[(&str, &str)] = &[
            ("garbage", "%% not toml %%"),
            ("bad-version", "version = 2\n"),
            (
                "missing-version",
                "[[databases]]\nname = \"a\"\nstate = \"online\"\n",
            ),
            (
                "invalid-name",
                "version = 1\n[[databases]]\nname = \"has space\"\nstate = \"online\"\n",
            ),
            (
                "not-lowercase",
                "version = 1\n[[databases]]\nname = \"Alpha\"\nstate = \"online\"\n",
            ),
            (
                "duplicate",
                "version = 1\n\
                 [[databases]]\nname = \"alpha\"\nstate = \"online\"\n\
                 [[databases]]\nname = \"alpha\"\nstate = \"offline\"\n",
            ),
            (
                "lists-default",
                "version = 1\n[[databases]]\nname = \"graphus\"\nstate = \"online\"\n",
            ),
            ("unknown-field", "version = 1\nsurprise = true\n"),
            (
                "bad-state",
                "version = 1\n[[databases]]\nname = \"a\"\nstate = \"paused\"\n",
            ),
        ];
        for (tag, text) in cases {
            let root = TempRoot::new(&format!("malformed-{tag}"));
            std::fs::write(root.path.join(CATALOG_FILE_NAME), text).expect("write file");
            let result = load_entries(&root.path, DEFAULT_DATABASE_NAME);
            assert!(
                matches!(result, Err(CatalogError::Corrupt { .. })),
                "{tag}: expected Corrupt, got {result:?}"
            );
            // Fail closed: the malformed file is never reset or rewritten by the failed load.
            assert_eq!(
                std::fs::read_to_string(root.path.join(CATALOG_FILE_NAME)).expect("file intact"),
                *text
            );
        }
    }

    // ---- lifecycle state transitions ---------------------------------------------------------------

    /// Reloads the durable desired states from disk through a fresh load (what the next boot
    /// would see), without starting any engine.
    fn durable_states(root: &TempRoot) -> BTreeMap<String, DbState> {
        load_entries(&root.path, DEFAULT_DATABASE_NAME).expect("reload")
    }

    #[tokio::test]
    async fn lifecycle_create_stop_start_stop_drop() {
        let root = TempRoot::new("lifecycle");
        let catalog = open_catalog(&root);

        // create → online, durable, directory provisioned.
        let handle = catalog.create("alpha").await.expect("create");
        drop(handle);
        assert!(catalog.handle("alpha").is_some());
        assert!(
            catalog.handle("ALPHA").is_some(),
            "lookup is case-insensitive"
        );
        assert_eq!(durable_states(&root).get("alpha"), Some(&DbState::Online));
        let dir = root.path.join(DATABASES_DIR_NAME).join("alpha");
        assert!(dir.join(STORE_FILE_NAME).exists(), "fresh store created");

        // stop → engine gone, durable offline.
        catalog.stop("alpha").await.expect("stop");
        assert!(catalog.handle("alpha").is_none());
        assert_eq!(durable_states(&root).get("alpha"), Some(&DbState::Offline));
        // Idempotent stop.
        catalog.stop("alpha").await.expect("stop again");

        // start → engine back (reopening the existing store), durable online.
        let handle = catalog.start("alpha").await.expect("start");
        drop(handle);
        assert!(catalog.handle("alpha").is_some());
        assert_eq!(durable_states(&root).get("alpha"), Some(&DbState::Online));
        // Idempotent start.
        let _ = catalog.start("alpha").await.expect("start again");

        // drop requires offline.
        assert!(matches!(
            catalog.drop_database("alpha").await,
            Err(CatalogError::NotOffline(_))
        ));
        catalog.stop("alpha").await.expect("stop before drop");
        catalog.drop_database("alpha").await.expect("drop");
        assert!(!durable_states(&root).contains_key("alpha"));
        assert!(!dir.exists(), "the database directory is deleted");

        catalog.shutdown_all().await;
    }

    #[tokio::test]
    async fn duplicate_and_default_and_unknown_are_rejected() {
        let root = TempRoot::new("rejections");
        let catalog = open_catalog(&root);

        let _ = catalog.create("alpha").await.expect("create");
        assert!(matches!(
            catalog.create("alpha").await,
            Err(CatalogError::AlreadyExists(_))
        ));
        assert!(
            matches!(
                catalog.create("ALPHA").await,
                Err(CatalogError::AlreadyExists(_)),
            ),
            "duplicate detection is case-insensitive"
        );

        // The default database is implicit and protected.
        assert!(matches!(
            catalog.create(DEFAULT_DATABASE_NAME).await,
            Err(CatalogError::DefaultDatabase {
                operation: "create",
                ..
            })
        ));
        assert!(matches!(
            catalog.stop(DEFAULT_DATABASE_NAME).await,
            Err(CatalogError::DefaultDatabase {
                operation: "stop",
                ..
            })
        ));
        assert!(matches!(
            catalog.drop_database(DEFAULT_DATABASE_NAME).await,
            Err(CatalogError::DefaultDatabase {
                operation: "drop",
                ..
            })
        ));
        // `start` of the not-running default is rejected (it is server-lifecycle-managed) …
        assert!(matches!(
            catalog.start(DEFAULT_DATABASE_NAME).await,
            Err(CatalogError::DefaultDatabase {
                operation: "start",
                ..
            })
        ));
        // … and idempotent once the server started it.
        let _ = catalog.start_default().await.expect("start default");
        let _ = catalog
            .start(DEFAULT_DATABASE_NAME)
            .await
            .expect("idempotent start of the running default");

        // Unknown names error on every lifecycle op.
        assert!(matches!(
            catalog.start("nope").await,
            Err(CatalogError::UnknownDatabase(_))
        ));
        assert!(matches!(
            catalog.stop("nope").await,
            Err(CatalogError::UnknownDatabase(_))
        ));
        assert!(matches!(
            catalog.drop_database("nope").await,
            Err(CatalogError::UnknownDatabase(_))
        ));
        // Invalid names are rejected before any state is touched.
        assert!(matches!(
            catalog.create("no/slash").await,
            Err(CatalogError::InvalidName(_))
        ));

        catalog.shutdown_all().await;
    }

    #[tokio::test]
    async fn list_reports_default_desired_and_actual_states() {
        let root = TempRoot::new("list");
        let catalog = open_catalog(&root);
        let _ = catalog.start_default().await.expect("start default");
        let _ = catalog.create("alpha").await.expect("create");
        catalog.stop("alpha").await.expect("stop");

        let infos = catalog.list().await;
        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].name, DEFAULT_DATABASE_NAME);
        assert!(infos[0].is_default);
        assert_eq!(infos[0].state, DbState::Online);
        assert_eq!(infos[1].name, "alpha");
        assert!(!infos[1].is_default);
        assert_eq!(infos[1].state, DbState::Offline);
        assert_eq!(infos[1].desired, DbState::Offline);
        assert_eq!(infos[1].error, None);

        catalog.shutdown_all().await;
    }

    #[tokio::test]
    async fn boot_reconciliation_starts_online_databases_and_shutdown_keeps_desired_state() {
        let root = TempRoot::new("boot");
        {
            let catalog = open_catalog(&root);
            let _ = catalog.start_default().await.expect("start default");
            let _ = catalog.create("alpha").await.expect("create alpha");
            let _ = catalog.create("beta").await.expect("create beta");
            catalog.stop("beta").await.expect("stop beta");
            // Process teardown: durable desired states must survive untouched.
            catalog.shutdown_all().await;
        }
        // "Next boot": alpha (desired online) starts, beta (desired offline) stays down.
        let catalog = open_catalog(&root);
        let _ = catalog.start_default().await.expect("start default");
        catalog.start_catalog_databases().await;
        assert!(catalog.handle("alpha").is_some(), "alpha reconciled online");
        assert!(catalog.handle("beta").is_none(), "beta stays offline");
        assert!(catalog.default_handle().is_some());

        catalog.shutdown_all().await;
    }

    // ---- persist-failure crash safety (fault-injected) --------------------------------------------

    /// Regression (storage audit F1 + F3): a `stop` whose persist fails must leave memory
    /// resynced to the durable file (still `online` — the rename never happened), and a retried
    /// `stop` must re-attempt the persist. Before the fix, the error branch left memory at
    /// `offline`, so the retry hit the idempotency check and reported success **without ever
    /// persisting** — the durable file still said `online` and the database resurrected at the
    /// next boot despite a reported successful stop.
    #[tokio::test]
    async fn failed_stop_persist_resyncs_memory_and_retry_persists_offline() {
        let root = TempRoot::new("stop-fault");
        let catalog = open_catalog(&root);
        let _ = catalog.create("alpha").await.expect("create");
        assert_eq!(durable_states(&root).get("alpha"), Some(&DbState::Online));

        // The stop drains the engine, then its persist fails (injected before the write/rename).
        catalog.inject_persist_faults(1);
        let err = catalog.stop("alpha").await;
        assert!(
            matches!(err, Err(CatalogError::Io { .. })),
            "stop reports the persist failure: {err:?}"
        );
        assert!(catalog.handle("alpha").is_none(), "the engine is down");
        // The durable file is untouched (the rename never happened) — and memory resynced to it.
        assert_eq!(durable_states(&root).get("alpha"), Some(&DbState::Online));
        let infos = catalog.list().await;
        let alpha = infos.iter().find(|i| i.name == "alpha").expect("listed");
        assert_eq!(
            alpha.desired,
            DbState::Online,
            "memory follows the published file, not the failed mutation"
        );
        assert_eq!(alpha.state, DbState::Offline, "actual state: engine down");

        // The retry skips the drain (the engine is already stopped) and re-attempts the persist.
        catalog.stop("alpha").await.expect("retried stop persists");
        assert_eq!(
            durable_states(&root).get("alpha"),
            Some(&DbState::Offline),
            "the retried stop made the offline state durable"
        );

        catalog.shutdown_all().await;
    }

    /// Regression (storage audit F3): every mutating persist failure resyncs memory from the
    /// published file (instead of a blind in-memory rollback), so memory never asserts state the
    /// filesystem does not hold and a plain retry always re-derives the right action.
    #[tokio::test]
    async fn failed_persists_resync_memory_and_retries_succeed() {
        let root = TempRoot::new("resync");
        let catalog = open_catalog(&root);

        // create: the failed persist leaves no entry (memory == published file == no "alpha").
        catalog.inject_persist_faults(1);
        assert!(matches!(
            catalog.create("alpha").await,
            Err(CatalogError::Io { .. })
        ));
        assert!(!durable_states(&root).contains_key("alpha"));
        assert!(catalog.list().await.iter().all(|i| i.name != "alpha"));
        let _ = catalog.create("alpha").await.expect("retried create");
        assert_eq!(durable_states(&root).get("alpha"), Some(&DbState::Online));

        // start: the failed persist resyncs to offline; the retry brings it online.
        catalog.stop("alpha").await.expect("stop");
        catalog.inject_persist_faults(1);
        assert!(matches!(
            catalog.start("alpha").await,
            Err(CatalogError::Io { .. })
        ));
        assert_eq!(durable_states(&root).get("alpha"), Some(&DbState::Offline));
        let infos = catalog.list().await;
        let alpha = infos.iter().find(|i| i.name == "alpha").expect("listed");
        assert_eq!(alpha.desired, DbState::Offline, "memory resynced");
        let _ = catalog.start("alpha").await.expect("retried start");

        // drop: the failed persist keeps the entry AND the data; the retry removes both.
        catalog.stop("alpha").await.expect("stop before drop");
        catalog.inject_persist_faults(1);
        assert!(matches!(
            catalog.drop_database("alpha").await,
            Err(CatalogError::Io { .. })
        ));
        assert_eq!(durable_states(&root).get("alpha"), Some(&DbState::Offline));
        let dir = root.path.join(DATABASES_DIR_NAME).join("alpha");
        assert!(dir.exists(), "a failed drop must not delete the data");
        catalog.drop_database("alpha").await.expect("retried drop");
        assert!(!durable_states(&root).contains_key("alpha"));
        assert!(!dir.exists());

        catalog.shutdown_all().await;
    }

    // ---- provisioning durability (storage audit F2) ------------------------------------------------

    /// Regression (storage audit F2): after `provision_fresh_dir` the directory exists and is
    /// **empty**, even when a stale populated directory (a crashed drop's leftovers) was present —
    /// the precondition the catalog needs before it may claim the name `online`.
    ///
    /// The `fsync` barrier itself (the dir + parent `sync_all` before returning) is asserted by
    /// code review of `provision_fresh_dir`, not by simulation: proving it would require
    /// replaying a kernel crash that journals the directory tree without the unlinks (e.g. a
    /// btrfs tree-log replay), which no user-space test can express. `graphus-sim` currently
    /// models deterministic clock/RNG capabilities only — it has no directory-entry durability
    /// model — so this test pins the observable protocol (clear → create → return only after the
    /// syncs succeed) and the barrier argument lives in the function's rustdoc.
    #[test]
    fn provision_fresh_dir_clears_stale_contents_including_nested() {
        let root = TempRoot::new("provision");
        let dir = root.path.join(DATABASES_DIR_NAME).join("alpha");
        std::fs::create_dir_all(dir.join("nested")).expect("stale nested dir");
        std::fs::write(dir.join(STORE_FILE_NAME), b"old dropped store").expect("stale store");
        std::fs::write(dir.join("nested").join("junk.bin"), b"junk").expect("stale junk");

        provision_fresh_dir(&dir).expect("provision");

        assert!(dir.is_dir(), "the directory exists after provisioning");
        assert_eq!(
            std::fs::read_dir(&dir).expect("read dir").count(),
            0,
            "the directory is empty: nothing of the dropped store can resurrect"
        );
    }

    /// `provision_fresh_dir` on a blank root (the very first `create`): the parent
    /// `<root>/databases/` is created explicitly so both fsync targets exist.
    #[test]
    fn provision_fresh_dir_creates_parent_on_first_use() {
        let root = TempRoot::new("provision-first");
        let dir = root.path.join(DATABASES_DIR_NAME).join("alpha");
        assert!(!root.path.join(DATABASES_DIR_NAME).exists());

        provision_fresh_dir(&dir).expect("provision");

        assert!(dir.is_dir());
        assert_eq!(std::fs::read_dir(&dir).expect("read dir").count(), 0);
    }

    #[tokio::test]
    async fn create_clears_an_inert_orphan_directory() {
        let root = TempRoot::new("orphan");
        let catalog = open_catalog(&root);
        // Simulate a crashed drop (entry persisted away, directory left behind with old data).
        let dir = root.path.join(DATABASES_DIR_NAME).join("alpha");
        std::fs::create_dir_all(&dir).expect("orphan dir");
        std::fs::write(dir.join("leftover.bin"), b"old data").expect("orphan file");

        let _ = catalog.create("alpha").await.expect("create over orphan");
        assert!(
            !dir.join("leftover.bin").exists(),
            "the orphan's contents never resurrect into the new database"
        );
        assert!(dir.join(STORE_FILE_NAME).exists());

        catalog.shutdown_all().await;
    }

    /// `rmp` #450 REGRESSION GATE: a **wedged** engine (armed to block far longer than the configured
    /// drain deadline inside its `Shutdown` handler) must NOT make [`DatabaseCatalog::shutdown_all`] hang.
    /// `stop_engine` wraps each engine's drain in a [`tokio::time::timeout`] of
    /// [`EngineParams::engine_shutdown_timeout`] and force-detaches a non-draining engine on elapse, so
    /// `shutdown_all` returns within a bounded multiple of that deadline (it processes engines serially)
    /// rather than blocking forever under the admin lock — the cross-tenant availability hazard #450
    /// describes (a single wedged thread would otherwise freeze every other tenant's admin op until a
    /// `SIGKILL`).
    ///
    /// Gated on `internal-test-udf` (the `arm_shutdown_hang` fault seam). The wedged engine blocks for a
    /// duration *much* larger than the deadline; the assertion is that `shutdown_all` nonetheless returns
    /// well before that, proving the timeout fired and force-detached it.
    #[cfg(feature = "internal-test-udf")]
    #[tokio::test]
    async fn wedged_engine_does_not_hang_shutdown_all() {
        use std::time::{Duration, Instant};

        // A catalog whose per-engine drain deadline is a short 300ms.
        let root = TempRoot::new("wedged-shutdown");
        let mut params = test_params();
        params.engine_shutdown_timeout = Duration::from_millis(300);
        let catalog = DatabaseCatalog::open(
            root.path.clone(),
            DEFAULT_DATABASE_NAME,
            params,
            Arc::new(Metrics::new()),
        )
        .expect("open catalog");

        // Bring up the default engine + a secondary, so `shutdown_all` has multiple engines to drain.
        catalog.start_default().await.expect("start default");
        let _ = catalog.create("alpha").await.expect("create alpha");

        // Arm ONE engine to wedge for 3s inside its `Shutdown` handler — two orders of magnitude past
        // the 300ms deadline. Without the #450 timeout, `shutdown_all` would block on this engine's
        // drain for the full 3s (and longer, on the unbounded join).
        crate::engine::arm_shutdown_hang(3_000);

        // `shutdown_all` must return promptly: bounded by ~deadline-per-engine (it force-detaches the
        // wedged one on elapse). Allow generous slack for CI scheduling, but it MUST be far below the 3s
        // hang — proving the timeout fired rather than the engine actually draining.
        let started = Instant::now();
        tokio::time::timeout(Duration::from_secs(2), catalog.shutdown_all())
            .await
            .expect("shutdown_all must not hang on a wedged engine (rmp #450)");
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "shutdown_all returned in {elapsed:?} — bounded by the drain deadline, not the 3s wedge"
        );

        // Disarm so a sibling test in this binary is never affected by a residual armed hang.
        crate::engine::arm_shutdown_hang(0);
    }

    /// `rmp` #450: while one engine is wedged, the admin lock `shutdown_all` holds is released within the
    /// bounded deadline, so **another tenant's admin op** (here, a `create`) issued concurrently is not
    /// blocked past that deadline. This is the cross-tenant amplification the #450 fix removes: a single
    /// wedged engine must not freeze every other tenant's control-plane operation.
    #[cfg(feature = "internal-test-udf")]
    #[tokio::test]
    async fn wedged_engine_does_not_block_other_tenants_admin_ops() {
        use std::time::{Duration, Instant};

        let root = TempRoot::new("wedged-cross-tenant");
        let mut params = test_params();
        params.engine_shutdown_timeout = Duration::from_millis(300);
        let catalog = Arc::new(
            DatabaseCatalog::open(
                root.path.clone(),
                DEFAULT_DATABASE_NAME,
                params,
                Arc::new(Metrics::new()),
            )
            .expect("open catalog"),
        );

        catalog.start_default().await.expect("start default");
        let _ = catalog.create("alpha").await.expect("create alpha");

        // Wedge an engine for 3s on shutdown, then start `shutdown_all` in the background (it grabs the
        // admin lock and begins draining — blocking on the wedged engine until its 300ms deadline).
        crate::engine::arm_shutdown_hang(3_000);
        let bg = {
            let catalog = Arc::clone(&catalog);
            tokio::spawn(async move { catalog.shutdown_all().await })
        };

        // A concurrent admin op on ANOTHER database (`create beta`) must complete within a bounded time —
        // it waits only for `shutdown_all` to release the admin lock, which the #450 deadline bounds. Far
        // below the 3s wedge. (It may fail because the catalog is shutting down; what matters is it does
        // not HANG for the full wedge — it returns, success or a clean error, within the bound.)
        let started = Instant::now();
        let outcome = tokio::time::timeout(Duration::from_secs(2), catalog.create("beta")).await;
        let elapsed = started.elapsed();
        assert!(
            outcome.is_ok(),
            "a concurrent admin op on another tenant must not block past the drain deadline (rmp #450) \
             — it hung for {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "the concurrent admin op returned in {elapsed:?} — bounded by the deadline, not the 3s wedge"
        );

        let _ = bg.await;
        crate::engine::arm_shutdown_hang(0);
    }
}
