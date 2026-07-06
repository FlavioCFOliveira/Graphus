//! **Network bulk-import Mode B** (`08-network-bulk-import.md` §5.3/§7.2/§8, `rmp` #520): the
//! session registry + batch driver that let an operator stream a large dataset into an
//! already-**live**, already-serving database, concurrent with ordinary Bolt/REST traffic, with
//! **zero exclusivity**.
//!
//! This is the async, off-engine-thread half of Mode B; the engine-thread chunk handler lives in
//! [`crate::engine::bulk_load_b`] (see its module docs for why Mode B is architecturally distinct
//! from Mode A and why `id_map` bookkeeping deliberately lives *here*, not on the engine thread).
//!
//! ## The batch-retry / `id_map` staging invariant — the single most safety-critical piece here
//!
//! A Mode B batch is an ordinary `TxnCoordinator` transaction (`Begin` → N × chunk → `Commit`/
//! `Rollback`) that can abort on an SSI pivot exactly like any other concurrent transaction (`08`
//! §7.2.1/§7.2.3). [`drive_mode_b_batch`] automatically retries an aborted batch (bounded by
//! [`crate::config::BulkImportConfig::mode_b_max_batch_retries`]), and — this is the load-bearing
//! rule — **[`ModeBSession::id_map`] and `stats` are mutated only after the whole batch's `Commit`
//! returns `Ok`**. Every row a retried attempt ingests is staged into a **local** (per-attempt)
//! scratch `Vec`/[`graphus_bulk::ImportStats`] delta that is discarded on any failure and merged into
//! the session's durable state only once. This reproduces, at the driver level, the exact `rmp` #517
//! `id_map`-staging invariant `graphus_bulk::BulkImporter` already enforces for the offline
//! importer's own batch-retry (see `08` §7.2.2's audit finding: the bug class this pattern exists to
//! prevent is a retried batch polluting the id map with bindings to a now-rolled-back, no-longer-
//! existent physical id — silent, hard-to-diagnose data corruption, not just an error).
//!
//! ## No durable checkpoint-sentinel node for Mode B — a deliberate scope decision
//!
//! Mode A's `LoadingSession` (`crate::engine::bulk_load`) writes a durable
//! `__graphus_bulk_import_session__` sentinel node in the **same commit** as each batch, so a
//! reconnecting client can resume after a process crash even though the in-memory session state is
//! gone. **Mode B has no equivalent.** This is a deliberate judgment call, not an oversight:
//!
//! - `08` §11's acceptance criteria explicitly scope the *tested* resumability requirement to Mode A
//!   only (§10.1); Mode B's own DST bullet list (§10.2) asks for ordinary WAL-recovery consistency
//!   under a mid-batch crash, not session/byte-offset resume.
//! - A durable sentinel node would be **visible to ordinary Cypher queries** on a live, already-
//!   serving database (unlike Mode A's `Loading` database, which is not queryable at all) —
//!   polluting a live customer's graph with internal bookkeeping nodes is a materially worse
//!   trade-off for Mode B than for Mode A.
//! - Mode B's crash story instead: every batch that committed before a crash is durable via ordinary
//!   ARIES/WAL recovery — `08` §7.2.5 says exactly this ("No new recovery mechanism is required"); an
//!   in-process HTTP reconnect (same engine process, same session id) resumes for free via the
//!   still-live [`ModeBSession`] parked in [`ModeBSessionRegistry`]; a full **process crash** loses
//!   every in-memory Mode B session (`id_map`, `stats`) — the operator must open a **new** Mode B
//!   session and re-supply data from the last file boundary they tracked client-side.
//! - **Operator-visible consequence, stated plainly (not a defect):** Mode B does **not** deduplicate
//!   against external ids the way the low-level offline importer does (it never needed to — it is
//!   not maintaining an id-map-keyed identity beyond a single still-live session). A re-sent,
//!   already-committed row after a crash simply creates a **second** node/relationship with the same
//!   properties, exactly as an ordinary Cypher client re-running a `CREATE` after a crash would. This
//!   is the honest, correct consequence of "no exclusivity, ordinary transactional semantics" (`08`
//!   §5.3), not a bug to fix here.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use graphus_bulk::{ImportStats, NodeHeader, RelHeader};
use graphus_core::GraphusError;

use crate::config::BulkImportConfig;
use crate::engine::{AccessMode, BulkImportModeBChunkInput, EngineHandle};

/// One in-flight (or paused-between-calls) Mode B session's state, owned entirely by the async
/// driver — never the engine thread (see the module docs).
pub struct ModeBSession {
    /// The target database name this session imports into.
    pub db: String,
    /// External `:ID` → physical node id, populated **only** by successfully-committed batches (the
    /// staging invariant above). A relationship batch resolves `:START_ID`/`:END_ID` only against
    /// this map.
    ///
    /// Held behind an [`Arc`] (`rmp` #598, Finding E-4) so a relationship batch's per-attempt
    /// endpoint-resolution snapshot is a **pointer clone**, never an `O(id_map)` map copy. Over a
    /// large multi-batch load the previous per-attempt full clone was quadratic-ish memory churn; the
    /// `Arc` collapses a relationship batch's snapshot to a refcount bump and a node batch's
    /// post-commit merge to an in-place [`Arc::make_mut`] (amortized `O(1)` — the map is uniquely
    /// owned during a node batch). The staging invariant is unchanged: new bindings are still merged
    /// in only *after* a batch's `Commit` returns `Ok`.
    pub id_map: Arc<HashMap<String, u64>>,
    /// Cumulative stats for the whole session so far, advanced only on a batch's successful commit.
    pub stats: ImportStats,
    /// The last time this session was touched (created, checked out, or checked back in) — the idle-
    /// reap clock (`08` §8).
    last_touched: Instant,
}

impl ModeBSession {
    /// Builds a fresh, empty session targeting `db` (an empty `id_map`, zeroed `stats`, freshly-
    /// touched idle clock). `pub` so a caller driving [`drive_mode_b_batch`] directly — outside the
    /// ordinary [`ModeBSessionRegistry::create`]/[`checkout`](ModeBSessionRegistry::checkout) flow
    /// the REST handler uses — can construct one (e.g. `bulk_import_mode_b_fairness.rs`'s real-thread
    /// latency test).
    #[must_use]
    pub fn new(db: String) -> Self {
        Self {
            db,
            id_map: Arc::new(HashMap::new()),
            stats: ImportStats::default(),
            last_touched: Instant::now(),
        }
    }
}

/// Mode B session-open was refused because the server-wide concurrent-session cap (`08` §8) is
/// already at capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeBCapacityReached {
    /// The configured cap that was reached.
    pub max: usize,
}

impl std::fmt::Display for ModeBCapacityReached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "server-wide Mode B concurrent-session cap reached ({} session(s) already open); retry \
             once another Mode B session ends",
            self.max
        )
    }
}

impl std::error::Error for ModeBCapacityReached {}

/// A server-wide registry of open Mode B sessions (`08` §8's concurrent-session cap), keyed by an
/// opaque, server-minted [`uuid::Uuid`].
///
/// ## Check-out / check-in discipline
///
/// A session is **checked out** (removed from the map) for the duration of one HTTP call driving it
/// — [`checkout`](Self::checkout)/[`checkin`](Self::checkin) never hold the `tokio::sync::Mutex`
/// guard across an `.await` (each is a single, momentary lock acquisition). A second concurrent call
/// naming the same session id while it is checked out simply finds it absent from the map — the REST
/// layer reports this the same way as an unknown/expired id (`409`; see the module's REST-facing
/// caller for the exact wording), because distinguishing the two cases would need extra state this
/// registry does not otherwise need to track and does not change what the client should do (retry
/// once the in-flight call completes).
///
/// ## Idle reaping
///
/// Every [`create`](Self::create)/[`checkout`](Self::checkout) call opportunistically sweeps entries
/// whose [`ModeBSession`]'s `last_touched` exceeds `idle_timeout` before doing its own work — a lazy
/// sweep-on-access, deliberately **not** a separate background task: Mode B sessions are opened
/// rarely relative to ordinary query traffic (an operator-driven, `Admin`-gated action), so a
/// dedicated long-lived reaping task would be a new, permanently-running piece of machinery for a
/// cold path. A session sitting idle between two `create`/`checkout` calls elsewhere in the process
/// is reaped the next time *any* call touches the registry, which is sufficient: `08` §8's
/// requirement is bounding *aggregate* resource consumption, not guaranteeing prompt reclamation to
/// the millisecond.
pub struct ModeBSessionRegistry {
    inner: tokio::sync::Mutex<HashMap<uuid::Uuid, ModeBSession>>,
    max_concurrent: usize,
    idle_timeout: Duration,
}

impl ModeBSessionRegistry {
    /// Builds an empty registry enforcing `max_concurrent` open sessions and reaping a session idle
    /// past `idle_timeout`.
    #[must_use]
    pub fn new(max_concurrent: usize, idle_timeout: Duration) -> Self {
        Self {
            inner: tokio::sync::Mutex::new(HashMap::new()),
            max_concurrent,
            idle_timeout,
        }
    }

    /// Builds a registry from the server's [`BulkImportConfig`].
    #[must_use]
    pub fn from_config(cfg: &BulkImportConfig) -> Self {
        Self::new(
            cfg.mode_b_max_concurrent_sessions,
            cfg.mode_b_session_idle_timeout(),
        )
    }

    /// Opens a new Mode B session targeting `db`, enforcing the concurrent-session cap (after an
    /// opportunistic idle sweep). Returns the new session's id.
    ///
    /// # Errors
    /// [`ModeBCapacityReached`] if the server-wide cap is already at capacity.
    pub async fn create(&self, db: impl Into<String>) -> Result<uuid::Uuid, ModeBCapacityReached> {
        let mut guard = self.inner.lock().await;
        sweep_idle(&mut guard, self.idle_timeout);
        if guard.len() >= self.max_concurrent {
            return Err(ModeBCapacityReached {
                max: self.max_concurrent,
            });
        }
        let id = uuid::Uuid::new_v4();
        guard.insert(id, ModeBSession::new(db.into()));
        Ok(id)
    }

    /// Checks out `id` for exclusive use by the calling task: removes and returns it, or `None` if no
    /// session with that id is currently parked here (never opened, already ended, idle-reaped, or
    /// currently checked out by another in-flight call).
    #[must_use]
    pub async fn checkout(&self, id: uuid::Uuid) -> Option<ModeBSession> {
        let mut guard = self.inner.lock().await;
        sweep_idle(&mut guard, self.idle_timeout);
        guard.remove(&id)
    }

    /// Checks `session` back in under `id`, refreshing its idle clock. The caller must have obtained
    /// `session` from a prior [`checkout`](Self::checkout) of the same `id` (or [`create`](Self::create)).
    pub async fn checkin(&self, id: uuid::Uuid, mut session: ModeBSession) {
        session.last_touched = Instant::now();
        self.inner.lock().await.insert(id, session);
    }

    /// Re-checks `session` in from a **synchronous** (`Drop`) context (`rmp` #598, Finding E-5), used
    /// by the REST handler's `SessionCheckinGuard` to restore a checked-out session when the driving
    /// task unwinds or is cancelled before the session is handed to the ingest sink.
    ///
    /// The registry map is only ever locked for a momentary, await-free critical section (see the type
    /// docs), so [`tokio::sync::Mutex::try_lock`] succeeds in the overwhelming common case — an
    /// immediate, synchronous check-in with no runtime interaction. On the rare contended miss it falls
    /// back to a **detached** async check-in (a single, self-completing task) so the session is still
    /// restored rather than silently lost. If no Tokio runtime is available (never, inside the server)
    /// the session is dropped — exactly the pre-#598 behavior.
    pub fn checkin_from_drop(self: &Arc<Self>, id: uuid::Uuid, mut session: ModeBSession) {
        session.last_touched = Instant::now();
        match self.inner.try_lock() {
            Ok(mut guard) => {
                guard.insert(id, session);
            }
            Err(_) => {
                let registry = Arc::clone(self);
                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    handle.spawn(async move {
                        registry.checkin(id, session).await;
                    });
                }
            }
        }
    }

    /// Ends session `id`: removes and returns it (its final stats), or `None` if it was never open /
    /// already ended — an idempotent no-op, mirroring Mode A's `End` contract (`08` §7.1 precedent).
    pub async fn end(&self, id: uuid::Uuid) -> Option<ModeBSession> {
        self.inner.lock().await.remove(&id)
    }

    /// The number of currently checked-in (not checked-out) open sessions — an observability/test
    /// hook.
    #[must_use]
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// Whether the registry currently holds no checked-in sessions.
    #[must_use]
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }
}

/// Removes every entry whose `last_touched` is older than `idle_timeout` (the lazy sweep-on-access,
/// see [`ModeBSessionRegistry`]'s docs).
fn sweep_idle(guard: &mut HashMap<uuid::Uuid, ModeBSession>, idle_timeout: Duration) {
    let now = Instant::now();
    guard.retain(|_, s| now.saturating_duration_since(s.last_touched) < idle_timeout);
}

/// One whole batch's worth of already-parsed CSV rows for the [`drive_mode_b_batch`] driver: the
/// node-vs-relationship discriminant plus the shared file header, split into
/// [`BulkImportConfig::mode_b_chunk_rows`]-sized chunks internally (never a single, whole-batch
/// [`crate::engine::BulkImportModeBChunk`](crate::engine::command::EngineCommand::BulkImportModeBChunk)
/// dispatch — `08` §7.2.6's fairness requirement).
pub enum BatchRows {
    /// A batch of node rows from a single node file.
    Nodes {
        /// The parsed node-file header, shared across every chunk of this batch.
        header: Arc<NodeHeader>,
        /// The rows to ingest, in file order.
        records: Vec<csv::StringRecord>,
    },
    /// A batch of relationship rows from a single relationship file.
    Relationships {
        /// The parsed relationship-file header, shared across every chunk of this batch.
        header: Arc<RelHeader>,
        /// The rows to ingest, in file order.
        records: Vec<csv::StringRecord>,
    },
}

impl BatchRows {
    /// The number of rows in this batch.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Nodes { records, .. } | Self::Relationships { records, .. } => records.len(),
        }
    }

    /// Whether this batch carries no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Whether `err` is the **retriable** class (`08` §7.2.3's automatic-retry case): a write-write lock
/// conflict, an SSI pivot abort surfaced from a chunk's captured error, or a pivot abort surfaced
/// from the batch's own `Commit` call. Matched structurally (never by string), per the codebase's
/// established convention (`crates/graphus-bolt/src/error.rs`: `GraphusError::Transaction` is the
/// *only* retriable variant; every other variant is terminal).
fn is_retriable(err: &GraphusError) -> bool {
    matches!(err, GraphusError::Transaction(_))
}

/// The lengths of the chunks `records.chunks(chunk_rows)` (the exact call [`run_one_attempt`] makes)
/// would split `total_rows` rows into, for `chunk_rows`-sized chunks (`chunk_rows` clamped to at
/// least 1). A fast, direct, allocation-free proof that the chunking mechanism genuinely bounds each
/// dispatch to at most `chunk_rows` rows — see `tests::chunk_rows_bounds_every_dispatch` and the
/// `network_bulk_ingest_mode_b` DST scenario's own direct assertion on submitted chunk sizes.
/// Test-only: production code calls `[T]::chunks` directly (this mirrors its exact size sequence,
/// verified once here rather than re-deriving it ad hoc in the test).
#[cfg(test)]
fn chunk_lengths(total_rows: usize, chunk_rows: usize) -> Vec<usize> {
    let chunk_rows = chunk_rows.max(1);
    if total_rows == 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(total_rows.div_ceil(chunk_rows));
    let mut remaining = total_rows;
    while remaining > 0 {
        let take = remaining.min(chunk_rows);
        out.push(take);
        remaining -= take;
    }
    out
}

/// A single, shared, empty `id_map` snapshot handed to a **node** batch's [`run_one_attempt`]
/// (`rmp` #598, Finding E-4). Node chunks never resolve `:START_ID`/`:END_ID` against previously
/// committed bindings, so the snapshot they receive is unused — passing this shared empty `Arc`
/// avoids both an allocation *and* bumping the session's real `id_map` refcount, which keeps the
/// post-commit [`Arc::make_mut`] merge uniquely-owned (`O(1)`, no copy) for the common nodes-first
/// load.
static EMPTY_ID_MAP: LazyLock<Arc<HashMap<String, u64>>> =
    LazyLock::new(|| Arc::new(HashMap::new()));

/// One attempt's outcome (before commit): the new external-id bindings this attempt's node chunks
/// produced, plus the cumulative row-count delta.
struct AttemptResult {
    pending_bindings: Vec<(String, u64)>,
    delta: ImportStats,
}

/// Runs one attempt of a batch: opens no transaction itself (the caller already did via `ticket`),
/// dispatches `rows` in `chunk_rows`-sized chunks, and returns the first chunk failure or the
/// accumulated result. Chunks are **never** dispatched after the first failure (`08` §7.2.3: "on a
/// pivot abort, none of the batch's writes are visible" — no point in continuing a doomed attempt).
///
/// `id_map_snapshot` is built **once per attempt** by the caller (not once per chunk) — a relationship
/// batch's chunks all share the same `Arc` clone, avoiding an O(chunks) re-clone of a possibly large
/// map within one attempt.
async fn run_one_attempt(
    engine: &EngineHandle,
    ticket: crate::engine::TxTicket,
    rows: &BatchRows,
    id_map_snapshot: &Arc<HashMap<String, u64>>,
    chunk_rows: usize,
) -> Result<AttemptResult, GraphusError> {
    let mut pending_bindings = Vec::new();
    let mut delta = ImportStats::default();
    match rows {
        BatchRows::Nodes { header, records } => {
            for chunk in records.chunks(chunk_rows.max(1)) {
                let input = BulkImportModeBChunkInput::Nodes {
                    header: Arc::clone(header),
                    records: chunk.to_vec(),
                };
                let outcome = engine.bulk_import_mode_b_chunk(ticket, input).await?;
                pending_bindings.extend(outcome.new_node_bindings);
                delta.nodes += outcome.nodes;
                delta.properties += outcome.properties;
            }
        }
        BatchRows::Relationships { header, records } => {
            for chunk in records.chunks(chunk_rows.max(1)) {
                let input = BulkImportModeBChunkInput::Relationships {
                    header: Arc::clone(header),
                    records: chunk.to_vec(),
                    id_map: Arc::clone(id_map_snapshot),
                };
                let outcome = engine.bulk_import_mode_b_chunk(ticket, input).await?;
                delta.relationships += outcome.relationships;
                delta.properties += outcome.properties;
            }
        }
    }
    Ok(AttemptResult {
        pending_bindings,
        delta,
    })
}

/// The exponential-with-cap backoff between automatic batch retries (`08` §7.2.3): `base_ms *
/// 2^attempt`, capped at [`BACKOFF_CAP_MS`]. There is no pre-existing transaction-retry-backoff
/// precedent in this codebase (the `Backoff` structs in `graphus-storage`/`graphus-bufpool` are
/// unrelated low-level spin-backoff for buffer-pool contention) — this is a new, purpose-built policy
/// for Mode B's batch retry.
const BACKOFF_CAP_MS: u64 = 2_000;

fn backoff_duration(cfg: &BulkImportConfig, attempt: u32) -> Duration {
    let shift = attempt.min(16); // clamp the shift so `1u64 << shift` never overflows
    let scaled = cfg.mode_b_retry_backoff_ms.saturating_mul(1u64 << shift);
    Duration::from_millis(scaled.min(BACKOFF_CAP_MS))
}

/// The pure retry decision (`08` §7.2.3): whether `err`, having occurred on attempt number `attempt`
/// (0-based), should be retried under `cfg`. Only [`GraphusError::Transaction`] is ever retriable
/// (matched structurally, never by string — the codebase's established convention), and only while
/// `attempt` is still below [`BulkImportConfig::mode_b_max_batch_retries`]. Extracted as its own pure
/// function (rather than inlined in [`drive_mode_b_batch`]'s loop) so it is directly, deterministically
/// unit-testable without needing a real engine or any timing control — see `tests::should_retry_*`.
fn should_retry(err: &GraphusError, attempt: u32, cfg: &BulkImportConfig) -> bool {
    is_retriable(err) && attempt < cfg.mode_b_max_batch_retries
}

/// Wraps a retries-exhausted error with a clearer, operator-facing message (`08` §7.2.3: "the session
/// surfaces a retriable error to the client rather than looping forever"), preserving the
/// [`GraphusError::Transaction`] classification (still retriable from the *client's* point of view —
/// a persistently hot predicate may clear later) so the REST layer's existing `Neo.TransientError`-
/// style `409` mapping applies unchanged. A non-retriable error passes through unmodified (it was
/// never a candidate for retry in the first place).
fn finalize_error(err: GraphusError, attempts: u32, cfg: &BulkImportConfig) -> GraphusError {
    match err {
        GraphusError::Transaction(detail) => GraphusError::Transaction(format!(
            "bulk-import Mode B batch aborted after {attempts} attempt(s) \
             (bulk_import.mode_b_max_batch_retries={} exceeded); a persistently hot contended \
             relationship type/predicate is likely (see `08-network-bulk-import.md` §7.2.1) — \
             surfaced to the client instead of retrying forever. Last error: {detail}",
            cfg.mode_b_max_batch_retries
        )),
        other => other,
    }
}

/// Drives one whole Mode B batch to completion against `session`, automatically retrying an SSI
/// pivot abort up to [`BulkImportConfig::mode_b_max_batch_retries`] times (`08` §7.2.3). This is the
/// direct implementation of the module docs' `id_map`-staging invariant: `session.id_map`/`stats` are
/// mutated **only** after a `Commit` returns `Ok` — never speculatively during a chunk dispatch or a
/// doomed attempt.
///
/// # Errors
/// - Whatever [`EngineHandle::begin`] returns (e.g. the engine is shut down) — not retried (opening
///   the transaction itself failing is not the `08` §7.2.3 abort case).
/// - A **terminal** error from a chunk (a malformed row, an unknown relationship endpoint) —
///   surfaced immediately, no retry; the batch's transaction is rolled back first.
/// - [`GraphusError::Transaction`], **wrapped** by [`finalize_error`], once
///   `mode_b_max_batch_retries` automatic retries have all also aborted.
pub async fn drive_mode_b_batch(
    engine: &EngineHandle,
    session: &mut ModeBSession,
    rows: &BatchRows,
    cfg: &BulkImportConfig,
) -> Result<(), GraphusError> {
    drive_mode_b_batch_from(engine, session, rows, cfg, None).await
}

/// [`drive_mode_b_batch`]'s real implementation, generalized to accept an **already-open** ticket for
/// its very first attempt (`first_ticket`), falling back to an ordinary [`EngineHandle::begin`] for
/// that attempt (and for every retry) when `None`.
///
/// This seam exists **only** so a test can deterministically prove the retry loop recovers from a
/// genuine SSI conflict without racing a spawned copy of this function against a concurrent seeding
/// task (which `#[tokio::test]`'s single-OS-thread engine makes needlessly fragile to synchronize):
/// the test opens a ticket, seeds a real conflict against it (in program order, no race), and hands it
/// in here as `first_ticket` — the retry loop then behaves **exactly** as it would in production (the
/// first attempt fails, `should_retry` fires, a fresh internal `begin()` opens attempt 2, which
/// succeeds because the seeded transaction has since settled). Kept `pub(crate)` — not part of the
/// public API surface — precisely because it exists for this one reason.
pub(crate) async fn drive_mode_b_batch_from(
    engine: &EngineHandle,
    session: &mut ModeBSession,
    rows: &BatchRows,
    cfg: &BulkImportConfig,
    first_ticket: Option<crate::engine::TxTicket>,
) -> Result<(), GraphusError> {
    let chunk_rows = cfg.mode_b_chunk_rows.max(1) as usize;
    let mut attempt: u32 = 0;
    let mut pending_first_ticket = first_ticket;

    // Build the endpoint-resolution snapshot ONCE per batch, and ONLY for relationship batches
    // (`rmp` #598, Finding E-4). Rationale:
    //  - Node chunks never resolve against previously-committed bindings, so they get the shared
    //    empty [`EMPTY_ID_MAP`] — no clone, and no refcount held on the session's real `id_map`, so
    //    the post-commit `Arc::make_mut` merge below stays uniquely-owned and copy-free.
    //  - A relationship batch shares the SAME `Arc` across every retry attempt: it never adds node
    //    bindings, so `session.id_map` is invariant across its attempts, making a per-attempt
    //    re-snapshot redundant. Because `id_map` is now an `Arc`, that snapshot is a pointer clone —
    //    not the old `O(id_map)` map copy that made a large multi-batch load quadratic-ish.
    let id_map_snapshot: Arc<HashMap<String, u64>> = match rows {
        BatchRows::Relationships { .. } => Arc::clone(&session.id_map),
        BatchRows::Nodes { .. } => Arc::clone(&EMPTY_ID_MAP),
    };

    loop {
        let ticket = match pending_first_ticket.take() {
            Some(t) => t,
            None => engine.begin(AccessMode::Write).await?,
        };

        let attempt_outcome =
            run_one_attempt(engine, ticket, rows, &id_map_snapshot, chunk_rows).await;
        let err = match attempt_outcome {
            Ok(AttemptResult {
                pending_bindings,
                delta,
            }) => match engine.commit(ticket).await {
                Ok(_) => {
                    // Merge ONLY after a successful commit — the module docs' staging invariant.
                    // `Arc::make_mut` extends in place: a node batch's `id_map` is uniquely owned
                    // (relationship batches are the only Arc-sharers, and none is in flight during a
                    // node batch), so this is amortized `O(1)` with no map copy (`rmp` #598). Guarded
                    // on non-empty so a relationship batch (which produces no bindings) never even
                    // touches the refcount.
                    if !pending_bindings.is_empty() {
                        Arc::make_mut(&mut session.id_map).extend(pending_bindings);
                    }
                    session.stats.nodes += delta.nodes;
                    session.stats.relationships += delta.relationships;
                    session.stats.properties += delta.properties;
                    session.last_touched = Instant::now();
                    return Ok(());
                }
                Err(e) => e,
            },
            Err(e) => {
                // A chunk failed mid-attempt: none of this attempt's writes must become visible.
                // Best-effort — the ticket may already be gone (the coordinator's own commit-path
                // self-abort never applies here since we never reached commit; an unknown-ticket
                // rollback is the documented idempotent no-op).
                let _ = engine.rollback(ticket).await;
                e
            }
        };

        if should_retry(&err, attempt, cfg) {
            attempt += 1;
            tokio::time::sleep(backoff_duration(cfg, attempt)).await;
            continue;
        }
        return Err(finalize_error(err, attempt + 1, cfg));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_bulk::{ColumnRole, PropertyType, ScalarType};
    use graphus_core::Value;
    use graphus_io::MemBlockDevice;
    use graphus_sim::SharedClock;
    use graphus_storage::RecordStore;
    use graphus_wal::MemLogSink;

    // ---- pure helper tests -------------------------------------------------------------------

    #[test]
    fn chunk_rows_bounds_every_dispatch() {
        // (c): a fast, direct proof that the chunking mechanism genuinely bounds a single dispatch
        // to `chunk_rows` records — not an inference from an integration test's side effects.
        for (total, chunk) in [(0, 10), (1, 10), (10, 10), (11, 10), (25, 7), (1000, 3)] {
            let lens = chunk_lengths(total, chunk);
            let sum: usize = lens.iter().sum();
            assert_eq!(
                sum, total,
                "chunk lengths must cover every row exactly once"
            );
            assert!(
                lens.iter().all(|&l| l <= chunk.max(1)),
                "no chunk may exceed chunk_rows={chunk}: {lens:?}"
            );
            if total > 0 {
                assert!(
                    lens.iter().all(|&l| l > 0),
                    "no empty chunk should be produced: {lens:?}"
                );
            }
        }
    }

    #[test]
    fn backoff_grows_exponentially_and_caps() {
        let cfg = BulkImportConfig {
            mode_b_retry_backoff_ms: 20,
            ..BulkImportConfig::default()
        };
        assert_eq!(backoff_duration(&cfg, 0), Duration::from_millis(20));
        assert_eq!(backoff_duration(&cfg, 1), Duration::from_millis(40));
        assert_eq!(backoff_duration(&cfg, 2), Duration::from_millis(80));
        // Eventually caps at BACKOFF_CAP_MS regardless of how large `attempt` grows.
        assert_eq!(
            backoff_duration(&cfg, 20),
            Duration::from_millis(BACKOFF_CAP_MS)
        );
    }

    #[test]
    fn should_retry_only_a_transaction_error_within_the_retry_budget() {
        let cfg = BulkImportConfig {
            mode_b_max_batch_retries: 2,
            ..BulkImportConfig::default()
        };
        let retriable = GraphusError::Transaction("conflict".to_owned());
        let terminal = GraphusError::Storage("bad row".to_owned());

        assert!(should_retry(&retriable, 0, &cfg), "attempt 0 < budget 2");
        assert!(should_retry(&retriable, 1, &cfg), "attempt 1 < budget 2");
        assert!(
            !should_retry(&retriable, 2, &cfg),
            "attempt 2 has exhausted the budget of 2"
        );
        assert!(
            !should_retry(&terminal, 0, &cfg),
            "a non-Transaction error is never retried, regardless of budget"
        );
    }

    #[test]
    fn should_retry_never_fires_when_max_batch_retries_is_zero() {
        let cfg = BulkImportConfig {
            mode_b_max_batch_retries: 0,
            ..BulkImportConfig::default()
        };
        let retriable = GraphusError::Transaction("conflict".to_owned());
        assert!(
            !should_retry(&retriable, 0, &cfg),
            "0 configured retries must surface even a genuinely retriable error immediately"
        );
    }

    #[test]
    fn finalize_error_wraps_a_transaction_error_and_passes_through_others() {
        let cfg = BulkImportConfig {
            mode_b_max_batch_retries: 3,
            ..BulkImportConfig::default()
        };
        let wrapped = finalize_error(GraphusError::Transaction("conflict".to_owned()), 4, &cfg);
        let msg = wrapped.to_string();
        assert!(matches!(wrapped, GraphusError::Transaction(_)));
        assert!(msg.contains("mode_b_max_batch_retries"), "{msg}");
        assert!(
            msg.contains("conflict"),
            "preserves the original detail: {msg}"
        );

        let terminal = finalize_error(GraphusError::Storage("bad row".to_owned()), 1, &cfg);
        assert!(
            matches!(terminal, GraphusError::Storage(ref m) if m == "bad row"),
            "a non-Transaction error passes through byte-identical: {terminal:?}"
        );
    }

    #[tokio::test]
    async fn registry_enforces_concurrent_session_cap_and_idle_reap() {
        let reg = ModeBSessionRegistry::new(2, Duration::from_millis(20));
        let a = reg.create("db").await.expect("first session");
        let b = reg.create("db").await.expect("second session");
        assert!(reg.create("db").await.is_err(), "cap of 2 must be enforced");
        assert_eq!(reg.len().await, 2);

        // Checkout removes it from the map (busy); checkin restores it.
        let sess = reg.checkout(a).await.expect("checkout a");
        assert_eq!(reg.len().await, 1);
        assert!(
            reg.checkout(a).await.is_none(),
            "a checked-out session is unavailable to a second concurrent call"
        );
        reg.checkin(a, sess).await;
        assert_eq!(reg.len().await, 2);

        // Idle reap: sleep past the idle timeout, then any registry access sweeps stale entries. Both
        // `a` and `b` are now idle-past-the-window, so the sweep frees both slots and a fresh `create`
        // (which itself triggers the sweep) must succeed even though the cap is still nominally 2.
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            reg.create("db2").await.is_ok(),
            "a create past the idle window must trigger the sweep and free capacity"
        );
        // Exactly one session (the fresh "db2" one) survives the sweep.
        assert_eq!(
            reg.len().await,
            1,
            "idle sessions swept, only the fresh one remains"
        );
        let _ = b; // silence unused warning in case of reordering
    }

    #[tokio::test]
    async fn end_is_idempotent_for_an_unknown_session() {
        let reg = ModeBSessionRegistry::new(4, Duration::from_secs(60));
        assert!(reg.end(uuid::Uuid::new_v4()).await.is_none());
    }

    /// (`rmp` #598, Finding E-5): the synchronous `Drop`-context re-check-in restores a checked-out
    /// session (its accumulated progress preserved), so an unwind/cancellation between checkout and
    /// the ingest sink does not strand it. The registry mutex is uncontended here, so the fast
    /// `try_lock` path runs — the check-in is immediate and synchronous, no spawned task involved.
    #[tokio::test]
    async fn checkin_from_drop_restores_a_checked_out_session_synchronously() {
        let reg = Arc::new(ModeBSessionRegistry::new(2, Duration::from_secs(60)));
        let id = reg.create("db").await.expect("create");
        let mut sess = reg.checkout(id).await.expect("checkout");
        assert_eq!(
            reg.len().await,
            0,
            "checked-out session is absent from the map"
        );

        // Simulate a batch having advanced the session's committed progress.
        Arc::make_mut(&mut sess.id_map).insert("ext-1".to_owned(), 42);
        sess.stats.nodes = 1;

        reg.checkin_from_drop(id, sess);
        assert_eq!(reg.len().await, 1, "the session is back in the registry");
        let restored = reg.checkout(id).await.expect("re-checkoutable");
        assert_eq!(restored.stats.nodes, 1, "accumulated progress preserved");
        assert_eq!(restored.id_map.get("ext-1"), Some(&42));
    }

    // ---- real-engine batch-driver tests ------------------------------------------------------

    fn engine() -> crate::engine::Engine {
        let clock: Arc<dyn graphus_core::capability::Clock + Send + Sync> =
            Arc::new(SharedClock::new(0));
        let metrics = Arc::new(crate::metrics::Metrics::new());
        crate::engine::spawn_engine::<MemBlockDevice, MemLogSink, _>(
            Arc::<str>::from("mode-b-test"),
            move || {
                let device = MemBlockDevice::new(0);
                let wal = graphus_wal::WalManager::create(MemLogSink::new())?;
                let store = RecordStore::create(device, wal, 256, 1)?;
                Ok(graphus_cypher::TxnCoordinator::new(store))
            },
            64,
            256,
            0,
            metrics,
            clock,
        )
        .expect("spawn test engine")
    }

    fn node_header() -> Arc<NodeHeader> {
        Arc::new(NodeHeader {
            columns: vec![
                ColumnRole::Id,
                ColumnRole::Label,
                ColumnRole::Property {
                    key: "name".to_owned(),
                    ty: PropertyType::Scalar(ScalarType::String),
                },
            ],
            id_index: 0,
        })
    }

    fn rel_header() -> Arc<RelHeader> {
        Arc::new(RelHeader {
            columns: vec![ColumnRole::StartId, ColumnRole::EndId, ColumnRole::Type],
            start_index: 0,
            end_index: 1,
            type_index: 2,
        })
    }

    fn record(fields: &[&str]) -> csv::StringRecord {
        csv::StringRecord::from(fields.to_vec())
    }

    async fn read_count(handle: &EngineHandle, stmt: &str) -> i64 {
        let ticket = handle
            .begin_auto_commit(AccessMode::Read)
            .await
            .expect("begin read");
        let mut reply = handle
            .run(ticket, stmt.to_owned(), vec![], true, None)
            .await
            .expect("run");
        let mut v = 0;
        while let Ok(Some(row)) = reply.rows.next() {
            if let Some(graphus_cypher::MaterializedValue::Value(Value::Integer(n))) = row.first() {
                v = *n;
            }
        }
        v
    }

    /// Forces a genuine SSI pivot abort against whichever transaction next writes a `:LINK`
    /// relationship-type predicate (a real conflict against the real
    /// `graphus_txn::ssi::SsiTracker`, not a mock), by constructing the exact rw-edge sequence
    /// `SsiTracker::add_edge`'s **eager committed-pivot-break rule** dooms:
    ///
    /// 1. `Trdr` begins and reads a marker predicate (`MATCH (:Marker) RETURN count(*)`), staying open.
    /// 2. `R` begins, reads the `:LINK` relationship-type predicate (the SAME predicate the target
    ///    transaction is about to write), then writes the marker predicate `Trdr` already read —
    ///    closing the edge `Trdr --rw--> R` (`R.in_conflict = true`) — then **commits**.
    /// 3. `R` is now a *committed* transaction with `in_conflict = true`, `out_conflict` still `false`
    ///    (its edge to the target hasn't formed yet).
    ///
    /// The **caller** is responsible for having already opened the target transaction (via
    /// [`EngineHandle::begin`], directly or through [`drive_mode_b_batch`]) **before** calling this
    /// function, so the target's `begin_ts` predates `R`'s eventual `commit_ts` — the concurrency
    /// precondition `SsiTracker::are_concurrent` requires — and for dispatching a `:LINK`-relationship-
    /// creating chunk on the target **after** this function returns: that write registers the target as
    /// a `RelType(:LINK)` predicate writer, which `record_predicate_write` immediately checks against
    /// `R` (a concurrent, already-committed reader of that exact predicate) — closing `R --rw--> target`
    /// right there and, because `R` is by then a committed pivot with both in- and out-conflict,
    /// **eagerly dooms the target** (`SsiTracker::add_edge`'s committed-pivot-break branch). The doom
    /// surfaces as a [`GraphusError::Transaction`] the next time the target is committed.
    async fn seed_pivot_abort_against(handle: &EngineHandle) {
        let trdr = handle.begin(AccessMode::Write).await.expect("begin trdr");
        let mut reply = handle
            .run(
                trdr,
                "MATCH (:Marker) RETURN count(*) AS c".to_owned(),
                vec![],
                false,
                None,
            )
            .await
            .expect("trdr read");
        while reply.rows.next().expect("drain").is_some() {}

        let r = handle.begin(AccessMode::Write).await.expect("begin r");
        let mut reply = handle
            .run(
                r,
                "MATCH ()-[:LINK]->() RETURN count(*) AS c".to_owned(),
                vec![],
                false,
                None,
            )
            .await
            .expect("r reads LINK predicate");
        while reply.rows.next().expect("drain").is_some() {}
        let mut reply = handle
            .run(r, "CREATE (:Marker)".to_owned(), vec![], false, None)
            .await
            .expect("r writes Marker predicate");
        while reply.rows.next().expect("drain").is_some() {}
        handle
            .commit(r)
            .await
            .expect("r commits (becomes a committed pivot: in_conflict=true)");

        // `trdr` is deliberately left OPEN (never rolled back or committed here). Rolling it back would
        // call `SsiTracker::forget(trdr)`, whose edge-cleanup (`rmp` #399) walks `trdr`'s `out_edges`
        // and RECOMPUTES the surviving partner's `in_conflict` flag from whatever edges remain — since
        // the `Trdr --rw--> R` edge was R's *only* in-edge at that point, forgetting `trdr` would reset
        // `R.in_conflict` back to `false`, silently erasing the very precondition this function exists
        // to establish (found empirically: an earlier version rolled `trdr` back here and the seeded
        // doom never fired). Leaving `trdr` open keeps the edge — and thus `R`'s conflict flags — intact
        // for the rest of the test. `trdr` itself is harmless left open; it is cleaned up when the test
        // engine shuts down.
    }

    /// (a): a batch whose FIRST attempt aborts (a genuine, real-engine concurrent SSI conflict — see
    /// [`seed_pivot_abort_against`] — not a mock) and whose automatic retry succeeds leaves
    /// `id_map`/`stats` reflecting EXACTLY the retry's own rows — no duplication, no stale bindings
    /// from the aborted attempt.
    ///
    /// Drives the REAL [`drive_mode_b_batch`] retry loop end to end, deterministically: a ticket is
    /// opened first (in program order, no task-interleaving race), the conflict is seeded against it,
    /// and it is handed to [`drive_mode_b_batch_from`] as the loop's first-attempt ticket — the loop
    /// then behaves exactly as production would (attempt 1 fails on the seeded conflict, `should_retry`
    /// fires, attempt 2 opens its own fresh ticket via the ordinary `EngineHandle::begin` path and
    /// succeeds because `R` has since settled).
    #[tokio::test]
    async fn retried_batch_after_a_real_pivot_abort_leaves_no_duplicate_or_stale_state() {
        let eng = engine();
        let handle = eng.handle.clone();

        // Nodes land first via an ordinary (unconflicted) batch.
        let mut session = ModeBSession::new("mode-b-test".to_owned());
        let node_rows = BatchRows::Nodes {
            header: node_header(),
            records: vec![
                record(&["n1", "Person", "Ada"]),
                record(&["n2", "Person", "Bob"]),
            ],
        };
        let cfg = BulkImportConfig {
            mode_b_max_batch_retries: 3,
            mode_b_retry_backoff_ms: 1,
            mode_b_chunk_rows: 10,
            ..BulkImportConfig::default()
        };
        drive_mode_b_batch(&handle, &mut session, &node_rows, &cfg)
            .await
            .expect("node batch commits cleanly (no conflict seeded against it)");
        assert_eq!(session.stats.nodes, 2);
        assert_eq!(session.id_map.len(), 2);

        let rel_rows = BatchRows::Relationships {
            header: rel_header(),
            records: vec![record(&["n1", "n2", "LINK"])],
        };

        // Open attempt 1's ticket first, THEN seed the conflict against it (deterministic program
        // order — no race), THEN hand it to the real retry loop.
        let ticket1 = handle
            .begin(AccessMode::Write)
            .await
            .expect("begin attempt 1");
        seed_pivot_abort_against(&handle).await;

        drive_mode_b_batch_from(&handle, &mut session, &rel_rows, &cfg, Some(ticket1))
            .await
            .expect("the batch eventually commits after the seeded pivot abort + automatic retry");

        assert_eq!(
            session.stats.relationships, 1,
            "exactly one relationship counted — no duplication from the aborted first attempt"
        );
        assert_eq!(
            session.stats.nodes, 2,
            "node stats untouched by the relationship batch's retry"
        );
        assert_eq!(
            session.id_map.len(),
            2,
            "id_map still holds exactly the 2 nodes, no duplicates"
        );
        let persisted = read_count(&handle, "MATCH ()-[:LINK]->() RETURN count(*) AS c").await;
        assert_eq!(
            persisted, 1,
            "exactly one :LINK relationship is durably visible — the aborted attempt left no trace"
        );

        let _ = handle.shutdown().await;
    }

    /// (b): a batch that exhausts all retries surfaces a clean terminal error and leaves
    /// `id_map`/`stats` byte-identical to their pre-batch state — nothing partially applied.
    ///
    /// Same deterministic seam as the retry-succeeds test above, but with `mode_b_max_batch_retries =
    /// 0`: the real [`drive_mode_b_batch`] retry loop must surface the seeded, genuinely retriable
    /// conflict immediately (no retry attempted) as a wrapped, still-`Transaction`-classified error.
    #[tokio::test]
    async fn a_batch_exhausting_all_retries_leaves_session_state_untouched() {
        let eng = engine();
        let handle = eng.handle.clone();
        let cfg = BulkImportConfig {
            mode_b_max_batch_retries: 0,
            mode_b_retry_backoff_ms: 1,
            mode_b_chunk_rows: 10,
            ..BulkImportConfig::default()
        };

        let mut session = ModeBSession::new("mode-b-test".to_owned());
        let node_rows = BatchRows::Nodes {
            header: node_header(),
            records: vec![
                record(&["n1", "Person", "Ada"]),
                record(&["n2", "Person", "Bob"]),
            ],
        };
        drive_mode_b_batch(&handle, &mut session, &node_rows, &cfg)
            .await
            .expect("node batch commits cleanly");
        let stats_before = session.stats;
        // A deep clone of the map contents (not the `Arc` pointer) so the post-abort assertion below
        // genuinely compares membership, not pointer identity.
        let id_map_before = (*session.id_map).clone();

        let rel_rows = BatchRows::Relationships {
            header: rel_header(),
            records: vec![record(&["n1", "n2", "LINK"])],
        };

        let ticket1 = handle
            .begin(AccessMode::Write)
            .await
            .expect("begin attempt 1");
        seed_pivot_abort_against(&handle).await;

        let err = drive_mode_b_batch_from(&handle, &mut session, &rel_rows, &cfg, Some(ticket1))
            .await
            .expect_err("the batch must surface a terminal error once retries are exhausted");
        assert!(
            matches!(err, GraphusError::Transaction(_)),
            "the exhausted-retries error stays classified Transaction/retriable: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("mode_b_max_batch_retries"),
            "the wrapped message should name the exceeded knob: {msg}"
        );

        assert_eq!(
            session.stats.nodes, stats_before.nodes,
            "stats untouched by the failed batch"
        );
        assert_eq!(session.stats.relationships, stats_before.relationships);
        assert_eq!(
            *session.id_map, id_map_before,
            "id_map untouched by the failed batch"
        );
        let persisted = read_count(&handle, "MATCH ()-[:LINK]->() RETURN count(*) AS c").await;
        assert_eq!(
            persisted, 0,
            "nothing from the exhausted-retries batch is durably visible"
        );

        let _ = handle.shutdown().await;
    }

    /// (`rmp` #598, Finding E-4): a nodes-first multi-batch load never keeps a per-attempt full
    /// clone of the growing `id_map` alive — the map is uniquely owned (`Arc::strong_count == 1`)
    /// after each node batch commits, which is what makes the post-commit `Arc::make_mut` merge an
    /// in-place, copy-free `O(1)` operation instead of the old `O(id_map)`-per-batch churn. The
    /// subsequent relationship batch still resolves its endpoints against the accumulated bindings,
    /// proving the sharing optimization did not weaken correctness.
    #[tokio::test]
    async fn nodes_first_load_keeps_id_map_uniquely_owned_and_still_resolves_rels() {
        let eng = engine();
        let handle = eng.handle.clone();
        let cfg = BulkImportConfig {
            mode_b_max_batch_retries: 3,
            mode_b_retry_backoff_ms: 1,
            mode_b_chunk_rows: 10,
            ..BulkImportConfig::default()
        };
        let mut session = ModeBSession::new("mode-b-test".to_owned());

        // Several separate node batches, mirroring a real streamed load's batch boundaries. After
        // EACH one the map must be uniquely owned (no lingering snapshot from the attempt).
        for (i, (a, b)) in [("n1", "n2"), ("n3", "n4"), ("n5", "n6")]
            .iter()
            .enumerate()
        {
            let node_rows = BatchRows::Nodes {
                header: node_header(),
                records: vec![record(&[a, "Person", "A"]), record(&[b, "Person", "B"])],
            };
            drive_mode_b_batch(&handle, &mut session, &node_rows, &cfg)
                .await
                .expect("node batch commits");
            assert_eq!(
                Arc::strong_count(&session.id_map),
                1,
                "after node batch {i} the id_map Arc must be uniquely owned (no per-attempt clone \
                 left alive) — the precondition for the copy-free make_mut merge"
            );
        }
        assert_eq!(session.id_map.len(), 6, "all six node bindings accumulated");
        assert_eq!(session.stats.nodes, 6);

        // A relationship batch resolves both endpoints against the accumulated (Arc-shared) bindings.
        let rel_rows = BatchRows::Relationships {
            header: rel_header(),
            records: vec![record(&["n1", "n6", "LINK"]), record(&["n3", "n4", "LINK"])],
        };
        drive_mode_b_batch(&handle, &mut session, &rel_rows, &cfg)
            .await
            .expect("relationship batch resolves endpoints against the shared id_map and commits");
        assert_eq!(session.stats.relationships, 2);
        assert_eq!(
            Arc::strong_count(&session.id_map),
            1,
            "a relationship batch's shared snapshot is dropped by the time the driver returns"
        );
        let persisted = read_count(&handle, "MATCH ()-[:LINK]->() RETURN count(*) AS c").await;
        assert_eq!(persisted, 2, "both relationships are durably visible");

        let _ = handle.shutdown().await;
    }
}
