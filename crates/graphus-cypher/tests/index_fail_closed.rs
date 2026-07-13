//! An index rebuild that cannot complete must leave **no index `Online` and empty** (`rmp` task #733).
//!
//! # The defects these tests pin
//!
//! **F2 — `TxnCoordinator::rebuild_index`.** The rebuild starts by calling `IndexSet::clear()`, which
//! drops every index's *entries* while deliberately keeping its *registration and state* (the caller is
//! about to refill it). If the store scan that refills them then **fails**, the old code simply
//! `return`ed — leaving every derived index registered, `Online` and **empty**. The planner kept routing
//! seeks to those indexes, the write path kept consulting them for uniqueness / node-key duplicate
//! detection, and the full-text / vector procedures kept reading their postings: all of them answering
//! **zero rows, silently**. The premature `return` also skipped the `rmp` #467 marker reset, so even the
//! cross-snapshot gate could not save a new reader. And this is not a recovery-only path: `rebuild_index`
//! also runs at run time from five index/constraint DDL call sites, so a *transient* I/O fault during a
//! `CREATE INDEX` could wipe the process's in-memory indexes and serve wrong answers until restart.
//!
//! **F4 — `TxnCoordinator::create_text_index`.** The trigram index was registered `Online` *before* the
//! scan that fills it. A fault in that scan returned an error to the client but left an `Online`, EMPTY
//! text index behind, after which every `CONTAINS` / `STARTS WITH` / `ENDS WITH` on the covered property
//! silently returned nothing. (The vector and composite creates had the same shape and are fixed with it.)
//!
//! # The contract
//!
//! A failed rebuild **fails closed**: `IndexSet::fail_closed()` makes every index *unusable* rather than
//! *empty* — the state-carrying kinds are demoted out of `Online`, the state-less candidate sources
//! (composite, bitmap) are unregistered, and the full-text/spatial marker is poisoned. Every consumer
//! then degrades to the always-correct store scan. The durable catalog is untouched, so the schema
//! survives and the next successful rebuild restores the fast paths.
//!
//! # The fault seam
//!
//! `MemBlockDevice`'s built-in faults are either write-only (`arm_io_error`) or *permanent*
//! (`FaultPlan::with_latent_sector_error`), and a permanently unreadable page would fail the scan
//! fallback too — proving only that the engine surfaces I/O errors, not that it degrades to a *correct*
//! answer. What this needs is a **transient** read fault: the store scan fails, the device then heals,
//! and the subsequent query must return the exact true set from the scan path. So these tests wrap
//! `MemBlockDevice` in a decorator that fails reads while armed — the smallest seam that models the real
//! scenario (a transient I/O fault during a `CREATE INDEX`).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use graphus_core::error::GraphusError;
use graphus_core::{PageId, Value};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::{IndexKind, IndexTarget};
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_index::fulltext::Analyzer;
use graphus_io::{BlockDevice, MemBlockDevice, Page};
use graphus_storage::recovery::recover_device;
use graphus_storage::{ConstraintKind, IndexState, RecordStore, VectorEntity, VectorSimilarity};
use graphus_wal::{LogSink, MemLogSink, WalManager};

// =================================================================================================
// A transient-read-fault device
// =================================================================================================

/// A [`BlockDevice`] decorator over [`MemBlockDevice`] whose **reads fail while armed**.
///
/// Models a transient I/O fault (the disk momentarily refuses reads, then recovers) — the scenario that
/// makes `rebuild_index`'s old failure mode dangerous, because the process keeps running afterwards with
/// silently-empty indexes. Writes and syncs are untouched: only the read path is faulted, which is what
/// the rebuild's `scan_node_ids` / `scan_rel_ids` depend on.
///
/// The arming flags are shared (`Arc`) so a test can arm/heal the device *after* it has been moved into
/// the store. Reads are counted, which lets a test sweep the fault across every read the rebuild makes.
#[derive(Debug)]
struct FaultyDevice {
    inner: MemBlockDevice,
    /// While `true`, every `read_page` fails with a storage error.
    armed: Arc<AtomicBool>,
    /// Total successful reads served (used to enumerate the fault-injection points).
    reads: Arc<AtomicUsize>,
    /// When `Some(n)`, reads succeed until the `n`-th one, which fails; then the device heals itself.
    /// This makes a fault land on ONE chosen read, wherever in the rebuild that read happens to fall.
    fail_at_read: Arc<AtomicUsize>,
    /// When not [`NO_DEAD_PAGE`], every read of this absolute device page fails **permanently** — a
    /// latent sector error that never heals (`rmp` task #733, B2). Unlike `armed` (every page) this
    /// targets ONE page, modelling e.g. a dead property/label page while node-slot pages read fine.
    dead_page: Arc<AtomicUsize>,
}

/// The sentinel meaning "no read-indexed fault armed" (no read is ever the `usize::MAX`-th).
const NO_FAIL_AT: usize = usize::MAX;
/// The sentinel meaning "no page is permanently dead".
const NO_DEAD_PAGE: usize = usize::MAX;

impl FaultyDevice {
    fn new(inner: MemBlockDevice) -> Self {
        Self {
            inner,
            armed: Arc::new(AtomicBool::new(false)),
            reads: Arc::new(AtomicUsize::new(0)),
            fail_at_read: Arc::new(AtomicUsize::new(NO_FAIL_AT)),
            dead_page: Arc::new(AtomicUsize::new(NO_DEAD_PAGE)),
        }
    }

    /// A handle that can arm / heal / inspect the device once it has been moved into the store.
    fn handle(&self) -> FaultHandle {
        FaultHandle {
            armed: Arc::clone(&self.armed),
            reads: Arc::clone(&self.reads),
            fail_at_read: Arc::clone(&self.fail_at_read),
            dead_page: Arc::clone(&self.dead_page),
        }
    }
}

#[derive(Debug, Clone)]
struct FaultHandle {
    armed: Arc<AtomicBool>,
    reads: Arc<AtomicUsize>,
    fail_at_read: Arc<AtomicUsize>,
    dead_page: Arc<AtomicUsize>,
}

impl FaultHandle {
    /// Fails **every** read until [`heal`](Self::heal).
    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    fn heal(&self) {
        self.armed.store(false, Ordering::SeqCst);
        self.fail_at_read.store(NO_FAIL_AT, Ordering::SeqCst);
        self.dead_page.store(NO_DEAD_PAGE, Ordering::SeqCst);
    }

    /// Fails exactly the `n`-th read from now on (0-based), then heals — a one-shot transient fault at a
    /// chosen point in the rebuild.
    fn fail_once_at_read(&self, n: usize) {
        self.reads.store(0, Ordering::SeqCst);
        self.fail_at_read.store(n, Ordering::SeqCst);
    }

    /// Marks absolute device page `page` **permanently unreadable** (`rmp` task #733, B2): a latent
    /// sector error that never heals, so any read of it hard-fails for the rest of the run.
    fn kill_page(&self, page: usize) {
        self.dead_page.store(page, Ordering::SeqCst);
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }

    fn reset_read_count(&self) {
        self.reads.store(0, Ordering::SeqCst);
    }
}

impl BlockDevice for FaultyDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> graphus_core::error::Result<()> {
        if self.armed.load(Ordering::SeqCst) {
            return Err(GraphusError::Storage(format!(
                "injected transient read fault on page {}",
                page.0
            )));
        }
        if page.0 as usize == self.dead_page.load(Ordering::SeqCst) {
            // A permanently dead page: it never heals and is NOT counted as a served read.
            return Err(GraphusError::Storage(format!(
                "injected PERMANENT dead-page fault on page {}",
                page.0
            )));
        }
        let n = self.reads.fetch_add(1, Ordering::SeqCst);
        if n == self.fail_at_read.load(Ordering::SeqCst) {
            // One-shot: heal so the rest of the run (and the scan fallback) sees a healthy device.
            self.fail_at_read.store(NO_FAIL_AT, Ordering::SeqCst);
            return Err(GraphusError::Storage(format!(
                "injected transient read fault on page {} (read #{n})",
                page.0
            )));
        }
        self.inner.read_page(page, buf)
    }

    fn write_page(&mut self, page: PageId, buf: &Page) -> graphus_core::error::Result<()> {
        self.inner.write_page(page, buf)
    }

    fn sync_data(&mut self) -> graphus_core::error::Result<()> {
        self.inner.sync_data()
    }

    fn sync_all(&mut self) -> graphus_core::error::Result<()> {
        self.inner.sync_all()
    }

    fn page_count(&self) -> u64 {
        self.inner.page_count()
    }

    fn extend(&mut self, additional: u64) -> graphus_core::error::Result<()> {
        self.inner.extend(additional)
    }
}

/// Articles carrying the search term — enough that the store spans far more pages than
/// [`FAULTED_POOL_PAGES`], so a rebuild scan MUST read the device (where the fault waits) rather than
/// being served entirely from a pool warmed by `RecordStore::open`.
const MATCHING: usize = 300;
/// Articles that do not carry it.
const NON_MATCHING: usize = 150;
/// The buffer-pool size of a faulted store: small enough that a full store scan cannot be served from
/// memory, so the injected read fault is actually reachable.
const FAULTED_POOL_PAGES: usize = 4;

type FaultyStore = RecordStore<FaultyDevice, MemLogSink>;
type FaultyCoord = TxnCoordinator<FaultyDevice, MemLogSink>;
type MemStore = RecordStore<MemBlockDevice, MemLogSink>;
type MemCoord = TxnCoordinator<MemBlockDevice, MemLogSink>;

// =================================================================================================
// Harness
// =================================================================================================

/// Compiles `src` against the **coordinator's real catalog** (`rmp` task #733).
///
/// This is load-bearing, not incidental. Compiling against `IndexCatalog::empty()` — as this harness
/// first did — means the planner NEVER emits an index seek, so every query runs as a scan and the seam
/// gates under test (`index_seek_eq` / `_range` / `_text` / `_spatial*` declining a non-`Online` index)
/// are never reached: the tests would pass on an engine with no gates at all. With the real catalog, a
/// healthy engine plans a genuine `NodeIndexSeek` / `NodeTextIndexSeek`, so the fault-injection tests
/// below actually exercise the seek path and its fallback.
fn compile<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    coord: &TxnCoordinator<D, S>,
    src: &str,
) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &coord.catalog())
}

/// Whether `src` compiles — against the coordinator's real catalog — to a plan containing `op`. Used to
/// prove that a healthy engine really does route this query through an index seek (so the degraded runs
/// below are testing the gate, not an accident of planning).
fn plan_contains<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    coord: &TxnCoordinator<D, S>,
    src: &str,
    op: &str,
) -> bool {
    format!("{:?}", compile(coord, src)).contains(op)
}

/// Runs `src` and returns its rows, asserting the statement captured no error.
fn run<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    coord: &mut TxnCoordinator<D, S>,
    src: &str,
) -> Vec<Row> {
    let plan = compile(coord, src);
    let txn = coord.begin_serializable();
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let rows = {
        let mut graph = coord.statement(txn).expect("statement");
        let rows = {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect")
        };
        assert!(
            !graph.has_error(),
            "statement captured an error: {:?}",
            graph.take_error()
        );
        rows
    };
    coord.commit(txn).expect("commit");
    rows
}

/// Runs `src` expecting the **statement** to fail (a captured runtime error or a cursor error), and
/// returns the rendered error. Used to prove that an unusable vector index ERRORS rather than returning
/// an empty neighbour set.
fn run_expect_error<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    coord: &mut TxnCoordinator<D, S>,
    src: &str,
) -> String {
    let plan = compile(coord, src);
    let txn = coord.begin_serializable();
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let err = {
        let mut graph = coord.statement(txn).expect("statement");
        let outcome = execute(&plan, &bound, &mut graph)
            .and_then(|mut cursor| cursor.collect_all())
            .err()
            .map(|e| format!("{e:?}"));
        outcome
            .or_else(|| graph.take_error().map(|e| format!("{e:?}")))
            .unwrap_or_default()
    };
    let _ = coord.rollback(txn);
    assert!(
        !err.is_empty(),
        "expected the statement to FAIL, but it succeeded silently: {src}"
    );
    err
}

fn write<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    coord: &mut TxnCoordinator<D, S>,
    src: &str,
) {
    let _ = run(coord, src);
}

fn ids_of(rows: &[Row], column: &str) -> Vec<u64> {
    let mut ids: Vec<u64> = rows
        .iter()
        .map(|r| match r.value(column) {
            Value::Integer(i) => i as u64,
            other => panic!("expected an integer id in {column:?}, got {other:?}"),
        })
        .collect();
    ids.sort_unstable();
    ids
}

/// Seeds a graph exercising **every** index kind whose consumer could read an empty index: nodes with a
/// text property (full-text + text + range), and typed relationships with a text property (relationship
/// full-text + relationship range).
fn seed<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    coord: &mut TxnCoordinator<D, S>,
) {
    write(
        coord,
        &format!(
            "UNWIND range(1, {MATCHING}) AS i \
             CREATE (:Article {{title: 'investigadores relatorio numero ' + toString(i), \
                                slug: 'match-' + toString(i)}})"
        ),
    );
    write(
        coord,
        &format!(
            "UNWIND range(1, {NON_MATCHING}) AS i \
             CREATE (:Article {{title: 'noticia diversa numero ' + toString(i), \
                                slug: 'other-' + toString(i)}})"
        ),
    );
    // Relationships carrying text, for the relationship full-text index.
    write(
        coord,
        "MATCH (a:Article {slug: 'match-1'}), (b:Article {slug: 'match-2'}) \
         CREATE (a)-[:CITES {note: 'investigadores citam prova', tag: 'prova'}]->(b)",
    );
    write(
        coord,
        "MATCH (a:Article {slug: 'match-3'}), (b:Article {slug: 'match-4'}) \
         CREATE (a)-[:CITES {note: 'nota irrelevante', tag: 'outro'}]->(b)",
    );
}

/// Declares one index of every kind, each fully built + `Online`.
fn declare_indexes<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    coord: &mut TxnCoordinator<D, S>,
) {
    coord
        .create_fulltext_index(
            "article_ft",
            &["Article".to_owned()],
            &["title".to_owned()],
            Analyzer::Standard,
            false,
        )
        .expect("create node fulltext index");
    coord
        .create_fulltext_rel_index(
            "cites_ft",
            &["CITES".to_owned()],
            &["note".to_owned()],
            Analyzer::Standard,
            false,
        )
        .expect("create rel fulltext index");
    coord
        .create_node_property_index("Article", "slug")
        .expect("create node property index");
    coord
        .create_text_index("article_title_text", "Article", "title", false)
        .expect("create text index");
    // Drive every incremental build to completion so the baseline is fully `Online`.
    let mut iters = 0;
    while coord.has_pending_index_builds() {
        coord.advance_index_builds(64);
        iters += 1;
        assert!(iters < 100_000, "the builds must terminate");
    }
}

fn truth_articles<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    coord: &mut TxnCoordinator<D, S>,
) -> Vec<u64> {
    let rows = run(
        coord,
        "MATCH (a:Article) WHERE a.title CONTAINS 'investigadores' RETURN id(a) AS id",
    );
    ids_of(&rows, "id")
}

fn fulltext_articles<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    coord: &mut TxnCoordinator<D, S>,
) -> Vec<u64> {
    let rows = run(
        coord,
        "CALL db.index.fulltext.queryNodes('article_ft', 'investigadores') \
         YIELD node RETURN id(node) AS id",
    );
    ids_of(&rows, "id")
}

fn fulltext_cites<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    coord: &mut TxnCoordinator<D, S>,
) -> Vec<u64> {
    let rows = run(
        coord,
        "CALL db.index.fulltext.queryRelationships('cites_ft', 'investigadores') \
         YIELD relationship RETURN id(relationship) AS id",
    );
    ids_of(&rows, "id")
}

/// A point lookup the planner routes through the node-property index when it is `Online`, and through a
/// label scan + filter when it is not — the same rows either way.
fn slug_lookup<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    coord: &mut TxnCoordinator<D, S>,
) -> Vec<u64> {
    let rows = run(
        coord,
        "MATCH (a:Article {slug: 'match-7'}) RETURN id(a) AS id",
    );
    ids_of(&rows, "id")
}

/// A `CONTAINS` the planner routes through the trigram text index when it is `Online`.
fn contains_lookup<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    coord: &mut TxnCoordinator<D, S>,
) -> Vec<u64> {
    let rows = run(
        coord,
        "MATCH (a:Article) WHERE a.title CONTAINS 'relatorio' RETURN id(a) AS id",
    );
    ids_of(&rows, "id")
}

/// Rebuilds the store's durable image on a **fresh [`FaultyDevice`]** — the faithful restart model
/// (mirrors `tests/checkpoint_reclaim.rs::recover_from_durable`): flush the pages home (steal), copy the
/// device image page by page, then replay the durable WAL over it. Replaying the WAL onto a *blank*
/// device would not do: once the store has checkpointed, the truth of record for the pages below the
/// checkpoint LSN lives on the **device**, and the WAL prefix may have been reclaimed.
///
/// The point of the fresh device is a **cold buffer pool**: the next coordinator's open-time rebuild must
/// actually read the device, which is where the injected fault waits.
fn restart_on_faulty_device(store: &mut MemStore) -> (FaultyDevice, WalManager<MemLogSink>) {
    store.flush().expect("flush pages home (steal)");
    let pages = store.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = FaultyDevice::new(MemBlockDevice::new(max + 1));
    let staged: Vec<(u64, Box<Page>)> = pages
        .iter()
        .map(|p| (p.0, store.read_device_page(*p).expect("read device page")))
        .collect();
    for (idx, bytes) in staged {
        device
            .write_page(PageId(idx), &bytes)
            .expect("stage device page");
    }
    device.sync_all().expect("persist the disk image");

    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    (device, wal)
}

/// A healthy, fully-indexed baseline store (in-memory device).
fn baseline() -> MemStore {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: MemStore = RecordStore::create(device, wal, 64, 1).expect("create store");
    let mut coord: MemCoord = TxnCoordinator::new(store);
    seed(&mut coord);
    declare_indexes(&mut coord);
    coord.into_store()
}

/// Whether the planner's catalog exposes an index of `kind` covering `(label, property)` — i.e. whether
/// the coordinator considers it `Online` and usable for a seek.
fn catalog_exposes<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    coord: &TxnCoordinator<D, S>,
    kind: IndexKind,
    label: &str,
    property: &str,
) -> bool {
    coord.catalog().indexes().iter().any(|d| {
        d.kind == kind
            && d.target == IndexTarget::label(label)
            && d.properties.iter().any(|p| p == property)
    })
}

// =================================================================================================
// F2 — a rebuild whose store scan faults must fail closed
// =================================================================================================

/// The headline F2 regression: a rebuild whose node scan faults must NOT leave indexes `Online` and
/// empty. Every reader must degrade to the correct scan; the vector-like kinds that cannot degrade must
/// error; and the durable schema must survive.
#[test]
fn a_rebuild_whose_scan_faults_never_leaves_an_online_empty_index() {
    let mut store = baseline();
    let (device, wal) = restart_on_faulty_device(&mut store);
    let fault = device.handle();

    // Arm the device so EVERY read fails, then open the store and build the coordinator: its
    // open-time `rebuild_index` runs against a cold buffer pool, so its `scan_node_ids` must reach the
    // device — and fault. This is the exact state the old code left behind as "Online and empty".
    let faulty: FaultyStore =
        RecordStore::open(device, wal, FAULTED_POOL_PAGES).expect("open store");
    fault.arm();
    let mut coord: FaultyCoord = TxnCoordinator::new(faulty);
    fault.heal();

    // The engine must SAY it is degraded (`rmp` task #733, B4): a silent degradation is
    // indistinguishable from a healthy-but-slow engine, and an automated readiness poll would sail
    // straight through it.
    assert!(coord.indexes_degraded(), "a fail-closed must be observable");
    assert_eq!(coord.index_fail_closed_events(), 1, "the event is counted");
    // ...and `SHOW INDEXES` must report the EFFECTIVE state, never the durable catalog's stale ONLINE —
    // otherwise a `wait_for_indexes` poll on `state != populating` passes instantly on a degraded engine.
    assert!(
        coord
            .list_node_property_indexes()
            .iter()
            .all(|(_, _, _, state)| *state == IndexState::Populating),
        "a degraded index must never report itself ONLINE: {:?}",
        coord.list_node_property_indexes()
    );
    assert!(
        coord
            .list_fulltext_indexes()
            .iter()
            .all(|l| l.5 == IndexState::Populating),
        "a degraded full-text index must never report itself ONLINE"
    );

    // The schema survived: the durable catalog is untouched by a failed rebuild.
    assert_eq!(
        coord.list_fulltext_indexes().len(),
        2,
        "a failed rebuild must not drop the durable schema"
    );

    // The planner no longer sees the (empty) indexes — they were demoted out of `Online`.
    assert!(
        !catalog_exposes(&coord, IndexKind::Property, "Article", "slug"),
        "an index left empty by a failed rebuild must be withdrawn from the planner's catalog"
    );
    assert!(
        !catalog_exposes(&coord, IndexKind::Text, "Article", "title"),
        "the text index must be withdrawn from the planner's catalog too"
    );

    // And every query still returns the TRUE rows, through the scan fallback.
    let expected = truth_articles(&mut coord);
    assert_eq!(expected.len(), MATCHING, "ground truth");
    assert_eq!(
        fulltext_articles(&mut coord),
        expected,
        "the node full-text query must fall back to the scan, never answer from an empty index"
    );
    assert_eq!(
        fulltext_cites(&mut coord).len(),
        1,
        "the relationship full-text query must fall back to the scan too"
    );
    assert_eq!(
        slug_lookup(&mut coord).len(),
        1,
        "the node-property point lookup must still find its row (via the label scan)"
    );
    assert_eq!(
        contains_lookup(&mut coord).len(),
        MATCHING,
        "CONTAINS must still find its rows (via the label scan + residual)"
    );
}

/// The same invariant, swept across **every** read the rebuild makes: whichever read faults — in the
/// node scan or in the relationship scan — the engine must end up fail-closed and still answer
/// correctly. This covers both scan branches without depending on the store's page layout.
#[test]
fn a_fault_at_any_point_of_the_rebuild_still_answers_correctly() {
    // How many device reads does a healthy open-time rebuild make? That is the space of injection points.
    let total_reads = {
        let mut store = baseline();
        let (device, wal) = restart_on_faulty_device(&mut store);
        let fault = device.handle();
        let faulty: FaultyStore =
            RecordStore::open(device, wal, FAULTED_POOL_PAGES).expect("open store");
        fault.reset_read_count();
        let _coord: FaultyCoord = TxnCoordinator::new(faulty);
        fault.reads()
    };
    assert!(
        total_reads > 1,
        "the rebuild must read the device on a cold pool (got {total_reads} reads)"
    );

    for k in 0..total_reads {
        let mut store = baseline();
        let (device, wal) = restart_on_faulty_device(&mut store);
        let fault = device.handle();
        let faulty: FaultyStore =
            RecordStore::open(device, wal, FAULTED_POOL_PAGES).expect("open store");
        // Fail exactly the k-th read of the rebuild, then heal: a transient fault at every position.
        fault.fail_once_at_read(k);
        let mut coord: FaultyCoord = TxnCoordinator::new(faulty);
        fault.heal();

        let expected = truth_articles(&mut coord);
        assert_eq!(
            expected.len(),
            MATCHING,
            "ground truth must hold with the fault at read #{k}"
        );
        assert_eq!(
            fulltext_articles(&mut coord),
            expected,
            "full-text must return the true set with the fault at read #{k}"
        );
        assert_eq!(
            slug_lookup(&mut coord).len(),
            1,
            "the point lookup must find its row with the fault at read #{k}"
        );
    }
}

/// A vector index has **no equivalent scan fallback** (an approximate structure cannot be re-derived
/// exactly by brute force), so an unusable one must raise a CLEAR ERROR — never an empty neighbour list,
/// which the caller cannot distinguish from "there are no near neighbours" (`rmp` task #733).
#[test]
fn an_unusable_vector_index_errors_instead_of_returning_no_neighbours() {
    // A store with a vector index over embeddings.
    let mut store = {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store: MemStore = RecordStore::create(device, wal, 64, 1).expect("create store");
        let mut coord: MemCoord = TxnCoordinator::new(store);
        write(
            &mut coord,
            "UNWIND range(1, 450) AS i CREATE (:Doc {embedding: [1.0, 0.0, 0.0], slug: 'd' + toString(i)})",
        );
        coord
            .begin_online_vector_index_named(
                Some("doc_vec"),
                VectorEntity::Node,
                "Doc",
                "embedding",
                3,
                VectorSimilarity::Cosine,
                16,
                100,
                false,
            )
            .expect("create vector index");
        coord.into_store()
    };

    // Sanity: on a healthy engine the k-NN answers.
    {
        let (device, wal) = restart_on_faulty_device(&mut store);
        let healthy: FaultyStore =
            RecordStore::open(device, wal, FAULTED_POOL_PAGES).expect("open store");
        let mut coord: FaultyCoord = TxnCoordinator::new(healthy);
        let rows = run(
            &mut coord,
            "CALL db.index.vector.queryNodes('doc_vec', 3, [1.0, 0.0, 0.0]) \
             YIELD node RETURN id(node) AS id",
        );
        assert_eq!(rows.len(), 3, "the healthy vector index must return k hits");
    }

    // Now fault the rebuild: the HNSW is left empty, so it is demoted and MUST refuse to answer.
    let (device, wal) = restart_on_faulty_device(&mut store);
    let fault = device.handle();
    let faulty: FaultyStore =
        RecordStore::open(device, wal, FAULTED_POOL_PAGES).expect("open store");
    fault.arm();
    let mut coord: FaultyCoord = TxnCoordinator::new(faulty);
    fault.heal();

    let err = run_expect_error(
        &mut coord,
        "CALL db.index.vector.queryNodes('doc_vec', 3, [1.0, 0.0, 0.0]) \
         YIELD node RETURN id(node) AS id",
    );
    assert!(
        err.contains("populating"),
        "the error must say the index cannot be queried yet, got: {err}"
    );
}

// =================================================================================================
// F4 — a create whose build faults must not leave the index `Online`
// =================================================================================================

/// `create_text_index` recorded the index `Online` **before** filling it. A fault in the fill returned an
/// error to the client but left an `Online`, EMPTY trigram index — after which every `CONTAINS` on the
/// covered property silently returned nothing. The create must now leave it not-`Online`, so `CONTAINS`
/// keeps returning the true rows via the label scan (`rmp` task #733).
#[test]
fn a_text_index_whose_build_faults_is_never_left_online() {
    // A store with articles but NO text index yet.
    let mut store = {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store: MemStore = RecordStore::create(device, wal, 64, 1).expect("create store");
        let mut coord: MemCoord = TxnCoordinator::new(store);
        seed(&mut coord);
        coord.into_store()
    };

    let (device, wal) = restart_on_faulty_device(&mut store);
    let fault = device.handle();
    let faulty: FaultyStore =
        RecordStore::open(device, wal, FAULTED_POOL_PAGES).expect("open store");
    let mut coord: FaultyCoord = TxnCoordinator::new(faulty); // healthy open: the pool warms up.

    // Fault the create's own build scan. A warm pool serves most pages from memory, so arming EVERY read
    // is what guarantees the scan faults wherever its first miss falls.
    fault.arm();
    let created = coord.create_text_index("article_title_text", "Article", "title", false);
    fault.heal();
    assert!(
        created.is_err(),
        "a create whose build cannot scan the store must report the fault"
    );

    // The index must NOT be usable: the planner must not see it...
    assert!(
        !catalog_exposes(&coord, IndexKind::Text, "Article", "title"),
        "a text index whose build faulted must never be exposed as Online"
    );
    // ...and the query must still return the true rows, through the label scan + residual.
    assert_eq!(
        contains_lookup(&mut coord).len(),
        MATCHING,
        "CONTAINS must keep returning the true rows after a faulted text-index build"
    );
}

/// The **incremental** build has the same hazard (`rmp` task #733): a node a chunk could not read is
/// missing from the inverted index for good, so the build must not march on and promote itself `Online`
/// over a hole. It must retry the chunk instead — and while it stays `Populating`, the full-text query
/// must keep returning the true set through the scan fallback.
#[test]
fn an_incremental_build_that_skips_a_node_never_promotes_itself() {
    // Articles, and a full-text index declared but NOT yet built (the incremental-build window).
    let mut store = {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store: MemStore = RecordStore::create(device, wal, 64, 1).expect("create store");
        let mut coord: MemCoord = TxnCoordinator::new(store);
        seed(&mut coord);
        coord.into_store()
    };

    let (device, wal) = restart_on_faulty_device(&mut store);
    let fault = device.handle();
    let faulty: FaultyStore =
        RecordStore::open(device, wal, FAULTED_POOL_PAGES).expect("open store");
    let mut coord: FaultyCoord = TxnCoordinator::new(faulty);
    coord
        .create_fulltext_index(
            "article_ft",
            &["Article".to_owned()],
            &["title".to_owned()],
            Analyzer::Standard,
            false,
        )
        .expect("create fulltext index");
    assert!(coord.has_pending_index_builds());

    // Fault the build's chunk reads: every chunk it attempts skips nodes it cannot read.
    fault.arm();
    for _ in 0..8 {
        coord.advance_index_builds(64);
    }
    fault.heal();

    // The build must NOT have promoted itself over the hole.
    assert!(
        coord.has_pending_index_builds(),
        "a build that could not read a node must not promote itself Online"
    );
    let expected = truth_articles(&mut coord);
    assert_eq!(expected.len(), MATCHING, "ground truth");
    assert_eq!(
        fulltext_articles(&mut coord),
        expected,
        "while the build is stalled, the query must be served by the exact scan fallback"
    );

    // The device has healed: the build now completes and the Online index agrees with the truth.
    let mut iters = 0;
    while coord.has_pending_index_builds() {
        coord.advance_index_builds(64);
        iters += 1;
        assert!(
            iters < 100_000,
            "the build must terminate once the fault heals"
        );
    }
    assert_eq!(
        fulltext_articles(&mut coord),
        expected,
        "the promoted index must agree with the scan"
    );
}

// =================================================================================================
// B1 — a fail-closed must invalidate an IN-FLIGHT incremental build (`rmp` task #733)
// =================================================================================================

/// **The B1 regression** (found by the storage auditor's fault-injection probe, reproduced here).
///
/// The incremental build queues live on the **coordinator**, not on the `IndexSet`, so `fail_closed()`
/// could not reach them: it emptied the half-built B-tree, and the build then RESUMED FROM ITS OLD
/// CURSOR, indexed only the TAIL of its snapshot, and promoted the index `Online` holding a fraction of
/// the rows. Two committed-data defects followed, both proven by the auditor's probe:
///
///  1. a point lookup through that `Online` index returned **0 rows** for a row that exists (an
///     `index_seek_eq` served from a tree missing the head of the snapshot); and
///  2. `unique_conflict` — which trusts the same tree as an **exact** candidate source — stopped seeing
///     the existing holder, so a `IS UNIQUE` constraint **accepted a duplicate**.
///
/// The fix is an epoch (`IndexSet::wipe_generation`): a build that observes a new epoch restarts from
/// cursor 0 over its snapshot. The full-text and spatial builds escaped the worst of this only by
/// accident (the `rmp` #467 marker poison keeps readers off the inverted index); the node-property
/// B-tree has no such marker, which is why this had to be closed at the build, not at the reader.
#[test]
fn a_wipe_mid_build_restarts_it_instead_of_publishing_a_holed_index() {
    // A healthy baseline store with articles but no indexes.
    let seeded = || {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store: MemStore = RecordStore::create(device, wal, 64, 1).expect("create store");
        let mut coord: MemCoord = TxnCoordinator::new(store);
        seed(&mut coord);
        coord.into_store()
    };

    // The scenario, with a one-shot transient read fault injected at read `k` of the DDL below. The DDL
    // (`CREATE INDEX` on a second property) drives a full `rebuild_index`; whichever read the fault lands
    // on, the invariant must hold: NO index may end up `Online` while missing committed rows.
    //
    // The fault is swept rather than pinned to one read because the DDL touches the store several times
    // (token lookup, catalog write, commit, then the rebuild's scan); sweeping guarantees we hit the
    // rebuild's scan — the window that wipes the in-flight build's tree — without hard-coding a page
    // layout, and every other landing point must be safe too.
    let scenario = |k: usize| -> (FaultyCoord, bool) {
        let mut store = seeded();
        let (device, wal) = restart_on_faulty_device(&mut store);
        let fault = device.handle();
        let faulty: FaultyStore =
            RecordStore::open(device, wal, FAULTED_POOL_PAGES).expect("open store");
        let mut coord: FaultyCoord = TxnCoordinator::new(faulty);

        // The **incremental** (non-blocking) create: it registers `Populating` and defers the per-node
        // indexing to `advance_index_builds` — the queue that lives on the coordinator, which
        // `IndexSet::fail_closed` cannot reach.
        coord
            .begin_online_node_property_index("Article", "slug")
            .expect("declare the online index");
        assert!(coord.has_pending_index_builds(), "the build is incremental");
        // Advance it PART WAY: its tree now holds the HEAD of the snapshot, cursor mid-way. This is the
        // state the wipe destroys.
        coord.advance_index_builds(64);
        assert!(coord.has_pending_index_builds(), "still mid-build");

        // ***THE LINE THAT MAKES THIS TEST NON-VACUOUS.*** A row written AFTER the build captured its
        // snapshot. `reindex_node` carries it straight into the (still `Populating`) tree — the index is
        // maintained for live writes, which is exactly why the build only ever needed to cover the rows
        // that pre-existed it.
        //
        // But `IndexSet::clear()` — which every rebuild runs immediately before the scan that may fault —
        // destroys those maintenance writes along with everything else. So a build that restarts at
        // cursor 0 over its ORIGINAL snapshot silently loses this row FOREVER, and then promotes itself
        // `Online` over the hole. Without a post-snapshot write the snapshot equals the whole store, the
        // restart covers everything, and the test is green while proving nothing.
        write(
            &mut coord,
            "CREATE (:Article {slug: 'late-1', title: 'escrita depois do snapshot'})",
        );

        // A second DDL — the SYNCHRONOUS create, which drives a full `rebuild_index` — with a transient
        // fault armed at read `k`. Its rebuild may fault, wiping the half-built tree of the in-flight
        // build above and failing closed; or the DDL may fail earlier. Both are acceptable, and both
        // must leave the engine correct.
        fault.fail_once_at_read(k);
        let _ = coord.create_node_property_index("Article", "title");
        fault.heal();
        let wiped = coord.indexes_degraded();

        // Drive every build to completion on the now-healthy device. This is the moment of truth: the
        // in-flight build either restarts over its snapshot (correct) or resumes from its stale cursor
        // and PROMOTES ITSELF `Online` over an emptied tree (the defect).
        //
        // The probes below run HERE — before any degraded-rebuild repair. The repair would refill every
        // registered index from the store and hide the hole, but it cannot undo what the engine did in
        // the meantime: a query served in this window returns wrong rows, and a uniqueness check served
        // in this window can COMMIT A DUPLICATE, which no later rebuild can take back.
        let mut iters = 0;
        while coord.has_pending_index_builds() {
            coord.advance_index_builds(64);
            iters += 1;
            assert!(iters < 100_000, "the builds must terminate");
        }
        (coord, wiped)
    };

    // How many reads does the faulted DDL make? That is the space of injection points.
    let probe_reads = {
        let mut store = seeded();
        let (device, wal) = restart_on_faulty_device(&mut store);
        let fault = device.handle();
        let faulty: FaultyStore =
            RecordStore::open(device, wal, FAULTED_POOL_PAGES).expect("open store");
        let mut coord: FaultyCoord = TxnCoordinator::new(faulty);
        coord
            .begin_online_node_property_index("Article", "slug")
            .expect("declare");
        coord.advance_index_builds(64);
        fault.reset_read_count();
        let _ = coord.create_node_property_index("Article", "title");
        fault.reads()
    };
    assert!(
        probe_reads > 0,
        "the DDL must reach the device (got {probe_reads} reads)"
    );

    let mut wipes = 0;
    for k in 0..probe_reads {
        let (mut coord, wiped) = scenario(k);
        if wiped {
            wipes += 1;
        }

        // The index must be Online AND the planner must route through it — otherwise the probe below is
        // measuring a scan and proves nothing.
        assert!(
            catalog_exposes(&coord, IndexKind::Property, "Article", "slug"),
            "the index must be Online once the builds complete (fault at read #{k})"
        );
        let probe = "MATCH (a:Article {slug: 'match-1'}) RETURN id(a) AS id";
        assert!(
            plan_contains(&coord, probe, "NodeIndexSeek"),
            "the probe must be served by an index seek (fault at read #{k})"
        );

        // PROBE 1 — rows from the HEAD of the build snapshot must still be found. Against the pre-fix
        // engine the build resumed from its stale cursor and published a tree holding only the TAIL, so
        // these returned 0 rows: a committed row invisible to a query.
        for slug in ["match-1", "match-2", "match-3", "match-7", "late-1"] {
            let rows = run(
                &mut coord,
                &format!("MATCH (a:Article {{slug: '{slug}'}}) RETURN id(a) AS id"),
            );
            assert_eq!(
                rows.len(),
                1,
                "an Online index must not be missing the head of its build snapshot \
                 (slug {slug}, fault at read #{k})"
            );
        }

        // PROBE 2 — the ACID one. `unique_conflict` trusts that same tree as an EXACT candidate source,
        // so a hole in it made a `IS UNIQUE` constraint ACCEPT a duplicate.
        coord
            .create_constraint_ddl(
                "article_slug_unique",
                "Article",
                &["slug"],
                ConstraintKind::Unique,
                None,
                false,
                false,
            )
            .expect("the constraint holds over the seeded data");
        // The duplicate is attempted on the POST-SNAPSHOT row: that is the one a cursor-0 restart drops
        // from the tree, so `unique_conflict` — which trusts the tree as an EXACT candidate source — would
        // see no holder and let the duplicate through. A committed violation of a declared invariant: no
        // later rebuild can take it back.
        for slug in ["match-7", "late-1"] {
            let dup = run_expect_error(
                &mut coord,
                &format!("CREATE (:Article {{slug: '{slug}', title: 'duplicate'}})"),
            );
            assert!(
                dup.to_lowercase().contains("constraint"),
                "a duplicate on {slug} must be REJECTED by the uniqueness constraint \
                 (fault at read #{k}), got: {dup}"
            );
            assert_eq!(
                run(
                    &mut coord,
                    &format!("MATCH (a:Article {{slug: '{slug}'}}) RETURN id(a) AS id")
                )
                .len(),
                1,
                "{slug} must still have exactly ONE holder — a duplicate was committed \
                 (fault at read #{k})"
            );
        }

        // Finally, the engine must be able to REPAIR itself (the `rmp` #733 B4 self-heal the engine tick
        // drives), leaving a healthy, index-backed engine behind.
        assert!(
            coord.retry_degraded_index_rebuild(),
            "a healthy device must let the rebuild repair the index set (fault at read #{k})"
        );
        assert!(!coord.indexes_degraded());
    }

    // The sweep must actually have produced the dangerous state at least once, or it proves nothing.
    assert!(
        wipes > 0,
        "no injection point wiped the index set mid-build — the test would be vacuous"
    );
}

// =================================================================================================
// B2 / B3 — no build and no DDL may publish a schema object it could not fully verify
// =================================================================================================

/// B2: `declare_bitmap_index` was the one build that ignored its own gap flag — a scan fault used to
/// `return Ok(())`, reporting SUCCESS while leaving an EMPTY bitmap registered. A bitmap is a
/// membership-exact candidate source, so an empty one answers every seek with zero rows
/// (`rmp` task #733).
#[test]
fn a_bitmap_index_whose_capture_faults_is_not_left_registered_and_empty() {
    let mut store = {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store: MemStore = RecordStore::create(device, wal, 64, 1).expect("create store");
        let mut coord: MemCoord = TxnCoordinator::new(store);
        seed(&mut coord);
        coord.into_store()
    };
    let (device, wal) = restart_on_faulty_device(&mut store);
    let fault = device.handle();
    let faulty: FaultyStore =
        RecordStore::open(device, wal, FAULTED_POOL_PAGES).expect("open store");
    let mut coord: FaultyCoord = TxnCoordinator::new(faulty);

    fault.arm();
    let declared = coord.declare_bitmap_index("Article", "slug");
    fault.heal();
    assert!(
        declared.is_err(),
        "a bitmap capture that could not scan the store must REPORT the fault, not return Ok"
    );

    // The (empty) bitmap must not be left answering seeks: every query still returns the true rows.
    assert_eq!(
        run(
            &mut coord,
            "MATCH (a:Article {slug: 'match-7'}) RETURN id(a) AS id"
        )
        .len(),
        1,
        "a point lookup must still find its row after a faulted bitmap capture"
    );
    assert_eq!(truth_articles(&mut coord).len(), MATCHING, "ground truth");
}

/// B3: a `CREATE CONSTRAINT … IS UNIQUE` must be REFUSED when the validation walk cannot read a node —
/// it used to `continue`, so the constraint could be accepted over data that violates it, with the
/// duplicate hiding in the unreadable node. Refusing is always safe for a DDL (`rmp` task #733).
#[test]
fn a_constraint_whose_validation_cannot_read_a_node_is_refused() {
    let mut store = {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store: MemStore = RecordStore::create(device, wal, 64, 1).expect("create store");
        let mut coord: MemCoord = TxnCoordinator::new(store);
        seed(&mut coord);
        coord.into_store()
    };
    let (device, wal) = restart_on_faulty_device(&mut store);
    let fault = device.handle();
    let faulty: FaultyStore =
        RecordStore::open(device, wal, FAULTED_POOL_PAGES).expect("open store");
    let mut coord: FaultyCoord = TxnCoordinator::new(faulty);

    fault.arm();
    let created = coord.create_constraint_ddl(
        "article_slug_unique",
        "Article",
        &["slug"],
        ConstraintKind::Unique,
        None,
        false,
        false,
    );
    fault.heal();
    assert!(
        created.is_err(),
        "a uniqueness constraint whose validation could not read the data must be REFUSED — \
         accepting it would declare an invariant that the committed data may already violate"
    );
    assert!(
        coord.list_constraints().is_empty(),
        "a refused constraint must leave no schema behind"
    );
}

/// B5: the defence-in-depth gates on the *seek* seams are only meaningful if the planner actually emits
/// a seek. This pins the harness's own coverage: on a HEALTHY engine these queries compile to real index
/// seeks (so the degraded runs above genuinely exercise `index_seek_eq` / `index_seek_text` declining),
/// and on a degraded one they fall back to scans and still return the truth.
#[test]
fn a_healthy_engine_really_does_plan_index_seeks_for_these_probes() {
    let mut store = baseline();
    let (device, wal) = restart_on_faulty_device(&mut store);
    let healthy: FaultyStore =
        RecordStore::open(device, wal, FAULTED_POOL_PAGES).expect("open store");
    let mut coord: FaultyCoord = TxnCoordinator::new(healthy);

    let point = "MATCH (a:Article {slug: 'match-7'}) RETURN id(a) AS id";
    let contains = "MATCH (a:Article) WHERE a.title CONTAINS 'relatorio' RETURN id(a) AS id";
    assert!(
        plan_contains(&coord, point, "NodeIndexSeek"),
        "the point lookup must plan a NodeIndexSeek on a healthy engine"
    );
    assert!(
        plan_contains(&coord, contains, "NodeTextIndexSeek"),
        "the CONTAINS must plan a NodeTextIndexSeek on a healthy engine"
    );
    assert_eq!(run(&mut coord, point).len(), 1);
    assert_eq!(run(&mut coord, contains).len(), MATCHING);
}

// =================================================================================================
// C2 — a build against a PERSISTENTLY faulting store must terminate (`rmp` task #733)
// =================================================================================================

/// Graphus assumes storage faults are **persistent** (checksum / torn page). A build that rewinds its
/// cursor on every unreadable chunk therefore never advances — and `LocalEngine::drain_index_builds`
/// spins `while coord.has_pending_index_builds() { coord.advance_index_builds(usize::MAX) }`, so that is
/// an **infinite loop at 100% CPU**, re-scanning the store on every iteration (the auditor measured
/// 20 001 iterations before giving up).
///
/// The build must instead be **poisoned** after a bounded number of stalled attempts: dropped
/// un-promoted, its index left `Populating` (and therefore never served, so answers stay correct via the
/// scan). Terminates, never holes, never spins.
#[test]
fn a_build_against_a_permanently_faulty_store_terminates_instead_of_spinning() {
    let mut store = {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store: MemStore = RecordStore::create(device, wal, 64, 1).expect("create store");
        let mut coord: MemCoord = TxnCoordinator::new(store);
        seed(&mut coord);
        coord.into_store()
    };
    let (device, wal) = restart_on_faulty_device(&mut store);
    let fault = device.handle();
    let faulty: FaultyStore =
        RecordStore::open(device, wal, FAULTED_POOL_PAGES).expect("open store");
    let mut coord: FaultyCoord = TxnCoordinator::new(faulty);
    coord
        .begin_online_node_property_index("Article", "slug")
        .expect("declare the online index");
    assert!(coord.has_pending_index_builds());

    // The device now fails EVERY read, for good — and stays that way. This is the drain loop the local
    // engine, the DST driver and the examples all run.
    fault.arm();
    let mut iters = 0u32;
    while coord.has_pending_index_builds() {
        coord.advance_index_builds(usize::MAX);
        iters += 1;
        assert!(
            iters < 10_000,
            "the drain loop MUST terminate against a permanently faulting store — \
             it spun {iters} times"
        );
    }
    fault.heal();

    // It terminated by poisoning the build, so the index was never promoted...
    assert!(
        !catalog_exposes(&coord, IndexKind::Property, "Article", "slug"),
        "a build that could never read the store must NOT have promoted its index"
    );
    // ...and every query still returns the truth, through the exact scan.
    assert_eq!(
        run(
            &mut coord,
            "MATCH (a:Article {slug: 'match-7'}) RETURN id(a) AS id"
        )
        .len(),
        1,
        "answers must stay correct while the index is unusable"
    );
    assert_eq!(truth_articles(&mut coord).len(), MATCHING);
}

// =================================================================================================
// C3 — a REL KEY duplicate check must FAIL CLOSED on a read fault (`rmp` task #733)
// =================================================================================================

/// `rel_key_tuple_conflict` swallowed a scan fault (`scan_rel_ids().ok()?`) and returned `None`, which
/// its caller reads as **"no duplicate exists"** — so a `REL KEY` constraint **accepted a duplicate** on
/// any read fault: a committed violation of a declared invariant, produced by an I/O error. It must
/// capture the error (aborting the write) exactly as its single-property twin `rel_scan_eq` already did.
#[test]
fn a_rel_key_duplicate_check_fails_closed_on_a_read_fault() {
    let seeded = || {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store: MemStore = RecordStore::create(device, wal, 64, 1).expect("create store");
        let mut coord: MemCoord = TxnCoordinator::new(store);
        seed(&mut coord);
        // MANY relationships, so the relationship store spans far more pages than the faulted buffer
        // pool: without this the duplicate check's `scan_rel_ids` is served entirely from memory and the
        // injected read fault can never land inside it — the test would be green and vacuous.
        write(
            &mut coord,
            "UNWIND range(1, 200) AS i \
             MATCH (a:Article {slug: 'match-1'}), (b:Article {slug: 'match-2'}) \
             CREATE (a)-[:CITES {note: 'nota ' + toString(i), tag: 'tag ' + toString(i)}]->(b)",
        );
        // The REL KEY is COMPOSITE (note, tag): a single-property one routes through `rel_scan_eq`, which
        // already failed closed — `rel_key_tuple_conflict` is the tuple path, and the one that did not.
        coord
            .create_constraint_ddl(
                "cites_note_key",
                "CITES",
                &["note", "tag"],
                ConstraintKind::RelKey,
                None,
                false,
                false,
            )
            .expect("the REL KEY holds over the seeded data");
        coord.into_store()
    };

    // The statement that must be REJECTED: it would give a second CITES the note an existing one holds.
    const DUP: &str = "MATCH (a:Article {slug: 'match-5'}), (b:Article {slug: 'match-6'}) \
                       CREATE (a)-[:CITES {note: 'investigadores citam prova', tag: 'prova'}]->(b)";
    const HOLDERS: &str = "MATCH ()-[r:CITES {note: 'investigadores citam prova', tag: 'prova'}]->() RETURN id(r) AS id";

    let open_faulty = |store: &mut MemStore| {
        let (device, wal) = restart_on_faulty_device(store);
        let fault = device.handle();
        let faulty: FaultyStore =
            RecordStore::open(device, wal, FAULTED_POOL_PAGES).expect("open store");
        let coord: FaultyCoord = TxnCoordinator::new(faulty);
        (coord, fault)
    };

    // Sanity + the injection-point count: on a HEALTHY engine the constraint rejects the duplicate.
    let reads = {
        let mut store = seeded();
        let (mut coord, fault) = open_faulty(&mut store);
        fault.reset_read_count();
        let err = run_expect_error(&mut coord, DUP);
        assert!(
            err.to_lowercase().contains("constraint"),
            "the healthy engine must reject the duplicate, got: {err}"
        );
        assert_eq!(run(&mut coord, HOLDERS).len(), 1, "still one holder");
        fault.reads()
    };
    assert!(reads > 0, "the write must reach the device");

    // Sweep a one-shot read fault across every read the statement makes. Whichever read faults — and one
    // of them IS the duplicate check's `scan_rel_ids` — the invariant must hold: the write either fails
    // or is rejected, but a SECOND holder of the key must NEVER be committed.
    //
    // Sweeping is what makes this test meaningful: arming every read simply makes the whole statement
    // fail for unrelated reasons (the MATCH cannot even read its endpoints), which proves nothing about
    // the duplicate check. The fail-OPEN was reachable precisely when everything else succeeded.
    for k in 0..reads {
        let mut store = seeded();
        let (mut coord, fault) = open_faulty(&mut store);
        fault.fail_once_at_read(k);
        let plan = compile(&coord, DUP);
        let txn = coord.begin_serializable();
        let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
        {
            let mut graph = coord.statement(txn).expect("statement");
            let outcome = execute(&plan, &bound, &mut graph).and_then(|mut c| c.collect_all());
            let failed = outcome.is_err() || graph.has_error();
            drop(graph);
            if failed {
                let _ = coord.rollback(txn);
            } else {
                // The statement believed it succeeded. That is only legitimate if no duplicate was made.
                coord.commit(txn).expect("commit");
            }
        }
        fault.heal();

        assert_eq!(
            run(&mut coord, HOLDERS).len(),
            1,
            "a duplicate REL KEY tuple was COMMITTED through a read fault at read #{k}: the \
             duplicate check swallowed the scan error and reported 'no duplicate'"
        );
    }
}

// =================================================================================================
// B2 — the poison<->resurrect cycle must be BOUNDED against a permanently-dead property page
// =================================================================================================

/// **The B2 regression** (a defect the round-4 M1 resurrection introduced, found by the auditor).
///
/// Resurrecting a poisoned build probes the store with `scan_node_ids`, which reads only the node *slot*
/// pages — not the property / label pages a build actually indexes. A build poisoned by an unreadable
/// **property** page therefore passes the probe, is resurrected with a full stall budget, re-drains, hits
/// the same dead page, and re-poisons. The M1 code reset the retry throttle to `0` on every successful
/// probe, so this repeated on **every** drive of the build: on a live server (2 ms tick) that is a
/// permanent ~100% CPU + I/O + log-flood storm — the very spin the round-3 stall budget had eliminated,
/// re-introduced through the resurrection door.
///
/// This replicates `LocalEngine::drain_index_builds` exactly (`retry_poisoned` → drain →
/// `retry_degraded`) and sweeps a permanently-dead page across the whole device. For **every** page the
/// two invariants must hold: (a) each drain *terminates* (the stall budget — round 3), and (b) the
/// number of poison events stays *bounded* across many drains rather than climbing by one per drain (the
/// B2 fix — an escalating backoff). Against the M1 code the property page climbs +1 per drain.
#[test]
fn a_dead_property_page_does_not_cause_an_unbounded_poison_resurrect_cycle() {
    // The LocalEngine drain, verbatim. Returns the poison-event count after this drain; asserts the inner
    // build loop TERMINATES (a reverted stall budget would otherwise hang the suite).
    fn drain(coord: &mut FaultyCoord) -> u64 {
        let _resurrected = coord.retry_poisoned_index_builds();
        let mut iters = 0;
        while coord.has_pending_index_builds() {
            coord.advance_index_builds(usize::MAX);
            iters += 1;
            assert!(
                iters < 10_000,
                "a single drain must terminate — the build loop spun {iters} times"
            );
        }
        let _healed = coord.retry_degraded_index_rebuild();
        coord.index_build_poison_events()
    }

    // A store with articles carrying string properties (slug + title), so it spans property/heap pages
    // distinct from the node-slot pages the resurrection probe reads. A small dedicated store (not the
    // 450-node `seed`) keeps each per-drain re-scan cheap while still spanning several property pages.
    let make_store = || {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store: MemStore = RecordStore::create(device, wal, 64, 1).expect("create store");
        let mut coord: MemCoord = TxnCoordinator::new(store);
        run(
            &mut coord,
            "UNWIND range(1, 120) AS i \
             CREATE (:Article {slug: 'slug-' + toString(i), title: 'title text ' + toString(i)})",
        );
        coord.into_store()
    };

    // How many pages does the device span? (Sweep every one as permanently dead.)
    let page_span = {
        let mut store = make_store();
        let (device, _wal) = restart_on_faulty_device(&mut store);
        device.page_count()
    };
    assert!(
        page_span > 4,
        "the store must span several pages (got {page_span})"
    );

    // Drives per page — enough that the M1 +1/drain cycle would be unmistakable (≈ DRAINS per page),
    // while the bounded fix stays in the single digits.
    const DRAINS: usize = 24;
    // The bound the fix must respect: a build re-poisons at most once per escalating backoff window
    // (1, 2, 4, 8, … drains), so over DRAINS drives it climbs at most ~log2(DRAINS) times. `10` is a
    // generous ceiling that the M1 cycle (= DRAINS = 24) blows past on the property page.
    const MAX_POISONS: u64 = 10;

    let mut saw_a_poisoning_page = false;
    for dead in 1..page_span {
        let mut store = make_store();
        let (device, wal) = restart_on_faulty_device(&mut store);
        let fault = device.handle();
        let faulty: FaultyStore =
            RecordStore::open(device, wal, FAULTED_POOL_PAGES).expect("open store");
        let mut coord: FaultyCoord = TxnCoordinator::new(faulty);

        // Declare an INCREMENTAL node-property build (deferred per-node indexing — the queue the
        // resurrection feeds), THEN kill a page for good. If the page is a node-slot page the declare's
        // own `scan_node_ids` snapshot already failed (no build enqueued); if it is a property page the
        // build enqueues and will fault on it during indexing.
        fault.kill_page(dead as usize);
        if coord
            .begin_online_node_property_index("Article", "slug")
            .is_err()
        {
            continue; // a node-slot / metadata page: nothing to index, not the scenario under test.
        }

        let mut last = 0;
        for _ in 0..DRAINS {
            last = drain(&mut coord);
        }
        fault.heal();

        assert!(
            last <= MAX_POISONS,
            "dead page {dead}: poison events climbed to {last} over {DRAINS} drains — an unbounded \
             poison<->resurrect cycle (the M1 defect); the escalating backoff must cap it"
        );
        if last > 0 {
            saw_a_poisoning_page = true;
        }

        // After healing, the build must be recoverable: a resurrection now completes it (self-heal).
        let mut iters = 0;
        while coord.has_pending_index_builds() || coord.poisoned_index_builds() > 0 {
            coord.retry_poisoned_index_builds();
            while coord.has_pending_index_builds() {
                coord.advance_index_builds(usize::MAX);
            }
            iters += 1;
            assert!(iters < 100, "the healed build must finish");
        }
    }

    // The sweep must actually have exercised the cycle on at least one page, or it proves nothing.
    assert!(
        saw_a_poisoning_page,
        "no page reproduced a property-page poisoning — the test would be vacuous"
    );
}

// =================================================================================================
// B1 — a NODE uniqueness / node-key duplicate check must FAIL CLOSED on a read fault
// =================================================================================================
//
// `filter_label_candidates` — the per-candidate re-check shared by every node index seek AND by the
// write-path uniqueness / node-key duplicate checks — swallowed a node read fault (`Err(_) => continue`).
// If the unreadable record is the EXISTING HOLDER of a unique value, the holder vanishes from the
// candidates, the duplicate check reports "no conflict", and a DUPLICATE is committed: silent
// committed-data corruption from an I/O error (`rmp` task #733). The `#733` round already closed the
// REL-KEY twin (`rel_key_tuple_conflict`) but LEFT this node seam open — the asymmetry the auditor found.
// This covers both the inline (`record_graph`) and off-thread (`read_source`) copies, both the index-seek
// (`Online`) and scan-fallback (`degraded`) arms, and both constraint kinds (IS UNIQUE + NODE KEY).

/// The shared sweep: over a `CREATE` that would make a duplicate, inject a **one-shot** read fault at
/// every read the statement makes; whichever read faults, a second holder of the key must NEVER be
/// committed. A one-shot (not a permanently-dead page) is essential for the composite / scan-fallback
/// arms: those call `mark_all_live_nodes` (a full `scan_node_ids`) *before* `filter_label_candidates`, so
/// a dead page would fault the scan first and fail closed there — masking whether the *per-candidate*
/// re-check is safe. A one-shot fault can instead let the scan succeed and land specifically on the
/// holder's `store.node` read inside `filter_label_candidates`, which (with the holder seeded first, so
/// its low-id page is evicted from the small pool) is a genuine device read. The fail-OPEN was reachable
/// precisely when everything else succeeded and only the holder's record read faulted.
fn sweep_duplicate_never_commits(
    open: impl Fn() -> (FaultyCoord, FaultHandle),
    dup: &str,
    holders: &str,
) {
    // Sanity on a healthy engine + the injection-point count.
    let reads = {
        let (mut coord, fault) = open();
        fault.reset_read_count();
        let err = run_expect_error(&mut coord, dup);
        assert!(
            err.to_lowercase().contains("constraint"),
            "the healthy engine must reject the duplicate, got: {err}"
        );
        assert_eq!(run(&mut coord, holders).len(), 1, "still one holder");
        fault.reads()
    };
    assert!(reads > 0, "the write must reach the device");

    for k in 0..reads {
        let (mut coord, fault) = open();
        fault.fail_once_at_read(k);
        let plan = compile(&coord, dup);
        let txn = coord.begin_serializable();
        let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
        {
            let mut graph = coord.statement(txn).expect("statement");
            let outcome = execute(&plan, &bound, &mut graph).and_then(|mut c| c.collect_all());
            let failed = outcome.is_err() || graph.has_error();
            drop(graph);
            if failed {
                let _ = coord.rollback(txn);
            } else {
                // The statement believed it succeeded — only legitimate if no duplicate was made.
                coord.commit(txn).expect("commit");
            }
        }
        fault.heal();
        assert_eq!(
            run(&mut coord, holders).len(),
            1,
            "a DUPLICATE was committed through a read fault at read #{k}: the node uniqueness / \
             node-key check swallowed the holder's record fault and reported 'no conflict'"
        );
    }
}

/// Seeds enough `:Article` nodes that the store spans far more pages than the faulted pool (so the
/// holder's record is cold and a swept fault can land on it), with a distinct holder for the duplicate.
fn seeded_articles(constraint: &str) -> MemStore {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: MemStore = RecordStore::create(device, wal, 64, 1).expect("create store");
    let mut coord: MemCoord = TxnCoordinator::new(store);
    // The holder is created FIRST (a low id), then buried under a bulk of later nodes. After the
    // open-time rebuild reads the whole store in id order, the pool retains only the LAST few (high-id)
    // pages, so the holder's low-id record is COLD — its `store.node` read reaches the device, where a
    // swept fault can land on it. (Creating the holder last would leave it cached, and the test vacuous.)
    run(
        &mut coord,
        "CREATE (:Article {slug: 'holder', tenant: 'acme'})",
    );
    run(
        &mut coord,
        "UNWIND range(1, 700) AS i \
         CREATE (:Article {slug: 'slug-' + toString(i), tenant: 'acme'})",
    );
    match constraint {
        "unique" => coord
            .create_constraint_ddl(
                "article_slug_unique",
                "Article",
                &["slug"],
                ConstraintKind::Unique,
                None,
                false,
                false,
            )
            .map(|_| ()),
        "nodekey" => coord
            .create_constraint_ddl(
                "article_slug_tenant_key",
                "Article",
                &["slug", "tenant"],
                ConstraintKind::NodeKey,
                None,
                false,
                false,
            )
            .map(|_| ()),
        other => panic!("unknown constraint {other}"),
    }
    .expect("the constraint holds over the seeded data");
    coord.into_store()
}

/// **B1, IS UNIQUE, Online arm** (`index_seek_eq` → `filter_label_candidates`).
#[test]
fn a_node_unique_check_fails_closed_on_a_read_fault() {
    let open = || {
        let mut store = seeded_articles("unique");
        let (device, wal) = restart_on_faulty_device(&mut store);
        let fault = device.handle();
        let faulty: FaultyStore =
            RecordStore::open(device, wal, FAULTED_POOL_PAGES).expect("open store");
        let coord: FaultyCoord = TxnCoordinator::new(faulty);
        (coord, fault)
    };
    sweep_duplicate_never_commits(
        open,
        "CREATE (:Article {slug: 'holder', tenant: 'acme'})",
        "MATCH (a:Article {slug: 'holder'}) RETURN id(a) AS id",
    );
}

/// **B1, NODE KEY, composite arm** (`node_key_tuple_conflict` → `composite_seek_eq` →
/// `filter_label_candidates`).
#[test]
fn a_node_key_check_fails_closed_on_a_read_fault() {
    let open = || {
        let mut store = seeded_articles("nodekey");
        let (device, wal) = restart_on_faulty_device(&mut store);
        let fault = device.handle();
        let faulty: FaultyStore =
            RecordStore::open(device, wal, FAULTED_POOL_PAGES).expect("open store");
        let coord: FaultyCoord = TxnCoordinator::new(faulty);
        (coord, fault)
    };
    sweep_duplicate_never_commits(
        open,
        "CREATE (:Article {slug: 'holder', tenant: 'acme'})",
        "MATCH (a:Article {slug: 'holder', tenant: 'acme'}) RETURN id(a) AS id",
    );
}

/// **B1, off-thread `read_source` twin.** `ReadOnlyGraph::filter_label_candidates` (the off-thread
/// re-check) must fail closed on a candidate record fault, exactly like the inline copy — otherwise an
/// off-thread read silently drops a row. Driven directly (not via `scan_nodes_by_label`, which faults at
/// `scan_node_ids` first): the candidate's record read must hit the device, so the store is large enough
/// (≈ 700 nodes) that most node-record pages are evicted from the small pool, and the device's reads are
/// then armed to fail — the first cold candidate read faults.
#[test]
fn the_off_thread_label_filter_fails_closed_on_a_read_fault() {
    use graphus_cypher::read_only_graph::ReadOnlyGraph;
    use graphus_storage::Namespace;
    use graphus_txn::SsiReadBuffer;

    // Enough nodes that the node store spans many more pages than the pool, so `filter_label_candidates`
    // must hit the DEVICE for the cold ids (a small store fits entirely in the pool and never faults).
    let seeded = || {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store: MemStore = RecordStore::create(device, wal, 64, 1).expect("create store");
        let mut coord: MemCoord = TxnCoordinator::new(store);
        run(
            &mut coord,
            "UNWIND range(1, 700) AS i CREATE (:Article {slug: 'slug-' + toString(i)})",
        );
        coord.into_store()
    };

    // The true labelled id set, from a HEALTHY coordinator.
    let all_ids: Vec<u64> = {
        let s = seeded();
        run(
            &mut TxnCoordinator::new(s),
            "MATCH (a:Article) RETURN id(a) AS id ORDER BY id",
        )
        .iter()
        .map(|r| match r.value("id") {
            Value::Integer(i) => i as u64,
            other => panic!("id: {other:?}"),
        })
        .collect()
    };
    let truth = all_ids.len();
    assert!(truth > 600);

    let mut store = seeded();
    let (device, wal) = restart_on_faulty_device(&mut store);
    let fault = device.handle();
    // A tiny pool: after the open-time rebuild only a handful of node pages remain cached, so the low ids
    // (read first below) are cold and their record reads reach the device.
    let faulty: FaultyStore = RecordStore::open(device, wal, 2).expect("open store");
    let mut coord: FaultyCoord = TxnCoordinator::new(faulty);

    let txn = coord.begin_serializable();
    let inputs = coord.read_task_inputs(txn).expect("read inputs");
    let label_token = inputs
        .tokens
        .token_id(Namespace::Label, "Article")
        .expect("Article label token");
    let ro: ReadOnlyGraph<FaultyDevice, MemLogSink> = ReadOnlyGraph::new(
        inputs.view,
        inputs.tokens,
        inputs.snapshot,
        inputs.registry,
        txn,
        SsiReadBuffer::new(txn),
    );

    // Sanity: healthy, the off-thread filter returns the whole true set.
    let healthy = ro.filter_label_candidates(label_token, all_ids.clone());
    assert_eq!(
        healthy.len(),
        truth,
        "healthy off-thread filter must return every node"
    );
    assert!(!ro.has_error());

    // Now every DEVICE read faults (pool hits still serve, but the cold ids must miss). A fresh reader
    // (fresh SIREAD buffer) so `has_error` starts clean.
    let txn2 = coord.begin_serializable();
    let inputs2 = coord.read_task_inputs(txn2).expect("read inputs");
    let ro2: ReadOnlyGraph<FaultyDevice, MemLogSink> = ReadOnlyGraph::new(
        inputs2.view,
        inputs2.tokens,
        inputs2.snapshot,
        inputs2.registry,
        txn2,
        SsiReadBuffer::new(txn2),
    );
    fault.arm();
    let got = ro2.filter_label_candidates(label_token, all_ids.clone());
    fault.heal();

    // The fix CAPTURES the fault and returns empty; the pre-fix `Err(_) => continue` silently dropped
    // every faulting candidate and returned a (smaller) set with `has_error() == false` — the silent
    // missing-row defect. The distinguishing assertion is `has_error()`.
    assert!(
        got.len() < truth,
        "with the device armed, cold candidate reads must have faulted (got {}/{}); increase the \
         node count or shrink the pool if this store fit entirely in the pool",
        got.len(),
        truth
    );
    assert!(
        ro2.has_error(),
        "read_source::filter_label_candidates must CAPTURE a candidate read fault, not silently \
         drop the row (returned {}/{} rows with has_error=false)",
        got.len(),
        truth
    );
}

// =================================================================================================
// B1 (columnar) — the analytical aggregation accelerator must FAIL CLOSED on a read fault
// =================================================================================================

/// `columnar_label_property_scan` / `columnar_label_pass` (the `rmp` #329/#330 vectorized aggregation
/// path) re-reads each candidate node's record for the visibility + label + freshness witness. That
/// per-candidate `store.node(id)` read used to swallow a fault (`Err(_) => continue`), silently dropping
/// the node from the aggregation and returning a WRONG `sum(...)` / `count(...)` from an I/O error
/// (`rmp` task #733). It must fail closed (capture → abort) exactly like `filter_label_candidates`.
///
/// Non-vacuous by construction: with the arm reverted to `Err(_) => continue`, a swept fault drops a
/// node and the aggregation returns a wrong sum with **no** error captured — the assertion below fires.
#[test]
fn a_columnar_aggregation_fails_closed_on_a_read_fault() {
    const N: i64 = 700;
    const AGG: &str = "MATCH (n:Article) RETURN sum(n.age) AS s";
    let true_sum: i64 = (1..=N).sum();

    // Many `:Article {age}` nodes so the records span many more pages than the faulted pool (cold reads
    // reach the device).
    let seeded = || {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store: MemStore = RecordStore::create(device, wal, 64, 1).expect("create store");
        let mut coord: MemCoord = TxnCoordinator::new(store);
        run(
            &mut coord,
            &format!("UNWIND range(1, {N}) AS i CREATE (:Article {{age: i}})"),
        );
        coord.into_store()
    };

    let open = || {
        let mut store = seeded();
        let (device, wal) = restart_on_faulty_device(&mut store);
        let fault = device.handle();
        let faulty: FaultyStore =
            RecordStore::open(device, wal, FAULTED_POOL_PAGES).expect("open store");
        let mut coord: FaultyCoord = TxnCoordinator::new(faulty);
        // The columnar cache is in-memory only (`rmp` #329, never recovered), so it MUST be declared on
        // THIS reopened coordinator — declaring it before the restart would be gone after reopen and the
        // aggregation would silently use the Volcano path, making the test vacuous. Declared here while
        // the device is healthy; the capture read warms then evicts the pool, leaving cold node pages for
        // the aggregation's per-candidate re-read to fault on.
        coord
            .declare_columnar_cache("Article", "age")
            .expect("declare columnar cache");
        (coord, fault)
    };

    // Sanity on a healthy engine + the injection-point count.
    let reads = {
        let (mut coord, fault) = open();
        fault.reset_read_count();
        let rows = run(&mut coord, AGG);
        let s = match rows[0].value("s") {
            Value::Integer(i) => i,
            other => panic!("expected an integer sum, got {other:?}"),
        };
        assert_eq!(s, true_sum, "healthy columnar aggregation must be exact");
        fault.reads()
    };
    assert!(reads > 0, "the aggregation must reach the device");

    let mut saw_a_fault = false;
    for k in 0..reads {
        let (mut coord, fault) = open();
        fault.fail_once_at_read(k);
        let plan = compile(&coord, AGG);
        let txn = coord.begin_serializable();
        let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
        let (sum, faulted) = {
            let mut graph = coord.statement(txn).expect("statement");
            let outcome = execute(&plan, &bound, &mut graph).and_then(|mut c| c.collect_all());
            // A fault is "captured" iff the cursor errored OR the seam set the statement error flag.
            let faulted = outcome.is_err() || graph.has_error();
            let sum = outcome.ok().and_then(|rows| {
                rows.first().map(|r| match r.value("s") {
                    Value::Integer(i) => i,
                    Value::Null => 0, // an aborted/empty fold yields null — treated as "no value"
                    other => panic!("expected an integer/null sum, got {other:?}"),
                })
            });
            drop(graph);
            let _ = coord.rollback(txn);
            (sum, faulted)
        };
        fault.heal();

        // The invariant: a read fault must be CAPTURED, never silently drop a node and report a WRONG
        // sum with no error. (When it faults, `sum` is irrelevant — the txn aborted.)
        if let Some(s) = sum
            && s != true_sum
        {
            assert!(
                faulted,
                "the columnar aggregation returned a WRONG sum {s} (true {true_sum}) with NO error \
                 captured at read #{k}: a node was silently dropped from the aggregation"
            );
        }
        if faulted {
            saw_a_fault = true;
        }
    }
    assert!(
        saw_a_fault,
        "no read fault reached the columnar aggregation path — the test would be vacuous"
    );
}

// =================================================================================================
// V1 — a RELATIONSHIP uniqueness check must FAIL CLOSED on a candidate read fault (index path)
// =================================================================================================

/// A `REL IS UNIQUE` constraint over an **`Online`** relationship-property index enforces uniqueness by
/// `rel_unique_conflict` → `rel_index_seek_eq`, whose per-candidate re-check reads the holder's record
/// and property (`rel_data` + `rel_property` → `read_rel_prop_one`). If that property read swallows a
/// fault, the existing holder vanishes from the candidates, the check reports "no conflict", and a
/// DUPLICATE is committed — the relationship twin of the node `filter_label_candidates` hole
/// (`rmp` task #733). Every read on this path captures; this pins that.
///
/// Non-vacuous by construction: reverting `read_rel_prop_one`'s `rel_properties` `Err` arm to
/// `return None` (no capture) makes a swept fault on the holder's property read drop the holder and
/// commit the duplicate — the assertion below fires.
#[test]
fn a_rel_unique_check_fails_closed_on_a_read_fault() {
    const N: usize = 700;
    const DUP: &str = "MATCH (a:Article {slug: 'a'}), (b:Article {slug: 'b'}) \
                       CREATE (a)-[:CITES {ref: 'holder'}]->(b)";
    const HOLDERS: &str = "MATCH ()-[r:CITES {ref: 'holder'}]->() RETURN id(r) AS id";

    let seeded = || {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store: MemStore = RecordStore::create(device, wal, 64, 1).expect("create store");
        let mut coord: MemCoord = TxnCoordinator::new(store);
        run(
            &mut coord,
            "CREATE (:Article {slug: 'a'}), (:Article {slug: 'b'})",
        );
        // The HOLDER relationship is created FIRST (a low rel id), then buried under many more, so its
        // record is COLD after reopen and its per-candidate re-read is a genuine device read.
        run(
            &mut coord,
            "MATCH (a:Article {slug: 'a'}), (b:Article {slug: 'b'}) \
             CREATE (a)-[:CITES {ref: 'holder'}]->(b)",
        );
        run(
            &mut coord,
            &format!(
                "UNWIND range(1, {N}) AS i \
                 MATCH (a:Article {{slug: 'a'}}), (b:Article {{slug: 'b'}}) \
                 CREATE (a)-[:CITES {{ref: 'ref-' + toString(i)}}]->(b)"
            ),
        );
        // Single-property REL uniqueness → an ONLINE relationship-property index, so the check goes
        // through `rel_index_seek_eq` (not the scan fallback). The scan fallback path is already covered
        // by `a_rel_key_duplicate_check_fails_closed_on_a_read_fault`.
        coord
            .create_constraint_ddl(
                "cites_ref_unique",
                "CITES",
                &["ref"],
                ConstraintKind::RelUnique,
                None,
                false,
                false,
            )
            .expect("the REL uniqueness constraint holds over the seeded data");
        coord.into_store()
    };

    let open = || {
        let mut store = seeded();
        let (device, wal) = restart_on_faulty_device(&mut store);
        let fault = device.handle();
        let faulty: FaultyStore =
            RecordStore::open(device, wal, FAULTED_POOL_PAGES).expect("open store");
        let coord: FaultyCoord = TxnCoordinator::new(faulty);
        (coord, fault)
    };

    // Sanity + injection-point count.
    let reads = {
        let (mut coord, fault) = open();
        fault.reset_read_count();
        let err = run_expect_error(&mut coord, DUP);
        assert!(
            err.to_lowercase().contains("constraint"),
            "the healthy engine must reject the duplicate relationship, got: {err}"
        );
        assert_eq!(run(&mut coord, HOLDERS).len(), 1, "still one holder");
        fault.reads()
    };
    assert!(reads > 0, "the write must reach the device");

    for k in 0..reads {
        let (mut coord, fault) = open();
        fault.fail_once_at_read(k);
        let plan = compile(&coord, DUP);
        let txn = coord.begin_serializable();
        let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
        {
            let mut graph = coord.statement(txn).expect("statement");
            let outcome = execute(&plan, &bound, &mut graph).and_then(|mut c| c.collect_all());
            let failed = outcome.is_err() || graph.has_error();
            drop(graph);
            if failed {
                let _ = coord.rollback(txn);
            } else {
                coord.commit(txn).expect("commit");
            }
        }
        fault.heal();
        assert_eq!(
            run(&mut coord, HOLDERS).len(),
            1,
            "a DUPLICATE relationship was committed through a read fault at read #{k}: the REL \
             uniqueness check swallowed the holder's record/property fault and reported 'no conflict'"
        );
    }
}
