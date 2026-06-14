//! Running one TCK scenario end-to-end over the **real** Graphus engine, isolated against panics.
//!
//! # The scenario flow (`tck/README.adoc` §"Format of a TCK scenario")
//!
//! 1. Build a fresh persistent store wrapped in a
//!    [`TxnCoordinator`](graphus_cypher::TxnCoordinator) (the production seam).
//! 2. Apply the `Given` step: empty / any graph (nothing to do), or seed a named graph.
//! 3. Run every `having executed:` initialisation query (committed).
//! 4. Snapshot the graph state (for the side-effect diff).
//! 5. Run each `When` query **block** in order against the *same* coordinator (a shared session): a
//!    scenario is a sequence of `(query → Then expectation → [And side effects])` blocks, where a
//!    follow-up `When executing control query:` observes the committed effect of the preceding
//!    block(s). For each block: resolve its result cells into self-contained [`Concrete`] snapshots
//!    **while the statement seam is still live**, then commit (or roll back on a runtime error).
//! 6. Compare each block against its `Then` step: a result-set assertion, or an error assertion.
//! 7. Snapshot before and after *each block* and diff to compute that block's own observed side
//!    effects; compare to the block's side-effect step. The scenario passes only if every block
//!    passes; it fails at the first block that does not.
//!
//! Steps 5–7 are the subtle parts: entity references in a result row carry only an id, so the runner
//! resolves labels/properties/paths through the [`GraphAccess`] seam before the transaction ends; and
//! the engine keeps no side-effect counters, so the runner computes them as the README defines —
//! the difference between a before- and after-snapshot of the observable graph state.
//!
//! # Panic isolation
//!
//! A young engine will panic on some inputs. Every scenario runs inside
//! [`std::panic::catch_unwind`] over a fresh store, so a panic becomes an [`Outcome::Errored`] for
//! that one scenario and never aborts the run. The panic hook is silenced for the duration so the
//! corpus run is not drowned in backtraces.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{self, AssertUnwindSafe};
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::executor::execute_with_procedures;
use graphus_cypher::graph_access::{GraphAccess, NodeId, RelId};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalOp, plan_physical_with_stats};
use graphus_cypher::procedure_registry::{ProcedureRegistry, ProcedureSet};
use graphus_cypher::runtime::{PathValue, Row, RowValue};
use graphus_cypher::semantics::{
    ValidatedQuery, analyze_with_procedures, check_implicit_call_parameters,
};
use graphus_cypher::{ErrorPhase, ErrorType};
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

use crate::compare::{
    Concrete, ConcreteNode, ConcretePath, ConcretePathStep, assert_ordered, assert_unordered,
};
use crate::feature::{KvRows, ProcedureStep, ResultTable, Scenario, StepKind, parse_row};
use crate::graphs::named_graph_cypher;

/// The store type the harness runs over: a real [`RecordStore`] on an in-memory device + log (the
/// same construction the engine's own end-to-end tests use).
type Store = RecordStore<MemBlockDevice, MemLogSink>;
/// The coordinator type over that store.
type Coord = graphus_cypher::TxnCoordinator<MemBlockDevice, MemLogSink>;

/// The classification of one scenario after running it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The engine's behaviour matched the scenario's expectation.
    Passed,
    /// The engine ran but produced the wrong result, wrong error, or wrong side effects.
    Failed(String),
    /// The engine panicked (caught and isolated). Carries the panic message.
    Errored(String),
    /// A step form the harness does not implement; the scenario is neither pass nor fail. Carries
    /// the raw step text so the report can list exactly which forms appeared.
    Unsupported(String),
}

/// A fresh, empty record store (identical construction to the engine's `record_store_graph.rs`).
fn fresh_store() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 64, 1).expect("create store")
}

/// The worker-thread stack size for one scenario (`128 MiB`).
///
/// A handful of pathological corpus queries (deeply-nested expressions, long pattern chains) drive
/// the recursive-descent parser / planner / evaluator very deep. The default 2 MiB test stack
/// overflows on them — and a stack overflow is a fatal `SIGABRT`, **not** a catchable panic, so it
/// would abort the whole corpus run. Running each scenario on a thread with a large stack absorbs the
/// deep-but-finite recursion; a genuinely unbounded recursion would still overflow even this, which
/// correctly surfaces a real engine bug rather than masking it.
const SCENARIO_STACK_BYTES: usize = 128 * 1024 * 1024;

/// The per-scenario wall-clock budget. A scenario that does not finish within this is recorded as an
/// [`Outcome::Errored`] (a runaway loop) and the corpus run continues; the worker thread is
/// abandoned (detached) rather than joined.
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(20);

/// Runs a single scenario on a dedicated large-stack worker thread, isolating any panic into
/// [`Outcome::Errored`] and bounding the wall-clock time.
///
/// `graphs_root` is `tck/graphs` (used only by scenarios with a `Given the <name> graph` step).
#[must_use]
pub fn run_scenario(scenario: &Scenario, graphs_root: &Path) -> Outcome {
    let scenario = scenario.clone();
    let graphs_root = graphs_root.to_path_buf();
    let (tx, rx) = mpsc::channel::<Outcome>();

    let builder = std::thread::Builder::new()
        .name("tck-scenario".to_owned())
        .stack_size(SCENARIO_STACK_BYTES);
    let handle = builder.spawn(move || {
        // Silence the panic hook for the duration so a corpus run is not flooded with backtraces; a
        // caught panic is reported via the message `catch_unwind` returns.
        let prev_hook = panic::take_hook();
        panic::set_hook(Box::new(|_| {}));
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            run_scenario_inner(&scenario, &graphs_root)
        }));
        panic::set_hook(prev_hook);
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(payload) => Outcome::Errored(panic_message(payload.as_ref())),
        };
        // The receiver may have already timed out and gone away; ignore the send error then.
        let _ = tx.send(outcome);
    });

    let Ok(handle) = handle else {
        return Outcome::Errored("failed to spawn scenario worker thread".to_owned());
    };

    match rx.recv_timeout(SCENARIO_TIMEOUT) {
        Ok(outcome) => {
            // Join the finished worker so its resources are reclaimed promptly.
            let _ = handle.join();
            outcome
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // The worker is still running (a runaway loop). Detach it (we cannot safely kill a
            // thread) and report a timeout. The detached thread holds only its own fresh store.
            Outcome::Errored(format!(
                "scenario exceeded the {}s time budget (likely a runaway loop)",
                SCENARIO_TIMEOUT.as_secs()
            ))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let _ = handle.join();
            Outcome::Errored("scenario worker disconnected without a result".to_owned())
        }
    }
}

/// Extracts a human message from a `catch_unwind` payload.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

/// The scenario body, run inside the panic guard.
fn run_scenario_inner(scenario: &Scenario, graphs_root: &Path) -> Outcome {
    let mut plan = ScenarioPlan::default();
    if let Err(form) = plan.collect(scenario) {
        return Outcome::Unsupported(form);
    }
    if plan.blocks.is_empty() {
        return Outcome::Unsupported("scenario has no `When executing query:` step".to_owned());
    }

    // ---- fixture procedures: the registry that backs compile AND execute for this scenario -----
    let mut registry = ProcedureSet::with_builtins();
    for step in &plan.procedures {
        if let Err(e) = crate::procedures::register(&mut registry, step) {
            return Outcome::Failed(format!("fixture procedure registration failed: {e}"));
        }
    }

    let mut coord = Coord::new(fresh_store());

    // ---- Given: seed a named graph, if any -----------------------------------------------------
    if let Some(name) = &plan.named_graph {
        let seed = match named_graph_cypher(graphs_root, name) {
            Ok(seed) => seed,
            Err(e) => return Outcome::Unsupported(format!("named graph load: {e}")),
        };
        if let Err(e) = run_write_query(&mut coord, &seed, &Parameters::new(), &registry) {
            return Outcome::Failed(format!("named-graph seed `{name}` failed: {e}"));
        }
    }

    // ---- having executed: initialisation queries -----------------------------------------------
    for init in &plan.init_queries {
        if let Err(e) = run_write_query(&mut coord, init, &Parameters::new(), &registry) {
            return Outcome::Failed(format!("init query failed: {init:?}: {e}"));
        }
    }

    // ---- parameters for the query under test ---------------------------------------------------
    // The TCK parameter table applies to every query block of the scenario; build it once.
    let params = match build_parameters(&plan.parameters) {
        Ok(p) => p,
        Err(e) => return Outcome::Failed(format!("parameter table: {e}")),
    };

    // ---- run each query block in order against the shared coordinator ---------------------------
    // A scenario is a sequence of `(query → Then → [And side effects])` blocks sharing one graph; a
    // follow-up `When executing control query:` sees the committed effect of the prior block(s). The
    // scenario passes only if every block passes, and fails at the first block that does not. Each
    // block's side effects are measured as the delta around *that block alone* (its own before/after
    // snapshot), so a CREATE block reports `+nodes 1` independently of a later read block reporting
    // none.
    let multi = plan.blocks.len() > 1;
    for (idx, block) in plan.blocks.iter().enumerate() {
        let outcome = run_query_block(&mut coord, block, &params, &registry);
        if !matches!(outcome, Outcome::Passed) {
            // For a multi-block scenario, prefix the failure with which block failed so the report
            // pinpoints it; a single-block scenario keeps the exact pre-sequence message verbatim.
            return if multi {
                annotate_block_failure(outcome, idx + 1, plan.blocks.len(), &block.query)
            } else {
                outcome
            };
        }
    }
    Outcome::Passed
}

/// Runs one [`QueryBlock`] against the shared coordinator and decides it against its `Then` step.
///
/// Snapshots the graph immediately before and after the block so the reported side effects are the
/// delta of this block's query alone (never accumulated across blocks).
fn run_query_block(
    coord: &mut Coord,
    block: &QueryBlock,
    params: &Parameters,
    registry: &dyn ProcedureRegistry,
) -> Outcome {
    // Snapshot before this block (for its own side-effect diff).
    let before = match snapshot(coord) {
        Ok(s) => s,
        Err(e) => return Outcome::Errored(format!("pre-snapshot failed: {e}")),
    };

    let run = run_query_resolving(coord, &block.query, params, registry);

    match &block.expectation {
        Expectation::Error {
            error_type,
            phase,
            detail,
        } => check_error_expectation(&run, error_type, phase, detail),
        Expectation::Rows { ordered, table } => {
            let outcome = check_rows_expectation(&run, *ordered, table);
            if !matches!(outcome, Outcome::Passed) {
                return outcome;
            }
            // Side effects only matter when the query succeeded and produced rows.
            check_side_effects(coord, &before, &block.side_effects)
        }
        Expectation::Empty => {
            let outcome = check_empty_expectation(&run);
            if !matches!(outcome, Outcome::Passed) {
                return outcome;
            }
            check_side_effects(coord, &before, &block.side_effects)
        }
        Expectation::None => {
            Outcome::Unsupported("scenario has no `Then` result/error assertion".to_owned())
        }
    }
}

/// Prefixes a failing block's outcome with which block (1-based) in the sequence failed, preserving
/// the failure kind (`Failed` / `Errored` / `Unsupported`).
fn annotate_block_failure(outcome: Outcome, block_no: usize, total: usize, query: &str) -> Outcome {
    let head = query.lines().next().unwrap_or("").trim();
    let prefix = format!("block {block_no}/{total} (`{head}`): ");
    match outcome {
        Outcome::Failed(m) => Outcome::Failed(format!("{prefix}{m}")),
        Outcome::Errored(m) => Outcome::Errored(format!("{prefix}{m}")),
        Outcome::Unsupported(m) => Outcome::Unsupported(format!("{prefix}{m}")),
        Outcome::Passed => Outcome::Passed,
    }
}

// =================================================================================================
// Collecting a scenario's steps into a plan
// =================================================================================================

/// The expected outcome a `Then` step asserts.
#[derive(Debug, Clone, Default)]
enum Expectation {
    /// `Then a TYPE should be raised at PHASE: DETAIL`.
    Error {
        error_type: String,
        phase: String,
        detail: String,
    },
    /// `Then the result should be[, in (any )?order]:` — a result table.
    Rows { ordered: bool, table: ResultTable },
    /// `Then the result should be empty`.
    Empty,
    /// No recognised `Then` assertion.
    #[default]
    None,
}

/// The side-effect expectation: an explicit table, "no side effects", or unspecified.
#[derive(Debug, Clone, Default)]
enum SideEffectSpec {
    /// `And the side effects should be:` with the counter table.
    Table(KvRows),
    /// `And no side effects` — every counter is zero.
    None,
    /// No side-effect step at all — unspecified counters imply zero (`tck/README.adoc`), so this is
    /// treated identically to [`Self::None`] but kept distinct for clarity.
    #[default]
    Unspecified,
}

/// One `(query → Then expectation → [And side effects])` block of a scenario.
///
/// A TCK scenario is an ordered sequence of these blocks executed against the *same* shared graph
/// (`tck/README.adoc` §"Format of a TCK scenario": a `When executing control query:` observes the
/// committed effect of the preceding `When executing query:`). Each block carries its own query, its
/// own `Then` assertion, and its own side-effect expectation; the side effects are the delta of *that
/// block's* query alone (a before/after snapshot taken around the block), never accumulated.
#[derive(Debug, Clone, Default)]
struct QueryBlock {
    query: String,
    expectation: Expectation,
    side_effects: SideEffectSpec,
}

/// A scenario flattened into the pieces the runner needs.
#[derive(Debug, Clone, Default)]
struct ScenarioPlan {
    named_graph: Option<String>,
    init_queries: Vec<String>,
    parameters: KvRows,
    procedures: Vec<ProcedureStep>,
    /// The ordered query blocks (length ≥ 1 for a runnable scenario). A single-query scenario yields
    /// a sequence of length 1 — behaviourally identical to the pre-sequence runner.
    blocks: Vec<QueryBlock>,
}

impl ScenarioPlan {
    /// Folds a scenario's classified steps into the plan, returning `Err(form)` if a step is an
    /// unsupported form the runner cannot proceed past.
    ///
    /// `When executing query:` (and `When executing control query:`, both classified as
    /// [`StepKind::Query`]) opens a new [`QueryBlock`]; the following `Then`/`And` result, error and
    /// side-effect steps bind to the block currently open. Setup steps (`Given` / `having executed:` /
    /// `parameters` / `procedure`) apply to the scenario as a whole and may appear only before the
    /// first query block.
    fn collect(&mut self, scenario: &Scenario) -> Result<(), String> {
        for step in &scenario.steps {
            match &step.kind {
                StepKind::EmptyGraph | StepKind::AnyGraph => {}
                StepKind::NamedGraph(name) => self.named_graph = Some(name.clone()),
                StepKind::InitQuery(q) => self.init_queries.push(q.clone()),
                StepKind::Parameters(rows) => self.parameters = rows.clone(),
                StepKind::Procedure(step) => self.procedures.push(step.clone()),
                // A new query (the `When` query, or a follow-up `When executing control query:`)
                // opens a fresh block; subsequent Then/And steps bind to it.
                StepKind::Query(q) => self.blocks.push(QueryBlock {
                    query: q.clone(),
                    ..QueryBlock::default()
                }),
                StepKind::ResultUnordered(t) => {
                    self.current_block()?.expectation = Expectation::Rows {
                        ordered: false,
                        table: t.clone(),
                    };
                }
                StepKind::ResultOrdered(t) => {
                    self.current_block()?.expectation = Expectation::Rows {
                        ordered: true,
                        table: t.clone(),
                    };
                }
                StepKind::ResultEmpty => self.current_block()?.expectation = Expectation::Empty,
                StepKind::Error {
                    error_type,
                    phase,
                    detail,
                } => {
                    self.current_block()?.expectation = Expectation::Error {
                        error_type: error_type.clone(),
                        phase: phase.clone(),
                        detail: detail.clone(),
                    };
                }
                StepKind::SideEffects(rows) => {
                    self.current_block()?.side_effects = SideEffectSpec::Table(rows.clone());
                }
                StepKind::NoSideEffects => {
                    self.current_block()?.side_effects = SideEffectSpec::None;
                }
                // An unsupported step form gates the whole scenario.
                StepKind::Unsupported(raw) => return Err(raw.clone()),
            }
        }
        Ok(())
    }

    /// The block currently being built (the last one opened by a `When` query). A `Then`/`And` step
    /// with no preceding query is a malformed scenario the runner cannot interpret.
    fn current_block(&mut self) -> Result<&mut QueryBlock, String> {
        self.blocks.last_mut().ok_or_else(|| {
            "a `Then`/`And` assertion appears before any `When executing query:` step".to_owned()
        })
    }
}

/// Builds engine [`Parameters`] from the TCK parameter table (each value is a mini-language cell).
///
/// # Errors
///
/// Returns a description if any cell is not a well-formed property value (a structural parameter is
/// not representable, so it is reported as an error — the engine cannot bind it anyway).
fn build_parameters(rows: &KvRows) -> Result<Parameters, String> {
    let mut params = Parameters::new();
    for (name, raw) in rows {
        let expected = crate::value::parse_expected(raw)
            .map_err(|e| format!("parameter `{name}` value {raw:?}: {e}"))?;
        let value = crate::value::to_property_value(&expected).ok_or_else(|| {
            format!("parameter `{name}` is a structural value, unsupported: {raw}")
        })?;
        params.insert(name.clone(), value);
    }
    Ok(params)
}

// =================================================================================================
// Running queries
// =================================================================================================

/// The classified outcome of running the When query: either resolved rows + columns, or an error
/// with its TCK classification.
enum QueryRun {
    /// The query produced rows (resolved into self-contained snapshots) under these columns.
    Rows {
        columns: Vec<String>,
        rows: Vec<Vec<Concrete>>,
    },
    /// The query raised an error classified into the TCK `(type, phase)` (detail best-effort).
    Error(TckError),
}

/// A TCK-classified engine error.
struct TckError {
    /// The TCK error type name (`SyntaxError`, `TypeError`, …).
    error_type: String,
    /// The TCK phase (`compile time` / `runtime`).
    phase: String,
    /// The fine-grained detail, when the engine produces a matching one (else `None`).
    detail: Option<String>,
    /// The full engine error message (for diagnostics).
    message: String,
}

/// Compiles `src` to a validated query against `registry`, mapping any compile-time failure to a
/// [`TckError`].
///
/// `params` is consulted for one compile-time check only: a standalone **implicit** procedure
/// call's arguments are the query parameters, and the TCK raises a missing one at compile time
/// (`ParameterMissing`/`MissingParameter` — [`check_implicit_call_parameters`]). The plan itself
/// stays parameter-independent.
fn compile(
    src: &str,
    params: &Parameters,
    registry: &dyn ProcedureRegistry,
) -> Result<ValidatedQuery, TckError> {
    let tokens = tokenize(src).map_err(|e| TckError {
        // A lexer error is a compile-time SyntaxError (`04 §7.3`).
        error_type: ErrorType::SyntaxError.as_tck_str().to_owned(),
        phase: ErrorPhase::CompileTime.as_tck_str().to_owned(),
        detail: None,
        message: e.to_string(),
    })?;
    let ast = parse_tokens(&tokens, src).map_err(|e| TckError {
        // A parser error is likewise a compile-time SyntaxError.
        error_type: ErrorType::SyntaxError.as_tck_str().to_owned(),
        phase: ErrorPhase::CompileTime.as_tck_str().to_owned(),
        detail: None,
        message: e.to_string(),
    })?;
    // Semantic analysis (and the implicit-call parameter check) carry their own verbatim TCK
    // classifications.
    let classify = |e: &graphus_cypher::SemanticError| {
        let c = e.classification();
        TckError {
            error_type: c.error_type.as_tck_str().to_owned(),
            phase: c.phase.as_tck_str().to_owned(),
            detail: Some(c.detail.as_tck_str().to_owned()),
            message: e.to_string(),
        }
    };
    let validated = analyze_with_procedures(&ast, registry).map_err(|e| classify(&e))?;
    check_implicit_call_parameters(&ast, params, registry).map_err(|e| classify(&e))?;
    Ok(validated)
}

/// Runs `src` as a **write** statement (named-graph seed / init query) and commits it.
///
/// Returns the engine error message on any compile or runtime failure (rolling back).
fn run_write_query(
    coord: &mut Coord,
    src: &str,
    params: &Parameters,
    registry: &dyn ProcedureRegistry,
) -> Result<(), String> {
    let validated = compile(src, params, registry).map_err(|e| e.message)?;
    // Stats-aware planning (`rmp` task #82): the TCK exercises the production cost-based optimiser
    // path; its rewrites are bag-preserving, so plan shape may differ but results never do.
    let stats = coord.statistics();
    let plan = plan_physical_with_stats(&lower(&validated), &coord.catalog(), Some(&stats));
    let bound = bind_parameters(&plan, params).map_err(|e| e.to_string())?;

    let txn = coord.begin_serializable();
    let run_result: Result<(), String> = (|| {
        let mut graph = coord.statement(txn).map_err(|e| e.to_string())?;
        {
            let mut cursor = execute_with_procedures(&plan, &bound, &mut graph, registry)
                .map_err(|e| e.to_string())?;
            cursor.collect_all().map_err(|e| e.to_string())?;
        }
        if graph.has_error() {
            return Err(format!("captured store error: {:?}", graph.take_error()));
        }
        Ok(())
    })();

    match run_result {
        Ok(()) => coord.commit(txn).map(|_| ()).map_err(|e| e.to_string()),
        Err(e) => {
            let _ = coord.rollback(txn);
            Err(e)
        }
    }
}

/// Runs the When query and resolves its result cells into self-contained [`Concrete`] snapshots
/// while the statement seam is live, committing on success and rolling back on a runtime error.
fn run_query_resolving(
    coord: &mut Coord,
    src: &str,
    params: &Parameters,
    registry: &dyn ProcedureRegistry,
) -> QueryRun {
    let validated = match compile(src, params, registry) {
        Ok(v) => v,
        Err(e) => return QueryRun::Error(e),
    };
    // Stats-aware planning (`rmp` task #82): same production cost-based path as `run_write_query`.
    let stats = coord.statistics();
    let plan = plan_physical_with_stats(&lower(&validated), &coord.catalog(), Some(&stats));
    let bound = match bind_parameters(&plan, params) {
        Ok(b) => b,
        Err(e) => {
            // A missing/ill-typed parameter is a runtime error; the TCK type is `ParameterMissing`.
            return QueryRun::Error(classify_bind_error(&e));
        }
    };
    let write_only = is_write_only_root(&plan.root);

    let txn = coord.begin_serializable();
    let resolved: Result<QueryRun, TckError> = (|| {
        let mut graph = coord.statement(txn).map_err(|e| TckError {
            error_type: "EntityNotFound".to_owned(),
            phase: ErrorPhase::Runtime.as_tck_str().to_owned(),
            detail: None,
            message: e.to_string(),
        })?;

        let mut cursor = execute_with_procedures(&plan, &bound, &mut graph, registry)
            .map_err(classify_exec_error)?;
        let columns = cursor.columns().to_vec();
        let rows = cursor.collect_all().map_err(classify_exec_error)?;
        drop(cursor);

        // A deferred store error (e.g. a non-storable property) is captured on the seam rather than
        // returned; treat it as a runtime error.
        if graph.has_error() {
            let msg = format!("{:?}", graph.take_error());
            return Err(classify_store_error(&msg));
        }

        // A **write-only** query (its plan root is a bare write op, i.e. no final `RETURN`/`WITH`
        // projection) produces no client-facing result set, even though the executor threads one
        // internal driving row per write and exposes the *internal* bindings (e.g. the matched `x`,
        // `y` of `MATCH (x), (y) CREATE (x)-[:R]->(y)`) as plan columns. The TCK result set is the
        // projected data; for a write-only query that is empty (`Then the result should be empty`).
        //
        // Likewise a **zero-column** result (a standalone CALL of a *void* procedure — the only
        // plan shape with no result columns, since `RETURN` always projects at least one) carries
        // no client-facing data: the executor's unit row is internal, and the TCK asserts
        // `Then the result should be empty` (`tck/features/clauses/call/Call1.feature` [1]).
        if write_only || columns.is_empty() {
            return Ok(QueryRun::Rows {
                columns: Vec::new(),
                rows: Vec::new(),
            });
        }

        // Resolve every result cell into a self-contained snapshot while `graph` is still live.
        let resolved_rows: Vec<Vec<Concrete>> = rows
            .iter()
            .map(|row| resolve_row(row, &columns, &graph))
            .collect();
        Ok(QueryRun::Rows {
            columns,
            rows: resolved_rows,
        })
    })();

    match resolved {
        Ok(run) => {
            // A successful read/write commits (so side-effect snapshots see its effect).
            let _ = coord.commit(txn);
            run
        }
        Err(err) => {
            let _ = coord.rollback(txn);
            QueryRun::Error(err)
        }
    }
}

/// Whether a plan's root operator is a **bare write op** (a query with no final `RETURN`/`WITH`
/// projection), so it produces no client-facing result set.
///
/// In openCypher the result columns of a query are the columns of its final `RETURN`; a write-only
/// query (`CREATE …`, `MATCH … DELETE`, `MATCH … SET`, …) returns nothing. In the physical plan such
/// a query's root is one of the write operators; a returning query's root is a projection-family op
/// (`Projection`/`Aggregation`) or a result-shaping wrapper above it. We descend through the
/// result-shaping wrappers so a trailing `WITH … LIMIT` that still ends in a write (no `RETURN`) is
/// also recognised as write-only.
fn is_write_only_root(root: &PhysicalOp) -> bool {
    match root {
        PhysicalOp::Create { .. }
        | PhysicalOp::Merge { .. }
        | PhysicalOp::SetClause { .. }
        | PhysicalOp::Delete { .. }
        | PhysicalOp::Remove { .. } => true,
        // A returning query terminates in a projection-family op.
        PhysicalOp::Projection { .. }
        | PhysicalOp::Aggregation { .. }
        | PhysicalOp::ProcedureCall { .. } => false,
        // Result-shaping wrappers: the write-only-ness is whatever the wrapped op is.
        PhysicalOp::Skip { input, .. }
        | PhysicalOp::Limit { input, .. }
        | PhysicalOp::Sort { input, .. }
        | PhysicalOp::TopN { input, .. }
        | PhysicalOp::Optional { input, .. } => is_write_only_root(input),
        // Any read leaf / join / expand at the root means a returning query (a bare `MATCH` with no
        // `RETURN` is a compile error, so this only arises for genuine read results).
        _ => false,
    }
}

/// Resolves a result [`Row`]'s cells (named by `columns`) into [`Concrete`] snapshots through the
/// live graph seam.
fn resolve_row(row: &Row, columns: &[String], graph: &dyn GraphAccess) -> Vec<Concrete> {
    columns
        .iter()
        .map(|name| {
            let cell = row.get(name).cloned().unwrap_or(RowValue::NULL);
            resolve_cell(&cell, graph)
        })
        .collect()
}

/// Resolves one [`RowValue`] cell into a [`Concrete`].
///
/// Entity references are read through the seam into owned snapshots; pure property values pass
/// through, except that a property **list/map may itself contain entities is not possible** here —
/// the engine only puts entities at the `RowValue` level, not nested inside a property `Value` — so a
/// `Value::List`/`Value::Map` is a pure-property container and stays a [`Concrete::Value`].
fn resolve_cell(cell: &RowValue, graph: &dyn GraphAccess) -> Concrete {
    match cell {
        RowValue::Value(v) => Concrete::Value(v.clone()),
        RowValue::Node(node) => resolve_node(node.id, graph),
        RowValue::Rel(rel) => resolve_rel(rel.id, graph),
        // A structural list (`collect(n)`, `nodes(p)`, …) resolves element-wise; a path resolves
        // into its alternating node/relationship snapshot sequence.
        RowValue::List(items) => {
            Concrete::List(items.iter().map(|it| resolve_cell(it, graph)).collect())
        }
        // A structural map (a map literal holding entities, e.g. `{key: u}`) resolves value-wise,
        // each value carried through as its own structural/property snapshot.
        RowValue::Map(entries) => Concrete::Map(
            entries
                .iter()
                .map(|(k, v)| (k.clone(), resolve_cell(v, graph)))
                .collect(),
        ),
        RowValue::Path(p) => Concrete::Path(resolve_path(p, graph)),
    }
}

/// Resolves a [`PathValue`] into a [`ConcretePath`]: the start node followed by each hop's
/// direction, relationship snapshot and arrival node, read through the live seam.
fn resolve_path(p: &PathValue, graph: &dyn GraphAccess) -> ConcretePath {
    ConcretePath {
        start: resolve_path_node(p.start, graph),
        steps: p
            .steps
            .iter()
            .map(|s| {
                let (rel_type, rel_properties) = match graph.rel_data(s.rel) {
                    Some(data) => (
                        data.rel_type,
                        graph.rel_properties(s.rel).unwrap_or_default(),
                    ),
                    None => (String::new(), Vec::new()),
                };
                ConcretePathStep {
                    forward: s.forward,
                    rel_type,
                    rel_properties,
                    node: resolve_path_node(s.node, graph),
                }
            })
            .collect(),
    }
}

/// Resolves a node id into the [`ConcreteNode`] used inside a [`ConcretePath`] (labels + props).
fn resolve_path_node(id: NodeId, graph: &dyn GraphAccess) -> ConcreteNode {
    ConcreteNode {
        labels: graph.node_labels(id).unwrap_or_default(),
        properties: graph.node_properties(id).unwrap_or_default(),
    }
}

/// Resolves a node id into a [`Concrete::Node`] snapshot (labels + properties), or `null` if the
/// node no longer exists.
fn resolve_node(id: NodeId, graph: &dyn GraphAccess) -> Concrete {
    let labels = graph.node_labels(id).unwrap_or_default();
    let properties = graph.node_properties(id).unwrap_or_default();
    Concrete::Node { labels, properties }
}

/// Resolves a relationship id into a [`Concrete::Rel`] snapshot (type + properties), or `null` if it
/// no longer exists.
fn resolve_rel(id: RelId, graph: &dyn GraphAccess) -> Concrete {
    match graph.rel_data(id) {
        Some(data) => Concrete::Rel {
            rel_type: data.rel_type,
            properties: graph.rel_properties(id).unwrap_or_default(),
        },
        None => Concrete::Value(Value::Null),
    }
}

// =================================================================================================
// Error classification (engine error -> TCK (type, phase, detail))
// =================================================================================================

/// Classifies a parameter-binding error. A missing parameter is the TCK `ParameterMissing`; a
/// wrong-typed one is an `ArgumentError` (both runtime).
fn classify_bind_error(e: &graphus_cypher::BindError) -> TckError {
    use graphus_cypher::BindError as B;
    let (error_type, detail) = match e {
        B::MissingParameter { .. } => ("ParameterMissing", None),
        B::WrongType { .. } => ("ArgumentError", None),
        _ => ("ArgumentError", None),
    };
    TckError {
        error_type: error_type.to_owned(),
        phase: ErrorPhase::Runtime.as_tck_str().to_owned(),
        detail: detail.map(str::to_owned),
        message: e.to_string(),
    }
}

/// Classifies an [`ExecError`](graphus_cypher::ExecError) into the TCK runtime taxonomy.
fn classify_exec_error(e: graphus_cypher::ExecError) -> TckError {
    use graphus_cypher::ExecError as X;
    let message = e.to_string();
    let (error_type, detail): (&str, Option<&str>) = match &e {
        X::Eval(eval) => return classify_eval_error(eval, message),
        // A non-DETACH delete of a connected node is the TCK `ConstraintValidationFailed`
        // (`DeleteConnectedNode`).
        X::DeleteConnectedNode => ("ConstraintValidationFailed", Some("DeleteConnectedNode")),
        // A write that found a non-entity where an entity was required is a TypeError at runtime.
        X::NotAnEntity { .. } => ("TypeError", None),
        X::PropertiesNotAMap => ("TypeError", None),
        // A MERGE whose inline property map yielded a null value is the TCK runtime
        // `SemanticError: MergeReadOwnWrites` (`clauses/merge/Merge1` [17], `Merge5` [29]).
        X::MergeNullProperty => ("SemanticError", Some("MergeReadOwnWrites")),
        // The pipeline was cancelled — not a TCK error class; surface as a generic runtime error so
        // the scenario fails loudly rather than masquerading as a matched error.
        X::Cancelled => ("Cancelled", None),
        // A runtime procedure-invocation failure (rmp #57). The TCK has no *runtime* CALL error
        // scenarios (procedure faults classify at compile time), so this only surfaces honestly on
        // a harness/engine defect (e.g. a compile/execute registry mismatch).
        X::Procedure(_) => ("ProcedureError", None),
        _ => ("TypeError", None),
    };
    TckError {
        error_type: error_type.to_owned(),
        phase: ErrorPhase::Runtime.as_tck_str().to_owned(),
        detail: detail.map(str::to_owned),
        message,
    }
}

/// Classifies an [`EvalError`](graphus_cypher::EvalError) into the TCK runtime taxonomy.
fn classify_eval_error(e: &graphus_cypher::EvalError, message: String) -> TckError {
    use graphus_cypher::EvalError as Ev;
    let (error_type, detail): (&str, Option<&str>) = match e {
        Ev::DivisionByZero => ("ArithmeticError", Some("DivisionByZero")),
        Ev::TypeError { .. } => ("TypeError", None),
        Ev::IntegerOverflow => ("ArithmeticError", None),
        // A built-in that passed compile-time arity but has no runtime implementation: not a real
        // TCK class. Mark it so the scenario fails honestly rather than matching.
        Ev::UnsupportedFunction { .. } => ("UnsupportedFunction", None),
        // An out-of-range numeric argument (e.g. a `percentileCont`/`percentileDisc` percentile
        // outside `[0,1]`) is the TCK `ArgumentError: NumberOutOfRange`.
        Ev::NumberOutOfRange { .. } => ("ArgumentError", Some("NumberOutOfRange")),
        _ => ("TypeError", None),
    };
    TckError {
        error_type: error_type.to_owned(),
        phase: ErrorPhase::Runtime.as_tck_str().to_owned(),
        detail: detail.map(str::to_owned),
        message,
    }
}

/// Classifies a captured store-layer error message into the TCK runtime taxonomy (best-effort on the
/// message text, since the store error is opaque here).
fn classify_store_error(message: &str) -> TckError {
    // A non-storable property subtype is the closest to a runtime TypeError.
    TckError {
        error_type: "TypeError".to_owned(),
        phase: ErrorPhase::Runtime.as_tck_str().to_owned(),
        detail: None,
        message: message.to_owned(),
    }
}

// =================================================================================================
// Deciding the Then step
// =================================================================================================

/// Checks an error-expecting scenario against the query run.
fn check_error_expectation(
    run: &QueryRun,
    expected_type: &str,
    expected_phase: &str,
    expected_detail: &str,
) -> Outcome {
    let err = match run {
        QueryRun::Error(e) => e,
        QueryRun::Rows { rows, .. } => {
            return Outcome::Failed(format!(
                "expected a {expected_type} at {expected_phase}: {expected_detail}, but the query produced {} row(s)",
                rows.len()
            ));
        }
    };

    // TYPE and PHASE must match (the load-bearing assertion). The TCK writes three wildcards where
    // the classification is implementation-defined (`tck/README.adoc`): the generic type `Error`
    // matches any engine error class, the phase `any time` matches any phase, and the detail `*`
    // matches any detail.
    if expected_type != "Error" && err.error_type != expected_type {
        return Outcome::Failed(format!(
            "error TYPE mismatch: expected {expected_type}, got {} (phase {}, msg: {})",
            err.error_type, err.phase, err.message
        ));
    }
    if expected_phase != "any time" && err.phase != expected_phase {
        return Outcome::Failed(format!(
            "error PHASE mismatch: expected {expected_phase}, got {} (type {}, msg: {})",
            err.phase, err.error_type, err.message
        ));
    }

    // DETAIL is compared only when the engine produced one; a detail mismatch where the engine has
    // no equivalent detail is a soft note, not a hard fail (`tck` guidance: TYPE/PHASE is the gate).
    if expected_detail == "*" {
        return Outcome::Passed;
    }
    match &err.detail {
        Some(detail) if detail != expected_detail => Outcome::Failed(format!(
            "error DETAIL mismatch: expected {expected_detail}, got {detail}"
        )),
        _ => Outcome::Passed,
    }
}

/// Checks a result-table scenario (ordered or unordered) against the query run.
fn check_rows_expectation(run: &QueryRun, ordered: bool, table: &ResultTable) -> Outcome {
    let (columns, rows) = match run {
        QueryRun::Rows { columns, rows } => (columns, rows),
        QueryRun::Error(e) => {
            return Outcome::Failed(format!(
                "expected rows, but the query raised {} at {}: {}",
                e.error_type, e.phase, e.message
            ));
        }
    };

    // Columns must equal the expected header by name, in order.
    if columns.as_slice() != table.header.as_slice() {
        return Outcome::Failed(format!(
            "column mismatch: expected {:?}, got {:?}",
            table.header, columns
        ));
    }

    // Parse the expected table rows into ExpectedValues.
    let mut expected_rows = Vec::with_capacity(table.rows.len());
    for raw_row in &table.rows {
        match parse_row(&table.header, raw_row) {
            Ok(parsed) => expected_rows.push(parsed),
            Err(e) => return Outcome::Failed(format!("expected-value parse error: {e}")),
        }
    }

    let result = if ordered {
        assert_ordered(&expected_rows, rows, table.ignore_list_order)
    } else {
        assert_unordered(&expected_rows, rows, table.ignore_list_order)
    };
    match result {
        Ok(()) => Outcome::Passed,
        Err(reason) => Outcome::Failed(reason),
    }
}

/// Checks a `Then the result should be empty` scenario.
fn check_empty_expectation(run: &QueryRun) -> Outcome {
    match run {
        QueryRun::Rows { rows, .. } if rows.is_empty() => Outcome::Passed,
        QueryRun::Rows { rows, .. } => Outcome::Failed(format!(
            "expected an empty result, got {} row(s)",
            rows.len()
        )),
        QueryRun::Error(e) => Outcome::Failed(format!(
            "expected an empty result, but the query raised {} at {}: {}",
            e.error_type, e.phase, e.message
        )),
    }
}

// =================================================================================================
// Side effects (before/after snapshot diff per `tck/README.adoc`)
// =================================================================================================

/// A snapshot of the observable graph state, sufficient to compute every side-effect metric as a
/// set/multiset difference (`tck/README.adoc` §"Observability of side effects").
#[derive(Debug, Clone, Default)]
struct GraphSnapshot {
    /// Live node ids.
    nodes: BTreeSet<u64>,
    /// Live relationship ids.
    rels: BTreeSet<u64>,
    /// Distinct labels present on any node.
    labels: BTreeSet<String>,
    /// The multiset of `(entity-kind, entity-id, key, value-debug)` property triples. The value is
    /// rendered to a stable string so it is `Ord`-comparable for the multiset diff.
    properties: BTreeMap<(u8, u64, String, String), usize>,
}

/// Takes a [`GraphSnapshot`] in a fresh read transaction over the coordinator.
fn snapshot(coord: &mut Coord) -> Result<GraphSnapshot, String> {
    let txn = coord.begin_serializable();
    let snap = (|| {
        let graph = coord.statement(txn).map_err(|e| e.to_string())?;
        let mut snap = GraphSnapshot::default();

        let node_ids = graph.scan_nodes();
        for nid in &node_ids {
            snap.nodes.insert(nid.0);
            if let Some(labels) = graph.node_labels(*nid) {
                for l in labels {
                    snap.labels.insert(l);
                }
            }
            if let Some(props) = graph.node_properties(*nid) {
                for (k, v) in props {
                    *snap
                        .properties
                        .entry((0, nid.0, k, format!("{v:?}")))
                        .or_insert(0) += 1;
                }
            }
        }

        // Relationships: enumerate them as the distinct rel ids incident to any node (the seam has no
        // global rel scan, but every live rel is incident to a live node).
        let mut seen_rels = BTreeSet::new();
        for nid in &node_ids {
            for rid in graph.incident_rels(*nid) {
                if !seen_rels.insert(rid.0) {
                    continue;
                }
                snap.rels.insert(rid.0);
                if let Some(props) = graph.rel_properties(rid) {
                    for (k, v) in props {
                        *snap
                            .properties
                            .entry((1, rid.0, k, format!("{v:?}")))
                            .or_insert(0) += 1;
                    }
                }
            }
        }
        Ok::<_, String>(snap)
    })();
    // A read transaction always commits cleanly (no writes).
    let _ = coord.commit(txn);
    snap
}

/// The observed side-effect counters between two snapshots.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SideEffects {
    added_nodes: usize,
    removed_nodes: usize,
    added_rels: usize,
    removed_rels: usize,
    added_labels: usize,
    removed_labels: usize,
    added_props: usize,
    removed_props: usize,
}

/// Computes the side-effect counters as the difference `after - before` (`tck/README.adoc`).
fn diff_side_effects(before: &GraphSnapshot, after: &GraphSnapshot) -> SideEffects {
    let added_nodes = after.nodes.difference(&before.nodes).count();
    let removed_nodes = before.nodes.difference(&after.nodes).count();
    let added_rels = after.rels.difference(&before.rels).count();
    let removed_rels = before.rels.difference(&after.rels).count();
    let added_labels = after.labels.difference(&before.labels).count();
    let removed_labels = before.labels.difference(&after.labels).count();

    // Properties are a multiset of triples; +properties is the count present in `after` beyond
    // `before`, summed over keys, and -properties the reverse.
    let (mut added_props, mut removed_props) = (0usize, 0usize);
    let all_keys: BTreeSet<_> = before
        .properties
        .keys()
        .chain(after.properties.keys())
        .collect();
    for key in all_keys {
        let b = before.properties.get(key).copied().unwrap_or(0);
        let a = after.properties.get(key).copied().unwrap_or(0);
        if a > b {
            added_props += a - b;
        } else if b > a {
            removed_props += b - a;
        }
    }

    SideEffects {
        added_nodes,
        removed_nodes,
        added_rels,
        removed_rels,
        added_labels,
        removed_labels,
        added_props,
        removed_props,
    }
}

/// Parses the expected side-effect counters from the spec into a [`SideEffects`].
///
/// Unspecified metrics imply zero (`tck/README.adoc`). Returns `Err` on a malformed counter cell.
fn expected_side_effects(spec: &SideEffectSpec) -> Result<SideEffects, String> {
    let mut se = SideEffects::default();
    let rows = match spec {
        SideEffectSpec::Table(rows) => rows,
        SideEffectSpec::None | SideEffectSpec::Unspecified => return Ok(se),
    };
    for (metric, count_raw) in rows {
        let count: usize = count_raw.trim().parse().map_err(|_| {
            format!("side-effect count {count_raw:?} for `{metric}` is not a number")
        })?;
        match metric.as_str() {
            "+nodes" => se.added_nodes = count,
            "-nodes" => se.removed_nodes = count,
            "+relationships" => se.added_rels = count,
            "-relationships" => se.removed_rels = count,
            "+labels" => se.added_labels = count,
            "-labels" => se.removed_labels = count,
            "+properties" => se.added_props = count,
            "-properties" => se.removed_props = count,
            other => return Err(format!("unknown side-effect metric `{other}`")),
        }
    }
    Ok(se)
}

/// Snapshots after the When query and compares the observed side effects to the expectation.
fn check_side_effects(coord: &mut Coord, before: &GraphSnapshot, spec: &SideEffectSpec) -> Outcome {
    let after = match snapshot(coord) {
        Ok(s) => s,
        Err(e) => return Outcome::Errored(format!("post-snapshot failed: {e}")),
    };
    let observed = diff_side_effects(before, &after);
    let expected = match expected_side_effects(spec) {
        Ok(e) => e,
        Err(e) => return Outcome::Failed(format!("side-effect spec: {e}")),
    };
    if observed == expected {
        Outcome::Passed
    } else {
        Outcome::Failed(format!(
            "side effects mismatch:\n  expected {expected:?}\n  observed {observed:?}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::load_feature_str;

    /// Runs the single scenario in a one-scenario feature string and returns its outcome.
    fn run_one(feature_text: &str) -> Outcome {
        let scenarios =
            load_feature_str(feature_text, "test/T.feature").expect("parse feature text");
        assert_eq!(scenarios.len(), 1, "expected exactly one scenario");
        run_scenario(&scenarios[0], &crate::tck_root().join("graphs"))
    }

    #[test]
    fn return_literal_passes() {
        let f = "Feature: F\n\n  Scenario: S\n\
                 \x20   Given any graph\n\
                 \x20   When executing query:\n      \"\"\"\n      RETURN 1 AS n\n      \"\"\"\n\
                 \x20   Then the result should be, in any order:\n      | n |\n      | 1 |\n\
                 \x20   And no side effects\n";
        assert_eq!(run_one(f), Outcome::Passed);
    }

    #[test]
    fn wrong_expected_value_fails() {
        let f = "Feature: F\n\n  Scenario: S\n\
                 \x20   Given any graph\n\
                 \x20   When executing query:\n      \"\"\"\n      RETURN 1 AS n\n      \"\"\"\n\
                 \x20   Then the result should be, in any order:\n      | n |\n      | 2 |\n";
        assert!(matches!(run_one(f), Outcome::Failed(_)));
    }

    #[test]
    fn create_reports_side_effects() {
        let f = "Feature: F\n\n  Scenario: S\n\
                 \x20   Given an empty graph\n\
                 \x20   When executing query:\n      \"\"\"\n      CREATE (:Person {name: 'Ada'})\n      \"\"\"\n\
                 \x20   Then the result should be empty\n\
                 \x20   And the side effects should be:\n      | +nodes | 1 |\n      | +labels | 1 |\n      | +properties | 1 |\n";
        assert_eq!(run_one(f), Outcome::Passed);
    }

    #[test]
    fn undefined_variable_is_a_compile_time_syntax_error() {
        let f = "Feature: F\n\n  Scenario: S\n\
                 \x20   Given any graph\n\
                 \x20   When executing query:\n      \"\"\"\n      MATCH () RETURN foo\n      \"\"\"\n\
                 \x20   Then a SyntaxError should be raised at compile time: UndefinedVariable\n";
        assert_eq!(run_one(f), Outcome::Passed);
    }

    #[test]
    fn matched_node_resolves_labels_and_properties() {
        let f = "Feature: F\n\n  Scenario: S\n\
                 \x20   Given an empty graph\n\
                 \x20   And having executed:\n      \"\"\"\n      CREATE (:A:B {n: 1})\n      \"\"\"\n\
                 \x20   When executing query:\n      \"\"\"\n      MATCH (n) RETURN n\n      \"\"\"\n\
                 \x20   Then the result should be, in any order:\n      | n              |\n      | (:A:B {n: 1}) |\n\
                 \x20   And no side effects\n";
        assert_eq!(run_one(f), Outcome::Passed);
    }

    /// A scenario with two query blocks — a `CREATE` then a `When executing control query:` that
    /// reads it back — must run both against the *same* graph, in order. Regression for `rmp` #127:
    /// the plan kept only the last query, so the CREATE never ran and the control query saw an empty
    /// graph (`row count mismatch: expected 1, got 0`).
    #[test]
    fn two_query_blocks_share_state_and_each_is_checked() {
        let f = "Feature: F\n\n  Scenario: S\n\
                 \x20   Given an empty graph\n\
                 \x20   When executing query:\n      \"\"\"\n      CREATE ({created: 7})\n      \"\"\"\n\
                 \x20   Then the result should be empty\n\
                 \x20   And the side effects should be:\n      | +nodes | 1 |\n      | +properties | 1 |\n\
                 \x20   When executing control query:\n      \"\"\"\n      MATCH (n) RETURN n.created\n      \"\"\"\n\
                 \x20   Then the result should be, in any order:\n      | n.created |\n      | 7         |\n\
                 \x20   And no side effects\n";
        assert_eq!(run_one(f), Outcome::Passed);
    }

    /// The first failing block stops the scenario and the message names which block failed.
    #[test]
    fn first_failing_block_fails_the_scenario_and_is_named() {
        // The control query expects the wrong value, so block 2/2 fails.
        let f = "Feature: F\n\n  Scenario: S\n\
                 \x20   Given an empty graph\n\
                 \x20   When executing query:\n      \"\"\"\n      CREATE ({created: 7})\n      \"\"\"\n\
                 \x20   Then the result should be empty\n\
                 \x20   And the side effects should be:\n      | +nodes | 1 |\n      | +properties | 1 |\n\
                 \x20   When executing control query:\n      \"\"\"\n      MATCH (n) RETURN n.created\n      \"\"\"\n\
                 \x20   Then the result should be, in any order:\n      | n.created |\n      | 999       |\n";
        match run_one(f) {
            Outcome::Failed(m) => assert!(
                m.starts_with("block 2/2"),
                "the failing block must be identified, got: {m}"
            ),
            other => panic!("expected a Failed outcome, got {other:?}"),
        }
    }

    /// A block whose side-effect delta is measured per-block: the CREATE block reports `+nodes 1`
    /// while the following read block reports none (not accumulated).
    #[test]
    fn per_block_side_effects_are_not_accumulated() {
        let f = "Feature: F\n\n  Scenario: S\n\
                 \x20   Given an empty graph\n\
                 \x20   When executing query:\n      \"\"\"\n      CREATE (:Person)\n      \"\"\"\n\
                 \x20   Then the result should be empty\n\
                 \x20   And the side effects should be:\n      | +nodes | 1 |\n      | +labels | 1 |\n\
                 \x20   When executing control query:\n      \"\"\"\n      MATCH (n) RETURN n\n      \"\"\"\n\
                 \x20   Then the result should be, in any order:\n      | n         |\n      | (:Person) |\n\
                 \x20   And no side effects\n";
        assert_eq!(run_one(f), Outcome::Passed);
    }

    #[test]
    fn empty_result_passes_when_no_match() {
        let f = "Feature: F\n\n  Scenario: S\n\
                 \x20   Given an empty graph\n\
                 \x20   When executing query:\n      \"\"\"\n      MATCH (n) RETURN n\n      \"\"\"\n\
                 \x20   Then the result should be empty\n\
                 \x20   And no side effects\n";
        assert_eq!(run_one(f), Outcome::Passed);
    }
}
