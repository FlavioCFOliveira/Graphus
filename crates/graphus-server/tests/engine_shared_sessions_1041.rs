//! **`rmp` #1041 — the engine's session state is the engine's, not each worker's.**
//!
//! The open-transaction table, the parked-statement queue and the compiled-plan cache used to be built
//! inside `run_engine_loop`, so an engine running `W` workers held `W` of each. Every gate below names
//! one thing that was therefore false, and each was verified by execution before the fix.
//!
//! # What each gate proves, and how it was shown not to be vacuous
//!
//! 1. [`shutdown_drain_rolls_back_every_workers_transaction`] — the graceful drain reached the table of
//!    whichever worker received `Shutdown` and reported success regardless. Non-vacuity: with the table
//!    per worker this gate reports **1 of 4** rolled back.
//! 2. [`ddl_on_one_worker_invalidates_every_workers_plan`] — a `DROP INDEX` bumped the schema version of
//!    one cache, so a `USING INDEX` plan compiled before it stayed servable from the others *for the
//!    life of the process*. The same query text was then ACCEPTED on one connection and REJECTED on
//!    another. Non-vacuity: with a cache per worker this gate finds a worker that still accepts.
//! 3. [`age_sweep_spares_a_transaction_executing_on_another_worker`] — the age sweep's exclusion list
//!    covers parked statements, and a statement that is *executing* is not parked. What protected it
//!    was that a foreign transaction was invisible in a per-worker table, which sharing removes.
//!    Non-vacuity: without the affinity test the sweep aborts the transaction mid-statement (**1**
//!    abort inside the execution window, against 0).
//! 4. [`age_sweep_spares_a_parked_statement`] — the complementary half, on a single-worker engine so
//!    the affinity test is unconditionally true and the parked-queue exclusion is the SOLE control.
//!    Non-vacuity: with the parked exclusion removed the suspended statement is truncated at **1 of
//!    2000 rows** with "statement in inactive txn".
//! 5. [`a_parked_statement_is_resumed_only_by_its_owner`] — sharing the parked queue is what makes
//!    this necessary: a resumed batch drives operators against a transaction, and a transaction has
//!    exactly one worker allowed inside it. Non-vacuity: with the pre-#1041 shape restored (a budget of
//!    `len()` and a plain `pop_front`) the idle siblings advance the parked statement by **1788 rows**
//!    while its owner is inside another statement of the same engine, against a bound of 2. Restoring
//!    BOTH is what the mutation has to do: the resume pass carries the affinity twice, once for
//!    correctness (which statement it may take) and once for fairness (how many turns it is owed), and
//!    a mutation of either alone leaves the other standing and the gate green.
//! 6. [`the_open_transaction_gauge_counts_each_transaction_once`] — the same "one per engine" mistake
//!    in the two metric folds, which publish coordinator-wide counts. Non-vacuity: with a gauge per
//!    worker the series reads **16** for four open transactions.
//! 7. [`the_open_transaction_gauge_returns_to_zero_under_concurrent_workers`] — the end-to-end
//!    quiescence check for the same folds. It does NOT gate the fold's ordering; see its own docs for
//!    why, and `engine::active_txn_gauge_tests` for the gate that does.
//!
//! Gates 3 and 4 are deliberately a pair, and were cross-checked in both directions. Both controls
//! prevent the reap of a *parked* statement on another worker, so a single test there would pass with
//! either one removed and prove neither. Each is therefore exercised where it is the only thing
//! standing between the sweep and a live cursor — gate 3 on a statement that never parks, gate 4 on a
//! one-worker engine — and each was confirmed to survive the OTHER's mutation: gate 3 passes with the
//! parked exclusion removed, gate 4 passes with the affinity test removed.
//!
//! Gate 5 needed the same care for a different reason, and getting it wrong the first time is worth
//! recording: it sampled the parked statement's progress AFTER joining the occupying statement, so the
//! rows its owner delivered the instant it was free — the correct behaviour the gate exists to permit —
//! landed inside the window it was measuring.
//!
//! # Both occupancy gates were measuring the machine, and `rmp` #1042 corrected them
//!
//! Gates 3 and 5 each watch a counter for as long as a worker is occupied, and each got two things
//! wrong that only an optimised build could reveal.
//!
//! The first is the ORDER of the two observations. Both checked "is it still busy?" and then read the
//! counter, which leaves a window between the two in which the legitimate event — the owner reaping
//! its own over-age transaction, or resuming its own parked statement, the instant it goes free —
//! lands in the sample and is attributed to a foreign worker. Both now read the counter FIRST and test
//! liveness AFTER: `is_finished` is monotonic, so an observation of "still running" at the later
//! instant proves the earlier sample was taken while it ran. The window closes by construction rather
//! than by being too small to hit.
//!
//! The second is that both sized their occupancy window with a fixed row count and a comment claiming
//! it lasted "hundreds of milliseconds" — a claim about the compiler's output, not about the engine.
//! At `opt-level = 1` the same statement runs in under a third of the time, both windows fell below
//! the minimum each gate demands of itself, and both failed. They failed LOUDLY, naming the duration
//! they got, because each carries a non-vacuity assertion; that is the only reason this was a
//! correction and not a pair of gates quietly measuring nothing. Both now size the statement by
//! measuring it ([`rows_for_window`]).
//!
//! # Why these engines are built directly
//!
//! `admission.engine_workers` above one is still refused by configuration (`rmp` #1037), so these gates
//! call `spawn_engine_with_timeout` — the same door `tests/engine_latch_scaling_1038.rs` uses. The
//! refusal bounds who can reach the multi-worker engine, not whether it is developed and tested.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::{AccessMode, IndexCommand, NodePropertyIndexRef};
use graphus_server::engine::{Engine, EngineHandle, TxTicket, spawn_engine_with_timeout};
use graphus_server::metrics::Metrics;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

struct RealClock;
impl Clock for RealClock {
    fn now_nanos(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }
}

/// A scratch directory, only needed by the gates that want a store on disk. The in-memory device is
/// enough for everything here, so this exists solely to keep the WAL sink honest.
struct TempDir {
    path: PathBuf,
}
impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "graphus_sessions1041_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("create scratch dir");
        Self { path }
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Builds an engine with `workers` workers over an in-memory store.
///
/// `result_buffer_capacity` is a parameter because one gate needs it small enough that an undrained
/// result fills the bounded egress channel and the statement parks — which is the state that gate is
/// about. `max_transaction_age` is a parameter for the same reason: two gates need the age sweep to
/// *want* to reap.
fn engine(
    _dir: &Path,
    workers: usize,
    result_buffer_capacity: usize,
    max_transaction_age: Option<Duration>,
) -> (Engine, Arc<Metrics>) {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(RealClock);
    let metrics = Arc::new(Metrics::new());
    let engine = spawn_engine_with_timeout::<MemBlockDevice, MemLogSink, _>(
        Arc::from("sessions1041"),
        move || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            let store = RecordStore::create(device, wal, 4_096, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        8192,
        result_buffer_capacity,
        2,
        workers,
        Arc::clone(&metrics),
        clock,
        None,
        max_transaction_age,
        None,
        Arc::new(graphus_server::txn_registry::TransactionRegistry::new()),
    )
    .expect("spawn engine");
    (engine, metrics)
}

/// The value of a Prometheus counter, by exact metric name. Reading the rendered text rather than a
/// private field keeps the oracle the same number an operator would see.
fn counter(metrics: &Metrics, name: &str) -> u64 {
    for line in metrics.render_prometheus().lines() {
        if let Some(rest) = line.strip_prefix(name) {
            let rest = rest.trim();
            if let Ok(v) = rest.parse::<u64>() {
                return v;
            }
        }
    }
    panic!("metric {name} not found in the Prometheus rendering");
}

/// Runs `query` to completion inside the already-open transaction `ticket`, returning its rows or the
/// terminal error. Drains the stream fully, so a statement that suspends on a full egress channel still
/// finishes.
fn run_in(
    handle: &EngineHandle,
    ticket: TxTicket,
    query: &str,
) -> Result<Vec<Vec<String>>, String> {
    let mut reply = handle
        .run_blocking(ticket, query.to_owned(), Vec::new(), false, None, None)
        .map_err(|e| e.to_string())?;
    let mut rows = Vec::new();
    loop {
        match reply.rows.next() {
            Ok(Some(row)) => rows.push(row.iter().map(|v| format!("{v:?}")).collect()),
            Ok(None) => return Ok(rows),
            Err(e) => return Err(e.to_string()),
        }
    }
}

/// The aggregation the two occupancy gates use to hold a worker, sized for `target` on THIS build.
///
/// Gates 3 and 5 both need a statement that keeps its worker inside the cursor for a window they can
/// sample, and both used to name a fixed row count for it — 700 000, with a comment asserting that it
/// was "long enough to hold its worker for hundreds of milliseconds". That was true of the binary the
/// gates were written against and of no other: measured on one machine, the identical statement takes
/// ~700 ms at `opt-level = 0` and ~200 ms at `opt-level = 1`. A fixed count therefore hard-codes an
/// optimisation level, and when the verification profile was optimised (`rmp` #1042) both windows
/// collapsed below the minimum each gate requires of itself.
///
/// Neither went quiet, and that is the only reason this is a correction and not an incident: each gate
/// asserts its own non-vacuity and each failed loudly, naming the duration it got. The remedy is to
/// stop assuming the machine and measure it — one calibration pass, then scale, because the statement
/// is linear in the row count (it filters and counts, and materialises nothing per row).
///
/// The scaling is deliberately CONSERVATIVE about its own error. The calibration pass pays a fixed
/// cost the scaled statement does not repeat per row (parse, plan, one auto-commit transaction), so
/// treating the whole measurement as per-row work underestimates the count needed — by ~15% at the
/// sizes used here. Callers therefore ask for a target several times the minimum their assertion
/// demands, and the assertion stays as the backstop that catches any machine where even that is wrong.
fn rows_for_window(handle: &EngineHandle, target: Duration) -> i64 {
    const CALIB_ROWS: i64 = 100_000;
    let started = std::time::Instant::now();
    run_auto(
        handle,
        &format!("UNWIND range(1, {CALIB_ROWS}) AS x WITH x WHERE x % 7 = 3 RETURN count(x) AS c"),
    )
    .expect("the calibration statement must succeed");
    let elapsed = started.elapsed().as_micros().max(1);
    let scaled = (u128::try_from(CALIB_ROWS).unwrap_or(0) * target.as_micros()) / elapsed;
    // Never below the calibration size: a host fast enough to make even that instantaneous would
    // otherwise be handed a statement too small to hold anything, and the gate's own non-vacuity
    // assertion — not this floor — is what would then report it.
    i64::try_from(scaled).unwrap_or(i64::MAX).max(CALIB_ROWS)
}

/// One auto-commit statement, drained. Used to seed data.
fn run_auto(handle: &EngineHandle, query: &str) -> Result<usize, String> {
    let ticket = handle
        .begin_auto_commit_blocking(AccessMode::Write)
        .map_err(|e| e.to_string())?;
    let mut reply = handle
        .run_blocking(ticket, query.to_owned(), Vec::new(), true, None, None)
        .map_err(|e| e.to_string())?;
    let mut n = 0usize;
    loop {
        match reply.rows.next() {
            Ok(Some(_)) => n += 1,
            Ok(None) => return Ok(n),
            Err(e) => return Err(e.to_string()),
        }
    }
}

fn shutdown(engine: Engine) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("shutdown runtime");
    rt.block_on(engine.handle.shutdown()).expect("shutdown");
    for j in engine.joins {
        j.join().expect("engine worker joins cleanly");
    }
}

/// Opens one explicit transaction per worker and returns their tickets.
///
/// `BEGIN` round-robins over the workers (`rmp` #1035), so `W` consecutive begins land on `W` distinct
/// workers — asserted here rather than assumed, because a gate about reaching every worker is worthless
/// if the fixture only ever reached one.
fn one_transaction_per_worker(handle: &EngineHandle, workers: usize) -> Vec<TxTicket> {
    let tickets: Vec<TxTicket> = (0..workers)
        .map(|_| handle.begin_blocking(AccessMode::Write).expect("begin"))
        .collect();
    let mut owners: Vec<usize> = tickets.iter().map(|t| (t.0 as usize) % workers).collect();
    owners.sort_unstable();
    owners.dedup();
    assert_eq!(
        owners.len(),
        workers,
        "the fixture must place a transaction on EVERY worker; tickets {:?} cover only {owners:?}",
        tickets.iter().map(|t| t.0).collect::<Vec<_>>()
    );
    tickets
}

/// **GATE 1 — a graceful stop rolls back every worker's transactions, not one worker's.**
///
/// The oracle is `graphus_transactions_aborted_total`, which `drain_inflight` increments once per
/// transaction it rolls back. With the open-transaction table per worker this reported 1 with `W = 4`
/// — and the shutdown still returned `Ok`, which is exactly why the defect survived: nothing the
/// operator could see said anything had been left behind. The `W - 1` transactions were undone by
/// ARIES on the next open instead, so no data was lost; what was lost was the property the final flush
/// documents, that a clean stop leaves recovery nothing to do.
#[test]
fn shutdown_drain_rolls_back_every_workers_transaction() {
    const WORKERS: usize = 4;
    let dir = TempDir::new("drain");
    let (engine, metrics) = engine(&dir.path, WORKERS, 256, None);
    let handle = engine.handle.clone();

    let tickets = one_transaction_per_worker(&handle, WORKERS);
    // Give each transaction a write, so the drain has real undo to do rather than closing an empty
    // read-only snapshot: a rollback that does nothing would still be counted, and the gate must be
    // about transactions that were genuinely mid-flight.
    for (i, ticket) in tickets.iter().enumerate() {
        run_in(&handle, *ticket, &format!("CREATE (:Straggler {{i: {i}}})"))
            .expect("write inside the explicit transaction");
    }

    let before = counter(&metrics, "graphus_transactions_aborted_total");
    drop(handle);
    shutdown(engine);
    let after = counter(&metrics, "graphus_transactions_aborted_total");

    assert_eq!(
        after - before,
        WORKERS as u64,
        "the graceful drain rolled back {} of {WORKERS} open transactions: it reached only the \
         worker that received Shutdown (rmp #1041)",
        after - before
    );
}

/// **GATE 2 — a DDL on one worker invalidates the plans every other worker is serving.**
///
/// A `USING INDEX` hint that cannot be satisfied is a compile ERROR, following Neo4j, so the hint is a
/// direct probe of what the planner can see. The sequence is: create the index, wait until the hinted
/// query compiles on every worker (the build is asynchronous), then `DROP INDEX` — which is
/// synchronous, and is routed round-robin to ONE worker — and re-run the same text on every worker.
///
/// With a cache per worker the worker that handled the `DROP` recompiled and rejected while the others
/// kept serving the cached plan and accepted, permanently. Whether a query is accepted is not allowed
/// to depend on which connection served it: that is a conformance property, and it is the reason this
/// gate asserts on acceptance rather than on rows. (No row was ever wrong — an index seek against a
/// dropped index declines and the executor falls back to a scan, the `rmp` #680/#738 contract.)
#[test]
fn ddl_on_one_worker_invalidates_every_workers_plan() {
    const WORKERS: usize = 4;
    const HINTED: &str = "MATCH (n:Hinted) USING INDEX n:Hinted(p) WHERE n.p = 3 RETURN n.p AS p";
    let dir = TempDir::new("plancache");
    let (engine, _metrics) = engine(&dir.path, WORKERS, 256, None);
    let handle = engine.handle.clone();

    run_auto(&handle, "UNWIND range(1, 64) AS i CREATE (:Hinted {p: i})").expect("seed");
    handle
        .index_ddl_blocking(IndexCommand::CreateNodePropertyIndex {
            name: Some("ix_hinted_p".to_owned()),
            label: "Hinted".to_owned(),
            properties: vec!["p".to_owned()],
            if_not_exists: false,
        })
        .expect("create index");

    // The build is asynchronous, so wait until the hint is satisfiable on EVERY worker before touching
    // anything. This also seeds the plan: after this loop every worker has served the hinted text.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let tickets = one_transaction_per_worker(&handle, WORKERS);
        let outcomes: Vec<_> = tickets
            .iter()
            .map(|t| run_in(&handle, *t, HINTED))
            .collect();
        for t in &tickets {
            let _ = handle.rollback_blocking(*t);
        }
        if outcomes.iter().all(Result::is_ok) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the index never came online on every worker: {outcomes:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    // Seed once more, so every worker's most recent compile of this text is the index plan and a stale
    // cache would have something to serve.
    let seed = one_transaction_per_worker(&handle, WORKERS);
    for t in &seed {
        run_in(&handle, *t, HINTED).expect("hinted query is accepted while the index exists");
        let _ = handle.rollback_blocking(*t);
    }

    // The synchronous DDL. It is routed round-robin, so exactly ONE worker executes it.
    handle
        .index_ddl_blocking(IndexCommand::DropNodePropertyIndex {
            index: NodePropertyIndexRef::Named("ix_hinted_p".to_owned()),
            if_exists: false,
        })
        .expect("drop index");

    let after = one_transaction_per_worker(&handle, WORKERS);
    let mut still_accepting = Vec::new();
    for t in &after {
        if run_in(&handle, *t, HINTED).is_ok() {
            still_accepting.push((t.0 as usize) % WORKERS);
        }
        let _ = handle.rollback_blocking(*t);
    }
    assert!(
        still_accepting.is_empty(),
        "workers {still_accepting:?} still accept a USING INDEX hint for an index that was dropped \
         on another worker: the plan-cache invalidation did not leave the worker that ran the DDL \
         (rmp #1041)"
    );

    drop(handle);
    shutdown(engine);
}

/// **GATE 3 — the age sweep spares a transaction another worker is executing in.**
///
/// The sweep excludes parked statements, and this statement is not parked: it is *running*. Nothing in
/// either shared table says so. What used to protect it was that the sweep could not see another
/// worker's transaction at all, and sharing the open-transaction table removed exactly that — so the
/// sweep now declines any ticket outside its own residue class, and every worker still sweeps its own.
///
/// # The oracle, and why the obvious one is worthless here
///
/// The obvious oracle is the statement's own result, and it does not work. Measured with the affinity
/// test removed: a sibling worker rolled the transaction back 100 ms into a 700 ms statement, and the
/// statement went on to produce the correct aggregate and report SUCCESS — because it reads no store
/// data, so nothing it does after the rollback consults the transaction that no longer exists. The
/// client is told its statement succeeded in a transaction that was destroyed while it ran. A
/// result-shaped assertion would pass over that, which is the definition of a vacuous gate.
///
/// So the oracle is `graphus_transactions_aborted_total`, sampled by this thread **while the statement
/// is still executing**: the reap increments it once. The ordering matters and is deliberate — the
/// sample is only taken after observing that the draining thread has NOT finished, so a legitimate
/// reap by the owning worker *after* the statement (the transaction is over-age and idle by then, and
/// reaping it is correct) can never be counted. The residual window is the few microseconds between
/// that check and the read; the defect it is hunting fires ~100 ms in, not in the last microsecond.
///
/// The transaction must also cross the cap **while its statement runs**, never before: a transaction
/// that is over-age and idle is reaped by its own worker, correctly, and a fixture that allowed that
/// would be testing the reaper rather than the exclusion. So the cap is 100 ms, the statement is
/// submitted immediately, and it runs for hundreds of milliseconds — during which the owning worker is
/// inside the cursor and cannot sweep, while the three siblings tick every 2 ms with no client traffic
/// at all and sweep hundreds of times each.
#[test]
fn age_sweep_spares_a_transaction_executing_on_another_worker() {
    const WORKERS: usize = 4;
    const CAP: Duration = Duration::from_millis(100);
    // The statement must outlive `CAP * 3` for the fixture to mean anything (asserted at the end), so
    // it is sized for well beyond that on THIS build rather than at a row count that only held a
    // worker while the code was unoptimised. See [`rows_for_window`].
    const WINDOW: Duration = Duration::from_millis(700);
    let dir = TempDir::new("reapexec");
    let (engine, metrics) = engine(&dir.path, WORKERS, 256, Some(CAP));
    let handle = engine.handle.clone();

    let rows_target = rows_for_window(&handle, WINDOW);
    // x % 7 == 3 for x in 1..=ROWS — one every seven, and the count is the oracle for truncation.
    let expected = (rows_target + 4) / 7;

    let ticket = handle.begin_blocking(AccessMode::Write).expect("begin");
    let before = counter(&metrics, "graphus_transactions_aborted_total");

    // Shaped to emit a SINGLE row at the very end: nothing streams, so the statement never parks and
    // the parked exclusion cannot be what saves it. Only the affinity test can.
    let started = std::time::Instant::now();
    let runner = {
        let handle = handle.clone();
        std::thread::spawn(move || {
            run_in(
                &handle,
                ticket,
                &format!(
                    "UNWIND range(1, {rows_target}) AS x WITH x WHERE x % 7 = 3 RETURN count(x) AS c"
                ),
            )
        })
    };

    // Watch for a reap for as long as — and only as long as — the statement is still running.
    //
    // THE ORDER OF THESE TWO OBSERVATIONS IS THE ORACLE. Read the counter FIRST and test liveness
    // AFTER: `is_finished` is monotonic, so a statement that has not finished at the later instant had
    // not finished at the earlier one either, and a count sampled before that check is therefore a
    // count that was already reached while the statement was executing. The reverse order — the one
    // this gate shipped with — leaves a window between the liveness check and the read in which the
    // OWNING worker's reap, which is correct and expected the moment the statement ends, lands in the
    // sample and is reported as a foreign worker's. That window is not theoretical: it is what made
    // this gate fail on an optimised build (`rmp` #1042), where the statement no longer ran for so
    // much longer than the cap that the last microseconds could be dismissed.
    let mut aborted_mid_statement = 0u64;
    loop {
        let sampled = counter(&metrics, "graphus_transactions_aborted_total") - before;
        if runner.is_finished() {
            break; // sample discarded: it may have been taken after the statement ended
        }
        if sampled > 0 {
            aborted_mid_statement = sampled; // proven: reaped WHILE executing
            break;
        }
        std::thread::sleep(Duration::from_micros(500));
    }
    let rows = runner.join().expect("the drain thread joins").expect(
        "a statement executing on its own worker must survive every sibling worker's age sweep \
         (rmp #1041)",
    );
    let elapsed = started.elapsed();

    assert_eq!(
        aborted_mid_statement, 0,
        "a transaction was rolled back while its own worker was executing a statement in it: a \
         sibling worker's age sweep claimed a ticket it does not own (rmp #1041). The statement \
         itself reports success, which is why this counter — and not the result — is the oracle."
    );
    assert_eq!(rows.len(), 1, "the aggregation must produce its one row");
    assert!(
        rows[0][0].contains(&format!("Integer({expected})")),
        "the aggregate must be the real count ({expected}), not a truncated one: {:?}",
        rows[0]
    );
    // The fixture only means anything if the statement outlived the cap: otherwise no sweep ever saw
    // an over-age transaction and the gate would pass on a machine fast enough to make it vacuous.
    assert!(
        elapsed > CAP * 3,
        "the statement finished in {elapsed:?}, so it barely crossed the {CAP:?} cap and the \
         sibling sweeps were never offered this transaction — the gate measured nothing"
    );

    let _ = handle.rollback_blocking(ticket);
    drop(handle);
    shutdown(engine);
}

/// **GATE 4 — the age sweep spares a PARKED statement, on a single-worker engine.**
///
/// The complement of gate 3, and the reason the two are separate. On a one-worker engine every ticket
/// is the sweeping worker's own, so the affinity test is unconditionally true and the parked-queue
/// exclusion is the only thing left. A gate that parked a statement on a *multi*-worker engine would
/// pass with either control removed and would therefore prove neither.
///
/// A result buffer of one row and a consumer that waits before draining fills the bounded egress
/// channel, which is what suspends the statement. As in gate 3 the transaction must cross the cap
/// AFTER the statement has taken hold — here, while it is parked — so the statement is submitted
/// immediately and the consumer then stalls for well over the cap. The oracle is the full row count: a
/// reaped transaction ends the stream early, which is the silent-truncation class the terminal-error
/// machinery exists to prevent.
#[test]
fn age_sweep_spares_a_parked_statement() {
    const ROWS: usize = 2_000;
    let dir = TempDir::new("reapparked");
    // One row of egress buffer, so the statement suspends almost immediately.
    let (engine, _metrics) = engine(&dir.path, 1, 1, Some(Duration::from_millis(50)));
    let handle = engine.handle.clone();

    let ticket = handle.begin_blocking(AccessMode::Read).expect("begin");
    let mut reply = handle
        .run_blocking(
            ticket,
            format!("UNWIND range(1, {ROWS}) AS x RETURN x"),
            Vec::new(),
            false,
            None,
            None,
        )
        .expect("run");
    // The statement has filled its egress and parked. Stall the consumer for many multiples of the
    // 50 ms cap: the engine keeps ticking, and every one of those ticks runs the sweep against a
    // transaction that is now over-age and has a suspended cursor.
    std::thread::sleep(Duration::from_millis(400));

    let mut seen = 0usize;
    loop {
        match reply.rows.next() {
            Ok(Some(_)) => seen += 1,
            Ok(None) => break,
            Err(e) => panic!(
                "the parked statement was terminated after {seen} of {ROWS} rows: the age sweep \
                 reaped a transaction whose cursor was suspended (rmp #477/#1041): {e}"
            ),
        }
    }
    assert_eq!(
        seen, ROWS,
        "the parked statement must deliver every row; it stopped at {seen}"
    );

    let _ = handle.rollback_blocking(ticket);
    drop(handle);
    shutdown(engine);
}

/// **GATE 5 — a parked statement is resumed by the worker that owns it, and by no other.**
///
/// The parked queue had to become engine-wide with the open-transaction table, so the age sweep can
/// see every suspended cursor. Resuming from it is a different matter, and the difference is the point
/// of this gate: a resumed batch drives real operators against the statement's transaction, and a
/// transaction is the unit that session affinity keeps single-threaded. A client may hold several
/// results open in one transaction, so its owning worker can be executing a second statement in that
/// very transaction while another worker looks at the first — two threads inside one write buffer and
/// one SSI footprint, with no lock between them because there has never needed to be one.
///
/// # The observable
///
/// A race has no deterministic symptom, so this gate asserts the property that PREVENTS it instead: a
/// parked statement makes no progress while its owner is busy. Two transactions are opened onto the
/// SAME worker (`BEGIN` round-robins, so the 1st and the `W+1`-th land together), one statement is
/// parked, and the other is a long aggregation that keeps their shared worker inside the cursor for
/// hundreds of milliseconds. With owner-only resume the parked statement cannot advance by a single
/// batch during that window. With any worker free to resume it, the three idle siblings drain it at
/// their 2 ms tick — hundreds of batches — which is what the assertion separates.
///
/// The delay is not a cost this gate is defending: the owner resumes the statement the moment it is
/// free, which the final drain confirms by requiring every row.
#[test]
fn a_parked_statement_is_resumed_only_by_its_owner() {
    const WORKERS: usize = 4;
    const PARKED_ROWS: usize = 4_000;
    // The occupying statement must hold its worker for longer than the 300 ms this gate requires of
    // itself below, on whatever build is running it. See [`rows_for_window`].
    const WINDOW: Duration = Duration::from_millis(700);
    let dir = TempDir::new("resumeowner");
    // One row of egress buffer, so the streaming statement suspends almost immediately.
    let (engine, _metrics) = engine(&dir.path, WORKERS, 1, None);
    let handle = engine.handle.clone();

    let busy_rows_target = rows_for_window(&handle, WINDOW);

    // Two transactions on ONE worker: `BEGIN` round-robins, so these are the 1st and the 5th.
    let parked_ticket = handle
        .begin_blocking(AccessMode::Read)
        .expect("begin parked");
    let mut busy_ticket = parked_ticket;
    for _ in 0..WORKERS {
        busy_ticket = handle.begin_blocking(AccessMode::Read).expect("begin busy");
    }
    assert_eq!(
        (parked_ticket.0 as usize) % WORKERS,
        (busy_ticket.0 as usize) % WORKERS,
        "the fixture must put both transactions on the SAME worker, or the busy statement blocks a \
         worker that was never going to resume the parked one and the gate proves nothing"
    );

    // Park the streaming statement: submitted and NOT drained, so its one-row egress fills at once.
    let mut parked = handle
        .run_blocking(
            parked_ticket,
            format!("UNWIND range(1, {PARKED_ROWS}) AS x RETURN x"),
            Vec::new(),
            false,
            None,
            None,
        )
        .expect("run the statement that parks");
    std::thread::sleep(Duration::from_millis(50)); // it is parked, and stays parked: nobody drains

    // Now occupy its owner, from a thread of its own: an aggregation emits nothing until it is
    // finished, so `run_blocking` does not return until the worker has ground through all of it.
    let started = std::time::Instant::now();
    let busy = {
        let handle = handle.clone();
        std::thread::spawn(move || {
            run_in(
                &handle,
                busy_ticket,
                &format!(
                    "UNWIND range(1, {busy_rows_target}) AS x WITH x WHERE x % 7 = 3 RETURN count(x) AS c"
                ),
            )
        })
    };
    // Let the occupying statement reach its worker and start executing before anything begins draining
    // the parked one: with the owner idle it would resume the parked statement itself, which is
    // correct behaviour and would make the window measure nothing.
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        !busy.is_finished(),
        "the occupying statement finished before the window even opened — the gate measured nothing"
    );

    // Drain the parked statement from another thread for exactly as long as its owner is busy.
    let delivered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let drainer = {
        let delivered = Arc::clone(&delivered);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                match parked.rows.next() {
                    Ok(Some(_)) => {
                        delivered.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    Ok(None) | Err(_) => break,
                }
            }
            // Finish the drain once the owner is free, to prove the statement was delayed, not lost.
            let mut total = delivered.load(std::sync::atomic::Ordering::Relaxed);
            loop {
                match parked.rows.next() {
                    Ok(Some(_)) => total += 1,
                    Ok(None) => return Ok(total),
                    Err(e) => return Err(format!("{e} after {total} rows")),
                }
            }
        })
    };

    // Sample the parked statement's progress for exactly as long as its owner is busy. Reading the
    // counter after the join instead would count the rows the owner delivers the moment it is free —
    // which is the correct behaviour this gate exists to permit, arriving after the window it is
    // measuring has closed.
    //
    // The order is the same one gate 3 uses, and for the same reason: SAMPLE FIRST, test liveness
    // AFTER. `is_finished` is monotonic, so an owner still busy at the later instant was busy at the
    // earlier one, which is what makes the sample admissible. Checking liveness first — as this gate
    // shipped — admits a sample taken after the owner went free, and the rows it then counts are the
    // owner's own legitimate resume.
    let mut during = 0usize;
    loop {
        let sampled = delivered.load(std::sync::atomic::Ordering::Relaxed);
        if busy.is_finished() {
            break; // sample discarded: it may post-date the owner becoming free
        }
        during = sampled; // proven: delivered while the owner was still inside the other statement
        std::thread::sleep(Duration::from_millis(1));
    }
    let busy_rows = busy
        .join()
        .expect("the occupying thread joins")
        .expect("the occupying statement must succeed");
    let busy_elapsed = started.elapsed();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let total = drainer
        .join()
        .expect("the drain thread joins")
        .expect("the parked statement must complete once its owner is free");

    assert_eq!(
        busy_rows.len(),
        1,
        "the occupying aggregation must produce its one row"
    );
    assert!(
        busy_elapsed > Duration::from_millis(300),
        "the occupying statement finished in {busy_elapsed:?}, so its worker was never busy long \
         enough for a sibling to have drained the parked statement — the gate measured nothing"
    );
    // The parked statement can only hand over what was already buffered when its owner became busy:
    // the one row in the bounded channel, plus at most one materialised row held back for the next
    // resume. Anything beyond that is a batch that some worker ran, and its owner ran none.
    assert!(
        during <= 2,
        "the parked statement advanced by {during} rows while the worker that owns it was executing \
         another statement: a sibling worker resumed a transaction it does not own, which puts two \
         threads inside one transaction (rmp #1041)"
    );
    assert_eq!(
        total, PARKED_ROWS,
        "the parked statement must deliver every row once its owner is free — the affinity check \
         delays a resume, it must never lose one"
    );

    drop(handle);
    shutdown(engine);
}

/// **GATE 6 — the open-transaction gauge counts the engine's transactions once, not once per worker.**
///
/// `ActiveTxnGauge` and `IndexBuildGauge` fold a *signed delta* into an additive server-wide gauge, so
/// that the series sums across database engines instead of reporting whichever engine wrote last. Both
/// were constructed inside the engine loop, so an engine running `W` workers held `W` of them — and
/// every one of them folded the same COORDINATOR-wide count. The published series then read up to `W`
/// times the truth.
///
/// The oracle is the invariant, not a single reading: the gauge may pass through intermediate values as
/// transactions open, but it must never exceed the number of transactions that exist. With four
/// transactions on four workers the per-worker shape reaches 16 — each worker folding a delta from its
/// own zero — where the truth is 4.
///
/// This is observability rather than data, and it self-corrects once the transactions close, which is
/// exactly what lets such a defect survive a glance at a dashboard.
#[test]
fn the_open_transaction_gauge_counts_each_transaction_once() {
    const WORKERS: usize = 4;
    let dir = TempDir::new("gauge");
    let (engine, metrics) = engine(&dir.path, WORKERS, 256, None);
    let handle = engine.handle.clone();

    let tickets = one_transaction_per_worker(&handle, WORKERS);
    // A statement on each, so every worker has dispatched a command and published at least once.
    for (i, ticket) in tickets.iter().enumerate() {
        run_in(&handle, *ticket, &format!("CREATE (:Gauged {{i: {i}}})")).expect("write");
    }

    // Settle, watching the whole way: the publish happens on the engine thread after the reply, so the
    // final value can lag the last statement, but no reading may ever exceed the truth.
    let mut worst = 0u64;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let settled = loop {
        let v = metrics.active_txns();
        worst = worst.max(v);
        if v == WORKERS as u64 && std::time::Instant::now() > deadline - Duration::from_secs(4) {
            break v;
        }
        if std::time::Instant::now() >= deadline {
            break v;
        }
        std::thread::sleep(Duration::from_millis(5));
    };

    assert!(
        worst <= WORKERS as u64,
        "the open-transaction gauge reached {worst} with only {WORKERS} transactions open: each \
         worker folded the engine-wide count into the same additive series (rmp #1041)"
    );
    assert_eq!(
        settled, WORKERS as u64,
        "the gauge must settle on the number of transactions that are actually open"
    );

    for t in &tickets {
        let _ = handle.rollback_blocking(*t);
    }
    drop(handle);
    shutdown(engine);
}

/// **GATE 7 — the engine leaves no open-transaction residue behind under concurrent load.**
///
/// Gate 6 pins the gauge against a static picture; this one drives 1600 transactions across four
/// clients and four workers and requires the gauge back at exactly **0** once they have all committed.
/// It gates the end-to-end bookkeeping: a ticket that leaks, a publish that never happens, a
/// retraction that goes missing on a path only concurrency reaches.
///
/// **What it does NOT gate, stated because the omission was measured.** The fold's *ordering* against
/// the value it remembers — where an unsound implementation loses a saturating decrement permanently —
/// is not reachable from here. The window is a handful of instructions and this test produces only a
/// few thousand publishes: run against the swap-then-fold shape, it passes. The gate for that lives
/// where the attempts are cheap enough to matter, in `engine::active_txn_gauge_tests` beside the
/// gauge, and it fails against that shape by 8. A test that named a defect it cannot reach would be
/// worse than no test, because the next reader would stop looking.
#[test]
fn the_open_transaction_gauge_returns_to_zero_under_concurrent_workers() {
    const WORKERS: usize = 4;
    const PER_CLIENT: usize = 400;
    let dir = TempDir::new("gaugerace");
    let (engine, metrics) = engine(&dir.path, WORKERS, 256, None);
    let handle = engine.handle.clone();

    let mut threads = Vec::with_capacity(WORKERS);
    for _ in 0..WORKERS {
        let handle = handle.clone();
        threads.push(std::thread::spawn(move || {
            for _ in 0..PER_CLIENT {
                let Ok(ticket) = handle.begin_blocking(AccessMode::Read) else {
                    continue;
                };
                // A statement, so the transaction is published as open by the worker that owns it and
                // then as closed — the pair of folds this gate is about.
                let _ = run_in(&handle, ticket, "RETURN 1 AS x");
                let _ = handle.commit_blocking(ticket);
            }
        }));
    }
    for t in threads {
        t.join().expect("client thread joins");
    }

    // Let every worker's last publish land. The gauge is written on the engine threads after the reply
    // reaches the client, so a settle window is needed — but a LOST decrement never returns, so
    // polling cannot mask the defect it is hunting: it can only give the correct code time to finish.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut observed = metrics.active_txns();
    while observed != 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
        observed = metrics.active_txns();
    }

    assert_eq!(
        observed,
        0,
        "after {} transactions all committed, the open-transaction gauge still reads {observed}: a \
         delta was folded out of order and the saturating decrement discarded it permanently (rmp \
         #1041)",
        WORKERS * PER_CLIENT
    );

    drop(handle);
    shutdown(engine);
}
