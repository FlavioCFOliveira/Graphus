//! The **real-server, mid-workload crash** driver (`rmp` #698): a concurrent OLTP client that is still
//! working — with at least one writer inside an **open, never-committed transaction** — at the instant
//! the server is `SIGKILL`ed, plus the post-restart verifier that proves what survived and what did not.
//!
//! # Why this exists
//!
//! The example's real-server phase used to spawn writers, **join them all**, assert the pre-crash
//! counts, and only then `SIGKILL` the server. That is a *post-quiescence* kill: no transaction is in
//! flight, so it can only ever prove the easy half of the contract (already-acknowledged commits
//! survive). The interesting half — *no in-flight effect may survive* — was never under test, even
//! though the README claimed a "mid-life" crash.
//!
//! This driver makes the kill genuinely mid-workload and makes the contract **falsifiable**:
//!
//! * **Committers** (`--writers N`) run auto-commit `CREATE` statements in a loop and record every
//!   commit the server **acknowledged**. They are still committing when the server dies.
//! * **One in-flight writer** opens an EXPLICIT transaction (`BEGIN`), writes `:Phantom` nodes inside
//!   it, proves they are visible *within* the transaction, and then **holds it open** — it never sends
//!   `COMMIT`. It keeps probing inside the transaction until the connection dies, so the ledger can
//!   state that the transaction was still open at the instant of the kill.
//! * The statement a committer had in flight when the socket died is **undetermined** (the ack never
//!   arrived — it may or may not have committed). It is recorded as such and never asserted either way:
//!   claiming otherwise would be a lie, not a durability proof.
//!
//! After the restart, [`verify`] re-connects and asserts the three-way partition:
//!
//! | Class | Obligation |
//! |-------|------------|
//! | acknowledged commits | **MUST** be present, complete, and correct (every node, every edge, every property) |
//! | in-flight (open txn) | **MUST NOT** be present — zero `:Phantom` nodes, no partial trace |
//! | undetermined (in-flight *statement* at the kill) | either fully present or fully absent — **never partial**, and never a batch outside the ledger |
//!
//! Everything is measured, never fabricated: commit latencies are the real per-commit wall times.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use graphus_core::Value;
use graphus_reco_gen::client::{BoltClient, ClientError, ClientResult};

/// The label the acknowledged (committed) accounts carry.
pub const ACCOUNT_LABEL: &str = "Account";
/// The label the **never-committed** (in-flight) nodes carry. Not one of these may exist after
/// recovery — that is the committed-or-nothing contract, made falsifiable.
pub const PHANTOM_LABEL: &str = "Phantom";
/// The relationship type chaining a batch's accounts.
pub const TRANSFER_TYPE: &str = "TRANSFER";

/// How long a client waits on a socket read before giving up (the server is local; a long stall means
/// it is gone).
const READ_TIMEOUT: Duration = Duration::from_secs(20);

/// The workload's configuration.
#[derive(Debug, Clone)]
pub struct WorkloadConfig {
    /// The server's UDS path.
    pub socket: PathBuf,
    /// Login user / password.
    pub user: String,
    /// The login password.
    pub password: String,
    /// Target database (empty ⇒ the server's default).
    pub db: String,
    /// Concurrent committing writers.
    pub writers: usize,
    /// Accounts created per committed statement (each batch also chains `nodes-1` `:TRANSFER` edges).
    pub batch_nodes: usize,
    /// `:Phantom` nodes the in-flight writer creates inside its never-committed transaction.
    pub phantom_nodes: usize,
    /// The ready file is touched once the in-flight transaction is open **and** at least this many
    /// commits have been acknowledged — the signal that a crash now lands genuinely mid-workload.
    pub min_acked_before_ready: u64,
    /// A safety valve: if the server is never killed, stop after this long and report honestly.
    pub max_secs: u64,
    /// Where to touch the "ready to crash" marker.
    pub ready_file: PathBuf,
    /// Where to write the ledger the verifier consumes.
    pub ledger_file: PathBuf,
}

/// A committed batch's identity: `(writer, batch)`. Every account it created carries both as
/// properties, so the verifier can find exactly the rows a given acknowledged commit produced.
pub type BatchKey = (u64, u64);

/// The client-side ledger of what the server **acknowledged** before it died — the ground truth a
/// durability proof is asserted against.
#[derive(Debug, Clone, Default)]
pub struct Ledger {
    /// Batches whose commit the server acknowledged. These MUST all survive the crash.
    pub acked: Vec<BatchKey>,
    /// Batches whose statement was in flight when the socket died: the ack never arrived, so they may
    /// or may not have committed. Asserted only for **atomicity** (all-or-nothing), never for presence.
    pub undetermined: Vec<BatchKey>,
    /// Accounts per batch.
    pub batch_nodes: u64,
    /// `:Phantom` nodes written inside the never-committed transaction.
    pub phantom_nodes: u64,
    /// How many of them the open transaction could see **from inside itself** (proves the writes really
    /// landed in the transaction, so the post-crash absence is a real undo, not a no-op).
    pub phantom_visible_in_txn: u64,
    /// `true` iff the explicit transaction was still **open** (its last in-transaction statement had
    /// just succeeded) when the connection died — i.e. the kill was genuinely mid-transaction.
    pub phantom_txn_open_at_kill: bool,
    /// The error the in-flight transaction's connection died with (the kill, observed client-side).
    pub phantom_txn_error: String,
    /// Commits the server rejected (e.g. an SSI serialization conflict) — never counted as acked.
    pub failed_commits: u64,
    /// Per-commit wall-clock latencies, in milliseconds, of the ACKNOWLEDGED commits (measured).
    pub commit_latencies_ms: Vec<f64>,
    /// The workload window: from the first statement to the connection dying, in milliseconds.
    pub workload_millis: f64,
}

impl Ledger {
    /// Accounts the acknowledged commits created (the durability obligation).
    #[must_use]
    pub fn acked_nodes(&self) -> u64 {
        self.acked.len() as u64 * self.batch_nodes
    }

    /// `:TRANSFER` edges the acknowledged commits created.
    #[must_use]
    pub fn acked_rels(&self) -> u64 {
        self.acked.len() as u64 * self.batch_nodes.saturating_sub(1)
    }

    /// The `p`-th percentile (0..=100) of the measured commit latencies, in ms, by the standard
    /// **nearest-rank** method (NIST *Engineering Statistics Handbook* §1.3.5.6: the smallest value at
    /// or below which at least `p`% of the samples fall — `index = ceil(p/100 * n) - 1`, zero-based).
    /// No interpolation, so every reported figure is a value that was actually measured.
    ///
    /// `None` when nothing was measured — an unmeasured percentile is OMITTED, never reported as `0.0`
    /// (`rmp` #699: no fabricated latency fields).
    #[must_use]
    pub fn latency_percentile_ms(&self, p: f64) -> Option<f64> {
        if self.commit_latencies_ms.is_empty() {
            return None;
        }
        let mut v = self.commit_latencies_ms.clone();
        v.sort_by(f64::total_cmp);
        let n = v.len();
        let rank = ((p / 100.0) * n as f64).ceil().max(1.0) as usize;
        v.get(rank.min(n) - 1).copied()
    }

    /// Acknowledged commits per second over the measured workload window. `None` if nothing committed.
    #[must_use]
    pub fn acked_commits_per_sec(&self) -> Option<f64> {
        let secs = self.workload_millis / 1_000.0;
        if self.acked.is_empty() || secs <= 0.0 {
            return None;
        }
        Some(self.acked.len() as f64 / secs)
    }

    /// Renders the ledger to the simple `key=value` text the shell consumes and [`Ledger::parse`]
    /// reads back.
    #[must_use]
    pub fn render(&self) -> String {
        let mut s = String::new();
        let keys = |v: &[BatchKey]| {
            v.iter()
                .map(|(w, b)| format!("{w}:{b}"))
                .collect::<Vec<_>>()
                .join(",")
        };
        let _ = writeln!(s, "batch_nodes={}", self.batch_nodes);
        let _ = writeln!(s, "acked_batches={}", self.acked.len());
        let _ = writeln!(s, "acked_nodes={}", self.acked_nodes());
        let _ = writeln!(s, "acked_rels={}", self.acked_rels());
        let _ = writeln!(s, "acked_keys={}", keys(&self.acked));
        let _ = writeln!(s, "undetermined_batches={}", self.undetermined.len());
        let _ = writeln!(s, "undetermined_keys={}", keys(&self.undetermined));
        let _ = writeln!(s, "failed_commits={}", self.failed_commits);
        let _ = writeln!(s, "phantom_nodes={}", self.phantom_nodes);
        let _ = writeln!(s, "phantom_visible_in_txn={}", self.phantom_visible_in_txn);
        let _ = writeln!(
            s,
            "phantom_txn_open_at_kill={}",
            if self.phantom_txn_open_at_kill {
                "yes"
            } else {
                "no"
            }
        );
        let _ = writeln!(s, "phantom_txn_error={}", self.phantom_txn_error);
        let _ = writeln!(s, "workload_millis={:.3}", self.workload_millis);
        if let Some(p) = self.latency_percentile_ms(50.0) {
            let _ = writeln!(s, "commit_p50_ms={p:.3}");
        }
        if let Some(p) = self.latency_percentile_ms(99.0) {
            let _ = writeln!(s, "commit_p99_ms={p:.3}");
        }
        if let Some(p) = self.latency_percentile_ms(99.9) {
            let _ = writeln!(s, "commit_p999_ms={p:.3}");
        }
        if let Some(tps) = self.acked_commits_per_sec() {
            let _ = writeln!(s, "acked_commits_per_sec={tps:.3}");
        }
        s
    }

    /// Parses a rendered ledger back (the verifier's input).
    ///
    /// # Errors
    /// Returns an [`io::Error`] if the file cannot be read.
    pub fn parse(text: &str) -> Self {
        let mut l = Ledger::default();
        let parse_keys = |v: &str| -> Vec<BatchKey> {
            v.split(',')
                .filter(|s| !s.is_empty())
                .filter_map(|s| {
                    let (w, b) = s.split_once(':')?;
                    Some((w.parse().ok()?, b.parse().ok()?))
                })
                .collect()
        };
        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            match k {
                "batch_nodes" => l.batch_nodes = v.parse().unwrap_or(0),
                "acked_keys" => l.acked = parse_keys(v),
                "undetermined_keys" => l.undetermined = parse_keys(v),
                "failed_commits" => l.failed_commits = v.parse().unwrap_or(0),
                "phantom_nodes" => l.phantom_nodes = v.parse().unwrap_or(0),
                "phantom_visible_in_txn" => l.phantom_visible_in_txn = v.parse().unwrap_or(0),
                "phantom_txn_open_at_kill" => l.phantom_txn_open_at_kill = v == "yes",
                "phantom_txn_error" => l.phantom_txn_error = v.to_owned(),
                "workload_millis" => l.workload_millis = v.parse().unwrap_or(0.0),
                _ => {}
            }
        }
        l
    }

    /// Loads a ledger from disk.
    ///
    /// # Errors
    /// Propagates the read error.
    pub fn load(path: &Path) -> io::Result<Self> {
        Ok(Self::parse(&std::fs::read_to_string(path)?))
    }
}

/// The deterministic balance of the `seq`-th account of batch `(w, b)` — a content fingerprint the
/// verifier re-derives independently, so a recovered row must carry the exact value the commit wrote.
#[must_use]
pub fn expected_balance(w: u64, b: u64, seq: u64) -> i64 {
    (w * 1_000_000 + b * 1_000 + seq) as i64
}

/// The Cypher a committer runs as ONE auto-commit statement: `batch_nodes` accounts chained by
/// `:TRANSFER` edges. Parameterised on `$w`/`$b` so the plan cache is hit and the wire carries no
/// re-planned literal text per commit.
fn batch_statement(batch_nodes: usize) -> String {
    let mut q = String::from("CREATE ");
    for i in 1..=batch_nodes {
        if i > 1 {
            q.push_str(", ");
        }
        // `bal` mirrors `expected_balance` exactly; it is re-derived (not read back) by the verifier.
        let _ = write!(
            q,
            "(a{i}:{ACCOUNT_LABEL} {{writer: $w, batch: $b, seq: {i}, bal: $w * 1000000 + $b * 1000 + {i}}})"
        );
    }
    for i in 2..=batch_nodes {
        let _ = write!(
            q,
            ", (a{})-[:{TRANSFER_TYPE} {{amount: {i}}}]->(a{i})",
            i - 1
        );
    }
    q
}

/// What one committer thread reports back when its connection dies.
struct CommitterOutcome {
    acked: Vec<BatchKey>,
    undetermined: Option<BatchKey>,
    failed: u64,
    latencies_ms: Vec<f64>,
}

/// Runs the concurrent OLTP workload and blocks until the server dies under it (or `max_secs` elapses),
/// then returns the ledger of exactly what was acknowledged.
///
/// The caller (`run.sh`) waits for [`WorkloadConfig::ready_file`] — which appears only once the
/// in-flight transaction is open *and* commits are being acknowledged — and only then sends `SIGKILL`.
///
/// # Errors
/// Returns an [`io::Error`] if the ledger cannot be written, or if the workload never reached the
/// mid-workload state the crash must land in (a hard failure: it would silently degrade the proof).
pub fn run_workload(cfg: &WorkloadConfig) -> io::Result<Ledger> {
    let stop = Arc::new(AtomicBool::new(false));
    let acked_count = Arc::new(AtomicU64::new(0));
    let started = Instant::now();

    // ---- The in-flight writer: opens a transaction, writes into it, and NEVER commits. ------------
    let (phantom_tx, phantom_rx) = mpsc::channel::<PhantomOutcome>();
    let phantom_cfg = cfg.clone();
    let phantom_stop = Arc::clone(&stop);
    let phantom_open = Arc::new(AtomicBool::new(false));
    let phantom_open_flag = Arc::clone(&phantom_open);
    let phantom_thread = std::thread::spawn(move || {
        let outcome = hold_open_transaction(&phantom_cfg, &phantom_open_flag, &phantom_stop);
        let _ = phantom_tx.send(outcome);
    });

    // ---- The committers: auto-commit batches, in a loop, until the server dies. --------------------
    let mut handles = Vec::with_capacity(cfg.writers);
    for w in 1..=cfg.writers as u64 {
        let c = cfg.clone();
        let stop = Arc::clone(&stop);
        let acked_count = Arc::clone(&acked_count);
        handles.push(std::thread::spawn(move || {
            commit_loop(w, &c, &stop, &acked_count)
        }));
    }

    // ---- Signal "ready to crash" once the mid-workload state is genuinely reached. -----------------
    let deadline = Instant::now() + Duration::from_secs(cfg.max_secs);
    let mut announced = false;
    loop {
        let open = phantom_open.load(Ordering::Acquire);
        let acked = acked_count.load(Ordering::Acquire);
        if !announced && open && acked >= cfg.min_acked_before_ready {
            std::fs::write(
                &cfg.ready_file,
                format!("open_txn=yes acked={acked}\n").as_bytes(),
            )?;
            announced = true;
        }
        // Done when every committer has died (the server was killed) — or the safety valve fires.
        if handles.iter().all(std::thread::JoinHandle::is_finished) {
            break;
        }
        if Instant::now() >= deadline {
            stop.store(true, Ordering::Release);
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    let mut ledger = Ledger {
        batch_nodes: cfg.batch_nodes as u64,
        phantom_nodes: cfg.phantom_nodes as u64,
        ..Ledger::default()
    };
    for h in handles {
        if let Ok(o) = h.join() {
            ledger.acked.extend(o.acked);
            ledger.undetermined.extend(o.undetermined);
            ledger.failed_commits += o.failed;
            ledger.commit_latencies_ms.extend(o.latencies_ms);
        }
    }
    stop.store(true, Ordering::Release);
    let _ = phantom_thread.join();
    if let Ok(p) = phantom_rx.recv_timeout(Duration::from_secs(5)) {
        ledger.phantom_visible_in_txn = p.visible_in_txn;
        ledger.phantom_txn_open_at_kill = p.open_at_kill;
        ledger.phantom_txn_error = p.error;
    }
    ledger.acked.sort_unstable();
    ledger.undetermined.sort_unstable();
    ledger.workload_millis = started.elapsed().as_secs_f64() * 1_000.0;

    std::fs::write(&cfg.ledger_file, ledger.render().as_bytes())?;

    if !announced {
        return Err(io::Error::other(format!(
            "the workload never reached the mid-workload crash state (open in-flight txn + >= {} \
             acked commits): acked={} phantom_open={} — the crash would NOT have been mid-workload, \
             so the proof is refused rather than silently weakened",
            cfg.min_acked_before_ready,
            ledger.acked.len(),
            phantom_open.load(Ordering::Acquire),
        )));
    }
    Ok(ledger)
}

/// What the in-flight writer observed.
struct PhantomOutcome {
    visible_in_txn: u64,
    open_at_kill: bool,
    error: String,
}

/// Opens an explicit transaction, writes `:Phantom` nodes into it, proves they are visible from inside
/// it, and then holds it open — probing inside the transaction until the connection dies. It NEVER
/// sends `COMMIT`, so nothing it wrote may ever be observable after recovery.
fn hold_open_transaction(
    cfg: &WorkloadConfig,
    open_flag: &AtomicBool,
    stop: &AtomicBool,
) -> PhantomOutcome {
    let mut out = PhantomOutcome {
        visible_in_txn: 0,
        open_at_kill: false,
        error: String::new(),
    };
    let mut client = match connect(cfg) {
        Ok(c) => c,
        Err(e) => {
            out.error = format!("connect: {e}");
            return out;
        }
    };
    if let Err(e) = client.begin(&cfg.db) {
        out.error = format!("BEGIN: {e}");
        return out;
    }
    for seq in 1..=cfg.phantom_nodes as u64 {
        let q = format!(
            "CREATE (p:{PHANTOM_LABEL} {{seq: $seq, note: 'never committed — must not survive'}})"
        );
        if let Err(e) = client.run_in_txn(&q, vec![("seq".to_owned(), Value::Integer(seq as i64))])
        {
            out.error = format!("in-txn CREATE: {e}");
            return out;
        }
    }
    // The writes really landed *in* the transaction: read them back from inside it. If this returned 0,
    // the post-crash absence of :Phantom rows would prove nothing.
    match client.run_in_txn(
        &format!("MATCH (p:{PHANTOM_LABEL}) RETURN count(p) AS c"),
        vec![],
    ) {
        Ok(r) => out.visible_in_txn = r.first_scalar().unwrap_or(0).max(0) as u64,
        Err(e) => {
            out.error = format!("in-txn read-back: {e}");
            return out;
        }
    }
    if out.visible_in_txn != cfg.phantom_nodes as u64 {
        out.error = format!(
            "in-txn read-back saw {} of {} phantom rows",
            out.visible_in_txn, cfg.phantom_nodes
        );
        return out;
    }
    open_flag.store(true, Ordering::Release);

    // Hold the transaction OPEN. Each probe that succeeds re-proves the transaction is still open; the
    // first that fails is the server dying underneath it — with our transaction still open, uncommitted.
    loop {
        if stop.load(Ordering::Acquire) {
            out.error = "workload stopped before the server was killed".to_owned();
            out.open_at_kill = false;
            // Leave the transaction open and drop the connection: still never committed.
            return out;
        }
        match client.run_in_txn(
            &format!("MATCH (p:{PHANTOM_LABEL}) RETURN count(p) AS c"),
            vec![],
        ) {
            Ok(_) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => {
                // The connection died while the transaction was open and uncommitted — exactly the
                // in-flight state the crash must discard.
                out.open_at_kill = true;
                out.error = e.to_string();
                return out;
            }
        }
    }
}

/// One committer: auto-commit batches until the server dies (or `stop`).
fn commit_loop(
    w: u64,
    cfg: &WorkloadConfig,
    stop: &AtomicBool,
    acked_count: &AtomicU64,
) -> CommitterOutcome {
    let mut out = CommitterOutcome {
        acked: Vec::new(),
        undetermined: None,
        failed: 0,
        latencies_ms: Vec::new(),
    };
    let Ok(mut client) = connect(cfg) else {
        return out;
    };
    let stmt = batch_statement(cfg.batch_nodes);
    let mut batch = 0u64;
    while !stop.load(Ordering::Acquire) {
        batch += 1;
        let params = vec![
            ("w".to_owned(), Value::Integer(w as i64)),
            ("b".to_owned(), Value::Integer(batch as i64)),
        ];
        match client.run(&stmt, params, &cfg.db) {
            Ok(r) => {
                out.latencies_ms.push(r.elapsed.as_secs_f64() * 1_000.0);
                out.acked.push((w, batch));
                acked_count.fetch_add(1, Ordering::AcqRel);
            }
            // The socket died mid-statement: the ack never arrived, so this batch is UNDETERMINED —
            // it may or may not have committed. Recorded, never asserted either way.
            Err(ClientError::Io(_) | ClientError::Protocol(_)) => {
                out.undetermined = Some((w, batch));
                return out;
            }
            // The server answered — it just refused (e.g. an SSI serialization conflict). Not acked.
            Err(ClientError::Failure(_)) => {
                out.failed += 1;
            }
        }
    }
    out
}

/// Connects + logs in over the UDS.
fn connect(cfg: &WorkloadConfig) -> ClientResult<BoltClient> {
    let mut c = BoltClient::connect_uds(&cfg.socket, READ_TIMEOUT)?;
    c.login(&cfg.user, &cfg.password)?;
    Ok(c)
}

/// The post-restart verdict: what recovery actually produced, against the ledger of what was
/// acknowledged.
#[derive(Debug, Clone, Default)]
pub struct VerifyReport {
    /// `:Phantom` rows present after recovery. MUST be `0` (nothing from the open transaction survived).
    pub phantom_after_recovery: u64,
    /// Acknowledged batches that came back complete and correct (node count, edge count, every balance).
    pub acked_batches_intact: u64,
    /// Acknowledged batches expected.
    pub acked_batches_expected: u64,
    /// Accounts present after recovery, in total.
    pub accounts_present: u64,
    /// `:TRANSFER` edges present after recovery, in total.
    pub transfers_present: u64,
    /// Undetermined batches that DID commit (their ack was lost with the socket) — informational.
    pub undetermined_present: u64,
    /// Batches present in the recovered graph that appear in NEITHER the acked nor the undetermined
    /// ledger — a fabricated commit. MUST be `0`.
    pub batches_outside_ledger: Vec<BatchKey>,
    /// Batches present but INCOMPLETE (some but not all of their rows/edges) — an atomicity breach.
    /// MUST be empty, for acknowledged *and* undetermined batches alike.
    pub partial_batches: Vec<BatchKey>,
    /// Acknowledged batches that came back WRONG (a missing row, a wrong balance, a missing edge) — a
    /// durability breach. MUST be empty.
    pub corrupt_batches: Vec<(BatchKey, String)>,
}

impl VerifyReport {
    /// `true` iff every durability + atomicity obligation held.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.phantom_after_recovery == 0
            && self.acked_batches_intact == self.acked_batches_expected
            && self.batches_outside_ledger.is_empty()
            && self.partial_batches.is_empty()
            && self.corrupt_batches.is_empty()
    }

    /// Renders the machine-readable verdict the example's `run.sh` asserts on.
    #[must_use]
    pub fn render(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(
            s,
            "verify.phantom_after_recovery={}",
            self.phantom_after_recovery
        );
        let _ = writeln!(
            s,
            "verify.acked_batches_intact={}/{}",
            self.acked_batches_intact, self.acked_batches_expected
        );
        let _ = writeln!(s, "verify.accounts_present={}", self.accounts_present);
        let _ = writeln!(s, "verify.transfers_present={}", self.transfers_present);
        let _ = writeln!(
            s,
            "verify.undetermined_present={}",
            self.undetermined_present
        );
        let _ = writeln!(
            s,
            "verify.batches_outside_ledger={}",
            self.batches_outside_ledger.len()
        );
        let _ = writeln!(s, "verify.partial_batches={}", self.partial_batches.len());
        let _ = writeln!(s, "verify.corrupt_batches={}", self.corrupt_batches.len());
        for (k, why) in &self.corrupt_batches {
            let _ = writeln!(s, "verify.corrupt_detail={}:{} {}", k.0, k.1, why);
        }
        let _ = writeln!(
            s,
            "VERDICT: {}",
            if self.passed() { "DURABLE" } else { "VIOLATED" }
        );
        s
    }
}

/// Re-connects to the RESTARTED server and verifies the recovered graph against `ledger`.
///
/// # Errors
/// Propagates any client error (a failure to reach the recovered server is itself a failure).
pub fn verify(cfg: &WorkloadConfig, ledger: &Ledger) -> ClientResult<VerifyReport> {
    let mut c = connect(cfg)?;
    let mut r = VerifyReport {
        acked_batches_expected: ledger.acked.len() as u64,
        ..VerifyReport::default()
    };

    // 1. NO in-flight effect survived: the never-committed transaction left nothing behind.
    r.phantom_after_recovery = scalar(
        &mut c,
        &format!("MATCH (p:{PHANTOM_LABEL}) RETURN count(p) AS c"),
        vec![],
        &cfg.db,
    )?;

    // 2. Totals.
    r.accounts_present = scalar(
        &mut c,
        &format!("MATCH (a:{ACCOUNT_LABEL}) RETURN count(a) AS c"),
        vec![],
        &cfg.db,
    )?;
    r.transfers_present = scalar(
        &mut c,
        &format!("MATCH ()-[t:{TRANSFER_TYPE}]->() RETURN count(t) AS c"),
        vec![],
        &cfg.db,
    )?;

    // 3. Every ACKNOWLEDGED batch must be present, complete and correct: the right number of rows, the
    //    right number of edges, and every balance exactly as the commit wrote it.
    let acked: BTreeSet<BatchKey> = ledger.acked.iter().copied().collect();
    let undetermined: BTreeSet<BatchKey> = ledger.undetermined.iter().copied().collect();
    for &(w, b) in &acked {
        match check_batch(&mut c, cfg, w, b, ledger.batch_nodes)? {
            BatchState::Complete => r.acked_batches_intact += 1,
            BatchState::Absent => r.corrupt_batches.push((
                (w, b),
                "an ACKNOWLEDGED commit vanished across recovery".to_owned(),
            )),
            BatchState::Partial(why) => {
                r.partial_batches.push((w, b));
                r.corrupt_batches.push(((w, b), why));
            }
            BatchState::Wrong(why) => r.corrupt_batches.push(((w, b), why)),
        }
    }

    // 4. Every batch PRESENT in the recovered graph must be in the ledger, and must be whole. A batch
    //    nobody acknowledged and nobody had in flight is a fabricated commit; a half-applied batch is an
    //    atomicity breach — for an undetermined batch just as much as for an acknowledged one.
    let present = present_batches(&mut c, cfg)?;
    for (w, b) in present {
        if !acked.contains(&(w, b)) && !undetermined.contains(&(w, b)) {
            r.batches_outside_ledger.push((w, b));
            continue;
        }
        if undetermined.contains(&(w, b)) {
            r.undetermined_present += 1;
            match check_batch(&mut c, cfg, w, b, ledger.batch_nodes)? {
                BatchState::Complete => {}
                BatchState::Absent => {}
                BatchState::Partial(_) => r.partial_batches.push((w, b)),
                BatchState::Wrong(why) => r.corrupt_batches.push(((w, b), why)),
            }
        }
    }
    r.partial_batches.sort_unstable();
    r.partial_batches.dedup();
    Ok(r)
}

/// The state of one batch in the recovered graph.
enum BatchState {
    /// All rows, all edges, all balances correct.
    Complete,
    /// Not one row of it exists (a legitimate outcome only for an undetermined batch).
    Absent,
    /// Some — but not all — of its rows/edges exist: an atomicity breach.
    Partial(String),
    /// All rows exist but a value is wrong: a durability/content breach.
    Wrong(String),
}

fn check_batch(
    c: &mut BoltClient,
    cfg: &WorkloadConfig,
    w: u64,
    b: u64,
    batch_nodes: u64,
) -> ClientResult<BatchState> {
    let params = vec![
        ("w".to_owned(), Value::Integer(w as i64)),
        ("b".to_owned(), Value::Integer(b as i64)),
    ];
    let rows = c.run(
        &format!(
            "MATCH (a:{ACCOUNT_LABEL} {{writer: $w, batch: $b}}) RETURN a.seq AS seq, a.bal AS bal \
             ORDER BY a.seq"
        ),
        params.clone(),
        &cfg.db,
    )?;
    let n = rows.row_count() as u64;
    if n == 0 {
        return Ok(BatchState::Absent);
    }
    if n != batch_nodes {
        return Ok(BatchState::Partial(format!(
            "{n} of {batch_nodes} account rows present — a half-applied transaction"
        )));
    }
    for (i, row) in rows.records.iter().enumerate() {
        let seq = match row.first() {
            Some(Value::Integer(s)) => *s,
            other => {
                return Ok(BatchState::Wrong(format!(
                    "row {i}: seq is not an integer ({other:?})"
                )));
            }
        };
        let bal = match row.get(1) {
            Some(Value::Integer(v)) => *v,
            other => {
                return Ok(BatchState::Wrong(format!(
                    "row {i}: bal is not an integer ({other:?})"
                )));
            }
        };
        let want = expected_balance(w, b, seq as u64);
        if bal != want {
            return Ok(BatchState::Wrong(format!(
                "seq {seq}: bal {bal} != {want} — a recovered property value is wrong"
            )));
        }
    }
    let edges = c.run(
        &format!(
            "MATCH (:{ACCOUNT_LABEL} {{writer: $w, batch: $b}})-[t:{TRANSFER_TYPE}]->\
             (:{ACCOUNT_LABEL} {{writer: $w, batch: $b}}) RETURN count(t) AS c"
        ),
        params,
        &cfg.db,
    )?;
    let want_edges = batch_nodes.saturating_sub(1) as i64;
    let got_edges = edges.first_scalar().unwrap_or(-1);
    if got_edges != want_edges {
        return Ok(BatchState::Partial(format!(
            "{got_edges} of {want_edges} :{TRANSFER_TYPE} edges present — a half-applied transaction"
        )));
    }
    Ok(BatchState::Complete)
}

/// Every `(writer, batch)` pair present in the recovered graph.
fn present_batches(c: &mut BoltClient, cfg: &WorkloadConfig) -> ClientResult<Vec<BatchKey>> {
    let r = c.run(
        &format!(
            "MATCH (a:{ACCOUNT_LABEL}) RETURN DISTINCT a.writer AS w, a.batch AS b ORDER BY w, b"
        ),
        vec![],
        &cfg.db,
    )?;
    Ok(r.records
        .iter()
        .filter_map(|row| match (row.first(), row.get(1)) {
            (Some(Value::Integer(w)), Some(Value::Integer(b))) => Some((*w as u64, *b as u64)),
            _ => None,
        })
        .collect())
}

/// Runs a scalar `count(...)` query.
fn scalar(
    c: &mut BoltClient,
    q: &str,
    params: Vec<(String, Value)>,
    db: &str,
) -> ClientResult<u64> {
    Ok(c.run(q, params, db)?.first_scalar().unwrap_or(0).max(0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_batch_statement_creates_the_nodes_and_chains_them() {
        let q = batch_statement(5);
        assert_eq!(q.matches(":Account").count(), 5, "5 accounts per batch");
        assert_eq!(q.matches(":TRANSFER").count(), 4, "chained by n-1 edges");
        assert!(
            q.contains("$w") && q.contains("$b"),
            "parameterised, not literal-inlined"
        );
    }

    #[test]
    fn expected_balance_is_a_unique_content_fingerprint() {
        // Distinct (writer, batch, seq) triples must not collide, or a wrong recovered row could pass.
        let mut seen = BTreeSet::new();
        for w in 1..=8u64 {
            for b in 1..=200u64 {
                for s in 1..=10u64 {
                    assert!(
                        seen.insert(expected_balance(w, b, s)),
                        "collision at {w}/{b}/{s}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_ledger_round_trips_through_its_text_form() {
        let l = Ledger {
            acked: vec![(1, 1), (1, 2), (2, 1)],
            undetermined: vec![(3, 7)],
            batch_nodes: 5,
            phantom_nodes: 4,
            phantom_visible_in_txn: 4,
            phantom_txn_open_at_kill: true,
            phantom_txn_error: "I/O error: broken pipe".to_owned(),
            failed_commits: 2,
            commit_latencies_ms: vec![1.0, 2.0, 3.0, 4.0],
            workload_millis: 500.0,
        };
        let back = Ledger::parse(&l.render());
        assert_eq!(back.acked, l.acked);
        assert_eq!(back.undetermined, l.undetermined);
        assert_eq!(back.batch_nodes, 5);
        assert_eq!(back.acked_nodes(), 15);
        assert_eq!(back.acked_rels(), 12);
        assert!(back.phantom_txn_open_at_kill);
        assert_eq!(back.phantom_visible_in_txn, 4);
    }

    /// Latency percentiles are MEASURED or ABSENT — never a fabricated `0.0` (`rmp` #699).
    #[test]
    fn latency_percentiles_are_absent_when_nothing_was_measured() {
        let empty = Ledger::default();
        assert!(empty.latency_percentile_ms(50.0).is_none());
        assert!(empty.acked_commits_per_sec().is_none());
        assert!(!empty.render().contains("commit_p50_ms"));

        let l = Ledger {
            commit_latencies_ms: vec![10.0, 20.0, 30.0, 40.0],
            acked: vec![(1, 1), (1, 2)],
            workload_millis: 1_000.0,
            ..Ledger::default()
        };
        // Nearest-rank (NIST §1.3.5.6): p50 of 4 samples -> index ceil(0.5*4)-1 = 1 -> 20 ms.
        assert_eq!(l.latency_percentile_ms(50.0), Some(20.0));
        assert_eq!(l.latency_percentile_ms(99.0), Some(40.0));
        assert_eq!(l.latency_percentile_ms(100.0), Some(40.0));
        // Every reported percentile is a value that was actually measured (no interpolation).
        for p in [50.0, 99.0, 99.9] {
            let got = l.latency_percentile_ms(p).expect("measured");
            assert!(
                l.commit_latencies_ms.contains(&got),
                "p{p} must be a measured sample"
            );
        }
        assert_eq!(l.acked_commits_per_sec(), Some(2.0));
    }

    /// The verdict has TEETH: each obligation, broken on its own, must flip the verdict to VIOLATED.
    #[test]
    fn the_verify_verdict_catches_every_class_of_violation() {
        let base = VerifyReport {
            acked_batches_expected: 10,
            acked_batches_intact: 10,
            ..VerifyReport::default()
        };
        assert!(base.passed(), "the clean report must pass");

        let mut phantom = base.clone();
        phantom.phantom_after_recovery = 1; // an in-flight effect survived
        assert!(!phantom.passed());
        assert!(phantom.render().contains("VERDICT: VIOLATED"));

        let mut lost = base.clone();
        lost.acked_batches_intact = 9; // an acknowledged commit was lost
        assert!(!lost.passed());

        let mut fabricated = base.clone();
        fabricated.batches_outside_ledger.push((9, 9)); // a commit nobody made
        assert!(!fabricated.passed());

        let mut partial = base.clone();
        partial.partial_batches.push((1, 1)); // a half-applied transaction
        assert!(!partial.passed());

        let mut wrong = base.clone();
        wrong.corrupt_batches.push(((1, 1), "bal wrong".to_owned())); // a wrong recovered value
        assert!(!wrong.passed());
    }
}
