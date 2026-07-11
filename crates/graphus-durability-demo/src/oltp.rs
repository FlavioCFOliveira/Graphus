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
//! # The crash window is DETERMINISTIC, not hoped for (`rmp` #712)
//!
//! The strongest claim this example makes — *a writer was inside an open, never-committed transaction
//! at the `SIGKILL`* — used to be reported by a **racy** observation, so it was only *sometimes* true
//! in the ledger even though it was *always* true on the server. Three defects, all fixed here:
//!
//! 1. **The shutdown race.** `run_workload` set the `stop` flag as soon as the committers died (the
//!    server was gone), while the in-flight writer was still asleep between two probes. It woke, saw
//!    `stop`, and wound down *without ever observing its own connection die* — so it reported
//!    `open_at_kill = false`. The transaction WAS open; the ledger simply failed to witness it. Now
//!    `stop` is the **safety valve only**: when the committers report the server DIED
//!    ([`server_died`](CrashFacts::server_died)), the driver does not stop the in-flight writer — it
//!    **joins** it and lets it observe the dead socket itself, which is guaranteed (a `SIGKILL`ed peer
//!    makes the very next probe fail) and bounded (one probe interval).
//! 2. **The false positive.** *Any* error used to be booked as "the connection died with my
//!    transaction open". A [`ClientError::Failure`] is the opposite: the server ANSWERED and refused,
//!    so the transaction is no longer open. It is now classified as such, and it FAILS the run instead
//!    of passing it vacuously.
//! 3. **A hope, not a fact.** The driver now REFUSES (a hard error) to emit a ledger in which the
//!    server died but no writer attested an open transaction at the kill — see [`crash_window_verdict`].
//!    A weakened proof is never silently published.
//!
//! While it holds, the in-flight writer refreshes a **hold beacon** ([`WorkloadConfig::hold_file`])
//! after every successful in-transaction probe. `run.sh` reads it immediately before the `SIGKILL`, so
//! the kill is sequenced *behind* a fresh, positive proof that the transaction is still being held —
//! and the server's own `graphus_active_transactions` gauge corroborates it from the other side.
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
    /// Where the in-flight writer refreshes its **hold beacon** after every successful
    /// in-transaction probe (`rmp` #712): `probes=<n>` written atomically (tmp + rename), so the
    /// caller can read a torn-free, *fresh* proof that the never-committed transaction is still being
    /// held at the instant it decides to `SIGKILL`. Empty ⇒ no beacon is written.
    pub hold_file: PathBuf,
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
    /// How many in-transaction probes the in-flight writer completed while HOLDING the transaction
    /// open (`rmp` #712). Each one is a round-trip the server answered from inside the never-committed
    /// transaction, so a non-zero count is positive evidence that the transaction was alive and held
    /// right up to the kill — not merely that a `BEGIN` was once sent.
    pub phantom_hold_probes: u64,
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
        let _ = writeln!(s, "phantom_hold_probes={}", self.phantom_hold_probes);
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
                "phantom_hold_probes" => l.phantom_hold_probes = v.parse().unwrap_or(0),
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

/// How long the driver will wait, after the committers report the server DEAD, for the in-flight
/// writer to observe its own connection die. A `SIGKILL`ed peer makes the very next probe fail
/// immediately, so this is one probe interval in practice; the bound exists so a pathological stall
/// becomes a loud failure instead of a silent `open_at_kill = false`.
const PHANTOM_DEATH_GRACE: Duration = Duration::from_secs(30);

/// How long the in-flight writer sleeps between two in-transaction probes. It bounds how stale the
/// hold beacon can be when `run.sh` reads it immediately before the `SIGKILL`, and how long the
/// writer takes to notice the dead socket afterwards.
const HOLD_PROBE_INTERVAL: Duration = Duration::from_millis(10);

/// The facts about the crash window, as the driver's own threads observed them. They decide whether a
/// ledger may be published at all ([`crash_window_verdict`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrashFacts {
    /// The mid-workload state was reached and announced (open transaction + enough acked commits), so
    /// the caller was cleared to `SIGKILL`.
    pub announced: bool,
    /// At least one committer's connection died mid-statement — i.e. the server really was killed
    /// under the workload (as opposed to the safety valve firing on a server that never died).
    pub server_died: bool,
    /// The in-flight writer's connection died while its transaction was still OPEN and never
    /// committed — the fact the example's strongest assertion rests on.
    pub open_at_kill: bool,
    /// In-transaction probes the in-flight writer completed while holding. `0` would mean it never
    /// actually held the transaction across a single round-trip.
    pub hold_probes: u64,
}

/// Decides whether the observed [`CrashFacts`] constitute the proof the example claims — or whether the
/// run must be REFUSED (`rmp` #712).
///
/// This is the honesty gate that used to be missing. The kill window used to be raced: when the server
/// died, the driver could wind the in-flight writer down before it noticed its own dead socket, and the
/// ledger then said `open_at_kill=no` for a transaction that had in fact been open the whole time. The
/// example's headline assertion therefore only *sometimes* held — a durability example that only
/// sometimes injects the crash it claims to inject is worthless as a regression instrument.
///
/// It is a pure function so the race is pinned by unit tests instead of by luck.
///
/// # Errors
/// Returns the reason the run is not a valid proof.
pub fn crash_window_verdict(facts: CrashFacts) -> Result<(), String> {
    if !facts.announced {
        return Err(
            "the workload never reached the mid-workload crash state (an open, never-committed \
             transaction + acknowledged commits), so a crash could not have landed mid-workload"
                .to_owned(),
        );
    }
    if !facts.server_died {
        return Err(
            "the safety valve fired: no committer's connection ever died, so the server was NEVER \
             killed under the workload — there is no crash to recover from"
                .to_owned(),
        );
    }
    if facts.hold_probes == 0 {
        return Err(
            "the in-flight writer never completed a single in-transaction probe, so it cannot \
             attest that it HELD its transaction open up to the kill"
                .to_owned(),
        );
    }
    if !facts.open_at_kill {
        return Err(
            "the server was killed, but no writer attested an OPEN, never-committed transaction at \
             the kill: the strongest half of the committed-or-nothing contract (no in-flight effect \
             may survive) would be VACUOUS. The proof is refused rather than silently weakened"
                .to_owned(),
        );
    }
    Ok(())
}

/// Runs the concurrent OLTP workload and blocks until the server dies under it (or `max_secs` elapses),
/// then returns the ledger of exactly what was acknowledged.
///
/// The caller (`run.sh`) waits for [`WorkloadConfig::ready_file`], re-checks the fresh hold beacon
/// ([`WorkloadConfig::hold_file`]) — positive proof the never-committed transaction is *still* being
/// held — and only then sends `SIGKILL`.
///
/// # Errors
/// Returns an [`io::Error`] if the ledger cannot be written, or if the observed [`CrashFacts`] do not
/// constitute the proof the example claims (see [`crash_window_verdict`]): a weakened proof is refused,
/// never silently published.
pub fn run_workload(cfg: &WorkloadConfig) -> io::Result<Ledger> {
    let stop = Arc::new(AtomicBool::new(false));
    let acked_count = Arc::new(AtomicU64::new(0));
    // Set by the first committer whose connection dies mid-statement: the server really was killed.
    // It is what tells the driver NOT to wind the in-flight writer down, but to let it witness the
    // dead socket itself — the fix for the race that made `open_at_kill` intermittent (`rmp` #712).
    let server_died = Arc::new(AtomicBool::new(false));
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
        let died = Arc::clone(&server_died);
        handles.push(std::thread::spawn(move || {
            commit_loop(w, &c, &stop, &acked_count, &died)
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
            // The SAFETY VALVE, and the ONLY thing that may set `stop`. It means the server was never
            // killed; the run is not a proof and `crash_window_verdict` will refuse it below.
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

    // The in-flight writer is NOT told to stop when the server died: its connection is already dead,
    // so its very next probe fails and it records — as a first-hand fact — that its transaction was
    // still open at the kill. Setting `stop` here (as the code used to) raced that observation and
    // silently downgraded the ledger to `open_at_kill=no` for a transaction that never closed.
    //
    // On the safety-valve path `stop` is already set, and the writer winds down reporting honestly
    // that no kill was ever observed.
    let died = server_died.load(Ordering::Acquire);
    let phantom = phantom_rx.recv_timeout(if died {
        PHANTOM_DEATH_GRACE
    } else {
        Duration::from_secs(5)
    });
    if let Ok(p) = phantom {
        ledger.phantom_visible_in_txn = p.visible_in_txn;
        ledger.phantom_txn_open_at_kill = p.open_at_kill;
        ledger.phantom_hold_probes = p.held_probes;
        ledger.phantom_txn_error = p.error;
    } else {
        ledger.phantom_txn_error =
            "the in-flight writer never reported back (it neither observed the kill nor stopped)"
                .to_owned();
    }
    // Now that its outcome is in, release the writer unconditionally (it has already returned on
    // every path that gets here; this only guarantees the thread is not left parked).
    stop.store(true, Ordering::Release);
    let _ = phantom_thread.join();

    ledger.acked.sort_unstable();
    ledger.undetermined.sort_unstable();
    ledger.workload_millis = started.elapsed().as_secs_f64() * 1_000.0;

    // The ledger is written even when the run is refused: it is the evidence of WHY it was refused.
    std::fs::write(&cfg.ledger_file, ledger.render().as_bytes())?;

    let facts = CrashFacts {
        announced,
        server_died: died,
        open_at_kill: ledger.phantom_txn_open_at_kill,
        hold_probes: ledger.phantom_hold_probes,
    };
    if let Err(why) = crash_window_verdict(facts) {
        return Err(io::Error::other(format!(
            "{why} — facts: acked={} undetermined={} hold_probes={} open_at_kill={} \
             server_died={} last_error={:?}",
            ledger.acked.len(),
            ledger.undetermined.len(),
            ledger.phantom_hold_probes,
            ledger.phantom_txn_open_at_kill,
            died,
            ledger.phantom_txn_error,
        )));
    }
    Ok(ledger)
}

/// What the in-flight writer observed.
struct PhantomOutcome {
    visible_in_txn: u64,
    open_at_kill: bool,
    held_probes: u64,
    error: String,
}

/// How one in-transaction probe ended, and what that says about the transaction (`rmp` #712).
///
/// The distinction the old code missed: a [`ClientError::Failure`] is the server ANSWERING — it
/// refused the statement, so the transaction is **no longer open**. Booking it (as any error used to
/// be booked) as "my connection died with my transaction open" is a FALSE POSITIVE that would let the
/// example's strongest assertion pass on a transaction the server had already rolled back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeOutcome {
    /// The server answered from inside the transaction: it is still open, still uncommitted.
    StillOpen,
    /// The connection died (I/O / protocol): the server was killed with the transaction OPEN.
    ConnectionDied,
    /// The server answered and REFUSED: the transaction is no longer open (it was rolled back).
    ServerRefused,
}

/// Classifies an in-transaction probe's result. Pure, so the false positive is pinned by a unit test.
fn classify_probe<T>(result: &Result<T, ClientError>) -> ProbeOutcome {
    match result {
        Ok(_) => ProbeOutcome::StillOpen,
        Err(ClientError::Io(_) | ClientError::Protocol(_)) => ProbeOutcome::ConnectionDied,
        Err(ClientError::Failure(_)) => ProbeOutcome::ServerRefused,
    }
}

/// Opens an explicit transaction, writes `:Phantom` nodes into it, proves they are visible from inside
/// it, and then holds it open — probing inside the transaction until the connection dies. It NEVER
/// sends `COMMIT` (there is no commit call on this path at all), so nothing it wrote may ever be
/// observable after recovery.
///
/// After every successful probe it refreshes the **hold beacon** ([`WorkloadConfig::hold_file`]), so
/// the caller can sequence its `SIGKILL` behind a fresh, positive proof that the transaction is still
/// being held right now — rather than behind a stale "it was open a moment ago" (`rmp` #712).
fn hold_open_transaction(
    cfg: &WorkloadConfig,
    open_flag: &AtomicBool,
    stop: &AtomicBool,
) -> PhantomOutcome {
    let mut out = PhantomOutcome {
        visible_in_txn: 0,
        open_at_kill: false,
        held_probes: 0,
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

    // Hold the transaction OPEN. Each probe the server answers re-proves it is still open (and
    // refreshes the beacon); the first that fails with a dead socket IS the kill, observed first-hand,
    // with our transaction still open and never committed.
    //
    // `stop` is the safety valve ONLY — it is set when the server was never killed at all. It is
    // deliberately NOT set on the kill path any more: doing so used to race this loop and wind the
    // writer down before it could witness the death, which is precisely how the example's strongest
    // assertion became intermittent (`rmp` #712).
    loop {
        if stop.load(Ordering::Acquire) {
            out.error =
                "the workload stopped before the server was killed (safety valve; no crash landed)"
                    .to_owned();
            out.open_at_kill = false;
            // Leave the transaction open and drop the connection: still never committed.
            return out;
        }
        let probe = client.run_in_txn(
            &format!("MATCH (p:{PHANTOM_LABEL}) RETURN count(p) AS c"),
            vec![],
        );
        match classify_probe(&probe) {
            ProbeOutcome::StillOpen => {
                out.held_probes += 1;
                write_hold_beacon(&cfg.hold_file, out.held_probes);
                std::thread::sleep(HOLD_PROBE_INTERVAL);
            }
            ProbeOutcome::ConnectionDied => {
                // The connection died while the transaction was open and uncommitted — exactly the
                // in-flight state the crash must discard. THIS is the fact the ledger records.
                out.open_at_kill = true;
                out.error = probe.err().map_or_else(String::new, |e| e.to_string());
                return out;
            }
            ProbeOutcome::ServerRefused => {
                // The server ANSWERED and refused: the transaction is no longer open, so the kill
                // (whenever it lands) will NOT find it in flight. Never booked as an open transaction.
                out.open_at_kill = false;
                out.error = format!(
                    "the server REFUSED an in-transaction probe, so the transaction was rolled back \
                     before the kill: {}",
                    probe.err().map_or_else(String::new, |e| e.to_string())
                );
                return out;
            }
        }
    }
}

/// Refreshes the hold beacon atomically (write to a sibling temp file, then `rename`), so a reader can
/// never observe a torn or empty beacon. A beacon that cannot be written is not fatal to the workload
/// — the caller's pre-kill check will simply fail loudly instead of silently proceeding.
fn write_hold_beacon(path: &Path, probes: u64) {
    if path.as_os_str().is_empty() {
        return;
    }
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, format!("probes={probes}\n").as_bytes()).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// One committer: auto-commit batches until the server dies (or `stop`). A connection that dies
/// mid-statement raises `server_died` — the signal that the crash really landed under the workload.
fn commit_loop(
    w: u64,
    cfg: &WorkloadConfig,
    stop: &AtomicBool,
    acked_count: &AtomicU64,
    server_died: &AtomicBool,
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
            // it may or may not have committed. Recorded, never asserted either way. It is also the
            // first-hand evidence that the SERVER DIED, which is what keeps the driver from winding
            // the in-flight writer down before it can witness the same death (`rmp` #712).
            Err(ClientError::Io(_) | ClientError::Protocol(_)) => {
                out.undetermined = Some((w, batch));
                server_died.store(true, Ordering::Release);
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
            phantom_hold_probes: 37,
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
        assert_eq!(
            back.phantom_hold_probes, 37,
            "the ledger must carry HOW MANY in-transaction probes the writer held across — a \
             non-zero count is what makes 'the transaction was open at the kill' a fact"
        );
    }

    /// **Regression (`rmp` #712), defect 2a — the FALSE POSITIVE.**
    ///
    /// The hold loop used to treat *every* error as "my connection died with my transaction open". A
    /// [`ClientError::Failure`] is the server ANSWERING and refusing: the transaction is rolled back
    /// and is no longer open. Booking it as an open transaction would let the example's strongest
    /// assertion ("a writer really was inside an OPEN, never-committed transaction at SIGKILL") pass
    /// over a transaction the server had already discarded — a green tick over a vacuous proof.
    #[test]
    fn a_server_refusal_is_not_a_connection_death() {
        let refused: Result<(), ClientError> =
            Err(ClientError::Failure(graphus_bolt::Failure::new(
                "Neo.TransientError.Transaction.Outdated",
                "serialization conflict",
            )));
        assert_eq!(
            classify_probe(&refused),
            ProbeOutcome::ServerRefused,
            "the server answered and refused: the transaction is NOT open any more"
        );

        let died: Result<(), ClientError> = Err(ClientError::Io(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "connection reset by peer",
        )));
        assert_eq!(
            classify_probe(&died),
            ProbeOutcome::ConnectionDied,
            "a dead socket IS the kill, observed from inside the open transaction"
        );

        let protocol: Result<(), ClientError> =
            Err(ClientError::Protocol("truncated message".to_owned()));
        assert_eq!(classify_probe(&protocol), ProbeOutcome::ConnectionDied);

        assert_eq!(classify_probe(&Ok(())), ProbeOutcome::StillOpen);
    }

    /// **Regression (`rmp` #712), defect 2b — the SHUTDOWN RACE, and the gate that now catches it.**
    ///
    /// The driver used to publish a ledger saying `open_at_kill=no` whenever the in-flight writer lost
    /// the race to the `stop` flag — the exact intermittent failure this task exists to kill. The facts
    /// are now run through [`crash_window_verdict`], which REFUSES the run instead of publishing a
    /// proof whose strongest half is vacuous.
    #[test]
    fn the_verdict_refuses_every_way_the_crash_window_can_be_vacuous() {
        let good = CrashFacts {
            announced: true,
            server_died: true,
            open_at_kill: true,
            hold_probes: 12,
        };
        assert!(
            crash_window_verdict(good).is_ok(),
            "a real mid-workload kill, witnessed from inside the open transaction, is the proof"
        );

        // THE RACE: the server died, the writer held its transaction — but it was wound down before it
        // could witness the death, so it reported `open_at_kill = false`. This is what used to be
        // published as a passing run's ledger (and then failed the run.sh assertion, flakily).
        let raced = CrashFacts {
            open_at_kill: false,
            ..good
        };
        let err = crash_window_verdict(raced).expect_err("a vacuous crash window must be REFUSED");
        assert!(err.contains("VACUOUS"), "unexpected reason: {err}");

        // The safety valve fired: the server was never killed at all.
        let never_killed = CrashFacts {
            server_died: false,
            open_at_kill: false,
            ..good
        };
        assert!(crash_window_verdict(never_killed).is_err());

        // The writer never held the transaction across a single round-trip.
        let never_held = CrashFacts {
            hold_probes: 0,
            ..good
        };
        assert!(crash_window_verdict(never_held).is_err());

        // The mid-workload state was never announced, so the caller was never cleared to kill.
        let never_ready = CrashFacts {
            announced: false,
            ..good
        };
        assert!(crash_window_verdict(never_ready).is_err());
    }

    /// The hold beacon must be readable and FRESH — `run.sh` sequences its `SIGKILL` behind it, so a
    /// torn or empty read would either abort a good run or (worse) wave a bad one through. It is
    /// written atomically (temp + rename) and always parses.
    #[test]
    fn the_hold_beacon_is_written_atomically_and_advances() {
        let dir = std::env::temp_dir().join(format!("gdur-beacon-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let beacon = dir.join("hold");

        for n in 1..=5u64 {
            write_hold_beacon(&beacon, n);
            let text =
                std::fs::read_to_string(&beacon).expect("the beacon must always be readable");
            assert_eq!(text.trim(), format!("probes={n}"));
        }
        // No temp file is left behind for a reader to trip over.
        assert!(!beacon.with_extension("tmp").exists());

        // An empty path is a no-op, never a panic (the beacon is optional).
        write_hold_beacon(Path::new(""), 1);
        std::fs::remove_dir_all(&dir).ok();
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
