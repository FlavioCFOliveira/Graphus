//! The **deterministic writer scheduler** (`rmp` #973): the policy behind
//! [`graphus_core::sched`]'s seam.
//!
//! # What it does
//!
//! It owns a single **execution token**. Exactly one registered thread runs at a time; at every yield
//! point the running thread hands the token back and this scheduler draws the next runnable thread
//! from a seeded [`SimRng`]. The global order of operations across N real writer threads therefore
//! becomes a pure function of the seed, which is what lets the DST reproduce a concurrency defect the
//! way it already reproduces a crash.
//!
//! # Why the policy lives here and not in `graphus-core`
//!
//! It needs [`SimRng`], which lives in `graphus-sim`, which depends on `graphus-core`. The split
//! mirrors [`graphus_core::capability`]: the traits sit in the core crate that every layer can reach,
//! the deterministic implementation sits outside it.
//!
//! # The determinism rules, and where each is enforced
//!
//! | Rule | Enforced by |
//! |---|---|
//! | No address ever enters a decision or the history | [`graphus_core::sched::ResourceId`] is a frame index / page id newtype with no pointer constructor |
//! | No [`std::thread::ThreadId`] | ids are minted by [`DetScheduler::register`] in registration order |
//! | Ordered runnable set | [`BTreeSet`], never a `HashSet` |
//! | No wall clock on a scheduled path | every draw comes from [`SimRng`]; the only clock reads are the stall/hang backstops, which influence no decision and fire only on a wedged run |
//! | Ids assigned by the parent, before the child runs | [`graphus_core::sched::spawn`] calls [`register`](DetScheduler::register) while holding the token |
//!
//! # Amortisation: seeded sampling, never a counter
//!
//! `with_page_fetched` is the hottest read in the engine, so a hand-off at every visit would mean
//! tens of millions of context switches. Each yield point therefore draws once from the RNG and
//! switches only with probability `switch_permille / 1000`. This stays deterministic precisely
//! *because* the token serialises the draws into one global stream. A counter keyed on **time**
//! ("switch every 100 µs") would not — which is why there is none.
//!
//! # Deadlock is a finding, not a hang
//!
//! A thread that cannot take a contended resource parks on it ([`park_on`](DetScheduler::park_on))
//! and the token moves on; a release reopens the set. If the runnable set empties while threads are
//! parked, that is a **deadlock**, reported with the history rather than left to hang. A run whose
//! token holder wedges inside a lock the scheduler does not mediate is caught by the stall backstop
//! in [`wait_for_token`](DetScheduler::wait_for_token) and, as a last resort, by the watchdog.

use graphus_core::capability::Rng;
use graphus_core::sched::{
    HISTORY_RECORD_LEN, LogicalThreadId, ResourceId, Scheduler, Step, YieldSite,
};
use graphus_sim::SimRng;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use crate::vopr::Fnv;

/// How the scheduler behaves for one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetSchedConfig {
    /// The seed the whole interleaving is a function of.
    pub seed: u64,
    /// Probability, in parts per thousand, that a yield point actually hands the token over.
    ///
    /// `1000` switches at every single yield point — the most aggressive exploration, and the right
    /// setting for a scenario whose window is a handful of record reads wide. Lower values amortise
    /// the hand-off cost over a long run.
    pub switch_permille: u32,
    /// Hard bound on recorded steps. Exceeding it fails the run with the history rather than letting
    /// a livelock spin forever.
    pub max_steps: u64,
    /// Whether to materialise the byte-exact history (the determinism gate needs it; a long soak may
    /// not). The digest is maintained either way.
    pub record_history: bool,
    /// How long a thread may wait for the token with **no global progress at all** before the run is
    /// declared wedged. Off the decision path: it influences no schedule, only the verdict on a run
    /// that has already stopped making progress.
    pub stall_timeout: Duration,
}

impl DetSchedConfig {
    /// A configuration that switches at **every** yield point — the setting a narrow-window scenario
    /// wants.
    #[must_use]
    pub fn exhaustive(seed: u64) -> Self {
        Self {
            seed,
            switch_permille: 1000,
            ..Self::new(seed)
        }
    }

    /// The default configuration for `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            switch_permille: 250,
            max_steps: 2_000_000,
            record_history: true,
            stall_timeout: Duration::from_secs(30),
        }
    }
}

/// Everything the scheduler mutates, behind one mutex.
#[derive(Debug)]
struct State {
    rng: SimRng,
    /// The thread currently holding the execution token. `None` only between a hand-off with an empty
    /// runnable set and the release that refills it.
    current: Option<LogicalThreadId>,
    /// Every live, non-parked thread — **including** the token holder, because a thread may draw
    /// itself as the next one to run. A `BTreeSet`, never a `HashSet`: the iteration order is an
    /// input to the RNG-indexed choice, so it must be total and stable.
    runnable: BTreeSet<LogicalThreadId>,
    /// Parked threads and the resource each is waiting on.
    blocked: BTreeMap<LogicalThreadId, ResourceId>,
    /// Threads whose body has ended, so a `join` on them does not park.
    finished: BTreeSet<LogicalThreadId>,
    names: BTreeMap<LogicalThreadId, String>,
    next_id: u32,
    seq: u64,
    switches: u64,
    threads_seen: BTreeSet<LogicalThreadId>,
    history: Vec<u8>,
    digest: Fnv,
    /// Set once the run is unrecoverable (deadlock / budget / stall). Every waiter panics with it, so
    /// a wedged run fails loudly on the test thread instead of hanging.
    fault: Option<String>,
}

/// State the watchdog shares with the scheduler without touching its mutex.
#[derive(Debug)]
struct Beacon {
    /// The step counter, mirrored so the watchdog can observe progress lock-free.
    progress: AtomicU64,
    stop: AtomicBool,
}

/// A seeded, cooperative scheduler that serialises every registered thread through one execution
/// token.
#[derive(Debug)]
pub struct DetScheduler {
    cfg: DetSchedConfig,
    state: Mutex<State>,
    cv: Condvar,
    beacon: Arc<Beacon>,
    watchdog: Mutex<Option<std::thread::JoinHandle<()>>>,
}

/// What a finished run recorded — the object the determinism gate compares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedHistory {
    /// The seed the run replays from.
    pub seed: u64,
    /// Fixed-width little-endian records, [`HISTORY_RECORD_LEN`] bytes each. Compared with `==`,
    /// byte for byte — there is nothing to parse and nothing to normalise.
    pub bytes: Vec<u8>,
    /// FNV-1a digest of the same records (maintained even when `record_history` is off).
    pub hash: u64,
    /// Total recorded steps.
    pub steps: u64,
    /// Steps at which the token actually moved to a different thread. The **non-vacuity** number: a
    /// run in which only one thread ever ran produces a perfectly deterministic and perfectly
    /// useless history.
    pub switches: u64,
    /// Distinct logical threads that appear in the history.
    pub threads: usize,
}

impl SchedHistory {
    /// The decoded steps, for diagnosis. The gate itself compares [`bytes`](Self::bytes).
    #[must_use]
    pub fn decode(&self) -> Vec<(u64, u32, u16, u8, u64)> {
        self.bytes
            .chunks_exact(HISTORY_RECORD_LEN)
            .map(|r| {
                (
                    u64::from_le_bytes(r[0..8].try_into().expect("8 bytes")),
                    u32::from_le_bytes(r[8..12].try_into().expect("4 bytes")),
                    u16::from_le_bytes(r[12..14].try_into().expect("2 bytes")),
                    r[14],
                    u64::from_le_bytes(r[16..24].try_into().expect("8 bytes")),
                )
            })
            .collect()
    }

    /// How many steps carry `site`. Used by the non-vacuity controls to prove a specific yield point
    /// was really reached.
    #[must_use]
    pub fn count_site(&self, site: YieldSite) -> usize {
        self.decode()
            .iter()
            .filter(|(_, _, s, _, _)| *s == site.code())
            .count()
    }
}

impl DetScheduler {
    /// Creates a scheduler for `cfg` and starts its watchdog.
    #[must_use]
    pub fn new(cfg: DetSchedConfig) -> Arc<Self> {
        let beacon = Arc::new(Beacon {
            progress: AtomicU64::new(0),
            stop: AtomicBool::new(false),
        });
        let sched = Arc::new(Self {
            cfg,
            state: Mutex::new(State {
                rng: SimRng::new(cfg.seed),
                current: None,
                runnable: BTreeSet::new(),
                blocked: BTreeMap::new(),
                finished: BTreeSet::new(),
                names: BTreeMap::new(),
                next_id: 0,
                seq: 0,
                switches: 0,
                threads_seen: BTreeSet::new(),
                history: Vec::new(),
                digest: Fnv::new(),
                fault: None,
            }),
            cv: Condvar::new(),
            beacon: Arc::clone(&beacon),
            watchdog: Mutex::new(None),
        });
        // Last-resort backstop for the one freeze the in-condvar stall check cannot see: EVERY
        // scheduled thread wedged inside a lock the scheduler does not mediate, so nobody is waiting
        // on the condvar to notice. It holds no reference to the scheduler (only to the beacon), so
        // there is no reference cycle keeping either alive.
        let hang_after = cfg.stall_timeout.saturating_mul(10);
        let handle = std::thread::Builder::new()
            .name("det-sched-watchdog".to_owned())
            .spawn(move || {
                // The watchdog is deliberately outside the simulation: it must never be scheduled,
                // and it must never panic-on-unregistered if it ever reaches a yield point.
                graphus_core::sched::exempt();
                let tick = Duration::from_millis(250);
                let mut last = 0u64;
                let mut still = Duration::ZERO;
                while !beacon.stop.load(Ordering::Relaxed) {
                    std::thread::sleep(tick);
                    let now = beacon.progress.load(Ordering::Relaxed);
                    if now == last {
                        still = still.saturating_add(tick);
                    } else {
                        last = now;
                        still = Duration::ZERO;
                    }
                    if still >= hang_after && now > 0 {
                        eprintln!(
                            "det-sched WATCHDOG: no scheduling progress for {still:?} at step \
                             {now}. Every scheduled thread is wedged inside a lock the scheduler \
                             does not mediate, so no thread is left to report it. Aborting with \
                             this diagnostic rather than hanging the run without one."
                        );
                        std::process::abort();
                    }
                }
            })
            .expect("det-sched: failed to spawn the watchdog thread");
        *unpoison(sched.watchdog.lock()) = Some(handle);
        sched
    }

    /// The run's history so far.
    #[must_use]
    pub fn history(&self) -> SchedHistory {
        let st = self.lock();
        SchedHistory {
            seed: self.cfg.seed,
            bytes: st.history.clone(),
            hash: st.digest.peek(),
            steps: st.seq,
            switches: st.switches,
            threads: st.threads_seen.len(),
        }
    }

    /// The fault that wedged the run, if any (a deadlock, an exhausted step budget, a stall).
    #[must_use]
    pub fn fault(&self) -> Option<String> {
        self.lock().fault.clone()
    }

    /// Stops the watchdog and joins it. Idempotent, and safe to call while other `Arc`s to this
    /// scheduler are still alive — which is exactly the case it exists for (see [`run_scheduled`]).
    pub fn retire_watchdog(&self) {
        self.beacon.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = unpoison(self.watchdog.lock()).take() {
            let _ = handle.join();
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        unpoison(self.state.lock())
    }

    /// Draws the next thread to run from the runnable set. `None` when nothing is runnable.
    ///
    /// The **only** RNG-consuming choice in the scheduler besides the switch coin, so the stream is a
    /// pure function of the sequence of yields and parks.
    fn pick_next(st: &mut State) -> Option<LogicalThreadId> {
        let n = st.runnable.len();
        if n == 0 {
            return None;
        }
        let k = (st.rng.next_u64() % n as u64) as usize;
        st.runnable.iter().nth(k).copied()
    }

    /// Appends one step to the history and the digest.
    fn record(
        &self,
        st: &mut State,
        thread: LogicalThreadId,
        site: YieldSite,
        resource: ResourceId,
        switched: u8,
    ) {
        let step = Step {
            seq: st.seq,
            thread,
            site,
            resource,
            switched,
        };
        let mut rec = Vec::with_capacity(HISTORY_RECORD_LEN);
        step.encode(&mut rec);
        debug_assert_eq!(rec.len(), HISTORY_RECORD_LEN);
        st.digest.bytes(&rec);
        if self.cfg.record_history {
            st.history.extend_from_slice(&rec);
        }
        st.seq += 1;
        st.switches += u64::from(switched);
        st.threads_seen.insert(thread);
        self.beacon.progress.store(st.seq, Ordering::Relaxed);
        if st.seq > self.cfg.max_steps && st.fault.is_none() {
            st.fault = Some(format!(
                "det-sched: step budget of {} exhausted (seed {}). The run is not converging: a \
                 thread is spinning through yield points without making progress. {}",
                self.cfg.max_steps,
                self.cfg.seed,
                Self::describe(st)
            ));
        }
    }

    /// A one-line dump of who is where, for every fault message.
    fn describe(st: &State) -> String {
        let name = |t: &LogicalThreadId| -> String {
            format!("{}#{}", st.names.get(t).map_or("<?>", String::as_str), t.0)
        };
        let runnable: Vec<String> = st.runnable.iter().map(name).collect();
        let blocked: Vec<String> = st
            .blocked
            .iter()
            .map(|(t, r)| format!("{} on {:?}", name(t), r))
            .collect();
        format!(
            "step={} switches={} current={:?} runnable=[{}] blocked=[{}]",
            st.seq,
            st.switches,
            st.current.as_ref().map(name),
            runnable.join(", "),
            blocked.join(", ")
        )
    }

    /// Blocks until `id` holds the token, or the run faults.
    ///
    /// The stall backstop lives here: if a whole window passes with **no step recorded anywhere** and
    /// the runnable set is empty while threads are parked, the run is deadlocked; if it merely stops
    /// advancing for `stall_timeout`, the token holder is wedged in a lock the scheduler does not
    /// mediate. Both are reported with the history. Neither reading influences any schedule — the
    /// clock is consulted only to decide that an already-stopped run has stopped.
    fn wait_for_token<'a>(
        &'a self,
        mut st: MutexGuard<'a, State>,
        id: LogicalThreadId,
    ) -> MutexGuard<'a, State> {
        let window = Duration::from_millis(100);
        let mut stalled = Duration::ZERO;
        loop {
            if let Some(fault) = st.fault.clone() {
                drop(st);
                panic!("{fault}");
            }
            if st.current == Some(id) {
                return st;
            }
            let before = st.seq;
            let (guard, timeout) = unpoison(self.cv.wait_timeout(st, window));
            st = guard;
            if !timeout.timed_out() || st.seq != before {
                stalled = Duration::ZERO;
                continue;
            }
            stalled = stalled.saturating_add(window);
            // A deadlock is reported sooner than a stall, but never on the first window: an exempt
            // thread (a reader-pool worker, the WAL fsync offload) legitimately holds a mediated
            // resource for a short while and its release reopens the set with no history impact.
            if st.runnable.is_empty() && !st.blocked.is_empty() && stalled >= window * 5 {
                st.fault = Some(format!(
                    "det-sched: DEADLOCK (seed {}). Every thread is parked and none can run. {}",
                    self.cfg.seed,
                    Self::describe(&st)
                ));
            } else if stalled >= self.cfg.stall_timeout {
                st.fault = Some(format!(
                    "det-sched: STALLED for {:?} (seed {}). The token holder is blocked inside a \
                     lock the scheduler does not mediate — a yield point was placed inside a \
                     latched region, or an unscheduled thread holds a resource a scheduled thread \
                     needs. {}",
                    stalled,
                    self.cfg.seed,
                    Self::describe(&st)
                ));
            }
        }
    }

    /// Moves every thread parked on `resource` back into the runnable set.
    fn wake(st: &mut State, resource: Option<ResourceId>) {
        let woken: Vec<LogicalThreadId> = st
            .blocked
            .iter()
            .filter(|(_, r)| resource.is_none_or(|want| **r == want))
            .map(|(t, _)| *t)
            .collect();
        for t in woken {
            st.blocked.remove(&t);
            st.runnable.insert(t);
        }
    }

    /// Recovers the token when a release finds nobody running.
    ///
    /// Deliberately **does not draw from the RNG**: this path is reachable only from a release issued
    /// by an exempt (unscheduled) thread, whose timing is not deterministic, so letting it consume
    /// the stream would make the stream depend on an uncontrolled thread. The lowest runnable id is a
    /// total, stable choice that costs the stream nothing.
    fn resume_if_idle(st: &mut State) {
        if st.current.is_none() {
            st.current = st.runnable.iter().next().copied();
        }
    }

    /// Panics if the run has faulted, releasing the guard first so the message is not truncated by a
    /// poisoned-lock panic.
    fn trip(st: &State) {
        if let Some(fault) = &st.fault {
            panic!("{fault}");
        }
    }
}

impl Drop for DetScheduler {
    fn drop(&mut self) {
        self.retire_watchdog();
    }
}

impl Scheduler for DetScheduler {
    fn register(&self, name: &str) -> LogicalThreadId {
        let mut st = self.lock();
        let id = LogicalThreadId(st.next_id);
        st.next_id += 1;
        st.names.insert(id, name.to_owned());
        st.runnable.insert(id);
        // The very first registration (the root, from `install`) takes the token, so the installing
        // thread continues to run without waiting for a hand-off that nobody could make.
        if st.current.is_none() {
            st.current = Some(id);
        }
        id
    }

    fn thread_entry(&self, id: LogicalThreadId) {
        let st = self.lock();
        // The scheduler may have chosen this child before the OS actually started it; that costs a
        // real wait and changes no state, so determinism is untouched.
        let mut st = self.wait_for_token(st, id);
        self.record(
            &mut st,
            id,
            YieldSite::ThreadStart,
            ResourceId::thread(id),
            0,
        );
        Self::trip(&st);
    }

    fn thread_exit(&self, id: LogicalThreadId) {
        let mut st = self.lock();
        st.runnable.remove(&id);
        st.finished.insert(id);
        // A joiner parked on this thread becomes runnable again the instant the body ends.
        Self::wake(&mut st, Some(ResourceId::thread(id)));
        self.record(
            &mut st,
            id,
            YieldSite::ThreadExit,
            ResourceId::thread(id),
            1,
        );
        st.current = Self::pick_next(&mut st);
        self.cv.notify_all();
        // Deliberately no `trip` here: this runs inside a `Drop` on the exiting thread, possibly
        // already unwinding, where a second panic would abort the process. The fault is reported by
        // whichever thread next waits for the token.
    }

    fn yield_at(&self, id: LogicalThreadId, site: YieldSite, resource: ResourceId) {
        let mut st = self.lock();
        debug_assert_eq!(
            st.current,
            Some(id),
            "det-sched: {id:?} yielded at {site:?} without holding the execution token"
        );
        let mut switched = 0u8;
        // ONE draw decides whether to switch at all — the seeded sampling that makes a yield point on
        // the engine's hottest read affordable. A SECOND draw picks the successor, and only when the
        // first said yes, so the stream stays a pure function of the decisions actually taken.
        let coin = st.rng.next_u64() % 1000;
        if coin < u64::from(self.cfg.switch_permille) {
            if let Some(next) = Self::pick_next(&mut st) {
                if next != id {
                    st.current = Some(next);
                    switched = 1;
                }
            }
        }
        self.record(&mut st, id, site, resource, switched);
        if switched == 1 {
            self.cv.notify_all();
            st = self.wait_for_token(st, id);
        }
        Self::trip(&st);
    }

    fn observe(&self, id: LogicalThreadId, site: YieldSite, resource: ResourceId) {
        let mut st = self.lock();
        debug_assert_eq!(
            st.current,
            Some(id),
            "det-sched: {id:?} recorded {site:?} without holding the execution token"
        );
        // No coin is drawn: a suppressed hand-off must not consume the RNG stream, or the schedule
        // would depend on how often the engine happens to pass through a no-switch region.
        self.record(&mut st, id, site, resource, 0);
        Self::trip(&st);
    }

    fn park_on(&self, id: LogicalThreadId, site: YieldSite, resource: ResourceId) {
        let mut st = self.lock();
        st.runnable.remove(&id);
        st.blocked.insert(id, resource);
        self.record(&mut st, id, site, resource, 1);
        st.current = Self::pick_next(&mut st);
        self.cv.notify_all();
        let st = self.wait_for_token(st, id);
        Self::trip(&st);
    }

    fn release(&self, id: Option<LogicalThreadId>, site: YieldSite, resource: ResourceId) {
        let mut st = self.lock();
        Self::wake(&mut st, Some(resource));
        // An exempt caller records NOTHING: an uncontrolled thread must never inject a step at a
        // nondeterministic position in the history.
        if let Some(id) = id {
            self.record(&mut st, id, site, resource, 0);
        }
        Self::resume_if_idle(&mut st);
        self.cv.notify_all();
    }

    fn release_all(&self, id: Option<LogicalThreadId>, site: YieldSite) {
        let mut st = self.lock();
        Self::wake(&mut st, None);
        if let Some(id) = id {
            self.record(&mut st, id, site, ResourceId::NONE, 0);
        }
        Self::resume_if_idle(&mut st);
        self.cv.notify_all();
    }

    /// # A wake-up is not a promise that the child has exited (`rmp` #1086)
    ///
    /// This re-checks `finished` in a **loop** rather than returning the first time it gets the token
    /// back, because [`release_all`](Self::release_all) reopens the WHOLE blocked set — a superset
    /// wake-up, and deliberately so: a batch flush latches and releases many frames at once, and a
    /// missed wake-up would be a lost one. The safety argument for that superset is written on
    /// `FlushBatch`: "a thread woken for a resource still held retries and re-parks". Every waiter
    /// parked on a frame does exactly that. This one did **not** — it took the token, returned, and
    /// handed `JoinHandle::join` a child that was still running, so the joiner blocked in `std`'s join
    /// **holding the token** and no other thread could ever run again. The run then died on the stall
    /// backstop with `blocked=[]` and nothing to point at, which is the least useful shape a
    /// deterministic failure can take.
    ///
    /// It made every scenario in which a batch flush overlaps a `join` unschedulable — which is why
    /// `RecordStore::checkpoint` had never been driven under this scheduler, and so why the redo-floor
    /// defect of `rmp` #1086 could sit behind a green suite. Retrying here restores the invariant the
    /// superset wake-up already claimed, for this waiter and for any future one.
    fn join_child(&self, id: LogicalThreadId, child: LogicalThreadId) {
        let mut st = self.lock();
        loop {
            if st.finished.contains(&child) {
                // Already gone: parking would wait for a release that has already happened, and the
                // scheduler would report that lost wake-up as a deadlock.
                self.record(
                    &mut st,
                    id,
                    YieldSite::ThreadJoin,
                    ResourceId::thread(child),
                    0,
                );
                Self::trip(&st);
                return;
            }
            st.runnable.remove(&id);
            st.blocked.insert(id, ResourceId::thread(child));
            self.record(
                &mut st,
                id,
                YieldSite::ThreadJoin,
                ResourceId::thread(child),
                1,
            );
            st.current = Self::pick_next(&mut st);
            self.cv.notify_all();
            st = self.wait_for_token(st, id);
            Self::trip(&st);
        }
    }

    fn history_hash(&self) -> u64 {
        self.lock().digest.peek()
    }
}

/// A poisoned scheduler lock must not wedge the process: the protected state is scheduling
/// bookkeeping, and a panicking scheduled thread is already failing its test.
fn unpoison<G>(r: std::result::Result<G, std::sync::PoisonError<G>>) -> G {
    r.unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Installs a scheduler for `cfg`, runs `body` on the calling thread as the root logical thread, and
/// returns what the run recorded.
///
/// The scheduler is uninstalled before this returns, on every path including an unwind out of `body`.
///
/// # Panics
/// Propagates a panic from `body` after uninstalling, and panics if the run deadlocks, stalls, or
/// exhausts its step budget.
pub fn run_scheduled<T>(cfg: DetSchedConfig, body: impl FnOnce() -> T) -> (T, SchedHistory) {
    let sched = DetScheduler::new(cfg);
    // Retires the watchdog when this run ends, on every path INCLUDING an unwind out of `body`.
    //
    // Without it, a `body` that panics while a child thread is still parked leaks that child, the
    // child's `Arc` keeps the scheduler (and its watchdog) alive past the end of the run, and the
    // watchdog would later abort the whole test binary over a run that had already reported a
    // perfectly clear failure — replacing a readable assertion message with an abort.
    let _retire = WatchdogRetirement(Arc::clone(&sched));
    let out = {
        let _installed =
            graphus_core::sched::install(Arc::clone(&sched) as Arc<dyn Scheduler>, "root");
        body()
    };
    let history = sched.history();
    if let Some(fault) = sched.fault() {
        panic!("{fault}");
    }
    (out, history)
}

/// Retires a scheduler's watchdog when the run it belongs to ends. See [`run_scheduled`].
struct WatchdogRetirement(Arc<DetScheduler>);

impl Drop for WatchdogRetirement {
    fn drop(&mut self) {
        self.0.retire_watchdog();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    /// The mechanism's own unit test: N threads hammering a shared counter must interleave, produce a
    /// byte-identical history for one seed, and different histories for different seeds.
    ///
    /// This proves the SCHEDULER. It deliberately does **not** stand in for acceptance criteria 1 and
    /// 2, which are asserted over the real two-thread engine scenario in
    /// `tests/det_scheduler_gc_reader_811.rs` — a synthetic self-test passing while the engine was
    /// never scheduled is exactly the vacuity this project has caught before.
    fn counter_run(seed: u64) -> SchedHistory {
        let cfg = DetSchedConfig::exhaustive(seed);
        let (_, history) = run_scheduled(cfg, || {
            let shared = Arc::new(AtomicU32::new(0));
            let mut handles = Vec::new();
            for t in 0..3u32 {
                let shared = Arc::clone(&shared);
                handles.push(graphus_core::sched::spawn(
                    &format!("worker-{t}"),
                    move || {
                        for _ in 0..20 {
                            graphus_core::sched::yield_at(
                                YieldSite::CommitRegistryRecord,
                                ResourceId::txn(u64::from(t)),
                            );
                            shared.fetch_add(1, Ordering::Relaxed);
                        }
                    },
                ));
            }
            for h in handles {
                h.join().expect("worker joined");
            }
            shared.load(Ordering::Relaxed)
        });
        history
    }

    #[test]
    fn same_seed_replays_byte_identically() {
        let a = counter_run(0xD37_5CED);
        let b = counter_run(0xD37_5CED);
        assert_eq!(a.bytes, b.bytes, "the same seed must replay byte for byte");
        assert_eq!(a.hash, b.hash);
        assert!(a.switches > 0, "the run never switched threads");
        assert!(
            a.threads >= 4,
            "root + 3 workers must appear in the history"
        );
    }

    #[test]
    fn different_seeds_explore_different_interleavings() {
        let seeds: [u64; 8] = [1, 2, 3, 5, 8, 13, 21, 34];
        let mut hashes: Vec<u64> = seeds.iter().map(|s| counter_run(*s).hash).collect();
        hashes.sort_unstable();
        hashes.dedup();
        assert_eq!(
            hashes.len(),
            seeds.len(),
            "different seeds collapsed onto the same interleaving"
        );
    }

    #[test]
    fn history_records_are_fixed_width() {
        let h = counter_run(7);
        assert_eq!(h.bytes.len() % HISTORY_RECORD_LEN, 0);
        assert_eq!(h.bytes.len() / HISTORY_RECORD_LEN, h.steps as usize);
    }

    /// A park that nobody can release is a **finding**, reported with the history — never a hang.
    #[test]
    #[should_panic(expected = "DEADLOCK")]
    fn an_unreleasable_park_is_reported_as_a_deadlock() {
        let mut cfg = DetSchedConfig::exhaustive(99);
        cfg.stall_timeout = Duration::from_secs(5);
        let _ = run_scheduled(cfg, || {
            // Nothing will ever release this resource, and the root is the only live thread.
            graphus_core::sched::acquire(
                YieldSite::FrameReadFetched,
                ResourceId::frame(0),
                || None::<()>,
                || (),
            );
        });
    }
}
