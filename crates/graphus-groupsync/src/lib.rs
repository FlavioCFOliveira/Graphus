#![forbid(unsafe_code)]
//! **Group staging** for the doublewrite buffer (`rmp` #994): one durability barrier amortised over
//! many concurrent evictors, instead of one barrier per evicted page.
//!
//! # Why this exists
//!
//! `rmp` #993 took the staging `fdatasync` out of the DWB device mutex, so evictors staging into
//! disjoint ring slots stopped serialising. What it did *not* change is that each evictor still
//! issued **its own** barrier. Measured on a 16-core host with a working set twice the buffer pool:
//! at 16 readers each eviction paid a 2.85 ms staging barrier plus a 2.68 ms home barrier — about
//! 12.6 threads permanently inside `fsync`. The ceiling stopped being contention and became
//! **fsync bandwidth**, at 8.8 % of the throughput measured with the doublewrite detached entirely.
//!
//! A barrier is not scoped to a region: one `fdatasync` on the DWB file makes durable *everything*
//! written to it beforehand. So K evictors that have already written their slots can share a single
//! barrier. That is what this module does.
//!
//! # The protocol (PostgreSQL's, read from the source)
//!
//! This is `XLogFlush`'s group-commit protocol, adapted. The shape comes from
//! `src/backend/access/transam/xlog.c` and `src/backend/storage/lmgr/lwlock.c` in the PostgreSQL
//! tree, whose `LWLockAcquireOrWait` documents the intent exactly:
//!
//! > when a backend flushes the WAL, holding WALWriteLock, it can flush the commit records of many
//! > other backends as a side-effect. Those other backends need to wait until the flush finishes,
//! > but don't need to acquire the lock anymore. **They can just wake up, observe that their records
//! > have already been flushed, and return.**
//!
//! Three details were taken deliberately, and one deliberately not:
//!
//! * **Recheck after waking, never assume.** PostgreSQL rechecks its flush watermark at three
//!   points: on entry, after waiting for the lock, and again after acquiring it. Here the single
//!   `while` loop in [`StagingBarrier::wait_durable`] is that recheck, and it is the only thing
//!   standing between a follower and silent data loss (see the correctness argument below).
//! * **The leader snapshots its target *before* the barrier**, exactly as PostgreSQL computes
//!   `insertpos` before `XLogWrite`. Publishing anything later would claim durability for writes
//!   that may have landed *during* the barrier.
//! * **The leader propagates its own error**, and a failed round advances nothing — so a follower
//!   whose bytes are still not durable simply becomes the next leader.
//! * **No artificial delay.** PostgreSQL has one (`commit_delay`, plus `commit_siblings` to gate
//!   it), which sleeps *after* taking the write lock to let more followers join the batch. It
//!   defaults to **0** — verified in `guc_tables.c`/`postgresql.conf.sample` — i.e. off. The
//!   batching that matters comes from the protocol itself: while the leader is inside a multi-
//!   millisecond `fdatasync`, every evictor that arrives naturally queues behind it. Adding a sleep
//!   trades latency for throughput and is a tuning knob, not part of the mechanism, so it is left
//!   out until measurement asks for it.
//!
//! # Correctness: why a ticket, and why the recheck is load-bearing
//!
//! The dangerous mistake is for a follower to wake up and *assume* the leader's barrier covered it.
//! If the leader started its `fdatasync` **before** the follower's `pwrite`s completed, it did not —
//! and the follower would then write its page home believing it has a durable doublewrite copy that
//! does not exist. A crash at that moment loses the copy and leaves a torn home page unrepairable.
//! Silent data loss, on a path whose entire purpose is to prevent exactly that.
//!
//! The ticket makes the two cases distinguishable:
//!
//! 1. Every evictor takes a ticket from a monotonic counter **after** its `pwrite`s have returned
//!    ([`StagingBarrier::ticket`], called while the DWB device mutex is still held).
//! 2. A leader, before starting its barrier, snapshots `target` = the counter's current value.
//! 3. On success it publishes `durable = max(durable, target)` — and nothing more.
//! 4. A caller is satisfied **only** when `durable >= its ticket`.
//!
//! If `ticket <= target` then this evictor's `fetch_add` precedes the leader's `load` in the
//! counter's modification order; the `fetch_add` happens after its `pwrite`s returned; therefore its
//! bytes were in the page cache before the barrier started, and an `fsync` flushes everything dirty
//! at the time it runs. Conversely a ticket **above** the snapshot is *not* claimed — that evictor
//! loops and drives its own barrier. The `while` loop is what implements "conversely".
//!
//! The protocol is `loom`-model-checked end to end (the `loom_model` module below), including an
//! oracle independent of the ticket arithmetic itself. This crate is a **leaf** — `graphus-core`
//! only — precisely so that model check is possible; see `Cargo.toml` for why.

use graphus_core::error::{GraphusError, Result};

mod sync;

use crate::sync::{AtomicU64, Condvar, Mutex, MutexGuard, Ordering};

/// Bound on how many barrier rounds one caller will drive before giving up.
///
/// Under a working device a caller needs at most two: one round it may have missed (its ticket
/// arrived after the in-flight leader's snapshot) and one it leads itself. The bound exists so a
/// persistently failing device surfaces an error instead of spinning; exhausting it is always
/// reported as an error, never as success.
const MAX_BARRIER_ROUNDS: usize = 64;

/// The mutable half of the barrier, behind one short-lived mutex.
///
/// The mutex is **never** held across the barrier itself — the leader releases it before syncing and
/// re-takes it afterwards — so followers can queue up while a barrier is in flight. That is what
/// makes the batching happen at all.
#[derive(Debug, Default)]
struct BarrierState {
    /// Every ticket `<= durable` is on stable storage. Monotonically non-decreasing.
    durable: u64,
    /// A leader is inside the barrier right now.
    flushing: bool,
    /// Barrier rounds that failed, for diagnostics.
    failed_rounds: u64,
}

/// Coordinates the doublewrite staging barrier across concurrent evictors.
pub struct StagingBarrier {
    /// Tickets issued so far. Incremented once per completed set of staging writes.
    issued: AtomicU64,
    state: Mutex<BarrierState>,
    ready: Condvar,
    /// Barriers actually issued, and callers satisfied without issuing one — the pair that shows
    /// the amortisation is happening (diagnostics; cheap enough to keep unconditionally).
    barriers: AtomicU64,
    piggybacked: AtomicU64,
}

impl std::fmt::Debug for StagingBarrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagingBarrier")
            .field("issued", &self.issued.load(Ordering::Relaxed))
            .field("barriers", &self.barriers.load(Ordering::Relaxed))
            .field("piggybacked", &self.piggybacked.load(Ordering::Relaxed))
            .finish()
    }
}

impl StagingBarrier {
    /// A fresh barrier with nothing issued and nothing durable.
    pub fn new() -> Self {
        Self {
            issued: AtomicU64::new(0),
            state: Mutex::new(BarrierState::default()),
            ready: Condvar::new(),
            barriers: AtomicU64::new(0),
            piggybacked: AtomicU64::new(0),
        }
    }

    /// Takes a ticket covering the staging writes this caller has **just completed**.
    ///
    /// # Contract
    /// MUST be called after the caller's `pwrite`s have returned — in practice, while the DWB device
    /// mutex is still held, immediately after the writes. Taking a ticket *before* the writes
    /// complete would break the ordering argument in the module docs and admit exactly the silent
    /// data loss the ticket exists to prevent.
    pub fn ticket(&self) -> u64 {
        // `AcqRel`: the release half publishes our page writes to any thread that later observes
        // this ticket value; the acquire half orders us after every earlier ticket.
        self.issued.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Blocks until the staging writes covered by `ticket` are durable, driving a barrier itself if
    /// no leader is doing so.
    ///
    /// Returns `Ok(())` **only** when `durable >= ticket`. There is no other success path: a caller
    /// can never conclude without its own bytes on stable storage.
    ///
    /// `barrier` performs the actual durability barrier. It is called with **no** lock of this
    /// module held (and, by the caller's contract, with the DWB device mutex released), so it may
    /// take milliseconds without blocking anyone else's arrival.
    ///
    /// Returns whether this caller **led** a barrier round. `false` means it rode on one another
    /// caller was already issuing — the amortisation this protocol exists for. Callers use it only
    /// for diagnostics; correctness never depends on it.
    ///
    /// # Errors
    /// Propagates the barrier's own failure when this caller is the leader that observed it, or
    /// reports failure to converge within [`MAX_BARRIER_ROUNDS`].
    pub fn wait_durable(&self, ticket: u64, barrier: &dyn Fn() -> Result<()>) -> Result<bool> {
        let mut state = self.lock();
        let mut led = false;
        for _ in 0..MAX_BARRIER_ROUNDS {
            // THE RECHECK. Every path back to the top of this loop re-evaluates it: after waking
            // from the condvar, and after leading a round. A follower that skipped this and simply
            // returned on wake would be claiming durability the leader never promised it — see the
            // module docs.
            if state.durable >= ticket {
                if !led {
                    self.piggybacked.fetch_add(1, Ordering::Relaxed);
                }
                return Ok(led);
            }
            if state.flushing {
                // A leader is inside the barrier. Wait for it to finish, then recheck: it may or may
                // not have covered us, and only the recheck can tell.
                state = self.wait(state);
                continue;
            }
            // Become the leader for this round.
            //
            // Snapshot the target BEFORE the barrier: every ticket issued up to here belongs to
            // writes that have already completed, so a successful barrier makes exactly those
            // durable. A ticket issued after this load may land during the barrier and is
            // deliberately NOT claimed.
            let target = self.issued.load(Ordering::Acquire);
            debug_assert!(
                target >= ticket,
                "our own ticket must have been issued before we read the counter"
            );
            state.flushing = true;
            drop(state);

            led = true;
            self.barriers.fetch_add(1, Ordering::Relaxed);
            let outcome = barrier();

            state = self.lock();
            state.flushing = false;
            match outcome {
                Ok(()) => {
                    // Monotonic: a concurrent round may already have published more.
                    if target > state.durable {
                        state.durable = target;
                    }
                    self.ready.notify_all();
                }
                Err(e) => {
                    // A failed round advances nothing, so every waiter re-evaluates and one of them
                    // becomes the next leader. We propagate: we are the caller that observed it.
                    state.failed_rounds += 1;
                    self.ready.notify_all();
                    return Err(e);
                }
            }
        }
        Err(GraphusError::Storage(format!(
            "doublewrite staging barrier did not make ticket {ticket} durable within \
             {MAX_BARRIER_ROUNDS} rounds ({} rounds failed); the page was NOT written home",
            self.lock().failed_rounds
        )))
    }

    /// Barriers issued and callers that rode on someone else's — the amortisation ratio.
    pub fn counters(&self) -> (u64, u64) {
        (
            self.barriers.load(Ordering::Relaxed),
            self.piggybacked.load(Ordering::Relaxed),
        )
    }

    /// The highest ticket known durable (tests and diagnostics).
    pub fn durable(&self) -> u64 {
        self.lock().durable
    }

    fn lock(&self) -> MutexGuard<'_, BarrierState> {
        // A poisoned barrier must not wedge every later eviction: the protected state is two
        // counters and a flag, and every durability decision is re-derived from them under the lock,
        // so recovering the guard is safe (mirrors the buffer pool's `unwrap_lock`).
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn wait<'a>(&self, guard: MutexGuard<'a, BarrierState>) -> MutexGuard<'a, BarrierState> {
        self.ready
            .wait(guard)
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Default for StagingBarrier {
    fn default() -> Self {
        Self::new()
    }
}

/// `loom` model of the group-staging protocol (`rmp` #994).
///
/// Compiled **only** under `--cfg loom`, so a normal `cargo test` never sees it. Run it with:
///
/// ```text
/// RUSTFLAGS="--cfg loom" cargo test -p graphus-storage --lib dwb_barrier --release
/// ```
///
/// # What is modelled, and why the oracle is independent
///
/// A leader/follower protocol with a generation counter is precisely the shape where a rare
/// interleaving is indistinguishable from correctness until it corrupts data. The model therefore
/// does **not** assert anything about tickets — asserting the ticket arithmetic against itself would
/// prove nothing. It maintains a separate oracle:
///
/// * `written` — a bitmask; thread `i` sets bit `i` when its (modelled) page writes complete;
/// * `durable` — a bitmask; the modelled barrier ORs in a **single atomic snapshot of `written`
///   taken at its entry**, i.e. exactly "everything whose writes completed before this barrier
///   started". A single atomic load is used so the snapshot cannot straddle a peer's write, which
///   would make the model more permissive than reality and could hide a bug.
///
/// The property asserted is the one that must never bend: **when `wait_durable` returns `Ok`, this
/// thread's own bit is set in `durable`.** A follower that woke and assumed the leader's barrier
/// covered it fails this assertion.
#[cfg(all(test, loom))]
mod loom_model {
    use super::*;
    use loom::sync::Arc;
    use loom::sync::atomic::{AtomicU64 as LoomAtomicU64, Ordering as LoomOrdering};

    /// One modelled evictor: complete the writes, take a ticket (in that order), then wait.
    fn evictor(
        idx: u32,
        barrier: &StagingBarrier,
        written: &LoomAtomicU64,
        durable: &LoomAtomicU64,
    ) {
        let bit = 1u64 << idx;
        // 1. The staging writes complete.
        written.fetch_or(bit, LoomOrdering::AcqRel);
        // 2. ONLY THEN take the ticket. This ordering is the whole basis of the correctness
        //    argument; reversing it is the bug the model exists to catch.
        let ticket = barrier.ticket();

        // The modelled barrier: snapshot what had completed at entry, then publish exactly that.
        let sync = || -> Result<()> {
            let snapshot = written.load(LoomOrdering::Acquire);
            durable.fetch_or(snapshot, LoomOrdering::AcqRel);
            Ok(())
        };
        barrier.wait_durable(ticket, &sync).expect("barrier");

        // THE ORACLE, independent of the ticket arithmetic.
        let d = durable.load(LoomOrdering::Acquire);
        assert!(
            d & bit != 0,
            "rmp #994: evictor {idx} concluded with ticket {ticket} while its own staging writes \
             were NOT durable (durable mask {d:#b}, own bit {bit:#b}). A follower must never assume \
             a leader's barrier covered it — that is silent data loss on the doublewrite path."
        );
    }

    /// Two concurrent evictors: every interleaving of leader election, the in-flight barrier, the
    /// condvar wait and the recheck.
    #[test]
    fn loom_two_evictors_never_conclude_without_their_own_bytes_durable() {
        loom::model(|| {
            let barrier = Arc::new(StagingBarrier::new());
            let written = Arc::new(LoomAtomicU64::new(0));
            let durable = Arc::new(LoomAtomicU64::new(0));

            let handles: Vec<_> = (0..2u32)
                .map(|i| {
                    let barrier = Arc::clone(&barrier);
                    let written = Arc::clone(&written);
                    let durable = Arc::clone(&durable);
                    loom::thread::spawn(move || evictor(i, &barrier, &written, &durable))
                })
                .collect();
            for h in handles {
                h.join().expect("join");
            }

            // Both concluded, so both must be durable.
            assert_eq!(
                durable.load(LoomOrdering::Acquire) & 0b11,
                0b11,
                "both evictors concluded, so both their writes must be durable"
            );
        });
    }

    /// The **follower** case specifically: one evictor stages and waits while the other is already
    /// inside a barrier. Modelled by having the second evictor start from a state where a ticket has
    /// already been issued, so the "my ticket is above the leader's snapshot" branch — the one the
    /// recheck exists for — is reachable.
    #[test]
    fn loom_late_arrival_is_not_claimed_by_an_in_flight_barrier() {
        loom::model(|| {
            let barrier = Arc::new(StagingBarrier::new());
            let written = Arc::new(LoomAtomicU64::new(0));
            let durable = Arc::new(LoomAtomicU64::new(0));

            // Evictor 0 runs on this thread; evictor 1 races it. With only two threads loom explores
            // the case where 1's ticket is issued after 0's leader snapshot, which is exactly when a
            // follower must NOT be satisfied by 0's barrier.
            let b1 = Arc::clone(&barrier);
            let w1 = Arc::clone(&written);
            let d1 = Arc::clone(&durable);
            let t = loom::thread::spawn(move || evictor(1, &b1, &w1, &d1));
            evictor(0, &barrier, &written, &durable);
            t.join().expect("join");

            assert_eq!(durable.load(LoomOrdering::Acquire) & 0b11, 0b11);
        });
    }

    /// A failing barrier must never advance the durable watermark: the leader propagates the error
    /// and nothing is claimed. Modelled with a barrier that always fails.
    #[test]
    fn loom_a_failed_barrier_claims_nothing() {
        loom::model(|| {
            let barrier = Arc::new(StagingBarrier::new());
            let ticket = barrier.ticket();
            let failing = || -> Result<()> {
                Err(GraphusError::Storage("modelled barrier failure".to_owned()))
            };
            assert!(
                barrier.wait_durable(ticket, &failing).is_err(),
                "a failed barrier must surface as an error, never as success"
            );
            assert_eq!(
                barrier.durable(),
                0,
                "a failed barrier must not advance the durable watermark"
            );
        });
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering as StdOrdering};

    /// A lone caller leads its own round and comes back durable through its ticket.
    #[test]
    fn a_lone_caller_leads_and_becomes_durable() {
        let b = StagingBarrier::new();
        let calls = AtomicUsize::new(0);
        let t = b.ticket();
        let led = b
            .wait_durable(t, &|| {
                calls.fetch_add(1, StdOrdering::Relaxed);
                Ok(())
            })
            .expect("barrier");
        assert!(led, "with no peer in flight the caller must lead");
        assert_eq!(calls.load(StdOrdering::Relaxed), 1);
        assert!(b.durable() >= t, "the caller's ticket must be durable");
    }

    /// A failed barrier surfaces as an error and advances nothing — a caller must never be told its
    /// bytes are durable because someone else's barrier failed.
    #[test]
    fn a_failed_barrier_errors_and_claims_nothing() {
        let b = StagingBarrier::new();
        let t = b.ticket();
        let r = b.wait_durable(t, &|| {
            Err(GraphusError::Storage("device failure".to_owned()))
        });
        assert!(r.is_err(), "a failed barrier must not report success");
        assert_eq!(
            b.durable(),
            0,
            "a failed barrier must not advance durability"
        );
    }

    /// Tickets are monotonic and each caller's own ticket is covered by the target its leader reads,
    /// so a batch of callers arriving before any barrier starts is satisfied by one barrier.
    #[test]
    fn one_barrier_covers_every_ticket_issued_before_it_started() {
        let b = StagingBarrier::new();
        let tickets: Vec<u64> = (0..5).map(|_| b.ticket()).collect();
        assert_eq!(tickets, vec![1, 2, 3, 4, 5], "tickets must be monotonic");
        b.wait_durable(tickets[0], &|| Ok(())).expect("barrier");
        // The leader snapshotted the counter AFTER all five tickets existed, so all five are covered.
        for t in &tickets {
            assert!(
                b.durable() >= *t,
                "ticket {t} must be covered by the one barrier"
            );
        }
        let (barriers, _) = b.counters();
        assert_eq!(barriers, 1, "exactly one barrier should have been issued");
    }

    /// Real threads: while one caller is inside a slow barrier, later arrivals queue and are then
    /// satisfied together — the amortisation the protocol exists for. Asserts the *counters*, since
    /// the correctness tests above pass equally well with no amortisation at all.
    #[test]
    fn concurrent_callers_amortise_barriers() {
        const THREADS: usize = 8;
        let b = Arc::new(StagingBarrier::new());
        std::thread::scope(|s| {
            for _ in 0..THREADS {
                let b = Arc::clone(&b);
                s.spawn(move || {
                    for _ in 0..20 {
                        let t = b.ticket();
                        b.wait_durable(t, &|| {
                            // A real barrier is milliseconds; an instantaneous one leaves no window
                            // for followers to arrive, so there would be nothing to amortise.
                            std::thread::sleep(std::time::Duration::from_micros(500));
                            Ok(())
                        })
                        .expect("barrier");
                    }
                });
            }
        });
        let (barriers, piggybacked) = b.counters();
        let total = (THREADS * 20) as u64;
        assert_eq!(
            barriers + piggybacked,
            total,
            "every caller must be accounted for exactly once as leader or follower"
        );
        assert!(
            piggybacked > 0,
            "no caller rode on another's barrier ({barriers} barriers for {total} callers): the \
             amortisation is not happening"
        );
    }
}
