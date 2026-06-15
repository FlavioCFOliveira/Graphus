//! The **open-transaction registry**: tracks explicit transactions by id, expires idle ones, and
//! deduplicates retried requests by `Idempotency-Key` (`04-technical-design.md` §8.2).
//!
//! `04 §8.2` requires the REST transactional surface to (a) hold open transactions keyed by id with
//! **inactivity auto-rollback**, and (b) honour an **`Idempotency-Key`** so a retried request
//! returns the first response rather than re-executing. Both are implemented here, over the
//! **injected [`Clock`](graphus_core::capability::Clock)** so expiry is deterministic and tests
//! advance time explicitly — there is no wall-clock and no background timer thread (the hard rule:
//! deterministic time, no wall-clock in logic).
//!
//! ## Lazy expiry, not a timer
//!
//! A transaction past its deadline is rolled back **the next time it is touched** (looked up,
//! swept, or shut down), and the server can call [`TxRegistry::sweep_expired`] opportunistically
//! (e.g. on an admin tick or, in production, from a single low-frequency task the listener owns).
//! Lazy expiry keeps the registry free of its own runtime: it needs only a `Clock`, so it drops
//! straight into the deterministic simulator. The model is "a deadline is a clock value; an
//! operation that observes `now >= deadline` rolls the transaction back and reports it gone."
//!
//! ## Concurrency
//!
//! axum shares one registry across all worker tasks, so it is internally synchronised with a
//! [`std::sync::Mutex`]. Every critical section is short and **contains no `.await`** (the engine
//! calls it makes are synchronous), so the guard is never held across a suspension point
//! (clippy `await_holding_lock` stays satisfied — `04 §3.3`). The mutex wraps only the bookkeeping
//! maps; the engine itself is `Sync` and called without the registry lock held where possible.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Mutex;

use crate::engine::{AccessMode, RestEngine, TxHandle};

/// Maximum number of distinct idempotency entries retained at once (rmp #184, CWE-770).
///
/// The idempotency cache only needs to cover a client's *retry window*, not its whole history, so a
/// hard cap on resident entries bounds memory regardless of how many distinct `Idempotency-Key`
/// values an authenticated client sends. When the cap is reached, the **oldest** entry is evicted
/// (insertion-order FIFO) to admit the new one — a re-fired key past the cap simply re-executes
/// (idempotency is best-effort by contract once an entry ages out). Combined with [`IDEMPOTENCY_TTL_NANOS`]
/// this makes the cache a bounded, self-pruning structure rather than an unbounded `HashMap`.
pub const IDEMPOTENCY_MAX_ENTRIES: usize = 4096;

/// How long an idempotency entry lives, in nanoseconds on the injected clock's timeline (rmp #184).
///
/// 5 minutes comfortably covers realistic client retry/back-off windows while ensuring stale entries
/// are reclaimed deterministically (the cache is pruned lazily on each access against the injected
/// [`Clock`](graphus_core::capability::Clock) value the router passes in — no wall-clock, no timer
/// thread, exactly as the transaction-expiry path works).
pub const IDEMPOTENCY_TTL_NANOS: u64 = 5 * 60 * 1_000_000_000;

/// A cached idempotent response: exactly the bytes (and content type + status) to replay for a
/// repeated `Idempotency-Key` (`04 §8.2`).
#[derive(Debug, Clone)]
pub struct CachedResponse {
    /// The HTTP status code of the first response.
    pub status: u16,
    /// The `Content-Type` header value of the first response.
    pub content_type: String,
    /// The full response body bytes of the first response.
    pub body: Vec<u8>,
}

/// One open explicit transaction's bookkeeping.
struct Entry {
    /// The engine's handle for this transaction.
    handle: TxHandle,
    /// The database the transaction is bound to.
    db: String,
    /// The access mode (`06 §4`).
    mode: AccessMode,
    /// The clock value (nanoseconds) at or after which the transaction is considered expired.
    deadline_nanos: u64,
}

/// A snapshot of a live transaction's coordinates, returned by [`TxRegistry::touch`].
#[derive(Debug, Clone, Copy)]
pub struct TxInfo {
    /// The engine handle to drive `run`/`commit`/`rollback`.
    pub handle: TxHandle,
    /// The access mode of the transaction.
    pub mode: AccessMode,
    /// The refreshed deadline (clock nanoseconds) after this touch.
    pub deadline_nanos: u64,
}

/// The registry of open transactions and replayable idempotent responses (`04 §8.2`).
///
/// Generic over the [`RestEngine`] so the auto-rollback path can call `engine.rollback(handle)`
/// directly when a transaction expires, and over a borrowed
/// [`Clock`](graphus_core::capability::Clock) passed per call so the registry holds no time source
/// of its own.
pub struct TxRegistry {
    inner: Mutex<Inner>,
    /// How long an idle transaction lives, in nanoseconds on the injected clock's timeline.
    ttl_nanos: u64,
    /// Monotonic counter minting the public, URL-facing transaction ids (`tx-<n>`), distinct from
    /// the engine's internal [`TxHandle`] ticket so the engine's id is never exposed.
    next_id: Mutex<u64>,
}

/// A stored idempotency entry: the bytes to replay plus the clock value at which it expires
/// (rmp #184). The expiry is evaluated lazily against the injected clock on each access.
struct IdempotencyEntry {
    response: CachedResponse,
    expires_at_nanos: u64,
}

/// The cache key for an idempotency entry: the **resolved principal** *and* the raw header value
/// (rmp #182). Namespacing by principal is what prevents a cross-tenant IDOR — user `bob` presenting
/// the key `alice` used hashes to a different slot and therefore misses alice's cached body.
#[derive(Clone, PartialEq, Eq, Hash)]
struct IdempotencyKey {
    principal: String,
    key: String,
}

#[derive(Default)]
struct Inner {
    /// Open transactions by their public id.
    txns: HashMap<String, Entry>,
    /// Cached responses keyed by `(principal, Idempotency-Key)` (rmp #182 scoping). Bounded by
    /// [`IDEMPOTENCY_MAX_ENTRIES`] and [`IDEMPOTENCY_TTL_NANOS`] (rmp #184) — never grows without
    /// limit.
    idempotency: HashMap<IdempotencyKey, IdempotencyEntry>,
    /// Insertion order of live idempotency keys, so the cap can evict the **oldest** entry in O(1)
    /// amortised when [`IDEMPOTENCY_MAX_ENTRIES`] is reached (a FIFO eviction queue).
    idempotency_order: VecDeque<IdempotencyKey>,
}

impl Inner {
    /// Drops every idempotency entry whose deadline is at or before `now_nanos` (rmp #184 lazy TTL).
    ///
    /// Called on each idempotency read/write so stale entries are reclaimed deterministically against
    /// the injected clock — no background timer. The order queue is filtered in lock-step so it never
    /// references an evicted key.
    fn prune_expired_idempotency(&mut self, now_nanos: u64) {
        if self.idempotency.is_empty() {
            return;
        }
        self.idempotency
            .retain(|_, e| now_nanos < e.expires_at_nanos);
        if self.idempotency.len() != self.idempotency_order.len() {
            let live = &self.idempotency;
            self.idempotency_order.retain(|k| live.contains_key(k));
        }
    }
}

impl TxRegistry {
    /// Creates an empty registry whose transactions expire after `ttl_nanos` of inactivity.
    #[must_use]
    pub fn new(ttl_nanos: u64) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            ttl_nanos,
            next_id: Mutex::new(0),
        }
    }

    /// Registers a freshly-opened transaction, returning the public id it is addressed by and the
    /// deadline it will expire at if untouched.
    ///
    /// `now_nanos` is the current injected-clock value; the deadline is `now + ttl`.
    pub fn open(
        &self,
        handle: TxHandle,
        db: &str,
        mode: AccessMode,
        now_nanos: u64,
    ) -> (String, u64) {
        let id = {
            let mut n = self
                .next_id
                .lock()
                .expect("INVARIANT: id mutex un-poisoned");
            *n += 1;
            format!("tx-{n}")
        };
        let deadline_nanos = now_nanos.saturating_add(self.ttl_nanos);
        let mut inner = self
            .inner
            .lock()
            .expect("INVARIANT: registry mutex un-poisoned");
        inner.txns.insert(
            id.clone(),
            Entry {
                handle,
                db: db.to_owned(),
                mode,
                deadline_nanos,
            },
        );
        (id, deadline_nanos)
    }

    /// Looks up an open transaction by id, **refreshing its deadline** (resetting the inactivity
    /// timeout, `04 §8.2`) to `now + ttl`.
    ///
    /// If the transaction is already past its deadline as of `now_nanos`, it is **rolled back**
    /// (auto-rollback) and removed, and `None` is returned — exactly as if it had never existed (the
    /// router then answers `404`). This is the lazy-expiry path: a stale id is reaped the moment it
    /// is touched.
    ///
    /// Returns `None` for an unknown (or just-expired) id.
    pub fn touch<E: RestEngine>(&self, id: &str, now_nanos: u64, engine: &E) -> Option<TxInfo> {
        // Take the handle to roll back *outside* the lock, so the engine call never runs under the
        // registry mutex (keeps the critical section short and lock ordering simple).
        let mut to_rollback = None;
        let result = {
            let mut inner = self
                .inner
                .lock()
                .expect("INVARIANT: registry mutex un-poisoned");
            match inner.txns.get_mut(id) {
                Some(entry) if now_nanos >= entry.deadline_nanos => {
                    to_rollback = Some(entry.handle);
                    inner.txns.remove(id);
                    None
                }
                Some(entry) => {
                    entry.deadline_nanos = now_nanos.saturating_add(self.ttl_nanos);
                    Some(TxInfo {
                        handle: entry.handle,
                        mode: entry.mode,
                        deadline_nanos: entry.deadline_nanos,
                    })
                }
                None => None,
            }
        };
        if let Some(handle) = to_rollback {
            // Idempotent rollback (`RestEngine::rollback` doc); ignore its result on the expiry path.
            let _ = engine.rollback(handle);
        }
        result
    }

    /// Removes a transaction from the registry and returns its engine handle, so the caller can
    /// commit or roll it back. Returns `None` if the id is unknown.
    ///
    /// Unlike [`touch`](Self::touch) this does **not** refresh or check the deadline — it is the
    /// terminal path (`COMMIT` / `DELETE`), after which the transaction no longer exists in the
    /// registry regardless of the engine's outcome. (An expired-but-not-yet-swept id still returns
    /// its handle here so a racing `DELETE` can finalise the rollback rather than 404; the engine's
    /// idempotent rollback makes a double-rollback harmless.)
    pub fn take(&self, id: &str) -> Option<(TxHandle, String, AccessMode)> {
        let mut inner = self
            .inner
            .lock()
            .expect("INVARIANT: registry mutex un-poisoned");
        inner.txns.remove(id).map(|e| (e.handle, e.db, e.mode))
    }

    /// Rolls back and removes **every** transaction whose deadline is at or before `now_nanos`
    /// (`04 §8.2` inactivity auto-rollback), returning the ids reaped.
    ///
    /// This is the explicit sweep the server can run on a tick; the tests call it after advancing
    /// the injected clock to prove expiry is deterministic.
    pub fn sweep_expired<E: RestEngine>(&self, now_nanos: u64, engine: &E) -> Vec<String> {
        // Collect expired (id, handle) under the lock, then roll back outside it.
        let expired: Vec<(String, TxHandle)> = {
            let mut inner = self
                .inner
                .lock()
                .expect("INVARIANT: registry mutex un-poisoned");
            let ids: Vec<String> = inner
                .txns
                .iter()
                .filter(|(_, e)| now_nanos >= e.deadline_nanos)
                .map(|(id, _)| id.clone())
                .collect();
            ids.into_iter()
                .filter_map(|id| inner.txns.remove(&id).map(|e| (id, e.handle)))
                .collect()
        };
        let mut reaped = Vec::with_capacity(expired.len());
        for (id, handle) in expired {
            let _ = engine.rollback(handle);
            reaped.push(id);
        }
        reaped
    }

    /// The number of currently-open transactions (for tests / an observability gauge).
    #[must_use]
    pub fn open_count(&self) -> usize {
        self.inner
            .lock()
            .expect("INVARIANT: registry mutex un-poisoned")
            .txns
            .len()
    }

    // ---- Idempotency-Key dedup (`04 §8.2`) ---------------------------------------------------

    /// Returns the cached response for a previously-seen `(principal, Idempotency-Key)`, if any and
    /// not expired as of `now_nanos`.
    ///
    /// The key is scoped by the **authenticated principal** (rmp #182): a key collision across users
    /// misses the cache, so one user can never replay another user's body. A non-`None` result means
    /// the router must **replay** it verbatim instead of re-executing (`04 §8.2`). Expired entries are
    /// pruned lazily against the injected clock on access (rmp #184).
    #[must_use]
    pub fn cached_response(
        &self,
        principal: &str,
        key: &str,
        now_nanos: u64,
    ) -> Option<CachedResponse> {
        let mut inner = self
            .inner
            .lock()
            .expect("INVARIANT: registry mutex un-poisoned");
        inner.prune_expired_idempotency(now_nanos);
        inner
            .idempotency
            .get(&IdempotencyKey {
                principal: principal.to_owned(),
                key: key.to_owned(),
            })
            .map(|e| e.response.clone())
    }

    /// Stores the first response for a `(principal, Idempotency-Key)` so a later retry replays it.
    ///
    /// Storing under a key already present is a no-op (the *first* response wins, per the idempotency
    /// contract), which also makes concurrent first-and-retry races resolve to one stored body. The
    /// entry expires `IDEMPOTENCY_TTL_NANOS` after `now_nanos`, and the cache is capped at
    /// [`IDEMPOTENCY_MAX_ENTRIES`] live entries — the oldest is evicted FIFO when the cap is hit
    /// (rmp #184, CWE-770: bounded memory regardless of how many distinct keys a client sends).
    pub fn store_response(
        &self,
        principal: &str,
        key: &str,
        now_nanos: u64,
        response: CachedResponse,
    ) {
        let cache_key = IdempotencyKey {
            principal: principal.to_owned(),
            key: key.to_owned(),
        };
        let mut inner = self
            .inner
            .lock()
            .expect("INVARIANT: registry mutex un-poisoned");
        inner.prune_expired_idempotency(now_nanos);

        if inner.idempotency.contains_key(&cache_key) {
            // First response wins — never overwrite, never re-queue (preserves FIFO age).
            return;
        }

        // Enforce the hard cap by evicting oldest-first before admitting the new entry.
        while inner.idempotency.len() >= IDEMPOTENCY_MAX_ENTRIES {
            match inner.idempotency_order.pop_front() {
                Some(oldest) => {
                    inner.idempotency.remove(&oldest);
                }
                // Order queue empty but map at cap: cannot happen (they are maintained in lock-step),
                // but break rather than loop forever if the invariant were ever violated.
                None => break,
            }
        }

        inner.idempotency.insert(
            cache_key.clone(),
            IdempotencyEntry {
                response,
                expires_at_nanos: now_nanos.saturating_add(IDEMPOTENCY_TTL_NANOS),
            },
        );
        inner.idempotency_order.push_back(cache_key);
    }

    /// The number of currently-resident idempotency entries (for tests / an observability gauge).
    #[must_use]
    pub fn idempotency_len(&self) -> usize {
        self.inner
            .lock()
            .expect("INVARIANT: registry mutex un-poisoned")
            .idempotency
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::mock::MockEngine;
    use graphus_core::capability::Clock;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A `Clock` whose value the test sets explicitly (deterministic time — no wall-clock).
    struct TestClock(AtomicU64);
    impl TestClock {
        fn new(start: u64) -> Self {
            Self(AtomicU64::new(start))
        }
        fn set(&self, v: u64) {
            self.0.store(v, Ordering::Relaxed);
        }
        fn now(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
    }
    impl Clock for TestClock {
        fn now_nanos(&self) -> u64 {
            self.now()
        }
    }

    const TTL: u64 = 1000;

    /// A fixed auto-commit origin for the registry unit tests.
    const TEST_ORIGIN: crate::engine::TxOrigin<'static> = crate::engine::TxOrigin {
        principal: "tester",
        explicit: false,
    };

    #[test]
    fn open_then_touch_returns_handle_and_refreshes_deadline() {
        let engine = MockEngine::new();
        let clock = TestClock::new(0);
        let reg = TxRegistry::new(TTL);

        let h = engine
            .begin("neo4j", AccessMode::Write, TEST_ORIGIN)
            .unwrap();
        let (id, deadline) = reg.open(h, "neo4j", AccessMode::Write, clock.now_nanos());
        assert_eq!(deadline, TTL);
        assert_eq!(reg.open_count(), 1);

        // Touch at t=500: still alive, deadline pushed to 1500.
        clock.set(500);
        let info = reg.touch(&id, clock.now_nanos(), &engine).expect("alive");
        assert_eq!(info.handle, h);
        assert_eq!(info.deadline_nanos, 1500);
    }

    #[test]
    fn touch_past_deadline_auto_rolls_back_and_reaps() {
        let engine = MockEngine::new();
        let clock = TestClock::new(0);
        let reg = TxRegistry::new(TTL);

        let h = engine
            .begin("neo4j", AccessMode::Write, TEST_ORIGIN)
            .unwrap();
        let (id, _) = reg.open(h, "neo4j", AccessMode::Write, clock.now_nanos());

        // Advance past the deadline; touching reaps it and returns None.
        clock.set(TTL + 1);
        assert!(reg.touch(&id, clock.now_nanos(), &engine).is_none());
        assert_eq!(reg.open_count(), 0);
        // The engine saw a rollback for that handle.
        assert!(
            engine
                .log()
                .iter()
                .any(|l| l == &format!("rollback(tx={})", h.0))
        );
    }

    #[test]
    fn sweep_reaps_only_expired_transactions() {
        let engine = MockEngine::new();
        let clock = TestClock::new(0);
        let reg = TxRegistry::new(TTL);

        // tx A opened at t=0 (deadline 1000); tx B opened at t=900 (deadline 1900).
        let ha = engine
            .begin("neo4j", AccessMode::Write, TEST_ORIGIN)
            .unwrap();
        let (_id_a, _) = reg.open(ha, "neo4j", AccessMode::Write, 0);
        clock.set(900);
        let hb = engine
            .begin("neo4j", AccessMode::Write, TEST_ORIGIN)
            .unwrap();
        let (id_b, _) = reg.open(hb, "neo4j", AccessMode::Write, clock.now_nanos());

        // Sweep at t=1000: only A is expired.
        clock.set(1000);
        let reaped = reg.sweep_expired(clock.now_nanos(), &engine);
        assert_eq!(reaped.len(), 1);
        assert_eq!(reg.open_count(), 1);
        // B is still touchable.
        assert!(reg.touch(&id_b, clock.now_nanos(), &engine).is_some());
    }

    #[test]
    fn take_removes_and_returns_handle() {
        let engine = MockEngine::new();
        let reg = TxRegistry::new(TTL);
        let h = engine
            .begin("neo4j", AccessMode::Read, TEST_ORIGIN)
            .unwrap();
        let (id, _) = reg.open(h, "neo4j", AccessMode::Read, 0);

        let (taken, db, mode) = reg.take(&id).expect("present");
        assert_eq!(taken, h);
        assert_eq!(db, "neo4j");
        assert_eq!(mode, AccessMode::Read);
        assert_eq!(reg.open_count(), 0);
        // Taking again is None.
        assert!(reg.take(&id).is_none());
    }

    #[test]
    fn idempotency_key_replays_first_response() {
        let reg = TxRegistry::new(TTL);
        let first = CachedResponse {
            status: 200,
            content_type: "application/json".to_owned(),
            body: b"{\"first\":true}".to_vec(),
        };
        assert!(reg.cached_response("alice", "key-1", 0).is_none());
        reg.store_response("alice", "key-1", 0, first.clone());

        // A second store under the same (principal, key) does NOT overwrite (first wins).
        reg.store_response(
            "alice",
            "key-1",
            0,
            CachedResponse {
                status: 500,
                content_type: "x".to_owned(),
                body: b"second".to_vec(),
            },
        );
        let got = reg.cached_response("alice", "key-1", 0).expect("cached");
        assert_eq!(got.status, 200);
        assert_eq!(got.body, first.body);
    }

    #[test]
    fn idempotency_key_is_scoped_per_principal() {
        // rmp #182: the same raw key under a different principal must miss the cache.
        let reg = TxRegistry::new(TTL);
        reg.store_response(
            "alice",
            "collide",
            0,
            CachedResponse {
                status: 200,
                content_type: "application/json".to_owned(),
                body: b"alice-body".to_vec(),
            },
        );
        // Alice replays her own body.
        assert_eq!(
            reg.cached_response("alice", "collide", 0).unwrap().body,
            b"alice-body".to_vec()
        );
        // Bob, presenting the identical key, sees nothing of alice's.
        assert!(reg.cached_response("bob", "collide", 0).is_none());
    }

    #[test]
    fn idempotency_entries_expire_on_ttl() {
        // rmp #184: an entry past IDEMPOTENCY_TTL_NANOS is pruned lazily on the next access.
        let reg = TxRegistry::new(TTL);
        reg.store_response(
            "alice",
            "k",
            0,
            CachedResponse {
                status: 200,
                content_type: "application/json".to_owned(),
                body: b"x".to_vec(),
            },
        );
        assert!(reg.cached_response("alice", "k", 0).is_some());
        // Just before expiry: still live.
        assert!(
            reg.cached_response("alice", "k", IDEMPOTENCY_TTL_NANOS - 1)
                .is_some()
        );
        // At/after expiry: pruned.
        assert!(
            reg.cached_response("alice", "k", IDEMPOTENCY_TTL_NANOS)
                .is_none()
        );
        assert_eq!(reg.idempotency_len(), 0);
    }

    #[test]
    fn idempotency_cache_is_capped_with_fifo_eviction() {
        // rmp #184: beyond the cap, the oldest entry is evicted (bounded memory).
        let reg = TxRegistry::new(TTL);
        for i in 0..IDEMPOTENCY_MAX_ENTRIES {
            reg.store_response(
                "alice",
                &format!("k-{i}"),
                0,
                CachedResponse {
                    status: 200,
                    content_type: "application/json".to_owned(),
                    body: vec![],
                },
            );
        }
        assert_eq!(reg.idempotency_len(), IDEMPOTENCY_MAX_ENTRIES);
        // The oldest key is still resident at exactly the cap.
        assert!(reg.cached_response("alice", "k-0", 0).is_some());

        // One more entry evicts the oldest (k-0); the count never exceeds the cap.
        reg.store_response(
            "alice",
            "k-new",
            0,
            CachedResponse {
                status: 200,
                content_type: "application/json".to_owned(),
                body: vec![],
            },
        );
        assert_eq!(reg.idempotency_len(), IDEMPOTENCY_MAX_ENTRIES);
        assert!(reg.cached_response("alice", "k-0", 0).is_none());
        assert!(reg.cached_response("alice", "k-new", 0).is_some());
    }

    #[test]
    fn ids_are_unique_and_opaque() {
        let reg = TxRegistry::new(TTL);
        let engine = MockEngine::new();
        let h1 = engine.begin("g", AccessMode::Write, TEST_ORIGIN).unwrap();
        let h2 = engine.begin("g", AccessMode::Write, TEST_ORIGIN).unwrap();
        let (id1, _) = reg.open(h1, "g", AccessMode::Write, 0);
        let (id2, _) = reg.open(h2, "g", AccessMode::Write, 0);
        assert_ne!(id1, id2);
        assert!(id1.starts_with("tx-"));
    }
}
