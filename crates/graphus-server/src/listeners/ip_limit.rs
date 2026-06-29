//! Per-source-IP concurrent-connection cap for the network listeners (`rmp` #478, D1/R1).
//!
//! The single global `max_connections` semaphore (`rmp` #118) bounds the process's *total*
//! file-descriptor/task budget, but on its own it lets **one** source occupy the whole budget: after
//! the `rmp` #469 pre-auth deadline made a flood self-freeing rather than permanent, a distributed
//! connect-then-(reap-and-reconnect) flood — or simply many connections from one abusive host — can
//! still keep the global budget saturated and shed legitimate clients during the window.
//!
//! [`PerIpConnLimiter`] closes that gap by tracking the live concurrent-connection count **per source
//! IP** and capping it. It composes *with* the global semaphore: the global cap is the outer bound
//! (protecting the whole budget), the per-IP cap is the inner bound (protecting any one source's share),
//! so a single abusive IP can never hold more than its cap of slots and therefore can never shed clients
//! arriving from *other* IPs.
//!
//! ## Why a count, not a semaphore
//!
//! The set of source IPs is open-ended (an attacker controls it), so a fixed per-IP semaphore per IP is
//! not viable — we would have to mint one lazily per IP and reclaim it, which *is* a counting map. We
//! therefore keep a small [`HashMap<IpAddr, usize>`] under a `Mutex`: a per-accept `lock → check →
//! increment` and a per-close `lock → decrement → prune`. The map is **self-pruning** (an entry is
//! removed when its count returns to zero), so its size is bounded by the number of IPs with at least one
//! live connection — itself bounded by the global `max_connections`. The lock is held only for the O(1)
//! map op, never across I/O, so contention is negligible next to the per-connection syscalls.
//!
//! ## RAII
//!
//! [`PerIpConnLimiter::try_admit`] returns a [`PerIpConnGuard`] that decrements the count **on drop** —
//! moved into the per-connection task and held for the connection's whole lifetime, so the slot is freed
//! on *every* exit path (clean close, timeout, transport error, or a panic unwinding the task), never
//! leaking. UDS connections have no peer IP and are exempt (see the module docs on `listeners`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};

/// A shared, thread-safe cap on the number of concurrently-open connections per source IP.
///
/// Construct one per server with [`PerIpConnLimiter::new`] and share it (as `Arc`) across the network
/// accept loops (Bolt-over-TCP + REST). A `cap` of `0` disables the limiter entirely (every connection
/// is admitted and nothing is tracked) — the deployment-behind-a-NAT/load-balancer setting where all
/// clients legitimately share one source IP.
#[derive(Debug)]
pub(crate) struct PerIpConnLimiter {
    /// The maximum live connections allowed per source IP; `0` disables the cap.
    cap: usize,
    /// Live connection count per source IP. An entry is removed the moment its count hits zero (so the
    /// map can never grow beyond the number of IPs with a live connection). `Mutex` is ample: every
    /// operation is an O(1) map access with no I/O held across the lock.
    counts: Mutex<HashMap<IpAddr, usize>>,
}

impl PerIpConnLimiter {
    /// Builds a limiter capping each source IP at `cap` concurrent connections (`0` = disabled).
    pub(crate) fn new(cap: usize) -> Arc<Self> {
        Arc::new(Self {
            cap,
            counts: Mutex::new(HashMap::new()),
        })
    }

    /// Whether the per-IP cap is active (`cap > 0`). When disabled, [`try_admit`](Self::try_admit) always
    /// admits and tracks nothing.
    pub(crate) fn is_enabled(&self) -> bool {
        self.cap > 0
    }

    /// Attempts to admit one more connection from `ip`.
    ///
    /// Returns `Some(guard)` when the IP is **under** its cap — the returned [`PerIpConnGuard`] holds the
    /// slot and releases it on drop. Returns `None` when the IP is **at** its cap (the caller must close
    /// the connection and count a rejection). When the limiter is disabled (`cap == 0`) it always returns
    /// `Some` with a no-op guard.
    ///
    /// The count is incremented **only** on a successful admission, so a rejected connection leaves the
    /// IP's count unchanged (no leak, and a rejection cannot itself push the count up).
    pub(crate) fn try_admit(self: &Arc<Self>, ip: IpAddr) -> Option<PerIpConnGuard> {
        if self.cap == 0 {
            // Disabled: admit without tracking. The guard carries no limiter, so its drop is a no-op.
            return Some(PerIpConnGuard { limiter: None, ip });
        }
        let mut counts = self.lock();
        let entry = counts.entry(ip).or_insert(0);
        if *entry >= self.cap {
            return None; // at the cap: reject WITHOUT incrementing.
        }
        *entry += 1;
        Some(PerIpConnGuard {
            limiter: Some(Arc::clone(self)),
            ip,
        })
    }

    /// Releases one slot for `ip` (the guard's drop path): decrements the count and prunes the entry
    /// when it returns to zero so the map stays bounded.
    fn release(&self, ip: IpAddr) {
        let mut counts = self.lock();
        if let Some(count) = counts.get_mut(&ip) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&ip);
            }
        }
    }

    /// Locks the count map, recovering from a poisoned lock: a panic while merely holding this
    /// bookkeeping lock must not cascade into the accept path (the map is plain counters — no invariant
    /// is left half-updated by an unwinding `try_admit`/`release`, both of which are panic-free under the
    /// lock).
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, usize>> {
        self.counts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The current live connection count for `ip` (test/observability only).
    #[cfg(test)]
    pub(crate) fn live_count(&self, ip: IpAddr) -> usize {
        self.lock().get(&ip).copied().unwrap_or(0)
    }

    /// The number of distinct IPs currently tracked (test only) — proves the map is pruned to empty when
    /// every connection closes.
    #[cfg(test)]
    pub(crate) fn tracked_ips(&self) -> usize {
        self.lock().len()
    }
}

/// An RAII guard for one admitted per-IP connection slot. Dropping it decrements the source IP's live
/// count (and prunes the map entry when it reaches zero). Moved into the per-connection task and held for
/// the connection's whole lifetime, so the slot is released on every exit path — clean close, timeout,
/// transport error, or a panic unwinding the task — and never leaks.
///
/// A guard built by a **disabled** limiter (`cap == 0`) carries no limiter and its drop is a no-op.
#[derive(Debug)]
#[must_use = "dropping the guard immediately frees the per-IP slot; hold it for the connection's life"]
pub(crate) struct PerIpConnGuard {
    /// `None` when the limiter is disabled (the guard is a tracked-nothing placeholder).
    limiter: Option<Arc<PerIpConnLimiter>>,
    ip: IpAddr,
}

impl Drop for PerIpConnGuard {
    fn drop(&mut self) {
        if let Some(limiter) = &self.limiter {
            limiter.release(self.ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn admits_up_to_cap_then_rejects() {
        let lim = PerIpConnLimiter::new(3);
        let a = ip(10, 0, 0, 1);
        let g1 = lim.try_admit(a).expect("1st under cap");
        let g2 = lim.try_admit(a).expect("2nd under cap");
        let g3 = lim.try_admit(a).expect("3rd under cap");
        assert_eq!(lim.live_count(a), 3);
        // The 4th from the SAME ip is rejected — and the rejection must NOT bump the count.
        assert!(lim.try_admit(a).is_none(), "4th over cap is rejected");
        assert_eq!(
            lim.live_count(a),
            3,
            "a rejection does not increment the count"
        );
        // Holding the guards keeps the slots occupied (they are not dropped yet).
        drop((g1, g2, g3));
    }

    #[test]
    fn raii_drop_decrements_and_frees_a_slot_without_leaking() {
        let lim = PerIpConnLimiter::new(2);
        let a = ip(192, 168, 1, 7);
        let g1 = lim.try_admit(a).expect("1st");
        let g2 = lim.try_admit(a).expect("2nd");
        assert_eq!(lim.live_count(a), 2);
        assert!(lim.try_admit(a).is_none(), "at cap");
        // Dropping one guard frees exactly one slot (RAII decrement) — a fresh admission then succeeds.
        drop(g1);
        assert_eq!(lim.live_count(a), 1, "drop decremented the count");
        let g3 = lim.try_admit(a).expect("a freed slot re-admits");
        assert_eq!(lim.live_count(a), 2);
        drop((g2, g3));
        // Every guard dropped ⇒ the count returns to zero AND the map entry is pruned (no leak).
        assert_eq!(lim.live_count(a), 0);
        assert_eq!(
            lim.tracked_ips(),
            0,
            "the map is pruned to empty when all slots free"
        );
    }

    #[test]
    fn per_ip_counts_are_independent() {
        let lim = PerIpConnLimiter::new(1);
        let a = ip(10, 0, 0, 1);
        let b = ip(10, 0, 0, 2);
        let _ga = lim.try_admit(a).expect("a admits");
        // a is now at its cap, but b is unaffected — a saturated IP never sheds another source.
        assert!(lim.try_admit(a).is_none(), "a is at cap");
        let _gb = lim.try_admit(b).expect("b admits independently of a");
        assert_eq!(lim.live_count(a), 1);
        assert_eq!(lim.live_count(b), 1);
        assert_eq!(lim.tracked_ips(), 2);
    }

    #[test]
    fn ipv4_and_ipv6_are_distinct_keys() {
        let lim = PerIpConnLimiter::new(1);
        let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let _g4 = lim.try_admit(v4).expect("v4 loopback");
        let _g6 = lim.try_admit(v6).expect("v6 loopback is a different key");
        assert_eq!(lim.live_count(v4), 1);
        assert_eq!(lim.live_count(v6), 1);
    }

    #[test]
    fn disabled_cap_admits_everything_and_tracks_nothing() {
        let lim = PerIpConnLimiter::new(0);
        assert!(!lim.is_enabled());
        let a = ip(10, 0, 0, 1);
        // Far past any cap: all admitted, and nothing is tracked (the guards are no-op placeholders).
        let guards: Vec<_> = (0..1000)
            .map(|_| lim.try_admit(a).expect("disabled always admits"))
            .collect();
        assert_eq!(lim.live_count(a), 0, "disabled limiter tracks nothing");
        assert_eq!(lim.tracked_ips(), 0);
        drop(guards); // dropping no-op guards is harmless.
    }

    #[test]
    fn guard_drop_is_concurrency_safe_and_balances_to_zero() {
        // Many threads each admit-then-drop in a loop; the count must net to zero with no leak and no
        // underflow (the RAII decrement and the admit increment are both under the same lock).
        let lim = PerIpConnLimiter::new(64);
        let a = ip(172, 16, 0, 9);
        let mut handles = Vec::new();
        for _ in 0..8 {
            let lim = Arc::clone(&lim);
            handles.push(std::thread::spawn(move || {
                for _ in 0..5_000 {
                    if let Some(g) = lim.try_admit(a) {
                        // Hold the slot for an instant, then release it.
                        std::hint::black_box(&g);
                        drop(g);
                    }
                }
            }));
        }
        for h in handles {
            h.join().expect("worker joins");
        }
        assert_eq!(
            lim.live_count(a),
            0,
            "every admit was balanced by its guard drop"
        );
        assert_eq!(lim.tracked_ips(), 0, "the map pruned back to empty");
    }
}
