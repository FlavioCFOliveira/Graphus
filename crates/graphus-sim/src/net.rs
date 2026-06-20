//! [`SimNet`] — a deterministic, in-memory network for the VOPR-style simulator (rmp #161).
//!
//! The simulator drives the **real** Bolt/REST protocol stacks, but over *this* network instead of
//! OS sockets, so the whole run stays single-threaded and reproducible from a seed. A [`SimEndpoint`]
//! implements [`graphus_bolt::Transport`], so a real `BoltSession` can read/write through it
//! unchanged; the REST client uses the same endpoint's raw byte API.
//!
//! ## Faithful transport model (reliable, ordered, delayable, breakable)
//!
//! Bolt-over-TCP/UDS and REST-over-HTTP are **reliable, ordered byte streams** (TCP). Modelling
//! byte-level drop / reorder / duplication would test behaviour the server is *not* required to
//! tolerate (TCP already prevents it) — so this network deliberately does **not** corrupt the byte
//! stream. The faults it injects are the ones a reliable transport genuinely exhibits, every one of
//! which the server must survive:
//!
//! - **Latency** — each write is delivered after a seed-drawn delay; per direction, delivery stays
//!   in order (monotonic due time), as TCP guarantees.
//! - **Partition / heal** — a link stops delivering (bytes are held in flight) until healed; models a
//!   network partition the server's idle/read timeouts must cope with.
//! - **Reset** — the connection breaks: in-flight bytes are dropped and both ends error on I/O;
//!   models an abrupt `RST` / client crash.
//! - **Close** — a graceful half-close: the reader sees EOF (`Ok(0)`) after draining; models an
//!   orderly `GOODBYE` / shutdown.
//!
//! ## Cooperative, single-threaded contract
//!
//! Delivery is explicit: a write puts bytes *in flight*; [`SimNet::advance_to`] moves the bytes whose
//! due time has arrived into the peer's readable buffer. A [`SimEndpoint::read`] returns only the
//! bytes already delivered. Because there is no second thread to block on, an **open but not-yet-fed**
//! read returns `Ok(0)` — the cooperative driver must call [`SimNet::advance_to`] first and use
//! [`SimEndpoint::is_eof`] to distinguish a true end-of-stream from a momentary starvation.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use graphus_bolt::{BoltError, BoltResult, Transport};

use crate::SimRng;

/// Which end of a link an endpoint is. The two ends are symmetric; the labels only fix the direction
/// each end writes into (so the byte streams don't cross).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The connecting end (e.g. a virtual Bolt/REST client).
    Client,
    /// The accepting end (the server's per-connection transport).
    Server,
}

impl Side {
    /// The direction index this side **writes** into (`Client`→client-to-server, `Server`→server-to-client).
    fn write_dir(self) -> usize {
        match self {
            Side::Client => 0,
            Side::Server => 1,
        }
    }

    /// The direction index this side **reads** from (the opposite of [`Self::write_dir`]).
    fn read_dir(self) -> usize {
        1 - self.write_dir()
    }
}

/// Tunables for the simulated network's latency distribution. Faults (partition/reset/close) are
/// applied explicitly by the caller via [`SimNet`] methods, not probabilistically here, so a scenario
/// has exact control over when they happen.
#[derive(Debug, Clone, Copy)]
pub struct NetConfig {
    /// Minimum per-write delivery latency, in logical nanoseconds.
    pub min_latency: u64,
    /// Maximum per-write delivery latency, in logical nanoseconds (`>= min_latency`).
    pub max_latency: u64,
}

impl Default for NetConfig {
    fn default() -> Self {
        // A small spread so simultaneous writes on different links interleave in a seed-driven way,
        // while a single link stays in order.
        Self {
            min_latency: 1,
            max_latency: 10,
        }
    }
}

/// A seed-driven plan for a single **transport fault** armed on one direction of a link (rmp #234),
/// built fluently from a seed in the same house style as the `graphus-io` disk `FaultPlan` and the
/// [`ClockFaultPlan`](crate::ClockFaultPlan): every parameter is a pure function of the seed, so the
/// same plan injects the identical fault, at the identical byte offset, every run.
///
/// The simulated network is a faithful *reliable, ordered* stream (TCP-like): it never drops,
/// duplicates or reorders the bytes it *does* deliver. These faults are the ones a reliable transport
/// genuinely exhibits and the server must survive — a mid-message reset, a truncated/stalled write, a
/// slow consumer — expressed at byte-offset precision so they can land *inside* a `RUN`/`PULL`/`COMMIT`
/// message, not only at a message boundary.
///
/// Exactly one pathology is armed per plan (the builders are mutually exclusive — the last one wins),
/// which keeps the surface composable for the unified fault scheduler (rmp #236): arm one plan per
/// `(link, side)` and let the scheduler own which links carry which fault.
///
/// # Liveness (no-hang) guarantee
///
/// Every fault drives the reader to a **terminal** state — a reset (read errors) or an EOF (read
/// returns `Ok(0)` with [`SimEndpoint::is_eof`] true) — so a blocking `BoltSession::run` read always
/// returns rather than blocking forever. `SlowChunk` only *rate-limits* delivery, so it likewise
/// reaches quiescence once every byte has drained.
///
/// ```
/// use graphus_sim::{Side, SimNet, TransportFaultPlan};
///
/// let net = SimNet::with_seed(7);
/// let link = net.connect();
/// // Reset the client→server stream somewhere inside the first 64 delivered bytes.
/// net.arm_transport_fault(link, Side::Server, TransportFaultPlan::new(0xF00D).drop_in_message(64));
/// ```
#[derive(Debug, Clone, Copy)]
pub struct TransportFaultPlan {
    seed: u64,
    spec: FaultSpec,
}

/// The pathology a [`TransportFaultPlan`] arms, with its *bound* (the seed resolves an exact value
/// within the bound when the plan is armed).
#[derive(Debug, Clone, Copy)]
enum FaultSpec {
    /// No fault (an inert plan reads through transparently).
    None,
    /// Reset the link at a seeded byte offset in `1..=bound`.
    DropInMessage { bound: u64 },
    /// Truncate-then-stall at a seeded byte offset in `1..=bound`.
    TruncateThenStall { bound: u64 },
    /// Throttle delivery to a seeded chunk size in `1..=bound` bytes per advance step.
    SlowConsumer { bound: u64 },
}

impl TransportFaultPlan {
    /// An inert plan seeded by `seed`. Arm a pathology with one of the builders below.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            spec: FaultSpec::None,
        }
    }

    /// Arms a **mid-message link drop**: the link is reset the instant cumulative delivery first
    /// reaches a seeded offset in `1..=max_bytes` bytes. Bytes already delivered before the offset stay
    /// readable; every read/write afterwards errors (a `RST` landing inside a message).
    #[must_use]
    pub fn drop_in_message(mut self, max_bytes: u64) -> Self {
        self.spec = FaultSpec::DropInMessage {
            bound: max_bytes.max(1),
        };
        self
    }

    /// Arms a **partial-write truncation then stall**: only the first seeded `1..=max_bytes` bytes are
    /// delivered, then the direction half-closes (the reader sees the truncated prefix, then EOF) and
    /// the remaining in-flight bytes are discarded. Models a write that stops mid-message and never
    /// completes — yet the reader still terminates (EOF), never hangs.
    #[must_use]
    pub fn truncate_then_stall(mut self, max_bytes: u64) -> Self {
        self.spec = FaultSpec::TruncateThenStall {
            bound: max_bytes.max(1),
        };
        self
    }

    /// Arms a **slow consumer**: delivery is throttled to a seeded `1..=max_chunk` bytes per
    /// [`SimNet::advance_to`] step (backpressure). All bytes still arrive, in order — only the delivery
    /// rate is capped — so the exchange reaches quiescence after enough steps.
    #[must_use]
    pub fn slow_consumer(mut self, max_chunk: u64) -> Self {
        self.spec = FaultSpec::SlowConsumer {
            bound: max_chunk.max(1),
        };
        self
    }

    /// Whether the plan arms no fault (reads through transparently).
    #[must_use]
    pub fn is_inert(&self) -> bool {
        matches!(self.spec, FaultSpec::None)
    }

    /// Resolves the seed into a concrete armed fault (or `None` for an inert plan). The draw is a pure
    /// function of the seed mixed with a per-kind tag, so distinct kinds draw independent offsets and
    /// the same plan always resolves to the same trigger point.
    fn resolve(&self) -> Option<ArmedFault> {
        let mut rng = SimRng::new(self.seed ^ 0x5452_414E_5350_5400); // "TRANSPT"
        let kind = match self.spec {
            FaultSpec::None => return None,
            FaultSpec::DropInMessage { bound } => FaultKind::DropAt {
                at: rng.range_inclusive(1, bound),
            },
            FaultSpec::TruncateThenStall { bound } => FaultKind::TruncateAt {
                at: rng.range_inclusive(1, bound),
            },
            FaultSpec::SlowConsumer { bound } => FaultKind::SlowChunk {
                chunk: rng.range_inclusive(1, bound),
            },
        };
        Some(ArmedFault { kind, fired: false })
    }
}

/// One byte segment in flight: the bytes and the logical time they become readable.
#[derive(Debug)]
struct Segment {
    data: Vec<u8>,
    due: u64,
}

/// One direction of a link: bytes in flight (not yet due), bytes delivered and awaiting a read, the
/// last due time (to keep delivery monotonic), and whether the writer has half-closed.
#[derive(Debug, Default)]
struct Direction {
    inflight: VecDeque<Segment>,
    readable: VecDeque<u8>,
    last_due: u64,
    write_closed: bool,
    /// Cumulative count of bytes that have crossed the in-flight/readable boundary on this direction
    /// (i.e. bytes the network has *delivered*). Drives byte-offset-precise transport faults.
    delivered: u64,
    /// A seed-driven transport fault armed on this direction, if any (see [`TransportFaultPlan`]).
    fault: Option<ArmedFault>,
}

/// A bidirectional link between two endpoints.
#[derive(Debug, Default)]
struct Link {
    dirs: [Direction; 2],
    partitioned: bool,
    broken: bool,
}

/// Which transport pathology an [`ArmedFault`] injects, with its seed-resolved parameters (resolved
/// once, when the plan is armed, so the trigger point is fixed and replayable).
#[derive(Debug, Clone, Copy)]
enum FaultKind {
    /// Reset (break) the link the instant cumulative delivery first reaches `at` bytes — a mid-message
    /// `RST`. Bytes already delivered stay readable up to `at`; thereafter both ends error.
    DropAt { at: u64 },
    /// Deliver only the first `at` bytes, then half-close the direction (the reader sees the truncated
    /// prefix then EOF) and discard the rest — a partial write that stalls and never completes.
    TruncateAt { at: u64 },
    /// Throttle delivery to at most `chunk` bytes per [`SimNet::advance_to`] step (a slow consumer /
    /// backpressure). All bytes are eventually delivered, in order — only the *rate* is capped.
    SlowChunk { chunk: u64 },
}

/// A transport fault armed on one direction of one link: the seed-resolved pathology plus whether it
/// has already fired (one-shot for `DropAt`/`TruncateAt`; `SlowChunk` is a standing rate cap).
#[derive(Debug, Clone, Copy)]
struct ArmedFault {
    kind: FaultKind,
    fired: bool,
}

/// The shared mutable network state behind every [`SimEndpoint`] and the [`SimNet`] handle.
#[derive(Debug)]
struct NetState {
    rng: SimRng,
    now: u64,
    config: NetConfig,
    links: Vec<Link>,
}

/// An opaque handle to one link created by [`SimNet::connect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkId(usize);

/// A deterministic in-memory network. Cheaply cloneable (a shared handle); all clones and all
/// [`SimEndpoint`]s view the same state.
#[derive(Debug, Clone)]
pub struct SimNet {
    state: Rc<RefCell<NetState>>,
}

impl SimNet {
    /// Creates an empty network seeded with `seed` and the given latency `config`.
    #[must_use]
    pub fn new(seed: u64, config: NetConfig) -> Self {
        Self {
            state: Rc::new(RefCell::new(NetState {
                rng: SimRng::new(seed),
                now: 0,
                config,
                links: Vec::new(),
            })),
        }
    }

    /// Creates a network with the default latency config.
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        Self::new(seed, NetConfig::default())
    }

    /// Opens a new bidirectional link, returning its id. Use [`Self::endpoint`] to get each end.
    pub fn connect(&self) -> LinkId {
        let mut st = self.state.borrow_mut();
        st.links.push(Link::default());
        LinkId(st.links.len() - 1)
    }

    /// A transport handle for `side` of `link`. Both ends can be fetched; handing the `Server` end to
    /// a real `BoltSession` and the `Client` end to a virtual client wires a full connection.
    #[must_use]
    pub fn endpoint(&self, link: LinkId, side: Side) -> SimEndpoint {
        SimEndpoint {
            net: Rc::clone(&self.state),
            link: link.0,
            side,
        }
    }

    /// The current logical time of the network.
    #[must_use]
    pub fn now(&self) -> u64 {
        self.state.borrow().now
    }

    /// Arms a seed-driven [`TransportFaultPlan`] on the **read** direction of `side` on `link` — i.e.
    /// the stream this side *reads*, which is the peer's writes. A `DropInMessage`/`TruncateThenStall`
    /// fault therefore lands inside a message the `side` endpoint is consuming (e.g. arm on
    /// [`Side::Server`] to corrupt the client's `RUN`/`PULL` as the real `BoltSession` reads it). An
    /// inert plan clears any armed fault. The plan composes with partition/reset/latency.
    pub fn arm_transport_fault(&self, link: LinkId, side: Side, plan: TransportFaultPlan) {
        let mut st = self.state.borrow_mut();
        st.links[link.0].dirs[side.read_dir()].fault = plan.resolve();
    }

    /// Advances logical time to `now`, delivering every in-flight segment whose due time has arrived
    /// (in order, per direction) into the peer's readable buffer. A partitioned link holds its bytes.
    /// `now` never moves backwards.
    ///
    /// A direction carrying a [`TransportFaultPlan`] (armed via [`Self::arm_transport_fault`]) delivers
    /// through the fault: a `DropInMessage` resets the link at its byte offset, a `TruncateThenStall`
    /// half-closes after its prefix, and a `SlowConsumer` caps the bytes moved per call. The faults are
    /// byte-offset-precise (they can fire *inside* a message) yet preserve the reliable-stream
    /// invariant — the bytes that *are* delivered stay ordered and uncorrupted.
    pub fn advance_to(&self, now: u64) {
        let mut st = self.state.borrow_mut();
        if now > st.now {
            st.now = now;
        }
        let now = st.now;
        for link in &mut st.links {
            if link.partitioned || link.broken {
                continue;
            }
            let mut reset_link = false;
            for dir in &mut link.dirs {
                if Self::deliver_direction(dir, now) {
                    reset_link = true;
                }
            }
            if reset_link {
                // A mid-message drop breaks the whole link (both ends). The already-delivered prefix is
                // left readable so the reader can consume it and *then* observe the reset error on its
                // next read (the `read` path errors once `readable` is drained on a broken link); the
                // still-in-flight tail is discarded, as a `RST` drops un-sent data.
                link.broken = true;
                for dir in &mut link.dirs {
                    dir.inflight.clear();
                }
            }
        }
    }

    /// Delivers the due, in-order bytes of one direction, applying its armed transport fault if any.
    /// Returns `true` iff a `DropInMessage` fault fired and the caller must reset the whole link.
    fn deliver_direction(dir: &mut Direction, now: u64) -> bool {
        // Per-call budget: `SlowConsumer` caps how many bytes may cross this call; everything else is
        // unbounded (`u64::MAX`). Decremented as bytes are delivered.
        let mut budget: u64 = match dir.fault {
            Some(ArmedFault {
                kind: FaultKind::SlowChunk { chunk },
                ..
            }) => chunk,
            _ => u64::MAX,
        };

        while budget > 0 {
            // Peek the next due segment.
            let Some(seg) = dir.inflight.front() else {
                break;
            };
            if seg.due > now {
                break;
            }

            // How many bytes of this segment are eligible to cross this call (segment size capped by
            // the per-call budget).
            let take = (seg.data.len() as u64).min(budget) as usize;

            // A one-shot offset fault (drop/truncate) may cut the crossing short *within* this segment.
            if let Some(ArmedFault { kind, fired: false }) = dir.fault {
                let trigger = match kind {
                    FaultKind::DropAt { at } | FaultKind::TruncateAt { at } => Some(at),
                    FaultKind::SlowChunk { .. } => None,
                };
                if let Some(at) = trigger {
                    // Bytes deliverable before reaching the trigger offset on this direction.
                    let remaining_to_trigger = at.saturating_sub(dir.delivered);
                    if remaining_to_trigger <= take as u64 {
                        // The trigger lands inside (or at the end of) this crossing. Deliver exactly up
                        // to the offset, then act on the fault.
                        let prefix = remaining_to_trigger as usize;
                        let seg = dir.inflight.front_mut().expect("front exists");
                        let moved: Vec<u8> = seg.data.drain(..prefix).collect();
                        dir.readable.extend(moved);
                        dir.delivered += prefix as u64;
                        if seg.data.is_empty() {
                            dir.inflight.pop_front();
                        }
                        dir.fault = Some(ArmedFault { kind, fired: true });
                        match kind {
                            FaultKind::DropAt { .. } => return true, // reset the whole link
                            FaultKind::TruncateAt { .. } => {
                                // Stall: half-close so the reader EOFs after the prefix, and discard the
                                // rest of the stream so it never completes.
                                dir.write_closed = true;
                                dir.inflight.clear();
                                return false;
                            }
                            FaultKind::SlowChunk { .. } => unreachable!("offset trigger only"),
                        }
                    }
                }
            }

            // No fault cut this crossing short: move `take` bytes (whole segment, or budget-capped).
            let seg = dir.inflight.front_mut().expect("front exists");
            if take == seg.data.len() {
                let seg = dir.inflight.pop_front().expect("front exists");
                let n = seg.data.len() as u64;
                dir.readable.extend(seg.data);
                dir.delivered += n;
                budget -= n;
            } else {
                let moved: Vec<u8> = seg.data.drain(..take).collect();
                dir.readable.extend(moved);
                dir.delivered += take as u64;
                budget -= take as u64;
            }
        }
        false
    }

    /// Partitions `link`: it stops delivering (in-flight bytes are held) until [`Self::heal`].
    pub fn partition(&self, link: LinkId) {
        self.state.borrow_mut().links[link.0].partitioned = true;
    }

    /// Heals a partitioned `link`; held bytes deliver on the next [`Self::advance_to`].
    pub fn heal(&self, link: LinkId) {
        self.state.borrow_mut().links[link.0].partitioned = false;
    }

    /// Resets `link`: drops all in-flight and undelivered bytes and marks both ends broken, so every
    /// further read/write errors (models an abrupt connection reset / peer crash).
    pub fn reset(&self, link: LinkId) {
        let mut st = self.state.borrow_mut();
        let l = &mut st.links[link.0];
        l.broken = true;
        for dir in &mut l.dirs {
            dir.inflight.clear();
            dir.readable.clear();
        }
    }

    /// Half-closes the write side of `side` on `link`: once the peer drains the already-delivered
    /// bytes, its reads return `Ok(0)` (EOF). Models an orderly shutdown.
    pub fn close(&self, link: LinkId, side: Side) {
        self.state.borrow_mut().links[link.0].dirs[side.write_dir()].write_closed = true;
    }
}

/// One end of a [`SimNet`] link — a deterministic, in-memory [`Transport`].
#[derive(Debug, Clone)]
pub struct SimEndpoint {
    net: Rc<RefCell<NetState>>,
    link: usize,
    side: Side,
}

impl SimEndpoint {
    /// The number of bytes already delivered to this endpoint and waiting to be read (does not
    /// include bytes still in flight). Lets a cooperative driver decide whether a read will make
    /// progress without treating an empty open stream as EOF.
    #[must_use]
    pub fn readable_len(&self) -> usize {
        let st = self.net.borrow();
        st.links[self.link].dirs[self.side.read_dir()]
            .readable
            .len()
    }

    /// Whether this endpoint is at a genuine end-of-stream: the peer has half-closed (or the link was
    /// reset) **and** all delivered bytes have been read. Distinguishes EOF from momentary starvation
    /// (an open link with bytes still in flight).
    #[must_use]
    pub fn is_eof(&self) -> bool {
        let st = self.net.borrow();
        let link = &st.links[self.link];
        let dir = &link.dirs[self.side.read_dir()];
        dir.readable.is_empty() && (link.broken || (dir.write_closed && dir.inflight.is_empty()))
    }

    /// Whether the link this endpoint belongs to has been reset (broken).
    #[must_use]
    pub fn is_broken(&self) -> bool {
        self.net.borrow().links[self.link].broken
    }
}

impl Transport for SimEndpoint {
    fn read(&mut self, buf: &mut [u8]) -> BoltResult<usize> {
        let mut st = self.net.borrow_mut();
        let link = &mut st.links[self.link];
        let broken = link.broken;
        let dir = &mut link.dirs[self.side.read_dir()];
        if broken && dir.readable.is_empty() {
            // A reset link, fully drained: surface a transport failure so the session sees an error
            // rather than a silent EOF. Any prefix delivered *before* the reset (e.g. a mid-message
            // drop) is still drained first, so the reader can consume it before observing the reset.
            return Err(BoltError::Transport(
                "simulated connection reset".to_owned(),
            ));
        }
        if dir.readable.is_empty() {
            // Open-but-starved or genuine EOF both surface as `Ok(0)`; the cooperative driver calls
            // `SimNet::advance_to` before reading and uses `is_eof()` to tell them apart (module docs).
            return Ok(0);
        }
        let n = buf.len().min(dir.readable.len());
        for slot in buf.iter_mut().take(n) {
            *slot = dir.readable.pop_front().expect("readable non-empty");
        }
        Ok(n)
    }

    fn write_all(&mut self, bytes: &[u8]) -> BoltResult<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let mut st = self.net.borrow_mut();
        let now = st.now;
        let (min, max) = (st.config.min_latency, st.config.max_latency);
        let latency = st.rng.range_inclusive(min, max);
        let link = &mut st.links[self.link];
        if link.broken {
            return Err(BoltError::Transport(
                "simulated connection reset".to_owned(),
            ));
        }
        let dir = &mut link.dirs[self.side.write_dir()];
        if dir.write_closed {
            return Err(BoltError::Transport("write after half-close".to_owned()));
        }
        // Keep delivery monotonic per direction (reliable, in-order like TCP): a segment is never due
        // before the previous one on the same direction.
        let due = dir.last_due.max(now).saturating_add(latency);
        dir.last_due = due;
        dir.inflight.push_back(Segment {
            data: bytes.to_vec(),
            due,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes `msg` from `from`, then advances time in unit steps until the peer can read it back;
    /// returns the logical time at which the whole message had arrived.
    fn send_and_drain(
        net: &SimNet,
        link: LinkId,
        from: Side,
        to: Side,
        msg: &[u8],
    ) -> (u64, Vec<u8>) {
        net.endpoint(link, from).write_all(msg).expect("write");
        let mut got = Vec::new();
        let mut t = net.now();
        let mut reader = net.endpoint(link, to);
        // Advance until everything in flight has been delivered and read.
        loop {
            t += 1;
            net.advance_to(t);
            let mut buf = [0u8; 64];
            loop {
                let n = reader.read(&mut buf).expect("read");
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            if got.len() >= msg.len() {
                break;
            }
        }
        (t, got)
    }

    #[test]
    fn round_trips_bytes_through_a_real_transport() {
        let net = SimNet::with_seed(1);
        let link = net.connect();
        let (_, got) = send_and_drain(&net, link, Side::Client, Side::Server, b"HELLO bolt");
        assert_eq!(
            got, b"HELLO bolt",
            "client→server bytes arrive intact and in order"
        );

        let (_, back) = send_and_drain(&net, link, Side::Server, Side::Client, b"SUCCESS");
        assert_eq!(
            back, b"SUCCESS",
            "server→client bytes arrive intact and in order"
        );
    }

    #[test]
    fn delivery_order_across_links_is_deterministic_per_seed() {
        // Two links; write one message on each at t=0; the seed-drawn latencies decide which arrives
        // first. The arrival order must be identical for the same seed.
        let arrival_order = |seed: u64| -> Vec<&'static str> {
            let net = SimNet::new(
                seed,
                NetConfig {
                    min_latency: 1,
                    max_latency: 50,
                },
            );
            let a = net.connect();
            let b = net.connect();
            net.endpoint(a, Side::Client)
                .write_all(b"A")
                .expect("write a");
            net.endpoint(b, Side::Client)
                .write_all(b"B")
                .expect("write b");
            let mut ra = net.endpoint(a, Side::Server);
            let mut rb = net.endpoint(b, Side::Server);
            let mut order = Vec::new();
            for t in 1..=100 {
                net.advance_to(t);
                let mut buf = [0u8; 4];
                if ra.read(&mut buf).expect("ra") > 0 && !order.contains(&"A") {
                    order.push("A");
                }
                if rb.read(&mut buf).expect("rb") > 0 && !order.contains(&"B") {
                    order.push("B");
                }
            }
            order
        };

        let first = arrival_order(12_345);
        let again = arrival_order(12_345);
        assert_eq!(
            first, again,
            "same seed ⇒ identical cross-link arrival order"
        );
        assert_eq!(first.len(), 2, "both messages arrive (non-vacuous)");
    }

    #[test]
    fn different_seeds_can_change_arrival_order() {
        // Search a handful of seeds; at least one pair must differ, proving the order is seed-driven
        // (not a fixed schedule). Deterministic: the seed list is fixed.
        let order = |seed: u64| -> Vec<u64> {
            let net = SimNet::new(
                seed,
                NetConfig {
                    min_latency: 1,
                    max_latency: 100,
                },
            );
            let links: Vec<LinkId> = (0..4).map(|_| net.connect()).collect();
            for (i, l) in links.iter().enumerate() {
                net.endpoint(*l, Side::Client)
                    .write_all(&[i as u8])
                    .expect("write");
            }
            let mut readers: Vec<SimEndpoint> = links
                .iter()
                .map(|l| net.endpoint(*l, Side::Server))
                .collect();
            let mut order = Vec::new();
            for t in 1..=200 {
                net.advance_to(t);
                for (i, r) in readers.iter_mut().enumerate() {
                    let mut buf = [0u8; 1];
                    if r.read(&mut buf).expect("read") > 0 && !order.contains(&(i as u64)) {
                        order.push(i as u64);
                    }
                }
            }
            order
        };

        let baseline = order(1);
        let differs = (2..40).any(|s| order(s) != baseline);
        assert!(differs, "some seed must reorder the four links vs. seed 1");
    }

    #[test]
    fn partition_holds_delivery_until_healed() {
        let net = SimNet::with_seed(5);
        let link = net.connect();
        net.endpoint(link, Side::Client)
            .write_all(b"X")
            .expect("write");
        net.partition(link);

        let mut reader = net.endpoint(link, Side::Server);
        net.advance_to(1000);
        let mut buf = [0u8; 8];
        assert_eq!(
            reader.read(&mut buf).expect("read"),
            0,
            "partition holds the byte"
        );

        net.heal(link);
        net.advance_to(2000);
        assert_eq!(
            reader.read(&mut buf).expect("read"),
            1,
            "healed link delivers"
        );
        assert_eq!(&buf[..1], b"X");
    }

    #[test]
    fn reset_breaks_both_ends() {
        let net = SimNet::with_seed(5);
        let link = net.connect();
        net.endpoint(link, Side::Client)
            .write_all(b"data")
            .expect("write");
        net.reset(link);

        let mut reader = net.endpoint(link, Side::Server);
        let mut buf = [0u8; 8];
        assert!(
            reader.read(&mut buf).is_err(),
            "a reset link errors on read"
        );
        assert!(
            net.endpoint(link, Side::Client).write_all(b"more").is_err(),
            "a reset link errors on write",
        );
        assert!(reader.is_broken());
    }

    /// Drives a faulted direction to quiescence: write the whole message, then step time in unit
    /// increments (bounded, so a test can never hang) collecting reads until EOF, a reset, or the step
    /// cap. Returns the bytes read, whether the link broke, and whether the reader hit a clean EOF.
    fn drain_with_steps(
        net: &SimNet,
        link: LinkId,
        reader_side: Side,
        max_steps: u64,
    ) -> (Vec<u8>, bool, bool) {
        let mut reader = net.endpoint(link, reader_side);
        let mut got = Vec::new();
        let mut t = net.now();
        let mut broke = false;
        let mut eof = false;
        for _ in 0..max_steps {
            t += 1;
            net.advance_to(t);
            let mut buf = [0u8; 64];
            match reader.read(&mut buf) {
                Ok(0) => {
                    if reader.is_eof() {
                        eof = true;
                        break;
                    }
                }
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(_) => {
                    broke = true;
                    break;
                }
            }
        }
        (got, broke, eof)
    }

    #[test]
    fn drop_in_message_resets_link_at_byte_offset() {
        let net = SimNet::with_seed(3);
        let link = net.connect();
        // 200-byte "message"; arm a reset somewhere inside the first 64 delivered bytes.
        let msg: Vec<u8> = (0..200u16).map(|i| i as u8).collect();
        net.arm_transport_fault(
            link,
            Side::Server,
            TransportFaultPlan::new(0xF00D).drop_in_message(64),
        );
        net.endpoint(link, Side::Client)
            .write_all(&msg)
            .expect("write");

        let (got, broke, eof) = drain_with_steps(&net, link, Side::Server, 10_000);
        assert!(broke, "a mid-message drop resets the link (read errors)");
        assert!(!eof, "a reset is not a clean EOF");
        assert!(
            got.len() < msg.len(),
            "the reset truncates the message: got {} of {}",
            got.len(),
            msg.len()
        );
        assert!(
            (1..=64).contains(&got.len()),
            "bytes delivered before the reset land in [1, 64], got {}",
            got.len()
        );
        assert_eq!(
            &got[..],
            &msg[..got.len()],
            "delivered prefix is uncorrupted"
        );
        assert!(net.endpoint(link, Side::Server).is_broken());
    }

    #[test]
    fn truncate_then_stall_yields_prefix_then_eof() {
        let net = SimNet::with_seed(9);
        let link = net.connect();
        let msg: Vec<u8> = (0..200u16).map(|i| i as u8).collect();
        net.arm_transport_fault(
            link,
            Side::Server,
            TransportFaultPlan::new(0xBEEF).truncate_then_stall(48),
        );
        net.endpoint(link, Side::Client)
            .write_all(&msg)
            .expect("write");

        let (got, broke, eof) = drain_with_steps(&net, link, Side::Server, 10_000);
        assert!(
            !broke,
            "a truncate-then-stall is a clean half-close, not a reset"
        );
        assert!(
            eof,
            "the reader reaches EOF after the truncated prefix (no hang)"
        );
        assert!(
            (1..=48).contains(&got.len()),
            "only the seeded prefix (1..=48) is delivered, got {}",
            got.len()
        );
        assert_eq!(
            &got[..],
            &msg[..got.len()],
            "delivered prefix is uncorrupted"
        );
    }

    #[test]
    fn slow_consumer_delivers_everything_in_small_chunks() {
        let net = SimNet::with_seed(15);
        let link = net.connect();
        let msg: Vec<u8> = (0..300u16).map(|i| (i % 256) as u8).collect();
        net.arm_transport_fault(
            link,
            Side::Server,
            TransportFaultPlan::new(0x51E0).slow_consumer(8),
        );
        net.endpoint(link, Side::Client)
            .write_all(&msg)
            .expect("write");

        // Each advance step delivers at most `chunk` (1..=8) bytes; with a generous step cap the whole
        // message still arrives, in order, uncorrupted (a slow consumer throttles rate, not content).
        let mut reader = net.endpoint(link, Side::Server);
        let mut got = Vec::new();
        let mut t = net.now();
        let mut max_step = 0usize;
        for _ in 0..10_000 {
            t += 1;
            let before = reader.readable_len();
            net.advance_to(t);
            // Bytes the network moved into the readable buffer this step (the throttled rate).
            max_step = max_step.max(reader.readable_len() - before);
            let mut buf = [0u8; 64];
            let n = reader.read(&mut buf).expect("slow consumer never errors");
            if n > 0 {
                got.extend_from_slice(&buf[..n]);
            }
            if got.len() >= msg.len() {
                break;
            }
        }
        assert_eq!(
            got, msg,
            "a slow consumer still delivers every byte, in order"
        );
        assert!(
            max_step <= 8,
            "delivery is throttled to <= chunk (8) bytes per advance step, saw {max_step}"
        );
    }

    #[test]
    fn transport_fault_is_deterministic_per_seed() {
        let run = |seed: u64| -> (Vec<u8>, bool, bool) {
            let net = SimNet::with_seed(1);
            let link = net.connect();
            let msg: Vec<u8> = (0..200u16).map(|i| i as u8).collect();
            net.arm_transport_fault(
                link,
                Side::Server,
                TransportFaultPlan::new(seed).drop_in_message(128),
            );
            net.endpoint(link, Side::Client)
                .write_all(&msg)
                .expect("write");
            drain_with_steps(&net, link, Side::Server, 10_000)
        };
        assert_eq!(
            run(0xABC),
            run(0xABC),
            "same seed ⇒ identical fault outcome"
        );
        // Different seeds should be able to pick a different drop offset (non-vacuous determinism).
        let baseline = run(1).0.len();
        assert!(
            (2..40).any(|s| run(s).0.len() != baseline),
            "some seed must drop at a different offset than seed 1"
        );
    }

    #[test]
    fn close_yields_eof_after_drain() {
        let net = SimNet::with_seed(5);
        let link = net.connect();
        net.endpoint(link, Side::Client)
            .write_all(b"bye")
            .expect("write");
        net.close(link, Side::Client);
        net.advance_to(1000);

        let mut reader = net.endpoint(link, Side::Server);
        let mut buf = [0u8; 8];
        let n = reader.read(&mut buf).expect("read");
        assert_eq!(
            &buf[..n],
            b"bye",
            "delivered bytes are still readable after close"
        );
        assert!(reader.is_eof(), "drained + half-closed ⇒ EOF");
        assert_eq!(reader.read(&mut buf).expect("read"), 0, "EOF reads as 0");
    }
}
