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
}

/// A bidirectional link between two endpoints.
#[derive(Debug, Default)]
struct Link {
    dirs: [Direction; 2],
    partitioned: bool,
    broken: bool,
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

    /// Advances logical time to `now`, delivering every in-flight segment whose due time has arrived
    /// (in order, per direction) into the peer's readable buffer. A partitioned link holds its bytes.
    /// `now` never moves backwards.
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
            for dir in &mut link.dirs {
                while let Some(seg) = dir.inflight.front() {
                    if seg.due <= now {
                        let seg = dir.inflight.pop_front().expect("front exists");
                        dir.readable.extend(seg.data);
                    } else {
                        break;
                    }
                }
            }
        }
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
        if link.broken {
            // A reset link: deliver any drained-but-already-read state as an error so the session
            // surfaces a transport failure rather than a silent EOF.
            return Err(BoltError::Transport(
                "simulated connection reset".to_owned(),
            ));
        }
        let dir = &mut link.dirs[self.side.read_dir()];
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
