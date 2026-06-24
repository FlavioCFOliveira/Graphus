//! The result-row channel between the engine task and a connection's result cursor
//! (`04-technical-design.md` §7.7 result streaming, §9.3 bounded egress).
//!
//! The engine executes a query on its single thread and pushes result rows into a **bounded**
//! [`std::sync::mpsc::SyncSender`]; the connection's cursor pulls them with a blocking `recv`. The
//! bound is the egress backpressure required by §9.3 (no unbounded channel on the request path): if
//! the consumer is slow, the bounded `send` blocks the engine thread, throttling production rather
//! than buffering an unbounded result in memory.
//!
//! A `std::sync::mpsc` (not a `tokio::sync::mpsc`) is used because **both** consumer seams pull rows
//! synchronously — `graphus_bolt::RecordStream::next_record` and `graphus_rest::ResultStream::next_row`
//! are blocking trait methods. The Bolt session runs on a blocking task and the REST router's row
//! pull runs on a blocking task too (see [`crate::listeners`]), so a blocking `recv` here never
//! parks a Tokio runtime worker (`04 §9.1`).

use std::sync::mpsc::{Receiver, Sender, SyncSender};

use graphus_core::GraphusError;
use graphus_cypher::MaterializedValue;

/// One item the engine streams: a successfully-produced row, or a runtime error that aborted row
/// production (delivered as the stream's terminal item — `06 §3.2`: a runtime error may arrive after
/// some rows have already streamed).
///
/// A row's cells are [`MaterializedValue`]s — each entity already resolved to its labels / type /
/// endpoints / properties through the cursor's graph seam (so RBAC and MVCC visibility are already
/// applied). The two wire seams (`seam_bolt`/`seam_rest`) map each cell onto their protocol-native
/// structural type (`BoltValue` / `RestValue`).
pub type RowItem = Result<Vec<MaterializedValue>, GraphusError>;

/// The sentinel `result_buffer_capacity` that selects an **unbounded** egress channel instead of a
/// bounded one (see [`egress`]). The production server always passes a small, finite admission-derived
/// capacity (`04 §9.3`), so `usize::MAX` is a safe, never-collides marker; the inline single-threaded
/// [`super::LocalEngine`] passes it because, with no concurrent consumer, a bounded channel would
/// dead-lock once full (its producer and consumer are the *same* thread).
pub const UNBOUNDED: usize = usize::MAX;

/// The engine's end of a result stream. Bounded for backpressure on the production path (`04 §9.3`),
/// or unbounded for the inline [`super::LocalEngine`] (which buffers a whole result on one thread).
///
/// A single enum keeps the streaming code (`exec::run_cursor`) identical for both: it just calls
/// [`RowSender::send`]. The receiving end is the same [`Receiver<RowItem>`] in both cases, so
/// [`RowReceiver`] is unaffected.
pub enum RowSender {
    /// A bounded `SyncSender`: a full channel blocks the producer (the §9.3 egress backpressure).
    Bounded(SyncSender<RowItem>),
    /// An unbounded `Sender`: never blocks, so a single-threaded producer/consumer cannot dead-lock.
    Unbounded(Sender<RowItem>),
}

impl RowSender {
    /// Pushes one row item, returning `Err` (with the item) only if the receiver was dropped — the
    /// same contract `SyncSender::send` has, so callers (`exec::run_cursor`) need no change.
    ///
    /// # Errors
    /// [`std::sync::mpsc::SendError`] if the consumer dropped its receiver (early disconnect).
    pub fn send(&self, item: RowItem) -> Result<(), std::sync::mpsc::SendError<RowItem>> {
        match self {
            RowSender::Bounded(s) => s.send(item),
            RowSender::Unbounded(s) => s.send(item),
        }
    }

    /// **Non-blocking** push of one row item, for the resumable-cursor egress path (`rmp` task #372).
    ///
    /// Unlike [`send`](Self::send) this never blocks the engine thread on a full bounded channel:
    /// when the channel is full it returns [`TrySend::Full`] carrying the **unsent** item back, so
    /// the caller can re-suspend its cursor while *holding* that one row (no row is lost or
    /// re-pulled). The [`Unbounded`](RowSender::Unbounded) variant (the inline
    /// [`super::LocalEngine`]/DST driver) never reports `Full` — its `send` cannot block — so the
    /// resumable path collapses to today's behaviour and bit-determinism is preserved.
    pub fn try_send(&self, item: RowItem) -> TrySend {
        match self {
            RowSender::Bounded(s) => match s.try_send(item) {
                Ok(()) => TrySend::Sent,
                Err(std::sync::mpsc::TrySendError::Full(item)) => TrySend::Full(item),
                Err(std::sync::mpsc::TrySendError::Disconnected(item)) => {
                    TrySend::Disconnected(item)
                }
            },
            // Unbounded never blocks: a successful enqueue is `Sent`; the only failure is a dropped
            // receiver, which is `Disconnected`. `Full` is therefore unreachable here (preserving the
            // inline driver's determinism — see the type doc).
            RowSender::Unbounded(s) => match s.send(item) {
                Ok(()) => TrySend::Sent,
                Err(std::sync::mpsc::SendError(item)) => TrySend::Disconnected(item),
            },
        }
    }
}

/// The outcome of a non-blocking [`RowSender::try_send`] (`rmp` task #372).
pub enum TrySend {
    /// The item was enqueued.
    Sent,
    /// The bounded channel was full; the **unsent** item is returned so the caller can hold it and
    /// retry after re-suspending (never produced by the unbounded variant).
    Full(RowItem),
    /// The consumer dropped its receiver; the item could not be delivered (early disconnect).
    Disconnected(RowItem),
}

/// Builds an egress channel of `capacity`: bounded (backpressure) for any finite value, or unbounded
/// when `capacity == `[`UNBOUNDED`]. Returns the sender half and the raw receiver
/// (wrap it in [`RowReceiver::new`]).
#[must_use]
pub fn egress(capacity: usize) -> (RowSender, Receiver<RowItem>) {
    if capacity == UNBOUNDED {
        let (tx, rx) = std::sync::mpsc::channel();
        (RowSender::Unbounded(tx), rx)
    } else {
        let (tx, rx) = std::sync::mpsc::sync_channel(capacity);
        (RowSender::Bounded(tx), rx)
    }
}

/// The consumer's end of a result stream: a receiver pulled by the connection's cursor.
#[derive(Debug)]
pub struct RowReceiver {
    rx: Receiver<RowItem>,
    /// `true` once a terminal item (the channel closed, or an `Err`) has been seen, so further
    /// `recv` calls short-circuit to `None`/the error is not double-delivered.
    done: bool,
}

impl RowReceiver {
    /// Wraps a raw receiver.
    #[must_use]
    pub fn new(rx: Receiver<RowItem>) -> Self {
        Self { rx, done: false }
    }

    /// Pulls the next row, blocking until one is available, the stream ends (`Ok(None)`), or a
    /// runtime error terminates it.
    ///
    /// Blocking is intentional and safe: every caller pulls on a blocking task (`04 §9.1`). Once the
    /// channel disconnects (the engine finished and dropped its sender) or an error is returned, the
    /// stream is marked done and subsequent calls return `Ok(None)`.
    ///
    /// # Errors
    /// [`GraphusError`] if the engine reported a runtime error mid-stream.
    // Not `Iterator::next`: it returns a `Result` and pulls from a fallible channel, mirroring
    // `graphus_cypher::Cursor::next` (which carries the same allow for the same reason).
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Vec<MaterializedValue>>, GraphusError> {
        if self.done {
            return Ok(None);
        }
        match self.rx.recv() {
            Ok(Ok(row)) => Ok(Some(row)),
            Ok(Err(e)) => {
                self.done = true;
                Err(e)
            }
            // The engine dropped the sender: the stream is exhausted (normal completion).
            Err(_) => {
                self.done = true;
                Ok(None)
            }
        }
    }

    /// Drains and discards any remaining rows so the engine's bounded `send` unblocks promptly when
    /// a consumer stops early (e.g. a Bolt `DISCARD`, or a dropped cursor). Cheap and idempotent.
    pub fn drain(&mut self) {
        if self.done {
            return;
        }
        // Pull until the engine closes the channel; ignore errors (we are discarding).
        while self.rx.recv().is_ok() {}
        self.done = true;
    }
}

impl Drop for RowReceiver {
    fn drop(&mut self) {
        // If a cursor is dropped before exhaustion (early client disconnect), drain so the engine
        // thread is not left blocked on a full bounded channel waiting for a gone consumer.
        self.drain();
    }
}
