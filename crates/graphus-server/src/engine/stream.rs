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

use std::sync::mpsc::{Receiver, SyncSender};

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

/// The engine's end of a result stream: a bounded sender it pushes rows into.
pub type RowSender = SyncSender<RowItem>;

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
