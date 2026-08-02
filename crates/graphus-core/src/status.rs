//! **Verbatim Neo4j status codes for driver-observable transaction failures**, and the constructors
//! that carry them to the wire (`rmp` task #988).
//!
//! # Why this module exists
//!
//! A Bolt `FAILURE` code is not decoration: the official Neo4j drivers **branch on it**. For a
//! managed transaction (`session.executeRead` / `executeWrite`, `session.execute_read` /
//! `execute_write`) the driver reads the *classification* — the second dotted segment of
//! `Neo.<Classification>.<Category>.<Title>` — and decides whether to **replay the unit of work**:
//!
//! * `TransientError` ⇒ retryable. The driver sleeps and replays, up to `maxTransactionRetryTime`
//!   (**30 s** by default in every official driver).
//! * `ClientError` / `DatabaseError` ⇒ not retryable. The driver fails the call **immediately**.
//!
//! So announcing a *permanent* fault as `TransientError` does not merely mislabel it — it makes the
//! driver burn its entire 30-second budget replaying a unit of work that cannot ever succeed, and
//! then surface a timeout instead of the real cause. That is the defect this module closes.
//!
//! Under MVCC/SSI a genuine serialization abort is normal and expected under contention, and it
//! *must* stay retryable. The retryability contract is therefore load-bearing infrastructure: the
//! client has to be able to tell "try again" from "this can never work". Deriving that answer from
//! the [`GraphusError`] variant alone cannot do it, because [`GraphusError::Transaction`] covers both
//! a serialization abort (retryable) and a pile of permanent misuse errors (not retryable).
//!
//! # How a code is carried to the wire
//!
//! Through the established verbatim-leaf-code mechanism
//! ([`wire_status_code_message`](crate::wire_status_code_message), `rmp` task #814): the message is
//! framed as `<sentinel><leaf code>\u{1f}<human>`, and the Bolt renderer
//! (`graphus_bolt::error::failure_from_error`) and the REST renderer
//! (`graphus_rest::problem::Problem::from_graphus_error`) emit the leaf code verbatim.
//!
//! That mechanism has one **invariant**: the carrier [`GraphusError`] variant must *agree*, on
//! classification, with the leaf code it carries — so that even a renderer that did not strip the
//! sentinel would still give the driver the right retry answer. Every constructor here is the single
//! place that pairing is made, which is why the codes are not exposed as loose constants for callers
//! to combine by hand.
//!
//! | Constructor | leaf code | classification | retryable | carrier variant (fallback code) |
//! | --- | --- | --- | --- | --- |
//! | [`write_in_read_access_mode`] | `Neo.ClientError.Statement.AccessMode` | `ClientError` | no | [`GraphusError::Runtime`] (`Neo.ClientError.Statement.ArgumentError`) |
//! | [`transaction_not_found`] | `Neo.ClientError.Transaction.TransactionNotFound` | `ClientError` | no | [`GraphusError::Protocol`] (`Neo.ClientError.Request.Invalid`) |
//! | [`transaction_timed_out`] | `Neo.ClientError.Transaction.TransactionTimedOut` | `ClientError` | no | [`GraphusError::Runtime`] (`Neo.ClientError.Statement.ArgumentError`) |
//! | [`illegal_transaction_request`] | `Neo.ClientError.Request.Invalid` | `ClientError` | no | [`GraphusError::Protocol`] (same code — no sentinel needed) |
//! | [`database_unavailable`] | `Neo.TransientError.General.DatabaseUnavailable` | `TransientError` | **yes** | [`GraphusError::Transaction`] (`Neo.TransientError.Transaction.Outdated`) |
//!
//! A genuine serialization abort keeps using a bare [`GraphusError::Transaction`], which renders as
//! the retryable `Neo.TransientError.Transaction.Outdated` (`rmp` #612 — the title must not be
//! `Terminated`/`LockClientStopped`, which the drivers' `ERROR_REWRITE_MAP` downgrades to a
//! non-retryable `ClientError`).
//!
//! # Provenance
//!
//! Every code below is **verbatim** from the reference server's own status catalogue,
//! `org.neo4j.kernel.api.exceptions.Status` (`community/common/src/main/java/org/neo4j/kernel/api/
//! exceptions/Status.java`), which is also what
//! <https://neo4j.com/docs/status-codes/current/errors/all-errors/> is generated from. None is
//! invented. Each constant records the enum member, its `Classification`, and the reference server's
//! own description.

use crate::error::{GraphusError, wire_status_code_message};

/// `Neo.ClientError.Statement.AccessMode` — "The request could not be completed due to access mode
/// violation".
///
/// Reference server: `Status.Statement.AccessMode(ClientError, …)`. It is the code Neo4j raises when
/// a statement writes inside a read-access-mode transaction —
/// `QueryRouterException.writeInReadAccessMode` / `FabricException` build it with
/// `WRITING_IN_READ_NOT_ALLOWED_MSG`, and Neo4j's own HTTP Query API integration test asserts it is
/// answered with HTTP **400** (`QueryResourceTxConfigIT`: `hasErrorStatus(400,
/// Status.Statement.AccessMode)`).
const ACCESS_MODE: &str = "Neo.ClientError.Statement.AccessMode";

/// `Neo.ClientError.Transaction.TransactionNotFound` — "The request referred to a transaction that
/// does not exist."
///
/// Reference server: `Status.Transaction.TransactionNotFound(ClientError, …)`, raised by
/// `InvalidTransactionId.transactionDoesNotExists` on the HTTP transactional endpoint. Neo4j answers
/// the REST twin with HTTP **404** (`TransactionNotFoundException` passes `Response.Status.NOT_FOUND`).
///
/// Reserved for a transaction that genuinely **does not exist**: an id that was never issued, or one
/// already spent by a `COMMIT`/`ROLLBACK`. A transaction the maximum-transaction-age sweep reaped is
/// deliberately **not** in this class — it existed and was stopped for cause, and says so with
/// [`TRANSACTION_TIMED_OUT`].
const TRANSACTION_NOT_FOUND: &str = "Neo.ClientError.Transaction.TransactionNotFound";

/// `Neo.ClientError.Transaction.TransactionTimedOut` — "The transaction has not completed within the
/// specified timeout (db.transaction.timeout). You may want to retry with a longer timeout."
///
/// Reference server: `Status.Transaction.TransactionTimedOut(ClientError, …)`, the **server-configured**
/// half of Neo4j's deliberate pair. `KernelImpl` picks between the two by *who supplied the bound*:
/// `TransactionTimeout(config.get(transaction_timeout), TransactionTimedOut)` for the server's own
/// setting, and `TransactionTimedOutClientConfiguration` for a bound the client sent. Graphus's
/// `timing.max_transaction_age_ms` sweep is the exact analogue of the former; the Bolt `tx_timeout`
/// path already emits the latter, so the pair is now symmetric on both sides.
///
/// It is distinct from [`TRANSACTION_NOT_FOUND`] on purpose: a transaction the age sweep reaped *did*
/// exist and was stopped for exceeding a configured limit. Telling its owner "does not exist" is
/// factually different and throws away the one fact an operator needs — it sends them looking for a
/// transaction-lifecycle bug when the cause is a configuration bound.
const TRANSACTION_TIMED_OUT: &str = "Neo.ClientError.Transaction.TransactionTimedOut";

/// `Neo.TransientError.General.DatabaseUnavailable` — "The database is not currently available to
/// serve your request, refer to the database logs for more details. Retrying your request at a later
/// time may succeed."
///
/// Reference server: `Status.General.DatabaseUnavailable(TransientError, …)`, carrying an explicit
/// source comment that it must **not** be moved out of the `General` namespace "as downstream clients
/// depend on the string representation being `Neo.TransientError.General.DatabaseUnavailable`". It is
/// the one code whose retryability is genuinely *correct* here: a server that is shutting down or has
/// released its engine may be reachable again later, and a driver that reconnects can succeed.
const DATABASE_UNAVAILABLE: &str = "Neo.TransientError.General.DatabaseUnavailable";

/// The error for a **write statement inside a READ-access-mode transaction** — the headline case of
/// `rmp` #988.
///
/// A client that calls `session.executeRead` and runs a `CREATE` has made a permanent mistake: no
/// amount of replay makes a write legal in a read transaction. Before this, the failure was announced
/// as the retryable `Neo.TransientError.Transaction.Outdated`, so the driver replayed it until
/// `maxTransactionRetryTime` (30 s) was spent and then reported a timeout instead of the real cause.
///
/// Human message: the reference server's own wording,
/// `FabricExecutor.WRITING_IN_READ_NOT_ALLOWED_MSG` = "Writing in read access mode not allowed",
/// extended with the detail that identifies *which* statement and mode were involved.
#[must_use]
pub fn write_in_read_access_mode() -> GraphusError {
    GraphusError::Runtime(wire_status_code_message(
        ACCESS_MODE,
        "Writing in read access mode not allowed; the statement performs writes but its transaction \
         was opened in READ mode",
    ))
}

/// The error for a request naming a **transaction that does not exist**: a stale Bolt ticket, a spent
/// REST handle, a transaction that has already been committed or rolled back, or one the
/// maximum-transaction-age sweep has reaped.
///
/// Permanent, and not retryable: the transaction the request names is gone, so replaying the *same*
/// request against the *same* id can never find it. (A driver's managed-transaction retry is a
/// different thing — it opens a fresh transaction — but it is not what this code drives; the client
/// is holding an id that no longer resolves.)
///
/// `detail` names the operation and the id, and is appended to the reference server's own wording for
/// this condition (`InvalidTransactionId`).
#[must_use]
pub fn transaction_not_found(detail: &str) -> GraphusError {
    GraphusError::Protocol(wire_status_code_message(
        TRANSACTION_NOT_FOUND,
        &format!(
            "Unrecognized transaction id. Transaction may have timed out and been rolled back \
             ({detail})"
        ),
    ))
}

/// The error for a transaction the server **stopped for exceeding its maximum age**
/// (`timing.max_transaction_age_ms`), reported when its owner next touches it.
///
/// Permanent and not retryable, exactly as the reference server classifies both of its transaction
/// timeouts: replaying the same long-running unit of work would simply run past the same bound again,
/// and a driver that retried it would burn its budget doing so. The client is told *why* its
/// transaction is gone, which [`transaction_not_found`] cannot express.
#[must_use]
pub fn transaction_timed_out(detail: &str) -> GraphusError {
    GraphusError::Runtime(wire_status_code_message(
        TRANSACTION_TIMED_OUT,
        &format!(
            "The transaction has not completed within the maximum transaction age configured on the \
             server (`timing.max_transaction_age_ms`); it has been rolled back ({detail})"
        ),
    ))
}

/// The error for a Bolt request that is **illegal for the session's current transaction state**:
/// `RUN` in an explicit transaction when none is open, `BEGIN` when one already is, `COMMIT` or
/// `ROLLBACK` with nothing open.
///
/// The reference server treats exactly these as state-machine violations and answers
/// `Neo.ClientError.Request.Invalid`: `org.neo4j.bolt.fsm.error.state.IllegalTransitionException`
/// returns `Request.Invalid` with "Message of type … cannot be handled by a session in the … state",
/// and `BoltException` likewise. `ClientError` ⇒ the driver fails immediately, which is right — the
/// client's message sequence is wrong and replaying it reproduces the same violation.
///
/// No sentinel is attached: `Neo.ClientError.Request.Invalid` is already what
/// [`GraphusError::Protocol`] renders as on both wires, so the variant *is* the code. Routing these
/// through one constructor keeps the choice documented and greppable.
#[must_use]
pub fn illegal_transaction_request(detail: impl Into<String>) -> GraphusError {
    GraphusError::Protocol(detail.into())
}

/// The error for an **engine that is no longer serving**: the server is shutting down, or a local
/// engine has been consumed by its `shutdown`.
///
/// Genuinely transient, and genuinely retryable — but a *different* transient class from a
/// serialization conflict, which is why it was wrong to share
/// `Neo.TransientError.Transaction.Outdated` with it. `Outdated` tells a client "your transaction
/// lost a race, replay it"; `DatabaseUnavailable` tells it "this database cannot serve you right now,
/// come back (or fail over) later" — the distinction a routing driver acts on.
#[must_use]
pub fn database_unavailable(detail: &str) -> GraphusError {
    GraphusError::Transaction(wire_status_code_message(DATABASE_UNAVAILABLE, detail))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{WIRE_STATUS_CODE_PREFIX, WIRE_STATUS_CODE_SEP};

    /// Splits the verbatim leaf code out of a framed message, or `None` when it carries no sentinel.
    fn leaf_of(e: &GraphusError) -> Option<String> {
        let s = e.to_string();
        let start = s.find(WIRE_STATUS_CODE_PREFIX)? + WIRE_STATUS_CODE_PREFIX.len();
        let rest = &s[start..];
        Some(rest.split(WIRE_STATUS_CODE_SEP).next()?.to_owned())
    }

    #[test]
    fn every_constructor_pairs_its_leaf_code_with_an_agreeing_carrier_variant() {
        // The invariant the whole verbatim-leaf-code mechanism rests on (`rmp` #814): the carrier
        // variant's OWN fallback classification must agree with the leaf code's classification, so a
        // renderer that failed to strip the sentinel would still give the driver the same retry
        // answer. `Runtime`/`Protocol` fall back to `Neo.ClientError.*`; `Transaction` falls back to
        // `Neo.TransientError.*`.
        let client_faults = [
            write_in_read_access_mode(),
            transaction_not_found("x"),
            transaction_timed_out("x"),
        ];
        for e in &client_faults {
            let leaf = leaf_of(e).expect("carries a verbatim leaf code");
            assert!(
                leaf.starts_with("Neo.ClientError."),
                "expected a ClientError leaf, got {leaf}"
            );
            assert!(
                matches!(e, GraphusError::Runtime(_) | GraphusError::Protocol(_)),
                "a ClientError leaf must ride a client-fault carrier variant: {e:?}"
            );
        }

        let leaf = leaf_of(&database_unavailable("down")).expect("carries a verbatim leaf code");
        assert_eq!(leaf, "Neo.TransientError.General.DatabaseUnavailable");
        assert!(
            matches!(database_unavailable("down"), GraphusError::Transaction(_)),
            "a TransientError leaf must ride the transient carrier variant"
        );
    }

    #[test]
    fn an_illegal_transaction_request_carries_no_sentinel_because_its_variant_is_the_code() {
        let e = illegal_transaction_request("COMMIT with no open transaction");
        assert!(matches!(e, GraphusError::Protocol(_)));
        assert!(
            leaf_of(&e).is_none(),
            "Protocol already renders as Neo.ClientError.Request.Invalid; no sentinel needed"
        );
    }

    #[test]
    fn the_leaf_codes_are_the_reference_servers_verbatim_spellings() {
        // Pinned literally: these strings are a wire contract that official drivers and applications
        // branch on, so a change has to be made in two places on purpose.
        assert_eq!(ACCESS_MODE, "Neo.ClientError.Statement.AccessMode");
        assert_eq!(
            TRANSACTION_NOT_FOUND,
            "Neo.ClientError.Transaction.TransactionNotFound"
        );
        assert_eq!(
            TRANSACTION_TIMED_OUT,
            "Neo.ClientError.Transaction.TransactionTimedOut"
        );
        // The two transaction timeouts are a DELIBERATE pair and must never collapse into one: the
        // server-configured bound and the client-configured (`tx_timeout`) bound have distinct titles
        // in the reference server, and an operator diagnoses from that difference.
        assert_ne!(
            TRANSACTION_TIMED_OUT,
            "Neo.ClientError.Transaction.TransactionTimedOutClientConfiguration"
        );
        // ... and "timed out" is not "does not exist".
        assert_ne!(TRANSACTION_TIMED_OUT, TRANSACTION_NOT_FOUND);
        assert_eq!(
            DATABASE_UNAVAILABLE,
            "Neo.TransientError.General.DatabaseUnavailable"
        );
    }
}
