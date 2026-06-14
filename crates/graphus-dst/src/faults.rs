//! `faults` — environment-fault scenarios for the deterministic harness (rmp #167): **crash +
//! restart durability** over the wire, and **network-fault resilience** (partition / reset).
//!
//! Crash-restart proves the inviolable ACID guarantee end-to-end *through the Bolt protocol*: every
//! acknowledged commit survives a power loss, and nothing un-acknowledged does — rebuilt purely from
//! the durable WAL via [`LocalEngine::crash_restart`], the wire-level analogue of the storage
//! harness's recovery. Network faults prove the real `BoltSession` copes with a dead/partitioned link
//! without panicking or hanging.

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;

    use graphus_bolt::server::BoltSession;
    use graphus_bolt::{Request, Response, Transport};
    use graphus_server::engine::LocalEngine;
    use graphus_sim::{SharedClock, Side, SimNet};

    use crate::wire::{
        LocalBoltExecutor, SharedEngine, login_prologue, run_scripted_bolt_session, sim_auth,
    };

    fn clock() -> Arc<dyn graphus_core::capability::Clock + Send + Sync> {
        Arc::new(SharedClock::new(0))
    }

    fn engine() -> SharedEngine {
        Rc::new(RefCell::new(
            LocalEngine::in_memory(clock(), 256).expect("engine"),
        ))
    }

    /// A Bolt session that auto-commits `create`, then MATCHes `match_q` back, returning the decoded
    /// responses.
    fn session(eng: SharedEngine, seed: u64, stmts: &[&str]) -> Vec<Response> {
        let auth = sim_auth();
        let mut reqs = login_prologue();
        for q in stmts {
            reqs.push(Request::Run {
                query: (*q).to_owned(),
                parameters: vec![],
                extra: vec![],
            });
            reqs.push(Request::Pull { n: -1, qid: None });
        }
        reqs.push(Request::Goodbye);
        run_scripted_bolt_session(eng, seed, &auth, &reqs).expect("session runs")
    }

    fn has_record_containing(responses: &[Response], needle: &str) -> bool {
        responses.iter().any(|r| match r {
            Response::Record { values } => values.iter().any(|v| format!("{v:?}").contains(needle)),
            _ => false,
        })
    }

    /// An acknowledged (auto-committed) write made over Bolt survives a crash + restart and is
    /// readable again over Bolt — end-to-end durability through the protocol.
    #[test]
    fn acked_commit_survives_crash_restart_over_bolt() {
        let eng = engine();
        let created = session(eng.clone(), 1, &["CREATE (:Person {name: 'Ada'})"]);
        assert!(
            !created.iter().any(|r| matches!(r, Response::Failure { .. })),
            "the create commits cleanly: {created:?}"
        );

        // Crash (drop the live engine) and restart purely from the durable WAL.
        let restarted = eng
            .borrow()
            .crash_restart(clock(), 256)
            .expect("recover from WAL");
        drop(eng);
        let eng2: SharedEngine = Rc::new(RefCell::new(restarted));

        let read = session(eng2, 2, &["MATCH (p:Person) RETURN p.name AS name"]);
        assert!(
            has_record_containing(&read, "Ada"),
            "the acked commit survived crash + restart: {read:?}"
        );
    }

    /// An explicit transaction left **uncommitted** before a crash leaves no trace after restart
    /// (atomicity: committed-or-nothing).
    #[test]
    fn uncommitted_write_does_not_survive_crash_restart() {
        let eng = engine();
        // BEGIN + CREATE + PULL, then GOODBYE with NO COMMIT — the write is never acknowledged.
        let auth = sim_auth();
        let mut reqs = login_prologue();
        reqs.extend([
            Request::Begin { extra: vec![] },
            Request::Run {
                query: "CREATE (:Ghost {x: 1})".to_owned(),
                parameters: vec![],
                extra: vec![],
            },
            Request::Pull { n: -1, qid: None },
            Request::Goodbye,
        ]);
        let _ = run_scripted_bolt_session(eng.clone(), 1, &auth, &reqs).expect("runs");

        let restarted = eng.borrow().crash_restart(clock(), 256).expect("recover");
        drop(eng);
        let eng2: SharedEngine = Rc::new(RefCell::new(restarted));

        let read = session(eng2, 2, &["MATCH (g:Ghost) RETURN g"]);
        assert!(
            !read.iter().any(|r| matches!(r, Response::Record { .. })),
            "an uncommitted write must not survive a crash: {read:?}"
        );
    }

    /// Crash-restart is deterministic: the recovered state reads identically on replay.
    #[test]
    fn crash_restart_is_deterministic() {
        let recover_and_read = || {
            let eng = engine();
            let _ = session(
                eng.clone(),
                7,
                &["CREATE (:N {v: 1})", "CREATE (:N {v: 2})"],
            );
            let restarted = eng.borrow().crash_restart(clock(), 256).expect("recover");
            drop(eng);
            let eng2: SharedEngine = Rc::new(RefCell::new(restarted));
            let read = session(eng2, 9, &["MATCH (n:N) RETURN n.v AS v ORDER BY n.v"]);
            format!("{read:?}")
        };
        assert_eq!(recover_and_read(), recover_and_read(), "recovery replays identically");
    }

    /// A partitioned link delivers nothing: the real `BoltSession` reads EOF and ends without
    /// panicking or hanging (liveness under a dead network).
    #[test]
    fn partitioned_link_is_handled_without_panic() {
        let eng = engine();
        let net = SimNet::with_seed(1);
        let link = net.connect();

        // The client sends a full handshake, but the link is partitioned so nothing is delivered.
        let mut input = graphus_bolt::server::encode_client_handshake([
            graphus_bolt::Proposal::range(5, 4, 4),
            graphus_bolt::Proposal::exact(0, 0),
            graphus_bolt::Proposal::exact(0, 0),
            graphus_bolt::Proposal::exact(0, 0),
        ]);
        input.extend_from_slice(b"more bytes that will never arrive");
        net.endpoint(link, Side::Client).write_all(&input).expect("write");
        net.partition(link);
        net.advance_to(1_000_000);

        let auth = sim_auth();
        let executor = LocalBoltExecutor::new(eng);
        let mut sess = BoltSession::new(net.endpoint(link, Side::Server), executor, &auth);
        // The contract: this returns (no panic, no hang). Result is Ok or Err — both fine.
        let _ = sess.run();
    }

    /// A link reset mid-handshake surfaces as a transport error to the session, never a panic.
    #[test]
    fn reset_link_surfaces_transport_error() {
        let eng = engine();
        let net = SimNet::with_seed(1);
        let link = net.connect();
        net.endpoint(link, Side::Client)
            .write_all(b"\x60\x60\xb0\x17partial handshake")
            .expect("write");
        net.advance_to(10);
        net.reset(link);

        let auth = sim_auth();
        let executor = LocalBoltExecutor::new(eng);
        let mut sess = BoltSession::new(net.endpoint(link, Side::Server), executor, &auth);
        let result = sess.run();
        assert!(result.is_err(), "a reset link makes the session fail, not panic");
    }
}
