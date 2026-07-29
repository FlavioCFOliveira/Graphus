//! **A zoned datetime that arrives as a Bolt parameter must be the same value Cypher builds**
//! (`rmp` task #908).
//!
//! # What this reproduces
//!
//! Every Neo4j driver sends a datetime with a named time zone as PackStream structure `0x69`
//! (`DateTimeZoneId`): a **UTC** instant plus an IANA zone id, and no numeric offset. The
//! specification's deserialization procedure has two steps — build the instant, then *localize it
//! to the zone* — but Graphus's decoder skipped the second one and stored a resolved offset of
//! `0`. The wall clock came out as the raw UTC clock with the zone name stapled on: the
//! specification's own example (`4500 s`, `42 ns`, `Europe/Paris`) yielded `01:15` instead of
//! `02:15+01:00`.
//!
//! Nothing in the codec noticed, because the bytes round-tripped perfectly: re-encoding computes
//! `utc = local - 0`, which is the instant it started from. The damage was entirely in the value
//! model — accessors, comparisons, ordering, and anything stored as a property.
//!
//! # Why it runs over the simulated Bolt wire
//!
//! The defect is only reachable through the **decoder**, so the value has to arrive the way a
//! driver sends it: packed by `pack_value`, framed, and unpacked server-side by `unpack_value`
//! into the parameter map. A test that constructed the `Value` in-process would bypass the only
//! code that was wrong. `graphus_dst::wire` drives the real `BoltSession` state machine and the
//! real PackStream codec against the real engine over the simulated network, so this is the
//! production path, minus the nondeterminism.
//!
//! The Cypher half of the comparison — `datetime({… timezone: 'Europe/Paris'})` — always resolved
//! the offset correctly, because the evaluator owned the IANA database that the codec could not
//! reach. That asymmetry *is* the bug: two logically identical datetimes disagreed depending on
//! which door they came through.
//!
//! # Why it cannot pass vacuously
//!
//! 1. **The equality arm has a negative control.** A datetime one second away must *not* match, so
//!    `=` is not simply matching everything.
//! 2. **The ordering arm is discriminating by construction.** The broken decoder produced a value
//!    with the *same UTC instant* as the correct one, so an `ORDER BY n.t` that only compared
//!    instants could not tell them apart. The tie is broken by `offset_seconds` (`0` versus
//!    `3600`), so the wire node lands on the wrong side of its Cypher twin — the assertion is on
//!    the exact label sequence, with values either side to prove the ordering is real.
//! 3. **The corpus is counted, not inferred.** Every arm asserts against a known node count, so a
//!    query that silently returned nothing would fail loudly rather than look like a pass.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use graphus_bolt::{BoltValue, Request, Response};
use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_core::value::temporal::{LocalDateTime, ZonedDateTime};
use graphus_dst::wire::{SharedEngine, login_prologue, run_scripted_bolt_session, sim_auth};
use graphus_server::engine::LocalEngine;
use graphus_sim::SharedClock;

/// The seed every run in this file uses. Fixed, so a failure reproduces exactly.
const SEED: u64 = 0x0908_2026;
/// Buffer-pool frames — enough for the corpus, small enough to stay quick.
const POOL_PAGES: usize = 256;

/// The UTC instant from the PackStream specification's `DateTimeZoneId` example.
const SPEC_UTC_SECONDS: i64 = 4_500;
/// The sub-second field from the same example.
const SPEC_NANOS: u32 = 42;
/// The offset `Europe/Paris` was in at that instant: CET, `+01:00`. France did not observe summer
/// time in 1970 (it was reintroduced in 1976), so this instant is unambiguous.
const PARIS_OFFSET: i32 = 3_600;

/// The Cypher spelling of the same moment: the *localized* wall clock, `02:15:00.000000042`
/// in `Europe/Paris`. This is the value the engine has always built correctly.
const CYPHER_TWIN: &str = "datetime({year: 1970, month: 1, day: 1, hour: 2, minute: 15, \
     second: 0, nanosecond: 42, timezone: 'Europe/Paris'})";

fn engine() -> SharedEngine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    Rc::new(RefCell::new(
        LocalEngine::in_memory(clock, POOL_PAGES).expect("engine"),
    ))
}

/// The parameter exactly as a driver puts it on the wire: an instant and a named zone. The
/// `offset_seconds` here is what the *client* resolved; the wire form does not carry it, so the
/// server has to resolve it again from the zone rules — which is the code under test.
fn wire_parameter() -> Value {
    Value::zoned_date_time(ZonedDateTime {
        local: LocalDateTime {
            epoch_seconds: SPEC_UTC_SECONDS + i64::from(PARIS_OFFSET),
            nanos: SPEC_NANOS,
        },
        offset_seconds: PARIS_OFFSET,
        zone_id: "Europe/Paris".to_owned(),
    })
}

/// Runs `(query, parameters)` pairs in one Bolt session over the simulated network.
fn session(eng: SharedEngine, stmts: &[(&str, Vec<(String, Value)>)]) -> Vec<Response> {
    let auth = sim_auth();
    let mut reqs = login_prologue();
    for (q, params) in stmts {
        reqs.push(Request::Run {
            query: (*q).to_owned(),
            parameters: params.clone(),
            extra: vec![],
        });
        reqs.push(Request::Pull { n: -1, qid: None });
    }
    reqs.push(Request::Goodbye);
    run_scripted_bolt_session(eng, SEED, &auth, &reqs).expect("the session runs")
}

/// Asserts no statement in the session failed, quoting the failure if one did.
fn assert_no_failure(responses: &[Response], what: &str) {
    let failure = responses.iter().find_map(|r| match r {
        Response::Failure(meta) => Some(format!("{meta:?}")),
        _ => None,
    });
    assert!(failure.is_none(), "{what} failed: {}", failure.unwrap());
}

/// The first integer any `RECORD` in `responses` carries.
fn scalar(responses: &[Response], what: &str) -> i64 {
    responses
        .iter()
        .find_map(|r| match r {
            Response::Record { values } => match values.first() {
                Some(BoltValue::Value(Value::Integer(n))) => Some(*n),
                _ => None,
            },
            _ => None,
        })
        .unwrap_or_else(|| panic!("{what}: no integer record in {responses:?}"))
}

/// Every string the session's `RECORD`s carry in their first column, in order.
fn strings(responses: &[Response]) -> Vec<String> {
    responses
        .iter()
        .filter_map(|r| match r {
            Response::Record { values } => match values.first() {
                Some(BoltValue::Value(Value::String(s))) => Some(s.clone()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// The parameter, once decoded and stored, must be **the same value** the Cypher constructor
/// builds for that instant and zone — equal under `=`, and matched by a query written against
/// either spelling. Storing one and matching on the other is the production shape.
#[test]
fn a_wire_datetime_equals_its_cypher_twin() {
    let eng = engine();
    let responses = session(
        eng,
        &[
            // The value arrives from the wire and is stored as a property.
            (
                "CREATE (:Reading {k: 'wire', t: $p})",
                vec![("p".to_owned(), wire_parameter())],
            ),
            // The same moment, spelled in Cypher.
            (
                &format!("CREATE (:Reading {{k: 'cypher', t: {CYPHER_TWIN}}})"),
                vec![],
            ),
            // Both rows exist — so the counts below mean something.
            ("MATCH (n:Reading) RETURN count(n)", vec![]),
            // The two properties are equal. The pair matches unconditionally (the corpus arm
            // above proves both rows exist), so the only thing `WHERE` can remove is inequality.
            (
                "MATCH (a:Reading {k: 'wire'}), (b:Reading {k: 'cypher'}) WHERE a.t = b.t \
                 RETURN count(*)",
                vec![],
            ),
            // Matching on the Cypher spelling finds the row that came off the wire, and vice
            // versa: the two are interchangeable in a predicate.
            (
                &format!("MATCH (n:Reading) WHERE n.t = {CYPHER_TWIN} RETURN count(n)"),
                vec![],
            ),
            (
                "MATCH (n:Reading) WHERE n.t = $p RETURN count(n)",
                vec![("p".to_owned(), wire_parameter())],
            ),
            // NEGATIVE CONTROL: one second away must not match, so `=` is discriminating.
            (
                "MATCH (n:Reading) WHERE n.t = datetime({year: 1970, month: 1, day: 1, \
                 hour: 2, minute: 15, second: 1, nanosecond: 42, timezone: 'Europe/Paris'}) \
                 RETURN count(n)",
                vec![],
            ),
        ],
    );
    assert_no_failure(&responses, "the datetime session");

    let counts: Vec<i64> = responses
        .iter()
        .filter_map(|r| match r {
            Response::Record { values } => match values.first() {
                Some(BoltValue::Value(Value::Integer(n))) => Some(*n),
                _ => None,
            },
            _ => None,
        })
        .collect();
    assert_eq!(
        counts.len(),
        5,
        "expected five counting statements to produce a record, got {counts:?}"
    );
    assert_eq!(counts[0], 2, "both readings must have been created");
    assert_eq!(
        counts[1], 1,
        "the wire value and its Cypher twin must be equal (a `0` here means `a.t <> b.t`, \
         i.e. the decoder did not localize the instant to Europe/Paris)"
    );
    assert_eq!(
        counts[2], 2,
        "a predicate written in Cypher must match BOTH rows, including the one from the wire"
    );
    assert_eq!(
        counts[3], 2,
        "a predicate carrying the wire value must match BOTH rows, including the Cypher one"
    );
    assert_eq!(counts[4], 0, "a datetime one second away must not match");
}

/// The two spellings must also **sort together**: an `ORDER BY` over the property has to place
/// them side by side, not on opposite sides of a tie-break.
///
/// This is the arm the instant alone cannot satisfy. The broken decoder produced a value with the
/// *same UTC instant* as the correct one — only the resolved offset differed (`0` versus `3600`) —
/// and `offset_seconds` is a tiebreaker in the Cypher ordering, so the wire row sorted ahead of
/// its own twin. Values either side pin that the ordering is real and not accidental.
#[test]
fn a_wire_datetime_sorts_together_with_its_cypher_twin() {
    let eng = engine();
    let responses = session(
        eng,
        &[
            (
                "CREATE (:Reading {k: 'b-wire', t: $p})",
                vec![("p".to_owned(), wire_parameter())],
            ),
            (
                &format!("CREATE (:Reading {{k: 'b-cypher', t: {CYPHER_TWIN}}})"),
                vec![],
            ),
            // One hour earlier and one hour later in the same zone, to bracket the pair.
            (
                "CREATE (:Reading {k: 'a-before', t: datetime({year: 1970, month: 1, day: 1, \
                 hour: 1, minute: 15, second: 0, nanosecond: 42, timezone: 'Europe/Paris'})})",
                vec![],
            ),
            (
                "CREATE (:Reading {k: 'c-after', t: datetime({year: 1970, month: 1, day: 1, \
                 hour: 3, minute: 15, second: 0, nanosecond: 42, timezone: 'Europe/Paris'})})",
                vec![],
            ),
            ("MATCH (n:Reading) RETURN count(n)", vec![]),
            // Order by the datetime, then by the key so the tie between the twins is resolved
            // deterministically. If the twins are genuinely equal they are adjacent and `k`
            // decides; if they are not, one of them escapes the middle of the sequence.
            ("MATCH (n:Reading) RETURN n.k ORDER BY n.t, n.k", vec![]),
        ],
    );
    assert_no_failure(&responses, "the ordering session");

    assert_eq!(
        scalar(&responses, "corpus size"),
        4,
        "all four readings must have been created"
    );
    assert_eq!(
        strings(&responses),
        vec!["a-before", "b-cypher", "b-wire", "c-after"],
        "the wire value and its Cypher twin must tie and sit adjacent in the middle; seeing \
         `b-wire` before `b-cypher` means the wire value kept offset 0 instead of +01:00"
    );
}
