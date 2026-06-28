//! The Bolt **5.4** request/response message set, each encoded as a PackStream structure
//! (`04-technical-design.md` §8.1; `06-bolt-and-error-shapes.md` §3).
//!
//! A Bolt message *is* a PackStream [`Structure`](crate::packstream::Structure): a signature/opcode
//! tag byte plus its fields (`04 §8.1`). This module gives each message a typed Rust form and the
//! exact opcode + field layout `04 §8.1` lists, then encodes/decodes it through [`crate::packstream`].
//!
//! ## Opcodes (`04 §8.1`)
//!
//! Requests: `HELLO`(0x01), `LOGON`(0x6A), `LOGOFF`(0x6B), `RUN`(0x10), `DISCARD`(0x2F),
//! `PULL`(0x3F), `BEGIN`(0x11), `COMMIT`(0x12), `ROLLBACK`(0x13), `RESET`(0x0F), `GOODBYE`(0x02).
//! Responses: `SUCCESS`(0x70), `RECORD`(0x71), `IGNORED`(0x7E), `FAILURE`(0x7F).
//!
//! `ROUTE`(0x66) and `TELEMETRY`(0x54) are part of the broader 5.x surface and are now modelled as
//! typed messages (rmp #95): `ROUTE` carries the routing-table context, bookmarks, and an extra map
//! (Bolt 4.4+ shape) so the server can answer with a single-instance routing table; `TELEMETRY`
//! carries an advisory `api` integer the server acknowledges with an empty `SUCCESS`. Any *other*
//! unrecognised opcode still decodes to [`Request::Unsupported`] so the server can answer per its
//! state machine without this layer inventing a wire shape it does not certify.
//!
//! ## Field layout (verified against the Neo4j Bolt message spec, 2026-06)
//!
//! - `HELLO` / `BEGIN` carry one **extra** map; `LOGON` one **auth** map.
//! - `RUN` carries three fields in order: `query` string, `parameters` map, `extra` map.
//! - `PULL` / `DISCARD` carry one **extra** map whose keys are `n` (fetch size, `-1` = all;
//!   **mandatory** — "n has no default and must be present") and `qid` (query id, `-1` = last;
//!   optional, defaults to `-1`).
//! - `LOGOFF` / `COMMIT` / `ROLLBACK` / `RESET` / `GOODBYE` carry **no** fields.
//! - `SUCCESS` / `FAILURE` carry one **metadata** map; `RECORD` one **values** list; `IGNORED` no
//!   fields.

use graphus_core::Value;

use crate::error::{BoltError, BoltResult, Failure};
use crate::packstream::{
    BoltValue, MAX_STRUCT_FIELDS, Packer, Unpacker, pack_bolt_value, pack_value, prealloc_cap,
    unpack_bolt_value, unpack_value,
};

/// Message opcode (signature) bytes (`04 §8.1`).
pub mod opcode {
    // Requests.
    pub const HELLO: u8 = 0x01;
    pub const GOODBYE: u8 = 0x02;
    pub const RESET: u8 = 0x0F;
    pub const RUN: u8 = 0x10;
    pub const BEGIN: u8 = 0x11;
    pub const COMMIT: u8 = 0x12;
    pub const ROLLBACK: u8 = 0x13;
    pub const DISCARD: u8 = 0x2F;
    pub const PULL: u8 = 0x3F;
    pub const TELEMETRY: u8 = 0x54;
    pub const ROUTE: u8 = 0x66;
    pub const LOGON: u8 = 0x6A;
    pub const LOGOFF: u8 = 0x6B;

    // Responses.
    pub const SUCCESS: u8 = 0x70;
    pub const RECORD: u8 = 0x71;
    pub const IGNORED: u8 = 0x7E;
    pub const FAILURE: u8 = 0x7F;
}

/// Sentinel value for "fetch / discard all remaining records" in a `PULL`/`DISCARD` `n` field, and
/// for "the last query" in a `qid` field (`04 §8.1`, mirrors Bolt's `-1`).
pub const ALL: i64 = -1;

/// A client → server request message (`04 §8.1`).
#[derive(Debug, Clone, PartialEq)]
pub enum Request {
    /// `HELLO` — opens the connection negotiation; carries the `extra` map (user agent, etc.).
    Hello {
        /// The `extra` metadata map (e.g. `user_agent`, `bolt_agent`, routing).
        extra: Vec<(String, Value)>,
    },
    /// `LOGON` — authenticates; carries the `auth` map (`scheme`, `principal`, `credentials`).
    Logon {
        /// The auth map.
        auth: Vec<(String, Value)>,
    },
    /// `LOGOFF` — drops the authenticated identity (no fields).
    Logoff,
    /// `RUN` — runs a query: `query` text, `parameters`, and an `extra` (tx) map.
    Run {
        /// The Cypher query text.
        query: String,
        /// The query parameters map.
        parameters: Vec<(String, Value)>,
        /// The `extra` map (bookmarks, tx_timeout, mode, db, …).
        extra: Vec<(String, Value)>,
    },
    /// `DISCARD` — discards `n` records of query `qid` (no `RECORD`s emitted).
    Discard {
        /// Number of records to discard (`-1` = [`ALL`]).
        n: i64,
        /// The target query id (`-1` = last), if present.
        qid: Option<i64>,
    },
    /// `PULL` — pulls `n` records of query `qid`.
    Pull {
        /// Number of records to fetch (`-1` = [`ALL`]).
        n: i64,
        /// The target query id (`-1` = last), if present.
        qid: Option<i64>,
    },
    /// `BEGIN` — opens an explicit transaction; carries the `extra` (tx) map.
    Begin {
        /// The `extra` map (mode, db, bookmarks, …).
        extra: Vec<(String, Value)>,
    },
    /// `COMMIT` — commits the explicit transaction (no fields).
    Commit,
    /// `ROLLBACK` — rolls back the explicit transaction (no fields).
    Rollback,
    /// `RESET` — clears a failure and returns the connection to `READY` (no fields).
    Reset,
    /// `GOODBYE` — the client is closing the connection (no fields).
    Goodbye,
    /// `ROUTE` — asks for the cluster routing table (Bolt 4.4+ shape: `ROUTE
    /// routing_table_context bookmarks extra`). On a single instance every role resolves to this
    /// server (rmp #95).
    Route {
        /// The routing-table context map (driver-supplied routing hints; e.g. `address`).
        routing: Vec<(String, Value)>,
        /// The bookmarks list the client wants the routing table to be consistent with.
        bookmarks: Vec<Value>,
        /// The `extra` map (`db` — the database the table is for; `imp_user` — impersonation).
        extra: Vec<(String, Value)>,
    },
    /// `TELEMETRY` — an advisory message reporting which driver API the client used; the server
    /// acknowledges it with an empty `SUCCESS` and otherwise ignores it (rmp #95).
    Telemetry {
        /// The driver-API code the client reports (informational only).
        api: i64,
    },
    /// An opcode this version does not model as a typed message (e.g. `ROUTE`, `TELEMETRY`); the
    /// server decides how to answer per its state machine without this layer guessing a shape.
    Unsupported {
        /// The raw opcode byte.
        opcode: u8,
        /// The raw fields, decoded as values.
        fields: Vec<Value>,
    },
}

/// A server → client response message (`04 §8.1`, `06 §3`).
#[derive(Debug, Clone, PartialEq)]
pub enum Response {
    /// `SUCCESS` — carries a metadata map (fields, query id, summary, `has_more`, …).
    Success {
        /// The metadata map.
        metadata: Vec<(String, Value)>,
    },
    /// `RECORD` — one result row, a list of the row's values in field order. Each value is a
    /// [`BoltValue`] so a cell may be a graph entity (`Node`/`Relationship`/`Path`), not only a
    /// property `Value` (rmp #76/#96).
    Record {
        /// The row values.
        values: Vec<BoltValue>,
    },
    /// `IGNORED` — the request was ignored (the connection is in `FAILED`; `04 §8.1`).
    Ignored,
    /// `FAILURE` — carries `{code, message}` (`06 §3.2`).
    Failure(Failure),
}

impl Request {
    /// Decodes a request from a message payload (the bytes inside the chunk framing).
    ///
    /// # Errors
    /// [`BoltError::Decode`] on a malformed structure, a wrong field count for the opcode, or
    /// truncated bytes.
    pub fn decode(payload: &[u8]) -> BoltResult<Self> {
        let mut u = Unpacker::new(payload);
        let (tag, field_count) = u.read_struct_header()?;
        let fields = read_fields(&mut u, field_count)?;
        Self::from_structure(tag, fields)
    }

    /// Builds a typed request from a decoded opcode + fields.
    fn from_structure(tag: u8, mut fields: Vec<Value>) -> BoltResult<Self> {
        match tag {
            opcode::HELLO => Ok(Request::Hello {
                extra: take_map(&mut fields, 0, tag, "HELLO.extra")?,
            }),
            opcode::LOGON => Ok(Request::Logon {
                auth: take_map(&mut fields, 0, tag, "LOGON.auth")?,
            }),
            opcode::LOGOFF => {
                expect_arity(tag, fields.len(), 0)?;
                Ok(Request::Logoff)
            }
            opcode::RUN => {
                expect_arity(tag, fields.len(), 3)?;
                // Take in reverse so each `swap_remove`-free `remove` keeps the earlier indices valid;
                // simplest is to drain into an iterator.
                let mut it = fields.into_iter();
                let query = expect_string(it.next(), tag, "RUN.query")?;
                let parameters = expect_map(it.next(), tag, "RUN.parameters")?;
                let extra = expect_map(it.next(), tag, "RUN.extra")?;
                Ok(Request::Run {
                    query,
                    parameters,
                    extra,
                })
            }
            opcode::DISCARD => {
                let extra = take_map(&mut fields, 0, tag, "DISCARD.extra")?;
                let (n, qid) = pull_discard_fields(&extra, tag, "DISCARD")?;
                Ok(Request::Discard { n, qid })
            }
            opcode::PULL => {
                let extra = take_map(&mut fields, 0, tag, "PULL.extra")?;
                let (n, qid) = pull_discard_fields(&extra, tag, "PULL")?;
                Ok(Request::Pull { n, qid })
            }
            opcode::BEGIN => Ok(Request::Begin {
                extra: take_map(&mut fields, 0, tag, "BEGIN.extra")?,
            }),
            opcode::COMMIT => {
                expect_arity(tag, fields.len(), 0)?;
                Ok(Request::Commit)
            }
            opcode::ROLLBACK => {
                expect_arity(tag, fields.len(), 0)?;
                Ok(Request::Rollback)
            }
            opcode::RESET => {
                expect_arity(tag, fields.len(), 0)?;
                Ok(Request::Reset)
            }
            opcode::GOODBYE => {
                expect_arity(tag, fields.len(), 0)?;
                Ok(Request::Goodbye)
            }
            opcode::ROUTE => {
                expect_arity(tag, fields.len(), 3)?;
                let mut it = fields.into_iter();
                let routing = expect_map(it.next(), tag, "ROUTE.routing")?;
                let bookmarks = expect_list(it.next(), tag, "ROUTE.bookmarks")?;
                let extra = expect_map(it.next(), tag, "ROUTE.extra")?;
                Ok(Request::Route {
                    routing,
                    bookmarks,
                    extra,
                })
            }
            opcode::TELEMETRY => {
                expect_arity(tag, fields.len(), 1)?;
                // The `api` field MUST be an integer. A non-integer is a malformed TELEMETRY: the
                // Bolt spec mandates that "a TELEMETRY message [that] contains a value that is not a
                // valid api value … responds with a FAILURE message and enters the FAILED state"
                // (neo4j.com/docs/bolt/current/bolt/message/). A non-integer can never be a valid
                // `api` (which is one of the integers 0..=3), so it is rejected here as a decode
                // error → the session answers `Neo.ClientError.Request.Invalid` → FAILED. The
                // out-of-range *integer* case (e.g. 99) is validated at dispatch, where the value is
                // known together with the connection state. (Supersedes the earlier rmp #95 "tolerate
                // as 0" leniency, which silently swallowed this spec-mandated FAILURE path.)
                let api = match fields.into_iter().next() {
                    Some(Value::Integer(n)) => n,
                    other => {
                        return Err(BoltError::Decode(format!(
                            "message {tag:#04x}: TELEMETRY api must be an integer, found {other:?}"
                        )));
                    }
                };
                Ok(Request::Telemetry { api })
            }
            other => Ok(Request::Unsupported {
                opcode: other,
                fields,
            }),
        }
    }

    /// Encodes this request to a message payload (used by tests and any future client-side use).
    ///
    /// # Errors
    /// [`BoltError::Encode`] if a structure would exceed 15 fields, or if a `String`/`Bytes`/`List`/
    /// `Map` length exceeds the PackStream maximum of `i32::MAX` (refused rather than emitted as an
    /// out-of-spec header). Neither happens for the standard messages.
    pub fn encode(&self) -> BoltResult<Vec<u8>> {
        let mut p = Packer::new();
        match self {
            Request::Hello { extra } => write_struct_with_map(&mut p, opcode::HELLO, extra)?,
            Request::Logon { auth } => write_struct_with_map(&mut p, opcode::LOGON, auth)?,
            Request::Logoff => p.write_struct_header(opcode::LOGOFF, 0)?,
            Request::Run {
                query,
                parameters,
                extra,
            } => {
                p.write_struct_header(opcode::RUN, 3)?;
                p.write_string(query);
                write_map(&mut p, parameters);
                write_map(&mut p, extra);
            }
            Request::Discard { n, qid } => {
                write_struct_with_map(&mut p, opcode::DISCARD, &pull_discard_extra(*n, *qid))?;
            }
            Request::Pull { n, qid } => {
                write_struct_with_map(&mut p, opcode::PULL, &pull_discard_extra(*n, *qid))?;
            }
            Request::Begin { extra } => write_struct_with_map(&mut p, opcode::BEGIN, extra)?,
            Request::Commit => p.write_struct_header(opcode::COMMIT, 0)?,
            Request::Rollback => p.write_struct_header(opcode::ROLLBACK, 0)?,
            Request::Reset => p.write_struct_header(opcode::RESET, 0)?,
            Request::Goodbye => p.write_struct_header(opcode::GOODBYE, 0)?,
            Request::Route {
                routing,
                bookmarks,
                extra,
            } => {
                p.write_struct_header(opcode::ROUTE, 3)?;
                write_map(&mut p, routing);
                p.write_list_header(bookmarks.len());
                for b in bookmarks {
                    pack_value(&mut p, b);
                }
                write_map(&mut p, extra);
            }
            Request::Telemetry { api } => {
                p.write_struct_header(opcode::TELEMETRY, 1)?;
                pack_value(&mut p, &Value::Integer(*api));
            }
            Request::Unsupported { opcode, fields } => {
                p.write_struct_header(*opcode, fields.len())?;
                for f in fields {
                    pack_value(&mut p, f);
                }
            }
        }
        // Refuse an out-of-spec collection length (> i32::MAX) instead of returning a corrupt buffer
        // with a truncated 32-bit header (rmp #445).
        p.check_overflow()?;
        Ok(p.into_inner())
    }
}

impl Response {
    /// Encodes this response to a message payload.
    ///
    /// # Errors
    /// [`BoltError::Encode`] only if a structure would exceed 15 fields (never for these messages).
    pub fn encode(&self) -> BoltResult<Vec<u8>> {
        let mut p = Packer::new();
        self.encode_into(&mut p)?;
        Ok(p.into_inner())
    }

    /// PERF (C4/C5): encodes this response into a caller-provided [`Packer`], producing byte-identical
    /// output to [`Response::encode`]. Lets the server reuse a single retained `Packer` (cleared via
    /// [`Packer::reset`]) across messages instead of allocating a fresh zero-capacity buffer per send.
    ///
    /// This is the single chokepoint for the server's response encoding (both [`Response::encode`]
    /// and the listener's retained-packer `send` path go through it), so the over-length collection
    /// check lives here.
    ///
    /// # Errors
    /// [`BoltError::Encode`] if a structure would exceed 15 fields, or if a `String`/`Bytes`/`List`/
    /// `Map` length exceeds the PackStream maximum of `i32::MAX` (refused rather than emitted as an
    /// out-of-spec header). Neither happens for the standard messages.
    pub fn encode_into(&self, p: &mut Packer) -> BoltResult<()> {
        match self {
            Response::Success { metadata } => {
                write_struct_with_map(p, opcode::SUCCESS, metadata)?;
            }
            Response::Record { values } => {
                p.write_struct_header(opcode::RECORD, 1)?;
                p.write_list_header(values.len());
                for v in values {
                    pack_bolt_value(p, v);
                }
            }
            Response::Ignored => p.write_struct_header(opcode::IGNORED, 0)?,
            Response::Failure(f) => {
                let meta = vec![
                    ("code".to_owned(), Value::String(f.code.clone())),
                    ("message".to_owned(), Value::String(f.message.clone())),
                ];
                write_struct_with_map(p, opcode::FAILURE, &meta)?;
            }
        }
        // Refuse an out-of-spec collection length (> i32::MAX) instead of framing a corrupt buffer
        // with a truncated 32-bit header (rmp #445). Unreachable for real responses (a RECORD value
        // never exceeds the 64 MiB inbound cap), but keeps the encoder strictly spec-faithful.
        p.check_overflow()?;
        Ok(())
    }

    /// Decodes a response from a message payload (the inverse of [`Response::encode`]; used by tests
    /// and any future client-side use).
    ///
    /// # Errors
    /// [`BoltError::Decode`] on a malformed structure or unknown response opcode.
    pub fn decode(payload: &[u8]) -> BoltResult<Self> {
        let mut u = Unpacker::new(payload);
        let (tag, field_count) = u.read_struct_header()?;
        // RECORD's single field is the row's value list, whose cells may be **structural** graph
        // entities (Node/Relationship/Path) that have no `Value` variant — so it is decoded directly
        // as a list of [`BoltValue`]s rather than through the generic `Value` field reader.
        if tag == opcode::RECORD {
            expect_arity(tag, field_count, 1)?;
            let count = u.read_list_header()?;
            // SECURITY (SEC-192, CWE-789): `count` is a raw wire `LIST_32` header (up to `u32::MAX`)
            // and `Response::decode` runs CLIENT-side over bytes an untrusted server sends. NEVER
            // size the allocation from it — cap the pre-reservation via `prealloc_cap` and let the
            // `Vec` grow as real cells are decoded. The loop is bounded by the actual input length
            // (each `unpack_bolt_value` consumes ≥1 byte and errors at end-of-input), so a genuinely
            // large record still decodes; only the unbounded pre-allocation is removed.
            let mut values = Vec::with_capacity(prealloc_cap(count));
            for _ in 0..count {
                values.push(unpack_bolt_value(&mut u)?);
            }
            return Ok(Response::Record { values });
        }
        let mut fields = read_fields(&mut u, field_count)?;
        match tag {
            opcode::SUCCESS => Ok(Response::Success {
                metadata: take_map(&mut fields, 0, tag, "SUCCESS.metadata")?,
            }),
            opcode::IGNORED => {
                expect_arity(tag, fields.len(), 0)?;
                Ok(Response::Ignored)
            }
            opcode::FAILURE => {
                let meta = take_map(&mut fields, 0, tag, "FAILURE.metadata")?;
                let code = map_get_string(&meta, "code").unwrap_or_default();
                let message = map_get_string(&meta, "message").unwrap_or_default();
                Ok(Response::Failure(Failure::new(code, message)))
            }
            other => Err(BoltError::Decode(format!(
                "unknown response opcode {other:#04x}"
            ))),
        }
    }
}

// ---- shared encode/decode helpers -------------------------------------------------------------

fn write_map(p: &mut Packer, entries: &[(String, Value)]) {
    p.write_map_header(entries.len());
    for (k, v) in entries {
        p.write_string(k);
        pack_value(p, v);
    }
}

fn write_struct_with_map(p: &mut Packer, tag: u8, map: &[(String, Value)]) -> BoltResult<()> {
    p.write_struct_header(tag, 1)?;
    write_map(p, map);
    Ok(())
}

fn read_fields(u: &mut Unpacker<'_>, count: usize) -> BoltResult<Vec<Value>> {
    // INVARIANT (SEC-193): `count` is the structure field count from `read_struct_header`, which is
    // the tiny-struct nibble and is therefore bounded to `0..=15` (== `MAX_STRUCT_FIELDS`). Unlike a
    // `LIST_32`/`MAP_32` length it is NOT attacker-scalable, so `Vec::with_capacity(count)` is safe
    // here without a `prealloc_cap` clamp. The `debug_assert!` pins the contract: if a future Bolt
    // revision adds a wide-struct marker, this must be re-audited (see SEC-192 for the uncapped case).
    debug_assert!(count <= MAX_STRUCT_FIELDS);
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        fields.push(unpack_value(u)?);
    }
    Ok(fields)
}

fn expect_arity(tag: u8, got: usize, want: usize) -> BoltResult<()> {
    if got == want {
        Ok(())
    } else {
        Err(BoltError::Decode(format!(
            "message {tag:#04x} expected {want} fields, found {got}"
        )))
    }
}

/// Removes the map at `idx` (after asserting exactly one field), returning its entries.
fn take_map(
    fields: &mut Vec<Value>,
    idx: usize,
    tag: u8,
    what: &str,
) -> BoltResult<Vec<(String, Value)>> {
    expect_arity(tag, fields.len(), 1)?;
    match fields.swap_remove(idx) {
        Value::Map(m) => Ok(m),
        other => Err(BoltError::Decode(format!(
            "{what} must be a map, found {other:?}"
        ))),
    }
}

fn expect_string(v: Option<Value>, tag: u8, what: &str) -> BoltResult<String> {
    match v {
        Some(Value::String(s)) => Ok(s),
        other => Err(BoltError::Decode(format!(
            "message {tag:#04x}: {what} must be a string, found {other:?}"
        ))),
    }
}

fn expect_map(v: Option<Value>, tag: u8, what: &str) -> BoltResult<Vec<(String, Value)>> {
    match v {
        Some(Value::Map(m)) => Ok(m),
        other => Err(BoltError::Decode(format!(
            "message {tag:#04x}: {what} must be a map, found {other:?}"
        ))),
    }
}

fn expect_list(v: Option<Value>, tag: u8, what: &str) -> BoltResult<Vec<Value>> {
    match v {
        Some(Value::List(l)) => Ok(l),
        other => Err(BoltError::Decode(format!(
            "message {tag:#04x}: {what} must be a list, found {other:?}"
        ))),
    }
}

/// Extracts `(n, qid)` from a `PULL`/`DISCARD` extra map.
///
/// `n` (the fetch size) is **mandatory**: the Bolt message spec states verbatim that for PULL and
/// DISCARD "`n` has no default and must be present" (neo4j.com/docs/bolt/current/bolt/message/). An
/// extra map that omits `n` is therefore a malformed request — it is rejected as a decode error so
/// the session answers `Neo.ClientError.Request.Invalid` → FAILED, rather than silently treating an
/// absent fetch size as "all" (which would also let a no-`n` PULL force full materialization of the
/// result set — a DoS-adjacent footgun). A missing `qid` stays `None` ("last query"), which the spec
/// *does* allow (`qid` defaults to `-1`).
///
/// # Errors
/// [`BoltError::Decode`] if the `n` key is absent (it has no default and must be present).
fn pull_discard_fields(
    extra: &[(String, Value)],
    tag: u8,
    what: &str,
) -> BoltResult<(i64, Option<i64>)> {
    let n = map_get_int(extra, "n").ok_or_else(|| {
        BoltError::Decode(format!(
            "message {tag:#04x}: {what} requires `n` (it has no default and must be present)"
        ))
    })?;
    let qid = map_get_int(extra, "qid");
    Ok((n, qid))
}

/// Builds the `PULL`/`DISCARD` extra map from `(n, qid)` for encoding.
fn pull_discard_extra(n: i64, qid: Option<i64>) -> Vec<(String, Value)> {
    let mut extra = vec![("n".to_owned(), Value::Integer(n))];
    if let Some(q) = qid {
        extra.push(("qid".to_owned(), Value::Integer(q)));
    }
    extra
}

fn map_get_int(map: &[(String, Value)], key: &str) -> Option<i64> {
    map.iter().find_map(|(k, v)| match v {
        Value::Integer(n) if k == key => Some(*n),
        _ => None,
    })
}

fn map_get_string(map: &[(String, Value)], key: &str) -> Option<String> {
    map.iter().find_map(|(k, v)| match v {
        Value::String(s) if k == key => Some(s.clone()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trips a request through `encode`/`decode`.
    fn rt_request(r: &Request) -> Request {
        let bytes = r.encode().expect("encode");
        Request::decode(&bytes).expect("decode")
    }

    /// Round-trips a response through `encode`/`decode`.
    fn rt_response(r: &Response) -> Response {
        let bytes = r.encode().expect("encode");
        Response::decode(&bytes).expect("decode")
    }

    #[test]
    fn hello_opcode_and_round_trip() {
        let r = Request::Hello {
            extra: vec![(
                "user_agent".to_owned(),
                Value::String("graphus-test/1.0".to_owned()),
            )],
        };
        let bytes = r.encode().unwrap();
        // tiny-struct with 1 field, tag 0x01.
        assert_eq!(bytes[0], 0xB1);
        assert_eq!(bytes[1], opcode::HELLO);
        assert_eq!(rt_request(&r), r);
    }

    #[test]
    fn logon_carries_auth_map() {
        let r = Request::Logon {
            auth: vec![
                ("scheme".to_owned(), Value::String("basic".to_owned())),
                ("principal".to_owned(), Value::String("alice".to_owned())),
                ("credentials".to_owned(), Value::String("pw".to_owned())),
            ],
        };
        assert_eq!(rt_request(&r), r);
    }

    #[test]
    fn run_three_fields_in_order() {
        let r = Request::Run {
            query: "RETURN $x".to_owned(),
            parameters: vec![("x".to_owned(), Value::Integer(42))],
            extra: vec![("mode".to_owned(), Value::String("w".to_owned()))],
        };
        let bytes = r.encode().unwrap();
        assert_eq!(bytes[0], 0xB3); // 3 fields
        assert_eq!(bytes[1], opcode::RUN);
        assert_eq!(rt_request(&r), r);
    }

    #[test]
    fn pull_n_and_qid_round_trip() {
        let r = Request::Pull {
            n: 100,
            qid: Some(7),
        };
        assert_eq!(rt_request(&r), r);
        // `n` is always encoded (it is mandatory on the wire); ALL (-1) round-trips to ALL.
        let all = Request::Pull { n: ALL, qid: None };
        assert_eq!(rt_request(&all), all);
    }

    #[test]
    fn pull_with_absent_n_is_a_decode_error() {
        // Bolt spec (neo4j.com/docs/bolt/current/bolt/message/): for PULL and DISCARD "n has no
        // default and must be present." A hand-built PULL whose extra map has no `n` key (B1 3F A0:
        // TINY_STRUCT-1, PULL opcode, empty MAP) MUST be a decode error, NOT a silent default to
        // ALL — otherwise a no-`n` PULL would force full materialization of the result set.
        let mut p = Packer::new();
        p.write_struct_header(opcode::PULL, 1).unwrap();
        p.write_map_header(0);
        let bytes = p.into_inner();
        assert_eq!(bytes, [0xB1, opcode::PULL, 0xA0], "hand-framed B1 3F A0");
        match Request::decode(&bytes) {
            Err(BoltError::Decode(msg)) => assert!(
                msg.contains('n') && msg.contains("must be present"),
                "decode error must explain the missing mandatory `n`: {msg}"
            ),
            other => panic!("expected a Decode error for absent n, got {other:?}"),
        }
    }

    #[test]
    fn discard_with_absent_n_is_a_decode_error() {
        // The same mandatory-`n` rule applies to DISCARD (B1 2F A0).
        let mut p = Packer::new();
        p.write_struct_header(opcode::DISCARD, 1).unwrap();
        p.write_map_header(0);
        let bytes = p.into_inner();
        assert_eq!(bytes, [0xB1, opcode::DISCARD, 0xA0], "hand-framed B1 2F A0");
        assert!(
            matches!(Request::decode(&bytes), Err(BoltError::Decode(_))),
            "DISCARD without `n` must be a decode error"
        );
    }

    #[test]
    fn pull_with_present_n_still_decodes() {
        // Regression guard: a PULL that DOES carry `n` (the normal driver case) still decodes — the
        // mandatory-`n` rule must reject only the *absent* case, never a present one.
        let mut p = Packer::new();
        p.write_struct_header(opcode::PULL, 1).unwrap();
        p.write_map_header(1);
        p.write_string("n");
        p.write_int(ALL);
        match Request::decode(&p.into_inner()).unwrap() {
            Request::Pull { n, qid } => {
                assert_eq!(n, ALL);
                assert_eq!(qid, None);
            }
            other => panic!("expected PULL, got {other:?}"),
        }
    }

    #[test]
    fn fieldless_requests_round_trip() {
        for r in [
            Request::Logoff,
            Request::Commit,
            Request::Rollback,
            Request::Reset,
            Request::Goodbye,
        ] {
            let bytes = r.encode().unwrap();
            assert_eq!(bytes[0], 0xB0, "zero-field struct marker for {r:?}");
            assert_eq!(rt_request(&r), r);
        }
    }

    #[test]
    fn begin_and_discard_round_trip() {
        let begin = Request::Begin {
            extra: vec![("db".to_owned(), Value::String("neo4j".to_owned()))],
        };
        assert_eq!(rt_request(&begin), begin);
        let discard = Request::Discard {
            n: ALL,
            qid: Some(1),
        };
        assert_eq!(rt_request(&discard), discard);
    }

    #[test]
    fn unknown_opcode_decodes_as_unsupported() {
        // A genuinely unmodelled opcode (0x55) with one map field.
        let mut p = Packer::new();
        p.write_struct_header(0x55, 1).unwrap();
        p.write_map_header(0);
        let bytes = p.into_inner();
        match Request::decode(&bytes).unwrap() {
            Request::Unsupported { opcode, fields } => {
                assert_eq!(opcode, 0x55);
                assert_eq!(fields, vec![Value::Map(vec![])]);
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn route_three_fields_round_trip() {
        let r = Request::Route {
            routing: vec![(
                "address".to_owned(),
                Value::String("localhost:7687".to_owned()),
            )],
            bookmarks: vec![Value::String("bm:1".to_owned())],
            extra: vec![("db".to_owned(), Value::String("neo4j".to_owned()))],
        };
        let bytes = r.encode().unwrap();
        assert_eq!(bytes[0], 0xB3, "ROUTE is a 3-field struct");
        assert_eq!(bytes[1], opcode::ROUTE);
        assert_eq!(rt_request(&r), r);
    }

    #[test]
    fn route_with_wrong_field_count_errors() {
        // ROUTE with a single map field (missing bookmarks + extra) is malformed.
        let mut p = Packer::new();
        p.write_struct_header(opcode::ROUTE, 1).unwrap();
        p.write_map_header(0);
        assert!(matches!(
            Request::decode(&p.into_inner()),
            Err(BoltError::Decode(_))
        ));
    }

    #[test]
    fn telemetry_carries_api_int_round_trip() {
        let r = Request::Telemetry { api: 3 };
        let bytes = r.encode().unwrap();
        assert_eq!(bytes[0], 0xB1, "TELEMETRY is a 1-field struct");
        assert_eq!(bytes[1], opcode::TELEMETRY);
        assert_eq!(rt_request(&r), r);
    }

    #[test]
    fn telemetry_non_integer_api_is_a_decode_error() {
        // A non-integer `api` can never be a valid api value (valid api ∈ {0,1,2,3}), so the Bolt
        // spec's "FAILURE on an invalid api value" applies: it is rejected as a decode error (which
        // the session turns into `Neo.ClientError.Request.Invalid` → FAILED), NOT tolerated as 0.
        let mut p = Packer::new();
        p.write_struct_header(opcode::TELEMETRY, 1).unwrap();
        p.write_string("oops");
        assert!(
            matches!(Request::decode(&p.into_inner()), Err(BoltError::Decode(_))),
            "a non-integer TELEMETRY api must be a decode error"
        );
    }

    #[test]
    fn telemetry_integer_api_decodes_even_out_of_range() {
        // An out-of-range *integer* api (e.g. 99) still decodes at the wire layer — its validity is a
        // semantic check the server performs at dispatch (where it knows the connection state). The
        // codec only rejects a non-integer; a too-large integer is the dispatch layer's call.
        let r = Request::Telemetry { api: 99 };
        assert_eq!(rt_request(&r), r);
    }

    #[test]
    fn success_record_ignored_failure_round_trip() {
        let success = Response::Success {
            metadata: vec![(
                "fields".to_owned(),
                Value::List(vec![Value::String("n".to_owned())]),
            )],
        };
        assert_eq!(rt_response(&success), success);

        let record = Response::Record {
            values: vec![
                BoltValue::Value(Value::Integer(1)),
                BoltValue::Value(Value::String("a".to_owned())),
            ],
        };
        let bytes = record.encode().unwrap();
        assert_eq!(bytes[1], opcode::RECORD);
        assert_eq!(rt_response(&record), record);

        assert_eq!(rt_response(&Response::Ignored), Response::Ignored);

        let failure = Response::Failure(Failure::new(
            "Neo.ClientError.Statement.SyntaxError",
            "boom",
        ));
        assert_eq!(rt_response(&failure), failure);
    }

    #[test]
    fn failure_metadata_has_code_and_message_keys() {
        let f = Response::Failure(Failure::new("X.Y.Z", "human"));
        let bytes = f.encode().unwrap();
        let mut u = Unpacker::new(&bytes);
        let (tag, n) = u.read_struct_header().unwrap();
        assert_eq!(tag, opcode::FAILURE);
        assert_eq!(n, 1);
        let map = u.read_map_header().unwrap();
        assert_eq!(map, 2);
    }

    #[test]
    fn run_with_wrong_field_count_errors() {
        // A RUN-tagged struct with only 1 field is malformed.
        let mut p = Packer::new();
        p.write_struct_header(opcode::RUN, 1).unwrap();
        p.write_string("RETURN 1");
        let bytes = p.into_inner();
        assert!(matches!(Request::decode(&bytes), Err(BoltError::Decode(_))));
    }
}
