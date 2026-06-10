//! Content negotiation for the REST API (`04-technical-design.md` §8.2; `D-serialization`).
//!
//! REST serves **typed JSON (Jolt) by default and CBOR via content negotiation**, and streams large
//! results as **NDJSON** (`04 §8.2`). This module turns the request's `Accept` and `Content-Type`
//! headers into the [`Wire`] format to encode the response in and the [`Decode`] format to read the
//! request body as.
//!
//! The negotiation is deliberately small (three media types) and **never guesses**: an `Accept`
//! that names only types Graphus cannot produce is a `406`, and a `Content-Type` Graphus cannot
//! decode is a `415` (the router builds those problems — [`crate::problem`]).
//!
//! ## Media types
//!
//! | Media type | Role |
//! | --- | --- |
//! | `application/json` | Jolt typed JSON (the **default** response, and the default body) |
//! | `application/cbor` | CBOR (RFC 8949) request/response |
//! | `application/x-ndjson` | NDJSON streaming response (one JSON object per line) |
//!
//! `*/*` (or a missing `Accept`) selects the default, Jolt JSON. A weighted `Accept` (`q=` values)
//! is honoured to the extent of preferring the highest-`q` media type Graphus supports; an unpar+
//! able `q` is treated as `q=1` (lenient, per RFC 9110 §12.4.2 the default quality is 1).

/// The wire format chosen for a response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Wire {
    /// Jolt typed JSON, buffered (the default for a non-streaming response).
    #[default]
    Json,
    /// CBOR (RFC 8949), buffered.
    Cbor,
    /// NDJSON: one JSON object per line, streamed (`04 §8.2`).
    Ndjson,
}

impl Wire {
    /// The `Content-Type` header value this wire format is sent with.
    #[must_use]
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Cbor => "application/cbor",
            Self::Ndjson => "application/x-ndjson",
        }
    }
}

/// The format a request body is decoded as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Decode {
    /// Jolt typed JSON (the default when no/again `application/json` `Content-Type`).
    #[default]
    Json,
    /// CBOR (RFC 8949).
    Cbor,
}

const JSON: &str = "application/json";
const CBOR: &str = "application/cbor";
const NDJSON: &str = "application/x-ndjson";

/// Chooses the response [`Wire`] from an `Accept` header value.
///
/// Returns `None` if the client explicitly accepts *only* media types Graphus cannot produce (the
/// router turns that into a `406`). A missing/empty header, or one that includes `*/*` or a
/// supported type, yields `Some(_)`.
///
/// NDJSON is selected only when the client explicitly asks for `application/x-ndjson`; a generic
/// `application/json` or `*/*` selects buffered Jolt JSON. (The router may still stream as NDJSON
/// for a multi-row result when the client opted in; see [`crate::router`](mod@crate::router).)
#[must_use]
pub fn response_wire(accept: Option<&str>) -> Option<Wire> {
    let Some(accept) = accept else {
        return Some(Wire::Json); // no Accept ⇒ default
    };
    let accept = accept.trim();
    if accept.is_empty() {
        return Some(Wire::Json);
    }

    let mut best: Option<(Wire, f32)> = None;
    let mut saw_wildcard = false;
    let mut saw_unsupported = false;

    for part in accept.split(',') {
        let (media, q) = parse_media_range(part);
        match media {
            JSON => consider(&mut best, Wire::Json, q),
            CBOR => consider(&mut best, Wire::Cbor, q),
            NDJSON => consider(&mut best, Wire::Ndjson, q),
            "*/*" | "application/*" => saw_wildcard = true,
            "" => {}
            _ => saw_unsupported = true,
        }
    }

    match best {
        Some((wire, _)) => Some(wire),
        // No explicitly-supported type, but a wildcard ⇒ default JSON.
        None if saw_wildcard => Some(Wire::Json),
        // Client listed only unsupported concrete types and no wildcard ⇒ 406.
        None if saw_unsupported => None,
        // Header had only blanks ⇒ default.
        None => Some(Wire::Json),
    }
}

/// Chooses the request-body [`Decode`] format from a `Content-Type` header value.
///
/// Returns `None` if the `Content-Type` is a concrete type Graphus cannot decode (the router turns
/// that into a `415`). A missing header defaults to JSON (a body-less request, or a client that
/// omitted it, is read as Jolt JSON).
#[must_use]
pub fn request_decode(content_type: Option<&str>) -> Option<Decode> {
    let Some(ct) = content_type else {
        return Some(Decode::Json);
    };
    // `Content-Type` is a single media type with optional parameters (`; charset=…`).
    let media = ct.split(';').next().unwrap_or("").trim();
    match media {
        "" | JSON => Some(Decode::Json),
        CBOR => Some(Decode::Cbor),
        _ => None,
    }
}

/// Parses one `Accept` element into `(media-type, quality)`, lowercasing the media type and reading
/// an optional `;q=` weight (default `1.0`).
fn parse_media_range(part: &str) -> (&str, f32) {
    let mut it = part.split(';');
    let media = it.next().unwrap_or("").trim();
    let mut q = 1.0_f32;
    for param in it {
        let param = param.trim();
        if let Some(qv) = param.strip_prefix("q=") {
            q = qv.parse().unwrap_or(1.0);
        }
    }
    (media, q)
}

/// Keeps the highest-quality candidate; ties keep the first seen (stable, and our preference order
/// already lists JSON first in typical clients).
fn consider(best: &mut Option<(Wire, f32)>, wire: Wire, q: f32) {
    if q <= 0.0 {
        return; // `q=0` means "not acceptable"
    }
    match best {
        Some((_, bq)) if *bq >= q => {}
        _ => *best = Some((wire, q)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_when_accept_absent_or_wildcard() {
        assert_eq!(response_wire(None), Some(Wire::Json));
        assert_eq!(response_wire(Some("")), Some(Wire::Json));
        assert_eq!(response_wire(Some("*/*")), Some(Wire::Json));
        assert_eq!(response_wire(Some("application/*")), Some(Wire::Json));
    }

    #[test]
    fn explicit_types_select_their_wire() {
        assert_eq!(response_wire(Some("application/json")), Some(Wire::Json));
        assert_eq!(response_wire(Some("application/cbor")), Some(Wire::Cbor));
        assert_eq!(
            response_wire(Some("application/x-ndjson")),
            Some(Wire::Ndjson)
        );
    }

    #[test]
    fn quality_weights_pick_the_preferred_type() {
        // CBOR strongly preferred over JSON.
        assert_eq!(
            response_wire(Some("application/json;q=0.2, application/cbor;q=0.9")),
            Some(Wire::Cbor)
        );
        // JSON preferred.
        assert_eq!(
            response_wire(Some("application/cbor;q=0.1, application/json")),
            Some(Wire::Json)
        );
    }

    #[test]
    fn q_zero_excludes_a_type() {
        // JSON excluded, only CBOR acceptable.
        assert_eq!(
            response_wire(Some("application/json;q=0, application/cbor")),
            Some(Wire::Cbor)
        );
    }

    #[test]
    fn only_unsupported_types_is_not_acceptable() {
        assert_eq!(response_wire(Some("text/html")), None);
        assert_eq!(response_wire(Some("image/png, text/plain")), None);
    }

    #[test]
    fn unsupported_plus_wildcard_falls_back_to_default() {
        assert_eq!(response_wire(Some("text/html, */*")), Some(Wire::Json));
    }

    #[test]
    fn content_type_decode_selection() {
        assert_eq!(request_decode(None), Some(Decode::Json));
        assert_eq!(request_decode(Some("application/json")), Some(Decode::Json));
        assert_eq!(
            request_decode(Some("application/json; charset=utf-8")),
            Some(Decode::Json)
        );
        assert_eq!(request_decode(Some("application/cbor")), Some(Decode::Cbor));
        assert_eq!(request_decode(Some("text/plain")), None);
    }
}
