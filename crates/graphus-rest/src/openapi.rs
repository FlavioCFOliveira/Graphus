//! The static **OpenAPI 3.1** document for the REST transactional API (`04-technical-design.md`
//! §8.2), served at `GET /openapi.json`.
//!
//! `04 §8.2` specifies the surface ("strictly following HTTP semantics … RFC 9457 for errors"); a
//! published OpenAPI 3.1 description makes that surface machine-discoverable. The document is
//! **hand-written** (a single source-of-truth [`serde_json::Value`]) rather than derived, so it can
//! describe the Jolt typed-value schema and the RFC 9457 error shape precisely and stays valid
//! independent of any code-generation macro. It declares `"openapi": "3.1.0"`, the five transaction
//! paths, the typed-value/`Statement`/`Problem` component schemas, and the Bearer security scheme.
//!
//! It is intentionally a *description*, not a contract enforced at runtime: the handlers validate
//! their own inputs (`06 §4` access_mode, [`crate::value`] decoding) and the document mirrors that
//! behaviour. A test asserts it parses as JSON and declares OpenAPI 3.1 plus the tx paths.

use serde_json::{Value as Json, json};

/// Builds the OpenAPI 3.1 document describing the REST API (`04 §8.2`).
///
/// Returns a fully-formed [`serde_json::Value`]; the router serialises it at `GET /openapi.json`.
/// It is built fresh per call (cheap, and avoids a global), but the router may cache it.
#[must_use]
pub fn document() -> Json {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Graphus REST transactional API",
            "version": "1",
            "summary": "Transactional HTTP API for the Graphus LPG database.",
            "description": "Open a transaction, run Cypher statements, and commit or roll back. \
                Values are typed JSON (Jolt) by default or CBOR via content negotiation; 64-bit \
                integers are string-encoded in JSON (int53-safe). Large results stream as NDJSON. \
                Errors are RFC 9457 problem+json. See specification/04-technical-design.md §8.2 and \
                specification/06-bolt-and-error-shapes.md §4.",
            "license": { "name": "See repository LICENSE" }
        },
        "servers": [ { "url": "/", "description": "This Graphus server (TLS-terminated by the listener)." } ],
        "security": [ { "bearerAuth": [] } ],
        "tags": [ { "name": "transaction", "description": "The Cypher transaction lifecycle." } ],
        "paths": {
            "/db/{db}/tx": {
                "post": {
                    "tags": ["transaction"],
                    "summary": "Open an explicit transaction.",
                    "description": "Opens a transaction in the given database and returns its id, \
                        commit URL, expiry, and effective access mode. Reads an optional \
                        `access_mode` (`READ`/`WRITE`, default `WRITE`).",
                    "operationId": "beginTransaction",
                    "parameters": [ { "$ref": "#/components/parameters/Db" } ],
                    "requestBody": { "$ref": "#/components/requestBodies/RunRequest" },
                    "responses": {
                        "201": {
                            "description": "Transaction opened.",
                            "content": { "application/json": {
                                "schema": { "$ref": "#/components/schemas/BeginResponse" }
                            } }
                        },
                        "400": { "$ref": "#/components/responses/Problem" },
                        "401": { "$ref": "#/components/responses/Problem" },
                        "403": { "$ref": "#/components/responses/Problem" }
                    }
                }
            },
            "/db/{db}/tx/{id}": {
                "post": {
                    "tags": ["transaction"],
                    "summary": "Run statements in an open transaction.",
                    "description": "Runs the request's statements in the open transaction, resetting \
                        its inactivity timeout. Results stream as NDJSON when the client accepts \
                        `application/x-ndjson`.",
                    "operationId": "runInTransaction",
                    "parameters": [
                        { "$ref": "#/components/parameters/Db" },
                        { "$ref": "#/components/parameters/TxId" }
                    ],
                    "requestBody": { "$ref": "#/components/requestBodies/RunRequest" },
                    "responses": {
                        "200": { "$ref": "#/components/responses/RunResponse" },
                        "400": { "$ref": "#/components/responses/Problem" },
                        "404": { "$ref": "#/components/responses/Problem" },
                        "409": { "$ref": "#/components/responses/Problem" }
                    }
                },
                "delete": {
                    "tags": ["transaction"],
                    "summary": "Roll back an open transaction.",
                    "operationId": "rollbackTransaction",
                    "parameters": [
                        { "$ref": "#/components/parameters/Db" },
                        { "$ref": "#/components/parameters/TxId" }
                    ],
                    "responses": {
                        "200": { "description": "Transaction rolled back." },
                        "404": { "$ref": "#/components/responses/Problem" }
                    }
                }
            },
            "/db/{db}/tx/{id}/commit": {
                "post": {
                    "tags": ["transaction"],
                    "summary": "Run final statements and commit.",
                    "operationId": "commitTransaction",
                    "parameters": [
                        { "$ref": "#/components/parameters/Db" },
                        { "$ref": "#/components/parameters/TxId" }
                    ],
                    "requestBody": { "$ref": "#/components/requestBodies/RunRequest" },
                    "responses": {
                        "200": { "$ref": "#/components/responses/RunResponse" },
                        "400": { "$ref": "#/components/responses/Problem" },
                        "404": { "$ref": "#/components/responses/Problem" },
                        "409": { "$ref": "#/components/responses/Problem" }
                    }
                }
            },
            "/db/{db}/tx/commit": {
                "post": {
                    "tags": ["transaction"],
                    "summary": "Single-statement auto-commit shortcut.",
                    "description": "Opens a transaction, runs the statements, and commits, in one \
                        request. Reads an optional `access_mode`.",
                    "operationId": "autoCommit",
                    "parameters": [ { "$ref": "#/components/parameters/Db" } ],
                    "requestBody": { "$ref": "#/components/requestBodies/RunRequest" },
                    "responses": {
                        "200": { "$ref": "#/components/responses/RunResponse" },
                        "400": { "$ref": "#/components/responses/Problem" },
                        "401": { "$ref": "#/components/responses/Problem" },
                        "403": { "$ref": "#/components/responses/Problem" },
                        "409": { "$ref": "#/components/responses/Problem" }
                    }
                }
            }
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                    "description": "RFC 6750 Bearer token (HS256 JWT); see specification/04 §8.4."
                }
            },
            "parameters": {
                "Db": {
                    "name": "db", "in": "path", "required": true,
                    "description": "The target database (graph) name.",
                    "schema": { "type": "string" }
                },
                "TxId": {
                    "name": "id", "in": "path", "required": true,
                    "description": "The open transaction id returned by `beginTransaction`.",
                    "schema": { "type": "string" }
                }
            },
            "requestBodies": {
                "RunRequest": {
                    "description": "Statements to run, with an optional `access_mode`.",
                    "content": {
                        "application/json": { "schema": { "$ref": "#/components/schemas/RunRequest" } },
                        "application/cbor": { "schema": { "$ref": "#/components/schemas/RunRequest" } }
                    }
                }
            },
            "responses": {
                "RunResponse": {
                    "description": "Statement results.",
                    "content": {
                        "application/json": { "schema": { "$ref": "#/components/schemas/RunResponse" } },
                        "application/cbor": { "schema": { "$ref": "#/components/schemas/RunResponse" } },
                        "application/x-ndjson": {
                            "schema": {
                                "type": "string",
                                "description": "One JSON object per line: a `fields` header line, \
                                    then one row line per result row, then a `summary` line."
                            }
                        }
                    }
                },
                "Problem": {
                    "description": "An RFC 9457 problem+json error.",
                    "content": {
                        "application/problem+json": { "schema": { "$ref": "#/components/schemas/Problem" } }
                    }
                }
            },
            "schemas": {
                "TypedValue": {
                    "description": "A Jolt-style typed value (specification/04 §8.2). 64-bit integers \
                        are string-encoded for int53 safety.",
                    "oneOf": [
                        { "type": "null", "title": "Null" },
                        { "type": "object", "title": "Boolean",
                          "properties": { "?": { "type": "string", "enum": ["true", "false"] } },
                          "required": ["?"], "additionalProperties": false },
                        { "type": "object", "title": "Integer",
                          "properties": { "Z": { "type": "string", "description": "Decimal i64, string-encoded." } },
                          "required": ["Z"], "additionalProperties": false },
                        { "type": "object", "title": "Float",
                          "properties": { "R": { "type": "string" } },
                          "required": ["R"], "additionalProperties": false },
                        { "type": "object", "title": "String",
                          "properties": { "U": { "type": "string" } },
                          "required": ["U"], "additionalProperties": false },
                        { "type": "object", "title": "Bytes",
                          "properties": { "#": { "type": "string", "description": "Uppercase hex." } },
                          "required": ["#"], "additionalProperties": false },
                        { "type": "object", "title": "Temporal",
                          "properties": { "T": { "type": "string", "description": "ISO-8601." } },
                          "required": ["T"], "additionalProperties": false },
                        { "type": "array", "title": "List", "items": { "$ref": "#/components/schemas/TypedValue" } },
                        { "type": "object", "title": "Map",
                          "properties": { "{}": { "type": "object", "additionalProperties": { "$ref": "#/components/schemas/TypedValue" } } },
                          "required": ["{}"], "additionalProperties": false }
                    ]
                },
                "Statement": {
                    "type": "object",
                    "required": ["statement"],
                    "properties": {
                        "statement": { "type": "string", "description": "Cypher query text." },
                        "parameters": { "type": "object", "description": "Query parameters (typed or sparse JSON)." }
                    }
                },
                "RunRequest": {
                    "type": "object",
                    "properties": {
                        "statements": { "type": "array", "items": { "$ref": "#/components/schemas/Statement" } },
                        "access_mode": {
                            "type": "string", "enum": ["READ", "WRITE"],
                            "description": "Access mode (default WRITE); specification/06 §4."
                        }
                    }
                },
                "BeginResponse": {
                    "type": "object",
                    "required": ["id", "commit", "expires_at_nanos", "access_mode"],
                    "properties": {
                        "id": { "type": "string" },
                        "commit": { "type": "string", "description": "Relative URL of the open transaction." },
                        "expires_at_nanos": { "type": "integer", "description": "Expiry on the server clock timeline (ns)." },
                        "access_mode": { "type": "string", "enum": ["READ", "WRITE"] }
                    }
                },
                "StatementResult": {
                    "type": "object",
                    "required": ["fields", "data", "summary"],
                    "properties": {
                        "fields": { "type": "array", "items": { "type": "string" } },
                        "data": { "type": "array", "items": { "type": "array", "items": { "$ref": "#/components/schemas/TypedValue" } } },
                        "summary": { "type": "object" }
                    }
                },
                "RunResponse": {
                    "type": "object",
                    "required": ["results"],
                    "properties": {
                        "results": { "type": "array", "items": { "$ref": "#/components/schemas/StatementResult" } },
                        "id": { "type": "string" },
                        "expires_at_nanos": { "type": "integer" }
                    }
                },
                "Problem": {
                    "type": "object",
                    "description": "RFC 9457 Problem Details.",
                    "required": ["type", "title", "status"],
                    "properties": {
                        "type": { "type": "string", "format": "uri" },
                        "title": { "type": "string" },
                        "status": { "type": "integer" },
                        "detail": { "type": "string" },
                        "code": { "type": "string", "description": "Engine error code (specification/06 §2.4)." }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_is_valid_json_and_declares_openapi_31() {
        let doc = document();
        // Re-parse from a string to prove it is real, serialisable JSON.
        let text = serde_json::to_string(&doc).unwrap();
        let reparsed: Json = serde_json::from_str(&text).unwrap();
        assert_eq!(reparsed["openapi"], "3.1.0");
    }

    #[test]
    fn document_declares_the_transaction_paths() {
        let doc = document();
        let paths = &doc["paths"];
        assert!(paths.get("/db/{db}/tx").is_some());
        assert!(paths.get("/db/{db}/tx/{id}").is_some());
        assert!(paths.get("/db/{db}/tx/{id}/commit").is_some());
        assert!(paths.get("/db/{db}/tx/commit").is_some());
        // The rollback verb is present on the {id} path.
        assert!(paths["/db/{db}/tx/{id}"].get("delete").is_some());
    }

    #[test]
    fn document_describes_typed_value_and_problem_schemas() {
        let doc = document();
        let schemas = &doc["components"]["schemas"];
        assert!(schemas.get("TypedValue").is_some());
        assert!(schemas.get("Problem").is_some());
        // The int53 string-encoding is described on the integer branch.
        let typed = serde_json::to_string(&schemas["TypedValue"]).unwrap();
        assert!(typed.contains("string-encoded"));
    }

    #[test]
    fn document_declares_bearer_security() {
        let doc = document();
        let scheme = &doc["components"]["securitySchemes"]["bearerAuth"];
        assert_eq!(scheme["type"], "http");
        assert_eq!(scheme["scheme"], "bearer");
    }
}
