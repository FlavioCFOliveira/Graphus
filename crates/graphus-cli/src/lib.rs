//! `graphus-cli` — the library behind the Graphus interactive Cypher shell and admin client.
//!
//! The crate ships a thin binary (`src/main.rs`) over this library so the client, renderer, and REPL
//! are exercisable both from the shell and from integration tests (the AC test drives the real
//! [`client::BoltClient`] over a live server's UDS socket).
//!
//! # Design
//!
//! Graphus is a *client* here: it does **not** reimplement the Bolt wire format. The
//! [`client::BoltClient`] drives the symmetric Bolt 5.4 codec from `graphus-bolt`
//! (handshake → framing → message → packstream) over a synchronous socket — the right shape for an
//! interactive, single-connection, request/response REPL (no async runtime needed; the codec is pure
//! sync byte ops).
//!
//! - [`client`] — the synchronous Bolt-over-UDS client: connect → handshake → `HELLO`/`LOGON` →
//!   `RUN`/`PULL` → `GOODBYE`, surfacing a server `FAILURE` as a clean error.
//! - [`render`] — Cypher-ish [`graphus_core::Value`] formatting and an aligned ASCII result table.
//! - [`repl`] — statement accumulation (`;`-terminated, multi-line), meta-commands (`:help`,
//!   `:status`, `:clear`, `:quit`), and result rendering, all over a [`client::BoltClient`].
#![forbid(unsafe_code)]

pub mod client;
pub mod render;
pub mod repl;
