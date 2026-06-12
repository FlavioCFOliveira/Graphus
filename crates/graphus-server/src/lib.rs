//! `graphus-server` — the Graphus server process (the integration capstone, rmp #20).
//!
//! This crate wires the tested building blocks into a runnable, multi-interface graph database
//! server (`04-technical-design.md` §8 connectivity, §9 concurrency/runtime):
//!
//! - **The engine** ([`engine`]) — the single-threaded query engine (`graphus_cypher`'s
//!   `TxnCoordinator` over the real `RecordStore`) on a dedicated thread behind a bounded command
//!   channel, the §9.1 "one shard" of the sharded write/ACID path. Both connectivity seams
//!   ([`engine::BoltEngineExecutor`], [`engine::RestEngineAdapter`]) are thin clients of it.
//! - **The database catalog** ([`dbcatalog`], decision `D-multi-db`) — the crash-safe catalog of
//!   named databases (one independent store + engine per database) and the registry of their
//!   running engines.
//! - **The administrative surface** ([`admin`], rmp #84) — server-side interception of
//!   `CREATE/DROP/START/STOP/SHOW DATABASE` statements (the query engine stays
//!   database-agnostic) plus per-session database targeting for all three connection types.
//! - **The listeners** ([`listeners`]) — the three async accept loops (UDS-Bolt, TCP-Bolt+TLS,
//!   REST+TLS), each accepted connection a Tokio task.
//! - **Admission control + load shedding** ([`engine::EngineHandle::try_admit`], `04 §9.3`).
//! - **Observability** ([`metrics`], [`observability`]) — a Prometheus `/metrics` exposition,
//!   structured logging + a slow-query log, and `/health/live` + `/health/ready`.
//! - **Config** ([`config`]) and **graceful shutdown** ([`shutdown`], `04 §9.4`).
//!
//! The crate is library-first so the integration tests can boot a server in-process on loopback; the
//! [`bin`](../graphus_server/index.html) `main` is a thin wrapper around [`Server::run`].
#![forbid(unsafe_code)]

pub mod admin;
pub mod audit;
pub mod config;
pub mod dbcatalog;
pub mod engine;
pub mod key_rotation;
pub mod listeners;
pub mod metrics;
pub mod observability;
pub mod security;
pub mod server;
pub mod shutdown;
pub mod store_device;

pub use audit::{AuditClass, AuditConfig, AuditEvent, AuditLog, AuditOutcome, AuditSource};
pub use config::{ConfigError, ServerConfig};
pub use dbcatalog::{CatalogError, DatabaseCatalog, DbInfo, DbState};
pub use server::{Server, ServerError, ServerHandle};
