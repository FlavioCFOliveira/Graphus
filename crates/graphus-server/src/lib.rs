//! `graphus-server` — the Graphus server process (the integration capstone, rmp #20).
//!
//! This crate wires the tested building blocks into a runnable, multi-interface graph database
//! server (`04-technical-design.md` §8 connectivity, §9 concurrency/runtime):
//!
//! - **The engine** ([`engine`]) — the single-threaded query engine (`graphus_cypher`'s
//!   `TxnCoordinator` over the real `RecordStore`) on a dedicated thread behind a bounded command
//!   channel, the §9.1 "one shard" of the sharded write/ACID path. Both connectivity seams
//!   ([`engine::BoltEngineExecutor`], [`engine::RestEngineAdapter`]) are thin clients of it.
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

pub mod config;
pub mod engine;
pub mod listeners;
pub mod metrics;
pub mod observability;
pub mod server;
pub mod shutdown;

pub use config::{ConfigError, ServerConfig};
pub use server::{Server, ServerError, ServerHandle};
