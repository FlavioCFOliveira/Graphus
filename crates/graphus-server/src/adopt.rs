//! The `graphus-server adopt` **offline** subcommand (`rmp` #681): make a `graphus-bulk`
//! offline-imported store directly servable by `graphus-server`.
//!
//! `graphus-bulk import` builds a store in an `<import-dir>` (`graph.store` + `graph.wal/`) whose file
//! names and directory layout the server does **not** open directly — the server expects
//! `graphus.store`/`graphus.wal` under its data root (the default database) or under
//! `databases/<name>/` (a named database), plus the durable `databases.toml` catalog for named
//! databases. This subcommand bridges that gap: it lays the imported store into the exact
//! server-servable layout and, for a named database, registers it in the catalog — so a subsequent
//! `graphus-server` boot serves it like any normally-created database, ACID and crash-safe.
//!
//! It is an **offline** operation (run while the server is stopped): the heavy lifting is
//! [`crate::dbcatalog::adopt_offline_store`], which copies + `fsync`s the store, opens it through the
//! server's recover→verify path, and persists the catalog entry last. This module is only the CLI
//! surface: argument parsing, config resolution (so the adopt target matches the server's own
//! `store_path`/encryption), and the operator-facing report.
//!
//! ```text
//! graphus-server adopt --from <import-dir> [--database <name>] [--config <file>] [--offline]
//! ```
//!
//! - `--from <import-dir>` (required): a `graphus-bulk import --db <dir>` output directory.
//! - `--database <name>` (default: the config's `default_database`): the target database name. When it
//!   equals the default database, the store is laid directly into the data root (no catalog); any
//!   other name is laid under `databases/<name>/` and registered in `databases.toml`.
//! - `--config <file>` (default: `$GRAPHUS_CONFIG`, else built-in defaults + `GRAPHUS_*` env): the
//!   **same** server config the server will run with, so the data root, default-database name, and
//!   encryption setting all match. Persist the store where the server will actually look for it.
//! - `--offline`: register a **named** database as `offline` (the operator must `START DATABASE`
//!   it later) instead of the default `online` (served automatically at the next boot). Ignored for
//!   the default database, which is always online while the server runs.
//!
//! To persist each node's original CSV `:ID` as a **queryable** property (so the adopted store can be
//! queried by original id, e.g. `MATCH (n:Person {personId: '42'})`), run the import with
//! `graphus-bulk import ... --persist-id` and a **named** `:ID` column (`personId:ID`). That is an
//! import-time choice (the external ids are only present in the CSV); adoption preserves whatever the
//! import stored.

use std::path::PathBuf;

use crate::config::ServerConfig;
use crate::dbcatalog::{AdoptOutcome, adopt_offline_store};

/// The `adopt` subcommand's usage text.
pub fn usage() -> String {
    "graphus-server adopt — make a graphus-bulk offline-imported store server-servable (rmp #681)\n\n\
     USAGE:\n  \
       graphus-server adopt --from <import-dir> [--database <name>] [--config <file>] [--offline]\n\n\
     --from <import-dir>   a `graphus-bulk import --db <dir>` output (graph.store + graph.wal/). Required.\n  \
     --database <name>     target database name (default: the config's default_database). A non-default\n  \
                           name is laid under databases/<name>/ and registered in databases.toml; the\n  \
                           default name is laid directly into the data root (implicit default database).\n  \
     --config <file>       the server config to resolve store_path / default_database / encryption from\n  \
                           (default: $GRAPHUS_CONFIG, else built-in defaults + GRAPHUS_* env).\n  \
     --offline             register a NAMED database as offline (START DATABASE it later) instead of\n  \
                           online (served at the next boot). Ignored for the default database.\n\n\
     NOTES:\n  \
       * Adoption is OFFLINE — run it while the server for this data root is stopped.\n  \
       * A plaintext graphus-bulk store cannot be adopted into an ENCRYPTED server (it would fail to\n  \
         open); adopt into a plaintext server, or load over the network bulk-import path instead.\n  \
       * To query nodes by their original CSV :ID, import with `graphus-bulk import ... --persist-id`\n  \
         and a NAMED :ID column (e.g. `personId:ID`) BEFORE adopting.\n"
        .to_owned()
}

/// Parses the `adopt` subcommand's arguments (everything after `adopt`), runs the adoption, and
/// prints an operator-facing report. Returns a human-readable error string on failure.
pub fn run(args: Vec<String>) -> Result<(), String> {
    let mut from: Option<PathBuf> = None;
    let mut database: Option<String> = None;
    let mut config_path: Option<PathBuf> = None;
    let mut online = true;

    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--from" => from = Some(PathBuf::from(next_value(&mut it, "--from")?)),
            "--database" | "--db" => database = Some(next_value(&mut it, "--database")?),
            "--config" => config_path = Some(PathBuf::from(next_value(&mut it, "--config")?)),
            "--offline" => online = false,
            "--online" => online = true,
            "-h" | "--help" | "help" => {
                println!("{}", usage());
                return Ok(());
            }
            other => return Err(format!("unexpected argument `{other}`\n\n{}", usage())),
        }
    }

    let from = from.ok_or_else(|| format!("adopt requires --from <import-dir>\n\n{}", usage()))?;

    // Resolve config the SAME way the server does (explicit --config, else $GRAPHUS_CONFIG, else
    // defaults + GRAPHUS_* env), so the adopt target matches the server's store_path / encryption.
    let resolved_config =
        config_path.or_else(|| std::env::var_os("GRAPHUS_CONFIG").map(PathBuf::from));
    let config = ServerConfig::load(resolved_config.as_deref())
        .map_err(|e| format!("loading server config: {e}"))?;

    let database = database.unwrap_or_else(|| config.default_database.clone());

    let outcome = adopt_offline_store(&config, &from, &database, online)
        .map_err(|e| format!("adopt failed: {e}"))?;

    print_report(&config, &outcome);
    Ok(())
}

/// Prints the operator-facing adoption report + next steps.
fn print_report(config: &ServerConfig, outcome: &AdoptOutcome) {
    println!(
        "adopted store as database {:?} ({} nodes, {} relationships)",
        outcome.database, outcome.nodes, outcome.relationships
    );
    println!("  store: {}", outcome.target_dir.display());
    if outcome.is_default {
        println!(
            "  served as the DEFAULT database at the next `graphus-server` boot (store_path = {}).",
            config.store_path.display()
        );
    } else {
        match outcome.desired_state {
            Some(crate::dbcatalog::DbState::Online) => println!(
                "  registered ONLINE in databases.toml — served automatically at the next \
                 `graphus-server` boot; query it via the `{}` database (e.g. REST /db/{}/tx or Bolt \
                 with the database selected).",
                outcome.database, outcome.database
            ),
            Some(crate::dbcatalog::DbState::Offline) => println!(
                "  registered OFFLINE in databases.toml — run `START DATABASE {}` (once the server \
                 is up) to serve it.",
                outcome.database
            ),
            _ => {}
        }
    }
}

/// Consumes the next CLI value after a flag, erroring if it is missing.
fn next_value(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} requires a value"))
}
