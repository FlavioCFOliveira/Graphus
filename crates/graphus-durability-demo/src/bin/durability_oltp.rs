//! `durability_oltp` — the **real-server, mid-workload crash** driver + post-restart verifier
//! (`rmp` #698), and the store's path-classified on-disk footprint.
//!
//! Three modes, one per phase of the example's real-server step:
//!
//! * `--workload` — drive concurrent committing writers against a live `graphus-server` over its UDS,
//!   **with one writer holding an EXPLICIT, never-committed transaction open**, and keep going until
//!   the server is `SIGKILL`ed underneath them. Touches `--ready-file` the moment the crash would land
//!   genuinely mid-workload (open transaction + acknowledged commits), and writes `--ledger` recording
//!   exactly what the server ACKNOWLEDGED, what was left UNDETERMINED (a statement in flight when the
//!   socket died), and that the explicit transaction was still open at the kill.
//! * `--verify` — re-connect to the RESTARTED server and assert the three-way contract: every
//!   acknowledged commit is present, complete and correct; NO in-flight effect survived; no batch is
//!   half-applied or fabricated.
//! * `--footprint` — print the store directory's on-disk bytes decomposed by PATH (the WAL is a
//!   DIRECTORY of `seg.<lsn>` files: classifying by leaf file name reports `wal=0` and hides the redo
//!   log entirely).
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use graphus_durability_demo::footprint;
use graphus_durability_demo::oltp::{Ledger, WorkloadConfig, run_workload, verify};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Workload,
    Verify,
    Footprint,
}

struct Args {
    mode: Mode,
    cfg: WorkloadConfig,
    store_dir: PathBuf,
}

fn usage() -> String {
    "durability_oltp — real-server mid-workload crash driver, verifier, and store footprint\n\n\
     USAGE:\n    \
     durability_oltp --workload  --uds <sock> --user <u> --password <p> [--db <db>] \\\n        \
     [--writers N] [--batch-nodes N] [--phantom-nodes N] [--min-acked N] [--max-secs N] \\\n        \
     --ready-file <path> [--hold-file <path>] --ledger <path>\n    \
     durability_oltp --verify    --uds <sock> --user <u> --password <p> [--db <db>] --ledger <path>\n    \
     durability_oltp --footprint --store-dir <dir>\n"
        .to_owned()
}

fn parse_args() -> Result<Args, String> {
    let mut mode: Option<Mode> = None;
    let mut cfg = WorkloadConfig {
        socket: PathBuf::new(),
        user: String::new(),
        password: String::new(),
        db: String::new(),
        writers: 4,
        batch_nodes: 5,
        phantom_nodes: 4,
        min_acked_before_ready: 8,
        max_secs: 120,
        ready_file: PathBuf::new(),
        hold_file: PathBuf::new(),
        ledger_file: PathBuf::new(),
    };
    let mut store_dir = PathBuf::new();

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut val = |label: &str| -> Result<String, String> {
            it.next()
                .ok_or_else(|| format!("flag {label} needs a value"))
        };
        match arg.as_str() {
            "--workload" => mode = Some(Mode::Workload),
            "--verify" => mode = Some(Mode::Verify),
            "--footprint" => mode = Some(Mode::Footprint),
            "--uds" => cfg.socket = PathBuf::from(val("--uds")?),
            "--user" => cfg.user = val("--user")?,
            "--password" => cfg.password = val("--password")?,
            "--db" => cfg.db = val("--db")?,
            "--writers" => {
                cfg.writers = val("--writers")?
                    .parse()
                    .map_err(|_| "--writers needs an integer")?;
            }
            "--batch-nodes" => {
                cfg.batch_nodes = val("--batch-nodes")?
                    .parse()
                    .map_err(|_| "--batch-nodes needs an integer")?;
            }
            "--phantom-nodes" => {
                cfg.phantom_nodes = val("--phantom-nodes")?
                    .parse()
                    .map_err(|_| "--phantom-nodes needs an integer")?;
            }
            "--min-acked" => {
                cfg.min_acked_before_ready = val("--min-acked")?
                    .parse()
                    .map_err(|_| "--min-acked needs an integer")?;
            }
            "--max-secs" => {
                cfg.max_secs = val("--max-secs")?
                    .parse()
                    .map_err(|_| "--max-secs needs an integer")?;
            }
            "--ready-file" => cfg.ready_file = PathBuf::from(val("--ready-file")?),
            "--hold-file" => cfg.hold_file = PathBuf::from(val("--hold-file")?),
            "--ledger" => cfg.ledger_file = PathBuf::from(val("--ledger")?),
            "--store-dir" => store_dir = PathBuf::from(val("--store-dir")?),
            "-h" | "--help" => return Err(usage()),
            other => return Err(format!("unknown flag {other}\n\n{}", usage())),
        }
    }

    let mode = mode.ok_or_else(|| {
        format!(
            "one of --workload/--verify/--footprint is required\n\n{}",
            usage()
        )
    })?;
    if mode != Mode::Footprint {
        if cfg.socket.as_os_str().is_empty() {
            return Err("--uds is required".to_owned());
        }
        if cfg.ledger_file.as_os_str().is_empty() {
            return Err("--ledger is required".to_owned());
        }
        if cfg.writers == 0 || cfg.batch_nodes < 2 || cfg.phantom_nodes == 0 {
            return Err("--writers >= 1, --batch-nodes >= 2, --phantom-nodes >= 1".to_owned());
        }
    } else if store_dir.as_os_str().is_empty() {
        return Err("--store-dir is required for --footprint".to_owned());
    }

    Ok(Args {
        mode,
        cfg,
        store_dir,
    })
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            if msg.starts_with("durability_oltp —") {
                println!("{msg}");
                return ExitCode::SUCCESS;
            }
            eprintln!("error: {msg}");
            return ExitCode::FAILURE;
        }
    };

    match args.mode {
        Mode::Footprint => {
            let fp = footprint::measure(&args.store_dir);
            // Decomposed by PATH: the WAL is a directory of `seg.<lsn>` files.
            println!("store.wal_bytes={}", fp.wal_bytes);
            println!("store.data_bytes={}", fp.data_bytes);
            println!("store.dwb_bytes={}", fp.dwb_bytes);
            println!("store.other_bytes={}", fp.other_bytes);
            println!("store.store_bytes={}", fp.store_bytes());
            println!("store.total_bytes={}", fp.total_bytes());
            match footprint::locate_db_paths(&args.store_dir) {
                Some((store, wal)) => {
                    println!("store.data_path={}", store.display());
                    println!("store.wal_path={}", wal.display());
                }
                None => {
                    eprintln!(
                        "durability_oltp: no databases/<db>/ layout under {}",
                        args.store_dir.display()
                    );
                    return ExitCode::FAILURE;
                }
            }
            ExitCode::SUCCESS
        }

        Mode::Workload => {
            eprintln!(
                "durability_oltp: {} committing writers + 1 writer holding an OPEN, never-committed \
                 transaction ({} :Phantom rows); the crash must land while they run",
                args.cfg.writers, args.cfg.phantom_nodes
            );
            match run_workload(&args.cfg) {
                Ok(l) => {
                    print!("{}", l.render());
                    eprintln!(
                        "durability_oltp: server died with {} acked commit(s), {} undetermined, \
                         open-txn-at-kill={} (held across {} in-transaction probes; died with: {})",
                        l.acked.len(),
                        l.undetermined.len(),
                        l.phantom_txn_open_at_kill,
                        l.phantom_hold_probes,
                        l.phantom_txn_error,
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("durability_oltp: workload failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }

        Mode::Verify => {
            let ledger = match Ledger::load(&args.cfg.ledger_file) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!(
                        "durability_oltp: cannot read ledger {}: {e}",
                        args.cfg.ledger_file.display()
                    );
                    return ExitCode::FAILURE;
                }
            };
            match verify(&args.cfg, &ledger) {
                Ok(r) => {
                    print!("{}", r.render());
                    if r.passed() {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                Err(e) => {
                    eprintln!("durability_oltp: verification could not run: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}
