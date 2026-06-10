//! `ldbc_snb` — runs the LDBC-SNB-flavoured macro benchmark to completion and prints its report.
//!
//! This is the runnable embodiment of `rmp` task #27's "LDBC SNB runs" acceptance criterion: it
//! generates a synthetic social graph through the real Graphus engine pipeline and times a mix of
//! SNB-style read/write operations, printing throughput + latency percentiles.
//!
//! Usage:
//! ```text
//! cargo run -p graphus-bench --bin ldbc_snb              # tiny scale (a few seconds)
//! cargo run -p graphus-bench --release --bin ldbc_snb -- --medium
//! ```
//!
//! Exit status is `0` on a successful run, `1` if graph generation failed (a harness bug). Per-
//! operation "deferred" outcomes (unsupported Cypher) are reported, not treated as failures — the
//! engine's supported subset grows over time and the harness is honest about today's coverage.

use std::process::ExitCode;

use graphus_bench::ldbc::{self, generator::ScaleFactor};

fn main() -> ExitCode {
    let medium = std::env::args().any(|a| a == "--medium");
    let scale = if medium {
        ScaleFactor::medium()
    } else {
        ScaleFactor::tiny()
    };

    eprintln!(
        "[ldbc_snb] generating + running at {} scale …",
        if medium { "medium" } else { "tiny" }
    );

    match ldbc::run(scale) {
        Ok(report) => {
            print!("{}", ldbc::render(&report));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("[ldbc_snb] FAILED during graph generation: {e}");
            ExitCode::FAILURE
        }
    }
}
