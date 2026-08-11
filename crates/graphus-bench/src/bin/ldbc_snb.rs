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

/// The heap profiler's allocator, installed **only** under the `dhat-heap` feature (CLAUDE.md,
/// "Empirical measurement"). Compiled out of every normal build, so the timings this harness reports
/// by default remain those of the uninstrumented allocator.
#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() -> ExitCode {
    // Armed before generation so the report covers the whole run — building the graph is itself a
    // heap consumer worth attributing, not just the query mix. Bound to a named local so it lives
    // until `main` returns; its `Drop` writes `dhat-heap.json` into the working directory.
    //
    // NOTE when reading the numbers: with this feature on, every allocation captures a backtrace, so
    // the throughput and latency columns printed below are NOT comparable to an ordinary run. Use
    // this build for *where the heap goes*, and a normal build for *how fast it is*.
    #[cfg(feature = "dhat-heap")]
    let _dhat_profiler = dhat::Profiler::new_heap();

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
