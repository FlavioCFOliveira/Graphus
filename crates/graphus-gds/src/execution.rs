//! The parallelism / determinism **execution knob** shared by every GDS algorithm.
//!
//! Graphus's mandate is to exploit **all** available CPU cores under load, while remaining
//! reproducible for the Deterministic Simulation Testing (DST) simulator. Those two goals meet in a
//! single [`Execution`] value threaded into each algorithm:
//!
//! - It selects **sequential vs data-parallel** execution ([`ExecMode`]).
//! - Every parallel path in this crate is **deterministic by construction** — a fixed reduction
//!   order and deterministic tie-breaking — so the result is:
//!   - **bit-identical to the sequential result** for the integer/exact algorithms
//!     (WCC, degree, triangle counting), and
//!   - **reproducible run-to-run and across rayon pool widths** for the floating-point ones
//!     (PageRank), matching the sequential result to a documented tolerance.
//!
//! There is deliberately **no non-deterministic mode**: an ACID database whose behaviour is replayed
//! by a deterministic simulator must never depend on how a thread pool happened to split the work.
//! "Force deterministic" is therefore not a toggle you can turn *off* — it is a guarantee this crate
//! upholds in both modes. The knob's only axis is *how many cores* to use, never *whether the answer
//! is stable*.
//!
//! # Which algorithms are bit-identical across modes
//!
//! | Algorithm | Parallel form | Relationship to the sequential result |
//! |-----------|---------------|----------------------------------------|
//! | PageRank / Personalized PageRank | pull/gather over a transpose, one output per node | reproducible; matches sequential to `≈ tolerance` (both converge to the same fixed point) |
//! | Triangle counting | node-centric, one count per node | **bit-identical** (integer) |
//! | Weakly Connected Components | lock-free link-by-min union-find | **bit-identical** (min-id labels are a graph invariant) |
//! | Degree centrality (out) | one slot per node | **bit-identical** (integer) |
//! | Closeness / Betweenness | per-source, fixed-order fold | **bit-identical** (fixed accumulation order) |
//! | Label propagation | **synchronous** sweeps | deterministic, but a *distinct variant* from the sequential semi-synchronous default (see [`crate::algo::community`]) |
//!
//! Strongly Connected Components (Tarjan) and single-source Dijkstra / Bellman-Ford are inherently
//! sequential in their classic form; see their module docs for why, and for the parallel entry points
//! that exist alongside them ([`crate::algo::shortest_path::dijkstra_multi_source`]).

use crate::error::Result;
use rayon::prelude::*;

/// Whether an algorithm runs sequentially or fans its work across cores with `rayon`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecMode {
    /// Run on a single thread. Always fully deterministic and the cheapest choice for small graphs
    /// (no thread-pool hand-off, no split overhead).
    Sequential,
    /// Fan the work across `rayon` when the problem is large enough (see
    /// [`Execution::min_parallel_work`]). Deterministic by construction — the result does not depend
    /// on the pool width or on work-stealing order.
    Parallel,
}

/// The execution knob threaded into every GDS algorithm.
///
/// Construct one with [`Execution::sequential`], [`Execution::parallel`], or
/// [`Execution::parallel_with_threshold`]; [`Execution::default`] is [`Execution::parallel`] with the
/// [`Execution::DEFAULT_MIN_PARALLEL_WORK`] threshold, so a production multi-core server gets
/// multi-core GDS out of the box while still running tiny graphs serially.
///
/// The pool the parallel work lands on is chosen by the **caller** (via `rayon`'s
/// [`ThreadPool::install`](rayon::ThreadPool::install)), not by this type — the server routes GDS
/// onto its bounded analytics pool exactly as it does for centrality. This keeps `graphus-gds`
/// free of any server/pool policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Execution {
    mode: ExecMode,
    /// Below this many units of work (nodes or sources, algorithm-dependent) the algorithm runs
    /// sequentially even in [`ExecMode::Parallel`], because the thread-pool overhead would dominate.
    min_parallel_work: usize,
}

impl Execution {
    /// The default parallel threshold: problems smaller than this run sequentially. Chosen so that
    /// the fixed-cost of a `rayon` fan-out (task creation + join) is comfortably amortised, while
    /// still keeping the reference/determinism graphs used across the test-suite (a few hundred
    /// nodes) on the genuinely parallel path.
    pub const DEFAULT_MIN_PARALLEL_WORK: usize = 128;

    /// Force sequential execution — the simplest, always-deterministic choice.
    #[must_use]
    pub const fn sequential() -> Self {
        Self {
            mode: ExecMode::Sequential,
            // `usize::MAX` means "never parallel", so `is_parallel` is a single comparison.
            min_parallel_work: usize::MAX,
        }
    }

    /// Data-parallel execution above [`Execution::DEFAULT_MIN_PARALLEL_WORK`] units of work.
    #[must_use]
    pub const fn parallel() -> Self {
        Self {
            mode: ExecMode::Parallel,
            min_parallel_work: Self::DEFAULT_MIN_PARALLEL_WORK,
        }
    }

    /// Data-parallel execution above a custom work threshold. A threshold of `0` parallelises
    /// unconditionally (useful in tests that must exercise the parallel path on a small graph).
    #[must_use]
    pub const fn parallel_with_threshold(min_parallel_work: usize) -> Self {
        Self {
            mode: ExecMode::Parallel,
            min_parallel_work,
        }
    }

    /// The execution mode.
    #[must_use]
    pub const fn mode(self) -> ExecMode {
        self.mode
    }

    /// The parallel work threshold (see the `min_parallel_work` field docs).
    #[must_use]
    pub const fn min_parallel_work(self) -> usize {
        self.min_parallel_work
    }

    /// Whether a problem of the given `work` size should run in parallel.
    #[must_use]
    pub const fn is_parallel(self, work: usize) -> bool {
        matches!(self.mode, ExecMode::Parallel) && work >= self.min_parallel_work
    }

    /// Like [`Execution::is_parallel`], but the `work` must additionally clear an **algorithm-specific
    /// `floor`** (`rmp` #580).
    ///
    /// The crate-wide [`Execution::DEFAULT_MIN_PARALLEL_WORK`] is calibrated for algorithms whose
    /// per-element work is non-trivial. A few algorithms need a higher bar before parallelism pays off:
    /// **degree centrality** does a single offset subtraction per node (so it is memory-bandwidth bound
    /// and only profits at very large `n`), and the **lock-free WCC** union-find pays fixed
    /// atomic/`rayon` overhead that a small graph cannot amortise. Empirically (see
    /// `tests/perf_probe.rs`) both *regress* — parallel slower than sequential — below their floor, so
    /// they gate on it here rather than on the generic threshold.
    ///
    /// An explicit [`Execution::parallel_with_threshold`]`(0)` — the test "force parallel" knob —
    /// bypasses the floor, so the parallel code path is still exercised on small test graphs.
    #[must_use]
    pub const fn is_parallel_floor(self, work: usize, floor: usize) -> bool {
        if !matches!(self.mode, ExecMode::Parallel) {
            return false;
        }
        // `parallel_with_threshold(0)` is an explicit "force parallel even when tiny" request.
        if self.min_parallel_work == 0 {
            return work > 0;
        }
        work >= self.min_parallel_work && work >= floor
    }

    /// Maps `0..len` into a `Vec<T>` with `f`, serially or in parallel per the knob, propagating the
    /// first error — the cooperative-cancellation idiom the per-source / per-node algorithms use.
    ///
    /// Determinism: `collect` preserves input (index) order for an indexed parallel iterator, and
    /// each `f(i)` is an independent pure function of `i`, so `out[i]` is identical whether the range
    /// was split across 1 or 64 workers.
    pub(crate) fn try_map<T, F>(self, len: usize, f: F) -> Result<Vec<T>>
    where
        T: Send,
        F: Fn(usize) -> Result<T> + Sync + Send,
    {
        if self.is_parallel(len) {
            (0..len).into_par_iter().map(f).collect()
        } else {
            (0..len).map(f).collect()
        }
    }

    /// Writes `f(i)` into `out[i]` for every `i`, serially or in parallel per the knob.
    ///
    /// Determinism: each slot is written exactly once by its own index, and `f` reads only shared
    /// immutable state, so the buffer is identical regardless of how the range was split. Infallible;
    /// callers needing per-element cancellation use [`Execution::try_map`] instead (cancellation for
    /// these callers is checked at a coarser, per-iteration granularity).
    pub(crate) fn map_into<T, F>(self, out: &mut [T], f: F)
    where
        T: Send,
        F: Fn(usize) -> T + Sync + Send,
    {
        if self.is_parallel(out.len()) {
            out.par_iter_mut()
                .enumerate()
                .for_each(|(i, slot)| *slot = f(i));
        } else {
            out.iter_mut()
                .enumerate()
                .for_each(|(i, slot)| *slot = f(i));
        }
    }

    /// Runs `f(i)` for every `i in 0..len` for its side effects, serially or in parallel per the
    /// knob, propagating the first error. Used by the lock-free WCC union phase, where `f` performs
    /// atomic union operations against shared state.
    pub(crate) fn try_for_each<F>(self, len: usize, f: F) -> Result<()>
    where
        F: Fn(usize) -> Result<()> + Sync + Send,
    {
        if self.is_parallel(len) {
            (0..len).into_par_iter().try_for_each(f)
        } else {
            (0..len).try_for_each(f)
        }
    }

    /// The fixed reduction block size for [`Execution::det_reduce`]. Chosen large enough that the
    /// per-chunk serial sum amortises the parallel task overhead, and small enough that a many-core
    /// pool still gets plenty of chunks to balance. It is a **constant** (never a function of the pool
    /// width), which is exactly what makes the reduction bit-identical across widths.
    const REDUCE_CHUNK: usize = 8192;

    /// A **deterministic** floating-point reduction of `f(0)..f(len)` into a sum, run serially or in
    /// parallel per the knob.
    ///
    /// Determinism across pool widths is the whole point: the range is split into **fixed-size** blocks
    /// of [`Execution::REDUCE_CHUNK`] elements; each block is summed **serially in ascending index
    /// order**, and the per-block partials are then combined **serially in ascending block order**.
    /// Because the block boundaries depend only on `len` — never on how `rayon` happened to split the
    /// work — the result is **bit-identical in [`ExecMode::Sequential`] and [`ExecMode::Parallel`] and
    /// across every pool width**. Only *whether the blocks are evaluated concurrently* differs. This is
    /// the sanctioned alternative to a `rayon` tree-reduce, whose association order (and therefore
    /// floating-point result) would depend on the pool width.
    pub(crate) fn det_reduce<F>(self, len: usize, f: F) -> f64
    where
        F: Fn(usize) -> f64 + Sync + Send,
    {
        if len == 0 {
            return 0.0;
        }
        let chunk = Self::REDUCE_CHUNK;
        let n_chunks = len.div_ceil(chunk);
        // The serial sum of block `c` (ascending index order within the block).
        let block_sum = |c: usize| -> f64 {
            let start = c * chunk;
            let end = (start + chunk).min(len);
            let mut acc = 0.0f64;
            for i in start..end {
                acc += f(i);
            }
            acc
        };
        if self.is_parallel(len) {
            // Per-block partials computed across cores; `collect` preserves block (index) order, so the
            // final serial fold is over `partials[0], partials[1], ...` in ascending block order.
            let partials: Vec<f64> = (0..n_chunks).into_par_iter().map(block_sum).collect();
            partials.iter().sum()
        } else {
            let mut acc = 0.0f64;
            for c in 0..n_chunks {
                acc += block_sum(c);
            }
            acc
        }
    }
}

impl Default for Execution {
    /// [`Execution::parallel`] — a production server gets multi-core GDS by default, with tiny graphs
    /// still short-circuited to the sequential path.
    fn default() -> Self {
        Self::parallel()
    }
}
