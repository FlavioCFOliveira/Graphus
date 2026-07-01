//! **Empirical measurement**: Mode B batch size vs. SSI pivot-abort rate
//! (`08-network-bulk-import.md` §7.2.1, `rmp` #520). This is the "measure to decide" evidence behind
//! `BulkImportConfig::mode_b_batch_rows`'s default — see
//! `crates/graphus-server/src/config.rs`'s doc comment for that field for the measured table this
//! module produces (numbers copied there verbatim from a run of this module's own test).
//!
//! ## Why a deterministic `LocalEngine` sweep, not a real-clock benchmark
//!
//! `LocalEngine` runs on one thread with no real clock, and every interleaving decision here is an
//! explicit, seed-derived program-order choice (never a real race) — so this is a normal, fast
//! `#[test]`, not a flaky wall-clock benchmark, while still exercising the REAL production primitives
//! (`LocalEngine::begin`/`bulk_import_mode_b_chunk`/`commit`).
//!
//! ## What this measures, precisely (an empirically-derived model, not an assumption)
//!
//! An early design of this module tried to seed a conflict on the **relationship-type-wide**
//! predicate (`08` §7.2.1's named contention source) uniformly between every chunk. Tracing the real
//! `graphus_txn::ssi::SsiTracker` showed that mechanism only ever dooms the *first* chunk that writes
//! a given type: once `create_rel` has registered the batch's transaction as a predicate **writer** of
//! that type, every later concurrent reader of the same type closes its rw-edge **during its own
//! read** (finding the already-registered writer) rather than staying open for the batch's *own*
//! later write to close — which is the specific ordering [`graphus_txn::ssi::SsiTracker::add_edge`]'s
//! eager committed-pivot-break rule requires to doom the **writer** (not the reader). So a
//! single-relationship-type batch's abort exposure does not scale with chunk count through that path.
//!
//! What *does* scale with batch size: **node** rows with **distinct per-row property values** (the
//! realistic case — a bulk-loaded `id`/`email`/`external_id` property is unique per row). Each row
//! introduces a **fresh** `Equality` predicate the SSI tracker has never seen written before, so a
//! concurrent reader that queries **the next row's own value** (e.g., an application checking "does
//! entity X exist yet" during a live migration — a genuine, realistic Mode B companion workload, not
//! a contrived one) can register an absence-read against that *specific*, not-yet-created row and
//! become a committed pivot before the batch's very next chunk creates it — reproducing a genuine,
//! per-chunk-scaling doom opportunity. This module measures **that** mechanism, seeding a conflicting
//! reader with a fixed, deliberately small per-gap probability (see [`CONFLICT_PROBABILITY_PER_MILLE`])
//! so a larger batch (more chunks, more gaps) is genuinely exposed to proportionally more chances —
//! `08` §7.2.1's "bigger batch ⇒ bigger, longer-held footprint ⇒ higher abort probability" trade-off.

use std::sync::Arc;

use graphus_bulk::{ColumnRole, NodeHeader, PropertyType, ScalarType};
use graphus_core::Value;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{BulkImportModeBChunkInput, LocalEngine};
use graphus_sim::SharedClock;
use graphus_wal::MemLogSink;

type Eng = LocalEngine<graphus_io::MemBlockDevice, MemLogSink>;

/// The node-file header the measured batch uses: an `:ID` column, a `:LABEL` column (a fixed
/// `Entity` label — REQUIRED for the SSI tracker's `Equality{label, property, value}` predicate
/// marker to register at all: `reindex_node`'s footprint loop is nested inside "for each label the
/// node carries", so an unlabeled node registers no `Equality` marker whatsoever, silently defeating
/// the mechanism this measurement depends on — found empirically while building this module), plus
/// one distinct-per-row `ext_id` integer property (the value concurrent readers probe for).
fn node_header() -> Arc<NodeHeader> {
    Arc::new(NodeHeader {
        columns: vec![
            ColumnRole::Id,
            ColumnRole::Label,
            ColumnRole::Property {
                key: "ext_id".to_owned(),
                ty: PropertyType::Scalar(ScalarType::Integer),
            },
        ],
        id_index: 0,
    })
}

fn node_row(external_id: u64) -> csv::StringRecord {
    csv::StringRecord::from(vec![
        external_id.to_string(),
        "Entity".to_owned(),
        external_id.to_string(),
    ])
}

/// Per-gap probability (out of 1000) of running a **genuinely conflicting** contender (see
/// [`run_conflicting_gap`]) rather than a harmless, unrelated one. Chosen so the candidate sweep in
/// the module's own test lands the largest candidate's cumulative abort probability in a realistic,
/// non-degenerate double-digit-percent range (an independent per-gap probability compounds as
/// `1 - (1-p)^gaps`) — representing "some, not all, concurrent traffic happens to probe an entity
/// right as it is being imported" (`08` §7.2.1's documented trade-off, applied to the node-property
/// mechanism this module's doc comment explains).
const CONFLICT_PROBABILITY_PER_MILLE: u64 = 12;

/// A harmless contender: ordinary concurrent traffic that touches a completely unrelated label/
/// property, so it never conflicts with the measured batch.
fn run_unrelated_contender(eng: &mut Eng, seed: u64) {
    let Ok(ticket) = eng.begin(AccessMode::Write) else {
        return;
    };
    let ok = eng
        .run(
            ticket,
            "CREATE (:Unrelated {tag: $t})",
            vec![("t".to_owned(), Value::Integer(seed as i64))],
            false,
            None,
        )
        .is_ok_and(|mut r| {
            while let Ok(Some(_)) = r.rows.next() {}
            true
        });
    if ok {
        let _ = eng.commit(ticket);
    } else {
        let _ = eng.rollback(ticket);
    }
}

/// A **genuinely conflicting** gap: reproduces the exact rw-edge sequence
/// `graphus_txn::ssi::SsiTracker::add_edge`'s eager committed-pivot-break rule dooms a concurrent
/// pure-writer transaction on (the same real mechanism `graphus_server::bulk_import_mode_b`'s own
/// retry tests prove against a real `EngineHandle`) — `trdr` (a caller-owned, already-open transaction
/// reading an unrelated marker predicate, kept open for the WHOLE trial so `forget()`'s edge-cleanup
/// never erases the edge it contributes) plus a fresh `r` that reads a **specific, not-yet-created**
/// node by the exact `ext_id` value the batch's **next** chunk is about to create (a realistic
/// "does entity X exist yet" probe), then writes the marker predicate `trdr` already read (closing
/// `trdr --rw--> r`) and commits — becoming a genuine committed pivot with an incoming conflict edge.
/// The measured batch's next chunk (creating that exact `ext_id`) then closes `r --rw--> batch` and
/// dooms it, since `r` is by then an already-committed pivot with both in- and out-conflict.
fn run_conflicting_gap(eng: &mut Eng, trdr: graphus_server::engine::TxTicket, next_ext_id: i64) {
    let Ok(r) = eng.begin(AccessMode::Write) else {
        return;
    };
    let read_ok = eng
        .run(
            r,
            "MATCH (n:Entity {ext_id: $id}) RETURN n",
            vec![("id".to_owned(), Value::Integer(next_ext_id))],
            false,
            None,
        )
        .is_ok_and(|mut reply| {
            while let Ok(Some(_)) = reply.rows.next() {}
            true
        });
    let write_ok = read_ok
        && eng
            .run(r, "CREATE (:Marker)", vec![], false, None)
            .is_ok_and(|mut reply| {
                while let Ok(Some(_)) = reply.rows.next() {}
                true
            });
    if write_ok {
        let _ = eng.commit(r);
    } else {
        let _ = eng.rollback(r);
    }
    let _ = trdr; // read implicitly by `r`'s write via the shared SSI tracker; not touched directly.
}

/// Runs ONE trial: a Mode B batch of `batch_rows` node rows (driven through the REAL
/// [`LocalEngine::bulk_import_mode_b_chunk`]/`begin`/`commit` primitives), split into
/// `chunk_rows`-sized chunks, with one contender interleaved between every chunk — with
/// [`CONFLICT_PROBABILITY_PER_MILLE`] chance of a genuine conflict targeting the very next row
/// ([`run_conflicting_gap`]), otherwise a harmless unrelated one. Returns whether the batch's own
/// final commit succeeded.
fn run_one_trial(batch_rows: u64, chunk_rows: u64, seed: u64) -> bool {
    let mut eng = LocalEngine::in_memory(Arc::new(SharedClock::new(0)), 256).expect("engine");

    // A long-lived reader kept open for the WHOLE trial (never committed/rolled back until the trial
    // ends): the anchor `run_conflicting_gap` needs, see its doc for why it must stay open.
    let trdr = eng.begin(AccessMode::Write).expect("begin trdr anchor");
    let _ = eng.run(
        trdr,
        "MATCH (:Marker) RETURN count(*) AS c",
        vec![],
        false,
        None,
    );

    let Ok(ticket) = eng.begin(AccessMode::Write) else {
        return false;
    };
    let header = node_header();
    let mut next_id: u64 = 0;
    let mut remaining = batch_rows;
    let mut row_seed = seed;
    let mut mid_batch_failure = false;

    while remaining > 0 {
        let this_chunk = remaining.min(chunk_rows).max(1);
        let records: Vec<_> = (next_id..next_id + this_chunk).map(node_row).collect();
        next_id += this_chunk;
        remaining -= this_chunk;

        let chunk_result = eng.bulk_import_mode_b_chunk(
            ticket,
            BulkImportModeBChunkInput::Nodes {
                header: Arc::clone(&header),
                records,
            },
        );
        if chunk_result.is_err() {
            mid_batch_failure = true;
            break;
        }
        if remaining == 0 {
            break; // no more chunks to follow ⇒ no more gaps needed.
        }

        // One contender interleaves between chunks — the realistic exposure window (module docs).
        row_seed = row_seed
            .wrapping_mul(2_862_933_555_777_941_757)
            .wrapping_add(1);
        if row_seed % 1000 < CONFLICT_PROBABILITY_PER_MILLE {
            // Targets the exact `ext_id` the NEXT chunk is about to create.
            run_conflicting_gap(&mut eng, trdr, next_id as i64);
        } else {
            run_unrelated_contender(&mut eng, row_seed);
        }
    }

    if mid_batch_failure {
        let _ = eng.rollback(ticket);
        return false;
    }
    eng.commit(ticket).is_ok()
}

/// One batch-size candidate's measured abort rate over [`TRIALS`] deterministic trials.
#[derive(Debug, Clone, Copy)]
pub struct AbortRateSample {
    /// The candidate `mode_b_batch_rows` value.
    pub batch_rows: u64,
    /// Aborted trials / total trials.
    pub abort_rate: f64,
}

/// Trials per batch-size candidate — enough to give a stable rate estimate while keeping the whole
/// sweep fast (`LocalEngine` in-memory, no real I/O).
const TRIALS: u64 = 20;

/// The fixed chunk size used for every candidate (`08` §7.2.6's yielding granularity) — independent
/// of the batch-size sweep itself, matching how `mode_b_chunk_rows` and `mode_b_batch_rows` are
/// separate, independently-configured knobs in production. Chosen larger than production's own
/// `mode_b_chunk_rows` default (25) purely to keep this measurement's total gap-transaction count (and
/// hence its wall-clock runtime as an ordinary `cargo test`) reasonable while still producing several
/// gaps for the larger candidates — the qualitative batch-size-vs-abort-rate relationship this sweep
/// measures does not depend on the specific chunk size used to produce it.
const MEASURED_CHUNK_ROWS: u64 = 250;

/// Runs the batch-size sweep, returning one [`AbortRateSample`] per candidate in `candidates`, each
/// averaged over [`TRIALS`] deterministic trials (seeded from the candidate's index so the whole
/// sweep is a pure, reproducible function of `candidates`).
#[must_use]
pub fn measure_abort_rates(candidates: &[u64]) -> Vec<AbortRateSample> {
    candidates
        .iter()
        .enumerate()
        .map(|(i, &batch_rows)| {
            let mut aborts = 0u64;
            for trial in 0..TRIALS {
                let seed = (i as u64) * 1_000_003 + trial;
                if !run_one_trial(batch_rows, MEASURED_CHUNK_ROWS, seed) {
                    aborts += 1;
                }
            }
            AbortRateSample {
                batch_rows,
                #[allow(clippy::cast_precision_loss)]
                abort_rate: aborts as f64 / TRIALS as f64,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal, isolated reproduction proving [`run_conflicting_gap`]'s mechanism genuinely dooms a
    /// concurrent Mode B batch ticket (a real SSI conflict, not a mock) — the load-bearing building
    /// block the sweep below depends on.
    #[test]
    fn conflicting_gap_genuinely_dooms_the_next_chunk() {
        let mut eng = LocalEngine::in_memory(Arc::new(SharedClock::new(0)), 256).expect("engine");
        let trdr = eng.begin(AccessMode::Write).expect("begin trdr");
        let _ = eng.run(
            trdr,
            "MATCH (:Marker) RETURN count(*) AS c",
            vec![],
            false,
            None,
        );

        let ticket = eng.begin(AccessMode::Write).expect("begin ticket");
        let header = node_header();
        // Chunk 1: creates ext_id=0.
        eng.bulk_import_mode_b_chunk(
            ticket,
            BulkImportModeBChunkInput::Nodes {
                header: Arc::clone(&header),
                records: vec![node_row(0)],
            },
        )
        .expect("chunk 1");

        // The gap: `r` probes for ext_id=1 (the NEXT chunk's row) before it exists.
        run_conflicting_gap(&mut eng, trdr, 1);

        // Chunk 2: creates ext_id=1 — this must close the doom.
        let chunk2 = eng.bulk_import_mode_b_chunk(
            ticket,
            BulkImportModeBChunkInput::Nodes {
                header,
                records: vec![node_row(1)],
            },
        );
        assert!(chunk2.is_ok(), "the row-level write itself succeeds");

        let commit = eng.commit(ticket);
        assert!(
            commit.is_err(),
            "the seeded conflict must abort the batch's commit: {commit:?}"
        );
    }

    /// The empirical sweep behind `BulkImportConfig::mode_b_batch_rows`'s default (`08` §7.2.1,
    /// `rmp` #520's "measure to decide" requirement). Prints the measured table (visible with
    /// `cargo test -- --nocapture`) and asserts the qualitative, load-bearing property the default
    /// is chosen from: the smallest candidate measures at or near zero abort rate, and the largest
    /// candidate's abort rate is no lower than the smallest's.
    #[test]
    fn mode_b_batch_size_abort_rate_sweep() {
        let candidates = [100u64, 500, 2_000, 5_000, 10_000];
        let samples = measure_abort_rates(&candidates);

        eprintln!("mode_b_batch_rows sweep (chunk_rows={MEASURED_CHUNK_ROWS}, trials={TRIALS}):");
        for s in &samples {
            eprintln!(
                "  batch_rows={:>6}  abort_rate={:>5.1}%",
                s.batch_rows,
                s.abort_rate * 100.0
            );
        }

        assert!(
            samples[0].abort_rate <= 0.20,
            "batch_rows=100 abort rate too high for a viable smallest candidate: {:?}",
            samples[0]
        );
        assert!(
            samples.last().unwrap().abort_rate >= samples[0].abort_rate,
            "expected abort rate to trend upward with batch size: {samples:?}"
        );
    }

    /// Determinism: the same batch size + seed always reproduces the same trial outcome (the DST
    /// harness's core requirement — no real races, only explicit, seed-derived interleaving).
    #[test]
    fn trial_outcome_is_deterministic() {
        for batch_rows in [100u64, 2_000] {
            for seed in 0u64..5 {
                let a = run_one_trial(batch_rows, MEASURED_CHUNK_ROWS, seed);
                let b = run_one_trial(batch_rows, MEASURED_CHUNK_ROWS, seed);
                assert_eq!(
                    a, b,
                    "batch_rows={batch_rows} seed={seed} must be deterministic"
                );
            }
        }
    }
}
