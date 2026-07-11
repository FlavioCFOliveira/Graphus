//! Measuring the **on-disk footprint** of a bulk-loaded store, and the amplification ratios and
//! per-element costs derived from it.
//!
//! This lives in the library, not in one binary, because three drivers need the *same* numbers over
//! the *same* store image: `bulk_evidence` (which imports, times, and then meters the store it just
//! built), `bulk_reopen` (which meters the WAL residual a reopen has to replay, before and after),
//! and any future consumer. Duplicating it per binary is how two drivers end up importing the same
//! dataset twice and reporting per-element costs over two *different* store images — real arithmetic
//! over mismatched inputs, which the examples' evidence-honesty rules call out by name.
//!
//! # The store layout
//!
//! `graphus-bulk import --db <dir>` writes a flat pair:
//!
//! ```text
//! <dir>/graph.store     the durable block-device image (the graph)
//! <dir>/graph.wal/      the segmented redo log — a DIRECTORY of seg.<lsn> files
//! ```
//!
//! The WAL is a **directory**. Classifying the footprint by leaf file name would count every WAL byte
//! as store and report `wal_bytes: 0`, silently hiding the entire redo log — so it is classified by
//! **path** ([`StorageMeter`] walks the WAL directory).
//!
//! # The two space-amplification figures, and why both are honest
//!
//! - **store-only** (`store_space_amplification` = `store_bytes / logical_csv_bytes`) — the DURABLE
//!   graph image against the logical input: the steady-state on-disk cost of the data (fixed-record
//!   padding, free-list slack, token catalogs). This is what a checkpointed/compacted store occupies.
//! - **total** (`space_amplification` = `(store + wal) / logical_csv_bytes`) — the PEAK footprint
//!   right after a bulk load, before any WAL reclamation. The WAL dominates it, because the batched
//!   commits logged every page. It is transient in principle — but only if something reclaims it, and
//!   the **WAL residual** this module reports is the measure of whether anything did.
//!
//! `write_amplification` uses the same total over the logical input as an honest **lower bound** on
//! bytes that hit the disk (it cannot see WAL bytes that were written and later recycled).

use std::path::Path;

use graphus_examples_harness::StorageMeter;

/// The raw on-disk footprint of a bulk-loaded store directory: the durable image and the redo log,
/// in bytes and in whole pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StoreFootprint {
    /// Bytes of the durable `graph.store` block-device image.
    pub store_bytes: u64,
    /// Whole-page equivalent of [`store_bytes`](Self::store_bytes).
    pub store_pages: u64,
    /// Bytes of the retained `graph.wal` redo-log **directory** — the **WAL residual** the load left
    /// behind, and precisely what a reopen must replay (`rmp` #576/#579).
    pub wal_bytes: u64,
    /// Whole-page equivalent of [`wal_bytes`](Self::wal_bytes).
    pub wal_pages: u64,
}

impl StoreFootprint {
    /// The total durable footprint: the graph image plus the redo log it is still carrying.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.store_bytes + self.wal_bytes
    }
}

/// Measures the footprint of a `graphus-bulk import --db <dir>` store directory.
///
/// # Errors
///
/// Returns the underlying I/O error message if the store file or WAL directory cannot be walked.
pub fn measure_store_dir(db: &Path) -> Result<StoreFootprint, String> {
    let store_file = db.join("graph.store");
    let wal_dir = db.join("graph.wal");
    let (store, wal) = StorageMeter::measure(&store_file, &wal_dir)
        .map_err(|e| format!("measuring store footprint: {e}"))?;
    Ok(StoreFootprint {
        store_bytes: store.bytes,
        store_pages: store.pages,
        wal_bytes: wal.bytes,
        wal_pages: wal.pages,
    })
}

/// The footprint plus every ratio and per-element cost derived from it against a known logical size.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FootprintReport {
    /// The raw measured footprint.
    pub footprint: StoreFootprint,
    /// Nodes the store holds (from the generator manifest).
    pub nodes: u64,
    /// Relationships the store holds (from the generator manifest).
    pub relationships: u64,
    /// The logical (uncompressed CSV) input size — the amplification denominator.
    pub logical_csv_bytes: u64,
    /// Durable **store-image** bytes amortised over the node count. A per-element COST, not a ratio.
    pub bytes_per_node: f64,
    /// Durable **store-image** bytes amortised over the relationship count. The two are two VIEWS of
    /// one image: they do not sum to `store_bytes`.
    pub bytes_per_edge: f64,
    /// `store_bytes / logical_csv_bytes` — the steady-state durable cost.
    pub store_space_amplification: f64,
    /// `(store + wal) / logical_csv_bytes` — the peak post-load footprint (WAL-dominated).
    pub space_amplification: f64,
    /// `(store + wal) / logical_csv_bytes` — an honest lower bound on bytes written.
    pub write_amplification: f64,
    /// `wal_bytes / store_bytes` — how many times the durable graph the load re-wrote into the redo
    /// log and never reclaimed. The WAL-residual signal (`rmp` #315/#556/#579): a load that leaves a
    /// redo log several times the size of the graph it produced is one whose reopen must read all of
    /// it.
    pub wal_to_store_ratio: f64,
}

/// Derives every ratio and per-element cost for a measured [`StoreFootprint`].
///
/// # Errors
///
/// Returns `Err` when `logical_csv_bytes` is zero: a dataset that was never generated has no logical
/// denominator, so there is no ratio to form. Failing loudly beats publishing a `0.0` that reads like
/// a measurement (the examples' evidence-honesty rule, `rmp` #711).
pub fn derive(
    footprint: StoreFootprint,
    nodes: u64,
    relationships: u64,
    logical_csv_bytes: u64,
) -> Result<FootprintReport, String> {
    let no_logical = || {
        "the manifest reports 0 logical CSV bytes: no amplification ratio can be formed (was the \
         dataset ever generated?)"
            .to_string()
    };
    let total = footprint.total_bytes();
    let store_space_amplification =
        StorageMeter::space_amplification(footprint.store_bytes, logical_csv_bytes)
            .ok_or_else(no_logical)?;
    let space_amplification =
        StorageMeter::space_amplification(total, logical_csv_bytes).ok_or_else(no_logical)?;
    let write_amplification =
        StorageMeter::write_amplification(total, logical_csv_bytes).ok_or_else(no_logical)?;

    // Per-element costs are over the STORE image (the durable graph), not the WAL (a redo log that
    // reclamation is supposed to reclaim). `max(1)` guards a degenerate empty dataset only; a real
    // one always has both.
    let bytes_per_node = footprint.store_bytes as f64 / nodes.max(1) as f64;
    let bytes_per_edge = footprint.store_bytes as f64 / relationships.max(1) as f64;
    let wal_to_store_ratio = if footprint.store_bytes > 0 {
        footprint.wal_bytes as f64 / footprint.store_bytes as f64
    } else {
        0.0
    };

    Ok(FootprintReport {
        footprint,
        nodes,
        relationships,
        logical_csv_bytes,
        bytes_per_node,
        bytes_per_edge,
        store_space_amplification,
        space_amplification,
        write_amplification,
        wal_to_store_ratio,
    })
}

/// Measures a store directory and derives its full report in one step.
///
/// # Errors
///
/// Propagates a measurement I/O error, or the zero-logical-bytes error from [`derive`].
pub fn measure_and_derive(
    db: &Path,
    nodes: u64,
    relationships: u64,
    logical_csv_bytes: u64,
) -> Result<FootprintReport, String> {
    let footprint = measure_store_dir(db)?;
    derive(footprint, nodes, relationships, logical_csv_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(store: u64, wal: u64) -> StoreFootprint {
        StoreFootprint {
            store_bytes: store,
            store_pages: 0,
            wal_bytes: wal,
            wal_pages: 0,
        }
    }

    #[test]
    fn per_element_costs_are_over_the_store_image_not_the_total() {
        let r = derive(fp(1000, 9000), 10, 100, 500).unwrap();
        // 1000 store bytes over 10 nodes / 100 rels — the WAL is NOT in the numerator.
        assert!((r.bytes_per_node - 100.0).abs() < 1e-9);
        assert!((r.bytes_per_edge - 10.0).abs() < 1e-9);
    }

    #[test]
    fn the_two_space_amplifications_differ_by_the_wal() {
        let r = derive(fp(1000, 9000), 10, 100, 500).unwrap();
        assert!((r.store_space_amplification - 2.0).abs() < 1e-9); // 1000 / 500
        assert!((r.space_amplification - 20.0).abs() < 1e-9); // (1000+9000) / 500
        assert!((r.write_amplification - 20.0).abs() < 1e-9);
    }

    #[test]
    fn wal_to_store_ratio_is_the_residual_signal() {
        // A load that leaves a redo log 9x the graph it produced.
        let r = derive(fp(1000, 9000), 10, 100, 500).unwrap();
        assert!((r.wal_to_store_ratio - 9.0).abs() < 1e-9);
    }

    #[test]
    fn a_zero_logical_size_is_an_error_not_a_zero_ratio() {
        // `rmp` #711: never publish a 0.0 that reads like a measured amplification.
        assert!(derive(fp(1000, 9000), 10, 100, 0).is_err());
    }
}
