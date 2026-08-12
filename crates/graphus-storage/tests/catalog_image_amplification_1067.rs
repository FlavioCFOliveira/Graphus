//! **`rmp` #1067 — what a commit writes, and whether the catalogue's size is part of it.**
//!
//! # The claim under test
//!
//! Before #1067 the cardinality counters reached disk inside the catalogue image that **every**
//! commit rewrites, so the bytes a commit wrote grew with the size of the schema: a store with many
//! populated counter keys paid for all of them again at every single commit, whatever that commit
//! had actually changed. The ficha for `rmp` #1055 measured the extreme of that shape — 73 267 bytes
//! of catalogue per commit against 784 bytes of data records.
//!
//! Since #1067 the counters are not in the per-commit image at all (a commit logs a delta record and
//! the image carries a base that only a checkpoint's fold moves), and an unchanged catalogue chunk is
//! not written again. So the property this file asserts is:
//!
//! > **Populating N cardinality counter keys does not change the number of bytes a commit writes.**
//!
//! # Why it is measured this way, and not against a remembered number
//!
//! A single "bytes per commit" figure is not evidence: it moves with the record layout, the WAL
//! header, the free-list shape and the number of pages the workload touches, so a threshold on it
//! would be a threshold on everything. What is wanted is the **counters' own contribution**, and this
//! isolates it by differencing two workloads that are identical in every other respect:
//!
//! * **[`Shape::TokensOnly`]** — `n` relationship-type tokens are interned, and every relationship
//!   created uses only the first. The token dictionary carries `n` names; the counter maps carry
//!   **one** key.
//! * **[`Shape::CountersToo`]** — the same `n` tokens are interned, and one relationship of **each**
//!   type is committed first. The token dictionary is identical; the counter maps now carry `n`
//!   entries in `rels_per_type` and `n` more in each directional projection.
//!
//! Both then run the same measured commits. The difference between the two is exactly what the
//! counters cost per commit, on this host, on this build — and it is what a regression would move.
//!
//! # Running it
//!
//! ```text
//! cargo test -p graphus-storage --test catalog_image_amplification_1067 -- --nocapture
//! ```

use graphus_core::TxnId;
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// The schema widths measured, and the table the `rmp` #1067 ficha names.
const WIDTHS: [usize; 4] = [1, 256, 1024, 4096];

/// Commits in the measured phase. Enough that a one-off cost (a page allocation, a chain growth)
/// divides away and what is left is the steady per-commit cost.
const MEASURED_COMMITS: u64 = 20;

/// Buffer-pool frames. Above the working set at the widest schema, so the measurement is of what is
/// written and not of what is evicted.
const POOL_PAGES: usize = 512;

/// Which of the two workloads a store is set up for. They differ in ONE respect — whether the
/// cardinality counter maps are populated — and that is the whole experiment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// `n` type tokens interned; one counter key populated.
    TokensOnly,
    /// `n` type tokens interned; `n` counter keys populated.
    CountersToo,
}

/// What one measured phase produced.
struct Measured {
    /// WAL bytes an ordinary commit appends, averaged over [`MEASURED_COMMITS`].
    bytes_per_commit: u64,
    /// Catalogue chunks those commits wrote, and chunks they skipped because the page already held
    /// exactly those bytes. Together they say WHY the byte count came out where it did — a ratio
    /// alone cannot tell "the counters are not in the image" from "the image is not being written".
    chunks_written: u64,
    chunks_skipped: u64,
}

/// Runs one workload and measures the steady per-commit cost.
fn bytes_per_commit(shape: Shape, n: usize) -> Measured {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: Store = RecordStore::create(device, wal, POOL_PAGES, 1).expect("create store");
    // The automatic checkpoint is disabled so that what is measured is the COMMIT path alone. A
    // checkpoint writes a catalogue image of its own (the counter fold, `rmp` #1067) and would land
    // inside the measured window at an arbitrary commit, turning the average into a mixture.
    store.set_checkpoint_interval_bytes(0);

    let types: Vec<u32> = (0..n)
        .map(|i| {
            store
                .intern_token(Namespace::RelType, &format!("T{i}"))
                .expect("intern a type token")
        })
        .collect();

    // Two endpoints, and — for `CountersToo` — one relationship of every type, so each type gets an
    // entry in `rels_per_type` and in both directional projections.
    let seed = TxnId(1);
    store.begin(seed);
    let (a, _) = store.create_node(seed).expect("create the start node");
    let (b, _) = store.create_node(seed).expect("create the end node");
    if shape == Shape::CountersToo {
        for &t in &types {
            store.create_rel(seed, t, a, b).expect("create a seed rel");
        }
    }
    store.commit(seed).expect("commit the seed");

    // The measured phase: identical in both shapes — one relationship of the FIRST type per commit.
    let before = store.with_wal(|w| w.durable_len());
    let (written_before, skipped_before) = store.meta_chunk_writes();
    for r in 0..MEASURED_COMMITS {
        let t = TxnId(1_000 + r);
        store.begin(t);
        store
            .create_rel(t, types[0], a, b)
            .expect("create the measured rel");
        store.commit(t).expect("commit the measured write");
    }
    let after = store.with_wal(|w| w.durable_len());
    let (written, skipped) = store.meta_chunk_writes();
    Measured {
        bytes_per_commit: (after - before) / MEASURED_COMMITS,
        chunks_written: written - written_before,
        chunks_skipped: skipped - skipped_before,
    }
}

/// **A commit's cost does not grow with the number of populated counter keys.**
///
/// # What a failure means
///
/// That the cardinality counters are back in the bytes a commit writes — either because the image
/// carries them again, or because the base is being rewritten when it has not changed. Both are the
/// write-amplification half of `rmp` #1067, and the correctness half (`rmp` #1055's two classes) can
/// be perfectly healthy while this regresses.
///
/// # The threshold, and why it is a ratio and not a byte count
///
/// The two shapes differ in exactly one thing, so their per-commit cost should be **identical**; the
/// allowance below exists only for the second-order effects of having more records in the store (a
/// wider free list, one more device page in a store's map), which are real and are not the counters.
/// A regression that puts the counters back is not a few per cent: at 4096 keys they are tens of
/// kilobytes against a commit that otherwise writes hundreds of bytes, so the allowance cannot hide
/// one.
#[test]
fn a_commits_cost_is_independent_of_the_cardinality_schema() {
    let mut rows = Vec::new();
    let mut regressions = Vec::new();
    for n in WIDTHS {
        let one = bytes_per_commit(Shape::TokensOnly, n);
        let many = bytes_per_commit(Shape::CountersToo, n);
        let (tokens_only, counters_too) = (one.bytes_per_commit, many.bytes_per_commit);
        let ratio = counters_too as f64 / tokens_only as f64;
        rows.push(format!(
            "{n:>5} counter keys: {tokens_only:>7} B/commit with one key, {counters_too:>7} \
             B/commit with {n} — ratio {ratio:.2}x; chunks written/skipped {}/{} against {}/{}",
            one.chunks_written, one.chunks_skipped, many.chunks_written, many.chunks_skipped,
        ));
        // 1.5x is far below what carrying the counters costs (at 4096 keys that is ~50 KiB of map
        // against a sub-kilobyte commit, i.e. two orders of magnitude) and far above the noise of a
        // slightly larger store.
        if ratio > 1.5 {
            regressions.push(format!(
                "{n} counter keys cost {ratio:.2}x per commit ({counters_too} B against \
                 {tokens_only} B)"
            ));
        }
    }
    println!(
        "per-commit WAL bytes, `rmp` #1067 (MemBlockDevice + MemLogSink, auto-checkpoint \
         disabled):\n{}",
        rows.join("\n")
    );
    assert!(
        regressions.is_empty(),
        "a commit's cost grows with the number of populated cardinality counter keys, so the \
         counters are being rewritten by every commit. They must reach disk as a logged delta \
         (`rmp` #1067), and the catalogue image must carry a base that only a checkpoint's fold \
         moves — an image whose bytes have not changed is not written at all:\n{}",
        regressions.join("\n")
    );
}

/// **The measurement is not vacuous: the schema really is `n` keys wide, and a commit really does
/// write.**
///
/// Two ways this file could go green while measuring nothing, both closed here:
///
/// * the `CountersToo` shape never populated the counters (a wrong token namespace, a refused
///   `create_rel`), so both workloads were the same workload. Read back out of the store's own
///   `Statistics`, never counted in the loop;
/// * a commit appends nothing at all, so every ratio is `0/0`. A commit that writes zero bytes would
///   make the assertion above trivially true.
#[test]
fn the_two_shapes_really_differ_in_the_counter_schema() {
    for n in [1usize, 256] {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store: Store = RecordStore::create(device, wal, POOL_PAGES, 1).expect("create store");
        let types: Vec<u32> = (0..n)
            .map(|i| {
                store
                    .intern_token(Namespace::RelType, &format!("T{i}"))
                    .expect("intern a type token")
            })
            .collect();
        let seed = TxnId(1);
        store.begin(seed);
        let (a, _) = store.create_node(seed).expect("start node");
        let (b, _) = store.create_node(seed).expect("end node");
        for &t in &types {
            store.create_rel(seed, t, a, b).expect("create a seed rel");
        }
        store.commit(seed).expect("commit the seed");

        let stats = store.statistics();
        let populated = types
            .iter()
            .filter(|&&t| stats.rel_count_for_type(t) > 0)
            .count();
        drop(stats);
        assert_eq!(
            populated, n,
            "the `CountersToo` shape was supposed to populate {n} distinct counter keys and \
             populated {populated}, so the two shapes measured in this file differ in nothing and \
             every ratio above is a comparison of a workload with itself"
        );
    }
    assert!(
        bytes_per_commit(Shape::TokensOnly, 1).bytes_per_commit > 0,
        "a commit appended no WAL bytes at all, so every ratio measured in this file is a \
         comparison of two zeroes"
    );
}
