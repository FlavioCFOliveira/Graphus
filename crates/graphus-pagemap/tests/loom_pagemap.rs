//! **`loom` model check of the lock-free page map's publication ordering** (`rmp` #721).
//!
//! Run with:
//!
//! ```text
//! RUSTFLAGS="--cfg loom" cargo test -p graphus-storage --test loom_pagemap --release
//! ```
//!
//! # Why a model checker, and not just the real-thread test
//!
//! [`graphus_storage::PageMap`] is a hand-rolled lock-free structure. Its correctness rests on exactly
//! one happens-before edge — the writer `Release`-stores `len` after writing an entry; a reader
//! `Acquire`-loads `len` before reading one — and the entries themselves are deliberately `Relaxed`
//! *because* that edge dominates them.
//!
//! **A real-thread test on this machine cannot verify that.** x86-64 is TSO: loads are acquire and
//! stores are release in hardware. Downgrade the `len` edge to `Relaxed` and
//! `pagemap::tests::concurrent_readers_never_miss_a_published_entry` still passes here — while the map
//! silently starts handing out stale or absent entries on **aarch64**, which CLAUDE.md names as a
//! first-class target (Apple Silicon, Raspberry Pi 5). Only a model checker explores the interleavings
//! the *memory model* permits rather than the ones this CPU happens to produce.
//!
//! These models exercise the **production type** (the atomics are swapped by `graphus_storage`'s
//! `src/sync.rs` seam, not the algorithm), so they cannot drift from the code they certify.
//!
//! # The property
//!
//! **A reader that observes `len > i` must see entry `i`, and see it correctly.** In storage terms:
//! *if a store page is published, a reader can always locate it* — which is the whole of `rmp` #721.
//! A missing `Acquire`/`Release` on the `len` edge lets a reader observe the new `len` while still
//! seeing the *old* (zero) entry — i.e. it would locate a committed record's page as device page 0,
//! the metadata page. loom finds that; TSO hardware hides it.

#![cfg(loom)]

use graphus_core::PageId;
use graphus_pagemap::PageMapWriter;

/// The core edge: one writer appends while one reader indexes. Every index the reader sees published
/// must resolve to the right device page — never zero (unwritten), never stale.
///
/// This is the model of the hot path: appends *within* an already-installed chunk, where the entry
/// stores/loads are `Relaxed` and `len` is the sole synchronisation. Flipping either side of the `len`
/// edge to `Relaxed` makes loom fail this.
#[test]
fn a_published_entry_is_always_visible_to_a_concurrent_reader() {
    loom::model(|| {
        let mut w = PageMapWriter::new();
        // Pre-publish one entry so the chunk is installed before the threads start: this isolates the
        // `len` edge, which is what the model is for.
        w.push(PageId(1)).unwrap();
        let map = w.reader();

        let reader = loom::thread::spawn(move || {
            // Exactly the read path: gate on `len`, then index.
            let len = map.len();
            for i in 0..len {
                let got = map
                    .get(i)
                    .expect("an index below the published len must always be mapped");
                // Entry `i` was pushed as `PageId(i + 1)`. Seeing `PageId(0)` would mean the reader
                // observed the published `len` but NOT the entry write — the exact reordering the
                // `Release`/`Acquire` pair forbids, and the exact one that would make a reader fetch
                // the metadata page in place of a record page.
                assert_eq!(
                    got,
                    PageId(i as u64 + 1),
                    "reader saw len {len} but entry {i} was stale/unwritten"
                );
            }
        });

        // The writer appends concurrently.
        w.push(PageId(2)).unwrap();
        w.push(PageId(3)).unwrap();

        reader.join().unwrap();
        assert_eq!(w.len(), 3);
    });
}

/// The same property **across a chunk boundary**, where a `push` also installs a fresh chunk.
///
/// The chunk install is an `OnceLock` (which loom 0.7 cannot instrument — see `graphus_storage`'s
/// `src/sync.rs`), but its ordering is not load-bearing: a reader reaches the chunk only *after* the
/// `Acquire` load of `len` that admits the index, and the install is sequenced-before the `Release`
/// store of that `len`. This model pins that reasoning — the reader must still never see a published
/// index it cannot resolve, even when resolving it requires a chunk the writer installed concurrently.
#[test]
fn a_published_entry_in_a_freshly_installed_chunk_is_visible() {
    loom::model(|| {
        let mut w = PageMapWriter::new();
        let map = w.reader();

        let reader = loom::thread::spawn(move || {
            let len = map.len();
            for i in 0..len {
                let got = map
                    .get(i)
                    .expect("an index below the published len must always be mapped");
                assert_eq!(got, PageId(i as u64 + 1), "entry {i} was stale/unwritten");
            }
        });

        // Under `--cfg loom` the first chunk holds a SINGLE entry (see `CHUNK0_LOG2`), so index 1
        // already crosses a chunk boundary: the writer installs a fresh chunk and publishes into it
        // while the reader is indexing — the exact path the production geometry reaches at index 64.
        w.push(PageId(1)).unwrap(); // chunk 0
        w.push(PageId(2)).unwrap(); // installs chunk 1
        w.push(PageId(3)).unwrap(); // chunk 1, second slot

        reader.join().unwrap();
        assert_eq!(w.len(), 3);
    });
}

/// Two readers and a writer: the map must serve every reader consistently. Guards against any
/// reader-visible state that is not purely a function of the published `len`.
#[test]
fn two_concurrent_readers_agree_with_the_writer() {
    loom::model(|| {
        let mut w = PageMapWriter::new();
        w.push(PageId(1)).unwrap();

        let readers: Vec<_> = (0..2)
            .map(|_| {
                let map = w.reader();
                loom::thread::spawn(move || {
                    let len = map.len();
                    // The map is monotone: whatever this reader saw published stays published and keeps
                    // resolving to the same page.
                    for i in 0..len {
                        assert_eq!(
                            map.get(i).expect("published index must resolve"),
                            PageId(i as u64 + 1)
                        );
                    }
                    len
                })
            })
            .collect();

        w.push(PageId(2)).unwrap();

        for r in readers {
            let seen = r.join().unwrap();
            assert!(
                seen >= 1,
                "a reader must see at least the pre-published entry"
            );
        }
    });
}
