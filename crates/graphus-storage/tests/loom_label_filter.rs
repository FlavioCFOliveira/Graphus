//! `loom` model-check of the **`rmp` #808** `LabelHistory` lock-free pre-filter publication ordering.
//!
//! # What this proves
//!
//! The pre-filter ([`graphus_storage::label_history::TrackedFilter`]) lets a reader decide, with
//! atomic **loads only**, that a node id is not tracked and skip the `RwLock`. Its safety contract is
//! **no false negative for a genuinely tracked id**. That rests on two ordering facts, each modelled
//! here as a falsifiable loom invariant over every legal interleaving of one writer and one reader:
//!
//! * **M1 — arming publication.** The writer sets an id's bits *before* it arms the gate
//!   (`filter.fetch_or(Release)` then `any.store(true, Release)`). A reader that observes the gate
//!   armed (`any.load(Acquire)`) and then loads the filter word (`Acquire`) MUST see the bits. This
//!   is the exact edge that makes a newly-armed id visible without the lock. **Falsifiable:** with
//!   `Relaxed` in place of the release/acquire pair, loom finds the interleaving where the reader sees
//!   `armed == true` but the bit still clear — a false negative, i.e. a dirty read.
//!
//! * **M2 — rebuild preserves the survivor.** When the writer rebuilds the image on a shrink
//!   (`forget`/`prune`), it publishes the new image one word at a time. A key that *survives* the
//!   shrink has its bit set in both the old and the new image, so any per-word value a concurrent
//!   reader may observe still carries that bit. **Falsifiable:** a rebuild that zeroes the word before
//!   re-setting the survivor's bit (a store of `0` then a store of the new image) lets loom catch the
//!   reader observing the transient `0` — a false negative for a still-tracked node.
//!
//! The bit-mapping and the word/mask arithmetic are transcribed 1:1 from `label_history.rs`; only the
//! atomic *type* differs (loom's instrumented atomics vs `std`), which is precisely what loom needs
//! to explore the memory model. A single 64-bit word suffices to model the ordering (the production
//! filter is 64 such words; the orderings are per-word identical).
//!
//! # How to run it
//!
//! `graphus-storage` is **not a leaf crate**: its transitive deps (`graphus-bufpool`, …) carry their
//! own `--cfg loom` shims that are only type-coherent when compiled as the loom root, so the storage
//! lib does not compile under `--cfg loom`. This model is therefore **self-contained** — it imports
//! nothing from `graphus-storage` and only needs `loom` — and is exercised in an isolated harness
//! (a one-file crate depending solely on `loom`, byte-identical to the bodies below). Both invariants
//! pass exhaustively, and each was verified falsifiable (Relaxed for M1, a clear-then-set rebuild for
//! M2 are both caught by loom).
//!
//! Making it runnable in-tree via `RUSTFLAGS="--cfg loom" cargo test -p graphus-storage --test
//! loom_label_filter` requires either extracting `TrackedFilter` into a leaf crate or making the
//! storage stack loom-coherent — an owner decision tracked alongside `rmp` #808. The file is
//! `#![cfg(loom)]`, so it is inert (compiles to nothing) in every normal build.

#![cfg(loom)]

use loom::sync::Arc;
use loom::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use loom::thread;

/// Two distinct bits within one word, standing in for two tracked node ids `A` and `B`.
const BIT_A: u64 = 1 << 5;
const BIT_B: u64 = 1 << 40;

/// M1 — a reader that sees the gate armed sees the newly-armed id's bit (no false negative on arm).
#[test]
fn arming_publication_has_no_false_negative() {
    loom::model(|| {
        let word = Arc::new(AtomicU64::new(0));
        let armed = Arc::new(AtomicBool::new(false));

        let w = {
            let word = Arc::clone(&word);
            let armed = Arc::clone(&armed);
            thread::spawn(move || {
                // `TrackedFilter::insert`: set the bit with Release, THEN arm the gate with Release.
                word.fetch_or(BIT_A, Ordering::Release);
                armed.store(true, Ordering::Release);
            })
        };

        // Reader: the `resolve` gate order — check `any` (Acquire), then the filter word (Acquire).
        if armed.load(Ordering::Acquire) {
            let seen = word.load(Ordering::Acquire);
            assert_ne!(
                seen & BIT_A,
                0,
                "false negative: gate observed armed but the tracked id's bit was not visible"
            );
        }

        w.join().unwrap();
    });
}

/// M2 — a concurrent reader always sees a SURVIVING key's bit during a shrink rebuild.
#[test]
fn rebuild_preserves_the_surviving_key() {
    loom::model(|| {
        // Start armed with A and B tracked (bits a|b set); the writer drops B, keeping A.
        let word = Arc::new(AtomicU64::new(BIT_A | BIT_B));

        let w = {
            let word = Arc::clone(&word);
            thread::spawn(move || {
                // `TrackedFilter::rebuild([A])`: publish the new image (A only) in ONE store, so the
                // survivor's bit is never transiently cleared. This is the property under test.
                word.store(BIT_A, Ordering::Release);
            })
        };

        // Reader resolving the SURVIVING id A: its bit is set in both old (a|b) and new (a) images,
        // so every observable value carries it.
        let seen = word.load(Ordering::Acquire);
        assert_ne!(
            seen & BIT_A,
            0,
            "false negative: surviving key's bit vanished during rebuild"
        );

        w.join().unwrap();
    });
}
