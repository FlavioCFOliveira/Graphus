//! **`loom` model check of the chain-head prepend publication protocol** (`rmp` #1028).
//!
//! Run with:
//!
//! ```text
//! RUSTFLAGS="--cfg loom" cargo test -p graphus-chainhead --test loom_chainhead --release
//! ```
//!
//! # What is being modelled, and what stands in for what
//!
//! [`graphus_chainhead::prepend`] is the production protocol, driven here unchanged. What the model
//! supplies is the **medium**: the head is a [`loom::sync::atomic::AtomicU64`] instead of an 8-byte
//! word on a WAL-logged page, and an entry's `next` is a slot in an array instead of a field in a
//! record. That substitution is the point of the exercise — it is exactly the contract
//! [`graphus_chainhead::ChainHead::compare_and_publish`] states, so a model over an atomic word is a
//! model of "the storage cell honours its contract", and `graphus-storage` honours it with the
//! rank-27 publication latch that makes the peek, the log append and the page write one step.
//!
//! # Why a model checker and not a thread test
//!
//! The lost prepend needs two writers to read one head before either publishes. On any given run of
//! a real-thread test that window may simply not open, and on x86-64 TSO it opens less often still. A
//! test that passes because the interleaving did not happen certifies nothing. loom enumerates the
//! interleavings the *memory model* permits, so the answer does not depend on this machine.
//!
//! # The property
//!
//! **Every entry that was prepended is reachable from the head.** In storage terms: no committed
//! relationship falls out of its node's incidence chain, no committed property version falls out of
//! its owner's chain, no committed delta falls out of the undo chain that decides visibility — the
//! `rmp` #220 defect class, stated as a concurrency property.
//!
//! # Non-vacuity
//!
//! [`naive_publication_loses_an_entry`] runs the identical protocol over a cell whose publication is
//! a plain load-then-store — the unconditional `write_chain_head` this task replaced — and requires
//! that at least one interleaving **loses** an entry. If a future change made the compare-and-publish
//! redundant, that test would start failing, so the pair says both "the protocol is correct" and "the
//! atomicity it rests on is doing the work".

#![cfg(loom)]

use std::convert::Infallible;
use std::sync::Arc as StdArc;
use std::sync::atomic::{AtomicUsize, Ordering as StdOrdering};

use graphus_chainhead::{ChainHead, prepend};
use loom::sync::atomic::{AtomicU64, Ordering};

/// The sentinel for "no successor", matching `graphus_storage`'s `NULL_ID`.
const NULL: u64 = 0;

/// The shared state of one modelled chain: the head word, and one `next` slot per entry id.
///
/// Entry ids are `1..=n`; slot `0` is unused so that `0` can be the null sentinel, exactly as the
/// record stores reserve physical id 0.
struct Chain {
    head: AtomicU64,
    next: Vec<AtomicU64>,
}

impl Chain {
    fn new(initial_head: u64, entries: usize) -> Self {
        Self {
            head: AtomicU64::new(initial_head),
            // `entries + 1` slots so an id may be used to index directly; the pre-existing tail (if
            // any) gets a slot too, and keeps its NULL successor.
            next: (0..=entries + 1).map(|_| AtomicU64::new(NULL)).collect(),
        }
    }

    /// Walks the chain from the head, returning the ids in order, or `Err` on a cycle.
    ///
    /// A bound on the walk is not defensive padding: a botched publication can leave a record whose
    /// `next` names itself, and an unbounded walk would hang the model rather than report it.
    fn walk(&self) -> Result<Vec<u64>, &'static str> {
        let mut seen = Vec::new();
        let mut cur = self.head.load(Ordering::Acquire);
        while cur != NULL {
            if seen.contains(&cur) {
                return Err("the chain contains a cycle");
            }
            seen.push(cur);
            if seen.len() > self.next.len() {
                return Err("the chain is longer than the number of entries");
            }
            cur = self.next[cur as usize].load(Ordering::Acquire);
        }
        Ok(seen)
    }
}

/// The **correct** cell: publication is an indivisible compare-and-exchange, which is what the
/// storage cell's rank-27 latch buys it.
struct AtomicCell {
    chain: StdArc<Chain>,
    entry: u64,
}

impl ChainHead for AtomicCell {
    type Error = Infallible;

    fn compare_and_publish(&mut self, expect: u64, entry: u64) -> Result<bool, Infallible> {
        Ok(self
            .chain
            .head
            .compare_exchange(expect, entry, Ordering::AcqRel, Ordering::Acquire)
            .is_ok())
    }

    fn reread(&mut self) -> Result<u64, Infallible> {
        Ok(self.chain.head.load(Ordering::Acquire))
    }

    fn relink(&mut self, head: u64) -> Result<(), Infallible> {
        // `Release`: everything this writer wrote into its entry must be visible to a reader that
        // subsequently `Acquire`-loads the head and reaches this entry.
        self.chain.next[self.entry as usize].store(head, Ordering::Release);
        Ok(())
    }
}

/// The **broken** cell, kept as a standing negative control: publication is a load, a comparison and
/// a separate store — precisely the `write_chain_head` shape this task removed, wrapped in a
/// comparison that looks like it helps and does not.
struct NaiveCell {
    chain: StdArc<Chain>,
    entry: u64,
}

impl ChainHead for NaiveCell {
    type Error = Infallible;

    fn compare_and_publish(&mut self, expect: u64, entry: u64) -> Result<bool, Infallible> {
        let current = self.chain.head.load(Ordering::Acquire);
        if current != expect {
            return Ok(false);
        }
        // The window. Another writer may publish between the load above and this store, and this
        // store then overwrites it — the comparison was true when it was made and stale by the time
        // it was acted upon.
        self.chain.head.store(entry, Ordering::Release);
        Ok(true)
    }

    fn reread(&mut self) -> Result<u64, Infallible> {
        Ok(self.chain.head.load(Ordering::Acquire))
    }

    fn relink(&mut self, head: u64) -> Result<(), Infallible> {
        self.chain.next[self.entry as usize].store(head, Ordering::Release);
        Ok(())
    }
}

/// One writer's whole job: observe the head, link the entry to it, then publish with retry.
///
/// The observation is deliberately OUTSIDE the publication. That is not a simplification of the
/// storage path, it is the storage path: `create_rel` reads the endpoint's `first_rel` from the node
/// record it had to read anyway, then allocates a physical id, maps and writes a whole relationship
/// record, and only then publishes. Holding a latch across all of that would hold it across device
/// growth, eviction and an `fdatasync`. So the head really can move under a writer, and the retry
/// loop really is load-bearing rather than defensive.
fn write_one<C: ChainHead<Error = Infallible>>(chain: &Chain, cell: &mut C, entry: u64) {
    let observed = chain.head.load(Ordering::Acquire);
    chain.next[entry as usize].store(observed, Ordering::Release);
    prepend(cell, observed, entry).expect("an infallible cell cannot fail");
}

/// **The property, and acceptance criterion 2**: two writers prepending onto one head produce a
/// chain containing BOTH entries, under every interleaving the memory model permits.
#[test]
fn two_writers_prepending_on_one_head_both_end_up_in_the_chain() {
    loom::model(|| {
        let chain = StdArc::new(Chain::new(NULL, 2));

        let a = {
            let chain = StdArc::clone(&chain);
            loom::thread::spawn(move || {
                let mut cell = AtomicCell {
                    chain: StdArc::clone(&chain),
                    entry: 1,
                };
                write_one(&chain, &mut cell, 1);
            })
        };
        let b = {
            let chain = StdArc::clone(&chain);
            loom::thread::spawn(move || {
                let mut cell = AtomicCell {
                    chain: StdArc::clone(&chain),
                    entry: 2,
                };
                write_one(&chain, &mut cell, 2);
            })
        };
        a.join().unwrap();
        b.join().unwrap();

        let mut seen = chain.walk().expect("the chain must be walkable");
        seen.sort_unstable();
        assert_eq!(
            seen,
            vec![1, 2],
            "both prepends must be reachable from the head: a missing entry is a committed \
             relationship, property version or undo delta that silently left its chain (`rmp` #220)"
        );
    });
}

/// A prepend must not orphan what was already there. The chain starts with entry `3` published, and
/// after two concurrent prepends all three must still be reachable, newest first.
#[test]
fn concurrent_prepends_never_orphan_the_pre_existing_tail() {
    loom::model(|| {
        let chain = StdArc::new(Chain::new(3, 2));

        let a = {
            let chain = StdArc::clone(&chain);
            loom::thread::spawn(move || {
                let mut cell = AtomicCell {
                    chain: StdArc::clone(&chain),
                    entry: 1,
                };
                write_one(&chain, &mut cell, 1);
            })
        };
        let b = {
            let chain = StdArc::clone(&chain);
            loom::thread::spawn(move || {
                let mut cell = AtomicCell {
                    chain: StdArc::clone(&chain),
                    entry: 2,
                };
                write_one(&chain, &mut cell, 2);
            })
        };
        a.join().unwrap();
        b.join().unwrap();

        let seen = chain.walk().expect("the chain must be walkable");
        assert_eq!(
            seen.len(),
            3,
            "the two new entries and the pre-existing tail must all be reachable, got {seen:?}"
        );
        assert_eq!(
            seen[2], 3,
            "the pre-existing entry must remain the tail, not be displaced or dropped: {seen:?}"
        );
    });
}

/// A refused publication must leave the loser's entry linked to the head it actually displaced, so a
/// walk of the finished chain is a simple path — never a fork, never a cycle.
#[test]
fn a_refused_publication_never_leaves_a_fork_or_a_cycle() {
    loom::model(|| {
        let chain = StdArc::new(Chain::new(3, 2));

        let a = {
            let chain = StdArc::clone(&chain);
            loom::thread::spawn(move || {
                let mut cell = AtomicCell {
                    chain: StdArc::clone(&chain),
                    entry: 1,
                };
                write_one(&chain, &mut cell, 1);
            })
        };
        let b = {
            let chain = StdArc::clone(&chain);
            loom::thread::spawn(move || {
                let mut cell = AtomicCell {
                    chain: StdArc::clone(&chain),
                    entry: 2,
                };
                write_one(&chain, &mut cell, 2);
            })
        };
        a.join().unwrap();
        b.join().unwrap();

        let seen = chain.walk().expect("a refusal must never produce a cycle");
        let mut sorted = seen.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            seen.len(),
            "no entry may appear twice on the chain: {seen:?}"
        );
    });
}

/// **NON-VACUITY (acceptance criterion 3).** The same protocol over a cell whose publication is a
/// plain load-compare-store must LOSE an entry on at least one interleaving.
///
/// Counted rather than asserted per execution, because most interleavings are harmless: the claim is
/// "the memory model permits the loss", which is a claim about the set of executions, not about each
/// one. The counter is a `std` atomic living outside the model, so loom does not schedule it.
///
/// This is the test that keeps the whole task honest. If it ever passes with zero losses, either loom
/// stopped exploring the window or the model stopped modelling a plain store — and in both cases the
/// positive tests above have become certificates of nothing.
#[test]
fn naive_publication_loses_an_entry() {
    let losses = StdArc::new(AtomicUsize::new(0));
    let counter = StdArc::clone(&losses);

    loom::model(move || {
        let chain = StdArc::new(Chain::new(NULL, 2));

        let a = {
            let chain = StdArc::clone(&chain);
            loom::thread::spawn(move || {
                let mut cell = NaiveCell {
                    chain: StdArc::clone(&chain),
                    entry: 1,
                };
                write_one(&chain, &mut cell, 1);
            })
        };
        let b = {
            let chain = StdArc::clone(&chain);
            loom::thread::spawn(move || {
                let mut cell = NaiveCell {
                    chain: StdArc::clone(&chain),
                    entry: 2,
                };
                write_one(&chain, &mut cell, 2);
            })
        };
        a.join().unwrap();
        b.join().unwrap();

        // A cycle counts as a loss too: it is the other way a non-atomic publication corrupts the
        // chain, and either way an entry is unreachable.
        match chain.walk() {
            Ok(seen) if seen.len() == 2 => {}
            _ => {
                counter.fetch_add(1, StdOrdering::Relaxed);
            }
        }
    });

    assert!(
        losses.load(StdOrdering::Relaxed) > 0,
        "an unconditional (load, compare, store) publication must lose a prepend on at least one \
         interleaving. Zero losses means this negative control has stopped controlling anything — \
         and with it, the guarantee the positive models above are supposed to certify."
    );
}
