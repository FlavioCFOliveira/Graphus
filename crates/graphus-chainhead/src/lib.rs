//! **The prepend publication protocol** shared by every chain head in Graphus (`rmp` #1028).
//!
//! A *chain head* is a single word inside a record that names the first entry of a singly-linked
//! chain hanging off that record. The storage core has three of them — a node's `first_rel`, an
//! entity's `first_prop`, and the MVCC `undo_ptr` — and every writer that adds to such a chain does
//! so by **prepending**:
//!
//! ```text
//! 1. read the head            H
//! 2. write the new entry E with  E.next := H     (E is private: nobody can reach it yet)
//! 3. publish                  head := E
//! 4. fix the back-pointer     H.prev := E        (doubly-linked chains only)
//! ```
//!
//! # Why this is a crate and not four copies of a loop
//!
//! Steps 1 and 3 are a read and a write of the *same* shared word, and between them any other writer
//! may publish its own entry. If step 3 is a plain store, the two prepends interleave as
//!
//! ```text
//!   A: read H          B: read H
//!   A: E_A.next := H   B: E_B.next := H
//!   B: head := E_B
//!   A: head := E_A                       <-- B's entry is now unreachable
//! ```
//!
//! and one of them is **silently lost**: a committed relationship vanishes from its node's incidence
//! chain, a committed property version vanishes from its owner's property chain, a committed delta
//! vanishes from the undo chain that decides visibility. This is the defect class of `rmp` #220,
//! reduced there to a durability question and left as a live concurrency hazard the moment more than
//! one thread may write. It is the reason this protocol exists in one place, model-checked, instead
//! of being open-coded at each of the six call sites that need it.
//!
//! The fix is the classic one: make step 3 a **compare-and-publish** against the head the entry was
//! linked to, and on refusal *re-link and retry*. The retry cannot live inside the publication
//! itself, because a refusal invalidates `E.next` — the entry was linked to a head that is no longer
//! the head — so recovering from it means going back and rewriting the entry. That is what
//! [`prepend`] does, and it is the whole of this crate.
//!
//! # The two ordering rules the protocol depends on
//!
//! Both are obligations on the [`ChainHead`] implementation, not on this code, and both are stated
//! on the trait's methods because getting either wrong reintroduces the lost prepend without any
//! symptom this crate could detect:
//!
//! * **Atomicity.** [`ChainHead::compare_and_publish`] must compare and store as one indivisible
//!   step with respect to every other publisher of the same head.
//! * **Durable order.** If the cell is durable (Graphus's is: a word on a WAL-logged page), the
//!   order in which publications enter the log must equal the order in which they take effect on the
//!   page. Recovery replays in log order; if that order differs from the order the writers actually
//!   applied, replay reaches a different verdict from the one the live system reached, and the
//!   *replayed* verdict is the one that survives the crash.
//!
//! # Step 4 comes AFTER step 3, and that is not an implementation detail
//!
//! Fixing the displaced predecessor's back-pointer before publishing looks harmless and is not:
//! having read `H`, a writer that has not yet published has no claim on `H` at all. If its
//! publication is then refused because another writer got there first, it has already overwritten
//! `H.prev` with its own id — clobbering the back-pointer the winner legitimately owns. Doing it
//! after the *winning* publication is what makes the ownership exclusive: only the publisher whose
//! compare-and-publish succeeded with `expect == H` displaced `H`, so only that publisher relinks
//! it, and two writers can never relink the same predecessor. [`prepend`] therefore returns the
//! head it displaced, and the caller performs step 4 with that value and no other.
//!
//! # No dependencies, on purpose
//!
//! See this crate's `Cargo.toml`: `--cfg loom` is a global rustflag, so a protocol that is to be
//! model-checked must sit in a crate with no edge to any other crate carrying a loom seam.

#![forbid(unsafe_code)]

use core::fmt;

/// The shared head word of a chain, as the prepend protocol needs to see it.
///
/// Implementors own the entry being published: [`relink`](Self::relink) rewrites that entry's `next`
/// field, and the entry must already be fully written (and linked to the head the caller observed)
/// before [`prepend`] is called.
pub trait ChainHead {
    /// Whatever can go wrong while reading or writing the underlying medium. Publication being
    /// *refused* is not an error — it is the ordinary outcome modelled by
    /// [`compare_and_publish`](Self::compare_and_publish) returning `Ok(false)`.
    type Error;

    /// Publishes `entry` as the new head **if and only if** the head still holds `expect`; reports
    /// whether it did.
    ///
    /// # Contract
    ///
    /// The comparison and the store must be **one indivisible step** with respect to every other
    /// publisher of this head. An implementation that loads, compares and stores with a window in
    /// between satisfies the signature and loses prepends exactly as a plain store does — the
    /// `naive_publication_loses_an_entry` model in `tests/loom_chainhead.rs` is that implementation,
    /// and it exists to keep this paragraph honest.
    ///
    /// For a **durable** head the contract has a second half: the record that will replay this
    /// publication must enter the log in the same order in which the store takes effect, so that
    /// replay reaches the same verdict the live system reached. See the crate docs.
    ///
    /// # Errors
    /// Returns [`Self::Error`] if the medium could not be read or written. A refusal is `Ok(false)`.
    fn compare_and_publish(&mut self, expect: u64, entry: u64) -> Result<bool, Self::Error>;

    /// Re-reads the head after a refusal.
    ///
    /// # Errors
    /// Returns [`Self::Error`] if the medium could not be read.
    fn reread(&mut self) -> Result<u64, Self::Error>;

    /// Re-points the still-unpublished entry's `next` field at `head`.
    ///
    /// Called only after a refusal, and always before the next attempt: an entry linked to a head
    /// that is no longer the head must not be published, or the chain would fork and everything
    /// below the displaced head would fall out of it.
    ///
    /// # Errors
    /// Returns [`Self::Error`] if the entry could not be written.
    fn relink(&mut self, head: u64) -> Result<(), Self::Error>;
}

/// The number of publication attempts [`prepend`] makes before giving up.
///
/// The loop is *lock-free* in the technical sense — an attempt is refused only when some other
/// publisher succeeded, so the system as a whole always progresses — and a live-lock is therefore
/// impossible. The bound is not there to break a live-lock; it is there so that a [`ChainHead`]
/// which can never accept (a mis-implemented cell, a head word being written by something outside
/// the protocol) surfaces as a loud, attributable failure instead of an unkillable thread inside a
/// database. Reaching it would mean this many *other* prepends landed on one head during a single
/// publication, which contention alone does not produce.
pub const MAX_ATTEMPTS: u32 = 65_536;

/// Why a prepend did not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrependError<E> {
    /// The head cell reported a failure of its underlying medium.
    Cell(E),
    /// [`MAX_ATTEMPTS`] publications were refused. See that constant: this is a broken cell, not
    /// contention.
    Exhausted {
        /// The number of attempts made — always [`MAX_ATTEMPTS`].
        attempts: u32,
    },
}

impl<E: fmt::Display> fmt::Display for PrependError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cell(e) => write!(f, "chain-head cell failed: {e}"),
            Self::Exhausted { attempts } => write!(
                f,
                "chain-head publication refused {attempts} times; the head is being written by \
                 something outside the prepend protocol"
            ),
        }
    }
}

impl<E: fmt::Display + fmt::Debug> core::error::Error for PrependError<E> {}

/// Publishes `entry` as the new head of the chain, retrying until it wins, and returns **the head it
/// displaced**.
///
/// `observed` is the head the caller read when it linked `entry` — that is, the value `entry.next`
/// currently holds. The returned value is the head that was actually displaced: equal to `observed`
/// when the first attempt succeeded, and the last re-read head otherwise. It is the *only* value the
/// caller may use to fix a back-pointer (step 4 of the protocol; see the crate docs), because
/// winning the compare-and-publish against it is precisely what makes this writer the one that
/// displaced it.
///
/// On refusal the entry is re-linked ([`ChainHead::relink`]) before the next attempt, so the entry
/// published is never one whose `next` names a stale head.
///
/// # Errors
/// Returns [`PrependError::Cell`] if the head cell reports a medium failure, or
/// [`PrependError::Exhausted`] after [`MAX_ATTEMPTS`] refusals.
pub fn prepend<H: ChainHead>(
    cell: &mut H,
    observed: u64,
    entry: u64,
) -> Result<u64, PrependError<H::Error>> {
    let mut head = observed;
    for _ in 0..MAX_ATTEMPTS {
        if cell
            .compare_and_publish(head, entry)
            .map_err(PrependError::Cell)?
        {
            return Ok(head);
        }
        // Refused: somebody else is the head now. The entry's `next` names a head that no longer is
        // one, so it MUST be re-linked before the next attempt — publishing it as it stands would
        // fork the chain and orphan everything below the winner.
        head = cell.reread().map_err(PrependError::Cell)?;
        cell.relink(head).map_err(PrependError::Cell)?;
    }
    Err(PrependError::Exhausted {
        attempts: MAX_ATTEMPTS,
    })
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    /// A single-threaded head cell that can be told to refuse the first `refuse` attempts, standing
    /// in for the publications another writer wins in between.
    struct FakeHead {
        head: u64,
        refuse: u32,
        /// `next` of the entry being published, as [`ChainHead::relink`] leaves it.
        entry_next: u64,
        /// Every head this cell has been asked to link the entry to, in order.
        linked: Vec<u64>,
    }

    impl ChainHead for FakeHead {
        type Error = &'static str;

        fn compare_and_publish(&mut self, expect: u64, entry: u64) -> Result<bool, Self::Error> {
            if self.refuse > 0 {
                self.refuse -= 1;
                // Another writer won: the head moves somewhere this writer did not expect.
                self.head = 900 + u64::from(self.refuse);
                return Ok(false);
            }
            assert_eq!(
                expect, self.head,
                "the protocol must compare against the head"
            );
            self.head = entry;
            Ok(true)
        }

        fn reread(&mut self) -> Result<u64, Self::Error> {
            Ok(self.head)
        }

        fn relink(&mut self, head: u64) -> Result<(), Self::Error> {
            self.entry_next = head;
            self.linked.push(head);
            Ok(())
        }
    }

    fn cell(refuse: u32) -> FakeHead {
        FakeHead {
            head: 7,
            refuse,
            entry_next: 7,
            linked: Vec::new(),
        }
    }

    #[test]
    fn an_uncontended_prepend_publishes_on_the_first_attempt() {
        let mut c = cell(0);
        assert_eq!(prepend(&mut c, 7, 42).unwrap(), 7, "it displaced head 7");
        assert_eq!(c.head, 42);
        assert!(c.linked.is_empty(), "no refusal, so no re-link");
        assert_eq!(
            c.entry_next, 7,
            "the entry still names the head it displaced"
        );
    }

    #[test]
    fn a_refused_prepend_relinks_before_retrying_and_reports_what_it_displaced() {
        let mut c = cell(2);
        let displaced = prepend(&mut c, 7, 42).unwrap();
        // Two refusals moved the head to 901 then 900; the winning attempt displaced 900.
        assert_eq!(displaced, 900);
        assert_eq!(c.head, 42);
        assert_eq!(
            c.linked,
            vec![901, 900],
            "each refusal must re-link the entry to the head it re-read"
        );
        assert_eq!(
            c.entry_next, displaced,
            "the published entry must name exactly the head it displaced — anything else forks the \
             chain"
        );
    }

    #[test]
    fn a_cell_that_never_accepts_is_reported_rather_than_spun_on() {
        let mut c = cell(MAX_ATTEMPTS + 1);
        assert_eq!(
            prepend(&mut c, 7, 42),
            Err(PrependError::Exhausted {
                attempts: MAX_ATTEMPTS
            })
        );
    }

    #[test]
    fn a_medium_failure_is_propagated_not_retried() {
        struct Broken;
        impl ChainHead for Broken {
            type Error = &'static str;
            fn compare_and_publish(&mut self, _: u64, _: u64) -> Result<bool, Self::Error> {
                Err("device gone")
            }
            fn reread(&mut self) -> Result<u64, Self::Error> {
                unreachable!("not reached after a failed publication")
            }
            fn relink(&mut self, _: u64) -> Result<(), Self::Error> {
                unreachable!("not reached after a failed publication")
            }
        }
        assert_eq!(
            prepend(&mut Broken, 1, 2),
            Err(PrependError::Cell("device gone"))
        );
    }
}
