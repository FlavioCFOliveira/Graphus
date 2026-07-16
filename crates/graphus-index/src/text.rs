//! Text (trigram) indexing: an in-memory **trigram inverted index** that accelerates the three
//! Cypher string predicates a plain range index cannot — `CONTAINS`, `ENDS WITH` and `STARTS WITH`
//! — over a single node string property (`04-technical-design.md` §6; `rmp` task #662).
//!
//! A forward-ordered B-tree (the RANGE index) can serve `=` and a bounded `STARTS WITH` prefix seek
//! (`rmp` task #658), but it fundamentally cannot serve a **substring** (`CONTAINS`) or **suffix**
//! (`ENDS WITH`) predicate — those are not a contiguous key range. Neo4j's `TEXT` index is a distinct
//! native string index for exactly these; this module is its data-structure core.
//!
//! This module is the **data-structure layer**, kept deliberately self-contained and pure so it is
//! unit-testable in isolation (no store, no WAL, no buffer pool) — exactly like the full-text
//! [`crate::fulltext`] and spatial [`crate::spatial`] indexes. The transactional maintenance, MVCC
//! re-check, and durability of the *catalog* are layered on top in `graphus-cypher`
//! (`IndexSet`/`TxnCoordinator`) and `graphus-storage` (the durable catalog): the trigram index
//! itself is **ephemeral and rebuilt from the store on open**, so — like the derived property index —
//! it needs no separate crash-recovery path.
//!
//! # How it works — character trigrams with head/tail sentinels
//!
//! A **trigram** is a window of three consecutive [`char`]s (Unicode scalar values). For a value
//! `v = c0 c1 … c(n-1)` the index stores the trigrams of the *sentinel-padded* sequence
//! `[Start, c0, c1, …, c(n-1), End]` — a leading [`Gram::Start`] and a trailing [`Gram::End`] marker
//! that cannot collide with any real character. So `"cat"` indexes the four grams
//! `[Start,c,a] [c,a,t] [a,t,End]` … (three for `"cat"`; in general `n` grams for an `n`-char value),
//! and even a one-char value `"a"` yields the single gram `[Start,a,End]`, so **short strings are
//! indexed too** without a special case.
//!
//! A query extracts the trigrams of its needle and returns the node ids present in **every** one of
//! them (a posting-list intersection), which is a **candidate superset** of the true matches:
//!
//! - `CONTAINS sub` → the **unanchored** (character-only) trigrams of `sub`. If `v` contains `sub`,
//!   then `sub`'s character sequence is a contiguous run inside `v`, so every 3-window of `sub` is a
//!   3-window of `v` and hence an indexed gram of `v` — the node is in every posting list. ⊆ holds.
//! - `ENDS WITH suf` → the trigrams of `[…suf…, End]` (the tail-**anchored** grams). If `v` ends with
//!   `suf`, its final padded gram `[c(n-2), c(n-1), End]` equals `suf`'s final anchored gram, and the
//!   interior grams are character windows of `v` — so every anchored gram of `suf` is an indexed gram
//!   of `v`. The `End` marker makes the seek *tighter* than a bare `CONTAINS` (a `suf` occurring only
//!   mid-string is excluded).
//! - `STARTS WITH pre` → the trigrams of `[Start, …pre…]` (the head-anchored grams), symmetrically.
//!
//! # Short needles fall back to "all candidates"
//!
//! A needle too short to form even one trigram (an unanchored needle under three chars; an anchored
//! needle under two chars) cannot narrow the set — [`query_contains`](TrigramIndex::query_contains)
//! and friends return [`None`], and the caller must treat that as "cannot narrow, scan the label".
//! A broader (all-nodes) candidate set is still a correct superset; the mandatory residual re-check
//! restores exactness either way. This mirrors the spatial index's "query the grid cannot bound →
//! all candidates" fallback.
//!
//! # Raw characters, no normalization (the superset contract)
//!
//! The trigrams are extracted from the **raw** Unicode scalar values, with **no** case folding and
//! **no** Unicode normalization. That is deliberate and load-bearing: the caller's residual predicate
//! is Cypher's `CONTAINS` / `STARTS WITH` / `ENDS WITH`, which the executor evaluates as a **raw**
//! [`str::contains`] / [`str::starts_with`] / [`str::ends_with`] (byte/scalar-exact, no
//! normalization). Operating on the same raw scalar values is what *guarantees* the index is a
//! superset of that exact residual — normalizing here could fold two byte-different-but-canonically-
//! equal strings, or split a needle differently at a normalization boundary, and drop a true raw match
//! (a **subset** — a wrong result). "Normalize consistently with how the store compares strings" ⇒
//! the store compares strings raw ⇒ the index operates raw.
//!
//! # Candidates, not answers (the crate-wide contract)
//!
//! Every query method returns **candidate** node ids: it never filters by MVCC visibility, by current
//! label membership, or by the value's *current* text (a posting may be stale until an update
//! re-indexes the node). The caller re-checks every candidate against the transaction snapshot with
//! the exact predicate, so returning a **superset** of the truly-matching ids is always correct and a
//! subset never is — identical to [`crate::fulltext`] and [`crate::spatial`].

use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// One element of a [`Trigram`]: a real character, or a head/tail **sentinel** that cannot collide
/// with any Unicode scalar value.
///
/// Modelling the boundary as a distinct enum variant (rather than reserving a code point) means a
/// sentinel is provably distinct from every possible character — even the private-use planes — so an
/// anchored (`STARTS WITH` / `ENDS WITH`) gram can never be spoofed by real text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Gram {
    /// The head-of-string sentinel (before the first character). Present only in the first padded gram.
    Start,
    /// A real Unicode scalar value from the string.
    Ch(char),
    /// The tail-of-string sentinel (after the last character). Present only in the last padded gram.
    End,
}

/// A trigram: three consecutive [`Gram`]s. [`Ord`]-derivable so posting lists stay in a deterministic
/// [`BTreeMap`] order (reproducible tests, the candidate-ordering contract).
pub type Trigram = [Gram; 3];

/// An in-memory **trigram inverted index**: trigram → sorted postings of node ids, plus the forward
/// map (node → its trigrams) needed to apply deletes and updates in O(trigrams-per-node) without
/// scanning the whole index (`rmp` task #662).
///
/// # Representation
///
/// - `postings: trigram -> sorted, de-duplicated node ids that contain the trigram`. Sorted so a query
///   returns candidates ascending (a deterministic order, like every other index kind) and posting
///   lists intersect efficiently; de-duplicated because a node either has a trigram or it does not — a
///   trigram appearing at several positions in one value contributes the node once.
/// - `forward: node -> the set of trigrams it currently contributes`. Without it, removing a node
///   would require scanning every posting list; with it, a delete/update is O(trigrams-per-node).
///
/// Both are [`BTreeMap`]/[`BTreeSet`]-backed so the structure is deterministic (ordered iteration),
/// which matters for reproducible tests and the candidate-ordering contract.
///
/// # Candidate contract
///
/// Like every derived index, this returns **candidates**: it never checks visibility, the node's
/// current label, or its current text. The caller re-checks. See the [module docs](self).
#[derive(Debug, Clone, Default)]
pub struct TrigramIndex {
    /// trigram → sorted, de-duplicated node ids that contain the trigram.
    postings: BTreeMap<Trigram, Vec<u64>>,
    /// node → the set of trigrams it currently contributes (the forward index, for deletes/updates).
    forward: BTreeMap<u64, BTreeSet<Trigram>>,
}

impl TrigramIndex {
    /// An empty trigram index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the index holds no values.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.forward.is_empty()
    }

    /// The number of indexed values (distinct node ids currently present).
    #[must_use]
    pub fn len(&self) -> usize {
        self.forward.len()
    }

    /// The number of distinct trigrams currently in the index.
    #[must_use]
    pub fn trigram_count(&self) -> usize {
        self.postings.len()
    }

    /// Indexes (or **re-indexes**) `node` with the string `value`. Idempotent on the node: it first
    /// removes any existing trigrams for `node` (so a re-index after a property update replaces the old
    /// trigrams wholesale), then inserts `node` into the posting list of each distinct trigram of the
    /// sentinel-padded value.
    ///
    /// An empty `value` yields no trigrams (`[Start, End]` has no 3-window), which removes the node from
    /// the index entirely — exactly the update-to-empty case. Only `CONTAINS ""` / `STARTS WITH ""` /
    /// `ENDS WITH ""` would match an empty string, and those needles are too short to form a trigram so
    /// they take the "all candidates" fallback anyway (the residual re-check keeps the empty value).
    ///
    /// Returns whether the node's indexed content actually **changed** — it was present before AND its
    /// new trigram set differs from the old (an update to a different value, or an update-to-empty
    /// removal). A brand-new node (a pure insert) and an *unchanged* re-index (e.g. the wholesale
    /// [`reindex_node`](crate::record_graph) a write of an UNRELATED property triggers) both return
    /// `false`. The full-text/spatial freshness-marker machinery (`rmp` task #756) uses this to poison
    /// the marker on rollback ONLY for a real change: a rolled-back change can leave a still-committed
    /// node dropped from a posting it should occupy (a false negative the re-check cannot resurrect),
    /// whereas a rolled-back pure insert or unchanged re-index leaves the committed posting exactly as it
    /// should be (at worst a re-check-filterable false positive) — so poisoning it would needlessly
    /// disable the fast path.
    pub fn index_value(&mut self, node: u64, value: &str) -> bool {
        let distinct = padded_trigrams(value);
        // Did the indexed content actually change? Present before AND the new trigram set differs. An
        // unchanged re-index (same trigrams) must report `false` so it does not poison on rollback
        // (`rmp` task #756). The borrow ends before the mutating `remove` below.
        let changed = self.forward.get(&node).is_some_and(|old| old != &distinct);

        // Remove the old value first so an update fully replaces, not accumulates, its trigrams.
        self.remove(node);

        if distinct.is_empty() {
            return changed;
        }
        for &tri in &distinct {
            let list = self.postings.entry(tri).or_default();
            // Keep each posting list sorted + de-duplicated. `node` is absent (we just removed it), so a
            // binary-search insert keeps the invariant in O(log n).
            if let Err(pos) = list.binary_search(&node) {
                list.insert(pos, node);
            }
        }
        self.forward.insert(node, distinct);
        changed
    }

    /// Removes `node` from the index entirely (its forward entry and every posting list it appears in),
    /// returning whether it was present. Idempotent: removing an absent node is a no-op.
    pub fn remove(&mut self, node: u64) -> bool {
        let Some(trigrams) = self.forward.remove(&node) else {
            return false;
        };
        for tri in trigrams {
            if let Some(list) = self.postings.get_mut(&tri) {
                if let Ok(pos) = list.binary_search(&node) {
                    list.remove(pos);
                }
                // Drop an emptied posting list so `trigram_count` reflects only live trigrams.
                if list.is_empty() {
                    self.postings.remove(&tri);
                }
            }
        }
        true
    }

    /// Drops every value, leaving an empty index (used by a full rebuild from the store).
    pub fn clear(&mut self) {
        self.postings.clear();
        self.forward.clear();
    }

    /// Candidate node ids that may **contain** `needle` as a substring, ascending and de-duplicated
    /// (`rmp` task #662). Uses the unanchored (character-only) trigrams of `needle`.
    ///
    /// Returns [`None`] when `needle` is too short to form a trigram (fewer than 3 characters): the
    /// index cannot narrow the set, so the caller must fall back to the full label scan (a broader
    /// superset the residual re-check trims). `Some(ids)` is a candidate **superset** — see the
    /// [module docs](self) for the ⊆ argument.
    #[must_use]
    pub fn query_contains(&self, needle: &str) -> Option<Vec<u64>> {
        self.intersect(unanchored_trigrams(needle))
    }

    /// Candidate node ids that may **start with** `prefix`, ascending and de-duplicated (`rmp` task
    /// #662). Uses the head-anchored (`[Start, …]`) trigrams of `prefix`.
    ///
    /// Returns [`None`] when `prefix` is too short to form an anchored trigram (fewer than 2
    /// characters), for the same "cannot narrow → scan the label" reason as
    /// [`query_contains`](Self::query_contains). `Some(ids)` is a candidate **superset**.
    #[must_use]
    pub fn query_starts_with(&self, prefix: &str) -> Option<Vec<u64>> {
        self.intersect(head_anchored_trigrams(prefix))
    }

    /// Candidate node ids that may **end with** `suffix`, ascending and de-duplicated (`rmp` task
    /// #662). Uses the tail-anchored (`[…, End]`) trigrams of `suffix`.
    ///
    /// Returns [`None`] when `suffix` is too short to form an anchored trigram (fewer than 2
    /// characters), for the same "cannot narrow → scan the label" reason as
    /// [`query_contains`](Self::query_contains). `Some(ids)` is a candidate **superset**.
    #[must_use]
    pub fn query_ends_with(&self, suffix: &str) -> Option<Vec<u64>> {
        self.intersect(tail_anchored_trigrams(suffix))
    }

    /// Intersects the posting lists of every trigram in `query` — the node ids present in **all** of
    /// them, ascending and de-duplicated. [`None`] when `query` is empty (a too-short needle: the index
    /// cannot narrow the set). An empty intersection (some trigram has no postings) is `Some(vec![])`.
    fn intersect(&self, query: BTreeSet<Trigram>) -> Option<Vec<u64>> {
        if query.is_empty() {
            return None;
        }
        // Gather the posting list for each distinct query trigram. A missing trigram means no node has
        // it, so the intersection — and thus the candidate set — is empty.
        let mut lists: Vec<&Vec<u64>> = Vec::with_capacity(query.len());
        for tri in &query {
            match self.postings.get(tri) {
                Some(list) => lists.push(list),
                None => return Some(Vec::new()),
            }
        }
        // Intersect the shortest list against the rest (each posting list is sorted ascending and
        // de-duplicated). Starting from the shortest keeps the candidate set — and the work — minimal.
        lists.sort_by_key(|l| l.len());
        let (shortest, rest) = lists.split_first().expect("query is non-empty");
        let mut acc: Vec<u64> = Vec::new();
        'candidate: for &id in shortest.iter() {
            for list in rest {
                if list.binary_search(&id).is_err() {
                    continue 'candidate;
                }
            }
            acc.push(id);
        }
        Some(acc)
    }
}

/// The distinct **sentinel-padded** trigrams of `value` — the grams stored for a node (`rmp` task
/// #662). The padded sequence is `[Start, c0, …, c(n-1), End]`; its 3-windows are the value's grams.
/// An empty value yields the empty set (`[Start, End]` has no 3-window).
fn padded_trigrams(value: &str) -> BTreeSet<Trigram> {
    let mut seq: Vec<Gram> = Vec::new();
    seq.push(Gram::Start);
    seq.extend(value.chars().map(Gram::Ch));
    seq.push(Gram::End);
    windows3(&seq)
}

/// The distinct **unanchored** (character-only) trigrams of `needle`, for a `CONTAINS` query. Empty
/// when `needle` has fewer than 3 characters (no 3-window).
fn unanchored_trigrams(needle: &str) -> BTreeSet<Trigram> {
    let seq: Vec<Gram> = needle.chars().map(Gram::Ch).collect();
    windows3(&seq)
}

/// The distinct **head-anchored** trigrams of `prefix` — the 3-windows of `[Start, p0, …]` — for a
/// `STARTS WITH` query. Empty when `prefix` has fewer than 2 characters (no 3-window after the anchor).
fn head_anchored_trigrams(prefix: &str) -> BTreeSet<Trigram> {
    let mut seq: Vec<Gram> = Vec::new();
    seq.push(Gram::Start);
    seq.extend(prefix.chars().map(Gram::Ch));
    windows3(&seq)
}

/// The distinct **tail-anchored** trigrams of `suffix` — the 3-windows of `[…, s(k-1), End]` — for an
/// `ENDS WITH` query. Empty when `suffix` has fewer than 2 characters (no 3-window before the anchor).
fn tail_anchored_trigrams(suffix: &str) -> BTreeSet<Trigram> {
    let mut seq: Vec<Gram> = suffix.chars().map(Gram::Ch).collect();
    seq.push(Gram::End);
    windows3(&seq)
}

/// The distinct 3-windows of `seq` (fewer than 3 elements ⇒ the empty set).
fn windows3(seq: &[Gram]) -> BTreeSet<Trigram> {
    seq.windows(3).map(|w| [w[0], w[1], w[2]]).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The distinct padded trigrams of `s`, as a sorted `Vec` for terse assertions.
    fn grams(s: &str) -> Vec<Trigram> {
        padded_trigrams(s).into_iter().collect()
    }

    #[test]
    fn short_values_are_indexed_via_sentinels() {
        // A one-char value yields exactly `[Start, a, End]`; a two-char value yields two grams.
        assert_eq!(grams("a"), vec![[Gram::Start, Gram::Ch('a'), Gram::End]]);
        assert_eq!(
            grams("ab"),
            vec![
                [Gram::Start, Gram::Ch('a'), Gram::Ch('b')],
                [Gram::Ch('a'), Gram::Ch('b'), Gram::End],
            ]
        );
        // An empty value yields no grams: `[Start, End]` has no 3-window.
        assert!(grams("").is_empty());
    }

    #[test]
    fn insert_query_contains_and_remove() {
        let mut idx = TrigramIndex::new();
        idx.index_value(10, "database");
        idx.index_value(20, "warehouse");
        idx.index_value(30, "data lake");
        assert_eq!(idx.len(), 3);

        // CONTAINS "ata" → 10 (database) and 30 (data lake), not 20.
        let mut got = idx.query_contains("ata").unwrap();
        got.sort_unstable();
        assert_eq!(got, vec![10, 30]);

        // Remove 30; only 10 remains.
        assert!(idx.remove(30));
        assert_eq!(idx.query_contains("ata"), Some(vec![10]));
        // Idempotent remove.
        assert!(!idx.remove(30));
    }

    #[test]
    fn contains_returns_a_superset_caller_rechecks() {
        // The trigram intersection is a *necessary* condition, not sufficient: a value can hold every
        // trigram of the needle without containing the needle contiguously. Here "abcx...xcab" holds
        // "abc"'s trigram {a,b,c} but the substring "cab" too, so a CONTAINS "abc" candidate that does
        // NOT actually contain "abc" is possible — the documented superset the caller re-checks.
        let mut idx = TrigramIndex::new();
        idx.index_value(1, "abcxcab"); // holds gram [a,b,c] (pos 0) — genuinely contains "abc"
        idx.index_value(2, "cabx"); // holds [c,a,b] but NOT the gram [a,b,c]
        let got = idx.query_contains("abc").unwrap();
        assert_eq!(
            got,
            vec![1],
            "only the value with the [a,b,c] gram is a candidate"
        );
        // The caller's exact `str::contains` would confirm 1 and (had it been a candidate) reject 2.
        assert!("abcxcab".contains("abc"));
        assert!(!"cabx".contains("abc"));
    }

    #[test]
    fn ends_with_is_tighter_than_contains() {
        let mut idx = TrigramIndex::new();
        idx.index_value(1, "report.txt"); // ends with "txt"
        idx.index_value(2, "txtfile.doc"); // contains "txt" but does NOT end with it
        // ENDS WITH "txt" uses the tail-anchored grams (…,t,End) → only the value actually ending in it.
        assert_eq!(idx.query_ends_with("txt"), Some(vec![1]));
        // Whereas CONTAINS "txt" admits both (they both hold the unanchored gram [t,x,t]).
        let mut both = idx.query_contains("txt").unwrap();
        both.sort_unstable();
        assert_eq!(both, vec![1, 2]);
    }

    #[test]
    fn starts_with_is_anchored_at_the_head() {
        let mut idx = TrigramIndex::new();
        idx.index_value(1, "prefix-match"); // starts with "pre"
        idx.index_value(2, "the-prefix"); // contains "pre" but does NOT start with it
        assert_eq!(idx.query_starts_with("pre"), Some(vec![1]));
        let mut both = idx.query_contains("pre").unwrap();
        both.sort_unstable();
        assert_eq!(both, vec![1, 2]);
    }

    #[test]
    fn short_needles_return_none_the_scan_fallback_signal() {
        let mut idx = TrigramIndex::new();
        idx.index_value(1, "anything");
        // A CONTAINS needle under 3 chars, or an anchored needle under 2 chars, cannot form a trigram:
        // the index cannot narrow, so it signals "None" (the caller scans the label).
        assert_eq!(idx.query_contains("ab"), None);
        assert_eq!(idx.query_contains("a"), None);
        assert_eq!(idx.query_contains(""), None);
        assert_eq!(idx.query_starts_with("a"), None);
        assert_eq!(idx.query_ends_with("a"), None);
        // But a 2-char anchored needle IS servable (Start/End makes 3 elements).
        assert!(idx.query_starts_with("an").is_some());
        assert!(idx.query_ends_with("ng").is_some());
    }

    #[test]
    fn no_match_yields_empty_not_none() {
        let mut idx = TrigramIndex::new();
        idx.index_value(1, "hello");
        // A well-formed needle that no value contains → Some(empty), distinct from the None (too-short)
        // signal: the index CAN narrow, and it narrowed to nothing.
        assert_eq!(idx.query_contains("zzz"), Some(Vec::new()));
    }

    #[test]
    fn reindex_replaces_trigrams_wholesale() {
        let mut idx = TrigramIndex::new();
        idx.index_value(10, "database");
        // Update: the node's text changed; it no longer mentions "data".
        idx.index_value(10, "warehouse");
        assert_eq!(idx.query_contains("hou"), Some(vec![10]));
        // The stale "dat" trigram must be gone — a wholesale replace, not an accumulation.
        assert_eq!(idx.query_contains("dat"), Some(Vec::new()));
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn reindex_to_empty_removes_the_node() {
        let mut idx = TrigramIndex::new();
        idx.index_value(10, "graph");
        idx.index_value(10, ""); // text became empty
        assert_eq!(idx.query_contains("gra"), Some(Vec::new()));
        assert!(idx.is_empty());
    }

    #[test]
    fn unicode_scalar_values_are_the_unit_no_normalization() {
        // Trigrams are over raw `char`s. A multi-byte character is one gram element, and the index does
        // NOT normalize — so a query must be a *raw* substring of the value (matching the executor's raw
        // `str::contains`). "cafétér" contains the accented run.
        let mut idx = TrigramIndex::new();
        idx.index_value(1, "cafétér"); // é = U+00E9, one scalar value
        // CONTAINS "fét" (3 scalar values f, é, t) is a raw substring → candidate.
        assert_eq!(idx.query_contains("fét"), Some(vec![1]));
        // A CJK example: three han characters form one trigram.
        idx.index_value(2, "日本語のテスト");
        assert_eq!(idx.query_contains("本語の"), Some(vec![2]));
    }

    #[test]
    fn nfc_and_nfd_do_not_cross_match_matching_the_raw_residual() {
        // The index is raw (no normalization), exactly like the executor's `str::contains`. A value
        // stored NFC-composed and a needle written NFD-decomposed are DIFFERENT scalar sequences, so
        // they do NOT cross-match — which is precisely what the raw residual does too, so the index
        // stays a faithful superset of it (normalizing here could drop a true raw match: a subset bug).
        let nfc = "caf\u{00e9}"; // café, composed  (…, U+00E9)
        let nfd = "cafe\u{0301}"; // café, decomposed (…, e, U+0301)
        let mut idx = TrigramIndex::new();
        idx.index_value(1, nfc);
        // Querying the NFD form does not match the NFC value — and neither does raw `str::contains`.
        assert!(!nfc.contains(nfd));
        // "afé" (a, f? no) — use a 3-scalar composed run present in the NFC value: "afé" = a,f,é.
        assert_eq!(idx.query_contains("af\u{00e9}"), Some(vec![1]));
        // The decomposed "é" run is absent from the NFC value (raw), so no candidate.
        assert_eq!(idx.query_contains("e\u{0301}z"), Some(Vec::new()));
    }

    #[test]
    fn brute_force_oracle_superset_over_many_values_and_needles() {
        // The headline correctness property: for many values and needles, the trigram candidate set is a
        // SUPERSET of the brute-force exact match set (never a subset). A subset would be a wrong query
        // result; a superset is corrected by the caller's residual re-check.
        let values: Vec<(u64, &str)> = vec![
            (1, "alpha beta"),
            (2, "gamma delta"),
            (3, "the quick brown fox"),
            (4, "brown sugar"),
            (5, "fox trot"),
            (6, "café society"),
            (7, ""),
            (8, "ab"),
            (9, "quickbrown"),
        ];
        let mut idx = TrigramIndex::new();
        for (id, v) in &values {
            idx.index_value(*id, v);
        }
        let needles = [
            "quick", "brown", "fox", "ck b", "a", "ab", "xyz", "café", "own", "the",
        ];
        for needle in needles {
            // CONTAINS.
            if let Some(cands) = idx.query_contains(needle) {
                let cands: BTreeSet<u64> = cands.into_iter().collect();
                for (id, v) in &values {
                    if v.contains(needle) {
                        assert!(
                            cands.contains(id),
                            "CONTAINS {needle:?}: value {id} ({v:?}) truly matches but is not a candidate",
                        );
                    }
                }
            }
            // STARTS WITH.
            if let Some(cands) = idx.query_starts_with(needle) {
                let cands: BTreeSet<u64> = cands.into_iter().collect();
                for (id, v) in &values {
                    if v.starts_with(needle) {
                        assert!(
                            cands.contains(id),
                            "STARTS WITH {needle:?}: value {id} ({v:?}) truly matches but is not a candidate",
                        );
                    }
                }
            }
            // ENDS WITH.
            if let Some(cands) = idx.query_ends_with(needle) {
                let cands: BTreeSet<u64> = cands.into_iter().collect();
                for (id, v) in &values {
                    if v.ends_with(needle) {
                        assert!(
                            cands.contains(id),
                            "ENDS WITH {needle:?}: value {id} ({v:?}) truly matches but is not a candidate",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn clear_empties_the_index() {
        let mut idx = TrigramIndex::new();
        idx.index_value(10, "alpha");
        idx.index_value(20, "beta");
        idx.clear();
        assert!(idx.is_empty());
        assert_eq!(idx.trigram_count(), 0);
        assert_eq!(idx.query_contains("alp"), Some(Vec::new()));
    }

    #[test]
    fn duplicate_trigram_in_one_value_appears_once_in_postings() {
        let mut idx = TrigramIndex::new();
        idx.index_value(10, "aaaa"); // the gram [a,a,a] occurs twice
        assert_eq!(idx.query_contains("aaa"), Some(vec![10]));
        // Postings: [Start,a,a], [a,a,a], [a,a,End] → 3 distinct grams, [a,a,a] once.
        assert_eq!(idx.trigram_count(), 3);
    }

    /// `rmp` #756: `index_value` must report whether the indexed content actually CHANGED — a pure insert
    /// and an UNCHANGED re-index both return `false`; only a real change (or an update-to-empty removal)
    /// returns `true`. The rollback-poison discriminator relies on this so an aborted write that
    /// re-indexes an unchanged value (a wholesale re-index driven by an unrelated property write) does
    /// NOT poison, while a rolled-back real change (a false-negative risk) does.
    #[test]
    fn index_value_reports_whether_the_value_actually_changed_756() {
        let mut idx = TrigramIndex::new();
        assert!(
            !idx.index_value(1, "apple"),
            "first index of a node is a pure insert, not a change"
        );
        assert!(
            !idx.index_value(1, "apple"),
            "re-indexing the SAME value is NOT a change (rmp #756)"
        );
        assert!(
            idx.index_value(1, "banana"),
            "re-index to a DIFFERENT value is a change"
        );
        assert!(
            idx.index_value(1, ""),
            "update-to-empty on a present node drops its posting (a change)"
        );
        assert!(
            !idx.index_value(2, ""),
            "an empty value on an absent node changes nothing"
        );
    }
}
