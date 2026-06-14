//! Full-text indexing: a documented **text analyzer** and an in-memory **inverted index**
//! (`04-technical-design.md` §6, `D-v1-index-types` — full-text search; `rmp` task #72).
//!
//! A full-text index covers one node label and one or more string properties. It enables tokenized,
//! analyzer-based text search (`db.index.fulltext.queryNodes`) — far faster and richer than a
//! substring (`CONTAINS`) scan, a common application need.
//!
//! This module is the **data-structure + analysis layer**, kept deliberately self-contained and
//! pure so it is unit-testable in isolation (no store, no WAL, no buffer pool). The transactional
//! maintenance, MVCC re-check and durability of the *catalog* are layered on top in `graphus-cypher`
//! (`IndexSet`/`TxnCoordinator`) and `graphus-storage` (the durable full-text catalog), exactly as
//! the node-property index (`rmp` tasks #48/#90/#91) is: the inverted index itself is **ephemeral
//! and rebuilt from the store on open**, so — like the derived [`crate::kinds::PropertyIndex`] the
//! `IndexSet` holds — it needs no separate crash-recovery path. See the [`crate::kinds`] crate-root
//! seam for the candidate-vs-answer contract this index also obeys.
//!
//! # Two layers
//!
//! - [`Analyzer`] — turns raw text into a sequence of normalized **terms** (tokens). The *same*
//!   analyzer must be applied at index time and at query time, or a document indexed under one
//!   normalization would never match a query normalized differently. The analyzer is a property of
//!   the index, chosen at `CREATE FULLTEXT INDEX` time and recorded in the durable catalog.
//! - [`InvertedIndex`] — the term → sorted-postings map, plus the **forward map** (node → its
//!   indexed terms) required to apply deletes and updates in O(terms-per-node) without scanning the
//!   whole index.
//!
//! # Candidates, not answers (the crate-wide contract)
//!
//! [`InvertedIndex::query`] returns **candidate** node ids: it never filters by MVCC visibility, by
//! current label membership, or by the document's *current* text (a posting may be stale until an
//! update re-indexes the node). The caller (the coordinator's statement seam) re-checks every
//! candidate against the transaction snapshot, so returning a **superset** of the truly-matching
//! ids is always correct and a subset never is — identical to [`crate::kinds`].

use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// The maximum length, in **bytes**, of a single analyzed term (`rmp` task #72).
///
/// Matches Lucene's `StandardAnalyzer` default `maxTokenLength` (255, rounded to a clean 256). It
/// bounds the memory a single untrusted token can amplify into: without a cap, a multi-megabyte run
/// of alphanumeric characters in a node property — or in a search string — would become one giant
/// term occupying a posting-list key and the forward set, an amplification path from untrusted text.
/// A run reaching the cap is **truncated** at the last whole character that fits (never split mid
/// UTF-8 sequence) and the remainder of the run is discarded, so the term stays a bounded, valid
/// `String`. Because the identical analyzer runs at index and query time, truncation is symmetric and
/// does not change which (in-bound) documents match.
pub const MAX_TERM_LEN: usize = 256;

/// The set of supported full-text analyzers (`rmp` task #72).
///
/// The analyzer is a **property of the index**, fixed at `CREATE FULLTEXT INDEX … OPTIONS {analyzer}`
/// time and recorded in the durable catalog, because the *identical* analysis must be applied when a
/// document is indexed and when a search string is queried — otherwise a term indexed as `"café"`
/// would never match a query that normalized it differently.
///
/// The on-disk discriminant ([`as_byte`](Self::as_byte) / [`from_byte`](Self::from_byte)) is frozen:
/// a stored catalog entry decodes its analyzer from this byte, so the mapping must never change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Analyzer {
    /// The **standard** analyzer (the default). Tokenization, normalization and stop-word removal
    /// are documented on [`Analyzer::analyze`]:
    ///
    /// 1. **Tokenize** on Unicode non-alphanumeric boundaries: a maximal run of
    ///    [`char::is_alphanumeric`] characters is one token; every other character (space,
    ///    punctuation, symbol) is a separator and is discarded. This is Unicode-aware — e.g.
    ///    `"l'été-2024"` tokenizes to `["l", "été", "2024"]` and CJK text splits per the
    ///    alphanumeric property.
    /// 2. **Lowercase** each token with [`str::to_lowercase`] (full Unicode case folding, so
    ///    `"Æon"` → `"æon"`, German `"ß"` is preserved as the spec defines, etc.).
    /// 3. **Remove stop-words**: tokens equal (after lowercasing) to one of the documented English
    ///    stop-words ([`STANDARD_STOP_WORDS`]) are dropped. The set is intentionally small and
    ///    conservative (the most common closed-class English words), so it never silently swallows a
    ///    meaningful term.
    #[default]
    Standard,
    /// The **keyword** (no-op) analyzer: the entire input is **one** term, lowercased, with no
    /// tokenization and no stop-word removal. Useful for exact-but-case-insensitive matching of a
    /// whole field (e.g. an identifier or tag). An empty / whitespace-only input yields no terms.
    Keyword,
}

impl Analyzer {
    /// The single-byte on-disk discriminant (frozen format, `rmp` task #72). Bytes `2..` are
    /// reserved for future analyzers (e.g. a language-specific stemmer).
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Standard => 0,
            Self::Keyword => 1,
        }
    }

    /// Decodes a single-byte discriminant, or [`None`] for an unknown (reserved/future) byte so a
    /// forward-incompatible catalog image is rejected rather than silently mis-decoded.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Standard),
            1 => Some(Self::Keyword),
            _ => None,
        }
    }

    /// The lower-cased name of the analyzer, as written in `OPTIONS { analyzer: '<name>' }` and
    /// shown by `SHOW FULLTEXT INDEXES`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Keyword => "keyword",
        }
    }

    /// Parses an analyzer name (case-insensitive), or [`None`] if it is not a recognized analyzer.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "standard" => Some(Self::Standard),
            "keyword" => Some(Self::Keyword),
            _ => None,
        }
    }

    /// Analyzes `text` into its sequence of normalized terms, in first-appearance order with
    /// duplicates preserved (the caller decides whether to deduplicate). The exact rules per
    /// analyzer are documented on the [`Analyzer`] variants; this is the **single** entry point used
    /// at both index time and query time so the two can never diverge.
    ///
    /// # Examples
    ///
    /// ```
    /// use graphus_index::fulltext::Analyzer;
    ///
    /// // Standard: tokenize, lowercase, drop stop-words ("the", "over" stays as it is not a stop word).
    /// let terms = Analyzer::Standard.analyze("The quick brown Fox!");
    /// assert_eq!(terms, vec!["quick", "brown", "fox"]); // "the" removed, rest lowercased
    ///
    /// // Keyword: the whole input is one lowercased term.
    /// assert_eq!(Analyzer::Keyword.analyze("Hello World"), vec!["hello world"]);
    /// ```
    #[must_use]
    pub fn analyze(self, text: &str) -> Vec<String> {
        match self {
            Self::Standard => Self::analyze_standard(text),
            Self::Keyword => Self::analyze_keyword(text),
        }
    }

    /// The standard analysis pipeline (tokenize → lowercase → drop stop-words). See [`Analyzer::Standard`].
    fn analyze_standard(text: &str) -> Vec<String> {
        let mut terms = Vec::new();
        let mut current = String::new();
        // Tokenize on Unicode non-alphanumeric boundaries.
        for ch in text.chars() {
            if ch.is_alphanumeric() {
                // Cap the in-progress token so an untrusted multi-megabyte alphanumeric run does not
                // amplify into one giant `String` (see `MAX_TERM_LEN`). Once the cap is reached we
                // stop accumulating; the rest of this run is discarded but still acts as no boundary,
                // so the following separator flushes the (capped) token.
                if current.len() + ch.len_utf8() <= MAX_TERM_LEN {
                    current.push(ch);
                }
            } else if !current.is_empty() {
                Self::push_standard_term(&mut terms, &current);
                current.clear();
            }
        }
        if !current.is_empty() {
            Self::push_standard_term(&mut terms, &current);
        }
        terms
    }

    /// Lowercases `raw` and pushes it onto `terms` unless it is a stop-word.
    fn push_standard_term(terms: &mut Vec<String>, raw: &str) {
        // Lowercasing may expand a char (e.g. `İ` → `i̇`); `to_lowercase` handles the full mapping.
        // It can push the result back over `MAX_TERM_LEN` even though `raw` was capped, so truncate
        // the lowercased form too (defense-in-depth against case-folding expansion).
        let lower = truncate_term(&raw.to_lowercase());
        if !is_standard_stop_word(&lower) {
            terms.push(lower);
        }
    }

    /// The keyword analysis: the whole trimmed input is one lowercased term (none if empty),
    /// truncated to [`MAX_TERM_LEN`] so an untrusted multi-megabyte field cannot become one giant
    /// term.
    fn analyze_keyword(text: &str) -> Vec<String> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            Vec::new()
        } else {
            vec![truncate_term(&trimmed.to_lowercase())]
        }
    }
}

/// Truncates `term` to at most [`MAX_TERM_LEN`] bytes on a UTF-8 character boundary, returning it
/// unchanged when already within the cap (the common case, no allocation).
fn truncate_term(term: &str) -> String {
    if term.len() <= MAX_TERM_LEN {
        return term.to_owned();
    }
    // Find the largest char boundary `<= MAX_TERM_LEN` so we never split a multi-byte char.
    let mut end = MAX_TERM_LEN;
    while end > 0 && !term.is_char_boundary(end) {
        end -= 1;
    }
    term[..end].to_owned()
}

/// The documented English stop-word set for the [`Analyzer::Standard`] analyzer (`rmp` task #72).
///
/// Deliberately small and conservative — the most common closed-class English words (articles,
/// conjunctions, prepositions, auxiliary/copular verbs, a handful of pronouns) — so it speeds up the
/// common case (these words are in almost every document and almost never the discriminating search
/// term) without silently swallowing a meaningful term. The list is sorted so the membership test
/// can binary-search. All entries are already lower-case (the membership test receives a lowercased
/// token).
pub const STANDARD_STOP_WORDS: &[&str] = &[
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "for", "if", "in", "into", "is", "it",
    "no", "not", "of", "on", "or", "such", "that", "the", "their", "then", "there", "these",
    "they", "this", "to", "was", "will", "with",
];

/// Whether `term` (already lower-cased) is a [`Analyzer::Standard`] stop-word.
///
/// Uses a binary search over the sorted [`STANDARD_STOP_WORDS`]; the slice is asserted sorted in a
/// unit test so the search is sound.
#[must_use]
pub fn is_standard_stop_word(term: &str) -> bool {
    STANDARD_STOP_WORDS.binary_search(&term).is_ok()
}

/// An in-memory **inverted index**: term → sorted postings of node ids, plus the forward map (node →
/// its indexed terms) needed to apply deletes and updates (`rmp` task #72).
///
/// # Representation
///
/// - `postings: term -> sorted, de-duplicated node ids`. Sorted so [`query`](Self::query) returns
///   candidates ascending (a deterministic order, like every other index kind) and a posting list
///   can be merged efficiently; de-duplicated because a node either matches a term or does not — a
///   repeated term in one document contributes the node once.
/// - `forward: node -> the set of terms it currently contributes`. Without this, removing a node
///   would require scanning every posting list; with it, a delete/update is O(terms-per-node).
///
/// Both are [`BTreeMap`]/[`BTreeSet`]-backed so the structure is deterministic (ordered iteration),
/// which matters for reproducible tests and the candidate ordering contract.
///
/// # Candidate contract
///
/// Like every [`crate::kinds`] index, this returns **candidates**: it never checks visibility, the
/// node's current label, or its current text. The caller re-checks. See the [module docs](self).
#[derive(Debug, Clone, Default)]
pub struct InvertedIndex {
    /// term → sorted, de-duplicated node ids that contain the term.
    postings: BTreeMap<String, Vec<u64>>,
    /// node → the set of terms it currently contributes (the forward index, for deletes/updates).
    forward: BTreeMap<u64, BTreeSet<String>>,
}

impl InvertedIndex {
    /// An empty inverted index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the index holds no documents.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.forward.is_empty()
    }

    /// The number of indexed documents (distinct node ids currently present).
    #[must_use]
    pub fn document_count(&self) -> usize {
        self.forward.len()
    }

    /// The number of distinct terms currently in the index.
    #[must_use]
    pub fn term_count(&self) -> usize {
        self.postings.len()
    }

    /// Indexes (or **re-indexes**) `node` with `terms` — the analyzed terms of all its indexed
    /// properties concatenated. This is idempotent on the document: it first removes any existing
    /// terms for `node` (so a re-index after a property update replaces the old terms wholesale),
    /// then inserts `node` into the posting list of each distinct term.
    ///
    /// Passing an empty `terms` removes the document entirely (a node whose indexed text became
    /// empty no longer matches anything), which is exactly the update-to-empty case.
    pub fn index_document(&mut self, node: u64, terms: &[String]) {
        // Remove the old document first so an update fully replaces, not accumulates, its terms.
        self.remove_document(node);

        if terms.is_empty() {
            return;
        }
        // PERF/I2: the previous code allocated a clone for `distinct.insert(term.clone())` on every
        // input term — including repeated terms, where the clone was immediately dropped on the
        // failed insert. Gate on `contains` first so a repeated term costs no allocation; a
        // genuinely new term is still owned independently by `forward` and `postings` (two owners,
        // two copies is the minimum). Index contents are identical.
        let mut distinct: BTreeSet<String> = BTreeSet::new();
        for term in terms {
            if distinct.contains(term) {
                continue;
            }
            distinct.insert(term.clone());
            let list = self.postings.entry(term.clone()).or_default();
            // Keep each posting list sorted + de-duplicated. `node` is absent (we just removed
            // the document), so a binary-search insert keeps the invariant in O(log n).
            if let Err(pos) = list.binary_search(&node) {
                list.insert(pos, node);
            }
        }
        self.forward.insert(node, distinct);
    }

    /// Removes `node` from the index entirely (its forward entry and every posting list it appears
    /// in), returning whether it was present. Idempotent: removing an absent node is a no-op.
    pub fn remove_document(&mut self, node: u64) -> bool {
        let Some(terms) = self.forward.remove(&node) else {
            return false;
        };
        for term in terms {
            if let Some(list) = self.postings.get_mut(&term) {
                if let Ok(pos) = list.binary_search(&node) {
                    list.remove(pos);
                }
                // Drop an emptied posting list so `term_count` reflects only live terms.
                if list.is_empty() {
                    self.postings.remove(&term);
                }
            }
        }
        true
    }

    /// Drops every document, leaving an empty index (used by a full rebuild from the store).
    pub fn clear(&mut self) {
        self.postings.clear();
        self.forward.clear();
    }

    /// The candidate node ids matching `query_terms` under `semantics`, ascending and de-duplicated.
    ///
    /// - [`MatchSemantics::Or`] (the default): a node is a candidate if it contains **at least one**
    ///   of the query terms (union of the posting lists). This is the simplest correct default and
    ///   the one the procedure surface documents.
    /// - [`MatchSemantics::And`]: a node is a candidate only if it contains **every** query term
    ///   (intersection of the posting lists).
    ///
    /// An empty `query_terms` (e.g. a search string that analyzed to nothing — all stop-words, or
    /// only punctuation) matches **no** node under either semantics.
    ///
    /// The result is a candidate set (see the [module docs](self)); the caller re-checks visibility.
    #[must_use]
    pub fn query(&self, query_terms: &[String], semantics: MatchSemantics) -> Vec<u64> {
        if query_terms.is_empty() {
            return Vec::new();
        }
        match semantics {
            MatchSemantics::Or => self.query_or(query_terms),
            MatchSemantics::And => self.query_and(query_terms),
        }
    }

    /// The OR-of-terms union: every node in any term's posting list, ascending + de-duplicated.
    fn query_or(&self, query_terms: &[String]) -> Vec<u64> {
        let mut union: BTreeSet<u64> = BTreeSet::new();
        for term in query_terms {
            if let Some(list) = self.postings.get(term) {
                union.extend(list.iter().copied());
            }
        }
        union.into_iter().collect()
    }

    /// The AND-of-terms intersection: nodes present in **every** distinct query term's posting list.
    fn query_and(&self, query_terms: &[String]) -> Vec<u64> {
        // Distinct terms only — a repeated query term does not tighten the intersection.
        let mut distinct: BTreeSet<&String> = BTreeSet::new();
        for t in query_terms {
            distinct.insert(t);
        }
        // If any distinct term is absent the intersection is empty.
        let mut lists: Vec<&Vec<u64>> = Vec::with_capacity(distinct.len());
        for term in &distinct {
            match self.postings.get(*term) {
                Some(list) => lists.push(list),
                None => return Vec::new(),
            }
        }
        // Intersect the shortest list against the rest (each posting list is sorted ascending and
        // de-duplicated — see `index_document`). PERF/I1: instead of cloning the shortest list and
        // `retain`-ing it (a full allocation + N×(K-1) binary searches even for ids that drop out
        // early), gallop each candidate id through the *remaining* lists, keeping it only if every
        // list contains it. Galloping search amortises to the classic sorted-set intersection cost
        // and never materialises the discarded ids. Output is the same ascending, de-duplicated set.
        lists.sort_by_key(|l| l.len());
        let (shortest, rest) = lists.split_first().expect("query_and: lists is non-empty");
        let mut acc: Vec<u64> = Vec::new();
        // A per-list cursor: because `shortest` is ascending, the search position in every other
        // (also ascending) list only moves forward, so galloping starts from where the last id left
        // off — giving the two-pointer behaviour across the whole scan.
        let mut cursors = vec![0usize; rest.len()];
        'candidate: for &id in shortest.iter() {
            for (list, cursor) in rest.iter().zip(cursors.iter_mut()) {
                *cursor = gallop_to(list, *cursor, id);
                if list.get(*cursor) != Some(&id) {
                    continue 'candidate;
                }
            }
            acc.push(id);
        }
        acc
    }

    /// A **best-effort relevance score** for `node` against `query_terms`: the number of distinct
    /// query terms the node contains (its term-overlap count). Documented as best-effort — it is a
    /// simple overlap count, not a TF-IDF / BM25 relevance score; it orders an OR query so that a
    /// node matching more of the query ranks above one matching fewer. Returns `0` for a node not in
    /// the index (the caller never asks for such a node on the happy path).
    #[must_use]
    pub fn score(&self, node: u64, query_terms: &[String]) -> u64 {
        let Some(doc_terms) = self.forward.get(&node) else {
            return 0;
        };
        let mut seen: BTreeSet<&String> = BTreeSet::new();
        let mut score = 0u64;
        for term in query_terms {
            // Count each distinct query term at most once, and only if the document has it.
            if seen.insert(term) && doc_terms.contains(term) {
                score += 1;
            }
        }
        score
    }
}

/// Galloping (exponential) search: returns the smallest index `>= from` in the ascending,
/// de-duplicated slice `list` whose element is `>= target`, or `list.len()` if none.
///
/// Probes `from`, `from+1`, `from+3`, `from+7`, … (doubling the step) until it overshoots `target`,
/// then binary-searches the bracketed window. Starting from a moving `from` cursor gives the
/// two-pointer behaviour [`InvertedIndex::query_and`] relies on: across a scan of ascending targets,
/// the total work is the standard sorted-set intersection cost, not O(n log n) independent searches.
fn gallop_to(list: &[u64], from: usize, target: u64) -> usize {
    let n = list.len();
    if from >= n {
        return n;
    }
    if list[from] >= target {
        return from;
    }
    // Exponentially expand a window [lo, hi] that brackets the first element >= target.
    let mut step = 1usize;
    let mut lo = from;
    let mut hi = from + step;
    while hi < n && list[hi] < target {
        lo = hi;
        step *= 2;
        hi = from + step;
    }
    let hi = hi.min(n);
    // Binary search the bracket [lo+1, hi): everything <= lo is < target by construction.
    lo + 1 + list[lo + 1..hi].partition_point(|&x| x < target)
}

/// The boolean combination of query terms for a full-text [`InvertedIndex::query`] (`rmp` task #72).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MatchSemantics {
    /// Match a node containing **at least one** query term (the documented default).
    #[default]
    Or,
    /// Match a node containing **every** query term.
    And,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----------------------------------------------------------------------------------------
    // Analyzer
    // ----------------------------------------------------------------------------------------

    #[test]
    fn stop_word_list_is_sorted_for_binary_search() {
        // The binary search in `is_standard_stop_word` is only sound if the slice is sorted.
        let mut sorted = STANDARD_STOP_WORDS.to_vec();
        sorted.sort_unstable();
        assert_eq!(
            sorted, STANDARD_STOP_WORDS,
            "STANDARD_STOP_WORDS must be sorted"
        );
    }

    #[test]
    fn standard_tokenizes_lowercases_and_drops_stop_words() {
        let terms = Analyzer::Standard.analyze("The Quick, brown FOX jumps over the lazy dog");
        // "the" (x2) is a stop word and removed; everything else lowercased; "over" is NOT a stop word.
        assert_eq!(
            terms,
            vec!["quick", "brown", "fox", "jumps", "over", "lazy", "dog"]
        );
    }

    #[test]
    fn standard_splits_on_punctuation_and_symbols() {
        // Non-alphanumeric chars (including '_', '-', '.', '@', ',') are separators; only maximal
        // runs of `char::is_alphanumeric` are tokens.
        let terms = Analyzer::Standard.analyze("foo-bar_baz.qux@example,com 42");
        assert_eq!(
            terms,
            vec!["foo", "bar", "baz", "qux", "example", "com", "42"]
        );
    }

    #[test]
    fn underscore_is_a_separator_not_a_word_char() {
        // Unlike the admin lexer, the *full-text* analyzer splits on '_' (it is not alphanumeric).
        let terms = Analyzer::Standard.analyze("hello_world");
        assert_eq!(terms, vec!["hello", "world"]);
    }

    #[test]
    fn standard_is_unicode_aware() {
        // Accented letters are alphanumeric and survive; the apostrophe and hyphen split.
        let terms = Analyzer::Standard.analyze("L'été 2024 — Café");
        assert_eq!(terms, vec!["l", "été", "2024", "café"]);
    }

    #[test]
    fn standard_handles_cjk_alphanumeric() {
        // CJK characters are alphanumeric (Unicode), so a run of them is one token; lowercasing is a
        // no-op for scripts without case.
        let terms = Analyzer::Standard.analyze("日本語 text");
        assert_eq!(terms, vec!["日本語", "text"]);
    }

    #[test]
    fn standard_empty_and_only_stop_words_yield_nothing() {
        assert!(Analyzer::Standard.analyze("").is_empty());
        assert!(Analyzer::Standard.analyze("   ,. ; ").is_empty());
        assert!(Analyzer::Standard.analyze("the and of to").is_empty());
    }

    #[test]
    fn oversized_tokens_are_capped_to_max_term_len() {
        // Regression for auditor finding #4: an untrusted multi-megabyte alphanumeric run must not
        // amplify into one giant term. Both analyzers cap a term at MAX_TERM_LEN bytes.
        let giant = "a".repeat(4 * 1024 * 1024); // 4 MiB single run

        // Standard: the run is one (capped) token; it stays within the byte cap.
        let standard = Analyzer::Standard.analyze(&giant);
        assert_eq!(standard.len(), 1, "the run is a single token");
        assert!(
            standard[0].len() <= MAX_TERM_LEN,
            "standard term must be capped to MAX_TERM_LEN, got {}",
            standard[0].len(),
        );

        // Keyword: the whole field is one (capped) term.
        let keyword = Analyzer::Keyword.analyze(&giant);
        assert_eq!(keyword.len(), 1);
        assert!(
            keyword[0].len() <= MAX_TERM_LEN,
            "keyword term must be capped to MAX_TERM_LEN, got {}",
            keyword[0].len(),
        );

        // A run mixed with separators still caps each token and keeps the surrounding tokens.
        let mixed = format!("head {giant} tail");
        let terms = Analyzer::Standard.analyze(&mixed);
        assert_eq!(terms.len(), 3, "head + capped giant + tail");
        assert_eq!(terms[0], "head");
        assert!(terms[1].len() <= MAX_TERM_LEN);
        assert_eq!(terms[2], "tail");
    }

    #[test]
    fn truncation_never_splits_a_multibyte_char() {
        // A run of multi-byte chars must truncate on a char boundary, yielding a valid String no
        // longer than MAX_TERM_LEN. 'é' is 2 bytes; MAX_TERM_LEN is even, but the guard must hold
        // regardless — assert the result is valid UTF-8 within the cap.
        let run = "é".repeat(4096); // 8 KiB of 2-byte chars
        let terms = Analyzer::Standard.analyze(&run);
        assert_eq!(terms.len(), 1);
        assert!(terms[0].len() <= MAX_TERM_LEN);
        // Must be a clean prefix of 'é' chars (no replacement char / no panic when constructed).
        assert!(terms[0].chars().all(|c| c == 'é'));
    }

    #[test]
    fn keyword_is_a_single_lowercased_term() {
        assert_eq!(
            Analyzer::Keyword.analyze("Hello, World!"),
            vec!["hello, world!"]
        );
        assert_eq!(Analyzer::Keyword.analyze("  Trimmed  "), vec!["trimmed"]);
        assert!(Analyzer::Keyword.analyze("   ").is_empty());
    }

    #[test]
    fn same_analyzer_at_index_and_query_time_matches() {
        // The load-bearing invariant: a term indexed and a term queried through the SAME analyzer
        // produce the SAME normalized form, so they match.
        let a = Analyzer::Standard;
        let indexed = a.analyze("Graph Databases Are GREAT");
        let queried = a.analyze("databases");
        assert!(queried.iter().all(|q| indexed.contains(q)));
    }

    #[test]
    fn analyzer_byte_and_name_round_trip() {
        for a in [Analyzer::Standard, Analyzer::Keyword] {
            assert_eq!(Analyzer::from_byte(a.as_byte()), Some(a));
            assert_eq!(Analyzer::from_name(a.name()), Some(a));
            assert_eq!(Analyzer::from_name(&a.name().to_uppercase()), Some(a));
        }
        assert_eq!(Analyzer::from_byte(99), None);
        assert_eq!(Analyzer::from_name("nope"), None);
        assert_eq!(Analyzer::default(), Analyzer::Standard);
    }

    // ----------------------------------------------------------------------------------------
    // InvertedIndex
    // ----------------------------------------------------------------------------------------

    fn t(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_owned()).collect()
    }

    #[test]
    fn insert_and_query_or_returns_union_ascending() {
        let mut idx = InvertedIndex::new();
        idx.index_document(10, &t(&["graph", "database"]));
        idx.index_document(20, &t(&["graph", "theory"]));
        idx.index_document(30, &t(&["relational", "database"]));

        // OR: nodes containing "graph" OR "database" -> 10, 20, 30 (10&20 by graph, 10&30 by database).
        let mut got = idx.query(&t(&["graph", "database"]), MatchSemantics::Or);
        got.sort_unstable();
        assert_eq!(got, vec![10, 20, 30]);

        // Single-term query.
        assert_eq!(idx.query(&t(&["theory"]), MatchSemantics::Or), vec![20]);
        // A term no document has -> empty.
        assert_eq!(
            idx.query(&t(&["nonexistent"]), MatchSemantics::Or),
            Vec::<u64>::new()
        );
    }

    #[test]
    fn query_and_returns_intersection() {
        let mut idx = InvertedIndex::new();
        idx.index_document(10, &t(&["graph", "database", "fast"]));
        idx.index_document(20, &t(&["graph", "database"]));
        idx.index_document(30, &t(&["graph"]));

        // AND graph+database -> 10, 20 (30 lacks "database").
        let mut got = idx.query(&t(&["graph", "database"]), MatchSemantics::And);
        got.sort_unstable();
        assert_eq!(got, vec![10, 20]);

        // AND graph+database+fast -> only 10.
        assert_eq!(
            idx.query(&t(&["graph", "database", "fast"]), MatchSemantics::And),
            vec![10]
        );

        // AND with an absent term -> empty.
        assert_eq!(
            idx.query(&t(&["graph", "missing"]), MatchSemantics::And),
            Vec::<u64>::new()
        );
    }

    #[test]
    fn empty_query_matches_nothing() {
        let mut idx = InvertedIndex::new();
        idx.index_document(1, &t(&["x"]));
        assert!(idx.query(&[], MatchSemantics::Or).is_empty());
        assert!(idx.query(&[], MatchSemantics::And).is_empty());
    }

    #[test]
    fn delete_document_removes_from_all_posting_lists() {
        let mut idx = InvertedIndex::new();
        idx.index_document(10, &t(&["graph", "database"]));
        idx.index_document(20, &t(&["graph"]));
        assert_eq!(idx.document_count(), 2);

        assert!(idx.remove_document(10));
        // 10 gone from both "graph" and "database"; "database" list now empty and dropped.
        assert_eq!(idx.query(&t(&["graph"]), MatchSemantics::Or), vec![20]);
        assert!(idx.query(&t(&["database"]), MatchSemantics::Or).is_empty());
        assert_eq!(idx.document_count(), 1);

        // Idempotent: removing again is a harmless no-op.
        assert!(!idx.remove_document(10));
    }

    #[test]
    fn reindex_replaces_terms_wholesale() {
        let mut idx = InvertedIndex::new();
        idx.index_document(10, &t(&["graph", "database"]));
        // Update: the node's text changed; it no longer mentions "database".
        idx.index_document(10, &t(&["graph", "theory"]));

        assert_eq!(idx.query(&t(&["graph"]), MatchSemantics::Or), vec![10]);
        assert_eq!(idx.query(&t(&["theory"]), MatchSemantics::Or), vec![10]);
        // The stale "database" term must be gone.
        assert!(idx.query(&t(&["database"]), MatchSemantics::Or).is_empty());
        assert_eq!(idx.document_count(), 1);
    }

    #[test]
    fn reindex_to_empty_removes_the_document() {
        let mut idx = InvertedIndex::new();
        idx.index_document(10, &t(&["graph"]));
        idx.index_document(10, &[]); // text became empty
        assert!(idx.query(&t(&["graph"]), MatchSemantics::Or).is_empty());
        assert!(idx.is_empty());
    }

    #[test]
    fn duplicate_terms_in_one_document_appear_once_in_postings() {
        let mut idx = InvertedIndex::new();
        idx.index_document(10, &t(&["graph", "graph", "graph"]));
        // The posting list for "graph" holds 10 exactly once.
        assert_eq!(idx.query(&t(&["graph"]), MatchSemantics::Or), vec![10]);
        assert_eq!(idx.term_count(), 1);
    }

    #[test]
    fn score_is_distinct_term_overlap_count() {
        let mut idx = InvertedIndex::new();
        idx.index_document(10, &t(&["graph", "database", "fast"]));
        // Overlap with {graph, database, slow} = 2 (graph, database).
        assert_eq!(idx.score(10, &t(&["graph", "database", "slow"])), 2);
        // A repeated query term counts once.
        assert_eq!(idx.score(10, &t(&["graph", "graph"])), 1);
        // All three present.
        assert_eq!(idx.score(10, &t(&["graph", "database", "fast"])), 3);
        // An unknown node scores 0.
        assert_eq!(idx.score(999, &t(&["graph"])), 0);
    }

    #[test]
    fn clear_empties_the_index() {
        let mut idx = InvertedIndex::new();
        idx.index_document(10, &t(&["a", "b"]));
        idx.index_document(20, &t(&["c"]));
        idx.clear();
        assert!(idx.is_empty());
        assert_eq!(idx.term_count(), 0);
        assert!(idx.query(&t(&["a"]), MatchSemantics::Or).is_empty());
    }
}
