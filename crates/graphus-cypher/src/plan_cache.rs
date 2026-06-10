//! The Cypher **plan cache** and the **literal auto-parameterisation** normalisation it relies on
//! (`04-technical-design.md` §7.5).
//!
//! `04 §7.5` is precise about the contract this module implements:
//!
//! > *"Plan cache keyed by `(normalized_query_text, schema_version, feature_flags)`; value is the
//! > compiled physical plan. Capacity-bounded (LRU), invalidated on DDL/index/constraint change
//! > (schema_version bump). Literal auto-parameterization (replacing inline literals with
//! > parameters) is applied during normalization so structurally identical queries share a plan — a
//! > TCK-safe transformation (it must not change observable semantics). Parameters bind at
//! > execution, never at compile, so the cache is parameter-independent."*
//!
//! # The three pieces
//!
//! - [`normalize_query`] performs **literal auto-parameterisation**: it rewrites the source so each
//!   inline **scalar** literal is replaced with a generated auto-parameter placeholder, yielding a
//!   [`NormalizedQuery`] holding the canonical key text *and* the lifted auto-parameter values. Two
//!   queries that differ only in their scalar literals normalise to the **same** key text (so they
//!   share one compiled plan) while their distinct literal values travel in the auto-parameter
//!   sidecar — which binds at execution exactly like a user `$param` ([`crate::binding`]).
//! - [`PlanCacheKey`] is the `(normalized_query_text, schema_version, feature_flags)` triple,
//!   verbatim from `04 §7.5`. **Parameters are deliberately absent** — the plan is
//!   parameter-independent, so one cached plan serves every parameter set.
//! - [`PlanCache`] is the capacity-bounded **LRU** store. A [`SchemaVersion`] bump (issued by the
//!   schema/index/constraint layer on any DDL change, `04 §6.6`/§7.5) changes the key, so stale
//!   plans are never reused; [`PlanCache::invalidate_schema_change`] additionally evicts the now-dead
//!   entries eagerly.
//!
//! # Why auto-parameterisation is TCK-safe (the soundness argument)
//!
//! The transformation lifts a scalar literal `L` out of the query text and re-supplies its **exact
//! value** as an auto-parameter at bind time. A Cypher scalar parameter and the scalar literal it
//! replaces evaluate to the identical [`Value`](graphus_core::Value): there is no Cypher operator
//! that can observe *whether* a scalar came from a literal or a parameter (the value model is the
//! same `Value`, `04 §7.2`). The lift is therefore **observably identity-preserving** — it changes
//! only *which plan-cache bucket* the query lands in, never the rows produced. A golden test pins
//! this (`tests/plan_cache.rs`).
//!
//! What is **deliberately not** auto-parameterised, to keep the transformation obviously sound:
//!
//! - **`null`** — kept inline. `null` participates in three-valued logic (`04 §7.6`) and planners
//!   may legitimately treat a static `IS NULL` / `= null` specially; not lifting it removes any
//!   doubt about the equivalence (named deferral).
//! - **List and map literals** — kept inline. They are *structural* (their shape can drive plan
//!   structure, e.g. an `IN [literal-list]` membership); lifting only the scalars *inside* them is
//!   Phase-2 territory (named deferral).
//! - **The variable-length range bounds, `SKIP`/`LIMIT` integer positions** — these are lifted like
//!   any other scalar literal here (they are ordinary integer literals in the AST), which is sound:
//!   their value binds at execution just as a `$param` in that position would.

use std::collections::HashMap;
use std::collections::VecDeque;

use graphus_core::Value;

use crate::ast::{
    CaseExpr, Clause, Expr, ExprKind, Literal, PatternComprehension, PatternElement,
    ProjectionBody, Query, QueryBody, SetItem, SingleQuery, StandaloneCall, StandaloneYield,
};
use crate::lexer::Span;

/// A monotone **schema version**. The schema/index/constraint layer bumps this on any DDL change
/// (index or constraint create/drop), and it is part of the [`PlanCacheKey`] so a plan compiled
/// against an older schema is never reused (`04 §6.6`/§7.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct SchemaVersion(pub u64);

impl SchemaVersion {
    /// The version a fresh, empty database starts at.
    pub const INITIAL: Self = Self(0);

    /// The next version (the value a DDL change bumps to).
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

/// The set of compile-affecting **feature flags** in force when a plan is compiled (`04 §7.5`,
/// part of the cache key).
///
/// `04 §7` notes the engine *"feature-flag[s] the newest constructs"* of the pinned Cypher line;
/// two plans compiled under different flag sets are not interchangeable, so the flags are part of
/// the key. The set is modelled as a sorted, de-duplicated list of flag names so the key text is
/// deterministic regardless of insertion order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[must_use]
pub struct FeatureFlags {
    /// Enabled flag names, kept sorted and unique for a deterministic key.
    flags: Vec<String>,
}

impl FeatureFlags {
    /// An empty flag set (the default).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Builds a flag set from an iterator of flag names (sorted and de-duplicated).
    pub fn from_iter_names<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut flags: Vec<String> = names.into_iter().map(Into::into).collect();
        flags.sort_unstable();
        flags.dedup();
        Self { flags }
    }

    /// Whether `flag` is enabled.
    #[must_use]
    pub fn contains(&self, flag: &str) -> bool {
        self.flags
            .binary_search_by(|f| f.as_str().cmp(flag))
            .is_ok()
    }

    /// The deterministic key fragment: flag names joined by `,`.
    fn key_fragment(&self) -> String {
        self.flags.join(",")
    }
}

/// A query after **literal auto-parameterisation** (`04 §7.5`).
///
/// Holds the canonical [`key_text`](Self::key_text) (literal-free, the cache-key component) and the
/// [`auto_params`](Self::auto_params) lifted out of the source, each a `(name, value)` pair that
/// binds at execution like a user parameter ([`crate::binding`]). The auto-parameter names use a
/// reserved `  AUTO_` prefix (two leading spaces) that the lexer can never produce as a user
/// parameter name, so an auto-parameter can never collide with a user `$param`.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct NormalizedQuery {
    key_text: String,
    auto_params: Vec<(String, Value)>,
}

impl NormalizedQuery {
    /// The canonical, literal-free query text — the `normalized_query_text` component of the
    /// [`PlanCacheKey`] (`04 §7.5`).
    #[must_use]
    pub fn key_text(&self) -> &str {
        &self.key_text
    }

    /// The auto-parameters lifted from the source, in source order: `(name, value)` pairs that bind
    /// at execution exactly like user parameters (`04 §7.5`).
    #[must_use]
    pub fn auto_params(&self) -> &[(String, Value)] {
        &self.auto_params
    }
}

/// The reserved prefix for an auto-parameter name (two leading spaces — the lexer never produces a
/// parameter name beginning with a space, so this can never collide with a user `$param`).
pub(crate) const AUTO_PARAM_PREFIX: &str = "  AUTO_";

/// Builds the `n`-th auto-parameter name.
fn auto_param_name(seq: usize) -> String {
    format!("{AUTO_PARAM_PREFIX}{seq}")
}

/// Performs **literal auto-parameterisation** on `src` guided by its parsed [`Query`]
/// (`04 §7.5`).
///
/// Walks the AST collecting every **scalar** literal (`Integer`/`Float`/`String`/`Boolean`) site —
/// its byte [`Span`] and decoded [`Value`] — then rewrites `src` so each such site becomes an
/// auto-parameter placeholder `$  AUTO_n`, canonicalising inter-token whitespace to single spaces.
/// The result is a [`NormalizedQuery`] whose [`key_text`](NormalizedQuery::key_text) is identical for
/// queries differing only in scalar-literal values, and whose
/// [`auto_params`](NormalizedQuery::auto_params) carry those values for binding at execution.
///
/// `null`, list literals, and map literals are intentionally **kept inline** (see the module docs
/// for the soundness rationale).
///
/// # Panics
///
/// Never panics: literal spans come from the parser and always lie within `src` on a char boundary
/// (the spans the lexer assigns are byte-accurate token ranges). The slicing is therefore always
/// valid; a defensive guard skips any span that is somehow out of range rather than panicking.
pub fn normalize_query(src: &str, query: &Query) -> NormalizedQuery {
    let mut sites: Vec<LiteralSite> = Vec::new();
    collect_query_literals(query, &mut sites);
    // Sort by start so the rewrite is a single left-to-right pass; de-duplicate identical spans
    // (a literal is visited once, but guard against accidental double-collection).
    sites.sort_by_key(|s| (s.span.start, s.span.end));
    sites.dedup_by_key(|s| (s.span.start, s.span.end));

    let mut key_raw = String::with_capacity(src.len());
    let mut auto_params: Vec<(String, Value)> = Vec::with_capacity(sites.len());
    let mut cursor = 0usize;
    for (seq, site) in sites.iter().enumerate() {
        // Guard: only rewrite a well-formed, in-range, non-overlapping span.
        if site.span.start < cursor || site.span.end > src.len() || site.span.start > site.span.end
        {
            continue;
        }
        key_raw.push_str(&src[cursor..site.span.start]);
        let name = auto_param_name(seq);
        // Emit the placeholder using the on-the-wire `$name` spelling so the normalised text is
        // itself a syntactically faithful Cypher fragment (the reserved space-prefixed name never
        // round-trips through the lexer, but the key is only ever compared as a string).
        key_raw.push('$');
        key_raw.push_str(&name);
        auto_params.push((name, site.value.clone()));
        cursor = site.span.end;
    }
    key_raw.push_str(&src[cursor..]);

    NormalizedQuery {
        key_text: canonicalize_whitespace(&key_raw),
        auto_params,
    }
}

/// Collapses every run of ASCII/Unicode whitespace to a single space and trims the ends, so two
/// queries differing only in spacing or layout normalise to the same key text.
///
/// This is a conservative canonicalisation: it touches **only** whitespace *between* tokens. Because
/// scalar literals (the one place whitespace could be significant inside a token — a quoted string)
/// have already been lifted to placeholders before this runs, collapsing whitespace can never alter
/// a surviving token's meaning.
fn canonicalize_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_was_space = false;
    for ch in s.chars() {
        if ch.is_whitespace() {
            if !last_was_space {
                out.push(' ');
                last_was_space = true;
            }
        } else {
            out.push(ch);
            last_was_space = false;
        }
    }
    out.trim().to_owned()
}

/// One auto-parameterisable scalar-literal site in the source.
struct LiteralSite {
    span: Span,
    value: Value,
}

/// Decodes a scalar [`Literal`] to its [`Value`], or `None` for a literal kept inline (`Null`) or
/// out of range (an integer that overflows `i64` — left inline so the parser/executor surfaces the
/// range error rather than the cache silently lifting a bad value).
fn scalar_literal_value(lit: &Literal) -> Option<Value> {
    match lit {
        Literal::Integer(int) => {
            // The magnitude is already decoded (held as a `u128`, base-independent). Only lift it if
            // it fits `i64` (the Cypher integer range); an out-of-range literal is left inline so its
            // handling (the parser/executor range check) is unchanged.
            i64::try_from(int.value).ok().map(Value::Integer)
        }
        Literal::Float(x) => Some(Value::Float(*x)),
        Literal::String(s) => Some(Value::String(s.clone())),
        Literal::Boolean(b) => Some(Value::Boolean(*b)),
        Literal::Null => None,
    }
}

// =================================================================================================
// AST literal collection
// =================================================================================================

fn collect_query_literals(query: &Query, out: &mut Vec<LiteralSite>) {
    match &query.body {
        QueryBody::Regular { head, unions } => {
            collect_single_query_literals(head, out);
            for part in unions {
                collect_single_query_literals(&part.query, out);
            }
        }
        QueryBody::StandaloneCall(call) => collect_standalone_call_literals(call, out),
    }
}

fn collect_single_query_literals(sq: &SingleQuery, out: &mut Vec<LiteralSite>) {
    for clause in &sq.clauses {
        collect_clause_literals(clause, out);
    }
}

fn collect_clause_literals(clause: &Clause, out: &mut Vec<LiteralSite>) {
    match clause {
        Clause::Match(m) => {
            collect_pattern_parts_literals(&m.pattern, out);
            if let Some(w) = &m.where_clause {
                collect_expr_literals(w, out);
            }
        }
        Clause::Unwind(u) => collect_expr_literals(&u.expr, out),
        Clause::LoadCsv(l) => collect_expr_literals(&l.url, out),
        Clause::Call(c) => {
            if let Some(args) = &c.call.args {
                for a in args {
                    collect_expr_literals(a, out);
                }
            }
            if let Some(w) = &c.where_clause {
                collect_expr_literals(w, out);
            }
        }
        Clause::Create(c) => collect_pattern_parts_literals(&c.pattern, out),
        Clause::Merge(m) => {
            collect_pattern_element_literals(&m.pattern.element, out);
            for action in &m.actions {
                match action {
                    crate::ast::MergeAction::OnCreate(items)
                    | crate::ast::MergeAction::OnMatch(items) => {
                        for item in items {
                            collect_set_item_literals(item, out);
                        }
                    }
                }
            }
        }
        Clause::Set(s) => {
            for item in &s.items {
                collect_set_item_literals(item, out);
            }
        }
        Clause::Delete(d) => {
            for e in &d.exprs {
                collect_expr_literals(e, out);
            }
        }
        Clause::Remove(r) => {
            for item in &r.items {
                if let crate::ast::RemoveItem::Property(e) = item {
                    collect_expr_literals(e, out);
                }
            }
        }
        Clause::With(w) => {
            collect_projection_body_literals(&w.body, out);
            if let Some(p) = &w.where_clause {
                collect_expr_literals(p, out);
            }
        }
        Clause::Return(r) => collect_projection_body_literals(&r.body, out),
    }
}

fn collect_standalone_call_literals(call: &StandaloneCall, out: &mut Vec<LiteralSite>) {
    if let Some(args) = &call.call.args {
        for a in args {
            collect_expr_literals(a, out);
        }
    }
    if let Some(StandaloneYield::Items {
        where_clause: Some(w),
        ..
    }) = &call.yield_clause
    {
        collect_expr_literals(w, out);
    }
}

fn collect_set_item_literals(item: &SetItem, out: &mut Vec<LiteralSite>) {
    match item {
        SetItem::Property { target, value } => {
            collect_expr_literals(target, out);
            collect_expr_literals(value, out);
        }
        SetItem::Replace { value, .. } | SetItem::Merge { value, .. } => {
            collect_expr_literals(value, out);
        }
        SetItem::Labels { .. } => {}
    }
}

fn collect_projection_body_literals(body: &ProjectionBody, out: &mut Vec<LiteralSite>) {
    for item in &body.items {
        collect_expr_literals(&item.expr, out);
    }
    for sort in &body.order_by {
        collect_expr_literals(&sort.expr, out);
    }
    if let Some(skip) = &body.skip {
        collect_expr_literals(skip, out);
    }
    if let Some(limit) = &body.limit {
        collect_expr_literals(limit, out);
    }
}

fn collect_pattern_parts_literals(parts: &[crate::ast::PatternPart], out: &mut Vec<LiteralSite>) {
    for part in parts {
        collect_pattern_element_literals(&part.element, out);
    }
}

fn collect_pattern_element_literals(element: &PatternElement, out: &mut Vec<LiteralSite>) {
    if let Some(props) = &element.start.properties {
        collect_expr_literals(props, out);
    }
    for link in &element.chain {
        if let Some(props) = &link.relationship.properties {
            collect_expr_literals(props, out);
        }
        if let Some(props) = &link.node.properties {
            collect_expr_literals(props, out);
        }
    }
}

/// Collects scalar-literal sites from an expression tree.
///
/// A scalar [`Literal`] (`Integer`/`Float`/`String`/`Boolean`) records its [`Span`] and [`Value`].
/// List and map literals are **not** lifted as a whole (they are structural), and crucially this
/// walker does **not** descend into a list/map literal to lift the scalars *inside* it (that would
/// risk changing the structural shape that a plan may key on, e.g. `x IN [1, 2, 3]`); descending
/// into non-literal compound expressions (binary, function args, …) is fine and intended.
fn collect_expr_literals(expr: &Expr, out: &mut Vec<LiteralSite>) {
    match &expr.kind {
        ExprKind::Literal(lit) => {
            if let Some(value) = scalar_literal_value(lit) {
                out.push(LiteralSite {
                    span: expr.span,
                    value,
                });
            }
        }
        ExprKind::Parameter(_) | ExprKind::Variable(_) | ExprKind::CountStar => {}
        ExprKind::Binary { lhs, rhs, .. } => {
            collect_expr_literals(lhs, out);
            collect_expr_literals(rhs, out);
        }
        ExprKind::Unary { operand, .. } | ExprKind::HasLabels { operand, .. } => {
            collect_expr_literals(operand, out);
        }
        ExprKind::Predicate { operand, rhs, .. } => {
            collect_expr_literals(operand, out);
            if let Some(r) = rhs {
                collect_expr_literals(r, out);
            }
        }
        ExprKind::Property { base, .. } => collect_expr_literals(base, out),
        ExprKind::Index { base, index } => {
            collect_expr_literals(base, out);
            collect_expr_literals(index, out);
        }
        ExprKind::Slice { base, low, high } => {
            collect_expr_literals(base, out);
            if let Some(l) = low {
                collect_expr_literals(l, out);
            }
            if let Some(h) = high {
                collect_expr_literals(h, out);
            }
        }
        ExprKind::FunctionCall { args, .. } => {
            for a in args {
                collect_expr_literals(a, out);
            }
        }
        // List/map literals are kept inline (structural); do NOT descend to lift inner scalars.
        ExprKind::List(_) | ExprKind::Map(_) => {}
        ExprKind::Case(case) => collect_case_literals(case, out),
        ExprKind::ListComprehension(lc) => {
            collect_expr_literals(&lc.list, out);
            if let Some(p) = &lc.predicate {
                collect_expr_literals(p, out);
            }
            if let Some(proj) = &lc.projection {
                collect_expr_literals(proj, out);
            }
        }
        ExprKind::PatternComprehension(pc) => collect_pattern_comprehension_literals(pc, out),
    }
}

fn collect_case_literals(case: &CaseExpr, out: &mut Vec<LiteralSite>) {
    if let Some(subject) = &case.subject {
        collect_expr_literals(subject, out);
    }
    for alt in &case.alternatives {
        collect_expr_literals(&alt.when, out);
        collect_expr_literals(&alt.then, out);
    }
    if let Some(else_expr) = &case.else_expr {
        collect_expr_literals(else_expr, out);
    }
}

fn collect_pattern_comprehension_literals(pc: &PatternComprehension, out: &mut Vec<LiteralSite>) {
    collect_pattern_element_literals(&pc.element, out);
    if let Some(p) = &pc.predicate {
        collect_expr_literals(p, out);
    }
    collect_expr_literals(&pc.projection, out);
}

// =================================================================================================
// Plan cache
// =================================================================================================

/// The plan-cache key: `(normalized_query_text, schema_version, feature_flags)` (`04 §7.5`,
/// verbatim).
///
/// **Parameters are intentionally not part of the key** — the compiled plan is parameter-independent
/// (`04 §7.5`), so one cached plan serves every parameter set. The `normalized_query_text` is a
/// [`NormalizedQuery::key_text`] (literals already auto-parameterised away), so queries differing
/// only in scalar literals collapse to one key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub struct PlanCacheKey {
    /// The literal-free normalised query text.
    pub normalized_query_text: String,
    /// The schema version the plan was (or will be) compiled against.
    pub schema_version: SchemaVersion,
    /// The compile-affecting feature flags in force.
    pub feature_flags: FeatureFlags,
}

impl PlanCacheKey {
    /// Builds a key from a [`NormalizedQuery`] and the current schema/flag context.
    pub fn new(
        normalized: &NormalizedQuery,
        schema_version: SchemaVersion,
        feature_flags: FeatureFlags,
    ) -> Self {
        Self {
            normalized_query_text: normalized.key_text().to_owned(),
            schema_version,
            feature_flags,
        }
    }

    /// A stable string rendering of the full key (diagnostics / logging).
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "{}@v{}[{}]",
            self.normalized_query_text,
            self.schema_version.0,
            self.feature_flags.key_fragment(),
        )
    }
}

/// A capacity-bounded, **LRU** plan cache (`04 §7.5`).
///
/// Maps a [`PlanCacheKey`] to a compiled `V` (the physical plan,
/// [`PhysicalPlan`](crate::physical::PhysicalPlan); generic here so the cache has no opinion on the
/// plan representation and stays trivially testable). On a [`get`](Self::get) hit the key is
/// promoted to most-recently-used; on an [`insert`](Self::insert) past capacity the least-recently
/// -used entry is evicted.
///
/// Invalidation on a schema/index/constraint change is via the [`SchemaVersion`] in the key (a bump
/// changes every key, so old plans are unreachable) plus [`invalidate_schema_change`](Self::invalidate_schema_change)
/// for eager eviction (`04 §6.6`/§7.5).
///
/// This is a **single-threaded** structure (the query layer compiles per session); a sharded /
/// lock-wrapped concurrent wrapper is a later concern, kept out of v1 to avoid premature
/// synchronisation (named deferral).
#[derive(Debug)]
#[must_use]
pub struct PlanCache<V> {
    capacity: usize,
    entries: HashMap<PlanCacheKey, V>,
    /// MRU at the back, LRU at the front. Holds exactly the keys present in `entries`.
    order: VecDeque<PlanCacheKey>,
    hits: u64,
    misses: u64,
}

impl<V> PlanCache<V> {
    /// Creates an LRU cache holding at most `capacity` plans.
    ///
    /// # Panics
    ///
    /// Panics if `capacity == 0`: a zero-capacity cache could never serve a hit and almost always
    /// indicates a configuration error.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "plan cache capacity must be non-zero");
        Self {
            capacity,
            entries: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            hits: 0,
            misses: 0,
        }
    }

    /// The configured capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The number of cached plans.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache holds no plans.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Cumulative hit / miss counts since creation (observability — `04` NFR-10 spirit).
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits,
            misses: self.misses,
            len: self.entries.len(),
            capacity: self.capacity,
        }
    }

    /// Looks up the plan for `key`, promoting it to most-recently-used on a hit.
    ///
    /// Returns `None` (and counts a miss) when absent; the caller then compiles and
    /// [`insert`](Self::insert)s.
    pub fn get(&mut self, key: &PlanCacheKey) -> Option<&V> {
        if self.entries.contains_key(key) {
            self.promote(key);
            self.hits += 1;
            self.entries.get(key)
        } else {
            self.misses += 1;
            None
        }
    }

    /// Whether `key` is cached, **without** affecting LRU order or hit/miss stats (test/inspection
    /// aid).
    #[must_use]
    pub fn contains(&self, key: &PlanCacheKey) -> bool {
        self.entries.contains_key(key)
    }

    /// Inserts (or replaces) the plan for `key`, evicting the least-recently-used entry if the
    /// cache is at capacity. The inserted key becomes most-recently-used.
    pub fn insert(&mut self, key: PlanCacheKey, value: V) {
        if self.entries.contains_key(&key) {
            // Replace in place and promote.
            self.entries.insert(key.clone(), value);
            self.promote(&key);
            return;
        }
        if self.entries.len() >= self.capacity {
            self.evict_lru();
        }
        self.order.push_back(key.clone());
        self.entries.insert(key, value);
    }

    /// Evicts every plan compiled against a schema version **older** than `current`, the eager half
    /// of schema-change invalidation (`04 §6.6`/§7.5). Returns the number of plans evicted.
    ///
    /// Plans at `current` or newer are retained. (A bump alone already makes older plans unreachable
    /// because the key changes; this reclaims their memory promptly.)
    pub fn invalidate_schema_change(&mut self, current: SchemaVersion) -> usize {
        let stale: Vec<PlanCacheKey> = self
            .entries
            .keys()
            .filter(|k| k.schema_version < current)
            .cloned()
            .collect();
        let n = stale.len();
        for key in stale {
            self.entries.remove(&key);
            self.order.retain(|k| k != &key);
        }
        n
    }

    /// Empties the cache (e.g. a full schema reload). Preserves the hit/miss counters.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    /// Moves `key` to the most-recently-used position.
    fn promote(&mut self, key: &PlanCacheKey) {
        if let Some(pos) = self.order.iter().position(|k| k == key) {
            if let Some(k) = self.order.remove(pos) {
                self.order.push_back(k);
            }
        }
    }

    /// Removes the least-recently-used entry.
    fn evict_lru(&mut self) {
        if let Some(lru) = self.order.pop_front() {
            self.entries.remove(&lru);
        }
    }
}

/// A snapshot of [`PlanCache`] counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct CacheStats {
    /// Cumulative cache hits.
    pub hits: u64,
    /// Cumulative cache misses.
    pub misses: u64,
    /// Current number of cached plans.
    pub len: usize,
    /// Configured capacity.
    pub capacity: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;

    fn normalized(src: &str) -> NormalizedQuery {
        let query = parse(src).expect("parses");
        normalize_query(src, &query)
    }

    #[test]
    fn auto_param_lifts_integer_literal() {
        let n = normalized("MATCH (n:Person) WHERE n.age = 30 RETURN n");
        assert!(
            !n.key_text().contains("30"),
            "literal lifted: {}",
            n.key_text()
        );
        assert_eq!(n.auto_params().len(), 1);
        assert_eq!(n.auto_params()[0].1, Value::Integer(30));
    }

    #[test]
    fn literal_only_variants_share_key_text() {
        let a = normalized("MATCH (n:Person) WHERE n.age = 30 RETURN n");
        let b = normalized("MATCH (n:Person) WHERE n.age = 41 RETURN n");
        assert_eq!(a.key_text(), b.key_text());
        assert_ne!(a.auto_params(), b.auto_params());
    }

    #[test]
    fn whitespace_is_canonicalised() {
        let a = normalized("MATCH (n) RETURN n");
        let b = normalized("MATCH    (n)\n  RETURN\tn");
        assert_eq!(a.key_text(), b.key_text());
    }

    #[test]
    fn null_is_not_lifted() {
        let n = normalized("MATCH (n) WHERE n.p IS NULL RETURN n");
        assert!(n.auto_params().is_empty());
        assert!(n.key_text().to_lowercase().contains("null"));
    }

    #[test]
    fn list_literal_is_kept_inline() {
        let n = normalized("MATCH (n) WHERE n.p IN [1, 2, 3] RETURN n");
        // The structural list (and its inner scalars) is NOT lifted.
        assert!(n.auto_params().is_empty(), "{:?}", n.auto_params());
        assert!(n.key_text().contains('['));
    }

    #[test]
    fn string_and_bool_literals_lift() {
        let n = normalized("MATCH (n) WHERE n.name = 'Ada' AND n.active = true RETURN n");
        assert_eq!(n.auto_params().len(), 2);
        assert_eq!(n.auto_params()[0].1, Value::String("Ada".to_owned()));
        assert_eq!(n.auto_params()[1].1, Value::Boolean(true));
    }

    #[test]
    fn feature_flags_are_order_independent() {
        let a = FeatureFlags::from_iter_names(["b", "a"]);
        let b = FeatureFlags::from_iter_names(["a", "b", "a"]);
        assert_eq!(a, b);
        assert!(a.contains("a") && a.contains("b") && !a.contains("c"));
    }

    fn key(src: &str, v: u64) -> PlanCacheKey {
        let n = normalized(src);
        PlanCacheKey::new(&n, SchemaVersion(v), FeatureFlags::empty())
    }

    #[test]
    fn cache_hit_and_miss_counting() {
        let mut cache: PlanCache<u32> = PlanCache::new(4);
        let k = key("MATCH (n) RETURN n", 0);
        assert!(cache.get(&k).is_none());
        cache.insert(k.clone(), 7);
        assert_eq!(cache.get(&k), Some(&7));
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn schema_bump_changes_key() {
        let k0 = key("MATCH (n) RETURN n", 0);
        let k1 = key("MATCH (n) RETURN n", 1);
        assert_ne!(k0, k1);
    }

    #[test]
    fn lru_evicts_least_recently_used() {
        let mut cache: PlanCache<u32> = PlanCache::new(2);
        let a = key("MATCH (a) RETURN a", 0);
        let b = key("MATCH (b) RETURN b", 0);
        let c = key("MATCH (c) RETURN c", 0);
        cache.insert(a.clone(), 1);
        cache.insert(b.clone(), 2);
        // Touch `a` so `b` becomes LRU.
        assert_eq!(cache.get(&a), Some(&1));
        cache.insert(c.clone(), 3); // evicts `b`
        assert!(cache.contains(&a));
        assert!(cache.contains(&c));
        assert!(!cache.contains(&b));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn invalidate_schema_change_evicts_older() {
        let mut cache: PlanCache<u32> = PlanCache::new(8);
        cache.insert(key("MATCH (n) RETURN n", 0), 1);
        cache.insert(key("MATCH (m) RETURN m", 0), 2);
        cache.insert(key("MATCH (p) RETURN p", 2), 3);
        let evicted = cache.invalidate_schema_change(SchemaVersion(2));
        assert_eq!(evicted, 2);
        assert_eq!(cache.len(), 1);
    }
}
